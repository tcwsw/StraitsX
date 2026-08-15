"""Three honest merchants plus one hostile one. Real x402 on the checkout endpoint.

Catalogue lives in product/catalog.json and is owned by the PM. This file should not need
editing to change products, prices, stock or the injection payload.

Run:  uvicorn merchants.server:app --port 4030
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from merchants.facilitator import SettlementFailed, settle, verify
from pg.x402_client import decode_header

# This process must receive only public merchant-wallet config (WALLET_* payment
# addresses) plus, when actually settling on-chain, its OWN RELAYER_PRIVATE_KEY — never
# the policy tier's AGENT_PRIVATE_KEY (signs consumer payments) or POLICY_SECRET (mints
# SpendIntents). Those belong exclusively to pg/policy_server.py (loaded from its own
# .env.policy) and must never reach the merchant process, on any settlement path.
_FORBIDDEN_IN_MERCHANT_PROCESS = ("AGENT_PRIVATE_KEY", "POLICY_SECRET")
_leaked = [k for k in _FORBIDDEN_IN_MERCHANT_PROCESS if os.environ.get(k)]
if _leaked:
    raise RuntimeError(
        "merchants.server refuses to start: policy-tier secret(s) present in this "
        f"process's environment: {', '.join(sorted(_leaked))}. These belong only to "
        "pg/policy_server.py — remove them from this process's environment (see run.sh's "
        "`env -u` flags on the merchant launch line)."
    )

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = Path(os.environ.get("CATALOG_PATH", ROOT / "product" / "catalog.json"))

XSGD_FUJI = "0xd769410dC8772695A7F55a304d2125320A65c2A5"
XSGD_MAINNET = "0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E"
NETWORK = os.environ.get("X402_NETWORK", "eip155:43113")
ASSET = os.environ.get("XSGD_ASSET") or (XSGD_MAINNET if NETWORK.endswith("43114") else XSGD_FUJI)
DECIMALS = 6

app = FastAPI(title="ProcureGuard demo merchants")
# Local demo tooling only (the static frontend/ page is served from its own origin and
# calls this API's public search/checkout endpoints directly). No secrets or cookies ever
# flow over this boundary.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

_catalog = json.loads(CATALOG_PATH.read_text())
CATALOG: dict[str, dict] = _catalog["merchants"]

# Each merchant settles to its own wallet. Set from .env for a real run.
WALLETS = {
    "techstore": os.environ.get("WALLET_TECHSTORE", "0x1111111111111111111111111111111111111111"),
    "gadgethub": os.environ.get("WALLET_GADGETHUB", "0x2222222222222222222222222222222222222222"),
    "cheapdealsstore": os.environ.get("WALLET_CHEAP", "0x3333333333333333333333333333333333333333"),
    "bargainbin": os.environ.get("WALLET_BARGAIN", "0x4444444444444444444444444444444444444444"),
}

# Demo/test-only attack simulation: when DEMO_EVIL_MERCHANT names one of the merchants
# above, that merchant's 402 challenge quotes DEMO_EVIL_PAYTO instead of its real
# registered wallet — simulating a compromised or redirected merchant. The policy engine's
# resolve_and_verify_payment() must refuse this (RECIPIENT_MISMATCH) BEFORE any signature
# is produced; nothing here bypasses that check, this only lets a demo/test trigger it via
# a genuine merchant 402 response instead of a hand-built one.
DEMO_EVIL_MERCHANT = os.environ.get("DEMO_EVIL_MERCHANT", "")
DEMO_EVIL_PAYTO = os.environ.get("DEMO_EVIL_PAYTO", "")


def _atomic(price: float) -> str:
    return str(int(round(price * 10**DECIMALS)))


@app.get("/merchants")
def merchants():
    return [
        {"merchant_id": mid, "name": m["name"], "items": len(m["items"])}
        for mid, m in CATALOG.items()
    ]


@app.get("/system/info")
def system_info():
    """Non-secret operational facts only — no keys, no wallet balances. Lets a thin client
    (the dashboard) show which network this merchant process is quoting on (e.g. for a
    'REAL MAINNET SELF-TRANSFER' badge) without ever reading X402_NETWORK itself, since
    that belongs to this process's own environment, not the dashboard's."""
    return {"network": NETWORK}


@app.get("/{merchant_id}/search")
def search(merchant_id: str, q: str = ""):
    m = CATALOG.get(merchant_id)
    if not m:
        return JSONResponse({"error": "no such merchant"}, 404)
    terms = [t for t in q.lower().split() if t]
    items = [
        i for i in m["items"]
        if not terms or any(t in i["title"].lower() or t in i["category"] for t in terms)
    ]
    out = {
        "merchant_id": merchant_id,
        "merchant_name": m["name"],
        "items": [{**i, "currency": "XSGD", "checkout_url": f"/{merchant_id}/checkout"} for i in items],
    }
    # The hostile merchant's items already carry their own (possibly injected) description
    # straight from product/catalog.json — nothing synthesized here.
    return out


@app.get("/{merchant_id}/product/{sku}", response_class=HTMLResponse)
def product_page(merchant_id: str, sku: str):
    """A human-looking page. The hostile merchant hides its item's own description (which may
    carry an injected instruction) in 1px white text."""
    m = CATALOG.get(merchant_id, {})
    item = next((i for i in m.get("items", []) if i["sku"] == sku), None)
    if not item:
        return HTMLResponse("<h1>404</h1>", 404)
    hidden = (
        f'<p style="color:#fff;font-size:1px">{item.get("description", "")}</p>'
        if m.get("hostile") else ""
    )
    return (
        f"<html><body style='font-family:system-ui'>"
        f"<h1>{item['title']}</h1><p>{item['price']:.2f} XSGD at {m['name']}</p>"
        f"{hidden}</body></html>"
    )


@app.post("/{merchant_id}/checkout")
async def checkout(
    merchant_id: str,
    request: Request,
    payment_signature: str | None = Header(default=None, alias="PAYMENT-SIGNATURE"),
):
    """One checkout, one payment — even for a multi-item basket. Send either the legacy
    single `{"sku", "quantity"}` body, or a basket `{"items": [{"sku", "quantity"}, ...]}`.
    Either way exactly one 402 challenge is issued, for the combined total, and exactly one
    PAYMENT-SIGNATURE settles the whole order."""
    body = await request.json()
    m = CATALOG.get(merchant_id)
    if not m:
        return JSONResponse({"error": "no such merchant"}, 404)

    if "items" in body:
        lines = [(str(i["sku"]), int(i.get("quantity", 1))) for i in body["items"]]
    else:
        lines = [(body.get("sku"), int(body.get("quantity", 1)))]

    resolved = []
    for sku, qty in lines:
        item = next((i for i in m.get("items", []) if i["sku"] == sku), None)
        if not item:
            return JSONResponse({"error": f"unknown sku {sku}"}, 404)
        resolved.append({"sku": sku, "quantity": qty, "unit_price": item["price"],
                          "subtotal": round(item["price"] * qty, 2)})

    total = round(sum(line["subtotal"] for line in resolved), 2)
    pay_to = WALLETS[merchant_id]
    if DEMO_EVIL_MERCHANT and DEMO_EVIL_PAYTO and merchant_id == DEMO_EVIL_MERCHANT:
        pay_to = DEMO_EVIL_PAYTO
    accept = {
        "scheme": "exact",
        "network": NETWORK,
        "amount": _atomic(total),
        "asset": ASSET,
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "chainId": int(NETWORK.split(":")[1]),
        "extra": {"assetTransferMethod": "eip3009", "name": "XSGD", "version": "2"},
    }

    if not payment_signature:
        return JSONResponse(
            {"x402Version": 1, "error": "PAYMENT-SIGNATURE header is required", "accepts": [accept]},
            status_code=402,
            headers={"PAYMENT-REQUIRED": "1"},
        )

    payload = decode_header(payment_signature)
    ok, why = verify(payload, accept)
    if not ok:
        return JSONResponse({"error": "payment invalid", "detail": why}, 402)

    try:
        tx_hash, settled = settle(payload, accept)
    except SettlementFailed as exc:
        # A transaction was actually submitted but the chain reverted it. No value moved
        # — this must never be reported as "paid". Non-200 so the caller's definite=True
        # /intents/{id}/failed path releases the reservation rather than counting spend
        # that never happened.
        return JSONResponse(
            {"error": "settlement reverted on-chain", "detail": str(exc),
             "tx_hash": exc.tx_hash, "status": exc.status},
            status_code=502,
        )
    except RuntimeError as exc:
        # SETTLE_MODE=onchain but RELAYER_PRIVATE_KEY is missing: a hard configuration
        # failure. Nothing was submitted and no tx hash exists — never invent one.
        return JSONResponse(
            {"error": "settlement configuration error", "detail": str(exc)},
            status_code=500,
        )
    order_id = f"{merchant_id}-{'-'.join(l['sku'] for l in resolved)}-{tx_hash[:10]}"
    return JSONResponse(
        {
            "status": "paid",
            "order_id": order_id,
            "merchant_id": merchant_id,
            "items": resolved,
            "amount": total,
            "currency": "XSGD",
            "receipt": {"tx_hash": tx_hash, "settled_onchain": settled, "network": NETWORK},
        },
        headers={"PAYMENT-RESPONSE": tx_hash},
    )

