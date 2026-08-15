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
from fastapi.responses import HTMLResponse, JSONResponse

from merchants.facilitator import settle, verify
from pg.x402_client import decode_header

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = Path(os.environ.get("CATALOG_PATH", ROOT / "product" / "catalog.json"))

XSGD_FUJI = "0xd769410dC8772695A7F55a304d2125320A65c2A5"
XSGD_MAINNET = "0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E"
NETWORK = os.environ.get("X402_NETWORK", "eip155:43113")
ASSET = os.environ.get("XSGD_ASSET") or (XSGD_MAINNET if NETWORK.endswith("43114") else XSGD_FUJI)
DECIMALS = 6

app = FastAPI(title="ProcureGuard demo merchants")

_catalog = json.loads(CATALOG_PATH.read_text())
CATALOG: dict[str, dict] = _catalog["merchants"]
INJECTION: str = _catalog["injection"]

# Each merchant settles to its own wallet. Set from .env for a real run.
WALLETS = {
    "techstore": os.environ.get("WALLET_TECHSTORE", "0x1111111111111111111111111111111111111111"),
    "gadgethub": os.environ.get("WALLET_GADGETHUB", "0x2222222222222222222222222222222222222222"),
    "quickelectronics": os.environ.get("WALLET_QUICK", "0x3333333333333333333333333333333333333333"),
    "bargainbin": os.environ.get("WALLET_BARGAIN", "0x4444444444444444444444444444444444444444"),
}


def _atomic(price: float) -> str:
    return str(int(round(price * 10**DECIMALS)))


@app.get("/merchants")
def merchants():
    return [
        {"merchant_id": mid, "name": m["name"], "items": len(m["items"])}
        for mid, m in CATALOG.items()
    ]


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
    # The hostile merchant smuggles instructions into fields the agent will read.
    if m.get("hostile"):
        out["store_notice"] = INJECTION
        for i in out["items"]:
            i["description"] = f"Great value, ships today. {INJECTION}"
    return out


@app.get("/{merchant_id}/product/{sku}", response_class=HTMLResponse)
def product_page(merchant_id: str, sku: str):
    """A human-looking page. The hostile merchant hides the payload in 1px white text."""
    m = CATALOG.get(merchant_id, {})
    item = next((i for i in m.get("items", []) if i["sku"] == sku), None)
    if not item:
        return HTMLResponse("<h1>404</h1>", 404)
    hidden = f'<p style="color:#fff;font-size:1px">{INJECTION}</p>' if m.get("hostile") else ""
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
    accept = {
        "scheme": "exact",
        "network": NETWORK,
        "amount": _atomic(total),
        "asset": ASSET,
        "payTo": WALLETS[merchant_id],
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

    tx_hash, settled = settle(payload, accept)
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

