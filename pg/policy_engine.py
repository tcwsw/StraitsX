"""The control plane. Deterministic. No LLM. Runs in its own process.

Design rule that wins the demo: this module NEVER receives merchant page text, agent
reasoning, or any other attacker-reachable string as a control input. It receives a
typed Decision and the Mandate, and it answers yes or no. Prompt injection cannot
reach it, because there is no prompt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import Decision, Mandate, PolicyVerdict, PurchaseProposal, SpendIntent, now_iso

CATALOG_PATH = Path(os.environ.get(
    "CATALOG_PATH", Path(__file__).resolve().parent.parent / "product" / "catalog.json"
))

MIN_SECRET_LENGTH = 32
# Placeholders that show up in .env.example / docs / old defaults. Any of these means the
# operator never set a real secret, which means anyone can forge a SpendIntent.
_INSECURE_SECRETS = {
    "", "change-me", "changeme", "dev-only-change-me", "secret", "password",
    "test", "testing", "development", "example", "your-secret-here",
}


def _load_policy_secret() -> bytes:
    secret = os.environ.get("POLICY_SECRET")
    if secret is None or secret.strip() == "":
        raise RuntimeError(
            "POLICY_SECRET is not set. Refusing to start: a policy engine without a real "
            "secret lets anyone forge a SpendIntent and sign against the mandate. Set "
            f"POLICY_SECRET to a random value of at least {MIN_SECRET_LENGTH} characters "
            "before starting this process."
        )
    if secret.strip().lower() in _INSECURE_SECRETS:
        raise RuntimeError(
            f"POLICY_SECRET={secret!r} is a known placeholder/insecure value. "
            "Generate a real secret, e.g. `python -c \"import secrets; print(secrets.token_hex(32))\"`."
        )
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"POLICY_SECRET is only {len(secret)} characters; need at least "
            f"{MIN_SECRET_LENGTH} to resist brute force."
        )
    return secret.encode()


SECRET = _load_policy_secret()
INTENT_TTL_SECONDS = int(os.environ.get("SPEND_INTENT_TTL", "180"))
APPROVAL_TTL_SECONDS = int(os.environ.get("APPROVAL_TTL", "300"))

# The network(s) and asset contract this deployment expects to pay on. Anything a merchant's
# 402 challenge quotes that does not match THESE values is refused, no matter what the
# challenge itself claims.
ALLOWED_NETWORKS = {n for n in os.environ.get("ALLOWED_NETWORKS", "eip155:43113").split(",") if n}
XSGD_ASSET = os.environ.get("XSGD_ASSET", "0xd769410dC8772695A7F55a304d2125320A65c2A5")


def expected_network() -> str:
    """The single network a freshly minted SpendIntent is bound to. One deployment, one
    profile (fuji.env / mainnet.env), one network — pick the first configured value."""
    return sorted(ALLOWED_NETWORKS)[0]


# Merchant reputation AND wallet come from OUR registry, never from the merchant's own
# claims. A merchant's 402 challenge can say whatever payTo it likes; only the address here
# is ever paid.
MERCHANT_REGISTRY: dict[str, dict] = {
    "techstore": {
        "name": "TechStore", "reputation": 0.94, "trusted": True,
        "wallet": os.environ.get("WALLET_TECHSTORE", "0x1111111111111111111111111111111111111111"),
    },
    "gadgethub": {
        "name": "GadgetHub", "reputation": 0.88, "trusted": True,
        "wallet": os.environ.get("WALLET_GADGETHUB", "0x2222222222222222222222222222222222222222"),
    },
    "quickelectronics": {
        "name": "QuickElectronics", "reputation": 0.81, "trusted": True,
        "wallet": os.environ.get("WALLET_QUICK", "0x3333333333333333333333333333333333333333"),
    },
    "bargainbin": {
        "name": "BargainBin", "reputation": 0.22, "trusted": False,
        "wallet": os.environ.get("WALLET_BARGAIN", "0x4444444444444444444444444444444444444444"),
    },
}

# One lock guards every mutable structure below: cumulative spend, in-flight reservations,
# committed (single-use) intents, and pending human approvals. SpendIntent redemption and
# approval resolution are the only places money or authority changes hands, so they are the
# only places that need to be safe under concurrent requests.
_STATE_LOCK = threading.RLock()

_SPENT: dict[str, float] = {}            # mandate_id -> cumulative COMMITTED spend
_RESERVED: dict[str, dict] = {}          # intent_id -> reservation record, in flight
_COMMITTED: set[str] = set()             # intent_id -> permanently used (paid or card-issued)
_PENDING: dict[str, dict] = {}           # approval_id -> approval record


def load_catalog() -> dict[str, dict[str, dict]]:
    """The ground truth for basket checks: merchant_id -> sku -> {title, category, price,
    delivery_days, in_stock}. Re-read from disk on every call (the file is tiny and PMs edit
    it without restarting anything else) — never cached values that could drift from what a
    PM just changed, and never anything supplied by a caller instead."""
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    out: dict[str, dict[str, dict]] = {}
    for merchant_id, merchant in data.get("merchants", {}).items():
        out[merchant_id] = {item["sku"]: item for item in merchant.get("items", [])}
    return out


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def spent(mandate_id: str) -> float:
    with _STATE_LOCK:
        return round(_SPENT.get(mandate_id, 0.0), 2)



def evaluate(mandate: Mandate, decision: Decision) -> PolicyVerdict:
    checks: list[dict] = []
    amount = decision.amount
    already = spent(mandate.mandate_id)
    remaining = round(mandate.budget_total - already, 2)

    # 1. mandate still alive
    alive = datetime.fromisoformat(mandate.expires_at) > datetime.now(timezone.utc)
    checks.append(_check("mandate_valid", alive, f"expires {mandate.expires_at}"))

    # 2. per-transaction ceiling
    checks.append(_check(
        "per_txn_limit", amount <= mandate.per_txn_max,
        f"{amount:.2f} <= {mandate.per_txn_max:.2f} {mandate.currency}",
    ))

    # 3. remaining budget
    checks.append(_check(
        "budget_remaining", amount <= remaining,
        f"{amount:.2f} <= {remaining:.2f} remaining of {mandate.budget_total:.2f}",
    ))

    # 4. merchant allowlist — by id, resolved against our registry
    reg = MERCHANT_REGISTRY.get(decision.chosen.merchant_id)
    merchant_ok = bool(reg and reg["trusted"] and decision.chosen.merchant_id in mandate.allowed_merchants)
    checks.append(_check(
        "merchant_allowed", merchant_ok,
        f"{decision.chosen.merchant_id} "
        + ("in allowlist, trusted" if merchant_ok else "NOT in allowlist or untrusted"),
    ))

    # 5. category
    cat_ok = decision.chosen.category in mandate.allowed_categories
    checks.append(_check("category_allowed", cat_ok, f"{decision.chosen.category}"))

    # 6. denied keywords against the STRUCTURED product fields only
    haystack = f"{decision.chosen.title} {decision.chosen.category} {decision.chosen.sku}".lower()
    hit = next((k for k in mandate.denied_keywords if k in haystack), None)
    checks.append(_check("no_denied_items", hit is None, f"blocked term: {hit}" if hit else "clean"))

    # 7. currency
    checks.append(_check(
        "currency", decision.chosen.currency == mandate.currency,
        f"{decision.chosen.currency}",
    ))

    allowed = all(c["passed"] for c in checks)
    needs_human = allowed and amount > mandate.require_human_above

    verdict = PolicyVerdict(
        allowed=allowed and not needs_human,
        checks=checks,
        needs_human=needs_human,
        reason=None if allowed else next(c["name"] for c in checks if not c["passed"]),
        remaining_budget=remaining,
    )
    if verdict.allowed:
        verdict.spend_intent = mint_intent(mandate, decision)
    elif needs_human:
        # Park it. Note what is escalated: the decision, not a blank cheque. The human
        # approves this exact purchase or nothing. Approval does not raise the mandate.
        verdict.approval_id = "a-" + uuid.uuid4().hex[:8]
        with _STATE_LOCK:
            _PENDING[verdict.approval_id] = {
                "mandate": mandate,
                "decision": decision,
                "kind": "single",
                "amount": amount,
                "created": time.time(),
                "status": "pending",
            }
    return verdict


def evaluate_basket(mandate: Mandate, proposal: PurchaseProposal) -> PolicyVerdict:
    """Basket-shaped counterpart to `evaluate()`. Checks the total basket amount, every
    merchant, every category, every SKU, stock for every line item, the delivery
    constraint for every line item, and prohibited keywords for every line item — each one
    re-derived from `load_catalog()` (product/catalog.json), never taken on faith from the
    proposal itself. For the initial demo, every line item must come from the same
    merchant: one checkout, one payment."""
    checks: list[dict] = []
    items = proposal.selected_items
    catalog = load_catalog()

    if not items:
        checks.append(_check("has_items", False, "no line items selected"))
        return PolicyVerdict(allowed=False, checks=checks, reason="has_items", remaining_budget=0.0)

    merchant_ids = proposal.merchant_ids
    single_merchant_ok = len(merchant_ids) == 1
    checks.append(_check(
        "single_merchant", single_merchant_ok,
        f"all {len(items)} line item(s) from {next(iter(merchant_ids))}" if single_merchant_ok
        else f"{len(merchant_ids)} distinct merchants in one basket: {sorted(merchant_ids)}",
    ))
    merchant_id = next(iter(merchant_ids)) if single_merchant_ok else None

    amount = proposal.total_amount
    already = spent(mandate.mandate_id)
    remaining = round(mandate.budget_total - already, 2)

    # mandate-level checks, same as the single-item path but against the basket total
    alive = datetime.fromisoformat(mandate.expires_at) > datetime.now(timezone.utc)
    checks.append(_check("mandate_valid", alive, f"expires {mandate.expires_at}"))
    checks.append(_check(
        "per_txn_limit", amount <= mandate.per_txn_max,
        f"{amount:.2f} <= {mandate.per_txn_max:.2f} {mandate.currency}",
    ))
    checks.append(_check(
        "budget_remaining", amount <= remaining,
        f"{amount:.2f} <= {remaining:.2f} remaining of {mandate.budget_total:.2f}",
    ))

    if merchant_id:
        reg = MERCHANT_REGISTRY.get(merchant_id)
        merchant_ok = bool(reg and reg["trusted"] and merchant_id in mandate.allowed_merchants)
        checks.append(_check(
            "merchant_allowed", merchant_ok,
            f"{merchant_id} " + ("in allowlist, trusted" if merchant_ok else "NOT in allowlist or untrusted"),
        ))
    else:
        checks.append(_check("merchant_allowed", False, "cannot check: basket spans multiple merchants"))

    merchant_catalog = catalog.get(merchant_id, {}) if merchant_id else {}
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        real = merchant_catalog.get(item.sku) if item.merchant_id == merchant_id else None

        checks.append(_check(f"sku_known[{label}]", real is not None,
                              "found in catalogue" if real else "no such SKU for this merchant"))
        if real is None:
            # Nothing further can be honestly checked for a SKU we cannot resolve.
            continue

        price_ok = abs(item.unit_price - float(real["price"])) < 0.005
        checks.append(_check(
            f"price_match[{label}]", price_ok,
            f"proposal {item.unit_price:.2f} vs catalogue {float(real['price']):.2f}",
        ))

        cat_ok = real["category"] in mandate.allowed_categories
        checks.append(_check(f"category_allowed[{label}]", cat_ok, f"{real['category']}"))

        stock_ok = bool(real.get("in_stock"))
        checks.append(_check(f"in_stock[{label}]", stock_ok,
                              "in stock" if stock_ok else "OUT OF STOCK"))

        delivery_days = int(real.get("delivery_days", 0))
        if mandate.max_delivery_days is None:
            delivery_ok = True
            delivery_detail = f"{delivery_days}d, no constraint configured"
        else:
            delivery_ok = delivery_days <= mandate.max_delivery_days
            delivery_detail = f"{delivery_days}d <= {mandate.max_delivery_days}d"
        checks.append(_check(f"delivery_ok[{label}]", delivery_ok, delivery_detail))

        haystack = f"{real['title']} {real['category']} {item.sku}".lower()
        hit = next((k for k in mandate.denied_keywords if k in haystack), None)
        checks.append(_check(f"no_denied_items[{label}]", hit is None,
                              f"blocked term: {hit}" if hit else "clean"))

    allowed = all(c["passed"] for c in checks)
    needs_human = allowed and amount > mandate.require_human_above

    verdict = PolicyVerdict(
        allowed=allowed and not needs_human,
        checks=checks,
        needs_human=needs_human,
        reason=None if allowed else next(c["name"] for c in checks if not c["passed"]),
        remaining_budget=remaining,
    )
    if verdict.allowed:
        verdict.spend_intent = mint_basket_intent(mandate, proposal)
    elif needs_human:
        verdict.approval_id = "a-" + uuid.uuid4().hex[:8]
        with _STATE_LOCK:
            _PENDING[verdict.approval_id] = {
                "mandate": mandate,
                "decision": proposal,
                "kind": "basket",
                "amount": amount,
                "created": time.time(),
                "status": "pending",
            }
    return verdict



def pending() -> list[dict]:
    with _STATE_LOCK:
        items = list(_PENDING.items())
    out = []
    for aid, p in items:
        d = p["decision"]
        if p.get("kind") == "basket":
            merchant = next(iter(d.merchant_ids), "?")
            item_label = f"{len(d.selected_items)} line item(s)"
            quantity = sum(i.quantity for i in d.selected_items)
        else:
            merchant = d.chosen.merchant_name
            item_label = d.chosen.title
            quantity = d.quantity
        out.append({
            "approval_id": aid,
            "status": p["status"],
            "amount": p["amount"],
            "merchant": merchant,
            "item": item_label,
            "quantity": quantity,
            "threshold": p["mandate"].require_human_above,
            "waiting_seconds": int(time.time() - p["created"]),
        })
    return out


def resolve(approval_id: str, approved: bool) -> tuple[bool, str, str | None]:
    """A human decides. Approval mints an intent for THIS purchase only."""
    with _STATE_LOCK:
        p = _PENDING.get(approval_id)
        if not p:
            return False, "no such approval", None
        if p["status"] != "pending":
            return False, f"already {p['status']}", None
        if time.time() - p["created"] > APPROVAL_TTL_SECONDS:
            p["status"] = "expired"
            return False, "approval request expired", None
        if not approved:
            p["status"] = "rejected"
            return True, "rejected by human", None
        p["status"] = "approved"
        # Park the intent here rather than returning it to the human's HTTP client. The
        # human approves; the agent collects. Two different callers, so the intent must
        # survive the approve response. It is still single-use, so collecting it twice
        # buys nothing.
        mint = mint_basket_intent if p.get("kind") == "basket" else mint_intent
        p["spend_intent"] = mint(p["mandate"], p["decision"])
        return True, "approved by human", p["spend_intent"]


def collect(approval_id: str) -> str | None:
    """The agent collects the intent a human approved. Returns None unless approved."""
    with _STATE_LOCK:
        p = _PENDING.get(approval_id)
        if not p or p["status"] != "approved":
            return None
        return p.get("spend_intent")


# ---------------------------------------------------------------- SpendIntent lifecycle


def _mint(mandate_id: str, decision_id: str, merchant_id: str, amount: float) -> str:
    """Shared minting logic for both the single-item and basket paths. Every field is
    looked up from OUR registry/config — never supplied by a caller."""
    reg = MERCHANT_REGISTRY.get(merchant_id)
    if not reg or not reg.get("wallet"):
        raise ValueError(f"no registered wallet for merchant {merchant_id!r}")
    network = expected_network()
    body = SpendIntent(
        intent_id=str(uuid.uuid4()),
        mandate_id=mandate_id,
        decision_id=decision_id,
        merchant_id=merchant_id,
        pay_to=reg["wallet"],
        asset=XSGD_ASSET,
        network=network,
        chain_id=int(network.split(":")[1]),
        amount=amount,
        nonce=secrets.token_hex(16),
        expires_at=now_iso(),
    ).model_dump()
    body["exp"] = int(time.time()) + INTENT_TTL_SECONDS
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}||{sig}"


def mint_intent(mandate: Mandate, decision: Decision) -> str:
    """Bind a fresh SpendIntent to exactly one merchant, one exact amount, one registered
    wallet, one asset contract, one network/chain, one expiry, and one single-use nonce."""
    return _mint(mandate.mandate_id, decision.decision_id, decision.chosen.merchant_id, decision.amount)


def mint_basket_intent(mandate: Mandate, proposal: PurchaseProposal) -> str:
    """Basket-shaped counterpart to `mint_intent()`. The SpendIntent itself only ever binds
    to one merchant and one total amount — it has no notion of SKUs or line items — so a
    basket checkout is authorized exactly the same way a single-item one is."""
    merchant_id = next(iter(proposal.merchant_ids))
    return _mint(mandate.mandate_id, proposal.decision_id, merchant_id, proposal.total_amount)


def _parse_token(token: str) -> dict | None:
    try:
        raw, sig = token.split("||")
    except ValueError:
        return None
    expect = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def reserve_intent(
    token: str,
    merchant_id: str,
    amount: float,
    pay_to: str,
    asset: str,
    network: str,
    chain_id: int | None,
) -> tuple[bool, str]:
    """Validate every field bound to this SpendIntent and hold it for exactly one caller.

    Nothing is spent and nothing is permanently consumed here. On success the caller MUST
    follow up with exactly one of commit_intent() (payment succeeded) or release_intent()
    (it did not) — until then the intent is held in-flight so a second, concurrent caller
    presenting the same token cannot also reserve it (replay-under-race).

    Returns (True, intent_id) on success, (False, reason) otherwise.
    """
    body = _parse_token(token)
    if body is None:
        return False, "malformed token or bad signature"

    if time.time() > body["exp"]:
        return False, "token expired"
    if body["merchant_id"] != merchant_id:
        return False, f"token bound to merchant {body['merchant_id']}, not {merchant_id}"
    if abs(amount - body["amount"]) > 1e-9:
        return False, f"amount {amount} does not exactly match approved amount {body['amount']}"
    if pay_to.lower() != body["pay_to"].lower():
        return False, f"payTo {pay_to} does not match the registered wallet {body['pay_to']}"
    if asset.lower() != body["asset"].lower():
        return False, f"asset {asset} does not match the configured contract {body['asset']}"
    if network != body["network"]:
        return False, f"network {network} does not match the bound network {body['network']}"
    if chain_id is not None and chain_id != body["chain_id"]:
        return False, f"chainId {chain_id} does not match the bound chain {body['chain_id']}"

    intent_id = body["intent_id"]
    with _STATE_LOCK:
        if intent_id in _COMMITTED:
            return False, "token already used"
        if intent_id in _RESERVED:
            return False, "token already reserved (concurrent use)"
        _RESERVED[intent_id] = {
            "mandate_id": body["mandate_id"],
            "amount": body["amount"],
        }
    return True, intent_id


def commit_intent(intent_id: str) -> bool:
    """Payment (or card issuance) succeeded: count the spend, permanently consume the
    intent. Called only after the money has actually moved (or the card actually issued),
    never before."""
    with _STATE_LOCK:
        record = _RESERVED.pop(intent_id, None)
        if record is None:
            return False
        _COMMITTED.add(intent_id)
        _SPENT[record["mandate_id"]] = round(
            _SPENT.get(record["mandate_id"], 0.0) + record["amount"], 2
        )
        return True


def release_intent(intent_id: str) -> bool:
    """Signing, settlement, or card issuance failed: give the reservation back. Nothing was
    spent, and the intent is available again — still single-use once it does succeed, but
    a transient failure does not burn the mandate's only shot at this purchase."""
    with _STATE_LOCK:
        return _RESERVED.pop(intent_id, None) is not None

