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
from decimal import Decimal
from pathlib import Path

from . import money
from .merchant_registry import MerchantRecord, MerchantRegistry, RegistryLookupError
from .models import (
    Decision, Mandate, Offer, PolicyVerdict, PurchaseProposal, SpendIntent, SpendIntentItem,
    SpendIntentLeg, now_iso,
)

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


# Merchant trust AND payment recipient come from the Merchant Wallet Registry (FINTECH-owned
# data/merchant_registry.json), never from the merchant's own claims. A merchant's 402
# challenge can say whatever payTo it likes; only the address the registry has on file is
# ever paid, and only resolve_and_verify_payment() (at payment-execution time, never at
# mint time) is allowed to look it up.
REGISTRY = MerchantRegistry()

# One lock guards every mutable structure below: cumulative spend, in-flight reservations,
# committed (single-use) intents, and pending human approvals. SpendIntent redemption and
# approval resolution are the only places money or authority changes hands, so they are the
# only places that need to be safe under concurrent requests.
_STATE_LOCK = threading.RLock()

_SPENT: dict[str, Decimal] = {}          # mandate_id -> cumulative COMMITTED spend
_RESERVED: dict[str, dict] = {}          # intent_id -> reservation record, in flight
_COMMITTED: set[str] = set()             # intent_id -> permanently used (paid or card-issued)
_PENDING: dict[str, dict] = {}           # approval_id -> approval record
_SETTLED_TX_HASHES: dict[str, str] = {}  # lowercased on-chain tx_hash -> the ONE intent_id it settled

# The explicit SpendIntent lifecycle. AUTHORIZED -> EXECUTING -> CONSUMED is the happy
# path; the others are every way it can end instead. Once created, a record is NEVER
# deleted (unlike `_RESERVED`, which is popped the moment a reservation ends) so
# GET /intents/{id} can always answer "what happened to this one", including long after
# settlement or failure. EXPIRED, DENIED, FAILED, CANCELLED and CONSUMED are TERMINAL —
# never reactivated, never re-reserved (see `reserve_intent()`); a retry after any of them
# requires a brand new evaluate()/evaluate_basket() call producing a brand new SpendIntent.
#   AUTHORIZED              — the policy engine has reserved the amount against the mandate.
#   EXECUTING               — recipient verified and payment signed (x402), or card issuance
#                              in flight (card) — NOT YET counted as spent.
#   CONSUMED                — merchant settlement verified (x402, via POST .../settled) or
#                              the card was actually issued (card) — spend is now permanent.
#                              TERMINAL.
#   EXPIRED                 — the token's TTL passed before it was ever redeemed. TERMINAL.
#   DENIED                  — a policy-level refusal at execution time (bad recipient,
#                              asset, network, or merchant status) — reservation released.
#                              TERMINAL.
#   FAILED                  — a definite technical execution failure (signing blew up, the
#                              card issuer refused, or the merchant reported a definite
#                              failure) — reservation released. TERMINAL: this exact token
#                              is never retried; a retry gets a new SpendIntent instead.
#   CANCELLED               — reserved for administrative/human cancellation of a still-
#                              live reservation (not currently reachable: nothing is minted
#                              ahead of human approval in this codebase, so there is nothing
#                              to cancel before that point) — defined for spec completeness.
#                              TERMINAL.
#   RECONCILIATION_REQUIRED — the payment's outcome is genuinely unknown (a timeout or a
#                              submission that never got a definite answer back) — the
#                              reservation is DELIBERATELY retained, pending manual review,
#                              because we do not know whether the merchant was actually
#                              paid. NOT terminal: the only way out is a human/operator
#                              resolving it (this codebase does not yet do that
#                              automatically).
_INTENT_RECORDS: dict[str, dict] = {}    # spend_intent_id -> lifecycle record, kept forever


# Terminal states: once a SpendIntent reaches one of these, it is done, forever. Never
# reactivated, never re-reserved — a retry after any of these requires a brand new
# evaluation (evaluate()/evaluate_basket()) producing a brand new SpendIntent. Only
# RECONCILIATION_REQUIRED is non-terminal: it is a deliberate holding state (reservation
# retained) awaiting manual reconciliation, not an end state.
TERMINAL_STATES = {"EXPIRED", "DENIED", "FAILED", "CANCELLED", "CONSUMED"}


def _set_intent_state(intent_id: str, state: str, detail: str | None = None) -> None:
    with _STATE_LOCK:
        rec = _INTENT_RECORDS.get(intent_id)
        if rec is not None:
            rec["status"] = state
            rec["updated_at"] = now_iso()
            if detail is not None:
                rec["detail"] = detail


# ---------------------------------------------------------------- agent status (ACTIVE/PAUSED/REVOKED)

AGENT_STATUSES = {"ACTIVE", "PAUSED", "REVOKED"}
DEFAULT_AGENT_STATUS = "ACTIVE"
_AGENT_STATUS: dict[str, str] = {}       # mandate_id -> ACTIVE | PAUSED | REVOKED


def set_agent_status(mandate_id: str, status: str) -> str:
    """Human/operator control: pause or revoke the agent acting under one mandate (or
    reinstate it to ACTIVE). Checked as the very first gate on every new procurement
    (`agent_active`, evaluate_basket()'s check #2) AND again, independently, immediately
    before a signature is ever produced (pg.policy_server's /authorize, /authorize-card) —
    so a pause that lands between those two moments still stops the money. Unknown
    mandate_ids are accepted (a status can be set before the mandate is even registered,
    or for a mandate this process has not seen /mandates for yet) — this is a control
    switch, not a mandate registry."""
    if status not in AGENT_STATUSES:
        raise ValueError(f"status must be one of {sorted(AGENT_STATUSES)}, got {status!r}")
    with _STATE_LOCK:
        _AGENT_STATUS[mandate_id] = status
    return status


def get_agent_status(mandate_id: str) -> str:
    """ACTIVE unless a human/operator has explicitly paused or revoked this mandate's
    agent — never a default of PAUSED/REVOKED, which would fail every mandate this
    process has not been told about yet."""
    with _STATE_LOCK:
        return _AGENT_STATUS.get(mandate_id, DEFAULT_AGENT_STATUS)


# ---------------------------------------------------------------- offers snapshot (ground truth)

_OFFERS_SNAPSHOT: dict[tuple[str, str], Offer] = {}   # (merchant_id, offer_id) -> Offer


def set_offers_snapshot(offers: list[Offer]) -> int:
    """Replace the entire in-memory offers snapshot with exactly what the caller just
    submitted (POST /offers/snapshot) — an explicit, attested point-in-time view of what
    the agent actually saw when it gathered quotes, so `offer_exists`/`stock_available`/
    `category_allowed` check against the SAME data the agent priced its proposal from,
    not a catalogue that could have changed underneath it between quoting and evaluation.
    Returns the number of offers stored."""
    with _STATE_LOCK:
        _OFFERS_SNAPSHOT.clear()
        for offer in offers:
            _OFFERS_SNAPSHOT[(offer.merchant_id, offer.offer_id)] = offer
        return len(_OFFERS_SNAPSHOT)


def _offer_from_catalog_entry(merchant_id: str, raw: dict) -> Offer:
    """Fallback ground truth for a (merchant_id, offer_id) not present in the posted
    offers snapshot: derive an Offer straight from product/catalog.json, the same shape
    pg.prehook.sanitise() produces. Exists purely so callers that never post a snapshot
    (every existing scripted demo/test) keep working unchanged; a posted snapshot entry
    for the same (merchant_id, offer_id) always wins over this."""
    reg = REGISTRY.get(merchant_id)
    in_stock = bool(raw.get("in_stock", True))
    return Offer(
        offer_id=raw.get("offer_id", raw["sku"]), merchant_id=merchant_id,
        merchant_name=reg.display_name if reg else merchant_id,
        sku=raw["sku"], title=raw["title"], product_type=raw.get("product_type", "unknown"),
        category=raw["category"], unit_price_xsgd=raw["price"],
        shipping_cost_xsgd=raw.get("shipping_cost", 0.0), currency=raw.get("currency", "XSGD"),
        delivery_days=int(raw.get("delivery_days", 0)),
        stock=(raw.get("stock") if in_stock else 0), in_stock=in_stock,
        reputation=reg.reputation if reg else 0.0,
        checkout_url=raw.get("checkout_url", f"/{merchant_id}/checkout"),
        attributes=raw.get("attributes", {}),
    )


def get_offer(merchant_id: str, offer_id: str) -> Offer | None:
    """The ground-truth Offer for one (merchant_id, offer_id): a posted offers snapshot
    entry if one exists, else derived from product/catalog.json, else None (no such
    offer, anywhere) — the data source behind `offer_exists`/`category_allowed`/
    `stock_available`/`no_denied_items`/`currency` in evaluate_basket()."""
    with _STATE_LOCK:
        snapshot_hit = _OFFERS_SNAPSHOT.get((merchant_id, offer_id))
    if snapshot_hit is not None:
        return snapshot_hit
    catalog = load_catalog()
    raw = catalog.get(merchant_id, {}).get(offer_id)
    if raw is None:
        return None
    return _offer_from_catalog_entry(merchant_id, raw)


def _sweep_expired() -> None:
    """Opportunistically release any reservation whose TTL silently passed without anyone
    ever presenting the token for payment, marking its record EXPIRED. Called before every
    reserved-budget read so a stale, never-redeemed reservation cannot indefinitely hold
    budget hostage."""
    now = time.time()
    with _STATE_LOCK:
        expired = [iid for iid, r in _RESERVED.items() if now > r.get("exp", float("inf"))]
        for iid in expired:
            _RESERVED.pop(iid, None)
            _set_intent_state(iid, "EXPIRED", "TTL passed before use")

# The last Mandate seen for a given mandate_id, cached purely so a later, mandate-object-less
# call (reserve_intent(), which only has what a freshly parsed SpendIntent token carries) can
# still do an authoritative, reservation-aware budget check at the moment it actually reserves
# money — not just the point-in-time check evaluate()/evaluate_basket() already did, which a
# concurrent request could have made stale. Populated by evaluate()/evaluate_basket(), the
# only two places that ever see a full Mandate.
_MANDATE_CACHE: dict[str, Mandate] = {}


def _remember_mandate(mandate: Mandate) -> None:
    with _STATE_LOCK:
        _MANDATE_CACHE[mandate.mandate_id] = mandate


def _reserved_total(mandate_id: str) -> Decimal:
    """Sum of every currently in-flight (reserved-but-not-yet-committed) reservation for one
    mandate — legacy single-leg reservations AND unclaimed basket-eager reservations alike.
    Used so 'remaining budget' always means spent + reserved + (about to be proposed), per
    the fintech requirement that a reservation itself — not just a completed payment —
    counts against the mandate."""
    _sweep_expired()
    with _STATE_LOCK:
        return sum(
            (r["amount"] for r in _RESERVED.values() if r["mandate_id"] == mandate_id), money.ZERO
        )


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


def spent(mandate_id: str) -> Decimal:
    with _STATE_LOCK:
        return _SPENT.get(mandate_id, money.ZERO)



def evaluate(mandate: Mandate, decision: Decision) -> PolicyVerdict:
    _remember_mandate(mandate)
    checks: list[dict] = []
    amount = decision.amount
    already = spent(mandate.mandate_id)
    remaining = mandate.budget_total - already - _reserved_total(mandate.mandate_id)

    # 1. mandate still alive
    alive = datetime.fromisoformat(mandate.expires_at) > datetime.now(timezone.utc)
    checks.append(_check("mandate_valid", alive, f"expires {mandate.expires_at}"))

    # 1b. agent not paused/revoked — checked again, independently, immediately before
    # signing in pg.policy_server's /authorize and /authorize-card.
    agent_status = get_agent_status(mandate.mandate_id)
    checks.append(_check(
        "agent_active", agent_status == "ACTIVE", f"agent status: {agent_status}",
    ))

    # 2. per-intent ceiling
    checks.append(_check(
        "per_intent_limit", amount <= mandate.per_intent_max,
        f"{amount:.2f} <= {mandate.per_intent_max:.2f} {mandate.currency}",
    ))

    # 3. remaining budget — spent (committed) + every currently in-flight reservation for
    # this mandate, so a concurrent purchase already holding budget cannot be double-counted
    # as still available.
    checks.append(_check(
        "budget_remaining", amount <= remaining,
        f"{amount:.2f} <= {remaining:.2f} remaining of {mandate.budget_total:.2f}",
    ))

    # 4. merchant allowlist — by id, resolved against the Merchant Wallet Registry
    merchant_ok = bool(
        REGISTRY.is_trusted(decision.chosen.merchant_id)
        and decision.chosen.merchant_id in mandate.allowed_merchants
    )
    checks.append(_check(
        "merchant_allowed", merchant_ok,
        f"{decision.chosen.merchant_id} "
        + ("in allowlist, trusted" if merchant_ok else "NOT in allowlist or untrusted"),
    ))

    # 5. category — must be on the allowlist, and must NOT be on the (belt-and-suspenders)
    # blocklist, which wins even if a category were misconfigured onto both lists.
    cat_ok = decision.chosen.category in mandate.allowed_categories
    checks.append(_check("category_allowed", cat_ok, f"{decision.chosen.category}"))

    blocked_hit = decision.chosen.category in mandate.blocked_categories
    checks.append(_check(
        "category_not_blocked", not blocked_hit,
        f"{decision.chosen.category}" + (" is blocked" if blocked_hit else ""),
    ))

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
    # None = no human-approval threshold configured for this mandate (never require one).
    needs_human = (
        allowed and mandate.require_human_above is not None and amount > mandate.require_human_above
    )

    verdict = PolicyVerdict(
        allowed=allowed and not needs_human,
        checks=checks,
        needs_human=needs_human,
        reason=None if allowed else next(c["name"] for c in checks if not c["passed"]),
        remaining_budget=remaining,
    )
    if verdict.allowed:
        try:
            items = [{"offer_id": decision.chosen.offer_id, "quantity": decision.quantity}]
            leg = _mint_single(mandate, decision.decision_id, decision.chosen.merchant_id, amount, items)
        except ValueError as exc:
            verdict.checks.append(_check("budget_remaining", False, str(exc)))
            verdict.allowed = False
            verdict.reason = "budget_remaining"
        else:
            verdict.spend_intent = leg["spend_intent"]
            verdict.spend_intents = [SpendIntentLeg(
                merchant_id=leg["merchant_id"], amount=leg["amount"], spend_intent=leg["spend_intent"],
            )]
            verdict.procurement_id = decision.decision_id
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
    """The full ordered policy pipeline for a (possibly split-merchant) basket. Implements
    exactly these twelve checks, in exactly this order:
      1. mandate_active    2. agent_active      3. offer_exists
      4. merchant_allowed  5. product_requested  6. category_allowed
      7. quantity_matches  8. stock_available    9. no_denied_items
     10. per_intent_limit 11. delegated_budget  12. currency
    Every fact about a line item (category, stock, title, currency, and the amount actually
    minted) is re-derived from `get_offer()` — a posted offers snapshot
    (POST /offers/snapshot), falling back to product/catalog.json — never taken on faith
    from the proposal itself. A basket may span multiple merchants: each merchant's items
    are grouped into their own subtotal and (if every check passes) their own SpendIntent —
    one checkout, one payment, per merchant leg, all linked by one shared
    `procurement_id`, minted atomically (every leg together, or none)."""
    _remember_mandate(mandate)
    checks: list[dict] = []
    items = proposal.selected_items

    if not items:
        checks.append(_check("has_items", False, "no line items selected"))
        return PolicyVerdict(allowed=False, checks=checks, reason="has_items", remaining_budget=money.ZERO)

    ground_truth: dict[tuple[str, str], Offer | None] = {
        (item.merchant_id, item.sku): get_offer(item.merchant_id, item.sku) for item in items
    }

    def offer_for(item) -> Offer | None:
        return ground_truth[(item.merchant_id, item.sku)]

    already = spent(mandate.mandate_id)
    reserved_now = _reserved_total(mandate.mandate_id)
    merchant_ids = sorted({item.merchant_id for item in items})

    # 1. mandate_active
    alive = datetime.fromisoformat(mandate.expires_at) > datetime.now(timezone.utc)
    checks.append(_check("mandate_active", alive, f"expires {mandate.expires_at}"))

    # 2. agent_active — checked again, independently, immediately before signing in
    # pg.policy_server's /authorize and /authorize-card.
    agent_status = get_agent_status(mandate.mandate_id)
    checks.append(_check("agent_active", agent_status == "ACTIVE", f"agent status: {agent_status}"))

    # 3. offer_exists — every line item, against the ground truth (posted snapshot, else
    # product/catalog.json)
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        offer = offer_for(item)
        checks.append(_check(
            f"offer_exists[{label}]", offer is not None,
            "found" if offer is not None else "no such offer for this merchant",
        ))

    # 4. merchant_allowed — one check per distinct merchant leg
    for merchant_id in merchant_ids:
        merchant_ok = bool(REGISTRY.is_trusted(merchant_id) and merchant_id in mandate.allowed_merchants)
        checks.append(_check(
            f"merchant_allowed[{merchant_id}]", merchant_ok,
            f"{merchant_id} " + ("in allowlist, trusted" if merchant_ok else "NOT in allowlist or untrusted"),
        ))

    # 5. product_requested — the item actually purchased must be something the mandate's
    # buyer actually asked for. An empty mandate.requested_items means this mandate is not
    # scoped to a pre-known shopping list (a general-purpose mandate) — nothing to
    # cross-check, so this (and quantity_matches, below) passes vacuously.
    requested_names = {ri.name.strip().lower() for ri in mandate.requested_items}
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        if not mandate.requested_items:
            checks.append(_check(f"product_requested[{label}]", True, "no requested_items configured on mandate"))
            continue
        was_requested = item.requested_item.name.strip().lower() in requested_names
        checks.append(_check(
            f"product_requested[{label}]", was_requested,
            f"{item.requested_item.name!r} "
            + ("was requested" if was_requested else "was NOT requested by this mandate"),
        ))

    # 6. category_allowed — every line item's ground-truth category
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        offer = offer_for(item)
        if offer is None:
            continue   # offer_exists already failed it; nothing honest to check
        cat_ok = offer.category in mandate.allowed_categories
        checks.append(_check(f"category_allowed[{label}]", cat_ok, f"{offer.category}"))

    # 7. quantity_matches — for each requested product, the TOTAL purchased quantity
    # across every matching line item must EXACTLY equal what was requested (e.g. exactly
    # two chargers and one HDMI cable) — neither a partial fill nor a silent upsell passes.
    if not mandate.requested_items:
        checks.append(_check("quantity_matches", True, "no requested_items configured on mandate"))
    else:
        for ri in mandate.requested_items:
            purchased = sum(
                item.quantity for item in items
                if item.requested_item.name.strip().lower() == ri.name.strip().lower()
            )
            checks.append(_check(
                f"quantity_matches[{ri.name}]", purchased == ri.quantity,
                f"{purchased} selected vs {ri.quantity} requested",
            ))

    # 8. stock_available — ground-truth stock must be a KNOWN count >= the requested
    # quantity. Unknown stock (None) fails CLOSED: never treated as "plenty available".
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        offer = offer_for(item)
        if offer is None:
            continue
        if offer.stock is None:
            checks.append(_check(f"stock_available[{label}]", False, "stock unknown (fails closed)"))
        else:
            checks.append(_check(
                f"stock_available[{label}]", offer.stock >= item.quantity,
                f"{offer.stock} in stock >= {item.quantity} requested",
            ))

    # 9. no_denied_items — the STRUCTURED product fields only, never merchant free text
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        offer = offer_for(item)
        if offer is None:
            continue
        haystack = f"{offer.title} {offer.category} {item.sku}".lower()
        hit = next((k for k in mandate.denied_keywords if k in haystack), None)
        checks.append(_check(f"no_denied_items[{label}]", hit is None,
                              f"blocked term: {hit}" if hit else "clean"))

    # Amounts for every remaining check (and for what is actually minted) are re-derived
    # from the ground-truth offer's price — never the proposal's own claimed unit_price.
    merchant_legs = _group_by_merchant(proposal, ground_truth)
    amount = sum((leg["amount"] for leg in merchant_legs.values()), money.ZERO)
    remaining = mandate.budget_total - already - reserved_now

    # 10. per_intent_limit — a per-leg concern: every merchant checkout is its own
    # payment transaction, checked against its own re-derived subtotal.
    for merchant_id in merchant_ids:
        subtotal = merchant_legs.get(merchant_id, {"amount": money.ZERO})["amount"]
        checks.append(_check(
            f"per_intent_limit[{merchant_id}]", subtotal <= mandate.per_intent_max,
            f"{subtotal:.2f} <= {mandate.per_intent_max:.2f} {mandate.currency}",
        ))

    # 11. delegated_budget — the COMBINED total across every merchant leg counts against
    # one shared remaining balance: committed spend PLUS every other currently in-flight
    # reservation for this mandate, so a concurrent purchase already holding budget cannot
    # be double-counted as still available.
    checks.append(_check(
        "delegated_budget", amount <= remaining,
        f"{amount:.2f} <= {remaining:.2f} remaining of {mandate.budget_total:.2f}",
    ))

    # 12. currency — every line item's ground-truth currency must match the mandate's
    for item in items:
        label = f"{item.merchant_id}:{item.sku}"
        offer = offer_for(item)
        if offer is None:
            continue
        checks.append(_check(f"currency[{label}]", offer.currency == mandate.currency, f"{offer.currency}"))

    allowed = all(c["passed"] for c in checks)
    # None = no human-approval threshold configured for this mandate (never require one).
    needs_human = (
        allowed and mandate.require_human_above is not None and amount > mandate.require_human_above
    )

    verdict = PolicyVerdict(
        allowed=allowed and not needs_human,
        checks=checks,
        needs_human=needs_human,
        reason=None if allowed else next(c["name"] for c in checks if not c["passed"]),
        remaining_budget=remaining,
    )
    if verdict.allowed:
        # Atomic: either every merchant leg is minted and reserved together (all-or-nothing,
        # under one lock acquisition), or none are. A race against another concurrent
        # reservation for the same mandate is only possible here, at the moment budget is
        # actually locked in — the checks above already passed against a point-in-time
        # snapshot that a concurrent request could since have made stale.
        try:
            legs = mint_basket_intents(mandate, proposal)
        except ValueError as exc:
            verdict.checks.append(_check("delegated_budget", False, str(exc)))
            verdict.allowed = False
            verdict.reason = "delegated_budget"
        else:
            verdict.spend_intents = [SpendIntentLeg(**leg) for leg in legs]
            verdict.procurement_id = proposal.decision_id
            if len(legs) == 1:
                verdict.spend_intent = legs[0]["spend_intent"]
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
    """A human decides. Approval mints an intent for THIS purchase only — one per merchant
    leg for a basket, atomically (see `mint_basket_intents()`)."""
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
        # Park the intent(s) here rather than returning them to the human's HTTP client. The
        # human approves; the agent collects. Two different callers, so the intent must
        # survive the approve response. Each is still single-use, so collecting them twice
        # buys nothing.
        if p.get("kind") == "basket":
            legs = mint_basket_intents(p["mandate"], p["decision"])
        else:
            decision = p["decision"]
            items = [{"offer_id": decision.chosen.offer_id, "quantity": decision.quantity}]
            legs = [_mint_single(
                p["mandate"], decision.decision_id, decision.chosen.merchant_id, decision.amount, items,
            )]
        p["spend_intents"] = legs
        p["spend_intent"] = legs[0]["spend_intent"]
        return True, "approved by human", p["spend_intent"]



def collect(approval_id: str) -> str | None:
    """The agent collects the intent a human approved. Returns None unless approved.
    DEPRECATED single-leg view — returns only the first merchant leg's token; a split-
    merchant basket's other legs are only available via `collect_all()`."""
    with _STATE_LOCK:
        p = _PENDING.get(approval_id)
        if not p or p["status"] != "approved":
            return None
        return p.get("spend_intent")


def collect_all(approval_id: str) -> list[dict] | None:
    """The agent collects every merchant leg a human approved. Returns None unless
    approved. Each entry is `{"merchant_id", "amount", "spend_intent"}`."""
    with _STATE_LOCK:
        p = _PENDING.get(approval_id)
        if not p or p["status"] != "approved":
            return None
        return p.get("spend_intents")



# ---------------------------------------------------------------- SpendIntent lifecycle


def _mint(mandate_id: str, procurement_id: str, merchant_id: str, amount: Decimal, items: list[dict]) -> str:
    """Shared minting logic for both the single-item and basket paths. Binds WHO
    (merchant_id), WHAT (items) and HOW MUCH (amount) only — deliberately no wallet, asset,
    network, or chain id. Those are resolved from the Merchant Wallet Registry at
    payment-execution time (`resolve_and_verify_payment()`), never baked in here. This also
    means minting never requires a registered recipient: `evaluate()`/`evaluate_basket()`
    already gated merchant trust via `REGISTRY.is_trusted()` before calling this, so a
    merchant whose settlement wallet FINTECH hasn't onboarded yet can still be approved to
    buy from — it simply cannot be PAID until a recipient is registered."""
    now_ts = int(time.time())
    exp_ts = now_ts + INTENT_TTL_SECONDS
    body = SpendIntent(
        spend_intent_id=str(uuid.uuid4()),
        procurement_id=procurement_id,
        mandate_id=mandate_id,
        merchant_id=merchant_id,
        items=[SpendIntentItem(**i) for i in items],
        amount_xsgd=amount,
        nonce=secrets.token_hex(16),
        status="AUTHORIZED",
        created_at=now_iso(),
        expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat(),
    ).model_dump()
    body["exp"] = exp_ts
    # default=str: `amount_xsgd` is a Decimal, which json.dumps cannot serialize natively.
    # _parse_token() converts it straight back to a Decimal via money.to_xsgd() on read.
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    sig = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}||{sig}"


def _mint_single(
    mandate: Mandate, procurement_id: str, merchant_id: str, amount: Decimal, items: list[dict],
) -> dict:
    """Mint AND atomically reserve exactly one merchant leg — the single-item counterpart
    to `mint_basket_intents()`, sharing the same all-or-nothing budget check
    (`_mint_and_reserve_legs()`). Raises ValueError if reserving `amount` would exceed the
    mandate's currently remaining budget. Returns
    `{"merchant_id", "amount", "spend_intent", "intent_id"}`."""
    ok, reason, legs = _mint_and_reserve_legs(
        mandate, procurement_id, {merchant_id: {"amount": amount, "items": items}},
    )
    if not ok:
        raise ValueError(reason)
    return legs[0]


def mint_intent(mandate: Mandate, decision: Decision) -> str:
    """Bind a fresh SpendIntent to exactly one merchant, one exact amount, one expiry, and
    one single-use nonce, reserving it immediately (state AUTHORIZED) against the
    mandate's budget. The recipient is resolved later, from the registry, at payment
    execution time."""
    items = [{"offer_id": decision.chosen.offer_id, "quantity": decision.quantity}]
    return _mint_single(
        mandate, decision.decision_id, decision.chosen.merchant_id, decision.amount, items,
    )["spend_intent"]


def _group_by_merchant(
    proposal: PurchaseProposal, ground_truth: dict[tuple[str, str], "Offer | None"] | None = None,
) -> dict[str, dict]:
    """Fold a (possibly split-merchant) basket's line items into one leg per distinct
    merchant — same-merchant items are bundled into a single amount and item list; a
    different merchant's items never touch another merchant's total. The amount is
    re-derived from each item's GROUND-TRUTH offer price (a posted snapshot, else
    product/catalog.json via `get_offer()`) — never the proposal's own claimed unit_price —
    falling back to the claimed price only for an item whose offer cannot be resolved at
    all (offer_exists has already failed it; there is nothing honest to charge instead)."""
    legs: dict[str, dict] = {}
    for item in proposal.selected_items:
        offer = (ground_truth or {}).get((item.merchant_id, item.sku))
        if offer is None and ground_truth is None:
            offer = get_offer(item.merchant_id, item.sku)
        unit_price = offer.unit_price_xsgd if offer is not None else item.unit_price
        offer_id = offer.offer_id if offer is not None else item.sku
        leg = legs.setdefault(item.merchant_id, {"amount": money.ZERO, "items": []})
        leg["amount"] += unit_price * item.quantity
        leg["items"].append({"offer_id": offer_id, "quantity": item.quantity})
    return legs


def _mint_and_reserve_legs(
    mandate: Mandate, procurement_id: str, merchant_legs: dict[str, dict],
) -> tuple[bool, str, list[dict]]:
    """Atomically mint AND reserve one SpendIntent per merchant leg, all under one lock
    acquisition: either every leg is created together, or none are. The combined total
    across every leg is checked against spent + every other currently in-flight
    reservation for this mandate — the authoritative, race-proof check, since it happens
    at the exact moment the budget is locked in, not at some earlier point a concurrent
    caller could have since invalidated.

    `merchant_legs` is `{merchant_id: {"amount": Decimal, "items": [{"offer_id",
    "quantity"}, ...]}}`. Returns (True, "", legs) on success — legs is
    [{"merchant_id", "amount", "spend_intent", "intent_id"}, ...], one per merchant, all
    sharing `procurement_id` — or (False, reason, []) if the combined total does not fit
    the mandate's remaining budget. Nothing is minted or reserved on failure."""
    total = sum((leg["amount"] for leg in merchant_legs.values()), money.ZERO)
    with _STATE_LOCK:
        committed = _SPENT.get(mandate.mandate_id, money.ZERO)
        reserved = _reserved_total(mandate.mandate_id)
        remaining = mandate.budget_total - committed - reserved
        if total > remaining:
            return False, (
                f"reserving {total:.2f} across {len(merchant_legs)} merchant leg(s) would "
                f"exceed the mandate's remaining budget ({remaining:.2f})"
            ), []

        legs: list[dict] = []
        for merchant_id, leg in sorted(merchant_legs.items()):
            amount, items = leg["amount"], leg["items"]
            token = _mint(mandate.mandate_id, procurement_id, merchant_id, amount, items)
            parsed = _parse_token(token)
            intent_id, exp = parsed["spend_intent_id"], parsed["exp"]
            _RESERVED[intent_id] = {
                "mandate_id": mandate.mandate_id, "amount": amount, "merchant_id": merchant_id,
                "claimed": False, "exp": exp,
            }
            _INTENT_RECORDS[intent_id] = {
                "spend_intent_id": intent_id, "mandate_id": mandate.mandate_id, "merchant_id": merchant_id,
                "procurement_id": procurement_id, "items": items, "amount_xsgd": amount,
                "currency": mandate.currency, "nonce": parsed["nonce"],
                "exp": exp, "created_at": parsed["created_at"], "updated_at": now_iso(),
                "status": "AUTHORIZED", "detail": None,
            }
            legs.append({"merchant_id": merchant_id, "amount": amount, "spend_intent": token, "intent_id": intent_id})
        return True, "", legs


def mint_basket_intents(mandate: Mandate, proposal: PurchaseProposal) -> list[dict]:
    """Group `proposal`'s line items by merchant and atomically mint + reserve one
    SpendIntent per merchant leg (see `_mint_and_reserve_legs()`). Raises ValueError (never
    partially mints) if the combined total does not fit the mandate's currently remaining
    budget."""
    merchant_legs = _group_by_merchant(proposal)
    ok, reason, legs = _mint_and_reserve_legs(mandate, proposal.decision_id, merchant_legs)
    if not ok:
        raise ValueError(reason)
    return legs


def _parse_token(token: str) -> dict | None:
    try:
        raw, sig = token.split("||")
    except ValueError:
        return None
    expect = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return None
    # `amount_xsgd` was serialized via default=str (see _mint()) since it is a Decimal;
    # convert it straight back so every downstream comparison stays exact Decimal
    # arithmetic.
    if "amount_xsgd" in body:
        body["amount_xsgd"] = money.to_xsgd(body["amount_xsgd"])
    return body


def peek_token(token: str) -> dict | None:
    """Read a SpendIntent token's body WITHOUT reserving, claiming, or consuming anything —
    safe to call purely to attach identifying fields (e.g. `procurement_id`, `merchant_id`)
    to an audit/ledger event before (or regardless of whether) a reservation is ever
    attempted. Still verifies the HMAC signature, so nothing forged is ever returned."""
    return _parse_token(token)


def resolve_and_verify_payment(merchant_id: str, accept: dict) -> MerchantRecord:
    """The ONLY place a payment recipient is resolved for the x402 rail — from the
    Merchant Wallet Registry, at the moment payment is executed, never from the SpendIntent
    (which does not carry pay_to/asset/network/chain_id) and never invented here.

    Checks, in order, and each with its own named failure so the caller can report and
    audit exactly which one fired:
      1. the merchant is registered, allowed, ACTIVE, and has a registered recipient
         (MERCHANT_NOT_REGISTERED / MERCHANT_SUSPENDED / NO_REGISTERED_RECIPIENT — via
         `MerchantRegistry.resolve_recipient()`);
      2. the challenge's network/chainId match this deployment's configured network
         (NETWORK_MISMATCH);
      3. the challenge's asset matches the configured XSGD contract (CURRENCY_MISMATCH);
      4. the challenge's payTo matches the registry's recipient for this merchant, compared
         case-insensitively (RECIPIENT_MISMATCH).

    Returns the resolved MerchantRecord on success; raises RegistryLookupError otherwise.
    """
    rec = REGISTRY.resolve_recipient(merchant_id)   # MERCHANT_NOT_REGISTERED / _SUSPENDED / NO_REGISTERED_RECIPIENT

    network = accept.get("network")
    if network not in ALLOWED_NETWORKS:
        raise RegistryLookupError(
            "NETWORK_MISMATCH", f"network {network} is not one of {sorted(ALLOWED_NETWORKS)}"
        )
    expected_chain_id = int(network.split(":")[1])
    if accept.get("chainId") != expected_chain_id:
        raise RegistryLookupError(
            "NETWORK_MISMATCH", f"chainId {accept.get('chainId')} does not match network {network}"
        )

    asset = accept.get("asset", "")
    if asset.lower() != XSGD_ASSET.lower():
        raise RegistryLookupError(
            "CURRENCY_MISMATCH", f"asset {asset} does not match the configured XSGD contract"
        )

    pay_to = accept.get("payTo", "")
    if pay_to.lower() != rec.payment_recipient:
        raise RegistryLookupError(
            "RECIPIENT_MISMATCH",
            f"accept.payTo {pay_to} does not match the registered recipient for {merchant_id!r}",
        )

    return rec


def reserve_intent(token: str, merchant_id: str, amount: Decimal) -> tuple[bool, str]:
    """Validate the SpendIntent token itself and hold it for exactly one caller.

    This checks ONLY what the intent binds: token validity/expiry, the merchant it was
    minted for, and the exact approved amount. It never touches a wallet, asset, network,
    or chain id — those are resolved and verified separately, by
    `resolve_and_verify_payment()` (x402 rail) or directly against the registry (card
    rail), BEFORE this is called. Nothing is spent and nothing is permanently consumed
    here. On success the caller MUST follow up with exactly one of commit_intent()/
    mark_consumed() (payment succeeded), mark_failed()/mark_denied() (it did not, and
    should release), or mark_reconciliation_required() (the outcome is unknown and the
    reservation must be RETAINED) — until then the intent is held in-flight so a second,
    concurrent caller presenting the same token cannot also reserve it (replay-under-race).

    Returns (True, intent_id) on success, (False, reason) otherwise.

    Every SpendIntent is minted already reserved (state AUTHORIZED, see
    `_mint_and_reserve_legs()`), so the ordinary case here is simply CLAIMING that
    existing reservation. Once an intent reaches a TERMINAL state (EXPIRED, DENIED,
    FAILED, CANCELLED, CONSUMED) it is NEVER reactivated or re-reserved — a retry requires
    a brand new evaluation (evaluate()/evaluate_basket()) producing a brand new
    SpendIntent, never re-presenting this same token.
    """
    body = _parse_token(token)
    if body is None:
        return False, "malformed token or bad signature"

    intent_id = body["spend_intent_id"]

    if time.time() > body["exp"]:
        with _STATE_LOCK:
            _RESERVED.pop(intent_id, None)
        _set_intent_state(intent_id, "EXPIRED", "TTL passed before use")
        return False, "token expired"
    if body["merchant_id"] != merchant_id:
        return False, f"token bound to merchant {body['merchant_id']}, not {merchant_id}"
    if money.to_xsgd(amount) != body["amount_xsgd"]:
        return False, f"amount {amount} does not exactly match approved amount {body['amount_xsgd']}"

    with _STATE_LOCK:
        record = _INTENT_RECORDS.get(intent_id)
        if record is not None and record["status"] in TERMINAL_STATES:
            return False, (
                f"intent is in terminal state {record['status']}; get a new SpendIntent "
                "from a fresh evaluation"
            )
        if intent_id in _COMMITTED:
            return False, "token already used"

        existing = _RESERVED.get(intent_id)
        if existing is not None:
            if existing.get("claimed"):
                return False, "token already reserved (concurrent use)"
            existing["claimed"] = True
            _set_intent_state(intent_id, "AUTHORIZED", "claimed for execution")
            return True, intent_id

        # Every intent is minted already reserved; the only ways `_RESERVED` loses an
        # entry (release_intent, via mark_failed/mark_denied, or _sweep_expired) also set
        # a terminal state, which is already caught above. Fail closed rather than
        # silently re-reserving something with no live reservation.
        return False, "no active reservation for this intent; get a new SpendIntent from a fresh evaluation"


def commit_intent(intent_id: str, detail: str | None = None) -> bool:
    """Payment (or card issuance) succeeded: count the spend, permanently consume the
    intent, and mark it CONSUMED. Called only after the money has actually moved (or the
    card actually issued), never before."""
    with _STATE_LOCK:
        record = _RESERVED.pop(intent_id, None)
        if record is None:
            return False
        _COMMITTED.add(intent_id)
        _SPENT[record["mandate_id"]] = _SPENT.get(record["mandate_id"], money.ZERO) + record["amount"]
        _set_intent_state(intent_id, "CONSUMED", detail)
        return True


def release_intent(intent_id: str) -> bool:
    """Give a reservation back without recording any terminal state — used internally by
    `mark_failed()`/`mark_denied()`. Nothing was spent, and the intent is available again
    (still single-use once it does succeed, but a transient failure does not burn the
    mandate's only shot at this purchase)."""
    with _STATE_LOCK:
        return _RESERVED.pop(intent_id, None) is not None


def claim_settlement_tx_hash(tx_hash: str, intent_id: str) -> bool:
    """Replay protection for independently-verified on-chain settlement: atomically bind
    one real transaction hash to at most one SpendIntent, ever. Returns True if this call
    performed (or already held) the claim for THIS intent_id; returns False if `tx_hash`
    is already linked to a DIFFERENT intent_id — meaning this settlement report is a
    replay of someone else's transaction and must never also consume this intent's
    reservation. Case-insensitive (EVM tx hashes are not case sensitive)."""
    key = tx_hash.strip().lower()
    with _STATE_LOCK:
        existing = _SETTLED_TX_HASHES.get(key)
        if existing is not None and existing != intent_id:
            return False
        _SETTLED_TX_HASHES[key] = intent_id
        return True


# ---------------------------------------------------------------- explicit state transitions


def mark_executing(intent_id: str, detail: str | None = None) -> None:
    """Recipient verified and payment signed (x402), or card issuance about to be
    attempted (card) — NOT YET counted as spent."""
    _set_intent_state(intent_id, "EXECUTING", detail)


def mark_consumed(intent_id: str, detail: str | None = None) -> bool:
    """Settlement verified (x402, via POST /intents/{id}/settled) or the card was actually
    issued (card rail): the ONLY place spend accounting actually happens."""
    return commit_intent(intent_id, detail)


def mark_denied(intent_id: str, detail: str) -> bool:
    """A policy-level refusal at execution time (bad recipient, asset, network, or
    merchant status) — releases the reservation. This intent_id stays DENIED forever; a
    caller who wants to try again must get a NEW SpendIntent from a fresh
    evaluate()/evaluate_basket() call, not reuse this one."""
    released = release_intent(intent_id)
    _set_intent_state(intent_id, "DENIED", detail)
    return released


def mark_failed(intent_id: str, detail: str) -> bool:
    """A definite technical execution failure (signing blew up, the card issuer refused,
    or the merchant reported a definite failure via POST /intents/{id}/failed) — releases
    the reservation and marks it FAILED, a TERMINAL state. This intent_id is done forever;
    a caller who wants to try again must get a NEW SpendIntent from a fresh
    evaluate()/evaluate_basket() call — `reserve_intent()` refuses to ever re-reserve it."""
    released = release_intent(intent_id)
    _set_intent_state(intent_id, "FAILED", detail)
    return released


def mark_reconciliation_required(intent_id: str, detail: str) -> None:
    """The payment's outcome is genuinely unknown (a timeout, or a submission that never
    got a definite answer back). The reservation is DELIBERATELY retained — released or
    committed only once a human/operator resolves the reconciliation — because releasing
    it here could let the same budget be spent twice if the merchant actually did settle
    it."""
    _set_intent_state(intent_id, "RECONCILIATION_REQUIRED", detail)


def get_intent(intent_id: str) -> dict | None:
    """The authoritative, current lifecycle record for one SpendIntent — the read model
    behind GET /intents/{id}. Returns None if this policy engine never minted this
    intent_id."""
    _sweep_expired()
    with _STATE_LOCK:
        rec = _INTENT_RECORDS.get(intent_id)
        return dict(rec) if rec is not None else None


def list_intents(procurement_id: str | None = None, mandate_id: str | None = None) -> list[dict]:
    """Every SpendIntent lifecycle record this policy engine knows about, optionally
    filtered by procurement_id (every leg of one basket shares one) or mandate_id — the
    read model behind GET /intents."""
    _sweep_expired()
    with _STATE_LOCK:
        recs = [dict(r) for r in _INTENT_RECORDS.values()]
    if procurement_id:
        recs = [r for r in recs if r.get("procurement_id") == procurement_id]
    if mandate_id:
        recs = [r for r in recs if r.get("mandate_id") == mandate_id]
    return sorted(recs, key=lambda r: r["created_at"])

