"""Execution agent. Searches, compares, decides, then asks the policy engine for permission.

Scripted by default so the demo never depends on an LLM round trip. Swap `choose()` for a
model call when you want the judges to see reasoning; the policy engine does not care which
one you use, which is the whole point.

Run:  python -m agent.run "Buy 2 USB-C chargers and 1 HDMI cable" --budget 80
      python -m agent.run --attack        # visit the hostile merchant
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from agent.execution_agent import ProposalValidationError
from pg.models import (
    Decision, Mandate, Offer, PurchaseProposal, RejectedAlternative,
    RequestedItem, SelectedLineItem,
)
from pg.prehook import sanitise
from pg.x402_client import PaymentRefused

REPO_ROOT = Path(__file__).resolve().parent.parent

# Load ONLY the execution agent's allow-listed keys (OPENAI_API_KEY, OPENAI_MODEL,
# AGENT_MODE, AUDIT_MODE, service URLs) from this process's OWN .env.app. Refuses to
# start (raises) rather than silently continuing if AGENT_PRIVATE_KEY, POLICY_SECRET, or
# RELAYER_PRIVATE_KEY is present anywhere in this process — those belong exclusively to
# pg/policy_server.py, loaded from the separate .env.policy. Must run before
# AGENT_MODE/AUDIT_MODE/OPENAI_* are read anywhere below.
from config.process_env import assert_no_financial_secrets, isolate_execution_agent_env

isolate_execution_agent_env(REPO_ROOT / ".env.app")
assert_no_financial_secrets()

FINTECH_POLICY_CONFIG = Path(os.environ.get(
    "FINTECH_POLICY_CONFIG", REPO_ROOT / "fintech" / "policy_config.json"
))
DEMO_SCENARIOS_PATH = Path(os.environ.get(
    "DEMO_SCENARIOS_PATH", REPO_ROOT / "product" / "demo_scenarios.json"
))


MERCHANTS_URL = os.environ.get("MERCHANTS_URL", "http://127.0.0.1:4030")
POLICY_URL = os.environ.get("POLICY_URL", "http://127.0.0.1:4020")
ALLOWED_NETWORKS = set(os.environ.get("ALLOWED_NETWORKS", "eip155:43113").split(","))
# scripted = deterministic choose() below (default). openai = agent/execution_agent.py.
AGENT_MODE = os.environ.get("AGENT_MODE", "scripted")

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "warn": "\033[93m", "off": "\033[0m"}


def say(msg: str, style: str = "") -> None:
    print(f"{C.get(style, '')}{msg}{C['off']}")


def _reputation_map(http: httpx.Client) -> dict[str, float]:
    """Merchant trust AND reputation come from the Merchant Wallet Registry (FINTECH-owned
    data/merchant_registry.json via the policy engine's read-only GET /merchants/registry),
    never from a hardcoded copy here or from the merchant's own claim about itself."""
    try:
        r = http.get(f"{POLICY_URL}/merchants/registry")
        r.raise_for_status()
        return {m["merchant_id"]: m["reputation"] for m in r.json().get("merchants", [])}
    except httpx.HTTPError:
        return {}


def gather(query: str, merchant_ids: list[str]) -> tuple[list[Offer], list]:
    """Fetch offers and run every response through the pre-hook before anything else sees it."""
    quotes: list[Offer] = []
    reports = []
    with httpx.Client(timeout=10) as http:
        reputation = _reputation_map(http)
        for mid in merchant_ids:
            r = http.get(f"{MERCHANTS_URL}/{mid}/search", params={"q": query})
            if r.status_code != 200:
                continue
            typed, report = sanitise(r.json(), reputation.get(mid, 0.0))
            quotes.extend(typed)
            reports.append(report)
    return quotes, reports


def choose(quotes: list[Offer], need_today: bool) -> tuple[Offer, list[Offer], str]:
    viable = [q for q in quotes if q.in_stock and (q.delivery_days == 0 or not need_today)]
    if not viable:
        raise SystemExit("no viable quote")
    best = min(viable, key=lambda q: (q.unit_price_xsgd, -q.reputation, q.delivery_days))
    rest = [q for q in quotes if q is not best]
    reason = (
        f"{best.merchant_name} at {best.unit_price_xsgd:.2f} XSGD, "
        f"{'same-day' if best.delivery_days == 0 else f'{best.delivery_days}d'} delivery, "
        f"reputation {best.reputation:.2f}. Cheapest in-stock option meeting the delivery constraint."
    )
    return best, rest, reason


def load_fintech_mandate_defaults() -> dict:
    """FINTECH-owned risk limits shared by every mandate (scripted or basket)."""
    cfg = json.loads(FINTECH_POLICY_CONFIG.read_text(encoding="utf-8"))
    return cfg["default_mandate"]


def describe_settlement(receipt_block: dict) -> str:
    """Label a merchant checkout's `receipt` block honestly. `tx_hash` is only a real
    Avalanche transaction hash when `settled_onchain` is true (SETTLE_MODE=onchain); under
    the default SETTLE_MODE=verify the merchant only recovers and validates the EIP-3009
    signature without submitting anything on-chain, so the same field is a verification
    reference, not a transaction hash."""
    tx_hash = receipt_block["tx_hash"]
    if receipt_block.get("settled_onchain"):
        return f"tx {tx_hash}"
    return f"verification reference {tx_hash} (cryptographically verified, not submitted on-chain)"


def gather_basket(requested_items: list[RequestedItem], merchant_ids: list[str]) -> dict[str, list[Offer]]:
    """Per-item quote gathering: item name -> quotes from every merchant, pre-hook applied."""
    quotes_by_item: dict[str, list[Offer]] = {}
    for item in requested_items:
        quotes, _ = gather(item.name, merchant_ids)
        quotes_by_item[item.name] = quotes
    return quotes_by_item


def choose_basket(
    requested_items: list[RequestedItem],
    quotes_by_item: dict[str, list[Offer]],
    require_same_day: bool = True,
) -> PurchaseProposal:
    """Deterministic, pure, no-I/O basket chooser. PREFERS one merchant that can supply
    every requested item in stock (and, if required, same-day) — the cheapest such
    merchant, tie-broken by reputation — so a basket that CAN be a single checkout always
    is one. Only when no single merchant can supply everything does this fall back to a
    split basket: independently, per requested item, the cheapest in-stock (same-day if
    required) merchant for THAT item. Same-merchant items in a split result are still
    bundled into one checkout downstream by the policy engine
    (`pg.policy_engine._group_by_merchant()` / `evaluate_basket()`), which mints one
    SpendIntent per distinct merchant leg."""
    all_merchants = {q.merchant_id for quotes in quotes_by_item.values() for q in quotes}

    def best_at(merchant_id: str, item: RequestedItem) -> Offer | None:
        candidates = [
            q for q in quotes_by_item.get(item.name, [])
            if q.merchant_id == merchant_id and q.in_stock
            and (not require_same_day or q.delivery_days == 0)
        ]
        return min(candidates, key=lambda q: q.unit_price_xsgd) if candidates else None

    bundles: dict[str, list[Offer]] = {}
    for merchant_id in all_merchants:
        picks = [best_at(merchant_id, item) for item in requested_items]
        if all(picks):
            bundles[merchant_id] = picks  # type: ignore[assignment]

    def bundle_total(merchant_id: str) -> Decimal:
        return sum(
            (q.unit_price_xsgd * item.quantity for q, item in zip(bundles[merchant_id], requested_items)),
            Decimal("0.00"),
        )

    if bundles:
        chosen_merchant = min(bundles, key=lambda mid: (bundle_total(mid), -bundles[mid][0].reputation))
        chosen_quotes = bundles[chosen_merchant]

        selected_items = [
            SelectedLineItem(
                requested_item=item, merchant_id=chosen_merchant, sku=q.sku,
                unit_price=q.unit_price_xsgd, quantity=item.quantity,
            )
            for item, q in zip(requested_items, chosen_quotes)
        ]

        rejected: list[RejectedAlternative] = []
        for merchant_id in sorted(all_merchants - {chosen_merchant}):
            if merchant_id in bundles:
                reason = (
                    f"bundle total {bundle_total(merchant_id):.2f} XSGD is more than "
                    f"{chosen_merchant}'s {bundle_total(chosen_merchant):.2f} XSGD"
                )
            else:
                reason = "cannot supply every requested item in stock" + (
                    " same-day" if require_same_day else ""
                )
            rejected.append(RejectedAlternative(merchant_id=merchant_id, reason=reason))

        reason = (
            f"{chosen_merchant} bundles all {len(requested_items)} item(s) for "
            f"{bundle_total(chosen_merchant):.2f} XSGD, the cheapest merchant that can supply "
            f"every line" + (" same-day" if require_same_day else "") + "."
        )
        return PurchaseProposal(
            decision_id="d-" + uuid.uuid4().hex[:8],
            goal=", ".join(f"{i.quantity}x {i.name}" for i in requested_items),
            selected_items=selected_items,
            rejected_alternatives=rejected,
            reasoning=reason,
        )

    # No single merchant can supply every item — split the basket: independently per
    # requested item, take the cheapest in-stock (same-day if required) merchant for that
    # item alone.
    split_selected: list[SelectedLineItem] = []
    split_rejected: list[RejectedAlternative] = []
    for item in requested_items:
        candidates = [
            q for q in quotes_by_item.get(item.name, [])
            if q.in_stock and (not require_same_day or q.delivery_days == 0)
        ]
        if not candidates:
            raise SystemExit(f"no viable quote for {item.name!r}")
        best = min(candidates, key=lambda q: (q.unit_price_xsgd, -q.reputation))
        split_selected.append(SelectedLineItem(
            requested_item=item, merchant_id=best.merchant_id, sku=best.sku,
            unit_price=best.unit_price_xsgd, quantity=item.quantity,
        ))
        for q in candidates:
            if q is best:
                continue
            split_rejected.append(RejectedAlternative(
                requested_item=item, merchant_id=q.merchant_id,
                reason=f"{q.unit_price_xsgd:.2f} XSGD for {item.name} is more than "
                       f"{best.merchant_id}'s {best.unit_price_xsgd:.2f} XSGD",
            ))

    split_merchants = sorted({i.merchant_id for i in split_selected})
    split_reason = (
        "no single merchant can supply every line; split across "
        f"{len(split_merchants)} merchants ({', '.join(split_merchants)}), cheapest "
        "in-stock option per item" + (" same-day" if require_same_day else "") + "."
    )
    return PurchaseProposal(
        decision_id="d-" + uuid.uuid4().hex[:8],
        goal=", ".join(f"{i.quantity}x {i.name}" for i in requested_items),
        selected_items=split_selected,
        rejected_alternatives=split_rejected,
        reasoning=split_reason,
    )


def build_basket_proposal(
    mandate: Mandate,
    requested_items: list[RequestedItem],
    quotes_by_item: dict[str, list[Offer]],
    goal: str,
    mode: str | None = None,
) -> PurchaseProposal:
    """The one router between the deterministic scripted chooser and the OpenAI execution
    agent. Contains no financial policy logic of its own — it only decides which chooser to
    ask; `pg.policy_engine.evaluate_basket()` remains the sole authority on whether the
    resulting `PurchaseProposal` may actually be paid. `mode` defaults to the module-level
    AGENT_MODE (itself read from the environment, .env-aware) so both the CLI and the
    dashboard follow AGENT_MODE unless a caller explicitly overrides it (e.g. tests)."""
    effective_mode = (mode if mode is not None else AGENT_MODE).strip().lower()
    if effective_mode == "scripted":
        return choose_basket(requested_items, quotes_by_item, require_same_day=True)
    if effective_mode == "openai":
        from agent.execution_agent import run as run_openai_agent
        _, proposal = run_openai_agent(mandate, requested_items, quotes_by_item, goal)
        return proposal
    raise ValueError(
        f"unknown AGENT_MODE {effective_mode!r}; expected 'scripted' or 'openai'"
    )


def wait_for_human(
    http: httpx.Client, approval_id: str, timeout: int = 300, want_legs: bool = False,
) -> str | list[dict] | None:
    """Block until a human resolves it. The agent has no way to resolve it itself.
    `want_legs=True` returns every merchant leg (`[{merchant_id, amount, spend_intent}, ...]`,
    for a split-merchant basket); otherwise returns just the first leg's token, unchanged
    for old single-leg callers."""
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        rows = http.get(f"{POLICY_URL}/approvals").json()
        row = next((r for r in rows if r["approval_id"] == approval_id), None)
        if row and row["status"] == "approved":
            print()
            body = http.get(f"{POLICY_URL}/approvals/{approval_id}/intent").json()
            return body.get("spend_intents") or [] if want_legs else body["spend_intent"]
        if row and row["status"] in {"rejected", "expired"}:
            print()
            return None
        dots = (dots + 1) % 4
        print(f"\r    waiting for a human{'.' * dots}   ", end="", flush=True)
        time.sleep(1)
    print()
    return None


def execute_payment(
    http: httpx.Client, spend_intent: str, rail: str, *,
    merchant_id: str, items: list[SelectedLineItem] | None = None,
    sku: str | None = None, quantity: int | None = None,
    cardholder_name: str | None = None,
) -> bool:
    """Unified, rail-agnostic settlement entry point for ONE SpendIntent. This is the only
    function in this file that talks to /authorize, /authorize-card, and the new
    /intents/{id}/settled|failed endpoints — `buy()` and `buy_basket()` both call this
    rather than each re-implementing their own copy of the redemption sequence.

    `spend_intent` (the bearer token) is the only thing that authorizes anything. This
    function never sends amount, wallet, currency, network, or card amount to the policy
    engine — every payment term is re-derived server-side from the token itself, the
    Merchant Wallet Registry, or the merchant's own 402 challenge. `merchant_id`/`items`/
    `sku`/`quantity` here are used ONLY to reach that merchant's own checkout endpoint (an
    external system ProcureGuard does not control) — they are never placed in the
    /authorize or /authorize-card request body.

    rail="x402": 402 handshake -> /authorize (signs, moves the intent to EXECUTING) ->
    merchant settlement -> reports the real outcome to POST /intents/{id}/settled (on a
    200) or POST /intents/{id}/failed (definite=True on a merchant-side rejection,
    definite=False on a network/timeout failure whose outcome is unknown).

    rail="card": /authorize-card issues a single-use StraitsX card. Card issuance IS
    settlement (StraitsX either issues synchronously or does not), so the policy engine
    already commits (CONSUMED) or fails synchronously — nothing further to report here.

    Returns True only for a fully completed, settled payment for THIS leg.
    """
    if rail == "x402":
        url = f"{MERCHANTS_URL}/{merchant_id}/checkout"
        body = ({"items": [{"sku": i.sku, "quantity": i.quantity} for i in items]} if items is not None
                else {"sku": sku, "quantity": quantity})
        r = http.post(url, json=body)
        if r.status_code != 402:
            say(f"  [{merchant_id}] expected 402, got {r.status_code}", "bad")
            return False
        challenge = r.json()
        accept = challenge["accepts"][0]
        say(f"\n  [{merchant_id}] 402 PAYMENT REQUIRED  {int(accept['amount']) / 10**6:.2f} XSGD "
            f"-> {accept['payTo']} on {accept['network']}", "dim")

        # merchant_id/amount are never sent — the policy engine derives both from the
        # SpendIntent token itself.
        auth = http.post(f"{POLICY_URL}/authorize", json={
            "spend_intent": spend_intent, "challenge": challenge,
        }).json()
        if not auth["ok"]:
            say(f"  [{merchant_id}] AUTHORIZATION REFUSED: {auth['detail']} — nothing signed", "bad")
            return False
        say(f"  [{merchant_id}] policy engine signed EIP-3009 as {auth['signer']} "
            f"for {auth['amount']:.2f} -> {auth['pay_to']}", "dim")
        intent_id = auth["intent_id"]

        try:
            paid = http.post(url, json=body, headers={"PAYMENT-SIGNATURE": auth["payment_header"]})
        except httpx.HTTPError as exc:
            # Outcome unknown — the signed payment may or may not have reached the
            # merchant. Flag for reconciliation rather than assuming it failed.
            http.post(f"{POLICY_URL}/intents/{intent_id}/failed", json={
                "reason": f"merchant service unreachable for settlement: {exc}", "definite": False,
            })
            say(f"  [{merchant_id}] merchant unreachable for settlement ({exc}) — flagged for reconciliation", "warn")
            return False

        if paid.status_code != 200:
            # A definite merchant-side rejection of a signed payment.
            http.post(f"{POLICY_URL}/intents/{intent_id}/failed", json={
                "reason": f"merchant settlement returned {paid.status_code}: {paid.text[:200]}", "definite": True,
            })
            say(f"  [{merchant_id}] settlement failed: {paid.status_code} {paid.text}", "bad")
            return False

        receipt = paid.json()
        http.post(f"{POLICY_URL}/intents/{intent_id}/settled", json={
            "tx_hash": receipt["receipt"]["tx_hash"], "network": receipt["receipt"]["network"],
            "order_id": receipt["order_id"],
        })
        say(f"\n  [{merchant_id}] PAID  order {receipt['order_id']}  "
            f"{describe_settlement(receipt['receipt'])}", "ok")
        return True

    if rail == "card":
        # merchant_id/amount are never sent — derived from the SpendIntent token itself.
        card_resp = http.post(f"{POLICY_URL}/authorize-card", json={
            "spend_intent": spend_intent, "cardholder_name": cardholder_name or "",
        }).json()
        if not card_resp["ok"]:
            say(f"  [{merchant_id}] CARD ISSUANCE REFUSED: {card_resp['detail']} — nothing issued", "bad")
            return False
        say(f"\n  [{merchant_id}] CARD ISSUED  {card_resp['card_opaque_id']}  "
            f"{card_resp['amount']:.2f} XSGD", "ok")
        return True

    raise ValueError(f"unknown rail {rail!r} — expected 'x402' or 'card'")


def buy(decision: Decision, mandate_id: str) -> None:
    with httpx.Client(timeout=30) as http:
        say(f"\n  proposing: {decision.chosen.title} x{decision.quantity} "
            f"from {decision.chosen.merchant_name} = {decision.amount:.2f} XSGD", "b")

        verdict = http.post(f"{POLICY_URL}/evaluate", json={
            "mandate_id": mandate_id, "decision": decision.model_dump()
        }).json()

        say("\n  POLICY ENGINE", "b")
        for c in verdict["checks"]:
            mark, style = ("PASS", "ok") if c["passed"] else ("FAIL", "bad")
            say(f"    [{mark}] {c['name']:<18} {c['detail']}", style)

        if not verdict["allowed"] and not verdict["needs_human"]:
            say(f"\n  BLOCKED before any signature was produced: {verdict['reason']}", "bad")
            return

        if verdict["needs_human"]:
            aid = verdict["approval_id"]
            say(f"\n  ESCALATED to a human: {decision.amount:.2f} XSGD is above the "
                f"approval threshold. Approval id {aid}", "warn")
            say(f"    approve:  curl -X POST {POLICY_URL}/approvals/{aid}/approve", "dim")
            say(f"    reject:   curl -X POST {POLICY_URL}/approvals/{aid}/reject", "dim")
            say("    the agent is now blocked. It cannot proceed on its own.", "dim")
            intent = wait_for_human(http, aid)
            if not intent:
                say("\n  NOT APPROVED — nothing signed", "bad")
                return
            say("  human approved this exact purchase", "ok")
            verdict["spend_intent"] = intent

        execute_payment(
            http, verdict["spend_intent"], "x402",
            merchant_id=decision.chosen.merchant_id,
            sku=decision.chosen.sku, quantity=decision.quantity,
        )


def buy_basket(proposal: PurchaseProposal, mandate_id: str) -> None:
    """Basket-shaped counterpart to `buy()`. A basket may span several merchants — one
    /evaluate-basket call produces one SpendIntent per merchant leg
    (`verdict['spend_intents']`), and each leg then runs its own independent 402/authorize/
    settlement cycle via `execute_payment()`. One leg's rejection or payment failure never
    blocks or unwinds any other leg's payment; only the shared `procurement_id` links them
    for audit."""
    items_by_merchant: dict[str, list[SelectedLineItem]] = {}
    for item in proposal.selected_items:
        items_by_merchant.setdefault(item.merchant_id, []).append(item)

    with httpx.Client(timeout=30) as http:
        say(f"\n  proposing basket across {len(items_by_merchant)} merchant(s): " +
            ", ".join(f"{i.requested_item.name} x{i.quantity} ({i.merchant_id}:{i.sku})"
                      for i in proposal.selected_items) +
            f" = {proposal.total_amount:.2f} XSGD", "b")

        verdict = http.post(f"{POLICY_URL}/evaluate-basket", json={
            "mandate_id": mandate_id, "proposal": proposal.model_dump()
        }).json()

        say("\n  POLICY ENGINE", "b")
        for c in verdict["checks"]:
            mark, style = ("PASS", "ok") if c["passed"] else ("FAIL", "bad")
            say(f"    [{mark}] {c['name']:<28} {c['detail']}", style)

        if not verdict["allowed"] and not verdict["needs_human"]:
            say(f"\n  BLOCKED before any signature was produced: {verdict['reason']}", "bad")
            return

        legs = verdict.get("spend_intents") or []
        if verdict["needs_human"]:
            aid = verdict["approval_id"]
            say(f"\n  ESCALATED to a human: {proposal.total_amount:.2f} XSGD is above the "
                f"approval threshold. Approval id {aid}", "warn")
            say(f"    approve:  curl -X POST {POLICY_URL}/approvals/{aid}/approve", "dim")
            say(f"    reject:   curl -X POST {POLICY_URL}/approvals/{aid}/reject", "dim")
            say("    the agent is now blocked. It cannot proceed on its own.", "dim")
            legs = wait_for_human(http, aid, want_legs=True)
            if not legs:
                say("\n  NOT APPROVED — nothing signed", "bad")
                return
            say("  human approved this exact purchase", "ok")

        if not legs:
            say("\n  no SpendIntent leg was minted — nothing to pay", "bad")
            return

        say(f"\n  {len(legs)} merchant leg(s), procurement_id={verdict.get('procurement_id')}", "b")
        results = {}
        for leg in legs:
            merchant_id = leg["merchant_id"]
            ok = execute_payment(
                http, leg["spend_intent"], "x402",
                merchant_id=merchant_id, items=items_by_merchant.get(merchant_id, []),
            )
            results[merchant_id] = ok

        succeeded = [m for m, ok in results.items() if ok]
        failed = [m for m, ok in results.items() if not ok]
        say(f"\n  basket summary: {len(succeeded)}/{len(legs)} leg(s) paid"
            + (f", failed: {', '.join(failed)}" if failed else ""),
            "ok" if not failed else "warn")


def run_basket_scenario(scenario_id: str = "basket_purchase") -> None:
    """PM+FINTECH-composed multi-item basket demo. Every amount, product, delivery
    constraint and expected outcome comes from product/demo_scenarios.json,
    product/catalog.json and fintech/policy_config.json — nothing is hardcoded here."""
    scenarios = json.loads(DEMO_SCENARIOS_PATH.read_text(encoding="utf-8"))["scenarios"]
    scenario = next((s for s in scenarios if s["id"] == scenario_id), None)
    if not scenario:
        raise SystemExit(f"no scenario {scenario_id!r} in {DEMO_SCENARIOS_PATH}")

    fintech = load_fintech_mandate_defaults()
    requested_items = [RequestedItem(**p) for p in scenario["requested_products"]]

    merchants = ["techstore", "gadgethub", "cheapdealsstore"]
    mandate = Mandate(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=scenario["budget"],
        per_intent_max=fintech["per_intent_max"],
        allowed_categories=fintech["allowed_categories"],
        allowed_merchants=merchants,
        denied_keywords=fintech["denied_keywords"],
        require_human_above=fintech["require_human_above"],
        max_delivery_days=fintech.get("max_delivery_days"),
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    with httpx.Client(timeout=10) as http:
        http.post(f"{POLICY_URL}/mandates", json=mandate.model_dump())
    human_threshold = (
        f"{mandate.require_human_above:.2f}" if mandate.require_human_above is not None else "none (no human approval required)"
    )
    say(f"mandate {mandate.mandate_id}: {mandate.budget_total:.2f} XSGD, "
        f"max {mandate.per_intent_max:.2f}/txn, human approval above {human_threshold}, "
        f"max delivery {mandate.max_delivery_days}d", "b")

    quotes_by_item = gather_basket(requested_items, merchants)
    for item in requested_items:
        say(f"\n  {item.quantity}x {item.name}: {len(quotes_by_item[item.name])} quotes", "dim")
        for q in quotes_by_item[item.name]:
            say(f"    {q.merchant_name:<17} {q.title:<22} {q.unit_price_xsgd:>6.2f}  "
                f"{'today' if q.delivery_days == 0 else str(q.delivery_days) + 'd':<6} "
                f"{'in stock' if q.in_stock else 'OUT':<9} rep {q.reputation:.2f}", "dim")

    proposal_goal = ", ".join(f"{i.quantity}x {i.name}" for i in requested_items)
    say(f"\n  execution agent: AGENT_MODE={AGENT_MODE}", "dim")
    try:
        proposal = build_basket_proposal(mandate, requested_items, quotes_by_item, proposal_goal)
    except ProposalValidationError as exc:
        say(f"\n  execution agent proposal rejected: {exc}", "bad")
        return
    except RuntimeError as exc:
        say(f"\n  execution agent failed: {exc}", "bad")
        return
    say(f"\n  chosen: {proposal.reasoning}", "b")

    try:
        buy_basket(proposal, mandate.mandate_id)
    except PaymentRefused as exc:
        say(f"  payment refused by client policy: {exc}", "bad")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("goal", nargs="?", default="usb-c charger")
    ap.add_argument("--budget", type=float, default=30.0)   # the real wallet
    ap.add_argument("--quantity", type=int, default=1)
    ap.add_argument("--attack", action="store_true", help="include the hostile merchant")
    ap.add_argument("--sku", help="force a specific SKU, for scripted demo beats")
    ap.add_argument("--basket", action="store_true",
                     help="run the multi-item basket demo (product/demo_scenarios.json)")
    args = ap.parse_args()

    if args.basket:
        run_basket_scenario()
        return

    merchants = ["techstore", "gadgethub", "cheapdealsstore"]
    allowed = list(merchants)
    if args.attack:
        merchants.append("bargainbin")   # the agent CAN see it; the mandate does not allow it

    mandate = Mandate(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=args.budget,
        per_intent_max=15.0,
        allowed_categories=["electronics", "accessories"],
        allowed_merchants=allowed,
        require_human_above=12.0,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    with httpx.Client(timeout=10) as http:
        http.post(f"{POLICY_URL}/mandates", json=mandate.model_dump())
    say(f"mandate {mandate.mandate_id}: {mandate.budget_total:.2f} XSGD, "
        f"max {mandate.per_intent_max:.2f}/txn, human approval above {mandate.require_human_above:.2f}", "b")

    quotes, reports = gather(args.goal, merchants)

    say("\n  PRE-HOOK", "b")
    for rep in reports:
        style = "bad" if rep.hostile else "dim"
        say(f"    {rep.merchant_id:<18} {rep.items_out}/{rep.items_in} items typed  {rep.summary()}", style)
        for s in rep.signals:
            say(f"      discarded [{s['signal']}] in {s['field']}: \"{s['excerpt'][:70]}...\"", "bad")

    say(f"\n  {len(quotes)} quotes from {len({q.merchant_id for q in quotes})} merchants", "dim")
    for q in quotes:
        say(f"    {q.merchant_name:<17} {q.title:<22} {q.unit_price_xsgd:>6.2f}  "
            f"{'today' if q.delivery_days == 0 else str(q.delivery_days) + 'd':<6} "
            f"{'in stock' if q.in_stock else 'OUT':<9} rep {q.reputation:.2f}", "dim")

    if args.sku:
        best = next((q for q in quotes if q.sku == args.sku), None)
        if not best:
            raise SystemExit(f"sku {args.sku} not in the gathered quotes")
        rest = [q for q in quotes if q is not best]
        reason = f"operator-specified SKU {args.sku} from {best.merchant_name}"
        decision = Decision(
            decision_id="d-" + uuid.uuid4().hex[:8], goal=args.goal,
            chosen=best, rejected=rest, reasoning=reason, quantity=args.quantity,
        )
        try:
            buy(decision, mandate.mandate_id)
        except PaymentRefused as exc:
            say(f"  payment refused by client policy: {exc}", "bad")
        return

    if AGENT_MODE == "openai":
        from agent.execution_agent import ProposalValidationError
        from agent.execution_agent import run as run_execution_agent

        say("\n  EXECUTION AGENT (openai)", "b")
        try:
            _agent_proposal, proposal = run_execution_agent(mandate, quotes, args.goal)
        except ProposalValidationError as exc:
            say(f"  execution agent did not produce a safe proposal: {exc}", "bad")
            return
        say(f"    reasoning: {proposal.reasoning}", "dim")
        try:
            buy_basket(proposal, mandate.mandate_id)
        except PaymentRefused as exc:
            say(f"  payment refused by client policy: {exc}", "bad")
        return

    best, rest, reason = choose(quotes, need_today=True)
    decision = Decision(
        decision_id="d-" + uuid.uuid4().hex[:8], goal=args.goal,
        chosen=best, rejected=rest, reasoning=reason, quantity=args.quantity,
    )
    try:
        buy(decision, mandate.mandate_id)
    except PaymentRefused as exc:
        say(f"  payment refused by client policy: {exc}", "bad")



if __name__ == "__main__":
    main()
