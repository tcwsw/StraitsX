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
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from agent.execution_agent import ProposalValidationError
from pg.models import (
    Decision, Mandate, PurchaseProposal, Quote, RejectedAlternative,
    RequestedItem, SelectedLineItem,
)
from pg.prehook import sanitise
from pg.x402_client import PaymentRefused

REPO_ROOT = Path(__file__).resolve().parent.parent

# Load the repo's .env (if present) BEFORE AGENT_MODE, AUDIT_MODE, OPENAI_MODEL or
# OPENAI_API_KEY are read anywhere below. override=False means a shell environment variable
# that is already set always wins over whatever is in .env.
try:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env", override=False)
except ImportError:
    pass

FINTECH_POLICY_CONFIG = Path(os.environ.get(
    "FINTECH_POLICY_CONFIG", REPO_ROOT / "fintech" / "policy_config.json"
))
DEMO_SCENARIOS_PATH = Path(os.environ.get(
    "DEMO_SCENARIOS_PATH", REPO_ROOT / "product" / "demo_scenarios.json"
))


MERCHANTS_URL = os.environ.get("MERCHANTS_URL", "http://127.0.0.1:4030")
POLICY_URL = os.environ.get("POLICY_URL", "http://127.0.0.1:4020")
ALLOWED_NETWORKS = set(os.environ.get("ALLOWED_NETWORKS", "eip155:43113").split(","))
REPUTATION = {"techstore": 0.94, "gadgethub": 0.88, "quickelectronics": 0.81, "bargainbin": 0.22}
# scripted = deterministic choose() below (default). openai = agent/execution_agent.py.
AGENT_MODE = os.environ.get("AGENT_MODE", "scripted")

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "warn": "\033[93m", "off": "\033[0m"}


def say(msg: str, style: str = "") -> None:
    print(f"{C.get(style, '')}{msg}{C['off']}")


def gather(query: str, merchant_ids: list[str]) -> tuple[list[Quote], list]:
    """Fetch offers and run every response through the pre-hook before anything else sees it."""
    quotes: list[Quote] = []
    reports = []
    with httpx.Client(timeout=10) as http:
        for mid in merchant_ids:
            r = http.get(f"{MERCHANTS_URL}/{mid}/search", params={"q": query})
            if r.status_code != 200:
                continue
            typed, report = sanitise(r.json(), REPUTATION.get(mid, 0.0))
            quotes.extend(typed)
            reports.append(report)
    return quotes, reports


def choose(quotes: list[Quote], need_today: bool) -> tuple[Quote, list[Quote], str]:
    viable = [q for q in quotes if q.in_stock and (q.delivery_days == 0 or not need_today)]
    if not viable:
        raise SystemExit("no viable quote")
    best = min(viable, key=lambda q: (q.price, -q.reputation, q.delivery_days))
    rest = [q for q in quotes if q is not best]
    reason = (
        f"{best.merchant_name} at {best.price:.2f} XSGD, "
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


def gather_basket(requested_items: list[RequestedItem], merchant_ids: list[str]) -> dict[str, list[Quote]]:
    """Per-item quote gathering: item name -> quotes from every merchant, pre-hook applied."""
    quotes_by_item: dict[str, list[Quote]] = {}
    for item in requested_items:
        quotes, _ = gather(item.name, merchant_ids)
        quotes_by_item[item.name] = quotes
    return quotes_by_item


def choose_basket(
    requested_items: list[RequestedItem],
    quotes_by_item: dict[str, list[Quote]],
    require_same_day: bool = True,
) -> PurchaseProposal:
    """Deterministic, pure, no-I/O basket chooser: pick ONE merchant that can supply every
    requested item in stock (and, if required, same-day), then take the cheapest such
    merchant, tie-broken by reputation. For the initial demo every basket is single-merchant
    by construction — there is one checkout and one payment."""
    all_merchants = {q.merchant_id for quotes in quotes_by_item.values() for q in quotes}

    def best_at(merchant_id: str, item: RequestedItem) -> Quote | None:
        candidates = [
            q for q in quotes_by_item.get(item.name, [])
            if q.merchant_id == merchant_id and q.in_stock
            and (not require_same_day or q.delivery_days == 0)
        ]
        return min(candidates, key=lambda q: q.price) if candidates else None

    bundles: dict[str, list[Quote]] = {}
    for merchant_id in all_merchants:
        picks = [best_at(merchant_id, item) for item in requested_items]
        if all(picks):
            bundles[merchant_id] = picks  # type: ignore[assignment]

    if not bundles:
        raise SystemExit("no single merchant can supply the full basket")

    def bundle_total(merchant_id: str) -> float:
        return round(sum(q.price * item.quantity for q, item in zip(bundles[merchant_id], requested_items)), 2)

    chosen_merchant = min(bundles, key=lambda mid: (bundle_total(mid), -bundles[mid][0].reputation))
    chosen_quotes = bundles[chosen_merchant]

    selected_items = [
        SelectedLineItem(
            requested_item=item, merchant_id=chosen_merchant, sku=q.sku,
            unit_price=q.price, quantity=item.quantity,
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


def build_basket_proposal(
    mandate: Mandate,
    requested_items: list[RequestedItem],
    quotes_by_item: dict[str, list[Quote]],
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


def wait_for_human(http: httpx.Client, approval_id: str, timeout: int = 300) -> str | None:
    """Block until a human resolves it. The agent has no way to resolve it itself."""
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        rows = http.get(f"{POLICY_URL}/approvals").json()
        row = next((r for r in rows if r["approval_id"] == approval_id), None)
        if row and row["status"] == "approved":
            print()
            return http.get(f"{POLICY_URL}/approvals/{approval_id}/intent").json()["spend_intent"]
        if row and row["status"] in {"rejected", "expired"}:
            print()
            return None
        dots = (dots + 1) % 4
        print(f"\r    waiting for a human{'.' * dots}   ", end="", flush=True)
        time.sleep(1)
    print()
    return None


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

        # 402 handshake
        url = f"{MERCHANTS_URL}{decision.chosen.checkout_url}"
        body = {"sku": decision.chosen.sku, "quantity": decision.quantity}
        r = http.post(url, json=body)
        if r.status_code != 402:
            say(f"  expected 402, got {r.status_code}", "bad")
            return
        challenge = r.json()
        accept = challenge["accepts"][0]
        say(f"\n  402 PAYMENT REQUIRED  {int(accept['amount']) / 10**6:.2f} XSGD "
            f"-> {accept['payTo']} on {accept['network']}", "dim")

        # This agent holds no key. It forwards the raw challenge and asks to be authorised.
        # The policy engine re-derives the amount, redeems the SpendIntent, and signs.
        auth = http.post(f"{POLICY_URL}/authorize", json={
            "spend_intent": verdict["spend_intent"],
            "merchant_id": decision.chosen.merchant_id,
            "challenge": challenge,
        }).json()
        if not auth["ok"]:
            say(f"  AUTHORIZATION REFUSED: {auth['detail']} — nothing signed", "bad")
            return
        say(f"  policy engine signed EIP-3009 as {auth['signer']} "
            f"for {auth['amount']:.2f} -> {auth['pay_to']}", "dim")

        paid = http.post(url, json=body, headers={"PAYMENT-SIGNATURE": auth["payment_header"]})
        if paid.status_code != 200:
            say(f"  settlement failed: {paid.status_code} {paid.text}", "bad")
            return
        receipt = paid.json()
        say(f"\n  PAID  order {receipt['order_id']}  {describe_settlement(receipt['receipt'])}", "ok")


def buy_basket(proposal: PurchaseProposal, mandate_id: str) -> None:
    """Basket-shaped counterpart to `buy()`. One /evaluate-basket call, one 402 challenge
    for the combined total, one signature, one checkout — all items in one order."""
    merchant_id = next(iter(proposal.merchant_ids))
    with httpx.Client(timeout=30) as http:
        say(f"\n  proposing basket from {merchant_id}: " +
            ", ".join(f"{i.requested_item.name} x{i.quantity} ({i.sku})" for i in proposal.selected_items) +
            f" = {proposal.total_amount:.2f} XSGD", "b")

        verdict = http.post(f"{POLICY_URL}/evaluate-basket", json={
            "mandate_id": mandate_id, "proposal": proposal.model_dump()
        }).json()

        say("\n  POLICY ENGINE", "b")
        for c in verdict["checks"]:
            mark, style = ("PASS", "ok") if c["passed"] else ("FAIL", "bad")
            say(f"    [{mark}] {c['name']:<24} {c['detail']}", style)

        if not verdict["allowed"] and not verdict["needs_human"]:
            say(f"\n  BLOCKED before any signature was produced: {verdict['reason']}", "bad")
            return

        if verdict["needs_human"]:
            aid = verdict["approval_id"]
            say(f"\n  ESCALATED to a human: {proposal.total_amount:.2f} XSGD is above the "
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

        # 402 handshake — one combined challenge for every line item
        url = f"{MERCHANTS_URL}/{merchant_id}/checkout"
        body = {"items": [{"sku": i.sku, "quantity": i.quantity} for i in proposal.selected_items]}
        r = http.post(url, json=body)
        if r.status_code != 402:
            say(f"  expected 402, got {r.status_code}", "bad")
            return
        challenge = r.json()
        accept = challenge["accepts"][0]
        say(f"\n  402 PAYMENT REQUIRED  {int(accept['amount']) / 10**6:.2f} XSGD "
            f"-> {accept['payTo']} on {accept['network']}", "dim")

        auth = http.post(f"{POLICY_URL}/authorize", json={
            "spend_intent": verdict["spend_intent"],
            "merchant_id": merchant_id,
            "challenge": challenge,
        }).json()
        if not auth["ok"]:
            say(f"  AUTHORIZATION REFUSED: {auth['detail']} — nothing signed", "bad")
            return
        say(f"  policy engine signed EIP-3009 as {auth['signer']} "
            f"for {auth['amount']:.2f} -> {auth['pay_to']}", "dim")

        paid = http.post(url, json=body, headers={"PAYMENT-SIGNATURE": auth["payment_header"]})
        if paid.status_code != 200:
            say(f"  settlement failed: {paid.status_code} {paid.text}", "bad")
            return
        receipt = paid.json()
        say(f"\n  PAID  order {receipt['order_id']}  {describe_settlement(receipt['receipt'])}", "ok")


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

    merchants = ["techstore", "gadgethub", "quickelectronics"]
    mandate = Mandate(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=scenario["budget"],
        per_txn_max=fintech["per_txn_max"],
        allowed_categories=fintech["allowed_categories"],
        allowed_merchants=merchants,
        denied_keywords=fintech["denied_keywords"],
        require_human_above=fintech["require_human_above"],
        max_delivery_days=fintech.get("max_delivery_days"),
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    with httpx.Client(timeout=10) as http:
        http.post(f"{POLICY_URL}/mandates", json=mandate.model_dump())
    say(f"mandate {mandate.mandate_id}: {mandate.budget_total:.2f} XSGD, "
        f"max {mandate.per_txn_max:.2f}/txn, human approval above {mandate.require_human_above:.2f}, "
        f"max delivery {mandate.max_delivery_days}d", "b")

    quotes_by_item = gather_basket(requested_items, merchants)
    for item in requested_items:
        say(f"\n  {item.quantity}x {item.name}: {len(quotes_by_item[item.name])} quotes", "dim")
        for q in quotes_by_item[item.name]:
            say(f"    {q.merchant_name:<17} {q.title:<22} {q.price:>6.2f}  "
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

    merchants = ["techstore", "gadgethub", "quickelectronics"]
    allowed = list(merchants)
    if args.attack:
        merchants.append("bargainbin")   # the agent CAN see it; the mandate does not allow it

    mandate = Mandate(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=args.budget,
        per_txn_max=15.0,
        allowed_categories=["electronics", "accessories"],
        allowed_merchants=allowed,
        require_human_above=12.0,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    with httpx.Client(timeout=10) as http:
        http.post(f"{POLICY_URL}/mandates", json=mandate.model_dump())
    say(f"mandate {mandate.mandate_id}: {mandate.budget_total:.2f} XSGD, "
        f"max {mandate.per_txn_max:.2f}/txn, human approval above {mandate.require_human_above:.2f}", "b")

    quotes, reports = gather(args.goal, merchants)

    say("\n  PRE-HOOK", "b")
    for rep in reports:
        style = "bad" if rep.hostile else "dim"
        say(f"    {rep.merchant_id:<18} {rep.items_out}/{rep.items_in} items typed  {rep.summary()}", style)
        for s in rep.signals:
            say(f"      discarded [{s['signal']}] in {s['field']}: \"{s['excerpt'][:70]}...\"", "bad")

    say(f"\n  {len(quotes)} quotes from {len({q.merchant_id for q in quotes})} merchants", "dim")
    for q in quotes:
        say(f"    {q.merchant_name:<17} {q.title:<22} {q.price:>6.2f}  "
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
