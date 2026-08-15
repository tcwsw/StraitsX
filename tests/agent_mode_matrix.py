"""AGENT_MODE / execution-agent wiring, as an executable table.

Everything here mocks `agents.Runner.run_sync` — it makes NO real OpenAI network calls.
Covers: the scripted/openai router (`agent.run.build_basket_proposal`), the OpenAI execution
agent's input contract (`agent/execution_agent.py`) and the trust boundary its controller
enforces (missing/duplicate/unknown selections, multi-merchant, model-authored numbers being
ignored), plus proof that an `AUDIT_MODE=openai` Audit Agent result can never suppress a
deterministic flag.

Run:  python -m tests.agent_mode_matrix
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agents  # the real openai-agents package; only Runner.run_sync is ever mocked below

import agent.execution_agent as ea
import agent.run as agent_run
import audit.audit_agent as audit_agent
from pg.models import Mandate, PolicyVerdict, Quote, RequestedItem

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


# ---------------------------------------------------------------- shared fixtures/helpers

@contextmanager
def env_var(name: str, value: str | None):
    """Set (or delete, if value is None) an environment variable for the duration of the
    block, then restore whatever was there before — regardless of the ambient environment."""
    had = name in os.environ
    old = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        if had:
            os.environ[name] = old
        else:
            os.environ.pop(name, None)


@contextmanager
def fake_runner(result=None, error: Exception | None = None):
    """Replace `agents.Runner` with a fake whose `run_sync` records every call and returns
    (or raises) exactly what the test wants — no real OpenAI network call is ever made."""
    calls: list[tuple] = []

    class _FakeRunner:
        @classmethod
        def run_sync(cls, agent, input_str, **kwargs):
            calls.append((agent, input_str))
            if error is not None:
                raise error
            return SimpleNamespace(final_output=result)

    original = agents.Runner
    agents.Runner = _FakeRunner
    try:
        yield calls
    finally:
        agents.Runner = original


def mandate(**over) -> Mandate:
    base = dict(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=30.0,
        per_txn_max=15.0,
        allowed_categories=["electronics", "accessories"],
        allowed_merchants=["techstore", "gadgethub", "quickelectronics"],
        require_human_above=12.0,
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
        max_delivery_days=0,
    )
    base.update(over)
    return Mandate(**base)


def _quote(merchant_id, sku, title, price, delivery_days=0, in_stock=True,
           category="electronics", reputation=0.9) -> Quote:
    return Quote(
        merchant_id=merchant_id, merchant_name=merchant_id.title(), sku=sku, title=title,
        category=category, price=price, delivery_days=delivery_days, in_stock=in_stock,
        reputation=reputation, checkout_url=f"/{merchant_id}/checkout",
    )


REQUESTED = [
    RequestedItem(name="usb-c charger", quantity=2),
    RequestedItem(name="wireless mouse", quantity=1),
]


def quotes_by_item_single_merchant() -> dict[str, list[Quote]]:
    """techstore can supply both lines (cheapest, same-day); gadgethub also offers both, so
    a model that ignores the single-merchant rule has a real (wrong) option to pick."""
    return {
        "usb-c charger": [
            _quote("techstore", "TS-USBC-65", "USB-C 65W Charger", 8.50),
            _quote("gadgethub", "GH-USBC-65", "USB-C 65W Charger", 7.20, delivery_days=2),
        ],
        "wireless mouse": [
            _quote("techstore", "TS-MOUSE-WL", "Wireless Mouse", 3.50, category="accessories"),
            _quote("gadgethub", "GH-MOUSE-WL", "Wireless Mouse", 3.00, delivery_days=2, category="accessories"),
        ],
    }


# quote_id assignment is deterministic given dict/list insertion order:
#   q0 = techstore usb-c charger (requested_item_index 0)
#   q1 = gadgethub usb-c charger (requested_item_index 0)
#   q2 = techstore wireless mouse (requested_item_index 1)
#   q3 = gadgethub wireless mouse (requested_item_index 1)


# ---------------------------------------------------------------- controller validation cases
# These call agent.execution_agent.validate_and_build_proposal() directly against crafted
# model outputs — proving the trust boundary holds regardless of what a model claims.

def validation_cases() -> list[tuple]:
    quotes_by_item = quotes_by_item_single_merchant()
    _for_agent, catalogue, quote_item_index = ea._assign_quote_ids(REQUESTED, quotes_by_item)
    out = []

    # V1: model tries to author quantity/price/sku — the schema has no field for them, so
    # they are silently dropped; the controller re-derives the truth regardless.
    tampered = ea.AgentPurchaseProposal.model_validate({
        "selected_items": [
            {"requested_item_index": 0, "quote_id": "q0",
             "sku": "FAKE-SKU", "unit_price": 0.01, "quantity": 999, "total_xsgd": 0.01},
            {"requested_item_index": 1, "quote_id": "q2",
             "sku": "FAKE-SKU-2", "unit_price": 0.01, "quantity": 999},
        ],
        "reasoning": "cheapest bundle",
    })
    proposal = ea.validate_and_build_proposal(tampered, catalogue, quote_item_index, REQUESTED, "test goal")
    ok = (
        proposal.selected_items[0].sku == "TS-USBC-65" and proposal.selected_items[0].unit_price == 8.50
        and proposal.selected_items[0].quantity == 2
        and proposal.selected_items[1].sku == "TS-MOUSE-WL" and proposal.selected_items[1].quantity == 1
        and proposal.total_amount == round(8.50 * 2 + 3.50 * 1, 2)
    )
    out.append(("V1", "model-authored quantity/price/sku are ignored; controller re-derives the truth", ok, True))

    # V2: unknown quote_id is rejected
    bad = ea.AgentPurchaseProposal(selected_items=[
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q0"),
        ea.AgentSelectedItem(requested_item_index=1, quote_id="q-never-offered"),
    ], reasoning="x")
    rejected = False
    try:
        ea.validate_and_build_proposal(bad, catalogue, quote_item_index, REQUESTED, "goal")
    except ea.ProposalValidationError:
        rejected = True
    out.append(("V2", "unknown quote_id is rejected", rejected, True))

    # V3: missing a selection for one requested item
    missing = ea.AgentPurchaseProposal(selected_items=[
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q0"),
    ], reasoning="x")
    rejected = False
    try:
        ea.validate_and_build_proposal(missing, catalogue, quote_item_index, REQUESTED, "goal")
    except ea.ProposalValidationError:
        rejected = True
    out.append(("V3", "missing requested-item selection is rejected", rejected, True))

    # V4: duplicate selections for the same requested item
    dup = ea.AgentPurchaseProposal(selected_items=[
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q0"),
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q1"),
    ], reasoning="x")
    rejected = False
    try:
        ea.validate_and_build_proposal(dup, catalogue, quote_item_index, REQUESTED, "goal")
    except ea.ProposalValidationError:
        rejected = True
    out.append(("V4", "duplicate requested-item selection is rejected", rejected, True))

    # V5: a legitimate per-item match that spans two merchants is still rejected
    multi = ea.AgentPurchaseProposal(selected_items=[
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q0"),   # techstore
        ea.AgentSelectedItem(requested_item_index=1, quote_id="q3"),   # gadgethub
    ], reasoning="x")
    rejected = False
    try:
        ea.validate_and_build_proposal(multi, catalogue, quote_item_index, REQUESTED, "goal")
    except ea.ProposalValidationError:
        rejected = True
    out.append(("V5", "multi-merchant selection is rejected", rejected, True))

    # V6: quote_id genuinely belongs to a different requested item than claimed
    misbound = ea.AgentPurchaseProposal(selected_items=[
        ea.AgentSelectedItem(requested_item_index=1, quote_id="q0"),   # q0 belongs to item 0, not 1
        ea.AgentSelectedItem(requested_item_index=0, quote_id="q2"),
    ], reasoning="x")
    rejected = False
    try:
        ea.validate_and_build_proposal(misbound, catalogue, quote_item_index, REQUESTED, "goal")
    except ea.ProposalValidationError:
        rejected = True
    out.append(("V6", "quote claimed for the wrong requested_item_index is rejected", rejected, True))

    return out


# ---------------------------------------------------------------- router + Runner-mocked cases

def runner_cases() -> list[tuple]:
    out = []
    quotes_by_item = quotes_by_item_single_merchant()
    m = mandate()
    goal = "2x usb-c charger, 1x wireless mouse"

    good_output = ea.AgentPurchaseProposal(
        selected_items=[
            ea.AgentSelectedItem(requested_item_index=0, quote_id="q0"),
            ea.AgentSelectedItem(requested_item_index=1, quote_id="q2"),
        ],
        reasoning="techstore bundles both items for the lowest total, same-day",
    )

    # R1: scripted mode never invokes Runner, even with a key present
    with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), fake_runner(result=good_output) as calls:
        proposal = agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="scripted")
        ok = len(calls) == 0 and proposal is not None
        out.append(("R1", "scripted mode never invokes Runner", ok, True))

    # R2: openai mode invokes Runner exactly once and the validated proposal is single-merchant
    with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), fake_runner(result=good_output) as calls:
        proposal = agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="openai")
        ok = len(calls) == 1 and set(proposal.merchant_ids) == {"techstore"}
        out.append(("R2", "openai mode invokes Runner exactly once", ok, True))

    # R3: the user goal and exact requested quantities reach the model payload
    with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), fake_runner(result=good_output) as calls:
        agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="openai")
        sent = json.loads(calls[0][1])
        pr = sent["procurement_request"]
        ok = (
            pr["goal"] == goal
            and pr["requested_items"][0]["quantity"] == 2
            and pr["requested_items"][0]["name"] == "usb-c charger"
            and pr["requested_items"][1]["quantity"] == 1
            and pr["requested_items"][1]["name"] == "wireless mouse"
        )
        out.append(("R3", "goal and exact requested quantities reach the model payload", ok, True))

    # R4: missing OPENAI_API_KEY fails clearly, before any Runner call (and thus before any
    # policy/payment step, since build_basket_proposal is always called first).
    with env_var("OPENAI_API_KEY", None), fake_runner(result=good_output) as calls:
        raised = False
        try:
            agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="openai")
        except RuntimeError:
            raised = True
        ok = raised and len(calls) == 0
        out.append(("R4", "missing OPENAI_API_KEY fails clearly before Runner/policy/payment", ok, True))

    # R5: a failing model call produces no proposal at all — nothing for a caller to hand
    # to the policy engine, so no SpendIntent can ever be requested for it.
    with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), \
         fake_runner(error=RuntimeError("simulated model backend failure")) as calls:
        raised = False
        try:
            agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="openai")
        except RuntimeError:
            raised = True
        ok = raised and len(calls) == 1
        out.append(("R5", "model failure raises; no proposal is produced to send to policy/payment", ok, True))

    # R6: any other mode fails with a clear error, without touching Runner
    with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), fake_runner(result=good_output) as calls:
        raised = False
        try:
            agent_run.build_basket_proposal(m, REQUESTED, quotes_by_item, goal, mode="not-a-real-mode")
        except ValueError:
            raised = True
        ok = raised and len(calls) == 0
        out.append(("R6", "an unknown AGENT_MODE fails with a clear error", ok, True))

    return out


# ---------------------------------------------------------------- Audit Agent independence

def audit_cases() -> list[tuple]:
    verdict = PolicyVerdict(allowed=True, checks=[], needs_human=False, reason=None,
                             spend_intent="tok-abc", approval_id=None, remaining_budget=18.0)
    envelope = audit_agent.AuditEnvelope(
        mandate_hash="deadbeef" * 8,
        policy_verdict=verdict,
        spend_intent_id="si-test",
        spend_intent_status="committed",
        approved_amount=12.0,
        observed_amount=12.0,
        expected_recipient="0x1111111111111111111111111111111111111111",
        observed_recipient="0x9999999999999999999999999999999999999999",   # wrong recipient
        expected_token="0xd769410dC8772695A7F55a304d2125320A65c2A5",
        observed_token="0xd769410dC8772695A7F55a304d2125320A65c2A5",
        expected_chain="eip155:43113",
        observed_chain="eip155:43113",
        nonce_use_count=1,
        approval_timestamp=None,
        payment_timestamp="2026-08-15T10:00:00+00:00",
        transaction_hash="0xTX123abc",
        settlement_status="settled",
        hash_chain_ok=True,
        hash_chain_message="chain intact",
    )
    suppressing_output = audit_agent.AuditVerdict(
        status="PASS", risk_score=0.0, flags=[],
        explanation="looks fine to me, nothing suspicious",
        recommended_action="no action needed",
    )

    original_mode = audit_agent.AUDIT_MODE
    audit_agent.AUDIT_MODE = "openai"
    try:
        with env_var("OPENAI_API_KEY", "sk-test-fake-key-not-real"), fake_runner(result=suppressing_output) as calls:
            merged = audit_agent.run_audit(envelope)
            ok = merged.status == "BLOCK" and "wrong_recipient" in merged.flags and len(calls) == 1
    finally:
        audit_agent.AUDIT_MODE = original_mode

    return [("AU1", "AUDIT_MODE=openai result cannot suppress a deterministic BLOCK/flag", ok, True)]


def run() -> int:
    failures = 0

    v_cases = validation_cases()
    r_cases = runner_cases()
    a_cases = audit_cases()

    print(f"\n{C['b']}AGENT MODE MATRIX — controller validation (no Runner involved){C['off']}")
    print(f"{C['dim']}{'id':<5}{'expect':<8}{'result':<8}case{C['off']}")
    for cid, desc, got, expect in v_cases:
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<8}{str(got):<8}{desc}  [{mark}]")

    print(f"\n{C['b']}AGENT MODE MATRIX — router + mocked Runner.run_sync{C['off']}")
    for cid, desc, got, expect in r_cases:
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<8}{str(got):<8}{desc}  [{mark}]")

    print(f"\n{C['b']}AGENT MODE MATRIX — Audit Agent independence{C['off']}")
    for cid, desc, got, expect in a_cases:
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<8}{str(got):<8}{desc}  [{mark}]")

    total = len(v_cases) + len(r_cases) + len(a_cases)
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
