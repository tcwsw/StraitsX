"""The Audit Agent specification, as an executable table.

Every flag audit/audit_agent.py is required to raise appears here as a case with an
expected status. This also proves the model-merge boundary holds: an OpenAI-mode
AuditVerdict can escalate a finding but can never suppress or downgrade one the
deterministic checker independently found.

Run:  python -m tests.audit_matrix
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import tempfile

from audit.audit_agent import AuditEnvelope, AuditVerdict, _merge_verdicts, evaluate_scripted, hash_mandate
from pg.ledger import Ledger
from pg.models import Mandate, PolicyVerdict

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


def verdict(**over) -> PolicyVerdict:
    base = dict(allowed=True, checks=[], needs_human=False, reason=None,
                spend_intent="tok-abc", approval_id=None, remaining_budget=18.0)
    base.update(over)
    return PolicyVerdict(**base)


def envelope(**over) -> AuditEnvelope:
    base = dict(
        mandate_hash="deadbeef" * 8,
        policy_verdict=verdict(),
        spend_intent_id="si-" + uuid.uuid4().hex[:8],
        spend_intent_status="committed",
        approved_amount=12.0,
        observed_amount=12.0,
        expected_recipient="0x1111111111111111111111111111111111111111",
        observed_recipient="0x1111111111111111111111111111111111111111",
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
    base.update(over)
    return AuditEnvelope(**base)


# ---------------------------------------------------------------- required flag cases

FLAG_CASES = [
    # (id, description, envelope, expect_status, expect_flag_or_None)
    ("A0", "clean envelope: everything matches, chain intact",
     envelope(), "PASS", None),

    ("A1", "payment happened, human approval was required, none was recorded",
     envelope(policy_verdict=verdict(needs_human=True, allowed=False)),
     "BLOCK", "payment_without_approval"),

    ("A2", "observed recipient differs from the expected registry wallet",
     envelope(observed_recipient="0x9999999999999999999999999999999999999999"),
     "BLOCK", "wrong_recipient"),

    ("A3", "observed token contract differs from the configured XSGD asset",
     envelope(observed_token="0xBADBADBADBADBADBADBADBADBADBADBADBADBAD"),
     "BLOCK", "wrong_asset"),

    ("A4", "observed chain differs from the expected network",
     envelope(observed_chain="eip155:43114"),
     "BLOCK", "wrong_chain"),

    ("A5", "observed settlement amount differs from the approved amount",
     envelope(observed_amount=20.0),
     "BLOCK", "amount_mismatch"),

    ("A6", "SpendIntent status is expired",
     envelope(spend_intent_status="expired"),
     "BLOCK", "expired_intent"),

    ("A7", "the same nonce was used more than once",
     envelope(nonce_use_count=2),
     "BLOCK", "replay"),

    ("A8", "intent committed but no transaction was ever recorded, still pending",
     envelope(transaction_hash=None, settlement_status="pending"),
     "WARN", "missing_transaction"),

    ("A9", "committed with no transaction and settlement already failed",
     envelope(transaction_hash=None, settlement_status="failed"),
     "BLOCK", "missing_transaction"),

    ("A10", "payment timestamp precedes the human approval timestamp",
     envelope(approval_timestamp="2026-08-15T10:00:00+00:00",
              payment_timestamp="2026-08-15T09:00:00+00:00"),
     "BLOCK", "payment_preceding_approval"),

    ("A11", "the hash-chained ledger itself failed verification",
     envelope(hash_chain_ok=False, hash_chain_message="tampered entry at seq 4"),
     "BLOCK", "broken_ledger_chain"),

    ("A12", "settlement lookup could not find the claimed transaction on-chain",
     envelope(settlement_status="not_found"),
     "BLOCK", "unmatched_onchain_transaction"),
]


def hash_mandate_cases() -> list[tuple]:
    m1 = Mandate(
        mandate_id="m-1", principal="Team ProcureGuard", budget_total=30.0, per_intent_max=15.0,
        allowed_categories=["electronics"], allowed_merchants=["techstore"],
        require_human_above=12.0,
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    )
    m2 = m1.model_copy(update={"budget_total": Decimal("999.00")})
    return [
        ("H1", "hashing the same mandate twice is stable", hash_mandate(m1) == hash_mandate(m1), True),
        ("H2", "hashing a different mandate produces a different hash", hash_mandate(m1) != hash_mandate(m2), True),
    ]


def ledger_verify_cases() -> list[tuple]:
    """pg.ledger.Ledger.verify() is the actual hash-chain tamper-detector `GET /audit`
    calls — build one in a throwaway temp file (never the real audit/ledger.jsonl) so this
    never grows the repo's real ledger."""
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ledger.jsonl")
        ledger = Ledger(path=path)
        ledger.append("mandate_registered", "human", {"mandate_id": "m-1"})
        ledger.append("procurement_request", "execution_agent", {"procurement_id": "p-1"})
        ledger.append("policy_verdict", "policy_engine", {"allowed": True})

        ok, msg = ledger.verify()
        out.append(("H3", "a freshly built, untampered hash chain verifies intact",
                   (ok, msg), (True, "chain intact")))

        # Tamper with the middle entry's data in place, leaving its recorded "hash" field
        # untouched — exactly what an attacker editing the file directly would produce.
        with open(path) as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        lines[1]["data"]["procurement_id"] = "p-TAMPERED"
        with open(path, "w") as fh:
            for entry in lines:
                fh.write(json.dumps(entry, default=str) + "\n")

        tampered_ok, tampered_msg = ledger.verify()
        out.append(("H4", "editing a past entry's data breaks the chain, is detected as tampered",
                   (tampered_ok, "tampered entry" in tampered_msg), (False, True)))

    return out


# ---------------------------------------------------------------- merge-logic cases
# The model is untrusted for anything security-relevant: it can escalate, but a deterministic
# BLOCK/flag can never be talked away.

def merge_cases() -> list[tuple]:
    out = []

    deterministic_block = evaluate_scripted(envelope(observed_recipient="0x9999999999999999999999999999999999999999"))
    model_says_pass = AuditVerdict(status="PASS", risk_score=0.0, flags=[],
                                    explanation="looks fine to me", recommended_action="none needed")
    merged = _merge_verdicts(deterministic_block, model_says_pass)
    out.append(("G1", "model claims PASS but deterministic found wrong_recipient: BLOCK still wins",
               merged.status == "BLOCK" and "wrong_recipient" in merged.flags, True))

    deterministic_pass = evaluate_scripted(envelope())
    model_escalates = AuditVerdict(status="WARN", risk_score=0.4, flags=["unusual_timing_pattern"],
                                    explanation="timing looks off", recommended_action="review manually")
    merged2 = _merge_verdicts(deterministic_pass, model_escalates)
    out.append(("G2", "model escalates a clean deterministic result to WARN: escalation is kept",
               merged2.status == "WARN" and "unusual_timing_pattern" in merged2.flags, True))

    deterministic_replay = evaluate_scripted(envelope(nonce_use_count=3))
    model_downplays = AuditVerdict(status="WARN", risk_score=0.2, flags=[],
                                    explanation="probably a retry, not a big deal",
                                    recommended_action="no action")
    merged3 = _merge_verdicts(deterministic_replay, model_downplays)
    out.append(("G3", "model downplays a replay to WARN: deterministic BLOCK still wins",
               merged3.status == "BLOCK" and "replay" in merged3.flags, True))

    return out


def run() -> int:
    failures = 0
    print(f"\n{C['b']}AUDIT MATRIX — required flag detection{C['off']}")
    print(f"{C['dim']}{'id':<5}{'expect':<10}{'result':<10}case{C['off']}")
    for cid, desc, env, expect_status, expect_flag in FLAG_CASES:
        v = evaluate_scripted(env)
        ok = v.status == expect_status
        if expect_flag:
            ok = ok and expect_flag in v.flags
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{expect_status:<10}{v.status:<10}{desc}{C['dim']} -> flags={v.flags}{C['off']}  [{mark}]")

    print(f"\n{C['b']}AUDIT MATRIX — mandate hashing{C['off']}")
    for cid, desc, got, expect in hash_mandate_cases():
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<10}{str(got):<10}{desc}  [{mark}]")

    print(f"\n{C['b']}AUDIT MATRIX — ledger hash-chain verify() / tamper detection{C['off']}")
    for cid, desc, got, expect in ledger_verify_cases():
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<24}{str(got):<24}{desc}  [{mark}]")

    print(f"\n{C['b']}AUDIT MATRIX — merge logic (model cannot suppress a deterministic finding){C['off']}")
    for cid, desc, got, expect in merge_cases():
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<10}{str(got):<10}{desc}  [{mark}]")

    total = len(FLAG_CASES) + 2 + 2 + 3
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
