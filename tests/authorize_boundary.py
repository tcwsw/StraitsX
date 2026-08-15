"""The financial authorization boundary, as an executable table.

Everything in tests/policy_matrix.py proves the POLICY is correct: which purchases are
allowed in principle. This file proves the AUTHORIZATION BOUNDARY is correct: that a
SpendIntent the policy engine already approved cannot be redirected, re-priced, replayed,
or double-spent on its way to a signature or a card. This is the boundary a compromised or
merely buggy execution agent sits behind — it is the one that has to hold even if the agent
forwards a tampered 402 challenge on purpose.

Run:  python -m tests.authorize_boundary
"""
from __future__ import annotations

import os
import sys
import threading
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins.
os.environ.setdefault("POLICY_SECRET", "test-only-authorize-boundary-secret-do-not-use")

from eth_account import Account
from fastapi.testclient import TestClient

from pg import policy_engine as pe
from pg import policy_server as ps
from tests.policy_matrix import C, decision, mandate, quote

client = TestClient(ps.app)

# A throwaway signing key so the "happy path" retries in A5/A6 have something real to sign
# with. Never used for anything but this test process.
os.environ.setdefault("AGENT_PRIVATE_KEY", Account.create().key.hex())


def build_accept(*, amount: float, network: str | None = None, asset: str | None = None,
                 pay_to: str | None = None, chain_id: int | None = None) -> dict:
    network = network or pe.expected_network()
    asset = asset or pe.XSGD_ASSET
    pay_to = pay_to or pe.REGISTRY.get("techstore").payment_recipient
    chain_id = int(network.split(":")[1]) if chain_id is None else chain_id
    return {
        "scheme": "exact",
        "network": network,
        "amount": str(int(round(amount * 10 ** 6))),
        "asset": asset,
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "chainId": chain_id,
        "extra": {"assetTransferMethod": "eip3009", "name": "XSGD", "version": "2"},
    }


def _authorize(spend_intent: str, merchant_id: str, accept: dict) -> dict:
    return client.post("/authorize", json={
        "spend_intent": spend_intent,
        "challenge": {"accepts": [accept]},
    }).json()


def _authorize_card(spend_intent: str, merchant_id: str, amount: float) -> dict:
    return client.post("/authorize-card", json={
        "spend_intent": spend_intent, "cardholder_name": "Test Person",
    }).json()


def _settle(intent_id: str) -> dict:
    return client.post(f"/intents/{intent_id}/settled", json={"tx_hash": "0x" + "ab" * 32}).json()


# ---------------------------------------------------------------- cases


def case_recipient_substitution() -> tuple[bool, str]:
    """A merchant (or an attacker in the middle) quotes a payTo that is not the wallet WE
    have on file for this merchant. Must be refused before anything is spent or signed."""
    m, d = mandate(), decision(quote(merchant_id="techstore", price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)
    attacker_wallet = "0x9999999999999999999999999999999999999999"
    body = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50, pay_to=attacker_wallet))
    ok = (not body["ok"]) and pe.spent(m.mandate_id) == before
    return ok, body.get("detail", "")


def case_wrong_token_contract() -> tuple[bool, str]:
    """The challenge names a token contract that is not the configured XSGD contract."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)
    fake_asset = "0xBADBADBADBADBADBADBADBADBADBADBADBADBAD"
    body = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50, asset=fake_asset))
    ok = (not body["ok"]) and pe.spent(m.mandate_id) == before
    return ok, body.get("detail", "")


def case_wrong_chain() -> tuple[bool, str]:
    """chainId does not match the network in the same accept entry."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)
    body = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50, chain_id=999999))
    ok = (not body["ok"]) and pe.spent(m.mandate_id) == before
    return ok, body.get("detail", "")


def case_exact_amount_mismatch() -> tuple[bool, str]:
    """The 402 quotes one cent more than the SpendIntent was minted for. <= max is not
    good enough any more — it must match exactly."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)
    body = _authorize(v.spend_intent, "techstore", build_accept(amount=8.51))
    ok = (not body["ok"]) and pe.spent(m.mandate_id) == before
    return ok, body.get("detail", "")


def case_failed_signing_does_not_consume() -> tuple[bool, str]:
    """Signing blows up (HSM offline, whatever). The reservation must be released, FAILED
    is TERMINAL, and the SAME token must never be re-reserved — a retry requires a brand
    new evaluation producing a brand new SpendIntent. A signature alone — even a
    successful one — must not itself consume the intent: spend only becomes real once
    merchant settlement is reported via POST /intents/{id}/settled."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)
    accept = build_accept(amount=8.50)

    real_sign_payment = ps.sign_payment

    def boom(*_a, **_kw):
        raise RuntimeError("signer unreachable")

    ps.sign_payment = boom
    try:
        first = _authorize(v.spend_intent, "techstore", accept)
    finally:
        ps.sign_payment = real_sign_payment

    mid_spent = pe.spent(m.mandate_id)
    same_token_retry = _authorize(v.spend_intent, "techstore", accept)
    after_same_token_spent = pe.spent(m.mandate_id)

    v2 = pe.evaluate(m, d)
    second = _authorize(v2.spend_intent, "techstore", accept)
    after_sign_spent = pe.spent(m.mandate_id)
    settled = _settle(second.get("intent_id", "")) if second.get("ok") else {}
    after_settle_spent = pe.spent(m.mandate_id)

    ok = (
        not first["ok"] and mid_spent == before
        and not same_token_retry["ok"] and after_same_token_spent == before
        and second["ok"] and after_sign_spent == before
        and settled.get("ok") and after_settle_spent == before + Decimal("8.50")
    )
    return ok, (
        f"first={first.get('detail')!r} same_token_retry_ok={same_token_retry['ok']} "
        f"new_intent_ok={second['ok']} "
        f"spent {before}->{mid_spent}->{after_same_token_spent}->{after_sign_spent}->{after_settle_spent}"
    )


def case_failed_card_issuance_does_not_consume() -> tuple[bool, str]:
    """Card issuance is refused by the issuer. The reservation must be released, FAILED is
    TERMINAL, and the SAME token must never be re-reserved — a retry requires a brand new
    evaluation producing a brand new SpendIntent."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)

    real_issue = ps.card_adapter.issue

    def boom(_amount, _name, _wallet):
        raise ps.card_adapter.CardRefused("issuer offline")

    ps.card_adapter.issue = boom
    try:
        first = _authorize_card(v.spend_intent, "techstore", 8.50)
    finally:
        ps.card_adapter.issue = real_issue

    mid_spent = pe.spent(m.mandate_id)
    same_token_retry = _authorize_card(v.spend_intent, "techstore", 8.50)
    after_same_token_spent = pe.spent(m.mandate_id)

    v2 = pe.evaluate(m, d)
    second = _authorize_card(v2.spend_intent, "techstore", 8.50)
    after_spent = pe.spent(m.mandate_id)

    ok = (
        not first["ok"] and mid_spent == before
        and not same_token_retry["ok"] and after_same_token_spent == before
        and second["ok"] and after_spent == before + Decimal("8.50")
    )
    return ok, (
        f"first={first.get('detail')!r} same_token_retry_ok={same_token_retry['ok']} "
        f"new_intent_ok={second['ok']} spent {before}->{mid_spent}->{after_same_token_spent}->{after_spent}"
    )


def case_concurrent_replay() -> tuple[bool, str]:
    """Two callers present the exact same SpendIntent at the same instant. Exactly one may
    reserve it; the other must be refused, even under a race."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)

    results: list[tuple[bool, str]] = []
    barrier = threading.Barrier(2)

    def attempt() -> None:
        barrier.wait()
        results.append(pe.reserve_intent(v.spend_intent, "techstore", 8.50))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0]]
    if successes:
        pe.commit_intent(successes[0][1])

    ok = len(successes) == 1
    return ok, f"successes={len(successes)} of {len(results)} concurrent reservations"


def case_executing_then_settled() -> tuple[bool, str]:
    """GET /intents/{id} reports the real backend lifecycle: AUTHORIZED before /authorize,
    EXECUTING right after a successful signature (spend NOT yet counted), CONSUMED only
    after POST /intents/{id}/settled."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before_state = client.get(f"/intents/{pe.peek_token(v.spend_intent)['spend_intent_id']}").json()["status"]

    resp = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50))
    intent_id = resp.get("intent_id", "")
    executing_state = client.get(f"/intents/{intent_id}").json().get("status")

    settled = _settle(intent_id)
    consumed_state = settled.get("intent", {}).get("status")

    ok = (
        before_state == "AUTHORIZED" and resp["ok"] and executing_state == "EXECUTING"
        and settled["ok"] and consumed_state == "CONSUMED"
    )
    return ok, f"states: {before_state} -> {executing_state} -> {consumed_state}"


def case_intent_failed_definite_releases() -> tuple[bool, str]:
    """POST /intents/{id}/failed with definite=true (a definite merchant rejection) marks
    FAILED and releases the reservation — spend never counted."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)

    resp = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50))
    intent_id = resp["intent_id"]
    reserved_before = pe._reserved_total(m.mandate_id)
    failed = client.post(f"/intents/{intent_id}/failed", json={
        "reason": "merchant declined the order", "definite": True,
    }).json()
    reserved_after = pe._reserved_total(m.mandate_id)

    ok = (
        resp["ok"] and failed["ok"] and failed["intent"]["status"] == "FAILED"
        and reserved_before > 0 and reserved_after == 0 and pe.spent(m.mandate_id) == before
    )
    return ok, f"state={failed.get('intent', {}).get('status')} reserved {reserved_before}->{reserved_after}"


def case_intent_failed_uncertain_retains_reservation() -> tuple[bool, str]:
    """POST /intents/{id}/failed with definite=false (a timeout — outcome unknown) marks
    RECONCILIATION_REQUIRED and DELIBERATELY keeps the reservation, since we do not know
    whether the merchant actually settled it."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)

    resp = _authorize(v.spend_intent, "techstore", build_accept(amount=8.50))
    intent_id = resp["intent_id"]
    reserved_before = pe._reserved_total(m.mandate_id)
    failed = client.post(f"/intents/{intent_id}/failed", json={
        "reason": "merchant checkout timed out", "definite": False,
    }).json()
    reserved_after = pe._reserved_total(m.mandate_id)

    ok = (
        resp["ok"] and failed["ok"] and failed["intent"]["status"] == "RECONCILIATION_REQUIRED"
        and reserved_before == reserved_after and reserved_after > 0
    )
    return ok, f"state={failed.get('intent', {}).get('status')} reserved {reserved_before}==={reserved_after}"


def case_demo_evil_merchant_recipient_mismatch_before_signature() -> tuple[bool, str]:
    """A redirected/compromised TechStore (DEMO_EVIL_MERCHANT/DEMO_EVIL_PAYTO) quotes an
    attacker's payTo in its own 402 challenge. /authorize must refuse with
    RECIPIENT_MISMATCH — real signing is never attempted — and the intent is marked
    DENIED, not spent."""
    # merchants.server refuses to import while this process's environment holds
    # AGENT_PRIVATE_KEY/POLICY_SECRET (policy-tier-only secrets) — exactly the guard this
    # suite is meant to prove. This test process deliberately holds both tiers in one
    # interpreter, so hide them for the moment of import only, then restore
    # AGENT_PRIVATE_KEY immediately (later cases in this file still need it present for
    # every /authorize call, which reads it dynamically, not just at import time).
    saved_agent_key = os.environ.pop("AGENT_PRIVATE_KEY", None)
    saved_policy_secret = os.environ.pop("POLICY_SECRET", None)
    try:
        from merchants import server as merchant_server
    finally:
        if saved_agent_key is not None:
            os.environ["AGENT_PRIVATE_KEY"] = saved_agent_key
        if saved_policy_secret is not None:
            os.environ["POLICY_SECRET"] = saved_policy_secret

    saved_merchant = merchant_server.DEMO_EVIL_MERCHANT
    saved_payto = merchant_server.DEMO_EVIL_PAYTO
    attacker_wallet = "0x8888888888888888888888888888888888888888"
    merchant_server.DEMO_EVIL_MERCHANT = "techstore"
    merchant_server.DEMO_EVIL_PAYTO = attacker_wallet
    merchants_client = TestClient(merchant_server.app)

    try:
        m, d = mandate(), decision(quote(merchant_id="techstore", price=7.20))
        v = pe.evaluate(m, d)
        before = pe.spent(m.mandate_id)

        r402 = merchants_client.post(
            "/techstore/checkout", json={"items": [{"sku": "TS-C01", "quantity": 1}]},
        )
        accept = r402.json()["accepts"][0]
        real_sign_payment = ps.sign_payment
        signed_called = {"count": 0}

        def spy(*a, **kw):
            signed_called["count"] += 1
            return real_sign_payment(*a, **kw)

        ps.sign_payment = spy
        try:
            body = _authorize(v.spend_intent, "techstore", accept)
        finally:
            ps.sign_payment = real_sign_payment

        intent_id = pe.peek_token(v.spend_intent)["spend_intent_id"]
        state = client.get(f"/intents/{intent_id}").json().get("status")

        ok = (
            r402.status_code == 402 and accept["payTo"] == attacker_wallet
            and not body["ok"] and body.get("error") == "RECIPIENT_MISMATCH"
            and signed_called["count"] == 0 and pe.spent(m.mandate_id) == before
            and state == "DENIED"
        )
        return ok, f"error={body.get('error')} signed_called={signed_called['count']} state={state}"
    finally:
        merchant_server.DEMO_EVIL_MERCHANT = saved_merchant
        merchant_server.DEMO_EVIL_PAYTO = saved_payto


CASES = [
    ("A1", "recipient-wallet substitution is refused, nothing spent", case_recipient_substitution),
    ("A2", "wrong token contract (asset) is refused, nothing spent", case_wrong_token_contract),
    ("A3", "chainId not matching the network is refused, nothing spent", case_wrong_chain),
    ("A4", "amount off by one cent from the exact intent is refused", case_exact_amount_mismatch),
    ("A5", "failed signing releases the intent instead of spending it", case_failed_signing_does_not_consume),
    ("A6", "failed card issuance releases the intent instead of spending it", case_failed_card_issuance_does_not_consume),
    ("A7", "two concurrent reservations of one intent: exactly one wins", case_concurrent_replay),
    ("A8", "AUTHORIZED -> EXECUTING -> CONSUMED matches GET /intents/{id}", case_executing_then_settled),
    ("A9", "POST /intents/{id}/failed(definite=true) -> FAILED, reservation released", case_intent_failed_definite_releases),
    ("A10", "POST /intents/{id}/failed(definite=false) -> RECONCILIATION_REQUIRED, reservation retained", case_intent_failed_uncertain_retains_reservation),
    ("A11", "DEMO_EVIL_MERCHANT redirect -> RECIPIENT_MISMATCH before any signature", case_demo_evil_merchant_recipient_mismatch_before_signature),
]


def run() -> int:
    failures = 0
    print(f"\n{C['b']}AUTHORIZATION BOUNDARY — /authorize and /authorize-card{C['off']}")
    for cid, desc, fn in CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<62}[{mark}]{C['dim']}  {detail}{C['off']}")

    total = len(CASES)
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
