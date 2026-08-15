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
    pay_to = pay_to or pe.MERCHANT_REGISTRY["techstore"]["wallet"]
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
        "spend_intent": spend_intent, "merchant_id": merchant_id,
        "challenge": {"accepts": [accept]},
    }).json()


def _authorize_card(spend_intent: str, merchant_id: str, amount: float) -> dict:
    return client.post("/authorize-card", json={
        "spend_intent": spend_intent, "merchant_id": merchant_id,
        "amount": amount, "cardholder_name": "Test Person",
    }).json()


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
    """Signing blows up (HSM offline, whatever). The reservation must be released: no
    spend recorded, and the same intent can still be redeemed once signing works again."""
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
    second = _authorize(v.spend_intent, "techstore", accept)
    after_spent = pe.spent(m.mandate_id)

    ok = (
        not first["ok"] and mid_spent == before
        and second["ok"] and abs(after_spent - round(before + 8.50, 2)) < 1e-9
    )
    return ok, f"first={first.get('detail')!r} second_ok={second['ok']} spent {before}->{mid_spent}->{after_spent}"


def case_failed_card_issuance_does_not_consume() -> tuple[bool, str]:
    """Card issuance is refused by the issuer. The reservation must be released: no spend
    recorded, and the same intent can still be redeemed once issuance works again."""
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
    second = _authorize_card(v.spend_intent, "techstore", 8.50)
    after_spent = pe.spent(m.mandate_id)

    ok = (
        not first["ok"] and mid_spent == before
        and second["ok"] and abs(after_spent - round(before + 8.50, 2)) < 1e-9
    )
    return ok, f"first={first.get('detail')!r} second_ok={second['ok']} spent {before}->{mid_spent}->{after_spent}"


def case_concurrent_replay() -> tuple[bool, str]:
    """Two callers present the exact same SpendIntent at the same instant. Exactly one may
    reserve it; the other must be refused, even under a race."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    reg = pe.MERCHANT_REGISTRY["techstore"]
    network = pe.expected_network()
    chain_id = int(network.split(":")[1])

    results: list[tuple[bool, str]] = []
    barrier = threading.Barrier(2)

    def attempt() -> None:
        barrier.wait()
        results.append(pe.reserve_intent(
            v.spend_intent, "techstore", 8.50,
            pay_to=reg["wallet"], asset=pe.XSGD_ASSET, network=network, chain_id=chain_id,
        ))

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


CASES = [
    ("A1", "recipient-wallet substitution is refused, nothing spent", case_recipient_substitution),
    ("A2", "wrong token contract (asset) is refused, nothing spent", case_wrong_token_contract),
    ("A3", "chainId not matching the network is refused, nothing spent", case_wrong_chain),
    ("A4", "amount off by one cent from the exact intent is refused", case_exact_amount_mismatch),
    ("A5", "failed signing releases the intent instead of spending it", case_failed_signing_does_not_consume),
    ("A6", "failed card issuance releases the intent instead of spending it", case_failed_card_issuance_does_not_consume),
    ("A7", "two concurrent reservations of one intent: exactly one wins", case_concurrent_replay),
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
