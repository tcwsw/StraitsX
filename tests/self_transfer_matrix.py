"""Self-transfer detection, the nine-point live-signing precondition gate, and the
on-chain settlement-failure boundary — as an executable table.

Everything here is mocked. This suite never touches a real RPC endpoint, never submits a
real transaction, and never signs with a real mainnet key. That is the point: it proves
the REFUSAL behaviour of pg/live_guard.py, pg/policy_server.py's self-transfer handling,
merchants/facilitator.py's receipt-status check, and tools/live_self_transfer.py's
interactive-only guard, without ever going near mainnet.

Run:  python -m tests.self_transfer_matrix
"""
from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins.
os.environ.setdefault("POLICY_SECRET", "test-only-self-transfer-matrix-secret-do-not-use")

from eth_account import Account
from fastapi.testclient import TestClient
from web3.exceptions import TransactionNotFound

from pg import live_guard
from pg import policy_engine as pe
from pg import policy_server as ps
from pg.x402_client import agent_address
from tests._test_registry import build_test_registry
from tests.policy_matrix import decision, mandate, quote

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}

# A throwaway signing key, unique to this test process. Its derived address is used as
# TechStore's payment_recipient in the test-only registry below, so payer == recipient —
# a genuine, deliberately-constructed self-transfer, never a real wallet.
SELF_KEY = Account.create().key.hex()
SELF_ADDRESS = agent_address(SELF_KEY)
os.environ.setdefault("AGENT_PRIVATE_KEY", SELF_KEY)

# Swap in a test-only registry (synthetic addresses, never the shipped
# data/merchant_registry.json, which deliberately leaves techstore's recipient
# unresolved) with techstore's recipient forced to equal the payer address above.
pe.REGISTRY = build_test_registry(techstore={"payment_recipient": SELF_ADDRESS})

client = TestClient(ps.app)


def _authorize(spend_intent: str, accept: dict) -> dict:
    return client.post("/authorize", json={
        "spend_intent": spend_intent, "challenge": {"accepts": [accept]},
    }).json()


def build_accept(**over) -> dict:
    network = over.pop("network", pe.expected_network())
    base = {
        "scheme": "exact",
        "network": network,
        "amount": str(int(round(over.pop("amount", 7.20) * 10 ** 6))),
        "asset": over.pop("asset", pe.XSGD_ASSET),
        "payTo": over.pop("pay_to", SELF_ADDRESS),
        "maxTimeoutSeconds": 300,
        "chainId": over.pop("chain_id", int(network.split(":")[1])),
        "extra": {"assetTransferMethod": "eip3009", "name": "XSGD", "version": "2"},
    }
    base.update(over)
    return base


def _mint() -> str:
    m, d = mandate(), decision(quote(merchant_id="techstore", price=7.20))
    v = pe.evaluate(m, d)
    return v.spend_intent


# ---------------------------------------------------------------- is_self_transfer / self_transfer_allowed

def case_is_self_transfer_case_insensitive() -> tuple[bool, str]:
    ok = live_guard.is_self_transfer("0xAbCd12", "0xabcd12") and not live_guard.is_self_transfer(
        "0x" + "11" * 20, "0x" + "22" * 20)
    return ok, "same address matches case-insensitively; different addresses do not"


def case_self_transfer_allowed_defaults_closed() -> tuple[bool, str]:
    saved = os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
    try:
        ok = live_guard.self_transfer_allowed() is False
        return ok, "unset ALLOW_SELF_TRANSFER_DEMO -> refused"
    finally:
        if saved is not None:
            os.environ["ALLOW_SELF_TRANSFER_DEMO"] = saved


def case_self_transfer_allowed_explicit_true() -> tuple[bool, str]:
    saved = os.environ.get("ALLOW_SELF_TRANSFER_DEMO")
    os.environ["ALLOW_SELF_TRANSFER_DEMO"] = "true"
    try:
        ok = live_guard.self_transfer_allowed() is True
        return ok, "explicit true opts in"
    finally:
        if saved is None:
            os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
        else:
            os.environ["ALLOW_SELF_TRANSFER_DEMO"] = saved


UNIT_CASES = [
    ("U1", "same address matches regardless of case; different addresses do not",
     case_is_self_transfer_case_insensitive),
    ("U2", "ALLOW_SELF_TRANSFER_DEMO unset/false -> self_transfer_allowed() is False",
     case_self_transfer_allowed_defaults_closed),
    ("U3", "ALLOW_SELF_TRANSFER_DEMO=true -> self_transfer_allowed() is True",
     case_self_transfer_allowed_explicit_true),
]


def run_unit_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — is_self_transfer / self_transfer_allowed{C['off']}")
    for cid, desc, fn in UNIT_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


# ---------------------------------------------------------------- /authorize self-transfer handling

def case_self_transfer_refused_by_default() -> tuple[bool, str]:
    saved = os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
    try:
        spend_intent = _mint()
        intent_id = pe.peek_token(spend_intent)["spend_intent_id"]
        body = _authorize(spend_intent, build_accept())
        state = client.get(f"/intents/{intent_id}").json().get("status")
        ok = (not body["ok"] and body.get("error") == "SELF_TRANSFER_DISABLED" and state == "DENIED")
        return ok, f"error={body.get('error')} state={state}"
    finally:
        if saved is not None:
            os.environ["ALLOW_SELF_TRANSFER_DEMO"] = saved


def case_self_transfer_allowed_and_labelled() -> tuple[bool, str]:
    saved = os.environ.get("ALLOW_SELF_TRANSFER_DEMO")
    os.environ["ALLOW_SELF_TRANSFER_DEMO"] = "true"
    try:
        spend_intent = _mint()
        body = _authorize(spend_intent, build_accept())
        ok = (
            body.get("ok") is True and body.get("self_transfer") is True
            and body.get("warning") == live_guard.SELF_TRANSFER_WARNING
        )
        return ok, f"ok={body.get('ok')} self_transfer={body.get('self_transfer')} warned={bool(body.get('warning'))}"
    finally:
        if saved is None:
            os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
        else:
            os.environ["ALLOW_SELF_TRANSFER_DEMO"] = saved


AUTHORIZE_CASES = [
    ("S1", "self-transfer refused by default, intent marked DENIED", case_self_transfer_refused_by_default),
    ("S2", "self-transfer allowed+labelled when ALLOW_SELF_TRANSFER_DEMO=true", case_self_transfer_allowed_and_labelled),
]


def run_authorize_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — /authorize{C['off']}")
    for cid, desc, fn in AUTHORIZE_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


# ---------------------------------------------------------------- require_live_signing_preconditions

def _baseline_kwargs(**over) -> dict:
    base = dict(
        network=live_guard.MAINNET_NETWORK,
        chain_id=live_guard.MAINNET_CHAIN_ID,
        asset="0x" + "aa" * 20,
        expected_asset="0x" + "aa" * 20,
        recipient_status="ACTIVE",
        amount=5.0,
        per_txn_max=15.0,
        settle_mode="onchain",
        agent_private_key="0x" + "ab" * 32,
        relayer_private_key_present=True,
        payer_address="0x" + "cc" * 20,
        get_avax_balance=lambda addr: 1.0,
        min_avax_for_gas=0.01,
    )
    base.update(over)
    return base


PRECONDITION_CASES = [
    ("G1", "all nine checks pass -> no refusal", {}, None),
    ("G2", "network is not mainnet", {"network": "eip155:43113"}, "NETWORK_IS_MAINNET"),
    ("G3", "chain_id is not 43114", {"chain_id": 43113}, "CHAIN_ID_MATCHES_MAINNET"),
    ("G4", "SETTLE_MODE is not onchain", {"settle_mode": "verify"}, "SETTLE_MODE_ONCHAIN"),
    ("G5", "asset does not match the configured XSGD contract",
     {"asset": "0x" + "bb" * 20}, "ASSET_MATCHES_CONFIGURED_XSGD"),
    ("G6", "recipient registry status is not ACTIVE", {"recipient_status": "SUSPENDED"}, "RECIPIENT_STATUS_ACTIVE"),
    ("G7", "amount exceeds the per-transaction max", {"amount": 16.0}, "AMOUNT_WITHIN_PER_TXN_MAX"),
    ("G8", "AGENT_PRIVATE_KEY is not a well-formed key", {"agent_private_key": "not-a-key"}, "AGENT_KEY_WELLFORMED"),
    ("G9", "RELAYER_PRIVATE_KEY is not configured", {"relayer_private_key_present": False}, "RELAYER_KEY_CONFIGURED"),
    ("G10", "no live balance lookup supplied -> fails closed, never assumes gas is available",
     {"get_avax_balance": None}, "PAYER_HAS_GAS_FOR_FEES"),
    ("G11", "live balance lookup reports insufficient AVAX for gas",
     {"get_avax_balance": lambda addr: 0.0}, "PAYER_HAS_GAS_FOR_FEES"),
]


def run_precondition_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — nine-point live-signing precondition gate (mocked balances only){C['off']}")
    for cid, desc, overrides, expect_code in PRECONDITION_CASES:
        kwargs = _baseline_kwargs(**overrides)
        try:
            live_guard.require_live_signing_preconditions(**kwargs)
            got = None
        except live_guard.LiveSigningRefused as exc:
            got = [code for code, _ in exc.failed]
        ok = (got is None) if expect_code is None else (got == [expect_code])
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}expect={expect_code!s:<28}got={got!s:<28}[{mark}]")
    return failures


# ---------------------------------------------------------------- facilitator.settle() receipt status

class _FakeSignedTx:
    raw_transaction = b"signed-raw-tx"


class _FakeTxHash:
    def hex(self) -> str:
        return "deadbeef"


class _FakeFn:
    def transferWithAuthorization(self, *_a, **_kw):
        class _Built:
            def estimate_gas(self, opts):
                return 100_000

            def build_transaction(self, opts):
                return {"from": opts.get("from")}
        return _Built()


class _FakeContract:
    functions = _FakeFn()


def _make_fake_web3(receipt_status: int):
    class _FakeEthAccount:
        @staticmethod
        def sign_transaction(tx, key):
            return _FakeSignedTx()

    class _FakeReceipt:
        status = receipt_status

    class _FakeEth:
        account = _FakeEthAccount()

        def contract(self, address, abi):
            return _FakeContract()

        def get_transaction_count(self, address, block_identifier="latest"):
            return 0

        def send_raw_transaction(self, raw):
            return _FakeTxHash()

        def wait_for_transaction_receipt(self, tx_hash, timeout=120):
            return _FakeReceipt()

    class _FakeWeb3:
        def __init__(self, provider):
            self.eth = _FakeEth()

        @staticmethod
        def HTTPProvider(url):
            return None

        @staticmethod
        def to_checksum_address(address):
            return address

    return _FakeWeb3


def _settle_payload() -> tuple[dict, dict]:
    payload = {"payload": {
        "authorization": {
            "from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "value": "7200000",
            "validAfter": 0, "validBefore": 9999999999, "nonce": "0x" + "33" * 32,
        },
        "signature": "0x" + "44" * 65,
    }}
    accept = {"asset": "0x" + "55" * 20, "chainId": 43114}
    return payload, accept


def case_settle_raises_on_reverted_receipt() -> tuple[bool, str]:
    import merchants.facilitator as facilitator
    payload, accept = _settle_payload()
    relayer_key = Account.create().key.hex()
    with patch.object(facilitator, "SETTLE_MODE", "onchain"), \
         patch.object(facilitator, "RELAYER_KEY", relayer_key), \
         patch("web3.Web3", _make_fake_web3(receipt_status=0)):
        try:
            facilitator.settle(payload, accept)
            return False, "expected SettlementFailed, none was raised"
        except facilitator.SettlementFailed as exc:
            return exc.status == 0 and exc.tx_hash == "deadbeef", f"status={exc.status} tx_hash={exc.tx_hash}"


def case_settle_succeeds_on_valid_receipt() -> tuple[bool, str]:
    import merchants.facilitator as facilitator
    payload, accept = _settle_payload()
    relayer_key = Account.create().key.hex()
    with patch.object(facilitator, "SETTLE_MODE", "onchain"), \
         patch.object(facilitator, "RELAYER_KEY", relayer_key), \
         patch("web3.Web3", _make_fake_web3(receipt_status=1)):
        tx_hash, settled = facilitator.settle(payload, accept)
        return (tx_hash == "deadbeef" and settled is True), f"tx_hash={tx_hash} settled={settled}"


def case_settle_verify_mode_never_touches_web3() -> tuple[bool, str]:
    import merchants.facilitator as facilitator
    payload, accept = _settle_payload()
    with patch.object(facilitator, "SETTLE_MODE", "verify"):
        tx_hash, settled = facilitator.settle(payload, accept)
        ok = settled is False and isinstance(tx_hash, str) and tx_hash.startswith("0x")
        return ok, f"tx_hash={tx_hash} settled={settled} (mock hash, no chain call made)"


def case_settle_onchain_without_relayer_key_hard_fails() -> tuple[bool, str]:
    """SETTLE_MODE=onchain with no RELAYER_PRIVATE_KEY must raise, never fabricate a hash."""
    import merchants.facilitator as facilitator
    payload, accept = _settle_payload()
    with patch.object(facilitator, "SETTLE_MODE", "onchain"), \
         patch.object(facilitator, "RELAYER_KEY", None):
        try:
            facilitator.settle(payload, accept)
            return False, "expected RuntimeError, none was raised"
        except RuntimeError as exc:
            return True, f"raised as expected: {exc}"


SETTLE_CASES = [
    ("F1", "SETTLE_MODE=onchain, receipt.status=0 -> SettlementFailed, never reported settled",
     case_settle_raises_on_reverted_receipt),
    ("F2", "SETTLE_MODE=onchain, receipt.status=1 -> settles cleanly", case_settle_succeeds_on_valid_receipt),
    ("F3", "SETTLE_MODE=verify never calls web3 at all", case_settle_verify_mode_never_touches_web3),
    ("F4", "SETTLE_MODE=onchain with no RELAYER_PRIVATE_KEY -> hard RuntimeError, never a fake hash",
     case_settle_onchain_without_relayer_key_hard_fails),
]


def run_settle_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — merchants/facilitator.py settle() receipt status (mocked web3){C['off']}")
    for cid, desc, fn in SETTLE_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


# ---------------------------------------------------------------- tools.live_self_transfer._require_interactive

def case_require_interactive_refuses_under_ci() -> tuple[bool, str]:
    import tools.live_self_transfer as lst
    saved = os.environ.get("CI")
    os.environ["CI"] = "true"
    try:
        lst._require_interactive()
        return False, "expected SystemExit when CI is set"
    except SystemExit:
        return True, "refused to run with CI set"
    finally:
        if saved is None:
            os.environ.pop("CI", None)
        else:
            os.environ["CI"] = saved



# ---------------------------------------------------------------- live_guard.verify_onchain_settlement() (mocked RPC)

def _make_fake_settlement_w3(
    *,
    tx_found: bool = True,
    mined: bool = True,
    receipt_status: int = 1,
    chain_id: int = live_guard.MAINNET_CHAIN_ID,
    tx_to: str | None = None,
    event_from: str | None = None,
    event_to: str | None = None,
    event_value: int | None = 19_200_000,
    no_receipt: bool = False,
    raise_on_lookup: Exception | None = None,
):
    """A fully mocked web3.Web3-like object: no real RPC endpoint, no real chain, ever."""

    class _FakeFilter:
        def process_receipt(self_inner, receipt):
            if event_from is None:
                return []
            return [{"args": {"from": event_from, "to": event_to, "value": event_value}}]

    class _FakeEvents:
        def Transfer(self_inner):
            return _FakeFilter()

    class _FakeContract:
        events = _FakeEvents()

    class _FakeEth:
        def __init__(self_inner):
            self_inner.chain_id = chain_id

        def get_transaction(self_inner, tx_hash):
            if raise_on_lookup is not None:
                raise raise_on_lookup
            if not tx_found:
                raise TransactionNotFound("mock: no such transaction")
            return {
                "blockNumber": 12345 if mined else None,
                "to": tx_to, "from": "0x" + "99" * 20, "gasPrice": 25_000_000_000,
            }

        def get_transaction_receipt(self_inner, tx_hash):
            if no_receipt:
                raise TransactionNotFound("mock: no receipt yet")
            return {"status": receipt_status, "gasUsed": 60_000, "effectiveGasPrice": 25_000_000_000}

        def contract(self_inner, address, abi):
            return _FakeContract()

    class _FakeW3:
        def __init__(self_inner):
            self_inner.eth = _FakeEth()

    return _FakeW3()


def _settlement_kwargs(**over) -> dict:
    base = dict(
        tx_hash="0x" + "cd" * 32,
        expected_chain_id=live_guard.MAINNET_CHAIN_ID,
        expected_asset="0x" + "aa" * 20,
        expected_payer=SELF_ADDRESS,
        expected_recipient=SELF_ADDRESS,
        expected_amount_atomic=19_200_000,
    )
    base.update(over)
    return base


def case_verify_settlement_valid() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(
        tx_to="0x" + "aa" * 20, event_from=SELF_ADDRESS, event_to=SELF_ADDRESS, event_value=19_200_000,
    )
    ctx = live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
    ok = ctx.passed and ctx.gas_payer_address == "0x" + "99" * 20 and ctx.gas_spent_avax and ctx.gas_spent_avax > 0
    return ok, f"passed={ctx.passed} gas_payer={ctx.gas_payer_address} gas_spent_avax={ctx.gas_spent_avax}"


def case_verify_settlement_wrong_amount() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(
        tx_to="0x" + "aa" * 20, event_from=SELF_ADDRESS, event_to=SELF_ADDRESS, event_value=5_000_000,
    )
    ctx = live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
    codes = [c for c, _ in ctx.failed]
    ok = (not ctx.passed) and "EVENT_VALUE_MATCHES_EXPECTED_AMOUNT" in codes
    return ok, f"failed=[{', '.join(codes)}]"


def case_verify_settlement_wrong_recipient() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(
        tx_to="0x" + "aa" * 20, event_from=SELF_ADDRESS, event_to="0x" + "66" * 20, event_value=19_200_000,
    )
    ctx = live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
    codes = [c for c, _ in ctx.failed]
    ok = (not ctx.passed) and "EVENT_TO_MATCHES_REGISTERED_RECIPIENT" in codes
    return ok, f"failed=[{', '.join(codes)}]"


def case_verify_settlement_wrong_contract() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(
        tx_to="0x" + "ff" * 20, event_from=SELF_ADDRESS, event_to=SELF_ADDRESS, event_value=19_200_000,
    )
    ctx = live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
    codes = [c for c, _ in ctx.failed]
    ok = (not ctx.passed) and "TRANSACTION_TARGETED_XSGD_CONTRACT" in codes
    return ok, f"failed=[{', '.join(codes)}]"


def case_verify_settlement_reverted_receipt() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(
        tx_to="0x" + "aa" * 20, event_from=SELF_ADDRESS, event_to=SELF_ADDRESS, event_value=19_200_000,
        receipt_status=0,
    )
    ctx = live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
    codes = [c for c, _ in ctx.failed]
    ok = (not ctx.passed) and "RECEIPT_STATUS_SUCCESS" in codes
    return ok, f"failed=[{', '.join(codes)}]"


def case_verify_settlement_replayed_tx_hash() -> tuple[bool, str]:
    tx_hash = "0x" + "ef" * 32
    ok1 = pe.claim_settlement_tx_hash(tx_hash, "intent-A")
    ok2 = pe.claim_settlement_tx_hash(tx_hash, "intent-A")   # idempotent retry, same intent
    ok3 = pe.claim_settlement_tx_hash(tx_hash, "intent-B")   # replay against a DIFFERENT intent
    ok = ok1 is True and ok2 is True and ok3 is False
    return ok, f"first-claim={ok1} same-intent-retry={ok2} different-intent-replay={ok3}"


def case_verify_settlement_unknown_outcome_is_uncertain_not_failed() -> tuple[bool, str]:
    w3 = _make_fake_settlement_w3(raise_on_lookup=ConnectionError("mock RPC timeout"))
    try:
        live_guard.verify_onchain_settlement(**_settlement_kwargs(), w3=w3)
        return False, "expected SettlementVerificationUncertain, none was raised"
    except live_guard.SettlementVerificationUncertain as exc:
        return True, f"raised as expected (never a hard failure): {exc}"


VERIFY_SETTLEMENT_CASES = [
    ("M1", "valid settlement -> every check passes", case_verify_settlement_valid),
    ("M2", "wrong amount -> EVENT_VALUE_MATCHES_EXPECTED_AMOUNT fails", case_verify_settlement_wrong_amount),
    ("M3", "wrong recipient -> EVENT_TO_MATCHES_REGISTERED_RECIPIENT fails", case_verify_settlement_wrong_recipient),
    ("M4", "wrong contract -> TRANSACTION_TARGETED_XSGD_CONTRACT fails", case_verify_settlement_wrong_contract),
    ("M5", "reverted receipt -> RECEIPT_STATUS_SUCCESS fails", case_verify_settlement_reverted_receipt),
    ("M6", "replayed tx_hash against a different intent is refused", case_verify_settlement_replayed_tx_hash),
    ("M7", "RPC timeout/unknown outcome -> Uncertain, never a hard failure",
     case_verify_settlement_unknown_outcome_is_uncertain_not_failed),
]


def run_verify_settlement_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — live_guard.verify_onchain_settlement() (mocked RPC){C['off']}")
    for cid, desc, fn in VERIFY_SETTLEMENT_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


# ---------------------------------------------------------------- POST /intents/{id}/settled (mainnet, hardened)

def _mint_executing(price: float = 19.20) -> str:
    """Mint (and reserve) a fresh SpendIntent against techstore, then move it straight to
    EXECUTING — the state a real /authorize call would already have left it in before the
    execution agent ever reports settlement. Mandate limits are overridden generously so
    the 19.20 XSGD self-transfer amount always fits, with no human-approval threshold."""
    m = mandate(per_txn_max=25.0, require_human_above=None)
    d = decision(quote(merchant_id="techstore", price=price))
    v = pe.evaluate(m, d)
    intent_id = pe.peek_token(v.spend_intent)["spend_intent_id"]
    pe.mark_executing(intent_id, "test setup")
    return intent_id


def _passing_ctx(tx_hash: str) -> live_guard.SettlementVerificationContext:
    return live_guard.SettlementVerificationContext(
        checks=[{"code": "MOCKED", "passed": True, "detail": "fully mocked RPC pass"}],
        tx_hash=tx_hash, gas_payer_address="0x" + "88" * 20, gas_spent_avax=0.0015,
    )


def _failing_ctx(tx_hash: str, code: str = "EVENT_VALUE_MATCHES_EXPECTED_AMOUNT") -> live_guard.SettlementVerificationContext:
    return live_guard.SettlementVerificationContext(
        checks=[{"code": code, "passed": False, "detail": "mocked failure"}], tx_hash=tx_hash,
    )


def case_settled_endpoint_valid_consumes() -> tuple[bool, str]:
    intent_id = _mint_executing()
    tx_hash = "0x" + "11" * 32
    with patch.object(live_guard, "verify_onchain_settlement", return_value=_passing_ctx(tx_hash)):
        resp = client.post(f"/intents/{intent_id}/settled",
                            json={"tx_hash": tx_hash, "network": live_guard.MAINNET_NETWORK}).json()
    status = client.get(f"/intents/{intent_id}").json().get("status")
    ok = (
        resp.get("ok") is True and status == "CONSUMED"
        and resp.get("self_transfer") is True and resp.get("wallet_balance_changed") is False
        and float(resp.get("economic_value_moved_xsgd")) == 0.0
        and float(resp.get("delegated_budget_consumed_xsgd")) == 19.20
        and resp.get("transaction_hash") == tx_hash and resp.get("gas_payer_address") == "0x" + "88" * 20
    )
    return ok, f"ok={resp.get('ok')} status={status} economic_value_moved={resp.get('economic_value_moved_xsgd')}"


def case_settled_endpoint_failed_verification_releases() -> tuple[bool, str]:
    intent_id = _mint_executing()
    tx_hash = "0x" + "22" * 32
    with patch.object(live_guard, "verify_onchain_settlement", return_value=_failing_ctx(tx_hash)):
        resp = client.post(f"/intents/{intent_id}/settled",
                            json={"tx_hash": tx_hash, "network": live_guard.MAINNET_NETWORK}).json()
    status = client.get(f"/intents/{intent_id}").json().get("status")
    ok = resp.get("ok") is False and resp.get("error") == "SETTLEMENT_VERIFICATION_FAILED" and status == "FAILED"
    return ok, f"ok={resp.get('ok')} error={resp.get('error')} status={status}"


def case_settled_endpoint_uncertain_retains_reservation() -> tuple[bool, str]:
    intent_id = _mint_executing()
    tx_hash = "0x" + "33" * 32
    with patch.object(live_guard, "verify_onchain_settlement",
                       side_effect=live_guard.SettlementVerificationUncertain("mock RPC timeout")):
        resp = client.post(f"/intents/{intent_id}/settled",
                            json={"tx_hash": tx_hash, "network": live_guard.MAINNET_NETWORK}).json()
    status = client.get(f"/intents/{intent_id}").json().get("status")
    ok = resp.get("ok") is False and resp.get("error") == "RECONCILIATION_REQUIRED" and status == "RECONCILIATION_REQUIRED"
    return ok, f"ok={resp.get('ok')} error={resp.get('error')} status={status}"


def case_settled_endpoint_replayed_tx_hash_refused() -> tuple[bool, str]:
    first_id = _mint_executing()
    second_id = _mint_executing()
    tx_hash = "0x" + "44" * 32
    with patch.object(live_guard, "verify_onchain_settlement", return_value=_passing_ctx(tx_hash)):
        first_resp = client.post(f"/intents/{first_id}/settled",
                                  json={"tx_hash": tx_hash, "network": live_guard.MAINNET_NETWORK}).json()
        second_resp = client.post(f"/intents/{second_id}/settled",
                                   json={"tx_hash": tx_hash, "network": live_guard.MAINNET_NETWORK}).json()
    first_status = client.get(f"/intents/{first_id}").json().get("status")
    second_status = client.get(f"/intents/{second_id}").json().get("status")
    ok = (
        first_resp.get("ok") is True and first_status == "CONSUMED"
        and second_resp.get("ok") is False and second_resp.get("error") == "TX_HASH_ALREADY_LINKED"
        and second_status == "FAILED"
    )
    return ok, f"first={first_resp.get('ok')}/{first_status} second={second_resp.get('error')}/{second_status}"


def case_settled_endpoint_missing_tx_hash_refused() -> tuple[bool, str]:
    """A mainnet settlement report with no tx_hash at all can never be independently
    verified — refused with TX_HASH_REQUIRED, intent marked FAILED, reservation released,
    never silently trusted the way a non-mainnet report would be."""
    intent_id = _mint_executing()
    resp = client.post(f"/intents/{intent_id}/settled",
                        json={"tx_hash": None, "network": live_guard.MAINNET_NETWORK}).json()
    status = client.get(f"/intents/{intent_id}").json().get("status")
    ok = resp.get("ok") is False and resp.get("error") == "TX_HASH_REQUIRED" and status == "FAILED"
    return ok, f"ok={resp.get('ok')} error={resp.get('error')} status={status}"


SETTLED_ENDPOINT_CASES = [
    ("E1", "valid mainnet settlement -> CONSUMED with the full self-transfer receipt",
     case_settled_endpoint_valid_consumes),
    ("E2", "failed RPC verification -> FAILED, reservation released",
     case_settled_endpoint_failed_verification_releases),
    ("E3", "uncertain/timeout RPC outcome -> RECONCILIATION_REQUIRED, reservation retained",
     case_settled_endpoint_uncertain_retains_reservation),
    ("E4", "the same tx_hash cannot settle a second, different SpendIntent",
     case_settled_endpoint_replayed_tx_hash_refused),
    ("E5", "a mainnet settlement report with no tx_hash is refused, never trusted",
     case_settled_endpoint_missing_tx_hash_refused),
]


def run_settled_endpoint_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — POST /intents/{{id}}/settled (mainnet, hardened, mocked RPC){C['off']}")
    for cid, desc, fn in SETTLED_ENDPOINT_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


def case_require_interactive_refuses_non_tty() -> tuple[bool, str]:
    import tools.live_self_transfer as lst
    saved = os.environ.pop("CI", None)
    try:
        with patch.object(sys.stdin, "isatty", return_value=False), \
             patch.object(sys.stdout, "isatty", return_value=True):
            try:
                lst._require_interactive()
                return False, "expected SystemExit for non-interactive stdin"
            except SystemExit:
                return True, "refused without a real interactive terminal"
    finally:
        if saved is not None:
            os.environ["CI"] = saved


INTERACTIVE_CASES = [
    ("I1", "refuses to run when CI is set", case_require_interactive_refuses_under_ci),
    ("I2", "refuses to run without a real interactive terminal", case_require_interactive_refuses_non_tty),
]


def run_interactive_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — tools/live_self_transfer.py interactive-only guard{C['off']}")
    for cid, desc, fn in INTERACTIVE_CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<70}{detail}  [{mark}]")
    return failures


# ---------------------------------------------------------------- one-wallet self-transfer validator

# Two independent, real (but throwaway) signing keys, unique to this test process. The
# final one-wallet spec deliberately uses ONE_WALLET_KEY for both AGENT_PRIVATE_KEY and
# RELAYER_PRIVATE_KEY (payer == relayer == recipient == whitelisted). OTHER_KEY/OTHER_ADDRESS
# exist purely to construct "derives to a different address" failure cases.
ONE_WALLET_KEY = "0x" + Account.create().key.hex().removeprefix("0x")
ONE_WALLET_ADDRESS = agent_address(ONE_WALLET_KEY)
OTHER_KEY = "0x" + Account.create().key.hex().removeprefix("0x")
OTHER_ADDRESS = agent_address(OTHER_KEY)


def _one_wallet_kwargs(**over) -> dict:
    base = dict(
        agent_private_key=ONE_WALLET_KEY,
        relayer_private_key=ONE_WALLET_KEY,
        registry_recipient=ONE_WALLET_ADDRESS,
        whitelisted_address=ONE_WALLET_ADDRESS,
        network=live_guard.MAINNET_NETWORK,
        settle_mode="onchain",
        allow_self_transfer_demo=True,
    )
    base.update(over)
    return base


ONE_WALLET_CASES = [
    ("W1", "all four addresses equal, keys well-formed, mainnet/onchain/allowed -> passes",
     {}, True, None),
    ("W2", "AGENT_PRIVATE_KEY missing", {"agent_private_key": None}, False, "AGENT_PRIVATE_KEY_CONFIGURED"),
    ("W3", "RELAYER_PRIVATE_KEY missing", {"relayer_private_key": None}, False, "RELAYER_PRIVATE_KEY_CONFIGURED"),
    ("W4", "payer/relayer derive to different addresses",
     {"relayer_private_key": OTHER_KEY}, False, "ALL_FOUR_ADDRESSES_EQUAL"),
    ("W5", "registry recipient differs from payer/relayer/whitelisted",
     {"registry_recipient": OTHER_ADDRESS}, False, "ALL_FOUR_ADDRESSES_EQUAL"),
    ("W6", "whitelisted address differs from payer/relayer/registry recipient",
     {"whitelisted_address": OTHER_ADDRESS}, False, "ALL_FOUR_ADDRESSES_EQUAL"),
    ("W7", "malformed registry recipient (not valid hex/length)",
     {"registry_recipient": "0xnothex"}, False, "REGISTRY_RECIPIENT_VALID"),
    ("W8", "zero address as registry recipient",
     {"registry_recipient": "0x" + "00" * 20}, False, "REGISTRY_RECIPIENT_VALID"),
    ("W9", "placeholder (all-repeated-digit) address as whitelisted address",
     {"whitelisted_address": "0x" + "11" * 20}, False, "WHITELISTED_ADDRESS_VALID"),
    ("W10", "network is not mainnet (e.g. fuji)",
     {"network": "eip155:43113"}, False, "NETWORK_IS_MAINNET"),
    ("W11", "SETTLE_MODE is not onchain",
     {"settle_mode": "verify"}, False, "SETTLE_MODE_ONCHAIN"),
    ("W12", "ALLOW_SELF_TRANSFER_DEMO is not true",
     {"allow_self_transfer_demo": False}, False, "ALLOW_SELF_TRANSFER_DEMO_TRUE"),
    ("W13", "AGENT_PRIVATE_KEY is present but malformed",
     {"agent_private_key": "not-a-key"}, False, "AGENT_PRIVATE_KEY_CONFIGURED"),
]


def run_one_wallet_cases() -> int:
    failures = 0
    print(f"\n{C['b']}SELF-TRANSFER MATRIX — one-wallet self-transfer validator (pg/live_guard.evaluate_one_wallet_self_transfer){C['off']}")
    for cid, desc, overrides, expect_pass, expect_code in ONE_WALLET_CASES:
        kwargs = _one_wallet_kwargs(**overrides)
        ctx = live_guard.evaluate_one_wallet_self_transfer(**kwargs)
        failed_codes = [code for code, _ in ctx.failed]
        if expect_pass:
            ok = ctx.passed
        else:
            ok = (not ctx.passed) and (expect_code in failed_codes)
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        got = "all-pass" if ctx.passed else ", ".join(failed_codes)
        print(f"{cid:<5}{desc:<70}got=[{got}]  [{mark}]")
    return failures


def case_one_wallet_never_leaks_private_keys() -> tuple[bool, str]:
    """Security sanity check: neither private key string ever appears in the raised
    exception's message, any check's code/detail, or the returned public addresses —
    only public addresses and named PASS/FAIL checks are ever surfaced."""
    kwargs = _one_wallet_kwargs(relayer_private_key=OTHER_KEY)  # force a failure (ALL_FOUR_ADDRESSES_EQUAL)
    try:
        live_guard.require_one_wallet_self_transfer(**kwargs)
        return False, "expected OneWalletSelfTransferRefused, none was raised"
    except live_guard.OneWalletSelfTransferRefused as exc:
        haystack = str(exc) + " ".join(f"{c}{d}" for c, d in exc.failed)
        leaked = ONE_WALLET_KEY in haystack or OTHER_KEY in haystack
        return (not leaked), "no private key material found in exception/checks" if not leaked else "LEAKED a private key"


def run_one_wallet_security_case() -> int:
    ok, detail = case_one_wallet_never_leaks_private_keys()
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{'W14':<5}{'never leaks private key material':<70}{detail}  [{mark}]")
    return int(not ok)


def run() -> int:
    failures = 0
    failures += run_unit_cases()
    failures += run_authorize_cases()
    failures += run_precondition_cases()
    failures += run_settle_cases()
    failures += run_verify_settlement_cases()
    failures += run_settled_endpoint_cases()
    failures += run_interactive_cases()
    failures += run_one_wallet_cases()
    failures += run_one_wallet_security_case()
    total = (
        len(UNIT_CASES) + len(AUTHORIZE_CASES) + len(PRECONDITION_CASES) + len(SETTLE_CASES)
        + len(VERIFY_SETTLEMENT_CASES) + len(SETTLED_ENDPOINT_CASES)
        + len(INTERACTIVE_CASES) + len(ONE_WALLET_CASES) + 1
    )
    print(f"\n{total - failures}/{total} cases as specified")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
