"""Merchant Wallet Registry — the specification, as an executable table.

Proves the fail-closed contract in pg/merchant_registry.py: a merchant is only payable
if it is registered, allowed, ACTIVE, and has a real recipient on file — and a malformed,
zero, or placeholder address is refused at LOAD time (a startup failure), never silently
defaulted or invented downstream. Also proves resolve_and_verify_payment()'s network/
currency/recipient checks in pg/policy_engine.py.

Run:  python -m tests.merchant_registry_matrix
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("POLICY_SECRET", "test-only-merchant-registry-matrix-secret-do-not-use")

from pg import policy_engine as pe
from pg.merchant_registry import MerchantRegistry, MerchantRegistryError, RegistryLookupError
from tests._test_registry import TEST_RECIPIENTS, build_test_registry

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}

pe.REGISTRY = build_test_registry()


def _registry_from(merchants: dict) -> MerchantRegistry:
    tmp_dir = Path(tempfile.mkdtemp(prefix="pg-registry-load-"))
    path = tmp_dir / "merchant_registry.json"
    path.write_text(json.dumps({"merchants": merchants}), encoding="utf-8")
    return MerchantRegistry(path=path)


def _entry(**over) -> dict:
    base = dict(
        display_name="Test Merchant", allowed=True, status="ACTIVE",
        payment_recipient=None, network="avalanche", chain_id=43114,
        currency="XSGD", reputation=0.5,
    )
    base.update(over)
    return base


# ---------------------------------------------------------------- load-time validation

def load_cases() -> list[tuple]:
    out = []

    out.append(("R1", "valid registered recipient loads cleanly",
        lambda: _registry_from({"m": _entry(payment_recipient="0x" + "ab" * 20)}), True))

    out.append(("R2", "null payment_recipient is a legal 'not yet onboarded' state",
        lambda: _registry_from({"m": _entry(payment_recipient=None)}), True))

    out.append(("R3", "FINTECH_TODO_REQUIRED sentinel treated as unresolved, not malformed",
        lambda: _registry_from({"m": _entry(payment_recipient="FINTECH_TODO_REQUIRED")}), True))

    out.append(("R4", "placeholder address (every hex char identical) rejected at load",
        lambda: _registry_from({"m": _entry(payment_recipient="0x" + "1" * 40)}), False))

    out.append(("R5", "zero address rejected at load",
        lambda: _registry_from({"m": _entry(payment_recipient="0x" + "0" * 40)}), False))

    out.append(("R6", "malformed address (not 40 hex chars) rejected at load",
        lambda: _registry_from({"m": _entry(payment_recipient="0xnotanaddress")}), False))

    out.append(("R7", "missing required field rejected at load",
        lambda: _registry_from({"m": {"display_name": "X", "allowed": True, "status": "ACTIVE"}}), False))

    out.append(("R8", "invalid status value rejected at load",
        lambda: _registry_from({"m": _entry(status="PENDING")}), False))

    return out


def run_load_cases() -> int:
    failures = 0
    print(f"\n{C['b']}MERCHANT REGISTRY — load-time validation{C['off']}")
    for cid, desc, fn, expect_ok in load_cases():
        try:
            fn()
            got_ok = True
        except MerchantRegistryError:
            got_ok = False
        ok = got_ok == expect_ok
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        verb = "load" if expect_ok else "reject"
        print(f"{cid:<5}{verb:<10}{str(got_ok):<8}{desc}  [{mark}]")
    return failures


# ---------------------------------------------------------------- lookup semantics

def lookup_cases() -> list[tuple]:
    reg = build_test_registry(gadgethub="SUSPENDED")
    out = []

    out.append(("R9", "is_trusted() true for allowed+ACTIVE merchant",
        lambda: reg.is_trusted("techstore"), True))

    out.append(("R10", "is_trusted() false for unknown merchant",
        lambda: reg.is_trusted("nosuchmerchant"), False))

    out.append(("R11", "is_trusted() false for a suspended merchant",
        lambda: reg.is_trusted("gadgethub"), False))

    def _resolve_ok():
        rec = reg.resolve_recipient("techstore")
        return rec.payment_recipient == TEST_RECIPIENTS["techstore"]
    out.append(("R12", "resolve_recipient() returns the registered recipient",
        _resolve_ok, True))

    def _resolve_suspended():
        try:
            reg.resolve_recipient("gadgethub")
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R13", "resolve_recipient() fails closed with MERCHANT_SUSPENDED",
        _resolve_suspended, "MERCHANT_SUSPENDED"))

    def _resolve_unregistered():
        try:
            reg.resolve_recipient("nosuchmerchant")
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R14", "resolve_recipient() fails closed with MERCHANT_NOT_REGISTERED",
        _resolve_unregistered, "MERCHANT_NOT_REGISTERED"))

    def _resolve_no_recipient():
        no_recipient = _registry_from({"m": _entry(allowed=True, status="ACTIVE", payment_recipient=None)})
        try:
            no_recipient.resolve_recipient("m")
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R15", "resolve_recipient() fails closed with NO_REGISTERED_RECIPIENT",
        _resolve_no_recipient, "NO_REGISTERED_RECIPIENT"))

    return out


def run_lookup_cases() -> int:
    failures = 0
    print(f"\n{C['b']}MERCHANT REGISTRY — lookup semantics{C['off']}")
    for cid, desc, fn, expect in lookup_cases():
        got = fn()
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<20}{str(got):<20}{desc}  [{mark}]")
    return failures


# ---------------------------------------------------------------- payment-execution verification

def payment_cases() -> list[tuple]:
    out = []
    accept_ok = {
        "network": pe.expected_network(),
        "chainId": int(pe.expected_network().split(":")[1]),
        "asset": pe.XSGD_ASSET,
        "payTo": TEST_RECIPIENTS["techstore"],
    }

    def _ok():
        rec = pe.resolve_and_verify_payment("techstore", accept_ok)
        return rec.merchant_id

    out.append(("R16", "matching network/asset/payTo resolves cleanly", _ok, "techstore"))

    def _bad_recipient():
        accept = dict(accept_ok, payTo="0x" + "9" * 40)
        try:
            pe.resolve_and_verify_payment("techstore", accept)
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R17", "attacker payTo substitution -> RECIPIENT_MISMATCH", _bad_recipient, "RECIPIENT_MISMATCH"))

    def _bad_asset():
        accept = dict(accept_ok, asset="0x" + "7" * 40)
        try:
            pe.resolve_and_verify_payment("techstore", accept)
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R18", "wrong asset contract -> CURRENCY_MISMATCH", _bad_asset, "CURRENCY_MISMATCH"))

    def _bad_network():
        accept = dict(accept_ok, network="eip155:1", chainId=1)
        try:
            pe.resolve_and_verify_payment("techstore", accept)
            return "no-error"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R19", "network not in ALLOWED_NETWORKS -> NETWORK_MISMATCH", _bad_network, "NETWORK_MISMATCH"))

    def _resolved_merchant():
        # The shipped, real registry (never the test one): as of the final one-wallet
        # self-transfer spec, FINTECH has resolved techstore's payment_recipient to the
        # demo's whitelisted wallet. Prove payment execution resolves it cleanly rather
        # than treating a now-real value as still unresolved.
        real = MerchantRegistry()
        try:
            rec = real.resolve_recipient("techstore")
            return "" if not rec.payment_recipient else "resolved"
        except RegistryLookupError as exc:
            return exc.code
    out.append(("R20", "shipped data/merchant_registry.json: techstore recipient is resolved (final spec)",
        _resolved_merchant, "resolved"))

    return out


def run_payment_cases() -> int:
    failures = 0
    print(f"\n{C['b']}MERCHANT REGISTRY — payment-execution verification{C['off']}")
    for cid, desc, fn, expect in payment_cases():
        got = fn()
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<22}{str(got):<22}{desc}  [{mark}]")
    return failures


def run() -> int:
    failures = run_load_cases() + run_lookup_cases() + run_payment_cases()
    total = len(load_cases()) + len(lookup_cases()) + len(payment_cases())
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
