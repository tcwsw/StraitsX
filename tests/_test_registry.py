"""Shared test-only Merchant Wallet Registry fixture.

Never used by production code, and never committed as data/merchant_registry.json (which
stays FINTECH-owned and, for techstore, deliberately unresolved —
payment_recipient: "FINTECH_TODO_REQUIRED" — exactly as shipped). This fixture exists only
so tests/policy_matrix.py, tests/authorize_boundary.py, tests/basket_matrix.py, and
tests/merchant_registry_matrix.py can exercise the happy path (a merchant WITH a valid
registered recipient) and recipient-mismatch/suspension cases without ever inventing a real
wallet address in the shipped registry.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pg.merchant_registry import MerchantRegistry

# Obviously-synthetic, deterministic test addresses — never a real wallet, never written to
# data/merchant_registry.json. Distinct per merchant so a "wrong recipient" test has a
# genuinely different registered address to compare against.
TEST_RECIPIENTS = {
    "techstore": "0x" + "a1" * 20,
    "gadgethub": "0x" + "b2" * 20,
    "bargainbin": "0x" + "c3" * 20,
    "cheapdealsstore": "0x" + "d4" * 20,
}


def build_test_registry(**overrides) -> MerchantRegistry:
    """techstore/gadgethub/bargainbin/cheapdealsstore, all ACTIVE + allowed + a valid synthetic
    recipient, so authorize-boundary/basket/policy tests can exercise a real happy path.

    Each keyword arg is either:
      - a plain string, a shorthand for overriding just that merchant's `status`
        (e.g. `bargainbin="SUSPENDED"`, unchanged from before); or
      - a dict of field overrides applied on top of that merchant's defaults
        (e.g. `gadgethub={"payment_recipient": None}` to test NO_REGISTERED_RECIPIENT).
    """
    merchants = {
        "techstore": {
            "display_name": "TechStore", "allowed": True, "status": "ACTIVE",
            "payment_recipient": TEST_RECIPIENTS["techstore"],
            "network": "avalanche", "chain_id": 43114, "currency": "XSGD", "reputation": 0.94,
        },
        "gadgethub": {
            "display_name": "GadgetHub", "allowed": True, "status": "ACTIVE",
            "payment_recipient": TEST_RECIPIENTS["gadgethub"],
            "network": "avalanche", "chain_id": 43114, "currency": "XSGD", "reputation": 0.88,
        },
        "bargainbin": {
            "display_name": "BargainBin", "allowed": True, "status": "ACTIVE",
            "payment_recipient": TEST_RECIPIENTS["bargainbin"],
            "network": "avalanche", "chain_id": 43114, "currency": "XSGD", "reputation": 0.22,
        },
        "cheapdealsstore": {
            "display_name": "CheapDealsStore", "allowed": True, "status": "ACTIVE",
            "payment_recipient": TEST_RECIPIENTS["cheapdealsstore"],
            "network": "avalanche", "chain_id": 43114, "currency": "XSGD", "reputation": 0.85,
        },
    }
    for merchant_id, override in overrides.items():
        if isinstance(override, str):
            merchants[merchant_id]["status"] = override
        else:
            merchants[merchant_id].update(override)

    tmp_dir = Path(tempfile.mkdtemp(prefix="pg-test-registry-"))
    path = tmp_dir / "merchant_registry.json"
    path.write_text(json.dumps({"merchants": merchants}), encoding="utf-8")
    return MerchantRegistry(path=path)
