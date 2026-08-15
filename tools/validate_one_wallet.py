"""Fail-closed, READ-ONLY report for the live one-wallet self-transfer demo.

Confirms that:
  1. AGENT_PRIVATE_KEY derives to a real address (the payer),
  2. RELAYER_PRIVATE_KEY derives to a real address (the relayer),
  3. TechStore's registered payment_recipient (read from the trusted merchant registry),
  4. WHITELISTED_WALLET_ADDRESS,
are all the SAME address, case-insensitively, and none of them is malformed, zero, or a
placeholder — plus that X402_NETWORK/SETTLE_MODE/ALLOW_SELF_TRANSFER_DEMO are all set for
a real mainnet self-transfer.

STRICTLY READ-ONLY: never sends a transaction, never makes a network/RPC call, and never
prints, logs, or returns a private key — only the public addresses derived from them and
named PASS/FAIL checks (see pg/live_guard.evaluate_one_wallet_self_transfer, a pure
function over explicit inputs).

Usage:
  python -m tools.validate_one_wallet

Exit codes:
  0 - every named check passed
  1 - one or more checks failed (fail-closed; do not proceed with a live self-transfer)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

from pg import live_guard
from pg.merchant_registry import MerchantRegistry, MerchantRegistryError

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env.policy"

MERCHANT_ID = "techstore"

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


def main() -> int:
    load_dotenv(ENV_PATH, override=True)

    try:
        registry = MerchantRegistry()
        rec = registry.get(MERCHANT_ID)
        registry_recipient = rec.payment_recipient if rec else None
    except MerchantRegistryError as exc:
        print(f"ERROR: could not load the merchant registry: {exc}", file=sys.stderr)
        return 2

    ctx = live_guard.evaluate_one_wallet_self_transfer(
        agent_private_key=os.environ.get("AGENT_PRIVATE_KEY"),
        relayer_private_key=os.environ.get("RELAYER_PRIVATE_KEY"),
        registry_recipient=registry_recipient,
        whitelisted_address=os.environ.get("WHITELISTED_WALLET_ADDRESS"),
        network=os.environ.get("X402_NETWORK", ""),
        settle_mode=os.environ.get("SETTLE_MODE", "verify"),
        allow_self_transfer_demo=live_guard.self_transfer_allowed(),
    )

    print(f"\n{C['b']}ONE-WALLET SELF-TRANSFER VALIDATION{C['off']}")
    for check in ctx.checks:
        mark = f"{C['ok']}PASS{C['off']}" if check["passed"] else f"{C['bad']}FAIL{C['off']}"
        print(f"  [{mark}] {check['code']:<32}{check['detail']}")

    print(f"\n{C['b']}Public addresses (never a private key){C['off']}")
    print(f"  payer address:      {ctx.payer_address}")
    print(f"  relayer address:    {ctx.relayer_address}")
    print(f"  registry recipient: {ctx.registry_recipient}")
    print(f"  whitelisted address:{ctx.whitelisted_address}")

    status = f"{C['ok']}PASS{C['off']}" if ctx.passed else f"{C['bad']}FAIL{C['off']}"
    print(f"\nOverall: [{status}]\n")
    return 0 if ctx.passed else 1


if __name__ == "__main__":
    sys.exit(main())
