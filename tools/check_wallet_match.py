"""Read-only sanity check: does AGENT_PRIVATE_KEY derive to WHITELISTED_WALLET_ADDRESS,
and is that address's/the whitelisted address's XSGD balance visible on Avalanche mainnet?

STRICTLY READ-ONLY: never sends a transaction and never requests/produces a signature
beyond `Account.from_key(...).address` (public-key derivation only). Only makes
`eth_chainId` / `balanceOf` / `decimals` calls.

AGENT_PRIVATE_KEY is never printed, logged, or included in any exception message.

Usage:
  python -m tools.check_wallet_match

Exit codes:
  0 - derived address matches the whitelisted address AND chain id is 43114
  1 - derived address does NOT match the whitelisted address
  2 - missing configuration, invalid config, RPC error, or wrong chain id
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env.policy"

REQUIRED_CHAIN_ID = 43114

ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]


def _fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 2


def main() -> int:
    load_dotenv(ENV_PATH, override=True)

    whitelisted = os.environ.get("WHITELISTED_WALLET_ADDRESS")
    rpc_url = os.environ.get("RPC_URL")
    xsgd_asset = os.environ.get("XSGD_ASSET")
    has_private_key = bool(os.environ.get("AGENT_PRIVATE_KEY"))

    missing = [
        name
        for name, present in (
            ("AGENT_PRIVATE_KEY", has_private_key),
            ("WHITELISTED_WALLET_ADDRESS", bool(whitelisted)),
            ("RPC_URL", bool(rpc_url)),
            ("XSGD_ASSET", bool(xsgd_asset)),
        )
        if not present
    ]
    if missing:
        return _fail(f"missing required config in .env.policy: {', '.join(missing)}")

    try:
        # Read the key into the narrowest possible scope; derive the address and
        # drop the reference immediately. Never referenced again after this block.
        derived_address = Account.from_key(os.environ["AGENT_PRIVATE_KEY"]).address
    except Exception:
        # Deliberately generic: never include exception args, which could echo key material.
        return _fail("could not derive an address from AGENT_PRIVATE_KEY (value withheld)")

    try:
        whitelisted_checksum = Web3.to_checksum_address(whitelisted)
    except ValueError:
        return _fail(f"WHITELISTED_WALLET_ADDRESS is not a valid address: {whitelisted!r}")

    is_match = derived_address.lower() == whitelisted_checksum.lower()

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = w3.eth.chain_id
    except Exception as exc:  # noqa: BLE001
        return _fail(f"RPC error while reading chain id from {rpc_url}: {exc}")

    is_correct_chain = chain_id == REQUIRED_CHAIN_ID

    try:
        xsgd_checksum = Web3.to_checksum_address(xsgd_asset)
        token = w3.eth.contract(address=xsgd_checksum, abi=ERC20_ABI)
        decimals = token.functions.decimals().call()
        derived_balance_raw = token.functions.balanceOf(
            Web3.to_checksum_address(derived_address)
        ).call()
        whitelisted_balance_raw = token.functions.balanceOf(whitelisted_checksum).call()
    except Exception as exc:  # noqa: BLE001
        return _fail(f"RPC error while reading XSGD contract at {xsgd_asset}: {exc}")

    derived_balance = derived_balance_raw / (10 ** decimals)
    whitelisted_balance = whitelisted_balance_raw / (10 ** decimals)

    print(f"Derived public address:     {derived_address}")
    print(f"Whitelisted wallet address: {whitelisted_checksum}")
    print(f"Status:                     {'MATCH' if is_match else 'MISMATCH'}")
    print(f"Avalanche chain ID:         {chain_id}" + ("" if is_correct_chain else f" (expected {REQUIRED_CHAIN_ID})"))
    print(f"XSGD balance (derived):     {derived_balance:.6f}")
    print(f"XSGD balance (whitelisted): {whitelisted_balance:.6f}")

    if not is_match:
        return 1
    if not is_correct_chain:
        return _fail(f"chain id {chain_id} != required {REQUIRED_CHAIN_ID}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
