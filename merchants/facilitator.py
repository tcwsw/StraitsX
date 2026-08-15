"""Self-facilitating x402 verifier + settler for XSGD (Circle FiatToken v2, EIP-3009).

verify()  — recover the EIP-712 signer and confirm every field matches what we quoted.
settle()  — submit transferWithAuthorization on Avalanche using the merchant relayer key.

SETTLE_MODE=onchain needs RELAYER_PRIVATE_KEY funded with AVAX for gas — if it is missing,
settle() raises a hard RuntimeError rather than ever fabricating a transaction hash.
SETTLE_MODE=verify (default) proves the signature is real and valid without spending gas,
which is what you want while iterating at 3am; that path alone returns a fake, clearly
non-onchain hash (settled_onchain=False).
"""
from __future__ import annotations

import os
import secrets

from eth_account import Account
from eth_account.messages import encode_typed_data

from pg.x402_client import TRANSFER_WITH_AUTHORIZATION_TYPES

SETTLE_MODE = os.environ.get("SETTLE_MODE", "verify")
RPC_URL = os.environ.get("RPC_URL", "https://api.avax-test.network/ext/bc/C/rpc")
RELAYER_KEY = os.environ.get("RELAYER_PRIVATE_KEY")


class SettlementFailed(Exception):
    """Raised when SETTLE_MODE=onchain actually submits a transaction but the chain
    reports it reverted (`receipt.status != 1`). A submitted-but-reverted transaction is
    NOT a settlement — no value moved — and must never be reported to the caller as if it
    were: the SpendIntent this pays for must stay reserved/denied, never CONSUMED, for a
    reverted transaction."""

    def __init__(self, tx_hash: str, status: int):
        self.tx_hash = tx_hash
        self.status = status
        super().__init__(f"on-chain settlement reverted (status={status}): tx {tx_hash}")

ABI = [{
    "name": "transferWithAuthorization",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "v", "type": "uint8"},
        {"name": "r", "type": "bytes32"},
        {"name": "s", "type": "bytes32"},
    ],
    "outputs": [],
}]


def verify(payload: dict, accept: dict) -> tuple[bool, str]:
    try:
        auth = payload["payload"]["authorization"]
        sig = payload["payload"]["signature"]
    except (KeyError, TypeError):
        return False, "malformed payment payload"

    if payload.get("network") != accept["network"]:
        return False, "network mismatch"
    if auth["to"].lower() != accept["payTo"].lower():
        return False, "payTo mismatch — this is not our wallet"
    if str(auth["value"]) != str(accept["amount"]):
        return False, f"amount mismatch: signed {auth['value']}, quoted {accept['amount']}"

    domain = {
        "name": accept["extra"]["name"],
        "version": accept["extra"]["version"],
        "chainId": accept["chainId"],
        "verifyingContract": accept["asset"],
    }
    message = {
        "from": auth["from"],
        "to": auth["to"],
        "value": int(auth["value"]),
        "validAfter": int(auth["validAfter"]),
        "validBefore": int(auth["validBefore"]),
        "nonce": bytes.fromhex(auth["nonce"][2:]),
    }
    signable = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=message,
    )
    recovered = Account.recover_message(signable, signature=bytes.fromhex(sig[2:]))
    if recovered.lower() != auth["from"].lower():
        return False, f"signature does not match declared payer ({recovered})"
    return True, f"valid EIP-3009 authorization from {recovered}"


def settle(payload: dict, accept: dict) -> tuple[str, bool]:
    if SETTLE_MODE == "onchain" and not RELAYER_KEY:
        # A hard, non-recoverable failure — never fabricate a transaction hash for a live
        # settlement that was never actually submitted.
        raise RuntimeError(
            "SETTLE_MODE=onchain requires RELAYER_PRIVATE_KEY to be configured on the "
            "merchant process; refusing to settle rather than fabricate a transaction hash."
        )
    if SETTLE_MODE != "onchain":
        return "0x" + secrets.token_hex(32), False

    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    relayer = Account.from_key(RELAYER_KEY)
    token = w3.eth.contract(address=Web3.to_checksum_address(accept["asset"]), abi=ABI)
    auth = payload["payload"]["authorization"]
    raw = bytes.fromhex(payload["payload"]["signature"][2:])
    r, s, v = raw[:32], raw[32:64], raw[64]
    if v < 27:
        v += 27

    fn = token.functions.transferWithAuthorization(
        Web3.to_checksum_address(auth["from"]),
        Web3.to_checksum_address(auth["to"]),
        int(auth["value"]),
        int(auth["validAfter"]),
        int(auth["validBefore"]),
        bytes.fromhex(auth["nonce"][2:]),
        v, r, s,
    )

    # Real, live gas estimate for THIS exact call — never a hardcoded gas limit. The
    # signature has already been verified by verify() above, so this estimate call executes
    # against real contract state. A 20% margin absorbs minor state changes between
    # estimation and inclusion in a block.
    estimated_gas = fn.estimate_gas({"from": relayer.address})
    gas_limit = int(estimated_gas * 1.2)

    tx = fn.build_transaction({
        "from": relayer.address,
        # The PENDING nonce, not "latest" — so a relayer with another transaction still
        # sitting in the mempool never reuses (and collides on) the same nonce.
        "nonce": w3.eth.get_transaction_count(relayer.address, "pending"),
        "chainId": accept["chainId"],
        "gas": gas_limit,
    })
    signed = w3.eth.account.sign_transaction(tx, RELAYER_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status != 1:
        raise SettlementFailed(tx_hash.hex(), receipt.status)
    return tx_hash.hex(), True
