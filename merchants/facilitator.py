"""Self-facilitating x402 verifier + settler for XSGD (Circle FiatToken v2, EIP-3009).

verify()  — recover the EIP-712 signer and confirm every field matches what we quoted.
settle()  — submit transferWithAuthorization on Avalanche using the merchant relayer key.

SETTLE_MODE=onchain needs RELAYER_PRIVATE_KEY funded with AVAX for gas. SETTLE_MODE=verify
(default) proves the signature is real and valid without spending gas, which is what you
want while iterating at 3am.
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
    if SETTLE_MODE != "onchain" or not RELAYER_KEY:
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

    tx = token.functions.transferWithAuthorization(
        Web3.to_checksum_address(auth["from"]),
        Web3.to_checksum_address(auth["to"]),
        int(auth["value"]),
        int(auth["validAfter"]),
        int(auth["validBefore"]),
        bytes.fromhex(auth["nonce"][2:]),
        v, r, s,
    ).build_transaction({
        "from": relayer.address,
        "nonce": w3.eth.get_transaction_count(relayer.address),
        "chainId": accept["chainId"],
    })
    signed = w3.eth.account.sign_transaction(tx, RELAYER_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    return tx_hash.hex(), True
