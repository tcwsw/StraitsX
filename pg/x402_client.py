"""x402 client: turn an HTTP 402 challenge into a signed EIP-3009 authorization.

Everything that determines where the money goes (payTo, asset, amount, chainId, EIP-712
domain) is read from the challenge and NOTHING is hardcoded — same rule the StraitsX
reference gateway enforces. The policy layer independently re-checks payTo and amount
before this module is allowed to sign.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

TRANSFER_WITH_AUTHORIZATION_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


class PaymentRefused(Exception):
    pass


def pick_accept(challenge: dict, allowed_networks: set[str]) -> dict:
    for accept in challenge.get("accepts", []):
        if accept.get("scheme") != "exact":
            continue
        if accept.get("network") not in allowed_networks:
            raise PaymentRefused(f"network {accept.get('network')} not in {allowed_networks}")
        if accept.get("extra", {}).get("assetTransferMethod", "eip3009") != "eip3009":
            raise PaymentRefused("unsupported transfer method")
        return accept
    raise PaymentRefused("no usable payment requirement in challenge")


def sign_payment(accept: dict, private_key: str, valid_for: int = 600) -> dict:
    acct = Account.from_key(private_key)
    now = int(time.time())
    authorization = {
        "from": acct.address,
        "to": accept["payTo"],
        "value": int(accept["amount"]),
        "validAfter": 0,
        "validBefore": now + valid_for,
        "nonce": "0x" + secrets.token_hex(32),
    }
    domain = {
        "name": accept.get("extra", {}).get("name", "XSGD"),
        "version": accept.get("extra", {}).get("version", "2"),
        "chainId": int(accept.get("chainId") or accept["network"].split(":")[1]),
        "verifyingContract": accept["asset"],
    }
    signable = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data={**authorization, "nonce": bytes.fromhex(authorization["nonce"][2:])},
    )
    signed = Account.sign_message(signable, private_key=private_key)
    return {
        "x402Version": 1,
        "scheme": "exact",
        "network": accept["network"],
        "payload": {
            "signature": "0x" + signed.signature.hex().removeprefix("0x"),
            "authorization": {**authorization, "value": str(authorization["value"])},
        },
    }


def encode_header(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def decode_header(header: str) -> dict[str, Any]:
    return json.loads(base64.b64decode(header))


def agent_address(private_key: str | None = None) -> str:
    key = private_key or os.environ["AGENT_PRIVATE_KEY"]
    return Account.from_key(key).address
