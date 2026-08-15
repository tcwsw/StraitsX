"""Rail two: a single-use StraitsX virtual card, issued only after policy approval.

Runs inside the policy engine process, for the same reason the signing does. The card
material and the one-time view URL never travel back to the execution agent, so they never
enter the model's context. The agent learns that a card exists and what its opaque id is.
A human opens the card.

Confirmed integration: StraitsX's MCP-over-SSE server (see pg/straitsx_mcp_client.py), not
a REST gateway. `issue()` calls a single MCP tool (`get_card_sandbox` in sandbox,
`get_card_prod` in production) through that client.

    STRAITSX_MCP_URL=https://card.straitsx.ai/sandbox/sse | https://card.straitsx.ai/production/sse
    STRAITSX_CARD_TOOL=get_card_sandbox | get_card_prod
    CARD_MODE=live | simulate
"""
from __future__ import annotations

import json
import os
import secrets
from typing import Any

from . import straitsx_mcp_client as mcp_client

CARD_MODE = os.environ.get("CARD_MODE", "simulate")
STRAITSX_MCP_URL = os.environ.get("STRAITSX_MCP_URL", "")
STRAITSX_CARD_TOOL = os.environ.get("STRAITSX_CARD_TOOL", "")

# StraitsX enforces these server-side on both sandbox and production. We enforce them here
# too, so a rejection is a policy decision with a readable reason rather than an HTTP error
# from someone else's server in the middle of a demo.
MIN_CARD_SGD = float(os.environ.get("MIN_CARD_SGD", "5"))
MAX_CARD_SGD = float(os.environ.get("MAX_CARD_SGD", "30"))
CARDHOLDER_MAX = 26

# Where in an MCP tools/call result the card fields might live. We never guess a key that
# isn't here, and anything not explicitly claimed as agent-safe stays human_only.
_CARD_ID_KEYS = ("card_opaque_id", "card_id", "id")
_SETTLEMENT_KEYS = ("settlement_tx", "settlement_reference", "settlement_ref", "reference", "tx")
_HUMAN_ONLY_KEYS = (
    "iframe_url", "view_url", "card_url", "card_html",
    "pan", "cvv", "cvc", "expiry", "expiry_date", "card_number", "full_pan",
)


class CardRefused(Exception):
    pass


def preflight(amount: float, cardholder_name: str) -> None:
    """Fail before touching the sponsor's endpoint. Their caps, checked on our side."""
    if not MIN_CARD_SGD <= amount <= MAX_CARD_SGD:
        raise CardRefused(
            f"card amount {amount:.2f} outside the issuer range "
            f"{MIN_CARD_SGD:.0f}-{MAX_CARD_SGD:.0f} SGD"
        )
    name = cardholder_name.strip()
    if not 2 <= len(name) <= CARDHOLDER_MAX or not all(c.isalpha() or c.isspace() for c in name):
        raise CardRefused(
            f"cardholder name must be 2-{CARDHOLDER_MAX} letters and spaces, got {name!r}"
        )


def _first(payload: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return None


def _extract_card_payload(result: dict[str, Any]) -> dict[str, Any]:
    """Pull a flat dict of card fields out of an MCP tools/call result. Raises CardRefused
    (fail closed) rather than guessing when the shape doesn't match anything we recognise."""
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured

    content = result.get("content")
    if isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text":
        try:
            parsed = json.loads(content[0].get("text", ""))
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            return parsed

    raise CardRefused("unexpected StraitsX MCP response shape")


def issue(amount: float, cardholder_name: str, wallet_address: str) -> dict[str, Any]:
    """Issue a single-use card. Returns issuer references, never card material.

    The returned dict is split deliberately:
      agent_safe  — what may go back to the execution agent and into the audit log
                    (opaque card id, amount, mode, settlement reference only)
      human_only  — the one-time view URL / card material, which the policy engine holds
                    for a human
    """
    preflight(amount, cardholder_name)

    if CARD_MODE != "live":
        opaque = "card_sim_" + secrets.token_hex(8)
        return {
            "agent_safe": {
                "card_opaque_id": opaque,
                "settlement_tx": "0x" + secrets.token_hex(32),
                "amount": amount,
                "mode": "simulate",
            },
            "human_only": {"iframe_url": f"simulated://card/{opaque}"},
        }

    if not wallet_address:
        raise CardRefused("wallet_address is required in CARD_MODE=live")
    if not STRAITSX_MCP_URL or not STRAITSX_CARD_TOOL:
        raise CardRefused("STRAITSX_MCP_URL / STRAITSX_CARD_TOOL not configured for CARD_MODE=live")

    try:
        result = mcp_client.issue_card(
            mcp_url=STRAITSX_MCP_URL,
            tool_name=STRAITSX_CARD_TOOL,
            wallet_address=wallet_address,
            cardholder_name=cardholder_name.strip(),
            amount_sgd=amount,
        )
    except mcp_client.McpCallFailed as exc:
        raise CardRefused(f"StraitsX card issuance failed: {exc}") from exc

    payload = _extract_card_payload(result)

    card_id = _first(payload, _CARD_ID_KEYS)
    settlement_ref = _first(payload, _SETTLEMENT_KEYS)
    if not card_id or not settlement_ref:
        raise CardRefused("StraitsX MCP response missing card id or settlement reference")

    human_only = {k: payload[k] for k in _HUMAN_ONLY_KEYS if payload.get(k) not in (None, "")}

    return {
        "agent_safe": {
            "card_opaque_id": card_id,
            "settlement_tx": settlement_ref,
            "amount": amount,
            "mode": "live",
        },
        # Held by the engine. Never returned to the agent, never logged, never in a prompt.
        "human_only": human_only,
    }
