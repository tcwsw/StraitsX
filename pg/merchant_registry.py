"""Merchant Wallet Registry — the single source of truth for which merchants may transact
and where their payment settles.

Data lives in data/merchant_registry.json (FINTECH-owned; see its _note). This module is the
ONLY code that loads and interprets that file, and it is deliberately strict:

- No default or invented wallets. A merchant with no configured `payment_recipient` (null,
  or an unresolved `*_TODO_REQUIRED` sentinel — the same convention config/loader.py uses)
  has NO recipient, ever. This module never falls back to a literal, invented, or
  environment-default address.
- Malformed, zero, and placeholder addresses are rejected at load time (a startup failure,
  not a silent runtime one) — including the exact repeated-digit placeholders
  (0x1111...1111, 0x2222...2222, ...) this codebase used to ship as "throwaway testnet
  wallets". Those are refused now: a fake-looking address must never be treated as real.
- Address comparisons are case-insensitive (every stored recipient is normalized to
  lowercase at load).
- Every lookup fails closed: an unknown merchant, a disallowed merchant, a suspended
  merchant, or a merchant with no registered recipient are all refusals — never a default.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

REGISTRY_PATH = Path(os.environ.get(
    "MERCHANT_REGISTRY_PATH", Path(__file__).resolve().parent.parent / "data" / "merchant_registry.json"
))

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Ownership sentinels, matching config/loader.py's convention: the owning team (FINTECH, for
# a payment_recipient) has not supplied a real value yet. Treated as "no recipient
# registered" — never as a malformed address, and never invented on this module's behalf.
_UNRESOLVED_SENTINELS = {"PM_TODO_REQUIRED", "FINTECH_TODO_REQUIRED"}

_VALID_STATUSES = {"ACTIVE", "SUSPENDED"}

_REQUIRED_FIELDS = ("display_name", "allowed", "status", "network", "chain_id", "currency", "reputation")


class MerchantRegistryError(RuntimeError):
    """The registry file itself is invalid. Raised at load time (a startup/deploy bug),
    never per-request."""


class RegistryLookupError(RuntimeError):
    """A specific, named refusal to resolve a payment recipient. `code` is one of
    MERCHANT_NOT_REGISTERED, MERCHANT_SUSPENDED, NO_REGISTERED_RECIPIENT, RECIPIENT_MISMATCH,
    NETWORK_MISMATCH, CURRENCY_MISMATCH — reported upward verbatim by the policy server and
    recorded in the audit ledger."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MerchantRecord:
    merchant_id: str
    display_name: str
    allowed: bool
    status: str
    payment_recipient: Optional[str]   # normalized lowercase 0x... address, or None
    network: str
    chain_id: int
    currency: str
    reputation: float

    def public_dict(self) -> dict:
        """The shape GET /merchants/registry returns. A settlement wallet address is public
        on-chain information, not a credential — nothing here is secret — but the shape is
        kept explicit and stable regardless."""
        return {
            "merchant_id": self.merchant_id,
            "display_name": self.display_name,
            "allowed": self.allowed,
            "status": self.status,
            "payment_recipient": self.payment_recipient,
            "network": self.network,
            "chain_id": self.chain_id,
            "currency": self.currency,
            "reputation": self.reputation,
        }


def _is_placeholder(hex_lower_no_prefix: str) -> bool:
    """Every character identical (0x1111...1111, 0xaaaa...aaaa, ...) — the exact pattern
    this codebase's old throwaway testnet wallets used. Never a real settlement address."""
    return len(set(hex_lower_no_prefix)) == 1


def _normalize_recipient(merchant_id: str, raw: object) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise MerchantRegistryError(
            f"merchant {merchant_id!r}: payment_recipient must be a string or null, "
            f"got {type(raw).__name__}"
        )
    value = raw.strip()
    if value == "" or value in _UNRESOLVED_SENTINELS:
        # Not yet supplied by FINTECH. Equivalent to null: no recipient registered.
        return None
    if not _ADDRESS_RE.match(value):
        raise MerchantRegistryError(
            f"merchant {merchant_id!r}: payment_recipient {raw!r} is not a valid 0x-prefixed, "
            "40-hex-character address"
        )
    lower = value.lower()
    if int(lower, 16) == 0:
        raise MerchantRegistryError(
            f"merchant {merchant_id!r}: payment_recipient is the zero address — refusing to "
            "register it as a real wallet"
        )
    if _is_placeholder(lower[2:]):
        raise MerchantRegistryError(
            f"merchant {merchant_id!r}: payment_recipient {raw!r} looks like a placeholder "
            "address (every hex character repeated) — refusing to register it. Supply a real "
            "wallet or leave payment_recipient null until one is available."
        )
    return lower


def _load_records(path: Path) -> dict[str, MerchantRecord]:
    if not path.exists():
        raise MerchantRegistryError(f"merchant registry file missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    merchants = data.get("merchants")
    if not isinstance(merchants, dict) or not merchants:
        raise MerchantRegistryError(f"{path}: no merchants defined under \"merchants\"")

    out: dict[str, MerchantRecord] = {}
    for merchant_id, entry in merchants.items():
        if not isinstance(entry, dict):
            raise MerchantRegistryError(f"merchant {merchant_id!r}: entry must be an object")

        missing = [k for k in _REQUIRED_FIELDS if k not in entry]
        if missing:
            raise MerchantRegistryError(f"merchant {merchant_id!r}: missing required field(s) {missing}")

        status = entry["status"]
        if status not in _VALID_STATUSES:
            raise MerchantRegistryError(
                f"merchant {merchant_id!r}: status must be one of {sorted(_VALID_STATUSES)}, got {status!r}"
            )

        recipient = _normalize_recipient(merchant_id, entry.get("payment_recipient"))

        out[merchant_id] = MerchantRecord(
            merchant_id=merchant_id,
            display_name=str(entry["display_name"]),
            allowed=bool(entry["allowed"]),
            status=status,
            payment_recipient=recipient,
            network=str(entry["network"]),
            chain_id=int(entry["chain_id"]),
            currency=str(entry["currency"]),
            reputation=float(entry["reputation"]),
        )
    return out


class MerchantRegistry:
    """Loaded once per process from data/merchant_registry.json (or MERCHANT_REGISTRY_PATH).
    The ONLY source of truth for merchant trust and payment recipients — nothing downstream
    may invent, default, or fall back to any other wallet."""

    def __init__(self, path: Path | None = None):
        self._path = Path(path) if path is not None else REGISTRY_PATH
        self._records = _load_records(self._path)

    def reload(self) -> None:
        self._records = _load_records(self._path)

    def all(self) -> dict[str, MerchantRecord]:
        return dict(self._records)

    def get(self, merchant_id: str) -> Optional[MerchantRecord]:
        return self._records.get(merchant_id)

    def is_trusted(self, merchant_id: str) -> bool:
        """True only for a known, allowed, ACTIVE merchant. Used by policy decisions
        (which merchant a purchase may be proposed at) — deliberately does NOT require a
        registered recipient, since a merchant can be legitimately shoppable while FINTECH
        is still onboarding its settlement wallet. Payment execution is gated separately,
        by `resolve_recipient()`."""
        rec = self._records.get(merchant_id)
        return bool(rec and rec.allowed and rec.status == "ACTIVE")

    def resolve_recipient(self, merchant_id: str) -> MerchantRecord:
        """The ONLY path payment execution may use to learn where money goes. Fails closed,
        with a named RegistryLookupError, for every non-payable state; never returns or
        falls back to any other address."""
        rec = self._records.get(merchant_id)
        if not rec or not rec.allowed:
            raise RegistryLookupError(
                "MERCHANT_NOT_REGISTERED", f"{merchant_id!r} is not a registered merchant"
            )
        if rec.status != "ACTIVE":
            raise RegistryLookupError("MERCHANT_SUSPENDED", f"{merchant_id!r} is suspended")
        if not rec.payment_recipient:
            raise RegistryLookupError(
                "NO_REGISTERED_RECIPIENT",
                f"{merchant_id!r} has no registered payment recipient yet",
            )
        return rec
