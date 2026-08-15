"""Exact XSGD money handling.

Every financial amount in ProcureGuard's policy/payment layer is a `Decimal`, quantized to
XSGD's two decimal places (cents) via `to_xsgd()`. Never compare, sum, or store a currency
amount as a bare `float`: 0.1 + 0.2 != 0.3 in binary floating point, and a policy engine
that decides whether real money moves cannot afford that kind of surprise.

`to_xsgd()` converts through `str()` first — never straight from a `float` to `Decimal` —
so a value that started life as a JSON/Python float is read at its base-10 textual value
(`Decimal(str(7.2))` == `Decimal("7.2")`), not its noisy raw binary one
(`Decimal(7.2)` == `Decimal('7.20000000000000017763568...')`).

`to_micros()` / `micros_to_xsgd()` convert to/from integer micro-XSGD units (1 XSGD =
1,000,000 micros), matching the on-chain XSGD token's 6-decimal precision — the natural,
exact-by-construction unit at the payment-execution boundary (atomic amounts in a 402
challenge or settlement).
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Union

Numeric = Union[int, float, str, Decimal]

CENTS = Decimal("0.01")
MICRO_XSGD = Decimal("0.000001")
ZERO = Decimal("0.00")
MICROS_PER_XSGD = 1_000_000


def to_xsgd(value: Numeric) -> Decimal:
    """Convert any numeric input (int, float, str, Decimal) to an exact `Decimal`
    quantized to XSGD's 2 decimal places. Raises `ValueError` (never a raw arithmetic
    exception) on anything that is not a valid amount, so callers using this as a pydantic
    validator get a clean `ValidationError` instead of an uncaught `decimal` exception."""
    if value is None:
        raise ValueError("cannot convert None to an XSGD amount")
    if isinstance(value, Decimal):
        d = value
    else:
        try:
            d = Decimal(str(value))
        except (ArithmeticError, ValueError, TypeError) as exc:
            raise ValueError(f"not a valid XSGD amount: {value!r}") from exc
    try:
        return d.quantize(CENTS, rounding=ROUND_HALF_UP)
    except ArithmeticError as exc:
        raise ValueError(f"not a valid XSGD amount: {value!r}") from exc


def to_micros(value: Numeric) -> int:
    """Exact integer micro-XSGD units (1 XSGD = 1,000,000 micros) — the on-chain XSGD
    token's 6-decimal precision."""
    d = value if isinstance(value, Decimal) else to_xsgd(value)
    return int((d * MICROS_PER_XSGD).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def micros_to_xsgd(micros: int) -> Decimal:
    """Inverse of `to_micros()`: integer micro-XSGD units back to a 2dp XSGD `Decimal`."""
    return to_xsgd(Decimal(int(micros)) / MICROS_PER_XSGD)
