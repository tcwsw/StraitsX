"""Deterministic pre-purchase clarification logic.

This is distinct from (and complementary to) `AgentPurchaseProposal.clarification_required`
in `agent/execution_agent.py` — that field is the LLM's own, free-form uncertainty signal
about a *specific proposal* it is about to submit. This module is a small, deterministic,
non-LLM gate that runs BEFORE any offer is even gathered: given only what the buyer said,
decide whether the request is well-formed enough to act on, and if a human ceiling was
given for this one purchase, apply it without ever touching the mandate itself.

Hard rule, enforced structurally rather than by convention: nothing in this module ever
reads or writes `Mandate.budget_total`, `Mandate.currency`, `Mandate.allowed_merchants`, or
`Mandate.allowed_categories` — there is simply no code path here that could. A human
ceiling for one purchase (e.g. "maximum 20 XSGD") can only ever narrow
`Mandate.per_intent_max` for that one intent; it can never raise it, and it can never touch
the lifetime `budget_total`.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Optional

from . import money
from .models import Mandate, RequestedItem


@dataclass
class RawPurchaseRequest:
    """What the buyer said, before it is known to be complete. Unlike `RequestedItem`,
    every field here may be missing — that is the entire point: this type exists so
    "quantity is missing" is representable, which `RequestedItem.quantity: int` (required,
    `gt=0`) deliberately cannot represent."""

    item_name: Optional[str] = None
    quantity: Optional[int] = None
    requested_ceiling: Optional[Decimal] = None   # this-purchase-only ceiling, if the buyer gave one


@dataclass
class ClarificationQuestion:
    field: str            # "item_name" | "quantity" | "ceiling"
    question: str


def clarification_questions(
    request: RawPurchaseRequest, *, ask_ceiling: bool = False
) -> list[ClarificationQuestion]:
    """Ask only about what is actually missing from `request`. Deterministic, non-LLM:

    - Ask about the item/product if `item_name` is missing.
    - Ask about quantity if `quantity` is missing (or not a positive integer).
    - Optionally (only if `ask_ceiling=True` AND none was already given) ask for this
      purchase's ceiling — never mandatory, never asked by default.

    Never asks about currency, the merchant allowlist, categories, the mandate's total
    budget, or its expiry — there is no question text for any of those anywhere in this
    module, by construction."""
    questions: list[ClarificationQuestion] = []
    if not request.item_name or not request.item_name.strip():
        questions.append(ClarificationQuestion(
            field="item_name",
            question="What product or item would you like to buy?",
        ))
    if request.quantity is None or request.quantity <= 0:
        questions.append(ClarificationQuestion(
            field="quantity",
            question="How many would you like?",
        ))
    if ask_ceiling and request.requested_ceiling is None:
        questions.append(ClarificationQuestion(
            field="ceiling",
            question="Is there a maximum you'd like to pay for this purchase? (optional)",
        ))
    return questions


def resolve_requested_item(request: RawPurchaseRequest) -> RequestedItem:
    """Build a proper `RequestedItem` once `request` is known to be complete. Raises
    `ValueError` (never proceeds silently) if the item name or quantity is still missing —
    callers should always check `clarification_questions()` is empty first."""
    if not request.item_name or not request.item_name.strip():
        raise ValueError("cannot resolve a requested item: item_name is missing")
    if request.quantity is None or request.quantity <= 0:
        raise ValueError("cannot resolve a requested item: quantity is missing or not positive")
    return RequestedItem(name=request.item_name.strip(), quantity=request.quantity)


def effective_intent_ceiling(mandate: Mandate, request: RawPurchaseRequest) -> Decimal:
    """The ceiling that actually applies to THIS purchase: the mandate's `per_intent_max`,
    narrowed (never widened) by a human-supplied `requested_ceiling` for this one purchase,
    if any. Never reads or writes `mandate.budget_total` — a per-purchase ceiling answer
    (e.g. "maximum 20 XSGD") can only ever tighten this one intent's ceiling, and can never
    overwrite, raise, or otherwise touch the mandate's lifetime budget."""
    if request.requested_ceiling is None:
        return mandate.per_intent_max
    human_ceiling = money.to_xsgd(request.requested_ceiling)
    return min(mandate.per_intent_max, human_ceiling)
