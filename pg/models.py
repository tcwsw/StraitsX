"""Shared types. The Mandate is the constitution: everything downstream is checked against it.

Every XSGD amount in this module is a `Decimal` (see `pg/money.py`), never a bare `float`:
policy and payment comparisons must be exact, not subject to binary floating point noise.
Fields typed `XsgdAmount`/`OptionalXsgdAmount` accept int/float/str/Decimal input (as JSON
naturally provides) and normalise it to an exact, 2-decimal-place `Decimal` before it is
ever stored, compared, or summed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, BeforeValidator, Field

from . import money


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_xsgd(value: object) -> Decimal:
    return money.to_xsgd(value)  # type: ignore[arg-type]


def _validate_xsgd_optional(value: object) -> Optional[Decimal]:
    return None if value is None else money.to_xsgd(value)  # type: ignore[arg-type]


# A required XSGD amount: any int/float/str/Decimal input is normalised to an exact,
# 2-decimal-place Decimal. Never accept or produce a bare float past this boundary.
XsgdAmount = Annotated[Decimal, BeforeValidator(_validate_xsgd)]
OptionalXsgdAmount = Annotated[Optional[Decimal], BeforeValidator(_validate_xsgd_optional)]


class RequestedItem(BaseModel):
    """One line of what the buyer actually asked for — a name and a quantity. Not what was
    found in any catalogue; see `SelectedLineItem` for the resolved match."""

    name: str
    quantity: int = Field(gt=0)


class Mandate(BaseModel):
    """Signed by the human, once. The agent never gets to edit this."""

    mandate_id: str
    principal: str                      # who the agent buys for
    currency: Literal["XSGD"] = "XSGD"
    budget_total: XsgdAmount            # lifetime cap for this mandate
    per_intent_max: XsgdAmount          # single-purchase (SpendIntent) ceiling
    requested_items: list[RequestedItem] = Field(default_factory=list)
    # ^ What the buyer originally asked for, if this mandate was minted for one specific
    # procurement. Empty for a general-purpose mandate not scoped to a pre-known request.
    allowed_categories: list[str]
    blocked_categories: list[str] = Field(default_factory=list)
    # ^ Belt-and-suspenders on top of allowed_categories: a category found here is refused
    # even if it were somehow also present in allowed_categories (a misconfiguration this
    # catches rather than silently allows). See pg.policy_engine's category_allowed check.
    allowed_merchants: list[str]        # merchant ids, not names scraped off a page
    denied_keywords: list[str] = Field(default_factory=lambda: ["gift card", "voucher", "top-up", "prepaid"])
    require_human_above: OptionalXsgdAmount = None   # None = no human-approval threshold enforced
    expires_at: str
    max_delivery_days: Optional[int] = None   # None = no delivery constraint enforced


# Attribute values may be scalars only — never a list/dict a merchant could smuggle
# arbitrary structure (or an instruction-bearing nested string) through as "just data".
AttributeScalar = Union[str, int, float, bool, None]
MAX_ATTRIBUTE_KEY_LENGTH = 32
MAX_ATTRIBUTE_VALUE_LENGTH = 64


def _validate_attributes(raw: object) -> dict[str, AttributeScalar]:
    """Keep only scalar-valued attributes, with a bounded key length (<=32 chars) and a
    bounded string value length (<=64 chars). Anything else (non-scalar values, oversized
    keys/values, a non-dict payload entirely) is silently dropped, never rejected wholesale
    — one bad attribute must not cost every other, honest one."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, AttributeScalar] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key or len(key) > MAX_ATTRIBUTE_KEY_LENGTH:
            continue
        if isinstance(value, str):
            if len(value) > MAX_ATTRIBUTE_VALUE_LENGTH:
                continue
            out[key] = value
        elif isinstance(value, bool) or isinstance(value, (int, float)) or value is None:
            out[key] = value
        # dict/list values (or any other non-scalar) are dropped: not a scalar.
    return out


OfferAttributes = Annotated[dict[str, AttributeScalar], BeforeValidator(_validate_attributes)]


class Offer(BaseModel):
    """A sanitized, fully typed merchant offer — the ONLY shape merchant data takes once it
    has passed through `pg.prehook.sanitise()`. Every field here is either PM-authored typed
    metadata (offer_id, sku, product_type, category, ...) or FINTECH/ProcureGuard-owned
    (reputation, currency) — never raw, untrusted merchant free text passed through
    unexamined.

    There is deliberately no `description` field: ordinary merchant free text is always
    discarded before it reaches this model (see `pg/prehook.py`). The one narrow, explicit
    exception is `untrusted_demo_description`, populated only for BargainBin's hostile
    BB-C01 item and only when `DEMO_INJECTION_PASSTHROUGH` is explicitly set — named to make
    unmistakably clear that its content is untrusted demo data, never something to act on.
    """

    offer_id: str
    merchant_id: str
    merchant_name: str
    sku: str
    title: str
    product_type: str
    category: str
    unit_price_xsgd: XsgdAmount
    shipping_cost_xsgd: XsgdAmount = Decimal("0.00")
    currency: str = "XSGD"
    delivery_days: int
    stock: Optional[int] = None         # None = UNKNOWN availability, never "unlimited"
    in_stock: bool
    reputation: float                   # 0-1, from OUR registry, never the merchant's claim
    checkout_url: str
    attributes: OfferAttributes = Field(default_factory=dict)
    untrusted_demo_description: Optional[str] = None
    # ^ See class docstring: BB-C01 + DEMO_INJECTION_PASSTHROUGH only, never populated
    # otherwise, for any merchant or item.

    def meets_quantity(self, quantity: int) -> bool:
        """True if this offer can fulfil `quantity` units. `stock=None` means UNKNOWN
        availability, not unlimited: it is gated purely by `in_stock` (never treated as a
        green light for an arbitrarily large quantity). Only an actually-reported stock
        count is checked numerically against the requested quantity."""
        if not self.in_stock:
            return False
        if self.stock is None:
            return True
        return self.stock >= quantity


class Decision(BaseModel):
    """What the execution agent wants to do, and why. Free text lives ONLY in `reasoning`."""

    decision_id: str
    goal: str
    chosen: Offer
    rejected: list[Offer]
    reasoning: str
    quantity: int = 1

    @property
    def amount(self) -> Decimal:
        return self.chosen.unit_price_xsgd * self.quantity


class SpendIntentLeg(BaseModel):
    """One merchant's slice of a (possibly split-merchant) procurement: its own SpendIntent
    bearer token, scoped to only that merchant's items and amount. A single-merchant
    purchase produces exactly one leg; a split-merchant basket produces one leg per
    distinct merchant, all sharing one `procurement_id`."""

    merchant_id: str
    amount: XsgdAmount
    spend_intent: str


class PolicyVerdict(BaseModel):
    allowed: bool
    checks: list[dict]                  # [{name, passed, detail}]
    needs_human: bool = False
    reason: Optional[str] = None
    spend_intent: Optional[str] = None
    # ^ DEPRECATED compatibility view: set only when there is exactly one leg (every
    # single-item purchase, and any basket that happens to resolve to one merchant), so old
    # single-leg callers/tests keep working unchanged. New code should use `spend_intents`.
    spend_intents: list[SpendIntentLeg] = Field(default_factory=list)
    procurement_id: Optional[str] = None   # links every leg of one checkout, single or split
    approval_id: Optional[str] = None    # set when needs_human; the human resolves this
    remaining_budget: XsgdAmount = Decimal("0.00")


class SelectedLineItem(BaseModel):
    """One resolved basket line: a `RequestedItem` matched to a specific merchant's SKU at a
    fixed unit price. `unit_price` and every other field here is re-checked by the policy
    engine against the developer-owned quote catalogue (`product/catalog.json`) before any
    money moves — nothing here is trusted just because it was proposed."""

    requested_item: RequestedItem
    merchant_id: str
    sku: str
    quote_id: Optional[str] = None      # set when a quote catalogue assigned one (openai mode)
    unit_price: XsgdAmount
    quantity: int = Field(gt=0)

    @property
    def subtotal(self) -> Decimal:
        return self.unit_price * self.quantity


class RejectedAlternative(BaseModel):
    """An offer that was considered and turned down, and why. Free text lives ONLY in
    `reason`."""

    requested_item: Optional[RequestedItem] = None
    merchant_id: Optional[str] = None
    sku: Optional[str] = None
    quote_id: Optional[str] = None
    reason: str


class PurchaseProposal(BaseModel):
    """A multi-item basket decision — the basket-shaped counterpart to `Decision` above.
    Used by both the scripted basket flow (agent/run.py) and the OpenAI execution agent
    (agent/execution_agent.py). Every field the policy engine needs to check a basket
    (total amount, merchant, category, SKU, stock, delivery, denied keywords) is derived
    from `selected_items`, cross-checked against the quote catalogue, never taken on faith."""

    decision_id: str
    goal: str
    selected_items: list[SelectedLineItem]
    rejected_alternatives: list[RejectedAlternative] = Field(default_factory=list)
    reasoning: str

    @property
    def total_amount(self) -> Decimal:
        return sum((item.subtotal for item in self.selected_items), Decimal("0.00"))

    @property
    def merchant_ids(self) -> set[str]:
        return {item.merchant_id for item in self.selected_items}


class SpendIntentItem(BaseModel):
    """One purchased line inside a SpendIntent: which offer, and how many units of it —
    nothing else. Never a price (the amount is the leg's exact total, see
    `SpendIntent.amount_xsgd`), never a wallet."""

    offer_id: str
    quantity: int = Field(gt=0)


class SpendIntent(BaseModel):
    """Scoped to one intent: one merchant, one exact amount, one window, one use. This
    intent identifies WHO (merchant_id), WHAT (items) and HOW MUCH (amount_xsgd) — it
    deliberately does not bind a wallet, asset, network, or chain id. Those are not decided
    until payment execution, when pg.policy_engine.resolve_and_verify_payment() resolves
    the recipient from the Merchant Wallet Registry (pg/merchant_registry.py) and checks it
    against what the merchant's 402 challenge actually claims. Binding a wallet at mint
    time would let a recipient go stale (or be minted before FINTECH has even registered
    one); resolving it at execution time means the registry is always the live source of
    truth.

    A single procurement (one PurchaseProposal) may now span several merchants — one
    SpendIntent is minted per merchant leg, each scoped to only that merchant's items and
    amount, and every leg of the same checkout shares one `procurement_id` so they can be
    linked together in audit events without granting one leg any authority over another's
    reservation, commit, or replay state.
    """

    spend_intent_id: str
    procurement_id: str           # links every leg of one checkout together
    mandate_id: str
    merchant_id: str
    items: list[SpendIntentItem]
    amount_xsgd: XsgdAmount        # EXACT approved amount — not a ceiling
    currency: Literal["XSGD"] = "XSGD"
    nonce: str                   # single-use anti-replay nonce
    status: str                  # AUTHORIZED | EXECUTING | CONSUMED | EXPIRED | DENIED |
                                  # FAILED | CANCELLED | RECONCILIATION_REQUIRED
    created_at: str
    expires_at: str
