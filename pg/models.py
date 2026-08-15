"""Shared types. The Mandate is the constitution: everything downstream is checked against it."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Mandate(BaseModel):
    """Signed by the human, once. The agent never gets to edit this."""

    mandate_id: str
    principal: str                      # who the agent buys for
    currency: Literal["XSGD"] = "XSGD"
    budget_total: float                 # lifetime cap for this mandate
    per_txn_max: float                  # single transaction ceiling
    allowed_categories: list[str]
    allowed_merchants: list[str]        # merchant ids, not names scraped off a page
    denied_keywords: list[str] = Field(default_factory=lambda: ["gift card", "voucher", "top-up", "prepaid"])
    require_human_above: float          # anything above this needs a human tap
    expires_at: str
    max_delivery_days: Optional[int] = None   # None = no delivery constraint enforced


class Quote(BaseModel):
    merchant_id: str
    merchant_name: str
    sku: str
    title: str
    category: str
    price: float
    currency: str = "XSGD"
    delivery_days: int
    in_stock: bool
    reputation: float                   # 0-1, from OUR registry, never from the merchant
    checkout_url: str


class Decision(BaseModel):
    """What the execution agent wants to do, and why. Free text lives ONLY in `reasoning`."""

    decision_id: str
    goal: str
    chosen: Quote
    rejected: list[Quote]
    reasoning: str
    quantity: int = 1

    @property
    def amount(self) -> float:
        return round(self.chosen.price * self.quantity, 2)


class PolicyVerdict(BaseModel):
    allowed: bool
    checks: list[dict]                  # [{name, passed, detail}]
    needs_human: bool = False
    reason: Optional[str] = None
    spend_intent: Optional[str] = None   # HMAC bearer; the ONLY thing that unlocks a signature
    approval_id: Optional[str] = None    # set when needs_human; the human resolves this
    remaining_budget: float = 0.0


class RequestedItem(BaseModel):
    """One line of what the buyer actually asked for — a name and a quantity. Not what was
    found in any catalogue; see `SelectedLineItem` for the resolved match."""

    name: str
    quantity: int = Field(gt=0)


class SelectedLineItem(BaseModel):
    """One resolved basket line: a `RequestedItem` matched to a specific merchant's SKU at a
    fixed unit price. `unit_price` and every other field here is re-checked by the policy
    engine against the developer-owned quote catalogue (`product/catalog.json`) before any
    money moves — nothing here is trusted just because it was proposed."""

    requested_item: RequestedItem
    merchant_id: str
    sku: str
    quote_id: Optional[str] = None      # set when a quote catalogue assigned one (openai mode)
    unit_price: float
    quantity: int = Field(gt=0)

    @property
    def subtotal(self) -> float:
        return round(self.unit_price * self.quantity, 2)


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
    def total_amount(self) -> float:
        return round(sum(item.subtotal for item in self.selected_items), 2)

    @property
    def merchant_ids(self) -> set[str]:
        return {item.merchant_id for item in self.selected_items}


class SpendIntent(BaseModel):
    """Scoped to one intent: one merchant, one exact amount, one wallet, one asset,
    one network, one window, one use. Every field here is re-checked at authorization
    time against what the merchant's 402 challenge actually claims — none of it is
    trusted from the challenge alone.
    """

    intent_id: str
    mandate_id: str
    decision_id: str
    merchant_id: str
    pay_to: str                 # expected merchant wallet, resolved from OUR registry
    asset: str                  # expected XSGD contract address
    network: str                 # expected network, e.g. eip155:43113
    chain_id: int                # expected EIP-155 chain id, derived from `network`
    amount: float                 # EXACT approved amount — not a ceiling
    nonce: str                   # single-use anti-replay nonce
    expires_at: str
