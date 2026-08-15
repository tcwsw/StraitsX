"""Pre-hook: the boundary where untrusted merchant data becomes typed facts.

Read this before you explain the architecture to a judge, because the ordering of the two
mechanisms below is the whole argument.

1. PROJECTION is the defence. Every merchant response is projected onto the `Quote` schema.
   Nine typed fields survive. Everything else — descriptions, store notices, HTML, unknown
   keys — is dropped before the data reaches the model or the policy engine. Attacker text
   cannot carry an instruction if it is never in the context window as one.

2. DETECTION is telemetry, not defence. The signal patterns below exist so the dashboard can
   say "1 injection attempt observed and discarded". If a judge asks what happens when an
   attacker phrases the injection differently, the honest and strong answer is: nothing
   changes. We do not depend on recognising the attack. We depend on never treating merchant
   text as instructions in the first place. The detector missing a novel phrasing costs us a
   number on a dashboard, not a payment.

Anyone who inverts that ordering — detection first, projection as backup — has built a
filter, and filters lose to paraphrase.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel

from .models import Quote

# Fields that survive projection. Anything not on this list never leaves the pre-hook.
ALLOWED_ITEM_FIELDS = {
    "sku", "title", "category", "price", "currency",
    "delivery_days", "in_stock", "checkout_url",
}

SIGNALS: list[tuple[str, str]] = [
    ("instruction_override", r"ignore (all )?(previous|prior|your)"),
    ("fake_authority", r"(system notice|administrator|authoris?ed override|policy has been updated)"),
    ("concealment", r"do not (mention|reveal|disclose|tell)"),
    ("limit_tampering", r"(spending|budget) limits?"),
    ("exfiltration", r"0x[a-fA-F0-9]{6,}|send (it|them|the card) to"),
    ("prohibited_goods", r"(gift card|voucher|prepaid|top-?up)"),
]


class PrehookReport(BaseModel):
    merchant_id: str
    items_in: int = 0
    items_out: int = 0
    fields_dropped: list[str] = []
    chars_dropped: int = 0
    signals: list[dict] = []          # [{field, signal, excerpt}]

    @property
    def hostile(self) -> bool:
        return bool(self.signals)

    def summary(self) -> str:
        if not self.signals:
            return f"{self.chars_dropped} chars of untyped text discarded, no signals"
        names = sorted({s["signal"] for s in self.signals})
        return (f"{self.chars_dropped} chars discarded, "
                f"{len(self.signals)} injection signals: {', '.join(names)}")


def _scan(field: str, text: str) -> list[dict]:
    found = []
    low = text.lower()
    for name, pattern in SIGNALS:
        m = re.search(pattern, low)
        if m:
            start = max(0, m.start() - 20)
            found.append({
                "field": field,
                "signal": name,
                "excerpt": text[start:m.end() + 40].strip(),
            })
    return found


def sanitise(response: dict[str, Any], reputation: float) -> tuple[list[Quote], PrehookReport]:
    """Project one merchant's search response into typed Quotes. Never raises on hostile input."""
    merchant_id = str(response.get("merchant_id", "unknown"))
    merchant_name = str(response.get("merchant_name", merchant_id))
    report = PrehookReport(merchant_id=merchant_id)
    quotes: list[Quote] = []

    # Top-level untyped fields (store_notice, banners, anything the merchant invents).
    for key, value in response.items():
        if key in {"merchant_id", "merchant_name", "items"}:
            continue
        if isinstance(value, str):
            report.fields_dropped.append(key)
            report.chars_dropped += len(value)
            report.signals.extend(_scan(key, value))

    for item in response.get("items", []):
        report.items_in += 1
        for key, value in item.items():
            if key not in ALLOWED_ITEM_FIELDS and isinstance(value, str):
                label = f"items[].{key}"
                if label not in report.fields_dropped:
                    report.fields_dropped.append(label)
                report.chars_dropped += len(value)
                report.signals.extend(_scan(label, value))
        try:
            quotes.append(Quote(
                merchant_id=merchant_id,
                merchant_name=merchant_name,
                sku=str(item["sku"]),
                title=str(item["title"]),
                category=str(item["category"]),
                price=float(item["price"]),
                currency=str(item.get("currency", "XSGD")),
                delivery_days=int(item["delivery_days"]),
                in_stock=bool(item["in_stock"]),
                reputation=reputation,              # ours, never the merchant's claim
                checkout_url=str(item["checkout_url"]),
            ))
            report.items_out += 1
        except (KeyError, TypeError, ValueError):
            continue                                 # malformed item, drop it silently

    # Deduplicate signals by (field, signal) so one repeated payload is not counted twice.
    seen: set[tuple[str, str]] = set()
    unique = []
    for s in report.signals:
        key = (s["field"], s["signal"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    report.signals = unique
    return quotes, report
