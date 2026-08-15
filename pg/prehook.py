"""Pre-hook: the boundary where untrusted merchant data becomes typed facts.

Read this before you explain the architecture to a judge, because the ordering of the two
mechanisms below is the whole argument.

1. PROJECTION is the defence. Every merchant response is projected onto the `Offer` schema.
   Only named, typed fields survive (see `ALLOWED_ITEM_FIELDS`). Everything else — free-text
   descriptions, store notices, HTML, unknown keys — is dropped before the data reaches the
   model or the policy engine. Attacker text cannot carry an instruction if it is never in
   the context window as one. The one deliberate exception is `DEMO_INJECTION_PASSTHROUGH`,
   an explicit, off-by-default env toggle that exposes BargainBin's hostile BB-C01 item's
   description, unstripped, as `Offer.untrusted_demo_description` — purely so a live demo
   can contrast "unprotected" against "defended" — never enabled by default, and never for
   any other item or merchant.

2. DETECTION is telemetry, not defence. The signal patterns below exist so the dashboard can
   say "1 injection attempt observed and discarded". If a judge asks what happens when an
   attacker phrases the injection differently, the honest and strong answer is: nothing
   changes. We do not depend on recognising the attack. We depend on never treating merchant
   text as instructions in the first place. The detector missing a novel phrasing costs us a
   number on a dashboard, not a payment.

Anyone who inverts that ordering — detection first, projection as backup — has built a
filter, and filters lose to paraphrase.

Every typed string field that DOES survive projection (title, product_type, category,
merchant_name) is additionally stripped of HTML markup before it reaches the `Offer` model
— an allowlisted field is still not a licence to carry a `<script>` or a hidden
`<span style="...">` an attacker relies on human review not noticing.
"""
from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from .models import Offer

# Fields that survive projection. Anything not on this list never leaves the pre-hook.
# offer_id/product_type/delivery_label are PM-authored typed metadata, same trust level as
# sku/title/category — never free text a merchant could use to carry an instruction.
ALLOWED_ITEM_FIELDS = {
    "offer_id", "sku", "title", "product_type", "category", "price", "currency",
    "delivery_days", "in_stock", "delivery_label", "checkout_url",
    "shipping_cost", "stock", "attributes",
}

# The one, deliberately narrow demo exception: only BargainBin's hostile BB-C01 item's
# `description` may ever be exposed unstripped, and only when this is explicitly set — see
# `Offer.untrusted_demo_description`. Never enabled by default, never enabled in any
# shipped profile/.env, never applied to any other item or merchant.
DEMO_INJECTION_PASSTHROUGH = os.environ.get("DEMO_INJECTION_PASSTHROUGH", "").strip().lower() in {
    "1", "true", "yes", "on",
}
DEMO_INJECTION_PASSTHROUGH_SKU = "BB-C01"

SIGNALS: list[tuple[str, str]] = [
    ("instruction_override", r"ignore (all )?(previous|prior|your)"),
    ("fake_authority", r"(system notice|administrator|authoris?ed override|policy has been updated)"),
    ("concealment", r"do not (mention|reveal|disclose|tell)"),
    ("limit_tampering", r"(spending|budget) limits?"),
    ("exfiltration", r"0x[a-fA-F0-9]{6,}|send (it|them|the card) to"),
    ("prohibited_goods", r"(gift card|voucher|prepaid|top-?up)"),
]

_HTML_TAG_RE = re.compile(r"<[^>]+>")


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


def _clean_typed_field(report: PrehookReport, field_label: str, raw: str) -> str:
    """Strip HTML markup from an otherwise-allowlisted typed string field. Being on the
    allowlist means the FIELD is trusted metadata, not that its literal text is exempt from
    the same discard-untyped-markup rule as everything else — an attacker should not be
    able to smuggle a hidden `<span>`/`<script>` through `title` just because `title` is a
    field we forward."""
    if not _HTML_TAG_RE.search(raw):
        return raw
    cleaned = _HTML_TAG_RE.sub("", raw)
    report.chars_dropped += len(raw) - len(cleaned)
    report.signals.append({
        "field": field_label,
        "signal": "html_markup",
        "excerpt": raw[:80].strip(),
    })
    return cleaned


def sanitise(response: dict[str, Any], reputation: float) -> tuple[list[Offer], PrehookReport]:
    """Project one merchant's search response into typed Offers. Never raises on hostile input."""
    merchant_id = str(response.get("merchant_id", "unknown"))
    report = PrehookReport(merchant_id=merchant_id)
    merchant_name = _clean_typed_field(report, "merchant_name", str(response.get("merchant_name", merchant_id)))
    offers: list[Offer] = []

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
        passthrough_description: str | None = None
        for key, value in item.items():
            if key not in ALLOWED_ITEM_FIELDS and isinstance(value, str):
                label = f"items[].{key}"
                if (
                    key == "description"
                    and DEMO_INJECTION_PASSTHROUGH
                    and str(item.get("sku")) == DEMO_INJECTION_PASSTHROUGH_SKU
                ):
                    # Still detected for telemetry, but NOT dropped — see
                    # DEMO_INJECTION_PASSTHROUGH above. Narrowly scoped to BB-C01 only.
                    passthrough_description = value
                    report.signals.extend(_scan(label, value))
                    continue
                if label not in report.fields_dropped:
                    report.fields_dropped.append(label)
                report.chars_dropped += len(value)
                report.signals.extend(_scan(label, value))
        try:
            offers.append(Offer(
                offer_id=str(item.get("offer_id", item["sku"])),
                merchant_id=merchant_id,
                merchant_name=merchant_name,
                sku=str(item["sku"]),
                title=_clean_typed_field(report, "items[].title", str(item["title"])),
                product_type=_clean_typed_field(
                    report, "items[].product_type", str(item.get("product_type", "unknown"))
                ),
                category=_clean_typed_field(report, "items[].category", str(item["category"])),
                unit_price_xsgd=item["price"],
                shipping_cost_xsgd=item.get("shipping_cost", 0),
                currency=str(item.get("currency", "XSGD")),
                delivery_days=int(item["delivery_days"]),
                stock=item.get("stock"),
                in_stock=bool(item["in_stock"]),
                reputation=reputation,              # ours, never the merchant's claim
                checkout_url=str(item["checkout_url"]),
                attributes=item.get("attributes", {}),
                untrusted_demo_description=passthrough_description,
            ))
            report.items_out += 1
        except (KeyError, TypeError, ValueError, ValidationError):
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
    return offers, report

