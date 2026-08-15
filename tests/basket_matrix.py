"""The basket policy specification, as an executable table — the multi-item counterpart to
tests/policy_matrix.py. Every rule the business cares about for a multi-line-item, single-
merchant checkout appears here as a case with an expected outcome.

Run:  python -m tests.basket_matrix
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins.
os.environ.setdefault("POLICY_SECRET", "test-only-basket-matrix-secret-do-not-use-in-prod")

from agent.run import choose_basket
from pg import policy_engine as pe
from pg.models import (
    Mandate, PurchaseProposal, Quote, RequestedItem, SelectedLineItem,
)

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}
TRUSTED = ["techstore", "gadgethub", "quickelectronics"]
REPO_ROOT = Path(__file__).resolve().parent.parent


def mandate(**over) -> Mandate:
    base = dict(
        mandate_id="m-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=30.0,
        per_txn_max=15.0,
        allowed_categories=["electronics", "accessories"],
        allowed_merchants=list(TRUSTED),
        require_human_above=12.0,
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
        max_delivery_days=0,
    )
    base.update(over)
    return Mandate(**base)


def line(merchant_id: str, sku: str, unit_price: float, quantity: int = 1,
         item_name: str | None = None) -> SelectedLineItem:
    """A basket line item. Prices/skus here are what the (possibly tampered) proposal
    CLAIMS — evaluate_basket() re-derives the truth from product/catalog.json regardless."""
    return SelectedLineItem(
        requested_item=RequestedItem(name=item_name or sku, quantity=quantity),
        merchant_id=merchant_id, sku=sku, unit_price=unit_price, quantity=quantity,
    )


def proposal(*items: SelectedLineItem, reasoning: str = "cheapest same-day bundle") -> PurchaseProposal:
    return PurchaseProposal(
        decision_id="d-" + uuid.uuid4().hex[:8], goal="basket test",
        selected_items=list(items), reasoning=reasoning,
    )


# ---------------------------------------------------------------- basket policy cases

BASKET_CASES = [
    # (id, description, mandate, proposal, expect_allowed, expect_failing_check)
    ("B1", "two real items, one merchant, in budget, same-day",
     mandate(), proposal(line("techstore", "TS-USBC-65", 8.50), line("techstore", "TS-MOUSE-WL", 3.50)),
     True, None),

    ("B2", "no line items selected",
     mandate(), proposal(), False, "has_items"),

    ("B3", "basket spans two merchants",
     mandate(), proposal(line("techstore", "TS-USBC-65", 8.50), line("gadgethub", "GH-MOUSE-WL", 3.00)),
     False, "single_merchant"),

    ("B4", "combined basket total above the per-transaction cap",
     mandate(), proposal(line("techstore", "TS-HUB-7P", 13.50), line("techstore", "TS-MOUSE-WL", 3.50)),
     False, "per_txn_limit"),

    ("B5", "combined basket total above the human-approval threshold but under the cap",
     mandate(max_delivery_days=None), proposal(line("techstore", "TS-HUB-7P", 13.50)),
     False, None),  # allowed=False because needs_human=True

    ("B6", "single line item over budget remaining",
     mandate(budget_total=5.0), proposal(line("techstore", "TS-USBC-65", 8.50)),
     False, "budget_remaining"),

    ("B7", "merchant not on the mandate allowlist",
     mandate(), proposal(line("bargainbin", "BB-USBC-65", 3.00)),
     False, "merchant_allowed"),

    ("B8", "unknown sku for the claimed merchant",
     mandate(), proposal(line("techstore", "TS-NO-SUCH-SKU", 1.00)),
     False, "sku_known[techstore:TS-NO-SUCH-SKU]"),

    ("B9", "claimed unit price does not match the catalogue",
     mandate(), proposal(line("techstore", "TS-USBC-65", 1.00)),
     False, "price_match[techstore:TS-USBC-65]"),

    ("B10", "prohibited category for one line item",
     mandate(allowed_categories=["electronics"]),
     proposal(line("techstore", "TS-USBC-65", 8.50), line("techstore", "TS-MOUSE-WL", 3.50)),
     False, "category_allowed[techstore:TS-MOUSE-WL]"),

    ("B11", "one line item out of stock",
     mandate(), proposal(line("quickelectronics", "QE-HDMI-2M", 6.80)),
     False, "in_stock[quickelectronics:QE-HDMI-2M]"),

    ("B12", "one line item breaches the same-day delivery constraint",
     mandate(max_delivery_days=0), proposal(line("gadgethub", "GH-USBC-65", 7.20)),
     False, "delivery_ok[gadgethub:GH-USBC-65]"),

    ("B13", "denied keyword matches a real catalogue item",
     mandate(denied_keywords=["mouse"]),
     proposal(line("techstore", "TS-USBC-65", 8.50), line("techstore", "TS-MOUSE-WL", 3.50)),
     False, "no_denied_items[techstore:TS-MOUSE-WL]"),
]


def mint_cases() -> list[tuple]:
    """A minted basket SpendIntent binds to ONE merchant and the combined total — proving
    the existing SpendIntent lifecycle (reserve/commit, replay-proof) needs no changes to
    support baskets."""
    out = []

    m, p = mandate(), proposal(line("techstore", "TS-USBC-65", 8.50), line("techstore", "TS-MOUSE-WL", 3.50))
    v = pe.evaluate_basket(m, p)
    reg = pe.MERCHANT_REGISTRY["techstore"]
    ok, ref = pe.reserve_intent(
        v.spend_intent, "techstore", 12.0, pay_to=reg["wallet"], asset=pe.XSGD_ASSET,
        network=pe.expected_network(), chain_id=int(pe.expected_network().split(":")[1]),
    )
    if ok:
        pe.commit_intent(ref)
    out.append(("M1", "basket SpendIntent redeemed once, for the exact combined total", ok, True))

    m2, p2 = mandate(), proposal(line("techstore", "TS-USBC-65", 8.50), line("techstore", "TS-MOUSE-WL", 3.50))
    v2 = pe.evaluate_basket(m2, p2)
    ok2, ref2 = pe.reserve_intent(
        v2.spend_intent, "techstore", 20.0, pay_to=reg["wallet"], asset=pe.XSGD_ASSET,
        network=pe.expected_network(), chain_id=int(pe.expected_network().split(":")[1]),
    )
    out.append(("M2", "402 quotes 20.00 against a basket intent approved for 12.00", ok2, False))

    return out


# ---------------------------------------------------------------- choose_basket (pure, no I/O)

def _quote(merchant_id, sku, title, price, delivery_days=0, in_stock=True, category="electronics") -> Quote:
    return Quote(
        merchant_id=merchant_id, merchant_name=merchant_id.title(), sku=sku, title=title,
        category=category, price=price, delivery_days=delivery_days, in_stock=in_stock,
        reputation=pe.MERCHANT_REGISTRY.get(merchant_id, {}).get("reputation", 0.0),
        checkout_url=f"/{merchant_id}/checkout",
    )


def choose_basket_cases() -> list[tuple]:
    requested = [RequestedItem(name="usb-c charger", quantity=1), RequestedItem(name="wireless mouse", quantity=1)]
    quotes_by_item = {
        "usb-c charger": [
            _quote("techstore", "TS-USBC-65", "USB-C 65W Charger", 8.50),
            _quote("gadgethub", "GH-USBC-65", "USB-C 65W Charger", 7.20, delivery_days=2),
            _quote("quickelectronics", "QE-USBC-65", "USB-C 65W Charger", 9.00),
        ],
        "wireless mouse": [
            _quote("techstore", "TS-MOUSE-WL", "Wireless Mouse", 3.50, category="accessories"),
            _quote("gadgethub", "GH-MOUSE-WL", "Wireless Mouse", 3.00, delivery_days=2, category="accessories"),
            _quote("quickelectronics", "QE-MOUSE-WL", "Wireless Mouse", 3.20, category="accessories"),
        ],
    }

    out = []

    p = choose_basket(requested, quotes_by_item, require_same_day=True)
    out.append(("K1", "cheapest merchant that can supply every line same-day wins",
               list(p.merchant_ids) == ["techstore"] and p.total_amount == 12.0, True))

    # GadgetHub is cheaper overall (10.20) but 2-day on every line, so it must be recorded as
    # rejected (unable to supply the full basket same-day), not silently dropped.
    gadgethub_rejected = next((r for r in p.rejected_alternatives if r.merchant_id == "gadgethub"), None)
    out.append(("K2", "a cheaper 2-day-only merchant is rejected and explained, not chosen",
               gadgethub_rejected is not None and "same-day" in gadgethub_rejected.reason, True))

    p_any_day = choose_basket(requested, quotes_by_item, require_same_day=False)
    out.append(("K3", "with no same-day requirement, GadgetHub's cheaper bundle wins",
               list(p_any_day.merchant_ids) == ["gadgethub"] and p_any_day.total_amount == 10.20, True))

    return out


# ---------------------------------------------------------------- end-to-end demo scenario

def demo_scenario_case() -> tuple[str, str, bool]:
    """Loads product/demo_scenarios.json's basket_purchase scenario and fintech/policy_config
    .json's default_mandate — exactly as agent/run.py's --basket flag does — and proves the
    deterministic chooser + policy engine reproduce the PM/FINTECH-configured expectations.
    Nothing here is hardcoded: change the JSON and this case follows."""
    scenarios = json.loads((REPO_ROOT / "product" / "demo_scenarios.json").read_text(encoding="utf-8"))["scenarios"]
    scenario = next(s for s in scenarios if s["id"] == "basket_purchase")
    fintech = json.loads((REPO_ROOT / "fintech" / "policy_config.json").read_text(encoding="utf-8"))["default_mandate"]

    requested = [RequestedItem(**p) for p in scenario["requested_products"]]
    m = mandate(
        budget_total=scenario["budget"],
        per_txn_max=fintech["per_txn_max"],
        allowed_categories=fintech["allowed_categories"],
        denied_keywords=fintech["denied_keywords"],
        require_human_above=fintech["require_human_above"],
        max_delivery_days=fintech.get("max_delivery_days"),
    )

    quotes_by_item = {}
    catalog = json.loads((REPO_ROOT / "product" / "catalog.json").read_text(encoding="utf-8"))
    for item in requested:
        matches = []
        for merchant_id, merchant in catalog["merchants"].items():
            for it in merchant["items"]:
                if item.name.split()[0].lower() in it["title"].lower() or \
                   all(w in it["title"].lower() for w in item.name.lower().split()):
                    matches.append(_quote(merchant_id, it["sku"], it["title"], it["price"],
                                           it["delivery_days"], it["in_stock"], it["category"]))
        quotes_by_item[item.name] = matches

    p = choose_basket(requested, quotes_by_item, require_same_day=True)
    v = pe.evaluate_basket(m, p)

    selected_ok = list(p.merchant_ids) == [scenario["expected_selected_merchant"]]
    outcome = "PAID" if v.allowed else ("HUMAN" if v.needs_human else "BLOCKED")
    outcome_ok = outcome == scenario["expected_outcome"]

    ending_ok = False
    if v.allowed and v.spend_intent:
        reg = pe.MERCHANT_REGISTRY[next(iter(p.merchant_ids))]
        ok, ref = pe.reserve_intent(
            v.spend_intent, next(iter(p.merchant_ids)), p.total_amount, pay_to=reg["wallet"],
            asset=pe.XSGD_ASSET, network=pe.expected_network(),
            chain_id=int(pe.expected_network().split(":")[1]),
        )
        if ok:
            pe.commit_intent(ref)
        ending_balance = round(m.budget_total - pe.spent(m.mandate_id), 2)
        ending_ok = ending_balance == scenario["expected_ending_balance"]

    return ("D1", "basket_purchase demo scenario matches PM+FINTECH-configured expectations",
            selected_ok and outcome_ok and ending_ok)


def run() -> int:
    failures = 0
    print(f"\n{C['b']}BASKET MATRIX — policy checks{C['off']}")
    print(f"{C['dim']}{'id':<5}{'expect':<24}{'result':<24}case{C['off']}")
    for cid, desc, m, p, expect_allowed, expect_check in BASKET_CASES:
        v = pe.evaluate_basket(m, p)
        ok = v.allowed == expect_allowed
        if expect_check:
            failed = [c["name"] for c in v.checks if not c["passed"]]
            ok = ok and expect_check in failed
        if cid == "B5":
            ok = ok and v.needs_human
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        exp = "allow" if expect_allowed else (expect_check or "human")
        got = "allow" if v.allowed else ("human" if v.needs_human else (v.reason or "block"))
        print(f"{cid:<5}{exp:<24}{got:<24}{desc}  [{mark}]")

    print(f"\n{C['b']}BASKET MATRIX — SpendIntent minting/replay{C['off']}")
    for cid, desc, got_ok, expect_ok in mint_cases():
        ok = got_ok == expect_ok
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        verb = "accept" if expect_ok else "reject"
        print(f"{cid:<5}{verb:<24}{str(got_ok):<24}{desc}  [{mark}]")

    print(f"\n{C['b']}BASKET MATRIX — choose_basket (pure, no I/O){C['off']}")
    for cid, desc, ok, expect_ok in choose_basket_cases():
        ok = ok == expect_ok
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(ok):<24}{'':<24}{desc}  [{mark}]")

    print(f"\n{C['b']}BASKET MATRIX — end-to-end demo scenario{C['off']}")
    cid, desc, ok = demo_scenario_case()
    failures += not ok
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{cid:<5}{'True':<24}{str(ok):<24}{desc}  [{mark}]")

    total = len(BASKET_CASES) + 2 + 3 + 1
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
