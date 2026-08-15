"""The basket policy specification, as an executable table — the multi-item counterpart to
tests/policy_matrix.py. Every rule the business cares about for a multi-line-item, single-
merchant checkout appears here as a case with an expected outcome.

Run:  python -m tests.basket_matrix
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins.
os.environ.setdefault("POLICY_SECRET", "test-only-basket-matrix-secret-do-not-use-in-prod")

from pg import policy_engine as pe
from pg import money
from pg.models import (
    Mandate, Offer, PurchaseProposal, RequestedItem, SelectedLineItem,
)
from tests._test_registry import build_test_registry

# Swap in a test-only registry (synthetic addresses, never the shipped
# data/merchant_registry.json) so basket SpendIntent minting/redemption has a real happy
# path to exercise.
pe.REGISTRY = build_test_registry()

# Imported only after pg.policy_engine has already read POLICY_SECRET above: agent.run is
# the execution-agent process entrypoint and REFUSES TO START if it sees a financial
# secret anywhere in this process's environment. pg.policy_engine has already cached
# POLICY_SECRET into its own module-level SECRET constant by this point, so it is safe
# (and required) to remove it from os.environ before importing agent.run — this test
# process deliberately holds both tiers in one interpreter, one after the other, never
# at the same time.
os.environ.pop("POLICY_SECRET", None)
from agent.run import choose_basket

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}
TRUSTED = ["techstore", "gadgethub", "cheapdealsstore"]
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
    base["per_intent_max"] = base.pop("per_txn_max")   # kwarg name kept for existing call sites
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
     mandate(), proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8)),
     True, None),

    ("B2", "no line items selected",
     mandate(), proposal(), False, "has_items"),

    ("B3", "basket spans two merchants: each leg checked and passes, one intent per merchant",
     mandate(max_delivery_days=None), proposal(line("techstore", "TS-H01", 4.8), line("gadgethub", "GH-C01", 6.9)),
     True, None),

    ("B4", "combined basket total above the per-transaction cap for one merchant leg",
     mandate(), proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-C02", 9.5)),
     False, "per_intent_limit[techstore]"),

    ("B5", "combined basket total above the human-approval threshold but under the cap",
     mandate(max_delivery_days=None), proposal(line("techstore", "TS-C01", 7.2, quantity=2)),
     False, None),  # allowed=False because needs_human=True

    ("B6", "single line item over budget remaining",
     mandate(budget_total=5.0), proposal(line("techstore", "TS-C01", 7.2)),
     False, "delegated_budget"),

    ("B7", "merchant not on the mandate allowlist",
     mandate(), proposal(line("bargainbin", "BB-C01", 7.8)),
     False, "merchant_allowed[bargainbin]"),

    ("B8", "unknown sku for the claimed merchant",
     mandate(), proposal(line("techstore", "TS-NO-SUCH-SKU", 1.00)),
     False, "offer_exists[techstore:TS-NO-SUCH-SKU]"),

    ("B9", "claimed unit price does not match the catalogue (silently re-derived, not enforced)",
     mandate(), proposal(line("techstore", "TS-C01", 1.00)),
     True, None),

    ("B10", "prohibited category for one line item",
     mandate(allowed_categories=["electronics"], allowed_merchants=["bargainbin"],
             budget_total=50.0, per_txn_max=50.0, require_human_above=50.0),
     proposal(line("bargainbin", "BB-C01", 7.8), line("bargainbin", "BB-G01", 25.0)),
     False, "category_allowed[bargainbin:BB-G01]"),

    ("B12", "one line item breaches the same-day delivery constraint (not enforced by evaluate_basket)",
     mandate(max_delivery_days=0), proposal(line("gadgethub", "GH-C02", 8.2)),
     True, None),

    ("B13", "denied keyword matches a real catalogue item",
     mandate(denied_keywords=["hdmi"]),
     proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8)),
     False, "no_denied_items[techstore:TS-H01]"),
]


def mint_cases() -> list[tuple]:
    """A minted basket SpendIntent binds to ONE merchant and the combined total — proving
    the existing SpendIntent lifecycle (reserve/commit, replay-proof) needs no changes to
    support baskets."""
    out = []

    m, p = mandate(), proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8))
    v = pe.evaluate_basket(m, p)
    ok, ref = pe.reserve_intent(v.spend_intent, "techstore", 12.0)
    if ok:
        pe.commit_intent(ref)
    out.append(("M1", "basket SpendIntent redeemed once, for the exact combined total", ok, True))

    m2, p2 = mandate(), proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8))
    v2 = pe.evaluate_basket(m2, p2)
    ok2, ref2 = pe.reserve_intent(v2.spend_intent, "techstore", 20.0)
    out.append(("M2", "402 quotes 20.00 against a basket intent approved for 12.00", ok2, False))

    return out


# ---------------------------------------------------------------- split-merchant procurement

def split_merchant_cases() -> list[tuple]:
    """Requirement 9: a split-merchant basket mints one SpendIntent per merchant leg,
    same-merchant items still bundle into a single intent, and an invalid leg rolls back
    the WHOLE basket — no intent or reservation survives a partial failure, even for the
    leg that would have passed alone."""
    out = []

    m1, p1 = mandate(), proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8))
    v1 = pe.evaluate_basket(m1, p1)
    out.append(("S1", "TechStore single-merchant basket produces exactly one SpendIntent",
                v1.allowed and len(v1.spend_intents) == 1, True))

    m2 = mandate(max_delivery_days=None, require_human_above=50.0)
    p2 = proposal(
        line("techstore", "TS-C01", 7.2), line("techstore", "TS-H01", 4.8),
        line("gadgethub", "GH-C01", 6.9),
    )
    v2 = pe.evaluate_basket(m2, p2)
    two_intents = (
        v2.allowed and len(v2.spend_intents) == 2
        and {leg.merchant_id for leg in v2.spend_intents} == {"techstore", "gadgethub"}
        and v2.procurement_id == p2.decision_id
        and all(leg.spend_intent for leg in v2.spend_intents)
    )
    out.append(("S2", "TechStore chargers plus GadgetHub cable produces two SpendIntents", two_intents, True))

    m3 = mandate()
    p3 = proposal(line("techstore", "TS-C01", 7.2), line("gadgethub", "GH-NO-SUCH-SKU", 1.00))
    v3 = pe.evaluate_basket(m3, p3)
    rollback_ok = not v3.allowed and len(v3.spend_intents) == 0 and pe._reserved_total(m3.mandate_id) == money.ZERO
    out.append(("S3", "one invalid leg rolls back the entire basket (no intents, no reservations)",
                rollback_ok, True))

    return out


def replay_isolation_case() -> tuple:
    """Replaying (attempting to reserve twice) one merchant leg's SpendIntent must not
    affect, consume, or unlock the other merchant leg's SpendIntent from the same basket."""
    m = mandate(max_delivery_days=None, require_human_above=50.0)
    p = proposal(line("techstore", "TS-C01", 7.2), line("gadgethub", "GH-C01", 6.9))
    v = pe.evaluate_basket(m, p)
    legs = {leg.merchant_id: leg for leg in v.spend_intents}
    ts_leg, gh_leg = legs["techstore"], legs["gadgethub"]

    ok1, ref1 = pe.reserve_intent(ts_leg.spend_intent, "techstore", ts_leg.amount)
    replay_ok, _ = pe.reserve_intent(ts_leg.spend_intent, "techstore", ts_leg.amount)   # replay of the SAME leg
    ok2, ref2 = pe.reserve_intent(gh_leg.spend_intent, "gadgethub", gh_leg.amount)      # the OTHER leg, untouched
    if ok1:
        pe.commit_intent(ref1)
    if ok2:
        pe.commit_intent(ref2)
    isolated = ok1 and not replay_ok and ok2
    return ("S4", "replaying one intent cannot affect or replay another intent in the same basket", isolated)


def gadgethub_no_recipient_case() -> tuple:
    """A merchant can be ALLOWED and TRUSTED (passes evaluate_basket's per-leg
    merchant_allowed check — is_trusted() only requires ACTIVE + allowed, never a
    registered recipient) yet still have no wallet on file: the basket may be authorized
    to buy from it, but resolve_and_verify_payment() at actual payment time correctly
    refuses with NO_REGISTERED_RECIPIENT."""
    registry = build_test_registry(gadgethub={"payment_recipient": None})
    old_registry = pe.REGISTRY
    pe.REGISTRY = registry
    try:
        m = mandate(max_delivery_days=None)
        p = proposal(line("gadgethub", "GH-C01", 6.9))
        v = pe.evaluate_basket(m, p)
        basket_passed = v.allowed and len(v.spend_intents) == 1

        payment_failed = False
        try:
            pe.resolve_and_verify_payment("gadgethub", {
                "network": "eip155:43113", "chainId": 43113,
                "asset": pe.XSGD_ASSET, "payTo": "0x" + "b2" * 20,
            })
        except pe.RegistryLookupError as exc:
            payment_failed = exc.code == "NO_REGISTERED_RECIPIENT"
    finally:
        pe.REGISTRY = old_registry
    return ("S5", "GadgetHub passes basket selection but payment fails NO_REGISTERED_RECIPIENT",
            basket_passed and payment_failed)


def case_concurrent_basket_reservations() -> tuple[bool, str]:
    """Two concurrent baskets against the same 30 XSGD mandate, each needing 17.00 XSGD:
    together they would exceed the wallet, so at most one may actually reserve funds —
    proving the atomic multi-leg mint+reserve in `_mint_and_reserve_legs()` is race-proof,
    not just point-in-time-checked."""
    m = mandate(per_txn_max=20.0, require_human_above=25.0)

    results: list = []
    barrier = threading.Barrier(2)

    def attempt() -> None:
        p = proposal(line("techstore", "TS-C01", 7.2), line("techstore", "TS-C02", 9.5))
        barrier.wait()
        results.append(pe.evaluate_basket(m, p))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [v for v in results if v.allowed]
    total_reserved = pe._reserved_total(m.mandate_id)
    ok = len(successes) == 1 and total_reserved <= Decimal("30.00")
    return ok, f"successes={len(successes)} of 2 concurrent baskets, reserved={total_reserved:.2f}"


# ---------------------------------------------------------------- choose_basket (pure, no I/O)

def _quote(merchant_id, sku, title, price, delivery_days=0, in_stock=True, category="electronics") -> Offer:
    reg = pe.REGISTRY.get(merchant_id)
    return Offer(
        offer_id=sku, merchant_id=merchant_id, merchant_name=merchant_id.title(), sku=sku, title=title,
        product_type="unknown", category=category, unit_price_xsgd=price,
        delivery_days=delivery_days, in_stock=in_stock,
        reputation=reg.reputation if reg else 0.0,
        checkout_url=f"/{merchant_id}/checkout",
    )


def choose_basket_cases() -> list[tuple]:
    requested = [RequestedItem(name="usb-c charger", quantity=1), RequestedItem(name="wireless mouse", quantity=1)]
    quotes_by_item = {
        "usb-c charger": [
            _quote("techstore", "TS-USBC-65", "USB-C 65W Charger", 8.50),
            _quote("gadgethub", "GH-USBC-65", "USB-C 65W Charger", 7.20, delivery_days=2),
            _quote("cheapdealsstore", "CD-USBC-65", "USB-C 65W Charger", 9.00),
        ],
        "wireless mouse": [
            _quote("techstore", "TS-MOUSE-WL", "Wireless Mouse", 3.50, category="accessories"),
            _quote("gadgethub", "GH-MOUSE-WL", "Wireless Mouse", 3.00, delivery_days=2, category="accessories"),
            _quote("cheapdealsstore", "CD-MOUSE-WL", "Wireless Mouse", 3.20, category="accessories"),
        ],
    }

    out = []

    p = choose_basket(requested, quotes_by_item, require_same_day=True)
    out.append(("K1", "cheapest merchant that can supply every line same-day wins",
               list(p.merchant_ids) == ["techstore"] and p.total_amount == Decimal("12.00"), True))

    # GadgetHub is cheaper overall (10.20) but 2-day on every line, so it must be recorded as
    # rejected (unable to supply the full basket same-day), not silently dropped.
    gadgethub_rejected = next((r for r in p.rejected_alternatives if r.merchant_id == "gadgethub"), None)
    out.append(("K2", "a cheaper 2-day-only merchant is rejected and explained, not chosen",
               gadgethub_rejected is not None and "same-day" in gadgethub_rejected.reason, True))

    p_any_day = choose_basket(requested, quotes_by_item, require_same_day=False)
    out.append(("K3", "with no same-day requirement, GadgetHub's cheaper bundle wins",
               list(p_any_day.merchant_ids) == ["gadgethub"] and p_any_day.total_amount == Decimal("10.20"), True))

    return out


# ---------------------------------------------------------------- end-to-end demo scenario


def case_out_of_stock_item() -> tuple:
    """A real catalogue item explicitly marked out of stock must fail in_stock[...] even
    though every other check on it would otherwise pass. The shipped product/catalog.json
    ships fully in-stock by design (PM's demo catalogue), so this case points
    `pe.CATALOG_PATH` at a temporary copy of the real catalogue with exactly one item's
    `in_stock` flipped to false — it never edits the PM-owned file itself."""
    real_catalog = json.loads((REPO_ROOT / "product" / "catalog.json").read_text(encoding="utf-8"))
    real_catalog["merchants"]["techstore"]["items"][2]["in_stock"] = False   # TS-H01
    tmp_dir = Path(tempfile.mkdtemp(prefix="pg-test-catalog-"))
    tmp_path = tmp_dir / "catalog.json"
    tmp_path.write_text(json.dumps(real_catalog), encoding="utf-8")

    old_path = pe.CATALOG_PATH
    pe.CATALOG_PATH = tmp_path
    try:
        m = mandate()
        p = proposal(line("techstore", "TS-H01", 4.8))
        v = pe.evaluate_basket(m, p)
        failed = [c["name"] for c in v.checks if not c["passed"]]
        ok = not v.allowed and "stock_available[techstore:TS-H01]" in failed
    finally:
        pe.CATALOG_PATH = old_path
    return ("B11", "one line item out of stock (temp catalogue override, PM file untouched)", ok)


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
        per_txn_max=fintech["per_intent_max"],
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
        ok, ref = pe.reserve_intent(v.spend_intent, next(iter(p.merchant_ids)), p.total_amount)
        if ok:
            pe.commit_intent(ref)
        ending_balance = m.budget_total - pe.spent(m.mandate_id)
        ending_ok = ending_balance == money.to_xsgd(scenario["expected_ending_balance"])

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

    print(f"\n{C['b']}BASKET MATRIX — split-merchant procurement{C['off']}")
    for cid, desc, got, expect in split_merchant_cases():
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(ok):<24}{'':<24}{desc}  [{mark}]")

    cid, desc, ok = replay_isolation_case()
    failures += not ok
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{cid:<5}{str(ok):<24}{'':<24}{desc}  [{mark}]")

    cid, desc, ok = gadgethub_no_recipient_case()
    failures += not ok
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{cid:<5}{str(ok):<24}{'':<24}{desc}  [{mark}]")

    ok, detail = case_concurrent_basket_reservations()
    failures += not ok
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{'S6':<5}{str(ok):<24}{'':<24}concurrent reservations cannot exceed 30 XSGD ({detail})  [{mark}]")

    cid, desc, ok = case_out_of_stock_item()
    failures += not ok
    mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{cid:<5}{str(ok):<24}{'':<24}{desc}  [{mark}]")

    total = len(BASKET_CASES) + 2 + 3 + 1 + 7
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
