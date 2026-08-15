"""The final one-screen demo, as an executable table.

Everything else in tests/ proves the underlying engine/agent/audit machinery in isolation.
This file proves the SPECIFIC fixture the final dashboard (dashboard/app.py) is built
around: TechStore/GadgetHub/BargainBin/CheapDealsStore quoting the final-demo item at
19.20/19.40/20.50/15.50 XSGD against a 30.00 XSGD budget with a 20.00 XSGD per-merchant cap;
the new `GET /system/info` routes and agent pause/resume wiring; the deterministic
BargainBin attack fixture; the real-catalog "two chargers, one HDMI cable" basket variant;
and the full 402 -> sign -> settle payment step-tracker sequence for a single merchant leg.

Nothing here imports dashboard/app.py directly (a Streamlit script, not an importable
module) — every case exercises the same underlying `pg`/`agent`/`merchants` functions and
FastAPI routes the dashboard itself calls.

    P1-P15  policy checks against the exact final-demo fixture
    R1-R9   /system/info, /mandates, /agent/{id}/status routes
    A1-A3   the deterministic BargainBin attack fixture
    B1-B7   the real-catalog basket variant (choose_basket, pure, no I/O)
    T1-T6   the full 402 -> sign -> settle payment step tracker, one merchant leg

Run:  python -m tests.final_matrix
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# merchants.server reads its WALLET_* env vars once, at import time, to build its payout
# table — set them to match tests/_test_registry.py's synthetic recipients BEFORE import,
# so a real end-to-end 402 -> authorize -> settle round trip resolves cleanly.
from tests._test_registry import TEST_RECIPIENTS, build_test_registry

os.environ.setdefault("WALLET_TECHSTORE", TEST_RECIPIENTS["techstore"])
os.environ.setdefault("WALLET_GADGETHUB", TEST_RECIPIENTS["gadgethub"])
os.environ.setdefault("WALLET_BARGAIN", TEST_RECIPIENTS["bargainbin"])
os.environ.setdefault("WALLET_CHEAP", TEST_RECIPIENTS["cheapdealsstore"])

from fastapi.testclient import TestClient

# merchants.server AND agent.run each refuse to start (RuntimeError, at import time) if
# AGENT_PRIVATE_KEY/POLICY_SECRET are present in this process's environment — both must be
# imported BEFORE either secret is set below. pg.policy_engine/pg.policy_server are the
# opposite: they require POLICY_SECRET to already be set to import at all.
import agent.run as agent_run
import merchants.server as ms

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins. Setting it BEFORE importing
# pg.policy_server also means _load_policy_dotenv() never touches the developer's real
# .env.policy (e.g. its mainnet X402_NETWORK) for this test process.
os.environ.setdefault("POLICY_SECRET", "test-only-final-matrix-secret-do-not-use-in-prod")

from eth_account import Account

from pg import policy_engine as pe
from pg import policy_server as ps
from pg.models import Mandate, Offer, PurchaseProposal, RequestedItem, SelectedLineItem

pe.REGISTRY = build_test_registry()
os.environ.setdefault("AGENT_PRIVATE_KEY", Account.create().key.hex())
os.environ.pop("POLICY_SECRET", None)

policy_client = TestClient(ps.app)
merchants_client = TestClient(ms.app)

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}

# ---------------------------------------------------------------- the final-demo fixture
# Matches dashboard/app.py's FINAL_DEMO_* constants and product/catalog.json's TS-FD01/
# GH-FD01/BB-FD01/CD-FD01 dedicated SKUs exactly.

ALLOWED_MERCHANTS = ["techstore", "gadgethub", "bargainbin"]   # cheapdealsstore excluded
FINAL_DEMO_ITEM_NAME = "usb-c charger"
FINAL_DEMO_SKUS = {"techstore": "TS-FD01", "gadgethub": "GH-FD01",
                   "bargainbin": "BB-FD01", "cheapdealsstore": "CD-FD01"}
FINAL_DEMO_PRICES = {"techstore": Decimal("19.20"), "gadgethub": Decimal("19.40"),
                     "bargainbin": Decimal("20.50"), "cheapdealsstore": Decimal("15.50")}


def _final_mandate(**overrides) -> Mandate:
    base = dict(
        mandate_id="m-final-" + uuid.uuid4().hex[:8],
        principal="Team ProcureGuard",
        budget_total=Decimal("30.00"),
        per_intent_max=Decimal("20.00"),
        requested_items=[RequestedItem(name=FINAL_DEMO_ITEM_NAME, quantity=1)],
        allowed_categories=["electronics"],
        blocked_categories=["gift_card", "cash_equivalent"],
        allowed_merchants=list(ALLOWED_MERCHANTS),
        require_human_above=None,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    base.update(overrides)
    return Mandate(**base)


def _final_offer(merchant_id: str, **overrides) -> Offer:
    sku = overrides.pop("sku", FINAL_DEMO_SKUS[merchant_id])
    base = dict(
        offer_id=sku, merchant_id=merchant_id, merchant_name=merchant_id.title(), sku=sku,
        title="Final-Demo Mainnet Power Module 45W", product_type="charger",
        category="electronics", unit_price_xsgd=FINAL_DEMO_PRICES[merchant_id],
        delivery_days=0, stock=10, in_stock=True, reputation=0.9,
        checkout_url=f"/{merchant_id}/checkout",
    )
    base.update(overrides)
    return Offer(**base)


def _final_proposal(merchant_id: str, *, item_name: str = FINAL_DEMO_ITEM_NAME,
                    quantity: int = 1, sku: str | None = None,
                    unit_price: Decimal | None = None) -> PurchaseProposal:
    sku = sku or FINAL_DEMO_SKUS[merchant_id]
    unit_price = unit_price if unit_price is not None else FINAL_DEMO_PRICES[merchant_id]
    return PurchaseProposal(
        decision_id="d-final-" + uuid.uuid4().hex[:8],
        goal=f"{quantity}x {item_name}",
        selected_items=[SelectedLineItem(
            requested_item=RequestedItem(name=item_name, quantity=quantity),
            merchant_id=merchant_id, sku=sku, unit_price=unit_price, quantity=quantity,
        )],
        reasoning="final-demo fixture",
    )


def _checks_by_name(verdict) -> dict[str, bool]:
    return {c["name"]: c["passed"] for c in verdict.checks}


# ================================================================== P1-P15: policy checks

def policy_cases() -> list[tuple]:
    out = []

    # P1: mandate_active — an expired mandate fails, before anything else is even relevant
    m = _final_mandate(expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat())
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    out.append(("P1", "mandate_active fails on an expired mandate",
               _checks_by_name(v).get("mandate_active"), False))

    # P2: agent_active — a paused agent fails, independently of every other check
    m = _final_mandate()
    pe.set_agent_status(m.mandate_id, "PAUSED")
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    out.append(("P2", "agent_active fails while the agent is PAUSED",
               _checks_by_name(v).get("agent_active"), False))

    # P3: offer_exists — an unknown SKU for an otherwise-valid merchant
    m = _final_mandate()
    pe.set_offers_snapshot([])
    v = pe.evaluate_basket(m, _final_proposal("techstore", sku="TS-NO-SUCH-SKU"))
    out.append(("P3", "offer_exists fails for an unknown SKU",
               _checks_by_name(v).get("offer_exists[techstore:TS-NO-SUCH-SKU]"), False))

    # P4: merchant_allowed — CheapDealsStore is searchable but never on this mandate's allowlist
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("cheapdealsstore")])
    v = pe.evaluate_basket(m, _final_proposal("cheapdealsstore"))
    out.append(("P4", "merchant_allowed fails for CheapDealsStore (not on the allowlist)",
               _checks_by_name(v).get("merchant_allowed[cheapdealsstore]"), False))

    # P5: product_requested — the proposal relabels the line as something else entirely
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore", item_name="digital gift card"))
    label = f"product_requested[techstore:{FINAL_DEMO_SKUS['techstore']}]"
    out.append(("P5", "product_requested fails when the line item was never actually requested",
               _checks_by_name(v).get(label), False))

    # P6: category_allowed — same SKU, wrong ground-truth category
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", category="furniture")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    label = f"category_allowed[techstore:{FINAL_DEMO_SKUS['techstore']}]"
    out.append(("P6", "category_allowed fails when the offer's real category is not allowed",
               _checks_by_name(v).get(label), False))

    # P7: quantity_matches — mandate wants 2, proposal only selects 1
    m = _final_mandate(requested_items=[RequestedItem(name=FINAL_DEMO_ITEM_NAME, quantity=2)])
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore", quantity=1))
    out.append(("P7", f"quantity_matches[{FINAL_DEMO_ITEM_NAME}] fails on a partial fill",
               _checks_by_name(v).get(f"quantity_matches[{FINAL_DEMO_ITEM_NAME}]"), False))

    # P8: stock_available — ground truth reports zero stock
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", stock=0)])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    label = f"stock_available[techstore:{FINAL_DEMO_SKUS['techstore']}]"
    out.append(("P8", "stock_available fails when ground-truth stock is zero",
               _checks_by_name(v).get(label), False))

    # P9: no_denied_items — title carries a denied keyword ("gift card" is denied by default)
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", title="Gift Card Bundle Charger")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    label = f"no_denied_items[techstore:{FINAL_DEMO_SKUS['techstore']}]"
    out.append(("P9", "no_denied_items fails on a denied keyword in the title",
               _checks_by_name(v).get(label), False))

    # P10: per_intent_limit — BargainBin's 20.50 exceeds the 20.00 per-merchant cap
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("bargainbin")])
    v = pe.evaluate_basket(m, _final_proposal("bargainbin"))
    out.append(("P10", "per_intent_limit[bargainbin] fails at 20.50 against a 20.00 cap",
               _checks_by_name(v).get("per_intent_limit[bargainbin]"), False))

    # P11: delegated_budget — a tight remaining budget rejects an otherwise-legal purchase
    m = _final_mandate(budget_total=Decimal("10.00"))
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    out.append(("P11", "delegated_budget fails when 19.20 exceeds a 10.00 remaining budget",
               _checks_by_name(v).get("delegated_budget"), False))

    # P12: currency — ground-truth offer quotes a non-XSGD currency
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", currency="USD")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    label = f"currency[techstore:{FINAL_DEMO_SKUS['techstore']}]"
    out.append(("P12", "currency fails when the ground-truth offer is not XSGD",
               _checks_by_name(v).get(label), False))

    # P13: delegated_budget exhaustion — the SAME mandate's second 19.20 purchase fails
    # once the first has already reserved 19.20 of the 30.00 total (10.80 remaining).
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore")])
    v1 = pe.evaluate_basket(m, _final_proposal("techstore"))
    v2 = pe.evaluate_basket(m, _final_proposal("techstore"))
    out.append(("P13", "a second 19.20 purchase against the same mandate fails delegated_budget "
                       "once 19.20 of 30.00 is already reserved",
               v1.allowed and not v2.allowed and _checks_by_name(v2).get("delegated_budget") is False, True))

    # P14: per_intent_limit boundary — exactly 20.00 passes, 20.01 fails
    m1 = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", unit_price_xsgd=Decimal("20.00"))])
    v_ok = pe.evaluate_basket(m1, _final_proposal("techstore", unit_price=Decimal("20.00")))
    m2 = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore", unit_price_xsgd=Decimal("20.01"))])
    v_bad = pe.evaluate_basket(m2, _final_proposal("techstore", unit_price=Decimal("20.01")))
    out.append(("P14", "per_intent_limit[techstore] passes at exactly 20.00 and fails at 20.01",
               _checks_by_name(v_ok).get("per_intent_limit[techstore]") is True
               and _checks_by_name(v_bad).get("per_intent_limit[techstore]") is False, True))

    # P15: the full happy-path baseline — TechStore at 19.20 is ALLOWED end to end, mints
    # exactly one SpendIntent leg for exactly 19.20.
    m = _final_mandate()
    pe.set_offers_snapshot([_final_offer("techstore")])
    v = pe.evaluate_basket(m, _final_proposal("techstore"))
    out.append(("P15", "TechStore at 19.20 XSGD is ALLOWED and mints exactly one 19.20 SpendIntent leg",
               v.allowed and len(v.spend_intents) == 1 and v.spend_intents[0].amount == Decimal("19.20"), True))

    return out


# ================================================================== R1-R9: routes

def route_cases() -> list[tuple]:
    out = []

    # R1: merchants /system/info reports its own network, non-secret
    r = merchants_client.get("/system/info").json()
    out.append(("R1", "merchants GET /system/info reports {'network': ...}", r.get("network"), ms.NETWORK))

    # R2/R3: policy /system/info defaults
    r = policy_client.get("/system/info").json()
    out.append(("R2", "policy GET /system/info defaults settle_mode to 'verify'", r.get("settle_mode"), "verify"))
    out.append(("R3", "policy GET /system/info defaults card_mode to 'simulate'", r.get("card_mode"), "simulate"))

    # R4: self_transfer_demo_allowed reflects ALLOW_SELF_TRANSFER_DEMO
    had = os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
    try:
        off = policy_client.get("/system/info").json()["self_transfer_demo_allowed"]
        os.environ["ALLOW_SELF_TRANSFER_DEMO"] = "true"
        on = policy_client.get("/system/info").json()["self_transfer_demo_allowed"]
    finally:
        if had is None:
            os.environ.pop("ALLOW_SELF_TRANSFER_DEMO", None)
        else:
            os.environ["ALLOW_SELF_TRANSFER_DEMO"] = had
    out.append(("R4", "self_transfer_demo_allowed toggles with ALLOW_SELF_TRANSFER_DEMO",
               (off, on), (False, True)))

    # R5: mainnet_network is the fixed Avalanche mainnet CAIP-2 id
    r = policy_client.get("/system/info").json()
    out.append(("R5", "policy GET /system/info reports the fixed mainnet_network",
               r.get("mainnet_network"), "eip155:43114"))

    # R6: GET /mandates/{id} reports spent=0.00/remaining=budget_total right after registration
    m = _final_mandate()
    policy_client.post("/mandates", json=m.model_dump(mode="json"))
    r = policy_client.get(f"/mandates/{m.mandate_id}").json()
    out.append(("R6", "a freshly registered mandate has spent=0.00 and remaining=budget_total",
               (r["spent"], r["remaining"]), (0.0, 30.0)))

    # R7: POST /agent/{id}/status?status=PAUSED then GET reflects PAUSED
    policy_client.post(f"/agent/{m.mandate_id}/status", params={"status": "PAUSED"})
    r = policy_client.get(f"/agent/{m.mandate_id}/status").json()
    out.append(("R7", "POST .../status?status=PAUSED is reflected by the following GET", r.get("status"), "PAUSED"))

    # R8: an invalid status value is refused with 400, not silently accepted
    resp = policy_client.post(f"/agent/{m.mandate_id}/status", params={"status": "NOT_A_REAL_STATUS"})
    out.append(("R8", "an invalid agent status value is refused with HTTP 400", resp.status_code, 400))

    # R9: a mandate_id never explicitly set defaults to ACTIVE (never PAUSED/REVOKED by default)
    fresh_id = "m-never-set-" + uuid.uuid4().hex[:8]
    r = policy_client.get(f"/agent/{fresh_id}/status").json()
    out.append(("R9", "an unset mandate's agent status defaults to ACTIVE", r.get("status"), "ACTIVE"))

    return out


# ================================================================== A1-A3: attack demo

def attack_cases() -> list[tuple]:
    out = []
    m = _final_mandate()

    # The exact deterministic attack fixture (see tests/agent_mode_matrix.py AT2 and
    # dashboard/app.py's Attack section): BargainBin's real BB-G01 gift card, relabelled as
    # the requested charger, posted directly to /evaluate-basket — never through
    # gather()/choose(), never through /authorize.
    attack_proposal = PurchaseProposal(
        decision_id="d-attack-" + uuid.uuid4().hex[:8],
        goal="1x usb-c charger",
        selected_items=[SelectedLineItem(
            requested_item=RequestedItem(name="digital gift card", quantity=1),
            merchant_id="bargainbin", sku="BB-G01", unit_price=Decimal("25.00"), quantity=1,
        )],
        reasoning="deterministic attack fixture: relabels a $25 gift card as the requested charger",
    )
    v = pe.evaluate_basket(m, attack_proposal)
    checks = _checks_by_name(v)

    out.append(("A1", "merchant_allowed[bargainbin] still PASSES — BargainBin itself is on the allowlist",
               checks.get("merchant_allowed[bargainbin]"), True))
    out.append(("A2", "product_requested/category_allowed FAIL (per_intent_limit now passes since "
                      "product/catalog.json's real BB-G01 price is only 2.50 against the 20.00 cap); "
                      "the verdict is still blocked",
               (checks.get("product_requested[bargainbin:BB-G01]"),
                checks.get("category_allowed[bargainbin:BB-G01]"),
                checks.get("per_intent_limit[bargainbin]"), v.allowed),
               (False, False, True, False)))
    out.append(("A3", "no SpendIntent is ever created — nothing exists to sign or submit",
               (len(v.spend_intents), v.spend_intent), (0, None)))

    return out


# ================================================================== B1-B7: basket variant
# The Centre column's "two chargers and one HDMI cable" real-catalog-shaped variant —
# choose_basket is pure/no-I/O, so it is exercised directly (as tests/basket_matrix.py's
# K1-K3 already do), never via agent_run.gather_basket()'s live HTTP calls.

def _basket_offer(merchant_id: str, sku: str, price, delivery_days: int = 0, category="electronics") -> Offer:
    return Offer(
        offer_id=sku, merchant_id=merchant_id, merchant_name=merchant_id.title(), sku=sku,
        title=sku, product_type="unknown", category=category, unit_price_xsgd=Decimal(str(price)),
        delivery_days=delivery_days, stock=10, in_stock=True, reputation=0.9,
        checkout_url=f"/{merchant_id}/checkout",
    )


def basket_variant_cases() -> list[tuple]:
    out = []
    requested = [RequestedItem(name="usb-c charger", quantity=2), RequestedItem(name="hdmi cable", quantity=1)]

    allowed_quotes = {
        "usb-c charger": [
            _basket_offer("techstore", "TS-CHG", 9.00),
            _basket_offer("gadgethub", "GH-CHG", 8.00, delivery_days=2),
            _basket_offer("bargainbin", "BB-CHG", 9.50),
        ],
        "hdmi cable": [
            _basket_offer("techstore", "TS-HDMI", 4.00),
            _basket_offer("gadgethub", "GH-HDMI", 3.50, delivery_days=2),
            _basket_offer("bargainbin", "BB-HDMI", 4.20),
        ],
    }

    # B1: cheapdealsstore is never fed into the quotes the chooser sees at all — it is
    # excluded from ALLOWED_MERCHANTS entirely, not merely out-competed.
    fed_merchants = {o.merchant_id for offers in allowed_quotes.values() for o in offers}
    out.append(("B1", "cheapdealsstore never appears among the quotes fed to the chooser",
               "cheapdealsstore" in fed_merchants, False))

    # B2: the cheapest same-day single-merchant bundle wins (TechStore: 2x9.00 + 4.00 = 22.00)
    p = agent_run.choose_basket(requested, allowed_quotes, require_same_day=True)
    out.append(("B2", "TechStore's same-day bundle (22.00) wins over a cheaper 2-day-only GadgetHub bundle",
               (list(p.merchant_ids), p.total_amount), (["techstore"], Decimal("22.00"))))

    # B3: total price is the exact re-derived sum, not a guess
    out.append(("B3", "the chosen bundle's total is exactly 22.00 XSGD", p.total_amount, Decimal("22.00")))

    # B4: proof that excluding cheapdealsstore actually matters — if it WERE fed (cheaper on
    # every line), it would incorrectly win, which is exactly why the dashboard never feeds it.
    quotes_with_cheapdeals = {
        item: offers + [_basket_offer("cheapdealsstore", f"CD-{item[:3].upper()}", 3.00)]
        for item, offers in allowed_quotes.items()
    }
    p_with_cheap = agent_run.choose_basket(requested, quotes_with_cheapdeals, require_same_day=True)
    out.append(("B4", "if fed, CheapDealsStore's cheaper bundle would win — proving why it must be excluded",
               "cheapdealsstore" in p_with_cheap.merchant_ids, True))

    # B5: posted through the real policy engine with matching requested_items, the chosen
    # bundle passes product_requested/quantity_matches for both distinct line items.
    basket_mandate = _final_mandate(
        budget_total=Decimal("30.00"), per_intent_max=Decimal("25.00"), requested_items=requested,
    )
    pe.set_offers_snapshot([o for offers in allowed_quotes.values() for o in offers])
    v = pe.evaluate_basket(basket_mandate, p)
    checks = _checks_by_name(v)
    out.append(("B5", "the chosen bundle passes quantity_matches for both requested lines",
               (checks.get("quantity_matches[usb-c charger]"), checks.get("quantity_matches[hdmi cable]")),
               (True, True)))

    # B6: a single-merchant win produces exactly one SpendIntent leg
    out.append(("B6", "a single-merchant bundle mints exactly one SpendIntent leg",
               len(v.spend_intents), 1))

    # B7: delegated_budget accounting after this basket purchase is exact (30.00 - 22.00 = 8.00)
    remaining = round(float(basket_mandate.budget_total) - float(pe.spent(basket_mandate.mandate_id))
                       - float(pe._reserved_total(basket_mandate.mandate_id)), 2)
    out.append(("B7", "remaining budget after the 22.00 basket purchase is exactly 8.00",
               v.allowed and remaining == 8.00, True))

    return out


# ================================================================== T1-T6: payment step tracker
# The full 402 -> authorize -> submit -> settled sequence for the exact TechStore 19.20 leg,
# through the real merchants.server + pg.policy_server FastAPI apps (TestClient, no live
# network sockets) — mirrors exactly what dashboard/app.py's Payment section does.

def payment_cases() -> list[tuple]:
    out = []

    m = _final_mandate()
    policy_client.post("/mandates", json=m.model_dump(mode="json"))
    proposal = _final_proposal("techstore")   # TS-FD01 is a real product/catalog.json entry at 19.20
    verdict = pe.evaluate_basket(m, proposal)
    spend_intent = verdict.spend_intent
    body = {"items": [{"sku": FINAL_DEMO_SKUS["techstore"], "quantity": 1}]}

    # T1: checkout without a signature returns a 402 challenge
    r402 = merchants_client.post("/techstore/checkout", json=body)
    out.append(("T1", "checkout without a signature returns HTTP 402 with an accepts challenge",
               (r402.status_code, "accepts" in r402.json()), (402, True)))
    challenge = r402.json()

    # T2: /authorize verifies the recipient, reserves, and signs — self_transfer is False
    # (the throwaway test AGENT_PRIVATE_KEY is not TechStore's registered recipient)
    auth = policy_client.post("/authorize", json={"spend_intent": spend_intent, "challenge": challenge}).json()
    out.append(("T2", "/authorize verifies + signs; self_transfer is False for an ordinary purchase",
               (auth.get("ok"), auth.get("self_transfer")), (True, False)))

    # T3: submitting the signature settles cleanly (verify mode: settled_onchain is False,
    # this is a cryptographic verification reference, never a fabricated on-chain claim)
    paid = merchants_client.post("/techstore/checkout", json=body,
                                  headers={"PAYMENT-SIGNATURE": auth["payment_header"]})
    receipt = paid.json() if paid.status_code == 200 else {}
    out.append(("T3", "submitting the signed payment settles with HTTP 200 and a receipt",
               (paid.status_code, receipt.get("receipt", {}).get("settled_onchain")), (200, False)))

    # T4: reporting settlement consumes the SpendIntent — GET /intents/{id} reflects CONSUMED
    settled = policy_client.post(f"/intents/{auth['intent_id']}/settled", json={
        "tx_hash": receipt.get("receipt", {}).get("tx_hash"),
        "network": receipt.get("receipt", {}).get("network"),
        "order_id": receipt.get("order_id"),
    }).json()
    intent_state = policy_client.get(f"/intents/{auth['intent_id']}").json()
    out.append(("T4", "POST .../settled consumes the intent; GET /intents/{id} reports CONSUMED",
               (settled.get("ok"), intent_state.get("status")), (True, "CONSUMED")))

    # T5: the mandate's remaining budget has decreased by exactly 1.92 (TS-FD01's real,
    # rescaled product/catalog.json price)
    m_after = policy_client.get(f"/mandates/{m.mandate_id}").json()
    out.append(("T5", "remaining budget decreased by exactly 1.92 after settlement",
               round(30.00 - m_after["remaining"], 2), 1.92))

    # T6: replaying the SAME (now CONSUMED, terminal) SpendIntent is refused, never re-payable
    replay = policy_client.post("/authorize", json={"spend_intent": spend_intent, "challenge": challenge}).json()
    out.append(("T6", "replaying the same consumed SpendIntent to /authorize is refused",
               replay.get("ok"), False))

    return out


def run() -> int:
    failures = 0
    sections = [
        ("P1-P15 — policy checks against the exact final-demo fixture", policy_cases()),
        ("R1-R9 — /system/info, /mandates, /agent/{id}/status routes", route_cases()),
        ("A1-A3 — the deterministic BargainBin attack fixture", attack_cases()),
        ("B1-B7 — the real-catalog basket variant (pure choose_basket)", basket_variant_cases()),
        ("T1-T6 — the full 402 -> sign -> settle payment step tracker", payment_cases()),
    ]

    total = 0
    for title, cases in sections:
        print(f"\n{C['b']}FINAL MATRIX — {title}{C['off']}")
        print(f"{C['dim']}{'id':<5}{'expect':<28}{'got':<28}case{C['off']}")
        for cid, desc, got, expect in cases:
            ok = got == expect
            failures += not ok
            total += 1
            mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
            print(f"{cid:<5}{str(expect):<28}{str(got):<28}{desc}  [{mark}]")

    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
