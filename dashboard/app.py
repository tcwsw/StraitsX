"""ProcureGuard dashboard (Streamlit) — the final one-screen demonstration.

A thin client over the existing FastAPI services. It holds no secrets, mints no
SpendIntent itself, and signs nothing itself — every financial control-plane decision
(policy checks, SpendIntent minting/redemption, signing, settlement) happens in
pg/policy_server.py and merchants/server.py over HTTP, exactly as it does for the CLI in
agent/run.py. This file only calls those services and renders their responses. Where it
needs a pure, no-I/O helper (parsing a request into line items, picking the cheapest
merchant bundle, deciding whether clarification is needed) it reuses the real functions
from agent/run.py and pg/clarify.py rather than reimplementing them.

Layout is one screen, six regions:
  Top     — wallet/budget metrics, agent status + PAUSE/RESUME, mainnet/self-transfer badge.
  Left    — the user's request, live clarification (pg.clarify) if it is ambiguous, and a
            Searching -> Comparing -> Selected breadcrumb.
  Centre  — the fixed 4-merchant eligibility comparison, plus an optional real-catalog
            "two chargers and one HDMI cable" basket variant.
  Right   — the policy verdict (prominent) with the execution agent's reasoning demoted to
            a caption below it, then the full ordered list of policy checks.
  Payment — the SpendIntent lifecycle: 402 -> recipient verified -> EIP-3009 signed ->
            submitted -> on-chain receipt verified -> consumed, with a Snowtrace link.
  Final metrics — kept strictly separate: Wallet (the real, self-transfer-unchanged XSGD
            balance + AVAX gas) vs Policy (the mandate's own delegated-budget accounting).
A final Attack section runs the deterministic BargainBin-relabelled-as-a-charger fixture
(see tests/agent_mode_matrix.py AT2) directly against /evaluate-basket.

Never shown here, by construction: AGENT_PRIVATE_KEY, POLICY_SECRET, OPENAI_API_KEY, or any
card CVV/PAN/full card material — this file never reads those env vars and never calls the
one endpoint that returns card material (GET /cards/{id}/view is human-only, one-time, and
is intentionally not wired up here). Ledger entries are additionally redacted defensively
before display in case that ever changes. The StraitsX card controls are additionally
gated behind CARD_FEATURE_ENABLED (a dashboard-only UI toggle, never a financial secret) —
hidden entirely unless explicitly turned on.

Run:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(__file__).resolve().parent.parent

# Load ONLY the execution agent's allow-listed keys (OPENAI_API_KEY, OPENAI_MODEL,
# AGENT_MODE, AUDIT_MODE, service URLs, CARD_FEATURE_ENABLED) from this process's OWN
# .env.app. Refuses to start (raises) rather than silently continuing if
# AGENT_PRIVATE_KEY, POLICY_SECRET, or RELAYER_PRIVATE_KEY is present anywhere in this
# process — those belong exclusively to pg/policy_server.py, loaded from the separate
# .env.policy. agent.run reads AGENT_MODE and audit.audit_agent reads AUDIT_MODE at import
# time, so this must happen before those imports.
from config.process_env import assert_no_financial_secrets, isolate_execution_agent_env

isolate_execution_agent_env(ROOT / ".env.app")
assert_no_financial_secrets()

import agent.run as agent_run
from audit.audit_agent import AuditEnvelope, hash_mandate, run_audit_with_commentary
from pg.clarify import RawPurchaseRequest, clarification_questions, resolve_requested_item
from pg.models import Mandate, Offer, PolicyVerdict, PurchaseProposal, RequestedItem, SelectedLineItem

UI_COPY_PATH = Path(os.environ.get("UI_COPY_PATH", ROOT / "product" / "ui_copy.json"))

# The final demo's own mandate: three allowed merchants (cheapdealsstore is deliberately
# excluded — shown in the Centre comparison as "unauthorized"), budget/per-merchant cap
# matching fintech/policy_config.json's current defaults.
ALLOWED_MERCHANTS = ["techstore", "gadgethub", "bargainbin"]
COMPARISON_MERCHANTS = ALLOWED_MERCHANTS + ["cheapdealsstore"]
FINAL_DEMO_BUDGET_TOTAL = 30.00
FINAL_DEMO_PER_INTENT_MAX = 20.00
FINAL_DEMO_ITEM_NAME = "usb-c charger"
# Dedicated, isolated catalog SKUs (product/catalog.json) reserved for this fixed
# comparison — never matched by a free-text merchant search for "usb-c charger"/"hdmi
# cable" (their titles deliberately contain neither substring), so they cannot collide
# with the general basket variant or with any existing test's catalog assumptions.
FINAL_DEMO_SKUS = {
    "techstore": "TS-FD01", "gadgethub": "GH-FD01",
    "bargainbin": "BB-FD01", "cheapdealsstore": "CD-FD01",
}
MERCHANT_NAMES = {
    "techstore": "TechStore", "gadgethub": "GadgetHub",
    "bargainbin": "BargainBin", "cheapdealsstore": "CheapDealsStore",
}

CARD_FEATURE_ENABLED = os.environ.get("CARD_FEATURE_ENABLED", "false").strip().lower() == "true"

_REDACT_KEYS = {
    "private_key", "agent_private_key", "policy_secret", "openai_api_key",
    "cvv", "pan", "card_number", "card_cvv", "full_pan",
}

st.set_page_config(page_title="ProcureGuard", layout="wide")


def load_copy() -> dict:
    return json.loads(UI_COPY_PATH.read_text(encoding="utf-8"))


COPY = load_copy()


def t(*path: str, default: str = "") -> str:
    """Walk a dotted path into ui_copy.json. Falls back to `default` rather than ever
    surfacing a PM_TODO_REQUIRED placeholder to an end user."""
    node: object = COPY
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    if isinstance(node, str) and node.endswith("_TODO_REQUIRED"):
        return default
    return node if isinstance(node, str) else default


def call(method: str, base: str, path: str, **kw) -> dict | None:
    try:
        with httpx.Client(timeout=15) as c:
            r = c.request(method, f"{base}{path}", **kw)
        if r.status_code >= 400:
            st.error(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
            return None
        return r.json()
    except httpx.RequestError as exc:
        st.error(f"{method} {path} failed ({exc.__class__.__name__}). Is the service running at {base}?")
        return None


def peek_intent(token: str | None) -> dict | None:
    """The SpendIntent bearer token is HMAC-signed, not encrypted — reading the JSON body
    for DISPLAY doesn't require the secret and grants no authority (it can't be re-signed
    or altered). Nothing here is ever used to make a decision, only to render one."""
    if not token:
        return None
    try:
        raw, _sig = token.split("||")
        return json.loads(raw)
    except Exception:
        return None


def leg_intent_state(policy_url: str, leg: dict) -> str:
    """The authoritative backend lifecycle state for one merchant leg, fetched fresh from
    GET /intents/{id} every time this is called — never a locally-assigned label. This is
    what requirement 10 means: the dashboard shows what the policy engine actually
    recorded, not a guess made at click time."""
    peek = peek_intent(leg.get("spend_intent"))
    intent_id = peek.get("spend_intent_id") if peek else None
    if not intent_id:
        return "unknown"
    data = call("GET", policy_url, f"/intents/{intent_id}")
    return (data or {}).get("status", "unknown")


def redact(obj):
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if k.lower() in _REDACT_KEYS else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def basket_total(selected_items: list[dict]) -> float:
    return round(sum(i["unit_price"] * i["quantity"] for i in selected_items), 2)


def status_badge(status: str) -> str:
    return {"PASS": "🟢 PASS", "WARN": "🟡 WARN", "BLOCK": "🔴 BLOCK"}.get(status, status)


ss = st.session_state

st.title(t("banner", "title", default="ProcureGuard"))
subtitle = t("banner", "subtitle")
if subtitle:
    st.caption(subtitle)

with st.sidebar:
    st.header("Services")
    policy_url = st.text_input("Policy engine URL", os.environ.get("POLICY_URL", "http://127.0.0.1:4020"))
    merchants_url = st.text_input("Merchants URL", os.environ.get("MERCHANTS_URL", "http://127.0.0.1:4030"))
    st.divider()
    st.caption(f"AGENT_MODE={os.environ.get('AGENT_MODE', 'scripted')}  ·  AUDIT_MODE={os.environ.get('AUDIT_MODE', 'scripted')}")
    st.caption(f"CARD_FEATURE_ENABLED={CARD_FEATURE_ENABLED}")
    st.info(t("never_show_note", default="Never displays private keys, the OpenAI API key, CVV, PAN, or complete card material."))
    if st.button(t("buttons", "reset", default="Reset demo")):
        for k in list(ss.keys()):
            del ss[k]
        st.rerun()

agent_run.MERCHANTS_URL = merchants_url


# ---------------------------------------------------------------- helpers specific to this final demo

def _fixed_offer(merchant_id: str, sku: str, price: float, stock: int | None, in_stock: bool) -> Offer:
    return Offer(
        offer_id=sku, merchant_id=merchant_id, merchant_name=MERCHANT_NAMES[merchant_id],
        sku=sku, title="Final-Demo Mainnet Power Module 45W", product_type="charger",
        category="electronics", unit_price_xsgd=price, delivery_days=0,
        stock=stock, in_stock=in_stock, reputation=0.9, checkout_url=f"/{merchant_id}/checkout",
    )


def fetch_final_demo_offers(merchants_url: str) -> dict[str, Offer] | None:
    """Fetch the dedicated final-demo item from every comparison merchant's REAL catalog
    (never hardcoded here) so the Centre panel's prices are always what the live merchant
    service would actually quote at checkout."""
    offers: dict[str, Offer] = {}
    for merchant_id in COMPARISON_MERCHANTS:
        sku = FINAL_DEMO_SKUS[merchant_id]
        data = call("GET", merchants_url, f"/{merchant_id}/search", params={"q": ""})
        if data is None:
            return None
        item = next((i for i in data.get("items", []) if i["sku"] == sku), None)
        if item is None:
            st.error(f"final-demo SKU {sku} missing from {merchant_id}'s catalog")
            return None
        offers[merchant_id] = _fixed_offer(
            merchant_id, sku, float(item["price"]), item.get("stock"), item.get("in_stock", True),
        )
    return offers


def eligibility_label(merchant_id: str, price: float, mandate: Mandate) -> str:
    if merchant_id not in mandate.allowed_merchants:
        return t("centre_labels", "unauthorized", default="unauthorized")
    if price > float(mandate.per_intent_max):
        return t("centre_labels", "over_cap", default="over cap")
    return t("centre_labels", "eligible", default="eligible")


def ensure_final_demo_mandate(policy_url: str) -> Mandate:
    """Create the ONE mandate governing this whole demo exactly once per session; every
    region below (top bar, main purchase) shares it."""
    if not ss.get("mandate"):
        mandate_obj = Mandate(
            mandate_id="m-" + uuid.uuid4().hex[:8],
            principal="Team ProcureGuard",
            budget_total=FINAL_DEMO_BUDGET_TOTAL,
            per_intent_max=FINAL_DEMO_PER_INTENT_MAX,
            requested_items=[RequestedItem(name=FINAL_DEMO_ITEM_NAME, quantity=1)],
            allowed_categories=["electronics"],
            blocked_categories=["gift_card", "cash_equivalent"],
            allowed_merchants=ALLOWED_MERCHANTS,
            require_human_above=None,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )
        call("POST", policy_url, "/mandates", json=mandate_obj.model_dump(mode="json"))
        ss.mandate = mandate_obj.model_dump()
        ss.starting_balance = FINAL_DEMO_BUDGET_TOTAL
    return Mandate(**ss.mandate)


mandate = ensure_final_demo_mandate(policy_url)

# =================================================================== TOP — wallet, budget, agent status, badge

sys_info = call("GET", policy_url, "/system/info") or {}
merchant_info = call("GET", merchants_url, "/system/info") or {}
network = merchant_info.get("network")
mainnet_network = sys_info.get("mainnet_network")
settle_mode = sys_info.get("settle_mode", "verify")
is_mainnet_self_transfer = bool(network) and network == mainnet_network and settle_mode == "onchain"

if is_mainnet_self_transfer:
    st.error(f"## {t('badges', 'real_mainnet_self_transfer', default='🔴 REAL MAINNET SELF-TRANSFER')}")
else:
    st.info(f"{t('badges', 'testnet_verify_mode', default='🧪 TESTNET / VERIFY MODE')} "
            f"(network={network or 'unknown'}, settle_mode={settle_mode})")

m_state = call("GET", policy_url, f"/mandates/{mandate.mandate_id}") or {}
remaining = m_state.get("remaining", float(mandate.budget_total))
agent_status = (call("GET", policy_url, f"/agent/{mandate.mandate_id}/status") or {}).get("status", "ACTIVE")

top = st.columns(6)
top[0].metric(t("top_bar_labels", "wallet", default="Wallet"), f"{ss.starting_balance:.2f} XSGD")
top[1].metric(t("top_bar_labels", "delegated_budget", default="Delegated budget"), f"{float(mandate.budget_total):.2f} XSGD")
top[2].metric(t("top_bar_labels", "max_per_merchant", default="Maximum per merchant"), f"{float(mandate.per_intent_max):.2f} XSGD")
top[3].metric(t("top_bar_labels", "available_budget", default="Available delegated budget"), f"{remaining:.2f} XSGD")
top[4].metric(t("top_bar_labels", "agent_status", default="Agent status"), agent_status)
with top[5]:
    st.write("")
    if agent_status == "ACTIVE":
        if st.button(t("top_bar_labels", "pause", default="Pause agent"), key="pause_agent"):
            call("POST", policy_url, f"/agent/{mandate.mandate_id}/status", params={"status": "PAUSED"})
            st.rerun()
    else:
        if st.button(t("top_bar_labels", "resume", default="Resume agent"), key="resume_agent", type="primary"):
            call("POST", policy_url, f"/agent/{mandate.mandate_id}/status", params={"status": "ACTIVE"})
            st.rerun()

st.divider()

# =================================================================== LEFT / CENTRE / RIGHT

left_col, centre_col, right_col = st.columns([1, 1.4, 1.3])

left_col.subheader(t("sections", "left_column", default="Request"))
request_text = left_col.text_input(
    "User request", value=ss.get("request_text", "1 x usb-c charger"), key="request_text_input",
)
ss.request_text = request_text
left_col.caption("Tip: clear the quantity (type just the item name) to see live clarification.")

_m = re.match(r"^\s*(\d+)\s*x\s*(.+?)\s*$", request_text, re.IGNORECASE)
if _m:
    raw_req = RawPurchaseRequest(item_name=_m.group(2), quantity=int(_m.group(1)))
elif request_text.strip():
    raw_req = RawPurchaseRequest(item_name=request_text.strip(), quantity=None)
else:
    raw_req = RawPurchaseRequest(item_name=None, quantity=None)

questions = clarification_questions(raw_req)
resolved_item: RequestedItem | None = None
if questions:
    left_col.warning("Clarification needed before this request can proceed:")
    answers: dict[str, str] = {}
    for q in questions:
        answers[q.field] = left_col.text_input(q.question, key=f"clarify_{q.field}")
    if left_col.button("Confirm", key="confirm_clarification"):
        quantity = raw_req.quantity
        qty_answer = answers.get("quantity")
        if qty_answer:
            try:
                quantity = int(qty_answer)
            except ValueError:
                quantity = None
        ss.clarified_request = {"item_name": answers.get("item_name") or raw_req.item_name, "quantity": quantity}
        st.rerun()
    if ss.get("clarified_request"):
        retry_req = RawPurchaseRequest(**ss.clarified_request)
        if not clarification_questions(retry_req):
            resolved_item = resolve_requested_item(retry_req)
else:
    ss.pop("clarified_request", None)
    resolved_item = resolve_requested_item(raw_req)

# ---- build the proposal + evaluate, cached by (mandate, item) so repeated Streamlit
# reruns (e.g. clicking Pause/Resume) never silently re-mint a fresh SpendIntent or
# re-call the OpenAI execution agent for input that hasn't changed.
offers: dict[str, Offer] | None = None
proposal: PurchaseProposal | None = None
verdict: dict | None = None
selected_merchant: str | None = None

if resolved_item is not None:
    offers = fetch_final_demo_offers(merchants_url)
    if offers is not None:
        proposal_key = [mandate.mandate_id, resolved_item.name, resolved_item.quantity]
        if ss.get("proposal_key") != proposal_key:
            quotes_by_item = {resolved_item.name: [offers[m] for m in ALLOWED_MERCHANTS]}
            goal = f"{resolved_item.quantity}x {resolved_item.name}"
            proposal_mode = os.environ.get("AGENT_MODE", "scripted").strip().lower()
            try:
                built = agent_run.build_basket_proposal(
                    mandate, [resolved_item], quotes_by_item, goal, mode=proposal_mode,
                )
                ss.proposal_cached = built.model_dump()
                ss.proposal_key = proposal_key
                ss.pop("evaluate_key", None)
            except Exception as exc:
                centre_col.error(f"Execution Agent could not produce a proposal: {exc}")
        if ss.get("proposal_key") == proposal_key and ss.get("proposal_cached"):
            proposal = PurchaseProposal(**ss.proposal_cached)
            selected_merchant = proposal.selected_items[0].merchant_id

        if proposal is not None:
            evaluate_key = [mandate.mandate_id, resolved_item.name, resolved_item.quantity, selected_merchant]
            if ss.get("evaluate_key") != evaluate_key:
                verdict_resp = call("POST", policy_url, "/evaluate-basket",
                                     json={"mandate_id": mandate.mandate_id,
                                           "proposal": proposal.model_dump(mode="json")})
                if verdict_resp:
                    ss.verdict = verdict_resp
                    ss.evaluate_key = evaluate_key
                    legs = verdict_resp.get("spend_intents") or []
                    if legs:
                        ss.leg = {"merchant_id": legs[0]["merchant_id"], "amount": float(legs[0]["amount"]),
                                  "spend_intent": legs[0]["spend_intent"]}
                        ss.payment = {}
                    else:
                        ss.pop("leg", None)
            verdict = ss.get("verdict")

breadcrumb = [
    (t("progress_labels", "searching", default="Searching"), offers is not None),
    (t("progress_labels", "comparing", default="Comparing"), offers is not None),
    (f"{t('progress_labels', 'selected', default='Selected')} "
     f"{MERCHANT_NAMES.get(selected_merchant, '')}".strip(), selected_merchant is not None),
]
left_col.write(" → ".join(f"✅ {lbl}" if ok else f"◯ {lbl}" for lbl, ok in breadcrumb))

# ---- Centre: fixed 4-merchant comparison + optional real-catalog basket variant
centre_col.subheader(t("sections", "centre_column", default="Merchant Comparison & Basket"))
if offers is not None:
    centre_col.dataframe(
        [{"merchant": MERCHANT_NAMES[mid], "price (XSGD)": f"{float(offers[mid].unit_price_xsgd):.2f}",
          "eligibility": eligibility_label(mid, float(offers[mid].unit_price_xsgd), mandate)}
         for mid in COMPARISON_MERCHANTS],
        hide_index=True, width="stretch",
    )
if proposal is not None:
    centre_col.caption(f"Execution Agent selected **{MERCHANT_NAMES.get(selected_merchant, selected_merchant)}** "
                        f"at {basket_total(proposal.model_dump()['selected_items']):.2f} XSGD — {proposal.reasoning}")

with centre_col.expander(t("centre_labels", "basket_heading",
                            default="Basket variant — two chargers and one HDMI cable")):
    if st.button("Run basket comparison", key="run_basket_variant"):
        basket_items = [RequestedItem(name="usb-c charger", quantity=2), RequestedItem(name="hdmi cable", quantity=1)]
        basket_quotes = agent_run.gather_basket(basket_items, ALLOWED_MERCHANTS)
        try:
            basket_proposal = agent_run.choose_basket(basket_items, basket_quotes, require_same_day=True)
            ss.basket_proposal = basket_proposal.model_dump()
        except SystemExit as exc:
            st.error(str(exc))
    if ss.get("basket_proposal"):
        bp = ss.basket_proposal
        st.write(f"**{basket_total(bp['selected_items']):.2f} XSGD** — {bp['reasoning']}")
        st.dataframe(
            [{"merchant": i["merchant_id"], "sku": i["sku"], "qty": i["quantity"],
              "unit_price": i["unit_price"], "subtotal": round(i["unit_price"] * i["quantity"], 2)}
             for i in bp["selected_items"]],
            hide_index=True, width="stretch",
        )

# ---- Right: the policy verdict, prominent, with model reasoning demoted below it
right_col.subheader(t("sections", "right_column", default="Policy Verdict"))
if verdict is not None:
    if verdict.get("allowed"):
        right_col.success(f"## ✅ {t('right_labels', 'verdict_heading', default='Policy Verdict')}: ALLOWED")
    elif verdict.get("needs_human"):
        right_col.warning(f"## ⏳ {t('right_labels', 'verdict_heading', default='Policy Verdict')}: NEEDS HUMAN APPROVAL")
    else:
        right_col.error(f"## ⛔ {t('right_labels', 'verdict_heading', default='Policy Verdict')}: "
                         f"BLOCKED — {verdict.get('reason')}")
    if proposal is not None:
        right_col.caption(f"{t('right_labels', 'reasoning_heading', default='Model reasoning (advisory only — not the verdict)')}"
                           f": {proposal.reasoning}")
    for c in verdict["checks"]:
        right_col.write(("✅" if c["passed"] else "❌") + f" `{c['name']}` — {c['detail']}")
else:
    right_col.caption("Awaiting a resolved request from the Left column.")

st.divider()

# =================================================================== PAYMENT

st.subheader(t("sections", "payment_column", default="Payment"))

leg = ss.get("leg")
if leg:
    payment = ss.setdefault("payment", {})
    state = leg_intent_state(policy_url, leg)
    peek = peek_intent(leg["spend_intent"]) or {}

    if state == "AUTHORIZED" and not payment.get("submitted"):
        if st.button(f"Run payment ({leg['amount']:.2f} XSGD, 402 → sign → settle)", type="primary", key="run_payment"):
            merchant_id = leg["merchant_id"]
            items = [i for i in ss.proposal_cached["selected_items"] if i["merchant_id"] == merchant_id]
            body = {"items": [{"sku": i["sku"], "quantity": i["quantity"]} for i in items]}
            try:
                r402 = httpx.post(f"{merchants_url}/{merchant_id}/checkout", json=body, timeout=15)
            except httpx.RequestError as exc:
                st.error(f"could not reach merchant service: {exc}")
                r402 = None
            if r402 is not None and r402.status_code == 402:
                payment["http_402"] = True
                challenge = r402.json()
                # merchant_id/amount are never sent — the policy engine derives them itself
                # from the SpendIntent token.
                auth = call("POST", policy_url, "/authorize",
                            json={"spend_intent": leg["spend_intent"], "challenge": challenge})
                if auth and auth.get("ok"):
                    payment["recipient_verified"] = True
                    payment["signed"] = True
                    payment["auth"] = auth
                    intent_id = auth["intent_id"]
                    try:
                        paid = httpx.post(f"{merchants_url}/{merchant_id}/checkout", json=body,
                                           headers={"PAYMENT-SIGNATURE": auth["payment_header"]}, timeout=15)
                    except httpx.RequestError as exc:
                        call("POST", policy_url, f"/intents/{intent_id}/failed",
                             json={"reason": f"merchant service unreachable: {exc}", "definite": False})
                        st.warning(f"signed, but the merchant service was unreachable for settlement ({exc}) "
                                   "— flagged for reconciliation")
                        paid = None
                    if paid is not None:
                        payment["submitted"] = True
                        if paid.status_code == 200:
                            receipt = paid.json()
                            payment["receipt"] = receipt
                            settled = call("POST", policy_url, f"/intents/{intent_id}/settled", json={
                                "tx_hash": receipt["receipt"]["tx_hash"], "network": receipt["receipt"]["network"],
                                "order_id": receipt["order_id"],
                            })
                            payment["settlement"] = settled
                            if settled and settled.get("ok"):
                                payment["onchain_receipt_verified"] = True
                                payment["consumed"] = True
                            elif settled:
                                st.warning(f"settlement not yet confirmed: "
                                           f"{settled.get('error') or settled.get('detail')}")
                        else:
                            call("POST", policy_url, f"/intents/{intent_id}/failed", json={
                                "reason": f"merchant settlement returned {paid.status_code}: {paid.text[:200]}",
                                "definite": True,
                            })
                            st.warning(f"merchant settlement returned {paid.status_code}: {paid.text[:200]}")
                else:
                    st.error(f"{t('labels', 'authorization_refused', default='AUTHORIZATION REFUSED')}: "
                             f"{(auth or {}).get('detail', 'no response')} — nothing signed")
            elif r402 is not None:
                st.error(f"expected a 402 challenge, got {r402.status_code}")
            ss.payment = payment
            st.rerun()

    state = leg_intent_state(policy_url, leg)
    remaining_s = int(peek.get("exp", 0) - time.time()) if peek else None
    rows = [
        (t("payment_labels", "spend_intent_id", default="SpendIntent ID"),
         (peek.get("spend_intent_id", "")[:16] + "…") if peek else "", bool(peek)),
        (t("payment_labels", "amount", default="Amount"), f"{leg['amount']:.2f} XSGD", True),
        (t("payment_labels", "expiry_countdown", default="Expiry countdown"),
         (f"{remaining_s}s" if remaining_s is not None and remaining_s > 0 else "expired"), remaining_s is not None),
        (t("payment_labels", "http_402_received", default="HTTP 402 received"), "", bool(payment.get("http_402"))),
        (t("payment_labels", "recipient_verified", default="Recipient verified"), "", bool(payment.get("recipient_verified"))),
        (t("payment_labels", "eip3009_signed", default="EIP-3009 signed"), "", bool(payment.get("signed"))),
        (t("payment_labels", "submitted", default="Submitted"), "", bool(payment.get("submitted"))),
        (t("payment_labels", "onchain_receipt_verified" if is_mainnet_self_transfer else "settlement_recorded",
           default="On-chain receipt verified" if is_mainnet_self_transfer else "Settlement recorded"),
         "", bool(payment.get("onchain_receipt_verified") or (payment.get("settlement") or {}).get("ok"))),
        (t("payment_labels", "consumed", default="Consumed"), "", state == "CONSUMED"),
    ]
    for label, extra, ok in rows:
        st.write(("✅ " if ok else "◯ ") + label + (f" — {extra}" if extra else ""))

    tx_hash = (payment.get("receipt") or {}).get("receipt", {}).get("tx_hash")
    if tx_hash:
        base_url = "https://snowtrace.io/tx/" if network == mainnet_network else "https://testnet.snowtrace.io/tx/"
        st.markdown(f"[{t('payment_labels', 'snowtrace_link', default='View on Snowtrace')}]({base_url}{tx_hash})")

    if CARD_FEATURE_ENABLED and state == "AUTHORIZED":
        cardholder_name = st.text_input("Cardholder name", value=mandate.principal, key="cardholder_name_input")
        if st.button("Issue restricted StraitsX card", key="issue_card"):
            card_resp = call("POST", policy_url, "/authorize-card",
                              json={"spend_intent": leg["spend_intent"], "cardholder_name": cardholder_name})
            if card_resp and card_resp.get("ok"):
                payment["card_result"] = card_resp
                ss.payment = payment
            else:
                st.error(f"CARD ISSUANCE REFUSED: {(card_resp or {}).get('detail', 'no response')} — nothing issued")
            st.rerun()
    if payment.get("card_result"):
        c = payment["card_result"]
        st.success(f"CARD ISSUED {c.get('card_opaque_id', '')} — {float(c.get('amount', 0)):.2f} XSGD")
else:
    st.caption("Awaiting a policy-allowed proposal before a SpendIntent can be minted.")

st.divider()

# =================================================================== FINAL METRICS — kept strictly separate

st.subheader(t("sections", "final_metrics", default="Final Metrics"))
wallet_col, policy_col = st.columns(2)

payment = ss.get("payment", {})
with wallet_col:
    st.markdown(f"**{t('final_metrics_labels', 'wallet_heading', default='Wallet')}**")
    settlement = payment.get("settlement") or {}
    self_transfer = (payment.get("auth") or {}).get("self_transfer")
    wallet_changed = settlement.get("wallet_balance_changed")
    gas_avax = settlement.get("gas_spent_avax")
    c1, c2 = st.columns(2)
    c1.metric(t("final_metrics_labels", "wallet_before", default="XSGD before"), f"{ss.starting_balance:.2f}")
    c2.metric(t("final_metrics_labels", "wallet_after", default="XSGD after"), f"{ss.starting_balance:.2f}")
    if self_transfer or wallet_changed is False:
        st.caption(f"✅ {t('final_metrics_labels', 'wallet_unchanged', default='unchanged due to self-transfer')}")
    if gas_avax is not None:
        st.caption(f"⛽ {t('final_metrics_labels', 'wallet_gas', default='AVAX reduced by gas')}: {gas_avax}")
    elif payment.get("submitted"):
        st.caption(f"⛽ {t('final_metrics_labels', 'wallet_gas', default='AVAX reduced by gas')}: "
                   "n/a (testnet/verify mode — no real AVAX gas was spent)")

with policy_col:
    st.markdown(f"**{t('final_metrics_labels', 'policy_heading', default='Policy')}**")
    m_now = call("GET", policy_url, f"/mandates/{mandate.mandate_id}") or {}
    consumed = m_now.get("spent", 0.0)
    available = m_now.get("remaining", float(mandate.budget_total))
    c1, c2, c3 = st.columns(3)
    c1.metric(t("final_metrics_labels", "policy_delegated", default="Delegated"), f"{float(mandate.budget_total):.2f}")
    c2.metric(t("final_metrics_labels", "policy_consumed", default="Consumed"), f"{consumed:.2f}")
    c3.metric(t("final_metrics_labels", "policy_available", default="Available"), f"{available:.2f}")

st.divider()

# =================================================================== HASH-CHAINED AUDIT TIMELINE + AUDIT VERDICT

st.subheader(t("sections", "audit_timeline", default="Hash-Chained Audit Timeline"))
audit_data = call("GET", policy_url, "/audit")
if audit_data:
    if audit_data["chain_ok"]:
        st.success(f"chain intact — {audit_data['message']}")
    else:
        st.error(f"chain broken — {audit_data['message']}")
    show_all = st.checkbox("show all ledger entries (not just this mandate)", value=False)
    entries = audit_data["entries"]
    if not show_all:
        entries = [e for e in entries if mandate.mandate_id in json.dumps(e)]
    for e in entries[-50:]:
        with st.expander(f"#{e['seq']}  {e['ts']}  {e['kind']}  ({e['actor']})"):
            st.json(redact(e["data"]))

if leg and payment.get("consumed"):
    st.subheader(t("sections", "audit_verdict", default="Audit Monitor Verdict"))
    if st.button(t("buttons", "run_audit", default="Run Audit Monitor")):
        audit_data = call("GET", policy_url, "/audit") or {"chain_ok": False, "message": "unavailable", "entries": []}
        merchant_id = leg["merchant_id"]
        items = [i for i in ss.proposal_cached["selected_items"] if i["merchant_id"] == merchant_id]
        auth_entry = next((e for e in reversed(audit_data["entries"])
                            if e["kind"] == "payment_signed" and e["data"].get("merchant_id") == merchant_id), None)
        accept = (payment.get("auth") or {})
        peek = peek_intent(leg["spend_intent"]) or {}
        approved_amount = basket_total(items)

        envelope = AuditEnvelope(
            mandate_hash=hash_mandate(mandate),
            policy_verdict=PolicyVerdict(**ss.verdict),
            spend_intent_id=peek.get("spend_intent_id", "unknown"),
            spend_intent_status="committed",
            approved_amount=approved_amount,
            observed_amount=payment["receipt"]["amount"] if payment.get("receipt") else approved_amount,
            expected_recipient=accept.get("pay_to", ""),
            observed_recipient=(auth_entry or {}).get("data", {}).get("pay_to", accept.get("pay_to", "")),
            expected_token=(payment.get("receipt") or {}).get("receipt", {}).get("network", ""),
            observed_token=(auth_entry or {}).get("data", {}).get("asset", ""),
            expected_chain=(payment.get("receipt") or {}).get("receipt", {}).get("network", ""),
            observed_chain=(auth_entry or {}).get("data", {}).get("network", ""),
            nonce_use_count=1,
            payment_timestamp=auth_entry["ts"] if auth_entry else None,
            transaction_hash=(payment.get("receipt") or {}).get("receipt", {}).get("tx_hash"),
            settlement_status=(
                "settled" if payment.get("receipt") and payment["receipt"]["receipt"]["settled_onchain"]
                else "pending" if payment.get("receipt") else "unknown"
            ),
            hash_chain_ok=audit_data["chain_ok"],
            hash_chain_message=audit_data["message"],
        )
        result = run_audit_with_commentary(envelope)
        ss.audit_verdict = {
            "deterministic": result["deterministic"].model_dump(),
            "ai": result["ai"].model_dump() if result["ai"] else None,
            "ai_error": result["ai_error"],
        }

    if ss.get("audit_verdict"):
        av = ss.audit_verdict
        st.markdown(f"**{t('sections', 'deterministic_audit', default='Deterministic Audit — authoritative')}**")
        det = av["deterministic"]
        st.write(f"### {status_badge(det['status'])}   risk score {det['risk_score']:.2f}")
        if det["flags"]:
            st.write(" ".join(f"`{f}`" for f in det["flags"]))
        st.write(det["explanation"])
        st.info(det["recommended_action"])

        st.markdown(f"**{t('sections', 'ai_audit_commentary', default='Optional AI Audit Commentary — advisory')}**")
        if av["ai"]:
            ai = av["ai"]
            st.write(f"#### {status_badge(ai['status'])}   risk score {ai['risk_score']:.2f}")
            if ai["flags"]:
                st.write(" ".join(f"`{f}`" for f in ai["flags"]))
            st.caption(ai["explanation"])
        elif av.get("ai_error"):
            st.caption(f"AI audit commentary unavailable ({av['ai_error']}) — the deterministic result above is unaffected.")
        else:
            st.caption("AUDIT_MODE is not 'openai' — no AI commentary was requested.")

# =================================================================== ATTACK — malicious BargainBin

st.divider()
st.header(t("sections", "attack_demo", default="Attack Demo — Malicious BargainBin"))
st.caption(t("attack_demo", "intro", default=""))

if st.button(t("buttons", "run_attack_demo", default="Run attack demo"), key="run_attack_demo"):
    attack_mandate = Mandate(
        mandate_id="m-atk-" + uuid.uuid4().hex[:8], principal="Team ProcureGuard",
        budget_total=FINAL_DEMO_BUDGET_TOTAL, per_intent_max=FINAL_DEMO_PER_INTENT_MAX,
        requested_items=[RequestedItem(name=FINAL_DEMO_ITEM_NAME, quantity=1)],
        allowed_categories=["electronics"], allowed_merchants=ALLOWED_MERCHANTS,
        require_human_above=None, expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    call("POST", policy_url, "/mandates", json=attack_mandate.model_dump(mode="json"))
    ss.atk_mandate = attack_mandate.model_dump()

    # Optional narrative only: reveal what the hostile merchant actually tried to smuggle
    # in, before the pre-hook strips it — this raw text is never fed to any agent's
    # context and plays no part in the deterministic verdict computed below.
    try:
        raw = httpx.get(f"{merchants_url}/bargainbin/search", params={"q": "usb-c charger"}, timeout=10).json()
    except httpx.RequestError as exc:
        raw = {"error": str(exc)}
    ss.atk_raw = raw

    # The deterministic attack fixture (see tests/agent_mode_matrix.py AT2): a proposal
    # that relabels a $25 gift card as fulfilling the "usb-c charger" request. Posted
    # directly to /evaluate-basket — never routed through gather()/choose(), and never
    # through /authorize, so no signature is ever produced.
    attack_proposal = PurchaseProposal(
        decision_id="d-attack-" + uuid.uuid4().hex[:8],
        goal="1x usb-c charger",
        selected_items=[SelectedLineItem(
            requested_item=RequestedItem(name="digital gift card", quantity=1),
            merchant_id="bargainbin", sku="BB-G01", unit_price=25.00, quantity=1,
        )],
        reasoning="deterministic attack fixture: relabels a $25 gift card as the requested charger",
    )
    ss.atk_verdict = call("POST", policy_url, "/evaluate-basket", json={
        "mandate_id": attack_mandate.mandate_id, "proposal": attack_proposal.model_dump(mode="json"),
    })

if ss.get("atk_mandate"):
    atk_descriptions = [
        i.get("description", "") for i in ss.get("atk_raw", {}).get("items", []) if i.get("description")
    ]
    if atk_descriptions:
        with st.expander(t("attack_demo", "hidden_instruction_heading",
                            default="Hidden merchant instruction (raw, before the pre-hook)")):
            st.warning("Raw merchant response — never fed to the agent's context. Shown here only "
                       "so a human can see what BargainBin tried to smuggle in.")
            for desc in atk_descriptions:
                st.code(desc, language=None)

    if ss.get("atk_verdict"):
        v = ss.atk_verdict
        checks_by_name = {c["name"]: c["passed"] for c in v["checks"]}
        merchant_allowed_ok = checks_by_name.get("merchant_allowed[bargainbin]") is True
        product_requested_failed = checks_by_name.get("product_requested[bargainbin:BB-G01]") is False
        category_allowed_failed = checks_by_name.get("category_allowed[bargainbin:BB-G01]") is False
        per_intent_limit_failed = checks_by_name.get("per_intent_limit[bargainbin]") is False

        st.write(f"**{t('attack_demo', 'policy_heading', default='Policy engine verdict')}**")
        c1, c2, c3, c4 = st.columns(4)
        c1.write(("✅ " if merchant_allowed_ok else "⚠️ ") + t("attack_labels", "merchant_allowed_pass", default="merchant_allowed PASS"))
        c2.write(("✅ " if product_requested_failed else "⚠️ ") + t("attack_labels", "product_requested_fail", default="product_requested FAIL"))
        c3.write(("✅ " if category_allowed_failed else "⚠️ ") + t("attack_labels", "category_allowed_fail", default="category_allowed FAIL"))
        c4.write(("✅ " if per_intent_limit_failed else "⚠️ ") + t("attack_labels", "per_intent_limit_fail", default="per_intent_limit FAIL"))

        with st.expander("Full check list"):
            for c in v["checks"]:
                st.write(("✅" if c["passed"] else "❌") + f" `{c['name']}` — {c['detail']}")

        st.error(f"{t('labels', 'blocked_before_signature', default='BLOCKED before any signature was produced')}: {v['reason']}")
        st.write(f"🚫 {t('attack_labels', 'spend_intent_not_created', default='SpendIntent NOT CREATED')}")
        st.write(f"🚫 {t('attack_labels', 'signature_not_created', default='Signature NOT CREATED')}")
        st.write(f"🚫 {t('attack_labels', 'transaction_not_submitted', default='Transaction submitted: NO')}")
