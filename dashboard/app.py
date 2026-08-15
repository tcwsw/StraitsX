"""ProcureGuard dashboard (Streamlit).

A thin client over the existing FastAPI services. It holds no secrets, mints no
SpendIntent itself, and signs nothing itself — every financial control-plane decision
(policy checks, SpendIntent minting/redemption, signing, settlement) happens in
pg/policy_server.py and merchants/server.py over HTTP, exactly as it does for the CLI in
agent/run.py. This file only calls those services and renders their responses. Where it
needs a pure, no-I/O helper (parsing a request into line items, picking the cheapest
merchant bundle) it reuses the real functions from agent/run.py rather than reimplementing
them.

Never shown here, by construction: AGENT_PRIVATE_KEY, POLICY_SECRET, OPENAI_API_KEY, or any
card CVV/PAN/full card material — this file never reads those env vars and never calls the
one endpoint that returns card material (GET /cards/{id}/view is human-only, one-time, and
is intentionally not wired up here). Ledger entries are additionally redacted defensively
before display in case that ever changes.

Run:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(__file__).resolve().parent.parent

# Load the repo's .env (if present) BEFORE AGENT_MODE, AUDIT_MODE, OPENAI_MODEL or
# OPENAI_API_KEY are read anywhere downstream — agent.run reads AGENT_MODE and
# audit.audit_agent reads AUDIT_MODE at import time, so this must happen before those
# imports. override=False means a shell environment variable that is already set always
# wins over whatever is in .env.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except ImportError:
    pass

import agent.run as agent_run
from audit.audit_agent import AuditEnvelope, hash_mandate, run_audit
from pg.models import Mandate, PolicyVerdict, Quote, RequestedItem

UI_COPY_PATH = Path(os.environ.get("UI_COPY_PATH", ROOT / "product" / "ui_copy.json"))

DEFAULT_MERCHANTS = ["techstore", "gadgethub", "quickelectronics"]
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
    st.info(t("never_show_note", default="Never displays private keys, the OpenAI API key, CVV, PAN, or complete card material."))
    if st.button(t("buttons", "reset", default="Reset demo")):
        for k in list(ss.keys()):
            del ss[k]
        st.rerun()

agent_run.MERCHANTS_URL = merchants_url

# ---------------------------------------------------------------- 1/2. starting balance & procurement request

st.header(t("sections", "starting_balance", default="Starting XSGD Balance") + " & " +
          t("sections", "procurement_request", default="Procurement Request"))

with st.form("setup_form"):
    starting_balance = st.number_input("Starting XSGD balance", min_value=1.0,
                                        value=float(ss.get("starting_balance", 30.0)), step=1.0)
    items_text = st.text_area(
        "One line item per line — format: `quantity x name`",
        value=ss.get("items_text", "1 x usb-c charger\n1 x wireless mouse"),
    )
    submitted = st.form_submit_button(t("buttons", "create_mandate", default="Create mandate & submit request"))

if submitted:
    parsed: list[RequestedItem] = []
    for line in items_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "x" in line:
            qty_str, _, name = line.partition("x")
            try:
                qty = int(qty_str.strip())
            except ValueError:
                qty, name = 1, line
        else:
            qty, name = 1, line
        parsed.append(RequestedItem(name=name.strip() or line, quantity=max(qty, 1)))

    if not parsed:
        st.error("no line items parsed from the request")
    else:
        fintech = agent_run.load_fintech_mandate_defaults()
        mandate = Mandate(
            mandate_id="m-" + uuid.uuid4().hex[:8],
            principal="Team ProcureGuard",
            budget_total=starting_balance,
            per_txn_max=fintech["per_txn_max"],
            allowed_categories=fintech["allowed_categories"],
            allowed_merchants=DEFAULT_MERCHANTS,
            denied_keywords=fintech["denied_keywords"],
            require_human_above=fintech["require_human_above"],
            max_delivery_days=fintech.get("max_delivery_days"),
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )
        result = call("POST", policy_url, "/mandates", json=mandate.model_dump())
        if result and result.get("ok"):
            for key in ("quotes_by_item", "proposal", "verdict", "approval_id", "spend_intent",
                        "spend_intent_state", "human_decision", "challenge", "receipt",
                        "ending_balance", "audit_verdict", "card_result"):
                ss.pop(key, None)
            ss.mandate = mandate.model_dump()
            ss.starting_balance = starting_balance
            ss.requested_items = [i.model_dump() for i in parsed]
            ss.items_text = items_text
            st.success(f"mandate {mandate.mandate_id} created: {starting_balance:.2f} XSGD, "
                       f"max {mandate.per_txn_max:.2f}/txn, human approval above {mandate.require_human_above:.2f}")

# ---------------------------------------------------------------- 3. parsed line items

if ss.get("mandate"):
    st.subheader(t("sections", "line_items", default="Parsed Line Items"))
    st.table(ss.requested_items)

# ---------------------------------------------------------------- 4. merchant comparison

if ss.get("mandate"):
    st.subheader(t("sections", "merchant_comparison", default="Merchant Comparison"))
    if st.button(t("buttons", "gather_quotes", default="Gather merchant quotes")):
        requested = [RequestedItem(**i) for i in ss.requested_items]
        quotes_by_item = agent_run.gather_basket(requested, DEFAULT_MERCHANTS)
        ss.quotes_by_item = {name: [q.model_dump() for q in qs] for name, qs in quotes_by_item.items()}
        for key in ("proposal", "verdict", "approval_id", "spend_intent", "spend_intent_state",
                    "human_decision", "challenge", "receipt", "ending_balance", "audit_verdict",
                    "card_result"):
            ss.pop(key, None)

    if ss.get("quotes_by_item"):
        for name, quotes in ss.quotes_by_item.items():
            st.write(f"**{name}**")
            st.dataframe(
                [{"merchant": q["merchant_name"], "item": q["title"], "price": q["price"],
                  "delivery": "today" if q["delivery_days"] == 0 else f"{q['delivery_days']}d",
                  "in_stock": q["in_stock"], "reputation": q["reputation"]} for q in quotes],
                hide_index=True, width="stretch",
            )

# ---------------------------------------------------------------- 5. Execution Agent proposal

if ss.get("quotes_by_item"):
    st.subheader(t("sections", "proposal", default="Execution Agent Proposal"))
    if st.button(t("buttons", "propose", default="Get Execution Agent proposal")):
        requested = [RequestedItem(**i) for i in ss.requested_items]
        quotes_objs = {name: [Quote(**q) for q in qs] for name, qs in ss.quotes_by_item.items()}
        goal = ", ".join(f"{i.quantity}x {i.name}" for i in requested)
        proposal_mode = os.environ.get("AGENT_MODE", "scripted").strip().lower()
        mandate_obj = Mandate(**ss.mandate)
        ss.pop("proposal", None)
        for key in ("verdict", "approval_id", "spend_intent", "spend_intent_state",
                    "human_decision", "challenge", "receipt", "ending_balance", "audit_verdict",
                    "card_result"):
            ss.pop(key, None)
        try:
            proposal = agent_run.build_basket_proposal(
                mandate_obj, requested, quotes_objs, goal, mode=proposal_mode,
            )
            ss.proposal = proposal.model_dump()
            ss.proposal_mode = proposal_mode
        except SystemExit as exc:
            st.error(f"Execution Agent ({proposal_mode}) could not produce a proposal: {exc}")
        except Exception as exc:
            st.error(f"Execution Agent ({proposal_mode}) failed: {exc}")

    if ss.get("proposal"):
        p = ss.proposal
        mode_label = ss.get("proposal_mode", os.environ.get("AGENT_MODE", "scripted"))
        if mode_label == "openai":
            model_name = os.environ.get("OPENAI_MODEL", "").strip() or "gpt-4o-mini"
            st.caption(f"Execution Agent: OpenAI / {model_name}")
        else:
            st.caption("Execution Agent: scripted")
        st.write(f"**{basket_total(p['selected_items']):.2f} XSGD** — {p['reasoning']}")
        st.dataframe(
            [{"merchant": i["merchant_id"], "sku": i["sku"], "qty": i["quantity"],
              "unit_price": i["unit_price"], "subtotal": round(i["unit_price"] * i["quantity"], 2)}
             for i in p["selected_items"]],
            hide_index=True, width="stretch",
        )
        if p["rejected_alternatives"]:
            st.caption("Rejected alternatives:")
            st.dataframe(
                [{"merchant": r.get("merchant_id"), "reason": r["reason"]} for r in p["rejected_alternatives"]],
                hide_index=True, width="stretch",
            )

# ---------------------------------------------------------------- 6. policy checks

if ss.get("proposal"):
    st.subheader(t("sections", "policy_checks", default="Policy Checks"))
    if st.button(t("buttons", "evaluate", default="Submit to policy engine")):
        resp = call("POST", policy_url, "/evaluate-basket",
                     json={"mandate_id": ss.mandate["mandate_id"], "proposal": ss.proposal})
        if resp:
            ss.verdict = resp
            if resp.get("spend_intent"):
                ss.spend_intent = resp["spend_intent"]
                ss.spend_intent_state = "minted"
            elif resp.get("needs_human"):
                ss.approval_id = resp.get("approval_id")
                ss.spend_intent_state = "pending_human"
            else:
                ss.spend_intent_state = "blocked"
            for key in ("challenge", "receipt", "ending_balance", "audit_verdict", "card_result"):
                ss.pop(key, None)

    if ss.get("verdict"):
        v = ss.verdict
        for c in v["checks"]:
            st.write(("✅" if c["passed"] else "❌") + f" `{c['name']}` — {c['detail']}")
        if not v["allowed"] and not v["needs_human"]:
            st.error(f"{t('labels', 'blocked_before_signature', default='BLOCKED before any signature was produced')}: {v['reason']}")
        elif v["needs_human"]:
            st.warning(f"{t('labels', 'escalated_to_human', default='ESCALATED to a human')} "
                       f"— approval id `{v['approval_id']}`")

# ---------------------------------------------------------------- 7. human approval and rejection buttons

if ss.get("spend_intent_state") == "pending_human":
    st.subheader(t("sections", "human_approval", default="Human Approval"))
    col1, col2 = st.columns(2)
    if col1.button(t("buttons", "approve", default="Approve this purchase"), type="primary"):
        resp = call("POST", policy_url, f"/approvals/{ss.approval_id}/approve")
        if resp and resp.get("ok"):
            ss.spend_intent = resp.get("spend_intent")
            ss.spend_intent_state = "minted"
            ss.human_decision = "approved"
            st.rerun()
    if col2.button(t("buttons", "reject", default="Reject this purchase")):
        resp = call("POST", policy_url, f"/approvals/{ss.approval_id}/reject")
        if resp and resp.get("ok"):
            ss.spend_intent_state = "rejected"
            ss.human_decision = "rejected"
            st.rerun()

if ss.get("spend_intent_state") == "rejected":
    st.error(t("labels", "not_approved", default="NOT APPROVED — nothing signed"))
elif ss.get("human_decision") == "approved":
    st.success(t("labels", "human_approved", default="human approved this exact purchase"))

# ---------------------------------------------------------------- 8. SpendIntent status and expiry

if ss.get("spend_intent"):
    st.subheader(t("sections", "spend_intent", default="SpendIntent Status & Expiry"))
    peek = peek_intent(ss.spend_intent)
    state = ss.get("spend_intent_state", "none")
    st.write(t("spend_intent_status_labels", state, default=state))
    if peek:
        remaining = int(peek.get("exp", 0) - time.time())
        cols = st.columns(4)
        cols[0].metric("intent_id", peek["intent_id"][:12] + "…")
        cols[1].metric("amount", f"{peek['amount']:.2f} XSGD")
        cols[2].metric("merchant", peek["merchant_id"])
        cols[3].metric("expires in", f"{remaining}s" if remaining > 0 else "EXPIRED")
elif ss.get("spend_intent_state") in ("blocked", "rejected"):
    st.subheader(t("sections", "spend_intent", default="SpendIntent Status & Expiry"))
    st.write(t("spend_intent_status_labels", ss.spend_intent_state, default=ss.spend_intent_state))

# ---------------------------------------------------------------- 9/10/11. payment progress, pay, transaction hash

STEPS = ["mandate", "quotes_by_item", "proposal", "verdict"]
STEP_LABELS = ["mandate created", "quotes gathered", "proposal chosen", "policy evaluated"]
if ss.get("spend_intent_state") not in (None, "blocked", "rejected"):
    STEPS.append("spend_intent")
    STEP_LABELS.append("SpendIntent minted")
if ss.get("receipt"):
    STEPS.append("receipt")
    STEP_LABELS.append("settlement confirmed")

if ss.get("mandate"):
    st.subheader(t("sections", "payment_progress", default="Payment Progress"))
    done = sum(1 for k in STEPS if ss.get(k))
    st.progress(done / len(STEPS))
    st.caption(" → ".join(f"✅ {lbl}" if ss.get(k) else f"◯ {lbl}" for k, lbl in zip(STEPS, STEP_LABELS)))

    if ss.get("spend_intent_state") == "minted":
        pay_col, card_col = st.columns(2)
        with pay_col:
            if st.button(t("buttons", "pay", default="Pay with XSGD via x402"), type="primary"):
                merchant_id = ss.proposal["selected_items"][0]["merchant_id"]
                body = {"items": [{"sku": i["sku"], "quantity": i["quantity"]} for i in ss.proposal["selected_items"]]}
                try:
                    r402 = httpx.post(f"{merchants_url}/{merchant_id}/checkout", json=body, timeout=15)
                except httpx.RequestError as exc:
                    st.error(f"could not reach merchant service: {exc}")
                    r402 = None
                if r402 is not None:
                    if r402.status_code != 402:
                        st.error(f"expected a 402 challenge, got {r402.status_code}")
                    else:
                        challenge = r402.json()
                        ss.challenge = challenge
                        auth = call("POST", policy_url, "/authorize", json={
                            "spend_intent": ss.spend_intent, "merchant_id": merchant_id, "challenge": challenge,
                        })
                        if not auth or not auth.get("ok"):
                            st.error(f"{t('labels', 'authorization_refused', default='AUTHORIZATION REFUSED')}: "
                                     f"{(auth or {}).get('detail', 'no response')} — nothing signed")
                            ss.spend_intent_state = "released"
                        else:
                            ss.auth_result = auth
                            ss.spend_intent_state = "committed"   # the policy engine counts the spend once signed
                            try:
                                paid = httpx.post(f"{merchants_url}/{merchant_id}/checkout", json=body,
                                                   headers={"PAYMENT-SIGNATURE": auth["payment_header"]}, timeout=15)
                                if paid.status_code == 200:
                                    ss.receipt = paid.json()
                                else:
                                    st.warning(f"payment was authorized and counted, but settlement with the "
                                               f"merchant returned {paid.status_code}: {paid.text[:200]}")
                            except httpx.RequestError as exc:
                                st.warning(f"payment was authorized and counted, but the merchant service "
                                           f"was unreachable for settlement ({exc})")
                        st.rerun()
        with card_col:
            cardholder_name = st.text_input(
                "Cardholder name", value=ss.get("cardholder_name", ss.mandate.get("principal", "")),
                key="cardholder_name_input",
            )
            if st.button(t("buttons", "issue_card", default="Issue restricted StraitsX card")):
                ss.cardholder_name = cardholder_name
                merchant_id = ss.proposal["selected_items"][0]["merchant_id"]
                peek = peek_intent(ss.spend_intent)
                approved_amount = peek["amount"] if peek else basket_total(ss.proposal["selected_items"])
                card_resp = call("POST", policy_url, "/authorize-card", json={
                    "spend_intent": ss.spend_intent, "merchant_id": merchant_id,
                    "amount": approved_amount, "cardholder_name": cardholder_name,
                })
                if not card_resp or not card_resp.get("ok"):
                    st.error(f"CARD ISSUANCE REFUSED: {(card_resp or {}).get('detail', 'no response')} — nothing issued")
                    ss.spend_intent_state = "released"
                else:
                    ss.card_result = card_resp
                    ss.spend_intent_state = "committed"   # the policy engine counts the spend once StraitsX issues the card
                st.rerun()

    if ss.get("card_result"):
        st.subheader("Restricted StraitsX Card")
        c = ss.card_result
        st.success("CARD ISSUED")
        cols = st.columns(4)
        cols[0].metric("card id", c.get("card_opaque_id", ""))
        cols[1].metric("amount", f"{c.get('amount', 0):.2f} XSGD")
        cols[2].metric("settlement reference", str(c.get("settlement_tx", ""))[:12] + "…")
        cols[3].metric("mode", c.get("mode", ""))

    if ss.get("receipt"):
        st.subheader(t("sections", "transaction", default="Transaction"))
        r = ss.receipt
        settled_onchain = r["receipt"]["settled_onchain"]
        st.success(f"{t('labels', 'paid', default='PAID')}  order `{r['order_id']}`")
        if settled_onchain:
            st.caption("Avalanche transaction hash")
        else:
            st.caption("Verification reference — cryptographically verified, not submitted on-chain "
                       "(SETTLE_MODE=verify)")
        st.code(r["receipt"]["tx_hash"], language=None)
        st.caption(f"{r['amount']:.2f} XSGD to {r['merchant_id']} on {r['receipt']['network']}")

# ---------------------------------------------------------------- 12. ending balance

if ss.get("spend_intent_state") in ("committed", "released", "rejected", "blocked"):
    st.subheader(t("sections", "ending_balance", default="Ending XSGD Balance"))
    m = call("GET", policy_url, f"/mandates/{ss.mandate['mandate_id']}")
    if m:
        ss.ending_balance = m["remaining"]
        c1, c2 = st.columns(2)
        c1.metric("starting balance", f"{ss.starting_balance:.2f} XSGD")
        c2.metric("ending balance", f"{m['remaining']:.2f} XSGD",
                   delta=f"{m['remaining'] - ss.starting_balance:.2f}")

# ---------------------------------------------------------------- 13. hash-chained audit timeline

if ss.get("mandate"):
    st.subheader(t("sections", "audit_timeline", default="Hash-Chained Audit Timeline"))
    audit_data = call("GET", policy_url, "/audit")
    if audit_data:
        if audit_data["chain_ok"]:
            st.success(f"chain intact — {audit_data['message']}")
        else:
            st.error(f"chain broken — {audit_data['message']}")
        show_all = st.checkbox("show all ledger entries (not just this mandate)", value=False)
        mid = ss.mandate["mandate_id"]
        entries = audit_data["entries"]
        if not show_all:
            entries = [e for e in entries if mid in json.dumps(e)]
        for e in entries[-50:]:
            with st.expander(f"#{e['seq']}  {e['ts']}  {e['kind']}  ({e['actor']})"):
                st.json(redact(e["data"]))

# ---------------------------------------------------------------- 14. Audit Agent verdict

if ss.get("spend_intent_state") in ("committed", "released") and ss.get("proposal") and ss.get("verdict"):
    st.subheader(t("sections", "audit_verdict", default="Audit Agent Verdict"))
    if st.button(t("buttons", "run_audit", default="Run Audit Agent")):
        audit_data = call("GET", policy_url, "/audit") or {"chain_ok": False, "message": "unavailable", "entries": []}
        merchant_id = ss.proposal["selected_items"][0]["merchant_id"]
        auth_entry = next((e for e in reversed(audit_data["entries"])
                            if e["kind"] == "payment_authorized" and e["data"].get("merchant_id") == merchant_id), None)
        approval_entry = next((e for e in reversed(audit_data["entries"])
                                if e["kind"] == "human_approved" and e["data"].get("approval_id") == ss.get("approval_id")), None)
        accept = (ss.get("challenge") or {}).get("accepts", [{}])[0]
        peek = peek_intent(ss.spend_intent) or {}
        approved_amount = basket_total(ss.proposal["selected_items"])

        envelope = AuditEnvelope(
            mandate_hash=hash_mandate(Mandate(**ss.mandate)),
            policy_verdict=PolicyVerdict(**ss.verdict),
            spend_intent_id=peek.get("intent_id", "unknown"),
            spend_intent_status="committed" if ss.spend_intent_state == "committed" else "released",
            approved_amount=approved_amount,
            observed_amount=ss.receipt["amount"] if ss.get("receipt") else approved_amount,
            expected_recipient=accept.get("payTo", (auth_entry or {}).get("data", {}).get("pay_to", "")),
            observed_recipient=(auth_entry or {}).get("data", {}).get("pay_to", accept.get("payTo", "")),
            expected_token=accept.get("asset", ""),
            observed_token=(auth_entry or {}).get("data", {}).get("asset", accept.get("asset", "")),
            expected_chain=accept.get("network", ""),
            observed_chain=(auth_entry or {}).get("data", {}).get("network", accept.get("network", "")),
            nonce_use_count=1,
            approval_timestamp=approval_entry["ts"] if approval_entry else None,
            payment_timestamp=auth_entry["ts"] if auth_entry else None,
            transaction_hash=ss.receipt["receipt"]["tx_hash"] if ss.get("receipt") else None,
            # FINTECH review note (see FINTECH.md): settlement_status may only be "settled"
            # when settled_onchain is true. SETTLE_MODE=verify cryptographically verifies the
            # EIP-3009 signature but submits nothing on-chain, so that outcome is reported as
            # "pending", never as a completed settlement.
            settlement_status=(
                "settled" if ss.get("receipt") and ss.receipt["receipt"]["settled_onchain"]
                else "pending" if ss.get("receipt")
                else ("failed" if ss.spend_intent_state == "released" else "unknown")
            ),
            hash_chain_ok=audit_data["chain_ok"],
            hash_chain_message=audit_data["message"],
        )
        ss.audit_verdict = run_audit(envelope).model_dump()

    if ss.get("audit_verdict"):
        av = ss.audit_verdict
        st.write(f"### {status_badge(av['status'])}   risk score {av['risk_score']:.2f}")
        if av["flags"]:
            st.write(" ".join(f"`{f}`" for f in av["flags"]))
        st.write(av["explanation"])
        st.info(av["recommended_action"])

# ---------------------------------------------------------------- 15. malicious BargainBin demonstration (attack demo)

st.divider()
st.header(t("sections", "attack_demo", default="Attack Demo — Malicious BargainBin"))
st.caption(t("attack_demo", "intro", default=""))

if st.button(t("buttons", "run_attack_demo", default="Run attack demo")):
    for key in list(ss.keys()):
        if key.startswith("atk_"):
            del ss[key]

    goal = "usb-c charger"
    merchants_incl_hostile = DEFAULT_MERCHANTS + ["bargainbin"]

    try:
        raw = httpx.get(f"{merchants_url}/bargainbin/search", params={"q": goal}, timeout=10).json()
    except httpx.RequestError as exc:
        raw = {"error": str(exc)}
    ss.atk_raw = raw

    mandate = Mandate(
        mandate_id="m-" + uuid.uuid4().hex[:8], principal="Team ProcureGuard",
        budget_total=30.0, per_txn_max=15.0, allowed_categories=["electronics", "accessories"],
        allowed_merchants=DEFAULT_MERCHANTS,   # bargainbin is reachable but never allowlisted
        require_human_above=12.0, expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )
    call("POST", policy_url, "/mandates", json=mandate.model_dump())
    ss.atk_mandate = mandate.model_dump()

    quotes, reports = agent_run.gather(goal, merchants_incl_hostile)
    ss.atk_reports = [r.model_dump() for r in reports]
    ss.atk_quotes = [q.model_dump() for q in quotes]

    try:
        best, rest, reason = agent_run.choose(quotes, need_today=True)
        decision = agent_run.Decision(
            decision_id="d-" + uuid.uuid4().hex[:8], goal=goal,
            chosen=best, rejected=rest, reasoning=reason, quantity=1,
        )
        verdict = call("POST", policy_url, "/evaluate", json={
            "mandate_id": mandate.mandate_id, "decision": decision.model_dump(),
        })
        ss.atk_decision = decision.model_dump()
        ss.atk_verdict = verdict
    except SystemExit as exc:
        st.error(str(exc))

if ss.get("atk_mandate"):
    if ss.get("atk_raw", {}).get("store_notice"):
        with st.expander(t("attack_demo", "hidden_instruction_heading",
                            default="Hidden merchant instruction (raw, before the pre-hook)")):
            st.warning("Raw merchant response — never fed to the agent's context. Shown here only "
                       "so a human can see what BargainBin tried to smuggle in.")
            st.code(ss.atk_raw["store_notice"], language=None)

    st.write(f"**{t('attack_demo', 'prehook_heading', default='Pre-hook: what the agent actually received')}**")
    for rep in ss.atk_reports:
        icon = "🚨" if rep["signals"] else "·"
        st.write(f"{icon} `{rep['merchant_id']}` — {rep['items_out']}/{rep['items_in']} items typed, "
                 f"{rep['chars_dropped']} chars discarded" +
                 (f", signals: {', '.join(sorted({s['signal'] for s in rep['signals']}))}" if rep["signals"] else ""))
        for s in rep["signals"]:
            st.caption(f"discarded [{s['signal']}] in {s['field']}: \"{s['excerpt'][:90]}\"")

    if ss.get("atk_decision"):
        st.write(f"**Execution agent proposed:** {ss.atk_decision['chosen']['merchant_name']} — "
                 f"{ss.atk_decision['reasoning']}")

    if ss.get("atk_verdict"):
        v = ss.atk_verdict
        st.write(f"**{t('attack_demo', 'policy_heading', default='Policy engine verdict')}**")
        for c in v["checks"]:
            st.write(("✅" if c["passed"] else "❌") + f" `{c['name']}` — {c['detail']}")
        if not v["allowed"] and not v["needs_human"]:
            st.error(f"{t('labels', 'blocked_before_signature', default='BLOCKED before any signature was produced')}: {v['reason']}")
            st.write(f"✅ {t('attack_demo', 'no_signature', default='No signature was produced.')}")
            m = call("GET", policy_url, f"/mandates/{ss.atk_mandate['mandate_id']}")
            if m:
                st.write(f"✅ {t('attack_demo', 'no_balance_change', default='No balance change.')} "
                         f"({m['spent']:.2f} XSGD spent, {m['remaining']:.2f} of "
                         f"{ss.atk_mandate['budget_total']:.2f} remaining)")
        else:
            st.warning("this run did not block as expected — check merchant/mandate configuration")
