"""The policy engine as its own service. Run: uvicorn pg.policy_server:app --port 4020

Separate process on purpose. The execution agent can be fully compromised and still
cannot mint a SpendIntent, because it does not hold POLICY_SECRET.
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel

from . import card_adapter, policy_engine as pe
from .ledger import Ledger
from .x402_client import (
    PaymentRefused, agent_address, encode_header, pick_accept, sign_payment,
)

from .models import Decision, Mandate, PolicyVerdict, PurchaseProposal

ALLOWED_NETWORKS = pe.ALLOWED_NETWORKS

app = FastAPI(title="ProcureGuard policy engine")
ledger = Ledger()
_MANDATES: dict[str, Mandate] = {}
_CARD_VIEWS: dict[str, dict] = {}   # card material, held here and nowhere else


class EvalRequest(BaseModel):
    mandate_id: str
    decision: Decision


class BasketEvalRequest(BaseModel):
    mandate_id: str
    proposal: PurchaseProposal


class CardRequest(BaseModel):
    spend_intent: str
    merchant_id: str
    amount: float
    cardholder_name: str


class AuthorizeRequest(BaseModel):
    """The agent forwards the raw 402 challenge. It does not get to summarise it."""

    spend_intent: str
    merchant_id: str
    challenge: dict


@app.post("/mandates")
def register(mandate: Mandate):
    _MANDATES[mandate.mandate_id] = mandate
    ledger.append("mandate_registered", "human", mandate.model_dump())
    return {"ok": True, "mandate_id": mandate.mandate_id}


@app.get("/mandates/{mandate_id}")
def get_mandate(mandate_id: str):
    m = _MANDATES[mandate_id]
    return {"mandate": m.model_dump(), "spent": pe.spent(mandate_id),
            "remaining": round(m.budget_total - pe.spent(mandate_id), 2)}


@app.post("/evaluate", response_model=PolicyVerdict)
def evaluate(req: EvalRequest):
    mandate = _MANDATES[req.mandate_id]
    ledger.append("decision_submitted", "execution_agent", {
        "decision_id": req.decision.decision_id,
        "goal": req.decision.goal,
        "chosen": req.decision.chosen.model_dump(),
        "rejected": [q.model_dump() for q in req.decision.rejected],
        "reasoning": req.decision.reasoning,
        "amount": req.decision.amount,
    })
    verdict = pe.evaluate(mandate, req.decision)
    ledger.append("policy_verdict", "policy_engine", {
        "decision_id": req.decision.decision_id,
        "allowed": verdict.allowed,
        "needs_human": verdict.needs_human,
        "reason": verdict.reason,
        "checks": verdict.checks,
    })
    return verdict


@app.post("/evaluate-basket", response_model=PolicyVerdict)
def evaluate_basket(req: BasketEvalRequest):
    """Basket-shaped counterpart to /evaluate. Same deterministic, LLM-free control plane —
    a typed PurchaseProposal and the Mandate go in, a verdict comes out."""
    mandate = _MANDATES[req.mandate_id]
    ledger.append("basket_proposal_submitted", "execution_agent", {
        "decision_id": req.proposal.decision_id,
        "goal": req.proposal.goal,
        "selected_items": [i.model_dump() for i in req.proposal.selected_items],
        "rejected_alternatives": [r.model_dump() for r in req.proposal.rejected_alternatives],
        "reasoning": req.proposal.reasoning,
        "total_amount": req.proposal.total_amount,
    })
    verdict = pe.evaluate_basket(mandate, req.proposal)
    ledger.append("basket_policy_verdict", "policy_engine", {
        "decision_id": req.proposal.decision_id,
        "allowed": verdict.allowed,
        "needs_human": verdict.needs_human,
        "reason": verdict.reason,
        "checks": verdict.checks,
    })
    return verdict


@app.post("/authorize")
def authorize(req: AuthorizeRequest):
    """Redeem the SpendIntent AND produce the signature, in one place, in this process.

    This endpoint is why the claim 'the model never touches the money' is literal rather
    than aspirational. AGENT_PRIVATE_KEY is read here and nowhere else. The execution agent
    forwards the 402 challenge it received and gets back a header value or a refusal. It
    cannot sign anything on its own, so a fully compromised agent — prompt-injected, or with
    an attacker executing code inside it — still cannot move a cent.

    Every field that determines where money goes is re-derived from the challenge HERE and
    re-checked HERE, twice: once against OUR merchant registry / asset / network config
    directly, and again against the exact values the SpendIntent itself was bound to at mint
    time. We do not trust the agent's summary of what the merchant asked for, and we do not
    increase cumulative spend until a payment actually succeeds.
    """
    try:
        accept = pick_accept(req.challenge, ALLOWED_NETWORKS)
    except PaymentRefused as exc:
        ledger.append("authorization_refused", "policy_engine", {"reason": str(exc)})
        return {"ok": False, "detail": str(exc)}

    quoted = int(accept["amount"]) / 10 ** 6

    # Layer 1: re-derive the expected wallet/asset/chain directly from OUR registry and
    # config. Never trust the challenge's own claims about where the money should go.
    expected_wallet = pe.MERCHANT_REGISTRY.get(req.merchant_id, {}).get("wallet")
    if not expected_wallet or accept.get("payTo", "").lower() != expected_wallet.lower():
        detail = (f"accept.payTo {accept.get('payTo')} does not match the registered "
                  f"wallet for merchant {req.merchant_id}")
        ledger.append("authorization_refused", "policy_engine", {
            "merchant_id": req.merchant_id, "detail": detail,
        })
        return {"ok": False, "detail": detail}

    if accept.get("asset", "").lower() != pe.XSGD_ASSET.lower():
        detail = f"accept.asset {accept.get('asset')} does not match the configured XSGD contract"
        ledger.append("authorization_refused", "policy_engine", {
            "merchant_id": req.merchant_id, "detail": detail,
        })
        return {"ok": False, "detail": detail}

    expected_chain_id = int(accept["network"].split(":")[1])
    if accept.get("chainId") != expected_chain_id:
        detail = f"chainId {accept.get('chainId')} does not match network {accept['network']}"
        ledger.append("authorization_refused", "policy_engine", {
            "merchant_id": req.merchant_id, "detail": detail,
        })
        return {"ok": False, "detail": detail}

    # Layer 2: reserve — never redeem outright. Checks the exact amount, payTo, asset,
    # network and chain against what THIS SpendIntent was bound to at mint time, and holds
    # it exclusively so a concurrent replay of the same token cannot also reserve it.
    ok, ref = pe.reserve_intent(
        req.spend_intent, req.merchant_id, quoted,
        pay_to=accept["payTo"], asset=accept["asset"],
        network=accept["network"], chain_id=accept.get("chainId"),
    )
    if not ok:
        ledger.append("spend_intent_rejected", "policy_engine", {
            "merchant_id": req.merchant_id, "quoted": quoted,
            "pay_to": accept["payTo"], "detail": ref,
        })
        return {"ok": False, "detail": ref}

    intent_id = ref
    key = os.environ.get("AGENT_PRIVATE_KEY")
    if not key:
        pe.release_intent(intent_id)
        ledger.append("authorization_dry_run", "policy_engine", {
            "merchant_id": req.merchant_id, "quoted": quoted, "pay_to": accept["payTo"],
            "intent_id": intent_id,
        })
        return {"ok": False, "detail": "AGENT_PRIVATE_KEY not set on the policy engine (dry run)"}

    try:
        payload = sign_payment(accept, key)
    except Exception as exc:
        pe.release_intent(intent_id)
        ledger.append("signing_failed", "policy_engine", {
            "merchant_id": req.merchant_id, "quoted": quoted, "intent_id": intent_id,
            "detail": str(exc),
        })
        return {"ok": False, "detail": f"signing failed: {exc}"}

    # Only now, with a real signed authorization in hand, does the spend become real.
    pe.commit_intent(intent_id)
    ledger.append("payment_authorized", "policy_engine", {
        "merchant_id": req.merchant_id,
        "amount": quoted,
        "pay_to": accept["payTo"],
        "asset": accept["asset"],
        "network": accept["network"],
        "signer": agent_address(key),
        "eip3009_nonce": payload["payload"]["authorization"]["nonce"],
        "valid_before": payload["payload"]["authorization"]["validBefore"],
        "intent_id": intent_id,
    })
    return {"ok": True, "payment_header": encode_header(payload), "signer": agent_address(key),
            "amount": quoted, "pay_to": accept["payTo"]}


@app.post("/authorize-card")
def authorize_card(req: CardRequest):
    """Rail two. Same gate, different instrument.

    A merchant that is not x402-native gets paid with a single-use StraitsX card instead.
    The policy decision is identical and happens first; only the instrument changes.
    AGENT_PRIVATE_KEY is read here and nowhere else, purely to derive the public wallet
    address StraitsX associates the card with — the key itself, POLICY_SECRET, and the
    SpendIntent bearer token never leave this process and are never sent to StraitsX. Card
    material stays in this process too, so the agent gets an opaque id and a settlement
    reference and nothing else.
    """
    expected_wallet = pe.MERCHANT_REGISTRY.get(req.merchant_id, {}).get("wallet")
    if not expected_wallet:
        detail = f"unknown merchant {req.merchant_id}"
        ledger.append("spend_intent_rejected", "policy_engine", {
            "rail": "card", "merchant_id": req.merchant_id, "detail": detail,
        })
        return {"ok": False, "detail": detail}

    ok, ref = pe.reserve_intent(
        req.spend_intent, req.merchant_id, req.amount,
        pay_to=expected_wallet, asset=pe.XSGD_ASSET,
        network=pe.expected_network(), chain_id=None,
    )
    if not ok:
        ledger.append("spend_intent_rejected", "policy_engine", {
            "rail": "card", "merchant_id": req.merchant_id,
            "amount": req.amount, "detail": ref,
        })
        return {"ok": False, "detail": ref}

    intent_id = ref
    key = os.environ.get("AGENT_PRIVATE_KEY")
    if not key:
        pe.release_intent(intent_id)
        ledger.append("card_authorization_dry_run", "policy_engine", {
            "merchant_id": req.merchant_id, "amount": req.amount, "intent_id": intent_id,
        })
        return {"ok": False, "detail": "AGENT_PRIVATE_KEY not set on the policy engine (dry run)"}

    wallet_address = agent_address(key)

    try:
        result = card_adapter.issue(req.amount, req.cardholder_name, wallet_address)
    except card_adapter.CardRefused as exc:
        pe.release_intent(intent_id)
        ledger.append("card_refused", "policy_engine", {
            "merchant_id": req.merchant_id, "amount": req.amount, "detail": str(exc),
        })
        return {"ok": False, "detail": str(exc)}

    pe.commit_intent(intent_id)
    safe = result["agent_safe"]
    _CARD_VIEWS[safe["card_opaque_id"]] = result["human_only"]
    ledger.append("card_issued", "policy_engine", {
        "merchant_id": req.merchant_id, "intent_id": intent_id, **safe,
    })
    return {"ok": True, **safe}



@app.get("/cards/{card_opaque_id}/view")
def view_card(card_opaque_id: str):
    """Human-only, and one-time. The agent never calls this and the model never sees it."""
    view = _CARD_VIEWS.pop(card_opaque_id, None)
    if not view:
        return {"ok": False, "detail": "no card, or it has already been viewed once"}
    ledger.append("card_viewed", "human", {"card_opaque_id": card_opaque_id})
    return {"ok": True, **view}


@app.get("/approvals")
def approvals():
    """What is waiting on a human right now. This is the PM's UI state."""
    return pe.pending()


@app.get("/approvals/{approval_id}/intent")
def collect(approval_id: str):
    """The agent collects an intent a human approved. Nothing to collect otherwise."""
    intent = pe.collect(approval_id)
    return {"ok": intent is not None, "spend_intent": intent}


@app.post("/approvals/{approval_id}/{action}")
def resolve(approval_id: str, action: str):
    """A human approves or rejects one specific purchase.

    Approval does not raise the mandate and does not grant a session. It mints an intent for
    this exact decision, which is still merchant-bound, amount-bound and single-use.
    """
    if action not in {"approve", "reject"}:
        return {"ok": False, "detail": "action must be approve or reject"}
    ok, detail, intent = pe.resolve(approval_id, action == "approve")
    ledger.append(f"human_{action}d" if ok else "human_action_failed", "human", {
        "approval_id": approval_id, "detail": detail,
    })
    return {"ok": ok, "detail": detail, "spend_intent": intent}


@app.get("/audit")
def audit():
    ok, msg = ledger.verify()
    return {"chain_ok": ok, "message": msg, "entries": list(ledger.read())}
