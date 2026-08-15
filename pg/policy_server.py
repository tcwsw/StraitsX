"""The policy engine as its own service. Run: uvicorn pg.policy_server:app --port 4020

Separate process on purpose. The execution agent can be fully compromised and still
cannot mint a SpendIntent, because it does not hold POLICY_SECRET.
"""
from __future__ import annotations

import os
from pathlib import Path


def _load_policy_dotenv() -> None:
    """Load this service's OWN, private `.env.policy` — never shared with the execution
    agent/dashboard process — before anything below imports `pg.policy_engine`, which
    reads POLICY_SECRET at import time. A value already exported into the shell (e.g. by
    `run.sh` sourcing `profiles/*.env` first, or a test process that has already set a
    placeholder POLICY_SECRET before importing anything under `pg`) always wins; this
    only fills in what is not already set, and skips the file entirely once POLICY_SECRET
    is present, so it never layers an unrelated developer's real `.env.policy` values on
    top of an already-configured process (test suites in particular). Safe to call if
    `.env.policy` does not exist or python-dotenv is not installed — either way, the
    secrets must already be in the shell environment or the imports below will raise."""
    if os.environ.get("POLICY_SECRET"):
        return
    try:
        from dotenv import dotenv_values
    except ImportError:
        return
    repo_root = Path(__file__).resolve().parent.parent
    for key, value in (dotenv_values(repo_root / ".env.policy") or {}).items():
        if value is not None and key not in os.environ:
            os.environ[key] = value


_load_policy_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import card_adapter, live_guard, money, policy_engine as pe
from .ledger import Ledger
from .x402_client import (
    PaymentRefused, agent_address, encode_header, pick_accept, sign_payment,
)

from .models import Decision, Mandate, Offer, PolicyVerdict, PurchaseProposal

ALLOWED_NETWORKS = pe.ALLOWED_NETWORKS

app = FastAPI(title="ProcureGuard policy engine")
# Local demo tooling only (the static frontend/ page is served from its own origin, e.g.
# http://127.0.0.1:8080, and needs to call this API directly). No secrets or cookies ever
# flow over this boundary — every value here is non-secret display/decision data.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
ledger = Ledger()
_MANDATES: dict[str, Mandate] = {}
_ISSUED_CARDS: set[str] = set()   # card_opaque_id -> issued by this policy engine (membership only, no material)


class EvalRequest(BaseModel):
    mandate_id: str
    decision: Decision


class BasketEvalRequest(BaseModel):
    mandate_id: str
    proposal: PurchaseProposal


class OffersSnapshotRequest(BaseModel):
    """An explicit, attested point-in-time view of what the agent actually saw when it
    gathered quotes — replaces the entire in-memory offers snapshot pg.policy_engine checks
    `offer_exists`/`category_allowed`/`stock_available`/`no_denied_items`/`currency`
    against (falling back to product/catalog.json for any (merchant_id, offer_id) not
    covered here)."""

    offers: list[Offer]


class CardRequest(BaseModel):
    """The application-level interface is execute_payment(spend_intent_id, rail) — the
    caller supplies only the intent and a human-facing name; merchant_id and amount are
    derived here, from the SpendIntent token itself, and the wallet address is derived
    from AGENT_PRIVATE_KEY below. The caller cannot supply, and therefore cannot lie
    about, any of those."""

    spend_intent: str
    cardholder_name: str


class AuthorizeRequest(BaseModel):
    """The agent forwards the raw 402 challenge. It does not get to summarise it, and it
    does not get to name the merchant either — that is derived from the SpendIntent token."""

    spend_intent: str
    challenge: dict


class IntentSettledRequest(BaseModel):
    """Reported by the execution agent once merchant settlement has (allegedly) occurred.
    For a MAINNET report (`network == live_guard.MAINNET_NETWORK`), this claim is NEVER
    sufficient by itself — `tx_hash` is independently re-verified directly against
    Avalanche RPC (see `_verify_and_consume_mainnet_settlement()`) before the SpendIntent
    is ever marked CONSUMED. Any other network keeps the original, unverified behavior
    (fuji/verify-mode demos, where there is no real chain to check)."""

    tx_hash: str | None = None
    network: str | None = None
    order_id: str | None = None


class IntentFailedRequest(BaseModel):
    """Reported by the execution agent when payment did not succeed. `definite=True` (a
    merchant rejection, a refused signature, anything with a clear answer) releases the
    reservation so the same intent may be retried. `definite=False` (a timeout, a dropped
    connection — anything where we genuinely do not know if the merchant was paid) instead
    marks RECONCILIATION_REQUIRED and DELIBERATELY retains the reservation."""

    reason: str
    definite: bool = True


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


@app.get("/merchants/registry")
def merchants_registry():
    """Read-only view of the Merchant Wallet Registry — which merchants may transact, their
    status, and where their payment settles. Source of truth is
    data/merchant_registry.json (FINTECH-owned); there is deliberately no write endpoint —
    registry changes are a FINTECH data change, never an API call."""
    return {"merchants": [rec.public_dict() for rec in pe.REGISTRY.all().values()]}


@app.get("/system/info")
def system_info():
    """Non-secret operational facts only — no private key, no POLICY_SECRET, no wallet
    balance. Lets a thin client (the dashboard) show accurate mainnet/self-transfer/card
    badges and gate its own UI controls without ever holding SETTLE_MODE/CARD_MODE/
    ALLOW_SELF_TRANSFER_DEMO itself — those belong to this process's own `.env.policy`."""
    return {
        "settle_mode": os.environ.get("SETTLE_MODE", "verify"),
        "card_mode": os.environ.get("CARD_MODE", "simulate"),
        "self_transfer_demo_allowed": live_guard.self_transfer_allowed(),
        "mainnet_network": live_guard.MAINNET_NETWORK,
    }


@app.post("/offers/snapshot")
def offers_snapshot(req: OffersSnapshotRequest):
    """Post an attested, point-in-time snapshot of the offers the agent actually gathered
    quotes from. Becomes the ground truth `evaluate_basket()`'s `offer_exists`,
    `category_allowed`, `stock_available`, `no_denied_items` and `currency` checks (and the
    amount actually minted) are checked against, for any (merchant_id, offer_id) it
    covers — anything not covered here still falls back to product/catalog.json."""
    count = pe.set_offers_snapshot(req.offers)
    ledger.append("offers_snapshot_stored", "execution_agent", {"offers_count": count})
    return {"ok": True, "offers_count": count}


@app.post("/agent/{mandate_id}/status")
def set_agent_status(mandate_id: str, status: str):
    """Human/operator control: PAUSE or REVOKE the agent acting under one mandate (or
    reinstate it to ACTIVE). Checked as `agent_active` — the very first gate on every new
    procurement — AND again, independently, immediately before a signature is ever produced
    in /authorize and /authorize-card, so a pause landing in between still stops the money."""
    try:
        new_status = pe.set_agent_status(mandate_id, status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    ledger.append("agent_status_changed", "human", {"mandate_id": mandate_id, "status": new_status})
    return {"ok": True, "mandate_id": mandate_id, "status": new_status}


@app.get("/agent/{mandate_id}/status")
def get_agent_status(mandate_id: str):
    """ACTIVE unless a human/operator has explicitly paused or revoked this mandate's
    agent."""
    return {"mandate_id": mandate_id, "status": pe.get_agent_status(mandate_id)}


@app.post("/evaluate", response_model=PolicyVerdict)
def evaluate(req: EvalRequest):
    mandate = _MANDATES[req.mandate_id]
    ledger.append("procurement_request", "execution_agent", {
        "procurement_id": req.decision.decision_id, "goal": req.decision.goal,
    })
    ledger.append("offers_evaluated", "execution_agent", {
        "procurement_id": req.decision.decision_id,
        "chosen": req.decision.chosen.model_dump(),
        "rejected": [q.model_dump() for q in req.decision.rejected],
    })
    ledger.append("decision_submitted", "execution_agent", {
        "decision_id": req.decision.decision_id,
        "procurement_id": req.decision.decision_id,
        "goal": req.decision.goal,
        "chosen": req.decision.chosen.model_dump(),
        "rejected": [q.model_dump() for q in req.decision.rejected],
        "reasoning": req.decision.reasoning,
        "amount": req.decision.amount,
    })
    verdict = pe.evaluate(mandate, req.decision)
    ledger.append("policy_verdict", "policy_engine", {
        "decision_id": req.decision.decision_id,
        "procurement_id": verdict.procurement_id,
        "allowed": verdict.allowed,
        "needs_human": verdict.needs_human,
        "reason": verdict.reason,
        "checks": verdict.checks,
    })
    if verdict.spend_intents:
        ledger.append("spend_intent_reserved", "policy_engine", {
            "procurement_id": verdict.procurement_id,
            "legs": [{"merchant_id": leg.merchant_id, "amount": leg.amount} for leg in verdict.spend_intents],
        })
    return verdict


@app.post("/evaluate-basket", response_model=PolicyVerdict)
def evaluate_basket(req: BasketEvalRequest):
    """Basket-shaped counterpart to /evaluate. Same deterministic, LLM-free control plane —
    a typed PurchaseProposal and the Mandate go in, a verdict comes out."""
    mandate = _MANDATES[req.mandate_id]
    ledger.append("procurement_request", "execution_agent", {
        "procurement_id": req.proposal.decision_id, "goal": req.proposal.goal,
    })
    ledger.append("offers_evaluated", "execution_agent", {
        "procurement_id": req.proposal.decision_id,
        "selected_items": [i.model_dump() for i in req.proposal.selected_items],
        "rejected_alternatives": [r.model_dump() for r in req.proposal.rejected_alternatives],
    })
    ledger.append("basket_proposal_submitted", "execution_agent", {
        "decision_id": req.proposal.decision_id,
        "procurement_id": req.proposal.decision_id,
        "goal": req.proposal.goal,
        "selected_items": [i.model_dump() for i in req.proposal.selected_items],
        "rejected_alternatives": [r.model_dump() for r in req.proposal.rejected_alternatives],
        "reasoning": req.proposal.reasoning,
        "total_amount": req.proposal.total_amount,
    })
    verdict = pe.evaluate_basket(mandate, req.proposal)
    ledger.append("basket_policy_verdict", "policy_engine", {
        "decision_id": req.proposal.decision_id,
        "procurement_id": verdict.procurement_id,
        "allowed": verdict.allowed,
        "needs_human": verdict.needs_human,
        "reason": verdict.reason,
        "checks": verdict.checks,
        "spend_intents": [leg.model_dump() for leg in verdict.spend_intents],
    })
    if verdict.spend_intents:
        ledger.append("spend_intent_reserved", "policy_engine", {
            "procurement_id": verdict.procurement_id,
            "legs": [{"merchant_id": leg.merchant_id, "amount": leg.amount} for leg in verdict.spend_intents],
        })
    return verdict


@app.post("/authorize")
def authorize(req: AuthorizeRequest):
    """Verify recipient and produce the EIP-3009 signature. Redemption happens in TWO
    steps, never one: this endpoint only reserves the intent and signs (state moves to
    EXECUTING) — it deliberately does NOT call commit_intent. The spend only becomes real,
    and cumulative budget only actually moves, once the caller reports merchant
    settlement via POST /intents/{intent_id}/settled. A caller who never reports back
    leaves the intent stuck at EXECUTING/AUTHORIZED, holding its reservation, rather than
    silently (and wrongly) counting money that may never have moved.

    This is why the claim 'the model never touches the money' is literal rather than
    aspirational. AGENT_PRIVATE_KEY is read here and nowhere else. The execution agent
    forwards the 402 challenge it received and gets back a header value or a refusal. It
    cannot sign anything on its own, so a fully compromised agent — prompt-injected, or with
    an attacker executing code inside it — still cannot move a cent.

    Where the money goes is resolved HERE, at execution time, from the Merchant Wallet
    Registry (never from the SpendIntent, which does not carry a wallet/asset/network/chain
    id at all, and never from the caller — merchant_id itself is derived from the token) —
    and re-checked against what the merchant's 402 challenge actually claims. Recipient
    verification happens BEFORE any reservation or signature is produced, so a redirected
    or compromised merchant's challenge is refused (RECIPIENT_MISMATCH) before anything is
    signed.
    """
    try:
        accept = pick_accept(req.challenge, ALLOWED_NETWORKS)
    except PaymentRefused as exc:
        ledger.append("authorization_refused", "policy_engine", {"reason": str(exc)})
        return {"ok": False, "detail": str(exc)}

    quoted = money.micros_to_xsgd(int(accept["amount"]))

    token_body = pe.peek_token(req.spend_intent)
    if token_body is None:
        return {"ok": False, "detail": "malformed token or bad signature"}
    merchant_id = token_body["merchant_id"]
    mandate_id = token_body.get("mandate_id")
    procurement_id = token_body.get("procurement_id")
    intent_id = token_body.get("spend_intent_id")

    # Paused/revoked agents are refused again here, independently, immediately before any
    # signature is ever produced — the first gate was `agent_active` in
    # evaluate()/evaluate_basket(), before the intent was even minted; a pause landing in
    # between those two moments must still stop the money.
    agent_status = pe.get_agent_status(mandate_id) if mandate_id else "ACTIVE"
    if agent_status != "ACTIVE":
        ledger.append("authorization_refused", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "reason": f"AGENT_NOT_ACTIVE: {agent_status}",
        })
        if intent_id:
            pe.mark_denied(intent_id, f"AGENT_NOT_ACTIVE: {agent_status}")
        return {"ok": False, "error": "AGENT_NOT_ACTIVE", "detail": f"agent status is {agent_status}"}

    # Resolve and verify the recipient from the registry, at execution time, BEFORE any
    # reservation or signature — never from the SpendIntent, never invented here.
    try:
        rec = pe.resolve_and_verify_payment(merchant_id, accept)
    except pe.RegistryLookupError as exc:
        ledger.append("RECIPIENT_VERIFICATION_FAILED", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "error": exc.code, "detail": exc.detail,
        })
        if intent_id:
            pe.mark_denied(intent_id, f"{exc.code}: {exc.detail}")
        return {"ok": False, "detail": exc.detail, "error": exc.code}


    ledger.append("RECIPIENT_VERIFIED", "policy_engine", {
        "procurement_id": procurement_id, "merchant_id": merchant_id,
        "payment_recipient": rec.payment_recipient,
        "network": rec.network, "chain_id": rec.chain_id, "currency": rec.currency,
    })

    # Reserve — never redeem outright. Checks the exact amount and merchant this
    # SpendIntent was bound to at mint time, and holds it exclusively so a concurrent
    # replay of the same token cannot also reserve it.
    ok, ref = pe.reserve_intent(req.spend_intent, merchant_id, quoted)
    if not ok:
        ledger.append("spend_intent_rejected", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id, "quoted": quoted,
            "pay_to": accept["payTo"], "detail": ref,
        })
        return {"ok": False, "detail": ref}

    intent_id = ref
    ledger.append("spend_intent_reserved", "policy_engine", {
        "procurement_id": procurement_id, "merchant_id": merchant_id,
        "intent_id": intent_id, "amount": quoted,
    })

    key = os.environ.get("AGENT_PRIVATE_KEY")
    if not key:
        pe.mark_denied(intent_id, "AGENT_PRIVATE_KEY not set on the policy engine (dry run)")
        ledger.append("authorization_dry_run", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id, "quoted": quoted,
            "pay_to": accept["payTo"], "intent_id": intent_id,
        })
        return {"ok": False, "detail": "AGENT_PRIVATE_KEY not set on the policy engine (dry run)"}

    # Self-transfer detection — BEFORE any signature is produced. The payer wallet
    # (derived from AGENT_PRIVATE_KEY) and the merchant's registry payment_recipient can,
    # in this demo, be the SAME address. That is never an ordinary purchase — no value
    # would change hands — so it is refused unless explicitly enabled, and always
    # labelled/warned about when it is.
    payer_address = agent_address(key)
    self_transfer = live_guard.is_self_transfer(payer_address, rec.payment_recipient)
    if self_transfer and not live_guard.self_transfer_allowed():
        pe.mark_denied(intent_id, "SELF_TRANSFER_DISABLED: payer wallet == merchant payment_recipient")
        ledger.append("self_transfer_refused", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "payer_address": payer_address, "payment_recipient": rec.payment_recipient,
            "intent_id": intent_id,
        })
        return {
            "ok": False, "error": "SELF_TRANSFER_DISABLED",
            "detail": "payer wallet and merchant payment_recipient are the same address; "
                      "set ALLOW_SELF_TRANSFER_DEMO=true to permit this labelled demo case",
        }
    if self_transfer:
        ledger.append("self_transfer_labelled", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "payer_address": payer_address, "payment_recipient": rec.payment_recipient,
            "warning": live_guard.SELF_TRANSFER_WARNING, "intent_id": intent_id,
        })

    # One-wallet self-transfer validator — ONLY for a self-transfer targeting real
    # Avalanche mainnet (never fuji/verify, where the whole point is to rehearse safely).
    # Fail-closed: derives payer/relayer addresses from their private keys and requires
    # them, TechStore's registry recipient, and WHITELISTED_WALLET_ADDRESS to all be the
    # SAME address before a signature is ever produced. Never prints a private key.
    if self_transfer and accept["network"] == live_guard.MAINNET_NETWORK:
        try:
            one_wallet_ctx = live_guard.require_one_wallet_self_transfer(
                agent_private_key=key,
                relayer_private_key=os.environ.get("RELAYER_PRIVATE_KEY"),
                registry_recipient=rec.payment_recipient,
                whitelisted_address=os.environ.get("WHITELISTED_WALLET_ADDRESS"),
                network=accept["network"],
                settle_mode=os.environ.get("SETTLE_MODE", "verify"),
                allow_self_transfer_demo=live_guard.self_transfer_allowed(),
            )
        except live_guard.OneWalletSelfTransferRefused as exc:
            pe.mark_denied(intent_id, f"ONE_WALLET_VALIDATION_FAILED: {exc}")
            ledger.append("one_wallet_self_transfer_refused", "policy_engine", {
                "procurement_id": procurement_id, "merchant_id": merchant_id,
                "intent_id": intent_id, "failed": exc.failed,
            })
            return {
                "ok": False, "error": "ONE_WALLET_VALIDATION_FAILED",
                "detail": str(exc), "failed_checks": exc.failed,
            }
        ledger.append("one_wallet_self_transfer_validated", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "payer_address": one_wallet_ctx.payer_address,
            "relayer_address": one_wallet_ctx.relayer_address,
        })

    # Live-signing preconditions — a nine-point, fail-closed gate that must pass in full
    # before this policy engine signs an authorization scoped to Avalanche MAINNET. Never
    # applies to the fuji/testnet profile, where the whole point is to rehearse safely.
    if accept["network"] == live_guard.MAINNET_NETWORK:
        mandate = _MANDATES.get(token_body.get("mandate_id"))
        per_intent_max = mandate.per_intent_max if mandate is not None else money.ZERO
        rpc_url = os.environ.get("RPC_URL")
        get_avax_balance = (
            (lambda addr: live_guard.live_avax_balance(addr, rpc_url)) if rpc_url else None
        )
        try:
            ctx = live_guard.require_live_signing_preconditions(
                network=accept["network"],
                chain_id=rec.chain_id,
                asset=accept["asset"],
                expected_asset=pe.XSGD_ASSET,
                recipient_status=rec.status,
                amount=quoted,
                per_txn_max=per_intent_max,
                settle_mode=os.environ.get("SETTLE_MODE", "verify"),
                agent_private_key=key,
                relayer_private_key_present=bool(os.environ.get("RELAYER_PRIVATE_KEY")),
                payer_address=payer_address,
                get_avax_balance=get_avax_balance,
            )
        except live_guard.LiveSigningRefused as exc:
            pe.mark_denied(intent_id, f"LIVE_SIGNING_PRECONDITIONS_FAILED: {exc}")
            ledger.append("live_signing_refused", "policy_engine", {
                "procurement_id": procurement_id, "merchant_id": merchant_id,
                "intent_id": intent_id, "failed": exc.failed,
            })
            return {
                "ok": False, "error": "LIVE_SIGNING_PRECONDITIONS_FAILED",
                "detail": str(exc), "failed_checks": exc.failed,
            }
        ledger.append("live_signing_preconditions_passed", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "checks": ctx.checks,
        })

    try:
        payload = sign_payment(accept, key)
    except Exception as exc:
        pe.mark_failed(intent_id, f"signing failed: {exc}")
        ledger.append("signing_failed", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id, "quoted": quoted,
            "intent_id": intent_id, "detail": str(exc),
        })
        return {"ok": False, "detail": f"signing failed: {exc}"}

    # A real signature exists now, but settlement has NOT been verified — do not commit.
    # The intent moves to EXECUTING and stays reserved until the caller reports back via
    # POST /intents/{intent_id}/settled or /intents/{intent_id}/failed.
    pe.mark_executing(intent_id, "EIP-3009 signature produced, awaiting merchant settlement")
    ledger.append("payment_signed", "policy_engine", {
        "procurement_id": procurement_id,
        "merchant_id": merchant_id,
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
            "amount": quoted, "pay_to": accept["payTo"], "procurement_id": procurement_id,
            "intent_id": intent_id, "self_transfer": self_transfer,
            "warning": live_guard.SELF_TRANSFER_WARNING if self_transfer else None}


@app.post("/authorize-card")
def authorize_card(req: CardRequest):
    """Rail two. Same gate, different instrument.

    A merchant that is not x402-native gets paid with a single-use StraitsX card instead.
    The policy decision is identical and happens first; only the instrument changes.
    merchant_id and amount are derived from the SpendIntent token itself — the caller
    supplies neither. AGENT_PRIVATE_KEY is read here and nowhere else, purely to derive
    the public wallet address StraitsX associates the card with — the key itself,
    POLICY_SECRET, and the SpendIntent bearer token never leave this process and are
    never sent to StraitsX. Card material stays in this process too, so the agent gets an
    opaque id and a settlement reference and nothing else.

    Unlike the x402 rail, card issuance IS the settlement confirmation — StraitsX either
    issues the card synchronously or it does not — so this endpoint commits (CONSUMED)
    immediately on success rather than waiting for a separate settled/failed report.
    """
    token_body = pe.peek_token(req.spend_intent)
    if token_body is None:
        return {"ok": False, "detail": "malformed token or bad signature"}
    merchant_id = token_body["merchant_id"]
    amount = token_body["amount_xsgd"]
    mandate_id = token_body.get("mandate_id")
    procurement_id = token_body.get("procurement_id")
    intent_id = token_body.get("spend_intent_id")

    # Paused/revoked agents are refused again here, independently, immediately before any
    # card is issued — see the matching gate in /authorize.
    agent_status = pe.get_agent_status(mandate_id) if mandate_id else "ACTIVE"
    if agent_status != "ACTIVE":
        ledger.append("authorization_refused", "policy_engine", {
            "rail": "card", "procurement_id": procurement_id, "merchant_id": merchant_id,
            "reason": f"AGENT_NOT_ACTIVE: {agent_status}",
        })
        if intent_id:
            pe.mark_denied(intent_id, f"AGENT_NOT_ACTIVE: {agent_status}")
        return {"ok": False, "error": "AGENT_NOT_ACTIVE", "detail": f"agent status is {agent_status}"}

    try:
        rec = pe.REGISTRY.resolve_recipient(merchant_id)
    except pe.RegistryLookupError as exc:
        ledger.append("RECIPIENT_VERIFICATION_FAILED", "policy_engine", {
            "rail": "card", "procurement_id": procurement_id, "merchant_id": merchant_id,
            "error": exc.code, "detail": exc.detail,
        })
        if intent_id:
            pe.mark_denied(intent_id, f"{exc.code}: {exc.detail}")
        return {"ok": False, "detail": exc.detail, "error": exc.code}

    ledger.append("RECIPIENT_VERIFIED", "policy_engine", {
        "rail": "card", "procurement_id": procurement_id, "merchant_id": merchant_id,
        "payment_recipient": rec.payment_recipient,
    })

    ok, ref = pe.reserve_intent(req.spend_intent, merchant_id, amount)
    if not ok:
        ledger.append("spend_intent_rejected", "policy_engine", {
            "rail": "card", "procurement_id": procurement_id, "merchant_id": merchant_id,
            "amount": amount, "detail": ref,
        })
        return {"ok": False, "detail": ref}

    intent_id = ref
    ledger.append("spend_intent_reserved", "policy_engine", {
        "rail": "card", "procurement_id": procurement_id, "merchant_id": merchant_id,
        "intent_id": intent_id, "amount": amount,
    })

    key = os.environ.get("AGENT_PRIVATE_KEY")
    if not key:
        pe.mark_denied(intent_id, "AGENT_PRIVATE_KEY not set on the policy engine (dry run)")
        ledger.append("card_authorization_dry_run", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "amount": amount, "intent_id": intent_id,
        })
        return {"ok": False, "detail": "AGENT_PRIVATE_KEY not set on the policy engine (dry run)"}

    wallet_address = agent_address(key)

    pe.mark_executing(intent_id, "issuing StraitsX card")
    try:
        result = card_adapter.issue(amount, req.cardholder_name, wallet_address)
    except card_adapter.CardRefused as exc:
        pe.mark_failed(intent_id, str(exc))
        ledger.append("card_refused", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "amount": amount, "detail": str(exc),
        })
        return {"ok": False, "detail": str(exc)}

    pe.mark_consumed(intent_id, "StraitsX card issued")
    safe = result["agent_safe"]
    _ISSUED_CARDS.add(safe["card_opaque_id"])
    ledger.append("card_issued", "policy_engine", {
        "procurement_id": procurement_id, "merchant_id": merchant_id, "intent_id": intent_id, **safe,
    })
    return {"ok": True, **safe, "procurement_id": procurement_id, "intent_id": intent_id}



@app.get("/cards/{card_opaque_id}/view")
def view_card(card_opaque_id: str):
    """Human-only. Makes one LIVE call to the configured StraitsX MCP view tool
    (view_card_sandbox / view_card_prod) every time — never returns a cached snapshot
    captured at issuance, so a human always sees the card's current state. The agent
    never calls this and the model never sees it."""
    if card_opaque_id not in _ISSUED_CARDS:
        return {"ok": False, "detail": "no such card, or it was never issued by this policy engine"}
    try:
        view = card_adapter.view(card_opaque_id)
    except card_adapter.CardRefused as exc:
        return {"ok": False, "detail": str(exc)}
    ledger.append("card_viewed", "human", {"card_opaque_id": card_opaque_id})
    return {"ok": True, **view}


@app.get("/intents")
def list_intents(procurement_id: str | None = None, mandate_id: str | None = None):
    """Every SpendIntent lifecycle record this policy engine knows about — optionally
    filtered to one procurement (every merchant leg of one basket shares a
    procurement_id) or one mandate."""
    return {"intents": pe.list_intents(procurement_id=procurement_id, mandate_id=mandate_id)}


@app.get("/intents/{intent_id}")
def get_intent(intent_id: str):
    """The authoritative, current lifecycle state of one SpendIntent — what the dashboard
    and any other caller should display, instead of locally-tracked labels."""
    rec = pe.get_intent(intent_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no such intent")
    return {"ok": True, **rec}


@app.post("/intents/{intent_id}/settled")
def intent_settled(intent_id: str, req: IntentSettledRequest):
    """The execution agent reports that merchant settlement occurred. The agent's claim is
    the ONLY input for a fuji/verify-mode report — unchanged from before, since there is no
    real chain to check there. For a MAINNET report (`network == live_guard.
    MAINNET_NETWORK`), the claim is NEVER enough by itself: see
    `_verify_and_consume_mainnet_settlement()`, which independently re-derives every fact
    from Avalanche RPC before this SpendIntent is ever marked CONSUMED."""
    rec = pe.get_intent(intent_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no such intent")

    if req.network == live_guard.MAINNET_NETWORK:
        return _verify_and_consume_mainnet_settlement(intent_id, rec, req)

    ok = pe.mark_consumed(intent_id, "merchant settlement verified")
    ledger.append("settlement_verified", "execution_agent", {
        "procurement_id": rec.get("procurement_id"), "merchant_id": rec.get("merchant_id"),
        "intent_id": intent_id, "amount": rec.get("amount_xsgd"),
        "tx_hash": req.tx_hash, "network": req.network, "order_id": req.order_id,
    })
    if req.tx_hash or req.order_id:
        ledger.append("receipt_recorded", "execution_agent", {
            "procurement_id": rec.get("procurement_id"), "merchant_id": rec.get("merchant_id"),
            "intent_id": intent_id, "tx_hash": req.tx_hash, "order_id": req.order_id,
        })
    return {"ok": ok, "intent": pe.get_intent(intent_id)}


def _verify_and_consume_mainnet_settlement(intent_id: str, rec: dict, req: IntentSettledRequest) -> dict:
    """Hardened path for a MAINNET settlement report. The execution agent's claim alone
    must never be enough to consume a SpendIntent: this independently re-verifies, directly
    against Avalanche RPC, that a real, mined, successful XSGD `transferWithAuthorization`
    settled EXACTLY this SpendIntent (merchant, amount, and the demo's self-transfer shape
    all included) before ever marking it CONSUMED. See `pg/live_guard.py::
    verify_onchain_settlement()` for the 9 RPC-verified checks; items 10-12 (replay,
    EXECUTING state, and matching the immutable intent) are enforced here.

    - A reverted or definitely-absent transaction, a replayed tx_hash, or any failed named
      check -> FAILED, reservation released.
    - An RPC timeout or a not-yet-mined transaction -> RECONCILIATION_REQUIRED, reservation
      DELIBERATELY retained (the merchant may still genuinely have been paid).
    - Only once every check passes -> CONSUMED, with the full settlement receipt recorded.
    """
    merchant_id = rec.get("merchant_id")
    procurement_id = rec.get("procurement_id")

    # Item 11: the SpendIntent must still be EXECUTING. Anything else (already CONSUMED,
    # DENIED, FAILED, ...) is refused outright with no state change at all — in particular,
    # an already-CONSUMED intent can never be "settled" a second time by a fresh report.
    if rec.get("status") != "EXECUTING":
        return {
            "ok": False, "error": "INTENT_NOT_EXECUTING",
            "detail": f"intent is in status {rec.get('status')!r}, expected EXECUTING; "
                      "refusing to verify or consume a settlement report for it",
            "intent": rec,
        }

    if not req.tx_hash:
        pe.mark_failed(intent_id, "mainnet settlement report has no tx_hash to independently verify")
        ledger.append("settlement_verification_failed", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "detail": "no tx_hash supplied for a mainnet settlement report",
        })
        return {
            "ok": False, "error": "TX_HASH_REQUIRED",
            "detail": "a mainnet settlement report must include a real tx_hash to verify",
            "intent": pe.get_intent(intent_id),
        }

    # Item 10: replay protection. The same real transaction can never be used to settle
    # two different SpendIntents.
    if not pe.claim_settlement_tx_hash(req.tx_hash, intent_id):
        pe.mark_failed(intent_id, f"tx_hash {req.tx_hash} is already linked to a different SpendIntent")
        ledger.append("settlement_replay_refused", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "tx_hash": req.tx_hash,
        })
        return {
            "ok": False, "error": "TX_HASH_ALREADY_LINKED",
            "detail": f"transaction {req.tx_hash} has already settled a different SpendIntent",
            "intent": pe.get_intent(intent_id),
        }

    # Item 12 (merchant half): the registered recipient for THIS intent's own immutable
    # merchant_id — never anything the caller supplies.
    try:
        merchant_rec = pe.REGISTRY.resolve_recipient(merchant_id)
    except pe.RegistryLookupError as exc:
        pe.mark_failed(intent_id, f"{exc.code}: {exc.detail}")
        ledger.append("settlement_verification_failed", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "detail": f"{exc.code}: {exc.detail}",
        })
        return {"ok": False, "error": exc.code, "detail": exc.detail, "intent": pe.get_intent(intent_id)}

    key = os.environ.get("AGENT_PRIVATE_KEY")
    if not key:
        # A policy-engine-side configuration gap, not a fact about the chain — this is
        # genuinely uncertain (we cannot even name the expected payer), never a hard FAILED.
        pe.mark_reconciliation_required(
            intent_id, "AGENT_PRIVATE_KEY not configured on the policy engine; cannot derive "
                       "the payer address needed to verify this settlement",
        )
        ledger.append("reconciliation_required", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "tx_hash": req.tx_hash,
            "detail": "AGENT_PRIVATE_KEY not configured",
        })
        return {
            "ok": False, "error": "RECONCILIATION_REQUIRED",
            "detail": "AGENT_PRIVATE_KEY not configured on the policy engine; cannot verify settlement",
            "intent": pe.get_intent(intent_id),
        }
    payer_address = agent_address(key)

    # Item 12 (amount half): re-derived from THIS intent's own immutable amount_xsgd —
    # never from anything the caller supplies.
    expected_amount_atomic = money.to_micros(rec["amount_xsgd"])

    try:
        ctx = live_guard.verify_onchain_settlement(
            tx_hash=req.tx_hash,
            expected_chain_id=live_guard.MAINNET_CHAIN_ID,
            expected_asset=pe.XSGD_ASSET,
            expected_payer=payer_address,
            expected_recipient=merchant_rec.payment_recipient,
            expected_amount_atomic=expected_amount_atomic,
            rpc_url=os.environ.get("RPC_URL"),
        )
    except live_guard.SettlementVerificationUncertain as exc:
        pe.mark_reconciliation_required(intent_id, str(exc))
        ledger.append("reconciliation_required", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "tx_hash": req.tx_hash, "detail": str(exc),
        })
        return {
            "ok": False, "error": "RECONCILIATION_REQUIRED", "detail": str(exc),
            "intent": pe.get_intent(intent_id),
        }

    if not ctx.passed:
        pe.mark_failed(intent_id, "; ".join(f"{code}: {detail}" for code, detail in ctx.failed))
        ledger.append("settlement_verification_failed", "policy_engine", {
            "procurement_id": procurement_id, "merchant_id": merchant_id,
            "intent_id": intent_id, "tx_hash": req.tx_hash, "checks": ctx.checks,
        })
        return {
            "ok": False, "error": "SETTLEMENT_VERIFICATION_FAILED",
            "failed_checks": ctx.failed, "intent": pe.get_intent(intent_id),
        }

    ok = pe.mark_consumed(intent_id, "on-chain self-transfer settlement independently verified")
    receipt_record = {
        "authorized_amount_xsgd": rec["amount_xsgd"],
        "economic_value_moved_xsgd": money.ZERO,
        "delegated_budget_consumed_xsgd": rec["amount_xsgd"],
        "wallet_balance_changed": False,
        "self_transfer": True,
        "gas_payer_address": ctx.gas_payer_address,
        "gas_spent_avax": ctx.gas_spent_avax,
        "transaction_hash": req.tx_hash,
    }
    ledger.append("settlement_verified", "policy_engine", {
        "procurement_id": procurement_id, "merchant_id": merchant_id,
        "intent_id": intent_id, "checks": ctx.checks, **receipt_record,
    })
    return {"ok": ok, "intent": pe.get_intent(intent_id), **receipt_record}


@app.post("/intents/{intent_id}/failed")
def intent_failed(intent_id: str, req: IntentFailedRequest):
    """The execution agent reports that payment did not (definitely) succeed, or that its
    outcome is unknown. See IntentFailedRequest for the FAILED vs RECONCILIATION_REQUIRED
    distinction."""
    rec = pe.get_intent(intent_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no such intent")
    if req.definite:
        pe.mark_failed(intent_id, req.reason)
        kind = "payment_failed"
    else:
        pe.mark_reconciliation_required(intent_id, req.reason)
        kind = "reconciliation_required"
    ledger.append(kind, "execution_agent", {
        "procurement_id": rec.get("procurement_id"), "merchant_id": rec.get("merchant_id"),
        "intent_id": intent_id, "reason": req.reason, "definite": req.definite,
    })
    return {"ok": True, "intent": pe.get_intent(intent_id)}


@app.get("/approvals")
def approvals():
    """What is waiting on a human right now. This is the PM's UI state."""
    return pe.pending()


@app.get("/approvals/{approval_id}/intent")
def collect(approval_id: str):
    """The agent collects an intent a human approved. Nothing to collect otherwise.
    `spend_intent` is the first merchant leg (back-compat); `spend_intents` lists every
    leg for a split-merchant basket."""
    intent = pe.collect(approval_id)
    legs = pe.collect_all(approval_id)
    return {"ok": intent is not None, "spend_intent": intent, "spend_intents": legs or []}


@app.post("/approvals/{approval_id}/{action}")
def resolve(approval_id: str, action: str):
    """A human approves or rejects one specific purchase.

    Approval does not raise the mandate and does not grant a session. It mints an intent for
    this exact decision, which is still merchant-bound, amount-bound and single-use.
    """
    if action not in {"approve", "reject"}:
        return {"ok": False, "detail": "action must be approve or reject"}
    ok, detail, intent = pe.resolve(approval_id, action == "approve")
    legs = pe.collect_all(approval_id) if ok and action == "approve" else None
    ledger.append(f"human_{action}d" if ok else "human_action_failed", "human", {
        "approval_id": approval_id, "detail": detail,
    })
    return {"ok": ok, "detail": detail, "spend_intent": intent, "spend_intents": legs or []}


@app.get("/audit")
def audit():
    ok, msg = ledger.verify()
    return {"chain_ok": ok, "message": msg, "entries": list(ledger.read())}
