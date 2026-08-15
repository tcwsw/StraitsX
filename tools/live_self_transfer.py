"""INTERACTIVE ONLY. Real Avalanche MAINNET self-transfer demonstration.

Normally invoked via `./run.sh live-self-transfer`, never directly in CI or a script.

This exercises the full mainnet payment path (mandate -> evaluate-basket -> 402 ->
/authorize -> merchant settlement -> /intents/{id}/settled) for the specific, labelled,
FINAL one-wallet spec: the payer (derived from AGENT_PRIVATE_KEY), the relayer (derived
from RELAYER_PRIVATE_KEY), TechStore's registered payment_recipient (from the trusted
merchant registry), and WHITELISTED_WALLET_ADDRESS are all, deliberately, the SAME
address. No XSGD value can change hands in that case — only gas is spent — which is
exactly why every display below says so explicitly rather than looking like an ordinary
purchase.

The basket is fixed and exact: 2x TS-C01 (USB-C Charger 45W, 0.72 XSGD each) + 1x TS-H01
(HDMI Cable 2m, 0.48 XSGD) from TechStore = exactly 1.92 XSGD (1,920,000 atomic units at
6 decimals). Both items resolve to the SAME TechStore merchant, so this basket mints
exactly one SpendIntent leg — it is deliberately NOT a split-merchant basket.

Secret handling: this script reads AGENT_PRIVATE_KEY/RELAYER_PRIVATE_KEY from .env.policy
for ONE purpose only — deriving their public addresses via
`pg.live_guard.derive_public_address()` — then drops both from this process's environment
immediately and never references either again. Every signature is produced exclusively
inside pg/policy_server.py, over HTTP; this script never signs, and never prints or
returns any private key. It deliberately never imports agent/run.py: that module asserts
at import time that its process holds none of these financial secrets
(config/process_env.assert_no_financial_secrets), so this script's basket-construction and
settlement-reporting logic is intentionally self-contained rather than shared.

Ten-point live preflight, ALL of which must pass before the confirmation prompt is even
shown (aborts immediately, before any mandate/SpendIntent exists, on the first failure):
  1. payer == recipient == relayer (== the operator-whitelisted address).
  2. the wallet holds at least 1.92 XSGD (the full basket total).
  3. the wallet holds enough native AVAX to cover a conservative, live-gas-price-based
     estimate of the settlement transaction's gas.
  4. TechStore is ACTIVE in the Merchant Wallet Registry.
  5. the registry's recipient for TechStore matches the payTo the merchant's own 402
     challenge actually quotes for this exact basket.
  6. network, chain id and the XSGD contract address are all the configured mainnet ones.
  7. SETTLE_MODE=onchain.
  8. ALLOW_SELF_TRANSFER_DEMO=true.
  9. stdin/stdout are a real interactive terminal (checked first, before anything else).
 10. the operator types the exact confirmation phrase below.

Usage:  python -m tools.live_self_transfer
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from dotenv import load_dotenv
from web3 import Web3

from pg import live_guard
from pg.models import Mandate, PurchaseProposal, RequestedItem, SelectedLineItem

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env.policy"
FINTECH_POLICY_CONFIG = ROOT / "fintech" / "policy_config.json"

CONFIRM_PHRASE = "LIVE SELF TRANSFER"
REQUIRED_CHAIN_ID = 43114
REQUIRED_NETWORK = "eip155:43114"
REQUIRED_XSGD_ASSET = "0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E"   # Avalanche mainnet XSGD
MERCHANT_ID = "techstore"

# The fixed, final basket: exactly two chargers and one HDMI cable, one merchant, one
# SpendIntent leg, exactly 1.92 XSGD total.
BASKET_ITEMS = [
    {"sku": "TS-C01", "title": "USB-C Charger 45W", "unit_price": Decimal("0.72"), "quantity": 2},
    {"sku": "TS-H01", "title": "HDMI Cable 2m", "unit_price": Decimal("0.48"), "quantity": 1},
]
TOTAL_XSGD = sum((item["unit_price"] * item["quantity"] for item in BASKET_ITEMS), Decimal("0.00"))
assert TOTAL_XSGD == Decimal("1.92"), f"basket total drifted: {TOTAL_XSGD}"

# Conservative, documented gas-limit ceiling for Circle FiatToken's transferWithAuthorization
# on Avalanche C-Chain, used ONLY for the pre-signature preflight sanity check below (a real
# signature does not exist yet at that point, so a real eth_estimateGas call is not possible
# — merchants/facilitator.py performs the REAL, exact gas estimate once the signature exists,
# right before submitting). A 50% margin absorbs gas price movement between preflight and
# actual submission.
PREFLIGHT_GAS_LIMIT_CEILING = 150_000
PREFLIGHT_GAS_SAFETY_MARGIN = 1.5

ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf",
     "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals",
     "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
]

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "warn": "\033[93m", "off": "\033[0m"}


def say(msg: str, style: str = "") -> None:
    print(f"{C.get(style, '')}{msg}{C['off']}")


def _fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 2


def _require_interactive() -> None:
    if os.environ.get("CI"):
        raise SystemExit(_fail("live-self-transfer refuses to run when CI is set."))
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit(_fail(
            "live-self-transfer refuses to run without a real interactive terminal. "
            "This command must never be invoked from CI, a script, or a non-interactive shell."
        ))


def _xsgd_balance(token, address: str, decimals: int) -> float:
    raw = token.functions.balanceOf(Web3.to_checksum_address(address)).call()
    return raw / (10 ** decimals)


def _print_checks(title: str, checks: list[dict]) -> bool:
    """Print an ordered PASS/FAIL report and return True only if every check passed."""
    all_passed = all(c["passed"] for c in checks)
    say(f"\n{title} — {'PASSED' if all_passed else 'FAILED'}", "ok" if all_passed else "bad")
    for c in checks:
        mark, style = ("PASS", "ok") if c["passed"] else ("FAIL", "bad")
        say(f"  [{mark}] {c['code']}: {c['detail']}", style)
    return all_passed


def main() -> int:
    _require_interactive()   # preflight item 9
    load_dotenv(ENV_PATH, override=True)

    policy_url = os.environ.get("POLICY_URL", "http://127.0.0.1:4020")
    merchants_url = os.environ.get("MERCHANTS_URL", "http://127.0.0.1:4030")
    rpc_url = os.environ.get("RPC_URL")
    xsgd_asset = os.environ.get("XSGD_ASSET")
    whitelisted = os.environ.get("WHITELISTED_WALLET_ADDRESS")
    network = os.environ.get("X402_NETWORK", "")
    settle_mode = os.environ.get("SETTLE_MODE", "verify")

    missing = [name for name, present in (
        ("AGENT_PRIVATE_KEY", bool(os.environ.get("AGENT_PRIVATE_KEY"))),
        ("RELAYER_PRIVATE_KEY", bool(os.environ.get("RELAYER_PRIVATE_KEY"))),
        ("WHITELISTED_WALLET_ADDRESS", bool(whitelisted)),
        ("RPC_URL", bool(rpc_url)),
        ("XSGD_ASSET", bool(xsgd_asset)),
    ) if not present]
    if missing:
        return _fail(f"missing required config in .env.policy: {', '.join(missing)}")

    try:
        with httpx.Client(timeout=10) as http:
            reg = http.get(f"{policy_url}/merchants/registry").json()
    except httpx.HTTPError as exc:
        return _fail(f"could not reach policy engine at {policy_url}: {exc}")

    rec = next((m for m in reg.get("merchants", []) if m["merchant_id"] == MERCHANT_ID), None)
    if rec is None:
        return _fail(f"{MERCHANT_ID} not found in the merchant registry via {policy_url}")
    if rec.get("status") != "ACTIVE":   # preflight item 4
        return _fail(f"{MERCHANT_ID} is not ACTIVE in the merchant registry")

    # Fail-closed one-wallet validator: derives the payer/relayer addresses from the two
    # private keys (never printed/logged/returned), and requires them, TechStore's trusted
    # registry recipient, and WHITELISTED_WALLET_ADDRESS to all be the SAME address, plus
    # network=mainnet/SETTLE_MODE=onchain/ALLOW_SELF_TRANSFER_DEMO=true. Keys are read into
    # the narrowest possible scope and dropped immediately after this call. Covers preflight
    # items 1 (payer==recipient==relayer==whitelisted), 7 (SETTLE_MODE=onchain) and 8
    # (ALLOW_SELF_TRANSFER_DEMO=true), plus the network half of item 6.
    try:
        ctx = live_guard.require_one_wallet_self_transfer(
            agent_private_key=os.environ.get("AGENT_PRIVATE_KEY"),
            relayer_private_key=os.environ.get("RELAYER_PRIVATE_KEY"),
            registry_recipient=rec.get("payment_recipient"),
            whitelisted_address=whitelisted,
            network=network,
            settle_mode=settle_mode,
            allow_self_transfer_demo=live_guard.self_transfer_allowed(),
        )
    except live_guard.OneWalletSelfTransferRefused as exc:
        say("\nONE-WALLET SELF-TRANSFER VALIDATION — FAILED", "bad")
        for code, detail in exc.failed:
            say(f"  [FAIL] {code}: {detail}", "bad")
        return _fail("refusing before any network call — see failed checks above.")
    finally:
        os.environ.pop("AGENT_PRIVATE_KEY", None)
        os.environ.pop("POLICY_SECRET", None)
        os.environ.pop("RELAYER_PRIVATE_KEY", None)

    payer_address = ctx.payer_address
    say("\nONE-WALLET SELF-TRANSFER VALIDATION — PASSED", "ok")
    for check in ctx.checks:
        say(f"  [PASS] {check['code']}: {check['detail']}", "ok")
    say(f"  payer address:     {ctx.payer_address}", "dim")
    say(f"  relayer address:   {ctx.relayer_address}", "dim")
    say(f"  registry recipient:{ctx.registry_recipient}", "dim")
    say(f"  whitelisted:       {ctx.whitelisted_address}", "dim")

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        chain_id = w3.eth.chain_id
    except Exception as exc:
        return _fail(f"RPC error while reading chain id from {rpc_url}: {exc}")

    token = w3.eth.contract(address=Web3.to_checksum_address(xsgd_asset), abi=ERC20_ABI)
    decimals = token.functions.decimals().call()
    avax_before = w3.eth.get_balance(Web3.to_checksum_address(payer_address)) / 10 ** 18
    xsgd_before = _xsgd_balance(token, payer_address, decimals)

    # Request the merchant's own 402 challenge for this EXACT basket now, before anything
    # else is minted, purely to validate it (preflight items 5 and 6) — a fresh challenge is
    # requested again at settlement time below, since a 402 challenge has its own short
    # maxTimeoutSeconds window.
    checkout_body = {"items": [{"sku": item["sku"], "quantity": item["quantity"]} for item in BASKET_ITEMS]}
    try:
        preflight_challenge = httpx.post(
            f"{merchants_url}/{MERCHANT_ID}/checkout", json=checkout_body, timeout=10,
        )
    except httpx.HTTPError as exc:
        return _fail(f"could not reach merchants service at {merchants_url}: {exc}")
    if preflight_challenge.status_code != 402:
        return _fail(
            f"expected a 402 PAYMENT REQUIRED challenge from {MERCHANT_ID}/checkout for the "
            f"basket, got {preflight_challenge.status_code}"
        )
    accept = preflight_challenge.json()["accepts"][0]

    estimated_gas_cost_avax = (w3.eth.gas_price * PREFLIGHT_GAS_LIMIT_CEILING) / 10 ** 18
    required_avax_for_gas = estimated_gas_cost_avax * PREFLIGHT_GAS_SAFETY_MARGIN

    preflight_checks = [
        {
            "code": "WALLET_HAS_SUFFICIENT_XSGD",
            "passed": xsgd_before >= float(TOTAL_XSGD),
            "detail": f"XSGD balance={xsgd_before:.6f}, need >= {TOTAL_XSGD:.2f} (the full basket total)",
        },
        {
            "code": "WALLET_HAS_AVAX_FOR_ESTIMATED_GAS",
            "passed": avax_before >= required_avax_for_gas,
            "detail": f"AVAX balance={avax_before:.6f}, need >= {required_avax_for_gas:.6f} "
                      f"(live gas price x {PREFLIGHT_GAS_LIMIT_CEILING} gas ceiling x "
                      f"{PREFLIGHT_GAS_SAFETY_MARGIN} safety margin; the exact gas cost is "
                      f"estimated for real once a signature exists, in merchants/facilitator.py)",
        },
        {
            "code": "TECHSTORE_ACTIVE",
            "passed": rec.get("status") == "ACTIVE",
            "detail": f"registry status={rec.get('status')!r}",
        },
        {
            "code": "REGISTRY_RECIPIENT_MATCHES_MERCHANT_PAYTO",
            "passed": (rec.get("payment_recipient") or "").strip().lower()
                       == (accept.get("payTo") or "").strip().lower()
                       and bool(rec.get("payment_recipient")),
            "detail": f"registry payment_recipient={rec.get('payment_recipient')!r}, "
                      f"merchant 402 payTo={accept.get('payTo')!r}",
        },
        {
            "code": "NETWORK_MATCHES_MAINNET",
            "passed": accept.get("network") == REQUIRED_NETWORK and network == REQUIRED_NETWORK,
            "detail": f"X402_NETWORK={network!r}, merchant 402 network={accept.get('network')!r}, "
                      f"expected {REQUIRED_NETWORK!r}",
        },
        {
            "code": "CHAIN_ID_MATCHES_MAINNET",
            "passed": chain_id == REQUIRED_CHAIN_ID and accept.get("chainId") == REQUIRED_CHAIN_ID,
            "detail": f"RPC chain id={chain_id!r}, merchant 402 chainId={accept.get('chainId')!r}, "
                      f"expected {REQUIRED_CHAIN_ID!r}",
        },
        {
            "code": "XSGD_CONTRACT_MATCHES_MAINNET",
            "passed": xsgd_asset is not None
                       and xsgd_asset.lower() == REQUIRED_XSGD_ASSET.lower()
                       and (accept.get("asset") or "").lower() == REQUIRED_XSGD_ASSET.lower(),
            "detail": f"XSGD_ASSET={xsgd_asset!r}, merchant 402 asset={accept.get('asset')!r}, "
                      f"expected {REQUIRED_XSGD_ASSET!r}",
        },
    ]
    if not _print_checks("LIVE PREFLIGHT (items 2, 3, 4, 5, 6)", preflight_checks):
        return _fail("refusing before any mandate or SpendIntent exists — see failed checks above.")

    say("\n" + "=" * 72, "warn")
    say("LIVE SELF-TRANSFER — REAL AVALANCHE MAINNET. Gas will be spent for real.", "warn")
    say("=" * 72, "warn")
    say(f"Payer AND recipient (SAME address): {payer_address}")
    say(f"Chain: Avalanche mainnet ({REQUIRED_CHAIN_ID})   Asset: XSGD ({xsgd_asset})")
    say(f"Basket from {MERCHANT_ID}:")
    for item in BASKET_ITEMS:
        say(f"  {item['quantity']}x {item['title']} ({item['sku']})  {item['unit_price']:.2f} XSGD each")
    say(f"Authorized amount: {TOTAL_XSGD:.2f} XSGD (1,920,000 atomic units)", "b")
    say("\nWallet balances BEFORE (live, on-chain — never cached or assumed):")
    say(f"  AVAX: {avax_before:.6f}")
    say(f"  XSGD: {xsgd_before:.6f}")
    say(
        "\nBecause payer == recipient, NO XSGD value will actually move. Only network gas "
        "(paid from the merchant's own RELAYER_PRIVATE_KEY) will be spent submitting the "
        "transaction. This will be labelled SELF-TRANSFER throughout — never shown as an "
        "ordinary merchant payment.",
        "warn",
    )
    say(f"\nType exactly {CONFIRM_PHRASE!r} to proceed, or anything else to abort.")   # preflight item 10
    typed = input("> ").strip()
    if typed != CONFIRM_PHRASE:
        say("\nAborted — confirmation phrase did not match. Nothing was sent.", "bad")
        return 1

    mandate_id = f"live-self-transfer-{uuid.uuid4().hex[:8]}"
    # FINTECH-owned final one-wallet spec: fintech/policy_config.json's default_mandate —
    # budget_total 30.00, per_intent_max 20.00, 7-day expiry, no human escalation
    # (require_human_above is null) — nothing hardcoded here except the fixed basket, priced
    # well within every one of those limits.
    fintech = json.loads(FINTECH_POLICY_CONFIG.read_text(encoding="utf-8"))["default_mandate"]
    mandate = Mandate(
        mandate_id=mandate_id, principal="demo-operator",
        budget_total=fintech["budget_total"], per_intent_max=fintech["per_intent_max"],
        allowed_categories=fintech["allowed_categories"],
        allowed_merchants=fintech["allowed_merchants"],
        denied_keywords=fintech["denied_keywords"],
        require_human_above=fintech["require_human_above"],
        expires_at=(datetime.now(timezone.utc) + timedelta(days=fintech["mandate_expiry_days"])).isoformat(),
        max_delivery_days=fintech.get("max_delivery_days"),
    )
    assert mandate.require_human_above is None, "this live run must never require human escalation"

    requested_items = [RequestedItem(name=item["title"], quantity=item["quantity"]) for item in BASKET_ITEMS]
    selected_items = [
        SelectedLineItem(
            requested_item=requested_items[i], merchant_id=MERCHANT_ID, sku=item["sku"],
            unit_price=item["unit_price"], quantity=item["quantity"],
        )
        for i, item in enumerate(BASKET_ITEMS)
    ]
    proposal = PurchaseProposal(
        decision_id=f"decision-{uuid.uuid4().hex[:8]}",
        goal="live self-transfer demonstration basket: 2x USB-C Charger 45W + 1x HDMI Cable 2m",
        selected_items=selected_items,
        rejected_alternatives=[],
        reasoning="Fixed, cheap, in-stock TechStore basket used only to exercise the real "
                  "mainnet self-transfer path end to end at exactly 1.92 XSGD.",
    )
    assert proposal.total_amount == TOTAL_XSGD, f"proposal total drifted: {proposal.total_amount}"

    with httpx.Client(timeout=30) as http:
        http.post(f"{policy_url}/mandates", json=mandate.model_dump())
        mandate_before = http.get(f"{policy_url}/mandates/{mandate_id}").json()

        verdict = http.post(f"{policy_url}/evaluate-basket", json={
            "mandate_id": mandate_id, "proposal": proposal.model_dump(),
        }).json()

        say("\n  POLICY ENGINE", "b")
        for c in verdict["checks"]:
            mark, style = ("PASS", "ok") if c["passed"] else ("FAIL", "bad")
            say(f"    [{mark}] {c['name']:<28} {c['detail']}", style)

        if not verdict.get("allowed"):
            say(f"\nPOLICY REFUSED: {verdict.get('reason')}", "bad")
            return 1
        if verdict.get("needs_human"):
            # This mandate has no human-approval threshold; reaching this branch means
            # something is misconfigured, and this run must not silently escalate/wait.
            return _fail("verdict unexpectedly needs human approval — this mandate must never escalate")

        legs = verdict.get("spend_intents") or []
        if len(legs) != 1:
            return _fail(
                f"expected exactly one SpendIntent leg (single-merchant basket), got {len(legs)}"
            )
        leg = legs[0]
        spend_intent = leg["spend_intent"]

        challenge_resp = http.post(f"{merchants_url}/{MERCHANT_ID}/checkout", json=checkout_body)
        if challenge_resp.status_code != 402:
            say(f"\nexpected 402 from merchant checkout, got {challenge_resp.status_code}", "bad")
            return 1
        challenge = challenge_resp.json()

        auth = http.post(f"{policy_url}/authorize", json={
            "spend_intent": spend_intent, "challenge": challenge,
        }).json()
        if not auth.get("ok"):
            say(f"\nAUTHORIZATION REFUSED: {auth.get('detail')}", "bad")
            for code, detail in auth.get("failed_checks") or []:
                say(f"  - {code}: {detail}", "bad")
            return 1

        if auth.get("self_transfer"):
            say(f"\n{auth['warning']}", "warn")

        intent_id = auth["intent_id"]
        paid = http.post(
            f"{merchants_url}/{MERCHANT_ID}/checkout", json=checkout_body,
            headers={"PAYMENT-SIGNATURE": auth["payment_header"]},
        )

        if paid.status_code != 200:
            http.post(f"{policy_url}/intents/{intent_id}/failed", json={
                "reason": f"merchant settlement returned {paid.status_code}: {paid.text[:300]}",
                "definite": True,
            })
            say(f"\nSETTLEMENT FAILED: {paid.status_code} {paid.text}", "bad")
            return 1

        paid_body = paid.json()
        receipt = paid_body["receipt"]
        if not receipt.get("settled_onchain"):
            # SETTLE_MODE=onchain was required and confirmed at preflight (item 7); reaching
            # here with settled_onchain=False means the merchant process is misconfigured.
            # Never present a verification-only reference as if it were a real settlement.
            http.post(f"{policy_url}/intents/{intent_id}/failed", json={
                "reason": "merchant did not settle on-chain despite SETTLE_MODE=onchain", "definite": True,
            })
            return _fail("merchant reported settlement but settled_onchain=False — refusing to report success")

        http.post(f"{policy_url}/intents/{intent_id}/settled", json={
            "tx_hash": receipt["tx_hash"], "network": receipt["network"],
            "order_id": paid_body.get("order_id"),
        })
        mandate_after = http.get(f"{policy_url}/mandates/{mandate_id}").json()

    avax_after = w3.eth.get_balance(Web3.to_checksum_address(payer_address)) / 10 ** 18
    xsgd_after = _xsgd_balance(token, payer_address, decimals)
    tx_hash = receipt["tx_hash"]
    snowtrace_url = f"https://snowtrace.io/tx/{tx_hash}"

    say("\n" + "=" * 72, "ok")
    say("SELF-TRANSFER SETTLED", "ok")
    say("=" * 72, "ok")
    say(f"Authorized amount: {TOTAL_XSGD:.2f} XSGD", "b")
    say(f"Payer and recipient (SAME public address): {payer_address}")
    say(f"To (merchant payTo, same wallet):          {auth['pay_to']}  (self-transfer, no value moved)")
    say(f"Real Snowtrace transaction: {snowtrace_url}")
    say("\nWallet balance BEFORE -> AFTER (live, on-chain):")
    say(f"  AVAX: {avax_before:.6f} -> {avax_after:.6f}  (spent {avax_before - avax_after:.6f} on gas)")
    say(f"  XSGD: {xsgd_before:.6f} -> {xsgd_after:.6f}  (unchanged: payer == recipient)")
    say("\nDelegated budget BEFORE -> AFTER:")
    say(f"  {mandate_before['mandate']['budget_total']:.2f} -> {mandate_after['remaining']:.2f} XSGD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
