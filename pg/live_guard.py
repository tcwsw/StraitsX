"""Safety gate for real, irreversible mainnet money movement.

Two independent responsibilities live here, both consulted from pg/policy_server.py's
/authorize, and both evaluated BEFORE any EIP-3009 authorization is signed:

1. Self-transfer detection (`is_self_transfer` / `self_transfer_allowed`): the demo's
   whitelisted payer wallet and TechStore's registered payment_recipient are, on purpose,
   the same address (WHITELISTED_WALLET_ADDRESS). Signing that payment is not "buying
   from a merchant" — it moves funds from a wallet back to itself, minus gas. That must
   never happen silently: it is refused unless an operator has explicitly set
   ALLOW_SELF_TRANSFER_DEMO=true, and even then it is always labelled and warned about,
   never displayed as an ordinary purchase.

2. Live-signing preconditions (`require_live_signing_preconditions`): a nine-point,
   named, fail-closed gate that must pass in full before this policy engine signs an
   authorization scoped to Avalanche MAINNET. Any single failed check refuses signing —
   there is no partial credit and no default-allow on an unset/unknown value.

Every check here is a pure function over explicit inputs (never reaches into os.environ
or makes a network call itself except the two balance helpers, which take an injectable
callable so tests never need a real RPC endpoint or a real chain).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable

from . import money

MAINNET_NETWORK = "eip155:43114"
MAINNET_CHAIN_ID = 43114

AGENT_KEY_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

SELF_TRANSFER_WARNING = (
    "SELF-TRANSFER: the payer wallet and the merchant's payment_recipient are the SAME "
    "address. No value changes hands — this only spends gas and, if allowed to proceed, "
    "must be labelled as a self-transfer everywhere it is shown, never displayed as an "
    "ordinary purchase from a merchant."
)


def is_self_transfer(payer_address: str, recipient_address: str) -> bool:
    """Case-insensitive comparison — EVM addresses are not case sensitive (EIP-55 checksum
    casing must never affect this comparison)."""
    return payer_address.strip().lower() == recipient_address.strip().lower()


def self_transfer_allowed() -> bool:
    """Read-only, explicit opt-in. Defaults closed (refused) — see profiles/*.env, both of
    which pin ALLOW_SELF_TRANSFER_DEMO=false."""
    return os.environ.get("ALLOW_SELF_TRANSFER_DEMO", "false").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _is_well_formed_address(address: str | None) -> bool:
    return bool(address) and bool(_ADDRESS_RE.match(address.strip()))


def _is_placeholder_address(address: str) -> bool:
    """Every hex character identical (0x1111...1111, 0xaaaa...aaaa, ...) — this codebase's
    old throwaway-testnet-wallet convention. Never treated as a real settlement/demo
    address."""
    hex_part = address.strip()[2:].lower()
    return len(set(hex_part)) == 1


def _is_real_address(address: str | None) -> bool:
    """Well-formed 0x + 40 hex chars, not the zero address, and not an all-repeated-digit
    placeholder. Used to reject malformed, zero, and placeholder addresses outright — a
    'match' against any of those is never a pass."""
    if not _is_well_formed_address(address):
        return False
    value = address.strip()
    if int(value, 16) == 0:
        return False
    return not _is_placeholder_address(value)


def derive_public_address(private_key: str | None) -> str | None:
    """Derive ONLY the public address from a private key. Never returns, logs, or raises
    with the key material itself — returns None for a missing/malformed key or if
    derivation fails for any reason."""
    if not private_key or not AGENT_KEY_RE.match(private_key):
        return None
    from eth_account import Account
    try:
        return Account.from_key(private_key).address
    except Exception:
        return None


class OneWalletSelfTransferRefused(Exception):
    """Raised by require_one_wallet_self_transfer() when one or more named checks fail.
    `.failed` is the ordered list of (code, detail) pairs that did not pass. Never carries
    a private key anywhere — only public addresses and check names/details."""

    def __init__(self, failed: list[tuple[str, str]]):
        self.failed = failed
        codes = ", ".join(code for code, _ in failed)
        super().__init__(f"one-wallet self-transfer validation failed: {codes}")


@dataclass
class OneWalletValidationContext:
    """The full, ordered result of every named check — including the ones that passed —
    plus the public addresses this validator derived/read. Never holds a private key."""

    checks: list[dict] = field(default_factory=list)
    payer_address: str | None = None
    relayer_address: str | None = None
    registry_recipient: str | None = None
    whitelisted_address: str | None = None

    @property
    def passed(self) -> bool:
        return all(c["passed"] for c in self.checks)

    @property
    def failed(self) -> list[tuple[str, str]]:
        return [(c["code"], c["detail"]) for c in self.checks if not c["passed"]]


def evaluate_one_wallet_self_transfer(
    *,
    agent_private_key: str | None,
    relayer_private_key: str | None,
    registry_recipient: str | None,
    whitelisted_address: str | None,
    network: str,
    settle_mode: str,
    allow_self_transfer_demo: bool,
) -> OneWalletValidationContext:
    """Fail-closed validator for the live, one-wallet self-transfer demonstration, where
    the payer, the relayer, TechStore's registered payment_recipient, and the
    operator-whitelisted address are all, deliberately, the SAME wallet.

    1. Derives payer_address from `agent_private_key`.
    2. Derives relayer_address from `relayer_private_key`.
    3. Takes `registry_recipient` as read by the caller from the trusted Merchant Wallet
       Registry (this function never loads the registry itself).
    4. Takes `whitelisted_address` as read by the caller from WHITELISTED_WALLET_ADDRESS.
    5. Requires all four to be equal, case-insensitively.
    6. Rejects malformed, zero, and placeholder addresses outright (never a pass, even if
       every field happens to hold the identical placeholder).
    7. Never prints, logs, or returns a private key — only the public addresses derived
       from them.
    8. Returns every named check (PASS and FAIL alike); never raises.

    Never reaches into os.environ and never makes a network call — every input is
    explicit, so this is trivially unit-testable and always mockable."""
    checks: list[dict] = []

    def _check(code: str, passed: bool, detail: str) -> None:
        checks.append({"code": code, "passed": bool(passed), "detail": detail})

    agent_key_ok = bool(agent_private_key) and bool(AGENT_KEY_RE.match(agent_private_key))
    _check(
        "AGENT_PRIVATE_KEY_CONFIGURED", agent_key_ok,
        "missing" if not agent_private_key else
        ("well-formed 0x + 64 hex char key" if agent_key_ok else "present but malformed"),
    )
    payer_address = derive_public_address(agent_private_key) if agent_key_ok else None
    _check(
        "PAYER_ADDRESS_DERIVED", payer_address is not None,
        payer_address or "could not derive an address from AGENT_PRIVATE_KEY",
    )

    relayer_key_ok = bool(relayer_private_key) and bool(AGENT_KEY_RE.match(relayer_private_key))
    _check(
        "RELAYER_PRIVATE_KEY_CONFIGURED", relayer_key_ok,
        "missing" if not relayer_private_key else
        ("well-formed 0x + 64 hex char key" if relayer_key_ok else "present but malformed"),
    )
    relayer_address = derive_public_address(relayer_private_key) if relayer_key_ok else None
    _check(
        "RELAYER_ADDRESS_DERIVED", relayer_address is not None,
        relayer_address or "could not derive an address from RELAYER_PRIVATE_KEY",
    )

    _check(
        "REGISTRY_RECIPIENT_VALID", _is_real_address(registry_recipient),
        registry_recipient or "TechStore has no registered payment_recipient",
    )
    _check(
        "WHITELISTED_ADDRESS_VALID", _is_real_address(whitelisted_address),
        whitelisted_address or "WHITELISTED_WALLET_ADDRESS is missing or malformed",
    )

    addresses = {
        "payer": payer_address,
        "relayer": relayer_address,
        "registry_recipient": registry_recipient,
        "whitelisted": whitelisted_address,
    }
    all_real = all(_is_real_address(v) for v in addresses.values())
    all_equal = all_real and len({v.strip().lower() for v in addresses.values()}) == 1
    _check(
        "ALL_FOUR_ADDRESSES_EQUAL", all_equal,
        "payer, relayer, registry recipient and whitelisted address all match" if all_equal
        else f"payer={payer_address!r} relayer={relayer_address!r} "
             f"registry_recipient={registry_recipient!r} whitelisted={whitelisted_address!r}",
    )

    _check(
        "NETWORK_IS_MAINNET", network == MAINNET_NETWORK,
        f"network={network!r}, expected {MAINNET_NETWORK!r}",
    )
    _check(
        "SETTLE_MODE_ONCHAIN", settle_mode == "onchain",
        f"SETTLE_MODE={settle_mode!r}, must be 'onchain' for real mainnet settlement",
    )
    _check(
        "ALLOW_SELF_TRANSFER_DEMO_TRUE", bool(allow_self_transfer_demo),
        "ALLOW_SELF_TRANSFER_DEMO is true" if allow_self_transfer_demo
        else "ALLOW_SELF_TRANSFER_DEMO is not true",
    )

    return OneWalletValidationContext(
        checks=checks, payer_address=payer_address, relayer_address=relayer_address,
        registry_recipient=registry_recipient, whitelisted_address=whitelisted_address,
    )


def require_one_wallet_self_transfer(**kwargs) -> OneWalletValidationContext:
    """Fail-closed wrapper around `evaluate_one_wallet_self_transfer()`: raises
    `OneWalletSelfTransferRefused` (carrying every failing check, not just the first) unless
    every single named check passes."""
    ctx = evaluate_one_wallet_self_transfer(**kwargs)
    if not ctx.passed:
        raise OneWalletSelfTransferRefused(ctx.failed)
    return ctx


class LiveSigningRefused(Exception):
    """Raised by require_live_signing_preconditions() when one or more of the nine named
    checks fails. `.failed` is the ordered list of (code, detail) pairs that did not pass —
    every failure is reported together, not just the first one, so an operator can fix
    everything in one pass instead of playing whack-a-mole."""

    def __init__(self, failed: list[tuple[str, str]]):
        self.failed = failed
        codes = ", ".join(code for code, _ in failed)
        super().__init__(f"live-signing preconditions failed: {codes}")


@dataclass
class LiveSigningContext:
    """The full, ordered result of every check — including the ones that passed — so the
    caller can log a complete audit trail, not just the failures."""

    checks: list[dict] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c["passed"] for c in self.checks)

    @property
    def failed(self) -> list[tuple[str, str]]:
        return [(c["code"], c["detail"]) for c in self.checks if not c["passed"]]


def require_live_signing_preconditions(
    *,
    network: str,
    chain_id: int,
    asset: str,
    expected_asset: str,
    recipient_status: str,
    amount: float,
    per_txn_max: float,
    settle_mode: str,
    agent_private_key: str | None,
    relayer_private_key_present: bool,
    payer_address: str,
    get_avax_balance: Callable[[str], float] | None = None,
    min_avax_for_gas: float = 0.01,
) -> LiveSigningContext:
    """Nine named, independent checks. ALL must pass or this raises `LiveSigningRefused`
    naming every one that failed. Fail-closed: anything this function cannot positively
    verify (e.g. no balance-lookup callable was supplied) counts as a FAILED check, never
    a pass-by-default.

    `amount`/`per_txn_max` accept int/float/str/Decimal (whatever the caller has on hand)
    and are normalised to an exact Decimal immediately below via `money.to_xsgd()` — this
    check compares real money, so it must never be decided on binary float noise.
    """
    amount = money.to_xsgd(amount)
    per_txn_max = money.to_xsgd(per_txn_max)
    checks: list[dict] = []

    def _check(code: str, passed: bool, detail: str) -> None:
        checks.append({"code": code, "passed": bool(passed), "detail": detail})

    _check(
        "NETWORK_IS_MAINNET", network == MAINNET_NETWORK,
        f"network={network!r}, expected {MAINNET_NETWORK!r}",
    )
    _check(
        "CHAIN_ID_MATCHES_MAINNET", chain_id == MAINNET_CHAIN_ID,
        f"chain_id={chain_id!r}, expected {MAINNET_CHAIN_ID!r}",
    )
    _check(
        "SETTLE_MODE_ONCHAIN", settle_mode == "onchain",
        f"SETTLE_MODE={settle_mode!r}, must be 'onchain' to sign for real mainnet settlement",
    )
    _check(
        "ASSET_MATCHES_CONFIGURED_XSGD", asset.strip().lower() == expected_asset.strip().lower(),
        f"asset={asset!r}, expected the configured XSGD contract {expected_asset!r}",
    )
    _check(
        "RECIPIENT_STATUS_ACTIVE", recipient_status == "ACTIVE",
        f"merchant registry status={recipient_status!r}, expected 'ACTIVE'",
    )
    _check(
        "AMOUNT_WITHIN_PER_TXN_MAX", 0 < amount <= per_txn_max,
        f"amount={amount}, per_txn_max={per_txn_max}",
    )
    key_ok = bool(agent_private_key) and bool(AGENT_KEY_RE.match(agent_private_key))
    _check(
        "AGENT_KEY_WELLFORMED", key_ok,
        "AGENT_PRIVATE_KEY missing or not a well-formed 0x + 64 hex char key",
    )
    _check(
        "RELAYER_KEY_CONFIGURED", relayer_private_key_present,
        "RELAYER_PRIVATE_KEY is not configured on the merchant/settlement side — a signed "
        "authorization would have nowhere to be submitted",
    )
    if get_avax_balance is None:
        _check(
            "PAYER_HAS_GAS_FOR_FEES", False,
            "no live balance lookup was supplied — cannot verify the payer wallet holds "
            "enough native AVAX to cover gas; refusing rather than assuming it does",
        )
    else:
        try:
            balance = get_avax_balance(payer_address)
            _check(
                "PAYER_HAS_GAS_FOR_FEES", balance >= min_avax_for_gas,
                f"payer AVAX balance={balance}, need >= {min_avax_for_gas}",
            )
        except Exception as exc:
            _check("PAYER_HAS_GAS_FOR_FEES", False, f"balance lookup failed: {exc}")

    ctx = LiveSigningContext(checks=checks)
    if not ctx.passed:
        raise LiveSigningRefused(ctx.failed)
    return ctx


def live_avax_balance(address: str, rpc_url: str | None = None) -> float:
    """Real, live native-AVAX balance in whole AVAX (not wei). Lazy `web3` import so
    importing this module never requires web3 to be installed (mocked out entirely in
    tests via the `get_avax_balance` callable above)."""
    from web3 import Web3

    url = rpc_url or os.environ["RPC_URL"]
    w3 = Web3(Web3.HTTPProvider(url))
    return w3.eth.get_balance(Web3.to_checksum_address(address)) / 10 ** 18


_ERC20_BALANCE_OF_ABI = [{
    "constant": True, "name": "balanceOf", "stateMutability": "view", "type": "function",
    "inputs": [{"name": "account", "type": "address"}],
    "outputs": [{"name": "", "type": "uint256"}],
}]


def live_xsgd_balance(address: str, asset: str | None = None, rpc_url: str | None = None) -> float:
    """Real, live XSGD (6-decimal ERC20) balance for `address`, read directly from the
    configured asset contract — never estimated, never carried over from a previous
    quote."""
    from web3 import Web3

    url = rpc_url or os.environ["RPC_URL"]
    token = asset or os.environ.get("XSGD_ASSET")
    w3 = Web3(Web3.HTTPProvider(url))
    contract = w3.eth.contract(address=Web3.to_checksum_address(token), abi=_ERC20_BALANCE_OF_ABI)
    raw = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    return raw / 10 ** 6


# ---------------------------------------------------------------- independent settlement verification


class SettlementVerificationUncertain(Exception):
    """The outcome could not be determined right now — an RPC timeout/connection error, or
    the transaction is not yet mined/has no receipt yet. NEVER a failure: the caller must
    mark RECONCILIATION_REQUIRED and keep the reservation, because the merchant may still
    genuinely have been paid."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


@dataclass
class SettlementVerificationContext:
    """The full, ordered result of every independent on-chain check (points 1-9 of the
    live settlement verification spec) plus the facts needed for the ledger/audit record.
    Never trusts the caller's claim — every field here was read directly from the chain."""

    checks: list[dict] = field(default_factory=list)
    tx_hash: str = ""
    gas_payer_address: str | None = None
    gas_spent_avax: float | None = None

    @property
    def passed(self) -> bool:
        return all(c["passed"] for c in self.checks)

    @property
    def failed(self) -> list[tuple[str, str]]:
        return [(c["code"], c["detail"]) for c in self.checks if not c["passed"]]


_ERC20_TRANSFER_EVENT_ABI = [{
    "anonymous": False, "name": "Transfer", "type": "event",
    "inputs": [
        {"indexed": True, "name": "from", "type": "address"},
        {"indexed": True, "name": "to", "type": "address"},
        {"indexed": False, "name": "value", "type": "uint256"},
    ],
}]


def verify_onchain_settlement(
    *,
    tx_hash: str,
    expected_chain_id: int,
    expected_asset: str,
    expected_payer: str,
    expected_recipient: str,
    expected_amount_atomic: int,
    rpc_url: str | None = None,
    w3: object | None = None,
) -> SettlementVerificationContext:
    """Independently verify, directly against Avalanche RPC, that `tx_hash` is a real,
    mined, successful XSGD `transferWithAuthorization` settlement matching everything a
    SpendIntent claims. The execution agent's own report of success is NEVER sufficient by
    itself — this is what actually decides it.

    Runs, in order: (1) the transaction exists, (2) receipt.status == 1, (3) chain id
    matches, (4) the transaction targeted the configured XSGD contract, (5) an XSGD
    Transfer event is present in the receipt logs, (6) event.from == the payer address,
    (7) event.to == the merchant's registered recipient, (8) event.from == event.to (this
    demo requires payer and recipient to be the same address), (9) event.value equals the
    expected atomic amount.

    `w3` may be injected directly (a real or fake `web3.Web3`-like object) for fully
    mocked testing; if omitted, a real `web3.Web3(HTTPProvider(rpc_url or
    os.environ["RPC_URL"]))` is constructed (lazy import, so importing this module never
    requires `web3` to be installed).

    Raises `SettlementVerificationUncertain` — never a hard failure — if the transaction
    is not yet mined, has no receipt yet, or an RPC call could not be completed at all: the
    caller must retain the reservation and mark RECONCILIATION_REQUIRED, never
    FAILED/release, since the merchant may still genuinely have been paid.

    Otherwise returns a `SettlementVerificationContext`; the caller checks `.passed` — a
    False here (reverted receipt, wrong contract/recipient/amount, all now definitively
    known) is a real, permanent FAILED, never RECONCILIATION_REQUIRED."""
    if w3 is None:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url or os.environ["RPC_URL"]))

    from web3.exceptions import TransactionNotFound

    checks: list[dict] = []

    def _check(code: str, passed: bool, detail: str) -> None:
        checks.append({"code": code, "passed": bool(passed), "detail": detail})

    try:
        tx = w3.eth.get_transaction(tx_hash)
    except TransactionNotFound:
        tx = None
    except Exception as exc:
        raise SettlementVerificationUncertain(
            f"could not reach RPC to look up transaction {tx_hash}: {exc}"
        ) from exc

    if tx is None:
        raise SettlementVerificationUncertain(
            f"transaction {tx_hash} was not found by RPC — it may still be propagating; "
            "this is NOT a definite failure"
        )
    if tx.get("blockNumber") is None:
        raise SettlementVerificationUncertain(
            f"transaction {tx_hash} exists but is not yet mined into a block"
        )
    _check("TRANSACTION_EXISTS", True, f"transaction found, mined in block {tx.get('blockNumber')!r}")

    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except TransactionNotFound as exc:
        raise SettlementVerificationUncertain(
            f"transaction {tx_hash} has a blockNumber but no receipt yet — RPC node lag"
        ) from exc
    except Exception as exc:
        raise SettlementVerificationUncertain(
            f"could not reach RPC to fetch the receipt for {tx_hash}: {exc}"
        ) from exc

    receipt_status = receipt.get("status")
    _check(
        "RECEIPT_STATUS_SUCCESS", receipt_status == 1,
        f"receipt.status={receipt_status!r}, expected 1",
    )

    chain_id = w3.eth.chain_id
    _check(
        "CHAIN_ID_MATCHES_MAINNET", chain_id == expected_chain_id,
        f"chain_id={chain_id!r}, expected {expected_chain_id!r}",
    )

    tx_to = tx.get("to") or ""
    _check(
        "TRANSACTION_TARGETED_XSGD_CONTRACT",
        tx_to.strip().lower() == expected_asset.strip().lower(),
        f"transaction 'to'={tx_to!r}, expected the configured XSGD contract {expected_asset!r}",
    )

    contract = w3.eth.contract(address=expected_asset, abi=_ERC20_TRANSFER_EVENT_ABI)
    events = contract.events.Transfer().process_receipt(receipt)
    event_found = len(events) > 0
    _check(
        "XSGD_TRANSFER_EVENT_EXISTS", event_found,
        f"{len(events)} XSGD Transfer event(s) decoded from the receipt logs",
    )

    event_from = event_to = None
    event_value = None
    if event_found:
        event_from, event_to, event_value = events[0]["args"]["from"], events[0]["args"]["to"], events[0]["args"]["value"]

    _check(
        "EVENT_FROM_MATCHES_PAYER",
        event_found and (event_from or "").strip().lower() == expected_payer.strip().lower(),
        f"event.from={event_from!r}, expected payer {expected_payer!r}",
    )
    _check(
        "EVENT_TO_MATCHES_REGISTERED_RECIPIENT",
        event_found and (event_to or "").strip().lower() == expected_recipient.strip().lower(),
        f"event.to={event_to!r}, expected registered recipient {expected_recipient!r}",
    )
    _check(
        "SELF_TRANSFER_FROM_EQUALS_TO",
        event_found and (event_from or "").strip().lower() == (event_to or "").strip().lower(),
        f"event.from={event_from!r}, event.to={event_to!r} — this demo requires them to be the same address",
    )
    _check(
        "EVENT_VALUE_MATCHES_EXPECTED_AMOUNT",
        event_found and event_value == expected_amount_atomic,
        f"event.value={event_value!r}, expected {expected_amount_atomic!r} atomic units",
    )

    gas_used = receipt.get("gasUsed")
    effective_gas_price = receipt.get("effectiveGasPrice", tx.get("gasPrice"))
    gas_spent_avax = (
        (gas_used * effective_gas_price) / 10 ** 18
        if gas_used is not None and effective_gas_price is not None else None
    )

    return SettlementVerificationContext(
        checks=checks, tx_hash=tx_hash,
        gas_payer_address=tx.get("from"), gas_spent_avax=gas_spent_avax,
    )
