# Fintech owner worksheet

Your three deliverables, and where each one now lives.

| Deliverable | Artifact | State |
|---|---|---|
| Exact policy specification | `tests/policy_matrix.py` | 17/17 green, executable |
| Verified rails, as commands not links | `tools/probe_straitsx.py` | written, **you must run it** |
| The trust boundary explanation | section 4 below | drafted, learn it |

---

## 1. The architecture change you should insist on

I built this wrong the first time and fixed it, and the reason matters to you specifically,
because the hole was in exactly the claim you own.

**The hole.** The execution agent held `AGENT_PRIVATE_KEY` and did its own signing. The policy
engine issued a SpendIntent, the agent redeemed it, then signed. A judge asks: "what stops a
compromised agent from just signing a transfer of the whole balance to an attacker address?"
Nothing did. The policy engine was advisory, and the agent was financially authoritative in
practice even though the slide said otherwise.

**The fix.** The private key now lives only in the policy engine process. The agent forwards the
raw 402 challenge to `POST /authorize` and receives back a `PAYMENT-SIGNATURE` header value or a
refusal. It cannot sign anything itself. The engine re-derives the amount and destination from
the challenge rather than trusting the agent's summary of them.

The demo proof is one line: the agent process runs with no `AGENT_PRIVATE_KEY` in its
environment and the payment still completes. Show that.

Your plan says the post-hook is financially authoritative. This is what makes that literally
true rather than a naming convention. If the developer implements the post-hook as middleware
inside the agent's own FastAPI app, the claim quietly becomes false. Separate process, separate
secret. Hold that line.

---

## 2. The policy specification

Run `python -m tests.policy_matrix`. Seventeen cases, all green. Hand the developer this file
rather than a document, because a document cannot fail.

### Mandate rules

| Rule | Field | Demo value | Failing check |
|---|---|---|---|
| Mandate must be live | `expires_at` | +12h | `mandate_valid` |
| Per-transaction ceiling | `per_txn_max` | 15.00 XSGD | `per_txn_limit` |
| Cumulative budget | `budget_total` | 30.00 XSGD (the real wallet) | `budget_remaining` |
| Merchant allowlist, by id | `allowed_merchants` | 3 trusted ids | `merchant_allowed` |
| Merchant trusted in our registry | `MERCHANT_REGISTRY` | bargainbin = false | `merchant_allowed` |
| Category allowlist | `allowed_categories` | electronics, accessories | `category_allowed` |
| Prohibited goods by keyword | `denied_keywords` | gift card, voucher, prepaid, top-up | `no_denied_items` |
| Currency | `currency` | XSGD | `currency` |
| Human approval threshold | `require_human_above` | 12.00 XSGD | (sets `needs_human`) |

Two details worth defending out loud. Merchant reputation comes from our registry, never from
the merchant's own claim about itself, so a hostile merchant cannot promote itself. Denied
keywords are matched against structured product fields only (`title`, `category`, `sku`), never
against free text, so the check cannot be poisoned by a merchant stuffing words into a
description.

### SpendIntent rules

One approval, one payment. Bound four ways and single-use.

| # | Attack | Result |
|---|---|---|
| T1 | Redeem once for the exact quoted amount | accepted |
| T2 | Replay the same intent | rejected, already used |
| T3 | 402 quotes 20.00 against an intent approved for 8.50 | rejected, exceeds cap |
| T4 | Intent minted for techstore, presented for bargainbin | rejected, merchant bound |
| T5 | Tampered HMAC | rejected, bad signature |
| T6 | Presented after the 180s TTL | rejected, expired |
| T7 | Third 12.00 purchase against the 30.00 wallet | rejected, budget exhausted |

---

## 3. The rails: what I verified, and what only you can

### Verified from the contract and the sponsor repo

| Fact | Value | How it was checked |
|---|---|---|
| XSGD mainnet | `0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E` | given in your brief |
| Proxy type | `FiatTokenProxy` (Circle) | Routescan `getsourcecode` |
| Implementation | `0x7C0fe33B1ACb50De0C15B70b8A5f40A294B2FcCb` | Routescan `getsourcecode` |
| EIP-3009 support | `transferWithAuthorization` (both overloads), `receiveWithAuthorization`, `authorizationState`, `permit` | implementation ABI |
| Contract version | v2.2 (`initializeV2_2` present) | implementation ABI |
| XSGD Fuji | `0xd769410dC8772695A7F55a304d2125320A65c2A5` | StraitsX repo profile |
| Decimals | 6 | 5.00 SGD quoted as `5000000` in the repo's captured challenge |
| EIP-712 domain | `{name: "XSGD", version: "2", chainId, verifyingContract}` | captured 402 challenge |
| Networks | `eip155:43113` sandbox, `eip155:43114` production | repo profiles |
| Card MCP | `https://card.straitsx.ai/{sandbox,production}/sse`, SSE transport | repo profiles |
| Card tools | `get_card_{sandbox,prod}` → `{wallet_address, cardholder_name, amount_sgd}` | repo README |
| Card API | `POST .../cardapi/issue_card`, 402 unpaid, `PAYMENT-REQUIRED` header, retry with `PAYMENT-SIGNATURE` | repo README |
| Card caps | 5–30 SGD per card, server-side, plus wallet whitelist on production | repo README |
| Gas | StraitsX relayer pays settlement gas | repo profiles |

The single most useful consequence: **XSGD needs no wrapper.** The x402 `exact` EVM scheme works
against it directly, and you can self-facilitate, meaning your own merchant server verifies the
signature and submits the transfer. No dependency on a third-party facilitator for the demo.

### You must run this

```bash
python -m tools.probe_straitsx --env sandbox --address 0xYourAgentAddress
```

It checks four things and prints a green/red table: the MCP SSE handshake and tool schemas, an
**unpaid** 402 probe against the card API with the decoded challenge, chain id plus XSGD
`name()` / `version()` / `decimals()` / your balance, and whether the EIP-712 domain the 402
quotes actually matches what the contract reports. Paste that output into the team channel. That
is your "tested commands, not documentation links" deliverable, discharged.

One safety rule, from the sponsor's own repo: **never send a paid POST to the live card API from
a script or test.** An unfunded paid POST still burns StraitsX relayer gas at settlement. Unpaid
402 probes only.

### The minimum x402 sequence, for the developer

```
1. POST  {merchant}/checkout            {sku, quantity}
   <-  402  + {"accepts": [{scheme, network, amount, asset, payTo, chainId, extra}]}

2. POST  policy:4020/authorize          {spend_intent, merchant_id, challenge}
   engine re-derives amount = int(accepts[0].amount) / 1e6
   engine redeems the intent (single-use, merchant-bound, amount-bound, TTL-bound)
   engine signs EIP-712 TransferWithAuthorization under the domain from the challenge
   <-  {ok: true, payment_header: "<base64>"}

3. POST  {merchant}/checkout            same body + header PAYMENT-SIGNATURE: <base64>
   merchant recovers the signer, checks to/value/network against what it quoted
   merchant submits transferWithAuthorization, or verifies only in dev
   <-  200  + {receipt: {tx_hash}}  + header PAYMENT-RESPONSE
```

The signed struct, exactly:

```
TransferWithAuthorization {
  address from; address to; uint256 value;
  uint256 validAfter; uint256 validBefore; bytes32 nonce;
}
domain: { name: "XSGD", version: "2", chainId: 43113|43114, verifyingContract: <XSGD> }
```

---

## 4. The trust boundary explanation

Your "done" is being able to answer these five without hedging.

**Who authorizes money?**
The policy engine, by minting a SpendIntent and then producing the signature itself. The model
produces a proposal. A proposal is not an authorization. The model's total influence over money
is a typed `Decision` object with nine fields, and the engine re-checks every one of them
against the mandate before anything is signed.

**What gets signed?**
An EIP-712 typed struct, `TransferWithAuthorization`, under the XSGD domain. That signature is
the payment instruction. It authorizes exactly one transfer, of exactly one amount, to exactly
one address, inside a time window, once. Nobody signs a session, a limit, or a permission. Each
signature is one payment.

**What can be replayed?**
Nothing that matters, and there are two independent reasons, which is the answer worth giving.
Cryptographically, the EIP-3009 nonce is a random 32-byte value that the token contract records
in `authorizationState`; resubmitting the same signature reverts on-chain. At the control plane,
the SpendIntent is single-use in the policy engine and is consumed before signing. Break one and
the other still holds.

**What cannot be tampered with?**
The destination and the amount are inside the signed struct, so a compromised agent cannot
re-point or inflate a signature it has been handed. It cannot mint a new SpendIntent because it
does not hold `POLICY_SECRET`. It cannot sign at all because it does not hold the private key.
And it cannot smuggle instructions into the control path, because the policy engine receives a
typed object and never a string of merchant prose.

**Where do StraitsX, x402 and Avalanche sit?**
Avalanche is settlement and the replay ledger. x402 is the negotiation protocol, an HTTP 402
carrying the challenge one way and the signature the other. StraitsX is the issuer on both
sides: of XSGD as the regulated Singapore-dollar stablecoin the agent holds, and of the
single-use card for merchants that are not x402-native. StraitsX also relays gas. Say plainly
that the card path covers the internet as it exists and the x402 path covers the internet as it
is becoming, and that ProcureGuard is indifferent to which rail a purchase takes because the
control plane sits above both.

**On prompt injection, if asked.** The defence is projection, not detection. Merchant responses
are projected onto a nine-field schema at the pre-hook and everything else is discarded before
the model or the engine sees it. The signal detector exists so the dashboard can report that an
attack occurred; it is telemetry. If an attacker paraphrases past the detector, nothing changes,
because we never treat merchant text as instructions in the first place. Anyone who inverts that
ordering has built a filter, and filters lose to paraphrase.

---

## 4b. Decisions taken, and what they added

| Decision | Choice | What exists now |
|---|---|---|
| Rails | both, card after policy approval | `pg/card_adapter.py`, `POST /authorize-card` |
| Human approval | yes, for specific purchases above threshold | `GET/POST /approvals`, agent blocks and waits |
| Chain | Fuji to build, mainnet for the final run | `./run.sh fuji` / `./run.sh mainnet` |

### The card rail

Same gate, different instrument. The policy decision happens first and is identical; only the
payment instrument changes. That is the sentence to say when a judge asks why you have two
rails: ProcureGuard is indifferent to the rail because the control plane sits above both.

Three properties worth demonstrating:

- **Card material never reaches the agent.** `/authorize-card` returns `card_opaque_id` and
  `settlement_tx`. The one-time view URL is held in the policy engine and served only from
  `GET /cards/{id}/view`, which the agent never calls. Verified: the agent-facing response
  contains no `iframe_url` and no `card_html`.
- **The view is genuinely one-time.** Second call returns "already been viewed once".
- **The SpendIntent is shared across rails.** Replaying an intent that was already spent on
  the x402 rail fails on the card rail too, because there is one intent ledger, not one per
  instrument. That is a question a sharp judge asks and most teams have not thought about.

StraitsX caps cards at 5–30 SGD server-side. We check that on our side first, so a violation
reads as `card amount 48.00 outside the issuer range 5-30 SGD` rather than an HTTP error from
someone else's server in the middle of your demo. Cardholder name is 2–26 letters and spaces,
also checked locally.

To run it live: `npm run stack` in the straitsX-mcp-demo checkout, then `CARD_MODE=live`.
Default is `simulate`, which exercises the whole path including the caps without touching the
sponsor's endpoint.

### Human approval

Escalation parks the **decision**, not a blank cheque. When the human approves, the engine mints
an intent for that exact purchase, still merchant-bound, amount-bound and single-use. Approval
does not raise the mandate and does not grant a session. Say that explicitly, because "human in
the loop" usually means someone clicking yes on a permission that then persists.

The agent blocks and polls. It has no endpoint that lets it resolve its own escalation.

```
python -m agent.run "usb-c hub" --sku TS-HUB-7P --quantity 1     # 13.50, above the 12.00 threshold
curl -s localhost:4020/approvals                                  # the PM's UI state
curl -X POST localhost:4020/approvals/<id>/approve                # or /reject
```

### Chain switch

```
./run.sh fuji       # eip155:43113, SETTLE_MODE=verify, CARD_MODE=simulate
./run.sh mainnet    # eip155:43114, SETTLE_MODE=onchain, CARD_MODE=live
```

Profiles hold network config, `.env` holds secrets and is loaded last so it wins. Nothing about
the switch touches application code, which is what makes it safe to do live.


---

## 4c. Treasury: you are spending real money now

30 XSGD on Avalanche mainnet, confirmed on Snowtrace. Two consequences that are easy to miss.

**30 is exactly one maximum-size card.** StraitsX caps a single card at 30 SGD, so your entire
treasury is one card at the ceiling, or several small ones. Design the demo for small ones.

**Card issuance is a real x402 payment out of that wallet.** Every card you mint while testing
spends real XSGD. There is no undo and no faucet.

### Allocation

| Purpose | Amount | Mode |
|---|---|---|
| All rehearsal, every run before the judged one | 0.00 | `./run.sh fuji`, verify + simulate |
| One live card, to prove the rail works | 5.00 | `CARD_MODE=live`, once |
| The judged run | 5.00–13.50 | live |
| Reserve for a second judged attempt | ~10.00 | untouched unless needed |

The demo mandate is now 30.00 total, 15.00 per transaction, 12.00 human threshold, against a
catalogue where the happy path is 8.50, the escalation is 13.50 and the blocked item is 3.00.
Those numbers are honest: the mandate is the wallet.

### Gas

You need no AVAX for the card path. StraitsX relays and pays settlement gas, which is why the
card rail is the right place to spend real money on stage.

You *would* need AVAX for `SETTLE_MODE=onchain` against your own merchant server, because then
your relayer submits `transferWithAuthorization` itself. Unless someone has mainnet AVAX
already, keep your own merchants on `SETTLE_MODE=verify` and let the card issuance be the real
money movement. `verify` still recovers the EIP-712 signer and validates every field, so the
cryptography on stage is real either way. Be precise about that distinction if a judge asks
rather than glossing it.

### One more thing to ask StraitsX

Ask for Fuji XSGD as well, even though you have mainnet. It costs them nothing and it lets you
rehearse against the real sandbox card API instead of local mocks. Rehearsing against the thing
you will demo is worth more than the mainnet balance is.

---

## 5. Send this to StraitsX now

"The sponsor" means StraitsX: Parag Pandit's team, the people who gave that deck and who are at
the event. They hold the Fuji XSGD faucet and the mainnet whitelist. Generate your wallet with
`python -m tools.newkey`, which writes the key to a chmod-600 `.env` and prints only the address.

> Hi, Team ProcureGuard. Our agent wallet address is `0x...`. Could you fund it with Fuji XSGD
> for the sandbox track, and whitelist it for production if we get that far? Three quick
> questions so we don't guess: (1) is there anything beyond the public `anishnar/straitsX-mcp-demo`
> repo we should have, such as a team key or a private gateway URL? (2) do we need to use the
> card MCP to qualify for the StraitsX track, or does pure XSGD x402 settlement count? (3) any
> rate limits on the sandbox card API we should design around?

---

## 6. Still open

1. **Wallet not yet funded.** Everything else is built and provable in simulate/verify mode.
   This is the only remaining external dependency, and it is on you.
2. **Whether the card MCP is required for the StraitsX prize track.** Ask when you hand over the
   address. If pure XSGD x402 counts, the card rail becomes a bonus rather than a requirement,
   which changes nothing you build but does change what you lead with in the pitch.
3. **Sandbox rate limits.** Worth asking so the PM does not schedule six rehearsals that trip a
   throttle an hour before judging.

---

## 7. FINTECH review note: settlement wording, and when an intent is actually "settled"

Fixed in the dashboard and CLI, not in the protocol: a `receipt.receipt.tx_hash` value is only
ever a real Avalanche transaction hash when `receipt.receipt.settled_onchain` is `true`. Under
the default `SETTLE_MODE=verify`, the merchant recovers the EIP-712 signer and validates every
field of the EIP-3009 authorization — that check is real cryptography — but nothing is ever
submitted on-chain, so the same field is now labelled a **verification reference**, and the UI
says "cryptographically verified, not submitted on-chain" instead of implying a settled
transaction. `AuditEnvelope.settlement_status` follows the same rule: it is never `"settled"`
unless `settled_onchain` is `true`; under `verify` mode it is reported as `"pending"`.

This is a wording fix only. **The payment protocol itself has not changed**: `reserve_intent()`
still marks a SpendIntent `committed` the moment a valid EIP-3009 signature is produced and
countersigned, which is before (and independent of) whether that authorization is ever actually
submitted to Avalanche. That is worth a FINTECH decision, not a developer one: should a
SpendIntent's ledger state distinguish "signed/committed" (funds are contractually authorized,
in a `verify`-only environment nothing has left the wallet) from "settled/spent" (the
`transferWithAuthorization` transaction has actually been mined and the on-chain balance moved)?
Today those two are conflated under `SETTLE_MODE=verify`, which is fine for local rehearsal but
would be misleading in front of a real ledger reconciliation. Flag this for FINTECH sign-off
before `SETTLE_MODE=onchain` is treated as anything other than the demo path to a real card
issuance (see §4c, Gas).

