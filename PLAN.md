# ProcureGuard: 24h plan

## What the research changed

Three things worth knowing before anyone writes code.

**1. StraitsX already built the card half.** `github.com/anishnar/straitsX-mcp-demo` is the
Phase-3 reference stack: an MCP + REST gateway that takes `{amount, cardholder_name}`, does the
whole x402 exchange against the live StraitsX sandbox, and hands back a single-use virtual Visa.
Live endpoints are `https://card.straitsx.ai/{sandbox,production}/sse`. Rebuilding any of that is
24 hours you do not have. Run their gateway on `:4010` and call it over REST from Python.

**2. The card API is itself an x402 server.** Unpaid `POST /cardapi/issue_card` returns HTTP 402
with the challenge in a `PAYMENT-REQUIRED` header; you sign EIP-3009 and retry with
`PAYMENT-SIGNATURE`. So x402 is already in your flow whether or not you build merchant-side x402.

**3. XSGD supports EIP-3009 natively.** The Avalanche mainnet contract is a Circle FiatToken
proxy (impl `0x7C0f…FcCb`) exposing `transferWithAuthorization`, `receiveWithAuthorization`,
`permit` and `authorizationState`. That means real x402 `exact` scheme works with XSGD with no
wrapper, and you can self-facilitate: your merchant server verifies the signature and submits the
transfer itself. Fuji XSGD is `0xd769…c2A5`, mainnet `0xb2F8…096E`, 6 decimals, EIP-712 domain
`{name: "XSGD", version: "2"}`.

## The pitch, sharpened

The deck's own closing line is the opening you should take: a scoped credential limits what a
compromised agent can spend, *it does not make the agent trustworthy, and that part is still
open*. StraitsX said out loud that this is the most interesting thing anyone could work on this
weekend. Build exactly that.

> The agent decides what to buy. ProcureGuard decides what may be paid. They do not share a
> process, a secret, or an input surface.

Every other team will demo an agent buying something. Yours should demo an agent being wrong and
the money not moving.

## Scope

**In.** Mandate → typed decision → deterministic policy engine → single-use spend token →
x402/EIP-3009 payment in XSGD → hash-chained audit → prompt-injection defence, demonstrated live.

**Out.** Real merchant checkout automation (StraitsX explicitly does not support it: merchant ToS
plus one-view card material). Any LLM in the control path. A pretty UI before the rails work.

## Team split, 3-4 people

| Owner | Track | Done when |
|---|---|---|
| A | Rails: fund the wallet, run the StraitsX gateway, issue one real card, get a settlement tx | A card renders and the tx is on Snowtrace |
| B | Policy engine + spend tokens + audit chain (scaffold is written, extend it) | `--attack` blocks, `chain_ok: true` |
| C | Execution agent + merchant mocks + the injected page | Agent picks correctly and gets blocked correctly |
| D | Dashboard, demo script, slides, rehearsal | Run end to end three times without touching a terminal |

If you are three, D is shared and starts at T-6h regardless of code state.

## Timeline

- **T+0 → T+2** Wallet generated, address sent to organizers for funding and whitelisting. This
  is the only hard external dependency, so it goes first. Scaffold running locally.
- **T+2 → T+8** Policy engine hardened. Merchant mocks final. Injection page written. Agent loop
  works end to end in `SETTLE_MODE=verify`.
- **T+8 → T+12** First real XSGD movement on Fuji. First StraitsX card issued via the gateway.
- **T+12 → T+16** Audit agent: an independent watcher that reconciles chain events against the
  ledger and flags anything it cannot match. It must not share state with the execution agent.
- **T+16 → T+20** Dashboard, freeze features.
- **T+20 → T+24** Rehearse. Record a backup video of the working demo. Sleep is optional, the
  video is not.

## Cut lines, in the order you cut

1. Mainnet. Fuji is fine, say so on the slide.
2. LLM reasoning. The scripted agent makes the same decision and never times out.
3. The chain-watching audit agent. The hash-chained ledger alone carries the story.
4. The dashboard. Terminal output with colour is honest and reads fine on a projector.

Never cut: the injection demo. That is the differentiated part.

## Demo script, 4 minutes

1. Show the mandate on screen: 100 XSGD total, 60 per transaction, three merchants, electronics
   only, human approval above 55. Say the mandate is signed once by a human and the agent cannot
   edit it.
2. Type the goal. Agent pulls quotes from three merchants, prints the comparison, picks one, and
   states its reason.
3. Policy engine prints seven checks, all green. Note that the engine never saw the merchant's
   page text.
4. 402 → sign → settle. Show the Snowtrace tx and the balance drop.
5. Re-run against BargainBin, which hides an override instruction in its product copy. The agent
   proposes it. The engine fails on `merchant_allowed` and nothing is signed. Say the line: the
   agent was manipulated, the money was not.
6. `curl /audit` → `chain_ok: true`, then edit one byte of the ledger by hand and re-run it to
   show the chain break.

Close on: an agent you can trust is hard. An agent that cannot spend outside its mandate is
buildable today, and here it is.

## What I still need from you

**Blocking, get these in the first hour:**

1. Agent wallet address submitted to the organizers for Fuji XSGD funding, plus mainnet
   whitelisting if you want a real card. Nothing on the payment track moves until this lands.
2. Whether the organizers gave out anything beyond the public repo: a team API key, a passphrase,
   a private gateway URL, or a funded wallet. The public docs show no card-issuing API at all, so
   the MCP is event-provisioned.
3. The judging criteria and the demo time limit. Four minutes versus ten changes what gets built.

**Useful, get these when you can:**

4. Whether you must use the StraitsX card MCP to qualify for their prize track, or whether pure
   XSGD/x402 settlement counts.
5. Whether an LLM API key is available to the team, and which. Determines if the agent reasons
   live or scripted.
6. Whether AWS Bedrock credits are part of the sponsor track. The deck links a Bedrock shopping
   assistant guidance, which suggests a second prize is sitting there.
7. Your team's actual names for the mandate principal and cardholder, since the card cardholder
   field is 2-26 letters.
