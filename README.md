# ProcureGuard

A procurement agent that can spend money, and a control plane that decides whether it may.

The agent searches, compares and decides. A separate deterministic policy engine holds the
mandate, and it is the only thing in the system that can mint a SpendIntent. Nothing gets
signed without one. Every step lands in a hash-chained audit log anchored by the on-chain
settlement tx.

Rails: XSGD on Avalanche via x402 (EIP-3009 `transferWithAuthorization`), plus a single-use
StraitsX virtual card for merchants that are not x402-native.

## Run it

```bash
pip install -r requirements.txt
cp .env.policy.example .env.policy   # set POLICY_SECRET and AGENT_PRIVATE_KEY (pg/policy_server.py only)
cp .env.app.example .env.app         # OPENAI_API_KEY etc. (agent/run.py, dashboard/app.py only)
./run.sh                             # policy :4020, merchants :4030

python -m agent.run "usb-c charger" --budget 80 --quantity 2      # happy path
python -m agent.run "usb-c charger" --budget 80 --attack          # hostile merchant
curl -s localhost:4020/audit | jq '.chain_ok, .message'
```

`.env.policy` and `.env.app` are two separate, gitignored files, loaded by two separate
processes, on purpose: `pg/policy_server.py` loads `.env.policy` (holding
`AGENT_PRIVATE_KEY`/`POLICY_SECRET`/`RELAYER_PRIVATE_KEY`) and is the only process ever
allowed to hold those. `agent/run.py` and `dashboard/app.py` load `.env.app` via
`config/process_env.isolate_execution_agent_env()`, which REFUSES TO START if any of those
three secrets is present in `.env.app` or already exported in the shell — see
[FINTECH.md](FINTECH.md) for the isolation contract in full.

## Execution Agent: scripted vs OpenAI

`AGENT_MODE` (in `.env.app`, or exported in the shell — the shell wins) selects which
chooser `agent.run.build_basket_proposal()` calls for the multi-item basket flow (CLI
`--basket` and the dashboard). `config/process_env.isolate_execution_agent_env()` loads
`.env.app` automatically before `AGENT_MODE`/`AUDIT_MODE`/`OPENAI_MODEL`/`OPENAI_API_KEY`
are read, in both `agent/run.py` and `dashboard/app.py`.

**Scripted (default, deterministic, no LLM call):**

```bash
pip install -r requirements.txt
cp .env.policy.example .env.policy   # POLICY_SECRET, AGENT_PRIVATE_KEY
cp .env.app.example .env.app         # AGENT_MODE=scripted (or leave unset)
./run.sh
python -m agent.run --basket
# or:
streamlit run dashboard/app.py
```

**OpenAI (`AGENT_MODE=openai`):**

```bash
pip install -r requirements.txt
cp .env.policy.example .env.policy   # POLICY_SECRET, AGENT_PRIVATE_KEY
cp .env.app.example .env.app
# .env.app: AGENT_MODE=openai, OPENAI_API_KEY=sk-..., OPENAI_MODEL=gpt-4o-mini (optional)
./run.sh
python -m agent.run --basket
# or:
streamlit run dashboard/app.py
```

Without `OPENAI_API_KEY`, `AGENT_MODE=openai` fails clearly (before any policy/payment call)
instead of silently falling back to scripted. The dashboard shows "Execution Agent: OpenAI /
`<model>`" or "Execution Agent: scripted" next to the proposal, and a failed model call never
reaches `/evaluate-basket`. `AUDIT_MODE` (`scripted` default, or `openai`) works the same way
for the independent Audit Agent — it shares no session, prompt or code path with the
Execution Agent.

## Layout

| Path | What it is |
|---|---|
| `pg/models.py` | Mandate, Quote, Decision, PolicyVerdict, SpendIntent |
| `pg/policy_engine.py` | Deterministic checks. No LLM. Mints HMAC SpendIntents |
| `pg/policy_server.py` | The engine as its own process on :4020 |
| `pg/x402_client.py` | 402 challenge → signed EIP-3009 authorization |
| `pg/ledger.py` | Hash-chained append-only audit log + `verify()` |
| `merchants/server.py` | 3 honest merchants + 1 hostile one, real x402 checkout |
| `merchants/facilitator.py` | Verify the EIP-712 signature; settle on Avalanche |
| `agent/run.py` | Scripted execution agent, basket demo, `build_basket_proposal()` router |
| `agent/execution_agent.py` | OpenAI Agents SDK execution agent (`AGENT_MODE=openai`) |
| `audit/audit_agent.py` | Independent Audit Agent, deterministic + optional `AUDIT_MODE=openai` |
| `dashboard/app.py` | Streamlit dashboard, thin client over the FastAPI services |

## The two gates

1. **Before search results are trusted.** Merchant responses are mapped into a typed `Quote`.
   Descriptions, store notices and page HTML are dropped. Attacker text never becomes a
   control input, only a display string.
2. **Before signing.** The policy engine re-checks the live 402 quote (`payTo`, amount,
   merchant) against the SpendIntent it issued earlier. Token is single-use, amount-bound,
   merchant-bound and expires in 180s.

The execution agent does not hold `POLICY_SECRET`. A fully compromised agent still cannot
authorise a payment.

## Settlement modes

- `SETTLE_MODE=verify` (default) — the merchant recovers the EIP-712 signer and validates
  every field. Real cryptography, no gas. Use this while building. Because nothing is
  submitted on-chain, `receipt.receipt.settled_onchain` is `false` and the CLI/dashboard
  label `tx_hash` a **verification reference**, not an Avalanche transaction hash — see the
  FINTECH review note in [FINTECH.md](FINTECH.md#7-fintech-review-note-settlement-wording-and-when-an-intent-is-actually-settled).
- `SETTLE_MODE=onchain` — submits `transferWithAuthorization` on Avalanche with
  `RELAYER_PRIVATE_KEY`. Fuji for testing, mainnet XSGD
  `0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E` for the real thing. Only then is
  `settled_onchain` `true` and the value a real transaction hash.

## Live self-transfer demonstration

`./run.sh live-self-transfer` runs `tools/live_self_transfer.py` — a real, Avalanche
**mainnet** demonstration where the payer wallet and TechStore's registered
`payment_recipient` are deliberately the SAME address. No XSGD value can change hands in
that case (only gas is spent); every check and display in that path says so explicitly.
It is INTERACTIVE ONLY: it refuses to run in CI or non-interactively, requires
`ALLOW_SELF_TRANSFER_DEMO=true` and `SETTLE_MODE=onchain` in `.env.policy`, requires the
registry recipient to genuinely equal the payer address, and requires typing an exact
confirmation phrase before anything is signed. The script itself never signs or holds a
private key beyond briefly deriving the payer's public address — every signature is still
produced exclusively inside `pg/policy_server.py`, over HTTP, gated by
`pg/live_guard.py`'s nine-point live-signing precondition check.

The committed `data/merchant_registry.json` ships with every `payment_recipient` left
`null` on purpose (see `config/loader.py`'s ownership-boundary convention) — it is never
edited to add a real wallet. To make techstore's recipient resolve to your own payer
address for this demo, copy `data/merchant_registry.local.json.example` to
`data/merchant_registry.local.json` (gitignored), fill in the address derived from your
`AGENT_PRIVATE_KEY`, and set `MERCHANT_REGISTRY_PATH=data/merchant_registry.local.json` in
`.env.policy` (see `.env.policy.example`).

## StraitsX card path

The StraitsX reference gateway (`github.com/anishnar/straitsX-mcp-demo`) already implements
agent → x402 → single-use Visa card. Do not rebuild it. Run `npm run stack` and call its REST
surface from Python:

```python
httpx.post("http://127.0.0.1:4010/card", json={"amount": 12, "cardholder_name": "Team X"})
```

Route through it only after the policy engine has approved, and log the returned
`settlement_tx` into the ledger.

The dashboard only renders the "Issue restricted StraitsX card" control when
`CARD_FEATURE_ENABLED=true` is set in `.env.app` (default off). This is a UI-visibility
toggle only — it never moves money and never itself gates a policy/payment decision;
`CARD_MODE` (in `.env.policy`, simulate/real) still governs whether an issued card is
simulated or a genuine StraitsX card, independent of whether the dashboard shows the control.

## `GET /system/info`

Both `pg/policy_server.py` and `merchants/server.py` expose a `GET /system/info` endpoint
returning non-secret operational facts only (no keys, no wallet balances): the merchants
process reports `{"network": ...}`; the policy process reports `{"settle_mode",
"card_mode", "self_transfer_demo_allowed", "mainnet_network"}`. This lets the dashboard show
an accurate mainnet/self-transfer badge and Snowtrace link base URL without ever holding
`SETTLE_MODE`/`CARD_MODE`/`ALLOW_SELF_TRANSFER_DEMO`/`X402_NETWORK` itself — those remain
each backend process's own configuration.

## Tests

No pytest — each module is a standalone runner with a colored PASS/FAIL table:

```bash
python -m compileall -q .
python -m tests.policy_matrix
python -m tests.authorize_boundary
python -m tests.basket_matrix
python -m tests.audit_matrix
python -m tests.config_loader
python -m tests.env_isolation
python -m tests.self_transfer_matrix   # mocked only — never touches real mainnet
python -m tests.agent_mode_matrix     # mocks Runner.run_sync — makes no real OpenAI calls
python -m tests.offer_matrix
python -m tests.merchant_registry_matrix
python -m tests.straitsx_mcp_matrix   # mocked MCP-over-SSE handshake — no real StraitsX calls
python -m tests.final_matrix          # the final one-screen demo fixture, end to end (40 cases)
python -m tests.export_source_matrix  # tools/export_source.py never leaks secrets/artifacts
```

## Source-only export

`tools/export_source.py` copies the repository into a clean, source-only directory —
excluding `.git/`, `.venv`/`venv/`, `__pycache__`/`*.pyc`, `.env`/`.env.app`/`.env.policy`/
`*.env.local`, the real runtime `audit/ledger.jsonl`, and the local
`data/merchant_registry.local.json` override. `.example` files and the shipped
`data/merchant_registry.json` seed data are kept.

```bash
python -m tools.export_source --dry-run     # list what would be copied, copies nothing
python -m tools.export_source [DEST_DIR]    # default: ./dist/procureguard-source
```

