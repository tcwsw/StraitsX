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
cp .env.example .env          # set POLICY_SECRET and AGENT_PRIVATE_KEY
./run.sh                      # policy :4020, merchants :4030

python -m agent.run "usb-c charger" --budget 80 --quantity 2      # happy path
python -m agent.run "usb-c charger" --budget 80 --attack          # hostile merchant
curl -s localhost:4020/audit | jq '.chain_ok, .message'
```

## Execution Agent: scripted vs OpenAI

`AGENT_MODE` (in `.env`, or exported in the shell — the shell wins) selects which chooser
`agent.run.build_basket_proposal()` calls for the multi-item basket flow (CLI `--basket` and
the dashboard). `python-dotenv` loads `.env` automatically before `AGENT_MODE`/`AUDIT_MODE`/
`OPENAI_MODEL`/`OPENAI_API_KEY` are read, in both `agent/run.py` and `dashboard/app.py`.

**Scripted (default, deterministic, no LLM call):**

```bash
pip install -r requirements.txt
cp .env.example .env
# .env: AGENT_MODE=scripted (or leave unset), POLICY_SECRET set, AGENT_PRIVATE_KEY set
./run.sh
python -m agent.run --basket
# or:
streamlit run dashboard/app.py
```

**OpenAI (`AGENT_MODE=openai`):**

```bash
pip install -r requirements.txt
cp .env.example .env
# .env: AGENT_MODE=openai, OPENAI_API_KEY=sk-..., OPENAI_MODEL=gpt-4o-mini (optional),
#       plus POLICY_SECRET and AGENT_PRIVATE_KEY as above
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

## StraitsX card path

The StraitsX reference gateway (`github.com/anishnar/straitsX-mcp-demo`) already implements
agent → x402 → single-use Visa card. Do not rebuild it. Run `npm run stack` and call its REST
surface from Python:

```python
httpx.post("http://127.0.0.1:4010/card", json={"amount": 12, "cardholder_name": "Team X"})
```

Route through it only after the policy engine has approved, and log the returned
`settlement_tx` into the ledger.

## Tests

No pytest — each module is a standalone runner with a colored PASS/FAIL table:

```bash
python -m compileall -q .
python -m tests.policy_matrix
python -m tests.authorize_boundary
python -m tests.basket_matrix
python -m tests.audit_matrix
python -m tests.config_loader
python -m tests.agent_mode_matrix     # mocks Runner.run_sync — makes no real OpenAI calls
```

