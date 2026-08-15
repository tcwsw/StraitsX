# ProcureGuard demo script (4 minutes)

Owner: PM. This is the run-of-show for the live demo. Edit freely — the developer's job is to
make the CLI match this script, not the other way around.

1. Show the mandate on screen: 30 XSGD total, 15 per transaction, three merchants, electronics
   and accessories only, human approval above 12. Say the mandate is signed once by a human and
   the agent cannot edit it.
2. Type the goal. The agent pulls quotes from three merchants, prints the comparison, picks one,
   and states its reason.
3. The policy engine prints its checks, all green. Note that the engine never saw the merchant's
   page text — only the typed `Decision`.
4. 402 → sign → settle. Show the Snowtrace tx and the balance drop.
5. Re-run against BargainBin, which hides an override instruction in its product copy. The agent
   proposes it. The engine fails on `merchant_allowed` and nothing is signed. Say the line: the
   agent was manipulated, the money was not.
6. `curl /audit` → `chain_ok: true`, then edit one byte of the ledger by hand and re-run it to
   show the chain break.

Close on: an agent you can trust is hard. An agent that cannot spend outside its mandate is
buildable today, and here it is.

## Open items

- Presenter / speaking order: PM_TODO_REQUIRED
- Backup video recorded and linked here: PM_TODO_REQUIRED
