# ProcureGuard demo script (4 minutes)

Owner: PM. This is the run-of-show for the live demo. Edit freely — the developer's job is to
make the dashboard match this script, not the other way around.

1. Open the dashboard. Point at the Top bar: Wallet 30.00 XSGD, Delegated budget 30.00, Max
   per merchant 20.00, Available delegated budget, and the Agent status control. Note the
   mainnet/testnet badge — this demo is a genuine on-chain **self-transfer**: the payer wallet
   and the recipient wallet are the same address, so no XSGD ever changes hands, only gas is
   spent. Say the mandate is signed once by a human and the agent cannot edit it.
2. Left column: type the request (`1 x usb-c charger`). The agent resolves the item and shows
   the Searching → Comparing → Selected breadcrumb.
3. Centre column: the live 4-merchant comparison — TechStore 19.20, GadgetHub 19.40, BargainBin
   20.50 (over the 20.00 per-merchant cap), CheapDealsStore 15.50 (not on the mandate's
   allowlist, so unauthorized regardless of price). TechStore wins.
4. Right column: the policy engine's verdict, ALLOWED, with all twelve checks green. The
   model's reasoning is shown only as an advisory caption below the verdict — never the
   verdict itself.
5. Payment section: click "Run payment". Walk the step tracker live — HTTP 402 received,
   recipient verified, EIP-3009 signed, submitted, on-chain receipt verified, consumed. Open
   the Snowtrace link.
6. Final Metrics: Wallet XSGD before/after are identical (unchanged due to self-transfer; only
   AVAX gas was spent) — kept strictly separate from the Policy metrics (Delegated 30.00,
   Consumed 19.20, Available 10.80), which is the mandate's own accounting, not a movement of
   real money.
7. Scroll to Attack Demo. Run it against BargainBin, which hides an override instruction in its
   product copy relabelling a $25 gift card as the requested charger. `merchant_allowed` passes,
   but `product_requested`, `category_allowed` and `per_intent_limit` all fail — nothing is
   signed, no SpendIntent is created. Say the line: the agent was manipulated, the money was
   not.
8. `curl /audit` → `chain_ok: true`, then edit one byte of the ledger by hand and re-run it to
   show the chain break.

Close on: an agent you can trust is hard. An agent that cannot spend outside its mandate is
buildable today, and here it is.

## Open items

- Presenter / speaking order: PM_TODO_REQUIRED
- Backup video recorded and linked here: PM_TODO_REQUIRED

