# Payment contract (FINTECH-owned)

This is the contract the payment rails are held to. If code and this document disagree, this
document wins and the code is wrong.

## Rail 1 — x402 / EIP-3009 (XSGD on Avalanche)

- Scheme: `exact`. Transfer method: `eip3009` (`transferWithAuthorization`) only — no other
  transfer method is accepted, regardless of what a merchant's 402 challenge claims.
- Every field that determines where money goes (`payTo`, `asset`, `amount`, `network`,
  `chainId`, EIP-712 domain) is re-derived from the live challenge and re-checked against both
  the merchant registry (`fintech/policy_config.json`) and the `SpendIntent` the policy engine
  minted earlier. A mismatch on any single field refuses the payment; nothing is signed.
- Amount matching is exact, not a ceiling. A challenge that quotes more OR less than the
  `SpendIntent`'s bound amount is refused.
- Networks and asset contracts are pinned per deployment profile in
  `fintech/policy_config.json` — see `networks.fuji` / `networks.mainnet`. Nothing outside
  that allowlist is ever paid on.

## Rail 2 — StraitsX single-use virtual card

- Same policy gate as rail 1, checked first; only the instrument differs.
- Card material (PAN, CVV, one-time view URL) never reaches the execution agent or the model's
  context. The agent receives an opaque card id and a settlement reference only.
- Issuer-side amount range and cardholder name constraints are enforced twice: once by the
  issuer, once locally before the request is even sent (`fintech/policy_config.json ->
  card_rail`).

## Settlement modes

- `verify` (default): recovers and validates the EIP-712 signature; no gas spent. Use while
  building and for CI.
- `onchain`: submits the transaction for real. Requires a gas-funded `RELAYER_PRIVATE_KEY`.

## Outstanding items

- Mainnet merchant settlement wallets: FINTECH_TODO_REQUIRED (see
  `fintech/policy_config.json -> merchant_wallets.*.production_wallet`).
- StraitsX production wallet whitelisting status: FINTECH_TODO_REQUIRED.
- Treasury / gas-funding source for the relayer key on mainnet: FINTECH_TODO_REQUIRED.
