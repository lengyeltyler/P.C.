# PhilCore controlled Sepolia Beta P2 factory-stake recovery

Status: completed through independently reconciled P2A and P2F execution.

## Incident

The approved P2R UserOperation
`0x74e3ec0f673028e14c4c143562e4f5539957a6b518dae83b779707ad37f121ef`
was rejected synchronously by the configured Alchemy Sepolia bundler with RPC
code `-32502` and `entity stake/unstake delay too low`.

The bundler identified `PhilCore4337AccountFactory` at
`0xCcbdB547b70741D78d327B4584607C651ddF327A` as the entity needing a minimum
`0.1 ETH` EntryPoint stake and a minimum one-day unstake delay. The factory
writes its `isPhilSepoliaMintAccount` mapping while creating the
counterfactual account, but the deployed V1 factory has no method that can call
`EntryPoint.addStake` as the factory itself.

The executor persisted its one-shot attempt lock before submission and did not
retry. Read-only reconciliation found no bundler receipt, no bundler operation,
no deployed account code, nonce zero, and all three replay fields unused. Both
independent Sepolia providers agreed. The account's previously approved
`0.00484 ETH` prefund was unchanged.

## Narrow recovery route

The recovery preserves the existing account address, factory, ActionGate,
consumer, authorities, owner commitment, salt, and prefund:

1. `P2A` performs one ordinary zero-value call to the existing factory's exact
   `createAccount(owner, ownerCommitment, salt)` calldata. The permissionless
   call is paid by the disposable Sepolia funding EOA. It deploys the already
   prefunded smart account and sets the existing factory registration mapping.
2. After both providers confirm the exact account runtime and constructor
   bindings, the normal composed Noir plus physical iPhone authorization flow
   runs again with `accountDeployed: true`.
3. `P2F` submits one newly signed ERC-4337 v0.7 UserOperation with empty
   `initCode` and no `factory` or `factoryData` RPC fields. The factory is no
   longer an entity in UserOperation validation, so the rejected storage-access
   condition is absent.

`P2A` and `P2F` each require their own exact digest-specific owner approval,
durable execution-attempt lock, single submission, two-provider receipt/state
verification, and no automatic retry. P2F requires a fresh physical iPhone
approval because changing `initCode` changes the UserOperation hash.

## P2A execution and read-only reconciliation

The approved P2A transaction
`0x78770827598af3378b6ddea04c1131df2b3b7b42baf530163078c2a5fb6cf2ce`
was confirmed successfully in Sepolia block `11572932`. Both configured
providers agreed on the exact type-2 transaction fields, successful receipt,
block hash, `1,557,868` gas used, deployed account code, factory registration,
constructor/runtime bindings, EntryPoint nonce zero, EntryPoint deposit zero,
and the unchanged `0.00484 ETH` account prefund.

The original executor stopped after confirmation because its post-transaction
checker incorrectly expected a fixed account runtime hash. The account embeds
five constructor immutables, so its deployed runtime hash is instance-specific.
The corrected verifier masks only the compiler-declared immutable byte ranges,
compares every other runtime byte to the compiled artifact, and separately
checks all immutable getters and storage-bound authorities. The stopped receipt
and one-shot lock remain preserved; a dedicated read-only reconciler records the
confirmed result without signing, broadcasting, or retrying the transaction.

## P2F execution and final reconciliation

The first approved P2F submission was rejected by the bundler because its
verification-gas reservation efficiency was below the bundler's `0.4`
threshold. The executor stopped without retry. Read-only reconciliation through
the bundler and both providers proved that no operation or receipt existed,
nonce remained zero, balances were unchanged, all replay fields remained
unused, and no pass was issued.

The reviewed correction selected a P2F-only verification-gas limit of `150000`
without changing the call-gas, pre-verification-gas, fee, funding, factory-free,
single-submission, or no-retry constraints. Because that field changes the
signed UserOperation hash, the correction required a fresh proof and physical
iPhone ceremony.

The final approved P2F plan digest
`0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e`
submitted UserOperation
`0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670`
exactly once. Its bundle transaction
[`0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934`](https://sepolia.etherscan.io/tx/0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934)
confirmed successfully in block `11573471` with no additional funding.

Both providers independently agreed on account nonce `1`, all three consumed
replay fields, pass token `1` owned by the initial execution validator, token
balance `1`, and next token ID `2`. The receipt contained exactly one
EntryPoint UserOperation event, one composed-authorization-consumed event, and
one pass-issued event. The complete public sequence is recorded in
[P2 Evidence](./PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_EVIDENCE_2026-08-26.md).

## Security boundary

The Noir proof and iPhone P-256 approval are still verified locally against the
same mint authorization digest before Device Vault releases the exact execution
signature. Ethereum does not independently verify Noir or P-256. Sepolia
enforces the restricted smart-account execution signature, account nonce,
ActionGate, value and target restrictions, and on-chain replay consumption.

This recovery does not authorize mainnet use, meaningful assets, contract
replacement, a permissive/noncompliant bundler, automatic retries, or any
mutation beyond the separately approved P2A and P2F plans.
