# O.27 Account 2 Direct Prefunding

Status: `COMPLETE`.

O.27 is the narrowly bounded direct-prefunding phase for the already-derived
Ethereum Sepolia counterfactual PhilCore account. It permits at most one public
mutation after a separate exact approval: one empty-calldata EIP-1559 native
ETH transfer from disposable Account 2 to the counterfactual account.

## Pre-Approval Boundary

The proposal generator:

* refreshes the complete O.26.1 Alchemy bundler, gas, fee, and prefund evidence;
* verifies the canonical identity record and both disposable-wallet key/address
  bindings without exposing key material;
* verifies Sepolia chain ID `11155111`, canonical EntryPoint v0.7, the O.23R
  target receipt and runtime, and the O.24 factory receipt, runtime, and
  immutable getters;
* independently reproduces the CREATE2 account address locally and through the
  deployed factory;
* requires the account to remain code-free with zero EntryPoint nonce and
  deposit;
* requires Account 1 to remain at nonce `3` and Account 2 to remain unused at
  nonce `0`;
* records a short-lived exact transaction proposal with no approval, signature,
  raw transaction, or public mutation.

The machine-readable proposal is:

* `config/ethereum-sepolia/O27_ACCOUNT2_DIRECT_PREFUND_PROPOSAL.json`

It is evidence, not reusable authority. An explicit yes/no approval must name
the exact proposal digest. Any approval-bound state or envelope change requires
a new proposal and approval.

## One-Shot Mutation Guard

Only the dedicated execution command can load Account 2 private material. It
requires a clean repository, the exact external approval digest, a current
proposal, and fresh state checks immediately before signing and broadcasting.
It recovers the signer, decodes every signed field, precomputes the transaction
hash, and exposes exactly one `eth_sendRawTransaction` attempt through a
one-shot client.

There is no automatic retry, replacement, speed-up, cancellation, fallback
provider loop, alternate nonce, or second transaction. An ambiguous transport
result is reconciled through the precomputed hash without rebroadcast.

Account 1 cannot sign or broadcast. The transaction contains no contract
calldata and does not call the factory, EntryPoint, target, Runtime, Device
Vault, or bundler.

## Stranded-Funds Warning

ETH sent to the counterfactual address can become permanently stranded if the
account is never successfully deployed or cannot execute an approved recovery
path. The current restricted account has no generic withdrawal function.
Residual ETH may fund later permitted UserOperations, but no recovery is
assumed or authorized in O.27.

## Stop Boundary

O.27 stops after the one approved transfer receipt and post-transfer
verification. It does not deploy the account, create an EntryPoint deposit,
generate a proof or Runtime authorization, request user presence, access the
Device Vault, construct a submission-ready UserOperation, contact a bundler for
submission, use a paymaster, move tokens, or begin any later phase.

After a successful transfer, sanitized final evidence is written to:

* `config/ethereum-sepolia/O27_ACCOUNT2_DIRECT_PREFUND_RECEIPT.json`

That receipt file is not created before the approved public mutation succeeds.

## Confirmed Transfer

The exact approved Account 2 transfer succeeded on Ethereum Sepolia:

* transaction:
  `0x37d191d70cf45cc6a4eaa83c9518a980a6d9a575e211ea70796e28143e51431d`;
* block: `11370545`;
* value: `5124486704000000` wei (`0.005124486704 ETH`);
* gas used: `21000`;
* effective gas price: `1105936800` wei;
* exact transaction fee: `23224672800000` wei;
* exact Account 2 debit: `5147711376800000` wei.

Account 1 remained unchanged. Account 2 advanced from nonce `0` to `1` and
ended with `87428401148173299` wei. The counterfactual account ended with the
exact approved `5124486704000000` wei balance while remaining undeployed and
code-free with EntryPoint nonce and deposit both zero.

The target and factory code and configuration bindings remained unchanged.
Exactly one public mutation occurred. No retry, replacement, second
transaction, factory call, account deployment, proof, Runtime authorization,
user-presence event, Device Vault signature, UserOperation submission, bundler
submission, paymaster action, or token movement occurred.

O.28 subsequently proved that the live V1 factory/account has no secure release
route and classified this funded counterfactual address
`PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY`. O.27 completion is historical
funding evidence and must not be interpreted as account-deployment readiness.
