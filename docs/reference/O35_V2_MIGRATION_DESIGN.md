# O.35 V2 Account Migration Design

Status: `LOCAL_IDENTITY_ADAPTER_MIGRATION_DESIGN_ONLY`.

PhilCore migration is explicit identity and chain-adapter version migration.
It is not a proxy upgrade, factory-admin action, asset seizure, or identity
replacement.

## Migration Model

```text
review new account and factory version
  -> prove identity continuity
  -> derive and activate new account
  -> inventory old account holdings
  -> authorize each exact movement under old account rules
  -> reconcile old and new state
  -> update canonical adapter selection
  -> retire old adapter from new ordinary use
```

The source account remains authoritative for its assets until it executes an
exact typed action. The destination account gains no claim over the source.
The factory has no role after creating the destination.

## Identity Continuity

Migration preserves the Phil identity through:

- the same canonical identity record;
- the same owner commitment;
- the same reviewed identity-binding commitment definition and value;
- explicit old/new chain-adapter records under that identity;
- an audit link between version manifests and account addresses.

It does not preserve:

- account address;
- factory address;
- account-version ID;
- creation/runtime bytecode;
- account nonce state;
- account-specific validator/recovery epochs;
- balances or EntryPoint deposits without explicit movement.

Identity continuity is not proof of control over an old account. The old
account's current validator/recovery state remains authoritative for old
assets.

## V1 To V2 Boundary

V1 source, factory, deployment artifacts, and evidence remain frozen.

The current V1 local-proof-gated account has no general typed asset release
surface. Therefore:

- V1 cannot execute a V2 migration intent;
- V2 cannot claim, redirect, withdraw, or sweep V1 assets;
- deploying V2 under the same Phil identity does not recover V1 funds;
- the O.27-prefunded V1 counterfactual address is not a migration source;
- no factory, recovery factor, validator, or identity-continuity claim
  creates a V1 release path.

V1 to V2 migration in O.35 means migration of the canonical chain-adapter
selection and identity continuity only. It does not mean migration of the V1
native balance.

This limitation must remain visible before any V2 deployment or funding
proposal.

## Future V2-To-New-Version Migration

A future recovery-capable source can migrate only through its fixed typed
capabilities:

- native transfer;
- ERC-20 transfer;
- ERC-721 safe transfer;
- ERC-1155 safe transfer;
- exact EntryPoint deposit withdrawal when that separately implemented
  capability has passed review.

Each action must use a migration-specific purpose and bind:

- source and destination accounts;
- chain and EntryPoint;
- source validator and recovery epochs;
- exact asset/token and token ID;
- exact amount;
- receiver data hash where applicable;
- source nonce lane and sequence;
- maximum fee and validity;
- O.28 lifecycle/release information;
- fresh Runtime proof, policy, approval, and presence;
- fresh validator authority.

There is no generic `migrate`, `sweepAll`, delegatecall, approval grant, token
operator, or factory-mediated transfer.

## Migration Manifest

Before movement, a deterministic manifest inventories:

- source/destination identity commitments and adapter versions;
- factory, account, code, EntryPoint, and chain bindings;
- source and destination lifecycle/verification state;
- source native balance;
- source EntryPoint deposit;
- every known ERC-20 balance;
- every known ERC-721 token ID;
- every known ERC-1155 token ID and amount;
- unsupported or unknown assets;
- pending operations and recovery/configuration state;
- intended residual recipient and maximum approved dust;
- per-asset route and expected final state.

The inventory is a read-only snapshot, not authority. Unknown holdings cannot
be silently treated as zero. Tokens with unsafe, nonstandard, fee-on-transfer,
rebasing, callback, or inaccessible enumeration behavior require separate
analysis.

## Fresh Authorization Rule

Migration authority is never reusable.

For every public source-account action:

1. refresh source/destination state;
2. create one exact migration intent;
3. run the complete Runtime authorization path;
4. show one exact human-readable approval;
5. require fresh local user presence;
6. produce one exact Device Vault validator signature;
7. construct and submit one exact UserOperation;
8. verify receipt, balances, nonce, events, and lifecycle state;
9. discard the consumed authority.

A successful native transfer does not authorize a token transfer. A token
approval is not used as a shortcut. Batch migration is absent from V2.0.

Recovery authority alone cannot move assets. If recovery is needed, it first
restores validator authority. Asset movement then uses entirely fresh ordinary
authorization under the new epochs.

## Destination Rules

Before any source movement, the destination must:

- be independently derived and deployed from the accepted version;
- be `ACTIVE_UNFUNDED` or have only explicitly reconciled test balances;
- have exact validator/recovery state and no pending recovery;
- prove the release route for every asset it may receive;
- accept the asset through a fixed receive surface;
- have no factory/deployer/admin control;
- have a recorded maximum loss and residual plan.

The destination does not need to share the source's validator address or
recovery configuration forever. Its initial bindings are independently
authorized creation inputs under the same Phil identity.

## Adapter Switch

The canonical chain-adapter record changes only after:

- destination acceptance;
- all approved movements have successful receipts;
- old and new native/deposit/token/NFT state is reconciled;
- remaining source balances are zero or explicitly bounded;
- no migration action is pending or ambiguous;
- destination ordinary authorization is locally verified;
- the user sees the residual and retirement consequences.

Changing the adapter record is a local identity/runtime lifecycle operation.
It does not move chain assets or disable the old contract.

Rollback of adapter selection may select the old account for new activity
only if its current security state is still accepted. It cannot reverse
already completed asset movements.

## Retirement

Retirement is non-destructive:

- old code remains deployed;
- old receipts and events remain canonical;
- old recovery and validator rules remain the only authority over residuals;
- the factory gains no control;
- the Phil identity remains active;
- no `selfdestruct`, proxy disable, global pause, or administrator revocation
  exists.

The preferred retirement state is zero native balance, zero EntryPoint
deposit, and zero known token/NFT holdings. Nonzero residuals require exact
inventory, maximum-loss acknowledgement, reason, intended disposition, and
continued monitoring.

Retirement cannot be claimed while an asset movement has an ambiguous
receipt, while a recovery is active, or while a known release is incomplete.

## Failure Cases

Migration stops without adapter change when:

- source or destination identity binding differs;
- version/factory/code verification fails;
- destination is not fully activated;
- source or destination recovery state is unexpected;
- authorization is stale, expired, replayed, or bound to another asset;
- a receipt is ambiguous or reverted;
- balance deltas do not match;
- a token behaves outside its reviewed typed handler;
- an unknown balance or deposit cannot be reconciled;
- the release path or final-state expectation fails.

Failure does not authorize a replacement transaction, broader amount, generic
call, factory intervention, administrator sweep, or alternate destination.

## Fund-Safety Consequences

The migration design preserves O.28:

- new account funding waits for complete lifecycle and release proof;
- migration into the new account is itself funding and must satisfy the same
  gate;
- operation and residual release approvals remain separate;
- maximum possible loss is shown before movement;
- destination and source final balances are verified;
- the factory is never treated as recovery or release infrastructure.

## O.35 Boundary

O.35 produces no migration intent, approval, presence event, proof, signature,
UserOperation, transaction, adapter-record mutation, asset movement, or
public mutation.
