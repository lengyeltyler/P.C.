# O.34 V2 Account Core Implementation

Status: `LOCAL_ACCOUNT_ENFORCEMENT_PROTOTYPE_COMPLETE`.

O.37.1 compatibility: EntryPoint caller checks, typed actions, nonce lanes,
request ID as authorized-intent hash, epoch invalidation, recovery freezes,
and terminal transitions remain unchanged. Future Solidity must replace this
phase's historical recovery commitment fixture with O.37.1
descriptor/configuration version `2`.

O.34 is the first local V2 account enforcement implementation. It consumes
the O.32 intent and digest primitives and the O.33 validator/authorization
decision. It does not create authority. It checks whether one exact,
already-authorized action fits the account's immutable configuration,
current nonce sequence, recovery state, and intentionally limited action
surface.

This phase is TypeScript-only. It creates no Solidity, bytecode, factory,
deployed account, transaction, signature, credential, proof, or
UserOperation. It performs no RPC call and no public mutation.

## Verified Baseline

The phase started at repository HEAD
`9192dd5213de02da0c0020bdf8d867a48879db9d` on
`codex/device-identity-v1`, with a clean tracked worktree. O.20 through O.33,
the O.32 cryptographic modules and vectors, the O.33 validator engine, the
existing ERC-4337 V1 components, and the frozen V1 account/factory were
reviewed.

The known historical O.22 current-source hash mismatch remains fail-closed.
It is unrelated to this local V2 implementation and supplies no deployment
or mutation authority.

O.31 describes cancellation by the current validator plus one independent
non-primary recovery factor. O.32 and O.33 currently encode only exact
two-role recovery bitmaps for cancellation. O.34 preserves that stricter
implemented rule and does not widen authority. The representation difference
still requires a separate cryptographic-version decision before deployment.

## Responsibility Boundary

```text
exact O.32 intent and Runtime authorization
  -> O.33 authority verification
  -> O.34 immutable, nonce, recovery, and lifecycle enforcement
  -> typed local effect draft
  -> no external call
```

The account core:

- normalizes and cross-checks immutable and mutable account state;
- requires the caller binding to equal the immutable EntryPoint;
- binds the external keyed nonce and UserOperation hash reference to the
  authorization package;
- delegates cryptographic and Runtime authorization verification to O.33;
- derives an action draft only from the verified intent payload;
- applies replay, nonce, validator, and recovery transitions to a local state
  value;
- reports zero execution, signatures, funds moved, UserOperations, and public
  mutations.

The account core does not:

- create an intent, proof, approval, presence event, or authority;
- infer a target, recipient, token, amount, purpose, or calldata;
- hold or invoke Device Vault material;
- call EntryPoint, a token, a confirmation target, or any other contract;
- serialize an ERC-4337 UserOperation;
- act as an administrator.

## Immutable State

Creation fixes:

1. chain ID;
2. EntryPoint address;
3. account address;
4. owner commitment;
5. factory binding;
6. O.32 account-version ID;
7. O.32 security-model ID;
8. confirmation target;
9. recovery delay of `172800` seconds;
10. recovery expiry of `604800` seconds.

The normalized state also fixes these negative capabilities:

- non-upgradeable;
- no administrator;
- no upgrade key;
- no arbitrary execution;
- no delegatecall;
- no modules or plugins;
- no session keys;
- no paymasters.

Any non-canonical version, security model, recovery timing, or
validator/immutable binding fails state construction.

## Mutable State And Layout

The prototype represents the security-bearing O.31 fields in this logical
order:

1. active validator state, epoch, status, recovery state, and execution lock;
2. validator key-ID binding;
3. validator commitment;
4. security-configuration hash;
5. primary-device factor commitment;
6. hardware-security-key commitment;
7. recovery-factor commitment;
8. recovery epoch and lifecycle;
9. pending recovery request ID;
10. pending validator and key-ID binding;
11. pending proposed validator epoch;
12. source epochs and request timing;
13. recovery authorization evidence commitment;
14. explicit nonce snapshots for lanes `0`, `1`, and `2`.

The validator commitment is recomputed from the active validator and key-ID
binding. The recovery-configuration hash is recomputed from the exact ordered
2-of-3 role commitments and must equal O.33 validator state.

This TypeScript object is a local logical model, not a Solidity
storage-layout artifact. Pending recovery-configuration rotation remains
unimplemented and fail-closed in O.34; it will require the remaining O.31
fields and a separately reviewed phase.

## ERC-4337 Validation Model

O.34 models the structure of `validateUserOperation` without creating a
UserOperation or calling EntryPoint:

1. reconstruct and validate account state;
2. require the supplied caller to equal immutable EntryPoint;
3. reject an active execution lock;
4. reject arbitrary target/calldata, delegatecall, module, session-key, or
   paymaster fields;
5. decompose the supplied ERC-4337-style keyed nonce;
6. require an implemented lane and the exact current sequence;
7. require the intent's lane and sequence to match the external envelope;
8. require the external bytes32 UserOperation hash binding to match the
   package binding;
9. derive one typed draft from the intent;
10. apply the O.28 fund-lifecycle gate for value-moving actions;
11. call O.33 with the current validator state;
12. require O.33's accepted nonce and state-transition class to match;
13. bind the result to the exact normalized state;
14. return a non-executable, process-local validation context.

The bytes32 UserOperation hash value is a compatibility binding only. No
UserOperation object, calldata, signature, or submission artifact exists.

## Nonce And Epoch Model

The nonce composition is unchanged:

```text
nonce = (uint256(uint192 key) << 64) | uint64(sequence)
```

| Lane | Purpose | Active recovery |
| --- | --- | --- |
| `0` | ordinary typed action | frozen |
| `1` | validator maintenance | frozen |
| `2` | recovery maintenance | exact recovery transition only |

O.34 holds explicit local sequence snapshots for the three fixed lanes. It
rejects stale sequences, future gaps, unsupported keys, intent/envelope
differences, and replay after local consumption. This models EntryPoint-owned
sequence state; it does not claim to replace EntryPoint state onchain.

An issued validation context is tracked by object identity in process, bound
to the exact normalized account state, and consumable once. Serialization,
copying, replay, or applying it to changed state fails. It is not a durable or
reusable authority artifact.

Every accepted action remains bound to current validator and recovery epochs
through O.32/O.33. Normal validator rotation increments only validator epoch.
Recovery completion increments validator and recovery epochs exactly once.
Cancellation changes neither epoch.

## Recovery State Machine

The account audit lifecycle is:

```text
NORMAL
  -> RECOVERY_ACTIVE
  -> RECOVERY_COMPLETED
  or RECOVERY_CANCELLED
```

`RECOVERY_ACTIVE` is paired with O.33's operational
`recovery_active` state and one exact pending request. The pending request
stores only public commitments and exact proposed state. It freezes lanes
`0` and `1`.

Request authority is exact 2-of-3 across:

1. primary-device recovery credential;
2. external hardware security key;
3. independent recovery factor.

A single role, duplicate/extra roles, wrong configuration, or stale epoch
fails. Completion is local and permissionless only after the fixed delay,
before expiry, for the exact request ID and unchanged source epochs. It
installs only the stored validator, increments both epochs, clears pending
state, and moves no value. Cancellation requires O.33 recovery authority for
the exact request, clears pending state, changes no epoch, and moves no value.

Recovery completion or cancellation returns O.33 operational state to
`normal`; the O.34 terminal lifecycle value remains as local audit state.
A later recovery request may deliberately begin a new lifecycle.

## Typed Execution Boundary

O.34 can produce only these non-executable drafts:

| Action | Fixed boundary |
| --- | --- |
| confirmation | immutable target, signed digest, zero value, fixed selector mode |
| native transfer | exact recipient and amount, empty calldata |
| ERC-20 transfer | exact token/recipient/amount, fixed `transfer` selector |
| ERC-721 transfer | exact token/recipient/token ID/data hash, fixed safe-transfer selector |
| ERC-1155 transfer | exact token/recipient/token ID/amount/data hash, fixed single safe-transfer selector |

Validator rotation and recovery request/cancellation are local state
transition drafts, not external execution capabilities.

EntryPoint deposit withdrawal is intentionally not implemented in O.34 even
though O.30 reserves a typed action for it. Arbitrary calls, token approvals,
batch transfer, delegatecall, fallback execution, modules, plugins, session
keys, paymasters, and unrestricted withdrawal have no accepted draft.

## Fund Lifecycle Gate

Every value-moving draft requires:

- the exact O.32 lifecycle preimage matching the intent digest;
- account and asset/token-ID coherence;
- a nonzero residual recipient;
- an authorized amount within the maximum holding bound;
- expected final balance no greater than maximum stranded value;
- an explicitly verified release path;
- bound residual handling;
- mandatory post-state verification;
- a separate future release authorization.

O.34 does not verify a real deployed release selector or simulation because
there is no V2 contract or funded account. The flags and digest are local
enforcement scaffolding. They do not satisfy O.28's deployment/funding gate.
No account may be funded until a later implementation proves the full route
locally and on a fork.

## Phase Boundary

O.34 completes only local account-core enforcement. Solidity implementation,
canonical decoding, production signature verification, recovery-config
rotation, EntryPoint deposit release, receivers, factory design, storage
layout, deployment, funding, and live operation remain future phases.
