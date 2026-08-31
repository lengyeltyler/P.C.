# O.37.9 V2 Minimal Account Compression Review

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION_ONLY`.

O.37.9 resolves the two O.37.8 architecture blockers without retaining an
account, interface, compiler configuration, ABI artifact, storage artifact,
or bytecode. It creates no factory, deployment path, signature,
UserOperation, RPC call, funding action, or public mutation.

## Baseline

The phase started at
`73eecd93e98c4b9c954e034aaae5fe15473b7ce0` on
`codex/device-identity-v1` with a clean tracked worktree. O.20 through O.37.8
were reviewed. The preserved V1 source hashes remain:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

O.37.4 authority transport, the O.37.6 security boundary, and the deployed
shape of the O.37.7 stateless verifier are unchanged.

## Version Decision

The compressed account is a future, separately implemented version:

```text
label: philcore-v2-minimal-account-v2
id:    0xe3809f55cf56b419ecaebf3d2a2e0a43278b5d9a0b4714c063933a87ba2085d4
```

The future version-specific factory is:

```text
label: philcore-v2-minimal-factory-v2
id:    0x66e130d6512db6801362a672a59d58b9b6c16bb2ba76172808d6b5c21814d671
```

Re-versioning is mandatory because O.37.9 reduces the account ABI, derives
previously stored values, consolidates settlement functions, and changes
bytecode. The O.37.6 V1 profile and its version IDs remain historical and are
not silently redefined. Identity, owner commitment, security-model ID,
authority transport, recovery threshold, and verifier version do not change.

## Current Size Evidence

The smallest O.37.8 candidate measured:

| Artifact | Bytes | Maximum | Required reduction |
| --- | ---: | ---: | ---: |
| Runtime | `19454` | `15360` | `4094` |
| Creation | `21755` | `18432` | `3323` |

The candidate was below EIP-170 but failed the stricter O.37.6 gates.

Read-only source-map analysis of O.37.8's nearby `19591`-byte manual-decoder
candidate was normalized by its measured `137`-byte delta to model the
`19454`-byte best candidate:

| Family | Modeled bytes |
| --- | ---: |
| compiler ABI dispatch, decoding, and canonical shape handling | `12510` |
| validation, EntryPoint, nonce, fee, validity, and verifier request logic | `4487` |
| typed execution and recovery lifecycle | `2115` |
| hash and commitment helpers | `288` |
| directly attributed dependency code | `1` |
| Solidity metadata | `53` |
| **Total** | **`19454`** |

The attribution is forensic planning evidence, not a replacement for a future
compiler measurement. With viaIR and inlining, revert paths, event encoders,
and imported helpers are charged to their calling functions. The transient
candidate exposed 24 custom errors and 11 events; inventing standalone byte
counts for them would be misleading.

## Selected Compression

### One authorization pass

`validateUserOp` is the only authority, intent-hash, nonce-lane, fee, validity,
epoch, freeze, and verifier check. Typed action functions remain callable only
by the immutable canonical EntryPoint.

The action functions do not repeat the complete authorization hash or common
header checks. This is safe because canonical EntryPoint v0.7 executes the
exact `userOp.callData` only after successful validation of that same
UserOperation. They still enforce action-local state-transition invariants,
recipient and amount rules, exact pending request IDs, timing, and the
execution lock.

Direct callers fail. Changed calldata changes `userOpHash` and the authorized
intent and therefore fails validation. EntryPoint continues to own replay
protection.

### Reduced public surface

Individual immutable, mutable, constant, and hashing getters are replaced by
four aggregate security views. Separate completion and expiry functions are
replaced by deterministic settlement functions: before the delay they revert,
from the delay until expiry they complete, and at or after expiry they expire.

### Derived values

The account validates but does not store values that are exact functions of
other authoritative state:

- identity-binding commitment;
- active validator commitment;
- active recovery-configuration hash;
- proposed validator commitment;
- proposed recovery-configuration hash;
- executable and expiry timestamps.

This does not move any check to Runtime. Every derived value is recomputed
onchain from immutable or current account state.

### Compact diagnostics and evidence

Errors use a small fixed category set with bounded numeric reason codes.
Action and authority changes use two commitment-oriented event shapes instead
of action-specific duplicated events. No private evidence enters logs.

## Capabilities

The future compressed account supports only:

- ERC-4337 v0.7 validation;
- confirmation to one immutable target;
- native ETH transfer;
- EntryPoint deposit withdrawal as native-ETH residual release;
- validator rotation;
- exact-2-of-3 validator recovery request and cancellation;
- validator-plus-exact-2-of-3 recovery-configuration request;
- exact-2-of-3 recovery-configuration cancellation;
- permissionless deterministic settlement;
- native ETH receive and reverting fallback.

Action values remain `1`, `2`, `6`, `7`, `8`, `9`, `10`, and `11`.
EntryPoint deposit withdrawal is retained because ERC-4337 refunds can remain
in the account's EntryPoint deposit; removing its typed release path could
strand native ETH.

ERC20, ERC721, ERC1155, token receivers, adapters, batching, arbitrary calls,
modules, plugins, sessions, paymasters, aggregators, proxies, and upgrades are
absent.

## Planned Budget

The size model allocates `4960` bytes of gross runtime reduction and `320`
bytes of factory-binding lookup overhead, for a planned net reduction of
`4640` bytes:

```text
projected runtime:  14814 bytes
runtime reserve:      546 bytes
projected creation: 16507 bytes
creation reserve:    1925 bytes
```

These are planning targets, not acceptance evidence. The next separately
approved implementation phase must compile once from the frozen design,
measure both artifacts, run fixtures and opcode checks, and stop without
retaining Solidity if either budget is exceeded.

## Rejected Reductions

O.37.9 rejects:

- removing recovery checks, epochs, delays, expiry, or exact threshold;
- moving authority or replay checks to Runtime;
- removing EntryPoint deposit release;
- manual fixed-word decoding, which increased O.37.8 runtime by `137` bytes;
- generic execute or arbitrary target/data;
- delegatecall libraries, proxies, modules, or registries;
- mutable or caller-selected verifiers;
- changing O.37.7 to absorb account-state or execution logic;
- removing canonical O.37.4 authority encoding.

## Stop Boundary

No Solidity account, account interface, factory, build configuration,
bytecode, deployment artifact, CREATE2 vector, RPC call, blockchain
interaction, funding, credential, signature, UserOperation, or push is
created by O.37.9.
