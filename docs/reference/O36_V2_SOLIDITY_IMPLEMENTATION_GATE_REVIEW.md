# O.36 V2 Solidity Account And Factory Implementation Gate Review

Status: `STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY`.

O.36 was authorized as the first local Solidity implementation phase for the
V2 account and factory. Repository review stopped implementation before any
contract source or deployable bytecode was created because the accepted
O.31--O.35 architecture still contains unresolved entry gates that the
implementation phase is not allowed to redesign.

Public mutations are zero.

## Verified Baseline

The phase began from:

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `7fed6ee96805fd8adf0453ab0067fc23f6b2450d`;
- tracked worktree: clean;
- upstream relationship without fetching: `origin/main`, ahead 91, behind 0.

The frozen V1 source SHA-256 bindings remained:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

The O.32 intent/authorization modules, O.33 validator engine, O.34 account
core, and O.35 factory/lifecycle design were inspected. No post-O.35 artifact
was found that closes the gates below.

## Blocking Architecture Gates

### 1. Recovery-factor verifier gate

O.31 requires a bounded chain-side P-256/WebAuthn verifier or an explicitly
reviewed independent hardware secp256k1 signer before Solidity starts. It
also directs implementation to stop rather than substitute a same-device
software key or remove the hardware role.

The repository contains an offchain WebAuthn verifier, but no accepted
Solidity P-256/WebAuthn implementation, fixed audited library decision,
chain-native primitive decision, bounded parser/gas evidence, or reviewed
hardware-signer replacement. O.35 continues to classify production factor
verifiers as future work.

Implementing the requested exact 2-of-3 recovery state machine without this
verifier would either create an unusable recovery path or silently replace
the independent hardware domain. Both outcomes violate O.31.

### 2. Production authority-verifier gate

O.33 deliberately defines only an evidence-reference boundary and a
fixture-only verifier. It creates and accepts no signature bytes. O.33 says a
future production verifier must enforce canonical 65-byte low-s secp256k1
authority over the exact O.32 digest.

No later reviewed contract-side authority-envelope ABI, canonical decoder,
or production verifier exists. O.35 explicitly leaves production validator
verifiers as future work. Inventing that boundary in O.36 would redesign
authorization while implementing it.

### 3. Identity-binding commitment gate

O.35 adds `identityBindingCommitment` to the constructor and CREATE2 input,
but expressly defers its exact cryptographic definition to a reviewed hashing
phase. The O.35 security analysis repeats that the exact format is unresolved.

Treating an arbitrary nonzero `bytes32` as sufficient would make deterministic
addresses depend on an undefined identity-continuity claim. Omitting the field
would violate the canonical 20-field initialization tuple.

### 4. Recovery-cancellation representation mismatch

O.31 permits cancellation by the current validator plus one independent
non-primary recovery factor. O.32/O.33 encode only the stricter exact
two-recovery-factor bitmaps. O.33 requires this mismatch to be resolved in a
separately reviewed cryptographic-version phase before Solidity implements
the O.31 option.

O.36 cannot widen the O.32/O.33 authority format or silently delete the O.31
liveness path.

### 5. ABI and verifier-dependency freeze

O.31 marks its Solidity signatures as pseudocode and requires a later phase to
freeze the exact ABI, selectors, errors, events, EIP-712 vectors, verifier
dependencies, and storage layout before deployable bytecode. O.35 defines the
ordered CREATE2 inputs but not their ABI or independent address vectors.

Those decisions are security architecture, not minor Solidity
normalization. They must be reviewed before account or factory code is added.

## Fail-Closed Decision

No V2 account, V2 factory, mock substitute, partial recovery implementation,
placeholder verifier, signature fixture, PackedUserOperation, CREATE2 vector,
or deployable V2 bytecode was created.

The following work remains blocked:

- ERC-4337 V2 account validation;
- typed asset execution;
- recovery request, cancellation, and completion;
- validator and recovery rotation;
- deterministic V2 factory creation;
- local fund-lifecycle simulation.

This stop does not alter O.29--O.35. It preserves the stricter O.32/O.33
recovery behavior and does not choose new authority.

## Required Inputs For A Fresh Implementation Phase

A later, separately approved implementation phase may begin after repository
evidence records all of the following:

1. an accepted fixed recovery-factor verifier design, dependency/source
   binding, malformed-input tests, and bounded gas behavior;
2. a frozen production execution-validator envelope and Solidity verifier
   with O.32 vector parity;
3. an exact privacy-reviewed identity-binding commitment definition and
   independent vectors;
4. a reviewed resolution of the O.31 versus O.32/O.33 cancellation model;
5. exact V2 ABI, selector, error, event, storage-layout, and CREATE2 encoding
   decisions;
6. exact pinned dependency versions for the implementation artifact.

Closing these gates requires architecture review. It grants no deployment,
funding, signing, UserOperation, or public-mutation authority.

## Stop Boundary

No public mutation occurred. No contract was deployed, no account was created
onchain, no funds moved, no credential was enrolled, no signature was
produced, and no UserOperation was created.
