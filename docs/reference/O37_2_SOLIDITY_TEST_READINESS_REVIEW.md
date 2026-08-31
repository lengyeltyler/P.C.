# O.37.2 V2 Solidity Test Readiness Review

Status: `DETERMINISTIC_PUBLIC_FIXTURES_READY_SOLIDITY_NOT_STARTED`.

O.37.2 resolves the remaining public-test-input condition identified by O.37
and O.37.1. Future Solidity tests now have accepted deterministic validator,
recovery, and ERC-4337 v0.7 inputs without using production PhilCore
authority.

This review does not authorize or implement Solidity.

## Verified Baseline

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `569fe5671cc82640a464f37a0c34efe8c1159bc6`;
- tracked worktree at phase start: clean;
- upstream without fetching: `origin/main`, ahead `99`, behind `0`;
- V1 account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- V1 factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

O.20 through O.37.1 canonical evidence was reviewed. No V2 Solidity
implementation existed at entry. No local credential or live-network
configuration was accessed.

## O.37.1 WebAuthn Clarification

Preparing real synthetic WebAuthn assertions exposed one specification-level
fixture error: the earlier O.37.1 synthetic descriptors derived `rpIdHash`
with Keccak-256. WebAuthn requires SHA-256 of the RP-ID UTF-8 bytes.

O.37.2 corrects the O.37.1 public vectors and documentation before producing
signatures:

```text
rpIdHash = SHA-256(UTF8("philcore.test"))
```

The origin-policy hash remains the explicitly documented PhilCore Keccak
policy commitment. No descriptor field, ABI type, recovery threshold,
authority rule, canonical identity, or production material changes. The
corrected O.37.1 package remains deterministic and its full conformance suite
passes.

## What Future Solidity Must Verify

A future account implementation must independently verify:

- exact EntryPoint caller and ERC-4337 v0.7 UserOperation hash;
- exact account, chain, EntryPoint, sender, nonce lane, epochs, validity, and
  typed-action bindings;
- O.32 intent and authorized-intent hashes;
- O.33 authority domain and validator digest;
- validator envelope length, versions, authority kind, verifier kind,
  validator, key-ID commitment, epochs, low-s secp256k1 signature, and signer;
- O.37.1 complete descriptor commitments and configuration membership;
- exact 2-of-3 bitmap and canonical selected-factor ordering;
- WebAuthn RP-ID hash, flags, client-data type/challenge/origin policy,
  challenge/type indices, P-256 point, low-s signature, and descriptor
  generation;
- independent secp256k1 recovery signer, low-s signature, and descriptor
  generation;
- replay prevention, recovery timing, request identity, proposal binding, and
  terminal state transitions.

The contract must reproduce the checked-in public vectors exactly. It must
reject every checked-in mutation and equivalent malformed ABI encodings.

## What Runtime Must Verify

The Runtime remains responsible for the protected local security process:

- identity/session state;
- policy evaluation;
- explicit user approval and fresh user presence;
- STARK/STWO proof creation and local verification where required;
- proof, policy, approval, presence, application, and fund-lifecycle inputs
  to the Runtime authorization digest;
- purpose-bound authority request presentation;
- ensuring a production Device Vault signs only the exact recomputed digest.

The deterministic fixture generator performs none of those production
operations. Its synthetic Runtime digest inputs exercise hashing only.

## What Remains Local-Only

The following are test infrastructure and must never enter production state:

- deterministic scalar derivation labels and derived scalar values;
- fixture chain, account, EntryPoint, RP ID, origin, and key identifiers;
- fixture validator and recovery identities;
- synthetic WebAuthn credential IDs, counters, and assertions;
- wrong-signer and malformed-signature evidence;
- intentionally mutated UserOperations;
- `TEST_FIXTURE_ONLY` acceptance expectations.

Production code must not contain a fallback that accepts fixture
classification, fixture domains, deterministic labels, or test keys.

## ABI Compatibility

The public package provides standard-ABI values for:

- the frozen 320-byte validator envelope;
- O.37.1 complete factor descriptor;
- WebAuthn evidence version `2`;
- secp256k1 evidence version `2`;
- the outer recovery evidence envelope;
- action-specific calldata;
- ERC-4337 v0.7 packed gas words and UserOperation fields.

Local tests independently decode and re-encode each evidence class and require
byte-for-byte equality. JSON remains a container, not a cryptographic
encoding.

## Test Coverage Now Available

The accepted package supports:

- validator success, wrong signer, zero `r`, zero `s`, invalid `v`, high-s,
  and modified-digest tests;
- sender, nonce, calldata, fee, chain, EntryPoint, and authorization-hash
  UserOperation binding tests;
- signature-exclusion tests for the v0.7 UserOperation hash;
- primary-plus-hardware and primary-plus-recovery exact 2-of-3 success tests;
- invalid bitmap, duplicate factor, changed generation/policy, stale epoch,
  wrong domain/account/version, and expired-validity tests;
- ABI decoder/re-encoder and malformed-evidence tests.

## Remaining Requirements Before Solidity

A separately approved implementation phase must still:

1. re-verify the repository baseline and all frozen O.36.1/O.37.1 interfaces;
2. pin and apply the already selected Solidity `0.8.27`, OpenZeppelin `5.6.1`,
   Account Abstraction `0.7.0`, Hardhat, optimizer, viaIR, Cancun, and V1
   override settings;
3. implement the exact account and factory without changing the fixture
   boundary;
4. add adversarial WebAuthn parsing, P-256, secp256k1, gas, storage-layout,
   selector, custom-error, CREATE2, and lifecycle tests;
5. produce deterministic ABI, storage-layout, and bytecode review artifacts;
6. stop before deployment, funding, live credentials, production authority,
   RPC, or public mutation unless separately approved.

Any need to alter a frozen descriptor, evidence tuple, authority digest,
threshold, storage invariant, or capability requires a new architecture
review, not an implementation shortcut.

## Decision

The deterministic-public-fixture condition is complete. The O.37 recovery
descriptor conflict remains resolved by O.37.1, and its WebAuthn RP-ID
algorithm is now corrected. These facts make a future Solidity test phase
possible; they do not make Solidity implemented or approved.

## Stop Boundary

No Solidity contract was implemented. No bytecode was created. No deployment,
blockchain interaction, fund movement, production credential, production
signature, or UserOperation submission occurred. Public mutations are
exactly zero.

## O.37.3 Downstream Conflict

O.37.3 confirmed that the accepted package can test ordinary validator
authorization and validator-recovery threshold evidence, but it cannot yet
test the frozen recovery-configuration rotation authority. That action
requires the current validator plus exact 2-of-3 factors, while O.36.1 and
O.37.1 define only separate validator and recovery envelopes. No canonical
combined transport or accepted O.37.2 combined fixture exists.

O.37.3 stopped before Solidity or toolchain changes. See
[O.37.3 Solidity Implementation Conflict Review](./O37_3_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md).

## O.37.4 Versioned Fixture Resolution

O.37.4 preserves this O.37.2 package byte-for-byte and adds a separate
versioned authority-transport package. The new package supplies deterministic
test-only combined config-rotation authority, factor-rotation,
recovery-cancellation, malformed-envelope, ordering, commitment, bitmap, and
epoch vectors. It binds synthetic UserOperation hashes but deliberately
creates no new `PackedUserOperation`.

The canonical combined transport and remaining Solidity integration boundary
are defined in
[O.37.4 Authority Transport Specification](./O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md)
and
[O.37.4 ERC-4337 Integration Specification](./O37_4_ERC4337_INTEGRATION_SPECIFICATION.md).
