# O.36.1 V2 Security Gate Resolution

Status: `COMPLETE_LOCAL_INTERFACE_FREEZE`.

O.37.1 correction: the role, threshold, verifier, validator, identity,
cancellation, timing, and no-value conclusions remain accepted. The
O.36.1 factor/configuration version `1` and factor evidence envelopes are
superseded by complete O.37.1 descriptor/configuration and evidence version
`2`. See
[O.37.1 Implementation Readiness Review](../reference/O37_1_IMPLEMENTATION_READINESS_REVIEW.md).

O.36.1 resolves the five architecture gates that stopped O.36. It creates
specifications and conformance evidence only. Public mutation count is zero.

## Baseline

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- phase-start HEAD:
  `402b48710eddc8c183dd7ebdc5bba6dc86f5c640`;
- phase-start tracked worktree: clean;
- upstream without fetch: `origin/main`, ahead 92, behind 0;
- V1 account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- V1 factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

O.20--O.36 documentation and O.32--O.35 implementation/evidence were
reviewed. The historical O.22 source-binding mismatch remains failed closed
and supplies no authority to this local phase.

## Gate Decisions

### Gate 1: hardware recovery verification

Result: `RESOLVED_AT_INTERFACE_LEVEL`.

- primary device: fixed WebAuthn P-256 role;
- external hardware key: fixed WebAuthn P-256 role;
- independent recovery: fixed purpose-bound secp256k1 role;
- threshold: exact 2-of-3;
- chain: verifies exact challenge, public commitment, signature, RP ID hash,
  UP/UV, bitmap, state, nonce, account, chain, EntryPoint, epochs, and request;
- Runtime: verifies enrollment, attestation policy, origin policy, device
  independence, protected storage, and local evidence.

The selected onchain library boundary is OpenZeppelin Contracts `5.6.1`
`WebAuthn` plus `P256`, with no external or calldata-selected verifier.

Security impact: one role cannot recover; same-device substitution is
forbidden; recovery cryptography is chain-verifiable.

Remaining risk: enrollment independence and origin policy are local trust
decisions. O.37 must produce bounded parsing, differential verification, and
gas evidence. Failure stops implementation rather than weakening the model.

### Gate 2: production validator envelope

Result: `RESOLVED`.

The validator uses the existing O.32 EIP-712 authorization digest and one
320-byte static ABI envelope containing fixed version, authority/verifier
kinds, validator/key binding, both epochs, canonical `r`,`s`,`v`. Solidity
recovers exactly the current validator with low-s enforcement.

Security impact: no arbitrary-message ambiguity, mutable verifier selection,
wrong-account replay, or stale-epoch fallback.

Remaining risk: Ethereum still verifies the validator signature, not the
local STARK proof. Device Vault custody and Runtime correctness remain trusted
offchain components.

### Gate 3: identity-binding commitment

Result: `RESOLVED`.

The binding is typed Keccak-256 over version `1`, canonical public
`ownerCommitment`, and the exact
`PHIL_OWNER_COMMITMENT_CANONICAL_V1` scheme ID. It is chain-independent and
immutable; CREATE2 separately supplies chain/version/factory separation.

Security impact: deterministic identity continuity without exposing a new
private value or coupling identity to a wallet, device, or recovery factor.

Remaining risk: the public owner commitment and derived binding are linkable.
They are not proof of private identity-root knowledge.

### Gate 4: recovery cancellation

Result: `RESOLVED`.

Recovery and recovery-configuration cancellation require exact 2-of-3 current
recovery factors. Validator-only and validator-plus-one-factor paths are
retired. The O.33 authorization engine now rejects the combined authority.

Security impact: a compromised daily validator cannot strengthen one
compromised factor into recovery control. One lost factor still leaves a live
two-factor path.

Remaining risk: compromise of two independent roles meets the intended
threshold. Challenge delay aids detection but is not a third authority.

### Gate 5: Solidity implementation freeze

Result: `RESOLVED_FOR_O37_ENTRY`.

Compiler, dependencies, settings, common types, account/factory surfaces,
events, errors, storage policy, forbidden capabilities, and artifact evidence
are frozen in the O.36.1 package.

Security impact: O.37 cannot redesign authorization, add generic wallet
surface, or silently change dependencies while implementing.

Remaining risk: repository dependencies are not changed in O.36.1. O.37 must
pin/install the selected versions and independently verify resulting source,
storage, ABI, and bytecode.

## Security Requirements

The frozen package confirms:

- no administrator, owner role, upgrade authority, proxy, or implementation
  registry;
- no arbitrary execute, batch, delegatecall, module, plugin, session key,
  token approval, sweep, or fallback execution;
- no recovery asset movement or external call;
- no private identity, Device Vault, credential, proof witness, approval, or
  recovery material onchain;
- no calldata-selected validator or factor verifier;
- no single-factor recovery takeover;
- no ambiguous personal-sign or transaction-signing authorization;
- no counterfactual funding acceptance before complete initialization,
  deployment verification, lifecycle simulation, and release-path proof.

## Rejected Alternatives

- same-device software key for hardware role: correlated compromise;
- synced passkey as external hardware role: does not prove domain
  independence;
- validator plus one factor cancellation: strengthens validator compromise
  and conflicts with strict O.32 threshold evidence;
- offchain Boolean recovery attestation: chain would trust mutable claims;
- external verifier registry or ERC-1271 dispatch: mutable verification
  authority;
- raw identity root or device/recovery data in identity binding: privacy and
  migration coupling;
- chain ID inside identity binding: makes Phil identity chain-specific;
- OpenZeppelin generic account/modular execution inheritance: adds surfaces
  outside PhilCore's typed enforcement model.

## Remaining O.37 Acceptance Work

O.37 must still implement and prove:

- exact Solidity/TypeScript hash parity;
- canonical envelope decoding and malformed-input rejection;
- WebAuthn/P-256 differential, parser, and gas bounds;
- complete storage-layout and bytecode reproduction;
- EntryPoint v0.7 validation and keyed nonce behavior;
- typed token/NFT external-call and reentrancy behavior;
- full recovery/configuration lifecycle and invariants;
- deterministic factory and CREATE2 vectors;
- local full fund lifecycle without public funding;
- static analysis and contamination checks.

These are implementation tests, not unresolved architecture choices. If they
require changing the frozen interface or security assumptions, O.37 must stop.

## Phase Boundary

No Solidity contract, bytecode, deployment, account, wallet, credential,
signature, UserOperation, transaction, funding action, RPC call, or public
mutation was created. O.37 requires separate approval.
