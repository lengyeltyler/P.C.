# O.37 V2 Solidity Account And Factory Implementation Conflict Review

Status: `STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY`.

O.37 was authorized as the first local Solidity implementation phase for the
V2 account and factory. The mandatory entry review found a security-relevant
conflict inside the frozen O.36.1 recovery interface. Implementation stopped
before any V2 contract source, test signature, UserOperation, or deployable
bytecode was created.

Public mutations are zero.

## Verified Baseline

The phase began from:

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `55babe3bd1da67c89c4eb7606ca1c8507acd0a10`;
- tracked worktree: clean;
- upstream relationship without fetching: `origin/main`, ahead 96, behind 0;
- local Node.js observed before build: `v26.0.0`.

The O.20 through O.36.1 canonical documentation and the machine-readable
O.36.1 freeze were inspected. The frozen V1 source SHA-256 bindings remained:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

At entry, Hardhat `2.28.4`, the Hardhat ethers plugin `3.0.8`, ethers
`6.17.0`, Account Abstraction `0.7.0`, optimizer runs `200`, and `viaIR`
matched the freeze. The repository still used Solidity `0.8.24`,
OpenZeppelin Contracts `5.0.2`, a declared Account Abstraction range
`^0.7.0`, and no explicit Cancun target. Those are the expected pre-O.37
settings that O.36.1 directs O.37 to update for V2.

The exact OpenZeppelin `5.6.1` and Account Abstraction `0.7.0` packages were
available and were inspected locally. Because the later security gate failed,
the dependency manifest, lockfile, installed dependency tree, and compiler
configuration were restored to the exact starting baseline. No partial O.37
toolchain change is retained.

## Blocking Frozen-Interface Conflict

### Commitment inputs required by O.32 and O.36.1

The frozen recovery-factor commitment contains:

```text
publicVerificationMaterialHash
rpIdHash
originPolicyHash
userVerificationPolicy
credentialGeneration
```

O.36.1 requires the account to reconstruct each factor commitment from
public evidence and compare it with the stored role commitment. The frozen
initialization and storage policy retain only the three factor commitments,
not the complete public role descriptors.

### Inputs available in the frozen evidence

`WebAuthnFactorEvidenceV1` supplies the P-256 point, signature, indices,
authenticator data, and client JSON. It does not supply
`originPolicyHash` or `credentialGeneration`. Although the RP ID hash can be
read from authenticator data and the user-verification policy is fixed for a
role, the other committed values cannot be recovered from that evidence or
from stored account state.

`Secp256k1FactorEvidenceV1` supplies the signer and signature fields. It does
not supply `credentialGeneration`. That committed value also cannot be
recovered from the evidence or stored account state.

Consequently, a contract following the frozen storage and evidence ABIs
cannot reconstruct either exact factor descriptor for commitment membership.
It cannot distinguish valid evidence for the enrolled generation and origin
policy from evidence using another descriptor with the same public key.

### Unsafe implementation choices rejected

O.37 cannot safely resolve the mismatch by:

- assuming credential generation `1`, because O.36.1 permits any nonzero
  generation;
- treating origin policy as an unverified constant;
- comparing only the public key or signer hash;
- adding descriptor fields to either evidence envelope;
- expanding account initialization or storage with descriptors;
- accepting a Runtime Boolean in place of chain-side membership;
- introducing a registry, module, or calldata-selected verifier.

The first three weaken the committed recovery identity. The remaining
choices change the frozen ABI, storage, or authority model. Each is forbidden
by the O.37 instruction to stop rather than redesign O.36.1.

## Independent Acceptance-Test Conflict

O.37 requires valid authorization, replay, and exact 2-of-3 recovery tests,
while also prohibiting the creation of signatures and UserOperations.

The checked-in O.32 and O.33 vectors provide hashes and fixture-only evidence
references. They explicitly record that no signature bytes or UserOperation
were created. O.36.1 likewise contains no accepted public signature,
WebAuthn assertion, recovery envelope, or `PackedUserOperation` fixture.

A valid Solidity cryptographic test therefore cannot be built from the
accepted fixtures. Generating deterministic test signatures or a local
`PackedUserOperation` would violate the current phase restriction. Replacing
cryptography with a mock would not test the production validator or recovery
boundary and is also prohibited.

This conflict independently prevents the required O.37 acceptance suite even
after the recovery descriptor mismatch is corrected.

## Reproducibility Input Still Unpinned

O.36.1 requires a repository-pinned O.37 Node.js runtime to be recorded before
build. The repository declares only `node >=22.0.0`; it has no `.nvmrc`,
`.node-version`, `.tool-versions`, or equivalent exact runtime pin. The
observed `v26.0.0` is an environment fact, not a frozen repository input.

This does not change the recovery decision, but it must be resolved before
deterministic compiler evidence is accepted.

## Fail-Closed Decision

No V2 account, factory, CREATE2 implementation, validator decoder, recovery
state machine, typed execution path, storage layout, ABI artifact, bytecode,
mock substitute, signature fixture, or UserOperation was created.

The requested account, factory, recovery, validation, execution, lifecycle,
storage-layout, and ABI deliverables remain unimplemented. V1 and all
historical deployment evidence remain unchanged.

## Required Resolution Before A Fresh Implementation Attempt

A separately reviewed revision to the O.36.1 freeze must:

1. choose and freeze one complete recovery descriptor-membership design:
   either include every committed descriptor field in canonical factor
   evidence or store the complete descriptors immutably in account
   initialization/state;
2. update the Solidity ABI, storage policy, machine-readable freeze, canonical
   re-encoding rules, and independent positive/negative recovery vectors for
   that choice;
3. provide accepted public, non-secret validator and two-factor recovery
   signature/UserOperation fixtures, or explicitly authorize creation of
   deterministic local-only fixtures for the implementation tests;
4. pin the exact Node.js runtime used for deterministic O.37 artifacts; and
5. rerun architecture and security review before implementation resumes.

That revision grants no deployment, account-creation, funding, credential,
signing, UserOperation-submission, RPC, or public-mutation authority.

## O.37.1 Resolution

O.37.1 completes descriptor and evidence membership with explicit version `2`
types while preserving the threshold and 20-field initialization. It also
pins Node/npm reproducibility. See
[O.37.1 Implementation Readiness Review](./O37_1_IMPLEMENTATION_READINESS_REVIEW.md).

O.37.2 separately resolves the test-authority condition with accepted,
deterministic, public-only validator, recovery, and ERC-4337 v0.7
`PackedUserOperation` fixtures. Those fixtures are isolated to a local test
domain and classified `TEST_FIXTURE_ONLY`. O.37.2 does not authorize or
implement Solidity. See
[O.37.2 Solidity Test Readiness Review](./O37_2_SOLIDITY_TEST_READINESS_REVIEW.md).

## Stop Boundary

No contract was deployed. No account was created onchain. No funds moved. No
credential was enrolled. No signature was produced. No UserOperation was
created. No RPC or live-chain interaction occurred. Public mutations remain
exactly zero.
