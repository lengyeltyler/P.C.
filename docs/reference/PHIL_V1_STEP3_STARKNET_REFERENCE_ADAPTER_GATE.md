# Phil V1 Step 3 Starknet Reference Adapter Gate

Status: In progress; backend compatibility and admission subgate open

Date: 2026-08-21

## Objective

Build one local, read-only Starknet reference adapter for Phil V1 exceptional
root proofs. The adapter must demonstrate that an exact witness-hiding proof can
bind Phil's scoped identity and authorization envelope and can be verified by a
pinned Cairo verifier without becoming Phil identity, routine-action authority,
or a deployed network path.

Step 3 is not a production backend selection. It authorizes no deployment,
account action, signer, RPC, transaction, fee payment, publication, real secret,
or physical device use.

## Exact Relation

Private witness:

- `phil_secret: bytes32`;
- `nullifierSeed: bytes32`.

Public inputs, in the accepted logical order:

```text
scopedOwnerCommitment
scopeId
scopeInstance
scopeEpoch
authorizationEnvelopeDigest
rootProofNullifier
proofDescriptorHash
```

The circuit must enforce the exact architecture relation:

```text
identityRoot = keccak256(abi.encode(PHIL_IDENTITY_ROOT_V1, phil_secret))

scopedOwnerCommitment = keccak256(
  abi.encode(
    PHIL_SCOPED_OWNER_COMMITMENT_V1,
    identityRoot,
    scopeId,
    scopeInstance,
    uint64(scopeEpoch)
  )
)

rootProofNullifier = keccak256(
  abi.encode(
    PHIL_ROOT_PROOF_NULLIFIER_V1,
    scopedOwnerCommitment,
    authorizationEnvelopeDigest,
    nullifierSeed
  )
)
```

`authorizationEnvelopeDigest` commits every envelope field except
`rootProofNullifier`. This deliberate omission breaks the otherwise circular
definition; the proof itself derives and binds the omitted nullifier from the
digest and private seed. The composed Step 4 account gate must verify the
envelope digest, public nullifier, and proof together.

The adapter, not the private witness, must bind `proofDescriptorHash` to the
exact pinned proof suite, toolchain, circuit, verification key, generated Cairo
verifier, public-input schema, and codec. The root proof never substitutes for
the separate device signature or for the Step 4 account-composition gate.

The candidate codec splits each public `bytes32` into big-endian high and low
`u128` values and preserves `scopeEpoch` as one `u64`, producing exactly 13
native public values. No field reduction or truncation is permitted. The
adapter must compare all seven reconstructed logical values, including the
exact admitted descriptor hash, before any later composition layer may consume
a successful verifier result.

## Candidate Compatibility Lane

The earlier isolated prototype used Noir `1.0.0-beta.26` and Barretenberg
`5.2.0`. It is useful witness-hiding and performance evidence, but its proof and
verification-key formats are not admitted for direct Garaga generation.

The Step 3 reference lane therefore evaluates a separate, exact compatibility
set:

| Component | Exact identity | Classification |
| --- | --- | --- |
| Noir/Nargo | `1.0.0-beta.16` | Garaga-compatible reference compiler; beta, not production-approved |
| Barretenberg | `3.0.0-nightly.20251104` | Garaga-compatible UltraKeccakZK Honk backend; nightly, not production-approved |
| Garaga | `1.0.1`, commit `aa91b6504c86995789edb4e78f9f9ba20571625c` | Audited Garaga release and reference Cairo generator |
| Cairo/Scarb | `2.14.0` | Exact Garaga-generated project pin; local build/test only |
| Starknet Foundry | `0.53.0` | Isolated no-fork verifier tests |
| Universal Sierra Compiler | `2.10.0` | Local test class compilation |

Compatibility references:

- <https://github.com/keep-starknet-strange/garaga/releases/tag/v1.0.1>
- <https://github.com/noir-lang/noir/releases/tag/v1.0.0-beta.16>

No artifact from this lane may be relabeled as a production backend. A newer
Noir/Barretenberg lane requires a matching, independently reviewed Garaga codec
and fresh measurements rather than silent cross-version reuse.

## Proving Placement

Step 3 targets the protected local desktop development environment for the
reference prover. iPhone proving is not selected or claimed. The accepted
iPhone role remains hardware-backed device approval and local-vault-key
wrapping, separate from root-proof generation.

If later product requirements demand iPhone proving, that is a new physical-
device admission gate with time, memory, battery, thermal, interruption, and
failure evidence. It is not inferred from desktop results.

## Required Source And Artifacts

The bounded candidate must include:

- a versioned Noir circuit for the exact Step 3 relation;
- canonical synthetic witness and public-input vectors generated independently
  by the Phil TypeScript SDK;
- a fail-closed proof descriptor and descriptor-hash implementation;
- a Starknet adapter manifest and canonical calldata codec;
- a Garaga-generated Cairo verifier pinned to the exact verification key;
- local proof, native verification, Cairo verifier build/test, and malformed-
  proof rejection evidence;
- an artifact manifest with cryptographic hashes and source/tool provenance;
- size, proof-time, memory, proof/calldata, verifier-class-size, and local Cairo
  execution-cost measurements where the local toolchain can establish them;
- negative tests for every required scope, action/envelope, nullifier, account,
  chain, scheme, verifier, and epoch binding; and
- an independent cryptographic/Cairo/account review of the exact candidate.

## Structural No-Authority Rules

The Step 3 implementation must:

- expose no RPC URL, account key, signer, deploy, declare, invoke, submit, fund,
  publish, or transaction function;
- accept only synthetic secrets in committed fixtures and local diagnostics;
- remain unreachable from renderer, preload, dapp, plugin, adapter-execution,
  agent, and Device Vault authority surfaces;
- produce verification and adapter-request candidates only;
- mark every result `productionAuthority: false` and `networkActivity: false`;
- keep STWO quarantined and import no STWO proof artifact; and
- leave Step 4 blocked until proof + device signature + policy + replay + epoch
  composition passes as one account action.

## Exit Contract

Step 3 can be accepted only when:

```text
exact compatibility toolchain pinned and reproducible
canonical TypeScript/Noir/Cairo public-input parity passed
valid proof verified natively and by the generated Cairo verifier locally
all required mismatches and malformed proofs rejected
artifact identities and measurements recorded
independent exact-candidate review accepted
no deployment, RPC, signing, device, secret, or authority mutation occurred
```

If the compatibility lane cannot pass, Step 3 stops with an evidence-backed
backend/toolchain blocker. It must not fall back to STWO or weaken the accepted
logical relation.

## Current Verdict

The exact local candidate now passes TypeScript/Noir public-input parity,
native proof verification, ten circuit-mismatch cases, malformed-proof
rejection, exact Scarb `2.14.0` compilation, and isolated Cairo verification.
The Cairo test returned all 13 public values for the canonical proof and
failed closed after one public-input limb was altered. The measured verifier
call cost was 259,670,377 L2 gas for the valid proof; no network fee was
measured because no RPC or network activity is authorized.

Exact candidate `11234ea623a6b8883eed0036f3d95174cef90627` received
`ACCEPT_STEP_3_EXACT_CANDIDATE`. The review reproduced the available local
adapter, artifact, ABI/Keccak, descriptor, Cairo, class-hash, and gas evidence
and recorded the native rerun limitations separately.

`STEP 3 STATUS: ACCEPTED - LOCAL REFERENCE EVIDENCE ONLY`

`PRODUCTION PROOF BACKEND SELECTED: NO`

`STARKNET REFERENCE ADAPTER AUTHORITY: LOCAL READ-ONLY ONLY`

`START STEP 4: NO`

## Step 3 Architecture Correction

The implementation preflight found that the prior text hashed
`rootProofNullifier` into `authorizationEnvelopeDigest` while also deriving the
nullifier from that digest. That construction requires an infeasible Keccak
fixed point. Because no Phil V1 envelope has been persisted or deployed, Step 3
corrected the pre-implementation definition rather than weakening the proof or
introducing an unversioned workaround.
