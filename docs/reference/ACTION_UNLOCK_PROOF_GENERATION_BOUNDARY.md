# ACTION_UNLOCK Proof Generation Boundary

## Purpose

Phase M.3 originally introduced a controlled `ACTION_UNLOCK` proof generation boundary. It is now quarantined as a synthetic research boundary.

The boundary may consume one valid `AuthorizationPackageDraft` only with the exact `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT_LOCAL_SYNTHETIC_RESEARCH_ONLY` acknowledgement and a process-local `local_test_fixture` provider. It returns an `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT` whose queried trace openings recover the synthetic `phil_secret`.

It does not accept Device Vault witness material, create executable authorization, finalize a package, or authorize transmission.

## Flow

```text
Authorization Package Draft
  -> protected witness request
  -> explicit local witness provider
  -> existing Rust/STWO prover
  -> bounded proof generation artifact
  -> sanitized Audit Event Draft
  -> stop
```

## Inputs

The proof generation request must receive explicit inputs:

- a valid `AuthorizationPackageDraft`
- an explicit protected witness provider
- the exact experimental secret-bearing-proof research acknowledgement
- optional expected `proofInputHash`
- optional process-local consumption/artifact stores
- optional audit draft collector
- optional timeout

The boundary must preserve the locked M.2 public tuple:

- `ownerCommitment`
- `actionHash`
- `policyHash`
- `nullifier`
- `consumerDataHash`
- `expiry`

It also preserves:

- `ACTION_UNLOCK`
- `proofInputHash`
- proof public input tuple ordering
- `proofType = "stwo-unlock-keccak-v1"`
- current proof/fact shape references

## Protected Witness Provider

Witness material is available only inside the explicit provider/prover boundary.

The protected witness provider may supply:

- `phil_secret`
- `nullifierSeed`

It must not return those values to the Runtime, facade, audit drafts, shell output, stores, or callers.

The local static provider added for M.3 is the only accepted provider kind. It is a synthetic development/test boundary, not Device Vault unlock, production authentication, or unrestricted secret access. Real secrets are prohibited.

## Existing Prover Reuse

M.3 reuses the existing Rust/STWO prover path instead of duplicating proof logic.

Current invocation:

```text
cargo +nightly-2025-07-14 run --quiet --manifest-path ./proving/Cargo.toml --bin generate-unlock-proof-json
```

The TypeScript boundary sends the prover JSON over standard input and parses JSON from standard output.

M.3 does not change Rust prover semantics, proof schemas, public input tuple shape, fact shape, contracts, or verification semantics.

## Proof Artifact

A successful proof generation artifact may include:

- artifact ID
- `proofType`
- `proofInputHash`
- proof byte length
- proof digest
- optional proof blob
- public-input binding summary
- prover invocation summary
- no-authority flags

It is explicitly labeled `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT`, reports
`witnessRecoverableFromProof = true`, and is invalid for finalization,
publication, adapter use, external verification, or execution preparation.

The artifact must record that:

- proof generation occurred
- public inputs matched the draft
- `proofInputHash` matched the draft
- witness material was not exposed
- no verified fact was published
- no nullifier was consumed
- no Authorization Package was finalized
- no adapter execution was allowed
- no transaction was submitted
- no persistence occurred

## Replay And Collection

M.3 may use process-local stores for hygiene:

- a proof generation consumption store
- an in-memory proof artifact store

These stores are ephemeral. They are not durable replay protection, on-chain nullifier consumption, audit persistence, Device Vault storage, or authorization state.

## Negative Guarantees

M.3 must not:

- expose `phil_secret`
- expose `nullifierSeed`
- return raw witness material
- write witness material to a durable file
- persist proof artifacts as authority
- verify the proof in the Runtime
- publish a verified fact
- consume a nullifier
- finalize an Authorization Package
- create or submit a UserOperation
- create or submit a transaction
- call contracts
- call adapters
- change proof tuple/hash/type/fact shape
- change Rust prover semantics
- change proof or contract schemas
- introduce multi-chain behavior

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_action_unlock_proof_generation
```

Supported diagnostic scenarios:

- `exact`
- `witness_binding_mismatch`
- `prover_failure`
- `proof_input_hash_mismatch`
- `timeout`
- `witness_replay`

Only the exact scenario creates a bounded proof generation artifact. Rejected scenarios produce diagnostics only and still do not expose witness material, verify facts, consume nullifiers, finalize packages, call adapters, submit transactions, or persist authority.

## Future Work

Local verification of the current artifact remains available only for
synthetic privacy and soundness regression testing. The current artifact may
not be finalized. Finalized non-executing package construction now requires a
reviewed non-secret witness-hiding proof reference without proof bytes.

After a witness-hiding replacement is independently reviewed, later milestones may define:

- verified fact publication
- on-chain/nullifier consumption semantics
- Ethereum Adapter execution

Those are outside M.3 and require separate Architecture Change Control if they alter accepted invariants.
