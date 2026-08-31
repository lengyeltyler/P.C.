# ACTION_UNLOCK Proof Verification And Finalization Boundary

## Purpose

Phase M.4 retains controlled local verification for synthetic `ACTION_UNLOCK` research proofs. Finalization of the current proof artifact is disabled.

This boundary may consume one valid `AuthorizationPackageDraft` and one quarantined M.3 artifact, invoke the existing Rust/STWO verifier, correlate it to the locked public tuple, and preview `[fact_high, fact_low]` for research. It rejects finalization because the proof contains recoverable witness openings.

It does not create executable authorization.

## Flow

```text
Valid Authorization Package Draft
  -> generated ACTION_UNLOCK proof artifact
  -> existing local Rust/STWO verifier
  -> bounded local proof-verification result
  -> proof/draft/public-input correlation
  -> finalization rejected: secret-bearing proof quarantined
  -> sanitized Audit Event Draft
  -> stop
```

## Local Verifier Reuse

M.4 reuses the existing Rust/STWO verifier path instead of adding a TypeScript verifier.

Current invocation:

```text
cargo +nightly-2025-07-14 run --quiet --manifest-path ./proving/Cargo.toml --bin verify-unlock-proof-json
```

The TypeScript boundary passes only the proof blob and locked public inputs over standard input and consumes bounded JSON output. The subprocess uses fixed arguments, no shell interpolation, a bounded timeout, sanitized error handling, and no secret-bearing logs.

M.4 does not change Rust proving or verification semantics, proof schemas, public tuple shape, fact shape, contracts, or adapter behavior.

## Correlation Requirements

The verification boundary requires exact equality across:

- Authorization Package Draft public tuple
- proof generation artifact public inputs
- verifier public inputs
- `proofInputHash`
- `proofType = "stwo-unlock-keccak-v1"`
- proof digest and proof byte length
- draft/session/application/owner/nullifier binding
- fact shape reference `[fact_high, fact_low]`

Any altered owner commitment, action hash, policy hash, nullifier, consumer data hash, expiry, `proofInputHash`, proof type, proof bytes, digest, or fact shape is rejected.

## Fact Shape Preview

M.4 may derive a local preview of the future fact shape:

```text
[fact_high, fact_low]
```

The preview is derived from the existing `proofInputHash` ordering and is local metadata only.

It is not fact publication, contract registration, verifier-contract execution, proof consumption, or nullifier consumption.

## Finalized Authorization Package

A finalized M.4 package means only:

```text
The local proof and canonical public authorization fields are complete and locally correlated.
```

It may contain:

- package ID
- draft ID
- proof digest and byte length
- proof type
- canonical public `ACTION_UNLOCK` tuple
- `proofInputHash`
- local verification result reference
- `[fact_high, fact_low]` preview
- application/session/owner/action correlations
- issue time and expiry
- audit correlation ID

The default package uses a reference model and does not return proof bytes. A bounded proof blob may be retained only when explicitly requested by later reviewed boundaries.

## Negative Guarantees

M.4 must not:

- publish a verified fact
- call a fact registry
- call an on-chain verifier
- consume a nullifier
- call an adapter
- call a contract
- create or submit a UserOperation
- sign or submit a transaction
- permit application execution
- expose witness material
- expose `phil_secret`
- expose `nullifierSeed`
- persist authority
- change `ACTION_UNLOCK`
- change the public tuple
- change `proofInputHash`
- change `[fact_high, fact_low]`
- introduce multi-chain behavior

Every successful local verification result must explicitly record:

- `proofVerifiedLocally = true`
- `verifiedFactPublished = false`
- `onChainVerificationPerformed = false`
- `nullifierConsumed = false`
- `adapterExecutionAllowed = false`
- `transactionSubmitted = false`

Every successful finalized package must explicitly record:

- `authorizationPackageFinalized = true`
- `proofVerifiedLocally = true`
- `verifiedFactPublished = false`
- `onChainVerificationPerformed = false`
- `nullifierConsumed = false`
- `adapterExecutionAllowed = false`
- `contractExecutionAllowed = false`
- `transactionSubmitted = false`
- `executableByApplications = false`
- `persisted = false`

## Process-Local Stores

M.4 may use process-local replay and collection stores for hygiene:

- proof verification consumption store
- proof verification result store
- finalized package consumption store
- finalized package store

These stores are ephemeral. They are not durable replay protection, audit persistence, Device Vault storage, nullifier consumption, contract state, or authorization state.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_finalized_authorization_package
```

Supported diagnostic scenarios:

- `exact`
- `invalid_proof`
- `public_input_mismatch`
- `proof_input_hash_mismatch`
- `fact_shape_mismatch`
- `verification_timeout`
- `expired_package`

Only the exact scenario creates a non-executing finalized package. Rejected scenarios produce diagnostics only and still do not publish facts, consume nullifiers, call adapters, submit transactions, expose witness material, or persist authority.

## M.5 Readiness Boundary

Phase M.5 consumes a valid finalized Authorization Package to create a verified-fact publication request draft and read-only execution-readiness snapshot.

M.5 still does not publish verified facts, call verifier/fact-registry contracts, consume nullifiers, create UserOperations, sign/submit transactions, call adapters, mutate chain state, or persist execution authority.

Phase M.7 consumes a valid finalized Authorization Package as one input for [Base Authorization Execution Preparation](./BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md). M.7 does not alter the finalized package, proof tuple, `proofInputHash`, proof blob, or `[fact_high, fact_low]` ordering.

## Future Work

Later milestones may define:

- verified fact publication transaction preparation
- durable nullifier consumption
- on-chain verifier/fact registry integration
- Ethereum Adapter consumption of finalized packages
- ERC-4337 UserOperation construction from approved packages

Those are outside M.4.
