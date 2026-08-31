# Authorization Package Draft Boundary

## Purpose

Phase M.2 introduces the smallest bounded `ACTION_UNLOCK` Authorization Package Draft.

An Authorization Package Draft means only:

```text
PhilCore has assembled the locked ACTION_UNLOCK public tuple and canonical proofInputHash for one exact Authorization Decision Candidate.
```

It is not a final Authorization Package, proof, verified fact, nullifier consumption, adapter call, transaction submission, UserOperation, signature, session key, or executable authority.

## Flow

```text
Active Authoritative Capability Grant
  -> Authorization Decision Candidate
  -> authoritative Trust / Policy / Approval references
  -> explicit canonical ACTION_UNLOCK inputs
  -> canonical actionHash
  -> canonical policyHash
  -> consumerDataHash
  -> public nullifier reference
  -> canonical proofInputHash
  -> Authorization Package Draft
  -> sanitized Audit Event Draft
  -> stop
```

## Candidate Versus Draft

An `AuthorizationDecisionCandidate` proves only that one active capability grant can be paired with one exact action intent for future package construction.

An `AuthorizationPackageDraft` goes one step further by assembling the locked `ACTION_UNLOCK` public tuple:

```text
ownerCommitment
actionHash
policyHash
nullifier
consumerDataHash
expiry
```

The draft still does not authorize the action. A future final package requires proof generation or another explicitly reviewed authorization mode.

## Locked ACTION_UNLOCK Tuple

M.2 preserves:

- `version = "v1"`
- `proofType = "stwo-unlock-keccak-v1"`
- tuple order: `ownerCommitment`, `actionHash`, `policyHash`, `nullifier`, `consumerDataHash`, `expiry`
- `proofInputHash` derivation
- future fact shape reference: `[fact_high, fact_low]`

No proof bytes or verified facts exist in M.2.

## Canonical Hashing

M.2 reuses existing canonical SDK helpers:

- `encodeUnlockConsumerData`
- `computeUnlockActionHashFromConsumerData`
- `dataHash`
- `policyHash`
- `buildUnlockProofPackageFromAuthorization`

The M.1 action digest preview is not the canonical `ACTION_UNLOCK` `actionHash`. Both may be recorded as references, but they have different purposes.

## Nullifier Boundary

M.2 accepts only a public nullifier or safe public reference.

It must not accept or expose:

- `phil_secret`
- `nullifierSeed`
- private witness material
- Device Vault keys
- credential private material

Process-local duplicate nullifier detection is a draft hygiene guardrail only. It is not durable replay protection and does not consume an on-chain nullifier.

## Negative Guarantees

Every successful draft must preserve:

- `authorizationPackageExecutable = false`
- `actionAuthorized = false`
- `proofGenerated = false`
- `proofVerified = false`
- `verifiedFactAvailable = false`
- `nullifierConsumed = false`
- `adapterExecutionAllowed = false`
- `transactionSubmitted = false`
- `signatureCreated = false`
- `sessionKeyCreated = false`
- `vaultAccessed = false`
- `persistedAsAuthority = false`

Adapters and contracts must not consume Authorization Package Drafts.

## Future Boundaries

Phase M.3 defines the next bounded step:

- protected witness request from an explicit local provider
- STARK proof generation from one valid draft
- bounded proof artifact return

M.3 still does not verify facts, consume nullifiers, finalize Authorization Packages, call adapters, submit transactions, or persist authority.

Future work after M.3 may define:

- local proof verification
- finalized but non-executing Authorization Package construction
- verified fact handling
- adapter execution after proof-backed authorization

Phase M.4 covers local proof verification and non-executing package finalization only. It still does not publish verified facts, consume nullifiers, call adapters, submit transactions, or persist authority.

Phase M.5 covers verified-fact publication request drafts and read-only execution-readiness snapshots only. It still does not publish facts, consume nullifiers, call contracts, create UserOperations, call adapters, sign/submit transactions, mutate chain state, or persist execution authority.

Those execution-oriented steps are not part of M.2.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_package_draft
```

Supported diagnostic scenarios:

- `exact`
- `mutated_action`
- `invalid_nullifier`
- `expiry_beyond_capability_grant`
- `evidence_chain_mismatch`
- `consumer_data_mismatch`

Only the exact scenario creates a package draft. Rejected scenarios produce diagnostics only and still do not generate proofs, verify facts, consume nullifiers, call adapters, submit transactions, or persist authority.
