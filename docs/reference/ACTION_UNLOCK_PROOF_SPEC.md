# ACTION_UNLOCK Proof Spec

Status: Quarantined, secret-bearing compatibility proof; prohibited from V1
authorization.

This document preserves the exact current statement for regression and
migration analysis. ACP-0003 Step 1 replaces its product role with routine
capability/device authorization and a separate exceptional root-proof contract
defined in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
No existing field, hash, proof type, or artifact may be relabeled as that new
contract.

## A. Statement Summary

The `ACTION_UNLOCK` AIR constrains a supplied private-trace `phil_secret` and
`nullifierSeed` such that canonical identity derivation yields the public
`ownerCommitment`, canonical nullifier derivation yields the public
`nullifier`, and the resulting relation is bound to one exact unlock
authorization context defined by the full public tuple `(version, proofType,
ownerCommitment, actionHash, policyHash, nullifier, consumerDataHash, expiry)`.
The current serialized proof exposes queried witness-bit openings, so this
constraint is not yet a privacy-preserving proof of knowledge.

## Terminology

`ACTION_UNLOCK` is a frozen v1 cryptographic identifier. It does not unlock
the PhilCore identity, User Session, Device Vault, validator key, or account.
Its exact meaning is: authorize one protected action tuple for later bounded
execution.

User-facing text must say "protected action authorization" or equivalent.
Renaming the domain to `ACTION_AUTHORIZE` would change the proof statement,
hashes, fixtures, and serialized compatibility. Any such rename requires a
versioned proof/circuit migration with a new domain separator; O.17 therefore
preserves the identifier and adds no alias that could be mistaken for the same
cryptographic statement.

## B. Private Witness

Exact private witness fields:
- `phil_secret`
- `nullifierSeed`

Classification:
- raw secret root witness:
  - `phil_secret`
- raw private one-time witness:
  - `nullifierSeed`
- derived private or intermediate witness values:
  - `identityRoot`
  - any internal ABI-encoding and Keccak permutation state required by the proving system

Witness details:
- `phil_secret`
  - must be a normalized 32-byte value
  - must be non-zero
  - must fit within the current 251-bit Stark-friendly private root range used by the SDK
- `nullifierSeed`
  - must be treated as a normalized private `bytes32` value inside the statement
  - is per authorization, not the identity root

`identityRoot` is not a separate root witness. It is a derived private intermediate computed from `phil_secret`.

No other hidden protocol values are required for the locked `ACTION_UNLOCK` statement.

Not witness:
- `consumerData`
- `callData`
- `policyData`
- `World ID` data
- chain state

## C. Public Inputs

Exact full public input list:
- `version`
- `proofType`
- `ownerCommitment`
- `actionHash`
- `policyHash`
- `nullifier`
- `consumerDataHash`
- `expiry`

Exact repo names:
- package-level fields:
  - `UnlockProofPackage.version`
  - `UnlockProofPackage.proofType`
  - `UnlockProofPackage.proofInputHash`
  - `UnlockProofPackage.proofBlob`
- tuple fields:
  - `UnlockProofPublicInputs.ownerCommitment`
  - `UnlockProofPublicInputs.actionHash`
  - `UnlockProofPublicInputs.policyHash`
  - `UnlockProofPublicInputs.nullifier`
  - `UnlockProofPublicInputs.consumerDataHash`
  - `UnlockProofPublicInputs.expiry`

Definitions:
- `version`
  - proof-input schema version
  - currently `"v1"` in the repo
- `proofType`
  - proof-family identifier
  - canonical current value: `"stwo-unlock-keccak-v1"`
  - direct trustless Base verification of the frozen raw proof bytes was ruled out, but this tuple field remains locked
- `ownerCommitment`
  - canonical public Phil identity anchor
- `actionHash`
  - semantic commitment to the unlock action
- `policyHash`
  - commitment to the policy parameters for this unlock authorization
- `nullifier`
  - one-time replay key bound to identity plus action plus policy plus `nullifierSeed`
- `consumerDataHash`
  - commitment to the raw encoded unlock payload bytes
- `expiry`
  - explicit expiration timestamp for the authorization

Already on-chain today:
- all 8 fields above are already present either directly in `BaseActionAuthorization` or in `UnlockProofPackage`

Only for future verifier integration:
- the proof system will consume all 8 fields directly
- the current Base gate does not verify a real proof against them yet

`proofInputHash` is not a separate proof public input. It is a derived public commitment computed from the full tuple.

## D. Identity Derivation

Locked canonical derivation path:

```text
identityRoot =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_IDENTITY_ROOT_V1"),
      phil_secret
    )
  )
```

```text
ownerCommitment =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_OWNER_COMMITMENT_CANONICAL_V1"),
      identityRoot
    )
  )
```

Current AIR derivations:
- `identityRoot` is derived in the AIR from the private-trace `phil_secret`
- `ownerCommitment` is derived in the AIR from `identityRoot`
- the AIR enforces equality between the derived `ownerCommitment` and the public `ownerCommitment`

Current off-chain vs on-chain state:
- today, the SDK derives these values off-chain
- today, Base consumes only the public `ownerCommitment`
- today, the pinned local STWO statement constrains the canonical secret-to-commitment relation
- today, Base does not receive `phil_secret` or directly verify its witness relation; it consumes the public fact/commitment boundary
- the current STWO proof serialization exposes queried secret-bit trace openings, so it is not a privacy-preserving proof of knowledge and is unsafe to disclose to an external verifier

Meaning of “knowledge of phil_secret” in this repo:
- the prover knows a private `phil_secret` that, under the locked canonical derivation above, produces the exact public `ownerCommitment` consumed by the authorization and proof package

## E. Action Binding

Exact `ACTION_UNLOCK` semantic binding:

```text
actionHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_ACTION_UNLOCK_V1"),
      chainId,
      consumer,
      account,
      target,
      value,
      keccak256(callData)
    )
  )
```

How `consumerDataHash` relates to the actual payload:
- `consumerData` is the ABI-encoded unlock payload:
  - `(account, target, value, callData)`
- `consumerDataHash = keccak256(consumerData)`
- Base currently checks `keccak256(consumerData) == consumerDataHash`
- `PhilUnlockConsumer` currently decodes `consumerData` and recomputes `actionHash`

How `policyHash` is constructed:

```text
policyHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_POLICY_V1"),
      chainId,
      consumer,
      target,
      expiry,
      keccak256(policyData)
    )
  )
```

How `expiry` is bound:
- `expiry` is included explicitly as a public field
- `expiry` is also included inside `policyHash`

Why these values must be in the proof:
- `actionHash` binds the proof to one exact unlock action
- `consumerDataHash` binds the proof to one exact raw payload
- `policyHash` binds the proof to one exact policy commitment
- `expiry` binds time-bounded validity and allows cheap on-chain expiration checks

Important current split:
- the proof binds to `actionHash`, `policyHash`, `consumerDataHash`, and `expiry`
- Base still must bind raw `consumerData` to `consumerDataHash`
- `PhilUnlockConsumer` still must recompute `actionHash` from actual payload bytes

The proof does not replace those raw payload checks. It complements them.

### Authorization Decision Candidate Boundary

The Runtime Authorization Decision Candidate boundary may create an action digest preview for future package-construction eligibility. That preview is not `ACTION_UNLOCK`, is not `proofInputHash`, is not the proof public input tuple, and is not executable authority.

`ACTION_UNLOCK`, `proofInputHash`, and the public input tuple remain governed by this specification and must not be assembled or changed by candidate-only runtime checks.

The Authorization Package Draft boundary may assemble the locked public tuple and compute canonical `proofInputHash` by reusing the existing helpers. It must not change tuple order, proof type, fact shape, or proof-input hashing semantics, and it must not generate proofs or consume nullifiers.

The ACTION_UNLOCK Proof Generation boundary is quarantined to an explicit process-local synthetic fixture provider and an exact research acknowledgement. It may invoke the existing Rust/STWO prover only to create an `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT`. It must never consume Device Vault material or a real Phil secret. The proof contains queried witness openings from which `phil_secret` is recoverable.

Local verification remains available for synthetic research and regression testing. Finalization is disabled for the current artifact. Shared finalized-package validation requires an independently reviewed non-secret, witness-hiding proof reference and rejects proof bytes or the current secret-bearing classification before verified-fact publication, adapter preparation, or execution preparation.

## F. Nullifier Binding

Exact nullifier semantics:
- `nullifier` is the one-time replay key for an unlock authorization
- it is identity-bound and authorization-bound

Exact construction:

```text
nullifier =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_NULLIFIER_V1"),
      ownerCommitment,
      actionHash,
      policyHash,
      nullifierSeed
    )
  )
```

Nullifier requirements:
- `nullifier` must be derived in-circuit in the real proof
- the proof must enforce equality between derived `nullifier` and public `nullifier`

Replay protection relation to Base gate state:
- Base stores `consumedNullifier[nullifier]`
- Base must reject any repeated use of the same `nullifier`
- Base must only mark `nullifier` consumed after all local checks and proof verification succeed, and before the external consumer call

## G. proofInputHash

Exact current role:
- `proofInputHash` is a deterministic commitment to the full public tuple
- the SDK computes it
- the Base gate recomputes it and checks parity with the package
- the proof stub binds the opaque artifact to it

Exact relationship:

```text
proofInputHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_UNLOCK_PROOF_INPUTS_V1"),
      version,
      proofType,
      ownerCommitment,
      actionHash,
      policyHash,
      nullifier,
      consumerDataHash,
      expiry
    )
  )
```

Long-term classification:
- current role: primary package integrity boundary
- future role: secondary but still useful integrity commitment

Recommendation:
- keep `proofInputHash` in the schema
- keep Base recomputation of `proofInputHash`
- do not use `proofInputHash` as a substitute for passing the full public tuple into the real verifier
- once full proof verification exists, the primary security boundary becomes:
  - proof bytes
  - explicit public tuple
- `proofInputHash` remains a packaging checksum and backwards-compatible integrity commitment

## H. Security Goals

The intended proof goals are:
- prove knowledge of the canonical Phil identity root secret
- bind that identity to one exact unlock authorization
- prevent reuse of the same authorization through nullifier replay
- prevent mutation of public action and policy commitments without invalidating the proof

What the finished proof does prevent:
- arbitrary claiming of another `ownerCommitment` without `phil_secret`
- arbitrary reuse of a valid public tuple with a different `nullifierSeed`
- substitution of different public inputs under the same proof

What the current repo does not yet prevent:
- execution by anyone who can submit the bearer-style authorization before ownership proof enforcement is live
- misuse arising from the absence of a real on-chain proof verifier
- deeper policy semantics beyond committed `policyHash`
- any World ID enforcement in the active unlock path

## I. Non-goals

This proof does not try to solve:
- World ID enforcement
- generalized action support beyond `ACTION_UNLOCK`
- smart account creation
- marketplace or mint flows
- policy interpretation beyond committed `policyHash`
- relayer policy
- bridge logic
- any chain beyond the active Base-first path
