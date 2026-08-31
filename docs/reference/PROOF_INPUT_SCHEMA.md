# Proof Input Schema

Status: Byte-stable compatibility schema for quarantined `ACTION_UNLOCK`
research. It is not the accepted V1 exceptional root-proof schema.

The target proof public inputs and proof descriptor are frozen in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
They use a scoped identity and bind the complete chain-agnostic authorization
envelope. Step 1 selected no backend and implemented no new schema.

## Scope

This document defines the legacy `ACTION_UNLOCK` proof package boundary
preserved for compatibility and research in PhilCore.

The schema remains shared conceptually across:
- the device-side SDK helpers
- the proving workspace
- the Base-facing authorization boundary

## Package Shape

The package shape remains:

```text
version
proofType
publicInputs
proofInputHash
proofBlob
```

Current locked defaults:

```text
version   = "v1"
proofType = "stwo-unlock-keccak-v1"
```

## Public Tuple

The public tuple remains fixed:

```text
ownerCommitment
actionHash
policyHash
nullifier
consumerDataHash
expiry
```

This tuple is locked only for byte-stable compatibility. It does not survive
as new V1 product authority and cannot be relabeled as the accepted root-proof
tuple.

## proofInputHash

`proofInputHash` remains:

```text
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

Its role is still:
- package integrity commitment
- parity check between the package metadata and the public tuple

It is not a substitute for passing the full public tuple to a real verifier path.

## proofBlob

`proofBlob` remains the raw proof artifact field at the verifier boundary.

For the frozen STWO path, the raw codec is:
- `phil-stwo-unlock-raw-proof-bincode-v1`

Important current truth:
- PhilTLS proved that direct trustless Base verification of those frozen raw bytes is not a credible path
- that does not invalidate the schema itself
- it only invalidates direct Base verification of that specific raw proof boundary

The schema stays locked for historical fixtures and migration analysis. It is
not a candidate production schema.

## Honest Status

Locked and preserved:
- public tuple shape
- `proofInputHash` derivation
- `proofBlob` as the proof artifact slot

Ruled out:
- direct trustless Base verification of the frozen raw STWO proof bytes

Current candidate direction:
- preserve this schema
- keep Base-side tuple semantics unchanged
- evaluate Starknet as the trustless proof-verification layer

## Authorization Package Drafts

Authorization Package Drafts may assemble this locked package shape and compute `proofInputHash` for one exact action candidate.

Drafts are not final packages: they contain no proof bytes, publish no verified fact, consume no nullifier, and grant no adapter or contract execution authority.
