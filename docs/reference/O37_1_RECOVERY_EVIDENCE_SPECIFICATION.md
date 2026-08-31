# O.37.1 V2 Recovery Evidence Specification

Status: `COMPLETE_LOCAL_INTERFACE_CORRECTION`.

This specification defines the complete public evidence model that a future
V2 Solidity account may decode. It creates no assertion, signature,
UserOperation, contract, bytecode, credential, or public mutation.

## Authority Envelope

The outer envelope is canonical ABI encoding of:

```text
RecoveryAuthorityEnvelopeV2 {
  RecoveryEvidenceContextV2 context
  bytes firstFactorEvidence
  bytes secondFactorEvidence
}
```

`envelopeVersion` is exactly `2` and authority kind is exactly `2`, recovery
factors. Evidence is ordered by increasing role ID. Only bitmaps `0b011`,
`0b101`, and `0b110` are valid.

The complete context type is:

```text
PhilCoreV2RecoveryEvidenceContextV2(
  uint8 envelopeVersion,
  uint8 authorityKind,
  uint8 actionType,
  uint8 factorBitmap,
  address account,
  uint256 chainId,
  address entryPoint,
  bytes32 authorizedIntentHash,
  bytes32 userOpHash,
  bytes32 requestId,
  bytes32 currentRecoveryConfigHash,
  uint64 validatorEpoch,
  uint64 recoveryEpoch,
  uint48 validAfter,
  uint48 validUntil,
  uint64 recoveryDelaySeconds,
  uint64 recoveryExpirySeconds,
  bytes32 proposedValidatorCommitment,
  bytes32 proposedRecoveryConfigHash,
  uint64 proposedRecoveryEpoch,
  bytes32 primaryDeviceCommitment,
  bytes32 hardwareSecurityKeyCommitment,
  bytes32 recoveryFactorCommitment,
  bytes32 firstFactorCommitment,
  bytes32 secondFactorCommitment
)
```

The context commitment is `keccak256(abi.encode(TYPEHASH, fields...))` in that
exact order. Standard ABI encoding is mandatory.

The three role commitments must reproduce `currentRecoveryConfigHash` under
configuration version `2`, threshold `2`. The first and second commitments
must match the two set bitmap roles in ascending order.

For a request action, `requestId` equals `authorizedIntentHash`. A
cancellation supplies the exact stored request ID. `validatorEpoch` and
`recoveryEpoch` must equal current account state. `proposedRecoveryEpoch` is
exactly current recovery epoch plus one.

Delay is exactly `172800` seconds and expiry is exactly `604800` seconds.
Intent validity still uses `validAfter` and `validUntil`. At request execution,
the account derives stored `executableAfter` and `expiresAt` from the block
timestamp and fixed durations; evidence cannot choose an alternate timing
policy.

## Tagged Action Rules

Only O.32 action types `8`, `9`, `10`, and `11` are accepted.

| Action | Proposed validator commitment | Proposed configuration hash |
| --- | --- | --- |
| validator recovery request (`8`) | nonzero exact proposal | zero |
| validator recovery cancel (`9`) | exact stored proposal | zero |
| configuration rotation request (`10`) | zero | nonzero exact proposal |
| configuration rotation cancel (`11`) | zero | exact stored proposal |

These are fixed tagged-union rules, not optional fields. Any noncanonical
zero/nonzero combination fails.

The proposed validator address, key-ID binding, validator epoch, proposed
factor commitments, and request salt remain bound by the action-specific
O.32 intent. The account recomputes the proposed validator commitment or
configuration hash from that payload and requires equality with the evidence
context.

## WebAuthn Factor Evidence

Canonical ABI encoding:

```text
WebAuthnFactorEvidenceV2 {
  RecoveryFactorDescriptorV2 descriptor
  bytes32 factorCommitment
  bytes32 qx
  bytes32 qy
  bytes32 r
  bytes32 s
  uint256 challengeIndex
  uint256 typeIndex
  bytes authenticatorData
  string clientDataJSON
}
```

The account:

1. checks the descriptor's exact version, role, verifier, domain, and policy;
2. recomputes the P-256 public-material hash from `qx`,`qy`;
3. recomputes the complete descriptor commitment;
4. matches it to `factorCommitment`, the selected context commitment, and the
   stored role commitment;
5. checks the signed authenticator RP ID, UP, UV, BE, and BS flags against the
   descriptor;
6. checks the exact `webauthn.get` type and base64url recovery challenge; and
7. verifies a canonical low-s P-256 signature.

The committed origin policy, credential-ID hash, attestation policy,
attachment policy, and independence binding are enrollment facts that
Runtime verifies. The account verifies exact commitment membership but does
not claim that an assertion independently proves browser origin, attestation,
or device independence.

The O.36.1 bounds remain: authenticator data 37--1024 bytes and client JSON
1--2048 bytes. Indices must be in bounds and canonical re-encoding must equal
the supplied bytes exactly.

## Purpose-Bound Secp256k1 Factor Evidence

Canonical ABI encoding:

```text
Secp256k1FactorEvidenceV2 {
  RecoveryFactorDescriptorV2 descriptor
  bytes32 factorCommitment
  address signer
  bytes32 r
  bytes32 s
  uint8 v
}
```

The account recomputes signer material and the complete descriptor
commitment, matches the selected stored role, and recovers the exact signer
over the unchanged O.32 recovery authorization digest. `r` and `s` are
nonzero, `s` is low, and `v` is exactly `27` or `28`. Personal-sign prefixes,
transaction signatures, ERC-1271 dispatch, and generic-message fallback are
prohibited.

## Solidity Verification Boundary

A future account must verify:

- EntryPoint caller, account, chain, EntryPoint, action, request ID, complete
  O.32 intent, UserOperation hash, epochs, nonce, validity, and timing;
- configuration version, hash, threshold, bitmap, ordering, and membership;
- every descriptor field and its role-specific policy;
- public-material and descriptor commitments;
- two distinct signatures over the exact recovery digest;
- current or pending action context as applicable.

No external verifier registry, module, delegatecall, Runtime Boolean, or
calldata-selected verifier is accepted.

## Runtime Verification Boundary

Runtime verifies before enrollment or replacement:

- raw credential identity and uniqueness;
- registration ceremony, RP, origin, attestation, attachment, UV, and backup
  policy;
- valid public point or signer derivation;
- primary/hardware/recovery custody-domain independence;
- generation monotonicity and replacement authorization;
- exact descriptor and commitment parity with the future account proposal.

Runtime later obtains fresh assertions/signatures over the exact recovery
digest. Runtime checks are defense in depth and never replace account-side
cryptography.

## Data That Never Leaves Protected Storage

- private credential or recovery keys;
- biometric data;
- raw attestation trust-store secrets;
- protected proof witness material;
- local approval and presence records;
- raw credential ID except where an authenticator API locally requires it.

Public descriptor hashes and one-time signature evidence are not classified
as secret, but signatures and assertions are not created in O.37.1.

## Completion And Expiry

Completion and expiry are permissionless transitions over exact pending state.
They accept only the stored request ID and require no new recovery evidence.
They cannot substitute a proposal, move assets, call an arbitrary target, or
change timing. Cancellation requires fresh exact 2-of-3 evidence.

## O.37.4 Transport Completion

O.37.4 does not change this envelope or any nested factor type. Actions `8`,
`9`, and `11` transport `RecoveryAuthorityEnvelopeV2` directly in
`PackedUserOperation.signature`. Action `10` nests the exact same canonical
bytes after the exact O.36.1 validator envelope inside
`CombinedAuthorityEnvelopeV1`, because configuration rotation requires both
authority classes. See
[O.37.4 Authority Transport Specification](./O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md).
