# O.37.1 V2 Cryptographic Descriptor Specification

Status: `COMPLETE_LOCAL_INTERFACE_CORRECTION`.

This document replaces only the incomplete O.36.1 recovery-factor commitment
and descriptor-evidence definitions. It preserves the three fixed recovery
roles, exact 2-of-3 threshold, validator separation, typed execution model,
O.32 intent and authority digests, and O.35 constructor-only initialization.

It creates no credential, signature, UserOperation, Solidity, bytecode, live
call, or public mutation.

## Version And Domain

The complete descriptor scheme is version `2`.

```text
descriptorVersion = 2
configurationVersion = 2
recoveryDomainLabel = "PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V2"
recoveryDomainId = keccak256(UTF8(recoveryDomainLabel))
```

The descriptor also binds the unchanged O.32 `accountVersionId` and
`securityModelId`. The type hash, explicit version, account version, security
model, recovery-domain ID, and role jointly prevent cross-type, cross-version,
cross-model, and cross-role substitution.

## Fixed Enumerations

Roles:

| Value | Role |
| ---: | --- |
| `0` | primary device |
| `1` | hardware security key |
| `2` | independent recovery factor |

Verifier kinds:

| Value | Verifier |
| ---: | --- |
| `1` | WebAuthn P-256 |
| `2` | purpose-bound secp256k1 |

WebAuthn policies:

| Policy | Value `0` | Value `1` | Value `2` |
| --- | --- | --- | --- |
| user verification | not applicable | presence required | verification required |
| backup | not applicable | single-device required | unsupported |
| attachment | not applicable | platform required | cross-platform required |
| attestation | not applicable | verified device-bound | verified external hardware |

Only the exact role-specific combinations below are accepted. Unknown values
fail closed.

## Public Material Hashes

WebAuthn P-256:

```text
WEBAUTHN_PUBLIC_MATERIAL_TYPEHASH = keccak256(UTF8(
  "PhilCoreV2WebAuthnPublicMaterial(bytes32 qx,bytes32 qy)"
))

publicVerificationMaterialHash = keccak256(abi.encode(
  WEBAUTHN_PUBLIC_MATERIAL_TYPEHASH,
  qx,
  qy
))
```

`qx` and `qy` are nonzero, distinct, 32-byte big-endian coordinates. Runtime
and the future Solidity P-256 verifier must reject a point not on the P-256
curve.

Purpose-bound secp256k1:

```text
SECP256K1_PUBLIC_MATERIAL_TYPEHASH = keccak256(UTF8(
  "PhilCoreV2Secp256k1PublicMaterial(address signer)"
))

publicVerificationMaterialHash = keccak256(abi.encode(
  SECP256K1_PUBLIC_MATERIAL_TYPEHASH,
  signer
))
```

The signer is the nonzero Ethereum address derived from the purpose-separated
public key. This is a verification identifier, not transaction authority.

## Credential Identifier

Runtime retains the raw WebAuthn credential ID only in protected local
storage. The public descriptor contains:

```text
credentialIdHash = keccak256(rawCredentialIdBytes)
```

The raw credential ID is never stored by the account or emitted by contract
events. The hash is public if descriptor evidence is submitted onchain and is
therefore treated as linkable metadata. It is not a secret and is not used as
a substitute for signature verification.

The secp256k1 role has no WebAuthn credential ID and must encode
`credentialIdHash` as zero.

For WebAuthn descriptors, `rpIdHash` is exactly:

```text
rpIdHash = SHA-256(UTF8(canonicalRpId))
```

This is the WebAuthn authenticator-data algorithm. Keccak-256 is not accepted
for RP-ID derivation. `originPolicyHash` remains a PhilCore policy commitment
and uses the descriptor package's explicit Keccak-256 policy-hash convention.

## Independence Binding

The exact type is:

```text
PhilCoreV2RecoveryIndependenceBinding(
  uint8 bindingVersion,
  uint8 role,
  bytes32 credentialIdHash,
  bytes32 enrollmentCeremonyHash,
  bytes32 attestationEvidenceHash,
  bytes32 custodyDomainId
)
```

The binding is:

```text
independenceBindingHash = keccak256(abi.encode(
  INDEPENDENCE_BINDING_TYPEHASH,
  1,
  role,
  credentialIdHash,
  enrollmentCeremonyHash,
  attestationEvidenceHash,
  custodyDomainId
))
```

For WebAuthn roles, all hashes are nonzero. For the secp256k1 role,
`credentialIdHash` and `attestationEvidenceHash` are exactly zero while the
enrollment-ceremony and separately controlled custody-domain hashes are
nonzero.

This binding does not let Ethereum independently prove device independence.
Runtime may create it only after verifying the registration ceremony,
attestation or authenticator metadata, attachment, backup eligibility,
credential uniqueness, and custody-domain separation. If those checks are
unavailable or inconclusive, enrollment fails. The account verifies that the
exact reviewed binding is part of the authorized descriptor; it never accepts
an uncommitted independence claim.

## Complete Factor Descriptor

The exact type string is:

```text
PhilCoreV2RecoveryFactorDescriptorV2(
  uint8 descriptorVersion,
  bytes32 accountVersionId,
  bytes32 securityModelId,
  bytes32 recoveryDomainId,
  uint8 role,
  uint8 verifierKind,
  bytes32 publicVerificationMaterialHash,
  bytes32 credentialIdHash,
  bytes32 rpIdHash,
  bytes32 originPolicyHash,
  bytes32 independenceBindingHash,
  uint8 userVerificationPolicy,
  uint8 backupPolicy,
  uint8 authenticatorAttachmentPolicy,
  uint8 attestationPolicy,
  uint64 credentialGeneration
)
```

The commitment is:

```text
factorCommitment = keccak256(abi.encode(
  FACTOR_DESCRIPTOR_TYPEHASH,
  descriptorVersion,
  accountVersionId,
  securityModelId,
  recoveryDomainId,
  role,
  verifierKind,
  publicVerificationMaterialHash,
  credentialIdHash,
  rpIdHash,
  originPolicyHash,
  independenceBindingHash,
  userVerificationPolicy,
  backupPolicy,
  authenticatorAttachmentPolicy,
  attestationPolicy,
  credentialGeneration
))
```

No field is optional. Encoding is standard ABI encoding, never packed
encoding, JSON, concatenated text, CBOR, or implementation-defined ordering.
Every `bytes32` is exactly 32 bytes and every integer is range-checked before
encoding.

### Primary device

- role `0`;
- verifier kind `1`;
- valid P-256 public-material hash;
- nonzero credential-ID, RP-ID, origin-policy, and independence hashes;
- user verification `2`;
- single-device backup policy `1`;
- platform attachment `1`;
- verified device-bound attestation policy `1`;
- nonzero credential generation.

### Hardware security key

- role `1`;
- verifier kind `1`;
- valid P-256 public-material hash;
- nonzero credential-ID, RP-ID, origin-policy, and independence hashes;
- user verification `2`;
- single-device backup policy `1`;
- cross-platform attachment `2`;
- verified external-hardware attestation policy `2`;
- nonzero credential generation.

A synced/multi-device passkey is rejected for this role. An authenticator for
which PhilCore cannot establish external-hardware classification and
independence is also rejected. The design does not downgrade to a
self-asserted hardware label.

### Independent recovery factor

- role `2`;
- verifier kind `2`;
- purpose-bound secp256k1 signer-material hash;
- zero credential-ID, RP-ID, and origin-policy hashes;
- nonzero independently reviewed custody binding;
- WebAuthn policy values all zero;
- nonzero credential generation.

The associated credential must remain offline or on a separately trusted
device. It cannot be the execution validator or a transaction-signing alias.

## Configuration Commitment

The corrected configuration type is:

```text
PhilCoreV2RecoveryConfigurationV2(
  uint8 configurationVersion,
  uint8 threshold,
  bytes32 primaryDeviceCommitment,
  bytes32 hardwareSecurityKeyCommitment,
  bytes32 recoveryFactorCommitment
)
```

Version is exactly `2`, threshold is exactly `2`, commitments are ordered by
role, and all three are nonzero and distinct. Public-material and
independence-binding hashes are also pairwise distinct; the two WebAuthn
credential-ID hashes must differ.

## Local And Public Storage

Protected local storage may retain:

- raw credential IDs;
- authenticator and attestation records;
- local credential references;
- custody metadata;
- replacement and revocation history.

The account stores only:

- the three factor commitments;
- the version-2 configuration hash;
- the recovery epoch and pending lifecycle state.

Complete public descriptors appear only in canonical one-time recovery
evidence so the account can recompute commitment membership. No private key,
credential private material, biometric information, recovery secret, proof
witness, or local approval record enters a descriptor or commitment.

## O.36.1 Correction

The O.36.1 `PhilCoreV2RecoveryFactor` commitment and version-1 factor evidence
remain historical compatibility evidence but are not accepted by a future V2
Solidity account. They lacked enough data to reconstruct origin policy and
credential generation. Descriptor and configuration version `2` are
mandatory for future implementation.
