# O.36.1 Hardware Recovery Interface Specification

Status: `SUPERSEDED_IN_PART_BY_O37_1`.

O.37.1 preserves the roles, verifiers, threshold, WebAuthn bounds, and
verification flow in this document, but supersedes the incomplete factor
commitment and version-1 factor evidence envelopes. Future Solidity must use
the complete descriptor/configuration version `2` and evidence version `2`
defined in
[O.37.1 Cryptographic Descriptor Specification](./O37_1_CRYPTOGRAPHIC_DESCRIPTOR_SPECIFICATION.md)
and
[O.37.1 Recovery Evidence Specification](./O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md).

This specification closes the recovery-factor architecture gate identified by
O.36. It defines public commitments and verification interfaces only. It
creates no credential, assertion, signature, UserOperation, Solidity, or
public mutation.

## Fixed Three-Domain Model

The recovery threshold is exactly two distinct roles out of:

| Role | ID | Fixed verifier | Independent domain |
| --- | ---: | --- | --- |
| primary device | `0` | WebAuthn P-256, kind `1` | device-bound PhilCore primary credential |
| hardware security key | `1` | WebAuthn P-256, kind `1` | cross-platform external authenticator |
| independent recovery factor | `2` | purpose-bound secp256k1, kind `2` | offline package or separately trusted device |

The initial V2 account version accepts no other role, verifier kind, or
threshold. A threshold commitment, social guardian assertion, managed
operator, generic EOA transaction signature, synced copy of the primary
credential, or credential stored in the same Device Vault is not a valid
factor.

The ordinary execution validator is not one of these three roles and cannot
be counted toward the threshold.

## Canonical Factor Commitment

O.32's type string and field order remain unchanged:

```text
PhilCoreV2RecoveryFactor(
  bytes32 accountVersionId,
  bytes32 securityModelId,
  uint8 role,
  uint8 verifierKind,
  bytes32 publicVerificationMaterialHash,
  bytes32 rpIdHash,
  bytes32 originPolicyHash,
  uint8 userVerificationPolicy,
  uint64 credentialGeneration
)
```

The commitment is:

```text
factorCommitment = keccak256(
  abi.encode(
    RECOVERY_FACTOR_TYPEHASH,
    accountVersionId,
    securityModelId,
    role,
    verifierKind,
    publicVerificationMaterialHash,
    rpIdHash,
    originPolicyHash,
    userVerificationPolicy,
    credentialGeneration
  )
)
```

For WebAuthn roles:

```text
publicVerificationMaterialHash = keccak256(
  abi.encode(
    keccak256(
      "PhilCoreV2WebAuthnPublicMaterial(bytes32 qx,bytes32 qy)"
    ),
    qx,
    qy
  )
)
```

- `qx` and `qy` are one valid P-256 public point;
- `rpIdHash` and `originPolicyHash` are nonzero;
- user-verification policy is exactly `2`, meaning required;
- credential generation is nonzero.

For the independent recovery role:

```text
publicVerificationMaterialHash = keccak256(
  abi.encode(
    keccak256(
      "PhilCoreV2Secp256k1PublicMaterial(address signer)"
    ),
    signer
  )
)
```

- `signer` is nonzero;
- `rpIdHash` and `originPolicyHash` are zero;
- user-verification policy is exactly `0`, not applicable;
- credential generation is nonzero.

The three factor commitments and all public verification material hashes must
be pairwise distinct. The execution-validator address or public-material hash
must not equal a recovery factor's signer/material hash.

The recovery-configuration hash remains the exact O.32 version-`1`,
threshold-`2` hash over the ordered role commitments.

## Public Witness Envelopes

The outer recovery envelope is canonical ABI encoding of:

```text
RecoveryAuthorityEnvelopeV1 {
  uint8 envelopeVersion       // exactly 1
  uint8 authorityKind         // exactly 2: recovery factors
  uint64 recoveryEpoch
  uint8 factorBitmap
  bytes firstFactorEvidence
  bytes secondFactorEvidence
}
```

Only bitmaps `0b011`, `0b101`, and `0b110` are accepted. Evidence is ordered
by increasing role ID. The account decodes each evidence item with the
verifier fixed by the stored role descriptor; calldata cannot select a
different verifier.

WebAuthn evidence is canonical ABI encoding of:

```text
WebAuthnFactorEvidenceV1 {
  uint8 envelopeVersion       // exactly 1
  uint8 role
  uint8 verifierKind          // exactly 1
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

Purpose-bound secp256k1 evidence is canonical ABI encoding of:

```text
Secp256k1FactorEvidenceV1 {
  uint8 envelopeVersion       // exactly 1
  uint8 role                  // exactly 2
  uint8 verifierKind          // exactly 2
  address signer
  bytes32 r
  bytes32 s
  uint8 v
}
```

O.37 must reject appended data and noncanonical encodings by checking exact
outer shape, bounded dynamic lengths, and byte-for-byte equality with a
canonical re-encoding. `authenticatorData` is bounded to 37--1024 bytes and
`clientDataJSON` to 1--2048 bytes. Indices must fall entirely within the
supplied JSON and cannot overlap an alternate type or challenge value.

Evidence bytes are public one-time transaction calldata. They are never
stored or emitted.

## Verification Flow

### Enrollment and Runtime

Trust Manager and Runtime:

1. perform the protected registration ceremony;
2. verify RP ID, origin policy, attestation policy, user verification, public
   key validity, and credential independence;
3. reject a synced/platform credential for the external hardware role;
4. reject key or role reuse and any factor derived from Phil identity
   material;
5. store private references and attestation metadata only in protected local
   storage;
6. produce only the public role descriptor and commitment for account
   initialization;
7. later obtain two fresh witnesses over the exact recovery digest.

Runtime verification is defense in depth. Runtime does not return a Boolean
claim that the account trusts in place of cryptographic evidence.

### Account

The account:

1. selects the required recovery authority from the typed action selector;
2. checks current recovery state, epoch, configuration hash, bitmap, nonce
   lane, action, validity, chain, account, EntryPoint, and UserOperation hash;
3. requires exactly two ordered distinct current roles;
4. reconstructs each public-material hash and factor commitment;
5. compares each commitment with the stored role commitment;
6. verifies each factor over the exact O.32 recovery digest;
7. rejects the complete authority if either factor fails.

For WebAuthn, the account verifies:

- exact `webauthn.get` type;
- exact base64url challenge representation of the recovery digest;
- P-256 signature with low-s enforcement;
- user-present and user-verified flags;
- valid backup-eligibility/backup-state relationship;
- authenticator-data RP ID hash equals the committed RP ID hash;
- valid P-256 public point and committed `qx`,`qy`.

The fixed OpenZeppelin verifier intentionally does not establish enrollment
attestation, credential independence, browser origin policy, or signature
counter history. Trust Manager verifies those facts locally. The browser and
authenticator enforce origin/RP ceremony rules, while the account
independently checks the signed RP ID hash and exact challenge.

For secp256k1, the account requires nonzero `r` and `s`, low `s`, canonical
`v` of `27` or `28`, and exact recovery of the committed signer. Personal-sign
prefixes, transaction signatures, ERC-1271 dispatch, and arbitrary-message
fallback are prohibited.

## Trust Assumptions

- The reviewed WebAuthn/P-256 library correctly parses and verifies the
  bounded assertion.
- Authenticators enforce credential use for the registered RP.
- Trust Manager's enrollment record correctly classifies the primary and
  hardware credentials as independent failure domains.
- The independent recovery credential remains offline or on a separately
  trusted device.
- Two compromised factor domains can recover the account; one cannot.
- Ethereum does not verify PhilCore's local STARK proof.

## Failure Cases

Fail closed on:

- zero, duplicate, reordered, or role-incompatible commitments;
- unsupported verifier kind, role, threshold, or configuration version;
- one factor, three factors, wrong bitmap, duplicate evidence, or wrong
  evidence order;
- wrong account, chain, EntryPoint, action, request, UserOperation hash,
  configuration, epoch, nonce, validity, or challenge;
- malformed or oversized WebAuthn input;
- invalid P-256 point/signature, missing UP/UV, wrong RP ID hash, or invalid
  backup flags;
- malformed, high-s, wrong-signer, or noncanonical secp256k1 evidence;
- factor/validator key reuse;
- any verifier selected by calldata, registry, module, proxy, or
  delegatecall;
- any recovery path that calls an asset or transfers value.

Implementation gas measurements and adversarial parser tests remain mandatory
O.37 acceptance evidence. A gas failure must stop O.37; it cannot justify
removing the hardware role or weakening threshold semantics.
