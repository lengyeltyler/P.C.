# O.39 Consumer Recovery Architecture

Canonical phase: **O.39 Consumer Recovery Model Revision, Implementation,
and Initialization Readiness**.

Classification:
`LOCAL_ONLY_RECOVERY_ARCHITECTURE_IMPLEMENTATION_AND_INTEGRATION`.

O.39 replaces the mandatory hardware-key recovery product policy with three
fixed recovery roles:

1. **Primary Device** — a recovery-only P-256 WebAuthn credential, separate
   from the normal execution validator.
2. **Independent Secondary Authenticator** — either a secondary platform
   device or an external hardware security key.
3. **Independent Offline Recovery Factor** — a recovery-only secp256k1
   authority exported outside both device custody domains.

The on-chain rule remains exact 2-of-3. Valid bitmaps remain `3`, `5`, and
`6`, roles remain `0`, `1`, and `2`, and the validator never counts as a
recovery factor.

## Profiles and product boundary

The Runtime exposes two reviewed profiles:

- **Standard:** primary device, secondary trusted platform device, offline
  factor.
- **Enhanced:** primary device, external hardware security key, offline
  factor.

Profile names are not on-chain authorities. The account sees only the three
ordered commitments and exact threshold. “Advanced” remains a future
Runtime policy concept and adds no module, role, or threshold in O.39.

## Descriptor V3 and configuration V3

Historical descriptor/configuration V2 remains traceable in the O.37
fixtures. O.39 does not reinterpret it. The current package accepts one
canonical V3 recovery descriptor:

```text
keccak256(abi.encode(
  keccak256("PhilCoreV2RecoveryFactorDescriptorV3(...)"),
  3,
  accountVersionId,
  securityModelId,
  keccak256("PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V3"),
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

The V3 account version is
`keccak256("philcore-v2-minimal-account-v3-consumer-recovery")` =
`0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f`.

The independence binding is V2:

```text
keccak256(abi.encode(
  keccak256("PhilCoreV2RecoveryIndependenceBindingV2(...)"),
  2,
  role,
  authenticatorClass,
  synchronizationClass,
  independenceAssurance,
  credentialIdHash,
  enrollmentCeremonyHash,
  attestationEvidenceHash,
  custodyDomainCommitment,
  credentialGeneration
))
```

The recovery configuration is:

```text
keccak256(abi.encode(
  keccak256("PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"),
  3,
  2,
  role0Commitment,
  role1Commitment,
  role2Commitment
))
```

Role 0 permits only a platform, device-bound, user-verified P-256 credential.
Role 1 permits exactly one of two canonical tuples: platform/device-bound
for a secondary device, or cross-platform/external-hardware for a security
key. Role 2 permits only the purpose-bound secp256k1 offline format.

## Independence policy

Cryptographically enforced facts are the distinct public material,
credential-ID commitments for roles 0 and 1, role, descriptor/configuration
version, RP ID hash, origin-policy hash, generation, account/security/domain
binding, and exact descriptor membership. Device-bound assertions must have
UP and UV set and both WebAuthn BE and BS flags clear.

Locally observed facts are authenticator attachment, registration metadata,
backup eligibility/state, verified attestation evidence, and distinct
enrollment events. The Runtime captures them and binds their evidence hashes.

User-attested facts are separate physical control, separate custody domain,
and non-reliance on the same cloud or password-manager domain. WebAuthn
cannot prove separate Apple IDs, Google accounts, password managers, family
custody, or cloud-backup domains. The UI must say so.

Duplicate public material, credential-ID commitments, and custody-domain
commitments fail. A changed factor must increment its generation by exactly
one; unchanged factors must retain their generation. Role 2 is compared
directly with the execution-validator address. P-256 recovery credentials
are a distinct verifier kind from the secp256k1 execution validator and may
not be substituted into validator authority.

## Synchronized-passkey policy

O.39 records BE and BS from authenticator data. A Role 0 or Role 1
credential with either bit set is **not deployable**. Unknown or
degraded-independence enrollment is also not deployable. This is stricter
than merely showing a warning: the V3 static verifier independently rejects
BE/BS during recovery assertion verification.

Future work may review a separately versioned degraded profile. It must not
silently receive the same assurance as a demonstrably device-bound
credential.

## Authority transport compatibility

The O.37.4 outer transport is byte-for-byte unchanged:

- recovery envelope version remains `2`;
- authority kind remains `2`;
- role IDs and bitmaps are unchanged;
- combined validator-plus-recovery envelope remains the only format for
  configuration rotation;
- validator envelope and success magic are unchanged.

Only the inner descriptor commitment, recovery-domain ID, account-version
ID, and recovery-configuration hash changed. Historical V2 recovery
envelopes therefore fail closed. The verifier does not implement permissive
multi-version decoding.

## Solidity impact and security boundary

Solidity changes were required because the retained verifier hard-coded
Role 1 as cross-platform hardware with external-hardware attestation. The
versioned verifier now accepts the two canonical Role 1 policy tuples and
accepts only descriptor/configuration V3. Account and factory use the new
account version and configuration hash. ABI and account storage are
unchanged; legacy ABI component names such as
`hardwareSecurityKeyCommitment` now mean the ordered Role 1 commitment.

The factory still pins verifier address and runtime code hash. There is no
registry, administrator, proxy, upgrade, `delegatecall`, caller-selected
verifier, session key, module, arbitrary execution, paymaster policy, or
token surface. EntryPoint nonce ownership, native-ETH-only execution,
recovery delay/expiry, validator exclusion, and configuration-rotation
authority are unchanged.

The changed bytecode invalidates O.38 deployment-readiness evidence. A
future readiness gate must regenerate every artifact and initialization
binding before any deployment.

## Threat analysis

- **Shared cloud compromise:** synced or backup-eligible credentials are
  rejected, but cloud-domain separation remains partly user-attested.
- **Primary loss:** secondary plus offline can recover.
- **Secondary loss:** primary plus offline can recover.
- **Offline theft:** one factor cannot recover; theft becomes critical only
  with compromise of either device factor.
- **Family-member device:** enrollment requires informed consent, custody
  disclosure, removal/replacement planning, and an availability plan.
- **Hardware key:** stronger independence is available, with explicit loss,
  PIN, backup-key, and replacement risks.
- **Enrollment substitution:** role/account/domain bindings, verified RP and
  origin, ceremony hashes, custody commitment, and final commitment review
  resist credential or QR/deep-link substitution. The UI must compare the
  staged device and profile before locking the initialization package.
- **Offline export:** loss is unrecoverable; theft, photography, cloud-photo
  sync, co-location with a device, and an untested copy are material risks.

No PhilCore server, SMS, email, password, security question, social recovery,
or custodian is introduced.
