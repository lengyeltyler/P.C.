# Phil V1 Secure Identity Architecture

Status: Accepted architecture source of truth

Accepted by: ACP-0003 Step 1

Implementation status: Architecture frozen; runtime implementation pending

## 1. Product Contract

Phil is a device-first personal security operating system. It gives one person
a private, recoverable cryptographic identity root and uses that root to
control encrypted data, devices, wallets, credentials, applications, and AI
agents across multiple networks without exposing the root secret.

The root is not a wallet, chain account, device key, passkey, proof system,
recovery share, storage provider, application, or agent. All of those are
replaceable authorities or consumers scoped beneath the root.

```text
Private Phil identity root
  -> encrypted identity and data vault
  -> user-controlled identity/data recovery
  -> enrolled device approval keys
  -> pairwise scoped public identities
  -> policy and revocable capabilities
  -> network, credential, application, and agent adapters
```

This document freezes the Phil V1 product architecture. It deliberately does
not select a production proof backend or authorize code, device, deployment,
signing, RPC, or public-network work.

## 2. Evidence And Claim Classes

Every security claim must be labeled as one of:

- `implemented`: present in product source and covered by the stated local
  tests;
- `prototype`: isolated synthetic feasibility evidence only;
- `externally_reviewed`: reviewed by an identified independent party for the
  exact version and scope;
- `production_approved`: separately accepted after implementation, device,
  audit, release, recovery, and operational gates; or
- `unverified`: not yet established.

Source publication, local test success, testnet deployment, platform
attestation, external audit, and production approval are distinct gates. None
implies another.

## 3. Canonical Root Identity

### 3.1 Root material

`phil_secret` remains the only canonical Phil V1 root witness.

Normative format:

- exactly 32 bytes;
- non-zero;
- current compatibility range: unsigned integer `< 2^251`; and
- generated from a cryptographically secure random source inside the protected
  runtime.

The existing derivation is preserved byte-for-byte:

```text
identityRoot =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_IDENTITY_ROOT_V1")),
      bytes32(phil_secret)
    )
  )

rootOwnerCommitment =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_OWNER_COMMITMENT_CANONICAL_V1")),
      bytes32(identityRoot)
    )
  )
```

`rootOwnerCommitment` is the new semantic name for the existing canonical
`ownerCommitment` value. Existing source, fixtures, contracts, and schemas may
continue to call it `ownerCommitment` until a later versioned implementation
migration. The bytes do not change.

### 3.2 Privacy classification

The following are protected identity-continuity material by default:

- `phil_secret`: secret;
- `identityRoot`: secret-derived protected material; and
- `rootOwnerCommitment`: protected correlation handle.

Neither `identityRoot` nor `rootOwnerCommitment` is a universal public Phil ID.
They must not appear by default in network accounts, public credentials,
application manifests, agent records, analytics, logs, service endpoints, or
cross-network payloads.

An explicit recovery, migration, audit, or deliberate-linking ceremony may
reveal `rootOwnerCommitment` to a narrowly identified verifier when policy
requires it. That disclosure is high risk, user approved, purpose bound,
audited, and never implied by ordinary use.

The current SDK type named `PhilIdentityPublic` is compatibility code, not the
accepted cross-network privacy boundary. Later implementation must replace or
constrain that exposure without silently changing existing bytes.

## 4. Scoped Public Identity

Phil exposes a different public commitment for each relationship by default.

### 4.1 Scope kinds

The frozen `scopeKind` values are:

| Value | Name | Intended relationship |
| ---: | --- | --- |
| `1` | `network_account` | One network/account relationship |
| `2` | `application` | One application relationship |
| `3` | `credential_relationship` | One issuer/verifier relationship |
| `4` | `agent` | One AI or automation principal |
| `5` | `persona` | One user-selected persona |
| `255` | `custom` | Future versioned use after review |

Values `0` and `6..254` are reserved and must be rejected in V1.

### 4.2 Scope descriptor

Every scope uses the exact fixed-width descriptor:

```text
PhilScopeDescriptorV1 {
  uint8   scopeKind;
  bytes32 namespaceHash;
  bytes32 contextHash;
}
```

`namespaceHash` and `contextHash` are hashes of adapter-registered canonical
bytes. Each adapter specification must publish the exact canonicalization and
test vectors before it can create product authority. For network adapters,
`namespaceHash` must include the canonical CAIP-2 chain identifier. For
application, credential, and agent relationships, the canonicalization must
include the stable application/origin, issuer/verifier, or agent principal
identifier respectively.

```text
scopeId =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_IDENTITY_SCOPE_V1")),
      uint8(scopeKind),
      bytes32(namespaceHash),
      bytes32(contextHash)
    )
  )
```

### 4.3 Scoped commitment

Each relationship also has:

- `scopeInstance`: a random, non-zero `bytes32` generated for that independent
  relationship; and
- `scopeEpoch`: a non-zero `uint64`, starting at `1` and incremented for a
  scoped-identity rotation.

```text
scopedOwnerCommitment =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_SCOPED_OWNER_COMMITMENT_V1")),
      bytes32(identityRoot),
      bytes32(scopeId),
      bytes32(scopeInstance),
      uint64(scopeEpoch)
    )
  )
```

`identityRoot` remains private in this derivation. A verifier receives only the
scoped commitment and the scope data that its relationship requires.

Different `scopeInstance` values allow multiple unlinkable accounts or
relationships inside the same namespace. The encrypted identity recovery
package must preserve `scopeId`, `scopeInstance`, and `scopeEpoch` so the same
scoped identity can be restored. Losing that registry creates a new scoped
identity even if the root survives.

### 4.4 Deliberate linking

No adapter may infer or assert that two scoped commitments share a root. A
cross-scope link requires:

- exact source and destination scoped commitments;
- a purpose hash;
- the requesting verifier/principal hash;
- a one-time link nonce;
- an expiry;
- explicit high-assurance user approval; and
- an admitted witness-hiding proof whose public inputs bind the complete link
  request.

Link authorization is one-time, purpose bound, and audited. It does not reveal
`identityRoot` or `rootOwnerCommitment`.

## 5. Encrypted User-Controlled Data

Phil separates identity continuity, data encryption, and device approval.

Required key classes:

- `K_data_root`: random 32-byte root for encrypted user data and record-key
  wrapping;
- `K_backup`: random 32-byte key for one identity/data recovery epoch; and
- per-record data-encryption keys or an admitted deterministic record-key
  derivation beneath `K_data_root`.

`K_data_root` must not be derived from `phil_secret`, a device signature key,
an account validator key, or a recovery share. Compromise or rotation of one
authority must not automatically compromise the others.

Every encrypted record must bind authenticated metadata including:

```text
PhilEncryptedRecordHeaderV1 {
  bytes32 formatVersionHash;
  bytes32 encryptionSuiteId;
  bytes32 recordId;
  bytes32 recordTypeHash;
  uint64  recordVersion;
  uint64  dataEpoch;
  bytes32 scopedOwnerCommitmentOrZero;
}
```

The exact authenticated-data hash is:

```text
recordAadHash =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_DATA_RECORD_AAD_V1")),
      formatVersionHash,
      encryptionSuiteId,
      recordId,
      recordTypeHash,
      recordVersion,
      dataEpoch,
      scopedOwnerCommitmentOrZero
    )
  )
```

An admitted encryption suite defines how `recordAadHash` is supplied to the
AEAD. No suite may omit or reinterpret it.

Storage may be local or user selected. Remote, cloud, and decentralized
storage providers receive ciphertext and the minimum routing metadata. Public
networks receive commitments, status, or proofs rather than personal data.

Phil controls keys, consent, local deletion, encrypted export, portability,
and disclosure. Phil cannot revoke plaintext already copied by a recipient or
erase data intentionally published to an immutable public network.

## 6. Identity And Data Recovery

Account-validator recovery is not Phil identity/data recovery.

### 6.1 Key separation

The recovery quorum reconstructs or unwraps only `K_backup`. It never directly
shares `phil_secret`, `K_data_root`, a device private key, or an account
validator private key.

`K_backup` authenticated-encrypts one continuity package containing the root
and the data key. A user-controlled `2-of-3` mechanism protects `K_backup`.
The Step 2 local candidate selects the suite-identified
`phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1` construction: each holder has
two independent pair contributions, each exact pair derives one pair-specific
key-encryption key, and three authenticated pair wrappers protect one random
`K_backup`. One holder has no complete pair key. This custom composition is
not production-admitted until independent cryptographic review passes.

No single Phil service, storage provider, application, network, account,
device, or recovery holder may reconstruct `K_backup` alone.

### 6.2 Public envelope

```text
PhilRecoveryEnvelopeV1 {
  bytes32 formatVersionHash;
  bytes32 encryptionSuiteId;
  bytes32 sharingSuiteId;
  bytes32 recoverySetId;
  uint64  recoveryEpoch;
  uint64  packageCounter;
  uint64  createdAt;
  bytes32 ciphertextHash;
}
```

`recoverySetId` is random, non-zero, and changes whenever shares are replaced.
`recoveryEpoch` starts at `1` and increases after completed recovery or a full
recovery-set rotation. `packageCounter` increases for every package written in
an epoch. Readers reject lower epochs or counters than the greatest accepted
local/reconciled value.

```text
recoveryPackageAadHash =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_RECOVERY_PACKAGE_AAD_V1")),
      formatVersionHash,
      encryptionSuiteId,
      sharingSuiteId,
      recoverySetId,
      recoveryEpoch,
      packageCounter,
      createdAt
    )
  )
```

The public envelope must not contain `identityRoot`, `rootOwnerCommitment`,
scope registry entries, account addresses, credential identifiers, or personal
data. `ciphertextHash` commits to the exact encrypted payload after encryption
and is not included recursively in `recoveryPackageAadHash`.

### 6.3 Encrypted continuity package

The authenticated encrypted payload must contain:

```text
PhilIdentityContinuityPackageV1 {
  bytes32 identitySuiteId;
  bytes32 philSecret;
  bytes32 identityRoot;
  bytes32 rootOwnerCommitment;
  bytes32 dataRootKey;
  uint64  dataEpoch;
  uint64  deviceEpoch;
  uint64  recoveryEpoch;
  uint64  validatorEpoch;
  uint64  capabilityEpoch;
  ScopeRecordV1[] scopeRegistry;
  AccountBindingRecordV1[] accountBindings;
  CredentialRecordV1[] credentialRegistry;
  PolicyStateV1 policyState;
  CapabilityRevocationStateV1 capabilityRevocationState;
  AuditContinuityStateV1 auditContinuityState;
}
```

Dynamic records require their own canonical versioned codecs and integrity
hashes before Step 2 implementation. After decryption the runtime must:

1. normalize `philSecret`;
2. recompute `identityRoot` and `rootOwnerCommitment`;
3. reject any mismatch;
4. validate every scope record and account binding;
5. validate epochs and anti-rollback state; and
6. authenticate the encrypted data vault before any authority is restored.

### 6.4 Material that never resumes automatically

Recovery must not restore or reactivate:

- device private keys;
- Secure Enclave, passkey, App Attest, or platform-attestation private keys;
- active User Sessions;
- pending approvals, signatures, proofs, transactions, or nullifier seeds;
- active agent or application capabilities;
- reusable proof randomness; or
- unverified pending network state.

After recovery, Phil increments `deviceEpoch`, `recoveryEpoch`, and
`capabilityEpoch`; suspends all prior capabilities; treats prior devices as
revoked or pending reconciliation; enrolls a new device through a recovery-only
ceremony; and requires explicit reconciliation before network account control
is resumed.

## 7. Device Approval

Device keys are replaceable approval factors, not the Phil identity.

```text
PhilDeviceEnrollmentRecordV1 {
  bytes32 deviceId;
  bytes32 deviceKeyId;
  bytes32 signatureSuiteId;
  bytes   publicKey;
  bytes32 publicKeyHash;
  uint64  deviceEpoch;
  uint64  enrolledAt;
  uint64  revokedAt;
  uint8   status;
  uint8   assuranceClass;
  bytes32 attestationEvidenceHash;
  bytes32 policyHash;
}
```

Device status values are `1=active`, `2=suspended`, `3=revoked`, and
`4=recovery_pending`. Value `0` and all other values are rejected.

The private key is generated by the strongest admitted platform hardware,
marked non-exportable when the platform permits, and never placed in the
recovery package. Apple documents Secure Enclave P-256, ML-DSA-65, and
ML-KEM-768/1024 on supported iOS 26+ platforms. Phil has physically verified
only its bounded P-256 source path. ML-DSA and ML-KEM remain candidate
capabilities until exact Phil integration, lifecycle, recovery, and device
evidence pass. Phil must never claim that `phil_secret` is imported into or
executed by the enclave.

Platform/App Attest evidence may raise an evidence classification after
server-side verification. It never creates identity, replaces user approval,
or becomes recovery authority.

For sensitive actions the device signs:

```text
deviceApprovalDigest =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_DEVICE_APPROVAL_V1")),
      authorizationEnvelopeDigest,
      deviceId,
      deviceKeyId,
      deviceEpoch,
      approvalNonce,
      approvedAt,
      approvalExpiresAt
    )
  )
```

The approval UI must display a deterministic human presentation whose hash is
already bound into `authorizationEnvelopeDigest`. Approval is one-time,
expires, and fails on digest, device, epoch, nonce, or time mismatch.

## 8. Authorization Classes

Phil V1 recognizes three sensitive-operation classes:

| Value | Class | Required authority |
| ---: | --- | --- |
| `1` | `routine` | Active scoped capability, enrolled device approval, policy, replay, limits, and adapter checks |
| `2` | `exceptional` | Admitted witness-hiding root proof **and** enrolled device approval, policy, replay, limits, and adapter checks |
| `3` | `recovery` | User-controlled recovery ceremony; authority is limited to restoring encrypted continuity and enrolling/reconciling devices/accounts |

Value `0` and values above `3` are rejected in V1.

Read-only public data access may occur outside these authority classes under
privacy policy. It creates no capability to mutate, sign, decrypt protected
data, or derive private identity material.

Exceptional operations include:

- first account/relationship enrollment from the Phil root;
- new device enrollment outside an already trusted migration path;
- identity/data recovery completion;
- validator or root-bound account rotation;
- recovery-set replacement;
- major security-policy or assurance downgrade;
- deliberate cross-scope linking; and
- issuance of a capability allowed to exceed the routine policy ceiling.

Policy may escalate a routine action to exceptional. It may never downgrade an
exceptional or recovery action to routine.

## 9. Scoped Capability Contract

Apps and agents receive capabilities, not root or wallet authority.

```text
PhilCapabilityGrantV1 {
  bytes32 formatVersionHash;
  bytes32 scopedOwnerCommitment;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  uint8   principalType;
  bytes32 principalIdHash;
  bytes32 applicationManifestHash;
  bytes32 allowedActionSetHash;
  bytes32 targetSetHash;
  bytes32 constraintHash;
  bytes32 policyHash;
  uint64  capabilityEpoch;
  uint64  deviceEpoch;
  uint64  issuedAt;
  uint64  validAfter;
  uint64  validUntil;
  uint64  maxUses;
  bytes32 grantNonce;
}
```

`principalType` values are `1=application`, `2=agent`, and `3=user_tool`.
Other values are rejected.

`formatVersionHash = keccak256(utf8("PHIL_CAPABILITY_GRANT_V1"))`.

```text
capabilityId =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_CAPABILITY_GRANT_V1")),
      every PhilCapabilityGrantV1 field in the order above
    )
  )
```

A routine use binds `capabilityId`, a monotonically enforced use nonce or
adapter-native replay key, and the current capability epoch. Expiry,
revocation, use count, action, target, value, fee, and policy constraints are
rechecked at authorization and immediately before execution.

An application or agent capability cannot grant capabilities, change its own
limits, modify identity/recovery/device/policy state, reveal root material, or
bypass user approval unless an explicit exceptional operation authorizes an
exact versioned action. Broad `approve_all`, unrestricted signing, generic
delegatecall, and unrestricted wallet capabilities are prohibited.

## 10. Chain-Agnostic Authorization Envelope

Every sensitive adapter action binds the following fixed-order envelope:

```text
PhilAuthorizationEnvelopeV1 {
  bytes32 formatVersionHash;
  uint8   operationClass;
  bytes32 scopedOwnerCommitment;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  bytes32 principalIdHash;
  bytes32 capabilityId;
  uint64  capabilityEpoch;
  bytes32 networkIdHash;
  bytes32 accountBindingHash;
  bytes32 adapterId;
  bytes32 actionTypeHash;
  bytes32 parametersHash;
  bytes32 intentDigest;
  bytes32 policyHash;
  bytes32 nonceDomain;
  uint256 nonce;
  bytes32 rootProofNullifier;
  uint64  validAfter;
  uint64  validUntil;
  uint256 valueLimit;
  uint256 feeLimit;
  uint64  deviceEpoch;
  uint64  recoveryEpoch;
  uint64  validatorEpoch;
  bytes32 deviceSignatureSuiteId;
  bytes32 proofDescriptorHash;
  bytes32 humanPresentationHash;
}
```

Rules:

- `formatVersionHash = keccak256(utf8("PHIL_AUTHORIZATION_ENVELOPE_V1"))`.
- `networkIdHash` is the hash of an adapter-canonical network identifier and is
  zero only for a reviewed non-network adapter action.
- `accountBindingHash` binds the exact existing or counterfactual account,
  credential, document, or resource authority and is never inferred from UI
  display text.
- `capabilityId` is required for routine actions and zero for exceptional and
  recovery actions.
- `rootProofNullifier` and `proofDescriptorHash` are required for exceptional
  actions and zero for routine actions.
- `deviceSignatureSuiteId` is required for routine and exceptional actions.
- recovery actions use a separate recovery-evidence descriptor in
  `parametersHash`; a missing old device signature can be replaced only for
  the narrow new-device enrollment/reconciliation operation authorized by the
  completed recovery ceremony.
- `validUntil` must be greater than or equal to `validAfter` and non-zero for
  every sensitive action.
- adapter-specific gas, fee, value, replay, calldata, credential, or document
  fields are committed by `parametersHash` and must also remain at or below
  the explicit envelope limits.

```text
authorizationEnvelopeDigest =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_AUTHORIZATION_ENVELOPE_V1")),
      every PhilAuthorizationEnvelopeV1 field after formatVersionHash
      in the order above, except rootProofNullifier
    )
  )
```

`rootProofNullifier` is the one intentional omission. Including it would create
an infeasible hash cycle because the exceptional-proof contract derives that
nullifier from `authorizationEnvelopeDigest`. For routine and recovery actions
the field is required to be zero. For exceptional actions the admitted proof
binds the public `rootProofNullifier` to this exact digest and the private
`nullifierSeed`; the composed account gate must verify the digest, proof, and
nullifier together. No adapter may omit or reinterpret any other envelope
field.

No adapter may add mutable, unsigned, uncommitted execution fields after this
digest is approved. Native transaction/account encoding may wrap the digest,
but the adapter must prove byte-for-byte that the native action enforces or is
bound to the same fields.

## 11. Exceptional Root-Proof Contract

Step 1 selects no proof backend. It freezes what an admitted exceptional proof
must prove.

Private witness:

- `phil_secret`;
- `nullifierSeed`; and
- private intermediates required to recompute `identityRoot` and the scoped
  commitment.

Public inputs, in order:

```text
PhilRootProofPublicInputsV1 {
  bytes32 scopedOwnerCommitment;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  bytes32 authorizationEnvelopeDigest;
  bytes32 rootProofNullifier;
  bytes32 proofDescriptorHash;
}
```

The circuit/program must:

1. normalize and derive the canonical root identity from `phil_secret`;
2. recompute `scopedOwnerCommitment` from the private `identityRoot` and public
   scope fields;
3. recompute the root-proof nullifier from the scoped commitment,
   authorization digest, recovery/capability epochs committed by that digest,
   and private `nullifierSeed`; and
4. enforce equality with all public inputs.

The target nullifier domain is `PHIL_ROOT_PROOF_NULLIFIER_V1`. The exact
logical nullifier is:

```text
rootProofNullifier =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_ROOT_PROOF_NULLIFIER_V1")),
      bytes32(scopedOwnerCommitment),
      bytes32(authorizationEnvelopeDigest),
      bytes32(nullifierSeed)
    )
  )
```

The authorization digest already binds the recovery and capability epochs. It
deliberately omits only `rootProofNullifier` to avoid a hash cycle; this proof
derives and binds that omitted field.
The exact backend-specific field packing and proof codec are not frozen until
a backend passes the admission gate; they may not alter the logical
public-input order or hash preimages above.

### 11.1 Proof descriptor

```text
PhilProofDescriptorV1 {
  bytes32 descriptorVersionHash;
  bytes32 proofSuiteId;
  bytes32 proofSystemVersionHash;
  bytes32 circuitOrProgramId;
  bytes32 publicInputSchemaId;
  bytes32 verificationKeyHash;
  bytes32 verifierCodeHash;
  bytes32 verifierBindingHash;
  bytes32 codecId;
}
```

`descriptorVersionHash = keccak256(utf8("PHIL_PROOF_DESCRIPTOR_V1"))`.

`verifierBindingHash` is not caller-selected metadata. It must equal:

```text
keccak256(
  abi.encode(
    keccak256(utf8("PHIL_VERIFIER_BINDING_V1")),
    proofSuiteId,
    proofSystemVersionHash,
    circuitOrProgramId,
    publicInputSchemaId,
    verificationKeyHash,
    verifierCodeHash,
    codecId
  )
)
```

```text
proofDescriptorHash =
  keccak256(
    abi.encode(
      keccak256(utf8("PHIL_PROOF_DESCRIPTOR_V1")),
      every descriptor field after descriptorVersionHash in the order above
    )
  )
```

An admitted backend must provide:

- a supported zero-knowledge/witness-hiding mode enabled by default;
- secure randomness and fail-closed randomness errors;
- canonical byte and public-input test vectors across every implementation;
- wrong-witness, wrong-scope, wrong-action, wrong-policy, wrong-nullifier,
  wrong-account, wrong-chain, wrong-epoch, malformed-proof, and replay tests;
- chosen-witness and repeated-proof leakage regression tests;
- target physical-device time, memory, battery, thermal, and interruption
  evidence;
- verifier size, cost, calldata, and failure measurements;
- pinned source, dependencies, circuit/program, keys, codec, and verifier;
- reproducible builds and release provenance;
- independent cryptographic and integration review; and
- a separate production enablement decision.

The current `stwo-unlock-keccak-v1` artifact fails witness hiding and is
ineligible. Noir/Barretenberg and RISC Zero remain prototype candidates only.

A root proof never establishes device possession, human approval, current
policy, account nonce, network fee limits, or revocation state by itself.

## 12. Network And Protocol Adapters

Every adapter must publish:

```text
PhilAdapterManifestV1 {
  bytes32 adapterId;
  bytes32 adapterVersionHash;
  uint8   adapterType;
  bytes32 networkIdHash;
  bytes32 accountModelId;
  bytes32 scopeCanonicalizationId;
  bytes32 actionCodecId;
  bytes32 replayModelId;
  bytes32 feeModelId;
  bytes32[] supportedDeviceSignatureSuiteIds;
  bytes32[] supportedProofSuiteIds;
  uint8   postQuantumCapability;
  bytes32 implementationHash;
  bytes32 auditStatusHash;
}
```

`adapterType` values are `1=network_account`, `2=credential`, `3=document`,
`4=application_service`, and `5=agent_execution`.

`postQuantumCapability` values are:

- `0=none`;
- `1=local_policy_only`;
- `2=onchain_or_protocol_hybrid`; and
- `3=onchain_or_protocol_native`.

Adapters receive only the minimum scoped identity, authorization envelope,
capability/device evidence, admitted proof evidence when exceptional, and
adapter-specific payload. They never receive `phil_secret`, `identityRoot`,
`rootOwnerCommitment`, `K_data_root`, `K_backup`, recovery shares, vault keys,
or unrestricted device/account signing handles.

If a network cannot enforce an envelope property, the adapter must identify it
as `local_policy_only`; Phil must not present it as an on-chain guarantee.

Starknet is the reference private-proof adapter. Ethereum/Base is the first
existing execution implementation. The separately authorized Step 6A candidate
now defines a local-only Base/ERC-4337 routine-action binding, but it verifies
no signature, creates no UserOperation, and grants no network authority.
The separately authorized Step 6B candidate consumes that binding in one
isolated local ERC-4337 account, verifies a synthetic P-256 approval, and
enforces an immutable narrow capability policy with exact-once execution. It
does not establish official EntryPoint or Base integration. Independent review
found no source bypass but rejected incomplete
committed negative coverage. A bounded corrective test candidate now covers
the omitted branches without changing the production account source and
was independently re-reviewed. Every category except one timestamp-shadowed
action-start test was confirmed. A second bounded correction now schedules and
observes the actual transaction before `validAfter`, changes neither production
account nor harness source, and was independently accepted as exact candidate
`d65aa5d734de8dd93a524d5a45eb31de7a012ceb` after that execution timing was
reproduced. Step 6B is complete as a local synthetic gate; Step 6 remains
incomplete. Independent review rejected exact Step 6C definitions `fdf3c2e`
and `a24873e`; the latter closed the original seven defects but retained four
high-severity target-runtime, crash-evidence, Solidity-calldata, and transport-
byte gaps. The second corrective definition uses an acyclic raw-
record graph so the iPhone derives its display, a separate signed chain-`31337`
environment, a new versioned Secure Enclave SHA-256-prehash/raw low-S profile,
normally deployed official EntryPoint v0.7, its keyed nonce as the sole
sequence, an immutable Step 5 epoch-1 boundary with a separate local V2
profile, signs the target runtime, persists exact local/official operation
evidence, freezes selector `0x5a99466a` and all tuples, and publishes literal
QR/HTTP/frame/journal bytes. It preserves Step 2 DER and Step 6B synthetic
evidence under their original meanings. Separately authorized Step 6C-1
implementation stopped before a source candidate after exposing a nonce-
catalog/policy contradiction in accepted definition `227bd48`. A bounded third
corrective definition now separates stable schema/capability/catalog/policy
identities from every nonce-bearing signed request. Exact status-correction
candidate `fcc0103`, tree `209df24`, was independently accepted; bounded Step
6C-1 synthetic local implementation resumed. Source candidates `a158688`,
`aea7359`, `591f6b6`, and `5ab4650` were independently rejected and are
superseded. Corrective source commit `6f048eb`, tree `a9032b2`, is frozen with
disclosed-synthetic artifacts and 37 focused passing cases. Exact candidate `22b5cf3`, tree
`2b0ff7f`, is independently accepted for the bounded Step 6C-1 local gate.
Step 6C-2 exact source candidate `4a81b08`, tree `188d7d0`, was independently
accepted after five superseded candidates. A separately authorized Step 6C-3
ceremony stopped on product defects; corrective source and packaging changes
were independently reviewed, and the fresh ceremony completed one real-iPhone
harmless authorization, verified its local receipt, and deleted both disposable
sides without changing identity or recovery state. Exact complete physical
evidence `0461ac7`, tree `c14838c`, was independently accepted. Step 6C and the
bounded six-step local architecture/composition route are complete. Additional
physical-device, public-network, and production work remain unauthorized.
Neither network defines Phil identity.

## 13. Post-Quantum And Algorithm Agility

Every cryptographic object carries an immutable suite identifier. At minimum:

- `identitySuiteId`;
- `scopedCommitmentSuiteId`;
- `encryptionSuiteId`;
- `sharingSuiteId`;
- `deviceSignatureSuiteId`;
- `validatorSignatureSuiteId`;
- `proofSuiteId`;
- `publicInputSchemaId`; and
- `verifierCodeHash` or equivalent verifier binding.

Suite identifiers are `keccak256(utf8(exact versioned suite name))`. An
algorithm, parameter set, byte encoding, key format, proof codec, or verifier
must never be changed under an existing suite identifier.

Every migration defines:

- old and new suite IDs;
- enrollment and verification overlap;
- downgrade prevention;
- hybrid requirements where supported;
- account/address migration effects;
- recovery behavior independent from the retiring suite;
- explicit user approval; and
- retirement and emergency rollback rules.

Current Phil is not post-quantum secure. P-256, secp256k1, existing account
validators, current recovery authorities, and the leading Noir/Honk prototype
are classical. A network can receive a PQ claim only when its native or
on-chain validator enforces the identified PQ scheme. Local policy cannot be
marketed as network-level PQ enforcement.

The independently accepted Step 5 architecture freezes the concrete registry,
hybrid-AND, candidate non-activation, network evidence, and migration ceremony rules in
[the Post-Quantum Migration Gate](./reference/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md).
Apple Secure Enclave ML-DSA-65 signing and ML-KEM support are treated as
platform-documented candidates; current admitted Phil device authorization
remains P-256 because neither PQ path has Phil integration or physical-device
evidence. Capabilities and policies bind the complete registry, exact
proof/verifier compatibility, and protected trusted freshness/provenance
state, including the exact current policy hash. A same-network ceremony may
move to a higher capability record without permitting rollback. A second
bounded correction also fixes the concrete secp256k1, SHA-256, and Apple
P-256 ECIES/X9.63 implementation bindings and rejects a forged trusted-state
format. Exact candidate `d1de608` was independently accepted with no unresolved
finding. This completes the local Step 5 architecture gate without claiming
PQ security, selecting a production backend, or authorizing deployment. Step 6
was separately authorized; its first Step 6A Base adapter candidate remained
local-only and was independently rejected for incomplete committed negative-
test evidence and a stale roadmap status. The omitted source branches failed
closed under independent probing, but a bounded corrective candidate is still
required. That bounded correction added the omitted deterministic tests and
reconciled current status without changing adapter source. Exact corrective
candidate `6719368` was
independently accepted with no unresolved finding, completing the Step 6A
local binding gate without establishing device-signature verification, a Base
authorization path, or production authority. The separately authorized Step
6B candidate adds synthetic local device-signature verification and one narrow
local account surface while granting no Base or production authority. The
first exact Step 6B candidate
was rejected only for incomplete committed adversarial coverage; the bounded
correction changes test evidence, not the accepted identity or account
semantics. Re-review rejected only one timestamp-shadowed test; the second
correction changes the test schedule and observed timestamp only. Exact
candidate `d65aa5d` was independently accepted after the corrected timestamp
path was reproduced. Step 6B is complete as a local synthetic gate; Step 6
remains incomplete. The first Step 6C definition and first corrective were
rejected; the accepted second corrective later proved internally inconsistent
during implementation. The bounded third corrective is now the accepted
current definition. Its suite/provider/wire
identities separate Phil's terminal Keccak request ID from Apple's SHA-256
digest-signing input and the contract's raw low-S `(r,s)` encoding. It retains
EntryPoint v0.7 only in a normally deployed chain-`31337` local environment;
any public EntryPoint is a separately admitted adapter/account migration. The
accepted Step 5 registry remains immutable; the local V2 signature profile
inherits rather than rewrites it. Exact status-correction candidate `fcc0103`,
tree `209df24`, was independently accepted, and bounded Step 6C-1 synthetic
implementation resumed. Candidates `a158688`, `aea7359`, `591f6b6`, and
`5ab4650` were independently rejected and are superseded. Corrective source
commit `6f048eb`, tree `a9032b2`, is the frozen replacement source. Exact
candidate `22b5cf3`, tree `2b0ff7f`, passed independent exact-source review.
Step 6C-2 exact source `4a81b08`, tree `188d7d0`, and exact complete physical
evidence `0461ac7`, tree `c14838c`, subsequently passed independent review.
The bounded real-iPhone ceremony approved and verified one harmless local
action and completed two-sided disposable cleanup. Step 6 is complete only as
the local architecture/composition route; no public-network, production, or
post-quantum enforcement claim follows.

## 14. Trust Without Requiring User Cryptographic Review

Phil cannot eliminate trust. It must make the trust basis inspectable by
specialists and automatically enforced for ordinary users.

Production approval requires:

- isolated security runtime and least-privilege app/agent boundaries;
- hardware-backed, user-present device approval where supported;
- deterministic human-readable intent/presentation bound to signed bytes;
- transaction/action simulation and explicit target, value, fee, expiry, and
  capability limits;
- fail-closed parsing, versioning, replay, revocation, and update behavior;
- signed releases, reproducible builds, dependency locks, SBOM, and build
  provenance;
- independent cryptographic, device, recovery, account, and application
  security review for the exact release;
- pinned verifier/circuit/program identities and public change history;
- private vulnerability reporting, security advisories, incident response,
  emergency revocation, and safe upgrade/migration ceremonies; and
- simple user-facing states that distinguish local, prototype, testnet,
  externally reviewed, and production-approved assurances.

Platform attestation is supporting evidence, not self-authenticating truth and
not user sovereignty authority.

## 15. Compatibility And Migration Boundary

The following remain implemented compatibility artifacts, not the target
cross-network identity surface:

- public `identityRoot` and `ownerCommitment` SDK types;
- `ACTION_UNLOCK`;
- `proofType = "stwo-unlock-keccak-v1"`;
- the legacy six-field proof public tuple;
- `proofInputHash` and `[fact_high, fact_low]`;
- existing Starknet-to-L1-to-Base research routes; and
- current Ethereum/Base account and account-recovery artifacts.

They must remain byte stable for historical tests and migration analysis. They
must not be relabeled as the new scoped architecture, accepted as a production
root proof, or used to expose a universal root commitment.

Later implementation introduces new versioned types and domains. It must not
silently reinterpret existing fields or proofs. Migration tests must prove
that compatibility paths cannot create new product authority.

## 16. Step 1 Exit And Step 2 Status

Frozen by this document:

- private root and protected root commitment;
- pairwise scoped public commitments;
- encrypted user-controlled data and key separation;
- user-controlled `2-of-3` identity/data recovery architecture;
- device keys as replaceable approval factors;
- routine capability versus exceptional proof authorization;
- chain-agnostic authorization envelope;
- proof admission and descriptor rules without backend selection;
- adapter isolation and guarantee classification;
- algorithm-agile/PQ migration requirements; and
- evidence-backed user trust requirements.

Step 1 did not implement or authorize:

- new runtime types or hashes;
- scoped commitment code;
- recovery package code or ceremony;
- physical-device proving;
- proof-backend selection;
- Starknet verifier integration;
- composed account authorization;
- PQ validator implementation;
- additional network adapters;
- secrets, signing, deployment, RPC mutation, or transactions.

The Step 2 local candidate now implements the new scoped-identity, encrypted
data, device-approval, and identity/data-recovery primitives described above.
Its separately authorized disposable physical-iPhone ceremony passed with
corrective cancellation handling and exact candidate deletion. A fail-closed
policy admits only that exact observed device/resource envelope and grants no
production authority. Independent reviews rejected `ac49f01` and `786ab61`;
the final exact source candidate
`fe583b6aef84a8636736b2041db2a56046a5972e` corrected those findings and
received `ACCEPT_STEP_2_EXACT_CANDIDATE`. Step 2 is complete. Proof-backend
selection remains open. The separately authorized Step 3 local reference
candidate `11234ea623a6b8883eed0036f3d95174cef90627` passed native and Cairo
verification and received `ACCEPT_STEP_3_EXACT_CANDIDATE`; it grants no
production or network authority and does not authorize Step 4.
