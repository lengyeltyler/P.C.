require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256, sha256, toUtf8Bytes } = require("ethers");

const {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_RECOVERY_FACTOR_BITMAP,
  PHILCORE_V2_RECOVERY_FACTOR_ROLE,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY,
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND,
  computePhilCoreV2ValidatorCommitment
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_BACKUP_POLICY,
  PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
  PHILCORE_V2_RECOVERY_DOMAIN_ID,
  PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  PHILCORE_V2_ZERO_BYTES32,
  assertPhilCoreV2RecoveryEvidenceMembership,
  assertPhilCoreV2RecoveryEvidenceState,
  computePhilCoreV2RecoveryDescriptorCommitment,
  computePhilCoreV2RecoveryEvidenceContextHash,
  computePhilCoreV2RecoveryIndependenceBinding,
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  computePhilCoreV2RecoveryConfigurationHashV2,
  validatePhilCoreV2RecoveryDescriptorSet,
  validatePhilCoreV2RecoveryRotation
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json"
);
const SOURCE_HEAD_AT_PHASE_START =
  "6dcc4099a78cd719d484c4e33c808586d2472780";

const ACCOUNT = "0x1000000000000000000000000000000000000001";
const ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const PROPOSED_VALIDATOR =
  "0x6000000000000000000000000000000000000006";
const RECOVERY_SIGNER =
  "0x7000000000000000000000000000000000000007";
const ROTATED_RECOVERY_SIGNER =
  "0x8000000000000000000000000000000000000008";

const P256_GENERATOR = {
  qx: "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  qy: "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
};
const P256_TWO_TIMES_GENERATOR = {
  qx: "0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
  qy: "0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
};

const H = (value) => keccak256(toUtf8Bytes(value));

function sha256File(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function stringify(value) {
  return `${JSON.stringify(
    value,
    (_key, item) => typeof item === "bigint" ? item.toString() : item,
    2
  )}\n`;
}

function independenceInput(role, credentialIdHash, label) {
  return {
    bindingVersion: 1,
    role,
    credentialIdHash,
    enrollmentCeremonyHash: H(`o37.1:${label}:enrollment-ceremony`),
    attestationEvidenceHash:
      role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
        ? PHILCORE_V2_ZERO_BYTES32
        : H(`o37.1:${label}:verified-attestation-evidence`),
    custodyDomainId: H(`o37.1:${label}:independent-custody-domain`)
  };
}

function descriptorFixtures() {
  const primaryCredentialIdHash = H(
    "o37.1:public-fixture:primary-credential-id"
  );
  const hardwareCredentialIdHash = H(
    "o37.1:public-fixture:hardware-credential-id"
  );
  const primaryIndependence = independenceInput(
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE,
    primaryCredentialIdHash,
    "primary"
  );
  const hardwareIndependence = independenceInput(
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY,
    hardwareCredentialIdHash,
    "hardware"
  );
  const recoveryIndependence = independenceInput(
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR,
    PHILCORE_V2_ZERO_BYTES32,
    "recovery"
  );

  const primaryDevice = {
    descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_DOMAIN_ID,
    role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash(P256_GENERATOR),
    credentialIdHash: primaryCredentialIdHash,
    rpIdHash: sha256(toUtf8Bytes("philcore.test")),
    originPolicyHash: H("https://philcore.test"),
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(primaryIndependence),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED,
    authenticatorAttachmentPolicy:
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    attestationPolicy:
      PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND,
    credentialGeneration: 1
  };
  const hardwareSecurityKey = {
    descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_DOMAIN_ID,
    role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash(P256_TWO_TIMES_GENERATOR),
    credentialIdHash: hardwareCredentialIdHash,
    rpIdHash: sha256(toUtf8Bytes("philcore.test")),
    originPolicyHash: H("https://philcore.test"),
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(hardwareIndependence),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED,
    authenticatorAttachmentPolicy:
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED,
    attestationPolicy:
      PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE,
    credentialGeneration: 1
  };
  const recoveryFactor = {
    descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_DOMAIN_ID,
    role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR,
    verifierKind:
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash:
      computePhilCoreV2Secp256k1PublicMaterialHash({
        signer: RECOVERY_SIGNER
      }),
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    rpIdHash: PHILCORE_V2_ZERO_BYTES32,
    originPolicyHash: PHILCORE_V2_ZERO_BYTES32,
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(recoveryIndependence),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.NOT_APPLICABLE,
    authenticatorAttachmentPolicy:
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.NOT_APPLICABLE,
    attestationPolicy: PHILCORE_V2_ATTESTATION_POLICY.NOT_APPLICABLE,
    credentialGeneration: 1
  };
  return {
    publicVerificationMaterial: {
      primaryDevice: P256_GENERATOR,
      hardwareSecurityKey: P256_TWO_TIMES_GENERATOR,
      recoveryFactor: { signer: RECOVERY_SIGNER }
    },
    independenceInputs: {
      primaryDevice: primaryIndependence,
      hardwareSecurityKey: hardwareIndependence,
      recoveryFactor: recoveryIndependence
    },
    descriptors: [primaryDevice, hardwareSecurityKey, recoveryFactor]
  };
}

function evidenceContext({
  actionType,
  bitmap,
  descriptorSet,
  requestId,
  proposedValidatorCommitment = PHILCORE_V2_ZERO_BYTES32,
  proposedRecoveryConfigHash = PHILCORE_V2_ZERO_BYTES32
}) {
  const [primary, hardware, recovery] = descriptorSet.commitments;
  const selected = bitmap === 3
    ? [primary, hardware]
    : bitmap === 5
      ? [primary, recovery]
      : [hardware, recovery];
  return {
    envelopeVersion: PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
    authorityKind: PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
    actionType,
    factorBitmap: bitmap,
    account: ACCOUNT,
    chainId: "11155111",
    entryPoint: ENTRYPOINT,
    authorizedIntentHash: H(`o37.1:authorized-intent:${actionType}`),
    userOperationHash: H(
      `o37.1:user-operation-hash-binding-only:no-user-operation:${actionType}`
    ),
    requestId,
    currentRecoveryConfigHash: descriptorSet.recoveryConfigHash,
    validatorEpoch: 3,
    recoveryEpoch: 2,
    validAfter: 1800000000,
    validUntil: 1800003600,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment,
    proposedRecoveryConfigHash,
    proposedRecoveryEpoch: 3,
    primaryDeviceCommitment: primary,
    hardwareSecurityKeyCommitment: hardware,
    recoveryFactorCommitment: recovery,
    firstFactorCommitment: selected[0],
    secondFactorCommitment: selected[1]
  };
}

function expectError(id, changedFields, expectedError, operation) {
  let actualError = null;
  try {
    operation();
  } catch (error) {
    actualError = error instanceof Error ? error.message : String(error);
  }
  if (actualError !== expectedError) {
    throw new Error(
      `O37_1_NEGATIVE_VECTOR_MISMATCH:${id}:${actualError}:${expectedError}`
    );
  }
  return {
    id,
    changedFields,
    expectedError,
    rejected: true,
    signatureCreated: false,
    userOperationCreated: false
  };
}

function buildO371VectorPackage() {
  const fixtures = descriptorFixtures();
  const descriptors = fixtures.descriptors;
  const descriptorSet = validatePhilCoreV2RecoveryDescriptorSet(descriptors);
  const proposedValidatorCommitment = computePhilCoreV2ValidatorCommitment({
    verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
    validator: PROPOSED_VALIDATOR,
    validatorKeyIdBinding: H("o37.1:proposed-validator-key-id")
  });

  const requestContext = evidenceContext({
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
    bitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE,
    descriptorSet,
    requestId: H(
      `o37.1:authorized-intent:${PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST}`
    ),
    proposedValidatorCommitment
  });
  assertPhilCoreV2RecoveryEvidenceMembership({
    context: requestContext,
    firstDescriptor: descriptors[0],
    secondDescriptor: descriptors[1]
  });
  assertPhilCoreV2RecoveryEvidenceState({
    context: requestContext,
    expectedAccount: ACCOUNT,
    expectedChainId: "11155111",
    expectedEntryPoint: ENTRYPOINT,
    currentValidatorEpoch: 3,
    currentRecoveryEpoch: 2
  });

  const rotatedRecoveryIndependence = independenceInput(
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR,
    PHILCORE_V2_ZERO_BYTES32,
    "rotated-recovery"
  );
  const rotatedRecoveryFactor = {
    ...descriptors[2],
    publicVerificationMaterialHash:
      computePhilCoreV2Secp256k1PublicMaterialHash({
        signer: ROTATED_RECOVERY_SIGNER
      }),
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(
        rotatedRecoveryIndependence
      ),
    credentialGeneration: 2
  };
  const proposedDescriptors = [
    descriptors[0],
    descriptors[1],
    rotatedRecoveryFactor
  ];
  const rotation = validatePhilCoreV2RecoveryRotation({
    currentRecoveryEpoch: 2,
    proposedRecoveryEpoch: 3,
    currentDescriptors: descriptors,
    proposedDescriptors
  });
  const rotationContext = evidenceContext({
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
    bitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.HARDWARE_AND_RECOVERY,
    descriptorSet,
    requestId: H(
      `o37.1:authorized-intent:${
        PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST
      }`
    ),
    proposedRecoveryConfigHash: rotation.proposedRecoveryConfigHash
  });
  assertPhilCoreV2RecoveryEvidenceMembership({
    context: rotationContext,
    firstDescriptor: descriptors[1],
    secondDescriptor: descriptors[2]
  });

  const negativeVectors = [
    expectError(
      "modified_credential_generation",
      "primaryDevice.credentialGeneration",
      "factor_evidence_commitment_mismatch",
      () => assertPhilCoreV2RecoveryEvidenceMembership({
        context: requestContext,
        firstDescriptor: {
          ...descriptors[0],
          credentialGeneration: 2
        },
        secondDescriptor: descriptors[1]
      })
    ),
    expectError(
      "modified_policy_hash",
      "primaryDevice.originPolicyHash",
      "factor_evidence_commitment_mismatch",
      () => assertPhilCoreV2RecoveryEvidenceMembership({
        context: requestContext,
        firstDescriptor: {
          ...descriptors[0],
          originPolicyHash: H("https://wrong-origin.test")
        },
        secondDescriptor: descriptors[1]
      })
    ),
    expectError(
      "wrong_role",
      "firstDescriptor.role",
      "factor_evidence_role_order_invalid",
      () => assertPhilCoreV2RecoveryEvidenceMembership({
        context: requestContext,
        firstDescriptor: descriptors[1],
        secondDescriptor: descriptors[1]
      })
    ),
    expectError(
      "wrong_verifier_kind",
      "primaryDevice.verifierKind",
      "primary_device_verifierKind_invalid",
      () => computePhilCoreV2RecoveryDescriptorCommitment({
        ...descriptors[0],
        verifierKind:
          PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1
      })
    ),
    expectError(
      "wrong_domain",
      "primaryDevice.recoveryDomainId",
      "recoveryDomainId_unsupported",
      () => computePhilCoreV2RecoveryDescriptorCommitment({
        ...descriptors[0],
        recoveryDomainId: H("o37.1:wrong-recovery-domain")
      })
    ),
    expectError(
      "stale_epoch",
      "validatorEpoch",
      "validator_epoch_stale",
      () => assertPhilCoreV2RecoveryEvidenceState({
        context: { ...requestContext, validatorEpoch: 2 },
        expectedAccount: ACCOUNT,
        expectedChainId: "11155111",
        expectedEntryPoint: ENTRYPOINT,
        currentValidatorEpoch: 3,
        currentRecoveryEpoch: 2
      })
    ),
    expectError(
      "duplicate_factor",
      "hardwareSecurityKeyCommitment",
      "recovery_factor_commitments_must_be_unique",
      () => computePhilCoreV2RecoveryConfigurationHashV2({
        configurationVersion:
          PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
        threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
        primaryDeviceCommitment: descriptorSet.commitments[0],
        hardwareSecurityKeyCommitment: descriptorSet.commitments[0],
        recoveryFactorCommitment: descriptorSet.commitments[2]
      })
    ),
    expectError(
      "invalid_bitmap",
      "factorBitmap",
      "recovery_factor_bitmap_invalid",
      () => computePhilCoreV2RecoveryEvidenceContextHash({
        ...requestContext,
        factorBitmap: 7
      })
    ),
    expectError(
      "same_factor_rotation",
      "proposedRecoveryFactor.publicVerificationMaterialHash",
      "rotated_factor_public_material_must_change",
      () => validatePhilCoreV2RecoveryRotation({
        currentRecoveryEpoch: 2,
        proposedRecoveryEpoch: 3,
        currentDescriptors: descriptors,
        proposedDescriptors: [
          descriptors[0],
          descriptors[1],
          {
            ...rotatedRecoveryFactor,
            publicVerificationMaterialHash:
              descriptors[2].publicVerificationMaterialHash
          }
        ]
      })
    )
  ];

  return {
    schemaVersion: "philcore-o37-1-v2-recovery-evidence-v1",
    phase: "O.37.1",
    canonicalPhaseName:
      "O.37.1 V2 Recovery Evidence and Cryptographic Descriptor Completion",
    classification: "COMPLETE_LOCAL_CRYPTOGRAPHIC_INTERFACE_CORRECTION",
    sourceHeadAtPhaseStart: SOURCE_HEAD_AT_PHASE_START,
    fixtureOnly: true,
    publicMutationCount: 0,
    implementationBindings: {
      recoveryEvidenceSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2RecoveryEvidence.ts"
      ),
      o32VectorPackageSha256: sha256File(
        "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
      ),
      o33VectorPackageSha256: sha256File(
        "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
      ),
      o36_1FreezeSha256: sha256File(
        "config/cryptography/O36_1_V2_SECURITY_INTERFACE_FREEZE.json"
      )
    },
    versions: {
      descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
      configurationVersion:
        PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
      evidenceVersion: PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
      authorityKind: PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
      threshold: PHILCORE_V2_RECOVERY_THRESHOLD
    },
    typeBindings: Object.fromEntries(
      Object.entries(PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE).map(
        ([key, typeString]) => [
          key,
          {
            typeString,
            typeHash: PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH[key]
          }
        ]
      )
    ),
    publicFixtureMaterial: {
      ...fixtures.publicVerificationMaterial,
      rotatedRecoveryFactor: { signer: ROTATED_RECOVERY_SIGNER },
      realCredential: false,
      privateKey: false,
      signature: false
    },
    independenceBindings: fixtures.independenceInputs,
    currentDescriptors: {
      primaryDevice: descriptors[0],
      hardwareSecurityKey: descriptors[1],
      recoveryFactor: descriptors[2]
    },
    currentCommitments: {
      primaryDevice: descriptorSet.commitments[0],
      hardwareSecurityKey: descriptorSet.commitments[1],
      recoveryFactor: descriptorSet.commitments[2],
      recoveryConfigHash: descriptorSet.recoveryConfigHash
    },
    validRecoveryRequest: {
      factorBitmap:
        PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE,
      context: requestContext,
      contextHash:
        computePhilCoreV2RecoveryEvidenceContextHash(requestContext),
      membershipAccepted: true,
      stateAccepted: true,
      signatureCreated: false,
      userOperationCreated: false
    },
    validRotationRequest: {
      factorBitmap:
        PHILCORE_V2_RECOVERY_FACTOR_BITMAP.HARDWARE_AND_RECOVERY,
      currentRecoveryEpoch: "2",
      proposedRecoveryEpoch: "3",
      changedRoles: rotation.changedRoles,
      proposedDescriptor: rotatedRecoveryFactor,
      proposedRecoveryConfigHash: rotation.proposedRecoveryConfigHash,
      context: rotationContext,
      contextHash:
        computePhilCoreV2RecoveryEvidenceContextHash(rotationContext),
      oldFactorRevokedByEpochAndConfigChange: true,
      signatureCreated: false,
      userOperationCreated: false
    },
    negativeVectors,
    compatibility: {
      o32VectorPackageChanged: false,
      o33VectorPackageChanged: false,
      o32IntentAndAuthorityDigestTypesRetained: true,
      o36_1LegacyFactorCommitmentAcceptedByFutureSolidity: false,
      o35AccountInitializationFieldCountRetained: 20,
      descriptorFieldsCarriedInPublicOneTimeEvidence: true
    },
    runtimeFreeze: {
      node: "26.0.0",
      npm: "11.12.1",
      lockfileVersion: 3,
      installCommand: "npm ci",
      runtimeCheckCommand: "npm run check:o37-1-runtime"
    },
    securityBoundary: {
      privateMaterialStored: false,
      privateMaterialCommitted: false,
      credentialCreated: false,
      signatureCreated: false,
      userOperationCreated: false,
      solidityCreated: false,
      bytecodeCreated: false,
      deploymentPerformed: false,
      accountCreated: false,
      rpcUsed: false,
      fundsMoved: false,
      publicMutationOccurred: false
    }
  };
}

function main() {
  const checkOnly = process.argv.includes("--check");
  const output = stringify(buildO371VectorPackage());
  if (checkOnly) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      throw new Error("O37_1_VECTOR_PACKAGE_MISSING");
    }
    if (fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O37_1_VECTOR_PACKAGE_STALE");
    }
    process.stdout.write("O.37.1 recovery evidence vector package is current\n");
    return;
  }
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO371VectorPackage,
  descriptorFixtures
};
