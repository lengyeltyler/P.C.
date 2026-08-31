require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  SigningKey,
  concat,
  computeAddress,
  getBytes,
  hexlify,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");

const {
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY,
  computePhilCoreV2RecoveryFactorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_BACKUP_POLICY,
  PHILCORE_V2_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const { PHILCORE_V2_SECURITY_MODEL_ID } =
  require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS,
  PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE,
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
  PHILCORE_V2_CONSUMER_SYNC_CLASS,
  computePhilCoreV2ConsumerRecoveryFactorCommitment,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding,
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  validatePhilCoreV2ConsumerRecoveryProfile
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_O37_2_P256_ORDER,
  PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE,
  buildPhilCoreO372WebAuthnClientData,
  computePhilCoreO372RpIdHash,
  computePhilCoreO372WebAuthnMessageHash,
  encodePhilCoreO372RecoveryEnvelope,
  encodePhilCoreO372Secp256k1Evidence,
  encodePhilCoreO372WebAuthnEvidence
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"
);
const H = (value) => keccak256(toUtf8Bytes(value));
const ACCOUNT = "0x0000000000000000000000000000000000003900";
const ENTRY_POINT = "0x00000000000000000000000000000000000F4337";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const CHAIN_ID = 31337n;
const RP_ID = "o39.fixture.philcore.invalid";
const ORIGIN = "https://o39.fixture.philcore.invalid";
const SECP_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function deterministicScalar(label, order) {
  return zeroPadValue(
    toBeHex((BigInt(H(`O39_TEST_ONLY:${label}`)) % (order - 1n)) + 1n),
    32
  );
}

function webAuthnFactor(label, role, authenticatorClass, attachment, attestation) {
  const privateScalar = deterministicScalar(label, PHILCORE_O37_2_P256_ORDER);
  const publicKey = p256.getPublicKey(getBytes(privateScalar), false);
  const qx = hexlify(publicKey.slice(1, 33));
  const qy = hexlify(publicKey.slice(33, 65));
  const credentialIdHash = H(`O39_PUBLIC_CREDENTIAL_ID_HASH:${label}`);
  const independence = {
    bindingVersion: PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
    role,
    authenticatorClass,
    synchronizationClass: PHILCORE_V2_CONSUMER_SYNC_CLASS.DEVICE_BOUND,
    independenceAssurance:
      PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.ENFORCED,
    credentialIdHash,
    enrollmentCeremonyHash: H(`O39_ENROLLMENT:${label}`),
    attestationEvidenceHash: H(`O39_ATTESTATION:${label}`),
    custodyDomainCommitment: H(`O39_CUSTODY_DOMAIN:${label}`),
    credentialGeneration: 1
  };
  const descriptor = {
    descriptorVersion: PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    role,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash({ qx, qy }),
    credentialIdHash,
    rpIdHash: computePhilCoreO372RpIdHash(RP_ID),
    originPolicyHash: H(ORIGIN),
    independenceBindingHash:
      computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED,
    authenticatorAttachmentPolicy: attachment,
    attestationPolicy: attestation,
    credentialGeneration: 1
  };
  return {
    privateScalar,
    qx,
    qy,
    descriptor,
    independence,
    factorCommitment:
      computePhilCoreV2ConsumerRecoveryFactorCommitment(descriptor)
  };
}

function offlineFactor(profile) {
  const privateKey = deterministicScalar(`${profile}:offline`, SECP_ORDER);
  const signingKey = new SigningKey(privateKey);
  const signer = computeAddress(signingKey.publicKey);
  const independence = {
    bindingVersion: PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
    role: 2,
    authenticatorClass:
      PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.OFFLINE_SECP256K1_EXPORT,
    synchronizationClass: PHILCORE_V2_CONSUMER_SYNC_CLASS.NOT_APPLICABLE,
    independenceAssurance:
      PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.ENFORCED,
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    enrollmentCeremonyHash: H(`O39_ENROLLMENT:${profile}:offline`),
    attestationEvidenceHash: H(`O39_OFFLINE_DRILL:${profile}`),
    custodyDomainCommitment: H(`O39_CUSTODY_DOMAIN:${profile}:offline`),
    credentialGeneration: 1
  };
  const descriptor = {
    descriptorVersion: PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    role: 2,
    verifierKind:
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash:
      computePhilCoreV2Secp256k1PublicMaterialHash({ signer }),
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    rpIdHash: PHILCORE_V2_ZERO_BYTES32,
    originPolicyHash: PHILCORE_V2_ZERO_BYTES32,
    independenceBindingHash:
      computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
    userVerificationPolicy: 0,
    backupPolicy: 0,
    authenticatorAttachmentPolicy: 0,
    attestationPolicy: 0,
    credentialGeneration: 1
  };
  return {
    privateKey,
    signer,
    descriptor,
    independence,
    factorCommitment:
      computePhilCoreV2ConsumerRecoveryFactorCommitment(descriptor)
  };
}

function publicFactor(factor) {
  const {
    privateScalar: _privateScalar,
    privateKey: _privateKey,
    ...publicValue
  } = factor;
  return publicValue;
}

function contextFor(request, commitments, bitmap) {
  const roles = bitmap === 3 ? [0, 1] : bitmap === 5 ? [0, 2] : [1, 2];
  return {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: 8,
    factorBitmap: bitmap,
    account: request.account,
    chainId: request.chainId,
    entryPoint: request.entryPoint,
    authorizedIntentHash: request.authorizedIntentHash,
    userOperationHash: request.userOpHash,
    requestId: request.requestId,
    currentRecoveryConfigHash: request.recoveryConfigHash,
    validatorEpoch: request.validatorEpoch,
    recoveryEpoch: request.recoveryEpoch,
    validAfter: request.validAfter,
    validUntil: request.validUntil,
    recoveryDelaySeconds: 172800,
    recoveryExpirySeconds: 604800,
    proposedValidatorCommitment: request.proposedValidatorCommitment,
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: request.proposedRecoveryEpoch,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: commitments[roles[0]],
    secondFactorCommitment: commitments[roles[1]]
  };
}

function webAuthnEvidence(factor, digest, counter, options = {}) {
  const client = buildPhilCoreO372WebAuthnClientData({
    challenge: digest,
    origin: options.origin ?? ORIGIN
  });
  const authenticatorData = hexlify(concat([
    options.rpIdHash ?? factor.descriptor.rpIdHash,
    options.flags ?? "0x05",
    zeroPadValue(toBeHex(counter), 4)
  ]));
  const messageHash = computePhilCoreO372WebAuthnMessageHash({
    authenticatorData,
    clientDataJSON: client.clientDataJSON
  });
  const signature = p256.sign(
    getBytes(messageHash),
    getBytes(factor.privateScalar),
    { lowS: true, prehash: false }
  );
  return encodePhilCoreO372WebAuthnEvidence({
    descriptor: factor.descriptor,
    factorCommitment: factor.factorCommitment,
    qx: factor.qx,
    qy: factor.qy,
    r: zeroPadValue(toBeHex(signature.r), 32),
    s: zeroPadValue(toBeHex(signature.s), 32),
    challengeIndex: client.challengeIndex,
    typeIndex: client.typeIndex,
    authenticatorData,
    clientDataJSON: client.clientDataJSON
  });
}

function secpEvidence(factor, digest) {
  const signature = new SigningKey(factor.privateKey).sign(digest);
  return encodePhilCoreO372Secp256k1Evidence({
    descriptor: factor.descriptor,
    factorCommitment: factor.factorCommitment,
    signer: factor.signer,
    r: signature.r,
    s: signature.s,
    v: signature.v
  });
}

function buildProfile(profile) {
  const primary = webAuthnFactor(
    `${profile}:primary`,
    0,
    PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const enhanced = profile === "ENHANCED";
  const secondary = webAuthnFactor(
    `${profile}:secondary`,
    1,
    enhanced
      ? PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY
      : PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.SECONDARY_PLATFORM_DEVICE,
    enhanced
      ? PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED
      : PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    enhanced
      ? PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE
      : PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const offline = offlineFactor(profile);
  const validated = validatePhilCoreV2ConsumerRecoveryProfile({
    factors: [
      { descriptor: primary.descriptor, independence: primary.independence },
      { descriptor: secondary.descriptor, independence: secondary.independence },
      {
        descriptor: offline.descriptor,
        independence: offline.independence,
        signer: offline.signer
      }
    ],
    executionValidator: VALIDATOR
  });
  const request = {
    actionType: 8,
    account: ACCOUNT,
    chainId: CHAIN_ID.toString(),
    entryPoint: ENTRY_POINT,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    authorizedIntentHash: H(`O39:${profile}:AUTHORIZED_INTENT`),
    userOpHash: H(`O39:${profile}:USER_OPERATION`),
    validator: VALIDATOR,
    validatorKeyIdBinding: H("O39:VALIDATOR_KEY_ID_BINDING"),
    validatorEpoch: 1,
    recoveryEpoch: 1,
    recoveryConfigHash: validated.recoveryConfigurationHash,
    requestId: H(`O39:${profile}:AUTHORIZED_INTENT`),
    validAfter: 1000,
    validUntil: 5000,
    proposedValidatorCommitment: H(`O39:${profile}:PROPOSED_VALIDATOR`),
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: 2,
    primaryDeviceCommitment: validated.commitments[0],
    hardwareSecurityKeyCommitment: validated.commitments[1],
    recoveryFactorCommitment: validated.commitments[2]
  };
  const pairs = [3, 5, 6].map((bitmap, index) => {
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: CHAIN_ID, account: ACCOUNT },
      {
        authorizedIntentHash: request.authorizedIntentHash,
        userOperationHash: request.userOpHash,
        recoveryConfigHash: request.recoveryConfigHash,
        recoveryEpoch: request.recoveryEpoch,
        factorBitmap: bitmap
      }
    ).digest;
    const selected = bitmap === 3
      ? [webAuthnEvidence(primary, digest, index + 1),
        webAuthnEvidence(secondary, digest, index + 11)]
      : bitmap === 5
        ? [webAuthnEvidence(primary, digest, index + 1),
          secpEvidence(offline, digest)]
        : [webAuthnEvidence(secondary, digest, index + 11),
          secpEvidence(offline, digest)];
    return {
      bitmap,
      roles: bitmap === 3 ? [0, 1] : bitmap === 5 ? [0, 2] : [1, 2],
      digest,
      envelope: encodePhilCoreO372RecoveryEnvelope({
        context: contextFor(request, validated.commitments, bitmap),
        firstFactorEvidence: selected[0],
        secondFactorEvidence: selected[1]
      })
    };
  });
  const invalidDigest = pairs[0].digest;
  const invalidContext = contextFor(request, validated.commitments, 3);
  const validSecondaryEvidence =
    webAuthnEvidence(secondary, invalidDigest, 99);
  const invalidEnvelopes = [
    {
      id: "wrong_origin",
      envelope: encodePhilCoreO372RecoveryEnvelope({
        context: invalidContext,
        firstFactorEvidence: webAuthnEvidence(
          primary,
          invalidDigest,
          90,
          { origin: "https://attacker.invalid" }
        ),
        secondFactorEvidence: validSecondaryEvidence
      })
    },
    {
      id: "wrong_rp_id",
      envelope: encodePhilCoreO372RecoveryEnvelope({
        context: invalidContext,
        firstFactorEvidence: webAuthnEvidence(
          primary,
          invalidDigest,
          91,
          { rpIdHash: sha256(toUtf8Bytes("attacker.invalid")) }
        ),
        secondFactorEvidence: validSecondaryEvidence
      })
    },
    {
      id: "backup_eligible_flag",
      envelope: encodePhilCoreO372RecoveryEnvelope({
        context: invalidContext,
        firstFactorEvidence: webAuthnEvidence(
          primary,
          invalidDigest,
          92,
          { flags: "0x0d" }
        ),
        secondFactorEvidence: validSecondaryEvidence
      })
    },
    {
      id: "malformed_backup_state_without_eligibility",
      envelope: encodePhilCoreO372RecoveryEnvelope({
        context: invalidContext,
        firstFactorEvidence: webAuthnEvidence(
          primary,
          invalidDigest,
          93,
          { flags: "0x15" }
        ),
        secondFactorEvidence: validSecondaryEvidence
      })
    }
  ];
  return {
    profile,
    request,
    recoveryConfigurationHash: validated.recoveryConfigurationHash,
    factors: {
      primary: publicFactor(primary),
      secondary: publicFactor(secondary),
      offline: publicFactor(offline)
    },
    validPairs: pairs,
    invalidEnvelopes
  };
}

function buildO39ConsumerRecoveryFixturePackage() {
  return {
    phase: "O.39",
    classification: "DETERMINISTIC_SYNTHETIC_TEST_ONLY",
    publicMutationCount: 0,
    descriptorVersion: 3,
    recoveryConfigurationVersion: 3,
    authorityTransport: {
      outerEnvelopeChanged: false,
      descriptorCommitmentsChanged: true,
      recoveryEnvelopeAbi: PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE
    },
    profiles: {
      standard: buildProfile("STANDARD"),
      enhanced: buildProfile("ENHANCED")
    },
    invalidCases: [
      "same_credential_roles_0_1",
      "same_public_key_roles_0_1",
      "same_custody_domain",
      "role_substitution",
      "execution_validator_reused",
      "stale_generation",
      "invalid_authenticator_class",
      "prohibited_sync_state",
      "malformed_backup_flags",
      "altered_independence_commitment",
      "wrong_rp_id",
      "wrong_origin",
      "wrong_account",
      "wrong_chain",
      "wrong_version",
      "wrong_recovery_epoch"
    ],
    secretsCommitted: false,
    productionCredentialIdsCommitted: false,
    productionSignaturesCommitted: false
  };
}

function stringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const output = stringify(buildO39ConsumerRecoveryFixturePackage());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH)
      || fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O39_CONSUMER_RECOVERY_FIXTURE_PACKAGE_STALE");
    }
    process.stdout.write("O.39 consumer recovery fixtures are current\n");
    return;
  }
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO39ConsumerRecoveryFixturePackage,
  contextFor,
  deterministicScalar,
  offlineFactor,
  secpEvidence,
  webAuthnEvidence,
  webAuthnFactor
};
