require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  AbiCoder,
  SigningKey,
  computeAddress,
  concat,
  getBytes,
  hexlify,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");

const {
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  encodePhilCoreV2Intent
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_RECOVERY_FACTOR_BITMAP,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2ConfigRotationDigest,
  computePhilCoreV2ProofBindingHash,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
  PHILCORE_V2_ZERO_BYTES32,
  computePhilCoreV2RecoveryConfigurationHashV2,
  computePhilCoreV2RecoveryDescriptorCommitment,
  computePhilCoreV2RecoveryEvidenceContextHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  validatePhilCoreV2RecoveryRotation
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_O37_2_P256_ORDER,
  PHILCORE_O37_2_SECP256K1_ORDER,
  buildPhilCoreO372WebAuthnClientData,
  computePhilCoreO372WebAuthnMessageHash,
  encodePhilCoreO372RecoveryEnvelope,
  encodePhilCoreO372Secp256k1Evidence,
  encodePhilCoreO372ValidatorEnvelope,
  encodePhilCoreO372WebAuthnEvidence,
  verifyPhilCoreO372P256Signature,
  verifyPhilCoreO372ValidatorEnvelope
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_O37_4_AUTHORITY_CLASS,
  PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION,
  PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
  PHILCORE_O37_4_COMBINED_AUTHORITY_KIND,
  PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE,
  PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH,
  PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES,
  PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES,
  PHILCORE_O37_4_CONFIG_ROTATION_ACTION,
  PHILCORE_O37_4_RECOVERY_EVIDENCE_MAX_BYTES,
  PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES,
  PHILCORE_O37_4_SECP256K1_EVIDENCE_BYTES,
  PHILCORE_O37_4_VALIDATOR_EVIDENCE_BYTES,
  PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MAX_BYTES,
  PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MIN_BYTES,
  decodePhilCoreO374AuthorityTransport,
  encodePhilCoreO374CombinedAuthorityEnvelope
} = require("../../apps/phil-device-sdk/src/v2AuthorityTransport.ts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
);
const O372_PATH = path.join(
  ROOT,
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
);
const SOURCE_HEAD_AT_PHASE_START =
  "888319327e6a50f17e188132711a7e5c307bc473";
const CLASSIFICATION = "TEST_FIXTURE_ONLY";
const abiCoder = AbiCoder.defaultAbiCoder();
const H = (value) => keccak256(toUtf8Bytes(value));

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

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

function deterministicScalar(label, order) {
  const material = sha256(toUtf8Bytes(
    `PHILCORE_O37_2_TEST_FIXTURE_ONLY:${label}`
  ));
  return zeroPadValue(
    toBeHex((BigInt(material) % (order - 1n)) + 1n),
    32
  );
}

function exactFixtureKeys(o372) {
  const validatorScalar = deterministicScalar(
    "execution-validator",
    PHILCORE_O37_2_SECP256K1_ORDER
  );
  const validatorKey = new SigningKey(validatorScalar);
  if (
    computeAddress(validatorKey.publicKey)
    !== o372.fixtureIdentities.executionValidator.address
  ) {
    throw new Error("O37_4_EXECUTION_VALIDATOR_DERIVATION_MISMATCH");
  }
  const recoveryScalar = deterministicScalar(
    "independent-recovery-factor",
    PHILCORE_O37_2_SECP256K1_ORDER
  );
  const recoveryKey = new SigningKey(recoveryScalar);
  if (
    computeAddress(recoveryKey.publicKey)
    !== o372.fixtureIdentities.independentRecoveryFactor.address
  ) {
    throw new Error("O37_4_RECOVERY_FACTOR_DERIVATION_MISMATCH");
  }
  const primaryScalar = deterministicScalar(
    "primary-device",
    PHILCORE_O37_2_P256_ORDER
  );
  const hardwareScalar = deterministicScalar(
    "hardware-security-key",
    PHILCORE_O37_2_P256_ORDER
  );
  for (const [scalar, fixture] of [
    [primaryScalar, o372.fixtureIdentities.primaryDevice],
    [hardwareScalar, o372.fixtureIdentities.hardwareSecurityKey]
  ]) {
    const publicKey = p256.getPublicKey(getBytes(scalar), false);
    if (
      hexlify(publicKey.slice(1, 33)) !== fixture.qx
      || hexlify(publicKey.slice(33, 65)) !== fixture.qy
    ) {
      throw new Error("O37_4_P256_DERIVATION_MISMATCH");
    }
  }
  return {
    validatorKey,
    recoveryKey,
    primaryScalar,
    hardwareScalar
  };
}

function authorizationChain(intent, label) {
  const encoded = encodePhilCoreV2Intent(intent);
  const proofBindingHash = computePhilCoreV2ProofBindingHash({
    proofTypeHash: H("o37.4:test-fixture-proof-type"),
    proofInputHash: H(`o37.4:${label}:proof-input`),
    proofArtifactDigest: H(`o37.4:${label}:proof-artifact`),
    nullifier: H(`o37.4:${label}:nullifier`)
  });
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest({
      intentCoreHash: encoded.intentCoreHash,
      proofBindingHash,
      policyDecisionHash: H(`o37.4:${label}:policy`),
      approvalEvidenceHash: H(`o37.4:${label}:approval`),
      userPresenceEvidenceHash: H(`o37.4:${label}:presence`)
    });
  return {
    intent,
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest,
    authorizedIntentHash: computePhilCoreV2AuthorizedIntentHash({
      intentCoreHash: encoded.intentCoreHash,
      runtimeAuthorizationDigest
    })
  };
}

function rotationIntent(o372, proposed, label, sequence) {
  const base = o372.recoveryAuthorizationFixtures.intent.header;
  return {
    header: {
      ...base,
      actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
      actionId: H(`o37.4:${label}:action`),
      purpose: PHILCORE_V2_PURPOSE.ROTATE_RECOVERY_CONFIG,
      nonceKey: PHILCORE_V2_NONCE_KEY.RECOVERY.toString(),
      nonceSequence: String(sequence),
      applicationContextHash: H(`o37.4:${label}:application-context`),
      fundLifecycleDigest: H(`o37.4:${label}:no-fund-lifecycle`),
      validAfter: "1900100000",
      validUntil: "1900103600"
    },
    payload: {
      kind: "RECOVERY_CONFIG_ROTATION_REQUEST",
      proposedRecoveryConfigHash: proposed.recoveryConfigHash,
      proposedPrimaryDeviceCommitment: proposed.primaryDeviceCommitment,
      proposedHardwareSecurityKeyCommitment:
        proposed.hardwareSecurityKeyCommitment,
      proposedRecoveryFactorCommitment: proposed.recoveryFactorCommitment,
      proposedRecoveryEpoch: "3"
    }
  };
}

function cancellationIntent(o372, requestId, label, sequence) {
  const base = o372.recoveryAuthorizationFixtures.intent.header;
  return {
    header: {
      ...base,
      actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL,
      actionId: H(`o37.4:${label}:action`),
      purpose: PHILCORE_V2_PURPOSE.CANCEL_RECOVERY_CONFIG_ROTATION,
      nonceKey: PHILCORE_V2_NONCE_KEY.RECOVERY.toString(),
      nonceSequence: String(sequence),
      applicationContextHash: H(`o37.4:${label}:application-context`),
      fundLifecycleDigest: H(`o37.4:${label}:no-fund-lifecycle`),
      validAfter: "1900100100",
      validUntil: "1900103700"
    },
    payload: {
      kind: "RECOVERY_CONFIG_ROTATION_CANCEL",
      recoveryConfigRotationRequestId: requestId
    }
  };
}

function proposedConfiguration(o372) {
  const currentHardware =
    o372.fixtureIdentities.hardwareSecurityKey.descriptor;
  const rotatedScalar = deterministicScalar(
    "o37-4-rotated-hardware-security-key",
    PHILCORE_O37_2_P256_ORDER
  );
  const publicKey = p256.getPublicKey(getBytes(rotatedScalar), false);
  const qx = hexlify(publicKey.slice(1, 33));
  const qy = hexlify(publicKey.slice(33, 65));
  const proposedHardwareDescriptor = {
    ...currentHardware,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash({ qx, qy }),
    credentialIdHash: H("o37.4:rotated-hardware:credential-id"),
    independenceBindingHash: H(
      "o37.4:rotated-hardware:independence-binding"
    ),
    credentialGeneration: 2
  };
  const proposedHardwareCommitment =
    computePhilCoreV2RecoveryDescriptorCommitment(
      proposedHardwareDescriptor
    );
  const proposed = {
    primaryDeviceCommitment:
      o372.fixtureIdentities.primaryDevice.factorCommitment,
    hardwareSecurityKeyCommitment: proposedHardwareCommitment,
    recoveryFactorCommitment:
      o372.fixtureIdentities.independentRecoveryFactor.factorCommitment
  };
  proposed.recoveryConfigHash =
    computePhilCoreV2RecoveryConfigurationHashV2({
      configurationVersion:
        PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
      threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
      ...proposed
    });
  validatePhilCoreV2RecoveryRotation({
    currentDescriptors: [
      o372.fixtureIdentities.primaryDevice.descriptor,
      currentHardware,
      o372.fixtureIdentities.independentRecoveryFactor.descriptor
    ],
    proposedDescriptors: [
      o372.fixtureIdentities.primaryDevice.descriptor,
      proposedHardwareDescriptor,
      o372.fixtureIdentities.independentRecoveryFactor.descriptor
    ],
    currentRecoveryEpoch: 2,
    proposedRecoveryEpoch: 3
  });
  return {
    ...proposed,
    rotatedRole: "HARDWARE_SECURITY_KEY",
    proposedHardwareDescriptor,
    proposedHardwarePublicMaterial: { qx, qy }
  };
}

function authenticatorData(rpIdHash, counter) {
  return hexlify(concat([
    rpIdHash,
    "0x05",
    zeroPadValue(toBeHex(counter), 4)
  ]));
}

function signWebAuthn(fixture, privateScalar, digest, counter) {
  const client = buildPhilCoreO372WebAuthnClientData({
    challenge: digest,
    origin: fixture.origin
  });
  const authData = authenticatorData(fixture.rpIdHash, counter);
  const messageHash = computePhilCoreO372WebAuthnMessageHash({
    authenticatorData: authData,
    clientDataJSON: client.clientDataJSON
  });
  const signature = p256.sign(
    getBytes(messageHash),
    getBytes(privateScalar),
    { lowS: true, prehash: false }
  );
  const evidence = {
    descriptor: fixture.descriptor,
    factorCommitment: fixture.factorCommitment,
    qx: fixture.qx,
    qy: fixture.qy,
    r: zeroPadValue(toBeHex(signature.r), 32),
    s: zeroPadValue(toBeHex(signature.s), 32),
    challengeIndex: client.challengeIndex,
    typeIndex: client.typeIndex,
    authenticatorData: authData,
    clientDataJSON: client.clientDataJSON
  };
  const verified = verifyPhilCoreO372P256Signature({
    messageHash,
    qx: fixture.qx,
    qy: fixture.qy,
    r: evidence.r,
    s: evidence.s
  });
  if (!verified.accepted) throw new Error("O37_4_P256_SIGNATURE_INVALID");
  return evidence;
}

function recoveryContext(o372, input) {
  const commitments = o372.recoveryConfiguration.commitments;
  const roles = input.bitmap === 3
    ? [commitments.primaryDevice, commitments.hardwareSecurityKey]
    : input.bitmap === 5
      ? [commitments.primaryDevice, commitments.recoveryFactor]
      : [commitments.hardwareSecurityKey, commitments.recoveryFactor];
  return {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: input.actionType,
    factorBitmap: input.bitmap,
    account: o372.fixtureDomain.account,
    chainId: o372.fixtureDomain.chainId,
    entryPoint: o372.fixtureDomain.entryPoint,
    authorizedIntentHash: input.authorizedIntentHash,
    userOperationHash: input.userOperationHash,
    requestId: input.requestId,
    currentRecoveryConfigHash:
      o372.recoveryConfiguration.recoveryConfigHash,
    validatorEpoch: 3,
    recoveryEpoch: 2,
    validAfter: input.validAfter,
    validUntil: input.validUntil,
    recoveryDelaySeconds: 172800,
    recoveryExpirySeconds: 604800,
    proposedValidatorCommitment: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryConfigHash: input.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: 3,
    primaryDeviceCommitment: commitments.primaryDevice,
    hardwareSecurityKeyCommitment: commitments.hardwareSecurityKey,
    recoveryFactorCommitment: commitments.recoveryFactor,
    firstFactorCommitment: roles[0],
    secondFactorCommitment: roles[1]
  };
}

function recoveryEvidencePair(o372, keys, input) {
  const authorizationInput = {
    authorizedIntentHash: input.authorizedIntentHash,
    userOperationHash: input.userOperationHash,
    recoveryConfigHash: o372.recoveryConfiguration.recoveryConfigHash,
    recoveryEpoch: 2,
    factorBitmap: input.bitmap
  };
  const digest = computePhilCoreV2RecoveryFactorDigest(
    {
      chainId: o372.fixtureDomain.chainId,
      account: o372.fixtureDomain.account
    },
    authorizationInput
  );
  const context = recoveryContext(o372, {
    ...input,
    requestId: input.requestId,
    validAfter: input.validAfter,
    validUntil: input.validUntil
  });
  const primary = signWebAuthn(
    o372.fixtureIdentities.primaryDevice,
    keys.primaryScalar,
    digest.digest,
    input.counter
  );
  const encodedPrimary = encodePhilCoreO372WebAuthnEvidence(primary);
  let second;
  let encodedSecond;
  if (input.bitmap === PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE) {
    second = signWebAuthn(
      o372.fixtureIdentities.hardwareSecurityKey,
      keys.hardwareScalar,
      digest.digest,
      input.counter + 1
    );
    encodedSecond = encodePhilCoreO372WebAuthnEvidence(second);
  } else {
    const signature = keys.recoveryKey.sign(digest.digest);
    second = {
      descriptor:
        o372.fixtureIdentities.independentRecoveryFactor.descriptor,
      factorCommitment:
        o372.fixtureIdentities.independentRecoveryFactor.factorCommitment,
      signer: o372.fixtureIdentities.independentRecoveryFactor.address,
      r: signature.r,
      s: signature.s,
      v: signature.v
    };
    encodedSecond = encodePhilCoreO372Secp256k1Evidence(second);
  }
  const encodedRecoveryEnvelope = encodePhilCoreO372RecoveryEnvelope({
    context,
    firstFactorEvidence: encodedPrimary,
    secondFactorEvidence: encodedSecond
  });
  computePhilCoreV2RecoveryEvidenceContextHash(context);
  return {
    classification: CLASSIFICATION,
    authorizationInput,
    recoveryDigest: digest.digest,
    context,
    contextHash: computePhilCoreV2RecoveryEvidenceContextHash(context),
    firstEvidence: primary,
    secondEvidence: second,
    encodedFirstEvidence: encodedPrimary,
    encodedSecondEvidence: encodedSecond,
    encodedRecoveryEnvelope
  };
}

function validatorEnvelope(o372, signingKey, digest) {
  const signature = signingKey.sign(digest);
  const envelope = {
    envelopeVersion: 1,
    authorityKind: 1,
    verifierKind: 1,
    validator: o372.fixtureIdentities.executionValidator.address,
    validatorKeyIdBinding:
      o372.fixtureIdentities.executionValidator.keyIdentifierBinding,
    validatorEpoch: 3,
    recoveryEpoch: 2,
    r: signature.r,
    s: signature.s,
    v: signature.v
  };
  const encoded = encodePhilCoreO372ValidatorEnvelope(envelope);
  const verified = verifyPhilCoreO372ValidatorEnvelope({
    digest,
    envelope,
    expectedValidator:
      o372.fixtureIdentities.executionValidator.address,
    expectedKeyIdBinding:
      o372.fixtureIdentities.executionValidator.keyIdentifierBinding,
    expectedValidatorEpoch: 3,
    expectedRecoveryEpoch: 2
  });
  if (!verified.accepted) {
    throw new Error("O37_4_VALIDATOR_SIGNATURE_INVALID");
  }
  return { envelope, encoded };
}

function rawCombined(version, kind, action, validatorEvidence, recoveryEvidence) {
  return abiCoder.encode(
    PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
    [version, kind, action, validatorEvidence, recoveryEvidence]
  );
}

function transportResult(id, actionType, encodedEnvelope, expected) {
  let accepted = false;
  let actualCode = "ACCEPTED";
  try {
    decodePhilCoreO374AuthorityTransport(actionType, encodedEnvelope);
    accepted = true;
  } catch (error) {
    actualCode = error.message;
  }
  if (accepted !== expected.accepted) {
    throw new Error(`O37_4_TRANSPORT_EXPECTATION_MISMATCH:${id}`);
  }
  if (!accepted && expected.code && actualCode !== expected.code) {
    throw new Error(
      `O37_4_TRANSPORT_CODE_MISMATCH:${id}:${actualCode}`
    );
  }
  return {
    classification: CLASSIFICATION,
    id,
    actionType,
    encodedEnvelope,
    expectedTransportAccepted: accepted,
    expectedCode: accepted ? "ACCEPTED" : actualCode,
    expectedVerificationLayer: expected.layer,
    expectedResult: expected.result
  };
}

function buildO374AuthorityTransportPackage() {
  const o372 = readJson(O372_PATH);
  const keys = exactFixtureKeys(o372);
  const proposed = proposedConfiguration(o372);
  const rotation = authorizationChain(
    rotationIntent(o372, proposed, "config-rotation", 2),
    "config-rotation"
  );
  const rotationUserOpHashBinding =
    H("o37.4:config-rotation:user-operation-hash-binding-only");
  const validatorDigest = computePhilCoreV2ConfigRotationDigest(
    {
      chainId: o372.fixtureDomain.chainId,
      account: o372.fixtureDomain.account
    },
    {
      authorizedIntentHash: rotation.authorizedIntentHash,
      userOperationHash: rotationUserOpHashBinding,
      validator: o372.fixtureIdentities.executionValidator.address,
      validatorEpoch: 3,
      recoveryConfigHash: o372.recoveryConfiguration.recoveryConfigHash,
      recoveryEpoch: 2,
      proposedRecoveryConfigHash: proposed.recoveryConfigHash,
      proposedRecoveryEpoch: 3,
      factorBitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE
    }
  );
  const validator = validatorEnvelope(
    o372,
    keys.validatorKey,
    validatorDigest.digest
  );
  const primaryHardware = recoveryEvidencePair(o372, keys, {
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
    bitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE,
    authorizedIntentHash: rotation.authorizedIntentHash,
    userOperationHash: rotationUserOpHashBinding,
    requestId: rotation.authorizedIntentHash,
    proposedRecoveryConfigHash: proposed.recoveryConfigHash,
    validAfter: rotation.intent.header.validAfter,
    validUntil: rotation.intent.header.validUntil,
    counter: 10
  });
  const primaryRecovery = recoveryEvidencePair(o372, keys, {
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
    bitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_RECOVERY,
    authorizedIntentHash: rotation.authorizedIntentHash,
    userOperationHash: rotationUserOpHashBinding,
    requestId: rotation.authorizedIntentHash,
    proposedRecoveryConfigHash: proposed.recoveryConfigHash,
    validAfter: rotation.intent.header.validAfter,
    validUntil: rotation.intent.header.validUntil,
    counter: 20
  });
  const combinedPrimaryHardware =
    encodePhilCoreO374CombinedAuthorityEnvelope({
      validatorEvidence: validator.encoded,
      recoveryEvidence: primaryHardware.encodedRecoveryEnvelope
    });
  const validatorDigestPrimaryRecovery =
    computePhilCoreV2ConfigRotationDigest(
      {
        chainId: o372.fixtureDomain.chainId,
        account: o372.fixtureDomain.account
      },
      {
        ...validatorDigest,
        authorizedIntentHash: rotation.authorizedIntentHash,
        userOperationHash: rotationUserOpHashBinding,
        validator: o372.fixtureIdentities.executionValidator.address,
        validatorEpoch: 3,
        recoveryConfigHash: o372.recoveryConfiguration.recoveryConfigHash,
        recoveryEpoch: 2,
        proposedRecoveryConfigHash: proposed.recoveryConfigHash,
        proposedRecoveryEpoch: 3,
        factorBitmap:
          PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_RECOVERY
      }
    );
  const validatorPrimaryRecovery = validatorEnvelope(
    o372,
    keys.validatorKey,
    validatorDigestPrimaryRecovery.digest
  );
  const combinedPrimaryRecovery =
    encodePhilCoreO374CombinedAuthorityEnvelope({
      validatorEvidence: validatorPrimaryRecovery.encoded,
      recoveryEvidence: primaryRecovery.encodedRecoveryEnvelope
    });

  const cancellation = authorizationChain(
    cancellationIntent(
      o372,
      rotation.authorizedIntentHash,
      "config-rotation-cancel",
      3
    ),
    "config-rotation-cancel"
  );
  const cancellationUserOpHashBinding =
    H("o37.4:config-cancel:user-operation-hash-binding-only");
  const cancellationEvidence = recoveryEvidencePair(o372, keys, {
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL,
    bitmap: PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_RECOVERY,
    authorizedIntentHash: cancellation.authorizedIntentHash,
    userOperationHash: cancellationUserOpHashBinding,
    requestId: rotation.authorizedIntentHash,
    proposedRecoveryConfigHash: proposed.recoveryConfigHash,
    validAfter: cancellation.intent.header.validAfter,
    validUntil: cancellation.intent.header.validUntil,
    counter: 30
  });

  const wrongBitmapContext = {
    ...primaryHardware.context,
    factorBitmap: 1
  };
  const wrongBitmapRecovery = encodePhilCoreO372RecoveryEnvelope({
    context: wrongBitmapContext,
    firstFactorEvidence: primaryHardware.encodedFirstEvidence,
    secondFactorEvidence: primaryHardware.encodedSecondEvidence
  });
  const duplicateRecovery = encodePhilCoreO372RecoveryEnvelope({
    context: primaryHardware.context,
    firstFactorEvidence: primaryHardware.encodedFirstEvidence,
    secondFactorEvidence: primaryHardware.encodedFirstEvidence
  });
  const reorderedRecovery = encodePhilCoreO372RecoveryEnvelope({
    context: primaryHardware.context,
    firstFactorEvidence: primaryHardware.encodedSecondEvidence,
    secondFactorEvidence: primaryHardware.encodedFirstEvidence
  });
const staleContext = {
  ...primaryHardware.context,
  recoveryEpoch: 1,
  proposedRecoveryEpoch: 2
};
  const staleRecovery = encodePhilCoreO372RecoveryEnvelope({
    context: staleContext,
    firstFactorEvidence: primaryHardware.encodedFirstEvidence,
    secondFactorEvidence: primaryHardware.encodedSecondEvidence
  });
  const alteredContext = {
    ...primaryHardware.context,
    firstFactorCommitment: H("o37.4:altered-factor-commitment")
  };
  const alteredRecovery = encodePhilCoreO372RecoveryEnvelope({
    context: alteredContext,
    firstFactorEvidence: primaryHardware.encodedFirstEvidence,
    secondFactorEvidence: primaryHardware.encodedSecondEvidence
  });

  const invalid = [
    transportResult(
      "missing_validator",
      10,
      rawCombined(
        1,
        3,
        10,
        "0x",
        primaryHardware.encodedRecoveryEnvelope
      ),
      {
        accepted: false,
        code: "validator_evidence_length_invalid",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "missing_recovery_witness",
      10,
      rawCombined(1, 3, 10, validator.encoded, "0x"),
      {
        accepted: false,
        code: "combined_authority_envelope_length_invalid",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "wrong_bitmap",
      10,
      rawCombined(1, 3, 10, validator.encoded, wrongBitmapRecovery),
      {
        accepted: false,
        code: "recovery_factor_bitmap_invalid",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "duplicate_factor",
      10,
      rawCombined(1, 3, 10, validator.encoded, duplicateRecovery),
      {
        accepted: false,
        code: "recovery_factor_evidence_missing_or_duplicate",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "wrong_role_order",
      10,
      rawCombined(1, 3, 10, validator.encoded, reorderedRecovery),
      {
        accepted: true,
        layer: "RECOVERY_MEMBERSHIP",
        result: "REJECTED"
      }
    ),
    transportResult(
      "stale_epoch",
      10,
      rawCombined(1, 3, 10, validator.encoded, staleRecovery),
      {
        accepted: true,
        layer: "ACCOUNT_STATE",
        result: "REJECTED"
      }
    ),
    transportResult(
      "malformed_truncation",
      10,
      combinedPrimaryHardware.slice(0, -64),
      {
        accepted: false,
        code: "combined_authority_envelope_malformed",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "reordered_outer_fields",
      10,
      rawCombined(
        1,
        3,
        10,
        primaryHardware.encodedRecoveryEnvelope,
        validator.encoded
      ),
      {
        accepted: false,
        code: "validator_evidence_length_invalid",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "altered_commitment",
      10,
      rawCombined(1, 3, 10, validator.encoded, alteredRecovery),
      {
        accepted: true,
        layer: "RECOVERY_MEMBERSHIP",
        result: "REJECTED"
      }
    ),
    transportResult(
      "mixed_version",
      10,
      rawCombined(
        2,
        3,
        10,
        validator.encoded,
        primaryHardware.encodedRecoveryEnvelope
      ),
      {
        accepted: false,
        code: "combined_authority_envelope_version_unsupported",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    ),
    transportResult(
      "appended_extension",
      10,
      hexlify(concat([
        combinedPrimaryHardware,
        PHILCORE_V2_ZERO_BYTES32
      ])),
      {
        accepted: false,
        code: "combined_authority_envelope_noncanonical",
        layer: "TRANSPORT",
        result: "REJECTED"
      }
    )
  ];

  decodePhilCoreO374AuthorityTransport(
    PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
    o372.validAuthorizationFixture.encodedValidatorEnvelope
  );
  decodePhilCoreO374AuthorityTransport(
    PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
    o372.recoveryAuthorizationFixtures.primaryAndHardware
      .encodedRecoveryEnvelope
  );
  decodePhilCoreO374AuthorityTransport(
    PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
    combinedPrimaryHardware
  );
  decodePhilCoreO374AuthorityTransport(
    PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL,
    cancellationEvidence.encodedRecoveryEnvelope
  );

  return {
    schemaVersion: "philcore-o37-4-authority-transport-v1",
    phase: "O.37.4",
    canonicalPhaseName:
      "O.37.4 V2 Authority Transport and ERC-4337 Envelope Finalization",
    classification: CLASSIFICATION,
    sourceHeadAtPhaseStart: SOURCE_HEAD_AT_PHASE_START,
    publicMutationCount: 0,
    priorFixturePackage: {
      path:
        "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json",
      sha256: sha256File(
        "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
      ),
      modifiedByO37_4: false
    },
    authorityTransportFreeze: {
      version: PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION,
      authorityClasses: PHILCORE_O37_4_AUTHORITY_CLASS,
      actionDispatch: {
        validatorOnly: [0, 1, 2, 3, 4, 5, 6, 7],
        recoveryOnly: [8, 9, 11],
        validatorAndRecovery: [10]
      },
      validatorOnly: {
        encoding: "O36_1_VALIDATOR_AUTHORITY_ENVELOPE_V1_DIRECT",
        exactBytes: PHILCORE_O37_4_VALIDATOR_EVIDENCE_BYTES
      },
      recoveryOnly: {
        encoding: "O37_1_RECOVERY_AUTHORITY_ENVELOPE_V2_DIRECT",
        minimumBytes: PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES,
        maximumBytes: PHILCORE_O37_4_RECOVERY_EVIDENCE_MAX_BYTES
      },
      combined: {
        typeString: PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE,
        typeHash: PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH,
        abiTypes: [...PHILCORE_O37_4_COMBINED_AUTHORITY_ABI],
        envelopeVersion: PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION,
        authorityKind: PHILCORE_O37_4_COMBINED_AUTHORITY_KIND,
        actionType: PHILCORE_O37_4_CONFIG_ROTATION_ACTION,
        fieldOrder: [
          "envelopeVersion",
          "authorityKind",
          "actionType",
          "validatorEvidence",
          "recoveryEvidence"
        ],
        lengthFormula:
          "544 + recoveryEvidence.length",
        minimumBytes: PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES,
        maximumBytes: PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES,
        canonicalReencodingRequired: true,
        appendedBytesAllowed: false
      },
      factorEvidenceBounds: {
        webAuthnMinimumBytes:
          PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MIN_BYTES,
        webAuthnMaximumBytes:
          PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MAX_BYTES,
        secp256k1ExactBytes:
          PHILCORE_O37_4_SECP256K1_EVIDENCE_BYTES
      }
    },
    nonceBoundary: {
      entryPointOwnsKeyedSequenceState: true,
      accountDuplicateNonceStorage: false,
      nonceEncoding: "(uint192 lane << 64) | uint64 sequence",
      lanes: {
        ordinary: 0,
        maintenance: 1,
        recovery: 2
      },
      accountVerifiesLaneActionAndIntentParity: true,
      intentIncludesLaneAndSequence: true
    },
    constructorBoundary: {
      fieldCount: 20,
      descriptorsInConstructor: false,
      onchainRecoveryMaterial:
        "THREE_DESCRIPTOR_COMMITMENTS_AND_CONFIGURATION_HASH",
      runtimeValidatesFullDescriptorsBeforeDeployment: true,
      accountRecomputesConfigurationHashVersion: 2,
      threshold: 2,
      create2BindsCompleteConstructorArguments: true
    },
    valid: {
      normalValidatorExecution: {
        classification: CLASSIFICATION,
        source: "O37_2",
        sourceUserOperationFixture: "O37_2_EXISTING_REFERENCE",
        userOperationCreated: false,
        actionType: PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
        encodedSignature:
          o372.validAuthorizationFixture.encodedValidatorEnvelope,
        authorityClass: "VALIDATOR_ONLY",
        expectedResult: "ACCEPTED"
      },
      validatorPlusPrimaryAndHardwareConfigRotation: {
        classification: CLASSIFICATION,
        actionType:
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
        authorityClass: "VALIDATOR_AND_RECOVERY",
        authorizedIntentHash: rotation.authorizedIntentHash,
        userOperationHashBinding: rotationUserOpHashBinding,
        userOperationCreated: false,
        validatorDigest: validatorDigest.digest,
        recoveryDigest: primaryHardware.recoveryDigest,
        validatorEnvelope: validator.envelope,
        encodedValidatorEvidence: validator.encoded,
        recoveryEvidence: primaryHardware,
        encodedSignature: combinedPrimaryHardware,
        expectedResult: "ACCEPTED"
      },
      validatorPlusPrimaryAndRecoveryFactorRotation: {
        classification: CLASSIFICATION,
        actionType:
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
        authorityClass: "VALIDATOR_AND_RECOVERY",
        authorizedIntentHash: rotation.authorizedIntentHash,
        userOperationHashBinding: rotationUserOpHashBinding,
        userOperationCreated: false,
        validatorDigest: validatorDigestPrimaryRecovery.digest,
        recoveryDigest: primaryRecovery.recoveryDigest,
        validatorEnvelope: validatorPrimaryRecovery.envelope,
        encodedValidatorEvidence: validatorPrimaryRecovery.encoded,
        recoveryEvidence: primaryRecovery,
        encodedSignature: combinedPrimaryRecovery,
        expectedResult: "ACCEPTED"
      },
      recoveryConfigCancellation: {
        classification: CLASSIFICATION,
        actionType:
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL,
        authorityClass: "RECOVERY_ONLY",
        authorizedIntentHash: cancellation.authorizedIntentHash,
        userOperationHashBinding: cancellationUserOpHashBinding,
        userOperationCreated: false,
        recoveryEvidence: cancellationEvidence,
        encodedSignature: cancellationEvidence.encodedRecoveryEnvelope,
        expectedResult: "ACCEPTED"
      }
    },
    proposedFactorRotation: {
      classification: CLASSIFICATION,
      currentRecoveryConfigHash:
        o372.recoveryConfiguration.recoveryConfigHash,
      proposedRecoveryConfigHash: proposed.recoveryConfigHash,
      currentRecoveryEpoch: 2,
      proposedRecoveryEpoch: 3,
      rotatedRole: proposed.rotatedRole,
      proposedHardwareDescriptor: proposed.proposedHardwareDescriptor,
      proposedHardwarePublicMaterial:
        proposed.proposedHardwarePublicMaterial,
      commitments: {
        primaryDevice: proposed.primaryDeviceCommitment,
        hardwareSecurityKey: proposed.hardwareSecurityKeyCommitment,
        recoveryFactor: proposed.recoveryFactorCommitment
      }
    },
    invalid,
    digestRules: {
      validatorForConfigRotation:
        "O32_CONFIG_ROTATION_AUTHORIZATION_DIGEST",
      factorsForConfigRotation:
        "O32_RECOVERY_AUTHORIZATION_DIGEST",
      sharedBindings: [
        "account",
        "chainId",
        "authorizedIntentHash",
        "userOperationHash",
        "validatorEpoch",
        "recoveryEpoch",
        "currentRecoveryConfigHash",
        "proposedRecoveryConfigHash",
        "proposedRecoveryEpoch",
        "factorBitmap"
      ]
    },
    implementationBindings: {
      authorityTransportSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2AuthorityTransport.ts"
      ),
      intentSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2Intent.ts"
      ),
      authorizationSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2Authorization.ts"
      ),
      recoveryEvidenceSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2RecoveryEvidence.ts"
      ),
      o37_2FixtureUtilitySha256: sha256File(
        "apps/phil-device-sdk/src/v2DeterministicFixtures.ts"
      )
    },
    securityBoundary: {
      classification: CLASSIFICATION,
      priorFixtureModified: false,
      privateScalarsCommitted: false,
      realCredentialCreated: false,
      productionSignatureCreated: false,
      productionUserOperationCreated: false,
      userOperationSubmitted: false,
      userOperationEstimated: false,
      solidityCreated: false,
      bytecodeCreated: false,
      deploymentPerformed: false,
      rpcUsed: false,
      fundsMoved: false,
      publicMutationOccurred: false
    }
  };
}

function main() {
  const checkOnly = process.argv.includes("--check");
  const output = stringify(buildO374AuthorityTransportPackage());
  if (checkOnly) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      throw new Error("O37_4_AUTHORITY_TRANSPORT_PACKAGE_MISSING");
    }
    if (fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O37_4_AUTHORITY_TRANSPORT_PACKAGE_STALE");
    }
    process.stdout.write("O.37.4 authority transport package is current\n");
    return;
  }
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO374AuthorityTransportPackage
};
