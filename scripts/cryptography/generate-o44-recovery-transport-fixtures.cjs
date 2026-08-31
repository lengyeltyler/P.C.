require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  getBytes,
  hexlify,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");

const transport = require("../../apps/phil-device-sdk/src/v2RecoveryTransport.ts");
const {
  computePhilCoreV2RecoveryFactorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  PHILCORE_V2_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  computePhilCoreV2ConsumerRecoveryEvidenceContextHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts");
const {
  computePhilCoreV2ConsumerRecoveryConfigurationHash,
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_O37_2_P256_HALF_ORDER,
  PHILCORE_O37_2_P256_ORDER
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_NATIVE_IPHONE_ROLE1
} = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  nativeEvidence,
  nativeFactor
} = require("./generate-o43-native-iphone-fixtures.cjs");
const {
  offlineFactor,
  secpEvidence,
  webAuthnEvidence,
  webAuthnFactor
} = require("./generate-o39-consumer-recovery-fixtures.cjs");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O44_RECOVERY_TRANSPORT_FIXTURES.json"
);
const H = (value) => keccak256(toUtf8Bytes(value));
const FORBIDDEN_PATTERNS = [
  /"privateScalar"\s*:/u,
  /"privateKey"\s*:/u,
  /"recoveryCode"\s*:/u,
  /"offlineEntropy"\s*:/u,
  /"ecdhPrivate"\s*:/u,
  /"sharedSecret"\s*:/u
];

function encodeDerInteger(value) {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = Buffer.from(hex, "hex");
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

function encodeDerSignature(r, s) {
  const body = Buffer.concat([encodeDerInteger(r), encodeDerInteger(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function deterministicP256Scalar(label) {
  return zeroPadValue(
    toBeHex((BigInt(H(label)) % (PHILCORE_O37_2_P256_ORDER - 1n)) + 1n),
    32
  );
}

function deterministicNonce(label) {
  return Buffer.from(getBytes(H(label))).subarray(0, 12);
}

function ecdhSharedSecretX(privateScalar, peerPublicKeyUncompressed) {
  const shared = p256.getSharedSecret(
    getBytes(privateScalar),
    peerPublicKeyUncompressed,
    true
  );
  // noble compressed shared secret: 0x02/0x03 || x  → use x only (Node ECDH style)
  return Buffer.from(shared.slice(1, 33));
}

function encryptDeterministicRecoveryApprovalMessage(input) {
  const sessionId = input.sessionId.toLowerCase();
  const key = Buffer.from(input.key);
  const nonce = Buffer.from(input.nonce);
  if (key.length !== 32 || nonce.length !== 12) {
    throw new Error("O44_DETERMINISTIC_CIPHER_PARAMS_INVALID");
  }
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`${input.direction}|${sessionId}`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(input.value), "utf8")),
    cipher.final()
  ]);
  return {
    version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    phoneEphemeralPublicKey: input.phoneEphemeralPublicKey ?? null,
    nonce: Buffer.from(nonce).toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
}

function buildV3Context(commitments, bitmap, overrides = {}) {
  const roles = transport.rolesForRecoveryFactorBitmap(bitmap);
  const currentRecoveryConfigHash =
    computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
  return {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: 8,
    factorBitmap: bitmap,
    account: "0x0000000000000000000000000000000000004400",
    chainId: "31337",
    entryPoint: "0x00000000000000000000000000000000000F4337",
    authorizedIntentHash: H("O44:AUTHORIZED_INTENT"),
    userOperationHash: H("O44:USER_OPERATION"),
    requestId: H("O44:AUTHORIZED_INTENT"),
    currentRecoveryConfigHash,
    validatorEpoch: 1,
    recoveryEpoch: 1,
    validAfter: 1000,
    validUntil: 5000,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment: H("O44:PROPOSED_VALIDATOR"),
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: 2,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: commitments[roles[0]],
    secondFactorCommitment: commitments[roles[1]],
    ...overrides
  };
}

function contextHashFor(context) {
  return computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
}

function digestFor(context) {
  return computePhilCoreV2RecoveryFactorDigest(
    { chainId: context.chainId, account: context.account },
    {
      authorizedIntentHash: context.authorizedIntentHash,
      userOperationHash: context.userOperationHash,
      recoveryConfigHash: context.currentRecoveryConfigHash,
      recoveryEpoch: context.recoveryEpoch,
      factorBitmap: context.factorBitmap
    }
  ).digest;
}

function buildDerLowSVectors() {
  const scalar = deterministicP256Scalar("O44:HIGH_S_KEY");
  const digest = getBytes(H("O44:HIGH_S_DIGEST"));

  const lowSignature = p256.sign(digest, getBytes(scalar), {
    lowS: true,
    prehash: false
  });
  const lowDer = encodeDerSignature(lowSignature.r, lowSignature.s);
  const lowParsed = transport.parseDerEcdsaP256Signature(lowDer);
  const lowNormalized = transport.normalizeP256SignatureLowS(lowParsed);

  let highSignature = p256.sign(digest, getBytes(scalar), {
    lowS: false,
    prehash: false
  });
  if (highSignature.s <= PHILCORE_O37_2_P256_HALF_ORDER) {
    highSignature = {
      r: highSignature.r,
      s: PHILCORE_O37_2_P256_ORDER - highSignature.s
    };
  }
  const highDer = encodeDerSignature(highSignature.r, highSignature.s);
  const highParsed = transport.parseDerEcdsaP256Signature(highDer);
  const highNormalized = transport.normalizeP256SignatureLowS(highParsed);

  return {
    alreadyLow: {
      derHex: hexlify(lowDer),
      r: lowNormalized.r,
      s: lowNormalized.s,
      normalized: lowNormalized.normalized
    },
    initiallyHigh: {
      derHex: hexlify(highDer),
      r: highNormalized.r,
      sBefore: highParsed.s,
      sAfter: highNormalized.s,
      normalized: highNormalized.normalized
    }
  };
}

function assertNoForbiddenSubstrings(serialized) {
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(`O44_FIXTURE_FORBIDDEN_SUBSTRING:${pattern}`);
    }
  }
}

function buildApprovalRequest(native, commitments, desktopEphemeralPublicKey) {
  const context = buildV3Context(commitments, 6);
  const recoveryFactorDigest = digestFor(context);
  const contextHash = contextHashFor(context);
  return {
    protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    context,
    claimedContextHash: contextHash,
    claimedRecoveryFactorDigest: recoveryFactorDigest,
    accountVersionId: native.descriptor.accountVersionId,
    securityModelId: native.descriptor.securityModelId,
    nativeRecoveryDomainId: native.descriptor.recoveryDomainId,
    applicationIdentity: PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity,
    localApprovalPolicy:
      "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST",
    selectedRole1CredentialIdentifierCommitment:
      native.descriptor.credentialIdentifierCommitment,
    selectedRole1CredentialGeneration: 1,
    trustedRole1Descriptor: native.descriptor,
    trustedRole1PublicKey: {
      qx: native.qx,
      qy: native.qy
    },
    sessionId: `0x${"55".repeat(32)}`,
    sessionChallenge: `0x${"66".repeat(32)}`,
    desktopEphemeralPublicKey,
    issuedAt: "1700000000000",
    expiresAt: "1700000300000",
    endpoint: "http://192.168.1.44:8787/philcore/recovery/v1/complete",
    now: "1700000100000",
    actionText: transport.derivedRecoveryActionText(context),
    networkText: transport.derivedRecoveryNetworkText(context)
  };
}

function cloneRequest(request, overrides = {}) {
  return {
    ...request,
    ...overrides,
    context: overrides.context
      ? { ...request.context, ...overrides.context }
      : { ...request.context },
    trustedRole1Descriptor: overrides.trustedRole1Descriptor
      || { ...request.trustedRole1Descriptor },
    trustedRole1PublicKey: overrides.trustedRole1PublicKey
      || { ...request.trustedRole1PublicKey }
  };
}

function buildNegativeMutations(baseRequest) {
  return [
    {
      field: "chainId",
      expectedError: "digest|mismatch|recomput|canonical|chainId",
      request: cloneRequest(baseRequest, {
        context: { chainId: "31338" }
      })
    },
    {
      field: "account",
      expectedError: "digest|mismatch|recomput|account|identity",
      request: cloneRequest(baseRequest, {
        context: {
          account: "0x0000000000000000000000000000000000004401"
        }
      })
    },
    {
      field: "factorBitmap",
      expectedError: "bitmap|role.?1|native",
      request: (() => {
        const context = buildV3Context(
          [
            baseRequest.context.primaryDeviceCommitment,
            baseRequest.context.hardwareSecurityKeyCommitment,
            baseRequest.context.recoveryFactorCommitment
          ],
          5
        );
        return cloneRequest(baseRequest, {
          context,
          claimedContextHash: contextHashFor(context),
          claimedRecoveryFactorDigest: digestFor(context)
        });
      })()
    },
    {
      field: "authorizedIntentHash",
      expectedError: "digest|mismatch|recomput",
      request: cloneRequest(baseRequest, {
        context: { authorizedIntentHash: H("O44:MUTATED_INTENT") }
      })
    },
    {
      field: "userOperationHash",
      expectedError: "digest|mismatch|recomput",
      request: cloneRequest(baseRequest, {
        context: { userOperationHash: H("O44:MUTATED_USEROP") }
      })
    },
    {
      field: "requestId",
      expectedError: "request.?id|authorized.?intent|mismatch|recomput",
      request: cloneRequest(baseRequest, {
        context: { requestId: H("O44:MUTATED_REQUEST_ID") }
      })
    },
    {
      field: "currentRecoveryConfigHash",
      expectedError: "current_recovery_config_hash_mismatch|mismatch",
      request: cloneRequest(baseRequest, {
        context: { currentRecoveryConfigHash: `0x${"11".repeat(32)}` }
      })
    },
    {
      field: "recoveryEpoch",
      expectedError: "digest|mismatch|recomput",
      request: cloneRequest(baseRequest, {
        context: { recoveryEpoch: 99 }
      })
    },
    {
      field: "sessionId",
      expectedError: "session|distinct|bytes32",
      request: cloneRequest(baseRequest, {
        sessionId: baseRequest.sessionChallenge
      })
    },
    {
      field: "sessionChallenge",
      expectedError: "session|distinct|bytes32",
      request: cloneRequest(baseRequest, {
        sessionChallenge: baseRequest.sessionId
      })
    },
    {
      field: "desktopEphemeralPublicKey",
      expectedError: "p256|ephemeral|curve|point",
      request: cloneRequest(baseRequest, {
        desktopEphemeralPublicKey: Buffer.alloc(65, 9).toString("base64url")
      })
    },
    {
      field: "endpoint",
      expectedError: "endpoint|invalid",
      request: cloneRequest(baseRequest, {
        endpoint: "http://127.0.0.1:8787/philcore/recovery/v1/complete"
      })
    },
    {
      field: "applicationIdentity",
      expectedError: "application|identity|pin",
      request: cloneRequest(baseRequest, {
        applicationIdentity: "WRONG_APPLICATION_IDENTITY"
      })
    },
    {
      field: "selectedRole1CredentialIdentifierCommitment",
      expectedError: "credential|descriptor|commitment",
      request: cloneRequest(baseRequest, {
        selectedRole1CredentialIdentifierCommitment: `0x${"99".repeat(32)}`
      })
    },
    {
      field: "claimedRecoveryFactorDigest",
      expectedError: "digest|mismatch|recomput",
      request: cloneRequest(baseRequest, {
        claimedRecoveryFactorDigest: `0x${"ab".repeat(32)}`
      })
    },
    {
      field: "now",
      expectedError: "expir|fresh|window",
      request: cloneRequest(baseRequest, {
        now: "1700000400000"
      })
    }
  ];
}

function buildFactorPairs(primary, native, offline, verifierRequest, commitments) {
  return [3, 5, 6].map((bitmap, index) => {
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: verifierRequest.chainId, account: verifierRequest.account },
      {
        authorizedIntentHash: verifierRequest.authorizedIntentHash,
        userOperationHash: verifierRequest.userOpHash,
        recoveryConfigHash: verifierRequest.recoveryConfigHash,
        recoveryEpoch: verifierRequest.recoveryEpoch,
        factorBitmap: bitmap
      }
    ).digest;
    const roles = transport.rolesForRecoveryFactorBitmap(bitmap);
    const evidence = bitmap === 3
      ? [
        webAuthnEvidence(primary, digest, index + 1),
        nativeEvidence(native, digest)
      ]
      : bitmap === 5
        ? [
          webAuthnEvidence(primary, digest, index + 1),
          secpEvidence(offline, digest)
        ]
        : [
          nativeEvidence(native, digest),
          secpEvidence(offline, digest)
        ];
    const envelope = transport.assemblePhilCoreRecoveryEnvelopeFromVerifiedFactors({
      request: verifierRequest,
      commitments,
      bitmap,
      verifiedFactors: [
        { role: roles[0], evidence: evidence[0] },
        { role: roles[1], evidence: evidence[1] }
      ]
    });
    return {
      bitmap,
      roles: [...roles],
      digest,
      envelope
    };
  });
}

function buildO44RecoveryTransportFixturePackage() {
  const primary = webAuthnFactor(
    "STANDARD:primary",
    0,
    PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const native = nativeFactor();
  const offline = offlineFactor("STANDARD");
  const commitments = [
    primary.factorCommitment,
    native.factorCommitment,
    offline.factorCommitment
  ];
  const recoveryConfigHash =
    computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);

  const desktopScalar = deterministicP256Scalar("O44:DESKTOP_EPHEMERAL_SCALAR");
  const phoneScalar = deterministicP256Scalar("O44:PHONE_EPHEMERAL_SCALAR");
  const desktopPublicKey = Buffer.from(
    p256.getPublicKey(getBytes(desktopScalar), false)
  );
  const phonePublicKey = Buffer.from(
    p256.getPublicKey(getBytes(phoneScalar), false)
  );
  const sharedFromDesktop = ecdhSharedSecretX(desktopScalar, phonePublicKey);
  const sharedFromPhone = ecdhSharedSecretX(phoneScalar, desktopPublicKey);
  if (!sharedFromDesktop.equals(sharedFromPhone)) {
    throw new Error("O44_ECDH_AGREEMENT_FAILED");
  }
  const agreementFingerprint = sha256(sharedFromDesktop);
  const desktopEphemeralPublicKey = desktopPublicKey.toString("base64url");
  const phoneEphemeralPublicKey = phonePublicKey.toString("base64url");

  const approvalRequest = buildApprovalRequest(
    native,
    commitments,
    desktopEphemeralPublicKey
  );
  const context = approvalRequest.context;
  const recoveryFactorDigest = approvalRequest.claimedRecoveryFactorDigest;
  const contextHash = approvalRequest.claimedContextHash;

  transport.validatePhilCoreRecoveryApprovalRequest(approvalRequest);
  const transcript = transport.buildPhilCoreNativeRecoveryApprovalTranscript(
    approvalRequest
  );
  const transcriptHashBytes =
    transport.hashPhilCoreNativeRecoveryApprovalTranscript(transcript);
  const transcriptHash = hexlify(transcriptHashBytes);
  const comparisonFingerprint =
    transport.displayPhilCoreRecoveryComparisonFingerprint(transcriptHashBytes);

  const aesKey = transport.deriveRecoveryApprovalAesKey(
    sharedFromDesktop,
    transcriptHashBytes
  );
  const aesKeyFingerprint = sha256(aesKey);

  const recoverySignature = p256.sign(
    getBytes(recoveryFactorDigest),
    getBytes(native.privateScalar),
    { lowS: true, prehash: false }
  );
  const derRecoverySignature = encodeDerSignature(
    recoverySignature.r,
    recoverySignature.s
  ).toString("base64url");

  const responsePlaintext = {
    protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId: approvalRequest.sessionId,
    transcriptHash,
    role1FactorCommitment: context.hardwareSecurityKeyCommitment,
    credentialIdentifierCommitment:
      approvalRequest.selectedRole1CredentialIdentifierCommitment,
    credentialGeneration: Number(
      approvalRequest.selectedRole1CredentialGeneration
    ),
    derRecoverySignature
  };
  const acknowledgementPlaintext = {
    protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId: approvalRequest.sessionId,
    transcriptHash,
    status: "ACCEPTED"
  };

  const responseNonce = deterministicNonce("O44:RESPONSE_AES_GCM_NONCE_V1");
  const ackNonce = deterministicNonce("O44:ACK_AES_GCM_NONCE_V1");
  if (responseNonce.equals(ackNonce)) {
    throw new Error("O44_NONCE_LABELS_COLLIDED");
  }

  const encryptedResponse = encryptDeterministicRecoveryApprovalMessage({
    value: responsePlaintext,
    sessionId: approvalRequest.sessionId,
    key: aesKey,
    direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP,
    phoneEphemeralPublicKey,
    nonce: responseNonce
  });
  const encryptedAcknowledgement = encryptDeterministicRecoveryApprovalMessage({
    value: acknowledgementPlaintext,
    sessionId: approvalRequest.sessionId,
    key: aesKey,
    direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE,
    phoneEphemeralPublicKey: null,
    nonce: ackNonce
  });

  transport.validateEncryptedNativeRecoveryResponse(encryptedResponse);
  transport.validateEncryptedRecoveryAcknowledgement(encryptedAcknowledgement);
  transport.assertDistinctRecoveryApprovalNonces(
    encryptedResponse,
    encryptedAcknowledgement
  );
  transport.validateNativeRecoveryResponsePayload(responsePlaintext, {
    sessionId: approvalRequest.sessionId,
    transcriptHash: transcriptHashBytes,
    role1FactorCommitment: context.hardwareSecurityKeyCommitment,
    credentialIdentifierCommitment:
      approvalRequest.selectedRole1CredentialIdentifierCommitment,
    credentialGeneration: Number(
      approvalRequest.selectedRole1CredentialGeneration
    )
  });
  transport.validateNativeRecoveryAcknowledgementPayload(
    acknowledgementPlaintext,
    {
      sessionId: approvalRequest.sessionId,
      transcriptHash: transcriptHashBytes
    }
  );

  const decryptedResponse = JSON.parse(transport.decryptRecoveryApprovalMessage({
    message: encryptedResponse,
    key: aesKey,
    direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP
  }).toString("utf8"));
  const decryptedAcknowledgement = JSON.parse(
    transport.decryptRecoveryApprovalMessage({
      message: encryptedAcknowledgement,
      key: aesKey,
      direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE
    }).toString("utf8")
  );
  if (JSON.stringify(decryptedResponse) !== JSON.stringify(responsePlaintext)) {
    throw new Error("O44_ENCRYPTED_RESPONSE_ROUNDTRIP_MISMATCH");
  }
  if (
    JSON.stringify(decryptedAcknowledgement)
      !== JSON.stringify(acknowledgementPlaintext)
  ) {
    throw new Error("O44_ENCRYPTED_ACKNOWLEDGEMENT_ROUNDTRIP_MISMATCH");
  }

  const verifierRequest = {
    actionType: 8,
    account: "0x0000000000000000000000000000000000004300",
    chainId: "31337",
    entryPoint: "0x00000000000000000000000000000000000F4337",
    accountVersionId: native.descriptor.accountVersionId,
    securityModelId: native.descriptor.securityModelId,
    authorizedIntentHash: H("O43:AUTHORIZED_INTENT"),
    userOpHash: H("O43:USER_OPERATION"),
    validator: "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa",
    validatorKeyIdBinding: H("O43:VALIDATOR_KEY_ID_BINDING"),
    validatorEpoch: 1,
    recoveryEpoch: 1,
    recoveryConfigHash,
    requestId: H("O43:AUTHORIZED_INTENT"),
    validAfter: 1000,
    validUntil: 5000,
    proposedValidatorCommitment: H("O43:PROPOSED_VALIDATOR"),
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: 2,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2]
  };

  const factorPairs = buildFactorPairs(
    primary,
    native,
    offline,
    verifierRequest,
    commitments
  );
  const bitmap6 = factorPairs.find((entry) => entry.bitmap === 6);

  const staticVerifierNegatives = [
    {
      label: "wrong_account",
      requestOverride: {
        account: "0x00000000000000000000000000000000000043ff"
      }
    },
    {
      label: "wrong_chain",
      requestOverride: { chainId: "31338" }
    },
    {
      label: "wrong_recovery_epoch",
      requestOverride: { recoveryEpoch: 99 }
    },
    {
      label: "wrong_config_hash",
      requestOverride: {
        recoveryConfigHash: `0x${"22".repeat(32)}`
      }
    },
    {
      label: "wrong_bitmap_via_byte_flip",
      envelope: (() => {
        const flipped = Buffer.from(getBytes(bitmap6.envelope));
        flipped[96] ^= 0x01;
        return hexlify(flipped);
      })()
    },
    {
      label: "truncated_envelope",
      envelope: hexlify(getBytes(bitmap6.envelope).slice(0, 64))
    }
  ];

  // Public approval request for fixtures — drop nothing sensitive; scalars never enter.
  const publicApprovalRequest = {
    ...approvalRequest,
    trustedRole1Descriptor: { ...native.descriptor },
    trustedRole1PublicKey: { qx: native.qx, qy: native.qy }
  };

  const pkg = {
    phase: "O.44",
    classification: "DETERMINISTIC_SYNTHETIC_TEST_ONLY",
    publicMutationCount: 0,
    networkCalls: 0,
    productionCredentialCreated: false,
    productionSignatureCreated: false,
    blockchainMutations: 0,
    secretsCommitted: false,
    protocolConstants: {
      transcriptLabel: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_TRANSCRIPT_LABEL,
      hkdfInfo: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO,
      aadPhoneToDesktop:
        transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP,
      aadDesktopToPhone:
        transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE,
      endpointPath: transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH,
      maxTtlMs: transport.PHILCORE_RECOVERY_APPROVAL_MAX_TTL_MS,
      phil39DomainLabel: transport.PHIL39_V1_OFFLINE_DERIVATION_DOMAIN_LABEL,
      phil39FormatPrefix: transport.PHIL39_V1_OFFLINE_FORMAT_PREFIX
    },
    validBitmaps: [3, 5, 6],
    nativeApprovalBitmaps: [3, 6],
    context,
    approvalRequest: publicApprovalRequest,
    contextHash,
    recoveryFactorDigest,
    transcriptHash,
    comparisonFingerprint,
    verifierRequest,
    hkdfAesGcm: {
      ikmLength: 32,
      transcriptHash,
      aesKeyLength: 32,
      aesKeyFingerprint,
      desktopEphemeralPublicKey,
      phoneEphemeralPublicKey,
      sharedSecretFingerprint: agreementFingerprint,
      ecdhAgreementProven: true,
      responsePlaintext,
      encryptedResponse,
      acknowledgementPlaintext,
      encryptedAcknowledgement
    },
    derLowS: buildDerLowSVectors(),
    factorPairs,
    phil39: {
      domainLabel: transport.PHIL39_V1_OFFLINE_DERIVATION_DOMAIN_LABEL,
      formatPrefix: transport.PHIL39_V1_OFFLINE_FORMAT_PREFIX
    },
    negativeMutations: buildNegativeMutations(publicApprovalRequest),
    staticVerifierNegatives
  };

  assertNoForbiddenSubstrings(JSON.stringify(
    pkg,
    (_key, value) => (typeof value === "bigint" ? value.toString() : value)
  ));
  return pkg;
}

function main() {
  const output = `${JSON.stringify(
    buildO44RecoveryTransportFixturePackage(),
    (_key, value) => (typeof value === "bigint" ? value.toString() : value),
    2
  )}\n`;
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH) || fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O44_RECOVERY_TRANSPORT_FIXTURES_STALE");
    }
    process.stdout.write("O.44 recovery transport fixtures are current\n");
    return;
  }
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO44RecoveryTransportFixturePackage
};
