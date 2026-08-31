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

const bootstrap = require("../../apps/phil-device-sdk/src/v2RecoveryBootstrap.ts");
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
  PHILCORE_O37_2_P256_ORDER
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_NATIVE_IPHONE_ROLE1
} = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  nativeFactor
} = require("./generate-o43-native-iphone-fixtures.cjs");
const {
  offlineFactor,
  webAuthnFactor
} = require("./generate-o39-consumer-recovery-fixtures.cjs");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O45_RECOVERY_BOOTSTRAP_FIXTURES.json"
);
const H = (value) => keccak256(toUtf8Bytes(value));
const FORBIDDEN_PATTERNS = [
  /"privateScalar"\s*:/u,
  /"privateKey"\s*:/u,
  /"recoveryCode"\s*:/u,
  /"offlineEntropy"\s*:/u,
  /"ecdhPrivate"\s*:/u,
  /"sharedSecret"\s*:/u,
  /"aesKey"\s*:/u
];

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
  return Buffer.from(shared.slice(1, 33));
}

function encryptRecoveryRequestDeliveryDeterministic(input) {
  const sessionId = input.sessionId.toLowerCase();
  const key = Buffer.from(input.key);
  const nonce = Buffer.from(input.nonce);
  if (key.length !== 32 || nonce.length !== 12) {
    throw new Error("O45_DETERMINISTIC_CIPHER_PARAMS_INVALID");
  }
  const aad = bootstrap.buildRequestDeliveryAad({
    sessionId,
    requestHash: input.requestHash,
    phoneEphemeralPublicKey: input.phoneEphemeralPublicKey,
    fetchChallenge: input.fetchChallenge
  });
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(input.plaintext)),
    cipher.final()
  ]);
  return {
    protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
    sessionId,
    nonce: Buffer.from(nonce).toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
}

function buildV3Context(commitments, bitmap) {
  const roles = transport.rolesForRecoveryFactorBitmap(bitmap);
  const currentRecoveryConfigHash =
    computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
  return {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: 8,
    factorBitmap: bitmap,
    account: "0x0000000000000000000000000000000000004500",
    chainId: "31337",
    entryPoint: "0x00000000000000000000000000000000000F4337",
    authorizedIntentHash: H("O45:AUTHORIZED_INTENT"),
    userOperationHash: H("O45:USER_OPERATION"),
    requestId: H("O45:AUTHORIZED_INTENT"),
    currentRecoveryConfigHash,
    validatorEpoch: 1,
    recoveryEpoch: 1,
    validAfter: 1000,
    validUntil: 5000,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment: H("O45:PROPOSED_VALIDATOR"),
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: 2,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: commitments[roles[0]],
    secondFactorCommitment: commitments[roles[1]]
  };
}

function buildApprovalRequest(native, commitments, desktopEphemeralPublicKey, bitmap) {
  const context = buildV3Context(commitments, bitmap);
  const recoveryFactorDigest = computePhilCoreV2RecoveryFactorDigest(
    { chainId: context.chainId, account: context.account },
    {
      authorizedIntentHash: context.authorizedIntentHash,
      userOperationHash: context.userOperationHash,
      recoveryConfigHash: context.currentRecoveryConfigHash,
      recoveryEpoch: context.recoveryEpoch,
      factorBitmap: context.factorBitmap
    }
  ).digest;
  const contextHash = computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
  return {
    protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    context,
    claimedContextHash: contextHash,
    claimedRecoveryFactorDigest: recoveryFactorDigest,
    accountVersionId: native.descriptor.accountVersionId,
    securityModelId: native.descriptor.securityModelId,
    nativeRecoveryDomainId: native.descriptor.recoveryDomainId,
    applicationIdentity: PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity,
    localApprovalPolicy: PHILCORE_NATIVE_IPHONE_ROLE1.localApprovalPolicy,
    selectedRole1CredentialIdentifierCommitment:
      native.descriptor.credentialIdentifierCommitment,
    selectedRole1CredentialGeneration: 1,
    trustedRole1Descriptor: { ...native.descriptor },
    trustedRole1PublicKey: { qx: native.qx, qy: native.qy },
    sessionId: `0x${"45".repeat(32)}`,
    sessionChallenge: `0x${"46".repeat(32)}`,
    desktopEphemeralPublicKey,
    issuedAt: "1700000000000",
    expiresAt: "1700000300000",
    endpoint: "http://192.168.1.45:8787/philcore/recovery/v1/complete",
    now: "1700000100000"
  };
}

function assertNoForbiddenSubstrings(serialized) {
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(`O45_FIXTURE_FORBIDDEN_SUBSTRING:${pattern}`);
    }
  }
}

function buildBitmapEntry(input) {
  const {
    bitmap,
    native,
    commitments,
    desktopScalar,
    phoneScalar,
    desktopPublicKey,
    phonePublicKey,
    sharedSecret
  } = input;

  const desktopEphemeralPublicKey = desktopPublicKey.toString("base64url");
  const phoneEphemeralPublicKey = phonePublicKey.toString("base64url");
  const approvalRequest = buildApprovalRequest(
    native,
    commitments,
    desktopEphemeralPublicKey,
    bitmap
  );
  transport.validatePhilCoreRecoveryApprovalRequest(approvalRequest);

  const canonicalRequestBytes = bootstrap.serializeCanonicalRecoveryRequest(
    approvalRequest
  );
  const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(
    canonicalRequestBytes
  );
  const nowSeconds = 1700000100n;
  const expiresAt = nowSeconds + 120n;
  const ticketBytes = bootstrap.encodePrb1Ticket({
    sessionId: Buffer.from("45".repeat(32), "hex"),
    expiresAt,
    ipv4: Buffer.from([192, 168, 1, 45]),
    port: 8787,
    desktopEphemeralPublicKey: desktopPublicKey,
    requestHash
  });
  const ticket = bootstrap.decodePrb1Ticket(ticketBytes);
  bootstrap.validatePrb1TicketPolicy({
    ticket,
    nowSeconds,
    boundRequestExpiresAtMs: approvalRequest.expiresAt
  });
  const uri = bootstrap.formatPrb1Uri(ticketBytes);
  const fetchChallenge = Buffer.from(getBytes(H(`O45:FETCH_CHALLENGE:${bitmap}`)));
  const fetchInit = bootstrap.buildFetchInit({
    sessionId: approvalRequest.sessionId,
    phoneEphemeralPublicKey,
    fetchChallenge
  });
  const requestKey = bootstrap.deriveRecoveryRequestAesKey(sharedSecret, requestHash);
  const encryptedRequestDelivery = encryptRecoveryRequestDeliveryDeterministic({
    plaintext: canonicalRequestBytes,
    sessionId: approvalRequest.sessionId,
    key: requestKey,
    requestHash,
    phoneEphemeralPublicKey,
    fetchChallenge,
    nonce: deterministicNonce(`O45:REQUEST_DELIVERY_NONCE:${bitmap}`)
  });
  const decrypted = bootstrap.decryptRecoveryRequestDelivery({
    message: encryptedRequestDelivery,
    key: requestKey,
    sessionId: approvalRequest.sessionId,
    requestHash,
    phoneEphemeralPublicKey,
    fetchChallenge
  });
  if (!decrypted.equals(canonicalRequestBytes)) {
    throw new Error("O45_REQUEST_DELIVERY_ROUNDTRIP_MISMATCH");
  }

  const transcript = transport.buildPhilCoreNativeRecoveryApprovalTranscript(
    approvalRequest
  );
  const transcriptHashBytes =
    transport.hashPhilCoreNativeRecoveryApprovalTranscript(transcript);
  const approvalKey = transport.deriveRecoveryApprovalAesKey(
    sharedSecret,
    transcriptHashBytes
  );
  if (requestKey.equals(approvalKey)) {
    throw new Error("O45_REQUEST_APPROVAL_KEY_COLLISION");
  }

  return {
    bitmap,
    canonicalRequestHex: canonicalRequestBytes.toString("hex"),
    canonicalRequestBase64url: canonicalRequestBytes.toString("base64url"),
    requestHashHex: requestHash.toString("hex"),
    rawTicketHex: ticketBytes.toString("hex"),
    rawTicketBase64url: ticketBytes.toString("base64url"),
    uri,
    ticket: {
      magic: ticket.magic,
      version: ticket.version,
      sessionIdHex: ticket.sessionId.toString("hex"),
      expiresAt: ticket.expiresAt.toString(),
      ipv4: "192.168.1.45",
      port: ticket.port,
      desktopEphemeralPublicKeyBase64url: desktopEphemeralPublicKey,
      requestHashHex: ticket.requestHash.toString("hex")
    },
    desktopEphemeralPublicKeyBase64url: desktopEphemeralPublicKey,
    phoneEphemeralPublicKeyBase64url: phoneEphemeralPublicKey,
    desktopEphemeralPublicKeyFingerprint: sha256(desktopPublicKey),
    phoneEphemeralPublicKeyFingerprint: sha256(phonePublicKey),
    fetchInit,
    requestDeliveryKeyFingerprint: sha256(requestKey),
    encryptedRequestDelivery,
    decryptedBytesHash: sha256(decrypted),
    o44TranscriptHash: hexlify(transcriptHashBytes),
    o44ComparisonFingerprint:
      transport.displayPhilCoreRecoveryComparisonFingerprint(transcriptHashBytes),
    approvalRequestWireOmits: ["now", "actionText", "networkText"],
    requestEndpoint: bootstrap.buildRequestEndpointFromTicket(ticket),
    completionEndpoint: approvalRequest.endpoint,
    sizes: {
      rawTicketBytes: ticketBytes.length,
      uriBytes: Buffer.byteLength(uri, "ascii"),
      requestBytes: canonicalRequestBytes.length
    },
    ecdhAgreementProven: true,
    sharedSecretFingerprint: sha256(sharedSecret),
    domainSeparation: {
      requestHkdfInfo: bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO,
      approvalHkdfInfo: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO,
      requestAadPrefix:
        bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_AAD_DESKTOP_TO_PHONE,
      approvalAadDesktopToPhone:
        transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE,
      keysDistinct: true
    }
  };
}

function buildNegativeMutations(baseEntry) {
  const goodTicket = Buffer.from(baseEntry.rawTicketHex, "hex");
  const goodUri = baseEntry.uri;
  const goodCanonical = Buffer.from(baseEntry.canonicalRequestHex, "hex");
  const requestHash = Buffer.from(baseEntry.requestHashHex, "hex");
  const fetchChallenge = Buffer.from(
    goodTicket.length ? getBytes(H("O45:FETCH_CHALLENGE:6")) : Buffer.alloc(32)
  );

  const truncated = goodTicket.subarray(0, 147);
  const trailing = Buffer.concat([goodTicket, Buffer.from([0xff])]);
  const badMagic = Buffer.from(goodTicket);
  badMagic[0] = 0x00;
  const badVersion = Buffer.from(goodTicket);
  badVersion[4] = 0x02;

  const mutatedJson = JSON.parse(goodCanonical.toString("utf8"));
  mutatedJson.extraField = "forbidden";
  const mutatedBytes = Buffer.from(JSON.stringify(mutatedJson), "utf8");
  const spaced = Buffer.from(goodCanonical.toString("utf8").replace("{", "{ "), "utf8");

  const wrongKey = Buffer.alloc(32, 0x11);
  return [
    {
      category: "ticket_truncation",
      kind: "decodeTicket",
      expectedError: "truncat|length",
      bytesHex: truncated.toString("hex")
    },
    {
      category: "ticket_trailing_bytes",
      kind: "decodeTicket",
      expectedError: "trailing|length",
      bytesHex: trailing.toString("hex")
    },
    {
      category: "ticket_wrong_magic",
      kind: "decodeTicket",
      expectedError: "magic",
      bytesHex: badMagic.toString("hex")
    },
    {
      category: "ticket_wrong_version",
      kind: "decodeTicket",
      expectedError: "version",
      bytesHex: badVersion.toString("hex")
    },
    {
      category: "uri_padding",
      kind: "parseUri",
      expectedError: "pad|uri|base64",
      uri: `${goodUri}=`
    },
    {
      category: "uri_alternate_prefix",
      kind: "parseUri",
      expectedError: "prefix|uri",
      uri: `philcore-recovery:v0:${goodUri.slice(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX.length)}`
    },
    {
      category: "uri_whitespace",
      kind: "parseUri",
      expectedError: "whitespace|uri",
      uri: ` ${goodUri}`
    },
    {
      category: "uri_query",
      kind: "parseUri",
      expectedError: "query|fragment|uri",
      uri: `${goodUri}?x=1`
    },
    {
      category: "uri_fragment",
      kind: "parseUri",
      expectedError: "query|fragment|uri",
      uri: `${goodUri}#x`
    },
    {
      category: "uri_trailing_text",
      kind: "parseUri",
      expectedError: "length|uri|trailing",
      uri: `${goodUri}x`
    },
    {
      category: "expiry_not_after_now",
      kind: "validateTicket",
      expectedError: "expir",
      ticketHex: baseEntry.rawTicketHex,
      nowSeconds: Number(baseEntry.ticket.expiresAt)
    },
    {
      category: "expiry_outlives_bound_request",
      kind: "validateTicket",
      expectedError: "bound|outlive|expir",
      ticketHex: baseEntry.rawTicketHex,
      nowSeconds: 1700000100,
      boundRequestExpiresAtMs: (Number(baseEntry.ticket.expiresAt) - 10) * 1000
    },
    {
      category: "expiry_exceeds_ttl_skew",
      kind: "validateTicket",
      expectedError: "ttl|skew|expir|future",
      ticketHex: baseEntry.rawTicketHex,
      nowSeconds: 1700000100,
      ticketOverrides: {
        expiresAt: String(1700000100 + 300 + 60 + 1)
      }
    },
    {
      category: "canonical_unknown_field",
      kind: "parseCanonical",
      expectedError: "unknown|unexpected|field",
      bytesHex: mutatedBytes.toString("hex"),
      now: "1700000100000"
    },
    {
      category: "canonical_whitespace",
      kind: "parseCanonical",
      expectedError: "reserialize|canonical|mismatch",
      bytesHex: spaced.toString("hex"),
      now: "1700000100000"
    },
    {
      category: "fetch_init_bad_version",
      kind: "validateFetchInit",
      expectedError: "protocol|version",
      value: {
        ...baseEntry.fetchInit,
        protocolVersion: 2
      }
    },
    {
      category: "fetch_init_unexpected_field",
      kind: "validateFetchInit",
      expectedError: "unexpected|field|schema",
      value: {
        ...baseEntry.fetchInit,
        extra: true
      }
    },
    {
      category: "delivery_wrong_key",
      kind: "decryptDelivery",
      expectedError: "authentication|failed|aad|tag",
      message: baseEntry.encryptedRequestDelivery,
      keyHex: wrongKey.toString("hex"),
      sessionId: baseEntry.fetchInit.sessionId,
      requestHashHex: requestHash.toString("hex"),
      phoneEphemeralPublicKey: baseEntry.phoneEphemeralPublicKeyBase64url,
      fetchChallengeHex: Buffer.from(
        baseEntry.fetchInit.fetchChallenge,
        "base64url"
      ).toString("hex")
    }
  ];
}

function buildO45RecoveryBootstrapFixturePackage() {
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

  const desktopScalar = deterministicP256Scalar("O45:DESKTOP_EPHEMERAL_SCALAR");
  const phoneScalar = deterministicP256Scalar("O45:PHONE_EPHEMERAL_SCALAR");
  const desktopPublicKey = Buffer.from(
    p256.getPublicKey(getBytes(desktopScalar), false)
  );
  const phonePublicKey = Buffer.from(
    p256.getPublicKey(getBytes(phoneScalar), false)
  );
  const sharedFromDesktop = ecdhSharedSecretX(desktopScalar, phonePublicKey);
  const sharedFromPhone = ecdhSharedSecretX(phoneScalar, desktopPublicKey);
  if (!sharedFromDesktop.equals(sharedFromPhone)) {
    throw new Error("O45_ECDH_AGREEMENT_FAILED");
  }

  const bitmaps = {};
  for (const bitmap of [3, 6]) {
    bitmaps[String(bitmap)] = buildBitmapEntry({
      bitmap,
      native,
      commitments,
      desktopScalar,
      phoneScalar,
      desktopPublicKey,
      phonePublicKey,
      sharedSecret: sharedFromDesktop
    });
  }

  const pkg = {
    phase: "O.45",
    classification: "DETERMINISTIC_SYNTHETIC_TEST_ONLY",
    publicMutationCount: 0,
    networkCalls: 0,
    productionCredentialCreated: false,
    productionSignatureCreated: false,
    blockchainMutations: 0,
    secretsCommitted: false,
    protocolConstants: {
      magic: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_MAGIC,
      version: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_VERSION,
      ticketBytes: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES,
      uriPrefix: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX,
      uriBytes: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES,
      requestPath: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      completionPath: bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      hkdfInfo: bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO,
      aadDesktopToPhone:
        bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_AAD_DESKTOP_TO_PHONE,
      maxTtlSeconds: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_MAX_TTL_SECONDS,
      clockSkewSeconds: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_CLOCK_SKEW_SECONDS,
      maxWireBytes: bootstrap.PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES,
      protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION
    },
    nativeApprovalBitmaps: [3, 6],
    bitmaps,
    negativeMutations: buildNegativeMutations(bitmaps["6"])
  };

  assertNoForbiddenSubstrings(JSON.stringify(
    pkg,
    (_key, value) => (typeof value === "bigint" ? value.toString() : value)
  ));
  return pkg;
}

function main() {
  const output = `${JSON.stringify(
    buildO45RecoveryBootstrapFixturePackage(),
    (_key, value) => (typeof value === "bigint" ? value.toString() : value),
    2
  )}\n`;
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH) || fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O45_RECOVERY_BOOTSTRAP_FIXTURES_STALE");
    }
    process.stdout.write("O.45 recovery bootstrap fixtures are current\n");
    return;
  }
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO45RecoveryBootstrapFixturePackage,
  encryptRecoveryRequestDeliveryDeterministic
};
