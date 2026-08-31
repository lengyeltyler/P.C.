require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
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

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O45_RECOVERY_BOOTSTRAP_FIXTURES.json"
);
const GENERATOR_PATH = path.join(
  ROOT,
  "scripts/cryptography/generate-o45-recovery-bootstrap-fixtures.cjs"
);

const bootstrap = require("../../apps/phil-device-sdk/src/v2RecoveryBootstrap.ts");
const transport = require("../../apps/phil-device-sdk/src/v2RecoveryTransport.ts");
const {
  computePhilCoreV2RecoveryFactorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  PHILCORE_V2_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  computePhilCoreV2ConsumerRecoveryEvidenceContextHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts");
const {
  computePhilCoreV2ConsumerRecoveryConfigurationHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_O37_2_P256_ORDER
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_NATIVE_IPHONE_ROLE1
} = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  nativeFactor
} = require("../../scripts/cryptography/generate-o43-native-iphone-fixtures.cjs");
const {
  offlineFactor,
  webAuthnFactor
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");
const {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");

function H(value) {
  return keccak256(toUtf8Bytes(value));
}

function loadFixtures() {
  return JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
}

function deterministicP256Scalar(label) {
  return zeroPadValue(
    toBeHex((BigInt(H(label)) % (PHILCORE_O37_2_P256_ORDER - 1n)) + 1n),
    32
  );
}

function ecdhSharedSecretX(privateScalar, peerPublicKeyUncompressed) {
  const shared = p256.getSharedSecret(
    getBytes(privateScalar),
    peerPublicKeyUncompressed,
    true
  );
  return Buffer.from(shared.slice(1, 33));
}

function buildCommitments() {
  const primary = webAuthnFactor(
    "STANDARD:primary",
    0,
    PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const native = nativeFactor();
  const offline = offlineFactor("STANDARD");
  return {
    primary,
    native,
    offline,
    commitments: [
      primary.factorCommitment,
      native.factorCommitment,
      offline.factorCommitment
    ]
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
    trustedRole1Descriptor: native.descriptor,
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

function validTicketFields(desktopPublicKey, requestHash, overrides = {}) {
  return {
    sessionId: Buffer.from("45".repeat(32), "hex"),
    expiresAt: 1700000100n + 120n,
    ipv4: Buffer.from([192, 168, 1, 45]),
    port: 8787,
    desktopEphemeralPublicKey: desktopPublicKey,
    requestHash,
    ...overrides
  };
}

describe("O.45 recovery bootstrap protocol", function () {
  let factors;
  let desktopScalar;
  let phoneScalar;
  let desktopPublicKey;
  let phonePublicKey;
  let desktopEphemeralPublicKeyB64;
  let phoneEphemeralPublicKeyB64;
  let sharedSecret;
  let approvalRequest;
  let fixtures;

  before(function () {
    factors = buildCommitments();
    desktopScalar = deterministicP256Scalar("O45:DESKTOP_EPHEMERAL_SCALAR");
    phoneScalar = deterministicP256Scalar("O45:PHONE_EPHEMERAL_SCALAR");
    desktopPublicKey = Buffer.from(
      p256.getPublicKey(getBytes(desktopScalar), false)
    );
    phonePublicKey = Buffer.from(
      p256.getPublicKey(getBytes(phoneScalar), false)
    );
    desktopEphemeralPublicKeyB64 = desktopPublicKey.toString("base64url");
    phoneEphemeralPublicKeyB64 = phonePublicKey.toString("base64url");
    sharedSecret = ecdhSharedSecretX(desktopScalar, phonePublicKey);
    approvalRequest = buildApprovalRequest(
      factors.native,
      factors.commitments,
      desktopEphemeralPublicKeyB64,
      6
    );
    fixtures = loadFixtures();
  });

  it("exports exact sizes and path constants", function () {
    assert.equal(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES, 148);
    assert.equal(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES, 219);
    assert.equal(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX, "philcore-recovery:v1:");
    assert.equal(
      bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      "/philcore/recovery/v1/request"
    );
    assert.equal(
      bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH
    );
    assert.equal(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_MAGIC, "PRB1");
    assert.equal(bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_VERSION, 0x01);
  });

  it("encodes and decodes a strict 148-byte PRB1 ticket", function () {
    const canonical = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(canonical);
    assert.equal(requestHash.length, 32);
    const ticketBytes = bootstrap.encodePrb1Ticket(
      validTicketFields(desktopPublicKey, requestHash)
    );
    assert.equal(ticketBytes.length, 148);
    assert.equal(ticketBytes.subarray(0, 4).toString("ascii"), "PRB1");
    assert.equal(ticketBytes[4], 0x01);
    const decoded = bootstrap.decodePrb1Ticket(ticketBytes);
    assert.equal(decoded.sessionId.toString("hex"), "45".repeat(32));
    assert.equal(decoded.port, 8787);
    assert.ok(decoded.desktopEphemeralPublicKey.equals(desktopPublicKey));
    assert.ok(decoded.requestHash.equals(requestHash));
    assert.equal(
      bootstrap.encodePrb1Ticket({
        sessionId: decoded.sessionId,
        expiresAt: decoded.expiresAt,
        ipv4: decoded.ipv4,
        port: decoded.port,
        desktopEphemeralPublicKey: decoded.desktopEphemeralPublicKey,
        requestHash: decoded.requestHash
      }).toString("hex"),
      ticketBytes.toString("hex")
    );
  });

  it("formats and parses a strict 219-byte unpadded URI", function () {
    const canonical = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(canonical);
    const ticketBytes = bootstrap.encodePrb1Ticket(
      validTicketFields(desktopPublicKey, requestHash)
    );
    const uri = bootstrap.formatPrb1Uri(ticketBytes);
    assert.equal(Buffer.byteLength(uri, "ascii"), 219);
    assert.ok(uri.startsWith("philcore-recovery:v1:"));
    assert.equal(uri.includes("="), false);
    const parsed = bootstrap.parsePrb1Uri(uri);
    assert.equal(parsed.length, 148);
    assert.equal(parsed.toString("hex"), ticketBytes.toString("hex"));
  });

  it("builds RFC1918 request endpoint and enforces ticket policy", function () {
    const canonical = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(canonical);
    const ticketBytes = bootstrap.encodePrb1Ticket(
      validTicketFields(desktopPublicKey, requestHash)
    );
    const ticket = bootstrap.decodePrb1Ticket(ticketBytes);
    assert.equal(
      bootstrap.buildRequestEndpointFromTicket(ticket),
      "http://192.168.1.45:8787/philcore/recovery/v1/request"
    );
    bootstrap.validatePrb1TicketPolicy({
      ticket,
      nowSeconds: 1700000100,
      boundRequestExpiresAtMs: approvalRequest.expiresAt
    });
  });

  it("rejects invalid endpoint/ticket policy inputs", function () {
    const canonical = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(canonical);
    const base = validTicketFields(desktopPublicKey, requestHash);

    assert.throws(
      () => bootstrap.encodePrb1Ticket({ ...base, port: 80 }),
      /port/i
    );
    assert.throws(
      () => bootstrap.encodePrb1Ticket({ ...base, ipv4: Buffer.from([8, 8, 8, 8]) }),
      /ipv4|rfc1918|address/i
    );
    assert.throws(
      () => bootstrap.encodePrb1Ticket({ ...base, ipv4: Buffer.from([127, 0, 0, 1]) }),
      /ipv4|rfc1918|loopback|address/i
    );
    assert.throws(
      () => bootstrap.encodePrb1Ticket({
        ...base,
        sessionId: Buffer.alloc(32, 0)
      }),
      /session/i
    );
    assert.throws(
      () => bootstrap.encodePrb1Ticket({
        ...base,
        requestHash: Buffer.alloc(32, 0)
      }),
      /request.?hash/i
    );
    assert.throws(
      () => bootstrap.decodePrb1Ticket(Buffer.alloc(147, 1)),
      /length|truncat/i
    );
    assert.throws(
      () => bootstrap.decodePrb1Ticket(Buffer.concat([
        Buffer.alloc(148, 1),
        Buffer.from([0xff])
      ])),
      /length|trailing/i
    );

    const good = bootstrap.encodePrb1Ticket(base);
    const badMagic = Buffer.from(good);
    badMagic[0] = 0x00;
    assert.throws(() => bootstrap.decodePrb1Ticket(badMagic), /magic/i);

    const paddedUri = `${bootstrap.formatPrb1Uri(good)}=`;
    assert.throws(() => bootstrap.parsePrb1Uri(paddedUri), /pad|uri|base64/i);
    assert.throws(
      () => bootstrap.parsePrb1Uri(`x${bootstrap.formatPrb1Uri(good)}`),
      /prefix|uri/i
    );
    assert.throws(
      () => bootstrap.parsePrb1Uri(`${bootstrap.formatPrb1Uri(good)}?x=1`),
      /uri|query|trailing/i
    );

    const ticket = bootstrap.decodePrb1Ticket(good);
    assert.throws(
      () => bootstrap.validatePrb1TicketPolicy({
        ticket,
        nowSeconds: Number(ticket.expiresAt)
      }),
      /expir/i
    );
    assert.throws(
      () => bootstrap.validatePrb1TicketPolicy({
        ticket,
        nowSeconds: Number(ticket.expiresAt) - 1,
        boundRequestExpiresAtMs: (Number(ticket.expiresAt) - 10) * 1000
      }),
      /bound|outlive|expir/i
    );
    assert.throws(
      () => bootstrap.validatePrb1TicketPolicy({
        ticket: {
          ...ticket,
          expiresAt: BigInt(1700000100 + 300 + 60 + 1)
        },
        nowSeconds: 1700000100
      }),
      /expir|ttl|skew|future/i
    );
  });

  it("red-gate: rejects ambiguous leading-zero IPv4 octets while preserving raw decode", function () {
    const canonical = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(canonical);
    const base = validTicketFields(desktopPublicKey, requestHash);

    const ambiguous = [
      "192.168.001.001",
      "010.168.1.1",
      "192.168.1.01",
      "172.016.0.1",
      "10.00.0.1",
      "00.0.0.0"
    ];
    for (const ipv4 of ambiguous) {
      assert.throws(
        () => bootstrap.encodePrb1Ticket({ ...base, ipv4 }),
        /ipv4_address_invalid|ipv4.*invalid|leading.?zero|canonical/i,
        `ambiguous IPv4 must be rejected: ${ipv4}`
      );
    }

    // Canonical single-digit "0" is parseable but still fails address policy.
    assert.throws(
      () => bootstrap.encodePrb1Ticket({ ...base, ipv4: "0.0.0.0" }),
      /ipv4_rfc1918_required/,
      'canonical "0.0.0.0" must reach RFC1918 policy rejection'
    );

    const accepted = [
      "10.0.0.1",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.0.1",
      "192.168.255.255"
    ];
    for (const ipv4 of accepted) {
      const encoded = bootstrap.encodePrb1Ticket({ ...base, ipv4 });
      assert.equal(encoded.length, 148);
      const decoded = bootstrap.decodePrb1Ticket(encoded);
      assert.equal(decoded.ipv4.toString("hex"), Buffer.from(
        ipv4.split(".").map((part) => Number(part))
      ).toString("hex"));
    }

    // Raw four-byte IPv4 ticket decoding remains unchanged.
    const rawTicket = bootstrap.encodePrb1Ticket({
      ...base,
      ipv4: Buffer.from([192, 168, 1, 45])
    });
    const rawDecoded = bootstrap.decodePrb1Ticket(rawTicket);
    assert.deepEqual([...rawDecoded.ipv4], [192, 168, 1, 45]);

    const malformed = [
      "192.168.1",
      "192.168.1.1.1",
      "192.168.1.256",
      "192.168.-1.1",
      "192.168.+1.1",
      "192.168.0x1.1",
      "192.168. 1.1",
      " 192.168.1.1",
      "192.168.1.1 ",
      "192.168.1.0a",
      "10.0.0.01"
    ];
    for (const ipv4 of malformed) {
      assert.throws(
        () => bootstrap.encodePrb1Ticket({ ...base, ipv4 }),
        /ipv4|address|rfc1918/i,
        `malformed IPv4 must be rejected: ${JSON.stringify(ipv4)}`
      );
    }
  });

  it("canonicalizes wire request and injects local now only", function () {
    const wire = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    assert.ok(wire.length > 0);
    assert.ok(wire.length <= bootstrap.PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES);
    const asJson = JSON.parse(wire.toString("utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(asJson, "now"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(asJson, "actionText"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(asJson, "networkText"), false);
    assert.equal(
      wire.toString("utf8"),
      bootstrap.serializeCanonicalRecoveryRequest(asJson).toString("utf8")
    );

    const validated = bootstrap.parseCanonicalRecoveryRequestBytes(wire, {
      now: approvalRequest.now
    });
    assert.equal(validated.now, String(approvalRequest.now));
    transport.validatePhilCoreRecoveryApprovalRequest(validated);

    const withSpace = Buffer.from(wire.toString("utf8").replace("{", "{ "), "utf8");
    assert.throws(
      () => bootstrap.parseCanonicalRecoveryRequestBytes(withSpace, {
        now: approvalRequest.now
      }),
      /canonical|byte|reserialize|whitespace/i
    );

    const mutated = JSON.parse(wire.toString("utf8"));
    mutated.extraField = "nope";
    const mutatedBytes = Buffer.from(JSON.stringify(mutated), "utf8");
    assert.throws(
      () => bootstrap.parseCanonicalRecoveryRequestBytes(mutatedBytes, {
        now: approvalRequest.now
      }),
      /unknown|unexpected|field|canonical/i
    );
  });

  it("computes request hash as SHA-256 of canonical bytes", function () {
    const wire = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const hash = bootstrap.computePhilCoreRecoveryRequestHash(wire);
    assert.equal(hash.toString("hex"), crypto.createHash("sha256").update(wire).digest("hex"));
    const fromRequest = bootstrap.computePhilCoreRecoveryRequestHash(approvalRequest);
    assert.equal(fromRequest.toString("hex"), hash.toString("hex"));
  });

  it("validates fetch-init and encrypts/decrypts request delivery", function () {
    const wire = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(wire);
    const fetchChallenge = Buffer.from(getBytes(H("O45:FETCH_CHALLENGE")));
    const fetchInit = bootstrap.buildFetchInit({
      sessionId: approvalRequest.sessionId,
      phoneEphemeralPublicKey: phoneEphemeralPublicKeyB64,
      fetchChallenge
    });
    assert.deepEqual(bootstrap.validateFetchInit(fetchInit), fetchInit);
    assert.equal(fetchInit.protocolVersion, 1);
    assert.equal(fetchInit.fetchChallenge.includes("="), false);

    const key = bootstrap.deriveRecoveryRequestAesKey(sharedSecret, requestHash);
    assert.equal(key.length, 32);

    const encrypted = bootstrap.encryptRecoveryRequestDelivery({
      plaintext: wire,
      sessionId: approvalRequest.sessionId,
      key,
      requestHash,
      phoneEphemeralPublicKey: phoneEphemeralPublicKeyB64,
      fetchChallenge
    });
    assert.equal(encrypted.protocolVersion, 1);
    assert.equal(encrypted.sessionId, approvalRequest.sessionId.toLowerCase());
    const decrypted = bootstrap.decryptRecoveryRequestDelivery({
      message: encrypted,
      key,
      sessionId: approvalRequest.sessionId,
      requestHash,
      phoneEphemeralPublicKey: phoneEphemeralPublicKeyB64,
      fetchChallenge
    });
    assert.equal(decrypted.toString("hex"), wire.toString("hex"));

    assert.throws(
      () => bootstrap.validateFetchInit({ ...fetchInit, protocolVersion: 2 }),
      /protocol|version/i
    );
    assert.throws(
      () => bootstrap.validateFetchInit({ ...fetchInit, extra: 1 }),
      /unexpected|field|schema/i
    );
  });

  it("domain-separates request key schedule from O.44 approval", function () {
    const wire = bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(wire);
    const transcript = transport.buildPhilCoreNativeRecoveryApprovalTranscript(
      approvalRequest
    );
    const transcriptHash =
      transport.hashPhilCoreNativeRecoveryApprovalTranscript(transcript);
    const requestKey = bootstrap.deriveRecoveryRequestAesKey(
      sharedSecret,
      requestHash
    );
    const approvalKey = transport.deriveRecoveryApprovalAesKey(
      sharedSecret,
      transcriptHash
    );
    assert.equal(requestKey.length, 32);
    assert.equal(approvalKey.length, 32);
    assert.notEqual(requestKey.toString("hex"), approvalKey.toString("hex"));
    assert.equal(
      bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO,
      "PHILCORE_NATIVE_RECOVERY_REQUEST_AES256_GCM_V1"
    );
    assert.notEqual(
      bootstrap.PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO,
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO
    );
    const aad = bootstrap.buildRequestDeliveryAad({
      sessionId: approvalRequest.sessionId,
      requestHash,
      phoneEphemeralPublicKey: phoneEphemeralPublicKeyB64,
      fetchChallenge: Buffer.from(getBytes(H("O45:FETCH_CHALLENGE")))
    }).toString("utf8");
    assert.ok(aad.startsWith("DESKTOP_TO_IPHONE_RECOVERY_REQUEST_V1|"));
    assert.ok(!aad.includes("RECOVERY_APPROVAL"));
  });

  it("matches committed fixtures for bitmaps 3 and 6", function () {
    assert.equal(fixtures.stub, undefined);
    assert.equal(fixtures.phase, "O.45");
    assert.equal(fixtures.secretsCommitted, false);
    for (const bitmap of [3, 6]) {
      const entry = fixtures.bitmaps[String(bitmap)];
      assert.ok(entry, `missing bitmap ${bitmap}`);
      assert.equal(entry.sizes.rawTicketBytes, 148);
      assert.equal(entry.sizes.uriBytes, 219);
      assert.ok(entry.sizes.requestBytes > 0);
      assert.equal(entry.uri.length, 219);
      assert.equal(Buffer.from(entry.rawTicketHex, "hex").length, 148);
      const recomputedHash = crypto
        .createHash("sha256")
        .update(Buffer.from(entry.canonicalRequestHex, "hex"))
        .digest("hex");
      assert.equal(entry.requestHashHex, recomputedHash);
      assert.equal(
        bootstrap.parsePrb1Uri(entry.uri).toString("hex"),
        entry.rawTicketHex
      );
      assert.ok(entry.requestDeliveryKeyFingerprint);
      assert.ok(entry.encryptedRequestDelivery);
      assert.ok(entry.decryptedBytesHash);
      assert.ok(entry.o44TranscriptHash);
      assert.ok(entry.o44ComparisonFingerprint);
    }
  });

  it("executes fixture negative mutations", function () {
    assert.ok(Array.isArray(fixtures.negativeMutations));
    assert.ok(fixtures.negativeMutations.length > 0);
    for (const mutation of fixtures.negativeMutations) {
      assert.ok(mutation.category, "mutation category required");
      assert.ok(mutation.expectedError, "expectedError required");
      const re = new RegExp(mutation.expectedError, "i");
      if (mutation.kind === "decodeTicket") {
        assert.throws(
          () => bootstrap.decodePrb1Ticket(Buffer.from(mutation.bytesHex, "hex")),
          re,
          mutation.category
        );
      } else if (mutation.kind === "parseUri") {
        assert.throws(() => bootstrap.parsePrb1Uri(mutation.uri), re, mutation.category);
      } else if (mutation.kind === "validateTicket") {
        const ticket = bootstrap.decodePrb1Ticket(
          Buffer.from(mutation.ticketHex, "hex")
        );
        assert.throws(
          () => bootstrap.validatePrb1TicketPolicy({
            ticket: mutation.ticketOverrides
              ? { ...ticket, ...Object.fromEntries(
                Object.entries(mutation.ticketOverrides).map(([k, v]) => {
                  if (typeof v === "string" && /^[0-9a-f]+$/iu.test(v) && v.length % 2 === 0) {
                    return [k, Buffer.from(v, "hex")];
                  }
                  if (k === "expiresAt") return [k, BigInt(v)];
                  return [k, v];
                })
              ) }
              : ticket,
            nowSeconds: mutation.nowSeconds,
            boundRequestExpiresAtMs: mutation.boundRequestExpiresAtMs
          }),
          re,
          mutation.category
        );
      } else if (mutation.kind === "parseCanonical") {
        assert.throws(
          () => bootstrap.parseCanonicalRecoveryRequestBytes(
            Buffer.from(mutation.bytesHex, "hex"),
            { now: mutation.now }
          ),
          re,
          mutation.category
        );
      } else if (mutation.kind === "validateFetchInit") {
        assert.throws(
          () => bootstrap.validateFetchInit(mutation.value),
          re,
          mutation.category
        );
      } else if (mutation.kind === "decryptDelivery") {
        assert.throws(
          () => bootstrap.decryptRecoveryRequestDelivery({
            message: mutation.message,
            key: Buffer.from(mutation.keyHex, "hex"),
            sessionId: mutation.sessionId,
            requestHash: Buffer.from(mutation.requestHashHex, "hex"),
            phoneEphemeralPublicKey: mutation.phoneEphemeralPublicKey,
            fetchChallenge: Buffer.from(mutation.fetchChallengeHex, "hex")
          }),
          re,
          mutation.category
        );
      } else {
        assert.fail(`unknown mutation kind ${mutation.kind}`);
      }
    }
  });

  it("excludes secret material from committed fixtures", function () {
    const raw = fs.readFileSync(FIXTURE_PATH, "utf8");
    for (const pattern of [
      /"privateScalar"\s*:/u,
      /"privateKey"\s*:/u,
      /"recoveryCode"\s*:/u,
      /"offlineEntropy"\s*:/u,
      /"ecdhPrivate"\s*:/u,
      /"sharedSecret"\s*:/u,
      /"aesKey"\s*:/u
    ]) {
      assert.equal(pattern.test(raw), false, String(pattern));
    }
  });

  it("generator --check detects fixture staleness", function () {
    const check = spawnSync(
      process.execPath,
      [GENERATOR_PATH, "--check"],
      { cwd: ROOT, encoding: "utf8" }
    );
    assert.equal(check.status, 0, check.stderr || check.stdout);
    assert.match(check.stdout, /current/i);

    const original = fs.readFileSync(FIXTURE_PATH, "utf8");
    try {
      fs.writeFileSync(FIXTURE_PATH, `${original.replace('"O.45"', '"O.45-STALE"')}`, "utf8");
      const stale = spawnSync(
        process.execPath,
        [GENERATOR_PATH, "--check"],
        { cwd: ROOT, encoding: "utf8" }
      );
      assert.notEqual(stale.status, 0);
      assert.match(`${stale.stderr}${stale.stdout}`, /STALE/i);
    } finally {
      fs.writeFileSync(FIXTURE_PATH, original, "utf8");
    }
  });
});
