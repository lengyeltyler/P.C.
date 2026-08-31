"use strict";

require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const { getBytes, hexlify, keccak256, sha256, toBeHex, toUtf8Bytes, zeroPadValue } = require("ethers");
const hre = require("hardhat");

// Desktop lane runs this file with `node` (no mocha). Provide a minimal harness.
const __nodeSuite = { before: null, tests: [] };
const __usedNodeShim = typeof describe !== "function";
if (__usedNodeShim) {
  global.describe = function describe(_name, fn) {
    const ctx = {
      timeout() {}
    };
    fn.call(ctx);
  };
  global.it = function it(name, fn) {
    __nodeSuite.tests.push({ name, fn });
  };
  global.before = function before(fn) {
    __nodeSuite.before = fn;
  };
}

const recoveryTransportHostModule = require("../src/main/recovery-transport-host.cjs");
const {
  STATES,
  SESSION_TTL_MS,
  SUCCESS_MAGIC,
  RecoveryTransportError,
  safeError,
  createRecoveryTransportHost,
  createInMemoryRole1TransportAdapter,
  createUnavailableRole1TransportAdapter,
  cloneJsonSafePublicSnapshot
} = recoveryTransportHostModule;
const {
  createProductionRole1TransportListenerAdapter
} = recoveryTransportHostModule;
const bootstrap = require("../../../apps/phil-device-sdk/src/v2RecoveryBootstrap.ts");
const {
  CHANNELS,
  RECOVERY_TRANSPORT_CHANNELS,
  validateBridgePayload
} = require("../src/shared/bridge-contract.cjs");
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require("../src/main/recovery-secure-origin.cjs");

const {
  buildO43NativeIPhoneFixturePackage,
  nativeFactor
} = require("../../../scripts/cryptography/generate-o43-native-iphone-fixtures.cjs");
const {
  offlineFactor,
  secpEvidence,
  webAuthnEvidence,
  webAuthnFactor
} = require("../../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");
const {
  encodePhilCoreO372WebAuthnEvidence,
  encodePhilCoreO372Secp256k1Evidence
} = require("../../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const transport = require("../../../apps/phil-device-sdk/src/v2RecoveryTransport.ts");
const {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID,
  PHILCORE_NATIVE_IPHONE_ROLE1
} = require("../../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  computePhilCoreV2RecoveryFactorDigest
} = require("../../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY
} = require("../../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS
} = require("../../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");

const { ethers, network } = hre;

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

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function asBytes32Hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function authenticatorData(flags = 0x05, rpId = RECOVERY_RP_ID, signCount = 1) {
  const data = Buffer.alloc(37);
  crypto.createHash("sha256").update(rpId).digest().copy(data);
  data[32] = flags;
  data.writeUInt32BE(signCount >>> 0, 33);
  return data;
}

function minimalAssertion({
  challenge,
  origin = RECOVERY_ORIGIN,
  flags = 0x05,
  credentialId = base64url(Buffer.alloc(32, 17)),
  signatureByte = 0x11
} = {}) {
  const authData = authenticatorData(flags);
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  return {
    id: "synthetic-recovery-assertion",
    rawId: credentialId,
    type: "public-key",
    response: {
      authenticatorData: base64url(authData),
      clientDataJSON: base64url(clientDataJSON),
      signature: base64url(Buffer.alloc(70, signatureByte)),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function createPhoneSimulator({
  privateScalar,
  factorCommitment,
  credentialIdentifierCommitment,
  credentialGeneration,
  mutatePayload,
  mutateCiphertext,
  fixedNonce
} = {}) {
  return async ({ request, transcriptHash, desktopEcdhPublicKey }) => {
    const phoneEcdh = crypto.createECDH("prime256v1");
    const phonePublic = phoneEcdh.generateKeys();
    const desktopPublic = Buffer.from(desktopEcdhPublicKey, "base64url");
    const sharedSecret = phoneEcdh.computeSecret(desktopPublic);
    assert.equal(sharedSecret.length, 32, "Node ECDH shared secret must be 32-byte x");

    const transcriptHashBytes = typeof transcriptHash === "string"
      ? Buffer.from(getBytes(transcriptHash))
      : Buffer.from(transcriptHash);
    const transcriptHashHex = typeof transcriptHash === "string"
      ? (transcriptHash.startsWith("0x") ? transcriptHash.toLowerCase() : `0x${transcriptHash}`)
      : asBytes32Hex(transcriptHashBytes);

    const aesKey = transport.deriveRecoveryApprovalAesKey(
      sharedSecret,
      transcriptHashBytes
    );

    const digest = request.claimedRecoveryFactorDigest;
    const signature = p256.sign(
      getBytes(digest),
      getBytes(privateScalar),
      { lowS: true, prehash: false }
    );
    const derSignature = encodeDerSignature(signature.r, signature.s);

    let payload = {
      protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
      sessionId: request.sessionId,
      transcriptHash: transcriptHashHex,
      role1FactorCommitment: factorCommitment,
      credentialIdentifierCommitment,
      credentialGeneration: Number(credentialGeneration),
      derRecoverySignature: base64url(derSignature)
    };
    if (typeof mutatePayload === "function") {
      payload = mutatePayload(payload, { request, transcriptHashHex });
    }

    let message;
    if (fixedNonce) {
      const nonce = Buffer.from(fixedNonce);
      const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, nonce);
      cipher.setAAD(Buffer.from(
        `${transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP}|${String(request.sessionId).toLowerCase()}`,
        "utf8"
      ));
      const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(JSON.stringify(payload), "utf8")),
        cipher.final()
      ]);
      message = {
        version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
        sessionId: String(request.sessionId).toLowerCase(),
        phoneEphemeralPublicKey: base64url(phonePublic),
        nonce: base64url(nonce),
        ciphertext: base64url(ciphertext),
        tag: base64url(cipher.getAuthTag())
      };
    } else {
      message = transport.encryptRecoveryApprovalMessage({
        value: payload,
        sessionId: request.sessionId,
        key: aesKey,
        direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP,
        phoneEphemeralPublicKey: base64url(phonePublic)
      });
    }

    if (typeof mutateCiphertext === "function") {
      message = mutateCiphertext(message);
    }
    return message;
  };
}

function buildFixtureBundle() {
  const o43 = buildO43NativeIPhoneFixturePackage();
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
  assert.equal(commitments[0], o43.factors.primary.factorCommitment);
  assert.equal(commitments[1], o43.factors.nativeIPhone.factorCommitment);
  assert.equal(commitments[2], o43.factors.offline.factorCommitment);

  const credentialId = base64url(Buffer.alloc(32, 17));
  const trustedConfig = {
    actionType: o43.request.actionType,
    account: o43.request.account,
    chainId: o43.request.chainId,
    entryPoint: o43.request.entryPoint,
    accountVersionId: o43.request.accountVersionId,
    securityModelId: o43.request.securityModelId,
    authorizedIntentHash: o43.request.authorizedIntentHash,
    userOpHash: o43.request.userOpHash,
    validator: o43.request.validator,
    validatorKeyIdBinding: o43.request.validatorKeyIdBinding,
    requestId: o43.request.requestId,
    recoveryConfigHash: o43.recoveryConfigurationHash,
    validatorEpoch: o43.request.validatorEpoch,
    recoveryEpoch: o43.request.recoveryEpoch,
    validAfter: o43.request.validAfter,
    validUntil: o43.request.validUntil,
    proposedValidatorCommitment: o43.request.proposedValidatorCommitment,
    proposedRecoveryConfigHash: o43.request.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: o43.request.proposedRecoveryEpoch,
    commitments,
    nativeRecoveryDomainId: PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID,
    applicationIdentity: PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity,
    localApprovalPolicy: PHILCORE_NATIVE_IPHONE_ROLE1.localApprovalPolicy,
    role0: {
      credentialId,
      publicKey: "synthetic-role0-spki",
      publicKeyAlgorithm: -7,
      storedSignCount: 0,
      qx: primary.qx,
      qy: primary.qy,
      factorCommitment: primary.factorCommitment,
      descriptor: primary.descriptor
    },
    role1: {
      descriptor: native.descriptor,
      publicKey: { qx: native.qx, qy: native.qy },
      factorCommitment: native.factorCommitment,
      credentialIdentifierCommitment:
        native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(native.descriptor.credentialGeneration)
    },
    role2: {
      factorCommitment: offline.factorCommitment,
      descriptor: offline.descriptor,
      signer: offline.signer
    }
  };

  return { o43, primary, native, offline, commitments, trustedConfig, credentialId };
}

async function createHardhatVerifierAdapter(account) {
  const factory = await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier");
  const verifier = await factory.deploy();
  await verifier.waitForDeployment();
  await network.provider.send("hardhat_impersonateAccount", [account]);
  const signer = await ethers.getSigner(account);
  return {
    verifier,
    localStaticVerifier: async ({ request, envelope }) => {
      const magic = await verifier.connect(signer).verifyAuthority.staticCall(
        request,
        envelope
      );
      return magic;
    }
  };
}

function mockAssertionVerifier(options = {}) {
  return {
    async verifyAssertion(input) {
      if (typeof options.verifyAssertion === "function") {
        return options.verifyAssertion(input);
      }
      if (options.fail) {
        return { verified: false, productionVerified: false };
      }
      const challenge = input?.expectedChallenge;
      const clientData = Buffer.from(
        input.assertion.response.clientDataJSON,
        "base64url"
      ).toString("utf8");
      const matches = typeof challenge === "string"
        && clientData.includes(`"challenge":"${challenge}"`);
      return {
        verified: matches,
        productionVerified: matches
      };
    }
  };
}

function encodeRole0FromFixture(primary, counterByDigest = new Map()) {
  return async ({ digest }) => {
    const next = (counterByDigest.get(digest) || 0) + 1;
    counterByDigest.set(digest, next);
    return webAuthnEvidence(primary, digest, next);
  };
}

function role2ProviderFromOffline(offline) {
  return async ({ digest }) => ({
    role: 2,
    evidence: secpEvidence(offline, digest)
  });
}

async function expectCode(promiseOrFn, code) {
  try {
    const value = typeof promiseOrFn === "function"
      ? promiseOrFn()
      : promiseOrFn;
    await value;
    assert.fail(`expected ${code}`);
  } catch (error) {
    const actual = error instanceof RecoveryTransportError
      ? error.code
      : (error && error.code) || (error && error.message);
    assert.equal(actual, code, `expected ${code}, got ${actual}`);
  }
}

function createHost(bundle, overrides = {}) {
  const clock = { nowMs: Date.now() };
  const phoneSimulator = overrides.phoneSimulator || createPhoneSimulator({
    privateScalar: bundle.native.privateScalar,
    factorCommitment: bundle.native.factorCommitment,
    credentialIdentifierCommitment:
      bundle.native.descriptor.credentialIdentifierCommitment,
    credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
  });
  const adapter = overrides.role1TransportAdapter
    || createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
  const host = createRecoveryTransportHost({
    trustedConfigProvider:
      overrides.trustedConfigProvider || (async () => bundle.trustedConfig),
    role2FactorProvider:
      overrides.role2FactorProvider || role2ProviderFromOffline(bundle.offline),
    localStaticVerifier:
      overrides.localStaticVerifier || (async () => SUCCESS_MAGIC),
    role1TransportAdapter: adapter,
    assertionVerifier: overrides.assertionVerifier || mockAssertionVerifier(),
    encodeRole0Evidence:
      overrides.encodeRole0Evidence || encodeRole0FromFixture(bundle.primary),
    now: overrides.now || (() => clock.nowMs),
    expectedOrigin: RECOVERY_ORIGIN,
    expectedRpId: RECOVERY_RP_ID,
    ...("randomBytes" in overrides ? { randomBytes: overrides.randomBytes } : {})
  });
  return { host, adapter, clock };
}

async function submitMockRole0(host, credentialId) {
  const options = host.beginRole0Assertion();
  const assertion = minimalAssertion({
    challenge: options.challenge,
    credentialId
  });
  return host.submitRole0Assertion({ assertion });
}

describe("desktop recovery transport host", function () {
  this.timeout(60_000);

  let bundle;
  let hardhatVerifier;

  before(async function () {
    bundle = buildFixtureBundle();
    hardhatVerifier = await createHardhatVerifierAdapter(bundle.trustedConfig.account);
  });

  it("rejects beginDrill with extra trusted-field overrides", async function () {
    const { host } = createHost(bundle, {
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });
    await expectCode(
      () => host.beginDrill({ bitmap: 3, digest: `0x${"11".repeat(32)}` }),
      "BEGIN_DRILL_UNEXPECTED_FIELD"
    );
    await expectCode(
      () => host.beginDrill({
        bitmap: 3,
        account: bundle.trustedConfig.account
      }),
      "BEGIN_DRILL_UNEXPECTED_FIELD"
    );
    await expectCode(
      () => host.beginDrill({
        bitmap: 3,
        contextHash: `0x${"22".repeat(32)}`
      }),
      "BEGIN_DRILL_UNEXPECTED_FIELD"
    );
  });

  it("rejects invalid bitmaps", async function () {
    const { host } = createHost(bundle);
    for (const bitmap of [0, 1, 2, 4, 7]) {
      await expectCode(() => host.beginDrill({ bitmap }), "BITMAP_INVALID");
    }
  });

  it("expires sessions and rejects late factor collection", async function () {
    const { host, clock } = createHost(bundle, {
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });
    await host.beginDrill({ bitmap: 5 });
    assert.equal(host.status().state, STATES.AWAITING_FIRST_FACTOR);
    clock.nowMs = host.status().expiresAt + 1;
    await expectCode(() => host.collectRole2(), "SESSION_EXPIRED");
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("replacement cancels prior session collect", async function () {
    let releasePhone;
    const phoneGate = new Promise((resolve) => {
      releasePhone = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const { host } = createHost(bundle, {
      phoneSimulator: async (args) => {
        await phoneGate;
        return phoneSimulator(args);
      },
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });

    const first = await host.beginDrill({ bitmap: 6 });
    const firstSessionId = first.sessionId;
    const lateCollect = host.collectRole1();
    const second = await host.beginDrill({ bitmap: 6 });
    assert.notEqual(second.sessionId, firstSessionId);
    releasePhone();
    await expectCode(lateCollect, "SESSION_REPLACED_OR_CANCELLED");
  });

  it("cancel is idempotent and blocks resume", async function () {
    const { host } = createHost(bundle);
    await host.beginDrill({ bitmap: 5 });
    const once = host.cancel();
    assert.equal(once.state, STATES.SESSION_CANCELLED);
    const twice = host.cancel();
    assert.equal(twice.state, STATES.SESSION_CANCELLED);
    await expectCode(() => host.collectRole2(), "SESSION_NOT_RESUMABLE");
    await expectCode(() => host.beginRole0Assertion(), "SESSION_NOT_RESUMABLE");
  });

  it("rejects duplicate factor / replay", async function () {
    const { host } = createHost(bundle, {
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    assert.equal(host.status().state, STATES.AWAITING_SECOND_FACTOR);
    await expectCode(
      () => submitMockRole0(host, bundle.credentialId),
      "ROLE_DUPLICATE_OR_REPLAY"
    );
  });

  it("rejects wrong-role / unselected-role collection", async function () {
    const { host } = createHost(bundle);
    await host.beginDrill({ bitmap: 3 });
    await expectCode(() => host.collectRole2(), "ROLE_NOT_SELECTED");
  });

  it("rejects Role 0 wrong challenge/origin/flags/credential/signature", async function () {
    const { host: challengeHost } = createHost(bundle, {
      assertionVerifier: mockAssertionVerifier({ fail: true })
    });
    await challengeHost.beginDrill({ bitmap: 5 });
    const options = challengeHost.beginRole0Assertion();
    await expectCode(
      () => challengeHost.submitRole0Assertion({
        assertion: minimalAssertion({ challenge: options.challenge })
      }),
      "ROLE0_ASSERTION_VERIFICATION_FAILED"
    );

    const { host: flagsHost } = createHost(bundle, {
      assertionVerifier: mockAssertionVerifier()
    });
    await flagsHost.beginDrill({ bitmap: 5 });
    const flagOptions = flagsHost.beginRole0Assertion();
    await expectCode(
      () => flagsHost.submitRole0Assertion({
        assertion: minimalAssertion({
          challenge: flagOptions.challenge,
          flags: 0x1d
        })
      }),
      "ROLE0_ASSERTION_POLICY_REJECTED"
    );

    const { host: originHost } = createHost(bundle, {
      assertionVerifier: {
        async verifyAssertion() {
          return { verified: false, productionVerified: false };
        }
      }
    });
    await originHost.beginDrill({ bitmap: 5 });
    const originOptions = originHost.beginRole0Assertion();
    await expectCode(
      () => originHost.submitRole0Assertion({
        assertion: minimalAssertion({
          challenge: originOptions.challenge,
          origin: "https://evil.example"
        })
      }),
      "ROLE0_ASSERTION_VERIFICATION_FAILED"
    );
  });

  it("rejects Role 1 wrong transcript binding, malformed ciphertext, and public endpoints", async function () {
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "https://example.com/philcore/recovery/v1/complete"
      ),
      false
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "http://8.8.8.8:18787/philcore/recovery/v1/complete"
      ),
      false
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        `http://192.168.1.10:18787${transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH}`
      ),
      true
    );

    const badBinding = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration),
      mutatePayload: (payload) => ({
        ...payload,
        transcriptHash: `0x${"ab".repeat(32)}`
      })
    });
    const { host: bindingHost } = createHost(bundle, {
      phoneSimulator: badBinding
    });
    await bindingHost.beginDrill({ bitmap: 6 });
    await expectCode(() => bindingHost.collectRole1(), "ROLE1_RESPONSE_BINDING_INVALID");

    const badCipher = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration),
      mutateCiphertext: (message) => {
        const bytes = Buffer.from(message.ciphertext, "base64url");
        bytes[0] ^= 0xff;
        return { ...message, ciphertext: base64url(bytes) };
      }
    });
    const { host: cipherHost } = createHost(bundle, {
      phoneSimulator: badCipher
    });
    await cipherHost.beginDrill({ bitmap: 6 });
    await expectCode(() => cipherHost.collectRole1(), "ROLE1_RESPONSE_DECRYPT_FAILED");
  });

  it("rejects Role 1 wrong descriptor generation and nonce reuse", async function () {
    const wrongGeneration = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: 99
    });
    const { host: generationHost } = createHost(bundle, {
      phoneSimulator: wrongGeneration
    });
    await generationHost.beginDrill({ bitmap: 6 });
    await expectCode(
      () => generationHost.collectRole1(),
      "ROLE1_RESPONSE_BINDING_INVALID"
    );

    // Host collects Role 1 only after assertDistinctRecoveryApprovalNonces(phone, ack).
    const reused = base64url(Buffer.alloc(12, 0x42));
    assert.throws(
      () => transport.assertDistinctRecoveryApprovalNonces(
        { nonce: reused },
        { nonce: reused }
      ),
      /nonce_reuse/i
    );
    assert.doesNotThrow(
      () => transport.assertDistinctRecoveryApprovalNonces(
        { nonce: reused },
        { nonce: base64url(Buffer.alloc(12, 0x43)) }
      )
    );

    // Bad simulatePhoneResponse with fixed nonce still decrypts; colliding ack nonce
    // is rejected by the same helper the host invokes before sendAcknowledgement.
    const fixedNonce = Buffer.alloc(12, 0x42);
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration),
      fixedNonce
    });
    const desktopEcdh = crypto.createECDH("prime256v1");
    const desktopPublic = desktopEcdh.generateKeys();
    const phoneMessage = await phoneSimulator({
      request: {
        sessionId: `0x${"11".repeat(32)}`,
        claimedRecoveryFactorDigest: `0x${"22".repeat(32)}`
      },
      transcriptHash: `0x${"33".repeat(32)}`,
      desktopEcdhPublicKey: base64url(desktopPublic)
    });
    assert.equal(phoneMessage.nonce, base64url(fixedNonce));
    assert.throws(
      () => transport.assertDistinctRecoveryApprovalNonces(
        phoneMessage,
        { nonce: phoneMessage.nonce }
      ),
      /nonce_reuse/i
    );
  });

  it("Role 2 cannot be submitted via bridge channels", function () {
    assert.ok(RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_BEGIN));
    assert.ok(
      RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION)
    );
    assert.equal(
      RECOVERY_TRANSPORT_CHANNELS.some((channel) => /role2|Role2|ROLE2/u.test(channel)),
      false
    );
    assert.equal(
      Object.values(CHANNELS).some((channel) => /contributeRole2/u.test(channel)),
      false
    );
    assert.throws(
      () => validateBridgePayload("philcore:recoveryTransport:contributeRole2", {
        evidence: "0x01"
      }),
      /Unsupported PhilCore desktop bridge channel/u
    );
    assert.equal(
      validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, {
        bitmap: 3,
        digest: `0x${"11".repeat(32)}`
      }).ok,
      false
    );
    assert.equal(
      validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 4 }).ok,
      false
    );
    assert.equal(
      validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 6 }).ok,
      true
    );
  });

  it("noncanonical factor ordering still assembles for bitmap 6", async function () {
    const { host } = createHost(bundle, {
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });
    await host.beginDrill({ bitmap: 6 });
    const afterRole2 = await host.collectRole2();
    assert.equal(afterRole2.state, STATES.AWAITING_SECOND_FACTOR);
    assert.deepEqual([...afterRole2.collectedRoles], [2]);
    const passed = await host.collectRole1();
    assert.equal(passed.state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(passed.result.state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(
      String(passed.result.digest || "").length > 0,
      true
    );
  });

  it("envelope assembly failure fails closed without LOCAL_DRILL_PASSED", async function () {
    const { host } = createHost(bundle, {
      role2FactorProvider: async () => ({
        role: 2,
        evidence: `0x${"deadbeef".repeat(8)}`
      }),
      localStaticVerifier: async () => SUCCESS_MAGIC
    });
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    await expectCode(() => host.collectRole2(), "ENVELOPE_ASSEMBLY_FAILED");
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("missing/reverting/wrong-magic localStaticVerifier fails closed", async function () {
    const { host: missingHost } = createHost(bundle, {
      localStaticVerifier: async () => {
        throw new Error("verifier unavailable");
      }
    });
    await missingHost.beginDrill({ bitmap: 5 });
    await submitMockRole0(missingHost, bundle.credentialId);
    await expectCode(
      () => missingHost.collectRole2(),
      "LOCAL_STATIC_VERIFIER_FAILED"
    );
    assert.notEqual(missingHost.status().state, STATES.LOCAL_DRILL_PASSED);

    const { host: wrongMagicHost } = createHost(bundle, {
      localStaticVerifier: async () => "0xdeadbeef"
    });
    await wrongMagicHost.beginDrill({ bitmap: 5 });
    await submitMockRole0(wrongMagicHost, bundle.credentialId);
    await expectCode(
      () => wrongMagicHost.collectRole2(),
      "LOCAL_STATIC_VERIFIER_MAGIC_MISMATCH"
    );
    assert.notEqual(wrongMagicHost.status().state, STATES.LOCAL_DRILL_PASSED);
  });

  it("never surfaces LOCAL_DRILL_PASSED before both factors and verifier success", async function () {
    const { host } = createHost(bundle, {
      localStaticVerifier: hardhatVerifier.localStaticVerifier
    });
    await host.beginDrill({ bitmap: 5 });
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
    await submitMockRole0(host, bundle.credentialId);
    assert.equal(host.status().state, STATES.AWAITING_SECOND_FACTOR);
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
    const passed = await host.collectRole2();
    assert.equal(passed.state, STATES.LOCAL_DRILL_PASSED);
  });

  it("runs successful simulated drills for bitmaps 3, 5, and 6", async function () {
    for (const bitmap of [3, 5, 6]) {
      const { host } = createHost(bundle, {
        localStaticVerifier: hardhatVerifier.localStaticVerifier
      });
      const started = await host.beginDrill({ bitmap });
      assert.equal(started.bitmap, bitmap);
      assert.equal(started.state, STATES.AWAITING_FIRST_FACTOR);

      if (bitmapIncludes(bitmap, 0)) {
        await submitMockRole0(host, bundle.credentialId);
      }
      if (bitmapIncludes(bitmap, 2) && host.status().state !== STATES.LOCAL_DRILL_PASSED) {
        if (!bitmapIncludes(bitmap, 1) || host.status().collectedRoles.includes(0)) {
          // role2 may be first or second depending on prior collection
        }
      }

      if (bitmap === 3) {
        const passed = await host.collectRole1();
        assert.equal(passed.state, STATES.LOCAL_DRILL_PASSED, "bitmap 3");
      } else if (bitmap === 5) {
        const passed = await host.collectRole2();
        assert.equal(passed.state, STATES.LOCAL_DRILL_PASSED, "bitmap 5");
      } else {
        await host.collectRole1();
        const passed = await host.collectRole2();
        assert.equal(passed.state, STATES.LOCAL_DRILL_PASSED, "bitmap 6");
      }

      const magic = await hardhatVerifier.verifier.SUCCESS_MAGIC();
      assert.equal(String(magic).toLowerCase(), SUCCESS_MAGIC.toLowerCase());
      assert.equal(host.status().result.state, STATES.LOCAL_DRILL_PASSED);
    }
  });

  it("uses in-memory Role 1 adapter with no listener/socket bind or RPC URL", function () {
    const adapter = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: async () => {
        throw new Error("unused");
      }
    });
    assert.equal(typeof adapter.listen, "undefined");
    assert.equal(typeof adapter.createServer, "undefined");
    assert.equal("rpcUrl" in adapter, false);
    assert.equal("url" in adapter, false);

    let listenCalled = false;
    const originalListen = net.Server.prototype.listen;
    net.Server.prototype.listen = function patchedListen(...args) {
      listenCalled = true;
      return originalListen.apply(this, args);
    };
    try {
      const { host } = createHost(bundle, { role1TransportAdapter: adapter });
      assert.equal(typeof host.beginDrill, "function");
      assert.equal(listenCalled, false);
      assert.equal(
        safeError(new RecoveryTransportError("TEST_CODE")).errorCode,
        "TEST_CODE"
      );
      assert.ok(SESSION_TTL_MS > 0);
      assert.ok(PHILCORE_V2_ACCOUNT_VERSION_ID);
      assert.ok(PHILCORE_V2_SECURITY_MODEL_ID);
      // Touch helpers that prove fixture wiring without network.
      assert.equal(typeof encodePhilCoreO372WebAuthnEvidence, "function");
      assert.equal(typeof encodePhilCoreO372Secp256k1Evidence, "function");
      assert.equal(typeof computePhilCoreV2RecoveryFactorDigest, "function");
      assert.equal(typeof hexlify, "function");
      assert.equal(typeof sha256, "function");
      assert.equal(typeof keccak256, "function");
      assert.equal(typeof toUtf8Bytes, "function");
      assert.equal(typeof zeroPadValue, "function");
      assert.equal(typeof toBeHex, "function");
    } finally {
      net.Server.prototype.listen = originalListen;
    }
  });

  it("red-gate: local static verifier success after TTL expiry must cancel and not reach LOCAL_DRILL_PASSED", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const { host, clock } = createHost(bundle, {
      localStaticVerifier: async () => {
        await gate;
        return SUCCESS_MAGIC;
      }
    });
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    const pending = host.collectRole2();
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("red-gate: Role 0 assertion verification completing after expiry fails closed", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const { host, clock } = createHost(bundle, {
      assertionVerifier: {
        async verifyAssertion(input) {
          await gate;
          return mockAssertionVerifier().verifyAssertion(input);
        }
      }
    });
    await host.beginDrill({ bitmap: 5 });
    const options = host.beginRole0Assertion();
    const pending = host.submitRole0Assertion({
      assertion: minimalAssertion({
        challenge: options.challenge,
        credentialId: bundle.credentialId
      })
    });
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
    assert.equal(host.status().collectedRoles.length, 0);
  });

  it("red-gate: Role 0 evidence encoding completing after expiry fails closed", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const encode = encodeRole0FromFixture(bundle.primary);
    const { host, clock } = createHost(bundle, {
      encodeRole0Evidence: async (input) => {
        await gate;
        return encode(input);
      }
    });
    await host.beginDrill({ bitmap: 5 });
    const options = host.beginRole0Assertion();
    const pending = host.submitRole0Assertion({
      assertion: minimalAssertion({
        challenge: options.challenge,
        credentialId: bundle.credentialId
      })
    });
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("red-gate: Role 1 adapter startup completing after expiry fails closed", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const adapter = {
      ...base,
      testOnly: true,
      async preparePresentation(input) {
        return base.preparePresentation
          ? base.preparePresentation(input)
          : {
            endpoint:
              `http://10.0.0.1:18787${transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH}`
          };
      },
      async startSession(presentation) {
        await gate;
        return base.startSession(presentation);
      },
      cancel() {
        return base.cancel();
      },
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement()
    };
    const { host, clock } = createHost(bundle, { role1TransportAdapter: adapter });
    const pending = host.beginDrill({ bitmap: 3 });
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("red-gate: Role 1 acknowledgement completing after expiry fails closed", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const adapter = {
      testOnly: true,
      preparePresentation: base.preparePresentation
        ? (...a) => base.preparePresentation(...a)
        : async () => ({
          endpoint:
            `http://10.0.0.1:18787${transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH}`
        }),
      startSession: (...a) => base.startSession(...a),
      waitForResponse: (...a) => base.waitForResponse(...a),
      cancel: () => base.cancel(),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement(),
      async sendAcknowledgement(ack, options) {
        await gate;
        return base.sendAcknowledgement(ack, options);
      }
    };
    const { host, clock } = createHost(bundle, {
      role1TransportAdapter: adapter,
      encodeRole0Evidence: encodeRole0FromFixture(bundle.primary)
    });
    await host.beginDrill({ bitmap: 3 });
    await submitMockRole0(host, bundle.credentialId);
    const pending = host.collectRole1();
    // Allow phone response path to reach acknowledgement, then expire.
    await new Promise((r) => setImmediate(r));
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("red-gate: Role 2 provider completing after expiry fails closed", async () => {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const { host, clock } = createHost(bundle, {
      role2FactorProvider: async (input) => {
        await gate;
        return role2ProviderFromOffline(bundle.offline)(input);
      }
    });
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    const pending = host.collectRole2();
    clock.nowMs += SESSION_TTL_MS + 1;
    release();
    await expectCode(pending, "SESSION_EXPIRED");
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
  });

  it("red-gate: replacement while async ops pending cancels captured sessions", async () => {
    let releaseConfig;
    const configGate = new Promise((resolve) => {
      releaseConfig = resolve;
    });
    let configCalls = 0;
    const { host } = createHost(bundle, {
      trustedConfigProvider: async () => {
        configCalls += 1;
        if (configCalls === 1) {
          await configGate;
        }
        return bundle.trustedConfig;
      }
    });
    const first = host.beginDrill({ bitmap: 5 });
    const second = host.beginDrill({ bitmap: 5 });
    releaseConfig();
    await expectCode(first, "SESSION_REPLACED_OR_CANCELLED");
    const secondStatus = await second;
    assert.ok(
      secondStatus.state === STATES.AWAITING_FIRST_FACTOR
      || secondStatus.state === STATES.REQUEST_CONSTRUCTED
      || secondStatus.state === STATES.AWAITING_SECOND_FACTOR
    );
    assert.notEqual(host.status().state, STATES.SESSION_CANCELLED);
  });

  it("red-gate: stale async rejection must not cancel replacement session", async () => {
    let rejectFirst;
    const firstGate = new Promise((_resolve, reject) => {
      rejectFirst = reject;
    });
    let calls = 0;
    const { host } = createHost(bundle, {
      trustedConfigProvider: async () => {
        calls += 1;
        if (calls === 1) {
          await firstGate;
        }
        return bundle.trustedConfig;
      }
    });
    const first = host.beginDrill({ bitmap: 5 });
    const secondStatus = await host.beginDrill({ bitmap: 5 });
    const replacementSessionId = secondStatus.sessionId;
    rejectFirst(new Error("stale-provider-boom"));
    await expectCode(first, "SESSION_REPLACED_OR_CANCELLED");
    assert.equal(host.status().sessionId, replacementSessionId);
    assert.notEqual(host.status().state, STATES.SESSION_CANCELLED);
    assert.ok(
      host.status().state === STATES.AWAITING_FIRST_FACTOR
      || host.status().state === STATES.REQUEST_CONSTRUCTED
    );
  });

  it("red-gate: envelope SecretValue.clear is invoked across terminal paths", async () => {
    const hostSrc = fs.readFileSync(
      path.join(__dirname, "../src/main/recovery-transport-host.cjs"),
      "utf8"
    );
    assert.match(
      hostSrc,
      /envelope\s*(?:instanceof\s+SecretValue[\s\S]{0,80})?\.clear\s*\(/
    );
    assert.match(hostSrc, /clearSessionSecrets/);
    // Behavioral: success path clears secrets from public status.
    const { host } = createHost(bundle);
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    await host.collectRole2();
    assert.equal(host.status().state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(host.status().envelope, undefined);
    assert.equal(host.status().factors, undefined);

    // Cancel path
    const cancelled = createHost(bundle);
    await cancelled.host.beginDrill({ bitmap: 5 });
    cancelled.host.cancel();
    assert.equal(cancelled.host.status().state, STATES.SESSION_CANCELLED);

    // Verifier failure path
    const failing = createHost(bundle, {
      localStaticVerifier: async () => {
        throw new Error("boom");
      }
    });
    await failing.host.beginDrill({ bitmap: 5 });
    await submitMockRole0(failing.host, bundle.credentialId);
    await expectCode(failing.host.collectRole2(), "LOCAL_STATIC_VERIFIER_FAILED");

    // Wrong-magic path
    const wrong = createHost(bundle, {
      localStaticVerifier: async () => 0xdeadbeef
    });
    await wrong.host.beginDrill({ bitmap: 5 });
    await submitMockRole0(wrong.host, bundle.credentialId);
    await expectCode(
      wrong.host.collectRole2(),
      "LOCAL_STATIC_VERIFIER_MAGIC_MISMATCH"
    );
  });

  it("red-gate: production main.cjs does not wire in-memory Role 1 simulator", () => {
    const mainSrc = fs.readFileSync(
      path.join(__dirname, "../src/main/main.cjs"),
      "utf8"
    );
    assert.equal(
      /role1TransportAdapter:\s*createInMemoryRole1TransportAdapter\s*\(/.test(mainSrc),
      false
    );
    assert.match(mainSrc, /createUnavailableRole1TransportAdapter\s*\(/);
  });

  it("red-gate: host no longer advertises hardcoded fictional endpoint", () => {
    const hostSrc = fs.readFileSync(
      path.join(__dirname, "../src/main/recovery-transport-host.cjs"),
      "utf8"
    );
    assert.equal(hostSrc.includes("192.168.1.10"), false);
    assert.equal(hostSrc.includes("ROLE1_PRESENTATION_ENDPOINT"), false);
  });

  it("red-gate: Role 1 presentation endpoint comes from host-owned adapter and passes O.44 validation", async () => {
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const adapter = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    assert.equal(typeof adapter.preparePresentation, "function");
    const prepared = await adapter.preparePresentation({ sessionId: "0x01" });
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(prepared.endpoint),
      true
    );
    assert.ok(
      prepared.endpoint.includes(transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH)
    );
    const { host } = createHost(bundle, { role1TransportAdapter: adapter });
    const status = await host.beginDrill({ bitmap: 3 });
    assert.ok(status.role1Presentation);
    assert.equal(status.role1Presentation.endpoint, prepared.endpoint);
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(status.role1Presentation.endpoint),
      true
    );
  });

  it("red-gate: unavailable production Role 1 transport fails closed before presenting QR/request", async () => {
    assert.equal(typeof createUnavailableRole1TransportAdapter, "function");
    const unavailable = createUnavailableRole1TransportAdapter();
    const { host } = createHost(bundle, { role1TransportAdapter: unavailable });
    await expectCode(host.beginDrill({ bitmap: 3 }), "ROLE1_TRANSPORT_NOT_CONFIGURED");
    const status = host.status();
    assert.equal(status.state, STATES.SESSION_CANCELLED);
    assert.equal(status.role1Presentation, undefined);
    assert.equal(status.request, undefined);
  });

  it("red-gate: in-memory adapter is explicitly test-only", () => {
    assert.throws(
      () => createInMemoryRole1TransportAdapter(),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "IN_MEMORY_ROLE1_ADAPTER_TEST_ONLY"
    );
    assert.throws(
      () => createInMemoryRole1TransportAdapter({ simulatePhoneResponse: async () => ({}) }),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "IN_MEMORY_ROLE1_ADAPTER_TEST_ONLY"
    );
    const adapter = createInMemoryRole1TransportAdapter({ testOnly: true });
    assert.equal(adapter.testOnly, true);
  });

  it("red-gate: malformed/wrong Role 2 evidence cannot reach LOCAL_DRILL_PASSED", async () => {
    const { host } = createHost(bundle, {
      role2FactorProvider: async () => ({
        role: 2,
        evidence: "0xdead"
      })
    });
    await host.beginDrill({ bitmap: 5 });
    await submitMockRole0(host, bundle.credentialId);
    let failed = false;
    try {
      await host.collectRole2();
    } catch (error) {
      failed = true;
      const code = error instanceof RecoveryTransportError
        ? error.code
        : String(error && error.code);
      assert.ok(
        code === "ENVELOPE_ASSEMBLY_FAILED"
        || code === "LOCAL_STATIC_VERIFIER_FAILED"
        || code === "LOCAL_STATIC_VERIFIER_MAGIC_MISMATCH"
        || code === "ROLE2_EVIDENCE_INVALID",
        `unexpected code ${code}`
      );
    }
    assert.equal(failed, true);
    assert.notEqual(host.status().state, STATES.LOCAL_DRILL_PASSED);
  });

  it("red-gate: Role 1 public presentation includes complete O.44 QR material for bitmaps 3 and 6", async () => {
    for (const bitmap of [3, 6]) {
      const { host, adapter } = createHost(bundle);
      const status = await host.beginDrill({ bitmap });
      const presentation = status.role1Presentation;
      assert.ok(presentation, `bitmap ${bitmap} missing role1Presentation`);

      assert.equal(
        presentation.protocolVersion,
        transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION
      );
      assert.equal(presentation.sessionId, status.sessionId);
      assert.ok(presentation.issuedAt);
      assert.equal(String(presentation.expiresAt), String(status.expiresAt));
      assert.equal(
        transport.isRfc1918RecoveryApprovalEndpoint(presentation.endpoint),
        true
      );

      assert.equal(typeof presentation.desktopEphemeralPublicKey, "string");
      assert.ok(presentation.desktopEphemeralPublicKey.length > 0);
      transport.validateUncompressedP256PublicKey(
        presentation.desktopEphemeralPublicKey,
        "desktop_ephemeral"
      );

      assert.ok(presentation.request);
      assert.equal(
        presentation.request.desktopEphemeralPublicKey,
        presentation.desktopEphemeralPublicKey
      );
      assert.equal(presentation.request.endpoint, presentation.endpoint);
      assert.equal(presentation.request.sessionId, presentation.sessionId);

      assert.match(presentation.transcriptHash, /^0x[0-9a-f]{64}$/i);
      assert.equal(typeof presentation.comparisonFingerprint, "string");
      assert.equal(
        presentation.comparisonFingerprint,
        transport.displayPhilCoreRecoveryComparisonFingerprint(
          presentation.transcriptHash
        )
      );

      const expectedAction = transport.derivedRecoveryActionText(
        presentation.request.context
      );
      const expectedNetwork = transport.derivedRecoveryNetworkText(
        presentation.request.context
      );
      assert.equal(presentation.actionText, expectedAction);
      assert.equal(presentation.networkText, expectedNetwork);
      assert.equal(presentation.request.actionText, expectedAction);
      assert.equal(presentation.request.networkText, expectedNetwork);

      const adapterRequest = adapter.getLastRequest();
      assert.ok(adapterRequest);
      // Public request snapshot must match the adapter-held request on all
      // O.44 approval fields, allowing BigInt→canonical-decimal-string
      // normalization in the detached public presentation only.
      for (const key of Object.keys(adapterRequest)) {
        assertPublicFieldEquivalent(
          presentation.request[key],
          adapterRequest[key],
          `bitmap ${bitmap} request field ${key}`
        );
      }

      const recomputedTranscript =
        transport.buildPhilCoreNativeRecoveryApprovalTranscript(
          presentation.request
        );
      const recomputedHash =
        transport.hashPhilCoreNativeRecoveryApprovalTranscript(
          recomputedTranscript
        );
      assert.equal(
        presentation.transcriptHash,
        asBytes32Hex(recomputedHash)
      );
    }
  });

  it("red-gate: Role 1 presentation is a detached deeply immutable public snapshot", async () => {
    const { host, adapter } = createHost(bundle);
    const status = await host.beginDrill({ bitmap: 3 });
    const presentation = status.role1Presentation;
    assert.ok(presentation);
    const originalEndpoint = presentation.endpoint;
    const originalSessionId = presentation.sessionId;
    const originalAccount = presentation.request.context.account;
    const adapterSessionId = adapter.getLastRequest().sessionId;

    assert.throws(() => {
      presentation.endpoint = "http://evil.example/philcore/recovery/v1/complete";
    });
    assert.throws(() => {
      presentation.request.sessionId = `0x${"11".repeat(32)}`;
    });
    assert.throws(() => {
      presentation.request.context.account = "0x0000000000000000000000000000000000000001";
    });
    assert.throws(() => {
      presentation.transcriptHash = `0x${"22".repeat(32)}`;
    });
    assert.throws(() => {
      presentation.comparisonFingerprint = "AAAA BBBB CCCC";
    });

    const again = host.status().role1Presentation;
    assert.equal(again.endpoint, originalEndpoint);
    assert.equal(again.sessionId, originalSessionId);
    assert.equal(again.request.context.account, originalAccount);
    assert.equal(adapter.getLastRequest().sessionId, adapterSessionId);
    assert.notEqual(again, presentation);
    assert.notEqual(again.request, presentation.request);
  });

  it("red-gate: Role 1 presentation excludes all secret and private material", async () => {
    const { host } = createHost(bundle);
    await host.beginDrill({ bitmap: 3 });
    const presentation = host.status().role1Presentation;
    assert.ok(presentation);
    assert.ok(presentation.request, "complete public request required");
    assert.ok(presentation.transcriptHash, "transcript hash required");
    assert.ok(presentation.desktopEphemeralPublicKey, "ephemeral public key required");
    assert.ok(presentation.comparisonFingerprint, "comparison fingerprint required");

    const forbiddenKeys = new Set([
      "privateKey",
      "privateScalar",
      "sharedSecret",
      "aesKey",
      "ecdh",
      "decryptedPayload",
      "plaintext",
      "envelope",
      "acknowledgement",
      "encryptedResponse",
      "evidence",
      "factors",
      "role2",
      "recoveryPhrase",
      "mnemonic",
      "seed"
    ]);
    const seen = [];
    function walk(value, path) {
      if (value === null || value === undefined) return;
      if (typeof value === "object") {
        if (Buffer.isBuffer(value)) {
          seen.push(`${path}:Buffer`);
          return;
        }
        for (const [key, child] of Object.entries(value)) {
          const next = path ? `${path}.${key}` : key;
          assert.equal(
            forbiddenKeys.has(key),
            false,
            `forbidden key ${next}`
          );
          walk(child, next);
        }
        return;
      }
      if (typeof value === "string") {
        assert.equal(/BEGIN (EC )?PRIVATE KEY/i.test(value), false, path);
        assert.equal(/sharedSecret|aesKey|privateKey/i.test(value), false, path);
      }
    }
    walk(presentation, "role1Presentation");
    const serialized = JSON.stringify(presentation);
    assert.equal(serialized.includes("sharedSecret"), false);
    assert.equal(serialized.includes("aesKey"), false);
    assert.equal(serialized.includes("decryptedPayload"), false);
    assert.equal(serialized.includes("\"envelope\""), false);
    assert.equal(serialized.includes("acknowledgement"), false);
    assert.equal(seen.some((entry) => entry.endsWith(":Buffer")), false);
  });

  it("red-gate: Role 1 presentation is suppressed across lifecycle and bitmap 5", async () => {
    // Before adapter preparation completes.
    let releasePrep;
    const prepGate = new Promise((resolve) => {
      releasePrep = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const gated = {
      testOnly: true,
      async preparePresentation(input) {
        await prepGate;
        return base.preparePresentation(input);
      },
      startSession: (...args) => base.startSession(...args),
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      cancel: () => base.cancel(),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement()
    };
    const gatedHost = createHost(bundle, { role1TransportAdapter: gated });
    const pendingBegin = gatedHost.host.beginDrill({ bitmap: 3 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(gatedHost.host.status().role1Presentation, undefined);
    releasePrep();
    const ready = await pendingBegin;
    assert.ok(ready.role1Presentation);
    assert.ok(ready.role1Presentation.request);
    assert.ok(ready.role1Presentation.transcriptHash);
    assert.ok(ready.role1Presentation.comparisonFingerprint);
    assert.ok(ready.role1Presentation.desktopEphemeralPublicKey);
    assert.ok(ready.role1Presentation.actionText);
    assert.ok(ready.role1Presentation.networkText);

    // Bitmap 5 never presents Role 1.
    const bitmap5 = createHost(bundle);
    const status5 = await bitmap5.host.beginDrill({ bitmap: 5 });
    assert.equal(status5.role1Presentation, undefined);

    // Cancellation.
    const cancelled = createHost(bundle);
    await cancelled.host.beginDrill({ bitmap: 3 });
    assert.ok(cancelled.host.status().role1Presentation.request);
    cancelled.host.cancel();
    assert.equal(cancelled.host.status().role1Presentation, undefined);

    // Replacement.
    const replaced = createHost(bundle);
    await replaced.host.beginDrill({ bitmap: 3 });
    const firstId = replaced.host.status().role1Presentation.sessionId;
    await replaced.host.beginDrill({ bitmap: 3 });
    const second = replaced.host.status().role1Presentation;
    assert.ok(second.request);
    assert.notEqual(second.sessionId, firstId);

    // Expiry.
    const expired = createHost(bundle);
    await expired.host.beginDrill({ bitmap: 3 });
    assert.ok(expired.host.status().role1Presentation.request);
    expired.clock.nowMs = expired.host.status().expiresAt;
    assert.equal(expired.host.status().role1Presentation, undefined);
    assert.equal(expired.host.status().state, STATES.SESSION_CANCELLED);

    // LOCAL_DRILL_PASSED.
    const passed = createHost(bundle);
    await passed.host.beginDrill({ bitmap: 3 });
    assert.ok(passed.host.status().role1Presentation.request);
    await submitMockRole0(passed.host, bundle.credentialId);
    await passed.host.collectRole1();
    assert.equal(passed.host.status().state, STATES.LOCAL_DRILL_PASSED);
    assert.equal(passed.host.status().role1Presentation, undefined);

    // Role 1 cryptographic/transport failure.
    const failingAdapter = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: async () => {
        throw new Error("role1-boom");
      }
    });
    const failing = createHost(bundle, { role1TransportAdapter: failingAdapter });
    await failing.host.beginDrill({ bitmap: 3 });
    assert.ok(failing.host.status().role1Presentation.request);
    await submitMockRole0(failing.host, bundle.credentialId);
    await expectCode(failing.host.collectRole1(), "ROLE1_TRANSPORT_WAIT_FAILED");
    assert.equal(failing.host.status().role1Presentation, undefined);
  });

  it("red-gate: transcript hash and comparison fingerprint are host-derived only", async () => {
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    let startedWith = null;
    const adapter = {
      testOnly: true,
      preparePresentation: (...args) => base.preparePresentation(...args),
      async startSession(presentation) {
        startedWith = presentation;
        // Attempt to inject attacker-controlled transcript material into the
        // adapter path; the host presentation must ignore it.
        return base.startSession({
          ...presentation,
          transcriptHash: `0x${"aa".repeat(32)}`,
          comparisonFingerprint: "DEAD BEEF CAFE",
          request: {
            ...presentation.request,
            transcriptHash: `0x${"bb".repeat(32)}`
          }
        });
      },
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      cancel: () => base.cancel(),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement()
    };
    const { host } = createHost(bundle, { role1TransportAdapter: adapter });
    const status = await host.beginDrill({ bitmap: 3 });
    const presentation = status.role1Presentation;
    assert.ok(presentation);
    assert.ok(startedWith);

    const expectedHash = asBytes32Hex(
      transport.hashPhilCoreNativeRecoveryApprovalTranscript(
        transport.buildPhilCoreNativeRecoveryApprovalTranscript(
          presentation.request
        )
      )
    );
    assert.equal(presentation.transcriptHash, expectedHash);
    assert.equal(
      presentation.comparisonFingerprint,
      transport.displayPhilCoreRecoveryComparisonFingerprint(expectedHash)
    );
    assert.notEqual(presentation.transcriptHash, `0x${"aa".repeat(32)}`);
    assert.notEqual(presentation.comparisonFingerprint, "DEAD BEEF CAFE");
    assert.equal(startedWith.transcriptHash, expectedHash);
  });

  it("red-gate: obsolete failClosed helper is absent", () => {
    const hostSrc = fs.readFileSync(
      path.join(__dirname, "../src/main/recovery-transport-host.cjs"),
      "utf8"
    );
    assert.equal(/\bfailClosed\s*\(/.test(hostSrc), false);
    assert.equal(/\bfunction\s+failClosed\b/.test(hostSrc), false);
  });

  it("red-gate: plain JSON.stringify of Role 1 presentation must succeed without BigInt replacer", async () => {
    const sizes = {};
    for (const bitmap of [3, 6]) {
      const internalGeneration =
        bundle.trustedConfig.role1.descriptor.credentialGeneration;
      const { host, adapter } = createHost(bundle);
      const status = await host.beginDrill({ bitmap });
      const presentation = status.role1Presentation;
      assert.ok(presentation);

      // Plain serialization must not throw and must not retain BigInt.
      const serialized = JSON.stringify(presentation);
      assert.equal(typeof serialized, "string");
      sizes[bitmap] = {
        presentationBytes: Buffer.byteLength(serialized, "utf8"),
        requestBytes: Buffer.byteLength(
          JSON.stringify(presentation.request),
          "utf8"
        )
      };
      assertNoBigInt(presentation, "presentation");

      const roundTripped = JSON.parse(serialized);
      assert.ok(roundTripped.request);
      assert.equal(roundTripped.sessionId, presentation.sessionId);
      assert.equal(roundTripped.transcriptHash, presentation.transcriptHash);
      assert.equal(
        roundTripped.comparisonFingerprint,
        presentation.comparisonFingerprint
      );
      assert.equal(roundTripped.actionText, presentation.actionText);
      assert.equal(roundTripped.networkText, presentation.networkText);

      const validated = transport.validatePhilCoreRecoveryApprovalRequest(
        roundTripped.request
      );
      assert.equal(validated.actionText, presentation.actionText);
      assert.equal(validated.networkText, presentation.networkText);

      const recomputedTranscript =
        transport.buildPhilCoreNativeRecoveryApprovalTranscript(
          roundTripped.request
        );
      const recomputedHash = asBytes32Hex(
        transport.hashPhilCoreNativeRecoveryApprovalTranscript(
          recomputedTranscript
        )
      );
      assert.equal(recomputedHash, presentation.transcriptHash);
      assert.equal(
        transport.displayPhilCoreRecoveryComparisonFingerprint(recomputedHash),
        presentation.comparisonFingerprint
      );
      assert.equal(
        transport.derivedRecoveryActionText(roundTripped.request.context),
        presentation.actionText
      );
      assert.equal(
        transport.derivedRecoveryNetworkText(roundTripped.request.context),
        presentation.networkText
      );

      const descriptor = roundTripped.request.trustedRole1Descriptor;
      for (const field of [
        "descriptorVersion",
        "role",
        "verifierKind",
        "credentialGeneration"
      ]) {
        assertCanonicalPublicInteger(descriptor[field], field);
      }
      assertCanonicalPublicInteger(
        roundTripped.request.selectedRole1CredentialGeneration,
        "selectedRole1CredentialGeneration"
      );

      // Internal trusted config / adapter request must remain unnormalized.
      assert.equal(
        bundle.trustedConfig.role1.descriptor.credentialGeneration,
        internalGeneration
      );
      const adapterRequest = adapter.getLastRequest();
      assert.ok(adapterRequest);
      const adapterGeneration =
        adapterRequest.trustedRole1Descriptor.credentialGeneration;
      const publicGeneration =
        presentation.request.trustedRole1Descriptor.credentialGeneration;
      if (typeof adapterGeneration === "bigint") {
        assert.equal(typeof publicGeneration, "string");
        assert.equal(publicGeneration, adapterGeneration.toString(10));
      }
      // Presentation snapshot is detached from adapter-held request object.
      assert.notEqual(
        presentation.request,
        adapterRequest
      );
      assert.notEqual(
        presentation.request.trustedRole1Descriptor,
        adapterRequest.trustedRole1Descriptor
      );
    }
    console.log(`presentation-byte-sizes ${JSON.stringify(sizes)}`);
  });

  it("red-gate: unsupported public snapshot values fail closed", () => {
    assert.equal(typeof cloneJsonSafePublicSnapshot, "function");
    assert.throws(
      () => cloneJsonSafePublicSnapshot(Buffer.from("x")),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_BUFFER_REJECTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(new Uint8Array([1, 2, 3])),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_BUFFER_REJECTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(() => "nope"),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_VALUE_UNSUPPORTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(Symbol("x")),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_VALUE_UNSUPPORTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(undefined),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_VALUE_UNSUPPORTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(Number.NaN),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_NUMBER_INVALID"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(Number.POSITIVE_INFINITY),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_NUMBER_INVALID"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(new Date()),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_PROTOTYPE_REJECTED"
    );
    const cyclic = { a: 1 };
    cyclic.self = cyclic;
    assert.throws(
      () => cloneJsonSafePublicSnapshot(cyclic),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_CYCLE_REJECTED"
    );
    assert.throws(
      () => cloneJsonSafePublicSnapshot(-1n),
      (error) =>
        error instanceof RecoveryTransportError
        && error.code === "ROLE1_PRESENTATION_BIGINT_NEGATIVE"
    );
    // Positive BigInt normalizes to canonical decimal string.
    assert.equal(cloneJsonSafePublicSnapshot(0n), "0");
    assert.equal(cloneJsonSafePublicSnapshot(42n), "42");
  });

  it("red-gate: main.cjs recovery WebAuthn SDK import resolves from main source file", () => {
    const mainPath = path.resolve(__dirname, "../src/main/main.cjs");
    const hostPath = path.resolve(
      __dirname,
      "../src/main/recovery-transport-host.cjs"
    );
    const expectedSdkPath = path.resolve(
      __dirname,
      "../../phil-device-sdk/src/deviceIdentityWebAuthn.ts"
    );
    assert.equal(fs.existsSync(expectedSdkPath), true);
    assert.equal(
      expectedSdkPath.includes(`${path.sep}philcore-desktop${path.sep}phil-device-sdk${path.sep}`),
      false
    );

    const mainSrc = fs.readFileSync(mainPath, "utf8");
    const hostSrc = fs.readFileSync(hostPath, "utf8");
    const mainMatches = [...mainSrc.matchAll(
      /require\(\s*["']([^"']*deviceIdentityWebAuthn\.ts)["']\s*\)/g
    )];
    assert.equal(mainMatches.length, 1, "expected one WebAuthn SDK require in main.cjs");
    const mainSpecifier = mainMatches[0][1];

    const hostMatches = [...hostSrc.matchAll(
      /require\(\s*["']([^"']*phil-device-sdk\/src\/[^"']+)["']\s*\)/g
    )];
    assert.ok(hostMatches.length >= 1, "expected recovery-transport host SDK requires");

    const previousCwd = process.cwd();
    const previousNodePath = process.env.NODE_PATH;
    const previousPath = process.env.PATH;
    try {
      process.chdir(os.tmpdir());
      delete process.env.NODE_PATH;

      const mainRequire = createRequire(mainPath);
      let resolvedMain;
      try {
        resolvedMain = mainRequire.resolve(mainSpecifier);
      } catch (error) {
        assert.fail(
          `main.cjs specifier ${mainSpecifier} must resolve from ${mainPath}: ${
            error && error.message
          }`
        );
      }
      assert.equal(path.resolve(resolvedMain), expectedSdkPath);
      assert.equal(
        resolvedMain.includes(`${path.sep}philcore-desktop${path.sep}phil-device-sdk${path.sep}`),
        false
      );

      const hostRequire = createRequire(hostPath);
      for (const match of hostMatches) {
        const specifier = match[1];
        const resolved = hostRequire.resolve(specifier);
        assert.equal(
          path.resolve(resolved).startsWith(
            path.resolve(__dirname, "../../phil-device-sdk", "src")
          ),
          true,
          `host specifier ${specifier} resolved outside sibling SDK: ${resolved}`
        );
        assert.equal(
          resolved.includes(`${path.sep}philcore-desktop${path.sep}phil-device-sdk${path.sep}`),
          false
        );
      }
    } finally {
      process.chdir(previousCwd);
      if (previousNodePath === undefined) {
        delete process.env.NODE_PATH;
      } else {
        process.env.NODE_PATH = previousNodePath;
      }
      process.env.PATH = previousPath;
    }
  });

  // ---------------------------------------------------------------------------
  // Package 2 — private-LAN recovery listener adapter (O.45 bootstrap wiring)
  // ---------------------------------------------------------------------------

  it("red-gate p2: production Role1 transport listener factory is exported", () => {
    assert.equal(
      typeof createProductionRole1TransportListenerAdapter,
      "function",
      "createProductionRole1TransportListenerAdapter must be exported"
    );
    assert.match(
      fs.readFileSync(
        path.join(__dirname, "../src/main/recovery-transport-host.cjs"),
        "utf8"
      ),
      /createProductionRole1TransportListenerAdapter/
    );
    assert.equal(
      fs.readFileSync(
        path.join(__dirname, "../src/main/main.cjs"),
        "utf8"
      ).includes("createProductionRole1TransportListenerAdapter"),
      false,
      "main.cjs must keep createUnavailableRole1TransportAdapter"
    );
  });

  it("red-gate p2: host Role1 presentation includes bootstrapUri (148-byte ticket / 219-byte URI)", async () => {
    const { host } = createHost(bundle);
    const status = await host.beginDrill({ bitmap: 3 });
    const presentation = status.role1Presentation;
    assert.ok(presentation, "role1Presentation required");
    assert.equal(typeof presentation.bootstrapUri, "string");
    assert.equal(
      Buffer.byteLength(presentation.bootstrapUri, "ascii"),
      bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES
    );
    const ticketBytes = bootstrap.parsePrb1Uri(presentation.bootstrapUri);
    assert.equal(
      ticketBytes.length,
      bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES
    );
    const ticket = bootstrap.decodePrb1Ticket(ticketBytes);
    const requestEndpoint = bootstrap.buildRequestEndpointFromTicket(ticket);
    assert.match(
      requestEndpoint,
      /\/philcore\/recovery\/v1\/request$/
    );
    assert.match(
      presentation.endpoint,
      /\/philcore\/recovery\/v1\/complete$/
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(presentation, "ticketHex"),
      false
    );
  });

  it("red-gate p2: bootstrapUri absent for bitmap 5 and before/after Role1 lifecycle edges", async () => {
    const bitmap5 = createHost(bundle);
    const status5 = await bitmap5.host.beginDrill({ bitmap: 5 });
    assert.equal(status5.role1Presentation, undefined);
    assert.equal(status5.bootstrapUri, undefined);

    let releasePrep;
    const prepGate = new Promise((resolve) => {
      releasePrep = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const gated = {
      testOnly: true,
      async preparePresentation(input) {
        await prepGate;
        return base.preparePresentation(input);
      },
      startSession: (...args) => base.startSession(...args),
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      cancel: () => base.cancel(),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement()
    };
    const gatedHost = createHost(bundle, { role1TransportAdapter: gated });
    const pending = gatedHost.host.beginDrill({ bitmap: 3 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(gatedHost.host.status().role1Presentation, undefined);
    releasePrep();
    const ready = await pending;
    assert.equal(typeof ready.role1Presentation.bootstrapUri, "string");

    const cancelled = createHost(bundle);
    await cancelled.host.beginDrill({ bitmap: 3 });
    assert.ok(cancelled.host.status().role1Presentation.bootstrapUri);
    cancelled.host.cancel();
    assert.equal(cancelled.host.status().role1Presentation, undefined);
  });

  it("red-gate p2: RFC1918 bind-address accept/reject matrix and ambiguous IPv4", async () => {
    assert.equal(typeof createProductionRole1TransportListenerAdapter, "function");
    const accepted = [
      "10.0.0.1",
      "10.255.255.255",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.0.1",
      "192.168.1.50"
    ];
    const rejected = [
      "0.0.0.0",
      "127.0.0.1",
      "169.254.1.1",
      "8.8.8.8",
      "172.15.0.1",
      "172.32.0.1",
      "192.168.1.01",
      "192.168.01.1",
      "01.0.0.1",
      "::1",
      "localhost",
      "192.168.1.50%eth0",
      "192.168.1.50:8080",
      "*",
      ""
    ];
    for (const address of accepted) {
      const harness = createInjectableListenerHarness({ bindAddress: address });
      const adapter = createProductionRole1TransportListenerAdapter(harness.options);
      const prepared = await adapter.preparePresentation({
        sessionId: `0x${"11".repeat(32)}`,
        issuedAtMs: 1_700_000_000_000,
        expiresAt: 1_700_000_000_000 + SESSION_TTL_MS
      });
      assert.equal(prepared.host, address);
      assert.equal(typeof prepared.port, "number");
      assert.ok(prepared.port >= 1024 && prepared.port <= 65535);
      assert.equal(
        prepared.completionEndpoint,
        `http://${address}:${prepared.port}${bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH}`
      );
      assert.equal(
        prepared.requestEndpoint,
        `http://${address}:${prepared.port}${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`
      );
      adapter.cancel("test-cleanup");
    }
    for (const address of rejected) {
      const harness = createInjectableListenerHarness({ bindAddress: address });
      const adapter = createProductionRole1TransportListenerAdapter(harness.options);
      await expectCode(
        () => adapter.preparePresentation({
          sessionId: `0x${"22".repeat(32)}`,
          issuedAtMs: 1_700_000_000_000,
          expiresAt: 1_700_000_000_000 + SESSION_TTL_MS
        }),
        "ROLE1_BIND_ADDRESS_INVALID"
      );
    }
    const ambiguous = createProductionRole1TransportListenerAdapter({
      bindAddressProvider: () => ["192.168.1.50", "10.0.0.1"],
      createHttpServer: createInjectableListenerHarness().options.createHttpServer,
      now: () => 1_700_000_000_000
    });
    await expectCode(
      () => ambiguous.preparePresentation({
        sessionId: `0x${"33".repeat(32)}`,
        issuedAtMs: 1_700_000_000_000,
        expiresAt: 1_700_000_000_000 + SESSION_TTL_MS
      }),
      "ROLE1_BIND_ADDRESS_INVALID"
    );
    const missing = createProductionRole1TransportListenerAdapter({
      createHttpServer: createInjectableListenerHarness().options.createHttpServer,
      now: () => 1_700_000_000_000
    });
    await expectCode(
      () => missing.preparePresentation({
        sessionId: `0x${"44".repeat(32)}`,
        issuedAtMs: 1_700_000_000_000,
        expiresAt: 1_700_000_000_000 + SESSION_TTL_MS
      }),
      "ROLE1_BIND_ADDRESS_INVALID"
    );
  });

  it("red-gate p2: bind host/port retained prepare→activate; pre-activation 503; exact routes", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.1.50" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"ab".repeat(32)}`;
    const prepared = await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    assert.equal(adapter.getPhase(), "BOUND_INACTIVE");
    const early = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: "{}"
    });
    assert.equal(early.statusCode, 503);

    const capabilityCalls = [];
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async (fetchInit) => {
        capabilityCalls.push(fetchInit);
        return {
          protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
          sessionId,
          nonce: base64url(Buffer.alloc(12, 7)),
          ciphertext: base64url(Buffer.alloc(32, 8)),
          tag: base64url(Buffer.alloc(16, 9))
        };
      }
    });
    assert.equal(adapter.getPhase(), "SESSION_ACTIVE");
    assert.equal(adapter.getBoundAddress(), prepared.host);
    assert.equal(adapter.getBoundPort(), prepared.port);

    const getRejected = await harness.inject({
      method: "GET",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: ""
    });
    assert.equal(getRejected.statusCode, 405);

    const wrongPath = await harness.inject({
      method: "POST",
      url: "/philcore/recovery/v1/other",
      headers: { "content-type": "application/json; charset=utf-8" },
      body: "{}"
    });
    assert.equal(wrongPath.statusCode, 404);

    const wrongCt = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json" },
      body: "{}"
    });
    assert.equal(wrongCt.statusCode, 415);
    assert.equal(capabilityCalls.length, 0);
    adapter.cancel("test-cleanup");
  });

  it("red-gate p2: body/header/framing limits and injected 5s idle timeout", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "10.0.0.8" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"cd".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => {
        throw new Error("should-not-run");
      }
    });

    const oversizedRequest = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: "x".repeat(1025)
    });
    assert.equal(oversizedRequest.statusCode, 413);

    const hugeHeaders = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "x-pad": "y".repeat(5000)
      },
      body: "{}"
    });
    assert.ok(
      hugeHeaders.statusCode === 431 || hugeHeaders.destroyed === true
    );

    const teAndCl = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "transfer-encoding": "chunked",
        "content-length": "2"
      },
      body: "{}"
    });
    assert.ok(teAndCl.statusCode === 400 || teAndCl.destroyed === true);

    const idle = await harness.injectIdleTimeout({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      advanceMs: 5000
    });
    assert.equal(idle.destroyed, true);
    adapter.cancel("test-cleanup");
  });

  it("red-gate p2: fetch attempt cap, phone-key lock, fresh nonces, single completion", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.10.20" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"ef".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });

    const phoneA = base64url(Buffer.concat([
      Buffer.from([0x04]),
      Buffer.alloc(64, 0x11)
    ]));
    // Use a real uncompressed P256 key from the fixture native peer material.
    const phoneKey = (() => {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      return base64url(ecdh.getPublicKey());
    })();
    const phoneKeyB = (() => {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      return base64url(ecdh.getPublicKey());
    })();
    void phoneA;

    const nonces = [];
    let deliveries = 0;
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async (fetchInit) => {
        deliveries += 1;
        const nonce = base64url(crypto.randomBytes(12));
        nonces.push(nonce);
        return {
          protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
          sessionId,
          nonce,
          ciphertext: base64url(Buffer.alloc(48, deliveries)),
          tag: base64url(Buffer.alloc(16, deliveries))
        };
      }
    });

    function fetchBody(phoneEphemeralPublicKey) {
      return JSON.stringify({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        phoneEphemeralPublicKey,
        fetchChallenge: base64url(Buffer.alloc(32, 3))
      });
    }

    const first = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKey)
    });
    assert.equal(first.statusCode, 200);

    const retrySame = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKey)
    });
    assert.equal(retrySame.statusCode, 200);

    const third = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKey)
    });
    assert.equal(third.statusCode, 200);
    assert.equal(deliveries, 3);
    assert.equal(new Set(nonces).size, 3);

    const fourth = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKey)
    });
    assert.equal(fourth.statusCode, 429);

    // Mismatch key on a fresh adapter after first lock must fail closed.
    const harness2 = createInjectableListenerHarness({ bindAddress: "192.168.10.21" });
    const adapter2 = createProductionRole1TransportListenerAdapter(harness2.options);
    await adapter2.preparePresentation({
      sessionId,
      issuedAtMs: harness2.clock.nowMs,
      expiresAt: harness2.clock.nowMs + SESSION_TTL_MS
    });
    let locked = false;
    await adapter2.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async (fetchInit) => {
        if (!locked) {
          locked = true;
          return {
            protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
            sessionId,
            nonce: base64url(Buffer.alloc(12, 1)),
            ciphertext: base64url(Buffer.alloc(32, 1)),
            tag: base64url(Buffer.alloc(16, 1))
          };
        }
        assert.equal(fetchInit.phoneEphemeralPublicKey, phoneKey);
        return {
          protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
          sessionId,
          nonce: base64url(Buffer.alloc(12, 2)),
          ciphertext: base64url(Buffer.alloc(32, 2)),
          tag: base64url(Buffer.alloc(16, 2))
        };
      }
    });
    const lockFirst = await harness2.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKey)
    });
    assert.equal(lockFirst.statusCode, 200);
    const mismatch = await harness2.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody(phoneKeyB)
    });
    assert.ok(mismatch.statusCode === 400 || mismatch.statusCode === 410);

    // Completion before request rejected.
    const harness3 = createInjectableListenerHarness({ bindAddress: "192.168.10.22" });
    const adapter3 = createProductionRole1TransportListenerAdapter(harness3.options);
    await adapter3.preparePresentation({
      sessionId,
      issuedAtMs: harness3.clock.nowMs,
      expiresAt: harness3.clock.nowMs + SESSION_TTL_MS
    });
    await adapter3.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => {
        throw new Error("unused");
      }
    });
    const earlyComplete = await harness3.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
        sessionId,
        phoneEphemeralPublicKey: phoneKey,
        nonce: base64url(Buffer.alloc(12, 4)),
        ciphertext: base64url(Buffer.alloc(64, 5)),
        tag: base64url(Buffer.alloc(16, 6))
      })
    });
    assert.ok(earlyComplete.statusCode === 400 || earlyComplete.statusCode === 409
      || earlyComplete.statusCode === 410);

    adapter.cancel("test-cleanup");
    adapter2.cancel("test-cleanup");
    adapter3.cancel("test-cleanup");
  });

  it("red-gate p2: raw encrypted O.44 forwarded; host decrypts; ack verbatim; cancel isolation", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "10.20.30.40" });
    // 10.20.30.40 is public — use RFC1918.
    const harnessOk = createInjectableListenerHarness({ bindAddress: "10.20.30.40" });
    void harness;
    const bind = "10.40.0.15";
    const h = createInjectableListenerHarness({ bindAddress: bind });
    const adapter = createProductionRole1TransportListenerAdapter(h.options);
    const sessionId = `0x${"55".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: h.clock.nowMs,
      expiresAt: h.clock.nowMs + SESSION_TTL_MS
    });

    const phoneEcdh = crypto.createECDH("prime256v1");
    phoneEcdh.generateKeys();
    const phoneKey = base64url(phoneEcdh.getPublicKey());
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        nonce: base64url(Buffer.alloc(12, 9)),
        ciphertext: base64url(Buffer.alloc(40, 8)),
        tag: base64url(Buffer.alloc(16, 7))
      })
    });
    const fetched = await h.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        phoneEphemeralPublicKey: phoneKey,
        fetchChallenge: base64url(Buffer.alloc(32, 2))
      })
    });
    assert.equal(fetched.statusCode, 200);

    const encryptedResponse = {
      version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
      sessionId,
      phoneEphemeralPublicKey: phoneKey,
      nonce: base64url(Buffer.alloc(12, 1)),
      ciphertext: base64url(Buffer.alloc(80, 2)),
      tag: base64url(Buffer.alloc(16, 3))
    };
    // Validate outer schema shape using transport helper when possible.
    let schemaOk = true;
    try {
      transport.validateEncryptedNativeRecoveryResponse(encryptedResponse);
    } catch {
      schemaOk = false;
    }
    assert.equal(schemaOk, true);

    const waitPromise = adapter.waitForResponse({ sessionId, timeoutMs: 30_000 });
    const completePromise = h.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify(encryptedResponse),
      holdOpen: true
    });
    const received = await waitPromise;
    assert.deepEqual(received, encryptedResponse);
    assert.equal(adapter.getPhase(), "COMPLETION_PENDING");
    assert.equal(
      JSON.stringify(adapter.getPublicStatus?.() || {}),
      JSON.stringify(adapter.getPublicStatus?.() || {})
    );
    const statusSnapshot = typeof adapter.getPublicStatus === "function"
      ? adapter.getPublicStatus()
      : { phase: adapter.getPhase() };
    const statusText = JSON.stringify(statusSnapshot);
    assert.equal(statusText.includes("private"), false);
    assert.equal(statusText.includes("aes"), false);
    assert.equal(statusText.includes("sharedSecret"), false);

    const ack = {
      version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
      sessionId,
      phoneEphemeralPublicKey: null,
      nonce: base64url(Buffer.alloc(12, 4)),
      ciphertext: base64url(Buffer.alloc(32, 5)),
      tag: base64url(Buffer.alloc(16, 6))
    };
    await adapter.sendAcknowledgement(ack, { sessionId });
    const completeResult = await completePromise;
    assert.equal(completeResult.statusCode, 200);
    assert.deepEqual(JSON.parse(completeResult.body), ack);
    assert.equal(
      completeResult.headers["content-type"],
      "application/json; charset=utf-8"
    );
    assert.equal(completeResult.headers["cache-control"], "no-store");
    assert.equal(completeResult.headers.connection, "close");

    // Late callback after cancel/replace must not affect replacement adapter.
    const h2 = createInjectableListenerHarness({ bindAddress: "10.40.0.16" });
    const replacement = createProductionRole1TransportListenerAdapter(h2.options);
    const session2 = `0x${"66".repeat(32)}`;
    await replacement.preparePresentation({
      sessionId: session2,
      issuedAtMs: h2.clock.nowMs,
      expiresAt: h2.clock.nowMs + SESSION_TTL_MS
    });
    await replacement.startSession({
      sessionId: session2,
      request: { sessionId: session2 },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId: session2,
        nonce: base64url(Buffer.alloc(12, 1)),
        ciphertext: base64url(Buffer.alloc(16, 1)),
        tag: base64url(Buffer.alloc(16, 1))
      })
    });
    adapter.cancel("replaced");
    await expectCode(
      () => adapter.sendAcknowledgement(ack, { sessionId }),
      "ROLE1_TRANSPORT_CANCELLED"
    );
    assert.equal(replacement.getPhase(), "SESSION_ACTIVE");
    replacement.cancel("test-cleanup");
    void harnessOk;
  });

  it("red-gate p2: production adapter + host end-to-end bootstrapUri binds hash and endpoints", async () => {
    assert.equal(typeof createProductionRole1TransportListenerAdapter, "function");
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.1.50" });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });

    // Adapter that binds via production listener but completes via in-memory simulator
    // path for waitForResponse by bridging startSession public values.
    const production = createProductionRole1TransportListenerAdapter(harness.options);
    const memory = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const hybrid = {
      testOnly: false,
      preparePresentation: (...args) => production.preparePresentation(...args),
      async startSession(presentation) {
        await production.startSession(presentation);
        return memory.startSession(presentation);
      },
      waitForResponse: (...args) => memory.waitForResponse(...args),
      sendAcknowledgement: (...args) => memory.sendAcknowledgement(...args),
      cancel() {
        production.cancel("hybrid-cancel");
        memory.cancel();
      },
      getLastRequest: () => memory.getLastRequest(),
      getLastAcknowledgement: () => memory.getLastAcknowledgement()
    };
    const { host } = createHost(bundle, { role1TransportAdapter: hybrid });
    const status = await host.beginDrill({ bitmap: 3 });
    const presentation = status.role1Presentation;
    assert.ok(presentation.bootstrapUri);
    const ticket = bootstrap.decodePrb1Ticket(
      bootstrap.parsePrb1Uri(presentation.bootstrapUri)
    );
    assert.equal(
      bootstrap.buildRequestEndpointFromTicket(ticket),
      `http://192.168.1.50:${ticket.port}${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`
    );
    assert.equal(
      presentation.endpoint,
      `http://192.168.1.50:${ticket.port}${bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH}`
    );
    const requestHash = bootstrap.computePhilCoreRecoveryRequestHash(
      presentation.request
    );
    assert.equal(
      Buffer.from(ticket.requestHash).toString("hex"),
      Buffer.from(requestHash).toString("hex")
    );
    hybrid.cancel();
  });

  // ---------------------------------------------------------------------------
  // Package 2 Commit 3 — harden private-LAN listener lifecycle
  // ---------------------------------------------------------------------------

  it("red-gate p2c3: async listen error rejects preparePresentation promptly", async () => {
    const harness = createInjectableListenerHarness({
      bindAddress: "192.168.1.50",
      listenAsyncError: { code: "EADDRNOTAVAIL", message: "listen EADDRNOTAVAIL" }
    });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const uncaught = [];
    const onUncaught = (err) => {
      uncaught.push(err);
    };
    process.on("uncaughtException", onUncaught);
    let settled = false;
    const pending = adapter.preparePresentation({
      sessionId: `0x${"a1".repeat(32)}`,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    }).then(
      (value) => {
        settled = true;
        return value;
      },
      (error) => {
        settled = true;
        throw error;
      }
    );
    const raced = Promise.race([
      pending,
      new Promise((_, reject) => {
        setTimeout(
          () => reject(new RecoveryTransportError("ROLE1_LISTENER_BIND_HUNG")),
          200
        );
      })
    ]);
    await expectCode(() => raced, "ROLE1_LISTENER_BIND_FAILED");
    assert.equal(settled, true);
    assert.equal(uncaught.length, 0);
    process.off("uncaughtException", onUncaught);
    assert.equal(adapter.getPhase(), "CLOSED");
  });

  it("red-gate p2c3: HTTP server factory receives parser limits and socket idle timeout", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "10.0.0.9" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    await adapter.preparePresentation({
      sessionId: `0x${"a2".repeat(32)}`,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    assert.ok(harness.lastCreateServerOptions);
    assert.equal(harness.lastCreateServerOptions.maxHeaderSize, 4096);
    assert.equal(harness.lastCreateServerOptions.headersTimeout, 5000);
    assert.equal(harness.lastCreateServerOptions.requestTimeout, 5000);
    const socket = harness.emitConnection();
    assert.equal(socket.timeoutMs, 5000);
    assert.equal(typeof socket.timeoutHandler, "function");
    const gen = adapter.getPublicStatus().sessionId;
    assert.ok(gen);
    socket.timeoutHandler();
    assert.equal(socket.destroyed, true);
    const overflow = harness.emitClientError({
      code: "HPE_HEADER_OVERFLOW",
      message: "Header overflow SECRET_INTERNAL"
    });
    assert.equal(overflow.statusLine.includes("431"), true);
    assert.equal(overflow.written.includes("SECRET_INTERNAL"), false);
    const other = harness.emitClientError({
      code: "HPE_INVALID_HEADER_TOKEN",
      message: "bad token SECRET"
    });
    assert.equal(other.destroyed, true);
    assert.equal(other.written.includes("SECRET"), false);
    adapter.cancel("test-cleanup");
  });

  it("red-gate p2c3: exact OS bind result rejects mismatch and sets boundHost from OS", async () => {
    const mismatch = createInjectableListenerHarness({
      bindAddress: "192.168.1.50",
      addressOverride: { address: "10.0.0.1", port: 18765, family: "IPv4" }
    });
    const mismatchAdapter = createProductionRole1TransportListenerAdapter(
      mismatch.options
    );
    await expectCode(
      () => mismatchAdapter.preparePresentation({
        sessionId: `0x${"a3".repeat(32)}`,
        issuedAtMs: mismatch.clock.nowMs,
        expiresAt: mismatch.clock.nowMs + SESSION_TTL_MS
      }),
      "ROLE1_BIND_ADDRESS_INVALID"
    );

    const familyBad = createInjectableListenerHarness({
      bindAddress: "192.168.1.50",
      addressOverride: { address: "192.168.1.50", port: 18765, family: "IPv6" }
    });
    await expectCode(
      () => createProductionRole1TransportListenerAdapter(familyBad.options)
        .preparePresentation({
          sessionId: `0x${"a4".repeat(32)}`,
          issuedAtMs: familyBad.clock.nowMs,
          expiresAt: familyBad.clock.nowMs + SESSION_TTL_MS
        }),
      "ROLE1_BIND_ADDRESS_INVALID"
    );

    const anyAddr = createInjectableListenerHarness({
      bindAddress: "192.168.1.50",
      addressOverride: { address: "0.0.0.0", port: 18765, family: "IPv4" }
    });
    await expectCode(
      () => createProductionRole1TransportListenerAdapter(anyAddr.options)
        .preparePresentation({
          sessionId: `0x${"a5".repeat(32)}`,
          issuedAtMs: anyAddr.clock.nowMs,
          expiresAt: anyAddr.clock.nowMs + SESSION_TTL_MS
        }),
      "ROLE1_BIND_ADDRESS_INVALID"
    );

    const ok = createInjectableListenerHarness({
      bindAddress: "192.168.1.50",
      addressOverride: { address: "192.168.1.50", port: 19001, family: 4 }
    });
    const okAdapter = createProductionRole1TransportListenerAdapter(ok.options);
    const prepared = await okAdapter.preparePresentation({
      sessionId: `0x${"a6".repeat(32)}`,
      issuedAtMs: ok.clock.nowMs,
      expiresAt: ok.clock.nowMs + SESSION_TTL_MS
    });
    assert.equal(prepared.host, "192.168.1.50");
    assert.equal(prepared.port, 19001);
    assert.equal(okAdapter.getBoundAddress(), "192.168.1.50");
    okAdapter.cancel("test-cleanup");
  });

  it("red-gate p2c3: proactive TTL closes listener without traffic", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "10.1.2.3" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const issuedAtMs = harness.clock.nowMs;
    const expiresAt = issuedAtMs + 2_000;
    await adapter.preparePresentation({
      sessionId: `0x${"b1".repeat(32)}`,
      issuedAtMs,
      expiresAt
    });
    assert.equal(adapter.getPhase(), "BOUND_INACTIVE");
    const timersBefore = harness.timers.size;
    assert.equal(timersBefore >= 1, true, "expiry timer must arm after bind");
    harness.advanceTimersBy(2_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(adapter.getPhase(), "CLOSED");
    const status = adapter.getPublicStatus();
    assert.equal(status.host, null);
    assert.equal(status.port, null);
    assert.equal(status.sessionId, null);
  });

  it("red-gate p2c3: waitForResponse timeout terminates adapter and fail-closes host", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.55.1" });
    const production = createProductionRole1TransportListenerAdapter(harness.options);
    let releaseWait;
    const waitGate = new Promise((resolve) => {
      releaseWait = resolve;
    });
    // Use production adapter only through host for Role1 wait path.
    const { host, clock } = createHost(bundle, {
      role1TransportAdapter: production,
      phoneSimulator: async () => {
        throw new Error("unused-phone-sim");
      }
    });
    // beginDrill needs startSession + capability; production path works.
    // Override collect via short TTL by advancing after drill.
    const status = await host.beginDrill({ bitmap: 3 });
    assert.ok(status.role1Presentation);
    assert.equal(production.getPhase(), "SESSION_ACTIVE");

    const collectPromise = host.collectRole1();
    // Allow waiter to register, then advance past wait timeout.
    await new Promise((resolve) => setImmediate(resolve));
    const timeoutMs = Math.max(1, status.expiresAt - clock.nowMs);
    harness.advanceTimersBy(timeoutMs);
    await expectCode(() => collectPromise, "ROLE1_TRANSPORT_TIMEOUT");
    assert.equal(production.getPhase(), "CLOSED");
    assert.equal(host.status().state, STATES.SESSION_CANCELLED);
    assert.equal(host.status().role1Presentation, undefined);
    const pub = production.getPublicStatus();
    assert.equal(pub.host, null);
    assert.equal(pub.sessionId, null);
    assert.equal(pub.hasPhoneKeyLock, false);
    void releaseWait;
    void waitGate;
  });

  it("red-gate p2c3: graceful ACK waits for finish before destroy; stalled force-closed", async () => {
    const harness = createInjectableListenerHarness({
      bindAddress: "10.8.8.8",
      deferResponseFinish: true
    });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"c1".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    const phoneKey = (() => {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      return base64url(ecdh.getPublicKey());
    })();
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        nonce: base64url(Buffer.alloc(12, 1)),
        ciphertext: base64url(Buffer.alloc(32, 2)),
        tag: base64url(Buffer.alloc(16, 3))
      })
    });
    assert.equal((await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        phoneEphemeralPublicKey: phoneKey,
        fetchChallenge: base64url(Buffer.alloc(32, 4))
      })
    })).statusCode, 200);

    const encryptedResponse = {
      version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
      sessionId,
      phoneEphemeralPublicKey: phoneKey,
      nonce: base64url(Buffer.alloc(12, 5)),
      ciphertext: base64url(Buffer.alloc(80, 6)),
      tag: base64url(Buffer.alloc(16, 7))
    };
    const waitPromise = adapter.waitForResponse({ sessionId, timeoutMs: 30_000 });
    const completePromise = harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify(encryptedResponse),
      holdOpen: true
    });
    await waitPromise;
    const ack = {
      version: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
      sessionId,
      phoneEphemeralPublicKey: null,
      nonce: base64url(Buffer.alloc(12, 8)),
      ciphertext: base64url(Buffer.alloc(32, 9)),
      tag: base64url(Buffer.alloc(16, 10))
    };
    const ackPromise = adapter.sendAcknowledgement(ack, { sessionId });
    await new Promise((resolve) => setImmediate(resolve));
    const pendingRes = harness.lastResponse;
    assert.ok(pendingRes);
    assert.equal(pendingRes.bodyEmitted, true);
    assert.deepEqual(JSON.parse(pendingRes.body), ack);
    assert.equal(
      pendingRes.socketDestroyedBeforeFinish,
      false,
      "ACK socket must not be destroyed before body flush"
    );
    assert.equal(pendingRes.finished, false);
    harness.releaseDeferredFinish();
    await Promise.race([
      Promise.all([ackPromise, completePromise]),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("ACK_FINISH_HUNG")), 500);
      })
    ]);
    const completeResult = await completePromise;
    assert.equal(completeResult.statusCode, 200);
    assert.deepEqual(JSON.parse(completeResult.body), ack);

    // Stalled finish force-closed by fallback timer.
    const harness2 = createInjectableListenerHarness({
      bindAddress: "10.8.8.9",
      deferResponseFinish: true
    });
    const adapter2 = createProductionRole1TransportListenerAdapter(harness2.options);
    const session2 = `0x${"c2".repeat(32)}`;
    await adapter2.preparePresentation({
      sessionId: session2,
      issuedAtMs: harness2.clock.nowMs,
      expiresAt: harness2.clock.nowMs + SESSION_TTL_MS
    });
    await adapter2.startSession({
      sessionId: session2,
      request: { sessionId: session2 },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId: session2,
        nonce: base64url(Buffer.alloc(12, 1)),
        ciphertext: base64url(Buffer.alloc(16, 1)),
        tag: base64url(Buffer.alloc(16, 1))
      })
    });
    assert.equal((await harness2.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId: session2,
        phoneEphemeralPublicKey: phoneKey,
        fetchChallenge: base64url(Buffer.alloc(32, 4))
      })
    })).statusCode, 200);
    const wait2 = adapter2.waitForResponse({ sessionId: session2, timeoutMs: 30_000 });
    const hold2 = harness2.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({ ...encryptedResponse, sessionId: session2 }),
      holdOpen: true
    });
    await wait2;
    const ack2Promise = adapter2.sendAcknowledgement({
      ...ack,
      sessionId: session2
    }, { sessionId: session2 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(harness2.lastResponse.finished, false);
    harness2.advanceTimersBy(5000);
    await Promise.race([
      Promise.all([ack2Promise, hold2]),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("ACK_STALL_FALLBACK_MISSING")), 500);
      })
    ]);
    assert.equal(harness2.lastResponse.forceDestroyedAfterStall, true);
    assert.equal(adapter2.getPhase(), "CLOSED");
  });

  it("red-gate p2c3: single Role1 collection in flight rejects duplicate cleanly", async () => {
    let releasePhone;
    const phoneGate = new Promise((resolve) => {
      releasePhone = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: async (input) => {
        await phoneGate;
        return phoneSimulator(input);
      }
    });
    const { host } = createHost(bundle, { role1TransportAdapter: base });
    await host.beginDrill({ bitmap: 3 });
    const first = host.collectRole1();
    await new Promise((resolve) => setImmediate(resolve));
    const second = host.collectRole1();
    await expectCode(
      () => Promise.race([
        second,
        new Promise((_, reject) => {
          setTimeout(
            () => reject(new RecoveryTransportError("ROLE1_COLLECTION_NOT_GUARDED")),
            100
          );
        })
      ]),
      "ROLE1_COLLECTION_IN_FLIGHT"
    );
    assert.equal(host.status().state, STATES.AWAITING_FIRST_FACTOR);
    assert.ok(host.status().role1Presentation);
    releasePhone();
    await first;
    assert.equal(host.status().collectedRoles.includes(1), true);
    assert.notEqual(host.status().state, STATES.SESSION_CANCELLED);
    await expectCode(() => host.collectRole1(), "ROLE_DUPLICATE_OR_REPLAY");
  });

  it("red-gate p2c4: session-owned Role1 collect guard survives replacement cleanup", async () => {
    const waitReleases = [];
    let waitOrdinal = 0;
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const adapter = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: async (input) => {
        const ordinal = waitOrdinal;
        waitOrdinal += 1;
        await new Promise((resolve) => {
          waitReleases[ordinal] = resolve;
        });
        return phoneSimulator(input);
      }
    });
    const { host } = createHost(bundle, { role1TransportAdapter: adapter });

    const sessionA = await host.beginDrill({ bitmap: 3 });
    const sessionAId = sessionA.sessionId;
    const collectA = host.collectRole1();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(typeof waitReleases[0], "function", "session A wait suspended");

    const sessionB = await host.beginDrill({ bitmap: 3 });
    assert.notEqual(sessionB.sessionId, sessionAId);
    const sessionBId = sessionB.sessionId;
    const collectB = host.collectRole1();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(typeof waitReleases[1], "function", "session B wait suspended");
    assert.equal(host.status().sessionId, sessionBId);
    assert.equal(host.status().state, STATES.AWAITING_FIRST_FACTOR);

    // Release Session A's stale wait so its rejection `finally` runs while B is in flight.
    waitReleases[0]();
    await expectCode(() => collectA, "SESSION_REPLACED_OR_CANCELLED");
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(host.status().sessionId, sessionBId);
    assert.equal(host.status().state, STATES.AWAITING_FIRST_FACTOR);
    assert.ok(host.status().role1Presentation);

    const duplicateB = host.collectRole1();
    await expectCode(
      () => Promise.race([
        duplicateB,
        new Promise((_, reject) => {
          setTimeout(
            () => reject(
              new RecoveryTransportError("ROLE1_COLLECTION_GUARD_CLEARED_BY_STALE_SESSION")
            ),
            100
          );
        })
      ]),
      "ROLE1_COLLECTION_IN_FLIGHT"
    );

    assert.equal(host.status().sessionId, sessionBId);
    assert.equal(host.status().state, STATES.AWAITING_FIRST_FACTOR);
    assert.ok(host.status().role1Presentation);
    assert.equal(host.status().collectedRoles.includes(1), false);

    waitReleases[1]();
    await collectB;
    assert.equal(host.status().sessionId, sessionBId);
    assert.equal(host.status().collectedRoles.includes(1), true);
    assert.notEqual(host.status().state, STATES.SESSION_CANCELLED);
    await expectCode(() => host.collectRole1(), "ROLE_DUPLICATE_OR_REPLAY");
  });

  it("red-gate p2c3: fatal UTF-8 decode and exact route matching", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.7.7" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"d1".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => {
        throw new Error("unused");
      }
    });
    const invalidUtf8 = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: Buffer.from([0x7b, 0xff, 0x7d])
    });
    assert.equal(invalidUtf8.statusCode, 400);
    assert.equal(invalidUtf8.body.includes("ff"), false);

    for (const url of [
      `${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}?x=1`,
      `${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}#frag`,
      `${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}/`,
      `http://192.168.7.7${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`,
      `${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH} `
    ]) {
      const rejected = await harness.inject({
        method: "POST",
        url,
        headers: { "content-type": "application/json; charset=utf-8" },
        body: "{}"
      });
      assert.equal(rejected.statusCode, 404, url);
    }
    adapter.cancel("test-cleanup");
  });

  it("red-gate p2c3: request hash uses exact canonical bytes not re-serialized object", async () => {
    const source = fs.readFileSync(
      path.join(__dirname, "../src/main/recovery-transport-host.cjs"),
      "utf8"
    );
    assert.match(
      source,
      /computePhilCoreRecoveryRequestHash\(\s*canonicalRequestBytes\s*\)/
    );
    assert.equal(
      /computePhilCoreRecoveryRequestHash\(\s*approvalRequest\s*\)/.test(source),
      false
    );
    const { host } = createHost(bundle);
    const status = await host.beginDrill({ bitmap: 3 });
    const expected = bootstrap.serializeCanonicalRecoveryRequest(
      status.role1Presentation.request
    );
    const hashFromBytes = bootstrap.computePhilCoreRecoveryRequestHash(expected);
    const ticket = bootstrap.decodePrb1Ticket(
      bootstrap.parsePrb1Uri(status.role1Presentation.bootstrapUri)
    );
    assert.equal(
      Buffer.from(ticket.requestHash).toString("hex"),
      Buffer.from(hashFromBytes).toString("hex")
    );
  });

  it("red-gate p2c3: delivery nonce reuse fails closed", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "192.168.9.9" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"e1".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    const phoneKey = (() => {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      return base64url(ecdh.getPublicKey());
    })();
    const reusedNonce = base64url(Buffer.alloc(12, 42));
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        nonce: reusedNonce,
        ciphertext: base64url(Buffer.alloc(32, 8)),
        tag: base64url(Buffer.alloc(16, 9))
      })
    });
    function fetchBody() {
      return JSON.stringify({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        phoneEphemeralPublicKey: phoneKey,
        fetchChallenge: base64url(crypto.randomBytes(32))
      });
    }
    const first = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody()
    });
    assert.equal(first.statusCode, 200);
    const second = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: { "content-type": "application/json; charset=utf-8" },
      body: fetchBody()
    });
    assert.ok(second.statusCode === 410 || second.destroyed === true);
    assert.equal(adapter.getPhase(), "CLOSED");
  });

  it("red-gate p2c3: public presentation publishes only after startSession succeeds", async () => {
    let releaseStart;
    const startGate = new Promise((resolve) => {
      releaseStart = resolve;
    });
    const phoneSimulator = createPhoneSimulator({
      privateScalar: bundle.native.privateScalar,
      factorCommitment: bundle.native.factorCommitment,
      credentialIdentifierCommitment:
        bundle.native.descriptor.credentialIdentifierCommitment,
      credentialGeneration: Number(bundle.native.descriptor.credentialGeneration)
    });
    const base = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    const gated = {
      testOnly: true,
      preparePresentation: (...args) => base.preparePresentation(...args),
      async startSession(...args) {
        await startGate;
        return base.startSession(...args);
      },
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      cancel: () => base.cancel(),
      getLastRequest: () => base.getLastRequest(),
      getLastAcknowledgement: () => base.getLastAcknowledgement(),
      getPhase: () => base.getPhase?.() || "SESSION_ACTIVE"
    };
    const { host } = createHost(bundle, { role1TransportAdapter: gated });
    const pending = host.beginDrill({ bitmap: 3 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(host.status().role1Presentation, undefined);
    assert.equal(host.status().bootstrapUri, undefined);
    releaseStart();
    const ready = await pending;
    assert.equal(typeof ready.role1Presentation.bootstrapUri, "string");

    let releaseStart2;
    const startGate2 = new Promise((resolve) => {
      releaseStart2 = resolve;
    });
    const gated2 = {
      testOnly: true,
      preparePresentation: (...args) => base.preparePresentation(...args),
      async startSession(...args) {
        await startGate2;
        return base.startSession(...args);
      },
      waitForResponse: (...args) => base.waitForResponse(...args),
      sendAcknowledgement: (...args) => base.sendAcknowledgement(...args),
      cancel: () => base.cancel()
    };
    // Fresh in-memory adapter for cancel-during-pending.
    const base3 = createInMemoryRole1TransportAdapter({
      testOnly: true,
      simulatePhoneResponse: phoneSimulator
    });
    let releaseStart3;
    const startGate3 = new Promise((resolve) => {
      releaseStart3 = resolve;
    });
    const gated3 = {
      testOnly: true,
      preparePresentation: (...args) => base3.preparePresentation(...args),
      async startSession(...args) {
        await startGate3;
        return base3.startSession(...args);
      },
      waitForResponse: (...args) => base3.waitForResponse(...args),
      sendAcknowledgement: (...args) => base3.sendAcknowledgement(...args),
      cancel: () => base3.cancel()
    };
    const cancelledHost = createHost(bundle, { role1TransportAdapter: gated3 });
    const pendingCancel = cancelledHost.host.beginDrill({ bitmap: 3 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(cancelledHost.host.status().role1Presentation, undefined);
    cancelledHost.host.cancel();
    releaseStart3();
    await expectCode(() => pendingCancel, "SESSION_REPLACED_OR_CANCELLED");
    assert.equal(cancelledHost.host.status().role1Presentation, undefined);
    void releaseStart2;
    void startGate2;
    void gated2;
  });

  it("red-gate p2c3: terminal cleanup clears public listener metadata", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "10.10.10.10" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"f1".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => ({
        protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
        sessionId,
        nonce: base64url(Buffer.alloc(12, 1)),
        ciphertext: base64url(Buffer.alloc(16, 1)),
        tag: base64url(Buffer.alloc(16, 1))
      })
    });
    assert.equal(adapter.getPublicStatus().host, "10.10.10.10");
    adapter.cancel("test-cleanup");
    const status = adapter.getPublicStatus();
    assert.equal(status.phase, "CLOSED");
    assert.equal(status.host, null);
    assert.equal(status.port, null);
    assert.equal(status.sessionId, null);
    assert.equal(status.hasPhoneKeyLock, false);
    assert.equal(status.fetchAttemptsReserved, 0);
    assert.equal(status.successfulDeliveries, 0);
    assert.equal(status.completionConsumed, false);
    assert.equal(harness.timers.size, 0);
  });

  it("red-gate p2c3: framing rejects oversized Content-Length and CL mismatch", async () => {
    const harness = createInjectableListenerHarness({ bindAddress: "172.16.0.9" });
    const adapter = createProductionRole1TransportListenerAdapter(harness.options);
    const sessionId = `0x${"f2".repeat(32)}`;
    await adapter.preparePresentation({
      sessionId,
      issuedAtMs: harness.clock.nowMs,
      expiresAt: harness.clock.nowMs + SESSION_TTL_MS
    });
    await adapter.startSession({
      sessionId,
      request: { sessionId },
      requestDeliveryCapability: async () => {
        throw new Error("unused");
      }
    });
    const oversizedCl = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "content-length": "2048"
      },
      body: "{}",
      skipAutoContentLength: true
    });
    assert.equal(oversizedCl.statusCode, 413);

    const mismatch = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "content-length": "2"
      },
      body: "{\"x\":1}",
      skipAutoContentLength: true
    });
    assert.equal(mismatch.statusCode, 400);

    const teAndCl = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "transfer-encoding": "chunked",
        "content-length": "2"
      },
      body: "{}"
    });
    assert.ok(teAndCl.statusCode === 400 || teAndCl.destroyed === true);

    const chunkedOk = await harness.inject({
      method: "POST",
      url: bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "transfer-encoding": "chunked"
      },
      body: "{}",
      skipAutoContentLength: true
    });
    // Invalid fetch body -> 400, but framing accepted (not 413).
    assert.equal(chunkedOk.statusCode, 400);
    adapter.cancel("test-cleanup");
  });
});

function createInjectableListenerHarness({
  bindAddress = "192.168.1.50",
  port = 18765,
  listenAsyncError = null,
  addressOverride = null,
  deferResponseFinish = false
} = {}) {
  const { EventEmitter } = require("node:events");
  const clock = { nowMs: 1_700_000_000_000 };
  const timers = new Map();
  let timerSeq = 1;
  let activeServer = null;
  let lastCreateServerOptions = null;
  let lastResponse = null;
  let deferredFinishRelease = null;

  function advanceTimersBy(ms) {
    clock.nowMs += Number(ms || 0);
    for (const [id, entry] of [...timers.entries()]) {
      if (entry.due <= clock.nowMs) {
        timers.delete(id);
        entry.fn();
      }
    }
  }

  function createHttpServer(serverOptions = {}) {
    lastCreateServerOptions = { ...serverOptions };
    const server = new EventEmitter();
    server.listening = false;
    server._host = null;
    server._port = null;
    server._requestHandlers = [];
    server._connectionHandlers = [];
    server._clientErrorHandlers = [];
    const originalOn = server.on.bind(server);
    server.on = (event, handler) => {
      if (event === "request") server._requestHandlers.push(handler);
      if (event === "connection") server._connectionHandlers.push(handler);
      if (event === "clientError") server._clientErrorHandlers.push(handler);
      return originalOn(event, handler);
    };
    server.listen = (listenPort, host, cb) => {
      server._host = host;
      server._port = listenPort === 0 ? port : listenPort;
      if (listenAsyncError) {
        queueMicrotask(() => {
          const err = new Error(listenAsyncError.message || "listen failed");
          err.code = listenAsyncError.code || "EADDRNOTAVAIL";
          server.emit("error", err);
        });
        return server;
      }
      server.listening = true;
      queueMicrotask(() => {
        if (typeof cb === "function") cb();
      });
      return server;
    };
    server.address = () => {
      if (!server.listening) return null;
      if (addressOverride) return { ...addressOverride };
      return { address: server._host, port: server._port, family: "IPv4" };
    };
    server.close = (cb) => {
      server.listening = false;
      queueMicrotask(() => {
        if (typeof cb === "function") cb();
      });
    };
    activeServer = server;
    return server;
  }

  function buildReqRes({
    method,
    url,
    headers,
    body,
    holdOpen = false,
    withholdBody = false,
    skipAutoContentLength = false,
    deferFinish: optionsDeferFinish = false
  }) {
    const req = new EventEmitter();
    req.method = method;
    req.url = url;
    const normalized = {};
    for (const [key, value] of Object.entries(headers || {})) {
      normalized[String(key).toLowerCase()] = String(value);
    }
    if (
      !skipAutoContentLength
      && body !== undefined
      && body !== null
      && !Object.prototype.hasOwnProperty.call(normalized, "content-length")
      && !Object.prototype.hasOwnProperty.call(normalized, "transfer-encoding")
    ) {
      normalized["content-length"] = String(Buffer.byteLength(
        Buffer.isBuffer(body) ? body : Buffer.from(body)
      ));
    }
    req.headers = normalized;
    const raw = [];
    for (const [key, value] of Object.entries(headers || {})) {
      raw.push(String(key), String(value));
    }
    if (
      !skipAutoContentLength
      && Object.prototype.hasOwnProperty.call(normalized, "content-length")
      && !(headers && Object.prototype.hasOwnProperty.call(
        Object.fromEntries(
          Object.entries(headers || {}).map(([k, v]) => [String(k).toLowerCase(), v])
        ),
        "content-length"
      ))
    ) {
      raw.push("Content-Length", normalized["content-length"]);
    }
    req.rawHeaders = raw;
    const socketState = {
      destroyed: false,
      timeoutMs: null,
      timeoutHandler: null,
      setTimeout(ms, handler) {
        this.timeoutMs = ms;
        if (typeof handler === "function") this.timeoutHandler = handler;
      },
      destroy() {
        this.destroyed = true;
        req.emit("close");
      }
    };
    req.socket = socketState;

    const resResult = {
      statusCode: 0,
      headers: {},
      body: "",
      destroyed: false,
      finished: false,
      bodyEmitted: false,
      socketDestroyedBeforeFinish: false,
      forceDestroyedAfterStall: false
    };

    const res = new EventEmitter();
    res.headersSent = false;
    res.writableEnded = false;
    res.statusCode = 200;
    res.socket = socketState;
    res.setHeader = (name, value) => {
      resResult.headers[String(name).toLowerCase()] = String(value);
    };
    res.getHeader = (name) => resResult.headers[String(name).toLowerCase()];
    res.writeHead = (code, maybeHeaders) => {
      res.statusCode = code;
      resResult.statusCode = code;
      res.headersSent = true;
      if (maybeHeaders && typeof maybeHeaders === "object") {
        for (const [key, value] of Object.entries(maybeHeaders)) {
          res.setHeader(key, value);
        }
      }
    };
    res.write = (chunk) => {
      resResult.body += Buffer.from(chunk).toString("utf8");
      resResult.bodyEmitted = true;
      return true;
    };
    const shouldDeferFinish = Boolean(
      optionsDeferFinish || (deferResponseFinish && holdOpen)
    );
    res.end = (chunk) => {
      if (chunk !== undefined) res.write(chunk);
      resResult.statusCode = res.statusCode;
      resResult.bodyEmitted = true;
      res.writableEnded = true;
      if (shouldDeferFinish) {
        deferredFinishRelease = () => {
          resResult.finished = true;
          res.finished = true;
          res.writableFinished = true;
          res.emit("finish");
          res.emit("close");
          for (const waiter of res._finishWaiters.splice(0)) waiter();
        };
      } else {
        resResult.finished = true;
        res.finished = true;
        res.writableFinished = true;
        res.emit("finish");
        res.emit("close");
        for (const waiter of res._finishWaiters.splice(0)) waiter();
      }
    };
    res.destroy = () => {
      if (!resResult.finished) {
        resResult.socketDestroyedBeforeFinish = true;
      }
      if (shouldDeferFinish && !resResult.finished) {
        resResult.forceDestroyedAfterStall = true;
      }
      resResult.destroyed = true;
      socketState.destroy();
      for (const waiter of res._finishWaiters.splice(0)) waiter();
    };
    res._finishWaiters = [];
    res.whenFinished = () => {
      if (resResult.finished || resResult.destroyed) {
        return Promise.resolve(resResult);
      }
      return new Promise((resolve) => {
        res._finishWaiters.push(() => resolve(resResult));
      });
    };

    function emitBody() {
      if (withholdBody) return;
      if (body !== undefined && body !== null) {
        req.emit("data", Buffer.isBuffer(body) ? body : Buffer.from(body));
      }
      req.emit("end");
    }

    lastResponse = resResult;
    resResult._res = res;
    resResult._req = req;
    return { req, res, resResult, emitBody, socketState };
  }

  async function inject(options) {
    if (!activeServer || activeServer._requestHandlers.length === 0) {
      throw new Error("listener server not ready");
    }
    const { req, res, resResult, emitBody } = buildReqRes(options);
    for (const handler of activeServer._requestHandlers) {
      handler(req, res);
    }
    await new Promise((resolve) => setImmediate(resolve));
    emitBody();
    if (options.holdOpen) {
      const finished = res.whenFinished();
      return Object.assign(finished, {
        then: finished.then.bind(finished),
        statusCodePending: true
      });
    }
    await res.whenFinished();
    if (req.socket.destroyed && !resResult.finished) {
      resResult.destroyed = true;
    }
    return resResult;
  }

  async function injectIdleTimeout(options) {
    if (!activeServer || activeServer._requestHandlers.length === 0) {
      throw new Error("listener server not ready");
    }
    const { req, res, resResult } = buildReqRes({
      ...options,
      withholdBody: true,
      body: undefined
    });
    for (const handler of activeServer._requestHandlers) {
      handler(req, res);
    }
    await new Promise((resolve) => setImmediate(resolve));
    advanceTimersBy(options.advanceMs || 5000);
    await new Promise((resolve) => setImmediate(resolve));
    resResult.destroyed = req.socket.destroyed || resResult.destroyed;
    return resResult;
  }

  function emitConnection() {
    const socket = {
      destroyed: false,
      timeoutMs: null,
      timeoutHandler: null,
      setTimeout(ms, handler) {
        this.timeoutMs = ms;
        if (typeof handler === "function") {
          this.timeoutHandler = handler;
        }
        return this;
      },
      on(event, handler) {
        if (event === "timeout" && typeof handler === "function") {
          this.timeoutHandler = handler;
        }
        return this;
      },
      destroy() {
        this.destroyed = true;
      }
    };
    for (const handler of activeServer?._connectionHandlers || []) {
      handler(socket);
    }
    return socket;
  }

  function emitClientError(error) {
    const state = {
      destroyed: false,
      writable: true,
      written: "",
      statusLine: "",
      end(data) {
        const text = data == null ? "" : String(data);
        this.written += text;
        this.statusLine = text.split("\r\n")[0] || "";
      },
      destroy() {
        this.destroyed = true;
        this.writable = false;
      }
    };
    for (const handler of activeServer?._clientErrorHandlers || []) {
      handler(error, state);
    }
    return state;
  }

  return {
    clock,
    timers,
    get lastCreateServerOptions() {
      return lastCreateServerOptions;
    },
    get lastResponse() {
      return lastResponse;
    },
    options: {
      bindAddressProvider: () => bindAddress,
      createHttpServer,
      now: () => clock.nowMs,
      setTimeout: (fn, ms) => {
        const id = timerSeq++;
        timers.set(id, { fn, due: clock.nowMs + Number(ms || 0) });
        return id;
      },
      clearTimeout: (id) => {
        timers.delete(id);
      }
    },
    inject,
    injectIdleTimeout,
    advanceTimersBy,
    emitConnection,
    emitClientError,
    releaseDeferredFinish() {
      if (typeof deferredFinishRelease === "function") {
        const release = deferredFinishRelease;
        deferredFinishRelease = null;
        release();
      }
    },
    getServer: () => activeServer
  };
}

function assertPublicFieldEquivalent(publicValue, internalValue, label) {
  if (typeof internalValue === "bigint") {
    assert.equal(typeof publicValue, "string", label);
    assert.equal(publicValue, internalValue.toString(10), label);
    return;
  }
  if (
    internalValue !== null
    && typeof internalValue === "object"
    && !Buffer.isBuffer(internalValue)
    && !ArrayBuffer.isView(internalValue)
  ) {
    assert.equal(typeof publicValue, "object", label);
    assert.ok(publicValue !== null, label);
    if (Array.isArray(internalValue)) {
      assert.equal(Array.isArray(publicValue), true, label);
      assert.equal(publicValue.length, internalValue.length, label);
      for (let i = 0; i < internalValue.length; i += 1) {
        assertPublicFieldEquivalent(
          publicValue[i],
          internalValue[i],
          `${label}[${i}]`
        );
      }
      return;
    }
    const internalKeys = Object.keys(internalValue);
    const publicKeys = Object.keys(publicValue);
    assert.deepEqual(publicKeys.sort(), internalKeys.slice().sort(), label);
    for (const key of internalKeys) {
      assertPublicFieldEquivalent(
        publicValue[key],
        internalValue[key],
        `${label}.${key}`
      );
    }
    return;
  }
  assert.deepEqual(publicValue, internalValue, label);
}

function assertNoBigInt(value, path) {
  assert.notEqual(typeof value, "bigint", path);
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoBigInt(entry, `${path}[${index}]`));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    assertNoBigInt(child, `${path}.${key}`);
  }
}

function assertCanonicalPublicInteger(value, label) {
  if (typeof value === "string") {
    assert.match(value, /^(0|[1-9]\d*)$/u, `${label} noncanonical`);
    assert.equal(String(BigInt(value)), value, `${label} precision`);
    return;
  }
  if (typeof value === "number") {
    assert.equal(Number.isInteger(value), true, `${label} noninteger`);
    assert.equal(Number.isSafeInteger(value), true, `${label} unsafe`);
    assert.equal(String(value), String(BigInt(value)), `${label} precision`);
    assert.match(String(value), /^(0|[1-9]\d*)$/u, `${label} noncanonical`);
    return;
  }
  assert.fail(`${label} must be canonical string or safe integer, got ${typeof value}`);
}

function bitmapIncludes(bitmap, role) {
  return transport.rolesForRecoveryFactorBitmap(bitmap).includes(role);
}

async function runNodeSuite() {
  try {
    if (typeof __nodeSuite.before === "function") {
      await __nodeSuite.before();
    }
    for (const entry of __nodeSuite.tests) {
      await entry.fn();
      console.log(`ok - ${entry.name}`);
    }
  } catch (error) {
    console.error("not ok - desktop recovery transport host");
    console.error(error);
    process.exitCode = 1;
  }
}

if (__usedNodeShim) {
  runNodeSuite();
}
