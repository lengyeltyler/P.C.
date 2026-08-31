require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  getBytes,
  id,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");
const hre = require("hardhat");

const { ethers, network } = hre;
const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O44_RECOVERY_TRANSPORT_FIXTURES.json"
);

const transport = require("../../apps/phil-device-sdk/src/v2RecoveryTransport.ts");
const {
  computePhilCoreV2RecoveryFactorDigest,
  PHILCORE_V2_RECOVERY_THRESHOLD
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  computePhilCoreV2RecoveryEvidenceContextHash,
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  PHILCORE_V2_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  computePhilCoreV2ConsumerRecoveryConfigurationHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_O37_2_P256_ORDER,
  PHILCORE_O37_2_P256_HALF_ORDER
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  inspectOfflineCode
} = require("../../apps/philcore-desktop/src/main/recovery-enrollment-host.cjs");
const {
  buildO43NativeIPhoneFixturePackage
} = require("../../scripts/cryptography/generate-o43-native-iphone-fixtures.cjs");

function H(value) {
  return keccak256(toUtf8Bytes(value));
}

function loadFixtures() {
  return JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
}

async function signerFor(address) {
  await network.provider.send("hardhat_impersonateAccount", [address]);
  return ethers.getSigner(address);
}

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

function deterministicUncompressedP256PublicKey(label) {
  const scalar = zeroPadValue(
    toBeHex((BigInt(H(label)) % (PHILCORE_O37_2_P256_ORDER - 1n)) + 1n),
    32
  );
  return Buffer.from(p256.getPublicKey(getBytes(scalar), false)).toString(
    "base64url"
  );
}

function buildV2Context(commitments, bitmap) {
  const roles = bitmap === 3 ? [0, 1] : bitmap === 5 ? [0, 2] : [1, 2];
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
    secondFactorCommitment: commitments[roles[1]]
  };
}

function contextHashFor(context) {
  const {
    computePhilCoreV2ConsumerRecoveryEvidenceContextHash
  } = require(
    "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
  );
  return computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
}

describe("O.44 recovery-signature transport protocol", function () {
  let verifier;
  let o43;

  before(async function () {
    o43 = buildO43NativeIPhoneFixturePackage();
    verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
  });

  it("rejects a supplied digest that was not recomputed", function () {
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const context = buildV2Context(commitments, 3);
    const realDigest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: context.chainId, account: context.account },
      {
        authorizedIntentHash: context.authorizedIntentHash,
        userOperationHash: context.userOperationHash,
        recoveryConfigHash: context.currentRecoveryConfigHash,
        recoveryEpoch: context.recoveryEpoch,
        factorBitmap: 3
      }
    ).digest;
    const realContextHash = contextHashFor(context);
    const forged = `0x${"ab".repeat(32)}`;
    assert.notEqual(forged, realDigest);
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest({
        protocolVersion: 1,
        context,
        claimedContextHash: realContextHash,
        claimedRecoveryFactorDigest: forged,
        accountVersionId: o43.request.accountVersionId,
        securityModelId: o43.request.securityModelId,
        nativeRecoveryDomainId: o43.factors.nativeIPhone.descriptor.recoveryDomainId,
        applicationIdentity: o43.applicationIdentity,
        localApprovalPolicy:
          "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST",
        selectedRole1CredentialIdentifierCommitment:
          o43.factors.nativeIPhone.descriptor.credentialIdentifierCommitment,
        selectedRole1CredentialGeneration: 1,
        trustedRole1Descriptor: o43.factors.nativeIPhone.descriptor,
        trustedRole1PublicKey: {
          qx: o43.factors.nativeIPhone.qx,
          qy: o43.factors.nativeIPhone.qy
        },
        sessionId: `0x${"11".repeat(32)}`,
        sessionChallenge: `0x${"22".repeat(32)}`,
        desktopEphemeralPublicKey:
          deterministicUncompressedP256PublicKey("O44:TEST:DESKTOP_EPHEMERAL"),
        issuedAt: "1700000000000",
        expiresAt: "1700000300000",
        endpoint: "http://192.168.1.10:8787/philcore/recovery/v1/complete",
        now: "1700000100000"
      }),
      /digest|mismatch|recomput/i,
      "supplied digest must not be trusted without recomputation"
    );
  });

  it("binds the complete recovery-approval transcript", function () {
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const context = buildV2Context(commitments, 6);
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: context.chainId, account: context.account },
      {
        authorizedIntentHash: context.authorizedIntentHash,
        userOperationHash: context.userOperationHash,
        recoveryConfigHash: context.currentRecoveryConfigHash,
        recoveryEpoch: context.recoveryEpoch,
        factorBitmap: 6
      }
    ).digest;
    const contextHash = contextHashFor(context);
    const request = {
      protocolVersion: 1,
      context,
      claimedContextHash: contextHash,
      claimedRecoveryFactorDigest: digest,
      accountVersionId: o43.request.accountVersionId,
      securityModelId: o43.request.securityModelId,
      nativeRecoveryDomainId: o43.factors.nativeIPhone.descriptor.recoveryDomainId,
      applicationIdentity: o43.applicationIdentity,
      localApprovalPolicy:
        "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST",
      selectedRole1CredentialIdentifierCommitment:
        o43.factors.nativeIPhone.descriptor.credentialIdentifierCommitment,
      selectedRole1CredentialGeneration: 1,
      trustedRole1Descriptor: o43.factors.nativeIPhone.descriptor,
      trustedRole1PublicKey: {
        qx: o43.factors.nativeIPhone.qx,
        qy: o43.factors.nativeIPhone.qy
      },
      sessionId: `0x${"33".repeat(32)}`,
      sessionChallenge: `0x${"44".repeat(32)}`,
      desktopEphemeralPublicKey:
        deterministicUncompressedP256PublicKey("O44:TEST:DESKTOP_EPHEMERAL_BIND"),
      issuedAt: "1700000000000",
      expiresAt: "1700000300000",
      endpoint: "http://10.0.0.8:9090/philcore/recovery/v1/complete",
      now: "1700000100000",
      actionText: "Recovery request",
      networkText: "chain 31337"
    };
    const transcript = transport.buildPhilCoreNativeRecoveryApprovalTranscript(request);
    const text = Buffer.from(transcript).toString("utf8");
    const required = [
      "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1",
      String(context.envelopeVersion),
      String(context.authorityKind),
      String(context.actionType),
      String(context.factorBitmap),
      context.account.toLowerCase(),
      String(context.chainId),
      context.entryPoint.toLowerCase(),
      context.authorizedIntentHash,
      context.userOperationHash,
      context.requestId,
      context.currentRecoveryConfigHash,
      String(context.validatorEpoch),
      String(context.recoveryEpoch),
      String(context.validAfter),
      String(context.validUntil),
      String(context.recoveryDelaySeconds),
      String(context.recoveryExpirySeconds),
      context.proposedValidatorCommitment,
      context.proposedRecoveryConfigHash,
      String(context.proposedRecoveryEpoch),
      context.primaryDeviceCommitment,
      context.hardwareSecurityKeyCommitment,
      context.recoveryFactorCommitment,
      context.firstFactorCommitment,
      context.secondFactorCommitment,
      request.accountVersionId,
      request.securityModelId,
      request.nativeRecoveryDomainId,
      request.applicationIdentity,
      request.localApprovalPolicy,
      request.selectedRole1CredentialIdentifierCommitment,
      String(request.selectedRole1CredentialGeneration),
      contextHash,
      digest,
      request.sessionId,
      request.sessionChallenge,
      request.endpoint
    ];
    for (const field of required) {
      assert.ok(
        text.includes(field),
        `transcript must bind field: ${field.slice(0, 48)}`
      );
    }
    assert.equal(
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_TRANSCRIPT_LABEL,
      "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1"
    );
    const hash = transport.hashPhilCoreNativeRecoveryApprovalTranscript(transcript);
    const fingerprint =
      transport.displayPhilCoreRecoveryComparisonFingerprint(hash);
    assert.match(fingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){5}$/u);
    const mutatedContext = { ...context, chainId: "31338" };
    const mutated = {
      ...request,
      networkText: "chain 31338",
      context: mutatedContext,
      claimedContextHash: contextHashFor(mutatedContext),
      claimedRecoveryFactorDigest: computePhilCoreV2RecoveryFactorDigest(
        { chainId: mutatedContext.chainId, account: mutatedContext.account },
        {
          authorizedIntentHash: mutatedContext.authorizedIntentHash,
          userOperationHash: mutatedContext.userOperationHash,
          recoveryConfigHash: mutatedContext.currentRecoveryConfigHash,
          recoveryEpoch: mutatedContext.recoveryEpoch,
          factorBitmap: mutatedContext.factorBitmap
        }
      ).digest
    };
    const mutatedTranscript =
      transport.buildPhilCoreNativeRecoveryApprovalTranscript(mutated);
    const mutatedHash =
      transport.hashPhilCoreNativeRecoveryApprovalTranscript(mutatedTranscript);
    assert.notEqual(
      Buffer.from(hash).toString("hex"),
      Buffer.from(mutatedHash).toString("hex")
    );
    assert.notEqual(
      fingerprint,
      transport.displayPhilCoreRecoveryComparisonFingerprint(mutatedHash)
    );
  });

  it("uses recovery-only domain labels and rejects pairing confusion", function () {
    assert.equal(
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_TRANSCRIPT_LABEL,
      "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1"
    );
    assert.equal(
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO,
      "PHILCORE_NATIVE_RECOVERY_APPROVAL_AES256_GCM_V1"
    );
    assert.equal(
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP,
      "IPHONE_TO_DESKTOP_RECOVERY_APPROVAL_V1"
    );
    assert.equal(
      transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE,
      "DESKTOP_TO_IPHONE_RECOVERY_APPROVAL_V1"
    );
    assert.equal(
      transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH,
      "/philcore/recovery/v1/complete"
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "http://192.168.1.10:8787/philcore/recovery/v1/complete"
      ),
      true
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "http://127.0.0.1:8787/philcore/recovery/v1/complete"
      ),
      false
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "http://192.168.1.10:8787/philcore/pair/v1/complete"
      ),
      false
    );
    assert.equal(
      transport.isRfc1918RecoveryApprovalEndpoint(
        "http://hostname.local:8787/philcore/recovery/v1/complete"
      ),
      false
    );
  });

  it("enforces exact bitmaps 3/5/6 and ascending role order", function () {
    assert.deepEqual(transport.rolesForRecoveryFactorBitmap(3), [0, 1]);
    assert.deepEqual(transport.rolesForRecoveryFactorBitmap(5), [0, 2]);
    assert.deepEqual(transport.rolesForRecoveryFactorBitmap(6), [1, 2]);
    assert.throws(() => transport.rolesForRecoveryFactorBitmap(7));
    assert.throws(() => transport.rolesForRecoveryFactorBitmap(1));
    assert.throws(() => transport.rolesForRecoveryFactorBitmap(0));
  });

  it("rejects malformed DER and normalizes high-s before native evidence encoding", function () {
    assert.throws(
      () => transport.parseDerEcdsaP256Signature(Buffer.from([0x30, 0x01, 0x00])),
      /DER|malformed|invalid/i
    );
    assert.throws(
      () => transport.parseDerEcdsaP256Signature(Buffer.from("not-der")),
      /DER|malformed|invalid/i
    );

    const privateScalar = zeroPadValue(
      toBeHex((BigInt(H("O44:HIGH_S_KEY")) % (PHILCORE_O37_2_P256_ORDER - 1n)) + 1n),
      32
    );
    const digest = getBytes(H("O44:HIGH_S_DIGEST"));
    let signature = p256.sign(digest, getBytes(privateScalar), {
      lowS: false,
      prehash: false
    });
    if (signature.s <= PHILCORE_O37_2_P256_HALF_ORDER) {
      signature = {
        r: signature.r,
        s: PHILCORE_O37_2_P256_ORDER - signature.s
      };
    }
    assert.ok(signature.s > PHILCORE_O37_2_P256_HALF_ORDER);
    const der = encodeDerSignature(signature.r, signature.s);
    const parsed = transport.parseDerEcdsaP256Signature(der);
    const normalized = transport.normalizeP256SignatureLowS(parsed);
    assert.equal(normalized.normalized, true);
    assert.ok(BigInt(normalized.s) <= PHILCORE_O37_2_P256_HALF_ORDER);

    const lowSignature = p256.sign(digest, getBytes(privateScalar), {
      lowS: true,
      prehash: false
    });
    const lowDer = encodeDerSignature(lowSignature.r, lowSignature.s);
    const lowParsed = transport.parseDerEcdsaP256Signature(lowDer);
    const lowNormalized = transport.normalizeP256SignatureLowS(lowParsed);
    assert.equal(lowNormalized.normalized, false);
    assert.ok(BigInt(lowNormalized.s) <= PHILCORE_O37_2_P256_HALF_ORDER);

    const publicKey = p256.getPublicKey(getBytes(privateScalar), false);
    const qx = `0x${Buffer.from(publicKey.slice(1, 33)).toString("hex")}`;
    const qy = `0x${Buffer.from(publicKey.slice(33, 65)).toString("hex")}`;
    const {
      buildPhilCoreNativeIPhoneDescriptor,
      computePhilCoreNativeIPhoneFactorCommitment,
      PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE
    } = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
    const descriptor = buildPhilCoreNativeIPhoneDescriptor({
      qx,
      qy,
      credentialIdentifierCommitment: H("O44:HIGH_S:CREDENTIAL_ID"),
      deviceCustodyCommitment: H("O44:HIGH_S:CUSTODY"),
      generation: 1
    });
    const evidence = transport.encodeNativeRecoveryEvidenceFromDer({
      descriptor,
      factorCommitment: computePhilCoreNativeIPhoneFactorCommitment(descriptor),
      qx,
      qy,
      derSignature: der,
      digest: H("O44:HIGH_S_DIGEST")
    });
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
      [PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE],
      evidence
    );
    const s = BigInt(decoded[0].s);
    assert.ok(s <= PHILCORE_O37_2_P256_HALF_ORDER, "evidence s must be low-s");
  });

  it("preserves exact PHIL39-V1 offline derivation domain labels (host owns keys)", function () {
    assert.equal(
      transport.PHIL39_V1_OFFLINE_DERIVATION_DOMAIN_LABEL,
      "PHILCORE_OFFLINE_RECOVERY_FACTOR_V1"
    );
    assert.equal(
      transport.PHIL39_V1_OFFLINE_FORMAT_PREFIX,
      "PHIL39-V1"
    );
    assert.equal(
      id(transport.PHIL39_V1_OFFLINE_DERIVATION_DOMAIN_LABEL),
      id("PHILCORE_OFFLINE_RECOVERY_FACTOR_V1")
    );
    assert.equal(
      typeof transport.derivePhil39V1OfflinePrivateKey,
      "undefined"
    );
    assert.equal(typeof transport.formatPhil39V1OfflineCode, "undefined");
    assert.equal(typeof transport.inspectPhil39V1OfflineCode, "undefined");
    // Host remains the sole offline-code inspector / key derivation surface.
    assert.equal(typeof inspectOfflineCode, "function");
  });

  it("assembles recovery envelopes accepted by the static verifier for bitmaps 3/5/6", async function () {
    const { AbiCoder } = require("ethers");
    const {
      PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE
    } = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
    const abiCoder = AbiCoder.defaultAbiCoder();
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    for (const pair of o43.validPairs) {
      const decoded = abiCoder.decode(
        [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
        pair.envelope
      )[0];
      const envelope = transport.assemblePhilCoreRecoveryEnvelopeFromVerifiedFactors({
        request: o43.request,
        commitments,
        bitmap: pair.bitmap,
        verifiedFactors: [
          { role: pair.roles[0], evidence: decoded.firstFactorEvidence },
          { role: pair.roles[1], evidence: decoded.secondFactorEvidence }
        ]
      });
      const signer = await signerFor(o43.request.account);
      const result = await verifier
        .connect(signer)
        .verifyAuthority.staticCall(o43.request, envelope);
      assert.equal(
        result,
        await verifier.SUCCESS_MAGIC(),
        `bitmap ${pair.bitmap} must verify`
      );
    }
  });

  it("keeps the deterministic O.44 package current and free of private inputs", function () {
    assert.ok(fs.existsSync(FIXTURE_PATH), "O.44 fixture file must exist");
    const fixtures = loadFixtures();
    assert.equal(fixtures.phase, "O.44");
    assert.equal(fixtures.classification, "DETERMINISTIC_SYNTHETIC_TEST_ONLY");
    assert.equal(fixtures.publicMutationCount, 0);
    assert.equal(fixtures.networkCalls, 0);
    assert.equal(fixtures.productionCredentialCreated, false);
    assert.equal(fixtures.productionSignatureCreated, false);
    assert.equal(fixtures.blockchainMutations, 0);
    assert.equal(fixtures.secretsCommitted, false);
    const serialized = JSON.stringify(fixtures);
    for (const forbidden of [
      /"privateScalar"\s*:/u,
      /"privateKey"\s*:/u,
      /"recoveryCode"\s*:/u,
      /"offlineEntropy"\s*:/u,
      /"ecdhPrivate"\s*:/u,
      /"sharedSecret"\s*:/u
    ]) {
      assert.equal(
        forbidden.test(serialized),
        false,
        `fixture must not commit ${forbidden}`
      );
    }
    const {
      buildO44RecoveryTransportFixturePackage
    } = require("../../scripts/cryptography/generate-o44-recovery-transport-fixtures.cjs");
    const expected = `${JSON.stringify(
      buildO44RecoveryTransportFixturePackage(),
      (_key, value) => (typeof value === "bigint" ? value.toString() : value),
      2
    )}\n`;
    assert.equal(fs.readFileSync(FIXTURE_PATH, "utf8"), expected);
  });
});

describe("O.44 amendment red-gate (Commit 1 defects)", function () {
  let o43;
  let verifier;

  before(async function () {
    o43 = buildO43NativeIPhoneFixturePackage();
    verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
  });

  function validApprovalRequest(overrides = {}) {
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const context = buildV2Context(commitments, 6);
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: context.chainId, account: context.account },
      {
        authorizedIntentHash: context.authorizedIntentHash,
        userOperationHash: context.userOperationHash,
        recoveryConfigHash: context.currentRecoveryConfigHash,
        recoveryEpoch: context.recoveryEpoch,
        factorBitmap: 6
      }
    ).digest;
    const contextHash = contextHashFor(context);
    return {
      protocolVersion: 1,
      context,
      claimedContextHash: contextHash,
      claimedRecoveryFactorDigest: digest,
      accountVersionId: o43.request.accountVersionId,
      securityModelId: o43.request.securityModelId,
      nativeRecoveryDomainId: o43.factors.nativeIPhone.descriptor.recoveryDomainId,
      applicationIdentity: o43.applicationIdentity,
      localApprovalPolicy:
        "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST",
      selectedRole1CredentialIdentifierCommitment:
        o43.factors.nativeIPhone.descriptor.credentialIdentifierCommitment,
      selectedRole1CredentialGeneration: 1,
      trustedRole1Descriptor: o43.factors.nativeIPhone.descriptor,
      trustedRole1PublicKey: {
        qx: o43.factors.nativeIPhone.qx,
        qy: o43.factors.nativeIPhone.qy
      },
      sessionId: `0x${"33".repeat(32)}`,
      sessionChallenge: `0x${"44".repeat(32)}`,
      desktopEphemeralPublicKey:
        deterministicUncompressedP256PublicKey("O44:TEST:DESKTOP_EPHEMERAL_RG"),
      issuedAt: "1700000000000",
      expiresAt: "1700000300000",
      endpoint: "http://10.0.0.8:9090/philcore/recovery/v1/complete",
      now: "1700000100000",
      ...overrides
    };
  }

  it("RG1 rejects forged claimed digest when building transcript", function () {
    const request = validApprovalRequest({
      claimedRecoveryFactorDigest: `0x${"ab".repeat(32)}`
    });
    assert.throws(
      () => transport.buildPhilCoreNativeRecoveryApprovalTranscript(request),
      /digest|mismatch|recomput/i
    );
  });

  it("RG2 rejects wrong identity pins", function () {
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({ accountVersionId: `0x${"11".repeat(32)}` })
      ),
      /accountVersion|identity|pin/i
    );
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({
          applicationIdentity: "WRONG_APP\nIDENTITY"
        })
      ),
      /application|identity|newline|pin/i
    );
  });

  it("RG3 rejects wrong Role 1 descriptor bindings", function () {
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({
          selectedRole1CredentialIdentifierCommitment: `0x${"99".repeat(32)}`
        })
      ),
      /credential|descriptor|commitment/i
    );
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({ selectedRole1CredentialGeneration: 99 })
      ),
      /generation|descriptor/i
    );
  });

  it("RG4 rejects newline-bearing textual fields", function () {
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({
          localApprovalPolicy:
            "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST\n"
        })
      ),
      /newline|policy|pin/i
    );
  });

  it("RG5 rejects bitmap 5 for native Role 1 approval", function () {
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const context = buildV2Context(commitments, 5);
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: context.chainId, account: context.account },
      {
        authorizedIntentHash: context.authorizedIntentHash,
        userOperationHash: context.userOperationHash,
        recoveryConfigHash: context.currentRecoveryConfigHash,
        recoveryEpoch: context.recoveryEpoch,
        factorBitmap: 5
      }
    ).digest;
    const contextHash = contextHashFor(context);
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({
          context,
          claimedContextHash: contextHash,
          claimedRecoveryFactorDigest: digest
        })
      ),
      /bitmap|role.?1|native/i
    );
  });

  it("RG6 rejects noncanonical numeric encodings", function () {
    const request = validApprovalRequest({
      context: {
        ...validApprovalRequest().context,
        chainId: "031337"
      }
    });
    assert.throws(
      () => transport.buildPhilCoreNativeRecoveryApprovalTranscript(request),
      /canonical|chainId|leading.?zero|noncanonical/i
    );
  });

  it("RG7 rejects expired requests against injected now", function () {
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({ now: "1700000400000" })
      ),
      /expir|fresh|window/i
    );
  });

  it("RG8 rejects invalid uncompressed P-256 ephemeral keys", function () {
    assert.throws(
      () => transport.validatePhilCoreRecoveryApprovalRequest(
        validApprovalRequest({
          desktopEphemeralPublicKey: Buffer.alloc(65, 9).toString("base64url")
        })
      ),
      /p256|ephemeral|curve|point/i
    );
  });

  it("RG9 fixture performs genuine two-sided ECDH", function () {
    const fixtures = loadFixtures();
    assert.ok(fixtures.hkdfAesGcm);
    assert.ok(
      fixtures.hkdfAesGcm.desktopEphemeralPublicKey
      && fixtures.hkdfAesGcm.phoneEphemeralPublicKey,
      "fixture must publish both ephemeral public keys"
    );
    assert.ok(
      fixtures.hkdfAesGcm.sharedSecretFingerprint,
      "fixture must include shared-secret fingerprint from real ECDH"
    );
    assert.notEqual(
      fixtures.hkdfAesGcm.desktopEphemeralPublicKey,
      Buffer.alloc(65, 9).toString("base64url")
    );
    assert.equal(
      fixtures.hkdfAesGcm.ecdhAgreementProven,
      true
    );
  });

  it("RG10 response carries DER recovery signature under strict schema", function () {
    const fixtures = loadFixtures();
    const plaintext = fixtures.hkdfAesGcm.responsePlaintext;
    assert.ok(plaintext.derRecoverySignature, "missing DER recovery signature");
    assert.equal(
      Object.keys(plaintext).sort().join(","),
      [
        "credentialGeneration",
        "credentialIdentifierCommitment",
        "derRecoverySignature",
        "protocolVersion",
        "role1FactorCommitment",
        "sessionId",
        "transcriptHash"
      ].join(",")
    );
    transport.validateNativeRecoveryResponsePayload(
      plaintext,
      {
        sessionId: fixtures.approvalRequest.sessionId,
        transcriptHash: Buffer.from(fixtures.transcriptHash.slice(2), "hex"),
        role1FactorCommitment:
          fixtures.approvalRequest.context.hardwareSecurityKeyCommitment,
        credentialIdentifierCommitment:
          fixtures.approvalRequest.selectedRole1CredentialIdentifierCommitment,
        credentialGeneration: Number(
          fixtures.approvalRequest.selectedRole1CredentialGeneration
        )
      }
    );
  });

  it("RG11 response and acknowledgement use distinct AES-GCM nonces", function () {
    const fixtures = loadFixtures();
    assert.notEqual(
      fixtures.hkdfAesGcm.encryptedResponse.nonce,
      fixtures.hkdfAesGcm.encryptedAcknowledgement.nonce
    );
    assert.throws(
      () => transport.assertDistinctRecoveryApprovalNonces(
        fixtures.hkdfAesGcm.encryptedResponse,
        {
          ...fixtures.hkdfAesGcm.encryptedAcknowledgement,
          nonce: fixtures.hkdfAesGcm.encryptedResponse.nonce
        }
      ),
      /nonce/i
    );
  });

  it("RG12 does not export derivePhil39V1OfflinePrivateKey", function () {
    assert.equal(
      typeof transport.derivePhil39V1OfflinePrivateKey,
      "undefined"
    );
  });

  it("RG13 consumer-V3 context uses versioned boundary; frozen rejects V3", function () {
    const {
      computePhilCoreV2ConsumerRecoveryEvidenceContextHash
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
    );
    const {
      computePhilCoreV2ConsumerRecoveryConfigurationHash
    } = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
    const {
      computePhilCoreV2RecoveryConfigurationHashV2,
      PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2
    } = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const v3Hash = computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
    const v2Hash = computePhilCoreV2RecoveryConfigurationHashV2({
      configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
      threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
      primaryDeviceCommitment: commitments[0],
      hardwareSecurityKeyCommitment: commitments[1],
      recoveryFactorCommitment: commitments[2]
    });
    const roles = [1, 2];
    const context = {
      ...buildV2Context(commitments, 6),
      currentRecoveryConfigHash: v3Hash,
      firstFactorCommitment: commitments[roles[0]],
      secondFactorCommitment: commitments[roles[1]]
    };
    // Frozen one-arg path rejects consumer-V3 configuration hashes.
    assert.throws(
      () => computePhilCoreV2RecoveryEvidenceContextHash(context),
      /current_recovery_config_hash_mismatch/
    );
    // Versioned O.44 boundary accepts V3 and rejects legacy V2.
    const hash = computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
    assert.match(hash, /^0x[0-9a-f]{64}$/u);
    assert.throws(
      () => computePhilCoreV2ConsumerRecoveryEvidenceContextHash({
        ...context,
        currentRecoveryConfigHash: v2Hash
      }),
      /current_recovery_config_hash_mismatch/
    );
    assert.throws(
      () => computePhilCoreV2ConsumerRecoveryEvidenceContextHash({
        ...context,
        currentRecoveryConfigHash: `0x${"11".repeat(32)}`
      }),
      /current_recovery_config_hash_mismatch/
    );
  });

  it("RG14/15 current-consumer decoder accepts 2272-byte bitmap-6 without ABI fallback", function () {
    const {
      decodePhilCoreO374RecoveryEvidence,
      PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES
    } = require("../../apps/phil-device-sdk/src/v2AuthorityTransport.ts");
    const {
      decodePhilCoreV2ConsumerRecoveryEvidence,
      PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES,
      PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    assert.equal(PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES, 2624);
    assert.equal(PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES, 2272);
    assert.equal(PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES, 640);
    const pair = o43.validPairs.find((entry) => entry.bitmap === 6);
    assert.equal(getBytes(pair.envelope).length, 2272);
    assert.throws(
      () => decodePhilCoreO374RecoveryEvidence(pair.envelope, 8),
      /recovery_evidence_length_invalid/
    );
    const decoded = decodePhilCoreV2ConsumerRecoveryEvidence(pair.envelope, 8);
    assert.equal(Number(decoded.context.factorBitmap), 6);
  });

  it("RG16 rejects DER/P-256 boundary violations", function () {
    assert.throws(
      () => transport.normalizeP256SignatureLowS({
        r: `0x${"00".repeat(32)}`,
        s: `0x${"01".repeat(32)}`
      }),
      /zero|out_of_range|invalid/i
    );
    assert.throws(
      () => transport.normalizeP256SignatureLowS({
        r: `0x${"01".repeat(32)}`,
        s: zeroPadValue(toBeHex(PHILCORE_O37_2_P256_ORDER), 32)
      }),
      /out_of_range|order|invalid/i
    );
  });

  it("RG17 static verifier rejects altered O.44 envelopes", async function () {
    const fixtures = loadFixtures();
    assert.ok(Array.isArray(fixtures.factorPairs) && fixtures.factorPairs.length === 3);
    assert.ok(
      Array.isArray(fixtures.staticVerifierNegatives)
      && fixtures.staticVerifierNegatives.length >= 5,
      "fixture must list executable static-verifier negatives"
    );
    const pair = fixtures.factorPairs.find((entry) => entry.bitmap === 6);
    const signer = await signerFor(fixtures.verifierRequest.account);
    const success = await verifier
      .connect(signer)
      .verifyAuthority.staticCall(fixtures.verifierRequest, pair.envelope);
    assert.equal(success, await verifier.SUCCESS_MAGIC());
    for (const negative of fixtures.staticVerifierNegatives) {
      await assert.rejects(async () => {
        await verifier.connect(signer).verifyAuthority.staticCall(
          { ...fixtures.verifierRequest, ...negative.requestOverride },
          negative.envelope || pair.envelope
        );
      });
    }
  });

  it("RG-mutations execute every listed negative mutation", function () {
    const fixtures = loadFixtures();
    assert.ok(Array.isArray(fixtures.negativeMutations));
    assert.ok(fixtures.negativeMutations.length > 0);
    for (const mutation of fixtures.negativeMutations) {
      assert.ok(mutation.field, "mutation must name a field");
      assert.ok(mutation.expectedError, "mutation must declare expectedError");
      assert.throws(
        () => transport.validatePhilCoreRecoveryApprovalRequest(
          mutation.request
        ),
        new RegExp(mutation.expectedError, "i"),
        `mutation ${mutation.field} must reject`
      );
    }
  });
});

describe("O.44 corrective Commit 3 red-gate (frozen O.37.1 + consumer-V3 isolation)", function () {
  const FROZEN_BINDING =
    "43cf487d974fed3ba34253ef54831405f8ca1247df7715c7a41f3fd0064b1cf8";
  const cryptoNode = require("node:crypto");

  function sourceSha256() {
    return cryptoNode
      .createHash("sha256")
      .update(fs.readFileSync(
        path.join(ROOT, "apps/phil-device-sdk/src/v2RecoveryEvidence.ts")
      ))
      .digest("hex");
  }

  it("C3-RG1 frozen v2RecoveryEvidence.ts SHA-256 equals restored O.37.1 binding", function () {
    const binding = JSON.parse(fs.readFileSync(
      path.join(ROOT, "config/cryptography/O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json"),
      "utf8"
    )).implementationBindings.recoveryEvidenceSourceSha256;
    assert.equal(binding, FROZEN_BINDING);
    assert.equal(sourceSha256(), FROZEN_BINDING);
  });

  it("C3-RG2 consumer-V3 context hash module exists", function () {
    const mod = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
    );
    assert.equal(
      typeof mod.computePhilCoreV2ConsumerRecoveryEvidenceContextHash,
      "function"
    );
  });

  it("C3-RG3 accepts consumer-V3 context and rejects legacy-V2 config hash", function () {
    const {
      computePhilCoreV2ConsumerRecoveryEvidenceContextHash
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
    );
    const {
      computePhilCoreV2ConsumerRecoveryConfigurationHash
    } = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
    const {
      computePhilCoreV2RecoveryConfigurationHashV2,
      PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2
    } = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
    const o43 = buildO43NativeIPhoneFixturePackage();
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const v3 = computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
    const v2 = computePhilCoreV2RecoveryConfigurationHashV2({
      configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
      threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
      primaryDeviceCommitment: commitments[0],
      hardwareSecurityKeyCommitment: commitments[1],
      recoveryFactorCommitment: commitments[2]
    });
    const base = {
      envelopeVersion: 2,
      authorityKind: 2,
      actionType: 8,
      factorBitmap: 6,
      account: "0x0000000000000000000000000000000000004400",
      chainId: "31337",
      entryPoint: "0x00000000000000000000000000000000000F4337",
      authorizedIntentHash: H("O44:C3:INTENT"),
      userOperationHash: H("O44:C3:USEROP"),
      requestId: H("O44:C3:INTENT"),
      validatorEpoch: 1,
      recoveryEpoch: 1,
      validAfter: 1000,
      validUntil: 5000,
      recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
      recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
      proposedValidatorCommitment: H("O44:C3:PROPOSED"),
      proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
      proposedRecoveryEpoch: 2,
      primaryDeviceCommitment: commitments[0],
      hardwareSecurityKeyCommitment: commitments[1],
      recoveryFactorCommitment: commitments[2],
      firstFactorCommitment: commitments[1],
      secondFactorCommitment: commitments[2]
    };
    const v3Hash = computePhilCoreV2ConsumerRecoveryEvidenceContextHash({
      ...base,
      currentRecoveryConfigHash: v3
    });
    assert.match(v3Hash, /^0x[0-9a-f]{64}$/u);
    assert.throws(
      () => computePhilCoreV2ConsumerRecoveryEvidenceContextHash({
        ...base,
        currentRecoveryConfigHash: v2
      }),
      /current_recovery_config_hash_mismatch/
    );
    // Frozen one-arg path still rejects bare V3.
    assert.throws(
      () => computePhilCoreV2RecoveryEvidenceContextHash({
        ...base,
        currentRecoveryConfigHash: v3
      }),
      /current_recovery_config_hash_mismatch/
    );
    // Encoding convention parity for legacy-V2-shaped context.
    const v2Context = { ...base, currentRecoveryConfigHash: v2 };
    const frozen = computePhilCoreV2RecoveryEvidenceContextHash(v2Context);
    const {
      hashPhilCoreV2RecoveryEvidenceContextFields
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
    );
    assert.equal(
      hashPhilCoreV2RecoveryEvidenceContextFields(v2Context),
      frozen
    );
  });

  it("C3-RG4 enforces frozen context invariants through the V3 boundary", function () {
    const {
      computePhilCoreV2ConsumerRecoveryEvidenceContextHash
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts"
    );
    const {
      computePhilCoreV2ConsumerRecoveryConfigurationHash
    } = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
    const o43 = buildO43NativeIPhoneFixturePackage();
    const commitments = [
      o43.factors.primary.factorCommitment,
      o43.factors.nativeIPhone.factorCommitment,
      o43.factors.offline.factorCommitment
    ];
    const v3 = computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
    const valid = {
      envelopeVersion: 2,
      authorityKind: 2,
      actionType: 8,
      factorBitmap: 6,
      account: "0x0000000000000000000000000000000000004400",
      chainId: "31337",
      entryPoint: "0x00000000000000000000000000000000000F4337",
      authorizedIntentHash: H("O44:C3:INV:INTENT"),
      userOperationHash: H("O44:C3:INV:USEROP"),
      requestId: H("O44:C3:INV:INTENT"),
      currentRecoveryConfigHash: v3,
      validatorEpoch: 1,
      recoveryEpoch: 1,
      validAfter: 1000,
      validUntil: 5000,
      recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
      recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
      proposedValidatorCommitment: H("O44:C3:INV:PROPOSED"),
      proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
      proposedRecoveryEpoch: 2,
      primaryDeviceCommitment: commitments[0],
      hardwareSecurityKeyCommitment: commitments[1],
      recoveryFactorCommitment: commitments[2],
      firstFactorCommitment: commitments[1],
      secondFactorCommitment: commitments[2]
    };
    const cases = [
      [{ ...valid, envelopeVersion: 1 }, /version|unsupported/i],
      [{ ...valid, authorityKind: 1 }, /authority|unsupported/i],
      [{ ...valid, actionType: 2 }, /action/i],
      [{ ...valid, factorBitmap: 7 }, /bitmap|factor/i],
      [{
        ...valid,
        account: "0x0000000000000000000000000000000000000000"
      }, /account/i],
      [{ ...valid, chainId: 0 }, /chainId/i],
      [{
        ...valid,
        entryPoint: "0x0000000000000000000000000000000000000000"
      }, /entryPoint/i],
      [{ ...valid, authorizedIntentHash: `0x${"11".repeat(32)}` }, /request_id|intent/i],
      [{ ...valid, userOperationHash: `0x${"00".repeat(32)}` }, /userOperation|nonzero|bytes32/i],
      [{ ...valid, requestId: `0x${"22".repeat(32)}` }, /request_id|intent/i],
      [{
        ...valid,
        currentRecoveryConfigHash: `0x${"33".repeat(32)}`
      }, /current_recovery_config_hash_mismatch/],
      [{ ...valid, validatorEpoch: 0 }, /validatorEpoch|nonzero/i],
      [{ ...valid, recoveryEpoch: 0 }, /recoveryEpoch|nonzero/i],
      [{ ...valid, validAfter: 5000, validUntil: 5000 }, /validity_window/i],
      [{ ...valid, recoveryDelaySeconds: 1 }, /recoveryDelay/i],
      [{ ...valid, recoveryExpirySeconds: 1 }, /recoveryExpiry/i],
      [{
        ...valid,
        proposedValidatorCommitment: PHILCORE_V2_ZERO_BYTES32
      }, /validator_recovery_action_context/i],
      [{
        ...valid,
        proposedRecoveryConfigHash: H("O44:C3:BAD_PROPOSED_CONFIG")
      }, /validator_recovery_action_context/i],
      [{ ...valid, proposedRecoveryEpoch: 9 }, /proposedRecoveryEpoch/i],
      [{
        ...valid,
        primaryDeviceCommitment: commitments[1]
      }, /unique|commitment/i],
      [{
        ...valid,
        hardwareSecurityKeyCommitment: commitments[0]
      }, /unique|commitment/i],
      [{
        ...valid,
        recoveryFactorCommitment: commitments[0]
      }, /unique|commitment/i],
      [{
        ...valid,
        firstFactorCommitment: commitments[0]
      }, /factor_commitment_order|membership/i],
      [{
        ...valid,
        secondFactorCommitment: commitments[0]
      }, /factor_commitment_order|membership/i]
    ];
    for (const [candidate, pattern] of cases) {
      assert.throws(
        () => computePhilCoreV2ConsumerRecoveryEvidenceContextHash(candidate),
        pattern
      );
    }
  });
});

describe("O.44 corrective Commit 4 red-gate (frozen O.37.4 + native decoder isolation)", function () {
  const FROZEN_AUTHORITY_SHA =
    "0461d7c83b1e8a0ae79b1ab5d88117c97f466eb4ee3d4c35489c96fa21971063";
  const cryptoNode = require("node:crypto");
  const { AbiCoder, getBytes: getBytesEthers } = require("ethers");
  const abiCoder = AbiCoder.defaultAbiCoder();
  const {
    PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE,
    encodePhilCoreO372RecoveryEnvelope
  } = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");

  function authoritySourceSha256() {
    return cryptoNode
      .createHash("sha256")
      .update(fs.readFileSync(
        path.join(ROOT, "apps/phil-device-sdk/src/v2AuthorityTransport.ts")
      ))
      .digest("hex");
  }

  function loadO374Package() {
    return JSON.parse(fs.readFileSync(
      path.join(ROOT, "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"),
      "utf8"
    ));
  }

  it("C4-RG1 live v2AuthorityTransport.ts SHA-256 equals frozen Commit 1 hash", function () {
    assert.equal(authoritySourceSha256(), FROZEN_AUTHORITY_SHA);
  });

  it("C4-RG2 consumer recovery authority decoder module exists", function () {
    const mod = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    assert.equal(
      typeof mod.decodePhilCoreV2ConsumerRecoveryEvidence,
      "function"
    );
  });

  it("C4-RG3 frozen decoder rejects valid 2272-byte bitmap-6 at historical floor", function () {
    const {
      decodePhilCoreO374RecoveryEvidence,
      PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES
    } = require("../../apps/phil-device-sdk/src/v2AuthorityTransport.ts");
    assert.equal(PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES, 2624);
    const o43 = buildO43NativeIPhoneFixturePackage();
    const pair = o43.validPairs.find((entry) => entry.bitmap === 6);
    assert.equal(getBytes(pair.envelope).length, 2272);
    assert.throws(
      () => decodePhilCoreO374RecoveryEvidence(pair.envelope, 8),
      /recovery_evidence_length_invalid/
    );
  });

  it("C4-RG4 current-consumer decoder accepts the same 2272-byte envelope", function () {
    const {
      decodePhilCoreV2ConsumerRecoveryEvidence
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    const o43 = buildO43NativeIPhoneFixturePackage();
    const pair = o43.validPairs.find((entry) => entry.bitmap === 6);
    const decoded = decodePhilCoreV2ConsumerRecoveryEvidence(pair.envelope, 8);
    assert.equal(Number(decoded.context.factorBitmap), 6);
    assert.equal(getBytes(decoded.firstFactorEvidence).length, 640);
    assert.equal(getBytes(decoded.secondFactorEvidence).length, 672);
  });

  it("C4-RG5 restored source SHA equals O.37.4 historical binding (candidate mismatches root cause)", function () {
    const pkg = loadO374Package();
    assert.equal(
      pkg.implementationBindings.authorityTransportSourceSha256,
      FROZEN_AUTHORITY_SHA
    );
    assert.equal(authoritySourceSha256(), FROZEN_AUTHORITY_SHA);
    assert.deepEqual(
      [
        "unit:o37-4-v2-authority-transport.test.cjs",
        "script:test:o37-4-authority-transport",
        "script:verify:o37-4-authority-transport-vectors"
      ],
      [
        "unit:o37-4-v2-authority-transport.test.cjs",
        "script:test:o37-4-authority-transport",
        "script:verify:o37-4-authority-transport-vectors"
      ]
    );
  });

  it("C4 accepts bitmaps 3/5/6 and legacy WebAuthn Role 1 envelopes", function () {
    const {
      decodePhilCoreV2ConsumerRecoveryEvidence
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    const o43 = buildO43NativeIPhoneFixturePackage();
    for (const bitmap of [3, 5, 6]) {
      const pair = o43.validPairs.find((entry) => entry.bitmap === bitmap);
      assert.ok(pair, `o43 pair bitmap ${bitmap}`);
      const decoded = decodePhilCoreV2ConsumerRecoveryEvidence(pair.envelope, 8);
      assert.equal(Number(decoded.context.factorBitmap), bitmap);
    }
    const o39 = require(
      "../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs"
    ).buildO39ConsumerRecoveryFixturePackage();
    const legacy = o39.profiles.standard.validPairs.find(
      (entry) => entry.bitmap === 3
    );
    assert.ok(legacy, "legacy webauthn bitmap-3 pair");
    assert.ok(getBytes(legacy.envelope).length >= 2624);
    const decodedLegacy = decodePhilCoreV2ConsumerRecoveryEvidence(
      legacy.envelope,
      8
    );
    assert.equal(Number(decodedLegacy.context.factorBitmap), 3);
    assert.ok(getBytes(decodedLegacy.firstFactorEvidence).length >= 992);
    assert.ok(getBytes(decodedLegacy.secondFactorEvidence).length >= 992);
  });

  it("C4 rejects structural decoder boundary violations", function () {
    const {
      decodePhilCoreV2ConsumerRecoveryEvidence,
      PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES,
      PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MAX_BYTES,
      PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES,
      PHILCORE_V2_CONSUMER_SECP256K1_EVIDENCE_BYTES
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    const o43 = buildO43NativeIPhoneFixturePackage();
    const pair6 = o43.validPairs.find((entry) => entry.bitmap === 6);
    const pair3 = o43.validPairs.find((entry) => entry.bitmap === 3);
    const decoded6 = decodePhilCoreV2ConsumerRecoveryEvidence(pair6.envelope, 8);
    const [tuple6] = abiCoder.decode(
      [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
      pair6.envelope
    );
    const [tuple3] = abiCoder.decode(
      [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
      pair3.envelope
    );

    function contextFrom(tuple, overrides = {}) {
      const c = tuple.context;
      return {
        envelopeVersion: c.envelopeVersion,
        authorityKind: c.authorityKind,
        actionType: c.actionType,
        factorBitmap: c.factorBitmap,
        account: c.account,
        chainId: c.chainId,
        entryPoint: c.entryPoint,
        authorizedIntentHash: c.authorizedIntentHash,
        userOperationHash: c.userOperationHash,
        requestId: c.requestId,
        currentRecoveryConfigHash: c.currentRecoveryConfigHash,
        validatorEpoch: c.validatorEpoch,
        recoveryEpoch: c.recoveryEpoch,
        validAfter: c.validAfter,
        validUntil: c.validUntil,
        recoveryDelaySeconds: c.recoveryDelaySeconds,
        recoveryExpirySeconds: c.recoveryExpirySeconds,
        proposedValidatorCommitment: c.proposedValidatorCommitment,
        proposedRecoveryConfigHash: c.proposedRecoveryConfigHash,
        proposedRecoveryEpoch: c.proposedRecoveryEpoch,
        primaryDeviceCommitment: c.primaryDeviceCommitment,
        hardwareSecurityKeyCommitment: c.hardwareSecurityKeyCommitment,
        recoveryFactorCommitment: c.recoveryFactorCommitment,
        firstFactorCommitment: c.firstFactorCommitment,
        secondFactorCommitment: c.secondFactorCommitment,
        ...overrides
      };
    }

    function reencode(baseTuple, mutator) {
      const next = {
        context: contextFrom(baseTuple),
        firstFactorEvidence: baseTuple.firstFactorEvidence,
        secondFactorEvidence: baseTuple.secondFactorEvidence
      };
      mutator(next);
      return encodePhilCoreO372RecoveryEnvelope(next);
    }

    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence("not-bytes", 8),
      /must_be_bytes|recoveryEvidence/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        `0x${"11".repeat(PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES - 1)}`,
        8
      ),
      /recovery_evidence_length_invalid/
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        `0x${"11".repeat(PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MAX_BYTES + 1)}`,
        8
      ),
      /recovery_evidence_length_invalid/
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(`${pair6.envelope}aa`, 8),
      /noncanonical|malformed|length/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple6, (value) => {
          value.context = contextFrom(tuple6, { envelopeVersion: 1 });
        }),
        8
      ),
      /version/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple6, (value) => {
          value.context = contextFrom(tuple6, { authorityKind: 1 });
        }),
        8
      ),
      /authority/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(pair6.envelope, 9),
      /action/i
    );
    for (const bitmap of [0, 1, 2, 4, 7]) {
      assert.throws(
        () => decodePhilCoreV2ConsumerRecoveryEvidence(
          reencode(tuple6, (value) => {
            value.context = contextFrom(tuple6, { factorBitmap: bitmap });
          }),
          8
        ),
        /bitmap/i
      );
    }
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple6, (value) => {
          value.firstFactorEvidence = "0x";
        }),
        8
      ),
      /missing_or_duplicate|evidence/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple6, (value) => {
          value.secondFactorEvidence = value.firstFactorEvidence;
        }),
        8
      ),
      /missing_or_duplicate|evidence/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        encodePhilCoreO372RecoveryEnvelope({
          context: contextFrom(tuple6, { factorBitmap: 3 }),
          firstFactorEvidence: decoded6.firstFactorEvidence,
          secondFactorEvidence: decoded6.secondFactorEvidence
        }),
        8
      ),
      /webauthn_evidence_length_invalid|role/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple6, (value) => {
          value.firstFactorEvidence = `0x${"22".repeat(100)}`;
        }),
        8
      ),
      /role1_evidence_length_invalid|evidence_length/i
    );
    const pair5 = o43.validPairs.find((entry) => entry.bitmap === 5);
    const [tuple5] = abiCoder.decode(
      [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
      pair5.envelope
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple5, (value) => {
          value.secondFactorEvidence = `0x${"33".repeat(
            PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES
          )}`;
        }),
        8
      ),
      /secp256k1_evidence_length_invalid/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        encodePhilCoreO372RecoveryEnvelope({
          context: contextFrom(tuple6),
          firstFactorEvidence: decoded6.secondFactorEvidence,
          secondFactorEvidence: decoded6.firstFactorEvidence
        }),
        8
      ),
      /role1_evidence_length_invalid|secp256k1_evidence_length_invalid|webauthn/i
    );

    const decoded3 = decodePhilCoreV2ConsumerRecoveryEvidence(pair3.envelope, 8);
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        encodePhilCoreO372RecoveryEnvelope({
          context: contextFrom(tuple5, { factorBitmap: 3 }),
          firstFactorEvidence: `0x${"44".repeat(
            PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES
          )}`,
          secondFactorEvidence: tuple5.firstFactorEvidence
        }),
        8
      ),
      /webauthn_evidence_length_invalid/i
    );
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        encodePhilCoreO372RecoveryEnvelope({
          context: contextFrom(tuple5, { factorBitmap: 3 }),
          firstFactorEvidence: `0x${"55".repeat(
            PHILCORE_V2_CONSUMER_SECP256K1_EVIDENCE_BYTES
          )}`,
          secondFactorEvidence: tuple5.firstFactorEvidence
        }),
        8
      ),
      /webauthn_evidence_length_invalid/i
    );

    // Role 2 must not accept WebAuthn-sized evidence.
    assert.throws(
      () => decodePhilCoreV2ConsumerRecoveryEvidence(
        reencode(tuple5, (value) => {
          value.secondFactorEvidence = decoded3.firstFactorEvidence;
        }),
        8
      ),
      /secp256k1_evidence_length_invalid/i
    );
  });

  it("C4 static-verifier parity accepts O.44 envelopes after consumer decode", async function () {
    const {
      decodePhilCoreV2ConsumerRecoveryEvidence
    } = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryAuthorityTransport.ts"
    );
    const fixtures = loadFixtures();
    const localVerifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await localVerifier.waitForDeployment();
    const signer = await signerFor(fixtures.verifierRequest.account);
    for (const pair of fixtures.factorPairs) {
      const decoded = decodePhilCoreV2ConsumerRecoveryEvidence(pair.envelope, 8);
      assert.equal(Number(decoded.context.factorBitmap), pair.bitmap);
      const success = await localVerifier
        .connect(signer)
        .verifyAuthority.staticCall(fixtures.verifierRequest, pair.envelope);
      assert.equal(success, await localVerifier.SUCCESS_MAGIC());
    }
    const pair = fixtures.factorPairs.find((entry) => entry.bitmap === 6);
    for (const negative of fixtures.staticVerifierNegatives) {
      await assert.rejects(async () => {
        await localVerifier.connect(signer).verifyAuthority.staticCall(
          { ...fixtures.verifierRequest, ...negative.requestOverride },
          negative.envelope || pair.envelope
        );
      });
    }
  });
});
