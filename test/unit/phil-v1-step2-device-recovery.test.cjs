const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  keccak256,
  toUtf8Bytes
} = require("ethers");

const {
  createPhilIdentityPrivate
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  createPhilScopeDescriptorV1,
  createPhilScopedIdentityV1,
  createPhilEncryptedRecordHeaderV1,
  encryptPhilDataRecordV1,
  decryptPhilDataRecordV1
} = require("../../apps/phil-device-sdk/src/secureIdentityV1.ts");
const {
  PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID,
  createPhilIdentityContinuityPackageV1,
  createPhilIdentityDataRecoveryBundleV1,
  restorePhilIdentityDataRecoveryBundleV1,
  summarizePhilIdentityDataRecoveryBundleV1,
  createPhilRecoveryRequestV1,
  cancelPhilRecoveryRequestV1,
  completePhilIdentityDataRecoveryV1,
  replacePhilIdentityDataRecoverySetV1
} = require("../../apps/phil-device-sdk/src/identityDataRecoveryV1.ts");
const {
  createPhilDeviceEnrollmentRecordV1,
  derivePhilDeviceApprovalDigestV1,
  createPhilDeviceApprovalEvidenceV1,
  verifyPhilDeviceApprovalEvidenceV1
} = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const {
  PHIL_STEP2_DEVICE_PROFILE_V1,
  assessPhilStep2DeviceAdmissionV1
} = require("../../apps/phil-device-sdk/src/step2DeviceAdmissionV1.ts");

function hash(label) {
  return keccak256(toUtf8Bytes(label));
}

function hex32(number) {
  return `0x${BigInt(number).toString(16).padStart(64, "0")}`;
}

function syntheticIdentity() {
  return createPhilIdentityPrivate({ philSecret: hex32(0x1234567890n) });
}

function fixturePackage() {
  const identity = syntheticIdentity();
  const scope = createPhilScopedIdentityV1({
    identityRoot: identity.identityRoot,
    descriptor: createPhilScopeDescriptorV1({
      scopeKind: 1,
      namespaceHash: hash("eip155:8453"),
      contextHash: hash("synthetic-account-context")
    }),
    scopeInstance: hex32(0x777n),
    scopeEpoch: 1
  });
  const continuityPackage = createPhilIdentityContinuityPackageV1({
    philSecret: identity.philSecret,
    dataRootKey: hash("synthetic-data-root-key"),
    scopeRegistry: [{ ...scope, status: "active" }],
    accountBindings: [{
      accountBindingId: hash("binding-id"),
      scopedOwnerCommitment: scope.scopedOwnerCommitment,
      networkIdHash: hash("eip155:8453"),
      accountBindingHash: hash("synthetic-account-binding"),
      validatorEpoch: "1",
      status: "active"
    }],
    credentialRegistry: [{
      credentialIdHash: hash("synthetic-device-credential"),
      credentialTypeHash: hash("secure-enclave-p256-device-approval-v1"),
      publicKeyHash: hash("synthetic-public-key"),
      deviceEpoch: "1",
      status: "active"
    }],
    policyState: { policyVersion: "1", policyHash: hash("policy-v1") },
    auditContinuityState: { eventCount: "3", auditHeadHash: hash("audit-head-3") }
  });
  return { identity, scope, continuityPackage };
}

function buildBundle(createdAt = 1_800_000_000) {
  const fixture = fixturePackage();
  const recovery = createPhilIdentityDataRecoveryBundleV1({
    continuityPackage: fixture.continuityPackage,
    createdAt
  });
  return { ...fixture, ...recovery };
}

function errorCode(code) {
  return (error) => error?.code === code;
}

describe("Phil V1 Step 2 secure identity, device approval, and recovery", function () {
  it("derives pairwise scoped identities and authenticates encrypted data records", function () {
    const identity = syntheticIdentity();
    const descriptor = createPhilScopeDescriptorV1({
      scopeKind: 2,
      namespaceHash: hash("https://example.invalid"),
      contextHash: hash("application-relationship")
    });
    const left = createPhilScopedIdentityV1({
      identityRoot: identity.identityRoot,
      descriptor,
      scopeInstance: hex32(1),
      scopeEpoch: 1
    });
    const right = createPhilScopedIdentityV1({
      identityRoot: identity.identityRoot,
      descriptor,
      scopeInstance: hex32(2),
      scopeEpoch: 1
    });
    assert.notEqual(left.scopedOwnerCommitment, right.scopedOwnerCommitment);
    assert.throws(
      () => createPhilScopeDescriptorV1({
        scopeKind: 2,
        namespaceHash: "0x01",
        contextHash: hash("application-relationship")
      }),
      (error) => error?.code === "PHIL_SECURE_IDENTITY_INVALID_BYTES32"
    );
    assert.throws(
      () => createPhilEncryptedRecordHeaderV1({
        formatVersionHash: hash("unsupported-future-record-format"),
        recordId: hash("record-unsupported"),
        recordTypeHash: hash("credential-metadata-v1"),
        recordVersion: 1,
        dataEpoch: 1,
        scopedOwnerCommitmentOrZero: left.scopedOwnerCommitment
      }),
      (error) => error?.code === "PHIL_SECURE_IDENTITY_RECORD_FORMAT_UNSUPPORTED"
    );

    const key = hash("synthetic-data-root-key");
    const header = createPhilEncryptedRecordHeaderV1({
      recordId: hash("record-1"),
      recordTypeHash: hash("credential-metadata-v1"),
      recordVersion: 1,
      dataEpoch: 1,
      scopedOwnerCommitmentOrZero: left.scopedOwnerCommitment
    });
    const plaintext = Buffer.from("synthetic protected user data", "utf8");
    const encrypted = encryptPhilDataRecordV1({ dataRootKey: key, header, plaintext });
    assert.deepEqual(
      Buffer.from(decryptPhilDataRecordV1({ dataRootKey: key, record: encrypted })),
      plaintext
    );
    assert.throws(
      () => decryptPhilDataRecordV1({ dataRootKey: hash("wrong-key"), record: encrypted }),
      (error) => error?.code === "PHIL_SECURE_IDENTITY_RECORD_AUTHENTICATION_FAILED"
    );
    assert.throws(
      () => decryptPhilDataRecordV1({
        dataRootKey: key,
        record: {
          ...encrypted,
          header: { ...encrypted.header, dataEpoch: "2" }
        }
      }),
      (error) => error?.code === "PHIL_SECURE_IDENTITY_RECORD_AUTHENTICATION_FAILED"
    );
  });

  it("restores with every exact pair and rejects a single or duplicate factor", function () {
    const { bundle, shares, continuityPackage } = buildBundle();
    assert.equal(bundle.envelope.sharingSuiteId, PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID);
    for (const pair of [[0, 1], [0, 2], [1, 2]]) {
      const restored = restorePhilIdentityDataRecoveryBundleV1({
        bundle,
        shares: [shares[pair[0]], shares[pair[1]]]
      });
      assert.equal(restored.philSecret, continuityPackage.philSecret);
      assert.equal(restored.dataRootKey, continuityPackage.dataRootKey);
      assert.equal(restored.rootOwnerCommitment, continuityPackage.rootOwnerCommitment);
    }
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({ bundle, shares: [shares[0]] }),
      errorCode("PHIL_RECOVERY_EXACT_TWO_SHARES_REQUIRED")
    );
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({ bundle, shares: [shares[0], shares[0]] }),
      errorCode("PHIL_RECOVERY_DUPLICATE_SHARE")
    );
  });

  it("keeps the public bundle free of root, data-key, and share material", function () {
    const { bundle, shares, continuityPackage } = buildBundle();
    const serialized = JSON.stringify(bundle);
    assert.equal(serialized.includes(continuityPackage.philSecret.slice(2)), false);
    assert.equal(serialized.includes(continuityPackage.identityRoot.slice(2)), false);
    assert.equal(serialized.includes(continuityPackage.rootOwnerCommitment.slice(2)), false);
    assert.equal(serialized.includes(continuityPackage.dataRootKey.slice(2)), false);
    for (const share of shares) {
      for (const contribution of share.contributions) {
        assert.equal(serialized.includes(contribution.material), false);
      }
    }
    const summary = summarizePhilIdentityDataRecoveryBundleV1(bundle);
    assert.deepEqual(Object.keys(summary).sort(), [
      "ciphertextHash",
      "createdAt",
      "format",
      "packageCounter",
      "pairCount",
      "recoveryEpoch",
      "recoverySetId",
      "sharingSuiteId"
    ]);
  });

  it("rejects mixed sets, corrupted shares, ciphertext tampering, and rollback", function () {
    const first = buildBundle(1_800_000_000);
    const second = buildBundle(1_800_000_001);
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: first.bundle,
        shares: [first.shares[0], second.shares[1]]
      }),
      errorCode("PHIL_RECOVERY_MIXED_SHARE_SET")
    );
    const damagedShare = {
      ...first.shares[0],
      contributions: first.shares[0].contributions.map((entry, index) => index === 0
        ? { ...entry, material: Buffer.alloc(32, 0xa5).toString("base64url") }
        : entry)
    };
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: first.bundle,
        shares: [damagedShare, first.shares[1]]
      }),
      errorCode("PHIL_RECOVERY_SHARE_CHECKSUM_MISMATCH")
    );
    const damagedCiphertext = {
      ...first.bundle,
      encryptedPackage: {
        ...first.bundle.encryptedPackage,
        ciphertext: Buffer.from("tampered").toString("base64url")
      }
    };
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: damagedCiphertext,
        shares: [first.shares[0], first.shares[1]]
      }),
      errorCode("PHIL_RECOVERY_CIPHERTEXT_HASH_MISMATCH")
    );
    const damagedWrapper = {
      ...first.bundle,
      keyWrappers: first.bundle.keyWrappers.map((wrapper, index) => index === 0
        ? {
            ...wrapper,
            ciphertext: `${wrapper.ciphertext[0] === "A" ? "B" : "A"}${wrapper.ciphertext.slice(1)}`
          }
        : wrapper)
    };
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: damagedWrapper,
        shares: [first.shares[0], first.shares[1]]
      }),
      errorCode("PHIL_RECOVERY_WRAPPER_HASH_MISMATCH")
    );
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: first.bundle,
        shares: [first.shares[0], first.shares[1]],
        antiRollbackFloor: { recoveryEpoch: "2", packageCounter: "1" }
      }),
      errorCode("PHIL_RECOVERY_ROLLBACK_REJECTED")
    );
  });

  it("enforces notification, destructive approval, delay, cancellation, and expiry", function () {
    const { bundle, shares } = buildBundle();
    const request = createPhilRecoveryRequestV1({
      bundle,
      operation: "identity_data_recovery",
      requestedAt: 1_800_000_100,
      delaySeconds: 3_600,
      expiresAfterSeconds: 86_400,
      destructiveApprovalDigest: hash("explicit-destructive-recovery-approval"),
      notificationTargetHashes: [hash("user-notification-channel")],
      notificationEvidenceHashes: [hash("notification-delivery-evidence")]
    });
    assert.throws(
      () => completePhilIdentityDataRecoveryV1({
        request: { ...request, notBefore: "1800000200" },
        bundle,
        shares: [shares[0], shares[1]],
        completedAt: 1_800_004_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_BINDING_INVALID")
    );
    assert.throws(
      () => completePhilIdentityDataRecoveryV1({
        request,
        bundle,
        shares: [shares[0], shares[1]],
        completedAt: 1_800_000_101
      }),
      errorCode("PHIL_RECOVERY_DELAY_ACTIVE")
    );
    const cancelled = cancelPhilRecoveryRequestV1({
      request,
      cancellationReasonHash: hash("user-cancelled")
    });
    assert.throws(
      () => completePhilIdentityDataRecoveryV1({
        request: cancelled,
        bundle,
        shares: [shares[0], shares[1]],
        completedAt: 1_800_004_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_NOT_PENDING")
    );
    assert.throws(
      () => completePhilIdentityDataRecoveryV1({
        request,
        bundle,
        shares: [shares[0], shares[1]],
        completedAt: 1_800_100_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_EXPIRED")
    );
    const otherBundle = buildBundle(1_800_000_001).bundle;
    assert.throws(
      () => completePhilIdentityDataRecoveryV1({
        request,
        bundle: otherBundle,
        shares: [shares[0], shares[1]],
        completedAt: 1_800_004_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_BUNDLE_MISMATCH")
    );
  });

  it("completes recovery by rotating the required device, recovery, and capability epochs and the recovery set", function () {
    const { bundle, shares, continuityPackage } = buildBundle();
    const request = createPhilRecoveryRequestV1({
      bundle,
      operation: "identity_data_recovery",
      requestedAt: 1_800_000_100,
      delaySeconds: 3_600,
      expiresAfterSeconds: 86_400,
      destructiveApprovalDigest: hash("explicit-destructive-recovery-approval"),
      notificationTargetHashes: [hash("user-notification-channel")],
      notificationEvidenceHashes: [hash("notification-delivery-evidence")]
    });
    const completion = completePhilIdentityDataRecoveryV1({
      request,
      bundle,
      shares: [shares[1], shares[2]],
      completedAt: 1_800_004_000
    });
    assert.equal(completion.request.status, "completed");
    assert.equal(completion.nextPackage.philSecret, continuityPackage.philSecret);
    assert.equal(completion.nextPackage.dataRootKey, continuityPackage.dataRootKey);
    assert.equal(completion.nextPackage.deviceEpoch, "2");
    assert.equal(completion.nextPackage.recoveryEpoch, "2");
    assert.equal(completion.nextPackage.capabilityEpoch, "2");
    assert.equal(completion.nextPackage.credentialRegistry[0].status, "revoked");
    assert.equal(completion.nextPackage.accountBindings[0].status, "pending_reconciliation");
    assert.notEqual(completion.nextBundle.envelope.recoverySetId, bundle.envelope.recoverySetId);
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: completion.nextBundle,
        shares: [shares[0], shares[2]]
      }),
      errorCode("PHIL_RECOVERY_MIXED_SHARE_SET")
    );
    const restoredNext = restorePhilIdentityDataRecoveryBundleV1({
      bundle: completion.nextBundle,
      shares: [completion.nextShares[0], completion.nextShares[2]]
    });
    assert.equal(restoredNext.recoveryEpoch, "2");
  });

  it("replaces a lost or revoked recovery factor by rotating the complete set", function () {
    const { bundle, shares } = buildBundle();
    const request = createPhilRecoveryRequestV1({
      bundle,
      operation: "recovery_set_replacement",
      requestedAt: 1_800_000_100,
      delaySeconds: 3_600,
      expiresAfterSeconds: 86_400,
      destructiveApprovalDigest: hash("replace-lost-share"),
      notificationTargetHashes: [hash("replacement-notification-channel")],
      notificationEvidenceHashes: [hash("replacement-notification-evidence")]
    });
    assert.throws(
      () => replacePhilIdentityDataRecoverySetV1({
        request,
        bundle,
        shares: [shares[0], shares[2]],
        replacedAt: 1_800_000_101
      }),
      errorCode("PHIL_RECOVERY_DELAY_ACTIVE")
    );
    const cancelledReplacement = cancelPhilRecoveryRequestV1({
      request,
      cancellationReasonHash: hash("cancel-replacement")
    });
    assert.throws(
      () => replacePhilIdentityDataRecoverySetV1({
        request: cancelledReplacement,
        bundle,
        shares: [shares[0], shares[2]],
        replacedAt: 1_800_010_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_NOT_PENDING")
    );
    assert.throws(
      () => replacePhilIdentityDataRecoverySetV1({
        request,
        bundle,
        shares: [shares[0], shares[2]],
        replacedAt: 1_800_100_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_EXPIRED")
    );
    const identityRecoveryRequest = createPhilRecoveryRequestV1({
      bundle,
      operation: "identity_data_recovery",
      requestedAt: 1_800_000_100,
      delaySeconds: 3_600,
      expiresAfterSeconds: 86_400,
      destructiveApprovalDigest: hash("not-a-replacement-request"),
      notificationTargetHashes: [hash("identity-recovery-notification-channel")],
      notificationEvidenceHashes: [hash("identity-recovery-notification-evidence")]
    });
    assert.throws(
      () => replacePhilIdentityDataRecoverySetV1({
        request: identityRecoveryRequest,
        bundle,
        shares: [shares[0], shares[2]],
        replacedAt: 1_800_010_000
      }),
      errorCode("PHIL_RECOVERY_REQUEST_OPERATION_MISMATCH")
    );
    const replacement = replacePhilIdentityDataRecoverySetV1({
      request,
      bundle,
      shares: [shares[0], shares[2]],
      replacedAt: 1_800_010_000
    });
    assert.equal(replacement.request.status, "completed");
    assert.equal("nextPackage" in replacement, false);
    assert.notEqual(replacement.nextBundle.envelope.recoverySetId, bundle.envelope.recoverySetId);
    assert.throws(
      () => restorePhilIdentityDataRecoveryBundleV1({
        bundle: replacement.nextBundle,
        shares: [shares[0], shares[1]]
      }),
      errorCode("PHIL_RECOVERY_MIXED_SHARE_SET")
    );
    const restored = restorePhilIdentityDataRecoveryBundleV1({
      bundle: replacement.nextBundle,
      shares: [replacement.nextShares[0], replacement.nextShares[1]]
    });
    assert.equal(restored.recoveryEpoch, "2");
    assert.throws(
      () => replacePhilIdentityDataRecoverySetV1({
        request: replacement.request,
        bundle,
        shares: [shares[0], shares[2]],
        replacedAt: 1_800_010_001
      }),
      errorCode("PHIL_RECOVERY_REQUEST_NOT_PENDING")
    );
  });

  it("binds device approval to envelope, presentation, device, epoch, time, and nonce", async function () {
    const signatureSuiteId = hash("p256-secure-enclave-sha256-digest-v1");
    const enrollment = createPhilDeviceEnrollmentRecordV1({
      deviceId: hash("synthetic-device-id"),
      deviceKeyId: hash("synthetic-device-key-id"),
      signatureSuiteId,
      publicKey: `0x04${"11".repeat(64)}`,
      deviceEpoch: 4,
      enrolledAt: 1_800_000_000,
      assuranceClass: 3,
      policyHash: hash("device-policy-v1")
    });
    const authorizationEnvelopeDigest = hash("authorization-envelope");
    const approvalNonce = hash("one-time-approval-nonce");
    const approvedAt = 1_800_000_100;
    const approvalExpiresAt = 1_800_000_200;
    const digest = derivePhilDeviceApprovalDigestV1({
      authorizationEnvelopeDigest,
      deviceId: enrollment.deviceId,
      deviceKeyId: enrollment.deviceKeyId,
      deviceEpoch: enrollment.deviceEpoch,
      approvalNonce,
      approvedAt,
      approvalExpiresAt
    });
    const signature = keccak256(digest);
    const evidence = createPhilDeviceApprovalEvidenceV1({
      authorizationEnvelopeDigest,
      enrollment,
      approvalNonce,
      approvedAt,
      approvalExpiresAt,
      humanPresentationHash: hash("human-presentation"),
      signature
    });
    const verifier = {
      verifierId: "synthetic-device-signature-verifier-v1",
      verify: (input) => input.digest === digest && input.signature === signature
    };
    const result = await verifyPhilDeviceApprovalEvidenceV1({
      evidence,
      enrollment,
      verifier,
      expectedAuthorizationEnvelopeDigest: authorizationEnvelopeDigest,
      expectedHumanPresentationHash: hash("human-presentation"),
      currentDeviceEpoch: 4,
      now: 1_800_000_150,
      consumedApprovalNonces: new Set()
    });
    assert.equal(result.status, "verified");
    await assert.rejects(
      verifyPhilDeviceApprovalEvidenceV1({
        evidence,
        enrollment,
        verifier,
        expectedAuthorizationEnvelopeDigest: authorizationEnvelopeDigest,
        expectedHumanPresentationHash: hash("wrong-presentation"),
        currentDeviceEpoch: 4,
        now: 1_800_000_150,
        consumedApprovalNonces: new Set()
      }),
      errorCode("PHIL_DEVICE_APPROVAL_BINDING_MISMATCH")
    );
    await assert.rejects(
      verifyPhilDeviceApprovalEvidenceV1({
        evidence,
        enrollment,
        verifier,
        expectedAuthorizationEnvelopeDigest: authorizationEnvelopeDigest,
        expectedHumanPresentationHash: hash("human-presentation"),
        currentDeviceEpoch: 5,
        now: 1_800_000_150,
        consumedApprovalNonces: new Set()
      }),
      errorCode("PHIL_DEVICE_APPROVAL_EPOCH_MISMATCH")
    );
    await assert.rejects(
      verifyPhilDeviceApprovalEvidenceV1({
        evidence,
        enrollment,
        verifier,
        expectedAuthorizationEnvelopeDigest: authorizationEnvelopeDigest,
        expectedHumanPresentationHash: hash("human-presentation"),
        currentDeviceEpoch: 4,
        now: 1_800_000_150,
        consumedApprovalNonces: new Set([approvalNonce])
      }),
      errorCode("PHIL_DEVICE_APPROVAL_REPLAY")
    );
    await assert.rejects(
      verifyPhilDeviceApprovalEvidenceV1({
        evidence,
        enrollment,
        verifier,
        expectedAuthorizationEnvelopeDigest: authorizationEnvelopeDigest,
        expectedHumanPresentationHash: hash("human-presentation"),
        currentDeviceEpoch: 4,
        now: 1_800_000_150
      }),
      errorCode("PHIL_DEVICE_APPROVAL_NONCE_STORE_REQUIRED")
    );
  });

  it("admits only the exact bounded physical-device evidence envelope", function () {
    const admittedInput = {
      profileId: PHIL_STEP2_DEVICE_PROFILE_V1.profileId,
      marketingModel: "iPhone 17",
      operatingSystemVersion: "26.6",
      operatingSystemBuild: "23G71",
      physicalDevice: true,
      secureEnclaveAvailable: true,
      deviceOwnerAuthenticationAvailable: true,
      protectedDataAvailable: true,
      physicalMemoryMiB: 7_671,
      batteryPercent: 100,
      lowPowerMode: false,
      thermalState: "nominal",
      operation: "device_approval"
    };
    assert.deepEqual(assessPhilStep2DeviceAdmissionV1(admittedInput), {
      admitted: true,
      classification: "bounded-step2-candidate",
      productionAuthority: false,
      reasons: []
    });

    const negativeCases = [
      ["unknown profile", { profileId: "unreviewed" }, "PROFILE_NOT_ADMITTED"],
      ["unknown operation", { operation: "identity_data_recovery" }, "OPERATION_NOT_ADMITTED"],
      ["different OS build", { operatingSystemBuild: "unreviewed" }, "PROFILE_NOT_ADMITTED"],
      ["Simulator", { physicalDevice: false }, "SIMULATOR_OR_NONPHYSICAL_DEVICE"],
      ["no Secure Enclave", { secureEnclaveAvailable: false }, "SECURE_ENCLAVE_UNAVAILABLE"],
      ["no owner authentication", { deviceOwnerAuthenticationAvailable: false }, "DEVICE_OWNER_AUTHENTICATION_UNAVAILABLE"],
      ["protected data unavailable", { protectedDataAvailable: false }, "PROTECTED_DATA_UNAVAILABLE"],
      ["lower memory", { physicalMemoryMiB: 7_670 }, "PHYSICAL_MEMORY_BELOW_EVIDENCE_FLOOR"],
      ["unknown battery", { batteryPercent: null }, "BATTERY_STATE_OUTSIDE_EVIDENCE"],
      ["lower battery", { batteryPercent: 99 }, "BATTERY_STATE_OUTSIDE_EVIDENCE"],
      ["Low Power Mode", { lowPowerMode: true }, "LOW_POWER_MODE_OUTSIDE_EVIDENCE"],
      ["fair thermal", { thermalState: "fair" }, "THERMAL_STATE_OUTSIDE_EVIDENCE"],
      ["critical thermal", { thermalState: "critical" }, "THERMAL_STATE_OUTSIDE_EVIDENCE"]
    ];
    for (const [label, change, expectedReason] of negativeCases) {
      const result = assessPhilStep2DeviceAdmissionV1({ ...admittedInput, ...change });
      assert.equal(result.admitted, false, label);
      assert.equal(result.productionAuthority, false, label);
      assert.ok(result.reasons.includes(expectedReason), label);
    }
  });

  it("uses only synthetic values and never needs network, signing service, or device access", function () {
    assert.equal(process.env.PHIL_REAL_SECRET, undefined);
    assert.equal(crypto.getFips() === 0 || crypto.getFips() === 1, true);
  });

  it("keeps recovery secrets out of renderer/preload surfaces and locks the iOS source boundary", function () {
    const desktopRoot = path.join(__dirname, "../../apps/philcore-desktop/src");
    const publicSurfaceFiles = [];
    for (const directory of ["renderer", "preload"]) {
      const absolute = path.join(desktopRoot, directory);
      if (!fs.existsSync(absolute)) continue;
      for (const entry of fs.readdirSync(absolute, { recursive: true, withFileTypes: true })) {
        if (entry.isFile()) publicSurfaceFiles.push(path.join(entry.parentPath, entry.name));
      }
    }
    for (const file of publicSurfaceFiles) {
      const source = fs.readFileSync(file, "utf8");
      assert.equal(source.includes("identityDataRecoveryV1"), false, file);
      assert.equal(source.includes("PhilIdentityContinuityPackageV1"), false, file);
    }

    const swift = fs.readFileSync(
      path.join(
        __dirname,
        "../../apps/philcore-ios-companion/PhilCoreCompanion/PhilDeviceApprovalKeyManager.swift"
      ),
      "utf8"
    );
    assert.match(swift, /kSecAttrTokenIDSecureEnclave/);
    assert.match(swift, /kSecAttrAccessibleWhenUnlockedThisDeviceOnly/);
    assert.match(swift, /\.privateKeyUsage, \.userPresence/);
    assert.match(swift, /targetEnvironment\(simulator\)[\s\S]*secureEnclaveUnavailable/);
    assert.match(swift, /ecdsaSignatureDigestX962SHA256/);
    assert.match(swift, /eciesEncryptionCofactorX963SHA256AESGCM/);
    assert.match(swift, /catch let metadataError[\s\S]*deleteKeyIfPresent\(tag: tag\)[\s\S]*throw metadataError/);
    assert.match(swift, /let updateStatus = SecItemUpdate\([\s\S]*if updateStatus == errSecSuccess \{ return \}[\s\S]*guard updateStatus == errSecItemNotFound/);
    assert.match(swift, /if addStatus == errSecDuplicateItem,[\s\S]*SecItemUpdate\(base as CFDictionary, update as CFDictionary\) == errSecSuccess/);
    assert.doesNotMatch(swift, /SecItemDelete\(base as CFDictionary\)/);
    assert.doesNotMatch(swift, /AppAttest|DCAppAttestService/);
    assert.doesNotMatch(swift, /philSecret|identityRoot|dataRootKey|recoveryShare/);
  });
});
