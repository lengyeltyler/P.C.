require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS,
  evaluateConsumerRecoveryEnrollmentPreflightV2
} = require(
  "../../apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollmentPreflight.ts"
);
const {
  CONSUMER_PLATFORM_POLICY_V1,
  EXTERNAL_HARDWARE_POLICY_V1
} = require(
  "../../apps/philcore-desktop/src/main/recovery-attestation-policy.cjs"
);
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require(
  "../../apps/philcore-desktop/src/main/recovery-secure-origin.cjs"
);

const ROOT = path.resolve(__dirname, "../..");

function sha256(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

describe("O.41 recovery enrollment environment", function () {
  it("classifies Standard independently from Enhanced", function () {
    const result = evaluateConsumerRecoveryEnrollmentPreflightV2({
      secureOriginReady: true,
      rpIdReady: true,
      consumerPlatformPolicyV1Ready: true,
      encryptedStorageReady: true,
      role0PathReady: true,
      standardRole1HandoffReady: true,
      externalHardwareTrustRootsReady: false,
      externalHardwareChainValidationReady: false,
      offlineRevealRestoreReady: true,
      loggingCrashExclusionReady: true,
      dependencyAdvisoryGateReady: true,
      packagedEnvironmentReady: true,
      interactivePhysicalDeviceValidationComplete: false
    });
    assert.equal(
      result.standard,
      PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.READY_WITH_USER_WARNINGS
    );
    assert.equal(result.enhanced, PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.BLOCKED);
    assert.equal(result.ceremonyReady, true);
    assert.equal(result.productionCredentialCreated, false);
    assert.deepEqual(
      result.enhancedBlockers,
      ["hardware_trust_roots", "hardware_chain_validation"]
    );
  });

  it("freezes one canonical offline-capable RP and explicit policy commitments", function () {
    assert.equal(RECOVERY_RP_ID, "recovery.philcore.localhost");
    assert.equal(RECOVERY_ORIGIN, "https://recovery.philcore.localhost:18443");
    assert.equal(CONSUMER_PLATFORM_POLICY_V1.rpId, RECOVERY_RP_ID);
    assert.equal(CONSUMER_PLATFORM_POLICY_V1.origin, RECOVERY_ORIGIN);
    assert.equal(CONSUMER_PLATFORM_POLICY_V1.attestation, "none");
    assert.equal(CONSUMER_PLATFORM_POLICY_V1.manufacturerProvenanceClaimed, false);
    assert.equal(EXTERNAL_HARDWARE_POLICY_V1.readiness, "BLOCKED");
    assert.equal(EXTERNAL_HARDWARE_POLICY_V1.supportedAttestationFormats.length, 0);
  });

  it("preserves all frozen V1 and O.39 V2 Solidity sources", function () {
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
    const evidence = JSON.parse(fs.readFileSync(
      path.join(ROOT, "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"),
      "utf8"
    ));
    assert.equal(
      evidence.contracts.PhilCoreV2StaticAuthorityVerifier.runtimeKeccak256,
      "0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7"
    );
    assert.equal(
      evidence.contracts.PhilCoreV2MinimalAccountV2.runtimeKeccak256,
      "0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519"
    );
    assert.equal(
      evidence.contracts.PhilCoreV2MinimalAccountFactoryV2.runtimeKeccak256,
      "0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95"
    );
  });

  it("keeps exact 2-of-3 and excludes TOTP from authority", function () {
    const renderer = fs.readFileSync(
      path.join(ROOT, "apps/philcore-desktop/src/renderer/app.js"),
      "utf8"
    );
    assert.match(renderer, /Exactly two are required/u);
    assert.match(renderer, /TOTP is deferred/u);
    assert.match(renderer, /not a recovery authority/u);
    assert.doesNotMatch(renderer, /navigator\.clipboard/u);
  });
});
