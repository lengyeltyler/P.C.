require("tsx/cjs");

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const {
  evaluateConsumerRecoveryEnrollmentPreflight
} = require(
  "../../apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollmentPreflight.ts"
);
const {
  run: runDeploymentPreparation
} = require(
  "../../scripts/ethereum-sepolia/prepare-o40-v2-deployment.cjs"
);
const {
  buildEvidence: buildO40Evidence
} = require(
  "../../scripts/cryptography/generate-o40-recovery-enrollment-evidence.cjs"
);

const ROOT = path.resolve(__dirname, "../..");
const O40_SOURCE_HEAD = "7a7722bdec6fbff0a484d865ff0fc9af7bc352f5";
const O40_EVIDENCE_COMMIT = "9797c947cc1ab2283bc43fa48f0b5a41ee4d4b7d";

function historicalSource(relative, revision = O40_SOURCE_HEAD) {
  return execFileSync("git", ["show", `${revision}:${relative}`], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024
  });
}

function readyEnvironment(overrides = {}) {
  return {
    rpId: "recovery.philcore.example",
    origin: "https://recovery.philcore.example",
    localApplicationOrigin: "https://recovery.philcore.example",
    secureContext: true,
    stableApplicationOrigin: true,
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true,
    secureCredentialStorageAdapterAvailable: true,
    credentialStorageEncrypted: true,
    opaqueCredentialReferencesOnly: true,
    rawCredentialIdsLogged: false,
    privateKeysLogged: false,
    terminalOutputSecretSafe: true,
    clipboardUsedForSecrets: false,
    crashLogsMayCaptureSecrets: false,
    localEnrollmentRecordsIgnored: true,
    localDirectoryMode: 0o700,
    localFileMode: 0o600,
    backupBehaviorUnderstood: true,
    directAttestationTrustValidationAvailable: true,
    offlineSecureDisplayAvailable: true,
    offlineSecureRestoreInputAvailable: true,
    role1Class: "STANDARD_SECONDARY_DEVICE",
    secondaryDeviceHandoffAvailable: true,
    hardwareKeyCeremonyAvailable: false,
    custodyLimitationsAcknowledged: true,
    ...overrides
  };
}

describe("O.40 recovery enrollment environment preflight", function () {
  it("accepts a fully integrated Standard environment", function () {
    const result = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment()
    );
    assert.equal(result.status, "READY");
    assert.equal(result.productionCredentialCreationPermitted, true);
    assert.deepEqual(result.blockerIds, []);
  });

  it("accepts a fully integrated Enhanced environment", function () {
    const result = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment({
        role1Class: "ENHANCED_HARDWARE_KEY",
        secondaryDeviceHandoffAvailable: false,
        hardwareKeyCeremonyAvailable: true
      })
    );
    assert.equal(result.status, "READY");
  });

  it("retains the cross-custody user warning without weakening hard gates", function () {
    const result = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment({ custodyLimitationsAcknowledged: false })
    );
    assert.equal(result.status, "READY_WITH_USER_WARNINGS");
    assert.equal(result.productionCredentialCreationPermitted, true);
    assert.equal(result.warnings.length, 1);
  });

  it("rejects file origins, RP substitution, and unstable application origins", function () {
    for (const mutation of [
      {
        rpId: undefined,
        origin: undefined,
        localApplicationOrigin: "file:///PhilCore/index.html",
        secureContext: false,
        stableApplicationOrigin: false
      },
      {
        rpId: "recovery.philcore.example",
        origin: "https://attacker.example",
        localApplicationOrigin: "https://attacker.example"
      },
      {
        localApplicationOrigin: "https://other.philcore.example"
      }
    ]) {
      const result = evaluateConsumerRecoveryEnrollmentPreflight(
        readyEnvironment(mutation)
      );
      assert.equal(result.status, "BLOCKED");
      assert.equal(result.productionCredentialCreationPermitted, false);
    }
  });

  it("rejects each secret-handling or protected-storage defect", function () {
    for (const mutation of [
      { secureCredentialStorageAdapterAvailable: false },
      { credentialStorageEncrypted: false },
      { opaqueCredentialReferencesOnly: false },
      { rawCredentialIdsLogged: true },
      { privateKeysLogged: true },
      { terminalOutputSecretSafe: false },
      { clipboardUsedForSecrets: true },
      { crashLogsMayCaptureSecrets: true },
      { localEnrollmentRecordsIgnored: false },
      { localDirectoryMode: 0o755 },
      { localFileMode: 0o644 },
      { offlineSecureDisplayAvailable: false },
      { offlineSecureRestoreInputAvailable: false }
    ]) {
      const result = evaluateConsumerRecoveryEnrollmentPreflight(
        readyEnvironment(mutation)
      );
      assert.equal(result.status, "BLOCKED");
    }
  });

  it("rejects absent attestation trust and either missing Role 1 ceremony", function () {
    const noTrust = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment({ directAttestationTrustValidationAvailable: false })
    );
    assert.equal(noTrust.status, "BLOCKED");
    assert.ok(noTrust.blockerIds.includes("direct_attestation_trust"));

    const noStandard = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment({ secondaryDeviceHandoffAvailable: false })
    );
    assert.ok(noStandard.blockerIds.includes("role1_ceremony"));

    const noEnhanced = evaluateConsumerRecoveryEnrollmentPreflight(
      readyEnvironment({
        role1Class: "ENHANCED_HARDWARE_KEY",
        secondaryDeviceHandoffAvailable: false,
        hardwareKeyCeremonyAvailable: false
      })
    );
    assert.ok(noEnhanced.blockerIds.includes("role1_ceremony"));
  });

  it("binds the historical O.40 fail-closed observations to its source", function () {
    const main = historicalSource(
      "apps/philcore-desktop/src/main/main.cjs"
    );
    const verifier = historicalSource(
      "apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts",
      O40_EVIDENCE_COMMIT
    );
    const bridge = historicalSource(
      "apps/philcore-desktop/src/shared/bridge-contract.cjs"
    );

    assert.match(main, /mainWindow\.loadFile\(/);
    assert.doesNotMatch(main, /recovery\.philcore/);
    const currentMain = fs.readFileSync(
      path.join(ROOT, "apps/philcore-desktop/src/main/main.cjs"),
      "utf8"
    );
    assert.match(currentMain, /createRecoverySecureOrigin/);
    assert.match(currentMain, /recoveryOrigin\.start/);
    assert.match(
      verifier,
      /Direct attestation trust root validation is not implemented/
    );
    assert.doesNotMatch(bridge, /consumerRecoveryEnrollment|recoveryEnrollment/);
  });

  it("runs current guarded preparation only to the initialization boundary", function () {
    const result = runDeploymentPreparation(["--dry-run"]);
    assert.equal(result.publicMutationCount, 0);
    assert.equal(result.rpcAccessed, false);
    assert.equal(result.credentialsAccessed, false);
    assert.equal(result.initialization.status, "INITIALIZATION_BLOCKED");
    assert.equal(result.create2, null);
    assert.equal(result.broadcastPathImplemented, false);
    assert.ok(result.initialization.missing.includes(
      "primaryDeviceRecoveryCommitment"
    ));
    assert.ok(result.initialization.missing.includes("futureFactoryAddress"));
    assert.throws(
      () => runDeploymentPreparation(["--broadcast"]),
      /O40_PUBLIC_MUTATION_PROHIBITED/
    );
  });

  it("keeps the fail-closed machine evidence deterministic and secret-free", function () {
    const evidencePath = path.join(
      ROOT,
      "config/solidity/O40_RECOVERY_ENROLLMENT_PREFLIGHT_EVIDENCE.json"
    );
    const evidence = buildO40Evidence();
    assert.equal(
      fs.readFileSync(evidencePath, "utf8"),
      `${JSON.stringify(evidence, null, 2)}\n`
    );
    assert.equal(evidence.readiness, "A_INITIALIZATION_STILL_BLOCKED");
    assert.equal(evidence.productionCredentialsCreated, false);
    assert.equal(evidence.productionSecretsGenerated, false);
    assert.equal(evidence.publicMutationCount, 0);
    assert.equal(evidence.rpcAccessed, false);
    assert.equal(evidence.infrastructure.futureAccountAddress, null);
    const serialized = JSON.stringify(evidence);
    assert.doesNotMatch(
      serialized,
      /PHIL39-V1-(?:[A-Z2-7]{4}-){8,}[A-Z2-7]{4,}/
    );
    assert.doesNotMatch(serialized, /BEGIN (?:EC |RSA )?PRIVATE KEY/);
  });
});
