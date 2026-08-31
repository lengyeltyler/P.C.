const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O42_1_PLATFORM_WEBAUTHN_COMPATIBILITY_EVIDENCE.json"
);

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8"));
}

function sha256(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

function buildEvidence() {
  const o39 = readJson(
    "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"
  );
  return {
    schemaVersion: 1,
    phase: "O.42.1",
    canonicalPhase:
      "O.42.1 macOS Electron Platform WebAuthn Enablement, Packaged Identity Repair, and Ceremony Resume",
    classification:
      "LOCAL_INTERACTIVE_DESKTOP_WEBAUTHN_COMPATIBILITY_AND_ENROLLMENT_REPAIR",
    sourceHeadAtPhaseStart:
      "626e57cb67d2a9bd3e8ed7c97b440f101894f7f5",
    result: "STOPPED_FAIL_CLOSED_BEFORE_DISPOSABLE_CREDENTIAL",
    readiness: "A_PLATFORM_WEBAUTHN_STILL_BLOCKED",
    publicMutationCount: 0,
    pushed: false,
    rootCause: {
      userDenialOccurred: false,
      priorElectron: "39.8.10",
      priorConfigureWebAuthnApiAvailable: false,
      selectedElectron: "41.10.3",
      exactPin: true,
      configureBeforeReady: true,
      chromiumFeatureFlagsUsed: false,
      missingPriorConfiguration: true,
      missingPriorKeychainEntitlement: true,
      remainingBlocker:
        "EXACT_DEVELOPER_ID_PROVISIONING_PROFILE_NOT_INSTALLED",
      observedLaunchError: "NO_MATCHING_PROFILE_FOUND"
    },
    macosIdentity: {
      model: "WITHHELD_PRIVATE_OWNER_OBSERVATION",
      architecture: "arm64",
      macosVersion: "26.5.2",
      bundleIdentifier: "com.philcore.desktop.localalpha",
      teamIdentifier: "B342738S82",
      applicationIdentifier:
        "B342738S82.com.philcore.desktop.localalpha",
      webAuthnKeychainAccessGroup:
        "B342738S82.com.philcore.desktop.localalpha.webauthn",
      wildcardAccessGroup: false,
      hardenedRuntime: true,
      developerIdIdentityAvailable: true,
      matchingProvisioningProfileInstalled: false
    },
    packageValidation: {
      packagedElectron: "41.10.3",
      developerIdStaticSignatureObjectsVerified: 32,
      developerIdLaunch: "BLOCKED_BY_MACOS_PROFILE_VALIDATION",
      notarized: false,
      gatekeeperAccepted: false,
      adHocCleanUserDataLaunch: "PASS",
      adHocPlatformWebAuthnIdentity: "PACKAGED_IDENTITY_MISMATCH",
      contextIsolationPreserved: true,
      rendererSandboxPreserved: true,
      crashUploadDisabled: true
    },
    protectedLocalState: {"publicExportDisposition":"WITHHELD_PRIVATE_OWNER_OBSERVATION"},
    certificateMigration: {
      schemaVersion: 2,
      firstInstallCreates: true,
      exactIdentityRestartReuses: true,
      preEnrollmentIdentityRebindPreservesCertificate: true,
      mismatchWithCredentialFailsClosed: true,
      inaccessibleSafeStorageFailsClosed: true,
      corruptionFailsClosed: true,
      silentRegenerationWithCredentials: false
    },
    disposableWebAuthn: {
      label: "O42_1_DISPOSABLE_PLATFORM_WEBAUTHN_TEST_ONLY",
      implementationReady: true,
      executed: false,
      reason: "STABLE_SIGNED_IDENTITY_NOT_LAUNCHABLE",
      rawCredentialIdReturned: false,
      productionAuthorityCreated: false
    },
    preflightV3: {
      primaryMacRole0: "BLOCKED",
      iphoneRole1: "BLOCKED",
      completeStandardCeremony: "BLOCKED",
      blockers: [
        "developerIdProvisioningProfile",
        "disposableCreationAssertion",
        "packagedBuild",
        "iphoneCompanionConnectivity",
        "iphoneRole1CredentialPolicy"
      ]
    },
    iphone: {
      intendedDevice: "iPhone",
      client: "Safari",
      loopbackReachableFromPhone: false,
      localhostResolvesToPhone: true,
      lanOrQrEndpointImplemented: false,
      tlsBypassImplemented: false,
      platformPasskeySyncModel: "ICLOUD_KEYCHAIN_SYNC_CAPABLE",
      requiredBackupFlags: { backupEligible: false, backupState: false },
      role1Readiness: "BLOCKED"
    },
    ceremony: {
      resumed: false,
      productionRole0Created: false,
      productionRole1Created: false,
      offlineFactorCreated: false,
      initializationPackageCreated: false,
      stopReason:
        "Complete Standard preflight did not reach READY_WITH_WARNINGS."
    },
    dependencies: {
      productionAudit: { low: 0, moderate: 0, high: 0, critical: 0 },
      completeAudit: { low: 10, moderate: 2, high: 7, critical: 0 },
      electronHighOrCriticalAdvisory: false,
      frozenSolidityVersionsChanged: false
    },
    frozenHashes: {
      v1AccountSourceSha256:
        "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
      v1FactorySourceSha256:
        "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9",
      v2RuntimeKeccak256: {
        verifier:
          o39.contracts.PhilCoreV2StaticAuthorityVerifier.runtimeKeccak256,
        account:
          o39.contracts.PhilCoreV2MinimalAccountV2.runtimeKeccak256,
        factory:
          o39.contracts.PhilCoreV2MinimalAccountFactoryV2.runtimeKeccak256
      }
    },
    sourceSha256: {
      platformWebAuthn:
        sha256("apps/philcore-desktop/src/main/platform-webauthn.cjs"),
      preflightV3:
        sha256("apps/philcore-desktop/src/main/recovery-preflight-v3.cjs"),
      secureOrigin:
        sha256("apps/philcore-desktop/src/main/recovery-secure-origin.cjs"),
      enrollmentHost:
        sha256("apps/philcore-desktop/src/main/recovery-enrollment-host.cjs"),
      main: sha256("apps/philcore-desktop/src/main/main.cjs"),
      renderer: sha256("apps/philcore-desktop/src/renderer/app.js"),
      disposable:
        sha256(
          "apps/philcore-desktop/src/renderer/disposable-platform-webauthn.js"
        ),
      signedEntitlements:
        sha256("apps/philcore-desktop/build/entitlements.mac.plist"),
      packageLock: sha256("package-lock.json")
    },
    security: {
      productionSecretCommitted: false,
      rawCredentialIdExposed: false,
      offlineFactorExposed: false,
      privateKeyExposed: false,
      credentialCreated: false,
      externalAuditStillRequired: true
    },
    stopBoundary: {
      publicDeployment: false,
      publicTransaction: false,
      sepoliaOrExternalRpc: false,
      externalBundlerSubmission: false,
      publicFundsMoved: false,
      productionAccountDeployed: false,
      productionSignatureCreated: false,
      userOperationCreated: false
    }
  };
}

function serialized() {
  return `${JSON.stringify(buildEvidence(), null, 2)}\n`;
}

if (require.main === module) {
  if (!process.argv.includes("--check")) require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  const expected = serialized();
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT) || fs.readFileSync(OUTPUT, "utf8") !== expected) {
      process.stderr.write("O.42.1 evidence is stale\n");
      process.exit(1);
    }
    process.stdout.write("O.42.1 evidence is current\n");
  } else {
    require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
    return;
  }
}

module.exports = { OUTPUT, buildEvidence, serialized };
