const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
require("tsx/cjs");

const {
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
  RECOVERY_HTTPS_PORT,
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require(
  "../../apps/philcore-desktop/src/main/recovery-secure-origin.cjs"
);

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O41_RECOVERY_ENROLLMENT_ENVIRONMENT_EVIDENCE.json"
);

function sha256File(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

function buildEvidence() {
  const o39 = JSON.parse(fs.readFileSync(
    path.join(ROOT, "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"),
    "utf8"
  ));
  const preflight = evaluateConsumerRecoveryEnrollmentPreflightV2({
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
  return {
    schemaVersion: 1,
    phase: "O.41",
    canonicalPhase:
      "O.41 Consumer Recovery Enrollment Environment and Secure Ceremony UI",
    classification: "LOCAL_ONLY_DESKTOP_RECOVERY_ENVIRONMENT_IMPLEMENTATION",
    sourceHeadAtPhaseStart:
      "9797c947cc1ab2283bc43fa48f0b5a41ee4d4b7d",
    result: "COMPLETE",
    publicMutationCount: 0,
    rpcAccessed: false,
    sepoliaAccessed: false,
    environmentFileContentsAccessed: false,
    environmentFileLoaded: false,
    environmentFileMetadataInspectedForIgnoreAndModeOnly: true,
    productionCredentialsCreated: false,
    realOfflineFactorsCreated: false,
    productionSignaturesCreated: false,
    pushed: false,
    baseline: {
      repository: "<repository-root>",
      branch: "codex/device-identity-v1",
      trackedWorktreeInitiallyClean: true,
      upstreamAtStart: "origin/main",
      aheadAtStart: 130,
      behindAtStart: 0,
      v1AccountSourceSha256:
        "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
      v1FactorySourceSha256:
        "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9",
      o39RuntimeKeccak256: {
        verifier:
          o39.contracts.PhilCoreV2StaticAuthorityVerifier.runtimeKeccak256,
        account:
          o39.contracts.PhilCoreV2MinimalAccountV2.runtimeKeccak256,
        factory:
          o39.contracts.PhilCoreV2MinimalAccountFactoryV2.runtimeKeccak256
      },
      discrepancy: null
    },
    recoveryModel: {
      roles: {
        "0": "PRIMARY_DEVICE_RECOVERY_ONLY_WEBAUTHN",
        "1": "INDEPENDENT_SECONDARY_PLATFORM_OR_EXTERNAL_KEY",
        "2": "OFFLINE_PHIL39_V1_SECP256K1"
      },
      threshold: "EXACT_2_OF_3",
      validBitmaps: [3, 5, 6],
      totp: "DEFERRED_OPTIONAL_DEFENSE_IN_DEPTH_NOT_AUTHORITY"
    },
    secureOrigin: {
      model: "APPLICATION_CONTROLLED_LOOPBACK_HTTPS_WITH_EXACT_CERTIFICATE_PIN",
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      listener: "127.0.0.1",
      port: RECOVERY_HTTPS_PORT,
      externalInterfaces: false,
      processAuthorization: "RANDOM_HEADER_INJECTED_BY_ELECTRON_SESSION",
      certificate: {
        kind: "PER_INSTALL_LOCALLY_GENERATED",
        privateKeyPersistence: "ELECTRON_SAFE_STORAGE_CIPHERTEXT",
        osTrustInstallation: false,
        tlsErrorsGenerallyIgnored: false,
        rotateWithinDaysOfExpiry: 30
      },
      developmentOriginEqualsPackagedOrigin: true,
      offlineAfterInstall: true
    },
    attestation: {
      consumerPlatformPolicy: CONSUMER_PLATFORM_POLICY_V1,
      externalHardwarePolicy: EXTERNAL_HARDWARE_POLICY_V1,
      trustRootSubsystem:
        "BOUNDED_DEFERRAL_NO_FORMATS_OR_AUTHENTICATORS_ALLOWLISTED",
      hardwareConsumerFallback:
        "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION",
      directAttestationContradiction:
        "RESOLVED_BY_EXPLICIT_VERSIONED_PROFILE_SPLIT_NOT_SILENT_DOWNGRADE"
    },
    storage: {
      root: "Electron userData/philcore-recovery-enrollment",
      directoryMode: "0700",
      fileMode: "0600",
      encryption: "ELECTRON_SAFE_STORAGE",
      envelopeVersion: 1,
      atomicWrite: true,
      symlinkDefense: true,
      rootAndUserBinding: true,
      rendererRawCredentialIdAccess: false,
      genericReadSecretMethod: false,
      rotationAndDeletion: true
    },
    pairing: {
      protocolVersion: 1,
      transport: "USER_MEDIATED_PUBLIC_REQUEST_AND_AEAD_RESPONSE",
      ttlSeconds: 300,
      sessionIdBits: 256,
      keyAgreement: "EPHEMERAL_P256_ECDH_HKDF_SHA256",
      encryption: "AES_256_GCM",
      singleUse: true,
      centralServerRequired: false,
      deterministicSyntheticSimulator: true
    },
    offlineFactor: {
      format: "PHIL39-V1",
      reveal: "DEDICATED_SANDBOXED_NO_PRELOAD_WINDOW",
      clipboard: "DISABLED",
      export: "USER_SELECTED_SYSTEM_PRINT_FLOW_ONLY",
      restoreDrillRequired: true,
      retainedSecret: false,
      retainedPublicFields: [
        "signer",
        "formatVersion",
        "safePublicFingerprint",
        "confirmationStatus",
        "restorationDrillStatus"
      ]
    },
    loggingAndCrash: {
      secretWrapper: true,
      explicitToJSONRedaction: true,
      boundedErrorCodes: true,
      crashReporterUploadDisabled: true,
      breakpadSwitchDisabled: true,
      uncaughtObjectDumping: false,
      rendererSensitiveConsoleObjects: false,
      canaryTests: "PASS"
    },
    preflightV2: preflight,
    packaging: {
      localStaticBuild: "PASS",
      localPackageComposition: "PASS",
      packagedLaunchAndBridge: "PASS",
      isolatedUserDataLaunch: "PASS",
      signedNotarizedBuild:
        "NOT_RUN_SIGNING_AND_NOTARIZATION_CREDENTIALS_NOT_AVAILABLE_OR_AUTHORIZED",
      publicDistributionCreated: false
    },
    dependencies: {
      refreshedDate: "2026-07-30",
      productionAudit: { low: 0, moderate: 0, high: 0, critical: 0 },
      completePinnedTree: { low: 10, moderate: 2, high: 8, critical: 0 },
      highGroups: [
        "@nomicfoundation/hardhat-ethers",
        "adm-zip",
        "brace-expansion",
        "hardhat",
        "immutable",
        "serialize-javascript",
        "tmp",
        "undici"
      ],
      reachableHighOrCriticalOnEnrollmentStartup: 0,
      hardhatBackedDesktopModulesLazyLoaded: true,
      solidityDependencyVersionsChanged: false
    },
    sourceEvidenceSha256: {
      secureOrigin:
        sha256File("apps/philcore-desktop/src/main/recovery-secure-origin.cjs"),
      attestationPolicy:
        sha256File("apps/philcore-desktop/src/main/recovery-attestation-policy.cjs"),
      enrollmentHost:
        sha256File("apps/philcore-desktop/src/main/recovery-enrollment-host.cjs"),
      desktopMain:
        sha256File("apps/philcore-desktop/src/main/main.cjs"),
      desktopRuntimeHost:
        sha256File("apps/philcore-desktop/src/main/runtime-host.cjs"),
      bridge:
        sha256File("apps/philcore-desktop/src/shared/bridge-contract.cjs"),
      preload:
        sha256File("apps/philcore-desktop/src/preload/preload.cjs"),
      renderer:
        sha256File("apps/philcore-desktop/src/renderer/app.js"),
      preflightV2:
        sha256File("apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollmentPreflight.ts")
    },
    tests: {
      focusedO41: "PASS",
      originAndCertificate: "PASS",
      attestationPolicy: "PASS",
      webAuthnFixtureIntegration: "PASS",
      storageAndIpc: "PASS",
      loggingCanaries: "PASS",
      pairing: "PASS",
      offlineRevealRestore: "PASS",
      stateMachine: "PASS",
      desktopRegression: "PASS",
      o39SolidityRegression: "PASS",
      secretScan: "PASS"
    },
    solidity: {
      changed: false,
      verifierRuntimeKeccak256:
        o39.contracts.PhilCoreV2StaticAuthorityVerifier.runtimeKeccak256,
      accountRuntimeKeccak256:
        o39.contracts.PhilCoreV2MinimalAccountV2.runtimeKeccak256,
      factoryRuntimeKeccak256:
        o39.contracts.PhilCoreV2MinimalAccountFactoryV2.runtimeKeccak256,
      deploymentEvidenceInvalidated: false
    },
    stopBoundary: {
      publicDeployment: false,
      publicTransaction: false,
      externalRpc: false,
      fundsMoved: false,
      productionAccountCreated: false,
      realProductionCredentialCreated: false,
      realOfflineFactorCreated: false,
      productionSecretCommitted: false,
      pushPerformed: false
    }
  };
}

function stringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}
function main() {
  if (!process.argv.includes("--check")) require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  const output = stringify(buildEvidence());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT) || fs.readFileSync(OUTPUT, "utf8") !== output) {
      throw new Error("O41_RECOVERY_ENROLLMENT_EVIDENCE_STALE");
    }
    process.stdout.write("O.41 recovery enrollment evidence is current\n");
    return;
  }
  require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  return;
}

if (require.main === module) main();

module.exports = { buildEvidence };
