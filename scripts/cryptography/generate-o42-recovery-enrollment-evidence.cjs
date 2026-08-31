const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O42_RECOVERY_ENROLLMENT_CEREMONY_EVIDENCE.json"
);

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8"));
}

function sha256File(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

function buildEvidence() {
  const o39 = readJson(
    "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"
  );
  const o41 = readJson(
    "config/solidity/O41_RECOVERY_ENROLLMENT_ENVIRONMENT_EVIDENCE.json"
  );
  return {
    schemaVersion: 1,
    phase: "O.42",
    canonicalPhase:
      "O.42 Real Standard Recovery Enrollment Ceremony and Production Initialization Package",
    classification: "LOCAL_INTERACTIVE_PRODUCTION_RECOVERY_ENROLLMENT",
    sourceHeadAtPhaseStart:
      "7b1315d8ecb85595351c88824ba9420a89daac47",
    result: "STOPPED_FAIL_CLOSED_BEFORE_CREDENTIAL_CREATION",
    readiness: "A_ENROLLMENT_CEREMONY_BLOCKED",
    publicMutationCount: 0,
    rpcAccessed: false,
    sepoliaAccessed: false,
    externalNetworkAccessed: false,
    environmentFileAccessed: false,
    pushed: false,
    baseline: {
      repository: "<repository-root>",
      branch: "codex/device-identity-v1",
      trackedWorktreeInitiallyClean: true,
      upstreamAtStart: "origin/main",
      aheadAtStart: 134,
      behindAtStart: 0,
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
      },
      securityRelevantDiscrepancy: null
    },
    canonicalIdentity: {"publicExportDisposition":"WITHHELD_PRIVATE_OWNER_OBSERVATION"},

























    staticPreflight: {
      o41EvidenceCurrent: true,
      canonicalRpId: o41.secureOrigin.rpId,
      canonicalOrigin: o41.secureOrigin.origin,
      listener: "127.0.0.1:18443",
      nonLoopbackListenerObserved: false,
      directoryMode: "0700",
      fileMode: "0600",
      safeStorageCertificateEnvelopeCreated: true,
      crashUploadDisabled: true,
      standardBeforePhysicalProbe: "READY_WITH_USER_WARNINGS",
      enhanced: "BLOCKED"
    },
    livePhysicalPreflight: {
      date: "WITHHELD_PRIVATE_OWNER_OBSERVATION",
      primaryIdentityUnlockedLocally: "WITHHELD_PRIVATE_OWNER_OBSERVATION",
      unlockSecretExposed: false,
      standardResult: "BLOCKED",
      state: "PREFLIGHT_BLOCKED",
      blockerIds: ["platformAuthenticator"],
      webAuthnApiAvailable: true,
      userVerifyingPlatformAuthenticatorAvailable: false,
      nativeLocalAuthenticationHelper: {
        available: true,
        provider: "macos_local_authentication_helper",
        userPresenceGuaranteed: true,
        biometricClaimSupported: true,
        promptedDuringDiagnostic: false,
        rawAuthenticationMaterialReturned: false
      },
      developmentRuntime: {
        electron: "39.8.10",
        macos: "26.5.2",
        architecture: "arm64",
        signature: "ADHOC_LINKER_SIGNED_NO_TEAM_IDENTIFIER"
      },
      conclusion:
        "Ordinary native local authentication is available, but the exact platform WebAuthn capability required for Role 0 is not."
    },
    packagedProbe: {
      currentSourceMatchedPackage: true,
      localAdHocHardenedSigningVerified: true,
      appleCredentialUsed: false,
      notarizationAttempted: false,
      protectedOriginRecordReusedAcrossApplicationIdentity: false,
      result: "STARTUP_FAILED_CLOSED_AT_RECOVERY_ENVIRONMENT",
      interpretation:
        "The safeStorage-bound origin envelope was not silently reused by a different application identity."
    },
    protectedLocalState: {"publicExportDisposition":"WITHHELD_PRIVATE_OWNER_OBSERVATION"},
    ceremony: {
      sessionCreated: false,
      role0Created: false,
      role1Created: false,
      role2Created: false,
      webAuthnCreationPromptShown: false,
      pairingSessionCreated: false,
      offlineFactorGenerated: false,
      restorationDrillPerformed: false,
      independenceQuestionsAsked: false,
      publicCommitmentApprovalRequested: false,
      stopReason:
        "The mandatory Role 0 platform WebAuthn preflight failed before credential creation."
    },
    initialization: {
      descriptorVersion: 3,
      configurationVersion: 3,
      recoveryEpoch: 1,
      validBitmaps: [3, 5, 6],
      role0Commitment: null,
      role1Commitment: null,
      role2Commitment: null,
      recoveryConfigurationHash: null,
      productionUserSaltGenerated: false,
      protectedInitializationPackageCreated: false,
      publicInitializationManifestCreated: false,
      factoryAddress: null,
      fixtureValuesUsed: false
    },
    regression: {
      o39FixturesAndEvidence: "PASS",
      o39FocusedTests: "13_PASSING",
      o40HistoricalBindingCorrection: "PASS",
      o40FocusedTests: "9_PASSING",
      o41Evidence: "PASS",
      o41FocusedTests: "PASS",
      o42FocusedTests: "PASS",
      o32ThroughO42: "247_PASSING_0_FAILING",
      typecheck: "PASS",
      solidityCompile: "PASS",
      solidityChanged: false,
      cleanIsolatedNpmCi: "PASS"
    },
    security: {
      trackedEvidenceSecretScan: "PASS",
      protectedStateStructuralScan: "PASS",
      rawCredentialIdExposed: false,
      offlineRecoveryFactorExposed: false,
      recoveryPrivateScalarExposed: false,
      pairingSecretExposed: false,
      productionSignatureCreated: false,
      productionSecretCommitted: false,
      highFindings: 0,
      criticalFindings: 0,
      externalAuditStillRequired: true
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
      renderer:
        sha256File("apps/philcore-desktop/src/renderer/app.js"),
      o38InitializationWorksheet:
        sha256File("docs/reference/O38_PRODUCTION_INITIALIZATION_WORKSHEET.md")
    },
    stopBoundary: {
      publicDeployment: false,
      publicTransaction: false,
      sepoliaOrExternalRpc: false,
      externalBundlerSubmission: false,
      publicFundsMoved: false,
      productionAccountDeployed: false,
      productionCredentialCreated: false,
      productionOfflineFactorCreated: false,
      productionSecretCommitted: false,
      rawCredentialIdExposed: false,
      offlineRecoveryFactorExposed: false,
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
      throw new Error("O42_RECOVERY_ENROLLMENT_EVIDENCE_STALE");
    }
    process.stdout.write("O.42 recovery enrollment evidence is current\n");
    return;
  }
  require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  return;
}

if (require.main === module) main();

module.exports = { buildEvidence };
