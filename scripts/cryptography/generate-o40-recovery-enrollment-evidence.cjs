const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
require("tsx/cjs");

const {
  evaluateConsumerRecoveryEnrollmentPreflight
} = require(
  "../../apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollmentPreflight.ts"
);
const {
  buildEvidence: buildO39Evidence
} = require("./generate-o39-consumer-recovery-evidence.cjs");
const {
  run: runDeploymentPreparation
} = require("../ethereum-sepolia/prepare-o40-v2-deployment.cjs");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O40_RECOVERY_ENROLLMENT_PREFLIGHT_EVIDENCE.json"
);
const O40_SOURCE_HEAD = "7a7722bdec6fbff0a484d865ff0fc9af7bc352f5";
const O40_EVIDENCE_COMMIT = "9797c947cc1ab2283bc43fa48f0b5a41ee4d4b7d";

function sha256HistoricalFile(revision, relative) {
  return crypto.createHash("sha256")
    .update(execFileSync("git", ["show", `${revision}:${relative}`], {
      cwd: ROOT,
      maxBuffer: 8 * 1024 * 1024
    }))
    .digest("hex");
}

function currentEnvironment(role1Class) {
  return {
    rpId: undefined,
    origin: undefined,
    localApplicationOrigin: "file://",
    secureContext: false,
    stableApplicationOrigin: false,
    webAuthnApiAvailable: false,
    platformAuthenticatorAvailable: false,
    secureCredentialStorageAdapterAvailable: false,
    credentialStorageEncrypted: false,
    opaqueCredentialReferencesOnly: false,
    rawCredentialIdsLogged: false,
    privateKeysLogged: false,
    terminalOutputSecretSafe: false,
    clipboardUsedForSecrets: false,
    crashLogsMayCaptureSecrets: true,
    localEnrollmentRecordsIgnored: false,
    localDirectoryMode: null,
    localFileMode: null,
    backupBehaviorUnderstood: true,
    directAttestationTrustValidationAvailable: false,
    offlineSecureDisplayAvailable: false,
    offlineSecureRestoreInputAvailable: false,
    role1Class,
    secondaryDeviceHandoffAvailable: false,
    hardwareKeyCeremonyAvailable: false,
    custodyLimitationsAcknowledged: false
  };
}

function buildEvidence() {
  const o39 = buildO39Evidence();
  const standard = evaluateConsumerRecoveryEnrollmentPreflight(
    currentEnvironment("STANDARD_SECONDARY_DEVICE")
  );
  const enhanced = evaluateConsumerRecoveryEnrollmentPreflight(
    currentEnvironment("ENHANCED_HARDWARE_KEY")
  );
  const preparation = runDeploymentPreparation(["--dry-run"]);
  return {
    schemaVersion: 1,
    phase: "O.40",
    canonicalPhase:
      "O.40 Real Three-Domain Recovery Enrollment Ceremony and Production Initialization Completion",
    classification: "LOCAL_INTERACTIVE_ENROLLMENT_AND_INITIALIZATION",
    sourceHeadAtPhaseStart: O40_SOURCE_HEAD,
    result: "STOPPED_FAIL_CLOSED_BEFORE_CREDENTIAL_CREATION",
    readiness: "A_INITIALIZATION_STILL_BLOCKED",
    publicMutationCount: 0,
    rpcAccessed: false,
    sepoliaAccessed: false,
    environmentFileAccessed: false,
    productionCredentialsCreated: false,
    productionSecretsGenerated: false,
    baseline: {
      repository: "<repository-root>",
      branch: "codex/device-identity-v1",
      trackedWorktreeInitiallyClean: true,
      v1AccountSourceSha256:
        "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
      v1FactorySourceSha256:
        "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    },
    hashChronology: {
      o38AcceptedRuntimeKeccak256:
        o39.baseline.acceptedO38RuntimeKeccak256,
      o39HistoricallyReportedInitialRuntimeKeccak256Incorrect:
        o39.baseline.historicallyReportedInitialV2RuntimeKeccak256Incorrect,
      actualO39PreChangeRuntimeKeccak256:
        o39.baseline.actualO39PreChangeRuntimeKeccak256,
      actualO39PostChangeRuntimeKeccak256: {
        verifier:
          o39.contracts.PhilCoreV2StaticAuthorityVerifier.runtimeKeccak256,
        account:
          o39.contracts.PhilCoreV2MinimalAccountV2.runtimeKeccak256,
        factory:
          o39.contracts.PhilCoreV2MinimalAccountFactoryV2.runtimeKeccak256
      },
      historicalReproductionCommit:
        "25bffe61ff008a85e29c24a32e8ca2f5550c4855",
      cause:
        "O.39 reporting transcription error; no matching tracked artifact, compiler drift, or repository corruption",
      resolution: "CORRECTED_WITH_HISTORICAL_ERROR_PRESERVED"
    },
    currentContractPackage: {
      compiler: {
        solidity: "0.8.27+commit.40a35a09.Emscripten.clang",
        evmVersion: "cancun",
        optimizerEnabled: true,
        optimizerRuns: 200,
        viaIR: true
      },
      contracts: o39.contracts,
      fixtureSha256: o39.fixtures.sha256
    },
    enrollmentEnvironment: {
      applicationLoadMode: "FILE_ORIGIN",
      rpId: null,
      origin: null,
      webAuthnPlatformProbe:
        "NOT_RUN_BECAUSE_NO_CANONICAL_SECURE_RP_ORIGIN",
      existingSafeStoragePrimitive:
        "ELECTRON_SAFE_STORAGE_PRESENT_BUT_NOT_INTEGRATED_FOR_O39_CREDENTIAL_IDS",
      credentialStorageAdapter: "ABSENT",
      secondaryDeviceHandoff: "ABSENT",
      hardwareKeyCeremonyIntegration: "ABSENT",
      offlineRevealAndRestoreInterface: "ABSENT",
      directAttestationTrustValidation: "ABSENT",
      runtimeBackupPolicy: "BE_AND_BS_MUST_BOTH_BE_FALSE",
      rawCredentialIdLoggingInO39Foundation: false,
      endToEndCrashAndDebugLogExclusionEstablished: false,
      standardPreflight: standard,
      enhancedPreflight: enhanced
    },
    enrollment: {
      role1ChoiceRequested: false,
      role0Created: false,
      role1Created: false,
      offlineFactorCreated: false,
      restorationDrillPerformed: false,
      reason:
        "Common preflight blockers make either profile unsafe before any physical user action."
    },
    initialization: {
      recoveryConfigurationCreated: false,
      productionUserSaltCreated: false,
      tupleFieldCount: 20,
      knownOrSelectedPendingLiveFieldCount: 15,
      missingEnrollmentDerivedFields: [
        "primaryDeviceRecoveryCommitment",
        "hardwareSecurityKeyCommitment",
        "independentRecoveryFactorCommitment",
        "recoveryConfigurationHash"
      ],
      protectedLocalPackageCreated: false,
      publicManifestCreated: false,
      fixtureValuesUsed: false
    },
    infrastructure: {
      confirmationTarget:
        "0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7",
      confirmationTargetClassification:
        "SELECTED_PENDING_FRESH_LIVE_VERIFICATION",
      historicalRuntimeKeccak256:
        "0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad",
      futureVerifierAddress: null,
      futureFactoryAddress: null,
      futureAccountAddress: null,
      preparation
    },
    blockers: [
      "canonical stable HTTPS RP ID/origin not configured; desktop loads from file://",
      "direct attestation is mandatory but trust-root validation is explicitly unimplemented",
      "no integrated encrypted recovery-credential storage adapter",
      "no Standard secondary-device handoff or Enhanced hardware-key ceremony integration",
      "no dedicated no-log offline reveal and restoration input",
      "end-to-end crash/debug-log exclusion for enrollment secrets is not established",
      "the pinned development dependency tree retains existing High advisories and remains Beta-blocked, although production dependencies audit clean"
    ],
    sourceEvidenceSha256: {
      preflight:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollmentPreflight.ts"
        ),
      enrollment:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollment.ts"
        ),
      webAuthn:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts"
        ),
      desktopMain:
        sha256HistoricalFile(
          O40_SOURCE_HEAD,
          "apps/philcore-desktop/src/main/main.cjs"
        ),
      desktopRuntimeHost:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "apps/philcore-desktop/src/main/runtime-host.cjs"
        ),
      desktopBridge:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "apps/philcore-desktop/src/shared/bridge-contract.cjs"
        ),
      deploymentTemplate:
        sha256HistoricalFile(
          O40_EVIDENCE_COMMIT,
          "config/ethereum-sepolia/O40_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json"
        )
    },
    tests: {
      o40FocusedPassing: 9,
      o40FocusedFailing: 0,
      o32ThroughO40Passing: 238,
      o32ThroughO40Failing: 0,
      typecheckPassed: true,
      solidityCompilePassed: true,
      isolatedTrackedOnlyCopy: {
        npmCi: "PASS",
        solidityFilesCompiled: 60,
        regression: "238_PASSING_0_FAILING",
        typecheck: "PASS",
        deterministicEvidence: "PASS",
        localGitIndexRequiredByO37_9Test: true
      }
    },
    security: {
      staticAnalysis: {
        generalRepositorySlither: "PASS_NO_UNRESOLVED_HIGH_OR_CRITICAL",
        v2SolidityChangedByO40: false,
        v2O39DetectorDispositionRetained:
          "23 occurrences; 0 unmitigated High and 0 Critical"
      },
      npmAudit: {
        productionDependencies: {
          low: 0,
          moderate: 0,
          high: 0,
          critical: 0
        },
        completePinnedDevelopmentTree: {
          low: 10,
          moderate: 2,
          high: 8,
          critical: 0,
          existingBetaGate:
            "BLOCKED_PENDING_HIGH_ADVISORY_ACCEPTANCE_OR_REMEDIATION"
        }
      },
      o40TrackedFileSecretScan: "PASS",
      productionSecretsCommitted: false,
      rawCredentialIdsCommitted: false,
      offlineRecoveryFactorCommitted: false,
      productionSignaturesCommitted: false,
      publicDeploymentPerformed: false,
      publicTransactionPerformed: false,
      pushPerformed: false,
      externalAuditStillRequired: true
    }
  };
}

function stringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const output = stringify(buildEvidence());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT)
      || fs.readFileSync(OUTPUT, "utf8") !== output) {
      throw new Error("O40_RECOVERY_ENROLLMENT_EVIDENCE_STALE");
    }
    process.stdout.write("O.40 recovery enrollment evidence is current\n");
    return;
  }
  fs.writeFileSync(OUTPUT, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT)}\n`);
}

if (require.main === module) main();

module.exports = { buildEvidence };
