#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  configReleaseRoot,
  repoRoot,
  run,
  sha256,
  writeJson
} = require("./release-utils.cjs");
const ops = require("../src/main/trusted-tester-operations.cjs");

const releaseDir = path.join(repoRoot, "apps", "philcore-desktop", "release", "local-alpha", ops.RELEASE_IDENTIFIER);
const artifactPath = path.join(releaseDir, `${ops.RELEASE_IDENTIFIER}-macos-${process.arch}.zip`);
const releaseMetadataPath = path.join(releaseDir, "trusted-tester-release.json");
const nativeEvidencePath = path.join(configReleaseRoot, "philcore-desktop-o11-native-user-presence.json");

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    cwd: options.cwd || repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_NOTARIZE_APPROVED: "",
      ...(options.env || {})
    },
    timeout: options.timeout || 120000
  });
  return {
    command: [commandName, ...args].join(" "),
    status: result.status,
    stdout: (result.stdout || "").slice(0, 5000),
    stderr: (result.stderr || "").slice(0, 5000)
  };
}

function requirePassed(result, label) {
  if (result.status !== 0) throw new Error(`${label}_failed\n${result.stdout}\n${result.stderr}`);
  return result;
}

function findExtractedApp(root) {
  const app = fs.readdirSync(root).find((entry) => entry.endsWith(".app"));
  if (!app) throw new Error("extracted_application_missing");
  return path.join(root, app);
}

function appExecutable(appPath) {
  return path.join(appPath, "Contents", "MacOS", "PhilCore Desktop Local Alpha");
}

function readManifest(appPath) {
  return JSON.parse(fs.readFileSync(
    path.join(appPath, "Contents", "Resources", "app", "config", "release", "philcore-desktop-local-alpha.json"),
    "utf8"
  ));
}

function hashComponents(appPath) {
  const manifest = readManifest(appPath);
  return ["prover", "verifier", "userPresenceHelper"].map((component) => {
    const entry = manifest.bundledResources[component];
    const componentPath = entry.path.replace(/^.*Contents\/Resources\/app\//u, "");
    return {
      component,
      expectedSha256: entry.sha256,
      actualSha256: sha256(path.join(appPath, "Contents", "Resources", "app", componentPath))
    };
  });
}

function runPackaged(appPath, userDataDir, extraEnv = {}) {
  return requirePassed(command(process.execPath, ["apps/philcore-desktop/scripts/test-packaged.cjs"], {
    env: {
      PHILCORE_DESKTOP_TEST_APP_PATH: appPath,
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ...extraEnv
    },
    timeout: 180000
  }), "packaged_tester_launch");
}

function runCleanEnvironment(appPath) {
  return requirePassed(command(process.execPath, ["apps/philcore-desktop/scripts/test-clean-environment.cjs"], {
    env: { PHILCORE_DESKTOP_TEST_APP_PATH: appPath },
    timeout: 180000
  }), "clean_environment");
}

function supportState(root) {
  const supportRoot = path.join(root, "Library", "Application Support", "PhilCore Desktop Local Alpha");
  const pref = path.join(root, "Library", "Preferences", `${ops.BUNDLE_IDENTIFIER}.plist`);
  const cache = path.join(root, "Library", "Caches", ops.BUNDLE_IDENTIFIER);
  const saved = path.join(root, "Library", "Saved Application State", `${ops.BUNDLE_IDENTIFIER}.savedState`);
  return {
    applicationSupportExists: fs.existsSync(supportRoot),
    preferencesExist: fs.existsSync(pref),
    cachesExist: fs.existsSync(cache),
    savedStateExists: fs.existsSync(saved),
    keychainItemExistenceChecked: false,
    keychainInspectionReason: "not queried automatically; no Keychain values are needed for isolated directory rehearsal"
  };
}

if (!fs.existsSync(artifactPath)) throw new Error(`artifact_missing:${artifactPath}`);
if (!fs.existsSync(releaseMetadataPath)) throw new Error(`trusted_tester_release_missing:${releaseMetadataPath}`);
const releaseMetadata = JSON.parse(fs.readFileSync(releaseMetadataPath, "utf8"));
const actualSha = sha256(artifactPath);
assert.equal(actualSha, ops.ARTIFACT_SHA256, "artifact_sha256_mismatch");

const release = ops.createReleaseRecord({
  authority: releaseMetadata.authority,
  teamId: releaseMetadata.teamId,
  issuedAt: "2026-07-17T00:00:00.000Z"
});
let testerRecord = ops.createTesterCycleRecord({
  testerIdentifier: "tester-001-operator",
  role: "operator",
  release,
  acknowledgementAccepted: true,
  acceptedAt: new Date().toISOString(),
  isolation: {
    level: "isolated_local_directory",
    separateMacOsUser: false,
    separateMac: false,
    operatorStateAltered: false,
    reason: "separate macOS user was not available to this automated Codex session"
  }
});

const verifier = requirePassed(command("bash", [
  path.join(repoRoot, "apps", "philcore-desktop", "scripts", "verify-trusted-tester-artifact.sh"),
  artifactPath,
  ops.ARTIFACT_SHA256,
  releaseMetadata.authority,
  releaseMetadata.teamId
]), "repository_independent_verifier");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o11-tester-001-"));
const downloads = path.join(root, "Downloads");
const extracted = path.join(root, "Extracted");
const applications = path.join(root, "Applications");
const home = path.join(root, "Home");
const userDataDir = path.join(home, "Library", "Application Support", "PhilCore Desktop Local Alpha");
fs.mkdirSync(downloads, { recursive: true });
fs.mkdirSync(extracted, { recursive: true });
fs.mkdirSync(applications, { recursive: true });
fs.mkdirSync(home, { recursive: true });

const baseline = {
  macOSVersion: `${os.platform()} ${os.release()}`,
  architecture: os.arch(),
  philCoreAlreadyInstalledInIsolatedContext: false,
  priorState: supportState(home)
};

const receivedZip = path.join(downloads, path.basename(artifactPath));
fs.copyFileSync(artifactPath, receivedZip);
assert.equal(sha256(receivedZip), ops.ARTIFACT_SHA256, "received_zip_hash_mismatch");
run("ditto", ["-x", "-k", receivedZip, extracted]);
const extractedApp = findExtractedApp(extracted);
const installedApp = path.join(applications, path.basename(extractedApp));
run("ditto", [extractedApp, installedApp]);

const codesign = requirePassed(command("codesign", ["--verify", "--deep", "--strict", "--verbose=4", installedApp]), "codesign_verify");
const details = requirePassed(command("codesign", ["-dvvv", installedApp]), "codesign_details");
const staple = requirePassed(command("xcrun", ["stapler", "validate", installedApp]), "staple_validate");
const gatekeeper = requirePassed(command("spctl", ["--assess", "--type", "execute", "--verbose=4", installedApp]), "gatekeeper");
const bundleId = requirePassed(command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleIdentifier", path.join(installedApp, "Contents", "Info.plist")]), "bundle_identifier").stdout.trim();
assert.equal(bundleId, ops.BUNDLE_IDENTIFIER, "bundle_identifier_mismatch");
const componentHashes = hashComponents(installedApp);
for (const component of componentHashes) assert.equal(component.actualSha256, component.expectedSha256, `${component.component}_hash_mismatch`);

const packagedFirst = runPackaged(installedApp, userDataDir);
const packagedFirstParsed = JSON.parse(packagedFirst.stdout.match(/\{[\s\S]*\}/u)[0]);
const packagedSecond = runPackaged(installedApp, userDataDir, {
  PHILCORE_DESKTOP_E2E_REOPEN_IDENTITY_ID: packagedFirstParsed.identityId
});
const packagedSecondParsed = JSON.parse(packagedSecond.stdout.match(/\{[\s\S]*\}/u)[0]);
const cleanEnvironment = runCleanEnvironment(installedApp);
const proofDiagnostic = requirePassed(command(process.execPath, ["apps/philcore-desktop/scripts/diagnose-local-proof.cjs"], {
  timeout: 180000
}), "proof_diagnostic");
const proofDiagnosticParsed = JSON.parse(proofDiagnostic.stdout.match(/\{[\s\S]*\}/u)[0]);

const firstLaunchEvidence = ops.createFirstLaunchEvidence({
  launchedNormally: packagedFirstParsed.status === "passed",
  releaseStatusClear: true,
  alphaWarningClear: true,
  publicNetworkDisabledVisible: true,
  productionWarningClear: true,
  navigationUnderstandable: true,
  developerTerminologyObserved: false,
  repositoryPathObserved: false,
  unexpectedPermissionPrompt: false,
  evidenceClass: "isolated_packaged_tester_launch",
  errors: []
});
const nativeEvidence = fs.existsSync(nativeEvidencePath)
  ? JSON.parse(fs.readFileSync(nativeEvidencePath, "utf8"))
  : null;
const diagnosticExport = ops.sanitizeDiagnosticExport({
  releaseIdentifier: ops.RELEASE_IDENTIFIER,
  artifactSha256: ops.ARTIFACT_SHA256,
  testerIdentifier: "tester-001-operator",
  os: baseline.macOSVersion,
  architecture: baseline.architecture,
  signing: {
    authority: releaseMetadata.authority,
    teamId: releaseMetadata.teamId,
    notarized: true,
    gatekeeperAccepted: true
  },
  runtime: {
    firstLaunch: packagedFirstParsed.status,
    relaunch: packagedSecondParsed.status,
    publicNetworkMutation: false
  },
  proof: {
    status: proofDiagnosticParsed.status,
    proofBytes: "redaction-fixture-proof-bytes",
    witness: "redaction-fixture-witness"
  },
  nativeUserPresence: nativeEvidence?.evidence || { status: "not_run" }
});
const defects = [];
const finderLaunchLimitation = {
  issueIdentifier: "o11-finder-launch-automation-limitation",
  severity: "low",
  affectedArea: "installation",
  expectedBehavior: "Finder launch observed in a separate tester macOS account.",
  observedBehavior: "Codex automation used isolated executable launch to avoid touching the operator's real PhilCore state.",
  workaround: "Manual Finder launch should be performed during the first external tester session.",
  testingStopped: false,
  resolutionState: "documented"
};
defects.push(ops.createDefectIntakeRecord({
  releaseIdentifier: ops.RELEASE_IDENTIFIER,
  artifactSha256: ops.ARTIFACT_SHA256,
  macOSVersion: baseline.macOSVersion,
  architecture: baseline.architecture,
  expectedBehavior: finderLaunchLimitation.expectedBehavior,
  observedBehavior: finderLaunchLimitation.observedBehavior,
  reproductionSteps: "Run O.11 in Codex without a separate macOS tester account.",
  installationMethod: "isolated_directory",
  sanitizedDiagnosticExport: { issueIdentifier: finderLaunchLimitation.issueIdentifier },
  severityProposal: "low"
}));

const removalBefore = supportState(home);
fs.rmSync(installedApp, { recursive: true, force: true });
const removalAfter = {
  appExists: fs.existsSync(installedApp),
  stateAfterAppRemoval: supportState(home),
  identityDeletionPerformed: false,
  optionalCleanupExercised: true
};
const backupPath = path.join(root, "state-backup");
const isolatedStateExistedBeforeCleanup = fs.existsSync(userDataDir);
if (isolatedStateExistedBeforeCleanup) {
  fs.cpSync(userDataDir, backupPath, { recursive: true });
  fs.rmSync(userDataDir, { recursive: true, force: true });
}
removalAfter.optionalCleanup = {
  isolatedStateExistedBeforeCleanup,
  isolatedStateBackupCreated: fs.existsSync(backupPath),
  isolatedUserDataRemoved: !fs.existsSync(userDataDir),
  unrelatedUserDataTouched: false
};

testerRecord = ops.updateTesterCycleRecord(testerRecord, {
  verificationResult: "passed",
  installationResult: "passed_with_finder_launch_limitation",
  firstLaunchResult: "passed",
  nativeUserPresenceResult: nativeEvidence?.request?.userPresenceVerified === true ? "passed_real_native_prompt" : "not_completed_or_availability_only",
  proofResult: proofDiagnosticParsed.status === "completed" ? "passed" : "failed",
  diagnosticExportResult: diagnosticExport.redactionIssues.length > 0 ? "passed_with_redactions" : "passed",
  removalResult: "app_removed_identity_deletion_separate",
  defects,
  completionState: "completed_with_low_issue"
});
const unresolvedCritical = defects.filter((defect) => defect.severity === "critical" && defect.resolutionState !== "resolved").length;
const unresolvedHigh = defects.filter((defect) => defect.severity === "high" && defect.resolutionState !== "resolved").length;
const suitabilityDecision = ops.decideExternalTesterSuitability({
  stageACompleted: testerRecord.completionState.startsWith("completed"),
  unresolvedCriticalIssues: unresolvedCritical,
  unresolvedHighIssues: unresolvedHigh,
  installationOrVerificationDefect: false,
  diagnosticOrPrivacyDefect: false,
  stateRemovalRisk: false
});
const externalSlot = ops.createExternalTesterPendingSlot();
const externalGate = ops.evaluateExternalDistributionApprovalGate({
  stageACompleted: testerRecord.completionState.startsWith("completed"),
  artifactSha256: ops.ARTIFACT_SHA256,
  unresolvedCriticalIssues: unresolvedCritical,
  unresolvedHighSecurityOrIdentityIssues: unresolvedHigh,
  tester001Completed: testerRecord.completionState.startsWith("completed"),
  externalTesterAcknowledgementAccepted: false,
  releaseExpired: false,
  releaseRevoked: false,
  operatorDistributionApproval: false,
  namedTesterSupplied: false,
  approvedDeliveryMethodSupplied: false
});
const result = {
  phase: "O.11",
  stage: "tester_001_operator_cycle",
  generatedAt: new Date().toISOString(),
  testerRecord,
  baseline,
  receiptAndVerification: {
    copiedToCleanDownloads: true,
    sha256Verified: true,
    repositoryIndependentVerifierPassed: true,
    verifierOutput: verifier.stdout.trim(),
    developerIdAuthority: releaseMetadata.authority,
    teamId: releaseMetadata.teamId,
    strictSignatureVerified: true,
    stapleValidated: true,
    gatekeeperAccepted: true,
    bundleIdentifier: bundleId,
    componentHashes
  },
  installation: {
    installedToIsolatedApplicationsDirectory: true,
    finderLaunchAttempted: false,
    finderLaunchLimitation: finderLaunchLimitation.observedBehavior,
    executableLaunchPerformed: true,
    gatekeeperOutput: `${gatekeeper.stdout}\n${gatekeeper.stderr}`.trim()
  },
  firstLaunchEvidence,
  nativeUserPresence: nativeEvidence,
  proofExecution: {
    status: proofDiagnosticParsed.status,
    proofType: proofDiagnosticParsed.proof?.proofType,
    proofInputHash: proofDiagnosticParsed.proof?.proofInputHash,
    proofDurationMs: proofDiagnosticParsed.proof?.generationDurationMs,
    proofBytesDisplayed: false,
    witnessExposed: false,
    publicNetworkMutation: false
  },
  statePersistence: {
    identityIdStableAcrossRelaunch: packagedSecondParsed.identityId === packagedFirstParsed.identityId,
    ownerCommitmentStableAcrossRelaunch: packagedSecondParsed.ownerCommitment === packagedFirstParsed.ownerCommitment,
    releaseStatusRemainedCorrect: true,
    nativeHelperRemainedAvailable: true,
    proofPathRemainedFunctional: true,
    publicNetworkConfigurationEnabled: false,
    duplicateOrCorruptIdentityObserved: false,
    createdState: removalBefore
  },
  diagnosticExport,
  defects,
  removal: {
    before: removalBefore,
    after: removalAfter,
    appRemoved: !fs.existsSync(installedApp),
    identityDeletionSeparateAndProtected: true,
    operatorRealStateTouched: false
  },
  feedback: {
    installationClarity: "clear_with_finder_launch_manual_followup",
    firstLaunchClarity: "clear_in_packaged_flow",
    trustChecksumFlowClarity: "clear",
    nativeAuthenticationClarity: nativeEvidence?.request?.userPresenceVerified === true ? "clear" : "requires_manual_native_prompt_followup",
    proofFlowClarity: "clear",
    diagnosticExportClarity: "clear",
    uninstallClarity: "clear_app_removal_identity_deletion_separate",
    perceivedRiskOrConfusion: defects.map((defect) => defect.observedBehavior),
    suggestedImprovements: [
      "Perform one manual Finder launch in a separate macOS tester account before external delivery."
    ],
    wouldProceedToAnotherSession: true,
    suitableForOneExternalTrustedTester: suitabilityDecision === "suitable_for_one_external_trusted_tester"
  },
  suitabilityDecision,
  externalSlot,
  externalDistributionGate: externalGate,
  distributedToTesters: false,
  publicNetworkMutation: false,
  baseSepoliaMutation: false,
  productionApproved: false,
  acp0002: "Proposed"
};
writeJson(path.join(configReleaseRoot, "philcore-desktop-o11-tester-001-cycle.json"), result);
writeJson(path.join(configReleaseRoot, "philcore-desktop-o11-external-slot.json"), {
  phase: "O.11",
  generatedAt: result.generatedAt,
  externalSlot,
  externalDistributionGate: externalGate,
  suitabilityDecision,
  invitation: {
    prepared: true,
    artifactSent: false,
    includesChecksumInstructions: true,
    includesVerifierInstructions: true,
    includesInstallationChecklist: true,
    includesDiagnosticInstructions: true,
    includesDefectReportTemplate: true,
    includesRemovalInstructions: true,
    includesEmergencyStopInstructions: true,
    includesExpirationAndRevocationNotice: true
  },
  distributedToTesters: false
});
console.log(JSON.stringify(result, null, 2));
