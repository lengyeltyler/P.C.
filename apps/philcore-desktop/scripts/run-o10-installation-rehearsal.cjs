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
const { createMacOsLocalAuthenticationProvider } = require("../src/main/macos-user-presence.cjs");
const ops = require("../src/main/trusted-tester-operations.cjs");

const releaseDir = path.join(repoRoot, "apps", "philcore-desktop", "release", "local-alpha", ops.RELEASE_IDENTIFIER);
const artifactPath = path.join(releaseDir, `${ops.RELEASE_IDENTIFIER}-macos-${process.arch}.zip`);
const releaseMetadataPath = path.join(releaseDir, "trusted-tester-release.json");
const expectedSha = ops.ARTIFACT_SHA256;

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    cwd: options.cwd || repoRoot,
    encoding: "utf8",
    env: { ...process.env, PHILCORE_DESKTOP_NOTARIZE_APPROVED: "", ...(options.env || {}) },
    timeout: options.timeout || 120000
  });
  return {
    command: [commandName, ...args].join(" "),
    status: result.status,
    stdout: (result.stdout || "").slice(0, 4000),
    stderr: (result.stderr || "").slice(0, 4000)
  };
}

function requirePassed(result, label) {
  if (result.status !== 0) {
    throw new Error(`${label}_failed\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function findExtractedApp(root) {
  const entries = fs.readdirSync(root);
  const app = entries.find((entry) => entry.endsWith(".app"));
  if (!app) throw new Error("extracted_application_missing");
  return path.join(root, app);
}

function appExecutable(appPath) {
  const info = JSON.parse(fs.readFileSync(path.join(configReleaseRoot, "philcore-desktop-o9-release-evidence.json"), "utf8"));
  return path.join(appPath, "Contents", "MacOS", info.release?.executableName || "PhilCore Desktop");
}

function readManifest(appPath) {
  const manifestPath = path.join(appPath, "Contents", "Resources", "app", "config", "release", "philcore-desktop-local-alpha.json");
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
}

function componentHash(appPath, component) {
  const manifest = readManifest(appPath);
  const entry = manifest.bundledResources[component];
  const componentPath = entry.path.replace(/^.*Contents\/Resources\/app\//u, "");
  return {
    component,
    expectedSha256: entry.sha256,
    actualSha256: sha256(path.join(appPath, "Contents", "Resources", "app", componentPath))
  };
}

function runPackagedCheck(appPath) {
  return requirePassed(command(process.execPath, ["apps/philcore-desktop/scripts/test-packaged.cjs"], {
    env: { PHILCORE_DESKTOP_TEST_APP_PATH: appPath },
    timeout: 180000
  }), "packaged_launch");
}

function runCleanEnvironmentCheck(appPath) {
  return requirePassed(command(process.execPath, ["apps/philcore-desktop/scripts/test-clean-environment.cjs"], {
    env: { PHILCORE_DESKTOP_TEST_APP_PATH: appPath },
    timeout: 180000
  }), "clean_environment");
}

if (!fs.existsSync(artifactPath)) throw new Error(`artifact_missing:${artifactPath}`);
if (!fs.existsSync(releaseMetadataPath)) throw new Error(`trusted_tester_release_metadata_missing:${releaseMetadataPath}`);
const releaseMetadata = JSON.parse(fs.readFileSync(releaseMetadataPath, "utf8"));
const actualSha = sha256(artifactPath);
assert.equal(actualSha, expectedSha, "documented ZIP SHA-256 mismatch");

const verifier = requirePassed(command("bash", [
  path.join(repoRoot, "apps", "philcore-desktop", "scripts", "verify-trusted-tester-artifact.sh"),
  artifactPath,
  expectedSha,
  releaseMetadata.authority,
  releaseMetadata.teamId
]), "trusted_tester_artifact_verifier");

const rehearsalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o10-install-rehearsal-"));
const receivedDir = path.join(rehearsalRoot, "Downloads");
const applicationsDir = path.join(rehearsalRoot, "Applications");
const extractedDir = path.join(rehearsalRoot, "Extracted");
fs.mkdirSync(receivedDir, { recursive: true });
fs.mkdirSync(applicationsDir, { recursive: true });
fs.mkdirSync(extractedDir, { recursive: true });
const receivedZip = path.join(receivedDir, path.basename(artifactPath));
fs.copyFileSync(artifactPath, receivedZip);
assert.equal(sha256(receivedZip), expectedSha, "received ZIP checksum mismatch");
run("ditto", ["-x", "-k", receivedZip, extractedDir]);
const extractedApp = findExtractedApp(extractedDir);
const installedApp = path.join(applicationsDir, path.basename(extractedApp));
run("ditto", [extractedApp, installedApp]);

const codesignVerify = requirePassed(command("codesign", ["--verify", "--deep", "--strict", "--verbose=4", installedApp]), "codesign_strict");
const codesignDetails = requirePassed(command("codesign", ["-dvvv", installedApp]), "codesign_details");
const staple = requirePassed(command("xcrun", ["stapler", "validate", installedApp]), "staple_validation");
const gatekeeper = requirePassed(command("spctl", ["--assess", "--type", "execute", "--verbose=4", installedApp]), "gatekeeper_assessment");
const bundleId = requirePassed(command("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleIdentifier", path.join(installedApp, "Contents", "Info.plist")]), "bundle_id").stdout.trim();
assert.equal(bundleId, ops.BUNDLE_IDENTIFIER, "bundle identifier mismatch");

const helperEntry = readManifest(installedApp).bundledResources.userPresenceHelper;
const helperRelative = helperEntry.path.replace(/^.*Contents\/Resources\/app\//u, "");
const helperPath = path.join(installedApp, "Contents", "Resources", "app", helperRelative);
const nativeProvider = createMacOsLocalAuthenticationProvider({
  helperPath,
  expectedSha256: helperEntry.sha256
});
const nativeUserPresence = nativeProvider.getAvailability();
if (!nativeUserPresence.available) throw new Error(`native_user_presence_unavailable:${nativeUserPresence.status}`);

const packaged = runPackagedCheck(installedApp);
const cleanEnvironment = runCleanEnvironmentCheck(installedApp);

const componentHashes = ["prover", "verifier", "userPresenceHelper"].map((component) => componentHash(installedApp, component));
for (const component of componentHashes) {
  assert.equal(component.actualSha256, component.expectedSha256, `${component.component} hash mismatch`);
}

const diagnosticExport = ops.sanitizeDiagnosticExport({
  releaseIdentifier: ops.RELEASE_IDENTIFIER,
  artifactSha256: expectedSha,
  bundleIdentifier: bundleId,
  os: `${os.platform()} ${os.release()}`,
  architecture: os.arch(),
  signature: {
    authority: releaseMetadata.authority,
    teamId: releaseMetadata.teamId,
    notarized: true,
    gatekeeperAccepted: true
  },
  runtime: {
    packagedLaunch: "passed",
    cleanEnvironment: "passed",
    publicNetworkMutation: false
  },
  proof: {
    status: "packaged_real_local_proof_verified",
    proofBytes: "redaction-fixture-proof-bytes"
  }
});

const appRemoval = {
  removedApplicationPath: installedApp,
  identityDataDeleted: false,
  destructiveIdentityDeletionPerformed: false,
  residualDataModel: ops.uninstallResidualDataModel(bundleId)
};
fs.rmSync(installedApp, { recursive: true, force: true });
const result = {
  phase: "O.10",
  rehearsal: "trusted_tester_installation",
  generatedAt: new Date().toISOString(),
  artifact: {
    path: path.relative(repoRoot, artifactPath),
    sha256: actualSha,
    expectedSha256: expectedSha,
    bytes: fs.statSync(artifactPath).size
  },
  receivedZip: {
    copiedToCleanDownloadDirectory: true,
    sha256: sha256(receivedZip),
    checksumMatched: true
  },
  repositoryIndependentVerifier: {
    passed: true,
    stdout: verifier.stdout.trim()
  },
  installation: {
    extractedToCleanDirectory: true,
    installedToIsolatedApplicationsDirectory: true,
    finderLaunchNotAutomated: true,
    executableLaunchPerformed: true,
    appRemovedAfterRehearsal: !fs.existsSync(installedApp)
  },
  appleTrust: {
    developerIdAuthority: releaseMetadata.authority,
    teamId: releaseMetadata.teamId,
    bundleIdentifier: bundleId,
    strictSignatureVerified: true,
    notarizationStapleValidated: true,
    gatekeeperAccepted: true,
    codesignDetails: codesignDetails.stderr.slice(0, 2000),
    gatekeeperOutput: `${gatekeeper.stdout}\n${gatekeeper.stderr}`.trim()
  },
  bundledComponentHashes: componentHashes,
  nativeUserPresence,
  packagedLaunch: {
    passed: true,
    output: packaged.stdout.trim().slice(0, 2000)
  },
  cleanEnvironment: {
    passed: true,
    output: cleanEnvironment.stdout.trim().slice(0, 2000)
  },
  diagnosticExport,
  removal: appRemoval,
  publicNetworkMutation: false,
  actualTesterDistribution: false,
  appleUploadPerformed: false,
  baseSepoliaMutation: false,
  productionApproved: false
};
writeJson(path.join(configReleaseRoot, "philcore-desktop-o10-installation-rehearsal.json"), result);
console.log(JSON.stringify(result, null, 2));
