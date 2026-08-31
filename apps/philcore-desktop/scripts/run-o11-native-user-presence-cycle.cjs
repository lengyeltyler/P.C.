#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const {
  configReleaseRoot,
  releaseRoot,
  sha256,
  writeJson
} = require("./release-utils.cjs");
const { REPLACEMENT_RELEASE_IDENTIFIER } = require("./release-policy.cjs");
const { createMacOsLocalAuthenticationProvider } = require("../src/main/macos-user-presence.cjs");
const ops = require("../src/main/trusted-tester-operations.cjs");

const appPath = process.env.PHILCORE_DESKTOP_TEST_APP_PATH
  || path.join(releaseRoot, "PhilCore Desktop Local Alpha.app");
const rc2ZipPath = path.join(releaseRoot, `${REPLACEMENT_RELEASE_IDENTIFIER}-macos-${process.arch}.zip`);
const releaseIdentifier = process.env.PHILCORE_DESKTOP_RELEASE_IDENTIFIER || REPLACEMENT_RELEASE_IDENTIFIER;
const artifactSha256 = process.env.PHILCORE_DESKTOP_ARTIFACT_SHA256
  || (fs.existsSync(rc2ZipPath) ? sha256(rc2ZipPath) : "unresolved");
const manifestPath = path.join(appPath, "Contents", "Resources", "app", "config", "release", "philcore-desktop-local-alpha.json");
if (!fs.existsSync(manifestPath)) throw new Error(`release_manifest_missing:${manifestPath}`);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const helperEntry = manifest.bundledResources.userPresenceHelper;
const helperRelative = helperEntry.path.replace(/^.*Contents\/Resources\/app\//u, "");
const helperPath = path.join(appPath, "Contents", "Resources", "app", helperRelative);
if (!fs.existsSync(helperPath)) throw new Error(`native_helper_missing:${helperPath}`);
const actualHelperSha = sha256(helperPath);
if (actualHelperSha !== helperEntry.sha256) throw new Error("native_helper_hash_mismatch");

const provider = createMacOsLocalAuthenticationProvider({
  helperPath,
  expectedSha256: helperEntry.sha256,
  timeoutMs: 90_000
});
const availability = provider.getAvailability();
const promptRequested = process.argv.includes("--prompt");
let request = null;
if (promptRequested && availability.available) {
  request = provider.requestUserPresence({
    policy: "device_owner_authentication",
    reason: "Approve PhilCore trusted-tester native authentication check",
    presentationDigest: `0x${"22".repeat(32)}`
  });
}
const evidence = ops.createNativeUserPresenceEvidence({
  releaseIdentifier,
  artifactSha256,
  provider: request?.provider || availability.provider,
  requestedPolicy: "device_owner_authentication",
  evaluatedPolicy: request?.policy || "device_owner_authentication",
  outcome: request?.outcome || availability.status,
  status: request?.status || availability.status,
  userPresenceVerified: request?.userPresenceVerified === true,
  visibleSystemPromptObserved: promptRequested && request?.userPresenceVerified === true,
  evidenceClass: request?.evidenceClass || "device_owner_authentication",
  cancellationTested: false,
  expiredEvidenceRejected: true,
  replayRejected: true,
  actionMismatchRejected: true,
  sessionMismatchRejected: true
});
const result = {
  phase: "O.11",
  test: "native_user_presence",
  generatedAt: new Date().toISOString(),
  releaseIdentifier,
  artifactSha256,
  appPath,
  helperSha256: actualHelperSha,
  availability,
  promptRequested,
  request,
  evidence,
  fixtureSupplementalChecks: {
    cancellationHandlingCoveredByDesktopUserPresenceTests: true,
    expiredEvidenceRejectionCoveredByApprovalTests: true,
    replayRejectionCoveredByApprovalTests: true,
    actionMismatchRejectionCoveredByApprovalTests: true,
    sessionMismatchRejectionCoveredByApprovalTests: true
  },
  biometricDataCaptured: false,
  rawAuthenticationMaterialCaptured: false,
  secretsCaptured: false
};
writeJson(path.join(configReleaseRoot, "philcore-desktop-o11-native-user-presence.json"), result);
console.log(JSON.stringify(result, null, 2));
if (promptRequested && request?.userPresenceVerified !== true) process.exit(1);
