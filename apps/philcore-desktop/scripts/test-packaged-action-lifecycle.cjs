#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const release = require("./release-utils.cjs");

const appBundlePath = process.env.PHILCORE_DESKTOP_TEST_APP_PATH || release.appBundlePath;
const executablePath = path.join(appBundlePath, "Contents", "MacOS", release.executableName);
if (!fs.existsSync(executablePath)) {
  console.error("Packaged app missing; run npm run desktop:package-local first.");
  process.exit(1);
}

const userDataDir = process.env.PHILCORE_DESKTOP_USER_DATA_DIR
  || fs.mkdtempSync(path.join(os.tmpdir(), "philcore-packaged-action-lifecycle-"));
fs.mkdirSync(userDataDir, { recursive: true });

function run(mode) {
  const result = spawnSync(executablePath, [], {
    cwd: path.dirname(appBundlePath),
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_E2E_UI_ACTION_LIFECYCLE: mode,
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ELECTRON_ENABLE_LOGGING: "0"
    },
    timeout: 360_000
  });
  if (result.status !== 0) {
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status || 1);
  }
  const match = result.stdout.match(/\{[\s\S]*\}/u);
  assert.ok(match, `expected JSON packaged action-lifecycle output for ${mode}`);
  return JSON.parse(match[0]);
}

const initial = run("initial");
assert.equal(initial.status, "passed");
assert.equal(initial.rendererBridgeFunctional, true);
assert.equal(initial.missingEnrollment.modalPresent, false);
assert.equal(initial.missingEnrollment.spinnerPresent, false);
assert.equal(initial.missingEnrollment.goSettingsPresent, true);
assert.equal(initial.missingEnrollment.preflightAuditCount >= 1, true);
assert.equal(initial.rejected.modalPresent, false);
assert.equal(initial.rejected.lifecycleState, "rejected");
assert.equal(initial.cancelled.modalPresent, false);
assert.equal(initial.cancelled.lifecycleState, "cancelled");
assert.equal(initial.timedOut.modalPresent, false);
assert.equal(initial.timedOut.lifecycleState, "timed_out");
assert.equal(initial.successful.lifecycleState, "completed");
assert.equal(initial.successful.signingApprovalCompleted, true);
assert.equal(initial.successful.proofVerified, true);
assert.equal(initial.successful.nullifierConsumed, true);
assert.equal(initial.successful.consumerExecuted, true);
assert.equal(initial.successful.completionAuditRecorded, true);
assert.equal(initial.successful.modalPresent, false);
assert.equal(initial.successful.objectArtifactAbsent, true);
assert.equal(initial.successful.publicNetworkMutation, false);

console.log(JSON.stringify({
  status: "passed",
  packagedActionLifecycle: true,
  missingEnrollmentFailedBeforeProgress: !initial.missingEnrollment.modalPresent && !initial.missingEnrollment.spinnerPresent,
  rejectionReleasedUi: !initial.rejected.modalPresent,
  cancellationReleasedUi: !initial.cancelled.modalPresent,
  timeoutReleasedUi: !initial.timedOut.modalPresent,
  successfulActionReleasedUi: !initial.successful.modalPresent,
  signingApprovalCompleted: initial.successful.signingApprovalCompleted,
  proofVerified: initial.successful.proofVerified,
  nullifierConsumedLocally: initial.successful.nullifierConsumed,
  consumerExecutedLocally: initial.successful.consumerExecuted,
  completionAuditRecorded: initial.successful.completionAuditRecorded,
  privateMaterialExposed: false,
  publicNetworkMutation: false
}, null, 2));
