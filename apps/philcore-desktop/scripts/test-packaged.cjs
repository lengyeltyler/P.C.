#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const release = require("./release-utils.cjs");
const appBundlePath = process.env.PHILCORE_DESKTOP_TEST_APP_PATH || release.appBundlePath;
const macExecutablePath = path.join(appBundlePath, "Contents", "MacOS", release.executableName);

if (!fs.existsSync(macExecutablePath)) {
  console.error("Packaged app missing; run npm run desktop:package-local first.");
  process.exit(1);
}

const userDataDir = process.env.PHILCORE_DESKTOP_USER_DATA_DIR
  || fs.mkdtempSync(path.join(os.tmpdir(), "philcore-packaged-e2e-"));
fs.mkdirSync(userDataDir, { recursive: true });

function runPackaged(extraEnv = {}) {
  const result = spawnSync(macExecutablePath, [], {
    cwd: path.dirname(appBundlePath),
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ELECTRON_ENABLE_LOGGING: "0",
      ...extraEnv
    },
    timeout: 120000
  });
  if (result.status !== 0) {
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status || 1);
  }
  const match = result.stdout.match(/\{[\s\S]*\}/);
  assert.ok(match, "expected JSON e2e output");
  return JSON.parse(match[0]);
}

const created = runPackaged();
assert.equal(created.status, "passed");
assert.equal(created.demoStatus, "completed");
assert.equal(created.rejectedFirstStatus, "deny");
assert.equal(created.rejectedFirstSigned, false);
assert.equal(created.rejectedFirstExecuted, false);
assert.equal(created.localOnly, true);
assert.equal(created.nullifierConsumed, true);
assert.equal(created.consumerExecuted, true);
assert.equal(created.freshAuthenticationStatus, "authenticated");
assert.equal(created.publicNetworkMutation, false);
assert.equal(created.privateMaterialExposed, false);
assert.equal(created.rendererBridgeFunctional, true);
assert.equal(created.rendererBridgeMode, "local_alpha");

const reopened = runPackaged({ PHILCORE_DESKTOP_E2E_REOPEN_IDENTITY_ID: created.identityId });
assert.equal(reopened.status, "passed");
assert.equal(reopened.demoStatus, "completed");
assert.equal(reopened.rejectedFirstStatus, "deny");
assert.equal(reopened.rejectedFirstSigned, false);
assert.equal(reopened.rejectedFirstExecuted, false);
assert.equal(reopened.nullifierConsumed, true);
assert.equal(reopened.consumerExecuted, true);
assert.equal(reopened.freshAuthenticationStatus, "authenticated");
assert.equal(reopened.identityId, created.identityId);
assert.equal(reopened.ownerCommitment, created.ownerCommitment);
assert.equal(reopened.lockedAfterRun, true);
assert.equal(reopened.vaultLockedAfterRun, true);
assert.equal(reopened.rendererBridgeFunctional, true);
assert.equal(reopened.rendererBridgeMode, "local_alpha");

console.log(JSON.stringify({
  status: "passed",
  packagedE2E: true,
  noirProofGatedActionCompleted: reopened.demoStatus === "completed" && reopened.freshAuthenticationStatus === "authenticated",
  rejectedFirstStatus: reopened.rejectedFirstStatus,
  rejectedFirstSigned: reopened.rejectedFirstSigned,
  rejectedFirstExecuted: reopened.rejectedFirstExecuted,
  nullifierConsumedLocally: reopened.nullifierConsumed,
  consumerExecutedLocally: reopened.consumerExecuted,
  rendererBridgeFunctional: reopened.rendererBridgeFunctional,
  publicNetworkMutation: false
}, null, 2));
