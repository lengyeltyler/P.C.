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
  || fs.mkdtempSync(path.join(os.tmpdir(), "philcore-packaged-unlock-ui-"));
fs.mkdirSync(userDataDir, { recursive: true });

function runPackagedUnlockFlow(mode) {
  const result = spawnSync(macExecutablePath, [], {
    cwd: path.dirname(appBundlePath),
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_E2E_UI_UNLOCK_FLOW: mode,
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ELECTRON_ENABLE_LOGGING: "0"
    },
    timeout: 120000
  });
  if (result.status !== 0) {
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status || 1);
  }
  const match = result.stdout.match(/\{[\s\S]*\}/u);
  assert.ok(match, "expected JSON packaged unlock-flow output");
  return JSON.parse(match[0]);
}

const created = runPackagedUnlockFlow("created");
assert.equal(created.status, "passed");
assert.equal(created.mode, "created");
assert.equal(created.rendererBridgeFunctional, true);
assert.equal(created.homeUnlockOpenedPassphraseForm, true);
assert.equal(created.settingsRedirectAbsent, true);
assert.equal(created.wrongPassphraseStayedOnUnlock, true);
assert.equal(created.correctPassphraseUnlocked, true);
assert.equal(created.protectedActionsAvailable, true);
assert.equal(created.settingsPrimaryUnlockAbsent, true);
assert.equal(created.settingsGoToUnlockOpenedPassphraseForm, true);
assert.equal(created.recentUnlockAuditRecorded, true);
assert.equal(created.privateMaterialExposed, false);
assert.equal(created.publicNetworkMutation, false);

const reopened = runPackagedUnlockFlow("reopened");
assert.equal(reopened.status, "passed");
assert.equal(reopened.mode, "reopened");
assert.equal(reopened.identityId, created.identityId);
assert.equal(reopened.ownerCommitment, created.ownerCommitment);
assert.equal(reopened.rendererBridgeFunctional, true);
assert.equal(reopened.homeUnlockOpenedPassphraseForm, true);
assert.equal(reopened.settingsRedirectAbsent, true);
assert.equal(reopened.wrongPassphraseStayedOnUnlock, true);
assert.equal(reopened.correctPassphraseUnlocked, true);
assert.equal(reopened.protectedActionsAvailable, true);
assert.equal(reopened.settingsPrimaryUnlockAbsent, true);
assert.equal(reopened.settingsGoToUnlockOpenedPassphraseForm, true);
assert.equal(reopened.recentUnlockAuditRecorded, true);
assert.equal(reopened.privateMaterialExposed, false);
assert.equal(reopened.publicNetworkMutation, false);

console.log(JSON.stringify({
  status: "passed",
  packagedUnlockFlow: true,
  createdMode: created.mode,
  reopenedMode: reopened.mode,
  identityStableAcrossRelaunch: reopened.identityId === created.identityId,
  ownerCommitmentStableAcrossRelaunch: reopened.ownerCommitment === created.ownerCommitment,
  homeUnlockOpenedPassphraseForm: reopened.homeUnlockOpenedPassphraseForm,
  wrongPassphraseStayedOnUnlock: reopened.wrongPassphraseStayedOnUnlock,
  correctPassphraseUnlocked: reopened.correctPassphraseUnlocked,
  protectedActionsAvailable: reopened.protectedActionsAvailable,
  settingsPrimaryUnlockAbsent: reopened.settingsPrimaryUnlockAbsent,
  settingsGoToUnlockOpenedPassphraseForm: reopened.settingsGoToUnlockOpenedPassphraseForm,
  privateMaterialExposed: false,
  publicNetworkMutation: false
}, null, 2));
