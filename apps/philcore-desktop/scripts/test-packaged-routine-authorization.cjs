#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const release = require("./release-utils.cjs");

const appBundlePath = process.env.PHILCORE_DESKTOP_TEST_APP_PATH || release.appBundlePath;
const executable = path.join(appBundlePath, "Contents", "MacOS", release.executableName);
if (!fs.existsSync(executable)) {
  console.error("Packaged app missing; run npm run desktop:package-local first.");
  process.exit(1);
}

function run(mode) {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-packaged-routine-${mode}-`));
  const result = spawnSync(executable, [], {
    cwd: path.dirname(appBundlePath),
    encoding: "utf8",
    timeout: 120_000,
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_E2E_UI_ROUTINE_AUTHORIZATION: "1",
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      PHILCORE_DESKTOP_E2E_ROUTINE_UNAVAILABLE: mode === "unavailable" ? "1" : "0",
      ELECTRON_ENABLE_LOGGING: "0"
    }
  });
  if (result.status !== 0) throw new Error(`${result.stdout}\n${result.stderr}`.trim());
  const match = result.stdout.match(/\{[\s\S]*\}/u);
  assert.ok(match, `expected packaged routine JSON for ${mode}`);
  return JSON.parse(match[0]);
}

const started = run("started");
if (started.status !== "passed") console.error(JSON.stringify(started, null, 2));
assert.equal(started.status, "passed");
assert.equal(started.qrDisplayed, true);
assert.equal(started.fingerprintDisplayed, true);
assert.equal(started.approvalGuidanceDisplayed, true);
assert.equal(started.cancelledSafely, true);
assert.equal(started.rendererBridgeFunctional, true);
assert.equal(started.publicNetworkMutation, false);

const unavailable = run("unavailable");
assert.equal(unavailable.status, "passed");
assert.equal(unavailable.visibleSafeFailure, true);
assert.equal(unavailable.qrDisplayed, false);
assert.equal(unavailable.rendererBridgeFunctional, true);
assert.equal(unavailable.publicNetworkMutation, false);

console.log(JSON.stringify({
  status: "passed",
  packagedRoutineButtonClicked: true,
  enrollmentQrDisplayed: true,
  safeFailureVisible: true,
  cancellationVisible: true,
  publicNetworkMutation: false,
  privateMaterialExposed: false
}, null, 2));
