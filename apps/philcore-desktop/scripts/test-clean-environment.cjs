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

const isolatedHome = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-clean-home-"));
const userDataDir = path.join(isolatedHome, "Library", "Application Support", "PhilCore Desktop Local Alpha");
fs.mkdirSync(userDataDir, { recursive: true });

const result = spawnSync(macExecutablePath, [], {
  cwd: isolatedHome,
  encoding: "utf8",
  env: {
    HOME: isolatedHome,
    TMPDIR: os.tmpdir(),
    PATH: "/usr/bin:/bin",
    PHILCORE_DESKTOP_E2E: "1",
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
const match = result.stdout.match(/\{[\s\S]*\}/);
assert.ok(match, "expected JSON e2e output");
const parsed = JSON.parse(match[0]);
assert.equal(parsed.status, "passed");
assert.equal(parsed.demoStatus, "completed");
assert.equal(parsed.publicNetworkMutation, false);
assert.equal(parsed.privateMaterialExposed, false);
console.log(JSON.stringify({
  status: "passed",
  cleanEnvironment: true,
  repositoryPathRequired: false,
  cargoRequiredAtRuntime: false,
  publicNetworkMutation: false,
  realProofDurationMs: parsed.realProofDurationMs
}, null, 2));
