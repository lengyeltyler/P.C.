const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const electron = require("electron");
const { formatSpawnDiagnosticJson, runWithGuaranteedFinal } = require("./desktop-e2e-diagnostic.cjs");

const ELECTRON_SPAWN_TIMEOUT_MS = 20000;

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-e2e-"));

function runElectron(extraEnv = {}) {
  const startedAt = Date.now();
  const result = spawnSync(electron, ["apps/philcore-desktop/src/main/main.cjs"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ELECTRON_ENABLE_LOGGING: "0",
      ...extraEnv
    },
    timeout: ELECTRON_SPAWN_TIMEOUT_MS
  });
  const elapsedMs = Date.now() - startedAt;

  if (result.status !== 0) {
    // Temporary fail-closed diagnostic: existing evidence (local + hosted
    // logs) does not prove the hosted crash cause, and this file's own
    // stdout/stderr are empty on the confirmed local SIGTRAP path, so the
    // pre-existing console.error(result.stdout/stderr) lines below carry no
    // signal by themselves. This adds the one piece of safe, deterministic
    // spawn metadata that was previously discarded.
    //
    // Diagnostic construction/serialization must never be able to mask this
    // exit: formatSpawnDiagnosticJson is itself guaranteed not to throw, and
    // runWithGuaranteedFinal additionally guarantees the original exit still
    // runs even if something unexpected throws while attempting to print.
    runWithGuaranteedFinal(
      () => {
        const diagnosticJson = formatSpawnDiagnosticJson(result, {
          elapsedMs,
          timedOut: elapsedMs >= ELECTRON_SPAWN_TIMEOUT_MS
        });
        if (diagnosticJson) console.error(diagnosticJson);
        console.error(result.stdout);
        console.error(result.stderr);
      },
      () => process.exit(result.status || 1)
    );
  }

  const match = result.stdout.match(/\{[\s\S]*\}/);
  assert.ok(match, "expected JSON e2e output");
  return JSON.parse(match[0]);
}

const created = runElectron();
assert.equal(created.status, "passed");
assert.equal(created.launched, true);
assert.equal(created.demoStatus, "completed");
assert.equal(created.rejectedFirstStatus, "deny");
assert.equal(created.rejectedFirstSigned, false);
assert.equal(created.rejectedFirstExecuted, false);
assert.equal(created.localOnly, true);
assert.equal(created.mode, "created");
assert.equal(created.identityCreated, true);
assert.equal(created.publicNetworkMutation, false);
assert.equal(created.privateMaterialExposed, false);
assert.equal(created.rendererBridgeFunctional, true);
assert.equal(created.rendererBridgeMode, "local_alpha");
assert.equal(created.platformProtection, "enabled");
assert.equal(created.freshAuthenticationStatus, "authenticated");
assert.equal(created.nullifierConsumed, true);
assert.equal(created.consumerExecuted, true);
assert.equal(created.lockedAfterRun, true);
assert.equal(created.vaultLockedAfterRun, true);

const reopened = runElectron({ PHILCORE_DESKTOP_E2E_REOPEN_IDENTITY_ID: created.identityId });
assert.equal(reopened.status, "passed");
assert.equal(reopened.mode, "reopened");
assert.equal(reopened.demoStatus, "completed");
assert.equal(reopened.rejectedFirstStatus, "deny");
assert.equal(reopened.rejectedFirstSigned, false);
assert.equal(reopened.rejectedFirstExecuted, false);
assert.equal(reopened.identityId, created.identityId);
assert.equal(reopened.ownerCommitment, created.ownerCommitment);
assert.equal(reopened.validatorAddress, created.validatorAddress);
assert.equal(reopened.recoveryAddress, created.recoveryAddress);
assert.equal(reopened.publicNetworkMutation, false);
assert.equal(reopened.privateMaterialExposed, false);
assert.equal(reopened.rendererBridgeFunctional, true);
assert.equal(reopened.rendererBridgeMode, "local_alpha");
assert.equal(reopened.platformProtection, "enabled");
assert.equal(reopened.freshAuthenticationStatus, "authenticated");
assert.equal(reopened.nullifierConsumed, true);
assert.equal(reopened.consumerExecuted, true);
assert.equal(reopened.lockedAfterRun, true);
assert.equal(reopened.vaultLockedAfterRun, true);

console.log("ok - desktop e2e creates and reopens identity behind the Noir local proof gate");
