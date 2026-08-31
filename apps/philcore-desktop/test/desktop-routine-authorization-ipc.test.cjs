const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const {
  CHANNELS,
  ROUTINE_AUTHORIZATION_CHANNELS,
  validateBridgePayload
} = require("../src/shared/bridge-contract.cjs");
const {
  createRoutineAuthorizationIpc,
  createRetryingRoutineAuthorizationProductHost,
  createUnavailableRoutineAuthorizationProductHost
} = require("../src/main/routine-authorization-ipc.cjs");

const requestId = `0x${"ab".repeat(32)}`;

test("routine authorization bridge exposes exactly five typed channels including read-only baseline", () => {
  assert.deepEqual(ROUTINE_AUTHORIZATION_CHANNELS, [
    CHANNELS.ROUTINE_AUTHORIZATION_BEGIN,
    CHANNELS.ROUTINE_AUTHORIZATION_BASELINE,
    CHANNELS.ROUTINE_AUTHORIZATION_STATUS,
    CHANNELS.ROUTINE_AUTHORIZATION_CANCEL,
    CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE
  ]);
  assert.equal(validateBridgePayload(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
    typedApplicationIntent: { action: "record_harmless_value" }
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
    typedApplicationIntent: { action: "record_harmless_value", target: "attacker" }
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
    typedApplicationIntent: { action: "replace_routine_device" }
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.ROUTINE_AUTHORIZATION_STATUS, { requestId }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.ROUTINE_AUTHORIZATION_STATUS, { requestId: "ab" }).ok, false);
});

test("routine authorization IPC never accepts trust anchors or execution parameters", async () => {
  const calls = [];
  const ipc = createRoutineAuthorizationIpc({
    async beginRoutineAuthorization(value) { calls.push(["begin", value]);return { status: "transport_waiting" }; },
    async getRoutineAuthorizationStatus(value) { calls.push(["status", value]);return { requestId: value, state: 2 }; },
    async cancelRoutineAuthorization(value) { calls.push(["cancel", value]);return "cancelled"; },
    async deleteDisposableProfile() { calls.push(["delete"]);return { status: "deleted" }; }
  });
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
    typedApplicationIntent: { action: "record_harmless_value" }
  }), { status: "transport_waiting" });
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_STATUS, { requestId }), {
    requestId, state: 2
  });
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_CANCEL, { requestId }), {
    requestId, result: "cancelled"
  });
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE, {
    confirmation: "DELETE DISPOSABLE ROUTINE PROFILE"
  }), { status: "deleted" });
  assert.deepEqual(calls, [
    ["begin", { action: "record_harmless_value" }], ["status", requestId], ["cancel", requestId], ["delete"]
  ]);
});

test("unconfigured packaged routine authority remains visibly fail closed", async () => {
  const ipc = createRoutineAuthorizationIpc(createUnavailableRoutineAuthorizationProductHost());
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
    typedApplicationIntent: { action: "record_harmless_value" }
  }), { status: "blocked", reason: "routine_authorization_product_runtime_unavailable" });
});

test("unavailable routine authority preserves only an allowlisted startup reason", async () => {
  const host = createUnavailableRoutineAuthorizationProductHost("routine_authorization_private_network_unavailable");
  assert.deepEqual(await host.beginRoutineAuthorization(), {
    status: "blocked",
    reason: "routine_authorization_private_network_unavailable"
  });
  assert.throws(() => createUnavailableRoutineAuthorizationProductHost("private details"), /reason is invalid/u);
});

test("retrying routine authority recovers after private Wi-Fi becomes available", async () => {
  const calls = [];
  let activeHost = null;
  let initializeCount = 0;
  let networkAvailable = false;
  const host = createRetryingRoutineAuthorizationProductHost({
    getActiveHost: () => activeHost,
    getUnavailableReason: () => "routine_authorization_private_network_unavailable",
    async initialize() {
      initializeCount += 1;
      if (!networkAvailable) {
        throw Object.assign(new Error("private network unavailable"), {
          code: "ROUTINE_AUTHORIZATION_PRIVATE_NETWORK_UNAVAILABLE"
        });
      }
      activeHost = {
        async beginRoutineAuthorization(intent) { calls.push(["begin", intent]);return { status: "transport_waiting" }; },
        async getRoutineAuthorizationStatus(value) { calls.push(["status", value]);return { requestId: value, state: 2 }; },
        async cancelRoutineAuthorization(value) { calls.push(["cancel", value]);return "cancelled"; },
        async deleteDisposableProfile() { calls.push(["delete"]);return { status: "deleted" }; }
      };
    }
  });
  const ipc = createRoutineAuthorizationIpc(host);
  const payload = { typedApplicationIntent: { action: "record_harmless_value" } };
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, payload), {
    status: "failed", reason: "routine_authorization_private_network_unavailable"
  });
  networkAvailable = true;
  assert.deepEqual(await ipc.invoke(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, payload), {
    status: "transport_waiting"
  });
  assert.equal(initializeCount, 2);
  assert.deepEqual(calls, [["begin", { action: "record_harmless_value" }]]);
});

test("retrying routine authority coalesces concurrent initialization and never initializes for unknown status", async () => {
  let activeHost = null;
  let initializeCount = 0;
  let releaseInitialization;
  const initializationGate = new Promise((resolve) => { releaseInitialization = resolve; });
  const host = createRetryingRoutineAuthorizationProductHost({
    getActiveHost: () => activeHost,
    getUnavailableReason: () => "routine_authorization_environment_failed",
    async initialize() {
      initializeCount += 1;
      await initializationGate;
      activeHost = {
        async beginRoutineAuthorization(intent) { return { status: "transport_waiting", intent }; },
        async getRoutineAuthorizationStatus(value) { return { requestId: value, state: 2 }; },
        async cancelRoutineAuthorization() { return "cancelled"; },
        async deleteDisposableProfile() { return { status: "deleted" }; }
      };
    }
  });
  await assert.rejects(host.getRoutineAuthorizationStatus(requestId), (error) => {
    assert.equal(error.code, "ROUTINE_AUTHORIZATION_ENVIRONMENT_FAILED");
    return true;
  });
  assert.equal(initializeCount, 0);
  const first = host.beginRoutineAuthorization({ action: "record_harmless_value" });
  const second = host.beginRoutineAuthorization({ action: "record_harmless_value" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(initializeCount, 1);
  releaseInitialization();
  assert.equal((await first).status, "transport_waiting");
  assert.equal((await second).status, "transport_waiting");
  assert.equal(initializeCount, 1);
});

test("renderer supplies the exact disposable-profile deletion confirmation",()=>{
  const source=fs.readFileSync(path.join(__dirname,"../src/renderer/app.js"),"utf8");
  const html=fs.readFileSync(path.join(__dirname,"../src/renderer/index.html"),"utf8");
  assert.match(source,/deleteDisposableProfile\(\s*"DELETE DISPOSABLE ROUTINE PROFILE"\s*\)/u);
  assert.match(source,/PhilCoreRoutineAuthorizationUi\.beginState\(outcome\.result\)/u);
  assert.match(source,/PhilCoreRoutineAuthorizationUi\.refreshedState/u);
  assert.match(source,/startRoutineAuthorizationPolling\(\)/u);
  assert.match(source,/Preparing an expiring iPhone-key enrollment request/u);
  assert.doesNotMatch(source,/Preparing an expiring replacement-enrollment request/u);
  assert.match(source,/catch \{\s*if \(window\.PhilCoreRoutineAuthorizationUi\.ownsRefresh\(/u);
  assert.ok(html.indexOf("routine-authorization-ui.cjs") < html.indexOf("app.js"));
});

test("ordinary Desktop startup composes the protected product host without an enable flag",()=>{
  const source=fs.readFileSync(path.join(__dirname,"../src/main/main.cjs"),"utf8");
  const packageSource=fs.readFileSync(path.join(__dirname,"../scripts/package-local.cjs"),"utf8");
  assert.match(source,/await createRoutineAuthorizationEnvironment\(\)/u);
  assert.match(source,/createRoutineDeviceEnrollmentHost\(/u);
  assert.match(source,/createRoutineAuthorizationProductHost\(/u);
  assert.match(source,/createRoutineAuthorizationLocalProductRuntime\(/u);
  assert.match(source,/createRetryingRoutineAuthorizationProductHost\(/u);
  assert.match(source,/initialize: \(\) => createRoutineAuthorizationEnvironment\(\)/u);
  assert.doesNotMatch(source,/PHILCORE_(?:ENABLE|USE)_ROUTINE/u);
  assert.doesNotMatch(source,/repositoryRoot:process\.cwd\(\)/u);
  assert.match(source,/hardhat\.phil-v1-step6c-product\.config\.cjs/u);
  assert.match(packageSource,/hardhat\.phil-v1-step6c-product\.config\.cjs/u);
  assert.match(packageSource,/"apps",\s*"phil-device-sdk"/u);
  assert.match(packageSource,/path\.join\(repoRoot,\s*"contracts"\)/u);
  assert.match(packageSource,/path\.join\(repoRoot,\s*"artifacts"\)/u);
  assert.match(packageSource,/shouldCopyContractArtifact/u);
  assert.match(packageSource,/shouldCopyContractSource/u);
});
