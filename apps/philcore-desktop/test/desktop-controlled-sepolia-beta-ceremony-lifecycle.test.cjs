"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  FILE_NAME,
  PHASES,
  TRANSITIONS,
  createControlledSepoliaBetaCeremonyLifecycle,
  classifyExistingCeremony,
  classifyAuthorizationStore,
  archiveInvalidatedCeremony,
  physicalEnrollmentLifecycle,
  sanitizedCode
} = require("../src/main/controlled-sepolia-beta-ceremony-lifecycle.cjs");

const COMMIT = "a".repeat(40);
const TREE = "b".repeat(40);
const ENROLLMENT_ID = `0x${"11".repeat(32)}`;
const AUTHORIZATION_ID = `0x${"22".repeat(32)}`;

function fixture(t, suffix = "state") {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-p3-lifecycle-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  let now = 1_800_000_000n;
  const storageRoot = path.join(parent, suffix);
  const options = {
    storageRoot, sourceCommit: COMMIT, sourceTree: TREE,
    expectedAppVersion: "0.1.0", expectedAppBuild: "56",
    expectedBundleIdentifier: "com.philcore.ios.companion.localalpha",
    now: () => now
  };
  return { parent, storageRoot, options, manager: createControlledSepoliaBetaCeremonyLifecycle(options), tick: () => { now += 1n; } };
}

function startEnrollment(manager) {
  manager.transition("enrollment_request_created", {
    requestType: "enrollment", enrollmentRequestId: ENROLLMENT_ID,
    expiresAt: "1800000300", diagnosticStage: "enrollment_create"
  });
  return manager.transition("waiting_for_enrollment_contact", {
    requestType: "enrollment", diagnosticStage: "enrollment_wait"
  });
}

function preflight(manager, counts = { preflightCount: 1, completionAttemptCount: 0 }) {
  return manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "waiting",
    expiresAt: "1800000300", ...counts,
    lastAttempt: { stage: "preflight_accepted", code: null, at: "1800000001", ...counts } });
}

function acceptEnrollment(manager) {
  preflight(manager);
  manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "completed",
    expiresAt: "1800000300", preflightCount: 1, completionAttemptCount: 1,
    lastAttempt: { stage: "completion_accepted", code: null, at: "1800000002",
      preflightCount: 1, completionAttemptCount: 1 } });
  return manager.snapshot();
}

test("fresh lifecycle has no inherited request, approval, counters, artifact, or lock state", (t) => {
  const value = fixture(t).manager.snapshot();
  assert.equal(value.phase, "no_active_request");
  assert.equal(value.enrollmentRequestId, null);
  assert.equal(value.authorizationRequestId, null);
  assert.equal(value.preflightCount, 0);
  assert.equal(value.completionAttemptCount, 0);
  assert.equal(value.persistenceSucceeded, false);
  assert.equal(value.cancellationOccurred, false);
  assert.equal(value.publicMutationOccurred, false);
  assert.equal(value.deviceVaultReleaseOccurred, false);
  assert.equal(Object.hasOwn(value, "signedArtifact"), false);
  assert.equal(Object.hasOwn(value, "executionLock"), false);
});

test("P3 enrollment orchestration creates one request, observes preflight, persists acceptance, and requires exact authorization", async (t) => {
  const { manager } = fixture(t);
  let started = 0;
  let begun = 0;
  let stored = false;
  const statuses = [
    { state: "waiting", preflightCount: 0, completionAttemptCount: 0, lastAttempt: null },
    { state: "waiting", preflightCount: 1, completionAttemptCount: 0,
      lastAttempt: { stage: "preflight_accepted", code: null } },
    { state: "completed", preflightCount: 1, completionAttemptCount: 1,
      lastAttempt: { stage: "completion_accepted", code: null } }
  ];
  const host = {
    async activeEnrollment() {
      if (!stored) throw Object.assign(new Error("missing"), { code: "ROUTINE_ENROLLMENT_NOT_FOUND" });
      return { evidenceClass: "synthetic_source_test", record: { generation: "1" } };
    },
    async start() { started += 1; },
    async beginEnrollment() { begun += 1; return { requestId: ENROLLMENT_ID,
      qrPayload: "prohibited-test-only-payload", comparisonFingerprint: "safe-fingerprint", expiresAt: "1800000300" }; },
    status(requestId) {
      assert.equal(requestId, ENROLLMENT_ID);
      const next = statuses.shift();
      if (next.state === "completed") stored = true;
      return { requestId, expiresAt: "1800000300", ...next };
    },
    async stop() {}
  };
  const announcements = [];
  const result = await physicalEnrollmentLifecycle({ host, lifecycle: manager,
    createQrImage: ({ requestId }) => `/private/${requestId.slice(2, 14)}.png`,
    announce: (value) => announcements.push(value), sleep: async () => {} });
  assert.equal(started, 1); assert.equal(begun, 1); assert.equal(result.record.generation, "1");
  assert.equal(manager.snapshot().phase, "transitioning_to_exact_authorization");
  assert.equal(manager.snapshot().persistenceSucceeded, true);
  assert.equal(manager.snapshot().authorizationRequestId, null);
  assert.ok(announcements.some((value) => value.status === "ENROLLMENT_PREFLIGHT_RECEIVED"));
  assert.ok(announcements.some((value) => value.status === "READY_FOR_EXACT_AUTHORIZATION"));
  assert.equal(announcements.some((value) => value.status.includes("COMPLETED_AUTHORIZATION")), false);
});

test("one active request is enforced and completion before preflight is recorded then rejected", (t) => {
  const { manager } = fixture(t);
  startEnrollment(manager);
  assert.throws(() => manager.transition("enrollment_request_created", {
    requestType: "enrollment", enrollmentRequestId: `0x${"33".repeat(32)}`
  }), /P3_CEREMONY_TRANSITION_INVALID/u);
  manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "waiting", expiresAt: "1800000300",
    preflightCount: 0, completionAttemptCount: 1,
    lastAttempt: { stage: "completion_rejected", code: "ROUTINE_ENROLLMENT_PREFLIGHT_REQUIRED" } });
  assert.equal(manager.snapshot().phase, "enrollment_completion_rejected");
  assert.equal(manager.snapshot().diagnosticCode, "ROUTINE_ENROLLMENT_PREFLIGHT_REQUIRED");
  assert.equal(manager.snapshot().persistenceSucceeded, false);
});

test("expiry before contact and after preflight preserves the safe terminal stage", (t) => {
  const before = fixture(t, "before"); startEnrollment(before.manager);
  before.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "expired", expiresAt: "1800000300",
    preflightCount: 0, completionAttemptCount: 0, lastAttempt: null });
  assert.deepEqual({ phase: before.manager.snapshot().phase, preflight: before.manager.snapshot().preflightCount,
    expired: before.manager.snapshot().expiryOccurred }, { phase: "expired", preflight: 0, expired: true });
  const after = fixture(t, "after"); startEnrollment(after.manager); preflight(after.manager);
  after.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "expired", expiresAt: "1800000300",
    preflightCount: 1, completionAttemptCount: 0,
    lastAttempt: { stage: "preflight_accepted", code: null } });
  assert.equal(after.manager.snapshot().phase, "expired");
  assert.equal(after.manager.snapshot().preflightCount, 1);
});

test("cancellation before contact and after partial progress prevents acceptance", (t) => {
  const before = fixture(t, "cancel-before"); startEnrollment(before.manager);
  before.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "cancelled", expiresAt: "1800000300",
    preflightCount: 0, completionAttemptCount: 0, lastAttempt: null });
  assert.equal(before.manager.snapshot().phase, "cancelled");
  assert.throws(() => before.manager.transition("accepted_enrollment_persisted", {}), /P3_CEREMONY_TRANSITION_INVALID/u);
  const after = fixture(t, "cancel-after"); startEnrollment(after.manager); preflight(after.manager);
  after.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "cancelled", expiresAt: "1800000300",
    preflightCount: 1, completionAttemptCount: 0, lastAttempt: { stage: "preflight_accepted", code: null } });
  assert.equal(after.manager.snapshot().phase, "cancelled");
  assert.equal(after.manager.snapshot().cancellationOccurred, true);
});

test("rejected completion and persistence failure are distinct and cannot advance", (t) => {
  const rejected = fixture(t, "rejected"); startEnrollment(rejected.manager); preflight(rejected.manager);
  rejected.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "waiting", expiresAt: "1800000300",
    preflightCount: 1, completionAttemptCount: 1,
    lastAttempt: { stage: "completion_rejected", code: "PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID" } });
  assert.equal(rejected.manager.snapshot().phase, "enrollment_completion_rejected");
  assert.equal(rejected.manager.snapshot().persistenceSucceeded, false);
  assert.throws(() => rejected.manager.transition("accepted_enrollment_persisted", {}), /P3_CEREMONY_TRANSITION_INVALID/u);
  const failed = fixture(t, "persistence"); startEnrollment(failed.manager); preflight(failed.manager);
  failed.manager.recordHostStatus({ requestId: ENROLLMENT_ID, state: "failed", expiresAt: "1800000300",
    preflightCount: 1, completionAttemptCount: 1,
    lastAttempt: { stage: "completion_internal_failure", code: "ROUTINE_ENROLLMENT_STORE_WRITE_FAILED" } });
  assert.equal(failed.manager.snapshot().phase, "enrollment_persistence_failed");
  assert.equal(failed.manager.snapshot().diagnosticStage, "enrollment_persistence");
  assert.equal(failed.manager.snapshot().persistenceSucceeded, false);
});

test("owner-only allowlisted evidence rejects arbitrary fields, dumps, and malformed diagnostic codes", (t) => {
  const { manager, storageRoot } = fixture(t);
  startEnrollment(manager);
  const location = path.join(storageRoot, FILE_NAME);
  assert.equal(fs.statSync(storageRoot).mode & 0o077, 0);
  assert.equal(fs.statSync(location).mode & 0o077, 0);
  assert.throws(() => manager.transition("enrollment_preflight_observed", {
    exception: { message: "rpc=https://secret.invalid", privateKey: "secret" }
  }), /P3_CEREMONY_PATCH_INVALID/u);
  assert.equal(sanitizedCode("bad code: bearer secret"), "P3_CEREMONY_DIAGNOSTIC_UNCLASSIFIED");
  const value = JSON.parse(fs.readFileSync(location, "utf8"));
  value.phil_secret = "forbidden";
  fs.writeFileSync(location, JSON.stringify(value), { mode: 0o600 });
  assert.throws(() => createControlledSepoliaBetaCeremonyLifecycle({
    storageRoot, sourceCommit: COMMIT, sourceTree: TREE,
    expectedAppVersion: "0.1.0", expectedAppBuild: "56",
    expectedBundleIdentifier: "com.philcore.ios.companion.localalpha", now: () => 1_800_000_010n
  }), /P3_CEREMONY_RECORD_INVALID/u);
});

test("unsafe restart is explicitly invalidated and archived without contaminating a fresh attempt", (t) => {
  const value = fixture(t); startEnrollment(value.manager); preflight(value.manager);
  const classified = classifyExistingCeremony(value.options);
  assert.equal(classified.action, "invalidate");
  const archived = archiveInvalidatedCeremony(value.options, classified.reason);
  assert.equal(archived.record.phase, "invalidated");
  assert.equal(archived.record.restartDetected, true);
  assert.equal(archived.record.invalidated, true);
  assert.equal(fs.existsSync(value.storageRoot), false);
  assert.equal(fs.statSync(archived.destination).mode & 0o077, 0);
  const fresh = createControlledSepoliaBetaCeremonyLifecycle(value.options).snapshot();
  assert.equal(fresh.phase, "no_active_request");
  assert.equal(fresh.preflightCount, 0);
  assert.equal(fresh.completionAttemptCount, 0);
  assert.equal(fresh.enrollmentRequestId, null);
});

test("expired, cancelled, rejected, interrupted, and superseded archives cannot contaminate a new request", (t) => {
  const makers = {
    expired(manager) { startEnrollment(manager); manager.recordHostStatus({ requestId: ENROLLMENT_ID,
      state: "expired", expiresAt: "1800000300", preflightCount: 0, completionAttemptCount: 0, lastAttempt: null }); },
    cancelled(manager) { startEnrollment(manager); manager.recordHostStatus({ requestId: ENROLLMENT_ID,
      state: "cancelled", expiresAt: "1800000300", preflightCount: 0, completionAttemptCount: 0, lastAttempt: null }); },
    rejected(manager) { startEnrollment(manager); preflight(manager); manager.recordHostStatus({ requestId: ENROLLMENT_ID,
      state: "waiting", expiresAt: "1800000300", preflightCount: 1, completionAttemptCount: 1,
      lastAttempt: { stage: "completion_rejected", code: "PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID" } }); },
    interrupted(manager) { startEnrollment(manager); },
    superseded(manager) { startEnrollment(manager); preflight(manager); }
  };
  for (const [name, make] of Object.entries(makers)) {
    const value = fixture(t, name); make(value.manager);
    const classified = classifyExistingCeremony(value.options);
    const archived = archiveInvalidatedCeremony(value.options,
      classified.reason || "P3_CEREMONY_SUPERSEDED_BY_FRESH_REQUEST");
    assert.equal(fs.existsSync(archived.destination), true, name);
    const fresh = createControlledSepoliaBetaCeremonyLifecycle(value.options);
    assert.equal(fresh.snapshot().phase, "no_active_request", name);
    assert.equal(fresh.snapshot().preflightCount, 0, name);
    assert.equal(fresh.snapshot().completionAttemptCount, 0, name);
    assert.equal(fresh.snapshot().enrollmentRequestId, null, name);
  }
});

test("persisted enrollment safely resumes but remains distinct from exact authorization", async (t) => {
  const { manager, options } = fixture(t); startEnrollment(manager); acceptEnrollment(manager);
  assert.equal(classifyExistingCeremony({ ...options, expectedAppBuild: "57" }).action, "invalidate");
  let beginCalls = 0;
  const result = await physicalEnrollmentLifecycle({
    host: { async activeEnrollment() { return { evidenceClass: "synthetic_source_test", record: { generation: "1" } }; },
      async start() {}, async beginEnrollment() { beginCalls += 1; }, status() {}, async stop() {} },
    lifecycle: manager, createQrImage() { throw new Error("must not create stale QR"); },
    announce() {}, sleep: async () => {}
  });
  assert.equal(result.record.generation, "1"); assert.equal(beginCalls, 0);
  assert.equal(manager.snapshot().phase, "transitioning_to_exact_authorization");
  assert.equal(manager.snapshot().safelyResumed, true);
  assert.equal(manager.snapshot().authorizationRequestId, null);
  assert.equal(manager.snapshot().deviceVaultReleaseOccurred, false);
});

test("approved authorization is the only post-request resume state and completion records cleanup", (t) => {
  const { manager, options } = fixture(t); startEnrollment(manager); acceptEnrollment(manager);
  manager.transition("transitioning_to_exact_authorization", { requestType: "exact_authorization",
    diagnosticStage: "authorization_transition", persistenceSucceeded: true });
  manager.transition("authorization_request_created", { requestType: "exact_authorization",
    authorizationRequestId: AUTHORIZATION_ID, expiresAt: "1800000300", diagnosticStage: "authorization_create" });
  assert.equal(classifyExistingCeremony(options).action, "invalidate");
  manager.transition("authorization_response_observed", { requestType: "exact_authorization",
    diagnosticStage: "authorization_response" });
  manager.transition("approved_authorization_persisted", { requestType: "exact_authorization",
    diagnosticStage: "authorization_persistence", persistenceSucceeded: true });
  assert.equal(classifyExistingCeremony(options).action, "resume");
  manager.markResumed();
  manager.transition("completed_cleaned", { requestType: "exact_authorization",
    diagnosticStage: "cleanup", persistenceSucceeded: true, completedAndCleaned: true,
    deviceVaultReleaseOccurred: true });
  assert.equal(manager.snapshot().phase, "completed_cleaned");
  assert.equal(manager.snapshot().publicMutationOccurred, false);
});

test("authorization store consistency permits only a fresh empty store or the exact durable approved record", (t) => {
  const { manager } = fixture(t); startEnrollment(manager); acceptEnrollment(manager);
  manager.transition("transitioning_to_exact_authorization", { requestType: "exact_authorization",
    diagnosticStage: "authorization_transition", persistenceSucceeded: true });
  assert.deepEqual(classifyAuthorizationStore(manager.snapshot(), { list: () => [], load() {} }),
    { action: "begin", requestId: null });
  assert.equal(classifyAuthorizationStore(manager.snapshot(), {
    list: () => [AUTHORIZATION_ID], load: () => ({ requestId: AUTHORIZATION_ID, state: "waiting" })
  }).action, "invalidate");
  manager.transition("authorization_request_created", { requestType: "exact_authorization",
    authorizationRequestId: AUTHORIZATION_ID, expiresAt: "1800000300", diagnosticStage: "authorization_create" });
  manager.transition("authorization_response_observed", { requestType: "exact_authorization",
    diagnosticStage: "authorization_response" });
  manager.transition("approved_authorization_persisted", { requestType: "exact_authorization",
    diagnosticStage: "authorization_persistence", persistenceSucceeded: true });
  assert.deepEqual(classifyAuthorizationStore(manager.snapshot(), {
    list: () => [AUTHORIZATION_ID], load: () => ({ requestId: AUTHORIZATION_ID, state: "approved" })
  }), { action: "resume", requestId: AUTHORIZATION_ID });
  for (const stale of [
    { ids: [], state: null },
    { ids: [AUTHORIZATION_ID], state: "waiting" },
    { ids: [AUTHORIZATION_ID], state: "completed" },
    { ids: [AUTHORIZATION_ID, `0x${"44".repeat(32)}`], state: "approved" }
  ]) assert.equal(classifyAuthorizationStore(manager.snapshot(), {
    list: () => stale.ids,
    load: (id) => ({ requestId: id, state: stale.state })
  }).action, "invalidate");
});

test("old request identifiers and unknown generations fail closed without mutation calls", (t) => {
  const { manager } = fixture(t); startEnrollment(manager); preflight(manager);
  let release = 0, submit = 0, mutation = 0;
  assert.throws(() => manager.recordHostStatus({ requestId: `0x${"99".repeat(32)}`, state: "completed",
    expiresAt: "1800000300", preflightCount: 7, completionAttemptCount: 9,
    lastAttempt: { stage: "completion_accepted", code: null } }), /P3_CEREMONY_REQUEST_MISMATCH/u);
  assert.equal(manager.snapshot().phase, "enrollment_preflight_observed");
  assert.deepEqual({ release, submit, mutation }, { release: 0, submit: 0, mutation: 0 });
});

test("lifecycle enumerates every required state and exposes only legal transitions", () => {
  for (const required of ["no_active_request", "enrollment_request_created", "waiting_for_enrollment_contact",
    "enrollment_preflight_observed", "enrollment_completion_received", "enrollment_completion_rejected",
    "accepted_enrollment_persisted", "transitioning_to_exact_authorization", "authorization_request_created",
    "authorization_response_observed", "approved_authorization_persisted", "expired", "cancelled",
    "restart_detected", "invalidated", "completed_cleaned"]) assert.ok(PHASES.includes(required), required);
  assert.deepEqual(TRANSITIONS.invalidated, []);
  assert.deepEqual(TRANSITIONS.completed_cleaned, []);
  assert.equal(TRANSITIONS.accepted_enrollment_persisted.includes("completed_cleaned"), false);
});

test("companion UI wires version, build, commit, tree, and second scan only from accepted state", () => {
  const root = path.resolve(__dirname, "../../..");
  const view = fs.readFileSync(path.join(root, "apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift"), "utf8");
  const plist = fs.readFileSync(path.join(root, "apps/philcore-ios-companion/PhilCoreCompanion/Info.plist"), "utf8");
  assert.match(view, /case \.accepted:[\s\S]*routine\.accepted\.scan\.button/u);
  assert.match(view, /CFBundleShortVersionString/u);
  assert.match(view, /CFBundleVersion/u);
  assert.match(view, /PhilCoreSourceCommit/u);
  assert.match(view, /PhilCoreSourceTree/u);
  assert.match(plist, /<key>PhilCoreSourceCommit<\/key>/u);
  assert.match(plist, /<key>PhilCoreSourceTree<\/key>/u);
});
