"use strict";

const fs = require("node:fs");
const path = require("node:path");

const FORMAT = "philcore-controlled-sepolia-beta-ceremony-lifecycle-v1";
const FILE_NAME = "ceremony-lifecycle-v1.json";
const PHASES = Object.freeze([
  "no_active_request",
  "enrollment_request_created",
  "waiting_for_enrollment_contact",
  "enrollment_preflight_observed",
  "enrollment_completion_received",
  "enrollment_completion_rejected",
  "enrollment_persistence_failed",
  "accepted_enrollment_persisted",
  "transitioning_to_exact_authorization",
  "authorization_request_created",
  "authorization_response_observed",
  "approved_authorization_persisted",
  "expired",
  "cancelled",
  "restart_detected",
  "invalidated",
  "completed_cleaned"
]);
const ACTIVE_UNSAFE = new Set([
  "enrollment_request_created",
  "waiting_for_enrollment_contact",
  "enrollment_preflight_observed",
  "enrollment_completion_received",
  "authorization_request_created",
  "authorization_response_observed"
]);
const SAFE_RESUME = new Set([
  "accepted_enrollment_persisted",
  "transitioning_to_exact_authorization",
  "approved_authorization_persisted"
]);
const TERMINAL_FRESH = new Set([
  "enrollment_completion_rejected",
  "enrollment_persistence_failed",
  "expired",
  "cancelled",
  "restart_detected",
  "invalidated",
  "completed_cleaned"
]);
const STAGES = new Set([
  "none", "startup", "enrollment_create", "enrollment_wait", "enrollment_preflight",
  "enrollment_completion", "enrollment_persistence", "authorization_transition",
  "authorization_create", "authorization_response", "authorization_persistence", "cleanup"
]);
const TRANSITIONS = Object.freeze({
  no_active_request: ["enrollment_request_created"],
  enrollment_request_created: ["waiting_for_enrollment_contact", "expired", "cancelled", "restart_detected"],
  waiting_for_enrollment_contact: ["enrollment_preflight_observed", "enrollment_completion_received", "expired", "cancelled", "restart_detected"],
  enrollment_preflight_observed: ["enrollment_completion_received", "expired", "cancelled", "restart_detected"],
  enrollment_completion_received: ["enrollment_completion_rejected", "enrollment_persistence_failed", "accepted_enrollment_persisted", "restart_detected"],
  enrollment_completion_rejected: ["cancelled", "expired", "restart_detected", "invalidated"],
  enrollment_persistence_failed: ["restart_detected", "invalidated"],
  accepted_enrollment_persisted: ["transitioning_to_exact_authorization", "restart_detected", "invalidated"],
  transitioning_to_exact_authorization: ["authorization_request_created", "restart_detected", "invalidated"],
  authorization_request_created: ["authorization_response_observed", "expired", "cancelled", "restart_detected"],
  authorization_response_observed: ["approved_authorization_persisted", "restart_detected"],
  approved_authorization_persisted: ["completed_cleaned", "restart_detected", "invalidated"],
  expired: ["restart_detected", "invalidated"],
  cancelled: ["restart_detected", "invalidated"],
  restart_detected: ["invalidated"],
  invalidated: [],
  completed_cleaned: []
});

class CeremonyLifecycleError extends Error {
  constructor(code) { super(code); this.name = "CeremonyLifecycleError"; this.code = code; }
}
function fail(code) { throw new CeremonyLifecycleError(code); }
function exactObject(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) fail(code);
}
function safeText(value, expression, code) {
  if (typeof value !== "string" || !expression.test(value)) fail(code);
  return value;
}
function safeNullable(value, expression, code) {
  if (value === null) return null;
  return safeText(value, expression, code);
}
function safeBoolean(value) { if (typeof value !== "boolean") fail("P3_CEREMONY_RECORD_INVALID"); return value; }
function safeCounter(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 1_000_000) fail("P3_CEREMONY_RECORD_INVALID");
  return value;
}
function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
function atomicWrite(location, value) {
  const directory = path.dirname(location);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const temporary = `${location}.tmp-${process.pid}`;
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  fs.renameSync(temporary, location);
  fs.chmodSync(location, 0o600);
  syncDirectory(directory);
}
function validateRecord(value) {
  const keys = [
    "format", "version", "phase", "previousPhase", "requestType", "enrollmentRequestId",
    "authorizationRequestId", "createdAt", "updatedAt", "expiresAt", "sourceCommit", "sourceTree",
    "expectedAppVersion", "expectedAppBuild", "expectedBundleIdentifier", "preflightCount",
    "completionAttemptCount", "diagnosticStage", "diagnosticCode", "persistenceSucceeded",
    "cancellationOccurred", "expiryOccurred", "restartDetected", "safelyResumed", "invalidated",
    "completedAndCleaned", "publicMutationOccurred", "deviceVaultReleaseOccurred"
  ];
  exactObject(value, keys, "P3_CEREMONY_RECORD_INVALID");
  if (value.format !== FORMAT || value.version !== 1 || !PHASES.includes(value.phase)
    || (value.previousPhase !== null && !PHASES.includes(value.previousPhase))) fail("P3_CEREMONY_RECORD_INVALID");
  safeText(value.requestType, /^(none|enrollment|exact_authorization)$/u, "P3_CEREMONY_RECORD_INVALID");
  safeNullable(value.enrollmentRequestId, /^0x[0-9a-f]{64}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeNullable(value.authorizationRequestId, /^0x[0-9a-f]{64}$/u, "P3_CEREMONY_RECORD_INVALID");
  for (const key of ["createdAt", "updatedAt"]) safeText(value[key], /^(0|[1-9][0-9]{0,19})$/u, "P3_CEREMONY_RECORD_INVALID");
  safeNullable(value.expiresAt, /^(0|[1-9][0-9]{0,19})$/u, "P3_CEREMONY_RECORD_INVALID");
  safeText(value.sourceCommit, /^[0-9a-f]{40}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeText(value.sourceTree, /^[0-9a-f]{40}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeText(value.expectedAppVersion, /^[A-Za-z0-9._+-]{1,64}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeText(value.expectedAppBuild, /^[A-Za-z0-9._+-]{1,64}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeText(value.expectedBundleIdentifier, /^[A-Za-z0-9.-]{1,128}$/u, "P3_CEREMONY_RECORD_INVALID");
  safeCounter(value.preflightCount); safeCounter(value.completionAttemptCount);
  if (!STAGES.has(value.diagnosticStage)) fail("P3_CEREMONY_RECORD_INVALID");
  safeNullable(value.diagnosticCode, /^[A-Z0-9_]{1,96}$/u, "P3_CEREMONY_RECORD_INVALID");
  for (const key of ["persistenceSucceeded", "cancellationOccurred", "expiryOccurred", "restartDetected",
    "safelyResumed", "invalidated", "completedAndCleaned", "publicMutationOccurred", "deviceVaultReleaseOccurred"]) safeBoolean(value[key]);
  if (value.publicMutationOccurred || (value.deviceVaultReleaseOccurred && value.phase !== "completed_cleaned")) {
    fail("P3_CEREMONY_RECORD_AUTHORITY_INVALID");
  }
  return Object.freeze({ ...value });
}
function sanitizedCode(value, fallback = "P3_CEREMONY_DIAGNOSTIC_UNCLASSIFIED") {
  return typeof value === "string" && /^[A-Z0-9_]{1,96}$/u.test(value) ? value : fallback;
}
function initialRecord(input, now) {
  return validateRecord({
    format: FORMAT, version: 1, phase: "no_active_request", previousPhase: null,
    requestType: "none", enrollmentRequestId: null, authorizationRequestId: null,
    createdAt: String(now), updatedAt: String(now), expiresAt: null,
    sourceCommit: input.sourceCommit, sourceTree: input.sourceTree,
    expectedAppVersion: input.expectedAppVersion, expectedAppBuild: input.expectedAppBuild,
    expectedBundleIdentifier: input.expectedBundleIdentifier, preflightCount: 0,
    completionAttemptCount: 0, diagnosticStage: "none", diagnosticCode: null,
    persistenceSucceeded: false, cancellationOccurred: false, expiryOccurred: false,
    restartDetected: false, safelyResumed: false, invalidated: false,
    completedAndCleaned: false, publicMutationOccurred: false, deviceVaultReleaseOccurred: false
  });
}
function createControlledSepoliaBetaCeremonyLifecycle(options) {
  exactObject(options, ["storageRoot", "sourceCommit", "sourceTree", "expectedAppVersion", "expectedAppBuild", "expectedBundleIdentifier", "now"], "P3_CEREMONY_OPTIONS_INVALID");
  if (typeof options.now !== "function") fail("P3_CEREMONY_OPTIONS_INVALID");
  const location = path.join(options.storageRoot, FILE_NAME);
  let current;
  function read() {
    if (!fs.existsSync(location)) return initialRecord(options, BigInt(options.now()));
    const directoryStat = fs.statSync(options.storageRoot);
    if (!directoryStat.isDirectory() || (directoryStat.mode & 0o077) !== 0) {
      fail("P3_CEREMONY_DIRECTORY_PERMISSIONS_INVALID");
    }
    const stat = fs.statSync(location);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) fail("P3_CEREMONY_RECORD_PERMISSIONS_INVALID");
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(location, "utf8")); } catch { fail("P3_CEREMONY_RECORD_INVALID"); }
    return validateRecord(parsed);
  }
  current = read();
  function snapshot() { return Object.freeze({ ...current }); }
  function transition(phase, patch = {}) {
    if (!PHASES.includes(phase) || !TRANSITIONS[current.phase].includes(phase)) fail("P3_CEREMONY_TRANSITION_INVALID");
    const allowed = new Set([
      "requestType", "enrollmentRequestId", "authorizationRequestId", "expiresAt", "preflightCount",
      "completionAttemptCount", "diagnosticStage", "diagnosticCode", "persistenceSucceeded",
      "cancellationOccurred", "expiryOccurred", "restartDetected", "safelyResumed", "invalidated",
      "completedAndCleaned", "deviceVaultReleaseOccurred"
    ]);
    if (!patch || typeof patch !== "object" || Array.isArray(patch)
      || Object.keys(patch).some((key) => !allowed.has(key))) fail("P3_CEREMONY_PATCH_INVALID");
    current = validateRecord({ ...current, ...patch, phase, previousPhase: current.phase, updatedAt: String(BigInt(options.now())) });
    atomicWrite(location, current);
    return snapshot();
  }
  function markResumed() {
    if (!SAFE_RESUME.has(current.phase)) fail("P3_CEREMONY_UNSAFE_RESUME");
    current = validateRecord({ ...current, safelyResumed: true, updatedAt: String(BigInt(options.now())) });
    atomicWrite(location, current);
    return snapshot();
  }
  function recordHostStatus(status) {
    exactObject(status, ["requestId", "state", "expiresAt", "preflightCount", "completionAttemptCount", "lastAttempt"], "P3_CEREMONY_HOST_STATUS_INVALID");
    if (status.requestId !== current.enrollmentRequestId) fail("P3_CEREMONY_REQUEST_MISMATCH");
    const base = { preflightCount: safeCounter(status.preflightCount), completionAttemptCount: safeCounter(status.completionAttemptCount), expiresAt: status.expiresAt };
    if (status.state === "expired") return transition("expired", { ...base, requestType: "enrollment", expiryOccurred: true, diagnosticStage: "enrollment_wait", diagnosticCode: "ROUTINE_ENROLLMENT_EXPIRED" });
    if (status.state === "cancelled") return transition("cancelled", { ...base, requestType: "enrollment", cancellationOccurred: true, diagnosticStage: "enrollment_wait", diagnosticCode: "ROUTINE_ENROLLMENT_CANCELLED" });
    const attempt = status.lastAttempt;
    if (status.preflightCount > 0 && current.phase === "waiting_for_enrollment_contact") {
      transition("enrollment_preflight_observed", { ...base, diagnosticStage: "enrollment_preflight", diagnosticCode: null });
      if (attempt?.stage === "preflight_accepted") return snapshot();
    }
    if (attempt?.stage === "completion_received"
      && ["waiting_for_enrollment_contact", "enrollment_preflight_observed"].includes(current.phase)) {
      return transition("enrollment_completion_received", { ...base, diagnosticStage: "enrollment_completion", diagnosticCode: null });
    }
    if (attempt?.stage === "completion_rejected") {
      if (["waiting_for_enrollment_contact", "enrollment_preflight_observed"].includes(current.phase)) transition("enrollment_completion_received", { ...base, diagnosticStage: "enrollment_completion", diagnosticCode: null });
      return transition("enrollment_completion_rejected", { ...base, diagnosticStage: "enrollment_completion", diagnosticCode: sanitizedCode(attempt.code, "ROUTINE_ENROLLMENT_REJECTION_UNCLASSIFIED") });
    }
    if (attempt?.stage === "completion_internal_failure") {
      if (["waiting_for_enrollment_contact", "enrollment_preflight_observed"].includes(current.phase)) transition("enrollment_completion_received", { ...base, diagnosticStage: "enrollment_completion", diagnosticCode: null });
      return transition("enrollment_persistence_failed", { ...base, diagnosticStage: "enrollment_persistence", diagnosticCode: sanitizedCode(attempt.code, "ROUTINE_ENROLLMENT_PERSISTENCE_UNCLASSIFIED") });
    }
    if (status.state === "completed") {
      if (["waiting_for_enrollment_contact", "enrollment_preflight_observed"].includes(current.phase)) transition("enrollment_completion_received", { ...base, diagnosticStage: "enrollment_completion", diagnosticCode: null });
      return transition("accepted_enrollment_persisted", { ...base, diagnosticStage: "enrollment_persistence", diagnosticCode: null, persistenceSucceeded: true });
    }
    return snapshot();
  }
  return Object.freeze({ location, snapshot, transition, markResumed, recordHostStatus });
}
function classifyExistingCeremony(options) {
  const manager = createControlledSepoliaBetaCeremonyLifecycle(options);
  const record = manager.snapshot();
  if (record.sourceCommit !== options.sourceCommit || record.sourceTree !== options.sourceTree) return Object.freeze({ action: "invalidate", reason: "P3_CEREMONY_SOURCE_IDENTITY_CHANGED", manager, record });
  if (record.expectedAppVersion !== options.expectedAppVersion
    || record.expectedAppBuild !== options.expectedAppBuild
    || record.expectedBundleIdentifier !== options.expectedBundleIdentifier) {
    return Object.freeze({ action: "invalidate", reason: "P3_CEREMONY_PACKAGE_IDENTITY_CHANGED", manager, record });
  }
  if (SAFE_RESUME.has(record.phase)) return Object.freeze({ action: "resume", reason: null, manager, record });
  if (ACTIVE_UNSAFE.has(record.phase)) return Object.freeze({ action: "invalidate", reason: "P3_CEREMONY_UNSAFE_RESUME_INVALIDATED", manager, record });
  if (TERMINAL_FRESH.has(record.phase)) return Object.freeze({ action: "fresh", reason: null, manager, record });
  return Object.freeze({ action: "invalid", reason: "P3_CEREMONY_EXISTING_STATE_INVALID", manager, record });
}
function classifyAuthorizationStore(record, ceremonyStore) {
  if (!record || typeof ceremonyStore?.list !== "function" || typeof ceremonyStore?.load !== "function") {
    fail("P3_CEREMONY_AUTHORIZATION_STORE_INVALID");
  }
  const identifiers = ceremonyStore.list();
  if (!Array.isArray(identifiers)
    || identifiers.some((id) => typeof id !== "string" || !/^0x[0-9a-f]{64}$/u.test(id))) {
    fail("P3_CEREMONY_AUTHORIZATION_STORE_INVALID");
  }
  if (record.phase === "transitioning_to_exact_authorization" && identifiers.length === 0) {
    return Object.freeze({ action: "begin", requestId: null });
  }
  if (record.phase === "approved_authorization_persisted"
    && identifiers.length === 1 && identifiers[0] === record.authorizationRequestId) {
    const stored = ceremonyStore.load(identifiers[0]);
    if (stored?.requestId === identifiers[0] && stored.state === "approved") {
      return Object.freeze({ action: "resume", requestId: identifiers[0] });
    }
  }
  return Object.freeze({ action: "invalidate", requestId: null });
}
function archiveInvalidatedCeremony(options, reason) {
  const classified = classifyExistingCeremony(options);
  let record = classified.record;
  if (ACTIVE_UNSAFE.has(record.phase) || SAFE_RESUME.has(record.phase)) {
    record = classified.manager.transition("restart_detected", { restartDetected: true, diagnosticStage: "startup", diagnosticCode: sanitizedCode(reason) });
  }
  if (record.phase === "restart_detected"
    || TRANSITIONS[record.phase].includes("invalidated")) {
    record = classified.manager.transition("invalidated", { invalidated: true, requestType: record.requestType, diagnosticStage: "startup", diagnosticCode: sanitizedCode(reason) });
  }
  const parent = path.dirname(options.storageRoot);
  const suffix = `${record.updatedAt}-${(record.enrollmentRequestId || record.authorizationRequestId || "none").slice(2, 14)}`;
  const destination = path.join(parent, `${path.basename(options.storageRoot)}-incident-${suffix}`);
  if (fs.existsSync(destination)) fail("P3_CEREMONY_ARCHIVE_COLLISION");
  fs.renameSync(options.storageRoot, destination);
  fs.chmodSync(destination, 0o700);
  syncDirectory(parent);
  return Object.freeze({ destination, record });
}

function operatorStatus(phase) {
  return Object.freeze({
    enrollment_request_created: "ENROLLMENT_REQUEST_CREATED",
    waiting_for_enrollment_contact: "WAITING_FOR_ENROLLMENT_CONTACT",
    enrollment_preflight_observed: "ENROLLMENT_PREFLIGHT_RECEIVED",
    enrollment_completion_received: "ENROLLMENT_COMPLETION_RECEIVED",
    enrollment_completion_rejected: "ENROLLMENT_RESPONSE_REJECTED",
    enrollment_persistence_failed: "ENROLLMENT_PERSISTENCE_FAILED",
    accepted_enrollment_persisted: "ENROLLMENT_ACCEPTED",
    transitioning_to_exact_authorization: "READY_FOR_EXACT_AUTHORIZATION",
    expired: "ENROLLMENT_REQUEST_EXPIRED",
    cancelled: "ENROLLMENT_REQUEST_CANCELLED",
    invalidated: "PRIOR_REQUEST_INVALIDATED_AFTER_RESTART"
  }[phase] || "CEREMONY_STATE_UPDATED");
}
async function waitForEnrollmentLifecycle(options) {
  exactObject(options, ["host", "requestId", "lifecycle", "announce", "sleep"], "P3_CEREMONY_WAIT_OPTIONS_INVALID");
  let priorPhase = options.lifecycle.snapshot().phase;
  while (true) {
    const value = options.host.status(options.requestId);
    const record = options.lifecycle.recordHostStatus({
      requestId: value.requestId, state: value.state, expiresAt: value.expiresAt,
      preflightCount: value.preflightCount, completionAttemptCount: value.completionAttemptCount,
      lastAttempt: value.lastAttempt
    });
    if (record.phase !== priorPhase) {
      options.announce({ status: operatorStatus(record.phase), phase: record.phase,
        diagnosticCode: record.diagnosticCode, publicMutationOccurred: false });
      priorPhase = record.phase;
    }
    if (value.state === "completed") return record;
    if (["expired", "cancelled", "failed"].includes(value.state)
      || ["enrollment_completion_rejected", "enrollment_persistence_failed"].includes(record.phase)) {
      fail(record.diagnosticCode || `P3_CEREMONY_ENROLLMENT_${String(value.state).toUpperCase()}`);
    }
    await options.sleep();
  }
}
async function physicalEnrollmentLifecycle(options) {
  exactObject(options, ["host", "lifecycle", "createQrImage", "announce", "sleep"], "P3_CEREMONY_ENROLLMENT_OPTIONS_INVALID");
  try {
    const stored = await options.host.activeEnrollment();
    const phase = options.lifecycle.snapshot().phase;
    if (!SAFE_RESUME.has(phase)) fail("P3_CEREMONY_STORED_ENROLLMENT_WITHOUT_SAFE_LIFECYCLE");
    options.lifecycle.markResumed();
    if (phase === "accepted_enrollment_persisted") {
      options.lifecycle.transition("transitioning_to_exact_authorization", {
        requestType: "exact_authorization", diagnosticStage: "authorization_transition",
        diagnosticCode: null, persistenceSucceeded: true
      });
    }
    options.announce({ status: "READY_FOR_EXACT_AUTHORIZATION", safelyResumed: true, publicMutationOccurred: false });
    return stored;
  } catch (error) {
    if (error?.code !== "ROUTINE_ENROLLMENT_NOT_FOUND") throw error;
  }
  if (options.lifecycle.snapshot().phase !== "no_active_request") fail("P3_CEREMONY_FRESH_STATE_REQUIRED");
  await options.host.start();
  const started = await options.host.beginEnrollment();
  options.lifecycle.transition("enrollment_request_created", {
    requestType: "enrollment", enrollmentRequestId: started.requestId,
    expiresAt: started.expiresAt, diagnosticStage: "enrollment_create", diagnosticCode: null
  });
  const imagePath = options.createQrImage(started);
  options.lifecycle.transition("waiting_for_enrollment_contact", {
    requestType: "enrollment", diagnosticStage: "enrollment_wait", diagnosticCode: null
  });
  options.announce({ status: "PHONE_ENROLLMENT_SCAN_REQUIRED", requestId: started.requestId,
    expiresAt: started.expiresAt, comparisonFingerprint: started.comparisonFingerprint,
    qrImagePath: imagePath, publicMutationOccurred: false });
  await waitForEnrollmentLifecycle({ host: options.host, requestId: started.requestId,
    lifecycle: options.lifecycle, announce: options.announce, sleep: options.sleep });
  await options.host.stop();
  const stored = await options.host.activeEnrollment();
  options.lifecycle.transition("transitioning_to_exact_authorization", {
    requestType: "exact_authorization", diagnosticStage: "authorization_transition",
    diagnosticCode: null, persistenceSucceeded: true
  });
  options.announce({ status: "READY_FOR_EXACT_AUTHORIZATION", safelyResumed: false, publicMutationOccurred: false });
  return stored;
}

module.exports = Object.freeze({
  FORMAT, FILE_NAME, PHASES, TRANSITIONS, CeremonyLifecycleError,
  createControlledSepoliaBetaCeremonyLifecycle, classifyExistingCeremony,
  classifyAuthorizationStore, archiveInvalidatedCeremony, sanitizedCode, waitForEnrollmentLifecycle,
  physicalEnrollmentLifecycle
});
