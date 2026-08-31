const assert = require("node:assert/strict");

const {
  createAdapterManifestDraft,
  createApplicationManifestDraft,
  createAuditCorrelationId,
  createCapabilityRequestDraft,
  createIntentDraft,
  createRuntimeRequestContext,
  isAdapterStatus,
  isApplicationTrustLevel,
  isCapabilityStatus,
  isIntentStatus,
  isRuntimeErrorCategory,
  isRuntimeResultStatus,
  isUserSessionLockState,
  runtimeDenied,
  runtimeFailed,
  runtimeOk,
  runtimePending,
  validateAdapterManifestShape,
  validateApplicationManifestShape,
  validateCapabilityRequestShape,
  validateIntentShape,
  validateRuntimeRequestContextShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

describe("PhilCore runtime request helpers", function () {
  it("creates and validates a well-formed intent draft", function () {
    const intent = createIntentDraft({
      intentId: "intent-1",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {
        chainId: 8453n,
        target: "0x0000000000000000000000000000000000000001",
        value: 0n
      },
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    });

    assert.equal(intent.status, "created");
    assert.deepEqual(validateIntentShape(intent), {
      valid: true,
      errors: []
    });
  });

  it("reports missing required intent fields", function () {
    const result = validateIntentShape({
      intentId: "",
      applicationId: "ethereum-net",
      requestedCapabilities: [],
      payload: {}
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("intentId is required"));
    assert.ok(result.errors.includes("kind is required"));
    assert.ok(result.errors.includes("requestedCapabilities must be a non-empty string array"));
  });

  it("reports invalid enum and expired intent shapes", function () {
    const result = validateIntentShape({
      intentId: "intent-expired",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {},
      status: "half-open",
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("status is invalid"));
    assert.ok(result.errors.includes("expiresAt must be in the future"));
  });

  it("creates and validates capability request drafts", function () {
    const request = createCapabilityRequestDraft({
      requestId: "cap-1",
      applicationId: "ethereum-net",
      capability: "request_message_signature",
      sensitivity: "sensitive",
      scope: {
        chainId: 8453n,
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      }
    });

    assert.deepEqual(validateCapabilityRequestShape(request), {
      valid: true,
      errors: []
    });
  });

  it("reports invalid capability request shapes", function () {
    const result = validateCapabilityRequestShape({
      requestId: "cap-invalid",
      applicationId: "",
      capability: "",
      sensitivity: "root",
      requestedAt: "not-a-date"
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("applicationId is required"));
    assert.ok(result.errors.includes("capability is required"));
    assert.ok(result.errors.includes("sensitivity is invalid"));
    assert.ok(result.errors.includes("requestedAt must be a parseable date string"));
  });

  it("validates runtime context, application manifest, and adapter manifest drafts", function () {
    const context = createRuntimeRequestContext({
      requestId: "runtime-request-1",
      sessionId: "session-1",
      applicationId: "ethereum-net",
      requestedAt: new Date().toISOString()
    });
    const application = createApplicationManifestDraft({
      applicationId: "ethereum-net",
      displayName: "Ethereum Net",
      version: "0.1.0",
      requestedCapabilities: ["read_balance"]
    });
    const adapter = createAdapterManifestDraft({
      adapterId: "ethereum",
      displayName: "Ethereum Adapter",
      version: "0.1.0",
      executionEnvironment: "ethereum",
      providedCapabilities: ["read_balance"],
      requiresAuthorizationPackage: true
    });

    assert.equal(validateRuntimeRequestContextShape(context).valid, true);
    assert.equal(validateApplicationManifestShape(application).valid, true);
    assert.equal(validateAdapterManifestShape(adapter).valid, true);
  });

  it("creates deterministic audit correlation ids", function () {
    assert.equal(
      createAuditCorrelationId(["session-1", "", "intent-1", "audit-1"]),
      "session-1:intent-1:audit-1"
    );
  });

  it("constructs runtime-neutral result envelopes", function () {
    const error = {
      category: "policy_denied",
      code: "POLICY_DENIED",
      message: "policy denied by test fixture",
      recoverable: false
    };

    assert.deepEqual(runtimeOk({ ok: true }), {
      status: "approved",
      value: { ok: true },
      auditEventId: undefined
    });
    assert.equal(runtimePending({ pendingApprovalId: "approval-1" }).status, "pending");
    assert.deepEqual(runtimeDenied(error), {
      status: "denied",
      error,
      auditEventId: undefined
    });
    assert.deepEqual(runtimeFailed(error), {
      status: "failed",
      error,
      auditEventId: undefined
    });
  });

  it("exposes conservative runtime type guards", function () {
    assert.equal(isRuntimeErrorCategory("policy_denied"), true);
    assert.equal(isRuntimeErrorCategory("policy-approved"), false);
    assert.equal(isIntentStatus("created"), true);
    assert.equal(isIntentStatus("drafting"), false);
    assert.equal(isCapabilityStatus("granted"), true);
    assert.equal(isCapabilityStatus("approved"), false);
    assert.equal(isUserSessionLockState("locked"), true);
    assert.equal(isUserSessionLockState("open"), false);
    assert.equal(isApplicationTrustLevel("verified"), true);
    assert.equal(isApplicationTrustLevel("core"), false);
    assert.equal(isAdapterStatus("available"), true);
    assert.equal(isAdapterStatus("online"), false);
    assert.equal(isRuntimeResultStatus("pending"), true);
    assert.equal(isRuntimeResultStatus("complete"), false);
  });
});
