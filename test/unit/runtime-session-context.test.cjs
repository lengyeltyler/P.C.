const assert = require("node:assert/strict");

const {
  bindSessionContextToRuntimeRequest,
  createCapabilityRequestDraft,
  createIntentDraft,
  createRuntimeRequestContext,
  createSessionBoundRuntimeRequestContext,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  validateUserSessionContextShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function validSessionInput(overrides = {}) {
  return {
    sessionId: "session-1",
    ownerCommitment: "0x1234",
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: ["capability-1"],
    pendingIntentIds: ["intent-1"],
    policyMode: "default",
    recoveryState: "inactive",
    timeout: {
      lockTimeoutAt: new Date(Date.now() + 60_000).toISOString()
    },
    metadata: {
      requestMetadata: {
        source: "unit-test"
      }
    },
    ...overrides
  };
}

function validSessionContext(overrides = {}) {
  const result = createUserSessionContext(validSessionInput(overrides));
  assert.equal(result.status, "approved");
  return result.context;
}

function validIntentRequest() {
  return {
    requestId: "request-1",
    applicationId: "ethereum-net",
    requestedAt: new Date().toISOString(),
    metadata: {
      hooks: {
        vaultCalls: 0,
        storageCalls: 0,
        trustCalls: 0,
        policyCalls: 0,
        authorizationCalls: 0,
        proofCalls: 0,
        adapterCalls: 0
      }
    },
    intent: createIntentDraft({
      intentId: "intent-1",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {
        chainId: 8453n,
        target: "0x0000000000000000000000000000000000000001"
      },
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    })
  };
}

function validCapabilityRequest() {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_message_signature",
    sensitivity: "sensitive",
    requestedAt: new Date().toISOString()
  });
}

describe("PhilCore runtime User Session context helpers", function () {
  it("creates a valid ephemeral User Session context and snapshot", function () {
    const result = createUserSessionContext(validSessionInput());

    assert.equal(result.status, "approved");
    assert.equal(result.context.sessionId, "session-1");
    assert.equal(result.context.ownerCommitment, "0x1234");
    assert.deepEqual(result.context.activeCapabilityIds, ["capability-1"]);
    assert.deepEqual(result.context.pendingIntentIds, ["intent-1"]);
    assert.equal(result.snapshot.context, result.context);
    assert.equal(Object.isFrozen(result.context), true);
  });

  it("rejects malformed User Session context shape", function () {
    const result = createUserSessionContext({
      sessionId: "",
      status: "authenticated",
      activeCapabilityIds: ["capability-1", ""],
      pendingIntentIds: "intent-1",
      policyMode: "ambient",
      recoveryState: "maybe",
      timeout: {
        lockTimeoutAt: "not-a-date"
      }
    });

    assert.equal(result.status, "failed");
    assert.ok(result.errors.includes("sessionId is required"));
    assert.ok(result.errors.includes("status is invalid"));
    assert.ok(result.errors.includes("activeCapabilityIds must be a string array when provided"));
    assert.ok(result.errors.includes("pendingIntentIds must be a string array when provided"));
    assert.ok(result.errors.includes("policyMode is invalid"));
    assert.ok(result.errors.includes("recoveryState is invalid"));
    assert.ok(result.errors.includes("timeout.lockTimeoutAt must be a parseable date string"));
  });

  it("binds session context to runtime request context", function () {
    const session = validSessionContext();
    const context = createRuntimeRequestContext({
      requestId: "request-1",
      applicationId: "ethereum-net",
      metadata: {
        source: "unit-test"
      }
    });

    const bound = bindSessionContextToRuntimeRequest(context, session);

    assert.equal(bound.sessionId, "session-1");
    assert.equal(bound.userSession, session);
    assert.equal(bound.metadata.source, "unit-test");
    assert.equal(bound.metadata.userSession.sessionId, "session-1");
    assert.equal(bound.metadata.userSession.ownerCommitment, "0x1234");
  });

  it("does not retain a session request-metadata subtree beyond the default depth", function () {
    const session = validSessionContext();
    const context = createRuntimeRequestContext({
      requestId: "request-depth-redaction",
      applicationId: "ethereum-net",
      metadata: {
        a: [{ b: [{ c: { password: "SESSION-DEPTH-CANARY" } }] }]
      }
    });

    const bound = bindSessionContextToRuntimeRequest(context, session);

    assert.equal(bound.metadata.a[0].b[0].c, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(JSON.stringify(bound).includes("SESSION-DEPTH-CANARY"), false);
  });

  it("creates a session-bound runtime request context", function () {
    const session = validSessionContext({ status: "locked", policyMode: "strict" });
    const bound = createSessionBoundRuntimeRequestContext({
      requestId: "request-1",
      applicationId: "ethereum-net"
    }, session);

    assert.equal(bound.sessionId, "session-1");
    assert.equal(bound.userSession.status, "locked");
    assert.equal(validateUserSessionContextShape(bound.userSession).valid, true);
  });

  it("includes session correlation in facade results and audit drafts", function () {
    const session = validSessionContext({ status: "partially-unlocked" });
    const api = createValidationOnlyRuntimeApi({ userSessionContext: session });
    const result = api.requestCapability(validCapabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, "session-1");
    assert.equal(result.value.auditEventDraft.sessionId, "session-1");
    assert.equal(result.value.auditEventDraft.redactedDetails.sessionId, "session-1");
  });

  it("preserves no-session facade behavior when no context is supplied", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability(validCapabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, undefined);
    assert.equal(result.value.auditEventDraft.sessionId, undefined);
  });

  it("represents lock, recovery, and suspend states as metadata only", function () {
    const states = [
      { status: "locked", recoveryState: "inactive" },
      { status: "partially-unlocked", recoveryState: "available" },
      { status: "unlocked", recoveryState: "inactive" },
      { status: "recovery", recoveryState: "active", policyMode: "recovery" },
      { status: "suspended", recoveryState: "pending" }
    ];

    for (const state of states) {
      const result = createUserSessionContext(validSessionInput(state));
      assert.equal(result.status, "approved", state.status);
      assert.equal(result.context.status, state.status);
      assert.equal(result.context.recoveryState, state.recoveryState);
    }
  });

  it("does not call vault, storage, trust, policy, authorization, proof, or adapter hooks", function () {
    const session = validSessionContext({ status: "locked" });
    const api = createValidationOnlyRuntimeApi({ userSessionContext: session });
    const request = validIntentRequest();
    const hooks = request.metadata.hooks;

    const result = api.requestAuthorization(request);

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(result.value.auditEventDraft.sessionId, "session-1");
  });
});
