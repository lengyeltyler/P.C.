const assert = require("node:assert/strict");

const {
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createIntentDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function sessionContext(sessionId, overrides = {}) {
  const result = createUserSessionContext({
    sessionId,
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: [`capability-${sessionId}`],
    pendingIntentIds: [`intent-${sessionId}`],
    policyMode: "default",
    recoveryState: "inactive",
    metadata: {
      requestMetadata: {
        source: sessionId
      }
    },
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.context;
}

function capabilityRequest() {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_message_signature",
    sensitivity: "sensitive",
    requestedAt: new Date().toISOString()
  });
}

function intentRequest(metadata = {}) {
  return {
    requestId: "request-1",
    applicationId: "ethereum-net",
    requestedAt: new Date().toISOString(),
    metadata,
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

describe("PhilCore ephemeral User Session store", function () {
  it("starts empty", function () {
    const store = createEphemeralUserSessionStore();

    assert.equal(store.hasSessionContext(), false);
    assert.equal(store.getSessionContext(), undefined);
    assert.equal(store.getSnapshot(), undefined);
    assert.deepEqual(store.getState(), {
      hasSessionContext: false,
      sessionId: undefined,
      snapshot: undefined
    });
  });

  it("sets and gets one session context", function () {
    const store = createEphemeralUserSessionStore();
    const context = sessionContext("session-1");

    const result = store.setSessionContext(context);

    assert.equal(result.status, "set");
    assert.equal(store.hasSessionContext(), true);
    assert.equal(store.getSessionContext().sessionId, "session-1");
    assert.equal(store.getSnapshot().context.sessionId, "session-1");
    assert.equal(Object.isFrozen(store.getSessionContext()), true);
    assert.equal(Object.isFrozen(store.getSnapshot()), true);
  });

  it("replaces session context and keeps one-context-only behavior", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1"));

    const result = store.replaceSessionContext(sessionContext("session-2"));

    assert.equal(result.status, "replaced");
    assert.equal(store.hasSessionContext(), true);
    assert.equal(store.getSessionContext().sessionId, "session-2");
    assert.equal(store.getState().sessionId, "session-2");
  });

  it("setSessionContext replaces an existing context without creating a registry", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1"));

    const result = store.setSessionContext(sessionContext("session-2"));

    assert.equal(result.status, "replaced");
    assert.equal(store.getSessionContext().sessionId, "session-2");
  });

  it("clears session context", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1"));

    const result = store.clearSessionContext();

    assert.equal(result.status, "cleared");
    assert.equal(store.hasSessionContext(), false);
    assert.equal(store.getSessionContext(), undefined);
    assert.equal(store.getSnapshot(), undefined);
  });

  it("returned snapshots cannot be mutated to affect store state", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1"));
    const snapshot = store.getSnapshot();

    snapshot.context.metadata.requestMetadata.source = "changed";
    try {
      snapshot.context.activeCapabilityIds.push("capability-extra");
    } catch {
      // Frozen arrays may throw; either way the store state must remain unchanged.
    }

    assert.equal(store.getSnapshot().context.metadata.requestMetadata.source, "session-1");
    assert.deepEqual(store.getSnapshot().context.activeCapabilityIds, ["capability-session-1"]);
  });

  it("rejects sensitive metadata using existing guardrails", function () {
    const store = createEphemeralUserSessionStore();
    const result = store.setSessionContext({
      sessionId: "session-unsafe",
      status: "unlocked",
      activeCapabilityIds: [],
      pendingIntentIds: [],
      policyMode: "default",
      metadata: {
        requestMetadata: {
          phil_secret: "must-not-store"
        }
      }
    });

    assert.equal(result.status, "invalid");
    assert.equal(store.hasSessionContext(), false);
    assert.ok(result.errors.some((error) => error.includes("phil_secret")));
    assert.equal(JSON.stringify(result).includes("must-not-store"), false);
  });

  it("facade can use session context from the store", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-store"));
    const api = createValidationOnlyRuntimeApi({ userSessionStore: store });

    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, "session-store");
    assert.equal(result.value.auditEventDraft.sessionId, "session-store");
  });

  it("direct session context takes precedence over store context", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-store"));
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: sessionContext("session-direct"),
      userSessionStore: store
    });

    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, "session-direct");
    assert.equal(result.value.auditEventDraft.sessionId, "session-direct");
    assert.equal(store.getSessionContext().sessionId, "session-store");
  });

  it("no-session behavior remains unchanged without a store context", function () {
    const store = createEphemeralUserSessionStore();
    const api = createValidationOnlyRuntimeApi({ userSessionStore: store });

    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, undefined);
    assert.equal(result.value.auditEventDraft.sessionId, undefined);
  });

  it("does not call vault, storage, trust, policy, authorization, proof, or adapter hooks", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1"));
    const api = createValidationOnlyRuntimeApi({ userSessionStore: store });
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };

    const result = api.requestAuthorization(intentRequest({ hooks }));

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
    assert.equal(store.getSessionContext().sessionId, "session-1");
  });
});
