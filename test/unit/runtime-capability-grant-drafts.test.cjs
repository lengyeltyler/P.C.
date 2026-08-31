const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  isCapabilityGrantDraftStatus,
  validateCapabilityGrantDraftInput,
  validateCapabilityGrantDraftShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function stringify(value) {
  return JSON.stringify(value);
}

function capabilityRequest(overrides = {}) {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_message_signature",
    sensitivity: "sensitive",
    requestedAt: new Date().toISOString(),
    ...overrides
  });
}

function sessionContext(sessionId, activeCapabilities = []) {
  const result = createUserSessionContext({
    sessionId,
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: activeCapabilities,
    pendingIntentIds: [],
    policyMode: "default"
  });
  assert.equal(result.status, "approved");
  return result.context;
}

function assertNoAuthority(value) {
  const text = stringify(value).toLowerCase();
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(text.includes("authoritytoken"), false);
  assert.equal(text.includes("signingauthority"), false);
  assert.equal(text.includes("walletauthority"), false);
  assert.equal(value.providesAuthority, false);
  assert.equal(value.persisted, false);
  assert.notEqual(value.status, "granted");
  assert.notEqual(value.outcome, "granted");
}

describe("PhilCore validation-only capability grant drafts", function () {
  it("creates a capability grant draft for a valid capability request", function () {
    const result = createCapabilityGrantDraft({
      capabilityRequest: capabilityRequest(),
      sessionId: "session-1"
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.capabilityRequestId, "capability-1");
    assert.equal(result.value.capabilityName, "request_message_signature");
    assert.equal(result.value.applicationId, "ethereum-net");
    assert.equal(result.value.sessionId, "session-1");
    assert.equal(result.value.status, "pending_policy");
    assert.equal(result.value.outcome, "draft_created");
    assert.equal(validateCapabilityGrantDraftShape(result.value).valid, true);
    assert.equal(Object.isFrozen(result.value), true);
    assertNoAuthority(result.value);
  });

  it("does not create a draft for invalid capability request input", function () {
    const result = createCapabilityGrantDraft({
      capabilityRequest: {
        requestId: "",
        applicationId: "",
        capability: "",
        sensitivity: "root"
      }
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.equal(result.error.category, "invalid_intent");
  });

  it("facade returns validation and audit output only for malformed capability requests", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability({
      requestId: "bad-capability",
      applicationId: "",
      capability: "",
      sensitivity: "root"
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.capabilityGrantDraft, undefined);
    assert.equal(result.value.auditEventDraft.category, "capability");
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
  });

  it("marks expired capability request drafts as expired without active authority", function () {
    const result = createCapabilityGrantDraft({
      capabilityRequest: capabilityRequest({
        scope: {
          expiresAt: new Date(Date.now() - 60_000).toISOString()
        }
      }),
      sessionId: "session-1"
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "expired");
    assert.equal(result.value.outcome, "expired");
    assertNoAuthority(result.value);
  });

  it("draft status helpers exclude granted authority", function () {
    assert.equal(isCapabilityGrantDraftStatus("pending_policy"), true);
    assert.equal(isCapabilityGrantDraftStatus("draft_created"), true);
    assert.equal(isCapabilityGrantDraftStatus("granted"), false);
  });

  it("facade creates a draft with direct session correlation", function () {
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: sessionContext("session-direct")
    });
    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.sessionId, "session-direct");
    assert.equal(result.value.capabilityGrantDraft.sessionId, "session-direct");
    assert.equal(result.value.auditEventDraft.redactedDetails.capabilityGrantDraftId,
      result.value.capabilityGrantDraft.capabilityGrantDraftId);
    assertNoAuthority(result.value.capabilityGrantDraft);
  });

  it("facade direct session context takes precedence over store context", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-store"));
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: sessionContext("session-direct"),
      userSessionStore: store
    });

    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.value.capabilityGrantDraft.sessionId, "session-direct");
    assert.equal(store.getSessionContext().sessionId, "session-store");
  });

  it("facade can use store session context without mutating active capabilities", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-store", ["existing-capability"]));
    const before = store.getSessionContext().activeCapabilityIds.slice();
    const api = createValidationOnlyRuntimeApi({ userSessionStore: store });

    const result = api.requestCapability(capabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.capabilityGrantDraft.sessionId, "session-store");
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, before);
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
  });

  it("redacts draft metadata and scope metadata", function () {
    const result = createCapabilityGrantDraft({
      capabilityRequest: capabilityRequest({
        scope: {
          resource: "message",
          metadata: {
            safe: "kept",
            secret: "secret-value"
          }
        }
      }),
      metadata: {
        safe: "kept",
        passphrase: "passphrase-value"
      }
    });
    const text = stringify(result.value);

    assert.equal(result.value.scope.metadata.safe, "kept");
    assert.equal(result.value.scope.metadata.secret, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.metadata.safe, "kept");
    assert.equal(result.value.metadata.passphrase, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(text.includes("secret-value"), false);
    assert.equal(text.includes("passphrase-value"), false);
  });

  it("rejects active-authority fields instead of producing a draft", function () {
    const result = createCapabilityGrantDraft({
      capabilityRequest: capabilityRequest(),
      metadata: {
        authorizationPackage: {
          id: "authz-1"
        }
      }
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.ok(result.error.details.errors[0].includes("active authority fields"));
  });

  it("validates no active authority or secret-shaped fields in draft shape", function () {
    const result = validateCapabilityGrantDraftInput({
      capabilityRequest: capabilityRequest(),
      signingKey: "key-value"
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors[0].includes("active authority fields"));
  });

  it("facade does not call trust, policy, user approval, authorization, proof, adapter, vault, or persistence hooks", function () {
    const hooks = {
      trustCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      vaultCalls: 0,
      persistenceCalls: 0
    };
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: sessionContext("session-1")
    });
    const result = api.requestCapability({
      ...capabilityRequest(),
      scope: {
        metadata: {
          hooks
        }
      }
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      trustCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      vaultCalls: 0,
      persistenceCalls: 0
    });
    assertNoAuthority(result.value.capabilityGrantDraft);
  });
});
