const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryTrustEvaluationDraftCollector,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityDraft(id = "capability-1", overrides = {}) {
  const result = createCapabilityGrantDraft({
    capabilityRequest: createCapabilityRequestDraft({
      requestId: id,
      applicationId: "ethereum-net",
      capability: "request_message_signature",
      sensitivity: "sensitive",
      requestedAt: "2026-07-10T00:00:00.000Z"
    }),
    sessionId: "session-1",
    auditCorrelationId: `${id}:capability-draft`,
    createdAt: "2026-07-10T00:00:00.000Z",
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function trustDraft(id, overrides = {}) {
  const result = createTrustEvaluationDraft({
    requestId: id,
    capabilityGrantDraft: capabilityDraft(`${id}:capability`),
    credentialReference: {
      credentialId: `${id}:credential`,
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    deviceReference: {
      deviceId: `${id}:device`,
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    auditCorrelationId: id,
    createdAt: "2026-07-10T00:00:00.000Z",
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function userSession(activeCapabilities = []) {
  const result = createUserSessionContext({
    sessionId: "session-1",
    ownerCommitment: "0x1234",
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: activeCapabilities,
    pendingIntentIds: [],
    policyMode: "default"
  });
  assert.equal(result.status, "approved");
  return result.context;
}

function assertDraftIsNotDecision(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("providestrustdecision\":true"), false);
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.authenticated, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore in-memory Trust Evaluation Draft collector", function () {
  it("starts empty", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();

    assert.equal(collector.count(), 0);
    assert.deepEqual(collector.getAll(), []);
    assert.equal(collector.getById("missing"), undefined);
  });

  it("adds and gets a draft", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    const item = trustDraft("trust-draft-1");

    const result = collector.addDraft(item);

    assert.equal(result.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById("trust-draft-1:draft").trustEvaluationDraftId, "trust-draft-1:draft");
    assert.equal(Object.isFrozen(collector.getById("trust-draft-1:draft")), true);
    assert.equal(Object.isFrozen(collector.getAll()), true);
    assertDraftIsNotDecision(collector.getById("trust-draft-1:draft"));
  });

  it("removes a draft", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    collector.addDraft(trustDraft("trust-draft-1"));

    const result = collector.removeDraft("trust-draft-1:draft");

    assert.equal(result.status, "removed");
    assert.equal(result.removedDraft.trustEvaluationDraftId, "trust-draft-1:draft");
    assert.equal(collector.count(), 0);
  });

  it("clears the collector", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    collector.addDraft(trustDraft("trust-draft-1"));
    collector.addDraft(trustDraft("trust-draft-2"));

    const result = collector.clear();

    assert.equal(result.status, "cleared");
    assert.equal(result.collection.count, 0);
    assert.equal(collector.count(), 0);
  });

  it("protects duplicate draft IDs", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    collector.addDraft(trustDraft("trust-draft-1"));

    const result = collector.addDraft(trustDraft("trust-draft-1"));

    assert.equal(result.status, "rejected_duplicate");
    assert.equal(collector.count(), 1);
  });

  it("rejects malformed, secret-shaped, or authority-shaped draft objects", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();

    const malformed = collector.addDraft({
      ...trustDraft("trust-draft-1"),
      trustEvaluationDraftId: ""
    });
    const secretShaped = collector.addDraft({
      ...trustDraft("trust-draft-2"),
      phil_secret: "must-not-enter"
    });
    const trustedShaped = collector.addDraft({
      ...trustDraft("trust-draft-3"),
      trusted: true
    });

    assert.equal(malformed.status, "rejected_invalid");
    assert.equal(secretShaped.status, "rejected_invalid");
    assert.equal(trustedShaped.status, "rejected_invalid");
    assert.equal(JSON.stringify(secretShaped).includes("must-not-enter"), false);
    assert.ok(secretShaped.errors.some((error) => error.includes("private material or active trust fields")));
    assert.ok(trustedShaped.errors.some((error) => error.includes("private material or active trust fields")));
    assert.equal(collector.count(), 0);
  });

  it("evicts oldest drafts at maximum size", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector({ maxDraftCount: 2 });
    collector.addDraft(trustDraft("trust-draft-1"));
    collector.addDraft(trustDraft("trust-draft-2"));

    const result = collector.addDraft(trustDraft("trust-draft-3"));

    assert.equal(result.status, "evicted_oldest");
    assert.equal(result.evictedDrafts[0].trustEvaluationDraftId, "trust-draft-1:draft");
    assert.equal(collector.count(), 2);
    assert.equal(collector.getById("trust-draft-1:draft"), undefined);
    assert.equal(collector.getById("trust-draft-2:draft").trustEvaluationDraftId, "trust-draft-2:draft");
    assert.equal(collector.getById("trust-draft-3:draft").trustEvaluationDraftId, "trust-draft-3:draft");
  });

  it("filters and queries drafts", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    collector.addDraft(trustDraft("trust-draft-1", { sessionId: "session-1" }));
    collector.addDraft(trustDraft("trust-draft-2", { sessionId: "session-2" }));
    collector.addDraft(trustDraft("trust-draft-3", {
      sessionId: "session-2",
      credentialReference: {
        credentialId: "credential-special",
        credentialKind: "webauthn"
      }
    }));

    assert.deepEqual(
      collector.filter({ sessionId: "session-2" }).map((item) => item.trustEvaluationDraftId),
      ["trust-draft-2:draft", "trust-draft-3:draft"]
    );
    assert.deepEqual(
      collector.query({ filter: { sessionId: "session-2" }, offset: 1, limit: 1 }).map(
        (item) => item.trustEvaluationDraftId
      ),
      ["trust-draft-3:draft"]
    );
    assert.deepEqual(
      collector.filter({ credentialId: "credential-special" }).map(
        (item) => item.trustEvaluationDraftId
      ),
      ["trust-draft-3:draft"]
    );
  });

  it("facade optionally collects successful Trust Evaluation Drafts", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      trustEvaluationDraftCollector: collector,
      userSessionContext: userSession()
    });

    const result = api.requestTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft(),
      credentialReference: {
        credentialId: "credential-1",
        credentialKind: "webauthn"
      },
      deviceReference: {
        deviceId: "device-1"
      }
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.trustEvaluationDraftCollectionResult.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(
      collector.getById(result.value.trustEvaluationDraft.trustEvaluationDraftId)
        .trustEvaluationDraftId,
      result.value.trustEvaluationDraft.trustEvaluationDraftId
    );
    assertDraftIsNotDecision(result.value.trustEvaluationDraft);
  });

  it("facade without a collector preserves prior behavior", function () {
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: userSession()
    });

    const result = api.requestTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft()
    });

    assert.equal(result.status, "approved");
    assert.ok(result.value.trustEvaluationDraft);
    assert.equal(result.value.trustEvaluationDraftCollectionResult, undefined);
  });

  it("does not mutate User Session or capability draft state", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    const store = createEphemeralUserSessionStore();
    const draft = capabilityDraft();
    store.setSessionContext(userSession(["existing-capability"]));
    const before = JSON.stringify(draft);
    const api = createValidationOnlyRuntimeApi({
      trustEvaluationDraftCollector: collector,
      userSessionStore: store
    });

    const result = api.requestTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: draft
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assert.equal(JSON.stringify(draft), before);
    assert.equal(Object.hasOwn(result.value.trustEvaluationDraft, "trustDecision"), false);
  });

  it("does not collect malformed facade trust draft requests", function () {
    const collector = createInMemoryTrustEvaluationDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      trustEvaluationDraftCollector: collector
    });

    const result = api.requestTrustEvaluationDraft({
      requestId: "",
      capabilityGrantDraft: capabilityDraft()
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.trustEvaluationDraft, undefined);
    assert.equal(result.value.trustEvaluationDraftCollectionResult, undefined);
    assert.equal(collector.count(), 0);
  });

  it("does not call credential loading, WebAuthn, vault, storage, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      credentialLoadCalls: 0,
      webAuthnCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const collector = createInMemoryTrustEvaluationDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      trustEvaluationDraftCollector: collector,
      userSessionContext: userSession()
    });

    const result = api.requestTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft(),
      credentialReference: {
        credentialId: "credential-1",
        publicMetadata: {
          hooks
        }
      }
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      credentialLoadCalls: 0,
      webAuthnCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(collector.count(), 1);
    assertDraftIsNotDecision(result.value.trustEvaluationDraft);
  });
});
