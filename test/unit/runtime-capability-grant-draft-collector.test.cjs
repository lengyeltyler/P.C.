const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryCapabilityGrantDraftCollector,
  createUserSessionContext,
  createValidationOnlyRuntimeApi
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityRequest(id, overrides = {}) {
  return createCapabilityRequestDraft({
    requestId: id,
    applicationId: "ethereum-net",
    capability: "request_message_signature",
    sensitivity: "sensitive",
    requestedAt: new Date().toISOString(),
    ...overrides
  });
}

function draft(id, overrides = {}) {
  const result = createCapabilityGrantDraft({
    capabilityRequest: capabilityRequest(id),
    sessionId: "session-1",
    auditCorrelationId: id,
    createdAt: "2026-07-10T00:00:00.000Z",
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.value;
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

function assertDraftIsNotGrant(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("grantid"), false);
  assert.equal(text.includes("decision"), false);
  assert.equal(text.includes("grantedat"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.providesAuthority, false);
  assert.equal(value.persisted, false);
  assert.notEqual(value.status, "granted");
  assert.notEqual(value.outcome, "granted");
}

describe("PhilCore in-memory capability grant draft collector", function () {
  it("starts empty", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();

    assert.equal(collector.count(), 0);
    assert.deepEqual(collector.getAll(), []);
    assert.equal(collector.getById("missing"), undefined);
  });

  it("adds and gets a draft", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const item = draft("draft-1");

    const result = collector.addDraft(item);

    assert.equal(result.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById("draft-1:draft").capabilityGrantDraftId, "draft-1:draft");
    assert.equal(Object.isFrozen(collector.getById("draft-1:draft")), true);
    assert.equal(Object.isFrozen(collector.getAll()), true);
    assertDraftIsNotGrant(collector.getById("draft-1:draft"));
  });

  it("removes a draft", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    collector.addDraft(draft("draft-1"));

    const result = collector.removeDraft("draft-1:draft");

    assert.equal(result.status, "removed");
    assert.equal(result.removedDraft.capabilityGrantDraftId, "draft-1:draft");
    assert.equal(collector.count(), 0);
  });

  it("clears the collector", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    collector.addDraft(draft("draft-1"));
    collector.addDraft(draft("draft-2"));

    const result = collector.clear();

    assert.equal(result.status, "cleared");
    assert.equal(result.collection.count, 0);
    assert.equal(collector.count(), 0);
  });

  it("protects duplicate draft IDs", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    collector.addDraft(draft("draft-1"));

    const result = collector.addDraft(draft("draft-1"));

    assert.equal(result.status, "rejected_duplicate");
    assert.equal(collector.count(), 1);
  });

  it("rejects invalid or authority-shaped draft objects", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const result = collector.addDraft({
      ...draft("draft-1"),
      grantId: "active-grant-1"
    });

    assert.equal(result.status, "rejected_invalid");
    assert.equal(collector.count(), 0);
    assert.ok(result.errors.some((error) => error.includes("active authority fields")));
  });

  it("evicts oldest drafts at maximum size", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector({ maxDraftCount: 2 });
    collector.addDraft(draft("draft-1"));
    collector.addDraft(draft("draft-2"));

    const result = collector.addDraft(draft("draft-3"));

    assert.equal(result.status, "evicted_oldest");
    assert.equal(result.evictedDrafts[0].capabilityGrantDraftId, "draft-1:draft");
    assert.equal(collector.count(), 2);
    assert.equal(collector.getById("draft-1:draft"), undefined);
    assert.equal(collector.getById("draft-2:draft").capabilityGrantDraftId, "draft-2:draft");
    assert.equal(collector.getById("draft-3:draft").capabilityGrantDraftId, "draft-3:draft");
  });

  it("filters and queries drafts", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    collector.addDraft(draft("draft-1", { sessionId: "session-1" }));
    collector.addDraft(draft("draft-2", { sessionId: "session-2" }));
    collector.addDraft(draft("draft-3", {
      sessionId: "session-2",
      status: "pending_trust"
    }));

    assert.deepEqual(
      collector.filter({ sessionId: "session-2" }).map((item) => item.capabilityGrantDraftId),
      ["draft-2:draft", "draft-3:draft"]
    );
    assert.deepEqual(
      collector.query({ filter: { sessionId: "session-2" }, offset: 1, limit: 1 }).map(
        (item) => item.capabilityGrantDraftId
      ),
      ["draft-3:draft"]
    );
    assert.deepEqual(
      collector.filter({ status: "pending_trust" }).map((item) => item.capabilityGrantDraftId),
      ["draft-3:draft"]
    );
  });

  it("facade optionally collects successful capability drafts", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      capabilityGrantDraftCollector: collector,
      userSessionContext: sessionContext("session-1")
    });

    const result = api.requestCapability(capabilityRequest("capability-1"));

    assert.equal(result.status, "approved");
    assert.equal(result.value.capabilityGrantDraftCollectionResult.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(
      collector.getById(result.value.capabilityGrantDraft.capabilityGrantDraftId)
        .capabilityGrantDraftId,
      result.value.capabilityGrantDraft.capabilityGrantDraftId
    );
    assertDraftIsNotGrant(result.value.capabilityGrantDraft);
  });

  it("facade without a collector preserves previous draft behavior", function () {
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: sessionContext("session-1")
    });

    const result = api.requestCapability(capabilityRequest("capability-1"));

    assert.equal(result.status, "approved");
    assert.ok(result.value.capabilityGrantDraft);
    assert.equal(result.value.capabilityGrantDraftCollectionResult, undefined);
  });

  it("does not mutate active session capabilities", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext("session-1", ["existing-capability"]));
    const api = createValidationOnlyRuntimeApi({
      capabilityGrantDraftCollector: collector,
      userSessionStore: store
    });

    const result = api.requestCapability(capabilityRequest("capability-1"));

    assert.equal(result.status, "approved");
    assert.equal(collector.count(), 1);
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
  });

  it("does not collect malformed capability requests", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      capabilityGrantDraftCollector: collector
    });

    const result = api.requestCapability({
      requestId: "",
      applicationId: "",
      capability: "",
      sensitivity: "root"
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.capabilityGrantDraft, undefined);
    assert.equal(result.value.capabilityGrantDraftCollectionResult, undefined);
    assert.equal(collector.count(), 0);
  });

  it("does not call vault, storage, trust, policy, user approval, authorization, proof, or adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      capabilityGrantDraftCollector: collector,
      userSessionContext: sessionContext("session-1")
    });

    const result = api.requestCapability(capabilityRequest("capability-1", {
      scope: {
        metadata: {
          hooks
        }
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(collector.count(), 1);
  });
});
