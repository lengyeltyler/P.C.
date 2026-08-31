const assert = require("node:assert/strict");

const {
  createAuditEventDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createIntentDraft,
  createValidationOnlyRuntimeApi
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function draft(id, overrides = {}) {
  return createAuditEventDraft({
    category: "runtime",
    outcome: "validation_succeeded",
    requestKind: "generic",
    applicationId: "ethereum-net",
    summary: `Draft ${id}`,
    auditCorrelationId: id,
    timestamp: "2026-07-09T00:00:00.000Z",
    ...overrides
  });
}

function validCapabilityRequest() {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_transaction_submission",
    sensitivity: "privileged",
    requestedAt: new Date().toISOString()
  });
}

function validIntentRequest(intentId = "intent-1") {
  return {
    requestId: `request-${intentId}`,
    sessionId: "session-1",
    applicationId: "ethereum-net",
    requestedAt: new Date().toISOString(),
    metadata: {
      hooks: {
        storageCalls: 0,
        vaultCalls: 0,
        proofCalls: 0,
        adapterCalls: 0
      }
    },
    intent: createIntentDraft({
      intentId,
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

function assertDraftOnly(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(text.includes("proofpackage"), false);
  assert.equal(text.includes("adapterexecutionresult"), false);
  assert.equal(text.includes("storagewrite"), false);
}

describe("PhilCore in-memory audit draft collector", function () {
  it("adds a draft and returns immutable collection views", function () {
    const collector = createInMemoryAuditDraftCollector();
    const result = collector.addDraft(draft("draft-1"));

    assert.equal(result.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById("draft-1:draft").eventDraftId, "draft-1:draft");
    assert.equal(Object.isFrozen(collector.getById("draft-1:draft")), true);
    assert.equal(Object.isFrozen(collector.getAll()), true);
  });

  it("removes drafts by ID", function () {
    const collector = createInMemoryAuditDraftCollector();
    collector.addDraft(draft("draft-1"));

    const removed = collector.removeDraft("draft-1:draft");

    assert.equal(removed.status, "removed");
    assert.equal(removed.removedDraft.eventDraftId, "draft-1:draft");
    assert.equal(collector.count(), 0);
  });

  it("clears all drafts", function () {
    const collector = createInMemoryAuditDraftCollector();
    collector.addDraft(draft("draft-1"));
    collector.addDraft(draft("draft-2"));

    const result = collector.clear();

    assert.equal(result.status, "cleared");
    assert.equal(result.collection.count, 0);
    assert.equal(collector.count(), 0);
  });

  it("rejects duplicate draft IDs", function () {
    const collector = createInMemoryAuditDraftCollector();
    collector.addDraft(draft("draft-1"));

    const duplicate = collector.addDraft(draft("draft-1"));

    assert.equal(duplicate.status, "rejected_duplicate");
    assert.equal(collector.count(), 1);
  });

  it("evicts oldest drafts when the maximum size is reached", function () {
    const collector = createInMemoryAuditDraftCollector({ maxDraftCount: 2 });
    collector.addDraft(draft("draft-1"));
    collector.addDraft(draft("draft-2"));

    const result = collector.addDraft(draft("draft-3"));

    assert.equal(result.status, "evicted_oldest");
    assert.equal(result.evictedDrafts[0].eventDraftId, "draft-1:draft");
    assert.equal(collector.count(), 2);
    assert.equal(collector.getById("draft-1:draft"), undefined);
    assert.equal(collector.getById("draft-2:draft").eventDraftId, "draft-2:draft");
    assert.equal(collector.getById("draft-3:draft").eventDraftId, "draft-3:draft");
  });

  it("filters and queries drafts without persistence", function () {
    const collector = createInMemoryAuditDraftCollector();
    collector.addDraft(draft("draft-1", { category: "capability" }));
    collector.addDraft(draft("draft-2", { category: "intent" }));
    collector.addDraft(draft("draft-3", { category: "intent" }));

    assert.equal(collector.filter({ category: "intent" }).length, 2);
    assert.deepEqual(
      collector.query({ filter: { category: "intent" }, offset: 1, limit: 1 }).map(
        (item) => item.eventDraftId
      ),
      ["draft-3:draft"]
    );
  });

  it("optionally collects facade validation drafts", function () {
    const collector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({ auditDraftCollector: collector });
    const result = api.requestCapability(validCapabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(
      collector.getById(result.value.auditEventDraft.eventDraftId).eventDraftId,
      result.value.auditEventDraft.eventDraftId
    );
  });

  it("collects validation drafts only and does not create execution artifacts", function () {
    const collector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({ auditDraftCollector: collector });
    const result = api.requestIntent(validIntentRequest());

    assert.equal(result.value.auditEventDraft.outcome, "validation_succeeded");
    assert.equal(result.value.auditEventDraft.persisted, false);
    assert.equal(result.value.auditEventDraft.encryptedByDefault, true);
    assertDraftOnly(result);
    assertDraftOnly(collector.getAll());
  });

  it("does not persist drafts across collector recreation", function () {
    const collector = createInMemoryAuditDraftCollector();
    collector.addDraft(draft("draft-1"));

    const recreated = createInMemoryAuditDraftCollector();

    assert.equal(collector.count(), 1);
    assert.equal(recreated.count(), 0);
  });

  it("does not call storage, vault, proof, or adapter hooks through facade collection", function () {
    const collector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({ auditDraftCollector: collector });
    const request = validIntentRequest();
    const hooks = request.metadata.hooks;

    const result = api.requestTransactionSubmission(request);

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      storageCalls: 0,
      vaultCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(collector.count(), 1);
  });
});
