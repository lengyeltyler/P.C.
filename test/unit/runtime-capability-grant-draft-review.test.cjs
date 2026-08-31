const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryCapabilityGrantDraftCollector,
  createUserSessionContext,
  getExpiredCapabilityGrantDrafts,
  getPendingCapabilityGrantDrafts,
  groupCapabilityGrantDraftsByApplication,
  groupCapabilityGrantDraftsByCapability,
  groupCapabilityGrantDraftsBySession,
  groupCapabilityGrantDraftsByStatus,
  summarizeCapabilityGrantDrafts
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityRequest(id, overrides = {}) {
  return createCapabilityRequestDraft({
    requestId: id,
    applicationId: "ethereum-net",
    capability: "request_message_signature",
    sensitivity: "sensitive",
    requestedAt: "2026-07-10T00:00:00.000Z",
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

function sessionContext(activeCapabilities = []) {
  const result = createUserSessionContext({
    sessionId: "session-1",
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: activeCapabilities,
    pendingIntentIds: [],
    policyMode: "default"
  });
  assert.equal(result.status, "approved");
  return result.context;
}

function populatedCollector() {
  const collector = createInMemoryCapabilityGrantDraftCollector();
  collector.addDraft(draft("draft-1", {
    sessionId: "session-1",
    createdAt: "2026-07-10T00:00:00.000Z"
  }));
  collector.addDraft(draft("draft-2", {
    sessionId: "session-2",
    status: "pending_trust",
    createdAt: "2026-07-10T00:01:00.000Z",
    capabilityRequest: capabilityRequest("draft-2", {
      capability: "request_transaction_submission",
      sensitivity: "privileged"
    })
  }));
  collector.addDraft(draft("draft-3", {
    sessionId: "session-2",
    createdAt: "2026-07-10T00:02:00.000Z",
    capabilityRequest: capabilityRequest("draft-3", {
      scope: {
        expiresAt: new Date(Date.now() - 60_000).toISOString()
      }
    })
  }));
  return collector;
}

describe("PhilCore capability grant draft review helpers", function () {
  it("summarizes an empty collector", function () {
    const collector = createInMemoryCapabilityGrantDraftCollector();
    const summary = summarizeCapabilityGrantDrafts(collector);

    assert.equal(summary.totalDraftCount, 0);
    assert.deepEqual(summary.draftsByApplication, {});
    assert.deepEqual(summary.draftsBySession, {});
    assert.deepEqual(summary.draftsByCapability, {});
    assert.deepEqual(summary.draftsByStatus, {});
    assert.deepEqual(summary.expiredDrafts, []);
    assert.deepEqual(summary.pendingDrafts, []);
    assert.equal(summary.earliestCreatedAt, undefined);
    assert.equal(summary.latestCreatedAt, undefined);
    assert.equal(summary.providesAuthority, false);
  });

  it("groups drafts by application, session, capability, and status", function () {
    const collector = populatedCollector();

    assert.deepEqual(Object.keys(groupCapabilityGrantDraftsByApplication(collector)), ["ethereum-net"]);
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(groupCapabilityGrantDraftsBySession(collector)).map(([key, value]) => [
          key,
          value.length
        ])
      ),
      {
        "session-1": 1,
        "session-2": 2
      }
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(groupCapabilityGrantDraftsByCapability(collector)).map(([key, value]) => [
          key,
          value.length
        ])
      ),
      {
        request_message_signature: 2,
        request_transaction_submission: 1
      }
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(groupCapabilityGrantDraftsByStatus(collector)).map(([key, value]) => [
          key,
          value.length
        ])
      ),
      {
        pending_policy: 1,
        pending_trust: 1,
        expired: 1
      }
    );
  });

  it("returns accurate summary counts and creation range", function () {
    const summary = summarizeCapabilityGrantDrafts(populatedCollector());

    assert.equal(summary.totalDraftCount, 3);
    assert.deepEqual(summary.draftsByApplication, {
      "ethereum-net": 3
    });
    assert.deepEqual(summary.draftsBySession, {
      "session-1": 1,
      "session-2": 2
    });
    assert.deepEqual(summary.draftsByCapability, {
      request_message_signature: 2,
      request_transaction_submission: 1
    });
    assert.deepEqual(summary.draftsByStatus, {
      pending_policy: 1,
      pending_trust: 1,
      expired: 1
    });
    assert.equal(summary.earliestCreatedAt, "2026-07-10T00:00:00.000Z");
    assert.equal(summary.latestCreatedAt, "2026-07-10T00:02:00.000Z");
  });

  it("filters expired and pending drafts without decisions", function () {
    const collector = populatedCollector();
    const expired = getExpiredCapabilityGrantDrafts(collector);
    const pending = getPendingCapabilityGrantDrafts(collector);

    assert.deepEqual(expired.map((item) => item.capabilityRequestId), ["draft-3"]);
    assert.deepEqual(pending.map((item) => item.capabilityRequestId), ["draft-1", "draft-2"]);
    assert.equal(expired[0].providesAuthority, false);
    assert.equal(pending.every((item) => item.providesAuthority === false), true);
  });

  it("returns immutable review objects and does not mutate collector state", function () {
    const collector = populatedCollector();
    const before = collector.getAll().map((item) => item.capabilityGrantDraftId);
    const grouped = groupCapabilityGrantDraftsBySession(collector);
    const summary = summarizeCapabilityGrantDrafts(collector);

    assert.equal(Object.isFrozen(grouped), true);
    assert.equal(Object.isFrozen(grouped["session-2"]), true);
    assert.equal(Object.isFrozen(summary), true);
    assert.equal(Object.isFrozen(summary.pendingDrafts), true);

    try {
      grouped["session-2"].push(draft("draft-extra"));
    } catch {
      // Frozen arrays may throw; either result is fine as long as collector state is unchanged.
    }

    assert.deepEqual(
      collector.getAll().map((item) => item.capabilityGrantDraftId),
      before
    );
  });

  it("does not generate authority or mutate User Session capabilities", function () {
    const collector = populatedCollector();
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext(["existing-capability"]));

    const summary = summarizeCapabilityGrantDrafts(collector);

    assert.equal(summary.providesAuthority, false);
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assert.equal(
      collector.getAll().some((item) => Object.hasOwn(item, "grantId")),
      false
    );
  });

  it("does not call trust, policy, proof, adapter, vault, or storage hooks", function () {
    const hooks = {
      trustCalls: 0,
      policyCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      vaultCalls: 0,
      storageCalls: 0
    };
    const collector = createInMemoryCapabilityGrantDraftCollector();
    collector.addDraft(draft("draft-1", {
      metadata: {
        hooks
      }
    }));

    summarizeCapabilityGrantDrafts(collector);
    groupCapabilityGrantDraftsByApplication(collector);
    getPendingCapabilityGrantDrafts(collector);

    assert.deepEqual(hooks, {
      trustCalls: 0,
      policyCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      vaultCalls: 0,
      storageCalls: 0
    });
  });
});
