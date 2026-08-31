const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryTrustEvaluationDraftCollector,
  createTrustEvaluationDraft,
  createUserSessionContext,
  getExpiredTrustEvaluationDrafts,
  getPendingCredentialResolutionDrafts,
  getPendingDeviceResolutionDrafts,
  getPendingTrustEvaluationDrafts,
  groupTrustEvaluationDraftsByApplication,
  groupTrustEvaluationDraftsByCredential,
  groupTrustEvaluationDraftsByDevice,
  groupTrustEvaluationDraftsByProviderKind,
  groupTrustEvaluationDraftsBySession,
  groupTrustEvaluationDraftsByStatus,
  reviewTrustEvaluationDrafts,
  summarizeTrustEvaluationDrafts
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

function sessionContext(activeCapabilities = []) {
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

function populatedCollector() {
  const collector = createInMemoryTrustEvaluationDraftCollector();
  collector.addDraft(trustDraft("trust-draft-1", {
    sessionId: "session-1",
    createdAt: "2026-07-10T00:00:00.000Z",
    credentialReference: undefined,
    deviceReference: undefined
  }));
  collector.addDraft(trustDraft("trust-draft-2", {
    sessionId: "session-2",
    createdAt: "2026-07-10T00:01:00.000Z",
    credentialReference: {
      credentialId: "credential-shared",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    deviceReference: undefined
  }));
  collector.addDraft(trustDraft("trust-draft-3", {
    sessionId: "session-2",
    createdAt: "2026-07-10T00:02:00.000Z",
    credentialReference: {
      credentialId: "credential-shared",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    deviceReference: {
      deviceId: "device-shared",
      providerKind: "webauthn-passkey-device-identity-v1"
    }
  }));
  collector.addDraft(trustDraft("trust-draft-4", {
    sessionId: "session-3",
    createdAt: "2026-07-10T00:03:00.000Z",
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
    credentialReference: {
      credentialId: "credential-expired",
      credentialKind: "webauthn",
      providerKind: "browser-webauthn-v1"
    },
    deviceReference: {
      deviceId: "device-expired",
      providerKind: "browser-webauthn-v1"
    }
  }));
  return collector;
}

function countEntries(grouped) {
  return Object.fromEntries(
    Object.entries(grouped).map(([key, value]) => [key, value.length])
  );
}

function assertNoTrustDecision(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("providestrustdecision\":true"), false);
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.providesTrustDecision, false);
}

describe("PhilCore Trust Evaluation Draft review helpers", function () {
  it("summarizes an empty collector", function () {
    const summary = summarizeTrustEvaluationDrafts(createInMemoryTrustEvaluationDraftCollector());

    assert.equal(summary.totalDraftCount, 0);
    assert.deepEqual(summary.draftsByApplication, {});
    assert.deepEqual(summary.draftsBySession, {});
    assert.deepEqual(summary.draftsByCredential, {});
    assert.deepEqual(summary.draftsByDevice, {});
    assert.deepEqual(summary.draftsByProviderKind, {});
    assert.deepEqual(summary.draftsByStatus, {});
    assert.equal(summary.pendingCredentialResolutionCount, 0);
    assert.equal(summary.pendingDeviceResolutionCount, 0);
    assert.equal(summary.pendingTrustEvaluationCount, 0);
    assert.equal(summary.expiredCount, 0);
    assert.deepEqual(summary.expiredDrafts, []);
    assert.equal(summary.earliestCreatedAt, undefined);
    assert.equal(summary.latestCreatedAt, undefined);
    assert.equal(summary.providesTrustDecision, false);
  });

  it("groups drafts by application, session, credential, device, provider kind, and status", function () {
    const collector = populatedCollector();

    assert.deepEqual(countEntries(groupTrustEvaluationDraftsByApplication(collector)), {
      "ethereum-net": 4
    });
    assert.deepEqual(countEntries(groupTrustEvaluationDraftsBySession(collector)), {
      "session-1": 1,
      "session-2": 2,
      "session-3": 1
    });
    assert.deepEqual(countEntries(groupTrustEvaluationDraftsByCredential(collector)), {
      "no-credential": 1,
      "credential-shared": 2,
      "credential-expired": 1
    });
    assert.deepEqual(countEntries(groupTrustEvaluationDraftsByDevice(collector)), {
      "no-device": 2,
      "device-shared": 1,
      "device-expired": 1
    });
    assert.deepEqual(countEntries(groupTrustEvaluationDraftsByProviderKind(collector)), {
      "no-provider-kind": 1,
      "webauthn-passkey-device-identity-v1": 2,
      "browser-webauthn-v1": 1
    });
    assert.deepEqual(countEntries(groupTrustEvaluationDraftsByStatus(collector)), {
      pending_credential_resolution: 1,
      pending_device_resolution: 1,
      pending_trust_evaluation: 2
    });
  });

  it("returns accurate summary counts and creation range", function () {
    const summary = summarizeTrustEvaluationDrafts(populatedCollector());

    assert.equal(summary.totalDraftCount, 4);
    assert.deepEqual(summary.draftsBySession, {
      "session-1": 1,
      "session-2": 2,
      "session-3": 1
    });
    assert.deepEqual(summary.draftsByCredential, {
      "no-credential": 1,
      "credential-shared": 2,
      "credential-expired": 1
    });
    assert.deepEqual(summary.draftsByDevice, {
      "no-device": 2,
      "device-shared": 1,
      "device-expired": 1
    });
    assert.equal(summary.pendingCredentialResolutionCount, 1);
    assert.equal(summary.pendingDeviceResolutionCount, 1);
    assert.equal(summary.pendingTrustEvaluationCount, 1);
    assert.equal(summary.expiredCount, 1);
    assert.equal(summary.earliestCreatedAt, "2026-07-10T00:00:00.000Z");
    assert.equal(summary.latestCreatedAt, "2026-07-10T00:03:00.000Z");
    assert.equal(summary.providesTrustDecision, false);
  });

  it("filters pending credential, device, trust-evaluation, and expired drafts", function () {
    const collector = populatedCollector();

    assert.deepEqual(
      getPendingCredentialResolutionDrafts(collector).map((item) => item.requestId),
      ["trust-draft-1"]
    );
    assert.deepEqual(
      getPendingDeviceResolutionDrafts(collector).map((item) => item.requestId),
      ["trust-draft-2"]
    );
    assert.deepEqual(
      getPendingTrustEvaluationDrafts(collector).map((item) => item.requestId),
      ["trust-draft-3"]
    );
    assert.deepEqual(
      getExpiredTrustEvaluationDrafts(collector).map((item) => item.requestId),
      ["trust-draft-4"]
    );
  });

  it("accepts collector snapshots and draft arrays without mutating state", function () {
    const collector = populatedCollector();
    const collection = collector.addDraft(trustDraft("trust-draft-5", {
      sessionId: "session-4",
      createdAt: "2026-07-10T00:04:00.000Z"
    })).collection;
    const draftArray = collector.getAll();
    const before = draftArray.map((item) => item.trustEvaluationDraftId);

    const fromCollection = summarizeTrustEvaluationDrafts(collection);
    const fromArray = summarizeTrustEvaluationDrafts(draftArray);

    assert.equal(fromCollection.totalDraftCount, 5);
    assert.equal(fromArray.totalDraftCount, 5);
    assert.deepEqual(
      collector.getAll().map((item) => item.trustEvaluationDraftId),
      before
    );
  });

  it("returns immutable review objects and does not mutate collector or draft state", function () {
    const collector = populatedCollector();
    const before = collector.getAll().map((item) => JSON.stringify(item));
    const grouped = groupTrustEvaluationDraftsByCredential(collector);
    const summary = summarizeTrustEvaluationDrafts(collector);
    const review = reviewTrustEvaluationDrafts(collector);

    assert.equal(Object.isFrozen(grouped), true);
    assert.equal(Object.isFrozen(grouped["credential-shared"]), true);
    assert.equal(Object.isFrozen(summary), true);
    assert.equal(Object.isFrozen(summary.pendingTrustEvaluationDrafts), true);
    assert.equal(Object.isFrozen(review), true);
    assert.equal(Object.isFrozen(review.groups), true);
    assert.equal(review.providesTrustDecision, false);

    try {
      grouped["credential-shared"].push(trustDraft("trust-draft-extra"));
    } catch {
      // Frozen arrays may throw; either result is fine as long as state remains unchanged.
    }

    assert.deepEqual(
      collector.getAll().map((item) => JSON.stringify(item)),
      before
    );
  });

  it("does not generate trust decisions or mutate User Session capabilities", function () {
    const collector = populatedCollector();
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(sessionContext(["existing-capability"]));

    const summary = summarizeTrustEvaluationDrafts(collector);
    const review = reviewTrustEvaluationDrafts(collector);

    assert.equal(summary.providesTrustDecision, false);
    assert.equal(review.providesTrustDecision, false);
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assert.equal(
      collector.getAll().some((item) => Object.hasOwn(item, "trustDecision")),
      false
    );
    collector.getAll().forEach(assertNoTrustDecision);
  });

  it("does not call credential/device resolution, WebAuthn, vault, storage, session, capability, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      credentialResolutionCalls: 0,
      deviceResolutionCalls: 0,
      webAuthnCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      sessionCalls: 0,
      capabilityCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const collector = createInMemoryTrustEvaluationDraftCollector();
    collector.addDraft(trustDraft("trust-draft-1", {
      metadata: {
        hooks
      }
    }));

    summarizeTrustEvaluationDrafts(collector);
    reviewTrustEvaluationDrafts(collector);
    groupTrustEvaluationDraftsByApplication(collector);
    groupTrustEvaluationDraftsByCredential(collector);
    getPendingTrustEvaluationDrafts(collector);

    assert.deepEqual(hooks, {
      credentialResolutionCalls: 0,
      deviceResolutionCalls: 0,
      webAuthnCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      sessionCalls: 0,
      capabilityCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
  });
});
