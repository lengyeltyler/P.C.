const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryPublicTrustMetadataEvaluationCollector,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  evaluatePublicTrustMetadata,
  getExpiredPublicTrustMetadataEvaluations,
  getMalformedMetadataEvaluations,
  getMetadataSufficientEvaluations,
  getMissingMetadataEvaluations,
  getPendingAuthenticatorVerificationEvaluations,
  getPendingPossessionVerificationEvaluations,
  getUnsupportedProviderEvaluations,
  groupPublicTrustMetadataEvaluationsByApplication,
  groupPublicTrustMetadataEvaluationsByCredential,
  groupPublicTrustMetadataEvaluationsByDevice,
  groupPublicTrustMetadataEvaluationsByOutcome,
  groupPublicTrustMetadataEvaluationsByProviderKind,
  groupPublicTrustMetadataEvaluationsBySession,
  summarizePublicTrustMetadataEvaluations
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityDraft(id = "capability-1") {
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
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function trustDraft(id = "trust-draft-1", overrides = {}) {
  const result = createTrustEvaluationDraft({
    requestId: id,
    capabilityGrantDraft: capabilityDraft(`${id}:capability`),
    credentialReference: {
      credentialId: "credential-1",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1",
      credentialStatusReference: "active"
    },
    deviceReference: {
      deviceId: "device-1",
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    ownerCommitment: "0x1234",
    auditCorrelationId: id,
    createdAt: "2026-07-10T00:00:00.000Z",
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function publicDeviceMetadata(overrides = {}) {
  return {
    version: "phil-device-identity-v1",
    providerKind: "webauthn-passkey-device-identity-v1",
    deviceIdentityId: "0xdevice",
    deviceKeyId: "0xdevicekey",
    credentialId: "credential-1",
    credentialPublicKey: "0xcredentialpublic",
    philIdentity: {
      version: "phil-identity-v1",
      ownerCommitment: "0x1234"
    },
    productionSafe: true,
    privateMaterialExportable: false,
    hardwareBacked: true,
    createdAt: "2026-07-10T00:00:00.000Z",
    ...overrides
  };
}

function publicCredential(overrides = {}) {
  return {
    credentialId: "credential-1",
    credentialKind: "webauthn",
    providerKind: "webauthn-passkey-device-identity-v1",
    lifecycleStatus: "active",
    ownerCommitment: "0x1234",
    publicMetadata: {
      label: "primary-passkey"
    },
    ...overrides
  };
}

function publicDevice(overrides = {}) {
  return {
    deviceId: "device-1",
    providerKind: "webauthn-passkey-device-identity-v1",
    lifecycleStatus: "active",
    ownerCommitment: "0x1234",
    publicMetadata: publicDeviceMetadata(),
    ...overrides
  };
}

function evaluationRequest(id = "public-trust-evaluation-1", overrides = {}) {
  return {
    requestId: id,
    trustEvaluationDraft: trustDraft(`${id}:draft`),
    credential: publicCredential(),
    device: publicDevice(),
    ownerCommitment: "0x1234",
    auditCorrelationId: id,
    requestedAt: "2026-07-10T00:01:00.000Z",
    ...overrides
  };
}

function evaluation(id, overrides = {}) {
  const result = evaluatePublicTrustMetadata(evaluationRequest(id, overrides.request ?? {}));
  assert.equal(result.status, "approved");
  return {
    ...result.value,
    evaluatedAt: overrides.evaluatedAt ?? "2026-07-10T00:00:00.000Z",
    ...overrides.result
  };
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

function countEntries(grouped) {
  return Object.fromEntries(
    Object.entries(grouped).map(([key, value]) => [key, value.length])
  );
}

function assertNoTrustAuthority(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("verified\":true"), false);
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorized\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.grantsAuthority, false);
  assert.equal(value.persisted, false);
}

function populatedCollector() {
  const collector = createInMemoryPublicTrustMetadataEvaluationCollector();
  collector.addResult(evaluation("eval-1", {
    evaluatedAt: "2026-07-10T00:00:00.000Z"
  }));
  collector.addResult(evaluation("eval-2", {
    evaluatedAt: "2026-07-10T00:01:00.000Z",
    request: {
      credential: undefined
    }
  }));
  collector.addResult(evaluation("eval-3", {
    evaluatedAt: "2026-07-10T00:02:00.000Z",
    request: {
      credential: publicCredential({
        providerKind: "unsupported-provider-kind"
      })
    }
  }));
  collector.addResult(evaluation("eval-4", {
    evaluatedAt: "2026-07-10T00:03:00.000Z",
    request: {
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }
  }));
  return collector;
}

describe("PhilCore public Trust metadata evaluation collection and review", function () {
  it("collector starts empty", function () {
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector();

    assert.equal(collector.count(), 0);
    assert.deepEqual(collector.getAll(), []);
    assert.equal(collector.getById("missing"), undefined);
  });

  it("adds, gets, removes, clears, and counts results", function () {
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector();
    const item = evaluation("eval-1");

    const addResult = collector.addResult(item);
    assert.equal(addResult.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById("eval-1:evaluation").evaluationId, "eval-1:evaluation");
    assert.equal(Object.isFrozen(collector.getById("eval-1:evaluation")), true);
    assert.equal(Object.isFrozen(collector.getAll()), true);

    const removeResult = collector.removeResult("eval-1:evaluation");
    assert.equal(removeResult.status, "removed");
    assert.equal(collector.count(), 0);

    collector.addResult(evaluation("eval-2"));
    assert.equal(collector.clear().status, "cleared");
    assert.equal(collector.count(), 0);
  });

  it("protects duplicates and rejects malformed, secret-shaped, and authority-shaped results", function () {
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector();
    collector.addResult(evaluation("eval-1"));

    const duplicate = collector.addResult(evaluation("eval-1"));
    const malformed = collector.addResult({
      ...evaluation("eval-2"),
      evaluationId: ""
    });
    const secretShaped = collector.addResult({
      ...evaluation("eval-3"),
      privateKey: "must-not-enter"
    });
    const authorityShaped = collector.addResult({
      ...evaluation("eval-4"),
      trustDecision: {
        decision: "trusted"
      }
    });

    assert.equal(duplicate.status, "rejected_duplicate");
    assert.equal(malformed.status, "rejected_invalid");
    assert.equal(secretShaped.status, "rejected_invalid");
    assert.equal(authorityShaped.status, "rejected_invalid");
    assert.equal(JSON.stringify(secretShaped).includes("must-not-enter"), false);
    assert.ok(authorityShaped.errors.some((error) => error.includes("trust authority fields")));
    assert.equal(collector.count(), 1);
  });

  it("evicts oldest results at maximum size", function () {
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector({ maxResultCount: 2 });
    collector.addResult(evaluation("eval-1"));
    collector.addResult(evaluation("eval-2"));

    const result = collector.addResult(evaluation("eval-3"));

    assert.equal(result.status, "evicted_oldest");
    assert.equal(result.evictedResults[0].evaluationId, "eval-1:evaluation");
    assert.equal(collector.count(), 2);
    assert.equal(collector.getById("eval-1:evaluation"), undefined);
    assert.equal(collector.getById("eval-2:evaluation").evaluationId, "eval-2:evaluation");
    assert.equal(collector.getById("eval-3:evaluation").evaluationId, "eval-3:evaluation");
  });

  it("filters and queries results", function () {
    const collector = populatedCollector();

    assert.deepEqual(
      collector.filter({ outcome: "metadata_sufficient" }).map((item) => item.evaluationId),
      ["eval-1:evaluation"]
    );
    assert.deepEqual(
      collector.query({ filter: { applicationId: "ethereum-net" }, offset: 1, limit: 2 }).map(
        (item) => item.evaluationId
      ),
      ["eval-2:evaluation", "eval-3:evaluation"]
    );
    assert.deepEqual(
      collector.filter({ requiresCredentialResolution: true }).map((item) => item.evaluationId),
      ["eval-2:evaluation"]
    );
  });

  it("facade optionally collects successful public metadata evaluations", function () {
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector();
    const api = createValidationOnlyRuntimeApi({
      publicTrustMetadataEvaluationCollector: collector,
      userSessionContext: userSession()
    });

    const result = api.requestPublicTrustMetadataEvaluation(evaluationRequest("eval-1"));

    assert.equal(result.status, "approved");
    assert.equal(result.value.publicTrustMetadataEvaluationCollectionResult.status, "collected");
    assert.equal(collector.count(), 1);
    assert.equal(
      collector.getById(result.value.publicTrustMetadataEvaluation.evaluationId).evaluationId,
      result.value.publicTrustMetadataEvaluation.evaluationId
    );
    assertNoTrustAuthority(result.value.publicTrustMetadataEvaluation);
  });

  it("facade without a collector preserves prior behavior", function () {
    const api = createValidationOnlyRuntimeApi({
      userSessionContext: userSession()
    });

    const result = api.requestPublicTrustMetadataEvaluation(evaluationRequest("eval-1"));

    assert.equal(result.status, "approved");
    assert.ok(result.value.publicTrustMetadataEvaluation);
    assert.equal(result.value.publicTrustMetadataEvaluationCollectionResult, undefined);
  });

  it("summarizes and groups results without inferring trust", function () {
    const collector = populatedCollector();
    const summary = summarizePublicTrustMetadataEvaluations(collector);

    assert.equal(summary.totalResultCount, 4);
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsByApplication(collector)), {
      "ethereum-net": 4
    });
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsBySession(collector)), {
      "session-1": 4
    });
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsByCredential(collector)), {
      "credential-1": 4
    });
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsByDevice(collector)), {
      "device-1": 4
    });
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsByProviderKind(collector)), {
      "webauthn-passkey-device-identity-v1": 3,
      "unsupported-provider-kind": 1
    });
    assert.deepEqual(countEntries(groupPublicTrustMetadataEvaluationsByOutcome(collector)), {
      metadata_sufficient: 1,
      metadata_missing: 1,
      provider_unsupported: 1,
      metadata_malformed: 1
    });
    assert.equal(summary.metadataSufficientCount, 1);
    assert.equal(summary.missingMetadataCount, 1);
    assert.equal(summary.malformedMetadataCount, 1);
    assert.equal(summary.unsupportedProviderCount, 1);
    assert.equal(summary.pendingPossessionVerificationCount, 1);
    assert.equal(summary.pendingAuthenticatorVerificationCount, 1);
    assert.equal(summary.pendingStrongerEvaluationCount, 1);
    assert.equal(summary.expiredCount, 1);
    assert.equal(summary.earliestEvaluatedAt, "2026-07-10T00:00:00.000Z");
    assert.equal(summary.latestEvaluatedAt, "2026-07-10T00:03:00.000Z");
    assert.equal(summary.providesTrustDecision, false);
    assert.equal(summary.grantsAuthority, false);
  });

  it("filters results by outcome and pending stronger-evaluation state", function () {
    const collector = populatedCollector();

    assert.deepEqual(
      getMetadataSufficientEvaluations(collector).map((item) => item.evaluationId),
      ["eval-1:evaluation"]
    );
    assert.deepEqual(
      getMissingMetadataEvaluations(collector).map((item) => item.evaluationId),
      ["eval-2:evaluation"]
    );
    assert.deepEqual(
      getUnsupportedProviderEvaluations(collector).map((item) => item.evaluationId),
      ["eval-3:evaluation"]
    );
    assert.deepEqual(
      getMalformedMetadataEvaluations(collector).map((item) => item.evaluationId),
      ["eval-4:evaluation"]
    );
    assert.deepEqual(
      getPendingPossessionVerificationEvaluations(collector).map((item) => item.evaluationId),
      ["eval-1:evaluation"]
    );
    assert.deepEqual(
      getPendingAuthenticatorVerificationEvaluations(collector).map((item) => item.evaluationId),
      ["eval-1:evaluation"]
    );
    assert.deepEqual(
      getExpiredPublicTrustMetadataEvaluations(collector).map((item) => item.evaluationId),
      ["eval-4:evaluation"]
    );
  });

  it("returns immutable review objects and does not mutate collector state", function () {
    const collector = populatedCollector();
    const before = collector.getAll().map((item) => item.evaluationId);
    const grouped = groupPublicTrustMetadataEvaluationsByOutcome(collector);
    const summary = summarizePublicTrustMetadataEvaluations(collector);

    assert.equal(Object.isFrozen(grouped), true);
    assert.equal(Object.isFrozen(grouped.metadata_sufficient), true);
    assert.equal(Object.isFrozen(summary), true);

    try {
      grouped.metadata_sufficient.push(evaluation("eval-extra"));
    } catch {
      // Frozen arrays may throw; either result is fine as long as state is unchanged.
    }

    assert.deepEqual(collector.getAll().map((item) => item.evaluationId), before);
  });

  it("does not mutate User Session, create authority, or call stronger trust hooks", function () {
    const hooks = {
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const collector = createInMemoryPublicTrustMetadataEvaluationCollector();
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(userSession(["existing-capability"]));
    const api = createValidationOnlyRuntimeApi({
      publicTrustMetadataEvaluationCollector: collector,
      userSessionStore: store
    });

    const result = api.requestPublicTrustMetadataEvaluation(evaluationRequest("eval-1", {
      metadata: {
        hooks
      }
    }));
    summarizePublicTrustMetadataEvaluations(collector);
    getMetadataSufficientEvaluations(collector);

    assert.equal(result.status, "approved");
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assert.deepEqual(hooks, {
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assertNoTrustAuthority(result.value.publicTrustMetadataEvaluation);
  });
});
