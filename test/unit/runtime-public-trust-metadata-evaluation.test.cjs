const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryAuditDraftCollector,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  evaluatePublicTrustMetadata
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

function evaluationRequest(overrides = {}) {
  return {
    requestId: "public-trust-evaluation-1",
    trustEvaluationDraft: trustDraft(),
    credential: publicCredential(),
    device: publicDevice(),
    ownerCommitment: "0x1234",
    requestedAt: "2026-07-10T00:01:00.000Z",
    ...overrides
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

function assertNoAuthenticationOrTrust(value) {
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

describe("PhilCore read-only public Trust metadata evaluation", function () {
  it("classifies valid public credential and device metadata as sufficient for further evaluation", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "metadata_sufficient");
    assert.equal(result.value.eligibleForFurtherEvaluation, true);
    assert.equal(result.value.requiresPossessionVerification, true);
    assert.equal(result.value.requiresAuthenticatorVerification, true);
    assert.equal(result.value.requiresCredentialResolution, false);
    assert.equal(result.value.requiresDeviceResolution, false);
    assert.ok(result.value.resolutionRequirements.includes("stronger_trust_evaluation"));
    assertNoAuthenticationOrTrust(result.value);
  });

  it("classifies missing credential metadata without resolving credentials", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: undefined
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "metadata_missing");
    assert.equal(result.value.requiresCredentialResolution, true);
    assert.equal(result.value.eligibleForFurtherEvaluation, false);
    assert.ok(result.value.reasons.includes("credential-metadata-missing"));
  });

  it("classifies missing device metadata without resolving devices", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      device: undefined
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "metadata_missing");
    assert.equal(result.value.requiresDeviceResolution, true);
    assert.equal(result.value.eligibleForFurtherEvaluation, false);
    assert.ok(result.value.reasons.includes("device-metadata-missing"));
  });

  it("classifies malformed public metadata without authenticating", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      device: publicDevice({
        publicMetadata: {
          ...publicDeviceMetadata(),
          privateMaterialExportable: true
        }
      })
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "metadata_malformed");
    assert.equal(result.value.eligibility, "malformed");
    assert.ok(result.value.reasons.includes("device-metadata-malformed"));
    assertNoAuthenticationOrTrust(result.value);
  });

  it("classifies unsupported provider kinds", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        providerKind: "unsupported-provider-kind"
      })
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "unsupported");
    assert.equal(result.value.outcome, "provider_unsupported");
    assert.equal(result.value.eligibility, "unsupported");
  });

  it("classifies active credential public status as ready for stronger evaluation", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        lifecycleStatus: "active"
      })
    }));

    assert.equal(result.value.outcome, "metadata_sufficient");
    assert.ok(result.value.reasons.includes("credential-status-active"));
  });

  it("classifies pending credential status as pending credential resolution", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        lifecycleStatus: "pending"
      })
    }));

    assert.equal(result.value.outcome, "pending_credential_resolution");
    assert.equal(result.value.requiresCredentialResolution, true);
    assert.ok(result.value.reasons.includes("credential-status-pending"));
  });

  it("classifies revoked credential status as ineligible", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        lifecycleStatus: "revoked"
      })
    }));

    assert.equal(result.value.outcome, "credential_status_ineligible");
    assert.equal(result.value.eligibility, "ineligible_for_ordinary_use");
    assert.ok(result.value.reasons.includes("credential-status-revoked"));
  });

  it("classifies archived credential status as ineligible", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        lifecycleStatus: "archived"
      })
    }));

    assert.equal(result.value.outcome, "credential_status_ineligible");
    assert.equal(result.value.eligibility, "ineligible_for_ordinary_use");
    assert.ok(result.value.reasons.includes("credential-status-archived"));
  });

  it("classifies recovery-only credentials separately from ordinary use", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        lifecycleStatus: "recovery-only"
      })
    }));

    assert.equal(result.value.outcome, "credential_status_ineligible");
    assert.equal(result.value.eligibility, "recovery_only");
    assert.ok(result.value.reasons.includes("credential-status-recovery-only"));
  });

  it("classifies owner commitment mismatch as malformed metadata", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        ownerCommitment: "0x9999"
      })
    }));

    assert.equal(result.value.outcome, "metadata_malformed");
    assert.equal(result.value.eligibility, "malformed");
    assert.ok(result.value.reasons.includes("owner-commitment-mismatch"));
  });

  it("classifies expired request or draft as malformed metadata", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }));

    assert.equal(result.value.outcome, "metadata_malformed");
    assert.ok(result.value.reasons.includes("request-expired"));
  });

  it("rejects secret-shaped metadata without echoing secret values", function () {
    const result = evaluatePublicTrustMetadata(evaluationRequest({
      credential: publicCredential({
        publicMetadata: {
          privateKey: "must-not-enter"
        }
      })
    }));

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.equal(JSON.stringify(result).includes("must-not-enter"), false);
    assert.ok(result.error.details.errors[0].includes("secret-shaped metadata"));
  });

  it("facade returns public metadata evaluation and audit draft without creating trust decisions", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      userSessionContext: userSession()
    });

    const result = api.requestPublicTrustMetadataEvaluation(evaluationRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.publicTrustMetadataEvaluation.outcome, "metadata_sufficient");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assertNoAuthenticationOrTrust(result.value.publicTrustMetadataEvaluation);
  });

  it("facade returns audit output only for invalid evaluation requests", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestPublicTrustMetadataEvaluation({
      ...evaluationRequest(),
      requestId: ""
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.publicTrustMetadataEvaluation, undefined);
    assert.equal(result.value.auditEventDraft.category, "trust");
  });

  it("does not access vault, storage, WebAuthn, signatures, session mutation, capability grants, policy, authorization, proof, or adapters", function () {
    const hooks = {
      deviceVaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(userSession(["existing-capability"]));
    const api = createValidationOnlyRuntimeApi({
      userSessionStore: store
    });

    const result = api.requestPublicTrustMetadataEvaluation(evaluationRequest({
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      deviceVaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assertNoAuthenticationOrTrust(result.value.publicTrustMetadataEvaluation);
  });
});
