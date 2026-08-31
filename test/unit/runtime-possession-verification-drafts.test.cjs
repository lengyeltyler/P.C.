const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryAuditDraftCollector,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  evaluatePublicTrustMetadata,
  isPossessionVerificationMethod,
  isPossessionVerificationRequestDraftStatus,
  validatePossessionVerificationRequestDraftInput,
  validatePossessionVerificationRequestDraftShape
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

function publicMetadataEvaluation(overrides = {}) {
  const result = evaluatePublicTrustMetadata({
    requestId: "public-trust-evaluation-1",
    trustEvaluationDraft: trustDraft(),
    credential: publicCredential(),
    device: publicDevice(),
    ownerCommitment: "0x1234",
    auditCorrelationId: "public-trust-evaluation-1",
    requestedAt: "2026-07-10T00:01:00.000Z",
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

function assertNoVerification(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("verified\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.verifiesPossession, false);
  assert.equal(value.authenticatesUser, false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.grantsAuthority, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore possession verification request drafts", function () {
  it("creates a draft for metadata evaluations requiring possession verification", function () {
    const evaluation = publicMetadataEvaluation();
    const result = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: evaluation,
      userSessionContext: userSession(),
      createdAt: "2026-07-10T00:02:00.000Z"
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.publicTrustMetadataEvaluationId, evaluation.evaluationId);
    assert.equal(result.value.trustEvaluationDraftId, evaluation.trustEvaluationDraftId);
    assert.equal(result.value.capabilityGrantDraftId, evaluation.capabilityGrantDraftId);
    assert.equal(result.value.applicationId, "ethereum-net");
    assert.equal(result.value.sessionId, "session-1");
    assert.equal(result.value.credentialId, "credential-1");
    assert.equal(result.value.deviceId, "device-1");
    assert.equal(result.value.verificationMethod, "webauthn_assertion");
    assert.equal(result.value.status, "pending_challenge_construction");
    assert.equal(validatePossessionVerificationRequestDraftShape(result.value).valid, true);
    assertNoVerification(result.value);
  });

  it("treats metadata_sufficient as still pending possession verification only", function () {
    const evaluation = publicMetadataEvaluation();
    const result = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: evaluation
    });

    assert.equal(evaluation.outcome, "metadata_sufficient");
    assert.equal(evaluation.requiresPossessionVerification, true);
    assert.equal(result.status, "approved");
    assert.ok(result.value.reasons.includes("future-possession-verification-required"));
    assertNoVerification(result.value);
  });

  it("does not create a draft for malformed metadata evaluations", function () {
    const evaluation = publicMetadataEvaluation({
      device: publicDevice({
        publicMetadata: {
          ...publicDeviceMetadata(),
          privateMaterialExportable: true
        }
      })
    });
    const result = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: evaluation
    });

    assert.equal(evaluation.outcome, "metadata_malformed");
    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.includes("publicTrustMetadataEvaluation is not eligible for further evaluation"));
  });

  it("does not create a draft for unsupported providers or methods", function () {
    const unsupportedProvider = publicMetadataEvaluation({
      credential: publicCredential({
        providerKind: "unsupported-provider-kind"
      })
    });
    const unsupportedProviderResult = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: unsupportedProvider
    });
    const unsupportedMethodResult = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-2",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      verificationMethod: "unsupported"
    });

    assert.equal(unsupportedProvider.outcome, "provider_unsupported");
    assert.equal(unsupportedProviderResult.status, "denied");
    assert.equal(unsupportedMethodResult.status, "denied");
  });

  it("does not create a draft for ineligible credential lifecycle status", function () {
    const evaluation = publicMetadataEvaluation({
      credential: publicCredential({
        lifecycleStatus: "revoked"
      })
    });
    const result = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: evaluation
    });

    assert.equal(evaluation.outcome, "credential_status_ineligible");
    assert.equal(result.status, "denied");
  });

  it("does not create a draft for expired evaluations or missing correlation", function () {
    const expired = publicMetadataEvaluation({
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    });
    const missingCredential = {
      ...publicMetadataEvaluation(),
      credentialId: undefined
    };

    const expiredResult = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: expired
    });
    const missingCorrelationResult = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-2",
      publicTrustMetadataEvaluation: missingCredential
    });

    assert.equal(expiredResult.status, "denied");
    assert.equal(missingCorrelationResult.status, "denied");
    assert.ok(missingCorrelationResult.error.details.errors.includes("publicTrustMetadataEvaluation.credentialId is required"));
  });

  it("creates a safe non-executing challenge descriptor", function () {
    const result = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      expiresAt: "2026-07-10T00:10:00.000Z"
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.challengeDescriptor.generatedChallenge, false);
    assert.equal(
      result.value.challengeDescriptor.challengePurpose,
      "credential_possession_verification"
    );
    assert.equal(result.value.challengeDescriptor.expectedApplicationId, "ethereum-net");
    assert.equal(result.value.challengeDescriptor.expectedSessionId, "session-1");
    assert.equal(result.value.challengeDescriptor.expectedCredentialId, "credential-1");
    assert.equal(result.value.challengeDescriptor.expectedDeviceId, "device-1");
    assert.equal(Object.hasOwn(result.value.challengeDescriptor, "rawChallenge"), false);
    assert.equal(Object.hasOwn(result.value.challengeDescriptor, "assertionResponse"), false);
  });

  it("rejects secret-shaped or raw assertion fields", function () {
    const secretMetadata = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      metadata: {
        privateKey: "must-not-enter"
      }
    });
    const rawChallenge = createPossessionVerificationRequestDraft({
      requestId: "possession-draft-2",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      challengeDescriptor: {
        challengePurpose: "credential_possession_verification",
        challengeReference: "placeholder",
        expectedApplicationId: "ethereum-net",
        verificationMethod: "webauthn_assertion",
        generatedChallenge: false,
        rawChallenge: "must-not-enter"
      }
    });

    assert.equal(secretMetadata.status, "denied");
    assert.equal(rawChallenge.status, "denied");
    assert.equal(JSON.stringify(secretMetadata).includes("must-not-enter"), false);
    assert.equal(JSON.stringify(rawChallenge).includes("must-not-enter"), false);
  });

  it("keeps status pending and never verified, authenticated, trusted, or approved", function () {
    assert.equal(isPossessionVerificationRequestDraftStatus("pending_challenge_construction"), true);
    assert.equal(isPossessionVerificationRequestDraftStatus("pending_possession_verification"), true);
    assert.equal(isPossessionVerificationRequestDraftStatus("verified"), false);
    assert.equal(isPossessionVerificationRequestDraftStatus("authenticated"), false);
    assert.equal(isPossessionVerificationRequestDraftStatus("trusted"), false);
    assert.equal(isPossessionVerificationRequestDraftStatus("approved"), false);
    assert.equal(isPossessionVerificationMethod("webauthn_assertion"), true);
    assert.equal(isPossessionVerificationMethod("device_signature"), true);
    assert.equal(isPossessionVerificationMethod("hardware_key_assertion"), true);
  });

  it("facade returns draft and audit correlation without executing verification", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      userSessionContext: userSession()
    });

    const result = api.requestPossessionVerificationDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: publicMetadataEvaluation()
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.possessionVerificationRequestDraft.sessionId, "session-1");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assertNoVerification(result.value.possessionVerificationRequestDraft);
  });

  it("facade returns audit output only for invalid draft requests", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestPossessionVerificationDraft({
      requestId: "",
      publicTrustMetadataEvaluation: publicMetadataEvaluation()
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.possessionVerificationRequestDraft, undefined);
    assert.equal(result.value.auditEventDraft.category, "trust");
  });

  it("validates input shape without executing WebAuthn or signatures", function () {
    const validation = validatePossessionVerificationRequestDraftInput({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      status: "verified"
    });

    assert.equal(validation.valid, false);
    assert.ok(validation.errors.includes("status is invalid"));
  });

  it("does not call WebAuthn, signature verification, credential loading, vault, storage, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      credentialLoadCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
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

    const result = api.requestPossessionVerificationDraft({
      requestId: "possession-draft-1",
      publicTrustMetadataEvaluation: publicMetadataEvaluation(),
      metadata: {
        hooks
      }
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      webAuthnCalls: 0,
      signatureVerificationCalls: 0,
      credentialLoadCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assertNoVerification(result.value.possessionVerificationRequestDraft);
  });
});
