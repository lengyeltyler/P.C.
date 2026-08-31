const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  isTrustEvaluationDraftStatus,
  validateTrustEvaluationDraftInput,
  validateTrustEvaluationDraftShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityDraft(overrides = {}) {
  const result = createCapabilityGrantDraft({
    capabilityRequest: createCapabilityRequestDraft({
      requestId: "capability-1",
      applicationId: "ethereum-net",
      capability: "request_message_signature",
      sensitivity: "sensitive",
      requestedAt: "2026-07-10T00:00:00.000Z"
    }),
    sessionId: "session-1",
    auditCorrelationId: "capability-draft-1",
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

function publicDeviceMetadata() {
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
    createdAt: "2026-07-10T00:00:00.000Z"
  };
}

function assertNoTrustDecision(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("providestrustdecision\":true"), false);
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.authenticated, false);
  assert.equal(value.persisted, false);
  assert.notEqual(value.status, "trusted");
  assert.notEqual(value.status, "approved");
  assert.notEqual(value.status, "authenticated");
  assert.notEqual(value.status, "verified");
}

describe("PhilCore validation-only Trust Evaluation Drafts", function () {
  it("creates a draft from valid public credential and device references", function () {
    const result = createTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft(),
      userSessionContext: userSession(),
      credentialReference: {
        credentialId: "credential-1",
        credentialKind: "webauthn",
        providerKind: "webauthn-passkey-device-identity-v1",
        credentialStatusReference: "active",
        publicMetadata: {
          label: "primary-passkey"
        }
      },
      deviceReference: {
        deviceId: "device-1",
        providerKind: "webauthn-passkey-device-identity-v1",
        deviceMetadataReference: publicDeviceMetadata(),
        productionSafe: true,
        hardwareBacked: true
      },
      requestedTrustLevel: "trusted-passkey",
      requirements: [{
        requirementId: "trust-requirement-1",
        requestedTrustLevel: "trusted-passkey",
        description: "Passkey reference must be resolved later."
      }],
      createdAt: "2026-07-10T00:01:00.000Z"
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "pending_trust_evaluation");
    assert.equal(result.value.outcome, "pending_trust_evaluation");
    assert.equal(result.value.capabilityGrantDraftId, "capability-draft-1:draft");
    assert.equal(result.value.applicationId, "ethereum-net");
    assert.equal(result.value.sessionId, "session-1");
    assert.equal(result.value.ownerCommitment, "0x1234");
    assert.equal(result.value.credentialId, "credential-1");
    assert.equal(result.value.deviceId, "device-1");
    assert.equal(result.value.providerKind, "webauthn-passkey-device-identity-v1");
    assert.equal(validateTrustEvaluationDraftShape(result.value).valid, true);
    assert.equal(Object.isFrozen(result.value), true);
    assertNoTrustDecision(result.value);
  });

  it("does not create a draft for malformed trust evaluation requests", function () {
    const result = createTrustEvaluationDraft({
      requestId: "",
      capabilityGrantDraft: capabilityDraft()
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.equal(result.error.category, "invalid_intent");
  });

  it("rejects invalid capability grant draft references", function () {
    const invalidCapabilityDraft = {
      ...capabilityDraft(),
      providesAuthority: true
    };
    const result = createTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: invalidCapabilityDraft
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.includes("capabilityGrantDraft.providesAuthority must be false"));
  });

  it("rejects secret-shaped or active-trust-shaped metadata", function () {
    const result = createTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft(),
      metadata: {
        phil_secret: "must-not-enter",
        trusted: true
      }
    });

    assert.equal(result.status, "denied");
    assert.equal(JSON.stringify(result).includes("must-not-enter"), false);
    assert.ok(result.error.details.errors[0].includes("private material or active trust fields"));
  });

  it("keeps draft status pending and never trusted or approved", function () {
    assert.equal(isTrustEvaluationDraftStatus("pending_trust_evaluation"), true);
    assert.equal(isTrustEvaluationDraftStatus("pending_credential_resolution"), true);
    assert.equal(isTrustEvaluationDraftStatus("trusted"), false);
    assert.equal(isTrustEvaluationDraftStatus("approved"), false);
    assert.equal(isTrustEvaluationDraftStatus("authenticated"), false);
    assert.equal(isTrustEvaluationDraftStatus("verified"), false);
  });

  it("uses pending credential and device resolution statuses without decisions", function () {
    const pendingCredential = createTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft()
    });
    const pendingDevice = createTrustEvaluationDraft({
      requestId: "trust-request-2",
      capabilityGrantDraft: capabilityDraft(),
      credentialReference: {
        credentialId: "credential-1"
      }
    });

    assert.equal(pendingCredential.value.status, "pending_credential_resolution");
    assert.equal(pendingDevice.value.status, "pending_device_resolution");
    assertNoTrustDecision(pendingCredential.value);
    assertNoTrustDecision(pendingDevice.value);
  });

  it("facade returns trust draft and audit correlation without loading credentials", function () {
    const api = createValidationOnlyRuntimeApi({
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
    assert.equal(result.value.trustEvaluationDraft.sessionId, "session-1");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(
      result.value.auditEventDraft.redactedDetails.trustEvaluationDraftId,
      result.value.trustEvaluationDraft.trustEvaluationDraftId
    );
    assertNoTrustDecision(result.value.trustEvaluationDraft);
  });

  it("facade returns audit output only for malformed trust draft requests", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestTrustEvaluationDraft({
      requestId: "",
      capabilityGrantDraft: capabilityDraft()
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.trustEvaluationDraft, undefined);
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
  });

  it("does not mutate User Session or convert capability drafts into grants", function () {
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(userSession(["existing-capability"]));
    const api = createValidationOnlyRuntimeApi({
      userSessionStore: store
    });
    const result = api.requestTrustEvaluationDraft({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft()
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assert.equal(Object.hasOwn(result.value.trustEvaluationDraft, "capabilityGrant"), false);
  });

  it("does not call WebAuthn, Device Vault, storage, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      webAuthnCalls: 0,
      deviceVaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const api = createValidationOnlyRuntimeApi({
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
      webAuthnCalls: 0,
      deviceVaultCalls: 0,
      storageCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assertNoTrustDecision(result.value.trustEvaluationDraft);
  });

  it("validates trust draft input shape without executing trust behavior", function () {
    const validation = validateTrustEvaluationDraftInput({
      requestId: "trust-request-1",
      capabilityGrantDraft: capabilityDraft(),
      status: "trusted"
    });

    assert.equal(validation.valid, false);
    assert.ok(validation.errors.includes("status is invalid"));
  });
});
