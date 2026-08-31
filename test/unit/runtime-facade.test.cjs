const assert = require("node:assert/strict");

const {
  createCapabilityRequestDraft,
  createIntentDraft,
  createValidationOnlyRuntimeApi,
  validateRuntimeApiFacadeEnvelope
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function validCapabilityRequest() {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_transaction_submission",
    sensitivity: "privileged",
    requestedAt: new Date().toISOString()
  });
}

function validIntent() {
  return createIntentDraft({
    intentId: "intent-1",
    kind: "submit-transaction",
    applicationId: "ethereum-net",
    requestedCapabilities: ["request_transaction_submission"],
    payload: {
      chainId: 8453n,
      target: "0x0000000000000000000000000000000000000001"
    },
    expiresAt: new Date(Date.now() + 60_000).toISOString()
  });
}

function validIntentRequest() {
  return {
    requestId: "request-1",
    sessionId: "session-1",
    applicationId: "ethereum-net",
    requestedAt: new Date().toISOString(),
    intent: validIntent()
  };
}

function assertNoBehaviorOutputs(result) {
  assert.equal(Object.hasOwn(result, "authorizationPackage"), false);
  assert.equal(Object.hasOwn(result, "proofPackage"), false);
  assert.equal(Object.hasOwn(result, "adapterExecutionResult"), false);
  assert.equal(Object.hasOwn(result, "storageWrite"), false);
  assert.equal(
    Boolean(result.value && Object.hasOwn(result.value, "authorizationPackage")),
    false
  );
  assert.equal(
    Boolean(result.value?.intake && Object.hasOwn(result.value.intake, "authorizationPackage")),
    false
  );
}

describe("PhilCore validation-only Runtime API facade", function () {
  it("validates a facade envelope directly", function () {
    const result = validateRuntimeApiFacadeEnvelope({
      kind: "capability",
      context: {
        requestId: "request-1",
        applicationId: "ethereum-net"
      },
      capabilityRequest: validCapabilityRequest()
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.intake.value.valid, true);
    assert.equal(result.value.auditEventDraft.outcome, "validation_succeeded");
  });

  it("returns validation success for a valid capability request", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability(validCapabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.intake.value.valid, true);
    assert.equal(result.value.auditEventDraft.category, "capability");
    assertNoBehaviorOutputs(result);
  });

  it("returns malformed result for an invalid capability request", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability({
      requestId: "capability-bad",
      applicationId: "",
      capability: "",
      sensitivity: "root"
    });

    assert.equal(result.status, "denied");
    assert.equal(result.error.category, "invalid_intent");
    assert.ok(result.error.details.issueCodes.includes("invalid_context"));
    assert.ok(result.error.details.issueCodes.includes("invalid_capability_shape"));
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
    assertNoBehaviorOutputs(result);
  });

  it("returns validation success for a valid intent request", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestIntent(validIntentRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.intake.value.valid, true);
    assert.equal(result.value.auditEventDraft.category, "intent");
    assertNoBehaviorOutputs(result);
  });

  it("returns malformed result for an invalid intent request", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestTransactionSubmission({
      requestId: "request-1",
      sessionId: "session-1",
      applicationId: "ethereum-net",
      intent: {
        intentId: "",
        kind: "submit-transaction",
        applicationId: "ethereum-net",
        requestedCapabilities: [],
        payload: {}
      }
    });

    assert.equal(result.status, "denied");
    assert.equal(result.error.category, "invalid_intent");
    assert.ok(result.error.details.issueCodes.includes("invalid_intent_shape"));
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
    assertNoBehaviorOutputs(result);
  });

  it("validates all behavior-neutral intent request methods through intake", function () {
    const api = createValidationOnlyRuntimeApi();
    const request = validIntentRequest();
    const methods = [
      "requestAuthorization",
      "requestMessageSignature",
      "requestTransactionPreparation",
      "requestTransactionSubmission",
      "requestContractCall",
      "requestSmartAccountDeployment",
      "requestSessionKeyManagement",
      "requestCredentialRotation",
      "requestCredentialRevocation",
      "requestEncryptedBackupExport",
      "requestRecoveryStart",
      "requestRecoveryApproval",
      "requestAuditReview"
    ];

    for (const method of methods) {
      const result = api[method](request);
      assert.equal(result.status, "approved", method);
      assert.equal(result.value.intake.value.valid, true, method);
      assertNoBehaviorOutputs(result);
    }
  });

  it("returns explicit unsupported result for future scoped agent permission", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestScopedAgentPermission({
      ...validIntentRequest(),
      futureOnly: true
    });

    assert.equal(result.status, "failed");
    assert.equal(result.error.category, "unsupported_operation");
    assert.equal(result.error.code, "RUNTIME_FACADE_UNSUPPORTED_FUTURE_AGENT_PERMISSION");
    assert.equal(result.value.auditEventDraft.category, "future_ai");
    assert.equal(result.value.auditEventDraft.outcome, "unsupported");
    assertNoBehaviorOutputs(result);
  });

  it("does not call adapter, proof, storage, or authorization hooks", function () {
    const api = createValidationOnlyRuntimeApi();
    const hooks = {
      adapterCalls: 0,
      proofCalls: 0,
      storageCalls: 0,
      authorizationCalls: 0
    };
    const result = api.requestAuthorization({
      ...validIntentRequest(),
      metadata: {
        hooks
      }
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      adapterCalls: 0,
      proofCalls: 0,
      storageCalls: 0,
      authorizationCalls: 0
    });
    assertNoBehaviorOutputs(result);
  });
});
