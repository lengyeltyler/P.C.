const assert = require("node:assert/strict");

const {
  createAuditEventDraft,
  createCapabilityRequestDraft,
  createIntentDraft,
  createValidationOnlyRuntimeApi
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
      target: "0x0000000000000000000000000000000000000001",
      phil_secret: "must-not-appear-in-audit-draft"
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

function stringify(value) {
  return JSON.stringify(value);
}

function assertDraftIsNotAuthorizationOrExecution(draft) {
  const text = stringify(draft).toLowerCase();
  assert.equal(text.includes("authorized"), false);
  assert.equal(text.includes("executed"), false);
  assert.equal(text.includes("signed"), false);
  assert.equal(text.includes("proven"), false);
  assert.equal(draft.persisted, false);
  assert.equal(draft.encryptedByDefault, true);
}

describe("PhilCore runtime audit event drafts", function () {
  it("creates explicit audit event drafts without persistence", function () {
    const draft = createAuditEventDraft({
      category: "runtime",
      outcome: "validation_succeeded",
      requestKind: "generic",
      applicationId: "ethereum-net",
      summary: "Runtime shape validation completed.",
      timestamp: "2026-07-09T00:00:00.000Z"
    });

    assert.equal(draft.eventDraftId, "ethereum-net:generic:shape-validation:validation_succeeded:draft");
    assert.equal(draft.persisted, false);
    assert.equal(draft.encryptedByDefault, true);
  });

  it("valid capability request produces validation success and audit draft", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability(validCapabilityRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.intake.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "capability");
    assert.equal(result.value.auditEventDraft.outcome, "validation_succeeded");
    assert.equal(result.value.auditEventDraft.capability, "request_transaction_submission");
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });

  it("invalid capability request produces validation failure and audit draft", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestCapability({
      requestId: "capability-bad",
      applicationId: "",
      capability: "",
      sensitivity: "root"
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value.intake.status, "denied");
    assert.equal(result.value.auditEventDraft.category, "capability");
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
    assert.ok(result.value.auditEventDraft.redactedDetails.issueCodes.includes("invalid_context"));
    assert.ok(
      result.value.auditEventDraft.redactedDetails.issueCodes.includes("invalid_capability_shape")
    );
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });

  it("valid intent request produces validation success and audit draft", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestIntent(validIntentRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "intent");
    assert.equal(result.value.auditEventDraft.outcome, "validation_succeeded");
    assert.equal(result.value.auditEventDraft.intentId, "intent-1");
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });

  it("invalid intent request produces validation failure and audit draft", function () {
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
    assert.equal(result.value.auditEventDraft.category, "intent");
    assert.equal(result.value.auditEventDraft.outcome, "validation_failed");
    assert.ok(result.value.auditEventDraft.redactedDetails.issueCodes.includes("invalid_intent_shape"));
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });

  it("unsupported future scoped agent permission produces unsupported audit draft", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestScopedAgentPermission({
      ...validIntentRequest(),
      futureOnly: true
    });

    assert.equal(result.status, "failed");
    assert.equal(result.value.auditEventDraft.category, "future_ai");
    assert.equal(result.value.auditEventDraft.outcome, "unsupported");
    assert.equal(result.error.category, "unsupported_operation");
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });

  it("audit drafts contain no secret payloads", function () {
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestIntent(validIntentRequest());
    const text = stringify(result.value.auditEventDraft);

    assert.equal(text.includes("phil_secret"), false);
    assert.equal(text.includes("must-not-appear-in-audit-draft"), false);
  });

  it("audit drafts do not retain a secret subtree beyond the default depth", function () {
    const draft = createAuditEventDraft({
      category: "runtime",
      outcome: "validation_succeeded",
      summary: "Depth redaction regression.",
      redactedDetails: {
        a: [{ b: [{ c: { password: "AUDIT-DEPTH-CANARY" } }] }]
      }
    });

    assert.equal(draft.redactedDetails.a[0].b[0].c, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(draft).includes("AUDIT-DEPTH-CANARY"), false);
  });

  it("audit draft facade path does not call storage, proof, adapter, or authorization hooks", function () {
    const api = createValidationOnlyRuntimeApi();
    const hooks = {
      adapterCalls: 0,
      proofCalls: 0,
      storageCalls: 0,
      authorizationCalls: 0
    };
    const result = api.requestAuthorization({
      ...validIntentRequest(),
      metadata: { hooks }
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      adapterCalls: 0,
      proofCalls: 0,
      storageCalls: 0,
      authorizationCalls: 0
    });
    assertDraftIsNotAuthorizationOrExecution(result.value.auditEventDraft);
  });
});
