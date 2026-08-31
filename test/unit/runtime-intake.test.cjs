const assert = require("node:assert/strict");

const {
  createAdapterManifestDraft,
  createApplicationManifestDraft,
  createCapabilityRequestDraft,
  createIntentDraft,
  createRuntimeRequestContext,
  validateAdapterRegistrationIntake,
  validateApplicationRegistrationIntake,
  validateCapabilityRequestIntake,
  validateIntentRequestIntake,
  validateRuntimeRequestIntake
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function validContext() {
  return createRuntimeRequestContext({
    requestId: "request-1",
    sessionId: "session-1",
    applicationId: "ethereum-net",
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

function validCapabilityRequest() {
  return createCapabilityRequestDraft({
    requestId: "capability-1",
    applicationId: "ethereum-net",
    capability: "request_transaction_submission",
    sensitivity: "privileged"
  });
}

function issueCodes(result) {
  return result.error.details.issueCodes;
}

describe("PhilCore runtime request intake", function () {
  it("accepts a valid generic intake envelope", function () {
    const result = validateRuntimeRequestIntake({
      kind: "generic",
      context: validContext(),
      intent: validIntent(),
      capabilityRequest: validCapabilityRequest()
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.valid, true);
    assert.deepEqual(result.value.issues, []);
  });

  it("reports unknown request kind", function () {
    const result = validateRuntimeRequestIntake({
      kind: "execute-now",
      context: validContext()
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("unknown_request_kind"));
  });

  it("reports missing context", function () {
    const result = validateRuntimeRequestIntake({
      kind: "intent",
      intent: validIntent()
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("missing_context"));
  });

  it("reports invalid context", function () {
    const result = validateRuntimeRequestIntake({
      kind: "intent",
      context: {
        requestId: "",
        applicationId: "",
        requestedAt: "not-a-date"
      },
      intent: validIntent()
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("invalid_context"));
  });

  it("reports invalid intent shape", function () {
    const result = validateIntentRequestIntake({
      context: validContext(),
      intent: {
        intentId: "",
        applicationId: "ethereum-net",
        requestedCapabilities: [],
        payload: {}
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("invalid_intent_shape"));
  });

  it("reports invalid capability request shape", function () {
    const result = validateCapabilityRequestIntake({
      context: validContext(),
      capabilityRequest: {
        requestId: "capability-bad",
        applicationId: "",
        capability: "",
        sensitivity: "root"
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("invalid_capability_shape"));
  });

  it("reports invalid application manifest shape", function () {
    const result = validateApplicationRegistrationIntake({
      context: validContext(),
      applicationManifest: {
        applicationId: "ethereum-net",
        displayName: "",
        version: "",
        requestedCapabilities: []
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("invalid_application_manifest_shape"));
  });

  it("reports invalid adapter manifest shape", function () {
    const result = validateAdapterRegistrationIntake({
      context: validContext(),
      adapterManifest: {
        adapterId: "",
        displayName: "Ethereum Adapter",
        version: "0.1.0",
        executionEnvironment: "ethereum",
        providedCapabilities: [],
        requiresAuthorizationPackage: "yes"
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("invalid_adapter_manifest_shape"));
  });

  it("reports expired intent shape", function () {
    const result = validateRuntimeRequestIntake({
      kind: "intent",
      context: validContext(),
      intent: createIntentDraft({
        intentId: "intent-expired",
        kind: "submit-transaction",
        applicationId: "ethereum-net",
        requestedCapabilities: ["request_transaction_submission"],
        payload: {},
        expiresAt: new Date(Date.now() - 60_000).toISOString()
      })
    });

    assert.equal(result.status, "denied");
    assert.ok(issueCodes(result).includes("expired_intent_shape"));
  });

  it("returns malformed request envelopes without authorization, proof, adapter, or storage effects", function () {
    const result = validateRuntimeRequestIntake({
      kind: "intent",
      context: validContext(),
      intent: {
        intentId: "",
        kind: "submit-transaction",
        applicationId: "ethereum-net",
        requestedCapabilities: ["request_transaction_submission"],
        payload: {}
      }
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.equal(result.error.category, "invalid_intent");
    assert.equal(result.error.boundary, "runtime-api");
    assert.equal(Object.hasOwn(result, "authorizationPackage"), false);
    assert.equal(Object.hasOwn(result, "proofPackage"), false);
    assert.equal(Object.hasOwn(result, "adapterExecutionResult"), false);
    assert.equal(Object.hasOwn(result, "storageWrite"), false);
  });

  it("accepts valid application and adapter registration envelopes", function () {
    const application = validateApplicationRegistrationIntake({
      context: validContext(),
      applicationManifest: createApplicationManifestDraft({
        applicationId: "ethereum-net",
        displayName: "Ethereum Net",
        version: "0.1.0",
        requestedCapabilities: ["read_balance"]
      })
    });
    const adapter = validateAdapterRegistrationIntake({
      context: validContext(),
      adapterManifest: createAdapterManifestDraft({
        adapterId: "ethereum",
        displayName: "Ethereum Adapter",
        version: "0.1.0",
        executionEnvironment: "ethereum",
        providedCapabilities: ["read_balance"],
        requiresAuthorizationPackage: true
      })
    });

    assert.equal(application.status, "approved");
    assert.equal(adapter.status, "approved");
  });
});
