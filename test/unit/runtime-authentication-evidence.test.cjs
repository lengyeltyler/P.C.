const assert = require("node:assert/strict");

const {
  createDeveloperFixtureAuthenticationProviderAdapter,
  createEphemeralUserSessionLifecycleStore,
  createProductionAuthenticationEvidence,
  createProductionAuthenticationRequest,
  createSessionLifecycleAuthenticationEvidenceReference,
  isAuthenticationProviderKind,
  isProductionAuthenticationEvidenceStatus,
  validateAuthenticationEvidenceAssurance,
  validateAuthenticationEvidenceCorrelation,
  validateAuthenticationEvidenceFreshness,
  validateAuthenticationProviderDescriptor,
  validateProductionAuthenticationEvidenceShape,
  validateProductionAuthenticationRequest
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function challengeReference(overrides = {}) {
  return {
    challengeReferenceId: "challenge-ref-1",
    challengeBindingHash: "challenge-binding-ref-1",
    createdAt: new Date().toISOString(),
    expiresAt: futureDate(),
    generatedChallenge: false,
    ...overrides
  };
}

function correlation(overrides = {}) {
  return {
    sessionId: "session-1",
    lifecycleTransitionRequestId: "unlock-transition-1",
    lifecycleEvent: "unlock_succeeded",
    ownerCommitment: "0xowner",
    applicationId: "ethereum-net",
    credentialId: "credential-1",
    deviceId: "device-1",
    auditCorrelationId: "session-1:unlock-transition-1:auth",
    ...overrides
  };
}

function requirement(overrides = {}) {
  const challenge = overrides.challengeReference ?? challengeReference();
  const corr = overrides.correlation ?? correlation();
  return {
    purpose: "session_unlock",
    provider: {
      providerKind: "developer_fixture",
      providerId: "developer-fixture-authentication-provider",
      minimumAssurance: ["developer_fixture", "user_presence"],
      userPresenceRequired: true
    },
    challengeReference: challenge,
    correlation: corr,
    expiresAt: futureDate(),
    requestedAssurance: ["developer_fixture", "user_presence"],
    ...overrides
  };
}

function authRequest(overrides = {}) {
  const req = createProductionAuthenticationRequest({
    requestId: overrides.requestId ?? "auth-request-1",
    purpose: overrides.purpose ?? "session_unlock",
    providerId: overrides.providerId ?? "developer-fixture-authentication-provider",
    providerKind: overrides.providerKind ?? "developer_fixture",
    requirement: overrides.requirement ?? requirement(),
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  });
  assert.equal(req.status, "approved", req.error?.details?.errors?.join("\n"));
  return req.value;
}

function webAuthnReference(overrides = {}) {
  return {
    kind: "webauthn",
    credentialId: "credential-1",
    authenticatorDataReference: "authenticator-data-ref",
    clientDataHashReference: "client-data-hash-ref",
    signatureReference: "signature-ref",
    signCounter: 42,
    userPresent: true,
    userVerified: true,
    origin: "https://philcore.local",
    rpId: "philcore.local",
    challengeBindingReference: "challenge-ref-1",
    ...overrides
  };
}

function biometricReference(overrides = {}) {
  return {
    kind: "platform_biometric",
    platformEvaluationReference: "biometric-evaluation-ref",
    userPresenceReference: "biometric-presence-ref",
    secureHardwareReference: "secure-hardware-ref",
    evaluatedAt: new Date().toISOString(),
    platformProviderId: "local-biometric-provider-ref",
    ...overrides
  };
}

function hardwareKeyReference(overrides = {}) {
  return {
    kind: "hardware_key",
    credentialId: "hardware-key-credential-1",
    assertionReference: "hardware-assertion-ref",
    signatureReference: "hardware-signature-ref",
    challengeReferenceId: "challenge-ref-1",
    userPresenceReference: "hardware-presence-ref",
    deviceProviderId: "hardware-key-provider-ref",
    ...overrides
  };
}

function recoveryReference(overrides = {}) {
  return {
    kind: "recovery_credential",
    recoveryCredentialId: "recovery-credential-1",
    recoveryModeReference: "recovery-mode-ref",
    recoveryCeremonyReference: "recovery-ceremony-ref",
    requiredDelayReference: "delay-ref",
    additionalFactorRequirements: [{
      providerKind: "hardware_security_key",
      minimumAssurance: ["user_presence"]
    }],
    ...overrides
  };
}

function evidenceFor(request, overrides = {}) {
  const result = createProductionAuthenticationEvidence({
    request,
    source: {
      providerId: request.providerId,
      providerKind: request.providerKind,
      fixtureOnly: true,
      productionAuthentication: false,
      platform: "local-dev"
    },
    providerEvidence: overrides.providerEvidence ?? webAuthnReference(),
    collectedAt: overrides.collectedAt,
    expiresAt: overrides.expiresAt ?? futureDate(),
    staleAfter: overrides.staleAfter,
    maxAgeMs: overrides.maxAgeMs,
    providedAssurance: overrides.providedAssurance ?? ["developer_fixture", "user_presence"],
    outcome: overrides.outcome,
    metadata: overrides.metadata
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function assertNoAuthority(evidence) {
  assert.equal(evidence.verifiesEvidence, false);
  assert.equal(evidence.authenticatesUser, false);
  assert.equal(evidence.trusted, false);
  assert.equal(evidence.approved, false);
  assert.equal(evidence.authorized, false);
  assert.equal(evidence.unlocksVault, false);
  assert.equal(evidence.grantsAuthority, false);
  assert.equal(evidence.persisted, false);
}

describe("PhilCore production authentication evidence boundary", function () {
  it("validates provider descriptors and provider kinds", function () {
    const adapter = createDeveloperFixtureAuthenticationProviderAdapter();
    const descriptor = adapter.describeProvider();

    assert.equal(validateAuthenticationProviderDescriptor(descriptor).valid, true);
    assert.equal(isAuthenticationProviderKind("webauthn_passkey"), true);
    assert.equal(isAuthenticationProviderKind("world_id"), false);
    assert.equal(descriptor.capabilities.fixtureOnly, true);
    assert.equal(descriptor.capabilities.productionAuthentication, false);
  });

  it("rejects unsupported provider kind in descriptor shape", function () {
    const result = validateAuthenticationProviderDescriptor({
      providerId: "provider-1",
      kind: "world_id",
      displayName: "World ID",
      status: "available",
      availability: "available",
      assurance: ["user_presence"],
      capabilities: {}
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((error) => error.includes("provider kind")));
  });

  it("creates and validates production authentication request shape without invoking a provider", function () {
    const request = authRequest();
    const validation = validateProductionAuthenticationRequest(request);

    assert.equal(validation.valid, true);
    assert.equal(request.invokesProvider, false);
    assert.equal(request.authenticatesUser, false);
    assert.equal(request.unlocksVault, false);
    assert.equal(request.grantsAuthority, false);
    assert.equal(request.persisted, false);
  });

  it("rejects malformed production authentication requests", function () {
    const result = validateProductionAuthenticationRequest({
      requestId: "",
      purpose: "session_unlock",
      providerId: "",
      providerKind: "developer_fixture",
      requestedAt: "not-a-date",
      invokesProvider: true,
      authenticatesUser: true,
      unlocksVault: true,
      grantsAuthority: true,
      persisted: true
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("requestId is required"));
    assert.ok(result.errors.includes("correlation is required"));
    assert.ok(result.errors.includes("invokesProvider must be false"));
  });

  it("detects session correlation mismatch", function () {
    const request = authRequest();
    const evidence = {
      ...evidenceFor(request),
      binding: {
        ...evidenceFor(request).binding,
        sessionId: "session-2"
      }
    };

    const validation = validateAuthenticationEvidenceCorrelation(request, evidence);

    assert.equal(validation.valid, false);
    assert.ok(validation.errors.some((error) => error.includes("sessionId")));
  });

  it("detects owner commitment mismatch", function () {
    const request = authRequest();
    const evidence = {
      ...evidenceFor(request),
      binding: {
        ...evidenceFor(request).binding,
        ownerCommitment: "0xother"
      }
    };

    const validation = validateAuthenticationEvidenceCorrelation(request, evidence);

    assert.equal(validation.valid, false);
    assert.ok(validation.errors.some((error) => error.includes("ownerCommitment")));
  });

  it("classifies challenge mismatch", function () {
    const request = authRequest();
    const result = createProductionAuthenticationEvidence({
      request: {
        ...request,
        challengeReference: {
          ...request.challengeReference,
          challengeReferenceId: "challenge-ref-expected"
        }
      },
      source: {
        providerId: request.providerId,
        providerKind: request.providerKind,
        fixtureOnly: true,
        productionAuthentication: false
      },
      providerEvidence: webAuthnReference(),
      expiresAt: futureDate(),
      providedAssurance: ["developer_fixture", "user_presence"]
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "verification_pending");

    const mismatched = {
      ...result.value,
      binding: {
        ...result.value.binding,
        challengeReferenceId: "challenge-ref-other"
      }
    };
    const correlation = validateAuthenticationEvidenceCorrelation(request, mismatched);
    assert.equal(correlation.valid, false);
    assert.ok(correlation.errors.some((error) => error.includes("challengeReferenceId")));
  });

  it("classifies expired and stale evidence", function () {
    const request = authRequest();
    const expiredEvidence = evidenceFor(request, {
      expiresAt: pastDate()
    });
    const staleEvidence = evidenceFor(request, {
      collectedAt: pastDate(120_000),
      maxAgeMs: 1_000,
      expiresAt: futureDate()
    });

    assert.equal(expiredEvidence.outcome, "evidence_expired");
    assert.equal(validateAuthenticationEvidenceFreshness(expiredEvidence).valid, false);
    assert.equal(staleEvidence.outcome, "evidence_replayed");
    assert.equal(validateAuthenticationEvidenceFreshness(staleEvidence).valid, false);
  });

  it("classifies insufficient assurance without authenticating", function () {
    const request = authRequest();
    const evidence = evidenceFor(request, {
      providedAssurance: ["developer_fixture"],
      expiresAt: futureDate()
    });

    assert.equal(evidence.outcome, "assurance_insufficient");
    assert.equal(validateAuthenticationEvidenceAssurance(
      evidence,
      ["developer_fixture", "user_presence"]
    ).valid, false);
    assertNoAuthority(evidence);
  });

  it("models WebAuthn evidence references without raw payloads", function () {
    const evidence = evidenceFor(authRequest(), {
      providerEvidence: webAuthnReference()
    });

    assert.equal(evidence.providerEvidence.kind, "webauthn");
    assert.equal(evidence.providerEvidence.credentialId, "credential-1");
    assert.equal(validateProductionAuthenticationEvidenceShape(evidence).valid, true);
    assert.equal(JSON.stringify(evidence).includes("clientDataJSON"), false);
    assertNoAuthority(evidence);
  });

  it("models platform biometric evidence references without biometric templates", function () {
    const evidence = evidenceFor(authRequest(), {
      providerEvidence: biometricReference(),
      providedAssurance: ["developer_fixture", "user_presence"]
    });

    assert.equal(evidence.providerEvidence.kind, "platform_biometric");
    assert.equal(evidence.providerEvidence.platformEvaluationReference, "biometric-evaluation-ref");
    assert.equal(validateProductionAuthenticationEvidenceShape(evidence).valid, true);
    assert.equal(JSON.stringify(evidence).includes("biometricTemplate"), false);
  });

  it("models hardware-key evidence references", function () {
    const evidence = evidenceFor(authRequest(), {
      providerEvidence: hardwareKeyReference()
    });

    assert.equal(evidence.providerEvidence.kind, "hardware_key");
    assert.equal(evidence.providerEvidence.challengeReferenceId, "challenge-ref-1");
    assert.equal(validateProductionAuthenticationEvidenceShape(evidence).valid, true);
  });

  it("models recovery credential evidence references", function () {
    const request = authRequest({
      purpose: "recovery_approval",
      requirement: requirement({
        purpose: "recovery_approval",
        requestedAssurance: ["developer_fixture"]
      })
    });
    const evidence = evidenceFor(request, {
      providerEvidence: recoveryReference(),
      providedAssurance: ["developer_fixture"]
    });

    assert.equal(evidence.providerEvidence.kind, "recovery_credential");
    assert.equal(evidence.providerEvidence.recoveryCredentialId, "recovery-credential-1");
    assert.equal(validateProductionAuthenticationEvidenceShape(evidence).valid, true);
  });

  it("rejects secret-shaped metadata and raw evidence fields", function () {
    const requestResult = createProductionAuthenticationRequest({
      requestId: "auth-secret",
      purpose: "session_unlock",
      providerId: "developer-fixture-authentication-provider",
      providerKind: "developer_fixture",
      requirement: requirement(),
      metadata: {
        phil_secret: "must-not-appear"
      }
    });
    const evidenceValidation = validateProductionAuthenticationEvidenceShape({
      ...evidenceFor(authRequest()),
      providerEvidence: {
        kind: "webauthn",
        credentialId: "credential-1",
        challengeBindingReference: "challenge-ref-1",
        clientDataJSON: "raw-client-data"
      }
    });

    assert.equal(requestResult.status, "denied");
    assert.equal(JSON.stringify(requestResult).includes("must-not-appear"), false);
    assert.equal(evidenceValidation.valid, false);
    assert.ok(evidenceValidation.errors.some((error) => error.includes("raw evidence")));
  });

  it("developer fixture adapter remains fixture-only and never calls platform APIs", function () {
    const adapter = createDeveloperFixtureAuthenticationProviderAdapter();
    const availability = adapter.checkAvailability();
    const request = adapter.createAuthenticationRequest(requirement()).value;
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      biometricCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const result = adapter.normalizeEvidence({
      request,
      providerResponseReference: webAuthnReference(),
      metadata: { hooks }
    });

    assert.equal(availability.fixtureOnly, true);
    assert.equal(availability.productionAuthentication, false);
    assert.equal(result.status, "approved");
    assert.equal(result.value.source.fixtureOnly, true);
    assert.equal(result.value.source.productionAuthentication, false);
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      biometricCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assertNoAuthority(result.value);
  });

  it("creates lifecycle evidence references without permitting lifecycle transitions", function () {
    const evidence = evidenceFor(authRequest());
    const bridge = createSessionLifecycleAuthenticationEvidenceReference(evidence);

    assert.equal(bridge.valid, true);
    assert.equal(bridge.reference.evidenceKind, "authentication_evidence");
    assert.equal(bridge.reference.verified, false);
    assert.equal(bridge.lifecycleEvidenceReference.verified, false);
    assert.equal(bridge.lifecycleEvidenceReference.rawEvidenceIncluded, false);
    assert.equal(bridge.permitsLifecycleTransition, false);
  });

  it("does not transition lifecycle state when evidence is created", function () {
    const store = createEphemeralUserSessionLifecycleStore();
    store.initialize({
      sessionId: "session-1",
      transitionRequestId: "initialize-1"
    });
    const before = store.getSnapshot();

    const evidence = evidenceFor(authRequest());
    const bridge = createSessionLifecycleAuthenticationEvidenceReference(evidence);

    assert.equal(bridge.permitsLifecycleTransition, false);
    assert.equal(store.getSnapshot().state, before.state);
    assert.equal(store.getSnapshot().sequence, before.sequence);
  });

  it("does not create active capability, session key, authorization, proof, adapter, or persistence", function () {
    const evidence = evidenceFor(authRequest());
    const text = JSON.stringify(evidence).toLowerCase();

    assert.equal(text.includes("sessionkey"), false);
    assert.equal(text.includes("authorizationpackage"), false);
    assert.equal(text.includes("capabilitygrant"), false);
    assert.equal(evidence.grantsAuthority, false);
    assert.equal(evidence.authorized, false);
    assert.equal(evidence.persisted, false);
    assert.equal(isProductionAuthenticationEvidenceStatus(evidence.status), true);
  });
});
