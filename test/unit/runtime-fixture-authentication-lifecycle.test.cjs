const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const {
  createDeveloperFixtureAuthenticationProviderAdapter,
  createEphemeralFixtureEvidenceConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createProductionAuthenticationEvidence,
  createProductionAuthenticationRequest,
  createUserSessionLifecycleSnapshot,
  transitionUserSessionWithVerifiedFixtureEvidence,
  verifyDeveloperFixtureAuthenticationEvidence
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function shell(args) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8"
    }
  );
}

function fixtureSetup(overrides = {}) {
  const adapter = createDeveloperFixtureAuthenticationProviderAdapter({
    providerId: overrides.providerId ?? "developer-fixture-authentication-provider"
  });
  const providerId = adapter.describeProvider().providerId;
  const challengeReferenceId = overrides.challengeReferenceId ?? "challenge-ref-1";
  const auditCorrelationId = overrides.auditCorrelationId ?? "session-1:fixture-auth";
  const requirement = {
    purpose: overrides.purpose ?? "session_unlock",
    provider: {
      providerKind: overrides.providerKind ?? "developer_fixture",
      providerId,
      minimumAssurance: overrides.expectedAssurance ?? ["developer_fixture", "user_presence"],
      userPresenceRequired: true
    },
    challengeReference: {
      challengeReferenceId,
      createdAt: new Date().toISOString(),
      expiresAt: futureDate(),
      generatedChallenge: false
    },
    correlation: {
      sessionId: overrides.sessionId ?? "session-1",
      lifecycleTransitionRequestId: overrides.lifecycleTransitionRequestId ?? "unlock-succeeded-1",
      lifecycleEvent: overrides.lifecycleEvent ?? "unlock_succeeded",
      ownerCommitment: overrides.ownerCommitment ?? "0xowner",
      applicationId: "ethereum-net",
      providerId,
      auditCorrelationId
    },
    expiresAt: futureDate(),
    requestedAssurance: overrides.expectedAssurance ?? ["developer_fixture", "user_presence"]
  };
  const request = createProductionAuthenticationRequest({
    requestId: overrides.authRequestId ?? "auth-request-1",
    purpose: requirement.purpose,
    providerId,
    providerKind: overrides.requestProviderKind ?? "developer_fixture",
    requirement,
    expiresAt: overrides.requestExpiresAt
  }).value;
  assert.ok(request);
  const evidence = createProductionAuthenticationEvidence({
    request,
    source: {
      providerId,
      providerKind: overrides.evidenceProviderKind ?? "developer_fixture",
      fixtureOnly: overrides.fixtureOnly ?? true,
      productionAuthentication: false,
      platform: "local-dev"
    },
    providerEvidence: {
      kind: "webauthn",
      credentialId: "fixture-credential-1",
      authenticatorDataReference: "fixture-authenticator-data-reference",
      clientDataHashReference: "fixture-client-data-hash-reference",
      signatureReference: "fixture-signature-reference",
      signCounter: 1,
      userPresent: true,
      userVerified: true,
      origin: "https://fixture.local",
      rpId: "fixture.local",
      challengeBindingReference: challengeReferenceId
    },
    collectedAt: overrides.collectedAt,
    expiresAt: overrides.evidenceExpiresAt ?? futureDate(),
    staleAfter: overrides.staleAfter,
    maxAgeMs: overrides.maxAgeMs,
    providedAssurance: overrides.providedAssurance ?? ["developer_fixture", "user_presence"]
  }).value;
  assert.ok(evidence);
  return {
    adapter,
    providerId,
    challengeReferenceId,
    auditCorrelationId,
    request,
    evidence
  };
}

function verify(setup, overrides = {}) {
  return verifyDeveloperFixtureAuthenticationEvidence({
    requestId: overrides.requestId ?? "fixture-verification-1",
    authenticationRequest: overrides.authenticationRequest ?? setup.request,
    evidence: overrides.evidence ?? setup.evidence,
    expectedSessionId: overrides.expectedSessionId ?? "session-1",
    expectedLifecycleTransitionRequestId:
      overrides.expectedLifecycleTransitionRequestId ?? "unlock-succeeded-1",
    expectedOwnerCommitment: overrides.expectedOwnerCommitment ?? "0xowner",
    expectedChallengeReferenceId:
      overrides.expectedChallengeReferenceId ?? setup.challengeReferenceId,
    expectedProviderId: overrides.expectedProviderId ?? setup.providerId,
    expectedAuditCorrelationId:
      overrides.expectedAuditCorrelationId ?? setup.auditCorrelationId,
    expectedAssurance: overrides.expectedAssurance ?? ["developer_fixture", "user_presence"],
    replayStore: overrides.replayStore
  });
}

function assertNoProductionAuthority(artifactOrValue) {
  assert.equal(artifactOrValue.fixtureOnly, true);
  assert.equal(artifactOrValue.productionAuthenticationPerformed, false);
  assert.equal(artifactOrValue.vaultUnlocked, false);
  assert.equal(artifactOrValue.grantsAuthority, false);
  assert.equal(artifactOrValue.persisted, false);
}

describe("PhilCore fixture-only authentication lifecycle bridge", function () {
  it("verifies valid developer fixture evidence", function () {
    const setup = fixtureSetup();
    const result = verify(setup);

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "fixture_evidence_verified");
    assert.equal(result.value.verifiedFixtureEvidenceReference.verified, true);
    assert.equal(result.value.verifiedFixtureEvidenceReference.fixtureOnly, true);
    assertNoProductionAuthority(result.value);
    assert.equal(result.value.platformWebAuthnPerformed, false);
    assert.equal(result.value.biometricVerificationPerformed, false);
  });

  it("rejects unsupported provider evidence", function () {
    const setup = fixtureSetup({
      requestProviderKind: "webauthn_passkey",
      evidenceProviderKind: "webauthn_passkey"
    });

    const result = verify(setup);

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("developer_fixture")));
  });

  it("rejects malformed evidence", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      evidence: {
        evidenceId: "",
        requestId: ""
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("evidence.")));
  });

  it("rejects session mismatch", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      expectedSessionId: "session-2"
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("session")));
  });

  it("rejects transition request mismatch", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      expectedLifecycleTransitionRequestId: "other-transition"
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("transition")));
  });

  it("rejects owner commitment mismatch", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      expectedOwnerCommitment: "0xother"
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("owner")));
  });

  it("rejects challenge mismatch", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      expectedChallengeReferenceId: "challenge-other"
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("challenge")));
  });

  it("rejects audit correlation mismatch", function () {
    const setup = fixtureSetup();
    const result = verify(setup, {
      expectedAuditCorrelationId: "audit-other"
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("audit")));
  });

  it("rejects expired and stale fixture evidence", function () {
    const expiredSetup = fixtureSetup({
      evidenceExpiresAt: pastDate()
    });
    const staleSetup = fixtureSetup({
      collectedAt: pastDate(120_000),
      maxAgeMs: 1_000
    });

    assert.equal(verify(expiredSetup).status, "denied");
    assert.ok(verify(expiredSetup).error.details.errors.some((error) => error.includes("expired")));
    assert.equal(verify(staleSetup).status, "denied");
    assert.ok(verify(staleSetup).error.details.errors.some((error) => error.includes("stale")));
  });

  it("rejects insufficient assurance", function () {
    const setup = fixtureSetup({
      providedAssurance: ["developer_fixture"]
    });
    const result = verify(setup);

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("assurance")));
  });

  it("rejects replayed fixture evidence with process-local replay state", function () {
    const setup = fixtureSetup();
    const replayStore = createEphemeralFixtureEvidenceConsumptionStore();
    const first = verify(setup, { replayStore });
    const second = verify(setup, { replayStore });

    assert.equal(first.status, "approved");
    assert.equal(second.status, "denied");
    assert.ok(second.error.details.errors.some((error) => error.includes("already consumed")));
    assert.equal(replayStore.has(setup.evidence.evidenceId), true);
  });

  it("performs a valid fixture unlock transition", function () {
    const store = createEphemeralUserSessionLifecycleStore();
    store.initialize({
      sessionId: "session-1",
      transitionRequestId: "initialize-1"
    });
    store.requestTransition({
      transitionRequestId: "request-unlock-1",
      event: "request_unlock"
    });
    const setup = fixtureSetup();
    const verified = verify(setup).value.verifiedFixtureEvidenceReference;
    const result = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: store.getSnapshot(),
      transitionRequest: {
        transitionRequestId: "unlock-succeeded-1",
        event: "unlock_succeeded"
      },
      verifiedFixtureEvidenceReference: verified
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.transitionResult.snapshot.state, "unlocked");
    assert.equal(result.value.vaultUnlocked, false);
    assert.equal(result.value.activeCapabilityCreated, false);
    assert.equal(result.value.authorizationCreated, false);
    assertNoProductionAuthority(result.value);
    assert.ok(result.value.transitionResult.snapshot.limitations.some(
      (limitation) => limitation.limitationId === "vault_remains_locked"
    ));
  });

  it("performs a valid fixture resume transition", function () {
    const setup = fixtureSetup({
      lifecycleTransitionRequestId: "resume-succeeded-1",
      lifecycleEvent: "resume_succeeded"
    });
    const verified = verify(setup, {
      expectedLifecycleTransitionRequestId: "resume-succeeded-1"
    }).value.verifiedFixtureEvidenceReference;
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-1",
      state: "resuming",
      sequence: 3,
      version: 3
    });

    const result = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "resume-succeeded-1",
        event: "resume_succeeded"
      },
      verifiedFixtureEvidenceReference: verified
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.transitionResult.snapshot.state, "unlocked");
    assert.equal(result.value.productionAuthenticationPerformed, false);
  });

  it("rejects unverified or non-fixture references for transition", function () {
    const setup = fixtureSetup();
    const verified = verify(setup).value.verifiedFixtureEvidenceReference;
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-1",
      state: "unlocking",
      sequence: 2,
      version: 2
    });

    const result = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-succeeded-1",
        event: "unlock_succeeded"
      },
      verifiedFixtureEvidenceReference: {
        ...verified,
        verified: false
      }
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("verified")));
  });

  it("rejects fixture evidence for unsupported recovery transitions", function () {
    const setup = fixtureSetup({
      lifecycleTransitionRequestId: "recovery-completed-1",
      lifecycleEvent: "recovery_completed"
    });
    const verified = verify(setup, {
      expectedLifecycleTransitionRequestId: "recovery-completed-1"
    }).value.verifiedFixtureEvidenceReference;
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-1",
      state: "recovery_mode",
      sequence: 2,
      version: 2
    });

    const result = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "recovery-completed-1",
        event: "recovery_completed"
      },
      verifiedFixtureEvidenceReference: verified
    });

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("unlock_succeeded")));
  });

  it("rejects replayed fixture evidence during lifecycle transition", function () {
    const replayStore = createEphemeralFixtureEvidenceConsumptionStore();
    const setup = fixtureSetup();
    const verified = verify(setup).value.verifiedFixtureEvidenceReference;
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-1",
      state: "unlocking",
      sequence: 2,
      version: 2
    });
    const first = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-succeeded-1",
        event: "unlock_succeeded"
      },
      verifiedFixtureEvidenceReference: verified,
      replayStore
    });
    const second = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-succeeded-1",
        event: "unlock_succeeded"
      },
      verifiedFixtureEvidenceReference: verified,
      replayStore
    });

    assert.equal(first.status, "approved");
    assert.equal(second.status, "denied");
    assert.ok(second.error.details.errors.some((error) => error.includes("already consumed")));
  });

  it("does not call platform WebAuthn, biometrics, vault, World ID, proof, adapter, or persistence hooks", function () {
    const hooks = {
      webAuthnCalls: 0,
      biometricCalls: 0,
      vaultCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      persistenceCalls: 0
    };
    const setup = fixtureSetup();
    const result = verify(setup, {
      requestId: "hooks-test",
      expectedAssurance: ["developer_fixture", "user_presence"],
      replayStore: undefined
    });

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      webAuthnCalls: 0,
      biometricCalls: 0,
      vaultCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      persistenceCalls: 0
    });
    assertNoProductionAuthority(result.value);
  });

  it("presents fixture unlock in the Alpha 0 lifecycle shell without real login language", function () {
    const result = shell(["--lifecycle", "--lifecycle-sequence", "fixture_unlock"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /fixture_unlock/);
    assert.match(result.stdout, /fixture-only authentication: yes/);
    assert.match(result.stdout, /production authentication: not performed/);
    assert.match(result.stdout, /Device Vault unlock: not performed/);
    assert.match(result.stdout, /Final lifecycle state: unlocked/);
  });
});
