const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryPossessionEvaluationResultCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createValidationOnlyRuntimeApi,
  evaluatePublicTrustMetadata,
  validatePossessionEvaluationResultShape
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

function trustDraft(id = "trust-draft-1") {
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
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function publicMetadataEvaluation() {
  const result = evaluatePublicTrustMetadata({
    requestId: "public-trust-evaluation-1",
    trustEvaluationDraft: trustDraft(),
    credential: {
      credentialId: "credential-1",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1",
      lifecycleStatus: "active",
      ownerCommitment: "0x1234"
    },
    device: {
      deviceId: "device-1",
      providerKind: "webauthn-passkey-device-identity-v1",
      lifecycleStatus: "active",
      ownerCommitment: "0x1234",
      publicMetadata: {
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
      }
    },
    ownerCommitment: "0x1234",
    auditCorrelationId: "public-trust-evaluation-1"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function possessionDraft() {
  const result = createPossessionVerificationRequestDraft({
    requestId: "possession-draft-1",
    publicTrustMetadataEvaluation: publicMetadataEvaluation(),
    auditCorrelationId: "possession-draft-1",
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function fixtureArtifact(draft, overrides = {}) {
  const outcome = overrides.outcome ?? "fixture_verified";
  return Object.freeze({
    artifactId: overrides.artifactId ?? "fixture-artifact-1",
    requestId: overrides.requestId ?? "fixture-request-1",
    possessionVerificationRequestDraftId:
      overrides.possessionVerificationRequestDraftId
        ?? draft.possessionVerificationRequestDraftId,
    publicTrustMetadataEvaluationId:
      overrides.publicTrustMetadataEvaluationId ?? draft.publicTrustMetadataEvaluationId,
    trustEvaluationDraftId: overrides.trustEvaluationDraftId ?? draft.trustEvaluationDraftId,
    applicationId: overrides.applicationId ?? draft.applicationId,
    sessionId: overrides.sessionId ?? draft.sessionId,
    credentialId: overrides.credentialId ?? draft.credentialId,
    deviceId: overrides.deviceId ?? draft.deviceId,
    fixtureId: overrides.fixtureId ?? "fixture-1",
    verifierKind: "webauthn-es256-spki-assertion-verifier-v1",
    status: outcome,
    outcome,
    reasons: ["possession-verification-draft-valid", "fixture-input-valid"],
    challengeMatched: overrides.challengeMatched ?? outcome !== "challenge_mismatch",
    originMatched: overrides.originMatched ?? true,
    rpIdHashMatched: overrides.rpIdHashMatched ?? true,
    userPresent: overrides.userPresent ?? outcome !== "user_presence_missing",
    userVerified: overrides.userVerified ?? outcome !== "user_verification_missing",
    signatureVerified: overrides.signatureVerified ?? outcome === "fixture_verified",
    counterStatus: overrides.counterStatus ?? "advanced",
    previousSignCount: overrides.previousSignCount ?? 6,
    newSignCount: overrides.newSignCount ?? 7,
    counterPersisted: false,
    verificationErrors: overrides.verificationErrors ?? [],
    verificationWarnings: overrides.verificationWarnings ?? [],
    verifiedAt: "2026-07-10T00:00:00.000Z",
    auditCorrelationId: overrides.auditCorrelationId ?? "fixture-artifact-1",
    fixtureOnly: true,
    productionAuthentication: false,
    authenticatesUser: false,
    verifiesProductionPossession: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });
}

function request(overrides = {}) {
  const draft = overrides.draft ?? possessionDraft();
  return {
    requestId: overrides.requestId ?? "possession-evaluation-request-1",
    possessionVerificationRequestDraft: draft,
    webAuthnFixtureVerificationArtifact:
      overrides.artifact ?? fixtureArtifact(draft, overrides.artifactOverrides),
    auditCorrelationId: overrides.auditCorrelationId,
    metadata: overrides.metadata
  };
}

function assertNonAuthoritative(result) {
  const text = JSON.stringify(result).toLowerCase();
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorized\":true"), false);
  assert.equal(text.includes("production_verified"), false);
  assert.equal(result.fixtureOnly, true);
  assert.equal(result.productionAuthentication, false);
  assert.equal(result.authenticatesUser, false);
  assert.equal(result.verifiesProductionPossession, false);
  assert.equal(result.providesTrustDecision, false);
  assert.equal(result.grantsAuthority, false);
  assert.equal(result.persisted, false);
}

describe("PhilCore non-authoritative possession evaluation results", function () {
  it("converts a successful WebAuthn fixture artifact into a non-authoritative result", function () {
    const result = createPossessionEvaluationResultFromWebAuthnFixture(request());

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "fixture_possession_checks_satisfied");
    assert.equal(result.value.counterAssessment.counterPersisted, false);
    assert.equal(result.value.evidence.fixtureOnly, true);
    assertNonAuthoritative(result.value);
  });

  it("converts failed fixture outcomes without creating trust authority", function () {
    const draft = possessionDraft();
    const failed = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        outcome: "user_verification_missing",
        userVerified: false,
        signatureVerified: false
      })
    }));
    const counter = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        artifactId: "fixture-artifact-counter",
        outcome: "counter_invalid",
        counterStatus: "rollback",
        newSignCount: 6,
        signatureVerified: false
      })
    }));

    assert.equal(failed.value.outcome, "authenticator_requirements_failed");
    assert.equal(counter.value.outcome, "counter_check_failed");
    assert.equal(counter.value.counterAssessment.counterPersisted, false);
    assertNonAuthoritative(failed.value);
    assertNonAuthoritative(counter.value);
  });

  it("rejects malformed artifacts and secret-shaped metadata", function () {
    const draft = possessionDraft();
    const malformed = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: {
        artifactId: "",
        possessionVerificationRequestDraftId: draft.possessionVerificationRequestDraftId
      }
    }));
    const secretMetadata = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      metadata: {
        phil_secret: "must-not-enter"
      }
    }));

    assert.equal(malformed.status, "denied");
    assert.equal(secretMetadata.status, "denied");
    assert.equal(JSON.stringify(secretMetadata).includes("must-not-enter"), false);
  });

  it("detects challenge, application, session, and credential correlation mismatches", function () {
    const draft = possessionDraft();
    const challengeMismatch = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        possessionVerificationRequestDraftId: "wrong-draft-id"
      })
    }));
    const applicationMismatch = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        artifactId: "fixture-artifact-app",
        applicationId: "nft-manager"
      })
    }));
    const sessionMismatch = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        artifactId: "fixture-artifact-session",
        sessionId: "session-2"
      })
    }));
    const credentialMismatch = createPossessionEvaluationResultFromWebAuthnFixture(request({
      draft,
      artifact: fixtureArtifact(draft, {
        artifactId: "fixture-artifact-credential",
        credentialId: "credential-2"
      })
    }));

    assert.equal(challengeMismatch.value.outcome, "challenge_binding_failed");
    assert.ok(challengeMismatch.value.reasons.includes("challenge-correlation-mismatch"));
    assert.ok(applicationMismatch.value.reasons.includes("application-correlation-mismatch"));
    assert.ok(sessionMismatch.value.reasons.includes("session-correlation-mismatch"));
    assert.ok(credentialMismatch.value.reasons.includes("credential-correlation-mismatch"));
  });

  it("collects possession evaluation results ephemerally", function () {
    const collector = createInMemoryPossessionEvaluationResultCollector({
      maxResultCount: 1
    });
    const first = createPossessionEvaluationResultFromWebAuthnFixture(request({
      requestId: "request-1",
      auditCorrelationId: "result-1"
    })).value;
    const second = createPossessionEvaluationResultFromWebAuthnFixture(request({
      requestId: "request-2",
      artifactOverrides: { artifactId: "fixture-artifact-2" },
      auditCorrelationId: "result-2"
    })).value;

    assert.equal(collector.count(), 0);
    assert.equal(collector.addResult(first).status, "collected");
    assert.equal(collector.addResult(first).status, "rejected_duplicate");
    const evicted = collector.addResult(second);
    assert.equal(evicted.status, "evicted_oldest");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById(first.possessionEvaluationResultId), undefined);
    assert.equal(collector.filter({ outcome: "fixture_possession_checks_satisfied" }).length, 1);
    assert.equal(collector.clear().status, "cleared");
  });

  it("facade creates audit drafts and optionally collects possession results", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const possessionEvaluationResultCollector =
      createInMemoryPossessionEvaluationResultCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      possessionEvaluationResultCollector
    });

    const result = api.requestFixturePossessionEvaluation(request());

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.possessionEvaluationResult.outcome, "fixture_possession_checks_satisfied");
    assert.equal(result.value.possessionEvaluationCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assert.equal(possessionEvaluationResultCollector.count(), 1);
    assertNonAuthoritative(result.value.possessionEvaluationResult);
  });

  it("does not call vault, storage, browser WebAuthn, session, capability, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      browserWebAuthnCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };

    const result = createPossessionEvaluationResultFromWebAuthnFixture(request({
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      browserWebAuthnCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(validatePossessionEvaluationResultShape(result.value).valid, true);
  });
});
