const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryBoundedTrustEvaluationResultCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createValidationOnlyRuntimeApi,
  evaluateBoundedTrustEvidence,
  evaluatePublicTrustMetadata,
  validateBoundedTrustEvaluationResultShape
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

function publicMetadataEvaluation(draft = trustDraft()) {
  const result = evaluatePublicTrustMetadata({
    requestId: "public-trust-evaluation-1",
    trustEvaluationDraft: draft,
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

function possessionDraft(metadata = publicMetadataEvaluation()) {
  const result = createPossessionVerificationRequestDraft({
    requestId: "possession-draft-1",
    publicTrustMetadataEvaluation: metadata,
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

function possessionEvaluation(draft = possessionDraft(), overrides = {}) {
  const result = createPossessionEvaluationResultFromWebAuthnFixture({
    requestId: overrides.requestId ?? "possession-evaluation-request-1",
    possessionVerificationRequestDraft: draft,
    webAuthnFixtureVerificationArtifact: fixtureArtifact(draft, overrides.artifactOverrides),
    auditCorrelationId: overrides.auditCorrelationId ?? "possession-evaluation-1"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function evidence(overrides = {}) {
  const draft = overrides.trustEvaluationDraft ?? trustDraft();
  const metadata = overrides.publicTrustMetadataEvaluation ?? publicMetadataEvaluation(draft);
  const possession = overrides.possessionEvaluationResult
    ?? possessionEvaluation(possessionDraft(metadata), overrides.possessionOverrides);
  return {
    requestId: overrides.requestId ?? "bounded-trust-evaluation-request-1",
    trustEvaluationDraft: draft,
    publicTrustMetadataEvaluation: metadata,
    possessionEvaluationResult: possession,
    credentialLifecycleStatus: overrides.credentialLifecycleStatus ?? "active",
    evaluationContext: overrides.evaluationContext,
    applicationId: overrides.applicationId,
    sessionId: overrides.sessionId,
    credentialId: overrides.credentialId,
    deviceId: overrides.deviceId,
    ownerCommitment: overrides.ownerCommitment,
    auditCorrelationId: overrides.auditCorrelationId,
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  };
}

function withMetadataOutcome(metadata, patch) {
  return Object.freeze({
    ...metadata,
    ...patch,
    reasons: patch.reasons ?? metadata.reasons
  });
}

function assertNonAuthoritative(result) {
  const text = JSON.stringify(result).toLowerCase();
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorized\":true"), false);
  assert.equal(text.includes("world_id_verified"), false);
  assert.equal(result.fixtureOnlyEvidence, true);
  assert.equal(result.productionAuthenticationPerformed, false);
  assert.equal(result.possessionVerifiedForProduction, false);
  assert.equal(result.credentialLoadedFromVault, false);
  assert.equal(result.counterPersisted, false);
  assert.equal(result.worldIdEnrollmentVerified, false);
  assert.equal(result.providesTrustDecision, false);
  assert.equal(result.grantsAuthority, false);
  assert.equal(result.persisted, false);
}

describe("PhilCore bounded non-authoritative Trust evaluation results", function () {
  it("classifies active lifecycle, sufficient metadata, and successful fixture possession as ready for future policy review", function () {
    const result = evaluateBoundedTrustEvidence(evidence());

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "evaluation_sufficient_for_policy_review");
    assert.equal(result.value.eligibleForPolicyReview, true);
    assert.equal(result.value.requiresProductionPossessionVerification, true);
    assert.equal(result.value.requiresWorldIdEnrollment, false);
    assert.equal(result.value.lifecycleAssessment.eligibleForOrdinaryUse, true);
    assertNonAuthoritative(result.value);
  });

  it("classifies missing metadata without loading credentials", function () {
    const base = evidence();
    const missing = withMetadataOutcome(base.publicTrustMetadataEvaluation, {
      outcome: "metadata_missing",
      eligibility: "pending_resolution",
      eligibleForFurtherEvaluation: false,
      requiresCredentialResolution: true,
      resolutionRequirements: ["credential_resolution"],
      reasons: ["credential-metadata-missing"]
    });
    const result = evaluateBoundedTrustEvidence(evidence({
      trustEvaluationDraft: base.trustEvaluationDraft,
      publicTrustMetadataEvaluation: missing,
      possessionEvaluationResult: base.possessionEvaluationResult
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "pending_credential_resolution");
    assert.equal(result.value.eligibleForPolicyReview, false);
    assert.ok(result.value.resolutionRequirements.includes("credential_resolution"));
  });

  it("classifies failed fixture possession as insufficient evidence", function () {
    const draft = possessionDraft();
    const failed = possessionEvaluation(draft, {
      artifactOverrides: {
        outcome: "user_verification_missing",
        userVerified: false,
        signatureVerified: false
      }
    });
    const result = evaluateBoundedTrustEvidence(evidence({
      trustEvaluationDraft: trustDraft(),
      publicTrustMetadataEvaluation: publicMetadataEvaluation(trustDraft()),
      possessionEvaluationResult: failed
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "possession_evidence_insufficient");
    assert.equal(result.value.eligibleForPolicyReview, false);
    assertNonAuthoritative(result.value);
  });

  it("classifies revoked, archived, pending, and ordinary recovery-only lifecycle statuses", function () {
    const revoked = evaluateBoundedTrustEvidence(evidence({
      credentialLifecycleStatus: "revoked"
    }));
    const archived = evaluateBoundedTrustEvidence(evidence({
      credentialLifecycleStatus: "archived"
    }));
    const pending = evaluateBoundedTrustEvidence(evidence({
      credentialLifecycleStatus: "pending"
    }));
    const recoveryOnlyOrdinary = evaluateBoundedTrustEvidence(evidence({
      credentialLifecycleStatus: "recovery-only"
    }));

    assert.equal(revoked.value.outcome, "credential_lifecycle_ineligible");
    assert.equal(archived.value.outcome, "credential_lifecycle_ineligible");
    assert.equal(pending.value.outcome, "pending_credential_resolution");
    assert.equal(recoveryOnlyOrdinary.value.outcome, "credential_lifecycle_ineligible");
    assert.equal(recoveryOnlyOrdinary.value.lifecycleAssessment.eligibleForRecoveryUse, false);
  });

  it("allows recovery-only lifecycle only in explicit recovery context", function () {
    const result = evaluateBoundedTrustEvidence(evidence({
      credentialLifecycleStatus: "recovery-only",
      evaluationContext: "recovery"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "evaluation_sufficient_for_policy_review");
    assert.equal(result.value.lifecycleAssessment.eligibleForOrdinaryUse, false);
    assert.equal(result.value.lifecycleAssessment.eligibleForRecoveryUse, true);
    assert.ok(result.value.resolutionRequirements.includes("recovery_policy_review"));
    assertNonAuthoritative(result.value);
  });

  it("rejects correlation mismatches, owner commitment mismatch, and application/session mismatch", function () {
    const ownerMismatch = evaluateBoundedTrustEvidence(evidence({
      ownerCommitment: "0x9999"
    }));
    const applicationMismatch = evaluateBoundedTrustEvidence(evidence({
      applicationId: "nft-manager"
    }));
    const sessionMismatch = evaluateBoundedTrustEvidence(evidence({
      sessionId: "session-2"
    }));

    assert.equal(ownerMismatch.status, "denied");
    assert.equal(applicationMismatch.status, "denied");
    assert.equal(sessionMismatch.status, "denied");
  });

  it("rejects expired evidence, malformed inputs, secret metadata, and false production-authentication claims", function () {
    const expired = evaluateBoundedTrustEvidence(evidence({
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }));
    const malformed = evaluateBoundedTrustEvidence({
      requestId: "",
      credentialLifecycleStatus: "active"
    });
    const secretMetadata = evaluateBoundedTrustEvidence(evidence({
      metadata: {
        privateKey: "must-not-enter"
      }
    }));
    const falseProduction = evaluateBoundedTrustEvidence(evidence({
      possessionEvaluationResult: {
        ...evidence().possessionEvaluationResult,
        productionAuthenticationPerformed: true
      }
    }));

    assert.equal(expired.status, "denied");
    assert.equal(malformed.status, "denied");
    assert.equal(secretMetadata.status, "denied");
    assert.equal(JSON.stringify(secretMetadata).includes("must-not-enter"), false);
    assert.equal(falseProduction.status, "denied");
  });

  it("keeps World ID future-only and requires it only for canonical activation context", function () {
    const ordinary = evaluateBoundedTrustEvidence(evidence());
    const canonical = evaluateBoundedTrustEvidence(evidence({
      evaluationContext: "canonical_phil_activation"
    }));

    assert.equal(ordinary.value.requiresWorldIdEnrollment, false);
    assert.equal(ordinary.value.worldIdEnrollmentVerified, false);
    assert.equal(canonical.value.requiresWorldIdEnrollment, true);
    assert.equal(canonical.value.worldIdEnrollmentVerified, false);
    assert.ok(canonical.value.resolutionRequirements.includes("world_id_enrollment"));
  });

  it("facade creates audit drafts and optionally collects bounded results", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const boundedTrustEvaluationResultCollector =
      createInMemoryBoundedTrustEvaluationResultCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      boundedTrustEvaluationResultCollector
    });

    const result = api.requestBoundedTrustEvaluation(evidence());

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.boundedTrustEvaluationResult.outcome, "evaluation_sufficient_for_policy_review");
    assert.equal(result.value.boundedTrustEvaluationCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assert.equal(boundedTrustEvaluationResultCollector.count(), 1);
    assertNonAuthoritative(result.value.boundedTrustEvaluationResult);
  });

  it("collector is ephemeral, duplicate protected, bounded, and rejects malformed authority-shaped results", function () {
    const collector = createInMemoryBoundedTrustEvaluationResultCollector({
      maxResultCount: 1
    });
    const first = evaluateBoundedTrustEvidence(evidence({
      auditCorrelationId: "bounded-result-1"
    })).value;
    const second = evaluateBoundedTrustEvidence(evidence({
      requestId: "bounded-request-2",
      auditCorrelationId: "bounded-result-2"
    })).value;

    assert.equal(collector.addResult(first).status, "collected");
    assert.equal(collector.addResult(first).status, "rejected_duplicate");
    assert.equal(collector.addResult({
      ...first,
      boundedTrustEvaluationResultId: "bad-result",
      productionAuthenticationPerformed: true
    }).status, "rejected_invalid");
    assert.equal(collector.addResult(second).status, "evicted_oldest");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById(first.boundedTrustEvaluationResultId), undefined);
    assert.equal(collector.filter({ eligibleForPolicyReview: true }).length, 1);
    assert.equal(collector.clear().status, "cleared");
  });

  it("does not call vault, storage, browser WebAuthn, policy, user approval, authorization, proof, or adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      browserWebAuthnCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };

    const result = evaluateBoundedTrustEvidence(evidence({
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      browserWebAuthnCalls: 0,
      policyCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(validateBoundedTrustEvaluationResultShape(result.value).valid, true);
    assertNonAuthoritative(result.value);
  });
});
