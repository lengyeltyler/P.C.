const assert = require("node:assert/strict");

const {
  createCapabilityActivationCandidate,
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryCapabilityActivationCandidateCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createUserApprovalRequestDraft,
  createUserDecisionFixtureArtifact,
  createValidationOnlyRuntimeApi,
  evaluateBoundedRuntimePolicy,
  evaluateBoundedTrustEvidence,
  evaluatePublicTrustMetadata,
  validateCapabilityActivationCandidateShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityDraft(overrides = {}) {
  const result = createCapabilityGrantDraft({
    capabilityRequest: createCapabilityRequestDraft({
      requestId: overrides.requestId ?? "capability-request-1",
      applicationId: overrides.applicationId ?? "ethereum-net",
      capability: overrides.capability ?? "request_message_signature",
      sensitivity: "sensitive",
      scope: overrides.scope,
      requestedAt: "2026-07-10T00:00:00.000Z"
    }),
    sessionId: overrides.sessionId ?? "session-1",
    auditCorrelationId: overrides.auditCorrelationId ?? "capability-draft-1",
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function trustDraft(capability) {
  const result = createTrustEvaluationDraft({
    requestId: "trust-draft-1",
    capabilityGrantDraft: capability,
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
    auditCorrelationId: "trust-draft-1",
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function metadataEvaluation(draft) {
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

function possessionDraft(metadata) {
  const result = createPossessionVerificationRequestDraft({
    requestId: "possession-draft-1",
    publicTrustMetadataEvaluation: metadata,
    auditCorrelationId: "possession-draft-1",
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function fixtureArtifact(draft) {
  return Object.freeze({
    artifactId: "fixture-artifact-1",
    requestId: "fixture-request-1",
    possessionVerificationRequestDraftId: draft.possessionVerificationRequestDraftId,
    publicTrustMetadataEvaluationId: draft.publicTrustMetadataEvaluationId,
    trustEvaluationDraftId: draft.trustEvaluationDraftId,
    applicationId: draft.applicationId,
    sessionId: draft.sessionId,
    credentialId: draft.credentialId,
    deviceId: draft.deviceId,
    fixtureId: "fixture-1",
    verifierKind: "webauthn-es256-spki-assertion-verifier-v1",
    status: "fixture_verified",
    outcome: "fixture_verified",
    reasons: ["possession-verification-draft-valid", "fixture-input-valid"],
    challengeMatched: true,
    originMatched: true,
    rpIdHashMatched: true,
    userPresent: true,
    userVerified: true,
    signatureVerified: true,
    counterStatus: "advanced",
    previousSignCount: 6,
    newSignCount: 7,
    counterPersisted: false,
    verificationErrors: [],
    verificationWarnings: [],
    verifiedAt: "2026-07-10T00:00:00.000Z",
    auditCorrelationId: "fixture-artifact-1",
    fixtureOnly: true,
    productionAuthentication: false,
    authenticatesUser: false,
    verifiesProductionPossession: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });
}

function possessionEvaluation(draft) {
  const result = createPossessionEvaluationResultFromWebAuthnFixture({
    requestId: "possession-evaluation-request-1",
    possessionVerificationRequestDraft: draft,
    webAuthnFixtureVerificationArtifact: fixtureArtifact(draft),
    auditCorrelationId: "possession-evaluation-1"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function evidence(overrides = {}) {
  const capability = capabilityDraft(overrides.capability ?? {});
  const trust = trustDraft(capability);
  const metadata = metadataEvaluation(trust);
  const possession = possessionEvaluation(possessionDraft(metadata));
  const boundedTrust = evaluateBoundedTrustEvidence({
    requestId: "bounded-trust-request-1",
    trustEvaluationDraft: trust,
    publicTrustMetadataEvaluation: metadata,
    possessionEvaluationResult: possession,
    credentialLifecycleStatus: overrides.credentialLifecycleStatus ?? "active",
    evaluationContext: overrides.evaluationContext,
    auditCorrelationId: "bounded-trust-1"
  });
  assert.equal(boundedTrust.status, "approved");
  return {
    capability,
    boundedTrust: overrides.boundedTrustOverride ?? boundedTrust.value
  };
}

function policyBundle(overrides = {}) {
  const built = overrides.evidence ?? evidence(overrides.evidenceOptions ?? {});
  const result = evaluateBoundedRuntimePolicy({
    requestId: "bounded-policy-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    policySet: {
      policySetId: "policy-set-1",
      rules: overrides.rules ?? [{
        ruleId: "require-user",
        type: "require_user_approval",
        effect: "require_user_approval"
      }]
    },
    context: {
      applicationId: built.capability.applicationId,
      sessionId: built.capability.sessionId,
      sessionStatus: "unlocked",
      policyMode: "default",
      action: overrides.actionContext
    },
    actionContext: overrides.actionContext,
    auditCorrelationId: "bounded-policy-1"
  });
  assert.equal(result.status, "approved");
  return {
    capability: built.capability,
    boundedTrust: built.boundedTrust,
    boundedPolicy: overrides.boundedPolicyOverride ?? result.value
  };
}

function approvalBundle(overrides = {}) {
  const built = overrides.policyBundle ?? policyBundle(overrides.policyOptions ?? {});
  const approvalResult = createUserApprovalRequestDraft({
    requestId: "approval-draft-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    boundedPolicyEvaluationResult: built.boundedPolicy,
    approvalSurface: "developer_fixture",
    requestedScope: overrides.requestedScope,
    effectiveScope: overrides.effectiveScope,
    requestedDurationSeconds: overrides.requestedDurationSeconds,
    effectiveDurationSeconds: overrides.effectiveDurationSeconds,
    auditCorrelationId: "approval-draft-1",
    expiresAt: overrides.approvalExpiresAt
  });
  assert.equal(approvalResult.status, "approved");
  const fixtureResult = createUserDecisionFixtureArtifact({
    requestId: "decision-fixture-approve",
    userApprovalRequestDraft: approvalResult.value,
    boundedPolicyEvaluationResult: built.boundedPolicy,
    boundedTrustEvaluationResult: built.boundedTrust,
    capabilityGrantDraft: built.capability,
    outcome: overrides.fixtureOutcome ?? "approve",
    auditCorrelationId: overrides.fixtureAuditCorrelationId ?? "decision-fixture-1",
    recordedAt: overrides.recordedAt ?? "2026-07-10T00:00:00.000Z"
  });
  assert.equal(fixtureResult.status, "approved");
  return {
    ...built,
    approval: overrides.approvalOverride ?? approvalResult.value,
    fixture: overrides.fixtureOverride ?? fixtureResult.value
  };
}

function candidateRequest(overrides = {}) {
  const built = overrides.bundle ?? approvalBundle(overrides.approvalOptions ?? {});
  return {
    requestId: overrides.requestId ?? "activation-candidate-request-1",
    capabilityGrantDraft: overrides.capability ?? built.capability,
    boundedTrustEvaluationResult: overrides.boundedTrust ?? built.boundedTrust,
    boundedPolicyEvaluationResult: overrides.boundedPolicy ?? built.boundedPolicy,
    userApprovalRequestDraft: overrides.approval ?? built.approval,
    userDecisionFixtureArtifact: overrides.fixture ?? built.fixture,
    applicationId: overrides.applicationId,
    sessionId: overrides.sessionId,
    ownerCommitment: overrides.ownerCommitment,
    capabilityName: overrides.capabilityName,
    requestedScope: overrides.requestedScope,
    effectiveScope: overrides.effectiveScope,
    requestedDurationSeconds: overrides.requestedDurationSeconds,
    effectiveDurationSeconds: overrides.effectiveDurationSeconds,
    auditCorrelationId: overrides.auditCorrelationId,
    createdAt: overrides.createdAt ?? "2026-07-10T00:00:00.000Z",
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  };
}

function assertCandidateOnly(candidate) {
  assert.equal(candidate.fixtureOnlyUserDecision, true);
  assert.equal(candidate.productionUserConsentCollected, false);
  assert.equal(candidate.productionAuthenticationPerformed, false);
  assert.equal(candidate.grantsAuthority, false);
  assert.equal(candidate.activeCapabilityCreated, false);
  assert.equal(candidate.createsCapabilityGrant, false);
  assert.equal(candidate.sessionKeyIssued, false);
  assert.equal(candidate.authorizationCreated, false);
  assert.equal(candidate.createsAuthorizationPackage, false);
  assert.equal(candidate.allowsExecution, false);
  assert.equal(candidate.worldIdEnrollmentVerified, false);
  assert.equal(candidate.persisted, false);
}

describe("PhilCore non-authoritative capability activation candidates", function () {
  it("creates a candidate from a fully correlated approve fixture", function () {
    const result = createCapabilityActivationCandidate(candidateRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "pending_production_consent");
    assert.equal(result.value.outcome, "pending_production_consent");
    assert.equal(result.value.evidence.fixtureOnlyUserDecision, true);
    assert.ok(result.value.limitations.includes("no_capability_grant"));
    assert.ok(result.value.limitations.includes("no_authorization"));
    assert.ok(result.value.reasons.includes("fixture-approval-not-production-consent"));
    assertCandidateOnly(result.value);
  });

  it("does not create candidates for deny, cancel, or expired fixture outcomes", function () {
    for (const fixtureOutcome of ["deny", "cancel"]) {
      const built = approvalBundle({ fixtureOutcome });
      const result = createCapabilityActivationCandidate(candidateRequest({ bundle: built }));
      assert.equal(result.status, "denied");
    }
    const built = approvalBundle();
    const expiredFixture = Object.freeze({
      ...built.fixture,
      outcome: "expired",
      status: "expired"
    });
    const expired = createCapabilityActivationCandidate(candidateRequest({
      bundle: built,
      fixture: expiredFixture
    }));
    assert.equal(expired.status, "denied");
  });

  it("rejects policy denial and unresolved stronger Trust", function () {
    const deniedBundle = approvalBundle();
    const deniedPolicy = Object.freeze({
      ...deniedBundle.boundedPolicy,
      outcome: "denied_by_policy",
      eligibleForUserApproval: false
    });
    const strongerTrustPolicy = Object.freeze({
      ...deniedBundle.boundedPolicy,
      outcome: "eligible_for_user_approval",
      requirementSummary: {
        ...deniedBundle.boundedPolicy.requirementSummary,
        requiresStrongerTrust: true
      },
      resolutionRequirements: Object.freeze([
        ...deniedBundle.boundedPolicy.resolutionRequirements,
        "stronger_trust"
      ])
    });

    assert.equal(createCapabilityActivationCandidate(candidateRequest({
      bundle: deniedBundle,
      boundedPolicy: deniedPolicy
    })).status, "denied");
    assert.equal(createCapabilityActivationCandidate(candidateRequest({
      bundle: deniedBundle,
      boundedPolicy: strongerTrustPolicy
    })).status, "denied");
  });

  it("preserves pending production possession requirements when explicitly present on eligible policy", function () {
    const built = approvalBundle();
    const policy = Object.freeze({
      ...built.boundedPolicy,
      requirementSummary: {
        ...built.boundedPolicy.requirementSummary,
        requiresProductionPossessionVerification: true
      },
      resolutionRequirements: Object.freeze([
        ...built.boundedPolicy.resolutionRequirements,
        "production_possession_verification"
      ])
    });
    const result = createCapabilityActivationCandidate(candidateRequest({
      bundle: built,
      boundedPolicy: policy
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "pending_production_authentication");
    assert.ok(result.value.reasons.includes("pending-production-authentication"));
    assertCandidateOnly(result.value);
  });

  it("blocks canonical activation with unresolved World ID while ordinary runtime does not require it automatically", function () {
    const ordinary = createCapabilityActivationCandidate(candidateRequest());
    const built = approvalBundle();
    const canonicalTrust = Object.freeze({
      ...built.boundedTrust,
      evaluationContext: "canonical_phil_activation",
      requiresWorldIdEnrollment: true
    });

    assert.equal(ordinary.status, "approved");
    assert.equal(createCapabilityActivationCandidate(candidateRequest({
      bundle: built,
      boundedTrust: canonicalTrust
    })).status, "denied");
  });

  it("preserves scope and duration restrictions from approval and policy artifacts", function () {
    const built = approvalBundle({
      requestedScope: { chainId: 8453, maxValue: "1" },
      effectiveScope: { chainId: 8453, maxValue: "0.1" },
      requestedDurationSeconds: 3600,
      effectiveDurationSeconds: 300
    });
    const policy = Object.freeze({
      ...built.boundedPolicy,
      requirementSummary: {
        ...built.boundedPolicy.requirementSummary,
        requiresScopeRestriction: true,
        requiresDurationRestriction: true
      },
      resolutionRequirements: Object.freeze([
        ...built.boundedPolicy.resolutionRequirements,
        "scope_restriction",
        "duration_restriction"
      ])
    });
    const result = createCapabilityActivationCandidate(candidateRequest({
      bundle: built,
      boundedPolicy: policy
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.scope.scopeRestricted, true);
    assert.equal(result.value.duration.durationRestricted, true);
    assert.equal(result.value.scope.effectiveScope.maxValue, "0.1");
    assert.equal(result.value.duration.effectiveDurationSeconds, 300);
  });

  it("rejects application, session, owner, capability, and audit correlation mismatches", function () {
    const built = approvalBundle();
    const cases = [
      { applicationId: "wrong-app" },
      { sessionId: "wrong-session" },
      { ownerCommitment: "0xwrong" },
      { capabilityName: "request_contract_call" },
      { auditCorrelationId: "wrong-audit-correlation" }
    ];

    for (const mismatch of cases) {
      assert.equal(createCapabilityActivationCandidate(candidateRequest({
        bundle: built,
        ...mismatch
      })).status, "denied");
    }
  });

  it("rejects secret metadata and active-authority-shaped candidate objects", function () {
    const secret = createCapabilityActivationCandidate(candidateRequest({
      metadata: {
        phil_secret: "never"
      }
    }));
    const valid = createCapabilityActivationCandidate(candidateRequest()).value;
    const authorityShaped = validateCapabilityActivationCandidateShape({
      ...valid,
      activeCapabilityCreated: true,
      sessionKey: "nope",
      authorizationPackage: {}
    });

    assert.equal(secret.status, "denied");
    assert.equal(authorityShaped.valid, false);
  });

  it("rejects secret candidate metadata beyond the default traversal depth", function () {
    const result = createCapabilityActivationCandidate(candidateRequest({
      metadata: {
        a: [{ b: [{ c: { password: "CAPABILITY-DEPTH-CANARY" } }] }]
      }
    }));

    assert.equal(result.status, "denied");
    assert.equal(JSON.stringify(result).includes("CAPABILITY-DEPTH-CANARY"), false);
  });

  it("integrates with the validation-only facade and optional collectors", function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const candidateCollector = createInMemoryCapabilityActivationCandidateCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      capabilityActivationCandidateCollector: candidateCollector
    });
    const result = api.requestCapabilityActivationCandidate(candidateRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.capabilityActivationCandidate.status, "pending_production_consent");
    assert.equal(result.value.capabilityActivationCandidateCollectionResult.status, "collected");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(candidateCollector.count(), 1);
    assert.equal(auditCollector.count(), 1);
    assert.equal(
      result.value.auditEventDraft.redactedDetails.capabilityActivationCandidateActiveCapabilityCreated,
      false
    );
    assertCandidateOnly(result.value.capabilityActivationCandidate);
  });

  it("keeps the candidate collector ephemeral, bounded, duplicate-safe, and read-only", function () {
    const collector = createInMemoryCapabilityActivationCandidateCollector({
      maxCandidateCount: 1
    });
    const first = createCapabilityActivationCandidate(candidateRequest({
      auditCorrelationId: "decision-fixture-1"
    })).value;
    const duplicate = collector.addCandidate(first);
    const duplicateAgain = collector.addCandidate(first);
    const second = createCapabilityActivationCandidate(candidateRequest({
      bundle: approvalBundle({ fixtureAuditCorrelationId: "decision-fixture-2" }),
      auditCorrelationId: "decision-fixture-2"
    })).value;
    const evicted = collector.addCandidate(second);
    const invalid = collector.addCandidate({
      ...second,
      capabilityActivationCandidateId: "invalid",
      activeCapabilityCreated: true
    });

    assert.equal(duplicate.status, "collected");
    assert.equal(duplicateAgain.status, "rejected_duplicate");
    assert.equal(evicted.status, "evicted_oldest");
    assert.equal(evicted.evictedCandidates[0].capabilityActivationCandidateId, first.capabilityActivationCandidateId);
    assert.equal(invalid.status, "rejected_invalid");
    assert.equal(collector.count(), 1);
    assert.equal(collector.filter({ status: "pending_production_consent" }).length, 1);
    assert.equal(collector.query({ filter: { applicationId: "ethereum-net" } }).length, 1);
    assert.throws(() => {
      collector.getAll().push(first);
    });
  });
});
