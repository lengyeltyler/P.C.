const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryUserDecisionFixtureArtifactCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createUserApprovalRequestDraft,
  createUserDecisionFixtureArtifact,
  createValidationOnlyRuntimeApi,
  evaluateBoundedRuntimePolicy,
  evaluateBoundedTrustEvidence,
  evaluatePublicTrustMetadata,
  validateUserDecisionFixtureArtifactShape
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

function evidence() {
  const capability = capabilityDraft();
  const trust = trustDraft(capability);
  const metadata = metadataEvaluation(trust);
  const possession = possessionEvaluation(possessionDraft(metadata));
  const boundedTrust = evaluateBoundedTrustEvidence({
    requestId: "bounded-trust-request-1",
    trustEvaluationDraft: trust,
    publicTrustMetadataEvaluation: metadata,
    possessionEvaluationResult: possession,
    credentialLifecycleStatus: "active",
    auditCorrelationId: "bounded-trust-1"
  });
  assert.equal(boundedTrust.status, "approved");
  return {
    capability,
    boundedTrust: boundedTrust.value
  };
}

function policyBundle() {
  const built = evidence();
  const result = evaluateBoundedRuntimePolicy({
    requestId: "bounded-policy-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    policySet: {
      policySetId: "policy-set-1",
      rules: [{
        ruleId: "require-user",
        type: "require_user_approval",
        effect: "require_user_approval"
      }]
    },
    context: {
      applicationId: built.capability.applicationId,
      sessionId: built.capability.sessionId,
      sessionStatus: "unlocked",
      policyMode: "default"
    },
    auditCorrelationId: "bounded-policy-1"
  });
  assert.equal(result.status, "approved");
  return {
    capability: built.capability,
    boundedTrust: built.boundedTrust,
    boundedPolicy: result.value
  };
}

function approvalBundle(overrides = {}) {
  const built = policyBundle();
  const result = createUserApprovalRequestDraft({
    requestId: "approval-draft-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    boundedPolicyEvaluationResult: built.boundedPolicy,
    approvalSurface: "developer_fixture",
    expiresAt: overrides.expiresAt,
    auditCorrelationId: overrides.auditCorrelationId ?? "approval-draft-1"
  });
  assert.equal(result.status, "approved");
  return {
    ...built,
    approval: overrides.approvalOverride ?? result.value
  };
}

function decisionRequest(outcome, overrides = {}) {
  const built = overrides.bundle ?? approvalBundle(overrides.approvalOverrides ?? {});
  return {
    requestId: overrides.requestId ?? `decision-fixture-${outcome}`,
    userApprovalRequestDraft: overrides.approval ?? built.approval,
    boundedPolicyEvaluationResult: overrides.boundedPolicy ?? built.boundedPolicy,
    boundedTrustEvaluationResult: overrides.boundedTrust ?? built.boundedTrust,
    capabilityGrantDraft: overrides.capability ?? built.capability,
    outcome,
    source: overrides.source,
    applicationId: overrides.applicationId,
    sessionId: overrides.sessionId,
    ownerCommitment: overrides.ownerCommitment,
    auditCorrelationId: overrides.auditCorrelationId,
    recordedAt: overrides.recordedAt ?? "2026-07-10T00:00:00.000Z",
    metadata: overrides.metadata
  };
}

function assertFixtureOnly(artifact) {
  assert.equal(artifact.fixtureOnly, true);
  assert.equal(artifact.productionUserConsentCollected, false);
  assert.equal(artifact.authenticationPerformed, false);
  assert.equal(artifact.biometricVerificationPerformed, false);
  assert.equal(artifact.webauthnPerformed, false);
  assert.equal(artifact.grantsAuthority, false);
  assert.equal(artifact.createsCapabilityGrant, false);
  assert.equal(artifact.createsAuthorization, false);
  assert.equal(artifact.createsAuthorizationPackage, false);
  assert.equal(artifact.allowsExecution, false);
  assert.equal(artifact.worldIdVerified, false);
  assert.equal(artifact.persisted, false);
}

describe("PhilCore user decision fixture artifacts", function () {
  it("records an approve fixture without creating production consent or authority", function () {
    const result = createUserDecisionFixtureArtifact(decisionRequest("approve"));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "approve");
    assert.equal(result.value.status, "fixture_recorded");
    assert.equal(result.value.source, "developer_fixture");
    assert.ok(result.value.reasons.includes("fixture-approval-not-production-consent"));
    assertFixtureOnly(result.value);
  });

  it("records deny and cancel fixtures against pending approval drafts", function () {
    const deny = createUserDecisionFixtureArtifact(decisionRequest("deny"));
    const cancel = createUserDecisionFixtureArtifact(decisionRequest("cancel"));

    assert.equal(deny.status, "approved");
    assert.equal(deny.value.outcome, "deny");
    assert.equal(cancel.status, "approved");
    assert.equal(cancel.value.outcome, "cancel");
    assertFixtureOnly(deny.value);
    assertFixtureOnly(cancel.value);
  });

  it("records expired only when the approval draft is actually expired", function () {
    const built = approvalBundle();
    const expiredApproval = Object.freeze({
      ...built.approval,
      expiresAt: "2026-07-09T00:00:00.000Z"
    });
    const expired = createUserDecisionFixtureArtifact(decisionRequest("expired", {
      bundle: built,
      approval: expiredApproval,
      recordedAt: "2026-07-10T00:00:00.000Z"
    }));
    const arbitraryExpired = createUserDecisionFixtureArtifact(decisionRequest("expired", {
      recordedAt: "2026-07-10T00:00:00.000Z"
    }));

    assert.equal(expired.status, "approved");
    assert.equal(expired.value.status, "expired");
    assert.ok(expired.value.reasons.includes("draft-expired"));
    assert.equal(arbitraryExpired.status, "denied");
  });

  it("rejects active approve fixtures against expired approval drafts", function () {
    const built = approvalBundle();
    const expiredApproval = Object.freeze({
      ...built.approval,
      expiresAt: "2026-07-09T00:00:00.000Z"
    });
    const result = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      bundle: built,
      approval: expiredApproval,
      recordedAt: "2026-07-10T00:00:00.000Z"
    }));

    assert.equal(result.status, "denied");
    assert.match(result.error.message, /validation/);
  });

  it("rejects malformed, unsupported, and mismatched fixture requests", function () {
    const built = approvalBundle();
    const appMismatch = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      bundle: built,
      applicationId: "wrong-app"
    }));
    const ownerMismatch = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      bundle: built,
      ownerCommitment: "0xwrong"
    }));
    const correlationMismatch = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      bundle: built,
      boundedPolicy: Object.freeze({
        ...built.boundedPolicy,
        capabilityGrantDraftId: "wrong-capability-draft"
      })
    }));
    const unsupported = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      bundle: built,
      source: "unsupported"
    }));
    const malformed = createUserDecisionFixtureArtifact({
      requestId: "",
      outcome: "approve"
    });

    assert.equal(appMismatch.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(correlationMismatch.status, "denied");
    assert.equal(unsupported.status, "denied");
    assert.equal(malformed.status, "denied");
  });

  it("rejects secret-shaped metadata and authority-shaped fixture artifacts", function () {
    const secret = createUserDecisionFixtureArtifact(decisionRequest("approve", {
      metadata: {
        phil_secret: "never"
      }
    }));
    const valid = createUserDecisionFixtureArtifact(decisionRequest("approve"));
    const authorityShaped = validateUserDecisionFixtureArtifactShape({
      ...valid.value,
      grantsAuthority: true,
      authorizationPackage: {
        id: "nope"
      }
    });

    assert.equal(secret.status, "denied");
    assert.equal(authorityShaped.valid, false);
  });

  it("integrates with the validation-only facade and audit collector", function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const fixtureCollector = createInMemoryUserDecisionFixtureArtifactCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      userDecisionFixtureArtifactCollector: fixtureCollector
    });
    const result = api.requestUserDecisionFixture(decisionRequest("approve"));

    assert.equal(result.status, "approved");
    assert.equal(result.value.userDecisionFixtureArtifact.outcome, "approve");
    assert.equal(result.value.userDecisionFixtureArtifactCollectionResult.status, "collected");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(fixtureCollector.count(), 1);
    assert.equal(auditCollector.count(), 1);
    assert.equal(result.value.auditEventDraft.persisted, false);
    assert.equal(
      result.value.auditEventDraft.redactedDetails.userDecisionFixtureGrantsAuthority,
      false
    );
  });

  it("keeps the fixture collector ephemeral, bounded, duplicate-safe, and read-only", function () {
    const collector = createInMemoryUserDecisionFixtureArtifactCollector({
      maxArtifactCount: 1
    });
    const first = createUserDecisionFixtureArtifact(decisionRequest("deny", {
      auditCorrelationId: "fixture-one"
    })).value;
    const duplicate = collector.addArtifact(first);
    const duplicateAgain = collector.addArtifact(first);
    const second = createUserDecisionFixtureArtifact(decisionRequest("cancel", {
      auditCorrelationId: "fixture-two"
    })).value;
    const evicted = collector.addArtifact(second);
    const invalid = collector.addArtifact({
      ...second,
      userDecisionFixtureArtifactId: "invalid",
      productionUserConsentCollected: true
    });

    assert.equal(duplicate.status, "collected");
    assert.equal(duplicateAgain.status, "rejected_duplicate");
    assert.equal(evicted.status, "evicted_oldest");
    assert.equal(evicted.evictedArtifacts[0].userDecisionFixtureArtifactId, first.userDecisionFixtureArtifactId);
    assert.equal(invalid.status, "rejected_invalid");
    assert.equal(collector.count(), 1);
    assert.equal(collector.filter({ outcome: "cancel" }).length, 1);
    assert.equal(collector.query({ filter: { source: "developer_fixture" } }).length, 1);
    assert.throws(() => {
      collector.getAll().push(first);
    });
  });
});
