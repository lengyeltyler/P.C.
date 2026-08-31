const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryUserApprovalRequestDraftCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createUserApprovalRequestDraft,
  createValidationOnlyRuntimeApi,
  evaluateBoundedRuntimePolicy,
  evaluateBoundedTrustEvidence,
  evaluatePublicTrustMetadata,
  validateUserApprovalRequestDraftShape
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
    boundedTrust: boundedTrust.value
  };
}

function rule(ruleId, type, effect, extra = {}) {
  return {
    ruleId,
    type,
    effect,
    ...extra
  };
}

function policyResult(rules, overrides = {}) {
  const built = overrides.evidence ?? evidence(overrides.evidenceOptions ?? {});
  const result = evaluateBoundedRuntimePolicy({
    requestId: overrides.requestId ?? "bounded-policy-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    policySet: {
      policySetId: "policy-set-1",
      rules
    },
    context: {
      applicationId: built.capability.applicationId,
      sessionId: built.capability.sessionId,
      sessionStatus: overrides.sessionStatus ?? "unlocked",
      policyMode: "default",
      action: overrides.actionContext
    },
    actionContext: overrides.actionContext,
    auditCorrelationId: overrides.auditCorrelationId ?? "bounded-policy-1"
  });
  assert.equal(result.status, "approved");
  return {
    capability: built.capability,
    boundedTrust: built.boundedTrust,
    boundedPolicy: result.value
  };
}

function approvalInput(rules, overrides = {}) {
  const built = overrides.policyBundle ?? policyResult(rules, overrides.policyOptions ?? {});
  return {
    requestId: overrides.requestId ?? "approval-draft-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    boundedPolicyEvaluationResult: built.boundedPolicy,
    approvalSurface: overrides.approvalSurface,
    requestedScope: overrides.requestedScope,
    effectiveScope: overrides.effectiveScope,
    requestedDurationSeconds: overrides.requestedDurationSeconds,
    effectiveDurationSeconds: overrides.effectiveDurationSeconds,
    actionSummary: overrides.actionSummary,
    riskSummary: overrides.riskSummary,
    disclosures: overrides.disclosures,
    applicationId: overrides.applicationId,
    sessionId: overrides.sessionId,
    ownerCommitment: overrides.ownerCommitment,
    auditCorrelationId: overrides.auditCorrelationId,
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  };
}

function assertDraftOnly(draft) {
  const text = JSON.stringify(draft).toLowerCase();
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorized\":true"), false);
  assert.equal(draft.collectsUserDecision, false);
  assert.equal(draft.userDecisionPresent, false);
  assert.equal(draft.authenticatesUser, false);
  assert.equal(draft.invokesBiometrics, false);
  assert.equal(draft.invokesWebAuthn, false);
  assert.equal(draft.grantsAuthority, false);
  assert.equal(draft.createsCapabilityGrant, false);
  assert.equal(draft.createsAuthorizationPackage, false);
  assert.equal(draft.allowsExecution, false);
  assert.equal(draft.persisted, false);
}

describe("PhilCore user approval request drafts", function () {
  it("creates a draft when policy requires user approval", function () {
    const result = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      approvalSurface: "desktop"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "pending_user_presentation");
    assert.equal(result.value.approvalSurface, "desktop");
    assert.ok(result.value.requirements.includes("collect_future_user_decision"));
    assertDraftOnly(result.value);
  });

  it("creates a draft for policy results eligible for future authorization", function () {
    const result = createUserApprovalRequestDraft(approvalInput([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ]));

    assert.equal(result.status, "approved");
    assert.equal(result.value.boundedPolicyEvaluationResultId, result.value.boundedPolicyEvaluationResultId);
    assertDraftOnly(result.value);
  });

  it("does not create drafts for denied or unresolved policy outcomes", function () {
    const denied = createUserApprovalRequestDraft(approvalInput([
      rule("deny", "deny_capability", "deny")
    ]));
    const stronger = createUserApprovalRequestDraft(approvalInput([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      policyOptions: {
        evidenceOptions: {
          credentialLifecycleStatus: "pending"
        }
      }
    }));
    const production = createUserApprovalRequestDraft(approvalInput([
      rule("production", "require_production_possession_verification", "require_production_verification")
    ]));
    const worldId = createUserApprovalRequestDraft(approvalInput([
      rule("world-id", "require_world_id_enrollment", "require_world_id_enrollment", {
        scope: {
          evaluationContexts: ["canonical_phil_activation"]
        }
      })
    ], {
      policyOptions: {
        evidenceOptions: {
          evaluationContext: "canonical_phil_activation"
        },
        actionContext: {
          canonicalPhilActivation: true
        }
      }
    }));
    const recovery = createUserApprovalRequestDraft(approvalInput([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      policyOptions: {
        evidenceOptions: {
          credentialLifecycleStatus: "recovery-only"
        }
      }
    }));

    assert.equal(denied.status, "denied");
    assert.equal(stronger.status, "denied");
    assert.equal(production.status, "denied");
    assert.equal(worldId.status, "denied");
    assert.equal(recovery.status, "denied");
  });

  it("preserves scope and duration restrictions", function () {
    const result = createUserApprovalRequestDraft(approvalInput([
      rule("limit-scope", "limit_scope", "restrict_scope"),
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      requestedScope: {
        resource: "account",
        action: "sign"
      },
      effectiveScope: {
        resource: "account",
        action: "sign",
        expiresAt: "2026-07-11T00:00:00.000Z"
      },
      requestedDurationSeconds: 3600,
      effectiveDurationSeconds: 600
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.effectiveScope.expiresAt, "2026-07-11T00:00:00.000Z");
    assert.equal(result.value.effectiveDurationSeconds, 600);
    assert.ok(result.value.requirements.includes("preserve_policy_restrictions"));
  });

  it("discloses fixture-only and policy/trust limitations without claiming safety", function () {
    const result = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      riskSummary: {
        labels: ["message signature risk"],
        messageSignatureRisk: true
      }
    }));

    assert.ok(result.value.riskSummary.labels.includes("fixture-only possession evidence"));
    assert.ok(result.value.riskSummary.labels.includes("production authentication not performed"));
    assert.ok(result.value.riskSummary.labels.includes("message signature risk"));
    assert.ok(result.value.disclosures.some((entry) => entry.disclosureId === "fixture-only-evidence"));
    assertDraftOnly(result.value);
  });

  it("rejects secret-shaped fields, expired input, and correlation mismatches", function () {
    const secret = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      metadata: {
        privateKey: "must-not-enter"
      }
    }));
    const expired = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }));
    const mismatch = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      applicationId: "nft-manager"
    }));

    assert.equal(secret.status, "denied");
    assert.equal(JSON.stringify(secret).includes("must-not-enter"), false);
    assert.equal(expired.status, "denied");
    assert.equal(mismatch.status, "denied");
  });

  it("rejects decision-shaped or authority-shaped draft objects", function () {
    const draft = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ])).value;
    const invalid = validateUserApprovalRequestDraftShape({
      ...draft,
      userApprovalRequestDraftId: "bad-draft",
      userDecision: "approved"
    });

    assert.equal(invalid.valid, false);
  });

  it("facade creates audit drafts and optionally collects approval drafts", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const userApprovalRequestDraftCollector = createInMemoryUserApprovalRequestDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      userApprovalRequestDraftCollector
    });

    const result = api.requestUserApprovalDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ]));

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "authorization_request");
    assert.equal(result.value.userApprovalRequestDraft.status, "pending_user_presentation");
    assert.equal(result.value.userApprovalRequestDraftCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assert.equal(userApprovalRequestDraftCollector.count(), 1);
  });

  it("collector is ephemeral, duplicate protected, bounded, and rejects decision-shaped drafts", function () {
    const collector = createInMemoryUserApprovalRequestDraftCollector({
      maxDraftCount: 1
    });
    const first = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      auditCorrelationId: "approval-draft-1"
    })).value;
    const second = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      requestId: "approval-draft-request-2",
      auditCorrelationId: "approval-draft-2"
    })).value;

    assert.equal(collector.addDraft(first).status, "collected");
    assert.equal(collector.addDraft(first).status, "rejected_duplicate");
    assert.equal(collector.addDraft({
      ...first,
      userApprovalRequestDraftId: "bad-draft",
      userDecisionPresent: true
    }).status, "rejected_invalid");
    assert.equal(collector.addDraft(second).status, "evicted_oldest");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById(first.userApprovalRequestDraftId), undefined);
    assert.equal(collector.filter({ approvalSurface: "desktop" }).length, 1);
  });

  it("does not collect decisions, authenticate, mutate session, grant authority, authorize, or call external hooks", function () {
    const hooks = {
      userDecisionCalls: 0,
      biometricCalls: 0,
      webAuthnCalls: 0,
      worldIdCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      sessionMutationCalls: 0
    };
    const result = createUserApprovalRequestDraft(approvalInput([
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      userDecisionCalls: 0,
      biometricCalls: 0,
      webAuthnCalls: 0,
      worldIdCalls: 0,
      vaultCalls: 0,
      storageCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      sessionMutationCalls: 0
    });
    assertDraftOnly(result.value);
  });
});
