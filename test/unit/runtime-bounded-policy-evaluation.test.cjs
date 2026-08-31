const assert = require("node:assert/strict");

const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createInMemoryAuditDraftCollector,
  createInMemoryBoundedPolicyEvaluationResultCollector,
  createPossessionEvaluationResultFromWebAuthnFixture,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createValidationOnlyRuntimeApi,
  evaluateBoundedRuntimePolicy,
  evaluateBoundedTrustEvidence,
  evaluatePublicTrustMetadata,
  validateBoundedPolicyEvaluationResultShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function capabilityDraft(overrides = {}) {
  const result = createCapabilityGrantDraft({
    capabilityRequest: createCapabilityRequestDraft({
      requestId: overrides.requestId ?? "capability-request-1",
      applicationId: overrides.applicationId ?? "ethereum-net",
      capability: overrides.capability ?? "request_message_signature",
      sensitivity: overrides.sensitivity ?? "sensitive",
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

function trustDraft(capability = capabilityDraft(), overrides = {}) {
  const result = createTrustEvaluationDraft({
    requestId: overrides.requestId ?? "trust-draft-1",
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
    auditCorrelationId: overrides.auditCorrelationId ?? "trust-draft-1",
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

function bundle(overrides = {}) {
  const capability = overrides.capabilityGrantDraft ?? capabilityDraft(overrides.capability ?? {});
  const trust = trustDraft(capability);
  const metadata = metadataEvaluation(trust);
  const possession = possessionEvaluation(possessionDraft(metadata));
  const boundedTrust = evaluateBoundedTrustEvidence({
    requestId: overrides.trustRequestId ?? "bounded-trust-request-1",
    trustEvaluationDraft: trust,
    publicTrustMetadataEvaluation: metadata,
    possessionEvaluationResult: possession,
    credentialLifecycleStatus: overrides.credentialLifecycleStatus ?? "active",
    evaluationContext: overrides.evaluationContext,
    auditCorrelationId: overrides.trustAuditCorrelationId ?? "bounded-trust-1"
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

function policySet(rules, overrides = {}) {
  return {
    policySetId: overrides.policySetId ?? "policy-set-1",
    version: "policy-v1",
    rules,
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  };
}

function request(rules, overrides = {}) {
  const built = overrides.bundle ?? bundle(overrides.bundleOptions ?? {});
  return {
    requestId: overrides.requestId ?? "bounded-policy-request-1",
    capabilityGrantDraft: built.capability,
    boundedTrustEvaluationResult: built.boundedTrust,
    policySet: policySet(rules, overrides.policySet ?? {}),
    context: {
      applicationId: overrides.applicationId ?? built.capability.applicationId,
      sessionId: overrides.sessionId ?? built.capability.sessionId,
      sessionStatus: overrides.sessionStatus ?? "unlocked",
      policyMode: overrides.policyMode ?? "default",
      evaluationContext: overrides.evaluationContext,
      action: overrides.actionContext,
      metadata: overrides.contextMetadata
    },
    applicationId: overrides.applicationId,
    sessionId: overrides.sessionId,
    capabilityName: overrides.capabilityName,
    actionContext: overrides.actionContext,
    auditCorrelationId: overrides.auditCorrelationId,
    expiresAt: overrides.expiresAt,
    metadata: overrides.metadata
  };
}

function assertNonAuthoritative(result) {
  const text = JSON.stringify(result).toLowerCase();
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorized\":true"), false);
  assert.equal(text.includes("capabilitygrant"), true);
  assert.equal(result.policyRulesLoadedFromStorage, false);
  assert.equal(result.providesPolicyDecision, false);
  assert.equal(result.grantsAuthority, false);
  assert.equal(result.createsCapabilityGrant, false);
  assert.equal(result.createsAuthorizationPackage, false);
  assert.equal(result.requestsUserApproval, false);
  assert.equal(result.productionAuthenticationPerformed, false);
  assert.equal(result.worldIdVerified, false);
  assert.equal(result.persisted, false);
}

describe("PhilCore bounded Security Policy evaluation", function () {
  it("classifies an eligible capability with sufficient bounded Trust evidence", function () {
    const result = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ]));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "eligible_for_future_authorization");
    assert.equal(result.value.eligibleForFutureAuthorization, true);
    assertNonAuthoritative(result.value);
  });

  it("applies explicit deny and deny precedence over allow", function () {
    const denied = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review"),
      rule("deny-message", "deny_capability", "deny")
    ]));

    assert.equal(denied.value.outcome, "denied_by_policy");
    assert.ok(denied.value.reasons.includes("deny-precedence"));
  });

  it("requires stronger Trust when bounded Trust is not eligible", function () {
    const built = bundle({
      credentialLifecycleStatus: "pending"
    });
    const result = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      bundle: built
    }));

    assert.equal(result.value.outcome, "requires_stronger_trust");
    assert.ok(result.value.resolutionRequirements.includes("stronger_trust"));
  });

  it("requires production possession verification and fixture evidence cannot satisfy it", function () {
    const result = evaluateBoundedRuntimePolicy(request([
      rule(
        "require-production-possession",
        "require_production_possession_verification",
        "require_production_verification"
      )
    ]));

    assert.equal(result.value.outcome, "requires_production_possession_verification");
    assert.ok(result.value.resolutionRequirements.includes("production_possession_verification"));
  });

  it("requires user approval without creating a user approval result", function () {
    const result = evaluateBoundedRuntimePolicy(request([
      rule("require-user", "require_user_approval", "require_user_approval")
    ]));

    assert.equal(result.value.outcome, "eligible_for_user_approval");
    assert.equal(result.value.eligibleForUserApproval, true);
    assert.equal(result.value.requestsUserApproval, false);
  });

  it("returns scope, duration, application, and session restrictions", function () {
    const scope = evaluateBoundedRuntimePolicy(request([
      rule("limit-scope", "limit_scope", "restrict_scope")
    ]));
    const duration = evaluateBoundedRuntimePolicy(request([
      rule("limit-duration", "limit_duration", "restrict_scope")
    ]));
    const app = evaluateBoundedRuntimePolicy(request([
      rule("restrict-app", "restrict_application", "restrict_scope")
    ]));
    const session = evaluateBoundedRuntimePolicy(request([
      rule("restrict-session", "restrict_session_state", "restrict_scope")
    ], {
      sessionStatus: "locked"
    }));

    assert.equal(scope.value.outcome, "scope_restricted");
    assert.equal(duration.value.outcome, "duration_restricted");
    assert.equal(app.value.outcome, "application_restricted");
    assert.equal(session.value.outcome, "session_state_ineligible");
  });

  it("handles recovery-only Trust evidence in ordinary and recovery contexts", function () {
    const ordinary = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      bundle: bundle({
        credentialLifecycleStatus: "recovery-only"
      })
    }));
    const recovery = evaluateBoundedRuntimePolicy(request([
      rule("recovery-only", "recovery_only", "allow_for_further_review"),
      rule("require-user", "require_user_approval", "require_user_approval")
    ], {
      bundle: bundle({
        credentialLifecycleStatus: "recovery-only",
        evaluationContext: "recovery"
      }),
      evaluationContext: "recovery"
    }));

    assert.equal(ordinary.value.outcome, "requires_recovery_context");
    assert.equal(recovery.value.outcome, "eligible_for_user_approval");
  });

  it("requires World ID only for canonical activation context, not ordinary runtime", function () {
    const ordinary = evaluateBoundedRuntimePolicy(request([
      rule("world-id", "require_world_id_enrollment", "require_world_id_enrollment", {
        scope: {
          evaluationContexts: ["canonical_phil_activation"]
        }
      }),
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ]));
    const canonical = evaluateBoundedRuntimePolicy(request([
      rule("world-id", "require_world_id_enrollment", "require_world_id_enrollment", {
        scope: {
          evaluationContexts: ["canonical_phil_activation"]
        }
      })
    ], {
      bundle: bundle({
        evaluationContext: "canonical_phil_activation"
      }),
      actionContext: {
        canonicalPhilActivation: true,
        humanUniquenessProviderKind: "development_fixture"
      }
    }));

    assert.equal(ordinary.value.outcome, "eligible_for_future_authorization");
    assert.equal(ordinary.value.worldIdVerified, false);
    assert.equal(canonical.value.outcome, "requires_world_id_enrollment");
    assert.equal(canonical.value.worldIdVerified, false);
  });

  it("rejects expired inputs, correlation mismatches, malformed rules, and secret metadata", function () {
    const expired = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }));
    const mismatch = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      applicationId: "nft-manager"
    }));
    const malformed = evaluateBoundedRuntimePolicy(request([
      { ruleId: "", type: "made_up", effect: "approve" }
    ]));
    const secret = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      metadata: {
        privateKey: "must-not-enter"
      }
    }));

    assert.equal(expired.status, "denied");
    assert.equal(mismatch.status, "denied");
    assert.equal(malformed.status, "denied");
    assert.equal(secret.status, "denied");
    assert.equal(JSON.stringify(secret).includes("must-not-enter"), false);
  });

  it("accepts a valid object-valued constraint on a bounded policy rule", function () {
    const result = evaluateBoundedRuntimePolicy(request([
      rule("limit-scope", "limit_scope", "restrict_scope", {
        constraints: [{ constraintId: "scope-1", kind: "scope", value: { action: "send_eth" } }]
      })
    ]));

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "scope_restricted");
  });

  it("rejects sensitive keys inside bounded policy-set metadata and object-valued constraint values within the policy inspection depth, and fails closed beyond it", function () {
    const policySetMetadataSecret = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      policySet: { metadata: { password: "BOUNDED-POLICY-SET-METADATA-SECRET" } }
    }));
    const constraintValueSecret = evaluateBoundedRuntimePolicy(request([
      rule("limit-scope", "limit_scope", "restrict_scope", {
        constraints: [{
          constraintId: "scope-1",
          kind: "scope",
          value: { password: "BOUNDED-CONSTRAINT-VALUE-SECRET" }
        }]
      })
    ]));
    const withinDepth = evaluateBoundedRuntimePolicy(request([
      rule("limit-scope", "limit_scope", "restrict_scope", {
        constraints: [{
          constraintId: "scope-1",
          kind: "scope",
          value: { a: { b: { c: { d: { password: "BOUNDED-WITHIN-DEPTH-SECRET" } } } } }
        }]
      })
    ]));
    const beyondDepth = evaluateBoundedRuntimePolicy(request([
      rule("limit-scope", "limit_scope", "restrict_scope", {
        constraints: [{
          constraintId: "scope-1",
          kind: "scope",
          value: { a: { b: { c: { d: { e: { password: "BOUNDED-BEYOND-DEPTH-SECRET" } } } } } }
        }]
      })
    ]));

    assert.equal(policySetMetadataSecret.status, "denied");
    assert.ok(
      policySetMetadataSecret.error.details.errors.some((error) =>
        error.includes("password") && error.includes("sensitive")),
      JSON.stringify(policySetMetadataSecret.error.details.errors)
    );
    assert.equal(
      JSON.stringify(policySetMetadataSecret).includes("BOUNDED-POLICY-SET-METADATA-SECRET"),
      false
    );

    assert.equal(constraintValueSecret.status, "denied");
    assert.ok(
      constraintValueSecret.error.details.errors.some((error) =>
        error.includes("password") && error.includes("sensitive")),
      JSON.stringify(constraintValueSecret.error.details.errors)
    );
    assert.equal(
      JSON.stringify(constraintValueSecret).includes("BOUNDED-CONSTRAINT-VALUE-SECRET"),
      false
    );

    assert.equal(withinDepth.status, "denied");
    assert.ok(
      withinDepth.error.details.errors.some((error) =>
        error.includes("password") && error.includes("sensitive")),
      JSON.stringify(withinDepth.error.details.errors)
    );
    assert.equal(JSON.stringify(withinDepth).includes("BOUNDED-WITHIN-DEPTH-SECRET"), false);

    assert.equal(beyondDepth.status, "denied");
    assert.ok(
      beyondDepth.error.details.errors.some((error) =>
        error.includes("maxDepth") || error.includes("traversal exceeded")),
      JSON.stringify(beyondDepth.error.details.errors)
    );
    assert.equal(JSON.stringify(beyondDepth).includes("BOUNDED-BEYOND-DEPTH-SECRET"), false);
  });

  it("handles unsupported rule effects as bounded unsupported results", function () {
    const result = evaluateBoundedRuntimePolicy(request([
      rule("experimental", "experimental_feature_required", "unsupported", {
        constraints: [{
          constraintId: "feature",
          kind: "custom",
          value: "future-feature"
        }]
      })
    ]));

    assert.equal(result.value.outcome, "unsupported");
  });

  it("facade creates audit drafts and optionally collects bounded policy results", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const boundedPolicyEvaluationResultCollector =
      createInMemoryBoundedPolicyEvaluationResultCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      boundedPolicyEvaluationResultCollector
    });

    const result = api.requestBoundedPolicyEvaluation(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ]));

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.category, "authorization_request");
    assert.equal(result.value.boundedPolicyEvaluationResult.outcome, "eligible_for_future_authorization");
    assert.equal(result.value.boundedPolicyEvaluationCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assert.equal(boundedPolicyEvaluationResultCollector.count(), 1);
  });

  it("collector is ephemeral, duplicate protected, bounded, and rejects authority-shaped results", function () {
    const collector = createInMemoryBoundedPolicyEvaluationResultCollector({
      maxResultCount: 1
    });
    const first = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      requestId: "policy-request-1",
      auditCorrelationId: "policy-result-1"
    })).value;
    const second = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      requestId: "policy-request-2",
      auditCorrelationId: "policy-result-2"
    })).value;

    assert.equal(collector.addResult(first).status, "collected");
    assert.equal(collector.addResult(first).status, "rejected_duplicate");
    assert.equal(collector.addResult({
      ...first,
      boundedPolicyEvaluationResultId: "bad-result",
      grantsAuthority: true
    }).status, "rejected_invalid");
    assert.equal(collector.addResult(second).status, "evicted_oldest");
    assert.equal(collector.count(), 1);
    assert.equal(collector.getById(first.boundedPolicyEvaluationResultId), undefined);
    assert.equal(collector.filter({ outcome: "eligible_for_future_authorization" }).length, 1);
  });

  it("does not grant capability, approve users, authorize, mutate session, or call vault/storage/WebAuthn/World ID/proof/adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      worldIdCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      sessionMutationCalls: 0
    };
    const result = evaluateBoundedRuntimePolicy(request([
      rule("allow-review", "allow_capability_for_review", "allow_for_further_review")
    ], {
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      worldIdCalls: 0,
      userApprovalCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0,
      sessionMutationCalls: 0
    });
    assert.equal(validateBoundedPolicyEvaluationResultShape(result.value).valid, true);
    assertNonAuthoritative(result.value);
  });
});
