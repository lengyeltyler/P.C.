const assert = require("node:assert/strict");

const {
  createAuthoritativePolicyDecision,
  createEphemeralPolicyDecisionEvidenceConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryAuthoritativePolicyDecisionStore,
  createValidationOnlyRuntimeApi,
  runAlpha0Shell,
  validateAuthoritativePolicyDecisionShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function lifecycleSnapshot(overrides = {}) {
  return Object.freeze({
    lifecycleId: "policy-lifecycle-1",
    sessionId: "policy-session-1",
    state: "unlocked",
    sequence: 4,
    version: 4,
    createdAt: now(),
    updatedAt: now(),
    metadata: Object.freeze({ deviceVaultUnlocked: true }),
    limitations: Object.freeze(["ephemeral_only"]),
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: true,
    grantsAuthority: false,
    ...overrides
  });
}

function trustDecision(overrides = {}) {
  return Object.freeze({
    authoritativeTrustDecisionId: "trust-decision-1",
    requestId: "trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "policy-session-1",
      applicationId: "ethereum-net",
      ownerCommitment: "0x1234",
      credentialId: "cred-1",
      credentialSafeReference: "0xabcd",
      providerKind: "webauthn_passkey",
      authenticationPurpose: "high_risk_action",
      requestedAssurance: Object.freeze([
        "user_presence",
        "user_verification",
        "phishing_resistant"
      ]),
      auditCorrelationId: "policy-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "policy-lifecycle-1",
      sessionLifecycleState: "unlocked",
      challengeReferenceId: "challenge-1",
      validityWindowId: "trust-validity-1",
      reusableAcrossSessions: false,
      reusableAcrossCredentials: false,
      reusableAcrossApplications: false,
      reusableAcrossPurposes: false,
      reusableAcrossOwners: false,
      reusableAcrossChallenges: false,
      reusableAcrossTimeWindows: false
    }),
    evidence: Object.freeze({
      productionAssertionVerified: true,
      productionVerifierUsed: true,
      fixtureOnlyEvidence: false,
      credentialCounterCommitted: true,
      acceptedZeroCounterSemantics: false,
      persistedCounter: 8,
      verifiedReturnedCounter: 8,
      counterStatus: "advanced",
      credentialLifecycleEligible: true,
      sessionContextEligible: true,
      assuranceSatisfied: true,
      userPresenceVerified: true,
      userVerificationVerified: true,
      challengeVerified: true,
      originVerified: true,
      rpIdHashVerified: true,
      signatureVerified: true,
      rawAssertionMaterialIncluded: false,
      publicKeyBytesIncluded: false,
      credentialRecordIncluded: false
    }),
    validity: Object.freeze({
      issuedAt: now(),
      expiresAt: futureDate(),
      expired: false,
      invalidatedBySessionLock: true,
      invalidatedBySessionClose: true,
      invalidatedByCredentialRevocation: true,
      invalidatedByOwnerMismatch: true
    }),
    requirements: Object.freeze(["successful_production_verification"]),
    limitations: Object.freeze(["trust_manager_authority_only"]),
    reasons: Object.freeze(["trust-manager-authority-only"]),
    revocationReference: Object.freeze({
      referenceId: "revocation-ref-1",
      durableRevocationImplemented: false,
      futureRevocationRequired: true
    }),
    trustDecisionCreated: true,
    productionAssertionVerified: true,
    credentialCounterCommitted: true,
    acceptedZeroCounterSemantics: false,
    credentialLifecycleEligible: true,
    sessionContextEligible: true,
    assuranceSatisfied: true,
    validForSpecifiedPurposeOnly: true,
    capabilityGranted: false,
    policyApproved: false,
    userApprovalCollected: false,
    authorizationCreated: false,
    sessionKeyCreated: false,
    executionAllowed: false,
    worldIdVerified: false,
    vaultMaterialExposed: false,
    registryPlaintextExposed: false,
    rawAssertionMaterialIncluded: false,
    credentialPrivateMaterialExposed: false,
    persistedAsAuthority: false,
    persisted: false,
    ...overrides
  });
}

function policySet(rules, overrides = {}) {
  return Object.freeze({
    policySetId: "policy-set-1",
    version: "policy-v1",
    expiresAt: futureDate(),
    rules: Object.freeze(rules),
    ...overrides
  });
}

function baseRequest(overrides = {}) {
  return {
    requestId: "policy-request-1",
    authoritativeTrustDecision: trustDecision(),
    capabilityRequest: {
      requestId: "capability-request-1",
      applicationId: "ethereum-net",
      capability: "request_transaction_submission",
      sensitivity: "privileged",
      scope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "target-1",
        expiresAt: futureDate()
      },
      requestedAt: now()
    },
    actionContext: {
      actionType: "send_eth",
      targetReference: "target-1",
      requestedValue: "0.01 ETH",
      requestedDurationSeconds: 300,
      requestedScope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "target-1"
      },
      chainId: 8453,
      network: "base"
    },
    policySet: policySet([{
      ruleId: "allow-review",
      type: "allow_capability_for_review",
      effect: "allow_for_capability_activation_review"
    }]),
    lifecycleSnapshot: lifecycleSnapshot(),
    sessionId: "policy-session-1",
    lifecycleState: "unlocked",
    ownerCommitment: "0x1234",
    applicationId: "ethereum-net",
    capabilityName: "request_transaction_submission",
    requestedScope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: "target-1"
    },
    requestedDurationSeconds: 300,
    actionType: "send_eth",
    targetReference: "target-1",
    requestedValue: "0.01 ETH",
    chainId: 8453,
    network: "base",
    authenticationPurpose: "high_risk_action",
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "policy-audit-1",
    ...overrides
  };
}

function decisionForRules(rules, overrides = {}) {
  return createAuthoritativePolicyDecision(baseRequest({
    policySet: policySet(rules),
    ...overrides
  }));
}

describe("PhilCore authoritative Security Policy Decision boundary", function () {
  it("creates a policy decision from a valid Trust Decision and permissive rules without authority", function () {
    const result = createAuthoritativePolicyDecision(baseRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "allowed_for_capability_activation_review");
    assert.equal(result.value.policyDecisionCreated, true);
    assert.equal(result.value.trustDecisionAccepted, true);
    assert.equal(result.value.rulesEvaluated, true);
    assert.equal(result.value.capabilityGranted, false);
    assert.equal(result.value.userApprovalCollected, false);
    assert.equal(result.value.authorizationCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.executionAllowed, false);
    assert.equal(result.value.proofExecuted, false);
    assert.equal(result.value.adapterExecuted, false);
    assert.equal(validateAuthoritativePolicyDecisionShape(result.value).valid, true);
  });

  it("applies deny precedence over allow", function () {
    const result = decisionForRules([
      { ruleId: "allow-review", type: "allow_capability_for_review", effect: "allow_for_capability_activation_review" },
      { ruleId: "deny", type: "deny_capability", effect: "deny" }
    ]);

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "denied");
    assert.equal(result.value.reasons.includes("deny-precedence"), true);
    assert.equal(result.value.capabilityGranted, false);
  });

  it("models approval, stronger trust, and production authentication requirements", function () {
    const approval = decisionForRules([
      { ruleId: "approval", type: "require_user_approval", effect: "require_user_approval" }
    ]);
    const stronger = decisionForRules([
      { ruleId: "trust", type: "require_trust_level", effect: "require_stronger_trust" }
    ]);
    const productionSatisfied = decisionForRules([
      {
        ruleId: "production",
        type: "require_production_possession_verification",
        effect: "require_production_verification"
      }
    ]);

    assert.equal(approval.value.outcome, "requires_user_approval");
    assert.equal(approval.value.requiresUserApproval, true);
    assert.equal(approval.value.userApprovalCollected, false);
    assert.equal(stronger.value.outcome, "requires_stronger_trust");
    assert.equal(productionSatisfied.status, "approved");
    assert.equal(productionSatisfied.value.requiresProductionAuthentication, false);
  });

  it("preserves World ID as canonical-activation specific", function () {
    const ordinary = createAuthoritativePolicyDecision(baseRequest());
    const canonical = createAuthoritativePolicyDecision(baseRequest({
      actionContext: {
        ...baseRequest().actionContext,
        canonicalPhilActivation: true
      },
      canonicalPhilActivationContext: true
    }));

    assert.equal(ordinary.status, "approved");
    assert.equal(ordinary.value.requiresWorldIdEnrollment, false);
    assert.equal(canonical.status, "approved");
    assert.equal(canonical.value.outcome, "requires_world_id_enrollment");
    assert.equal(canonical.value.worldIdVerified, false);
  });

  it("applies scope, duration, value, target, application, and session restrictions", function () {
    const scope = decisionForRules([{
      ruleId: "scope",
      type: "limit_scope",
      effect: "restrict_scope",
      constraints: [{ constraintId: "scope-1", kind: "scope", value: { action: "send_eth" } }]
    }]);
    const duration = decisionForRules([{
      ruleId: "duration",
      type: "limit_duration",
      effect: "restrict_duration",
      constraints: [{ constraintId: "duration-1", kind: "duration", value: 60 }]
    }]);
    const value = decisionForRules([{
      ruleId: "value",
      type: "limit_value",
      effect: "restrict_value",
      constraints: [{ constraintId: "value-1", kind: "value", value: "0.001 ETH" }]
    }]);
    const target = decisionForRules([{
      ruleId: "target",
      type: "restrict_target",
      effect: "restrict_target"
    }]);
    const application = decisionForRules([{
      ruleId: "application",
      type: "restrict_application",
      effect: "restrict_scope"
    }]);
    const session = decisionForRules([{
      ruleId: "session",
      type: "restrict_session_state",
      effect: "restrict_scope"
    }]);

    assert.equal(scope.value.outcome, "scope_restricted");
    assert.equal(duration.value.outcome, "duration_restricted");
    assert.equal(duration.value.effectiveDurationSeconds, 60);
    assert.equal(value.value.outcome, "value_restricted");
    assert.equal(value.value.effectiveValueLimit, "0.001 ETH");
    assert.equal(target.value.outcome, "target_restricted");
    assert.deepEqual(target.value.effectiveTargetRestrictions, ["target-1"]);
    assert.equal(application.value.outcome, "application_restricted");
    assert.equal(session.value.outcome, "session_state_ineligible");
  });

  it("handles recovery-only context and rejects expired or mismatched request chains", function () {
    const recoveryMissing = decisionForRules([{
      ruleId: "recovery",
      type: "recovery_only",
      effect: "require_stronger_trust"
    }]);
    const recoveryOk = decisionForRules([{
      ruleId: "recovery",
      type: "recovery_only",
      effect: "allow_for_further_review",
      scope: { recoveryOnly: true }
    }], { recoveryContext: true });
    const expiredTrust = createAuthoritativePolicyDecision(baseRequest({
      authoritativeTrustDecision: trustDecision({
        validity: { ...trustDecision().validity, expiresAt: pastDate() }
      })
    }));
    const expiredRequest = createAuthoritativePolicyDecision(baseRequest({ expiresAt: pastDate() }));
    const expiredPolicy = createAuthoritativePolicyDecision(baseRequest({
      policySet: policySet([], { expiresAt: pastDate() })
    }));
    const purposeMismatch = createAuthoritativePolicyDecision(baseRequest({
      authenticationPurpose: "credential_rotation"
    }));
    const ownerMismatch = createAuthoritativePolicyDecision(baseRequest({ ownerCommitment: "0x9999" }));
    const appMismatch = createAuthoritativePolicyDecision(baseRequest({ applicationId: "nft-manager" }));
    const auditMismatch = createAuthoritativePolicyDecision(baseRequest({ auditCorrelationId: "other-audit" }));
    const policyVersionMissing = createAuthoritativePolicyDecision(baseRequest({
      policySet: { policySetId: "policy-set", expiresAt: futureDate(), rules: [] }
    }));

    assert.equal(recoveryMissing.value.outcome, "requires_recovery_context");
    assert.equal(recoveryOk.value.outcome, "allowed_for_capability_activation_review");
    assert.equal(expiredTrust.status, "denied");
    assert.equal(expiredRequest.status, "denied");
    assert.equal(expiredPolicy.status, "denied");
    assert.equal(purposeMismatch.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(appMismatch.status, "denied");
    assert.equal(auditMismatch.status, "denied");
    assert.equal(policyVersionMissing.status, "denied");
  });

  it("rejects replayed evidence, malformed rules, unsupported rules, and secret-shaped metadata", function () {
    const store = createEphemeralPolicyDecisionEvidenceConsumptionStore();
    const first = createAuthoritativePolicyDecision(baseRequest(), store);
    const replay = createAuthoritativePolicyDecision(baseRequest(), store);
    const malformed = createAuthoritativePolicyDecision(baseRequest({
      policySet: policySet([{ ruleId: "", type: "deny_capability", effect: "deny" }])
    }));
    const unsupported = createAuthoritativePolicyDecision(baseRequest({
      policySet: policySet([{ ruleId: "weird", type: "made_up", effect: "deny" }])
    }));
    const secret = createAuthoritativePolicyDecision(baseRequest({
      metadata: { phil_secret: "nope" }
    }));

    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(malformed.status, "denied");
    assert.equal(unsupported.status, "denied");
    assert.equal(secret.status, "denied");
  });

  it("accepts a valid object-valued constraint on an authoritative policy rule", function () {
    const result = decisionForRules([{
      ruleId: "scope-object-value",
      type: "limit_scope",
      effect: "restrict_scope",
      constraints: [{
        constraintId: "scope-object-1",
        kind: "scope",
        value: { action: "send_eth", resource: "target-1" }
      }]
    }]);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "scope_restricted");
    assert.deepEqual(result.value.effectiveScope, { action: "send_eth", resource: "target-1" });
  });

  it("rejects sensitive keys inside policy-set metadata, rule metadata, constraint metadata, requirement metadata, and object-valued constraint values", function () {
    const cases = [
      ["POLICY-SET-METADATA-SECRET", decisionForRules([{
        ruleId: "allow-review",
        type: "allow_capability_for_review",
        effect: "allow_for_capability_activation_review"
      }], {
        policySet: policySet([{
          ruleId: "allow-review",
          type: "allow_capability_for_review",
          effect: "allow_for_capability_activation_review"
        }], { metadata: { password: "POLICY-SET-METADATA-SECRET" } })
      })],
      ["RULE-METADATA-SECRET", decisionForRules([{
        ruleId: "allow-review",
        type: "allow_capability_for_review",
        effect: "allow_for_capability_activation_review",
        metadata: { password: "RULE-METADATA-SECRET" }
      }])],
      ["CONSTRAINT-METADATA-SECRET", decisionForRules([{
        ruleId: "scope",
        type: "limit_scope",
        effect: "restrict_scope",
        constraints: [{
          constraintId: "scope-1",
          kind: "scope",
          value: "send_eth",
          metadata: { password: "CONSTRAINT-METADATA-SECRET" }
        }]
      }])],
      ["REQUIREMENT-METADATA-SECRET", decisionForRules([{
        ruleId: "scope",
        type: "limit_scope",
        effect: "restrict_scope",
        requirements: [{
          requirementId: "req-1",
          kind: "scope_restriction",
          metadata: { password: "REQUIREMENT-METADATA-SECRET" }
        }]
      }])],
      ["CONSTRAINT-VALUE-SECRET", decisionForRules([{
        ruleId: "scope",
        type: "limit_scope",
        effect: "restrict_scope",
        constraints: [{
          constraintId: "scope-1",
          kind: "scope",
          value: { password: "CONSTRAINT-VALUE-SECRET" }
        }]
      }])]
    ];

    for (const [canary, result] of cases) {
      assert.equal(result.status, "denied", canary);
      assert.equal(JSON.stringify(result).includes(canary), false, canary);
    }
  });

  it("reports a specific sensitive-field finding within the policy inspection depth and fails closed beyond it", function () {
    const withinDepth = decisionForRules([{
      ruleId: "scope",
      type: "limit_scope",
      effect: "restrict_scope",
      constraints: [{
        constraintId: "scope-1",
        kind: "scope",
        value: { a: { b: { c: { d: { password: "WITHIN-DEPTH-SECRET" } } } } }
      }]
    }]);
    const beyondDepth = decisionForRules([{
      ruleId: "scope",
      type: "limit_scope",
      effect: "restrict_scope",
      constraints: [{
        constraintId: "scope-1",
        kind: "scope",
        value: { a: { b: { c: { d: { e: { password: "BEYOND-DEPTH-SECRET" } } } } } }
      }]
    }]);

    assert.equal(withinDepth.status, "denied");
    assert.ok(
      withinDepth.error.details.errors.some((error) =>
        error.includes("password") && error.includes("sensitive runtime metadata key")),
      JSON.stringify(withinDepth.error.details.errors)
    );
    assert.equal(JSON.stringify(withinDepth).includes("WITHIN-DEPTH-SECRET"), false);

    assert.equal(beyondDepth.status, "denied");
    assert.ok(
      beyondDepth.error.details.errors.some((error) =>
        error.includes("maxDepth") || error.includes("traversal exceeded")),
      JSON.stringify(beyondDepth.error.details.errors)
    );
    assert.equal(JSON.stringify(beyondDepth).includes("BEYOND-DEPTH-SECRET"), false);
  });

  it("does not report duplicate sensitive or depth errors from the same policy scan", function () {
    const result = decisionForRules([{
      ruleId: "allow-review",
      type: "allow_capability_for_review",
      effect: "allow_for_capability_activation_review"
    }], {
      policySet: policySet([{
        ruleId: "allow-review",
        type: "allow_capability_for_review",
        effect: "allow_for_capability_activation_review"
      }], { metadata: { secret: "DUPLICATE-SCAN-SECRET" } })
    });

    assert.equal(result.status, "denied");
    const matches = result.error.details.errors.filter((error) =>
      error.includes("contains sensitive runtime metadata key secret"));
    assert.equal(matches.length, 1, JSON.stringify(result.error.details.errors));
  });

  it("integrates through the facade, audit drafts, and optional process-local store", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const decisionStore = createInMemoryAuthoritativePolicyDecisionStore({ maxDecisionCount: 1 });
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      authoritativePolicyDecisionStore: decisionStore,
      policyDecisionEvidenceConsumptionStore: createEphemeralPolicyDecisionEvidenceConsumptionStore()
    });
    const result = api.requestAuthoritativePolicyDecision(baseRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.authoritativePolicyDecision.policyDecisionCreated, true);
    assert.equal(result.value.authoritativePolicyDecisionCollectionResult.status, "collected");
    assert.equal(decisionStore.count(), 1);
    assert.equal(result.value.authoritativePolicyDecision.capabilityGranted, false);
    assert.equal(result.value.authoritativePolicyDecision.authorizationCreated, false);
    assert.equal(result.value.auditEventDraft.redactedDetails.authoritativePolicyDecisionCapabilityGranted, false);
    assert.equal(JSON.stringify(result.value.auditEventDraft).includes("phil_secret"), false);
  });

  it("runs Alpha 0 authoritative policy diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_authoritative_policy_decision"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_authoritative_policy_decision", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Authoritative Security Policy Decision:/i);
    assert.match(textOutput, /policy rules evaluated: yes/i);
    assert.match(textOutput, /capability grant created: no/i);
    assert.match(textOutput, /Authorization Package created: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.authoritativePolicyDecision.status, "policy_decision_created");
    assert.equal(parsed.authoritativePolicyDecision.capabilityGranted, false);
    assert.equal(parsed.authoritativePolicyDecision.userApprovalCollected, false);
    assert.equal(parsed.authoritativePolicyDecision.authorizationCreated, false);
    assert.equal(parsed.authoritativePolicyDecision.executionAllowed, false);
  });
});
