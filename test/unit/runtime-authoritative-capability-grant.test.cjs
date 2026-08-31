const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const {
  createAuthoritativeCapabilityGrant,
  createAuthoritativePolicyDecision,
  createEphemeralCapabilityActivationEvidenceConsumptionStore,
  createEphemeralUserApprovalArtifactConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryAuthoritativeCapabilityGrantStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createValidationOnlyRuntimeApi,
  validateAuthoritativeCapabilityGrantShape
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
    lifecycleId: "capability-lifecycle-1",
    sessionId: "capability-session-1",
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

function userSessionContext(overrides = {}) {
  return Object.freeze({
    sessionId: "capability-session-1",
    ownerCommitment: "0x1234",
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: [],
    pendingIntentIds: [],
    policyMode: "default",
    metadata: Object.freeze({ deviceVaultUnlocked: true }),
    ...overrides
  });
}

function trustDecision(overrides = {}) {
  return Object.freeze({
    authoritativeTrustDecisionId: "capability-trust-decision-1",
    requestId: "capability-trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "capability-session-1",
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
      auditCorrelationId: "capability-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "capability-lifecycle-1",
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

function policyDecision(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const result = createAuthoritativePolicyDecision({
    requestId: "capability-policy-request-1",
    authoritativeTrustDecision: trust,
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
    policySet: {
      policySetId: "policy-set-1",
      version: "policy-v1",
      expiresAt: futureDate(),
      rules: [
        { ruleId: "approval", type: "require_user_approval", effect: "require_user_approval" },
        {
          ruleId: "duration",
          type: "limit_duration",
          effect: "restrict_duration",
          constraints: [{ constraintId: "duration-1", kind: "duration", value: 300 }]
        },
        {
          ruleId: "value",
          type: "limit_value",
          effect: "restrict_value",
          constraints: [{ constraintId: "value-1", kind: "value", value: "0.01 ETH" }]
        },
        {
          ruleId: "target",
          type: "restrict_target",
          effect: "restrict_target",
          constraints: [{ constraintId: "target-1", kind: "custom", value: "target-1" }]
        }
      ]
    },
    lifecycleSnapshot: lifecycleSnapshot(),
    sessionId: "capability-session-1",
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
    auditCorrelationId: "capability-audit-1",
    ...overrides.input
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function actionRequest(overrides = {}) {
  return Object.freeze({
    sessionId: "capability-session-1",
    applicationId: "ethereum-net",
    ownerCommitment: "0x1234",
    capabilityName: "request_transaction_submission",
    actionType: "send_eth",
    targetReference: "target-1",
    requestedValue: "0.01 ETH",
    effectiveScope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: "target-1"
    },
    effectiveDurationSeconds: 300,
    chainId: 8453,
    network: "base",
    auditCorrelationId: "capability-audit-1",
    ...overrides
  });
}

function approvalDecision(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const policy = overrides.policy ?? policyDecision({ trust });
  const action = overrides.action ?? actionRequest();
  const summary = {
    applicationId: "ethereum-net",
    applicationName: "Ethereum Net",
    capabilityName: "request_transaction_submission",
    actionType: "send_eth",
    targetReference: "target-1",
    requestedValue: "0.01 ETH",
    effectiveScope: action.effectiveScope,
    effectiveDurationSeconds: 300,
    chainId: 8453,
    network: "base",
    policyRestrictions: {
      effectiveDurationSeconds: 300,
      effectiveValueLimit: "0.01 ETH",
      effectiveTargetRestrictions: ["target-1"]
    },
    expiresAt: futureDate()
  };
  const approvalRequest = createPlatformUserApprovalRequest({
    requestId: "platform-approval-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    lifecycleSnapshot: lifecycleSnapshot(),
    approvalSurface: "desktop_native",
    approvalChallengeReference: "approval-challenge-1",
    presentationSummary: summary,
    requestedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "capability-audit-1"
  });
  assert.equal(approvalRequest.status, "approved", approvalRequest.error?.details?.errors?.join("\n"));
  const artifact = {
    platformUserApprovalArtifactId: overrides.artifactId ?? "approval-artifact-1",
    platformUserApprovalRequestId: approvalRequest.value.platformUserApprovalRequestId,
    approvalSurface: "desktop_native",
    outcome: overrides.outcome ?? "approved",
    decidedAt: now(),
    presentationDigest: approvalRequest.value.presentationDigest,
    approvalChallengeReference: approvalRequest.value.approvalChallengeReference,
    sessionId: action.sessionId,
    applicationId: action.applicationId,
    ownerCommitment: action.ownerCommitment,
    deviceReference: "device-safe-ref-1",
    platformProviderReference: "desktop-local-platform",
    userPresenceIndicated: (overrides.outcome ?? "approved") === "approved",
    userVerificationIndicated: (overrides.outcome ?? "approved") === "approved",
    productionBound: true,
    fixtureOnly: false,
    expiresAt: overrides.expired ? pastDate() : futureDate(),
    auditCorrelationId: action.auditCorrelationId,
    biometricTemplateIncluded: false,
    rawPlatformSecretIncluded: false,
    rawPrivateKeyIncluded: false,
    rawWebAuthnPrivateMaterialIncluded: false,
    vaultMaterialIncluded: false,
    credentialRecordIncluded: false,
    authorizationPackageIncluded: false,
    adapterPayloadIncluded: false
  };
  const decision = createPlatformUserApprovalDecision({
    requestId: "platform-approval-decision-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    platformApprovalRequest: approvalRequest.value,
    platformApprovalArtifact: artifact,
    lifecycleSnapshot: lifecycleSnapshot(),
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "capability-audit-1"
  }, createEphemeralUserApprovalArtifactConsumptionStore());
  assert.equal(decision.status, "approved", decision.error?.details?.errors?.join("\n"));
  return { trust, policy, action, approval: decision.value };
}

function activationRequest(overrides = {}) {
  const bundle = overrides.bundle ?? approvalDecision();
  return {
    requestId: "capability-activation-request-1",
    authoritativeTrustDecision: bundle.trust,
    authoritativePolicyDecision: bundle.policy,
    platformUserApprovalDecision: bundle.approval,
    lifecycleSnapshot: lifecycleSnapshot(overrides.lifecycleSnapshot),
    userSessionContext: userSessionContext(overrides.userSessionContext),
    ownerCommitment: "0x1234",
    sessionId: "capability-session-1",
    applicationId: "ethereum-net",
    capabilityName: "request_transaction_submission",
    requestedScope: actionRequest().effectiveScope,
    effectiveScope: bundle.policy.effectiveScope,
    requestedDurationSeconds: 300,
    effectiveDurationSeconds: bundle.policy.effectiveDurationSeconds,
    allowedTargets: bundle.policy.effectiveTargetRestrictions,
    valueLimit: bundle.policy.effectiveValueLimit,
    actionTypes: [bundle.policy.scope.actionType],
    chainId: 8453,
    network: "base",
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "capability-audit-1",
    ...overrides.request
  };
}

function runShell(args) {
  return spawnSync(process.execPath, ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
}

describe("PhilCore authoritative scoped capability grant boundary", function () {
  it("creates a scoped active capability grant without authorization or execution", function () {
    const result = createAuthoritativeCapabilityGrant(activationRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.status, "active");
    assert.equal(result.value.capabilityGranted, true);
    assert.equal(result.value.activeCapabilityCreated, false);
    assert.equal(result.value.actionAuthorized, false);
    assert.equal(result.value.authorizationCreated, false);
    assert.equal(result.value.authorizationPackageCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.executionAllowed, false);
    assert.equal(result.value.proofExecuted, false);
    assert.equal(result.value.adapterExecuted, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.vaultAccessed, false);
    assert.equal(result.value.worldIdVerified, false);
    assert.equal(result.value.persistedAsAuthority, false);
    assert.equal(validateAuthoritativeCapabilityGrantShape(result.value).valid, true);
  });

  it("rejects denied approval, expired evidence, locked sessions, widened scope, and target/value mismatches", function () {
    const denied = createAuthoritativeCapabilityGrant(activationRequest({
      bundle: approvalDecision({ outcome: "denied", artifactId: "deny-artifact" })
    }));
    const expired = createAuthoritativeCapabilityGrant(activationRequest({
      request: { expiresAt: pastDate() }
    }));
    const locked = createAuthoritativeCapabilityGrant(activationRequest({
      lifecycleSnapshot: { state: "locked" },
      userSessionContext: { status: "locked" }
    }));
    const scope = createAuthoritativeCapabilityGrant(activationRequest({
      request: { effectiveScope: { applicationId: "ethereum-net", action: "send_eth", resource: "other" } }
    }));
    const value = createAuthoritativeCapabilityGrant(activationRequest({
      request: { valueLimit: "1 ETH" }
    }));
    const target = createAuthoritativeCapabilityGrant(activationRequest({
      request: { allowedTargets: ["other-target"] }
    }));

    for (const result of [denied, expired, locked, scope, value, target]) {
      assert.notEqual(result.status, "approved");
      assert.equal(result.value, undefined);
    }
  });

  it("rejects replay and obvious secret-shaped metadata", function () {
    const replayStore = createEphemeralCapabilityActivationEvidenceConsumptionStore();
    const request = activationRequest();
    const first = createAuthoritativeCapabilityGrant(request, replayStore);
    const replay = createAuthoritativeCapabilityGrant(request, replayStore);
    const secret = createAuthoritativeCapabilityGrant(activationRequest({
      request: { metadata: { phil_secret: "nope" } }
    }));

    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(replay.error.code, "AUTHORITATIVE_CAPABILITY_ACTIVATION_REPLAYED");
    assert.notEqual(secret.status, "approved");
    assert.equal(secret.value, undefined);
  });

  it("activates, rejects duplicates/overlaps, revokes, expires, and clears process-local grants", function () {
    const grant = createAuthoritativeCapabilityGrant(activationRequest()).value;
    const store = createInMemoryAuthoritativeCapabilityGrantStore();
    const first = store.activate(grant);
    const duplicate = store.activate(grant);
    const overlapping = store.activate(createAuthoritativeCapabilityGrant(activationRequest({
      request: { requestId: "capability-activation-request-2" }
    })).value);
    const active = store.findActiveCapability({
      sessionId: "capability-session-1",
      applicationId: "ethereum-net",
      ownerCommitment: "0x1234",
      capabilityName: "request_transaction_submission"
    });
    const otherCapability = store.findActiveCapability({
      sessionId: "capability-session-1",
      applicationId: "ethereum-net",
      ownerCommitment: "0x1234",
      capabilityName: "request_message_signature"
    });
    const revoked = store.revoke(grant.authoritativeCapabilityGrantId, "user_revoked");
    const expired = store.expire("missing-grant");
    const cleared = store.clearSession("capability-session-1", "session_locked");

    assert.equal(first.status, "activated");
    assert.equal(first.activeCapabilityCreated, true);
    assert.equal(first.grant.activeCapabilityCreated, true);
    assert.equal(first.authorizationCreated, false);
    assert.equal(duplicate.status, "rejected_duplicate");
    assert.equal(overlapping.status, "rejected_overlap");
    assert.equal(active.authoritativeCapabilityGrantId, grant.authoritativeCapabilityGrantId);
    assert.equal(otherCapability, undefined);
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.grant.status, "revoked");
    assert.equal(expired.status, "not_found");
    assert.equal(cleared.status, "cleared");
  });

  it("integrates with the facade, audit collector, revocation, and inspection without creating authorization", function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const store = createInMemoryAuthoritativeCapabilityGrantStore();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      capabilityActivationEvidenceConsumptionStore:
        createEphemeralCapabilityActivationEvidenceConsumptionStore(),
      authoritativeCapabilityGrantStore: store
    });
    const activated = api.requestAuthoritativeCapabilityActivation(activationRequest());
    const inspected = api.inspectActiveCapabilityGrants({
      requestId: "inspect-1",
      sessionId: "capability-session-1",
      applicationId: "ethereum-net",
      requestedAt: now(),
      auditCorrelationId: "capability-audit-1"
    });
    const revoked = api.requestCapabilityGrantRevocation({
      requestId: "revoke-1",
      grantId: activated.value.authoritativeCapabilityGrant.authoritativeCapabilityGrantId,
      reason: "user_revoked",
      requestedAt: now(),
      sessionId: "capability-session-1",
      applicationId: "ethereum-net",
      auditCorrelationId: "capability-audit-1"
    });

    assert.equal(activated.status, "approved", activated.error?.details?.errors?.join("\n"));
    assert.equal(activated.value.authoritativeCapabilityGrant.capabilityGranted, true);
    assert.equal(activated.value.userSessionCapabilityMutationResult.status, "activated");
    assert.equal(activated.value.authoritativeCapabilityGrant.authorizationCreated, false);
    assert.equal(inspected.status, "approved");
    assert.equal(inspected.value.activeCapabilityGrantInspection.count, 1);
    assert.equal(inspected.value.activeCapabilityGrantInspection.authorizationCreated, false);
    assert.equal(revoked.status, "approved");
    assert.equal(revoked.value.userSessionCapabilityMutationResult.status, "revoked");
    assert.equal(auditCollector.count(), 4);
  });
});

describe("PhilCore Alpha 0 authoritative capability activation diagnostic", function () {
  it("shows approved activation as scoped capability only", function () {
    const result = runShell([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_authoritative_capability_activation",
      "--json"
    ]);
    assert.equal(result.status, 0, result.stderr);
    const json = JSON.parse(result.stdout);

    assert.equal(json.finalStatus, "succeeded");
    assert.equal(json.authoritativeCapabilityGrant.status, "active");
    assert.equal(json.authoritativeCapabilityGrant.capabilityGranted, true);
    assert.equal(json.authoritativeCapabilityGrant.activeCapabilityCreated, true);
    assert.equal(json.authoritativeCapabilityGrant.authorizationPackageCreated, false);
    assert.equal(json.authoritativeCapabilityGrant.executionAllowed, false);
    assert.equal(json.nonAuthority.activeCapabilityCreated, true);
    assert.equal(json.nonAuthority.authorizationCreated, false);
    assert.equal(json.nonAuthority.proofExecuted, false);
    assert.equal(json.nonAuthority.adapterExecuted, false);
  });

  it("shows denied approval produces no capability grant", function () {
    const result = runShell([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_authoritative_capability_activation",
      "--approval-outcome",
      "deny",
      "--json"
    ]);
    assert.equal(result.status, 0, result.stderr);
    const json = JSON.parse(result.stdout);

    assert.equal(json.finalStatus, "succeeded");
    assert.equal(json.platformUserApprovalDecision.outcome, "user_denied");
    assert.equal(json.authoritativeCapabilityGrant.status, "rejected");
    assert.equal(json.authoritativeCapabilityGrant.capabilityGranted, false);
    assert.equal(json.nonAuthority.activeCapabilityCreated, false);
    assert.equal(json.nonAuthority.authorizationCreated, false);
  });
});
