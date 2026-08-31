const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const {
  createAuthorizationActionDigestPreview,
  createAuthorizationDecisionCandidate,
  createAuthoritativeCapabilityGrant,
  createAuthoritativePolicyDecision,
  createEphemeralAuthorizationCandidateConsumptionStore,
  createEphemeralUserApprovalArtifactConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryAuthorizationDecisionCandidateStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createValidationOnlyRuntimeApi,
  validateAuthorizationDecisionCandidateShape
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
    lifecycleId: "authorization-lifecycle-1",
    sessionId: "authorization-session-1",
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
    sessionId: "authorization-session-1",
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
    authoritativeTrustDecisionId: "authorization-trust-decision-1",
    requestId: "authorization-trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "authorization-session-1",
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
      auditCorrelationId: "authorization-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "authorization-lifecycle-1",
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
    requestId: "authorization-policy-request-1",
    authoritativeTrustDecision: trust,
    capabilityRequest: {
      requestId: "authorization-capability-request-1",
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
    sessionId: "authorization-session-1",
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
    auditCorrelationId: "authorization-audit-1",
    ...overrides.input
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function actionRequest(overrides = {}) {
  return Object.freeze({
    sessionId: "authorization-session-1",
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
    auditCorrelationId: "authorization-audit-1",
    ...overrides
  });
}

function approvalDecision(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const policy = overrides.policy ?? policyDecision({ trust });
  const action = overrides.action ?? actionRequest();
  const approvalRequest = createPlatformUserApprovalRequest({
    requestId: "authorization-platform-approval-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    lifecycleSnapshot: lifecycleSnapshot(),
    approvalSurface: "desktop_native",
    approvalChallengeReference: "approval-challenge-1",
    presentationSummary: {
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
    },
    requestedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "authorization-audit-1"
  });
  assert.equal(approvalRequest.status, "approved", approvalRequest.error?.details?.errors?.join("\n"));
  const decision = createPlatformUserApprovalDecision({
    requestId: "authorization-platform-approval-decision-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    platformApprovalRequest: approvalRequest.value,
    platformApprovalArtifact: {
      platformUserApprovalArtifactId: overrides.artifactId ?? "approval-artifact-1",
      platformUserApprovalRequestId: approvalRequest.value.platformUserApprovalRequestId,
      approvalSurface: "desktop_native",
      outcome: "approved",
      decidedAt: now(),
      presentationDigest: approvalRequest.value.presentationDigest,
      approvalChallengeReference: approvalRequest.value.approvalChallengeReference,
      sessionId: action.sessionId,
      applicationId: action.applicationId,
      ownerCommitment: action.ownerCommitment,
      deviceReference: "device-safe-ref-1",
      platformProviderReference: "desktop-local-platform",
      userPresenceIndicated: true,
      userVerificationIndicated: true,
      productionBound: true,
      fixtureOnly: false,
      expiresAt: futureDate(),
      auditCorrelationId: action.auditCorrelationId,
      biometricTemplateIncluded: false,
      rawPlatformSecretIncluded: false,
      rawPrivateKeyIncluded: false,
      rawWebAuthnPrivateMaterialIncluded: false,
      vaultMaterialIncluded: false,
      credentialRecordIncluded: false,
      authorizationPackageIncluded: false,
      adapterPayloadIncluded: false
    },
    lifecycleSnapshot: lifecycleSnapshot(),
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "authorization-audit-1"
  }, createEphemeralUserApprovalArtifactConsumptionStore());
  assert.equal(decision.status, "approved", decision.error?.details?.errors?.join("\n"));
  return { trust, policy, action, approval: decision.value };
}

function activeGrant(overrides = {}) {
  const bundle = overrides.bundle ?? approvalDecision();
  const result = createAuthoritativeCapabilityGrant({
    requestId: overrides.requestId ?? "authorization-capability-activation-request-1",
    authoritativeTrustDecision: bundle.trust,
    authoritativePolicyDecision: bundle.policy,
    platformUserApprovalDecision: bundle.approval,
    lifecycleSnapshot: lifecycleSnapshot(overrides.lifecycleSnapshot),
    userSessionContext: userSessionContext(overrides.userSessionContext),
    ownerCommitment: "0x1234",
    sessionId: "authorization-session-1",
    applicationId: "ethereum-net",
    capabilityName: overrides.capabilityName ?? "request_transaction_submission",
    requestedScope: actionRequest().effectiveScope,
    effectiveScope: overrides.effectiveScope ?? bundle.policy.effectiveScope,
    requestedDurationSeconds: 300,
    effectiveDurationSeconds: overrides.effectiveDurationSeconds ?? bundle.policy.effectiveDurationSeconds,
    allowedTargets: overrides.allowedTargets ?? bundle.policy.effectiveTargetRestrictions,
    valueLimit: overrides.valueLimit ?? bundle.policy.effectiveValueLimit,
    actionTypes: overrides.actionTypes ?? [bundle.policy.scope.actionType],
    chainId: overrides.chainId ?? 8453,
    network: overrides.network ?? "base",
    issuedAt: now(),
    expiresAt: overrides.expiresAt ?? futureDate(),
    auditCorrelationId: "authorization-audit-1",
    ...overrides.request
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function candidateRequest(grant = activeGrant(), overrides = {}) {
  return {
    requestId: "authorization-decision-candidate-request-1",
    activeCapabilityGrant: grant,
    intent: {
      intentId: "authorization-intent-1",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {
        chainId: 8453,
        target: "target-1",
        value: "0.01 ETH",
        callData: "0x"
      },
      status: "created",
      createdAt: now(),
      expiresAt: futureDate(30_000)
    },
    actionType: "transaction_submission",
    lifecycleSnapshot: lifecycleSnapshot(),
    userSessionContext: userSessionContext(),
    ownerCommitment: "0x1234",
    sessionId: "authorization-session-1",
    applicationId: "ethereum-net",
    target: "target-1",
    method: "send_eth",
    value: "0.01 ETH",
    scope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: "target-1"
    },
    requestedDurationSeconds: 300,
    chainId: 8453,
    network: "base",
    consumerDataReference: "consumer-data-v1",
    issuedAt: now(),
    expiresAt: futureDate(30_000),
    auditCorrelationId: "authorization-audit-1",
    ...overrides
  };
}

function runShell(args) {
  return spawnSync(process.execPath, ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
}

describe("PhilCore bounded Authorization Decision Candidate boundary", function () {
  it("creates a candidate for one exact action without package, proof, signature, or execution", function () {
    const result = createAuthorizationDecisionCandidate(candidateRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.status, "candidate_created");
    assert.equal(result.value.outcome, "authorization_candidate_created");
    assert.equal(result.value.actionSummary.actionType, "transaction_submission");
    assert.equal(result.value.actionSummary.requiredCapability, "request_transaction_submission");
    assert.equal(result.value.proofRequirement, "proof_required_by_action");
    assert.equal(result.value.authorizationDecisionCandidateCreated, true);
    assert.equal(result.value.activeCapabilityGrantAccepted, true);
    assert.equal(result.value.authorizationPackageCreated, false);
    assert.equal(result.value.actionAuthorized, false);
    assert.equal(result.value.proofInputHashCreated, false);
    assert.equal(result.value.proofExecuted, false);
    assert.equal(result.value.signatureCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.adapterExecutionAllowed, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.vaultAccessed, false);
    assert.equal(result.value.worldIdVerified, false);
    assert.equal(result.value.persistedAsAuthority, false);
    assert.equal(validateAuthorizationDecisionCandidateShape(result.value).valid, true);
  });

  it("rejects missing, revoked, expired, and replayed active capability grant evidence", function () {
    const missing = createAuthorizationDecisionCandidate(candidateRequest(undefined, {
      activeCapabilityGrant: undefined
    }));
    const revokedGrant = {
      ...activeGrant(),
      status: "revoked",
      revocation: {
        revoked: true,
        revokedAt: now(),
        reason: "user_revoked",
        durableRevocationImplemented: false,
        processLocalOnly: true
      }
    };
    const revoked = createAuthorizationDecisionCandidate(candidateRequest(revokedGrant));
    const expiredGrant = {
      ...activeGrant(),
      validity: { ...activeGrant().validity, expiresAt: pastDate(), expired: true }
    };
    const expired = createAuthorizationDecisionCandidate(candidateRequest(expiredGrant));
    const replayStore = createEphemeralAuthorizationCandidateConsumptionStore();
    const replayRequest = candidateRequest(activeGrant());
    const first = createAuthorizationDecisionCandidate(replayRequest, replayStore);
    const replay = createAuthorizationDecisionCandidate(replayRequest, replayStore);

    assert.equal(missing.status, "denied");
    assert.equal(revoked.status, "denied");
    assert.equal(expired.status, "denied");
    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(replay.error.code, "AUTHORIZATION_DECISION_CANDIDATE_REPLAYED");
  });

  it("does not let a preparation capability imply submission authority or read capability imply writes", function () {
    const preparation = createAuthorizationDecisionCandidate(candidateRequest(activeGrant(), {
      actionType: "transaction_preparation",
      intent: {
        ...candidateRequest().intent,
        requestedCapabilities: ["request_transaction_preparation"]
      }
    }));
    const readOnlyGrant = {
      ...activeGrant(),
      scope: {
        ...activeGrant().scope,
        capabilityName: "view_transactions",
        actionTypes: ["view_transactions"]
      },
      binding: {
        ...activeGrant().binding,
        capabilityName: "view_transactions"
      }
    };
    const writeFromRead = createAuthorizationDecisionCandidate(candidateRequest(readOnlyGrant));

    assert.equal(preparation.status, "denied");
    assert.match(preparation.error.details.errors.join("\n"), /capability mismatch/);
    assert.equal(writeFromRead.status, "denied");
    assert.match(writeFromRead.error.details.errors.join("\n"), /capability mismatch/);
  });

  it("rejects target, value, scope, duration, network, session, owner, and application widening", function () {
    const mutations = [
      candidateRequest(activeGrant(), { target: "target-2" }),
      candidateRequest(activeGrant(), { value: "1 ETH" }),
      candidateRequest(activeGrant(), {
        scope: { applicationId: "ethereum-net", chainId: 8453, action: "send_eth", resource: "target-2" }
      }),
      candidateRequest(activeGrant(), { requestedDurationSeconds: 301 }),
      candidateRequest(activeGrant(), { chainId: 1 }),
      candidateRequest(activeGrant(), { lifecycleSnapshot: lifecycleSnapshot({ sessionId: "other-session" }) }),
      candidateRequest(activeGrant(), { userSessionContext: userSessionContext({ ownerCommitment: "0x9999" }) }),
      candidateRequest(activeGrant(), { applicationId: "nft-manager" })
    ];

    for (const request of mutations) {
      const result = createAuthorizationDecisionCandidate(request);
      assert.equal(result.status, "denied");
      assert.equal(result.value, undefined);
    }
  });

  it("requires additional approval when a previously approved action digest preview changes", function () {
    const grant = activeGrant();
    const approved = createAuthorizationActionDigestPreview({
      intentId: "authorization-intent-1",
      actionType: "transaction_submission",
      applicationId: "ethereum-net",
      sessionId: "authorization-session-1",
      ownerCommitment: "0x1234",
      requiredCapability: "request_transaction_submission",
      target: "target-1",
      method: "send_eth",
      value: "0.01 ETH",
      scope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "target-1"
      },
      requestedDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      consumerDataReference: "consumer-data-v1",
      issuedAt: "approved-issued-at",
      expiresAt: "approved-expires-at",
      auditCorrelationId: "authorization-audit-1"
    }).digestPreview;
    const result = createAuthorizationDecisionCandidate(candidateRequest(grant, {
      consumerDataReference: "consumer-data-v2",
      approvedActionDigestPreview: approved
    }));

    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "additional_user_approval_required");
    assert.equal(result.value, undefined);
  });

  it("keeps digest previews sensitive to exact action data without creating proof input hashes", function () {
    const base = {
      intentId: "intent-digest",
      actionType: "transaction_submission",
      applicationId: "ethereum-net",
      sessionId: "authorization-session-1",
      ownerCommitment: "0x1234",
      requiredCapability: "request_transaction_submission",
      target: "target-1",
      method: "send_eth",
      value: "0.01 ETH",
      scope: { applicationId: "ethereum-net", action: "send_eth", resource: "target-1" },
      requestedDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      consumerDataReference: "consumer-data-v1",
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "authorization-audit-1"
    };
    const digest = createAuthorizationActionDigestPreview(base);
    const targetDigest = createAuthorizationActionDigestPreview({ ...base, target: "target-2" });
    const valueDigest = createAuthorizationActionDigestPreview({ ...base, value: "1 ETH" });
    const methodDigest = createAuthorizationActionDigestPreview({ ...base, method: "contract_call" });

    assert.notEqual(digest.digestPreview, targetDigest.digestPreview);
    assert.notEqual(digest.digestPreview, valueDigest.digestPreview);
    assert.notEqual(digest.digestPreview, methodDigest.digestPreview);
    assert.equal(digest.actionUnlockAssembled, false);
    assert.equal(digest.proofInputHashCreated, false);
    assert.equal(digest.authorizationPackageCreated, false);
  });

  it("collects candidates and facade audit output without mutating authority", function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const candidateStore = createInMemoryAuthorizationDecisionCandidateStore({ maxCandidateCount: 2 });
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      authorizationCandidateConsumptionStore: createEphemeralAuthorizationCandidateConsumptionStore(),
      authorizationDecisionCandidateStore: candidateStore
    });
    const result = api.requestAuthorizationDecisionCandidate(candidateRequest(activeGrant()));

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.authorizationDecisionCandidate.authorizationPackageCreated, false);
    assert.equal(result.value.authorizationDecisionCandidateCollectionResult.status, "collected");
    assert.equal(candidateStore.count(), 1);
    assert.equal(auditCollector.count(), 2);
  });

  it("guards the in-memory candidate store with duplicates, eviction, frozen returns, and no persistence", function () {
    const store = createInMemoryAuthorizationDecisionCandidateStore({ maxCandidateCount: 1 });
    const first = createAuthorizationDecisionCandidate(candidateRequest(activeGrant(), {
      requestId: "candidate-one",
      intent: { ...candidateRequest().intent, intentId: "intent-one" }
    })).value;
    const second = createAuthorizationDecisionCandidate(candidateRequest(activeGrant(), {
      requestId: "candidate-two",
      intent: { ...candidateRequest().intent, intentId: "intent-two" }
    })).value;
    const added = store.addCandidate(first);
    const duplicate = store.addCandidate(first);
    const boundedAdd = store.addCandidate(second);
    const all = store.getAll();

    assert.equal(added.status, "collected");
    assert.equal(duplicate.status, "duplicate_rejected");
    assert.equal(boundedAdd.status, "collected");
    assert.equal(store.count(), 1);
    assert.equal(all[0].authorizationDecisionCandidateId, second.authorizationDecisionCandidateId);
    assert.equal(store.getById(first.authorizationDecisionCandidateId), undefined);
    assert.equal(Object.isFrozen(all), true);
    assert.equal(boundedAdd.persisted, false);
  });
});

describe("PhilCore Alpha 0 authorization decision candidate diagnostic", function () {
  it("shows an exact action candidate as bounded and non-authoritative", function () {
    const result = runShell([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_authorization_decision_candidate",
      "--json"
    ]);
    assert.equal(result.status, 0, result.stderr);
    const json = JSON.parse(result.stdout);

    assert.equal(json.finalStatus, "succeeded");
    assert.equal(json.authorizationDecisionCandidate.status, "candidate_created");
    assert.equal(json.authorizationDecisionCandidate.authorizationPackageCreated, false);
    assert.equal(json.authorizationDecisionCandidate.actionAuthorized, false);
    assert.equal(json.authorizationDecisionCandidate.proofInputHashCreated, false);
    assert.equal(json.authorizationDecisionCandidate.proofExecuted, false);
    assert.equal(json.authorizationDecisionCandidate.signatureCreated, false);
    assert.equal(json.authorizationDecisionCandidate.sessionKeyCreated, false);
    assert.equal(json.authorizationDecisionCandidate.adapterExecutionAllowed, false);
    assert.equal(json.authorizationDecisionCandidate.transactionSubmitted, false);
    assert.equal(json.authorizationDecisionCandidate.vaultAccessed, false);
  });

  it("shows capability mismatch and additional approval diagnostics as rejected candidates only", function () {
    for (const scenario of ["capability_mismatch", "additional_approval_required"]) {
      const result = runShell([
        "--lifecycle",
        "--lifecycle-sequence",
        "production_authorization_decision_candidate",
        "--authorization-candidate-scenario",
        scenario,
        "--json"
      ]);
      assert.equal(result.status, 0, result.stderr);
      const json = JSON.parse(result.stdout);

      assert.equal(json.finalStatus, "succeeded");
      assert.equal(json.authorizationDecisionCandidate.status, "rejected");
      assert.equal(json.authorizationDecisionCandidate.authorizationDecisionCandidateCreated, false);
      assert.equal(json.authorizationDecisionCandidate.authorizationPackageCreated, false);
      assert.equal(json.authorizationDecisionCandidate.actionAuthorized, false);
      assert.equal(json.authorizationDecisionCandidate.proofInputHashCreated, false);
      assert.equal(json.authorizationDecisionCandidate.adapterExecutionAllowed, false);
      assert.equal(json.authorizationDecisionCandidate.transactionSubmitted, false);
    }
  });
});
