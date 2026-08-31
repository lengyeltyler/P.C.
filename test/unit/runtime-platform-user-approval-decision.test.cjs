const assert = require("node:assert/strict");

const {
  createAuthoritativePolicyDecision,
  createEphemeralUserApprovalArtifactConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryPlatformUserApprovalDecisionStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createUserApprovalPresentationDigest,
  createValidationOnlyRuntimeApi,
  runAlpha0Shell,
  validatePlatformUserApprovalDecisionShape
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
    lifecycleId: "approval-lifecycle-1",
    sessionId: "approval-session-1",
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
    authoritativeTrustDecisionId: "approval-trust-decision-1",
    requestId: "approval-trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "approval-session-1",
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
      auditCorrelationId: "approval-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "approval-lifecycle-1",
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
  const result = createAuthoritativePolicyDecision({
    requestId: "approval-policy-request-1",
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
        }
      ]
    },
    lifecycleSnapshot: lifecycleSnapshot(),
    sessionId: "approval-session-1",
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
    auditCorrelationId: "approval-audit-1",
    ...overrides
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function actionRequest(overrides = {}) {
  return Object.freeze({
    sessionId: "approval-session-1",
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
    auditCorrelationId: "approval-audit-1",
    ...overrides
  });
}

function presentationSummary(overrides = {}) {
  return Object.freeze({
    applicationId: "ethereum-net",
    applicationName: "Ethereum Net",
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
    policyRestrictions: {
      effectiveDurationSeconds: 300,
      effectiveValueLimit: "0.01 ETH",
      effectiveTargetRestrictions: ["target-1"]
    },
    riskDisclosures: [{
      disclosureId: "risk-1",
      summary: "Transaction submission requires explicit approval.",
      severity: "medium"
    }],
    expiresAt: futureDate(),
    ...overrides
  });
}

function approvalRequest(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const policy = overrides.policy ?? policyDecision();
  const action = overrides.action ?? actionRequest();
  const summary = overrides.summary ?? presentationSummary();
  const result = createPlatformUserApprovalRequest({
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
    auditCorrelationId: "approval-audit-1",
    ...overrides.input
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function artifact(request, overrides = {}) {
  return Object.freeze({
    platformUserApprovalArtifactId: "approval-artifact-1",
    platformUserApprovalRequestId: request.platformUserApprovalRequestId,
    approvalSurface: request.approvalSurface,
    outcome: "approved",
    decidedAt: now(),
    presentationDigest: request.presentationDigest,
    approvalChallengeReference: request.approvalChallengeReference,
    sessionId: request.actionRequest.sessionId,
    applicationId: request.actionRequest.applicationId,
    ownerCommitment: request.actionRequest.ownerCommitment,
    deviceReference: "device-safe-ref-1",
    platformProviderReference: "desktop-local-platform",
    userPresenceIndicated: true,
    userVerificationIndicated: true,
    productionBound: true,
    fixtureOnly: false,
    expiresAt: futureDate(),
    auditCorrelationId: request.auditCorrelationId,
    biometricTemplateIncluded: false,
    rawPlatformSecretIncluded: false,
    rawPrivateKeyIncluded: false,
    rawWebAuthnPrivateMaterialIncluded: false,
    vaultMaterialIncluded: false,
    credentialRecordIncluded: false,
    authorizationPackageIncluded: false,
    adapterPayloadIncluded: false,
    ...overrides
  });
}

function decisionRequest(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const policy = overrides.policy ?? policyDecision();
  const action = overrides.action ?? actionRequest();
  const request = overrides.approvalRequest ?? approvalRequest({ trust, policy, action });
  const approvalArtifact = overrides.artifact ?? artifact(request);
  return {
    requestId: "platform-approval-decision-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    platformApprovalRequest: request,
    platformApprovalArtifact: approvalArtifact,
    lifecycleSnapshot: lifecycleSnapshot(),
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "approval-audit-1",
    ...overrides.request
  };
}

function approvalBundle() {
  const trust = trustDecision();
  const policy = policyDecision();
  const action = actionRequest();
  const request = approvalRequest({ trust, policy, action });
  return Object.freeze({ trust, policy, action, request });
}

describe("PhilCore bounded Platform User Approval Decision boundary", function () {
  it("creates an approved platform decision bound to the exact visible action without authority", function () {
    const result = createPlatformUserApprovalDecision(decisionRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "user_approved");
    assert.equal(result.value.userApprovalDecisionCreated, true);
    assert.equal(result.value.userApproved, true);
    assert.equal(result.value.trustDecisionAccepted, true);
    assert.equal(result.value.policyDecisionAccepted, true);
    assert.equal(result.value.presentationDigestMatched, true);
    assert.equal(result.value.validForExactRequestOnly, true);
    assert.equal(result.value.capabilityGranted, false);
    assert.equal(result.value.authorizationCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.executionAllowed, false);
    assert.equal(result.value.proofExecuted, false);
    assert.equal(result.value.adapterExecuted, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.biometricTemplateStored, false);
    assert.equal(result.value.rawPlatformSecretIncluded, false);
    assert.equal(validatePlatformUserApprovalDecisionShape(result.value).valid, true);
  });

  it("records deny, cancel, and expired outcomes without activation eligibility", function () {
    const bundle = approvalBundle();
    const denied = createPlatformUserApprovalDecision(decisionRequest({
      trust: bundle.trust,
      policy: bundle.policy,
      action: bundle.action,
      approvalRequest: bundle.request,
      artifact: artifact(bundle.request, { platformUserApprovalArtifactId: "deny-artifact", outcome: "denied" })
    }));
    const cancelled = createPlatformUserApprovalDecision(decisionRequest({
      trust: bundle.trust,
      policy: bundle.policy,
      action: bundle.action,
      approvalRequest: bundle.request,
      artifact: artifact(bundle.request, { platformUserApprovalArtifactId: "cancel-artifact", outcome: "cancelled" })
    }));
    const expired = createPlatformUserApprovalDecision(decisionRequest({
      trust: bundle.trust,
      policy: bundle.policy,
      action: bundle.action,
      approvalRequest: bundle.request,
      artifact: artifact(bundle.request, {
        platformUserApprovalArtifactId: "expired-artifact",
        outcome: "expired",
        expiresAt: pastDate()
      })
    }));

    assert.equal(denied.status, "approved");
    assert.equal(denied.value.outcome, "user_denied");
    assert.equal(denied.value.eligibleForCapabilityActivationReview, false);
    assert.equal(cancelled.value.outcome, "user_cancelled");
    assert.equal(cancelled.value.eligibleForCapabilityActivationReview, false);
    assert.equal(expired.value.outcome, "approval_expired");
    assert.equal(expired.value.approvalExpired, true);
    assert.equal(expired.value.eligibleForCapabilityActivationReview, false);
  });

  it("rejects presentation digest mismatch and hidden target/value/scope/duration mutations", function () {
    const req = approvalRequest();
    const badDigest = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      artifact: artifact(req, {
        platformUserApprovalArtifactId: "bad-digest-artifact",
        presentationDigest: createUserApprovalPresentationDigest({
          ...presentationSummary(),
          targetReference: "evil-target"
        })
      })
    }));
    const target = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ targetReference: "evil-target" })
    }));
    const value = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ requestedValue: "1 ETH" })
    }));
    const scope = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ effectiveScope: { action: "call_contract" } })
    }));
    const duration = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ effectiveDurationSeconds: 999 })
    }));

    assert.equal(badDigest.status, "denied");
    assert.equal(target.status, "denied");
    assert.equal(value.status, "denied");
    assert.equal(scope.status, "denied");
    assert.equal(duration.status, "denied");
  });

  it("rejects Trust, Policy, session, owner, application, capability, action, and audit mismatches", function () {
    const req = approvalRequest();
    const trustMismatch = createPlatformUserApprovalDecision(decisionRequest({
      trust: trustDecision({
        authoritativeTrustDecisionId: "different-trust"
      }),
      approvalRequest: req
    }));
    const policyMismatch = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: {
        ...req,
        authoritativePolicyDecisionId: "different-policy"
      }
    }));
    const session = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ sessionId: "other-session" })
    }));
    const owner = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ ownerCommitment: "0x9999" })
    }));
    const app = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ applicationId: "nft-manager" })
    }));
    const capability = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ capabilityName: "view_nfts" })
    }));
    const action = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      action: actionRequest({ actionType: "sign_message" })
    }));
    const audit = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      request: { auditCorrelationId: "other-audit" }
    }));

    for (const result of [trustMismatch, policyMismatch, session, owner, app, capability, action, audit]) {
      assert.equal(result.status, "denied");
    }
  });

  it("rejects unsupported and fixture surfaces for production approval decisions", function () {
    const req = approvalRequest();
    const fixture = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      artifact: artifact(req, {
        platformUserApprovalArtifactId: "fixture-artifact",
        approvalSurface: "developer_fixture",
        productionBound: false,
        fixtureOnly: true
      })
    }));
    const unsupported = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      artifact: artifact(req, {
        platformUserApprovalArtifactId: "unsupported-artifact",
        approvalSurface: "unsupported"
      })
    }));

    assert.equal(fixture.status, "denied");
    assert.equal(unsupported.status, "denied");
  });

  it("rejects replayed artifacts and stores accepted decisions ephemerally", function () {
    const replayStore = createEphemeralUserApprovalArtifactConsumptionStore();
    const decisionStore = createInMemoryPlatformUserApprovalDecisionStore({ maxDecisionCount: 1 });
    const bundle = approvalBundle();
    const firstRequest = decisionRequest({
      trust: bundle.trust,
      policy: bundle.policy,
      action: bundle.action,
      approvalRequest: bundle.request
    });
    const first = createPlatformUserApprovalDecision(firstRequest, replayStore, decisionStore);
    const replay = createPlatformUserApprovalDecision(firstRequest, replayStore, decisionStore);
    const secondPolicy = policyDecision({ requestId: "second-policy-request" });
    const secondAction = actionRequest();
    const secondReq = approvalRequest({
      policy: secondPolicy,
      action: secondAction,
      input: { requestId: "second-approval-request" }
    });
    const second = createPlatformUserApprovalDecision(decisionRequest({
      policy: secondPolicy,
      action: secondAction,
      approvalRequest: secondReq,
      artifact: artifact(secondReq, { platformUserApprovalArtifactId: "second-artifact" }),
      request: { requestId: "second-decision-request" }
    }), undefined, decisionStore);

    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(second.status, "approved");
    assert.equal(decisionStore.count(), 1);
    assert.equal(decisionStore.getById(first.value.platformUserApprovalDecisionId), undefined);
    assert.equal(decisionStore.getById(second.value.platformUserApprovalDecisionId).userApproved, true);
  });

  it("rejects obvious private/platform/vault material leakage", function () {
    const req = approvalRequest();
    const result = createPlatformUserApprovalDecision(decisionRequest({
      approvalRequest: req,
      artifact: artifact(req, {
        platformUserApprovalArtifactId: "leaky-artifact",
        metadata: { biometricTemplate: "nope" }
      })
    }));

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
  });

  it("integrates through the facade with sanitized audit drafts and optional store", function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const decisionStore = createInMemoryPlatformUserApprovalDecisionStore();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      userApprovalArtifactConsumptionStore: createEphemeralUserApprovalArtifactConsumptionStore(),
      platformUserApprovalDecisionStore: decisionStore
    });
    const result = api.requestPlatformUserApprovalDecision(decisionRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.platformUserApprovalDecision.userApproved, true);
    assert.equal(result.value.platformUserApprovalDecisionCollectionResult.status, "collected");
    assert.equal(result.value.auditEventDraft.redactedDetails.platformUserApprovalDecisionUserApproved, true);
    assert.equal(result.value.auditEventDraft.redactedDetails.platformUserApprovalDecisionCapabilityGranted, false);
    assert.equal(result.value.auditEventDraft.redactedDetails.platformUserApprovalDecisionAuthorizationCreated, false);
    assert.equal(auditDraftCollector.count() >= 1, true);
    assert.equal(decisionStore.count(), 1);
  });

  it("runs Alpha 0 platform approval diagnostics in text and JSON modes", async function () {
    const textChunks = [];
    const jsonChunks = [];
    const textOutput = { write: (chunk) => textChunks.push(String(chunk)) };
    const jsonOutput = { write: (chunk) => jsonChunks.push(String(chunk)) };

    const textExit = await runAlpha0Shell({
      argv: [
        "--lifecycle",
        "--lifecycle-sequence",
        "production_platform_user_approval_decision",
        "--approval-outcome",
        "approve"
      ],
      output: textOutput,
      errorOutput: textOutput
    });
    const jsonExit = await runAlpha0Shell({
      argv: [
        "--lifecycle",
        "--lifecycle-sequence",
        "production_platform_user_approval_decision",
        "--approval-outcome",
        "digest_mismatch",
        "--json"
      ],
      output: jsonOutput,
      errorOutput: jsonOutput
    });

    assert.equal(textExit.exitCode, 0);
    assert.equal(textChunks.join("").includes("Platform User Approval Decision"), true);
    assert.equal(textChunks.join("").includes("capability grant created: no"), true);
    assert.equal(jsonExit.exitCode, 0);
    const parsed = JSON.parse(jsonChunks.join(""));
    assert.equal(parsed.platformUserApprovalDecision.outcome, "presentation_digest_mismatch");
    assert.equal(parsed.platformUserApprovalDecision.capabilityGranted, false);
    assert.equal(parsed.platformUserApprovalDecision.authorizationCreated, false);
    assert.equal(parsed.platformUserApprovalDecision.executionAllowed, false);
  });
});
