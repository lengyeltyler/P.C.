const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const { ethers } = require("hardhat");

const {
  createAuthorizationDecisionCandidate,
  createAuthorizationPackageDraft,
  createAuthoritativeCapabilityGrant,
  createAuthoritativePolicyDecision,
  createEphemeralAuthorizationPackageDraftConsumptionStore,
  createEphemeralUserApprovalArtifactConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryAuthorizationPackageDraftStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createValidationOnlyRuntimeApi,
  deriveCanonicalAuthorizationActionHash,
  validateAuthorizationPackageDraftShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const {
  dataHash,
  policyHash
} = require("../../apps/phil-device-sdk/src/hashes.ts");
const {
  buildUnlockProofPackageFromAuthorization
} = require("../../apps/phil-device-sdk/src/proof/publicInputs.ts");
const { deployContract } = require("../helpers/context.cjs");

const TARGET = "0x1000000000000000000000000000000000000003";
const CONSUMER = "0x1000000000000000000000000000000000000001";
const ACCOUNT = "0x1000000000000000000000000000000000000002";

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
    lifecycleId: "package-lifecycle-1",
    sessionId: "package-session-1",
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
    sessionId: "package-session-1",
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
    authoritativeTrustDecisionId: "package-trust-decision-1",
    requestId: "package-trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "package-session-1",
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
      auditCorrelationId: "package-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "package-lifecycle-1",
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

function policyDecision(trust = trustDecision(), overrides = {}) {
  const result = createAuthoritativePolicyDecision({
    requestId: "package-policy-request-1",
    authoritativeTrustDecision: trust,
    capabilityRequest: {
      requestId: "package-capability-request-1",
      applicationId: "ethereum-net",
      capability: "request_transaction_submission",
      sensitivity: "privileged",
      scope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: TARGET,
        expiresAt: futureDate()
      },
      requestedAt: now()
    },
    actionContext: {
      actionType: "send_eth",
      targetReference: TARGET,
      requestedValue: "0",
      requestedDurationSeconds: 300,
      requestedScope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: TARGET
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
          constraints: [{ constraintId: "value-1", kind: "value", value: "0" }]
        },
        {
          ruleId: "target",
          type: "restrict_target",
          effect: "restrict_target",
          constraints: [{ constraintId: "target-1", kind: "custom", value: TARGET }]
        }
      ]
    },
    lifecycleSnapshot: lifecycleSnapshot(),
    sessionId: "package-session-1",
    lifecycleState: "unlocked",
    ownerCommitment: "0x1234",
    applicationId: "ethereum-net",
    capabilityName: "request_transaction_submission",
    requestedScope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: TARGET
    },
    requestedDurationSeconds: 300,
    actionType: "send_eth",
    targetReference: TARGET,
    requestedValue: "0",
    chainId: 8453,
    network: "base",
    authenticationPurpose: "high_risk_action",
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "package-audit-1",
    ...overrides
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function actionRequest(overrides = {}) {
  return Object.freeze({
    sessionId: "package-session-1",
    applicationId: "ethereum-net",
    ownerCommitment: "0x1234",
    capabilityName: "request_transaction_submission",
    actionType: "send_eth",
    targetReference: TARGET,
    requestedValue: "0",
    effectiveScope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: TARGET
    },
    effectiveDurationSeconds: 300,
    chainId: 8453,
    network: "base",
    auditCorrelationId: "package-audit-1",
    ...overrides
  });
}

function approvalDecision(trust = trustDecision(), policy = policyDecision(trust)) {
  const action = actionRequest();
  const approvalRequest = createPlatformUserApprovalRequest({
    requestId: "package-approval-request-1",
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
      targetReference: TARGET,
      requestedValue: "0",
      effectiveScope: action.effectiveScope,
      effectiveDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      policyRestrictions: {
        effectiveDurationSeconds: 300,
        effectiveValueLimit: "0",
        effectiveTargetRestrictions: [TARGET]
      },
      expiresAt: futureDate()
    },
    requestedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "package-audit-1"
  });
  assert.equal(approvalRequest.status, "approved", approvalRequest.error?.details?.errors?.join("\n"));
  const decision = createPlatformUserApprovalDecision({
    requestId: "package-approval-decision-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    platformApprovalRequest: approvalRequest.value,
    platformApprovalArtifact: {
      platformUserApprovalArtifactId: "approval-artifact-1",
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
    auditCorrelationId: "package-audit-1"
  }, createEphemeralUserApprovalArtifactConsumptionStore());
  assert.equal(decision.status, "approved", decision.error?.details?.errors?.join("\n"));
  return decision.value;
}

function grantDecisionBundle(overrides = {}) {
  const trust = overrides.trust ?? trustDecision();
  const policy = overrides.policy ?? policyDecision(trust);
  const approval = overrides.approval ?? approvalDecision(trust, policy);
  const grantResult = createAuthoritativeCapabilityGrant({
    requestId: "package-capability-activation-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    platformUserApprovalDecision: approval,
    lifecycleSnapshot: lifecycleSnapshot(),
    userSessionContext: userSessionContext(),
    ownerCommitment: "0x1234",
    sessionId: "package-session-1",
    applicationId: "ethereum-net",
    capabilityName: "request_transaction_submission",
    requestedScope: actionRequest().effectiveScope,
    effectiveScope: policy.effectiveScope,
    requestedDurationSeconds: 300,
    effectiveDurationSeconds: policy.effectiveDurationSeconds,
    allowedTargets: policy.effectiveTargetRestrictions,
    valueLimit: policy.effectiveValueLimit,
    actionTypes: [policy.scope.actionType],
    chainId: 8453,
    network: "base",
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "package-audit-1",
    ...overrides.grantRequest
  });
  assert.equal(grantResult.status, "approved", grantResult.error?.details?.errors?.join("\n"));
  return { trust, policy, approval, grant: grantResult.value };
}

function candidateForGrant(grant, overrides = {}) {
  const request = {
    requestId: "package-candidate-request-1",
    activeCapabilityGrant: grant,
    intent: {
      intentId: "package-intent-1",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {
        chainId: 8453,
        target: TARGET,
        value: "0",
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
    sessionId: "package-session-1",
    applicationId: "ethereum-net",
    target: TARGET,
    method: "send_eth",
    value: "0",
    scope: {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: TARGET
    },
    requestedDurationSeconds: 300,
    chainId: 8453,
    network: "base",
    consumerDataReference: "package-consumer-data-v1",
    issuedAt: now(),
    expiresAt: futureDate(30_000),
    auditCorrelationId: "package-audit-1",
    ...overrides
  };
  const result = createAuthorizationDecisionCandidate(request);
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function packageDraftRequest(overrides = {}) {
  const bundle = overrides.bundle ?? grantDecisionBundle();
  const candidate = overrides.candidate ?? candidateForGrant(bundle.grant);
  const packageExpiresAt = overrides.request?.expiresAt
    ?? new Date(Date.parse(candidate.validity.expiresAt) - 1_000).toISOString();
  return {
    requestId: "package-draft-request-1",
    activeCapabilityGrant: bundle.grant,
    authorizationDecisionCandidate: candidate,
    authoritativeTrustDecision: bundle.trust,
    authoritativePolicyDecision: bundle.policy,
    platformUserApprovalDecision: bundle.approval,
    intent: {
      intentId: candidate.binding.intentId,
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: { target: TARGET, value: "0" },
      status: "created",
      createdAt: now(),
      expiresAt: packageExpiresAt
    },
    chainId: 8453,
    consumer: CONSUMER,
    account: ACCOUNT,
    target: TARGET,
    method: "send_eth",
    value: 0,
    callData: "0x",
    policyData: "0x",
    nullifier: ethers.id("package-public-nullifier"),
    nullifierSafeReference: "package-public-nullifier-ref",
    issuedAt: now(),
    expiresAt: packageExpiresAt,
    auditCorrelationId: "package-audit-1",
    ...overrides.request
  };
}

function runShell(args) {
  return spawnSync(process.execPath, ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
}

describe("PhilCore bounded ACTION_UNLOCK Authorization Package Draft boundary", function () {
  it("creates a package draft from a valid candidate without proof, nullifier consumption, or execution", function () {
    const result = createAuthorizationPackageDraft(packageDraftRequest());

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.status, "package_draft_created");
    assert.equal(result.value.outcome, "authorization_package_draft_created");
    assert.equal(result.value.actionUnlockPublicInputDraft.proofType, "stwo-unlock-keccak-v1");
    assert.deepEqual(result.value.actionUnlockPublicInputDraft.tupleFieldOrder, [
      "ownerCommitment",
      "actionHash",
      "policyHash",
      "nullifier",
      "consumerDataHash",
      "expiry"
    ]);
    assert.equal(result.value.actionUnlockPublicInputDraft.factShapeReference, "[fact_high, fact_low]");
    assert.equal(result.value.authorizationPackageDraftCreated, true);
    assert.equal(result.value.authorizationPackageExecutable, false);
    assert.equal(result.value.actionAuthorized, false);
    assert.equal(result.value.proofGenerated, false);
    assert.equal(result.value.proofVerified, false);
    assert.equal(result.value.verifiedFactAvailable, false);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(result.value.adapterExecutionAllowed, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.signatureCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.vaultAccessed, false);
    assert.equal(validateAuthorizationPackageDraftShape(result.value).valid, true);
  });

  it("reuses canonical ACTION_UNLOCK action, policy, consumerData, and proofInputHash helpers", function () {
    const request = packageDraftRequest();
    const result = createAuthorizationPackageDraft(request);
    const canonicalAction = deriveCanonicalAuthorizationActionHash({
      chainId: request.chainId,
      consumer: request.consumer,
      account: request.account,
      target: request.target,
      value: request.value,
      callData: request.callData
    });
    const expectedPolicyHash = policyHash({
      chainId: request.chainId,
      consumer: request.consumer,
      target: request.target,
      expiry: BigInt(Math.floor(Date.parse(request.expiresAt) / 1000)),
      policyDataHash: dataHash(request.policyData)
    });
    const expectedProofPackage = buildUnlockProofPackageFromAuthorization(
      result.value.baseActionAuthorization
    );

    assert.equal(result.status, "approved");
    assert.equal(result.value.hashSummary.actionHash, canonicalAction.actionHash);
    assert.equal(result.value.hashSummary.policyHash, expectedPolicyHash);
    assert.equal(result.value.hashSummary.consumerDataHash, canonicalAction.consumerDataHash);
    assert.equal(
      result.value.hashSummary.proofInputHash,
      expectedProofPackage.proofInputHash
    );
    assert.equal(result.value.hashSummary.m1PreviewIsCanonicalActionHash, false);
    assert.notEqual(
      result.value.hashSummary.m1ActionDigestPreview,
      result.value.hashSummary.actionHash
    );
  });

  it("rejects invalid grants, expired candidates, widened expiry, and evidence mismatches", function () {
    const bundle = grantDecisionBundle();
    const candidate = candidateForGrant(bundle.grant);
    const inactiveGrant = { ...bundle.grant, status: "revoked" };
    const expiredCandidate = {
      ...candidate,
      validity: { ...candidate.validity, expiresAt: pastDate(), expired: true }
    };
    const trustMismatch = { ...bundle.trust, authoritativeTrustDecisionId: "other-trust" };
    const policyMismatch = { ...bundle.policy, authoritativePolicyDecisionId: "other-policy" };
    const approvalMismatch = { ...bundle.approval, platformUserApprovalDecisionId: "other-approval" };
    const mismatches = [
      packageDraftRequest({ bundle, candidate, request: { activeCapabilityGrant: inactiveGrant } }),
      packageDraftRequest({ bundle, candidate: expiredCandidate }),
      packageDraftRequest({ bundle, candidate, request: { expiresAt: futureDate(120_000) } }),
      packageDraftRequest({ bundle: { ...bundle, trust: trustMismatch }, candidate }),
      packageDraftRequest({ bundle: { ...bundle, policy: policyMismatch }, candidate }),
      packageDraftRequest({ bundle: { ...bundle, approval: approvalMismatch }, candidate }),
      packageDraftRequest({ bundle, candidate, request: { auditCorrelationId: "other-audit" } })
    ];

    for (const request of mismatches) {
      const result = createAuthorizationPackageDraft(request);
      assert.equal(result.status, "denied");
      assert.equal(result.value, undefined);
    }
  });

  it("rejects action, target, method, value, consumer data, nullifier, and proofInputHash mutations", function () {
    const request = packageDraftRequest();
    const valid = createAuthorizationPackageDraft(request);
    const cases = [
      packageDraftRequest({ request: { expectedActionHash: ethers.id("wrong-action") } }),
      packageDraftRequest({ request: { target: "0x1000000000000000000000000000000000000004" } }),
      packageDraftRequest({ request: { method: "unexpected_method" } }),
      packageDraftRequest({ request: { value: 1 } }),
      packageDraftRequest({ request: { expectedPolicyHash: ethers.id("wrong-policy") } }),
      packageDraftRequest({ request: { expectedConsumerDataHash: ethers.id("wrong-consumer") } }),
      packageDraftRequest({ request: { expectedProofInputHash: ethers.id("wrong-proof") } }),
      packageDraftRequest({ request: { nullifier: "0x1234" } }),
      packageDraftRequest({ request: { nullifierSeed: ethers.id("forbidden") } })
    ];

    assert.equal(valid.status, "approved");
    for (const mutated of cases) {
      const result = createAuthorizationPackageDraft(mutated);
      assert.equal(result.status, "denied");
      assert.equal(result.value, undefined);
    }
  });

  it("changes proofInputHash when each public tuple field changes", function () {
    const base = createAuthorizationPackageDraft(packageDraftRequest()).value;
    const mutations = [
      packageDraftRequest({ request: { account: "0x1000000000000000000000000000000000000004" } }),
      packageDraftRequest({ request: { policyData: "0x1234" } }),
      packageDraftRequest({ request: { nullifier: ethers.id("other-nullifier") } }),
      packageDraftRequest({ request: { callData: "0x1234" } }),
      packageDraftRequest({ request: { expiresAt: futureDate(20_000) } })
    ];

    for (const mutation of mutations) {
      const result = createAuthorizationPackageDraft(mutation);
      assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
      assert.notEqual(result.value.hashSummary.proofInputHash, base.hashSummary.proofInputHash);
    }
  });

  it("guards process-local draft replay, duplicate nullifiers, facade output, and in-memory collection", function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const consumptionStore = createEphemeralAuthorizationPackageDraftConsumptionStore();
    const draftStore = createInMemoryAuthorizationPackageDraftStore({ maxDraftCount: 1 });
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      authorizationPackageDraftConsumptionStore: consumptionStore,
      authorizationPackageDraftStore: draftStore
    });
    const request = packageDraftRequest();
    const first = api.requestAuthorizationPackageDraft(request);
    const replay = api.requestAuthorizationPackageDraft(request);
    const differentEvidenceSameNullifier = api.requestAuthorizationPackageDraft(packageDraftRequest({
      request: { requestId: "package-draft-request-2" }
    }));

    assert.equal(first.status, "approved", first.error?.details?.errors?.join("\n"));
    assert.equal(first.value.authorizationPackageDraft.authorizationPackageExecutable, false);
    assert.equal(first.value.authorizationPackageDraftCollectionResult.status, "collected");
    assert.equal(replay.status, "denied");
    assert.equal(differentEvidenceSameNullifier.status, "denied");
    assert.equal(draftStore.count(), 1);
    assert.equal(auditCollector.count(), 4);
  });

  it("matches Solidity proofInputHash parity for the draft proof package", async function () {
    const [deployer] = await ethers.getSigners();
    const gate = await deployContract(deployer, "PhilBaseActionGate", [ethers.ZeroAddress]);
    const harness = await deployContract(deployer, "PhilHashHarness");
    const draft = createAuthorizationPackageDraft(packageDraftRequest()).value;

    assert.equal(
      await harness.computeUnlockProofInputHash(draft.actionUnlockPublicInputDraft.proofPackageDraft),
      draft.hashSummary.proofInputHash
    );
    assert.equal(
      await gate.computeProofInputHash(draft.actionUnlockPublicInputDraft.proofPackageDraft),
      draft.hashSummary.proofInputHash
    );
  });
});

describe("PhilCore Alpha 0 Authorization Package Draft diagnostic", function () {
  it("shows exact package draft as non-executable and proofless", function () {
    const result = runShell([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_authorization_package_draft",
      "--json"
    ]);
    assert.equal(result.status, 0, result.stderr);
    const json = JSON.parse(result.stdout);

    assert.equal(json.finalStatus, "succeeded");
    assert.equal(json.authorizationPackageDraft.status, "package_draft_created");
    assert.equal(json.authorizationPackageDraft.proofType, "stwo-unlock-keccak-v1");
    assert.equal(json.authorizationPackageDraft.factShapeReference, "[fact_high, fact_low]");
    assert.equal(json.authorizationPackageDraft.authorizationPackageExecutable, false);
    assert.equal(json.authorizationPackageDraft.actionAuthorized, false);
    assert.equal(json.authorizationPackageDraft.proofGenerated, false);
    assert.equal(json.authorizationPackageDraft.proofVerified, false);
    assert.equal(json.authorizationPackageDraft.nullifierConsumed, false);
    assert.equal(json.authorizationPackageDraft.adapterExecutionAllowed, false);
    assert.equal(json.authorizationPackageDraft.transactionSubmitted, false);
  });

  it("shows mutated action, invalid nullifier, and consumer-data mismatch as rejected diagnostics only", function () {
    for (const scenario of ["mutated_action", "invalid_nullifier", "consumer_data_mismatch"]) {
      const result = runShell([
        "--lifecycle",
        "--lifecycle-sequence",
        "production_authorization_package_draft",
        "--authorization-package-draft-scenario",
        scenario,
        "--json"
      ]);
      assert.equal(result.status, 0, result.stderr);
      const json = JSON.parse(result.stdout);

      assert.equal(json.finalStatus, "succeeded");
      assert.equal(json.authorizationPackageDraft.status, "rejected");
      assert.equal(json.authorizationPackageDraft.authorizationPackageDraftCreated, false);
      assert.equal(json.authorizationPackageDraft.authorizationPackageExecutable, false);
      assert.equal(json.authorizationPackageDraft.proofGenerated, false);
      assert.equal(json.authorizationPackageDraft.nullifierConsumed, false);
      assert.equal(json.authorizationPackageDraft.adapterExecutionAllowed, false);
      assert.equal(json.authorizationPackageDraft.transactionSubmitted, false);
    }
  });
});
