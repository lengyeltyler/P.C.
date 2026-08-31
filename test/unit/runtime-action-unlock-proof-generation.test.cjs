const assert = require("node:assert/strict");
const { keccak256 } = require("ethers");

const {
  createAuthorizationDecisionCandidate,
  createAuthorizationPackageDraft,
  createAuthoritativeCapabilityGrant,
  createAuthoritativePolicyDecision,
  createEphemeralActionUnlockProofGenerationConsumptionStore,
  createEphemeralActionUnlockProofVerificationConsumptionStore,
  createEphemeralFinalizedAuthorizationPackageConsumptionStore,
  createEphemeralUserApprovalArtifactConsumptionStore,
  createFixtureAuthorizationNullifierStateReader,
  createFixtureVerifiedFactStateReader,
  createInMemoryActionUnlockProofGenerationArtifactStore,
  createInMemoryActionUnlockProofVerificationResultStore,
  createInMemoryAuditDraftCollector,
  createInMemoryAuthorizationExecutionReadinessResultStore,
  createInMemoryFinalizedAuthorizationPackageStore,
  createInMemoryVerifiedFactPublicationRequestDraftStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createStaticActionUnlockProtectedWitnessProvider,
  createValidationOnlyRuntimeApi,
  createVerifiedFactPublicationRequestDraft,
  deriveCanonicalAuthorizationActionHash,
  evaluateAuthorizationExecutionReadiness,
  finalizeAuthorizationPackage,
  generateActionUnlockProof,
  validateAuthorizationExecutionReadinessResultShape,
  validateActionUnlockProofGenerationArtifact,
  validateActionUnlockProofVerificationResult,
  validateFinalizedAuthorizationPackageShape,
  validateVerifiedFactPublicationRequest,
  verifyGeneratedActionUnlockProof
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const {
  EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT,
  EXPERIMENTAL_SECRET_BEARING_PROOF_GATE
} = require("../../apps/phil-device-sdk/src/runtime/actionUnlockProofGeneration.ts");
const {
  dataHash,
  nullifier,
  policyHash
} = require("../../apps/phil-device-sdk/src/hashes.ts");
const {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic
} = require("../../apps/phil-device-sdk/src/identity.ts");

const PHIL_SECRET = "0x0000000000000000000000000000000000000000000000000000000000123456";
const NULLIFIER_SEED = "0x0000000000000000000000000000000000000000000000000000000000abcdef";
const TARGET = "0x1000000000000000000000000000000000000003";
const CONSUMER = "0x1000000000000000000000000000000000000001";
const ACCOUNT = "0x1000000000000000000000000000000000000002";
const VERIFIER = "0x1000000000000000000000000000000000000004";
const FACT_REGISTRY = "0x1000000000000000000000000000000000000005";

function safeStringify(value) {
  return JSON.stringify(value, (_key, entry) =>
    typeof entry === "bigint" ? entry.toString() : entry
  );
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 120_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function identity() {
  return derivePhilIdentityPublic(createPhilIdentityPrivate({ philSecret: PHIL_SECRET }));
}

function lifecycleSnapshot(ownerCommitment = identity().ownerCommitment, overrides = {}) {
  return Object.freeze({
    lifecycleId: "proof-lifecycle-1",
    sessionId: "proof-session-1",
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
    ownerCommitment,
    ...overrides
  });
}

function userSessionContext(ownerCommitment = identity().ownerCommitment) {
  return Object.freeze({
    sessionId: "proof-session-1",
    ownerCommitment,
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: [],
    pendingIntentIds: [],
    policyMode: "default",
    metadata: Object.freeze({ deviceVaultUnlocked: true })
  });
}

function trustDecision(ownerCommitment = identity().ownerCommitment, overrides = {}) {
  return Object.freeze({
    authoritativeTrustDecisionId: "proof-trust-decision-1",
    requestId: "proof-trust-request-1",
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: Object.freeze({
      sessionId: "proof-session-1",
      applicationId: "ethereum-net",
      ownerCommitment,
      credentialId: "cred-1",
      credentialSafeReference: "0xabcd",
      providerKind: "webauthn_passkey",
      authenticationPurpose: "high_risk_action",
      requestedAssurance: Object.freeze([
        "user_presence",
        "user_verification",
        "phishing_resistant"
      ]),
      auditCorrelationId: "proof-audit-1"
    }),
    binding: Object.freeze({
      productionVerificationResultId: "verification-1",
      boundedTrustDecisionCandidateId: "candidate-1",
      credentialCounterPersistenceReceiptId: "receipt-1",
      sessionLifecycleId: "proof-lifecycle-1",
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

function policyDecision(trust = trustDecision()) {
  const result = createAuthoritativePolicyDecision({
    requestId: "proof-policy-request-1",
    authoritativeTrustDecision: trust,
    capabilityRequest: {
      requestId: "proof-capability-request-1",
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
      policySetId: "proof-policy-set-1",
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
    lifecycleSnapshot: lifecycleSnapshot(trust.scope.ownerCommitment),
    sessionId: "proof-session-1",
    lifecycleState: "unlocked",
    ownerCommitment: trust.scope.ownerCommitment,
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
    auditCorrelationId: "proof-audit-1"
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function actionRequest(ownerCommitment = identity().ownerCommitment) {
  return Object.freeze({
    sessionId: "proof-session-1",
    applicationId: "ethereum-net",
    ownerCommitment,
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
    auditCorrelationId: "proof-audit-1"
  });
}

function approvalDecision(trust = trustDecision(), policy = policyDecision(trust)) {
  const action = actionRequest(trust.scope.ownerCommitment);
  const approvalRequest = createPlatformUserApprovalRequest({
    requestId: "proof-approval-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    lifecycleSnapshot: lifecycleSnapshot(trust.scope.ownerCommitment),
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
    auditCorrelationId: "proof-audit-1"
  });
  assert.equal(approvalRequest.status, "approved", approvalRequest.error?.details?.errors?.join("\n"));
  const decision = createPlatformUserApprovalDecision({
    requestId: "proof-approval-decision-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest: action,
    platformApprovalRequest: approvalRequest.value,
    platformApprovalArtifact: {
      platformUserApprovalArtifactId: "proof-approval-artifact-1",
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
    lifecycleSnapshot: lifecycleSnapshot(action.ownerCommitment),
    issuedAt: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "proof-audit-1"
  }, createEphemeralUserApprovalArtifactConsumptionStore());
  assert.equal(decision.status, "approved", decision.error?.details?.errors?.join("\n"));
  return decision.value;
}

function grantDecisionBundle() {
  const ownerCommitment = identity().ownerCommitment;
  const trust = trustDecision(ownerCommitment);
  const policy = policyDecision(trust);
  const approval = approvalDecision(trust, policy);
  const grantResult = createAuthoritativeCapabilityGrant({
    requestId: "proof-capability-activation-request-1",
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    platformUserApprovalDecision: approval,
    lifecycleSnapshot: lifecycleSnapshot(ownerCommitment),
    userSessionContext: userSessionContext(ownerCommitment),
    ownerCommitment,
    sessionId: "proof-session-1",
    applicationId: "ethereum-net",
    capabilityName: "request_transaction_submission",
    requestedScope: actionRequest(ownerCommitment).effectiveScope,
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
    auditCorrelationId: "proof-audit-1"
  });
  assert.equal(grantResult.status, "approved", grantResult.error?.details?.errors?.join("\n"));
  return { trust, policy, approval, grant: grantResult.value, ownerCommitment };
}

function candidateForGrant(grant, ownerCommitment) {
  const result = createAuthorizationDecisionCandidate({
    requestId: "proof-candidate-request-1",
    activeCapabilityGrant: grant,
    intent: {
      intentId: "proof-intent-1",
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
      expiresAt: futureDate(60_000)
    },
    actionType: "transaction_submission",
    lifecycleSnapshot: lifecycleSnapshot(ownerCommitment),
    userSessionContext: userSessionContext(ownerCommitment),
    ownerCommitment,
    sessionId: "proof-session-1",
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
    consumerDataReference: "proof-consumer-data-v1",
    issuedAt: now(),
    expiresAt: futureDate(60_000),
    auditCorrelationId: "proof-audit-1"
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function packageDraft() {
  const bundle = grantDecisionBundle();
  const candidate = candidateForGrant(bundle.grant, bundle.ownerCommitment);
  const expiresAt = new Date(Date.parse(candidate.validity.expiresAt) - 1_000).toISOString();
  const action = deriveCanonicalAuthorizationActionHash({
    chainId: 8453,
    consumer: CONSUMER,
    account: ACCOUNT,
    target: TARGET,
    value: 0,
    callData: "0x"
  });
  const effectivePolicyHash = policyHash({
    chainId: 8453,
    consumer: CONSUMER,
    target: TARGET,
    expiry: BigInt(Math.floor(Date.parse(expiresAt) / 1000)),
    policyDataHash: dataHash("0x")
  });
  const publicNullifier = nullifier({
    ownerCommitment: bundle.ownerCommitment,
    actionHash: action.actionHash,
    policyHash: effectivePolicyHash,
    nullifierSeed: NULLIFIER_SEED
  });
  const result = createAuthorizationPackageDraft({
    requestId: "proof-package-draft-request-1",
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
      expiresAt
    },
    chainId: 8453,
    consumer: CONSUMER,
    account: ACCOUNT,
    target: TARGET,
    method: "send_eth",
    value: 0,
    callData: "0x",
    policyData: "0x",
    nullifier: publicNullifier,
    nullifierSafeReference: "proof-public-nullifier-ref",
    issuedAt: now(),
    expiresAt,
    auditCorrelationId: "proof-audit-1"
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

function provider(overrides = {}) {
  return createStaticActionUnlockProtectedWitnessProvider({
    providerId: "proof-test-provider",
    philSecret: PHIL_SECRET,
    nullifierSeed: NULLIFIER_SEED,
    ...overrides
  });
}

function proofRequest(overrides = {}) {
  return {
    requestId: "proof-generation-request-1",
    authorizationPackageDraft: packageDraft(),
    witnessProvider: provider(),
    issuedAt: now(),
    expiresAt: futureDate(120_000),
    auditCorrelationId: "proof-audit-1",
    experimentalSecretBearingProofGate: EXPERIMENTAL_SECRET_BEARING_PROOF_GATE,
    timeoutMs: 120_000,
    includeProofBlob: true,
    ...overrides
  };
}

function publicationTarget(overrides = {}) {
  return Object.freeze({
    chainProfile: Object.freeze({
      chainId: 8453,
      network: "base",
      profileId: "ethereum-base",
      adapterId: "ethereum",
      ethereumFirstExecutionPath: true
    }),
    verifier: Object.freeze({
      verifierReference: "base-action-unlock-verifier",
      verifierAddress: VERIFIER,
      proofType: "stwo-unlock-keccak-v1"
    }),
    registry: Object.freeze({
      registryReference: "base-verified-fact-registry",
      registryAddress: FACT_REGISTRY,
      factShapeReference: "[fact_high, fact_low]"
    }),
    consumer: Object.freeze({
      consumerReference: "base-action-unlock-consumer",
      consumerAddress: CONSUMER,
      smartAccountReference: ACCOUNT
    }),
    smartAccount: Object.freeze({
      smartAccountReference: ACCOUNT,
      smartAccountAddress: ACCOUNT,
      authorityModel: "erc4337_smart_account",
      requiresPhilCoreAuthorization: true
    }),
    ...overrides
  });
}

describe("PhilCore controlled ACTION_UNLOCK witness and STARK proof generation boundary", function () {
  this.timeout(180_000);

  it("generates an explicitly quarantined synthetic research artifact through the existing Rust prover", async function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const artifactStore = createInMemoryActionUnlockProofGenerationArtifactStore();
    const result = await generateActionUnlockProof(
      proofRequest(),
      createEphemeralActionUnlockProofGenerationConsumptionStore(),
      artifactStore,
      auditCollector
    );

    assert.equal(result.status, "approved", JSON.stringify(result.error));
    assert.equal(result.value.status, "proof_generated");
    assert.equal(
      result.value.artifactClassification,
      EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT
    );
    assert.equal(result.value.proofGenerated, true);
    assert.equal(result.value.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.value.summary.proverUsed, "generate-unlock-proof-json");
    assert.equal(result.value.summary.proverInvocation, "subprocess");
    assert.equal(result.value.summary.publicInputsMatched, true);
    assert.equal(result.value.summary.proofInputHashMatched, true);
    assert.equal(result.value.proofVerifiedByRuntime, false);
    assert.equal(result.value.verifiedFactPublished, false);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(result.value.authorizationPackageFinalized, false);
    assert.equal(result.value.adapterExecutionAllowed, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.witnessMaterialExposed, false);
    assert.equal(result.value.persisted, false);
    assert.match(result.value.proofArtifact.proofDigest, /^0x[0-9a-f]{64}$/);
    assert.ok(result.value.proofArtifact.proofByteLength > 0);
    assert.equal(result.value.proofArtifact.nonSecretProofArtifact, false);
    assert.equal(result.value.proofArtifact.containsWitnessOpenings, true);
    assert.equal(
      result.value.proofArtifact.safeForExternalVerifierTransmission,
      false
    );
    assert.equal(result.value.rawWitnessFieldsReturned, false);
    assert.equal(result.value.witnessRecoverableFromProof, true);
    assert.equal(validateActionUnlockProofGenerationArtifact(result.value).valid, true);
    assert.equal(artifactStore.count(), 1);
    assert.equal(auditCollector.count() >= 1, true);

    const serialized = safeStringify(result.value);
    assert.equal(serialized.includes(PHIL_SECRET.slice(2)), false);
    assert.equal(serialized.includes(NULLIFIER_SEED.slice(2)), false);
    assert.equal(serialized.includes("philSecret"), false);
    assert.equal(serialized.includes("nullifierSeed"), false);
  });

  it("rejects ordinary generation and non-synthetic witness providers", async function () {
    const ordinary = await generateActionUnlockProof(proofRequest({
      experimentalSecretBearingProofGate: undefined
    }));
    assert.equal(ordinary.status, "denied");
    assert.match(
      ordinary.error.details.errors.join("\n"),
      /experimental secret-bearing proof gate is required/
    );

    const realSecretProvider = await generateActionUnlockProof(proofRequest({
      witnessProvider: provider({ providerKind: "local_device_vault" })
    }));
    assert.equal(realSecretProvider.status, "denied");
    assert.match(
      realSecretProvider.error.details.errors.join("\n"),
      /process-local synthetic fixture provider/
    );
  });

  it("rejects invalid draft, proofInputHash mismatch, provider unavailable, and witness binding mismatch", async function () {
    const validDraft = packageDraft();
    const expiredDraft = {
      ...validDraft,
      validity: { ...validDraft.validity, expiresAt: pastDate(), expired: true }
    };
    const cases = [
      proofRequest({ authorizationPackageDraft: expiredDraft }),
      proofRequest({ expectedProofInputHash: "0x0000000000000000000000000000000000000000000000000000000000000001" }),
      proofRequest({ witnessProvider: provider({ unavailable: true }) }),
      proofRequest({
        witnessProvider: createStaticActionUnlockProtectedWitnessProvider({
          providerId: "wrong-witness",
          philSecret: PHIL_SECRET,
          nullifierSeed: "0x0000000000000000000000000000000000000000000000000000000000000001"
        })
      })
    ];

    for (const request of cases) {
      const result = await generateActionUnlockProof(request);
      assert.notEqual(result.status, "approved");
      assert.equal(result.value, undefined);
    }
  });

  it("guards process-local replay, facade output, and no-authority semantics", async function () {
    const draft = packageDraft();
    const consumptionStore = createEphemeralActionUnlockProofGenerationConsumptionStore();
    const artifactStore = createInMemoryActionUnlockProofGenerationArtifactStore();
    const api = createValidationOnlyRuntimeApi({
      actionUnlockProofGenerationConsumptionStore: consumptionStore,
      actionUnlockProofGenerationArtifactStore: artifactStore,
      auditDraftCollector: createInMemoryAuditDraftCollector()
    });
    const request = proofRequest({
      authorizationPackageDraft: draft,
      witnessProvider: provider()
    });
    const first = await api.requestActionUnlockProofGeneration(request);
    const replay = await api.requestActionUnlockProofGeneration({
      ...request,
      witnessProvider: provider()
    });

    assert.equal(first.status, "approved", JSON.stringify(first.error));
    assert.equal(first.value.actionUnlockProofGenerationArtifact.proofGenerated, true);
    assert.equal(first.value.actionUnlockProofGenerationArtifact.verifiedFactPublished, false);
    assert.equal(first.value.actionUnlockProofGenerationArtifact.nullifierConsumed, false);
    assert.equal(first.value.actionUnlockProofGenerationArtifact.authorizationPackageFinalized, false);
    assert.equal(first.value.actionUnlockProofGenerationArtifact.adapterExecutionAllowed, false);
    assert.equal(first.value.actionUnlockProofGenerationArtifact.transactionSubmitted, false);
    assert.equal(replay.status, "denied");
    assert.equal(artifactStore.count(), 1);
  });

  it("handles prover timeout/failure without leaking witness material", async function () {
    const timeoutResult = await generateActionUnlockProof(proofRequest({ timeoutMs: 1 }));
    assert.equal(timeoutResult.status, "failed");
    const serialized = safeStringify(timeoutResult);
    assert.equal(serialized.includes(PHIL_SECRET.slice(2)), false);
    assert.equal(serialized.includes(NULLIFIER_SEED.slice(2)), false);

    const providerFailure = await generateActionUnlockProof(proofRequest({
      witnessProvider: provider({ failOnConsume: true })
    }));
    assert.equal(providerFailure.status, "failed");
  });
});

describe("PhilCore controlled ACTION_UNLOCK local proof verification and non-executing finalization boundary", function () {
  this.timeout(240_000);

  async function generatedProof(overrides = {}) {
    const result = await generateActionUnlockProof(proofRequest(overrides));
    assert.equal(result.status, "approved", JSON.stringify(result.error));
    return {
      draft: result.value.publicInputs
        ? overrides.authorizationPackageDraft ?? proofRequest(overrides).authorizationPackageDraft
        : undefined,
      artifact: result.value
    };
  }

  async function generatedProofBundle() {
    const draft = packageDraft();
    const result = await generateActionUnlockProof(proofRequest({
      authorizationPackageDraft: draft
    }));
    assert.equal(result.status, "approved", JSON.stringify(result.error));
    return { draft, artifact: result.value };
  }

  async function finalizedPackageBundle() {
    const { draft, artifact } = await generatedProofBundle();
    const verification = await verifyGeneratedActionUnlockProof({
      requestId: "proof-verification-for-publication-readiness",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(verification.status, "approved", JSON.stringify(verification.error));
    const publicInputs = artifact.publicInputs;
    const finalizedPackage = Object.freeze({
      finalizedAuthorizationPackageId: "hypothetical-witness-hiding-package",
      status: "authorization_package_finalized",
      outcome: "authorization_package_finalized",
      binding: Object.freeze({
        authorizationPackageDraftId: draft.authorizationPackageDraftId,
        proofGenerationArtifactId: "hypothetical-witness-hiding-generation",
        proofVerificationResultId: "hypothetical-witness-hiding-verification",
        sessionId: draft.binding.sessionId,
        applicationId: draft.binding.applicationId,
        intentId: draft.binding.intentId,
        capabilityName: draft.binding.capabilityName,
        ownerCommitment: draft.binding.ownerCommitment,
        proofInputHash: artifact.proofInputHash,
        auditCorrelationId: "proof-audit-1"
      }),
      actionUnlockAuthorization: Object.freeze({
        version: "v1",
        proofType: "stwo-unlock-keccak-v1",
        ...publicInputs,
        expiry: BigInt(publicInputs.expiry).toString(),
        proofInputHash: artifact.proofInputHash,
        factShapeReference: "[fact_high, fact_low]"
      }),
      proofArtifact: Object.freeze({
        proofArtifactId: "hypothetical-witness-hiding-proof",
        proofGenerationArtifactId: "hypothetical-witness-hiding-generation",
        proofVerificationResultId: "hypothetical-witness-hiding-verification",
        proofType: "stwo-unlock-keccak-v1",
        proofDigest: artifact.proofArtifact.proofDigest,
        proofByteLength: artifact.proofArtifact.proofByteLength,
        proofInputHash: artifact.proofInputHash,
        proofBlobIncluded: false,
        proofBytesLogged: false,
        nonSecretProofArtifact: true,
        containsWitnessOpenings: false,
        safeForExternalVerifierTransmission: true,
        executableByAdapters: false
      }),
      evidence: Object.freeze({
        proofGenerated: true,
        proofVerifiedLocally: true,
        proofTypeMatched: true,
        publicInputsMatched: true,
        proofInputHashMatched: true,
        factShapeValidated: true,
        localVerificationResultId: "hypothetical-witness-hiding-verification",
        verifiedProofReferenceId: "hypothetical-witness-hiding-reference"
      }),
      factShapePreview: verification.value.factShapePreview,
      validity: Object.freeze({ issuedAt: now(), expiresAt: futureDate(), expired: false }),
      limitations: Object.freeze(["local_finalization_only", "non_executing_authorization_package"]),
      authorizationPackageFinalized: true,
      proofGenerated: true,
      proofVerifiedLocally: true,
      verifiedFactPublished: false,
      onChainVerificationPerformed: false,
      nullifierConsumed: false,
      adapterExecutionAllowed: false,
      contractExecutionAllowed: false,
      transactionSubmitted: false,
      executableByApplications: false,
      witnessMaterialExposed: false,
      persisted: false
    });
    assert.equal(validateFinalizedAuthorizationPackageShape(finalizedPackage).valid, true);
    return {
      draft,
      artifact,
      verification: verification.value,
      finalizedPackage
    };
  }

  it("verifies a generated proof locally through the existing Rust verifier", async function () {
    const { draft, artifact } = await generatedProofBundle();
    const auditCollector = createInMemoryAuditDraftCollector();
    const verificationStore = createInMemoryActionUnlockProofVerificationResultStore();
    const result = await verifyGeneratedActionUnlockProof({
      requestId: "proof-verification-request-1",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1",
      timeoutMs: 120_000
    }, createEphemeralActionUnlockProofVerificationConsumptionStore(),
    verificationStore,
    auditCollector);

    assert.equal(result.status, "approved", JSON.stringify(result.error));
    assert.equal(result.value.status, "proof_verified_locally");
    assert.equal(result.value.proofVerifiedLocally, true);
    assert.equal(result.value.summary.verifierUsed, "verify-unlock-proof-json");
    assert.equal(result.value.summary.verifierInvocation, "subprocess");
    assert.equal(result.value.summary.publicInputsMatched, true);
    assert.equal(result.value.summary.proofInputHashMatched, true);
    assert.equal(result.value.factShapePreview.factShapeReference, "[fact_high, fact_low]");
    assert.match(result.value.factShapePreview.factHigh, /^0x[0-9a-f]{32}$/);
    assert.match(result.value.factShapePreview.factLow, /^0x[0-9a-f]{32}$/);
    assert.equal(result.value.verifiedFactPublished, false);
    assert.equal(result.value.onChainVerificationPerformed, false);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(result.value.adapterExecutionAllowed, false);
    assert.equal(result.value.transactionSubmitted, false);
    assert.equal(result.value.proofBytesExposedToAudit, false);
    assert.equal(result.value.witnessMaterialExposed, false);
    assert.equal(validateActionUnlockProofVerificationResult(result.value).valid, true);
    assert.equal(verificationStore.count(), 1);
    assert.equal(auditCollector.count() >= 1, true);

    const serialized = safeStringify(result.value);
    assert.equal(serialized.includes(PHIL_SECRET.slice(2)), false);
    assert.equal(serialized.includes(NULLIFIER_SEED.slice(2)), false);
    assert.equal(serialized.includes("philSecret"), false);
    assert.equal(serialized.includes("nullifierSeed"), false);
  });

  it("rejects malformed proof artifacts, tampered proof bytes, and public-input correlation mismatches", async function () {
    const { draft, artifact } = await generatedProofBundle();
    const missingBlob = {
      ...artifact,
      proofArtifact: {
        ...artifact.proofArtifact,
        proofBlob: undefined,
        proofBlobIncluded: false
      }
    };
    const tamperedBlob = "0x1234";
    const tamperedArtifact = {
      ...artifact,
      proofArtifact: {
        ...artifact.proofArtifact,
        proofBlob: tamperedBlob,
        proofDigest: keccak256(tamperedBlob),
        proofByteLength: 2
      }
    };
    const mismatchedInputs = {
      ...artifact,
      publicInputs: {
        ...artifact.publicInputs,
        actionHash: "0x0000000000000000000000000000000000000000000000000000000000000001"
      }
    };
    const requests = [
      ["missing blob", { proofGenerationArtifact: missingBlob }],
      ["tampered proof", { proofGenerationArtifact: tamperedArtifact }],
      ["mismatched inputs", { proofGenerationArtifact: mismatchedInputs }],
      ["wrong expected hash", { expectedProofInputHash: "0x0000000000000000000000000000000000000000000000000000000000000001" }]
    ];

    for (const [label, partial] of requests) {
      const result = await verifyGeneratedActionUnlockProof({
        requestId: `proof-verification-reject-${label.replaceAll(" ", "-")}`,
        authorizationPackageDraft: draft,
        proofGenerationArtifact: artifact,
        issuedAt: now(),
        expiresAt: futureDate(),
        auditCorrelationId: "proof-audit-1",
        timeoutMs: 120_000,
        ...partial
      });
      assert.notEqual(result.status, "approved", label);
      assert.equal(result.value, undefined);
    }
  });

  it("quarantines the locally verified secret-bearing proof before finalization", async function () {
    const { draft, artifact } = await generatedProofBundle();
    const verification = await verifyGeneratedActionUnlockProof({
      requestId: "proof-verification-for-finalization",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(verification.status, "approved", JSON.stringify(verification.error));

    const packageStore = createInMemoryFinalizedAuthorizationPackageStore();
    const result = finalizeAuthorizationPackage({
      requestId: "finalized-package-request-1",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      proofVerificationResult: verification.value,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    }, createEphemeralFinalizedAuthorizationPackageConsumptionStore(),
    packageStore,
    createInMemoryAuditDraftCollector());

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.equal(result.error.details.outcome, "secret_bearing_proof_quarantined");
    assert.match(
      result.error.details.errors.join("\n"),
      /secret-bearing proof artifact cannot be finalized/
    );
    assert.equal(packageStore.count(), 0);
  });

  it("guards facade/store replay and never converts finalization into execution authority", async function () {
    const { draft, artifact } = await generatedProofBundle();
    const api = createValidationOnlyRuntimeApi({
      actionUnlockProofVerificationConsumptionStore:
        createEphemeralActionUnlockProofVerificationConsumptionStore(),
      actionUnlockProofVerificationResultStore:
        createInMemoryActionUnlockProofVerificationResultStore(),
      finalizedAuthorizationPackageConsumptionStore:
        createEphemeralFinalizedAuthorizationPackageConsumptionStore(),
      finalizedAuthorizationPackageStore:
        createInMemoryFinalizedAuthorizationPackageStore(),
      auditDraftCollector: createInMemoryAuditDraftCollector()
    });
    const verificationRequest = {
      requestId: "facade-proof-verification-request",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    };
    const firstVerification = await api.requestActionUnlockProofVerification(verificationRequest);
    const replayVerification = await api.requestActionUnlockProofVerification(verificationRequest);
    assert.equal(firstVerification.status, "approved", JSON.stringify(firstVerification.error));
    assert.equal(replayVerification.status, "denied");

    const finalizationRequest = {
      requestId: "facade-finalized-package-request",
      authorizationPackageDraft: draft,
      proofGenerationArtifact: artifact,
      proofVerificationResult: firstVerification.value.actionUnlockProofVerification,
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    };
    const firstFinalization = api.requestFinalizedAuthorizationPackage(finalizationRequest);
    const replayFinalization = api.requestFinalizedAuthorizationPackage(finalizationRequest);
    assert.equal(firstFinalization.status, "denied");
    assert.equal(replayFinalization.status, "denied");
    assert.equal(firstFinalization.value.finalizedAuthorizationPackage, undefined);
    assert.equal(
      firstFinalization.value.intake.error.details.outcome,
      "secret_bearing_proof_quarantined"
    );
  });

  it("creates a verified-fact publication request draft and execution readiness snapshot without authority", async function () {
    const { finalizedPackage } = await finalizedPackageBundle();
    const auditCollector = createInMemoryAuditDraftCollector();
    const publicationStore = createInMemoryVerifiedFactPublicationRequestDraftStore();
    const readinessStore = createInMemoryAuthorizationExecutionReadinessResultStore();
    const request = {
      requestId: "publication-request-ready-1",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1",
      expectedChainId: 8453,
      expectedNetwork: "base",
      expectedProofInputHash: finalizedPackage.actionUnlockAuthorization.proofInputHash,
      expectedFactHigh: finalizedPackage.factShapePreview.factHigh,
      expectedFactLow: finalizedPackage.factShapePreview.factLow,
      expectedNullifier: finalizedPackage.actionUnlockAuthorization.nullifier
    };

    assert.equal(validateVerifiedFactPublicationRequest(request).valid, true);
    const publicationResult = createVerifiedFactPublicationRequestDraft(
      request,
      publicationStore,
      auditCollector
    );
    assert.equal(publicationResult.status, "approved", JSON.stringify(publicationResult.error));
    assert.equal(publicationResult.value.binding.proofInputHash, finalizedPackage.actionUnlockAuthorization.proofInputHash);
    assert.equal(publicationResult.value.binding.factHigh, finalizedPackage.factShapePreview.factHigh);
    assert.equal(publicationResult.value.binding.factLow, finalizedPackage.factShapePreview.factLow);
    assert.equal(publicationResult.value.payloadDraft.proofBytesIncluded, false);
    assert.equal(publicationResult.value.payloadDraft.executableCalldataIncluded, false);
    assert.equal(publicationResult.value.factPublished, false);
    assert.equal(publicationResult.value.nullifierConsumed, false);
    assert.equal(publicationResult.value.contractCalled, false);
    assert.equal(publicationResult.value.userOperationCreated, false);
    assert.equal(publicationResult.value.transactionSigned, false);
    assert.equal(publicationResult.value.transactionSubmitted, false);
    assert.equal(publicationResult.value.adapterExecuted, false);
    assert.equal(publicationResult.value.chainStateMutated, false);
    assert.equal(publicationStore.count(), 1);

    const readinessResult = await evaluateAuthorizationExecutionReadiness({
      requestId: "readiness-request-ready-1",
      publicationRequestDraft: publicationResult.value,
      factStateReader: createFixtureVerifiedFactStateReader(),
      nullifierStateReader: createFixtureAuthorizationNullifierStateReader(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1",
      expectedChainId: 8453,
      expectedNetwork: "base"
    }, readinessStore, auditCollector);

    assert.equal(readinessResult.status, "approved", JSON.stringify(readinessResult.error));
    assert.equal(readinessResult.value.outcome, "ready_for_future_execution_preparation");
    assert.equal(readinessResult.value.summary.factState, "fact_not_published");
    assert.equal(readinessResult.value.summary.nullifierState, "nullifier_available");
    assert.equal(readinessResult.value.summary.raceConditionWarning, "read_only_snapshot_must_be_revalidated_before_execution");
    assert.equal(readinessResult.value.summary.revalidationRequiredBeforeTransaction, true);
    assert.equal(readinessResult.value.summary.executionPreparationAllowedNow, false);
    assert.equal(readinessResult.value.factPublished, false);
    assert.equal(readinessResult.value.nullifierConsumed, false);
    assert.equal(readinessResult.value.contractCalled, false);
    assert.equal(readinessResult.value.userOperationCreated, false);
    assert.equal(readinessResult.value.transactionSigned, false);
    assert.equal(readinessResult.value.transactionSubmitted, false);
    assert.equal(readinessResult.value.adapterExecuted, false);
    assert.equal(readinessResult.value.chainStateMutated, false);
    assert.equal(validateAuthorizationExecutionReadinessResultShape(readinessResult.value).valid, true);
    assert.equal(readinessStore.count(), 1);
    assert.equal(auditCollector.count() >= 1, true);
  });

  it("rejects invalid finalized-package/config/correlation inputs before readiness", async function () {
    const { finalizedPackage } = await finalizedPackageBundle();
    const invalidPackageResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-invalid-package",
      finalizedAuthorizationPackage: Object.freeze({
        ...finalizedPackage,
        proofVerifiedLocally: false
      }),
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(invalidPackageResult.status, "denied");
    assert.equal(invalidPackageResult.value, undefined);

    const expiredPackageResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-expired-package",
      finalizedAuthorizationPackage: Object.freeze({
        ...finalizedPackage,
        validity: Object.freeze({
          ...finalizedPackage.validity,
          expiresAt: pastDate()
        })
      }),
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(expiredPackageResult.status, "denied");

    const correlationMismatchResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-proof-input-hash-mismatch",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1",
      expectedProofInputHash: "0x0000000000000000000000000000000000000000000000000000000000000001"
    });
    assert.equal(correlationMismatchResult.status, "denied");
    assert.equal(correlationMismatchResult.error.details.outcome, "correlation_mismatch");

    const chainMismatchResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-chain-mismatch",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget({
        chainProfile: Object.freeze({
          chainId: 1,
          network: "base",
          profileId: "ethereum-base",
          adapterId: "ethereum",
          ethereumFirstExecutionPath: true
        })
      }),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(chainMismatchResult.status, "denied");
    assert.equal(chainMismatchResult.value, undefined);

    const verifierMismatchResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-verifier-mismatch",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget({
        verifier: Object.freeze({
          verifierReference: "base-action-unlock-verifier",
          verifierAddress: VERIFIER,
          proofType: "other-proof-type"
        })
      }),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(verifierMismatchResult.status, "denied");

    const registryMismatchResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-registry-mismatch",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget({
        registry: Object.freeze({
          registryReference: "base-verified-fact-registry",
          registryAddress: FACT_REGISTRY,
          factShapeReference: "[invalid_fact_shape]"
        })
      }),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(registryMismatchResult.status, "denied");

    const consumerMismatchResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-consumer-mismatch",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget({
        consumer: Object.freeze({
          consumerReference: "",
          consumerAddress: CONSUMER,
          smartAccountReference: ACCOUNT
        })
      }),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(consumerMismatchResult.status, "denied");
  });

  it("blocks readiness on read-only fact/nullifier state without mutating chain state", async function () {
    const { finalizedPackage } = await finalizedPackageBundle();
    const publicationResult = createVerifiedFactPublicationRequestDraft({
      requestId: "publication-request-blocking-state",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(publicationResult.status, "approved", JSON.stringify(publicationResult.error));

    const cases = [
      {
        label: "fact already published",
        factState: "fact_already_published",
        nullifierState: "nullifier_available",
        outcome: "fact_already_published"
      },
      {
        label: "nullifier already consumed",
        factState: "fact_not_published",
        nullifierState: "nullifier_already_consumed",
        outcome: "nullifier_already_consumed"
      },
      {
        label: "unknown fact state",
        factState: "fact_state_unknown",
        nullifierState: "nullifier_available",
        outcome: "fact_state_unresolved"
      },
      {
        label: "unknown nullifier state",
        factState: "fact_not_published",
        nullifierState: "nullifier_state_unknown",
        outcome: "nullifier_state_unresolved"
      },
      {
        label: "reader unavailable",
        factState: "reader_unavailable",
        nullifierState: "nullifier_available",
        outcome: "fact_state_unresolved"
      }
    ];

    for (const entry of cases) {
      const result = await evaluateAuthorizationExecutionReadiness({
        requestId: `readiness-request-${entry.label.replaceAll(" ", "-")}`,
        publicationRequestDraft: publicationResult.value,
        factStateReader: createFixtureVerifiedFactStateReader({
          state: entry.factState,
          blockReference: "fixture-block:blocking",
          freshnessWindowMs: 5_000
        }),
        nullifierStateReader: createFixtureAuthorizationNullifierStateReader({
          state: entry.nullifierState,
          blockReference: "fixture-block:blocking",
          freshnessWindowMs: 5_000
        }),
        issuedAt: now(),
        expiresAt: futureDate(),
        auditCorrelationId: "proof-audit-1",
        expectedChainId: 8453,
        expectedNetwork: "base"
      });
      assert.equal(result.status, "denied", entry.label);
      assert.equal(result.error.details.outcome, entry.outcome);
      assert.equal(result.value, undefined);
      assert.equal(safeStringify(result).includes(PHIL_SECRET.slice(2)), false);
      assert.equal(safeStringify(result).includes(NULLIFIER_SEED.slice(2)), false);
    }
  });

  it("integrates facade and ephemeral stores without publishing facts or creating execution authority", async function () {
    const { finalizedPackage } = await finalizedPackageBundle();
    const publicationStore = createInMemoryVerifiedFactPublicationRequestDraftStore();
    const readinessStore = createInMemoryAuthorizationExecutionReadinessResultStore();
    const auditCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      verifiedFactPublicationRequestDraftStore: publicationStore,
      authorizationExecutionReadinessResultStore: readinessStore,
      auditDraftCollector: auditCollector
    });

    const publication = api.requestVerifiedFactPublicationDraft({
      requestId: "facade-publication-request",
      finalizedAuthorizationPackage: finalizedPackage,
      target: publicationTarget(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(publication.status, "approved", JSON.stringify(publication.error));
    assert.equal(publication.value.verifiedFactPublicationRequestDraft.factPublished, false);
    assert.equal(publication.value.verifiedFactPublicationRequestDraft.contractCalled, false);
    assert.equal(publication.value.verifiedFactPublicationRequestDraftCollectionResult.status, "collected");
    assert.equal(publicationStore.count(), 1);

    const readiness = await api.requestAuthorizationExecutionReadiness({
      requestId: "facade-readiness-request",
      publicationRequestDraft: publication.value.verifiedFactPublicationRequestDraft,
      factStateReader: createFixtureVerifiedFactStateReader(),
      nullifierStateReader: createFixtureAuthorizationNullifierStateReader(),
      issuedAt: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "proof-audit-1"
    });
    assert.equal(readiness.status, "approved", JSON.stringify(readiness.error));
    assert.equal(readiness.value.authorizationExecutionReadiness.factPublished, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.nullifierConsumed, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.contractCalled, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.userOperationCreated, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.transactionSigned, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.transactionSubmitted, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.adapterExecuted, false);
    assert.equal(readiness.value.authorizationExecutionReadiness.chainStateMutated, false);
    assert.equal(readiness.value.authorizationExecutionReadinessCollectionResult.status, "collected");
    assert.equal(readinessStore.count(), 1);
    assert.equal(auditCollector.count() >= 2, true);
    const serialized = safeStringify(readiness);
    assert.equal(serialized.includes(PHIL_SECRET.slice(2)), false);
    assert.equal(serialized.includes(NULLIFIER_SEED.slice(2)), false);
  });
});
