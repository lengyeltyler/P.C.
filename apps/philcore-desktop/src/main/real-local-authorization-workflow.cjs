const { ethers } = require("hardhat");
const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const runtime = require("../../../phil-device-sdk/src/runtime/index.ts");
const hashes = require("../../../phil-device-sdk/src/hashes.ts");
const proofInputs = require("../../../phil-device-sdk/src/proof/publicInputs.ts");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  PHILCORE_4337_EMPTY_BYTES,
  createAuthorizationDecisionCandidate,
  createAuthorizationPackageDraft,
  createAuthoritativeCapabilityGrant,
  createAuthoritativePolicyDecision,
  createBaseMirroredFactEvidence,
  createFixtureBaseExecutionFeeDataReader,
  createFixtureBaseExecutionGasEstimator,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createStaticActionUnlockProtectedWitnessProvider,
  deriveCanonicalAuthorizationActionHash,
  finalizeAuthorizationPackage,
  generateActionUnlockProof,
  prepareBaseAuthorizationExecutionTransaction,
  preparePhilCore4337UserOperation,
  signPhilCore4337UserOperation,
  verifyGeneratedActionUnlockProof
} = runtime;

const {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  dataHash,
  nullifier,
  policyHash
} = hashes;

const { buildUnlockProofPackageFromAuthorization } = proofInputs;

const APPLICATION_ID = "ethereum-net";
const APPLICATION_NAME = "Ethereum Net";
const CAPABILITY_NAME = "request_contract_call";
const WORKFLOW_VERSION = "philcore-desktop-real-local-authorization-o5-v1";
const HYPOTHETICAL_STACK_CLASSIFICATION =
  "HYPOTHETICAL_WITNESS_HIDING_TEST_STACK_NOT_AN_IMPLEMENTATION";
const NOIR_ALPHA_STACK_CLASSIFICATION =
  "PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_LOCAL_ALPHA_V1";

function proofStackFor(input) {
  const injected = input.testOnlyHypotheticalWitnessHidingProofStack;
  if (injected !== undefined) {
    if (injected?.classification !== HYPOTHETICAL_STACK_CLASSIFICATION
      || typeof injected.generateActionUnlockProof !== "function"
      || typeof injected.verifyGeneratedActionUnlockProof !== "function"
      || typeof injected.finalizeAuthorizationPackage !== "function") {
      throw new Error("invalid hypothetical witness-hiding test stack");
    }
    return injected;
  }
  const selected = input.rootProofStack;
  if (selected !== undefined) {
    if (selected?.classification !== NOIR_ALPHA_STACK_CLASSIFICATION
      || typeof selected.generateActionUnlockProof !== "function"
      || typeof selected.verifyGeneratedActionUnlockProof !== "function"
      || typeof selected.finalizeAuthorizationPackage !== "function") {
      throw new Error("invalid Noir root-proof Alpha stack");
    }
    return selected;
  }
  {
    return {
      generateActionUnlockProof,
      verifyGeneratedActionUnlockProof,
      finalizeAuthorizationPackage
    };
  }
}

function nowIso() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function shortRef(value) {
  const text = String(value || "");
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-6)}`;
}

function freeze(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function stage(id, label, evidenceClass, status, details = {}) {
  return freeze({
    id,
    label,
    evidenceClass,
    status,
    at: nowIso(),
    details
  });
}

function assertApproved(result, label) {
  if (result?.status !== "approved" || !result.value) {
    const reason = result?.error?.details?.errors?.join("; ")
      || result?.error?.message
      || result?.status
      || "unknown failure";
    throw new Error(`${label}: ${reason}`);
  }
  return result.value;
}

function hexPairFromProofInputHash(proofInputHash) {
  const raw = String(proofInputHash).slice(2).padStart(64, "0");
  return {
    factHigh: `0x${raw.slice(0, 32)}`,
    factLow: `0x${raw.slice(32)}`
  };
}

function proofBlobForFact(factHigh, factLow) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint256"],
    [BigInt(factHigh), BigInt(factLow)]
  );
}

function encodeUnlockRequest(request) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    [request]
  );
}

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
}

async function deployLocalContracts({ ownerAddress, ownerCommitment }) {
  const [deployer, beneficiary, l1RemoteSender, localTarget] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const baseMessenger = await deploy("MockBaseCrossDomainMessenger", deployer);
  const adapter = await deploy("PhilBaseCrossDomainMessengerAdapter", deployer, [
    await baseMessenger.getAddress(),
    200000
  ]);
  const baseMirror = await deploy("PhilBaseProofInputHashMirror", deployer, [
    await baseMessenger.getAddress(),
    await adapter.getAddress()
  ]);
  const verifier = await deploy("PhilBaseMirroredFactUnlockProofVerifier", deployer, [
    await baseMirror.getAddress()
  ]);
  const actionGate = await deploy("PhilBaseActionGate", deployer, [await verifier.getAddress()]);
  const unlockConsumer = await deploy("PhilUnlockConsumer", deployer, [await actionGate.getAddress()]);
  const accountFactory = await deploy("PhilCore4337AccountFactory", deployer, [
    await entryPoint.getAddress(),
    await actionGate.getAddress(),
    l1RemoteSender.address,
    60,
    3600
  ]);
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const predicted = await accountFactory
    .getFunction("getAddress")
    .staticCall(ownerAddress, ownerCommitment, 1n);
  await (await accountFactory.createAccount(ownerAddress, ownerCommitment, 1n)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  await (await deployer.sendTransaction({ to: predicted, value: ethers.parseEther("1") })).wait();
  return {
    deployer,
    beneficiary,
    l1RemoteSender,
    localTarget,
    entryPoint,
    baseMessenger,
    adapter,
    baseMirror,
    verifier,
    actionGate,
    unlockConsumer,
    accountFactory,
    account,
    accountAddress: predicted,
    chainId
  };
}

async function deploy(name, signer, args = []) {
  const Factory = await ethers.getContractFactory(name, signer);
  const contract = await Factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

function lifecycleSnapshot(input) {
  const now = nowIso();
  return freeze({
    lifecycleId: `${input.workflowId}:lifecycle`,
    sessionId: input.sessionId,
    state: "unlocked",
    sequence: 1,
    version: 1,
    createdAt: now,
    updatedAt: now,
    metadata: { deviceVaultUnlocked: true, protectedStateAvailable: true },
    limitations: ["desktop_local_alpha"],
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: true,
    grantsAuthority: false,
    ownerCommitment: input.ownerCommitment
  });
}

function userSessionContext(input) {
  return freeze({
    sessionId: input.sessionId,
    ownerCommitment: input.ownerCommitment,
    status: "unlocked",
    activeApplicationId: APPLICATION_ID,
    activeCapabilityIds: [],
    pendingIntentIds: [],
    policyMode: "desktop_local_alpha",
    metadata: { deviceVaultUnlocked: true, protectedStateAvailable: true }
  });
}

function trustDecision(input) {
  const now = nowIso();
  return freeze({
    authoritativeTrustDecisionId: `${input.workflowId}:trust-decision`,
    requestId: `${input.workflowId}:trust-request`,
    status: "trust_decision_created",
    outcome: "trust_decision_created",
    scope: {
      sessionId: input.sessionId,
      applicationId: APPLICATION_ID,
      ownerCommitment: input.ownerCommitment,
      credentialId: input.validator.keyReferenceId,
      credentialSafeReference: shortRef(input.validator.publicOwnerAddress),
      providerKind: "device_vault_ecdsa_local_alpha",
      authenticationPurpose: input.authenticationPurpose || "local_authorization_execution",
      requestedAssurance: ["local_device_vault_unlocked", "fresh_desktop_approval"],
      auditCorrelationId: input.auditCorrelationId
    },
    binding: {
      productionVerificationResultId: `${input.workflowId}:local-desktop-verification`,
      boundedTrustDecisionCandidateId: `${input.workflowId}:trust-candidate`,
      credentialCounterPersistenceReceiptId: `${input.workflowId}:counter-local`,
      sessionLifecycleId: `${input.workflowId}:lifecycle`,
      sessionLifecycleState: "unlocked",
      challengeReferenceId: `${input.workflowId}:desktop-challenge`,
      validityWindowId: `${input.workflowId}:trust-validity`,
      reusableAcrossSessions: false,
      reusableAcrossCredentials: false,
      reusableAcrossApplications: false,
      reusableAcrossPurposes: false,
      reusableAcrossOwners: false,
      reusableAcrossChallenges: false,
      reusableAcrossTimeWindows: false
    },
    evidence: {
      productionAssertionVerified: true,
      productionVerifierUsed: false,
      fixtureOnlyEvidence: false,
      credentialCounterCommitted: false,
      acceptedZeroCounterSemantics: true,
      persistedCounter: 0,
      verifiedReturnedCounter: 0,
      counterStatus: "unchanged-zero",
      credentialLifecycleEligible: true,
      sessionContextEligible: true,
      assuranceSatisfied: true,
      userPresenceVerified: false,
      userVerificationVerified: false,
      challengeVerified: true,
      originVerified: false,
      rpIdHashVerified: false,
      signatureVerified: false,
      rawAssertionMaterialIncluded: false,
      publicKeyBytesIncluded: false,
      credentialRecordIncluded: false
    },
    validity: {
      issuedAt: now,
      expiresAt: input.workflowExpiresAt || futureDate(),
      expired: false,
      invalidatedBySessionLock: true,
      invalidatedBySessionClose: true,
      invalidatedByCredentialRevocation: true,
      invalidatedByOwnerMismatch: true
    },
    requirements: ["unlocked_device_vault", "desktop_digest_bound_approval"],
    limitations: ["desktop_local_alpha_trust_evidence", "not_production_webauthn"],
    reasons: ["local-device-vault-unlocked"],
    revocationReference: {
      referenceId: `${input.workflowId}:trust-revocation-ref`,
      durableRevocationImplemented: false,
      futureRevocationRequired: true
    },
    trustDecisionCreated: true,
    productionAssertionVerified: true,
    credentialCounterCommitted: false,
    acceptedZeroCounterSemantics: true,
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
    persisted: false
  });
}

function createPolicy(input, trust, targetAddress) {
  const result = createAuthoritativePolicyDecision({
    requestId: `${input.workflowId}:policy-request`,
    authoritativeTrustDecision: trust,
    capabilityRequest: {
      requestId: `${input.workflowId}:capability-request`,
      applicationId: APPLICATION_ID,
      capability: CAPABILITY_NAME,
      sensitivity: "privileged",
      scope: {
        applicationId: APPLICATION_ID,
        chainId: input.chainId,
        action: "contract_call",
        resource: targetAddress,
        expiresAt: input.workflowExpiresAt || futureDate()
      },
      requestedAt: nowIso()
    },
    actionContext: {
      actionType: "contract_call",
      targetReference: targetAddress,
      requestedValue: "0",
      requestedDurationSeconds: 300,
      requestedScope: {
        applicationId: APPLICATION_ID,
        chainId: input.chainId,
        action: "contract_call",
        resource: targetAddress
      },
      chainId: input.chainId,
      network: input.network || "hardhat"
    },
    policySet: {
      policySetId: `${input.workflowId}:policy-set`,
      version: "desktop-local-alpha-policy-v1",
      expiresAt: input.workflowExpiresAt || futureDate(),
      rules: [
        { ruleId: "approval", type: "require_user_approval", effect: "require_user_approval" },
        {
          ruleId: "value-zero",
          type: "limit_value",
          effect: "restrict_value",
          constraints: [{ constraintId: "value-zero", kind: "value", value: "0" }]
        },
        {
          ruleId: "target-fixed",
          type: "restrict_target",
          effect: "restrict_target",
          constraints: [{ constraintId: "target-fixed", kind: "custom", value: targetAddress }]
        }
      ]
    },
    lifecycleSnapshot: lifecycleSnapshot(input),
    sessionId: input.sessionId,
    lifecycleState: "unlocked",
    ownerCommitment: input.ownerCommitment,
    applicationId: APPLICATION_ID,
    capabilityName: CAPABILITY_NAME,
    requestedScope: {
      applicationId: APPLICATION_ID,
      chainId: input.chainId,
      action: "contract_call",
      resource: targetAddress
    },
    requestedDurationSeconds: 300,
    actionType: "contract_call",
    targetReference: targetAddress,
    requestedValue: "0",
    chainId: input.chainId,
    network: input.network || "hardhat",
    authenticationPurpose: input.authenticationPurpose || "local_authorization_execution",
    requestedAssurance: ["local_device_vault_unlocked", "fresh_desktop_approval"],
    issuedAt: nowIso(),
    expiresAt: input.workflowExpiresAt || futureDate(),
    auditCorrelationId: input.auditCorrelationId
  });
  return assertApproved(result, "policy decision");
}

function platformApprovalActionRequest(input, policy) {
  return freeze({
    sessionId: input.sessionId,
    applicationId: APPLICATION_ID,
    ownerCommitment: input.ownerCommitment,
    capabilityName: CAPABILITY_NAME,
    actionType: "contract_call",
    targetReference: policy.scope.targetReference,
    requestedValue: "0",
    effectiveScope: policy.effectiveScope,
    effectiveDurationSeconds: policy.effectiveDurationSeconds,
    chainId: input.chainId,
    network: input.network || "hardhat",
    auditCorrelationId: input.auditCorrelationId
  });
}

function platformApprovalPresentationSummary(input, policy) {
  return freeze({
    applicationId: APPLICATION_ID,
    applicationName: APPLICATION_NAME,
    capabilityName: CAPABILITY_NAME,
    actionType: "contract_call",
    targetReference: policy.scope.targetReference,
    requestedValue: "0",
    effectiveScope: policy.effectiveScope,
    effectiveDurationSeconds: policy.effectiveDurationSeconds,
    chainId: input.chainId,
    network: input.network || "hardhat",
    policyRestrictions: {
      effectiveDurationSeconds: policy.effectiveDurationSeconds,
      effectiveValueLimit: policy.effectiveValueLimit,
      effectiveTargetRestrictions: policy.effectiveTargetRestrictions
    },
    riskDisclosures: [{
      disclosureId: `${input.workflowId}:desktop-risk`,
      summary: input.approvalRiskSummary
        || "Local ActionGate execution requires explicit desktop approval.",
      severity: "medium"
    }],
    expiresAt: input.workflowExpiresAt || futureDate()
  });
}

function createPlatformApprovalDecision(input, trust, policy, desktopApproval) {
  const actionRequest = platformApprovalActionRequest(input, policy);
  const approvalRequest = assertApproved(createPlatformUserApprovalRequest({
    requestId: `${input.workflowId}:platform-approval-request`,
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest,
    lifecycleSnapshot: lifecycleSnapshot(input),
    approvalSurface: "desktop_native",
    approvalChallengeReference: desktopApproval.presentationId,
    presentationSummary: platformApprovalPresentationSummary(input, policy),
    requestedAt: desktopApproval.decidedAt,
    expiresAt: desktopApproval.expiresAt,
    auditCorrelationId: input.auditCorrelationId,
    humanReadableSummary: "Approve the bounded local PhilCore authorization action."
  }), "platform approval request");
  const approvalArtifact = {
    platformUserApprovalArtifactId: desktopApproval.approvalArtifactId,
    platformUserApprovalRequestId: approvalRequest.platformUserApprovalRequestId,
    approvalSurface: approvalRequest.approvalSurface,
    outcome: "approved",
    decidedAt: desktopApproval.decidedAt,
    presentationDigest: approvalRequest.presentationDigest,
    approvalChallengeReference: approvalRequest.approvalChallengeReference,
    sessionId: actionRequest.sessionId,
    applicationId: actionRequest.applicationId,
    ownerCommitment: actionRequest.ownerCommitment,
    deviceReference: "desktop-local-alpha-main-process",
    platformProviderReference: "philcore-desktop-o4-approval",
    userPresenceIndicated: true,
    userVerificationIndicated: false,
    productionBound: true,
    fixtureOnly: false,
    expiresAt: desktopApproval.expiresAt,
    auditCorrelationId: input.auditCorrelationId,
    biometricTemplateIncluded: false,
    rawPlatformSecretIncluded: false,
    rawPrivateKeyIncluded: false,
    rawWebAuthnPrivateMaterialIncluded: false,
    vaultMaterialIncluded: false,
    credentialRecordIncluded: false,
    authorizationPackageIncluded: false,
    adapterPayloadIncluded: false
  };
  return assertApproved(createPlatformUserApprovalDecision({
    requestId: `${input.workflowId}:platform-approval-decision`,
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    actionRequest,
    platformApprovalRequest: approvalRequest,
    platformApprovalArtifact: approvalArtifact,
    lifecycleSnapshot: lifecycleSnapshot(input),
    issuedAt: desktopApproval.decidedAt,
    expiresAt: desktopApproval.expiresAt,
    auditCorrelationId: input.auditCorrelationId
  }), "platform approval decision");
}

function createGrant(input, trust, policy, approval) {
  const result = createAuthoritativeCapabilityGrant({
    requestId: `${input.workflowId}:capability-activation-request`,
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    platformUserApprovalDecision: approval,
    lifecycleSnapshot: lifecycleSnapshot(input),
    userSessionContext: userSessionContext(input),
    ownerCommitment: input.ownerCommitment,
    sessionId: input.sessionId,
    applicationId: APPLICATION_ID,
    capabilityName: CAPABILITY_NAME,
    requestedScope: policy.scope.requestedScope,
    effectiveScope: policy.effectiveScope,
    requestedDurationSeconds: 300,
    effectiveDurationSeconds: policy.effectiveDurationSeconds,
    allowedTargets: policy.effectiveTargetRestrictions,
    valueLimit: policy.effectiveValueLimit,
    actionTypes: [policy.scope.actionType],
    chainId: input.chainId,
    network: input.network || "hardhat",
    issuedAt: nowIso(),
    expiresAt: input.workflowExpiresAt || futureDate(),
    auditCorrelationId: input.auditCorrelationId
  });
  return assertApproved(result, "capability grant");
}

function createCandidate(input, grant, targetAddress, consumerDataReference) {
  const result = createAuthorizationDecisionCandidate({
    requestId: `${input.workflowId}:authorization-candidate-request`,
    activeCapabilityGrant: grant,
    intent: {
      intentId: `${input.workflowId}:intent`,
      kind: "contract-call",
      applicationId: APPLICATION_ID,
      requestedCapabilities: [CAPABILITY_NAME],
      payload: {
        chainId: input.chainId,
        target: targetAddress,
        value: "0",
        callData: "0x"
      },
      status: "created",
      createdAt: nowIso(),
      expiresAt: input.workflowExpiresAt || futureDate()
    },
    actionType: "contract_call",
    lifecycleSnapshot: lifecycleSnapshot(input),
    userSessionContext: userSessionContext(input),
    ownerCommitment: input.ownerCommitment,
    sessionId: input.sessionId,
    applicationId: APPLICATION_ID,
    target: targetAddress,
    method: "contract_call",
    value: "0",
    scope: {
      applicationId: APPLICATION_ID,
      chainId: input.chainId,
      action: "contract_call",
      resource: targetAddress
    },
    requestedDurationSeconds: 300,
    chainId: input.chainId,
    network: input.network || "hardhat",
    consumerDataReference,
    issuedAt: nowIso(),
    expiresAt: input.workflowExpiresAt || futureDate(),
    auditCorrelationId: input.auditCorrelationId
  });
  return assertApproved(result, "authorization candidate");
}

function createPackage(input, grant, candidate, trust, policy, approval, action) {
  const result = createAuthorizationPackageDraft({
    requestId: `${input.workflowId}:package-draft-request`,
    activeCapabilityGrant: grant,
    authorizationDecisionCandidate: candidate,
    authoritativeTrustDecision: trust,
    authoritativePolicyDecision: policy,
    platformUserApprovalDecision: approval,
    intent: {
      intentId: candidate.binding.intentId,
      kind: "contract-call",
      applicationId: APPLICATION_ID,
      requestedCapabilities: [CAPABILITY_NAME],
      payload: { target: action.target, value: "0" },
      status: "created",
      createdAt: nowIso(),
      expiresAt: action.expiresAt
    },
    chainId: input.chainId,
    consumer: action.consumer,
    account: action.account,
    target: action.target,
    method: "contract_call",
    value: 0,
    callData: action.callData,
    policyData: "0x",
    nullifier: action.publicNullifier,
    nullifierSafeReference: shortRef(action.publicNullifier),
    issuedAt: nowIso(),
    expiresAt: action.expiresAt,
    auditCorrelationId: input.auditCorrelationId
  });
  return assertApproved(result, "authorization package draft");
}

function createDesktopRuntimeAuthorizationArtifacts(input) {
  const trust = trustDecision(input);
  const policy = createPolicy(input, trust, input.action.target);
  const approval = createPlatformApprovalDecision(
    input,
    trust,
    policy,
    input.desktopApproval
  );
  const grant = createGrant(input, trust, policy, approval);
  const candidate = createCandidate(
    input,
    grant,
    input.action.target,
    input.action.consumerDataReference
  );
  const draft = createPackage(input, grant, candidate, trust, policy, approval, {
    consumer: input.action.consumer,
    account: input.action.account,
    target: input.action.target,
    callData: input.action.callData,
    expiresAt: input.action.expiresAt,
    publicNullifier: input.action.publicNullifier
  });
  return { trust, policy, approval, grant, candidate, draft };
}

function deploymentReader(contracts) {
  return {
    async readBaseActionGateDeployment(request) {
      return {
        status: "deployment_valid",
        chainId: request.configuration.activeProfile.chainId,
        actionGateAddress: await contracts.actionGate.getAddress(),
        verifierAddress: await contracts.verifier.getAddress(),
        mirrorAddress: await contracts.baseMirror.getAddress(),
        consumerAddress: await contracts.unlockConsumer.getAddress(),
        baseMessengerAddress: await contracts.baseMessenger.getAddress(),
        authorizedL1RemoteSender: await contracts.adapter.getAddress(),
        methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
        checkedAt: nowIso()
      };
    }
  };
}

function nullifierReader(contracts) {
  return {
    async readNullifierState(request) {
      const consumed = await contracts.actionGate.consumedNullifier(request.nullifier);
      return {
        status: consumed ? "nullifier_consumed" : "nullifier_available",
        actionGateAddress: request.actionGateAddress,
        nullifier: request.nullifier,
        checkedAt: nowIso(),
        nullifierConsumed: consumed,
        nullifierReserved: false,
        baseStateMutated: false
      };
    }
  };
}

function baseNonceReader() {
  return {
    async readNonce() {
      return { status: "resolved", nonce: "0", checkedAt: nowIso(), source: "local_fixture" };
    }
  };
}

function accountStateReader(account) {
  return {
    async readAccountState(request) {
      const code = await ethers.provider.getCode(request.accountAddress);
      return {
        accountAddress: request.accountAddress,
        chainId: request.expectedChainId,
        codeExists: code !== "0x",
        codeHash: ethers.keccak256(code),
        entryPoint: await account.entryPoint(),
        owner: await account.owner(),
        ownerCommitment: await account.ownerCommitment(),
        approvedActionGate: await account.approvedActionGate(),
        checkedAt: nowIso()
      };
    }
  };
}

function entryPointNonceReader(entryPoint) {
  return {
    async readNonce(request) {
      return {
        status: "resolved",
        nonce: (await entryPoint.getNonce(request.accountAddress, 0)).toString(),
        nonceKey: request.nonceKey,
        source: "entrypoint_get_nonce",
        checkedAt: nowIso()
      };
    }
  };
}

function deviceVaultSigner(material) {
  const descriptor = {
    signerId: `desktop-device-vault-ecdsa:${material.validator.keyReferenceId}`,
    mode: "device_vault_beta_ecdsa",
    ownerAddress: material.validator.publicOwnerAddress,
    keyReference: {
      keyReferenceId: material.validator.keyReferenceId,
      mode: "device_vault_beta_ecdsa",
      custody: "desktop_device_vault_encrypted",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available: true,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  };
  return {
    async describeSigner() {
      return descriptor;
    },
    async checkAvailability() {
      return descriptor;
    },
    async getOwnerAddress() {
      return material.validator.publicOwnerAddress;
    },
    async signUserOperationHash(request) {
      if (request.expectedOwner.toLowerCase() !== material.validator.publicOwnerAddress.toLowerCase()) {
        return { status: "rejected", signerDescriptor: descriptor, signedAt: nowIso(), errors: ["owner mismatch"] };
      }
      const wallet = new ethers.Wallet(material.validator.privateKey);
      return {
        status: "signed",
        signature: await wallet.signMessage(ethers.getBytes(request.userOperationHash)),
        signerDescriptor: descriptor,
        signedAt: nowIso()
      };
    }
  };
}

function runtimeAuthority() {
  return {
    capabilityGrantStatus: "active",
    sessionStatus: "eligible",
    platformApprovalStatus: "valid",
    baseExecutionApprovalStatus: "valid",
    finalizedPackageStatus: "valid",
    mirroredFactStatus: "present",
    nullifierStatus: "available"
  };
}

async function startDesktopRealLocalAuthorizationWorkflow(input) {
  const workflowId = input.workflowId;
  const stages = [];
  const timings = {};
  const startedAt = Date.now();
  const material = input.protectedMaterial;
  const auditCorrelationId = input.auditCorrelationId;
  const proofStack = proofStackFor(input);
  const proofEvidenceClass = proofStack.classification === HYPOTHETICAL_STACK_CLASSIFICATION
    ? "hypothetical_witness_hiding_test_fixture"
    : proofStack.classification === NOIR_ALPHA_STACK_CLASSIFICATION
      ? "real_local_noir_ultra_keccak_zk_honk_alpha"
      : "unavailable_secret_bearing_proof_quarantined";
  const baseInput = {
    workflowId,
    sessionId: input.sessionId,
    ownerCommitment: material.ownerCommitment,
    validator: material.validator,
    auditCorrelationId,
    chainId: 31337,
    workflowExpiresAt: futureDate(600_000)
  };
  const mark = (id, label, evidenceClass, status, details) => {
    const item = stage(id, label, evidenceClass, status, details);
    stages.push(item);
    return item;
  };

  try {
    mark("intent_created", "Request received", "real_local", "completed", {
      application: APPLICATION_NAME,
      action: "Zero-value local unlock consumer action"
    });

    const contracts = await deployLocalContracts({
      ownerAddress: material.validator.publicOwnerAddress,
      ownerCommitment: material.ownerCommitment
    });
    baseInput.chainId = contracts.chainId;

    const consumer = await contracts.unlockConsumer.getAddress();
    const account = contracts.accountAddress;
    const target = contracts.localTarget.address;
    const callData = "0x";
    const expiresAt = baseInput.workflowExpiresAt;
    const expiry = BigInt(Math.floor(Date.parse(expiresAt) / 1000));
    const consumerData = encodeUnlockRequest({ account, target, value: 0n, callData });
    const actionHash = deriveCanonicalAuthorizationActionHash({
      chainId: contracts.chainId,
      consumer,
      account,
      target,
      value: 0,
      callData
    }).actionHash;
    const effectivePolicyHash = policyHash({
      chainId: contracts.chainId,
      consumer,
      target,
      expiry,
      policyDataHash: dataHash("0x")
    });
    const nullifierSeed = ethers.hexlify(ethers.randomBytes(32));
    const publicNullifier = nullifier({
      ownerCommitment: material.ownerCommitment,
      actionHash,
      policyHash: effectivePolicyHash,
      nullifierSeed
    });

    const trust = trustDecision(baseInput);
    mark("trust_evaluated", "Trust checked", "real_local", "completed", {
      outcome: trust.outcome,
      credential: shortRef(material.validator.publicOwnerAddress),
      limitations: trust.limitations
    });
    const policy = createPolicy(baseInput, trust, target);
    mark("policy_decided", "Policy approved", "real_local", "completed", {
      outcome: policy.outcome,
      valueLimit: policy.effectiveValueLimit,
      target: shortRef(target)
    });
    mark("approval_completed", "Your approval", "real_local", "completed", {
      approvalArtifactId: shortRef(input.desktopApproval.approvalArtifactId),
      presentationDigest: shortRef(input.desktopApproval.presentationDigest)
    });
    const approval = createPlatformApprovalDecision(baseInput, trust, policy, input.desktopApproval);
    const grant = createGrant(baseInput, trust, policy, approval);
    mark("capability_activated", "Capability active", "real_local", "completed", {
      capability: grant.scope.capabilityName,
      expiry: grant.validity.expiresAt,
      status: grant.status
    });
    const candidate = createCandidate(baseInput, grant, target, "phil-unlock-consumer-data-v1");
    mark("authorization_candidate_created", "Authorization candidate", "real_local", "completed", {
      candidateId: shortRef(candidate.authorizationDecisionCandidateId)
    });
    const draft = createPackage(baseInput, grant, candidate, trust, policy, approval, {
      consumer,
      account,
      target,
      callData,
      expiresAt,
      publicNullifier
    });
    mark("package_draft_created", "Authorization prepared", "real_local", "completed", {
      proofInputHash: shortRef(draft.hashSummary.proofInputHash),
      nullifier: shortRef(publicNullifier)
    });

    const proofStart = Date.now();
    mark("proof_generating", "Proof generating", proofEvidenceClass, "running", {
      proofType: UNLOCK_PROOF_TYPE
    });
    const witnessProvider = createStaticActionUnlockProtectedWitnessProvider({
      providerId: `${workflowId}:desktop-protected-witness`,
      providerKind: "local_device_vault",
      displayName: "Desktop Device Vault protected witness",
      philSecret: material.philSecret,
      nullifierSeed
    });
    const proofArtifact = assertApproved(await proofStack.generateActionUnlockProof({
      requestId: `${workflowId}:proof-generation`,
      authorizationPackageDraft: draft,
      witnessProvider,
      issuedAt: nowIso(),
      expiresAt: futureDate(180_000),
      auditCorrelationId,
      timeoutMs: input.proofTimeoutMs ?? 120_000,
      includeProofBlob: true,
      expectedProofInputHash: draft.hashSummary.proofInputHash,
      expectedProofType: UNLOCK_PROOF_TYPE
    }), "proof generation");
    timings.proofGenerationMs = Date.now() - proofStart;
    mark("proof_generated", "Proof generated", proofEvidenceClass, "completed", {
      proofDigest: shortRef(proofArtifact.proofArtifact.proofDigest),
      proofByteLength: proofArtifact.proofArtifact.proofByteLength,
      durationMs: proofArtifact.summary.durationMs
    });
    const verificationStart = Date.now();
    const verification = assertApproved(await proofStack.verifyGeneratedActionUnlockProof({
      requestId: `${workflowId}:proof-verification`,
      authorizationPackageDraft: draft,
      proofGenerationArtifact: proofArtifact,
      issuedAt: nowIso(),
      expiresAt: futureDate(180_000),
      auditCorrelationId,
      timeoutMs: input.proofTimeoutMs ?? 120_000,
      expectedProofInputHash: draft.hashSummary.proofInputHash,
      expectedProofType: UNLOCK_PROOF_TYPE,
      expectedFactShapeReference: "[fact_high, fact_low]"
    }), "proof verification");
    timings.proofVerificationMs = Date.now() - verificationStart;
    mark("proof_verified", "Proof verified", proofEvidenceClass, "completed", {
      proofInputHash: shortRef(verification.proofInputHash),
      factHigh: shortRef(verification.factShapePreview.factHigh),
      factLow: shortRef(verification.factShapePreview.factLow)
    });
    const finalized = assertApproved(await proofStack.finalizeAuthorizationPackage({
      requestId: `${workflowId}:finalize-package`,
      authorizationPackageDraft: draft,
      proofGenerationArtifact: proofArtifact,
      proofVerificationResult: verification,
      issuedAt: nowIso(),
      expiresAt: futureDate(180_000),
      auditCorrelationId
    }), "package finalization");
    mark("package_finalized", "Package finalized", "real_local", "completed", {
      finalizedPackageId: shortRef(finalized.finalizedAuthorizationPackageId)
    });

    const fact = hexPairFromProofInputHash(finalized.actionUnlockAuthorization.proofInputHash);
    await (await contracts.adapter.sendMessage(
      await contracts.baseMirror.getAddress(),
      contracts.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
        BigInt(fact.factHigh),
        BigInt(fact.factLow)
      ])
    )).wait();
    mark("fact_available_local", "Local fact fixture", "local_fixture", "completed", {
      factHigh: shortRef(fact.factHigh),
      factLow: shortRef(fact.factLow),
      publicPublication: false
    });

    const baseProofPackage = buildUnlockProofPackageFromAuthorization(
      {
        consumer,
        ownerCommitment: material.ownerCommitment,
        actionHash: finalized.actionUnlockAuthorization.actionHash,
        policyHash: finalized.actionUnlockAuthorization.policyHash,
        nullifier: finalized.actionUnlockAuthorization.nullifier,
        consumerDataHash: finalized.actionUnlockAuthorization.consumerDataHash,
        expiry
      },
      { proofBlob: proofBlobForFact(fact.factHigh, fact.factLow) }
    );
    const baseAuthorization = {
      consumer,
      ownerCommitment: material.ownerCommitment,
      actionHash: finalized.actionUnlockAuthorization.actionHash,
      policyHash: finalized.actionUnlockAuthorization.policyHash,
      nullifier: finalized.actionUnlockAuthorization.nullifier,
      consumerDataHash: finalized.actionUnlockAuthorization.consumerDataHash,
      expiry
    };
    const configuration = {
      configurationId: `${workflowId}:base-action-gate-config`,
      approvalStatus: "accepted",
      activeProfile: {
        profileId: "hardhat-base-local",
        network: "hardhat",
        chainId: contracts.chainId,
        enabled: true
      },
      actionGateAddress: await contracts.actionGate.getAddress(),
      verifier: {
        address: await contracts.verifier.getAddress(),
        expectedProofType: UNLOCK_PROOF_TYPE,
        baseMirrorAddress: await contracts.baseMirror.getAddress(),
        approved: true
      },
      mirror: {
        address: await contracts.baseMirror.getAddress(),
        messengerAddress: await contracts.baseMessenger.getAddress(),
        authorizedL1RemoteSender: await contracts.adapter.getAddress(),
        approved: true
      },
      consumer: {
        address: consumer,
        consumerKind: "PhilUnlockConsumer",
        actionGateAddress: await contracts.actionGate.getAddress(),
        approved: true,
        payable: true
      },
      methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
      abiVersion: "phil-base-action-gate-v1",
      supportedProofType: UNLOCK_PROOF_TYPE,
      valuePolicy: "exact_authorized_value",
      mainnetAllowed: false
    };
    const mirroredFactEvidence = createBaseMirroredFactEvidence({
      source: "local_hardhat_receipt",
      binding: {
        baseChainId: contracts.chainId,
        baseMirrorAddress: await contracts.baseMirror.getAddress(),
        baseMessengerAddress: await contracts.baseMessenger.getAddress(),
        authorizedL1RemoteSender: await contracts.adapter.getAddress(),
        mirrorTransactionHash: `${workflowId}:local-mirror-fixture`,
        factHigh: fact.factHigh,
        factLow: fact.factLow,
        proofInputHash: finalized.actionUnlockAuthorization.proofInputHash,
        auditCorrelationId
      }
    });
    const basePrepStart = Date.now();
    const baseDraft = assertApproved(await prepareBaseAuthorizationExecutionTransaction({
      requestId: `${workflowId}:base-execution-preparation`,
      finalizedAuthorizationPackage: finalized,
      baseActionAuthorization: baseAuthorization,
      proofPackage: baseProofPackage,
      consumerData,
      mirroredFactEvidence,
      activeCapabilityGrant: grant,
      sessionLifecycleSnapshot: lifecycleSnapshot(baseInput),
      configuration,
      deploymentReader: deploymentReader(contracts),
      nullifierStateReader: nullifierReader(contracts),
      senderAccount: account,
      simulator: undefined,
      gasEstimator: createFixtureBaseExecutionGasEstimator(),
      nonceReader: baseNonceReader(),
      feeDataReader: createFixtureBaseExecutionFeeDataReader(),
      issuedAt: nowIso(),
      expiresAt: futureDate(),
      auditCorrelationId
    }), "base execution preparation");
    timings.baseExecutionPreparationMs = Date.now() - basePrepStart;
    mark("base_execution_prepared", "Smart account call prepared", "real_local", "completed", {
      actionGate: shortRef(baseDraft.to),
      calldataHash: shortRef(baseDraft.calldataHash)
    });

    const foundation = createPhilCore4337LocalFoundationConfiguration({
      chainId: contracts.chainId,
      entryPointAddress: await contracts.entryPoint.getAddress(),
      factoryAddress: await contracts.accountFactory.getAddress(),
      approvedActionGateAddress: await contracts.actionGate.getAddress(),
      owner: material.validator.publicOwnerAddress,
      ownerCommitment: material.ownerCommitment
    });
    const userOpStart = Date.now();
    const userOpDraft = assertApproved(await preparePhilCore4337UserOperation({
      requestId: `${workflowId}:user-operation-preparation`,
      baseExecutionDraft: baseDraft,
      foundation,
      accountMode: "deployed",
      accountAddress: account,
      accountStateReader: accountStateReader(contracts.account),
      nonceReader: entryPointNonceReader(contracts.entryPoint),
      gasEstimator: createFixturePhilCore4337GasEstimator(),
      prefundReader: createFixturePhilCore4337PrefundReader(),
      issuedAt: nowIso(),
      expiresAt: futureDate(),
      auditCorrelationId
    }), "UserOperation preparation");
    timings.userOperationPreparationMs = Date.now() - userOpStart;
    const signingPresentation = createPhilCore4337SigningPresentation(userOpDraft);
    mark("user_operation_prepared", "Ready to sign", "real_local", "approval_required", {
      userOperationHash: shortRef(userOpDraft.binding.userOperationHash),
      presentationDigest: shortRef(signingPresentation.presentationDigest),
      paymaster: "disabled"
    });

    const workflow = {
      workflowId,
      status: "signing_approval_required",
      version: WORKFLOW_VERSION,
      startedAt: new Date(startedAt).toISOString(),
      updatedAt: nowIso(),
      stages,
      timings,
      evidenceLabels: evidenceLabels(proofEvidenceClass),
      selectedAction: selectedActionSummary({ target, consumer, account, chainId: contracts.chainId }),
      correlation: {
        identityId: material.identityId,
        ownerCommitment: material.ownerCommitment,
        applicationId: APPLICATION_ID,
        sessionId: input.sessionId,
        auditCorrelationId,
        capabilityGrantId: grant.authoritativeCapabilityGrantId,
        authorizationPackageDraftId: draft.authorizationPackageDraftId,
        finalizedAuthorizationPackageId: finalized.finalizedAuthorizationPackageId,
        proofInputHash: finalized.actionUnlockAuthorization.proofInputHash,
        publicNullifier: finalized.actionUnlockAuthorization.nullifier,
        smartAccount: account,
        entryPoint: await contracts.entryPoint.getAddress(),
        userOperationHash: userOpDraft.binding.userOperationHash
      },
      proof: {
        proofType: proofArtifact.proofArtifact.proofType,
        proofSuite: proofArtifact.proofArtifact.proofSuite,
        proofDigest: proofArtifact.proofArtifact.proofDigest,
        proofByteLength: proofArtifact.proofArtifact.proofByteLength,
        proofInputHash: finalized.actionUnlockAuthorization.proofInputHash,
        rootProofNullifier: finalized.rootProofAuthorization?.publicInputs?.rootProofNullifier,
        proofDescriptorHash: finalized.rootProofAuthorization?.descriptorHash,
        factHigh: fact.factHigh,
        factLow: fact.factLow,
        generationDurationMs: proofArtifact.summary.durationMs,
        verificationDurationMs: verification.summary.durationMs,
        proofBytesDisplayed: false,
        witnessExposed: false
      },
      execution: {
        account,
        entryPoint: await contracts.entryPoint.getAddress(),
        actionGate: await contracts.actionGate.getAddress(),
        consumer,
        target,
        userOperationHash: userOpDraft.binding.userOperationHash,
        transactionHash: "not_submitted",
        nonce: userOpDraft.userOperation.nonce,
        nullifier: finalized.actionUnlockAuthorization.nullifier,
        consumerResult: "pending_signature",
        localOnly: true
      },
      pendingSigningPresentation: {
        presentationDigest: signingPresentation.presentationDigest,
        presentation: signingPresentation.presentation,
        fields: signingPresentationFields(userOpDraft, baseDraft, signingPresentation)
      },
      privateState: {
        contracts,
        foundation,
        userOpDraft,
        signingPresentation,
        baseDraft,
        grant,
        finalized,
        fact,
        consumerData,
        baseAuthorization,
        material
      }
    };
    return workflow;
  } catch (error) {
    const runningStageIndex = stages.findLastIndex((item) => item.status === "running");
    if (runningStageIndex >= 0) {
      const runningStage = stages[runningStageIndex];
      stages[runningStageIndex] = stage(
        runningStage.id,
        runningStage.label,
        runningStage.evidenceClass,
        "failed",
        {
          ...runningStage.details,
          terminalReason: runningStage.evidenceClass === "unavailable_secret_bearing_proof_quarantined"
            ? "proof_privacy_quarantine"
            : "workflow_failed"
        }
      );
    }
    mark("failed", "Failed", "real_local", "failed", {
      reason: error instanceof Error ? error.message : "unknown_error"
    });
    return {
      workflowId,
      status: "failed",
      version: WORKFLOW_VERSION,
      startedAt: new Date(startedAt).toISOString(),
      updatedAt: nowIso(),
      stages,
      timings,
      evidenceLabels: evidenceLabels(proofEvidenceClass),
      selectedAction: selectedActionSummary({}),
      error: error instanceof Error ? error.message : "unknown_error",
      privateState: undefined
    };
  }
}

async function completeDesktopRealLocalAuthorizationWorkflow(workflow, input) {
  if (!workflow || workflow.status !== "signing_approval_required" || !workflow.privateState) {
    return { ...workflow, status: "failed", error: "workflow_not_waiting_for_signing_approval" };
  }
  const state = workflow.privateState;
  const stages = [...workflow.stages];
  const timings = { ...workflow.timings };
  const mark = (id, label, evidenceClass, status, details) => {
    const item = stage(id, label, evidenceClass, status, details);
    stages.push(item);
    return item;
  };
  try {
    if (!input.freshAuthenticationEvidence
      || input.freshAuthenticationEvidence.presentationDigest !== workflow.pendingSigningPresentation.presentationDigest
      || input.freshAuthenticationEvidence.sessionId !== workflow.correlation.sessionId) {
      throw new Error("fresh authentication evidence mismatch");
    }
    mark("signing_approval_completed", "Signing approved", "real_local", "completed", {
      presentationDigest: shortRef(workflow.pendingSigningPresentation.presentationDigest),
      freshAuthMethod: input.freshAuthenticationEvidence.method
    });
    const approval = createPhilCore4337SigningApprovalArtifact({
      approvalId: input.signingApprovalId,
      presentationDigest: workflow.pendingSigningPresentation.presentationDigest,
      source: "desktop_digest_bound_approval",
      approved: true,
      approvedAt: nowIso(),
      expiresAt: futureDate(120_000),
      oneTime: true,
      publicNetworkAllowed: false
    });
    const signStart = Date.now();
    const signed = assertApproved(await signPhilCore4337UserOperation({
      requestId: `${workflow.workflowId}:user-operation-signing`,
      draft: state.userOpDraft,
      foundation: state.foundation,
      runtimeAuthority: runtimeAuthority(),
      approval,
      signer: deviceVaultSigner(state.material),
      nonceReader: entryPointNonceReader(state.contracts.entryPoint),
      gasEstimator: createFixturePhilCore4337GasEstimator(),
      prefundReader: createFixturePhilCore4337PrefundReader(),
      accountStateReader: accountStateReader(state.contracts.account),
      issuedAt: nowIso(),
      expiresAt: futureDate(),
      auditCorrelationId: workflow.correlation.auditCorrelationId
    }), "UserOperation signing");
    timings.signingMs = Date.now() - signStart;
    mark("user_operation_signed", "Signed", "real_local", "completed", {
      userOperationHash: shortRef(signed.binding.userOperationHash),
      signer: shortRef(signed.signerDescriptor.ownerAddress)
    });

    const submitStart = Date.now();
    const tx = await state.contracts.entryPoint.handleOps(
      [signed.userOperation],
      state.contracts.beneficiary.address,
      { gasLimit: 6_000_000 }
    );
    const receipt = await tx.wait();
    timings.localExecutionMs = Date.now() - submitStart;
    mark("user_operation_submitted_local", "Executed locally", "real_local", "completed", {
      transactionHash: shortRef(receipt.hash),
      blockNumber: receipt.blockNumber
    });

    const nullifierConsumed = await state.contracts.actionGate.consumedNullifier(
      state.finalized.actionUnlockAuthorization.nullifier
    );
    const actionGateAddress = (await state.contracts.actionGate.getAddress()).toLowerCase();
    const consumerAddress = (await state.contracts.unlockConsumer.getAddress()).toLowerCase();
    const actionGateLogs = receipt.logs.filter((log) => log.address.toLowerCase() === actionGateAddress);
    const consumerLogs = receipt.logs.filter((log) => log.address.toLowerCase() === consumerAddress);
    if (!nullifierConsumed) throw new Error("nullifier_not_consumed");
    if (actionGateLogs.length === 0) throw new Error("action_gate_event_missing");
    if (consumerLogs.length === 0) throw new Error("consumer_event_missing");
    mark("execution_verified", "Result verified", "real_local", "completed", {
      nullifierConsumed: true,
      actionGateEventObserved: true,
      consumerEventObserved: true
    });
    return {
      ...workflow,
      status: "completed",
      updatedAt: nowIso(),
      stages,
      timings,
      pendingSigningPresentation: undefined,
      privateState: undefined,
      execution: {
        ...workflow.execution,
        transactionHash: receipt.hash,
        consumerResult: "verified",
        nullifierConsumed: true,
        consumerExecuted: true,
        entryPointReceiptStatus: receipt.status === 1 ? "success" : "failed",
        blockNumber: receipt.blockNumber
      }
    };
  } catch (error) {
    mark("failed", "Failed", "real_local", "failed", {
      reason: error instanceof Error ? error.message : "unknown_error"
    });
    return {
      ...workflow,
      status: "failed",
      updatedAt: nowIso(),
      stages,
      timings,
      pendingSigningPresentation: undefined,
      privateState: undefined,
      error: error instanceof Error ? error.message : "unknown_error"
    };
  }
}

function signingPresentationFields(userOpDraft, baseDraft, presentationResult) {
  return freeze([
    ["Application", APPLICATION_NAME],
    ["Action", "Sign local ERC-4337 UserOperation"],
    ["Network", "Hardhat local fixture"],
    ["Smart account", userOpDraft.binding.smartAccountAddress],
    ["EntryPoint", userOpDraft.binding.entryPointAddress],
    ["ActionGate", userOpDraft.binding.actionGateAddress],
    ["Method", "PhilCore4337Account.execute(ActionGate.verifyAndConsume)"],
    ["UserOperation hash", userOpDraft.binding.userOperationHash],
    ["Presentation digest", presentationResult.presentationDigest],
    ["Proof input hash", userOpDraft.binding.proofInputHash],
    ["Nullifier", userOpDraft.binding.nullifier],
    ["Paymaster", "disabled"],
    ["Value", baseDraft.value],
    ["Calldata hash", baseDraft.calldataHash],
    ["Expiry", userOpDraft.expiresAt]
  ].map(([label, value]) => ({ label, value: String(value) })));
}

function selectedActionSummary(input) {
  return freeze({
    applicationId: APPLICATION_ID,
    applicationName: APPLICATION_NAME,
    capability: CAPABILITY_NAME,
    action: "zero_value_contract_call",
    target: input.target ? shortRef(input.target) : "not_selected",
    consumer: input.consumer ? shortRef(input.consumer) : "not_selected",
    account: input.account ? shortRef(input.account) : "not_selected",
    value: "0",
    chainId: input.chainId ?? 31337,
    meaningfulAssets: false,
    arbitraryTargetSelection: false
  });
}

function evidenceLabels(proofEvidenceClass = "unavailable_secret_bearing_proof_quarantined") {
  return freeze({
    durableIdentity: "real_local",
    deviceVault: "real_local",
    trustAndPolicy: "real_local",
    desktopApproval: "real_local",
    starkProofGeneration: proofEvidenceClass,
    proofVerification: proofEvidenceClass,
    starknetPublication: "not_executed",
    l1Anchoring: "not_executed",
    basePublicRelay: "not_executed",
    localMirrorFixture: "local_fixture",
    erc4337Preparation: "real_local",
    deviceVaultSigning: "real_local",
    entryPointExecution: "real_local",
    publicBundler: "not_executed"
  });
}

function sanitizeWorkflow(workflow) {
  if (!workflow) return undefined;
  const { privateState: _privateState, ...safe } = workflow;
  return freeze({
    ...safe,
    includesSecrets: false,
    proofWitnessExposed: false,
    privateKeyExposed: false,
    rawUserOperationExposed: false,
    publicNetworkMutation: false,
    productionApprovalGranted: false
  });
}

function auditCurrentDesktopDemoStages() {
  return freeze([
    { stage: "identity source", classification: "real_local", gap: "already durable encrypted desktop identity" },
    { stage: "session source", classification: "real_local", gap: "already desktop User Session metadata" },
    { stage: "trust evaluation", classification: "summary_only", gap: "O.5 wires local authoritative boundary-shaped trust evidence" },
    { stage: "policy evaluation", classification: "summary_only", gap: "O.5 calls authoritative policy helper" },
    { stage: "approval", classification: "real_local", gap: "O.4 digest-bound approval already available" },
    { stage: "Capability Grant", classification: "summary_only", gap: "O.5 activates actual scoped grant object" },
    { stage: "Authorization Package", classification: "summary_only", gap: "O.5 creates actual draft and finalized package" },
    { stage: "root proof generation", classification: "real_local_noir_ultra_keccak_zk_honk_alpha", gap: "Desktop-only Alpha route; the protected witness and witness stream are never persisted" },
    { stage: "root proof verification", classification: "real_local_noir_ultra_keccak_zk_honk_alpha", gap: "verified locally against the accepted pinned verification key" },
    { stage: "Starknet account composition", classification: "accepted_local_reference", gap: "Step 4 Cairo composition is accepted but not deployed or invoked by the Desktop product" },
    { stage: "fact availability", classification: "local_fixture", gap: "the local Ethereum demonstration still installs a fixture mirror only after the Noir root-proof gate passes" },
    { stage: "smart-account operation", classification: "summary_only", gap: "O.5 prepares actual v0.7 PackedUserOperation" },
    { stage: "signing", classification: "summary_only", gap: "O.5 signs exact UserOperation hash with desktop Device Vault validator" },
    { stage: "EntryPoint submission", classification: "simulated", gap: "O.5 submits to actual local EntryPoint fixture" },
    { stage: "nullifier verification", classification: "simulated", gap: "O.5 reads ActionGate consumedNullifier" },
    { stage: "consumer verification", classification: "simulated", gap: "O.5 verifies consumer event evidence" },
    { stage: "audit trail", classification: "summary_only", gap: "O.5 correlates stage evidence under one workflow ID" }
  ]);
}

module.exports = {
  WORKFLOW_VERSION,
  auditCurrentDesktopDemoStages,
  completeDesktopRealLocalAuthorizationWorkflow,
  createDesktopRuntimeAuthorizationArtifacts,
  sanitizeWorkflow,
  startDesktopRealLocalAuthorizationWorkflow
};
