const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseMirroredFactEvidence,
  createFixtureBaseActionGateDeploymentReader,
  createFixtureBaseAuthorizationExecutionSimulator,
  createFixtureBaseExecutionFeeDataReader,
  createFixtureBaseExecutionGasEstimator,
  createFixtureBaseExecutionNonceReader,
  createFixtureBaseNullifierStateReader,
  prepareBaseAuthorizationExecutionTransaction
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  dataHash,
  unlockActionHash
} = require("../../apps/phil-device-sdk/src/hashes.ts");
const {
  buildUnlockProofPackageFromAuthorization
} = require("../../apps/phil-device-sdk/src/proof/publicInputs.ts");
const { AbiCoder, hexlify, toUtf8Bytes } = require("ethers");

const abiCoder = AbiCoder.defaultAbiCoder();
const ACTION_GATE = "0x1000000000000000000000000000000000000001";
const VERIFIER = "0x1000000000000000000000000000000000000002";
const BASE_MIRROR = "0x1000000000000000000000000000000000000003";
const BASE_MESSENGER = "0x1000000000000000000000000000000000000004";
const AUTHORIZED_L1_REMOTE_SENDER = "0x1000000000000000000000000000000000000005";
const UNLOCK_CONSUMER = "0x1000000000000000000000000000000000000006";
const SENDER = "0x1000000000000000000000000000000000000007";
const ACCOUNT = "0x1000000000000000000000000000000000000008";
const TARGET = "0x1000000000000000000000000000000000000009";
const OWNER_COMMITMENT = `0x${"11".repeat(32)}`;
const POLICY_HASH = `0x${"22".repeat(32)}`;
const NULLIFIER = `0x${"33".repeat(32)}`;

function hasArg(name) {
  return process.argv.includes(name);
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function factPair(proofInputHash) {
  const raw = proofInputHash.slice(2).padStart(64, "0");
  return {
    factHigh: `0x${raw.slice(0, 32)}`,
    factLow: `0x${raw.slice(32)}`
  };
}

function proofBlobForFact(factHigh, factLow) {
  return abiCoder.encode(["uint256", "uint256"], [BigInt(factHigh), BigInt(factLow)]);
}

function buildFixtureRequest() {
  const issuedAt = now();
  const expiresAt = futureDate();
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const unlockRequest = {
    account: ACCOUNT,
    target: TARGET,
    value: 0n,
    callData: hexlify(toUtf8Bytes("philcore-m7-diagnostic"))
  };
  const consumerData = abiCoder.encode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    [unlockRequest]
  );
  const authorization = {
    consumer: UNLOCK_CONSUMER,
    ownerCommitment: OWNER_COMMITMENT,
    actionHash: unlockActionHash({
      chainId: 31337,
      consumer: UNLOCK_CONSUMER,
      account: unlockRequest.account,
      target: unlockRequest.target,
      value: unlockRequest.value,
      callDataHash: dataHash(unlockRequest.callData)
    }),
    policyHash: POLICY_HASH,
    nullifier: NULLIFIER,
    consumerDataHash: dataHash(consumerData),
    expiry
  };
  const initialPackage = buildUnlockProofPackageFromAuthorization(authorization, { proofBlob: "0x1234" });
  const fact = factPair(initialPackage.proofInputHash);
  const proofPackage = buildUnlockProofPackageFromAuthorization(authorization, {
    proofBlob: proofBlobForFact(fact.factHigh, fact.factLow)
  });
  const proofDigest = dataHash(proofPackage.proofBlob);
  const finalizedAuthorizationPackage = {
    finalizedAuthorizationPackageId: "diagnostic-m7-finalized-package",
    status: "authorization_package_finalized",
    outcome: "authorization_package_finalized",
    binding: {
      authorizationPackageDraftId: "diagnostic-m7-package-draft",
      proofGenerationArtifactId: "diagnostic-m7-proof-generation",
      proofVerificationResultId: "diagnostic-m7-proof-verification",
      sessionId: "diagnostic-m7-session",
      applicationId: "ethereum-net",
      intentId: "diagnostic-m7-intent",
      capabilityName: "request_contract_call",
      ownerCommitment: OWNER_COMMITMENT,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "diagnostic-m7-audit"
    },
    actionUnlockAuthorization: {
      version: UNLOCK_PROOF_SCHEMA_VERSION,
      proofType: UNLOCK_PROOF_TYPE,
      ownerCommitment: authorization.ownerCommitment,
      actionHash: authorization.actionHash,
      policyHash: authorization.policyHash,
      nullifier: authorization.nullifier,
      consumerDataHash: authorization.consumerDataHash,
      expiry: expiry.toString(),
      proofInputHash: proofPackage.proofInputHash,
      factShapeReference: "[fact_high, fact_low]"
    },
    proofArtifact: {
      proofArtifactId: "diagnostic-m7-proof-artifact",
      proofGenerationArtifactId: "diagnostic-m7-proof-generation",
      proofVerificationResultId: "diagnostic-m7-proof-verification",
      proofType: UNLOCK_PROOF_TYPE,
      proofDigest,
      proofByteLength: (proofPackage.proofBlob.length - 2) / 2,
      proofInputHash: proofPackage.proofInputHash,
      proofBlobIncluded: false,
      proofBytesLogged: false,
      nonSecretProofArtifact: true,
      containsWitnessOpenings: false,
      safeForExternalVerifierTransmission: true,
      executableByAdapters: false
    },
    evidence: {
      proofGenerated: true,
      proofVerifiedLocally: true,
      proofTypeMatched: true,
      publicInputsMatched: true,
      proofInputHashMatched: true,
      factShapeValidated: true,
      localVerificationResultId: "diagnostic-m7-proof-verification",
      verifiedProofReferenceId: "diagnostic-m7-proof-artifact"
    },
    factShapePreview: {
      factShapeReference: "[fact_high, fact_low]",
      factHigh: fact.factHigh,
      factLow: fact.factLow,
      sourceProofInputHash: proofPackage.proofInputHash,
      ordering: "fact_high_then_fact_low",
      factPublished: false,
      onChainRegistered: false
    },
    validity: { issuedAt, expiresAt, expired: false },
    limitations: [
      "local_finalization_only",
      "non_executing_authorization_package",
      "no_verified_fact_publication",
      "no_on_chain_verification",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_contract_execution",
      "no_transaction_submission",
      "process_local_package_store_only"
    ],
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
  };
  const activeCapabilityGrant = {
    authoritativeCapabilityGrantId: "diagnostic-m7-capability-grant",
    requestId: "diagnostic-m7-capability-request",
    status: "active",
    outcome: "capability_granted",
    scope: {
      capabilityName: "request_contract_call",
      allowedTargets: [UNLOCK_CONSUMER],
      actionTypes: ["base_authorization_execution"],
      chainId: 31337,
      network: "hardhat"
    },
    binding: {
      authoritativeTrustDecisionId: "diagnostic-m7-trust",
      authoritativePolicyDecisionId: "diagnostic-m7-policy",
      platformUserApprovalDecisionId: "diagnostic-m7-approval",
      sessionLifecycleId: "diagnostic-m7-lifecycle",
      sessionLifecycleState: "unlocked",
      ownerCommitment: OWNER_COMMITMENT,
      sessionId: "diagnostic-m7-session",
      applicationId: "ethereum-net",
      capabilityName: "request_contract_call",
      auditCorrelationId: "diagnostic-m7-audit",
      validityWindowId: "diagnostic-m7-window",
      reusableAcrossOwners: false,
      reusableAcrossSessions: false,
      reusableAcrossApplications: false,
      reusableAcrossCapabilities: false,
      reusableAcrossScopes: false,
      reusableAcrossTimeWindows: false
    },
    constraints: [],
    requirements: [],
    limitations: ["authorization_still_required"],
    reasons: ["trust_policy_and_user_approval_satisfied"],
    validity: {
      issuedAt,
      expiresAt,
      expired: false,
      invalidatedBySessionLock: true,
      invalidatedBySessionClose: true,
      invalidatedByExplicitRevocation: true,
      invalidatedByTrustDecisionExpiry: true,
      invalidatedByPolicyDecisionExpiry: true,
      invalidatedByApprovalDecisionExpiry: true
    },
    revocation: { revoked: false, durableRevocationImplemented: false, processLocalOnly: true },
    usagePolicy: {
      mayRequestFutureActions: true,
      actionAuthorizationStillRequired: true,
      authorizationEngineRequired: true,
      proofMayBeRequiredLater: true,
      adapterExecutionAllowed: false,
      unrestrictedWalletAuthority: false,
      usageCountConsumed: 0
    },
    capabilityGranted: true,
    activeCapabilityCreated: true,
    actionAuthorized: false,
    authorizationCreated: false,
    authorizationPackageCreated: false,
    sessionKeyCreated: false,
    executionAllowed: false,
    proofExecuted: false,
    adapterExecuted: false,
    transactionSubmitted: false,
    vaultAccessed: false,
    worldIdVerified: false,
    rawTrustEvidenceIncluded: false,
    rawApprovalArtifactIncluded: false,
    credentialRecordIncluded: false,
    privateMaterialIncluded: false,
    persisted: false,
    persistedAsAuthority: false
  };
  const mirroredFactEvidence = createBaseMirroredFactEvidence({
    source: "fixture_receipt",
    binding: {
      baseChainId: 31337,
      baseMirrorAddress: BASE_MIRROR,
      baseMessengerAddress: BASE_MESSENGER,
      authorizedL1RemoteSender: AUTHORIZED_L1_REMOTE_SENDER,
      mirrorTransactionHash: `0x${"ab".repeat(32)}`,
      factHigh: fact.factHigh,
      factLow: fact.factLow,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "diagnostic-m7-audit"
    }
  });
  const configuration = {
    configurationId: "diagnostic-m7-base-action-gate",
    approvalStatus: "accepted",
    activeProfile: { profileId: "hardhat-base-local", network: "hardhat", chainId: 31337, enabled: true },
    actionGateAddress: ACTION_GATE,
    verifier: { address: VERIFIER, expectedProofType: UNLOCK_PROOF_TYPE, baseMirrorAddress: BASE_MIRROR, approved: true },
    mirror: {
      address: BASE_MIRROR,
      messengerAddress: BASE_MESSENGER,
      authorizedL1RemoteSender: AUTHORIZED_L1_REMOTE_SENDER,
      approved: true
    },
    consumer: {
      address: UNLOCK_CONSUMER,
      consumerKind: "PhilUnlockConsumer",
      actionGateAddress: ACTION_GATE,
      approved: true,
      payable: true
    },
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    abiVersion: "phil-base-action-gate-v1",
    supportedProofType: UNLOCK_PROOF_TYPE,
    valuePolicy: "exact_authorized_value",
    mainnetAllowed: false
  };
  return {
    requestId: "diagnostic-m7-base-execution-preparation",
    finalizedAuthorizationPackage,
    baseActionAuthorization: authorization,
    proofPackage,
    consumerData,
    mirroredFactEvidence,
    activeCapabilityGrant,
    sessionLifecycleSnapshot: {
      lifecycleId: "diagnostic-m7-lifecycle",
      sessionId: "diagnostic-m7-session",
      state: hasArg("--locked") ? "locked" : "unlocked",
      sequence: 7,
      version: 7,
      createdAt: issuedAt,
      updatedAt: issuedAt,
      metadata: { deviceVaultUnlocked: true },
      limitations: ["ephemeral_only"],
      persisted: false,
      ownsSecrets: false,
      authenticatesUser: false,
      unlocksVault: true,
      grantsAuthority: false
    },
    configuration,
    deploymentReader: createFixtureBaseActionGateDeploymentReader({
      chainId: 31337,
      actionGateAddress: ACTION_GATE,
      verifierAddress: VERIFIER,
      mirrorAddress: BASE_MIRROR,
      consumerAddress: UNLOCK_CONSUMER,
      baseMessengerAddress: BASE_MESSENGER,
      authorizedL1RemoteSender: AUTHORIZED_L1_REMOTE_SENDER
    }),
    nullifierStateReader: createFixtureBaseNullifierStateReader(
      hasArg("--nullifier-consumed") ? "nullifier_consumed" : "nullifier_available"
    ),
    senderAccount: SENDER,
    simulator: createFixtureBaseAuthorizationExecutionSimulator(
      hasArg("--simulation-reverted") ? "consumer_reverted" : "simulation_succeeded"
    ),
    gasEstimator: createFixtureBaseExecutionGasEstimator("500000"),
    nonceReader: createFixtureBaseExecutionNonceReader("9"),
    feeDataReader: createFixtureBaseExecutionFeeDataReader(),
    issuedAt,
    expiresAt,
    auditCorrelationId: "diagnostic-m7-audit"
  };
}

async function main() {
  const result = await prepareBaseAuthorizationExecutionTransaction(buildFixtureRequest());
  const draft = result.status === "approved" ? result.value : undefined;
  const summary = {
    phase: "M.7",
    status: result.status,
    outcome: draft?.outcome ?? result.error?.details?.outcome,
    actionGate: ACTION_GATE,
    method: "verifyAndConsume",
    methodSelector: draft?.methodSelector ?? BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    calldataHash: draft?.calldataHash ?? null,
    value: draft?.value ?? null,
    proofInputHash: draft?.binding.proofInputHash ?? result.error?.details?.proofInputHash ?? null,
    factHigh: draft?.binding.factHigh ?? null,
    factLow: draft?.binding.factLow ?? null,
    nonceStatus: draft?.nonce.status ?? "unavailable",
    gasStatus: draft?.gas.status ?? "unavailable",
    feeStatus: draft?.fee.status ?? "unavailable",
    simulationStatus: draft?.simulation?.status ?? "unavailable",
    executionPrepared: result.status === "approved",
    transactionSigned: false,
    transactionSubmitted: false,
    userOperationCreated: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    baseStateMutated: false,
    applicationCanSubmitDirectly: false,
    liveMirroredFactEvidence: draft?.liveMirroredFactEvidence ?? false,
    productionSignable: draft?.productionSignable ?? false
  };
  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Base authorization execution preparation diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
