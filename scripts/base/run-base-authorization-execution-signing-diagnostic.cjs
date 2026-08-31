const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseExecutionSigningPresentation,
  createBaseFinalExecutionApproval,
  createFixtureBaseActionGateDeploymentReader,
  createFixtureBaseExecutionFeeDataReader,
  createFixtureBaseExecutionGasEstimator,
  createFixtureBaseExecutionNonceReader,
  createFixtureBaseExecutionSigner,
  createFixtureBaseMirroredFactStateReader,
  createFixtureBaseNullifierStateReader,
  createBaseMirroredFactEvidence,
  requestBaseExecutionSigning
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const { keccak256, Wallet } = require("ethers");

const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const CALLER = new Wallet(PRIVATE_KEY).address;
const ACTION_GATE = "0x1000000000000000000000000000000000000001";
const VERIFIER = "0x1000000000000000000000000000000000000002";
const MIRROR = "0x1000000000000000000000000000000000000003";
const MESSENGER = "0x1000000000000000000000000000000000000004";
const REMOTE = "0x1000000000000000000000000000000000000005";
const CONSUMER = "0x1000000000000000000000000000000000000006";
const OWNER = `0x${"11".repeat(32)}`;
const NULLIFIER = `0x${"33".repeat(32)}`;
const PROOF_INPUT_HASH = "0xaeb171de197647486fe798d3945f1f8475bb4d6f15bd8f5533d41ecec70f5882";
const FACT_HIGH = "0xaeb171de197647486fe798d3945f1f84";
const FACT_LOW = "0x75bb4d6f15bd8f5533d41ecec70f5882";

function hasArg(name) {
  return process.argv.includes(name);
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function fixtureDraft() {
  const calldata = `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}${"00".repeat(96)}`;
  return {
    baseAuthorizationExecutionTransactionDraftId: "diagnostic-m8-draft",
    status: "execution_transaction_draft_created",
    outcome: "execution_transaction_draft_created",
    binding: {
      finalizedAuthorizationPackageId: "diagnostic-finalized-package",
      authoritativeCapabilityGrantId: "diagnostic-capability-grant",
      sessionId: "diagnostic-session",
      applicationId: "ethereum-net",
      ownerCommitment: OWNER,
      actionHash: `0x${"44".repeat(32)}`,
      policyHash: `0x${"55".repeat(32)}`,
      nullifier: NULLIFIER,
      proofInputHash: PROOF_INPUT_HASH,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      actionGateAddress: ACTION_GATE,
      verifierAddress: VERIFIER,
      baseMirrorAddress: MIRROR,
      consumerAddress: CONSUMER,
      senderAccount: CALLER,
      value: "0",
      calldataHash: keccak256(calldata),
      consumerDataHash: `0x${"66".repeat(32)}`,
      auditCorrelationId: "diagnostic-m8-audit"
    },
    to: ACTION_GATE,
    from: CALLER,
    chainId: 31337,
    methodName: "verifyAndConsume",
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    calldata,
    calldataHash: keccak256(calldata),
    value: "0",
    consumerCallPreview: {
      account: "0x1000000000000000000000000000000000000008",
      target: "0x1000000000000000000000000000000000000009",
      value: "0",
      callData: "0x",
      consumerData: "0x",
      consumerDataHash: `0x${"66".repeat(32)}`,
      actionHash: `0x${"44".repeat(32)}`,
      callDataHash: `0x${"77".repeat(32)}`
    },
    nullifierState: {
      status: "nullifier_available",
      actionGateAddress: ACTION_GATE,
      nullifier: NULLIFIER,
      checkedAt: now(),
      nullifierConsumed: false,
      nullifierReserved: false,
      baseStateMutated: false
    },
    gas: { status: "estimated", gasLimit: "900000", checkedAt: now(), source: "fixture" },
    nonce: { status: "resolved", nonce: "0", checkedAt: now(), source: "fixture" },
    fee: {
      status: "resolved",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
      checkedAt: now(),
      source: "fixture"
    },
    issuedAt: now(),
    expiresAt: futureDate(),
    transactionPrepared: true,
    transactionSigned: false,
    transactionSubmitted: false,
    simulationPerformed: true,
    simulationSucceeded: true,
    nullifierConsumed: false,
    consumerExecuted: false,
    baseStateMutated: false,
    userOperationCreated: false,
    applicationCanSubmitDirectly: false,
    liveMirroredFactEvidence: false,
    productionSignable: false
  };
}

async function main() {
  const draft = fixtureDraft();
  const presentation = createBaseExecutionSigningPresentation({ draft, fee: draft.fee });
  const approval = createBaseFinalExecutionApproval({
    presentation,
    source: "developer_fixture_approval",
    approved: true,
    expiresAt: futureDate()
  });
  const mirroredFactEvidence = createBaseMirroredFactEvidence({
    source: "fixture_receipt",
    binding: {
      baseChainId: 31337,
      baseMirrorAddress: MIRROR,
      baseMessengerAddress: MESSENGER,
      authorizedL1RemoteSender: REMOTE,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      proofInputHash: PROOF_INPUT_HASH,
      auditCorrelationId: "diagnostic-m8-audit"
    }
  });
  const signed = await requestBaseExecutionSigning({
    requestId: "diagnostic-m8-signing",
    draft,
    mirroredFactEvidence,
    mirroredFactStateReader: createFixtureBaseMirroredFactStateReader("fact_mirrored"),
    activeCapabilityGrant: {
      authoritativeCapabilityGrantId: "diagnostic-capability-grant",
      requestId: "diagnostic-capability-request",
      status: "active",
      outcome: "capability_granted",
      scope: { capabilityName: "request_contract_call", allowedTargets: [CONSUMER], actionTypes: ["base_authorization_execution"] },
      binding: {
        authoritativeTrustDecisionId: "trust",
        authoritativePolicyDecisionId: "policy",
        platformUserApprovalDecisionId: "approval",
        sessionLifecycleId: "lifecycle",
        sessionLifecycleState: "unlocked",
        ownerCommitment: OWNER,
        sessionId: "diagnostic-session",
        applicationId: "ethereum-net",
        capabilityName: "request_contract_call",
        auditCorrelationId: "diagnostic-m8-audit",
        validityWindowId: "window",
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
        issuedAt: now(),
        expiresAt: futureDate(),
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
    },
    sessionLifecycleSnapshot: {
      lifecycleId: "lifecycle",
      sessionId: "diagnostic-session",
      state: hasArg("--locked") ? "locked" : "unlocked",
      sequence: 8,
      version: 8,
      createdAt: now(),
      updatedAt: now(),
      limitations: ["ephemeral_only"],
      persisted: false,
      ownsSecrets: false,
      authenticatesUser: false,
      unlocksVault: true,
      grantsAuthority: false
    },
    configuration: {
      configurationId: "diagnostic-base-action-gate",
      approvalStatus: "accepted",
      activeProfile: { profileId: "hardhat-base-local", network: "hardhat", chainId: 31337, enabled: true },
      actionGateAddress: ACTION_GATE,
      verifier: { address: VERIFIER, expectedProofType: "stwo-unlock-keccak-v1", baseMirrorAddress: MIRROR, approved: true },
      mirror: { address: MIRROR, messengerAddress: MESSENGER, authorizedL1RemoteSender: REMOTE, approved: true },
      consumer: { address: CONSUMER, consumerKind: "PhilUnlockConsumer", actionGateAddress: ACTION_GATE, approved: true, payable: true },
      methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
      abiVersion: "phil-base-action-gate-v1",
      supportedProofType: "stwo-unlock-keccak-v1",
      valuePolicy: "exact_authorized_value",
      mainnetAllowed: false
    },
    deploymentReader: createFixtureBaseActionGateDeploymentReader({
      chainId: 31337,
      actionGateAddress: ACTION_GATE,
      verifierAddress: VERIFIER,
      mirrorAddress: MIRROR,
      consumerAddress: CONSUMER,
      baseMessengerAddress: MESSENGER,
      authorizedL1RemoteSender: REMOTE
    }),
    nullifierStateReader: createFixtureBaseNullifierStateReader("nullifier_available"),
    callerIdentity: {
      callerId: "diagnostic-fixture-caller",
      mode: "developer_fixture",
      address: CALLER,
      displayName: "Diagnostic fixture caller",
      approved: true,
      productionSuitable: false
    },
    policy: {
      allowedCallerModes: ["developer_fixture"],
      allowedBaseChainIds: [31337],
      allowedActionGateAddresses: [ACTION_GATE],
      allowedConsumerAddresses: [CONSUMER],
      allowMainnet: false,
      requireLiveMirroredFactEvidence: false,
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "200000000",
      maxGasLimit: "1000000",
      minBalanceWei: "1",
      allowedApprovalSources: ["developer_fixture_approval"]
    },
    approval: approval.value,
    gasEstimator: createFixtureBaseExecutionGasEstimator("900000"),
    nonceReader: createFixtureBaseExecutionNonceReader("0"),
    feeDataReader: createFixtureBaseExecutionFeeDataReader(),
    fundingStatus: { status: "sufficient", balanceWei: "1000000000000000000", checkedAt: now() },
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m8-audit",
    signer: createFixtureBaseExecutionSigner({ privateKey: PRIVATE_KEY, callerAddress: CALLER })
  });
  const summary = {
    phase: "M.8",
    status: signed.status,
    outcome: signed.status === "approved" ? signed.value.outcome : signed.error.details.outcome,
    callerModel: "philcore_eoa_compatibility_for_local_and_testnet_only",
    preferredProductionModel: "philcore_erc4337_smart_account",
    actionGate: ACTION_GATE,
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    transactionHash: signed.status === "approved" ? signed.value.transactionHashBinding.transactionHash : null,
    transactionSigned: signed.status === "approved",
    transactionSubmitted: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    baseStateMutated: false,
    live_base_execution_performed: false,
    reason: "fixture/local diagnostic only; live Base Sepolia prerequisites are not configured"
  };
  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Base authorization execution signing diagnostic");
  for (const [key, value] of Object.entries(summary)) console.log(`${key}: ${value}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
