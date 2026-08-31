const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");

const { deployContract, expectRevert } = require("../helpers/context.cjs");
const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseExecutionSigningPresentation,
  createBaseExecutionSubmissionApproval,
  createBaseFinalExecutionApproval,
  createBaseMirroredFactEvidence,
  createFixtureBaseActionGateDeploymentReader,
  createFixtureBaseAuthorizationExecutionSimulator,
  createFixtureBaseExecutionFeeDataReader,
  createFixtureBaseExecutionGasEstimator,
  createFixtureBaseExecutionNonceReader,
  createFixtureBaseExecutionReceiptReader,
  createFixtureBaseExecutionSigner,
  createFixtureBaseExecutionTransactionSubmitter,
  createFixtureBaseMirroredFactStateReader,
  createFixtureBaseNullifierStateReader,
  createInMemoryBaseExecutionSubmittedTransactionStore,
  monitorBaseAuthorizationExecution,
  prepareBaseAuthorizationExecutionTransaction,
  requestBaseExecutionAuthorization,
  requestBaseExecutionSigning,
  requestBaseExecutionSubmission
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

const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const DEPLOYER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const POLICY_HASH = `0x${"22".repeat(32)}`;
const OWNER_COMMITMENT = `0x${"11".repeat(32)}`;

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

function encodeUnlockRequest(request) {
  return abiCoder.encode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    [request]
  );
}

async function deployContracts() {
  const [deployer, account, target] = await ethers.getSigners();
  const baseMessenger = await deployContract(deployer, "MockBaseCrossDomainMessenger");
  const adapter = await deployContract(deployer, "PhilBaseCrossDomainMessengerAdapter", [
    await baseMessenger.getAddress(),
    200000
  ]);
  const baseMirror = await deployContract(deployer, "PhilBaseProofInputHashMirror", [
    await baseMessenger.getAddress(),
    await adapter.getAddress()
  ]);
  const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
    await baseMirror.getAddress()
  ]);
  const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);
  const unlockConsumer = await deployContract(deployer, "PhilUnlockConsumer", [await gate.getAddress()]);
  return { deployer, account, target, baseMessenger, adapter, baseMirror, verifier, gate, unlockConsumer };
}

async function buildM8Fixture(options = {}) {
  const contracts = await deployContracts();
  const issuedAt = now();
  const expiresAt = futureDate();
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const consumerAddress = await contracts.unlockConsumer.getAddress();
  const nullifier = options.nullifier ?? `0x${"33".repeat(32)}`;
  const unlockRequest = {
    account: await contracts.account.getAddress(),
    target: options.target ?? await contracts.target.getAddress(),
    value: options.value ?? 0n,
    callData: ethers.hexlify(ethers.toUtf8Bytes("philcore-m8"))
  };
  const consumerData = encodeUnlockRequest(unlockRequest);
  const actionHash = unlockActionHash({
    chainId: 31337,
    consumer: consumerAddress,
    account: unlockRequest.account,
    target: unlockRequest.target,
    value: unlockRequest.value,
    callDataHash: dataHash(unlockRequest.callData)
  });
  const authorization = {
    consumer: consumerAddress,
    ownerCommitment: OWNER_COMMITMENT,
    actionHash,
    policyHash: POLICY_HASH,
    nullifier,
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
    finalizedAuthorizationPackageId: "m8-finalized-package",
    status: "authorization_package_finalized",
    outcome: "authorization_package_finalized",
    binding: {
      authorizationPackageDraftId: "m8-package-draft",
      proofGenerationArtifactId: "m8-proof-generation",
      proofVerificationResultId: "m8-proof-verification",
      sessionId: "m8-session",
      applicationId: "ethereum-net",
      intentId: "m8-intent",
      capabilityName: "request_contract_call",
      ownerCommitment: OWNER_COMMITMENT,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "m8-audit"
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
      proofArtifactId: "m8-proof-artifact",
      proofGenerationArtifactId: "m8-proof-generation",
      proofVerificationResultId: "m8-proof-verification",
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
      localVerificationResultId: "m8-proof-verification",
      verifiedProofReferenceId: "m8-proof-artifact"
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
    authoritativeCapabilityGrantId: "m8-capability-grant",
    requestId: "m8-capability-request",
    status: "active",
    outcome: "capability_granted",
    scope: {
      capabilityName: "request_contract_call",
      allowedTargets: [consumerAddress],
      actionTypes: ["base_authorization_execution"],
      chainId: 31337,
      network: "hardhat"
    },
    binding: {
      authoritativeTrustDecisionId: "m8-trust",
      authoritativePolicyDecisionId: "m8-policy",
      platformUserApprovalDecisionId: "m8-approval",
      sessionLifecycleId: "m8-lifecycle",
      sessionLifecycleState: "unlocked",
      ownerCommitment: OWNER_COMMITMENT,
      sessionId: "m8-session",
      applicationId: "ethereum-net",
      capabilityName: "request_contract_call",
      auditCorrelationId: "m8-audit",
      validityWindowId: "m8-window",
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
  const sessionLifecycleSnapshot = {
    lifecycleId: "m8-lifecycle",
    sessionId: "m8-session",
    state: "unlocked",
    sequence: 8,
    version: 8,
    createdAt: issuedAt,
    updatedAt: issuedAt,
    metadata: { deviceVaultUnlocked: true },
    limitations: ["ephemeral_only"],
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: true,
    grantsAuthority: false
  };
  const configuration = {
    configurationId: "m8-base-action-gate",
    approvalStatus: "accepted",
    activeProfile: { profileId: "hardhat-base-local", network: "hardhat", chainId: 31337, enabled: true },
    actionGateAddress: await contracts.gate.getAddress(),
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
      address: consumerAddress,
      consumerKind: "PhilUnlockConsumer",
      actionGateAddress: await contracts.gate.getAddress(),
      approved: true,
      payable: true
    },
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    abiVersion: "phil-base-action-gate-v1",
    supportedProofType: UNLOCK_PROOF_TYPE,
    valuePolicy: "exact_authorized_value",
    mainnetAllowed: false
  };
  const mirrorTx = await contracts.adapter.sendMessage(
    await contracts.baseMirror.getAddress(),
    contracts.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
      BigInt(fact.factHigh),
      BigInt(fact.factLow)
    ])
  );
  await mirrorTx.wait();
  const mirroredFactEvidence = createBaseMirroredFactEvidence({
    source: "local_hardhat_receipt",
    binding: {
      baseChainId: 31337,
      baseMirrorAddress: await contracts.baseMirror.getAddress(),
      baseMessengerAddress: await contracts.baseMessenger.getAddress(),
      authorizedL1RemoteSender: await contracts.adapter.getAddress(),
      mirrorTransactionHash: mirrorTx.hash,
      factHigh: fact.factHigh,
      factLow: fact.factLow,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "m8-audit"
    }
  });
  const nonce = String(await ethers.provider.getTransactionCount(await contracts.deployer.getAddress()));
  const deploymentReader = createFixtureBaseActionGateDeploymentReader({
    chainId: 31337,
    actionGateAddress: await contracts.gate.getAddress(),
    verifierAddress: await contracts.verifier.getAddress(),
    mirrorAddress: await contracts.baseMirror.getAddress(),
    consumerAddress,
    baseMessengerAddress: await contracts.baseMessenger.getAddress(),
    authorizedL1RemoteSender: await contracts.adapter.getAddress()
  });
  const prepared = await prepareBaseAuthorizationExecutionTransaction({
    requestId: "m8-preparation",
    finalizedAuthorizationPackage,
    baseActionAuthorization: authorization,
    proofPackage,
    consumerData,
    mirroredFactEvidence,
    activeCapabilityGrant,
    sessionLifecycleSnapshot,
    configuration,
    deploymentReader,
    nullifierStateReader: createFixtureBaseNullifierStateReader("nullifier_available"),
    senderAccount: await contracts.deployer.getAddress(),
    simulator: createFixtureBaseAuthorizationExecutionSimulator("simulation_succeeded"),
    gasEstimator: createFixtureBaseExecutionGasEstimator("900000"),
    nonceReader: createFixtureBaseExecutionNonceReader(nonce),
    feeDataReader: createFixtureBaseExecutionFeeDataReader(),
    issuedAt,
    expiresAt,
    auditCorrelationId: "m8-audit"
  });
  assert.equal(prepared.status, "approved", JSON.stringify(prepared.error, null, 2));
  const draft = prepared.value;
  const fee = draft.fee;
  const presentation = createBaseExecutionSigningPresentation({ draft, fee, auditCorrelationId: "m8-audit" });
  const approval = createBaseFinalExecutionApproval({
    presentation,
    source: "developer_fixture_approval",
    approved: true,
    expiresAt: futureDate()
  });
  assert.equal(approval.status, "approved");
  const callerIdentity = {
    callerId: "m8-developer-fixture-caller",
    mode: "developer_fixture",
    address: await contracts.deployer.getAddress(),
    displayName: "Developer fixture caller",
    approved: true,
    productionSuitable: false
  };
  const policy = {
    allowedCallerModes: ["developer_fixture"],
    allowedBaseChainIds: [31337],
    allowedActionGateAddresses: [await contracts.gate.getAddress()],
    allowedConsumerAddresses: [consumerAddress],
    allowMainnet: false,
    requireLiveMirroredFactEvidence: false,
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "200000000",
    maxGasLimit: "1000000",
    minBalanceWei: "1",
    allowedApprovalSources: ["developer_fixture_approval"]
  };
  const mirroredFactStateReader = {
    async readMirroredFactState(request) {
      const mirrored = await contracts.baseMirror.mirroredProofInputHashFact(
        BigInt(request.factHigh),
        BigInt(request.factLow)
      );
      return {
        status: mirrored ? "fact_mirrored" : "fact_not_mirrored",
        baseMirrorAddress: request.baseMirrorAddress,
        factHigh: request.factHigh,
        factLow: request.factLow,
        proofInputHash: request.proofInputHash,
        checkedAt: now(),
        baseStateMutated: false
      };
    }
  };
  const nullifierStateReader = {
    async readNullifierState(request) {
      const consumed = await contracts.gate.consumedNullifier(request.nullifier);
      return {
        status: consumed ? "nullifier_consumed" : "nullifier_available",
        actionGateAddress: request.actionGateAddress,
        nullifier: request.nullifier,
        checkedAt: now(),
        nullifierConsumed: consumed,
        nullifierReserved: false,
        baseStateMutated: false
      };
    }
  };
  const signingRequest = {
    requestId: "m8-signing",
    draft,
    mirroredFactEvidence,
    mirroredFactStateReader,
    activeCapabilityGrant,
    sessionLifecycleSnapshot,
    configuration,
    deploymentReader,
    nullifierStateReader,
    callerIdentity,
    policy,
    approval: approval.value,
    gasEstimator: createFixtureBaseExecutionGasEstimator("900000"),
    nonceReader: createFixtureBaseExecutionNonceReader(nonce),
    feeDataReader: createFixtureBaseExecutionFeeDataReader(),
    fundingStatus: { status: "sufficient", balanceWei: "100000000000000000000", checkedAt: now() },
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "m8-audit",
    signer: createFixtureBaseExecutionSigner({
      privateKey: DEPLOYER_PRIVATE_KEY,
      callerAddress: await contracts.deployer.getAddress()
    })
  };
  return {
    ...contracts,
    authorization,
    proofPackage,
    consumerData,
    fact,
    activeCapabilityGrant,
    sessionLifecycleSnapshot,
    deploymentReader,
    mirroredFactStateReader,
    nullifierStateReader,
    configuration,
    draft,
    policy,
    callerIdentity,
    approval: approval.value,
    signingRequest
  };
}

function receiptFromEthers(receipt) {
  return {
    transactionHash: receipt.hash,
    status: receipt.status === 1 ? "confirmed" : "reverted",
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    gasUsed: receipt.gasUsed.toString(),
    effectiveGasPrice: receipt.gasPrice?.toString() ?? "0",
    confirmations: 1,
    logs: receipt.logs.map((log) => ({
      address: log.address,
      topics: [...log.topics],
      data: log.data
    }))
  };
}

describe("Base authorization execution signing, submission, and monitoring boundary", function () {
  it("authorizes and signs the exact execution transaction without submitting it", async function () {
    const fixture = await buildM8Fixture();
    const authorization = await requestBaseExecutionAuthorization(fixture.signingRequest);
    assert.equal(authorization.status, "approved");
    assert.equal(authorization.value.outcome, "execution_authorized_for_signing");

    const signed = await requestBaseExecutionSigning(fixture.signingRequest);
    assert.equal(signed.status, "approved", JSON.stringify(signed.error, null, 2));
    assert.equal(signed.value.transactionSigned, true);
    assert.equal(signed.value.transactionSubmitted, false);
    assert.equal(signed.value.nullifierConsumed, false);
    assert.equal(signed.value.consumerExecuted, false);
    assert.equal(signed.value.baseStateMutated, false);
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), false);
  });

  it("rejects missing approval, live-required fixture approval, locked sessions, consumed nullifiers, and changed nonce", async function () {
    const fixture = await buildM8Fixture();
    const missingApproval = await requestBaseExecutionSigning({ ...fixture.signingRequest, approval: undefined });
    assert.equal(missingApproval.status, "denied");
    assert.equal(missingApproval.error.details.outcome, "additional_approval_required");

    const liveRequired = await requestBaseExecutionSigning({
      ...fixture.signingRequest,
      policy: { ...fixture.policy, requireLiveMirroredFactEvidence: true }
    });
    assert.equal(liveRequired.status, "denied");
    assert.equal(liveRequired.error.details.outcome, "mirrored_fact_ineligible");

    const locked = await requestBaseExecutionSigning({
      ...fixture.signingRequest,
      sessionLifecycleSnapshot: { ...fixture.sessionLifecycleSnapshot, state: "locked" }
    });
    assert.equal(locked.status, "denied");
    assert.equal(locked.error.details.outcome, "session_ineligible");

    const consumed = await requestBaseExecutionSigning({
      ...fixture.signingRequest,
      nullifierStateReader: createFixtureBaseNullifierStateReader("nullifier_consumed")
    });
    assert.equal(consumed.status, "denied");
    assert.equal(consumed.error.details.outcome, "nullifier_unavailable");

    const nonceChanged = await requestBaseExecutionSigning({
      ...fixture.signingRequest,
      nonceReader: createFixtureBaseExecutionNonceReader("999")
    });
    assert.equal(nonceChanged.status, "denied");
    assert.equal(nonceChanged.error.details.outcome, "malformed");
  });

  it("submits only the exact signed artifact with approval and blocks duplicates or changed state", async function () {
    const fixture = await buildM8Fixture();
    const signed = await requestBaseExecutionSigning(fixture.signingRequest);
    assert.equal(signed.status, "approved");
    const submissionApproval = createBaseExecutionSubmissionApproval({
      signedTransaction: signed.value,
      source: "developer_fixture_approval"
    });
    const store = createInMemoryBaseExecutionSubmittedTransactionStore();
    const submitted = await requestBaseExecutionSubmission({
      requestId: "m8-submission",
      signedTransaction: signed.value,
      submissionApproval,
      mirroredFactStateReader: fixture.mirroredFactStateReader,
      nullifierStateReader: fixture.nullifierStateReader,
      activeCapabilityGrant: fixture.activeCapabilityGrant,
      sessionLifecycleSnapshot: fixture.sessionLifecycleSnapshot,
      deploymentReader: fixture.deploymentReader,
      configuration: fixture.configuration,
      gasEstimator: createFixtureBaseExecutionGasEstimator("900000"),
      nonceReader: createFixtureBaseExecutionNonceReader(fixture.draft.nonce.nonce),
      feeDataReader: createFixtureBaseExecutionFeeDataReader(),
      submitter: createFixtureBaseExecutionTransactionSubmitter(),
      submittedTransactionStore: store,
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(submitted.status, "approved");
    assert.equal(submitted.value.transactionSubmitted, true);
    assert.equal(submitted.value.transactionConfirmed, false);

    const duplicate = await requestBaseExecutionSubmission({
      requestId: "m8-submission-duplicate",
      signedTransaction: signed.value,
      submissionApproval,
      mirroredFactStateReader: fixture.mirroredFactStateReader,
      nullifierStateReader: fixture.nullifierStateReader,
      activeCapabilityGrant: fixture.activeCapabilityGrant,
      sessionLifecycleSnapshot: fixture.sessionLifecycleSnapshot,
      deploymentReader: fixture.deploymentReader,
      configuration: fixture.configuration,
      gasEstimator: createFixtureBaseExecutionGasEstimator("900000"),
      nonceReader: createFixtureBaseExecutionNonceReader(fixture.draft.nonce.nonce),
      feeDataReader: createFixtureBaseExecutionFeeDataReader(),
      submitter: createFixtureBaseExecutionTransactionSubmitter(),
      submittedTransactionStore: store,
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(duplicate.status, "denied");
    assert.equal(duplicate.error.details.outcome, "duplicate_submission");
  });

  it("executes the real local ActionGate path, verifies nullifier consumption and consumer execution, and blocks replay", async function () {
    const fixture = await buildM8Fixture();
    const signed = await requestBaseExecutionSigning(fixture.signingRequest);
    assert.equal(signed.status, "approved");

    const tx = await ethers.provider.broadcastTransaction(signed.value.signatureArtifact.rawSignedTransaction);
    const receipt = await tx.wait();
    const runtimeReceipt = receiptFromEthers(receipt);
    assert.equal(runtimeReceipt.status, "confirmed");

    const consumerInterface = new ethers.Interface([
      "event UnlockForwarded(bytes32 indexed nullifier,address indexed account,address indexed target,bytes32 actionHash)"
    ]);
    const unlockForwardedTopic = consumerInterface.getEvent("UnlockForwarded").topicHash;
    const consumerExecutionReader = {
      async readConsumerExecution({ signedTransaction, receipt: monitoredReceipt }) {
        let matched = false;
        for (const log of monitoredReceipt.logs) {
          if (log.address.toLowerCase() !== signedTransaction.binding.consumerAddress.toLowerCase()) continue;
          try {
            const parsed = consumerInterface.parseLog({ topics: log.topics, data: log.data });
            matched = parsed?.name === "UnlockForwarded"
              && String(parsed.args.nullifier).toLowerCase() === signedTransaction.binding.nullifier.toLowerCase();
          } catch {
            matched = log.topics[0] === unlockForwardedTopic
              && log.topics[1]?.toLowerCase() === signedTransaction.binding.nullifier.toLowerCase();
          }
        }
        return {
          status: matched ? "consumer_executed" : "consumer_not_executed",
          consumerAddress: signedTransaction.binding.consumerAddress,
          actionGateAddress: signedTransaction.binding.actionGateAddress,
          transactionHash: signedTransaction.transactionHashBinding.transactionHash,
          nullifier: signedTransaction.binding.nullifier,
          actionHash: signedTransaction.binding.actionHash,
          consumerDataHash: signedTransaction.binding.consumerDataHash,
          target: fixture.draft.consumerCallPreview.target,
          value: signedTransaction.binding.value,
          checkedAt: now(),
          approvedActionMatched: matched
        };
      }
    };
    const monitored = await monitorBaseAuthorizationExecution({
      requestId: "m8-monitoring",
      signedTransaction: signed.value,
      receiptReader: createFixtureBaseExecutionReceiptReader(runtimeReceipt),
      nullifierStateReader: fixture.nullifierStateReader,
      consumerExecutionReader,
      minConfirmations: 1
    });
    assert.equal(monitored.status, "approved", JSON.stringify(monitored.error, null, 2));
    assert.equal(monitored.value.transactionConfirmed, true);
    assert.equal(monitored.value.nullifierConsumed, true);
    assert.equal(monitored.value.consumerExecuted, true);
    assert.equal(monitored.value.approvedActionMatched, true);
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), true);

    await expectRevert(
      () => fixture.gate.verifyAndConsume(fixture.authorization, fixture.proofPackage, fixture.consumerData),
      "expected replay to revert"
    );
  });

  it("keeps diagnostics non-mutating", function () {
    const diagnostic = spawnSync("npm", ["run", "diagnose:base-execution-signing", "--", "--json"], {
      encoding: "utf8"
    });
    assert.equal(diagnostic.status, 0, diagnostic.stderr);
    const output = JSON.parse(diagnostic.stdout.slice(diagnostic.stdout.indexOf("{")));
    assert.equal(output.phase, "M.8");
    assert.equal(output.transactionSigned, true);
    assert.equal(output.transactionSubmitted, false);
    assert.equal(output.nullifierConsumed, false);
    assert.equal(output.consumerExecuted, false);
    assert.equal(output.live_base_execution_performed, false);
  });
});
