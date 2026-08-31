require("tsx/cjs");

const { spawnSync } = require("node:child_process");
const {
  Contract,
  JsonRpcProvider,
  getAddress,
  keccak256
} = require("ethers");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  createRestrictedSepoliaBundlerClient,
  redactRpcEndpoint
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const { loadSepoliaLocalEnvironment } = require("./local-environment.cjs");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  ROOT,
  ensureNoSecrets,
  readJson,
  verifyConfiguredKeyPairs
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  O23R_RECEIPT_PATH,
  O24_RECEIPT_PATH,
  calculateO24Addresses,
  expectedFactoryRuntimeBinding
} = require("./o24-factory-common.cjs");
const {
  O25_PREFUND_PATH,
  O25_READINESS_PATH,
  O25_USER_OPERATION_PATH,
  PROPOSAL_FRESHNESS_SECONDS,
  amount,
  buildEstimationOnlyUserOperation,
  buildFundingProposal,
  calculateFeeScenarios,
  calculateNoPaymasterRequiredPrefund,
  writeJson
} = require("./o25-readiness-common.cjs");

const FACTORY_ARTIFACT = require(
  "../../artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json"
);
const O24_PROPOSAL_PATH =
  `${ROOT}/config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_PROPOSAL.json`;
const EXPECTED_TARGET_RUNTIME_HASH =
  "0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad";
const EXPECTED_ENTRYPOINT_RUNTIME_HASH =
  "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";

function runLocalSimulation() {
  const result = spawnSync(
    process.execPath,
    ["scripts/ethereum-sepolia/estimate-o25-local-entrypoint.cjs"],
    {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env }
    }
  );
  if (result.status !== 0) {
    throw new Error(`o25_local_entrypoint_simulation_failed:${result.stderr.trim()}`);
  }
  const output = JSON.parse(result.stdout);
  if (
    output.publicNetworkContacted !== false
    || output.realUserSignatureGenerated !== false
    || output.allFailureChecksPassed !== true
    || output.state.confirmationSucceeded !== true
  ) {
    throw new Error("o25_local_entrypoint_simulation_invalid");
  }
  return output;
}

async function bundlerReadiness(userOperation) {
  const url = process.env.PHILCORE_SEPOLIA_BUNDLER_URL;
  if (!url) {
    return {
      status: "BUNDLER_NOT_CONFIGURED",
      configured: false,
      endpointClassification: "not_configured",
      contacted: false,
      supportedEntryPointV07: false,
      estimationPerformed: false,
      submissionMethodCalled: false,
      requirementsSatisfied: false
    };
  }
  const client = createRestrictedSepoliaBundlerClient({ url });
  const [chainResult, supported] = await Promise.all([
    client.request("eth_chainId", []),
    client.request("eth_supportedEntryPoints", [])
  ]);
  const chainId = Number(BigInt(String(chainResult)));
  if (chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("BUNDLER_WRONG_CHAIN");
  }
  const entryPoints = Array.isArray(supported)
    ? supported.map((value) => getAddress(String(value)))
    : [];
  const v07Supported = entryPoints.includes(
    getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)
  );
  if (!v07Supported) throw new Error("BUNDLER_ENTRYPOINT_V07_UNSUPPORTED");
  const nullHash = `0x${"00".repeat(32)}`;
  const methodResults = {};
  for (const [method, params] of [
    ["eth_getUserOperationByHash", [nullHash]],
    ["eth_getUserOperationReceipt", [nullHash]]
  ]) {
    try {
      await client.request(method, params);
      methodResults[method] = "supported";
    } catch (error) {
      methodResults[method] = `failed_sanitized:${error instanceof Error ? error.name : "Error"}`;
    }
  }
  let estimation;
  try {
    estimation = await client.request("eth_estimateUserOperationGas", [
      userOperation.rpcV07Representation,
      ERC4337_V07_CANONICAL_ENTRYPOINT
    ]);
  } catch (error) {
    estimation = {
      status: "estimation_rejected_or_unavailable",
      errorClassification: error instanceof Error ? error.name : "Error"
    };
  }
  return {
    status: "BUNDLER_READ_ONLY_CAPABILITIES_CHECKED",
    configured: true,
    endpointClassification: client.endpointClassification,
    contacted: true,
    chainId,
    chainMatched: true,
    supportedEntryPointV07: true,
    supportedEntryPoints: entryPoints,
    methodResults,
    estimation,
    estimationPerformed: true,
    submissionMethodCalled: false,
    requirementsSatisfied:
      methodResults.eth_getUserOperationByHash === "supported"
      && methodResults.eth_getUserOperationReceipt === "supported"
  };
}

function assertEqual(actual, expected, error) {
  if (actual !== expected) throw new Error(error);
}

async function main() {
  const localEnvironment = loadSepoliaLocalEnvironment({
    includeO23rSensitiveSelectors: true
  });
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const factory = new Contract(EXPECTED_FACTORY, FACTORY_ARTIFACT.abi, provider);
  const entryPoint = new Contract(
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    EntryPointArtifact.abi,
    provider
  );

  const network = await provider.getNetwork();
  assertEqual(Number(network.chainId), ETHEREUM_SEPOLIA_CHAIN_ID, "WRONG_ETHEREUM_CHAIN");
  const latestBlock = await provider.getBlock("latest");
  if (!latestBlock?.hash || latestBlock.baseFeePerGas === null) {
    throw new Error("latest_block_fee_evidence_unavailable");
  }
  const observedAt = new Date(Number(latestBlock.timestamp) * 1000).toISOString();
  const expiresAt = new Date(
    (Number(latestBlock.timestamp) + PROPOSAL_FRESHNESS_SECONDS) * 1000
  ).toISOString();

  const [
    feeData,
    feeHistory,
    targetCode,
    factoryCode,
    entryPointCode,
    accountCode,
    targetTxCount,
    factoryTxCount,
    accountLatestNonce,
    accountPendingNonce,
    accountBalance,
    accountDeposit,
    entryPointNonce,
    account1LatestNonce,
    account1PendingNonce,
    account1Balance,
    account2LatestNonce,
    account2PendingNonce,
    account2Balance,
    factoryEntryPoint,
    factoryTarget,
    factoryChain
  ] = await Promise.all([
    provider.getFeeData(),
    provider.send("eth_feeHistory", [5, "latest", [10, 50, 90]]),
    provider.getCode(EXPECTED_TARGET),
    provider.getCode(EXPECTED_FACTORY),
    provider.getCode(ERC4337_V07_CANONICAL_ENTRYPOINT),
    provider.getCode(EXPECTED_ACCOUNT),
    provider.getTransactionCount(EXPECTED_TARGET, "latest"),
    provider.getTransactionCount(EXPECTED_FACTORY, "latest"),
    provider.getTransactionCount(EXPECTED_ACCOUNT, "latest"),
    provider.getTransactionCount(EXPECTED_ACCOUNT, "pending"),
    provider.getBalance(EXPECTED_ACCOUNT),
    entryPoint.balanceOf(EXPECTED_ACCOUNT),
    entryPoint.getNonce(EXPECTED_ACCOUNT, 0),
    provider.getTransactionCount(EXPECTED_DEPLOYER, "latest"),
    provider.getTransactionCount(EXPECTED_DEPLOYER, "pending"),
    provider.getBalance(EXPECTED_DEPLOYER),
    provider.getTransactionCount(EXPECTED_FUNDING, "latest"),
    provider.getTransactionCount(EXPECTED_FUNDING, "pending"),
    provider.getBalance(EXPECTED_FUNDING),
    factory.entryPoint(),
    factory.approvedConfirmationTarget(),
    factory.expectedChainId()
  ]);

  const targetCodeHash = keccak256(targetCode);
  const factoryCodeHash = keccak256(factoryCode);
  const entryPointCodeHash = keccak256(entryPointCode);
  assertEqual(targetCodeHash, EXPECTED_TARGET_RUNTIME_HASH, "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH");
  assertEqual(
    factoryCodeHash,
    expectedFactoryRuntimeBinding().bytecodeHash,
    "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH"
  );
  assertEqual(
    entryPointCodeHash,
    EXPECTED_ENTRYPOINT_RUNTIME_HASH,
    "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH"
  );
  assertEqual(
    getAddress(factoryEntryPoint),
    getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT),
    "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH"
  );
  assertEqual(
    getAddress(factoryTarget),
    getAddress(EXPECTED_TARGET),
    "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH"
  );
  assertEqual(
    Number(factoryChain),
    ETHEREUM_SEPOLIA_CHAIN_ID,
    "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH"
  );

  if (
    accountCode !== "0x"
    || accountBalance !== 0n
    || accountDeposit !== 0n
    || entryPointNonce !== 0n
    || accountLatestNonce !== 0
    || accountPendingNonce !== 0
  ) {
    throw new Error("COUNTERFACTUAL_ACCOUNT_STATE_CHANGED");
  }

  const identity = localEnvironment.identity;
  const localAddress = calculateO24Addresses(
    identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const factoryAddress = await factory[
    "getAddress(address,bytes32,bytes32,uint256)"
  ](
    identity.validatorAddress,
    identity.ownerCommitment,
    localAddress.validatorKeyIdBinding,
    BigInt(process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT)
  );
  assertEqual(localAddress.account, EXPECTED_ACCOUNT, "COUNTERFACTUAL_ACCOUNT_PREDICTION_CHANGED");
  assertEqual(getAddress(factoryAddress), EXPECTED_ACCOUNT, "COUNTERFACTUAL_ACCOUNT_PREDICTION_CHANGED");

  const baseFee = latestBlock.baseFeePerGas;
  if (
    feeData.gasPrice === null
    || feeData.maxFeePerGas === null
    || feeData.maxPriorityFeePerGas === null
  ) {
    throw new Error("sepolia_fee_data_unavailable");
  }
  const feeScenarios = calculateFeeScenarios({
    baseFeePerGasWei: baseFee.toString(),
    maxFeePerGasWei: feeData.maxFeePerGas.toString(),
    maxPriorityFeePerGasWei: feeData.maxPriorityFeePerGas.toString()
  });
  const estimationOnlyUserOperation = buildEstimationOnlyUserOperation({
    identity,
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    expiry: String(Number(latestBlock.timestamp) + 600),
    maxFeePerGas: feeScenarios.recommended.maxFeePerGas.wei,
    maxPriorityFeePerGas: feeScenarios.recommended.maxPriorityFeePerGas.wei
  });
  const bundler = await bundlerReadiness(estimationOnlyUserOperation);
  const simulation = runLocalSimulation();

  const gasLimits = {
    verificationGasLimit: "1500000",
    callGasLimit: "300000",
    preVerificationGas: "200000",
    paymasterVerificationGasLimit: "0",
    paymasterPostOpGasLimit: "0"
  };
  const currentPrefund = calculateNoPaymasterRequiredPrefund({
    ...gasLimits,
    maxFeePerGas: feeScenarios.current.maxFeePerGas.wei
  });
  const recommendedPrefund = calculateNoPaymasterRequiredPrefund({
    ...gasLimits,
    maxFeePerGas: feeScenarios.recommended.maxFeePerGas.wei
  });
  const hardCeiling = calculateNoPaymasterRequiredPrefund({
    ...gasLimits,
    maxFeePerGas: feeScenarios.rejectionCeiling.maxFeePerGas.wei
  });
  const observedExecutionCost =
    BigInt(simulation.operation.userOperationActualGasUsed) * feeData.gasPrice;

  const fundingProposal = buildFundingProposal({
    valueWei: recommendedPrefund.requiredPrefundWei,
    maxFeePerGasWei: feeScenarios.recommended.maxFeePerGas.wei,
    maxPriorityFeePerGasWei: feeScenarios.recommended.maxPriorityFeePerGas.wei,
    nonce: String(account2PendingNonce),
    senderBalanceWei: account2Balance.toString(),
    smartAccountBalanceWei: accountBalance.toString(),
    latestBlockNumber: latestBlock.number,
    latestBlockHash: latestBlock.hash,
    observedAt,
    expiresAt
  });

  const o24Proposal = readJson(O24_PROPOSAL_PATH);
  const o23rReceipt = readJson(O23R_RECEIPT_PATH);
  const o24Receipt = readJson(O24_RECEIPT_PATH);
  const readiness = {
    schemaVersion: "philcore-o25-counterfactual-account-readiness-v1",
    phase: "O.25",
    status: bundler.configured
      ? "READ_ONLY_READINESS_REVIEW_COMPLETE"
      : "READ_ONLY_READINESS_REVIEW_COMPLETE_BUNDLER_NOT_CONFIGURED",
    generatedAt: new Date().toISOString(),
    sourceHead: require("node:child_process").execFileSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: ROOT, encoding: "utf8" }
    ).trim(),
    securityModel: "local-proof-gated-v1",
    network: {
      name: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      latestBlockNumber: String(latestBlock.number),
      latestBlockHash: latestBlock.hash,
      latestBlockTimestamp: observedAt,
      rpcClassification: redactRpcEndpoint(process.env.PHILCORE_SEPOLIA_RPC_URL)
    },
    repositoryAndEnvironment: {
      branch: require("node:child_process").execFileSync(
        "git",
        ["branch", "--show-current"],
        { cwd: ROOT, encoding: "utf8" }
      ).trim(),
      localEnvironmentPath: ".env.sepolia.local",
      localEnvironmentIgnored: true,
      localEnvironmentMode: "0600",
      account1KeyAddressBinding: keyBindings.deployer.addressMatch,
      account2KeyAddressBinding: keyBindings.funding.addressMatch,
      privateMaterialPrinted: false
    },
    canonicalIdentity: {
      identityId: identity.identityId,
      ownerCommitment: identity.ownerCommitment,
      validatorAddress: identity.validatorAddress,
      validatorKeyReferenceId: identity.validatorKeyId,
      validatorKeyIdBinding: localAddress.validatorKeyIdBinding,
      preserved: identity.validatorAddress === EXPECTED_VALIDATOR
    },
    confirmationTarget: {
      address: EXPECTED_TARGET,
      deploymentTransaction: o23rReceipt.transactionHash,
      runtimeCodeHash: targetCodeHash,
      expectedRuntimeCodeHash: EXPECTED_TARGET_RUNTIME_HASH,
      matched: true,
      transactionCount: String(targetTxCount),
      changedDuringO25: false
    },
    factory: {
      address: EXPECTED_FACTORY,
      deploymentTransaction: o24Receipt.transactionHash,
      runtimeCodeHash: factoryCodeHash,
      expectedRuntimeCodeHash: expectedFactoryRuntimeBinding().bytecodeHash,
      entryPoint: getAddress(factoryEntryPoint),
      approvedConfirmationTarget: getAddress(factoryTarget),
      expectedChainId: Number(factoryChain),
      matched: true,
      transactionCount: String(factoryTxCount),
      changedDuringO25: false
    },
    entryPoint: {
      address: ERC4337_V07_CANONICAL_ENTRYPOINT,
      version: "0.7",
      runtimeCodeHash: entryPointCodeHash,
      expectedRuntimeCodeHash: EXPECTED_ENTRYPOINT_RUNTIME_HASH,
      matched: true
    },
    accounts: {
      account1: {
        address: EXPECTED_DEPLOYER,
        role: "completed_target_and_factory_deployer_only",
        latestNonce: String(account1LatestNonce),
        pendingNonce: String(account1PendingNonce),
        balance: amount(account1Balance),
        signingUsedDuringO25: false
      },
      account2: {
        address: EXPECTED_FUNDING,
        role: "future_counterfactual_prefund_only",
        latestNonce: String(account2LatestNonce),
        pendingNonce: String(account2PendingNonce),
        balance: amount(account2Balance),
        signingUsedDuringO25: false
      }
    },
    counterfactualAccount: {
      address: EXPECTED_ACCOUNT,
      localCreate2Derivation: localAddress.account,
      factoryGetAddressResult: getAddress(factoryAddress),
      agreement: true,
      factory: EXPECTED_FACTORY,
      saltDecimal: localAddress.accountSaltDecimal,
      saltBytes32: localAddress.accountSaltBytes32,
      owner: identity.validatorAddress,
      ownerCommitment: identity.ownerCommitment,
      validatorKeyIdBinding: localAddress.validatorKeyIdBinding,
      creationBytecodeHash: localAddress.accountCreationBytecodeHash,
      constructorDataHash: localAddress.accountConstructorDataHash,
      initCodeHash: localAddress.accountInitCodeHash,
      codeStatus: "empty",
      balance: amount(accountBalance),
      latestTransactionCount: String(accountLatestNonce),
      pendingTransactionCount: String(accountPendingNonce),
      entryPointNonce: entryPointNonce.toString(),
      entryPointDeposit: amount(accountDeposit),
      deployed: false,
      funded: false,
      unexpectedTransactionHistory: false
    },
    initialization: {
      factoryMethod: "createAccount(address,bytes32,bytes32,uint256)",
      factoryAddress: EXPECTED_FACTORY,
      factoryDataHash: estimationOnlyUserOperation.factoryDataHash,
      packedInitCodeHash: keccak256(
        estimationOnlyUserOperation.packedUserOperation.initCode
      ),
      v07RpcRepresentation: "factory_and_factoryData",
      expectedSender: EXPECTED_ACCOUNT,
      expectedEntryPointNonce: "0",
      constructorInputs: {
        entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
        owner: identity.validatorAddress,
        ownerCommitment: identity.ownerCommitment,
        approvedConfirmationTarget: EXPECTED_TARGET,
        validatorKeyId: localAddress.validatorKeyIdBinding,
        expectedChainId: ETHEREUM_SEPOLIA_CHAIN_ID
      },
      recoveryAuthorityPresent: false,
      arbitraryOwnerSubstitutionAllowed: false,
      accountCreationAndConfirmationAtomic: true,
      failureRollsBackCreation: true,
      sourceProposalAccountInitCodeHash:
        o24Proposal.counterfactualAccount.accountInitCodeHash
    },
    estimationOnlyUserOperation: {
      artifact: "config/ethereum-sepolia/O25_ESTIMATION_ONLY_USER_OPERATION.json",
      artifactDigest: estimationOnlyUserOperation.artifactDigest,
      submissionReady: false
    },
    localSimulation: simulation,
    feeEvidence: {
      observedAt,
      latestBlockNumber: String(latestBlock.number),
      latestBlockHash: latestBlock.hash,
      baseFeePerGas: amount(baseFee),
      gasPrice: amount(feeData.gasPrice),
      rpcSuggestedMaxFeePerGas: amount(feeData.maxFeePerGas),
      rpcSuggestedMaxPriorityFeePerGas: amount(feeData.maxPriorityFeePerGas),
      feeHistory: {
        oldestBlock: feeHistory.oldestBlock,
        baseFeePerGas: feeHistory.baseFeePerGas,
        gasUsedRatio: feeHistory.gasUsedRatio,
        reward: feeHistory.reward
      },
      scenarios: feeScenarios
    },
    bundler,
    bundlerRequirements: [
      "Ethereum Sepolia chain ID 11155111",
      "ERC-4337 v0.7 canonical EntryPoint support",
      "counterfactual factory deployment",
      "eth_estimateUserOperationGas",
      "eth_sendUserOperation only after separate future authorization",
      "UserOperation lookup and receipt lookup",
      "no mandatory paymaster",
      "no mutation of signed fields",
      "transparent request-size, fee, and rate limits"
    ],
    prefund: {
      formula: currentPrefund.formula,
      gasLimits,
      empiricalActualExecutionCostAtObservedGasPrice: amount(observedExecutionCost),
      estimatedMinimumAtCurrentSuggestedMaxFee: amount(
        currentPrefund.requiredPrefundWei
      ),
      recommendedDisposableTestPrefund: amount(
        recommendedPrefund.requiredPrefundWei
      ),
      proposedMaximumFundingApproval: amount(
        recommendedPrefund.requiredPrefundWei
      ),
      absoluteRejectionCeilingExposure: amount(
        hardCeiling.requiredPrefundWei
      ),
      currentCalculation: currentPrefund,
      recommendedCalculation: recommendedPrefund,
      hardCeilingCalculation: hardCeiling,
      recommendationUsesHardCeiling: false,
      extraFundingForFailedOffchainBundlerAttemptWei: "0"
    },
    fundingMechanism: {
      selected: "direct_eth_transfer_to_counterfactual_address",
      entryPointDepositRequired: false,
      worksBeforeDeployment:
        "ETH balance at the deterministic address survives CREATE2 deployment and BaseAccount pays missingAccountFunds to EntryPoint during validation.",
      create2AddressAffectedByBalance: false,
      transactionHistoryIntroducedByFunding: true,
      residualFunds:
        "Residual ETH can fund later permitted UserOperations, but the account has no general withdrawal or transfer method and may strand unused ETH.",
      neverDeployed:
        "ETH remains at the counterfactual address without an available private key; practical recovery requires exact account deployment and remains restricted by account code.",
      entryPointDepositWithdrawal:
        "EntryPoint withdrawTo requires the account itself as caller, and the current account exposes no withdrawal path.",
      account2Role: "single_future_direct_prefund_proposal_only"
    },
    fundingProposal: {
      artifact: "config/ethereum-sepolia/O25_ACCOUNT_PREFUND_PROPOSAL.json",
      proposalDigest: fundingProposal.proposalDigest,
      approved: false,
      signed: false,
      broadcast: false
    },
    limits: {
      verificationGasLimitMaximum: "1500000",
      callGasLimitMaximum: "300000",
      preVerificationGasMaximum: "200000",
      maxFeePerGasWeiMaximum: "100000000000",
      maxPriorityFeePerGasWeiMaximum: "5000000000",
      authorizationLifetimeSecondsMaximum: "600"
    },
    stopBoundary: {
      ethTransferred: false,
      entryPointDepositCreated: false,
      accountDeployed: false,
      factoryMutationCalled: false,
      starkProofGenerated: false,
      runtimeAuthorizationGenerated: false,
      deviceVaultUsed: false,
      userOperationSigned: false,
      userOperationSubmitted: false,
      bundlerSubmissionCalled: false,
      paymasterUsed: false,
      publicMutationOccurred: false
    },
    warnings: bundler.configured ? [] : ["BUNDLER_NOT_CONFIGURED"],
    remainingApprovals: [
      "approve one compatible Sepolia ERC-4337 v0.7 bundler",
      "refresh all chain, fee, nonce, balance, deposit, and bundler estimates",
      "approve the exact Account 2 direct-funding transaction",
      "after funding, separately generate a fresh proof and Runtime authorization",
      "separately approve Device Vault signing",
      "separately approve exact UserOperation submission"
    ]
  };
  ensureNoSecrets(readiness);
  ensureNoSecrets(fundingProposal);
  ensureNoSecrets(estimationOnlyUserOperation);
  writeJson(O25_USER_OPERATION_PATH, estimationOnlyUserOperation);
  writeJson(O25_PREFUND_PATH, fundingProposal);
  writeJson(O25_READINESS_PATH, readiness);
  process.stdout.write(`${JSON.stringify({
    status: readiness.status,
    latestBlockNumber: readiness.network.latestBlockNumber,
    account: EXPECTED_ACCOUNT,
    bundlerStatus: bundler.status,
    recommendedPrefundWei: recommendedPrefund.requiredPrefundWei,
    fundingProposalSigned: false,
    fundingProposalBroadcast: false,
    publicMutationOccurred: false,
    files: [
      O25_READINESS_PATH.replace(`${ROOT}/`, ""),
      O25_PREFUND_PATH.replace(`${ROOT}/`, ""),
      O25_USER_OPERATION_PATH.replace(`${ROOT}/`, "")
    ]
  }, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
