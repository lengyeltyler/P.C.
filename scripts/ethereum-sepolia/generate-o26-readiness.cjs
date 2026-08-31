require("tsx/cjs");

const { execFileSync, spawnSync } = require("node:child_process");
const {
  Contract,
  JsonRpcProvider,
  getAddress,
  keccak256
} = require("ethers");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");
const FACTORY_ARTIFACT = require(
  "../../artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json"
);

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  createRestrictedSepoliaBundlerClient
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const { loadSepoliaLocalEnvironment } = require("./local-environment.cjs");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  ROOT,
  ensureNoSecrets,
  verifyConfiguredKeyPairs
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  calculateO24Addresses,
  expectedFactoryRuntimeBinding
} = require("./o24-factory-common.cjs");
const {
  amount,
  calculateFeeScenarios,
  writeJson
} = require("./o25-readiness-common.cjs");
const {
  BUNDLER_PROVIDER_COMPARISON,
  O26_COMPATIBILITY_PATH,
  O26_ESTIMATE_PATH,
  O26_PREFUND_PATH,
  buildO26EstimationOnlyUserOperation,
  calculatePrefundEvidence,
  hashEndpointBinding,
  reconcileGasEstimates,
  validateBundlerCapabilities,
  validateBundlerEstimateResponse
} = require("./o26-bundler-readiness-common.cjs");

const EXPECTED_TARGET_RUNTIME_HASH =
  "0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad";
const EXPECTED_ENTRYPOINT_RUNTIME_HASH =
  "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";
const EVIDENCE_FRESHNESS_SECONDS = 15 * 60;

function assertEqual(actual, expected, error) {
  if (actual !== expected) throw new Error(error);
}

function runLocalSimulation() {
  const result = spawnSync(
    process.execPath,
    ["scripts/ethereum-sepolia/estimate-o25-local-entrypoint.cjs"],
    { cwd: ROOT, encoding: "utf8", env: { ...process.env } }
  );
  if (result.status !== 0) {
    throw new Error(`o26_local_entrypoint_simulation_failed:${result.stderr.trim()}`);
  }
  const output = JSON.parse(result.stdout);
  if (
    output.publicNetworkContacted !== false
    || output.realUserSignatureGenerated !== false
    || output.allFailureChecksPassed !== true
  ) {
    throw new Error("o26_local_entrypoint_simulation_invalid");
  }
  return output;
}

function classifyLookupResult(error) {
  const message = error instanceof Error ? error.message : String(error);
  return /method not found|-32601/i.test(message)
    ? "unsupported"
    : "supported_with_sanitized_error";
}

async function inspectConfiguredBundler(userOperation, endpoint) {
  const client = createRestrictedSepoliaBundlerClient({ url: endpoint });
  const chainResult = await client.request("eth_chainId", []);
  const chainId = Number(BigInt(String(chainResult)));
  const supportedEntryPointsRaw = await client.request("eth_supportedEntryPoints", []);
  const supportedEntryPoints = Array.isArray(supportedEntryPointsRaw)
    ? supportedEntryPointsRaw.map((value) => getAddress(String(value)))
    : [];
  const supportedMethods = [
    "eth_supportedEntryPoints",
    "eth_estimateUserOperationGas"
  ];
  const zeroHash = `0x${"00".repeat(32)}`;
  const methodChecks = {};
  for (const method of [
    "eth_getUserOperationByHash",
    "eth_getUserOperationReceipt"
  ]) {
    try {
      await client.request(method, [zeroHash]);
      methodChecks[method] = "supported";
      supportedMethods.push(method);
    } catch (error) {
      methodChecks[method] = classifyLookupResult(error);
      if (methodChecks[method] !== "unsupported") supportedMethods.push(method);
    }
  }
  validateBundlerCapabilities({
    chainId,
    supportedEntryPoints,
    supportedMethods,
    paymasterRequired: false
  });

  let estimationResponse;
  try {
    estimationResponse = await client.request("eth_estimateUserOperationGas", [
      userOperation.rpcV07Representation,
      ERC4337_V07_CANONICAL_ENTRYPOINT
    ]);
  } catch (error) {
    const classification = classifyLookupResult(error);
    if (/signature|AA24|AA23/i.test(error instanceof Error ? error.message : "")) {
      throw new Error("BUNDLER_REQUIRES_REAL_SIGNATURE_FOR_ESTIMATION");
    }
    throw new Error(`BUNDLER_ESTIMATION_FAILED:${classification}`);
  }
  validateBundlerEstimateResponse(estimationResponse);
  return Object.freeze({
    status: "BUNDLER_COMPATIBILITY_VALIDATED",
    configured: true,
    contacted: true,
    endpoint: hashEndpointBinding(endpoint),
    chainId,
    supportedEntryPoints,
    supportedMethods,
    methodChecks,
    paymasterRequired: false,
    estimationResponse,
    estimationPerformed: true,
    submissionMethodExposed: false,
    submissionMethodCalled: false
  });
}

async function main() {
  const localEnvironment = loadSepoliaLocalEnvironment({
    includeO23rSensitiveSelectors: true
  });
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  const bundlerEndpoint = String(process.env.PHILCORE_SEPOLIA_BUNDLER_URL ?? "").trim();
  const endpointBinding = hashEndpointBinding(bundlerEndpoint);
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
    (Number(latestBlock.timestamp) + EVIDENCE_FRESHNESS_SECONDS) * 1000
  ).toISOString();

  const [
    feeData,
    targetCode,
    factoryCode,
    entryPointCode,
    accountCode,
    accountBalance,
    accountDeposit,
    entryPointNonce,
    accountLatestNonce,
    accountPendingNonce,
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
    provider.getCode(EXPECTED_TARGET),
    provider.getCode(EXPECTED_FACTORY),
    provider.getCode(ERC4337_V07_CANONICAL_ENTRYPOINT),
    provider.getCode(EXPECTED_ACCOUNT),
    provider.getBalance(EXPECTED_ACCOUNT),
    entryPoint.balanceOf(EXPECTED_ACCOUNT),
    entryPoint.getNonce(EXPECTED_ACCOUNT, 0),
    provider.getTransactionCount(EXPECTED_ACCOUNT, "latest"),
    provider.getTransactionCount(EXPECTED_ACCOUNT, "pending"),
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
  assertEqual(getAddress(factoryTarget), EXPECTED_TARGET, "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH");
  assertEqual(Number(factoryChain), ETHEREUM_SEPOLIA_CHAIN_ID, "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH");
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
  if (
    feeData.gasPrice === null
    || feeData.maxFeePerGas === null
    || feeData.maxPriorityFeePerGas === null
  ) {
    throw new Error("sepolia_fee_data_unavailable");
  }

  const feeScenarios = calculateFeeScenarios({
    baseFeePerGasWei: latestBlock.baseFeePerGas.toString(),
    maxFeePerGasWei: feeData.maxFeePerGas.toString(),
    maxPriorityFeePerGasWei: feeData.maxPriorityFeePerGas.toString()
  });
  const userOperation = buildO26EstimationOnlyUserOperation({
    identity,
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    expiry: String(Number(latestBlock.timestamp) + 600),
    maxFeePerGas: feeScenarios.recommended.maxFeePerGas.wei,
    maxPriorityFeePerGas: feeScenarios.recommended.maxPriorityFeePerGas.wei
  });
  const localSimulation = runLocalSimulation();
  const bundler = endpointBinding.configured
    ? await inspectConfiguredBundler(userOperation, bundlerEndpoint)
    : Object.freeze({
      status: "BUNDLER_CONFIGURATION_REQUIRED",
      configured: false,
      contacted: false,
      endpoint: endpointBinding,
      chainId: null,
      supportedEntryPoints: [],
      supportedMethods: [],
      paymasterRequired: null,
      estimationResponse: null,
      estimationPerformed: false,
      submissionMethodExposed: false,
      submissionMethodCalled: false
    });
  const localComponents = {
    approximateFirstOperationCreationGasComponent:
      localSimulation.accountCreation.approximateFirstOperationCreationGasComponent,
    validationGasEstimate: localSimulation.operation.validationGasEstimate,
    executionGasEstimate: localSimulation.operation.executionGasEstimate,
    actualGasUsed: localSimulation.operation.userOperationActualGasUsed
  };
  const reconciliation = reconcileGasEstimates(
    localComponents,
    bundler.estimationResponse
  );
  const prefund = calculatePrefundEvidence({
    selectedGas: reconciliation.selected,
    currentMaxFeePerGasWei: feeScenarios.current.maxFeePerGas.wei,
    recommendedMaxFeePerGasWei: feeScenarios.recommended.maxFeePerGas.wei,
    localActualGasUsed: localSimulation.operation.userOperationActualGasUsed,
    observedGasPriceWei: feeData.gasPrice.toString()
  });
  const status = bundler.configured
    ? "BUNDLER_ESTIMATION_COMPLETE_UNSIGNED_UNFUNDED"
    : "BUNDLER_CONFIGURATION_REQUIRED";
  const sourceHead = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();
  const branch = execFileSync("git", ["branch", "--show-current"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();

  const compatibilityReport = {
    schemaVersion: "philcore-o26-bundler-compatibility-report-v1",
    phase: "O.26",
    status,
    generatedAt: new Date().toISOString(),
    sourceHead,
    branch,
    securityModel: "local-proof-gated-v1",
    configuredBundler: bundler,
    providerComparisonAsOf: "2026-07-27",
    providerComparison: BUNDLER_PROVIDER_COMPARISON,
    recommendation: {
      primary: "Pimlico",
      fallback: "Alchemy",
      automaticallySelected: false,
      rationale:
        "Pimlico documents a credential-free, rate-limited public endpoint, standard v0.7 methods, sender-balance override for estimates, and no mandatory paymaster.",
      exactNextConfiguration:
        "Set PHILCORE_SEPOLIA_BUNDLER_URL in ignored mode-0600 .env.sepolia.local to an explicitly approved Sepolia endpoint; preserve credentials outside version control.",
      nextSafeCommand: "npm run ethereum-sepolia:refresh-o26-readiness"
    },
    requiredChainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    requiredEntryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
    configuredProviderContacted: bundler.contacted,
    remoteEstimationPerformed: bundler.estimationPerformed,
    paymasterPermitted: false,
    providerMayMutateUserOperation: false,
    submissionApiExposed: false,
    submissionMethodCalled: false,
    publicMutationOccurred: false
  };

  const gasEstimate = {
    schemaVersion: "philcore-o26-first-userop-gas-estimate-v1",
    phase: "O.26",
    status,
    generatedAt: new Date().toISOString(),
    sourceHead,
    network: {
      name: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      blockNumber: String(latestBlock.number),
      blockHash: latestBlock.hash,
      observedAt,
      expiresAt
    },
    infrastructure: {
      target: { address: EXPECTED_TARGET, runtimeCodeHash: targetCodeHash, matched: true },
      factory: {
        address: EXPECTED_FACTORY,
        runtimeCodeHash: factoryCodeHash,
        entryPoint: getAddress(factoryEntryPoint),
        target: getAddress(factoryTarget),
        expectedChainId: Number(factoryChain),
        matched: true
      },
      entryPoint: {
        address: ERC4337_V07_CANONICAL_ENTRYPOINT,
        runtimeCodeHash: entryPointCodeHash,
        version: "0.7",
        matched: true
      }
    },
    counterfactualAccount: {
      address: EXPECTED_ACCOUNT,
      localDerivation: localAddress.account,
      factoryGetAddress: getAddress(factoryAddress),
      code: "0x",
      balance: amount(accountBalance),
      deposit: amount(accountDeposit),
      entryPointNonce: entryPointNonce.toString(),
      latestNonce: String(accountLatestNonce),
      pendingNonce: String(accountPendingNonce),
      unchanged: true
    },
    accounts: {
      account1: {
        address: EXPECTED_DEPLOYER,
        latestNonce: String(account1LatestNonce),
        pendingNonce: String(account1PendingNonce),
        balance: amount(account1Balance),
        signingUsed: false
      },
      account2: {
        address: EXPECTED_FUNDING,
        latestNonce: String(account2LatestNonce),
        pendingNonce: String(account2PendingNonce),
        balance: amount(account2Balance),
        signingUsed: false
      }
    },
    estimationOnlyUserOperation: userOperation,
    localSimulation,
    bundlerEstimate: {
      configured: bundler.configured,
      performed: bundler.estimationPerformed,
      response: bundler.estimationResponse,
      exactRemoteGasAvailable: bundler.estimationResponse !== null,
      warning: bundler.configured
        ? null
        : "No exact remote bundler estimate exists until an endpoint is explicitly configured."
    },
    localComponents,
    reconciliation,
    authority: {
      proofGenerated: false,
      runtimeAuthorizationGenerated: false,
      approvalGenerated: false,
      freshPresenceRecorded: false,
      deviceVaultUsed: false,
      signatureGenerated: false,
      accountFunded: false,
      userOperationSubmitted: false,
      publicMutationOccurred: false
    }
  };

  const prefundProposal = {
    schemaVersion: "philcore-o26-refreshed-prefund-proposal-v1",
    phase: "O.26",
    status: bundler.configured
      ? "PROPOSED_PENDING_SEPARATE_FUNDING_APPROVAL"
      : "BLOCKED_PENDING_BUNDLER_CONFIGURATION",
    approved: false,
    signed: false,
    broadcast: false,
    generatedAt: new Date().toISOString(),
    sourceHead,
    network: {
      name: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      blockNumber: String(latestBlock.number),
      blockHash: latestBlock.hash,
      observedAt,
      expiresAt
    },
    feeEvidence: {
      baseFeePerGas: amount(latestBlock.baseFeePerGas),
      gasPrice: amount(feeData.gasPrice),
      rpcSuggestedMaxFeePerGas: amount(feeData.maxFeePerGas),
      rpcSuggestedMaxPriorityFeePerGas: amount(feeData.maxPriorityFeePerGas),
      scenarios: feeScenarios
    },
    selectedGas: reconciliation.selected,
    prefund: {
      formula: prefund.formula,
      estimatedMinimum: amount(prefund.estimatedMinimumPrefundWei),
      recommendedDisposableTestPrefund: amount(
        prefund.recommendedDisposableTestPrefundWei
      ),
      proposedMaximumFundingApproval: amount(
        prefund.proposedMaximumFundingApprovalWei
      ),
      absoluteRejectionCeilingExposure: amount(
        prefund.absoluteRejectionCeilingExposureWei
      ),
      expectedActualCostAtObservedGasPrice: amount(
        prefund.expectedActualCostAtObservedGasPriceWei
      ),
      expectedResidualAfterSuccess: amount(
        prefund.expectedResidualAfterSuccessWei
      )
    },
    fundingMechanism: {
      proposed: "direct_eth_transfer_to_counterfactual_address",
      performed: false,
      sender: EXPECTED_FUNDING,
      recipient: EXPECTED_ACCOUNT,
      residualRiskClassification: prefund.residualRiskClassification,
      residualCanFundFuturePermittedUserOperations: true,
      generalWithdrawalAvailable: false,
      entryPointDepositWithdrawalAvailableThroughAccount: false,
      failedOffchainSimulationConsumesPrefund: false,
      validationTransactionRevertLeavesTransferBalanceUnchanged: true,
      includedExecutionFailureMayConsumeActualGas: true,
      undeployedAddressBalanceRecoverableWithoutExactDeployment: false,
      recommendation:
        "Use only disposable Sepolia ETH after remote bundler estimation and separate approval. Add a reviewed restricted recovery/withdrawal capability before non-disposable use."
    },
    blockers: bundler.configured
      ? ["separate exact funding approval remains required"]
      : [
        "PHILCORE_SEPOLIA_BUNDLER_URL is not configured",
        "exact remote bundler gas estimation has not occurred",
        "funding approval is absent"
      ],
    account1Signed: false,
    account2Signed: false,
    ethTransferred: false,
    accountDeployed: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  };

  for (const artifact of [compatibilityReport, gasEstimate, prefundProposal]) {
    ensureNoSecrets(artifact);
  }
  writeJson(O26_COMPATIBILITY_PATH, compatibilityReport);
  writeJson(O26_ESTIMATE_PATH, gasEstimate);
  writeJson(O26_PREFUND_PATH, prefundProposal);
  process.stdout.write(`${JSON.stringify({
    status,
    latestBlockNumber: String(latestBlock.number),
    bundlerConfigured: bundler.configured,
    bundlerContacted: bundler.contacted,
    remoteEstimationPerformed: bundler.estimationPerformed,
    recommendedProvider: "Pimlico",
    fallbackProvider: "Alchemy",
    selectedDeclaredGas: reconciliation.selected,
    recommendedDisposablePrefundWei:
      prefund.recommendedDisposableTestPrefundWei,
    account1Signed: false,
    account2Signed: false,
    ethTransferred: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
