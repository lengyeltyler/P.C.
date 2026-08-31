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
  LOCAL_PROOF_GATED_PREPARATION_LIMITS
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
  PROPOSAL_FRESHNESS_SECONDS,
  amount,
  buildO26EstimationOnlyUserOperation,
  calculateFeeScenarios,
  canonicalDigest,
  writeJson
} = (() => {
  const o25 = require("./o25-readiness-common.cjs");
  const o26 = require("./o26-bundler-readiness-common.cjs");
  return { ...o25, ...o26 };
})();
const {
  O26_1_COMPATIBILITY_PATH,
  O26_1_ESTIMATE_PATH,
  O26_1_PREFUND_PATH,
  REQUIRED_BUNDLER_METHODS,
  buildO261FundingProposal,
  buildO261Prefund,
  classifyEstimationResult,
  createO261LogicalClients,
  reconcileO261Gas,
  requestDigest,
  sanitizeBundlerError
} = require("./o26-1-live-bundler-common.cjs");

const EXPECTED_TARGET_RUNTIME_HASH =
  "0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad";
const EXPECTED_ENTRYPOINT_RUNTIME_HASH =
  "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";
const MUTATION_APPROVALS = Object.freeze([
  "PHILCORE_ETHEREUM_SEPOLIA_APPROVED",
  "PHILCORE_ETHEREUM_SEPOLIA_DEPLOYMENT_APPROVED",
  "PHILCORE_SEPOLIA_TARGET_DEPLOYMENT_APPROVED",
  "PHILCORE_SEPOLIA_ACCOUNT_DEPLOYMENT_APPROVED",
  "PHILCORE_SEPOLIA_FUNDING_APPROVED",
  "PHILCORE_SEPOLIA_USEROP_SUBMISSION_APPROVED"
]);

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
    throw new Error(`o26_1_local_entrypoint_simulation_failed:${result.stderr.trim()}`);
  }
  const output = JSON.parse(result.stdout);
  if (
    output.publicNetworkContacted !== false
    || output.realUserSignatureGenerated !== false
    || output.allFailureChecksPassed !== true
    || output.rollbackAndFailureChecks.invalidPlaceholderSignature !== true
  ) {
    throw new Error("o26_1_local_entrypoint_simulation_invalid");
  }
  return output;
}

function classifyMethodError(sanitized) {
  if (/method not found/i.test(sanitized.message) || sanitized.code === -32601) {
    return "unsupported";
  }
  if (/auth|api key|unauthorized|forbidden/i.test(sanitized.message)) {
    return "authentication_gated";
  }
  return "supported";
}

async function inspectBundler(logicalClients, userOperation) {
  const observedAt = new Date().toISOString();
  const chainResult = await logicalClients.bundler.getChainId();
  const chainId = Number(BigInt(String(chainResult)));
  const entryPointResult = await logicalClients.bundler.getSupportedEntryPoints();
  const supportedEntryPoints = Array.isArray(entryPointResult)
    ? entryPointResult.map((value) => getAddress(String(value)))
    : [];
  if (!supportedEntryPoints.includes(getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT))) {
    throw new Error("BUNDLER_ENTRYPOINT_V07_UNSUPPORTED");
  }

  const zeroHash = `0x${"00".repeat(32)}`;
  const methodChecks = {
    eth_supportedEntryPoints: {
      status: "supported",
      resultClassification: "entrypoint_list_returned"
    },
    eth_estimateUserOperationGas: {
      status: "pending",
      resultClassification: "not_called_yet"
    }
  };
  for (const [method, invoke] of [
    [
      "eth_getUserOperationByHash",
      () => logicalClients.bundler.getUserOperationByHash(zeroHash)
    ],
    [
      "eth_getUserOperationReceipt",
      () => logicalClients.bundler.getUserOperationReceipt(zeroHash)
    ]
  ]) {
    try {
      const result = await invoke();
      methodChecks[method] = {
        status: "supported",
        resultClassification: result === null ? "null_for_nonexistent_hash" : "safe_response"
      };
    } catch (error) {
      const sanitized = sanitizeBundlerError(error);
      methodChecks[method] = {
        status: classifyMethodError(sanitized),
        resultClassification: "sanitized_json_rpc_error_for_nonexistent_hash",
        errorClassification: "expected_invalid_nonexistent_hash",
        error: sanitized
      };
    }
  }

  const exactRequestDigest = requestDigest(userOperation);
  const beforeDigest = canonicalDigest(userOperation.rpcV07Representation);
  let response = null;
  let error = null;
  try {
    response = await logicalClients.bundler.estimateUserOperationGas(
      userOperation.rpcV07Representation,
      ERC4337_V07_CANONICAL_ENTRYPOINT
    );
    methodChecks.eth_estimateUserOperationGas = {
      status: "supported",
      resultClassification: "gas_estimate_returned"
    };
  } catch (caught) {
    error = sanitizeBundlerError(caught);
    methodChecks.eth_estimateUserOperationGas = {
      status: classifyMethodError(error),
      resultClassification: "sanitized_estimation_error",
      error
    };
  }
  const afterDigest = canonicalDigest(userOperation.rpcV07Representation);
  if (beforeDigest !== afterDigest) throw new Error("BUNDLER_REQUEST_MUTATED");
  const status = classifyEstimationResult({ response, error, partialGas: false });
  if (status !== "BUNDLER_ESTIMATION_SUCCEEDED") {
    return {
      provider: "alchemy",
      authenticationPassed: true,
      chainId,
      observedAt,
      supportedEntryPoints,
      methodChecks,
      requestDigest: exactRequestDigest,
      requestObjectDigestBefore: beforeDigest,
      requestObjectDigestAfter: afterDigest,
      requestMutated: false,
      status,
      response: null,
      error,
      paymasterRequired: false,
      submissionMethodCalled: false
    };
  }
  return {
    provider: "alchemy",
    authenticationPassed: true,
    chainId,
    observedAt,
    supportedEntryPoints,
    methodChecks,
    requestDigest: exactRequestDigest,
    requestObjectDigestBefore: beforeDigest,
    requestObjectDigestAfter: afterDigest,
    requestMutated: false,
    status,
    response,
    responseDigest: canonicalDigest(response),
    responseRequestId: null,
    error: null,
    paymasterRequired: false,
    submissionMethodCalled: false
  };
}

async function main() {
  const localEnvironment = loadSepoliaLocalEnvironment({
    includeO23rSensitiveSelectors: true
  });
  const mutationApprovals = Object.fromEntries(
    MUTATION_APPROVALS.map((name) => [name, process.env[name] === "1"])
  );
  if (Object.values(mutationApprovals).some(Boolean)) {
    throw new Error("O26_1_MUTATION_APPROVAL_PRESENT");
  }
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  const logicalClients = createO261LogicalClients({
    rpcUrl: process.env.PHILCORE_SEPOLIA_RPC_URL,
    bundlerUrl: process.env.PHILCORE_SEPOLIA_BUNDLER_URL
  });
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

  const restrictedChainId = await logicalClients.chain.getChainId();
  assertEqual(
    Number(BigInt(String(restrictedChainId))),
    ETHEREUM_SEPOLIA_CHAIN_ID,
    "WRONG_ETHEREUM_CHAIN"
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
  assertEqual(entryPointCodeHash, EXPECTED_ENTRYPOINT_RUNTIME_HASH, "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH");
  assertEqual(getAddress(factoryEntryPoint), getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT), "DEPLOYED_INFRASTRUCTURE_BINDING_MISMATCH");
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
  const addresses = calculateO24Addresses(
    identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const factoryAddress = await factory[
    "getAddress(address,bytes32,bytes32,uint256)"
  ](
    identity.validatorAddress,
    identity.ownerCommitment,
    addresses.validatorKeyIdBinding,
    BigInt(process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT)
  );
  assertEqual(addresses.account, EXPECTED_ACCOUNT, "COUNTERFACTUAL_ACCOUNT_PREDICTION_CHANGED");
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
  const bundler = await inspectBundler(logicalClients, userOperation);
  if (bundler.status !== "BUNDLER_ESTIMATION_SUCCEEDED") {
    throw new Error(bundler.status);
  }

  const localGas = {
    approximateFirstOperationCreationGasComponent:
      localSimulation.accountCreation.approximateFirstOperationCreationGasComponent,
    validationGasEstimate: localSimulation.operation.validationGasEstimate,
    executionGasEstimate: localSimulation.operation.executionGasEstimate,
    declaredPreVerificationGas: localSimulation.operation.declaredPreVerificationGas,
    actualGasUsed: localSimulation.operation.userOperationActualGasUsed,
    handleOpsEstimate: localSimulation.operation.handleOpsTransactionEstimate
  };
  const reconciliation = reconcileO261Gas({
    local: localGas,
    remote: bundler.response
  });
  const prefund = buildO261Prefund({
    selectedGas: reconciliation.selected,
    currentMaxFeePerGasWei: feeScenarios.current.maxFeePerGas.wei,
    recommendedMaxFeePerGasWei: feeScenarios.recommended.maxFeePerGas.wei,
    hardMaxFeePerGasWei: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei,
    localActualGasUsed: localSimulation.operation.userOperationActualGasUsed,
    observedGasPriceWei: feeData.gasPrice.toString()
  });
  const infrastructureBinding = canonicalDigest({
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    target: EXPECTED_TARGET,
    targetCodeHash,
    factory: EXPECTED_FACTORY,
    factoryCodeHash,
    entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
    entryPointCodeHash,
    account: EXPECTED_ACCOUNT,
    blockNumber: String(latestBlock.number),
    blockHash: latestBlock.hash
  });
  const fundingProposal = buildO261FundingProposal({
    valueWei: prefund.recommendedDisposableTestPrefund.wei,
    maxFeePerGasWei: feeScenarios.recommended.maxFeePerGas.wei,
    maxPriorityFeePerGasWei: feeScenarios.recommended.maxPriorityFeePerGas.wei,
    nonce: String(account2PendingNonce),
    senderBalanceWei: account2Balance.toString(),
    smartAccountBalanceWei: accountBalance.toString(),
    latestBlockNumber: latestBlock.number,
    latestBlockHash: latestBlock.hash,
    observedAt,
    expiresAt,
    providerBinding: logicalClients.configuration.bundlerBindingSha256,
    gasEstimateBinding: bundler.responseDigest,
    infrastructureBinding
  });
  const sourceHead = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();
  const branch = execFileSync("git", ["branch", "--show-current"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();

  const compatibilityReport = {
    schemaVersion: "philcore-o26-1-live-bundler-compatibility-report-v1",
    phase: "O.26.1",
    status: "BUNDLER_ESTIMATION_SUCCEEDED",
    generatedAt: new Date().toISOString(),
    sourceHead,
    branch,
    securityModel: "local-proof-gated-v1",
    provider: {
      name: "alchemy",
      authenticationPassed: bundler.authenticationPassed,
      endpointClassification: logicalClients.configuration.endpointClassification,
      endpointBindingSha256: logicalClients.configuration.bundlerBindingSha256,
      sharedEndpoint: logicalClients.configuration.sharedEndpoint,
      sharedEndpointSupported: logicalClients.configuration.sharedEndpointSupported,
      logicalClientSeparationRequired: true,
      completeEndpointRecorded: false
    },
    clientIsolation: {
      distinctClientInstances: logicalClients.distinctClientInstances,
      chainAuditClassification: logicalClients.chain.auditClassification,
      bundlerAuditClassification: logicalClients.bundler.auditClassification,
      independentAllowlists: true,
      genericRequestExposed: logicalClients.genericRequestExposed,
      submissionMethodExposed: logicalClients.submissionMethodExposed,
      mutationMethodsExposed: false
    },
    network: {
      name: "ethereum_sepolia",
      chainId: bundler.chainId,
      chainRpcVerified: true,
      bundlerChainVerified: true
    },
    supportedEntryPoints: bundler.supportedEntryPoints,
    canonicalEntryPointV07Supported: true,
    requiredMethods: REQUIRED_BUNDLER_METHODS,
    methodChecks: bundler.methodChecks,
    paymasterRequired: false,
    estimationStatus: bundler.status,
    submissionMethodCalled: false,
    mutationApprovals,
    publicMutationOccurred: false
  };

  const estimateArtifact = {
    schemaVersion: "philcore-o26-1-remote-userop-gas-estimate-v1",
    phase: "O.26.1",
    status: "BUNDLER_ESTIMATION_SUCCEEDED",
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
      bindingDigest: infrastructureBinding,
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
    canonicalIdentity: {
      identityId: identity.identityId,
      ownerCommitment: identity.ownerCommitment,
      validatorAddress: identity.validatorAddress,
      validatorKeyIdBinding: addresses.validatorKeyIdBinding,
      preserved: true
    },
    counterfactualAccount: {
      address: EXPECTED_ACCOUNT,
      localDerivation: addresses.account,
      factoryGetAddress: getAddress(factoryAddress),
      code: accountCode,
      balance: amount(accountBalance),
      entryPointDeposit: amount(accountDeposit),
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
      },
      keyBindingsVerified: keyBindings.deployer.addressMatch && keyBindings.funding.addressMatch
    },
    estimationOnlyUserOperation: userOperation,
    estimationEnvelope: {
      lengthBytes: userOperation.placeholders.signatureLengthBytes,
      digest: keccak256(userOperation.rpcV07Representation.signature),
      decoderCorrect: true,
      cryptographicallyValid: false,
      submissionAuthority: false,
      localInvalidityVerified: localSimulation.rollbackAndFailureChecks.invalidPlaceholderSignature
    },
    request: {
      method: "eth_estimateUserOperationGas",
      digest: bundler.requestDigest,
      objectDigestBefore: bundler.requestObjectDigestBefore,
      objectDigestAfter: bundler.requestObjectDigestAfter,
      mutated: bundler.requestMutated,
      sentOnce: true,
      retryPerformed: false
    },
    response: {
      provider: "alchemy",
      receivedAt: bundler.observedAt,
      requestId: bundler.responseRequestId,
      digest: bundler.responseDigest,
      gas: bundler.response,
      paymasterFieldsReturned: false,
      error: null
    },
    localSimulation,
    localGas,
    reconciliation,
    authority: {
      accountFunded: false,
      realProofGenerated: false,
      realAuthorizationGenerated: false,
      realApprovalGenerated: false,
      freshPresenceRecorded: false,
      deviceVaultSignatureGenerated: false,
      userOperationSubmitted: false,
      publicMutationOccurred: false
    }
  };

  const prefundProposal = {
    schemaVersion: "philcore-o26-1-refreshed-prefund-proposal-v1",
    phase: "O.26.1",
    status: "FUNDING_READY_FOR_SEPARATE_APPROVAL",
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
    providerBinding: logicalClients.configuration.bundlerBindingSha256,
    gasEstimateBinding: bundler.responseDigest,
    infrastructureBinding,
    feeEvidence: {
      baseFeePerGas: amount(latestBlock.baseFeePerGas),
      gasPrice: amount(feeData.gasPrice),
      rpcSuggestedMaxFeePerGas: amount(feeData.maxFeePerGas),
      rpcSuggestedMaxPriorityFeePerGas: amount(feeData.maxPriorityFeePerGas),
      scenarios: feeScenarios
    },
    selectedGas: reconciliation.selected,
    prefund,
    residualFundClassification: prefund.residualFundClassification,
    fundingProposal,
    approved: false,
    signed: false,
    broadcast: false,
    account1Signed: false,
    account2Signed: false,
    ethTransferred: false,
    accountDeployed: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  };

  for (const artifact of [compatibilityReport, estimateArtifact, prefundProposal]) {
    ensureNoSecrets(artifact);
  }
  writeJson(O26_1_COMPATIBILITY_PATH, compatibilityReport);
  writeJson(O26_1_ESTIMATE_PATH, estimateArtifact);
  writeJson(O26_1_PREFUND_PATH, prefundProposal);
  process.stdout.write(`${JSON.stringify({
    status: "BUNDLER_ESTIMATION_SUCCEEDED",
    provider: "alchemy",
    sharedEndpointAccepted: logicalClients.configuration.sharedEndpointSupported,
    chainId: bundler.chainId,
    canonicalEntryPointV07Supported: true,
    bundlerGas: bundler.response,
    selectedGas: reconciliation.selected,
    recommendedDisposablePrefundWei: prefund.recommendedDisposableTestPrefund.wei,
    fundingReadiness: "FUNDING_READY_FOR_SEPARATE_APPROVAL",
    fundingApproved: false,
    fundingSigned: false,
    fundingBroadcast: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  const sanitized = sanitizeBundlerError(error);
  process.stderr.write(`${sanitized.message}\n`);
  process.exitCode = 1;
});
