"use strict";

const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p1-common.cjs");

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function sameAddress(left, right) {
  return ethers.getAddress(left).toLowerCase() === ethers.getAddress(right).toLowerCase();
}

async function agreed(label, leftPromise, rightPromise, normalize = String) {
  const [left, right] = await Promise.all([leftPromise, rightPromise]);
  if (normalize(left) !== normalize(right)) common.fail(`PHILCORE_CONTROLLED_BETA_PROVIDER_DISAGREEMENT_${label}`);
  return left;
}

async function main() {
  const source = common.sourceIdentity();
  const runnerReview = {
    reviewedCommit: common.required("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_COMMIT"),
    reviewedTree: common.required("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_TREE"),
    reportSha256: common.required("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_SHA256").toLowerCase(),
    disposition: common.required("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_DISPOSITION")
  };
  if (runnerReview.reviewedCommit !== source.commit || runnerReview.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(runnerReview.reportSha256)
    || runnerReview.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_INVALID");
  }
  const outputPath = argument("--output", common.DEFAULT_PLAN_PATH);
  const metadataPath = common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH");
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  const fundingAddress = ethers.getAddress(common.required("PHILCORE_CONTROLLED_BETA_FUNDING_SOURCE_ADDRESS"));
  const fundingService = common.required("PHILCORE_CONTROLLED_BETA_FUNDING_KEYCHAIN_SERVICE");
  const metadata = common.normalizePublicMetadata(common.readJson(metadataPath));
  const deployer = metadata.addresses.deployer;
  const deployerService = metadata.keychainServices.deployer;
  if (!deployerService || !sameAddress(fundingAddress, common.LEGACY_ALPHA_FUNDING_SOURCE)
    || sameAddress(fundingAddress, deployer)
    || Object.values(metadata.addresses).some((address) => sameAddress(address, fundingAddress))) {
    common.fail("PHILCORE_CONTROLLED_BETA_FUNDING_AUTHORITY_SEPARATION_INVALID");
  }

  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, { staticNetwork: true });
  const reconciliation = new ethers.JsonRpcProvider(reconciliationUrl, common.CHAIN_ID, { staticNetwork: true });
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, { staticNetwork: true });
  const chainId = await agreed(
    "CHAIN_ID",
    primary.send("eth_chainId", []),
    reconciliation.send("eth_chainId", []),
    (value) => BigInt(value).toString()
  );
  if (Number(BigInt(chainId)) !== common.CHAIN_ID) common.fail("PHILCORE_CONTROLLED_BETA_WRONG_CHAIN");

  const entryPointCode = await agreed(
    "ENTRYPOINT_CODE",
    primary.getCode(common.ENTRY_POINT),
    reconciliation.getCode(common.ENTRY_POINT),
    (value) => value.toLowerCase()
  );
  if (entryPointCode === "0x") common.fail("PHILCORE_CONTROLLED_BETA_ENTRYPOINT_MISSING");
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported)
    || !supported.some((value) => value.toLowerCase() === common.ENTRY_POINT.toLowerCase())) {
    common.fail("PHILCORE_CONTROLLED_BETA_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }

  const deployerNonce = await agreed(
    "DEPLOYER_NONCE",
    primary.getTransactionCount(deployer, "pending"),
    reconciliation.getTransactionCount(deployer, "pending"),
    String
  );
  const fundingNonce = await agreed(
    "FUNDING_NONCE",
    primary.getTransactionCount(fundingAddress, "pending"),
    reconciliation.getTransactionCount(fundingAddress, "pending"),
    String
  );
  const deployerBalance = await agreed(
    "DEPLOYER_BALANCE",
    primary.getBalance(deployer),
    reconciliation.getBalance(deployer),
    String
  );
  const fundingBalance = await agreed(
    "FUNDING_BALANCE",
    primary.getBalance(fundingAddress),
    reconciliation.getBalance(fundingAddress),
    String
  );

  const compiled = common.artifacts();
  const compiler = common.compilerIdentity();
  const graph = common.deploymentGraph({
    compiled,
    deployer,
    startingNonce: deployerNonce,
    executionOwner: metadata.addresses.initialExecutionValidator,
    recoveryAuthority: metadata.addresses.initialRecoveryAuthority,
    ownerCommitment: metadata.ownerCommitment,
    accountSalt: metadata.accountSalt
  });
  const expectedPredictions = {
    PhilSepoliaMintPassConsumerV1: graph.consumer,
    PhilSepoliaLocalComposedActionGateV1: graph.gate,
    PhilCore4337AccountFactory: graph.factory
  };
  for (const [label, address] of Object.entries(expectedPredictions)) {
    if (!sameAddress(metadata.recordedPredictions[label], address)) {
      common.fail("PHILCORE_CONTROLLED_BETA_RECORDED_PREDICTION_CHANGED");
    }
  }
  if (!sameAddress(metadata.recordedAccount.predictedAddress, graph.account)) {
    common.fail("PHILCORE_CONTROLLED_BETA_RECORDED_ACCOUNT_CHANGED");
  }
  for (const address of Object.values(graph)) {
    const code = await agreed(
      "PREDICTED_CODE",
      primary.getCode(address),
      reconciliation.getCode(address),
      (value) => value.toLowerCase()
    );
    if (code !== "0x") common.fail("PHILCORE_CONTROLLED_BETA_PREDICTED_ADDRESS_OCCUPIED");
  }

  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_FEE_DATA_UNAVAILABLE");
  }
  const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas * 5n / 4n;
  const maxFeePerGas = feeData.maxFeePerGas * 5n / 4n;
  if (maxFeePerGas > ethers.parseUnits("100", "gwei") || maxPriorityFeePerGas > maxFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_FEE_CAP_UNSAFE");
  }
  const deployments = await common.deploymentDescriptors({
    compiled,
    graph,
    deployer,
    startingNonce: deployerNonce,
    provider: primary,
    recoveryAuthority: metadata.addresses.initialRecoveryAuthority
  });
  const deploymentMaximumFeeWei = deployments.reduce(
    (total, deployment) => total + BigInt(deployment.gasLimit) * maxFeePerGas,
    0n
  );
  const fundingGasEstimate = await primary.estimateGas({
    from: fundingAddress,
    to: deployer,
    nonce: fundingNonce,
    value: deploymentMaximumFeeWei
  });
  const fundingGasLimit = fundingGasEstimate * 125n / 100n;
  const maximumStageCostWei = deploymentMaximumFeeWei + fundingGasLimit * maxFeePerGas;
  const maximumExposureWei = ethers.parseEther("0.05");
  if (maximumStageCostWei > maximumExposureWei
    || fundingBalance < maximumStageCostWei
    || deployerBalance !== 0n) {
    common.fail("PHILCORE_CONTROLLED_BETA_FUNDING_LIMIT_INVALID");
  }

  const endpointBindings = {
    primaryRpcUrlSha256: common.endpointDigest(primaryUrl),
    reconciliationRpcUrlSha256: common.endpointDigest(reconciliationUrl),
    bundlerUrlSha256: common.endpointDigest(bundlerUrl)
  };
  const body = {
    format: "philcore-controlled-sepolia-beta-p1-plan-v1",
    version: 1,
    stageId: "P1",
    status: "EXACT_P1_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt: new Date().toISOString(),
    source,
    runnerReview,
    compiler,
    chainId: String(common.CHAIN_ID),
    entryPoint: common.ENTRY_POINT,
    entryPointCodeHash: ethers.keccak256(entryPointCode),
    endpoints: {
      primary: common.sanitizedEndpoint(primaryUrl),
      reconciliation: common.sanitizedEndpoint(reconciliationUrl),
      bundler: common.sanitizedEndpoint(bundlerUrl)
    },
    endpointBindings,
    fundingSource: fundingAddress,
    deployer,
    startingNonces: { fundingSource: String(fundingNonce), deployer: String(deployerNonce) },
    feePolicy: {
      maxFeePerGas: maxFeePerGas.toString(),
      maxPriorityFeePerGas: maxPriorityFeePerGas.toString()
    },
    authorities: {
      initialExecutionValidator: metadata.addresses.initialExecutionValidator,
      initialRecoveryAuthority: metadata.addresses.initialRecoveryAuthority,
      replacementExecutionValidator: metadata.addresses.replacementExecutionValidator,
      replacementRecoveryAuthority: metadata.addresses.replacementRecoveryAuthority
    },
    account: {
      predictedAddress: graph.account,
      ownerCommitment: metadata.ownerCommitment,
      salt: metadata.accountSalt,
      creationCodeHash: ethers.keccak256(compiled.account.bytecode)
    },
    contracts: graph,
    deployments,
    funding: {
      nonce: String(fundingNonce),
      recipient: deployer,
      valueWei: deploymentMaximumFeeWei.toString(),
      gasEstimate: fundingGasEstimate.toString(),
      gasLimit: fundingGasLimit.toString(),
      transactionHash: null
    },
    maximumStageCostWei: maximumStageCostWei.toString(),
    maximumOperatorExposureWei: maximumExposureWei.toString(),
    mutations: [],
    publicMutationCount: common.P1_MUTATION_COUNT,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    approval: { requiredPhrase: null, approved: false }
  };

  const fundingWallet = common.walletFromKeychain(fundingService, fundingAddress);
  const deployerWallet = common.walletFromKeychain(deployerService, deployer);
  const unsignedPlan = { ...body };
  const signed = await common.signedP1Transactions(unsignedPlan, fundingWallet, deployerWallet);
  body.funding.transactionHash = signed[0].hash;
  for (let index = 0; index < deployments.length; index += 1) deployments[index].transactionHash = signed[index + 1].hash;
  body.mutations = signed.map((transaction, index) => ({
    order: index + 1,
    kind: transaction.label,
    transactionHash: transaction.hash,
    target: index === 0 ? deployer : deployments[index - 1].expectedContractAddress,
    valueWei: index === 0 ? body.funding.valueWei : "0"
  }));
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  const planDigest = common.canonicalSha256(digestBody);
  body.approval.requiredPhrase = common.approvalPhrase("P1", planDigest);
  const plan = { ...body, planDigest };
  common.atomicWriteJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    mutationCount: plan.publicMutationCount,
    maximumStageCostWei: plan.maximumStageCostWei,
    outputPath,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || "PHILCORE_CONTROLLED_BETA_P1_PLAN_FAILED"}\n`);
  process.exitCode = 1;
});
