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

function assertOriginalPlan(plan) {
  const { planDigest, ...body } = plan;
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  if (plan?.format !== "philcore-controlled-sepolia-beta-p1-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P1"
    || plan.status !== "EXACT_P1_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.publicMutationCount !== common.P1_MUTATION_COUNT
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || common.canonicalSha256(digestBody).toLowerCase() !== String(planDigest).toLowerCase()
    || plan.approval?.requiredPhrase !== common.approvalPhrase("P1", planDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_ORIGINAL_PLAN_INVALID");
  }
}

function assertStoppedReceipt(receipt, plan) {
  if (receipt?.format !== "philcore-controlled-sepolia-beta-p1-receipt-v1"
    || receipt.version !== 1 || receipt.stageId !== "P1"
    || receipt.status !== "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION"
    || receipt.planDigest?.toLowerCase() !== plan.planDigest.toLowerCase()
    || receipt.publicMutationOccurred !== true || receipt.automaticRetryOccurred !== false
    || receipt.failureCode !== "INSUFFICIENT_FUNDS"
    || !Array.isArray(receipt.mutations) || receipt.mutations.length !== 2
    || receipt.mutations[0]?.order !== 1
    || receipt.mutations[0]?.kind !== "FUND_BETA_DEPLOYER_FROM_LEGACY_ALPHA_SOURCE"
    || receipt.mutations[0]?.status !== "confirmed_by_both_providers"
    || receipt.mutations[0]?.transactionHash?.toLowerCase() !== plan.funding.transactionHash.toLowerCase()
    || receipt.mutations[1]?.order !== 2
    || receipt.mutations[1]?.kind !== "DEPLOY_PhilSepoliaMintPassConsumerV1"
    || receipt.mutations[1]?.status !== "submission_requested"
    || receipt.mutations[1]?.transactionHash?.toLowerCase() !== plan.deployments[0].transactionHash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_STOPPED_RECEIPT_INVALID");
  }
}

async function main() {
  const source = common.sourceIdentity();
  const runnerReview = {
    reviewedCommit: common.required("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_RUNNER_REVIEW_COMMIT"),
    reviewedTree: common.required("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_RUNNER_REVIEW_TREE"),
    reportSha256: common.required("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_RUNNER_REVIEW_SHA256").toLowerCase(),
    disposition: common.required("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_RUNNER_REVIEW_DISPOSITION")
  };
  if (runnerReview.reviewedCommit !== source.commit || runnerReview.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(runnerReview.reportSha256)
    || runnerReview.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_RUNNER_REVIEW_INVALID");
  }

  const originalPlanPath = argument("--original-plan", common.DEFAULT_PLAN_PATH);
  const originalReceiptPath = argument("--original-receipt", common.DEFAULT_RECEIPT_PATH);
  const outputPath = argument("--output", common.DEFAULT_RECOVERY_PLAN_PATH);
  const originalPlan = common.readJson(originalPlanPath);
  const originalReceipt = common.readJson(originalReceiptPath);
  assertOriginalPlan(originalPlan);
  assertStoppedReceipt(originalReceipt, originalPlan);

  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  if (!sameAddress(metadata.addresses.deployer, originalPlan.deployer)
    || !sameAddress(originalPlan.fundingSource, common.LEGACY_ALPHA_FUNDING_SOURCE)
    || !sameAddress(originalPlan.funding.recipient, originalPlan.deployer)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_METADATA_INVALID");
  }

  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (new URL(primaryUrl).hostname.toLowerCase() === new URL(reconciliationUrl).hostname.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, { staticNetwork: true });
  const reconciliation = new ethers.JsonRpcProvider(reconciliationUrl, common.CHAIN_ID, { staticNetwork: true });
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, { staticNetwork: true });

  const chainId = await agreed("CHAIN_ID", primary.send("eth_chainId", []), reconciliation.send("eth_chainId", []), (value) => BigInt(value).toString());
  if (Number(BigInt(chainId)) !== common.CHAIN_ID) common.fail("PHILCORE_CONTROLLED_BETA_WRONG_CHAIN");
  const entryPointCode = await agreed("ENTRYPOINT_CODE", primary.getCode(common.ENTRY_POINT), reconciliation.getCode(common.ENTRY_POINT), (value) => value.toLowerCase());
  if (entryPointCode === "0x") common.fail("PHILCORE_CONTROLLED_BETA_ENTRYPOINT_MISSING");
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported) || !supported.some((value) => value.toLowerCase() === common.ENTRY_POINT.toLowerCase())) {
    common.fail("PHILCORE_CONTROLLED_BETA_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }

  const [fundingReceiptPrimary, fundingReceiptReconciliation] = await Promise.all([
    primary.getTransactionReceipt(originalPlan.funding.transactionHash),
    reconciliation.getTransactionReceipt(originalPlan.funding.transactionHash)
  ]);
  if (!fundingReceiptPrimary || !fundingReceiptReconciliation
    || fundingReceiptPrimary.status !== 1 || fundingReceiptReconciliation.status !== 1
    || fundingReceiptPrimary.blockHash.toLowerCase() !== fundingReceiptReconciliation.blockHash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_FUNDING_RECEIPT_INVALID");
  }
  const failedHash = originalPlan.deployments[0].transactionHash;
  const failedSubmission = await Promise.all([
    primary.getTransaction(failedHash), primary.getTransactionReceipt(failedHash),
    reconciliation.getTransaction(failedHash), reconciliation.getTransactionReceipt(failedHash)
  ]);
  if (failedSubmission.some(Boolean)) common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_PRIOR_DEPLOYMENT_FOUND");

  const deployerNonce = await agreed("DEPLOYER_NONCE", primary.getTransactionCount(originalPlan.deployer, "pending"), reconciliation.getTransactionCount(originalPlan.deployer, "pending"), String);
  const fundingNonce = await agreed("FUNDING_NONCE", primary.getTransactionCount(originalPlan.fundingSource, "pending"), reconciliation.getTransactionCount(originalPlan.fundingSource, "pending"), String);
  const deployerBalance = await agreed("DEPLOYER_BALANCE", primary.getBalance(originalPlan.deployer), reconciliation.getBalance(originalPlan.deployer), String);
  if (Number(deployerNonce) !== Number(originalPlan.startingNonces.deployer)
    || Number(fundingNonce) !== Number(originalPlan.startingNonces.fundingSource) + 1) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_NONCE_INVALID");
  }

  const compiled = common.artifacts();
  const compiler = common.compilerIdentity();
  const graph = common.deploymentGraph({
    compiled,
    deployer: originalPlan.deployer,
    startingNonce: deployerNonce,
    executionOwner: metadata.addresses.initialExecutionValidator,
    recoveryAuthority: metadata.addresses.initialRecoveryAuthority,
    ownerCommitment: metadata.ownerCommitment,
    accountSalt: metadata.accountSalt
  });
  if (common.canonicalJson(graph) !== common.canonicalJson(originalPlan.contracts)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_GRAPH_CHANGED");
  }
  for (const address of Object.values(graph)) {
    const code = await agreed("PREDICTED_CODE", primary.getCode(address), reconciliation.getCode(address), (value) => value.toLowerCase());
    if (code !== "0x") common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_PREDICTED_ADDRESS_OCCUPIED");
  }

  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas) common.fail("PHILCORE_CONTROLLED_BETA_FEE_DATA_UNAVAILABLE");
  const maxFeePerGas = feeData.maxFeePerGas * 5n / 4n;
  const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas * 5n / 4n;
  if (maxFeePerGas > ethers.parseUnits("100", "gwei") || maxPriorityFeePerGas > maxFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_FEE_CAP_UNSAFE");
  }
  const deployments = await common.deploymentDescriptors({
    compiled,
    graph,
    deployer: originalPlan.deployer,
    startingNonce: deployerNonce,
    provider: primary,
    recoveryAuthority: metadata.addresses.initialRecoveryAuthority
  });
  const maximumRecoveryCostWei = deployments.reduce(
    (total, deployment) => total + BigInt(deployment.gasLimit) * maxFeePerGas,
    0n
  );
  if (deployerBalance < maximumRecoveryCostWei
    || maximumRecoveryCostWei > BigInt(originalPlan.maximumOperatorExposureWei)
    || BigInt(originalPlan.maximumOperatorExposureWei) !== ethers.parseEther("0.05")) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_BALANCE_INVALID");
  }

  const body = {
    format: "philcore-controlled-sepolia-beta-p1-recovery-plan-v1",
    version: 1,
    stageId: "P1R",
    status: "EXACT_P1_RECOVERY_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
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
    endpointBindings: {
      primaryRpcUrlSha256: common.endpointDigest(primaryUrl),
      reconciliationRpcUrlSha256: common.endpointDigest(reconciliationUrl),
      bundlerUrlSha256: common.endpointDigest(bundlerUrl)
    },
    originalP1: {
      planDigest: originalPlan.planDigest,
      receiptSha256: common.canonicalSha256(originalReceipt),
      fundingTransactionHash: originalPlan.funding.transactionHash,
      fundingBlockHash: fundingReceiptPrimary.blockHash,
      rejectedDeploymentTransactionHash: failedHash
    },
    fundingSource: originalPlan.fundingSource,
    deployer: originalPlan.deployer,
    startingNonces: { fundingSource: String(fundingNonce), deployer: String(deployerNonce) },
    deployerBalanceAtPlan: deployerBalance.toString(),
    feePolicy: { maxFeePerGas: maxFeePerGas.toString(), maxPriorityFeePerGas: maxPriorityFeePerGas.toString() },
    authorities: originalPlan.authorities,
    account: originalPlan.account,
    contracts: graph,
    deployments,
    maximumRecoveryCostWei: maximumRecoveryCostWei.toString(),
    maximumOperatorExposureWei: originalPlan.maximumOperatorExposureWei,
    mutations: [],
    publicMutationCount: common.P1_RECOVERY_MUTATION_COUNT,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    approval: { requiredPhrase: null, approved: false }
  };
  const deployerWallet = common.walletFromKeychain(metadata.keychainServices.deployer, originalPlan.deployer);
  const signed = await common.signedDeploymentTransactions(body, deployerWallet);
  body.mutations = signed.map((transaction, index) => {
    deployments[index].transactionHash = transaction.hash;
    return {
      order: index + 1,
      kind: transaction.label,
      transactionHash: transaction.hash,
      target: deployments[index].expectedContractAddress,
      valueWei: "0"
    };
  });
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  const planDigest = common.canonicalSha256(digestBody);
  body.approval.requiredPhrase = common.approvalPhrase("P1R", planDigest);
  const plan = { ...body, planDigest };
  common.atomicWriteJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    mutationCount: plan.publicMutationCount,
    maximumRecoveryCostWei: plan.maximumRecoveryCostWei,
    outputPath,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || "PHILCORE_CONTROLLED_BETA_P1_RECOVERY_PLAN_FAILED"}\n`);
  process.exitCode = 1;
});
