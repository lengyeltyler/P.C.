"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function acceptedReview(source) {
  const prefix = "PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RUNNER_REVIEW";
  const review = {
    reviewedCommit: common.required(`${prefix}_COMMIT`),
    reviewedTree: common.required(`${prefix}_TREE`),
    reportSha256: common.required(`${prefix}_SHA256`).toLowerCase(),
    disposition: common.required(`${prefix}_DISPOSITION`)
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RUNNER_REVIEW_INVALID");
  }
  return review;
}

function assertIncidentEvidence(receipt, lock, config) {
  const errorData = receipt?.error?.rpcData;
  if (receipt?.format !== "philcore-controlled-sepolia-beta-p2-recovery-receipt-v1"
    || receipt.stageId !== "P2R"
    || receipt.status !== "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION"
    || receipt.planDigest !== lock?.planDigest
    || receipt.publicMutationOccurred !== true
    || receipt.automaticRetryOccurred !== false
    || receipt.mutations?.length !== 1
    || receipt.mutations[0]?.status !== "submission_requested"
    || receipt.mutations[0]?.userOperationHash
      !== "0x74e3ec0f673028e14c4c143562e4f5539957a6b518dae83b779707ad37f121ef"
    || receipt.error?.rpcCode !== -32502
    || receipt.error?.rpcMessage !== "entity stake/unstake delay too low"
    || !common.sameAddress(errorData?.needsStake?.factory, config.infrastructure.factory)
    || BigInt(errorData?.minimumStake || 0) !== ethers.parseEther("0.1")
    || BigInt(errorData?.minimumUnstakeDelay || 0) !== 86400n
    || lock?.format !== "philcore-controlled-sepolia-beta-p2-recovery-execution-attempt-lock-v1"
    || lock.stageId !== "P2R" || lock.automaticRetryAllowed !== false) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_INCIDENT_EVIDENCE_INVALID");
  }
}

async function main() {
  const outputPath = argument("--output", common.DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH);
  const source = common.sourceIdentity();
  const runnerReview = acceptedReview(source);
  if (fs.existsSync(outputPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PLAN_ALREADY_EXISTS");
  }
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const incidentReceiptBytes = fs.readFileSync(common.DEFAULT_RECOVERY_RECEIPT_PATH);
  const incidentLockBytes = fs.readFileSync(common.DEFAULT_RECOVERY_EXECUTION_LOCK_PATH);
  const incidentReceipt = JSON.parse(incidentReceiptBytes);
  const incidentLock = JSON.parse(incidentLockBytes);
  assertIncidentEvidence(incidentReceipt, incidentLock, config);

  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (common.endpointDigest(primaryUrl) === common.endpointDigest(reconciliationUrl)) {
    common.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const placeholder = {
    authorizationEnvelopeDigest: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_ENVELOPE"),
    rootProofNullifier: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_NULLIFIER"),
    deviceApprovalNonce: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_DEVICE_NONCE")
  };
  const state = await common.assertProviderPair(
    primary, reconciliation, config, placeholder, { expectUnfunded: false }
  );
  if (state.accountBalanceWei !== common.P2_RECOVERY_ORIGIN.confirmedFundingValueWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PREFUND_CHANGED");
  }
  const incidentHash = incidentReceipt.mutations[0].userOperationHash;
  const [bundlerReceipt, bundlerOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [incidentHash]),
    bundler.send("eth_getUserOperationByHash", [incidentHash])
  ]);
  if (bundlerReceipt !== null || bundlerOperation !== null) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_INCIDENT_OPERATION_FOUND");
  }

  const fundingSource = ethers.getAddress(common.required(
    "PHILCORE_CONTROLLED_BETA_FUNDING_SOURCE_ADDRESS"
  ));
  const data = common.factoryInterface.encodeFunctionData("createAccount", [
    config.account.initialExecutionValidator,
    config.account.ownerCommitment,
    config.account.salt
  ]);
  const [primaryNonce, reconciliationNonce, primaryBalance, reconciliationBalance,
    primaryGas, reconciliationGas] = await Promise.all([
    primary.getTransactionCount(fundingSource, "pending"),
    reconciliation.getTransactionCount(fundingSource, "pending"),
    primary.getBalance(fundingSource), reconciliation.getBalance(fundingSource),
    primary.estimateGas({ from: fundingSource, to: config.infrastructure.factory, data, value: 0n }),
    reconciliation.estimateGas({ from: fundingSource, to: config.infrastructure.factory, data, value: 0n })
  ]);
  if (primaryNonce !== reconciliationNonce || primaryBalance !== reconciliationBalance) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PROVIDER_DISAGREEMENT");
  }
  const gasEstimate = primaryGas > reconciliationGas ? primaryGas : reconciliationGas;
  const gasLimit = (gasEstimate * 12n + 9n) / 10n;
  const maxFeePerGas = BigInt(config.gasPolicy.maxFeePerGas);
  const maxPriorityFeePerGas = BigInt(config.gasPolicy.maxPriorityFeePerGas);
  const maximumFeeWei = gasLimit * maxFeePerGas;
  if (gasLimit > 2_000_000n || maximumFeeWei > BigInt(config.maximumOperatorExposureWei)
    || primaryBalance < maximumFeeWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_FEE_POLICY_INVALID");
  }
  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > maxFeePerGas
    || feeData.maxPriorityFeePerGas > maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_FEE_CAP_STALE");
  }

  const body = {
    format: "philcore-controlled-sepolia-beta-p2-account-deployment-plan-v1",
    version: 1,
    stageId: "P2A",
    status: "EXACT_P2_ACCOUNT_DEPLOYMENT_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt: new Date().toISOString(),
    source,
    runnerReview,
    chainId: String(common.CHAIN_ID),
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
    incident: {
      failedPlanDigest: incidentReceipt.planDigest,
      userOperationHash: incidentHash,
      receiptByteSha256: common.sha256Bytes(incidentReceiptBytes),
      lockByteSha256: common.sha256Bytes(incidentLockBytes),
      bundlerRejectionCode: -32502,
      bundlerRejectionMessage: "entity stake/unstake delay too low",
      rejectedOperationAbsentFromBundler: true,
      noOnChainMutationConfirmedByTwoProviders: true
    },
    account: {
      address: config.account.predictedAddress,
      owner: config.account.initialExecutionValidator,
      ownerCommitment: config.account.ownerCommitment,
      salt: config.account.salt,
      startingNativeBalanceWei: state.accountBalanceWei,
      startingEntryPointNonce: "0",
      deployedBefore: false,
      deployedAfter: true
    },
    transaction: {
      from: fundingSource,
      to: config.infrastructure.factory,
      nonce: String(primaryNonce),
      valueWei: "0",
      data,
      dataSha256: common.sha256Bytes(Buffer.from(data.slice(2), "hex")),
      gasEstimate: gasEstimate.toString(),
      gasLimit: gasLimit.toString(),
      maxFeePerGas: maxFeePerGas.toString(),
      maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
      maximumFeeWei: maximumFeeWei.toString(),
      type: 2
    },
    mutations: [{
      order: 1,
      kind: "DIRECTLY_DEPLOY_PREFUNDED_SMART_ACCOUNT_THROUGH_EXISTING_FACTORY",
      from: fundingSource,
      target: config.infrastructure.factory,
      createdAccount: config.account.predictedAddress,
      valueWei: "0"
    }],
    publicMutationCount: 1,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    stopConditions: [
      "source_or_review_identity_changed",
      "incident_evidence_changed_or_operation_found",
      "provider_disagreement",
      "account_code_balance_nonce_or_replay_state_changed",
      "funding_source_nonce_or_balance_changed",
      "gas_estimate_or_fee_cap_stale",
      "durable_execution_attempt_lock_already_exists"
    ],
    approval: { requiredPhrase: null, approved: false }
  };
  const planDigest = common.canonicalSha256(body);
  body.approval.requiredPhrase = common.approvalPhrase("P2A", planDigest);
  const plan = { ...body, planDigest };
  common.atomicCreateJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    mutationCount: plan.publicMutationCount,
    caller: fundingSource,
    factory: config.infrastructure.factory,
    smartAccount: config.account.predictedAddress,
    maximumFeeWei: plan.transaction.maximumFeeWei,
    outputPath,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || String(error)}\n`);
  process.exitCode = 1;
});
