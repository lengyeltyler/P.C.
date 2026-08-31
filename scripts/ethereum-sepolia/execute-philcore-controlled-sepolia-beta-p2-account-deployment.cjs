"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

let receiptPath = common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH;
let evidence;

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function persist() {
  if (evidence) common.atomicWriteJson(receiptPath, evidence);
}

function sanitizeErrorValue(value, depth = 0) {
  if (value === null || value === undefined || typeof value === "boolean"
    || typeof value === "number") return value ?? null;
  if (typeof value === "string") {
    return value.replace(/https?:\/\/[^\s"')]+/giu, "[REDACTED_ENDPOINT]").slice(0, 8192);
  }
  if (depth >= 4) return "[TRUNCATED]";
  if (Array.isArray(value)) {
    return value.slice(0, 32).map((item) => sanitizeErrorValue(item, depth + 1));
  }
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).slice(0, 64).map(([key, item]) => (
      [key, sanitizeErrorValue(item, depth + 1)]
    )));
  }
  return String(value).slice(0, 8192);
}

function errorEvidence(error) {
  return Object.freeze({
    code: error?.code ?? null,
    shortMessage: sanitizeErrorValue(error?.shortMessage),
    message: sanitizeErrorValue(error?.message),
    rpcCode: error?.info?.error?.code ?? error?.error?.code ?? null,
    rpcMessage: sanitizeErrorValue(
      error?.info?.error?.message ?? error?.error?.message
    ),
    rpcData: sanitizeErrorValue(error?.info?.error?.data ?? error?.error?.data)
  });
}

function assertPlan(plan, approvedDigest) {
  const digestBody = { ...plan };
  delete digestBody.planDigest;
  digestBody.approval = { requiredPhrase: null, approved: false };
  const digest = common.canonicalSha256(digestBody);
  if (plan?.format !== "philcore-controlled-sepolia-beta-p2-account-deployment-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P2A"
    || plan.status !== "EXACT_P2_ACCOUNT_DEPLOYMENT_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || digest !== approvedDigest.toLowerCase() || plan.planDigest !== digest
    || plan.approval?.requiredPhrase !== common.approvalPhrase("P2A", digest)
    || plan.approval.approved !== false || plan.publicMutationCount !== 1
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.mutations?.length !== 1
    || plan.mutations[0]?.kind
      !== "DIRECTLY_DEPLOY_PREFUNDED_SMART_ACCOUNT_THROUGH_EXISTING_FACTORY"
    || plan.transaction?.valueWei !== "0" || plan.transaction?.type !== 2) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PLAN_INVALID");
  }
}

function assertPlanBindings(plan, config, fundingSource) {
  let factoryCall;
  try {
    factoryCall = common.factoryInterface.parseTransaction({ data: plan.transaction.data });
  } catch {}
  if (plan.chainId !== String(common.CHAIN_ID)
    || plan.runnerReview?.reviewedCommit !== plan.source?.commit
    || plan.runnerReview?.reviewedTree !== plan.source?.tree
    || !/^0x[0-9a-f]{64}$/u.test(plan.runnerReview?.reportSha256 || "")
    || plan.runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    || !common.sameAddress(plan.transaction.from, fundingSource)
    || !common.sameAddress(plan.transaction.to, config.infrastructure.factory)
    || !common.sameAddress(plan.mutations[0].from, fundingSource)
    || !common.sameAddress(plan.mutations[0].target, config.infrastructure.factory)
    || !common.sameAddress(plan.mutations[0].createdAccount, config.account.predictedAddress)
    || !common.sameAddress(plan.account.address, config.account.predictedAddress)
    || !common.sameAddress(plan.account.owner, config.account.initialExecutionValidator)
    || plan.account.ownerCommitment.toLowerCase() !== config.account.ownerCommitment.toLowerCase()
    || BigInt(plan.account.salt) !== BigInt(config.account.salt)
    || plan.account.startingEntryPointNonce !== "0"
    || plan.account.deployedBefore !== false || plan.account.deployedAfter !== true
    || !factoryCall || factoryCall.name !== "createAccount"
    || !common.sameAddress(factoryCall.args[0], config.account.initialExecutionValidator)
    || String(factoryCall.args[1]).toLowerCase() !== config.account.ownerCommitment.toLowerCase()
    || BigInt(factoryCall.args[2]) !== BigInt(config.account.salt)
    || common.sha256Bytes(Buffer.from(plan.transaction.data.slice(2), "hex"))
      !== plan.transaction.dataSha256
    || BigInt(plan.transaction.gasLimit) > 2_000_000n
    || BigInt(plan.transaction.maximumFeeWei)
      !== BigInt(plan.transaction.gasLimit) * BigInt(plan.transaction.maxFeePerGas)
    || BigInt(plan.transaction.maximumFeeWei) > BigInt(config.maximumOperatorExposureWei)
    || BigInt(plan.transaction.maxPriorityFeePerGas) > BigInt(plan.transaction.maxFeePerGas)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PLAN_BINDING_INVALID");
  }
}

async function waitForReceipt(provider, hash, deadlineMs = 180_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const receipt = await provider.getTransactionReceipt(hash);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECEIPT_TIMEOUT");
}

async function verifyDeployed(primary, reconciliation, plan, config) {
  const placeholder = {
    authorizationEnvelopeDigest: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_ENVELOPE"),
    rootProofNullifier: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_NULLIFIER"),
    deviceApprovalNonce: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_DEVICE_NONCE")
  };
  const state = await common.assertProviderPair(primary, reconciliation, config, placeholder, {
    expectUnfunded: false,
    expectDeployed: true
  });
  const code = await primary.getCode(plan.account.address);
  if (state.accountBalanceWei !== plan.account.startingNativeBalanceWei
    || state.accountCodeHash?.toLowerCase() !== ethers.keccak256(code).toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_FINAL_STATE_INVALID");
  }
  return {
    smartAccount: ethers.getAddress(plan.account.address),
    runtimeCodeHash: state.accountCodeHash,
    immutableMaskedRuntimeCodeHash: state.accountImmutableMaskedRuntimeCodeHash,
    nativeBalanceWei: state.accountBalanceWei,
    entryPointNonce: "0",
    factoryRegistration: true
  };
}

async function main() {
  const approvedDigest = argument("--plan-digest");
  if (!approvedDigest || !/^0x[0-9a-f]{64}$/iu.test(approvedDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_EXPLICIT_PLAN_DIGEST_REQUIRED");
  }
  const suppliedApproval = common.required(
    "PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_APPROVAL"
  );
  if (suppliedApproval !== common.approvalPhrase("P2A", approvedDigest.toLowerCase())) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_EXACT_APPROVAL_REQUIRED");
  }
  const planPath = argument("--plan", common.DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH);
  receiptPath = argument("--receipt-output", common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH);
  if (fs.existsSync(receiptPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECEIPT_ALREADY_EXISTS");
  }
  const plan = common.readJson(planPath);
  assertPlan(plan, approvedDigest);
  if (!common.sourceIdentityMatches(plan.source)) {
    common.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  }
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const configuredFundingSource = ethers.getAddress(common.required(
    "PHILCORE_CONTROLLED_BETA_FUNDING_SOURCE_ADDRESS"
  ));
  assertPlanBindings(plan, config, configuredFundingSource);
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  common.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const incidentReceiptBytes = fs.readFileSync(common.DEFAULT_RECOVERY_RECEIPT_PATH);
  const incidentLockBytes = fs.readFileSync(common.DEFAULT_RECOVERY_EXECUTION_LOCK_PATH);
  if (common.sha256Bytes(incidentReceiptBytes) !== plan.incident.receiptByteSha256
    || common.sha256Bytes(incidentLockBytes) !== plan.incident.lockByteSha256) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_INCIDENT_EVIDENCE_CHANGED");
  }
  const [oldReceipt, oldOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [plan.incident.userOperationHash]),
    bundler.send("eth_getUserOperationByHash", [plan.incident.userOperationHash])
  ]);
  if (oldReceipt !== null || oldOperation !== null) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_INCIDENT_OPERATION_FOUND");
  }
  const placeholder = {
    authorizationEnvelopeDigest: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_ENVELOPE"),
    rootProofNullifier: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_NULLIFIER"),
    deviceApprovalNonce: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_DEVICE_NONCE")
  };
  const state = await common.assertProviderPair(
    primary, reconciliation, config, placeholder, { expectUnfunded: false }
  );
  const fundingSource = configuredFundingSource;
  const [nonceLeft, nonceRight, balanceLeft, balanceRight, estimateLeft, estimateRight] = await Promise.all([
    primary.getTransactionCount(fundingSource, "pending"),
    reconciliation.getTransactionCount(fundingSource, "pending"),
    primary.getBalance(fundingSource), reconciliation.getBalance(fundingSource),
    primary.estimateGas({
      from: fundingSource, to: plan.transaction.to,
      data: plan.transaction.data, value: 0n
    }),
    reconciliation.estimateGas({
      from: fundingSource, to: plan.transaction.to,
      data: plan.transaction.data, value: 0n
    })
  ]);
  if (state.accountBalanceWei !== plan.account.startingNativeBalanceWei
    || nonceLeft !== Number(plan.transaction.nonce) || nonceRight !== nonceLeft
    || balanceLeft !== balanceRight || balanceLeft < BigInt(plan.transaction.maximumFeeWei)
    || estimateLeft > BigInt(plan.transaction.gasLimit)
    || estimateRight > BigInt(plan.transaction.gasLimit)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_PREFLIGHT_CHANGED");
  }
  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > BigInt(plan.transaction.maxFeePerGas)
    || feeData.maxPriorityFeePerGas > BigInt(plan.transaction.maxPriorityFeePerGas)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_FEE_CAP_STALE");
  }

  const wallet = common.walletFromKeychain(
    common.required("PHILCORE_CONTROLLED_BETA_FUNDING_KEYCHAIN_SERVICE"),
    fundingSource
  );
  const raw = await wallet.signTransaction({
    chainId: common.CHAIN_ID,
    type: 2,
    nonce: nonceLeft,
    to: plan.transaction.to,
    value: 0n,
    data: plan.transaction.data,
    gasLimit: BigInt(plan.transaction.gasLimit),
    maxFeePerGas: BigInt(plan.transaction.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(plan.transaction.maxPriorityFeePerGas)
  });
  const transactionHash = ethers.keccak256(raw);
  const executionLock = common.acquireBoundedExecutionLock(
    plan.planDigest, plan.source, "P2A", common.DEFAULT_ACCOUNT_DEPLOYMENT_EXECUTION_LOCK_PATH
  );
  evidence = {
    format: "philcore-controlled-sepolia-beta-p2-account-deployment-receipt-v1",
    version: 1,
    stageId: "P2A",
    status: "APPROVAL_VERIFIED_EXECUTION_STARTING",
    planDigest: plan.planDigest,
    source: plan.source,
    chainId: plan.chainId,
    endpoints: plan.endpoints,
    approval: { phraseMatched: true, planDigestMatched: true, verifiedAt: new Date().toISOString() },
    executionLock,
    mutations: [],
    publicMutationOccurred: false,
    automaticRetryOccurred: false
  };
  persist();
  evidence.status = "MUTATION_1_ACCOUNT_DEPLOYMENT_SUBMISSION_REQUESTED";
  evidence.publicMutationOccurred = true;
  evidence.mutations.push({
    order: 1,
    kind: plan.mutations[0].kind,
    transactionHash,
    status: "submission_requested"
  });
  persist();
  const response = await primary.broadcastTransaction(raw);
  if (response.hash.toLowerCase() !== transactionHash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_BROADCAST_HASH_CHANGED");
  }
  const primaryReceipt = await response.wait(1, 180_000);
  const reconciliationReceipt = await waitForReceipt(reconciliation, transactionHash);
  if (!primaryReceipt || primaryReceipt.status !== 1 || reconciliationReceipt.status !== 1
    || primaryReceipt.blockHash.toLowerCase() !== reconciliationReceipt.blockHash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECEIPT_INVALID");
  }
  const finalState = await verifyDeployed(primary, reconciliation, plan, config);
  evidence.mutations[0] = {
    ...evidence.mutations[0],
    status: "confirmed_by_both_providers",
    blockNumber: String(primaryReceipt.blockNumber),
    gasUsed: primaryReceipt.gasUsed.toString()
  };
  evidence.status = "P2_ACCOUNT_DEPLOYMENT_CONFIRMED";
  evidence.completedAt = new Date().toISOString();
  evidence.finalState = finalState;
  evidence.publicMutationOccurred = true;
  persist();
  process.stdout.write(`${JSON.stringify({
    status: evidence.status,
    planDigest: plan.planDigest,
    transactionHash,
    finalState,
    automaticRetryOccurred: false,
    receiptPath
  }, null, 2)}\n`);
}

main().catch((error) => {
  const failure = errorEvidence(error);
  if (evidence) {
    evidence.status = "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION";
    evidence.stoppedAt = new Date().toISOString();
    evidence.failureCode = failure.rpcMessage || failure.shortMessage
      || failure.code || failure.message || "P2_ACCOUNT_DEPLOYMENT_FAILED";
    evidence.error = failure;
    evidence.automaticRetryOccurred = false;
    try { persist(); } catch {}
  }
  process.stderr.write(`${failure.rpcMessage || failure.shortMessage
    || failure.code || failure.message || "P2_ACCOUNT_DEPLOYMENT_FAILED"}\n`);
  process.exitCode = 1;
});
