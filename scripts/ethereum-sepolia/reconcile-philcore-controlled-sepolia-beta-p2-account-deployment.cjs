"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

const INCIDENT = Object.freeze({
  planDigest: "0xdf9fcb7a6aaacb5946d70845404d1235aa424d9784ccda1d2b690bae19e75519",
  transactionHash: "0x78770827598af3378b6ddea04c1131df2b3b7b42baf530163078c2a5fb6cf2ce",
  source: Object.freeze({
    commit: "ca397da3b6e69d01a1ed226afd80cc9d0a4c2043",
    tree: "cac597de6178fb88abe9a30874e6044d36a96cd8",
    protectedUntrackedFile: "pqREADME.md",
    protectedUntrackedFileSha256:
      "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8"
  })
});

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) {
    common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  }
  return process.argv[index + 1];
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

function assertPlan(plan) {
  const digestBody = { ...plan };
  delete digestBody.planDigest;
  digestBody.approval = { requiredPhrase: null, approved: false };
  const digest = common.canonicalSha256(digestBody);
  if (plan?.format !== "philcore-controlled-sepolia-beta-p2-account-deployment-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P2A"
    || plan.status !== "EXACT_P2_ACCOUNT_DEPLOYMENT_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.planDigest !== digest
    || plan.approval?.requiredPhrase !== common.approvalPhrase("P2A", digest)
    || plan.approval?.approved !== false || plan.publicMutationCount !== 1
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.mutations?.length !== 1
    || plan.mutations[0]?.kind
      !== "DIRECTLY_DEPLOY_PREFUNDED_SMART_ACCOUNT_THROUGH_EXISTING_FACTORY") {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_PLAN_INVALID");
  }
}

function assertStoppedEvidence(receipt, lock, plan) {
  if (receipt?.format !== "philcore-controlled-sepolia-beta-p2-account-deployment-receipt-v1"
    || receipt.version !== 1 || receipt.stageId !== "P2A"
    || receipt.status !== "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION"
    || receipt.planDigest !== plan.planDigest || receipt.publicMutationOccurred !== true
    || receipt.automaticRetryOccurred !== false || receipt.mutations?.length !== 1
    || receipt.mutations[0]?.status !== "submission_requested"
    || !/^0x[0-9a-f]{64}$/u.test(receipt.mutations[0]?.transactionHash || "")
    || lock?.format !== "philcore-controlled-sepolia-beta-p2a-execution-attempt-lock-v1"
    || lock.version !== 1 || lock.stageId !== "P2A" || lock.planDigest !== plan.planDigest
    || lock.automaticRetryAllowed !== false
    || common.canonicalJson(lock.source) !== common.canonicalJson(plan.source)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_STOPPED_EVIDENCE_INVALID");
  }
  if (plan.planDigest !== INCIDENT.planDigest
    || receipt.mutations[0].transactionHash !== INCIDENT.transactionHash
    || common.canonicalJson(plan.source) !== common.canonicalJson(INCIDENT.source)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_INCIDENT_IDENTITY_INVALID");
  }
}

function rawTransactionMatches(transaction, plan, transactionHash) {
  const data = transaction?.input ?? transaction?.data;
  return transaction
    && String(transaction.hash).toLowerCase() === transactionHash
    && common.sameAddress(transaction.from, plan.transaction.from)
    && common.sameAddress(transaction.to, plan.transaction.to)
    && String(data).toLowerCase() === plan.transaction.data.toLowerCase()
    && BigInt(transaction.nonce) === BigInt(plan.transaction.nonce)
    && BigInt(transaction.value) === 0n
    && BigInt(transaction.gas) === BigInt(plan.transaction.gasLimit)
    && BigInt(transaction.maxFeePerGas) === BigInt(plan.transaction.maxFeePerGas)
    && BigInt(transaction.maxPriorityFeePerGas)
      === BigInt(plan.transaction.maxPriorityFeePerGas)
    && BigInt(transaction.type) === 2n
    && BigInt(transaction.chainId) === BigInt(common.CHAIN_ID);
}

function createdEvent(receipt, config) {
  const matches = [];
  for (const log of receipt.logs || []) {
    if (!common.sameAddress(log.address, config.infrastructure.factory)) continue;
    try {
      const parsed = common.factoryInterface.parseLog(log);
      if (parsed?.name === "PhilCore4337AccountCreated") matches.push(parsed);
    } catch {}
  }
  if (matches.length !== 1) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_CREATED_EVENT_INVALID");
  }
  const event = matches[0];
  if (!common.sameAddress(event.args.account, config.account.predictedAddress)
    || !common.sameAddress(event.args.owner, config.account.initialExecutionValidator)
    || String(event.args.ownerCommitment).toLowerCase()
      !== config.account.ownerCommitment.toLowerCase()
    || !common.sameAddress(event.args.approvedActionGate, config.infrastructure.actionGate)
    || !common.sameAddress(event.args.recoveryAuthority, config.account.initialRecoveryAuthority)
    || BigInt(event.args.salt) !== BigInt(config.account.salt)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_CREATED_EVENT_BINDING_INVALID");
  }
}

function writeExclusiveBytes(target, bytes) {
  fs.mkdirSync(require("node:path").dirname(target), { recursive: true, mode: 0o700 });
  let descriptor;
  try {
    descriptor = fs.openSync(target, "wx", 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } catch (error) {
    common.fail(error?.code === "EEXIST"
      ? "PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_ALREADY_EXISTS"
      : "PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_WRITE_FAILED");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

async function main() {
  const planPath = argument("--plan", common.DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH);
  const receiptPath = argument("--receipt", common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH);
  const lockPath = argument(
    "--lock", common.DEFAULT_ACCOUNT_DEPLOYMENT_EXECUTION_LOCK_PATH
  );
  const reconciliationPath = argument(
    "--output", common.DEFAULT_ACCOUNT_DEPLOYMENT_RECONCILIATION_PATH
  );
  const stoppedReceiptPath = argument(
    "--stopped-receipt-output", common.DEFAULT_ACCOUNT_DEPLOYMENT_STOPPED_RECEIPT_PATH
  );
  if (fs.existsSync(reconciliationPath) || fs.existsSync(stoppedReceiptPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_ALREADY_EXISTS");
  }
  const planBytes = fs.readFileSync(planPath);
  const receiptBytes = fs.readFileSync(receiptPath);
  const lockBytes = fs.readFileSync(lockPath);
  const plan = JSON.parse(planBytes);
  const receipt = JSON.parse(receiptBytes);
  const lock = JSON.parse(lockBytes);
  assertPlan(plan);
  assertStoppedEvidence(receipt, lock, plan);
  const reconciliationSource = common.sourceIdentity();
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  common.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const transactionHash = receipt.mutations[0].transactionHash;
  const [leftTransaction, rightTransaction, leftReceipt, rightReceipt] = await Promise.all([
    primary.send("eth_getTransactionByHash", [transactionHash]),
    reconciliation.send("eth_getTransactionByHash", [transactionHash]),
    primary.send("eth_getTransactionReceipt", [transactionHash]),
    reconciliation.send("eth_getTransactionReceipt", [transactionHash])
  ]);
  if (!rawTransactionMatches(leftTransaction, plan, transactionHash)
    || !rawTransactionMatches(rightTransaction, plan, transactionHash)
    || common.canonicalJson(leftTransaction) !== common.canonicalJson(rightTransaction)
    || !leftReceipt || !rightReceipt
    || BigInt(leftReceipt.status) !== 1n || BigInt(rightReceipt.status) !== 1n
    || String(leftReceipt.blockHash).toLowerCase()
      !== String(rightReceipt.blockHash).toLowerCase()
    || BigInt(leftReceipt.blockNumber) !== BigInt(rightReceipt.blockNumber)
    || BigInt(leftReceipt.gasUsed) !== BigInt(rightReceipt.gasUsed)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_INVALID");
  }
  createdEvent(leftReceipt, config);
  createdEvent(rightReceipt, config);
  const placeholder = {
    authorizationEnvelopeDigest: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_ENVELOPE"),
    rootProofNullifier: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_NULLIFIER"),
    deviceApprovalNonce: ethers.id("PHILCORE_P2_ACCOUNT_DEPLOYMENT_DEVICE_NONCE")
  };
  const finalState = await common.assertProviderPair(
    primary, reconciliation, config, placeholder, { expectUnfunded: false, expectDeployed: true }
  );
  if (finalState.accountBalanceWei !== plan.account.startingNativeBalanceWei
    || !/^0x[0-9a-f]{64}$/u.test(finalState.accountCodeHash || "")
    || !/^0x[0-9a-f]{64}$/u.test(finalState.accountImmutableMaskedRuntimeCodeHash || "")) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_FINAL_STATE_INVALID");
  }
  const reconciledAt = new Date().toISOString();
  const reconciliationRecord = {
    format: "philcore-controlled-sepolia-beta-p2-account-deployment-reconciliation-v1",
    version: 1,
    stageId: "P2A",
    status: "P2_ACCOUNT_DEPLOYMENT_CONFIRMED_AFTER_READ_ONLY_RECONCILIATION",
    reconciledAt,
    source: plan.source,
    reconciliationSource,
    planDigest: plan.planDigest,
    planByteSha256: common.sha256Bytes(planBytes),
    stoppedReceiptByteSha256: common.sha256Bytes(receiptBytes),
    executionLockByteSha256: common.sha256Bytes(lockBytes),
    transactionHash,
    blockNumber: BigInt(leftReceipt.blockNumber).toString(),
    blockHash: leftReceipt.blockHash,
    gasUsed: BigInt(leftReceipt.gasUsed).toString(),
    confirmedByBothProviders: true,
    publicMutationPerformedByReconciliation: false,
    automaticRetryOccurred: false,
    finalState: {
      smartAccount: ethers.getAddress(config.account.predictedAddress),
      runtimeCodeHash: finalState.accountCodeHash,
      immutableMaskedRuntimeCodeHash: finalState.accountImmutableMaskedRuntimeCodeHash,
      nativeBalanceWei: finalState.accountBalanceWei,
      entryPointNonce: "0",
      factoryRegistration: true
    }
  };
  const confirmedReceipt = {
    ...receipt,
    status: "P2_ACCOUNT_DEPLOYMENT_CONFIRMED",
    reconciledAt,
    historicalStoppedAttempt: {
      status: receipt.status,
      stoppedAt: receipt.stoppedAt,
      failureCode: receipt.failureCode,
      error: receipt.error
    },
    failureCode: undefined,
    error: undefined,
    mutations: [{
      ...receipt.mutations[0],
      status: "confirmed_by_both_providers",
      blockNumber: reconciliationRecord.blockNumber,
      gasUsed: reconciliationRecord.gasUsed
    }],
    finalState: reconciliationRecord.finalState,
    publicMutationOccurred: true,
    automaticRetryOccurred: false,
    reconciliation: {
      evidencePath: reconciliationPath,
      stoppedReceiptPath,
      stoppedReceiptByteSha256: reconciliationRecord.stoppedReceiptByteSha256,
      confirmedByBothProviders: true,
      publicMutationPerformedByReconciliation: false
    }
  };
  writeExclusiveBytes(stoppedReceiptPath, receiptBytes);
  common.atomicWriteJson(reconciliationPath, reconciliationRecord);
  common.atomicWriteJson(receiptPath, confirmedReceipt);
  process.stdout.write(`${JSON.stringify({
    status: reconciliationRecord.status,
    transactionHash,
    blockNumber: reconciliationRecord.blockNumber,
    finalState: reconciliationRecord.finalState,
    publicMutationPerformedByReconciliation: false,
    automaticRetryOccurred: false,
    reconciliationPath,
    receiptPath
  }, null, 2)}\n`);
}

main().catch((error) => {
  const failure = errorEvidence(error);
  process.stderr.write(`${failure.rpcMessage || failure.shortMessage
    || failure.code || failure.message || "P2_ACCOUNT_DEPLOYMENT_RECONCILIATION_FAILED"}\n`);
  process.exitCode = 1;
});
