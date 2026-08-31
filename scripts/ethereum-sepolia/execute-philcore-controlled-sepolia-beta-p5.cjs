"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const p5 = require("./philcore-controlled-sepolia-beta-p5-common.cjs");

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) p5.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

async function executeWithDependencies({ plan, planBytes, artifact, artifactBytes, approvedDigest,
  suppliedApproval, config, primary, reconciliation, bundler, lockPath,
  receiptPath, persist = p5.atomicWriteJson, sourceMatches = p5.sourceIdentityMatches,
  readState = p5.readProviderPair, acquireLock = p5.acquireExecutionLock,
  classify = p5.classifyOperationEvidence, redactionValues = [] }) {
  p5.assertPlan(plan, approvedDigest, config);
  if (suppliedApproval !== p5.approvalPhrase(p5.STAGE_ID, plan.planDigest)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_EXACT_APPROVAL_REQUIRED");
  }
  if (!sourceMatches(plan.source)) p5.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  const parsed = p5.assertArtifactBinding(plan, planBytes, artifact, artifactBytes, config);
  const estimateBefore = await bundler.send("eth_estimateUserOperationGas", [
    parsed.rpc, p5.ENTRY_POINT
  ]);
  const feeData = await primary.getFeeData();
  p5.assertFeeAndEstimate(plan, estimateBefore, feeData);
  if (plan.maximumAdditionalFundingWei !== "0" || plan.prefund.externalFundingWei !== "0") {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_ADDITIONAL_FUNDING_REQUIRED");
  }
  const [existingReceipt, existingOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [plan.userOperation.hash]),
    bundler.send("eth_getUserOperationByHash", [plan.userOperation.hash])
  ]);
  if (existingReceipt !== null || existingOperation !== null) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_ALREADY_FOUND");
  }
  const live = await readState(primary, reconciliation, config);
  p5.assertStateEqualsPlan(live, plan.account);
  const executionLock = acquireLock(plan, lockPath);
  let evidence = {
    format: p5.RECEIPT_FORMAT,
    version: 2,
    stageId: p5.STAGE_ID,
    lineageId: plan.lineageId,
    status: "APPROVAL_AND_PRESTATE_VERIFIED_EXECUTION_LOCKED",
    planDigest: plan.planDigest,
    source: plan.source,
    executionLock,
    mutations: [{
      order: 1,
      kind: plan.mutations[0].kind,
      userOperationHash: plan.userOperation.hash,
      status: "submission_not_yet_requested"
    }],
    publicMutationOccurred: false,
    automaticRetryOccurred: false,
    additionalFundingWei: "0"
  };
  persist(receiptPath, evidence);
  const attemptedAt = new Date().toISOString();
  evidence.mutations[0].status = "submission_requested_once";
  evidence.mutations[0].attemptedAt = attemptedAt;
  evidence.publicMutationOccurred = true;
  persist(receiptPath, evidence);
  let returnedHash = null;
  let sendError = null;
  try {
    returnedHash = await bundler.send("eth_sendUserOperation", [parsed.rpc, p5.ENTRY_POINT]);
  } catch (error) {
    sendError = error;
  }
  if (returnedHash !== null
    && String(returnedHash).toLowerCase() !== plan.userOperation.hash.toLowerCase()) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_BUNDLER_HASH_MISMATCH");
  }
  const sendDisposition = p5.classifySendDisposition(sendError, returnedHash);
  const rejectionEvidence = sendError ? p5.bundlerRejectionEvidence(sendError, {
    sendDisposition,
    userOperationHash: plan.userOperation.hash,
    attemptedAt,
    redactionValues
  }) : null;
  if (rejectionEvidence) {
    evidence = {
      ...evidence,
      status: "SEND_REJECTED_PENDING_EXACT_HASH_RECONCILIATION",
      sendReturnedHash: null,
      sendDisposition,
      rejectionEvidence,
      automaticRetryOccurred: false
    };
    evidence.mutations[0] = {
      ...evidence.mutations[0],
      status: "submission_rejected_pending_exact_hash_reconciliation"
    };
    persist(receiptPath, evidence);
  }
  const [operation, userOperationReceipt] = await Promise.all([
    bundler.send("eth_getUserOperationByHash", [plan.userOperation.hash]),
    bundler.send("eth_getUserOperationReceipt", [plan.userOperation.hash])
  ]);
  let transactionReceipt = null;
  let finalState = null;
  const transactionHash = userOperationReceipt?.receipt?.transactionHash;
  if (/^0x[0-9a-f]{64}$/iu.test(transactionHash || "")) {
    const [left, right] = await Promise.all([
      primary.getTransactionReceipt(transactionHash),
      reconciliation.getTransactionReceipt(transactionHash)
    ]);
    if (!left || !right || left.blockHash.toLowerCase() !== right.blockHash.toLowerCase()
      || left.status !== right.status) {
      p5.fail("PHILCORE_CONTROLLED_BETA_P5_RECEIPT_PROVIDER_DISAGREEMENT");
    }
    transactionReceipt = left;
    finalState = await readState(primary, reconciliation, config);
  }
  const classification = classify({
    plan, operation, userOperationReceipt, transactionReceipt, finalState, sendDisposition
  });
  evidence = {
    ...evidence,
    status: classification.status,
    completedAt: new Date().toISOString(),
    sendReturnedHash: returnedHash,
    sendDisposition,
    rejectionEvidence,
    classification,
    automaticRetryOccurred: false
  };
  evidence.mutations[0] = {
    ...evidence.mutations[0],
    status: classification.status,
    transactionHash: transactionHash || null
  };
  persist(receiptPath, evidence);
  if (classification.status !== "INCLUDED_SUCCESS_RECONCILED") {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_STOPPED_REQUIRES_HUMAN_RECONCILIATION");
  }
  return evidence;
}

async function main() {
  const approvedDigest = argument("--plan-digest");
  if (!approvedDigest || !/^0x[0-9a-f]{64}$/iu.test(approvedDigest)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_EXPLICIT_PLAN_DIGEST_REQUIRED");
  }
  const suppliedApproval = p5.required("PHILCORE_CONTROLLED_BETA_P5_APPROVAL");
  if (suppliedApproval !== p5.approvalPhrase(p5.STAGE_ID, approvedDigest.toLowerCase())) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_EXACT_APPROVAL_REQUIRED");
  }
  const lineageId = p5.assertFutureLineageId(argument("--lineage-id"));
  const lineagePaths = p5.lineagePaths(lineageId);
  const planPath = lineagePaths.plan;
  const artifactPath = lineagePaths.signedArtifact;
  const receiptPath = lineagePaths.receipt;
  const lockPath = lineagePaths.executionLock;
  if (fs.existsSync(receiptPath)) p5.fail("PHILCORE_CONTROLLED_BETA_P5_RECEIPT_ALREADY_EXISTS");
  const planBytes = fs.readFileSync(planPath);
  const plan = JSON.parse(planBytes);
  p5.assertPlan(plan, approvedDigest.toLowerCase());
  if (plan.lineageId !== lineageId) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_LINEAGE_BINDING_INVALID");
  }
  if (!p5.sourceIdentityMatches(plan.source)) p5.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  const artifactBytes = fs.readFileSync(artifactPath);
  const artifact = JSON.parse(artifactBytes);
  const config = p5.loadConfiguration();
  const primaryUrl = p5.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = p5.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = p5.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  p5.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
  const primary = new ethers.JsonRpcProvider(primaryUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS);
  const evidence = await executeWithDependencies({
    plan,
    planBytes,
    artifact,
    artifactBytes,
    approvedDigest: approvedDigest.toLowerCase(),
    suppliedApproval,
    config,
    primary,
    reconciliation,
    bundler,
    lockPath,
    receiptPath,
    redactionValues: [primaryUrl, reconciliationUrl, bundlerUrl]
  });
  process.stdout.write(`${JSON.stringify({
    status: evidence.status,
    planDigest: plan.planDigest,
    userOperationHash: plan.userOperation.hash,
    automaticRetryOccurred: false,
    additionalFundingWei: "0",
    receiptPath
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error?.code || error?.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, executeWithDependencies };
