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

function acceptedReview(source) {
  const review = {
    reviewedCommit: p5.required("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_COMMIT"),
    reviewedTree: p5.required("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_TREE"),
    reportSha256: p5.required("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_SHA256").toLowerCase(),
    disposition: p5.required("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_DISPOSITION")
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_INVALID");
  }
  return review;
}

async function main() {
  const lineageId = p5.assertFutureLineageId(argument("--lineage-id"));
  const outputPath = p5.lineagePaths(lineageId).plan;
  const source = p5.sourceIdentity();
  const runnerReview = acceptedReview(source);
  if (fs.existsSync(outputPath)) p5.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_ALREADY_EXISTS");
  const config = p5.loadConfiguration();
  const primaryUrl = p5.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = p5.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = p5.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (p5.endpointDigest(primaryUrl) === p5.endpointDigest(reconciliationUrl)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(primaryUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, p5.CHAIN_ID, p5.PROVIDER_OPTIONS);
  const state = await p5.readProviderPair(primary, reconciliation, config);
  const provisional = p5.createUnsignedOperation({
    config, state, gasPolicy: p5.provisionalP5GasPolicy(config)
  });
  const [supported, provisionalEstimate, feeData] = await Promise.all([
    bundler.send("eth_supportedEntryPoints", []),
    bundler.send("eth_estimateUserOperationGas", [provisional.estimationRpc, p5.ENTRY_POINT]),
    primary.getFeeData()
  ]);
  if (!supported.some((value) => p5.sameAddress(value, p5.ENTRY_POINT))) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }
  const gasSelection = p5.selectP5GasPolicy({
    estimate: provisionalEstimate,
    feeData,
    config,
    verificationGasEvidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  p5.assertP5VerificationEfficiency(gasSelection.basis.verificationEfficiency);
  const unsigned = p5.createUnsignedOperation({
    config, state, gasPolicy: gasSelection.selected
  });
  const [existingReceipt, existingOperation, estimate] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [unsigned.userOperationHash]),
    bundler.send("eth_getUserOperationByHash", [unsigned.userOperationHash]),
    bundler.send("eth_estimateUserOperationGas", [unsigned.estimationRpc, p5.ENTRY_POINT])
  ]);
  if (existingReceipt !== null || existingOperation !== null) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_ALREADY_FOUND");
  }
  const endpointBindings = {
    primaryRpcUrlSha256: p5.endpointDigest(primaryUrl),
    reconciliationRpcUrlSha256: p5.endpointDigest(reconciliationUrl),
    bundlerUrlSha256: p5.endpointDigest(bundlerUrl)
  };
  const plan = p5.createPlan({
    lineageId,
    source,
    runnerReview,
    config,
    state,
    estimate,
    feeData,
    gasSelection,
    endpointBindings,
    endpoints: {
      primary: p5.sanitizedEndpoint(primaryUrl),
      reconciliation: p5.sanitizedEndpoint(reconciliationUrl),
      bundler: p5.sanitizedEndpoint(bundlerUrl)
    },
    compiler: p5.compilerIdentity()
  });
  p5.atomicCreateJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest: plan.planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    userOperationHash: plan.userOperation.hash,
    maximumPrefundWei: plan.prefund.maximumPrefundWei,
    maximumTerminalEntryPointDepositWei: plan.prefund.maximumTerminalEntryPointDepositWei,
    exactZeroEntryPointDepositPromised: false,
    outputPath,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error?.code || error?.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, acceptedReview };
