"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");
const p3Mode = process.argv.includes("--p3");

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function acceptedReview(source) {
  const prefix = p3Mode
    ? "PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW"
    : "PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNNER_REVIEW";
  const review = {
    reviewedCommit: common.required(`${prefix}_COMMIT`),
    reviewedTree: common.required(`${prefix}_TREE`),
    reportSha256: common.required(`${prefix}_SHA256`).toLowerCase(),
    disposition: common.required(`${prefix}_DISPOSITION`)
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail(p3Mode
      ? "PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_INVALID"
      : "PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNNER_REVIEW_INVALID");
  }
  return review;
}

function assertDeploymentReceipt(receipt, config) {
  if (receipt?.format !== "philcore-controlled-sepolia-beta-p2-account-deployment-receipt-v1"
    || receipt.version !== 1 || receipt.stageId !== "P2A"
    || receipt.status !== "P2_ACCOUNT_DEPLOYMENT_CONFIRMED"
    || receipt.publicMutationOccurred !== true || receipt.automaticRetryOccurred !== false
    || receipt.mutations?.length !== 1
    || receipt.mutations[0]?.status !== "confirmed_by_both_providers"
    || !/^0x[0-9a-f]{64}$/u.test(receipt.mutations[0]?.transactionHash || "")
    || !common.sameAddress(receipt.finalState?.smartAccount, config.account.predictedAddress)
    || !/^0x[0-9a-f]{64}$/u.test(receipt.finalState?.runtimeCodeHash || "")
    || !/^0x[0-9a-f]{64}$/u.test(
      receipt.finalState?.immutableMaskedRuntimeCodeHash || ""
    )
    || receipt.finalState?.entryPointNonce !== "0"
    || receipt.finalState?.factoryRegistration !== true) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_DEPLOYMENT_EVIDENCE_INVALID");
  }
}

async function main() {
  const outputPath = argument(
    "--output", p3Mode ? common.DEFAULT_P3_PLAN_PATH : common.DEFAULT_FINAL_PLAN_PATH
  );
  const signedArtifactPath = argument(
    "--signed-artifact",
    p3Mode ? common.DEFAULT_P3_SIGNED_ARTIFACT_PATH : common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH
  );
  const source = common.sourceIdentity();
  const runnerReview = acceptedReview(source);
  if (fs.existsSync(outputPath)) common.fail(p3Mode
    ? "PHILCORE_CONTROLLED_BETA_P3_PLAN_ALREADY_EXISTS"
    : "PHILCORE_CONTROLLED_BETA_P2_FINAL_PLAN_ALREADY_EXISTS");
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const priorReceiptBytes = fs.readFileSync(p3Mode
    ? common.DEFAULT_FINAL_RECEIPT_PATH
    : common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH);
  const priorReceipt = JSON.parse(priorReceiptBytes);
  if (p3Mode) common.assertP2FinalReceipt(priorReceipt, priorReceiptBytes, config);
  else assertDeploymentReceipt(priorReceipt, config);
  const p2FinalPlanBytes = p3Mode
    ? fs.readFileSync(common.DEFAULT_FINAL_PLAN_PATH)
    : null;
  const p2FinalPlan = p3Mode
    ? common.assertP2FinalPlan(JSON.parse(p2FinalPlanBytes), config)
    : null;
  const signedArtifactBytes = fs.readFileSync(signedArtifactPath);
  const signedArtifact = JSON.parse(signedArtifactBytes);
  const parsed = common.parseSignedArtifact(
    signedArtifact, config, common.artifacts(),
    { accountDeployed: true, expectedNonce: p3Mode ? 1 : 0 }
  );
  if (p3Mode) common.assertP3GasPolicy(parsed.gas, config.gasPolicy);
  else common.assertP2FinalGasPolicy(parsed.gas, config.gasPolicy);
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (parsed.validUntil <= now + 300n) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_AUTHORIZATION_WINDOW_TOO_SHORT");
  }
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
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported)
    || !supported.some((value) => common.sameAddress(value, common.ENTRY_POINT))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }
  const state = await common.assertProviderPair(
    primary, reconciliation, config, signedArtifact,
    {
      expectUnfunded: false,
      expectDeployed: true,
      expectedNonce: p3Mode ? 1 : 0,
      expectedNextTokenId: p3Mode ? 2 : 1,
      expectedEntryPointDepositWei: p3Mode
        ? common.P2_FINAL_ORIGIN.entryPointDepositWei
        : "0"
    }
  );
  if (state.accountBalanceWei !== priorReceipt.finalState.nativeBalanceWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_BALANCE_CHANGED");
  }
  const expectedAccountRuntime = p3Mode
    ? p2FinalPlan.runtimeCodeHashes.account
    : priorReceipt.finalState.runtimeCodeHash;
  const expectedMaskedRuntime = p3Mode
    ? p2FinalPlan.runtimeCodeHashes.accountImmutableMasked
    : priorReceipt.finalState.immutableMaskedRuntimeCodeHash;
  if (state.accountCodeHash?.toLowerCase() !== expectedAccountRuntime.toLowerCase()
    || state.accountImmutableMaskedRuntimeCodeHash?.toLowerCase()
      !== expectedMaskedRuntime.toLowerCase()
    || (p3Mode && state.accountCodeHash?.toLowerCase()
      !== priorReceipt.finalState.accountCodeHash.toLowerCase())) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_RUNTIME_CHANGED");
  }
  let p2FinalOrigin = null;
  let staleP2Rejection = null;
  let rejectedP3Submission = null;
  if (p3Mode) {
    p2FinalOrigin = await common.assertP2FinalOriginLive(
      primary, reconciliation, bundler, config
    );
    const staleP2Artifact = common.readJson(common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH);
    staleP2Rejection = await common.assertStaleP2UserOperationRejected(
      bundler, staleP2Artifact, config
    );
    rejectedP3Submission = await common.assertRejectedP3SubmissionAbsent(bundler);
  }
  const [nextReceipt, nextOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [signedArtifact.userOperationHash]),
    bundler.send("eth_getUserOperationByHash", [signedArtifact.userOperationHash])
  ]);
  if (nextReceipt !== null || nextOperation !== null) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_USER_OPERATION_ALREADY_FOUND");
  }
  const estimate = common.normalizeEstimate(await bundler.send(
    "eth_estimateUserOperationGas", [parsed.rpc, common.ENTRY_POINT]
  ));
  common.assertEstimateWithinSignedCaps(estimate, parsed);
  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > parsed.gas.maxFeePerGas
    || feeData.maxPriorityFeePerGas > parsed.gas.maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_SIGNED_FEE_CAP_STALE");
  }
  if (BigInt(state.accountBalanceWei) < parsed.maximumTotalFeeWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_PREFUND_INSUFFICIENT");
  }
  const endpointBindings = {
    primaryRpcUrlSha256: common.endpointDigest(primaryUrl),
    reconciliationRpcUrlSha256: common.endpointDigest(reconciliationUrl),
    bundlerUrlSha256: common.endpointDigest(bundlerUrl)
  };
  const priorStageEvidence = p3Mode ? {
    p2Final: {
      planDigest: priorReceipt.planDigest,
      planByteSha256: common.sha256Bytes(p2FinalPlanBytes),
      userOperationHash: common.P2_FINAL_ORIGIN.userOperationHash,
      transactionHash: priorReceipt.mutations[0].transactionHash,
      receiptByteSha256: common.sha256Bytes(priorReceiptBytes),
      confirmedByBothProviders: true
    },
    staleP2ReplayProof: {
      ...staleP2Rejection,
      replayFieldsConsumed: p2FinalOrigin.replayFieldsConsumed,
      confirmedByBothProviders: p2FinalOrigin.confirmedByBothProviders
    },
    rejectedP3Submission: {
      ...rejectedP3Submission,
      liveNonce: state.entryPointNonce,
      liveNextTokenId: state.nextTokenId,
      confirmedByBothProviders: true
    }
  } : {
    accountDeployment: {
      planDigest: priorReceipt.planDigest,
      transactionHash: priorReceipt.mutations[0].transactionHash,
      receiptByteSha256: common.sha256Bytes(priorReceiptBytes),
      confirmedByBothProviders: true
    }
  };
  const body = {
    format: p3Mode
      ? "philcore-controlled-sepolia-beta-p3-plan-v1"
      : "philcore-controlled-sepolia-beta-p2-final-plan-v1",
    version: 1,
    stageId: p3Mode ? "P3" : "P2F",
    status: p3Mode
      ? "EXACT_P3_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
      : "EXACT_P2_FINAL_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt: new Date().toISOString(),
    source,
    runnerReview,
    compiler: common.compilerIdentity(),
    chainId: String(common.CHAIN_ID),
    entryPoint: common.ENTRY_POINT,
    endpoints: {
      primary: common.sanitizedEndpoint(primaryUrl),
      reconciliation: common.sanitizedEndpoint(reconciliationUrl),
      bundler: common.sanitizedEndpoint(bundlerUrl)
    },
    endpointBindings,
    contracts: {
      consumer: config.infrastructure.mintConsumer,
      gate: config.infrastructure.actionGate,
      factory: config.infrastructure.factory,
      account: config.account.predictedAddress
    },
    runtimeCodeHashes: {
      ...config.runtimeCodeHashes,
      account: state.accountCodeHash,
      accountImmutableMasked: state.accountImmutableMaskedRuntimeCodeHash
    },
    authorities: {
      initialExecutionValidator: config.account.initialExecutionValidator,
      initialRecoveryAuthority: config.account.initialRecoveryAuthority
    },
    account: {
      address: config.account.predictedAddress,
      ownerCommitment: config.account.ownerCommitment,
      salt: config.account.salt,
      startingNonce: p3Mode ? "1" : "0",
      startingNativeBalanceWei: state.accountBalanceWei,
      startingEntryPointDepositWei: p3Mode
        ? common.P2_FINAL_ORIGIN.entryPointDepositWei
        : "0",
      deployed: true
    },
    ...priorStageEvidence,
    composition: {
      format: signedArtifact.format,
      signedArtifactSha256: common.canonicalSha256(signedArtifact),
      signedArtifactByteSha256: common.sha256Bytes(signedArtifactBytes),
      authorizationEnvelopeDigest: signedArtifact.authorizationEnvelopeDigest,
      rootProofNullifier: signedArtifact.rootProofNullifier,
      deviceApprovalNonce: signedArtifact.deviceApprovalNonce,
      ethereumVerifiesNoirProof: false,
      ethereumVerifiesP256Approval: false,
      phoneAssurance: signedArtifact.phoneAssurance,
      localCompositionRequiredBeforeDeviceVaultRelease: true,
      proofAndPhoneP256PossessionApprovalCompleted: true
    },
    userOperation: {
      hash: signedArtifact.userOperationHash,
      validUntil: parsed.validUntil.toString(),
      rpc: parsed.rpc,
      packed: signedArtifact.userOperation,
      bundlerEstimate: Object.fromEntries(
        Object.entries(estimate).map(([key, value]) => [key, value.toString()])
      ),
      maximumTotalFeeWei: parsed.maximumTotalFeeWei.toString(),
      actionValueWei: "0",
      paymasterAndData: "0x",
      factoryDataPresent: false,
      submissionAttemptsAllowed: 1
    },
    maximumAdditionalFundingWei: "0",
    maximumPrefundedUserOperationCostWei: parsed.maximumTotalFeeWei.toString(),
    mutations: [{
      order: 1,
      kind: p3Mode
        ? "SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_1_V07_USER_OPERATION"
        : "SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_0_V07_USER_OPERATION",
      userOperationHash: signedArtifact.userOperationHash,
      target: config.entryPoint,
      valueWei: "0"
    }],
    publicMutationCount: 1,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    stopConditions: [
      "source_or_review_identity_changed",
      p3Mode ? "p2_final_evidence_changed" : "account_deployment_evidence_changed",
      "provider_disagreement",
      "account_code_balance_deposit_nonce_or_binding_changed",
      "user_operation_found_or_replay_field_consumed",
      "bundler_estimate_exceeds_signed_cap",
      "fee_cap_stale_or_expiry_too_close",
      "durable_execution_attempt_lock_already_exists"
    ],
    approval: { requiredPhrase: null, approved: false }
  };
  const planDigest = common.canonicalSha256(body);
  body.approval.requiredPhrase = common.approvalPhrase(p3Mode ? "P3" : "P2F", planDigest);
  const plan = { ...body, planDigest };
  common.atomicCreateJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    mutationCount: plan.publicMutationCount,
    maximumAdditionalFundingWei: plan.maximumAdditionalFundingWei,
    maximumPrefundedUserOperationCostWei: plan.maximumPrefundedUserOperationCostWei,
    userOperationHash: plan.userOperation.hash,
    validUntil: plan.userOperation.validUntil,
    outputPath,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || String(error)}\n`);
  process.exitCode = 1;
});
