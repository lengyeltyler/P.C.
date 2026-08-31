"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) {
    common.fail(`PHILCORE_CONTROLLED_BETA_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  }
  return process.argv[index + 1];
}

function acceptedReview(source) {
  const review = {
    reviewedCommit: common.required("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_COMMIT"),
    reviewedTree: common.required("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_TREE"),
    reportSha256: common.required(
      "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_SHA256"
    ).toLowerCase(),
    disposition: common.required(
      "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_DISPOSITION"
    )
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_INVALID");
  }
  return review;
}

async function main() {
  const outputPath = argument("--output", common.DEFAULT_RECOVERY_PLAN_PATH);
  const signedArtifactPath = argument(
    "--signed-artifact", common.DEFAULT_RECOVERY_SIGNED_ARTIFACT_PATH
  );
  const source = common.sourceIdentity();
  const runnerReview = acceptedReview(source);
  if (fs.existsSync(outputPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_PLAN_ALREADY_EXISTS_REQUIRES_ARCHIVE");
  }

  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const signedArtifactBytes = fs.readFileSync(signedArtifactPath);
  const signedArtifact = JSON.parse(signedArtifactBytes);
  const parsed = common.parseSignedArtifact(signedArtifact, config, common.artifacts());
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (parsed.validUntil <= now + 300n) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_AUTHORIZATION_WINDOW_TOO_SHORT");
  }

  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (common.endpointDigest(primaryUrl) === common.endpointDigest(reconciliationUrl)) {
    common.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(
    primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(
    bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported)
    || !supported.some((value) => common.sameAddress(value, common.ENTRY_POINT))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }

  const state = await common.assertProviderPair(
    primary, reconciliation, config, signedArtifact, { expectUnfunded: false }
  );
  const [nextReceipt, nextOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [signedArtifact.userOperationHash]),
    bundler.send("eth_getUserOperationByHash", [signedArtifact.userOperationHash])
  ]);
  if (state.accountBalanceWei !== common.P2_RECOVERY_ORIGIN.confirmedFundingValueWei
    || nextReceipt !== null || nextOperation !== null) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_USER_OPERATION_STATE_INVALID");
  }
  const originLive = await common.assertP2RecoveryOriginLive(
    primary, reconciliation, bundler, config
  );

  const estimate = common.normalizeEstimate(await bundler.send(
    "eth_estimateUserOperationGas", [parsed.rpc, common.ENTRY_POINT]
  ));
  common.assertEstimateWithinSignedCaps(estimate, parsed);
  if (parsed.gas.maxPriorityFeePerGas < common.MINIMUM_BUNDLER_PRIORITY_FEE_WEI) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_PRIORITY_FEE_BELOW_BUNDLER_FLOOR");
  }
  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > parsed.gas.maxFeePerGas
    || feeData.maxPriorityFeePerGas > parsed.gas.maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_SIGNED_FEE_CAP_STALE");
  }
  const [nonceLeft, nonceRight] = await Promise.all([
    primary.getTransactionCount(config.deployer, "pending"),
    reconciliation.getTransactionCount(config.deployer, "pending")
  ]);
  if (nonceLeft !== 4 || nonceRight !== 4
    || BigInt(state.accountBalanceWei) < parsed.maximumTotalFeeWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_PREFUNDED_STATE_INVALID");
  }

  const endpointBindings = {
    primaryRpcUrlSha256: common.endpointDigest(primaryUrl),
    reconciliationRpcUrlSha256: common.endpointDigest(reconciliationUrl),
    bundlerUrlSha256: common.endpointDigest(bundlerUrl)
  };
  const body = {
    format: "philcore-controlled-sepolia-beta-p2-recovery-plan-v1",
    version: 1,
    stageId: "P2R",
    status: "EXACT_P2_RECOVERY_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
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
    runtimeCodeHashes: config.runtimeCodeHashes,
    authorities: {
      initialExecutionValidator: config.account.initialExecutionValidator,
      initialRecoveryAuthority: config.account.initialRecoveryAuthority
    },
    account: {
      predictedAddress: config.account.predictedAddress,
      ownerCommitment: config.account.ownerCommitment,
      salt: config.account.salt,
      startingNonce: "0",
      startingNativeBalanceWei: state.accountBalanceWei,
      startingEntryPointDepositWei: "0",
      deployed: false
    },
    recoveryOrigin: {
      ...common.P2_RECOVERY_ORIGIN,
      originalLocalGeneratedArtifactsAvailable: false,
      originalEvidenceBoundary:
        "owner_approved_digest_and_incident_transcript_plus_live_two_provider_reconciliation",
      rejectedUserOperationAbsentFromBundler: true,
      originalReplayFieldsUnusedOnChain: true,
      fundingReceiptConfirmedByBothProviders: true,
      fundingBlockHash: originLive.fundingBlockHash
    },
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
      factoryDataPresent: true,
      maxPriorityFeePerGas: parsed.gas.maxPriorityFeePerGas.toString(),
      submissionAttemptsAllowed: 1
    },
    maximumAdditionalFundingWei: "0",
    maximumPrefundedUserOperationCostWei: parsed.maximumTotalFeeWei.toString(),
    mutations: [{
      order: 1,
      kind: "SUBMIT_RECOVERY_NONCE_0_V07_USER_OPERATION",
      userOperationHash: signedArtifact.userOperationHash,
      target: config.entryPoint,
      valueWei: "0"
    }],
    publicMutationCount: common.P2_RECOVERY_MUTATION_COUNT,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    stopConditions: [
      "source_or_review_identity_changed",
      "approved_origin_constants_or_live_incident_state_changed",
      "provider_endpoint_or_funding_receipt_disagreement",
      "account_code_balance_deposit_or_nonce_changed",
      "prior_or_recovery_user_operation_found",
      "replay_field_consumed",
      "bundler_estimate_exceeds_signed_cap",
      "priority_fee_below_bundler_floor",
      "fee_cap_stale_or_expiry_too_close",
      "durable_recovery_execution_attempt_lock_already_exists"
    ],
    approval: { requiredPhrase: null, approved: false }
  };
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  const planDigest = common.canonicalSha256(digestBody);
  body.approval.requiredPhrase = common.approvalPhrase("P2R", planDigest);
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
