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
  const review = {
    reviewedCommit: common.required("PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_COMMIT"),
    reviewedTree: common.required("PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_TREE"),
    reportSha256: common.required("PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_SHA256").toLowerCase(),
    disposition: common.required("PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_DISPOSITION")
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_INVALID");
  }
  return review;
}

async function main() {
  const outputPath = argument("--output", common.DEFAULT_PLAN_PATH);
  const signedArtifactPath = argument("--signed-artifact", common.DEFAULT_SIGNED_ARTIFACT_PATH);
  const source = common.sourceIdentity();
  const runnerReview = acceptedReview(source);
  if (fs.existsSync(outputPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_PLAN_ALREADY_EXISTS_REQUIRES_ARCHIVE");
  }
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const signedArtifactBytes = fs.readFileSync(signedArtifactPath);
  const signedArtifact = JSON.parse(signedArtifactBytes);
  const compiled = common.artifacts();
  const parsed = common.parseSignedArtifact(signedArtifact, config, compiled);

  const now = BigInt(Math.floor(Date.now() / 1000));
  if (parsed.validUntil <= now + 300n) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_AUTHORIZATION_WINDOW_TOO_SHORT");
  }
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (common.endpointDigest(primaryUrl) === common.endpointDigest(reconciliationUrl)) {
    common.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported)
    || !supported.some((value) => common.sameAddress(value, common.ENTRY_POINT))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }
  await common.assertProviderPair(primary, reconciliation, config, signedArtifact);
  const estimate = common.normalizeEstimate(await bundler.send(
    "eth_estimateUserOperationGas",
    [parsed.rpc, common.ENTRY_POINT]
  ));
  common.assertEstimateWithinSignedCaps(estimate, parsed);

  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > parsed.gas.maxFeePerGas
    || feeData.maxPriorityFeePerGas > parsed.gas.maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_SIGNED_FEE_CAP_STALE");
  }
  const [deployerNonceLeft, deployerNonceRight, deployerBalanceLeft, deployerBalanceRight] = await Promise.all([
    primary.getTransactionCount(config.deployer, "pending"),
    reconciliation.getTransactionCount(config.deployer, "pending"),
    primary.getBalance(config.deployer),
    reconciliation.getBalance(config.deployer)
  ]);
  if (deployerNonceLeft !== 3 || deployerNonceRight !== 3
    || deployerBalanceLeft !== deployerBalanceRight) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_DEPLOYER_STATE_INVALID");
  }
  const fundingValueWei = parsed.maximumTotalFeeWei;
  if (fundingValueWei <= 0n
    || fundingValueWei > BigInt(config.maximumNativeAccountBalanceWei)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FUNDING_VALUE_INVALID");
  }
  const fundingGasEstimate = await primary.estimateGas({
    from: config.deployer,
    to: config.account.predictedAddress,
    nonce: deployerNonceLeft,
    value: fundingValueWei
  });
  const fundingGasLimit = fundingGasEstimate * 125n / 100n;
  const fundingMaxFeePerGas = parsed.gas.maxFeePerGas;
  const fundingMaxPriorityFeePerGas = parsed.gas.maxPriorityFeePerGas;
  const maximumStageCostWei = fundingValueWei + fundingGasLimit * fundingMaxFeePerGas;
  if (maximumStageCostWei > BigInt(config.maximumOperatorExposureWei)
    || deployerBalanceLeft < maximumStageCostWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_OPERATOR_EXPOSURE_INVALID");
  }
  const endpointBindings = {
    primaryRpcUrlSha256: common.endpointDigest(primaryUrl),
    reconciliationRpcUrlSha256: common.endpointDigest(reconciliationUrl),
    bundlerUrlSha256: common.endpointDigest(bundlerUrl)
  };
  const body = {
    format: "philcore-controlled-sepolia-beta-p2-plan-v1",
    version: 1,
    stageId: "P2",
    status: "EXACT_P2_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
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
      deployer: config.deployer,
      initialExecutionValidator: config.account.initialExecutionValidator,
      initialRecoveryAuthority: config.account.initialRecoveryAuthority
    },
    account: {
      predictedAddress: config.account.predictedAddress,
      ownerCommitment: config.account.ownerCommitment,
      salt: config.account.salt,
      startingNonce: "0",
      startingNativeBalanceWei: "0",
      startingEntryPointDepositWei: "0"
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
      submissionAttemptsAllowed: 1
    },
    funding: {
      source: config.deployer,
      nonce: String(deployerNonceLeft),
      recipient: config.account.predictedAddress,
      valueWei: fundingValueWei.toString(),
      gasEstimate: fundingGasEstimate.toString(),
      gasLimit: fundingGasLimit.toString(),
      maxFeePerGas: fundingMaxFeePerGas.toString(),
      maxPriorityFeePerGas: fundingMaxPriorityFeePerGas.toString(),
      transactionHash: null
    },
    maximumStageCostWei: maximumStageCostWei.toString(),
    maximumOperatorExposureWei: config.maximumOperatorExposureWei,
    mutations: [],
    publicMutationCount: common.P2_MUTATION_COUNT,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    stopConditions: [
      "source_or_review_identity_changed",
      "provider_or_endpoint_disagreement",
      "p1_binding_or_runtime_changed",
      "account_code_balance_deposit_or_nonce_changed",
      "replay_field_consumed",
      "bundler_estimate_exceeds_signed_cap",
      "fee_cap_stale_or_expiry_too_close",
      "funding_receipt_or_user_operation_receipt_ambiguous",
      "durable_execution_attempt_lock_already_exists"
    ],
    approval: { requiredPhrase: null, approved: false }
  };
  const fundingWallet = common.walletFromKeychain(
    metadata.keychainServices.deployer,
    config.deployer
  );
  const signedFunding = await common.signFundingTransaction(body, fundingWallet);
  body.funding.transactionHash = signedFunding.hash;
  body.mutations = [
    {
      order: 1,
      kind: "FUND_COUNTERFACTUAL_BETA_ACCOUNT",
      transactionHash: signedFunding.hash,
      target: config.account.predictedAddress,
      valueWei: fundingValueWei.toString()
    },
    {
      order: 2,
      kind: "SUBMIT_NONCE_0_V07_USER_OPERATION",
      userOperationHash: signedArtifact.userOperationHash,
      target: config.entryPoint,
      valueWei: "0"
    }
  ];
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  const planDigest = common.canonicalSha256(digestBody);
  body.approval.requiredPhrase = common.approvalPhrase("P2", planDigest);
  const plan = { ...body, planDigest };
  common.atomicCreateJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({
    status: plan.status,
    stageId: plan.stageId,
    planDigest,
    requiredApproval: plan.approval.requiredPhrase,
    mutationCount: plan.publicMutationCount,
    fundingValueWei: plan.funding.valueWei,
    maximumStageCostWei: plan.maximumStageCostWei,
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
