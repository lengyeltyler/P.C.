"use strict";

const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p1-common.cjs");

let receiptPath = common.DEFAULT_RECEIPT_PATH;
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

function sameAddress(left, right) {
  return ethers.getAddress(left).toLowerCase() === ethers.getAddress(right).toLowerCase();
}

function assertPlanDigest(plan, approvedDigest) {
  const { planDigest, ...body } = plan;
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  if (plan?.format !== "philcore-controlled-sepolia-beta-p1-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P1"
    || plan.status !== "EXACT_P1_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.approval?.approved !== false
    || common.canonicalSha256(digestBody).toLowerCase() !== String(planDigest).toLowerCase()
    || String(planDigest).toLowerCase() !== approvedDigest.toLowerCase()
    || plan.approval.requiredPhrase !== common.approvalPhrase("P1", planDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_PLAN_DIGEST_INVALID");
  }
}

function assertExactPlanShape(plan) {
  const labels = [
    "FUND_BETA_DEPLOYER_FROM_LEGACY_ALPHA_SOURCE",
    "DEPLOY_PhilSepoliaMintPassConsumerV1",
    "DEPLOY_PhilSepoliaLocalComposedActionGateV1",
    "DEPLOY_PhilCore4337AccountFactory"
  ];
  if (plan.chainId !== String(common.CHAIN_ID)
    || plan.entryPoint.toLowerCase() !== common.ENTRY_POINT.toLowerCase()
    || plan.publicMutationCount !== common.P1_MUTATION_COUNT
    || !Array.isArray(plan.deployments) || plan.deployments.length !== 3
    || !Array.isArray(plan.mutations) || plan.mutations.length !== common.P1_MUTATION_COUNT
    || plan.mutations.some((mutation, index) => mutation.order !== index + 1 || mutation.kind !== labels[index])) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_MUTATION_SEQUENCE_INVALID");
  }
  if (plan.runnerReview?.reviewedCommit !== plan.source?.commit
    || plan.runnerReview?.reviewedTree !== plan.source?.tree
    || !/^0x[0-9a-f]{64}$/u.test(plan.runnerReview?.reportSha256 || "")
    || plan.runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_INVALID");
  }
  if (!sameAddress(plan.fundingSource, common.LEGACY_ALPHA_FUNDING_SOURCE)
    || plan.funding.nonce !== plan.startingNonces.fundingSource
    || plan.deployments.some((deployment, index) => (
      deployment.nonce !== String(Number(plan.startingNonces.deployer) + index)
    ))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_NONCE_OR_FUNDING_SOURCE_INVALID");
  }
  if (!sameAddress(plan.mutations[0].target, plan.deployer)
    || sameAddress(plan.fundingSource, plan.deployer)
    || !sameAddress(plan.funding.recipient, plan.deployer)
    || plan.mutations[0].valueWei !== plan.funding.valueWei
    || plan.funding.transactionHash.toLowerCase() !== plan.mutations[0].transactionHash.toLowerCase()
    || plan.deployments.some((deployment, index) => (
      deployment.transactionHash.toLowerCase() !== plan.mutations[index + 1].transactionHash.toLowerCase()
      || !sameAddress(deployment.expectedContractAddress, plan.mutations[index + 1].target)
    ))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_TRANSACTION_BINDING_INVALID");
  }
  const deploymentFees = plan.deployments.reduce(
    (total, deployment) => total + BigInt(deployment.gasLimit) * BigInt(plan.feePolicy.maxFeePerGas),
    0n
  );
  const total = deploymentFees + BigInt(plan.funding.gasLimit) * BigInt(plan.feePolicy.maxFeePerGas);
  if (BigInt(plan.funding.valueWei) !== deploymentFees
    || BigInt(plan.maximumStageCostWei) !== total
    || total > BigInt(plan.maximumOperatorExposureWei)
    || BigInt(plan.maximumOperatorExposureWei) !== ethers.parseEther("0.05")) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_EXPOSURE_INVALID");
  }
}

async function assertProvidersAgree(primary, reconciliation, plan) {
  const [primaryChain, reconciliationChain] = await Promise.all([
    primary.send("eth_chainId", []),
    reconciliation.send("eth_chainId", [])
  ]);
  if (BigInt(primaryChain) !== BigInt(common.CHAIN_ID)
    || BigInt(reconciliationChain) !== BigInt(common.CHAIN_ID)) {
    common.fail("PHILCORE_CONTROLLED_BETA_WRONG_CHAIN");
  }
  const [primaryEntryPoint, reconciliationEntryPoint] = await Promise.all([
    primary.getCode(common.ENTRY_POINT),
    reconciliation.getCode(common.ENTRY_POINT)
  ]);
  if (primaryEntryPoint.toLowerCase() !== reconciliationEntryPoint.toLowerCase()
    || ethers.keccak256(primaryEntryPoint).toLowerCase() !== plan.entryPointCodeHash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_ENTRYPOINT_OR_PROVIDER_CHANGED");
  }
  for (const [address, expectedNonce] of [
    [plan.fundingSource, plan.startingNonces.fundingSource],
    [plan.deployer, plan.startingNonces.deployer]
  ]) {
    const [left, right] = await Promise.all([
      primary.getTransactionCount(address, "pending"),
      reconciliation.getTransactionCount(address, "pending")
    ]);
    if (left !== right || left !== Number(expectedNonce)) {
      common.fail("PHILCORE_CONTROLLED_BETA_NONCE_OR_PROVIDER_CHANGED");
    }
  }
  for (const address of Object.values(plan.contracts)) {
    const [left, right] = await Promise.all([primary.getCode(address), reconciliation.getCode(address)]);
    if (left !== "0x" || right !== "0x") common.fail("PHILCORE_CONTROLLED_BETA_PREDICTED_ADDRESS_CHANGED");
  }
  const [fundingBalanceLeft, fundingBalanceRight, deployerBalanceLeft, deployerBalanceRight] = await Promise.all([
    primary.getBalance(plan.fundingSource),
    reconciliation.getBalance(plan.fundingSource),
    primary.getBalance(plan.deployer),
    reconciliation.getBalance(plan.deployer)
  ]);
  if (fundingBalanceLeft !== fundingBalanceRight
    || deployerBalanceLeft !== deployerBalanceRight
    || fundingBalanceLeft < BigInt(plan.maximumStageCostWei)
    || deployerBalanceLeft !== 0n) {
    common.fail("PHILCORE_CONTROLLED_BETA_BALANCE_OR_PROVIDER_CHANGED");
  }
}

async function reconcileReceipt(provider, transactionHash, deadlineMs = 60_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const receipt = await provider.getTransactionReceipt(transactionHash);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  common.fail("PHILCORE_CONTROLLED_BETA_P1_RECEIPT_AMBIGUOUS");
}

async function verifyBindings(provider, plan, compiled) {
  const consumer = new ethers.Contract(plan.contracts.consumer, compiled.consumer.abi, provider);
  const gate = new ethers.Contract(plan.contracts.gate, compiled.gate.abi, provider);
  const factory = new ethers.Contract(plan.contracts.factory, compiled.factory.abi, provider);
  const values = await Promise.all([
    consumer.actionGate(),
    gate.expectedChainId(),
    gate.accountFactory(),
    gate.mintConsumer(),
    gate.authorizedAccount(),
    factory.entryPoint(),
    factory.approvedActionGate(),
    factory.recoveryAuthority(),
    factory.recoveryDelaySeconds(),
    factory.recoveryExpirySeconds(),
    factory["getAddress(address,bytes32,uint256)"](
      plan.authorities.initialExecutionValidator,
      plan.account.ownerCommitment,
      plan.account.salt
    )
  ]);
  if (!sameAddress(values[0], plan.contracts.gate)
    || values[1] !== BigInt(common.CHAIN_ID)
    || !sameAddress(values[2], plan.contracts.factory)
    || !sameAddress(values[3], plan.contracts.consumer)
    || !sameAddress(values[4], plan.account.predictedAddress)
    || !sameAddress(values[5], common.ENTRY_POINT)
    || !sameAddress(values[6], plan.contracts.gate)
    || !sameAddress(values[7], plan.authorities.initialRecoveryAuthority)
    || values[8] !== common.RECOVERY_DELAY_SECONDS
    || values[9] !== common.RECOVERY_EXPIRY_SECONDS
    || !sameAddress(values[10], plan.account.predictedAddress)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_CONSTRUCTOR_BINDING_INVALID");
  }
}

async function main() {
  const approvedDigest = argument("--plan-digest");
  if (!approvedDigest || !/^0x[0-9a-f]{64}$/iu.test(approvedDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_EXPLICIT_PLAN_DIGEST_REQUIRED");
  }
  const suppliedApproval = common.required("PHILCORE_CONTROLLED_BETA_P1_APPROVAL");
  const requiredApproval = common.approvalPhrase("P1", approvedDigest.toLowerCase());
  if (suppliedApproval !== requiredApproval) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_EXACT_APPROVAL_REQUIRED");
  }

  // Plan, endpoint, network, and Keychain access are intentionally unreachable
  // until the exact digest-specific owner approval above has matched.
  const planPath = argument("--plan", common.DEFAULT_PLAN_PATH);
  receiptPath = argument("--receipt-output", common.DEFAULT_RECEIPT_PATH);
  const plan = common.readJson(planPath);
  assertPlanDigest(plan, approvedDigest);
  assertExactPlanShape(plan);
  if (!common.sourceIdentityMatches(plan.source)) common.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");

  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  if (!sameAddress(metadata.addresses.deployer, plan.deployer)
    || !sameAddress(metadata.addresses.initialExecutionValidator, plan.authorities.initialExecutionValidator)
    || !sameAddress(metadata.addresses.initialRecoveryAuthority, plan.authorities.initialRecoveryAuthority)
    || metadata.ownerCommitment.toLowerCase() !== plan.account.ownerCommitment.toLowerCase()
    || metadata.accountSalt.toLowerCase() !== plan.account.salt.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_CHANGED");
  }
  if (Object.values(metadata.addresses).some((address) => sameAddress(address, plan.fundingSource))) {
    common.fail("PHILCORE_CONTROLLED_BETA_FUNDING_AUTHORITY_SEPARATION_INVALID");
  }
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  common.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, { staticNetwork: true });
  const reconciliation = new ethers.JsonRpcProvider(reconciliationUrl, common.CHAIN_ID, { staticNetwork: true });
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, { staticNetwork: true });
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported)
    || !supported.some((value) => value.toLowerCase() === common.ENTRY_POINT.toLowerCase())) {
    common.fail("PHILCORE_CONTROLLED_BETA_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }
  await assertProvidersAgree(primary, reconciliation, plan);
  const liveFee = await primary.getFeeData();
  if ((liveFee.maxFeePerGas && liveFee.maxFeePerGas > BigInt(plan.feePolicy.maxFeePerGas))
    || (liveFee.maxPriorityFeePerGas
      && liveFee.maxPriorityFeePerGas > BigInt(plan.feePolicy.maxPriorityFeePerGas))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_FEE_CAP_STALE");
  }

  const compiled = common.artifacts();
  if (common.canonicalJson(common.compilerIdentity()) !== common.canonicalJson(plan.compiler)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_COMPILER_IDENTITY_CHANGED");
  }
  const graph = common.deploymentGraph({
    compiled,
    deployer: plan.deployer,
    startingNonce: Number(plan.startingNonces.deployer),
    executionOwner: plan.authorities.initialExecutionValidator,
    recoveryAuthority: plan.authorities.initialRecoveryAuthority,
    ownerCommitment: plan.account.ownerCommitment,
    accountSalt: plan.account.salt
  });
  if (common.canonicalJson(graph) !== common.canonicalJson(plan.contracts)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_DEPLOYMENT_GRAPH_CHANGED");
  }
  const regenerated = await common.deploymentDescriptors({
    compiled,
    graph,
    deployer: plan.deployer,
    startingNonce: Number(plan.startingNonces.deployer),
    provider: primary,
    recoveryAuthority: plan.authorities.initialRecoveryAuthority
  });
  for (let index = 0; index < regenerated.length; index += 1) {
    const current = regenerated[index];
    const frozen = plan.deployments[index];
    if (current.label !== frozen.label
      || current.data !== frozen.data
      || current.deploymentDataHash !== frozen.deploymentDataHash
      || current.expectedRuntimeCodeHash !== frozen.expectedRuntimeCodeHash
      || !sameAddress(current.expectedContractAddress, frozen.expectedContractAddress)
      || BigInt(current.gasEstimate) > BigInt(frozen.gasLimit)) {
      common.fail("PHILCORE_CONTROLLED_BETA_P1_DEPLOYMENT_CHANGED");
    }
  }
  const currentFundingGas = await primary.estimateGas({
    from: plan.fundingSource,
    to: plan.funding.recipient,
    nonce: Number(plan.funding.nonce),
    value: BigInt(plan.funding.valueWei)
  });
  if (currentFundingGas > BigInt(plan.funding.gasLimit)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P1_FUNDING_GAS_STALE");
  }

  const fundingWallet = common.walletFromKeychain(
    common.required("PHILCORE_CONTROLLED_BETA_FUNDING_KEYCHAIN_SERVICE"),
    plan.fundingSource
  );
  const deployerWallet = common.walletFromKeychain(metadata.keychainServices.deployer, plan.deployer);
  const transactions = await common.signedP1Transactions(plan, fundingWallet, deployerWallet);
  if (transactions.length !== common.P1_MUTATION_COUNT) common.fail("PHILCORE_CONTROLLED_BETA_P1_TRANSACTION_COUNT_INVALID");

  // No public mutation is reachable above this line. Persist before the first
  // and every subsequent exact one-shot broadcast. Automatic retry is forbidden.
  evidence = {
    format: "philcore-controlled-sepolia-beta-p1-receipt-v1",
    version: 1,
    stageId: "P1",
    status: "APPROVAL_VERIFIED_EXECUTION_STARTING",
    planDigest: plan.planDigest,
    source: plan.source,
    chainId: plan.chainId,
    endpoints: plan.endpoints,
    approval: { phraseMatched: true, planDigestMatched: true, verifiedAt: new Date().toISOString() },
    mutations: [],
    publicMutationOccurred: false,
    automaticRetryOccurred: false
  };
  persist();

  for (let index = 0; index < transactions.length; index += 1) {
    const transaction = transactions[index];
    const mutation = plan.mutations[index];
    evidence.status = `MUTATION_${index + 1}_SUBMISSION_REQUESTED`;
    evidence.publicMutationOccurred = true;
    evidence.mutations.push({
      order: index + 1,
      kind: mutation.kind,
      transactionHash: transaction.hash,
      status: "submission_requested"
    });
    persist();
    const response = await primary.broadcastTransaction(transaction.raw);
    if (response.hash.toLowerCase() !== transaction.hash.toLowerCase()) {
      common.fail("PHILCORE_CONTROLLED_BETA_P1_BROADCAST_HASH_CHANGED");
    }
    const primaryReceipt = await response.wait(1, 180_000);
    if (!primaryReceipt || primaryReceipt.status !== 1) common.fail("PHILCORE_CONTROLLED_BETA_P1_RECEIPT_INVALID");
    const reconciliationReceipt = await reconcileReceipt(reconciliation, transaction.hash);
    if (reconciliationReceipt.status !== 1
      || reconciliationReceipt.blockHash.toLowerCase() !== primaryReceipt.blockHash.toLowerCase()) {
      common.fail("PHILCORE_CONTROLLED_BETA_P1_RECEIPT_PROVIDER_DISAGREEMENT");
    }
    const record = {
      order: index + 1,
      kind: mutation.kind,
      transactionHash: primaryReceipt.hash,
      blockNumber: String(primaryReceipt.blockNumber),
      gasUsed: primaryReceipt.gasUsed.toString(),
      status: "confirmed_by_both_providers"
    };
    if (index > 0) {
      if (!primaryReceipt.contractAddress
        || !sameAddress(primaryReceipt.contractAddress, plan.deployments[index - 1].expectedContractAddress)) {
        common.fail("PHILCORE_CONTROLLED_BETA_P1_CONTRACT_ADDRESS_INVALID");
      }
      const [leftCode, rightCode] = await Promise.all([
        primary.getCode(primaryReceipt.contractAddress),
        reconciliation.getCode(primaryReceipt.contractAddress)
      ]);
      const expectedHash = plan.deployments[index - 1].expectedRuntimeCodeHash.toLowerCase();
      if (ethers.keccak256(leftCode).toLowerCase() !== expectedHash
        || ethers.keccak256(rightCode).toLowerCase() !== expectedHash) {
        common.fail("PHILCORE_CONTROLLED_BETA_P1_RUNTIME_CODE_INVALID");
      }
      record.contractAddress = primaryReceipt.contractAddress;
      record.runtimeCodeHash = expectedHash;
    }
    evidence.mutations[index] = record;
    persist();
  }

  await verifyBindings(primary, plan, compiled);
  await verifyBindings(reconciliation, plan, compiled);
  evidence.status = "P1_INFRASTRUCTURE_DEPLOYMENT_CONFIRMED";
  evidence.completedAt = new Date().toISOString();
  evidence.constructorBindingsVerifiedByBothProviders = true;
  persist();
  process.stdout.write(`${JSON.stringify({
    status: evidence.status,
    planDigest: plan.planDigest,
    receiptPath,
    mutations: evidence.mutations,
    constructorBindingsVerifiedByBothProviders: true
  }, null, 2)}\n`);
}

main().catch((error) => {
  if (evidence) {
    evidence.status = "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION";
    evidence.stoppedAt = new Date().toISOString();
    evidence.failureCode = error?.code || error?.message || "PHILCORE_CONTROLLED_BETA_P1_EXECUTION_FAILED";
    evidence.automaticRetryOccurred = false;
    persist();
  }
  process.stderr.write(`${error?.code || error?.message || "PHILCORE_CONTROLLED_BETA_P1_EXECUTION_FAILED"}\n`);
  process.exitCode = 1;
});
