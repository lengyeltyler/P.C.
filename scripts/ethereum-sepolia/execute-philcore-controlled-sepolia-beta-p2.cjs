"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

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

function assertPlanDigest(plan, approvedDigest) {
  const { planDigest, ...body } = plan;
  const digestBody = { ...body, approval: { requiredPhrase: null, approved: false } };
  if (plan?.format !== "philcore-controlled-sepolia-beta-p2-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P2"
    || plan.status !== "EXACT_P2_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.approval?.approved !== false
    || common.canonicalSha256(digestBody).toLowerCase() !== String(planDigest).toLowerCase()
    || String(planDigest).toLowerCase() !== approvedDigest.toLowerCase()
    || plan.approval.requiredPhrase !== common.approvalPhrase("P2", planDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_PLAN_DIGEST_INVALID");
  }
}

function signedArtifactFromPlan(plan) {
  return Object.freeze({
    format: plan.composition.format,
    authorizationEnvelopeDigest: plan.composition.authorizationEnvelopeDigest,
    rootProofNullifier: plan.composition.rootProofNullifier,
    deviceApprovalNonce: plan.composition.deviceApprovalNonce,
    accountNonce: plan.account.startingNonce,
    userOperationHash: plan.userOperation.hash,
    userOperation: plan.userOperation.packed,
    smartAccount: common.canonicalSignedArtifactAddress(plan.account.predictedAddress),
    actionGate: common.canonicalSignedArtifactAddress(plan.contracts.gate),
    maximumTotalFeeWei: plan.userOperation.maximumTotalFeeWei,
    signed: true,
    submitted: false,
    ethereumVerifiesNoirProof: false,
    ethereumVerifiesP256Approval: false,
    phoneAssurance: plan.composition.phoneAssurance
  });
}

function assertExactPlanShape(plan, config, parsed) {
  const expectedLabels = [
    "FUND_COUNTERFACTUAL_BETA_ACCOUNT",
    "SUBMIT_NONCE_0_V07_USER_OPERATION"
  ];
  if (plan.chainId !== String(common.CHAIN_ID)
    || !common.sameAddress(plan.entryPoint, common.ENTRY_POINT)
    || plan.publicMutationCount !== common.P2_MUTATION_COUNT
    || !Array.isArray(plan.mutations) || plan.mutations.length !== common.P2_MUTATION_COUNT
    || plan.mutations.some((mutation, index) => (
      mutation.order !== index + 1 || mutation.kind !== expectedLabels[index]
    ))
    || plan.runnerReview?.reviewedCommit !== plan.source?.commit
    || plan.runnerReview?.reviewedTree !== plan.source?.tree
    || !/^0x[0-9a-f]{64}$/u.test(plan.runnerReview?.reportSha256 || "")
    || plan.runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    || !common.sameAddress(plan.contracts.consumer, config.infrastructure.mintConsumer)
    || !common.sameAddress(plan.contracts.gate, config.infrastructure.actionGate)
    || !common.sameAddress(plan.contracts.factory, config.infrastructure.factory)
    || !common.sameAddress(plan.contracts.account, config.account.predictedAddress)
    || common.canonicalJson(plan.runtimeCodeHashes) !== common.canonicalJson(config.runtimeCodeHashes)
    || !common.sameAddress(plan.funding.source, config.deployer)
    || plan.funding.nonce !== "3"
    || !common.sameAddress(plan.funding.recipient, config.account.predictedAddress)
    || plan.funding.valueWei !== parsed.maximumTotalFeeWei.toString()
    || plan.funding.transactionHash.toLowerCase() !== plan.mutations[0].transactionHash.toLowerCase()
    || plan.userOperation.hash.toLowerCase() !== plan.mutations[1].userOperationHash.toLowerCase()
    || !common.sameAddress(plan.mutations[0].target, config.account.predictedAddress)
    || !common.sameAddress(plan.mutations[1].target, config.entryPoint)
    || plan.userOperation.actionValueWei !== "0"
    || plan.userOperation.paymasterAndData !== "0x"
    || plan.userOperation.factoryDataPresent !== true
    || plan.userOperation.submissionAttemptsAllowed !== 1
    || plan.composition.proofAndPhoneP256PossessionApprovalCompleted !== true
    || common.canonicalJson(plan.composition.phoneAssurance)
      !== common.canonicalJson(config.phoneAssurance)
    || plan.composition.localCompositionRequiredBeforeDeviceVaultRelease !== true
    || plan.composition.ethereumVerifiesNoirProof !== false
    || plan.composition.ethereumVerifiesP256Approval !== false) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_PLAN_SHAPE_INVALID");
  }
  const maximum = BigInt(plan.funding.valueWei)
    + BigInt(plan.funding.gasLimit) * BigInt(plan.funding.maxFeePerGas);
  if (maximum !== BigInt(plan.maximumStageCostWei)
    || maximum > BigInt(plan.maximumOperatorExposureWei)
    || BigInt(plan.maximumOperatorExposureWei) !== ethers.parseEther("0.05")) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_EXPOSURE_INVALID");
  }
}

async function receiptByBoth(primary, reconciliation, hash, deadlineMs = 90_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const [left, right] = await Promise.all([
      primary.getTransactionReceipt(hash), reconciliation.getTransactionReceipt(hash)
    ]);
    if (left && right) {
      if (left.hash.toLowerCase() !== right.hash.toLowerCase()
        || left.blockHash.toLowerCase() !== right.blockHash.toLowerCase()
        || left.status !== right.status) {
        common.fail("PHILCORE_CONTROLLED_BETA_P2_PROVIDER_RECEIPT_DISAGREEMENT");
      }
      return left;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  common.fail("PHILCORE_CONTROLLED_BETA_P2_TRANSACTION_RECEIPT_AMBIGUOUS");
}

async function userOperationReceipt(bundler, hash, deadlineMs = 120_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const result = await bundler.send("eth_getUserOperationReceipt", [hash]);
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  common.fail("PHILCORE_CONTROLLED_BETA_P2_USER_OPERATION_RECEIPT_AMBIGUOUS");
}

function findEvent(receipt, contractAddress, iface, eventName) {
  const matches = [];
  for (const log of receipt.logs || []) {
    if (!common.sameAddress(log.address, contractAddress)) continue;
    try {
      const parsed = iface.parseLog({ topics: log.topics, data: log.data });
      if (parsed?.name === eventName) matches.push(parsed);
    } catch {}
  }
  if (matches.length !== 1) common.fail(`PHILCORE_CONTROLLED_BETA_P2_${eventName.toUpperCase()}_EVENT_INVALID`);
  return matches[0];
}

async function verifyFinalState(primary, reconciliation, plan, transactionReceipt) {
  const providers = [primary, reconciliation];
  const snapshots = [];
  for (const provider of providers) {
    const accountCode = await provider.getCode(plan.account.predictedAddress);
    if (accountCode === "0x") common.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_NOT_DEPLOYED");
    const account = new ethers.Contract(plan.account.predictedAddress, common.accountInterface, provider);
    const factory = new ethers.Contract(plan.contracts.factory, common.factoryInterface, provider);
    const gate = new ethers.Contract(plan.contracts.gate, common.gateInterface, provider);
    const consumer = new ethers.Contract(plan.contracts.consumer, common.consumerInterface, provider);
    const entry = new ethers.Contract(plan.entryPoint, common.entryPointInterface, provider);
    const values = await Promise.all([
      account.owner(), account.ownerCommitment(), account.approvedActionGate(),
      account.recoveryAuthority(), account.entryPoint(),
      factory.isPhilSepoliaMintAccount(plan.account.predictedAddress),
      entry.getNonce(plan.account.predictedAddress, 0),
      entry.balanceOf(plan.account.predictedAddress),
      provider.getBalance(plan.account.predictedAddress),
      gate.consumedEnvelopeDigest(plan.composition.authorizationEnvelopeDigest),
      gate.consumedRootNullifier(plan.composition.rootProofNullifier),
      gate.consumedDeviceApprovalNonce(plan.composition.deviceApprovalNonce),
      consumer.tokenIdByEnvelopeDigest(plan.composition.authorizationEnvelopeDigest),
      consumer.tokenIdByRootNullifier(plan.composition.rootProofNullifier),
      consumer.balanceOf(plan.authorities.initialExecutionValidator),
      consumer.nextTokenId()
    ]);
    const tokenId = values[12];
    const ownerOf = tokenId > 0n ? await consumer.ownerOf(tokenId) : ethers.ZeroAddress;
    if (!common.sameAddress(values[0], plan.authorities.initialExecutionValidator)
      || String(values[1]).toLowerCase() !== plan.account.ownerCommitment.toLowerCase()
      || !common.sameAddress(values[2], plan.contracts.gate)
      || !common.sameAddress(values[3], plan.authorities.initialRecoveryAuthority)
      || !common.sameAddress(values[4], plan.entryPoint)
      || values[5] !== true || values[6] !== 1n
      || values[7] > ethers.parseEther("0.01")
      || values[8] > ethers.parseEther("0.01")
      || values[9] !== true || values[10] !== true || values[11] !== true
      || tokenId === 0n || values[13] !== tokenId
      || values[14] !== 1n || values[15] !== 2n
      || !common.sameAddress(ownerOf, plan.authorities.initialExecutionValidator)) {
      common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_STATE_INVALID");
    }
    snapshots.push({
      accountCodeHash: ethers.keccak256(accountCode),
      entryPointNonce: values[6].toString(),
      entryPointDepositWei: values[7].toString(),
      nativeBalanceWei: values[8].toString(),
      tokenId: tokenId.toString(),
      passOwner: ethers.getAddress(ownerOf)
    });
  }
  if (common.canonicalJson(snapshots[0]) !== common.canonicalJson(snapshots[1])) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_PROVIDER_DISAGREEMENT");
  }
  const entryEvent = findEvent(
    transactionReceipt, plan.entryPoint, common.entryPointInterface, "UserOperationEvent"
  );
  const gateEvent = findEvent(
    transactionReceipt, plan.contracts.gate, common.gateInterface,
    "PhilSepoliaLocalComposedAuthorizationConsumed"
  );
  const passEvent = findEvent(
    transactionReceipt, plan.contracts.consumer, common.consumerInterface,
    "PhilSepoliaMintPassIssued"
  );
  if (String(entryEvent.args.userOpHash).toLowerCase() !== plan.userOperation.hash.toLowerCase()
    || !common.sameAddress(entryEvent.args.sender, plan.account.predictedAddress)
    || BigInt(entryEvent.args.nonce) !== 0n || entryEvent.args.success !== true
    || String(gateEvent.args.authorizationEnvelopeDigest).toLowerCase()
      !== plan.composition.authorizationEnvelopeDigest.toLowerCase()
    || String(gateEvent.args.rootProofNullifier).toLowerCase()
      !== plan.composition.rootProofNullifier.toLowerCase()
    || String(gateEvent.args.deviceApprovalNonce).toLowerCase()
      !== plan.composition.deviceApprovalNonce.toLowerCase()
    || !common.sameAddress(gateEvent.args.account, plan.account.predictedAddress)
    || !common.sameAddress(gateEvent.args.recipient, plan.authorities.initialExecutionValidator)
    || String(passEvent.args.authorizationEnvelopeDigest).toLowerCase()
      !== plan.composition.authorizationEnvelopeDigest.toLowerCase()
    || String(passEvent.args.rootProofNullifier).toLowerCase()
      !== plan.composition.rootProofNullifier.toLowerCase()
    || !common.sameAddress(passEvent.args.recipient, plan.authorities.initialExecutionValidator)
    || BigInt(passEvent.args.tokenId) !== BigInt(gateEvent.args.tokenId)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_EVENT_BINDING_INVALID");
  }
  return Object.freeze({ ...snapshots[0], actualGasCostWei: String(entryEvent.args.actualGasCost) });
}

async function main() {
  const approvedDigest = argument("--plan-digest");
  if (!approvedDigest || !/^0x[0-9a-f]{64}$/iu.test(approvedDigest)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_EXPLICIT_PLAN_DIGEST_REQUIRED");
  }
  const suppliedApproval = common.required("PHILCORE_CONTROLLED_BETA_P2_APPROVAL");
  const requiredApproval = common.approvalPhrase("P2", approvedDigest.toLowerCase());
  if (suppliedApproval !== requiredApproval) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_EXACT_APPROVAL_REQUIRED");
  }

  // Plan, endpoint, network, and Keychain access are intentionally unreachable
  // until the exact digest-specific owner approval above has matched.
  const planPath = argument("--plan", common.DEFAULT_PLAN_PATH);
  receiptPath = argument("--receipt-output", common.DEFAULT_RECEIPT_PATH);
  if (fs.existsSync(receiptPath)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_RECEIPT_ALREADY_EXISTS_REQUIRES_RECONCILIATION");
  }
  const plan = common.readJson(planPath);
  assertPlanDigest(plan, approvedDigest);
  if (!common.sourceIdentityMatches(plan.source)) {
    common.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  }
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const signedArtifact = signedArtifactFromPlan(plan);
  const parsed = common.parseSignedArtifact(signedArtifact, config, common.artifacts());
  assertExactPlanShape(plan, config, parsed);
  if (common.canonicalJson(common.compilerIdentity()) !== common.canonicalJson(plan.compiler)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_COMPILER_IDENTITY_CHANGED");
  }
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (parsed.validUntil <= now + 60n) common.fail("PHILCORE_CONTROLLED_BETA_P2_AUTHORIZATION_EXPIRED");

  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  common.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
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
    "eth_estimateUserOperationGas", [parsed.rpc, common.ENTRY_POINT]
  ));
  common.assertEstimateWithinSignedCaps(estimate, parsed);
  const feeData = await primary.getFeeData();
  if ((feeData.maxFeePerGas && feeData.maxFeePerGas > parsed.gas.maxFeePerGas)
    || (feeData.maxPriorityFeePerGas
      && feeData.maxPriorityFeePerGas > parsed.gas.maxPriorityFeePerGas)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_SIGNED_FEE_CAP_STALE");
  }
  const [nonceLeft, nonceRight, balanceLeft, balanceRight] = await Promise.all([
    primary.getTransactionCount(config.deployer, "pending"),
    reconciliation.getTransactionCount(config.deployer, "pending"),
    primary.getBalance(config.deployer), reconciliation.getBalance(config.deployer)
  ]);
  if (nonceLeft !== Number(plan.funding.nonce) || nonceRight !== Number(plan.funding.nonce)
    || balanceLeft !== balanceRight || balanceLeft < BigInt(plan.maximumStageCostWei)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_DEPLOYER_STATE_CHANGED");
  }
  const currentFundingGas = await primary.estimateGas({
    from: plan.funding.source,
    to: plan.funding.recipient,
    nonce: Number(plan.funding.nonce),
    value: BigInt(plan.funding.valueWei)
  });
  if (currentFundingGas > BigInt(plan.funding.gasLimit)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FUNDING_GAS_STALE");
  }
  const deployerWallet = common.walletFromKeychain(
    metadata.keychainServices.deployer,
    config.deployer
  );
  const funding = await common.signFundingTransaction(plan, deployerWallet);
  const executionLock = common.acquireExecutionLock(plan.planDigest, plan.source);

  // No public mutation is reachable above this line. Persist before each of
  // the two exact one-shot submissions. The durable exclusive lock above
  // makes any later or concurrent manual invocation fail closed. Automatic
  // retry is forbidden.
  evidence = {
    format: "philcore-controlled-sepolia-beta-p2-receipt-v1",
    version: 1,
    stageId: "P2",
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

  evidence.status = "MUTATION_1_FUNDING_SUBMISSION_REQUESTED";
  evidence.publicMutationOccurred = true;
  evidence.mutations.push({
    order: 1,
    kind: plan.mutations[0].kind,
    transactionHash: funding.hash,
    status: "submission_requested"
  });
  persist();
  await primary.broadcastTransaction(funding.raw);
  const fundingReceipt = await receiptByBoth(primary, reconciliation, funding.hash);
  if (fundingReceipt.status !== 1) common.fail("PHILCORE_CONTROLLED_BETA_P2_FUNDING_REVERTED");
  evidence.mutations[0] = {
    ...evidence.mutations[0],
    status: "confirmed_by_both_providers",
    blockNumber: String(fundingReceipt.blockNumber),
    gasUsed: fundingReceipt.gasUsed.toString()
  };
  evidence.status = "MUTATION_1_CONFIRMED";
  persist();
  const [fundedLeft, fundedRight] = await Promise.all([
    primary.getBalance(plan.account.predictedAddress),
    reconciliation.getBalance(plan.account.predictedAddress)
  ]);
  if (fundedLeft !== fundedRight || fundedLeft !== BigInt(plan.funding.valueWei)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FUNDED_BALANCE_INVALID");
  }

  evidence.status = "MUTATION_2_USER_OPERATION_SUBMISSION_REQUESTED";
  evidence.mutations.push({
    order: 2,
    kind: plan.mutations[1].kind,
    userOperationHash: plan.userOperation.hash,
    status: "submission_requested"
  });
  persist();
  const returnedHash = await bundler.send(
    "eth_sendUserOperation", [parsed.rpc, common.ENTRY_POINT]
  );
  if (String(returnedHash).toLowerCase() !== plan.userOperation.hash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_BUNDLER_HASH_MISMATCH");
  }
  const bundlerReceipt = await userOperationReceipt(bundler, plan.userOperation.hash);
  const transactionHash = bundlerReceipt?.receipt?.transactionHash;
  if (!/^0x[0-9a-f]{64}$/iu.test(transactionHash || "") || bundlerReceipt.success !== true) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_USER_OPERATION_FAILED");
  }
  const transactionReceipt = await receiptByBoth(primary, reconciliation, transactionHash);
  if (transactionReceipt.status !== 1) common.fail("PHILCORE_CONTROLLED_BETA_P2_BUNDLE_TRANSACTION_REVERTED");
  const finalState = await verifyFinalState(primary, reconciliation, plan, transactionReceipt);
  evidence.mutations[1] = {
    ...evidence.mutations[1],
    status: "confirmed_by_bundler_and_both_providers",
    transactionHash,
    blockNumber: String(transactionReceipt.blockNumber),
    actualGasCostWei: finalState.actualGasCostWei
  };
  evidence.status = "P2_CONFIRMED";
  evidence.completedAt = new Date().toISOString();
  evidence.finalState = finalState;
  evidence.publicMutationOccurred = true;
  evidence.automaticRetryOccurred = false;
  persist();
  process.stdout.write(`${JSON.stringify({
    status: evidence.status,
    planDigest: plan.planDigest,
    fundingTransactionHash: funding.hash,
    userOperationHash: plan.userOperation.hash,
    bundleTransactionHash: transactionHash,
    finalState,
    automaticRetryOccurred: false,
    executionLockDisposition: executionLock.disposition,
    receiptPath
  }, null, 2)}\n`);
}

main().catch((error) => {
  const failure = errorEvidence(error);
  if (evidence) {
    evidence.status = "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION";
    evidence.stoppedAt = new Date().toISOString();
    evidence.stopReason = failure.rpcMessage || failure.shortMessage
      || failure.code || failure.message || String(error);
    evidence.error = failure;
    evidence.automaticRetryOccurred = false;
    try { persist(); } catch {}
  }
  process.stderr.write(`${failure.rpcMessage || failure.shortMessage
    || failure.code || failure.message || String(error)}\n`);
  process.exitCode = 1;
});
