"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");
const p3Mode = process.argv.includes("--p3");

let receiptPath = p3Mode ? common.DEFAULT_P3_RECEIPT_PATH : common.DEFAULT_FINAL_RECEIPT_PATH;
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
  if (Array.isArray(value)) return value.slice(0, 32).map((item) => sanitizeErrorValue(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).slice(0, 64).map(
      ([key, item]) => [key, sanitizeErrorValue(item, depth + 1)]
    ));
  }
  return String(value).slice(0, 8192);
}

function errorEvidence(error) {
  return {
    code: error?.code || null,
    shortMessage: error?.shortMessage || null,
    message: sanitizeErrorValue(error?.message || String(error)),
    rpcCode: error?.error?.code ?? null,
    rpcMessage: sanitizeErrorValue(error?.error?.message || null),
    rpcData: sanitizeErrorValue(error?.error?.data || null)
  };
}

function assertPlan(plan, approvedDigest) {
  const digestBody = { ...plan };
  delete digestBody.planDigest;
  digestBody.approval = { requiredPhrase: null, approved: false };
  const digest = common.canonicalSha256(digestBody);
  if (plan?.format !== (p3Mode
      ? "philcore-controlled-sepolia-beta-p3-plan-v1"
      : "philcore-controlled-sepolia-beta-p2-final-plan-v1")
    || plan.version !== 1 || plan.stageId !== (p3Mode ? "P3" : "P2F")
    || plan.status !== (p3Mode
      ? "EXACT_P3_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
      : "EXACT_P2_FINAL_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED")
    || digest !== approvedDigest.toLowerCase() || plan.planDigest !== digest
    || plan.approval?.requiredPhrase !== common.approvalPhrase(p3Mode ? "P3" : "P2F", digest)
    || plan.approval.approved !== false || plan.publicMutationCount !== 1
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.mutations?.length !== 1
    || plan.mutations[0]?.kind !== (p3Mode
      ? "SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_1_V07_USER_OPERATION"
      : "SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_0_V07_USER_OPERATION")
    || plan.userOperation?.factoryDataPresent !== false
    || plan.userOperation?.rpc?.factory !== null
    || plan.userOperation?.rpc?.factoryData !== null
    || plan.userOperation?.packed?.initCode !== "0x"
    || (p3Mode && (plan.p2Final?.planDigest !== common.P2_FINAL_ORIGIN.planDigest
      || plan.p2Final?.receiptByteSha256 !== common.P2_FINAL_ORIGIN.receiptByteSha256
      || plan.p2Final?.userOperationHash !== common.P2_FINAL_ORIGIN.userOperationHash
      || plan.p2Final?.transactionHash !== common.P2_FINAL_ORIGIN.transactionHash
      || !/^0x[0-9a-f]{64}$/u.test(plan.p2Final?.planByteSha256 || "")
      || plan.p2Final?.confirmedByBothProviders !== true
      || plan.staleP2ReplayProof?.publicMutationOccurred !== false
      || plan.staleP2ReplayProof?.method !== "eth_estimateUserOperationGas"
      || plan.staleP2ReplayProof?.staleUserOperationHash
        !== common.P2_FINAL_ORIGIN.userOperationHash
      || plan.staleP2ReplayProof?.staleNonce !== "0"
      || plan.staleP2ReplayProof?.liveNonce !== "1"
      || plan.staleP2ReplayProof?.rejection
        !== "ENTRYPOINT_NONCE_REJECTED_READ_ONLY_ESTIMATE"
      || plan.staleP2ReplayProof?.replayFieldsConsumed !== true
      || plan.staleP2ReplayProof?.confirmedByBothProviders !== true
      || plan.rejectedP3Submission?.planDigest
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.planDigest
      || plan.rejectedP3Submission?.userOperationHash
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.userOperationHash
      || plan.rejectedP3Submission?.verificationGasLimit
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.verificationGasLimit
      || plan.rejectedP3Submission?.requiredEfficiency
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.requiredEfficiency
      || plan.rejectedP3Submission?.observedEfficiency
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.observedEfficiency
      || plan.rejectedP3Submission?.rpcCode
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.rpcCode
      || plan.rejectedP3Submission?.rejection
        !== common.P3_REJECTED_SUBMISSION_ORIGIN.rejection
      || plan.rejectedP3Submission?.bundlerReceipt !== null
      || plan.rejectedP3Submission?.bundlerOperation !== null
      || plan.rejectedP3Submission?.confirmedAbsent !== true
      || plan.rejectedP3Submission?.publicMutationConfirmedOnChain !== false
      || plan.rejectedP3Submission?.liveNonce !== "1"
      || plan.rejectedP3Submission?.liveNextTokenId !== "2"
      || plan.rejectedP3Submission?.confirmedByBothProviders !== true))
    || plan.maximumAdditionalFundingWei !== "0") {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_PLAN_INVALID");
  }
}

function assertPlanBindings(plan, config, parsed) {
  common.assertFinalRuntimeCodeHashes(plan.runtimeCodeHashes, config.runtimeCodeHashes);
  if (plan.chainId !== String(common.CHAIN_ID)
    || !common.sameAddress(plan.entryPoint, common.ENTRY_POINT)
    || plan.runnerReview?.reviewedCommit !== plan.source?.commit
    || plan.runnerReview?.reviewedTree !== plan.source?.tree
    || !/^0x[0-9a-f]{64}$/u.test(plan.runnerReview?.reportSha256 || "")
    || plan.runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    || !common.sameAddress(plan.contracts.consumer, config.infrastructure.mintConsumer)
    || !common.sameAddress(plan.contracts.gate, config.infrastructure.actionGate)
    || !common.sameAddress(plan.contracts.factory, config.infrastructure.factory)
    || !common.sameAddress(plan.contracts.account, config.account.predictedAddress)
    || !common.sameAddress(plan.account.address, config.account.predictedAddress)
    || !common.sameAddress(plan.mutations[0].target, config.entryPoint)
    || plan.mutations[0].userOperationHash.toLowerCase() !== plan.userOperation.hash.toLowerCase()
    || !common.sameAddress(
      plan.authorities.initialExecutionValidator, config.account.initialExecutionValidator
    )
    || !common.sameAddress(
      plan.authorities.initialRecoveryAuthority, config.account.initialRecoveryAuthority
    )
    || plan.account.ownerCommitment.toLowerCase() !== config.account.ownerCommitment.toLowerCase()
    || BigInt(plan.account.salt) !== BigInt(config.account.salt)
    || plan.account.startingNonce !== (p3Mode ? "1" : "0")
    || plan.account.startingEntryPointDepositWei !== (p3Mode
      ? common.P2_FINAL_ORIGIN.entryPointDepositWei
      : "0")
    || plan.account.deployed !== true
    || plan.maximumPrefundedUserOperationCostWei !== parsed.maximumTotalFeeWei.toString()
    || plan.userOperation.maximumTotalFeeWei !== parsed.maximumTotalFeeWei.toString()
    || common.canonicalJson(plan.userOperation.rpc) !== common.canonicalJson(parsed.rpc)
    || plan.userOperation.actionValueWei !== "0"
    || plan.userOperation.paymasterAndData !== "0x"
    || plan.userOperation.submissionAttemptsAllowed !== 1
    || plan.mutations[0].valueWei !== "0"
    || plan.composition.proofAndPhoneP256PossessionApprovalCompleted !== true
    || common.canonicalJson(plan.composition.phoneAssurance)
      !== common.canonicalJson(config.phoneAssurance)
    || plan.composition.localCompositionRequiredBeforeDeviceVaultRelease !== true
    || plan.composition.ethereumVerifiesNoirProof !== false
    || plan.composition.ethereumVerifiesP256Approval !== false) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_PLAN_BINDING_INVALID");
  }
}

async function userOperationReceipt(bundler, hash, deadlineMs = 180_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const receipt = await bundler.send("eth_getUserOperationReceipt", [hash]);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_USER_OPERATION_RECEIPT_TIMEOUT");
}

async function receiptByBoth(primary, reconciliation, hash, deadlineMs = 90_000) {
  const deadline = Date.now() + deadlineMs;
  let left;
  let right;
  while (Date.now() < deadline) {
    [left, right] = await Promise.all([
      primary.getTransactionReceipt(hash), reconciliation.getTransactionReceipt(hash)
    ]);
    if (left && right) break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (!left || !right || left.blockHash.toLowerCase() !== right.blockHash.toLowerCase()
    || left.status !== right.status) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_RECEIPT_PROVIDER_DISAGREEMENT");
  }
  return left;
}

function findEvent(receipt, contractAddress, iface, eventName) {
  const matches = [];
  for (const log of receipt.logs || []) {
    if (!common.sameAddress(log.address, contractAddress)) continue;
    try {
      const parsed = iface.parseLog(log);
      if (parsed?.name === eventName) matches.push(parsed);
    } catch {}
  }
  if (matches.length !== 1) common.fail(`PHILCORE_CONTROLLED_BETA_P2_FINAL_${eventName.toUpperCase()}_INVALID`);
  return matches[0];
}

async function verifyFinalState(primary, reconciliation, plan, transactionReceipt) {
  const snapshots = [];
  for (const provider of [primary, reconciliation]) {
    const accountCode = await provider.getCode(plan.account.address);
    if (accountCode === "0x"
      || ethers.keccak256(accountCode).toLowerCase() !== plan.runtimeCodeHashes.account.toLowerCase()
      || common.accountRuntimeIdentity(accountCode).immutableMaskedRuntimeCodeHash.toLowerCase()
        !== plan.runtimeCodeHashes.accountImmutableMasked.toLowerCase()) {
      common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_CODE_INVALID");
    }
    const account = new ethers.Contract(plan.account.address, common.accountInterface, provider);
    const factory = new ethers.Contract(plan.contracts.factory, common.factoryInterface, provider);
    const gate = new ethers.Contract(plan.contracts.gate, common.gateInterface, provider);
    const consumer = new ethers.Contract(plan.contracts.consumer, common.consumerInterface, provider);
    const entry = new ethers.Contract(plan.entryPoint, common.entryPointInterface, provider);
    const values = await Promise.all([
      account.owner(), account.ownerCommitment(), account.approvedActionGate(),
      account.recoveryAuthority(), account.entryPoint(),
      factory.isPhilSepoliaMintAccount(plan.account.address),
      entry.getNonce(plan.account.address, 0), entry.balanceOf(plan.account.address),
      provider.getBalance(plan.account.address),
      gate.consumedEnvelopeDigest(plan.composition.authorizationEnvelopeDigest),
      gate.consumedRootNullifier(plan.composition.rootProofNullifier),
      gate.consumedDeviceApprovalNonce(plan.composition.deviceApprovalNonce),
      consumer.tokenIdByEnvelopeDigest(plan.composition.authorizationEnvelopeDigest),
      consumer.tokenIdByRootNullifier(plan.composition.rootProofNullifier),
      consumer.balanceOf(plan.authorities.initialExecutionValidator), consumer.nextTokenId(),
      gate.consumedEnvelopeDigest(common.P2_FINAL_ORIGIN.authorizationEnvelopeDigest),
      gate.consumedRootNullifier(common.P2_FINAL_ORIGIN.rootProofNullifier),
      gate.consumedDeviceApprovalNonce(common.P2_FINAL_ORIGIN.deviceApprovalNonce),
      consumer.tokenIdByEnvelopeDigest(common.P2_FINAL_ORIGIN.authorizationEnvelopeDigest),
      consumer.tokenIdByRootNullifier(common.P2_FINAL_ORIGIN.rootProofNullifier),
      consumer.ownerOf(BigInt(common.P2_FINAL_ORIGIN.tokenId))
    ]);
    const tokenId = values[12];
    const ownerOf = tokenId > 0n ? await consumer.ownerOf(tokenId) : ethers.ZeroAddress;
    if (!common.sameAddress(values[0], plan.authorities.initialExecutionValidator)
      || String(values[1]).toLowerCase() !== plan.account.ownerCommitment.toLowerCase()
      || !common.sameAddress(values[2], plan.contracts.gate)
      || !common.sameAddress(values[3], plan.authorities.initialRecoveryAuthority)
      || !common.sameAddress(values[4], plan.entryPoint)
      || values[5] !== true || values[6] !== (p3Mode ? 2n : 1n)
      || values[7] > ethers.parseEther("0.01") || values[8] > ethers.parseEther("0.01")
      || values[9] !== true || values[10] !== true || values[11] !== true
      || tokenId !== (p3Mode ? 2n : 1n) || values[13] !== tokenId
      || values[14] !== (p3Mode ? 2n : 1n) || values[15] !== (p3Mode ? 3n : 2n)
      || !common.sameAddress(ownerOf, plan.authorities.initialExecutionValidator)
      || (p3Mode && (values[16] !== true || values[17] !== true || values[18] !== true
        || values[19] !== 1n || values[20] !== 1n
        || !common.sameAddress(values[21], plan.authorities.initialExecutionValidator)))) {
      common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_STATE_INVALID");
    }
    snapshots.push({
      accountCodeHash: ethers.keccak256(accountCode),
      entryPointNonce: values[6].toString(),
      entryPointDepositWei: values[7].toString(),
      nativeBalanceWei: values[8].toString(),
      tokenId: tokenId.toString(),
      passOwner: ethers.getAddress(ownerOf),
      ...(p3Mode ? {
        priorP2ReplayFieldsRemainConsumed: true,
        priorP2TokenId: values[19].toString()
      } : {})
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
    || !common.sameAddress(entryEvent.args.sender, plan.account.address)
    || BigInt(entryEvent.args.nonce) !== (p3Mode ? 1n : 0n) || entryEvent.args.success !== true
    || String(gateEvent.args.authorizationEnvelopeDigest).toLowerCase()
      !== plan.composition.authorizationEnvelopeDigest.toLowerCase()
    || String(gateEvent.args.rootProofNullifier).toLowerCase()
      !== plan.composition.rootProofNullifier.toLowerCase()
    || String(gateEvent.args.deviceApprovalNonce).toLowerCase()
      !== plan.composition.deviceApprovalNonce.toLowerCase()
    || !common.sameAddress(gateEvent.args.account, plan.account.address)
    || !common.sameAddress(gateEvent.args.recipient, plan.authorities.initialExecutionValidator)
    || String(passEvent.args.authorizationEnvelopeDigest).toLowerCase()
      !== plan.composition.authorizationEnvelopeDigest.toLowerCase()
    || String(passEvent.args.rootProofNullifier).toLowerCase()
      !== plan.composition.rootProofNullifier.toLowerCase()
    || !common.sameAddress(passEvent.args.recipient, plan.authorities.initialExecutionValidator)
    || BigInt(passEvent.args.tokenId) !== BigInt(gateEvent.args.tokenId)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_EVENT_BINDING_INVALID");
  }
  return { ...snapshots[0], actualGasCostWei: String(entryEvent.args.actualGasCost) };
}

async function main() {
  const approvedDigest = argument("--plan-digest");
  if (!approvedDigest || !/^0x[0-9a-f]{64}$/iu.test(approvedDigest)) {
    common.fail(p3Mode
      ? "PHILCORE_CONTROLLED_BETA_P3_EXPLICIT_PLAN_DIGEST_REQUIRED"
      : "PHILCORE_CONTROLLED_BETA_P2_FINAL_EXPLICIT_PLAN_DIGEST_REQUIRED");
  }
  const suppliedApproval = common.required(p3Mode
    ? "PHILCORE_CONTROLLED_BETA_P3_APPROVAL"
    : "PHILCORE_CONTROLLED_BETA_P2_FINAL_APPROVAL");
  if (suppliedApproval !== common.approvalPhrase(
    p3Mode ? "P3" : "P2F", approvedDigest.toLowerCase()
  )) {
    common.fail(p3Mode
      ? "PHILCORE_CONTROLLED_BETA_P3_EXACT_APPROVAL_REQUIRED"
      : "PHILCORE_CONTROLLED_BETA_P2_FINAL_EXACT_APPROVAL_REQUIRED");
  }
  const planPath = argument(
    "--plan", p3Mode ? common.DEFAULT_P3_PLAN_PATH : common.DEFAULT_FINAL_PLAN_PATH
  );
  const signedArtifactPath = argument(
    "--signed-artifact",
    p3Mode ? common.DEFAULT_P3_SIGNED_ARTIFACT_PATH : common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH
  );
  receiptPath = argument(
    "--receipt-output", p3Mode ? common.DEFAULT_P3_RECEIPT_PATH : common.DEFAULT_FINAL_RECEIPT_PATH
  );
  if (fs.existsSync(receiptPath)) common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_RECEIPT_ALREADY_EXISTS");
  const plan = common.readJson(planPath);
  assertPlan(plan, approvedDigest);
  if (!common.sourceIdentityMatches(plan.source)) common.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  const config = common.loadConfiguration();
  const metadata = common.normalizePublicMetadata(common.readJson(
    common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")
  ));
  common.assertConfigurationMetadata(config, metadata);
  const priorReceiptBytes = fs.readFileSync(p3Mode
    ? common.DEFAULT_FINAL_RECEIPT_PATH
    : common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH);
  const priorReceipt = JSON.parse(priorReceiptBytes);
  if (p3Mode) {
    common.assertP2FinalReceipt(priorReceipt, priorReceiptBytes, config);
    if (common.sha256Bytes(priorReceiptBytes) !== plan.p2Final.receiptByteSha256) {
      common.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_EVIDENCE_CHANGED");
    }
    const p2FinalPlanBytes = fs.readFileSync(common.DEFAULT_FINAL_PLAN_PATH);
    const p2FinalPlan = common.assertP2FinalPlan(JSON.parse(p2FinalPlanBytes), config);
    if (common.sha256Bytes(p2FinalPlanBytes) !== plan.p2Final.planByteSha256
      || p2FinalPlan.runtimeCodeHashes.account.toLowerCase()
        !== priorReceipt.finalState.accountCodeHash.toLowerCase()) {
      common.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_PLAN_EVIDENCE_CHANGED");
    }
  } else if (common.sha256Bytes(priorReceiptBytes)
      !== plan.accountDeployment.receiptByteSha256) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_DEPLOYMENT_EVIDENCE_CHANGED");
  }
  const signedArtifactBytes = fs.readFileSync(signedArtifactPath);
  const signedArtifact = JSON.parse(signedArtifactBytes);
  if (common.sha256Bytes(signedArtifactBytes) !== plan.composition.signedArtifactByteSha256
    || common.canonicalSha256(signedArtifact) !== plan.composition.signedArtifactSha256) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_SIGNED_ARTIFACT_CHANGED");
  }
  const parsed = common.parseSignedArtifact(
    signedArtifact, config, common.artifacts(),
    { accountDeployed: true, expectedNonce: p3Mode ? 1 : 0 }
  );
  if (p3Mode) common.assertP3GasPolicy(parsed.gas, config.gasPolicy);
  else common.assertP2FinalGasPolicy(parsed.gas, config.gasPolicy);
  assertPlanBindings(plan, config, parsed);
  if (common.canonicalJson(parsed.rpc) !== common.canonicalJson(plan.userOperation.rpc)
    || parsed.localUserOperationHash.toLowerCase() !== plan.userOperation.hash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_USER_OPERATION_CHANGED");
  }
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  common.assertEndpointBindings(plan.endpointBindings, primaryUrl, reconciliationUrl, bundlerUrl);
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(
    reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS
  );
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
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
  if (p3Mode) {
    await common.assertP2FinalOriginLive(primary, reconciliation, bundler, config);
    const staleP2Artifact = common.readJson(common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH);
    await common.assertStaleP2UserOperationRejected(bundler, staleP2Artifact, config);
    await common.assertRejectedP3SubmissionAbsent(bundler);
  }
  if (state.accountCodeHash?.toLowerCase() !== plan.runtimeCodeHashes.account.toLowerCase()
    || state.accountImmutableMaskedRuntimeCodeHash?.toLowerCase()
      !== plan.runtimeCodeHashes.accountImmutableMasked.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_RUNTIME_CHANGED");
  }
  const [existingReceipt, existingOperation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [plan.userOperation.hash]),
    bundler.send("eth_getUserOperationByHash", [plan.userOperation.hash])
  ]);
  if (existingReceipt !== null || existingOperation !== null
    || state.accountBalanceWei !== plan.account.startingNativeBalanceWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_LIVE_STATE_CHANGED");
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
  const executionLock = common.acquireBoundedExecutionLock(
    plan.planDigest,
    plan.source,
    p3Mode ? "P3" : "P2F",
    p3Mode ? common.DEFAULT_P3_EXECUTION_LOCK_PATH : common.DEFAULT_FINAL_EXECUTION_LOCK_PATH
  );
  evidence = {
    format: p3Mode
      ? "philcore-controlled-sepolia-beta-p3-receipt-v1"
      : "philcore-controlled-sepolia-beta-p2-final-receipt-v1",
    version: 1,
    stageId: p3Mode ? "P3" : "P2F",
    status: "APPROVAL_VERIFIED_EXECUTION_STARTING",
    planDigest: plan.planDigest,
    source: plan.source,
    chainId: plan.chainId,
    endpoints: plan.endpoints,
    approval: { phraseMatched: true, planDigestMatched: true, verifiedAt: new Date().toISOString() },
    executionLock,
    mutations: [],
    additionalFundingWei: "0",
    publicMutationOccurred: false,
    automaticRetryOccurred: false
  };
  persist();
  evidence.status = p3Mode
    ? "MUTATION_1_P3_USER_OPERATION_SUBMISSION_REQUESTED"
    : "MUTATION_1_FINAL_USER_OPERATION_SUBMISSION_REQUESTED";
  evidence.publicMutationOccurred = true;
  evidence.mutations.push({
    order: 1,
    kind: plan.mutations[0].kind,
    userOperationHash: plan.userOperation.hash,
    status: "submission_requested"
  });
  persist();
  const returnedHash = await bundler.send(
    "eth_sendUserOperation", [parsed.rpc, common.ENTRY_POINT]
  );
  if (String(returnedHash).toLowerCase() !== plan.userOperation.hash.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_BUNDLER_HASH_MISMATCH");
  }
  const bundlerReceipt = await userOperationReceipt(bundler, plan.userOperation.hash);
  const transactionHash = bundlerReceipt?.receipt?.transactionHash;
  if (!/^0x[0-9a-f]{64}$/iu.test(transactionHash || "") || bundlerReceipt.success !== true) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_USER_OPERATION_FAILED");
  }
  const transactionReceipt = await receiptByBoth(primary, reconciliation, transactionHash);
  if (transactionReceipt.status !== 1) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_BUNDLE_TRANSACTION_REVERTED");
  }
  const finalState = await verifyFinalState(primary, reconciliation, plan, transactionReceipt);
  evidence.mutations[0] = {
    ...evidence.mutations[0],
    status: "confirmed_by_bundler_and_both_providers",
    transactionHash,
    blockNumber: String(transactionReceipt.blockNumber),
    actualGasCostWei: finalState.actualGasCostWei
  };
  evidence.status = p3Mode ? "P3_CONFIRMED" : "P2_FINAL_CONFIRMED";
  evidence.completedAt = new Date().toISOString();
  evidence.finalState = finalState;
  evidence.publicMutationOccurred = true;
  persist();
  process.stdout.write(`${JSON.stringify({
    status: evidence.status,
    planDigest: plan.planDigest,
    additionalFundingWei: "0",
    userOperationHash: plan.userOperation.hash,
    bundleTransactionHash: transactionHash,
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
