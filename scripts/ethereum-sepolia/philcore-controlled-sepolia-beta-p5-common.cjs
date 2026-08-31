"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");
require("tsx/cjs");

const preparation = require(
  "../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts"
);
const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");

const STAGE_ID = "P5";
const RELEASE_SELECTOR = "0xb818fbeb";
const PLAN_FORMAT = "philcore-controlled-sepolia-beta-p5-plan-v2";
const ARTIFACT_FORMAT = "philcore-controlled-sepolia-beta-p5-signed-unsubmitted-v2";
const RECEIPT_FORMAT = "philcore-controlled-sepolia-beta-p5-receipt-v2";
const CONSUMED_ATTEMPT_1_LINEAGE_ID = "p5-attempt-0001";
const DEFAULT_SIGNED_ARTIFACT_PATH = path.join(
  common.PRIVATE_EVIDENCE_ROOT, "p5-signed-unsubmitted-v1.json"
);
const DEFAULT_PLAN_PATH = path.join(common.PRIVATE_EVIDENCE_ROOT, "p5-plan.json");
const DEFAULT_RECEIPT_PATH = path.join(common.PRIVATE_EVIDENCE_ROOT, "p5-receipt.json");
const DEFAULT_EXECUTION_LOCK_PATH = path.join(
  common.PRIVATE_EVIDENCE_ROOT, "p5-execution-attempt.lock.json"
);
// A structurally valid, non-owner ECDSA signature used only for read-only
// eth_estimateUserOperationGas. It is never stored in the unsigned plan and is
// never eligible for submission.
const ESTIMATION_SIGNATURE = `0x${"00".repeat(31)}01${"00".repeat(31)}011b`;
// Phase 7D independently observed these exact deployed-account cleanup estimates.
// P5 applies the mandatory 125% planning margin to call gas, pre-verification
// gas, and fees. Verification gas is selected separately from exact-operation
// validation evidence because both an absolute safety floor and bundler
// efficiency ceiling constrain it. The inherited P2/P3 policy is unchanged.
const P5_REVIEWED_CLEANUP_GAS_ESTIMATE = Object.freeze({
  verificationGasLimit: 150000n,
  callGasLimit: 300000n,
  preVerificationGas: 100000n
});
const P5_MAX_FEE_PER_GAS = 3_000_000_000n;
const P5_BUNDLER_PRIORITY_FEE_FLOOR = 100_000_000n;
const P5_VERIFICATION_EFFICIENCY_NUMERATOR = 2n;
const P5_VERIFICATION_EFFICIENCY_DENOMINATOR = 5n;
const P5_VERIFICATION_SAFETY_MARGIN_NUMERATOR = 5n;
const P5_VERIFICATION_SAFETY_MARGIN_DENOMINATOR = 4n;
const P5_ACTUAL_VALIDATION_GAS = 37_050n;
const P5_MINIMUM_SAFE_VERIFICATION_GAS = 46_313n;
const P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS = 92_625n;
const P5_SELECTED_VERIFICATION_GAS = 80_000n;
const P5_VERIFICATION_GAS_EVIDENCE_BODY = Object.freeze({
  format: "philcore-controlled-sepolia-beta-p5-verification-gas-evidence-v1",
  version: 1,
  evidenceType: "EXACT_P5_OPERATION_VALIDATION_GAS",
  methodIdentifier:
    "ENTRYPOINT_V07_SIMULATE_VALIDATION_STATE_OVERRIDE_TWO_PROVIDER_RECONCILIATION",
  exactOperationBound: true,
  actualValidationGas: P5_ACTUAL_VALIDATION_GAS.toString(),
  safetyMarginNumerator: P5_VERIFICATION_SAFETY_MARGIN_NUMERATOR.toString(),
  safetyMarginDenominator: P5_VERIFICATION_SAFETY_MARGIN_DENOMINATOR.toString(),
  minimumSafeVerificationGas: P5_MINIMUM_SAFE_VERIFICATION_GAS.toString(),
  efficiencyThresholdNumerator: P5_VERIFICATION_EFFICIENCY_NUMERATOR.toString(),
  efficiencyThresholdDenominator: P5_VERIFICATION_EFFICIENCY_DENOMINATOR.toString(),
  maximumEfficiencyCompliantVerificationGas:
    P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS.toString(),
  selectedVerificationGasLimit: P5_SELECTED_VERIFICATION_GAS.toString(),
  reference: Object.freeze({
    chainId: "11155111",
    entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    account: "0xb72053013089F089502B075009c0BD807349eCC6",
    releaseSelector: RELEASE_SELECTOR,
    userOperationHash:
      "0xade275d0de8db399a4f829e47b5b20b7212c84571762f70584567bbeee64503e",
    primaryMeasurementBlock: "11588147",
    reproducedMeasurementBlock: "11588131",
    accountCodeHash:
      "0x5ee74f9e45b3d944b6bf220d60cb83000d04ca878c26ab455eaeda1dcea8b8ad",
    entryPointCodeHash:
      "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58",
    simulationRuntimeCodeHash:
      "0xf163e04019f4aa79f31ea386472d662c067e956e0568be7d4d8d59c8f25adad2",
    providerAgreement: "PRIMARY_AND_INDEPENDENT_RECONCILIATION_EXACT_MATCH"
  })
});
const P5_VERIFICATION_GAS_EVIDENCE = Object.freeze({
  ...P5_VERIFICATION_GAS_EVIDENCE_BODY,
  sha256: common.canonicalSha256(P5_VERIFICATION_GAS_EVIDENCE_BODY)
});
const P5_REJECTION_MESSAGE_MAX_LENGTH = 1024;
const P5_R_L01 = Object.freeze({
  id: "P5-R-L01",
  severity: "LOW",
  status: "OPEN",
  disposition: "FAIL_CLOSED",
  condition:
    "UNRELATED_USEROPERATIONS_IN_SAME_BUNDLER_TRANSACTION_MAY_CAUSE_CONSERVATIVE_RECONCILIATION_FAILURE",
  canCreateFalseSuccess: false,
  retryAuthorized: false,
  secondSubmissionAuthorized: false
});
const P3_REPLAY = Object.freeze({
  authorizationEnvelopeDigest:
    "0x2db392b8c2842732e4f419d66643830530b34377ed807215d9020f67b998fc83",
  rootProofNullifier:
    "0xe2659832b7bde479ef9ec3d68fadb5df029bc0f9ef2ad5d9d86f91e988380a3b",
  deviceApprovalNonce:
    "0x18c3aaf418482cb0a593cdd9789a5736ffd768d479503790b0b8c67840944f87"
});

const accountInterface = new ethers.Interface([
  ...common.accountInterface.fragments,
  "function frozen() view returns (bool)",
  "function recoveryRequest() view returns (address,uint64,uint64,uint64,bytes32,bool)",
  "function recoveryAuthorityRotationRequest() view returns (address,address,uint64,uint64,uint64,bytes32,bool)",
  "function releaseTestFunds(uint256 nativeAmountWei,uint256 entryPointDepositAmountWei)",
  "event TestFundsReleased(address indexed recipient,uint256 nativeAmountWei,uint256 entryPointDepositAmountWei)"
]);
const entryPointInterface = new ethers.Interface([
  ...common.entryPointInterface.fragments,
  "event UserOperationRevertReason(bytes32 indexed userOpHash,address indexed sender,uint256 nonce,bytes revertReason)",
  "event Withdrawn(address indexed account,address withdrawAddress,uint256 amount)"
]);

function asUint(value, label, { positive = false } = {}) {
  let parsed;
  try { parsed = BigInt(value); } catch { common.fail(`PHILCORE_CONTROLLED_BETA_P5_${label}_INVALID`); }
  if (parsed < 0n || (positive && parsed === 0n)) {
    common.fail(`PHILCORE_CONTROLLED_BETA_P5_${label}_INVALID`);
  }
  return parsed;
}

function assertFutureLineageId(value) {
  if (!/^p5-attempt-[0-9]{4}$/u.test(value || "")
    || Number(value.slice(-4)) < 2
    || value === CONSUMED_ATTEMPT_1_LINEAGE_ID) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_FUTURE_LINEAGE_ID_INVALID");
  }
  return value;
}

function lineagePaths(lineageId) {
  const exact = assertFutureLineageId(lineageId);
  const root = path.join(common.PRIVATE_EVIDENCE_ROOT, "p5-lineages", exact);
  return Object.freeze({
    root,
    plan: path.join(root, "plan-v2.json"),
    signedArtifact: path.join(root, "signed-unsubmitted-v2.json"),
    executionLock: path.join(root, "execution-attempt.lock.json"),
    receipt: path.join(root, "receipt-v2.json")
  });
}

function sanitizeDiagnosticText(value, redactionValues = []) {
  if (value === null || value === undefined) return null;
  let text = String(value);
  for (const secret of redactionValues) {
    if (typeof secret === "string" && secret.length >= 8) {
      text = text.split(secret).join("[REDACTED_SECRET]");
    }
  }
  return text
    .replace(/https?:\/\/[^\s"')]+/giu, "[REDACTED_ENDPOINT]")
    .replace(/\bauthorization["']?\s*[:=]\s*["']?(?:bearer\s+)?[^\s,;"']+/giu,
      "[REDACTED_CREDENTIAL]")
    .replace(/\b(?:api[_-]?key|token)["']?\s*[:=]\s*["']?[^\s,;"']+/giu,
      "[REDACTED_CREDENTIAL]")
    .replace(/\bprivate[_ -]?key["']?\s*[:=]\s*["']?0x[0-9a-f]{64}["']?/giu,
      "[REDACTED_PRIVATE_KEY]")
    .replace(/0x[0-9a-f]{130,}/giu, "[REDACTED_SIGNED_PAYLOAD]")
    .slice(0, P5_REJECTION_MESSAGE_MAX_LENGTH);
}

function rpcDataEvidence(value, redactionValues = []) {
  if (value === null || value === undefined) {
    return Object.freeze({ present: false, type: "NULL", sha256: null, keys: [], summary: null });
  }
  const type = Array.isArray(value) ? "ARRAY" : typeof value === "object"
    ? "OBJECT" : typeof value === "string" ? "STRING" : "SCALAR";
  const keys = type === "OBJECT" ? Object.keys(value).slice(0, 16).map((key) => (
    sanitizeDiagnosticText(key, redactionValues).slice(0, 128)
  )) : [];
  let summary = null;
  if (typeof value === "string") summary = sanitizeDiagnosticText(value, redactionValues);
  else if (value && typeof value === "object") {
    summary = sanitizeDiagnosticText(value.message ?? value.reason ?? null, redactionValues);
  }
  return Object.freeze({
    present: true,
    type,
    sha256: common.canonicalSha256({ type, keys, summary }),
    keys,
    summary
  });
}

function classifyBundlerRejection({ sendDisposition, message, aaCode, rpcData }) {
  const text = `${message || ""} ${rpcData?.summary || ""} ${aaCode || ""}`.toLowerCase();
  if (sendDisposition === "AMBIGUOUS_TRANSPORT_RESULT") return "TRANSPORT_OR_AMBIGUOUS";
  if (/priority.{0,40}fee|must be at least.{0,40}(?:fee|gas)/u.test(text)) {
    return "PRIORITY_FEE_ADMISSION_REJECTION";
  }
  if (/verification.{0,40}(?:efficiency|gas limit efficiency)|efficiency too low/u.test(text)) {
    return "VERIFICATION_GAS_EFFICIENCY_REJECTION";
  }
  if (/prefund|aa21|aa31/u.test(text)) return "PREFUND_REJECTION";
  if (/nonce|aa25/u.test(text)) return "NONCE_REJECTION";
  if (/signature|aa24/u.test(text)) return "SIGNATURE_REJECTION";
  if (aaCode) return "AA_VALIDATION_REJECTION";
  if (/policy|stake|unstake|reputation|throttl/u.test(text)) return "BUNDLER_POLICY_REJECTION";
  return "UNKNOWN_REJECTION";
}

function bundlerRejectionEvidence(error, { sendDisposition, userOperationHash,
  attemptedAt, redactionValues = [] } = {}) {
  const rpc = error?.info?.error ?? error?.error ?? null;
  const diagnosticMessage = rpc?.message ?? error?.shortMessage
    ?? (error?.info ? null : error?.message) ?? null;
  const rpcMessage = sanitizeDiagnosticText(diagnosticMessage, redactionValues);
  const data = rpcDataEvidence(rpc?.data, redactionValues);
  const aaMatch = `${rpcMessage || ""} ${data.summary || ""}`.match(/\bAA\d{2}\b/iu);
  const aaCode = aaMatch ? aaMatch[0].toUpperCase() : null;
  const requestId = error?.info?.payload?.id;
  const safeRequestId = Number.isSafeInteger(requestId) && requestId >= 0 ? requestId : null;
  const result = {
    format: "philcore-controlled-sepolia-beta-p5-bundler-rejection-evidence-v1",
    providerRole: "bundler",
    rpcMethod: "eth_sendUserOperation",
    requestId: safeRequestId,
    attemptedAt,
    userOperationHash,
    rejectionStage: "BUNDLER_SEND",
    sendDisposition,
    ethersCode: sanitizeDiagnosticText(error?.code ?? null, redactionValues),
    rpcCode: typeof rpc?.code === "number" ? rpc.code : null,
    message: rpcMessage,
    aaCode,
    rpcData: data
  };
  return Object.freeze({
    ...result,
    classification: classifyBundlerRejection({
      sendDisposition, message: result.message, aaCode, rpcData: data
    })
  });
}

function assertP5VerificationGasEvidence(evidence) {
  if (!evidence || typeof evidence !== "object") {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EVIDENCE_INVALID");
  }
  const body = { ...evidence };
  delete body.sha256;
  if (common.canonicalJson(body) !== common.canonicalJson(P5_VERIFICATION_GAS_EVIDENCE_BODY)
    || evidence.sha256 !== P5_VERIFICATION_GAS_EVIDENCE.sha256
    || common.canonicalSha256(body) !== evidence.sha256
    || asUint(evidence.actualValidationGas, "EVIDENCE_ACTUAL_VALIDATION_GAS", {
      positive: true
    }) !== P5_ACTUAL_VALIDATION_GAS
    || asUint(evidence.minimumSafeVerificationGas, "EVIDENCE_MINIMUM_SAFE_GAS", {
      positive: true
    }) !== P5_MINIMUM_SAFE_VERIFICATION_GAS
    || asUint(evidence.maximumEfficiencyCompliantVerificationGas,
      "EVIDENCE_MAXIMUM_EFFICIENT_GAS", { positive: true })
      !== P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS
    || asUint(evidence.selectedVerificationGasLimit, "EVIDENCE_SELECTED_GAS", {
      positive: true
    }) !== P5_SELECTED_VERIFICATION_GAS
    || (P5_ACTUAL_VALIDATION_GAS * P5_VERIFICATION_SAFETY_MARGIN_NUMERATOR
      + P5_VERIFICATION_SAFETY_MARGIN_DENOMINATOR - 1n)
      / P5_VERIFICATION_SAFETY_MARGIN_DENOMINATOR !== P5_MINIMUM_SAFE_VERIFICATION_GAS
    || P5_ACTUAL_VALIDATION_GAS * P5_VERIFICATION_EFFICIENCY_DENOMINATOR
      / P5_VERIFICATION_EFFICIENCY_NUMERATOR !== P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EVIDENCE_INVALID");
  }
  return P5_VERIFICATION_GAS_EVIDENCE;
}

function assessP5VerificationEfficiency({ verificationGasLimit, evidence } = {}) {
  const limit = asUint(verificationGasLimit, "EFFICIENCY_VERIFICATION_GAS", { positive: true });
  if (evidence === null || evidence === undefined) {
    return Object.freeze({
      status: "VERIFICATION_EFFICIENCY_UNPROVEN",
      thresholdNumerator: P5_VERIFICATION_EFFICIENCY_NUMERATOR.toString(),
      thresholdDenominator: P5_VERIFICATION_EFFICIENCY_DENOMINATOR.toString(),
      verificationGasLimit: limit.toString(),
      actualValidationGas: null,
      minimumSafeVerificationGas: null,
      maximumEfficientVerificationGasLimit: null,
      evidence: null
    });
  }
  const exactEvidence = assertP5VerificationGasEvidence(evidence);
  const actual = P5_ACTUAL_VALIDATION_GAS;
  const minimum = P5_MINIMUM_SAFE_VERIFICATION_GAS;
  const maximum = P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS;
  const status = limit < minimum ? "VERIFICATION_GAS_ABSOLUTE_SAFETY_FAIL"
    : limit > maximum ? "VERIFICATION_EFFICIENCY_FAIL"
      : "VERIFICATION_EFFICIENCY_PASS";
  return Object.freeze({
    status,
    thresholdNumerator: P5_VERIFICATION_EFFICIENCY_NUMERATOR.toString(),
    thresholdDenominator: P5_VERIFICATION_EFFICIENCY_DENOMINATOR.toString(),
    verificationGasLimit: limit.toString(),
    actualValidationGas: actual.toString(),
    minimumSafeVerificationGas: minimum.toString(),
    maximumEfficientVerificationGasLimit: maximum.toString(),
    evidence: exactEvidence
  });
}

function assertP5VerificationEfficiency(value) {
  if (value?.status === "VERIFICATION_EFFICIENCY_UNPROVEN") {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EFFICIENCY_UNPROVEN");
  }
  if (value?.status !== "VERIFICATION_EFFICIENCY_PASS") {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EFFICIENCY_INSUFFICIENT");
  }
  return value;
}

function gasFields(userOperation) {
  const limits = asUint(userOperation?.accountGasLimits, "ACCOUNT_GAS_LIMITS");
  const fees = asUint(userOperation?.gasFees, "GAS_FEES");
  const mask = (1n << 128n) - 1n;
  const result = Object.freeze({
    verificationGasLimit: limits >> 128n,
    callGasLimit: limits & mask,
    preVerificationGas: asUint(userOperation?.preVerificationGas, "PRE_VERIFICATION_GAS", {
      positive: true
    }),
    maxPriorityFeePerGas: fees >> 128n,
    maxFeePerGas: fees & mask
  });
  if (result.verificationGasLimit === 0n || result.callGasLimit === 0n
    || result.maxFeePerGas === 0n
    || result.maxPriorityFeePerGas > result.maxFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_GAS_POLICY_INVALID");
  }
  return result;
}

function normalizeEstimate(value) {
  const result = Object.freeze({
    verificationGasLimit: asUint(value?.verificationGasLimit, "ESTIMATE_VERIFICATION_GAS", {
      positive: true
    }),
    callGasLimit: asUint(value?.callGasLimit, "ESTIMATE_CALL_GAS", { positive: true }),
    preVerificationGas: asUint(value?.preVerificationGas, "ESTIMATE_PRE_VERIFICATION_GAS", {
      positive: true
    })
  });
  return result;
}

function prefundModel({ nativeBalanceWei, entryPointDepositWei, gas, estimate }) {
  const nativeBalance = asUint(nativeBalanceWei, "NATIVE_BALANCE");
  const deposit = asUint(entryPointDepositWei, "ENTRYPOINT_DEPOSIT");
  const signed = Object.fromEntries(Object.entries(gas).map(([key, value]) => [
    key, asUint(value, `GAS_${key.toUpperCase()}`, { positive: key !== "maxPriorityFeePerGas" })
  ]));
  const estimated = normalizeEstimate(estimate);
  if (estimated.verificationGasLimit > signed.verificationGasLimit
    || estimated.callGasLimit > signed.callGasLimit
    || estimated.preVerificationGas > signed.preVerificationGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_EXCEEDS_SIGNED_LIMIT");
  }
  const maximumGas = signed.verificationGasLimit + signed.callGasLimit
    + signed.preVerificationGas;
  const maximumPrefund = maximumGas * signed.maxFeePerGas;
  const missingAccountFunds = maximumPrefund > deposit ? maximumPrefund - deposit : 0n;
  if (missingAccountFunds > nativeBalance) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_ADDITIONAL_FUNDING_REQUIRED");
  }
  const withdrawableDeposit = deposit > maximumPrefund ? deposit - maximumPrefund : 0n;
  const releasableNative = nativeBalance - missingAccountFunds;
  if (releasableNative + withdrawableDeposit === 0n) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_ZERO_RELEASE_FORBIDDEN");
  }
  const estimatedGas = estimated.verificationGasLimit + estimated.callGasLimit
    + estimated.preVerificationGas;
  return Object.freeze({
    formula: "P=(verificationGasLimit+callGasLimit+preVerificationGas)*maxFeePerGas;M=max(P-D,0);W=max(D-P,0);R=N-M",
    maximumGas: maximumGas.toString(),
    maximumPrefundWei: maximumPrefund.toString(),
    missingAccountFundsWei: missingAccountFunds.toString(),
    withdrawableEntryPointDepositWei: withdrawableDeposit.toString(),
    releasableNativeWei: releasableNative.toString(),
    estimatedCleanupGas: estimatedGas.toString(),
    estimatedMaximumCostWei: (estimatedGas * signed.maxFeePerGas).toString(),
    maximumTerminalEntryPointDepositWei: maximumPrefund.toString(),
    terminalBoundFormula: "maximumTerminalEntryPointDepositWei=maximumPrefundWei",
    exactZeroEntryPointDepositPromised: false,
    ownerAcceptanceRequired: true,
    externalFundingWei: "0"
  });
}

function normalizeState(value) {
  const state = Object.freeze({
    account: ethers.getAddress(value.account),
    owner: ethers.getAddress(value.owner),
    entryPoint: ethers.getAddress(value.entryPoint),
    accountCodeHash: String(value.accountCodeHash).toLowerCase(),
    nonce: asUint(value.nonce, "NONCE").toString(),
    nativeBalanceWei: asUint(value.nativeBalanceWei, "NATIVE_BALANCE").toString(),
    entryPointDepositWei: asUint(value.entryPointDepositWei, "ENTRYPOINT_DEPOSIT").toString(),
    frozen: value.frozen,
    recoveryActive: value.recoveryActive,
    recoveryAuthorityRotationActive: value.recoveryAuthorityRotationActive,
    passBalance: asUint(value.passBalance, "PASS_BALANCE").toString(),
    nextTokenId: asUint(value.nextTokenId, "NEXT_TOKEN_ID").toString(),
    token1Owner: ethers.getAddress(value.token1Owner),
    token2Owner: ethers.getAddress(value.token2Owner),
    p2ReplayConsumed: value.p2ReplayConsumed,
    p3ReplayConsumed: value.p3ReplayConsumed
  });
  if (!/^0x[0-9a-f]{64}$/u.test(state.accountCodeHash)
    || typeof state.frozen !== "boolean" || typeof state.recoveryActive !== "boolean"
    || typeof state.recoveryAuthorityRotationActive !== "boolean"
    || typeof state.p2ReplayConsumed !== "boolean"
    || typeof state.p3ReplayConsumed !== "boolean") {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_STATE_INVALID");
  }
  return state;
}

function assertProtectedFileBinding(actual, expected) {
  if (typeof expected !== "string" || !/^[0-9a-f]{64}$/u.test(expected)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_EXPECTED_PROTECTED_FILE_SHA_INVALID");
  }
  if (typeof actual !== "string" || !/^[0-9a-f]{64}$/u.test(actual)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PROTECTED_FILE_SHA_INVALID");
  }
  if (actual !== expected) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PROTECTED_FILE_SHA_MISMATCH");
  }
  return actual;
}

function expectedPostState(state, prefund) {
  const exact = normalizeState(state);
  const terminalMaximum = asUint(
    prefund?.maximumTerminalEntryPointDepositWei,
    "MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT"
  ).toString();
  return Object.freeze({
    condition: "SUCCESSFUL_EXACT_STATE_P5_CLEANUP",
    lane0Nonce: Object.freeze({
      planned: exact.nonce,
      expectedAfterSuccess: (BigInt(exact.nonce) + 1n).toString()
    }),
    smartAccountNativeBalanceWei: "0",
    entryPointDepositWei: Object.freeze({
      knowledgeBeforeInclusion: "UNKNOWN",
      successUpperBoundWei: terminalMaximum,
      relation:
        "LESS_THAN_OR_EQUAL_TO_PLAN_SELECTED_MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT_WEI"
    }),
    owner: exact.owner,
    passBalance: exact.passBalance,
    token1Owner: exact.token1Owner,
    token2Owner: exact.token2Owner,
    nextTokenId: exact.nextTokenId,
    p2ReplayConsumed: true,
    p3ReplayConsumed: true,
    frozen: false,
    recoveryActive: false,
    recoveryAuthorityRotationActive: false,
    infrastructure: Object.freeze({
      actionGate: "UNCHANGED",
      consumer: "UNCHANGED",
      factory: "UNCHANGED"
    })
  });
}

function structuralRefundLimitation(prefund, gasSelectionBasis) {
  const selectedMaximum = asUint(
    prefund?.maximumTerminalEntryPointDepositWei,
    "MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT"
  );
  const fixedMaximum = asUint(
    gasSelectionBasis?.ceilingExposureAtFeeCap?.maximumTerminalEntryPointDepositWei,
    "FIXED_POLICY_MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT"
  );
  if (selectedMaximum > fixedMaximum) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SELECTED_REFUND_BOUND_EXCEEDS_POLICY");
  }
  return Object.freeze({
    exactZeroEntryPointDepositPromised: false,
    unusedPrefundRefundTiming: "AFTER_ACCOUNT_EXECUTION",
    finalEntryPointDepositKnownBeforeInclusion: false,
    successUpperBoundRelation:
      "LESS_THAN_OR_EQUAL_TO_PLAN_SELECTED_MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT_WEI",
    planSelectedMaximumTerminalEntryPointDepositWei: selectedMaximum.toString(),
    fixedPolicyOuterMaximumTerminalEntryPointDepositWei: fixedMaximum.toString(),
    fixedPolicyOuterCeilingIsOwnerApprovedResidual: false
  });
}

function assertOwnerReviewBindings(plan) {
  const requiredPostState = expectedPostState(plan.account, plan.prefund);
  if (!plan.expectedPostState
    || common.canonicalJson(plan.expectedPostState)
      !== common.canonicalJson(requiredPostState)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_EXPECTED_POST_STATE_INVALID");
  }
  if (!Array.isArray(plan.residualRisks) || plan.residualRisks.length !== 1
    || common.canonicalJson(plan.residualRisks[0]) !== common.canonicalJson(P5_R_L01)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_RESIDUAL_RISK_DISCLOSURE_INVALID");
  }
  const requiredRefundLimitation = structuralRefundLimitation(
    plan.prefund, plan.userOperation?.gasAndFeeSelection
  );
  if (!plan.structuralRefundLimitation
    || common.canonicalJson(plan.structuralRefundLimitation)
      !== common.canonicalJson(requiredRefundLimitation)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_STRUCTURAL_REFUND_LIMITATION_INVALID");
  }
  return true;
}

function assertStatePair(left, right) {
  const normalizedLeft = normalizeState(left);
  const normalizedRight = normalizeState(right);
  if (common.canonicalJson(normalizedLeft) !== common.canonicalJson(normalizedRight)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PROVIDER_DISAGREEMENT");
  }
  return normalizedLeft;
}

function assertStateEqualsPlan(live, planned) {
  const current = normalizeState(live);
  const expected = normalizeState(planned);
  if (common.canonicalJson(current) !== common.canonicalJson(expected)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_EXACT_PRESTATE_CHANGED");
  }
  return current;
}

function rpcV07(userOperation) {
  return {
    sender: ethers.getAddress(userOperation.sender),
    nonce: ethers.toQuantity(asUint(userOperation.nonce, "NONCE")),
    factory: null,
    factoryData: null,
    callData: userOperation.callData,
    callGasLimit: ethers.toQuantity(gasFields(userOperation).callGasLimit),
    verificationGasLimit: ethers.toQuantity(gasFields(userOperation).verificationGasLimit),
    preVerificationGas: ethers.toQuantity(asUint(userOperation.preVerificationGas, "PRE_VERIFICATION_GAS")),
    maxFeePerGas: ethers.toQuantity(gasFields(userOperation).maxFeePerGas),
    maxPriorityFeePerGas: ethers.toQuantity(gasFields(userOperation).maxPriorityFeePerGas),
    paymaster: null,
    paymasterVerificationGasLimit: null,
    paymasterPostOpGasLimit: null,
    paymasterData: null,
    signature: userOperation.signature
  };
}

function configuredGasPolicy(config) {
  const inheritedFeePolicy = config?.gasPolicy;
  const result = Object.freeze({
    verificationGasLimit: P5_FIXED_GAS_CEILINGS.verificationGasLimit,
    callGasLimit: P5_FIXED_GAS_CEILINGS.callGasLimit,
    preVerificationGas: P5_FIXED_GAS_CEILINGS.preVerificationGas,
    maxFeePerGas: P5_MAX_FEE_PER_GAS,
    maxPriorityFeePerGas: asUint(inheritedFeePolicy?.maxPriorityFeePerGas,
      "CONFIGURED_PRIORITY_FEE")
  });
  if (result.maxPriorityFeePerGas < P5_BUNDLER_PRIORITY_FEE_FLOOR
    || result.maxPriorityFeePerGas > result.maxFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_GAS_POLICY_INVALID");
  }
  return result;
}

function margin125(value) {
  return (value * 5n + 3n) / 4n;
}

const P5_FIXED_GAS_CEILINGS = Object.freeze({
  verificationGasLimit: P5_SELECTED_VERIFICATION_GAS,
  callGasLimit: margin125(margin125(P5_REVIEWED_CLEANUP_GAS_ESTIMATE.callGasLimit)),
  preVerificationGas:
    margin125(margin125(P5_REVIEWED_CLEANUP_GAS_ESTIMATE.preVerificationGas))
});

function p5GasCeilingExposure(config) {
  const bounded = configuredGasPolicy(config);
  const maximumGas = bounded.verificationGasLimit + bounded.callGasLimit
    + bounded.preVerificationGas;
  const maximumPrefund = maximumGas * bounded.maxFeePerGas;
  return Object.freeze({
    maximumGas: maximumGas.toString(),
    maximumPrefundWei: maximumPrefund.toString(),
    maximumTerminalEntryPointDepositWei: maximumPrefund.toString(),
    maxFeePerGas: bounded.maxFeePerGas.toString()
  });
}

function selectP5GasPolicy({ estimate, feeData, config, verificationGasEvidence }) {
  const bounded = configuredGasPolicy(config);
  const basis = normalizeEstimate(estimate);
  const currentMaxFee = asUint(feeData?.maxFeePerGas, "CURRENT_MAX_FEE", { positive: true });
  const currentPriority = asUint(feeData?.maxPriorityFeePerGas, "CURRENT_PRIORITY_FEE");
  const priorityWithMargin = margin125(currentPriority);
  const selectedPriority = priorityWithMargin > P5_BUNDLER_PRIORITY_FEE_FLOOR
    ? priorityWithMargin : P5_BUNDLER_PRIORITY_FEE_FLOOR;
  const selected = Object.freeze({
    verificationGasLimit: P5_SELECTED_VERIFICATION_GAS,
    callGasLimit: margin125(basis.callGasLimit),
    preVerificationGas: margin125(basis.preVerificationGas),
    maxFeePerGas: margin125(currentMaxFee),
    maxPriorityFeePerGas: selectedPriority
  });
  for (const field of ["verificationGasLimit", "callGasLimit", "preVerificationGas",
    "maxFeePerGas", "maxPriorityFeePerGas"]) {
    if (selected[field] > bounded[field]) {
      common.fail("PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_MARGIN_EXCEEDS_CONFIGURED_CAP");
    }
  }
  if (selected.maxPriorityFeePerGas > selected.maxFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_GAS_POLICY_INVALID");
  }
  const verificationEfficiency = assessP5VerificationEfficiency({
    evidence: verificationGasEvidence,
    verificationGasLimit: selected.verificationGasLimit
  });
  return Object.freeze({
    selected,
    basis: Object.freeze({
      marginNumerator: "5",
      marginDenominator: "4",
      fixedGasCeilings: Object.fromEntries(Object.entries(P5_FIXED_GAS_CEILINGS).map(
        ([key, value]) => [key, value.toString()]
      )),
      reviewedCleanupEstimate: Object.fromEntries(Object.entries(
        P5_REVIEWED_CLEANUP_GAS_ESTIMATE
      ).map(([key, value]) => [key, value.toString()])),
      ceilingDerivation:
        "verificationGasLimit is evidence-selected; callGasLimit and preVerificationGas use ceil(raw*5/4); fixed call/preVerification ceilings permit one bounded 25% raw-estimate growth window",
      ceilingExposureAtFeeCap: p5GasCeilingExposure(config),
      estimate: Object.fromEntries(Object.entries(basis).map(
        ([key, value]) => [key, value.toString()]
      )),
      feeData: {
        maxFeePerGas: currentMaxFee.toString(),
        maxPriorityFeePerGas: currentPriority.toString()
      },
      priorityFeeAdmission: Object.freeze({
        selectionFormula:
          "max(ceil(rawMaxPriorityFeePerGas*5/4),bundlerPriorityFeeFloorWei)",
        rawMaxPriorityFeePerGas: currentPriority.toString(),
        marginSelectedWei: priorityWithMargin.toString(),
        bundlerPriorityFeeFloorWei: P5_BUNDLER_PRIORITY_FEE_FLOOR.toString(),
        absolutePriorityFeeCapWei: bounded.maxPriorityFeePerGas.toString(),
        selectedMaxPriorityFeePerGas: selectedPriority.toString()
      }),
      verificationEfficiency
    })
  });
}

function provisionalP5GasPolicy(config) {
  return Object.freeze(Object.fromEntries(Object.entries(
    common.p2FinalGasPolicy(config.gasPolicy)
  ).map(([key, value]) => [key, BigInt(value)])));
}

function assertCleanupReady(exactState, config) {
  if (!common.sameAddress(exactState.account, config.account.predictedAddress)
    || !common.sameAddress(exactState.entryPoint, config.entryPoint)
    || !common.sameAddress(exactState.owner, config.account.initialExecutionValidator)
    || exactState.frozen || exactState.recoveryActive
    || exactState.recoveryAuthorityRotationActive
    || !exactState.p2ReplayConsumed || !exactState.p3ReplayConsumed) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_LIVE_STATE_NOT_CLEANUP_READY");
  }
}

function createUnsignedOperation({ config, state, gasPolicy = configuredGasPolicy(config) }) {
  const exactState = normalizeState(state);
  assertCleanupReady(exactState, config);
  const gas = Object.freeze(Object.fromEntries(Object.entries(gasPolicy).map(([key, value]) => [
    key, asUint(value, `SELECTED_${key.toUpperCase()}`, {
      positive: key !== "maxPriorityFeePerGas"
    })
  ])));
  const capEstimate = {
    verificationGasLimit: gas.verificationGasLimit,
    callGasLimit: gas.callGasLimit,
    preVerificationGas: gas.preVerificationGas
  };
  const prefund = prefundModel({
    nativeBalanceWei: exactState.nativeBalanceWei,
    entryPointDepositWei: exactState.entryPointDepositWei,
    gas,
    estimate: capEstimate
  });
  const callData = accountInterface.encodeFunctionData("releaseTestFunds", [
    prefund.releasableNativeWei,
    prefund.withdrawableEntryPointDepositWei
  ]);
  const userOperation = Object.freeze({
    sender: ethers.getAddress(config.account.predictedAddress),
    nonce: exactState.nonce,
    initCode: "0x",
    callData,
    accountGasLimits: preparation.packPhilCore4337AccountGasLimits(gas),
    preVerificationGas: gas.preVerificationGas.toString(),
    gasFees: preparation.packPhilCore4337GasFees(gas),
    paymasterAndData: "0x",
    signature: "0x"
  });
  const userOperationHash = preparation.computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: config.entryPoint,
    chainId: common.CHAIN_ID
  });
  return Object.freeze({
    state: exactState,
    gas,
    prefund,
    callData,
    callDataHash: ethers.keccak256(callData),
    userOperation,
    userOperationHash,
    estimationRpc: rpcV07({ ...userOperation, signature: ESTIMATION_SIGNATURE })
  });
}

function assertUnsignedOperationBinding(plan, config) {
  const op = plan?.userOperation?.packed;
  if (!op || op.signature !== "0x" || op.initCode !== "0x" || op.paymasterAndData !== "0x"
    || !common.sameAddress(op.sender, plan.account?.account)
    || !common.sameAddress(op.sender, config.account.predictedAddress)
    || asUint(op.nonce, "NONCE") !== BigInt(plan.account?.nonce)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_OPERATION_INVALID");
  }
  const localHash = preparation.computePhilCore4337UserOperationHash({
    userOperation: op,
    entryPointAddress: plan.entryPoint,
    chainId: Number(plan.chainId)
  });
  if (localHash.toLowerCase() !== String(plan.userOperation.hash).toLowerCase()
    || op.callData.toLowerCase() !== String(plan.cleanup?.callData).toLowerCase()
    || ethers.keccak256(op.callData).toLowerCase()
      !== String(plan.cleanup?.callDataHash).toLowerCase()
    || common.canonicalJson(rpcV07(op)) !== common.canonicalJson(plan.userOperation.rpc)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_OPERATION_INVALID");
  }
  return Object.freeze({ userOperation: op, userOperationHash: localHash });
}

function parseSignedArtifact(artifact, plan, config) {
  if (artifact?.format !== ARTIFACT_FORMAT || artifact.version !== 2
    || artifact.stageId !== STAGE_ID || artifact.lineageId !== plan.lineageId
    || artifact.signed !== true
    || artifact.submitted !== false || artifact.additionalFundingWei !== "0"
    || artifact.planDigest !== plan.planDigest
    || artifact.planCanonicalSha256 !== common.canonicalSha256(plan)
    || artifact.source?.commit !== plan.source?.commit
    || artifact.source?.tree !== plan.source?.tree
    || !common.sameAddress(artifact.owner, plan.account?.owner)
    || String(artifact.userOperationHash).toLowerCase()
      !== String(plan.userOperation?.hash).toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID");
  }
  const op = artifact.userOperation;
  if (!op || op.initCode !== "0x" || op.paymasterAndData !== "0x"
    || !common.sameAddress(op.sender, config.account.predictedAddress)
    || asUint(op.nonce, "NONCE") !== BigInt(plan.account.nonce)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_BINDING_INVALID");
  }
  const unsigned = { ...op, signature: "0x" };
  if (common.canonicalJson(unsigned) !== common.canonicalJson(plan.userOperation.packed)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_BINDING_INVALID");
  }
  const localHash = preparation.computePhilCore4337UserOperationHash({
    userOperation: op,
    entryPointAddress: plan.entryPoint,
    chainId: Number(plan.chainId)
  });
  if (localHash.toLowerCase() !== String(plan.userOperation.hash).toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_HASH_INVALID");
  }
  let recovered;
  try { recovered = ethers.verifyMessage(ethers.getBytes(localHash), op.signature); } catch {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID");
  }
  if (!common.sameAddress(recovered, plan.account.owner)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID");
  }
  return Object.freeze({
    userOperation: op,
    rpc: rpcV07(op),
    gas: gasFields(op),
    callData: op.callData,
    callDataHash: ethers.keccak256(op.callData),
    userOperationHash: localHash,
    owner: ethers.getAddress(recovered)
  });
}

function createPlan({ lineageId, source, runnerReview, config, state, estimate, feeData,
  gasSelection = selectP5GasPolicy({ estimate, feeData, config }),
  endpointBindings, endpoints, compiler }) {
  const exactLineageId = assertFutureLineageId(lineageId);
  assertP5VerificationEfficiency(gasSelection?.basis?.verificationEfficiency);
  const draft = createUnsignedOperation({ config, state, gasPolicy: gasSelection.selected });
  const exactState = draft.state;
  const prefund = prefundModel({
    nativeBalanceWei: exactState.nativeBalanceWei,
    entryPointDepositWei: exactState.entryPointDepositWei,
    gas: draft.gas,
    estimate
  });
  if (prefund.releasableNativeWei !== draft.prefund.releasableNativeWei
    || prefund.withdrawableEntryPointDepositWei
      !== draft.prefund.withdrawableEntryPointDepositWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_CLEANUP_ARITHMETIC_CHANGED");
  }
  const maxFee = draft.gas.maxFeePerGas;
  const maxPriority = draft.gas.maxPriorityFeePerGas;
  if (asUint(feeData?.maxFeePerGas, "CURRENT_MAX_FEE", { positive: true }) > maxFee
    || asUint(feeData?.maxPriorityFeePerGas, "CURRENT_PRIORITY_FEE") > maxPriority) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_CONFIGURED_FEE_CAP_STALE");
  }
  if (runnerReview?.reviewedCommit !== source.commit
    || runnerReview?.reviewedTree !== source.tree
    || runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    || !/^0x[0-9a-f]{64}$/u.test(runnerReview?.reportSha256 || "")) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_RUNNER_REVIEW_INVALID");
  }
  assertProtectedFileBinding(
    source?.protectedUntrackedFileSha256, common.PROTECTED_FILE_SHA256
  );
  const postState = expectedPostState(exactState, prefund);
  const refundLimitation = structuralRefundLimitation(prefund, gasSelection.basis);
  const body = {
    format: PLAN_FORMAT,
    version: 2,
    stageId: STAGE_ID,
    lineageId: exactLineageId,
    lineage: Object.freeze({
      lineageId: exactLineageId,
      attemptNumber: String(Number(exactLineageId.slice(-4))),
      priorAttemptLineageId: CONSUMED_ATTEMPT_1_LINEAGE_ID,
      priorAttemptDisposition: "ATTEMPT_CONSUMED_RESUBMISSION_FORBIDDEN",
      priorPlanDigest:
        "0x7e0bba321eefbaa0584ab46d9625d0d163a26bb3cb0b52ef3c44dcae684e4e97",
      priorUserOperationHash:
        "0xade275d0de8db399a4f829e47b5b20b7212c84571762f70584567bbeee64503e"
    }),
    status: "EXACT_P5_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt: new Date().toISOString(),
    source,
    runnerReview,
    compiler,
    chainId: String(common.CHAIN_ID),
    entryPoint: config.entryPoint,
    endpoints,
    endpointBindings,
    account: {
      ...exactState,
      deployed: true,
      destinationSemantics: "releaseTestFunds -> hard-coded current owner"
    },
    cleanup: {
      function: "releaseTestFunds(uint256,uint256)",
      selector: RELEASE_SELECTOR,
      currentOwner: exactState.owner,
      destinationPolicy: "CURRENT_EXECUTION_OWNER_ONLY",
      nativeAmountWei: prefund.releasableNativeWei,
      entryPointDepositAmountWei: prefund.withdrawableEntryPointDepositWei,
      callValueWei: "0",
      callData: draft.callData,
      callDataHash: draft.callDataHash
    },
    prefund,
    expectedPostState: postState,
    residualRisks: Object.freeze([P5_R_L01]),
    structuralRefundLimitation: refundLimitation,
    signing: {
      required: true,
      status: "NOT_SIGNED",
      format: ARTIFACT_FORMAT,
      owner: exactState.owner,
      exactPlanRequired: true,
      publicSubmissionAuthorized: false
    },
    userOperation: {
      hash: draft.userOperationHash,
      hashSemantics: "ERC4337_V07_PACKED_USER_OPERATION_HASH_EXCLUDES_SIGNATURE",
      packed: draft.userOperation,
      rpc: rpcV07(draft.userOperation),
      estimate: Object.fromEntries(Object.entries(normalizeEstimate(estimate)).map(
        ([key, value]) => [key, value.toString()]
      )),
      gasAndFeeSelection: gasSelection.basis,
      submissionAttemptsAllowed: 1
    },
    maximumAdditionalFundingWei: "0",
    publicMutationCount: 1,
    publicMutationOccurred: false,
    automaticRetryAllowed: false,
    ambiguityPolicy: "RECONCILE_EXACT_HASH_NEVER_RESUBMIT",
    mutations: [{
      order: 1,
      kind: "SUBMIT_P5_RELEASE_TEST_FUNDS_USER_OPERATION",
      target: config.entryPoint,
      userOperationHash: draft.userOperationHash,
      valueWei: "0"
    }],
    approval: { requiredPhrase: null, approved: false }
  };
  const planDigest = common.canonicalSha256(body);
  body.approval.requiredPhrase = common.approvalPhrase(STAGE_ID, planDigest);
  return Object.freeze({ ...body, planDigest });
}

function assertPlanIntegrity(plan, config = common.loadConfiguration()) {
  assertProtectedFileBinding(
    plan?.source?.protectedUntrackedFileSha256, common.PROTECTED_FILE_SHA256
  );
  const body = { ...plan };
  delete body.planDigest;
  body.approval = { requiredPhrase: null, approved: false };
  const digest = common.canonicalSha256(body);
  if (plan?.format !== PLAN_FORMAT || plan.version !== 2 || plan.stageId !== STAGE_ID
    || assertFutureLineageId(plan.lineageId) !== plan.lineageId
    || plan.lineage?.lineageId !== plan.lineageId
    || plan.lineage?.attemptNumber !== String(Number(plan.lineageId.slice(-4)))
    || plan.lineage?.priorAttemptLineageId !== CONSUMED_ATTEMPT_1_LINEAGE_ID
    || plan.lineage?.priorAttemptDisposition
      !== "ATTEMPT_CONSUMED_RESUBMISSION_FORBIDDEN"
    || plan.lineage?.priorPlanDigest
      !== "0x7e0bba321eefbaa0584ab46d9625d0d163a26bb3cb0b52ef3c44dcae684e4e97"
    || plan.lineage?.priorUserOperationHash
      !== "0xade275d0de8db399a4f829e47b5b20b7212c84571762f70584567bbeee64503e"
    || plan.status !== "EXACT_P5_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.planDigest !== digest
    || plan.approval?.requiredPhrase !== common.approvalPhrase(STAGE_ID, digest)
    || plan.approval?.approved !== false || plan.publicMutationCount !== 1
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.maximumAdditionalFundingWei !== "0" || plan.mutations?.length !== 1
    || plan.userOperation?.submissionAttemptsAllowed !== 1
    || plan.userOperation?.packed?.signature !== "0x"
    || plan.userOperation?.packed?.initCode !== "0x"
    || plan.userOperation?.packed?.paymasterAndData !== "0x"
    || plan.cleanup?.selector !== RELEASE_SELECTOR
    || plan.cleanup?.destinationPolicy !== "CURRENT_EXECUTION_OWNER_ONLY"
    || plan.cleanup?.callValueWei !== "0"
    || plan.prefund?.externalFundingWei !== "0"
    || plan.prefund?.exactZeroEntryPointDepositPromised !== false
    || plan.prefund?.ownerAcceptanceRequired !== true
    || plan.prefund?.maximumTerminalEntryPointDepositWei
      !== plan.prefund?.maximumPrefundWei
    || plan.chainId !== String(common.CHAIN_ID)
    || !common.sameAddress(plan.entryPoint, config.entryPoint)
    || !common.sameAddress(plan.account?.account, config.account.predictedAddress)
    || !common.sameAddress(plan.account?.owner, config.account.initialExecutionValidator)
    || plan.signing?.required !== true || plan.signing?.status !== "NOT_SIGNED"
    || plan.signing?.format !== ARTIFACT_FORMAT
    || plan.signing?.exactPlanRequired !== true
    || plan.signing?.publicSubmissionAuthorized !== false
    || !/^[0-9a-f]{40}$/u.test(plan.source?.commit || "")
    || !/^[0-9a-f]{40}$/u.test(plan.source?.tree || "")
    || plan.source?.protectedUntrackedFile !== "pqREADME.md"
    || plan.runnerReview?.reviewedCommit !== plan.source.commit
    || plan.runnerReview?.reviewedTree !== plan.source.tree
    || plan.runnerReview?.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    || !/^0x[0-9a-f]{64}$/u.test(plan.runnerReview?.reportSha256 || "")
    || plan.mutations[0]?.order !== 1
    || plan.mutations[0]?.kind !== "SUBMIT_P5_RELEASE_TEST_FUNDS_USER_OPERATION"
    || !common.sameAddress(plan.mutations[0]?.target, config.entryPoint)
    || plan.mutations[0]?.userOperationHash !== plan.userOperation?.hash
    || plan.mutations[0]?.valueWei !== "0") {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID");
  }
  assertOwnerReviewBindings(plan);
  const bound = assertUnsignedOperationBinding(plan, config);
  const selected = selectP5GasPolicy({
    estimate: plan.userOperation.gasAndFeeSelection?.estimate,
    feeData: plan.userOperation.gasAndFeeSelection?.feeData,
    verificationGasEvidence:
      plan.userOperation.gasAndFeeSelection?.verificationEfficiency?.evidence,
    config
  });
  assertP5VerificationEfficiency(selected.basis.verificationEfficiency);
  if (common.canonicalJson(selected.basis)
    !== common.canonicalJson(plan.userOperation.gasAndFeeSelection)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID");
  }
  const derived = createUnsignedOperation({
    config, state: plan.account, gasPolicy: selected.selected
  });
  if (common.canonicalJson(bound.userOperation) !== common.canonicalJson(derived.userOperation)
    || plan.cleanup.nativeAmountWei !== derived.prefund.releasableNativeWei
    || plan.cleanup.entryPointDepositAmountWei
      !== derived.prefund.withdrawableEntryPointDepositWei
    || plan.cleanup.callData !== derived.callData
    || plan.cleanup.callDataHash !== derived.callDataHash
    || plan.prefund.maximumPrefundWei !== derived.prefund.maximumPrefundWei
    || plan.prefund.missingAccountFundsWei !== derived.prefund.missingAccountFundsWei
    || plan.prefund.withdrawableEntryPointDepositWei
      !== derived.prefund.withdrawableEntryPointDepositWei
    || plan.prefund.releasableNativeWei !== derived.prefund.releasableNativeWei) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID");
  }
  prefundModel({
    nativeBalanceWei: plan.account.nativeBalanceWei,
    entryPointDepositWei: plan.account.entryPointDepositWei,
    gas: gasFields(plan.userOperation.packed),
    estimate: plan.userOperation.estimate
  });
  return plan;
}

function assertPlan(plan, approvedDigest, config = common.loadConfiguration()) {
  assertPlanIntegrity(plan, config);
  if (plan.planDigest !== String(approvedDigest).toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID");
  }
  return plan;
}

function assertArtifactBinding(plan, planBytes, artifact, bytes, config) {
  if (!artifact || !bytes) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID");
  }
  let artifactFromBytes;
  try { artifactFromBytes = JSON.parse(bytes); } catch {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID");
  }
  if (artifact.planByteSha256 !== common.sha256Bytes(planBytes)
    || common.canonicalJson(artifactFromBytes) !== common.canonicalJson(artifact)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_BINDING_INVALID");
  }
  return parseSignedArtifact(artifact, plan, config);
}

function assertFeeAndEstimate(plan, estimate, feeData) {
  const parsedEstimate = normalizeEstimate(estimate);
  const gas = gasFields(plan.userOperation.packed);
  if (parsedEstimate.verificationGasLimit > gas.verificationGasLimit
    || parsedEstimate.callGasLimit > gas.callGasLimit
    || parsedEstimate.preVerificationGas > gas.preVerificationGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_EXCEEDS_SIGNED_LIMIT");
  }
  if (gas.maxPriorityFeePerGas < P5_BUNDLER_PRIORITY_FEE_FLOOR) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_PRIORITY_FEE_ADMISSION_FLOOR_NOT_MET");
  }
  if (asUint(feeData?.maxFeePerGas, "CURRENT_MAX_FEE", { positive: true }) > gas.maxFeePerGas
    || asUint(feeData?.maxPriorityFeePerGas, "CURRENT_PRIORITY_FEE")
      > gas.maxPriorityFeePerGas) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNED_FEE_CAP_STALE");
  }
  return true;
}

function acquireExecutionLock(plan, target) {
  assertFutureLineageId(plan?.lineageId);
  const exactTarget = target ?? lineagePaths(plan.lineageId).executionLock;
  const record = Object.freeze({
    format: "philcore-controlled-sepolia-beta-p5-execution-attempt-lock-v2",
    version: 2,
    stageId: STAGE_ID,
    lineageId: plan.lineageId,
    planDigest: plan.planDigest,
    source: plan.source,
    acquiredAt: new Date().toISOString(),
    publicMutationOccurredAtAcquisition: false,
    automaticRetryAllowed: false,
    disposition: "PERSIST_PERMANENTLY_AFTER_ONE_SEND_ATTEMPT"
  });
  try { common.atomicCreateJson(exactTarget, record); } catch (error) {
    if (error?.code === "EEXIST") {
      common.fail("PHILCORE_CONTROLLED_BETA_P5_EXECUTION_ALREADY_ATTEMPTED");
    }
    throw error;
  }
  return record;
}

function classifySendDisposition(error, returnedHash) {
  if (returnedHash !== null && returnedHash !== undefined) return "ACCEPTED_HASH_RETURNED";
  const text = `${error?.code || ""} ${error?.message || error || ""}`.toLowerCase();
  if (/timeout|timed out|disconnect|socket|network|econn|transport|http 5\d\d/u.test(text)) {
    return "AMBIGUOUS_TRANSPORT_RESULT";
  }
  return "REJECTED_BEFORE_BUNDLER_ACCEPTANCE";
}

function eventMatches(receipt, address, iface, name) {
  const matches = [];
  for (const log of receipt?.logs || []) {
    if (!common.sameAddress(log.address, address)) continue;
    try {
      const parsed = iface.parseLog(log);
      if (parsed?.name === name) matches.push(parsed);
    } catch {}
  }
  return matches;
}

function assertOperationLookupBinding(plan, operation) {
  if (!operation) return;
  const found = operation.userOperation || operation;
  if (!found?.sender || found.nonce === undefined || !found.callData
    || !common.sameAddress(found.sender, plan.account.account)
    || asUint(found.nonce, "LOOKUP_NONCE") !== BigInt(plan.account.nonce)
    || found.callData.toLowerCase() !== plan.cleanup.callData.toLowerCase()
    || (operation.entryPoint && !common.sameAddress(operation.entryPoint, plan.entryPoint))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_LOOKUP_INVALID");
  }
}

function assertUserOperationReceiptBinding(plan, receipt) {
  if (!receipt) return;
  if (!/^0x[0-9a-f]{64}$/iu.test(receipt.userOpHash || "")
    || receipt.userOpHash.toLowerCase() !== plan.userOperation.hash.toLowerCase()
    || !common.sameAddress(receipt.sender, plan.account.account)
    || asUint(receipt.nonce, "RECEIPT_NONCE") !== BigInt(plan.account.nonce)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_RECEIPT_INVALID");
  }
}

function classifyOperationEvidence({ plan, operation, userOperationReceipt,
  transactionReceipt, finalState, sendDisposition = null }) {
  assertOperationLookupBinding(plan, operation);
  assertUserOperationReceiptBinding(plan, userOperationReceipt);
  if (!operation && !userOperationReceipt && !transactionReceipt) {
    if (sendDisposition === "REJECTED_BEFORE_BUNDLER_ACCEPTANCE") {
      return Object.freeze({
        status: "REJECTED_BEFORE_BUNDLER_ACCEPTANCE", retryAllowed: false
      });
    }
    if (sendDisposition === "AMBIGUOUS_TRANSPORT_RESULT") {
      return Object.freeze({
        status: "AMBIGUOUS_TRANSPORT_RESULT_REQUIRES_HUMAN_REVIEW", retryAllowed: false
      });
    }
    if (sendDisposition === "ACCEPTED_HASH_RETURNED") {
      return Object.freeze({ status: "ACCEPTED_NOT_YET_INCLUDED", retryAllowed: false });
    }
    return Object.freeze({
      status: "ABSENT_OPERATION_REQUIRES_HUMAN_REVIEW", retryAllowed: false
    });
  }
  if (operation && !userOperationReceipt) {
    return Object.freeze({ status: "ACCEPTED_NOT_YET_INCLUDED", retryAllowed: false });
  }
  if (!userOperationReceipt || !transactionReceipt) {
    return Object.freeze({
      status: "AMBIGUOUS_TRANSPORT_RESULT_REQUIRES_HUMAN_REVIEW", retryAllowed: false
    });
  }
  const userEvents = eventMatches(
    transactionReceipt, plan.entryPoint, entryPointInterface, "UserOperationEvent"
  );
  const revertEvents = eventMatches(
    transactionReceipt, plan.entryPoint, entryPointInterface, "UserOperationRevertReason"
  );
  const releaseEvents = eventMatches(
    transactionReceipt, plan.account.account, accountInterface, "TestFundsReleased"
  );
  const withdrawEvents = eventMatches(
    transactionReceipt, plan.entryPoint, entryPointInterface, "Withdrawn"
  );
  const event = userEvents[0];
  const includedFailure = transactionReceipt.status === 1
    && (userOperationReceipt.success !== true || event?.args?.success !== true
      || revertEvents.length !== 0 || releaseEvents.length !== 1);
  if (includedFailure) {
    return Object.freeze({
      status: "INCLUDED_USER_OPERATION_EXECUTION_FAILED",
      retryAllowed: false,
      nonceAndGasConsequencesRequireReconciliation: true
    });
  }
  if (transactionReceipt.status !== 1 || userEvents.length !== 1 || releaseEvents.length !== 1
    || String(event.args.userOpHash).toLowerCase() !== plan.userOperation.hash.toLowerCase()
    || !common.sameAddress(event.args.sender, plan.account.account)
    || BigInt(event.args.nonce) !== BigInt(plan.account.nonce)
    || !common.sameAddress(releaseEvents[0].args.recipient, plan.account.owner)
    || releaseEvents[0].args.nativeAmountWei.toString() !== plan.cleanup.nativeAmountWei
    || releaseEvents[0].args.entryPointDepositAmountWei.toString()
      !== plan.cleanup.entryPointDepositAmountWei
    || withdrawEvents.length !== (BigInt(plan.cleanup.entryPointDepositAmountWei) > 0n ? 1 : 0)
    || (withdrawEvents.length === 1
      && (!common.sameAddress(withdrawEvents[0].args.account, plan.account.account)
        || !common.sameAddress(withdrawEvents[0].args.withdrawAddress, plan.account.owner)
        || withdrawEvents[0].args.amount.toString()
          !== plan.cleanup.entryPointDepositAmountWei))) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_RECONCILIATION_EVENT_INVALID");
  }
  const final = normalizeState(finalState);
  if (!common.sameAddress(final.account, plan.account.account)
    || !common.sameAddress(final.owner, plan.account.owner)
    || !common.sameAddress(final.entryPoint, plan.account.entryPoint)
    || final.accountCodeHash !== plan.account.accountCodeHash
    || BigInt(final.nonce) !== BigInt(plan.account.nonce) + 1n
    || final.nativeBalanceWei !== "0"
    || BigInt(final.entryPointDepositWei)
      > BigInt(plan.prefund.maximumTerminalEntryPointDepositWei)
    || final.frozen !== plan.account.frozen
    || final.recoveryActive !== plan.account.recoveryActive
    || final.recoveryAuthorityRotationActive
      !== plan.account.recoveryAuthorityRotationActive
    || final.passBalance !== plan.account.passBalance
    || final.nextTokenId !== plan.account.nextTokenId
    || !common.sameAddress(final.token1Owner, plan.account.token1Owner)
    || !common.sameAddress(final.token2Owner, plan.account.token2Owner)
    || final.p2ReplayConsumed !== plan.account.p2ReplayConsumed
    || final.p3ReplayConsumed !== plan.account.p3ReplayConsumed) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_FINAL_STATE_INVALID");
  }
  return Object.freeze({
    status: "INCLUDED_SUCCESS_RECONCILED",
    retryAllowed: false,
    actualGasCostWei: event.args.actualGasCost.toString(),
    terminalEntryPointDepositWei: final.entryPointDepositWei
  });
}

async function readSnapshot(provider, config) {
  const account = new ethers.Contract(config.account.predictedAddress, accountInterface, provider);
  const entry = new ethers.Contract(config.entryPoint, entryPointInterface, provider);
  const gate = new ethers.Contract(config.infrastructure.actionGate, common.gateInterface, provider);
  const consumer = new ethers.Contract(
    config.infrastructure.mintConsumer, common.consumerInterface, provider
  );
  const code = await provider.getCode(config.account.predictedAddress);
  if (code === "0x") common.fail("PHILCORE_CONTROLLED_BETA_P5_ACCOUNT_NOT_DEPLOYED");
  const values = await Promise.all([
    account.owner(), account.entryPoint(), account.frozen(), account.recoveryRequest(),
    account.recoveryAuthorityRotationRequest(),
    entry.getNonce(config.account.predictedAddress, 0),
    provider.getBalance(config.account.predictedAddress),
    entry.balanceOf(config.account.predictedAddress),
    consumer.balanceOf(config.account.initialExecutionValidator), consumer.nextTokenId(),
    consumer.ownerOf(1n), consumer.ownerOf(2n),
    gate.consumedEnvelopeDigest(common.P2_FINAL_ORIGIN.authorizationEnvelopeDigest),
    gate.consumedRootNullifier(common.P2_FINAL_ORIGIN.rootProofNullifier),
    gate.consumedDeviceApprovalNonce(common.P2_FINAL_ORIGIN.deviceApprovalNonce),
    gate.consumedEnvelopeDigest(P3_REPLAY.authorizationEnvelopeDigest),
    gate.consumedRootNullifier(P3_REPLAY.rootProofNullifier),
    gate.consumedDeviceApprovalNonce(P3_REPLAY.deviceApprovalNonce)
  ]);
  return normalizeState({
    account: config.account.predictedAddress,
    owner: values[0],
    entryPoint: values[1],
    accountCodeHash: ethers.keccak256(code),
    frozen: values[2],
    recoveryActive: values[3][5],
    recoveryAuthorityRotationActive: values[4][6],
    nonce: values[5],
    nativeBalanceWei: values[6],
    entryPointDepositWei: values[7],
    passBalance: values[8],
    nextTokenId: values[9],
    token1Owner: values[10],
    token2Owner: values[11],
    p2ReplayConsumed: values.slice(12, 15).every((value) => value === true),
    p3ReplayConsumed: values.slice(15, 18).every((value) => value === true)
  });
}

async function readProviderPair(primary, reconciliation, config) {
  const [leftChain, rightChain, left, right] = await Promise.all([
    primary.send("eth_chainId", []), reconciliation.send("eth_chainId", []),
    readSnapshot(primary, config), readSnapshot(reconciliation, config)
  ]);
  if (BigInt(leftChain) !== BigInt(common.CHAIN_ID)
    || BigInt(rightChain) !== BigInt(common.CHAIN_ID)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P5_WRONG_CHAIN");
  }
  return assertStatePair(left, right);
}

module.exports = {
  ...common,
  STAGE_ID,
  RELEASE_SELECTOR,
  PLAN_FORMAT,
  ARTIFACT_FORMAT,
  RECEIPT_FORMAT,
  CONSUMED_ATTEMPT_1_LINEAGE_ID,
  DEFAULT_SIGNED_ARTIFACT_PATH,
  DEFAULT_PLAN_PATH,
  DEFAULT_RECEIPT_PATH,
  DEFAULT_EXECUTION_LOCK_PATH,
  ESTIMATION_SIGNATURE,
  P5_REVIEWED_CLEANUP_GAS_ESTIMATE,
  P5_MAX_FEE_PER_GAS,
  P5_BUNDLER_PRIORITY_FEE_FLOOR,
  P5_VERIFICATION_EFFICIENCY_NUMERATOR,
  P5_VERIFICATION_EFFICIENCY_DENOMINATOR,
  P5_VERIFICATION_SAFETY_MARGIN_NUMERATOR,
  P5_VERIFICATION_SAFETY_MARGIN_DENOMINATOR,
  P5_ACTUAL_VALIDATION_GAS,
  P5_MINIMUM_SAFE_VERIFICATION_GAS,
  P5_MAXIMUM_EFFICIENT_VERIFICATION_GAS,
  P5_SELECTED_VERIFICATION_GAS,
  P5_VERIFICATION_GAS_EVIDENCE_BODY,
  P5_VERIFICATION_GAS_EVIDENCE,
  P5_R_L01,
  P5_FIXED_GAS_CEILINGS,
  P3_REPLAY,
  accountInterface,
  entryPointInterface,
  computePhilCore4337UserOperationHash: preparation.computePhilCore4337UserOperationHash,
  assertFutureLineageId,
  lineagePaths,
  sanitizeDiagnosticText,
  rpcDataEvidence,
  classifyBundlerRejection,
  bundlerRejectionEvidence,
  assertP5VerificationGasEvidence,
  assessP5VerificationEfficiency,
  assertP5VerificationEfficiency,
  gasFields,
  normalizeEstimate,
  prefundModel,
  normalizeState,
  assertProtectedFileBinding,
  expectedPostState,
  structuralRefundLimitation,
  assertOwnerReviewBindings,
  assertStatePair,
  assertStateEqualsPlan,
  rpcV07,
  configuredGasPolicy,
  p5GasCeilingExposure,
  selectP5GasPolicy,
  provisionalP5GasPolicy,
  createUnsignedOperation,
  assertUnsignedOperationBinding,
  parseSignedArtifact,
  createPlan,
  assertPlanIntegrity,
  assertPlan,
  assertArtifactBinding,
  assertFeeAndEstimate,
  acquireExecutionLock,
  classifySendDisposition,
  assertOperationLookupBinding,
  assertUserOperationReceiptBinding,
  classifyOperationEvidence,
  readSnapshot,
  readProviderPair
};
