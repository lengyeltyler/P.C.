"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { ethers } = require("ethers");
require("tsx/cjs");

const preparation = require(
  "../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts"
);
const p5 = require("../../scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p5-common.cjs");
const executor = require(
  "../../scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p5.cjs"
);
const signer = require(
  "../../scripts/ethereum-sepolia/sign-philcore-controlled-sepolia-beta-p5.cjs"
);

const ROOT = path.resolve(__dirname, "../..");
const PLANNER = path.join(
  ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p5.cjs"
);
const EXECUTOR = path.join(
  ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p5.cjs"
);
const SIGNER = path.join(
  ROOT, "scripts/ethereum-sepolia/sign-philcore-controlled-sepolia-beta-p5.cjs"
);
const COMMON = path.join(
  ROOT, "scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p5-common.cjs"
);
const source = (location) => fs.readFileSync(location, "utf8");

function baseConfig(owner) {
  const config = JSON.parse(JSON.stringify(p5.loadConfiguration()));
  config.account.initialExecutionValidator = owner.address;
  config.gasPolicy = {
    ...config.gasPolicy,
    maxFeePerGas: GAS.maxFeePerGas.toString(),
    maxPriorityFeePerGas: GAS.maxPriorityFeePerGas.toString()
  };
  return config;
}

function stateFor(config, values = {}) {
  const owner = values.owner || config.account.initialExecutionValidator;
  return {
    account: config.account.predictedAddress,
    owner,
    entryPoint: config.entryPoint,
    accountCodeHash: `0x${"11".repeat(32)}`,
    nonce: values.nonce ?? "2",
    nativeBalanceWei: values.nativeBalanceWei ?? "10000000000000",
    entryPointDepositWei: values.entryPointDepositWei ?? "1000000000000",
    frozen: values.frozen ?? false,
    recoveryActive: values.recoveryActive ?? false,
    recoveryAuthorityRotationActive: values.recoveryAuthorityRotationActive ?? false,
    passBalance: values.passBalance ?? "2",
    nextTokenId: values.nextTokenId ?? "3",
    token1Owner: values.token1Owner || owner,
    token2Owner: values.token2Owner || owner,
    p2ReplayConsumed: values.p2ReplayConsumed ?? true,
    p3ReplayConsumed: values.p3ReplayConsumed ?? true
  };
}

const GAS = Object.freeze({
  verificationGasLimit: 100n,
  callGasLimit: 100n,
  preVerificationGas: 50n,
  maxFeePerGas: 100000000n,
  maxPriorityFeePerGas: 100000000n
});
const SELECTED_GAS = Object.freeze({
  ...GAS,
  verificationGasLimit: p5.P5_SELECTED_VERIFICATION_GAS
});
const ESTIMATE = Object.freeze({
  verificationGasLimit: 80n,
  callGasLimit: 80n,
  preVerificationGas: 40n
});

async function fixture(values = {}) {
  const owner = values.ownerWallet || new ethers.Wallet(`0x${"51".repeat(32)}`);
  const config = baseConfig(owner);
  const state = stateFor(config, values);
  const sourceIdentity = {
    commit: "a".repeat(40),
    tree: "b".repeat(40),
    protectedUntrackedFile: "pqREADME.md",
    protectedUntrackedFileSha256: p5.PROTECTED_FILE_SHA256
  };
  const feeData = { maxFeePerGas: 80000000n, maxPriorityFeePerGas: 4000000n };
  const gasSelection = p5.selectP5GasPolicy({
    estimate: ESTIMATE,
    feeData,
    config,
    verificationGasEvidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  const plan = p5.createPlan({
    lineageId: "p5-attempt-0002",
    source: sourceIdentity,
    runnerReview: {
      reviewedCommit: sourceIdentity.commit,
      reviewedTree: sourceIdentity.tree,
      reportSha256: `0x${"cd".repeat(32)}`,
      disposition: "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    },
    config,
    state,
    estimate: ESTIMATE,
    feeData,
    gasSelection,
    endpointBindings: {
      primaryRpcUrlSha256: `0x${"01".repeat(32)}`,
      reconciliationRpcUrlSha256: `0x${"02".repeat(32)}`,
      bundlerUrlSha256: `0x${"03".repeat(32)}`
    },
    endpoints: {
      primary: "https://primary.invalid/<redacted>",
      reconciliation: "https://reconciliation.invalid/<redacted>",
      bundler: "https://bundler.invalid/<redacted>"
    },
    compiler: { solcVersion: "fixture" }
  });
  const planBytes = Buffer.from(`${JSON.stringify(plan, null, 2)}\n`);
  const signature = await owner.signMessage(ethers.getBytes(plan.userOperation.hash));
  const artifact = signer.createSignedArtifact({ plan, planBytes, config, signature });
  const artifactBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  return { owner, config, state, prefund: plan.prefund, artifact, artifactBytes, plan, planBytes };
}

function realShapedPlan() {
  const owner = new ethers.Wallet(`0x${"61".repeat(32)}`);
  const config = JSON.parse(JSON.stringify(p5.loadConfiguration()));
  config.account.initialExecutionValidator = owner.address;
  const state = stateFor(config, {
    nativeBalanceWei: "3353861479486230",
    entryPointDepositWei: "700036093178300"
  });
  const rawEstimate = {
    verificationGasLimit: 150000n,
    callGasLimit: 300000n,
    preVerificationGas: 100000n
  };
  const feeData = { maxFeePerGas: 2229560190n, maxPriorityFeePerGas: 1000000n };
  const gasSelection = p5.selectP5GasPolicy({
    estimate: rawEstimate,
    feeData,
    config,
    verificationGasEvidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  const plan = p5.createPlan({
    lineageId: "p5-attempt-0002",
    source: {
      commit: "b1ad777e441f6e9dc8bb72934ce1b28a37d8baba",
      tree: "2be4f221eab169370c383414c53758897da1f66a",
      protectedUntrackedFile: "pqREADME.md",
      protectedUntrackedFileSha256: p5.PROTECTED_FILE_SHA256
    },
    runnerReview: {
      reviewedCommit: "b1ad777e441f6e9dc8bb72934ce1b28a37d8baba",
      reviewedTree: "2be4f221eab169370c383414c53758897da1f66a",
      reportSha256: `0x${"95".repeat(32)}`,
      disposition: "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH"
    },
    config,
    state,
    estimate: gasSelection.selected,
    feeData,
    gasSelection,
    endpointBindings: {
      primaryRpcUrlSha256: `0x${"11".repeat(32)}`,
      reconciliationRpcUrlSha256: `0x${"22".repeat(32)}`,
      bundlerUrlSha256: `0x${"33".repeat(32)}`
    },
    endpoints: {
      primary: "https://primary.invalid/<redacted>",
      reconciliation: "https://reconciliation.invalid/<redacted>",
      bundler: "https://bundler.invalid/<redacted>"
    },
    compiler: { solcVersion: "real-shaped-fixture" }
  });
  return { config, plan };
}

function changed(value, patch) {
  return { ...value, ...patch };
}

function redigest(plan) {
  const body = { ...plan };
  delete body.planDigest;
  body.approval = { requiredPhrase: null, approved: false };
  const planDigest = p5.canonicalSha256(body);
  return {
    ...body,
    approval: { requiredPhrase: p5.approvalPhrase("P5", planDigest), approved: false },
    planDigest
  };
}

test("P5 native-only fixture derives exact release amounts with zero new funding", async () => {
  const row = await fixture({
    nativeBalanceWei: "10000000000000", entryPointDepositWei: "1000000000000"
  });
  assert.equal(row.plan.cleanup.nativeAmountWei, "2985000000000");
  assert.equal(row.plan.cleanup.entryPointDepositAmountWei, "0");
  assert.equal(row.plan.prefund.missingAccountFundsWei, "7015000000000");
  assert.equal(row.plan.prefund.externalFundingWei, "0");
});

test("P5 deposit-only fixture is valid", async () => {
  const row = await fixture({ nativeBalanceWei: "0", entryPointDepositWei: "9000000000000" });
  assert.equal(row.plan.cleanup.nativeAmountWei, "0");
  assert.equal(row.plan.cleanup.entryPointDepositAmountWei, "985000000000");
});

test("P5 combined fixture releases native and the execution-time withdrawable deposit", async () => {
  const row = await fixture({
    nativeBalanceWei: "10000000000000", entryPointDepositWei: "9000000000000"
  });
  assert.equal(row.plan.cleanup.nativeAmountWei, "10000000000000");
  assert.equal(row.plan.cleanup.entryPointDepositAmountWei, "985000000000");
});

test("prefund arithmetic and terminal dust are exact and never promise zero", async () => {
  const row = await fixture({
    nativeBalanceWei: "10000000000000", entryPointDepositWei: "9000000000000"
  });
  assert.equal(row.plan.prefund.maximumGas, "80150");
  assert.equal(row.plan.prefund.maximumPrefundWei, "8015000000000");
  assert.equal(row.plan.prefund.estimatedCleanupGas, "200");
  assert.equal(row.plan.prefund.estimatedMaximumCostWei, "20000000000");
  assert.equal(row.plan.prefund.maximumTerminalEntryPointDepositWei, "8015000000000");
  assert.equal(row.plan.prefund.exactZeroEntryPointDepositPromised, false);
  assert.equal(row.plan.prefund.ownerAcceptanceRequired, true);
});

test("P5 selects evidence-bound verification gas and margins other gas and fee fields", () => {
  const owner = new ethers.Wallet(`0x${"51".repeat(32)}`);
  const config = baseConfig(owner);
  const selected = p5.selectP5GasPolicy({
    estimate: ESTIMATE,
    feeData: { maxFeePerGas: 80000000n, maxPriorityFeePerGas: 4000000n },
    config
  });
  assert.deepEqual(selected.selected, SELECTED_GAS);
  assert.equal(selected.selected.verificationGasLimit, 80000n);
  assert.notEqual(selected.selected.verificationGasLimit, (80000n * 5n + 3n) / 4n);
  assert.equal(selected.basis.marginNumerator, "5");
  assert.equal(selected.basis.marginDenominator, "4");
  assert.deepEqual(selected.basis.fixedGasCeilings, {
    verificationGasLimit: "80000",
    callGasLimit: "468750",
    preVerificationGas: "156250"
  });
  assert.throws(() => p5.selectP5GasPolicy({
    estimate: { ...ESTIMATE, callGasLimit: 375001n },
    feeData: { maxFeePerGas: 80000000n, maxPriorityFeePerGas: 4000000n },
    config
  }), /PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_MARGIN_EXCEEDS_CONFIGURED_CAP/u);
});

test("Phase 7D cleanup estimates fit fixed P5 double-margin gas ceilings", () => {
  const config = p5.loadConfiguration();
  const selected = p5.selectP5GasPolicy({
    estimate: {
      verificationGasLimit: 150000n,
      callGasLimit: 300000n,
      preVerificationGas: 100000n
    },
    feeData: { maxFeePerGas: 2400000000n, maxPriorityFeePerGas: 1000000n },
    config
  });
  assert.deepEqual(selected.selected, {
    verificationGasLimit: 80000n,
    callGasLimit: 375000n,
    preVerificationGas: 125000n,
    maxFeePerGas: 3000000000n,
    maxPriorityFeePerGas: 100000000n
  });
  assert.equal(selected.basis.ceilingDerivation,
    "verificationGasLimit is evidence-selected; callGasLimit and preVerificationGas use ceil(raw*5/4); fixed call/preVerification ceilings permit one bounded 25% raw-estimate growth window");
});

test("fixed P5 call and pre-verification ceilings retain exact-boundary rejection", () => {
  const config = p5.loadConfiguration();
  const boundary = {
    verificationGasLimit: 187500n,
    callGasLimit: 375000n,
    preVerificationGas: 125000n
  };
  const exact = p5.selectP5GasPolicy({
    estimate: boundary,
    feeData: { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000n },
    config
  });
  assert.deepEqual({
    verificationGasLimit: exact.selected.verificationGasLimit,
    callGasLimit: exact.selected.callGasLimit,
    preVerificationGas: exact.selected.preVerificationGas
  }, p5.P5_FIXED_GAS_CEILINGS);
  for (const field of ["callGasLimit", "preVerificationGas"]) {
    assert.throws(() => p5.selectP5GasPolicy({
      estimate: { ...boundary, [field]: boundary[field] + 1n },
      feeData: { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000n },
      config
    }), /PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_MARGIN_EXCEEDS_CONFIGURED_CAP/u, field);
  }
});

test("P5 max-fee ceiling is isolated, fixed, and margin-bounded", () => {
  const config = p5.loadConfiguration();
  assert.equal(config.gasPolicy.maxFeePerGas, "2200000000");
  assert.equal(config.gasPolicy.maxPriorityFeePerGas, "100000000");
  assert.equal(p5.p2FinalGasPolicy(config.gasPolicy).maxFeePerGas, "2200000000");
  assert.equal(p5.p3GasPolicy(config.gasPolicy).maxFeePerGas, "2200000000");
  assert.equal(p5.P5_MAX_FEE_PER_GAS, 3000000000n);
  assert.equal(p5.configuredGasPolicy(config).maxFeePerGas, 3000000000n);
  assert.equal(p5.configuredGasPolicy(config).maxPriorityFeePerGas, 100000000n);
  assert.equal((2400000000n * 5n + 3n) / 4n, 3000000000n);
  assert.equal((2400000001n * 5n + 3n) / 4n, 3000000002n);
  const estimate = {
    verificationGasLimit: 150000n,
    callGasLimit: 300000n,
    preVerificationGas: 100000n
  };
  assert.equal(p5.selectP5GasPolicy({
    estimate,
    feeData: { maxFeePerGas: 2400000000n, maxPriorityFeePerGas: 80000000n },
    config
  }).selected.maxFeePerGas, 3000000000n);
  assert.equal(p5.selectP5GasPolicy({
    estimate,
    feeData: { maxFeePerGas: 2125578600n, maxPriorityFeePerGas: 1000000n },
    config
  }).selected.maxFeePerGas, 2656973250n);
  for (const feeData of [
    { maxFeePerGas: 2400000001n, maxPriorityFeePerGas: 1000000n },
    { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 80000001n }
  ]) {
    assert.throws(() => p5.selectP5GasPolicy({ estimate, feeData, config }),
      /PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_MARGIN_EXCEEDS_CONFIGURED_CAP/u);
  }
});

test("fixed P5 gas ceilings have deterministic prefund and terminal-residual exposure", () => {
  const config = p5.loadConfiguration();
  const exposure = p5.p5GasCeilingExposure(config);
  assert.deepEqual(exposure, {
    maximumGas: "705000",
    maximumPrefundWei: "2115000000000000",
    maximumTerminalEntryPointDepositWei: "2115000000000000",
    maxFeePerGas: "3000000000"
  });
});

test("selected P5 cleanup gas binds the lower plan-approved residual at the new fee cap", () => {
  const selectedGas = {
    verificationGasLimit: 80000n,
    callGasLimit: 375000n,
    preVerificationGas: 125000n,
    maxFeePerGas: p5.P5_MAX_FEE_PER_GAS,
    maxPriorityFeePerGas: 100000000n
  };
  const prefund = p5.prefundModel({
    nativeBalanceWei: "3353861479486230",
    entryPointDepositWei: "700036093178300",
    gas: selectedGas,
    estimate: {
      verificationGasLimit: 80000n,
      callGasLimit: 300000n,
      preVerificationGas: 100000n
    }
  });
  assert.equal(prefund.maximumPrefundWei, "1740000000000000");
  assert.equal(prefund.maximumTerminalEntryPointDepositWei, "1740000000000000");
  assert.equal(prefund.exactZeroEntryPointDepositPromised, false);
  assert.equal(prefund.externalFundingWei, "0");
});

test("planner binds exact owner, nonce, balances, freeze, recovery, and rotation state", async () => {
  const row = await fixture();
  for (const field of ["owner", "nonce", "nativeBalanceWei", "entryPointDepositWei",
    "frozen", "recoveryActive", "recoveryAuthorityRotationActive"]) {
    assert.deepEqual(row.plan.account[field], p5.normalizeState(row.state)[field], field);
  }
  assert.equal(row.plan.account.destinationSemantics, "releaseTestFunds -> hard-coded current owner");
});

test("planner creates one unapproved unsigned plan before any signed artifact exists", async () => {
  const row = await fixture();
  assert.equal(row.plan.approval.approved, false);
  assert.equal(row.plan.signing.status, "NOT_SIGNED");
  assert.equal(row.plan.userOperation.packed.signature, "0x");
  assert.equal(row.plan.userOperation.rpc.signature, "0x");
  assert.equal(Object.hasOwn(row.plan, "signedArtifact"), false);
  assert.doesNotThrow(() => p5.assertPlanIntegrity(row.plan, row.config));
});

test("canonical protected-file SHA is exported, exact, and unavailable expectations fail closed", async () => {
  const expected = "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8";
  assert.equal(typeof p5.PROTECTED_FILE_SHA256, "string");
  assert.equal(p5.PROTECTED_FILE_SHA256, expected);
  assert.match(p5.PROTECTED_FILE_SHA256, /^[0-9a-f]{64}$/u);
  const row = await fixture();
  assert.equal(row.plan.source.protectedUntrackedFileSha256, expected);
  assert.equal(p5.assertProtectedFileBinding(expected, p5.PROTECTED_FILE_SHA256), expected);
  for (const unavailable of [undefined, null, "", "f".repeat(63)]) {
    assert.throws(
      () => p5.assertProtectedFileBinding(expected, unavailable),
      /PHILCORE_CONTROLLED_BETA_P5_EXPECTED_PROTECTED_FILE_SHA_INVALID/u
    );
  }
});

test("protected-file plan binding rejects missing, malformed, and mismatched actual values", () => {
  const { config, plan } = realShapedPlan();
  assert.doesNotThrow(() => p5.assertPlanIntegrity(plan, config));
  const mismatched = `${p5.PROTECTED_FILE_SHA256.slice(0, -1)}9`;
  for (const value of [undefined, "", "0xdeadbeef", mismatched]) {
    const sourceIdentity = { ...plan.source };
    if (value === undefined) delete sourceIdentity.protectedUntrackedFileSha256;
    else sourceIdentity.protectedUntrackedFileSha256 = value;
    assert.throws(
      () => p5.assertPlanIntegrity(redigest({ ...plan, source: sourceIdentity }), config),
      /PHILCORE_CONTROLLED_BETA_P5_PROTECTED_FILE_SHA_(?:INVALID|MISMATCH)/u
    );
  }
});

test("real-shaped plan integrity-binds expected post-state and rejects every required drift", () => {
  const { config, plan } = realShapedPlan();
  assert.deepEqual(plan.expectedPostState, {
    condition: "SUCCESSFUL_EXACT_STATE_P5_CLEANUP",
    lane0Nonce: { planned: "2", expectedAfterSuccess: "3" },
    smartAccountNativeBalanceWei: "0",
    entryPointDepositWei: {
      knowledgeBeforeInclusion: "UNKNOWN",
      successUpperBoundWei: plan.prefund.maximumTerminalEntryPointDepositWei,
      relation: "LESS_THAN_OR_EQUAL_TO_PLAN_SELECTED_MAXIMUM_TERMINAL_ENTRYPOINT_DEPOSIT_WEI"
    },
    owner: plan.account.owner,
    passBalance: "2",
    token1Owner: plan.account.token1Owner,
    token2Owner: plan.account.token2Owner,
    nextTokenId: "3",
    p2ReplayConsumed: true,
    p3ReplayConsumed: true,
    frozen: false,
    recoveryActive: false,
    recoveryAuthorityRotationActive: false,
    infrastructure: { actionGate: "UNCHANGED", consumer: "UNCHANGED", factory: "UNCHANGED" }
  });
  const withoutPostState = { ...plan };
  delete withoutPostState.expectedPostState;
  const cases = [
    withoutPostState,
    { ...plan, expectedPostState: { ...plan.expectedPostState,
      lane0Nonce: { ...plan.expectedPostState.lane0Nonce, expectedAfterSuccess: "4" } } },
    { ...plan, expectedPostState: { ...plan.expectedPostState,
      smartAccountNativeBalanceWei: "1" } },
    { ...plan, expectedPostState: { ...plan.expectedPostState,
      entryPointDepositWei: { ...plan.expectedPostState.entryPointDepositWei, relation: undefined } } },
    { ...plan, expectedPostState: { ...plan.expectedPostState, owner: undefined } },
    { ...plan, expectedPostState: { ...plan.expectedPostState, owner: ethers.ZeroAddress } },
    { ...plan, expectedPostState: { ...plan.expectedPostState, passBalance: "3" } },
    { ...plan, expectedPostState: { ...plan.expectedPostState, p2ReplayConsumed: false } },
    { ...plan, expectedPostState: { ...plan.expectedPostState, p3ReplayConsumed: false } }
  ];
  for (const candidate of cases) {
    assert.throws(
      () => p5.assertPlanIntegrity(redigest(candidate), config),
      /PHILCORE_CONTROLLED_BETA_P5_EXPECTED_POST_STATE_INVALID/u
    );
  }
});

test("real-shaped plan integrity-binds open fail-closed P5-R-L01", () => {
  const { config, plan } = realShapedPlan();
  assert.deepEqual(plan.residualRisks, [p5.P5_R_L01]);
  const withoutRisk = { ...plan };
  delete withoutRisk.residualRisks;
  for (const candidate of [
    withoutRisk,
    { ...plan, residualRisks: [{ ...p5.P5_R_L01, severity: "INFORMATIONAL" }] },
    { ...plan, residualRisks: [{ ...p5.P5_R_L01, status: "RESOLVED" }] },
    { ...plan, residualRisks: [{ ...p5.P5_R_L01, retryAuthorized: true }] },
    { ...plan, residualRisks: [{ ...p5.P5_R_L01, secondSubmissionAuthorized: true }] },
    { ...plan, residualRisks: [{ ...p5.P5_R_L01, canCreateFalseSuccess: true }] }
  ]) {
    assert.throws(
      () => p5.assertPlanIntegrity(redigest(candidate), config),
      /PHILCORE_CONTROLLED_BETA_P5_RESIDUAL_RISK_DISCLOSURE_INVALID/u
    );
  }
});

test("real-shaped plan integrity-binds structural refund limitation and selected dust bound", () => {
  const { config, plan } = realShapedPlan();
  assert.equal(plan.structuralRefundLimitation.exactZeroEntryPointDepositPromised, false);
  assert.equal(plan.structuralRefundLimitation.finalEntryPointDepositKnownBeforeInclusion, false);
  assert.equal(
    plan.structuralRefundLimitation.planSelectedMaximumTerminalEntryPointDepositWei,
    plan.prefund.maximumTerminalEntryPointDepositWei
  );
  assert.notEqual(
    plan.structuralRefundLimitation.planSelectedMaximumTerminalEntryPointDepositWei,
    plan.structuralRefundLimitation.fixedPolicyOuterMaximumTerminalEntryPointDepositWei
  );
  const withoutLimitation = { ...plan };
  delete withoutLimitation.structuralRefundLimitation;
  for (const candidate of [
    withoutLimitation,
    { ...plan, structuralRefundLimitation: { ...plan.structuralRefundLimitation,
      exactZeroEntryPointDepositPromised: true } },
    { ...plan, structuralRefundLimitation: { ...plan.structuralRefundLimitation,
      finalEntryPointDepositKnownBeforeInclusion: true } },
    { ...plan, structuralRefundLimitation: { ...plan.structuralRefundLimitation,
      successUpperBoundRelation: undefined } },
    { ...plan, structuralRefundLimitation: { ...plan.structuralRefundLimitation,
      planSelectedMaximumTerminalEntryPointDepositWei:
        plan.structuralRefundLimitation.fixedPolicyOuterMaximumTerminalEntryPointDepositWei } },
    { ...plan, structuralRefundLimitation: { ...plan.structuralRefundLimitation,
      fixedPolicyOuterCeilingIsOwnerApprovedResidual: true } }
  ]) {
    assert.throws(
      () => p5.assertPlanIntegrity(redigest(candidate), config),
      /PHILCORE_CONTROLLED_BETA_P5_STRUCTURAL_REFUND_LIMITATION_INVALID/u
    );
  }
});

test("frozen UserOperation hash excludes later signature exactly as the implementation does", async () => {
  const row = await fixture();
  const unsignedHash = preparation.computePhilCore4337UserOperationHash({
    userOperation: row.plan.userOperation.packed,
    entryPointAddress: row.plan.entryPoint,
    chainId: Number(row.plan.chainId)
  });
  const signedHash = preparation.computePhilCore4337UserOperationHash({
    userOperation: row.artifact.userOperation,
    entryPointAddress: row.plan.entryPoint,
    chainId: Number(row.plan.chainId)
  });
  assert.equal(unsignedHash, row.plan.userOperation.hash);
  assert.equal(signedHash, unsignedHash);
  assert.notEqual(row.artifact.userOperation.signature, "0x");
});

test("planner is structurally no-send, no-sign, no-lock, and cannot fund", () => {
  const value = source(PLANNER);
  for (const forbidden of ["eth_sendUserOperation", "eth_sendRawTransaction",
    "eth_sendTransaction", ".sendTransaction(", ".signMessage(", ".signTransaction(",
    "acquireExecutionLock", "depositTo("]) assert.equal(value.includes(forbidden), false, forbidden);
  assert.match(value, /eth_estimateUserOperationGas/u);
  assert.match(value, /publicMutationOccurred: false/u);
  assert.equal(value.includes("DEFAULT_SIGNED_ARTIFACT_PATH"), false);
  assert.equal(value.includes("readFileSync(artifact"), false);
});

test("signing path is structurally separate and contains no send, lock, or funding call", () => {
  const value = source(SIGNER);
  for (const forbidden of ["eth_sendUserOperation", "eth_sendRawTransaction",
    "eth_sendTransaction", "acquireExecutionLock", "depositTo(", "sendTransaction(",
    "broadcastTransaction("]) assert.equal(value.includes(forbidden), false, forbidden);
  assert.match(value, /signUserOperationHash/u);
  assert.match(value, /assertStateEqualsPlan/u);
});

test("configured custody signs only the exact planned hash after stale-state revalidation", async () => {
  const row = await fixture();
  const requests = [];
  const persisted = [];
  const artifact = await signer.signPlanWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    config: row.config,
    signer: {
      async getOwnerAddress() { return row.owner.address; },
      async signUserOperationHash(request) {
        requests.push(request);
        return {
          status: "signed",
          signature: await row.owner.signMessage(ethers.getBytes(request.userOperationHash))
        };
      }
    },
    readState: async () => row.state,
    sourceMatches: () => true,
    outputPath: "/fixture/p5-signed.json",
    persist: (location, value) => persisted.push({ location, value })
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].userOperationHash, row.plan.userOperation.hash);
  assert.equal(requests[0].planDigest, row.plan.planDigest);
  assert.equal(persisted.length, 1);
  assert.equal(artifact.planDigest, row.plan.planDigest);
  assert.equal(artifact.planCanonicalSha256, p5.canonicalSha256(row.plan));
  assert.equal(artifact.planByteSha256, p5.sha256Bytes(row.planBytes));
  assert.doesNotThrow(() => p5.parseSignedArtifact(artifact, row.plan, row.config));
});

test("signing refuses stale state before custody is touched", async () => {
  const row = await fixture();
  let signCalls = 0;
  await assert.rejects(signer.signPlanWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    config: row.config,
    signer: { async signUserOperationHash() { signCalls++; } },
    readState: async () => changed(row.state, { nonce: "3" }),
    sourceMatches: () => true,
    persist() {}
  }), /PHILCORE_CONTROLLED_BETA_P5_EXACT_PRESTATE_CHANGED/u);
  assert.equal(signCalls, 0);
});

test("signing requires one readable plan and rejects duplicate or corrupt candidates", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-p5-plan-load-"));
  const valid = path.join(root, "plan.json");
  const corrupt = path.join(root, "corrupt.json");
  fs.writeFileSync(valid, "{}\n", { mode: 0o600 });
  fs.writeFileSync(corrupt, "{\n", { mode: 0o600 });
  try {
    assert.throws(() => signer.loadExactlyOnePlan([]),
      /PHILCORE_CONTROLLED_BETA_P5_EXACTLY_ONE_PLAN_REQUIRED/u);
    assert.throws(() => signer.loadExactlyOnePlan([valid, valid]),
      /PHILCORE_CONTROLLED_BETA_P5_EXACTLY_ONE_PLAN_REQUIRED/u);
    assert.throws(() => signer.loadExactlyOnePlan([path.join(root, "missing.json")]),
      /PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_PLAN_MISSING/u);
    assert.throws(() => signer.loadExactlyOnePlan([corrupt]),
      /PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_PLAN_CORRUPT/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("duplicate unsigned plans and duplicate signed artifacts fail exclusive creation", async () => {
  const row = await fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-p5-exclusive-"));
  const planPath = path.join(root, "plan.json");
  const artifactPath = path.join(root, "signed.json");
  try {
    p5.atomicCreateJson(planPath, row.plan);
    assert.throws(() => p5.atomicCreateJson(planPath, row.plan),
      /EEXIST/u);
    p5.atomicCreateJson(artifactPath, row.artifact);
    assert.throws(() => p5.atomicCreateJson(artifactPath, row.artifact),
      /EEXIST/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("signing rejects approval-order violations, source drift, and custody-owner drift", async () => {
  const row = await fixture();
  const base = {
    plan: row.plan, planBytes: row.planBytes, config: row.config,
    signer: {
      async getOwnerAddress() { return row.owner.address; },
      async signUserOperationHash() { throw new Error("must not sign"); }
    },
    readState: async () => row.state,
    sourceMatches: () => true,
    persist() {}
  };
  await assert.rejects(signer.signPlanWithDependencies({
    ...base, plan: { ...row.plan, approval: { ...row.plan.approval, approved: true } }
  }), /PHILCORE_CONTROLLED_BETA_P5_PLAN_ALREADY_APPROVED_BEFORE_SIGNING/u);
  await assert.rejects(signer.signPlanWithDependencies({
    ...base, sourceMatches: () => false
  }), /PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED/u);
  await assert.rejects(signer.signPlanWithDependencies({
    ...base, signer: {
      async getOwnerAddress() { return ethers.Wallet.createRandom().address; },
      async signUserOperationHash() { throw new Error("must not sign"); }
    }
  }), /PHILCORE_CONTROLLED_BETA_P5_CUSTODY_OWNER_MISMATCH/u);
});

test("field-level plan corruption fails before signing", async () => {
  const row = await fixture();
  const cases = [
    ["nonce", { userOperation: { ...row.plan.userOperation, packed: {
      ...row.plan.userOperation.packed, nonce: "3"
    } } }],
    ["calldata", { userOperation: { ...row.plan.userOperation, packed: {
      ...row.plan.userOperation.packed, callData: "0xdeadbeef"
    } } }],
    ["release", { cleanup: { ...row.plan.cleanup, nativeAmountWei: "1" } }],
    ["gas", { userOperation: { ...row.plan.userOperation, packed: {
      ...row.plan.userOperation.packed, accountGasLimits: `0x${"00".repeat(32)}`
    } } }],
    ["fee", { userOperation: { ...row.plan.userOperation, packed: {
      ...row.plan.userOperation.packed, gasFees: `0x${"00".repeat(32)}`
    } } }],
    ["entrypoint", { entryPoint: ethers.Wallet.createRandom().address }],
    ["chain", { chainId: "1" }],
    ["owner", { account: { ...row.plan.account, owner: ethers.Wallet.createRandom().address } }],
    ["hash", { userOperation: { ...row.plan.userOperation,
      hash: `0x${"ff".repeat(32)}` } }]
  ];
  for (const [label, patch] of cases) {
    assert.throws(() => p5.assertPlanIntegrity({ ...row.plan, ...patch }, row.config),
      /PHILCORE_CONTROLLED_BETA_P5_/u, label);
  }
});

test("wrong-hash or malformed custody signatures never create an artifact", async () => {
  const row = await fixture();
  const otherHash = `0x${"ee".repeat(32)}`;
  for (const signature of [
    await row.owner.signMessage(ethers.getBytes(otherHash)), "0xdeadbeef"
  ]) {
    assert.throws(() => signer.createSignedArtifact({
      plan: row.plan, planBytes: row.planBytes, config: row.config, signature
    }), /PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID/u);
  }
});

test("executor has exactly one bundler send site and no retry or funding site", () => {
  const value = source(EXECUTOR);
  assert.equal((value.match(/"eth_sendUserOperation"/gu) || []).length, 1);
  for (const forbidden of ["eth_sendRawTransaction", "eth_sendTransaction", "depositTo(",
    "sendTransaction(", "broadcastTransaction("]) assert.equal(value.includes(forbidden), false);
  assert.equal((value.match(/automaticRetryOccurred: false/gu) || []).length >= 2, true);
});

test("P5 common source fixes the selector and has no arbitrary recipient parameter", () => {
  assert.equal(p5.RELEASE_SELECTOR, "0xb818fbeb");
  assert.equal(p5.accountInterface.getFunction("releaseTestFunds").selector, p5.RELEASE_SELECTOR);
  assert.match(source(COMMON), /destinationPolicy: "CURRENT_EXECUTION_OWNER_ONLY"/u);
});

test("wrong owner signature and changed owner after planning fail closed", async () => {
  const row = await fixture();
  const other = ethers.Wallet.createRandom();
  const wrongSignature = await other.signMessage(ethers.getBytes(row.plan.userOperation.hash));
  assert.throws(
    () => p5.parseSignedArtifact(
      { ...row.artifact, userOperation: {
        ...row.artifact.userOperation, signature: wrongSignature
      } }, row.plan, row.config
    ),
    /PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID/u
  );
  assert.throws(
    () => p5.assertStateEqualsPlan(changed(row.state, { owner: other.address }), row.plan.account),
    /PHILCORE_CONTROLLED_BETA_P5_EXACT_PRESTATE_CHANGED/u
  );
});

test("every material upward and downward pre-state drift fails exact equality", async () => {
  const row = await fixture({ entryPointDepositWei: "9000000000000" });
  const cases = [
    ["nonce", "3"],
    ["nativeBalanceWei", "99999"],
    ["nativeBalanceWei", "100001"],
    ["entryPointDepositWei", "49999999999"],
    ["entryPointDepositWei", "50000000001"],
    ["frozen", true],
    ["recoveryActive", true],
    ["recoveryAuthorityRotationActive", true]
  ];
  for (const [field, value] of cases) {
    assert.throws(
      () => p5.assertStateEqualsPlan(changed(row.state, { [field]: value }), row.plan.account),
      /PHILCORE_CONTROLLED_BETA_P5_EXACT_PRESTATE_CHANGED/u,
      field
    );
  }
});

test("provider disagreement fails closed", async () => {
  const row = await fixture();
  assert.throws(
    () => p5.assertStatePair(row.state, changed(row.state, { nonce: "3" })),
    /PHILCORE_CONTROLLED_BETA_P5_PROVIDER_DISAGREEMENT/u
  );
});

test("frozen, recovery-active, and rotation-active plans are not cleanup-ready", async () => {
  for (const patch of [{ frozen: true }, { recoveryActive: true },
    { recoveryAuthorityRotationActive: true }]) {
    const row = await fixture();
    assert.throws(
      () => p5.createPlan({
        lineageId: row.plan.lineageId,
        source: row.plan.source,
        runnerReview: row.plan.runnerReview,
        config: row.config,
        state: changed(row.state, patch),
        estimate: ESTIMATE,
        feeData: { maxFeePerGas: 80000000n, maxPriorityFeePerGas: 4000000n },
        gasSelection: {
          selected: p5.gasFields(row.plan.userOperation.packed),
          basis: row.plan.userOperation.gasAndFeeSelection
        },
        endpointBindings: row.plan.endpointBindings,
        endpoints: row.plan.endpoints,
        compiler: row.plan.compiler
      }),
      /PHILCORE_CONTROLLED_BETA_P5_LIVE_STATE_NOT_CLEANUP_READY/u
    );
  }
});

test("changed nonce, calldata, amount, selector, initCode, or paymaster is rejected", async () => {
  const row = await fixture();
  const overNative = p5.accountInterface.encodeFunctionData("releaseTestFunds", ["100001", "0"]);
  const overDeposit = p5.accountInterface.encodeFunctionData("releaseTestFunds", ["85000", "1"]);
  const cases = [
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, { nonce: "3" }) },
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, { callData: overNative }) },
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, { callData: overDeposit }) },
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, { callData: "0xdeadbeef" }) },
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, { initCode: "0x01" }) },
    { ...row.artifact, userOperation: changed(row.artifact.userOperation, {
      paymasterAndData: `0x${"12".repeat(20)}`
    }) }
  ];
  for (const artifact of cases) {
    assert.throws(() => p5.parseSignedArtifact(artifact, row.plan, row.config));
  }
});

test("additional funding requirement and zero release fail closed", () => {
  assert.throws(
    () => p5.prefundModel({
      nativeBalanceWei: "10", entryPointDepositWei: "10", gas: GAS, estimate: ESTIMATE
    }),
    /PHILCORE_CONTROLLED_BETA_P5_ADDITIONAL_FUNDING_REQUIRED/u
  );
  const exactAssetsGas = { ...GAS, verificationGasLimit: 1n, callGasLimit: 1n,
    preVerificationGas: 1n, maxFeePerGas: 10n };
  assert.throws(
    () => p5.prefundModel({
      nativeBalanceWei: "20", entryPointDepositWei: "10", gas: exactAssetsGas,
      estimate: { verificationGasLimit: 1n, callGasLimit: 1n, preVerificationGas: 1n }
    }),
    /PHILCORE_CONTROLLED_BETA_P5_ZERO_RELEASE_FORBIDDEN/u
  );
});

test("gas estimate and current fee above signed capability fail closed", async () => {
  const row = await fixture();
  assert.throws(
    () => p5.assertFeeAndEstimate(row.plan, {
      ...ESTIMATE, callGasLimit: 101n
    }, { maxFeePerGas: 90n, maxPriorityFeePerGas: 1n }),
    /PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_EXCEEDS_SIGNED_LIMIT/u
  );
  assert.throws(
    () => p5.assertFeeAndEstimate(row.plan, ESTIMATE, {
      maxFeePerGas: 100000001n, maxPriorityFeePerGas: 1n
    }),
    /PHILCORE_CONTROLLED_BETA_P5_SIGNED_FEE_CAP_STALE/u
  );
});

test("plan and signed-artifact digest changes fail closed", async () => {
  const row = await fixture();
  assert.doesNotThrow(() => p5.assertPlan(row.plan, row.plan.planDigest, row.config));
  assert.throws(
    () => p5.assertPlan(
      { ...row.plan, maximumAdditionalFundingWei: "1" }, row.plan.planDigest, row.config
    ),
    /PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID/u
  );
  assert.throws(
    () => p5.assertArtifactBinding(
      row.plan, row.planBytes, { ...row.artifact, submitted: true },
      Buffer.from(`${JSON.stringify({ ...row.artifact, submitted: true }, null, 2)}\n`), row.config
    ),
    /PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID/u
  );
});

test("re-digested alteration of frozen P5 gas-ceiling evidence fails closed", async () => {
  const row = await fixture();
  const altered = redigest({
    ...row.plan,
    userOperation: {
      ...row.plan.userOperation,
      gasAndFeeSelection: {
        ...row.plan.userOperation.gasAndFeeSelection,
        fixedGasCeilings: {
          ...row.plan.userOperation.gasAndFeeSelection.fixedGasCeilings,
          callGasLimit: "468751"
        }
      }
    }
  });
  assert.throws(
    () => p5.assertPlan(altered, altered.planDigest, row.config),
    /PHILCORE_CONTROLLED_BETA_P5_PLAN_INVALID/u
  );
});

test("artifact from a different valid plan is rejected", async () => {
  const row = await fixture();
  const otherPlan = redigest({ ...row.plan, compiler: { solcVersion: "other-fixture" } });
  const otherPlanBytes = Buffer.from(`${JSON.stringify(otherPlan, null, 2)}\n`);
  const signature = await row.owner.signMessage(ethers.getBytes(otherPlan.userOperation.hash));
  const otherArtifact = signer.createSignedArtifact({
    plan: otherPlan, planBytes: otherPlanBytes, config: row.config, signature
  });
  const otherArtifactBytes = Buffer.from(`${JSON.stringify(otherArtifact, null, 2)}\n`);
  assert.throws(() => p5.assertArtifactBinding(
    row.plan, row.planBytes, otherArtifact, otherArtifactBytes, row.config
  ), /PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_(?:INVALID|BINDING_INVALID)/u);
});

test("executor rejects an unsigned-only plan with no signed artifact before any send", async () => {
  const row = await fixture();
  const mocks = executionMocks(row);
  await assert.rejects(executor.executeWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    artifact: null,
    artifactBytes: Buffer.from("null\n"),
    approvedDigest: row.plan.planDigest,
    suppliedApproval: row.plan.approval.requiredPhrase,
    config: row.config,
    primary: mocks.primary,
    reconciliation: mocks.reconciliation,
    bundler: mocks.bundler,
    persist() {},
    sourceMatches: () => true,
    readState: async () => row.state,
    acquireLock: () => { throw new Error("must not lock"); }
  }), /PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID/u);
  assert.equal(mocks.counts().sendCount, 0);
});

test("exclusive durable lock rejects pre-existing and duplicate acquisition", async () => {
  const row = await fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-p5-lock-"));
  const lock = path.join(root, "attempt.lock.json");
  try {
    const record = p5.acquireExecutionLock(row.plan, lock);
    assert.equal(record.stageId, "P5");
    assert.equal(record.automaticRetryAllowed, false);
    assert.equal(fs.statSync(lock).mode & 0o777, 0o600);
    assert.throws(
      () => p5.acquireExecutionLock(row.plan, lock),
      /PHILCORE_CONTROLLED_BETA_P5_EXECUTION_ALREADY_ATTEMPTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function log(address, iface, name, args) {
  const encoded = iface.encodeEventLog(iface.getEvent(name), args);
  return { address, topics: encoded.topics, data: encoded.data };
}

function operationEvidence(row) {
  return {
    entryPoint: row.plan.entryPoint,
    userOperation: {
      sender: row.plan.account.account,
      nonce: row.plan.account.nonce,
      callData: row.plan.cleanup.callData
    }
  };
}

function operationReceipt(row, success) {
  return {
    userOpHash: row.plan.userOperation.hash,
    sender: row.plan.account.account,
    nonce: row.plan.account.nonce,
    success,
    receipt: { transactionHash: `0x${"ab".repeat(32)}` }
  };
}

test("successful reconciliation requires UserOperation success, release, withdrawal, and unchanged state", async () => {
  const row = await fixture({ entryPointDepositWei: "9000000000000" });
  const finalState = changed(row.state, {
    nonce: "3", nativeBalanceWei: "0", entryPointDepositWei: "1000"
  });
  const logs = [
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationEvent", [
      row.plan.userOperation.hash, row.plan.account.account, ethers.ZeroAddress,
      2n, true, 24000n, 240n
    ]),
    log(row.plan.account.account, p5.accountInterface, "TestFundsReleased", [
      row.plan.account.owner, BigInt(row.plan.cleanup.nativeAmountWei),
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ]),
    log(row.plan.entryPoint, p5.entryPointInterface, "Withdrawn", [
      row.plan.account.account, row.plan.account.owner,
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ])
  ];
  const result = p5.classifyOperationEvidence({
    plan: row.plan,
    operation: operationEvidence(row),
    userOperationReceipt: operationReceipt(row, true),
    transactionReceipt: { status: 1, logs },
    finalState
  });
  assert.equal(result.status, "INCLUDED_SUCCESS_RECONCILED");
  assert.equal(result.retryAllowed, false);
});

test("reconciliation rejects a withdrawal sent anywhere but the exact current owner", async () => {
  const row = await fixture({ entryPointDepositWei: "9000000000000" });
  const wrongDestination = ethers.Wallet.createRandom().address;
  const logs = [
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationEvent", [
      row.plan.userOperation.hash, row.plan.account.account, ethers.ZeroAddress,
      2n, true, 24000n, 240n
    ]),
    log(row.plan.account.account, p5.accountInterface, "TestFundsReleased", [
      row.plan.account.owner, BigInt(row.plan.cleanup.nativeAmountWei),
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ]),
    log(row.plan.entryPoint, p5.entryPointInterface, "Withdrawn", [
      row.plan.account.account, wrongDestination,
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ])
  ];
  assert.throws(() => p5.classifyOperationEvidence({
    plan: row.plan,
    operation: operationEvidence(row),
    userOperationReceipt: operationReceipt(row, true),
    transactionReceipt: { status: 1, logs },
    finalState: changed(row.state, {
      nonce: "3", nativeBalanceWei: "0", entryPointDepositWei: "1000"
    })
  }), /PHILCORE_CONTROLLED_BETA_P5_RECONCILIATION_EVENT_INVALID/u);
});

test("included UserOperation failure is distinct from successful bundle transaction", async () => {
  const row = await fixture();
  const logs = [
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationEvent", [
      row.plan.userOperation.hash, row.plan.account.account, ethers.ZeroAddress,
      2n, false, 1000n, 10n
    ]),
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationRevertReason", [
      row.plan.userOperation.hash, row.plan.account.account, 2n, "0xdeadbeef"
    ])
  ];
  const result = p5.classifyOperationEvidence({
    plan: row.plan,
    operation: operationEvidence(row),
    userOperationReceipt: operationReceipt(row, false),
    transactionReceipt: { status: 1, logs },
    finalState: null
  });
  assert.equal(result.status, "INCLUDED_USER_OPERATION_EXECUTION_FAILED");
  assert.equal(result.nonceAndGasConsequencesRequireReconciliation, true);
  assert.equal(result.retryAllowed, false);
});

test("UserOperation lookup and receipt identities are bound to the exact approved operation", async () => {
  const row = await fixture();
  assert.throws(() => p5.assertOperationLookupBinding(row.plan, {
    ...operationEvidence(row),
    userOperation: { ...operationEvidence(row).userOperation, nonce: "3" }
  }), /PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_LOOKUP_INVALID/u);
  assert.throws(() => p5.assertUserOperationReceiptBinding(row.plan, {
    ...operationReceipt(row, true), userOpHash: `0x${"ff".repeat(32)}`
  }), /PHILCORE_CONTROLLED_BETA_P5_USER_OPERATION_RECEIPT_INVALID/u);
});

test("rejected, pending, ambiguous transport, and absent outcomes remain distinct and non-retryable", async () => {
  const row = await fixture();
  assert.equal(p5.classifyOperationEvidence({ plan: row.plan }).status,
    "ABSENT_OPERATION_REQUIRES_HUMAN_REVIEW");
  assert.equal(p5.classifyOperationEvidence({
    plan: row.plan, sendDisposition: "REJECTED_BEFORE_BUNDLER_ACCEPTANCE"
  }).status, "REJECTED_BEFORE_BUNDLER_ACCEPTANCE");
  assert.equal(p5.classifyOperationEvidence({
    plan: row.plan, sendDisposition: "AMBIGUOUS_TRANSPORT_RESULT"
  }).status, "AMBIGUOUS_TRANSPORT_RESULT_REQUIRES_HUMAN_REVIEW");
  assert.equal(p5.classifyOperationEvidence({
    plan: row.plan, sendDisposition: "ACCEPTED_HASH_RETURNED"
  }).status, "ACCEPTED_NOT_YET_INCLUDED");
  assert.equal(p5.classifyOperationEvidence({
    plan: row.plan, operation: operationEvidence(row)
  }).status,
    "ACCEPTED_NOT_YET_INCLUDED");
  assert.equal(p5.classifyOperationEvidence({
    plan: row.plan,
    userOperationReceipt: {
      ...operationReceipt(row, true),
      receipt: null
    }
  }).status, "AMBIGUOUS_TRANSPORT_RESULT_REQUIRES_HUMAN_REVIEW");
  assert.equal(p5.classifySendDisposition(new Error("transport timeout"), null),
    "AMBIGUOUS_TRANSPORT_RESULT");
  assert.equal(p5.classifySendDisposition({ code: -32500, message: "AA23 reverted" }, null),
    "REJECTED_BEFORE_BUNDLER_ACCEPTANCE");
});

test("terminal deposit above the approved bound fails reconciliation", async () => {
  const row = await fixture({ entryPointDepositWei: "9000000000000" });
  const logs = [
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationEvent", [
      row.plan.userOperation.hash, row.plan.account.account, ethers.ZeroAddress,
      2n, true, 1n, 1n
    ]),
    log(row.plan.account.account, p5.accountInterface, "TestFundsReleased", [
      row.plan.account.owner, BigInt(row.plan.cleanup.nativeAmountWei),
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ]),
    log(row.plan.entryPoint, p5.entryPointInterface, "Withdrawn", [
      row.plan.account.account, row.plan.account.owner,
      BigInt(row.plan.cleanup.entryPointDepositAmountWei)
    ])
  ];
  assert.throws(
    () => p5.classifyOperationEvidence({
      plan: row.plan,
      operation: operationEvidence(row),
      userOperationReceipt: operationReceipt(row, true),
      transactionReceipt: { status: 1, logs },
      finalState: changed(row.state, {
        nonce: "3",
        nativeBalanceWei: "0",
        entryPointDepositWei: (BigInt(row.plan.prefund.maximumTerminalEntryPointDepositWei)
          + 1n).toString()
      })
    }),
    /PHILCORE_CONTROLLED_BETA_P5_FINAL_STATE_INVALID/u
  );
});

test("unrelated pass, replay, or recovery changes fail final reconciliation", async () => {
  const row = await fixture();
  const finalBase = changed(row.state, {
    nonce: "3", nativeBalanceWei: "0", entryPointDepositWei: "1"
  });
  const logs = [
    log(row.plan.entryPoint, p5.entryPointInterface, "UserOperationEvent", [
      row.plan.userOperation.hash, row.plan.account.account, ethers.ZeroAddress,
      2n, true, 24999n, 249n
    ]),
    log(row.plan.account.account, p5.accountInterface, "TestFundsReleased", [
      row.plan.account.owner, BigInt(row.plan.cleanup.nativeAmountWei), 0n
    ])
  ];
  for (const patch of [{ passBalance: "3" }, { p2ReplayConsumed: false },
    { p3ReplayConsumed: false }, { recoveryActive: true }, { frozen: true }]) {
    assert.throws(() => p5.classifyOperationEvidence({
      plan: row.plan,
      operation: operationEvidence(row),
      userOperationReceipt: operationReceipt(row, true),
      transactionReceipt: { status: 1, logs },
      finalState: changed(finalBase, patch)
    }), /PHILCORE_CONTROLLED_BETA_P5_FINAL_STATE_INVALID/u);
  }
});

function executionMocks(row, { sendThrows = false, sendError = null, classification = null } = {}) {
  let sendCount = 0;
  let receiptReads = 0;
  let operationReads = 0;
  const bundler = {
    async send(method) {
      if (method === "eth_estimateUserOperationGas") return ESTIMATE;
      if (method === "eth_getUserOperationReceipt") { receiptReads++; return null; }
      if (method === "eth_getUserOperationByHash") { operationReads++; return null; }
      if (method === "eth_sendUserOperation") {
        sendCount++;
        if (sendError) throw sendError;
        if (sendThrows) throw new Error("transport timeout");
        return row.plan.userOperation.hash;
      }
      throw new Error(`unexpected ${method}`);
    }
  };
  return {
    bundler,
    primary: { async getFeeData() { return { maxFeePerGas: 90n, maxPriorityFeePerGas: 1n }; } },
    reconciliation: {},
    counts: () => ({ sendCount, receiptReads, operationReads }),
    classify: classification || p5.classifyOperationEvidence
  };
}

test("ambiguous send performs exact-hash reconciliation and never retries", async () => {
  const row = await fixture();
  const mocks = executionMocks(row, { sendThrows: true });
  await assert.rejects(
    executor.executeWithDependencies({
      plan: row.plan,
      planBytes: row.planBytes,
      artifact: row.artifact,
      artifactBytes: row.artifactBytes,
      approvedDigest: row.plan.planDigest,
      suppliedApproval: row.plan.approval.requiredPhrase,
      config: row.config,
      primary: mocks.primary,
      reconciliation: mocks.reconciliation,
      bundler: mocks.bundler,
      lockPath: "/not-used",
      receiptPath: "/not-used",
      persist() {},
      sourceMatches: () => true,
      readState: async () => row.state,
      acquireLock: () => ({ stageId: "P5" }),
      classify: mocks.classify
    }),
    /PHILCORE_CONTROLLED_BETA_P5_STOPPED_REQUIRES_HUMAN_RECONCILIATION/u
  );
  assert.deepEqual(mocks.counts(), { sendCount: 1, receiptReads: 2, operationReads: 2 });
});

test("durable lock prevents a second executor invocation and second send", async () => {
  const row = await fixture();
  const mocks = executionMocks(row, {
    classification: () => ({ status: "INCLUDED_SUCCESS_RECONCILED", retryAllowed: false })
  });
  let locked = false;
  const acquireLock = () => {
    if (locked) p5.fail("PHILCORE_CONTROLLED_BETA_P5_TEST_LOCK_EXISTS");
    locked = true;
    return { stageId: "P5" };
  };
  const input = {
    plan: row.plan,
    planBytes: row.planBytes,
    artifact: row.artifact,
    artifactBytes: row.artifactBytes,
    approvedDigest: row.plan.planDigest,
    suppliedApproval: row.plan.approval.requiredPhrase,
    config: row.config,
    primary: mocks.primary,
    reconciliation: mocks.reconciliation,
    bundler: mocks.bundler,
    lockPath: "/not-used",
    receiptPath: "/not-used",
    persist() {},
    sourceMatches: () => true,
    readState: async () => row.state,
    acquireLock,
    classify: mocks.classify
  };
  await executor.executeWithDependencies(input);
  await assert.rejects(executor.executeWithDependencies(input),
    /PHILCORE_CONTROLLED_BETA_P5_TEST_LOCK_EXISTS/u);
  assert.equal(mocks.counts().sendCount, 1);
});

test("approval is exact and checked before state, lock, or submission", async () => {
  const row = await fixture();
  const mocks = executionMocks(row);
  await assert.rejects(executor.executeWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    artifact: row.artifact,
    artifactBytes: row.artifactBytes,
    approvedDigest: row.plan.planDigest,
    suppliedApproval: "WRONG",
    config: row.config,
    primary: mocks.primary,
    reconciliation: mocks.reconciliation,
    bundler: mocks.bundler,
    persist() {},
    sourceMatches: () => true,
    readState: async () => { throw new Error("must not read"); },
    acquireLock: () => { throw new Error("must not lock"); }
  }), /PHILCORE_CONTROLLED_BETA_P5_EXACT_APPROVAL_REQUIRED/u);
  assert.equal(mocks.counts().sendCount, 0);
});

test("fresh two-provider state equality is the final operation before locking", async () => {
  const row = await fixture();
  const calls = [];
  const mocks = executionMocks(row, {
    classification: () => ({ status: "INCLUDED_SUCCESS_RECONCILED", retryAllowed: false })
  });
  const originalSend = mocks.bundler.send;
  mocks.bundler.send = async (method, params) => {
    calls.push(method);
    return originalSend(method, params);
  };
  mocks.primary.getFeeData = async () => {
    calls.push("getFeeData");
    return { maxFeePerGas: 90n, maxPriorityFeePerGas: 1n };
  };
  await executor.executeWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    artifact: row.artifact,
    artifactBytes: row.artifactBytes,
    approvedDigest: row.plan.planDigest,
    suppliedApproval: row.plan.approval.requiredPhrase,
    config: row.config,
    primary: mocks.primary,
    reconciliation: mocks.reconciliation,
    bundler: mocks.bundler,
    lockPath: "/not-used",
    receiptPath: "/not-used",
    persist() {},
    sourceMatches: () => true,
    readState: async () => { calls.push("readProviderPair"); return row.state; },
    acquireLock: () => { calls.push("acquireExecutionLock"); return { stageId: "P5" }; },
    classify: mocks.classify
  });
  const lockIndex = calls.indexOf("acquireExecutionLock");
  assert.equal(calls[lockIndex - 1], "readProviderPair");
  assert.equal(calls.filter((value) => value === "acquireExecutionLock").length, 1);
  assert.equal(calls.filter((value) => value === "eth_sendUserOperation").length, 1);
});

test("planner and executor use distinct P5-only evidence paths", () => {
  assert.match(p5.DEFAULT_PLAN_PATH, /p5-plan\.json$/u);
  assert.match(p5.DEFAULT_SIGNED_ARTIFACT_PATH, /p5-signed-unsubmitted-v1\.json$/u);
  assert.match(p5.DEFAULT_RECEIPT_PATH, /p5-receipt\.json$/u);
  assert.match(p5.DEFAULT_EXECUTION_LOCK_PATH, /p5-execution-attempt\.lock\.json$/u);
  assert.notEqual(p5.DEFAULT_PLAN_PATH, p5.DEFAULT_P3_PLAN_PATH);
});

test("P5 priority admission floor has exact deterministic boundaries without changing P2 or P3", () => {
  const config = p5.loadConfiguration();
  const estimate = {
    verificationGasLimit: 150000n,
    callGasLimit: 300000n,
    preVerificationGas: 100000n
  };
  const selectedPriority = (raw) => p5.selectP5GasPolicy({
    estimate,
    feeData: { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: raw },
    config
  }).selected.maxPriorityFeePerGas;

  assert.equal(selectedPriority(1000000n), 100000000n);
  assert.equal(selectedPriority(79999999n), 100000000n);
  assert.equal((80000000n * 5n + 3n) / 4n, 100000000n);
  assert.equal(selectedPriority(80000000n), 100000000n);
  assert.equal((80000001n * 5n + 3n) / 4n, 100000002n);
  assert.throws(() => selectedPriority(80000001n),
    /PHILCORE_CONTROLLED_BETA_P5_ESTIMATE_MARGIN_EXCEEDS_CONFIGURED_CAP/u);
  assert.equal(selectedPriority(1000000n) === 1250000n, false);
  assert.equal(p5.p2FinalGasPolicy(config.gasPolicy).maxPriorityFeePerGas, "100000000");
  assert.equal(p5.p3GasPolicy(config.gasPolicy).maxPriorityFeePerGas, "100000000");
});

function changedEvidence(fields) {
  const body = { ...p5.P5_VERIFICATION_GAS_EVIDENCE_BODY, ...fields };
  return { ...body, sha256: p5.canonicalSha256(body) };
}

test("exact P5 evidence selects final 80000 without applying the margin again", () => {
  const config = p5.loadConfiguration();
  const selection = p5.selectP5GasPolicy({
    estimate: {
      verificationGasLimit: 150000n,
      callGasLimit: 300000n,
      preVerificationGas: 100000n
    },
    feeData: { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000n },
    config,
    verificationGasEvidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  assert.equal(selection.selected.verificationGasLimit, 80000n);
  assert.notEqual(selection.selected.verificationGasLimit, 100000n);
  assert.equal(selection.basis.verificationEfficiency.status, "VERIFICATION_EFFICIENCY_PASS");
  assert.equal(selection.basis.verificationEfficiency.actualValidationGas, "37050");
  assert.equal(selection.basis.verificationEfficiency.minimumSafeVerificationGas, "46313");
  assert.equal(selection.basis.verificationEfficiency.maximumEfficientVerificationGasLimit,
    "92625");
  assert.equal(46313n <= selection.selected.verificationGasLimit, true);
  assert.equal(selection.selected.verificationGasLimit <= 92625n, true);
  assert.equal(37050 / 80000, 0.463125);
  assert.equal(p5.assertP5VerificationEfficiency(
    selection.basis.verificationEfficiency
  ), selection.basis.verificationEfficiency);
});

test("46312 fails absolute safety and 46313 is the exact minimum safe boundary", () => {
  const below = p5.assessP5VerificationEfficiency({
    verificationGasLimit: 46312n, evidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  const boundary = p5.assessP5VerificationEfficiency({
    verificationGasLimit: 46313n, evidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  assert.equal(below.status, "VERIFICATION_GAS_ABSOLUTE_SAFETY_FAIL");
  assert.equal(boundary.status, "VERIFICATION_EFFICIENCY_PASS");
  assert.throws(() => p5.assertP5VerificationEfficiency(below),
    /PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EFFICIENCY_INSUFFICIENT/u);
});

test("92625 is the exact efficiency maximum and 92626 fails", () => {
  const boundary = p5.assessP5VerificationEfficiency({
    verificationGasLimit: 92625n, evidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  const above = p5.assessP5VerificationEfficiency({
    verificationGasLimit: 92626n, evidence: p5.P5_VERIFICATION_GAS_EVIDENCE
  });
  assert.equal(boundary.status, "VERIFICATION_EFFICIENCY_PASS");
  assert.equal(above.status, "VERIFICATION_EFFICIENCY_FAIL");
  assert.throws(() => p5.assertP5VerificationEfficiency(above),
    /PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EFFICIENCY_INSUFFICIENT/u);
});

test("missing verification evidence is UNPROVEN and planner selection fails closed", () => {
  const config = p5.loadConfiguration();
  const selection = p5.selectP5GasPolicy({
    estimate: {
      verificationGasLimit: 150000n,
      callGasLimit: 300000n,
      preVerificationGas: 100000n
    },
    feeData: { maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000n },
    config
  });
  assert.equal(selection.basis.verificationEfficiency.status,
    "VERIFICATION_EFFICIENCY_UNPROVEN");
  assert.throws(() => p5.assertP5VerificationEfficiency(
    selection.basis.verificationEfficiency
  ), /PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EFFICIENCY_UNPROVEN/u);
});

test("malformed, mismatched-gas, mismatched-threshold, and changed-selection evidence fail closed", () => {
  const cases = [
    {},
    changedEvidence({ actualValidationGas: "37051" }),
    changedEvidence({ efficiencyThresholdNumerator: "3" }),
    changedEvidence({ efficiencyThresholdDenominator: "6" }),
    changedEvidence({ selectedVerificationGasLimit: "80001" }),
    changedEvidence({ minimumSafeVerificationGas: "46312" }),
    changedEvidence({ maximumEfficiencyCompliantVerificationGas: "92626" })
  ];
  for (const evidence of cases) {
    assert.throws(() => p5.assessP5VerificationEfficiency({
      verificationGasLimit: 80000n, evidence
    }), /PHILCORE_CONTROLLED_BETA_P5_VERIFICATION_EVIDENCE_INVALID/u);
  }
});

test("synthetic replacement plan integrity-binds PASS evidence and final 80000", async () => {
  const row = await fixture();
  assert.equal(p5.gasFields(row.plan.userOperation.packed).verificationGasLimit, 80000n);
  assert.equal(row.plan.userOperation.gasAndFeeSelection.verificationEfficiency.status,
    "VERIFICATION_EFFICIENCY_PASS");
  assert.deepEqual(
    row.plan.userOperation.gasAndFeeSelection.verificationEfficiency.evidence,
    p5.P5_VERIFICATION_GAS_EVIDENCE
  );
  assert.equal(p5.assertPlanIntegrity(row.plan, row.config), row.plan);
  assert.match(source(PLANNER),
    /verificationGasEvidence: p5\.P5_VERIFICATION_GAS_EVIDENCE/u);
  assert.match(source(PLANNER),
    /assertP5VerificationEfficiency\(gasSelection\.basis\.verificationEfficiency\)/u);
});

function nestedRpcError(message, data = { detail: "bounded" }, code = -32602) {
  const error = new Error("could not coalesce error");
  error.code = "UNKNOWN_ERROR";
  error.shortMessage = "bundler rejected operation";
  error.info = {
    error: { code, message, data },
    payload: {
      id: 17,
      jsonrpc: "2.0",
      method: "eth_sendUserOperation",
      params: [{ signature: `0x${"77".repeat(130)}` }]
    }
  };
  return error;
}

test("sanitized bundler rejection classifier covers deterministic AA and policy categories", () => {
  const cases = [
    ["AA23 reverted during validation", "AA_VALIDATION_REJECTION", "AA23"],
    ["max priority fee per gas must be at least 100000000", "PRIORITY_FEE_ADMISSION_REJECTION", null],
    ["verification gas limit efficiency too low", "VERIFICATION_GAS_EFFICIENCY_REJECTION", null],
    ["AA21 didn't pay prefund", "PREFUND_REJECTION", "AA21"],
    ["AA25 invalid account nonce", "NONCE_REJECTION", "AA25"],
    ["AA24 signature error", "SIGNATURE_REJECTION", "AA24"],
    ["entity reputation policy requires stake", "BUNDLER_POLICY_REJECTION", null],
    ["provider declined request", "UNKNOWN_REJECTION", null]
  ];
  for (const [message, classification, aaCode] of cases) {
    const evidence = p5.bundlerRejectionEvidence(nestedRpcError(message), {
      sendDisposition: "REJECTED_BEFORE_BUNDLER_ACCEPTANCE",
      userOperationHash: `0x${"11".repeat(32)}`,
      attemptedAt: "2026-08-28T00:00:00.000Z"
    });
    assert.equal(evidence.classification, classification, message);
    assert.equal(evidence.aaCode, aaCode, message);
    assert.equal(evidence.ethersCode, "UNKNOWN_ERROR");
    assert.equal(evidence.rpcCode, -32602);
    assert.equal(evidence.requestId, 17);
    assert.equal(evidence.providerRole, "bundler");
    assert.equal(evidence.rpcMethod, "eth_sendUserOperation");
    assert.equal(evidence.rpcData.type, "OBJECT");
    assert.match(evidence.rpcData.sha256, /^0x[0-9a-f]{64}$/u);
    assert.equal(Object.hasOwn(evidence, "params"), false);
    assert.equal(JSON.stringify(evidence).includes(`0x${"77".repeat(130)}`), false);
  }

  const transport = p5.bundlerRejectionEvidence(new Error("transport timeout"), {
    sendDisposition: "AMBIGUOUS_TRANSPORT_RESULT",
    userOperationHash: `0x${"22".repeat(32)}`,
    attemptedAt: "2026-08-28T00:00:00.000Z"
  });
  assert.equal(transport.classification, "TRANSPORT_OR_AMBIGUOUS");
  assert.equal(transport.message, "transport timeout");
});

test("bundler diagnostic sanitizer removes credentials, endpoints, private keys, and signed payloads", () => {
  const knownSecret = "known-secret-token-123";
  const privateKey = `0x${"44".repeat(32)}`;
  const signedPayload = `0x${"55".repeat(130)}`;
  const message = [
    "request rejected at https://bundler.invalid/rpc?apiKey=visible-secret",
    "Authorization: Bearer bearer-secret",
    "api_key=api-secret",
    `private_key=${privateKey}`,
    knownSecret,
    signedPayload,
    "x".repeat(2000)
  ].join(" ");
  const evidence = p5.bundlerRejectionEvidence(nestedRpcError(message, {
    message,
    rawRequest: { signature: signedPayload }
  }), {
    sendDisposition: "REJECTED_BEFORE_BUNDLER_ACCEPTANCE",
    userOperationHash: `0x${"33".repeat(32)}`,
    attemptedAt: "2026-08-28T00:00:00.000Z",
    redactionValues: [knownSecret]
  });
  const durable = JSON.stringify(evidence);
  for (const secret of ["visible-secret", "bearer-secret", "api-secret", knownSecret,
    privateKey, signedPayload]) {
    assert.equal(durable.includes(secret), false, secret);
  }
  assert.ok(evidence.message.length <= 1024);
  assert.ok((evidence.rpcData.summary || "").length <= 1024);
  assert.deepEqual(evidence.rpcData.keys.sort(), ["message", "rawRequest"]);
  assert.equal(Object.hasOwn(evidence.rpcData, "rawRequest"), false);
  assert.match(durable, /REDACTED_/u);
});

test("synthetic attempt-1-shaped rejection demonstrates prospective retention without recovery claim", () => {
  const attempt1Hash = "0xade275d0de8db399a4f829e47b5b20b7212c84571762f70584567bbeee64503e";
  const fixtureStatement = "SYNTHETIC_FIXTURE_ORIGINAL_PROVIDER_RESPONSE_UNAVAILABLE";
  const evidence = p5.bundlerRejectionEvidence(
    nestedRpcError("AA23 synthetic validation rejection", { detail: fixtureStatement }),
    {
      sendDisposition: "REJECTED_BEFORE_BUNDLER_ACCEPTANCE",
      userOperationHash: attempt1Hash,
      attemptedAt: "2026-08-27T00:00:00.000Z"
    }
  );
  assert.equal(evidence.userOperationHash, attempt1Hash);
  assert.equal(evidence.aaCode, "AA23");
  assert.equal(evidence.classification, "AA_VALIDATION_REJECTION");
  assert.equal(fixtureStatement.includes("ORIGINAL_PROVIDER_RESPONSE_UNAVAILABLE"), true);
});

test("executor durably persists sanitized rejection before generic fail-closed stop", async () => {
  const row = await fixture();
  const credentialUrl = "https://bundler.invalid/rpc?apiKey=never-store-this";
  const mocks = executionMocks(row, {
    sendError: nestedRpcError(`AA23 validation failed via ${credentialUrl}`)
  });
  const snapshots = [];
  await assert.rejects(executor.executeWithDependencies({
    plan: row.plan,
    planBytes: row.planBytes,
    artifact: row.artifact,
    artifactBytes: row.artifactBytes,
    approvedDigest: row.plan.planDigest,
    suppliedApproval: row.plan.approval.requiredPhrase,
    config: row.config,
    primary: mocks.primary,
    reconciliation: mocks.reconciliation,
    bundler: mocks.bundler,
    lockPath: "/not-used",
    receiptPath: "/not-used",
    persist(_target, value) { snapshots.push(JSON.parse(JSON.stringify(value))); },
    sourceMatches: () => true,
    readState: async () => row.state,
    acquireLock: () => ({ stageId: "P5", lineageId: row.plan.lineageId }),
    classify: mocks.classify,
    redactionValues: [credentialUrl]
  }), /PHILCORE_CONTROLLED_BETA_P5_STOPPED_REQUIRES_HUMAN_RECONCILIATION/u);

  const rejectionSnapshot = snapshots.find((value) =>
    value.status === "SEND_REJECTED_PENDING_EXACT_HASH_RECONCILIATION");
  assert.ok(rejectionSnapshot);
  assert.equal(rejectionSnapshot.rejectionEvidence.aaCode, "AA23");
  assert.equal(rejectionSnapshot.rejectionEvidence.classification, "AA_VALIDATION_REJECTION");
  assert.equal(JSON.stringify(rejectionSnapshot).includes("never-store-this"), false);
  assert.equal(rejectionSnapshot.automaticRetryOccurred, false);
  assert.deepEqual(mocks.counts(), { sendCount: 1, receiptReads: 2, operationReads: 2 });
});

test("future P5 lineage namespace rejects consumed attempt 1 and binds every replacement artifact", async () => {
  assert.throws(() => p5.assertFutureLineageId("p5-attempt-0001"),
    /PHILCORE_CONTROLLED_BETA_P5_FUTURE_LINEAGE_ID_INVALID/u);
  const attempt2 = p5.lineagePaths("p5-attempt-0002");
  const attempt3 = p5.lineagePaths("p5-attempt-0003");
  assert.notEqual(attempt2.root, attempt3.root);
  assert.notEqual(attempt2.executionLock, p5.DEFAULT_EXECUTION_LOCK_PATH);
  assert.notEqual(attempt2.receipt, p5.DEFAULT_RECEIPT_PATH);
  assert.match(attempt2.plan, /p5-lineages\/p5-attempt-0002\/plan-v2\.json$/u);

  const row = await fixture();
  assert.equal(row.plan.lineageId, "p5-attempt-0002");
  assert.equal(row.artifact.lineageId, row.plan.lineageId);
  assert.equal(row.plan.lineage.priorAttemptLineageId, "p5-attempt-0001");
  assert.equal(row.plan.lineage.priorAttemptDisposition,
    "ATTEMPT_CONSUMED_RESUBMISSION_FORBIDDEN");
  const mismatched = { ...row.artifact, lineageId: "p5-attempt-0003" };
  const mismatchedBytes = Buffer.from(`${JSON.stringify(mismatched, null, 2)}\n`);
  assert.throws(() => p5.assertArtifactBinding(
    row.plan, row.planBytes, mismatched, mismatchedBytes, row.config
  ), /PHILCORE_CONTROLLED_BETA_P5_SIGNED_ARTIFACT_INVALID/u);
});

test("executor retains exactly one P5 send site and no automatic retry path", () => {
  const executorSource = source(EXECUTOR);
  assert.equal((executorSource.match(/bundler\.send\("eth_sendUserOperation"/gu) || []).length, 1);
  assert.doesNotMatch(executorSource, /retry\s*\(/iu);
});
