"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { ethers } = require("ethers");
require("tsx/cjs");
const preparation = require(
  "../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts"
);

const ROOT = path.resolve(__dirname, "../..");
const script = (name) => path.join(ROOT, "scripts/ethereum-sepolia", name);
const COMMON = script("philcore-controlled-sepolia-beta-p2-common.cjs");
const COMPOSITION = script("prepare-philcore-controlled-sepolia-beta-p2-composition.cjs");
const PLAN = script("prepare-philcore-controlled-sepolia-beta-p2-final.cjs");
const EXECUTE = script("execute-philcore-controlled-sepolia-beta-p2-final.cjs");
const P3_COMPOSITION = script("prepare-philcore-controlled-sepolia-beta-p3-composition.cjs");
const P3_PLAN = script("prepare-philcore-controlled-sepolia-beta-p3.cjs");
const P3_EXECUTE = script("execute-philcore-controlled-sepolia-beta-p3.cjs");
const CEREMONY_LIFECYCLE = path.join(
  ROOT, "apps/philcore-desktop/src/main/controlled-sepolia-beta-ceremony-lifecycle.cjs"
);

function source(location) {
  return fs.readFileSync(location, "utf8");
}

function run(location, args = [], env = {}) {
  return spawnSync(process.execPath, [location, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env }
  });
}

async function nonceOneFixture() {
  const common = require(COMMON);
  const compiled = common.artifacts();
  const owner = new ethers.Wallet(`0x${"41".repeat(32)}`);
  const config = JSON.parse(JSON.stringify(common.loadConfiguration()));
  config.account.initialExecutionValidator = owner.address;
  config.account.ownerCommitment = ethers.id("p3-parser-owner");
  config.account.salt = ethers.id("p3-parser-salt");
  const constructor = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address", "address", "uint64", "uint64"],
    [
      config.entryPoint,
      owner.address,
      config.account.ownerCommitment,
      config.infrastructure.actionGate,
      config.account.initialRecoveryAuthority,
      common.RECOVERY_DELAY_SECONDS,
      common.RECOVERY_EXPIRY_SECONDS
    ]
  );
  config.account.predictedAddress = ethers.getCreate2Address(
    config.infrastructure.factory,
    config.account.salt,
    ethers.keccak256(ethers.concat([compiled.account.bytecode, constructor]))
  );
  const envelope = ethers.id("p3-parser-envelope");
  const nullifier = ethers.id("p3-parser-nullifier");
  const deviceNonce = ethers.id("p3-parser-device");
  const gateData = common.gateInterface.encodeFunctionData("verifyAndConsume", [
    envelope, nullifier, deviceNonce, 2_000_000_000n, owner.address
  ]);
  const gas = {
    verificationGasLimit: common.P3_VERIFICATION_GAS_LIMIT,
    callGasLimit: 500_000n,
    preVerificationGas: 150_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 100_000_000n
  };
  const operation = {
    sender: config.account.predictedAddress.toLowerCase(),
    nonce: "1",
    initCode: "0x",
    callData: common.accountInterface.encodeFunctionData("execute", [
      config.infrastructure.actionGate, 0n, gateData
    ]),
    accountGasLimits: preparation.packPhilCore4337AccountGasLimits(gas),
    preVerificationGas: gas.preVerificationGas.toString(),
    gasFees: preparation.packPhilCore4337GasFees(gas),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const hash = preparation.computePhilCore4337UserOperationHash({
    userOperation: operation,
    entryPointAddress: config.entryPoint,
    chainId: common.CHAIN_ID
  });
  operation.signature = await owner.signMessage(ethers.getBytes(hash));
  const maximum = (gas.verificationGasLimit + gas.callGasLimit + gas.preVerificationGas)
    * gas.maxFeePerGas;
  return {
    common,
    compiled,
    config,
    artifact: {
      format: "phil-sepolia-mint-signed-unsubmitted-v1",
      signed: true,
      submitted: false,
      ethereumVerifiesNoirProof: false,
      ethereumVerifiesP256Approval: false,
      phoneAssurance: config.phoneAssurance,
      authorizationEnvelopeDigest: envelope,
      rootProofNullifier: nullifier,
      deviceApprovalNonce: deviceNonce,
      smartAccount: config.account.predictedAddress,
      actionGate: config.infrastructure.actionGate,
      accountNonce: "1",
      maximumTotalFeeWei: maximum.toString(),
      userOperationHash: hash,
      userOperation: operation
    }
  };
}

test("P3 entrypoints select a distinct fail-closed mode", () => {
  for (const location of [P3_COMPOSITION, P3_PLAN, P3_EXECUTE]) {
    assert.match(source(location), /process\.argv\.push\("--p3"\)/u);
  }
  const common = require(COMMON);
  assert.notEqual(common.DEFAULT_P3_SIGNED_ARTIFACT_PATH, common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH);
  assert.notEqual(common.DEFAULT_P3_PLAN_PATH, common.DEFAULT_FINAL_PLAN_PATH);
  assert.notEqual(common.DEFAULT_P3_RECEIPT_PATH, common.DEFAULT_FINAL_RECEIPT_PATH);
  assert.notEqual(common.DEFAULT_P3_EXECUTION_LOCK_PATH, common.DEFAULT_FINAL_EXECUTION_LOCK_PATH);
});

test("P3 composition requires exact-source review before phone, RPC, or Keychain access", () => {
  const value = source(COMPOSITION);
  const review = value.indexOf("acceptedReview(source, mode)");
  assert.ok(review >= 0);
  for (const later of [
    "common.loadConfiguration()",
    'common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH")',
    'common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL")',
    "selectIPhonePrivateInterface()",
    "readVaultKey(metadata.keychainServices.vault)",
    "physicalEnrollment({"
  ]) assert.ok(review < value.indexOf(later), later);
  assert.match(value, /PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW/u);
  assert.match(value, /expectedNonce: p3Mode \? 1 : 0/u);
  assert.match(value, /accountNonce: p3Mode \? "1" : "0"/u);
  assert.match(value, /accountDeployed: finalMode \|\| p3Mode/u);
});

test("P3 planner is read-only and proves the stale P2 operation rejected", () => {
  const value = source(PLAN);
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(value.includes(forbidden), false, forbidden);
  assert.match(value, /common\.assertP2FinalReceipt/u);
  assert.match(value, /common\.assertP2FinalOriginLive/u);
  assert.match(value, /common\.assertStaleP2UserOperationRejected/u);
  assert.match(value, /SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_1_V07_USER_OPERATION/u);
  assert.match(value, /maximumAdditionalFundingWei: "0"/u);
  assert.match(value, /factoryDataPresent: false/u);
  assert.match(value, /submissionAttemptsAllowed: 1/u);
});

test("P3 stale replay proof uses a non-mutating bundler estimate and requires nonce rejection", () => {
  const value = source(COMMON);
  assert.match(value, /async function assertStaleP2UserOperationRejected/u);
  assert.match(value, /"eth_estimateUserOperationGas"/u);
  assert.match(value, /\(AA25\|invalid account nonce\|nonce\)/u);
  assert.match(value, /publicMutationOccurred: false/u);
  const functionStart = value.indexOf("async function assertStaleP2UserOperationRejected");
  const functionEnd = value.indexOf("function normalizeEstimate", functionStart);
  const body = value.slice(functionStart, functionEnd);
  assert.equal(body.includes("eth_sendUserOperation"), false);
  assert.equal(body.includes("eth_sendRawTransaction"), false);
});

test("P3 corrective gas cap satisfies the observed bundler efficiency threshold", () => {
  const common = require(COMMON);
  const configured = common.loadConfiguration().gasPolicy;
  const selected = common.p3GasPolicy(configured);
  assert.equal(common.P3_VERIFICATION_GAS_LIMIT, 80_000n);
  assert.equal(BigInt(selected.verificationGasLimit), 80_000n);
  assert.ok(37_538 / Number(common.P3_VERIFICATION_GAS_LIMIT) >= 0.4);
  assert.doesNotThrow(() => common.assertP3GasPolicy(selected, configured));
  assert.throws(
    () => common.assertP3GasPolicy({ ...selected, verificationGasLimit: "150000" }, configured),
    /PHILCORE_CONTROLLED_BETA_P3_GAS_POLICY_INVALID/u
  );
  assert.throws(
    () => common.p3GasPolicy({ ...configured, verificationGasLimit: "79999" }),
    /PHILCORE_CONTROLLED_BETA_P3_VERIFICATION_GAS_CAP_INSUFFICIENT/u
  );
  assert.match(source(COMPOSITION), /p3Mode \? common\.p3GasPolicy\(config\.gasPolicy\)/u);
  assert.match(source(PLAN), /p3Mode\) common\.assertP3GasPolicy/u);
  assert.match(source(EXECUTE), /p3Mode\) common\.assertP3GasPolicy/u);
});

test("Phase 1 preserves the distinct P2F verification gas cap", () => {
  const common = require(COMMON);
  const configured = common.loadConfiguration().gasPolicy;
  const selected = common.p2FinalGasPolicy(configured);
  assert.equal(common.P2_FINAL_VERIFICATION_GAS_LIMIT, 150_000n);
  assert.equal(BigInt(selected.verificationGasLimit), 150_000n);
  assert.doesNotThrow(() => common.assertP2FinalGasPolicy(selected, configured));
  assert.throws(
    () => common.assertP2FinalGasPolicy({ ...selected, verificationGasLimit: "80000" }, configured),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_GAS_POLICY_INVALID/u
  );
});

test("P3 composition uses the sanitized lifecycle at the real enrollment and authorization boundary", () => {
  const composition = source(COMPOSITION);
  const lifecycle = source(CEREMONY_LIFECYCLE);
  assert.match(composition, /physicalEnrollmentLifecycle\(\{/u);
  assert.match(composition, /reconcileP3SupportRoot\(outputRoot, source\)/u);
  assert.match(composition, /authorization_response_observed/u);
  assert.match(composition, /approved_authorization_persisted/u);
  assert.match(composition, /restoreApproved\(\)/u);
  assert.match(composition, /completed_cleaned/u);
  for (const forbidden of ["eth_sendUserOperation", "eth_sendRawTransaction", "eth_sendTransaction",
    "phil_secret", "privateKey", "qrPayload", "authorizationEnvelope", "rpcUrl", "bundlerUrl"])
    assert.equal(lifecycle.includes(forbidden), false, forbidden);
});

test("Phase 1 failure handling stays before Device Vault release and every P3 mutation artifact", () => {
  const composition = source(COMPOSITION);
  const signedGuard = composition.indexOf("fs.existsSync(signedArtifactPath)");
  const lifecycleReconcile = composition.indexOf("if (p3Mode) p3Lifecycle = reconcileP3SupportRoot(outputRoot, source)");
  const guardedFailure = composition.indexOf("guardedPaths.some((location) => fs.existsSync(location))");
  const enrollment = composition.indexOf("physicalEnrollmentLifecycle({");
  const responseObserved = composition.indexOf('"authorization_response_observed"');
  const vaultRelease = composition.indexOf("createDeviceVaultSigner: async");
  assert.ok(signedGuard >= 0 && signedGuard < lifecycleReconcile);
  assert.ok(guardedFailure >= 0 && guardedFailure < lifecycleReconcile);
  assert.ok(lifecycleReconcile < enrollment);
  assert.ok(enrollment < responseObserved && responseObserved < vaultRelease);
  assert.match(composition, /DEFAULT_P3_PLAN_PATH[\s\S]*DEFAULT_P3_RECEIPT_PATH[\s\S]*DEFAULT_P3_EXECUTION_LOCK_PATH/u);
});

test("P3 corrective runner binds the rejected submission and proves it absent", () => {
  const common = require(COMMON);
  assert.deepEqual(common.P3_REJECTED_SUBMISSION_ORIGIN, {
    planDigest: "0x211ce78797e0c9a85d7b2071bfc280e4fa98c3de316ca565bacdc09bcceb7b45",
    userOperationHash: "0x3cb1fffacce39bfdabce03f4636375f04f623f95c82aa0d445ea74f89e9ca843",
    verificationGasLimit: "150000",
    requiredEfficiency: "0.4",
    observedEfficiency: "0.2502533333333333",
    rpcCode: -32602,
    rejection: "VERIFICATION_GAS_LIMIT_EFFICIENCY_TOO_LOW",
    resultingNonce: "1",
    resultingNextTokenId: "2"
  });
  assert.ok(Object.isFrozen(common.P3_REJECTED_SUBMISSION_ORIGIN));
  const commonSource = source(COMMON);
  assert.match(commonSource, /async function assertRejectedP3SubmissionAbsent/u);
  assert.match(commonSource, /PHILCORE_CONTROLLED_BETA_P3_REJECTED_SUBMISSION_FOUND/u);
  assert.match(source(PLAN), /common\.assertRejectedP3SubmissionAbsent\(bundler\)/u);
  assert.match(source(EXECUTE), /common\.assertRejectedP3SubmissionAbsent\(bundler\)/u);
  assert.match(source(EXECUTE), /plan\.rejectedP3Submission\?\.confirmedAbsent !== true/u);
});

test("P3 parser accepts only the deployed-account nonce-1 operation", async () => {
  const fixture = await nonceOneFixture();
  const parsed = fixture.common.parseSignedArtifact(
    fixture.artifact,
    fixture.config,
    fixture.compiled,
    { accountDeployed: true, expectedNonce: 1 }
  );
  assert.equal(parsed.rpc.nonce, "0x1");
  assert.equal(parsed.rpc.factory, null);
  assert.equal(parsed.rpc.factoryData, null);
  assert.equal(parsed.accountDeployed, true);
  assert.throws(
    () => fixture.common.parseSignedArtifact(
      fixture.artifact, fixture.config, fixture.compiled, { accountDeployed: true }
    ),
    /PHILCORE_CONTROLLED_BETA_P2_OPERATION_BINDING_INVALID/u
  );
  assert.throws(
    () => fixture.common.parseSignedArtifact(
      { ...fixture.artifact, accountNonce: "0" },
      fixture.config,
      fixture.compiled,
      { accountDeployed: true, expectedNonce: 1 }
    ),
    /PHILCORE_CONTROLLED_BETA_P2_OPERATION_BINDING_INVALID/u
  );
});

test("P3 exact P2 origin is immutable and receipt-bound", () => {
  const common = require(COMMON);
  assert.deepEqual(common.P2_FINAL_ORIGIN, {
    planDigest: "0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e",
    receiptByteSha256: "0x821dfa42c6c554725a6a31d7038ca7487dde1a2a8d51a2de60a5a7481efecec7",
    userOperationHash: "0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670",
    transactionHash: "0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934",
    blockNumber: "11573471",
    authorizationEnvelopeDigest: "0xe4962daa72bb3d11de8054959f9c012b1feff7e173093e09d91fdbc005a37f46",
    rootProofNullifier: "0xd4eea817f0068971cd0b9c9170525884e4b3ce6b0ea4f2bcf36ec3aba075b452",
    deviceApprovalNonce: "0x314c40d0d8f71c9385f6c1155844d744a6685a5d3f37a3e745f456862692078b",
    tokenId: "1",
    resultingNonce: "1",
    entryPointDepositWei: "779861479486230",
    resultingBalance: "1",
    resultingNextTokenId: "2"
  });
  assert.ok(Object.isFrozen(common.P2_FINAL_ORIGIN));
});

test("P3 preflight binds the exact P2 EntryPoint deposit instead of assuming zero", () => {
  const commonSource = source(COMMON);
  assert.match(
    commonSource,
    /expectedEntryPointDepositWei = BigInt\(options\.expectedEntryPointDepositWei \?\? 0\)/u
  );
  assert.match(commonSource, /left\[14\] !== expectedEntryPointDepositWei/u);
  assert.match(
    commonSource,
    /receipt\.finalState\?\.entryPointDepositWei !== P2_FINAL_ORIGIN\.entryPointDepositWei/u
  );
  for (const location of [COMPOSITION, PLAN, EXECUTE]) {
    const value = source(location);
    assert.match(value, /expectedEntryPointDepositWei: p3Mode/u);
    assert.match(value, /common\.P2_FINAL_ORIGIN\.entryPointDepositWei/u);
  }
  assert.match(
    source(PLAN),
    /startingEntryPointDepositWei: p3Mode\s*\? common\.P2_FINAL_ORIGIN\.entryPointDepositWei\s*:\s*"0"/u
  );
  assert.match(
    source(EXECUTE),
    /plan\.account\.startingEntryPointDepositWei !== \(p3Mode\s*\? common\.P2_FINAL_ORIGIN\.entryPointDepositWei\s*:\s*"0"\)/u
  );
});

test("P3 executor requires the exact digest approval before plan or network access", () => {
  const digest = `0x${"ab".repeat(32)}`;
  const absent = run(P3_EXECUTE, ["--plan-digest", digest]);
  assert.notEqual(absent.status, 0);
  assert.match(absent.stderr, /PHILCORE_CONTROLLED_BETA_P3_APPROVAL_REQUIRED/u);
  const wrong = run(P3_EXECUTE, ["--plan-digest", digest], {
    PHILCORE_CONTROLLED_BETA_P3_APPROVAL: "WRONG"
  });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /PHILCORE_CONTROLLED_BETA_P3_EXACT_APPROVAL_REQUIRED/u);
  assert.equal(absent.stderr.includes("ENOENT"), false);
  assert.equal(wrong.stderr.includes("ENOENT"), false);
});

test("P3 executor contains one submission call, no funding, and no retry", () => {
  const value = source(EXECUTE);
  assert.equal((value.match(/"eth_sendUserOperation"/gu) || []).length, 1);
  assert.equal(value.includes("eth_sendRawTransaction"), false);
  assert.equal(value.includes("eth_sendTransaction"), false);
  assert.equal(value.includes("broadcastTransaction("), false);
  assert.match(value, /DEFAULT_P3_EXECUTION_LOCK_PATH/u);
  assert.match(value, /automaticRetryOccurred: false/u);
  assert.match(value, /plan\.userOperation\?\.packed\?\.initCode !== "0x"/u);
});

test("P3 executor binds every frozen P2-origin and stale-rejection field", () => {
  const value = source(EXECUTE);
  for (const binding of [
    "plan.p2Final?.planDigest !== common.P2_FINAL_ORIGIN.planDigest",
    "plan.p2Final?.receiptByteSha256 !== common.P2_FINAL_ORIGIN.receiptByteSha256",
    "plan.p2Final?.userOperationHash !== common.P2_FINAL_ORIGIN.userOperationHash",
    "plan.p2Final?.transactionHash !== common.P2_FINAL_ORIGIN.transactionHash",
    'plan.staleP2ReplayProof?.method !== "eth_estimateUserOperationGas"',
    "plan.staleP2ReplayProof?.staleUserOperationHash",
    'plan.staleP2ReplayProof?.staleNonce !== "0"',
    'plan.staleP2ReplayProof?.liveNonce !== "1"',
    "plan.staleP2ReplayProof?.confirmedByBothProviders !== true"
  ]) assert.ok(value.includes(binding), binding);
});

test("P3 final-state reconciliation requires nonce 2, pass 2, and preserved P2 replay", () => {
  const value = source(EXECUTE);
  assert.match(value, /values\[6\] !== \(p3Mode \? 2n : 1n\)/u);
  assert.match(value, /tokenId !== \(p3Mode \? 2n : 1n\)/u);
  assert.match(value, /values\[14\] !== \(p3Mode \? 2n : 1n\)/u);
  assert.match(value, /values\[15\] !== \(p3Mode \? 3n : 2n\)/u);
  assert.match(value, /priorP2ReplayFieldsRemainConsumed: true/u);
  assert.match(value, /BigInt\(entryEvent\.args\.nonce\) !== \(p3Mode \? 1n : 0n\)/u);
});

test("P3 approval phrase is stage-specific", () => {
  const common = require(COMMON);
  const digest = `0x${"cd".repeat(32)}`;
  assert.equal(
    common.approvalPhrase("P3", digest),
    `I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_${"CD".repeat(32)}`
  );
  assert.notEqual(common.approvalPhrase("P3", digest), common.approvalPhrase("P2F", digest));
});
