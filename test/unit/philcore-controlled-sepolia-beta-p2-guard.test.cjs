"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { ethers } = require("ethers");
require("tsx/cjs");
const preparation = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");

const ROOT = path.resolve(__dirname, "../..");
const COMMON = path.join(ROOT, "scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p2-common.cjs");
const COMPOSITION = path.join(ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-composition.cjs");
const PLAN = path.join(ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2.cjs");
const EXECUTE = path.join(ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2.cjs");
const RECOVERY_PLAN = path.join(
  ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-recovery.cjs"
);
const RECOVERY_EXECUTE = path.join(
  ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2-recovery.cjs"
);
const ACCOUNT_DEPLOYMENT_PLAN = path.join(
  ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-account-deployment.cjs"
);
const ACCOUNT_DEPLOYMENT_EXECUTE = path.join(
  ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2-account-deployment.cjs"
);
const ACCOUNT_DEPLOYMENT_RECONCILE = path.join(
  ROOT, "scripts/ethereum-sepolia/reconcile-philcore-controlled-sepolia-beta-p2-account-deployment.cjs"
);
const FINAL_PLAN = path.join(
  ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-final.cjs"
);
const FINAL_EXECUTE = path.join(
  ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2-final.cjs"
);
const IOS_ROOT_VIEW = path.join(
  ROOT, "apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift"
);
const CLEAN = path.join(ROOT, "scripts/clean.cjs");

function run(script, args = [], env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env }
  });
}

async function signedFixture(recipientMode = "owner", accountDeployed = false) {
  const common = require(COMMON);
  const compiled = common.artifacts();
  const owner = new ethers.Wallet(`0x${"31".repeat(32)}`);
  const config = JSON.parse(JSON.stringify(common.loadConfiguration()));
  config.account.initialExecutionValidator = owner.address;
  config.account.ownerCommitment = ethers.id("p2-parser-owner");
  config.account.salt = ethers.id("p2-parser-salt");
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
  const envelope = ethers.id("p2-parser-envelope");
  const nullifier = ethers.id("p2-parser-nullifier");
  const approvalNonce = ethers.id("p2-parser-approval");
  const factoryData = common.factoryInterface.encodeFunctionData("createAccount", [
    owner.address, config.account.ownerCommitment, config.account.salt
  ]);
  const recipient = recipientMode === "owner" ? owner.address : config.account.predictedAddress;
  const gateData = common.gateInterface.encodeFunctionData("verifyAndConsume", [
    envelope, nullifier, approvalNonce, 2_000_000_000n, recipient
  ]);
  const callData = common.accountInterface.encodeFunctionData("execute", [
    config.infrastructure.actionGate, 0n, gateData
  ]);
  const gas = {
    verificationGasLimit: 1_500_000n,
    callGasLimit: 500_000n,
    preVerificationGas: 150_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 100_000_000n
  };
  const op = {
    sender: config.account.predictedAddress.toLowerCase(),
    nonce: "0",
    initCode: accountDeployed
      ? "0x"
      : ethers.concat([config.infrastructure.factory, factoryData]).toLowerCase(),
    callData,
    accountGasLimits: preparation.packPhilCore4337AccountGasLimits(gas),
    preVerificationGas: gas.preVerificationGas.toString(),
    gasFees: preparation.packPhilCore4337GasFees(gas),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const hash = preparation.computePhilCore4337UserOperationHash({
    userOperation: op,
    entryPointAddress: config.entryPoint,
    chainId: common.CHAIN_ID
  });
  op.signature = await owner.signMessage(ethers.getBytes(hash));
  const artifact = {
    format: "phil-sepolia-mint-signed-unsubmitted-v1",
    authorizationEnvelopeDigest: envelope,
    rootProofNullifier: nullifier,
    deviceApprovalNonce: approvalNonce,
    accountNonce: "0",
    userOperationHash: hash,
    userOperation: op,
    smartAccount: config.account.predictedAddress,
    actionGate: config.infrastructure.actionGate,
    maximumTotalFeeWei: ((gas.verificationGasLimit + gas.callGasLimit + gas.preVerificationGas)
      * gas.maxFeePerGas).toString(),
    signed: true,
    submitted: false,
    ethereumVerifiesNoirProof: false,
    ethereumVerifiesP256Approval: false,
    phoneAssurance: config.phoneAssurance
  };
  return { common, compiled, config, artifact, owner };
}

test("P2 planner contains no public mutation method and requires exact-source review first", () => {
  const source = fs.readFileSync(PLAN, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(source.includes(forbidden), false, forbidden);
  assert.match(source, /publicMutationOccurred: false/u);
  const result = run(PLAN);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHILCORE_CONTROLLED_BETA_(SOURCE_NOT_FROZEN|P2_RUNNER_REVIEW_COMMIT_REQUIRED)/u);
  assert.doesNotMatch(result.stderr, /RPC|NETWORK|KEYCHAIN/u);
  assert.ok(source.indexOf("common.sourceIdentity()")
    < source.indexOf("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL"));
});

test("P2 composition is local-only and requires exact-source review before phone, network, or Keychain access", () => {
  const source = fs.readFileSync(COMPOSITION, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(source.includes(forbidden), false, forbidden);
  assert.match(source, /submitted: false/u);
  assert.match(source, /publicMutationOccurred: false/u);
  const result = run(COMPOSITION);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHILCORE_CONTROLLED_BETA_(SOURCE_NOT_FROZEN|P2_RUNNER_REVIEW_COMMIT_REQUIRED)/u);
  assert.doesNotMatch(result.stderr, /VAULT_KEY|PRIVATE_INTERFACE|RPC|NETWORK|KEYCHAIN/u);
  assert.ok(source.indexOf("common.sourceIdentity()") < source.indexOf("selectIPhonePrivateInterface()"));
  assert.ok(source.indexOf("acceptedReview(source)") < source.indexOf("const vaultKey = readVaultKey("));
  assert.match(source, /PHILCORE_CONTROLLED_BETA_P2_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE/u);
  assert.ok(source.indexOf("fs.existsSync(location)") < source.indexOf("selectIPhonePrivateInterface()"));
  assert.ok(source.indexOf("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT")
    < source.indexOf("selectIPhonePrivateInterface()"));
  assert.equal(/rmSync|unlinkSync/u.test(source), false);
});

test("P2 disables JSON-RPC batching for provider-pair and bundler calls", () => {
  const common = require(COMMON);
  assert.deepEqual(common.PROVIDER_OPTIONS, { staticNetwork: true, batchMaxCount: 1 });
  for (const script of [
    COMPOSITION, PLAN, EXECUTE, RECOVERY_PLAN, RECOVERY_EXECUTE,
    ACCOUNT_DEPLOYMENT_PLAN, ACCOUNT_DEPLOYMENT_EXECUTE, FINAL_PLAN, FINAL_EXECUTE
  ]) {
    const source = fs.readFileSync(script, "utf8");
    assert.match(
      source,
      /new ethers\.JsonRpcProvider\([\s\S]*?common\.PROVIDER_OPTIONS\s*\)/u,
      script
    );
    assert.equal(source.includes("{ staticNetwork: true }"), false, script);
  }
});

test("P2 recovery planner is read-only and requires exact-source review first", () => {
  const source = fs.readFileSync(RECOVERY_PLAN, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(source.includes(forbidden), false, forbidden);
  assert.match(source, /publicMutationCount: common\.P2_RECOVERY_MUTATION_COUNT/u);
  assert.match(source, /maximumAdditionalFundingWei: "0"/u);
  assert.match(source, /prior_or_recovery_user_operation_found/u);
  const result = run(RECOVERY_PLAN);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHILCORE_CONTROLLED_BETA_(SOURCE_NOT_FROZEN|P2_RECOVERY_RUNNER_REVIEW_COMMIT_REQUIRED)/u);
  assert.doesNotMatch(result.stderr, /RPC|NETWORK|KEYCHAIN|ENOENT/u);
  assert.ok(source.indexOf("common.sourceIdentity()")
    < source.indexOf("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL"));
});

test("P2 recovery executor rejects absent and wrong approval before plan or network access", () => {
  const digest = `0x${"56".repeat(32)}`;
  const args = ["--plan-digest", digest, "--plan", "/definitely/not/a/recovery-plan.json"];
  const absent = run(RECOVERY_EXECUTE, args);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /PHILCORE_CONTROLLED_BETA_P2_RECOVERY_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(absent.stderr, /ENOENT|RPC|NETWORK/u);
  const wrong = run(RECOVERY_EXECUTE, args, {
    PHILCORE_CONTROLLED_BETA_P2_RECOVERY_APPROVAL: "approve"
  });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXACT_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(wrong.stderr, /ENOENT|RPC|NETWORK/u);
});

test("P2 recovery freezes one UserOperation, zero funding, and no automatic retry", () => {
  const planner = fs.readFileSync(RECOVERY_PLAN, "utf8");
  const executor = fs.readFileSync(RECOVERY_EXECUTE, "utf8");
  assert.match(planner, /SUBMIT_RECOVERY_NONCE_0_V07_USER_OPERATION/u);
  assert.equal((executor.match(/"eth_sendUserOperation"/gu) || []).length, 1);
  assert.equal((executor.match(/\.broadcastTransaction\(/gu) || []).length, 0);
  assert.equal((executor.match(/eth_sendRawTransaction/gu) || []).length, 0);
  assert.match(executor, /No public mutation is reachable above this line/u);
  assert.match(executor, /additionalFundingWei: "0"/u);
  assert.match(executor, /automaticRetryOccurred: false/u);
  assert.match(executor, /STOPPED_REQUIRES_READ_ONLY_RECONCILIATION/u);
  assert.match(planner, /originalLocalGeneratedArtifactsAvailable: false/u);
  assert.match(planner, /owner_approved_digest_and_incident_transcript_plus_live_two_provider_reconciliation/u);
  assert.match(planner, /common\.P2_RECOVERY_ORIGIN/u);
  assert.match(planner, /common\.assertP2RecoveryOriginLive/u);
  assert.match(executor, /common\.P2_RECOVERY_ORIGIN/u);
  assert.match(executor, /common\.assertP2RecoveryOriginLive/u);
  assert.doesNotMatch(planner, /originalPlanByteSha256|originalReceiptByteSha256|originalExecutionLockByteSha256/u);
  assert.doesNotMatch(executor, /originalPlanByteSha256|originalReceiptByteSha256|originalExecutionLockByteSha256/u);
  assert.match(executor, /rpcMessage/u);
  assert.match(executor, /rpcData/u);
  assert.match(executor, /REDACTED_ENDPOINT/u);
  assert.match(executor, /common\.acquireRecoveryExecutionLock\(plan\.planDigest, plan\.source\)/u);
  assert.ok(executor.indexOf("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_APPROVAL")
    < executor.indexOf("common.readJson(planPath)"));
  assert.ok(executor.indexOf("common.acquireRecoveryExecutionLock(plan.planDigest, plan.source)")
    < executor.indexOf('"eth_sendUserOperation"'));
});

test("P2 executors reconstruct signed-artifact addresses in canonical lowercase", () => {
  const common = require(COMMON);
  const checksummed = "0xD48e07a5c3A4E472E4923Db39219140F417A42D4";
  const canonical = "0xd48e07a5c3a4e472e4923db39219140f417a42d4";
  assert.equal(common.canonicalSignedArtifactAddress(checksummed), canonical);
  assert.equal(common.canonicalSignedArtifactAddress(canonical), canonical);
  assert.throws(
    () => common.canonicalSignedArtifactAddress("0xnot-an-address"),
    /invalid address/u
  );
  for (const script of [EXECUTE, RECOVERY_EXECUTE]) {
    const source = fs.readFileSync(script, "utf8");
    assert.match(
      source,
      /smartAccount: common\.canonicalSignedArtifactAddress\(plan\.account\.predictedAddress\)/u
    );
    assert.match(
      source,
      /actionGate: common\.canonicalSignedArtifactAddress\(plan\.contracts\.gate\)/u
    );
  }
});

test("P2 durable evidence lives outside generated build artifacts", () => {
  const common = require(COMMON);
  const generatedArtifactsRoot = path.join(ROOT, "artifacts");
  assert.equal(common.PRIVATE_EVIDENCE_ROOT.startsWith(`${generatedArtifactsRoot}${path.sep}`), false);
  assert.equal(common.PRIVATE_EVIDENCE_ROOT, path.join(
    ROOT, ".philcore-local", "controlled-sepolia-beta"
  ));
  for (const evidencePath of [
    common.DEFAULT_SIGNED_ARTIFACT_PATH,
    common.DEFAULT_PLAN_PATH,
    common.DEFAULT_RECEIPT_PATH,
    common.DEFAULT_EXECUTION_LOCK_PATH,
    common.DEFAULT_RECOVERY_SIGNED_ARTIFACT_PATH,
    common.DEFAULT_RECOVERY_PLAN_PATH,
    common.DEFAULT_RECOVERY_RECEIPT_PATH,
    common.DEFAULT_RECOVERY_EXECUTION_LOCK_PATH,
    common.DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH,
    common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH,
    common.DEFAULT_ACCOUNT_DEPLOYMENT_EXECUTION_LOCK_PATH,
    common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH,
    common.DEFAULT_FINAL_PLAN_PATH,
    common.DEFAULT_FINAL_RECEIPT_PATH,
    common.DEFAULT_FINAL_EXECUTION_LOCK_PATH
  ]) {
    assert.equal(evidencePath.startsWith(`${common.PRIVATE_EVIDENCE_ROOT}${path.sep}`), true);
  }
});

test("P2 recovery freezes the exact stopped incident and uses read-only live reconciliation", () => {
  const common = require(COMMON);
  const source = fs.readFileSync(COMMON, "utf8");
  assert.deepEqual(common.P2_RECOVERY_ORIGIN, {
    originalPlanDigest: "0x23467979ac3c95b6f7aa2c288292aa4718b4ae5c94e2998636ed7f9868ae0997",
    originalSourceCommit: "93966d02da445cc871447874aa8959e62ccd02cb",
    originalSourceTree: "47500c8ba00ad9d4ea73c3eca80e95e2790f631c",
    confirmedFundingTransactionHash: "0x60029b4b50246fa4c318caaf61ea184b838d6c28e2c41be6782409ff15136c9a",
    confirmedFundingBlockNumber: "11568484",
    confirmedFundingValueWei: "4840000000000000",
    confirmedFundingGasUsed: "21000",
    rejectedUserOperationHash: "0xff258b993d44b5d8729b1bee326887b9e65166b71bbf0337525f03be5e9e2cf6",
    originalAuthorizationEnvelopeDigest: "0xc5721ce3ab6d32bb09a3ab48d559f459dfe1deaf0fe79dfed22c0bc0871ce7e7",
    originalRootProofNullifier: "0xc102a31e0f9b17cf603c46fe94b6ea3f881b86375e20d6787db1e6c9e50b8b2d",
    originalDeviceApprovalNonce: "0xc20c377ea13fd1bc135948861a3a757da9b2603b0d9d8dc831c6045564b61f0d",
    rejectionCode: -32000,
    rejectionMessage: "precheck failed: maxPriorityFeePerGas is 1000000 but must be at least 100000000"
  });
  const liveFunction = source.slice(
    source.indexOf("async function assertP2RecoveryOriginLive"),
    source.indexOf("function normalizeEstimate")
  );
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(liveFunction.includes(forbidden), false, forbidden);
  assert.match(liveFunction, /eth_getUserOperationReceipt/u);
  assert.match(liveFunction, /eth_getUserOperationByHash/u);
  assert.match(liveFunction, /getTransactionReceipt/u);
  assert.match(liveFunction, /getTransaction/u);
});

test("P2 recovery durable execution lock permits one local attempt", () => {
  const common = require(COMMON);
  const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-p2r-lock-"));
  const lockPath = path.join(root, "attempt.lock.json");
  try {
    const source = { commit: "3".repeat(40), tree: "4".repeat(40) };
    const digest = `0x${"78".repeat(32)}`;
    const first = common.acquireRecoveryExecutionLock(digest, source, lockPath);
    assert.equal(first.stageId, "P2R");
    assert.equal(first.planDigest, digest);
    assert.equal(first.automaticRetryAllowed, false);
    assert.throws(
      () => common.acquireRecoveryExecutionLock(digest, source, lockPath),
      /PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXECUTION_ALREADY_ATTEMPTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("P2 account-deployment recovery is one exact direct factory call", () => {
  const planner = fs.readFileSync(ACCOUNT_DEPLOYMENT_PLAN, "utf8");
  const executor = fs.readFileSync(ACCOUNT_DEPLOYMENT_EXECUTE, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(planner.includes(forbidden), false, forbidden);
  assert.match(planner, /DIRECTLY_DEPLOY_PREFUNDED_SMART_ACCOUNT_THROUGH_EXISTING_FACTORY/u);
  assert.match(planner, /publicMutationCount: 1/u);
  assert.match(planner, /rejectedOperationAbsentFromBundler: true/u);
  assert.equal((executor.match(/\.broadcastTransaction\(/gu) || []).length, 1);
  assert.equal((executor.match(/"eth_sendUserOperation"/gu) || []).length, 0);
  assert.match(executor, /automaticRetryOccurred: false/u);
  assert.match(executor, /\[REDACTED_ENDPOINT\]/u);
  assert.match(executor, /evidence\.error = failure/u);
  assert.match(executor, /error\?\.info\?\.error\?\.data/u);
  assert.ok(executor.indexOf("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_DEPLOYMENT_APPROVAL")
    < executor.indexOf("common.readJson(planPath)"));
  assert.ok(executor.indexOf("common.acquireBoundedExecutionLock(")
    < executor.indexOf(".broadcastTransaction("));
  assert.equal(executor.includes("config.runtimeCodeHashes.account"), false);
});

test("P2 account-deployment reconciliation is read-only and preserves stopped evidence", () => {
  const reconciler = fs.readFileSync(ACCOUNT_DEPLOYMENT_RECONCILE, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction(", "walletFromKeychain(", ".signTransaction("
  ]) assert.equal(reconciler.includes(forbidden), false, forbidden);
  assert.match(reconciler, /eth_getTransactionByHash/u);
  assert.match(reconciler, /eth_getTransactionReceipt/u);
  assert.match(reconciler, /writeExclusiveBytes\(stoppedReceiptPath, receiptBytes\)/u);
  assert.match(reconciler, /publicMutationPerformedByReconciliation: false/u);
  assert.match(reconciler, /confirmed_by_both_providers/u);
  assert.match(reconciler, /\[REDACTED_ENDPOINT\]/u);
  assert.match(reconciler, /error\?\.info\?\.error\?\.data/u);
  assert.match(reconciler, /0x78770827598af3378b6ddea04c1131df2b3b7b42baf530163078c2a5fb6cf2ce/u);
  assert.match(reconciler, /0xdf9fcb7a6aaacb5946d70845404d1235aa424d9784ccda1d2b690bae19e75519/u);
});

test("P2 deployed-account runtime validation masks only compiler-declared immutables", () => {
  const common = require(COMMON);
  const compiled = common.artifacts().account.deployedBytecode;
  const immutableOnly = Buffer.from(compiled.slice(2), "hex");
  immutableOnly.fill(0x7a, 519, 551);
  assert.match(
    common.accountRuntimeIdentity(`0x${immutableOnly.toString("hex")}`).runtimeCodeHash,
    /^0x[0-9a-f]{64}$/u
  );
  const executableMutation = Buffer.from(compiled.slice(2), "hex");
  executableMutation[100] ^= 0x01;
  assert.throws(
    () => common.accountRuntimeIdentity(`0x${executableMutation.toString("hex")}`),
    /PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_RUNTIME_TEMPLATE_INVALID/u
  );
});

test("P2 bounded recovery locks are durable and stage-specific", () => {
  const common = require(COMMON);
  const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-p2-bounded-"));
  try {
    const source = { commit: "5".repeat(40), tree: "6".repeat(40) };
    const digest = `0x${"9a".repeat(32)}`;
    const p2aPath = path.join(root, "p2a.lock.json");
    const p2fPath = path.join(root, "p2f.lock.json");
    assert.equal(common.acquireBoundedExecutionLock(digest, source, "P2A", p2aPath).stageId, "P2A");
    assert.equal(common.acquireBoundedExecutionLock(digest, source, "P2F", p2fPath).stageId, "P2F");
    assert.throws(
      () => common.acquireBoundedExecutionLock(digest, source, "P2A", p2aPath),
      /PHILCORE_CONTROLLED_BETA_P2_BOUNDED_EXECUTION_ALREADY_ATTEMPTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("P2 recovery stage approval phrases are accepted and exact", () => {
  const common = require(COMMON);
  const digest = `0x${"ab".repeat(32)}`;
  assert.equal(
    common.approvalPhrase("P2A", digest),
    `I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P2A_${"AB".repeat(32)}`
  );
  assert.equal(
    common.approvalPhrase("P2F", digest),
    `I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P2F_${"AB".repeat(32)}`
  );
  assert.throws(
    () => common.approvalPhrase("P2Z", digest),
    /PHILCORE_CONTROLLED_BETA_APPROVAL_INPUT_INVALID/u
  );
});

test("P2 final flow is factory-free and permits one UserOperation only", () => {
  const composition = fs.readFileSync(COMPOSITION, "utf8");
  const planner = fs.readFileSync(FINAL_PLAN, "utf8");
  const executor = fs.readFileSync(FINAL_EXECUTE, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendUserOperation",
    ".broadcastTransaction(", ".sendTransaction("
  ]) assert.equal(planner.includes(forbidden), false, forbidden);
  assert.match(planner, /factoryDataPresent: false/u);
  assert.match(planner, /SUBMIT_PREDEPLOYED_ACCOUNT_NONCE_0_V07_USER_OPERATION/u);
  assert.equal((executor.match(/"eth_sendUserOperation"/gu) || []).length, 1);
  assert.equal((executor.match(/\.broadcastTransaction\(/gu) || []).length, 0);
  assert.match(executor, /plan\.userOperation\?\.packed\?\.initCode !== "0x"/u);
  assert.match(executor, /automaticRetryOccurred: false/u);
  assert.match(planner, /PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_RUNTIME_CHANGED/u);
  assert.match(planner, /accountImmutableMaskedRuntimeCodeHash/u);
  assert.match(executor, /common\.accountRuntimeIdentity\(accountCode\)/u);
  assert.match(executor, /runtimeCodeHashes\.accountImmutableMasked/u);
  assert.match(executor, /assertFinalRuntimeCodeHashes/u);
  assert.match(composition, /finalMode \? common\.p2FinalGasPolicy\(config\.gasPolicy\)/u);
  assert.match(planner, /common\.assertP2FinalGasPolicy\(parsed\.gas, config\.gasPolicy\)/u);
  assert.match(executor, /common\.assertP2FinalGasPolicy\(parsed\.gas, config\.gasPolicy\)/u);
  assert.match(executor, /PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_RUNTIME_CHANGED/u);
  assert.ok(executor.indexOf("PHILCORE_CONTROLLED_BETA_P2_FINAL_APPROVAL")
    < executor.indexOf("common.readJson(planPath)"));
  assert.ok(executor.indexOf("common.acquireBoundedExecutionLock(")
    < executor.indexOf('"eth_sendUserOperation"'));
});

test("P2 final gas policy stays within the configured cap and rejects drift", () => {
  const common = require(COMMON);
  const configured = common.loadConfiguration().gasPolicy;
  const selected = common.p2FinalGasPolicy(configured);
  assert.equal(
    BigInt(selected.verificationGasLimit), common.P2_FINAL_VERIFICATION_GAS_LIMIT
  );
  assert.equal(selected.callGasLimit, configured.callGasLimit);
  assert.equal(selected.preVerificationGas, configured.preVerificationGas);
  assert.doesNotThrow(() => common.assertP2FinalGasPolicy(selected, configured));
  assert.throws(
    () => common.assertP2FinalGasPolicy({ ...selected, verificationGasLimit: "1800000" }, configured),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_GAS_POLICY_INVALID/u
  );
  assert.throws(
    () => common.p2FinalGasPolicy({ ...configured, verificationGasLimit: "149999" }),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_VERIFICATION_GAS_CAP_INSUFFICIENT/u
  );
});

test("P2 final runtime manifest separates infrastructure and deployed-account hashes", () => {
  const common = require(COMMON);
  const configured = {
    entryPoint: `0x${"11".repeat(32)}`,
    consumer: `0x${"22".repeat(32)}`,
    gate: `0x${"33".repeat(32)}`,
    factory: `0x${"44".repeat(32)}`
  };
  const planned = {
    ...configured,
    account: `0x${"55".repeat(32)}`,
    accountImmutableMasked: `0x${"66".repeat(32)}`
  };
  assert.deepEqual(common.assertFinalRuntimeCodeHashes(planned, configured), planned);
  assert.throws(
    () => common.assertFinalRuntimeCodeHashes({ ...planned, factory: `0x${"77".repeat(32)}` }, configured),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNTIME_CODE_HASHES_INVALID/u
  );
  assert.throws(
    () => common.assertFinalRuntimeCodeHashes({ ...planned, extra: `0x${"88".repeat(32)}` }, configured),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNTIME_CODE_HASHES_INVALID/u
  );
  const missingAccount = { ...planned };
  delete missingAccount.account;
  assert.throws(
    () => common.assertFinalRuntimeCodeHashes(missingAccount, configured),
    /PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNTIME_CODE_HASHES_INVALID/u
  );
});

test("P2 parser accepts a deployed-account UserOperation only in deployed mode", async () => {
  const fixture = await signedFixture("owner", true);
  assert.throws(
    () => fixture.common.parseSignedArtifact(fixture.artifact, fixture.config, fixture.compiled),
    /PHILCORE_CONTROLLED_BETA_P2_INIT_CODE_INVALID/u
  );
  const parsed = fixture.common.parseSignedArtifact(
    fixture.artifact, fixture.config, fixture.compiled, { accountDeployed: true }
  );
  assert.equal(parsed.accountDeployed, true);
  assert.equal(parsed.rpc.factory, null);
  assert.equal(parsed.rpc.factoryData, null);
  assert.equal(parsed.localUserOperationHash, fixture.artifact.userOperationHash);
});

test("P2 fee policy enforces the bundler priority floor", async () => {
  const fixture = await signedFixture();
  assert.equal(
    BigInt(fixture.config.gasPolicy.maxPriorityFeePerGas),
    fixture.common.MINIMUM_BUNDLER_PRIORITY_FEE_WEI
  );
  const belowFloor = structuredClone(fixture.artifact);
  const unpacked = preparation.unpackPhilCore4337GasFees
    ? preparation.unpackPhilCore4337GasFees(belowFloor.userOperation.gasFees)
    : null;
  const maxFeePerGas = unpacked?.maxFeePerGas ?? 2_000_000_000n;
  belowFloor.userOperation.gasFees = preparation.packPhilCore4337GasFees({
    maxFeePerGas,
    maxPriorityFeePerGas: fixture.common.MINIMUM_BUNDLER_PRIORITY_FEE_WEI - 1n
  });
  belowFloor.maximumTotalFeeWei = "4300000000000000";
  const hash = preparation.computePhilCore4337UserOperationHash({
    userOperation: belowFloor.userOperation,
    entryPointAddress: fixture.config.entryPoint,
    chainId: fixture.common.CHAIN_ID
  });
  belowFloor.userOperationHash = hash;
  belowFloor.userOperation.signature = await fixture.owner.signMessage(ethers.getBytes(hash));
  assert.throws(
    () => fixture.common.parseSignedArtifact(belowFloor, fixture.config, fixture.compiled),
    /PHILCORE_CONTROLLED_BETA_P2_FEE_BINDING_INVALID/u
  );
});

test("P2 accepted screen exposes a second routine scan control", () => {
  const source = fs.readFileSync(IOS_ROOT_VIEW, "utf8");
  assert.match(source, /routine\.accepted\.scan\.button/u);
  assert.match(source, /Scan authorization QR code/u);
  assert.match(source, /Scan another routine QR code/u);
});

test("P2 executor rejects absent and wrong approval before plan, endpoint, network, or Keychain access", () => {
  const digest = `0x${"12".repeat(32)}`;
  const args = ["--plan-digest", digest, "--plan", "/definitely/not/a/plan.json"];
  const absent = run(EXECUTE, args);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /PHILCORE_CONTROLLED_BETA_P2_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(absent.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);
  const wrong = run(EXECUTE, args, { PHILCORE_CONTROLLED_BETA_P2_APPROVAL: "approve" });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /PHILCORE_CONTROLLED_BETA_P2_EXACT_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(wrong.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);
});

test("P2 freezes exactly two one-shot mutations and no automatic retry", () => {
  const planner = fs.readFileSync(PLAN, "utf8");
  const executor = fs.readFileSync(EXECUTE, "utf8");
  assert.match(planner, /publicMutationCount: common\.P2_MUTATION_COUNT/u);
  assert.match(planner, /FUND_COUNTERFACTUAL_BETA_ACCOUNT/u);
  assert.match(planner, /SUBMIT_NONCE_0_V07_USER_OPERATION/u);
  assert.match(planner, /PHILCORE_CONTROLLED_BETA_P2_PLAN_ALREADY_EXISTS_REQUIRES_ARCHIVE/u);
  assert.equal((executor.match(/\.broadcastTransaction\(/gu) || []).length, 1);
  assert.equal((executor.match(/"eth_sendUserOperation"/gu) || []).length, 1);
  assert.match(executor, /No public mutation is reachable above this line/u);
  assert.match(executor, /STOPPED_REQUIRES_READ_ONLY_RECONCILIATION/u);
  assert.match(executor, /automaticRetryOccurred: false/u);
  assert.match(executor, /PHILCORE_CONTROLLED_BETA_P2_RECEIPT_ALREADY_EXISTS_REQUIRES_RECONCILIATION/u);
  assert.match(executor, /common\.acquireExecutionLock\(plan\.planDigest, plan\.source\)/u);
  assert.equal(executor.includes("--execution-lock"), false);
  assert.ok(executor.indexOf("common.acquireExecutionLock(plan.planDigest, plan.source)")
    < executor.indexOf(".broadcastTransaction("));
  assert.ok(executor.indexOf("PHILCORE_CONTROLLED_BETA_P2_APPROVAL")
    < executor.indexOf("common.readJson(planPath)"));
  assert.ok(executor.indexOf("common.readJson(planPath)")
    < executor.indexOf("walletFromKeychain"));
});

test("P2 durable execution lock permits one local attempt and blocks the second", () => {
  const common = require(COMMON);
  const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-p2-lock-"));
  const lockPath = path.join(root, "attempt.lock.json");
  try {
    const source = { commit: "1".repeat(40), tree: "2".repeat(40) };
    const digest = `0x${"34".repeat(32)}`;
    const first = common.acquireExecutionLock(digest, source, lockPath);
    assert.equal(first.planDigest, digest);
    assert.equal(first.automaticRetryAllowed, false);
    assert.equal(first.disposition, "PERSIST_UNTIL_READ_ONLY_RECONCILIATION");
    assert.throws(
      () => common.acquireExecutionLock(digest, source, lockPath),
      /PHILCORE_CONTROLLED_BETA_P2_EXECUTION_ALREADY_ATTEMPTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("P2 signed gas estimates must be positive and stay within every signed cap", async () => {
  const { common, artifact, config, compiled } = await signedFixture();
  const parsed = common.parseSignedArtifact(artifact, config, compiled);
  const within = common.normalizeEstimate({
    verificationGasLimit: parsed.gas.verificationGasLimit,
    callGasLimit: parsed.gas.callGasLimit,
    preVerificationGas: parsed.gas.preVerificationGas
  });
  assert.doesNotThrow(() => common.assertEstimateWithinSignedCaps(within, parsed));
  assert.throws(
    () => common.normalizeEstimate({
      verificationGasLimit: 0,
      callGasLimit: parsed.gas.callGasLimit,
      preVerificationGas: parsed.gas.preVerificationGas
    }),
    /PHILCORE_CONTROLLED_BETA_P2_BUNDLER_ESTIMATE_INVALID/u
  );
  for (const field of ["verificationGasLimit", "callGasLimit", "preVerificationGas"]) {
    const estimate = { ...within, [field]: parsed.gas[field] + 1n };
    assert.throws(
      () => common.assertEstimateWithinSignedCaps(estimate, parsed),
      /PHILCORE_CONTROLLED_BETA_P2_SIGNED_GAS_CAP_INSUFFICIENT/u,
      field
    );
  }
});

test("P2 plan and signed-artifact creation cannot overwrite a concurrent destination", () => {
  const common = require(COMMON);
  const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-p2-create-"));
  const output = path.join(root, "evidence.json");
  try {
    common.atomicCreateJson(output, { attempt: 1 });
    assert.throws(() => common.atomicCreateJson(output, { attempt: 2 }), /EEXIST/u);
    assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")), { attempt: 1 });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("generic project cleanup preserves controlled Sepolia Beta evidence", () => {
  const { cleanBuildOutputs, PRESERVED_ARTIFACT_NAMES } = require(CLEAN);
  const root = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-clean-"));
  const preserved = path.join(root, "artifacts", PRESERVED_ARTIFACT_NAMES[0]);
  const disposable = path.join(root, "artifacts", "contracts");
  const cache = path.join(root, "cache");
  try {
    fs.mkdirSync(preserved, { recursive: true });
    fs.mkdirSync(disposable, { recursive: true });
    fs.mkdirSync(cache, { recursive: true });
    fs.writeFileSync(path.join(preserved, "p2-execution-attempt.lock.json"), "{}\n");
    fs.writeFileSync(path.join(disposable, "build.json"), "{}\n");
    cleanBuildOutputs(root);
    assert.equal(fs.existsSync(preserved), true);
    assert.equal(fs.existsSync(path.join(preserved, "p2-execution-attempt.lock.json")), true);
    assert.equal(fs.existsSync(disposable), false);
    assert.equal(fs.existsSync(cache), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("P2 parser accepts the seven-argument Beta account graph and owner recipient", async () => {
  const fixture = await signedFixture();
  const parsed = fixture.common.parseSignedArtifact(
    fixture.artifact, fixture.config, fixture.compiled
  );
  assert.equal(parsed.executionOwner, fixture.owner.address);
  assert.equal(parsed.recipient, fixture.owner.address);
  assert.equal(parsed.localUserOperationHash, fixture.artifact.userOperationHash);
  assert.equal(parsed.maximumTotalFeeWei, 4_300_000_000_000_000n);
});

test("P2 parser rejects the obsolete Alpha account-as-recipient binding", async () => {
  const fixture = await signedFixture("account");
  assert.throws(
    () => fixture.common.parseSignedArtifact(fixture.artifact, fixture.config, fixture.compiled),
    /PHILCORE_CONTROLLED_BETA_P2_GATE_BINDING_INVALID/u
  );
});

test("P2 configuration retains all public ceilings and keeps mutation disabled", () => {
  const common = require(COMMON);
  const config = common.loadConfiguration();
  assert.equal(config.publicMutationEnabled, false);
  assert.equal(config.submissionEnabled, false);
  assert.equal(config.automaticRetryAllowed, false);
  assert.equal(BigInt(config.maximumTotalFeeWei), ethers.parseEther("0.005"));
  assert.equal(BigInt(config.maximumNativeAccountBalanceWei), ethers.parseEther("0.01"));
  assert.equal(BigInt(config.maximumOperatorExposureWei), ethers.parseEther("0.05"));
  assert.equal(config.phoneAssurance.trustedPhilCoreIOSApplicationRequired, true);
  assert.equal(config.phoneAssurance.p256ProofOfPossessionRequired, true);
  assert.equal(config.phoneAssurance.remoteHardwareAttestationEstablished, false);
  assert.equal(config.phoneAssurance.maliciousAlternateClientResistanceClaimed, false);
});
