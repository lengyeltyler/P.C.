"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "../..");
const COMMON = path.join(ROOT, "scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p1-common.cjs");
const PLAN = path.join(ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p1.cjs");
const EXECUTE = path.join(ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p1.cjs");
const RECOVERY_PLAN = path.join(ROOT, "scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p1-recovery.cjs");
const RECOVERY_EXECUTE = path.join(ROOT, "scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p1-recovery.cjs");

function run(script, args = [], env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env }
  });
}

test("P1 planner contains no public mutation method", () => {
  const source = fs.readFileSync(PLAN, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "eth_sendUserOperation",
    ".broadcastTransaction(",
    ".sendTransaction("
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  assert.match(source, /publicMutationOccurred: false/u);
  assert.match(source, /common\.signedP1Transactions/u);
});

test("P1 planner requires an accepted exact-source runner review before endpoint or Keychain access", () => {
  const result = run(PLAN);
  assert.equal(result.status, 1);
  assert.match(
    result.stderr,
    /PHILCORE_CONTROLLED_BETA_(SOURCE_NOT_FROZEN|P1_RUNNER_REVIEW_COMMIT_REQUIRED)/u
  );
  assert.doesNotMatch(result.stderr, /RPC|NETWORK|KEYCHAIN/u);
  const source = fs.readFileSync(PLAN, "utf8");
  assert.ok(source.indexOf("common.sourceIdentity()") < source.indexOf("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL"));
  assert.ok(source.indexOf("PHILCORE_CONTROLLED_BETA_P1_RUNNER_REVIEW_COMMIT") < source.indexOf("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL"));
});

test("P1 executor rejects absent and wrong approval before plan, endpoint, network, or Keychain access", () => {
  const digest = `0x${"12".repeat(32)}`;
  const args = ["--plan-digest", digest, "--plan", "/definitely/not/a/plan.json"];
  const absent = run(EXECUTE, args);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /PHILCORE_CONTROLLED_BETA_P1_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(absent.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);

  const wrong = run(EXECUTE, args, { PHILCORE_CONTROLLED_BETA_P1_APPROVAL: "approve" });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /PHILCORE_CONTROLLED_BETA_P1_EXACT_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(wrong.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);
});

test("P1 approval is exact and bound to a canonical digest", () => {
  const common = require(COMMON);
  const body = { stage: "P1", mutations: [{ order: 1, valueWei: "1" }] };
  const digest = common.canonicalSha256(body);
  assert.match(common.approvalPhrase("P1", digest), /^I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P1_[0-9A-F]{64}$/u);
  assert.notEqual(
    digest,
    common.canonicalSha256({ stage: "P1", mutations: [{ order: 1, valueWei: "2" }] })
  );
  assert.throws(() => common.approvalPhrase("P2", "0x00"), /APPROVAL_INPUT_INVALID/u);
});

test("P1 records one unambiguous compiler build identity", () => {
  const common = require(COMMON);
  const compiler = common.compilerIdentity();
  assert.match(compiler.solcVersion, /^0\.8\./u);
  assert.match(compiler.solcLongVersion, /^0\.8\./u);
  assert.match(compiler.compilerSettingsSha256, /^0x[0-9a-f]{64}$/u);
  assert.match(compiler.buildInfoSha256, /^0x[0-9a-f]{64}$/u);
});

test("P1 freezes exactly four mutations and the corrected four-argument gate binding", () => {
  const commonSource = fs.readFileSync(COMMON, "utf8");
  const plannerSource = fs.readFileSync(PLAN, "utf8");
  assert.match(commonSource, /const P1_MUTATION_COUNT = 4/u);
  assert.match(
    commonSource,
    /args: \[CHAIN_ID, graph\.factory, graph\.consumer, graph\.account\]/u
  );
  for (const label of [
    "FUND_BETA_DEPLOYER_FROM_LEGACY_ALPHA_SOURCE",
    "DEPLOY_PhilSepoliaMintPassConsumerV1",
    "DEPLOY_PhilSepoliaLocalComposedActionGateV1",
    "DEPLOY_PhilCore4337AccountFactory"
  ]) {
    assert.match(`${plannerSource}\n${fs.readFileSync(EXECUTE, "utf8")}`, new RegExp(label, "u"));
  }
  assert.match(plannerSource, /maximumExposureWei = ethers\.parseEther\("0\.05"\)/u);
});

test("P1 executor has one one-shot broadcast site, no user-operation submission, and ambiguous-stop evidence", () => {
  const source = fs.readFileSync(EXECUTE, "utf8");
  assert.equal((source.match(/\.broadcastTransaction\(/gu) || []).length, 1);
  assert.equal((source.match(/eth_sendUserOperation/gu) || []).length, 0);
  assert.match(source, /No public mutation is reachable above this line/u);
  assert.match(source, /automaticRetryOccurred: false/u);
  assert.match(source, /STOPPED_REQUIRES_READ_ONLY_RECONCILIATION/u);
  assert.match(source, /constructorBindingsVerifiedByBothProviders/u);
  assert.ok(source.indexOf("PHILCORE_CONTROLLED_BETA_P1_APPROVAL") < source.indexOf("common.readJson(planPath)"));
  assert.ok(source.indexOf("common.readJson(planPath)") < source.indexOf("walletFromKeychain"));
});

test("P1 executors call the factory prediction function by its full Solidity signature", () => {
  for (const script of [EXECUTE, RECOVERY_EXECUTE]) {
    const source = fs.readFileSync(script, "utf8");
    assert.match(source, /factory\["getAddress\(address,bytes32,uint256\)"\]\(/u);
    assert.doesNotMatch(source, /factory\.getAddress\(/u);
  }
});

test("legacy Alpha public-mutation runner remains structurally retired", () => {
  const legacy = path.join(ROOT, "scripts/ethereum-sepolia/phil-sepolia-mint-public-common.cjs");
  const common = require(legacy);
  assert.throws(
    () => common.assertLegacyAlphaRunnerRetired(),
    /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u
  );
});

test("P1 recovery planner is read-only and requires an exact-source review first", () => {
  const source = fs.readFileSync(RECOVERY_PLAN, "utf8");
  for (const forbidden of [
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "eth_sendUserOperation",
    ".broadcastTransaction(",
    ".sendTransaction("
  ]) assert.equal(source.includes(forbidden), false, forbidden);
  const result = run(RECOVERY_PLAN);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHILCORE_CONTROLLED_BETA_(SOURCE_NOT_FROZEN|P1_RECOVERY_RUNNER_REVIEW_COMMIT_REQUIRED)/u);
  assert.ok(source.indexOf("common.sourceIdentity()") < source.indexOf("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL"));
});

test("P1 recovery approval is exact and rejected before plan, endpoint, or Keychain access", () => {
  const common = require(COMMON);
  const digest = common.canonicalSha256({ stageId: "P1R", prior: "funding-confirmed", mutations: 3 });
  assert.match(common.approvalPhrase("P1R", digest), /^I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P1R_[0-9A-F]{64}$/u);
  const args = ["--plan-digest", digest, "--plan", "/definitely/not/a/recovery-plan.json"];
  const absent = run(RECOVERY_EXECUTE, args);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /PHILCORE_CONTROLLED_BETA_P1_RECOVERY_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(absent.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);
  const wrong = run(RECOVERY_EXECUTE, args, { PHILCORE_CONTROLLED_BETA_P1_RECOVERY_APPROVAL: "approve" });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /PHILCORE_CONTROLLED_BETA_P1_RECOVERY_EXACT_APPROVAL_REQUIRED/u);
  assert.doesNotMatch(wrong.stderr, /ENOENT|KEYCHAIN|RPC|NETWORK/u);
});

test("P1 recovery freezes exactly three deployments with no funding or automatic retry", () => {
  const planner = fs.readFileSync(RECOVERY_PLAN, "utf8");
  const executor = fs.readFileSync(RECOVERY_EXECUTE, "utf8");
  assert.match(planner, /publicMutationCount: common\.P1_RECOVERY_MUTATION_COUNT/u);
  assert.match(planner, /rejectedDeploymentTransactionHash/u);
  assert.match(planner, /PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT/u);
  assert.equal((executor.match(/\.broadcastTransaction\(/gu) || []).length, 1);
  assert.equal((executor.match(/eth_sendUserOperation/gu) || []).length, 0);
  assert.doesNotMatch(executor, /FUND_BETA_DEPLOYER_FROM_LEGACY_ALPHA_SOURCE/u);
  assert.match(executor, /retries are forbidden/u);
  assert.match(executor, /automaticRetryOccurred: false/u);
  assert.match(executor, /STOPPED_REQUIRES_READ_ONLY_RECONCILIATION/u);
  assert.ok(executor.indexOf("PHILCORE_CONTROLLED_BETA_P1_RECOVERY_APPROVAL") < executor.indexOf("common.readJson(planPath)"));
  assert.ok(executor.indexOf("common.readJson(planPath)") < executor.indexOf("walletFromKeychain"));
});
