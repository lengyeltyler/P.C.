"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "../..");
const PLAN = path.join(ROOT, "scripts/ethereum-sepolia/prepare-phil-sepolia-mint-public-plan.cjs");
const EXECUTE = path.join(ROOT, "scripts/ethereum-sepolia/execute-phil-sepolia-mint-public-plan.cjs");
const COMMON = path.join(ROOT, "scripts/ethereum-sepolia/phil-sepolia-mint-public-common.cjs");

function run(script, args = [], env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env }
  });
}

test("legacy Alpha planner is retired before it can read artifacts or contact a network", () => {
  const source = fs.readFileSync(PLAN, "utf8");
  for (const forbidden of ["eth_sendRawTransaction", "eth_sendUserOperation", ".broadcastTransaction(", ".sendTransaction("]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  const result = run(PLAN);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u);
});

test("legacy Alpha common path and read-only preflight are retired fail closed", () => {
  const common = require(COMMON);
  assert.throws(
    () => common.assertLegacyAlphaRunnerRetired(),
    /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u
  );
  const preflight = run(path.join(ROOT, "scripts/ethereum-sepolia/prepare-phil-sepolia-mint-demo.cjs"));
  assert.equal(preflight.status, 1);
  assert.match(preflight.stderr, /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u);
});

test("approved plan endpoint digests reject independent RPC and bundler drift", () => {
  const common = require(COMMON);
  const rpc = "https://rpc.example.invalid/credential-one";
  const bundler = "https://bundler.example.invalid/credential-two";
  const bindings = {
    rpcUrlSha256: common.endpointDigest(rpc),
    bundlerUrlSha256: common.endpointDigest(bundler)
  };
  assert.deepEqual(common.assertEndpointBindings(bindings, rpc, bundler), bindings);
  assert.throws(
    () => common.assertEndpointBindings(bindings, `${rpc}-drift`, bundler),
    /PHIL_SEPOLIA_MINT_ENDPOINT_BINDING_MISMATCH/u
  );
  assert.throws(
    () => common.assertEndpointBindings(bindings, rpc, `${bundler}-drift`),
    /PHIL_SEPOLIA_MINT_ENDPOINT_BINDING_MISMATCH/u
  );
});

test("legacy Alpha executor is retired before approval, plan, secret, or network handling", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-mint-guard-"));
  const signed = path.join(directory, "signed.json");
  fs.writeFileSync(signed, "{}\n", { mode: 0o600 });
  const args = ["--signed-artifact", signed, "--plan-digest", `0x${"00".repeat(32)}`];
  const absent = run(EXECUTE, args);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u);
  const wrong = run(EXECUTE, args, {
    PHILCORE_SEPOLIA_MINT_PUBLIC_MUTATION_APPROVAL: "approve"
  });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES/u);
});

test("executor has one submission call, no retry loop around mutation calls, and persists ambiguous-stop evidence", () => {
  const source = fs.readFileSync(EXECUTE, "utf8");
  assert.match(source, /common\.assertLegacyAlphaRunnerRetired\(\)/u);
  assert.equal((source.match(/eth_sendUserOperation/gu) || []).length, 1);
  assert.equal((source.match(/broadcastTransaction/gu) || []).length, 2);
  assert.match(source, /automaticRetryOccurred: false/u);
  assert.match(source, /STOPPED_REQUIRES_READ_ONLY_RECONCILIATION/u);
  assert.match(source, /No public mutation is reachable above this line/u);
  assert.match(source, /assertEndpointBindings\(plan\.endpointBindings, rpcUrl, bundlerUrl\)/u);
  assert.match(source, /assertExactPlanBindings\(plan, config, parsed\)/u);
  assert.match(source, /PHIL_SEPOLIA_MINT_DEPLOYMENT_SEQUENCE_INVALID/u);
  assert.match(source, /PHIL_SEPOLIA_MINT_MUTATION_SEQUENCE_INVALID/u);
  assert.match(source, /PHIL_SEPOLIA_MINT_MAXIMUM_PUBLIC_COST_INVALID/u);
  assert.match(source, /PHIL_SEPOLIA_MINT_FUNDING_GAS_LIMIT_STALE/u);
});
