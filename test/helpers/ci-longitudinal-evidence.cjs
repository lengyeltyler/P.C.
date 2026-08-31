"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const evidence = require("../../scripts/ci/longitudinal-evidence.cjs");
const repositoryRoot = path.resolve(__dirname, "../..");

function observation() {
  return { test: evidence.TEST, result: "PASS", physicalEquivalence: "MEDIUM",
    requests: 6, executions: 3, desktopReinitializations: 1, signaturesAfterEnrollment: 3, publicMutations: 0,
    transitions: ["comparingFingerprint", "accepted", "comparingFingerprint", "reviewing", "accepted",
      "comparingFingerprint", "reviewing", "denied", "expired", "comparingFingerprint", "cancelled",
      "comparingFingerprint", "reviewing", "accepted", "idle", "comparingFingerprint", "reviewing", "accepted"] };
}

describe("CI longitudinal evidence durability", function () {
  this.timeout(20000);
  let root, git, identity, resultFile, observationFile;
  beforeEach(function () {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-longitudinal-evidence-test-"));
    git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    git("init", "-q");
    git("-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid", "-c", "commit.gpgsign=false",
      "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "fixture");
    identity = evidence.gitIdentity(root, {});
    resultFile = path.join(root, evidence.RESULT_PATH);
    observationFile = path.join(root, evidence.OBSERVATION_PATH);
    fs.mkdirSync(path.dirname(resultFile), { recursive: true });
  });
  afterEach(function () { fs.rmSync(root, { recursive: true, force: true }); });
  const writeObservation = file => fs.writeFileSync(file, JSON.stringify(observation()));

  it("publishes canonical PASS only after the complete successful run resolves", async function () {
    let finish;
    const completed = new Promise(resolve => { finish = resolve; });
    const pending = evidence.runWithDurableResult({ root, env: {}, run: async () => {
      writeObservation(observationFile);
      assert.equal(fs.existsSync(resultFile), false);
      return completed;
    } });
    await Promise.resolve();
    assert.equal(fs.existsSync(resultFile), false);
    finish(0);
    assert.equal(await pending, 0);
    const result = evidence.verifyResultFile(resultFile, identity);
    assert.deepEqual(Object.fromEntries(Object.keys(evidence.EXPECTED_COUNTERS).map(k => [k, result[k]])), evidence.EXPECTED_COUNTERS);
    assert.equal(fs.readFileSync(resultFile, "utf8"), evidence.serialize(result));
  });

  it("preserves nonzero failure and removes even an earlier XCTest PASS observation", async function () {
    const status = await evidence.runWithDurableResult({ root, env: {}, run: async () => {
      writeObservation(observationFile); return 7;
    } });
    assert.equal(status, 7);
    assert.equal(fs.existsSync(resultFile), false);
    assert.equal(fs.existsSync(observationFile), false);
  });

  it("cannot publish PASS when test completion or teardown throws", async function () {
    await assert.rejects(evidence.runWithDurableResult({ root, env: {}, run: async () => {
      writeObservation(observationFile); throw new Error("teardown failed");
    } }), /teardown failed/);
    assert.equal(fs.existsSync(resultFile), false);
    assert.equal(fs.existsSync(observationFile), false);
  });

  it("does not reuse stale durable or raw PASS evidence", async function () {
    writeObservation(observationFile);
    fs.writeFileSync(resultFile, evidence.serialize(evidence.resultFromObservation(observation(), identity)));
    await assert.rejects(evidence.runWithDurableResult({ root, env: {}, run: async () => 0 }), /ENOENT/);
    assert.equal(fs.existsSync(resultFile), false);
  });

  it("fails verification when the required file is missing", function () {
    assert.throws(() => evidence.verifyResultFile(resultFile, identity), /ENOENT/);
  });

  it("rejects wrong source and tested commit or tree identities", function () {
    const valid = evidence.resultFromObservation(observation(), identity);
    for (const key of ["sourceCommit", "sourceTree", "testedCommit", "testedTree"]) {
      fs.writeFileSync(resultFile, evidence.serialize({ ...valid, [key]: "a".repeat(40) }));
      assert.throws(() => evidence.verifyResultFile(resultFile, identity), /IDENTITY_MISMATCH/);
    }
  });

  it("rejects every incorrect counter, including nonzero public-chain mutations", function () {
    const valid = evidence.resultFromObservation(observation(), identity);
    for (const key of Object.keys(evidence.EXPECTED_COUNTERS)) {
      for (const value of [valid[key] + 1, String(valid[key]), true, null, -1]) {
        assert.throws(() => evidence.validateResult({ ...valid, [key]: value }, identity), /COUNTER_MISMATCH/);
      }
    }
  });

  it("rejects malformed, duplicate-key, empty, oversized and symlink result files", function () {
    const valid = evidence.serialize(evidence.resultFromObservation(observation(), identity));
    for (const value of ["", "{", "{}", "x".repeat(evidence.MAX_RESULT_BYTES + 1), valid.replace('{', '{"result":"FAIL",')]) {
      fs.writeFileSync(resultFile, value);
      assert.throws(() => evidence.verifyResultFile(resultFile, identity));
    }
    fs.writeFileSync(observationFile, valid); fs.unlinkSync(resultFile); fs.symlinkSync(observationFile, resultFile);
    assert.throws(() => evidence.verifyResultFile(resultFile, identity), /FILE_INVALID/);
  });

  it("requires exact schema version, test name and PASS verdict", function () {
    const valid = evidence.resultFromObservation(observation(), identity);
    for (const patch of [{ schemaVersion: 2 }, { test: "other" }, { result: "FAIL" }]) {
      assert.throws(() => evidence.validateResult({ ...valid, ...patch }, identity), /RESULT_INVALID/);
    }
  });

  it("copies only the bounded public counter schema and rejects secret-bearing fields", function () {
    const valid = evidence.resultFromObservation(observation(), identity);
    assert.deepEqual(Object.keys(valid), ["schemaVersion", "test", "result", "sourceCommit", "sourceTree", "testedCommit", "testedTree",
      "requests", "approvals", "rejections", "expiries", "cancellations", "executions", "publicChainMutations"]);
    for (const key of ["privateKey", "deviceId", "credential", "qrPayload", "signature", "publicKeyFingerprint"]) {
      assert.throws(() => evidence.validateResult({ ...valid, [key]: "excluded" }, identity), /SCHEMA_INVALID/);
      assert.throws(() => evidence.resultFromObservation({ ...observation(), [key]: "excluded" }, identity), /SCHEMA_INVALID/);
    }
  });

  it("requires the observed rejection, expiry, cancellation and approval counts", async function () {
    for (const phase of ["denied", "expired", "cancelled", "accepted"]) {
      const raw = observation(); raw.transitions.splice(raw.transitions.indexOf(phase), 1);
      await assert.rejects(evidence.runWithDurableResult({ root, env: {}, run: async () => {
        fs.writeFileSync(observationFile, JSON.stringify(raw)); return 0;
      } }), /MISMATCH/);
      assert.equal(fs.existsSync(resultFile), false);
    }
  });

  it("binds a synthetic merge to its exact PR head and equal tree", function () {
    const base = identity.sourceCommit;
    git("-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid", "-c", "commit.gpgsign=false",
      "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "head");
    const head = git("rev-parse", "HEAD");
    const merge = git("-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid", "-c", "commit.gpgsign=false",
      "commit-tree", "HEAD^{tree}", "-p", base, "-p", head, "-m", "merge");
    git("update-ref", "HEAD", merge);
    const bound = evidence.gitIdentity(root, { GITHUB_ACTIONS: "true", GITHUB_SHA: merge, PHIL_LONGITUDINAL_SOURCE_COMMIT: head });
    assert.equal(bound.sourceCommit, head); assert.equal(bound.testedCommit, merge);
    assert.equal(bound.sourceTree, bound.testedTree);
    assert.throws(() => evidence.gitIdentity(root, { GITHUB_ACTIONS: "true" }), /EXPECTED_HEAD_MISSING/);
    assert.throws(() => evidence.gitIdentity(root, { GITHUB_ACTIONS: "true", GITHUB_SHA: head, PHIL_LONGITUDINAL_SOURCE_COMMIT: head }), /CHECKOUT_MISMATCH/);
    assert.throws(() => evidence.gitIdentity(root, { PHIL_LONGITUDINAL_SOURCE_COMMIT: base }), /PARENT_MISMATCH/);
  });

  it("rejects changes to the tested Git identity during execution", async function () {
    await assert.rejects(evidence.runWithDurableResult({ root, env: {}, run: async () => {
      writeObservation(observationFile);
      git("-c", "user.name=CI fixture", "-c", "user.email=ci@example.invalid", "-c", "commit.gpgsign=false",
        "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "changed");
      return 0;
    } }), /SOURCE_CHANGED/);
    assert.equal(fs.existsSync(resultFile), false);
  });

  for (const exitCode of [0, 7]) {
    it(`drains large piped lane output and preserves exit status ${exitCode}`, function () {
      // Only child command results are synthetic. The actual CI entry point,
      // output handling and shutdown path execute in an isolated Node process.
      const preload = path.join(root, "preload.cjs");
      fs.writeFileSync(preload, `
        const root=${JSON.stringify(repositoryRoot)};
        require(root+'/scripts/ci/discovery.cjs').loadClassification=()=>({items:[
          {id:'unit:synthetic.test.cjs',kind:'unit_test',lane:'required_product_runtime'},
          {id:'script:synthetic-simulator',kind:'package_script',lane:'required_product_runtime',execution:{mode:'executed_directly'}}]});
        require(root+'/scripts/ci/command-runner.cjs').runArgv=argv=>({
          status:argv.includes('compile')?0:argv.includes('hardhat')?${exitCode}:0,
          stdout:argv.includes('compile')?'':argv.includes('hardhat')?'X'.repeat(2*1024*1024)+'\\nUNIT_OUTPUT_END\\n':'LONGITUDINAL MULTI-REQUEST TEST: PASS\\n',stderr:''});
      `);
      const result = spawnSync(process.execPath, ["--require", preload, path.join(repositoryRoot, "scripts/ci/run-lane.cjs"), "required_product_runtime"],
        { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
      assert.equal(result.status, exitCode, result.stderr);
      assert.ok(result.stdout.includes("X".repeat(2 * 1024 * 1024) + "\nUNIT_OUTPUT_END\n"));
      assert.equal(result.stdout.includes("LONGITUDINAL MULTI-REQUEST TEST: PASS"), exitCode === 0);
    });
  }
});
