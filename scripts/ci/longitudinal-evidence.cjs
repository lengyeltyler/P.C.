"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const RESULT_PATH = ".local/release-validation/longitudinal-release-gate.json";
const OBSERVATION_PATH = ".local/release-validation/longitudinal-result.json";
const TEST = "routine_authorization_longitudinal_acceptance";
const MAX_RESULT_BYTES = 2048;
const EXPECTED_COUNTERS = Object.freeze({
  requests: 6, approvals: 3, rejections: 1, expiries: 1,
  cancellations: 1, executions: 3, publicChainMutations: 0
});
const IDENTITY_KEYS = ["sourceCommit", "sourceTree", "testedCommit", "testedTree"];
const RESULT_KEYS = ["schemaVersion", "test", "result", ...IDENTITY_KEYS, ...Object.keys(EXPECTED_COUNTERS)];

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join("\n") !== [...keys].sort().join("\n")) {
    throw new Error("LONGITUDINAL_EVIDENCE_SCHEMA_INVALID");
  }
}

function validateIdentity(identity) {
  exactKeys(identity, IDENTITY_KEYS);
  for (const key of IDENTITY_KEYS) {
    if (typeof identity[key] !== "string" || !/^[0-9a-f]{40}$/.test(identity[key])) {
      throw new Error("LONGITUDINAL_EVIDENCE_IDENTITY_INVALID");
    }
  }
  if (identity.sourceTree !== identity.testedTree) throw new Error("LONGITUDINAL_EVIDENCE_TREE_MISMATCH");
}

function gitIdentity(root, env = process.env) {
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const testedCommit = git("rev-parse", "HEAD");
  if (env.GITHUB_ACTIONS === "true" && !env.PHIL_LONGITUDINAL_SOURCE_COMMIT) {
    throw new Error("LONGITUDINAL_EVIDENCE_EXPECTED_HEAD_MISSING");
  }
  if (env.GITHUB_ACTIONS === "true" && env.GITHUB_SHA !== testedCommit) {
    throw new Error("LONGITUDINAL_EVIDENCE_CHECKOUT_MISMATCH");
  }
  const sourceCommit = env.PHIL_LONGITUDINAL_SOURCE_COMMIT || testedCommit;
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) throw new Error("LONGITUDINAL_EVIDENCE_IDENTITY_INVALID");
  const identity = { sourceCommit, sourceTree: git("rev-parse", `${sourceCommit}^{tree}`),
    testedCommit, testedTree: git("rev-parse", "HEAD^{tree}") };
  validateIdentity(identity);
  if (sourceCommit !== testedCommit) {
    // Read raw parents: this remains correct at a shallow checkout boundary.
    const header = git("cat-file", "-p", "HEAD").split("\n\n")[0];
    const parents = header.split("\n").filter(line => line.startsWith("parent ")).map(line => line.slice(7));
    if (parents.length !== 2 || parents[1] !== sourceCommit) throw new Error("LONGITUDINAL_EVIDENCE_PARENT_MISMATCH");
  }
  git("diff", "--exit-code", "HEAD", "--");
  return identity;
}

function readBoundedJson(file, maximumBytes) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.size === 0 || stat.size > maximumBytes) throw new Error("LONGITUDINAL_EVIDENCE_FILE_INVALID");
  const text = fs.readFileSync(file, "utf8");
  if (Buffer.byteLength(text) > maximumBytes) throw new Error("LONGITUDINAL_EVIDENCE_FILE_INVALID");
  return { text, value: JSON.parse(text) };
}

function resultFromObservation(observation, identity) {
  exactKeys(observation, ["test", "result", "physicalEquivalence", "transitions", "executions", "requests",
    "desktopReinitializations", "signaturesAfterEnrollment", "publicMutations"]);
  if (observation.test !== TEST || observation.result !== "PASS" || observation.physicalEquivalence !== "MEDIUM"
    || observation.desktopReinitializations !== 1 || !Array.isArray(observation.transitions)
    || observation.transitions.length > 64
    || observation.transitions.some(phase => !["comparingFingerprint", "accepted", "reviewing", "denied", "expired", "cancelled", "idle"].includes(phase))) {
    throw new Error("LONGITUDINAL_EVIDENCE_OBSERVATION_INVALID");
  }
  const count = phase => observation.transitions.filter(value => value === phase).length;
  // One accepted transition belongs to enrollment, not a routine approval.
  if (count("accepted") !== observation.signaturesAfterEnrollment + 1) throw new Error("LONGITUDINAL_EVIDENCE_APPROVAL_MISMATCH");
  const result = { schemaVersion: 1, test: TEST, result: "PASS", ...identity,
    requests: observation.requests, approvals: observation.signaturesAfterEnrollment,
    rejections: count("denied"), expiries: count("expired"), cancellations: count("cancelled"),
    executions: observation.executions, publicChainMutations: observation.publicMutations };
  validateResult(result, identity);
  return result;
}

function validateResult(result, identity) {
  validateIdentity(identity);
  exactKeys(result, RESULT_KEYS);
  if (result.schemaVersion !== 1 || result.test !== TEST || result.result !== "PASS") throw new Error("LONGITUDINAL_EVIDENCE_RESULT_INVALID");
  for (const key of IDENTITY_KEYS) {
    if (result[key] !== identity[key]) throw new Error(`LONGITUDINAL_EVIDENCE_IDENTITY_MISMATCH:${key}`);
  }
  for (const [key, expected] of Object.entries(EXPECTED_COUNTERS)) {
    if (!Number.isSafeInteger(result[key]) || result[key] !== expected) throw new Error(`LONGITUDINAL_EVIDENCE_COUNTER_MISMATCH:${key}`);
  }
  return result;
}

function serialize(result) {
  return `${JSON.stringify(Object.fromEntries(RESULT_KEYS.map(key => [key, result[key]])), null, 2)}\n`;
}

function verifyResultFile(file, identity) {
  const { text, value } = readBoundedJson(file, MAX_RESULT_BYTES);
  validateResult(value, identity);
  // Canonical bytes also reject duplicate keys, BOMs and alternative encodings.
  if (text !== serialize(value)) throw new Error("LONGITUDINAL_EVIDENCE_ENCODING_INVALID");
  return value;
}

async function runWithDurableResult({ root, run, env = process.env }) {
  const destination = path.join(root, RESULT_PATH);
  const observationPath = path.join(root, OBSERVATION_PATH);
  fs.rmSync(destination, { force: true });
  fs.rmSync(observationPath, { force: true });
  const identity = gitIdentity(root, env);
  let temporary;
  try {
    // Includes XCTest, fixture exclusion and child teardown. No durable PASS
    // exists while the test is running, even if XCTest wrote its observation.
    const status = await run();
    if (status !== 0) {
      fs.rmSync(observationPath, { force: true });
      return Number.isInteger(status) && status > 0 ? status : 1;
    }
    const after = gitIdentity(root, env);
    if (JSON.stringify(after) !== JSON.stringify(identity)) throw new Error("LONGITUDINAL_EVIDENCE_SOURCE_CHANGED");
    const result = resultFromObservation(readBoundedJson(observationPath, 8192).value, identity);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    temporary = `${destination}.tmp-${process.pid}`;
    const fd = fs.openSync(temporary, "wx", 0o600);
    try { fs.writeFileSync(fd, serialize(result)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, destination);
    verifyResultFile(destination, identity);
    return 0;
  } catch (error) {
    fs.rmSync(destination, { force: true });
    fs.rmSync(observationPath, { force: true });
    throw error;
  } finally {
    if (temporary) fs.rmSync(temporary, { force: true });
  }
}

if (require.main === module) {
  try {
    if (process.argv.length > 3) throw new Error("Usage: node scripts/ci/longitudinal-evidence.cjs [result-file]");
    const root = path.resolve(__dirname, "../..");
    verifyResultFile(process.argv[2] || path.join(root, RESULT_PATH), gitIdentity(root));
    console.log("LONGITUDINAL DURABLE RESULT VERIFIED: PASS");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { RESULT_PATH, OBSERVATION_PATH, TEST, EXPECTED_COUNTERS, MAX_RESULT_BYTES,
  gitIdentity, resultFromObservation, validateResult, verifyResultFile, serialize, runWithDurableResult };
