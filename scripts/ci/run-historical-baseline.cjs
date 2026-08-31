"use strict";

const { ROOT, loadClassification, loadHistoricalManifest } = require("./discovery.cjs");
const { validateHistoricalManifestPolicy } = require("./validate-classification.cjs");
const { runArgv, argvForItem } = require("./command-runner.cjs");
const {
  normalizeFailureText,
  sha256,
  normalizedStreamDigests,
  parseMochaFailures,
  parseMochaCounts,
  extractStructuredErrorCode,
  detectCrashOrUnrelatedFailure,
  exitCategory,
  failuresEqualExact
} = require("./normalize-failures.cjs");

function matchMochaEntry(result, entry) {
  const reasons = [];
  const category = exitCategory(result.status, result.signal);
  if (result.signal) {
    reasons.push(`unexpected signal ${result.signal}`);
  }
  if (category !== entry.expectedExitCategory) {
    reasons.push(
      `exit category ${category} !== expected ${entry.expectedExitCategory}`
    );
  }
  if (result.status !== entry.expectedExitCode) {
    reasons.push(`exit code ${result.status} !== expected ${entry.expectedExitCode}`);
  }

  const crash = detectCrashOrUnrelatedFailure(result.combined, null);
  if (crash) reasons.push(crash);

  const counts = parseMochaCounts(result.combined);
  if (counts.passing !== entry.passing) {
    reasons.push(`passing ${counts.passing} !== expected ${entry.passing}`);
  }
  if (counts.failing !== entry.failing) {
    reasons.push(`failing ${counts.failing} !== expected ${entry.failing}`);
  }

  const observed = parseMochaFailures(result.combined, [ROOT]).map((f) => ({
    identity: f.identity,
    bodySha256: f.bodySha256
  }));
  if (!failuresEqualExact(observed, entry.failures || [])) {
    reasons.push("mocha failure identities/body hashes mismatch");
    reasons.push(`observed=${JSON.stringify(observed)}`);
    reasons.push(`expected=${JSON.stringify(entry.failures || [])}`);
  }

  // Bind the entire normalized command output so unrelated lines outside the
  // parsed Mocha failure blocks (including stderr) cannot be ignored.
  const digests = normalizedStreamDigests(result, [ROOT]);
  if (digests.normalizedOutputSha256 !== entry.normalizedOutputSha256) {
    reasons.push(
      `normalizedOutputSha256 ${digests.normalizedOutputSha256} !== expected ${entry.normalizedOutputSha256}`
    );
  }
  if (digests.normalizedStdoutSha256 !== entry.normalizedStdoutSha256) {
    reasons.push(
      `normalizedStdoutSha256 ${digests.normalizedStdoutSha256} !== expected ${entry.normalizedStdoutSha256}`
    );
  }
  if (digests.normalizedStderrSha256 !== entry.normalizedStderrSha256) {
    reasons.push(
      `normalizedStderrSha256 ${digests.normalizedStderrSha256} !== expected ${entry.normalizedStderrSha256}`
    );
  }

  return { ok: reasons.length === 0, reasons, observed, digests };
}

function matchStructuredEntry(result, entry) {
  const reasons = [];
  const category = exitCategory(result.status, result.signal);
  if (result.signal) {
    reasons.push(`unexpected signal ${result.signal}`);
  }
  if (category !== entry.expectedExitCategory) {
    reasons.push(
      `exit category ${category} !== expected ${entry.expectedExitCategory}`
    );
  }
  if (result.status !== entry.expectedExitCode) {
    reasons.push(`exit code ${result.status} !== expected ${entry.expectedExitCode}`);
  }

  const crash = detectCrashOrUnrelatedFailure(result.combined, entry.errorCode);
  if (crash) reasons.push(crash);

  const code = extractStructuredErrorCode(result.combined);
  if (code !== entry.errorCode) {
    reasons.push(`errorCode ${code} !== expected ${entry.errorCode}`);
  }

  const digest = sha256(normalizeFailureText(result.combined, [ROOT]));
  if (digest !== entry.normalizedOutputSha256) {
    reasons.push(
      `normalizedOutputSha256 ${digest} !== expected ${entry.normalizedOutputSha256}`
    );
  }

  return { ok: reasons.length === 0, reasons, code, digest };
}

/**
 * Exact historical matcher used by the runner and unit tests.
 */
function matchHistoricalResult(result, entry) {
  if (!entry || !entry.matcher) {
    return { ok: false, reasons: ["missing matcher"] };
  }
  if (entry.matcher === "mocha_hardhat" || entry.matcher === "alias") {
    return matchMochaEntry(result, entry);
  }
  if (entry.matcher === "structured_error") {
    return matchStructuredEntry(result, entry);
  }
  return { ok: false, reasons: [`unknown matcher ${entry.matcher}`] };
}

function resolveExecItem(entry, byId) {
  if (entry.matcher === "alias" && entry.aliasOf) {
    const target = byId.get(entry.aliasOf);
    if (!target) throw new Error(`alias target missing for ${entry.id}: ${entry.aliasOf}`);
    return target;
  }
  const item = byId.get(entry.id);
  if (!item) throw new Error(`classification missing for historical entry ${entry.id}`);
  return item;
}

function main() {
  const manifest = loadHistoricalManifest();
  const policyErrors = validateHistoricalManifestPolicy(manifest);
  if (policyErrors.length > 0) {
    for (const error of policyErrors) console.error(error);
    process.exit(1);
  }
  const classification = loadClassification();
  const byId = new Map(classification.items.map((item) => [item.id, item]));

  const historicalIds = new Set(
    classification.items
      .filter((item) => item.lane === "historical_known_baseline")
      .map((item) => item.id)
  );
  const manifestIds = new Set((manifest.entries || []).map((e) => e.id));
  for (const id of historicalIds) {
    if (!manifestIds.has(id)) {
      console.error(`historical classification missing manifest entry: ${id}`);
      process.exit(1);
    }
  }
  for (const id of manifestIds) {
    if (!historicalIds.has(id)) {
      console.error(`historical manifest has extra entry: ${id}`);
      process.exit(1);
    }
  }

  let failures = 0;
  let executed = 0;

  for (const entry of manifest.entries) {
    const item = resolveExecItem(entry, byId);
    console.log(`Historical baseline check: ${entry.id}`);
    const argv = argvForItem(item);
    console.log(`$ ${argv.join(" ")}`);
    const result = runArgv(argv);
    executed += 1;

    if (result.status === 0) {
      console.error(
        `Expected non-zero exit for historical entry ${entry.id}, but command succeeded. ` +
          "Do not silently green historical/stale evidence."
      );
      failures += 1;
      continue;
    }

    const match = matchHistoricalResult(result, entry);
    if (!match.ok) {
      console.error(`Historical identity mismatch for ${entry.id}`);
      for (const reason of match.reasons) console.error(` - ${reason}`);
      console.error("Observed tail:");
      console.error(result.combined.split("\n").slice(-30).join("\n"));
      failures += 1;
      continue;
    }

    console.log(`OK: ${entry.id} matched approved exact historical identity`);
  }

  if (failures > 0) {
    console.error(`Historical baseline lane failed (${failures} mismatches); executed=${executed}`);
    process.exit(1);
  }
  console.log(
    `Historical baseline lane matched approved failure identities (executed=${executed}, manifest=${manifest.entries.length})`
  );
}

if (require.main === module) {
  main();
}

module.exports = {
  matchHistoricalResult,
  matchMochaEntry,
  matchStructuredEntry
};
