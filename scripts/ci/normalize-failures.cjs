"use strict";

const crypto = require("node:crypto");

/**
 * Terminal Mocha Spec reporter duration on a single line.
 * Matches either already-normalized "(<ms>)" or raw "(123ms)" / "(1s)" / "(1.5s)".
 */
const MOCHA_REPORTER_DURATION_SUFFIX =
  / (\(\d+(?:\.\d+)?(?:ms|s)\)|\(<ms>\))$/;

/**
 * Mocha Spec successful-test lines: indentation + success glyph + title.
 * Glyphs cover Unicode and fallback log-symbols forms (✔ / ✓ / √).
 */
const MOCHA_SUCCESS_TEST_LINE = /^(\s+)([✔✓√])(\s+)(.*)$/;

/**
 * Mocha Spec passing-count summary line (not failing/pending).
 */
const MOCHA_PASSING_SUMMARY_LINE = /^(\s*)(\d+ passing\b)(.*)$/;

/**
 * Strip terminal reporter durations from Mocha success-test and "N passing"
 * summary lines only. Leaves failure bodies, failing/pending summaries, and
 * arbitrary parenthetical text (including durations embedded in titles) intact.
 */
function canonicalizeMochaReporterDurations(text) {
  return String(text)
    .split("\n")
    .map((line) => {
      if (MOCHA_SUCCESS_TEST_LINE.test(line)) {
        return line.replace(MOCHA_REPORTER_DURATION_SUFFIX, "");
      }
      if (MOCHA_PASSING_SUMMARY_LINE.test(line)) {
        return line.replace(MOCHA_REPORTER_DURATION_SUFFIX, "");
      }
      return line;
    })
    .join("\n");
}

/**
 * Normalize mocha/hardhat/script failure text for stable comparison.
 * Strips absolute paths and nondeterministic timing / ephemeral addresses.
 * Mocha Spec success-test and "N passing" reporter durations are removed so
 * medium/slow timing presence (and ms vs s units) cannot drift across hosts.
 */
function normalizeFailureText(text, roots = []) {
  let value = String(text);
  for (const root of roots) {
    if (!root) continue;
    const escaped = root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    value = value.replace(new RegExp(escaped, "g"), "<ABS_PATH>");
  }
  value = value.replace(/\/private\/tmp\/[^\s)'"]+/g, "<TMP>");
  value = value.replace(/\/var\/folders\/[^\s)'"]+/g, "<TMP>");
  value = value.replace(/\/tmp\/[^\s)'"]+/g, "<TMP>");
  value = value.replace(/\/Users\/[^/\s]+\/[^\s)'"]+/g, "<ABS_PATH>");
  value = value.replace(/\/home\/[^/\s]+\/[^\s)'"]+/g, "<ABS_PATH>");
  // Node's internal loader line numbers and version footer can change between
  // patch releases without changing the application failure. Public CI pins
  // Node exactly, but normalizing this runtime-only noise also keeps approved
  // historical identities portable across checkout/bootstrap environments.
  value = value.replace(
    /node:internal\/([^\s)]+):\d+:\d+/g,
    "node:internal/$1:<line>:<column>"
  );
  value = value.replace(
    /^Node\.js v\d+\.\d+\.\d+(?:-[^\s]+)?$/gm,
    "Node.js <version>"
  );
  value = value.replace(/\(\d+ms\)/g, "(<ms>)");
  value = value.replace(/\b\d+ms\b/g, "<ms>");
  value = value.replace(/0x[0-9a-fA-F]{40}/g, "<ADDR>");
  value = value.replace(/(^|[\s"'`(])(\/(?:[^/\s)'"`]+\/)+[^/\s)'"`]+)/g, "$1<ABS_PATH>");
  value = canonicalizeMochaReporterDurations(value);
  return value;
}

function sha256(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

/**
 * Exact digests of fully normalized command streams.
 * Used so Mocha historical matching cannot ignore unrelated stdout/stderr
 * outside parsed failure blocks.
 */
function normalizedStreamDigests(result, roots = []) {
  const stdout = result && result.stdout != null ? String(result.stdout) : "";
  const stderr = result && result.stderr != null ? String(result.stderr) : "";
  const combined =
    result && result.combined != null
      ? String(result.combined)
      : `${stdout}\n${stderr}`;
  return {
    normalizedOutputSha256: sha256(normalizeFailureText(combined, roots)),
    normalizedStdoutSha256: sha256(normalizeFailureText(stdout, roots)),
    normalizedStderrSha256: sha256(normalizeFailureText(stderr, roots))
  };
}

function parseMochaFailures(output, roots = []) {
  const start = output.search(/\n\s+\d+ failing\b/);
  if (start < 0) return [];
  const after = output.slice(start);
  const firstDetail = after.search(/\n\s+1\) /);
  const section = firstDetail >= 0 ? after.slice(firstDetail + 1) : after;
  const norm = normalizeFailureText(section, roots);
  const blocks = norm.split(/\n(?=\s+\d+\) )/);
  const failures = [];
  for (const block of blocks) {
    const match = block.match(/^\s+(\d+)\)\s+([^\n]+)\n\s+([^\n]+):?\n([\s\S]*)$/);
    if (!match) continue;
    const body = match[4].trim();
    failures.push({
      identity: `${match[2].trim()} :: ${match[3].trim().replace(/:$/, "")}`.replace(/\s+/g, " "),
      body,
      bodySha256: sha256(body)
    });
  }
  return failures;
}

function parseMochaCounts(output) {
  const passing = Number((String(output).match(/\n\s+(\d+) passing\b/) || [])[1] || 0);
  const failingMatch = String(output).match(/\n\s+(\d+) failing\b/);
  const failing = failingMatch ? Number(failingMatch[1]) : 0;
  return { passing, failing };
}

function extractStructuredErrorCode(combined) {
  const text = String(combined);
  const patterns = [
    /Error:\s+(O40_INITIALIZATION_MISMATCH:[A-Za-z0-9_.:-]+)/,
    /Error:\s+([A-Z][A-Z0-9_]{2,})/,
    /^(O\.\d[\w.]* evidence is stale)\s*$/m,
    /^(O\d+[A-Z0-9_]*)\s*$/m
  ];
  for (const re of patterns) {
    const match = text.match(re);
    if (match) return match[1];
  }
  return null;
}

const CRASH_PATTERNS = Object.freeze([
  /\bSyntaxError\b/,
  /\bERR_MODULE_NOT_FOUND\b/,
  /\bCannot find module\b/,
  /\bFATAL ERROR\b/,
  /\bSegmentation fault\b/i
]);

function detectCrashOrUnrelatedFailure(combined, approvedErrorCode) {
  const text = String(combined);
  for (const re of CRASH_PATTERNS) {
    if (re.test(text)) {
      return `crash_or_module_error:${re}`;
    }
  }
  // An approved stale token plus an unrelated Error: line is rejected by callers
  // when comparing structured codes / mocha identities. Extra hard error codes:
  if (approvedErrorCode) {
    const codes = [...text.matchAll(/Error:\s+([A-Z0-9_.:-]+)/g)].map((m) => m[1]);
    const extras = codes.filter(
      (code) => code !== approvedErrorCode && !approvedErrorCode.startsWith(code)
    );
    // Ignore Node.js version footer noise
    const meaningful = extras.filter((code) => !/^v?\d+\.\d+\.\d+/.test(code));
    if (meaningful.length > 0 && !meaningful.every((c) => approvedErrorCode.includes(c))) {
      // Only flag when a clearly different ERROR token appears alongside the approved one
      const foreign = meaningful.filter((c) => c !== approvedErrorCode);
      if (foreign.some((c) => c.length >= 8 && c !== approvedErrorCode)) {
        return `additional_error_codes:${foreign.join(",")}`;
      }
    }
  }
  return null;
}

function exitCategory(status, signal) {
  if (signal) return `signal:${signal}`;
  if (status === 0) return "zero_exit";
  if (status === null) return "unknown";
  return "nonzero_exit";
}

function failuresEqualExact(observed, expected) {
  if (observed.length !== expected.length) return false;
  for (let i = 0; i < observed.length; i += 1) {
    if (observed[i].identity !== expected[i].identity) return false;
    if (observed[i].bodySha256 !== expected[i].bodySha256) return false;
  }
  return true;
}

function identitiesEqual(a, b) {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((value, index) => value === sb[index]);
}

module.exports = {
  normalizeFailureText,
  sha256,
  normalizedStreamDigests,
  parseMochaFailures,
  parseMochaCounts,
  extractStructuredErrorCode,
  detectCrashOrUnrelatedFailure,
  exitCategory,
  failuresEqualExact,
  identitiesEqual,
  CRASH_PATTERNS
};
