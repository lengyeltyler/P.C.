"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");

const LANES = Object.freeze([
  "required_product_runtime",
  "solidity_erc4337",
  "desktop",
  "proving",
  "deterministic_evidence",
  "historical_known_baseline",
  "environment_dependent",
  "physical_ceremony_manual",
  "public_network_prohibited"
]);

const REQUIRED_AUTOMATED_LANES = Object.freeze([
  "required_product_runtime",
  "solidity_erc4337",
  "desktop",
  "proving",
  "deterministic_evidence"
]);

const EXECUTION_MODES = Object.freeze([
  "executed_directly",
  "alias_of",
  "workflow_step"
]);

/**
 * Command-position-aware prohibited detection for automated lanes.
 * Harmless filenames containing words like "signing" are not automatically rejected.
 */
function tokenizeCommand(command) {
  return String(command)
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function isLocalNetworkToken(token) {
  return /^(hardhat|localhost|127\.0\.0\.1|::1)$/i.test(token);
}

function looksLikePublicRpcUrl(token) {
  if (!/^https?:\/\//i.test(token)) return false;
  if (/localhost|127\.0\.0\.1|\[::1\]/i.test(token)) return false;
  return true;
}

function commandLooksProhibited(command) {
  const text = String(command);
  const tokens = tokenizeCommand(text);

  // Public RPC URLs anywhere
  if (tokens.some(looksLikePublicRpcUrl)) return true;

  // Non-local --network <name>
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i] === "--network" && tokens[i + 1] && !isLocalNetworkToken(tokens[i + 1])) {
      return true;
    }
  }

  // npm/pnpm/yarn run <script> where script itself is an operational verb
  const runIdx = tokens.findIndex((t, i) =>
    (t === "run" || t === "run-script") && i > 0 && /^(npm|npx|pnpm|yarn)$/.test(tokens[i - 1])
  );
  if (runIdx >= 0 && tokens[runIdx + 1]) {
    const script = tokens[runIdx + 1];
    if (
      /^(submit:|broadcast|fund:|deploy:|monitor:)/.test(script) ||
      /:(submit|broadcast|fund|deploy|monitor)(:|$)/.test(script) ||
      script === "broadcast" ||
      script === "submit:userop"
    ) {
      return true;
    }
  }

  // hardhat run ... deploy scripts with non-local network already covered;
  // also flag explicit deploy/submission verbs as command position (not filename-only).
  const first = tokens[0] || "";
  const second = tokens[1] || "";
  if (
    (first === "npx" || first === "node") &&
    /deploy|submit|broadcast|fund|monitor|notariz/i.test(tokens.slice(0, 6).join(" "))
  ) {
    // Only when not a hardhat *test* of a file whose path merely contains the word
    const isHardhatTest =
      tokens.includes("hardhat") && tokens.includes("test");
    const isNodeUnitFile =
      first === "node" && /\.test\.cjs$/.test(tokens[tokens.length - 1] || "");
    if (!isHardhatTest && !isNodeUnitFile) {
      if (/\b(deploy|submit|broadcast|fund|monitor|notariz)/i.test(text)) return true;
    }
  }

  // Explicit operational phrases
  if (/\b--monitor\b/i.test(text)) return true;
  if (/\blive[-_ ]?bundler\b/i.test(text)) return true;
  if (/\bbundler-submission\b/i.test(text)) return true;
  if (/\bpublic[-_ ]?network\b/i.test(text)) return true;
  if (/\bmainnet\b/i.test(text)) return true;
  if (/ethereum-sepolia:(submit|fund|deploy|monitor)/i.test(text)) return true;
  if (/\buser-presence:manual\b/i.test(text)) return true;
  if (/\bphysical[-_ ]?ceremony\b/i.test(text)) return true;
  if (/\breal[-_ ]?funds?\b/i.test(text)) return true;
  if (/\bnotariz/i.test(text) && !/\.test\.cjs\b/.test(text)) return true;

  // hardhat run scripts/deploy.js --network sepolia style
  if (
    tokens.includes("hardhat") &&
    tokens.includes("run") &&
    tokens.some((t) => /deploy/i.test(t))
  ) {
    return true;
  }

  // transaction signing *commands* (not unit tests about signing)
  if (
    /\b(gpg|codesign|xcrun\s+notarytool|security\s+sign)\b/i.test(text) ||
    /\bsign-transaction\b/i.test(text) ||
    /\bsend-raw-transaction\b/i.test(text)
  ) {
    return true;
  }

  void second;
  void first;
  return false;
}

const PROHIBITED_ALLOWLIST_IDS = Object.freeze(new Set([]));

function readJson(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));
}

function walkFiles(dir, predicate, acc = []) {
  if (!fs.existsSync(path.join(ROOT, dir))) return acc;
  for (const ent of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = path.join(dir, ent.name);
    if (ent.isDirectory()) walkFiles(rel, predicate, acc);
    else if (predicate(rel, ent.name)) acc.push(rel.split(path.sep).join("/"));
  }
  return acc;
}

function discoverUniverse() {
  const pkg = readJson("package.json");
  const unitTests = walkFiles("test/unit", (_rel, name) => name.endsWith(".test.cjs")).sort();
  const desktopTests = walkFiles("apps/philcore-desktop", (_rel, name) =>
    name.endsWith(".test.cjs")
  ).sort();
  const scripts = Object.keys(pkg.scripts)
    .filter(
      (k) =>
        /^(test:|verify:|check:)/.test(k) ||
        k === "typecheck" ||
        k === "compile" ||
        k === "desktop:test"
    )
    .sort();

  const ids = new Set();
  for (const rel of unitTests) ids.add(`unit:${path.basename(rel)}`);
  for (const rel of desktopTests) ids.add(`desktop_file:${rel}`);
  ids.add("proving:phase34_core");
  for (const name of scripts) ids.add(`script:${name}`);
  ids.add("evidence:o37-10-v2-minimal-account:check");

  return {
    unitTests,
    desktopTests,
    scripts,
    scriptBodies: Object.fromEntries(scripts.map((name) => [name, pkg.scripts[name]])),
    expectedIds: [...ids].sort()
  };
}

function loadClassification() {
  return readJson("config/ci/classification.json");
}

function loadHistoricalManifest() {
  return readJson("config/ci/historical-failure-manifest.json");
}

module.exports = {
  ROOT,
  LANES,
  REQUIRED_AUTOMATED_LANES,
  EXECUTION_MODES,
  PROHIBITED_ALLOWLIST_IDS,
  discoverUniverse,
  loadClassification,
  loadHistoricalManifest,
  commandLooksProhibited,
  tokenizeCommand,
  readJson
};
