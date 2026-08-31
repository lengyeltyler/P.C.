#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");

const requiredFiles = [
  "docs/ARCHITECTURE_CHANGE_CONTROL.md",
  "docs/CANONICAL_DOCS.md",
  "docs/security/PHILCORE_EXTERNAL_AUDIT_SCOPE.md",
  "docs/security/PHILCORE_SOLIDITY_STATIC_ANALYSIS_N6.md",
  "docs/security/PHILCORE_ERC4337_SECURITY_REVIEW_N1.md",
  "docs/security/PHILCORE_BASE_SEPOLIA_BETA_SECURITY_GATE.md",
  "docs/security/PHILCORE_MEANINGFUL_ASSETS_POLICY.md",
  "docs/security/PHILCORE_RECOVERY_AUTHORITY_ROTATION.md",
  "docs/application/PHILCORE_DESKTOP_ALPHA_FOUNDATION.md",
  "docs/application/PHILCORE_DESKTOP_LOCAL_IDENTITY_AND_VAULT.md",
  "docs/application/PHILCORE_DESKTOP_SECURITY_BOUNDARY.md",
  "docs/application/PHILCORE_LOCAL_AUTHORIZATION_DEMO.md",
  "docs/application/PHILCORE_DESKTOP_TESTING.md",
  "config/security/philcore-external-audit-manifest.json",
  "config/security/philcore-dependency-exposure.json",
  "config/security/philcore-solidity-static-analysis.json",
  "config/security/philcore-contract-invariants-report.json",
  "config/security/philcore-npm-audit-report.json",
  "config/security/philcore-base-sepolia-beta-security-gate.json",
  "config/security/philcore-erc4337-security-findings.json",
  "config/security/philcore-recovery-authority-rotation.json",
  "package-lock.json",
  "hardhat.config.cjs",
  "docs/architecture-changes/ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md"
];

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function sha256(relativePath) {
  return crypto.createHash("sha256").update(read(relativePath)).digest("hex");
}

function run(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env
  });
}

const missing = requiredFiles.filter((relativePath) => !fs.existsSync(path.join(repoRoot, relativePath)));
const jsonFiles = requiredFiles.filter((relativePath) => relativePath.endsWith(".json"));
const jsonParseErrors = [];
for (const jsonFile of jsonFiles) {
  try {
    readJson(jsonFile);
  } catch (error) {
    jsonParseErrors.push(`${jsonFile}: ${error.message}`);
  }
}

const manifest = jsonParseErrors.length === 0
  ? readJson("config/security/philcore-external-audit-manifest.json")
  : {};
const dependencyExposure = jsonParseErrors.length === 0
  ? readJson("config/security/philcore-dependency-exposure.json")
  : {};
const betaGate = jsonParseErrors.length === 0
  ? readJson("config/security/philcore-base-sepolia-beta-security-gate.json")
  : {};

const security = run("npm", ["run", "security:full"]);
const acpText = read("docs/architecture-changes/ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md");
const acpStatusExplicit = /Status:\s*Proposed/i.test(acpText) || /review status/i.test(acpText);
const manifestLockHashMatches = manifest?.lockfiles?.packageLockSha256 === sha256("package-lock.json");
const noSecretInclusions = Array.isArray(manifest.excludedFilesAndPatterns)
  && [".env", "private key", "mnemonic", "vault", "secret"].every((needle) =>
    manifest.excludedFilesAndPatterns.some((entry) => String(entry).toLowerCase().includes(needle))
  );
const dependencyBoundaryHasCategories = Array.isArray(dependencyExposure.categories)
  && dependencyExposure.categories.length >= 6;
const betaGateBlocked = betaGate.status === "blocked" && betaGate.productionApprovalGranted === false;

const checks = [
  { id: "audit-required-files", passed: missing.length === 0, details: missing },
  { id: "audit-json-parse", passed: jsonParseErrors.length === 0, details: jsonParseErrors },
  { id: "audit-security-full", passed: security.status === 0, details: security.status === 0 ? "passed" : security.stderr || security.stdout },
  { id: "audit-acp-status-explicit", passed: acpStatusExplicit },
  { id: "audit-package-lock-hash", passed: manifestLockHashMatches },
  { id: "audit-no-secret-inclusions", passed: noSecretInclusions },
  { id: "audit-dependency-boundary-categories", passed: dependencyBoundaryHasCategories },
  { id: "audit-beta-gate-not-falsely-passed", passed: betaGateBlocked }
];
const failed = checks.filter((check) => !check.passed);
const report = {
  phase: manifest.phase || "unknown",
  status: failed.length === 0 ? "passed" : "failed",
  generatedAt: new Date().toISOString(),
  packageLockSha256: fs.existsSync(path.join(repoRoot, "package-lock.json")) ? sha256("package-lock.json") : null,
  checks,
  failed,
  securityCommand: {
    command: "npm run security:full",
    exitCode: security.status
  },
  noArchiveCreated: true,
  noUploadPerformed: true,
  productionApprovalGranted: false
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failed.length > 0) process.exit(1);
