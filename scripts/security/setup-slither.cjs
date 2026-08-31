#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const toolchainPath = path.join(repoRoot, "config/security/slither-toolchain.json");
const toolchain = JSON.parse(fs.readFileSync(toolchainPath, "utf8"));
const venvPath = path.join(repoRoot, toolchain.venvPath);
const requirementsLock = path.join(repoRoot, toolchain.slither.lockfile);
const requirements = path.join(repoRoot, toolchain.slither.requirements);
const python = process.env.PHILCORE_SECURITY_PYTHON || toolchain.python.expectedExecutable;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: options.stdio || ["ignore", "pipe", "pipe"],
    env: process.env
  });
  if (result.error) {
    return { ...result, failed: true, errorMessage: result.error.message };
  }
  return { ...result, failed: result.status !== 0 };
}

function fail(reason, details = {}) {
  console.error(JSON.stringify({ status: "blocked", reason, ...details }, null, 2));
  process.exit(1);
}

const pythonVersion = run(python, ["-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"]);
if (pythonVersion.failed) {
  fail("python_unavailable", { python, stderr: pythonVersion.stderr, error: pythonVersion.errorMessage });
}

const versionText = pythonVersion.stdout.trim();
const [major, minor] = versionText.split(".").map((value) => Number(value));
if (major !== 3 || minor < 9 || minor > 12) {
  fail("python_version_outside_tested_range", {
    python,
    installedVersion: versionText,
    expectedMinimum: toolchain.python.minimumVersion,
    maximumUntested: `${toolchain.python.maximumUntestedMajor}.${toolchain.python.maximumUntestedMinor}`
  });
}

if (!fs.existsSync(venvPath)) {
  const created = run(python, ["-m", "venv", toolchain.venvPath], { stdio: "inherit" });
  if (created.failed) {
    fail("venv_creation_failed", { python, venvPath: toolchain.venvPath });
  }
}

const venvPython = path.join(venvPath, "bin/python");
const venvSlither = path.join(venvPath, "bin/slither");
const installSource = fs.existsSync(requirementsLock) ? requirementsLock : requirements;

const pipUpgrade = run(venvPython, ["-m", "pip", "install", "--upgrade", "pip"], { stdio: "inherit" });
if (pipUpgrade.failed) {
  fail("pip_upgrade_failed", { venvPath: toolchain.venvPath });
}

const installed = run(venvPython, ["-m", "pip", "install", "-r", path.relative(repoRoot, installSource)], {
  stdio: "inherit"
});
if (installed.failed) {
  fail("slither_install_failed", {
    venvPath: toolchain.venvPath,
    installSource: path.relative(repoRoot, installSource)
  });
}

const version = run(venvSlither, ["--version"]);
const slitherVersionOutput = `${version.stdout}${version.stderr}`.trim();
const slitherVersion = slitherVersionOutput.split(/\r?\n/)[0];
if (version.failed || !slitherVersionOutput.includes(toolchain.slither.version)) {
  fail("slither_version_mismatch", {
    expectedVersion: toolchain.slither.version,
    installedVersion: slitherVersionOutput
  });
}

const freeze = run(venvPython, ["-m", "pip", "freeze"]);
if (!freeze.failed && !fs.existsSync(requirementsLock)) {
  fs.writeFileSync(requirementsLock, freeze.stdout);
}

console.log(JSON.stringify({
  status: "passed",
  model: toolchain.selectedModel,
  python: versionText,
  venvPath: toolchain.venvPath,
  slitherVersion,
  slitherVersionWarnings: slitherVersionOutput.split(/\r?\n/).slice(1),
  installSource: path.relative(repoRoot, installSource),
  globalInstallRequired: false
}, null, 2));
