const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "../..");
const TOOLCHAIN_PATH = path.join(REPO_ROOT, "config/starknet-toolchain.json");

function expandHome(value) {
  if (!value || typeof value !== "string") return value;
  if (value === "~") return process.env.HOME || value;
  if (value.startsWith("~/")) return path.join(process.env.HOME || "", value.slice(2));
  return value;
}

function loadToolchain() {
  return JSON.parse(fs.readFileSync(TOOLCHAIN_PATH, "utf8"));
}

function run(command, args = [], options = {}) {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: options.env || process.env
  });

  return {
    command: [command, ...args].join(" "),
    status: result.status,
    stdout: String(result.stdout || "").trim(),
    stderr: String(result.stderr || "").trim(),
    error: result.error
  };
}

function parseVersion(text) {
  const match = String(text || "").match(
    /(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)/
  );
  return match ? match[1] : null;
}

function compareSemver(actual, expected) {
  const parse = (value) => String(value).split(".").map((part) => Number(part));
  const a = parse(actual);
  const e = parse(expected);
  for (let i = 0; i < Math.max(a.length, e.length); i += 1) {
    const av = a[i] || 0;
    const ev = e[i] || 0;
    if (av > ev) return 1;
    if (av < ev) return -1;
  }
  return 0;
}

function checkVersion({ name, command, args, expected, exact = true }) {
  const result = run(command, args);
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
  const actual = parseVersion(output);
  let ok = Boolean(actual);
  if (ok && exact) {
    ok = actual === expected;
  } else if (ok) {
    ok = compareSemver(actual, expected) >= 0;
  }

  return {
    name,
    command: result.command,
    expected,
    actual,
    installed: !result.error && result.status === 0,
    ok,
    output,
    error: result.error ? result.error.message : null
  };
}

function candidateCommands(name, configured) {
  const candidates = [];
  if (configured?.pinnedBinary) candidates.push(expandHome(configured.pinnedBinary));
  if (configured?.pinnedBinaryDirectory) candidates.push(path.join(expandHome(configured.pinnedBinaryDirectory), name));
  candidates.push(name);
  return [...new Set(candidates)];
}

function checkPinnedVersion({ name, configured, args, expected, exact = true }) {
  const attempts = [];
  for (const command of candidateCommands(name, configured)) {
    const result = run(command, args);
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
    const actual = parseVersion(output);
    let ok = Boolean(actual);
    if (ok && exact) {
      ok = actual === expected;
    } else if (ok) {
      ok = compareSemver(actual, expected) >= 0;
    }
    attempts.push({
      command: result.command,
      actual,
      installed: !result.error && result.status === 0,
      ok,
      output,
      error: result.error ? result.error.message : null
    });
    if (ok) {
      return {
        name,
        command: result.command,
        expected,
        actual,
        installed: !result.error && result.status === 0,
        ok,
        output,
        error: null,
        attempts
      };
    }
  }
  const last = attempts[attempts.length - 1] || {};
  return {
    name,
    command: last.command || name,
    expected,
    actual: last.actual || null,
    installed: Boolean(last.installed),
    ok: false,
    output: last.output || "",
    error: last.error || null,
    attempts
  };
}

function checkRustNightly(toolchain) {
  const result = run("cargo", [`+${toolchain.rust.nightlyToolchain}`, "--version"]);
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
  return {
    name: "cargo",
    command: result.command,
    expected: toolchain.rust.nightlyToolchain,
    actual: output || null,
    installed: !result.error && result.status === 0,
    ok: !result.error && result.status === 0,
    output,
    error: result.error ? result.error.message : null
  };
}

function main() {
  const json = process.argv.includes("--json");
  const toolchain = loadToolchain();
  const checks = [
    checkPinnedVersion({
      name: "scarb",
      configured: toolchain.scarb,
      args: ["--version"],
      expected: toolchain.scarb.version
    }),
    checkPinnedVersion({
      name: "proof-scarb",
      configured: toolchain.proofScarb,
      args: ["--version"],
      expected: toolchain.proofScarb.version
    }),
    checkPinnedVersion({
      name: "cairo-execute",
      configured: toolchain.cairo,
      args: ["--version"],
      expected: toolchain.cairo.version
    }),
    checkPinnedVersion({
      name: "snforge",
      configured: toolchain.starknetFoundry,
      args: ["--version"],
      expected: toolchain.starknetFoundry.version
    }),
    checkPinnedVersion({
      name: "universal-sierra-compiler",
      configured: toolchain.universalSierraCompiler,
      args: ["--version"],
      expected: toolchain.universalSierraCompiler.version
    }),
    checkPinnedVersion({
      name: "nargo",
      configured: toolchain.nargo,
      args: ["--version"],
      expected: toolchain.nargo.version
    }),
    checkPinnedVersion({
      name: "bb",
      configured: toolchain.barretenberg,
      args: ["--version"],
      expected: toolchain.barretenberg.version
    }),
    checkRustNightly(toolchain),
    checkVersion({
      name: "node",
      command: "node",
      args: ["--version"],
      expected: toolchain.node.version
    }),
    checkVersion({
      name: "npm",
      command: "npm",
      args: ["--version"],
      expected: toolchain.npm.version
    })
  ];

  const failed = checks.filter((check) => !check.ok);
  const report = {
    version: 1,
    toolchainReference: path.relative(REPO_ROOT, TOOLCHAIN_PATH),
    ok: failed.length === 0,
    checks,
    installationGuidance: [
      "Run npm run ci:install-starknet-toolchain to install the checksum-pinned Starknet proof toolchain.",
      "If using the repo-local cache, run: source scripts/starknet/activate-pinned-toolchain.sh",
      "This checker verifies tools only; it never installs or upgrades them.",
      "Use exact Node 26.0.0 and npm 11.12.1 as pinned by package.json.",
      "Install Rust nightly-2025-07-14 with rustup if cargo reports the toolchain is missing."
    ]
  };

  if (json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("PhilCore Starknet toolchain check");
    for (const check of checks) {
      const status = check.ok ? "PASS" : "FAIL";
      console.log(`- ${status} ${check.name}: expected ${check.expected}, actual ${check.actual || "<missing>"}`);
      if (!check.ok && check.output) {
        console.log(`  ${check.output.split("\n")[0]}`);
      }
      if (!check.ok && check.error) {
        console.log(`  ${check.error}`);
      }
    }
  }

  if (!report.ok) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  loadToolchain,
  run,
  checkVersion,
  parseVersion
};
