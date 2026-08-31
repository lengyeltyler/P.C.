"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { ROOT } = require("./discovery.cjs");

const ALLOWED_EXECUTABLES = Object.freeze(new Set(["npx", "npm", "node", "cargo"]));
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const DESKTOP_HARDHAT_ARGV = Object.freeze({
  "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization.test.cjs": Object.freeze([
    "npx",
    "hardhat",
    "test",
    "--config",
    "./hardhat.phil-v1-step6c.config.cjs",
    "--no-compile",
    "./apps/philcore-desktop/test/desktop-routine-authorization.test.cjs"
  ]),
  "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization-local-product-runtime.test.cjs": Object.freeze([
    "npx",
    "hardhat",
    "test",
    "--config",
    "./hardhat.phil-v1-step6c-product.config.cjs",
    "--no-compile",
    "./apps/philcore-desktop/test/desktop-routine-authorization-local-product-runtime.test.cjs"
  ]),
  "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization-product-flow.test.cjs": Object.freeze([
    "npx",
    "hardhat",
    "test",
    "--config",
    "./hardhat.phil-v1-step6c-product.config.cjs",
    "--no-compile",
    "./apps/philcore-desktop/test/desktop-routine-authorization-product-flow.test.cjs"
  ])
});
const UNIT_HARDHAT_ARGV = Object.freeze({
  "unit:phil-v1-step6b-local-smart-account.test.cjs": Object.freeze([
    "npx",
    "hardhat",
    "test",
    "--config",
    "./hardhat.phil-v1-step6b.config.cjs",
    "--no-compile",
    "./test/unit/phil-v1-step6b-local-smart-account.test.cjs"
  ]),
  "unit:phil-sepolia-local-composed-contracts.test.cjs": Object.freeze([
    "npx",
    "hardhat",
    "test",
    "--config",
    "./hardhat.phil-sepolia-mint.config.cjs",
    "--no-compile",
    "./test/unit/phil-sepolia-local-composed-contracts.test.cjs"
  ])
});

/**
 * Run an allowlisted argv without shell:true.
 * Prefer this for classification-controlled commands.
 */
function runArgv(argv, options = {}) {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error("runArgv requires a non-empty argv array");
  }
  const [executable, ...args] = argv;
  const resolved =
    executable === "node"
      ? process.execPath
      : executable;
  const baseName = path.basename(resolved);
  if (
    executable !== "node" &&
    !ALLOWED_EXECUTABLES.has(executable) &&
    !ALLOWED_EXECUTABLES.has(baseName)
  ) {
    throw new Error(`Refusing non-allowlisted executable: ${executable}`);
  }

  const result = spawnSync(resolved, args, {
    cwd: options.cwd || ROOT,
    env: options.env || process.env,
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false
  });

  return {
    argv,
    status: result.status === null ? 1 : result.status,
    signal: result.signal || null,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    combined: `${result.stdout || ""}\n${result.stderr || ""}`,
    error: result.error || null
  };
}

/**
 * Build argv for a classified item from its kind/id — never from free-form shell strings.
 */
function argvForItem(item) {
  if (!item || typeof item !== "object") {
    throw new Error("argvForItem requires an item");
  }

  if (item.kind === "unit_test") {
    if (UNIT_HARDHAT_ARGV[item.id]) {
      return [...UNIT_HARDHAT_ARGV[item.id]];
    }
    const file = `test/unit/${item.id.replace(/^unit:/, "")}`;
    return ["npx", "hardhat", "test", "--no-compile", `./${file}`];
  }

  if (item.kind === "desktop_test_file") {
    if (DESKTOP_HARDHAT_ARGV[item.id]) {
      return [...DESKTOP_HARDHAT_ARGV[item.id]];
    }
    const file = item.id.replace(/^desktop_file:/, "");
    return ["node", file];
  }

  if (item.kind === "package_script") {
    const name = item.id.replace(/^script:/, "");
    return ["npm", "run", name];
  }

  if (item.kind === "evidence_check") {
    // Constant argv for the only evidence_check id — not arbitrary manifest shell.
    if (item.id === "evidence:o37-10-v2-minimal-account:check") {
      return ["npm", "run", "evidence:o37-10-v2-minimal-account", "--", "--check"];
    }
    throw new Error(`No argv mapping for evidence_check ${item.id}`);
  }

  if (item.kind === "proving_target") {
    // Constant cargo argv (no shell). Caller may need cargo on PATH.
    return [
      "cargo",
      "+nightly-2025-07-14",
      "test",
      "--manifest-path",
      "./proving/Cargo.toml",
      "--test",
      "phase34_core"
    ];
  }

  throw new Error(`No argv mapping for kind=${item.kind} id=${item.id}`);
}

function argvForHardhatUnitFiles(files) {
  return ["npx", "hardhat", "test", "--no-compile", ...files.map((f) => `./${f}`)];
}

module.exports = {
  ALLOWED_EXECUTABLES,
  DESKTOP_HARDHAT_ARGV,
  UNIT_HARDHAT_ARGV,
  MAX_COMMAND_OUTPUT_BYTES,
  runArgv,
  argvForItem,
  argvForHardhatUnitFiles
};
