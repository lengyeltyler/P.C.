"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const RUNTIME_ROOTS = Object.freeze([
  "ethers", "starknet", "@noble/curves", "tsx", "hardhat", "dotenv",
  "@nomicfoundation/hardhat-ethers", "@account-abstraction/contracts", "@openzeppelin/contracts"
]);
// The packaged Hardhat task registry is empty: the product only uses its
// in-process provider and precompiled artifacts, never compiler/CLI/test tasks.
const HARDHAT_TOOL_ONLY = new Set([
  "@nomicfoundation/solidity-analyzer", "adm-zip", "chokidar", "mocha", "solc", "tsort",
  "aggregate-error", "boxen", "enquirer", "mnemonist", "p-map", "uuid", "immutable", "@sentry/node"
]);
const HASH = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function packageLocation(repoRoot, requester, name) {
  let current = requester ? path.join(repoRoot, requester) : repoRoot;
  for (;;) {
    const candidate = path.join(current, "node_modules", name);
    if (fs.existsSync(path.join(candidate, "package.json"))) return path.relative(repoRoot, candidate).split(path.sep).join("/");
    if (current === repoRoot) break;
    const parent = path.dirname(current);
    if (!parent.startsWith(repoRoot) || parent === current) break;
    current = parent;
  }
  return null;
}

function runtimePackageSelection(repoRoot, target = { os: "darwin", cpu: "arm64" }) {
  const lock = JSON.parse(fs.readFileSync(path.join(repoRoot, "package-lock.json"), "utf8"));
  const selected = new Map();
  const omitted = [];
  const visit = (name, requester, reason, optional = false) => {
    if (name.startsWith("@types/") || name === "typescript") return;
    // EDR's platform tarballs do not declare npm os/cpu metadata.
    if (name.startsWith("@nomicfoundation/edr-") && name !== `@nomicfoundation/edr-${target.os}-${target.cpu}`) return;
    if (requester === "node_modules/hardhat" && HARDHAT_TOOL_ONLY.has(name)) {
      omitted.push({ name, requester, reason: "compiler_or_test_task_removed_from_release" }); return;
    }
    const relative = packageLocation(repoRoot, requester, name);
    if (!relative) { if (optional) return; throw new Error(`runtime_dependency_missing:${name}`); }
    const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, relative, "package.json"), "utf8"));
    const supports = (values, value) => !values || ((!values.some((v) => !v.startsWith("!")) || values.includes(value)) && !values.includes(`!${value}`));
    const locked = lock.packages[relative] || {};
    if (!supports(pkg.os || locked.os, target.os) || !supports(pkg.cpu || locked.cpu, target.cpu)) return;
    if (selected.has(relative)) { selected.get(relative).requiredBy.push(reason); return; }
    selected.set(relative, { path: relative, name: pkg.name, version: pkg.version, license: pkg.license || null,
      requiredBy: [reason], category: ["hardhat", "tsx", "esbuild"].includes(pkg.name) ? "required_local_runtime_engine" : "runtime_dependency" });
    // Solidity packages are shipped as corresponding source / prebuilt artifacts,
    // not executed as JavaScript. Their unrelated Uniswap build dependencies
    // are not product runtime dependencies.
    if (["@account-abstraction/contracts", "@openzeppelin/contracts"].includes(pkg.name)) return;
    for (const dep of Object.keys(pkg.dependencies || {}).sort()) visit(dep, relative, `${pkg.name}@${pkg.version}`);
    for (const dep of Object.keys(pkg.optionalDependencies || {}).sort()) visit(dep, relative, `${pkg.name}@${pkg.version}:optional`, true);
    for (const dep of Object.keys(pkg.peerDependencies || {}).sort()) visit(dep, relative, `${pkg.name}@${pkg.version}:peer`, true);
  };
  for (const root of RUNTIME_ROOTS) visit(root, null, "product_runtime_import");
  return { target, roots: RUNTIME_ROOTS, packages: [...selected.values()].sort((a,b) => a.path.localeCompare(b.path)), omitted };
}

function selectedNodeModuleEntry(relative, selection) {
  const normalized = `node_modules/${relative.split(path.sep).join("/")}`;
  // Native build intermediates and prebuilds for a different release target
  // are not runtime inputs. Keep the selected platform's loadable addon.
  if (/(?:^|\/)obj\.target(?:\/|$)|\.o$/u.test(normalized)) return false;
  const prebuild = normalized.match(/\/prebuilds\/([^/]+)/u);
  if (prebuild && prebuild[1] !== `${selection.target.os}-${selection.target.cpu}`) return false;
  return selection.packages.some((pkg) => normalized === pkg.path || pkg.path.startsWith(`${normalized}/`)
    || (normalized.startsWith(`${pkg.path}/`) && !normalized.slice(pkg.path.length + 1).includes("node_modules/")));
}

function restrictHardhatTasks(payloadRoot) {
  const relative = "node_modules/hardhat/internal/core/tasks/builtin-tasks.js";
  const file = path.join(payloadRoot, relative);
  const original = fs.readFileSync(file);
  if (!original.toString().includes('require("../../../builtin-tasks/test")')
    || !original.toString().includes('require("../../../builtin-tasks/compile")')) throw new Error("hardhat_task_registry_source_drift");
  const replacement = '"use strict";\n// Phil distribution modification: no compiler, CLI, or test tasks are registered.\n// The unchanged Hardhat provider/artifact APIs serve the local product runtime.\n';
  fs.writeFileSync(file, replacement);
  for (const entry of fs.readdirSync(path.join(payloadRoot, "node_modules/hardhat/builtin-tasks"))) {
    if (entry !== "task-names.js") fs.rmSync(path.join(payloadRoot, "node_modules/hardhat/builtin-tasks", entry), { recursive: true, force: true });
  }
  for (const entry of fs.readdirSync(path.join(payloadRoot, "node_modules/hardhat/internal/cli"))) {
    if (entry !== "ArgumentsParser.js") fs.rmSync(path.join(payloadRoot, "node_modules/hardhat/internal/cli", entry), { recursive: true, force: true });
  }
  for (const directory of ["internal/solidity", "internal/sentry", "internal/hardhat-network/provider/fork", "sample-projects", "src"]) {
    fs.rmSync(path.join(payloadRoot, "node_modules/hardhat", directory), { recursive: true, force: true });
  }
  return { path: relative, upstreamSha256: HASH(original), packagedSha256: HASH(replacement),
    change: "Remove registration and files of build/CLI/test tasks; provider, artifacts and authorization code unchanged" };
}

module.exports = { RUNTIME_ROOTS, HARDHAT_TOOL_ONLY, runtimePackageSelection, selectedNodeModuleEntry, restrictHardhatTasks };
