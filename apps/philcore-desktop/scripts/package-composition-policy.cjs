const path = require("node:path");

const TARGET_NATIVE_PACKAGE = "darwin-arm64";

const EDR_PLATFORM_PACKAGES = Object.freeze([
  "@nomicfoundation/edr-darwin-arm64",
  "@nomicfoundation/edr-darwin-x64",
  "@nomicfoundation/edr-linux-arm64-gnu",
  "@nomicfoundation/edr-linux-arm64-musl",
  "@nomicfoundation/edr-linux-x64-gnu",
  "@nomicfoundation/edr-linux-x64-musl",
  "@nomicfoundation/edr-win32-x64-msvc"
]);

const SOLIDITY_ANALYZER_PACKAGES = Object.freeze([
  "@nomicfoundation/solidity-analyzer",
  "@nomicfoundation/solidity-analyzer-darwin-arm64",
  "@nomicfoundation/solidity-analyzer-darwin-x64",
  "@nomicfoundation/solidity-analyzer-linux-arm64-gnu",
  "@nomicfoundation/solidity-analyzer-linux-arm64-musl",
  "@nomicfoundation/solidity-analyzer-linux-x64-gnu",
  "@nomicfoundation/solidity-analyzer-linux-x64-musl",
  "@nomicfoundation/solidity-analyzer-win32-x64-msvc"
]);

const BUILD_TIME_ONLY_PACKAGES = Object.freeze([
  "solc",
  "typescript"
]);

const RETAINED_RUNTIME_TOOLING = Object.freeze([
  "@esbuild/darwin-arm64",
  "@nomicfoundation/edr",
  "@nomicfoundation/edr-darwin-arm64",
  "esbuild",
  "hardhat",
  "tsx"
]);

const EXCLUDED_EDR_PLATFORM_PACKAGES = Object.freeze(
  EDR_PLATFORM_PACKAGES.filter((packageName) => packageName !== "@nomicfoundation/edr-darwin-arm64")
);

const EXCLUDED_NODE_PACKAGES = Object.freeze([
  ...EXCLUDED_EDR_PLATFORM_PACKAGES,
  ...SOLIDITY_ANALYZER_PACKAGES,
  ...BUILD_TIME_ONLY_PACKAGES
]);

function normalizedRelative(relative) {
  return relative.split(path.sep).join("/");
}

function nodeModulePackageName(relative) {
  const normalized = normalizedRelative(relative);
  const [first, second] = normalized.split("/");
  if (!first) return "";
  if (first.startsWith("@")) return second ? `${first}/${second}` : "";
  return first;
}

function shouldCopyNodeModuleEntry(_source, relative) {
  const packageName = nodeModulePackageName(relative);
  const normalized = normalizedRelative(relative);

  if (!packageName) return true;
  if (packageName === "electron") return false;
  if (EXCLUDED_NODE_PACKAGES.includes(packageName)) return false;

  if (packageName === "esbuild" && normalized === "esbuild/bin/esbuild") {
    return false;
  }
  if (packageName === "esbuild" && normalized === "esbuild/install.js") {
    return false;
  }
  if (normalized.endsWith(".d.ts")) return false;

  return true;
}

function shouldCopyContractArtifact(_source, relative) {
  const normalized = normalizedRelative(relative);
  if (normalized.split("/").some((part) => part === "test" || part === "tests")) return false;
  if (normalized === "build-info" || normalized.startsWith("build-info/")) return false;
  if (normalized.endsWith(".dbg.json")) return false;
  return true;
}

function shouldCopyContractSource(_source, relative) {
  const normalized = normalizedRelative(relative);
  return !normalized.split("/").some((part) => part === "test" || part === "tests");
}

function isPathPresent(root, relative) {
  return require("node:fs").existsSync(path.join(root, ...relative.split("/")));
}

module.exports = {
  BUILD_TIME_ONLY_PACKAGES,
  EDR_PLATFORM_PACKAGES,
  EXCLUDED_EDR_PLATFORM_PACKAGES,
  EXCLUDED_NODE_PACKAGES,
  RETAINED_RUNTIME_TOOLING,
  SOLIDITY_ANALYZER_PACKAGES,
  TARGET_NATIVE_PACKAGE,
  isPathPresent,
  nodeModulePackageName,
  shouldCopyContractArtifact,
  shouldCopyContractSource,
  shouldCopyNodeModuleEntry
};
