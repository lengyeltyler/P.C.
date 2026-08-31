#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const {
  appBundlePath,
  appPayloadPath,
  listFiles,
  repoRoot,
  writeJson
} = require("./release-utils.cjs");
const {
  BUILD_TIME_ONLY_PACKAGES,
  EDR_PLATFORM_PACKAGES,
  EXCLUDED_EDR_PLATFORM_PACKAGES,
  SOLIDITY_ANALYZER_PACKAGES,
  TARGET_NATIVE_PACKAGE
} = require("./package-composition-policy.cjs");

function sizeOf(target) {
  if (!fs.existsSync(target)) return 0;
  const stat = fs.statSync(target);
  if (stat.isFile()) return stat.size;
  return listFiles(target).reduce((total, filePath) => total + fs.statSync(filePath).size, 0);
}

function entry(label, relative, classification) {
  const target = path.join(appBundlePath, relative);
  return {
    label,
    path: relative,
    bytes: sizeOf(target),
    mib: Number((sizeOf(target) / 1024 / 1024).toFixed(2)),
    classification
  };
}

const breakdown = [
  entry("Electron framework", "Contents/Frameworks", "required_at_runtime"),
  entry("Main executable", "Contents/MacOS", "required_at_runtime"),
  entry("Application source", "Contents/Resources/app/apps", "required_at_runtime"),
  entry("Node modules", "Contents/Resources/app/node_modules", "required_at_runtime_for_local_fixture"),
  entry("Contract artifacts", "Contents/Resources/app/artifacts", "required_for_local_entrypoint_fixture"),
  entry("Contract sources", "Contents/Resources/app/contracts", "required_for_hardhat_local_fixture"),
  entry("Bundled binaries", "Contents/Resources/app/bin", "required_at_runtime"),
  entry("Release config", "Contents/Resources/app/config", "required_for_integrity_status")
];

const nodePackage = (packageName) => entry(
  packageName,
  `Contents/Resources/app/node_modules/${packageName}`,
  "node_module"
);

const packageBreakdown = [
  ...EDR_PLATFORM_PACKAGES.map(nodePackage),
  ...SOLIDITY_ANALYZER_PACKAGES.map(nodePackage),
  ...BUILD_TIME_ONLY_PACKAGES.map(nodePackage),
  nodePackage("tsx"),
  nodePackage("esbuild"),
  nodePackage("@esbuild/darwin-arm64"),
  entry("Hardhat build-info", "Contents/Resources/app/artifacts/build-info", "pruned_when_absent")
];

const sourceMapFiles = listFiles(appPayloadPath).filter((filePath) => filePath.endsWith(".map"));
const packagedTests = listFiles(appPayloadPath).filter((filePath) => /(^|\/)(test|tests)(\/|$)/u.test(path.relative(appPayloadPath, filePath)));
const docs = listFiles(appPayloadPath).filter((filePath) => /(^|\/)(doc|docs)(\/|$)|\.md$/iu.test(path.relative(appPayloadPath, filePath)));

const result = {
  phase: "O.7",
  status: "audited",
  appPath: path.relative(repoRoot, appBundlePath),
  totalBytes: sizeOf(appBundlePath),
  totalMiB: Number((sizeOf(appBundlePath) / 1024 / 1024).toFixed(2)),
  breakdown,
  packageBreakdown,
  removedOrExcludedClasses: [
    "node_modules_tests",
    "node_modules_docs_except_license_notices",
    "source_maps",
    "electron_package_dependency",
    "scarb_cargo_targets",
    "repository_docs",
    "desktop_test_sources",
    "incompatible_edr_platform_packages",
    "solidity_analyzer_runtime_compile_path",
    "typescript_compiler_package",
    "solc_runtime_compiler_package",
    "hardhat_build_info",
    "hardhat_debug_artifacts",
    "duplicate_esbuild_root_binary"
  ],
  retainedLargeClasses: [
    "electron_framework",
    "hardhat_local_fixture_dependency_tree",
    "ethers_and_hardhat_tooling_required_by_current_local_fixture",
    `edr_${TARGET_NATIVE_PACKAGE}`,
    "tsx_and_esbuild_required_by_current_hardhat_shared_config",
    "bundled_prover_and_verifier"
  ],
  pruningPolicy: {
    targetNativePackage: TARGET_NATIVE_PACKAGE,
    excludedEdrPlatformPackages: EXCLUDED_EDR_PLATFORM_PACKAGES,
    excludedSolidityAnalyzerPackages: SOLIDITY_ANALYZER_PACKAGES,
    excludedBuildTimeOnlyPackages: BUILD_TIME_ONLY_PACKAGES,
    esbuildRootBinaryExcluded: true
  },
  packagedSourceMaps: sourceMapFiles.length,
  packagedTestFiles: packagedTests.length,
  packagedDocsOrMarkdownFiles: docs.length,
  publicNetworkMutation: false
};

writeJson(path.join(repoRoot, "config", "release", "philcore-desktop-package-size-audit.json"), result);
console.log(JSON.stringify(result, null, 2));
