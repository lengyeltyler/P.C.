#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const {
  appBundlePath,
  appPayloadPath,
  baseReleaseManifest,
  bundleIdentifier,
  copyFiltered,
  createCleanZip,
  directorySize,
  displayName,
  executableName,
  getElectronAppPath,
  macExecutablePath,
  noirRootProofPaths,
  packageProfile,
  productName,
  proofBinaryPaths,
  qrHelperPaths,
  releaseRoot,
  removePath,
  repoRoot,
  run,
  setPlistValue,
  sha256,
  userPresenceHelperPaths,
  version,
  writeJson,
  zipArtifactPath
} = require("./release-utils.cjs");
const {
  BUILD_TIME_ONLY_PACKAGES,
  EXCLUDED_EDR_PLATFORM_PACKAGES,
  RETAINED_RUNTIME_TOOLING,
  SOLIDITY_ANALYZER_PACKAGES,
  TARGET_NATIVE_PACKAGE,
  shouldCopyContractArtifact,
  shouldCopyContractSource,
  shouldCopyNodeModuleEntry
} = require("./package-composition-policy.cjs");
const { copyDependencyNotices, verifyNotices } = require("./distribution-notices.cjs");
const { writeReleaseSources } = require("./release-source-policy.cjs");
const { runtimePackageSelection, selectedNodeModuleEntry, restrictHardhatTasks } = require("./runtime-package-inventory.cjs");

if (process.platform !== "darwin") {
  throw new Error("PhilCore desktop local Alpha packaging currently targets macOS only.");
}

console.log("== verify pinned release runtime");
run(process.execPath, [
  path.join(repoRoot, "scripts", "cryptography", "check-o37-1-runtime.cjs")
], { stdio: "inherit" });

console.log("== compile local contracts");
run("npm", ["run", "compile"], { stdio: "inherit" });

console.log("== build bundled proof binaries");
run("cargo", [
  "+nightly-2025-07-14",
  "build",
  "--manifest-path",
  "./proving/Cargo.toml",
  "--release",
  "--bin",
  "generate-unlock-proof-json",
  "--bin",
  "verify-unlock-proof-json"
], { stdio: "inherit" });

console.log("== build macOS user-presence helper");
const helperPaths = userPresenceHelperPaths();
fs.mkdirSync(path.dirname(helperPaths.source), { recursive: true });
run("swiftc", [
  helperPaths.swiftSource,
  "-framework",
  "LocalAuthentication",
  "-O",
  "-o",
  helperPaths.source
], { stdio: "inherit" });

console.log("== build local QR helper");
const qrPaths = qrHelperPaths();
fs.mkdirSync(path.dirname(qrPaths.source), { recursive: true });
run("swiftc", [
  qrPaths.swiftSource,
  "-framework",
  "AppKit",
  "-framework",
  "CoreImage",
  "-O",
  "-o",
  qrPaths.source
], { stdio: "inherit" });

console.log("== create macOS .app");
console.log("== bundle sandbox-safe preload");
const bundledPreloadPath = path.join(repoRoot, "apps", "philcore-desktop", "build", "preload", "preload.cjs");
run(process.execPath, [path.join(repoRoot, "apps", "philcore-desktop", "scripts", "bundle-preload.cjs"), bundledPreloadPath], { stdio: "inherit" });

fs.mkdirSync(releaseRoot, { recursive: true });
// Preserve immutable historical release-candidate directories and evidence.
// Only transient working artifacts are cleared for a genuinely fresh build.
for (const transient of [
  appBundlePath,
  zipArtifactPath
]) removePath(transient);
fs.cpSync(getElectronAppPath(), appBundlePath, {
  recursive: true,
  mode: fs.constants.COPYFILE_FICLONE,
  dereference: false,
  verbatimSymlinks: true
});

const oldExecutable = path.join(appBundlePath, "Contents", "MacOS", "Electron");
if (fs.existsSync(oldExecutable)) fs.renameSync(oldExecutable, macExecutablePath);
const plist = path.join(appBundlePath, "Contents", "Info.plist");
setPlistValue(plist, "CFBundleName", "string", displayName);
setPlistValue(plist, "CFBundleDisplayName", "string", displayName);
setPlistValue(plist, "CFBundleExecutable", "string", executableName);
setPlistValue(plist, "CFBundleIdentifier", "string", bundleIdentifier);
setPlistValue(plist, "CFBundleShortVersionString", "string", version);
setPlistValue(plist, "CFBundleVersion", "string", packageProfile.buildNumber);
setPlistValue(plist, "LSMinimumSystemVersion", "string", packageProfile.minimumMacOS);

console.log("== copy local-alpha app payload");
fs.rmSync(appPayloadPath, { recursive: true, force: true });
fs.mkdirSync(appPayloadPath, { recursive: true });

writeJson(path.join(appPayloadPath, "package.json"), {
  name: "philcore-desktop-local-alpha",
  version,
  private: true,
  main: "apps/philcore-desktop/src/main/main.cjs",
  type: "commonjs",
  productName,
  bundleIdentifier,
  releaseChannel: "local-alpha"
});

for (const relative of [
  "hardhat.config.cjs",
  "hardhat.phil-v1-step6c-product.config.cjs",
  "hardhat.shared.cjs",
  "tsconfig.json",
  "package-lock.json",
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
]) {
  const destination = path.join(appPayloadPath, relative);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(path.join(repoRoot, relative), destination);
}
copyFiltered(path.join(repoRoot, "LICENSES"), path.join(appPayloadPath, "LICENSES"));
for (const relative of [
  "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_V1.json",
  "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_READ_ONLY_PREFLIGHT.json"
]) {
  const destination = path.join(appPayloadPath, relative);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(path.join(repoRoot, relative), destination);
}

copyFiltered(path.join(repoRoot, "apps", "philcore-desktop", "src"), path.join(appPayloadPath, "apps", "philcore-desktop", "src"));
writeReleaseSources(repoRoot, appPayloadPath);
fs.copyFileSync(
  bundledPreloadPath,
  path.join(appPayloadPath, "apps", "philcore-desktop", "src", "preload", "preload.cjs")
);
copyFiltered(path.join(repoRoot, "apps", "phil-device-sdk", "src"), path.join(appPayloadPath, "apps", "phil-device-sdk", "src"));
copyFiltered(path.join(repoRoot, "artifacts"), path.join(appPayloadPath, "artifacts"), shouldCopyContractArtifact);
copyFiltered(
  path.join(repoRoot, "contracts"),
  path.join(appPayloadPath, "contracts"),
  shouldCopyContractSource
);
const runtimeSelection = runtimePackageSelection(repoRoot);
copyFiltered(path.join(repoRoot, "node_modules"), path.join(appPayloadPath, "node_modules"), (src, relative) => {
  if (!selectedNodeModuleEntry(relative, runtimeSelection)) return false;
  // A workspace-local convenience link at node_modules/node_modules points
  // back to the dependency root. It is not a runtime dependency and would
  // become an absolute, outside-bundle symlink if copied into the app.
  if (relative === "node_modules") return false;
  if (relative.includes(`${path.sep}.cache${path.sep}`)) return false;
  if (relative.includes(`${path.sep}test${path.sep}`) || relative.includes(`${path.sep}tests${path.sep}`)) return false;
  if (relative.includes(`${path.sep}docs${path.sep}`) || relative.includes(`${path.sep}doc${path.sep}`)) return false;
  if (relative.endsWith(".map") || relative.endsWith(".tsbuildinfo")) return false;
  if (relative.endsWith(".md") && !/licen[sc]e|notice|copying/i.test(relative)) return false;
  return shouldCopyNodeModuleEntry(src, relative);
});
const hardhatModification = restrictHardhatTasks(appPayloadPath);
copyDependencyNotices(repoRoot, appPayloadPath, runtimeSelection);
verifyNotices(appPayloadPath);
writeJson(path.join(appPayloadPath, "config/release/runtime-package-inventory.json"), {
  schemaVersion: 1, ...runtimeSelection, hardhatModification
});

const proofPaths = proofBinaryPaths();
const noirPaths = noirRootProofPaths();
fs.mkdirSync(path.dirname(proofPaths.bundled.prover), { recursive: true });
fs.copyFileSync(proofPaths.source.prover, proofPaths.bundled.prover);
fs.copyFileSync(proofPaths.source.verifier, proofPaths.bundled.verifier);
fs.chmodSync(proofPaths.bundled.prover, 0o755);
fs.chmodSync(proofPaths.bundled.verifier, 0o755);
for (const [source, bundled, label] of [
  [noirPaths.source.nargo, noirPaths.bundled.nargo, "nargo"],
  [noirPaths.source.bb, noirPaths.bundled.bb, "barretenberg"]
]) {
  if (!fs.existsSync(source)) throw new Error(`Pinned ${label} binary is unavailable: ${source}`);
  fs.copyFileSync(source, bundled);
  fs.chmodSync(bundled, 0o755);
}
fs.mkdirSync(path.join(noirPaths.bundled.project, "src"), { recursive: true });
fs.mkdirSync(path.join(noirPaths.bundled.project, "artifacts"), { recursive: true });
for (const relative of [
  "Nargo.toml",
  "src/main.nr",
  "artifacts/vk",
  "artifacts/descriptor.json"
]) {
  fs.copyFileSync(
    path.join(noirPaths.source.project, relative),
    path.join(noirPaths.bundled.project, relative)
  );
}
fs.copyFileSync(helperPaths.source, helperPaths.bundled);
fs.chmodSync(helperPaths.bundled, 0o755);
fs.copyFileSync(qrPaths.source, qrPaths.bundled);
fs.chmodSync(qrPaths.bundled, 0o755);

require("./native-notice-coverage.cjs").verifyCoverage(appBundlePath, { beforeTransforms: true });
try {
  run("strip", [proofPaths.bundled.prover], { stdio: "ignore" });
  run("strip", [proofPaths.bundled.verifier], { stdio: "ignore" });
  run("strip", [helperPaths.bundled], { stdio: "ignore" });
  run("strip", [qrPaths.bundled], { stdio: "ignore" });
} catch {
  // Stripping is a size optimization only; verification still hashes the bundled binaries.
}

const manifest = baseReleaseManifest({
  packagedAt: new Date().toISOString(),
  packagedResourcesPolicy: {
    repositoryRequiredAtRuntime: false,
    cargoRequiredAtRuntime: false,
    hardhatFixtureBundled: true,
    rendererControlledPaths: false,
    bundledProofBinaries: true,
    targetNativePackage: TARGET_NATIVE_PACKAGE,
    retainedRuntimeTooling: RETAINED_RUNTIME_TOOLING,
    packageTimePruning: {
      excludedEdrPlatformPackages: EXCLUDED_EDR_PLATFORM_PACKAGES,
      excludedSolidityAnalyzerPackages: SOLIDITY_ANALYZER_PACKAGES,
      excludedBuildTimeOnlyPackages: BUILD_TIME_ONLY_PACKAGES,
      excludedDuplicateDependencyRoot: true,
      excludedDuplicateEsbuildBinary: true,
      excludedHardhatBuildInfo: true,
      excludedHardhatDebugArtifacts: true,
      retainedEsbuildRuntimeReason: "hardhat.shared.cjs loads tsx/cjs in the packaged local fixture path; tsx depends on esbuild."
    }
  },
  userPresenceHelper: {
    bundled: true,
    sha256: sha256(helperPaths.bundled),
    policy: "device_owner_authentication"
  },
  qrHelper: {
    bundled: true,
    sha256: sha256(qrPaths.bundled),
    payload: "expiring_public_pairing_request_only"
  },
  producedArtifacts: [
    {
      kind: "macos_app",
      path: path.relative(repoRoot, appBundlePath),
      signed: false,
      notarized: false
    },
    {
      kind: "zip",
      path: path.relative(repoRoot, zipArtifactPath),
      signed: false,
      notarized: false
    }
  ]
});
const embeddedManifestPath = path.join(appPayloadPath, "config", "release", "philcore-desktop-local-alpha.json");
for (let attempt = 0; attempt < 4; attempt += 1) {
  writeJson(embeddedManifestPath, manifest);
  const exactAppSizeBytes = directorySize(appBundlePath);
  if (manifest.artifact.appSizeBytes === exactAppSizeBytes) break;
  manifest.artifact.appSizeBytes = exactAppSizeBytes;
  if (attempt === 3) throw new Error("release_manifest_app_size_did_not_stabilize");
}

// Quarantine, Finder, AppleDouble, and resource-fork metadata are never package
// inputs. This runs before signing; the bundle is immutable afterwards.
for (const file of [".DS_Store"]) {
  for (const found of require("./release-utils.cjs").listFiles(appBundlePath).filter((item) => path.basename(item) === file || path.basename(item).startsWith("._"))) {
    fs.rmSync(found, { force: true });
  }
}
const cleanupStack = [appBundlePath];
while (cleanupStack.length > 0) {
  const current = cleanupStack.pop();
  const stat = fs.lstatSync(current);
  if (stat.isSymbolicLink()) {
    if (!fs.existsSync(current)) fs.unlinkSync(current);
    continue;
  }
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(current)) cleanupStack.push(path.join(current, entry));
  }
}
run("xattr", ["-cr", appBundlePath], { stdio: "inherit" });
require("./native-notice-coverage.cjs").verifyCoverage(appBundlePath, { beforeSigning: true });
require("./release-contamination-audit.cjs").assertAuditPassed(
  require("./release-contamination-audit.cjs").auditFilesystem(appBundlePath, { stage: "pre_signing_unsigned_app" })
);

console.log("== create local-alpha zip artifact");
createCleanZip(appBundlePath, zipArtifactPath, "unsigned_local_package_zip");

console.log(JSON.stringify({
  status: "packaged",
  appPath: path.relative(repoRoot, appBundlePath),
  zipPath: path.relative(repoRoot, zipArtifactPath),
  codeSigned: false,
  notarized: false,
  publicNetworkMutation: false
}, null, 2));
