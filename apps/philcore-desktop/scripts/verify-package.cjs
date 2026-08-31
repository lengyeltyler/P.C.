#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const {
  appBundlePath,
  appPayloadPath,
  bundleIdentifier,
  codeSignatureStatus,
  currentGitReference,
  directorySize,
  listFiles,
  macExecutablePath,
  noirRootProofPaths,
  proofBinaryPaths,
  readJson,
  releaseRoot,
  repoRoot,
  secretLikePath,
  sha256,
  userPresenceHelperPaths,
  writeJson,
  zipArtifactPath
} = require("./release-utils.cjs");

const failures = [];
const warnings = [];
const embeddedManifestPath = path.join(
  appPayloadPath,
  "config",
  "release",
  "philcore-desktop-local-alpha.json"
);
const { verifyPackagedPreload } = require("./verify-preload-package.cjs");
const {
  BUILD_TIME_ONLY_PACKAGES,
  EXCLUDED_EDR_PLATFORM_PACKAGES,
  RETAINED_RUNTIME_TOOLING,
  SOLIDITY_ANALYZER_PACKAGES,
  isPathPresent
} = require("./package-composition-policy.cjs");

function requireFile(filePath, label) {
  if (!fs.existsSync(filePath)) failures.push(`missing_${label}:${filePath}`);
}

requireFile(appBundlePath, "app_bundle");
requireFile(macExecutablePath, "app_executable");
requireFile(path.join(appPayloadPath, "package.json"), "payload_package_json");
requireFile(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "main", "main.cjs"), "desktop_main");
requireFile(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "preload", "preload.cjs"), "desktop_preload");
requireFile(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "shared", "bridge-contract.cjs"), "desktop_bridge_contract");
requireFile(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "index.html"), "desktop_renderer");
requireFile(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "startup-guard.js"), "desktop_startup_guard");
requireFile(path.join(appPayloadPath, "THIRD_PARTY_NOTICES.md"), "third_party_notices");
requireFile(path.join(appPayloadPath, "LICENSES", "OFL-1.1-Pixelify-Sans.txt"), "pixelify_ofl_license");
requireFile(path.join(appPayloadPath, "LICENSES", "PHIL-BRAND-ASSETS.txt"), "phil_brand_assets_notice");
requireFile(embeddedManifestPath, "embedded_release_manifest");

const proofPaths = proofBinaryPaths();
requireFile(proofPaths.bundled.prover, "bundled_prover");
requireFile(proofPaths.bundled.verifier, "bundled_verifier");
const noirPaths = noirRootProofPaths();
requireFile(noirPaths.bundled.nargo, "bundled_noir_nargo");
requireFile(noirPaths.bundled.bb, "bundled_noir_barretenberg");
requireFile(path.join(noirPaths.bundled.project, "Nargo.toml"), "bundled_noir_manifest");
requireFile(path.join(noirPaths.bundled.project, "src", "main.nr"), "bundled_noir_circuit");
requireFile(path.join(noirPaths.bundled.project, "artifacts", "vk"), "bundled_noir_vk");
requireFile(path.join(noirPaths.bundled.project, "artifacts", "descriptor.json"), "bundled_noir_descriptor");
const helperPaths = userPresenceHelperPaths();
requireFile(helperPaths.bundled, "macos_user_presence_helper");

const main = fs.existsSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "main", "main.cjs"))
  ? fs.readFileSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "main", "main.cjs"), "utf8")
  : "";
const preload = fs.existsSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "preload", "preload.cjs"))
  ? fs.readFileSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "preload", "preload.cjs"), "utf8")
  : "";
const html = fs.existsSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "index.html"))
  ? fs.readFileSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "index.html"), "utf8")
  : "";
const renderer = fs.existsSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "app.js"))
  ? fs.readFileSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "app.js"), "utf8")
  : "";
const startupGuard = fs.existsSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "startup-guard.js"))
  ? fs.readFileSync(path.join(appPayloadPath, "apps", "philcore-desktop", "src", "renderer", "startup-guard.js"), "utf8")
  : "";

for (const [label, regex] of [
  ["contextIsolation", /contextIsolation:\s*true/],
  ["nodeIntegration_false", /nodeIntegration:\s*false/],
  ["sandbox_true", /sandbox:\s*true/],
  ["devtools_profile_bound", /devTools:\s*isDevelopment/],
  ["navigation_blocked", /will-navigate/],
  ["window_open_blocked", /setWindowOpenHandler/],
  ["preload_bridge", /contextBridge\.exposeInMainWorld\("philcore"/],
  ["csp", /Content-Security-Policy/]
]) {
  const source = label === "preload_bridge" ? preload : label === "csp" ? html : main;
  if (!regex.test(source)) failures.push(`security_check_failed:${label}`);
}

try {
  verifyPackagedPreload(appPayloadPath);
} catch (error) {
  failures.push(`preload_package_boundary_failed:${error.message}`);
}
if (!startupGuard.includes("PHILCORE_PRELOAD_BRIDGE_UNAVAILABLE")) failures.push("startup_guard_diagnostic_missing");
if (!renderer.includes("PhilCoreRendererStartup.requireBridge()")) failures.push("renderer_startup_guard_missing");
if (html.indexOf("startup-guard.js") < 0 || html.indexOf("startup-guard.js") > html.indexOf("app.js")) {
  failures.push("startup_guard_must_load_before_renderer");
}

const suspicious = listFiles(appPayloadPath, {
  filter: (_file, relative) => !relative.includes(`node_modules${path.sep}`)
}).filter(secretLikePath);
if (suspicious.length > 0) failures.push(`secret_like_files:${suspicious.map((item) => path.relative(repoRoot, item)).join(",")}`);

const manifest = fs.existsSync(embeddedManifestPath) ? readJson(embeddedManifestPath) : {};
const pinnedRuntime = readJson(path.join(repoRoot, "package.json")).engines || {};
const currentCommit = currentGitReference();
if (!/^[0-9a-f]{40}$/u.test(manifest.sourceCommit || "")) failures.push("source_commit_must_be_full_sha");
if (manifest.sourceCommit !== currentCommit) failures.push("source_commit_mismatch");
if (manifest.sourceTree?.checked !== true) failures.push("source_tree_must_be_checked");
if (manifest.sourceTree?.dirty !== false) failures.push("source_tree_must_be_clean_at_build");
if (manifest.sourceTree?.changedPathCount !== 0) failures.push("source_tree_changed_path_count_must_be_zero");
if (manifest.packageProfile === "local_alpha_adhoc") {
  const evidencePath = path.join(releaseRoot, "philcore-desktop-local-alpha-adhoc-evidence.json");
  const expectedEvidence = path.relative(repoRoot, evidencePath);
  if (manifest.artifact?.zip?.sha256 !== null || manifest.artifact?.zip?.bytes !== null
    || manifest.artifact?.zip?.finalHashEvidence !== expectedEvidence) {
    failures.push("adhoc_zip_hash_must_defer_to_post_archive_evidence");
  } else if (!fs.existsSync(evidencePath)) {
    failures.push("adhoc_post_archive_evidence_missing");
  } else {
    const evidence = readJson(evidencePath);
    const expectedTree = execFileSync("git", ["rev-parse", `${manifest.sourceCommit}^{tree}`], {
      cwd: repoRoot,
      encoding: "utf8"
    }).trim();
    if (evidence.kind !== "philcore-desktop-local-alpha-adhoc-evidence"
      || evidence.source?.commit !== manifest.sourceCommit
      || evidence.source?.tree !== expectedTree
      || evidence.source?.clean !== true
      || evidence.artifact?.zipPath !== path.relative(repoRoot, zipArtifactPath)
      || evidence.artifact?.zipSha256 !== sha256(zipArtifactPath)
      || evidence.artifact?.zipBytes !== fs.statSync(zipArtifactPath).size
      || evidence.artifact?.embeddedManifestSha256 !== sha256(embeddedManifestPath)
      || evidence.signing?.strictVerification !== true
      || evidence.signing?.postZipExtractionVerification !== true) {
      failures.push("adhoc_post_archive_evidence_mismatch");
    }
  }
}
const actualAppSizeBytes = directorySize(appBundlePath);
if (manifest.signing?.codeSigned === true) {
  // Nested and top-level code signatures are added after the embedded manifest
  // is sealed. Their exact byte contribution is platform/toolchain dependent;
  // integrity is established by strict code-signature verification plus the
  // individually hashed bundled resources below.
  if (actualAppSizeBytes < Number(manifest.artifact?.appSizeBytes || 0)) {
    failures.push("app_size_mismatch");
  }
} else if (manifest.artifact?.appSizeBytes !== actualAppSizeBytes) {
  failures.push("app_size_mismatch");
}
if (manifest.nodeVersion !== `v${pinnedRuntime.node}`) failures.push("node_version_mismatch");
if (manifest.npmVersion !== pinnedRuntime.npm) failures.push("npm_version_mismatch");
if (manifest.bundleIdentifier !== bundleIdentifier) failures.push("bundle_identifier_mismatch");
if (manifest.securityStatus?.productionApproved !== false) failures.push("production_approval_must_be_false");
if (manifest.publicNetwork?.publicUserOperationSubmission !== false) failures.push("public_userop_status_must_be_false");
if (manifest.signing?.notarized !== false) failures.push("notarization_must_not_be_claimed");
if (manifest.bundledResources?.prover?.sha256 && fs.existsSync(proofPaths.bundled.prover)
  && manifest.bundledResources.prover.sha256 !== sha256(proofPaths.bundled.prover)) {
  failures.push("prover_hash_mismatch");
}
if (manifest.bundledResources?.verifier?.sha256 && fs.existsSync(proofPaths.bundled.verifier)
  && manifest.bundledResources.verifier.sha256 !== sha256(proofPaths.bundled.verifier)) {
  failures.push("verifier_hash_mismatch");
}
for (const [manifestKey, filePath] of [
  ["noirNargo", noirPaths.bundled.nargo],
  ["noirBarretenberg", noirPaths.bundled.bb],
  ["noirVerificationKey", path.join(noirPaths.bundled.project, "artifacts", "vk")],
  ["noirProofDescriptor", path.join(noirPaths.bundled.project, "artifacts", "descriptor.json")]
]) {
  if (manifest.bundledResources?.[manifestKey]?.sha256
    && fs.existsSync(filePath)
    && manifest.bundledResources[manifestKey].sha256 !== sha256(filePath)) {
    failures.push(`${manifestKey}_hash_mismatch`);
  }
}
if (manifest.bundledResources?.userPresenceHelper?.sha256 && fs.existsSync(helperPaths.bundled)
  && manifest.bundledResources.userPresenceHelper.sha256 !== sha256(helperPaths.bundled)) {
  failures.push("user_presence_helper_hash_mismatch");
}
if (manifest.userPresence?.touchIdClaimed === true) failures.push("touch_id_must_not_be_claimed_by_o7_default");
if (manifest.userPresence?.safeStorageAloneSatisfiesReleaseCandidateSigning !== false) {
  failures.push("safe_storage_alone_must_not_satisfy_release_candidate_signing");
}
const devOnlyFiles = listFiles(appPayloadPath).filter((filePath) => {
  const relative = path.relative(appPayloadPath, filePath);
  return /(^|\/)(test|tests|\.cache)(\/|$)|\.map$|\.tsbuildinfo$/u.test(relative);
});
if (devOnlyFiles.length > 0) failures.push(`development_only_files_packaged:${devOnlyFiles.slice(0, 8).map((item) => path.relative(repoRoot, item)).join(",")}`);

function requirePackaged(relativePath, label) {
  if (!isPathPresent(appPayloadPath, relativePath)) failures.push(`required_runtime_package_missing:${label}:${relativePath}`);
}

function requireAbsent(relativePath, label) {
  if (isPathPresent(appPayloadPath, relativePath)) failures.push(`pruned_package_path_present:${label}:${relativePath}`);
}

requirePackaged("node_modules/@nomicfoundation/edr/index.js", "edr_loader");
requirePackaged("node_modules/@nomicfoundation/edr-darwin-arm64/edr.darwin-arm64.node", "edr_darwin_arm64");
requirePackaged("node_modules/esbuild/lib/main.js", "esbuild_js_api");
requirePackaged("node_modules/@esbuild/darwin-arm64/bin/esbuild", "esbuild_darwin_arm64");
requirePackaged("node_modules/tsx/dist/cjs/index.cjs", "tsx_cjs_loader");
requirePackaged(
  "artifacts/contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol/PhilV1Step6CHarmlessTarget.json",
  "routine_harmless_target_artifact"
);
requirePackaged(
  "contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol",
  "routine_harmless_target_source"
);
for (const packageName of RETAINED_RUNTIME_TOOLING) {
  requirePackaged(`node_modules/${packageName}/package.json`, packageName);
}
for (const packageName of EXCLUDED_EDR_PLATFORM_PACKAGES) {
  requireAbsent(`node_modules/${packageName}`, packageName);
}
for (const packageName of SOLIDITY_ANALYZER_PACKAGES) {
  requireAbsent(`node_modules/${packageName}`, packageName);
}
for (const packageName of BUILD_TIME_ONLY_PACKAGES) {
  requireAbsent(`node_modules/${packageName}`, packageName);
}
requireAbsent("node_modules/esbuild/bin/esbuild", "duplicate_esbuild_binary");
requireAbsent("node_modules/esbuild/install.js", "esbuild_install_script");
requireAbsent("artifacts/build-info", "hardhat_build_info");
const debugArtifacts = listFiles(path.join(appPayloadPath, "artifacts")).filter((filePath) => filePath.endsWith(".dbg.json"));
if (debugArtifacts.length > 0) failures.push(`debug_artifacts_packaged:${debugArtifacts.slice(0, 8).map((item) => path.relative(repoRoot, item)).join(",")}`);

const packagedTypeDeclarations = listFiles(path.join(appPayloadPath, "node_modules")).filter((filePath) => filePath.endsWith(".d.ts"));
if (packagedTypeDeclarations.length > 0) {
  failures.push(`node_module_type_declarations_packaged:${packagedTypeDeclarations.slice(0, 8).map((item) => path.relative(repoRoot, item)).join(",")}`);
}

const repositoryPathNeedles = [repoRoot];
const repositoryPathPatterns = [
  /\/Users\/[^/]+\/(?:Developer|Documents)\/PhilCore/u
];
const textLikePackageFiles = listFiles(appPayloadPath).filter((filePath) => {
  const base = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();
  if (fs.statSync(filePath).size > 2 * 1024 * 1024) return false;
  return [".cjs", ".css", ".html", ".js", ".json", ".mjs", ".txt"].includes(ext)
    || ["license", "notice", "copying"].includes(base);
});
const repositoryPathLeaks = [];
for (const filePath of textLikePackageFiles) {
  const content = fs.readFileSync(filePath, "utf8");
  if (
    repositoryPathNeedles.some((needle) => content.includes(needle))
      || repositoryPathPatterns.some((pattern) => pattern.test(content))
  ) {
    repositoryPathLeaks.push(path.relative(repoRoot, filePath));
  }
}
if (repositoryPathLeaks.length > 0) {
  failures.push(`repository_paths_packaged:${repositoryPathLeaks.slice(0, 8).join(",")}`);
}

const signature = codeSignatureStatus(appBundlePath);
if (manifest.signing?.codeSigned === true && !signature.signed) {
  failures.push("manifest_claims_missing_code_signature");
}
if (!signature.signed) warnings.push("unsigned_local_alpha_package");

const result = {
  phase: "O.8",
  status: failures.length === 0 ? "passed" : "failed",
  appPath: path.relative(repoRoot, appBundlePath),
  manifestPath: path.relative(repoRoot, embeddedManifestPath),
  sourceCommit: manifest.sourceCommit || null,
  sourceTreeCleanAtBuild: manifest.sourceTree?.dirty === false,
  failures,
  warnings,
  codeSigned: Boolean(signature.signed),
  notarized: false,
  publicNetworkMutation: false,
  productionApproved: false
};
writeJson(path.join(releaseRoot, "philcore-desktop-package-verification.json"), result);
console.log(JSON.stringify(result, null, 2));
if (failures.length > 0) process.exit(1);
