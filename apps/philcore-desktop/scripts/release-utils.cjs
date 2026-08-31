const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const appRoot = path.join(repoRoot, "apps", "philcore-desktop");
const releaseRoot = path.join(appRoot, "release", "local-alpha");
const configReleaseRoot = path.join(repoRoot, "config", "release");
const profilePath = path.join(appRoot, "build", "release-profiles.json");
const profile = JSON.parse(fs.readFileSync(profilePath, "utf8"));
const productName = profile.productName;
const displayName = profile.displayName || productName;
const executableName = profile.executableName;
const bundleIdentifier = profile.bundleIdentifier;
const version = profile.version;
const appBundlePath = path.join(releaseRoot, `${productName}.app`);
const zipArtifactPath = path.join(releaseRoot, `${productName}-${version}-local-alpha-macos-${executableArchLabel()}.zip`);
const appPayloadPath = path.join(appBundlePath, "Contents", "Resources", "app");
const macExecutablePath = path.join(appBundlePath, "Contents", "MacOS", executableName);
const manifestPath = path.join(configReleaseRoot, "philcore-desktop-local-alpha.json");
const sbomPath = path.join(releaseRoot, "philcore-desktop-sbom.json");
const packageProfileName = process.env.PHILCORE_DESKTOP_PACKAGE_PROFILE || "local_alpha_unsigned";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    encoding: "utf8",
    stdio: options.stdio || "pipe",
    env: { ...process.env, ...(options.env || {}) }
  });
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`${command} ${args.join(" ")} failed${detail ? `\n${detail}` : ""}`);
  }
  return result;
}

function sha256(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function removePath(target) {
  fs.rmSync(target, { recursive: true, force: true });
}

function copyFiltered(source, target, filter = () => true) {
  fs.cpSync(source, target, {
    recursive: true,
    mode: fs.constants.COPYFILE_FICLONE,
    dereference: false,
    // Without this Node rewrites relative framework symlinks to absolute links
    // into node_modules. A copied macOS framework must remain self-contained.
    verbatimSymlinks: true,
    filter: (src) => {
      const relative = path.relative(source, src);
      if (!relative) return true;
      const parts = relative.split(path.sep);
      const base = parts.at(-1);
      if (relative.includes(`${path.sep}.git${path.sep}`)) return false;
      if (base === ".DS_Store" || base.startsWith("._") || parts.includes("__MACOSX")) return false;
      return filter(src, relative);
    }
  });
}

function createCleanZip(source, zipPath, stage) {
  const { assertAuditPassed, auditArchive, auditFilesystem } = require("./release-contamination-audit.cjs");
  assertAuditPassed(auditFilesystem(source, { stage: `${stage}:source` }));
  fs.rmSync(zipPath, { force: true });
  run("ditto", ["-c", "-k", "--norsrc", "--keepParent", path.basename(source), zipPath], {
    cwd: path.dirname(source),
    stdio: "inherit"
  });
  return assertAuditPassed(auditArchive(zipPath, { stage: `${stage}:archive` }));
}

function extractCleanZip(zipPath, destination, stage, method = "ditto") {
  const { assertAuditPassed, auditArchive, auditFilesystem } = require("./release-contamination-audit.cjs");
  assertAuditPassed(auditArchive(zipPath, { stage: `${stage}:archive_input` }));
  fs.mkdirSync(destination, { recursive: true });
  if (method === "ditto") run("ditto", ["-x", "-k", "--norsrc", zipPath, destination], { stdio: "inherit" });
  else if (method === "unzip") run("/usr/bin/unzip", ["-q", zipPath, "-d", destination], { stdio: "inherit" });
  else throw new Error(`unsupported_extraction_method:${method}`);
  const appName = fs.readdirSync(destination).find((entry) => entry.endsWith(".app"));
  if (!appName) throw new Error(`extracted_application_missing:${stage}`);
  const appPath = path.join(destination, appName);
  assertAuditPassed(auditFilesystem(appPath, { stage: `${stage}:${method}_extracted_app` }));
  return appPath;
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function getElectronAppPath() {
  const electronApp = path.join(repoRoot, "node_modules", "electron", "dist", "Electron.app");
  if (!fs.existsSync(electronApp)) throw new Error("Electron.app not found; run npm install first.");
  return electronApp;
}

function plistBuddy(args) {
  return spawnSync("/usr/libexec/PlistBuddy", args, { encoding: "utf8" });
}

function setPlistValue(plist, key, type, value) {
  const set = plistBuddy(["-c", `Set :${key} ${value}`, plist]);
  if (set.status === 0) return;
  const add = plistBuddy(["-c", `Add :${key} ${type} ${value}`, plist]);
  if (add.status !== 0) {
    throw new Error(`Failed to update Info.plist ${key}: ${add.stderr || set.stderr}`);
  }
}

function executableArchLabel() {
  if (process.platform !== "darwin") return `${process.platform}-${process.arch}`;
  return process.arch === "arm64" ? "darwin-arm64" : "darwin-x64";
}

function proofBinaryPaths() {
  const arch = executableArchLabel();
  return {
    arch,
    source: {
      prover: path.join(repoRoot, "proving", "target", "release", "generate-unlock-proof-json"),
      verifier: path.join(repoRoot, "proving", "target", "release", "verify-unlock-proof-json")
    },
    bundled: {
      prover: path.join(appPayloadPath, "bin", arch, "generate-unlock-proof-json"),
      verifier: path.join(appPayloadPath, "bin", arch, "verify-unlock-proof-json")
    }
  };
}

function noirRootProofPaths() {
  const arch = executableArchLabel();
  const cacheRoot = process.env.PHIL_STEP3_CACHE_DIR
    || path.join(os.homedir(), ".cache", "phil-v1-step3");
  return {
    arch,
    source: {
      nargo: process.env.PHILCORE_NOIR_NARGO_BIN
        || path.join(cacheRoot, "toolchains", "nargo-1.0.0-beta.16", "nargo"),
      bb: process.env.PHILCORE_NOIR_BB_BIN
        || path.join(cacheRoot, "toolchains", "bb-3.0.0-nightly.20251104", "bb"),
      project: path.join(repoRoot, "proofs", "phil-v1-step3-noir")
    },
    bundled: {
      nargo: path.join(appPayloadPath, "bin", arch, "nargo"),
      bb: path.join(appPayloadPath, "bin", arch, "bb"),
      project: path.join(appPayloadPath, "proofs", "phil-v1-step3-noir")
    }
  };
}

function userPresenceHelperPaths() {
  const arch = executableArchLabel();
  return {
    arch,
    source: path.join(appRoot, "build", "native", arch, "PhilCoreUserPresenceHelper"),
    bundled: path.join(appPayloadPath, "bin", arch, "PhilCoreUserPresenceHelper"),
    swiftSource: path.join(appRoot, "native", "macos-user-presence", "PhilCoreUserPresenceHelper.swift")
  };
}

function qrHelperPaths() {
  const arch = executableArchLabel();
  return {
    arch,
    source: path.join(appRoot, "build", "native", arch, "PhilCoreQRCode"),
    bundled: path.join(appPayloadPath, "bin", arch, "PhilCoreQRCode"),
    swiftSource: path.join(appRoot, "native", "macos-qr", "PhilCoreQRCode.swift")
  };
}

function listFiles(root, options = {}) {
  const results = [];
  if (!fs.existsSync(root)) return results;
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    const relative = path.relative(root, current);
    if (relative && options.filter && !options.filter(current, relative, stat)) continue;
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) stack.push(path.join(current, entry));
    } else if (stat.isFile()) {
      results.push(current);
    }
  }
  return results.sort();
}

function secretLikePath(filePath) {
  return /(phil_secret|private[-_]?key|mnemonic|seedPhrase|seed_phrase|vaultKey|wrappingKey|recoverySecret|\.pem$|\.keystore$|\.env$)/i.test(filePath);
}

function currentGitReference() {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function gitDirtyStatus() {
  const result = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  if (result.status !== 0) return { checked: false, dirty: true, reason: "git_status_failed" };
  const lines = result.stdout.split(/\r?\n/u).filter(Boolean);
  const protectedPath = path.join(repoRoot, "pqREADME.md");
  const protectedOwnerFile = lines.length === 1
    && lines[0] === "?? pqREADME.md"
    && fs.existsSync(protectedPath)
    && sha256(protectedPath) === "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8";
  const sourceChanges = protectedOwnerFile ? [] : lines;
  return {
    checked: true,
    dirty: sourceChanges.length > 0,
    changedPathCount: sourceChanges.length,
    excludedProtectedUntrackedFiles: protectedOwnerFile
      ? [{ path: "pqREADME.md", sha256: sha256(protectedPath), packaged: false }]
      : []
  };
}

function codeSignatureStatus(target = appBundlePath) {
  if (process.platform !== "darwin" || !fs.existsSync(target)) {
    return { checked: false, signed: false, reason: "not_darwin_or_missing_app" };
  }
  const verify = spawnSync("codesign", ["--verify", "--deep", "--strict", "--verbose=2", target], {
    encoding: "utf8"
  });
  return {
    checked: true,
    signed: verify.status === 0,
    status: verify.status,
    stderr: (verify.stderr || "")
      .replaceAll(repoRoot, "<repo>")
      .trim()
      .slice(0, 800)
  };
}

function artifactSummary(filePath) {
  if (!fs.existsSync(filePath)) return undefined;
  const stat = fs.statSync(filePath);
  return {
    path: path.relative(repoRoot, filePath),
    sha256: sha256(filePath),
    bytes: stat.size
  };
}

function baseReleaseManifest(extra = {}) {
  const proofPaths = proofBinaryPaths();
  const noirPaths = noirRootProofPaths();
  const appExists = fs.existsSync(appBundlePath);
  const signature = codeSignatureStatus(appBundlePath);
  return {
    phase: "O.8",
    packageProfile: packageProfileName,
    productName,
    executableName,
    bundleIdentifier,
    version,
    buildNumber: profile.buildNumber,
    releaseChannel: profile.releaseChannel,
    generatedAt: new Date().toISOString(),
    sourceCommit: currentGitReference(),
    sourceTreeHash: run("git",["rev-parse","HEAD^{tree}"]).stdout.trim(),
    sourceTree: gitDirtyStatus(),
    electronVersion: readJson(path.join(repoRoot, "node_modules", "electron", "package.json")).version,
    nodeVersion: process.version,
    npmVersion: /^npm\/([^\s]+)/u.exec(String(process.env.npm_config_user_agent || ""))?.[1] || "unknown",
    targetArchitecture: executableArchLabel(),
    packageTool: {
      selected: "custom_macos_packager",
      electronBuilderEvaluatedVersion: "26.15.3",
      electronForgeEvaluated: true,
      rationale: "Existing desktop build is custom and O.5 still requires a precise local-alpha resource set; O.7 adds native user-presence helper packaging and guarded signed release-candidate paths."
    },
    artifact: {
      appPath: path.relative(repoRoot, appBundlePath),
      exists: appExists,
      executablePath: path.relative(repoRoot, macExecutablePath),
      appSizeBytes: appExists ? directorySize(appBundlePath) : 0,
      zip: artifactSummary(zipArtifactPath)
    },
    signing: {
      codeSigned: Boolean(signature.signed),
      hardenedRuntimeConfigured: true,
      notarized: false,
      notarizationClaimed: false,
      identitySummary: process.env.PHILCORE_DESKTOP_SIGNING_IDENTITY
        ? String(process.env.PHILCORE_DESKTOP_SIGNING_IDENTITY).replace(/\(([A-Z0-9]+)\)/u, "(team-id-redacted)")
        : "not_configured",
      signature
    },
    publicNetwork: {
      publicUserOperationSubmission: false,
      publicStarknetPublication: false,
      ethereumL1Anchoring: false,
      l1ToBaseRelay: false,
      publicBaseSubmission: false,
      paymaster: false
    },
    securityStatus: {
      acp0002: "Proposed",
      baseSepoliaBetaGate: "blocked",
      productionApproved: false,
      externalAudit: "not_completed",
      meaningfulAssets: "not_allowed"
    },
    bundledResources: {
      prover: artifactSummary(proofPaths.bundled.prover),
      verifier: artifactSummary(proofPaths.bundled.verifier),
      noirNargo: artifactSummary(noirPaths.bundled.nargo),
      noirBarretenberg: artifactSummary(noirPaths.bundled.bb),
      noirVerificationKey: artifactSummary(path.join(noirPaths.bundled.project, "artifacts", "vk")),
      noirProofDescriptor: artifactSummary(path.join(noirPaths.bundled.project, "artifacts", "descriptor.json")),
      userPresenceHelper: artifactSummary(userPresenceHelperPaths().bundled),
      entryPointArtifact: artifactSummary(path.join(appPayloadPath, "node_modules", "@account-abstraction", "contracts", "artifacts", "EntryPoint.json")),
      actionGateArtifact: artifactSummary(path.join(appPayloadPath, "artifacts", "contracts", "base", "PhilBaseActionGate.sol", "PhilBaseActionGate.json"))
    },
    userPresence: {
      selectedModel: "small_signed_swift_helper",
      nativeUserPresenceStatus: fs.existsSync(userPresenceHelperPaths().bundled) ? "helper_bundled" : "helper_not_bundled",
      touchIdClaimed: false,
      broadDeviceOwnerPolicy: true,
      safeStorageAloneSatisfiesReleaseCandidateSigning: false,
      fixtureUsedForAutomatedTests: true
    },
    limitations: [
      "local_alpha_only",
      "unsigned_unless_external_developer_id_identity_is_supplied",
      "not_notarized_in_o7_without_explicit_credentials_and_command",
      "local_hardhat_fixture_bundled_for_o5_path",
      "public_network_mutation_disabled"
    ],
    ...extra
  };
}

function directorySize(root) {
  return listFiles(root).reduce((total, filePath) => total + fs.statSync(filePath).size, 0);
}

function loadManifest() {
  if (!fs.existsSync(manifestPath)) return baseReleaseManifest();
  return readJson(manifestPath);
}

module.exports = {
  appBundlePath,
  appPayloadPath,
  appRoot,
  baseReleaseManifest,
  bundleIdentifier,
  codeSignatureStatus,
  configReleaseRoot,
  copyFiltered,
  createCleanZip,
  currentGitReference,
  directorySize,
  displayName,
  executableArchLabel,
  executableName,
  extractCleanZip,
  getElectronAppPath,
  gitDirtyStatus,
  listFiles,
  loadManifest,
  macExecutablePath,
  manifestPath,
  noirRootProofPaths,
  packageProfile: profile,
  productName,
  proofBinaryPaths,
  qrHelperPaths,
  readJson,
  releaseRoot,
  removePath,
  repoRoot,
  run,
  sbomPath,
  secretLikePath,
  setPlistValue,
  sha256,
  userPresenceHelperPaths,
  version,
  writeJson,
  zipArtifactPath
};
