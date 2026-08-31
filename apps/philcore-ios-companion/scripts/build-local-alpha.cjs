#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "../../..");
const projectPath = path.join(repoRoot, "apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj");
const releaseRoot = path.join(repoRoot, "apps/philcore-ios-companion/release/local-alpha");
const derivedData = path.join(releaseRoot, "DerivedData");
const evidencePath = path.join(releaseRoot, "philcore-ios-local-alpha-evidence.json");

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    encoding: "utf8",
    stdio: options.stdio || "pipe",
    maxBuffer: 16 * 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(`${path.basename(executable)} failed (${result.status}): ${(result.stderr || result.stdout || "").trim()}`);
  }
  return String(result.stdout || result.stderr || "").trim();
}

function git(...args) {
  return run("/usr/bin/git", ["-C", repoRoot, ...args]);
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function listEntries(root, current = root, entries = []) {
  for (const name of fs.readdirSync(current).sort()) {
    const full = path.join(current, name);
    const relative = path.relative(root, full).split(path.sep).join("/");
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) {
      entries.push({ path: relative, kind: "symlink", target: fs.readlinkSync(full) });
    } else if (stat.isDirectory()) {
      listEntries(root, full, entries);
    } else if (stat.isFile()) {
      entries.push({ path: relative, kind: "file", bytes: stat.size, sha256: sha256(full) });
    }
  }
  return entries;
}

function appSummary(appPath) {
  const entries = listEntries(appPath);
  const canonical = entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n";
  return {
    treeSha256: crypto.createHash("sha256").update(canonical).digest("hex"),
    fileAndSymlinkCount: entries.length,
    byteCount: entries.reduce((sum, entry) => sum + (entry.bytes || 0), 0)
  };
}

function plistValue(plistPath, key) {
  return run("/usr/libexec/PlistBuddy", ["-c", `Print :${key}`, plistPath]);
}

if (process.platform !== "darwin") throw new Error("iOS local Alpha packaging requires macOS");
const pinnedNode = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8")).engines.node;
if (process.versions.node !== pinnedNode) {
  throw new Error(`ios_package_node_version_mismatch:${process.versions.node}:${pinnedNode}`);
}
const dirty = git("status", "--porcelain", "--untracked-files=all");
const dirtyLines = dirty.split(/\r?\n/u).filter(Boolean);
const protectedOwnerPath = path.join(repoRoot, "pqREADME.md");
const protectedOwnerFile = dirtyLines.length === 1
  && dirtyLines[0] === "?? pqREADME.md"
  && fs.existsSync(protectedOwnerPath)
  && sha256(protectedOwnerPath) === "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8";
if (dirtyLines.length > 0 && !protectedOwnerFile) {
  throw new Error(`ios_package_requires_clean_tree:${dirtyLines[0]}`);
}

const sourceCommit = git("rev-parse", "HEAD");
const sourceTree = git("rev-parse", "HEAD^{tree}");
fs.rmSync(releaseRoot, { recursive: true, force: true });
fs.mkdirSync(releaseRoot, { recursive: true });

const developerDir = process.env.DEVELOPER_DIR || "/Applications/Xcode.app/Contents/Developer";
const xcodebuild = path.join(developerDir, "usr/bin/xcodebuild");
run(xcodebuild, [
  "-quiet",
  "-project", projectPath,
  "-scheme", "PhilCoreCompanion",
  "-configuration", "Release",
  "-destination", "generic/platform=iOS",
  "-derivedDataPath", derivedData,
  `PHILCORE_SOURCE_COMMIT=${sourceCommit}`,
  `PHILCORE_SOURCE_TREE=${sourceTree}`,
  "PHILCORE_SOURCE_TREE_CLEAN=true",
  "build"
], { env: { ...process.env, DEVELOPER_DIR: developerDir }, stdio: "inherit" });

const builtApp = path.join(derivedData, "Build/Products/Release-iphoneos/PhilCoreCompanion.app");
if (!fs.existsSync(builtApp)) throw new Error("ios_release_app_missing");
const builtInfoPlist = path.join(builtApp, "Info.plist");
const builtVersion = plistValue(builtInfoPlist, "CFBundleShortVersionString");
const builtNumber = plistValue(builtInfoPlist, "CFBundleVersion");
const frozenApp = path.join(releaseRoot, `PhilCoreCompanion-${builtVersion}-build${builtNumber}.app`);
fs.cpSync(builtApp, frozenApp, { recursive: true, dereference: false, verbatimSymlinks: true });

const infoPlist = path.join(frozenApp, "Info.plist");
const executable = path.join(frozenApp, "PhilCoreCompanion");
const font = path.join(frozenApp, "PixelifySans-wght.ttf");
const license = path.join(frozenApp, "OFL-1.1-Pixelify-Sans.txt");
const characterLicense = path.join(frozenApp, "PHIL-BRAND-ASSETS.txt");
const characterAssets = path.join(frozenApp, "Characters");
for (const required of [infoPlist, executable, font, license, characterLicense, characterAssets]) {
  if (!fs.existsSync(required)) throw new Error(`ios_release_resource_missing:${path.basename(required)}`);
}
if (plistValue(infoPlist, "PhilCoreSourceCommit") !== sourceCommit) throw new Error("ios_source_commit_not_embedded");
if (plistValue(infoPlist, "PhilCoreSourceTree") !== sourceTree) throw new Error("ios_source_tree_not_embedded");
if (plistValue(infoPlist, "PhilCoreSourceTreeClean") !== "true") throw new Error("ios_clean_state_not_embedded");

const verify = spawnSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", frozenApp], { encoding: "utf8" });
const details = spawnSync("/usr/bin/codesign", ["-d", "--verbose=4", frozenApp], { encoding: "utf8" });
const detailText = `${details.stdout || ""}\n${details.stderr || ""}`;
const field = (name) => new RegExp(`^${name}=(.+)$`, "mu").exec(detailText)?.[1]?.trim() || null;
const authority = field("Authority") || "unknown";
const summary = appSummary(frozenApp);
const profile = path.join(frozenApp, "embedded.mobileprovision");
const evidence = {
  schemaVersion: 1,
  kind: "philcore-ios-local-alpha-build-evidence",
  generatedAt: new Date().toISOString(),
  source: {
    commit: sourceCommit,
    tree: sourceTree,
    clean: true,
    excludedProtectedUntrackedFiles: protectedOwnerFile
      ? [{ path: "pqREADME.md", sha256: sha256(protectedOwnerPath), packaged: false }]
      : []
  },
  product: {
    bundleIdentifier: plistValue(infoPlist, "CFBundleIdentifier"),
    version: plistValue(infoPlist, "CFBundleShortVersionString"),
    build: plistValue(infoPlist, "CFBundleVersion"),
    minimumIOS: "17.0"
  },
  artifact: {
    appPath: path.relative(repoRoot, frozenApp),
    ...summary,
    executableSha256: sha256(executable),
    infoPlistSha256: sha256(infoPlist),
    fontSha256: sha256(font),
    oflLicenseSha256: sha256(license),
    philBrandAssetsNoticeSha256: sha256(characterLicense),
    characterAssetCount: fs.readdirSync(characterAssets).filter((name) => name.endsWith(".png")).length,
    provisioningProfileSha256: fs.existsSync(profile) ? sha256(profile) : null
  },
  signing: {
    verified: verify.status === 0,
    identifier: field("Identifier"),
    teamIdentifier: field("TeamIdentifier"),
    authorityKind: authority.includes(":") ? authority.slice(0, authority.indexOf(":")) : authority
  },
  limitations: {
    localAlphaOnly: true,
    productionApproved: false,
    publicNetworkMutation: false,
    installationPerformedByThisScript: false,
    physicalCeremonyPerformedByThisScript: false
  }
};
if (!evidence.signing.verified) throw new Error(`ios_code_signature_invalid:${verify.stderr || verify.stdout || "unknown"}`);
fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
