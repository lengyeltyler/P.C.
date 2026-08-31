"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const defaultRepoRoot = path.resolve(__dirname, "..", "..", "..");
const defaultAppRoot = path.join(defaultRepoRoot, "apps", "philcore-desktop");
const defaultProfilePath = path.join(defaultAppRoot, "build", "release-profiles.json");
const defaultProfile = JSON.parse(fs.readFileSync(defaultProfilePath, "utf8"));
const CANONICAL_RELEASE_FAMILY = "Phil-Controlled-Sepolia-Beta";
const EXPECTED_NOTARY_KEYCHAIN_PROFILE = "philcore-beta-notary";

function assertFilenameComponent(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)) {
    throw new Error(`invalid_${label}`);
  }
  return value;
}

function sha256(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function directorySha256(root) {
  if (!fs.existsSync(root)) throw new Error(`bundle_missing:${root}`);
  const entries = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    const stat = fs.lstatSync(current);
    const relative = path.relative(root, current).split(path.sep).join("/") || ".";
    if (stat.isDirectory()) {
      entries.push(`directory\0${relative}\0${stat.mode & 0o7777}`);
      for (const child of fs.readdirSync(current).sort().reverse()) pending.push(path.join(current, child));
    } else if (stat.isSymbolicLink()) {
      entries.push(`symlink\0${relative}\0${fs.readlinkSync(current)}`);
    } else if (stat.isFile()) {
      entries.push(`file\0${relative}\0${stat.mode & 0o7777}\0${sha256(current)}`);
    } else {
      throw new Error(`unsupported_bundle_entry:${relative}`);
    }
  }
  return crypto.createHash("sha256").update(entries.sort().join("\n")).digest("hex");
}

function sourceIdentity(repoRoot = defaultRepoRoot) {
  function revParse(reference) {
    const result = spawnSync("git", ["rev-parse", reference], {
      cwd: repoRoot,
      encoding: "utf8"
    });
    if (result.status !== 0) throw new Error(`source_identity_unavailable:${reference}`);
    return result.stdout.trim();
  }
  return Object.freeze({ commit: revParse("HEAD"), tree: revParse("HEAD^{tree}") });
}

function portablePath(repoRoot, target) {
  const relative = path.relative(repoRoot, target);
  if (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative)) {
    return relative.split(path.sep).join("/");
  }
  return path.resolve(target);
}

function canonicalBaseIdentity(version, arch) {
  return `${CANONICAL_RELEASE_FAMILY}-${assertFilenameComponent(version, "version")}-macos-${assertFilenameComponent(arch, "architecture")}`;
}

function buildReleaseArtifactLineage(options = {}) {
  const repoRoot = path.resolve(options.repoRoot || defaultRepoRoot);
  const appRoot = path.resolve(options.appRoot || path.join(repoRoot, "apps", "philcore-desktop"));
  const releaseRoot = path.resolve(options.releaseRoot || path.join(appRoot, "release", "local-alpha"));
  const version = options.version || defaultProfile.version;
  const arch = options.arch || process.arch;
  const productName = options.productName || defaultProfile.productName;
  const executableName = options.executableName || defaultProfile.executableName;
  const baseIdentity = canonicalBaseIdentity(version, arch);
  const appPath = path.resolve(options.appPath || path.join(releaseRoot, `${productName}.app`));
  const executablePath = path.resolve(options.executablePath || path.join(appPath, "Contents", "MacOS", executableName));
  const signedArchivePath = path.join(releaseRoot, `${baseIdentity}-notarization.zip`);
  const outputDirectory = path.join(releaseRoot, baseIdentity);
  const finalArchivePath = path.join(outputDirectory, `${baseIdentity}.zip`);
  return Object.freeze({
    schemaVersion: 1,
    releaseFamily: CANONICAL_RELEASE_FAMILY,
    baseIdentity,
    version,
    arch,
    repoRoot,
    appRoot,
    releaseRoot,
    appPath,
    executablePath,
    signedArchivePath,
    notarizationInputPath: signedArchivePath,
    signedArtifactRecordPath: path.join(releaseRoot, `${baseIdentity}-signed-artifact.json`),
    notarizationReceiptPath: path.join(releaseRoot, `${baseIdentity}-notarization-result.json`),
    stapleTargetPath: appPath,
    stapledArtifactRecordPath: path.join(releaseRoot, `${baseIdentity}-stapled-app.json`),
    outputDirectory,
    finalArchivePath,
    finalEvidencePath: path.join(outputDirectory, "trusted-tester-release.json")
  });
}

function lineageBinding(lineage, identity = sourceIdentity(lineage.repoRoot)) {
  const binding = {
    releaseFamily: lineage.releaseFamily,
    baseIdentity: lineage.baseIdentity,
    version: lineage.version,
    arch: lineage.arch,
    sourceCommit: identity.commit,
    sourceTree: identity.tree,
    appPath: portablePath(lineage.repoRoot, lineage.appPath),
    executablePath: portablePath(lineage.repoRoot, lineage.executablePath),
    signedArchivePath: portablePath(lineage.repoRoot, lineage.signedArchivePath),
    notarizationInputPath: portablePath(lineage.repoRoot, lineage.notarizationInputPath),
    stapleTargetPath: portablePath(lineage.repoRoot, lineage.stapleTargetPath),
    finalArchivePath: portablePath(lineage.repoRoot, lineage.finalArchivePath)
  };
  const lineageId = crypto.createHash("sha256").update(JSON.stringify(binding)).digest("hex");
  return Object.freeze({ ...binding, lineageId });
}

function createSignedArtifactRecord(lineage, identity = sourceIdentity(lineage.repoRoot)) {
  if (!fs.existsSync(lineage.appPath)) throw new Error(`signed_app_missing:${lineage.appPath}`);
  if (!fs.existsSync(lineage.executablePath)) throw new Error(`signed_executable_missing:${lineage.executablePath}`);
  if (!fs.existsSync(lineage.signedArchivePath)) throw new Error(`signed_archive_missing:${lineage.signedArchivePath}`);
  const binding = lineageBinding(lineage, identity);
  return Object.freeze({
    schemaVersion: 1,
    kind: "philcore-desktop-signed-release-artifact",
    ...binding,
    executableSha256: sha256(lineage.executablePath),
    appBundleSha256: directorySha256(lineage.appPath),
    archiveSha256: sha256(lineage.signedArchivePath),
    archiveBytes: fs.statSync(lineage.signedArchivePath).size
  });
}

function verifySignedArtifactRecord(lineage, record, identity = sourceIdentity(lineage.repoRoot), options = {}) {
  if (!record || record.kind !== "philcore-desktop-signed-release-artifact") {
    throw new Error("signed_artifact_record_invalid");
  }
  const expected = lineageBinding(lineage, identity);
  for (const key of Object.keys(expected)) {
    if (record[key] !== expected[key]) throw new Error(`signed_artifact_lineage_mismatch:${key}`);
  }
  if (!fs.existsSync(lineage.signedArchivePath)) {
    throw new Error(`signed_archive_missing:${lineage.signedArchivePath}`);
  }
  if (!fs.existsSync(lineage.executablePath)) {
    throw new Error(`signed_executable_missing:${lineage.executablePath}`);
  }
  if (record.archiveSha256 !== sha256(lineage.signedArchivePath)) {
    throw new Error("signed_archive_hash_mismatch");
  }
  if (record.executableSha256 !== sha256(lineage.executablePath)) {
    throw new Error("signed_executable_hash_mismatch");
  }
  if (options.verifyAppBundle !== false && record.appBundleSha256 !== directorySha256(lineage.appPath)) {
    throw new Error("signed_app_bundle_hash_mismatch");
  }
  return Object.freeze({ binding: expected, archiveSha256: record.archiveSha256, executableSha256: record.executableSha256 });
}

function verifyNotarizationReceipt(lineage, record, receipt, identity = sourceIdentity(lineage.repoRoot), options = {}) {
  const verified = verifySignedArtifactRecord(lineage, record, identity, options);
  if (!receipt || receipt.status !== "Accepted") throw new Error("accepted_notarization_receipt_required");
  for (const key of ["baseIdentity", "lineageId", "sourceCommit", "sourceTree", "artifactFile", "artifactSha256"]) {
    const expected = key === "artifactFile"
      ? path.basename(lineage.notarizationInputPath)
      : key === "artifactSha256"
        ? verified.archiveSha256
        : verified.binding[key];
    if (receipt[key] !== expected) throw new Error(`notarization_receipt_lineage_mismatch:${key}`);
  }
  return verified;
}

function createStapledArtifactRecord(lineage, signedRecord, receipt, identity = sourceIdentity(lineage.repoRoot)) {
  const verified = verifyNotarizationReceipt(lineage, signedRecord, receipt, identity, { verifyAppBundle: false });
  return Object.freeze({
    schemaVersion: 1,
    kind: "philcore-desktop-stapled-release-app",
    ...verified.binding,
    executableSha256: sha256(lineage.executablePath),
    signedAppBundleSha256: signedRecord.appBundleSha256,
    stapledAppBundleSha256: directorySha256(lineage.appPath),
    notarizationArtifactSha256: verified.archiveSha256
  });
}

function verifyStapledArtifactRecord(lineage, signedRecord, receipt, stapledRecord, identity = sourceIdentity(lineage.repoRoot)) {
  const verified = verifyNotarizationReceipt(lineage, signedRecord, receipt, identity, { verifyAppBundle: false });
  if (!stapledRecord || stapledRecord.kind !== "philcore-desktop-stapled-release-app") {
    throw new Error("stapled_artifact_record_invalid");
  }
  for (const key of Object.keys(verified.binding)) {
    if (stapledRecord[key] !== verified.binding[key]) throw new Error(`stapled_artifact_lineage_mismatch:${key}`);
  }
  if (stapledRecord.signedAppBundleSha256 !== signedRecord.appBundleSha256) {
    throw new Error("stapled_artifact_signed_app_mismatch");
  }
  if (stapledRecord.notarizationArtifactSha256 !== verified.archiveSha256) {
    throw new Error("stapled_artifact_notarization_hash_mismatch");
  }
  if (stapledRecord.executableSha256 !== sha256(lineage.executablePath)) {
    throw new Error("stapled_executable_hash_mismatch");
  }
  if (stapledRecord.stapledAppBundleSha256 !== directorySha256(lineage.appPath)) {
    throw new Error("stapled_app_bundle_hash_mismatch");
  }
  return verified;
}

function dryRunReport(lineage, identity = sourceIdentity(lineage.repoRoot)) {
  const binding = lineageBinding(lineage, identity);
  return Object.freeze({
    mode: "dry_run",
    operationsPerformed: { signing: false, notarizationSubmission: false, stapling: false, credentialMutation: false },
    canonicalBaseIdentity: lineage.baseIdentity,
    sourceCommit: binding.sourceCommit,
    sourceTree: binding.sourceTree,
    signedOutputPath: binding.signedArchivePath,
    notarizationInputPath: binding.notarizationInputPath,
    signedOutputEqualsNotarizationInput: binding.signedArchivePath === binding.notarizationInputPath,
    expectedStapleTargetPath: binding.stapleTargetPath,
    expectedFinalDistributionPath: binding.finalArchivePath,
    signedArtifactRecordPath: portablePath(lineage.repoRoot, lineage.signedArtifactRecordPath),
    notarizationReceiptPath: portablePath(lineage.repoRoot, lineage.notarizationReceiptPath),
    stapledArtifactRecordPath: portablePath(lineage.repoRoot, lineage.stapledArtifactRecordPath),
    manualRenameOrCopyRequired: false,
    internalPackageProfile: "local_alpha_unsigned",
    developerIdProvisioningProfileRequired: true,
    notaryKeychainProfileRequired: true,
    expectedNotaryKeychainProfile: EXPECTED_NOTARY_KEYCHAIN_PROFILE,
    stages: [
      { stage: 1, name: "unsigned_app", output: binding.appPath },
      { stage: 2, name: "developer_id_signed_app", input: binding.appPath, output: binding.appPath },
      { stage: 3, name: "signed_notarization_archive", input: binding.appPath, output: binding.signedArchivePath },
      { stage: 4, name: "apple_notarization_result", input: binding.notarizationInputPath, output: portablePath(lineage.repoRoot, lineage.notarizationReceiptPath) },
      { stage: 5, name: "stapled_app", input: binding.appPath, output: binding.stapleTargetPath },
      { stage: 6, name: "final_distribution_archive", input: binding.stapleTargetPath, output: binding.finalArchivePath }
    ]
  });
}

module.exports = {
  CANONICAL_RELEASE_FAMILY,
  EXPECTED_NOTARY_KEYCHAIN_PROFILE,
  buildReleaseArtifactLineage,
  canonicalBaseIdentity,
  createSignedArtifactRecord,
  createStapledArtifactRecord,
  directorySha256,
  dryRunReport,
  lineageBinding,
  sha256,
  sourceIdentity,
  verifyNotarizationReceipt,
  verifySignedArtifactRecord,
  verifyStapledArtifactRecord
};
