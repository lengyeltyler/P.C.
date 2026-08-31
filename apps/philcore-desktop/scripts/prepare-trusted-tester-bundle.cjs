#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  appBundlePath, appRoot, configReleaseRoot, createCleanZip, extractCleanZip, releaseRoot, repoRoot, run, sbomPath,
  sha256, writeJson
} = require("./release-utils.cjs");
const { verifyDeveloperId } = require("./macos-signing.cjs");
const { assertAuditPassed, auditArchive, auditFilesystem } = require("./release-contamination-audit.cjs");
const { FINAL_MANIFEST, verifyCoverage, verifyFinalCoverage } = require("./native-notice-coverage.cjs");
const {
  buildReleaseArtifactLineage,
  directorySha256,
  sourceIdentity,
  verifyStapledArtifactRecord
} = require("./release-artifact-lineage.cjs");

const releaseLineage = buildReleaseArtifactLineage();
const releaseIdentifier = releaseLineage.baseIdentity;
const authority = process.env.PHILCORE_DESKTOP_SIGNING_IDENTITY;
const teamId = authority?.match(/\(([A-Z0-9]+)\)$/u)?.[1];
const requiredKeychainGroup = teamId
  ? `${teamId}.com.philcore.desktop.localalpha.webauthn`
  : null;
const receiptPath = releaseLineage.notarizationReceiptPath;
if (!authority || !teamId) throw new Error("Externally selected Developer ID authority and Team ID required");
if (!fs.existsSync(receiptPath) || !fs.existsSync(releaseLineage.signedArtifactRecordPath) || !fs.existsSync(releaseLineage.stapledArtifactRecordPath)) {
  throw new Error("Accepted lineage-bound live notarization receipt required");
}
const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const signedArtifact = JSON.parse(fs.readFileSync(releaseLineage.signedArtifactRecordPath, "utf8"));
const stapledArtifact = JSON.parse(fs.readFileSync(releaseLineage.stapledArtifactRecordPath, "utf8"));
verifyStapledArtifactRecord(releaseLineage, signedArtifact, receipt, stapledArtifact, sourceIdentity(repoRoot));
const notarizationZip = releaseLineage.notarizationInputPath;
assertAuditPassed(auditArchive(notarizationZip, { stage: "accepted_notarization_upload_zip" }));
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "post_stapling_pre_distribution_app" }));
verifyDeveloperId(appBundlePath, authority, teamId, requiredKeychainGroup);
run("xcrun", ["stapler", "validate", appBundlePath], { stdio: "inherit" });
run("spctl", ["--assess", "--type", "execute", "--verbose=4", appBundlePath], { stdio: "inherit" });

const output = releaseLineage.outputDirectory;
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
const zip = releaseLineage.finalArchivePath;
const finalNativeCoverage = {
  schemaVersion: 1, source: sourceIdentity(repoRoot),
  appBundleSha256: directorySha256(appBundlePath), coverage: verifyCoverage(appBundlePath)
};
const finalNativeCoveragePath = path.join(output, FINAL_MANIFEST);
writeJson(finalNativeCoveragePath, finalNativeCoverage);
createCleanZip(appBundlePath, zip, "final_trusted_tester_distribution_zip");
// Keep the final signed hashes outside the signed app to avoid a circular
// resource/signature hash, but inside the distributable archive.
run("/usr/bin/zip", ["-j", zip, finalNativeCoveragePath], { stdio: "inherit" });
const finalZipAudit = assertAuditPassed(auditArchive(zip, { stage: "final_distribution_with_native_notices" }));
const extractionMatrix = [];
function verifyMatrixEntry(matrixZip, extracted, method, transferPath, installationPath) {
  if (sha256(matrixZip) !== sha256(zip)) throw new Error(`matrix_transfer_hash_mismatch:${transferPath}`);
  const extractedApp = extractCleanZip(matrixZip, extracted, `final_distribution_round_trip:${transferPath}`, method);
  const extractedCoverage = JSON.parse(fs.readFileSync(path.join(extracted, FINAL_MANIFEST), "utf8"));
  if (JSON.stringify(extractedCoverage) !== JSON.stringify(finalNativeCoverage)
      || directorySha256(extractedApp) !== extractedCoverage.appBundleSha256) {
    throw new Error("final_native_notice_manifest_or_app_mismatch");
  }
  verifyFinalCoverage(extractedApp, extractedCoverage.coverage);
  verifyDeveloperId(extractedApp, authority, teamId, requiredKeychainGroup);
  run("xcrun", ["stapler", "validate", extractedApp], { stdio: "inherit" });
  run("spctl", ["--assess", "--type", "execute", "--verbose=4", extractedApp], { stdio: "inherit" });
  extractionMatrix.push({ method, transferPath, installationPath, contaminationAuditPassed: true, strictCodeSigningPassed: true, stapleValidated: true, gatekeeperAccepted: true });
}
for (const method of ["ditto", "unzip"]) {
  const extracted = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-beta-final-${method}-`));
  try { verifyMatrixEntry(zip, extracted, method, "direct_local_path", "isolated_applications_style_directory"); }
  finally { fs.rmSync(extracted, { recursive: true, force: true }); }
}
const sharedMatrixRoot = fs.mkdtempSync(path.join("/Users/Shared", "philcore-beta-matrix-"));
const sharedZip = path.join(sharedMatrixRoot, path.basename(zip));
fs.copyFileSync(zip, sharedZip);
for (const method of ["ditto", "unzip"]) {
  const extracted = path.join(sharedMatrixRoot, `Applications-${method}`);
  try { verifyMatrixEntry(sharedZip, extracted, method, "users_shared_copy", "users_shared_isolated_applications_style_directory"); }
  finally { fs.rmSync(extracted, { recursive: true, force: true }); }
}
fs.rmSync(sharedMatrixRoot, { recursive: true, force: true });

run(process.execPath, [path.join(appRoot, "scripts", "sbom.cjs"), sbomPath], { stdio: "inherit" });

for (const source of [
  path.join(configReleaseRoot, "philcore-desktop-local-alpha.json"),
  path.join(configReleaseRoot, "philcore-desktop-package-size.json"),
  sbomPath,
  receiptPath,
  path.join(appRoot, "scripts", "verify-trusted-tester-artifact.sh"),
  releaseLineage.signedArtifactRecordPath,
  releaseLineage.stapledArtifactRecordPath
]) {
  if (fs.existsSync(source)) fs.copyFileSync(source, path.join(output, path.basename(source)));
}
const result = {
  phase: "CONTROLLED_SEPOLIA_BETA", releaseIdentifier, producedAt: new Date().toISOString(),
  artifact: { file: path.basename(zip), bytes: fs.statSync(zip).size, sha256: sha256(zip) },
  lineage: {
    lineageId: signedArtifact.lineageId,
    sourceCommit: signedArtifact.sourceCommit,
    sourceTree: signedArtifact.sourceTree,
    executableSha256: signedArtifact.executableSha256,
    signedAppBundleSha256: signedArtifact.appBundleSha256,
    stapledAppBundleSha256: stapledArtifact.stapledAppBundleSha256,
    notarizationArtifactFile: receipt.artifactFile,
    notarizationArtifactSha256: receipt.artifactSha256,
    finalArchiveSha256: sha256(zip)
  },
  bundleIdentifier: "com.philcore.desktop.localalpha", authority, teamId,
  developerIdVerified: true, notarizationAccepted: true, stapled: true,
  sbom: { file: path.basename(sbomPath), sha256: sha256(sbomPath), matchesFinalStapledApp: true },
  nativeNoticeCoverage: { file: FINAL_MANIFEST, sha256: sha256(finalNativeCoveragePath), verifiedAfterExtraction: true },
  zipEntryAudit: finalZipAudit,
  automatedExtractionMatrix: extractionMatrix,
  stapleValidatedAfterExtraction: true, gatekeeperAcceptedAfterExtraction: true,
  finderValidation: "pending_independent_second_user",
  independentUserGatekeeperValidation: "pending_independent_second_user",
  suitableForExternalDistribution: false,
  distributedToTesters: false, productionApproved: false, publicNetworkMutation: false
};
writeJson(path.join(output, "trusted-tester-release.json"), result);
fs.writeFileSync(path.join(output, "SHA256SUMS"), `${result.artifact.sha256}  ${result.artifact.file}\n`);
console.log(JSON.stringify(result, null, 2));
