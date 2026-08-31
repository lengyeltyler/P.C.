#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { appBundlePath, extractCleanZip, run, writeJson } = require("./release-utils.cjs");
const { verifyStrict } = require("./macos-signing.cjs");
const { assertAuditPassed, auditArchive, auditFilesystem } = require("./release-contamination-audit.cjs");
const {
  buildReleaseArtifactLineage,
  sourceIdentity,
  verifySignedArtifactRecord
} = require("./release-artifact-lineage.cjs");

const profile = process.env.PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE;
if (process.env.PHILCORE_DESKTOP_NOTARIZE_APPROVED !== "1" || !profile) {
  console.error(JSON.stringify({ status: "blocked", reason: "PHILCORE_DESKTOP_NOTARIZE_APPROVED=1 and external PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE required", submissionPerformed: false, accepted: false }, null, 2));
  process.exit(1);
}
const releaseLineage = buildReleaseArtifactLineage();
const releaseSourceIdentity = sourceIdentity(releaseLineage.repoRoot);
if (!fs.existsSync(releaseLineage.signedArtifactRecordPath)) {
  throw new Error(`signed_artifact_record_missing:${releaseLineage.signedArtifactRecordPath}`);
}
const signedArtifact = JSON.parse(fs.readFileSync(releaseLineage.signedArtifactRecordPath, "utf8"));
const verifiedArtifact = verifySignedArtifactRecord(releaseLineage, signedArtifact, releaseSourceIdentity);
const detail = run("codesign", ["-dvvv", appBundlePath]);
if (!/Authority=Developer ID Application:/u.test(detail.stderr)) throw new Error("Developer ID signed application required; ad-hoc packages cannot be notarized");
run("codesign", ["--verify", "--deep", "--strict", "--verbose=4", appBundlePath], { stdio: "inherit" });
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "pre_notarization_upload_signed_app" }));
const artifact = releaseLineage.notarizationInputPath;
const artifactSha256 = verifiedArtifact.archiveSha256;
if (fs.existsSync(releaseLineage.notarizationReceiptPath)) {
  const priorReceipt = JSON.parse(fs.readFileSync(releaseLineage.notarizationReceiptPath, "utf8"));
  if (priorReceipt.lineageId === verifiedArtifact.binding.lineageId && priorReceipt.artifactSha256 === artifactSha256) {
    if (priorReceipt.status === "In Progress") {
      console.log(JSON.stringify({
        submissionPerformed: false,
        duplicateSubmissionPrevented: true,
        status: priorReceipt.status,
        submissionId: priorReceipt.id,
        artifactSha256
      }, null, 2));
      process.exit(0);
    }
    if (priorReceipt.status === "Accepted") {
      console.log(JSON.stringify({
        submissionPerformed: false,
        duplicateSubmissionPrevented: true,
        accepted: true,
        submissionId: priorReceipt.id,
        artifactSha256
      }, null, 2));
      process.exit(0);
    }
  }
}
assertAuditPassed(auditArchive(artifact, { stage: "notarization_upload_zip:archive" }));
for (const method of ["ditto", "unzip"]) {
  const extractedRoot = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-pre-notary-${method}-`));
  const extractedApp = extractCleanZip(artifact, extractedRoot, "pre_notarization_round_trip", method);
  verifyStrict(extractedApp);
}
const result = run("xcrun", ["notarytool", "submit", artifact, "--keychain-profile", profile, "--wait", "--output-format", "json"]);
const response = JSON.parse(result.stdout);
const safeResult = {
  id: response.id,
  status: response.status,
  capturedAt: new Date().toISOString(),
  baseIdentity: releaseLineage.baseIdentity,
  lineageId: verifiedArtifact.binding.lineageId,
  sourceCommit: verifiedArtifact.binding.sourceCommit,
  sourceTree: verifiedArtifact.binding.sourceTree,
  artifactFile: path.basename(artifact),
  artifactSha256
};
writeJson(releaseLineage.notarizationReceiptPath, safeResult);
if (response.status !== "Accepted") {
  const log = run("xcrun", ["notarytool", "log", response.id, "--keychain-profile", profile, "--output-format", "json"]);
  const sanitized = log.stdout
    .replaceAll(process.env.HOME || "/path-not-set", "<home>")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, "<email-redacted>");
  fs.writeFileSync(path.join(releaseLineage.releaseRoot, `${releaseLineage.baseIdentity}-notarization-log-sanitized.json`), sanitized);
  throw new Error(`Notarization was not accepted: ${response.status}`);
}
console.log(JSON.stringify({ submissionPerformed: true, accepted: true, submissionId: response.id }, null, 2));
