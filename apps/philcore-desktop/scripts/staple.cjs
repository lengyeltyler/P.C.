#!/usr/bin/env node
const fs = require("node:fs");
const { appBundlePath, run } = require("./release-utils.cjs");
const { assertAuditPassed, auditFilesystem } = require("./release-contamination-audit.cjs");
const {
  buildReleaseArtifactLineage,
  createStapledArtifactRecord,
  sourceIdentity,
  verifyNotarizationReceipt
} = require("./release-artifact-lineage.cjs");
const releaseLineage = buildReleaseArtifactLineage();
if (!fs.existsSync(releaseLineage.signedArtifactRecordPath) || !fs.existsSync(releaseLineage.notarizationReceiptPath)) {
  throw new Error("accepted_lineage_bound_notarization_receipt_required");
}
const signedArtifact = JSON.parse(fs.readFileSync(releaseLineage.signedArtifactRecordPath, "utf8"));
const receipt = JSON.parse(fs.readFileSync(releaseLineage.notarizationReceiptPath, "utf8"));
verifyNotarizationReceipt(releaseLineage, signedArtifact, receipt, sourceIdentity(releaseLineage.repoRoot));
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "immediately_before_stapling" }));
run("xcrun", ["stapler", "staple", appBundlePath], { stdio: "inherit" });
run("xcrun", ["stapler", "validate", appBundlePath], { stdio: "inherit" });
run("codesign", ["--verify", "--deep", "--strict", "--verbose=4", appBundlePath], { stdio: "inherit" });
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "immediately_after_stapling" }));
const stapledArtifact = createStapledArtifactRecord(
  releaseLineage,
  signedArtifact,
  receipt,
  sourceIdentity(releaseLineage.repoRoot)
);
fs.writeFileSync(releaseLineage.stapledArtifactRecordPath, `${JSON.stringify(stapledArtifact, null, 2)}\n`);
console.log(JSON.stringify({ stapled: true, stapleValidated: true, lineageId: signedArtifact.lineageId, stapledAppBundleSha256: stapledArtifact.stapledAppBundleSha256 }, null, 2));
