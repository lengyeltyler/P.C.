#!/usr/bin/env node
const path = require("node:path");
const fs = require("node:fs");
const { configReleaseRoot, writeJson } = require("./release-utils.cjs");
const ops = require("../src/main/trusted-tester-operations.cjs");

const trustedTesterReleasePath = path.join(
  __dirname,
  "..",
  "release",
  "local-alpha",
  ops.RELEASE_IDENTIFIER,
  "trusted-tester-release.json"
);
const trustedTesterRelease = fs.existsSync(trustedTesterReleasePath)
  ? JSON.parse(fs.readFileSync(trustedTesterReleasePath, "utf8"))
  : {};
const release = ops.createReleaseRecord({
  issuedAt: "2026-07-17T00:00:00.000Z",
  authority: trustedTesterRelease.authority || "Developer ID Application",
  teamId: trustedTesterRelease.teamId || "unresolved"
});
const acknowledgement = ops.createTrustedTesterAcknowledgementTemplate(release);
const cohort = ops.createEmptyTrustedTesterCohort({
  cohortIdentifier: "o10-no-real-testers"
});
const diagnosticFixture = ops.sanitizeDiagnosticExport({
  releaseIdentifier: release.releaseIdentifier,
  artifactSha256: release.artifactSha256,
  os: "macOS fixture",
  architecture: "arm64",
  runtime: { status: "local_alpha_verified" },
  proof: { status: "verified", proofBytes: "-----BEGIN SECRET FIXTURE-----" },
  privateKey: "fixture-private-key"
});
const updateValidation = {
  validReplacementFixture: ops.validateReplacementArtifact({
    sha256: release.artifactSha256,
    bundleIdentifier: release.bundleIdentifier,
    teamId: release.teamId,
    authority: `Developer ID Application: Fixture (${release.teamId})`,
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true
  }, release),
  rejectedWrongBundleFixture: ops.validateReplacementArtifact({
    sha256: release.artifactSha256,
    bundleIdentifier: "com.philcore.desktop",
    teamId: release.teamId,
    authority: `Developer ID Application: Fixture (${release.teamId})`,
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true
  }, release),
  rejectedUnsignedFixture: ops.validateReplacementArtifact({
    sha256: release.artifactSha256,
    bundleIdentifier: release.bundleIdentifier,
    teamId: release.teamId,
    authority: `Developer ID Application: Fixture (${release.teamId})`,
    signatureKind: "unsigned",
    notarized: false,
    gatekeeperAccepted: false
  }, release)
};
const rollbackValidation = ops.evaluateRollbackCandidate(
  { ...release, stateVersion: "o10-state-v1" },
  {
    sha256: release.artifactSha256,
    bundleIdentifier: release.bundleIdentifier,
    teamId: release.teamId,
    authority: `Developer ID Application: Fixture (${release.teamId})`,
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true,
    requiresStateVersion: "o10-state-v1"
  }
);
const defectPolicy = ops.createDefectIntakeRecord({
  releaseIdentifier: release.releaseIdentifier,
  artifactSha256: release.artifactSha256,
  macOSVersion: "fixture-macos",
  architecture: "arm64",
  expectedBehavior: "signing is restricted to exact presentations",
  observedBehavior: "fixture unauthorized signing attempt was rejected",
  reproductionSteps: "fixture only",
  signingInvolved: true,
  sanitizedDiagnosticExport: { privateKey: "fixture-private-key" }
});
const betaMatrix = ops.betaReadinessMatrix();
const result = {
  phase: "O.10",
  evidenceType: "trusted_tester_operations_fixture",
  generatedAt: new Date().toISOString(),
  release,
  acknowledgement,
  cohort,
  diagnosticFixture,
  defectPolicy,
  updateValidation,
  rollbackValidation,
  revocationFixture: ops.createReleaseRevocationRecord({
    releaseIdentifier: release.releaseIdentifier,
    artifactSha256: release.artifactSha256,
    reason: "fixture_revocation_drill"
  }),
  uninstallModel: ops.uninstallResidualDataModel(release.bundleIdentifier),
  distributionDryRun: ops.createDistributionDryRun(release),
  bundleIdentifierRecommendation: ops.bundleIdentifierRecommendation(),
  betaReadinessMatrix: betaMatrix,
  betaReadinessSummary: ops.summarizeReadiness(betaMatrix),
  actualTesterDistribution: false,
  publicNetworkMutation: false,
  productionApproved: false
};

writeJson(path.join(configReleaseRoot, "philcore-desktop-o10-trusted-tester-ops.json"), result);
console.log(JSON.stringify(result, null, 2));
