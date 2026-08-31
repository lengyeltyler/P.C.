const assert = require("node:assert/strict");
const ops = require("../src/main/trusted-tester-operations.cjs");

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error);
    process.exitCode = 1;
  }
}

test("acknowledgement template names release limits and forbidden materials", () => {
  const release = ops.createReleaseRecord({ issuedAt: "2026-07-17T00:00:00.000Z", teamId: "TEAMID1234" });
  const template = ops.createTrustedTesterAcknowledgementTemplate(release);
  assert.equal(template.releaseIdentifier, ops.RELEASE_IDENTIFIER);
  assert.equal(template.artifactSha256, ops.ARTIFACT_SHA256);
  assert.match(template.requiredStatements.join("\n"), /not production-approved/);
  assert.match(template.requiredStatements.join("\n"), /Public-network mutation is disabled/);
  assert.ok(template.prohibitedRequests.includes("private keys"));
});

test("real cohort is empty by default", () => {
  const cohort = ops.createEmptyTrustedTesterCohort();
  assert.equal(cohort.realTesterCount, 0);
  assert.equal(cohort.fixtureTesterCount, 0);
  assert.deepEqual(cohort.testers, []);
  assert.equal(cohort.distributedToTesters, false);
});

test("tester acceptance requires real acknowledgement timestamp", () => {
  assert.throws(() => ops.createTesterAcceptanceRecord({ testerReference: "tester-a" }), /tester_acknowledgement_required/);
  const accepted = ops.createTesterAcceptanceRecord({
    testerReference: "fixture-tester",
    fixtureOnly: true,
    acknowledgedAt: "2026-07-17T01:00:00.000Z"
  });
  assert.equal(accepted.fixtureOnly, true);
  assert.equal(accepted.distributedToTester, false);
  assert.equal(accepted.installationStatus, "not_reported");
  const verified = ops.transitionTesterRecord(accepted, {
    installationStatus: "installed",
    verificationStatus: "checksum_and_gatekeeper_verified"
  });
  assert.equal(verified.verificationStatus, "checksum_and_gatekeeper_verified");
  assert.equal(accepted.verificationStatus, "not_reported");
});

test("release expiration is deterministic and fail-closed without expiry", () => {
  const expiresAt = ops.releaseExpiration("2026-07-01T00:00:00.000Z", 30);
  assert.equal(expiresAt, "2026-07-31T00:00:00.000Z");
  assert.equal(ops.isReleaseExpired({ expiresAt }, "2026-08-01T00:00:00.000Z"), true);
  assert.equal(ops.isReleaseExpired({ expiresAt }, "2026-07-02T00:00:00.000Z"), false);
  assert.equal(ops.isReleaseExpired({}), true);
});

test("release revocation is PhilCore distribution policy, not Apple revocation", () => {
  const revocation = ops.createReleaseRevocationRecord({
    releaseIdentifier: ops.RELEASE_IDENTIFIER,
    reason: "fixture_critical_defect"
  });
  assert.equal(revocation.philCoreDistributionPolicyRevoked, true);
  assert.equal(revocation.appleCertificateRevoked, false);
  assert.equal(revocation.notarizationRevoked, false);
});

test("artifact checksum mismatch, wrong authority, wrong Team ID, and wrong bundle are rejected", () => {
  const expected = ops.createReleaseRecord({ teamId: "TEAMID1234" });
  const result = ops.validateReplacementArtifact({
    sha256: "bad",
    bundleIdentifier: "com.example.other",
    teamId: "OTHERTEAM1",
    authority: "Apple Development: Example",
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true
  }, expected);
  assert.equal(result.trusted, false);
  assert.ok(result.reasons.includes("checksum_mismatch"));
  assert.ok(result.reasons.includes("wrong_authority"));
  assert.ok(result.reasons.includes("wrong_team_id"));
  assert.ok(result.reasons.includes("wrong_bundle_identifier"));
});

test("unsigned, ad-hoc, and non-notarized replacements fail closed", () => {
  const expected = ops.createReleaseRecord({ teamId: "TEAMID1234" });
  const result = ops.validateReplacementArtifact({
    sha256: expected.artifactSha256,
    bundleIdentifier: expected.bundleIdentifier,
    teamId: expected.teamId,
    authority: "Developer ID Application: Example (TEAMID1234)",
    signatureKind: "ad_hoc",
    notarized: false,
    gatekeeperAccepted: false
  }, expected);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.includes("not_developer_id_signed"));
  assert.ok(result.reasons.includes("not_notarized"));
  assert.ok(result.reasons.includes("gatekeeper_not_accepted"));
});

test("trusted replacement accepts only exact Developer ID, Team ID, bundle, checksum, notarization, and Gatekeeper evidence", () => {
  const expected = ops.createReleaseRecord({ teamId: "TEAMID1234", artifactSha256: "a".repeat(64) });
  const result = ops.validateReplacementArtifact({
    sha256: expected.artifactSha256,
    bundleIdentifier: expected.bundleIdentifier,
    teamId: expected.teamId,
    authority: "Developer ID Application: Example (TEAMID1234)",
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true
  }, expected);
  assert.equal(result.status, "trusted_replacement");
  assert.deepEqual(result.reasons, []);
});

test("revoked O.9 artifact can never become a trusted replacement", () => {
  const expected = ops.createReleaseRecord({ teamId: "TEAMID1234" });
  const result = ops.validateReplacementArtifact({
    sha256: ops.ARTIFACT_SHA256,
    bundleIdentifier: expected.bundleIdentifier,
    teamId: expected.teamId,
    authority: "Developer ID Application: Example (TEAMID1234)",
    signatureKind: "developer_id",
    notarized: true,
    gatekeeperAccepted: true
  }, expected);
  assert.equal(result.trusted, false);
  assert.ok(result.reasons.includes("release_revoked"));
});

test("rollback refuses incompatible state or revoked artifacts", () => {
  const current = ops.createReleaseRecord({ teamId: "TEAMID1234", stateVersion: "v2" });
  const result = ops.evaluateRollbackCandidate(
    { ...current, stateVersion: "v2" },
    {
      sha256: current.artifactSha256,
      bundleIdentifier: current.bundleIdentifier,
      teamId: current.teamId,
      authority: "Developer ID Application: Example (TEAMID1234)",
      signatureKind: "developer_id",
      notarized: true,
      gatekeeperAccepted: true,
      requiresStateVersion: "v1",
      revoked: true
    }
  );
  assert.equal(result.status, "rollback_rejected");
  assert.equal(result.backupRequired, true);
  assert.equal(result.deleteIdentityByDefault, false);
  assert.ok(result.reasons.includes("state_version_incompatible"));
  assert.ok(result.reasons.includes("release_revoked"));
});

test("diagnostic export redacts obvious secrets and preserves safe release data", () => {
  const diagnostic = ops.sanitizeDiagnosticExport({
    releaseIdentifier: ops.RELEASE_IDENTIFIER,
    artifactSha256: ops.ARTIFACT_SHA256,
    os: "macOS",
    privateKey: "0xabc",
    nested: { phil_secret: "secret", status: "ok" },
    proof: { proofBytes: "-----BEGIN SECRET-----" }
  });
  assert.equal(diagnostic.manuallyInitiated, true);
  assert.equal(diagnostic.automaticTelemetry, false);
  assert.equal(diagnostic.sanitized.releaseIdentifier, ops.RELEASE_IDENTIFIER);
  assert.equal(diagnostic.sanitized.privateKey, "[REDACTED]");
  assert.equal(diagnostic.sanitized.nested.phil_secret, "[REDACTED]");
  assert.equal(diagnostic.sanitized.proof.proofBytes, "[REDACTED]");
  assert.ok(diagnostic.redactionIssues.length >= 3);
});

test("defect severity tells testers to stop on critical and high defects", () => {
  const base = {
    releaseIdentifier: ops.RELEASE_IDENTIFIER,
    artifactSha256: ops.ARTIFACT_SHA256,
    macOSVersion: "15.0",
    architecture: "arm64",
    expectedBehavior: "unlock succeeds",
    reproductionSteps: "open app and unlock",
    sanitizedDiagnosticExport: { safe: true }
  };
  const critical = ops.createDefectIntakeRecord({
    ...base,
    observedBehavior: "private key was exposed"
  });
  assert.equal(critical.severity, "critical");
  assert.equal(critical.testingStopped, true);
  const medium = ops.createDefectIntakeRecord({
    ...base,
    observedBehavior: "installation wording was confusing but workaround exists"
  });
  assert.equal(medium.severity, "medium");
  assert.equal(medium.testingStopped, false);
});

test("uninstall distinguishes application deletion from identity deletion", () => {
  const model = ops.uninstallResidualDataModel();
  assert.equal(model.deletingApplicationRemovesExecutable, true);
  assert.equal(model.deletingApplicationDeletesIdentity, false);
  assert.equal(model.identityDeletionRequiresSeparateFreshAuthentication, true);
  assert.equal(model.destructiveRemovalDefault, false);
});

test("distribution dry run does not send or upload the artifact", () => {
  const dryRun = ops.createDistributionDryRun();
  assert.equal(dryRun.actualSendPerformed, false);
  assert.equal(dryRun.publicUploadPerformed, false);
  assert.equal(dryRun.namedTesterRequiredBeforeSend, true);
  assert.equal(dryRun.operatorApprovalRequiredBeforeSend, true);
});

test("bundle identifier recommendation is explicit and time-boxed", () => {
  const recommendation = ops.bundleIdentifierRecommendation();
  assert.equal(recommendation.currentBundleIdentifier, ops.BUNDLE_IDENTIFIER);
  assert.equal(recommendation.stableCandidate, "com.philcore.desktop");
  assert.match(recommendation.recommendation, /retain_current_identifier/);
  assert.match(recommendation.mustRevisitBefore, /broader Beta/);
});

test("Beta readiness remains blocked despite notarized desktop artifact", () => {
  const matrix = ops.betaReadinessMatrix();
  const summary = ops.summarizeReadiness(matrix);
  assert.equal(summary.status, "blocked");
  assert.equal(summary.baseSepoliaBetaGate, "blocked");
  assert.equal(summary.productionApproved, false);
  assert.ok(summary.blockedItems.some((entry) => entry.item === "baseSepoliaConfiguration"));
  assert.ok(summary.blockedItems.some((entry) => entry.item === "externalAudit"));
});
