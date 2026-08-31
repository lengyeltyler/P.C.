const crypto = require("node:crypto");
const os = require("node:os");
const { REVOKED_ARTIFACTS } = require("../../scripts/release-policy.cjs");

const DEFAULT_RELEASE_TTL_DAYS = 30;
const RELEASE_IDENTIFIER = "philcore-desktop-o9-trusted-tester-rc1";
const ARTIFACT_SHA256 = "eb3ae7e67ecad33128477269dd2e8de98003671fdaa5156f3854d4744c045a9c";
const BUNDLE_IDENTIFIER = "com.philcore.desktop.localalpha";
const REQUIRED_AUTHORITY_PREFIX = "Developer ID Application:";
const APPROVED_STATES = Object.freeze(["demonstrated", "locally_demonstrated", "fixture_demonstrated_only"]);
const SECRET_KEY_PATTERN = /(apple.*password|api.?key|app.?specific|credential|private.?key|phil.?secret|vault.?key|wrapping.?key|recovery.?key|nullifier.?seed|mnemonic|seed.?phrase|witness|proof.?bytes|biometric|raw.?auth|keychain)/iu;
const SECRET_VALUE_PATTERN = /(-----BEGIN|AKIA[0-9A-Z]{16}|phil_secret|private_key|vaultKey|wrappingKey|recoverySecret|nullifierSeed|mnemonic|seedPhrase)/iu;

function nowIso() {
  return new Date().toISOString();
}

function freeze(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function releaseExpiration(issuedAt, ttlDays = DEFAULT_RELEASE_TTL_DAYS) {
  const issued = new Date(issuedAt);
  if (!Number.isFinite(issued.getTime())) throw new Error("invalid_release_issue_time");
  return new Date(issued.getTime() + ttlDays * 24 * 60 * 60 * 1000).toISOString();
}

function isReleaseExpired(release, at = nowIso()) {
  if (!release?.expiresAt) return true;
  return new Date(release.expiresAt).getTime() <= new Date(at).getTime();
}

function createReleaseRecord(input = {}) {
  const issuedAt = input.issuedAt || nowIso();
  const artifactSha256 = input.artifactSha256 || ARTIFACT_SHA256;
  const revocation = REVOKED_ARTIFACTS[artifactSha256] || null;
  return freeze({
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256,
    bundleIdentifier: input.bundleIdentifier || BUNDLE_IDENTIFIER,
    version: input.version || "0.1.0-local-alpha.1",
    authority: input.authority || "Developer ID Application",
    teamId: input.teamId || "unresolved",
    issuedAt,
    expiresAt: input.expiresAt || releaseExpiration(issuedAt),
    productionApproved: false,
    baseSepoliaBetaApproved: false,
    publicNetworkMutation: false,
    distributedToTesters: false,
    revoked: Boolean(revocation),
    revocationReason: revocation?.reason || null,
    finderValidation: revocation ? "failed" : "pending",
    independentUserGatekeeperValidation: revocation ? "failed" : "pending",
    suitableForExternalDistribution: false
  });
}

function createTrustedTesterAcknowledgementTemplate(release = createReleaseRecord()) {
  return freeze({
    acknowledgementVersion: "philcore-trusted-tester-acknowledgement-v1",
    releaseIdentifier: release.releaseIdentifier,
    artifactSha256: release.artifactSha256,
    requiredStatements: [
      "This is pre-Beta release-candidate software and is not production-approved.",
      "Do not use high-value assets or rely on recovery guarantees at this stage.",
      "Public-network mutation is disabled for this artifact.",
      "Verify the checksum before installation.",
      "Diagnostics are manually initiated, previewable, and should be reviewed before sharing.",
      "Report security, identity, signing, proof, or local-state anomalies immediately.",
      "The package expires or may be replaced under PhilCore trusted-tester policy."
    ],
    prohibitedRequests: [
      "private keys",
      "Apple credentials",
      "phil_secret",
      "vault or wrapping keys",
      "recovery keys",
      "proof witnesses",
      "biometric data",
      "raw authentication factors"
    ]
  });
}

function createEmptyTrustedTesterCohort(input = {}) {
  return freeze({
    cohortFormat: "philcore-trusted-tester-cohort-v1",
    cohortIdentifier: input.cohortIdentifier || "o10-fixture-empty-cohort",
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256: input.artifactSha256 || ARTIFACT_SHA256,
    realTesterCount: 0,
    fixtureTesterCount: 0,
    testers: [],
    distributedToTesters: false,
    createdAt: input.createdAt || nowIso()
  });
}

function createTesterAcceptanceRecord(input) {
  if (!input?.testerReference) throw new Error("tester_reference_required");
  if (!input?.acknowledgedAt) throw new Error("tester_acknowledgement_required");
  const release = createReleaseRecord(input.release || {});
  return freeze({
    recordFormat: "philcore-trusted-tester-acceptance-v1",
    testerReference: input.testerReference,
    contactReference: input.contactReference || null,
    fixtureOnly: Boolean(input.fixtureOnly),
    cohortIdentifier: input.cohortIdentifier || "unassigned",
    releaseIdentifier: release.releaseIdentifier,
    artifactSha256: release.artifactSha256,
    acknowledgementVersion: input.acknowledgementVersion || "philcore-trusted-tester-acknowledgement-v1",
    acceptedAt: input.acknowledgedAt,
    expiresAt: input.expiresAt || release.expiresAt,
    installationStatus: "not_reported",
    verificationStatus: "not_reported",
    firstLaunchStatus: "not_reported",
    issueReportStatus: "none",
    revocationStatus: "not_revoked",
    distributedToTester: false
  });
}

function transitionTesterRecord(record, patch) {
  return freeze({
    ...record,
    ...patch,
    updatedAt: patch.updatedAt || nowIso()
  });
}

function createTesterCycleRecord(input = {}) {
  if (!input.testerIdentifier) throw new Error("tester_identifier_required");
  const release = createReleaseRecord(input.release || {});
  return freeze({
    recordFormat: "philcore-trusted-tester-cycle-v1",
    testerIdentifier: input.testerIdentifier,
    role: input.role || "operator",
    cohortIdentifier: input.cohortIdentifier || "o11-stage-a-operator",
    releaseIdentifier: release.releaseIdentifier,
    artifactSha256: release.artifactSha256,
    acknowledgementVersion: input.acknowledgementVersion || "philcore-trusted-tester-acknowledgement-v1",
    acknowledgementAccepted: Boolean(input.acknowledgementAccepted),
    acceptedAt: input.acceptedAt || null,
    isolation: input.isolation || {
      level: "isolated_local_directory",
      separateMacOsUser: false,
      operatorStateAltered: false
    },
    verificationResult: "not_started",
    installationResult: "not_started",
    firstLaunchResult: "not_started",
    nativeUserPresenceResult: "not_started",
    proofResult: "not_started",
    diagnosticExportResult: "not_started",
    removalResult: "not_started",
    issueCount: 0,
    defects: [],
    completionState: "not_started",
    distributedToTesters: false,
    createdAt: input.createdAt || nowIso()
  });
}

function updateTesterCycleRecord(record, patch = {}) {
  if (patch.artifactSha256 && patch.artifactSha256 !== record.artifactSha256) {
    throw new Error("tester_cycle_artifact_hash_mismatch");
  }
  const defects = patch.defects || record.defects || [];
  return freeze({
    ...record,
    ...patch,
    defects,
    issueCount: defects.length,
    distributedToTesters: false,
    updatedAt: patch.updatedAt || nowIso()
  });
}

function createFirstLaunchEvidence(input = {}) {
  return freeze({
    evidenceFormat: "philcore-first-launch-evidence-v1",
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256: input.artifactSha256 || ARTIFACT_SHA256,
    launchedNormally: Boolean(input.launchedNormally),
    releaseStatusClear: Boolean(input.releaseStatusClear),
    alphaWarningClear: Boolean(input.alphaWarningClear),
    publicNetworkDisabledVisible: Boolean(input.publicNetworkDisabledVisible),
    productionWarningClear: Boolean(input.productionWarningClear),
    navigationUnderstandable: Boolean(input.navigationUnderstandable),
    developerTerminologyObserved: Boolean(input.developerTerminologyObserved),
    repositoryPathObserved: Boolean(input.repositoryPathObserved),
    unexpectedPermissionPrompt: Boolean(input.unexpectedPermissionPrompt),
    errors: input.errors || [],
    evidenceClass: input.evidenceClass || "isolated_packaged_launch"
  });
}

function createNativeUserPresenceEvidence(input = {}) {
  const issuedAt = input.issuedAt || nowIso();
  const expiresAt = input.expiresAt || new Date(new Date(issuedAt).getTime() + 2 * 60_000).toISOString();
  const digest = sha256Text(JSON.stringify({
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256: input.artifactSha256 || ARTIFACT_SHA256,
    provider: input.provider,
    outcome: input.outcome,
    issuedAt,
    expiresAt,
    actionBinding: input.actionBinding || "tester-cycle-native-user-presence"
  }));
  return freeze({
    evidenceFormat: "philcore-native-user-presence-tester-evidence-v1",
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256: input.artifactSha256 || ARTIFACT_SHA256,
    requestedPolicy: input.requestedPolicy || "device_owner_authentication",
    evaluatedPolicy: input.evaluatedPolicy || input.requestedPolicy || "device_owner_authentication",
    outcome: input.outcome || "not_run",
    status: input.status || input.outcome || "not_run",
    provider: input.provider || "unknown",
    providerClassification: input.providerClassification || "native_macos_helper",
    visibleSystemPromptObserved: Boolean(input.visibleSystemPromptObserved),
    userPresenceVerified: Boolean(input.userPresenceVerified),
    cancellationTested: Boolean(input.cancellationTested),
    expiredEvidenceRejected: Boolean(input.expiredEvidenceRejected),
    replayRejected: Boolean(input.replayRejected),
    actionMismatchRejected: Boolean(input.actionMismatchRejected),
    sessionMismatchRejected: Boolean(input.sessionMismatchRejected),
    issuedAt,
    expiresAt,
    safeEvidenceDigest: digest,
    biometricDataCaptured: false,
    rawAuthenticationMaterialCaptured: false,
    touchIdClaimed: Boolean(input.touchIdClaimed && input.evidenceClass === "touch_id_biometric_verified"),
    evidenceClass: input.evidenceClass || "device_owner_authentication"
  });
}

function createExternalTesterPendingSlot(input = {}) {
  return freeze({
    recordFormat: "philcore-external-tester-pending-slot-v1",
    testerIdentifier: input.testerIdentifier || "tester-002-external-pending",
    cohortIdentifier: input.cohortIdentifier || "o11-stage-b-one-external-slot",
    releaseIdentifier: input.releaseIdentifier || RELEASE_IDENTIFIER,
    artifactSha256: input.artifactSha256 || ARTIFACT_SHA256,
    acknowledgementAccepted: false,
    artifactDelivered: false,
    checksumVerified: false,
    installed: false,
    firstLaunchCompleted: false,
    distributedToTesters: false,
    personIdentified: false,
    contactRecorded: false,
    createdAt: input.createdAt || nowIso()
  });
}

function evaluateExternalDistributionApprovalGate(input = {}) {
  const reasons = [];
  if (input.stageACompleted !== true) reasons.push("stage_a_incomplete");
  if (input.artifactSha256 !== ARTIFACT_SHA256) reasons.push("artifact_hash_mismatch");
  if (REVOKED_ARTIFACTS[input.artifactSha256]) reasons.push("artifact_revoked");
  if (input.unresolvedCriticalIssues > 0) reasons.push("unresolved_critical_issue");
  if (input.unresolvedHighSecurityOrIdentityIssues > 0) reasons.push("unresolved_high_security_or_identity_issue");
  if (input.tester001Completed !== true) reasons.push("tester_001_incomplete");
  if (input.externalTesterAcknowledgementAccepted !== true) reasons.push("external_acknowledgement_missing");
  if (input.releaseExpired === true) reasons.push("release_expired");
  if (input.releaseRevoked === true) reasons.push("release_revoked");
  if (input.operatorDistributionApproval !== true) reasons.push("operator_distribution_approval_missing");
  if (!input.namedTesterSupplied) reasons.push("named_tester_missing");
  if (!input.approvedDeliveryMethodSupplied) reasons.push("approved_delivery_method_missing");
  return freeze({
    gateFormat: "philcore-external-distribution-approval-gate-v1",
    status: reasons.length === 0 ? "approved_for_single_external_delivery" : "blocked",
    approved: reasons.length === 0,
    reasons,
    distributedToTesters: false,
    usesAppleNotarizationApproval: false
  });
}

function decideExternalTesterSuitability(input = {}) {
  const critical = Number(input.unresolvedCriticalIssues || 0);
  const high = Number(input.unresolvedHighIssues || 0);
  if (critical > 0) return "blocked_by_critical_defect";
  if (high > 0) return "blocked_by_high_defect";
  if (REVOKED_ARTIFACTS[input.artifactSha256 || ARTIFACT_SHA256]) return "blocked_by_revoked_artifact";
  if (input.installationOrVerificationDefect) return "blocked_by_installation_or_verification_defect";
  if (input.diagnosticOrPrivacyDefect) return "blocked_by_diagnostic_or_privacy_defect";
  if (input.stateRemovalRisk) return "blocked_by_state_removal_risk";
  if (input.stageACompleted === true) return "suitable_for_one_external_trusted_tester";
  return "suitable_only_for_further_operator_testing";
}

function sanitizeDiagnosticExport(diagnostic) {
  const issues = [];
  function sanitize(value, keyPath = []) {
    const key = String(keyPath[keyPath.length - 1] || "");
    if (SECRET_KEY_PATTERN.test(key)) {
      issues.push({ keyPath: keyPath.join("."), reason: "sensitive_key_redacted" });
      return "[REDACTED]";
    }
    if (typeof value === "string") {
      if (SECRET_VALUE_PATTERN.test(value)) {
        issues.push({ keyPath: keyPath.join("."), reason: "sensitive_value_redacted" });
        return "[REDACTED]";
      }
      return value.replace(new RegExp(os.userInfo().username, "gu"), "[user]");
    }
    if (Array.isArray(value)) return value.map((entry, index) => sanitize(entry, [...keyPath, String(index)]));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        sanitize(childValue, [...keyPath, childKey])
      ]));
    }
    return value;
  }
  const sanitized = sanitize(diagnostic || {});
  return freeze({
    diagnosticFormat: "philcore-trusted-tester-diagnostic-export-v1",
    manuallyInitiated: true,
    previewBeforeSharingRequired: true,
    automaticTelemetry: false,
    sanitized,
    redactionIssues: issues
  });
}

function classifyDefectSeverity(report) {
  const text = `${report?.summary || ""}\n${report?.observedBehavior || ""}\n${report?.area || ""}`.toLowerCase();
  const involvesSecurity = Boolean(report?.identityInvolved || report?.recoveryInvolved || report?.signingInvolved || report?.proofInvolved || report?.localStateInvolved);
  if (/secret|private key|unauthorized signing|integrity bypass|public-network mutation|unrecoverable vault|identity compromise/u.test(text)) {
    return "critical";
  }
  if (/cannot unlock|signing failure|authorization failure|proof verification failure|gatekeeper|signature regression|state corruption/u.test(text)) {
    return "high";
  }
  if (involvesSecurity && /failure|error|mismatch|corrupt|stuck/u.test(text)) return "high";
  if (/workaround|install|removal|diagnostic|incorrect status|workflow failure/u.test(text)) return "medium";
  return "low";
}

function createDefectIntakeRecord(report) {
  for (const field of ["releaseIdentifier", "artifactSha256", "macOSVersion", "architecture", "expectedBehavior", "observedBehavior", "reproductionSteps"]) {
    if (!report?.[field]) throw new Error(`defect_${field}_required`);
  }
  const diagnostic = sanitizeDiagnosticExport(report.sanitizedDiagnosticExport || {});
  const severity = report.severityProposal || classifyDefectSeverity(report);
  return freeze({
    defectFormat: "philcore-trusted-tester-defect-intake-v1",
    releaseIdentifier: report.releaseIdentifier,
    artifactSha256: report.artifactSha256,
    macOSVersion: report.macOSVersion,
    architecture: report.architecture,
    installationMethod: report.installationMethod || "unknown",
    expectedBehavior: report.expectedBehavior,
    observedBehavior: report.observedBehavior,
    reproductionSteps: report.reproductionSteps,
    diagnostic,
    involvedAreas: {
      identity: Boolean(report.identityInvolved),
      recovery: Boolean(report.recoveryInvolved),
      signing: Boolean(report.signingInvolved),
      proof: Boolean(report.proofInvolved),
      localState: Boolean(report.localStateInvolved)
    },
    severity,
    testingStopped: severity === "critical" || severity === "high",
    requestsSecrets: false
  });
}

function createReleaseRevocationRecord(input) {
  if (!input?.releaseIdentifier && !input?.artifactSha256) throw new Error("revocation_release_or_artifact_required");
  return freeze({
    revocationFormat: "philcore-release-revocation-v1",
    releaseIdentifier: input.releaseIdentifier || null,
    artifactSha256: input.artifactSha256 || null,
    reason: input.reason || "operator_policy",
    issuedAt: input.issuedAt || nowIso(),
    appleCertificateRevoked: false,
    notarizationRevoked: false,
    philCoreDistributionPolicyRevoked: true,
    cohortWithdrawalRequired: Boolean(input.cohortWithdrawalRequired)
  });
}

function validateReplacementArtifact(candidate, expected) {
  const reasons = [];
  if (candidate?.sha256 !== expected.artifactSha256) reasons.push("checksum_mismatch");
  if (candidate?.bundleIdentifier !== expected.bundleIdentifier) reasons.push("wrong_bundle_identifier");
  if (candidate?.teamId !== expected.teamId) reasons.push("wrong_team_id");
  if (!String(candidate?.authority || "").startsWith(REQUIRED_AUTHORITY_PREFIX)) reasons.push("wrong_authority");
  if (candidate?.signatureKind !== "developer_id") reasons.push("not_developer_id_signed");
  if (candidate?.notarized !== true) reasons.push("not_notarized");
  if (candidate?.gatekeeperAccepted !== true) reasons.push("gatekeeper_not_accepted");
  if (candidate?.revoked === true || REVOKED_ARTIFACTS[candidate?.sha256]) reasons.push("release_revoked");
  return freeze({
    status: reasons.length === 0 ? "trusted_replacement" : "rejected",
    trusted: reasons.length === 0,
    reasons,
    publicNetworkMutation: false
  });
}

function evaluateRollbackCandidate(current, candidate) {
  const validation = validateReplacementArtifact(candidate, {
    artifactSha256: candidate?.sha256,
    bundleIdentifier: current.bundleIdentifier,
    teamId: current.teamId
  });
  const incompatibleState = Boolean(candidate?.requiresStateVersion && current?.stateVersion && candidate.requiresStateVersion !== current.stateVersion);
  const reasons = [...validation.reasons];
  if (incompatibleState) reasons.push("state_version_incompatible");
  if (candidate?.revoked) reasons.push("rollback_artifact_revoked");
  return freeze({
    status: reasons.length === 0 ? "rollback_candidate_compatible" : "rollback_rejected",
    backupRequired: true,
    deleteIdentityByDefault: false,
    reasons
  });
}

function uninstallResidualDataModel(bundleIdentifier = BUNDLE_IDENTIFIER) {
  return freeze({
    uninstallModel: "philcore-desktop-uninstall-v1",
    deletingApplicationRemovesExecutable: true,
    deletingApplicationDeletesIdentity: false,
    identityDeletionRequiresSeparateFreshAuthentication: true,
    residualLocations: [
      `~/Library/Application Support/${bundleIdentifier}`,
      `~/Library/Preferences/${bundleIdentifier}.plist`,
      "~/Library/Caches/com.philcore.desktop.localalpha",
      "~/Library/Saved Application State/com.philcore.desktop.localalpha.savedState",
      "Keychain items created by PhilCore Desktop local identity and platform protection boundaries",
      "Local audit evidence and diagnostic exports saved by the tester"
    ],
    destructiveRemovalDefault: false
  });
}

function bundleIdentifierRecommendation() {
  return freeze({
    currentBundleIdentifier: BUNDLE_IDENTIFIER,
    stableCandidate: "com.philcore.desktop",
    recommendation: "retain_current_identifier_for_first_o10_trusted_tester_cohort",
    maximumScope: "first controlled trusted-tester release-candidate cohort only",
    mustRevisitBefore: "broader Beta distribution or any public-network-enabled build",
    rationale: [
      "The current O.9 artifact is already signed, notarized, stapled, and verified under the local-alpha identifier.",
      "Changing now would require a new signed and notarized artifact plus explicit operator approval.",
      "Local identity, preferences, Keychain service behavior, saved state, and tester migration need a planned transition."
    ],
    changeRisks: [
      "macOS treats a new bundle identifier as a distinct application identity.",
      "Preferences, Keychain access groups/service names, saved state, and data directories may not migrate automatically.",
      "Existing tester diagnostics and audit references would need explicit release mapping."
    ]
  });
}

function createDistributionDryRun(release = createReleaseRecord()) {
  return freeze({
    dryRunFormat: "philcore-trusted-tester-distribution-dry-run-v1",
    releaseIdentifier: release.releaseIdentifier,
    artifactSha256: release.artifactSha256,
    actualSendPerformed: false,
    publicUploadPerformed: false,
    namedTesterRequiredBeforeSend: true,
    operatorApprovalRequiredBeforeSend: true,
    steps: [
      "select approved tester",
      "record acknowledgement",
      "confirm release validity and expiration",
      "calculate checksum immediately before sending",
      "provide checksum and verifier instructions through a trusted channel",
      "record delivery only after actual transfer",
      "record tester verification, installation, first launch, and sanitized defects"
    ]
  });
}

function betaReadinessMatrix() {
  return freeze({
    matrixFormat: "philcore-desktop-o10-beta-readiness-v1",
    baseSepoliaBetaGate: "blocked",
    productionApproved: false,
    acp0002: "Proposed",
    items: {
      desktopPackageTrust: "demonstrated",
      nativeUserPresence: "locally_demonstrated",
      identityCreation: "locally_demonstrated",
      identityUnlock: "locally_demonstrated",
      deviceVault: "locally_demonstrated",
      trustManager: "locally_demonstrated",
      authorizationEngine: "locally_demonstrated",
      proofGenerationAndVerification: "locally_demonstrated",
      auditIntegrity: "locally_demonstrated",
      recovery: "fixture_demonstrated_only",
      ethereumNet: "not_approved",
      erc4337SmartAccountBehavior: "locally_demonstrated",
      publicNetworkMutationControls: "blocked",
      paymasterControls: "blocked",
      transactionSimulation: "locally_demonstrated",
      transactionAuthorization: "locally_demonstrated",
      baseSepoliaConfiguration: "blocked",
      externalAudit: "not_implemented",
      dependencyAdvisories: "blocked",
      releaseUpdateAndRollback: "fixture_demonstrated_only",
      privacy: "locally_demonstrated",
      diagnostics: "fixture_demonstrated_only",
      testerOperations: "fixture_demonstrated_only",
      incidentResponse: "fixture_demonstrated_only",
      productionCredentialHandling: "not_approved"
    }
  });
}

function summarizeReadiness(matrix = betaReadinessMatrix()) {
  const blocked = Object.entries(matrix.items).filter(([, state]) => !APPROVED_STATES.includes(state));
  return freeze({
    status: blocked.length === 0 ? "ready" : "blocked",
    blockedItems: blocked.map(([item, state]) => ({ item, state })),
    baseSepoliaBetaGate: matrix.baseSepoliaBetaGate,
    productionApproved: matrix.productionApproved
  });
}

module.exports = {
  ARTIFACT_SHA256,
  BUNDLE_IDENTIFIER,
  RELEASE_IDENTIFIER,
  betaReadinessMatrix,
  bundleIdentifierRecommendation,
  classifyDefectSeverity,
  createExternalTesterPendingSlot,
  createDefectIntakeRecord,
  createDistributionDryRun,
  createEmptyTrustedTesterCohort,
  createFirstLaunchEvidence,
  createNativeUserPresenceEvidence,
  createReleaseRecord,
  createReleaseRevocationRecord,
  createTesterCycleRecord,
  createTesterAcceptanceRecord,
  createTrustedTesterAcknowledgementTemplate,
  decideExternalTesterSuitability,
  evaluateExternalDistributionApprovalGate,
  evaluateRollbackCandidate,
  isReleaseExpired,
  releaseExpiration,
  sanitizeDiagnosticExport,
  sha256Text,
  summarizeReadiness,
  updateTesterCycleRecord,
  transitionTesterRecord,
  uninstallResidualDataModel,
  validateReplacementArtifact
};
