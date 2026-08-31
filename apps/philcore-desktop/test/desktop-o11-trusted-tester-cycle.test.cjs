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

test("Tester 001 cycle starts incomplete and binds the exact artifact hash", () => {
  const record = ops.createTesterCycleRecord({
    testerIdentifier: "tester-001-operator",
    acknowledgementAccepted: true,
    acceptedAt: "2026-07-17T21:00:00.000Z"
  });
  assert.equal(record.testerIdentifier, "tester-001-operator");
  assert.equal(record.artifactSha256, ops.ARTIFACT_SHA256);
  assert.equal(record.verificationResult, "not_started");
  assert.equal(record.completionState, "not_started");
  assert.equal(record.distributedToTesters, false);
});

test("Tester 001 cycle rejects action updates bound to another artifact", () => {
  const record = ops.createTesterCycleRecord({ testerIdentifier: "tester-001-operator" });
  assert.throws(() => ops.updateTesterCycleRecord(record, {
    artifactSha256: "different",
    verificationResult: "passed"
  }), /tester_cycle_artifact_hash_mismatch/);
});

test("Tester 001 state transitions keep distribution false and count defects", () => {
  const record = ops.createTesterCycleRecord({ testerIdentifier: "tester-001-operator" });
  const defect = ops.createDefectIntakeRecord({
    releaseIdentifier: ops.RELEASE_IDENTIFIER,
    artifactSha256: ops.ARTIFACT_SHA256,
    macOSVersion: "fixture",
    architecture: "arm64",
    expectedBehavior: "clear wording",
    observedBehavior: "minor wording confusion",
    reproductionSteps: "fixture"
  });
  const updated = ops.updateTesterCycleRecord(record, {
    verificationResult: "passed",
    installationResult: "passed",
    firstLaunchResult: "passed_with_low_issue",
    defects: [defect],
    completionState: "completed"
  });
  assert.equal(updated.issueCount, 1);
  assert.equal(updated.distributedToTesters, false);
  assert.equal(updated.completionState, "completed");
});

test("first-launch evidence records clarity without pretending production approval", () => {
  const evidence = ops.createFirstLaunchEvidence({
    launchedNormally: true,
    releaseStatusClear: true,
    alphaWarningClear: true,
    publicNetworkDisabledVisible: true,
    productionWarningClear: true,
    navigationUnderstandable: true
  });
  assert.equal(evidence.launchedNormally, true);
  assert.equal(evidence.publicNetworkDisabledVisible, true);
  assert.equal(evidence.developerTerminologyObserved, false);
  assert.equal(evidence.repositoryPathObserved, false);
});

test("native user-presence evidence is digest-bound and secret-free", () => {
  const evidence = ops.createNativeUserPresenceEvidence({
    provider: "macos_local_authentication_helper",
    outcome: "user_presence_verified",
    userPresenceVerified: true,
    visibleSystemPromptObserved: true,
    cancellationTested: true,
    expiredEvidenceRejected: true,
    replayRejected: true,
    actionMismatchRejected: true,
    sessionMismatchRejected: true
  });
  assert.equal(evidence.userPresenceVerified, true);
  assert.match(evidence.safeEvidenceDigest, /^[a-f0-9]{64}$/u);
  assert.equal(evidence.biometricDataCaptured, false);
  assert.equal(evidence.rawAuthenticationMaterialCaptured, false);
});

test("external tester slot is pending and no-send by default", () => {
  const slot = ops.createExternalTesterPendingSlot();
  assert.equal(slot.testerIdentifier, "tester-002-external-pending");
  assert.equal(slot.acknowledgementAccepted, false);
  assert.equal(slot.artifactDelivered, false);
  assert.equal(slot.checksumVerified, false);
  assert.equal(slot.installed, false);
  assert.equal(slot.distributedToTesters, false);
  assert.equal(slot.personIdentified, false);
});

test("external distribution approval gate is blocked by default", () => {
  const gate = ops.evaluateExternalDistributionApprovalGate({});
  assert.equal(gate.status, "blocked");
  assert.equal(gate.approved, false);
  assert.equal(gate.distributedToTesters, false);
  assert.equal(gate.usesAppleNotarizationApproval, false);
  assert.ok(gate.reasons.includes("operator_distribution_approval_missing"));
  assert.ok(gate.reasons.includes("external_acknowledgement_missing"));
});

test("external distribution approval gate requires the separate distribution-specific state", () => {
  const blocked = ops.evaluateExternalDistributionApprovalGate({
    stageACompleted: true,
    artifactSha256: ops.ARTIFACT_SHA256,
    unresolvedCriticalIssues: 0,
    unresolvedHighSecurityOrIdentityIssues: 0,
    tester001Completed: true,
    externalTesterAcknowledgementAccepted: true,
    releaseExpired: false,
    releaseRevoked: false,
    operatorDistributionApproval: false,
    namedTesterSupplied: true,
    approvedDeliveryMethodSupplied: true
  });
  assert.equal(blocked.approved, false);
  assert.ok(blocked.reasons.includes("operator_distribution_approval_missing"));
  const approved = ops.evaluateExternalDistributionApprovalGate({
    stageACompleted: true,
    artifactSha256: ops.ARTIFACT_SHA256,
    unresolvedCriticalIssues: 0,
    unresolvedHighSecurityOrIdentityIssues: 0,
    tester001Completed: true,
    externalTesterAcknowledgementAccepted: true,
    releaseExpired: false,
    releaseRevoked: false,
    operatorDistributionApproval: true,
    namedTesterSupplied: true,
    approvedDeliveryMethodSupplied: true
  });
  assert.equal(approved.status, "blocked");
  assert.ok(approved.reasons.includes("artifact_revoked"));
});

test("suitability decision blocks Critical and High defects before external tester", () => {
  assert.equal(ops.decideExternalTesterSuitability({
    stageACompleted: true,
    unresolvedCriticalIssues: 1
  }), "blocked_by_critical_defect");
  assert.equal(ops.decideExternalTesterSuitability({
    stageACompleted: true,
    unresolvedHighIssues: 1
  }), "blocked_by_high_defect");
  assert.equal(ops.decideExternalTesterSuitability({
    stageACompleted: true
  }), "blocked_by_revoked_artifact");
});

test("identity deletion remains distinct from application removal", () => {
  const model = ops.uninstallResidualDataModel();
  assert.equal(model.deletingApplicationDeletesIdentity, false);
  assert.equal(model.identityDeletionRequiresSeparateFreshAuthentication, true);
  assert.equal(model.destructiveRemovalDefault, false);
});
