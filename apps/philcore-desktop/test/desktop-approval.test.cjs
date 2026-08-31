const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS, validateBridgePayload } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");
const {
  createHypotheticalWitnessHidingProofStack
} = require("./helpers/hypothetical-witness-hiding-proof-stack.cjs");

const PASSPHRASE = "approval-Local-alpha-passphrase!1";

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function hostFor(dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-approval-")), adapter = createFixturePlatformKeyAdapter()) {
  return {
    dir,
    adapter,
    host: createDesktopRuntimeHost({
      preferencesPath: path.join(dir, "prefs.json"),
      identityStorageRoot: path.join(dir, "identities"),
      platformKeyAdapter: adapter,
      testOnlyHypotheticalWitnessHidingProofStack: createHypotheticalWitnessHidingProofStack(),
      sessionTtlMs: 60_000
    })
  };
}

function approve(host, kind, scenario = "", typedConfirmation = "") {
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind, scenario, confirmationTarget: typedConfirmation });
  assert.equal(presentation.status, "presentation_created");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation
  });
  assert.equal(approved.status, "approved");
  return { presentation: presentation.presentation, approval: approved.approvalArtifact };
}

function createUnlockEnroll(host) {
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Approval Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const enrollment = approve(host, "platform_unlock_enrollment");
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: enrollment.approval.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
  return created.identity.identityId;
}

function freshFor(host, presentation, purpose = "approval_test") {
  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose,
    presentationId: presentation.presentationId,
    presentationDigest: presentation.digest
  });
  assert.equal(fresh.status, "authenticated");
  assert.equal(fresh.evidence.wrappingKeyReturned, false);
  return fresh.evidence;
}

test("renderer cannot create arbitrary presentation digests or unsupported kinds", () => {
  assert.equal(validateBridgePayload(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind: "arbitrary_transfer",
    digest: "0x1234"
  }).ok, false);
});

test("presentations are Runtime generated, digest-bound, and sanitized", () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "local_authorization_execution" });
  assert.equal(created.status, "presentation_created");
  assert.match(created.presentation.digest, /^0x[a-f0-9]{64}$/);
  assert.equal(created.presentation.rendererMayModify, false);
  assert.equal(created.presentation.publicNetworkMutation, false);
  assert.equal(JSON.stringify(created).includes("privateKey"), false);
  assert.equal(JSON.stringify(created).includes("wrappingKey"), false);
});

test("deny and cancel cannot execute local authorization", async () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const deniedPresentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "local_authorization_execution" });
  const denied = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: deniedPresentation.presentation.presentationId,
    decision: "deny"
  });
  assert.equal(denied.status, "deny");
  assert.equal((await host.invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, {})).status, "approval_required");

  const cancelledPresentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "local_authorization_execution" });
  const cancelled = host.invoke(CHANNELS.CANCEL_APPROVAL, {
    presentationId: cancelledPresentation.presentation.presentationId
  });
  assert.equal(cancelled.status, "cancelled");
  assert.equal((await host.invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, {})).status, "approval_required");
});

test("approved digest mismatch, replay, and missing fresh auth are rejected", async () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const execution = approve(host, "local_authorization_execution");

  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approval.approvalArtifactId
  });
  assert.equal(started.status, "signing_approval_required", started.workflow?.error);
  let result = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: ""
  });
  assert.equal(result.status, "fresh_authentication_required");

  const wrongFresh = freshFor(host, execution.presentation, "wrong_digest");
  result = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: "0x" + "11".repeat(32),
    freshAuthenticationEvidenceId: wrongFresh.evidenceId
  });
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "presentation_digest_mismatch");
});

test("complete approved local authorization consumes approvals once", async () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const execution = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approval.approvalArtifactId
  });
  assert.equal(started.status, "signing_approval_required", started.workflow?.error);
  const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    workflowId: started.workflow.workflowId
  });
  assert.equal(fresh.status, "authenticated");
  const completed = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
  assert.equal(completed.status, "completed");
  assert.equal(completed.snapshot.ethereum.nullifierState, "consumed_local_fixture");

  const replay = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approval.approvalArtifactId,
  });
  assert.equal(replay.status, "approval_required");
});

test("lock and restart invalidate pending approval authority", () => {
  const setup = hostFor();
  const identityId = createUnlockEnroll(setup.host);
  const pending = setup.host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "local_authorization_execution" });
  assert.equal(pending.status, "presentation_created");
  setup.host.invoke(CHANNELS.LOCK_SESSION, {});
  assert.equal(setup.host.invoke(CHANNELS.GET_APPROVAL_PRESENTATION, {
    presentationId: pending.presentation.presentationId
  }).status, "not_found");

  const reopened = hostFor(setup.dir, setup.adapter);
  reopened.host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  assert.equal(reopened.host.invoke(CHANNELS.GET_APPROVAL_PRESENTATION, {
    presentationId: pending.presentation.presentationId
  }).status, "not_found");
});

test("approval from another identity or session is rejected", () => {
  const setup = hostFor();
  const firstIdentity = createUnlockEnroll(setup.host);
  const first = approve(setup.host, "local_authorization_execution");
  setup.host.invoke(CHANNELS.LOCK_SESSION, {});

  setup.host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Second",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  setup.host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  setup.host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const result = setup.host.invoke(CHANNELS.CONSUME_APPROVAL, {
    approvalArtifactId: first.approval.approvalArtifactId,
    kind: "local_authorization_execution",
    presentationDigest: first.presentation.digest
  });
  assert.equal(result.status, "failed");
  assert.equal(result.reason, "approval_not_found_or_consumed");
  assert.notEqual(setup.host.snapshot().identity.identityId, firstIdentity);
});

test("recovery approval requires exact presentation and fresh auth where required", () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const recovery = approve(host, "recovery_request", "request");
  let result = host.invoke(CHANNELS.RUN_RECOVERY_DEMO, {
    scenario: "request",
    approvalArtifactId: recovery.approval.approvalArtifactId
  });
  assert.equal(result.status, "approval_required");
  assert.equal(result.reason, "fresh_authentication_required");

  const recovery2 = approve(host, "recovery_request", "request");
  const fresh = freshFor(host, recovery2.presentation, "recovery_request");
  result = host.invoke(CHANNELS.RUN_RECOVERY_DEMO, {
    scenario: "request",
    approvalArtifactId: recovery2.approval.approvalArtifactId,
    freshAuthenticationEvidenceId: fresh.evidenceId
  });
  assert.equal(result.session.lockState, "unlocked");
});

test("platform disablement requires approval and fresh authentication", () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const blocked = host.invoke(CHANNELS.DISABLE_PLATFORM_AUTH, { passphrase: PASSPHRASE });
  assert.equal(blocked.status, "approval_required");
  const disablement = approve(host, "platform_unlock_disablement");
  const fresh = freshFor(host, disablement.presentation, "platform_unlock_disablement");
  const disabled = host.invoke(CHANNELS.DISABLE_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: disablement.approval.approvalArtifactId,
    freshAuthenticationEvidenceId: fresh.evidenceId
  });
  assert.equal(disabled.status, "disabled");
});

test("local identity reset requires digest-bound typed confirmation", () => {
  const { host } = hostFor();
  const identityId = createUnlockEnroll(host);
  host.invoke(CHANNELS.LOCK_SESSION, {});
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  const confirmation = `RESET ${identityId}`;
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind: "local_identity_reset",
    confirmationTarget: confirmation
  });
  assert.equal(presentation.status, "presentation_created");
  assert.equal(host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation: "wrong"
  }).status, "failed");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation: confirmation
  });
  const reset = host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, {
    confirmation,
    approvalArtifactId: approved.approvalArtifact.approvalArtifactId,
    passphrase: PASSPHRASE
  });
  assert.equal(reset.status, "reset");
  assert.equal(reset.snapshot.localIdentities.some((entry) => entry.identityId === identityId), false);
});

process.nextTick(async () => {
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`ok - ${name}`);
    } catch (error) {
      console.error(`not ok - ${name}`);
      console.error(error);
      process.exitCode = 1;
    }
  }
});
