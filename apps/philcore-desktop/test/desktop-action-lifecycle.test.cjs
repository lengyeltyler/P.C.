const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const { createDesktopRuntimeHost, createFixturePlatformKeyAdapter } = require("../src/main/runtime-host.cjs");
const { createFixtureMacOsUserPresenceProvider } = require("../src/main/macos-user-presence.cjs");
const {
  createHypotheticalWitnessHidingProofStack
} = require("./helpers/hypothetical-witness-hiding-proof-stack.cjs");

const PASSPHRASE = "Action-lifecycle-passphrase!1";
const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function fixture(
  root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-action-lifecycle-")),
  useHypotheticalProofStack = true
) {
  const presence = createFixtureMacOsUserPresenceProvider();
  const options = {
    preferencesPath: path.join(root, "preferences.json"),
    identityStorageRoot: path.join(root, "identities"),
    platformKeyAdapter: createFixturePlatformKeyAdapter({ masterKey: "action-lifecycle-fixture-key" }),
    userPresenceProvider: presence,
    sessionTtlMs: 600_000,
    ...(useHypotheticalProofStack ? {
      testOnlyHypotheticalWitnessHidingProofStack: createHypotheticalWitnessHidingProofStack()
    } : {})
  };
  return { root, options, presence, host: createDesktopRuntimeHost(options) };
}

function approve(host, kind) {
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind });
  return host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve"
  });
}

function createUnlock(host, enroll = true) {
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Action Lifecycle",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  if (enroll) {
    const approval = approve(host, "platform_unlock_enrollment");
    const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
      passphrase: PASSPHRASE,
      approvalArtifactId: approval.approvalArtifact.approvalArtifactId
    });
    assert.equal(enrolled.status, "enrolled");
  }
  return created.identity.identityId;
}

async function start(host) {
  const approval = approve(host, "local_authorization_execution");
  const result = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    proofTimeoutMs: 120_000
  });
  assert.equal(
    result.status,
    "signing_approval_required",
    `expected status "signing_approval_required" but got "${result.status}"` +
      (result.workflow?.error ? `: ${result.workflow.error}` : "")
  );
  return result.workflow;
}

test("missing protected Mac unlock is blocked by preflight before workflow creation", () => {
  const { host } = fixture();
  createUnlock(host, false);
  const result = host.invoke(CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {});
  assert.equal(result.status, "blocked");
  assert.equal(result.reason, "platform_unlock_not_enrolled");
  assert.equal(result.preflight.ready, false);
  assert.equal(result.snapshot.demo.status, "not_started");
  assert.equal(result.snapshot.protectedAction.eligible, true);
  assert.equal(result.snapshot.audit.recent.filter((event) => event.action === "protected_action_preflight").length, 1);
});

test("default proof stack fails closed before signing because current artifacts are secret-bearing", async () => {
  const { host } = fixture(undefined, false);
  createUnlock(host, true);
  const approval = approve(host, "local_authorization_execution");
  const result = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    proofTimeoutMs: 120_000
  });
  assert.equal(result.status, "failed");
  assert.match(result.workflow.error, /secret-bearing proof research|experimental secret-bearing proof gate/u);
  const proofStage = result.workflow.stages.find((stage) => stage.id === "proof_generating");
  assert.equal(proofStage.status, "failed");
  assert.equal(proofStage.details.terminalReason, "proof_privacy_quarantine");
  assert.equal(result.workflow.stages.some((stage) => stage.status === "running"), false);
  assert.equal(result.workflow.pendingSigningPresentation, undefined);
  assert.equal(result.workflow.publicNetworkMutation, false);
});

test("fresh-auth terminal failure clears active workflow and permits retry", async () => {
  const { host } = fixture();
  const identityId = createUnlock(host, true);
  const workflow = await start(host);
  fs.rmSync(path.join(host._storageRoot, identityId, "platform-protection.json"), { force: true });
  const failed = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, { workflowId: workflow.workflowId });
  assert.equal(failed.status, "failed");
  assert.equal(failed.reason, "platform_unlock_not_enrolled");
  assert.equal(failed.workflow.status, "failed");
  assert.equal(failed.workflow.pendingSigningPresentation, undefined);
  assert.equal(failed.snapshot.protectedAction.reason, "platform_unlock_not_enrolled");
  assert.equal(failed.snapshot.audit.recent.filter((event) => event.action === "fresh_authentication_stopped").length, 1);
});

test("user cancellation and helper timeout are distinct terminal states", async () => {
  for (const [outcome, expected] of [["user_cancelled", "cancelled"], ["helper_timeout", "timed_out"]]) {
    const { host, presence } = fixture();
    createUnlock(host, true);
    const workflow = await start(host);
    presence.setNextOutcome(outcome);
    const result = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, { workflowId: workflow.workflowId });
    assert.equal(result.status, expected);
    assert.equal(result.workflow.status, expected);
    assert.equal(result.workflow.pendingSigningPresentation, undefined);
  }
});

test("late approval cannot complete a cancelled workflow", async () => {
  const { host } = fixture();
  createUnlock(host, true);
  const workflow = await start(host);
  const cancelled = host.invoke(CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    workflowId: workflow.workflowId,
    terminalStatus: "cancelled",
    reason: "user_cancelled"
  });
  assert.equal(cancelled.status, "cancelled");
  const late = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: workflow.workflowId,
    decision: "approve",
    presentationDigest: workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: "fresh_auth_late"
  });
  assert.notEqual(late.status, "completed");
  assert.equal(host.snapshot().demo.status, "cancelled");
  assert.equal(host.snapshot().audit.recent.filter((event) => event.action === "real_local_workflow_cancelled").length, 1);
});

test("cancellation during proof preparation blocks duplicate work and wins over the late result", async () => {
  const { host } = fixture();
  createUnlock(host, true);
  const approval = approve(host, "local_authorization_execution");
  const clientActionId = "desktop_action_cancel_during_proof";
  const pending = host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    clientActionId,
    proofTimeoutMs: 120_000
  });
  const busy = host.invoke(CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {});
  assert.equal(busy.status, "blocked");
  assert.equal(busy.reason, "protected_action_already_active");
  const cancelled = host.invoke(CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    workflowId: clientActionId,
    terminalStatus: "cancelled",
    reason: "user_cancelled_during_proof"
  });
  assert.equal(cancelled.status, "cancelled");
  const late = await pending;
  assert.equal(late.status, "cancelled");
  assert.equal(host.snapshot().demo.status, "cancelled");
});

test("restart reconciles a persisted in-progress action exactly once", async () => {
  const first = fixture();
  createUnlock(first.host, true);
  await start(first.host);
  const second = createDesktopRuntimeHost(first.options);
  const interrupted = second.snapshot().audit.recent.filter((event) => event.action === "protected_action_interrupted");
  assert.equal(interrupted.length, 1);
  assert.equal(interrupted[0].result, "interrupted");
  assert.equal(fs.existsSync(path.join(first.host._storageRoot, "active-protected-action.json")), false);
});

process.nextTick(async () => {
  for (const item of tests) {
    try {
      await item.fn();
      console.log(`ok - ${item.name}`);
    } catch (error) {
      console.error(`not ok - ${item.name}`);
      console.error(error);
      process.exitCode = 1;
      break;
    }
  }
});
