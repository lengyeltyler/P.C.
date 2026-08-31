const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");
const {
  createHypotheticalWitnessHidingProofStack
} = require("./helpers/hypothetical-witness-hiding-proof-stack.cjs");

const PASSPHRASE = "real-Local-alpha-passphrase!1";

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function hostFor() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-real-local-"));
  return createDesktopRuntimeHost({
    preferencesPath: path.join(dir, "prefs.json"),
    identityStorageRoot: path.join(dir, "identities"),
    platformKeyAdapter: createFixturePlatformKeyAdapter(),
    testOnlyHypotheticalWitnessHidingProofStack: createHypotheticalWitnessHidingProofStack(),
    sessionTtlMs: 600_000
  });
}

function approve(host, kind, typedConfirmation = "") {
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind,
    confirmationTarget: typedConfirmation
  });
  assert.equal(created.status, "presentation_created");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve",
    typedConfirmation
  });
  assert.equal(approved.status, "approved");
  return approved;
}

function createUnlockEnroll(host) {
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Real Local",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const enrollment = approve(host, "platform_unlock_enrollment");
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
  return created.identity.identityId;
}

async function startWorkflow(host) {
  const approval = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    proofTimeoutMs: 120_000
  });
  assert.equal(started.status, "signing_approval_required", started.workflow?.error);
  return started.workflow;
}

async function completeWorkflow(host, workflow) {
  const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    workflowId: workflow.workflowId
  });
  assert.equal(fresh.status, "authenticated");
  const completed = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: workflow.workflowId,
    decision: "approve",
    presentationDigest: workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
  assert.equal(completed.status, "completed", completed.workflow?.error);
  return completed.workflow;
}

test("hypothetical witness-hiding fixture preserves signing and local execution lifecycle coverage", async () => {
  const host = hostFor();
  createUnlockEnroll(host);
  const prepared = await startWorkflow(host);
  assert.equal(
    prepared.evidenceLabels.starkProofGeneration,
    "hypothetical_witness_hiding_test_fixture"
  );
  assert.equal(prepared.evidenceLabels.localMirrorFixture, "local_fixture");
  assert.equal(prepared.evidenceLabels.starknetPublication, "not_executed");
  assert.match(prepared.proof.proofInputHash, /^0x[a-f0-9]{64}$/);
  assert.equal(prepared.proof.witnessExposed, false);
  assert.equal(prepared.privateState, undefined);

  const completed = await completeWorkflow(host, prepared);
  assert.equal(completed.execution.nullifierConsumed, true);
  assert.equal(completed.execution.consumerExecuted, true);
  assert.match(completed.execution.userOperationHash, /^0x[a-f0-9]{64}$/);
  assert.match(completed.execution.transactionHash, /^0x[a-f0-9]{64}$/);
  assert.equal(completed.publicNetworkMutation, false);
  assert.equal(completed.proofWitnessExposed, false);
  assert.equal(completed.privateKeyExposed, false);
  const serialized = JSON.stringify(completed);
  assert.equal(serialized.includes("phil_secret"), false);
  assert.equal(serialized.includes("nullifierSeed"), false);
  assert.equal(serialized.includes("privateKey\""), false);
  assert.equal(serialized.includes("wrappingKey"), false);
});

test("workflow rejects concurrent critical authorization while proof/signing is active", async () => {
  const host = hostFor();
  createUnlockEnroll(host);
  const prepared = await startWorkflow(host);
  const secondApproval = approve(host, "local_authorization_execution");
  const second = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: secondApproval.approvalArtifact.approvalArtifactId
  });
  assert.equal(second.status, "busy");
  assert.equal(second.workflow.workflowId, prepared.workflowId);
});

test("lock interruption clears private workflow state and invalidates signing approval", async () => {
  const host = hostFor();
  createUnlockEnroll(host);
  const prepared = await startWorkflow(host);
  const locked = host.invoke(CHANNELS.LOCK_SESSION, {});
  assert.equal(locked.session.lockState, "locked");
  const result = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: prepared.workflowId,
    decision: "approve",
    presentationDigest: prepared.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: "fresh_auth_missing"
  });
  assert.notEqual(result.status, "completed");
  assert.equal(result.workflow?.privateState, undefined);
});

test("local identity reset requires fresh auth or passphrase reauthentication", async () => {
  const host = hostFor();
  const identityId = createUnlockEnroll(host);
  host.invoke(CHANNELS.LOCK_SESSION, {});
  const confirmation = `RESET ${identityId}`;
  const approval = approve(host, "local_identity_reset", confirmation);
  const blocked = host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, {
    confirmation,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId
  });
  assert.equal(blocked.status, "approval_required");
  assert.equal(blocked.reason, "fresh_authentication_required");

  const reset = host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, {
    confirmation,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    passphrase: PASSPHRASE
  });
  assert.equal(reset.status, "reset");
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
