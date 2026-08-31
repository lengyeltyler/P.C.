#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const PASSPHRASE = "Local-alpha-real-authorization!1";

function approve(host, kind) {
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind });
  if (created.status !== "presentation_created") throw new Error(created.reason || `approval ${kind} not created`);
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve"
  });
  if (approved.status !== "approved") throw new Error(approved.reason || `approval ${kind} not approved`);
  return approved;
}

async function run() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-real-local-demo-"));
  const host = createDesktopRuntimeHost({
    preferencesPath: path.join(dir, "prefs.json"),
    identityStorageRoot: path.join(dir, "identities"),
    platformKeyAdapter: createFixturePlatformKeyAdapter(),
    sessionTtlMs: 600_000
  });
  host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Real Local Demo",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const enrollment = approve(host, "platform_unlock_enrollment");
  host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
  });
  const execution = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approvalArtifact.approvalArtifactId,
    proofTimeoutMs: 120_000
  });
  if (started.status !== "signing_approval_required") throw new Error(started.workflow?.error || started.reason);
  const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    workflowId: started.workflow.workflowId
  });
  if (fresh.status !== "authenticated") throw new Error(fresh.reason || "fresh auth failed");
  const completed = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
  if (completed.status !== "completed") throw new Error(completed.workflow?.error || completed.reason);
  const workflow = completed.workflow;
  console.log(JSON.stringify({
    status: completed.status,
    workflowId: workflow.workflowId,
    proof: workflow.proof,
    execution: workflow.execution,
    timings: workflow.timings,
    evidenceLabels: workflow.evidenceLabels,
    includesSecrets: false,
    publicNetworkMutation: false
  }, null, 2));
}

run().catch((error) => {
  console.error(JSON.stringify({ status: "failed", reason: error.message, includesSecrets: false }, null, 2));
  process.exit(1);
});
