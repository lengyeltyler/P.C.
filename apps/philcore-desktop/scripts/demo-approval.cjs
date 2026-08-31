#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-approval-demo-"));
const passphrase = "Approval-demo-passphrase!1";
const host = createDesktopRuntimeHost({
  preferencesPath: path.join(root, "prefs.json"),
  identityStorageRoot: path.join(root, "identities"),
  platformKeyAdapter: createFixturePlatformKeyAdapter()
});

function approve(kind, scenario = "") {
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind, scenario });
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve"
  });
  return { presentation: presentation.presentation, approval: approved.approvalArtifact };
}

host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
  label: "Approval Demo",
  passphrase,
  createRecoveryAuthority: true
});
host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase });
host.invoke(CHANNELS.UNLOCK_VAULT, {});
const enrollment = approve("platform_unlock_enrollment");
host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
  passphrase,
  approvalArtifactId: enrollment.approval.approvalArtifactId
});
const execution = approve("local_authorization_execution");
const signingPresentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "user_operation_signing" });
const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
  purpose: "approval_demo_signing",
  presentationId: signingPresentation.presentation.presentationId,
  presentationDigest: signingPresentation.presentation.digest
});
const signing = host.invoke(CHANNELS.RESPOND_APPROVAL, {
  presentationId: signingPresentation.presentation.presentationId,
  decision: "approve"
});
const demo = host.invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, {
  approvalArtifactId: execution.approval.approvalArtifactId,
  signingApprovalArtifactId: signing.approvalArtifact.approvalArtifactId,
  freshAuthenticationEvidenceId: fresh.evidence.evidenceId
});

process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_approval_demo",
  status: demo.status,
  executionDigest: execution.presentation.digestShort,
  signingDigest: signingPresentation.presentation.digestShort,
  freshAuthMethod: fresh.evidence.method,
  stages: demo.stages?.length,
  localOnly: true,
  publicNetworkMutation: false,
  includesSecrets: false
}, null, 2)}\n`);
