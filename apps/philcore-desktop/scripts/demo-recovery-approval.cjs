#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-recovery-approval-"));
const passphrase = "Recovery-approval-passphrase!1";
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
  label: "Recovery Approval Demo",
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
const recovery = approve("recovery_request", "request");
const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
  purpose: "recovery_request",
  presentationId: recovery.presentation.presentationId,
  presentationDigest: recovery.presentation.digest
});
const result = host.invoke(CHANNELS.RUN_RECOVERY_DEMO, {
  scenario: "request",
  approvalArtifactId: recovery.approval.approvalArtifactId,
  freshAuthenticationEvidenceId: fresh.evidence.evidenceId
});

process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_recovery_approval_demo",
  lockState: result.session?.lockState,
  recoveryDigest: recovery.presentation.digestShort,
  freshAuthMethod: fresh.evidence.method,
  localOnly: true,
  publicNetworkMutation: false,
  includesSecrets: false
}, null, 2)}\n`);
