#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-fresh-auth-"));
const passphrase = "Fresh-auth-diagnostic-passphrase!1";
const host = createDesktopRuntimeHost({
  preferencesPath: path.join(root, "prefs.json"),
  identityStorageRoot: path.join(root, "identities"),
  platformKeyAdapter: createFixturePlatformKeyAdapter()
});

host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
  label: "Fresh Auth Diagnostic",
  passphrase,
  createRecoveryAuthority: true
});
host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase });
host.invoke(CHANNELS.UNLOCK_VAULT, {});
const enrollmentPresentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "platform_unlock_enrollment" });
const enrollmentApproval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
  presentationId: enrollmentPresentation.presentation.presentationId,
  decision: "approve"
});
host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
  passphrase,
  approvalArtifactId: enrollmentApproval.approvalArtifact.approvalArtifactId
});

const signingPresentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "user_operation_signing" });
const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
  purpose: "fresh_auth_diagnostic",
  presentationId: signingPresentation.presentation.presentationId,
  presentationDigest: signingPresentation.presentation.digest
});

process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_fresh_auth",
  status: fresh.status,
  method: fresh.evidence?.method,
  evidenceType: fresh.evidence?.evidenceType,
  presentationDigestBound: fresh.evidence?.presentationDigest === signingPresentation.presentation.digest,
  userPresenceGuaranteed: fresh.evidence?.userPresenceGuaranteed,
  keychainValueReturned: false,
  wrappingKeyReturned: false,
  includesSecrets: false,
  publicNetworkMutation: false
}, null, 2)}\n`);
