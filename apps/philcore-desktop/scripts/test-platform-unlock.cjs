#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-platform-unlock-"));
const passphrase = "Platform-unlock-diagnostic-passphrase!1";
const adapter = createFixturePlatformKeyAdapter();

function hostFor() {
  return createDesktopRuntimeHost({
    preferencesPath: path.join(root, "philcore-desktop-preferences.json"),
    identityStorageRoot: path.join(root, "philcore-local-identities"),
    platformKeyAdapter: adapter
  });
}

let host = hostFor();
const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
  label: "Platform Unlock Diagnostic",
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
const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
  passphrase,
  approvalArtifactId: enrollmentApproval.approvalArtifact.approvalArtifactId
});
host.invoke(CHANNELS.LOCK_SESSION, {});

host = hostFor();
host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId: created.identity.identityId });
const unlocked = host.invoke(CHANNELS.PLATFORM_UNLOCK, {});
const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, { purpose: "local_signing_presentation" });
host.invoke(CHANNELS.LOCK_SESSION, {});

process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_platform_unlock_fixture",
  localOnly: true,
  publicNetworkMutation: false,
  enrolled: enrolled.status,
  platformUnlock: unlocked.status,
  freshAuthentication: fresh.status,
  sameOwnerCommitment: created.identity.ownerCommitment === unlocked.snapshot.identity.ownerCommitment,
  includesSecrets: false,
  keychainValueReturned: false,
  wrappingKeyReturned: false
}, null, 2)}\n`);
