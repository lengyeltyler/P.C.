const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS, containsForbiddenKey } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter,
  createUnsupportedPlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const PASSPHRASE = "platform-Local-alpha-passphrase!1";

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

function hostFor(dir, adapter = createFixturePlatformKeyAdapter()) {
  return {
    adapter,
    host: createDesktopRuntimeHost({
      preferencesPath: path.join(dir, "prefs.json"),
      identityStorageRoot: path.join(dir, "identities"),
      platformKeyAdapter: adapter,
      sessionTtlMs: 60_000
    })
  };
}

function createUnlockEnroll(host) {
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Platform Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "platform_unlock_enrollment" });
  assert.equal(presentation.status, "presentation_created");
  const approval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve"
  });
  assert.equal(approval.status, "approved");
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
  return created.identity.identityId;
}

test("platform availability and unsupported platform are explicit", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-platform-auth-"));
  let setup = hostFor(dir);
  assert.equal(setup.host.invoke(CHANNELS.GET_PLATFORM_AUTH_AVAILABILITY, {}).available, true);

  setup = hostFor(dir, createUnsupportedPlatformKeyAdapter("linux"));
  const unavailable = setup.host.invoke(CHANNELS.GET_PLATFORM_AUTH_AVAILABILITY, {});
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.status, "unsupported_platform");
});

test("enrollment migrates to platform protection and preserves explicit passphrase fallback", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-platform-enroll-"));
  const { host } = hostFor(dir);
  const identityId = createUnlockEnroll(host);
  const snapshot = host.snapshot();
  assert.equal(snapshot.platformAuth.status, "enabled");
  assert.equal(snapshot.platformAuth.passphraseFallbackAllowed, true);
  assert.equal(snapshot.platformAuth.keychainReferenceExposed, false);
  assert.equal(JSON.stringify(snapshot).includes("wrappingKey"), false);

  host.invoke(CHANNELS.LOCK_SESSION, {});
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  const fallback = host.invoke(CHANNELS.UNLOCK_VAULT, {});
  assert.equal(fallback.status, "unlocked");
  assert.equal(fallback.snapshot.identity.identityId, identityId);
});

test("platform unlock works after restart and creates fresh-auth evidence", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-platform-restart-"));
  const adapter = createFixturePlatformKeyAdapter();
  let setup = hostFor(dir, adapter);
  const identityId = createUnlockEnroll(setup.host);
  const ownerCommitment = setup.host.snapshot().identity.ownerCommitment;
  setup.host.invoke(CHANNELS.LOCK_SESSION, {});

  setup = hostFor(dir, adapter);
  setup.host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  const unlocked = setup.host.invoke(CHANNELS.PLATFORM_UNLOCK, {});
  assert.equal(unlocked.status, "unlocked");
  assert.equal(unlocked.snapshot.identity.ownerCommitment, ownerCommitment);
  assert.equal(unlocked.snapshot.session.authentication, "platform_keychain");
  const fresh = setup.host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, { purpose: "local_signing_presentation" });
  assert.equal(fresh.status, "authenticated");
  assert.equal(fresh.evidence.wrappingKeyReturned, false);
});

test("platform cancellation, denial, missing, and corrupted key leave vault locked", () => {
  for (const outcome of ["platform_authentication_cancelled", "keychain_access_denied", "keychain_item_missing", "wrapping_key_invalid"]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-platform-${outcome}-`));
    const adapter = createFixturePlatformKeyAdapter();
    const { host } = hostFor(dir, adapter);
    const identityId = createUnlockEnroll(host);
    host.invoke(CHANNELS.LOCK_SESSION, {});
    host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
    adapter.setNextReadOutcome(outcome);
    const result = host.invoke(CHANNELS.PLATFORM_UNLOCK, {});
    assert.equal(result.status, "failed");
    assert.equal(result.snapshot.session.lockState, "locked");
    assert.equal(result.snapshot.vault.status, "locked");
  }
});

test("disablement restores passphrase-only access and does not strand the identity", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-platform-disable-"));
  const adapter = createFixturePlatformKeyAdapter();
  const { host } = hostFor(dir, adapter);
  const identityId = createUnlockEnroll(host);
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "platform_unlock_disablement" });
  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose: "platform_unlock_disablement",
    presentationId: presentation.presentation.presentationId,
    presentationDigest: presentation.presentation.digest
  });
  const approval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve"
  });
  const disabled = host.invoke(CHANNELS.DISABLE_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
  assert.equal(disabled.status, "disabled");
  assert.equal(disabled.snapshot.platformAuth.status, "not_enrolled");
  host.invoke(CHANNELS.LOCK_SESSION, {});
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  const platform = host.invoke(CHANNELS.PLATFORM_UNLOCK, {});
  assert.equal(platform.status, "failed");
  assert.equal(platform.reason, "migration_required");
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  assert.equal(host.invoke(CHANNELS.UNLOCK_VAULT, {}).status, "unlocked");
});

test("bridge rejects arbitrary keychain names and secret-shaped payloads", () => {
  assert.equal(containsForbiddenKey({ wrappingKey: "nope" }), true);
  assert.equal(containsForbiddenKey({ service: "caller-selected-service" }), false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-platform-bridge-"));
  const { host } = hostFor(dir);
  const malformed = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, "bad");
  assert.equal(malformed.status, "failed");
});
