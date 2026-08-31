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
  createFixtureMacOsUserPresenceProvider,
  createMacOsLocalAuthenticationProvider,
  validateRequest
} = require("../src/main/macos-user-presence.cjs");
const {
  createHypotheticalWitnessHidingProofStack
} = require("./helpers/hypothetical-witness-hiding-proof-stack.cjs");

const PASSPHRASE = "Native-presence-passphrase!1";

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function hostFor(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-user-presence-"));
  return {
    dir,
    presence: options.userPresenceProvider || createFixtureMacOsUserPresenceProvider(options.presenceOptions),
    host: createDesktopRuntimeHost({
      preferencesPath: path.join(dir, "prefs.json"),
      identityStorageRoot: path.join(dir, "identities"),
      platformKeyAdapter: createFixturePlatformKeyAdapter(),
      userPresenceProvider: options.userPresenceProvider || createFixtureMacOsUserPresenceProvider(options.presenceOptions),
      requireNativeUserPresence: Boolean(options.requireNativeUserPresence),
      testOnlyHypotheticalWitnessHidingProofStack: createHypotheticalWitnessHidingProofStack(),
      sessionTtlMs: 60_000
    })
  };
}

function createUnlockEnroll(host) {
  host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Presence Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "platform_unlock_enrollment" });
  const approval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve"
  });
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
}

function approve(host, kind) {
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind });
  assert.equal(presentation.status, "presentation_created");
  const approval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve"
  });
  assert.equal(approval.status, "approved");
  return { presentation: presentation.presentation, approval: approval.approvalArtifact };
}

test("user-presence request schema is narrow", () => {
  assert.equal(validateRequest({ policy: "device_owner_authentication", presentationDigest: `0x${"11".repeat(32)}` }).ok, true);
  assert.equal(validateRequest({ policy: "arbitrary_keychain_access" }).ok, false);
  assert.equal(validateRequest({ policy: "device_owner_authentication", presentationDigest: "0x1234" }).ok, false);
});

test("native helper provider rejects modified helper hash", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-helper-"));
  const helper = path.join(dir, "helper");
  fs.writeFileSync(helper, "#!/bin/sh\nprintf '%s\\n' '{\"version\":1,\"status\":\"user_presence_verified\",\"outcome\":\"user_presence_verified\",\"evidenceClass\":\"device_owner_authentication_verified\",\"provider\":\"macos_local_authentication_helper\",\"policy\":\"device_owner_authentication\",\"biometricDataReturned\":false,\"rawAuthenticationMaterialReturned\":false}'\n");
  fs.chmodSync(helper, 0o755);
  const provider = createMacOsLocalAuthenticationProvider({
    helperPath: helper,
    expectedSha256: "0".repeat(64),
    platform: "darwin"
  });
  assert.equal(provider.getAvailability().status, "helper_integrity_mismatch");
  assert.equal(provider.requestUserPresence({ policy: "device_owner_authentication" }).userPresenceVerified, false);
});

test("fresh authentication records macOS user-presence evidence when provider is available", () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const action = approve(host, "user_operation_signing");
  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose: "user_operation_signing",
    presentationId: action.presentation.presentationId,
    presentationDigest: action.presentation.digest
  });
  assert.equal(fresh.status, "authenticated");
  assert.equal(fresh.evidence.method, "device_owner_authentication_verified");
  assert.equal(fresh.evidence.evidenceType, "macos_local_authentication_user_presence_without_secret");
  assert.equal(fresh.evidence.presentationDigest, action.presentation.digest);
  assert.equal(fresh.evidence.userPresenceGuaranteed, true);
  assert.equal(JSON.stringify(fresh).includes("biometric"), true);
  assert.equal(fresh.evidence.wrappingKeyReturned, false);
});

test("release-candidate mode rejects safeStorage-only fresh authentication", () => {
  const unavailable = Object.freeze({
    getAvailability: () => ({ available: false, status: "helper_missing", provider: "none", reason: "helper_missing" }),
    requestUserPresence: () => ({ userPresenceVerified: false, status: "helper_missing", outcome: "helper_missing" })
  });
  const { host } = hostFor({ userPresenceProvider: unavailable, requireNativeUserPresence: true });
  createUnlockEnroll(host);
  const action = approve(host, "user_operation_signing");
  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose: "user_operation_signing",
    presentationId: action.presentation.presentationId,
    presentationDigest: action.presentation.digest
  });
  assert.equal(fresh.status, "failed");
  assert.equal(fresh.reason, "native_user_presence_required");
});

test("user-presence cancellation prevents local signing completion", async () => {
  const provider = createFixtureMacOsUserPresenceProvider();
  const { host } = hostFor({ userPresenceProvider: provider });
  createUnlockEnroll(host);
  const execution = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approval.approvalArtifactId
  });
  assert.equal(started.status, "signing_approval_required");
  provider.setNextOutcome("user_cancelled");
  const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    workflowId: started.workflow.workflowId
  });
  assert.equal(fresh.status, "cancelled");
  assert.equal(fresh.reason, "user_cancelled");
  const completed = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: ""
  });
  assert.notEqual(completed.status, "completed");
  assert.equal(host.snapshot().demo.status, "cancelled");
});

test("evidence from another presentation is rejected", async () => {
  const { host } = hostFor();
  createUnlockEnroll(host);
  const execution = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approval.approvalArtifactId
  });
  const other = approve(host, "user_operation_signing");
  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose: "wrong_presentation",
    presentationId: other.presentation.presentationId,
    presentationDigest: other.presentation.digest
  });
  const result = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
  assert.equal(result.status, "failed");
});

(async () => {
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
})();
