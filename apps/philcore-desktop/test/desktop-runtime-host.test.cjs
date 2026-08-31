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

const PASSPHRASE = "Local-alpha-passphrase!1";

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function newHost(dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-test-"))) {
  return {
    dir,
    host: createDesktopRuntimeHost({
      preferencesPath: path.join(dir, "prefs.json"),
      identityStorageRoot: path.join(dir, "identities"),
      platformKeyAdapter: createFixturePlatformKeyAdapter(),
      testOnlyHypotheticalWitnessHidingProofStack: createHypotheticalWitnessHidingProofStack(),
      sessionTtlMs: 60_000
    })
  };
}

function createAndUnlock(host, createRecoveryAuthority = true) {
  let snapshot = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority
  });
  const identityId = snapshot.identity.identityId;
  snapshot = host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE }).snapshot;
  snapshot = host.invoke(CHANNELS.UNLOCK_VAULT, {}).snapshot;
  return { snapshot, identityId };
}

function approve(host, kind, scenario = "", typedConfirmation = "") {
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind, scenario, confirmationTarget: typedConfirmation });
  assert.equal(created.status, "presentation_created");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve",
    typedConfirmation
  });
  assert.equal(approved.status, "approved");
  return approved;
}

async function runApprovedDemo(host) {
  if (!host.snapshot().platformAuth.enabled) {
    const enrollment = approve(host, "platform_unlock_enrollment");
    const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
      passphrase: PASSPHRASE,
      approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
    });
    assert.equal(enrolled.status, "enrolled");
  }
  const execution = approve(host, "local_authorization_execution");
  const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approvalArtifact.approvalArtifactId
  });
  assert.equal(started.status, "signing_approval_required", started.workflow?.error);
  const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    purpose: "local_user_operation_signing",
    workflowId: started.workflow.workflowId
  });
  assert.equal(fresh.status, "authenticated");
  return host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
}

test("durable local identity and vault unlock stay local-only", () => {
  const { host } = newHost();
  let snapshot = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  assert.equal(snapshot.identity.localIdentityState, "locked");
  assert.equal(snapshot.app.publicNetworkMutationEnabled, false);
  assert.equal(snapshot.vault.status, "locked");
  assert.equal(JSON.stringify(snapshot).includes("phil_secret"), false);

  snapshot = host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE }).snapshot;
  assert.equal(snapshot.session.lockState, "partially_unlocked");
  snapshot = host.invoke(CHANNELS.UNLOCK_VAULT, {}).snapshot;
  assert.equal(snapshot.session.lockState, "unlocked");
  assert.equal(snapshot.session.authentication, "local_alpha_passphrase_scrypt_verified");
  assert.equal(snapshot.vault.handleExposedToRenderer, false);
  assert.equal(snapshot.protectedAction.eligible, true);
  assert.equal(snapshot.protectedAction.publicNetworkMutation, false);
});

test("local Phil preview persists as decorative public metadata", () => {
  const setup = newHost();
  const preview = {
    selectionId: "local-philenator-05",
    sequence: 5,
    traits: {
      bgColor: "bgColor-12345678",
      bgNebula: "bgNebula-12345678",
      bgStars: "bgStars-12345678",
      bgSpiral: "bgSpiral-12345678",
      bgDust: "bgDust-12345678",
      bgOverlay: "bgOverlay-12345678",
      bodyBase: "bodyBase-12345678",
      body: "body-12345678",
      spikes: "spikes-12345678",
      teeth: "teeth-12345678",
      jawNose: "jawNose-12345678",
      eyes: "eyes-12345678",
      top: "top-12345678"
    },
    source: "philenator-local",
    artworkSource: "philenator-local",
    generatorRevision: "f174dedda16a354c592e3252d9b0b5805bab59c4",
    mintStatus: "not-minted",
    publicToken: null
  };
  const created = setup.host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Preview",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true,
    philPreview: preview
  });
  assert.deepEqual(created.identity.philPreview, preview);
  assert.deepEqual(created.localIdentities[0].philPreview, preview);

  const restarted = newHost(setup.dir).host.snapshot();
  assert.deepEqual(restarted.localIdentities[0].philPreview, preview);
  assert.equal(restarted.localIdentities[0].philPreview.publicToken, null);
  assert.equal(restarted.app.publicNetworkMutationEnabled, false);
});

test("normal protected action eligibility is projected by the runtime host", () => {
  const { host } = newHost();
  let snapshot = host.snapshot();
  assert.equal(snapshot.protectedAction.eligible, false);
  assert.equal(snapshot.protectedAction.reason, "no_identity");

  snapshot = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Eligibility",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  assert.equal(snapshot.protectedAction.eligible, false);
  assert.equal(snapshot.protectedAction.reason, "identity_locked");

  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  snapshot = host.invoke(CHANNELS.UNLOCK_VAULT, {}).snapshot;
  assert.equal(snapshot.protectedAction.eligible, true);
  assert.equal(snapshot.protectedAction.canonicalOperation, "startRealLocalAuthorizationWorkflow");
});

test("local authorization demo requires unlocked real local session", async () => {
  const { host, dir } = newHost();
  assert.equal((await host.invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, {})).status, "blocked");
  createAndUnlock(host);
  assert.equal((await host.invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, {})).status, "approval_required");
  const result = await runApprovedDemo(host);
  assert.equal(result.status, "completed");
  assert.equal(result.workflow.stages.some((item) => item.id === "proof_generated"), true);
  assert.equal(result.snapshot.proof.witnessExposed, false);
  assert.equal(result.snapshot.ethereum.nullifierState, "consumed_local_fixture");
  assert.equal(result.snapshot.app.publicNetworkMutationEnabled, false);
  assert.equal(result.snapshot.audit.recent.some((event) => event.action === "protected_action_requested"), true);
  assert.equal(result.snapshot.audit.recent.some((event) => event.action === "local_security_proof_verified"), true);
  assert.equal(result.snapshot.audit.recent.some((event) => event.action === "local_ethereum_test_action_completed"), true);
  const ledgerPath = path.join(dir, "identities", "local-nullifier-ledger.json");
  const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
  assert.equal(ledger.format, "philcore-local-nullifier-ledger");
  assert.equal(ledger.entries.length, 1);
  assert.equal(ledger.entries[0].state, "consumed");
  assert.equal(ledger.entries[0].nullifier, result.workflow.execution.nullifier);
  if (process.platform !== "win32") assert.equal(fs.statSync(ledgerPath).mode & 0o777, 0o600);
  newHost(dir);
  assert.deepEqual(JSON.parse(fs.readFileSync(ledgerPath, "utf8")), ledger);
});

test("settings persistence is non-secret preference only", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-test-"));
  const preferencesPath = path.join(dir, "prefs.json");
  const host = createDesktopRuntimeHost({
    preferencesPath,
    identityStorageRoot: path.join(dir, "identities")
  });
  host.invoke(CHANNELS.UPDATE_SETTINGS, {
    sessionTimeoutMinutes: 20,
    auditDetailLevel: "developer",
    introCompleted: true,
    presentationMode: "technical"
  });
  const saved = JSON.parse(fs.readFileSync(preferencesPath, "utf8"));
  assert.equal(saved.sessionTimeoutMinutes, 20);
  assert.equal(saved.auditDetailLevel, "developer");
  assert.equal(saved.introCompleted, true);
  assert.equal(saved.presentationMode, "technical");
  assert.equal(Object.keys(saved).some((key) => key.toLowerCase().includes("secret")), false);
});

test("identity display name changes without changing cryptographic identity", () => {
  const setup = newHost();
  const created = setup.host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "My Phil",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  const before = created.identity;
  assert.equal(before.label, "My Phil");
  const protectedFiles = fs.readdirSync(path.join(setup.dir, "identities", before.identityId))
    .filter((name) => name.endsWith(".encrypted.json"));
  assert.ok(protectedFiles.length >= 3);
  const protectedBytes = protectedFiles.map((name) => fs.readFileSync(path.join(setup.dir, "identities", before.identityId, name)));
  const renamed = setup.host.invoke(CHANNELS.RENAME_LOCAL_IDENTITY, { label: "Personal Phil" });
  assert.equal(renamed.status, "renamed");
  assert.equal(renamed.identity.label, "Personal Phil");
  assert.equal(renamed.identity.identityId, before.identityId);
  assert.equal(renamed.identity.ownerCommitment, before.ownerCommitment);
  protectedFiles.forEach((name, index) => assert.deepEqual(
    fs.readFileSync(path.join(setup.dir, "identities", before.identityId, name)), protectedBytes[index]
  ));
  assert.equal(renamed.snapshot.ethereum.executionOwnerAddress, created.ethereum.executionOwnerAddress);
  assert.equal(renamed.snapshot.ethereum.smartAccountAddress, created.ethereum.smartAccountAddress);

  const restarted = newHost(setup.dir);
  const reopened = restarted.host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId: before.identityId });
  assert.equal(reopened.identity.label, "Personal Phil");
  assert.equal(reopened.identity.ownerCommitment, before.ownerCommitment);
  assert.equal(reopened.audit.history.some((event) => event.action === "rename_local_identity"), false);
});

test("validator and recovery authority public views are durable and sanitized", () => {
  const { host } = newHost();
  const { snapshot } = createAndUnlock(host, true);
  assert.equal(snapshot.ethereum.validator.status, "available");
  assert.match(snapshot.ethereum.validator.publicOwnerAddress, /^0x[a-fA-F0-9]{40}$/);
  assert.equal(snapshot.ethereum.recovery.status, "available");
  assert.equal(snapshot.ethereum.recovery.sameDeviceWarning, true);
  assert.equal(JSON.stringify(snapshot).includes("privateKey"), false);
});

test("wrong passphrase fails closed", () => {
  const { host } = newHost();
  host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: false
  });
  const result = host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: "wrong-passphrase" });
  assert.equal(result.status, "failed");
  assert.equal(result.snapshot.session.lockState, "locked");
  assert.equal(result.snapshot.vault.status, "locked");
});

test("created passphrase unlocks the same identity after wrong retry and restart", () => {
  const setup = newHost();
  const created = setup.host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Restart Unlock",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  const identityId = created.identity.identityId;

  const wrong = setup.host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: "wrong-passphrase" });
  assert.equal(wrong.status, "failed");
  assert.equal(wrong.snapshot.session.lockState, "locked");
  assert.equal(wrong.snapshot.vault.status, "locked");

  const authenticated = setup.host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  assert.equal(authenticated.status, "authenticated");
  const unlocked = setup.host.invoke(CHANNELS.UNLOCK_VAULT, {});
  assert.equal(unlocked.status, "unlocked");
  assert.equal(unlocked.snapshot.session.lockState, "unlocked");
  assert.equal(unlocked.snapshot.protectedAction.eligible, true);

  const locked = setup.host.invoke(CHANNELS.LOCK_SESSION, {});
  assert.equal(locked.session.lockState, "locked");

  const restarted = newHost(setup.dir);
  const opened = restarted.host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  assert.equal(opened.identity.identityId, identityId);
  assert.equal(opened.session.lockState, "locked");
  assert.equal(opened.vault.status, "locked");

  const reopenedWrong = restarted.host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: "wrong-passphrase" });
  assert.equal(reopenedWrong.status, "failed");
  assert.equal(reopenedWrong.snapshot.session.lockState, "locked");

  const reopenedAuthenticated = restarted.host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  assert.equal(reopenedAuthenticated.status, "authenticated");
  const reopenedUnlocked = restarted.host.invoke(CHANNELS.UNLOCK_VAULT, {});
  assert.equal(reopenedUnlocked.status, "unlocked");
  assert.equal(reopenedUnlocked.snapshot.session.lockState, "unlocked");
  assert.equal(reopenedUnlocked.snapshot.protectedAction.eligible, true);
  assert.equal(reopenedUnlocked.snapshot.identity.identityId, identityId);

  const serialized = JSON.stringify(reopenedUnlocked.snapshot);
  assert.equal(serialized.includes(PASSPHRASE), false);
  assert.equal(serialized.includes("wrong-passphrase"), false);
  assert.equal(reopenedUnlocked.snapshot.audit.recent.some((event) => event.action === "unlock_device_vault"), true);
});

test("platform unlock enrollment reports clear success and failure states", () => {
  const { host } = newHost();
  createAndUnlock(host, true);
  let enrollment = approve(host, "platform_unlock_enrollment");
  const failed = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: "wrong-passphrase",
    approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.snapshot.platformAuth.status, "not_enrolled");
  assert.equal(failed.snapshot.audit.recent.some((event) => event.action === "platform_protection_enrollment_failed"), true);

  enrollment = approve(host, "platform_unlock_enrollment");
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
  assert.equal(enrolled.snapshot.platformAuth.status, "enabled");
  assert.equal(enrolled.snapshot.audit.recent.some((event) => event.action === "platform_protection_enrollment_completed"), true);
});

test("protected views require unlocked vault and hide registry plaintext", () => {
  const { host } = newHost();
  host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  assert.equal(host.invoke(CHANNELS.GET_PROTECTED_VIEW, { viewType: "registry_summary" }).status, "locked");
  createAndUnlock(host, true);
  const view = host.invoke(CHANNELS.GET_PROTECTED_VIEW, { viewType: "registry_summary" });
  assert.equal(view.status, "view_created");
  assert.equal(view.registryPlaintextReturned, false);
  assert.equal(view.containsSecrets, false);
});

test("manual lock invalidates vault handle and protected state", () => {
  const { host } = newHost();
  createAndUnlock(host, true);
  const before = host.invoke(CHANNELS.GET_VAULT_STATUS, {});
  assert.equal(before.status, "unlocked");
  const after = host.invoke(CHANNELS.LOCK_SESSION, {});
  assert.equal(after.vault.status, "locked");
  assert.equal(host.invoke(CHANNELS.GET_PROTECTED_VIEW, { viewType: "runtime_summary" }).status, "locked");
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
