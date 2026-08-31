const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const { createDesktopRuntimeHost } = require("../src/main/runtime-host.cjs");

const PASSPHRASE = "restart-Local-alpha-passphrase!1";

function hostFor(dir) {
  return createDesktopRuntimeHost({
    preferencesPath: path.join(dir, "prefs.json"),
    identityStorageRoot: path.join(dir, "identities"),
    sessionTtlMs: 60_000
  });
}

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

function createUnlock(host) {
  let snapshot = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Restart Test",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  const identityId = snapshot.identity.identityId;
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  snapshot = host.invoke(CHANNELS.UNLOCK_VAULT, {}).snapshot;
  return { identityId, snapshot };
}

test("restart reopens same encrypted identity locked, then unlocks same public state", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-restart-"));
  let host = hostFor(dir);
  const created = createUnlock(host);
  const ownerCommitment = created.snapshot.identity.ownerCommitment;
  const validatorAddress = created.snapshot.ethereum.validator.publicOwnerAddress;
  const recoveryAddress = created.snapshot.ethereum.recovery.publicAddress;
  host.invoke(CHANNELS.LOCK_SESSION, {});

  host = hostFor(dir);
  const list = host.invoke(CHANNELS.LIST_LOCAL_IDENTITIES, {});
  assert.equal(list.identities.length, 1);
  assert.equal(list.identities[0].identityId, created.identityId);

  let snapshot = host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId: created.identityId });
  assert.equal(snapshot.session.lockState, "locked");
  assert.equal(snapshot.identity.ownerCommitment, ownerCommitment);
  assert.equal(host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: "incorrect-passphrase" }).status, "failed");
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  snapshot = host.invoke(CHANNELS.UNLOCK_VAULT, {}).snapshot;
  assert.equal(snapshot.identity.ownerCommitment, ownerCommitment);
  assert.equal(snapshot.ethereum.validator.publicOwnerAddress, validatorAddress);
  assert.equal(snapshot.ethereum.recovery.publicAddress, recoveryAddress);
});

test("ciphertext tampering fails closed", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-tamper-"));
  let host = hostFor(dir);
  const { identityId } = createUnlock(host);
  host.invoke(CHANNELS.LOCK_SESSION, {});
  const registryPath = path.join(dir, "identities", identityId, "registry.encrypted.json");
  const envelope = JSON.parse(fs.readFileSync(registryPath, "utf8"));
  envelope.ciphertext = `${envelope.ciphertext.slice(0, -2)}xx`;
  fs.writeFileSync(registryPath, `${JSON.stringify(envelope)}\n`);

  host = hostFor(dir);
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  const result = host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  assert.equal(result.status, "failed");
  assert.equal(result.snapshot.session.lockState, "locked");
});

test("identity index owner tampering is rejected by encrypted binding", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-index-tamper-"));
  let host = hostFor(dir);
  const { identityId } = createUnlock(host);
  host.invoke(CHANNELS.LOCK_SESSION, {});
  const indexPath = path.join(dir, "identities", "identity-index.json");
  const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  index.identities[0].ownerCommitment = `0x${"11".repeat(32)}`;
  fs.writeFileSync(indexPath, `${JSON.stringify(index)}\n`);

  host = hostFor(dir);
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
  const result = host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE });
  assert.equal(result.status, "failed");
  assert.equal(result.snapshot.session.lockState, "locked");
});

test("local reset requires locked identity and exact confirmation", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-reset-"));
  const host = hostFor(dir);
  const { identityId } = createUnlock(host);
  assert.equal(host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, { confirmation: `RESET ${identityId}` }).status, "failed");
  host.invoke(CHANNELS.LOCK_SESSION, {});
  assert.equal(host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, { confirmation: "RESET wrong" }).status, "approval_required");
  const confirmation = `RESET ${identityId}`;
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind: "local_identity_reset",
    confirmationTarget: confirmation
  });
  assert.equal(presentation.status, "presentation_created");
  assert.equal(host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation: "RESET wrong"
  }).status, "failed");
  const approval = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation: confirmation
  });
  assert.equal(approval.status, "approved");
  const reset = host.invoke(CHANNELS.RESET_LOCAL_IDENTITY, {
    confirmation,
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    passphrase: PASSPHRASE
  });
  assert.equal(reset.status, "reset");
  assert.equal(host.invoke(CHANNELS.LIST_LOCAL_IDENTITIES, {}).identities.length, 0);
});
