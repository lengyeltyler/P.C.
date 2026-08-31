#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const { createDesktopRuntimeHost } = require("../src/main/runtime-host.cjs");

const PASSPHRASE = "diagnostic-Local-alpha-passphrase!1";

function storageRoot() {
  return process.env.PHILCORE_DESKTOP_DIAGNOSTIC_DIR || fs.mkdtempSync(path.join(os.tmpdir(), "philcore-desktop-vault-diagnostic-"));
}

const root = storageRoot();
fs.mkdirSync(root, { recursive: true, mode: 0o700 });

const host = createDesktopRuntimeHost({
  preferencesPath: path.join(root, "philcore-desktop-preferences.json"),
  identityStorageRoot: path.join(root, "philcore-local-identities"),
  sessionTtlMs: 60_000
});

let identities = host.invoke(CHANNELS.LIST_LOCAL_IDENTITIES, {}).identities;
let createdTemporaryIdentity = false;
if (identities.length === 0) {
  host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Diagnostic Local Identity",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: true
  });
  createdTemporaryIdentity = true;
  identities = host.invoke(CHANNELS.LIST_LOCAL_IDENTITIES, {}).identities;
}

if (identities[0]) {
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId: identities[0].identityId });
  host.invoke(CHANNELS.AUTHENTICATE_LOCAL, {
    passphrase: process.env.PHILCORE_DESKTOP_DIAGNOSTIC_PASSPHRASE || PASSPHRASE
  });
  host.invoke(CHANNELS.UNLOCK_VAULT, {});
}

const result = host.invoke(CHANNELS.DIAGNOSE_VAULT, {});
host.invoke(CHANNELS.LOCK_SESSION, {});

process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_vault",
  localOnly: true,
  publicNetworkMutation: false,
  createdTemporaryIdentity,
  ...result,
  privateMaterialExposed: false
}, null, 2)}\n`);
