#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const { createDesktopRuntimeHost } = require("../src/main/runtime-host.cjs");

function storageRoot() {
  return process.env.PHILCORE_DESKTOP_DIAGNOSTIC_DIR || path.join(os.tmpdir(), "philcore-desktop-diagnostics");
}

const root = storageRoot();
fs.mkdirSync(root, { recursive: true, mode: 0o700 });

const host = createDesktopRuntimeHost({
  preferencesPath: path.join(root, "philcore-desktop-preferences.json"),
  identityStorageRoot: path.join(root, "philcore-local-identities")
});

const identities = host.invoke(CHANNELS.LIST_LOCAL_IDENTITIES, {}).identities;
if (process.env.PHILCORE_DESKTOP_DIAGNOSTIC_IDENTITY_ID) {
  host.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, {
    identityId: process.env.PHILCORE_DESKTOP_DIAGNOSTIC_IDENTITY_ID
  });
}

const result = host.invoke(CHANNELS.DIAGNOSE_IDENTITY, {});
process.stdout.write(`${JSON.stringify({
  diagnostic: "desktop_identity",
  localOnly: true,
  publicNetworkMutation: false,
  identityCount: identities.length,
  ...result
}, null, 2)}\n`);
