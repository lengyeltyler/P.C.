#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter,
  createUnsupportedPlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");

const root = process.env.PHILCORE_DESKTOP_DIAGNOSTIC_DIR || path.join(os.tmpdir(), "philcore-desktop-diagnostics");
fs.mkdirSync(root, { recursive: true, mode: 0o700 });

const host = createDesktopRuntimeHost({
  preferencesPath: path.join(root, "philcore-desktop-preferences.json"),
  identityStorageRoot: path.join(root, "philcore-local-identities"),
  platformKeyAdapter: process.env.PHILCORE_DESKTOP_DIAGNOSTIC_USE_FIXTURE === "1"
    ? createFixturePlatformKeyAdapter()
    : createUnsupportedPlatformKeyAdapter(process.platform)
});

const result = host.invoke(CHANNELS.DIAGNOSE_PLATFORM_AUTH, {});
process.stdout.write(`${JSON.stringify({
  ...result,
  realMacosKeychainCheckRequiresElectronMainProcess: process.env.PHILCORE_DESKTOP_DIAGNOSTIC_USE_FIXTURE !== "1",
  fixtureMode: process.env.PHILCORE_DESKTOP_DIAGNOSTIC_USE_FIXTURE === "1"
}, null, 2)}\n`);
