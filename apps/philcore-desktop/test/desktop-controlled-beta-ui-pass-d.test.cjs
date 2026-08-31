#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const appRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(appRoot, "../..");
const readApp = (relativePath) => fs.readFileSync(path.join(appRoot, relativePath), "utf8");
const readRepo = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

test("Pass D packaged Desktop isolates developer controls while retaining bounded Advanced evidence", () => {
  const main = readApp("src/main/main.cjs");
  const runtime = readApp("src/main/runtime-host.cjs");
  const renderer = readApp("src/renderer/app.js");

  assert.match(main, /const isDevelopment = !app\.isPackaged && process\.env\.PHILCORE_DESKTOP_DEV === "1"/u);
  assert.match(main, /developerSurfacesAllowed: isDevelopment/u);
  assert.match(runtime, /developerSurfacesAllowed: options\.developerSurfacesAllowed === true/u);
  assert.match(renderer, /function developerSurfacesAllowed\(\)/u);
  assert.match(renderer, /isTechnicalMode\(\) && developerSurfacesAllowed\(\)/u);
  assert.match(renderer, /developerSurfacesAllowed\(\) && snapshot\.settings\.developerModeVisible/u);
  assert.match(renderer, /value === "user" \? "User" : "Advanced"/u);
  assert.match(renderer, /Advanced Beta evidence/u);
  assert.match(renderer, /\["Package profile", snapshot\.release\.packageProfile\]/u);
  assert.match(renderer, /\["UI package source", snapshot\.release\.sourceCommit\]/u);
  assert.match(renderer, /\["Beta evidence source commit", evidence\.sourceCommit\]/u);
});

test("Pass D About and Advanced surfaces state the complete Beta boundary", () => {
  const renderer = readApp("src/renderer/app.js");
  for (const expected of [
    "Phil — Controlled Sepolia Beta",
    "Ethereum Sepolia",
    "Test only · Not mainnet",
    "No meaningful assets or production custody",
    "Deferred and unavailable",
    "Not post-quantum secure",
    "App version",
    "Advanced Beta evidence",
    "Smart account",
    "EntryPoint",
    "Final nonce",
    "P2 transaction",
    "P3 transaction",
    "P5 transaction",
    "Reconciliation"
  ]) assert.match(renderer, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
});

test("Pass D ordinary release claims remain truthful and recovery remains deferred", () => {
  const renderer = readApp("src/renderer/app.js");
  const ios = readRepo("apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift");
  const ordinaryClaims = `${renderer}\n${ios}`;

  for (const prohibited of [
    /mainnet[- ]ready/iu,
    /production custody (?:is )?(?:ready|available|supported)/iu,
    /meaningful assets (?:are )?safe/iu,
    /\b(?:is|are) currently post-quantum secure/iu,
    /Ethereum verifies (?:the )?Noir/iu,
    /Ethereum verifies (?:the )?iPhone P-256/iu,
    /V2 recovery is active/iu,
    /STWO is (?:the )?(?:current|production)/iu,
    /local demo (?:is|equals) (?:a )?(?:new )?public/iu,
    /completed Beta action can be replayed/iu
  ]) assert.doesNotMatch(ordinaryClaims, prohibited);

  assert.match(renderer, /Recovery is unavailable in this Beta/u);
  assert.match(ios, /Recovery deferred/u);
  assert.match(renderer, /do not replay or recreate the completed Controlled Beta/u);
});

test("Pass D public evidence projections exclude secret-bearing classes", () => {
  const desktopEvidence = readApp("src/main/controlled-beta-release-state.cjs");
  const iosEvidence = readRepo("apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift")
    .slice(readRepo("apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift").indexOf("enum ControlledBetaEvidence"), readRepo("apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift").indexOf("enum PhilBetaGuidance"));
  const evidence = `${desktopEvidence}\n${iosEvidence}`;
  for (const forbidden of [
    /private.?key/iu,
    /api.?key/iu,
    /authenticated.?url/iu,
    /phil.?secret/iu,
    /witness/iu,
    /nullifier.?seed/iu,
    /recovery.?secret/iu,
    /device.?vault.?material/iu
  ]) assert.doesNotMatch(evidence, forbidden);
});

test("Pass D iOS fixture routing and large-type overrides remain DEBUG-only", () => {
  const app = readRepo("apps/philcore-ios-companion/PhilCoreCompanion/PhilCoreCompanionApp.swift");
  const model = readRepo("apps/philcore-ios-companion/PhilCoreCompanion/CompanionModel.swift");
  assert.match(app, /#if DEBUG[\s\S]*--philcore-ui-test-large-type[\s\S]*#else[\s\S]*RootView\(\)[\s\S]*#endif/u);
  assert.match(model, /#if DEBUG[\s\S]*--philcore-ui-test-state[\s\S]*#endif/u);
});
