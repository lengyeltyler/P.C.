#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { bundlePreload } = require("./bundle-preload.cjs");

const appRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(appRoot, "..", "..");
const distRoot = path.join(appRoot, "dist-local");
const requiredFiles = [
  "src/main/main.cjs",
  "src/main/runtime-host.cjs",
  "src/main/controlled-beta-release-state.cjs",
  "src/main/recovery-secure-origin.cjs",
  "src/main/recovery-attestation-policy.cjs",
  "src/main/recovery-enrollment-host.cjs",
  "src/main/native-iphone-pairing-host.cjs",
  "src/main/native-qr-code.cjs",
  "src/preload/preload.cjs",
  "src/shared/bridge-contract.cjs",
  "src/renderer/index.html",
  "src/renderer/startup-guard.js",
  "src/renderer/presentation.js",
  "src/renderer/philenator-engine.js",
  "src/renderer/phil-preview-provider.js",
  "src/renderer/external-credential-provider.js",
  "src/renderer/ecosystem-discovery.js",
  "src/renderer/chain-catalog.js",
  "src/renderer/disposable-platform-webauthn.js",
  "src/renderer/routine-authorization-ui.cjs",
  "src/renderer/unlock-transition-policy.cjs",
  "src/renderer/phil-helper.cjs",
  "src/renderer/styles.css",
  "src/renderer/final-beta-ui.css",
  "src/renderer/monochrome-final.css",
  "src/renderer/app.js",
  "src/renderer/recovery-secret.html",
  "src/renderer/recovery-secret.css",
  "src/renderer/recovery-secret.js"
];

function listFiles(relativeDirectory) {
  const absoluteDirectory = path.join(appRoot, relativeDirectory);
  return fs.readdirSync(absoluteDirectory, { withFileTypes: true })
    .flatMap((entry) => {
      const relative = path.join(relativeDirectory, entry.name);
      return entry.isDirectory() ? listFiles(relative) : [relative];
    })
    .sort();
}

requiredFiles.push(...listFiles("src/renderer/assets"));

for (const relative of requiredFiles) {
  const source = path.join(appRoot, relative);
  if (!fs.existsSync(source)) throw new Error(`Missing desktop source: ${relative}`);
}

fs.rmSync(distRoot, { recursive: true, force: true });
for (const relative of requiredFiles) {
  const source = path.join(appRoot, relative);
  const target = path.join(distRoot, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}
bundlePreload(path.join(distRoot, "src", "preload", "preload.cjs"));

const manifest = {
  phase: "O.43",
  stack: "electron_static_renderer",
  localOnly: true,
  publicNetworkMutationEnabled: false,
  digestBoundApprovalEnabled: true,
  main: "src/main/main.cjs",
  generatedAt: new Date().toISOString(),
  files: requiredFiles
};
fs.writeFileSync(path.join(distRoot, "philcore-desktop-local-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
process.stdout.write(`Built local desktop artifact at ${path.relative(repoRoot, distRoot)}\n`);
