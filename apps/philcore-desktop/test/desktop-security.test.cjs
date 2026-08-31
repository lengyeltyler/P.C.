const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const appRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(appRoot, "..", "..");

function read(relative) {
  return fs.readFileSync(path.join(appRoot, relative), "utf8");
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

test("Electron BrowserWindow uses isolated renderer settings", () => {
  const main = read("src/main/main.cjs");
  assert.match(main, /contextIsolation:\s*true/);
  assert.match(main, /nodeIntegration:\s*false/);
  assert.match(main, /sandbox:\s*true/);
  assert.match(main, /setWindowOpenHandler/);
  assert.match(main, /will-navigate/);
  assert.equal(main.includes("event.senderFrame?.url !== `${RECOVERY_ORIGIN}/index.html`"), true);
  assert.equal(main.includes("mainWindow.loadURL(`${RECOVERY_ORIGIN}/index.html`)"), true);
  assert.doesNotMatch(main, /loadFile\(path\.join\(__dirname,\s*"\.\.\/renderer\/index\.html"/u);
});

test("renderer has CSP and no Node imports", () => {
  const html = read("src/renderer/index.html");
  const renderer = read("src/renderer/app.js");
  assert.match(html, /Content-Security-Policy/);
  assert.doesNotMatch(renderer, /require\s*\(/);
  assert.doesNotMatch(renderer, /ipcRenderer/);
  assert.doesNotMatch(renderer, /child_process|fs\.|process\./);
});

test("recovery secrets have no clipboard, crash upload, or generic bridge route", () => {
  const main = read("src/main/main.cjs");
  const renderer = [
    read("src/renderer/app.js"),
    read("src/renderer/recovery-secret.js")
  ].join("\n");
  const bridge = read("src/shared/bridge-contract.cjs");
  assert.match(main, /appendSwitch\("disable-breakpad"\)/u);
  assert.match(main, /setUploadToServer\(false\)/u);
  assert.match(main, /getUploadToServer\(\)/u);
  assert.doesNotMatch(renderer, /navigator\.clipboard|localStorage|sessionStorage/u);
  assert.doesNotMatch(bridge, /readAllSecrets|genericFilesystem|executeCommand/u);
});

test("preload exposes narrow bridge only", () => {
  const preload = read("src/preload/preload.cjs");
  assert.match(preload, /contextBridge\.exposeInMainWorld\("philcore"/);
  assert.doesNotMatch(preload, /sendSync/);
  assert.doesNotMatch(preload, /shell|child_process|fs/);
});

test("sandboxed preload is bundled without disabling renderer security", () => {
  const main = read("src/main/main.cjs");
  const bundler = read("scripts/bundle-preload.cjs");
  assert.match(main, /resolvePreloadPath\(\)/u);
  assert.match(main, /sandbox:\s*true/u);
  assert.match(bundler, /bundle:\s*true/u);
  assert.match(bundler, /external:\s*\["electron"\]/u);
  assert.doesNotMatch(main, /sandbox:\s*false/u);
  assert.doesNotMatch(main, /nodeIntegration:\s*true/u);
});

test("renderer does not render forbidden secret-shaped tokens", () => {
  const all = [
    read("src/renderer/index.html"),
    read("src/renderer/app.js"),
    read("src/renderer/styles.css")
  ].join("\n");
  for (const token of ["phil_secret", "privateKey", "vaultKey", "wrappingKey", "rawWrappingKey", "nullifierSeed", "mnemonic", "seedPhrase"]) {
    assert.equal(all.includes(token), false, `${token} should not appear in renderer`);
  }
});

test("release hardening config keeps local Alpha unsigned and public-network disabled", () => {
  const profile = JSON.parse(read("build/release-profiles.json"));
  assert.equal(profile.bundleIdentifier, "com.philcore.desktop.localalpha");
  assert.equal(profile.bundleIdentifiers.releaseCandidate, "com.philcore.desktop.localalpha");
  assert.equal(profile.profiles.local_alpha_unsigned.publicNetworkMutation, false);
  assert.equal(profile.profiles.local_alpha_adhoc.signed, "ad_hoc");
  assert.equal(profile.profiles.release_candidate_signed.nativeUserPresence, "required");
  assert.equal(profile.profiles.localAlpha.publicNetworkMutation, false);
  assert.equal(profile.profiles.localAlpha.publicBundler, false);
  assert.equal(profile.profiles.localAlpha.paymaster, false);
  assert.equal(profile.profiles.localAlpha.baseSepoliaBetaGate, "blocked");
  assert.equal(profile.profiles.signedReleaseCandidate.credentialsRequiredExternally, true);
  assert.equal(profile.profiles.production.enabled, false);
});

test("package excludes the duplicate dependency-root link from the app bundle", () => {
  const packaging = read("scripts/package-local.cjs");
  assert.match(packaging, /relative === "node_modules"/u);
  assert.match(packaging, /excludedDuplicateDependencyRoot:\s*true/u);
});

test("ad-hoc package defers the final ZIP hash to post-archive evidence", () => {
  const adhoc = read("scripts/package-adhoc.cjs");
  const verifier = read("scripts/verify-package.cjs");
  assert.match(adhoc, /philcore-desktop-local-alpha-adhoc-evidence\.json/u);
  assert.match(adhoc, /embeddedManifestSha256/u);
  assert.match(adhoc, /postZipExtractionVerification:\s*true/u);
  assert.match(verifier, /adhoc_post_archive_evidence_mismatch/u);
  assert.match(verifier, /zipSha256\s*!==\s*sha256\(zipArtifactPath\)/u);
});

test("native user-presence helper remains main-process only", () => {
  const main = read("src/main/main.cjs");
  const host = read("src/main/runtime-host.cjs");
  const preload = read("src/preload/preload.cjs");
  const renderer = read("src/renderer/app.js");
  assert.match(main, /createMacOsLocalAuthenticationProvider/);
  assert.match(host, /native_user_presence/);
  assert.doesNotMatch(preload, /UserPresenceHelper|macos-user-presence|LocalAuthentication/);
  assert.doesNotMatch(renderer, /UserPresenceHelper|LocalAuthentication|macos-user-presence/);
});

test("release status is visible without claiming notarization or production approval", () => {
  const runtimeHost = read("src/main/runtime-host.cjs");
  const renderer = read("src/renderer/app.js");
  assert.match(runtimeHost, /function releaseStatus/);
  assert.match(runtimeHost, /not_notarized/);
  assert.match(runtimeHost, /productionApproved:\s*false/);
  assert.match(renderer, /About and diagnostics/);
  assert.match(renderer, /Notarization/);
});

test("signed and notarization commands are guarded by external approval", () => {
  const signed = spawnSync(process.execPath, ["apps/philcore-desktop/scripts/package-signed.cjs"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, PHILCORE_DESKTOP_SIGNING_IDENTITY: "" }
  });
  assert.notEqual(signed.status, 0);
  assert.match(`${signed.stdout}\n${signed.stderr}`, /PHILCORE_DESKTOP_SIGNING_IDENTITY/);

  const wrongIdentity = spawnSync(process.execPath, ["apps/philcore-desktop/scripts/package-signed.cjs"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, PHILCORE_DESKTOP_SIGNING_IDENTITY: "Apple Development: Example" }
  });
  assert.notEqual(wrongIdentity.status, 0);
  assert.match(`${wrongIdentity.stdout}\n${wrongIdentity.stderr}`, /developer_id_application_identity_required|Package app first/);

  const notarize = spawnSync(process.execPath, ["apps/philcore-desktop/scripts/notarize.cjs"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, PHILCORE_DESKTOP_NOTARIZE_APPROVED: "" }
  });
  assert.notEqual(notarize.status, 0);
  assert.match(`${notarize.stdout}\n${notarize.stderr}`, /PHILCORE_DESKTOP_NOTARIZE_APPROVED=1/);
});
