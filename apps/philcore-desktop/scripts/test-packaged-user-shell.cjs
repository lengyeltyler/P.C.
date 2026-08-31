#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const release = require("./release-utils.cjs");

const appBundlePath = process.env.PHILCORE_DESKTOP_TEST_APP_PATH || release.appBundlePath;
const executablePath = path.join(appBundlePath, "Contents", "MacOS", release.executableName);
if (!fs.existsSync(executablePath)) {
  console.error("Packaged app missing; run npm run desktop:package-local first.");
  process.exit(1);
}

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-packaged-o15-user-shell-"));
const screenshotDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-packaged-o15-screenshots-"));
const consoleDiagnostics = [];

function run(mode) {
  const result = spawnSync(executablePath, [], {
    cwd: path.dirname(appBundlePath),
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_E2E: "1",
      PHILCORE_DESKTOP_E2E_UI_USER_SHELL: mode,
      PHILCORE_DESKTOP_E2E_SCREENSHOT_DIR: screenshotDir,
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ELECTRON_ENABLE_LOGGING: "0"
    },
    timeout: 360_000
  });
  if (result.status !== 0) {
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status || 1);
  }
  const stderrLines = result.stderr.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  const certificateErrors = stderrLines.filter((line) => /ssl_client_socket_impl\.cc:924.*net_error -202/u.test(line));
  const metaCspWarnings = stderrLines.filter((line) => /frame-ancestors.*ignored.*<meta>/u.test(line));
  const unexplained = stderrLines.filter((line) => !certificateErrors.includes(line) && !metaCspWarnings.includes(line));
  assert.deepEqual(unexplained, [], `unexpected packaged console diagnostics for ${mode}`);
  consoleDiagnostics.push({
    mode,
    exactPinnedLocalCertificateDiagnostics: certificateErrors.length,
    chromiumMetaCspDiagnostics: metaCspWarnings.length,
    unexplained: unexplained.length
  });
  const match = result.stdout.match(/\{[\s\S]*\}/u);
  assert.ok(match, `expected JSON packaged user-shell output for ${mode}`);
  return JSON.parse(match[0]);
}

const initial = run("initial");
assert.equal(initial.status, "passed");
assert.equal(initial.rendererBridgeFunctional, true);
assert.equal(initial.hello.title, "Hello");
assert.equal(initial.hello.approvedPositioning, true);
assert.equal(initial.hello.standalone, true);
assert.equal(initial.hello.sidebarHidden, true);
assert.equal(initial.hello.topbarHidden, true);
assert.equal(initial.hello.modeSwitchAbsent, true);
assert.equal(initial.hello.diagnosticsAbsent, true);
assert.equal(initial.hello.randomizerPresent, true);
assert.equal(initial.hello.initialPreview.dataUri, true);
assert.equal(initial.hello.mintedClaimAbsent, true);
assert.equal(initial.randomizedPhil.changed, true);
assert.equal(initial.randomizedPhil.preview.dataUri, true);
assert.notEqual(initial.randomizedPhil.preview.sha256, initial.hello.initialPreview.sha256);
assert.equal(initial.intro.present, true);
assert.equal(initial.intro.stepCount, 3);
assert.equal(initial.intro.firstTitle, "I'm your security sidekick");
assert.equal(initial.intro.characterImageLoaded, true);
assert.match(initial.intro.characterImageSrc, /assets\/characters\/phil\/phil_wave\.png$/u);
assert.equal(initial.createPage.standalone, true);
assert.equal(initial.createPage.sidebarHidden, true);
assert.equal(initial.createPage.topbarHidden, true);
assert.equal(initial.createPage.modeSwitchAbsent, true);
assert.equal(initial.createPage.localCreationCopy, true);
assert.equal(initial.createPage.preview.sha256, initial.randomizedPhil.preview.sha256);
assert.deepEqual(initial.partialPassphrase, {
  min_length: false,
  lowercase: true,
  uppercase: true,
  number: false,
  special: false
});
assert.equal(Object.values(initial.completePassphrase).every(Boolean), true);
assert.equal(initial.mismatchVisible, true);
assert.equal(initial.matchVisible, true);
assert.equal(initial.home.identityName, initial.identityName);
assert.deepEqual(initial.home.nav, ["Home", "Recovery later", "Activity", "Settings"]);
assert.equal(initial.home.favoriteChains.length, 8);
assert.equal(initial.home.favoriteChains.find((chain) => chain.id === "ethereum")?.status, "Sepolia Beta");
assert.equal(initial.home.favoriteChains.filter((chain) => chain.id !== "ethereum").every((chain) => chain.status === "Preview"), true);
assert.equal(initial.home.technicalPanelVisible, false);
assert.equal(initial.home.worldIdPreviewAvailable, true);
assert.deepEqual(initial.home.trendingItems, ["Collectible Gallery", "Identity Community"]);
assert.equal(initial.home.trendingDemoLabel, true);
assert.equal(initial.home.recentActivityHeading, true);
assert.equal(initial.home.oldActivityHeadingAbsent, true);
assert.equal(initial.home.forbiddenUserTermsPresent, false);
assert.equal(initial.home.publicNetworkMutation, false);
assert.equal(initial.passCShellSmoke.keyboard.nextNavigation, "recovery");
assert.equal(initial.passCShellSmoke.minimumWidth.windowBoundsWidth, 1040);
assert.equal(initial.passCShellSmoke.minimumWidth.innerWidth >= 1000, true);
assert.equal(initial.passCShellSmoke.minimumWidth.innerWidth <= 1040, true);
assert.equal(initial.passCShellSmoke.minimumWidth.horizontalOverflow, false);
assert.equal(initial.passCShellSmoke.minimumWidth.homeActionVisible, true);
assert.equal(initial.passCShellSmoke.minimumWidth.compactLayoutActive, true);
assert.equal(initial.worldIdPreview.identityRootDenied, true);
assert.equal(initial.worldIdPreview.noRequest, true);
assert.equal(initial.worldIdPreview.noBiometrics, true);
assert.equal(initial.featuredPreview.informationalOnly, true);
assert.equal(initial.featuredPreview.liveClaimAbsent, true);
assert.deepEqual(initial.search.resultIds, ["solana"]);
assert.equal(initial.search.localCatalogCopy, true);
assert.equal(initial.technicalHome.mode, "technical");
assert.equal(initial.technicalHome.diagnosticsVisible, true);
assert.equal(initial.technicalHome.sameIdentity, true);
assert.equal(initial.sepoliaMintReachability.buttonPresent, true);
assert.equal(initial.sepoliaMintReachability.exactHeadingPresent, true);
assert.equal(initial.sepoliaMintReachability.submissionLocked, true);
assert.equal(initial.sepoliaMintReachability.zeroValuePreparationPresent, true);
assert.equal(initial.sepoliaMintReachability.publicNetworkMutation, false);
assert.equal(initial.ethereumAccount.status, "Testnet account");
assert.equal(initial.ethereumAccount.controlledBeta, true);
assert.equal(initial.ethereumAccount.readOnly, true);
assert.equal(initial.protectedAction.completed, true);
assert.equal(initial.protectedAction.signingApprovalCompleted, true);
assert.equal(initial.protectedAction.proofVerified, true);
assert.equal(initial.protectedAction.nullifierConsumed, true);
assert.equal(initial.protectedAction.consumerExecuted, true);
assert.equal(initial.protectedAction.completionAuditRecorded, true);
assert.equal(initial.protectedAction.objectArtifactAbsent, true);
assert.equal(initial.protectedAction.publicNetworkMutation, false);
assert.equal(initial.preview.status, "Preview");
assert.equal(initial.preview.actionAbsent, true);
assert.equal(initial.preview.publicClaimAbsent, true);
assert.equal(initial.preview.accountStatus, "Not available");
assert.equal(initial.preview.unavailableCopy, true);
assert.equal(initial.activityBefore.available >= initial.activityBefore.rendered, true);
assert.equal(initial.activityBefore.loadOlderPresent, true);
assert.equal(initial.activityAfter.rendered > initial.activityBefore.rendered, true);
assert.equal(initial.technicalActivity.objectArtifactAbsent, true);
assert.equal(initial.technicalActivity.completedSummaryVisible, true);
assert.equal(initial.technicalActivity.proofGeneratingTerminalStatus, "completed");
assert.deepEqual(initial.settingsSections, [initial.identityName, "Trust", "Recovery is unavailable in this Beta", "Protected Mac unlock"]);
assert.equal(initial.settingsObjectArtifactsAbsent, true);
assert.equal(initial.technicalSettings.mode, "technical");
assert.equal(initial.technicalSettings.developerSurfacesAllowed, false);
assert.equal(initial.technicalSettings.developerToolsVisible, false);
assert.equal(initial.technicalSettings.developerTabAbsent, true);
assert.equal(initial.technicalSettings.developerToggleAbsent, true);
assert.equal(initial.technicalSettings.developerAuditChoiceAbsent, true);
assert.equal(initial.technicalSettings.advancedEvidenceVisible, true);
assert.equal(initial.technicalSettings.secretClassLabelsAbsent, true);
assert.equal(initial.privateMaterialExposed, false);
assert.equal(initial.publicNetworkMutation, false);

const returning = run("returning");
assert.equal(returning.status, "passed");
assert.equal(returning.rendererBridgeFunctional, true);
assert.equal(returning.returningWelcome.introPresent, false);
assert.equal(returning.returningWelcome.identityNamePresent, true);
assert.equal(returning.returningWelcome.standalone, true);
assert.equal(returning.returningWelcome.sidebarHidden, true);
assert.equal(returning.returningWelcome.topbarHidden, true);
assert.equal(returning.returningWelcome.modeSwitchAbsent, true);
assert.equal(returning.returningWelcome.philPreview.sha256, initial.randomizedPhil.preview.sha256);
assert.equal(returning.returningWelcome.presentationMode, "technical");
assert.equal(returning.returningHome.identityName, initial.identityName);
assert.equal(returning.returningHome.presentationMode, "technical");
assert.deepEqual(returning.returningHome.nav, ["Home", "Recovery later", "Activity", "Settings"]);
assert.equal(returning.returningHome.chainCount >= 8, true);
assert.equal(returning.returningHome.publicNetworkMutation, false);
assert.equal(returning.privateMaterialExposed, false);
assert.equal(returning.publicNetworkMutation, false);

console.log(JSON.stringify({
  status: "passed",
  packagedUserShellWalkthrough: true,
  firstRunCompleted: true,
  returningUserCompleted: true,
  identityNamePersisted: returning.returningHome.identityName === initial.identityName,
  philPreviewPersisted: returning.returningWelcome.philPreview.sha256 === initial.randomizedPhil.preview.sha256,
  presentationModePersisted: returning.returningHome.presentationMode === "technical",
  normalNavigation: returning.returningHome.nav,
  favoriteChainCount: initial.home.favoriteChains.length,
  localSearchResult: initial.search.resultIds,
  noirProofVerifiedAndActionCompleted: initial.protectedAction.proofVerified && initial.protectedAction.completed,
  previewChainStayedInactive: initial.preview.actionAbsent,
  activityHistoryAvailable: initial.activityBefore.available,
  settingsSections: initial.settingsSections,
  developerSurfacesIsolatedFromRelease: initial.technicalSettings.developerTabAbsent
    && initial.technicalSettings.developerToggleAbsent
    && initial.technicalSettings.developerAuditChoiceAbsent,
  advancedEvidenceAvailable: initial.technicalSettings.advancedEvidenceVisible,
  consoleDiagnostics,
  screenshots: fs.readdirSync(screenshotDir).sort().map((name) => path.join(screenshotDir, name)),
  privateMaterialExposed: false,
  publicNetworkMutation: false
}, null, 2));
