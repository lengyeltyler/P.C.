const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(appRoot, "../..");

function read(relative) {
  return fs.readFileSync(path.join(appRoot, relative), "utf8");
}

function readRepo(relative) {
  return fs.readFileSync(path.join(repoRoot, relative), "utf8");
}

function loadPresentation() {
  const context = { window: {}, Object, String };
  vm.runInNewContext(read("src/renderer/presentation.js"), context, { filename: "presentation.js" });
  return context.window.PhilCorePresentation;
}

function loadCatalog() {
  const context = { globalThis: {}, Object, String };
  vm.runInNewContext(read("src/renderer/chain-catalog.js"), context, { filename: "chain-catalog.js" });
  return context.globalThis.PhilCoreChainCatalog;
}

function loadPhilPreviewProvider() {
  const context = { globalThis: {}, Object, String, Number };
  vm.runInNewContext(read("src/renderer/phil-preview-provider.js"), context, { filename: "phil-preview-provider.js" });
  return context.globalThis.PhilPreviewProvider;
}

function loadExternalCredentialProviders() {
  const context = { globalThis: {}, Object };
  vm.runInNewContext(read("src/renderer/external-credential-provider.js"), context, { filename: "external-credential-provider.js" });
  return context.globalThis.PhilCoreExternalCredentialProviders;
}

function loadDiscovery() {
  const context = { globalThis: {}, Object };
  vm.runInNewContext(read("src/renderer/ecosystem-discovery.js"), context, { filename: "ecosystem-discovery.js" });
  return context.globalThis.PhilCoreEcosystemDiscovery;
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

test("presentation layer still translates internal state", () => {
  const present = loadPresentation();
  assert.equal(present.label("local_alpha"), "Local testing mode");
  assert.equal(present.label("public_testnet_disabled"), "Public blockchain connections are off");
  assert.equal(present.label("pending_signature"), "Waiting for approval");
  assert.equal(present.lock({ session: { lockState: "unlocked", vaultState: "unlocked" }, identity: { label: "Local" } }), "Unlocked");
});

test("normal sidebar includes the bounded deferred-recovery environment", () => {
  const renderer = read("src/renderer/app.js");
  const navBlock = renderer.match(/const navItems = \[([\s\S]*?)\];/u)?.[1] || "";
  assert.match(navBlock, /\["home", "Home"\]/);
  assert.match(navBlock, /\["recovery", "Recovery later"\]/);
  assert.match(navBlock, /\["audit", "Activity"\]/);
  assert.match(navBlock, /\["settings", "Settings"\]/);
  for (const removed of ["Identity", "Trust", "Ethereum", "Developer"]) {
    assert.equal(navBlock.includes(`"${removed}"`), false);
  }
  assert.match(renderer, /const utilityViews = new Set\(\["intro", "welcome", "create", "unlock", "chain"\]\)/);
});

test("User and Technical mode are one persisted presentation preference", () => {
  const renderer = read("src/renderer/app.js");
  const contract = read("src/shared/bridge-contract.cjs");
  assert.match(renderer, /data-presentation-mode/);
  assert.match(renderer, /presentationMode/);
  assert.match(renderer, /window\.philcore\.settings\.update/);
  assert.match(contract, /\["user", "technical"\]/);
  assert.doesNotMatch(renderer, /technicalRuntime|userRuntime/);
});

test("Welcome is a standalone minimal Phil entry screen", () => {
  const renderer = read("src/renderer/app.js");
  const styles = read("src/renderer/styles.css");
  assert.match(renderer, /<p class="welcome-hello">Hello<\/p>/);
  assert.match(renderer, /current authorization uses classical cryptography and is not currently post-quantum secure/);
  assert.match(renderer, /data-action="beginCreatePhil" type="button"/);
  assert.match(renderer, /selectedPhilPreview\.generated \? "Create Phil" : "Building Phil…"/);
  assert.match(renderer, /!snapshot\.identity && !\["intro", "welcome", "create", "settings"\]\.includes\(currentView\)/);
  assert.match(renderer, /introReturnView = "create"/);
  const main = read("src/main/main.cjs");
  assert.match(main, /character-led introduction/);
  assert.match(main, /characterImageLoaded/);
  assert.match(renderer, /Existing identities/);
  assert.match(renderer, /Last used/);
  assert.match(renderer, /· Locked/);
  assert.match(styles, /body\[data-standalone="true"\] \.sidebar/);
  assert.match(styles, /body\[data-standalone="true"\] \.topbar/);
  assert.match(styles, /\.status-card\.warn,[\s\S]*rgba\(8, 8, 8, \.96\)/);
  assert.match(styles, /\.result-panel\.ok,[\s\S]*\.event,[\s\S]*\.stage/);
  assert.doesNotMatch(renderer, /Your Phil has been minted|Mint successful|Connected account|quantum-proof/);
  assert.match(renderer, /not currently post-quantum secure/);
});

test("Phil preview uses the pinned local Philenator engine and persists by reference", () => {
  const provider = loadPhilPreviewProvider();
  const first = provider.localProvider.defaultPreview();
  assert.equal(first.source, "philenator-local");
  assert.equal(first.generatorRevision, "f174dedda16a354c592e3252d9b0b5805bab59c4");
  assert.equal(first.mintStatus, "not-minted");
  assert.equal(first.publicToken, null);
  assert.equal(provider.localProvider.remoteAccessEnabled, false);
  assert.deepEqual(Array.from(provider.layerOrder), [
    "bgColor", "bgNebula", "bgStars", "bgSpiral", "bgDust", "bgOverlay",
    "bodyBase", "body", "spikes", "teeth", "jawNose", "eyes", "top"
  ]);
  assert.match(first.imageUri, /^\.\/assets\/characters\/phil\/phil_[a-z_]+\.png$/);
  assert.equal(first.generated, false);
  assert.match(read("src/renderer/philenator-engine.js"), /PhilenatorEngine/);
  assert.match(read("src/renderer/philenator-engine.js"), /f174dedda16a354c592e3252d9b0b5805bab59c4/);
  assert.match(read("src/renderer/app.js"), /syncPhilenatorBackground/);
  const manifest = JSON.parse(read("src/renderer/assets/philenator/manifest.json"));
  assert.equal(Boolean(manifest.BgColor && manifest.BodyBase && manifest.JawNose && manifest.Top), true);
  const traitFiles = fs.readdirSync(path.join(appRoot, "src/renderer/assets/philenator/traits"), { recursive: true })
    .filter((name) => name.endsWith(".svg"));
  assert.equal(traitFiles.length, 503);
  const runtime = read("src/main/runtime-host.cjs");
  assert.match(runtime, /philPreview: input\.philPreview/);
  assert.match(runtime, /philPreview: sanitizeIndexEntry\(entry\)\.philPreview/);
});

test("standalone identity creation keeps live passphrase and visibility safeguards", () => {
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /create: \(\) => html/);
  assert.match(renderer, /standalone-entry creation-entry/);
  assert.match(renderer, /create-passphrase-confirm/);
  assert.match(renderer, /At least 12 characters/);
  assert.match(renderer, /One lowercase letter/);
  assert.match(renderer, /One uppercase letter/);
  assert.match(renderer, /One number/);
  assert.match(renderer, /One special character/);
  assert.match(renderer, /togglePassphraseVisibility/);
  assert.match(renderer, /bindCreateFormRealtime/);
  assert.match(renderer, /addEventListener\("input", updatePassphraseFeedback\)/);
  assert.match(renderer, /Passphrases match/);
  assert.match(renderer, /Create Phil identity/);
  assert.match(renderer, /data-action="backWelcome"/);
  assert.match(renderer, /renameLocal/);
});

test("bundled chain catalog is local extensible and truthful", () => {
  const catalog = loadCatalog();
  assert.equal(catalog.chains.length, 8);
  assert.deepEqual(Array.from(catalog.chains, (chain) => chain.name), [
    "Ethereum", "Bitcoin", "Solana", "Base", "Polygon", "Cardano", "Arbitrum", "Optimism"
  ]);
  assert.equal(catalog.getById("ethereum").status, "Sepolia Beta");
  assert.equal(catalog.getById("ethereum").accountStatus, "deployed-testnet");
  assert.equal(catalog.getById("ethereum").publicNetworkEnabled, false);
  for (const chain of catalog.chains.filter((item) => item.id !== "ethereum")) {
    assert.equal(chain.status, "Preview");
    assert.ok(["prepared", "unavailable"].includes(chain.accountStatus));
    assert.equal(chain.publicNetworkEnabled, false);
  }
  assert.deepEqual(Array.from(catalog.accountStatuses), ["none", "local-test", "prepared", "deployed-testnet", "deployed-mainnet", "unavailable"]);
  assert.equal(catalog.remoteSearchEnabled, false);
  assert.equal(catalog.search("layer 2").length >= 3, true);
  assert.equal(catalog.search("does-not-exist").length, 0);
});

test("Home is a local portal with search favorites and limited recent activity", () => {
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /Search blockchains, apps, and ecosystems/);
  assert.match(renderer, /Searches only the catalog bundled with this Beta/);
  assert.match(renderer, /chainCatalog\.search/);
  assert.match(renderer, /chainCatalog\.favorites/);
  assert.match(renderer, /slice\(0, 4\)/);
  assert.match(renderer, /View all activity/);
  assert.match(renderer, /<h3>Recent Activity<\/h3>/);
  assert.doesNotMatch(renderer, /What happened lately/);
  assert.doesNotMatch(renderer, /\bfetch\(|XMLHttpRequest|https?:\/\//);
});

test("Phil world styling stays presentational and opens only after a real unlock", () => {
  const renderer = read("src/renderer/app.js");
  const html = read("src/renderer/index.html");
  const styles = read("src/renderer/styles.css");
  const unlockPolicy = require("../src/renderer/unlock-transition-policy.cjs");
  assert.match(html, /id="world-transition"[^>]*aria-hidden="true"/);
  assert.match(html, /Your identity stays with you\. Every connection asks permission\./);
  assert.match(renderer, /if \(worldTransitionPending && currentView === "home"\)/);
  assert.match(renderer, /function playWorldTransition\(\)/);
  assert.equal(unlockPolicy.identityCreated(null), false);
  assert.equal(unlockPolicy.identityCreated({ status: "failed" }), false);
  assert.equal(unlockPolicy.authenticationSucceeded({ status: "failed" }), false);
  assert.equal(unlockPolicy.authenticationSucceeded({ status: "cancelled" }), false);
  assert.equal(unlockPolicy.vaultUnlockSucceeded({ status: "failed" }), false);
  assert.equal(unlockPolicy.vaultUnlockSucceeded({ status: "cancelled" }), false);
  assert.equal(unlockPolicy.vaultUnlockSucceeded({ status: "unlocked" }), true);
  assert.match(renderer, /if \(!unlockTransitionPolicy\.identityCreated\(created\)\)[\s\S]*?authenticationSucceeded\(authenticated\)[\s\S]*?vaultUnlockSucceeded\(unlocked\)[\s\S]*?worldTransitionPending = true;/);
  assert.equal((renderer.match(/worldTransitionPending = true;/g) || []).length, 3);
  assert.match(renderer, /class="lock-space unlock-gateway"/);
  assert.match(renderer, /if \(isLockedScreen\(\)\) currentView = "unlock"/);
  const lockedView = renderer.slice(renderer.lastIndexOf("  unlock: () => html`"), renderer.lastIndexOf("  home: () => html`"));
  assert.match(lockedView, /philAvatar\("hero"\)/);
  assert.doesNotMatch(lockedView, /ownerCommitment|accountAddress|balance|technical-panel|Activity|snapshot\.ethereum/);
  assert.match(styles, /\.world-transition \{[\s\S]*?pointer-events: none;/);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(styles, /The renderer remains a presentation layer/);
});

test("PhilUI visual language is bundled locally without changing authority", () => {
  const html = read("src/renderer/index.html");
  const styles = read("src/renderer/styles.css");
  const fontPath = path.join(appRoot, "src/renderer/assets/pixelify-sans-latin-wght-normal.woff2");
  const notices = readRepo("THIRD_PARTY_NOTICES.md");
  const license = readRepo("LICENSES/OFL-1.1-Pixelify-Sans.txt");
  const characterNotice = readRepo("LICENSES/PHIL-BRAND-ASSETS.txt");
  const characterRoot = path.join(appRoot, "src/renderer/assets/characters");
  const characterFiles = fs.readdirSync(characterRoot, { recursive: true })
    .filter((name) => name.endsWith(".png"));
  const renderer = read("src/renderer/app.js");

  assert.match(html, /Your trustworthy digital identity/);
  assert.match(styles, /font-family: "Pixelify Sans"/);
  assert.match(styles, /Final monochrome tokens/);
  assert.match(styles, /--accent: #fff/);
  assert.doesNotMatch(styles, /grayscale\(/);
  assert.match(styles, /filter: saturate\(1\.08\) contrast\(1\.2\) brightness\(\.52\)/);
  assert.match(styles, /clip-path: polygon/);
  assert.equal(fs.statSync(fontPath).isFile(), true);
  assert.match(notices, /Pixelify Sans/);
  assert.match(license, /SIL OPEN FONT LICENSE Version 1\.1/);
  assert.equal(characterFiles.length, 24);
  assert.match(characterNotice, /Copyright \(c\) 2026 Tyler Lengyel/);
  assert.match(renderer, /companionGuideMarkup/);
  assert.doesNotMatch(renderer, /riding_pair|pair_[a-z_]+\.png/);
  assert.doesNotMatch(html, /riding_pair|pair_[a-z_]+\.png/);
  assert.match(renderer, /avastar\/avastar_idle\.png/);
  assert.match(html, /avastar\/avastar_walk_right\.png/);
  assert.match(html, /id="philenator-background"/);
  assert.match(html, /philenator-engine\.js/);

  assert.doesNotMatch(renderer, /PhilUI|github\.com\/lengyeltyler\/PhilUI/);
});

test("local Alpha product cannot reach legacy Sepolia or STWO preparation", () => {
  const renderer = read("src/renderer/app.js");
  const preload = read("src/preload/preload.cjs");
  const main = read("src/main/main.cjs");
  for (const forbidden of [
    "preflightSepoliaUserOperationPreparation",
    "startSepoliaUserOperationPreparation",
    "getSepoliaUserOperationPreparation",
    "finalizeSepoliaSignedArtifact"
  ]) {
    assert.doesNotMatch(renderer, new RegExp(forbidden));
    assert.doesNotMatch(preload, new RegExp(forbidden));
  }
  assert.doesNotMatch(renderer, /Create Ethereum Test Account Action|Experimental Sepolia preparation/);
  assert.match(main, /LOCAL_ALPHA_FORBIDDEN_IPC_CHANNELS/);
  assert.match(main, /ALLOWED_CHANNELS\.filter\(\(channel\) => !LOCAL_ALPHA_FORBIDDEN_IPC_CHANNELS\.has\(channel\)\)/);
  assert.match(main, /for \(const channel of LOCAL_ALPHA_PRODUCT_CHANNELS\)/);
});

test("real Desktop composition requires native Mac user presence", () => {
  const main = read("src/main/main.cjs");
  assert.match(main, /requireNativeUserPresence: !isE2E/);
  assert.doesNotMatch(main, /PHILCORE_REQUIRE_NATIVE_USER_PRESENCE/);
});

test("packaged user journey completes behind the Noir private-proof gate", () => {
  const main = read("src/main/main.cjs");
  const smokeRunner = read("scripts/test-packaged.cjs");
  const runner = read("scripts/test-packaged-user-shell.cjs");
  const lifecycleRunner = read("scripts/test-packaged-action-lifecycle.cjs");
  const journey = main.match(/async function runPackagedUiUserShell[\s\S]*?\n}\n\nfunction approve\(/)?.[0] || "";
  const lifecycle = main.match(/async function runPackagedUiActionLifecycle[\s\S]*?\n}\n\nasync function runPackagedUiUserShell/)?.[0] || "";
  assert.match(journey, /approveLocalSigningAndWaitForCompletion/);
  assert.equal((main.match(/await waitForWorldTransitionHidden\(browserWindow\);/g) || []).length, 2);
  assert.match(main, /async function waitForWorldTransitionHidden\(browserWindow\)[\s\S]*?aria-hidden[\s\S]*?is-opening/);
  assert.match(journey, /proofVerified/);
  assert.match(journey, /signingApprovalCompleted/);
  assert.match(journey, /nullifierConsumed/);
  assert.match(journey, /consumerExecuted/);
  assert.match(runner, /noirProofVerifiedAndActionCompleted/);
  assert.match(runner, /completionAuditRecorded/);
  assert.match(lifecycle, /approveLocalSigningAndWaitForCompletion/);
  assert.match(lifecycle, /signingApprovalCompleted/);
  assert.match(lifecycle, /proofVerified/);
  assert.match(lifecycle, /consumerExecuted/);
  assert.match(lifecycleRunner, /nullifierConsumedLocally/);
  assert.match(lifecycleRunner, /consumerExecutedLocally/);
  assert.match(smokeRunner, /assert\.equal\(created\.demoStatus, "completed"\)/);
  assert.match(smokeRunner, /assert\.equal\(reopened\.demoStatus, "completed"\)/);
  assert.match(smokeRunner, /nullifierConsumedLocally/);
  assert.match(smokeRunner, /consumerExecutedLocally/);
  assert.match(smokeRunner, /assert\.equal\(created\.nullifierConsumed, true\)/);
  assert.match(smokeRunner, /assert\.equal\(created\.consumerExecuted, true\)/);
});

test("package verification binds the embedded manifest to one clean full commit", () => {
  const releaseUtils = read("scripts/release-utils.cjs");
  const packager = read("scripts/package-local.cjs");
  const verifier = read("scripts/verify-package.cjs");
  assert.match(releaseUtils, /\["rev-parse", "HEAD"\]/);
  assert.doesNotMatch(releaseUtils, /\["rev-parse", "--short", "HEAD"\]/);
  assert.match(packager, /embeddedManifestPath/);
  assert.match(packager, /check-o37-1-runtime\.cjs/);
  assert.match(packager, /THIRD_PARTY_NOTICES\.md/);
  assert.match(packager, /verifyNotices\(appPayloadPath\)/);
  assert.match(read("scripts/distribution-notices.cjs"), /OFL-1\.1-Pixelify-Sans\.txt/);
  assert.match(read("scripts/distribution-notices.cjs"), /PHIL-BRAND-ASSETS\.txt/);
  assert.match(packager, /directorySize\(appBundlePath\)/);
  assert.match(packager, /release_manifest_app_size_did_not_stabilize/);
  assert.doesNotMatch(packager, /writeJson\(manifestPath, manifest\)/);
  assert.match(verifier, /readJson\(embeddedManifestPath\)/);
  assert.match(verifier, /source_commit_must_be_full_sha/);
  assert.match(verifier, /source_commit_mismatch/);
  assert.match(verifier, /source_tree_must_be_clean_at_build/);
  assert.match(verifier, /source_tree_changed_path_count_must_be_zero/);
  assert.match(verifier, /app_size_mismatch/);
  assert.match(verifier, /node_version_mismatch/);
  assert.match(verifier, /npm_version_mismatch/);
  assert.match(verifier, /pixelify_ofl_license/);
  assert.match(verifier, /phil_brand_assets_notice/);
  assert.match(verifier, /writeJson\(path\.join\(releaseRoot, "philcore-desktop-package-verification\.json"\), result\)/);
  assert.doesNotMatch(verifier, /writeJson\(path\.join\(repoRoot, "config", "release"/);
  assert.doesNotMatch(verifier, /const manifest = loadManifest\(\)/);
});

test("World ID remains an inert optional credential preview", () => {
  const providers = loadExternalCredentialProviders();
  const worldId = providers.getById("world-id");
  assert.equal(worldId.identityRootAuthority, false);
  assert.equal(worldId.remoteSdkLoaded, false);
  assert.equal(worldId.networkRequestsEnabled, false);
  assert.equal(providers.identityRootProvider, "philcore");
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /Connect World ID/);
  assert.match(renderer, /It is not the PhilCore identity root/);
  assert.match(renderer, /No World ID request occurs in this Beta/);
});

test("Trending is a bundled demonstration rather than live popularity data", () => {
  const discovery = loadDiscovery();
  assert.equal(discovery.liveTrending, false);
  assert.equal(discovery.remoteAccessEnabled, false);
  assert.deepEqual(Array.from(discovery.items, (item) => item.name), [
    "Collectible Gallery",
    "Identity Community"
  ]);
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /<h3>Trending<\/h3>/);
  assert.match(renderer, /Demo examples/);
  assert.match(renderer, /does not open a website, query live data, show prices, or perform a transaction/);
});

test("chain destinations separate Ethereum local action from previews", () => {
  const renderer = read("src/renderer/app.js");
  const chainViewStart = renderer.indexOf("  chain: () => {");
  const chainViewEnd = renderer.indexOf("  audit: () => {", chainViewStart);
  assert.ok(chainViewStart >= 0 && chainViewEnd > chainViewStart);
  const chainView = renderer.slice(chainViewStart, chainViewEnd);
  assert.match(renderer, /currentView = "chain"/);
  assert.match(chainView, /\$\{sepoliaMintPanel\(\)\.__html\}/);
  assert.match(renderer, /protectedActionPanel\("ethereum"\)/);
  assert.match(renderer, /Run local demonstration/);
  assert.match(renderer, /planned but not active in this Beta/);
  assert.match(renderer, /Public account connection/);
  assert.match(renderer, /Nothing is sent publicly/);
  assert.match(renderer, /View Beta account/);
  assert.match(renderer, /Create account/);
  assert.match(renderer, /No seed phrase, new account, or public transaction is created from this read-only view/);
  assert.match(renderer, /!ethereum \? raw\(`<span class="chain-status preview">Preview<\/span>`\) : raw\(""\)/);
});

test("Sepolia authorization and signed-operation details render as trusted markup", () => {
  const renderer = read("src/renderer/app.js");
  const panelStart = renderer.indexOf("function sepoliaMintPanel()");
  const panelEnd = renderer.indexOf("function stopSepoliaMintPolling()", panelStart);
  assert.ok(panelStart >= 0 && panelEnd > panelStart);
  const panel = renderer.slice(panelStart, panelEnd);
  assert.match(panel, /<dl class="approval-grid inline-summary" aria-label="Authorization summary">/);
  assert.match(panel, /details\("Details", kv\(\[[\s\S]*?\]\)\)\.__html/);
  assert.match(panel, /details\("Signed operation", kv\(\[[\s\S]*?\]\)\)\.__html/);
  assert.doesNotMatch(panel, /\$\{details\([^}]+\)\}/);
});

test("STARK and Sepolia readiness documents match inspected implementation", () => {
  const role = readRepo("docs/reference/STARK_ROLE_AND_BINDINGS.md");
  const onchain = readRepo("docs/reference/ONCHAIN_STARK_VERIFICATION_ASSESSMENT.md");
  const readiness = readRepo("docs/reference/SEPOLIA_ACCOUNT_READINESS.md");
  const pq = readRepo("docs/reference/PQ_MIGRATION_READINESS.md");
  const plan = readRepo("docs/reference/SEPOLIA_EXECUTION_PLAN.md");
  const proof = readRepo("proving/src/unlock_statement.rs");
  const account = readRepo("contracts/base/erc4337/PhilCore4337Account.sol");
  const gate = readRepo("config/security/philcore-base-sepolia-beta-security-gate.json");

  assert.match(proof, /Blake2sM31Channel/);
  assert.match(role, /does not unlock the Device Vault/);
  assert.match(role, /not a proof public input/);
  assert.match(onchain, /17,127,260/);
  assert.match(onchain, /no-go for direct trustless Base verification/);
  assert.match(account, /PackedUserOperation/);
  assert.match(account, /approvedActionGate/);
  assert.match(plan, /chainId 84532/);
  assert.match(readiness, /ACP-0002 remains `Proposed`/);
  assert.match(gate, /"status": "blocked"/);
  assert.match(pq, /future PQ validator can preserve the private Phil identity/);
  assert.match(pq, /explicitly migrating the affected scoped\s+account binding/);
  assert.match(plan, /paymaster disabled/);
  assert.doesNotMatch(plan, /private key\s*=/i);
});

test("Settings relocates identity trust recovery and security", () => {
  const renderer = read("src/renderer/app.js");
  for (const section of ["General", "Identity", "Trust", "Recovery", "Security"]) {
    assert.match(renderer, new RegExp(`"${section.toLowerCase()}", "${section}"`));
  }
  assert.match(renderer, /Phil name/);
  assert.match(renderer, /Trusted devices and credentials/);
  assert.match(renderer, /Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared/);
  assert.match(renderer, /Protected Mac unlock/);
  assert.match(renderer, /Developer tools/);
  assert.match(renderer, /isTechnicalMode\(\) && developerSurfacesAllowed\(\) && snapshot\.settings\.developerModeVisible/);
  assert.match(renderer, /same-Mac engineering fallback is local test infrastructure/);
  assert.match(renderer, /Future recovery engineering controls are intentionally absent from the ordinary Beta interface/);
  assert.match(renderer, /PACKAGED_IDENTITY_MISMATCH/);
  assert.match(renderer, /Unsigned test-build limitation/);
});

test("Activity separates recent display from complete available history", () => {
  const renderer = read("src/renderer/app.js");
  const runtime = read("src/main/runtime-host.cjs");
  assert.match(renderer, /snapshot\.audit\.history/);
  assert.match(renderer, /activityVisibleCount/);
  assert.match(renderer, /Load older/);
  assert.match(runtime, /history: \[\.\.\.auditEvents, \.\.\.registryAuditEvents\(\)\]/);
  assert.doesNotMatch(runtime, /auditEvents\.length > 120/);
});

test("technical information remains available without a second authority path", () => {
  const renderer = read("src/renderer/app.js");
  for (const term of ["Owner commitment", "Evidence class", "Proof type", "Workflow stages", "Bundle ID", "Gatekeeper"]) {
    assert.match(renderer, new RegExp(term));
  }
  assert.match(renderer, /technical-panel/);
  assert.match(renderer, /startProtectedLocalAction/);
  assert.doesNotMatch(renderer, /window\.confirm|window\.prompt|window\.alert/);
});

test("protected action lifecycle guardrails remain intact", () => {
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /PROTECTED_ACTION_TRANSITIONS/);
  assert.match(renderer, /PROTECTED_ACTION_TIMEOUTS_MS/);
  assert.match(renderer, /data-progress-action="cancel"/);
  assert.match(renderer, /late_result_after_action_invalidated/);
  assert.match(renderer, /Protected Mac unlock is not set up yet/);
  assert.match(renderer, /Protected action timed out/);
  assert.match(renderer, /Review a protected local action/);
  assert.match(renderer, /data-approval-action="approve"/);
  assert.match(renderer, /data-approval-action="deny"/);
  assert.match(renderer, /data-approval-action="cancel"/);
  assert.match(renderer, /Protected identity check stopped/);
  assert.match(renderer, /available proof could expose protected information/);
  assert.match(renderer, /ask again before protected signing/);
  assert.match(renderer, /generates and independently verifies a Noir UltraKeccakZK proof/);
  assert.match(renderer, /Protected Mac key unavailable/);
  assert.match(renderer, /earlier unsigned Alpha build/);
  assert.match(renderer, /will not weaken or replace the protected key automatically/);
  assert.doesNotMatch(renderer, /Unlock with this Mac failed/);
});

test("renderer loads catalog and presentation before application", () => {
  const html = read("src/renderer/index.html");
  assert.ok(html.indexOf("startup-guard.js") < html.indexOf("presentation.js"));
  assert.ok(html.indexOf("presentation.js") < html.indexOf("phil-preview-provider.js"));
  assert.ok(html.indexOf("phil-preview-provider.js") < html.indexOf("external-credential-provider.js"));
  assert.ok(html.indexOf("external-credential-provider.js") < html.indexOf("ecosystem-discovery.js"));
  assert.ok(html.indexOf("ecosystem-discovery.js") < html.indexOf("chain-catalog.js"));
  assert.ok(html.indexOf("sepolia-mint-ui.cjs") < html.indexOf("app.js"));
  assert.ok(html.indexOf("unlock-transition-policy.cjs") < html.indexOf("app.js"));
  assert.ok(html.indexOf("chain-catalog.js") < html.indexOf("app.js"));
});

test("renderer keeps secret-shaped fields out of visible code", () => {
  const combined = `${read("src/renderer/app.js")}\n${read("src/renderer/presentation.js")}`;
  for (const token of ["privateKey", "vaultKey", "wrappingKey", "nullifierSeed", "mnemonic", "seedPhrase"]) {
    assert.equal(combined.includes(token), false, `${token} should not appear in renderer copy`);
  }
  assert.match(combined, /Nothing was sent publicly|Nothing is sent publicly/);
});

test("renderer has guardrails against object artifacts", () => {
  const renderer = read("src/renderer/app.js");
  const main = read("src/main/main.cjs");
  assert.match(renderer, /function displayValue/);
  assert.match(renderer, /Object\.prototype\.hasOwnProperty\.call\(value, "__html"\)/);
  assert.match(renderer, /details available/);
  assert.match(renderer, /\[rendered content\]/);
  assert.doesNotMatch(renderer, /\[object Object\]/);
  assert.match(renderer, /\]\)\.__html\}/);
  assert.match(renderer, /\)\.__html\}/);
  assert.match(renderer, /function technicalReleasePanel\(\)[\s\S]*?\]\)\.__html\}/);
  assert.match(main, /querySelector\("\.settings-layout"\)/);
});

test("terminal routine state is replaced instead of mutating frozen projections", () => {
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /function setRoutineAuthorizationNotice\(notice\)/u);
  assert.match(renderer, /routineAuthorizationUi = \{ \.\.\.routineAuthorizationUi, notice \}/u);
  assert.doesNotMatch(renderer, /routineAuthorizationUi\.[A-Za-z0-9_]+\s*=(?!=)/u);
});
