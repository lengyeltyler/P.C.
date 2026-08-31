const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const appRoot = path.resolve(__dirname, "..");
const releaseModulePath = path.join(appRoot, "src/main/controlled-beta-release-state.cjs");
const { CONTROLLED_BETA_RELEASE_STATE: beta, controlledBetaReleaseState } = require(releaseModulePath);

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

test("canonical controlled Beta projection is exact, immutable, and read-only", () => {
  assert.strictEqual(controlledBetaReleaseState(), beta);
  assert.equal(Object.isFrozen(beta), true);
  assert.equal(Object.isFrozen(beta.evidence.P5), true);
  assert.deepEqual(
    [beta.productStage, beta.status, beta.environment.network, beta.environment.chainId],
    ["Controlled Sepolia Beta", "completed", "Ethereum Sepolia", "11155111"]
  );
  assert.deepEqual(
    [beta.environment.mainnet, beta.environment.meaningfulAssetsAllowed, beta.environment.productionCustody, beta.environment.postQuantumSecure],
    [false, false, false, false]
  );
  assert.deepEqual(
    [beta.account.finalNonce, beta.account.nativeBalanceWei, beta.account.entryPointDepositWei, beta.account.passBalance],
    ["3", "0", "1297280743685756", "2"]
  );
  assert.deepEqual(beta.milestones.map(({ id, status }) => [id, status]), [
    ["P2", "completed"], ["P3", "completed"], ["P5", "completed"]
  ]);
  assert.equal(beta.reconciliation.status, "successful");
  assert.deepEqual(
    [beta.evidence.P5.lineage, beta.evidence.P5.submissions, beta.evidence.P5.retries, beta.evidence.P5.additionalFundingWei],
    ["p5-attempt-0002", 1, 0, "0"]
  );
  assert.equal(beta.recovery.availableInBeta, false);
  assert.equal(beta.recovery.summary, "Recovery is intentionally unavailable in this Controlled Sepolia Beta.");
  assert.doesNotMatch(read("src/main/controlled-beta-release-state.cjs"), /require\(["']node:(?:fs|path)["']\)|\.philcore-local|receipt-v2/u);
});

test("public projection excludes secret classes and authenticated infrastructure", () => {
  const serialized = JSON.stringify(beta);
  for (const forbidden of [
    /private.?key/iu,
    /api.?key/iu,
    /rpc.?url/iu,
    /authenticated.?url/iu,
    /witness/iu,
    /phil.?secret/iu,
    /nullifier.?seed/iu,
    /device.?vault/iu,
    /recovery.?secret/iu,
    /approval.?phrase/iu
  ]) assert.doesNotMatch(serialized, forbidden);
});

test("runtime exposes one frozen projection through the existing snapshot", () => {
  const runtime = read("src/main/runtime-host.cjs");
  assert.match(runtime, /require\("\.\/controlled-beta-release-state\.cjs"\)/u);
  assert.match(runtime, /controlledBeta: controlledBetaReleaseState\(\)/u);
});

test("ordinary Desktop shell states the Beta and safety boundaries", () => {
  const html = read("src/renderer/index.html");
  const renderer = read("src/renderer/app.js");
  const presentation = read("src/renderer/presentation.js");
  const catalog = read("src/renderer/chain-catalog.js");
  const releaseProfile = JSON.parse(read("build/release-profiles.json"));
  assert.equal(releaseProfile.displayName, "Phil — Controlled Sepolia Beta");
  assert.match(html, /Phil — Controlled Sepolia Beta/u);
  assert.match(html, /Ethereum Sepolia · Test only/u);
  assert.match(renderer, /current authorization uses classical cryptography and is not currently post-quantum secure/u);
  assert.match(renderer, /Local demonstrations do not create a new public transaction/u);
  assert.match(renderer, /protected local action/u);
  assert.match(renderer, /not mainnet, meaningful-asset use, or production custody/u);
  assert.match(renderer, /P2 issued the first harmless test pass/u);
  assert.match(renderer, /P3 issued the second harmless test pass/u);
  assert.match(renderer, /P5 completed with one submission, no retry, and no new funding/u);
  assert.doesNotMatch(renderer, /controlledBetaAdvancedEvidence\(\)\.__html/u);
  assert.match(renderer, /beta\.reconciliation\.summary/u);
  assert.match(beta.reconciliation.summary, /bundler, primary Sepolia provider, and independent provider agreed/u);
  assert.match(presentation, /Controlled Sepolia Beta/u);
  assert.match(presentation, /Beta verified/u);
  assert.match(catalog, /Sepolia Beta/u);
  assert.match(catalog, /deployed-testnet/u);
});

test("ordinary recovery is informational and has no recovery mutation control", () => {
  const renderer = read("src/renderer/app.js");
  const activeViews = renderer.slice(renderer.indexOf("Object.assign(views, {"));
  const recovery = activeViews.match(/recovery: \(\) => html`([\s\S]*?)`,\n  audit:/u)?.[1] || "";
  assert.match(recovery, /Recovery later/u);
  assert.match(recovery, /Recovery is intentionally outside this Controlled Sepolia Beta/u);
  assert.doesNotMatch(recovery, /data-action="(?:recovery|startRecovery|approveRecovery|enrollRecovery)/iu);
  assert.match(renderer, /This screen cannot enroll a recovery factor or approve a recovery request/u);
  assert.match(renderer, /Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared/u);
});

test("normal setup and locked actions cannot imply authorization", () => {
  const renderer = read("src/renderer/app.js");
  assert.match(renderer, /isTechnicalMode\(\) \? raw\(`<label class="check-row"><input id="create-recovery" type="checkbox">/u);
  assert.match(renderer, /if \(!unlocked\) return "locked"/u);
  assert.match(renderer, /guidanceForStage\(routineGuidanceStage/u);
  assert.match(renderer, /data-action="routineAuthorizationBegin"[^>]*\$\{!unlocked[^}]*\? "disabled"/u);
  assert.match(renderer, /Unlock your Phil identity before preparing a local authorization demonstration/u);
  assert.match(renderer, /No public submission/u);
  assert.match(renderer, /It does not recreate or submit the completed P2, P3, or P5 Beta actions/u);
});
