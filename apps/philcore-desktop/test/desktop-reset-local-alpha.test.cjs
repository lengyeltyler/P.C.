const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const script = path.join(repoRoot, "apps", "philcore-desktop", "scripts", "reset-local-alpha-data.cjs");

function run(userDataDir, extraEnv = {}) {
  const result = spawnSync(process.execPath, [script], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PHILCORE_DESKTOP_USER_DATA_DIR: userDataDir,
      ...extraEnv
    }
  });
  assert.equal(result.stderr, "");
  assert.equal(result.status, 0);
  return JSON.parse(result.stdout);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-reset-test-"));
const prefs = path.join(root, "philcore-desktop-preferences.json");
const identities = path.join(root, "philcore-local-identities");
fs.mkdirSync(identities, { recursive: true });
fs.writeFileSync(prefs, "{}\n");
fs.writeFileSync(path.join(identities, "sentinel.txt"), "test");

const dry = run(root);
assert.equal(dry.status, "approval_required");
assert.equal(dry.approved, false);
assert.equal(fs.existsSync(prefs), true);
assert.equal(fs.existsSync(identities), true);
assert.equal(dry.removesPackagedApplication, false);
assert.equal(dry.removesSourceCode, false);
assert.equal(dry.removesKeychainItems, false);

const reset = run(root, { PHILCORE_DESKTOP_RESET_LOCAL_ALPHA_APPROVED: "1" });
assert.equal(reset.status, "reset_performed");
assert.equal(reset.approved, true);
assert.equal(fs.existsSync(prefs), false);
assert.equal(fs.existsSync(identities), false);
assert.equal(reset.targets.every((target) => path.resolve(target).startsWith(`${path.resolve(root)}${path.sep}`)), true);

console.log("ok - guarded local Alpha reset is explicit and scoped");
