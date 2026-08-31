const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { bundlePreload } = require("../scripts/bundle-preload.cjs");

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

test("sandbox preload bundles every local CommonJS dependency", () => {
  const output = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "philcore-preload-bundle-")), "preload.cjs");
  bundlePreload(output);
  const bundled = fs.readFileSync(output, "utf8");
  assert.doesNotMatch(bundled, /require\(["']\.\.\/shared\/bridge-contract\.cjs["']\)/u);
  assert.match(bundled, /philcore:state:getSnapshot/u);
  assert.match(bundled, /exposeInMainWorld/u);
});

test("source preload dependency path exists with exact casing", () => {
  const sourcePreload = path.resolve(__dirname, "..", "src", "preload", "preload.cjs");
  const bridge = path.resolve(path.dirname(sourcePreload), "../shared/bridge-contract.cjs");
  assert.ok(fs.existsSync(sourcePreload));
  assert.ok(fs.existsSync(bridge));
  assert.equal(path.basename(bridge), "bridge-contract.cjs");
});

test("bundled preload no longer exposes the retired assertion oracle", () => {
  const output = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "philcore-preload-bundle-")), "preload.cjs");
  bundlePreload(output);
  const bundled = fs.readFileSync(output, "utf8");
  assert.doesNotMatch(bundled, /requestAssertion/u);
  assert.doesNotMatch(bundled, /philcore:recoveryEnrollment:requestAssertion/u);
  assert.match(bundled, /philcore:state:getSnapshot/u);
  assert.match(bundled, /exposeInMainWorld/u);
});
