const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appRoot = path.resolve(__dirname, "..");
const guardSource = fs.readFileSync(path.join(appRoot, "src", "renderer", "startup-guard.js"), "utf8");

function loadGuard(philcore) {
  const context = { window: { philcore }, Error, Object };
  vm.runInNewContext(guardSource, context, { filename: "startup-guard.js" });
  return context.window.PhilCoreRendererStartup;
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

test("renderer blocks startup when preload namespace is absent", () => {
  const guard = loadGuard(undefined);
  assert.throws(
    () => guard.requireBridge(),
    /PHILCORE_PRELOAD_BRIDGE_UNAVAILABLE.*window\.philcore.*startup is blocked/u
  );
});

test("renderer reports an incomplete preload API precisely", () => {
  const guard = loadGuard({ runtime: {} });
  assert.throws(
    () => guard.requireBridge(),
    /window\.philcore\.runtime\.getSnapshot/u
  );
});

test("renderer starts only with the expected preload runtime method", () => {
  const bridge = { runtime: { getSnapshot() {} } };
  assert.equal(loadGuard(bridge).requireBridge(), bridge);
});

test("startup guard loads before the renderer application", () => {
  const html = fs.readFileSync(path.join(appRoot, "src", "renderer", "index.html"), "utf8");
  assert.ok(html.indexOf("startup-guard.js") < html.indexOf("app.js"));
  const renderer = fs.readFileSync(path.join(appRoot, "src", "renderer", "app.js"), "utf8");
  assert.match(renderer, /PhilCoreRendererStartup\.requireBridge\(\)/u);
  assert.match(renderer, /console\.error\(/u);
  assert.doesNotMatch(renderer, /window\.philcore\.runtime\.getSnapshot\(\)/u);
});
