"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const ts = require("typescript");
const { releaseEnvironmentError, RELEASE_TEST_SELECTOR_ERROR } = require("../src/main/release-environment.cjs");
const { releaseSource, RELEASE_SOURCE_FILES } = require("../scripts/release-source-policy.cjs");
const root = path.resolve(__dirname, "../src/main");

for (const name of ["PHILCORE_DESKTOP_E2E", "PHILCORE_DESKTOP_E2E_UI_UNLOCK_FLOW",
  "PHILCORE_DESKTOP_E2E_ROUTINE_UNAVAILABLE", "PHILCORE_DESKTOP_DEV", "PHILCORE_UI_TEST_STATE",
  "PHILCORE_MACOS_USER_PRESENCE_HELPER", "PHILCORE_MACOS_USER_PRESENCE_HELPER_SHA256"]) {
  test(`Release rejects inherited selector ${name}, including disabled-looking values`, () => {
    for (const value of ["1", "0", "", "do-not-echo-this-value"]) {
      assert.equal(releaseEnvironmentError({ packaged: true, env: { [name]: value } }), RELEASE_TEST_SELECTOR_ERROR);
    }
    assert.equal(releaseEnvironmentError({ packaged: false, env: { [name]: "1" } }), null);
  });
}
test("Release rejects test argv and accepts an ordinary real-auth launch", () => {
  for (const arg of ["--philcore-e2e", "--philcore-ui-test-state=ready", "--test-auth=fixture", "--fixture"]) {
    assert.equal(releaseEnvironmentError({ packaged: true, argv: ["Phil", arg] }), RELEASE_TEST_SELECTOR_ERROR);
  }
  assert.equal(releaseEnvironmentError({ packaged: true, env: { PATH: "/usr/bin" }, argv: ["Phil"] }), null);
});
test("Release package removes fixture factories, keys, and E2E scenarios", () => {
  for (const name of RELEASE_SOURCE_FILES) {
    const code = releaseSource(name, fs.readFileSync(path.join(root, name), "utf8"));
    new vm.Script(code, { filename: name });
    assert.doesNotMatch(code, /createFixturePlatformKeyAdapter|createFixtureMacOsUserPresenceProvider|philcore-o41-e2e-safe-storage-adapter|philcore-desktop-e2e-platform-key/u);
    if (name === "main.cjs") {
      assert.doesNotMatch(code, /runPackagedUi|PHILCORE_DESKTOP_E2E/u);
      assert.match(code, /createElectronSafeStoragePlatformKeyAdapter/u);
      assert.match(code, /createMacOsLocalAuthenticationProvider/u);
      assert.match(code, /requireNativeUserPresence: !0/u);
    }
  }
});
test("Release entry rejects a selector before Runtime, storage, or auth can load", () => {
  const source = releaseSource("main.cjs", fs.readFileSync(path.join(root, "main.cjs"), "utf8"));
  const seen = []; const stop = new Error("expected_exit");
  const mockProcess = { env: { PHILCORE_DESKTOP_E2E: "1" }, argv: ["Phil"], stderr: { write: (s) => seen.push(s) }, exit: () => { throw stop; } };
  assert.throws(() => vm.runInNewContext(source, {
    process: mockProcess,
    require: (name) => {
      if (name.startsWith("node:")) return require(name);
      if (name === "electron") return { app: { isPackaged: true, exit: (code) => { assert.equal(code, 78); throw stop; } } };
      if (name === "./release-environment.cjs") return { releaseEnvironmentError };
      assert.fail(`product module loaded before rejection: ${name}`);
    }
  }), (error) => error === stop);
  assert.deepEqual(seen, [RELEASE_TEST_SELECTOR_ERROR + "\n"]);
});
test("The real auth providers and native-presence requirement survive release compilation", () => {
  const source = releaseSource("main.cjs", fs.readFileSync(path.join(root, "main.cjs"), "utf8"));
  const ast = ts.createSourceFile("release.cjs", source, ts.ScriptTarget.Latest, true);
  const code = ast.statements.find((n) => ts.isFunctionDeclaration(n) && n.name.text === "createHost").getText(ast);
  let captured;
  vm.runInNewContext(code + "\ncreateHost();", {
    __dirname: "/isolated/src/main", path, app: { getPath: () => "/isolated" }, isDevelopment: false, safeStorage: {},
    createDesktopRuntimeHost: (options) => (captured = options, {}),
    createElectronSafeStoragePlatformKeyAdapter: () => ({ kind: "real_safe_storage" }),
    createMacOsLocalAuthenticationProvider: () => ({ kind: "real_native_auth" }),
    createNoirRootProofStack: () => ({}), createRoutineAuthorizationIpc: () => ({}),
    createRetryingRoutineAuthorizationProductHost: () => ({}), createQrDataUrl: () => {}, process: { platform: "darwin" }
  });
  assert.equal(captured.platformKeyAdapter.kind, "real_safe_storage");
  assert.equal(captured.userPresenceProvider.kind, "real_native_auth");
  assert.equal(captured.requireNativeUserPresence, true);
});
