#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const { appPayloadPath } = require("./release-utils.cjs");

function verifyPackagedPreload(payloadRoot = appPayloadPath) {
  const preloadPath = path.join(payloadRoot, "apps", "philcore-desktop", "src", "preload", "preload.cjs");
  const bridgeContractPath = path.join(payloadRoot, "apps", "philcore-desktop", "src", "shared", "bridge-contract.cjs");

  assert.ok(fs.existsSync(preloadPath), `Packaged preload missing: ${preloadPath}`);
  assert.ok(fs.existsSync(bridgeContractPath), `Packaged bridge contract missing: ${bridgeContractPath}`);

  const resolvedBridge = createRequire(preloadPath).resolve("../shared/bridge-contract.cjs");
  assert.equal(resolvedBridge, bridgeContractPath, "Bridge contract must resolve from the packaged preload location");

  const preload = fs.readFileSync(preloadPath, "utf8");
  assert.doesNotMatch(
    preload,
    /require\(["']\.\.\/shared\/bridge-contract\.cjs["']\)/u,
    "Packaged sandbox preload must not depend on a relative CommonJS require"
  );

  let exposed = null;
  const invocations = [];
  const context = {
    require(request) {
      assert.equal(request, "electron", `Sandboxed preload imported unsupported module: ${request}`);
      return {
        contextBridge: {
          exposeInMainWorld(name, value) {
            exposed = { name, value };
          }
        },
        ipcRenderer: {
          invoke(...args) {
            invocations.push(args);
            return { invoked: true };
          }
        }
      };
    },
    console,
    process: { env: {} },
    Buffer,
    setImmediate,
    clearImmediate,
    setTimeout,
    clearTimeout
  };
  vm.runInNewContext(preload, context, { filename: preloadPath });

  assert.equal(exposed?.name, "philcore", "Preload must expose only the PhilCore bridge namespace");
  assert.equal(typeof exposed?.value?.runtime?.getSnapshot, "function", "Runtime bridge must be exposed");
  assert.deepEqual(exposed.value.runtime.getSnapshot(), { invoked: true });
  assert.equal(invocations.length, 1);
  assert.equal(invocations[0][0], "philcore:state:getSnapshot");
  assert.equal(JSON.stringify(invocations[0][1]), "{}");

  return {
    preloadPath,
    bridgeContractPath,
    bridgeContractResolved: true,
    sandboxBundleExecuted: true,
    namespace: exposed.name
  };
}

if (require.main === module) {
  console.log(JSON.stringify({ status: "passed", ...verifyPackagedPreload() }, null, 2));
}

module.exports = { verifyPackagedPreload };
