#!/usr/bin/env node
const fs = require("node:fs");
const { run, sha256, userPresenceHelperPaths, writeJson, repoRoot } = require("./release-utils.cjs");
const path = require("node:path");

if (process.platform !== "darwin") {
  console.log(JSON.stringify({
    status: "unsupported_platform",
    reason: "macos_local_authentication_helper_is_macos_only"
  }, null, 2));
  process.exit(0);
}

const helper = userPresenceHelperPaths();
fs.mkdirSync(path.dirname(helper.source), { recursive: true });
run("swiftc", [
  helper.swiftSource,
  "-framework",
  "LocalAuthentication",
  "-O",
  "-o",
  helper.source
], { stdio: "inherit" });
fs.chmodSync(helper.source, 0o755);
const result = {
  phase: "O.7",
  status: "built",
  helperPath: path.relative(repoRoot, helper.source),
  sha256: sha256(helper.source),
  biometricDataReturned: false,
  rawAuthenticationMaterialReturned: false
};
writeJson(path.join(repoRoot, "config", "release", "philcore-desktop-user-presence-helper.json"), result);
console.log(JSON.stringify(result, null, 2));
