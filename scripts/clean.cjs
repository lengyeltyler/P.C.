"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const PRESERVED_ARTIFACT_NAMES = Object.freeze([
  "philcore-controlled-sepolia-beta"
]);

function assertScopedRoot(root) {
  const resolved = path.resolve(root);
  if (resolved === path.parse(resolved).root || resolved === path.resolve(require("node:os").homedir())) {
    throw new Error("PHILCORE_CLEAN_ROOT_UNSAFE");
  }
  return resolved;
}

function cleanBuildOutputs(root = ROOT) {
  const scopedRoot = assertScopedRoot(root);
  const artifacts = path.join(scopedRoot, "artifacts");
  const preserved = new Set(PRESERVED_ARTIFACT_NAMES);
  if (fs.existsSync(artifacts)) {
    for (const entry of fs.readdirSync(artifacts, { withFileTypes: true })) {
      if (!preserved.has(entry.name)) {
        fs.rmSync(path.join(artifacts, entry.name), { recursive: true, force: true });
      }
    }
  }
  fs.rmSync(path.join(scopedRoot, "cache"), { recursive: true, force: true });
}

if (require.main === module) cleanBuildOutputs();

module.exports = { PRESERVED_ARTIFACT_NAMES, cleanBuildOutputs };
