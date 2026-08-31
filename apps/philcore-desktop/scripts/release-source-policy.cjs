"use strict";
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");
const esbuild = require("esbuild");

const FIXTURE_FACTORIES = new Set([
  "createFixturePlatformKeyAdapter", "createFixtureMacOsUserPresenceProvider"
]);
const RELEASE_SOURCE_FILES = ["main.cjs", "runtime-host.cjs", "macos-user-presence.cjs"];

// This is a package-time removal of existing development paths, not a second
// Runtime. All normal product branches come from the same reviewed source.
function releaseSource(filename, source) {
  const ast = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const result = ts.transform(ast, [(context) => {
    const visit = (node) => {
      if (ts.isFunctionDeclaration(node) && FIXTURE_FACTORIES.has(node.name?.text)) return undefined;
      if (ts.isShorthandPropertyAssignment(node) && FIXTURE_FACTORIES.has(node.name.text)) return undefined;
      if (ts.isBindingElement(node) && FIXTURE_FACTORIES.has(node.name.text)) return undefined;
      if (filename === "main.cjs" && ts.isIdentifier(node) && node.text === "isE2E") {
        if (ts.isVariableDeclaration(node.parent) && node.parent.name === node) return node;
        return ts.factory.createFalse();
      }
      if (filename === "main.cjs" && ts.isVariableDeclaration(node) && node.name.getText(ast) === "isE2E") {
        return ts.factory.updateVariableDeclaration(node, node.name, undefined, undefined, ts.factory.createFalse());
      }
      return ts.visitEachChild(node, visit, context);
    };
    return (root) => ts.visitNode(root, visit);
  }]);
  const printed = ts.createPrinter().printFile(result.transformed[0]);
  result.dispose();
  const output = esbuild.transformSync(printed, {
    loader: "js", format: "cjs", platform: "node", target: "node24",
    treeShaking: true, minifySyntax: true, legalComments: "inline"
  }).code;
  for (const forbidden of [
    ...FIXTURE_FACTORIES, "philcore-desktop-e2e-platform-key",
    "philcore-desktop-fixture-platform-key", "philcore-o41-e2e-safe-storage-adapter"
  ]) {
    if (output.includes(forbidden)) throw new Error(`release_fixture_source_remains:${filename}`);
  }
  if (filename === "main.cjs" && !output.includes("releaseEnvironmentError")) {
    throw new Error("release_startup_guard_missing");
  }
  return output;
}

function writeReleaseSources(repoRoot, payloadRoot) {
  const relative = "apps/philcore-desktop/src/main";
  for (const filename of RELEASE_SOURCE_FILES) {
    fs.writeFileSync(path.join(payloadRoot, relative, filename),
      releaseSource(filename, fs.readFileSync(path.join(repoRoot, relative, filename), "utf8")));
  }
}

module.exports = { FIXTURE_FACTORIES, RELEASE_SOURCE_FILES, releaseSource, writeReleaseSources };
