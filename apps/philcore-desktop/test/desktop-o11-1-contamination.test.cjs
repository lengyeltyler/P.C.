#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  ELECTRON_FRAMEWORK_SYMLINKS,
  auditArchive,
  auditFilesystem,
  debrisReason
} = require("../scripts/release-contamination-audit.cjs");
const { createCleanZip, extractCleanZip } = require("../scripts/release-utils.cjs");

function makeApp(root) {
  const app = path.join(root, "Fixture.app");
  const framework = path.join(app, "Contents", "Frameworks", "Electron Framework.framework");
  const version = path.join(framework, "Versions", "A");
  for (const entry of Object.keys(ELECTRON_FRAMEWORK_SYMLINKS)) fs.mkdirSync(path.join(version, entry), { recursive: true });
  fs.symlinkSync("A", path.join(framework, "Versions", "Current"));
  for (const [entry, target] of Object.entries(ELECTRON_FRAMEWORK_SYMLINKS)) fs.symlinkSync(target, path.join(framework, entry));
  return { app, framework };
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-appledouble-regression-"));
const { app, framework } = makeApp(root);
assert.equal(auditFilesystem(app, { stage: "clean_fixture" }).pass, true);

const fixture = path.join(__dirname, "fixtures", "appledouble", "._Helpers");
fs.copyFileSync(fixture, path.join(framework, "._Helpers"));
const contaminatedApp = auditFilesystem(app, { stage: "contaminated_fixture" });
assert.equal(contaminatedApp.pass, false);
assert.ok(contaminatedApp.findings.some((entry) => entry.reason === "appledouble"));
assert.ok(contaminatedApp.findings.some((entry) => entry.reason === "unexpected_electron_framework_root_entry"));

const zip = path.join(root, "contaminated.zip");
const zipped = spawnSync("/usr/bin/zip", ["-q", "-r", "-y", zip, path.basename(app)], { cwd: root, encoding: "utf8" });
assert.equal(zipped.status, 0, zipped.stderr);
const contaminatedArchive = auditArchive(zip, { stage: "contaminated_zip_fixture" });
assert.equal(contaminatedArchive.pass, false);
assert.ok(contaminatedArchive.findings.some((entry) => entry.location === "archive" && entry.reason === "appledouble"));

fs.unlinkSync(path.join(framework, "._Helpers"));
fs.writeFileSync(path.join(framework, "unexpected.txt"), "unexpected framework root content\n");
const unexpectedRoot = auditFilesystem(app, { stage: "framework_allowlist_fixture" });
assert.ok(unexpectedRoot.findings.some((entry) => entry.reason === "unexpected_electron_framework_root_entry"));
fs.unlinkSync(path.join(framework, "unexpected.txt"));

const cleanZip = path.join(root, "clean-norsrc.zip");
const cleanArchive = createCleanZip(app, cleanZip, "clean_norsrc_fixture");
assert.equal(cleanArchive.pass, true);
for (const method of ["ditto", "unzip"]) {
  const destination = path.join(root, `clean-${method}`);
  const extracted = extractCleanZip(cleanZip, destination, "clean_norsrc_fixture", method);
  assert.equal(auditFilesystem(extracted, { stage: `clean_${method}_fixture` }).pass, true);
}

assert.equal(debrisReason("Fixture.app/Contents/._Info.plist"), "appledouble");
assert.equal(debrisReason("__MACOSX/Foo"), "macos_metadata_directory");
assert.equal(debrisReason("Fixture.app/.DS_Store"), "finder_metadata");
console.log("ok - O.11.1 AppleDouble archive entries, framework allowlist, and symlink policy");
