"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { CATALOG, verifyCoverage, verifyFinalCoverage } = require("../scripts/native-notice-coverage.cjs");
const hash = (b) => crypto.createHash("sha256").update(b).digest("hex");

function fixture(t) {
  const app = fs.mkdtempSync(path.join(os.tmpdir(), "phil-native-notices-"));
  t.after(() => fs.rmSync(app, { recursive: true, force: true }));
  const payload = path.join(app, "Contents/Resources/app");
  const binary = "Contents/MacOS/test-native";
  const put = (relative, data) => { const f = path.join(app, relative); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, data); };
  const bytes = Buffer.from("cffaedfe0001020304050607", "hex");
  put(binary, bytes);
  const notice = { path: "LICENSES/test.txt", sha256: hash("notice") };
  put("Contents/Resources/app/LICENSES/test.txt", "notice");
  const inventoryBytes = JSON.stringify({ requiredReferences: [notice], packages: [{ name: "test", version: "1.0.0" }] });
  const inventory = { path: "LICENSES/test-inventory.json", sha256: hash(inventoryBytes) };
  put(`Contents/Resources/app/${inventory.path}`, inventoryBytes);
  const catalog = { schemaVersion: 1, coverageStatus: "COMPLETE", inventories: [inventory], notices: [notice], nativeFiles: [{ path: binary, inputSha256: hash(bytes), packagedInputSha256: hash(bytes), sourceRevision: "test-revision", licenseIds: ["MIT"], inventoryReferences: [inventory.path], noticeReferences: [notice.path] }] };
  const writeCatalog = () => fs.writeFileSync(path.join(payload, CATALOG), JSON.stringify(catalog));
  writeCatalog();
  return { app, payload, binary, catalog, writeCatalog, put };
}

test("pinned input, inventory and notices validate, then final bytes freeze independently", (t) => {
  const f = fixture(t);
  verifyCoverage(f.app, { beforeSigning: true });
  // Model the controlled signature step changing bytes without editing policy.
  fs.appendFileSync(path.join(f.app, f.binary), "signature");
  const final = verifyCoverage(f.app);
  assert.equal(verifyFinalCoverage(f.app, final), true);
  assert.throws(() => verifyCoverage(f.app, { beforeSigning: true }), /native_input_hash_mismatch/);
  fs.appendFileSync(path.join(f.app, f.binary), "tamper");
  assert.throws(() => verifyFinalCoverage(f.app, final), /native_final_coverage_mismatch/);
});

test("changed dependency inventory fails without silently refreshing its hash", (t) => {
  const f = fixture(t);
  fs.appendFileSync(path.join(f.payload, f.catalog.inventories[0].path), " ");
  assert.throws(() => verifyCoverage(f.app), /native_notice_reference_mismatch/);
});

test("raw inputs and reviewed package transformations have separate immutable pins", (t) => {
  const f = fixture(t), file = path.join(f.app, f.binary);
  const transformed = Buffer.from("cffaedfe0011223344556677", "hex");
  f.catalog.nativeFiles[0].packagedInputSha256 = hash(transformed); f.writeCatalog();
  verifyCoverage(f.app, { beforeTransforms: true });
  assert.throws(() => verifyCoverage(f.app, { beforeSigning: true }), /native_input_hash_mismatch/);
  fs.writeFileSync(file, transformed);
  verifyCoverage(f.app, { beforeSigning: true });
  assert.throws(() => verifyCoverage(f.app, { beforeTransforms: true }), /native_input_hash_mismatch/);
});

test("missing or changed required license/source fails", (t) => {
  const f = fixture(t), file = path.join(f.payload, f.catalog.notices[0].path);
  fs.writeFileSync(file, "changed");
  assert.throws(() => verifyCoverage(f.app), /native_notice_reference_mismatch/);
  fs.unlinkSync(file);
  assert.throws(() => verifyCoverage(f.app));
});

test("unbound required inventory notice and incomplete closure fail", (t) => {
  const f = fixture(t);
  f.catalog.notices = [{ path: f.catalog.inventories[0].path, sha256: f.catalog.inventories[0].sha256 }];
  f.writeCatalog();
  assert.throws(() => verifyCoverage(f.app), /native_inventory_notice_unbound/);
  f.catalog.coverageStatus = "PENDING_REVIEW"; f.writeCatalog();
  assert.throws(() => verifyCoverage(f.app), /native_notice_coverage_incomplete/);
});

test("an extra or missing native executable fails the exact path set", (t) => {
  const f = fixture(t);
  f.put("Contents/MacOS/unaccounted", Buffer.from("cffaedfe00112233", "hex"));
  assert.throws(() => verifyCoverage(f.app), /native_binary_path_set_mismatch/);
  fs.unlinkSync(path.join(f.app, "Contents/MacOS/unaccounted"));
  for (const magic of ["cafebabf", "bfbafeca"]) {
    f.put("Contents/MacOS/unaccounted-fat64", Buffer.from(`${magic}00112233`, "hex"));
    assert.throws(() => verifyCoverage(f.app), /native_binary_path_set_mismatch/);
    fs.unlinkSync(path.join(f.app, "Contents/MacOS/unaccounted-fat64"));
  }
  fs.unlinkSync(path.join(f.app, f.binary));
  assert.throws(() => verifyCoverage(f.app), /native_binary_path_set_mismatch/);
});
