"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const CATALOG = "LICENSES/native-notice-coverage.json";
const FINAL_MANIFEST = "native-notice-coverage-final.json";
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function checkedFile(root, relative) {
  if (typeof relative !== "string" || relative.includes("\\") || path.posix.isAbsolute(relative)
      || relative.split("/").some((part) => !part || part === "." || part === "..")) {
    throw Error("native_notice_invalid_path");
  }
  const file = path.join(root, relative);
  const realRoot = fs.realpathSync(root);
  if (!fs.realpathSync(file).startsWith(`${realRoot}${path.sep}`) || !fs.statSync(file).isFile()) {
    throw Error(`native_notice_invalid_file:${relative}`);
  }
  return file;
}

function verifyReference(root, reference) {
  if (!/^[a-f0-9]{64}$/.test(reference.sha256)
      || hash(fs.readFileSync(checkedFile(root, reference.path))) !== reference.sha256) {
    throw Error(`native_notice_reference_mismatch:${reference.path}`);
  }
}

function nativeFiles(app) {
  const found = [];
  function walk(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name), stat = fs.lstatSync(file);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) { walk(file); continue; }
      if (!stat.isFile() || stat.size < 4) continue;
      const fd = fs.openSync(file, "r"), magic = Buffer.alloc(4);
      try { fs.readSync(fd, magic, 0, 4, 0); } finally { fs.closeSync(fd); }
      if ([0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic.readUInt32BE())) {
        found.push({ path: path.relative(app, file).split(path.sep).join("/"), sha256: hash(fs.readFileSync(file)) });
      }
    }
  }
  walk(app);
  return found.sort((a, b) => a.path.localeCompare(b.path));
}

function verifyCoverage(app, { beforeSigning = false, beforeTransforms = false } = {}) {
  const payload = path.join(app, "Contents/Resources/app");
  const bytes = fs.readFileSync(checkedFile(payload, CATALOG));
  const catalog = JSON.parse(bytes);
  if (catalog.schemaVersion !== 1 || catalog.coverageStatus !== "COMPLETE"
      || !catalog.inventories?.length || !catalog.notices?.length || !catalog.nativeFiles?.length) {
    throw Error("native_notice_coverage_incomplete");
  }
  const noticeMap = new Map();
  for (const ref of catalog.notices) {
    if (noticeMap.has(ref.path)) throw Error(`native_notice_duplicate:${ref.path}`);
    verifyReference(payload, ref);
    noticeMap.set(ref.path, ref.sha256);
  }
  const inventoryMap = new Map();
  for (const ref of catalog.inventories) {
    if (inventoryMap.has(ref.path)) throw Error(`native_inventory_duplicate:${ref.path}`);
    verifyReference(payload, ref);
    inventoryMap.set(ref.path, ref.sha256);
    // The catalog must cover every required reference declared by an inventory.
    const inventory = JSON.parse(fs.readFileSync(checkedFile(payload, ref.path)));
    for (const required of inventory.requiredReferences || []) {
      if (noticeMap.get(required.path) !== required.sha256) throw Error(`native_inventory_notice_unbound:${required.path}`);
    }
  }
  const actual = nativeFiles(app);
  const expected = [...catalog.nativeFiles].sort((a, b) => a.path.localeCompare(b.path));
  if (JSON.stringify(actual.map((f) => f.path)) !== JSON.stringify(expected.map((f) => f.path))) {
    throw Error("native_binary_path_set_mismatch");
  }
  for (let index = 0; index < expected.length; index++) {
    const item = expected[index];
    if (!item.sourceRevision || !item.licenseIds?.length || !item.inventoryReferences?.length
        || !item.noticeReferences?.length || !/^[a-f0-9]{64}$/.test(item.inputSha256)
        || !/^[a-f0-9]{64}$/.test(item.packagedInputSha256)) {
      throw Error(`native_binary_coverage_incomplete:${item.path}`);
    }
    for (const ref of item.inventoryReferences) if (!inventoryMap.has(ref)) throw Error(`native_binary_inventory_unbound:${ref}`);
    for (const ref of item.noticeReferences) if (!noticeMap.has(ref)) throw Error(`native_binary_notice_unbound:${ref}`);
    const expectedInput = beforeTransforms ? item.inputSha256 : item.packagedInputSha256;
    if ((beforeSigning || beforeTransforms) && actual[index].sha256 !== expectedInput) throw Error(`native_input_hash_mismatch:${item.path}`);
  }
  return { schemaVersion: 1, catalogSha256: hash(bytes), inventories: catalog.inventories,
    notices: catalog.notices, nativeFiles: actual,
    inputHashPolicy: "Pinned input hashes are checked before signing; these are final file hashes." };
}

function verifyFinalCoverage(app, expected) {
  const actual = verifyCoverage(app);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw Error("native_final_coverage_mismatch");
  return true;
}

module.exports = { CATALOG, FINAL_MANIFEST, nativeFiles, verifyCoverage, verifyFinalCoverage };
