"use strict";

/**
 * PhilCore Package 6B — evidence provenance v2 registry verifier.
 *
 * Verifies `config/provenance/v2-registry.json` against the committed
 * provenance v2 records it names: strict registry schema, no duplicate or
 * unregistered records, no symlinks anywhere along the checked paths, byte-
 * for-byte and digest agreement between the working tree and the record's
 * git-committed container commit, and independent recomputation of every
 * declared source blob hash from git object bytes at the source baseline.
 *
 * Fail closed on any ambiguity. Never regenerates, normalizes, rewrites, or
 * repairs registry or record content — verification only.
 *
 * CLI output is intentionally sanitized: only a short stable error category
 * (`PROVENANCE_V2_REGISTRY: <CODE>`) is ever printed on failure. No absolute
 * paths, git stderr, record contents, or environment values are emitted.
 */

const fs = require("node:fs");
const path = require("node:path");

const {
  assertFullCommitSha,
  assertRelativePosixPath,
  assertNoSymlinkComponents,
  readBoundedFileBytes,
  parseJsonStrictNoDuplicateKeys,
  sha256Buffer,
  verifyCommittedProvenanceRecordV2,
  readSourcesAtBaseline,
  gitShow,
  resolveCommit,
  assertEvidenceContainerBinding,
  PROVENANCE_V2_DIR,
  RESOURCE_LIMITS,
  provenanceError,
  lstatOrMissing
} = require("../cryptography/evidence-provenance-v2.cjs");

const REGISTRY_DIR = "config/provenance";
const REGISTRY_RELATIVE_PATH = `${REGISTRY_DIR}/v2-registry.json`;
const REGISTRY_KIND = "philcore-evidence-provenance-v2-registry";
const REGISTRY_SCHEMA_VERSION = 1;

const REGISTRY_ALLOWED_KEYS = Object.freeze(["schemaVersion", "kind", "records"]);
const ENTRY_ALLOWED_KEYS = Object.freeze([
  "id",
  "recordPath",
  "containerCommit",
  "sourceBaselineCommit",
  "sourceBaselineTree",
  "recordFileSha256"
]);

const HEX64_RE = /^[0-9a-f]{64}$/;

function isPlainObjectLocal(value) {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function assertAllowedKeysOnly(obj, allowed, code) {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw provenanceError(code, `${code}: unknown field "${key}"`);
    }
  }
}

function assertPathComponentsSafe(repoRoot, relDir, symlinkCode) {
  try {
    assertNoSymlinkComponents(repoRoot, relDir);
  } catch {
    throw provenanceError(symlinkCode, `${symlinkCode}: unsafe path component`);
  }
}

/* -------------------------------------------------------------------------- */
/* Registry-level schema                                                      */
/* -------------------------------------------------------------------------- */

function loadRegistry(repoRoot) {
  assertPathComponentsSafe(repoRoot, REGISTRY_DIR, "REGISTRY_SYMLINK");
  const registryAbsPath = path.join(repoRoot, REGISTRY_RELATIVE_PATH);
  const lst = lstatOrMissing(registryAbsPath);
  if (lst === null) {
    throw provenanceError("REGISTRY_MISSING", "REGISTRY_MISSING");
  }
  if (lst.isSymbolicLink()) {
    throw provenanceError("REGISTRY_SYMLINK", "REGISTRY_SYMLINK");
  }
  if (!lst.isFile()) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: registry path is not a regular file");
  }

  const bytes = readBoundedFileBytes(registryAbsPath, RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES);
  const registry = parseJsonStrictNoDuplicateKeys(bytes.toString("utf8"));

  if (!isPlainObjectLocal(registry)) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: registry must be a JSON object");
  }
  assertAllowedKeysOnly(registry, REGISTRY_ALLOWED_KEYS, "REGISTRY_UNKNOWN_FIELD");

  if (registry.schemaVersion !== REGISTRY_SCHEMA_VERSION) {
    throw provenanceError(
      "REGISTRY_SCHEMA",
      `REGISTRY_SCHEMA: schemaVersion must equal ${REGISTRY_SCHEMA_VERSION}`
    );
  }
  if (registry.kind !== REGISTRY_KIND) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: kind mismatch");
  }
  if (!Array.isArray(registry.records)) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: records must be an array");
  }

  return registry;
}

/* -------------------------------------------------------------------------- */
/* Entry-level schema                                                         */
/* -------------------------------------------------------------------------- */

function assertValidRecordPath(recordPath) {
  if (typeof recordPath !== "string") {
    throw provenanceError("RECORD_PATH_INVALID", "RECORD_PATH_INVALID: not a string");
  }
  try {
    assertRelativePosixPath(recordPath);
  } catch {
    throw provenanceError("RECORD_PATH_INVALID", "RECORD_PATH_INVALID: malformed path");
  }
  const prefix = `${PROVENANCE_V2_DIR}/`;
  if (!recordPath.startsWith(prefix)) {
    throw provenanceError(
      "RECORD_PATH_INVALID",
      `RECORD_PATH_INVALID: must start with ${prefix}`
    );
  }
  const remainder = recordPath.slice(prefix.length);
  if (remainder.length === 0 || remainder.includes("/")) {
    throw provenanceError(
      "RECORD_PATH_INVALID",
      "RECORD_PATH_INVALID: must be a flat file directly under v2/"
    );
  }
  return recordPath;
}

function validateEntrySchema(entry) {
  if (!isPlainObjectLocal(entry)) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: record entry must be an object");
  }
  assertAllowedKeysOnly(entry, ENTRY_ALLOWED_KEYS, "REGISTRY_UNKNOWN_FIELD");

  if (typeof entry.id !== "string" || entry.id.length === 0) {
    throw provenanceError("REGISTRY_SCHEMA", "REGISTRY_SCHEMA: id must be a non-empty string");
  }
  assertValidRecordPath(entry.recordPath);
  assertFullCommitSha(entry.containerCommit, "containerCommit");
  assertFullCommitSha(entry.sourceBaselineCommit, "sourceBaselineCommit");
  assertFullCommitSha(entry.sourceBaselineTree, "sourceBaselineTree");
  if (typeof entry.recordFileSha256 !== "string" || !HEX64_RE.test(entry.recordFileSha256)) {
    throw provenanceError(
      "REGISTRY_SCHEMA",
      "REGISTRY_SCHEMA: recordFileSha256 must be 64 lowercase hex characters"
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Source blob independent recomputation                                      */
/* -------------------------------------------------------------------------- */

function verifySourceBlobBijectionAndHashes(repoRoot, sourceBaselineCommit, computed) {
  if (!isPlainObjectLocal(computed)) {
    throw provenanceError("SOURCE_PATH_BIJECTION", "SOURCE_PATH_BIJECTION: computed must be an object");
  }
  const hasSourcePaths = Object.prototype.hasOwnProperty.call(computed, "sourcePaths");
  const hasSourceBlobSha256 = Object.prototype.hasOwnProperty.call(computed, "sourceBlobSha256");
  if (!hasSourcePaths && !hasSourceBlobSha256) {
    return;
  }
  if (!hasSourcePaths || !hasSourceBlobSha256) {
    throw provenanceError(
      "SOURCE_PATH_BIJECTION",
      "SOURCE_PATH_BIJECTION: sourcePaths and sourceBlobSha256 must both be present"
    );
  }

  const sourcePaths = computed.sourcePaths;
  const sourceBlobSha256 = computed.sourceBlobSha256;
  if (!Array.isArray(sourcePaths)) {
    throw provenanceError("SOURCE_PATH_BIJECTION", "SOURCE_PATH_BIJECTION: sourcePaths must be an array");
  }
  if (!isPlainObjectLocal(sourceBlobSha256)) {
    throw provenanceError(
      "SOURCE_PATH_BIJECTION",
      "SOURCE_PATH_BIJECTION: sourceBlobSha256 must be an object"
    );
  }

  const seenPaths = new Set();
  for (const p of sourcePaths) {
    if (typeof p !== "string") {
      throw provenanceError(
        "SOURCE_PATH_BIJECTION",
        "SOURCE_PATH_BIJECTION: sourcePaths entries must be strings"
      );
    }
    assertRelativePosixPath(p);
    if (seenPaths.has(p)) {
      throw provenanceError(
        "SOURCE_PATH_BIJECTION",
        "SOURCE_PATH_BIJECTION: duplicate sourcePaths entry"
      );
    }
    seenPaths.add(p);
  }

  const hashKeys = Object.keys(sourceBlobSha256);
  const hashKeySet = new Set(hashKeys);
  if (hashKeySet.size !== hashKeys.length) {
    throw provenanceError(
      "SOURCE_PATH_BIJECTION",
      "SOURCE_PATH_BIJECTION: duplicate sourceBlobSha256 key"
    );
  }
  if (hashKeySet.size !== seenPaths.size) {
    throw provenanceError(
      "SOURCE_PATH_BIJECTION",
      "SOURCE_PATH_BIJECTION: sourcePaths/sourceBlobSha256 key count mismatch"
    );
  }
  for (const p of seenPaths) {
    if (!hashKeySet.has(p)) {
      throw provenanceError(
        "SOURCE_PATH_BIJECTION",
        "SOURCE_PATH_BIJECTION: sourcePaths entry missing from sourceBlobSha256"
      );
    }
  }
  for (const k of hashKeySet) {
    if (!seenPaths.has(k)) {
      throw provenanceError(
        "SOURCE_PATH_BIJECTION",
        "SOURCE_PATH_BIJECTION: sourceBlobSha256 key absent from sourcePaths"
      );
    }
  }

  const sourceBytesByPath = readSourcesAtBaseline(repoRoot, sourceBaselineCommit, sourcePaths);
  for (const p of sourcePaths) {
    const claimed = sourceBlobSha256[p];
    if (typeof claimed !== "string" || !HEX64_RE.test(claimed)) {
      throw provenanceError(
        "SOURCE_PATH_BIJECTION",
        "SOURCE_PATH_BIJECTION: sourceBlobSha256 value must be 64 lowercase hex characters"
      );
    }
    const actual = sha256Buffer(sourceBytesByPath[p]);
    if (actual !== claimed) {
      throw provenanceError("SOURCE_BLOB_MISMATCH", `SOURCE_BLOB_MISMATCH: ${p}`);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Per-entry full verification                                                */
/* -------------------------------------------------------------------------- */

function verifyEntry(repoRoot, entry) {
  const recordDirRel = path.dirname(entry.recordPath);
  assertPathComponentsSafe(repoRoot, recordDirRel, "RECORD_SYMLINK");

  const recordAbsPath = path.join(repoRoot, entry.recordPath);
  const leafLst = lstatOrMissing(recordAbsPath);
  if (leafLst === null) {
    throw provenanceError("RECORD_MISSING", `RECORD_MISSING: ${entry.id}`);
  }
  if (leafLst.isSymbolicLink()) {
    throw provenanceError("RECORD_SYMLINK", `RECORD_SYMLINK: ${entry.id}`);
  }
  if (!leafLst.isFile()) {
    throw provenanceError("RECORD_PATH_INVALID", `RECORD_PATH_INVALID: ${entry.id} is not a regular file`);
  }

  // Independently resolve both commits before any byte comparison so an
  // unresolvable/shallow history fails closed early via existing helpers.
  resolveCommit(repoRoot, entry.containerCommit);
  resolveCommit(repoRoot, entry.sourceBaselineCommit);

  const workingBytes = readBoundedFileBytes(recordAbsPath, RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES);

  let committedBytes;
  try {
    committedBytes = gitShow(repoRoot, entry.containerCommit, entry.recordPath);
  } catch (err) {
    if (err && err.code === "SOURCE_BLOB_MISSING") {
      throw provenanceError("RECORD_MISSING", `RECORD_MISSING: ${entry.id} absent at containerCommit`);
    }
    throw err;
  }
  if (committedBytes.length > RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `RESOURCE_LIMIT_EXCEEDED: ${entry.id} committed bytes exceed bound`
    );
  }
  if (!workingBytes.equals(committedBytes)) {
    throw provenanceError("BYTE_MISMATCH", `BYTE_MISMATCH: ${entry.id}`);
  }

  const actualHash = sha256Buffer(workingBytes);
  if (actualHash !== entry.recordFileSha256) {
    throw provenanceError("HASH_MISMATCH", `HASH_MISMATCH: ${entry.id}`);
  }

  const record = parseJsonStrictNoDuplicateKeys(workingBytes.toString("utf8"));
  if (!isPlainObjectLocal(record)) {
    throw provenanceError("REGISTRY_SCHEMA", `REGISTRY_SCHEMA: ${entry.id} record must be an object`);
  }
  if (
    record.sourceBaselineCommit !== entry.sourceBaselineCommit ||
    record.sourceBaselineTree !== entry.sourceBaselineTree
  ) {
    throw provenanceError("BASELINE_MISMATCH", `BASELINE_MISMATCH: ${entry.id}`);
  }

  verifyCommittedProvenanceRecordV2({
    repoRoot,
    record,
    containerCommit: entry.containerCommit
  });

  // Independent re-confirmation of container topology (single dedicated
  // child of sourceBaselineCommit) beyond the check already performed inside
  // verifyCommittedProvenanceRecordV2.
  assertEvidenceContainerBinding({
    repoRoot,
    sourceBaselineCommit: record.sourceBaselineCommit,
    sourceBaselineTree: record.sourceBaselineTree,
    containerCommit: entry.containerCommit
  });

  verifySourceBlobBijectionAndHashes(repoRoot, record.sourceBaselineCommit, record.computed);
}

/* -------------------------------------------------------------------------- */
/* config/provenance/v2/ directory reconciliation                             */
/* -------------------------------------------------------------------------- */

function scanV2Directory(repoRoot, registeredFileNames) {
  assertPathComponentsSafe(repoRoot, PROVENANCE_V2_DIR, "V2_SYMLINK");
  const v2AbsPath = path.join(repoRoot, PROVENANCE_V2_DIR);
  const lst = lstatOrMissing(v2AbsPath);
  if (lst === null) {
    if (registeredFileNames.size > 0) {
      throw provenanceError("RECORD_MISSING", "RECORD_MISSING: v2 directory absent");
    }
    return;
  }
  if (lst.isSymbolicLink()) {
    throw provenanceError("V2_SYMLINK", "V2_SYMLINK: v2 directory is a symlink");
  }
  if (!lst.isDirectory()) {
    throw provenanceError("V2_UNEXPECTED_DIRECTORY", "V2_UNEXPECTED_DIRECTORY: v2 path is not a directory");
  }

  let dirents;
  try {
    dirents = fs.readdirSync(v2AbsPath, { withFileTypes: true });
  } catch {
    throw provenanceError("V2_UNEXPECTED_DIRECTORY", "V2_UNEXPECTED_DIRECTORY: cannot list v2 directory");
  }
  if (dirents.length > RESOURCE_LIMITS.MAX_ARRAY_LENGTH) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `RESOURCE_LIMIT_EXCEEDED: v2 directory exceeds MAX_ARRAY_LENGTH (${RESOURCE_LIMITS.MAX_ARRAY_LENGTH})`
    );
  }

  const seenOnDisk = new Set();
  for (const dirent of dirents) {
    const name = dirent.name;
    if (dirent.isSymbolicLink()) {
      throw provenanceError("V2_SYMLINK", `V2_SYMLINK: ${name}`);
    }
    if (dirent.isDirectory()) {
      throw provenanceError("V2_UNEXPECTED_DIRECTORY", `V2_UNEXPECTED_DIRECTORY: ${name}`);
    }
    if (!dirent.isFile()) {
      throw provenanceError("V2_UNEXPECTED_DIRECTORY", `V2_UNEXPECTED_DIRECTORY: non-regular entry ${name}`);
    }
    seenOnDisk.add(name);
    if (!registeredFileNames.has(name)) {
      throw provenanceError("RECORD_UNREGISTERED", `RECORD_UNREGISTERED: ${name}`);
    }
  }
  for (const name of registeredFileNames) {
    if (!seenOnDisk.has(name)) {
      throw provenanceError("RECORD_MISSING", `RECORD_MISSING: ${name}`);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Top-level verification                                                     */
/* -------------------------------------------------------------------------- */

function verifyProvenanceV2Registry({ repoRoot } = {}) {
  if (typeof repoRoot !== "string" || repoRoot.length === 0) {
    throw provenanceError("INVALID_INPUT", "INVALID_INPUT: repoRoot must be a non-empty string");
  }

  const registry = loadRegistry(repoRoot);
  const entries = registry.records;

  const seenIds = new Set();
  const seenRecordPaths = new Set();
  const seenContainerCommits = new Set();
  const registeredFileNames = new Set();

  for (const entry of entries) {
    validateEntrySchema(entry);

    if (seenIds.has(entry.id)) {
      throw provenanceError("REGISTRY_DUPLICATE_ID", `REGISTRY_DUPLICATE_ID: ${entry.id}`);
    }
    seenIds.add(entry.id);

    if (seenRecordPaths.has(entry.recordPath)) {
      throw provenanceError("REGISTRY_DUPLICATE_PATH", `REGISTRY_DUPLICATE_PATH: ${entry.recordPath}`);
    }
    seenRecordPaths.add(entry.recordPath);

    if (seenContainerCommits.has(entry.containerCommit)) {
      throw provenanceError(
        "REGISTRY_DUPLICATE_CONTAINER",
        `REGISTRY_DUPLICATE_CONTAINER: ${entry.containerCommit}`
      );
    }
    seenContainerCommits.add(entry.containerCommit);

    verifyEntry(repoRoot, entry);

    registeredFileNames.add(path.basename(entry.recordPath));
  }

  scanV2Directory(repoRoot, registeredFileNames);

  return { ok: true, recordCount: entries.length };
}

/* -------------------------------------------------------------------------- */
/* CLI                                                                        */
/* -------------------------------------------------------------------------- */

function main() {
  const repoRoot = path.resolve(__dirname, "../..");
  try {
    const result = verifyProvenanceV2Registry({ repoRoot });
    console.log(`Provenance v2 registry verification passed (${result.recordCount} record(s))`);
    process.exit(0);
  } catch (err) {
    const code = (err && err.code) || "UNKNOWN_ERROR";
    console.error(`PROVENANCE_V2_REGISTRY: ${code}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  REGISTRY_RELATIVE_PATH,
  REGISTRY_KIND,
  REGISTRY_SCHEMA_VERSION,
  REGISTRY_ALLOWED_KEYS,
  ENTRY_ALLOWED_KEYS,
  verifyProvenanceV2Registry
};
