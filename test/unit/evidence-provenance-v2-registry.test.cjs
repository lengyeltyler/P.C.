"use strict";

/**
 * Package 6B — evidence provenance v2 registry verifier.
 *
 * Exercises `scripts/ci/verify-provenance-v2-registry.cjs` against the real,
 * already-committed Phase 5B record (Commit A `e8697f9f...`, source baseline
 * `45c38dec...`, source tree `eb6f0463...`) plus a comprehensive set of
 * fail-closed negative fixtures covering registry schema, entry schema,
 * duplicate detection, git container-topology binding, byte/hash/digest
 * integrity, symlink defenses, `config/provenance/v2/` directory
 * reconciliation, and independent source-blob bijection recomputation.
 *
 * Hard rules honored throughout this file:
 *  - Every fixture lives in an isolated temp directory created via
 *    `fs.mkdtempSync(os.tmpdir())`. Nothing is ever written into the real
 *    PhilCore worktree, and no destructive cleanup ever targets it.
 *  - The only read against the real worktree (`ROOT`) is the happy-path
 *    fixture builder, which clones ROOT's git object store (`git clone
 *    --shared --no-checkout`, so no monorepo checkout ever happens) and
 *    copies the already-committed record bytes to seed the temp registry.
 *  - All temp directories are tracked and removed in `afterEach`/`after`.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../..");

const {
  verifyProvenanceV2Registry,
  REGISTRY_RELATIVE_PATH,
  REGISTRY_KIND,
  REGISTRY_SCHEMA_VERSION
} = require("../../scripts/ci/verify-provenance-v2-registry.cjs");

const {
  RESOURCE_LIMITS,
  canonicalize,
  digestComputed,
  digestObserved,
  digestRecord
} = require("../../scripts/cryptography/evidence-provenance-v2.cjs");

/* -------------------------------------------------------------------------- */
/* Real, immutable Phase 5B fixture identity (Commit A)                       */
/* -------------------------------------------------------------------------- */

const CONTAINER_COMMIT = "e8697f9fc50c13fe8cc5ecf18301482cee1e6067";
const SOURCE_BASELINE_COMMIT = "45c38dec9ba0e3f13db83bcbc943f1e72c64b894";
const SOURCE_BASELINE_TREE = "eb6f0463882c1c5ac47c7d56900bc7ffb5ec762b";
const RECORD_RELATIVE_PATH =
  "config/provenance/v2/45c38dec9ba0e3f13db83bcbc943f1e72c64b894-phase5b-secure-enclave-disposable-key-gate.json";
const RECORD_FILE_SHA256 =
  "cb5e5874b701993a20701d253db6378b60652642aa8d5068f5c6d2adf67fb717";
const REGISTRY_ID =
  "phase5b-secure-enclave-disposable-key-gate-45c38dec9ba0e3f13db83bcbc943f1e72c64b894";

/* Package 6C — V2 Sepolia offline readiness (Commit A container) */
const PACKAGE_6C_CONTAINER_COMMIT =
  "2c65c05fa477f5d9fce210f5cfe04f54ab8facec";
const PACKAGE_6C_SOURCE_BASELINE_COMMIT =
  "7276ee42e94d2c9a08fee3706fb94a6c69c1f822";
const PACKAGE_6C_SOURCE_BASELINE_TREE =
  "12d658580f0a42bed7947c43c00be8b1f320674b";
const PACKAGE_6C_RECORD_RELATIVE_PATH =
  "config/provenance/v2/7276ee42e94d2c9a08fee3706fb94a6c69c1f822-current-v2-sepolia-offline-readiness.json";
const PACKAGE_6C_RECORD_FILE_SHA256 =
  "fe3ff7f75cb5a45570bd29f2c6bd4cb8d3cfb9a337536d25420cacebf3203eda";
const PACKAGE_6C_REGISTRY_ID =
  "current-v2-sepolia-offline-readiness-7276ee42e94d2c9a08fee3706fb94a6c69c1f822";

// A real, unrelated, independently resolvable commit in ROOT's history. Used
// only as a syntactically-valid "wrong" commit reference in negative fixtures
// — never mutated, never treated as this record's actual baseline.
const UNRELATED_REAL_COMMIT = "d1d85696fbb6800de68eec4b6bc20177e8b14e42";

/* -------------------------------------------------------------------------- */
/* Temp fixture bookkeeping                                                   */
/* -------------------------------------------------------------------------- */

const trackedTemps = [];

function trackTemp(dir) {
  trackedTemps.push(dir);
  return dir;
}

function mktempDir(prefix) {
  return trackTemp(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function cleanupTrackedTemps() {
  for (const dir of trackedTemps) {
    try {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    } catch {
      // best-effort
    }
  }
  trackedTemps.length = 0;
}

/* -------------------------------------------------------------------------- */
/* git helpers                                                                */
/* -------------------------------------------------------------------------- */

function git(cwd, args, opts = {}) {
  return spawnSync("git", args, { cwd, encoding: "utf8", ...opts });
}

function gitOk(cwd, args, opts = {}) {
  const result = git(cwd, args, opts);
  assert.equal(result.status, 0, `git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout.trim();
}

/**
 * Clones ROOT's object store into a disposable temp directory via `--shared
 * --no-checkout`. `--shared` means no object data is copied (only an
 * alternates file referencing ROOT's `.git/objects`), and `--no-checkout`
 * means no working-tree files are ever written for the monorepo. The only
 * files that end up in the fixture's working tree are the two we write
 * explicitly (the registry and the record). This still gives full,
 * independent `git rev-parse` / `git show` access to every commit reachable
 * from any branch in ROOT, including Commit A and its parent baseline.
 */
function cloneRootShared(label) {
  const dir = mktempDir(`philcore-prov-registry-${label}-`);
  const result = spawnSync(
    "git",
    ["clone", "--shared", "--no-checkout", "--quiet", ROOT, dir],
    { cwd: os.tmpdir(), encoding: "utf8" }
  );
  assert.equal(result.status, 0, `git clone --shared failed: ${result.stderr}`);
  gitOk(dir, ["config", "user.email", "prov-registry-fixture@example.test"]);
  gitOk(dir, ["config", "user.name", "Provenance Registry Fixture"]);
  return dir;
}

/**
 * Writes `bytes` as a git blob (`git hash-object -w`), builds a one-file tree
 * containing it at `relPath` via a scratch `GIT_INDEX_FILE`, and creates a
 * commit over that tree with the given `parents` — all via plumbing, so no
 * working-tree checkout of the monorepo is ever required to fabricate
 * adversarial container commits (zero parents, multiple parents, wrong
 * parent, or a tree missing the record entirely).
 */
function hashObjectBytes(dir, bytes) {
  const tmpFile = path.join(dir, `.tmp-blob-${crypto.randomBytes(6).toString("hex")}`);
  fs.writeFileSync(tmpFile, bytes);
  try {
    return gitOk(dir, ["hash-object", "-w", "--", tmpFile]);
  } finally {
    fs.rmSync(tmpFile, { force: true });
  }
}

function buildTreeWithSingleBlob(dir, relPath, blobSha) {
  const indexFile = path.join(dir, `.tmp-index-${crypto.randomBytes(6).toString("hex")}`);
  const env = { ...process.env, GIT_INDEX_FILE: indexFile };
  const add = spawnSync(
    "git",
    ["update-index", "--add", "--cacheinfo", "100644", blobSha, relPath],
    { cwd: dir, env, encoding: "utf8" }
  );
  assert.equal(add.status, 0, `git update-index failed: ${add.stderr}`);
  const writeTree = spawnSync("git", ["write-tree"], { cwd: dir, env, encoding: "utf8" });
  assert.equal(writeTree.status, 0, `git write-tree failed: ${writeTree.stderr}`);
  fs.rmSync(indexFile, { force: true });
  return writeTree.stdout.trim();
}

function commitTree(dir, treeSha, parents, message) {
  const args = ["commit-tree", treeSha];
  for (const parent of parents) {
    args.push("-p", parent);
  }
  args.push("-m", message);
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: "Provenance Registry Fixture",
    GIT_AUTHOR_EMAIL: "prov-registry-fixture@example.test",
    GIT_COMMITTER_NAME: "Provenance Registry Fixture",
    GIT_COMMITTER_EMAIL: "prov-registry-fixture@example.test"
  };
  const result = spawnSync("git", args, { cwd: dir, env, encoding: "utf8" });
  assert.equal(result.status, 0, `git commit-tree failed: ${result.stderr}`);
  return result.stdout.trim();
}

function buildCustomContainer(dir, { relPath = RECORD_RELATIVE_PATH, bytes, parents, message = "custom container" }) {
  const blobSha = hashObjectBytes(dir, bytes);
  const treeSha = buildTreeWithSingleBlob(dir, relPath, blobSha);
  return commitTree(dir, treeSha, parents, message);
}

/* -------------------------------------------------------------------------- */
/* Record / registry construction helpers                                    */
/* -------------------------------------------------------------------------- */

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function loadRealRecordBytes() {
  return fs.readFileSync(path.join(ROOT, RECORD_RELATIVE_PATH));
}

function loadRealRecordObject() {
  return JSON.parse(loadRealRecordBytes().toString("utf8"));
}

function makeEntry(overrides = {}) {
  return {
    id: REGISTRY_ID,
    recordPath: RECORD_RELATIVE_PATH,
    containerCommit: CONTAINER_COMMIT,
    sourceBaselineCommit: SOURCE_BASELINE_COMMIT,
    sourceBaselineTree: SOURCE_BASELINE_TREE,
    recordFileSha256: RECORD_FILE_SHA256,
    ...overrides
  };
}

function makeRegistry(entries, overrides = {}) {
  return {
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    kind: REGISTRY_KIND,
    records: entries,
    ...overrides
  };
}

function writeRegistryRaw(fixtureDir, text) {
  const abs = path.join(fixtureDir, REGISTRY_RELATIVE_PATH);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, text, "utf8");
}

function writeRegistryObject(fixtureDir, obj) {
  writeRegistryRaw(fixtureDir, `${JSON.stringify(obj, null, 2)}\n`);
}

function writeRecordBytes(fixtureDir, relPath, bytes) {
  const abs = path.join(fixtureDir, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, bytes);
}

/**
 * Builds the disposable happy-path fixture: a `--shared --no-checkout` clone
 * of ROOT (so Commit A and its parent baseline exist as git objects) with the
 * real, byte-identical record copied into the working tree and a fresh
 * `config/provenance/v2-registry.json` naming it. ROOT itself is never
 * mutated and the registry may not exist there at all yet — this fixture is
 * fully self-contained.
 */
function makeHappyFixture(label = "happy") {
  const dir = cloneRootShared(label);
  writeRecordBytes(dir, RECORD_RELATIVE_PATH, loadRealRecordBytes());
  const entry = makeEntry();
  writeRegistryObject(dir, makeRegistry([entry]));
  return {
    dir,
    registryPath: path.join(dir, REGISTRY_RELATIVE_PATH),
    recordPath: path.join(dir, RECORD_RELATIVE_PATH),
    entry
  };
}

/** Deep-clones the real record and applies `mutateFn` to it. */
function tamperRecord(mutateFn) {
  const record = loadRealRecordObject();
  mutateFn(record);
  return record;
}

/** Recomputes `computed.digest` from the (possibly tampered) computed fields. */
function recomputeComputedDigest(record) {
  const computedSans = { ...record.computed };
  delete computedSans.digest;
  record.computed = { ...computedSans, digest: digestComputed(computedSans) };
}

/** Recomputes the whole-record `recordDigest` envelope over current content. */
function recomputeRecordDigest(record) {
  record.recordDigest = null;
  record.recordDigest = digestRecord(record);
}

function serializeRecord(record) {
  return Buffer.from(`${canonicalize(record)}\n`, "utf8");
}

function errCode(code, pattern) {
  return (err) =>
    err && (err.code === code || (pattern && pattern.test(String(err.message))));
}

/* -------------------------------------------------------------------------- */
/* Tests                                                                      */
/* -------------------------------------------------------------------------- */

describe("Package 6B — evidence provenance v2 registry verifier", function () {
  this.timeout(120_000);

  afterEach(function () {
    cleanupTrackedTemps();
  });

  after(function () {
    cleanupTrackedTemps();
  });

  describe("documentation", function () {
    it("documents Package 6B: registry-level verification of committed provenance v2 records", function () {
      // config/provenance/v2-registry.json names one-or-more provenance v2
      // records already committed under config/provenance/v2/. Verification
      // never regenerates, normalizes, rewrites, or repairs anything — it
      // fails closed on any ambiguity, ties every record to a specific,
      // dedicated-child git container commit, and independently recomputes
      // every declared source blob hash from git object bytes at the source
      // baseline. Real Commit A used throughout this file:
      //   containerCommit        = e8697f9fc50c13fe8cc5ecf18301482cee1e6067
      //   sourceBaselineCommit    = 45c38dec9ba0e3f13db83bcbc943f1e72c64b894
      //   sourceBaselineTree      = eb6f0463882c1c5ac47c7d56900bc7ffb5ec762b
      assert.equal(typeof verifyProvenanceV2Registry, "function");
      assert.equal(REGISTRY_RELATIVE_PATH, "config/provenance/v2-registry.json");
      assert.equal(REGISTRY_KIND, "philcore-evidence-provenance-v2-registry");
      assert.equal(REGISTRY_SCHEMA_VERSION, 1);
      assert.match(CONTAINER_COMMIT, /^[0-9a-f]{40}$/);
      assert.match(SOURCE_BASELINE_COMMIT, /^[0-9a-f]{40}$/);
      assert.match(SOURCE_BASELINE_TREE, /^[0-9a-f]{40}$/);
    });
  });

  describe("Happy path — real Commit A registered via a disposable temp clone", function () {
    it("accepts the real registered Phase 5B record built in an isolated temp clone of ROOT", function () {
      const fixture = makeHappyFixture("happy");
      const result = verifyProvenanceV2Registry({ repoRoot: fixture.dir });
      assert.deepEqual(result, { ok: true, recordCount: 1 });
    });

    it("verifies ROOT directly once the registry exists there (forward-compatible; skips while absent)", function () {
      const rootRegistryPath = path.join(ROOT, REGISTRY_RELATIVE_PATH);
      if (!fs.existsSync(rootRegistryPath)) {
        this.skip();
        return;
      }
      const result = verifyProvenanceV2Registry({ repoRoot: ROOT });
      assert.equal(result.ok, true);
    });
  });

  describe("Package 6C — real repository registry contains the Sepolia offline readiness record", function () {
    it("asserts the live registry has exactly two records and the Package 6C entry identity", function () {
      const registryPath = path.join(ROOT, REGISTRY_RELATIVE_PATH);
      assert.equal(fs.existsSync(registryPath), true);
      const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
      assert.equal(registry.records.length, 2);

      const entry = registry.records.find((r) => r.id === PACKAGE_6C_REGISTRY_ID);
      assert.ok(entry, "Package 6C registry entry must be present");
      assert.equal(entry.recordPath, PACKAGE_6C_RECORD_RELATIVE_PATH);
      assert.equal(entry.containerCommit, PACKAGE_6C_CONTAINER_COMMIT);
      assert.equal(entry.sourceBaselineCommit, PACKAGE_6C_SOURCE_BASELINE_COMMIT);
      assert.equal(entry.sourceBaselineTree, PACKAGE_6C_SOURCE_BASELINE_TREE);
      assert.equal(entry.recordFileSha256, PACKAGE_6C_RECORD_FILE_SHA256);

      const result = verifyProvenanceV2Registry({ repoRoot: ROOT });
      assert.deepEqual(result, { ok: true, recordCount: 2 });
    });
  });

  describe("Registry-level schema and parsing", function () {
    it("throws REGISTRY_MISSING when config/provenance/v2-registry.json is absent", function () {
      const fixture = makeHappyFixture("missing-registry");
      fs.rmSync(fixture.registryPath);
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_MISSING")
      );
    });

    it("throws INVALID_JSON for malformed registry JSON", function () {
      const fixture = makeHappyFixture("malformed-json");
      writeRegistryRaw(fixture.dir, "{ not valid json");
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("INVALID_JSON")
      );
    });

    it("throws DUPLICATE_JSON_KEY for a raw registry payload with duplicate top-level keys", function () {
      const fixture = makeHappyFixture("dup-json-keys");
      writeRegistryRaw(
        fixture.dir,
        `{"schemaVersion":1,"schemaVersion":1,"kind":"${REGISTRY_KIND}","records":[]}`
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("DUPLICATE_JSON_KEY")
      );
    });

    it("throws REGISTRY_UNKNOWN_FIELD for an unknown registry top-level field", function () {
      const fixture = makeHappyFixture("unknown-top-field");
      writeRegistryObject(fixture.dir, {
        ...makeRegistry([fixture.entry]),
        extraTopLevelField: true
      });
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_UNKNOWN_FIELD")
      );
    });
  });

  describe("Resource limits", function () {
    it("throws RESOURCE_LIMIT_EXCEEDED for a registry file over MAX_RAW_STAGED_BYTES", function () {
      const fixture = makeHappyFixture("oversized-registry");
      writeRegistryRaw(fixture.dir, "x".repeat(RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES + 1000));
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RESOURCE_LIMIT_EXCEEDED")
      );
    });

    it("throws RESOURCE_LIMIT_EXCEEDED for a record file over MAX_RAW_STAGED_BYTES", function () {
      const fixture = makeHappyFixture("oversized-record");
      fs.writeFileSync(
        fixture.recordPath,
        Buffer.alloc(RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES + 1000, 0x61)
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RESOURCE_LIMIT_EXCEEDED")
      );
    });
  });

  describe("Entry-level schema", function () {
    it("throws REGISTRY_UNKNOWN_FIELD for an unknown entry field", function () {
      const fixture = makeHappyFixture("unknown-entry-field");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([{ ...fixture.entry, notAllowed: true }])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_UNKNOWN_FIELD")
      );
    });

    it("throws INVALID_COMMIT_SHA for a malformed containerCommit (not 40 lowercase hex)", function () {
      const fixture = makeHappyFixture("bad-sha");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: "E8697F9FC50C13FE8CC5ECF18301482CEE1E6067" })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("INVALID_COMMIT_SHA")
      );
    });
  });

  describe("Registry duplicate detection", function () {
    it("throws REGISTRY_DUPLICATE_ID when two entries share the same id", function () {
      const fixture = makeHappyFixture("dup-id");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([
          fixture.entry,
          makeEntry({
            recordPath: "config/provenance/v2/other-name.json",
            containerCommit: "1111111111111111111111111111111111111111"
          })
        ])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_DUPLICATE_ID")
      );
    });

    it("throws REGISTRY_DUPLICATE_PATH when two entries share the same recordPath", function () {
      const fixture = makeHappyFixture("dup-path");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([
          fixture.entry,
          makeEntry({
            id: "other-id",
            containerCommit: "2222222222222222222222222222222222222222"
          })
        ])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_DUPLICATE_PATH")
      );
    });

    it("throws REGISTRY_DUPLICATE_CONTAINER when two entries share the same containerCommit", function () {
      const fixture = makeHappyFixture("dup-container");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([
          fixture.entry,
          makeEntry({ id: "other-id-2", recordPath: "config/provenance/v2/other2.json" })
        ])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_DUPLICATE_CONTAINER")
      );
    });
  });

  describe("Baseline binding correctness", function () {
    it("throws BASELINE_MISMATCH when the registry's sourceBaselineCommit disagrees with the record", function () {
      const fixture = makeHappyFixture("wrong-baseline-commit");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ sourceBaselineCommit: UNRELATED_REAL_COMMIT })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("BASELINE_MISMATCH")
      );
    });

    it("throws BASELINE_MISMATCH when the registry's sourceBaselineTree disagrees with the record", function () {
      const fixture = makeHappyFixture("wrong-baseline-tree");
      const flippedFirstChar = SOURCE_BASELINE_TREE.startsWith("0") ? "1" : "0";
      const wrongTree = `${flippedFirstChar}${SOURCE_BASELINE_TREE.slice(1)}`;
      assert.notEqual(wrongTree, SOURCE_BASELINE_TREE);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ sourceBaselineTree: wrongTree })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("BASELINE_MISMATCH")
      );
    });
  });

  describe("Container topology (git parent binding)", function () {
    it("throws SOURCE_BASELINE_MERGE_CONTAINER for an orphan (zero-parent) container commit", function () {
      const fixture = makeHappyFixture("zero-parents");
      const bytes = loadRealRecordBytes();
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [] });
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_BASELINE_MERGE_CONTAINER")
      );
    });

    it("throws SOURCE_BASELINE_MERGE_CONTAINER for a merge (multi-parent) container commit", function () {
      const fixture = makeHappyFixture("multi-parents");
      const bytes = loadRealRecordBytes();
      const containerSha = buildCustomContainer(fixture.dir, {
        bytes,
        parents: [SOURCE_BASELINE_COMMIT, UNRELATED_REAL_COMMIT]
      });
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_BASELINE_MERGE_CONTAINER")
      );
    });

    it("throws SOURCE_BASELINE_NOT_DEDICATED_CHILD when the container's single parent is not sourceBaselineCommit", function () {
      const fixture = makeHappyFixture("wrong-parent");
      const bytes = loadRealRecordBytes();
      const containerSha = buildCustomContainer(fixture.dir, {
        bytes,
        parents: [UNRELATED_REAL_COMMIT]
      });
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_BASELINE_NOT_DEDICATED_CHILD")
      );
    });

    it("throws RECORD_MISSING when the container commit's tree lacks the record entirely", function () {
      const fixture = makeHappyFixture("record-absent");
      const containerSha = buildCustomContainer(fixture.dir, {
        relPath: "config/provenance/v2/unrelated-placeholder.json",
        bytes: Buffer.from("{}\n"),
        parents: [SOURCE_BASELINE_COMMIT]
      });
      writeRegistryObject(fixture.dir, makeRegistry([makeEntry({ containerCommit: containerSha })]));
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_MISSING")
      );
    });
  });

  describe("Byte-for-byte and hash integrity", function () {
    it("throws RECORD_MISSING when the record file is deleted from the working tree", function () {
      const fixture = makeHappyFixture("missing-record");
      fs.rmSync(fixture.recordPath);
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_MISSING")
      );
    });

    it("throws BYTE_MISMATCH when the working-tree record diverges from the committed container bytes", function () {
      const fixture = makeHappyFixture("changed-bytes-working-only");
      const tampered = Buffer.concat([loadRealRecordBytes(), Buffer.from("\n")]);
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, tampered);
      // registry recordFileSha256 left as the ORIGINAL correct hash.
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("BYTE_MISMATCH")
      );
    });

    it("throws HASH_MISMATCH when only the registry's recordFileSha256 is corrupted", function () {
      const fixture = makeHappyFixture("hash-mismatch");
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ recordFileSha256: "0".repeat(64) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("HASH_MISMATCH")
      );
    });

    it("throws BYTE_MISMATCH even when recordFileSha256 is updated to match tampered working-tree bytes", function () {
      // Demonstrates the byte-for-byte compare against the container's git
      // blob cannot be bypassed merely by keeping the declared hash in sync
      // with tampered working-tree bytes: the container's git object is the
      // real, unmodified content, so bytes still disagree first.
      const fixture = makeHappyFixture("candidate-diff-from-blob");
      const tampered = Buffer.concat([loadRealRecordBytes(), Buffer.from("\n")]);
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, tampered);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ recordFileSha256: sha256(tampered) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("BYTE_MISMATCH")
      );
    });
  });

  describe("Digest and sanitizer integrity", function () {
    it("throws PROVENANCE_DIGEST_MISMATCH when computed.digest is tampered inside an otherwise byte-matching container", function () {
      const fixture = makeHappyFixture("digest-mismatch");
      const record = loadRealRecordObject();
      record.computed = { ...record.computed, digest: "0".repeat(64) };
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("PROVENANCE_DIGEST_MISMATCH")
      );
    });

    it("throws a sanitize error when observed.payload carries a field outside the observation allowlist", function () {
      const fixture = makeHappyFixture("sanitizer-failure");
      const record = loadRealRecordObject();
      record.observed = {
        ...record.observed,
        payload: { ...record.observed.payload, unknownField: "not-allowed" }
      };
      record.observed.payloadDigest = digestObserved(record.observed.payload);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SANITIZE_UNKNOWN_KEY", /Unknown observation key/)
      );
    });
  });

  describe("Symlink defenses", function () {
    it("throws REGISTRY_SYMLINK when the registry file itself is a symlink", function () {
      const fixture = makeHappyFixture("symlink-registry");
      fs.rmSync(fixture.registryPath);
      const target = path.join(fixture.dir, "registry-target.json");
      fs.writeFileSync(target, JSON.stringify(makeRegistry([fixture.entry])), "utf8");
      fs.symlinkSync(target, fixture.registryPath);
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_SYMLINK")
      );
    });

    it("throws RECORD_SYMLINK when the record leaf is a live symlink", function () {
      const fixture = makeHappyFixture("symlink-record");
      fs.rmSync(fixture.recordPath);
      const target = path.join(fixture.dir, "record-target.json");
      fs.copyFileSync(path.join(ROOT, RECORD_RELATIVE_PATH), target);
      fs.symlinkSync(target, fixture.recordPath);
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_SYMLINK")
      );
    });

    it("throws RECORD_SYMLINK when the record leaf is a dangling symlink", function () {
      const fixture = makeHappyFixture("dangling-record-symlink");
      fs.rmSync(fixture.recordPath);
      fs.symlinkSync(
        path.join(fixture.dir, "config/provenance/v2/does-not-exist.json"),
        fixture.recordPath
      );
      assert.equal(fs.existsSync(fixture.recordPath), false, "symlink target must not exist");
      assert.equal(fs.lstatSync(fixture.recordPath).isSymbolicLink(), true);
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_SYMLINK")
      );
    });

    it("throws REGISTRY_SYMLINK when a path component (config/provenance) is itself a symlink", function () {
      const fixture = makeHappyFixture("symlink-path-component");
      const realTarget = path.join(fixture.dir, "config/elsewhere-provenance");
      fs.mkdirSync(realTarget, { recursive: true });
      fs.rmSync(path.join(fixture.dir, "config/provenance"), { recursive: true, force: true });
      fs.symlinkSync(realTarget, path.join(fixture.dir, "config/provenance"));
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("REGISTRY_SYMLINK")
      );
    });
  });

  describe("config/provenance/v2/ directory reconciliation", function () {
    it("throws RECORD_UNREGISTERED for an extra record-shaped file under v2/ that isn't in the registry", function () {
      const fixture = makeHappyFixture("extra-file");
      fs.writeFileSync(
        path.join(fixture.dir, "config/provenance/v2/unexpected-extra.json"),
        "{}\n"
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_UNREGISTERED")
      );
    });

    it("throws RECORD_UNREGISTERED for any other unregistered file added under v2/", function () {
      const fixture = makeHappyFixture("added-unregistered");
      fs.writeFileSync(
        path.join(fixture.dir, "config/provenance/v2/rogue-notes.txt"),
        "not a record\n"
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("RECORD_UNREGISTERED")
      );
    });

    it("throws V2_UNEXPECTED_DIRECTORY for a subdirectory found beneath v2/", function () {
      const fixture = makeHappyFixture("unexpected-dir");
      fs.mkdirSync(path.join(fixture.dir, "config/provenance/v2/nested-dir"), { recursive: true });
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("V2_UNEXPECTED_DIRECTORY")
      );
    });
  });

  describe("Independent source-blob recomputation (bijection)", function () {
    it("throws SOURCE_PATH_BIJECTION when a sourceBlobSha256 key has no matching sourcePaths entry", function () {
      const fixture = makeHappyFixture("bijection-missing-path");
      const record = tamperRecord((r) => {
        r.computed.sourcePaths = r.computed.sourcePaths.slice(1);
      });
      recomputeComputedDigest(record);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_PATH_BIJECTION")
      );
    });

    it("throws SOURCE_PATH_BIJECTION when sourceBlobSha256 has an extra key absent from sourcePaths", function () {
      const fixture = makeHappyFixture("bijection-extra-key");
      const record = tamperRecord((r) => {
        r.computed.sourceBlobSha256["apps/extra/unlisted-file.txt"] = "0".repeat(64);
      });
      recomputeComputedDigest(record);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_PATH_BIJECTION")
      );
    });

    it("throws SOURCE_PATH_BIJECTION for a duplicate entry within sourcePaths", function () {
      const fixture = makeHappyFixture("bijection-dup-path");
      const record = tamperRecord((r) => {
        r.computed.sourcePaths = [...r.computed.sourcePaths, r.computed.sourcePaths[0]];
      });
      recomputeComputedDigest(record);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_PATH_BIJECTION")
      );
    });

    it("throws SOURCE_BLOB_MISMATCH when a declared source-blob hash disagrees with the recomputed baseline blob", function () {
      const fixture = makeHappyFixture("bijection-changed-hash");
      const record = tamperRecord((r) => {
        const key = r.computed.sourcePaths[0];
        r.computed.sourceBlobSha256[key] = "0".repeat(64);
      });
      recomputeComputedDigest(record);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_BLOB_MISMATCH")
      );
    });

    it("throws SOURCE_BLOB_MISSING when a declared source path does not exist at the source baseline", function () {
      const fixture = makeHappyFixture("bijection-absent-baseline");
      const record = tamperRecord((r) => {
        const missingPath =
          "apps/philcore-ios-companion/PhilCoreCompanion/NONEXISTENT_FILE_FOR_TEST.swift";
        r.computed.sourcePaths = [...r.computed.sourcePaths, missingPath];
        r.computed.sourceBlobSha256[missingPath] = "1".repeat(64);
      });
      recomputeComputedDigest(record);
      recomputeRecordDigest(record);
      const bytes = serializeRecord(record);
      const containerSha = buildCustomContainer(fixture.dir, { bytes, parents: [SOURCE_BASELINE_COMMIT] });
      writeRecordBytes(fixture.dir, RECORD_RELATIVE_PATH, bytes);
      writeRegistryObject(
        fixture.dir,
        makeRegistry([makeEntry({ containerCommit: containerSha, recordFileSha256: sha256(bytes) })])
      );
      assert.throws(
        () => verifyProvenanceV2Registry({ repoRoot: fixture.dir }),
        errCode("SOURCE_BLOB_MISSING")
      );
    });
  });
});
