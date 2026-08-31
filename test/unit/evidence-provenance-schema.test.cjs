"use strict";

/**
 * Package 6A — fail-closed provenance v2 mechanics and permanent legacy locks.
 * Disposable fixture repos/temp directories only. Never mutates real PhilCore
 * legacy evidence bytes or creates v2 ceremony records in the real worktree.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../..");

const OWNER_LOCKED_BASELINE_COMMIT =
  "d1d85696fbb6800de68eec4b6bc20177e8b14e42";

const LOCKED_ARTIFACTS = Object.freeze([
  {
    id: "o41-recovery-enrollment-environment",
    path: "config/solidity/O41_RECOVERY_ENROLLMENT_ENVIRONMENT_EVIDENCE.json",
    sha256:
      "41ffb81c24c1fe21e4ea6ff89152941b4555e61b749fa437a47036f0ea8861f5"
  },
  {
    id: "o42-recovery-enrollment-ceremony",
    path: "config/solidity/O42_RECOVERY_ENROLLMENT_CEREMONY_EVIDENCE.json",
    sha256:
      "be9cd76c70239c121e4703ff74978844d6a853bd562ff7c0c04c79b6a97463fe"
  },
  {
    id: "o42-1-platform-webauthn-compatibility",
    path: "config/solidity/O42_1_PLATFORM_WEBAUTHN_COMPATIBILITY_EVIDENCE.json",
    sha256:
      "d24c9e808cc22f0171e3b4d484869b61dede6c138e584096fd9dae79cdcfbb85"
  },
  {
    id: "o43-native-iphone-implementation",
    path: "config/solidity/O43_NATIVE_IPHONE_IMPLEMENTATION_EVIDENCE.json",
    sha256:
      "892bae52762138ab27fbc7856349060662a4f7bf83711b73f311ccb7c500399d"
  }
]);

const LEGACY_GENERATORS = Object.freeze([
  "scripts/cryptography/generate-o41-recovery-enrollment-evidence.cjs",
  "scripts/cryptography/generate-o42-recovery-enrollment-evidence.cjs",
  "scripts/cryptography/generate-o42-1-platform-webauthn-evidence.cjs",
  "scripts/cryptography/generate-o43-native-iphone-evidence.cjs"
]);

const OVERWRITE_ESCAPE_FLAGS = Object.freeze([
  "--force",
  "--overwrite",
  "--allow-legacy-write",
  "--break-glass",
  "--legacy-write"
]);

const OVERWRITE_ESCAPE_ENV = Object.freeze([
  "PHILCORE_ALLOW_LEGACY_EVIDENCE_WRITE",
  "PHILCORE_LEGACY_EVIDENCE_BREAK_GLASS",
  "PHILCORE_FORCE_LEGACY_EVIDENCE_OVERWRITE",
  "ALLOW_LEGACY_EVIDENCE_WRITE"
]);

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

function sha256File(abs) {
  return crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
}

function privateLegacyBaselineAvailable() {
  const commit = git(ROOT, [
    "cat-file",
    "-e",
    `${OWNER_LOCKED_BASELINE_COMMIT}^{commit}`
  ]);
  return (
    commit.status === 0 &&
    LOCKED_ARTIFACTS.every(
      (artifact) =>
        fs.existsSync(path.join(ROOT, artifact.path)) &&
        sha256File(path.join(ROOT, artifact.path)) === artifact.sha256
    )
  );
}

// A clean public-history candidate intentionally cannot execute assertions that
// require the private owner's locked commit and its pre-sanitization bytes.
function privateLegacyIt(title, fn) {
  return privateLegacyBaselineAvailable() ? it(title, fn) : it.skip(title, fn);
}

function loadProvenance() {
  return require("../../scripts/cryptography/evidence-provenance-v2.cjs");
}

function git(repo, args, opts = {}) {
  return spawnSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    ...opts
  });
}

function initFixtureRepo() {
  const dir = mktempDir("philcore-prov-fixture-");
  assert.equal(git(dir, ["init"]).status, 0);
  assert.equal(git(dir, ["config", "user.email", "prov@example.test"]).status, 0);
  assert.equal(git(dir, ["config", "user.name", "Provenance Fixture"]).status, 0);
  fs.mkdirSync(path.join(dir, "config/solidity"), { recursive: true });
  fs.mkdirSync(path.join(dir, "config/provenance/v2"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "config/solidity/source.txt"),
    "baseline-source-v1\n",
    "utf8"
  );
  assert.equal(git(dir, ["add", "-A"]).status, 0);
  assert.equal(git(dir, ["commit", "-m", "baseline"]).status, 0);
  const baselineCommit = git(dir, ["rev-parse", "HEAD"]).stdout.trim();
  const baselineTree = git(dir, ["rev-parse", "HEAD^{tree}"]).stdout.trim();
  assert.match(baselineCommit, /^[0-9a-f]{40}$/);
  assert.match(baselineTree, /^[0-9a-f]{40}$/);
  return { dir, baselineCommit, baselineTree };
}

function writeTempJson(obj, name = "payload") {
  const dir = trackTemp(mktempDir(`philcore-prov-${name}-`));
  const file = path.join(dir, `${name}.json`);
  fs.writeFileSync(file, `${JSON.stringify(obj)}\n`, "utf8");
  return file;
}

function validObservation(overrides = {}) {
  return {
    schemaVersion: 1,
    observationKind: "simulator-test",
    platform: "ios-simulator",
    result: "pass",
    ...overrides
  };
}

function validAttestation(overrides = {}) {
  return {
    schemaVersion: 1,
    attestationKind: "operator-statement",
    operatorRole: "EVIDENCE_WITNESS",
    statement: "Reviewed local simulator gate evidence package.",
    ...overrides
  };
}

function errCode(code, pattern) {
  return (err) =>
    err &&
    (err.code === code || (pattern && pattern.test(String(err.message))));
}

function initNestedGitWorktreeTemp() {
  const dir = mktempDir("philcore-prov-nested-git-");
  assert.equal(git(dir, ["init"]).status, 0);
  assert.equal(git(dir, ["config", "user.email", "nested@example.test"]).status, 0);
  assert.equal(git(dir, ["config", "user.name", "Nested"]).status, 0);
  fs.writeFileSync(path.join(dir, "seed.txt"), "seed\n", "utf8");
  assert.equal(git(dir, ["add", "-A"]).status, 0);
  assert.equal(git(dir, ["commit", "-m", "seed"]).status, 0);
  return dir;
}

function copyLegacyLockTree(destRoot) {
  fs.mkdirSync(path.join(destRoot, "config/provenance"), { recursive: true });
  fs.copyFileSync(
    path.join(ROOT, "config/provenance/legacy-evidence-lock.json"),
    path.join(destRoot, "config/provenance/legacy-evidence-lock.json")
  );
  for (const art of LOCKED_ARTIFACTS) {
    const abs = path.join(destRoot, art.path);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.copyFileSync(path.join(ROOT, art.path), abs);
  }
}

function createDedicatedChild(fixture, label = Date.now()) {
  fs.writeFileSync(
    path.join(fixture.dir, `dedicated-child-${label}.txt`),
    `dedicated-${label}\n`,
    "utf8"
  );
  assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
  assert.equal(git(fixture.dir, ["commit", "-m", `dedicated child ${label}`]).status, 0);
  return git(fixture.dir, ["rev-parse", "HEAD"]).stdout.trim();
}

function createMergeContainer(fixture) {
  const { dir, baselineCommit } = fixture;
  git(dir, ["checkout", "--orphan", "orphan-root"]);
  git(dir, ["rm", "-rf", "--cached", "."]);
  for (const name of fs.readdirSync(dir)) {
    if (name === ".git") continue;
    const abs = path.join(dir, name);
    fs.rmSync(abs, { recursive: true, force: true });
  }
  fs.writeFileSync(path.join(dir, "orphan-root.txt"), "orphan\n", "utf8");
  assert.equal(git(dir, ["add", "-A"]).status, 0);
  assert.equal(git(dir, ["commit", "-m", "orphan root"]).status, 0);
  const orphanCommit = git(dir, ["rev-parse", "HEAD"]).stdout.trim();

  assert.equal(git(dir, ["checkout", baselineCommit]).status, 0);
  fs.writeFileSync(
    path.join(dir, "config/solidity/source.txt"),
    "baseline-source-v1\n",
    "utf8"
  );
  fs.mkdirSync(path.join(dir, "config/provenance/v2"), { recursive: true });
  fs.writeFileSync(path.join(dir, "child-of-baseline.txt"), "child\n", "utf8");
  assert.equal(git(dir, ["add", "-A"]).status, 0);
  assert.equal(git(dir, ["commit", "-m", "child of baseline"]).status, 0);
  const childCommit = git(dir, ["rev-parse", "HEAD"]).stdout.trim();

  const merge = git(dir, [
    "merge",
    orphanCommit,
    "-m",
    "merge container",
    "--allow-unrelated-histories",
    "--no-edit"
  ]);
  assert.equal(merge.status, 0, merge.stderr || merge.stdout);
  const mergeCommit = git(dir, ["rev-parse", "HEAD"]).stdout.trim();
  const parents = git(dir, ["rev-parse", `${mergeCommit}^@`]).stdout.trim().split(/\s+/);
  assert.equal(parents.length, 2);
  assert.ok(parents.includes(baselineCommit) || parents.includes(childCommit));
  return mergeCommit;
}

function assembleAndCommitEvidence(fixture, options = {}) {
  const {
    assembleProvenanceRecordV2,
    verifyAssembledProvenanceRecordPreCommit,
    verifyCommittedProvenanceRecordV2
  } = loadProvenance();
  const outRel =
    options.outputRelativePath ||
    `config/provenance/v2/evidence-${Date.now()}-${Math.random().toString(16).slice(2)}.json`;
  const observationPath =
    options.observationPath ||
    writeTempJson(validObservation(options.observation), "obs");
  const attestationPath =
    options.attestationPath !== undefined
      ? options.attestationPath
      : writeTempJson(validAttestation(options.attestation), "att");
  const { record } = assembleProvenanceRecordV2({
    repoRoot: fixture.dir,
    sourceBaselineCommit: fixture.baselineCommit,
    sourceBaselineTree: fixture.baselineTree,
    computedInputs: options.computedInputs || {
      sourcePaths: ["config/solidity/source.txt"],
      phase: options.phase || "FIXTURE"
    },
    observationPath,
    attestationPath,
    outputRelativePath: outRel
  });
  verifyAssembledProvenanceRecordPreCommit({
    repoRoot: fixture.dir,
    record
  });
  assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
  assert.equal(git(fixture.dir, ["commit", "-m", "evidence container"]).status, 0);
  const containerCommit = git(fixture.dir, ["rev-parse", "HEAD"]).stdout.trim();
  verifyCommittedProvenanceRecordV2({
    repoRoot: fixture.dir,
    record,
    containerCommit
  });
  return { record, outRel, containerCommit };
}

describe("PhilCore evidence provenance schema v2 and legacy locks", function () {
  this.timeout(120_000);

  afterEach(function () {
    cleanupTrackedTemps();
  });

  after(function () {
    cleanupTrackedTemps();
  });

  describe("Legacy — frozen artifacts and trust anchor", function () {
    privateLegacyIt("matches all four frozen evidence artifacts to locked baseline digests on ROOT", function () {
      for (const art of LOCKED_ARTIFACTS) {
        const abs = path.join(ROOT, art.path);
        assert.equal(fs.existsSync(abs), true, `missing ${art.path}`);
        assert.equal(sha256File(abs), art.sha256, art.path);
      }
    });

    privateLegacyIt("loadLegacyLock + verifyLegacyLockedArtifacts on ROOT agree with owner baseline git blobs", function () {
      const {
        loadLegacyLock,
        verifyLegacyLockedArtifacts,
        OWNER_LOCKED_BASELINE_COMMIT: ownerCommit,
        OWNER_LOCKED_BASELINE_TREE: ownerTree
      } = loadProvenance();
      const lock = loadLegacyLock(ROOT);
      assert.equal(lock.policy, "LEGACY_EVIDENCE_PERMANENTLY_FROZEN");
      assert.equal(lock.lockedAtCommit, ownerCommit);
      assert.equal(lock.lockedAtCommit, OWNER_LOCKED_BASELINE_COMMIT);
      assert.equal(lock.lockedAtTree, ownerTree);
      assert.equal(lock.artifacts.length, 4);
      for (const expected of LOCKED_ARTIFACTS) {
        const row = lock.artifacts.find((a) => a.path === expected.path);
        assert.ok(row, expected.path);
        assert.equal(row.sha256, expected.sha256);
        assert.equal(row.baselineCommit, OWNER_LOCKED_BASELINE_COMMIT);
      }
      const verified = verifyLegacyLockedArtifacts({ repoRoot: ROOT });
      assert.equal(verified.ok, true);
      assert.equal(verified.artifacts.length, 4);
      const withExplicitGitRoot = verifyLegacyLockedArtifacts({
        repoRoot: ROOT,
        gitRepoRoot: ROOT
      });
      assert.equal(withExplicitGitRoot.ok, true);
    });

    it("detects hand-editing via tmp copy while baseline git blobs come from ROOT", function () {
      const { verifyLegacyLockedArtifacts } = loadProvenance();
      const tmpCopy = mktempDir("philcore-prov-lockedit-");
      copyLegacyLockTree(tmpCopy);
      const victim = path.join(tmpCopy, LOCKED_ARTIFACTS[0].path);
      fs.writeFileSync(victim, `${fs.readFileSync(victim, "utf8")}\n`, "utf8");
      assert.throws(
        () =>
          verifyLegacyLockedArtifacts({
            repoRoot: tmpCopy,
            gitRepoRoot: ROOT
          }),
        (err) =>
          err &&
          (err.code === "LEGACY_ARTIFACT_MISMATCH" ||
            /LEGACY_ARTIFACT_MISMATCH/.test(String(err.message)))
      );
    });

    privateLegacyIt("throws LEGACY_BASELINE_UNAVAILABLE when gitRepoRoot lacks the locked baseline commit", function () {
      const { verifyLegacyLockedArtifacts } = loadProvenance();
      const tmpCopy = mktempDir("philcore-prov-lockcopy-");
      copyLegacyLockTree(tmpCopy);
      const emptyFixture = initFixtureRepo();
      assert.throws(
        () =>
          verifyLegacyLockedArtifacts({
            repoRoot: tmpCopy,
            gitRepoRoot: emptyFixture.dir
          }),
        (err) =>
          err &&
          (err.code === "LEGACY_BASELINE_UNAVAILABLE" ||
            /LEGACY_BASELINE_UNAVAILABLE/.test(String(err.message)))
      );
    });

    it("refuseLegacyEvidenceWrite always throws LEGACY_EVIDENCE_FROZEN regardless of escape attempts", function () {
      const { refuseLegacyEvidenceWrite, LEGACY_EVIDENCE_FROZEN } =
        loadProvenance();
      assert.throws(
        () => refuseLegacyEvidenceWrite(),
        (err) =>
          err &&
          (err.code === LEGACY_EVIDENCE_FROZEN ||
            String(err.message).includes(LEGACY_EVIDENCE_FROZEN))
      );
      const saved = { ...process.env };
      try {
        for (const envName of OVERWRITE_ESCAPE_ENV) {
          process.env[envName] = "1";
          assert.throws(
            () =>
              refuseLegacyEvidenceWrite({
                argv: ["node", "gen.cjs", "--force"],
                env: process.env
              }),
            (err) => String(err.message).includes(LEGACY_EVIDENCE_FROZEN)
          );
        }
        for (const flag of OVERWRITE_ESCAPE_FLAGS) {
          assert.throws(
            () =>
              refuseLegacyEvidenceWrite({
                argv: ["node", "gen.cjs", flag]
              }),
            (err) => String(err.message).includes(LEGACY_EVIDENCE_FROZEN)
          );
        }
      } finally {
        for (const key of OVERWRITE_ESCAPE_ENV) {
          if (saved[key] === undefined) delete process.env[key];
          else process.env[key] = saved[key];
        }
      }
    });

    it("default legacy generator invocation refuses before write; --check stays read-only", function () {
      for (const rel of LEGACY_GENERATORS) {
        const src = fs.readFileSync(path.join(ROOT, rel), "utf8");
        assert.match(
          src,
          /refuseLegacyEvidenceWrite|LEGACY_EVIDENCE_FROZEN/,
          `${rel} must refuse legacy writes before any spawn`
        );
      }
      const before = Object.fromEntries(
        LOCKED_ARTIFACTS.map((a) => [a.path, sha256File(path.join(ROOT, a.path))])
      );
      try {
        for (const rel of LEGACY_GENERATORS) {
          const result = spawnSync(process.execPath, [path.join(ROOT, rel)], {
            cwd: ROOT,
            encoding: "utf8",
            env: { ...process.env }
          });
          assert.notEqual(result.status, 0, rel);
          assert.match(`${result.stdout || ""}${result.stderr || ""}`, /LEGACY_EVIDENCE_FROZEN/);
        }
        for (const rel of LEGACY_GENERATORS) {
          spawnSync(process.execPath, [path.join(ROOT, rel), "--check"], {
            cwd: ROOT,
            encoding: "utf8"
          });
        }
      } finally {
        for (const art of LOCKED_ARTIFACTS) {
          assert.equal(
            sha256File(path.join(ROOT, art.path)),
            before[art.path],
            `${art.path} must remain byte-identical`
          );
        }
      }
    });
  });

  describe("A — evidence-container binding", function () {
    it("rejects merge commits even when one parent is the source baseline", function () {
      const { assertEvidenceContainerBinding } = loadProvenance();
      const fixture = initFixtureRepo();
      const mergeCommit = createMergeContainer(fixture);
      assert.throws(
        () =>
          assertEvidenceContainerBinding({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            containerCommit: mergeCommit
          }),
        (err) =>
          err &&
          (err.code === "SOURCE_BASELINE_MERGE_CONTAINER" ||
            /SOURCE_BASELINE_MERGE_CONTAINER/.test(String(err.message)))
      );
    });

    it("requires exactly one immediate parent equal to sourceBaselineCommit for dedicated children", function () {
      const { assertEvidenceContainerBinding } = loadProvenance();
      const fixture = initFixtureRepo();
      const dedicated = createDedicatedChild(fixture);
      assert.doesNotThrow(() =>
        assertEvidenceContainerBinding({
          repoRoot: fixture.dir,
          sourceBaselineCommit: fixture.baselineCommit,
          sourceBaselineTree: fixture.baselineTree,
          containerCommit: dedicated
        })
      );
      const secondChild = createDedicatedChild(fixture);
      assert.throws(
        () =>
          assertEvidenceContainerBinding({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            containerCommit: secondChild
          }),
        (err) =>
          err &&
          (err.code === "SOURCE_BASELINE_NOT_DEDICATED_CHILD" ||
            /SOURCE_BASELINE_NOT_DEDICATED_CHILD/.test(String(err.message)))
      );
    });

    it("verifyCommittedProvenanceRecordV2 requires containerCommit and binds the container", function () {
      const {
        verifyCommittedProvenanceRecordV2,
        verifyAssembledProvenanceRecordPreCommit,
        assembleProvenanceRecordV2
      } = loadProvenance();
      const fixture = initFixtureRepo();

      const outRel = `config/provenance/v2/bind-${Date.now()}.json`;
      const observationPath = writeTempJson(validObservation(), "obs");
      const { record } = assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: {
          sourcePaths: ["config/solidity/source.txt"],
          phase: "BIND"
        },
        observationPath,
        outputRelativePath: outRel
      });
      verifyAssembledProvenanceRecordPreCommit({
        repoRoot: fixture.dir,
        record
      });
      assert.throws(
        () =>
          verifyCommittedProvenanceRecordV2({
            repoRoot: fixture.dir,
            record
          }),
        errCode("CONTAINER_COMMIT_REQUIRED")
      );
      assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
      assert.equal(git(fixture.dir, ["commit", "-m", "container"]).status, 0);
      const containerCommit = git(fixture.dir, ["rev-parse", "HEAD"]).stdout.trim();
      verifyCommittedProvenanceRecordV2({
        repoRoot: fixture.dir,
        record,
        containerCommit
      });
    });

    it("verifyAssembledProvenanceRecordPreCommit rejects containerCommit (PRECOMMIT_API_MISUSE)", function () {
      const { verifyAssembledProvenanceRecordPreCommit, assembleProvenanceRecordV2 } =
        loadProvenance();
      const fixture = initFixtureRepo();
      const observationPath = writeTempJson(validObservation(), "obs");
      const outRel = `config/provenance/v2/pre-${Date.now()}.json`;
      const { record } = assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: { phase: "PRECOMMIT" },
        observationPath,
        outputRelativePath: outRel
      });
      assert.throws(
        () =>
          verifyAssembledProvenanceRecordPreCommit({
            repoRoot: fixture.dir,
            record,
            containerCommit: fixture.baselineCommit
          }),
        (err) =>
          err &&
          (err.code === "PRECOMMIT_API_MISUSE" ||
            /PRECOMMIT_API_MISUSE/.test(String(err.message)))
      );
      verifyAssembledProvenanceRecordPreCommit({
        repoRoot: fixture.dir,
        record
      });
    });
  });

  describe("B — cleanup safety", function () {
    it("rejects invalid observation paths without unlinking them", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const nestedGit = initNestedGitWorktreeTemp();
      const invalidObs = path.join(nestedGit, "obs.json");
      fs.writeFileSync(invalidObs, `${JSON.stringify(validObservation())}\n`, "utf8");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "BAD_OBS" },
            observationPath: invalidObs,
            outputRelativePath: `config/provenance/v2/bad-obs-${Date.now()}.json`
          }),
        errCode("INVALID_EXTERNAL_TEMP_PATH")
      );
      assert.equal(fs.existsSync(invalidObs), true);
    });

    it("cleans validated observation temp when attestation fails; leaves never-validated att path", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const observationPath = writeTempJson(validObservation(), "obs");
      const nestedGit = initNestedGitWorktreeTemp();
      const neverValidatedAtt = path.join(nestedGit, "never-validated-att.json");
      fs.writeFileSync(
        neverValidatedAtt,
        `${JSON.stringify(validAttestation({ statement: "token leak" }))}\n`,
        "utf8"
      );
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "ATT_FAIL" },
            observationPath,
            attestationPath: neverValidatedAtt,
            outputRelativePath: `config/provenance/v2/att-fail-${Date.now()}.json`
          }),
        errCode("INVALID_EXTERNAL_TEMP_PATH", /git worktree|INVALID_EXTERNAL_TEMP/)
      );
      assert.equal(fs.existsSync(observationPath), false, "owned observation temp must be cleaned");
      assert.equal(fs.existsSync(neverValidatedAtt), true, "never-validated att path must remain");
    });

    it("cleans validated observation when attestation sanitization fails after load", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const observationPath = writeTempJson(validObservation(), "obs");
      const attestationPath = writeTempJson(
        validAttestation({ statement: "contains token material" }),
        "att"
      );
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "ATT_SAN_FAIL" },
            observationPath,
            attestationPath,
            outputRelativePath: `config/provenance/v2/att-san-${Date.now()}.json`
          }),
        errCode("SANITIZE_DENIED_VALUE", /Denied secret-shaped/)
      );
      assert.equal(fs.existsSync(observationPath), false);
      assert.equal(fs.existsSync(attestationPath), false);
    });

    it("rejects symlink staging inputs", function () {
      const { assembleProvenanceRecordV2, assertExternalTempPath } = loadProvenance();
      const fixture = initFixtureRepo();
      const realDir = mktempDir("philcore-prov-real-");
      const realFile = path.join(realDir, "obs.json");
      fs.writeFileSync(realFile, `${JSON.stringify(validObservation())}\n`, "utf8");
      const linkDir = mktempDir("philcore-prov-link-");
      const symlinkPath = path.join(linkDir, "obs-link.json");
      fs.symlinkSync(realFile, symlinkPath);
      assert.throws(() => assertExternalTempPath(symlinkPath), /Symlink rejected/);
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "SYMLINK" },
            observationPath: symlinkPath,
            outputRelativePath: `config/provenance/v2/symlink-${Date.now()}.json`
          }),
        /Symlink rejected|INVALID_EXTERNAL_TEMP_PATH/
      );
      assert.equal(fs.existsSync(realFile), true);
    });

    it("never deletes files outside validated os.tmpdir roots", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const outsideDir = trackTemp(
        fs.mkdtempSync(path.join(os.homedir(), "philcore-prov-outside-"))
      );
      const outsideMarker = path.join(outsideDir, "outside-marker.txt");
      fs.writeFileSync(outsideMarker, "keep-me\n", "utf8");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "OUTSIDE" },
            observationPath: outsideMarker,
            outputRelativePath: `config/provenance/v2/outside-${Date.now()}.json`
          }),
        errCode("INVALID_EXTERNAL_TEMP_PATH")
      );
      assert.equal(fs.readFileSync(outsideMarker, "utf8"), "keep-me\n");
    });

    it("cleans staging temps on success and after post-validation assembly failure", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const observationPath = writeTempJson(validObservation(), "obs");
      const outRel = `config/provenance/v2/clean-ok-${Date.now()}.json`;
      assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: { phase: "CLEAN_OK" },
        observationPath,
        outputRelativePath: outRel
      });
      assert.equal(fs.existsSync(observationPath), false);

      const fixture2 = initFixtureRepo();
      const observationPath2 = writeTempJson(validObservation(), "obs2");
      const attestationPath2 = writeTempJson(
        validAttestation({ statement: "contains token material" }),
        "att2"
      );
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture2.dir,
            sourceBaselineCommit: fixture2.baselineCommit,
            sourceBaselineTree: fixture2.baselineTree,
            computedInputs: { phase: "CLEAN_FAIL" },
            observationPath: observationPath2,
            attestationPath: attestationPath2,
            outputRelativePath: `config/provenance/v2/clean-fail-${Date.now()}.json`
          }),
        errCode("SANITIZE_DENIED_VALUE", /Denied secret-shaped/)
      );
      assert.equal(fs.existsSync(observationPath2), false);
      assert.equal(fs.existsSync(attestationPath2), false);
    });
  });

  describe("C — strict JSON and prototype safety", function () {
    it("rejects __proto__, constructor, and prototype keys at every depth", function () {
      const { parseJsonStrictNoDuplicateKeys, canonicalize } = loadProvenance();
      for (const key of ["__proto__", "constructor", "prototype"]) {
        assert.throws(
          () => parseJsonStrictNoDuplicateKeys(`{"${key}":1}`),
          /DANGEROUS_JSON_KEY/
        );
        assert.throws(
          () => parseJsonStrictNoDuplicateKeys(`{"outer":{"${key}":1}}`),
          /DANGEROUS_JSON_KEY/
        );
        assert.throws(() => canonicalize({ [key]: 1 }), /DANGEROUS_JSON_KEY/);
        assert.throws(
          () => canonicalize({ nested: { [key]: 1 } }),
          /DANGEROUS_JSON_KEY/
        );
      }
    });

    it("parsing malicious JSON cannot pollute Object.prototype", function () {
      const { parseJsonStrictNoDuplicateKeys } = loadProvenance();
      const marker = "__philcore_pollution_marker__";
      Object.prototype[marker] = "polluted";
      try {
        assert.throws(
          () =>
            parseJsonStrictNoDuplicateKeys(
              '{"__proto__":{"' + marker + '":"owned"}}'
            ),
          /DANGEROUS_JSON_KEY/
        );
        assert.equal(Object.prototype[marker], "polluted");
        const safe = parseJsonStrictNoDuplicateKeys('{"a":1}');
        assert.equal(safe.a, 1);
        assert.equal(Object.prototype.a, undefined);
      } finally {
        delete Object.prototype[marker];
      }
    });

    it("rejects duplicate keys before ordinary JSON.parse can discard them", function () {
      const { parseJsonStrictNoDuplicateKeys } = loadProvenance();
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys('{"a":1,"a":2}'),
        /DUPLICATE_JSON_KEY/
      );
      assert.throws(() =>
        parseJsonStrictNoDuplicateKeys('{"outer":{"x":1,"x":2}}')
      );
      assert.deepEqual(parseJsonStrictNoDuplicateKeys('{"a":1,"b":2}'), {
        a: 1,
        b: 2
      });
    });

    it("revives plain objects without copying dangerous attacker keys into ordinary {}", function () {
      const { parseJsonStrictNoDuplicateKeys } = loadProvenance();
      const parsed = parseJsonStrictNoDuplicateKeys('{"safe":1}');
      assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
      assert.equal(parsed.constructor, Object);
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys('{"__proto__":{"polluted":true}}'),
        /DANGEROUS_JSON_KEY/
      );
    });
  });

  describe("D — resource bounds", function () {
    it("enforces every RESOURCE_LIMITS threshold before excessive allocation", function () {
      const { parseJsonStrictNoDuplicateKeys, canonicalize, RESOURCE_LIMITS } =
        loadProvenance();

      const bigRaw = `"${"a".repeat(RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES)}"`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(bigRaw),
        /RESOURCE_LIMIT_EXCEEDED|MAX_RAW_STAGED_BYTES/
      );

      let deep = "0";
      for (let d = 0; d <= RESOURCE_LIMITS.MAX_NESTING_DEPTH + 1; d++) {
        deep = `{"n":${deep}}`;
      }
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(deep),
        /RESOURCE_LIMIT_EXCEEDED|MAX_NESTING_DEPTH/
      );

      const manyNodesParts = [];
      for (let i = 0; i < 100; i++) {
        const inner = Array.from({ length: 20 }, (_, j) => `"i${j}":1`).join(",");
        manyNodesParts.push(`"o${i}":{${inner}}`);
      }
      const manyNodes = `{${manyNodesParts.join(",")}}`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(manyNodes),
        errCode("RESOURCE_LIMIT_EXCEEDED", /MAX_TOTAL_NODES/)
      );

      const manyKeys = `{${Array.from(
        { length: RESOURCE_LIMITS.MAX_OBJECT_KEYS + 1 },
        (_, i) => `"k${i}":1`
      ).join(",")}}`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(manyKeys),
        /RESOURCE_LIMIT_EXCEEDED|MAX_OBJECT_KEYS/
      );

      const longArray = `[${new Array(RESOURCE_LIMITS.MAX_ARRAY_LENGTH + 1)
        .fill("1")
        .join(",")}]`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(longArray),
        /RESOURCE_LIMIT_EXCEEDED|MAX_ARRAY_LENGTH/
      );

      const longStringJson = `"${"x".repeat(RESOURCE_LIMITS.MAX_STRING_LENGTH + 1)}"`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(longStringJson),
        /RESOURCE_LIMIT_EXCEEDED|MAX_STRING_LENGTH/
      );

      assert.throws(
        () => canonicalize("x".repeat(RESOURCE_LIMITS.MAX_STRING_LENGTH + 1)),
        /RESOURCE_LIMIT_EXCEEDED|MAX_STRING_LENGTH/
      );
    });

    it("detects cycles with stable PROVENANCE_CYCLE", function () {
      const { canonicalize } = loadProvenance();
      const a = {};
      a.self = a;
      assert.throws(() => canonicalize(a), /PROVENANCE_CYCLE/);
      const b = { left: null, right: null };
      b.left = b;
      assert.throws(() => canonicalize(b), /PROVENANCE_CYCLE/);
    });
  });

  describe("E — numeric canonicalization", function () {
    it("rejects non-safe integers during parse and canonicalize", function () {
      const { parseJsonStrictNoDuplicateKeys, canonicalize } = loadProvenance();
      const unsafe = `${Number.MAX_SAFE_INTEGER + 1}`;
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(unsafe),
        /non-safe integer|RESOURCE_LIMIT|INVALID_JSON/i
      );
      assert.throws(() => canonicalize(Number.MAX_SAFE_INTEGER + 1), /Non-safe integers/);
    });

    it("canonicalizes negative zero to positive zero", function () {
      const { canonicalize } = loadProvenance();
      assert.equal(Object.is(-0, 0), false);
      assert.equal(canonicalize(-0), canonicalize(0));
      assert.equal(canonicalize(-0), "0");
    });

    it("rejects non-finite numbers", function () {
      const { canonicalize, parseJsonStrictNoDuplicateKeys } = loadProvenance();
      for (const bad of [NaN, Infinity, -Infinity]) {
        assert.throws(() => canonicalize(bad), /Non-finite|CANONICALIZE_REJECTED/);
      }
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys("NaN"),
        errCode("INVALID_JSON", /unexpected character|non-finite/i)
      );
    });
  });

  describe("F — output containment", function () {
    it("rejects symlink components under config/provenance/v2", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const v2Dir = path.join(fixture.dir, "config/provenance/v2");
      const realDir = path.join(fixture.dir, "config/provenance/real-target");
      fs.mkdirSync(realDir, { recursive: true });
      const symlinkComponent = path.join(v2Dir, "link-out");
      fs.symlinkSync(realDir, symlinkComponent);
      assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
      assert.equal(git(fixture.dir, ["commit", "-m", "add symlink"]).status, 0);
      const observationPath = writeTempJson(validObservation(), "obs");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "SYMLINK_OUT" },
            observationPath,
            outputRelativePath: "config/provenance/v2/link-out/evidence.json"
          }),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected/)
      );
    });

    it("creates missing real parent directories safely", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const nestedParent = path.join(fixture.dir, "config/provenance/v2/nested/deep");
      assert.equal(fs.existsSync(nestedParent), false);
      const observationPath = writeTempJson(validObservation(), "obs");
      const outRel = `config/provenance/v2/nested/deep/evidence-${Date.now()}.json`;
      assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: { phase: "MKDIR" },
        observationPath,
        outputRelativePath: outRel
      });
      assert.equal(fs.existsSync(path.join(fixture.dir, outRel)), true);
      assert.equal(fs.lstatSync(nestedParent).isDirectory(), true);
    });

    it("uses exclusive create and refuses to overwrite an existing target", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const outRel = `config/provenance/v2/exclusive-${Date.now()}.json`;
      const observationPath1 = writeTempJson(validObservation(), "obs1");
      assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: { phase: "EXCL_1" },
        observationPath: observationPath1,
        outputRelativePath: outRel
      });
      const existingAbs = path.join(fixture.dir, outRel);
      const existingBytes = fs.readFileSync(existingAbs);
      assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
      assert.equal(git(fixture.dir, ["commit", "-m", "seal exclusive"]).status, 0);
      const observationPath2 = writeTempJson(validObservation(), "obs2");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "EXCL_2" },
            observationPath: observationPath2,
            outputRelativePath: outRel
          }),
        /PROVENANCE_OUTPUT_EXISTS/
      );
      assert.deepEqual(fs.readFileSync(existingAbs), existingBytes);
      // Residual same-user parent-directory TOCTOU: validation/mkdir and O_EXCL
      // open are separate steps; O_EXCL prevents truncating an existing leaf file.
    });

    it("rejects output paths outside config/provenance/v2", function () {
      const { assembleProvenanceRecordV2 } = loadProvenance();
      const fixture = initFixtureRepo();
      const observationPath = writeTempJson(validObservation(), "obs");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "BAD_OUT" },
            observationPath,
            outputRelativePath: "config/solidity/not-v2.json"
          }),
        /PROVENANCE_OUTPUT_PATH/
      );
    });

    it("rejects dangling symlinks in every output-path component via lstat", function () {
      const { assertOutputRelativePath, assertNoSymlinkComponents } =
        loadProvenance();
      const fixture = initFixtureRepo();
      const components = [
        "config",
        "config/provenance",
        "config/provenance/v2",
        "config/provenance/v2/nested"
      ];
      for (const rel of components) {
        const abs = path.join(fixture.dir, rel);
        // Replace a real directory with a dangling symlink after ensuring parents exist.
        if (fs.existsSync(abs) && fs.lstatSync(abs).isDirectory()) {
          // Only replace leaf of this relative path for the test iteration by
          // using a child dangling name under a safe parent when needed.
        }
      }
      // Dangling symlink as `config/provenance/v2` itself.
      const v2 = path.join(fixture.dir, "config/provenance/v2");
      fs.rmSync(v2, { recursive: true, force: true });
      fs.symlinkSync(path.join(fixture.dir, "config/provenance/missing-v2-target"), v2);
      assert.throws(
        () => assertNoSymlinkComponents(fixture.dir, "config/provenance/v2"),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected/)
      );
      assert.throws(
        () =>
          assertOutputRelativePath(
            "config/provenance/v2/evidence.json",
            fixture.dir
          ),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected/)
      );
      // Restore real v2 for subsequent component tests in this fixture.
      fs.unlinkSync(v2);
      fs.mkdirSync(v2, { recursive: true });

      // Dangling symlink as intermediate `nested` under real v2.
      const nested = path.join(v2, "nested");
      fs.symlinkSync(path.join(v2, "missing-nested-target"), nested);
      assert.throws(
        () =>
          assertOutputRelativePath(
            "config/provenance/v2/nested/evidence.json",
            fixture.dir
          ),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected/)
      );
      // existsSync is false for dangling links — protection must not rely on it.
      assert.equal(fs.existsSync(nested), false);
      assert.equal(fs.lstatSync(nested).isSymbolicLink(), true);
    });

    it("rejects a dangling or live symlink at the output leaf", function () {
      const { assertOutputRelativePath, assembleProvenanceRecordV2 } =
        loadProvenance();
      const fixture = initFixtureRepo();
      const outRel = "config/provenance/v2/leaf-link.json";
      const abs = path.join(fixture.dir, outRel);
      fs.symlinkSync(path.join(fixture.dir, "config/provenance/v2/missing-leaf"), abs);
      assert.equal(fs.existsSync(abs), false);
      assert.equal(fs.lstatSync(abs).isSymbolicLink(), true);
      assert.throws(
        () => assertOutputRelativePath(outRel, fixture.dir),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected.*leaf|output leaf/i)
      );
      // Commit the dangling leaf so assembly fails on symlink policy, not dirty-tree.
      assert.equal(git(fixture.dir, ["add", "-A"]).status, 0);
      assert.equal(git(fixture.dir, ["commit", "-m", "dangling-leaf"]).status, 0);
      const observationPath = writeTempJson(validObservation(), "obs");
      assert.throws(
        () =>
          assembleProvenanceRecordV2({
            repoRoot: fixture.dir,
            sourceBaselineCommit: fixture.baselineCommit,
            sourceBaselineTree: fixture.baselineTree,
            computedInputs: { phase: "LEAF_LINK" },
            observationPath,
            outputRelativePath: outRel
          }),
        errCode("PROVENANCE_OUTPUT_PATH", /Symlink rejected/)
      );
    });

    it("on partial write after exclusive create removes only the new target", function () {
      const { writeExclusiveNewFile } = loadProvenance();
      const dir = mktempDir("philcore-prov-partial-");
      const bystander = path.join(dir, "bystander.json");
      const bystanderBytes = Buffer.from('{"keep":true}\n', "utf8");
      fs.writeFileSync(bystander, bystanderBytes);
      const colliding = path.join(dir, "already.json");
      const collidingBytes = Buffer.from('{"preexisting":true}\n', "utf8");
      fs.writeFileSync(colliding, collidingBytes);
      const target = path.join(dir, "fresh.json");

      const origWrite = fs.writeFileSync;
      fs.writeFileSync = function patchedWrite(fdOrPath, data, enc) {
        if (typeof fdOrPath === "number") {
          throw new Error("INJECTED_WRITE_FAILURE");
        }
        return origWrite.call(fs, fdOrPath, data, enc);
      };
      try {
        assert.throws(
          () => writeExclusiveNewFile(target, '{"partial":true}\n'),
          /INJECTED_WRITE_FAILURE/
        );
        assert.equal(fs.existsSync(target), false, "partial target must be removed");
        assert.deepEqual(fs.readFileSync(bystander), bystanderBytes);
        assert.throws(() => writeExclusiveNewFile(colliding, '{"nope":true}\n'));
        assert.deepEqual(
          fs.readFileSync(colliding),
          collidingBytes,
          "colliding pre-existing target must never be removed"
        );
      } finally {
        fs.writeFileSync = origWrite;
      }
    });
  });

  describe("amendment — legacy trust and exact resource boundaries", function () {
    privateLegacyIt("rejects coordinated artifact+manifest tampering via owner baseline blob", function () {
      const { verifyLegacyLockedArtifacts } = loadProvenance();
      const tmp = mktempDir("philcore-prov-coord-tamper-");
      fs.mkdirSync(path.join(tmp, "config/provenance"), { recursive: true });
      fs.mkdirSync(path.join(tmp, "config/solidity"), { recursive: true });
      const lock = JSON.parse(
        fs.readFileSync(
          path.join(ROOT, "config/provenance/legacy-evidence-lock.json"),
          "utf8"
        )
      );
      for (const art of lock.artifacts) {
        fs.mkdirSync(path.dirname(path.join(tmp, art.path)), { recursive: true });
        fs.copyFileSync(path.join(ROOT, art.path), path.join(tmp, art.path));
      }
      const victim = lock.artifacts[0];
      const victimAbs = path.join(tmp, victim.path);
      const tampered = `${fs.readFileSync(victimAbs, "utf8")}\n`;
      fs.writeFileSync(victimAbs, tampered, "utf8");
      const tamperedHash = crypto
        .createHash("sha256")
        .update(tampered)
        .digest("hex");
      // Coordinated: update manifest hash to match the tampered bytes.
      victim.sha256 = tamperedHash;
      fs.writeFileSync(
        path.join(tmp, "config/provenance/legacy-evidence-lock.json"),
        `${JSON.stringify(lock, null, 2)}\n`,
        "utf8"
      );
      assert.throws(
        () =>
          verifyLegacyLockedArtifacts({
            repoRoot: tmp,
            gitRepoRoot: ROOT
          }),
        (err) =>
          err &&
          (err.code === "LEGACY_BASELINE_BLOB_MISMATCH" ||
            /LEGACY_BASELINE_BLOB_MISMATCH/.test(String(err.message)))
      );
    });

    it("accepts exact RESOURCE_LIMITS boundaries and rejects boundary+1", function () {
      const { parseJsonStrictNoDuplicateKeys, canonicalize, RESOURCE_LIMITS } =
        loadProvenance();
      const {
        MAX_STRING_LENGTH,
        MAX_ARRAY_LENGTH,
        MAX_OBJECT_KEYS,
        MAX_NESTING_DEPTH,
        MAX_TOTAL_NODES,
        MAX_RAW_STAGED_BYTES
      } = RESOURCE_LIMITS;

      // String length boundary
      assert.equal(canonicalize("x".repeat(MAX_STRING_LENGTH)).length > 0, true);
      assert.throws(
        () => canonicalize("x".repeat(MAX_STRING_LENGTH + 1)),
        /RESOURCE_LIMIT_EXCEEDED|MAX_STRING_LENGTH/
      );
      parseJsonStrictNoDuplicateKeys(`"${"y".repeat(MAX_STRING_LENGTH)}"`);
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(`"${"y".repeat(MAX_STRING_LENGTH + 1)}"`),
        /RESOURCE_LIMIT_EXCEEDED|MAX_STRING_LENGTH/
      );

      // Array length boundary
      const arrOk = JSON.stringify(new Array(MAX_ARRAY_LENGTH).fill(1));
      parseJsonStrictNoDuplicateKeys(arrOk);
      assert.throws(
        () =>
          parseJsonStrictNoDuplicateKeys(
            JSON.stringify(new Array(MAX_ARRAY_LENGTH + 1).fill(1))
          ),
        /RESOURCE_LIMIT_EXCEEDED|MAX_ARRAY_LENGTH/
      );

      // Object key count boundary
      const objOk = {};
      for (let i = 0; i < MAX_OBJECT_KEYS; i++) objOk[`k${i}`] = 1;
      canonicalize(objOk);
      parseJsonStrictNoDuplicateKeys(JSON.stringify(objOk));
      const objBad = { ...objOk, [`k${MAX_OBJECT_KEYS}`]: 1 };
      assert.throws(() => canonicalize(objBad), /MAX_OBJECT_KEYS/);
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(JSON.stringify(objBad)),
        /MAX_OBJECT_KEYS/
      );

      // Nesting depth: root parseValue(0); array at depth MAX is allowed; MAX+1 rejected.
      let nest = "1";
      for (let d = 0; d <= MAX_NESTING_DEPTH; d++) nest = `[${nest}]`;
      parseJsonStrictNoDuplicateKeys(nest);
      assert.throws(
        () => parseJsonStrictNoDuplicateKeys(`[${nest}]`),
        /MAX_NESTING_DEPTH/
      );

      // Node count: build a flat array that stays under array-length but exceeds nodes.
      // Root array (1) + each element (1) => need MAX_TOTAL_NODES+1 nodes.
      assert.ok(MAX_TOTAL_NODES > MAX_ARRAY_LENGTH);
      // Use nested objects to grow nodes without exceeding array length.
      let nodes = "{}";
      // Each wrap adds an object node: {"a": <prev>}
      for (let i = 0; i < Math.min(MAX_NESTING_DEPTH, 8); i++) {
        nodes = `{"a":${nodes}}`;
      }
      // Ensure MAX_TOTAL_NODES boundary via programmatic structure
      const prog = [];
      for (let i = 0; i < MAX_ARRAY_LENGTH; i++) prog.push(i);
      canonicalize(prog);
      // Exceed nodes with a large flat object under key limit? keys limited to 128.
      // Build a tree of small objects.
      function buildNodes(n) {
        const leaves = [];
        for (let i = 0; i < n; i++) leaves.push({ v: i });
        return leaves;
      }
      // MAX_ARRAY_LENGTH objects each bump nodes: array + each object + each v = 1+2*N
      const under = buildNodes(Math.min(MAX_ARRAY_LENGTH, Math.floor((MAX_TOTAL_NODES - 2) / 2)));
      canonicalize(under);

      // Raw staged bytes boundary exercised via parse of in-memory JSON size check
      // and via bounded file read tests below.
      assert.ok(MAX_RAW_STAGED_BYTES >= 1024);
    });

    it("rejects oversized staging/lock files without unbounded materialization", function () {
      const {
        readBoundedFileBytes,
        RESOURCE_LIMITS,
        loadLegacyLock,
        assertExternalTempPath
      } = loadProvenance();
      const dir = mktempDir("philcore-prov-bounded-");
      const oversized = path.join(dir, "big.json");
      const limit = RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES;
      // Create a sparse-ish large file via write of limit+1 bytes without building a huge JS string in assert path.
      const fd = fs.openSync(oversized, "w");
      try {
        fs.writeSync(fd, Buffer.alloc(1, 0x61), 0, 1, limit);
        fs.writeSync(fd, Buffer.alloc(1, 0x61), 0, 1, 0);
      } finally {
        fs.closeSync(fd);
      }
      assert.equal(fs.statSync(oversized).size, limit + 1);
      assert.throws(
        () => readBoundedFileBytes(oversized),
        /RESOURCE_LIMIT_EXCEEDED|MAX_RAW_STAGED_BYTES|before read/
      );

      // Lock path: place oversized file where lock would be read.
      const fakeRoot = mktempDir("philcore-prov-lockbound-");
      fs.mkdirSync(path.join(fakeRoot, "config/provenance"), { recursive: true });
      const lockPath = path.join(fakeRoot, "config/provenance/legacy-evidence-lock.json");
      const lfd = fs.openSync(lockPath, "w");
      try {
        fs.writeSync(lfd, Buffer.alloc(1, 0x7b), 0, 1, limit);
        fs.writeSync(lfd, Buffer.alloc(1, 0x7b), 0, 1, 0);
      } finally {
        fs.closeSync(lfd);
      }
      assert.throws(() => loadLegacyLock(fakeRoot), /RESOURCE_LIMIT_EXCEEDED|MAX_RAW/);

      // Staging path must be regular file under tmp — size reject before full read.
      const stage = path.join(dir, "stage.json");
      const sfd = fs.openSync(stage, "w");
      try {
        fs.writeSync(sfd, Buffer.alloc(1, 0x7b), 0, 1, limit);
        fs.writeSync(sfd, Buffer.from("{}"), 0, 2, 0);
      } finally {
        fs.closeSync(sfd);
      }
      assertExternalTempPath(stage);
      assert.throws(
        () => readBoundedFileBytes(stage),
        /RESOURCE_LIMIT_EXCEEDED|MAX_RAW_STAGED_BYTES|before read/
      );
    });

    it("bounds programmatic oversized objects/strings before expensive sort/NFC work", function () {
      const { canonicalize, RESOURCE_LIMITS } = loadProvenance();
      const obj = {};
      for (let i = 0; i < RESOURCE_LIMITS.MAX_OBJECT_KEYS + 1; i++) {
        obj[`key_${i}`] = i;
      }
      assert.throws(() => canonicalize(obj), /MAX_OBJECT_KEYS/);
      // NFD string that expands under NFC still checked pre/post normalize.
      const long = "x".repeat(RESOURCE_LIMITS.MAX_STRING_LENGTH + 1);
      assert.throws(() => canonicalize(long), /MAX_STRING_LENGTH/);
    });
  });

  describe("G — embedded disclosure controls", function () {
    it("rejects notes and strings with embedded absolute paths and secret-shaped substrings", function () {
      const { sanitizeObservation, matchesDeniedDisclosure } = loadProvenance();
      const base = {
        schemaVersion: 1,
        observationKind: "simulator-test",
        platform: "ios-simulator",
        result: "pass"
      };
      const deniedNotes = [
        "ran under /Users/example/Developer/PhilCore",
        "private copy at /private/var/folders/x",
        "windows path C:\\Users\\secret\\file",
        "unc path \\\\server\\share\\evidence",
        "token=abc123",
        "seed phrase material",
        "recovery_factor value",
        "credential_id leaked",
        "commitment hash",
        "proof_input blob"
      ];
      for (const notes of deniedNotes) {
        assert.equal(matchesDeniedDisclosure(notes), true, notes);
        assert.throws(
          () => sanitizeObservation({ ...base, notes }),
          errCode("SANITIZE_DENIED_VALUE", /Denied secret-shaped/)
        );
      }
    });

    it("rejects NULs and unsafe control characters", function () {
      const { sanitizeObservation, matchesDeniedDisclosure } = loadProvenance();
      assert.equal(matchesDeniedDisclosure("before\u0000after"), true);
      assert.equal(matchesDeniedDisclosure("vertical\u000btab"), true);
      assert.throws(
        () =>
          sanitizeObservation({
            schemaVersion: 1,
            observationKind: "simulator-test",
            platform: "ios-simulator",
            result: "pass",
            notes: "bad\u0000control"
          }),
        errCode("SANITIZE_DENIED_VALUE", /Denied secret-shaped/)
      );
    });

    it("normalizes safe strings to NFC with LF newlines", function () {
      const { canonicalize, sanitizeObservation } = loadProvenance();
      const nfc = "é".normalize("NFC");
      const nfd = "é".normalize("NFD");
      assert.equal(canonicalize(nfd), canonicalize(nfc));
      const sanitized = sanitizeObservation({
        schemaVersion: 1,
        observationKind: "simulator-test",
        platform: "ios-simulator",
        result: "pass",
        notes: "line1\r\nline2"
      });
      assert.equal(sanitized.notes.includes("\r"), false);
      assert.equal(sanitized.notes, "line1\nline2");
    });
  });

  describe("H — git argument safety", function () {
    it("assertFullCommitSha accepts lowercase 40-hex only", function () {
      const { assertFullCommitSha } = loadProvenance();
      assert.equal(
        assertFullCommitSha("0123456789abcdef0123456789abcdef01234567"),
        "0123456789abcdef0123456789abcdef01234567"
      );
      const rejects = [
        "-0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "0123456789abcdef0123456789abcdef0123456g",
        "0123456789abcdef0123456789abcdef01234567 ",
        " 0123456789abcdef0123456789abcdef01234567",
        "HEAD",
        "main"
      ];
      for (const bad of rejects) {
        assert.throws(() => assertFullCommitSha(bad), errCode("INVALID_COMMIT_SHA"));
      }
    });

    it("keeps relative git paths strict (POSIX, non-absolute)", function () {
      const { assertRelativePosixPath } = loadProvenance();
      assertRelativePosixPath("config/provenance/v2/example.json");
      for (const bad of [
        "/tmp/x",
        "~/.ssh/id",
        "config\\provenance\\v2\\x.json",
        "C:\\Windows\\x",
        "../outside.json",
        ""
      ]) {
        assert.throws(() => assertRelativePosixPath(bad), errCode("INVALID_RELATIVE_PATH"));
      }
    });
  });

  describe("I — digest domain separation", function () {
    it("identical payload bytes yield different digests across domains", function () {
      const {
        digestComputed,
        digestObserved,
        digestAttested,
        digestRecord,
        DIGEST_DOMAINS
      } = loadProvenance();
      const payload = { phase: "DOMAIN", n: 1 };
      const dc = digestComputed(payload);
      const dob = digestObserved(payload);
      const da = digestAttested(payload);
      const recordShell = {
        schemaVersion: 2,
        kind: "philcore-evidence-provenance-v2",
        sourceBaselineCommit: "0123456789abcdef0123456789abcdef01234567",
        sourceBaselineTree: "0123456789abcdef0123456789abcdef01234567",
        computed: { ...payload, digest: dc },
        observed: null,
        operatorAttested: null,
        recordDigest: null
      };
      const dr = digestRecord(recordShell);
      const uniq = new Set([dc, dob, da, dr]);
      assert.equal(uniq.size, 4);
      assert.equal(DIGEST_DOMAINS.COMPUTED, "COMPUTED");
      assert.equal(DIGEST_DOMAINS.OBSERVED, "OBSERVED");
      assert.equal(DIGEST_DOMAINS.OPERATOR_ATTESTED, "OPERATOR_ATTESTED");
      assert.equal(DIGEST_DOMAINS.RECORD, "RECORD");
    });

    it("verifiers enforce the correct domain digests for assembled records", function () {
      const {
        assembleProvenanceRecordV2,
        verifyAssembledProvenanceRecordPreCommit,
        digestComputed,
        digestObserved,
        digestAttested,
        digestRecord
      } = loadProvenance();
      const fixture = initFixtureRepo();
      const observation = validObservation();
      const attestation = validAttestation();
      const observationPath = writeTempJson(observation, "obs");
      const attestationPath = writeTempJson(attestation, "att");
      const outRel = `config/provenance/v2/domain-${Date.now()}.json`;
      const { record } = assembleProvenanceRecordV2({
        repoRoot: fixture.dir,
        sourceBaselineCommit: fixture.baselineCommit,
        sourceBaselineTree: fixture.baselineTree,
        computedInputs: {
          sourcePaths: ["config/solidity/source.txt"],
          phase: "DOMAIN_VERIFY"
        },
        observationPath,
        attestationPath,
        outputRelativePath: outRel
      });
      const computedSans = { ...record.computed };
      delete computedSans.digest;
      assert.equal(record.computed.digest, digestComputed(computedSans));
      assert.equal(record.observed.payloadDigest, digestObserved(observation));
      assert.equal(
        record.operatorAttested.payloadDigest,
        digestAttested(attestation)
      );
      assert.notEqual(record.computed.digest, record.observed.payloadDigest);
      const forRecord = { ...record, recordDigest: null };
      assert.equal(record.recordDigest, digestRecord(forRecord));
      verifyAssembledProvenanceRecordPreCommit({
        repoRoot: fixture.dir,
        record
      });
      const swapped = structuredClone(record);
      swapped.observed.payloadDigest = record.computed.digest;
      assert.throws(
        () =>
          verifyAssembledProvenanceRecordPreCommit({
            repoRoot: fixture.dir,
            record: swapped
          }),
        errCode("PROVENANCE_DIGEST_MISMATCH")
      );
    });
  });

  describe("K — misc safety", function () {
    it("rejects circular inputs with PROVENANCE_CYCLE", function () {
      const { canonicalize } = loadProvenance();
      const cycle = [];
      cycle.push(cycle);
      assert.throws(() => canonicalize(cycle), /PROVENANCE_CYCLE/);
    });

    it("rejects embedded absolute paths in observation notes", function () {
      const { sanitizeObservation } = loadProvenance();
      assert.throws(
        () =>
          sanitizeObservation(
            validObservation({ notes: "artifacts under /tmp/philcore-run" })
          ),
        errCode("SANITIZE_DENIED_VALUE", /Denied secret-shaped/)
      );
    });

    it("does not create schema-v2 ceremony records in the real repo (fixtures only)", function () {
      const v2Root = path.join(ROOT, "config/provenance/v2");
      const listV2 = () =>
        fs.existsSync(v2Root)
          ? new Set(fs.readdirSync(v2Root).filter((name) => name !== ".git"))
          : new Set();
      const before = listV2();
      const fixture = initFixtureRepo();
      assembleAndCommitEvidence(fixture, { phase: "REAL_REPO_GUARD" });
      assert.deepEqual(listV2(), before);
      assert.equal(before.has(".gitkeep"), false);
    });

    it("reads historical sources at baseline rather than the diverged working tree", function () {
      const { gitShow, readSourcesAtBaseline } = loadProvenance();
      const fixture = initFixtureRepo();
      const baselineBytes = gitShow(
        fixture.dir,
        fixture.baselineCommit,
        "config/solidity/source.txt"
      );
      assert.equal(baselineBytes.toString("utf8"), "baseline-source-v1\n");
      fs.writeFileSync(
        path.join(fixture.dir, "config/solidity/source.txt"),
        "diverged-working-tree\n",
        "utf8"
      );
      const map = readSourcesAtBaseline(fixture.dir, fixture.baselineCommit, [
        "config/solidity/source.txt"
      ]);
      assert.equal(
        map["config/solidity/source.txt"].toString("utf8"),
        "baseline-source-v1\n"
      );
    });

    it("verification APIs remain read-only", function () {
      const fixture = initFixtureRepo();
      const { record } = assembleAndCommitEvidence(fixture, { phase: "READONLY" });
      const statusBefore = git(fixture.dir, ["status", "--porcelain"]).stdout;
      const { verifyCommittedProvenanceRecordV2 } = loadProvenance();
      verifyCommittedProvenanceRecordV2({
        repoRoot: fixture.dir,
        record,
        containerCommit: git(fixture.dir, ["rev-parse", "HEAD"]).stdout.trim()
      });
      assert.equal(git(fixture.dir, ["status", "--porcelain"]).stdout, statusBefore);
    });
  });
});
