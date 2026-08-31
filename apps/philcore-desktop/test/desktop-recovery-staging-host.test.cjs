"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");
const { spawnSync } = require("node:child_process");

// Desktop lane runs this file with `node` (no mocha). Provide a minimal harness.
const __nodeSuite = { beforeEach: null, tests: [] };
const __usedNodeShim = typeof describe !== "function";
if (__usedNodeShim) {
  global.describe = function describe(_name, fn) {
    const ctx = { timeout() {} };
    fn.call(ctx);
  };
  global.it = function it(name, fn) {
    __nodeSuite.tests.push({ name, fn });
  };
  global.beforeEach = function beforeEach(fn) {
    __nodeSuite.beforeEach = fn;
  };
}

require("tsx/cjs");

const HOST_PATH = path.resolve(
  __dirname,
  "../src/main/recovery-staging-host.cjs"
);
const MAIN_PATH = path.resolve(__dirname, "../src/main/main.cjs");
const PRELOAD_DIR = path.resolve(__dirname, "../src/preload");
const REPO_ROOT = path.resolve(__dirname, "../../..");

const {
  PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID,
  PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID
} = require("../../phil-device-sdk/src/v2ConsumerRecoveryCeremonyLifecycle.ts");

const PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID =
  PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID;
const PHILCORE_V2_LOCAL_SECURITY_MODEL_ID =
  PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID;
const PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID =
  PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID;

const REAL_REQUIRE = Module.prototype.require;

const hostModule = require(HOST_PATH);

const {
  createRecoveryStagingHost,
  PhilCoreV2ConsumerRecoveryStagingJournalError,
  PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE
} = hostModule;

const CEREMONY_ID =
  "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34";
const ALT_CEREMONY_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT = "0xd5520BEEC59848D796EBA0badAa9c65f1be6E6F6";
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID = "11155111";
const MINTED_AT = 1_700_000_000;
const EXPIRES_AT = 1_700_000_300;
const EXPECTED_HASH =
  "0xa25696743026591b11d05287ac1b31fbcca2f26140a08d79bedf565b71d515e7";
const CEREMONY_ID_HEX = CEREMONY_ID.slice(2);
const JOURNAL_BASENAME = `ceremony_${CEREMONY_ID_HEX}.v1.json`;
const JOURNAL_TMP_BASENAME = `.ceremony_${CEREMONY_ID_HEX}.v1.json.tmp`;
const STALE_LOCK_MIN_AGE_SECONDS = 60;

const ROLE_KIND = Object.freeze([
  "ROLE0_PUBLIC_CANDIDATE_COMMITMENT_V1",
  "ROLE1_PUBLIC_CANDIDATE_COMMITMENT_V1",
  "ROLE2_PUBLIC_CANDIDATE_COMMITMENT_V1"
]);

const RETIREMENT_RECORD_KEYS = Object.freeze([
  "state",
  "endReason",
  "ceremonyId",
  "mintedAtUnixSeconds",
  "expiresAtUnixSeconds",
  "lastObservedAtUnixSeconds",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "account",
  "chainId",
  "entryPoint",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch",
  "enrollmentCeremonyHash"
]);

function assertCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(
      error.name,
      "PhilCoreV2ConsumerRecoveryStagingJournalError",
      `expected staging journal error, got ${error.name}`
    );
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return true;
  });
}

function makeStorageRoot(prefix = "philcore-staging-host-") {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync(tmp);
}

function derivePaths(storageRoot) {
  const sharedParent = path.join(storageRoot, "philcore-recovery-enrollment");
  const stagingDir = path.join(sharedParent, "ceremony-staging");
  return Object.freeze({
    storageRoot,
    sharedParent,
    stagingDir,
    lockPath: path.join(stagingDir, ".staging.lock"),
    corruptQuarantineDir: path.join(stagingDir, ".corrupt-quarantine"),
    staleLockQuarantineDir: path.join(stagingDir, ".stale-lock-quarantine"),
    journalPath: path.join(stagingDir, JOURNAL_BASENAME),
    journalTmpPath: path.join(stagingDir, JOURNAL_TMP_BASENAME)
  });
}

function validContext(overrides = {}) {
  return {
    ceremonyId: CEREMONY_ID,
    enrollmentCeremonyHash: EXPECTED_HASH,
    accountVersionId: PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    entryPoint: ENTRY_POINT,
    expectedRecoveryEpoch: "1",
    expectedValidatorEpoch: "1",
    expiresAtUnixSeconds: String(EXPIRES_AT),
    ...overrides
  };
}

function validCandidate(role, overrides = {}) {
  const commitmentByte = String(role + 1).padStart(2, "0");
  return {
    candidateKind: ROLE_KIND[role],
    candidateVersion: 1,
    publicCandidateCommitment: `0x${commitmentByte.repeat(32)}`,
    credentialGeneration: "1",
    ...overrides
  };
}

function validRetirementRecord(context, endReason, overrides = {}) {
  const ctx = validContext(context);
  const record = {
    state: "ENDED",
    endReason,
    ceremonyId: ctx.ceremonyId,
    mintedAtUnixSeconds: BigInt(MINTED_AT),
    expiresAtUnixSeconds: BigInt(ctx.expiresAtUnixSeconds),
    lastObservedAtUnixSeconds:
      endReason === "EXPIRED"
        ? BigInt(ctx.expiresAtUnixSeconds)
        : BigInt(MINTED_AT + 1),
    accountVersionId: ctx.accountVersionId,
    securityModelId: ctx.securityModelId,
    recoveryDomainId: ctx.recoveryDomainId,
    account: ACCOUNT,
    chainId: BigInt(ctx.chainId),
    entryPoint: ENTRY_POINT,
    expectedRecoveryEpoch: BigInt(ctx.expectedRecoveryEpoch),
    expectedValidatorEpoch: BigInt(ctx.expectedValidatorEpoch),
    enrollmentCeremonyHash: ctx.enrollmentCeremonyHash,
    ...overrides
  };
  assert.deepEqual(Object.keys(record).sort(), [...RETIREMENT_RECORD_KEYS].sort());
  return record;
}

function loadHostModuleWithFsFacade(facadeFactory) {
  delete require.cache[HOST_PATH];
  Module.prototype.require = function guardedRequire(request) {
    const parentFile = this.filename || (this.id && String(this.id));
    if (
      (request === "node:fs" || request === "fs")
      && parentFile === HOST_PATH
    ) {
      const realFs = REAL_REQUIRE.apply(this, arguments);
      return facadeFactory(realFs);
    }
    return REAL_REQUIRE.apply(this, arguments);
  };
  try {
    return require(HOST_PATH);
  } finally {
    Module.prototype.require = REAL_REQUIRE;
  }
}

function wrapFs(realFs, handlers = {}) {
  return new Proxy(realFs, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value === "function" && Object.prototype.hasOwnProperty.call(handlers, prop)) {
        return handlers[prop](value.bind(target));
      }
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
}

function fsyncFailOnCall(callNumber) {
  let seen = 0;
  return {
    fsyncSync(original) {
      return (...args) => {
        seen += 1;
        if (seen === callNumber) {
          const error = new Error("injected fsync failure");
          error.code = "EIO";
          throw error;
        }
        return original(...args);
      };
    }
  };
}

function fsyncFailAfterUnlink() {
  let unlinked = false;
  let failedOnce = false;
  return {
    unlinkSync(original) {
      return (...args) => {
        const result = original(...args);
        unlinked = true;
        return result;
      };
    },
    fsyncSync(original) {
      return (...args) => {
        if (unlinked && !failedOnce) {
          failedOnce = true;
          const error = new Error("injected post-unlink fsync failure");
          error.code = "EIO";
          throw error;
        }
        return original(...args);
      };
    }
  };
}

function fsyncFailAfterRename() {
  let renamed = false;
  let failedOnce = false;
  return {
    renameSync(original) {
      return (...args) => {
        const result = original(...args);
        renamed = true;
        return result;
      };
    },
    fsyncSync(original) {
      return (...args) => {
        if (renamed && !failedOnce) {
          failedOnce = true;
          const error = new Error("injected post-rename fsync failure");
          error.code = "EIO";
          throw error;
        }
        return original(...args);
      };
    }
  };
}

function fsyncFailAfterLockUnlink() {
  let lockUnlinked = false;
  return {
    unlinkSync(original) {
      return (targetPath, ...rest) => {
        const result = original(targetPath, ...rest);
        if (String(targetPath).endsWith(".staging.lock")) {
          lockUnlinked = true;
        }
        return result;
      };
    },
    fsyncSync(original) {
      return (...args) => {
        if (lockUnlinked) {
          const error = new Error("injected post-lock-unlink fsync failure");
          error.code = "EIO";
          throw error;
        }
        return original(...args);
      };
    }
  };
}

function createHarness(options = {}) {
  const storageRoot = options.storageRoot ?? makeStorageRoot();
  let now = options.startNow ?? MINTED_AT;
  const activity = {
    nowCalls: 0,
    retireCalls: [],
    livenessCalls: 0,
    fsMutations: 0
  };

  const retireCeremonyFn =
    options.retireCeremonyFn
    ?? ((ceremonyId) => validRetirementRecord(validContext(), "CANCELLED", { ceremonyId }));

  const deps = {
    storageRoot,
    retireCeremonyFn(ceremonyId) {
      activity.retireCalls.push(ceremonyId);
      return retireCeremonyFn(ceremonyId);
    },
    nowFn() {
      activity.nowCalls += 1;
      return now;
    }
  };

  if (options.livenessProbeFn) {
    deps.livenessProbeFn = (pid) => {
      activity.livenessCalls += 1;
      return options.livenessProbeFn(pid);
    };
  }

  const host = createRecoveryStagingHost(deps);
  const paths = derivePaths(storageRoot);

  return {
    host,
    storageRoot,
    paths,
    activity,
    setNow(value) {
      now = value;
    },
    getNow() {
      return now;
    },
    reconcileAndCreate(context = validContext()) {
      host.reconcileRestart();
      return host.createJournal(context);
    }
  };
}

function writeLockFile(lockPath, payload, mode = 0o600) {
  const stagingDir = path.dirname(lockPath);
  const sharedParent = path.dirname(stagingDir);
  fs.mkdirSync(stagingDir, { recursive: true, mode: 0o700 });
  const corrupt = path.join(stagingDir, ".corrupt-quarantine");
  const stale = path.join(stagingDir, ".stale-lock-quarantine");
  fs.mkdirSync(corrupt, { recursive: true, mode: 0o700 });
  fs.mkdirSync(stale, { recursive: true, mode: 0o700 });
  fs.chmodSync(sharedParent, 0o700);
  fs.chmodSync(stagingDir, 0o700);
  fs.chmodSync(corrupt, 0o700);
  fs.chmodSync(stale, 0o700);
  fs.writeFileSync(lockPath, JSON.stringify(payload), { mode });
}

function runFreshProcessAgainstPoisonedRoot(storageRoot) {
  // Fresh process must NOT inherit the parent's in-memory poison sets.
  // Parent must have released the lock before this runs.
  const script = `
    "use strict";
    process.chdir(${JSON.stringify(REPO_ROOT)});
    require("tsx/cjs");
    const HOST = ${JSON.stringify(HOST_PATH)};
    const { createRecoveryStagingHost } = require(HOST);
    const storageRoot = ${JSON.stringify(storageRoot)};
    try {
      const host = createRecoveryStagingHost({
        storageRoot,
        retireCeremonyFn() {
          return {
            state: "ENDED",
            endReason: "CANCELLED",
            ceremonyId: ${JSON.stringify(CEREMONY_ID)},
            mintedAtUnixSeconds: 1700000000n,
            expiresAtUnixSeconds: 1700000300n,
            lastObservedAtUnixSeconds: 1700000001n,
            accountVersionId: ${JSON.stringify(PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID)},
            securityModelId: ${JSON.stringify(PHILCORE_V2_LOCAL_SECURITY_MODEL_ID)},
            recoveryDomainId: ${JSON.stringify(PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID)},
            account: ${JSON.stringify(ACCOUNT)},
            chainId: 11155111n,
            entryPoint: ${JSON.stringify(ENTRY_POINT)},
            expectedRecoveryEpoch: 1n,
            expectedValidatorEpoch: 1n,
            enrollmentCeremonyHash: ${JSON.stringify(EXPECTED_HASH)}
          };
        },
        nowFn: () => 1700000000,
        livenessProbeFn: () => "DEAD"
      });
      host.reconcileRestart();
      host.close();
      process.exit(0);
    } catch (error) {
      console.error(error && error.code ? error.code : error);
      process.exit(1);
    }
  `;
  return spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    env: process.env
  });
}

describe("desktop recovery staging host (5B-1)", function () {
  describe("dependency boundary and export surface", function () {
    it("exports the closed error class, code literals, and host factory only", function () {
      assert.equal(typeof createRecoveryStagingHost, "function");
      assert.equal(
        PhilCoreV2ConsumerRecoveryStagingJournalError.prototype.name,
        "PhilCoreV2ConsumerRecoveryStagingJournalError"
      );
      assert.ok(Object.isFrozen(PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE));
      assert.equal(
        PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE.HOST_PROCESS_POISONED,
        "HOST_PROCESS_POISONED"
      );
      assert.equal(
        PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE.LOCK_RELEASE_INDETERMINATE,
        "LOCK_RELEASE_INDETERMINATE"
      );
      assert.equal(
        PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE.CEREMONY_RETIREMENT_THENABLE_REJECTED,
        "CEREMONY_RETIREMENT_THENABLE_REJECTED"
      );
    });

    it("rejects prohibited production dependency keys", function () {
      const root = makeStorageRoot();
      for (const key of ["fsOps", "processInfo", "reset", "testOnly", "createTestRecoveryStagingHost"]) {
        assert.throws(
          () => createRecoveryStagingHost({
            storageRoot: root,
            retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
            [key]: {}
          }),
          (error) => error.code === "HOST_DEPENDENCY_EXTRA"
        );
      }
    });

    it("requires storageRoot and retireCeremonyFn", function () {
      const root = makeStorageRoot();
      assert.throws(
        () => createRecoveryStagingHost({ retireCeremonyFn: () => null }),
        (error) => error.code === "HOST_DEPENDENCY_MISSING"
      );
      assert.throws(
        () => createRecoveryStagingHost({ storageRoot: root }),
        (error) => error.code === "HOST_DEPENDENCY_MISSING"
      );
    });

    it("freezes the host with exactly reconcileRestart, createJournal, stageRole, cancel, status, close", function () {
      const harness = createHarness();
      assert.ok(Object.isFrozen(harness.host));
      assert.deepEqual(
        Object.keys(harness.host).sort(),
        ["cancel", "close", "createJournal", "reconcileRestart", "stageRole", "status"].sort()
      );
      for (const method of Object.keys(harness.host)) {
        assert.equal(typeof harness.host[method], "function");
      }
      harness.host.close();
    });

    it("uses imported real node:fs and real process identity in production source", function () {
      const source = fs.readFileSync(HOST_PATH, "utf8");
      assert.ok(/require\(["']node:fs["']\)|require\(["']fs["']\)/.test(source));
      assert.equal(/\bfsOps\b/.test(source), false);
      assert.equal(/\bprocessInfo\b/.test(source), false);
      assert.equal(/\bresetPoison\b|\breset\(\)/.test(source), false);
      assert.equal(/\bcreateTestRecoveryStagingHost\b/.test(source), false);
      assert.ok(source.includes('require("tsx/cjs")'));
      assert.ok(source.includes("v2ConsumerRecoveryStagingJournal.ts"));
      assert.equal(/process\.pid/.test(source), true);
      assert.equal(/process\.getuid/.test(source), true);
    });

    it("restores Module.prototype.require after isolated fault reload", function () {
      const before = Module.prototype.require;
      const reloaded = loadHostModuleWithFsFacade((realFs) => realFs);
      assert.notEqual(reloaded, hostModule);
      assert.equal(Module.prototype.require, REAL_REQUIRE);
      assert.equal(Module.prototype.require, before);
      reloaded.createRecoveryStagingHost({
        storageRoot: makeStorageRoot("philcore-staging-reload-"),
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      }).close();
    });

    it("documents canonical single-path production loading via resolved HOST_PATH", function () {
      assert.equal(require.resolve(HOST_PATH), HOST_PATH);
      assert.equal(fs.existsSync(HOST_PATH), true);
    });
  });

  describe("storage layout and directory policy", function () {
    it("realpath-normalizes macOS /var temp roots before deriving canonical staging key", function () {
      const root = makeStorageRoot();
      assert.ok(root.startsWith(fs.realpathSync(os.tmpdir()).slice(0, 8)));
      const harness = createHarness({ storageRoot: root });
      harness.host.reconcileRestart();
      assert.equal(fs.existsSync(harness.paths.sharedParent), true);
      assert.equal(fs.existsSync(harness.paths.stagingDir), true);
      harness.host.close();
    });

    it("creates shared parent with mode 0700 and owned staging/quarantine directories", function () {
      const harness = createHarness();
      harness.host.reconcileRestart();
      assert.equal(
        fs.statSync(harness.paths.sharedParent).mode & 0o777,
        0o700
      );
      assert.equal(
        fs.statSync(harness.paths.stagingDir).mode & 0o777,
        0o700
      );
      assert.equal(
        fs.statSync(harness.paths.corruptQuarantineDir).mode & 0o777,
        0o700
      );
      assert.equal(
        fs.statSync(harness.paths.staleLockQuarantineDir).mode & 0o777,
        0o700
      );
      harness.host.close();
    });

    it("repairs existing shared-parent mode drift to 0700", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o755 });
      const harness = createHarness({ storageRoot: root });
      harness.host.reconcileRestart();
      assert.equal(fs.statSync(paths.sharedParent).mode & 0o777, 0o700);
      harness.host.close();
    });

    it("rejects owned staging directory mode drift without repair", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.stagingDir, { mode: 0o755 });
      assert.throws(
        () => createHarness({ storageRoot: root }),
        (error) => error.code === "STORAGE_DIRECTORY_MODE_INVALID"
      );
    });

    it("rejects owned quarantine directory mode drift without repair", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.stagingDir, { mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { mode: 0o755 });
      assert.throws(
        () => createHarness({ storageRoot: root }),
        (error) => error.code === "QUARANTINE_DIRECTORY_MODE_INVALID"
      );
    });

    it("rejects storage roots outside safe containment", function () {
      assert.throws(
        () => createHarness({ storageRoot: path.parse(makeStorageRoot()).root }),
        (error) => error.code === "STORAGE_ROOT_UNSAFE"
      );
    });

    it("uses the exact journal filename derived from ceremonyId", function () {
      const harness = createHarness();
      const snapshot = harness.reconcileAndCreate();
      assert.equal(snapshot.ceremonyId, CEREMONY_ID);
      assert.equal(fs.existsSync(harness.paths.journalPath), true);
      assert.match(path.basename(harness.paths.journalPath), /^ceremony_[0-9a-f]{64}\.v1\.json$/u);
      harness.host.close();
    });
  });

  describe("lock schema, liveness, and stale-lock handling", function () {
    it("acquires an exclusive lock with the exact two-key schema", function () {
      const harness = createHarness();
      harness.host.reconcileRestart();
      const raw = fs.readFileSync(harness.paths.lockPath, "utf8");
      assert.ok(raw.length <= 256);
      const parsed = JSON.parse(raw);
      assert.deepEqual(Object.keys(parsed).sort(), ["createdAtUnixSeconds", "pid"].sort());
      assert.match(parsed.pid, /^(0|[1-9][0-9]*)$/);
      assert.match(parsed.createdAtUnixSeconds, /^(0|[1-9][0-9]*)$/);
      assert.equal(Number(parsed.pid), process.pid);
      harness.host.close();
    });

    it("rejects lock files larger than 256 bytes", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: String(process.pid),
        createdAtUnixSeconds: String(MINTED_AT),
        padding: "x".repeat(300)
      });
      assert.throws(
        () => createHarness({ storageRoot: root }),
        (error) => error.code === "LOCK_FILE_OVERSIZED"
      );
    });

    it("maps production liveness probe LIVE, DEAD, and AMBIGUOUS", function () {
      const rootLive = makeStorageRoot();
      const pathsLive = derivePaths(rootLive);
      writeLockFile(pathsLive.lockPath, {
        pid: "999997",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      assert.throws(
        () => createHarness({
          storageRoot: rootLive,
          startNow: MINTED_AT,
          livenessProbeFn: () => "LIVE"
        }),
        (error) => error.code === "LOCK_HELD"
      );

      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: "999999",
        createdAtUnixSeconds: String(MINTED_AT - STALE_LOCK_MIN_AGE_SECONDS - 1)
      });
      const harnessDead = createHarness({
        storageRoot: root,
        startNow: MINTED_AT,
        livenessProbeFn: () => "DEAD"
      });
      harnessDead.host.reconcileRestart();
      harnessDead.host.close();

      writeLockFile(paths.lockPath, {
        pid: "999998",
        createdAtUnixSeconds: String(MINTED_AT - STALE_LOCK_MIN_AGE_SECONDS - 1)
      });
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "AMBIGUOUS"
        }),
        (error) => error.code === "LOCK_HELD_OR_AMBIGUOUS"
      );
    });

    it("rejects invalid injected liveness literals", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, { pid: "42", createdAtUnixSeconds: "1" });
      assert.throws(
        () => createHarness({
          storageRoot: root,
          livenessProbeFn: () => "MAYBE"
        }),
        (error) => error.code === "LOCK_LIVENESS_RESULT_INVALID"
      );
    });

    it("refuses stale-lock quarantine when age is 59 seconds", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: "424242",
        createdAtUnixSeconds: String(MINTED_AT - 59)
      });
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_HELD_OR_AMBIGUOUS"
      );
    });

    it("allows stale-lock quarantine at exactly 60 seconds of age", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: "424243",
        createdAtUnixSeconds: String(MINTED_AT - STALE_LOCK_MIN_AGE_SECONDS)
      });
      const harness = createHarness({
        storageRoot: root,
        startNow: MINTED_AT,
        livenessProbeFn: () => "DEAD"
      });
      harness.host.reconcileRestart();
      assert.equal(fs.existsSync(paths.lockPath), true);
      harness.host.close();
    });

    it("rejects future-dated lock timestamps", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: "424244",
        createdAtUnixSeconds: String(MINTED_AT + 3600)
      });
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_HELD_OR_AMBIGUOUS"
      );
    });

    it("rejects pre-existing staging mode drift even when a lock file already exists", function () {
      const root = makeStorageRoot("philcore-mode-lock-");
      const paths = derivePaths(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      fs.chmodSync(paths.stagingDir, 0o755);
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "STORAGE_DIRECTORY_MODE_INVALID"
      );
    });
  });

  describe("restart reconciliation", function () {
    it("requires reconcileRestart before createJournal and memoizes the report", function () {
      const harness = createHarness();
      assert.throws(
        () => harness.host.createJournal(validContext()),
        (error) => error.code === "RECONCILIATION_REQUIRED"
      );
      const first = harness.reconcileAndCreate();
      assert.equal(first.state, "STAGING");
      const second = harness.host.reconcileRestart();
      assert.ok(Object.isFrozen(second));
      assert.deepEqual(second, harness.host.reconcileRestart());
      harness.host.close();
    });

    it("reports ABSENT when no journal exists on disk", function () {
      const harness = createHarness();
      const report = harness.host.reconcileRestart();
      assert.equal(report.journalDisposition, "ABSENT");
      assert.equal(report.terminalState, null);
      assert.equal(report.corruptJournalFilesQuarantined, 0);
      harness.host.close();
    });

    it("supersedes and removes a valid STAGING journal on restart", function () {
      const root = makeStorageRoot();
      const first = createHarness({ storageRoot: root });
      first.reconcileAndCreate();
      first.host.close();

      const second = createHarness({ storageRoot: root });
      const report = second.host.reconcileRestart();
      assert.equal(report.journalDisposition, "STAGING_SUPERSEDED_AND_REMOVED");
      assert.equal(report.terminalState, "SUPERSEDED");
      assert.equal(fs.existsSync(second.paths.journalPath), false);
      assert.equal(second.host.status(), null);
      second.host.close();
    });

    it("removes terminal CANCELLED, EXPIRED, and SUPERSEDED journals on restart", function () {
      const pure = require("../../phil-device-sdk/src/v2ConsumerRecoveryStagingJournal.ts");
      for (const terminal of [
        { state: "CANCELLED", endReason: "CANCELLED", updatedAt: MINTED_AT + 1 },
        { state: "EXPIRED", endReason: "EXPIRED", updatedAt: EXPIRES_AT },
        { state: "SUPERSEDED", endReason: "SUPERSEDED", updatedAt: MINTED_AT + 2 }
      ]) {
        const root = makeStorageRoot(`philcore-staging-terminal-${terminal.state}-`);
        const paths = derivePaths(root);
        fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
        fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
        fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
        let journal = pure.createStagingJournal(validContext(), MINTED_AT);
        if (terminal.state === "CANCELLED") {
          journal = pure.cancelStagingJournal(journal, terminal.updatedAt);
        } else if (terminal.state === "EXPIRED") {
          journal = pure.expireStagingJournalIfNeeded(journal, terminal.updatedAt);
        } else {
          journal = pure.supersedeStagingJournal(journal, terminal.updatedAt);
        }
        assert.equal(journal.state, terminal.state);
        assert.equal(journal.endReason, terminal.endReason);
        fs.writeFileSync(paths.journalPath, `${JSON.stringify(journal)}\n`, {
          encoding: "utf8",
          mode: 0o600
        });
        const restart = createHarness({ storageRoot: root });
        const report = restart.host.reconcileRestart();
        assert.equal(report.journalDisposition, "TERMINAL_REMOVED");
        assert.equal(report.terminalState, terminal.state);
        assert.equal(fs.existsSync(restart.paths.journalPath), false);
        restart.host.close();
      }
    });

    it("never resumes STAGING into memory and finishes with status null", function () {
      const root = makeStorageRoot();
      const first = createHarness({ storageRoot: root });
      first.reconcileAndCreate();
      first.host.close();
      const second = createHarness({ storageRoot: root });
      second.host.reconcileRestart();
      assert.equal(second.host.status(), null);
      second.host.close();
    });
  });

  describe("createJournal, stageRole, cancel, and status lifecycle", function () {
    it("creates a deeply frozen public snapshot with bigint-normalized context fields as strings", function () {
      const harness = createHarness();
      const snapshot = harness.reconcileAndCreate(validContext({
        chainId: 11155111n,
        expectedRecoveryEpoch: 1n,
        expectedValidatorEpoch: 1n,
        expiresAtUnixSeconds: BigInt(EXPIRES_AT)
      }));
      assert.ok(Object.isFrozen(snapshot));
      assert.equal(snapshot.enrollmentCeremonyHash, EXPECTED_HASH);
      assert.equal(typeof snapshot.chainId, "string");
      assert.equal(snapshot.state, "STAGING");
      assert.equal(snapshot.endReason, null);
      assert.ok(Object.isFrozen(snapshot.manifest));
      harness.host.close();
    });

    it("rejects duplicate journal creation in memory and on disk", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      assert.throws(
        () => harness.host.createJournal(validContext()),
        (error) => error.code === "JOURNAL_ALREADY_EXISTS"
      );
      harness.host.close();
    });

    it("stages role candidates with host-authored role and timestamp", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      const staged = harness.host.stageRole(0, validCandidate(0));
      assert.equal(staged.manifest["0"].role, 0);
      assert.equal(staged.manifest["0"].candidateKind, ROLE_KIND[0]);
      assert.equal(staged.manifest["0"].stagedAtUnixSeconds, String(MINTED_AT));
      harness.host.close();
    });

    it("performs whole-entry replacement when re-staging the same role", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.host.stageRole(1, validCandidate(1, { credentialGeneration: "1" }));
      harness.setNow(MINTED_AT + 5);
      const replaced = harness.host.stageRole(1, validCandidate(1, { credentialGeneration: "2" }));
      assert.equal(replaced.manifest["1"].credentialGeneration, "2");
      assert.equal(replaced.manifest["1"].stagedAtUnixSeconds, String(MINTED_AT + 5));
      harness.host.close();
    });

    it("returns observational pre-expiry status without changing updatedAtUnixSeconds", function () {
      const harness = createHarness();
      const created = harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 10);
      const observed = harness.host.status();
      assert.equal(observed.updatedAtUnixSeconds, created.updatedAtUnixSeconds);
      assert.equal(observed.state, "STAGING");
      harness.host.close();
    });

    it("detects clock regression through status", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 20);
      harness.host.status();
      harness.setNow(MINTED_AT + 10);
      assertCode(() => harness.host.status(), "CLOCK_REGRESSION_DETECTED");
      harness.host.close();
    });

    it("cancels durably, invokes retirement with exact ceremonyId after unlink, then clears memory", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      const cancelled = harness.host.cancel();
      assert.equal(cancelled.state, "CANCELLED");
      assert.equal(cancelled.endReason, "CANCELLED");
      assert.equal(fs.existsSync(harness.paths.journalPath), false);
      assert.deepEqual(harness.activity.retireCalls, [CEREMONY_ID]);
      assert.equal(harness.host.status(), null);
      harness.host.close();
    });

    it("returns EXPIRED once through status at exact expiry then null on the next call", function () {
      const harness = createHarness({
        retireCeremonyFn: () => validRetirementRecord(validContext(), "EXPIRED")
      });
      harness.reconcileAndCreate();
      harness.setNow(EXPIRES_AT);
      const expired = harness.host.status();
      assert.equal(expired.state, "EXPIRED");
      assert.equal(expired.endReason, "EXPIRED");
      assert.equal(harness.host.status(), null);
      harness.host.close();
    });

    it("does not install a candidate when staging at exact expiry", function () {
      const harness = createHarness({
        retireCeremonyFn: () => validRetirementRecord(validContext(), "EXPIRED")
      });
      harness.reconcileAndCreate();
      harness.setNow(EXPIRES_AT);
      const expired = harness.host.stageRole(0, validCandidate(0));
      assert.equal(expired.state, "EXPIRED");
      assert.equal(expired.manifest["0"], null);
      assert.equal(harness.host.status(), null);
      harness.host.close();
    });
  });

  describe("retirement result classification", function () {
    function poisonedCancelHarness(retireCeremonyFn) {
      const harness = createHarness({ retireCeremonyFn });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      return harness;
    }

    it("classifies synchronous retirement throw as CEREMONY_RETIREMENT_FAILED with poison", function () {
      const harness = poisonedCancelHarness(() => {
        throw new Error("known clean 5B-0.1 precondition");
      });
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_FAILED");
      assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
      harness.host.close();
    });

    it("classifies null, undefined, boolean, number, string, bigint, symbol, and function results", function () {
      for (const value of [null, undefined, true, 1, "x", 1n, Symbol("x"), () => {}]) {
        const harness = poisonedCancelHarness(() => value);
        assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
        assertCode(() => harness.host.createJournal(validContext({ ceremonyId: ALT_CEREMONY_ID })), "HOST_PROCESS_POISONED");
        harness.host.close();
      }
    });

    it("classifies ordinary Promise and callable own then without invoking it", function () {
      const harnessPromise = poisonedCancelHarness(async () => validRetirementRecord(validContext(), "CANCELLED"));
      assertCode(() => harnessPromise.host.cancel(), "CEREMONY_RETIREMENT_THENABLE_REJECTED");
      harnessPromise.host.close();

      const harnessThen = poisonedCancelHarness(() => ({
        then(onFulfilled) {
          return onFulfilled(validRetirementRecord(validContext(), "CANCELLED"));
        }
      }));
      assertCode(() => harnessThen.host.cancel(), "CEREMONY_RETIREMENT_THENABLE_REJECTED");
      harnessThen.host.close();
    });

    it("classifies inherited callable then, throwing then getter, and Proxy traps", function () {
      const inherited = poisonedCancelHarness(() => Object.create({
        then() {
          return validRetirementRecord(validContext(), "CANCELLED");
        }
      }));
      assertCode(() => inherited.host.cancel(), "CEREMONY_RETIREMENT_THENABLE_REJECTED");
      inherited.host.close();

      const throwingGetter = poisonedCancelHarness(() => {
        const target = {};
        Object.defineProperty(target, "then", {
          get() {
            throw new Error("then getter trap");
          }
        });
        return target;
      });
      assertCode(() => throwingGetter.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      throwingGetter.host.close();

      const proxyThenLookup = poisonedCancelHarness(() => new Proxy({}, {
        get(_target, prop) {
          if (prop === "then") throw new Error("then lookup trap");
          return undefined;
        }
      }));
      assertCode(() => proxyThenLookup.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      proxyThenLookup.host.close();

      const proxyValidation = poisonedCancelHarness(() => new Proxy({}, {
        get(_target, prop) {
          if (prop === "then") return undefined;
          if (prop === "state") throw new Error("validation trap");
          return undefined;
        },
        ownKeys() {
          return [...RETIREMENT_RECORD_KEYS];
        },
        getOwnPropertyDescriptor(_target, prop) {
          if (RETIREMENT_RECORD_KEYS.includes(prop)) {
            return {
              configurable: true,
              enumerable: true,
              writable: true,
              value: undefined
            };
          }
          return undefined;
        }
      }));
      assertCode(() => proxyValidation.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      proxyValidation.host.close();
    });

    it("classifies wrong own keys, ceremony ID, state, end reason, and context mismatches", function () {
      const base = validRetirementRecord(validContext(), "CANCELLED");
      const cases = [
        { ...base, extra: true },
        Object.fromEntries(Object.entries(base).filter(([key]) => key !== "state")),
        { ...base, ceremonyId: ALT_CEREMONY_ID },
        { ...base, state: "ACTIVE" },
        { ...base, endReason: "EXPIRED" },
        { ...base, enrollmentCeremonyHash: ALT_CEREMONY_ID },
        { ...base, account: "0x0000000000000000000000000000000000000001" },
        { ...base, chainId: "11155111" },
        { ...base, chainId: 0n },
        { ...base, expectedRecoveryEpoch: 0n },
        { ...base, mintedAtUnixSeconds: 0n },
        { ...base, lastObservedAtUnixSeconds: BigInt(EXPIRES_AT) }
      ];
      for (const record of cases) {
        const harness = poisonedCancelHarness(() => record);
        assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
        harness.host.close();
      }
    });

    it("accepts a valid synchronous 5B-0.1 record with native bigint numerics compared via toString(10)", function () {
      const harness = createHarness({
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED")
      });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      const cancelled = harness.host.cancel();
      assert.equal(cancelled.endReason, "CANCELLED");
      assert.equal(harness.host.status(), null);
      harness.host.close();
    });

    it("performs zero post-failure journal deletion or recreation activity", function () {
      const harness = poisonedCancelHarness(() => null);
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      const retireCallsAfterFailure = harness.activity.retireCalls.length;
      const nowCallsAfterFailure = harness.activity.nowCalls;
      assertCode(() => harness.host.cancel(), "HOST_PROCESS_POISONED");
      assert.equal(harness.activity.retireCalls.length, retireCallsAfterFailure);
      assert.equal(harness.activity.nowCalls, nowCallsAfterFailure);
      harness.host.close();
    });
  });

  describe("filesystem durability and fault injection", function () {
    it("uses an isolated fs facade only for the host module load and unique roots per reload", function () {
      const rootA = makeStorageRoot("philcore-staging-fault-a-");
      const rootB = makeStorageRoot("philcore-staging-fault-b-");
      const modA = loadHostModuleWithFsFacade((realFs) => realFs);
      const modB = loadHostModuleWithFsFacade((realFs) => realFs);
      const hostA = modA.createRecoveryStagingHost({
        storageRoot: rootA,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      hostA.reconcileRestart();
      hostA.close();
      const hostB = modB.createRecoveryStagingHost({
        storageRoot: rootB,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      hostB.reconcileRestart();
      hostB.close();
      assert.notEqual(rootA, rootB);
    });

    it("maps post-rename directory fsync failure to DURABILITY_INDETERMINATE and poisons", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, fsyncFailAfterRename())
      );
      const host = mod.createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      host.reconcileRestart();
      assertCode(() => host.createJournal(validContext()), "DURABILITY_INDETERMINATE");
      assert.equal(fs.existsSync(paths.journalPath), true);
      const surviving = fs.readFileSync(paths.journalPath, "utf8");
      assert.ok(surviving.length > 0);
      assert.match(surviving, /"state":"STAGING"/);
      assertCode(() => host.status(), "HOST_PROCESS_POISONED");
      assertCode(() => host.createJournal(validContext()), "HOST_PROCESS_POISONED");
      host.close();
    });

    it("maps journal removal directory fsync failure to JOURNAL_REMOVAL_INDETERMINATE and poisons", function () {
      const root = makeStorageRoot();
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, fsyncFailAfterUnlink())
      );
      let now = MINTED_AT;
      let retireCalls = 0;
      const host = mod.createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => {
          retireCalls += 1;
          return validRetirementRecord(validContext(), "CANCELLED");
        },
        nowFn: () => now
      });
      host.reconcileRestart();
      host.createJournal(validContext());
      now = MINTED_AT + 1;
      assertCode(() => host.cancel(), "JOURNAL_REMOVAL_INDETERMINATE");
      assert.equal(retireCalls, 0);
      assertCode(() => host.status(), "HOST_PROCESS_POISONED");
      assertCode(() => host.cancel(), "HOST_PROCESS_POISONED");
      host.close();
    });
  });

  describe("poison semantics", function () {
    it("keeps one loaded module instance poisoned for same-process reuse of lexical root", function () {
      const root = makeStorageRoot();
      const harness = createHarness({
        storageRoot: root,
        retireCeremonyFn: () => {
          throw new Error("retire throw");
        }
      });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_FAILED");
      assertCode(
        () => createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
      harness.host.close();
    });

    it("does not treat fault-test module reload as poison recovery", function () {
      const root = makeStorageRoot();
      const mod = loadHostModuleWithFsFacade((realFs) => realFs);
      let now = MINTED_AT;
      const host = mod.createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => {
          throw new Error("retire throw");
        },
        nowFn: () => now
      });
      host.reconcileRestart();
      host.createJournal(validContext());
      now = MINTED_AT + 1;
      assertCode(() => host.cancel(), "CEREMONY_RETIREMENT_FAILED");
      assert.doesNotThrow(() => {
        const freshRoot = makeStorageRoot("philcore-staging-reload-clean-");
        const freshHost = mod.createRecoveryStagingHost({
          storageRoot: freshRoot,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        });
        freshHost.reconcileRestart();
        freshHost.close();
      });
      host.close();
    });

    it("resets poison only in a fresh child process while same process remains poisoned", function () {
      const root = makeStorageRoot();
      const harness = createHarness({
        storageRoot: root,
        retireCeremonyFn: () => {
          throw new Error("retire throw");
        }
      });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_FAILED");
      harness.host.close();

      const child = runFreshProcessAgainstPoisonedRoot(root);
      assert.equal(child.status, 0, child.stderr || child.stdout);

      assert.throws(
        () => createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) => error.code === "HOST_PROCESS_POISONED"
      );
    });
  });

  describe("close protocol", function () {
    it("allows close after poison while other methods stay inert", function () {
      const harness = createHarness({
        retireCeremonyFn: () => null
      });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      assert.doesNotThrow(() => harness.host.close());
      assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
    });

    it("returns without activity on repeated successful close", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.host.close();
      assert.doesNotThrow(() => harness.host.close());
    });

    it("rethrows LOCK_RELEASE_INDETERMINATE without filesystem activity on later close", function () {
      const root = makeStorageRoot();
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, fsyncFailAfterLockUnlink())
      );
      const host = mod.createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      host.reconcileRestart();
      host.createJournal(validContext());
      assertCode(() => host.close(), "LOCK_RELEASE_INDETERMINATE");
      assertCode(() => host.close(), "LOCK_RELEASE_INDETERMINATE");
    });

    it("never clears poison sets through close", function () {
      const root = makeStorageRoot();
      const harness = createHarness({
        storageRoot: root,
        retireCeremonyFn: () => null
      });
      harness.reconcileAndCreate();
      harness.setNow(MINTED_AT + 1);
      assertCode(() => harness.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      harness.host.close();
      assert.throws(
        () => createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) => error.code === "HOST_PROCESS_POISONED"
      );
    });
  });

  describe("restart reconciliation — disk adversaria and bounds", function () {
    it("fails before mutation when multiple journal candidates exist", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(paths.journalPath, "{}", { mode: 0o600 });
      fs.writeFileSync(
        path.join(paths.stagingDir, `ceremony_${"ab".repeat(32)}.v1.json`),
        "{}",
        { mode: 0o600 }
      );
      const harness = createHarness({ storageRoot: root });
      assert.throws(
        () => harness.host.reconcileRestart(),
        (error) => error.code === "MULTIPLE_JOURNALS_FOUND"
      );
      harness.host.close();
    });

    it("quarantines corrupt journals and reports CORRUPT_QUARANTINED", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(paths.journalPath, "{not-json", { mode: 0o600 });
      const harness = createHarness({ storageRoot: root });
      const report = harness.host.reconcileRestart();
      assert.equal(report.journalDisposition, "CORRUPT_QUARANTINED");
      assert.equal(report.corruptJournalFilesQuarantined, 1);
      assert.equal(fs.existsSync(paths.journalPath), false);
      assert.equal(fs.readdirSync(paths.corruptQuarantineDir).length, 1);
      harness.host.close();
    });

    it("quarantines filename and ceremonyId mismatches as corrupt", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      const wrongName = path.join(
        paths.stagingDir,
        `ceremony_${"cd".repeat(32)}.v1.json`
      );
      fs.writeFileSync(wrongName, "{}", { mode: 0o600 });
      const harness = createHarness({ storageRoot: root });
      const report = harness.host.reconcileRestart();
      assert.equal(report.journalDisposition, "CORRUPT_QUARANTINED");
      harness.host.close();
    });

    it("removes orphan temp files during reconciliation", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(paths.journalTmpPath, "{}", { mode: 0o600 });
      const harness = createHarness({ storageRoot: root });
      const report = harness.host.reconcileRestart();
      assert.equal(report.orphanTempFilesRemoved, 1);
      assert.equal(fs.existsSync(paths.journalTmpPath), false);
      harness.host.close();
    });

    it("rejects unexpected staging directory entries before mutation", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(paths.stagingDir, "unexpected.txt"), "x", { mode: 0o600 });
      const harness = createHarness({ storageRoot: root });
      assert.throws(
        () => harness.host.reconcileRestart(),
        (error) => error.code === "UNEXPECTED_STAGING_ENTRY"
      );
      harness.host.close();
    });

    it("installs no in-memory journal after successful reconciliation", function () {
      const root = makeStorageRoot();
      const first = createHarness({ storageRoot: root });
      first.reconcileAndCreate();
      first.host.close();
      const second = createHarness({ storageRoot: root });
      second.host.reconcileRestart();
      assert.throws(
        () => second.host.stageRole(0, validCandidate(0)),
        (error) => error.code === "JOURNAL_NOT_FOUND"
      );
      second.host.close();
    });
  });

  describe("candidate input, journal bounds, and HOST_CLOSED", function () {
    it("rejects invalid stage roles and candidate schema errors via error.code", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      assertCode(() => harness.host.stageRole(3, validCandidate(0)), "STAGE_ROLE_INVALID");
      assertCode(
        () => harness.host.stageRole(0, { ...validCandidate(0), candidateKind: "WRONG" }),
        "CANDIDATE_INPUT_KIND_MISMATCH"
      );
      harness.host.close();
    });

    it("rejects manifest entries above 512 compact bytes", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      assertCode(
        () => harness.host.stageRole(0, validCandidate(0, {
          credentialGeneration: "1".repeat(600)
        })),
        "MANIFEST_ENTRY_OVERSIZED"
      );
      harness.host.close();
    });

    it("rejects operations after close with HOST_CLOSED", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.host.close();
      assertCode(() => harness.host.reconcileRestart(), "HOST_CLOSED");
      assertCode(() => harness.host.createJournal(validContext()), "HOST_CLOSED");
      assertCode(() => harness.host.stageRole(0, validCandidate(0)), "HOST_CLOSED");
      assertCode(() => harness.host.cancel(), "HOST_CLOSED");
      assertCode(() => harness.host.status(), "HOST_CLOSED");
    });

    it("rejects expired ceremony context at createJournal", function () {
      const harness = createHarness({ startNow: EXPIRES_AT });
      harness.host.reconcileRestart();
      assertCode(
        () => harness.host.createJournal(validContext()),
        "CEREMONY_CONTEXT_EXPIRED"
      );
      harness.host.close();
    });

    it("rejects JSON number chainId in ceremony context", function () {
      const harness = createHarness();
      harness.host.reconcileRestart();
      assertCode(
        () => harness.host.createJournal(validContext({ chainId: 11155111 })),
        "CHAIN_ID_INVALID"
      );
      harness.host.close();
    });
  });

  describe("shared-parent repair failures and symlink containment", function () {
    it("maps chmod failure before confirmed mutation to STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED", function () {
      const root = makeStorageRoot();
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o755 });
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          chmodSync(original) {
            return (...args) => {
              if ((args[1] & 0o777) === 0o700) {
                const error = new Error("chmod failed");
                error.code = "EPERM";
                throw error;
              }
              return original(...args);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) => error.code === "STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED"
      );
    });

    it("rejects symlinked storage roots as unsafe", function () {
      const root = makeStorageRoot();
      const linkRoot = path.join(path.dirname(root), `philcore-staging-link-${Date.now()}`);
      fs.symlinkSync(root, linkRoot, "dir");
      assert.throws(
        () => createHarness({ storageRoot: linkRoot }),
        (error) => error.code === "STORAGE_ROOT_UNSAFE"
      );
      fs.unlinkSync(linkRoot);
    });
  });

  describe("scope and threat boundary source scans", function () {
    it("is not registered in main.cjs and has no preload IPC surface", function () {
      const mainSource = fs.readFileSync(MAIN_PATH, "utf8");
      assert.equal(mainSource.includes("recovery-staging-host"), false);
      assert.equal(mainSource.includes("createRecoveryStagingHost"), false);

      const hostSource = fs.readFileSync(HOST_PATH, "utf8");
      assert.equal(/ipcMain|BrowserWindow|contextBridge|preload/i.test(hostSource), false);
      assert.equal(
        /require\(["']electron["']\)|require\(["']node:http["']\)|require\(["']http["']\)|require\(["']node:net["']\)|require\(["']net["']\)/.test(hostSource),
        false
      );

      assert.equal(fs.existsSync(PRELOAD_DIR), true);
      for (const name of fs.readdirSync(PRELOAD_DIR)) {
        const text = fs.readFileSync(path.join(PRELOAD_DIR, name), "utf8");
        assert.equal(text.includes("recovery-staging-host"), false);
        assert.equal(text.includes("createRecoveryStagingHost"), false);
      }
    });

    it("does not reference F_FULLFSYNC, secrets, network, signing, or candidate-artifact files", function () {
      const hostSource = fs.readFileSync(HOST_PATH, "utf8");
      assert.equal(hostSource.includes("F_FULLFSYNC"), false);
      assert.equal(/mnemonic|seed phrase|privateKey|rpc|sepolia|sign(ing)?/i.test(hostSource), false);
      assert.equal(/candidate-artifact|credential-store|ipcMain/i.test(hostSource), false);
    });

    it("validates retirement records with exactly fifteen own keys and native bigint numerics", function () {
      const record = validRetirementRecord(validContext(), "CANCELLED");
      assert.equal(Object.keys(record).length, 15);
      assert.equal(record.state, "ENDED");
      assert.equal(record.chainId.toString(10), CHAIN_ID);
      assert.equal(record.expectedRecoveryEpoch.toString(10), "1");
      assert.equal(record.expiresAtUnixSeconds.toString(10), String(EXPIRES_AT));
    });
  });

  describe("corrective-pass regressions", function () {
    it("rejects a missing storageRoot without creating directories or consulting the clock", function () {
      const missingRoot = path.join(
        os.tmpdir(),
        `philcore-missing-root-${process.pid}-${Date.now()}`
      );
      assert.equal(fs.existsSync(missingRoot), false);
      let nowCalls = 0;
      assertCode(
        () => createRecoveryStagingHost({
          storageRoot: missingRoot,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn() {
            nowCalls += 1;
            throw new Error("clock must not run for missing storage root");
          }
        }),
        "STORAGE_ROOT_INVALID"
      );
      assert.equal(fs.existsSync(missingRoot), false);
      assert.equal(nowCalls, 0);
    });

    it("gives storage-safety errors precedence over a throwing nowFn", function () {
      const missingRoot = path.join(
        os.tmpdir(),
        `philcore-missing-root-prec-${process.pid}-${Date.now()}`
      );
      assertCode(
        () => createRecoveryStagingHost({
          storageRoot: missingRoot,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn() {
            throw new Error("boom");
          }
        }),
        "STORAGE_ROOT_INVALID"
      );
      assert.equal(fs.existsSync(missingRoot), false);

      const poisonedRoot = makeStorageRoot("philcore-poison-prec-");
      const first = createHarness({
        storageRoot: poisonedRoot,
        retireCeremonyFn: () => null
      });
      first.reconcileAndCreate();
      first.setNow(MINTED_AT + 1);
      assertCode(() => first.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      first.host.close();
      assertCode(
        () => createRecoveryStagingHost({
          storageRoot: poisonedRoot,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn() {
            throw new Error("clock after poison");
          }
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("maps shared-parent creation durability failure to DURABILITY_INDETERMINATE and poison", function () {
      const root = makeStorageRoot("philcore-shared-create-fsync-");
      let sharedCreated = false;
      let failNextDirFsync = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          mkdirSync(original) {
            return (target, options) => {
              const result = original(target, options);
              if (String(target).endsWith(`${path.sep}philcore-recovery-enrollment`)) {
                sharedCreated = true;
                failNextDirFsync = true;
              }
              return result;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (failNextDirFsync && sharedCreated) {
                failNextDirFsync = false;
                const error = new Error("injected shared-parent creation fsync failure");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "DURABILITY_INDETERMINATE"
      );
      assert.equal(sharedCreated, true);
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("maps owned ceremony-staging creation durability failure to DURABILITY_INDETERMINATE and poison", function () {
      const root = makeStorageRoot("philcore-owned-create-fsync-");
      let stagingCreated = false;
      let failNextDirFsync = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          mkdirSync(original) {
            return (target, options) => {
              const result = original(target, options);
              if (String(target).endsWith(`${path.sep}ceremony-staging`)) {
                stagingCreated = true;
                failNextDirFsync = true;
              }
              return result;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (failNextDirFsync && stagingCreated) {
                failNextDirFsync = false;
                const error = new Error("injected staging-dir creation fsync failure");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "DURABILITY_INDETERMINATE"
      );
      assert.equal(stagingCreated, true);
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("maps successful lock creation followed by staging-directory fsync failure to LOCK_ACQUISITION_INDETERMINATE", function () {
      const root = makeStorageRoot("philcore-lock-dir-fsync-");
      let lockCreated = false;
      let lockFileFsyncSeen = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          openSync(original) {
            return (target, flags, mode) => {
              const fd = original(target, flags, mode);
              if (
                String(target).endsWith(`${path.sep}.staging.lock`)
                && typeof flags === "number"
                && (flags & realFs.constants.O_CREAT) !== 0
              ) {
                lockCreated = true;
              }
              return fd;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (lockCreated && !lockFileFsyncSeen) {
                lockFileFsyncSeen = true;
                return original(fd);
              }
              if (lockCreated && lockFileFsyncSeen) {
                const error = new Error("injected staging-dir fsync after lock create");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "LOCK_ACQUISITION_INDETERMINATE"
      );
      assert.equal(lockCreated, true);
      assert.equal(lockFileFsyncSeen, true);
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("rejects journal files above 8192 bytes before JSON parse and accepts the 8192 boundary for corrupt classification", function () {
      const root = makeStorageRoot("philcore-journal-size-");
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });

      fs.writeFileSync(paths.journalPath, Buffer.alloc(8193, 0x61), { mode: 0o600 });
      const oversize = createHarness({ storageRoot: root });
      const oversizeReport = oversize.host.reconcileRestart();
      assert.equal(oversizeReport.journalDisposition, "CORRUPT_QUARANTINED");
      oversize.host.close();

      const root2 = makeStorageRoot("philcore-journal-size2-");
      const paths2 = derivePaths(root2);
      fs.mkdirSync(paths2.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths2.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths2.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(paths2.journalPath, Buffer.alloc(8192, 0x7b), { mode: 0o600 });
      const boundary = createHarness({ storageRoot: root2 });
      const boundaryReport = boundary.host.reconcileRestart();
      assert.equal(boundaryReport.journalDisposition, "CORRUPT_QUARANTINED");
      boundary.host.close();
    });

    it("accepts schema-valid lock payloads of exactly 256 bytes and rejects 257 before quarantine mutation", function () {
      const root256 = makeStorageRoot("philcore-lock-size256-");
      const paths256 = derivePaths(root256);
      fs.mkdirSync(paths256.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths256.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths256.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      const base = JSON.stringify({
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      const exact256 = `${base}${" ".repeat(256 - Buffer.byteLength(base, "utf8"))}`;
      assert.equal(Buffer.byteLength(exact256, "utf8"), 256);
      fs.writeFileSync(paths256.lockPath, exact256, { mode: 0o600 });
      const harness256 = createHarness({
        storageRoot: root256,
        startNow: MINTED_AT,
        livenessProbeFn: () => "DEAD"
      });
      assert.doesNotThrow(() => harness256.host.reconcileRestart());
      harness256.host.close();

      const root257 = makeStorageRoot("philcore-lock-size257-");
      const paths257 = derivePaths(root257);
      fs.mkdirSync(paths257.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths257.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths257.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      const exact257 = `${base}${" ".repeat(257 - Buffer.byteLength(base, "utf8"))}`;
      assert.equal(Buffer.byteLength(exact257, "utf8"), 257);
      fs.writeFileSync(paths257.lockPath, exact257, { mode: 0o600 });
      const beforeEntries = fs.readdirSync(paths257.staleLockQuarantineDir);
      assert.throws(
        () => createHarness({
          storageRoot: root257,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_FILE_OVERSIZED"
      );
      assert.deepEqual(fs.readdirSync(paths257.staleLockQuarantineDir), beforeEntries);
    });
  });

  describe("adversarial lock/journal/quarantine/write coverage", function () {
    function prepareStagingLayout(root) {
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.chmodSync(paths.sharedParent, 0o700);
      fs.chmodSync(paths.stagingDir, 0o700);
      fs.chmodSync(paths.corruptQuarantineDir, 0o700);
      fs.chmodSync(paths.staleLockQuarantineDir, 0o700);
      return paths;
    }

    function assertLockRejects(payload, code) {
      const root = makeStorageRoot("philcore-lock-reject-");
      const paths = prepareStagingLayout(root);
      fs.writeFileSync(paths.lockPath, JSON.stringify(payload), { mode: 0o600 });
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === code
      );
    }

    it("enforces lock pid bounds and canonical syntax", function () {
      assertLockRejects({ pid: "0", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: "2147483648", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: "-1", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: " 1", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: "1e2", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: "1_1", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");
      assertLockRejects({ pid: "01", createdAtUnixSeconds: String(MINTED_AT - 120) }, "LOCK_PID_INVALID");

      for (const pid of ["1", "2147483647"]) {
        const root = makeStorageRoot("philcore-lock-pid-ok-");
        const paths = prepareStagingLayout(root);
        writeLockFile(paths.lockPath, {
          pid,
          createdAtUnixSeconds: String(MINTED_AT - 120)
        });
        const harness = createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        });
        assert.doesNotThrow(() => harness.host.reconcileRestart());
        harness.host.close();
      }
    });

    it("enforces lock createdAtUnixSeconds bounds and canonical syntax", function () {
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "0" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "281474976710656" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "-1" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: " 1" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "1e3" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "1_0" }, "LOCK_CREATED_AT_INVALID");
      assertLockRejects({ pid: "1", createdAtUnixSeconds: "01" }, "LOCK_CREATED_AT_INVALID");

      const rootMin = makeStorageRoot("philcore-lock-created-min-");
      const pathsMin = prepareStagingLayout(rootMin);
      writeLockFile(pathsMin.lockPath, { pid: "1", createdAtUnixSeconds: "1" });
      const harnessMin = createHarness({
        storageRoot: rootMin,
        startNow: MINTED_AT,
        livenessProbeFn: () => "DEAD"
      });
      assert.doesNotThrow(() => harnessMin.host.reconcileRestart());
      harnessMin.host.close();

      const rootMax = makeStorageRoot("philcore-lock-created-max-");
      const pathsMax = prepareStagingLayout(rootMax);
      writeLockFile(pathsMax.lockPath, {
        pid: "1",
        createdAtUnixSeconds: "281474976710655"
      });
      assert.throws(
        () => createHarness({
          storageRoot: rootMax,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_HELD_OR_AMBIGUOUS"
      );
    });

    it("fills stale-lock quarantine slots 0-9 and refuses before entry 11", function () {
      const root = makeStorageRoot("philcore-stale-slots-");
      const paths = prepareStagingLayout(root);
      fs.chmodSync(paths.sharedParent, 0o700);
      fs.chmodSync(paths.stagingDir, 0o700);
      fs.chmodSync(paths.corruptQuarantineDir, 0o700);
      fs.chmodSync(paths.staleLockQuarantineDir, 0o700);
      for (let slot = 0; slot < 10; slot += 1) {
        fs.writeFileSync(
          path.join(paths.staleLockQuarantineDir, `staging.lock.stale.${slot}`),
          "{}",
          { mode: 0o600 }
        );
      }
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      fs.chmodSync(paths.lockPath, 0o600);
      assert.equal(fs.readdirSync(paths.staleLockQuarantineDir).length, 10);
      assert.throws(
        () => createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "STALE_LOCK_QUARANTINE_BOUND_EXCEEDED"
      );
      assert.equal(fs.readdirSync(paths.staleLockQuarantineDir).length, 10);
      assert.equal(fs.existsSync(paths.lockPath), true);
    });

    it("maps a lost race after stale-lock quarantine to LOCK_HELD", function () {
      const root = makeStorageRoot("philcore-stale-lost-race-");
      const paths = prepareStagingLayout(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      let renamedOnce = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          renameSync(original) {
            return (from, to) => {
              const result = original(from, to);
              if (!renamedOnce && String(from).endsWith(".staging.lock")) {
                renamedOnce = true;
                fs.writeFileSync(
                  from,
                  JSON.stringify({
                    pid: "2",
                    createdAtUnixSeconds: String(MINTED_AT)
                  }),
                  { mode: 0o600 }
                );
              }
              return result;
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_HELD"
      );
    });

    it("fills corrupt-journal quarantine slots 0-9 and refuses before entry 11", function () {
      const root = makeStorageRoot("philcore-corrupt-slots-");
      const paths = prepareStagingLayout(root);
      for (let slot = 0; slot < 10; slot += 1) {
        fs.writeFileSync(
          path.join(paths.corruptQuarantineDir, `${JOURNAL_BASENAME}.corrupt.${slot}`),
          "{}",
          { mode: 0o600 }
        );
      }
      fs.writeFileSync(paths.journalPath, "{not-json", { mode: 0o600 });
      const before = fs.readdirSync(paths.corruptQuarantineDir).length;
      const harness = createHarness({ storageRoot: root });
      assert.throws(
        () => harness.host.reconcileRestart(),
        (error) => error.code === "CORRUPT_QUARANTINE_BOUND_EXCEEDED"
      );
      assert.equal(fs.readdirSync(paths.corruptQuarantineDir).length, before);
      assert.equal(fs.existsSync(paths.journalPath), true);
      harness.host.close();
    });

    it("refuses createJournal when a matching temp already exists (MAX_TEMP_FILES = 1)", function () {
      const harness = createHarness();
      harness.host.reconcileRestart();
      fs.writeFileSync(harness.paths.journalTmpPath, "{}", { mode: 0o600 });
      assertCode(() => harness.host.createJournal(validContext()), "TEMP_FILE_BOUND_EXCEEDED");
      harness.host.close();
    });

    it("fails reconciliation before mutation at temp-sweep 11 and keeps operation counting within bound for legal layouts", function () {
      const rootTemps = makeStorageRoot("philcore-temp-sweep-");
      const pathsTemps = prepareStagingLayout(rootTemps);
      fs.chmodSync(pathsTemps.sharedParent, 0o700);
      fs.chmodSync(pathsTemps.stagingDir, 0o700);
      fs.chmodSync(pathsTemps.corruptQuarantineDir, 0o700);
      fs.chmodSync(pathsTemps.staleLockQuarantineDir, 0o700);
      for (let i = 0; i < 11; i += 1) {
        const hex = i.toString(16).padStart(64, "a");
        fs.writeFileSync(
          path.join(pathsTemps.stagingDir, `.ceremony_${hex}.v1.json.tmp`),
          "{}",
          { mode: 0o600 }
        );
      }
      const harnessTemps = createHarness({ storageRoot: rootTemps });
      assert.throws(
        () => harnessTemps.host.reconcileRestart(),
        (error) => error.code === "RECONCILIATION_TEMP_SWEEP_BOUND_EXCEEDED"
      );
      assert.equal(
        fs.readdirSync(pathsTemps.stagingDir).filter((name) => name.endsWith(".tmp")).length,
        11
      );
      harnessTemps.host.close();

      const rootTen = makeStorageRoot("philcore-temp-sweep10-");
      const pathsTen = prepareStagingLayout(rootTen);
      fs.chmodSync(pathsTen.sharedParent, 0o700);
      fs.chmodSync(pathsTen.stagingDir, 0o700);
      fs.chmodSync(pathsTen.corruptQuarantineDir, 0o700);
      fs.chmodSync(pathsTen.staleLockQuarantineDir, 0o700);
      for (let i = 0; i < 10; i += 1) {
        const hex = i.toString(16).padStart(64, "e");
        fs.writeFileSync(
          path.join(pathsTen.stagingDir, `.ceremony_${hex}.v1.json.tmp`),
          "{}",
          { mode: 0o600 }
        );
      }
      const harnessTen = createHarness({ storageRoot: rootTen });
      const report = harnessTen.host.reconcileRestart();
      assert.equal(report.orphanTempFilesRemoved, 10);
      assert.equal(report.operationsPerformed, 10);
      assert.equal(report.operationsPerformed <= 32, true);
      assert.equal(
        fs.readdirSync(pathsTen.stagingDir).filter((name) => name.endsWith(".tmp")).length,
        0
      );
      harnessTen.host.close();
    });

    it("rejects zero-progress and maps partial writes through the write loop", function () {
      const root = makeStorageRoot("philcore-partial-write-");
      let calls = 0;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          writeSync(original) {
            return (fd, buffer, offset, length, position) => {
              calls += 1;
              if (calls === 1) {
                return 0;
              }
              return original(fd, buffer, offset, length, position);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) =>
          error.code === "FILESYSTEM_MUTATION_FAILED"
          || error.code === "LOCK_ACQUISITION_FAILED"
          || error.code === "LOCK_ACQUISITION_INDETERMINATE"
      );
    });

    it("detects retained lock descriptor versus fresh-path inode replacement", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      const lockStat = fs.statSync(harness.paths.lockPath);
      const moved = path.join(harness.storageRoot, ".moved-staging-lock");
      fs.renameSync(harness.paths.lockPath, moved);
      fs.writeFileSync(
        harness.paths.lockPath,
        JSON.stringify({
          pid: String(process.pid),
          createdAtUnixSeconds: String(MINTED_AT)
        }),
        { mode: 0o600 }
      );
      const replacement = fs.statSync(harness.paths.lockPath);
      assert.notEqual(`${lockStat.dev}:${lockStat.ino}`, `${replacement.dev}:${replacement.ino}`);
      let statusCode = null;
      try {
        harness.host.status();
      } catch (error) {
        statusCode = error.code;
      }
      assert.equal(
        statusCode === "LOCK_LOST_OR_REPLACED" || statusCode === "LOCK_DESCRIPTOR_INVALID",
        true,
        `expected lock replacement detection, got ${statusCode}`
      );
      try {
        harness.host.close();
      } catch (error) {
        assert.equal(error.code, "LOCK_RELEASE_INDETERMINATE");
      }
      assert.equal(fs.existsSync(harness.paths.lockPath), true);
      fs.unlinkSync(moved);
    });

    it("rejects hard-linked lock files through nlink !== 1", function () {
      const root = makeStorageRoot("philcore-hardlink-");
      const paths = prepareStagingLayout(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      const linkPath = path.join(paths.stagingDir, ".staging.lock.hardlink");
      fs.linkSync(paths.lockPath, linkPath);
      assert.throws(
        () => createHarness({
          storageRoot: root,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_DESCRIPTOR_INVALID"
      );
      fs.unlinkSync(linkPath);
    });

    it("rejects wrong owner and wrong mode for lock and journal files", function () {
      const rootLockMode = makeStorageRoot("philcore-lock-mode-");
      const pathsLockMode = prepareStagingLayout(rootLockMode);
      writeLockFile(pathsLockMode.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      }, 0o644);
      assert.throws(
        () => createHarness({
          storageRoot: rootLockMode,
          startNow: MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_DESCRIPTOR_INVALID"
      );

      const rootJournalMode = makeStorageRoot("philcore-journal-mode-");
      const first = createHarness({ storageRoot: rootJournalMode });
      first.reconcileAndCreate();
      first.host.close();
      fs.chmodSync(first.paths.journalPath, 0o644);
      const second = createHarness({ storageRoot: rootJournalMode });
      assert.throws(
        () => second.host.reconcileRestart(),
        (error) => error.code === "JOURNAL_DESCRIPTOR_INVALID"
      );
      second.host.close();

      const rootOwner = makeStorageRoot("philcore-lock-owner-");
      const pathsOwner = prepareStagingLayout(rootOwner);
      writeLockFile(pathsOwner.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          fstatSync(original) {
            return (fd) => {
              const stat = original(fd);
              if (stat.isFile() && (stat.mode & 0o777) === 0o600) {
                return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
                  uid: stat.uid + 1
                });
              }
              return stat;
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: rootOwner,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) =>
          error.code === "LOCK_DESCRIPTOR_INVALID"
          || error.code === "STORAGE_DIRECTORY_OWNER_INVALID"
          || error.code === "STORAGE_DIRECTORY_INVALID"
      );
    });

    it("rejects nonregular lock and journal paths", function () {
      const rootLock = makeStorageRoot("philcore-lock-dir-");
      const pathsLock = prepareStagingLayout(rootLock);
      fs.mkdirSync(pathsLock.lockPath, { mode: 0o700 });
      assert.throws(
        () => createHarness({ storageRoot: rootLock }),
        (error) => error.code === "LOCK_DESCRIPTOR_INVALID"
      );

      const rootJournal = makeStorageRoot("philcore-journal-dir-");
      const pathsJournal = prepareStagingLayout(rootJournal);
      fs.mkdirSync(pathsJournal.journalPath, { mode: 0o700 });
      const harness = createHarness({ storageRoot: rootJournal });
      assert.throws(
        () => harness.host.reconcileRestart(),
        (error) => error.code === "JOURNAL_DESCRIPTOR_INVALID"
      );
      harness.host.close();
    });

    it("maps shared-parent post-chmod verification/fsync failure to STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE", function () {
      const root = makeStorageRoot("philcore-shared-repair-indet-");
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o755 });
      let chmodSeen = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          chmodSync(original) {
            return (...args) => {
              const result = original(...args);
              chmodSeen = true;
              return result;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (chmodSeen) {
                const error = new Error("injected post-chmod fsync failure");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) => error.code === "STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE"
      );
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("maps pre-rename temp cleanup durability failure to TEMP_REMOVAL_INDETERMINATE", function () {
      const root = makeStorageRoot("philcore-temp-removal-");
      const paths = derivePaths(root);
      fs.mkdirSync(paths.stagingDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.staleLockQuarantineDir, { recursive: true, mode: 0o700 });
      fs.chmodSync(paths.sharedParent, 0o700);
      fs.chmodSync(paths.stagingDir, 0o700);
      fs.chmodSync(paths.corruptQuarantineDir, 0o700);
      fs.chmodSync(paths.staleLockQuarantineDir, 0o700);
      fs.writeFileSync(paths.journalTmpPath, "{}", { mode: 0o600 });
      let failNextTempFsync = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          unlinkSync(original) {
            return (target, ...rest) => {
              const result = original(target, ...rest);
              if (String(target).endsWith(".tmp")) {
                failNextTempFsync = true;
              }
              return result;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (failNextTempFsync) {
                failNextTempFsync = false;
                const error = new Error("injected temp-removal fsync failure");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      const host = mod.createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      assertCode(() => host.reconcileRestart(), "TEMP_REMOVAL_INDETERMINATE");
      assertCode(() => host.status(), "HOST_PROCESS_POISONED");
      host.close();
    });

    it("never unlinks a foreign lock when close() sees retained/fresh identity mismatch", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      const foreignPayload = JSON.stringify({
        pid: "9",
        createdAtUnixSeconds: String(MINTED_AT)
      });
      fs.unlinkSync(harness.paths.lockPath);
      fs.writeFileSync(harness.paths.lockPath, foreignPayload, { mode: 0o600 });
      assertCode(() => harness.host.close(), "LOCK_RELEASE_INDETERMINATE");
      assert.equal(fs.existsSync(harness.paths.lockPath), true);
      assert.equal(fs.readFileSync(harness.paths.lockPath, "utf8"), foreignPayload);
      assertCode(() => harness.host.close(), "LOCK_RELEASE_INDETERMINATE");
      assert.equal(fs.existsSync(harness.paths.lockPath), true);
    });

    it("fails newly created owned-directory confirmation when post-create fsync fails", function () {
      const root = makeStorageRoot("philcore-newdir-fsync-");
      let mkdirSeen = false;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          mkdirSync(original) {
            return (...args) => {
              const result = original(...args);
              mkdirSeen = true;
              return result;
            };
          },
          fsyncSync(original) {
            return (fd) => {
              if (mkdirSeen) {
                const error = new Error("injected post-create dir fsync failure");
                error.code = "EIO";
                throw error;
              }
              return original(fd);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        (error) => error.code === "DURABILITY_INDETERMINATE"
      );
      assertCode(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT
        }),
        "HOST_PROCESS_POISONED"
      );
    });

    it("rejects quarantine-directory failure before clock, liveness, and lock activity", function () {
      const root = makeStorageRoot("philcore-quarantine-prec-");
      const paths = derivePaths(root);
      fs.mkdirSync(paths.sharedParent, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.stagingDir, { mode: 0o700 });
      fs.mkdirSync(paths.corruptQuarantineDir, { mode: 0o755 });
      let nowCalls = 0;
      let livenessCalls = 0;
      assert.throws(
        () => createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn() {
            nowCalls += 1;
            throw new Error("clock must not run before quarantine validation");
          },
          livenessProbeFn() {
            livenessCalls += 1;
            return "DEAD";
          }
        }),
        (error) => error.code === "QUARANTINE_DIRECTORY_MODE_INVALID"
      );
      assert.equal(nowCalls, 0);
      assert.equal(livenessCalls, 0);
      assert.equal(fs.existsSync(paths.lockPath), false);
    });

    it("observes public-method clock precedence for lock-only and journal-state gates", function () {
      const harness = createHarness();
      const report = harness.host.reconcileRestart();
      const beforeMemo = harness.activity.nowCalls;
      const again = harness.host.reconcileRestart();
      assert.deepEqual(again, report);
      assert.equal(harness.activity.nowCalls, beforeMemo);

      assert.equal(harness.host.status(), null);
      assert.equal(harness.activity.nowCalls, beforeMemo);

      assertCode(
        () => harness.host.stageRole(0, validCandidate(0)),
        "JOURNAL_NOT_FOUND"
      );
      assert.equal(harness.activity.nowCalls, beforeMemo);
      assertCode(() => harness.host.cancel(), "JOURNAL_NOT_FOUND");
      assert.equal(harness.activity.nowCalls, beforeMemo);

      const snapshot = harness.host.createJournal(validContext());
      assert.equal(snapshot.state, "STAGING");
      const afterCreate = harness.activity.nowCalls;
      assertCode(
        () => harness.host.createJournal(validContext()),
        "JOURNAL_ALREADY_EXISTS"
      );
      assert.equal(harness.activity.nowCalls, afterCreate);
      harness.host.close();

      const rootDisk = makeStorageRoot("philcore-clock-disk-");
      const pathsDisk = prepareStagingLayout(rootDisk);
      fs.writeFileSync(pathsDisk.journalPath, "{}", { mode: 0o600 });
      const diskHarness = createHarness({ storageRoot: rootDisk });
      // Corrupt journal is quarantined during reconcile; plant another after.
      diskHarness.host.reconcileRestart();
      fs.writeFileSync(pathsDisk.journalPath, "{}", { mode: 0o600 });
      const beforeDisk = diskHarness.activity.nowCalls;
      assertCode(
        () => diskHarness.host.createJournal(validContext()),
        "DISK_STATE_CHANGED"
      );
      assert.equal(diskHarness.activity.nowCalls, beforeDisk);
      diskHarness.host.close();
    });

    it("validates host stageRole candidates before INVALID_NOW and expiry clock activity", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      harness.setNow(EXPIRES_AT);
      const nowCalls = harness.activity.nowCalls;
      assertCode(
        () => harness.host.stageRole(0, { ...validCandidate(0), extra: true }),
        "CANDIDATE_INPUT_EXTRA_KEY"
      );
      assert.equal(harness.activity.nowCalls, nowCalls);
      assertCode(
        () => harness.host.stageRole(0, {
          ...validCandidate(0),
          publicCandidateCommitment: `0x${"00".repeat(32)}`
        }),
        "CANDIDATE_INPUT_COMMITMENT_INVALID"
      );
      assert.equal(harness.activity.nowCalls, nowCalls);
      harness.host.close();
    });

    it("latches RECONCILIATION_FAILED and preserves temps when corrupt quarantine is full", function () {
      const root = makeStorageRoot("philcore-recon-latch-");
      const paths = prepareStagingLayout(root);
      for (let slot = 0; slot < 10; slot += 1) {
        fs.writeFileSync(
          path.join(paths.corruptQuarantineDir, `ceremony_x.v1.json.corrupt.${slot}`),
          "{}",
          { mode: 0o600 }
        );
      }
      fs.writeFileSync(paths.journalPath, "{not-json", { mode: 0o600 });
      const tempPath = path.join(
        paths.stagingDir,
        `.ceremony_${"cd".repeat(32)}.v1.json.tmp`
      );
      fs.writeFileSync(tempPath, "{}", { mode: 0o600 });
      const harness = createHarness({ storageRoot: root });
      assertCode(() => harness.host.reconcileRestart(), "CORRUPT_QUARANTINE_BOUND_EXCEEDED");
      assert.equal(fs.existsSync(tempPath), true);
      assert.equal(fs.existsSync(paths.journalPath), true);
      assertCode(() => harness.host.reconcileRestart(), "RECONCILIATION_FAILED");
      assertCode(() => harness.host.createJournal(validContext()), "RECONCILIATION_FAILED");
      assertCode(() => harness.host.status(), "RECONCILIATION_FAILED");
      harness.host.close();
    });

    it("proves the reachable reconciliation operation maximum under simultaneous temp and journal bounds", function () {
      // Under MAX_RECONCILIATION_TEMP_SWEEP=10 and a single journal, the current
      // reachable plan is 10 temp removals + supersede write + journal remove = 12.
      // Operation 33 is unreachable without inventing illegal disk state.
      const root2 = makeStorageRoot("philcore-op-max2-");
      const paths2 = prepareStagingLayout(root2);
      const seeder = createHarness({ storageRoot: root2 });
      seeder.reconcileAndCreate();
      seeder.host.close();
      for (let i = 0; i < 10; i += 1) {
        const hex = i.toString(16).padStart(64, "2");
        fs.writeFileSync(
          path.join(paths2.stagingDir, `.ceremony_${hex}.v1.json.tmp`),
          "{}",
          { mode: 0o600 }
        );
      }
      const beforeTemps = fs
        .readdirSync(paths2.stagingDir)
        .filter((name) => name.endsWith(".tmp")).length;
      assert.equal(beforeTemps, 10);
      assert.equal(fs.existsSync(paths2.journalPath), true);
      const harness = createHarness({ storageRoot: root2 });
      const report = harness.host.reconcileRestart();
      assert.equal(report.orphanTempFilesRemoved, 10);
      assert.equal(report.journalDisposition, "STAGING_SUPERSEDED_AND_REMOVED");
      assert.equal(report.operationsPerformed, 12);
      assert.equal(
        fs.readdirSync(paths2.stagingDir).filter((name) => name.endsWith(".tmp")).length,
        0
      );
      assert.equal(fs.existsSync(paths2.journalPath), false);
      harness.host.close();
    });

    it("fails closed when an existing lock path is replaced immediately before read", function () {
      const root = makeStorageRoot("philcore-lock-preread-");
      const paths = prepareStagingLayout(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      let lockOpens = 0;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          openSync(original) {
            return (...args) => {
              const target = String(args[0]);
              if (target.endsWith(`${path.sep}.staging.lock`)) {
                lockOpens += 1;
                // Opens 1-2: retained + identity probe. Open 3: pre-read probe.
                if (lockOpens === 3) {
                  fs.unlinkSync(paths.lockPath);
                  fs.writeFileSync(
                    paths.lockPath,
                    JSON.stringify({
                      pid: "9",
                      createdAtUnixSeconds: String(MINTED_AT)
                    }),
                    { mode: 0o600 }
                  );
                }
              }
              return original(...args);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_DESCRIPTOR_INVALID"
      );
    });

    it("fails closed when a lock path is replaced immediately before stale quarantine rename", function () {
      const root = makeStorageRoot("philcore-lock-prerename-");
      const paths = prepareStagingLayout(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      let lockOpens = 0;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          openSync(original) {
            return (...args) => {
              const target = String(args[0]);
              if (target.endsWith(`${path.sep}.staging.lock`)) {
                lockOpens += 1;
                // Opens 1-3: retained, identity probe, pre-read probe.
                // Open 4: quarantine pre-rename probe.
                if (lockOpens === 4) {
                  fs.unlinkSync(paths.lockPath);
                  fs.writeFileSync(
                    paths.lockPath,
                    JSON.stringify({
                      pid: "8",
                      createdAtUnixSeconds: String(MINTED_AT)
                    }),
                    { mode: 0o600 }
                  );
                }
              }
              return original(...args);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "LOCK_DESCRIPTOR_INVALID"
      );
    });

    it("fails closed when orphan temp or corrupt journal path identity changes before mutation", function () {
      const rootTemp = makeStorageRoot("philcore-temp-race-");
      const pathsTemp = prepareStagingLayout(rootTemp);
      const tempPath = path.join(
        pathsTemp.stagingDir,
        `.ceremony_${"aa".repeat(32)}.v1.json.tmp`
      );
      fs.writeFileSync(tempPath, "{}", { mode: 0o600 });
      let tempOpens = 0;
      const modTemp = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          openSync(original) {
            return (...args) => {
              const target = String(args[0]);
              if (target === tempPath) {
                tempOpens += 1;
                // Open 1 retained, open 2 identity probe, open 3 pre-unlink probe.
                if (tempOpens === 3) {
                  fs.unlinkSync(tempPath);
                  fs.writeFileSync(tempPath, "{}", { mode: 0o600 });
                }
              }
              return original(...args);
            };
          }
        })
      );
      const hostTemp = modTemp.createRecoveryStagingHost({
        storageRoot: rootTemp,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      assert.throws(
        () => hostTemp.reconcileRestart(),
        (error) => error.code === "JOURNAL_DESCRIPTOR_INVALID"
      );
      hostTemp.close();

      const rootCorrupt = makeStorageRoot("philcore-corrupt-race-");
      const pathsCorrupt = prepareStagingLayout(rootCorrupt);
      fs.writeFileSync(pathsCorrupt.journalPath, "{not-json", { mode: 0o600 });
      let journalOpens = 0;
      const modCorrupt = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          openSync(original) {
            return (...args) => {
              const target = String(args[0]);
              if (target === pathsCorrupt.journalPath) {
                journalOpens += 1;
                // Classification: retained+probe. Quarantine: retained+probe+pre-rename.
                // Replace immediately before the pre-rename probe.
                if (journalOpens === 5) {
                  fs.unlinkSync(pathsCorrupt.journalPath);
                  fs.writeFileSync(pathsCorrupt.journalPath, "{also-bad", { mode: 0o600 });
                }
              }
              return original(...args);
            };
          }
        })
      );
      const hostCorrupt = modCorrupt.createRecoveryStagingHost({
        storageRoot: rootCorrupt,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn: () => MINTED_AT
      });
      assert.throws(
        () => hostCorrupt.reconcileRestart(),
        (error) => error.code === "JOURNAL_DESCRIPTOR_INVALID"
      );
      hostCorrupt.close();
    });

    it("rejects host nowFn above uint48 max and retirement chainId above uint256 max", function () {
      const rootClock = makeStorageRoot("philcore-uint48-");
      assertCode(
        () => createRecoveryStagingHost({
          storageRoot: rootClock,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => 281474976710656
        }),
        "INVALID_NOW"
      );

      const harnessRetire = createHarness({
        retireCeremonyFn: () => {
          const record = validRetirementRecord(validContext(), "CANCELLED");
          return {
            ...record,
            chainId: (1n << 256n)
          };
        }
      });
      harnessRetire.reconcileAndCreate();
      assertCode(() => harnessRetire.host.cancel(), "CEREMONY_RETIREMENT_RESULT_INVALID");
      harnessRetire.host.close();
    });

    it("rejects partial lock and journal reads that return zero progress before completion", function () {
      const root = makeStorageRoot("philcore-partial-read-");
      const paths = prepareStagingLayout(root);
      writeLockFile(paths.lockPath, {
        pid: "1",
        createdAtUnixSeconds: String(MINTED_AT - 120)
      });
      let readCalls = 0;
      const mod = loadHostModuleWithFsFacade((realFs) =>
        wrapFs(realFs, {
          readSync(original) {
            return (fd, buffer, offset, length, position) => {
              readCalls += 1;
              if (readCalls === 1) {
                const n = Math.max(1, Math.floor(length / 2));
                const got = original(fd, buffer, offset, n, position);
                return got;
              }
              if (readCalls === 2) {
                return 0;
              }
              return original(fd, buffer, offset, length, position);
            };
          }
        })
      );
      assert.throws(
        () => mod.createRecoveryStagingHost({
          storageRoot: root,
          retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
          nowFn: () => MINTED_AT,
          livenessProbeFn: () => "DEAD"
        }),
        (error) => error.code === "FILESYSTEM_READ_FAILED"
      );
    });

    it("surfaces malformed createJournal context before INVALID_NOW from a throwing nowFn", function () {
      const root = makeStorageRoot("philcore-create-prec-");
      let clockThrows = 0;
      let armed = false;
      const host = createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
        nowFn() {
          clockThrows += 1;
          if (!armed) {
            return MINTED_AT;
          }
          throw new Error("clock boom");
        }
      });
      host.reconcileRestart();
      clockThrows = 0;
      armed = true;
      assert.throws(
        () => host.createJournal({ ceremonyId: CEREMONY_ID }),
        (error) => error.code === "CEREMONY_CONTEXT_MISSING_KEY"
      );
      assert.equal(clockThrows, 1);
      assert.equal(fs.existsSync(derivePaths(root).journalPath), false);
      assert.equal(fs.existsSync(derivePaths(root).journalTmpPath), false);
      assert.throws(
        () => host.createJournal(validContext()),
        (error) => {
          assert.equal(error.code, "INVALID_NOW");
          assert.equal(error.cause && error.cause.message, "clock boom");
          return true;
        }
      );
      host.close();
    });

    it("snapshots stageRole candidate own keys once before clock activity", function () {
      const harness = createHarness();
      harness.reconcileAndCreate();
      const reads = { kind: 0, version: 0, commitment: 0, generation: 0 };
      const base = validCandidate(0);
      const candidate = {
        get candidateKind() {
          reads.kind += 1;
          return base.candidateKind;
        },
        get candidateVersion() {
          reads.version += 1;
          return base.candidateVersion;
        },
        get publicCandidateCommitment() {
          reads.commitment += 1;
          if (reads.commitment === 1) {
            return base.publicCandidateCommitment;
          }
          return `0x${"44".repeat(32)}`;
        },
        get credentialGeneration() {
          reads.generation += 1;
          return base.credentialGeneration;
        }
      };
      const beforeNow = harness.activity.nowCalls;
      const snapshot = harness.host.stageRole(0, candidate);
      assert.equal(snapshot.manifest["0"].publicCandidateCommitment, base.publicCandidateCommitment);
      assert.equal(reads.kind, 1);
      assert.equal(reads.version, 1);
      assert.equal(reads.commitment, 1);
      assert.equal(reads.generation, 1);
      assert.equal(harness.activity.nowCalls, beforeNow + 1);
      harness.host.close();
    });

    it("rejects a regular-file storageRoot as STORAGE_ROOT_INVALID before activity", function () {
      const fileRoot = path.join(
        os.tmpdir(),
        `philcore-file-root-${process.pid}-${Date.now()}`
      );
      fs.writeFileSync(fileRoot, "not-a-directory", { mode: 0o600 });
      let nowCalls = 0;
      let livenessCalls = 0;
      let retireCalls = 0;
      assert.throws(
        () => createRecoveryStagingHost({
          storageRoot: fileRoot,
          retireCeremonyFn: () => {
            retireCalls += 1;
            return validRetirementRecord(validContext(), "CANCELLED");
          },
          nowFn() {
            nowCalls += 1;
            return MINTED_AT;
          },
          livenessProbeFn() {
            livenessCalls += 1;
            return "DEAD";
          }
        }),
        (error) => error.code === "STORAGE_ROOT_INVALID"
      );
      assert.equal(nowCalls, 0);
      assert.equal(livenessCalls, 0);
      assert.equal(retireCalls, 0);
      fs.unlinkSync(fileRoot);
    });

    it("validates process.pid through the same PID helper before fresh-lock serialization", function () {
      const source = fs.readFileSync(HOST_PATH, "utf8");
      assert.ok(
        /function requireValidLockPid\b/.test(source)
        || /function assertValidLockPid\b/.test(source)
        || /function validateLockPid\b/.test(source)
      );
      assert.ok(
        /requireValidLockPid\(\s*process\.pid\s*\)|assertValidLockPid\(\s*process\.pid\s*\)|validateLockPid\(\s*process\.pid\s*\)/.test(
          source
        )
      );
      const harness = createHarness();
      harness.host.reconcileRestart();
      const lock = JSON.parse(fs.readFileSync(harness.paths.lockPath, "utf8"));
      const pid = Number(lock.pid);
      assert.ok(Number.isInteger(pid) && pid >= 1 && pid <= 2147483647);
      assert.equal(pid, process.pid);
      harness.host.close();
    });

    it("keeps host-level malformed JSON, filename mismatch, and oversize classification after removing the pure options bag", function () {
      const rootJson = makeStorageRoot("philcore-host-json-");
      const pathsJson = prepareStagingLayout(rootJson);
      fs.writeFileSync(pathsJson.journalPath, "{not-json", { mode: 0o600 });
      const harnessJson = createHarness({ storageRoot: rootJson });
      assert.equal(harnessJson.host.reconcileRestart().journalDisposition, "CORRUPT_QUARANTINED");
      harnessJson.host.close();

      const rootName = makeStorageRoot("philcore-host-name-");
      const pathsName = prepareStagingLayout(rootName);
      const wrongName = path.join(pathsName.stagingDir, `ceremony_${"11".repeat(32)}.v1.json`);
      fs.writeFileSync(wrongName, "{}", { mode: 0o600 });
      const harnessName = createHarness({ storageRoot: rootName });
      assert.equal(harnessName.host.reconcileRestart().journalDisposition, "CORRUPT_QUARANTINED");
      harnessName.host.close();

      const rootSize = makeStorageRoot("philcore-host-size-");
      const pathsSize = prepareStagingLayout(rootSize);
      fs.writeFileSync(pathsSize.journalPath, Buffer.alloc(8193, 0x61), { mode: 0o600 });
      const harnessSize = createHarness({ storageRoot: rootSize });
      assert.equal(harnessSize.host.reconcileRestart().journalDisposition, "CORRUPT_QUARANTINED");
      harnessSize.host.close();
    });
  });
});

describe("desktop recovery staging host (5B-1) -- constructor dependency property-access safety", function () {
  function baseDeps(overrides = {}) {
    return {
      storageRoot: makeStorageRoot(),
      retireCeremonyFn: () => validRetirementRecord(validContext(), "CANCELLED"),
      ...overrides
    };
  }

  function throwingGetterDeps(base, key, error) {
    const out = { ...base };
    Object.defineProperty(out, key, {
      get() {
        throw error;
      },
      enumerable: true,
      configurable: true
    });
    return out;
  }

  // Object.keys() and Object.prototype.hasOwnProperty.call() both rely on
  // [[GetOwnProperty]], so a blanket getOwnPropertyDescriptor throw is
  // caught by whichever runs first (enumeration, in this file's
  // validateDependencyObject). To isolate the presence-check path, let the
  // trap succeed for exactly the number of own keys (covering
  // Object.keys()'s internal descriptor reads), then throw on the next
  // call -- the first hasOwnProperty-driven required-key check.
  function presenceOnlyTrap(base, ownKeyCount) {
    let calls = 0;
    return new Proxy(base, {
      getOwnPropertyDescriptor(target, key) {
        calls += 1;
        if (calls > ownKeyCount) {
          throw new Error("presence trap");
        }
        return Object.getOwnPropertyDescriptor(target, key);
      }
    });
  }

  function assertClassified(fn, code) {
    let threw = false;
    try {
      fn();
    } catch (error) {
      threw = true;
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
      assert.ok(error.cause, "expected a cause to be attached");
      assert.equal(
        Object.prototype.propertyIsEnumerable.call(error, "cause"),
        false,
        "cause must be non-enumerable"
      );
    }
    assert.ok(threw, "expected construction to throw");
  }

  it("classifies a throwing enumeration trap as HOST_DEPENDENCIES_NOT_OBJECT", function () {
    const trap = new Proxy(baseDeps(), {
      ownKeys() {
        throw new Error("enumeration trap");
      }
    });
    assertClassified(() => createRecoveryStagingHost(trap), "HOST_DEPENDENCIES_NOT_OBJECT");
  });

  it("classifies a throwing presence trap as HOST_DEPENDENCY_MISSING", function () {
    // Unlike the pure module's context/journal/candidate validators (which
    // enumerate for extra keys before checking presence), this
    // constructor's precedence checks required-key presence FIRST -- so
    // the presence trap must throw immediately (no "free" calls to absorb
    // Object.keys()'s own descriptor reads, since that hasn't run yet).
    const base = baseDeps();
    const trap = presenceOnlyTrap(base, 0);
    assertClassified(() => createRecoveryStagingHost(trap), "HOST_DEPENDENCY_MISSING");
  });

  it("classifies a throwing getter for storageRoot, retireCeremonyFn, nowFn, and livenessProbeFn as HOST_DEPENDENCY_INVALID", function () {
    assertClassified(
      () => createRecoveryStagingHost(throwingGetterDeps(baseDeps(), "storageRoot", new Error("boom"))),
      "HOST_DEPENDENCY_INVALID"
    );
    assertClassified(
      () => createRecoveryStagingHost(throwingGetterDeps(baseDeps(), "retireCeremonyFn", new Error("boom"))),
      "HOST_DEPENDENCY_INVALID"
    );
    assertClassified(
      () =>
        createRecoveryStagingHost(
          throwingGetterDeps(baseDeps({ nowFn: () => MINTED_AT }), "nowFn", new Error("boom"))
        ),
      "HOST_DEPENDENCY_INVALID"
    );
    assertClassified(
      () =>
        createRecoveryStagingHost(
          throwingGetterDeps(
            baseDeps({ livenessProbeFn: () => "DEAD" }),
            "livenessProbeFn",
            new Error("boom")
          )
        ),
      "HOST_DEPENDENCY_INVALID"
    );
  });

  it("rejects an extra dependency key before reading any field value", function () {
    const hostile = throwingGetterDeps(
      { ...baseDeps(), extra: "x" },
      "storageRoot",
      new Error("must never be reached")
    );
    assertCode(() => createRecoveryStagingHost(hostile), "HOST_DEPENDENCY_EXTRA");
  });

  it("lets an earlier invalid dependency value win over a later field's throwing getter", function () {
    const hostile = throwingGetterDeps(
      baseDeps({ storageRoot: 12345, livenessProbeFn: () => "DEAD" }),
      "livenessProbeFn",
      new Error("must never be reached")
    );
    assertCode(() => createRecoveryStagingHost(hostile), "HOST_DEPENDENCY_INVALID");
  });

  it("touches no filesystem, clock, liveness, or retirement activity after a deterministic dependency failure", function () {
    const missingRoot = path.join(os.tmpdir(), `philcore-host-untouched-${Date.now()}`);
    let retireCalls = 0;
    let nowCalls = 0;
    let livenessCalls = 0;
    const deps = {
      storageRoot: missingRoot,
      retireCeremonyFn: () => {
        retireCalls += 1;
        return validRetirementRecord(validContext(), "CANCELLED");
      },
      nowFn: () => {
        nowCalls += 1;
        return MINTED_AT;
      },
      livenessProbeFn: () => {
        livenessCalls += 1;
        return "DEAD";
      },
      extraDependency: true
    };
    assertCode(() => createRecoveryStagingHost(deps), "HOST_DEPENDENCY_EXTRA");
    assert.equal(fs.existsSync(missingRoot), false, "storageRoot must never have been created");
    assert.equal(retireCalls, 0);
    assert.equal(nowCalls, 0);
    assert.equal(livenessCalls, 0);
  });

  it("reads each dependency field exactly once across a full successful construction", function () {
    const storageRoot = makeStorageRoot();
    const reads = { storageRoot: 0, retireCeremonyFn: 0, nowFn: 0, livenessProbeFn: 0 };
    const realRetire = () => validRetirementRecord(validContext(), "CANCELLED");
    const realNow = () => MINTED_AT;
    const realLiveness = () => "DEAD";
    const counted = {};
    Object.defineProperty(counted, "storageRoot", {
      get() {
        reads.storageRoot += 1;
        return storageRoot;
      },
      enumerable: true,
      configurable: true
    });
    Object.defineProperty(counted, "retireCeremonyFn", {
      get() {
        reads.retireCeremonyFn += 1;
        return realRetire;
      },
      enumerable: true,
      configurable: true
    });
    Object.defineProperty(counted, "nowFn", {
      get() {
        reads.nowFn += 1;
        return realNow;
      },
      enumerable: true,
      configurable: true
    });
    Object.defineProperty(counted, "livenessProbeFn", {
      get() {
        reads.livenessProbeFn += 1;
        return realLiveness;
      },
      enumerable: true,
      configurable: true
    });
    const host = createRecoveryStagingHost(counted);
    try {
      host.reconcileRestart();
    } finally {
      host.close();
    }
    for (const key of Object.keys(reads)) {
      assert.equal(reads[key], 1, `expected exactly one read of ${key}, got ${reads[key]}`);
    }
  });

  it("classifies a throwing getter on createJournal's ceremonyContext end-to-end without poisoning the host", function () {
    const harness = createHarness();
    harness.host.reconcileRestart();
    const hostileContext = { ...validContext() };
    Object.defineProperty(hostileContext, "chainId", {
      get() {
        throw new Error("hostile ceremony-context getter");
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      harness.host.createJournal(hostileContext);
    } catch (error) {
      threw = true;
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, "CHAIN_ID_INVALID");
      assert.ok(error.cause);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected createJournal to throw");
    // Not a poison trigger: the host must remain usable afterward.
    assert.equal(harness.host.status(), null);
    harness.host.close();
  });

  it("classifies a throwing getter on stageRole's candidateInput end-to-end without poisoning the host", function () {
    const harness = createHarness();
    harness.reconcileAndCreate();
    const hostileCandidate = { ...validCandidate(0) };
    Object.defineProperty(hostileCandidate, "credentialGeneration", {
      get() {
        throw new Error("hostile candidate-input getter");
      },
      enumerable: true,
      configurable: true
    });
    const nowCallsBeforeAttempt = harness.activity.nowCalls;
    let threw = false;
    try {
      harness.host.stageRole(0, hostileCandidate);
    } catch (error) {
      threw = true;
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, "CANDIDATE_INPUT_GENERATION_TYPE_INVALID");
      assert.ok(error.cause);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected stageRole to throw");
    assert.equal(
      harness.activity.nowCalls,
      nowCallsBeforeAttempt,
      "clock must not be touched on a deterministic candidate failure"
    );
    // Not a poison trigger: the host must remain usable afterward.
    const status = harness.host.status();
    assert.equal(status.state, "STAGING");
    harness.host.close();
  });
});

describe("desktop recovery staging host (5B-1) -- hostile-Proxy, revoked-Proxy, and explicit-undefined hardening", function () {
  const rawEscape = new Error("raw escape from getPrototypeOf trap");
  function hostileThrownValue() {
    return new Proxy(
      {},
      {
        getPrototypeOf() {
          throw rawEscape;
        }
      }
    );
  }

  function revokedProxy() {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  function assertPhilCoreError(error, code) {
    assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
  }

  it("classifies a dependency getter throwing a hostile Proxy without leaking the trap's raw value", function () {
    const hostile = hostileThrownValue();
    const deps = { storageRoot: makeStorageRoot(), retireCeremonyFn: () => ({}) };
    Object.defineProperty(deps, "storageRoot", {
      get() {
        throw hostile;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      createRecoveryStagingHost(deps);
    } catch (error) {
      threw = true;
      assert.notEqual(error, rawEscape, "the getPrototypeOf trap's raw value must never escape");
      assertPhilCoreError(error, "HOST_DEPENDENCY_INVALID");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, hostile, "cause must be the original hostile value, not rawEscape");
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected construction to throw");
  });

  it("classifies retirement-record validation throwing a hostile Proxy: CEREMONY_RETIREMENT_RESULT_INVALID, poison installed, subsequent non-close activity returns HOST_PROCESS_POISONED", function () {
    const hostile = hostileThrownValue();
    const record = validRetirementRecord(validContext(), "CANCELLED");
    Object.defineProperty(record, "chainId", {
      get() {
        throw hostile;
      },
      enumerable: true,
      configurable: true
    });
    const harness = createHarness({ retireCeremonyFn: () => record });
    harness.reconcileAndCreate();
    let threw = false;
    try {
      harness.host.cancel();
    } catch (error) {
      threw = true;
      assert.notEqual(error, rawEscape, "the getPrototypeOf trap's raw value must never escape");
      assertPhilCoreError(error, "CEREMONY_RETIREMENT_RESULT_INVALID");
    }
    assert.ok(threw, "expected cancel() to throw");
    assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
    harness.host.close();
  });

  it("revoked Proxy as constructor deps -> HOST_DEPENDENCIES_NOT_OBJECT, no raw TypeError", function () {
    let threw = false;
    try {
      createRecoveryStagingHost(revokedProxy());
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "HOST_DEPENDENCIES_NOT_OBJECT");
      assert.ok(error.cause instanceof TypeError, "underlying revoked-proxy TypeError retained as cause");
    }
    assert.ok(threw, "expected construction to throw");
  });

  it("revoked Proxy as retirement result -> CEREMONY_RETIREMENT_RESULT_INVALID, poison installed", function () {
    const harness = createHarness({ retireCeremonyFn: () => revokedProxy() });
    harness.reconcileAndCreate();
    let threw = false;
    try {
      harness.host.cancel();
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "CEREMONY_RETIREMENT_RESULT_INVALID");
      assert.ok(error.cause instanceof TypeError);
    }
    assert.ok(threw, "expected cancel() to throw");
    assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
    harness.host.close();
  });

  it("createJournal with nowFn throwing undefined: exact INVALID_NOW with its own non-enumerable cause equal to undefined", function () {
    let armed = false;
    // Built directly (not via createHarness, which wraps nowFn in its own
    // call-counting closure) so nowFn can be swapped to explicitly throw
    // `undefined` only for the createJournal call under test.
    const root = makeStorageRoot();
    const h = createRecoveryStagingHost({
      storageRoot: root,
      retireCeremonyFn: () => ({}),
      nowFn: () => {
        if (armed) {
          // eslint-disable-next-line no-throw-literal
          throw undefined;
        }
        return MINTED_AT;
      }
    });
    h.reconcileRestart();
    armed = true;
    let threw = false;
    try {
      h.createJournal(validContext());
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "INVALID_NOW");
      assert.ok(
        Object.prototype.hasOwnProperty.call(error, "cause"),
        "expected an own cause property even though the thrown value was undefined"
      );
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected createJournal to throw");
    h.close();
  });

  it("a normal readNow route (status/cancel) with nowFn throwing undefined captures its own cause equal to undefined", function () {
    let armed = false;
    const root = makeStorageRoot();
    const h = createRecoveryStagingHost({
      storageRoot: root,
      retireCeremonyFn: () => ({}),
      nowFn: () => {
        if (armed) {
          // eslint-disable-next-line no-throw-literal
          throw undefined;
        }
        return MINTED_AT;
      }
    });
    h.reconcileRestart();
    h.createJournal(validContext());
    armed = true;
    let threw = false;
    try {
      h.status();
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "INVALID_NOW");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected status() to throw");
    h.close();
  });

  it("livenessProbeFn throwing undefined through the public constructor path captures its own cause equal to undefined", function () {
    const root = makeStorageRoot();
    const paths = derivePaths(root);
    writeLockFile(paths.lockPath, {
      pid: "999999",
      createdAtUnixSeconds: String(MINTED_AT - STALE_LOCK_MIN_AGE_SECONDS - 1)
    });
    let threw = false;
    try {
      createRecoveryStagingHost({
        storageRoot: root,
        retireCeremonyFn: () => ({}),
        nowFn: () => MINTED_AT,
        livenessProbeFn: () => {
          // eslint-disable-next-line no-throw-literal
          throw undefined;
        }
      });
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "LOCK_LIVENESS_RESULT_INVALID");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected construction to throw");
  });

  it("retireCeremonyFn throwing undefined: exact CEREMONY_RETIREMENT_FAILED, own non-enumerable cause equal to undefined, and poison installed", function () {
    const harness = createHarness({
      retireCeremonyFn: () => {
        // eslint-disable-next-line no-throw-literal
        throw undefined;
      }
    });
    harness.reconcileAndCreate();
    let threw = false;
    try {
      harness.host.cancel();
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "CEREMONY_RETIREMENT_FAILED");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected cancel() to throw");
    assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
    harness.host.close();
  });

  it("a dependency property getter throwing undefined captures its own non-enumerable cause equal to undefined", function () {
    const deps = { storageRoot: makeStorageRoot(), retireCeremonyFn: () => ({}) };
    Object.defineProperty(deps, "retireCeremonyFn", {
      get() {
        // eslint-disable-next-line no-throw-literal
        throw undefined;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      createRecoveryStagingHost(deps);
    } catch (error) {
      threw = true;
      assertPhilCoreError(error, "HOST_DEPENDENCY_INVALID");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected construction to throw");
  });
});

describe("desktop recovery staging host (5B-1) -- unforgeable classified-error brand", function () {
  // The host imports PhilCoreV2ConsumerRecoveryStagingJournalError directly
  // from the pure module rather than redefining it, so the pure module's
  // WeakSet-branded Symbol.hasInstance protects every `instanceof` check in
  // this file too -- these tests confirm that end-to-end through the host's
  // own public surfaces, not just the SDK's.
  function makeSpoof(overrides = {}) {
    const spoof = Object.create(PhilCoreV2ConsumerRecoveryStagingJournalError.prototype);
    spoof.code = "HOST_PROCESS_POISONED";
    spoof.message = "spoofed";
    Object.assign(spoof, overrides);
    return spoof;
  }

  it("confirms a spoof passes a raw instanceof check but is not the branded class, using the host's own imported reference", function () {
    const spoof = makeSpoof();
    assert.equal(spoof instanceof PhilCoreV2ConsumerRecoveryStagingJournalError, false);
  });

  it("wraps a dependency getter that throws Object.create(ErrorClass.prototype) as HOST_DEPENDENCY_INVALID, never escaping unchanged", function () {
    const spoof = makeSpoof();
    const deps = { storageRoot: makeStorageRoot(), retireCeremonyFn: () => ({}) };
    Object.defineProperty(deps, "storageRoot", {
      get() {
        throw spoof;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      createRecoveryStagingHost(deps);
    } catch (error) {
      threw = true;
      assert.notEqual(error, spoof, "the spoof must never escape unchanged");
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, "HOST_DEPENDENCY_INVALID");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, spoof);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected construction to throw");
  });

  it("wraps a retirement-record field getter that throws a spoof as CEREMONY_RETIREMENT_RESULT_INVALID, installs poison, and never lets it escape unchanged", function () {
    const spoof = makeSpoof();
    const record = validRetirementRecord(validContext(), "CANCELLED");
    Object.defineProperty(record, "chainId", {
      get() {
        throw spoof;
      },
      enumerable: true,
      configurable: true
    });
    const harness = createHarness({ retireCeremonyFn: () => record });
    harness.reconcileAndCreate();
    let threw = false;
    try {
      harness.host.cancel();
    } catch (error) {
      threw = true;
      assert.notEqual(error, spoof, "the spoof must never escape unchanged");
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, "CEREMONY_RETIREMENT_RESULT_INVALID");
    }
    assert.ok(threw, "expected cancel() to throw");
    assertCode(() => harness.host.status(), "HOST_PROCESS_POISONED");
    harness.host.close();
  });

  it("createJournal cannot be induced to read a spoofed hostile .code getter, and never reclassifies to the spoof's fake code", function () {
    let codeGetterCalls = 0;
    const spoofWithTrackedCode = Object.create(PhilCoreV2ConsumerRecoveryStagingJournalError.prototype);
    Object.defineProperty(spoofWithTrackedCode, "code", {
      get() {
        codeGetterCalls += 1;
        return "INVALID_NOW"; // attempts to trick the reclassification branch
      },
      enumerable: true,
      configurable: true
    });
    let armed = false;
    const root = makeStorageRoot();
    const h = createRecoveryStagingHost({
      storageRoot: root,
      retireCeremonyFn: () => ({}),
      nowFn: () => {
        if (armed) {
          throw spoofWithTrackedCode;
        }
        return MINTED_AT;
      }
    });
    h.reconcileRestart();
    armed = true;
    let threw = false;
    try {
      h.createJournal(validContext());
    } catch (error) {
      threw = true;
      assert.notEqual(error, spoofWithTrackedCode, "the spoof must never escape unchanged");
      assert.equal(codeGetterCalls, 0, "the spoof's .code getter must never be read");
      assert.equal(error.code, "INVALID_NOW", "the genuine pure-module INVALID_NOW error, not the spoof");
    }
    assert.ok(threw, "expected createJournal to throw");
    h.close();
  });

  it("still recognizes a genuine error thrown by a dependency getter and rethrows it unchanged", function () {
    const genuine = new PhilCoreV2ConsumerRecoveryStagingJournalError("HOST_DEPENDENCY_INVALID");
    const deps = { storageRoot: makeStorageRoot(), retireCeremonyFn: () => ({}) };
    Object.defineProperty(deps, "storageRoot", {
      get() {
        throw genuine;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      createRecoveryStagingHost(deps);
    } catch (error) {
      threw = true;
      assert.equal(error, genuine, "a genuine classified error must be rethrown unchanged, not re-wrapped");
    }
    assert.ok(threw, "expected construction to throw");
  });
});

async function runNodeSuite() {
  try {
    for (const entry of __nodeSuite.tests) {
      if (typeof __nodeSuite.beforeEach === "function") {
        await __nodeSuite.beforeEach();
      }
      await entry.fn();
      console.log(`ok - ${entry.name}`);
    }
  } catch (error) {
    console.error("not ok - desktop recovery staging host");
    console.error(error);
    process.exitCode = 1;
  }
}

if (__usedNodeShim) {
  runNodeSuite();
}
