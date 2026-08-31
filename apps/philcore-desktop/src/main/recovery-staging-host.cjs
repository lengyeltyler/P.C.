"use strict";

const fs = require("node:fs");
const path = require("node:path");

require("tsx/cjs");

const journalPure = require("../../../phil-device-sdk/src/v2ConsumerRecoveryStagingJournal.ts");

const {
  createStagingJournal,
  stageRoleCandidate,
  cancelStagingJournal,
  expireStagingJournalIfNeeded,
  supersedeStagingJournal,
  validateStagingJournalRecord,
  PhilCoreV2ConsumerRecoveryStagingJournalError,
  PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE,
  MAX_JOURNAL_FILE_BYTES
} = journalPure;

PhilCoreV2ConsumerRecoveryStagingJournalError.prototype.name =
  "PhilCoreV2ConsumerRecoveryStagingJournalError";

const CODES = PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE;

const O_RDONLY = fs.constants.O_RDONLY;
const O_RDWR = fs.constants.O_RDWR;
const O_WRONLY = fs.constants.O_WRONLY;
const O_CREAT = fs.constants.O_CREAT;
const O_EXCL = fs.constants.O_EXCL;
const O_NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY;

const SHARED_ENROLLMENT = "philcore-recovery-enrollment";
const STAGING_LEAF = "ceremony-staging";
const LOCK_BASENAME = ".staging.lock";
const CORRUPT_QUARANTINE = ".corrupt-quarantine";
const STALE_LOCK_QUARANTINE = ".stale-lock-quarantine";

const MAX_LOCK_FILE_BYTES = 256;
const MAX_CORRUPT_QUARANTINE_FILES = 10;
const MAX_STALE_LOCK_QUARANTINE_FILES = 10;
const STALE_LOCK_MIN_AGE_SECONDS = 60;
const MAX_TEMP_FILES = 1;
const MAX_RECONCILIATION_TEMP_SWEEP = 10;
// Independent future-proof ceiling. Current simultaneous bounds
// (MAX_RECONCILIATION_TEMP_SWEEP=10 plus at most one journal's supersede/remove)
// cap any legal plan at 12 logical operations, so operation 33 is unreachable
// through real disk state today. The comparison below still runs before mutation.
const MAX_RECONCILIATION_OPERATIONS = 32;
const UINT48_MAX = 281474976710655;
const UINT256_MAX = (1n << 256n) - 1n;

const JOURNAL_NAME_RE = /^ceremony_([0-9a-f]{64})\.v1\.json$/u;
const TEMP_NAME_RE = /^\.ceremony_([0-9a-f]{64})\.v1\.json\.tmp$/u;

const JOURNAL_SNAPSHOT_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "ceremonyId",
  "enrollmentCeremonyHash",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "account",
  "chainId",
  "entryPoint",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch",
  "expiresAtUnixSeconds",
  "state",
  "createdAtUnixSeconds",
  "updatedAtUnixSeconds",
  "manifest",
  "endReason",
  "integrityChecksum"
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

const LOCK_OWN_KEYS = Object.freeze(["pid", "createdAtUnixSeconds"]);
const LIVENESS_LITERALS = new Set(["LIVE", "DEAD", "AMBIGUOUS"]);
const DEPENDENCY_OWN_KEYS = Object.freeze([
  "storageRoot",
  "retireCeremonyFn",
  "nowFn",
  "livenessProbeFn"
]);
const DEPENDENCY_REQUIRED_KEYS = Object.freeze(["storageRoot", "retireCeremonyFn"]);

const PROCESS_POISONED_STAGING_ROOTS = new Set();
const POISONED_LEXICAL_STORAGE_ROOTS = new Set();

function defaultNowFn() {
  return Math.floor(Date.now() / 1000);
}

function defaultLivenessProbeFn(pid) {
  try {
    process.kill(pid, 0);
    return "LIVE";
  } catch (error) {
    if (error && error.code === "ESRCH") {
      return "DEAD";
    }
    return "AMBIGUOUS";
  }
}

// General-purpose error construction. throwCode ALWAYS constructs the
// requested code, even when `cause` is itself an already-classified
// PhilCoreV2ConsumerRecoveryStagingJournalError -- this is required so
// existing callers can reclassify a lower-level closed error into an exact
// higher-level one (e.g. a directory-fsync helper's DURABILITY_WRITE_FAILED
// becoming a caller's DURABILITY_INDETERMINATE/LOCK_ACQUISITION_INDETERMINATE/
// JOURNAL_REMOVAL_INDETERMINATE). Do not add a global "rethrow if already
// classified" branch here; that would silently break every such
// reclassification throughout this file.
//
// `arguments.length` (not `cause !== undefined`) distinguishes "no cause
// argument supplied" (throwCode(code), the common case throughout this
// file) from "cause argument explicitly supplied as undefined" (a
// dependency/getter/callback that itself threw `undefined`) -- the two are
// otherwise indistinguishable, and the second must still get its own
// non-enumerable `cause` property set to `undefined`.
function throwCode(code, cause) {
  const error = new PhilCoreV2ConsumerRecoveryStagingJournalError(code);
  if (arguments.length >= 2) {
    Object.defineProperty(error, "cause", {
      value: cause,
      enumerable: false,
      configurable: true,
      writable: true
    });
  }
  throw error;
}

// `cause instanceof PhilCoreV2ConsumerRecoveryStagingJournalError` is itself
// a hostile-surface operation: for a Proxy `cause` (including a revoked
// one), `instanceof` invokes the getPrototypeOf trap, which can throw an
// unrelated raw value. That raw value must never escape here -- on any such
// failure, `cause` is conservatively treated as not-already-classified (the
// safe default: it gets wrapped with the caller-supplied code below, same
// as any other unclassified cause).
function isClassifiedError(value) {
  try {
    return value instanceof PhilCoreV2ConsumerRecoveryStagingJournalError;
  } catch {
    return false;
  }
}

// Dedicated classifier for hostile enumeration/presence/read operations on
// caller-controlled objects (deps, candidate input, etc.) ONLY. Unlike
// throwCode, an already-classified error is rethrown unchanged here -- there
// is no "lower-level closed error being reclassified" scenario for a raw
// property access, so the original classification (if any) is preserved.
// `cause` is always meaningful here (it is always "the value that was
// actually thrown/caught"), so it is always attached, including when that
// value is explicitly `undefined`.
function classifyPropertyAccess(code, cause) {
  if (isClassifiedError(cause)) {
    throw cause;
  }
  const error = new PhilCoreV2ConsumerRecoveryStagingJournalError(code);
  Object.defineProperty(error, "cause", {
    value: cause,
    enumerable: false,
    configurable: true,
    writable: true
  });
  throw error;
}

function ownEnumerableStringKeys(value, enumerationCode) {
  try {
    return Object.keys(value);
  } catch (error) {
    classifyPropertyAccess(enumerationCode, error);
  }
}

function hasOwnStringKey(value, key, presenceCode) {
  try {
    return Object.prototype.hasOwnProperty.call(value, key);
  } catch (error) {
    classifyPropertyAccess(presenceCode, error);
  }
}

function readOwnProperty(value, key, readCode) {
  try {
    return value[key];
  } catch (error) {
    classifyPropertyAccess(readCode, error);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// `isPlainObject`'s internal Array.isArray call throws a raw TypeError for a
// revoked Proxy. Every call site below that operates on a caller-controlled
// value (constructor deps, a retirement result) must use this wrapper
// instead of calling isPlainObject directly, so that failure is classified
// with the caller's own "not an object" code rather than escaping raw.
function requireCallerObjectShape(value, notObjectCode) {
  let valid;
  try {
    valid = isPlainObject(value);
  } catch (error) {
    classifyPropertyAccess(notObjectCode, error);
  }
  if (!valid) {
    throwCode(notObjectCode);
  }
}

function lexicalNormalizeStorageRoot(storageRoot) {
  if (typeof storageRoot !== "string" || storageRoot.length === 0) {
    throwCode(CODES.STORAGE_ROOT_INVALID);
  }
  return path.resolve(storageRoot);
}

function deriveCanonicalStagingKey(realStorageRoot) {
  return path.join(realStorageRoot, SHARED_ENROLLMENT, STAGING_LEAF);
}

function installPoison(lexicalRoot, canonicalStagingKey) {
  POISONED_LEXICAL_STORAGE_ROOTS.add(lexicalRoot);
  PROCESS_POISONED_STAGING_ROOTS.add(canonicalStagingKey);
}

function assertNotProcessPoisoned(lexicalRoot, canonicalStagingKey) {
  if (
    POISONED_LEXICAL_STORAGE_ROOTS.has(lexicalRoot)
    || PROCESS_POISONED_STAGING_ROOTS.has(canonicalStagingKey)
  ) {
    throwCode(CODES.HOST_PROCESS_POISONED);
  }
}

function isSafeContainment(parentDir, childPath) {
  const parent = path.resolve(parentDir);
  const child = path.resolve(childPath);
  return child === parent || child.startsWith(`${parent}${path.sep}`);
}

function assertStorageRootSafe(lexicalRoot) {
  if (lexicalRoot === path.parse(lexicalRoot).root) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }
  let lst;
  try {
    lst = fs.lstatSync(lexicalRoot);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throwCode(CODES.STORAGE_ROOT_INVALID);
    }
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  }
  if (lst.isSymbolicLink()) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }
  if (!lst.isDirectory()) {
    throwCode(CODES.STORAGE_ROOT_INVALID);
  }
}

function resolveStorageRootRealpath(lexicalRoot) {
  try {
    return fs.realpathSync(lexicalRoot);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throwCode(CODES.STORAGE_ROOT_INVALID);
    }
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  }
}

function assertResolvedRootMatchesLexical(lexicalRoot, realStorageRoot) {
  if (realStorageRoot !== lexicalRoot) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }
}

function requirePlatformUid() {
  if (typeof process.getuid !== "function") {
    throwCode(CODES.DURABILITY_UNSUPPORTED);
  }
  return process.getuid();
}

function readNow(nowFn) {
  let value;
  try {
    value = nowFn();
  } catch (error) {
    throwCode(CODES.INVALID_NOW, error);
  }
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value <= 0
    || value > UINT48_MAX
  ) {
    throwCode(CODES.INVALID_NOW);
  }
  return value;
}

function assertClockNotRegressed(nowUnixSeconds, updatedAtUnixSeconds) {
  const updated = Number(updatedAtUnixSeconds);
  if (nowUnixSeconds < updated) {
    throwCode(CODES.CLOCK_REGRESSION_DETECTED);
  }
}

function fstatIdentity(fd) {
  const stat = fs.fstatSync(fd);
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
    nlink: stat.nlink,
    isFile: stat.isFile(),
    isDirectory: stat.isDirectory()
  });
}

function assertRegularFileOwned(identity, uid) {
  if (
    !identity.isFile
    || identity.uid !== uid
    || (identity.mode & 0o777) !== 0o600
    || identity.nlink !== 1
  ) {
    throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
  }
}

function assertDirectoryOwnedExactMode(identity, uid) {
  if (
    !identity.isDirectory
    || identity.uid !== uid
    || (identity.mode & 0o777) !== 0o700
  ) {
    return false;
  }
  return true;
}

function completeRead(fd, size) {
  const raw = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const n = fs.readSync(fd, raw, offset, size - offset, offset);
    if (n <= 0) {
      throwCode(CODES.FILESYSTEM_READ_FAILED);
    }
    offset += n;
  }
  return raw;
}

function fsyncDirectory(dirPath) {
  let fd;
  try {
    fd = fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    fs.fsyncSync(fd);
  } catch (error) {
    throwCode(CODES.DURABILITY_WRITE_FAILED, error);
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

function durableConfirmDirectory(dirPath, options = {}) {
  let fd;
  try {
    fd = fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    fs.fsyncSync(fd);
    if (options.fsyncParent !== false) {
      fsyncDirectory(path.dirname(dirPath));
    }
  } catch (error) {
    throwCode(CODES.DURABILITY_WRITE_FAILED, error);
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

function confirmNewlyCreatedDirectory(dirPath, parentPath, uid, poisonFn) {
  let lst;
  try {
    lst = fs.lstatSync(dirPath);
  } catch (error) {
    poisonFn();
    throwCode(CODES.DURABILITY_INDETERMINATE, error);
  }
  if (
    !lst.isDirectory()
    || lst.isSymbolicLink()
    || lst.uid !== uid
    || (lst.mode & 0o777) !== 0o700
    || !isSafeContainment(parentPath, dirPath)
  ) {
    poisonFn();
    throwCode(CODES.DURABILITY_INDETERMINATE);
  }

  let fd;
  try {
    fd = fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    const after = fstatIdentity(fd);
    if (
      after.dev !== lst.dev
      || after.ino !== lst.ino
      || !after.isDirectory
      || after.uid !== uid
      || (after.mode & 0o777) !== 0o700
    ) {
      poisonFn();
      throwCode(CODES.DURABILITY_INDETERMINATE);
    }
    fs.fsyncSync(fd);
    fsyncDirectory(parentPath);
  } catch (error) {
    if (
      error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
      && error.code === CODES.DURABILITY_INDETERMINATE
    ) {
      throw error;
    }
    poisonFn();
    throwCode(CODES.DURABILITY_INDETERMINATE, error);
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

function partialWriteLoop(fd, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const written = fs.writeSync(fd, buffer, offset, buffer.length - offset);
    if (written <= 0) {
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED);
    }
    offset += written;
  }
}

function validateDependencyObject(deps) {
  requireCallerObjectShape(deps, CODES.HOST_DEPENDENCIES_NOT_OBJECT);
  // Exact required precedence: dependency object -> missing required keys
  // -> extra keys -> dependency value types. Enumeration happens exactly
  // once (a Proxy's ownKeys trap could otherwise return different results
  // on a second call, silently admitting a key the first pass rejected);
  // the captured list is reused, never re-enumerated.
  for (const key of DEPENDENCY_REQUIRED_KEYS) {
    if (!hasOwnStringKey(deps, key, CODES.HOST_DEPENDENCY_MISSING)) {
      throwCode(CODES.HOST_DEPENDENCY_MISSING);
    }
  }
  const keys = ownEnumerableStringKeys(deps, CODES.HOST_DEPENDENCIES_NOT_OBJECT);
  for (const key of keys) {
    if (!DEPENDENCY_OWN_KEYS.includes(key)) {
      throwCode(CODES.HOST_DEPENDENCY_EXTRA);
    }
  }

  // Sequential, one-field-at-a-time read-and-type-check. Each dependency's
  // own property is read exactly once and never reread later in the
  // constructor -- callers reuse the returned snapshot instead.
  const storageRoot = readOwnProperty(deps, "storageRoot", CODES.HOST_DEPENDENCY_INVALID);
  if (typeof storageRoot !== "string" || storageRoot.length === 0) {
    throwCode(CODES.HOST_DEPENDENCY_INVALID);
  }
  const retireCeremonyFn = readOwnProperty(deps, "retireCeremonyFn", CODES.HOST_DEPENDENCY_INVALID);
  if (typeof retireCeremonyFn !== "function") {
    throwCode(CODES.HOST_DEPENDENCY_INVALID);
  }
  let nowFn;
  if (hasOwnStringKey(deps, "nowFn", CODES.HOST_DEPENDENCY_INVALID)) {
    nowFn = readOwnProperty(deps, "nowFn", CODES.HOST_DEPENDENCY_INVALID);
    if (typeof nowFn !== "function") {
      throwCode(CODES.HOST_DEPENDENCY_INVALID);
    }
  }
  let livenessProbeFn;
  if (hasOwnStringKey(deps, "livenessProbeFn", CODES.HOST_DEPENDENCY_INVALID)) {
    livenessProbeFn = readOwnProperty(deps, "livenessProbeFn", CODES.HOST_DEPENDENCY_INVALID);
    if (typeof livenessProbeFn !== "function") {
      throwCode(CODES.HOST_DEPENDENCY_INVALID);
    }
  }

  return Object.freeze({ storageRoot, retireCeremonyFn, nowFn, livenessProbeFn });
}

function ensureSharedParent(realStorageRoot, uid, poisonFn) {
  const sharedParent = path.join(realStorageRoot, SHARED_ENROLLMENT);
  if (!isSafeContainment(realStorageRoot, sharedParent)) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }

  if (!fs.existsSync(sharedParent)) {
    try {
      fs.mkdirSync(sharedParent, { mode: 0o700 });
    } catch (error) {
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    }
    confirmNewlyCreatedDirectory(sharedParent, realStorageRoot, uid, poisonFn);
    return sharedParent;
  }

  let before;
  try {
    before = fs.lstatSync(sharedParent);
  } catch (error) {
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  }
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throwCode(CODES.STORAGE_DIRECTORY_INVALID);
  }
  if (!isSafeContainment(realStorageRoot, sharedParent)) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }
  if (before.uid !== uid) {
    throwCode(CODES.STORAGE_DIRECTORY_OWNER_INVALID);
  }

  let chmodAttempted = false;
  if ((before.mode & 0o777) !== 0o700) {
    try {
      fs.chmodSync(sharedParent, 0o700);
      chmodAttempted = true;
    } catch (error) {
      throwCode(CODES.STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED, error);
    }
  }

  let fd;
  try {
    fd = fs.openSync(sharedParent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    const after = fstatIdentity(fd);
    if (
      after.dev !== before.dev
      || after.ino !== before.ino
      || !after.isDirectory
      || after.uid !== uid
      || (after.mode & 0o777) !== 0o700
    ) {
      if (chmodAttempted) {
        poisonFn();
        throwCode(CODES.STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE);
      }
      throwCode(CODES.STORAGE_DIRECTORY_INVALID);
    }
    fs.fsyncSync(fd);
  } catch (error) {
    if (
      error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
      && (
        error.code === CODES.STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE
        || error.code === CODES.STORAGE_DIRECTORY_INVALID
      )
    ) {
      throw error;
    }
    if (chmodAttempted) {
      poisonFn();
      throwCode(CODES.STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE, error);
    }
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }

  return sharedParent;
}

function ensureOwnedDirectory(
  dirPath,
  parentPath,
  uid,
  invalidCode,
  modeInvalidCode,
  poisonFn
) {
  if (!isSafeContainment(parentPath, dirPath)) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }

  if (!fs.existsSync(dirPath)) {
    try {
      fs.mkdirSync(dirPath, { mode: 0o700 });
    } catch (error) {
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    }
    confirmNewlyCreatedDirectory(dirPath, parentPath, uid, poisonFn);
    return;
  }

  validateExistingOwnedDirectory(
    dirPath,
    parentPath,
    uid,
    invalidCode,
    modeInvalidCode
  );
}

function validateExistingOwnedDirectory(
  dirPath,
  parentPath,
  uid,
  invalidCode,
  modeInvalidCode
) {
  if (!isSafeContainment(parentPath, dirPath)) {
    throwCode(CODES.STORAGE_ROOT_UNSAFE);
  }
  let lst;
  try {
    lst = fs.lstatSync(dirPath);
  } catch (error) {
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  }
  if (!lst.isDirectory() || lst.isSymbolicLink()) {
    throwCode(invalidCode);
  }
  if (lst.uid !== uid) {
    throwCode(
      invalidCode === CODES.QUARANTINE_DIRECTORY_INVALID
        ? CODES.QUARANTINE_DIRECTORY_OWNER_INVALID
        : CODES.STORAGE_DIRECTORY_OWNER_INVALID
    );
  }
  if ((lst.mode & 0o777) !== 0o700) {
    throwCode(modeInvalidCode);
  }

  let fd;
  try {
    fd = fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    const retained = fstatIdentity(fd);
    if (
      retained.dev !== lst.dev
      || retained.ino !== lst.ino
      || !retained.isDirectory
      || retained.uid !== uid
      || (retained.mode & 0o777) !== 0o700
    ) {
      throwCode(invalidCode);
    }
    let probeFd;
    try {
      probeFd = fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      const probe = fstatIdentity(probeFd);
      if (probe.dev !== retained.dev || probe.ino !== retained.ino) {
        throwCode(invalidCode);
      }
    } finally {
      if (probeFd !== undefined) {
        fs.closeSync(probeFd);
      }
    }
  } catch (error) {
    if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
      throw error;
    }
    throwCode(CODES.FILESYSTEM_READ_FAILED, error);
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

function parseCanonicalDecimalString(value, invalidCode) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throwCode(invalidCode);
  }
  return value;
}

function parseLockPayload(raw) {
  if (raw.length > MAX_LOCK_FILE_BYTES) {
    throwCode(CODES.LOCK_FILE_OVERSIZED);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throwCode(CODES.LOCK_FILE_JSON_INVALID, error);
  }
  if (!isPlainObject(parsed)) {
    throwCode(CODES.LOCK_FILE_NOT_OBJECT);
  }
  const keys = Object.keys(parsed);
  if (keys.length !== LOCK_OWN_KEYS.length) {
    if (keys.length < LOCK_OWN_KEYS.length) {
      throwCode(CODES.LOCK_FILE_MISSING_KEY);
    }
    throwCode(CODES.LOCK_FILE_EXTRA_KEY);
  }
  for (let index = 0; index < LOCK_OWN_KEYS.length; index += 1) {
    if (keys[index] !== LOCK_OWN_KEYS[index]) {
      if (!Object.prototype.hasOwnProperty.call(parsed, LOCK_OWN_KEYS[index])) {
        throwCode(CODES.LOCK_FILE_MISSING_KEY);
      }
      throwCode(CODES.LOCK_FILE_EXTRA_KEY);
    }
  }
  const pidString = parseCanonicalDecimalString(parsed.pid, CODES.LOCK_PID_INVALID);
  const createdAtString = parseCanonicalDecimalString(
    parsed.createdAtUnixSeconds,
    CODES.LOCK_CREATED_AT_INVALID
  );
  const pid = requireValidLockPid(Number(pidString));
  const createdAt = Number(createdAtString);
  if (!Number.isSafeInteger(createdAt) || createdAt < 1 || createdAt > 281474976710655) {
    throwCode(CODES.LOCK_CREATED_AT_INVALID);
  }
  return Object.freeze({ pid, createdAtUnixSeconds: createdAt, pidString, createdAtString });
}

function requireValidLockPid(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) {
    throwCode(CODES.LOCK_PID_INVALID);
  }
  return pid;
}

function probeLiveness(livenessProbeFn, pid) {
  let result;
  try {
    result = livenessProbeFn(pid);
  } catch (error) {
    throwCode(CODES.LOCK_LIVENESS_RESULT_INVALID, error);
  }
  if (!LIVENESS_LITERALS.has(result)) {
    throwCode(CODES.LOCK_LIVENESS_RESULT_INVALID);
  }
  return result;
}

function lowestUnusedQuarantineSlot(quarantineDir) {
  const existing = new Set(
    fs.readdirSync(quarantineDir).map((name) => {
      const match = name.match(/\.(\d+)$/u);
      return match ? Number(match[1]) : -1;
    }).filter((slot) => slot >= 0)
  );
  for (let slot = 0; slot < 10; slot += 1) {
    if (!existing.has(slot)) {
      return slot;
    }
  }
  return -1;
}

function journalBasename(ceremonyId) {
  const hex = ceremonyId.startsWith("0x") ? ceremonyId.slice(2) : ceremonyId;
  return `ceremony_${hex.toLowerCase()}.v1.json`;
}

function journalTempBasename(ceremonyId) {
  return `.${journalBasename(ceremonyId)}.tmp`;
}

function journalPathForCeremony(stagingDir, ceremonyId) {
  return path.join(stagingDir, journalBasename(ceremonyId));
}

function journalTempPathForCeremony(stagingDir, ceremonyId) {
  return path.join(stagingDir, journalTempBasename(ceremonyId));
}

function toPublicSnapshot(journal) {
  const manifest = Object.freeze({
    "0": journal.manifest["0"] ? Object.freeze({ ...journal.manifest["0"] }) : null,
    "1": journal.manifest["1"] ? Object.freeze({ ...journal.manifest["1"] }) : null,
    "2": journal.manifest["2"] ? Object.freeze({ ...journal.manifest["2"] }) : null
  });
  const snapshot = {};
  for (const key of JOURNAL_SNAPSHOT_KEYS) {
    snapshot[key] = key === "manifest" ? manifest : journal[key];
  }
  return Object.freeze(snapshot);
}

function validateLockDescriptor(identity, uid) {
  if (
    !identity.isFile
    || identity.uid !== uid
    || (identity.mode & 0o777) !== 0o600
    || identity.nlink !== 1
  ) {
    throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
  }
}

function createRecoveryStagingHost(deps) {
  const dependencySnapshot = validateDependencyObject(deps);

  const lexicalStorageRoot = lexicalNormalizeStorageRoot(dependencySnapshot.storageRoot);
  assertNotProcessPoisoned(lexicalStorageRoot, deriveCanonicalStagingKey(lexicalStorageRoot));

  assertStorageRootSafe(lexicalStorageRoot);
  const realStorageRoot = resolveStorageRootRealpath(lexicalStorageRoot);
  assertResolvedRootMatchesLexical(lexicalStorageRoot, realStorageRoot);

  const canonicalStagingKey = deriveCanonicalStagingKey(realStorageRoot);
  if (PROCESS_POISONED_STAGING_ROOTS.has(canonicalStagingKey)) {
    POISONED_LEXICAL_STORAGE_ROOTS.add(lexicalStorageRoot);
    throwCode(CODES.HOST_PROCESS_POISONED);
  }

  const uid = requirePlatformUid();
  // validateDependencyObject already rejected an own nowFn/livenessProbeFn
  // key whose value isn't a function, so by construction a defined value
  // here is always a valid override; undefined means the key was absent.
  const nowFn = dependencySnapshot.nowFn !== undefined
    ? dependencySnapshot.nowFn
    : defaultNowFn;
  const livenessProbeFn = dependencySnapshot.livenessProbeFn !== undefined
    ? dependencySnapshot.livenessProbeFn
    : defaultLivenessProbeFn;
  const retireCeremonyFn = dependencySnapshot.retireCeremonyFn;

  const poisonFn = () => installPoison(lexicalStorageRoot, canonicalStagingKey);

  const sharedParent = ensureSharedParent(realStorageRoot, uid, poisonFn);
  const stagingDir = path.join(sharedParent, STAGING_LEAF);
  const corruptQuarantineDir = path.join(stagingDir, CORRUPT_QUARANTINE);
  const staleLockQuarantineDir = path.join(stagingDir, STALE_LOCK_QUARANTINE);
  const lockPath = path.join(stagingDir, LOCK_BASENAME);

  ensureOwnedDirectory(
    stagingDir,
    sharedParent,
    uid,
    CODES.STORAGE_DIRECTORY_INVALID,
    CODES.STORAGE_DIRECTORY_MODE_INVALID,
    poisonFn
  );
  ensureOwnedDirectory(
    corruptQuarantineDir,
    stagingDir,
    uid,
    CODES.QUARANTINE_DIRECTORY_INVALID,
    CODES.QUARANTINE_DIRECTORY_MODE_INVALID,
    poisonFn
  );
  ensureOwnedDirectory(
    staleLockQuarantineDir,
    stagingDir,
    uid,
    CODES.QUARANTINE_DIRECTORY_INVALID,
    CODES.QUARANTINE_DIRECTORY_MODE_INVALID,
    poisonFn
  );

  function ensureQuarantineDirectories() {
    validateExistingOwnedDirectory(
      corruptQuarantineDir,
      stagingDir,
      uid,
      CODES.QUARANTINE_DIRECTORY_INVALID,
      CODES.QUARANTINE_DIRECTORY_MODE_INVALID
    );
    validateExistingOwnedDirectory(
      staleLockQuarantineDir,
      stagingDir,
      uid,
      CODES.QUARANTINE_DIRECTORY_INVALID,
      CODES.QUARANTINE_DIRECTORY_MODE_INVALID
    );
  }

  let lockFd;
  let lockIdentity;

  function writeFreshLockFile(fd, nowUnixSeconds) {
    const pid = requireValidLockPid(process.pid);
    const payload = Buffer.from(
      JSON.stringify({
        pid: String(pid),
        createdAtUnixSeconds: String(nowUnixSeconds)
      }),
      "utf8"
    );
    partialWriteLoop(fd, payload);
    fs.fsyncSync(fd);
    lockIdentity = fstatIdentity(fd);
    validateLockDescriptor(lockIdentity, uid);
  }

  function acquireExclusiveLock(nowUnixSeconds) {
    let fd;
    try {
      fd = fs.openSync(
        lockPath,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW,
        0o600
      );
    } catch (error) {
      if (error && error.code === "EEXIST") {
        throwCode(CODES.LOCK_ACQUISITION_FAILED, error);
      }
      throwCode(CODES.LOCK_ACQUISITION_FAILED, error);
    }
    try {
      writeFreshLockFile(fd, nowUnixSeconds);
      try {
        fsyncDirectory(stagingDir);
      } catch (error) {
        poisonFn();
        try {
          fs.closeSync(fd);
        } catch {
          // ignore close failure during indeterminate cleanup
        }
        fd = undefined;
        try {
          fs.unlinkSync(lockPath);
          try {
            fsyncDirectory(stagingDir);
          } catch {
            // cleanup directory fsync failure remains indeterminate
          }
        } catch {
          // cleanup unlink failure remains indeterminate
        }
        throwCode(CODES.LOCK_ACQUISITION_INDETERMINATE, error);
      }
      lockFd = fd;
    } catch (error) {
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && error.code === CODES.LOCK_ACQUISITION_INDETERMINATE
      ) {
        throw error;
      }
      try {
        if (fd !== undefined) {
          fs.closeSync(fd);
        }
      } catch {
        // ignore close failure during cleanup
      }
      try {
        fs.unlinkSync(lockPath);
        fsyncDirectory(stagingDir);
      } catch {
        poisonFn();
        throwCode(CODES.LOCK_ACQUISITION_INDETERMINATE, error);
      }
      if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
        throw error;
      }
      throwCode(CODES.LOCK_ACQUISITION_FAILED, error);
    }
  }

  function quarantineStaleLock(existingLockFd, existingIdentity, nowUnixSeconds) {
    ensureQuarantineDirectories();
    if (fs.readdirSync(staleLockQuarantineDir).length >= MAX_STALE_LOCK_QUARANTINE_FILES) {
      throwCode(CODES.STALE_LOCK_QUARANTINE_BOUND_EXCEEDED);
    }
    const slot = lowestUnusedQuarantineSlot(staleLockQuarantineDir);
    if (slot < 0) {
      throwCode(CODES.STALE_LOCK_QUARANTINE_BOUND_EXCEEDED);
    }
    const destination = path.join(
      staleLockQuarantineDir,
      `staging.lock.stale.${slot}`
    );
    try {
      let probeFd;
      try {
        probeFd = fs.openSync(lockPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        validateLockDescriptor(probeIdentity, uid);
        if (
          probeIdentity.dev !== existingIdentity.dev
          || probeIdentity.ino !== existingIdentity.ino
        ) {
          throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }
      fs.renameSync(lockPath, destination);
      fsyncDirectory(stagingDir);
      fsyncDirectory(staleLockQuarantineDir);
    } catch (error) {
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && error.code === CODES.LOCK_DESCRIPTOR_INVALID
      ) {
        throw error;
      }
      poisonFn();
      throwCode(CODES.STALE_LOCK_QUARANTINE_INDETERMINATE, error);
    } finally {
      try {
        fs.closeSync(existingLockFd);
      } catch {
        // ignore
      }
    }
    try {
      acquireExclusiveLock(nowUnixSeconds);
    } catch (error) {
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && error.code === CODES.LOCK_ACQUISITION_FAILED
      ) {
        throwCode(CODES.LOCK_HELD, error);
      }
      throw error;
    }
  }

  function openExistingLockWithIdentity() {
    let existingFd;
    try {
      existingFd = fs.openSync(lockPath, O_RDONLY | O_NOFOLLOW);
    } catch (error) {
      throwCode(CODES.LOCK_ACQUISITION_FAILED, error);
    }
    let existingIdentity;
    try {
      existingIdentity = fstatIdentity(existingFd);
      validateLockDescriptor(existingIdentity, uid);
      let probeFd;
      try {
        probeFd = fs.openSync(lockPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        validateLockDescriptor(probeIdentity, uid);
        if (
          probeIdentity.dev !== existingIdentity.dev
          || probeIdentity.ino !== existingIdentity.ino
        ) {
          throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }
      return { existingFd, existingIdentity };
    } catch (error) {
      try {
        fs.closeSync(existingFd);
      } catch {
        // ignore
      }
      throw error;
    }
  }

  function handleExistingLock(nowUnixSeconds) {
    const { existingFd, existingIdentity } = openExistingLockWithIdentity();
    try {
      const size = fs.fstatSync(existingFd).size;
      if (size > MAX_LOCK_FILE_BYTES) {
        throwCode(CODES.LOCK_FILE_OVERSIZED);
      }
      // Re-probe immediately before reading so a replaced path fails closed
      // before parse/liveness.
      let preReadProbe;
      try {
        preReadProbe = fs.openSync(lockPath, O_RDONLY | O_NOFOLLOW);
        const preReadIdentity = fstatIdentity(preReadProbe);
        validateLockDescriptor(preReadIdentity, uid);
        if (
          preReadIdentity.dev !== existingIdentity.dev
          || preReadIdentity.ino !== existingIdentity.ino
        ) {
          throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
        }
      } finally {
        if (preReadProbe !== undefined) {
          fs.closeSync(preReadProbe);
        }
      }
      const raw = completeRead(existingFd, size);
      const lock = parseLockPayload(raw.toString("utf8"));
      const liveness = probeLiveness(livenessProbeFn, lock.pid);
      const age = nowUnixSeconds - lock.createdAtUnixSeconds;

      if (liveness === "LIVE") {
        throwCode(CODES.LOCK_HELD);
      }

      if (
        liveness !== "DEAD"
        || age < STALE_LOCK_MIN_AGE_SECONDS
        || lock.createdAtUnixSeconds > nowUnixSeconds
      ) {
        throwCode(CODES.LOCK_HELD_OR_AMBIGUOUS);
      }
    } catch (error) {
      try {
        fs.closeSync(existingFd);
      } catch {
        // ignore
      }
      throw error;
    }

    quarantineStaleLock(existingFd, existingIdentity, nowUnixSeconds);
  }

  const constructorNow = readNow(nowFn);
  try {
    acquireExclusiveLock(constructorNow);
  } catch (error) {
    if (
      error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
      && error.code === CODES.LOCK_ACQUISITION_FAILED
      && fs.existsSync(lockPath)
    ) {
      handleExistingLock(constructorNow);
    } else if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
      throw error;
    } else {
      throwCode(CODES.LOCK_ACQUISITION_FAILED, error);
    }
  }
  if (lockFd === undefined || lockIdentity === undefined) {
    throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
  }

  function ensureExclusiveLockAcquired() {
    assertActiveLockIdentity();
  }

  let closed = false;
  let closeState = "open";
  let reconciled = false;
  let reconciliationFailed = false;
  let reconciliationReport = null;
  let current = null;
  let lastObservedNowUnixSeconds = null;

  function readAndTrackNow() {
    const nowUnixSeconds = readNow(nowFn);
    if (
      lastObservedNowUnixSeconds !== null
      && nowUnixSeconds < lastObservedNowUnixSeconds
    ) {
      throwCode(CODES.CLOCK_REGRESSION_DETECTED);
    }
    lastObservedNowUnixSeconds = nowUnixSeconds;
    return nowUnixSeconds;
  }

  function assertHostActive(methodAllowedAfterPoison = false) {
    assertNotProcessPoisoned(lexicalStorageRoot, canonicalStagingKey);
    if (closed && methodAllowedAfterPoison !== "close") {
      throwCode(CODES.HOST_CLOSED);
    }
  }

  function assertActiveLockIdentity() {
    if (lockFd === undefined || lockIdentity === undefined) {
      throwCode(CODES.LOCK_DESCRIPTOR_INVALID);
    }
    const retained = fstatIdentity(lockFd);
    validateLockDescriptor(retained, uid);
    if (retained.dev !== lockIdentity.dev || retained.ino !== lockIdentity.ino) {
      poisonFn();
      throwCode(CODES.LOCK_LOST_OR_REPLACED);
    }

    let probeFd;
    try {
      probeFd = fs.openSync(lockPath, O_RDONLY | O_NOFOLLOW);
      const probeIdentity = fstatIdentity(probeFd);
      validateLockDescriptor(probeIdentity, uid);
      if (probeIdentity.dev !== lockIdentity.dev || probeIdentity.ino !== lockIdentity.ino) {
        poisonFn();
        throwCode(CODES.LOCK_LOST_OR_REPLACED);
      }
    } catch (error) {
      if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
        throw error;
      }
      poisonFn();
      throwCode(CODES.LOCK_LOST_OR_REPLACED, error);
    } finally {
      if (probeFd !== undefined) {
        fs.closeSync(probeFd);
      }
    }
  }

  function readJournalFile(journalPath) {
    let fd;
    try {
      fd = fs.openSync(journalPath, O_RDONLY | O_NOFOLLOW);
    } catch (error) {
      throwCode(CODES.FILESYSTEM_READ_FAILED, error);
    }
    try {
      const identity = fstatIdentity(fd);
      assertRegularFileOwned(identity, uid);
      let probeFd;
      try {
        probeFd = fs.openSync(journalPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        if (probeIdentity.dev !== identity.dev || probeIdentity.ino !== identity.ino) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }

      const size = fs.fstatSync(fd).size;
      if (size > MAX_JOURNAL_FILE_BYTES) {
        throwCode(CODES.JOURNAL_OVERSIZED);
      }
      const raw = completeRead(fd, size);
      let parsed;
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch (error) {
        throwCode(CODES.JOURNAL_JSON_INVALID, error);
      }
      const record = validateStagingJournalRecord(parsed);
      const basename = path.basename(journalPath);
      const match = basename.match(JOURNAL_NAME_RE);
      if (!match || `0x${match[1]}` !== record.ceremonyId) {
        throwCode(CODES.JOURNAL_FILENAME_ID_MISMATCH);
      }
      return Object.freeze({ record, journalPath, identity });
    } catch (error) {
      if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
        throw error;
      }
      throwCode(CODES.FILESYSTEM_READ_FAILED, error);
    } finally {
      fs.closeSync(fd);
    }
  }

  function classifyJournalReadResult(journalPath) {
    try {
      const { record } = readJournalFile(journalPath);
      return Object.freeze({ kind: "valid", record, journalPath });
    } catch (error) {
      if (!(error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError)) {
        return Object.freeze({ kind: "corrupt", journalPath, error });
      }
      if (
        error.code === CODES.JOURNAL_DESCRIPTOR_INVALID
        || error.code === CODES.FILESYSTEM_READ_FAILED
      ) {
        throw error;
      }
      if (
        error.code === CODES.JOURNAL_FILENAME_ID_MISMATCH
        || error.code.startsWith("JOURNAL_")
        || error.code.startsWith("MANIFEST_")
      ) {
        return Object.freeze({ kind: "corrupt", journalPath, error });
      }
      return Object.freeze({ kind: "corrupt", journalPath, error });
    }
  }

  function removeTempIfPresent(tempPath, poisonOnIndeterminate) {
    if (!fs.existsSync(tempPath)) {
      return;
    }
    let fd;
    try {
      fd = fs.openSync(tempPath, O_RDONLY | O_NOFOLLOW);
      const identity = fstatIdentity(fd);
      assertRegularFileOwned(identity, uid);
      let probeFd;
      try {
        probeFd = fs.openSync(tempPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        if (
          probeIdentity.dev !== identity.dev
          || probeIdentity.ino !== identity.ino
        ) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }
      // Re-probe immediately before unlink.
      let preUnlinkProbe;
      try {
        preUnlinkProbe = fs.openSync(tempPath, O_RDONLY | O_NOFOLLOW);
        const preUnlinkIdentity = fstatIdentity(preUnlinkProbe);
        if (
          preUnlinkIdentity.dev !== identity.dev
          || preUnlinkIdentity.ino !== identity.ino
        ) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (preUnlinkProbe !== undefined) {
          fs.closeSync(preUnlinkProbe);
        }
      }
      fs.unlinkSync(tempPath);
      try {
        fsyncDirectory(stagingDir);
      } catch (error) {
        if (poisonOnIndeterminate) {
          poisonFn();
          throwCode(CODES.TEMP_REMOVAL_INDETERMINATE, error);
        }
        throw error;
      }
    } catch (error) {
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && error.code === CODES.TEMP_REMOVAL_INDETERMINATE
      ) {
        throw error;
      }
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && error.code === CODES.JOURNAL_DESCRIPTOR_INVALID
      ) {
        throw error;
      }
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    } finally {
      if (fd !== undefined) {
        fs.closeSync(fd);
      }
    }
  }

  function writeJournalAtomic(journal, ceremonyId) {
    const finalPath = journalPathForCeremony(stagingDir, ceremonyId);
    const tempPath = journalTempPathForCeremony(stagingDir, ceremonyId);
    const payload = Buffer.from(`${JSON.stringify(journal)}\n`, "utf8");
    if (payload.length > MAX_JOURNAL_FILE_BYTES) {
      throwCode(CODES.JOURNAL_OVERSIZED);
    }

    if (fs.existsSync(tempPath)) {
      throwCode(CODES.TEMP_FILE_BOUND_EXCEEDED);
    }

    if (fs.existsSync(finalPath)) {
      const existing = readJournalFile(finalPath);
      if (existing.record.ceremonyId !== ceremonyId) {
        throwCode(CODES.DISK_STATE_CHANGED);
      }
    }

    let tempFd;
    try {
      tempFd = fs.openSync(tempPath, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600);
    } catch (error) {
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    }

    try {
      const tempIdentity = fstatIdentity(tempFd);
      assertRegularFileOwned(tempIdentity, uid);
      partialWriteLoop(tempFd, payload);
      fs.fsyncSync(tempFd);

      let probeFd;
      try {
        probeFd = fs.openSync(tempPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        if (probeIdentity.dev !== tempIdentity.dev || probeIdentity.ino !== tempIdentity.ino) {
          poisonFn();
          throwCode(CODES.DURABILITY_INDETERMINATE);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }

      fs.renameSync(tempPath, finalPath);
      try {
        fsyncDirectory(stagingDir);
      } catch (error) {
        poisonFn();
        throwCode(CODES.DURABILITY_INDETERMINATE, error);
      }
    } catch (error) {
      try {
        removeTempIfPresent(tempPath, true);
      } catch (cleanupError) {
        if (
          cleanupError instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
          && cleanupError.code === CODES.TEMP_REMOVAL_INDETERMINATE
        ) {
          throw cleanupError;
        }
      }
      if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
        throw error;
      }
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    } finally {
      if (tempFd !== undefined) {
        fs.closeSync(tempFd);
      }
    }
  }

  function removeJournalAtomic(ceremonyId) {
    const finalPath = journalPathForCeremony(stagingDir, ceremonyId);
    if (!fs.existsSync(finalPath)) {
      return;
    }

    let fd;
    try {
      fd = fs.openSync(finalPath, O_RDONLY | O_NOFOLLOW);
      const identity = fstatIdentity(fd);
      assertRegularFileOwned(identity, uid);

      let probeFd;
      try {
        probeFd = fs.openSync(finalPath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        if (probeIdentity.dev !== identity.dev || probeIdentity.ino !== identity.ino) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }

      fs.unlinkSync(finalPath);
      try {
        fsyncDirectory(stagingDir);
      } catch (error) {
        poisonFn();
        throwCode(CODES.JOURNAL_REMOVAL_INDETERMINATE, error);
      }
    } catch (error) {
      if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
        throw error;
      }
      throwCode(CODES.FILESYSTEM_MUTATION_FAILED, error);
    } finally {
      if (fd !== undefined) {
        fs.closeSync(fd);
      }
    }
  }

  function quarantineCorruptJournal(sourcePath) {
    if (fs.readdirSync(corruptQuarantineDir).length >= MAX_CORRUPT_QUARANTINE_FILES) {
      throwCode(CODES.CORRUPT_QUARANTINE_BOUND_EXCEEDED);
    }
    const slot = lowestUnusedQuarantineSlot(corruptQuarantineDir);
    if (slot < 0) {
      throwCode(CODES.CORRUPT_QUARANTINE_BOUND_EXCEEDED);
    }
    const original = path.basename(sourcePath);
    const destination = path.join(corruptQuarantineDir, `${original}.corrupt.${slot}`);
    let fd;
    try {
      fd = fs.openSync(sourcePath, O_RDONLY | O_NOFOLLOW);
      const identity = fstatIdentity(fd);
      assertRegularFileOwned(identity, uid);
      let probeFd;
      try {
        probeFd = fs.openSync(sourcePath, O_RDONLY | O_NOFOLLOW);
        const probeIdentity = fstatIdentity(probeFd);
        if (
          probeIdentity.dev !== identity.dev
          || probeIdentity.ino !== identity.ino
        ) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (probeFd !== undefined) {
          fs.closeSync(probeFd);
        }
      }
      // Re-probe immediately before rename.
      let preRenameProbe;
      try {
        preRenameProbe = fs.openSync(sourcePath, O_RDONLY | O_NOFOLLOW);
        const preRenameIdentity = fstatIdentity(preRenameProbe);
        if (
          preRenameIdentity.dev !== identity.dev
          || preRenameIdentity.ino !== identity.ino
        ) {
          throwCode(CODES.JOURNAL_DESCRIPTOR_INVALID);
        }
      } finally {
        if (preRenameProbe !== undefined) {
          fs.closeSync(preRenameProbe);
        }
      }
      fs.renameSync(sourcePath, destination);
      fsyncDirectory(stagingDir);
      fsyncDirectory(corruptQuarantineDir);
    } catch (error) {
      if (
        error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError
        && (
          error.code === CODES.CORRUPT_QUARANTINE_BOUND_EXCEEDED
          || error.code === CODES.JOURNAL_DESCRIPTOR_INVALID
        )
      ) {
        throw error;
      }
      poisonFn();
      throwCode(CODES.CORRUPT_QUARANTINE_INDETERMINATE, error);
    } finally {
      if (fd !== undefined) {
        try {
          fs.closeSync(fd);
        } catch {
          // ignore
        }
      }
    }
  }

  function requirePositiveUint48Bigint(value, fieldName) {
    if (typeof value !== "bigint" || value <= 0n || value > ((1n << 48n) - 1n)) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (fieldName) {
      return value;
    }
    return value;
  }

  function requireNonzeroUint64Bigint(value) {
    if (typeof value !== "bigint" || value <= 0n || value > ((1n << 64n) - 1n)) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    return value;
  }

  function requireNonzeroUint256Bigint(value) {
    if (typeof value !== "bigint" || value <= 0n || value > UINT256_MAX) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    return value;
  }

  function validateRetirementRecord(record, journal, endReason) {
    requireCallerObjectShape(record, CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    const keys = Object.keys(record);
    if (
      keys.length !== RETIREMENT_RECORD_KEYS.length
      || RETIREMENT_RECORD_KEYS.some((key, index) => keys[index] !== key)
    ) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }

    if (record.state !== "ENDED") {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.endReason !== endReason) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.ceremonyId !== journal.ceremonyId) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.enrollmentCeremonyHash !== journal.enrollmentCeremonyHash) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.accountVersionId !== journal.accountVersionId) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.securityModelId !== journal.securityModelId) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.recoveryDomainId !== journal.recoveryDomainId) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.account !== journal.account) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.entryPoint !== journal.entryPoint) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }

    requireNonzeroUint256Bigint(record.chainId);
    requireNonzeroUint64Bigint(record.expectedRecoveryEpoch);
    requireNonzeroUint64Bigint(record.expectedValidatorEpoch);
    requirePositiveUint48Bigint(record.expiresAtUnixSeconds);
    requirePositiveUint48Bigint(record.mintedAtUnixSeconds);
    requirePositiveUint48Bigint(record.lastObservedAtUnixSeconds);

    if (record.chainId.toString(10) !== journal.chainId) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.expectedRecoveryEpoch.toString(10) !== journal.expectedRecoveryEpoch) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.expectedValidatorEpoch.toString(10) !== journal.expectedValidatorEpoch) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.expiresAtUnixSeconds.toString(10) !== journal.expiresAtUnixSeconds) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }

    if (record.mintedAtUnixSeconds >= record.expiresAtUnixSeconds) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (record.lastObservedAtUnixSeconds < record.mintedAtUnixSeconds) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (endReason === "CANCELLED" && record.lastObservedAtUnixSeconds >= record.expiresAtUnixSeconds) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
    if (endReason === "EXPIRED" && record.lastObservedAtUnixSeconds < record.expiresAtUnixSeconds) {
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }
  }

  function classifyRetirementResult(journal, endReason) {
    let retirementResult;
    try {
      retirementResult = retireCeremonyFn(journal.ceremonyId);
    } catch (error) {
      poisonFn();
      throwCode(CODES.CEREMONY_RETIREMENT_FAILED, error);
    }

    if (
      retirementResult === null
      || retirementResult === undefined
      || typeof retirementResult !== "object"
      || typeof retirementResult === "function"
    ) {
      poisonFn();
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID);
    }

    let thenValue;
    try {
      thenValue = retirementResult.then;
    } catch (error) {
      poisonFn();
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID, error);
    }
    if (typeof thenValue === "function") {
      poisonFn();
      throwCode(CODES.CEREMONY_RETIREMENT_THENABLE_REJECTED);
    }

    try {
      validateRetirementRecord(retirementResult, journal, endReason);
    } catch (error) {
      if (isClassifiedError(error)) {
        poisonFn();
        throw error;
      }
      poisonFn();
      throwCode(CODES.CEREMONY_RETIREMENT_RESULT_INVALID, error);
    }
  }

  function performTerminalCleanup(journal, endReason) {
    writeJournalAtomic(journal, journal.ceremonyId);
    removeJournalAtomic(journal.ceremonyId);
    classifyRetirementResult(journal, endReason);
    current = null;
    lastObservedNowUnixSeconds = null;
    return toPublicSnapshot(journal);
  }

  function assertReconciled() {
    if (reconciliationFailed) {
      throwCode(CODES.RECONCILIATION_FAILED);
    }
    if (!reconciled) {
      throwCode(CODES.RECONCILIATION_REQUIRED);
    }
  }

  const host = {
    reconcileRestart() {
      assertHostActive();
      if (closed) {
        throwCode(CODES.HOST_CLOSED);
      }
      if (reconciliationFailed) {
        throwCode(CODES.RECONCILIATION_FAILED);
      }
      if (reconciled && reconciliationReport) {
        assertActiveLockIdentity();
        return reconciliationReport;
      }

      try {
        assertActiveLockIdentity();
        ensureQuarantineDirectories();

        let operationsPerformed = 0;
        let orphanTempFilesRemoved = 0;
        let corruptJournalFilesQuarantined = 0;
        let journalDisposition = "ABSENT";
        let terminalState = null;

        let entries;
        try {
          entries = fs.readdirSync(stagingDir);
        } catch (error) {
          throwCode(CODES.FILESYSTEM_READ_FAILED, error);
        }

        const journalPaths = [];
        const tempPaths = [];

        for (const entry of entries) {
          if (entry === LOCK_BASENAME) {
            continue;
          }
          if (entry === CORRUPT_QUARANTINE || entry === STALE_LOCK_QUARANTINE) {
            const entryPath = path.join(stagingDir, entry);
            const lst = fs.lstatSync(entryPath);
            if (!lst.isDirectory() || lst.isSymbolicLink()) {
              throwCode(CODES.UNEXPECTED_STAGING_ENTRY);
            }
            continue;
          }
          if (JOURNAL_NAME_RE.test(entry)) {
            journalPaths.push(path.join(stagingDir, entry));
            continue;
          }
          if (TEMP_NAME_RE.test(entry)) {
            tempPaths.push(path.join(stagingDir, entry));
            continue;
          }
          throwCode(CODES.UNEXPECTED_STAGING_ENTRY);
        }

        if (journalPaths.length > 1) {
          throwCode(CODES.MULTIPLE_JOURNALS_FOUND);
        }
        if (tempPaths.length > MAX_RECONCILIATION_TEMP_SWEEP) {
          throwCode(CODES.RECONCILIATION_TEMP_SWEEP_BOUND_EXCEEDED);
        }

        let classification = null;
        if (journalPaths.length === 1) {
          classification = classifyJournalReadResult(journalPaths[0]);
        }

        let plannedOperations = tempPaths.length;
        let stagingNowUnixSeconds = null;
        let plannedKind = "absent";

        if (classification !== null && classification.kind === "corrupt") {
          if (fs.readdirSync(corruptQuarantineDir).length >= MAX_CORRUPT_QUARANTINE_FILES) {
            throwCode(CODES.CORRUPT_QUARANTINE_BOUND_EXCEEDED);
          }
          plannedOperations += 1;
          plannedKind = "corrupt";
        } else if (classification !== null) {
          const record = classification.record;
          if (record.state === "STAGING") {
            stagingNowUnixSeconds = readNow(nowFn);
            supersedeStagingJournal(record, stagingNowUnixSeconds);
            plannedOperations += 2;
            plannedKind = "staging";
          } else if (
            record.state === "CANCELLED"
            || record.state === "EXPIRED"
            || record.state === "SUPERSEDED"
          ) {
            plannedOperations += 1;
            plannedKind = "terminal";
          } else {
            if (fs.readdirSync(corruptQuarantineDir).length >= MAX_CORRUPT_QUARANTINE_FILES) {
              throwCode(CODES.CORRUPT_QUARANTINE_BOUND_EXCEEDED);
            }
            plannedOperations += 1;
            plannedKind = "corrupt";
          }
        }

        if (plannedOperations > MAX_RECONCILIATION_OPERATIONS) {
          throwCode(CODES.RECONCILIATION_OPERATION_BOUND_EXCEEDED);
        }

        for (const tempPath of tempPaths) {
          removeTempIfPresent(tempPath, true);
          orphanTempFilesRemoved += 1;
          operationsPerformed += 1;
        }

        if (plannedKind === "absent") {
          reconciled = true;
          current = null;
          reconciliationReport = Object.freeze({
            journalDisposition,
            terminalState,
            orphanTempFilesRemoved,
            corruptJournalFilesQuarantined,
            operationsPerformed
          });
          return reconciliationReport;
        }

        const journalPath = journalPaths[0];
        if (plannedKind === "corrupt") {
          quarantineCorruptJournal(journalPath);
          corruptJournalFilesQuarantined = 1;
          operationsPerformed += 1;
          journalDisposition = "CORRUPT_QUARANTINED";
        } else if (plannedKind === "staging") {
          const superseded = supersedeStagingJournal(
            classification.record,
            stagingNowUnixSeconds
          );
          writeJournalAtomic(superseded, superseded.ceremonyId);
          operationsPerformed += 1;
          removeJournalAtomic(superseded.ceremonyId);
          operationsPerformed += 1;
          journalDisposition = "STAGING_SUPERSEDED_AND_REMOVED";
          terminalState = "SUPERSEDED";
        } else if (plannedKind === "terminal") {
          removeJournalAtomic(classification.record.ceremonyId);
          operationsPerformed += 1;
          journalDisposition = "TERMINAL_REMOVED";
          terminalState = classification.record.state;
        }

        reconciled = true;
        current = null;
        reconciliationReport = Object.freeze({
          journalDisposition,
          terminalState,
          orphanTempFilesRemoved,
          corruptJournalFilesQuarantined,
          operationsPerformed
        });
        return reconciliationReport;
      } catch (error) {
        reconciliationFailed = true;
        throw error;
      }
    },

    createJournal(ceremonyContext) {
      assertHostActive();
      if (closed) {
        throwCode(CODES.HOST_CLOSED);
      }
      assertReconciled();
      assertActiveLockIdentity();

      if (current !== null) {
        throwCode(CODES.JOURNAL_ALREADY_EXISTS);
      }

      for (const entry of fs.readdirSync(stagingDir)) {
        if (JOURNAL_NAME_RE.test(entry)) {
          throwCode(CODES.DISK_STATE_CHANGED);
        }
      }

      // `clockFailed` is a plain boolean sentinel, never a value that could
      // itself have been thrown -- `clockCause` alone cannot distinguish
      // "nowFn did not throw" from "nowFn explicitly threw undefined"
      // (both leave the variable `undefined`), which would otherwise lose
      // the fact that undefined was thrown and silently drop that cause.
      let clockFailed = false;
      let clockCause;
      let sampledNow = 0;
      try {
        sampledNow = nowFn();
      } catch (error) {
        clockFailed = true;
        clockCause = error;
        sampledNow = 0;
      }

      let journal;
      try {
        journal = createStagingJournal(ceremonyContext, sampledNow);
      } catch (error) {
        if (
          clockFailed
          && isClassifiedError(error)
          && error.code === CODES.INVALID_NOW
        ) {
          throwCode(CODES.INVALID_NOW, clockCause);
        }
        throw error;
      }

      // Host-side clock tracking only after successful pure creation. Reject
      // values the pure path accepted but that violate host tracking bounds.
      const trackedNow = readNow(() => sampledNow);
      if (
        lastObservedNowUnixSeconds !== null
        && trackedNow < lastObservedNowUnixSeconds
      ) {
        throwCode(CODES.CLOCK_REGRESSION_DETECTED);
      }
      lastObservedNowUnixSeconds = trackedNow;
      writeJournalAtomic(journal, journal.ceremonyId);
      current = journal;
      return toPublicSnapshot(journal);
    },

    stageRole(role, candidateInput) {
      assertHostActive();
      if (closed) {
        throwCode(CODES.HOST_CLOSED);
      }
      assertReconciled();
      assertActiveLockIdentity();

      if (current === null) {
        throwCode(CODES.JOURNAL_NOT_FOUND);
      }
      if (current.state !== "STAGING") {
        throwCode(CODES.JOURNAL_NOT_STAGING);
      }

      if (!(role === 0 || role === 1 || role === 2)) {
        throwCode(CODES.STAGE_ROLE_INVALID);
      }

      // Candidate-input sequence before method clock activity: the pure
      // stageRoleCandidate/validateCandidateInput chain performs exact
      // sequential structural, extra/missing-key, and per-field type/
      // semantic validation of candidateInput -- including safe, single-
      // read property access via that module's own hostile-getter
      // classification -- before this peek call ever touches the clock.
      // Peek with the journal's own updatedAt (never a regression, never
      // expired relative to itself) and discard the result so a malformed
      // candidate fails without calling nowFn.
      //
      // The peek's validated candidate fields are embedded in its returned
      // manifest entry; reuse that plain, already-validated object as the
      // candidate input for the real transition below instead of touching
      // candidateInput's own properties a second time. This guarantees
      // every caller-owned candidate field is read exactly once, and that
      // the value staged cannot drift from the value precedence-checked.
      const peek = stageRoleCandidate(
        current,
        role,
        candidateInput,
        Number(current.updatedAtUnixSeconds)
      );
      const validatedEntry = peek.manifest[String(role)];
      const candidateSnapshot = Object.freeze({
        candidateKind: validatedEntry.candidateKind,
        candidateVersion: validatedEntry.candidateVersion,
        publicCandidateCommitment: validatedEntry.publicCandidateCommitment,
        credentialGeneration: validatedEntry.credentialGeneration
      });

      const nowUnixSeconds = readAndTrackNow();
      assertClockNotRegressed(nowUnixSeconds, current.updatedAtUnixSeconds);

      let next;
      if (nowUnixSeconds >= Number(current.expiresAtUnixSeconds)) {
        next = stageRoleCandidate(current, role, candidateSnapshot, nowUnixSeconds);
        return performTerminalCleanup(next, "EXPIRED");
      }

      next = stageRoleCandidate(current, role, candidateSnapshot, nowUnixSeconds);
      writeJournalAtomic(next, next.ceremonyId);
      current = next;
      return toPublicSnapshot(next);
    },

    cancel() {
      assertHostActive();
      if (closed) {
        throwCode(CODES.HOST_CLOSED);
      }
      assertReconciled();
      assertActiveLockIdentity();

      if (current === null) {
        throwCode(CODES.JOURNAL_NOT_FOUND);
      }
      if (current.state !== "STAGING") {
        throwCode(CODES.JOURNAL_NOT_STAGING);
      }

      const nowUnixSeconds = readAndTrackNow();
      assertClockNotRegressed(nowUnixSeconds, current.updatedAtUnixSeconds);

      const cancelled = cancelStagingJournal(current, nowUnixSeconds);
      const endReason = cancelled.state === "EXPIRED" ? "EXPIRED" : "CANCELLED";
      return performTerminalCleanup(cancelled, endReason);
    },

    status() {
      assertHostActive();
      if (closed) {
        throwCode(CODES.HOST_CLOSED);
      }
      assertReconciled();
      assertActiveLockIdentity();

      if (current === null) {
        return null;
      }

      const nowUnixSeconds = readAndTrackNow();
      assertClockNotRegressed(nowUnixSeconds, current.updatedAtUnixSeconds);

      if (nowUnixSeconds >= Number(current.expiresAtUnixSeconds)) {
        const expired = expireStagingJournalIfNeeded(current, nowUnixSeconds);
        return performTerminalCleanup(expired, "EXPIRED");
      }

      return toPublicSnapshot(current);
    },

    close() {
      if (closeState === "released") {
        return;
      }
      if (closeState === "indeterminate") {
        throwCode(CODES.LOCK_RELEASE_INDETERMINATE);
      }

      if (lockFd === undefined) {
        closeState = "released";
        closed = true;
        return;
      }

      try {
        assertActiveLockIdentity();
      } catch (error) {
        closeState = "indeterminate";
        poisonFn();
        if (error instanceof PhilCoreV2ConsumerRecoveryStagingJournalError) {
          throwCode(CODES.LOCK_RELEASE_INDETERMINATE, error);
        }
        throwCode(CODES.LOCK_RELEASE_INDETERMINATE, error);
      }

      try {
        fs.unlinkSync(lockPath);
        try {
          fsyncDirectory(stagingDir);
        } catch (error) {
          closeState = "indeterminate";
          poisonFn();
          throwCode(CODES.LOCK_RELEASE_INDETERMINATE, error);
        }
      } catch (error) {
        closeState = "indeterminate";
        poisonFn();
        throwCode(CODES.LOCK_RELEASE_INDETERMINATE, error);
      } finally {
        if (lockFd !== undefined) {
          try {
            fs.closeSync(lockFd);
          } catch {
            // ignore
          }
          lockFd = undefined;
        }
      }

      closeState = "released";
      closed = true;
    }
  };

  return Object.freeze(host);
}

module.exports = {
  createRecoveryStagingHost,
  PhilCoreV2ConsumerRecoveryStagingJournalError,
  PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE
};
