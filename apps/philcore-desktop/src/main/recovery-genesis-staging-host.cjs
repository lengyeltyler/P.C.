"use strict";

// PhilCore Package 5B-0.5 — dormant recovery genesis staging host.
//
// This module is intentionally unwired: nothing in the desktop main process,
// preload, renderer, IPC, or bridge contract requires it. It performs no work
// at require time, opens no network socket, touches no device, reads no
// secret, and signs nothing.
//
// Publication of the final journal uses ordinary fs.renameSync (decision D27,
// ratified by explicit user vote). The accepted design performs a final CAS
// probe/classify/identity-compare immediately before the rename with no
// intervening syscall, but it does NOT provide atomic no-clobber protection:
// a non-cooperating same-UID writer that creates the final journal path inside
// the last check-to-rename window can be silently overwritten, and the
// affected operation still reports success. That residual risk is disclosed,
// not defended against, and the threat model remains cooperative-only.
//
// linkSync-based no-clobber publication was declined as a SCOPE decision for
// this package. Node's fs.link/fs.linkSync were confirmed available; the
// alternative was not rejected for needing a native binding.
//
// Every filesystem call below goes through the `fs` namespace object rather
// than a destructured binding, so a deterministic, scoped fault facade can
// intercept an exact call site during testing (decision D6) without this
// module exposing any test-only surface.

const fs = require("node:fs");
const path = require("node:path");

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

// 98 externally thrown codes (83 landed + 15 credential-obligation).
const EXTERNAL_CODES = [
  "HOST_ACKNOWLEDGMENT_CHECKSUM_MISMATCH",
  "HOST_ACKNOWLEDGMENT_ENUMERATION_FAILED",
  "HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH",
  "HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY",
  "HOST_ACKNOWLEDGMENT_INPUT_INVALID",
  "HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY",
  "HOST_ACKNOWLEDGMENT_INPUT_NOT_OBJECT",
  "HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED",
  "HOST_ACKNOWLEDGMENT_READ_FAILED",
  "HOST_CLEANUP_DESCRIPTOR_LEAKED",
  "HOST_CLOCK_REGRESSION_DETECTED",
  "HOST_CLOSED",
  "HOST_CORRUPT_QUARANTINE_BOUND_EXCEEDED",
  "HOST_CORRUPT_QUARANTINE_FAILED",
  "HOST_CORRUPT_QUARANTINE_INDETERMINATE",
  "HOST_DEPENDENCIES_NOT_OBJECT",
  "HOST_DEPENDENCY_ENUMERATION_FAILED",
  "HOST_DEPENDENCY_EXTRA",
  "HOST_DEPENDENCY_INVALID",
  "HOST_DEPENDENCY_MISSING",
  "HOST_DEPENDENCY_READ_FAILED",
  "HOST_DESCRIPTOR_CLOSE_FAILED",
  "HOST_DISK_STATE_CHANGED",
  "HOST_DURABILITY_INDETERMINATE",
  "HOST_DURABILITY_WRITE_FAILED",
  "HOST_ENUMERATION_HANDLE_CLOSE_FAILED",
  "HOST_FILESYSTEM_MUTATION_FAILED",
  "HOST_FILESYSTEM_READ_FAILED",
  "HOST_FINALIZED_PROFILE_ALREADY_EXISTS",
  "HOST_FINALIZED_PROFILE_CONFLICT",
  "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID",
  "HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_EMPTY",
  "HOST_FINALIZED_PROFILE_FILE_OVERSIZED",
  "HOST_FINALIZED_PROFILE_FILENAME_ID_MISMATCH",
  "HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_JSON_INVALID",
  "HOST_FINALIZED_PROFILE_MISSING_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_NONCANONICAL",
  "HOST_FINALIZED_PROFILE_SCAN_OVERFLOW",
  "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID",
  "HOST_FINALIZED_PROFILE_SUPERSESSION_CLOCK_REGRESSION",
  "HOST_FINALIZED_PROFILE_TEMP_BOUND_EXCEEDED",
  "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_UTF8_INVALID",
  "HOST_MULTIPLE_FINALIZED_PROFILES_FOUND",
  "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY",
  "HOST_INVALID_NOW",
  "HOST_JOURNAL_ALREADY_EXISTS",
  "HOST_JOURNAL_DESCRIPTOR_INVALID",
  "HOST_JOURNAL_NOT_ACTIVE",
  "HOST_JOURNAL_NOT_FOUND",
  "HOST_JOURNAL_REMOVAL_INDETERMINATE",
  "HOST_LOCK_ACQUISITION_FAILED",
  "HOST_LOCK_ACQUISITION_INDETERMINATE",
  "HOST_LOCK_DESCRIPTOR_INVALID",
  "HOST_LOCK_FILE_MALFORMED",
  "HOST_LOCK_FILE_OVERSIZED",
  "HOST_LOCK_HELD",
  "HOST_LOCK_HELD_OR_AMBIGUOUS",
  "HOST_LOCK_LIVENESS_RESULT_INVALID",
  "HOST_LOCK_LOST_OR_REPLACED",
  "HOST_LOCK_RELEASE_INDETERMINATE",
  "HOST_MULTIPLE_JOURNALS_FOUND",
  "HOST_PLATFORM_UNSUPPORTED",
  "HOST_PROCESS_POISONED",
  "HOST_QUARANTINE_SCAN_OVERFLOW",
  "HOST_RECONCILIATION_REQUIRED",
  "HOST_SERIALIZATION_REJECTED",
  "HOST_STAGING_SCAN_OVERFLOW",
  "HOST_STALE_LOCK_QUARANTINE_BOUND_EXCEEDED",
  "HOST_STALE_LOCK_QUARANTINE_FAILED",
  "HOST_STALE_LOCK_QUARANTINE_INDETERMINATE",
  "HOST_STORAGE_DIRECTORY_CREATE_FAILED",
  "HOST_STORAGE_DIRECTORY_INVALID",
  "HOST_STORAGE_DIRECTORY_MODE_INVALID",
  "HOST_STORAGE_DIRECTORY_OWNER_INVALID",
  "HOST_STORAGE_ROOT_INVALID",
  "HOST_STORAGE_ROOT_NOT_FOUND",
  "HOST_STORAGE_ROOT_UNSAFE",
  "HOST_TEMP_FILE_BOUND_EXCEEDED",
  "HOST_TEMP_REMOVAL_INDETERMINATE",
  "HOST_UNEXPECTED_STAGING_ENTRY",
  "HOST_CREDENTIAL_OBLIGATION_ALREADY_EXISTS",
  "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND",
  "HOST_CREDENTIAL_OBLIGATION_INVALID",
  "HOST_CREDENTIAL_OBLIGATION_OVERSIZED",
  "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID",
  "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_CREDENTIAL_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_ORPHANED",
  "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
  "HOST_CREDENTIAL_OBLIGATION_DURABILITY_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_RETIREMENT_FAILED",
  "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED",
  "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY"
];

// 7 internal journal-corruption classifications. These are never thrown as a
// top-level code; they surface only as report.corruptionCode or
// detail.primaryCode.
const INTERNAL_CODES = [
  "HOST_JOURNAL_EMPTY",
  "HOST_JOURNAL_FILENAME_ID_MISMATCH",
  "HOST_JOURNAL_FILE_OVERSIZED",
  "HOST_JOURNAL_JSON_INVALID",
  "HOST_JOURNAL_NONCANONICAL",
  "HOST_JOURNAL_STORED_RECORD_INVALID",
  "HOST_JOURNAL_UTF8_INVALID"
];

const CODE = Object.freeze(
  Object.fromEntries([...EXTERNAL_CODES, ...INTERNAL_CODES].map((c) => [c, c]))
);

// The five top-level codes permitted to carry a non-null primaryCode. The
// relation is acyclic: a primaryCode is always an antecedent's own code and is
// never itself one of these five carriers reported recursively.
const PRIMARY_CODE_CARRIERS = new Set([
  "HOST_TEMP_REMOVAL_INDETERMINATE",
  "HOST_CORRUPT_QUARANTINE_FAILED",
  "HOST_CORRUPT_QUARANTINE_INDETERMINATE",
  "HOST_LOCK_ACQUISITION_INDETERMINATE",
  "HOST_CLEANUP_DESCRIPTOR_LEAKED",
  "HOST_FINALIZED_PROFILE_CONFLICT",
  "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE"
]);

const COMMIT_STATES = new Set([
  "NOT_APPLICABLE",
  "NOT_COMMITTED",
  "COMMITTED",
  "INDETERMINATE",
  "PROFILE_COMMITTED",
  "SUPERSESSION_INDETERMINATE",
  "MANIFEST_COMMITTED",
  "OBLIGATION_RETIREMENT_INDETERMINATE"
]);

const SUBJECTS = new Set([
  "SHARED_DIRECTORY",
  "STAGING_DIRECTORY",
  "CORRUPT_QUARANTINE_DIRECTORY",
  "STALE_LOCK_QUARANTINE_DIRECTORY",
  "FINALIZED_PROFILE_DIRECTORY",
  "FINALIZED_PROFILE_FILE",
  "LOCK_FILE",
  "JOURNAL_FILE",
  "TEMP_FILE",
  "CREDENTIAL_OBLIGATION_FILE"
]);

// Explicit finalized-authority contradiction codes that poison before throw (D1).
const FINALIZED_AUTHORITY_POISON_CODES = new Set([
  "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY",
  "HOST_MULTIPLE_FINALIZED_PROFILES_FOUND",
  "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID",
  "HOST_FINALIZED_PROFILE_FILE_OVERSIZED",
  "HOST_FINALIZED_PROFILE_EMPTY",
  "HOST_FINALIZED_PROFILE_UTF8_INVALID",
  "HOST_FINALIZED_PROFILE_JSON_INVALID",
  "HOST_FINALIZED_PROFILE_NONCANONICAL",
  "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID",
  "HOST_FINALIZED_PROFILE_FILENAME_ID_MISMATCH",
  "HOST_FINALIZED_PROFILE_CONFLICT",
  "HOST_FINALIZED_PROFILE_MISSING_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE"
]);

const OBLIGATION_AUTHORITY_POISON_CODES = new Set([
  "HOST_CREDENTIAL_OBLIGATION_INVALID",
  "HOST_CREDENTIAL_OBLIGATION_OVERSIZED",
  "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_DURABILITY_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED",
  "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY"
]);

// ---------------------------------------------------------------------------
// Storage layout and bounds
// ---------------------------------------------------------------------------
const SHARED_ENROLLMENT = "philcore-recovery-enrollment";
const STAGING_LEAF = "genesis-staging";
const FINALIZED_LEAF = "genesis-profiles";
const LOCK_BASENAME = ".staging.lock";
const CORRUPT_QUARANTINE = ".corrupt-quarantine";
const STALE_LOCK_QUARANTINE = ".stale-lock-quarantine";

const UINT48_MAX = 281474976710655;
const MAX_LOCK_FILE_BYTES = 256;
const MAX_CORRUPT_QUARANTINE_FILES = 10;
const MAX_STALE_LOCK_QUARANTINE_FILES = 10;
const STALE_LOCK_MIN_AGE_SECONDS = 60;
const MAX_STAGING_ENTRIES = 512;
const MAX_FINALIZED_ENTRIES = 512;
const MAX_QUARANTINE_ENTRIES = 64;
const MAX_FINALIZED_PROFILE_FILE_BYTES = 32768;

// Revision 7 byte contract. The true maxima are the real record limits; the
// comparator boundaries are the independent size gate. Passing the comparator
// never by itself implies the record is valid — the two checks are separate.
const TRUE_ENTRY_MAX_BYTES = 1874;
const TRUE_JOURNAL_MAX_BYTES = 7540;
const ENTRY_COMPARATOR_BOUNDARY = 4096;
const JOURNAL_COMPARATOR_BOUNDARY = 16384;

const JOURNAL_NAME_RE = /^ceremony_([0-9a-f]{64})\.v1\.json$/u;
const TEMP_NAME_RE = /^\.ceremony_([0-9a-f]{64})\.v1\.json\.tmp$/u;
const FINALIZED_PROFILE_NAME_RE = /^profile_([0-9a-f]{64})\.v1\.json$/u;
const FINALIZED_TEMP_NAME_RE = /^\.profile_([0-9a-f]{64})\.v1\.json\.tmp$/u;
const MAX_RECONCILIATION_TEMP_SWEEP = 10;
const MAX_FINALIZED_RECONCILIATION_TEMP_SWEEP = 10;
const ACK_OWN_KEYS = Object.freeze(["intentId", "integrityChecksum"]);
const OBLIGATION_FINAL_NAME = "genesis-credential-obligation.v1.json";
const OBLIGATION_TEMP_NAME = "genesis-credential-obligation.v1.json.tmp";
const OBLIGATION_NAME_PREFIX = "genesis-credential-obligation.";
const MAX_OBLIGATION_FILE_BYTES = 4096;
const RECORD_CREATED_OWN_KEYS = Object.freeze([
  "expectedCeremonyId", "credentialIdHash", "publicVerificationMaterialHash"
]);

const DEPENDENCY_OWN_KEYS = Object.freeze(["storageRoot", "nowFn", "livenessProbeFn"]);
const DEPENDENCY_REQUIRED_KEYS = Object.freeze(["storageRoot"]);
const LOCK_OWN_KEYS = Object.freeze(["pid", "createdAtUnixSeconds"]);
const LIVENESS_LITERALS = new Set(["LIVE", "DEAD", "AMBIGUOUS"]);

// Module-private poisoned-root registry, keyed by path.resolve(storageRoot),
// computed without filesystem access. close() never clears it; a fresh process
// is the only production reset.
const POISONED_ROOTS = new Set();

const O = fs.constants;


// ---------------------------------------------------------------------------
// Descriptor metadata contract
// ---------------------------------------------------------------------------
// The accepted post-read revalidation is seven-field. A snapshot is captured
// once per boundary from an already-obtained stat; no extra sensitive read is
// ever performed to satisfy these checks.
const SEVEN_FIELDS = Object.freeze(["dev", "ino", "type", "uid", "mode", "nlink", "size"]);

// "type" is captured from the already-obtained stat's own predicate, so the
// snapshot still costs no additional filesystem call.
function snapshotSeven(stat) {
  const out = Object.create(null);
  out.dev = stat.dev;
  out.ino = stat.ino;
  out.type = stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other";
  out.uid = stat.uid;
  out.mode = stat.mode;
  out.nlink = stat.nlink;
  out.size = stat.size;
  return out;
}

function sevenFieldEqual(a, b) {
  for (const field of SEVEN_FIELDS) {
    if (a[field] !== b[field]) return false;
  }
  return true;
}

// A journal, temp, or lock file: regular, current-UID owned, exactly 0600,
// single link.
function isOwnedRegularFile(stat) {
  return (
    stat.isFile() &&
    stat.uid === process.getuid() &&
    (stat.mode & 0o777) === 0o600 &&
    stat.nlink === 1
  );
}

// A derived directory: real directory, current-UID owned, exactly 0700.
function isOwnedDirectory(stat) {
  return (
    stat.isDirectory() &&
    stat.uid === process.getuid() &&
    (stat.mode & 0o777) === 0o700
  );
}

// ---------------------------------------------------------------------------
// Error type — detail carries exactly five keys and never a raw cause
// ---------------------------------------------------------------------------
const HOST_ERROR_BRAND = new WeakSet();

class PhilCoreV2ConsumerRecoveryGenesisStagingHostError extends Error {
  constructor(code, detail) {
    super(code);
    this.name = "PhilCoreV2ConsumerRecoveryGenesisStagingHostError";
    this.code = code;
    this.detail = Object.freeze({
      commitState: detail.commitState,
      operation: detail.operation,
      phase: detail.phase,
      primaryCode: detail.primaryCode === undefined ? null : detail.primaryCode,
      subject: detail.subject === undefined ? null : detail.subject
    });
    HOST_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value) {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return false;
    }
    return HOST_ERROR_BRAND.has(value);
  }
}

Object.defineProperty(
  PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2ConsumerRecoveryGenesisStagingHostError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

function failure(code, operation, phase, subject, commitState, primaryCode) {
  if (!CODE[code]) throw new Error(`internal: unknown code ${code}`);
  if (!COMMIT_STATES.has(commitState)) throw new Error(`internal: bad commitState ${commitState}`);
  if (subject !== null && !SUBJECTS.has(subject)) throw new Error(`internal: bad subject ${subject}`);
  if (primaryCode != null && !PRIMARY_CODE_CARRIERS.has(code)) {
    throw new Error(`internal: ${code} may not carry a primaryCode`);
  }
  if (primaryCode != null && PRIMARY_CODE_CARRIERS.has(primaryCode)) {
    throw new Error(`internal: primaryCode ${primaryCode} may not be a carrier`);
  }
  return new PhilCoreV2ConsumerRecoveryGenesisStagingHostError(code, {
    commitState,
    operation,
    phase,
    primaryCode: primaryCode === undefined ? null : primaryCode,
    subject
  });
}

function failFinalized(ctx, code, operation, phase, subject, commitState, primaryCode) {
  if (FINALIZED_AUTHORITY_POISON_CODES.has(code)) poison(ctx);
  throw failure(code, operation, phase, subject, commitState, primaryCode);
}

function failObligation(ctx, code, operation, phase, subject, commitState, primaryCode) {
  if (OBLIGATION_AUTHORITY_POISON_CODES.has(code)) poison(ctx);
  throw failure(code, operation, phase, subject, commitState, primaryCode);
}

function rejectIfFinalizedProfileCommitted(state, op) {
  if (state.finalizedProfile !== null) {
    throw failure(
      "HOST_FINALIZED_PROFILE_ALREADY_EXISTS",
      op,
      "FINALIZED_GUARD",
      null,
      "NOT_APPLICABLE"
    );
  }
}

// ---------------------------------------------------------------------------
// Hostile-value discipline
// ---------------------------------------------------------------------------
// A caller-supplied or thrown value is never read, enumerated, coerced, or
// probed. Only `typeof` — which invokes no trap — is ever applied.
function isObjectLike(value) {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}

module.exports = {
  createRecoveryGenesisStagingHost,
  PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
  PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_HOST_ERROR_CODE: CODE
};

// ---------------------------------------------------------------------------
// Construction — Chain 1
// ---------------------------------------------------------------------------
function createRecoveryGenesisStagingHost(deps) {
  const op = "construct";

  // --- 1.01-1.06 DEPENDENCY_VALIDATION -------------------------------------
  if (!isObjectLike(deps)) {
    throw failure("HOST_DEPENDENCIES_NOT_OBJECT", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
  }

  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(deps);
  } catch {
    // The thrown value is discarded unread: no property access, no coercion.
    throw failure("HOST_DEPENDENCY_ENUMERATION_FAILED", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
  }

  for (const key of ownKeys) {
    if (typeof key === "symbol" || !DEPENDENCY_OWN_KEYS.includes(key)) {
      throw failure("HOST_DEPENDENCY_EXTRA", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
    }
  }
  for (const key of DEPENDENCY_REQUIRED_KEYS) {
    if (!ownKeys.includes(key)) {
      throw failure("HOST_DEPENDENCY_MISSING", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
    }
  }

  const read = (key) => {
    try {
      return Reflect.get(deps, key);
    } catch {
      throw failure("HOST_DEPENDENCY_READ_FAILED", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
    }
  };

  const storageRoot = read("storageRoot");
  const nowFn = ownKeys.includes("nowFn") ? read("nowFn") : defaultNowFn;
  const livenessProbeFn = ownKeys.includes("livenessProbeFn") ? read("livenessProbeFn") : defaultLivenessProbeFn;

  if (typeof storageRoot !== "string" || storageRoot.length === 0) {
    throw failure("HOST_DEPENDENCY_INVALID", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
  }
  if (typeof nowFn !== "function" || typeof livenessProbeFn !== "function") {
    throw failure("HOST_DEPENDENCY_INVALID", op, "DEPENDENCY_VALIDATION", null, "NOT_APPLICABLE");
  }

  // --- 1.07 MODULE_POISON_CHECK --------------------------------------------
  // Resolved without any filesystem access, and consulted before any syscall.
  const registryKey = path.resolve(storageRoot);
  if (POISONED_ROOTS.has(registryKey)) {
    throw failure("HOST_PROCESS_POISONED", op, "MODULE_POISON_CHECK", null, "NOT_APPLICABLE");
  }

  // --- 1.08 PLATFORM_VALIDATION --------------------------------------------
  if (process.platform !== "darwin") {
    throw failure("HOST_PLATFORM_UNSUPPORTED", op, "PLATFORM_VALIDATION", null, "NOT_APPLICABLE");
  }

  const ctx = {
    op,
    registryKey,
    storageRoot,
    nowFn,
    livenessProbeFn,
    sharedDir: path.join(registryKey, SHARED_ENROLLMENT),
    stagingDir: path.join(registryKey, SHARED_ENROLLMENT, STAGING_LEAF),
    finalizedDir: path.join(registryKey, SHARED_ENROLLMENT, FINALIZED_LEAF),
    corruptDir: path.join(registryKey, SHARED_ENROLLMENT, STAGING_LEAF, CORRUPT_QUARANTINE),
    staleDir: path.join(registryKey, SHARED_ENROLLMENT, STAGING_LEAF, STALE_LOCK_QUARANTINE),
    derivedDirectoriesCreated: 0
  };
  ctx.lockPath = path.join(ctx.stagingDir, LOCK_BASENAME);

  // --- 1.09-1.11 ROOT_VALIDATION -------------------------------------------
  let rootStat;
  try {
    rootStat = fs.lstatSync(registryKey);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw failure("HOST_STORAGE_ROOT_NOT_FOUND", op, "ROOT_VALIDATION", "SHARED_DIRECTORY", "NOT_APPLICABLE");
    }
    throw failure("HOST_STORAGE_ROOT_INVALID", op, "ROOT_VALIDATION", "SHARED_DIRECTORY", "NOT_APPLICABLE");
  }
  if (rootStat.isSymbolicLink()) {
    throw failure("HOST_STORAGE_ROOT_UNSAFE", op, "ROOT_VALIDATION", "SHARED_DIRECTORY", "NOT_APPLICABLE");
  }
  if (!rootStat.isDirectory()) {
    throw failure("HOST_STORAGE_ROOT_INVALID", op, "ROOT_VALIDATION", "SHARED_DIRECTORY", "NOT_APPLICABLE");
  }

  // --- 1.12-1.18 derived directories ---------------------------------------
  ensureDirectory(ctx, ctx.sharedDir, "SHARED_DIRECTORY");
  ensureDirectory(ctx, ctx.stagingDir, "STAGING_DIRECTORY");
  ensureDirectory(ctx, ctx.finalizedDir, "FINALIZED_PROFILE_DIRECTORY");
  ensureDirectory(ctx, ctx.corruptDir, "CORRUPT_QUARANTINE_DIRECTORY");
  ensureDirectory(ctx, ctx.staleDir, "STALE_LOCK_QUARANTINE_DIRECTORY");

  // --- 1.19-1.22 bounded quarantine enumeration ----------------------------
  const staleSlots = enumerateBounded(
    ctx,
    ctx.staleDir,
    "STALE_LOCK_QUARANTINE_DIRECTORY",
    MAX_QUARANTINE_ENTRIES,
    "HOST_QUARANTINE_SCAN_OVERFLOW",
    "NOT_APPLICABLE"
  );

  // --- 1.23-1.45 existing-lock probe, liveness, stale-lock quarantine ------
  acquireLock(ctx, staleSlots);

  const host = makeHost(ctx);
  return host;
}

function defaultNowFn() {
  return Math.floor(Date.now() / 1000);
}

function defaultLivenessProbeFn(pid) {
  try {
    process.kill(pid, 0);
    return "LIVE";
  } catch (error) {
    if (error && error.code === "ESRCH") return "DEAD";
    return "AMBIGUOUS";
  }
}

// ---------------------------------------------------------------------------
// Directory creation and durability — 1.12-1.18
// ---------------------------------------------------------------------------
function ensureDirectory(ctx, dir, subject) {
  const op = ctx.op;
  let created = false;
  let stat;
  try {
    stat = fs.lstatSync(dir);
  } catch (error) {
    if (!error || error.code !== "ENOENT") {
      throw failure("HOST_STORAGE_DIRECTORY_INVALID", op, "DIRECTORY_VALIDATE", subject, "NOT_APPLICABLE");
    }
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
      created = true;
      ctx.derivedDirectoriesCreated += 1;
    } catch {
      throw failure("HOST_STORAGE_DIRECTORY_CREATE_FAILED", op, "DIRECTORY_CREATE", subject, "NOT_APPLICABLE");
    }
  }

  // Re-open the directory itself and validate the descriptor, so a path swap
  // between the probe and the open cannot be missed.
  let fd;
  try {
    fd = fs.openSync(dir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    throw failure("HOST_STORAGE_DIRECTORY_INVALID", op, "DIRECTORY_OPEN", subject, "NOT_APPLICABLE");
  }

  let closed = false;
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_STORAGE_DIRECTORY_INVALID", op, "DIRECTORY_VALIDATE", subject, "NOT_APPLICABLE");
    }
    if (!dstat.isDirectory()) {
      throw failure("HOST_STORAGE_DIRECTORY_INVALID", op, "DIRECTORY_VALIDATE", subject, "NOT_APPLICABLE");
    }
    if (dstat.uid !== process.getuid()) {
      throw failure("HOST_STORAGE_DIRECTORY_OWNER_INVALID", op, "DIRECTORY_VALIDATE", subject, "NOT_APPLICABLE");
    }
    if ((dstat.mode & 0o777) !== 0o700) {
      throw failure("HOST_STORAGE_DIRECTORY_MODE_INVALID", op, "DIRECTORY_VALIDATE", subject, "NOT_APPLICABLE");
    }
    void isOwnedDirectory;

    if (created) {
      try {
        fs.fsyncSync(fd);
      } catch {
        throw failure("HOST_DURABILITY_WRITE_FAILED", op, "DIRECTORY_FSYNC", subject, "NOT_APPLICABLE");
      }
    }
  } finally {
    if (!closed) {
      try {
        fs.closeSync(fd);
        closed = true;
      } catch {
        // DC3: a read-only descriptor close in an operation that mutated no
        // journal or lock. Not poisoning; the read result is discarded. The
        // descriptor's actual disposition is left unasserted and never reused.
        throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", ctx.op, "DIRECTORY_CLOSE", subject, "NOT_APPLICABLE");
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Bounded enumeration — SM11
// ---------------------------------------------------------------------------
function enumerateBounded(ctx, dir, subject, ceiling, overflowCode, commitState, prefix) {
  const op = ctx.op;
  const p = prefix || "ENUMERATION";
  let handle;
  try {
    handle = fs.opendirSync(dir);
  } catch {
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${p}_OPEN`, subject, commitState);
  }

  const names = [];
  try {
    for (;;) {
      let entry;
      try {
        entry = handle.readSync();
      } catch {
        throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${p}_READ`, subject, commitState);
      }
      if (entry === null) break;
      // Read first, then increment, then compare (decision D30).
      names.push(entry.name);
      if (names.length > ceiling) {
        throw failure(overflowCode, op, `${p}_READ`, subject, commitState);
      }
    }
  } finally {
    try {
      handle.closeSync();
    } catch {
      throw failure("HOST_ENUMERATION_HANDLE_CLOSE_FAILED", op, `${p}_CLOSE`, subject, commitState);
    }
  }
  return names;
}

// ---------------------------------------------------------------------------
// Lock acquisition — 1.23-1.61
// ---------------------------------------------------------------------------
function acquireLock(ctx, staleSlots) {
  const op = ctx.op;
  const S = "LOCK_FILE";

  // --- 1.23-1.29 probe an existing lock ------------------------------------
  let probeFd = null;
  try {
    probeFd = fs.openSync(ctx.lockPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch (error) {
    if (!error || error.code !== "ENOENT") {
      throw failure("HOST_FILESYSTEM_READ_FAILED", op, "LOCK_PROBE_OPEN", S, "NOT_APPLICABLE");
    }
    probeFd = null;
  }

  if (probeFd !== null) {
    let payload = null;
    try {
      let pstat;
      try {
        pstat = fs.fstatSync(probeFd);
      } catch {
        throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_PROBE_CLASSIFY", S, "NOT_APPLICABLE");
      }
      if (!isOwnedRegularFile(pstat)) {
        throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_PROBE_CLASSIFY", S, "NOT_APPLICABLE");
      }
      const capturedLock = snapshotSeven(pstat);
    if (pstat.size > MAX_LOCK_FILE_BYTES) {
        throw failure("HOST_LOCK_FILE_OVERSIZED", op, "LOCK_PROBE_CLASSIFY", S, "NOT_APPLICABLE");
      }

      const buffer = Buffer.allocUnsafe(pstat.size);
      let read = 0;
      while (read < pstat.size) {
        let n;
        try {
          n = fs.readSync(probeFd, buffer, read, pstat.size - read, read);
        } catch {
          throw failure("HOST_FILESYSTEM_READ_FAILED", op, "LOCK_PROBE_READ", S, "NOT_APPLICABLE");
        }
        if (n === 0) break;
        read += n;
      }

      let rstat;
      try {
        rstat = fs.fstatSync(probeFd);
      } catch {
        throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_PROBE_RECHECK", S, "NOT_APPLICABLE");
      }
      if (rstat.dev !== pstat.dev || rstat.ino !== pstat.ino || rstat.size !== pstat.size) {
        throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_PROBE_RECHECK", S, "NOT_APPLICABLE");
      }
      payload = buffer.subarray(0, read);
    } finally {
      try {
        fs.closeSync(probeFd);
      } catch {
        throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "LOCK_PROBE_CLOSE", S, "NOT_APPLICABLE");
      }
    }

    const record = parseLockPayload(ctx, payload);

    // --- 1.30-1.33 liveness and staleness ----------------------------------
    let liveness;
    try {
      liveness = ctx.livenessProbeFn(record.pid);
    } catch {
      throw failure("HOST_LOCK_LIVENESS_RESULT_INVALID", op, "LOCK_LIVENESS", S, "NOT_APPLICABLE");
    }
    if (typeof liveness !== "string" || !LIVENESS_LITERALS.has(liveness)) {
      throw failure("HOST_LOCK_LIVENESS_RESULT_INVALID", op, "LOCK_LIVENESS", S, "NOT_APPLICABLE");
    }
    if (liveness === "LIVE") {
      throw failure("HOST_LOCK_HELD", op, "LOCK_LIVENESS", S, "NOT_APPLICABLE");
    }
    if (liveness === "AMBIGUOUS") {
      throw failure("HOST_LOCK_HELD_OR_AMBIGUOUS", op, "LOCK_LIVENESS", S, "NOT_APPLICABLE");
    }

    const now = sampleClock(ctx, op, "LOCK_STALENESS_WINDOW", S, "NOT_APPLICABLE");
    if (now - record.createdAtUnixSeconds < STALE_LOCK_MIN_AGE_SECONDS) {
      throw failure("HOST_LOCK_HELD_OR_AMBIGUOUS", op, "LOCK_STALENESS_WINDOW", S, "NOT_APPLICABLE");
    }

    quarantineStaleLock(ctx, staleSlots);
  }

  // --- 1.46 create the lock ------------------------------------------------
  let lockFd;
  try {
    lockFd = fs.openSync(ctx.lockPath, O.O_CREAT | O.O_EXCL | O.O_RDWR | O.O_NOFOLLOW, 0o600);
  } catch {
    throw failure("HOST_LOCK_ACQUISITION_FAILED", op, "LOCK_CREATE", S, "NOT_COMMITTED");
  }

  // --- 1.47-1.55 post-create validate, write, durability, identity ---------
  let identity = null;
  try {
    let lstat;
    try {
      lstat = fs.fstatSync(lockFd);
    } catch {
      // No identity was ever established for the file this operation created,
      // so cleanup may not unlink by path.
      throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_POST_CREATE_VALIDATE", S, "NOT_COMMITTED");
    }
    // Ownership is established the instant the descriptor's identity is
    // readable, before any classification predicate, so a classification
    // failure still owns the file it created under O_EXCL.
    identity = { dev: lstat.dev, ino: lstat.ino };
    ctx.lockIdentity = identity;
    if (!isOwnedRegularFile(lstat)) {
      throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_POST_CREATE_VALIDATE", S, "NOT_COMMITTED");
    }

    const body = Buffer.from(
      JSON.stringify({
        pid: String(process.pid),
        createdAtUnixSeconds: String(sampleClock(ctx, op, "LOCK_PAYLOAD_WRITE", S, "NOT_COMMITTED"))
      }),
      "utf8"
    );
    let written = 0;
    while (written < body.length) {
      let n;
      try {
        n = fs.writeSync(lockFd, body, written, body.length - written, written);
      } catch {
        throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "LOCK_PAYLOAD_WRITE", S, "NOT_COMMITTED");
      }
      if (n === 0) {
        throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "LOCK_PAYLOAD_WRITE", S, "NOT_COMMITTED");
      }
      written += n;
    }

    try {
      fs.fsyncSync(lockFd);
    } catch {
      throw failure("HOST_DURABILITY_WRITE_FAILED", op, "LOCK_PAYLOAD_FSYNC", S, "NOT_COMMITTED");
    }
  } catch (error) {
    cleanupCreatedLock(ctx, lockFd, error);
    throw error;
  }

  // The payload descriptor is closed only after the payload is durable.
  try {
    fs.closeSync(lockFd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "LOCK_PAYLOAD_CLOSE", S, "NOT_COMMITTED");
    cleanupCreatedLock(ctx, null, error);
    throw error;
  }

  // --- 1.51-1.54 directory durability for the new lock name ----------------
  try {
    fsyncDirectory(ctx, ctx.stagingDir, "STAGING_DIRECTORY", "LOCK_DIR", "NOT_COMMITTED");
  } catch (error) {
    cleanupCreatedLock(ctx, null, error);
    throw error;
  }

  // --- 1.55 final identity confirmation ------------------------------------
  let finalStat;
  try {
    finalStat = fs.lstatSync(ctx.lockPath);
  } catch {
    const error = failure("HOST_LOCK_LOST_OR_REPLACED", ctx.op, "LOCK_IDENTITY", S, "NOT_COMMITTED");
    cleanupCreatedLock(ctx, null, error);
    throw error;
  }
  if (finalStat.dev !== identity.dev || finalStat.ino !== identity.ino) {
    const antecedent = failure("HOST_LOCK_LOST_OR_REPLACED", ctx.op, "LOCK_IDENTITY", S, "NOT_COMMITTED");
    // The cleanup probe runs independently. If it confirms the foreign
    // occupant, nothing is unlinked and this row stands; if the probe itself
    // fails, the accepted indeterminate cleanup outcome is reported instead.
    cleanupCreatedLock(ctx, null, antecedent, true);
    throw antecedent;
  }

  // ctx.lockIdentity was already retained at post-create validation.
  ctx.lockIdentity = identity;
}

function parseLockPayload(ctx, payload) {
  const S = "LOCK_FILE";
  let text;
  let parsed;
  try {
    text = payload.toString("utf8");
    parsed = JSON.parse(text);
  } catch {
    throw failure("HOST_LOCK_FILE_MALFORMED", ctx.op, "LOCK_PROBE_PARSE", S, "NOT_APPLICABLE");
  }
  if (!isObjectLike(parsed) || Array.isArray(parsed)) {
    throw failure("HOST_LOCK_FILE_MALFORMED", ctx.op, "LOCK_PROBE_PARSE", S, "NOT_APPLICABLE");
  }
  const keys = Object.keys(parsed);
  if (keys.length !== LOCK_OWN_KEYS.length || !LOCK_OWN_KEYS.every((k) => keys.includes(k))) {
    throw failure("HOST_LOCK_FILE_MALFORMED", ctx.op, "LOCK_PROBE_PARSE", S, "NOT_APPLICABLE");
  }
  const pid = Number(parsed.pid);
  const createdAtUnixSeconds = Number(parsed.createdAtUnixSeconds);
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) {
    throw failure("HOST_LOCK_FILE_MALFORMED", ctx.op, "LOCK_PROBE_PARSE", S, "NOT_APPLICABLE");
  }
  if (!Number.isSafeInteger(createdAtUnixSeconds) || createdAtUnixSeconds < 1) {
    throw failure("HOST_LOCK_FILE_MALFORMED", ctx.op, "LOCK_PROBE_PARSE", S, "NOT_APPLICABLE");
  }
  return { pid, createdAtUnixSeconds };
}

function sampleClock(ctx, op, phase, subject, commitState) {
  let value;
  try {
    value = ctx.nowFn();
  } catch {
    throw failure("HOST_INVALID_NOW", op, phase, subject, commitState);
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > UINT48_MAX) {
    throw failure("HOST_INVALID_NOW", op, phase, subject, commitState);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Directory durability helper — used by every *_DIR_* phase family
// ---------------------------------------------------------------------------
function fsyncDirectory(ctx, dir, subject, phasePrefix, commitState, indeterminateCode, primaryCode) {
  const op = ctx.op;
  const openPhase = `${phasePrefix}_OPEN`;
  const validatePhase = `${phasePrefix}_VALIDATE`;
  const fsyncPhase = `${phasePrefix}_FSYNC`;
  const closePhase = `${phasePrefix}_CLOSE`;

  const readFail = indeterminateCode || "HOST_FILESYSTEM_READ_FAILED";
  const validateFail = indeterminateCode || "HOST_STORAGE_DIRECTORY_INVALID";
  const fsyncFail = indeterminateCode || "HOST_DURABILITY_WRITE_FAILED";

  let fd;
  try {
    fd = fs.openSync(dir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    throw failure(readFail, op, openPhase, subject, commitState, primaryCode);
  }

  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      throw failure(validateFail, op, validatePhase, subject, commitState, primaryCode);
    }
    if (!isOwnedDirectory(dstat)) {
      throw failure(validateFail, op, validatePhase, subject, commitState, primaryCode);
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      throw failure(fsyncFail, op, fsyncPhase, subject, commitState, primaryCode);
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // The fsync already succeeded when we reach here on the success path, so
      // the namespace change is durable and only the descriptor is in doubt.
      throw failure(
        indeterminateCode || "HOST_DESCRIPTOR_CLOSE_FAILED",
        op, closePhase, subject, commitState, primaryCode
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Stale-lock quarantine — 1.34-1.45
// ---------------------------------------------------------------------------
function quarantineStaleLock(ctx, staleSlots) {
  const op = ctx.op;
  const S = "LOCK_FILE";

  const used = staleSlots.filter((n) => /^staging\.lock\.stale\.\d$/u.test(n));
  if (used.length >= MAX_STALE_LOCK_QUARANTINE_FILES) {
    throw failure("HOST_STALE_LOCK_QUARANTINE_BOUND_EXCEEDED", op, "QUARANTINE_BOUND", S, "NOT_COMMITTED");
  }
  let slot = 0;
  while (used.includes(`staging.lock.stale.${slot}`)) slot += 1;
  const destination = path.join(ctx.staleDir, `staging.lock.stale.${slot}`);

  let before;
  try {
    before = fs.lstatSync(ctx.lockPath);
  } catch {
    throw failure("HOST_STALE_LOCK_QUARANTINE_FAILED", op, "QUARANTINE_PROBE", S, "NOT_COMMITTED");
  }

  let confirm;
  try {
    confirm = fs.lstatSync(ctx.lockPath);
  } catch {
    throw failure("HOST_STALE_LOCK_QUARANTINE_FAILED", op, "QUARANTINE_PRE_RENAME", S, "NOT_COMMITTED");
  }
  if (confirm.dev !== before.dev || confirm.ino !== before.ino) {
    throw failure("HOST_STALE_LOCK_QUARANTINE_FAILED", op, "QUARANTINE_PRE_RENAME", S, "NOT_COMMITTED");
  }

  try {
    fs.renameSync(ctx.lockPath, destination);
  } catch {
    throw failure("HOST_STALE_LOCK_QUARANTINE_FAILED", op, "QUARANTINE_RENAME", S, "NOT_COMMITTED");
  }

  // Destination-first fsync ordering: the reverse risks a durable removal from
  // the source without a durable addition at the destination, which is data
  // loss. That ordering was withdrawn by authoritative correction (D37).
  try {
    fsyncDirectory(
      ctx,
      ctx.staleDir,
      "STALE_LOCK_QUARANTINE_DIRECTORY",
      "QUARANTINE_DEST_DIR",
      "INDETERMINATE",
      "HOST_STALE_LOCK_QUARANTINE_INDETERMINATE"
    );
  } catch (error) {
    poison(ctx);
    throw error;
  }

  try {
    fsyncDirectorySource(ctx);
  } catch (error) {
    poison(ctx);
    throw error;
  }
}

function fsyncDirectorySource(ctx) {
  const op = ctx.op;
  const subject = "STAGING_DIRECTORY";
  let fd;
  try {
    fd = fs.openSync(ctx.stagingDir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    throw failure("HOST_STALE_LOCK_QUARANTINE_INDETERMINATE", op, "QUARANTINE_SOURCE_DIR_OPEN", subject, "INDETERMINATE");
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      throw failure(
        "HOST_STALE_LOCK_QUARANTINE_INDETERMINATE",
        op,
        "QUARANTINE_SOURCE_DIR_VALIDATE",
        subject,
        "INDETERMINATE"
      );
    }
    if (!isOwnedDirectory(dstat)) {
      throw failure(
        "HOST_STALE_LOCK_QUARANTINE_INDETERMINATE",
        op,
        "QUARANTINE_SOURCE_DIR_VALIDATE",
        subject,
        "INDETERMINATE"
      );
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      throw failure(
        "HOST_STALE_LOCK_QUARANTINE_INDETERMINATE",
        op,
        "QUARANTINE_SOURCE_DIR_FSYNC",
        subject,
        "INDETERMINATE"
      );
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // Both directory fsyncs already succeeded, so the quarantine move is
      // durable at both ends: the move is COMMITTED and only the descriptor
      // is in doubt (DC2).
      throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "QUARANTINE_SOURCE_DIR_CLOSE", subject, "COMMITTED");
    }
  }
}

// ---------------------------------------------------------------------------
// Post-create lock cleanup — 1.56-1.61 (SM5)
// ---------------------------------------------------------------------------
function cleanupCreatedLock(ctx, openFd, antecedent, foreignIsAntecedent) {
  const op = ctx.op;
  const S = "LOCK_FILE";
  const primary = antecedent && antecedent.code ? antecedent.code : null;

  if (openFd !== null && openFd !== undefined) {
    try {
      fs.closeSync(openFd);
    } catch {
      // Descriptor disposition is left unasserted; it is never retried or
      // reused. The cleanup continues, since the lock file still exists.
    }
  }

  // Never unlink a file whose identity was not verified as owned. If the
  // owned identity was never established -- including a post-create
  // validation failure -- no unlink is attempted by path at all.
  if (!ctx.lockIdentity) {
    // Ownership was never established, so nothing may be unlinked by path and
    // the removal outcome is genuinely indeterminate.
    poison(ctx);
    throw failure(
      "HOST_LOCK_ACQUISITION_INDETERMINATE", op, "LOCK_CLEANUP_PROBE", S, "INDETERMINATE", primary
    );
  }
  let probe;
  try {
    probe = fs.lstatSync(ctx.lockPath);
  } catch {
    poison(ctx);
    throw failure("HOST_LOCK_ACQUISITION_INDETERMINATE", op, "LOCK_CLEANUP_PROBE", S, "INDETERMINATE", primary);
  }
  if (probe.dev !== ctx.lockIdentity.dev || probe.ino !== ctx.lockIdentity.ino) {
    // The occupant is foreign. It is left byte-identical and untouched, and no
    // later cleanup step is entered. The antecedent stands on its own.
    if (foreignIsAntecedent) return;
    poison(ctx);
    throw failure("HOST_LOCK_ACQUISITION_INDETERMINATE", op, "LOCK_CLEANUP_PROBE", S, "INDETERMINATE", primary);
  }

  try {
    fs.unlinkSync(ctx.lockPath);
  } catch {
    poison(ctx);
    throw failure("HOST_LOCK_ACQUISITION_INDETERMINATE", op, "LOCK_CLEANUP_UNLINK", S, "INDETERMINATE", primary);
  }

  let fd;
  try {
    fd = fs.openSync(ctx.stagingDir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    poison(ctx);
    throw failure(
      "HOST_LOCK_ACQUISITION_INDETERMINATE",
      op,
      "LOCK_CLEANUP_DIR_OPEN",
      "STAGING_DIRECTORY",
      "INDETERMINATE",
      primary
    );
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      poison(ctx);
      throw failure(
        "HOST_LOCK_ACQUISITION_INDETERMINATE",
        op,
        "LOCK_CLEANUP_DIR_VALIDATE",
        "STAGING_DIRECTORY",
        "INDETERMINATE",
        primary
      );
    }
    if (!isOwnedDirectory(dstat)) {
      poison(ctx);
      throw failure(
        "HOST_LOCK_ACQUISITION_INDETERMINATE",
        op,
        "LOCK_CLEANUP_DIR_VALIDATE",
        "STAGING_DIRECTORY",
        "INDETERMINATE",
        primary
      );
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      poison(ctx);
      throw failure(
        "HOST_LOCK_ACQUISITION_INDETERMINATE",
        op,
        "LOCK_CLEANUP_DIR_FSYNC",
        "STAGING_DIRECTORY",
        "INDETERMINATE",
        primary
      );
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // The cleanup unlink and its directory fsync both already succeeded, so
      // the removal is durable and only the descriptor leaked. This is a
      // promoted top-level code rather than a DC5 silent preservation.
      POISONED_ROOTS.add(ctx.registryKey);
      throw failure(
        "HOST_CLEANUP_DESCRIPTOR_LEAKED",
        op,
        "LOCK_CLEANUP_DIR_CLOSE",
        "STAGING_DIRECTORY",
        "NOT_COMMITTED",
        primary
      );
    }
  }
}

// Poison marks the module-private registry and the host's internal state
// only. No public property is ever added to the host object. When code is one
// of the finalized-authority contradiction literals (D1), the registry is also
// poisoned before the throw via failFinalized().
function poison(ctx) {
  POISONED_ROOTS.add(ctx.registryKey);
  if (ctx.state) ctx.state.poisoned = true;
}

function obligationFinalPath(ctx) {
  return path.join(ctx.stagingDir, OBLIGATION_FINAL_NAME);
}

function obligationTempPath(ctx) {
  return path.join(ctx.stagingDir, OBLIGATION_TEMP_NAME);
}

function populatedSlotCount(journal) {
  let count = 0;
  if (!journal || !journal.manifest) return 0;
  for (const slot of ["0", "1", "2"]) {
    if (journal.manifest[slot] !== null) count += 1;
  }
  return count;
}

function freezeRestartReport(outcome, corruptionCode, journal, finalizedProfile, obligation, credentialOutcome) {
  return Object.freeze({
    outcome,
    corruptionCode,
    journal,
    finalizedProfile,
    credentialObligation: obligation === undefined ? null : obligation,
    credentialOutcome: credentialOutcome || "ABSENT"
  });
}

function serializeObligationRecord(ctx, op, record) {
  const projection = Object.create(null);
  const keys = [
    "schemaVersion", "formatProvenance", "intentId", "genesisDeploymentIntentHash",
    "ceremonyVersion", "role", "credentialGeneration", "ceremonyId",
    "ceremonyExpiresAtUnixSeconds", "genesisEnrollmentCeremonyHash", "state",
    "credentialIdHash", "publicVerificationMaterialHash", "createdAtUnixSeconds",
    "updatedAtUnixSeconds", "creationAuthorizedAtUnixSeconds", "orphanReason",
    "integrityChecksum"
  ];
  try {
    for (const key of keys) projection[key] = record[key];
    const bytes = Buffer.from(JSON.stringify(projection), "utf8");
    if (bytes.length > MAX_OBLIGATION_FILE_BYTES) {
      throw failure(
        "HOST_SERIALIZATION_REJECTED", op, "OBLIGATION_SERIALIZE",
        "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
      );
    }
    return bytes;
  } catch (error) {
    if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) throw error;
    throw failure(
      "HOST_SERIALIZATION_REJECTED", op, "OBLIGATION_SERIALIZE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
  }
}

function writeObligationOwnedTemp(ctx, op, bytes, state) {
  const S = "TEMP_FILE";
  const cs = "NOT_COMMITTED";
  const tempPath = obligationTempPath(ctx);
  let fd;
  try {
    fd = fs.openSync(tempPath, O.O_CREAT | O.O_EXCL | O.O_WRONLY | O.O_NOFOLLOW, 0o600);
  } catch (error) {
    if (error && error.code === "EEXIST") {
      failObligation(
        ctx, "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED", op, "OBLIGATION_TEMP_OPEN",
        S, "NOT_APPLICABLE"
      );
    }
    throw failure("HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", op, "OBLIGATION_TEMP_OPEN", S, cs);
  }
  try {
    let written = 0;
    while (written < bytes.length) {
      let n;
      try {
        n = fs.writeSync(fd, bytes, written, bytes.length - written, written);
      } catch {
        throw failure("HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", op, "OBLIGATION_TEMP_WRITE", S, cs);
      }
      if (n === 0) {
        throw failure("HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", op, "OBLIGATION_TEMP_WRITE", S, cs);
      }
      written += n;
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      throw failure("HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", op, "OBLIGATION_TEMP_FSYNC", S, cs);
    }
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* unasserted */ }
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  try {
    fs.closeSync(fd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "OBLIGATION_TEMP_CLOSE", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  let vfd;
  try {
    vfd = fs.openSync(tempPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    const error = failure("HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_TEMP_VERIFY_OPEN", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  try {
    let vstat;
    try {
      vstat = fs.fstatSync(vfd);
    } catch {
      throw failure("HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_TEMP_VERIFY_CLASSIFY", S, cs);
    }
    if (!isOwnedRegularFile(vstat) || vstat.size !== bytes.length) {
      failObligation(
        ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_TEMP_VERIFY_CLASSIFY", S, "NOT_APPLICABLE"
      );
    }
  } catch (error) {
    try { fs.closeSync(vfd); } catch { /* unasserted */ }
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  try {
    fs.closeSync(vfd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "OBLIGATION_TEMP_VERIFY_CLOSE", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
}

function probeObligationAbsence(ctx, op) {
  const finalPath = obligationFinalPath(ctx);
  try {
    fs.lstatSync(finalPath);
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_ALREADY_EXISTS", op, "OBLIGATION_CAS_PROBE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  } catch (error) {
    if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) throw error;
    if (!error || error.code !== "ENOENT") {
      throw failure(
        "HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_CAS_PROBE",
        "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
      );
    }
  }
}

function probeObligationIdentity(ctx, op, identity, commitState) {
  const finalPath = obligationFinalPath(ctx);
  const S = "CREDENTIAL_OBLIGATION_FILE";
  const cs = commitState || "NOT_COMMITTED";
  let stat;
  try {
    stat = fs.lstatSync(finalPath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw failure("HOST_DISK_STATE_CHANGED", op, "OBLIGATION_CAS_PROBE", S, cs);
    }
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_CAS_PROBE", S, cs);
  }
  if (!isOwnedRegularFile(stat)) {
    failObligation(ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CAS_CLASSIFY", S, "NOT_APPLICABLE");
  }
  if (identity && (stat.dev !== identity.dev || stat.ino !== identity.ino)) {
    throw failure("HOST_DISK_STATE_CHANGED", op, "OBLIGATION_CAS_IDENTITY_COMPARE", S, cs);
  }
}

function finishObligationPublication(ctx, op, state, record) {
  const tempPath = obligationTempPath(ctx);
  const finalPath = obligationFinalPath(ctx);
  try {
    fs.renameSync(tempPath, finalPath);
  } catch {
    const error = failure(
      "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", op, "OBLIGATION_RENAME",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
    cleanupOwnedTemp(ctx, op, tempPath, error, state, "NOT_COMMITTED");
    throw error;
  }
  directoryDurability(ctx, op, "OBLIGATION_PARENT_DIR", "STAGING_DIRECTORY", {
    indeterminateCode: "HOST_CREDENTIAL_OBLIGATION_DURABILITY_INDETERMINATE",
    indeterminateCommitState: "INDETERMINATE",
    closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
    closeCommitState: "COMMITTED",
    poisonOnIndeterminate: true,
    poisonOnClose: true
  });
  if (state.pendingNow !== undefined && state.pendingNow !== null) {
    state.lastSampledNowUnixSeconds = state.pendingNow;
    state.pendingNow = null;
  }
  state.obligation = record;
}

function publishObligation(ctx, state, op, record, previousIdentity) {
  const bytes = serializeObligationRecord(ctx, op, record);
  writeObligationOwnedTemp(ctx, op, bytes, state);
  try {
    if (previousIdentity) {
      probeObligationIdentity(ctx, op, previousIdentity);
    } else {
      probeObligationAbsence(ctx, op);
    }
  } catch (error) {
    cleanupOwnedTemp(ctx, op, obligationTempPath(ctx), error, state, "NOT_COMMITTED");
    throw error;
  }
  finishObligationPublication(ctx, op, state, record);
}

function unlinkObligationSidecar(
  ctx, state, op, commitState, indeterminateCommitState, failedCode, indeterminateCode, identity
) {
  const finalPath = obligationFinalPath(ctx);
  if (identity) {
    try {
      probeObligationIdentity(ctx, op, identity, commitState);
    } catch (error) {
      if (commitState === "MANIFEST_COMMITTED") {
        throw failure(
          failedCode, op, "OBLIGATION_CAS_IDENTITY_COMPARE",
          "CREDENTIAL_OBLIGATION_FILE", commitState
        );
      }
      throw error;
    }
  }
  try {
    fs.unlinkSync(finalPath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      state.obligation = null;
      return;
    }
    throw failure(failedCode, op, "OBLIGATION_UNLINK", "CREDENTIAL_OBLIGATION_FILE", commitState);
  }
  directoryDurability(ctx, op, "OBLIGATION_UNLINK_DIR", "STAGING_DIRECTORY", {
    indeterminateCode,
    indeterminateCommitState,
    closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
    closeCommitState: commitState === "MANIFEST_COMMITTED" ? "MANIFEST_COMMITTED" : "COMMITTED",
    poisonOnIndeterminate: true,
    poisonOnClose: true
  });
  state.obligation = null;
}

function readObligationFile(ctx, op, obligationPath) {
  const S = "CREDENTIAL_OBLIGATION_FILE";
  let fd;
  try {
    fd = fs.openSync(obligationPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_OPEN", S, "NOT_APPLICABLE");
  }
  try {
    let stat;
    try {
      stat = fs.fstatSync(fd);
    } catch {
      failObligation(ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY", S, "NOT_APPLICABLE");
    }
    if (!isOwnedRegularFile(stat)) {
      failObligation(ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY", S, "NOT_APPLICABLE");
    }
    const captured = snapshotSeven(stat);
    if (stat.size > MAX_OBLIGATION_FILE_BYTES) {
      return { oversized: true, bytes: null, identity: { dev: stat.dev, ino: stat.ino } };
    }
    const buffer = Buffer.allocUnsafe(stat.size);
    let read = 0;
    while (read < stat.size) {
      let n;
      try {
        n = fs.readSync(fd, buffer, read, stat.size - read, read);
      } catch {
        throw failure("HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_READ", S, "NOT_APPLICABLE");
      }
      if (n === 0) break;
      read += n;
    }
    let recheck;
    try {
      recheck = fs.fstatSync(fd);
    } catch {
      failObligation(ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_RECHECK", S, "NOT_APPLICABLE");
    }
    if (!sevenFieldEqual(snapshotSeven(recheck), captured)) {
      failObligation(ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_RECHECK", S, "NOT_APPLICABLE");
    }
    return { bytes: buffer.subarray(0, read), identity: { dev: stat.dev, ino: stat.ino } };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "OBLIGATION_CLOSE", S, "NOT_APPLICABLE");
    }
  }
}

function classifyObligationBytes(ctx, op, bytes) {
  if (bytes.length > MAX_OBLIGATION_FILE_BYTES) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_OVERSIZED", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  try {
    return obligationPure().validatePhilCoreV2GenesisCredentialObligationRecord(parsed);
  } catch (error) {
    if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) throw error;
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
}

function loadValidatedObligation(ctx, op) {
  const finalPath = obligationFinalPath(ctx);
  let probe;
  try {
    probe = fs.lstatSync(finalPath);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw failure(
      "HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_PROBE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  void probe;
  const read = readObligationFile(ctx, op, finalPath);
  if (read.oversized) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_OVERSIZED", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  const record = classifyObligationBytes(ctx, op, read.bytes);
  return { record, identity: read.identity };
}

function assertDurableObligationContext(ctx, op, sidecar, journal) {
  if (journal === null || journal === undefined) return;
  if (
    sidecar.intentId !== journal.intentId
    || sidecar.genesisDeploymentIntentHash !== journal.genesisDeploymentIntentHash
  ) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  if (BigInt(sidecar.ceremonyExpiresAtUnixSeconds) > BigInt(journal.expiresAt)) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
  const roleNumber = Number(sidecar.role);
  const entry = journal.manifest[sidecar.role];
  if (entry === null) {
    if (roleNumber !== populatedSlotCount(journal)) {
      failObligation(
        ctx, "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH", op, "OBLIGATION_CLASSIFY",
        "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
      );
    }
    return;
  }
  if (
    entry.ceremonyId !== sidecar.ceremonyId
    || entry.genesisEnrollmentCeremonyHash !== sidecar.genesisEnrollmentCeremonyHash
    || entry.ceremonyExpiresAtUnixSeconds !== sidecar.ceremonyExpiresAtUnixSeconds
    || entry.role !== sidecar.role
  ) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }
}

function manifestCredentialMatch(entry, sidecar) {
  return entry.descriptor.credentialIdHash === sidecar.credentialIdHash
    && entry.descriptor.publicVerificationMaterialHash === sidecar.publicVerificationMaterialHash;
}

function requireExpectedCeremonyIdString(value, expected, op) {
  if (typeof value !== "string" || value !== expected) {
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT",
      null, "NOT_APPLICABLE"
    );
  }
}

function readRecordCreatedInput(input, op) {
  if (!isObjectLike(input)) {
    throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
  }
  let keys;
  try {
    keys = Reflect.ownKeys(input);
  } catch {
    throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
  }
  for (const key of keys) {
    if (typeof key === "symbol" || !RECORD_CREATED_OWN_KEYS.includes(key)) {
      throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
    }
  }
  for (const key of RECORD_CREATED_OWN_KEYS) {
    if (!keys.includes(key)) {
      throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
    }
  }
  const snapshot = Object.create(null);
  for (const key of RECORD_CREATED_OWN_KEYS) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(input, key);
    } catch {
      throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
    }
    if (!descriptor) {
      throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
    }
    try {
      if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        snapshot[key] = descriptor.value;
      } else if (typeof descriptor.get === "function") {
        snapshot[key] = descriptor.get.call(input);
      } else {
        throw new Error();
      }
    } catch (error) {
      if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) throw error;
      throw failure("HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_INPUT", null, "NOT_APPLICABLE");
    }
  }
  return snapshot;
}

function verifyStagedManifestAgainstSidecar(ctx, op, current, updated, sidecar, role) {
  const roleKey = String(role);
  const previous = current.manifest[roleKey];
  const entry = updated.manifest[roleKey];
  if (previous !== null || entry === null) {
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_COMPARE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
  }
  if (sidecar.intentId !== updated.intentId || entry.role !== sidecar.role) {
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_COMPARE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
  }
  if (
    entry.ceremonyId !== sidecar.ceremonyId
    || entry.genesisEnrollmentCeremonyHash !== sidecar.genesisEnrollmentCeremonyHash
    || entry.ceremonyExpiresAtUnixSeconds !== sidecar.ceremonyExpiresAtUnixSeconds
  ) {
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_COMPARE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
  }
  if (!manifestCredentialMatch(entry, sidecar)) {
    throw failure(
      "HOST_CREDENTIAL_OBLIGATION_CREDENTIAL_MISMATCH", op, "OBLIGATION_COMPARE",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_COMMITTED"
    );
  }
}

function handleSidecarBeforeJournalTerminal(ctx, state, op, now) {
  const loaded = loadValidatedObligation(ctx, op);
  if (loaded === null) {
    state.obligation = null;
    return;
  }
  const sidecar = loaded.record;
  if (sidecar.state === "ACTIVE") {
    unlinkObligationSidecar(
      ctx, state, op, "NOT_COMMITTED", "INDETERMINATE",
      "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
      "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
      loaded.identity
    );
    return;
  }
  if (sidecar.state === "ORPHANED") {
    state.obligation = sidecar;
    return;
  }
  const sample = { value: now, threw: false };
  const orphaned = delegateWithClock(ctx, op, sample, (nowValue) =>
    obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
      current: sidecar,
      reason: "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION",
      nowUnixSeconds: nowValue
    })
  );
  checkRegression(ctx, state, op, sample);
  publishObligation(ctx, state, op, orphaned, loaded.identity);
}

function finishReconcile(ctx, state, op, now, report) {
  const loaded = (() => {
    try {
      return loadValidatedObligation(ctx, op);
    } catch (error) {
      throw error;
    }
  })();
  if (loaded === null) {
    state.obligation = null;
    return freezeRestartReport(
      report.outcome, report.corruptionCode, report.journal, report.finalizedProfile, null, "ABSENT"
    );
  }
  const sidecar = loaded.record;
  const journal = report.journal;
  assertDurableObligationContext(ctx, op, sidecar, journal);

  const journalState = journal === null ? "absent" : journal.state;
  const terminal = journal === null || journalState !== "STAGING";
  const entry = journal === null ? null : journal.manifest[sidecar.role];
  const occupied = entry !== null && entry !== undefined;

  if (sidecar.state === "ACTIVE" && !occupied && !terminal) {
    state.obligation = sidecar;
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, sidecar, "ACTIVE"
    );
  }
  if (sidecar.state === "ACTIVE" && !occupied && terminal) {
    unlinkObligationSidecar(
      ctx, state, op, "NOT_COMMITTED", "INDETERMINATE",
      "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
      "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
      loaded.identity
    );
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, null, "ABSENT"
    );
  }
  if (sidecar.state === "ACTIVE" && occupied) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY",
      "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
    );
  }

  if (
    (sidecar.state === "CREATION_AUTHORIZED" || sidecar.state === "CREDENTIAL_RECORDED")
    && !occupied
    && !terminal
  ) {
    const sample = { value: now, threw: false };
    const orphaned = delegateWithClock(ctx, op, sample, (nowValue) =>
      obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
        current: sidecar,
        reason: "RESTART_DURING_CREATION",
        nowUnixSeconds: nowValue
      })
    );
    checkRegression(ctx, state, op, sample, "NOT_APPLICABLE");
    publishObligation(ctx, state, op, orphaned, loaded.identity);
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, orphaned, "ORPHANED"
    );
  }
  if (
    (sidecar.state === "CREATION_AUTHORIZED" || sidecar.state === "CREDENTIAL_RECORDED")
    && !occupied
    && terminal
  ) {
    const sample = { value: now, threw: false };
    const orphaned = delegateWithClock(ctx, op, sample, (nowValue) =>
      obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
        current: sidecar,
        reason: "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION",
        nowUnixSeconds: nowValue
      })
    );
    checkRegression(ctx, state, op, sample, "NOT_APPLICABLE");
    publishObligation(ctx, state, op, orphaned, loaded.identity);
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, orphaned, "ORPHANED"
    );
  }

  if (sidecar.state === "CREDENTIAL_RECORDED" && occupied) {
    if (manifestCredentialMatch(entry, sidecar)) {
      unlinkObligationSidecar(
        ctx, state, op, "NOT_COMMITTED", "INDETERMINATE",
        "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
        "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
        loaded.identity
      );
      return freezeRestartReport(
        report.outcome, report.corruptionCode, journal, report.finalizedProfile, null, "CONSUMED_RECOVERED"
      );
    }
    const sample = { value: now, threw: false };
    const orphaned = delegateWithClock(ctx, op, sample, (nowValue) =>
      obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
        current: sidecar,
        reason: "RECORDED_CREDENTIAL_MISMATCH",
        nowUnixSeconds: nowValue
      })
    );
    checkRegression(ctx, state, op, sample, "NOT_APPLICABLE");
    publishObligation(ctx, state, op, orphaned, loaded.identity);
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, orphaned, "ORPHANED"
    );
  }

  if (sidecar.state === "ORPHANED" && sidecar.credentialIdHash !== null && occupied) {
    // RECORDED_CREDENTIAL_MISMATCH orphans must remain durably blocked even on exact hash match.
    if (
      manifestCredentialMatch(entry, sidecar)
      && sidecar.orphanReason !== "RECORDED_CREDENTIAL_MISMATCH"
    ) {
      unlinkObligationSidecar(
        ctx, state, op, "NOT_COMMITTED", "INDETERMINATE",
        "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
        "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
        loaded.identity
      );
      return freezeRestartReport(
        report.outcome, report.corruptionCode, journal, report.finalizedProfile, null, "CONSUMED_RECOVERED"
      );
    }
  }
  if (sidecar.state === "ORPHANED") {
    state.obligation = sidecar;
    return freezeRestartReport(
      report.outcome, report.corruptionCode, journal, report.finalizedProfile, sidecar, "ORPHANED"
    );
  }

  failObligation(
    ctx, "HOST_CREDENTIAL_OBLIGATION_INVALID", op, "OBLIGATION_CLASSIFY",
    "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
  );
}

// ---------------------------------------------------------------------------
// Host object — the 12 public methods
// ---------------------------------------------------------------------------
function makeHost(ctx) {
  const state = {
    poisoned: false,
    closed: false,
    reconciled: false,
    current: null,
    finalizedProfile: null,
    lastSampledNowUnixSeconds: null,
    obligation: null
  };
  ctx.state = state;

  const guard = (op, allowClosed) => {
    if (state.poisoned || POISONED_ROOTS.has(ctx.registryKey)) {
      throw failure("HOST_PROCESS_POISONED", op, "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
    }
    if (state.closed && !allowClosed) {
      throw failure("HOST_CLOSED", op, "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
    }
  };

  const requireReconciled = (op) => {
    if (!state.reconciled) {
      throw failure("HOST_RECONCILIATION_REQUIRED", op, "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
    }
  };

  const confirmLockIdentity = (op, commitState) => {
    let stat;
    try {
      stat = fs.lstatSync(ctx.lockPath);
    } catch {
      throw failure("HOST_LOCK_LOST_OR_REPLACED", op, "LOCK_IDENTITY", "LOCK_FILE", commitState);
    }
    if (stat.dev !== ctx.lockIdentity.dev || stat.ino !== ctx.lockIdentity.ino) {
      throw failure("HOST_LOCK_LOST_OR_REPLACED", op, "LOCK_IDENTITY", "LOCK_FILE", commitState);
    }
  };

  const host = {
    // --- Chain 2 ---------------------------------------------------------
    reconcileRestart() {
      const op = "reconcileRestart";
      ctx.op = op;
      guard(op, false);
      confirmLockIdentity(op, "NOT_APPLICABLE");

      const now = sampleClock(ctx, op, "CLOCK_SAMPLE", null, "NOT_APPLICABLE");

      const stagingEntries = enumerateBounded(
        ctx, ctx.stagingDir, "STAGING_DIRECTORY", MAX_STAGING_ENTRIES,
        "HOST_STAGING_SCAN_OVERFLOW", "NOT_APPLICABLE"
      );
      const { journals, temps: stagingTemps, obligationTemps } = classifyStagingDirectoryEntries(
        ctx, op, stagingEntries
      );

      enumerateBounded(
        ctx, ctx.corruptDir, "CORRUPT_QUARANTINE_DIRECTORY", MAX_QUARANTINE_ENTRIES,
        "HOST_QUARANTINE_SCAN_OVERFLOW", "NOT_APPLICABLE"
      );
      enumerateBounded(
        ctx, ctx.staleDir, "STALE_LOCK_QUARANTINE_DIRECTORY", MAX_QUARANTINE_ENTRIES,
        "HOST_QUARANTINE_SCAN_OVERFLOW", "NOT_APPLICABLE"
      );

      const finalizedEntries = enumerateBounded(
        ctx, ctx.finalizedDir, "FINALIZED_PROFILE_DIRECTORY", MAX_FINALIZED_ENTRIES,
        "HOST_FINALIZED_PROFILE_SCAN_OVERFLOW", "NOT_APPLICABLE", "FINALIZED_SCAN"
      );
      const { profiles, temps: finalizedTemps } = classifyFinalizedDirectoryEntries(
        ctx, op, finalizedEntries
      );

      let finalizedProfile = null;
      let finalizedInvalidCode = null;
      if (profiles.length === 1) {
        const profileName = profiles[0];
        const profilePath = path.join(ctx.finalizedDir, profileName);
        const read = readFinalizedProfileFile(ctx, op, profilePath);
        if (read.oversized) {
          finalizedInvalidCode = "HOST_FINALIZED_PROFILE_FILE_OVERSIZED";
        } else {
          const profileClassification = classifyFinalizedProfileBytes(read.bytes, profileName);
          if (profileClassification.corruptionCode !== null) {
            finalizedInvalidCode = profileClassification.corruptionCode;
          } else {
            finalizedProfile = profileClassification.record;
          }
        }
      }

      sweepOwnedTemps(ctx, op, ctx.stagingDir, stagingTemps, "TEMP_FILE", {
        prefix: "UNLINK_DIR",
        subject: "STAGING_DIRECTORY",
        options: {
          indeterminateCode: "HOST_TEMP_REMOVAL_INDETERMINATE",
          indeterminateCommitState: "INDETERMINATE",
          closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
          closeCommitState: "NOT_APPLICABLE",
          poisonOnIndeterminate: true
        }
      });
      sweepOwnedTemps(ctx, op, ctx.stagingDir, obligationTemps, "TEMP_FILE", {
        prefix: "UNLINK_DIR",
        subject: "STAGING_DIRECTORY",
        options: {
          indeterminateCode: "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
          indeterminateCommitState: "INDETERMINATE",
          closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
          closeCommitState: "NOT_APPLICABLE",
          poisonOnIndeterminate: true
        }
      });
      sweepOwnedTemps(ctx, op, ctx.finalizedDir, finalizedTemps, "FINALIZED_PROFILE_FILE", {
        prefix: "UNLINK_DIR",
        subject: "FINALIZED_PROFILE_DIRECTORY",
        options: {
          indeterminateCode: "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE",
          indeterminateCommitState: "INDETERMINATE",
          closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
          closeCommitState: "NOT_APPLICABLE",
          poisonOnIndeterminate: true
        }
      });

      if (finalizedProfile !== null || finalizedInvalidCode !== null) {
        let journalInfo;
        if (journals.length === 0) {
          journalInfo = { absent: true, journal: null, corruptCode: null };
        } else {
          const journalName = journals[0];
          const journalPath = path.join(ctx.stagingDir, journalName);
          const journalRead = readJournalFile(ctx, op, journalPath);
          if (journalRead.oversized) {
            journalInfo = { absent: false, journal: null, corruptCode: "HOST_JOURNAL_FILE_OVERSIZED" };
          } else {
            const journalClassification = classifyJournalBytes(journalRead.bytes, journalName);
            if (journalClassification.corruptionCode !== null) {
              journalInfo = {
                absent: false,
                journal: null,
                corruptCode: journalClassification.corruptionCode
              };
            } else {
              journalInfo = {
                absent: false,
                journal: journalClassification.record,
                corruptCode: null
              };
            }
          }
        }
        if (finalizedInvalidCode !== null) {
          failFinalizedInvalidWithJournalContext(ctx, op, finalizedInvalidCode, journalInfo);
        }
        return finishReconcile(
          ctx, state, op, now, resolveCombinedFinalJournalState(ctx, state, op, now, finalizedProfile, journalInfo)
        );
      }

      if (journals.length === 0) {
        state.reconciled = true;
        state.current = null;
        state.lastSampledNowUnixSeconds = now;
        return finishReconcile(ctx, state, op, now, {
          outcome: "NOTHING_TO_RECONCILE",
          corruptionCode: null,
          journal: null,
          finalizedProfile: null
        });
      }

      const journalName = journals[0];
      const journalPath = path.join(ctx.stagingDir, journalName);
      const read = readJournalFile(ctx, op, journalPath);

      const classification = read.oversized
        ? { corruptionCode: "HOST_JOURNAL_FILE_OVERSIZED", record: null }
        : classifyJournalBytes(read.bytes, journalName);
      if (classification.corruptionCode !== null) {
        quarantineCorruptJournal(ctx, op, journalPath, journalName, classification.corruptionCode);
        state.reconciled = true;
        state.current = null;
        state.lastSampledNowUnixSeconds = now;
        return finishReconcile(ctx, state, op, now, {
          outcome: "QUARANTINED_CORRUPT",
          corruptionCode: classification.corruptionCode,
          journal: null,
          finalizedProfile: null
        });
      }

      const validated = classification.record;

      if (validated.state === "SUPERSEDED") {
        failFinalized(
          ctx, "HOST_FINALIZED_PROFILE_MISSING_AFTER_SUPERSESSION", op, "FINALIZED_RECOVERY_MATCH",
          "FINALIZED_PROFILE_FILE", "SUPERSESSION_INDETERMINATE"
        );
      }

      if (validated.state === "STAGING" && BigInt(now) >= BigInt(validated.expiresAt)) {
        handleSidecarBeforeJournalTerminal(ctx, state, op, now);
        const updated = delegate(() => pure().expireGenesisStagingJournalIfNeeded(validated, now));
        publishRecord(ctx, op, journalName, updated, validated);
        state.reconciled = true;
        state.current = updated;
        state.lastSampledNowUnixSeconds = now;
        return finishReconcile(ctx, state, op, now, {
          outcome: "EXPIRED_ON_RECOVERY",
          corruptionCode: null,
          journal: updated,
          finalizedProfile: null
        });
      }

      state.reconciled = true;
      state.current = validated;
      state.lastSampledNowUnixSeconds = now;
      return finishReconcile(ctx, state, op, now, {
        outcome: "ACTIVE",
        corruptionCode: null,
        journal: validated,
        finalizedProfile: null
      });
    },

    // --- Chain 3 ---------------------------------------------------------
    createJournal(intent) {
      const op = "createJournal";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      rejectIfFinalizedProfileCommitted(state, op);

      // 3.05 — an in-memory current record forbids creation outright.
      if (state.current !== null) {
        throw failure("HOST_JOURNAL_ALREADY_EXISTS", op, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
      }

      // 3.06-3.10 — a fresh bounded disk scan, since memory is not authoritative.
      const preScan = enumerateBounded(
        ctx, ctx.stagingDir, "STAGING_DIRECTORY", MAX_STAGING_ENTRIES,
        "HOST_STAGING_SCAN_OVERFLOW", "NOT_APPLICABLE"
      );
      if (preScan.some((n) => JOURNAL_NAME_RE.test(n))) {
        throw failure("HOST_JOURNAL_ALREADY_EXISTS", op, "JOURNAL_PRECONDITION_DISK_SCAN", "JOURNAL_FILE", "NOT_APPLICABLE");
      }

      // 3.11-3.12 — sample, then delegate, then compare for regression.
      const sample = drawClockSample(ctx);
      const record = delegateWithClock(ctx, op, sample, (nowValue) =>
        buildRecord(ctx, op, intent, nowValue)
      );
      checkRegression(ctx, state, op, sample);

      // 3.13 — serialization, strictly before any temp exists.
      const bytes = serializeRecord(ctx, op, record);

      const journalName = journalNameFor(record);
      const tempName = `.${journalName}.tmp`;
      const tempPath = path.join(ctx.stagingDir, tempName);
      const journalPath = path.join(ctx.stagingDir, journalName);

      writeOwnedTemp(ctx, op, tempPath, bytes, state);

      // 3.22-3.28 — createJournal's final CAS is a fresh grammar scan plus an
      // absence probe; there is no initial CAS because nothing exists to read.
      let scan;
      try {
        scan = enumerateBounded(
          ctx, ctx.stagingDir, "STAGING_DIRECTORY", MAX_STAGING_ENTRIES,
          "HOST_STAGING_SCAN_OVERFLOW", "NOT_COMMITTED", "CAS_CREATE_SCAN"
        );
      } catch (error) {
        cleanupOwnedTemp(ctx, op, tempPath, error, state);
        throw error;
      }
      if (scan.some((n) => JOURNAL_NAME_RE.test(n))) {
        const error = failure("HOST_DISK_STATE_CHANGED", op, "CAS_CREATE_SCAN_MATCH", "JOURNAL_FILE", "NOT_COMMITTED");
        cleanupOwnedTemp(ctx, op, tempPath, error, state);
        throw error;
      }
      try {
        fs.lstatSync(journalPath);
        throw failure("HOST_DISK_STATE_CHANGED", op, "CAS_CREATE_ABSENCE", "JOURNAL_FILE", "NOT_COMMITTED");
      } catch (error) {
        if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) {
          cleanupOwnedTemp(ctx, op, tempPath, error, state);
          throw error;
        }
        if (!error || error.code !== "ENOENT") {
          const wrapped = failure("HOST_FILESYSTEM_READ_FAILED", op, "CAS_CREATE_ABSENCE", "JOURNAL_FILE", "NOT_COMMITTED");
          cleanupOwnedTemp(ctx, op, tempPath, wrapped, state);
          throw wrapped;
        }
      }

      finishPublication(ctx, op, tempPath, journalPath, state, record);
      state.current = record;
      return Object.freeze({ journal: record });
    },

    // --- Chain 4 ---------------------------------------------------------
    stageRole(role, roleInput) {
      const op = "stageRole";
      ctx.op = op;
      return mutateExistingJournal(ctx, state, op, { role, roleInput }, {
        notFoundCode: "HOST_JOURNAL_NOT_FOUND",
        inactiveCode: "HOST_JOURNAL_NOT_ACTIVE",
        requireRecordedObligation: true,
        afterDelegate: (current, updated, input, loaded) => {
          if (updated.state !== "STAGING") {
            const orphaned = obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
              current: loaded.record,
              reason: "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION",
              nowUnixSeconds: Number(updated.updatedAtUnixSeconds)
            });
            publishObligation(ctx, state, op, orphaned, loaded.identity);
            return;
          }
          verifyStagedManifestAgainstSidecar(ctx, op, current, updated, loaded.record, input.role);
        },
        afterCommit: (updated, loaded) => {
          if (updated.state !== "STAGING") return;
          unlinkObligationSidecar(
            ctx, state, op, "MANIFEST_COMMITTED", "OBLIGATION_RETIREMENT_INDETERMINATE",
            "HOST_CREDENTIAL_OBLIGATION_RETIREMENT_FAILED",
            "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
            loaded.identity
          );
        },
        transform: (current, value, now) => delegateStageRole(ctx, op, current, value, now)
      });
    },

    // --- Chain 5 ---------------------------------------------------------
    cancel() {
      const op = "cancel";
      ctx.op = op;
      return mutateExistingJournal(ctx, state, op, undefined, {
        notFoundCode: "HOST_JOURNAL_NOT_FOUND",
        inactiveCode: "HOST_JOURNAL_NOT_ACTIVE",
        beforeDelegate: (_current, now) => {
          handleSidecarBeforeJournalTerminal(ctx, state, op, now);
        },
        transform: (current, value, now) => delegateCancel(ctx, op, current, now)
      });
    },

    beginCredentialObligation(ceremonyRecord) {
      const op = "beginCredentialObligation";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      rejectIfFinalizedProfileCommitted(state, op);

      const current = state.current;
      if (current === null || current.state !== "STAGING") {
        throw failure("HOST_JOURNAL_NOT_FOUND", op, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
      }
      if (populatedSlotCount(current) >= 3) {
        throw failure("HOST_JOURNAL_NOT_ACTIVE", op, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
      }
      let tempProbe = false;
      try {
        fs.lstatSync(obligationTempPath(ctx));
        tempProbe = true;
      } catch (error) {
        if (!error || error.code !== "ENOENT") {
          throw failure(
            "HOST_FILESYSTEM_READ_FAILED", op, "OBLIGATION_PROBE",
            "TEMP_FILE", "NOT_APPLICABLE"
          );
        }
      }
      if (loadValidatedObligation(ctx, op) !== null || tempProbe) {
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_ALREADY_EXISTS", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }

      const sample = drawClockSample(ctx);
      const record = delegateWithClock(ctx, op, sample, (nowValue) => {
        if (BigInt(nowValue) >= BigInt(current.expiresAt)) {
          throw failure(
            "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_CONTEXT",
            "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
          );
        }
        const created = obligationPure().createPhilCoreV2GenesisCredentialObligation({
          ceremony: ceremonyRecord,
          intentId: current.intentId,
          nowUnixSeconds: nowValue
        });
        if (
          created.genesisDeploymentIntentHash !== current.genesisDeploymentIntentHash
          || created.role !== String(populatedSlotCount(current))
          || BigInt(created.ceremonyExpiresAtUnixSeconds) > BigInt(current.expiresAt)
        ) {
          throw failure(
            "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH", op, "OBLIGATION_CONTEXT",
            "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
          );
        }
        return created;
      });
      checkRegression(ctx, state, op, sample);
      publishObligation(ctx, state, op, record, null);
      return Object.freeze({ journal: current, obligation: record });
    },

    authorizeCredentialCreation(expectedCeremonyId) {
      const op = "authorizeCredentialCreation";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      rejectIfFinalizedProfileCommitted(state, op);
      if (state.current === null || state.current.state !== "STAGING") {
        throw failure("HOST_JOURNAL_NOT_FOUND", op, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
      }
      const loaded = loadValidatedObligation(ctx, op);
      if (loaded === null) {
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      if (loaded.record.state === "ORPHANED") {
        state.obligation = loaded.record;
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_ORPHANED", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      requireExpectedCeremonyIdString(expectedCeremonyId, loaded.record.ceremonyId, op);
      const sample = drawClockSample(ctx);
      const updated = delegateWithClock(ctx, op, sample, (nowValue) =>
        obligationPure().authorizePhilCoreV2GenesisCredentialCreation({
          current: loaded.record,
          expectedCeremonyId,
          nowUnixSeconds: nowValue
        })
      );
      checkRegression(ctx, state, op, sample);
      publishObligation(ctx, state, op, updated, loaded.identity);
      return Object.freeze({ journal: state.current, obligation: updated });
    },

    recordCreatedCredential(input) {
      const op = "recordCreatedCredential";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      rejectIfFinalizedProfileCommitted(state, op);
      const loaded = loadValidatedObligation(ctx, op);
      if (loaded === null) {
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      if (loaded.record.state === "ORPHANED") {
        state.obligation = loaded.record;
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_ORPHANED", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      const snapshot = readRecordCreatedInput(input, op);
      const sample = drawClockSample(ctx);
      const updated = delegateWithClock(ctx, op, sample, (nowValue) =>
        obligationPure().recordPhilCoreV2GenesisCreatedCredential({
          current: loaded.record,
          expectedCeremonyId: snapshot.expectedCeremonyId,
          credentialIdHash: snapshot.credentialIdHash,
          publicVerificationMaterialHash: snapshot.publicVerificationMaterialHash,
          nowUnixSeconds: nowValue
        })
      );
      checkRegression(ctx, state, op, sample);
      publishObligation(ctx, state, op, updated, loaded.identity);
      return Object.freeze({ journal: state.current, obligation: updated });
    },

    cancelCredentialObligation(expectedCeremonyId) {
      const op = "cancelCredentialObligation";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      const loaded = loadValidatedObligation(ctx, op);
      if (loaded === null) {
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      requireExpectedCeremonyIdString(expectedCeremonyId, loaded.record.ceremonyId, op);
      if (loaded.record.state === "ORPHANED") {
        state.obligation = loaded.record;
        return Object.freeze({ journal: state.current, obligation: loaded.record });
      }
      if (loaded.record.state === "ACTIVE") {
        unlinkObligationSidecar(
          ctx, state, op, "NOT_COMMITTED", "INDETERMINATE",
          "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
          "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
          loaded.identity
        );
        return Object.freeze({ journal: state.current, obligation: null });
      }
      const sample = drawClockSample(ctx);
      const orphaned = delegateWithClock(ctx, op, sample, (nowValue) =>
        obligationPure().orphanPhilCoreV2GenesisCredentialObligation({
          current: loaded.record,
          reason: "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION",
          nowUnixSeconds: nowValue
        })
      );
      checkRegression(ctx, state, op, sample);
      publishObligation(ctx, state, op, orphaned, loaded.identity);
      return Object.freeze({ journal: state.current, obligation: orphaned });
    },

    // --- Chain 6 ---------------------------------------------------------
    status() {
      const op = "status";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");
      if (state.finalizedProfile !== null) {
        return Object.freeze({ state: "FINALIZED", credentialObligation: state.obligation });
      }
      return Object.freeze({
        state: state.current === null ? "ABSENT" : state.current.state,
        credentialObligation: state.obligation
      });
    },

    // --- Chain 7 ---------------------------------------------------------
    acknowledgeTerminal(input) {
      const op = "acknowledgeTerminal";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");

      // 7.05-7.10 — acknowledgment input validation, hostile-value safe.
      if (!isObjectLike(input)) {
        throw failure("HOST_ACKNOWLEDGMENT_INPUT_NOT_OBJECT", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
      }
      let ackKeys;
      try {
        ackKeys = Reflect.ownKeys(input);
      } catch {
        throw failure("HOST_ACKNOWLEDGMENT_ENUMERATION_FAILED", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
      }
      for (const key of ackKeys) {
        if (typeof key === "symbol" || !ACK_OWN_KEYS.includes(key)) {
          throw failure("HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
        }
      }
      for (const key of ACK_OWN_KEYS) {
        if (!ackKeys.includes(key)) {
          throw failure("HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
        }
      }
      const ack = {};
      for (const key of ACK_OWN_KEYS) {
        try {
          ack[key] = Reflect.get(input, key);
        } catch {
          throw failure("HOST_ACKNOWLEDGMENT_READ_FAILED", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
        }
      }
      if (typeof ack.intentId !== "string" || typeof ack.integrityChecksum !== "string") {
        throw failure("HOST_ACKNOWLEDGMENT_INPUT_INVALID", op, "ACK_INPUT_VALIDATION", null, "NOT_APPLICABLE");
      }

      // 7.11-7.12 — the record must exist and must be terminal.
      const current = state.current;
      if (current === null) {
        throw failure("HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED", op, "ACK_PRECONDITION", null, "NOT_APPLICABLE");
      }
      if (state.obligation !== null || loadValidatedObligation(ctx, op) !== null) {
        throw failure(
          state.obligation && state.obligation.state === "ORPHANED"
            ? "HOST_CREDENTIAL_OBLIGATION_ORPHANED"
            : "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID",
          op, "ACK_PRECONDITION", "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }
      if (current.state === "STAGING") {
        throw failure("HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED", op, "ACK_PRECONDITION_NON_TERMINAL", null, "NOT_APPLICABLE");
      }

      // 7.13-7.14 — identity and checksum must match the retained record.
      if (ack.intentId !== current.intentId) {
        throw failure("HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH", op, "ACK_IDENTITY_MATCH", "JOURNAL_FILE", "NOT_APPLICABLE");
      }
      if (ack.integrityChecksum !== current.integrityChecksum) {
        throw failure("HOST_ACKNOWLEDGMENT_CHECKSUM_MISMATCH", op, "ACK_IDENTITY_MATCH", "JOURNAL_FILE", "NOT_APPLICABLE");
      }

      // 7.15-7.26 — full initial CAS, then final CAS, then removal.
      const journalName = journalNameFor(current);
      const journalPath = path.join(ctx.stagingDir, journalName);
      const initial = casInitial(ctx, op, journalPath, current, "NOT_COMMITTED");
      casFinal(ctx, op, journalPath, initial.identity, "NOT_COMMITTED");

      // 7.27-7.31 — unlink the acknowledged journal and make it durable.
      try {
        fs.unlinkSync(journalPath);
      } catch {
        throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "UNLINK", "JOURNAL_FILE", "NOT_COMMITTED");
      }
      directoryDurability(ctx, op, "UNLINK_DIR", "STAGING_DIRECTORY", {
        indeterminateCode: "HOST_JOURNAL_REMOVAL_INDETERMINATE",
        indeterminateCommitState: "INDETERMINATE",
        closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
        closeCommitState: "COMMITTED",
        poisonOnIndeterminate: true,
        poisonOnClose: true
      });

      state.current = null;
      return Object.freeze({ acknowledged: true });
    },

    // --- Chain 8 ---------------------------------------------------------
    finalizeProfile(expectedValidationResult) {
      const op = "finalizeProfile";
      ctx.op = op;
      guard(op, false);
      requireReconciled(op);
      confirmLockIdentity(op, "NOT_APPLICABLE");

      if (state.obligation !== null || loadValidatedObligation(ctx, op) !== null) {
        throw failure(
          "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID", op, "OBLIGATION_PRECONDITION",
          "CREDENTIAL_OBLIGATION_FILE", "NOT_APPLICABLE"
        );
      }

      const diskFinal = loadFinalizedProfileForFinalize(ctx, op, expectedValidationResult);

      if (diskFinal !== null) {
        if (state.finalizedProfile === null) {
          commitFinalizedProfileState(
            state, diskFinal, Number(diskFinal.finalizedAtUnixSeconds)
          );
        }

        const current = state.current;
        if (current === null) {
          return Object.freeze({
            outcome: "ALREADY_FINALIZED",
            finalizedProfile: diskFinal,
            journal: null
          });
        }
        if (current.state === "SUPERSEDED") {
          if (!validateSupersededMatches(current, diskFinal)) {
            failFinalized(
              ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
              "PROFILE_COMMITTED", null
            );
          }
          return Object.freeze({
            outcome: "ALREADY_FINALIZED",
            finalizedProfile: diskFinal,
            journal: current
          });
        }
        if (current.state === "STAGING") {
          if (!recordsCanonicallyEqual(current, diskFinal.sourceJournal)) {
            failFinalized(
              ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
              "PROFILE_COMMITTED", null
            );
          }
          const nowValue = sampleClock(ctx, op, "CLOCK_SAMPLE", null, "PROFILE_COMMITTED");
          const superseded = performSupersession(ctx, state, op, nowValue, diskFinal, current);
          state.current = superseded;
          return Object.freeze({
            outcome: "FINALIZED",
            finalizedProfile: diskFinal,
            journal: superseded
          });
        }
        failFinalized(
          ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
          "PROFILE_COMMITTED", null
        );
      }

      rejectIfFinalizedProfileCommitted(state, op);

      const current = state.current;
      if (current === null || current.state !== "STAGING") {
        throw failure("HOST_JOURNAL_NOT_FOUND", op, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
      }

      const journalName = journalNameFor(current);
      const journalPath = path.join(ctx.stagingDir, journalName);
      const initial = casInitial(
        ctx, op, journalPath, current, "NOT_COMMITTED", "FINALIZED_SOURCE_CAS_INITIAL"
      );

      const sample = drawClockSample(ctx);
      const finalizedRecord = delegateWithClock(ctx, op, sample, (nowValue) =>
        delegate(() =>
          finalizedPure().createGenesisFinalizedProfileRecord(current, expectedValidationResult, nowValue)
        )
      );
      checkRegression(ctx, state, op, sample);

      const bytes = serializeFinalizedRecord(ctx, op, finalizedRecord);
      const finalName = finalizedProfileNameFor(finalizedRecord);
      const tempName = `.${finalName}.tmp`;
      const tempPath = path.join(ctx.finalizedDir, tempName);
      const finalPath = path.join(ctx.finalizedDir, finalName);

      writeFinalizedOwnedTemp(ctx, op, tempPath, bytes, state);

      try {
        casFinal(
          ctx, op, journalPath, initial.identity, "NOT_COMMITTED", "FINALIZED_SOURCE_CAS_FINAL"
        );
      } catch (error) {
        cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
        throw error;
      }

      try {
        probeFinalDestinationAbsence(ctx, op, finalPath, "NOT_COMMITTED");
      } catch (error) {
        cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
        throw error;
      }

      finishFinalizedPublication(ctx, op, tempPath, finalPath, state, finalizedRecord, sample.value);

      const superseded = performSupersession(ctx, state, op, sample.value, finalizedRecord, current);
      state.current = superseded;

      return Object.freeze({
        outcome: "FINALIZED",
        finalizedProfile: finalizedRecord,
        journal: superseded
      });
    },

    // --- Chain 9 ---------------------------------------------------------
    close() {
      const op = "close";
      ctx.op = op;
      if (state.closed) return;
      releaseLock(ctx, state);
      state.closed = true;
    }
  };

  ctx.host = host;
  return host;
}

// ---------------------------------------------------------------------------
// Lock release — Chain 8
// ---------------------------------------------------------------------------
function releaseLock(ctx, state) {
  const op = "close";
  const S = "LOCK_FILE";

  let probe;
  try {
    probe = fs.lstatSync(ctx.lockPath);
  } catch (error) {
    POISONED_ROOTS.add(ctx.registryKey);
    state.poisoned = true;
    if (error && error.code === "ENOENT") {
      throw failure("HOST_LOCK_LOST_OR_REPLACED", op, "LOCK_RELEASE_PROBE", S, "NOT_COMMITTED");
    }
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, "LOCK_RELEASE_PROBE", S, "NOT_COMMITTED");
  }

  // Only the single already-captured path-based lstat result is read; no
  // additional filesystem call is made for classification.
  if (probe.isSymbolicLink() || probe.isFIFO() || probe.isDirectory() || probe.nlink !== 1) {
    POISONED_ROOTS.add(ctx.registryKey);
    state.poisoned = true;
    throw failure("HOST_LOCK_DESCRIPTOR_INVALID", op, "LOCK_RELEASE_PROBE", S, "NOT_COMMITTED");
  }
  if (probe.dev !== ctx.lockIdentity.dev || probe.ino !== ctx.lockIdentity.ino) {
    POISONED_ROOTS.add(ctx.registryKey);
    state.poisoned = true;
    throw failure("HOST_LOCK_LOST_OR_REPLACED", op, "LOCK_RELEASE_PROBE", S, "NOT_COMMITTED");
  }

  try {
    fs.unlinkSync(ctx.lockPath);
  } catch {
    POISONED_ROOTS.add(ctx.registryKey);
    state.poisoned = true;
    throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "LOCK_RELEASE_UNLINK", S, "NOT_COMMITTED");
  }

  let fd;
  try {
    fd = fs.openSync(ctx.stagingDir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    POISONED_ROOTS.add(ctx.registryKey);
    state.poisoned = true;
    throw failure("HOST_LOCK_RELEASE_INDETERMINATE", op, "LOCK_RELEASE_DIR_OPEN", "STAGING_DIRECTORY", "INDETERMINATE");
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      POISONED_ROOTS.add(ctx.registryKey);
      state.poisoned = true;
      throw failure(
        "HOST_LOCK_RELEASE_INDETERMINATE",
        op,
        "LOCK_RELEASE_DIR_VALIDATE",
        "STAGING_DIRECTORY",
        "INDETERMINATE"
      );
    }
    if (!isOwnedDirectory(dstat)) {
      POISONED_ROOTS.add(ctx.registryKey);
      state.poisoned = true;
      throw failure(
        "HOST_LOCK_RELEASE_INDETERMINATE",
        op,
        "LOCK_RELEASE_DIR_VALIDATE",
        "STAGING_DIRECTORY",
        "INDETERMINATE"
      );
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      // A failed shared-directory fsync proves neither that this removal
      // completed nor that it did not, and says nothing about any other
      // pending namespace change in the same directory. No re-probe is made
      // and no retry is attempted.
      POISONED_ROOTS.add(ctx.registryKey);
      state.poisoned = true;
      throw failure(
        "HOST_LOCK_RELEASE_INDETERMINATE",
        op,
        "LOCK_RELEASE_DIR_FSYNC",
        "STAGING_DIRECTORY",
        "INDETERMINATE"
      );
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // The unlink and the directory fsync both succeeded, so the release is
      // durably COMMITTED and only the descriptor is in doubt (DC2).
      POISONED_ROOTS.add(ctx.registryKey);
      state.poisoned = true;
      throw failure(
        "HOST_DESCRIPTOR_CLOSE_FAILED",
        op,
        "LOCK_RELEASE_DIR_CLOSE",
        "STAGING_DIRECTORY",
        "COMMITTED"
      );
    }
  }
}

// ---------------------------------------------------------------------------
// 5B-0.4 delegation boundary
// ---------------------------------------------------------------------------
// The pure genesis staging journal module is loaded lazily so that requiring
// this host performs no work and pulls in no loader until an operation that
// actually needs record construction runs.
let pureModule = null;
function pure() {
  if (pureModule === null) {
    require("tsx/cjs");
    pureModule = require("../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts");
  }
  return pureModule;
}

let finalizedPureModule = null;
function finalizedPure() {
  if (finalizedPureModule === null) {
    require("tsx/cjs");
    finalizedPureModule = require(
      "../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisFinalizedProfile.ts"
    );
  }
  return finalizedPureModule;
}

let obligationPureModule = null;
function obligationPure() {
  if (obligationPureModule === null) {
    require("tsx/cjs");
    obligationPureModule = require(
      "../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
    );
  }
  return obligationPureModule;
}

// A genuine 5B-0.4 error is rethrown as the exact same object, identity
// preserved, never wrapped or converted into a host error.
function delegate(fn) {
  return fn();
}

function buildRecord(ctx, op, intent, now) {
  return delegate(() => pure().createGenesisStagingJournal(intent, now));
}
// The host passes the caller's declared role and candidate straight through to
// the pure module, which owns all candidate validation.
function delegateStageRole(ctx, op, current, call, now) {
  return delegate(() => pure().stageGenesisRoleCandidate(current, call.role, call.roleInput, now));
}
function delegateCancel(ctx, op, current, now) {
  return delegate(() => pure().cancelGenesisStagingJournal(current, now));
}

function journalNameFor(record) {
  return `ceremony_${String(record.ceremonyId || record.intentId || "").replace(/^0x/u, "")}.v1.json`;
}

function finalizedProfileNameFor(record) {
  const hash = String(record.genesisDeploymentIntentHash).replace(/^0x/u, "");
  return `profile_${hash}.v1.json`;
}

const FINALIZED_RECORD_KEYS = Object.freeze([
  "schemaVersion", "formatProvenance", "state", "intentId",
  "genesisDeploymentIntentHash", "sourceJournalIntegrityChecksum",
  "finalizedAtUnixSeconds", "sourceJournal", "validationResult", "integrityChecksum"
]);
const FINALIZED_RESULT_KEYS = Object.freeze([
  "genesisDeploymentIntentHash", "genesisEnrollmentCeremonyHashes", "profile"
]);
const FINALIZED_PROFILE_RESULT_KEYS = Object.freeze([
  "profile", "descriptors", "commitments", "recoveryConfigurationHash",
  "independenceAssurance", "warnings"
]);

function projectFinalizedValidationResult(value) {
  const result = projectContainer(value, FINALIZED_RESULT_KEYS, (key, leaf) => {
    if (key === "genesisEnrollmentCeremonyHashes") {
      return projectTuple(leaf, ["0", "1", "2"], (_k, v) => requireLeafString(v));
    }
    if (key === "profile") {
      return projectContainer(leaf, FINALIZED_PROFILE_RESULT_KEYS, (pKey, pLeaf) => {
        if (pKey === "descriptors") {
          return projectTuple(pLeaf, ["0", "1", "2"], (_k, slot) =>
            projectFactor(slot, DESCRIPTOR_KEYS)
          );
        }
        if (pKey === "commitments") {
          return projectTuple(pLeaf, ["0", "1", "2"], (_k, v) => requireLeafString(v));
        }
        if (pKey === "warnings") {
          if (pLeaf === null || typeof pLeaf !== "object" || !Array.isArray(pLeaf)) {
            throw new SerializationRejected();
          }
          return pLeaf.map((w) => requireLeafString(w));
        }
        return requireLeafString(pLeaf);
      });
    }
    return requireLeafString(leaf);
  });
  return result;
}

function projectFinalizedRecord(record) {
  return projectContainer(record, FINALIZED_RECORD_KEYS, (key, leaf) => {
    if (key === "schemaVersion") {
      if (typeof leaf !== "number") throw new SerializationRejected();
      return leaf;
    }
    if (key === "sourceJournal") return projectRecord(leaf);
    if (key === "validationResult") return projectFinalizedValidationResult(leaf);
    return requireLeafString(leaf);
  });
}

function canonicalFinalizedBytes(record) {
  const projection = projectFinalizedRecord(record);
  return Buffer.from(JSON.stringify(projection), "utf8");
}

function serializeFinalizedRecord(ctx, op, record) {
  let bytes;
  try {
    bytes = canonicalFinalizedBytes(record);
  } catch {
    throw failure(
      "HOST_SERIALIZATION_REJECTED", op, "FINALIZED_SERIALIZE", "FINALIZED_PROFILE_FILE", "NOT_COMMITTED"
    );
  }
  if (bytes.length > MAX_FINALIZED_PROFILE_FILE_BYTES) {
    throw failure(
      "HOST_SERIALIZATION_REJECTED", op, "FINALIZED_SERIALIZE", "FINALIZED_PROFILE_FILE", "NOT_COMMITTED"
    );
  }
  return bytes;
}

function recordsCanonicallyEqual(a, b) {
  try {
    return canonicalBytes(a).equals(canonicalBytes(b));
  } catch {
    return false;
  }
}

function readFinalizedProfileFile(ctx, op, profilePath) {
  const S = "FINALIZED_PROFILE_FILE";
  let fd;
  try {
    fd = fs.openSync(profilePath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, "FINALIZED_READ_OPEN", S, "NOT_APPLICABLE");
  }
  try {
    let stat;
    try {
      stat = fs.fstatSync(fd);
    } catch {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op,
        "FINALIZED_READ_CLASSIFY", S, "SUPERSESSION_INDETERMINATE"
      );
    }
    if (!isOwnedRegularFile(stat)) {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op,
        "FINALIZED_READ_CLASSIFY", S, "SUPERSESSION_INDETERMINATE"
      );
    }
    const captured = snapshotSeven(stat);
    if (stat.size > MAX_FINALIZED_PROFILE_FILE_BYTES) {
      return { oversized: true, bytes: null, identity: { dev: stat.dev, ino: stat.ino } };
    }
    const buffer = Buffer.allocUnsafe(stat.size);
    let read = 0;
    while (read < stat.size) {
      let n;
      try {
        n = fs.readSync(fd, buffer, read, stat.size - read, read);
      } catch {
        throw failure("HOST_FILESYSTEM_READ_FAILED", op, "FINALIZED_READ", S, "NOT_APPLICABLE");
      }
      if (n === 0) break;
      read += n;
    }
    let recheck;
    try {
      recheck = fs.fstatSync(fd);
    } catch {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op,
        "FINALIZED_READ_RECHECK", S, "SUPERSESSION_INDETERMINATE"
      );
    }
    if (!sevenFieldEqual(snapshotSeven(recheck), captured)) {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op,
        "FINALIZED_READ_RECHECK", S, "SUPERSESSION_INDETERMINATE"
      );
    }
    return { bytes: buffer.subarray(0, read), identity: { dev: stat.dev, ino: stat.ino } };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "FINALIZED_READ_CLOSE", S, "NOT_APPLICABLE");
    }
  }
}

function classifyFinalizedProfileStructure(bytes, profileName) {
  if (bytes.length === 0) return { corruptionCode: "HOST_FINALIZED_PROFILE_EMPTY", parsed: null };
  if (bytes.length > MAX_FINALIZED_PROFILE_FILE_BYTES) {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_FILE_OVERSIZED", parsed: null };
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_UTF8_INVALID", parsed: null };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_UTF8_INVALID", parsed: null };
  }
  if (text.charCodeAt(0) === 0xfeff) return { corruptionCode: "HOST_FINALIZED_PROFILE_UTF8_INVALID", parsed: null };

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_JSON_INVALID", parsed: null };
  }
  if (!isObjectLike(parsed) || Array.isArray(parsed)) {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID", parsed: null };
  }

  let canonical;
  try {
    canonical = canonicalFinalizedBytes(parsed);
  } catch {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID", parsed: null };
  }
  if (!canonical.equals(bytes)) return { corruptionCode: "HOST_FINALIZED_PROFILE_NONCANONICAL", parsed: null };

  const nameMatch = profileName.match(FINALIZED_PROFILE_NAME_RE);
  const fileHash = nameMatch ? nameMatch[1] : null;
  const recordHash = typeof parsed.genesisDeploymentIntentHash === "string"
    ? parsed.genesisDeploymentIntentHash.replace(/^0x/u, "")
    : null;
  if (fileHash === null || recordHash === null || fileHash !== recordHash) {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_FILENAME_ID_MISMATCH", parsed: null };
  }
  return { corruptionCode: null, parsed };
}

function classifyFinalizedProfileBytes(bytes, profileName) {
  const structure = classifyFinalizedProfileStructure(bytes, profileName);
  if (structure.corruptionCode !== null) {
    return { corruptionCode: structure.corruptionCode, record: null };
  }
  let validated;
  try {
    validated = finalizedPure().validateGenesisFinalizedProfileRecord(structure.parsed);
  } catch {
    return { corruptionCode: "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID", record: null };
  }
  return { corruptionCode: null, record: validated };
}

function classifyStagingDirectoryEntries(ctx, op, entries) {
  const journals = [];
  const temps = [];
  const obligations = [];
  const obligationTemps = [];
  for (const name of entries) {
    if (name === "." || name === ".." || name === LOCK_BASENAME) continue;
    if (name === CORRUPT_QUARANTINE || name === STALE_LOCK_QUARANTINE) continue;
    if (JOURNAL_NAME_RE.test(name)) { journals.push(name); continue; }
    if (TEMP_NAME_RE.test(name)) { temps.push(name); continue; }
    if (name === OBLIGATION_FINAL_NAME) { obligations.push(name); continue; }
    if (name === OBLIGATION_TEMP_NAME) { obligationTemps.push(name); continue; }
    if (typeof name === "string" && name.startsWith(OBLIGATION_NAME_PREFIX)) {
      failObligation(
        ctx, "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY", op, "ENTRY_CLASSIFY",
        "STAGING_DIRECTORY", "NOT_APPLICABLE"
      );
    }
    throw failure("HOST_UNEXPECTED_STAGING_ENTRY", op, "ENTRY_CLASSIFY", "STAGING_DIRECTORY", "NOT_APPLICABLE");
  }
  if (journals.length > 1) {
    throw failure("HOST_MULTIPLE_JOURNALS_FOUND", op, "ENTRY_CLASSIFY", "STAGING_DIRECTORY", "NOT_APPLICABLE");
  }
  if (temps.length > MAX_RECONCILIATION_TEMP_SWEEP) {
    throw failure("HOST_TEMP_FILE_BOUND_EXCEEDED", op, "ENTRY_CLASSIFY", "TEMP_FILE", "NOT_APPLICABLE");
  }
  if (obligationTemps.length > 1) {
    failObligation(
      ctx, "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED", op, "ENTRY_CLASSIFY",
      "TEMP_FILE", "NOT_APPLICABLE"
    );
  }
  return { journals, temps, obligations, obligationTemps };
}

function classifyFinalizedDirectoryEntries(ctx, op, entries) {
  const profiles = [];
  const temps = [];
  for (const name of entries) {
    if (name === "." || name === "..") continue;
    if (FINALIZED_PROFILE_NAME_RE.test(name)) { profiles.push(name); continue; }
    if (FINALIZED_TEMP_NAME_RE.test(name)) { temps.push(name); continue; }
    failFinalized(
      ctx, "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY", op, "FINALIZED_ENTRY_CLASSIFY",
      "FINALIZED_PROFILE_DIRECTORY", "NOT_APPLICABLE"
    );
  }
  if (profiles.length > 1) {
    failFinalized(
      ctx, "HOST_MULTIPLE_FINALIZED_PROFILES_FOUND", op, "FINALIZED_ENTRY_CLASSIFY",
      "FINALIZED_PROFILE_DIRECTORY", "NOT_APPLICABLE"
    );
  }
  if (temps.length > MAX_FINALIZED_RECONCILIATION_TEMP_SWEEP) {
    throw failure(
      "HOST_FINALIZED_PROFILE_SCAN_OVERFLOW", op, "FINALIZED_ENTRY_CLASSIFY",
      "FINALIZED_PROFILE_DIRECTORY", "NOT_APPLICABLE"
    );
  }
  return { profiles, temps };
}

function sweepOwnedTemps(ctx, op, dir, temps, subject, unlinkOpts) {
  for (const name of temps) {
    const tempPath = path.join(dir, name);
    let tstat;
    try {
      tstat = fs.lstatSync(tempPath);
    } catch {
      const code = subject === "FINALIZED_PROFILE_FILE"
        ? "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID"
        : "HOST_JOURNAL_DESCRIPTOR_INVALID";
      const commit = subject === "FINALIZED_PROFILE_FILE"
        ? "SUPERSESSION_INDETERMINATE"
        : "NOT_APPLICABLE";
      if (subject === "FINALIZED_PROFILE_FILE") {
        failFinalized(ctx, code, op, "FINALIZED_ENTRY_CLASSIFY", subject, commit);
      }
      throw failure(code, op, "ENTRY_CLASSIFY", subject, commit);
    }
    if (!isOwnedRegularFile(tstat)) {
      const code = subject === "FINALIZED_PROFILE_FILE"
        ? "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID"
        : "HOST_JOURNAL_DESCRIPTOR_INVALID";
      const commit = subject === "FINALIZED_PROFILE_FILE"
        ? "SUPERSESSION_INDETERMINATE"
        : "NOT_APPLICABLE";
      if (subject === "FINALIZED_PROFILE_FILE") {
        failFinalized(ctx, code, op, "FINALIZED_ENTRY_CLASSIFY", subject, commit);
      }
      throw failure(code, op, "ENTRY_CLASSIFY", subject, commit);
    }
    try {
      fs.unlinkSync(tempPath);
    } catch {
      throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "UNLINK", subject, "NOT_COMMITTED");
    }
    directoryDurability(ctx, op, unlinkOpts.prefix, unlinkOpts.subject, unlinkOpts.options, dir);
  }
}

function validateSupersededMatches(live, finalizedProfile) {
  if (live.state !== "SUPERSEDED" || live.endReason !== "SUPERSEDED") return false;
  const source = finalizedProfile.sourceJournal;
  const liveUpdated = BigInt(live.updatedAtUnixSeconds);
  const sourceUpdated = BigInt(source.updatedAtUnixSeconds);
  if (liveUpdated < 1n || liveUpdated < sourceUpdated) return false;
  const derived = delegate(() =>
    pure().supersedeGenesisStagingJournal(source, Number(live.updatedAtUnixSeconds))
  );
  return recordsCanonicallyEqual(derived, live);
}

function guardSupersessionClock(ctx, op, now, finalizedProfile) {
  const sourceUpdatedAt = Number(finalizedProfile.sourceJournal.updatedAtUnixSeconds);
  if (now < sourceUpdatedAt) {
    throw failure(
      "HOST_FINALIZED_PROFILE_SUPERSESSION_CLOCK_REGRESSION",
      op, "FINALIZED_RECOVERY_CLOCK", "JOURNAL_FILE", "PROFILE_COMMITTED"
    );
  }
}

function performSupersession(ctx, state, op, now, finalizedProfile, currentJournal) {
  guardSupersessionClock(ctx, op, now, finalizedProfile);
  if (
    state.lastSampledNowUnixSeconds !== null &&
    now < state.lastSampledNowUnixSeconds
  ) {
    throw failure("HOST_CLOCK_REGRESSION_DETECTED", op, "CLOCK_TRACKING", null, "PROFILE_COMMITTED");
  }
  const superseded = delegate(() =>
    pure().supersedeGenesisStagingJournal(finalizedProfile.sourceJournal, now)
  );
  publishRecord(ctx, op, journalNameFor(currentJournal), superseded, currentJournal, "PROFILE_COMMITTED");
  return superseded;
}

function commitFinalizedProfileState(state, finalizedProfile, now) {
  state.finalizedProfile = finalizedProfile;
  if (state.pendingNow !== undefined && state.pendingNow !== null) {
    state.lastSampledNowUnixSeconds = state.pendingNow;
    state.pendingNow = null;
  } else {
    state.lastSampledNowUnixSeconds = now;
  }
}

function failFinalizedInvalidWithJournalContext(ctx, op, finalizedInvalidCode, journalInfo) {
  if (journalInfo.corruptCode !== null) {
    failFinalized(
      ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
      "SUPERSESSION_INDETERMINATE", journalInfo.corruptCode
    );
  }
  if (journalInfo.journal !== null && journalInfo.journal.state === "SUPERSEDED") {
    failFinalized(
      ctx, "HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION", op, "FINALIZED_RECOVERY_MATCH",
      "FINALIZED_PROFILE_FILE", "SUPERSESSION_INDETERMINATE", null
    );
  }
  failFinalized(
    ctx, finalizedInvalidCode, op, "FINALIZED_VALIDATE", "FINALIZED_PROFILE_FILE",
    "SUPERSESSION_INDETERMINATE", null
  );
}

function resolveCombinedFinalJournalState(ctx, state, op, now, finalizedProfile, journalInfo) {
  if (journalInfo.corruptCode !== null) {
    failFinalized(
      ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
      "SUPERSESSION_INDETERMINATE", journalInfo.corruptCode
    );
  }

  if (journalInfo.absent) {
    state.reconciled = true;
    state.finalizedProfile = finalizedProfile;
    state.current = null;
    state.lastSampledNowUnixSeconds = now;
    return Object.freeze({
      outcome: "FINALIZED",
      corruptionCode: null,
      journal: null,
      finalizedProfile
    });
  }

  const live = journalInfo.journal;

  if (live.state === "STAGING") {
    if (!recordsCanonicallyEqual(live, finalizedProfile.sourceJournal)) {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
        "PROFILE_COMMITTED", null
      );
    }
    const superseded = performSupersession(ctx, state, op, now, finalizedProfile, live);
    state.reconciled = true;
    state.finalizedProfile = finalizedProfile;
    state.current = superseded;
    state.lastSampledNowUnixSeconds = now;
    return Object.freeze({
      outcome: "RECOVERED_FINALIZED_AND_SUPERSEDED",
      corruptionCode: null,
      journal: superseded,
      finalizedProfile
    });
  }

  if (live.state === "SUPERSEDED") {
    if (!validateSupersededMatches(live, finalizedProfile)) {
      failFinalized(
        ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
        "PROFILE_COMMITTED", null
      );
    }
    state.reconciled = true;
    state.finalizedProfile = finalizedProfile;
    state.current = live;
    state.lastSampledNowUnixSeconds = now;
    return Object.freeze({
      outcome: "FINALIZED",
      corruptionCode: null,
      journal: live,
      finalizedProfile
    });
  }

  failFinalized(
    ctx, "HOST_FINALIZED_PROFILE_CONFLICT", op, "FINALIZED_RECOVERY_MATCH", "JOURNAL_FILE",
    "PROFILE_COMMITTED", null
  );
}

function probeFinalDestinationAbsence(ctx, op, finalPath, commitState) {
  const S = "FINALIZED_PROFILE_FILE";
  try {
    fs.lstatSync(finalPath);
    throw failure("HOST_DISK_STATE_CHANGED", op, "FINALIZED_DESTINATION_ABSENCE", S, commitState);
  } catch (error) {
    if (error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError) throw error;
    if (!error || error.code !== "ENOENT") {
      throw failure("HOST_FILESYSTEM_READ_FAILED", op, "FINALIZED_DESTINATION_ABSENCE", S, commitState);
    }
  }
}

function writeFinalizedOwnedTemp(ctx, op, tempPath, bytes, state) {
  const S = "FINALIZED_PROFILE_FILE";
  let fd;
  try {
    fd = fs.openSync(tempPath, O.O_CREAT | O.O_EXCL | O.O_WRONLY | O.O_NOFOLLOW, 0o600);
  } catch (error) {
    if (error && error.code === "EEXIST") {
      throw failure("HOST_FINALIZED_PROFILE_TEMP_BOUND_EXCEEDED", op, "FINALIZED_TEMP_OPEN", S, "NOT_COMMITTED");
    }
    throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "FINALIZED_TEMP_OPEN", S, "NOT_COMMITTED");
  }

  try {
    let written = 0;
    while (written < bytes.length) {
      let n;
      try {
        n = fs.writeSync(fd, bytes, written, bytes.length - written, written);
      } catch {
        throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "FINALIZED_TEMP_WRITE", S, "NOT_COMMITTED");
      }
      if (n === 0) throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "FINALIZED_TEMP_WRITE", S, "NOT_COMMITTED");
      written += n;
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      throw failure("HOST_DURABILITY_WRITE_FAILED", op, "FINALIZED_TEMP_FSYNC", S, "NOT_COMMITTED");
    }
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* unasserted */ }
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }

  try {
    fs.closeSync(fd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "FINALIZED_TEMP_CLOSE", S, "NOT_COMMITTED");
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }

  let vfd;
  try {
    vfd = fs.openSync(tempPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    const error = failure("HOST_FILESYSTEM_READ_FAILED", op, "FINALIZED_TEMP_VERIFY_OPEN", S, "NOT_COMMITTED");
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }
  try {
    let vstat;
    try {
      vstat = fs.fstatSync(vfd);
    } catch {
      throw failure("HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op, "FINALIZED_TEMP_VERIFY_CLASSIFY", S, "NOT_COMMITTED");
    }
    if (!isOwnedRegularFile(vstat) || vstat.size !== bytes.length) {
      throw failure("HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", op, "FINALIZED_TEMP_VERIFY_CLASSIFY", S, "NOT_COMMITTED");
    }
  } catch (error) {
    try { fs.closeSync(vfd); } catch { /* unasserted */ }
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }
  try {
    fs.closeSync(vfd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "FINALIZED_TEMP_VERIFY_CLOSE", S, "NOT_COMMITTED");
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }
}

function cleanupFinalizedOwnedTemp(ctx, op, tempPath, antecedent, state) {
  const primary = antecedent && antecedent.code ? antecedent.code : null;
  const poisonNow = () => {
    POISONED_ROOTS.add(ctx.registryKey);
    if (state) state.poisoned = true;
  };

  try {
    fs.unlinkSync(tempPath);
  } catch {
    poisonNow();
    throw failure(
      "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", op, "FINALIZED_TEMP_CLEANUP_UNLINK",
      "FINALIZED_PROFILE_FILE", "INDETERMINATE", primary
    );
  }

  let fd;
  try {
    fd = fs.openSync(ctx.finalizedDir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    poisonNow();
    throw failure(
      "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", op, "FINALIZED_TEMP_CLEANUP_DIR_OPEN",
      "FINALIZED_PROFILE_DIRECTORY", "INDETERMINATE", primary
    );
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      poisonNow();
      throw failure(
        "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", op, "FINALIZED_TEMP_CLEANUP_DIR_VALIDATE",
        "FINALIZED_PROFILE_DIRECTORY", "INDETERMINATE", primary
      );
    }
    if (!isOwnedDirectory(dstat)) {
      poisonNow();
      throw failure(
        "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", op, "FINALIZED_TEMP_CLEANUP_DIR_VALIDATE",
        "FINALIZED_PROFILE_DIRECTORY", "INDETERMINATE", primary
      );
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      poisonNow();
      throw failure(
        "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", op, "FINALIZED_TEMP_CLEANUP_DIR_FSYNC",
        "FINALIZED_PROFILE_DIRECTORY", "INDETERMINATE", primary
      );
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      poisonNow();
      throw failure(
        "HOST_CLEANUP_DESCRIPTOR_LEAKED", op, "FINALIZED_TEMP_CLEANUP_DIR_CLOSE",
        "FINALIZED_PROFILE_DIRECTORY", "NOT_COMMITTED", primary
      );
    }
  }
}

function finishFinalizedPublication(ctx, op, tempPath, finalPath, state, record, now) {
  try {
    fs.renameSync(tempPath, finalPath);
  } catch {
    const error = failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "FINALIZED_RENAME", "FINALIZED_PROFILE_FILE", "NOT_COMMITTED");
    cleanupFinalizedOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }

  directoryDurability(ctx, op, "FINALIZED_PARENT_DIR", "FINALIZED_PROFILE_DIRECTORY", {
    indeterminateCode: "HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE",
    indeterminateCommitState: "INDETERMINATE",
    closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
    closeCommitState: "COMMITTED",
    poisonOnIndeterminate: true,
    poisonOnClose: true
  }, ctx.finalizedDir);

  commitFinalizedProfileState(state, record, now);
  void now;
}

function loadFinalizedProfileForFinalize(ctx, op, expectedValidationResult) {
  const entries = enumerateBounded(
    ctx, ctx.finalizedDir, "FINALIZED_PROFILE_DIRECTORY", MAX_FINALIZED_ENTRIES,
    "HOST_FINALIZED_PROFILE_SCAN_OVERFLOW", "NOT_APPLICABLE", "FINALIZED_SCAN"
  );
  const { profiles } = classifyFinalizedDirectoryEntries(ctx, op, entries);
  if (profiles.length === 0) return null;

  const profileName = profiles[0];
  const profilePath = path.join(ctx.finalizedDir, profileName);
  const read = readFinalizedProfileFile(ctx, op, profilePath);
  if (read.oversized) {
    failFinalized(
      ctx, "HOST_FINALIZED_PROFILE_FILE_OVERSIZED", op, "FINALIZED_VALIDATE",
      "FINALIZED_PROFILE_FILE", "SUPERSESSION_INDETERMINATE"
    );
  }
  const structure = classifyFinalizedProfileStructure(read.bytes, profileName);
  if (structure.corruptionCode !== null) {
    failFinalized(
      ctx, structure.corruptionCode, op, "FINALIZED_VALIDATE",
      "FINALIZED_PROFILE_FILE", "SUPERSESSION_INDETERMINATE"
    );
  }

  let validated;
  try {
    validated = finalizedPure().validateGenesisFinalizedProfileRecord(structure.parsed);
  } catch {
    failFinalized(
      ctx, "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID", op,
      "FINALIZED_VALIDATE", "FINALIZED_PROFILE_FILE",
      "SUPERSESSION_INDETERMINATE"
    );
  }
  const checksumWithExpected = delegate(() =>
    finalizedPure().computeGenesisFinalizedProfileChecksum({
      schemaVersion: validated.schemaVersion,
      formatProvenance: validated.formatProvenance,
      state: validated.state,
      intentId: validated.intentId,
      genesisDeploymentIntentHash: validated.genesisDeploymentIntentHash,
      sourceJournalIntegrityChecksum: validated.sourceJournalIntegrityChecksum,
      finalizedAtUnixSeconds: validated.finalizedAtUnixSeconds,
      sourceJournal: validated.sourceJournal,
      validationResult: expectedValidationResult
    })
  );
  if (checksumWithExpected !== validated.integrityChecksum) {
    const pure = finalizedPure();
    throw new pure.PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError(
      pure.PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE
        .FINALIZED_PROFILE_RESULT_MISMATCH
    );
  }
  return validated;
}

// The five ordered key arrays of the accepted serializer contract
// (33 + 3 + 9 + 16 + 10 = 71 slots).
const INTENT_KEYS = Object.freeze([
  "intentVersion", "intentId", "chainId", "entryPoint", "factoryBinding",
  "confirmationTarget", "verifier", "verifierRuntimeCodeHash",
  "accountCreationBytecodeHash", "accountVersionId", "securityModelId",
  "recoveryDomainId", "ownerCommitment", "identityBindingCommitment",
  "initialValidator", "validatorVerifierKind", "validatorKeyIdBinding",
  "validatorCommitment", "validatorEpoch", "recoveryEpoch",
  "recoveryDelaySeconds", "recoveryExpirySeconds", "userSalt", "expiresAt"
]);
const JOURNAL_KEYS = Object.freeze([
  "schemaVersion", "formatProvenance", ...INTENT_KEYS,
  "genesisDeploymentIntentHash", "state", "createdAtUnixSeconds",
  "updatedAtUnixSeconds", "manifest", "endReason", "integrityChecksum"
]);
const MANIFEST_SLOT_KEYS = Object.freeze(["0", "1", "2"]);
const MANIFEST_ENTRY_KEYS = Object.freeze([
  "role", "ceremonyId", "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash", "descriptor", "independence", "signer",
  "factorCommitment", "stagedAtUnixSeconds"
]);
const DESCRIPTOR_KEYS = Object.freeze([
  "descriptorVersion", "accountVersionId", "securityModelId",
  "recoveryDomainId", "role", "verifierKind", "publicVerificationMaterialHash",
  "credentialIdHash", "rpIdHash", "originPolicyHash", "independenceBindingHash",
  "userVerificationPolicy", "backupPolicy", "authenticatorAttachmentPolicy",
  "attestationPolicy", "credentialGeneration"
]);
const INDEPENDENCE_KEYS = Object.freeze([
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialIdHash", "enrollmentCeremonyHash",
  "attestationEvidenceHash", "custodyDomainCommitment", "credentialGeneration"
]);

class SerializationRejected extends Error {}

// Projects one container level into a fresh null-prototype object.
// Reflect.ownKeys is guarded and called exactly once; only own data
// descriptors are accepted, so no accessor getter is ever invoked; the key set
// and its order are enforced exactly. Because every container is
// null-prototype and no caller-owned reference survives, JSON.stringify can
// find neither an own nor an inherited toJSON.
function projectContainer(source, keys, leafKind) {
  if (!isObjectLike(source) || Array.isArray(source)) throw new SerializationRejected();
  let own;
  try {
    own = Reflect.ownKeys(source);
  } catch {
    throw new SerializationRejected();
  }
  if (own.length !== keys.length) throw new SerializationRejected();
  for (let i = 0; i < keys.length; i += 1) {
    if (own[i] !== keys[i]) throw new SerializationRejected();
  }
  const out = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Reflect.getOwnPropertyDescriptor(source, key);
    } catch {
      throw new SerializationRejected();
    }
    if (!descriptor) throw new SerializationRejected();
    // An accessor own property is rejected outright, never invoked.
    if (!("value" in descriptor)) throw new SerializationRejected();
    out[key] = leafKind(key, descriptor.value);
  }
  return out;
}

function projectTuple(source, keys, leafKind) {
  if (!Array.isArray(source)) throw new SerializationRejected();
  if (source.length !== keys.length) throw new SerializationRejected();
  const out = [];
  for (let i = 0; i < keys.length; i += 1) {
    if (String(i) !== keys[i]) throw new SerializationRejected();
    out.push(leafKind(keys[i], source[i]));
  }
  return out;
}

function requireLeafString(value) {
  if (typeof value !== "string") throw new SerializationRejected();
  return value;
}
function requireLeafStringOrNull(value) {
  if (value !== null && typeof value !== "string") throw new SerializationRejected();
  return value;
}

function projectFactor(value, keys) {
  return projectContainer(value, keys, (_k, leaf) => requireLeafString(leaf));
}

function projectManifestEntry(value) {
  return projectContainer(value, MANIFEST_ENTRY_KEYS, (key, leaf) => {
    if (key === "descriptor") return projectFactor(leaf, DESCRIPTOR_KEYS);
    if (key === "independence") return projectFactor(leaf, INDEPENDENCE_KEYS);
    if (key === "signer") return requireLeafStringOrNull(leaf);
    return requireLeafString(leaf);
  });
}

function projectManifest(value) {
  return projectContainer(value, MANIFEST_SLOT_KEYS, (_k, leaf) =>
    leaf === null ? null : projectManifestEntry(leaf)
  );
}

function projectRecord(record) {
  return projectContainer(record, JOURNAL_KEYS, (key, leaf) => {
    if (key === "manifest") return projectManifest(leaf);
    if (key === "schemaVersion") {
      if (typeof leaf !== "number") throw new SerializationRejected();
      return leaf;
    }
    if (key === "endReason") return requireLeafStringOrNull(leaf);
    return requireLeafString(leaf);
  });
}

// Canonical bytes: compact, no BOM, no trailing newline.
function canonicalBytes(record) {
  const projection = projectRecord(record);
  return Buffer.from(JSON.stringify(projection), "utf8");
}

function serializeRecord(ctx, op, record, commitState) {
  const cs = commitState || "NOT_COMMITTED";
  let bytes;
  try {
    bytes = canonicalBytes(record);
  } catch {
    // No raw cause is retained at any rejection.
    throw failure("HOST_SERIALIZATION_REJECTED", op, "SERIALIZE", "JOURNAL_FILE", cs);
  }
  // The size comparator is an independent gate; passing it never by itself
  // implies the record is valid.
  if (bytes.length > JOURNAL_COMPARATOR_BOUNDARY) {
    throw failure("HOST_SERIALIZATION_REJECTED", op, "SERIALIZE", "JOURNAL_FILE", cs);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Pending live-clock commitment (SM12)
// ---------------------------------------------------------------------------
// The accepted order is: guards -> preconditions -> sample -> delegated pure
// operation -> regression comparison -> filesystem CAS/write.
//
// The sample is drawn opaquely. If nowFn throws, the thrown marker is
// discarded completely unread -- no property access, enumeration, coercion, or
// Proxy trap invocation -- and the accepted sentinel 0 is substituted. Only a
// boolean records that a throw occurred.
function drawClockSample(ctx) {
  try {
    return { value: ctx.nowFn(), threw: false };
  } catch {
    return { value: 0, threw: true };
  }
}

function isPureInvalidNow(error) {
  if (!Boolean(error)) return false;
  try {
    return error.code === "INVALID_NOW"
      || error.code === "STAGING_PROFILE_INVALID_NOW";
  } catch {
    return false;
  }
}

// Runs the delegated pure operation with the sampled value passed through
// unmodified. A genuine non-INVALID_NOW 5B-0.4 error outranks the host clock
// error and is rethrown as the exact same object, identity preserved. Only the
// host-invalid-clock outcome -- a thrown nowFn whose substituted sentinel makes
// the pure call fail with exactly INVALID_NOW -- maps to HOST_INVALID_NOW.
function delegateWithClock(ctx, op, sample, run) {
  try {
    return run(sample.value);
  } catch (error) {
    if (sample.threw && isPureInvalidNow(error)) {
      throw failure("HOST_INVALID_NOW", op, "CLOCK_SAMPLE", null, "NOT_COMMITTED");
    }
    throw error;
  }
}

// The regression comparison runs only after the delegated call has succeeded.
// Equality is accepted; only a strictly smaller sample regresses.
function checkRegression(ctx, state, op, sample, regressionCommitState) {
  const commitState = regressionCommitState || "NOT_COMMITTED";
  if (
    state.lastSampledNowUnixSeconds !== null &&
    sample.value < state.lastSampledNowUnixSeconds
  ) {
    throw failure("HOST_CLOCK_REGRESSION_DETECTED", op, "CLOCK_TRACKING", null, commitState);
  }
  state.pendingNow = sample.value;
}

// ---------------------------------------------------------------------------
// Directory durability with a caller-chosen phase family
// ---------------------------------------------------------------------------
function directoryDurability(ctx, op, prefix, subject, opts, targetDir) {
  const o = opts || {};
  const dir = targetDir || ctx.stagingDir;
  const failCode = o.indeterminateCode || "HOST_DURABILITY_INDETERMINATE";
  const failCommit = o.indeterminateCommitState || "INDETERMINATE";
  const primary = o.primaryCode || null;
  const mark = () => {
    if (o.poisonOnIndeterminate) {
      POISONED_ROOTS.add(ctx.registryKey);
      if (ctx.state) ctx.state.poisoned = true;
    }
  };

  let fd;
  try {
    fd = fs.openSync(dir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    mark();
    throw failure(failCode, op, `${prefix}_OPEN`, subject, failCommit, primary);
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      mark();
      throw failure(failCode, op, `${prefix}_VALIDATE`, subject, failCommit, primary);
    }
    if (!isOwnedDirectory(dstat)) {
      mark();
      throw failure(failCode, op, `${prefix}_VALIDATE`, subject, failCommit, primary);
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      // A failed shared-directory fsync proves neither completion nor
      // non-completion of this operation's own namespace change, and says
      // nothing about any other pending change in the same directory. No
      // re-probe is performed and no retry is attempted.
      mark();
      throw failure(failCode, op, `${prefix}_FSYNC`, subject, failCommit, primary);
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // The fsync already succeeded, so the namespace change is durable; only
      // the descriptor is in doubt. Its disposition is left unasserted and it
      // is never retried or reused.
      if (o.poisonOnClose) {
        POISONED_ROOTS.add(ctx.registryKey);
        if (ctx.state) ctx.state.poisoned = true;
      }
      throw failure(
        o.closeCode || "HOST_DESCRIPTOR_CLOSE_FAILED",
        op,
        `${prefix}_CLOSE`,
        subject,
        o.closeCommitState || "COMMITTED",
        o.closePrimaryCode || null
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Journal reading and classification
// ---------------------------------------------------------------------------
function readJournalFile(ctx, op, journalPath) {
  const S = "JOURNAL_FILE";
  let fd;
  try {
    fd = fs.openSync(journalPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, "JOURNAL_OPEN", S, "NOT_APPLICABLE");
  }
  try {
    let stat;
    try {
      stat = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "JOURNAL_CLASSIFY", S, "NOT_APPLICABLE");
    }
    if (!isOwnedRegularFile(stat)) {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "JOURNAL_CLASSIFY", S, "NOT_APPLICABLE");
    }
    const captured = snapshotSeven(stat);
    // JOURNAL_SIZE_PREFLIGHT — a declared size beyond the comparator is
    // classified here, before any buffer is allocated and before a single byte
    // is read, so an attacker-declared size can never drive allocation or I/O.
    if (stat.size > JOURNAL_COMPARATOR_BOUNDARY) {
      return { oversized: true, bytes: null, identity: { dev: stat.dev, ino: stat.ino } };
    }
    const buffer = Buffer.allocUnsafe(stat.size);
    let read = 0;
    while (read < stat.size) {
      let n;
      try {
        n = fs.readSync(fd, buffer, read, stat.size - read, read);
      } catch {
        throw failure("HOST_FILESYSTEM_READ_FAILED", op, "JOURNAL_READ", S, "NOT_APPLICABLE");
      }
      if (n === 0) break;
      read += n;
    }
    let recheck;
    try {
      recheck = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "JOURNAL_METADATA_RECHECK", S, "NOT_APPLICABLE");
    }
    if (!sevenFieldEqual(snapshotSeven(recheck), captured)) {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "JOURNAL_METADATA_RECHECK", S, "NOT_APPLICABLE");
    }
    const bytes = buffer.subarray(0, read);
    return { bytes, identity: { dev: stat.dev, ino: stat.ino } };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "JOURNAL_CLOSE", S, "NOT_APPLICABLE");
    }
  }
}

// Returns a closed two-shape object: either a corruption code with a null
// record, or a null code with the deep-frozen record the pure 5B-0.4 validator
// accepted. The classification order is unchanged: size preflight -> explicit
// fatal UTF-8 decode with BOM/whitespace rejection -> JSON.parse -> the pure
// 5B-0.4 stored-record validator -> canonical reserialization with exact
// raw-byte equality -> filename identity. No code is ever thrown as a top-level
// code; each surfaces only as report.corruptionCode or detail.primaryCode.
function classifyJournalBytes(bytes, journalName) {
  // JOURNAL_SIZE_PREFLIGHT
  if (bytes.length === 0) return { corruptionCode: "HOST_JOURNAL_EMPTY", record: null };
  if (bytes.length > JOURNAL_COMPARATOR_BOUNDARY) {
    return { corruptionCode: "HOST_JOURNAL_FILE_OVERSIZED", record: null };
  }

  // JOURNAL_DECODE — a UTF-8 BOM is rejected here, before parse, validation,
  // or canonical comparison. The raw bytes are inspected directly because a
  // decoder configured to honour the BOM would strip it and hide it from the
  // decoded string; ignoreBOM is therefore set so it also stays observable.
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { corruptionCode: "HOST_JOURNAL_UTF8_INVALID", record: null };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { corruptionCode: "HOST_JOURNAL_UTF8_INVALID", record: null };
  }
  if (text.charCodeAt(0) === 0xfeff) return { corruptionCode: "HOST_JOURNAL_UTF8_INVALID", record: null };
  // Leading or trailing whitespace is rejected at the decode stage too.
  if (text !== text.trim()) return { corruptionCode: "HOST_JOURNAL_UTF8_INVALID", record: null };

  // JOURNAL_PARSE
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { corruptionCode: "HOST_JOURNAL_JSON_INVALID", record: null };
  }
  if (!isObjectLike(parsed) || Array.isArray(parsed)) {
    return { corruptionCode: "HOST_JOURNAL_STORED_RECORD_INVALID", record: null };
  }

  // JOURNAL_STORED_VALIDATE — the pure 5B-0.4 contract is authoritative, and
  // the record it returns is the deep-frozen value the host goes on to retain.
  let validated;
  try {
    validated = pure().validateGenesisStagingJournalRecord(parsed);
  } catch {
    return { corruptionCode: "HOST_JOURNAL_STORED_RECORD_INVALID", record: null };
  }

  // JOURNAL_CANONICAL_COMPARE — reserialize and require exact raw-byte
  // equality, which also closes duplicate JSON keys that the parser accepts.
  // This must operate on the parse result, never on the validated record.
  let canonical;
  try {
    canonical = canonicalBytes(parsed);
  } catch {
    return { corruptionCode: "HOST_JOURNAL_STORED_RECORD_INVALID", record: null };
  }
  if (!canonical.equals(bytes)) return { corruptionCode: "HOST_JOURNAL_NONCANONICAL", record: null };

  // JOURNAL_FILENAME_CHECK
  if (journalNameFor(parsed) !== journalName) {
    return { corruptionCode: "HOST_JOURNAL_FILENAME_ID_MISMATCH", record: null };
  }
  return { corruptionCode: null, record: validated };
}

// ---------------------------------------------------------------------------
// Corrupt-journal quarantine — 2.31-2.42
// ---------------------------------------------------------------------------
function quarantineCorruptJournal(ctx, op, journalPath, journalName, classification) {
  const S = "JOURNAL_FILE";
  const slots = enumerateBounded(
    ctx, ctx.corruptDir, "CORRUPT_QUARANTINE_DIRECTORY", MAX_QUARANTINE_ENTRIES,
    "HOST_QUARANTINE_SCAN_OVERFLOW", "NOT_COMMITTED"
  );
  const used = slots.filter((n) => n.startsWith(`${journalName}.corrupt.`));
  if (used.length >= MAX_CORRUPT_QUARANTINE_FILES) {
    throw failure("HOST_CORRUPT_QUARANTINE_BOUND_EXCEEDED", op, "QUARANTINE_BOUND", S, "NOT_COMMITTED");
  }
  let slot = 0;
  while (used.includes(`${journalName}.corrupt.${slot}`)) slot += 1;
  const destination = path.join(ctx.corruptDir, `${journalName}.corrupt.${slot}`);

  let before;
  try {
    before = fs.lstatSync(journalPath);
  } catch {
    throw failure("HOST_CORRUPT_QUARANTINE_FAILED", op, "QUARANTINE_PROBE", S, "NOT_COMMITTED", classification);
  }
  let confirm;
  try {
    confirm = fs.lstatSync(journalPath);
  } catch {
    throw failure("HOST_CORRUPT_QUARANTINE_FAILED", op, "QUARANTINE_PRE_RENAME", S, "NOT_COMMITTED", classification);
  }
  if (confirm.dev !== before.dev || confirm.ino !== before.ino) {
    throw failure("HOST_CORRUPT_QUARANTINE_FAILED", op, "QUARANTINE_PRE_RENAME", S, "NOT_COMMITTED", classification);
  }
  try {
    fs.renameSync(journalPath, destination);
  } catch {
    throw failure("HOST_CORRUPT_QUARANTINE_FAILED", op, "QUARANTINE_RENAME", S, "NOT_COMMITTED", classification);
  }

  // Destination-first ordering (D37): the reverse risks a durable source
  // removal without a durable destination addition, which is data loss.
  quarantineDirDurable(ctx, op, ctx.corruptDir, "CORRUPT_QUARANTINE_DIRECTORY", "QUARANTINE_DEST_DIR", classification);
  quarantineDirDurable(ctx, op, ctx.stagingDir, "STAGING_DIRECTORY", "QUARANTINE_SOURCE_DIR", classification);
}

function quarantineDirDurable(ctx, op, dir, subject, prefix, classification) {
  const poisonNow = () => {
    POISONED_ROOTS.add(ctx.registryKey);
    if (ctx.state) ctx.state.poisoned = true;
  };
  let fd;
  try {
    fd = fs.openSync(dir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    poisonNow();
    throw failure("HOST_CORRUPT_QUARANTINE_INDETERMINATE", op, `${prefix}_OPEN`, subject, "INDETERMINATE", classification);
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      poisonNow();
      throw failure("HOST_CORRUPT_QUARANTINE_INDETERMINATE", op, `${prefix}_VALIDATE`, subject, "INDETERMINATE", classification);
    }
    if (!isOwnedDirectory(dstat)) {
      poisonNow();
      throw failure("HOST_CORRUPT_QUARANTINE_INDETERMINATE", op, `${prefix}_VALIDATE`, subject, "INDETERMINATE", classification);
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      poisonNow();
      throw failure("HOST_CORRUPT_QUARANTINE_INDETERMINATE", op, `${prefix}_FSYNC`, subject, "INDETERMINATE", classification);
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      poisonNow();
      if (prefix === "QUARANTINE_SOURCE_DIR") {
        // Both ends are durable, so the move is COMMITTED (DC2).
        throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, `${prefix}_CLOSE`, subject, "COMMITTED");
      }
      throw failure("HOST_CORRUPT_QUARANTINE_INDETERMINATE", op, `${prefix}_CLOSE`, subject, "INDETERMINATE", classification);
    }
  }
}

// ---------------------------------------------------------------------------
// Owned-temp write path
// ---------------------------------------------------------------------------
function writeOwnedTemp(ctx, op, tempPath, bytes, state, commitState) {
  const S = "TEMP_FILE";
  const cs = commitState || "NOT_COMMITTED";
  let fd;
  try {
    fd = fs.openSync(tempPath, O.O_CREAT | O.O_EXCL | O.O_WRONLY | O.O_NOFOLLOW, 0o600);
  } catch (error) {
    // An O_EXCL collision identifies a file this operation did not create and
    // does not own. It is never unlinked, and no cleanup path is reachable.
    if (error && error.code === "EEXIST") {
      throw failure("HOST_TEMP_FILE_BOUND_EXCEEDED", op, "TEMP_OPEN", S, cs);
    }
    throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "TEMP_OPEN", S, cs);
  }

  // From here the path is owned, so failures may attempt cleanup.
  try {
    let written = 0;
    while (written < bytes.length) {
      let n;
      try {
        n = fs.writeSync(fd, bytes, written, bytes.length - written, written);
      } catch {
        throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "TEMP_WRITE", S, cs);
      }
      if (n === 0) throw failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "TEMP_WRITE", S, cs);
      written += n;
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      throw failure("HOST_DURABILITY_WRITE_FAILED", op, "TEMP_FSYNC", S, cs);
    }
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* disposition unasserted, never reused */ }
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }

  try {
    fs.closeSync(fd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "TEMP_CLOSE", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }

  // Fresh reopen verification — a new descriptor, not the retained one.
  let vfd;
  try {
    vfd = fs.openSync(tempPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch {
    const error = failure("HOST_FILESYSTEM_READ_FAILED", op, "TEMP_VERIFY_OPEN", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  try {
    let vstat;
    try {
      vstat = fs.fstatSync(vfd);
    } catch {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "TEMP_VERIFY_CLASSIFY", S, cs);
    }
    if (!isOwnedRegularFile(vstat) || vstat.size !== bytes.length) {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, "TEMP_VERIFY_CLASSIFY", S, cs);
    }
  } catch (error) {
    try { fs.closeSync(vfd); } catch { /* unasserted */ }
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  try {
    fs.closeSync(vfd);
  } catch {
    const error = failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, "TEMP_VERIFY_CLOSE", S, cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
}

// Cleanup of an owned temp after an antecedent failure. The antecedent's own
// code becomes primaryCode on the indeterminate outcomes.
function cleanupOwnedTemp(ctx, op, tempPath, antecedent, state, commitState) {
  const primary = antecedent && antecedent.code ? antecedent.code : null;
  const cleanupCommitState = commitState === "PROFILE_COMMITTED"
    ? "INDETERMINATE"
    : "NOT_COMMITTED";
  const poisonNow = () => {
    POISONED_ROOTS.add(ctx.registryKey);
    if (state) state.poisoned = true;
  };

  try {
    fs.unlinkSync(tempPath);
  } catch {
    poisonNow();
    throw failure("HOST_TEMP_REMOVAL_INDETERMINATE", op, "TEMP_CLEANUP_UNLINK", "TEMP_FILE", cleanupCommitState, primary);
  }

  let fd;
  try {
    fd = fs.openSync(ctx.stagingDir, O.O_RDONLY | O.O_DIRECTORY | O.O_NOFOLLOW);
  } catch {
    poisonNow();
    throw failure("HOST_TEMP_REMOVAL_INDETERMINATE", op, "TEMP_CLEANUP_DIR_OPEN", "STAGING_DIRECTORY", cleanupCommitState, primary);
  }
  try {
    let dstat;
    try {
      dstat = fs.fstatSync(fd);
    } catch {
      poisonNow();
      throw failure("HOST_TEMP_REMOVAL_INDETERMINATE", op, "TEMP_CLEANUP_DIR_VALIDATE", "STAGING_DIRECTORY", cleanupCommitState, primary);
    }
    if (!isOwnedDirectory(dstat)) {
      poisonNow();
      throw failure("HOST_TEMP_REMOVAL_INDETERMINATE", op, "TEMP_CLEANUP_DIR_VALIDATE", "STAGING_DIRECTORY", cleanupCommitState, primary);
    }
    try {
      fs.fsyncSync(fd);
    } catch {
      poisonNow();
      throw failure("HOST_TEMP_REMOVAL_INDETERMINATE", op, "TEMP_CLEANUP_DIR_FSYNC", "STAGING_DIRECTORY", cleanupCommitState, primary);
    }
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      poisonNow();
      throw failure("HOST_CLEANUP_DESCRIPTOR_LEAKED", op, "TEMP_CLEANUP_DIR_CLOSE", "STAGING_DIRECTORY", cleanupCommitState, primary);
    }
  }
}

// ---------------------------------------------------------------------------
// CAS stages
// ---------------------------------------------------------------------------
function casInitial(ctx, op, journalPath, expected, commitState, phasePrefix) {
  const S = "JOURNAL_FILE";
  const pfx = phasePrefix || "CAS_INITIAL";
  let fd;
  try {
    fd = fs.openSync(journalPath, O.O_RDONLY | O.O_NOFOLLOW | O.O_NONBLOCK);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_OPEN`, S, commitState);
    }
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${pfx}_OPEN`, S, commitState);
  }
  try {
    let stat;
    try {
      stat = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, `${pfx}_CLASSIFY`, S, commitState);
    }
    if (!isOwnedRegularFile(stat)) {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, `${pfx}_CLASSIFY`, S, commitState);
    }
    const captured = snapshotSeven(stat);
    if (stat.size > JOURNAL_COMPARATOR_BOUNDARY) {
      throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${pfx}_READ`, S, commitState);
    }
    const buffer = Buffer.allocUnsafe(stat.size);
    let read = 0;
    while (read < stat.size) {
      let n;
      try {
        n = fs.readSync(fd, buffer, read, stat.size - read, read);
      } catch {
        throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${pfx}_READ`, S, commitState);
      }
      if (n === 0) break;
      read += n;
    }
    let recheck;
    try {
      recheck = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, `${pfx}_RECHECK`, S, commitState);
    }
    if (!sevenFieldEqual(snapshotSeven(recheck), captured)) {
      throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, `${pfx}_RECHECK`, S, commitState);
    }
    let onDisk = null;
    try {
      onDisk = JSON.parse(buffer.subarray(0, read).toString("utf8"));
    } catch {
      onDisk = null;
    }
    if (!onDisk || onDisk.integrityChecksum !== expected.integrityChecksum) {
      throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_CHECKSUM_COMPARE`, S, commitState);
    }
    let identityProbe;
    try {
      identityProbe = fs.fstatSync(fd);
    } catch {
      throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_IDENTITY_COMPARE`, S, commitState);
    }
    if (identityProbe.dev !== stat.dev || identityProbe.ino !== stat.ino) {
      throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_IDENTITY_COMPARE`, S, commitState);
    }
    return { identity: { dev: stat.dev, ino: stat.ino }, record: onDisk };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      throw failure("HOST_DESCRIPTOR_CLOSE_FAILED", op, `${pfx}_CLOSE`, S, commitState);
    }
  }
}

function casFinal(ctx, op, journalPath, identity, commitState, phasePrefix) {
  const S = "JOURNAL_FILE";
  const pfx = phasePrefix || "CAS_FINAL";
  let probe;
  try {
    probe = fs.lstatSync(journalPath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_PROBE`, S, commitState);
    }
    throw failure("HOST_FILESYSTEM_READ_FAILED", op, `${pfx}_PROBE`, S, commitState);
  }
  if (!isOwnedRegularFile(probe)) {
    throw failure("HOST_JOURNAL_DESCRIPTOR_INVALID", op, `${pfx}_CLASSIFY`, S, commitState);
  }
  if (identity && (probe.dev !== identity.dev || probe.ino !== identity.ino)) {
    throw failure("HOST_DISK_STATE_CHANGED", op, `${pfx}_IDENTITY_COMPARE`, S, commitState);
  }
}

// ---------------------------------------------------------------------------
// Publication — ordinary renameSync (D27) and parent-directory durability
// ---------------------------------------------------------------------------
function finishPublication(ctx, op, tempPath, journalPath, state, record, commitState) {
  const cs = commitState || "NOT_COMMITTED";
  try {
    fs.renameSync(tempPath, journalPath);
  } catch {
    const error = failure("HOST_FILESYSTEM_MUTATION_FAILED", op, "RENAME", "JOURNAL_FILE", cs);
    cleanupOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }

  const durabilityOpts = cs === "PROFILE_COMMITTED"
    ? {
        indeterminateCode: "HOST_DURABILITY_INDETERMINATE",
        indeterminateCommitState: "SUPERSESSION_INDETERMINATE",
        closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
        closeCommitState: "COMMITTED",
        poisonOnIndeterminate: true,
        poisonOnClose: true
      }
    : {
        indeterminateCode: "HOST_DURABILITY_INDETERMINATE",
        indeterminateCommitState: "INDETERMINATE",
        closeCode: "HOST_DESCRIPTOR_CLOSE_FAILED",
        closeCommitState: "COMMITTED",
        poisonOnIndeterminate: true,
        poisonOnClose: true
      };

  directoryDurability(ctx, op, "PARENT_DIR", "STAGING_DIRECTORY", durabilityOpts);

  if (state.pendingNow !== undefined && state.pendingNow !== null) {
    state.lastSampledNowUnixSeconds = state.pendingNow;
    state.pendingNow = null;
  }
  void record;
}

function publishRecord(ctx, op, journalName, updated, previous, commitState) {
  const cs = commitState || "NOT_COMMITTED";
  const state = ctx.state;
  const bytes = serializeRecord(ctx, op, updated, cs);
  const tempPath = path.join(ctx.stagingDir, `.${journalName}.tmp`);
  const journalPath = path.join(ctx.stagingDir, journalName);
  writeOwnedTemp(ctx, op, tempPath, bytes, state, cs);
  let identity = null;
  try {
    const probe = fs.lstatSync(journalPath);
    identity = { dev: probe.dev, ino: probe.ino };
  } catch {
    identity = null;
  }
  try {
    casFinal(ctx, op, journalPath, identity, cs);
  } catch (error) {
    cleanupOwnedTemp(ctx, op, tempPath, error, state, cs);
    throw error;
  }
  finishPublication(ctx, op, tempPath, journalPath, state, updated, cs);
  void previous;
}

// ---------------------------------------------------------------------------
// Shared mutation path for stageRole (Chain 4) and cancel (Chain 5)
// ---------------------------------------------------------------------------
function mutateExistingJournal(ctx, state, op, input, opts) {
  const guardFailure = (code, phase, subject, commitState) =>
    failure(code, op, phase, subject, commitState);

  if (state.poisoned || POISONED_ROOTS.has(ctx.registryKey)) {
    throw guardFailure("HOST_PROCESS_POISONED", "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
  }
  if (state.closed) {
    throw guardFailure("HOST_CLOSED", "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
  }
  if (!state.reconciled) {
    throw guardFailure("HOST_RECONCILIATION_REQUIRED", "LIFECYCLE_GUARD", null, "NOT_APPLICABLE");
  }

  rejectIfFinalizedProfileCommitted(state, op);

  let lockStat;
  try {
    lockStat = fs.lstatSync(ctx.lockPath);
  } catch {
    throw guardFailure("HOST_LOCK_LOST_OR_REPLACED", "LOCK_IDENTITY", "LOCK_FILE", "NOT_APPLICABLE");
  }
  if (lockStat.dev !== ctx.lockIdentity.dev || lockStat.ino !== ctx.lockIdentity.ino) {
    throw guardFailure("HOST_LOCK_LOST_OR_REPLACED", "LOCK_IDENTITY", "LOCK_FILE", "NOT_APPLICABLE");
  }

  const current = state.current;
  if (current === null) {
    throw guardFailure(opts.notFoundCode, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
  }
  if (current.state !== "STAGING") {
    throw guardFailure(opts.inactiveCode, "JOURNAL_PRECONDITION", "JOURNAL_FILE", "NOT_APPLICABLE");
  }
  let loadedObligation = null;
  if (opts.requireRecordedObligation) {
    loadedObligation = loadValidatedObligation(ctx, op);
    if (loadedObligation === null || loadedObligation.record.state !== "CREDENTIAL_RECORDED") {
      throw guardFailure(
        loadedObligation === null
          ? "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND"
          : "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID",
        "OBLIGATION_PRECONDITION",
        "CREDENTIAL_OBLIGATION_FILE",
        "NOT_APPLICABLE"
      );
    }
    state.obligation = loadedObligation.record;
  }

  const sample = drawClockSample(ctx);
  if (typeof opts.beforeDelegate === "function" && !sample.threw) {
    opts.beforeDelegate(current, sample.value);
  }
  const updated = delegateWithClock(ctx, op, sample, (nowValue) =>
    opts.transform(current, input, nowValue)
  );
  if (typeof opts.afterDelegate === "function") {
    opts.afterDelegate(current, updated, input, loadedObligation);
  }
  checkRegression(ctx, state, op, sample);

  const journalName = journalNameFor(current);
  const journalPath = path.join(ctx.stagingDir, journalName);
  const initial = casInitial(ctx, op, journalPath, current, "NOT_COMMITTED");

  const bytes = serializeRecord(ctx, op, updated);

  const tempPath = path.join(ctx.stagingDir, `.${journalName}.tmp`);
  writeOwnedTemp(ctx, op, tempPath, bytes, state);

  try {
    casFinal(ctx, op, journalPath, initial.identity, "NOT_COMMITTED");
  } catch (error) {
    cleanupOwnedTemp(ctx, op, tempPath, error, state);
    throw error;
  }

  finishPublication(ctx, op, tempPath, journalPath, state, updated);
  state.current = updated;
  if (typeof opts.afterCommit === "function") {
    opts.afterCommit(updated, loadedObligation);
  }
  return Object.freeze({
    journal: updated,
    obligation: state.obligation === undefined ? null : state.obligation
  });
}
