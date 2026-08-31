"use strict";

const os = require("node:os");

const DIAGNOSTIC_KIND = "desktop_e2e_spawn_diagnostic";
const DIAGNOSTIC_VERSION = 1;

// Fixed, constant fallback: composed only of literal primitives we control,
// so building and serializing it can never throw. Computed once at module
// load -- the actual failure path only ever returns/prints this precomputed
// value, never re-serializes anything.
const FALLBACK_DIAGNOSTIC = Object.freeze({
  kind: DIAGNOSTIC_KIND,
  version: DIAGNOSTIC_VERSION,
  diagnosticError: "serialization_failed"
});
const FALLBACK_DIAGNOSTIC_JSON = JSON.stringify(FALLBACK_DIAGNOSTIC);

// --- Field-specific token allowlists ---------------------------------------
// Every string-capable field below is validated against a positive,
// field-specific allowlist rather than accepted as an arbitrary
// length-capped string. A value that does not match becomes null; it is
// never partially preserved, redacted-in-place, or passed through a generic
// secret scanner. This is the primary boundary, not a backstop.

// Node's own trusted signal-name source (os.constants.signals), not a regex
// over "SIG..." shapes.
const SIGNAL_ALLOWLIST = new Set(Object.keys(os.constants.signals || {}));

// Narrow, evidence-based set of Error class names Node actually uses for
// spawn-related failures.
const ERROR_NAME_ALLOWLIST = new Set(["Error", "TypeError", "RangeError", "SystemError"]);

// Evidence-based set of libuv/POSIX errno codes realistically observable
// from a failed spawn/spawnSync/execFile call (command missing, permission
// denied, resource limits, timeout, broken pipe, etc). Node's own ERR_*
// identifiers are intentionally not included here: none are evidenced for
// this spawn path, and a fixed exact-match allowlist is preferred over a
// broader grammar per the required design.
const ERROR_CODE_ALLOWLIST = new Set([
  "ENOENT",
  "EACCES",
  "EPERM",
  "EMFILE",
  "ENFILE",
  "ENOMEM",
  "EAGAIN",
  "ETIMEDOUT",
  "EPIPE",
  "ESRCH",
  "ENOEXEC",
  "E2BIG",
  "ETXTBSY"
]);

// Node's own child_process error .syscall values are the bare operation
// name alone ("spawn") OR the operation name followed by a space and the
// command/path that was attempted ("spawnSync /path/to/electron") --
// confirmed empirically against this Node version. Only the operation
// token itself is ever safe to keep; the command/path suffix is never
// accepted, matching "do not accept strings containing command paths or
// arguments."
const SYSCALL_ALLOWLIST = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const MAX_SYSCALL_INPUT_LENGTH = 4096;

// Reads a single property without ever letting a throwing getter or a
// hostile Proxy trap escape. Isolated per-property so one poisoned field
// cannot prevent extraction of the others.
function safeGet(source, key) {
  try {
    return source[key];
  } catch {
    return undefined;
  }
}

function toSafeFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function toSafeNonNegativeFiniteNumber(value) {
  const n = toSafeFiniteNumber(value);
  return n !== null && n >= 0 ? n : null;
}

function toSafeSafeInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

// Byte length is computed only from an actual string or Buffer -- anything
// else (including a hostile object with a throwing/misleading .length or
// Symbol.toPrimitive) is reported as null rather than coerced.
function safeByteLength(value) {
  if (typeof value === "string") return Buffer.byteLength(value, "utf8");
  if (Buffer.isBuffer(value)) return value.length;
  return null;
}

// Exact-match allowlist check. Never coerces; a non-string input (object,
// array, function, symbol, BigInt, etc) is rejected by the typeof check
// alone, before any Set lookup.
function toAllowlistedString(value, allowlist) {
  if (typeof value !== "string") return null;
  return allowlist.has(value) ? value : null;
}

function toSafeSignal(value) {
  return toAllowlistedString(value, SIGNAL_ALLOWLIST);
}

function toSafeErrorName(value) {
  return toAllowlistedString(value, ERROR_NAME_ALLOWLIST);
}

function toSafeErrorCode(value) {
  return toAllowlistedString(value, ERROR_CODE_ALLOWLIST);
}

function toSafeErrno(value) {
  const asInteger = toSafeSafeInteger(value);
  if (asInteger !== null) return asInteger;
  // Node documents error.errno as a number; this only exists as a defensive
  // fallback in case a platform/version legitimately supplies a string
  // errno token, in which case the same strict error-code grammar applies.
  return toSafeErrorCode(value);
}

// Accepts only the bare, known operation token -- either the whole string
// IS that token, or the string is "<token> <anything>" and only the token
// prefix is kept. The command/path/argument suffix is always discarded,
// never preserved in any form.
function toSafeSyscall(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_SYSCALL_INPUT_LENGTH) return null;
  if (SYSCALL_ALLOWLIST.has(value)) return value;
  const spaceIndex = value.indexOf(" ");
  if (spaceIndex === -1) return null;
  const prefix = value.slice(0, spaceIndex);
  return SYSCALL_ALLOWLIST.has(prefix) ? prefix : null;
}

/**
 * Builds a deterministic, secret-free diagnostic for a failed Electron
 * spawnSync result. Returns null when the (safely read) status is exactly
 * 0, so a successful spawn never produces a diagnostic.
 *
 * Every field is read through safeGet and converted through a
 * field-specific positive allowlist (signal/errorName/errorCode/errorSyscall)
 * or a type check (status/errorErrno/byte lengths/elapsedMs) -- never
 * through toJSON/toString/valueOf/coercion, and never through a generic
 * capped-string pass-through. Anything that doesn't match its field's
 * allowlist becomes null outright; it is never partially preserved. The
 * whole function is additionally wrapped in try/catch as a second layer of
 * defense: if anything still goes unexpectedly wrong, it returns the same
 * fixed FALLBACK_DIAGNOSTIC shape rather than throwing or returning a
 * partially-built, potentially unsafe object.
 */
function buildSpawnDiagnostic(result, meta) {
  try {
    if (!result) return null;
    const status = safeGet(result, "status");
    if (status === 0) return null;

    const info = meta || {};
    const error = safeGet(result, "error");

    return {
      kind: DIAGNOSTIC_KIND,
      version: DIAGNOSTIC_VERSION,
      status: toSafeFiniteNumber(status),
      signal: toSafeSignal(safeGet(result, "signal")),
      errorName: error ? toSafeErrorName(safeGet(error, "name")) : null,
      errorCode: error ? toSafeErrorCode(safeGet(error, "code")) : null,
      errorErrno: error ? toSafeErrno(safeGet(error, "errno")) : null,
      errorSyscall: error ? toSafeSyscall(safeGet(error, "syscall")) : null,
      timedOut: info.timedOut === true,
      stdoutByteLength: safeByteLength(safeGet(result, "stdout")),
      stderrByteLength: safeByteLength(safeGet(result, "stderr")),
      elapsedMs: toSafeNonNegativeFiniteNumber(info.elapsedMs)
    };
  } catch {
    return FALLBACK_DIAGNOSTIC;
  }
}

/**
 * Builds and serializes the diagnostic in one call. Never throws: if
 * construction or JSON.stringify fails for any reason, returns the fixed
 * FALLBACK_DIAGNOSTIC_JSON string instead. Returns null (no output) on a
 * successful spawn.
 */
function formatSpawnDiagnosticJson(result, meta) {
  try {
    const diagnostic = buildSpawnDiagnostic(result, meta);
    if (!diagnostic) return null;
    return JSON.stringify(diagnostic);
  } catch {
    return FALLBACK_DIAGNOSTIC_JSON;
  }
}

/**
 * Runs attemptFn, then unconditionally runs finalFn -- even if attemptFn
 * throws. Used so the real spawn-failure exit path is guaranteed to run
 * regardless of what happens while building/printing a diagnostic.
 */
function runWithGuaranteedFinal(attemptFn, finalFn) {
  try {
    attemptFn();
  } finally {
    finalFn();
  }
}

module.exports = {
  buildSpawnDiagnostic,
  formatSpawnDiagnosticJson,
  runWithGuaranteedFinal,
  DIAGNOSTIC_KIND,
  DIAGNOSTIC_VERSION,
  FALLBACK_DIAGNOSTIC,
  FALLBACK_DIAGNOSTIC_JSON,
  SIGNAL_ALLOWLIST,
  ERROR_NAME_ALLOWLIST,
  ERROR_CODE_ALLOWLIST,
  SYSCALL_ALLOWLIST
};
