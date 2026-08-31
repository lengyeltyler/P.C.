"use strict";
// Test-only, focused/adversarial checks for the e2e spawn-diagnostic
// formatter. Not part of the classified CI universe by design (does not end
// in .test.cjs) -- this exercises pure formatter/wrapper logic, not a real
// Electron spawn.
const assert = require("node:assert/strict");
const {
  buildSpawnDiagnostic,
  formatSpawnDiagnosticJson,
  runWithGuaranteedFinal,
  DIAGNOSTIC_KIND,
  DIAGNOSTIC_VERSION,
  FALLBACK_DIAGNOSTIC,
  FALLBACK_DIAGNOSTIC_JSON
} = require("./desktop-e2e-diagnostic.cjs");

const EXPECTED_KEYS = [
  "elapsedMs",
  "errorCode",
  "errorErrno",
  "errorName",
  "errorSyscall",
  "kind",
  "signal",
  "status",
  "stderrByteLength",
  "stdoutByteLength",
  "timedOut",
  "version"
].sort();

function assertNeverThrows(label, fn) {
  let value;
  assert.doesNotThrow(() => {
    value = fn();
  }, label);
  return value;
}

// --- successful spawn emits nothing ---------------------------------------
assert.equal(
  buildSpawnDiagnostic({ status: 0, signal: null, stdout: "anything", stderr: "" }, { elapsedMs: 10 }),
  null,
  "successful spawn must not produce a diagnostic object"
);
assert.equal(
  formatSpawnDiagnosticJson({ status: 0, signal: null, stdout: "anything", stderr: "" }, { elapsedMs: 10 }),
  null,
  "successful spawn must not produce a diagnostic JSON line"
);

// --- null status plus SIGTRAP (the confirmed local shape) -----------------
{
  const d = buildSpawnDiagnostic(
    { status: null, signal: "SIGTRAP", stdout: "", stderr: "" },
    { elapsedMs: 334, timedOut: false }
  );
  assert.equal(d.kind, DIAGNOSTIC_KIND);
  assert.equal(d.version, DIAGNOSTIC_VERSION);
  assert.equal(d.status, null);
  assert.equal(d.signal, "SIGTRAP");
  assert.equal(d.timedOut, false);
  assert.equal(d.stdoutByteLength, 0);
  assert.equal(d.stderrByteLength, 0);
  assert.equal(d.elapsedMs, 334);
  assert.equal(d.errorName, null);
  assert.equal(d.errorCode, null);
  assert.equal(d.errorErrno, null);
  assert.equal(d.errorSyscall, null);
}

// --- timeout shape ----------------------------------------------------------
{
  const d = buildSpawnDiagnostic(
    { status: null, signal: "SIGTERM", stdout: "", stderr: "" },
    { elapsedMs: 20003, timedOut: true }
  );
  assert.equal(d.timedOut, true);
  assert.equal(d.elapsedMs, 20003);
  assert.equal(d.signal, "SIGTERM");
}

// --- launch-error shape, proving path/spawnargs never leak -----------------
// error.syscall is the real Node shape for a failed spawn: "<op> <command>".
// Only the leading operation token ("spawn") is ever kept; the command/path
// suffix is discarded outright, never preserved in any form.
{
  const err = new Error("spawn electron ENOENT");
  err.name = "Error";
  err.code = "ENOENT";
  err.errno = -2;
  err.syscall = "spawn electron";
  err.path = "/Users/example/secret/electron";
  err.spawnargs = ["/Users/example/secret/electron", "apps/philcore-desktop/src/main/main.cjs"];
  const d = buildSpawnDiagnostic(
    { status: null, signal: null, stdout: "", stderr: "", error: err },
    { elapsedMs: 5, timedOut: false }
  );
  assert.equal(d.errorName, "Error");
  assert.equal(d.errorCode, "ENOENT");
  assert.equal(d.errorErrno, -2);
  assert.equal(d.errorSyscall, "spawn", "only the bare operation token survives, never the command suffix");
  const json = JSON.stringify(d);
  assert.equal(json.includes("/Users/"), false, "must not leak absolute paths");
  assert.equal(json.includes("secret"), false, "must not leak error.path/spawnargs content");
  assert.equal(json.includes("electron"), false, "must not leak the command name from syscall");
}

// --- real Node spawnSync ENOENT syscall shape survives (empirically observed:
// "spawnSync <command>", where <command> can itself be an absolute path) ----
{
  const d = buildSpawnDiagnostic(
    {
      status: null,
      signal: null,
      error: {
        name: "Error",
        code: "ENOENT",
        errno: -2,
        syscall: "spawnSync /Users/example/Developer/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron"
      }
    },
    { elapsedMs: 1 }
  );
  assert.equal(d.errorSyscall, "spawnSync");
  const json = JSON.stringify(d);
  assert.equal(json.includes("/Users/"), false, "must not leak the absolute Electron path embedded in syscall");
  assert.equal(json.includes("Electron.app"), false);
}

// --- exact key allowlist + absence of sensitive content ---------------------
{
  const d = buildSpawnDiagnostic(
    {
      status: 1,
      signal: null,
      stdout: "ownerCommitment=0xSECRET identityId=abc philSecret=deadbeef",
      stderr: "/Users/attacker/.philcore/identities/leak proofArtifact=xyz",
      error: {
        name: "Error",
        code: "EFAKE",
        errno: 1,
        syscall: "spawn",
        path: "/Users/attacker/electron",
        spawnargs: ["--token=abc123", "PHILCORE_SECRET=zzz"]
      },
      env: { PHILCORE_SECRET: "zzz" }
    },
    { elapsedMs: 1, timedOut: false }
  );
  const keys = Object.keys(d).sort();
  assert.deepEqual(keys, EXPECTED_KEYS, "diagnostic must expose exactly the allowlisted keys");
  const json = JSON.stringify(d);
  for (const forbidden of [
    "ownerCommitment",
    "identityId",
    "philSecret",
    "proofArtifact",
    "/Users/",
    "token",
    "PHILCORE_SECRET",
    "env"
  ]) {
    assert.equal(json.includes(forbidden), false, `must not leak "${forbidden}"`);
  }
}

// --- circular error.name -----------------------------------------------------
{
  const circular = {};
  circular.self = circular;
  const d = assertNeverThrows("circular error.name", () =>
    buildSpawnDiagnostic(
      { status: null, signal: null, error: { name: circular, code: "C", errno: 1, syscall: "S" } },
      { elapsedMs: 1 }
    )
  );
  assert.equal(d.errorName, null);
  assertNeverThrows("JSON.stringify after circular error.name", () => JSON.stringify(d));
}

// --- object-valued error.code -------------------------------------------------
{
  const d = buildSpawnDiagnostic(
    { status: null, signal: null, error: { name: "N", code: { nested: true }, errno: 1, syscall: "S" } },
    { elapsedMs: 1 }
  );
  assert.equal(d.errorCode, null);
}

// --- throwing toJSON on error.name -------------------------------------------
{
  const hostile = { toJSON() { throw new Error("hostile toJSON"); } };
  const d = assertNeverThrows("throwing toJSON on error.name", () =>
    buildSpawnDiagnostic(
      { status: null, signal: null, error: { name: hostile, code: "C", errno: 1, syscall: "S" } },
      { elapsedMs: 1 }
    )
  );
  assert.equal(d.errorName, null);
  assertNeverThrows("JSON.stringify after throwing toJSON on error.name", () => JSON.stringify(d));
}

// --- throwing toString on error.code -----------------------------------------
{
  const hostile = { toString() { throw new Error("hostile toString"); } };
  const d = assertNeverThrows("throwing toString on error.code", () =>
    buildSpawnDiagnostic(
      { status: null, signal: null, error: { name: "N", code: hostile, errno: 1, syscall: "S" } },
      { elapsedMs: 1 }
    )
  );
  assert.equal(d.errorCode, null);
}

// --- throwing getter for each allowlisted error field, isolated -------------
// Base values are all legitimate, allowlisted values (not arbitrary "N"/"C"/
// "S" placeholders) so a sibling field's survival genuinely proves isolation
// rather than being trivially null under the new field-specific allowlists.
for (const field of ["name", "code", "errno", "syscall"]) {
  const err = { name: "Error", code: "ENOENT", errno: 1, syscall: "spawn" };
  Object.defineProperty(err, field, {
    get() {
      throw new Error(`hostile getter: ${field}`);
    }
  });
  const d = assertNeverThrows(`throwing getter for error.${field}`, () =>
    buildSpawnDiagnostic({ status: null, signal: null, error: err }, { elapsedMs: 1 })
  );
  const fieldKey = `error${field[0].toUpperCase()}${field.slice(1)}`;
  assert.equal(d[fieldKey], null, `error.${field}'s throwing getter must sanitize to null`);
  // Sibling fields must still be extracted correctly -- proves per-field
  // isolation rather than one throw discarding the whole error object.
  for (const sibling of ["name", "code", "errno", "syscall"]) {
    if (sibling === field) continue;
    const siblingKey = `error${sibling[0].toUpperCase()}${sibling.slice(1)}`;
    assert.notEqual(d[siblingKey], null, `sibling error.${sibling} must survive error.${field} throwing`);
  }
}

// --- hostile Proxy get trap on error, and on the whole result --------------
{
  const hostileError = new Proxy(
    {},
    {
      get() {
        throw new Error("proxy trap on error");
      }
    }
  );
  const d = assertNeverThrows("hostile Proxy error", () =>
    buildSpawnDiagnostic({ status: null, signal: null, error: hostileError }, { elapsedMs: 1 })
  );
  assert.equal(d.errorName, null);
  assert.equal(d.errorCode, null);
  assert.equal(d.errorErrno, null);
  assert.equal(d.errorSyscall, null);
}
{
  const hostileResult = new Proxy(
    {},
    {
      get() {
        throw new Error("proxy trap on result");
      }
    }
  );
  const d = assertNeverThrows("hostile Proxy result", () => buildSpawnDiagnostic(hostileResult, { elapsedMs: 1 }));
  // Cannot safely determine status was 0, so this must not be treated as a
  // silent success -- it must fail closed into a (mostly-null) diagnostic.
  assert.notEqual(d, null);
  assert.equal(d.status, null);
}

// --- BigInt / Symbol / function / array values ------------------------------
{
  const d = buildSpawnDiagnostic(
    {
      status: null,
      signal: null,
      error: { name: function namedFn() {}, code: Symbol("x"), errno: 10n, syscall: ["spawn"] }
    },
    { elapsedMs: 1 }
  );
  assert.equal(d.errorName, null);
  assert.equal(d.errorCode, null);
  assert.equal(d.errorErrno, null);
  assert.equal(d.errorSyscall, null);
  assertNeverThrows("JSON.stringify with BigInt/Symbol/function/array sanitized away", () => JSON.stringify(d));
}

// --- NaN, +Infinity, -Infinity -----------------------------------------------
for (const bad of [NaN, Infinity, -Infinity]) {
  const d = buildSpawnDiagnostic(
    { status: null, signal: null, error: { name: "N", code: "C", errno: bad, syscall: "S" } },
    { elapsedMs: bad }
  );
  assert.equal(d.errorErrno, null, `errno=${bad} must sanitize to null`);
  assert.equal(d.elapsedMs, null, `elapsedMs=${bad} must sanitize to null`);
}

// --- hostile/non-string stdout and stderr values -----------------------------
{
  const hostileStream = new Proxy(
    {},
    {
      get() {
        throw new Error("hostile stream access");
      }
    }
  );
  const d = assertNeverThrows("hostile stdout/stderr", () =>
    buildSpawnDiagnostic({ status: null, signal: null, stdout: hostileStream, stderr: 12345 }, { elapsedMs: 1 })
  );
  assert.equal(d.stdoutByteLength, null);
  assert.equal(d.stderrByteLength, null);
}
{
  // Positive case: a real Buffer is measured correctly, not coerced away.
  const d = buildSpawnDiagnostic(
    { status: null, signal: null, stdout: Buffer.from("hello"), stderr: "world" },
    { elapsedMs: 1 }
  );
  assert.equal(d.stdoutByteLength, 5);
  assert.equal(d.stderrByteLength, 5);
}

// --- serialization fallback: hostile Object.prototype.toJSON ---------------
{
  const hadOwnToJSON = Object.prototype.hasOwnProperty.call(Object.prototype, "toJSON");
  const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  Object.defineProperty(Object.prototype, "toJSON", {
    value() {
      throw new Error("hostile prototype toJSON");
    },
    configurable: true,
    writable: true
  });
  try {
    const json = assertNeverThrows("formatSpawnDiagnosticJson under poisoned Object.prototype.toJSON", () =>
      formatSpawnDiagnosticJson({ status: null, signal: "SIGTRAP" }, { elapsedMs: 1 })
    );
    assert.equal(json, FALLBACK_DIAGNOSTIC_JSON, "must fall back to the fixed diagnostic JSON string");
    assert.deepEqual(JSON.parse(json), FALLBACK_DIAGNOSTIC);
  } finally {
    if (hadOwnToJSON) {
      Object.defineProperty(Object.prototype, "toJSON", originalDescriptor);
    } else {
      delete Object.prototype.toJSON;
    }
  }
}

// --- diagnostic-output failure / guaranteed final action --------------------
// runWithGuaranteedFinal does not swallow the attempt's error -- it only
// guarantees finalFn already ran before that error can propagate further.
// In real usage finalFn calls process.exit(), which terminates synchronously
// before any re-thrown error would matter; these tests observe finalFn
// directly since they cannot safely call the real process.exit().
{
  let finalCalls = 0;
  let caught = null;
  try {
    runWithGuaranteedFinal(
      () => {
        throw new Error("diagnostic output failed");
      },
      () => {
        finalCalls += 1;
      }
    );
  } catch (error) {
    caught = error;
  }
  assert.equal(finalCalls, 1, "final action must run even when the attempt throws an Error");
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "diagnostic output failed");
}
{
  // Non-Error thrown values must not defeat the guarantee either.
  let finalCalls = 0;
  let caught;
  try {
    runWithGuaranteedFinal(
      () => {
        throw "plain string failure"; // eslint-disable-line no-throw-literal
      },
      () => {
        finalCalls += 1;
      }
    );
  } catch (error) {
    caught = error;
  }
  assert.equal(finalCalls, 1, "final action must run even when a non-Error value is thrown");
  assert.equal(caught, "plain string failure");
}
{
  // Success path: the final action still runs exactly once, and exactly
  // once (no double-invocation), when the attempt does not throw.
  let attemptCalls = 0;
  let finalCalls = 0;
  runWithGuaranteedFinal(
    () => {
      attemptCalls += 1;
    },
    () => {
      finalCalls += 1;
    }
  );
  assert.equal(attemptCalls, 1);
  assert.equal(finalCalls, 1);
}

// --- integration: the real exit-code selection survives a poisoned toJSON,
// mirroring exactly how desktop-e2e.test.cjs's runElectron uses these two
// exports together. This is the direct proof that diagnostic construction
// or serialization can never mask the original fail-closed exit.
for (const [label, status] of [["numeric status", 7], ["null status (SIGTRAP shape)", null]]) {
  const hadOwnToJSON = Object.prototype.hasOwnProperty.call(Object.prototype, "toJSON");
  const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  Object.defineProperty(Object.prototype, "toJSON", {
    value() {
      throw new Error("hostile prototype toJSON");
    },
    configurable: true,
    writable: true
  });
  let exitCode = null;
  try {
    const result = { status, signal: status === null ? "SIGTRAP" : null, stdout: "", stderr: "" };
    runWithGuaranteedFinal(
      () => {
        const diagnosticJson = formatSpawnDiagnosticJson(result, { elapsedMs: 1, timedOut: false });
        assert.equal(diagnosticJson, FALLBACK_DIAGNOSTIC_JSON, `${label}: must fall back under a poisoned toJSON`);
      },
      () => {
        exitCode = result.status || 1;
      }
    );
  } finally {
    if (hadOwnToJSON) {
      Object.defineProperty(Object.prototype, "toJSON", originalDescriptor);
    } else {
      delete Object.prototype.toJSON;
    }
  }
  const expectedExitCode = status || 1;
  assert.equal(exitCode, expectedExitCode, `${label}: original exit code must still be selected`);
}

// --- field-specific allowlist adversarial matrix ----------------------------
// Every string-capable field (signal, errorName, errorCode, errorErrno-as-
// string, errorSyscall) must reject every value below outright to null --
// never truncate, redact-in-place, or otherwise partially preserve it. The
// positive allowlist is the boundary; these poison values probe it from
// outside, not via a generic secret-content scanner.
const HOSTILE_COERCION_OBJECT = {
  toString() {
    throw new Error("hostile toString");
  },
  valueOf() {
    throw new Error("hostile valueOf");
  },
  [Symbol.toPrimitive]() {
    throw new Error("hostile Symbol.toPrimitive");
  }
};

const POISON_VALUES = [
  ["absolute_posix_path", "/Users/attacker/.philcore/secret"],
  ["windows_path", "C:\\Users\\attacker\\.philcore\\secret.txt"],
  ["file_url", "file:///Users/attacker/.philcore/secret"],
  ["http_url", "http://attacker.example/exfil?x=1"],
  ["https_url", "https://attacker.example/exfil?x=1"],
  ["newline", "before\nafter"],
  ["carriage_return", "before\rafter"],
  ["tab", "before\tafter"],
  ["double_quote", 'has "quotes" inside'],
  ["backslash", "has\\backslash\\inside"],
  ["token_kv", "token=abc123def456"],
  ["secret_kv", "secret=abc123def456"],
  ["ghp_token", "ghp_1234567890abcdef1234567890abcdef1234"],
  ["github_pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"],
  ["sk_token", "sk-1234567890abcdefABCDEF1234567890"],
  ["bearer", "Bearer abc123def456ghi789"],
  ["extremely_long", "A".repeat(10000)],
  ["hostile_coercion_object", HOSTILE_COERCION_OBJECT]
];

const FIELD_PROBES = [
  {
    label: "signal",
    plausibleUnknown: "SIGCUSTOM99",
    extract: (d) => d.signal,
    resultFor: (value) => ({ status: null, signal: value, stdout: "", stderr: "" })
  },
  {
    label: "errorName",
    plausibleUnknown: "CustomSpawnError",
    extract: (d) => d.errorName,
    resultFor: (value) => ({
      status: null,
      signal: null,
      error: { name: value, code: "ENOENT", errno: 1, syscall: "spawn" }
    })
  },
  {
    label: "errorCode",
    plausibleUnknown: "EFAKE1",
    extract: (d) => d.errorCode,
    resultFor: (value) => ({
      status: null,
      signal: null,
      error: { name: "Error", code: value, errno: 1, syscall: "spawn" }
    })
  },
  {
    label: "errorErrno (string form)",
    plausibleUnknown: "EFAKE1",
    extract: (d) => d.errorErrno,
    resultFor: (value) => ({
      status: null,
      signal: null,
      error: { name: "Error", code: "ENOENT", errno: value, syscall: "spawn" }
    })
  },
  {
    label: "errorSyscall",
    plausibleUnknown: "spawnFake",
    extract: (d) => d.errorSyscall,
    resultFor: (value) => ({
      status: null,
      signal: null,
      error: { name: "Error", code: "ENOENT", errno: 1, syscall: value }
    })
  }
];

for (const probe of FIELD_PROBES) {
  const poisonsForField = [...POISON_VALUES, ["plausible_unknown_token", probe.plausibleUnknown]];
  for (const [poisonLabel, poisonValue] of poisonsForField) {
    const label = `${probe.label} / ${poisonLabel}`;
    const d = assertNeverThrows(label, () => buildSpawnDiagnostic(probe.resultFor(poisonValue), { elapsedMs: 1 }));
    assert.equal(probe.extract(d), null, `${label}: must sanitize to null, not partially preserve`);
    assertNeverThrows(`JSON.stringify after ${label}`, () => JSON.stringify(d));
  }
}

// --- legitimate values must survive their field's allowlist -----------------
{
  const d = buildSpawnDiagnostic({ status: null, signal: "SIGTRAP", stdout: "", stderr: "" }, { elapsedMs: 1 });
  assert.equal(d.signal, "SIGTRAP");
}
{
  const d = buildSpawnDiagnostic(
    { status: null, signal: null, error: { name: "Error", code: "ENOENT", errno: -2, syscall: "spawn" } },
    { elapsedMs: 1 }
  );
  assert.equal(d.errorName, "Error");
  assert.equal(d.errorCode, "ENOENT");
  assert.equal(d.errorErrno, -2);
  assert.equal(d.errorSyscall, "spawn");
}

// --- exact reproducible regression: a poisoned error.name must not leak an
// attacker-controlled path/token pair into the diagnostic, while sibling
// safe fields (code/errno/syscall) survive untouched. -----------------------
{
  const err = {
    name: "/Users/attacker/.philcore/secret\ntoken=ghp_aaa",
    code: "ENOENT",
    errno: -2,
    syscall: "spawn"
  };
  const d = assertNeverThrows("verbatim regression case", () =>
    buildSpawnDiagnostic({ status: null, signal: null, error: err }, { elapsedMs: 1 })
  );
  assert.equal(d.errorName, null);
  assert.equal(d.errorCode, "ENOENT");
  assert.equal(d.errorErrno, -2);
  assert.equal(d.errorSyscall, "spawn");
  const json = JSON.stringify(d);
  assert.equal(json.includes("/Users/"), false, "regression: must not leak the poisoned path");
  assert.equal(json.includes("token="), false, "regression: must not leak the poisoned token= content");
  assert.equal(json.includes("ghp_"), false, "regression: must not leak the poisoned ghp_ secret");
}

console.log("ok - desktop e2e spawn diagnostic formatter (adversarial)");
