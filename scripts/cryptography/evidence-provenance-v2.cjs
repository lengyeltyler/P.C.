"use strict";

/**
 * PhilCore Package 6A — evidence provenance schema v2 core mechanics.
 *
 * Fail-closed legacy freeze, deterministic canonicalization, domain-framed
 * digests, external-temp observation/attestation staging, and git-bound
 * provenance records.
 *
 * Attestation digests are not signatures and provide no non-repudiation.
 * No network, hardware, signing, or new dependencies.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../..");

const OWNER_LOCKED_BASELINE_COMMIT =
  "d1d85696fbb6800de68eec4b6bc20177e8b14e42";
const OWNER_LOCKED_BASELINE_TREE =
  "5293c0aa38055771424acf52ca47489ef406b307";

const RESOURCE_LIMITS = Object.freeze({
  MAX_RAW_STAGED_BYTES: 65536,
  MAX_NESTING_DEPTH: 16,
  MAX_TOTAL_NODES: 2048,
  MAX_OBJECT_KEYS: 128,
  MAX_ARRAY_LENGTH: 256,
  MAX_STRING_LENGTH: 4096
});

const DIGEST_FRAMING_PREFIX = "PHILCORE_EVIDENCE_PROVENANCE_V2";
const DIGEST_DOMAINS = Object.freeze({
  COMPUTED: "COMPUTED",
  OBSERVED: "OBSERVED",
  OPERATOR_ATTESTED: "OPERATOR_ATTESTED",
  RECORD: "RECORD"
});

const LEGACY_EVIDENCE_FROZEN = "LEGACY_EVIDENCE_FROZEN";
const PROVENANCE_SCHEMA_VERSION = 2;
const PROVENANCE_V2_DIR = "config/provenance/v2";
const LEGACY_LOCK_PATH = "config/provenance/legacy-evidence-lock.json";

const ATTESTATION_NON_REPUDIATION_NOTICE =
  "Attestation digests are not signatures and provide no non-repudiation.";

const DANGEROUS_JSON_KEYS = Object.freeze([
  "__proto__",
  "constructor",
  "prototype"
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

const OPERATOR_ROLES = Object.freeze([
  "RELEASE_OPERATOR",
  "SECURITY_REVIEWER",
  "EVIDENCE_WITNESS",
  "CI_AUTOMATION"
]);

const OBSERVATION_KEYS = Object.freeze([
  "schemaVersion",
  "observationKind",
  "platform",
  "osVersion",
  "simulator",
  "xcodeVersion",
  "runtime",
  "destinationName",
  "testFilter",
  "result",
  "executedAt",
  "notes"
]);

const ATTESTATION_KEYS = Object.freeze([
  "schemaVersion",
  "attestationKind",
  "operatorRole",
  "statement",
  "attestedAt",
  "scope"
]);

const DENY_SUBSTRINGS = Object.freeze([
  "username",
  "password",
  "token",
  "api_key",
  "apikey",
  "private_key",
  "privatekey",
  "mnemonic",
  "seed",
  "phil_secret",
  "nullifier",
  "witness",
  "biometric",
  "serial",
  "udid",
  "credentialid",
  "credential_id",
  "identityroot",
  "offlinerecovery",
  "offline_factor",
  "offlinefactor",
  "commitment",
  "proof_input",
  "proofinput",
  "recovery_factor",
  "recoveryfactor"
]);

const DISCLOSURE_ABSOLUTE_RES = Object.freeze([
  /\/Users\//,
  /\/home\//,
  /\/private\//,
  /\/tmp\//,
  /\/var\//,
  /\/etc\//,
  /\/Volumes\//,
  /~\//,
  /[A-Za-z]:[\\/]/,
  /\\\\[^\\]+/
]);

const DIGEST_DOMAIN_VALUES = new Set(Object.values(DIGEST_DOMAINS));
const DANGEROUS_JSON_KEY_SET = new Set(DANGEROUS_JSON_KEYS);

function provenanceError(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

function normalizeInputString(value) {
  const raw = String(value);
  // Bound before NFC / CRLF work. Callers that already hold a huge string have
  // already allocated it; this helper bounds traversal and subsequent work only.
  if (raw.length > RESOURCE_LIMITS.MAX_STRING_LENGTH) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `String exceeds MAX_STRING_LENGTH (${RESOURCE_LIMITS.MAX_STRING_LENGTH})`
    );
  }
  const normalized = raw.normalize("NFC").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.length > RESOURCE_LIMITS.MAX_STRING_LENGTH) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `String exceeds MAX_STRING_LENGTH (${RESOURCE_LIMITS.MAX_STRING_LENGTH})`
    );
  }
  return normalized;
}

/**
 * Inspect type/size then read at most maxBytes+1 via a bounded FD loop.
 * Never uses unbounded readFileSync for provenance/staging/lock inputs.
 */
function readBoundedFileBytes(absPath, maxBytes = RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES) {
  let fd;
  try {
    let lst;
    try {
      lst = fs.lstatSync(absPath);
    } catch (err) {
      throw provenanceError(
        "INVALID_INPUT_FILE",
        `Input path not accessible: ${absPath}`
      );
    }
    if (lst.isSymbolicLink()) {
      throw provenanceError(
        "INVALID_INPUT_FILE",
        `Symlink rejected for bounded input read: ${absPath}`
      );
    }
    if (!lst.isFile()) {
      throw provenanceError(
        "INVALID_INPUT_FILE",
        `Bounded input must be a regular file: ${absPath}`
      );
    }
    if (lst.size > maxBytes) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `File exceeds MAX_RAW_STAGED_BYTES (${maxBytes}) before read`
      );
    }
    const openFlags =
      fs.constants.O_RDONLY |
      (fs.constants.O_NOFOLLOW !== undefined ? fs.constants.O_NOFOLLOW : 0);
    fd = fs.openSync(absPath, openFlags);
    const chunks = [];
    let total = 0;
    const buf = Buffer.alloc(Math.min(65536, maxBytes + 1));
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) {
        throw provenanceError(
          "RESOURCE_LIMIT_EXCEEDED",
          `File exceeds MAX_RAW_STAGED_BYTES (${maxBytes}) during bounded read`
        );
      }
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    // Post-read growth race: re-stat and reject if the file grew past the limit.
    const after = fs.fstatSync(fd);
    if (after.size > maxBytes) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `File grew past MAX_RAW_STAGED_BYTES (${maxBytes}) during read`
      );
    }
    return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, total);
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore close errors on cleanup paths
      }
    }
  }
}

function lstatOrMissing(absPath) {
  try {
    return fs.lstatSync(absPath);
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    throw err;
  }
}

function sha256Buffer(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256File(absPath) {
  return sha256Buffer(fs.readFileSync(absPath));
}

function assertDangerousJsonKey(key) {
  if (DANGEROUS_JSON_KEY_SET.has(key)) {
    throw provenanceError(
      "DANGEROUS_JSON_KEY",
      `DANGEROUS_JSON_KEY: rejected key "${key}"`
    );
  }
}

function matchesDeniedDisclosure(text) {
  const normalized = normalizeInputString(text);
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if (code === 0) return true;
    if (code < 0x20 && code !== 0x09 && code !== 0x0a) return true;
  }
  for (const re of DISCLOSURE_ABSOLUTE_RES) {
    if (re.test(normalized)) return true;
  }
  if (/\$[A-Z_][A-Z0-9_]*|process\.env|ENV\s*=/i.test(normalized)) {
    return true;
  }
  const lower = normalized.toLowerCase();
  for (const needle of DENY_SUBSTRINGS) {
    if (lower.includes(needle)) return true;
  }
  return false;
}

function assertFullCommitSha(value, field = "commit") {
  if (typeof value !== "string") {
    throw provenanceError(
      "INVALID_COMMIT_SHA",
      `${field} must be a string`
    );
  }
  if (value !== value.trim() || value.length !== 40) {
    throw provenanceError(
      "INVALID_COMMIT_SHA",
      `${field} must be exactly 40 lowercase hex characters`
    );
  }
  if (value.startsWith("-")) {
    throw provenanceError(
      "INVALID_COMMIT_SHA",
      `${field} must not look like a CLI option`
    );
  }
  if (!/^[0-9a-f]{40}$/.test(value)) {
    throw provenanceError(
      "INVALID_COMMIT_SHA",
      `${field} must match /^[0-9a-f]{40}$/`
    );
  }
  return value;
}

function canonicalizeNumber(value) {
  if (!Number.isFinite(value)) {
    throw provenanceError(
      "CANONICALIZE_REJECTED",
      "Non-finite numbers are rejected"
    );
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw provenanceError(
      "CANONICALIZE_REJECTED",
      "Non-safe integers are rejected"
    );
  }
  const normalized = Object.is(value, -0) ? 0 : value;
  return JSON.stringify(normalized);
}

function digestDomain(domainConstant, value) {
  if (!DIGEST_DOMAIN_VALUES.has(domainConstant)) {
    throw provenanceError(
      "DIGEST_DOMAIN_INVALID",
      `digestDomain requires a DIGEST_DOMAINS constant, got ${String(domainConstant)}`
    );
  }
  const canonical = canonicalize(value);
  const framed = `${DIGEST_FRAMING_PREFIX}\0${domainConstant}\0${canonical}`;
  return sha256Buffer(Buffer.from(framed, "utf8"));
}

function digestComputed(value) {
  return digestDomain(DIGEST_DOMAINS.COMPUTED, value);
}

function digestObserved(value) {
  return digestDomain(DIGEST_DOMAINS.OBSERVED, value);
}

function digestAttested(value) {
  return digestDomain(DIGEST_DOMAINS.OPERATOR_ATTESTED, value);
}

function digestRecord(value) {
  return digestDomain(DIGEST_DOMAINS.RECORD, value);
}

function digestCanonical(value) {
  return digestRecord(value);
}

function loadLegacyLock(repoRoot = ROOT) {
  const abs = path.join(repoRoot, LEGACY_LOCK_PATH);
  const text = readBoundedFileBytes(abs).toString("utf8");
  const lock = parseJsonStrictNoDuplicateKeys(text);
  if (!lock || typeof lock !== "object" || !Array.isArray(lock.artifacts)) {
    throw provenanceError(
      "LEGACY_LOCK_INVALID",
      `Invalid legacy evidence lock at ${LEGACY_LOCK_PATH}`
    );
  }
  return lock;
}

function gitSpawn(repoRoot, args) {
  return spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "buffer",
    maxBuffer: 32 * 1024 * 1024
  });
}

function resolveCommit(repoRoot, rev) {
  const sha = assertFullCommitSha(rev, "commit");
  const result = gitSpawn(repoRoot, ["rev-parse", "--verify", `${sha}^{commit}`]);
  if (result.status !== 0) {
    throw provenanceError(
      "SOURCE_BASELINE_UNAVAILABLE",
      `SOURCE_BASELINE_UNAVAILABLE: revision ${sha}`
    );
  }
  return result.stdout.toString("utf8").trim();
}

function resolveCommitTree(repoRoot, rev) {
  const sha = assertFullCommitSha(rev, "commit");
  const result = gitSpawn(repoRoot, ["rev-parse", `${sha}^{tree}`]);
  if (result.status !== 0) {
    throw provenanceError(
      "SOURCE_BASELINE_UNAVAILABLE",
      `SOURCE_BASELINE_UNAVAILABLE: cannot resolve tree for ${sha}`
    );
  }
  return result.stdout.toString("utf8").trim();
}

function gitShow(repoRoot, rev, relativePath) {
  assertRelativePosixPath(relativePath);
  const sha = assertFullCommitSha(rev, "commit");
  const result = gitSpawn(repoRoot, ["show", `${sha}:${relativePath}`]);
  if (result.status !== 0) {
    const errText = (result.stderr || Buffer.alloc(0)).toString("utf8");
    const combined = `${errText}\n${(result.stdout || Buffer.alloc(0)).toString("utf8")}`;
    const revCheck = gitSpawn(repoRoot, [
      "rev-parse",
      "--verify",
      `${sha}^{commit}`
    ]);
    if (revCheck.status !== 0) {
      throw provenanceError(
        "SOURCE_BASELINE_UNAVAILABLE",
        `SOURCE_BASELINE_UNAVAILABLE: revision ${sha}`
      );
    }
    if (
      /unknown revision|bad revision|invalid object name|ambiguous argument/i.test(
        combined
      ) ||
      /exists on disk, but not in/i.test(combined)
    ) {
      throw provenanceError(
        "SOURCE_BLOB_MISSING",
        `SOURCE_BLOB_MISSING: ${sha}:${relativePath}`
      );
    }
    throw provenanceError(
      "SOURCE_BLOB_MISSING",
      `SOURCE_BLOB_MISSING: ${sha}:${relativePath}`
    );
  }
  return Buffer.from(result.stdout || Buffer.alloc(0));
}

function verifyLegacyLockedArtifacts({
  repoRoot = ROOT,
  gitRepoRoot = repoRoot
} = {}) {
  const lock = loadLegacyLock(repoRoot);
  assertFullCommitSha(lock.lockedAtCommit, "lockedAtCommit");
  if (lock.lockedAtCommit !== OWNER_LOCKED_BASELINE_COMMIT) {
    throw provenanceError(
      "LEGACY_LOCK_INVALID",
      "lockedAtCommit does not match owner locked baseline"
    );
  }
  if (lock.lockedAtTree !== OWNER_LOCKED_BASELINE_TREE) {
    throw provenanceError(
      "LEGACY_LOCK_INVALID",
      "lockedAtTree does not match owner locked baseline tree"
    );
  }

  const pending = [];
  for (const art of lock.artifacts) {
    if (!art || typeof art.path !== "string" || typeof art.sha256 !== "string") {
      throw provenanceError(
        "LEGACY_LOCK_INVALID",
        "Legacy lock artifact entry missing path/sha256"
      );
    }
    assertRelativePosixPath(art.path);
    assertFullCommitSha(art.baselineCommit, "baselineCommit");
    if (art.baselineCommit !== OWNER_LOCKED_BASELINE_COMMIT) {
      throw provenanceError(
        "LEGACY_LOCK_INVALID",
        `artifact baselineCommit must equal ${OWNER_LOCKED_BASELINE_COMMIT}`
      );
    }

    const abs = path.join(repoRoot, art.path);
    if (!fs.existsSync(abs)) {
      throw provenanceError(
        "LEGACY_ARTIFACT_MISSING",
        `LEGACY_ARTIFACT_MISSING: ${art.path}`
      );
    }
    const currentHash = sha256File(abs);
    if (art.sha256 !== currentHash) {
      throw provenanceError(
        "LEGACY_ARTIFACT_MISMATCH",
        `LEGACY_ARTIFACT_MISMATCH: ${art.path} expected ${art.sha256} got ${currentHash}`
      );
    }
    pending.push(art);
  }

  let resolvedCommit;
  let resolvedTree;
  try {
    resolvedCommit = resolveCommit(gitRepoRoot, lock.lockedAtCommit);
    resolvedTree = resolveCommitTree(gitRepoRoot, resolvedCommit);
  } catch (err) {
    if (err && err.code === "SOURCE_BASELINE_UNAVAILABLE") {
      throw provenanceError(
        "LEGACY_BASELINE_UNAVAILABLE",
        `LEGACY_BASELINE_UNAVAILABLE: ${lock.lockedAtCommit}`
      );
    }
    throw err;
  }
  if (resolvedTree !== OWNER_LOCKED_BASELINE_TREE) {
    throw provenanceError(
      "LEGACY_BASELINE_UNAVAILABLE",
      `LEGACY_BASELINE_UNAVAILABLE: tree mismatch for ${lock.lockedAtCommit}`
    );
  }

  const artifacts = [];
  for (const art of pending) {
    let baselineBytes;
    try {
      baselineBytes = gitShow(gitRepoRoot, art.baselineCommit, art.path);
    } catch (err) {
      if (err && err.code === "SOURCE_BASELINE_UNAVAILABLE") {
        throw provenanceError(
          "LEGACY_BASELINE_UNAVAILABLE",
          `LEGACY_BASELINE_UNAVAILABLE: ${art.baselineCommit}`
        );
      }
      if (err && err.code === "SOURCE_BLOB_MISSING") {
        throw provenanceError(
          "LEGACY_BASELINE_BLOB_MISMATCH",
          `LEGACY_BASELINE_BLOB_MISMATCH: ${art.path}`
        );
      }
      throw err;
    }
    const baselineHash = sha256Buffer(baselineBytes);

    if (baselineHash !== art.sha256) {
      throw provenanceError(
        "LEGACY_BASELINE_BLOB_MISMATCH",
        `LEGACY_BASELINE_BLOB_MISMATCH: ${art.path}`
      );
    }

    artifacts.push({
      id: art.id,
      path: art.path,
      sha256: art.sha256,
      baselineCommit: art.baselineCommit
    });
  }
  return { ok: true, artifacts };
}

function collectEscapeAttempts(argv, env) {
  const args = Array.isArray(argv) ? argv : [];
  const flags = [];
  for (const arg of args) {
    if (typeof arg !== "string") continue;
    const base = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
    if (OVERWRITE_ESCAPE_FLAGS.includes(base) || OVERWRITE_ESCAPE_FLAGS.includes(arg)) {
      flags.push(arg);
    }
  }
  const envHits = [];
  for (const name of OVERWRITE_ESCAPE_ENV) {
    if (env && env[name] !== undefined && env[name] !== "") {
      envHits.push(name);
    }
  }
  for (const name of OVERWRITE_ESCAPE_ENV) {
    if (
      process.env[name] !== undefined &&
      process.env[name] !== "" &&
      !envHits.includes(name)
    ) {
      envHits.push(name);
    }
  }
  for (const arg of process.argv) {
    if (typeof arg !== "string") continue;
    const base = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
    if (
      (OVERWRITE_ESCAPE_FLAGS.includes(base) ||
        OVERWRITE_ESCAPE_FLAGS.includes(arg)) &&
      !flags.includes(arg)
    ) {
      flags.push(arg);
    }
  }
  return { flags, envHits };
}

function refuseLegacyEvidenceWrite(options = {}) {
  const argv = options.argv !== undefined ? options.argv : process.argv;
  const env = options.env !== undefined ? options.env : process.env;
  collectEscapeAttempts(argv, env);
  throw provenanceError(
    LEGACY_EVIDENCE_FROZEN,
    `${LEGACY_EVIDENCE_FROZEN}: legacy evidence artifacts are permanently frozen; overwrite flags and break-glass environment variables are not honored`
  );
}

function assertNoLegacyOverwriteEscape(options = {}) {
  const argv = options.argv !== undefined ? options.argv : process.argv;
  const env = options.env !== undefined ? options.env : process.env;
  const { flags, envHits } = collectEscapeAttempts(argv, env);
  if (flags.length > 0 || envHits.length > 0) {
    throw provenanceError(
      LEGACY_EVIDENCE_FROZEN,
      `${LEGACY_EVIDENCE_FROZEN}: overwrite escape attempt ignored (flags=${flags.join(",") || "none"} env=${envHits.join(",") || "none"})`
    );
  }
  return { ok: true, escapesHonored: false };
}

function assertRelativePosixPath(p) {
  if (typeof p !== "string" || p.length === 0) {
    throw provenanceError(
      "INVALID_RELATIVE_PATH",
      "Relative path must be a non-empty string"
    );
  }
  if (p.startsWith("~")) {
    throw provenanceError("INVALID_RELATIVE_PATH", `Home path rejected: ${p}`);
  }
  if (p.includes("\\") || p.startsWith("/") || /^[A-Za-z]:/.test(p)) {
    throw provenanceError(
      "INVALID_RELATIVE_PATH",
      `Absolute or non-POSIX path rejected: ${p}`
    );
  }
  if (path.isAbsolute(p)) {
    throw provenanceError(
      "INVALID_RELATIVE_PATH",
      `Absolute path rejected: ${p}`
    );
  }
  if (p.includes("\0")) {
    throw provenanceError("INVALID_RELATIVE_PATH", "NUL in path");
  }
  for (const seg of p.split("/")) {
    if (seg === "..") {
      throw provenanceError(
        "INVALID_RELATIVE_PATH",
        `Path escape segment rejected: ${p}`
      );
    }
  }
  return p;
}

function realpathSafe(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    const parent = path.dirname(p);
    try {
      return path.join(fs.realpathSync(parent), path.basename(p));
    } catch {
      return path.resolve(p);
    }
  }
}

function pathUnder(root, candidate) {
  const rootNorm = root.endsWith(path.sep) ? root : root + path.sep;
  return candidate === root || candidate.startsWith(rootNorm);
}

function isInsideGitWorkTree(absPath) {
  let cur = absPath;
  try {
    if (fs.existsSync(absPath) && fs.statSync(absPath).isDirectory()) {
      cur = absPath;
    } else {
      cur = path.dirname(absPath);
    }
  } catch {
    cur = path.dirname(absPath);
  }
  let probe = cur;
  for (;;) {
    if (fs.existsSync(path.join(probe, ".git"))) return true;
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  const gitCheck = spawnSync(
    "git",
    ["-C", cur, "rev-parse", "--is-inside-work-tree"],
    { encoding: "utf8" }
  );
  return (
    gitCheck.status === 0 && String(gitCheck.stdout || "").trim() === "true"
  );
}

function assertExternalTempPath(p, { repoRoot = ROOT } = {}) {
  if (typeof p !== "string" || p.length === 0 || !path.isAbsolute(p)) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      "External temp path must be absolute"
    );
  }
  if (p.includes("\0")) {
    throw provenanceError("INVALID_EXTERNAL_TEMP_PATH", "NUL in path");
  }
  let lst;
  try {
    lst = fs.lstatSync(p);
  } catch {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `External temp path not accessible: ${p}`
    );
  }
  if (lst.isSymbolicLink()) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `Symlink rejected for external temp path: ${p}`
    );
  }
  if (!lst.isFile()) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `External temp path must be a regular file: ${p}`
    );
  }
  const abs = realpathSafe(p);
  const tmpRoot = realpathSafe(os.tmpdir());
  if (!pathUnder(tmpRoot, abs)) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `Path is not under os.tmpdir(): ${p}`
    );
  }
  const repoAbs = realpathSafe(repoRoot);
  if (pathUnder(repoAbs, abs)) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `External temp path must not be under repo root: ${p}`
    );
  }
  if (isInsideGitWorkTree(abs)) {
    throw provenanceError(
      "INVALID_EXTERNAL_TEMP_PATH",
      `External temp path must not be inside a git worktree: ${p}`
    );
  }
  return abs;
}

function safeUnlinkOwned(p, ownedSet) {
  if (!ownedSet || !ownedSet.has(p)) return;
  try {
    const lst = fs.lstatSync(p);
    if (lst.isSymbolicLink() || !lst.isFile()) return;
    const tmpRoot = realpathSafe(os.tmpdir());
    const abs = realpathSafe(p);
    if (!pathUnder(tmpRoot, abs)) return;
    fs.unlinkSync(p);
    ownedSet.delete(p);
  } catch {
    // best-effort cleanup
  }
}

function cleanupOwnedTemps(ownedSet) {
  if (!ownedSet) return;
  for (const p of [...ownedSet]) {
    safeUnlinkOwned(p, ownedSet);
  }
}

/* -------------------------------------------------------------------------- */
/* JSON strict parse (reject duplicate keys before JSON.parse can discard)    */
/* -------------------------------------------------------------------------- */

function parseJsonStrictNoDuplicateKeys(text) {
  if (typeof text !== "string") {
    throw provenanceError("INVALID_JSON", "JSON text must be a string");
  }
  if (Buffer.byteLength(text, "utf8") > RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `JSON exceeds MAX_RAW_STAGED_BYTES (${RESOURCE_LIMITS.MAX_RAW_STAGED_BYTES})`
    );
  }

  const s = text;
  let i = 0;
  let totalNodes = 0;

  function peek() {
    return s[i];
  }

  function advance() {
    return s[i++];
  }

  function skipWs() {
    while (i < s.length) {
      const c = s[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
      else break;
    }
  }

  function fail(msg) {
    throw provenanceError("INVALID_JSON", `${msg} at index ${i}`);
  }

  function parseString() {
    if (advance() !== '"') fail("expected string");
    let out = "";
    while (i < s.length) {
      const c = advance();
      if (c === '"') {
        if (out.length > RESOURCE_LIMITS.MAX_STRING_LENGTH) {
          throw provenanceError(
            "RESOURCE_LIMIT_EXCEEDED",
            `String exceeds MAX_STRING_LENGTH (${RESOURCE_LIMITS.MAX_STRING_LENGTH})`
          );
        }
        return out;
      }
      if (out.length >= RESOURCE_LIMITS.MAX_STRING_LENGTH) {
        throw provenanceError(
          "RESOURCE_LIMIT_EXCEEDED",
          `String exceeds MAX_STRING_LENGTH (${RESOURCE_LIMITS.MAX_STRING_LENGTH})`
        );
      }
      if (c === "\\") {
        if (i >= s.length) fail("truncated escape");
        const e = advance();
        switch (e) {
          case '"':
          case "\\":
          case "/":
            out += e;
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "\t";
            break;
          case "u": {
            if (i + 4 > s.length) fail("truncated unicode escape");
            const hex = s.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad unicode escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail(`invalid escape \\${e}`);
        }
      } else {
        if (c.charCodeAt(0) < 0x20) fail("unescaped control character");
        out += c;
      }
    }
    fail("unterminated string");
  }

  function parseNumber() {
    const start = i;
    if (peek() === "-") i++;
    if (peek() === "0") {
      i++;
    } else if (peek() >= "1" && peek() <= "9") {
      while (peek() >= "0" && peek() <= "9") i++;
    } else {
      fail("invalid number");
    }
    if (peek() === ".") {
      i++;
      if (!(peek() >= "0" && peek() <= "9")) fail("invalid fraction");
      while (peek() >= "0" && peek() <= "9") i++;
    }
    if (peek() === "e" || peek() === "E") {
      i++;
      if (peek() === "+" || peek() === "-") i++;
      if (!(peek() >= "0" && peek() <= "9")) fail("invalid exponent");
      while (peek() >= "0" && peek() <= "9") i++;
    }
    const raw = s.slice(start, i);
    const n = Number(raw);
    if (!Number.isFinite(n)) fail("non-finite number");
    if (Number.isInteger(n) && !Number.isSafeInteger(n)) {
      fail("non-safe integer");
    }
    return n;
  }

  function parseLiteral(lit, value) {
    if (s.slice(i, i + lit.length) !== lit) fail(`expected ${lit}`);
    i += lit.length;
    return value;
  }

  function bumpNodeCount() {
    totalNodes += 1;
    if (totalNodes > RESOURCE_LIMITS.MAX_TOTAL_NODES) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Exceeded MAX_TOTAL_NODES (${RESOURCE_LIMITS.MAX_TOTAL_NODES})`
      );
    }
  }

  function parseArray(depth) {
    if (depth > RESOURCE_LIMITS.MAX_NESTING_DEPTH) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Exceeded MAX_NESTING_DEPTH (${RESOURCE_LIMITS.MAX_NESTING_DEPTH})`
      );
    }
    bumpNodeCount();
    if (advance() !== "[") fail("expected [");
    skipWs();
    const arr = [];
    if (peek() === "]") {
      advance();
      return arr;
    }
    for (;;) {
      skipWs();
      // Reject the next element before parsing/allocating it when already at limit.
      if (arr.length >= RESOURCE_LIMITS.MAX_ARRAY_LENGTH) {
        throw provenanceError(
          "RESOURCE_LIMIT_EXCEEDED",
          `Array exceeds MAX_ARRAY_LENGTH (${RESOURCE_LIMITS.MAX_ARRAY_LENGTH})`
        );
      }
      arr.push(parseValue(depth + 1));
      skipWs();
      if (peek() === ",") {
        advance();
        continue;
      }
      if (peek() === "]") {
        advance();
        return arr;
      }
      fail("expected , or ]");
    }
  }

  function parseObject(depth) {
    if (depth > RESOURCE_LIMITS.MAX_NESTING_DEPTH) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Exceeded MAX_NESTING_DEPTH (${RESOURCE_LIMITS.MAX_NESTING_DEPTH})`
      );
    }
    bumpNodeCount();
    if (advance() !== "{") fail("expected {");
    skipWs();
    const obj = Object.create(null);
    const seen = new Set();
    if (peek() === "}") {
      advance();
      return obj;
    }
    for (;;) {
      skipWs();
      if (peek() !== '"') fail("expected object key string");
      const key = parseString();
      assertDangerousJsonKey(key);
      if (seen.has(key)) {
        throw provenanceError(
          "DUPLICATE_JSON_KEY",
          `DUPLICATE_JSON_KEY: duplicate key "${key}"`
        );
      }
      seen.add(key);
      if (seen.size > RESOURCE_LIMITS.MAX_OBJECT_KEYS) {
        throw provenanceError(
          "RESOURCE_LIMIT_EXCEEDED",
          `Object exceeds MAX_OBJECT_KEYS (${RESOURCE_LIMITS.MAX_OBJECT_KEYS})`
        );
      }
      skipWs();
      if (advance() !== ":") fail("expected :");
      skipWs();
      obj[key] = parseValue(depth + 1);
      skipWs();
      if (peek() === ",") {
        advance();
        continue;
      }
      if (peek() === "}") {
        advance();
        return obj;
      }
      fail("expected , or }");
    }
  }

  function parseValue(depth) {
    skipWs();
    const c = peek();
    if (c === undefined) fail("unexpected end");
    if (c === '"') {
      bumpNodeCount();
      return parseString();
    }
    if (c === "{") return parseObject(depth);
    if (c === "[") return parseArray(depth);
    if (c === "t") {
      bumpNodeCount();
      return parseLiteral("true", true);
    }
    if (c === "f") {
      bumpNodeCount();
      return parseLiteral("false", false);
    }
    if (c === "n") {
      bumpNodeCount();
      return parseLiteral("null", null);
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      bumpNodeCount();
      return parseNumber();
    }
    fail(`unexpected character ${JSON.stringify(c)}`);
  }

  skipWs();
  const value = parseValue(0);
  skipWs();
  if (i < s.length) {
    throw provenanceError(
      "INVALID_JSON",
      `Trailing content after JSON value at index ${i}`
    );
  }
  return revivePlain(value);
}

function revivePlain(value) {
  if (Array.isArray(value)) return value.map(revivePlain);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value)) {
      assertDangerousJsonKey(key);
      out[key] = revivePlain(value[key]);
    }
    return out;
  }
  return value;
}

/* -------------------------------------------------------------------------- */
/* Canonicalization                                                           */
/* -------------------------------------------------------------------------- */

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function canonicalize(value) {
  const visited = new WeakSet();
  let totalNodes = 0;
  return canonicalizeInner(value, 0, visited, () => {
    totalNodes += 1;
    if (totalNodes > RESOURCE_LIMITS.MAX_TOTAL_NODES) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Exceeded MAX_TOTAL_NODES (${RESOURCE_LIMITS.MAX_TOTAL_NODES})`
      );
    }
  });
}

function canonicalizeInner(value, depth, visited, bumpNode) {
  bumpNode();
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return canonicalizeNumber(value);
  if (t === "string") {
    // normalizeInputString checks raw length before NFC and normalized length after.
    const normalized = normalizeInputString(value);
    return JSON.stringify(normalized);
  }
  if (t === "undefined") {
    throw provenanceError("CANONICALIZE_REJECTED", "undefined is rejected");
  }
  if (t === "function") {
    throw provenanceError("CANONICALIZE_REJECTED", "functions are rejected");
  }
  if (t === "symbol") {
    throw provenanceError("CANONICALIZE_REJECTED", "symbols are rejected");
  }
  if (t === "bigint") {
    throw provenanceError("CANONICALIZE_REJECTED", "BigInt is rejected");
  }
  if (t !== "object") {
    throw provenanceError(
      "CANONICALIZE_REJECTED",
      `Unsupported type: ${t}`
    );
  }
  if (visited.has(value)) {
    throw provenanceError("PROVENANCE_CYCLE", "PROVENANCE_CYCLE");
  }
  if (value instanceof Date) {
    throw provenanceError("CANONICALIZE_REJECTED", "Date is rejected");
  }
  if (value instanceof Map || value instanceof Set) {
    throw provenanceError("CANONICALIZE_REJECTED", "Map/Set are rejected");
  }
  if (Buffer.isBuffer(value)) {
    throw provenanceError("CANONICALIZE_REJECTED", "Buffer is rejected");
  }
  if (ArrayBuffer.isView(value)) {
    throw provenanceError("CANONICALIZE_REJECTED", "Typed arrays are rejected");
  }
  if (depth > RESOURCE_LIMITS.MAX_NESTING_DEPTH) {
    throw provenanceError(
      "RESOURCE_LIMIT_EXCEEDED",
      `Exceeded MAX_NESTING_DEPTH (${RESOURCE_LIMITS.MAX_NESTING_DEPTH})`
    );
  }

  visited.add(value);

  if (Array.isArray(value)) {
    if (value.length > RESOURCE_LIMITS.MAX_ARRAY_LENGTH) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Array exceeds MAX_ARRAY_LENGTH (${RESOURCE_LIMITS.MAX_ARRAY_LENGTH})`
      );
    }
    const parts = value.map((v) =>
      canonicalizeInner(v, depth + 1, visited, bumpNode)
    );
    visited.delete(value);
    return `[${parts.join(",")}]`;
  }
  if (!isPlainObject(value)) {
    throw provenanceError(
      "CANONICALIZE_REJECTED",
      "Non-plain objects are rejected"
    );
  }
  // Early-stop key enumeration before allocating+sorting a complete key list
  // from Object.keys(). Note: if the caller already constructed an oversized
  // object, that memory was allocated before this helper ran; we only bound
  // traversal and subsequent canonicalization allocation here.
  const keys = [];
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    assertDangerousJsonKey(key);
    keys.push(key);
    if (keys.length > RESOURCE_LIMITS.MAX_OBJECT_KEYS) {
      throw provenanceError(
        "RESOURCE_LIMIT_EXCEEDED",
        `Object exceeds MAX_OBJECT_KEYS (${RESOURCE_LIMITS.MAX_OBJECT_KEYS})`
      );
    }
  }
  keys.sort((a, b) => {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  });
  const parts = [];
  for (const key of keys) {
    assertDangerousJsonKey(key);
    const v = value[key];
    if (v === undefined) {
      throw provenanceError(
        "CANONICALIZE_REJECTED",
        `undefined property rejected: ${key}`
      );
    }
    parts.push(
      `${JSON.stringify(normalizeInputString(key))}:${canonicalizeInner(v, depth + 1, visited, bumpNode)}`
    );
  }
  visited.delete(value);
  return `{${parts.join(",")}}`;
}

function assertProvenanceSourceTreeClean(repoRoot) {
  const result = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  if (result.status !== 0) {
    throw provenanceError(
      "PROVENANCE_SOURCE_TREE_DIRTY",
      `PROVENANCE_SOURCE_TREE_DIRTY: git status failed: ${result.stderr || result.error}`
    );
  }
  if ((result.stdout || "").trim().length > 0) {
    throw provenanceError(
      "PROVENANCE_SOURCE_TREE_DIRTY",
      "PROVENANCE_SOURCE_TREE_DIRTY: working tree is not clean"
    );
  }
  return { ok: true };
}

function assertSourceBaselineBinding({
  repoRoot,
  sourceBaselineCommit,
  sourceBaselineTree
} = {}) {
  if (!repoRoot || !sourceBaselineCommit || !sourceBaselineTree) {
    throw provenanceError(
      "SOURCE_BASELINE_UNAVAILABLE",
      "SOURCE_BASELINE_UNAVAILABLE: missing binding fields"
    );
  }
  assertFullCommitSha(sourceBaselineCommit, "sourceBaselineCommit");
  const resolvedCommit = resolveCommit(repoRoot, sourceBaselineCommit);
  const tree = resolveCommitTree(repoRoot, resolvedCommit);
  if (tree !== sourceBaselineTree) {
    throw provenanceError(
      "SOURCE_BASELINE_TREE_MISMATCH",
      `SOURCE_BASELINE_TREE_MISMATCH: expected ${sourceBaselineTree} got ${tree}`
    );
  }
  return {
    ok: true,
    sourceBaselineCommit: resolvedCommit,
    sourceBaselineTree: tree
  };
}

function assertEvidenceContainerBinding({
  repoRoot,
  sourceBaselineCommit,
  sourceBaselineTree,
  containerCommit
} = {}) {
  if (!repoRoot || !sourceBaselineCommit || !sourceBaselineTree) {
    throw provenanceError(
      "SOURCE_BASELINE_UNAVAILABLE",
      "SOURCE_BASELINE_UNAVAILABLE: missing binding fields"
    );
  }
  if (!containerCommit) {
    throw provenanceError(
      "CONTAINER_COMMIT_REQUIRED",
      "CONTAINER_COMMIT_REQUIRED: containerCommit is required"
    );
  }
  assertFullCommitSha(sourceBaselineCommit, "sourceBaselineCommit");
  assertFullCommitSha(containerCommit, "containerCommit");

  const resolvedBaseline = resolveCommit(repoRoot, sourceBaselineCommit);
  const baselineTree = resolveCommitTree(repoRoot, resolvedBaseline);
  if (baselineTree !== sourceBaselineTree) {
    throw provenanceError(
      "SOURCE_BASELINE_TREE_MISMATCH",
      `SOURCE_BASELINE_TREE_MISMATCH: expected ${sourceBaselineTree} got ${baselineTree}`
    );
  }

  const resolvedContainer = resolveCommit(repoRoot, containerCommit);
  if (resolvedContainer === resolvedBaseline) {
    throw provenanceError(
      "SELF_REFERENCE",
      "SELF_REFERENCE: containerCommit must not equal sourceBaselineCommit"
    );
  }

  const parentsResult = gitSpawn(repoRoot, [
    "rev-parse",
    `${resolvedContainer}^@`
  ]);
  if (parentsResult.status !== 0) {
    throw provenanceError(
      "SOURCE_BASELINE_NOT_DEDICATED_CHILD",
      "SOURCE_BASELINE_NOT_DEDICATED_CHILD: cannot list container parents"
    );
  }
  const parents = parentsResult.stdout
    .toString("utf8")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (parents.length !== 1) {
    throw provenanceError(
      "SOURCE_BASELINE_MERGE_CONTAINER",
      "SOURCE_BASELINE_MERGE_CONTAINER: containerCommit must have exactly one parent"
    );
  }
  if (parents[0] !== resolvedBaseline) {
    throw provenanceError(
      "SOURCE_BASELINE_NOT_DEDICATED_CHILD",
      "SOURCE_BASELINE_NOT_DEDICATED_CHILD: container parent must equal sourceBaselineCommit"
    );
  }

  return {
    ok: true,
    sourceBaselineCommit: resolvedBaseline,
    sourceBaselineTree: baselineTree,
    containerCommit: resolvedContainer
  };
}

function readSourcesAtBaseline(repoRoot, sourceBaselineCommit, relativePaths) {
  if (!Array.isArray(relativePaths)) {
    throw provenanceError(
      "INVALID_SOURCE_PATHS",
      "relativePaths must be an array"
    );
  }
  resolveCommit(repoRoot, sourceBaselineCommit);
  const map = Object.create(null);
  for (const rel of relativePaths) {
    assertRelativePosixPath(rel);
    map[rel] = gitShow(repoRoot, sourceBaselineCommit, rel);
  }
  return map;
}

function assertAllowedKey(key, allowlist, kind) {
  assertDangerousJsonKey(key);
  if (!allowlist.includes(key)) {
    throw provenanceError(
      "SANITIZE_UNKNOWN_KEY",
      `Unknown ${kind} key rejected: ${key}`
    );
  }
  if (matchesDeniedDisclosure(key)) {
    throw provenanceError(
      "SANITIZE_DENIED_KEY",
      `Denied ${kind} key rejected: ${key}`
    );
  }
}

function sanitizeStringValue(value, key) {
  if (typeof value !== "string") {
    throw provenanceError("SANITIZE_TYPE", `Expected string for ${key}`);
  }
  const normalized = normalizeInputString(value);
  if (matchesDeniedDisclosure(normalized)) {
    throw provenanceError(
      "SANITIZE_DENIED_VALUE",
      `Denied secret-shaped value for ${key}`
    );
  }
  if (key === "notes" && normalized.length > 2000) {
    throw provenanceError("SANITIZE_TOO_LONG", "notes exceeds length limit");
  }
  return normalized;
}

function sanitizeObservation(obj) {
  if (!isPlainObject(obj)) {
    throw provenanceError("SANITIZE_TYPE", "observation must be a plain object");
  }
  const out = {};
  for (const key of Object.keys(obj)) {
    assertAllowedKey(key, OBSERVATION_KEYS, "observation");
    const value = obj[key];
    if (key === "schemaVersion") {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw provenanceError("SANITIZE_TYPE", "schemaVersion must be a finite number");
      }
      out.schemaVersion = value;
      continue;
    }
    if (key === "simulator") {
      if (typeof value !== "boolean" && typeof value !== "string") {
        throw provenanceError("SANITIZE_TYPE", "simulator must be boolean or string");
      }
      out.simulator =
        typeof value === "string" ? sanitizeStringValue(value, key) : value;
      continue;
    }
    if (typeof value === "string") {
      out[key] = sanitizeStringValue(value, key);
      continue;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      out[key] = value;
      continue;
    }
    if (typeof value === "boolean") {
      out[key] = value;
      continue;
    }
    throw provenanceError(
      "SANITIZE_TYPE",
      `Unsupported observation value type for ${key}`
    );
  }
  return out;
}

function sanitizeAttestation(obj) {
  if (!isPlainObject(obj)) {
    throw provenanceError("SANITIZE_TYPE", "attestation must be a plain object");
  }
  const out = {};
  for (const key of Object.keys(obj)) {
    assertAllowedKey(key, ATTESTATION_KEYS, "attestation");
    const value = obj[key];
    if (key === "schemaVersion") {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw provenanceError("SANITIZE_TYPE", "schemaVersion must be a finite number");
      }
      out.schemaVersion = value;
      continue;
    }
    if (key === "operatorRole") {
      if (typeof value !== "string" || !OPERATOR_ROLES.includes(value)) {
        throw provenanceError(
          "SANITIZE_OPERATOR_ROLE",
          `operatorRole must be one of ${OPERATOR_ROLES.join(", ")}`
        );
      }
      out.operatorRole = value;
      continue;
    }
    if (typeof value === "string") {
      out[key] = sanitizeStringValue(value, key);
      continue;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      out[key] = value;
      continue;
    }
    if (typeof value === "boolean") {
      out[key] = value;
      continue;
    }
    throw provenanceError(
      "SANITIZE_TYPE",
      `Unsupported attestation value type for ${key}`
    );
  }
  return out;
}

function loadSanitizedJsonFromExternalTemp(
  absPath,
  sanitizer,
  repoRoot,
  ownedSet
) {
  const validated = assertExternalTempPath(absPath, { repoRoot });
  // Bound type/size inspection and FD read before materializing JSON text.
  const buf = readBoundedFileBytes(validated);
  ownedSet.add(validated);
  const parsed = parseJsonStrictNoDuplicateKeys(buf.toString("utf8"));
  return sanitizer(parsed);
}

function assertNoSymlinkComponents(repoRoot, relativeDir) {
  assertRelativePosixPath(relativeDir);
  const segments = relativeDir.split("/").filter(Boolean);
  let cur = repoRoot;
  for (const seg of segments) {
    cur = path.join(cur, seg);
    // lstat distinguishes real dirs, symlinks (including dangling), and missing.
    // Do not use existsSync — it returns false for dangling symlinks and would
    // skip the rejection path.
    const lst = lstatOrMissing(cur);
    if (lst === null) {
      // Genuinely missing component — later mkdir may create it.
      continue;
    }
    if (lst.isSymbolicLink()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Symlink rejected in provenance path component: ${seg}`
      );
    }
    if (!lst.isDirectory()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Output path component is not a directory: ${seg}`
      );
    }
  }
}

function ensureDirectoryNoSymlink(absDir) {
  const lst = lstatOrMissing(absDir);
  if (lst !== null) {
    if (lst.isSymbolicLink()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Symlink rejected for output directory: ${absDir}`
      );
    }
    if (!lst.isDirectory()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Output path component is not a directory: ${absDir}`
      );
    }
    return;
  }
  fs.mkdirSync(absDir, { recursive: true });
  const after = lstatOrMissing(absDir);
  if (after === null || after.isSymbolicLink() || !after.isDirectory()) {
    throw provenanceError(
      "PROVENANCE_OUTPUT_PATH",
      `Output directory creation failed safely: ${absDir}`
    );
  }
}

function assertOutputRelativePath(outputRelativePath, repoRoot) {
  assertRelativePosixPath(outputRelativePath);
  const prefix = `${PROVENANCE_V2_DIR}/`;
  if (
    outputRelativePath !== PROVENANCE_V2_DIR &&
    !outputRelativePath.startsWith(prefix)
  ) {
    throw provenanceError(
      "PROVENANCE_OUTPUT_PATH",
      `PROVENANCE_OUTPUT_PATH: output must be under ${PROVENANCE_V2_DIR}/`
    );
  }
  if (outputRelativePath === PROVENANCE_V2_DIR || outputRelativePath.endsWith("/")) {
    throw provenanceError(
      "PROVENANCE_OUTPUT_PATH",
      "PROVENANCE_OUTPUT_PATH: output must be a file path under v2/"
    );
  }
  assertNoSymlinkComponents(repoRoot, PROVENANCE_V2_DIR);
  const abs = path.join(repoRoot, outputRelativePath);
  const parentRel = path.dirname(outputRelativePath);
  assertNoSymlinkComponents(repoRoot, parentRel);

  // Leaf: reject existing regular files and any symlink leaf (including dangling).
  const leaf = lstatOrMissing(abs);
  if (leaf !== null) {
    if (leaf.isSymbolicLink()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Symlink rejected at provenance output leaf: ${outputRelativePath}`
      );
    }
    throw provenanceError(
      "PROVENANCE_OUTPUT_EXISTS",
      `PROVENANCE_OUTPUT_EXISTS: ${outputRelativePath}`
    );
  }

  ensureDirectoryNoSymlink(path.dirname(abs));
  assertNoSymlinkComponents(repoRoot, parentRel);
  // Re-check leaf after mkdir in case of concurrent create.
  const leafAfter = lstatOrMissing(abs);
  if (leafAfter !== null) {
    if (leafAfter.isSymbolicLink()) {
      throw provenanceError(
        "PROVENANCE_OUTPUT_PATH",
        `Symlink rejected at provenance output leaf: ${outputRelativePath}`
      );
    }
    throw provenanceError(
      "PROVENANCE_OUTPUT_EXISTS",
      `PROVENANCE_OUTPUT_EXISTS: ${outputRelativePath}`
    );
  }
  return abs;
}

function writeExclusiveNewFile(absPath, content) {
  const baseFlags =
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY;
  const openFlags =
    fs.constants.O_NOFOLLOW !== undefined
      ? baseFlags | fs.constants.O_NOFOLLOW
      : baseFlags;
  let fd;
  // True only after this invocation's exclusive open succeeds.
  let createdByThisInvocation = false;
  try {
    // Residual same-user parent-directory race: a hostile concurrent mutation in
    // the same user namespace could replace a parent directory between validation
    // and open so the new file is created outside the intended repository path.
    // O_EXCL still prevents truncating an existing target. Accepted local-workflow
    // residual — not zero risk.
    fd = fs.openSync(absPath, openFlags, 0o644);
    createdByThisInvocation = true;
    fs.writeFileSync(fd, content, "utf8");
    fs.closeSync(fd);
    fd = undefined;
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
      fd = undefined;
    }
    // Only remove a path this invocation exclusively created. Never unlink when
    // open failed (pre-existing file/symlink/bystander).
    if (createdByThisInvocation) {
      try {
        const lst = fs.lstatSync(absPath);
        if (!lst.isSymbolicLink() && lst.isFile()) {
          fs.unlinkSync(absPath);
        }
      } catch {
        // ignore partial cleanup failure
      }
    }
    throw err;
  }
}

function buildProvenanceRecordV2({
  sourceBaselineCommit,
  sourceBaselineTree,
  computedInputs,
  observation,
  attestation
}) {
  if (!isPlainObject(computedInputs)) {
    throw provenanceError(
      "INVALID_COMPUTED_INPUTS",
      "computedInputs must be a plain object"
    );
  }
  if (Object.prototype.hasOwnProperty.call(computedInputs, "digest")) {
    throw provenanceError(
      "INVALID_COMPUTED_INPUTS",
      "computedInputs must not include digest"
    );
  }
  const computedSansDigest = { ...computedInputs };
  const computedDigest = digestComputed(computedSansDigest);
  const computed = { ...computedSansDigest, digest: computedDigest };

  let observed = null;
  if (observation != null) {
    observed = {
      payload: observation,
      payloadDigest: digestObserved(observation)
    };
  }

  let operatorAttested = null;
  if (attestation != null) {
    operatorAttested = {
      payload: attestation,
      payloadDigest: digestAttested(attestation)
    };
  }

  const record = {
    schemaVersion: PROVENANCE_SCHEMA_VERSION,
    kind: "philcore-evidence-provenance-v2",
    sourceBaselineCommit,
    sourceBaselineTree,
    computed,
    observed,
    operatorAttested,
    recordDigest: null
  };
  record.recordDigest = digestRecord(record);
  return record;
}

function verifyRecordDigestsAndSanitization(record) {
  if (!record.computed || typeof record.computed !== "object") {
    throw provenanceError("PROVENANCE_DIGEST_MISMATCH", "missing computed");
  }
  const computedSans = { ...record.computed };
  const claimedComputedDigest = computedSans.digest;
  delete computedSans.digest;
  if (claimedComputedDigest !== digestComputed(computedSans)) {
    throw provenanceError(
      "PROVENANCE_DIGEST_MISMATCH",
      "computed.digest mismatch"
    );
  }

  if (record.observed != null) {
    if (
      !record.observed.payload ||
      record.observed.payloadDigest !== digestObserved(record.observed.payload)
    ) {
      throw provenanceError(
        "PROVENANCE_DIGEST_MISMATCH",
        "observed.payloadDigest mismatch"
      );
    }
    sanitizeObservation(record.observed.payload);
  }

  if (record.operatorAttested != null) {
    if (
      !record.operatorAttested.payload ||
      record.operatorAttested.payloadDigest !==
        digestAttested(record.operatorAttested.payload)
    ) {
      throw provenanceError(
        "PROVENANCE_DIGEST_MISMATCH",
        "operatorAttested.payloadDigest mismatch"
      );
    }
    sanitizeAttestation(record.operatorAttested.payload);
  }

  const forRecordDigest = {
    ...record,
    recordDigest: null
  };
  if (record.recordDigest !== digestRecord(forRecordDigest)) {
    throw provenanceError(
      "PROVENANCE_DIGEST_MISMATCH",
      "recordDigest mismatch"
    );
  }
}

function verifyProvenanceRecordCore({
  repoRoot,
  record,
  requireCleanTree = false
}) {
  if (!record || typeof record !== "object") {
    throw provenanceError("PROVENANCE_RECORD_INVALID", "record required");
  }
  if (requireCleanTree) {
    assertProvenanceSourceTreeClean(repoRoot);
  }
  if (record.schemaVersion !== PROVENANCE_SCHEMA_VERSION) {
    throw provenanceError(
      "PROVENANCE_SCHEMA_MISMATCH",
      `Expected schemaVersion ${PROVENANCE_SCHEMA_VERSION}`
    );
  }
  if (record.kind !== "philcore-evidence-provenance-v2") {
    throw provenanceError(
      "PROVENANCE_KIND_MISMATCH",
      "Unexpected provenance kind"
    );
  }

  verifyRecordDigestsAndSanitization(record);

  if (
    Array.isArray(record.computed.sourcePaths) &&
    record.computed.sourcePaths.length > 0
  ) {
    readSourcesAtBaseline(
      repoRoot,
      record.sourceBaselineCommit,
      record.computed.sourcePaths
    );
  }

  return { ok: true, record };
}

function verifyAssembledProvenanceRecordPreCommit({
  repoRoot = ROOT,
  record,
  containerCommit,
  requireCleanTree = false
} = {}) {
  if (containerCommit !== undefined && containerCommit !== null) {
    throw provenanceError(
      "PRECOMMIT_API_MISUSE",
      "PRECOMMIT_API_MISUSE: verifyAssembledProvenanceRecordPreCommit must not accept containerCommit"
    );
  }
  verifyProvenanceRecordCore({ repoRoot, record, requireCleanTree });
  assertSourceBaselineBinding({
    repoRoot,
    sourceBaselineCommit: record.sourceBaselineCommit,
    sourceBaselineTree: record.sourceBaselineTree
  });
  return { ok: true, record };
}

function verifyCommittedProvenanceRecordV2({
  repoRoot = ROOT,
  record,
  containerCommit,
  requireCleanTree = false
} = {}) {
  if (!containerCommit) {
    throw provenanceError(
      "CONTAINER_COMMIT_REQUIRED",
      "CONTAINER_COMMIT_REQUIRED: containerCommit is required"
    );
  }
  verifyProvenanceRecordCore({ repoRoot, record, requireCleanTree });
  assertEvidenceContainerBinding({
    repoRoot,
    sourceBaselineCommit: record.sourceBaselineCommit,
    sourceBaselineTree: record.sourceBaselineTree,
    containerCommit
  });
  return { ok: true, record };
}

function verifyProvenanceRecordV2(options) {
  return verifyCommittedProvenanceRecordV2(options);
}

function assembleProvenanceRecordV2({
  repoRoot = ROOT,
  sourceBaselineCommit,
  sourceBaselineTree,
  computedInputs,
  observationPath,
  attestationPath,
  outputRelativePath
} = {}) {
  const ownedTemps = new Set();
  try {
    assertFullCommitSha(sourceBaselineCommit, "sourceBaselineCommit");
    assertProvenanceSourceTreeClean(repoRoot);
    assertSourceBaselineBinding({
      repoRoot,
      sourceBaselineCommit,
      sourceBaselineTree
    });

    let observationLoaded = null;
    let attestationLoaded = null;

    if (observationPath) {
      observationLoaded = loadSanitizedJsonFromExternalTemp(
        observationPath,
        sanitizeObservation,
        repoRoot,
        ownedTemps
      );
    }
    if (attestationPath) {
      attestationLoaded = loadSanitizedJsonFromExternalTemp(
        attestationPath,
        sanitizeAttestation,
        repoRoot,
        ownedTemps
      );
    }

    const outputAbsolutePath = assertOutputRelativePath(
      outputRelativePath,
      repoRoot
    );

    const record = buildProvenanceRecordV2({
      sourceBaselineCommit: resolveCommit(repoRoot, sourceBaselineCommit),
      sourceBaselineTree,
      computedInputs,
      observation: observationLoaded,
      attestation: attestationLoaded
    });

    writeExclusiveNewFile(outputAbsolutePath, `${canonicalize(record)}\n`);

    return { record, outputAbsolutePath };
  } finally {
    cleanupOwnedTemps(ownedTemps);
  }
}

module.exports = {
  ROOT,
  OWNER_LOCKED_BASELINE_COMMIT,
  OWNER_LOCKED_BASELINE_TREE,
  RESOURCE_LIMITS,
  DIGEST_FRAMING_PREFIX,
  DIGEST_DOMAINS,
  LEGACY_EVIDENCE_FROZEN,
  PROVENANCE_SCHEMA_VERSION,
  PROVENANCE_V2_DIR,
  LEGACY_LOCK_PATH,
  ATTESTATION_NON_REPUDIATION_NOTICE,
  OPERATOR_ROLES,
  OBSERVATION_KEYS,
  ATTESTATION_KEYS,
  DANGEROUS_JSON_KEYS,
  provenanceError,
  loadLegacyLock,
  sha256Buffer,
  sha256File,
  readBoundedFileBytes,
  lstatOrMissing,
  writeExclusiveNewFile,
  assertOutputRelativePath,
  assertNoSymlinkComponents,
  verifyLegacyLockedArtifacts,
  refuseLegacyEvidenceWrite,
  assertNoLegacyOverwriteEscape,
  assertRelativePosixPath,
  assertFullCommitSha,
  assertExternalTempPath,
  safeUnlinkOwned,
  parseJsonStrictNoDuplicateKeys,
  canonicalize,
  digestDomain,
  digestComputed,
  digestObserved,
  digestAttested,
  digestRecord,
  digestCanonical,
  matchesDeniedDisclosure,
  assertProvenanceSourceTreeClean,
  gitShow,
  resolveCommit,
  resolveCommitTree,
  assertSourceBaselineBinding,
  assertEvidenceContainerBinding,
  readSourcesAtBaseline,
  sanitizeObservation,
  sanitizeAttestation,
  assembleProvenanceRecordV2,
  verifyAssembledProvenanceRecordPreCommit,
  verifyCommittedProvenanceRecordV2,
  verifyProvenanceRecordV2
};
