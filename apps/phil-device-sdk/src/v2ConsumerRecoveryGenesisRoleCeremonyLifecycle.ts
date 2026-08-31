import type { Hex } from "./hashes.ts";
import { computePhilCoreV2LocalGenesisEnrollmentCeremonyHash } from "./v2ConsumerRecoveryGenesisProtocol.ts";

// ---------------------------------------------------------------------------
// Pure, dormant, device-independent genesis role-ceremony lifecycle.
//
// This module belongs wholly to the GENESIS domain: it commits to a genesis
// deployment-intent hash plus a role, and never to an account address. The
// account-bound enrollment-ceremony domain is a separate commitment space and
// the two must never cross-validate.
//
// The module is pure. It reads no clock, generates no entropy, touches no
// file system, opens no socket, and performs no work when it is first
// evaluated. Every clock value is injected by the caller.
// ---------------------------------------------------------------------------

export const PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS = 300n;
export const PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION = 1n;
export const PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION = 1n;

// The 300-second time-to-live above is an independent decision for the genesis
// domain. It coincides numerically with the account-bound recovery ceremony's
// own time-to-live; that coincidence is not a shared constant, is never
// imported or aliased, and must never be refactored into one.

const UINT48_MAX_BIGINT = (1n << 48n) - 1n; // 281474976710655n
const UINT48_MAX_NUMBER = 281474976710655; // < Number.MAX_SAFE_INTEGER
const BYTES32_LOWER_RE = /^0x[0-9a-f]{64}$/u;
const CANONICAL_UINT_RE = /^(0|[1-9][0-9]*)$/u;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export const PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE = Object.freeze({
  CEREMONY_ALREADY_ACTIVE: "CEREMONY_ALREADY_ACTIVE",
  CEREMONY_PENDING_RETIREMENT: "CEREMONY_PENDING_RETIREMENT",
  CEREMONY_NOT_ACTIVE: "CEREMONY_NOT_ACTIVE",
  CEREMONY_NOT_INSTALLED: "CEREMONY_NOT_INSTALLED",
  CEREMONY_STILL_ACTIVE: "CEREMONY_STILL_ACTIVE",
  CEREMONY_ID_MISMATCH: "CEREMONY_ID_MISMATCH",
  INVALID_RECORD: "INVALID_RECORD",
  INPUT_NOT_OBJECT: "INPUT_NOT_OBJECT",
  INPUT_EXTRA_KEY: "INPUT_EXTRA_KEY",
  INPUT_MISSING_KEY: "INPUT_MISSING_KEY",
  INPUT_ENUMERATION_FAILED: "INPUT_ENUMERATION_FAILED",
  INPUT_PROPERTY_READ_FAILED: "INPUT_PROPERTY_READ_FAILED",
  CEREMONY_ID_INVALID: "CEREMONY_ID_INVALID",
  INTENT_HASH_INVALID: "INTENT_HASH_INVALID",
  ROLE_INVALID: "ROLE_INVALID",
  INVALID_NOW: "INVALID_NOW",
  INTENT_EXPIRY_INVALID: "INTENT_EXPIRY_INVALID",
  EXPIRY_OVERFLOW: "EXPIRY_OVERFLOW",
  EXPIRY_NOT_IN_FUTURE: "EXPIRY_NOT_IN_FUTURE",
  CLOCK_REGRESSION_DETECTED: "CLOCK_REGRESSION_DETECTED",
  CEREMONY_HASH_COMPUTATION_FAILED: "CEREMONY_HASH_COMPUTATION_FAILED"
} as const);

// Twenty-one declared codes: twenty reachable through the public API, and
// CEREMONY_HASH_COMPUTATION_FAILED, which is defensive-only. Both of its call
// sites complete every local field, schema, range, coherence, and canonicality
// check before the trusted genesis hash implementation is invoked, so that
// implementation can only throw if it violates its own validated contract. The
// code is retained so such a change surfaces as a closed code here rather than
// as an unclassified throw.

export type PhilCoreV2GenesisRoleCeremonyErrorCode =
  typeof PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE
  ];

type Code = PhilCoreV2GenesisRoleCeremonyErrorCode;

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

/**
 * The module's only thrown type. `instanceof` is answered from a private
 * WeakSet brand through a non-writable, non-configurable `Symbol.hasInstance`,
 * so a hostile object cannot forge membership by adopting the prototype, and
 * the check itself cannot be replaced. No thrown value from any inner call is
 * ever retained on an instance -- not as `cause`, not under any other name.
 */
export class PhilCoreV2GenesisRoleCeremonyLifecycleError extends Error {
  readonly code: PhilCoreV2GenesisRoleCeremonyErrorCode;

  constructor(code: PhilCoreV2GenesisRoleCeremonyErrorCode, message?: string) {
    super(message ?? code);
    this.name = "PhilCoreV2GenesisRoleCeremonyLifecycleError";
    this.code = code;
    CLASSIFIED_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return false;
    }
    return CLASSIFIED_ERROR_BRAND.has(value as object);
  }
}

Object.defineProperty(
  PhilCoreV2GenesisRoleCeremonyLifecycleError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2GenesisRoleCeremonyLifecycleError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

export type PhilCoreV2GenesisRoleCeremonyState = "ACTIVE" | "ENDED";

export type PhilCoreV2GenesisRoleCeremonyEndReason =
  | null
  | "CANCELLED"
  | "EXPIRED"
  | "CONSUMED";

/**
 * `CANCELLED` and `EXPIRED` both assert that no durable record binds this
 * ceremony to anything. `CONSUMED` asserts the opposite: the staging journal
 * accepted the ceremony and a durable manifest entry now records its
 * ceremonyId, so the id can never be reused. That discriminator is the only
 * ceremony-level signal a future orphan-credential policy can rely on, which
 * is why consume is a distinct transition rather than a flavour of cancel.
 */
export type PhilCoreV2GenesisRoleCeremonyRecord = {
  readonly state: PhilCoreV2GenesisRoleCeremonyState;
  readonly endReason: PhilCoreV2GenesisRoleCeremonyEndReason;
  readonly ceremonyVersion: bigint;
  readonly ceremonyId: Hex;
  readonly genesisDeploymentIntentHash: Hex;
  readonly role: bigint;
  readonly credentialGeneration: bigint;
  readonly expiresAtUnixSeconds: bigint;
  readonly mintedAtUnixSeconds: bigint;
  readonly lastObservedAtUnixSeconds: bigint;
  readonly genesisEnrollmentCeremonyHash: Hex;
};

/** Module-private. The six-key genesis hash commitment, decimal-canonical. */
type GenesisRoleCeremonyHashInput = {
  readonly ceremonyVersion: string;
  readonly ceremonyId: string;
  readonly genesisDeploymentIntentHash: string;
  readonly role: string;
  readonly credentialGeneration: string;
  readonly expiresAt: string;
};

const RECORD_KEYS = Object.freeze([
  "state",
  "endReason",
  "ceremonyVersion",
  "ceremonyId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "expiresAtUnixSeconds",
  "mintedAtUnixSeconds",
  "lastObservedAtUnixSeconds",
  "genesisEnrollmentCeremonyHash"
] as const);

const MINT_INPUT_KEYS = Object.freeze([
  "current",
  "ceremonyId",
  "role",
  "genesisDeploymentIntentHash",
  "intentExpiresAtUnixSeconds",
  "nowUnixSeconds"
] as const);

const CLOCK_INPUT_KEYS = Object.freeze(["current", "nowUnixSeconds"] as const);

const RETIRE_INPUT_KEYS = Object.freeze([
  "current",
  "expectedCeremonyId"
] as const);

const E = PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE;

function fail(code: Code, message?: string): never {
  throw new PhilCoreV2GenesisRoleCeremonyLifecycleError(code, message);
}

function isBrandedError(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisRoleCeremonyLifecycleError;
  } catch {
    return false;
  }
}

/**
 * Converts an untrusted thrown value into a closed classified code. A genuine
 * branded error is rethrown unchanged, preserving its own code. Anything else
 * is discarded entirely: it is never inspected beyond the brand check, never
 * retained as `cause`, and never exposed under any other property.
 */
function failDiscardingThrown(code: Code, thrown: unknown): never {
  if (isBrandedError(thrown)) {
    throw thrown;
  }
  fail(code);
}

// ---------------------------------------------------------------------------
// Hostile-input discipline.
//
// Every caller-supplied object passes through `readExactOwnKeys`. Own keys are
// enumerated with a guarded `Reflect.ownKeys`, which reports CANDIDATES only:
// a hostile Proxy may name a key that resolves solely through its prototype
// chain, so every candidate is independently re-verified with a guarded
// `Object.getOwnPropertyDescriptor` and read strictly from that descriptor,
// never through a second ordinary lookup. Symbol keys and non-enumerable extra
// keys are rejected outright. Values are never coerced, stringified, or probed
// beyond `typeof`.
//
// Two boundaries share this machinery with different closed codes: operation
// inputs classify precisely, while record validation and projection collapse
// every schema, property, and field failure to INVALID_RECORD.
// ---------------------------------------------------------------------------

type Boundary = {
  readonly notObject: Code;
  readonly extraKey: Code;
  readonly missingKey: Code;
  readonly enumerationFailed: Code;
  readonly readFailed: Code;
};

const OPERATION_BOUNDARY: Boundary = Object.freeze({
  notObject: E.INPUT_NOT_OBJECT,
  extraKey: E.INPUT_EXTRA_KEY,
  missingKey: E.INPUT_MISSING_KEY,
  enumerationFailed: E.INPUT_ENUMERATION_FAILED,
  readFailed: E.INPUT_PROPERTY_READ_FAILED
});

const RECORD_BOUNDARY: Boundary = Object.freeze({
  notObject: E.INVALID_RECORD,
  extraKey: E.INVALID_RECORD,
  missingKey: E.INVALID_RECORD,
  enumerationFailed: E.INVALID_RECORD,
  readFailed: E.INVALID_RECORD
});

/**
 * Reads a value strictly from an already-verified own-property descriptor. A
 * data property yields `descriptor.value`. An accessor invokes `descriptor.get`
 * at most once with the object as receiver; a set-only accessor is rejected
 * rather than silently yielding `undefined`, and any throw from the getter is
 * classified with the raw thrown value discarded.
 */
function readFromDescriptor(
  value: object,
  descriptor: PropertyDescriptor,
  code: Code
): unknown {
  if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    return descriptor.value;
  }
  if (typeof descriptor.get !== "function") {
    fail(code, "accessor own property has no getter");
  }
  try {
    return descriptor.get.call(value);
  } catch (thrown) {
    failDiscardingThrown(code, thrown);
  }
}

/**
 * Validates that `value`'s own-key surface is exactly `allowedKeys` and returns
 * a null-prototype snapshot of the verified values. The prototype gate accepts
 * only `Object.prototype` and `null`; every boxed primitive and every exotic or
 * subclassed object therefore fails as a non-object. Enumeration is attempted
 * before the prototype gate, so a Proxy whose `ownKeys` trap throws is
 * classified as an enumeration failure rather than as a non-object.
 */
function readExactOwnKeys(
  value: unknown,
  allowedKeys: readonly string[],
  boundary: Boundary
): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    fail(boundary.notObject);
  }

  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (thrown) {
    failDiscardingThrown(boundary.notObject, thrown);
  }
  if (isArray) {
    fail(boundary.notObject);
  }

  let candidateKeys: readonly (string | symbol)[];
  try {
    candidateKeys = Reflect.ownKeys(value);
  } catch (thrown) {
    failDiscardingThrown(boundary.enumerationFailed, thrown);
  }

  let prototype: unknown;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch (thrown) {
    failDiscardingThrown(boundary.notObject, thrown);
  }
  if (prototype !== null && prototype !== Object.prototype) {
    fail(boundary.notObject);
  }

  const allowed = new Set<string>(allowedKeys);
  const candidates: string[] = [];
  for (const key of candidateKeys) {
    if (typeof key === "symbol") {
      fail(boundary.extraKey, "unexpected symbol own key");
    }
    if (!allowed.has(key)) {
      fail(boundary.extraKey, "unexpected own key");
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (thrown) {
      failDiscardingThrown(boundary.enumerationFailed, thrown);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }

  for (const key of allowedKeys) {
    if (!verified.has(key)) {
      fail(boundary.missingKey, "missing own key");
    }
  }

  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    snapshot[key] = readFromDescriptor(
      value,
      verified.get(key) as PropertyDescriptor,
      boundary.readFailed
    );
  }
  return snapshot;
}

// ---------------------------------------------------------------------------
// Field validators. Hex canonicality is an explicit lowercase regex, matching
// the genesis protocol's own canonicality rule; no external hex helper and no
// coercion is involved anywhere.
// ---------------------------------------------------------------------------

function requireLowercaseBytes32(value: unknown, code: Code): Hex {
  if (typeof value !== "string") {
    fail(code);
  }
  if (!BYTES32_LOWER_RE.test(value)) {
    fail(code);
  }
  if (value === ZERO_BYTES32) {
    fail(code);
  }
  return value as Hex;
}

/** Operation-input role: a bigint or a canonical decimal string in {0,1,2}. */
function requireRoleInput(value: unknown, code: Code): bigint {
  let normalized: bigint;
  if (typeof value === "bigint") {
    normalized = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_UINT_RE.test(value)) {
      fail(code);
    }
    normalized = BigInt(value);
  } else {
    fail(code);
  }
  if (normalized !== 0n && normalized !== 1n && normalized !== 2n) {
    fail(code);
  }
  return normalized;
}

/** Record role: strictly a bigint in {0,1,2}; no string or number is accepted. */
function requireRecordRole(value: unknown, code: Code): bigint {
  if (typeof value !== "bigint") {
    fail(code);
  }
  if (value !== 0n && value !== 1n && value !== 2n) {
    fail(code);
  }
  return value;
}

/**
 * Intent expiry is taken explicitly from the caller: never derived from a
 * clock, never defaulted. A bigint, a canonical decimal string, or a safe
 * integer number is accepted and normalized to a bigint in [1, UINT48_MAX].
 */
function requireIntentExpiry(value: unknown, code: Code): bigint {
  let normalized: bigint;
  if (typeof value === "bigint") {
    normalized = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_UINT_RE.test(value)) {
      fail(code);
    }
    normalized = BigInt(value);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(code);
    }
    normalized = BigInt(value);
  } else {
    fail(code);
  }
  if (normalized < 1n || normalized > UINT48_MAX_BIGINT) {
    fail(code);
  }
  return normalized;
}

/**
 * The clock domain: a JavaScript number that is a safe integer in
 * [1, UINT48_MAX_NUMBER]. The number is returned unconverted so that each
 * caller performs the single `BigInt(...)` conversion explicitly at its own
 * boundary, after which no arithmetic in this module touches a number again.
 */
function requireClockSeconds(value: unknown, code: Code): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 1
    || value > UINT48_MAX_NUMBER
  ) {
    fail(code);
  }
  return value;
}

/** Record time field: strictly a bigint in [1, UINT48_MAX]. */
function requireRecordUint48(value: unknown, code: Code): bigint {
  if (typeof value !== "bigint") {
    fail(code);
  }
  if (value < 1n || value > UINT48_MAX_BIGINT) {
    fail(code);
  }
  return value;
}

/** Record pinned field: strictly a bigint equal to the pinned value. */
function requireRecordPinned(value: unknown, expected: bigint, code: Code): bigint {
  if (typeof value !== "bigint" || value !== expected) {
    fail(code);
  }
  return value;
}

// ---------------------------------------------------------------------------
// The genesis hash commitment and its projection.
// ---------------------------------------------------------------------------

/**
 * Builds the frozen, null-prototype six-key genesis hash input in its exact
 * committed order. Numeric members are canonical decimal strings, which is
 * required rather than stylistic: the genesis protocol's canonical-uint reader
 * rejects every JavaScript number outright.
 */
function buildHashInput(fields: {
  readonly ceremonyVersion: bigint;
  readonly ceremonyId: Hex;
  readonly genesisDeploymentIntentHash: Hex;
  readonly role: bigint;
  readonly credentialGeneration: bigint;
  readonly expiresAtUnixSeconds: bigint;
}): GenesisRoleCeremonyHashInput {
  const input = Object.create(null) as {
    ceremonyVersion: string;
    ceremonyId: string;
    genesisDeploymentIntentHash: string;
    role: string;
    credentialGeneration: string;
    expiresAt: string;
  };
  input.ceremonyVersion = fields.ceremonyVersion.toString(10);
  input.ceremonyId = fields.ceremonyId;
  input.genesisDeploymentIntentHash = fields.genesisDeploymentIntentHash;
  input.role = fields.role.toString(10);
  input.credentialGeneration = fields.credentialGeneration.toString(10);
  input.expiresAt = fields.expiresAtUnixSeconds.toString(10);
  return Object.freeze(input);
}

/**
 * The single trusted-call wrapper. Reached only after complete local
 * validation, so a throw here means the imported implementation violated its
 * own validated contract. The raw thrown value is discarded outright.
 */
function computeCeremonyHash(input: GenesisRoleCeremonyHashInput): Hex {
  try {
    return computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(input);
  } catch {
    fail(E.CEREMONY_HASH_COMPUTATION_FAILED);
  }
}

/**
 * Rebuilds the record in the one committed key order and freezes it. Every
 * member is a string, a bigint, or null, so no mutable sub-object is reachable
 * and this single freeze is a deep freeze.
 */
function freezeRecord(
  fields: PhilCoreV2GenesisRoleCeremonyRecord
): PhilCoreV2GenesisRoleCeremonyRecord {
  return Object.freeze({
    state: fields.state,
    endReason: fields.endReason,
    ceremonyVersion: fields.ceremonyVersion,
    ceremonyId: fields.ceremonyId,
    genesisDeploymentIntentHash: fields.genesisDeploymentIntentHash,
    role: fields.role,
    credentialGeneration: fields.credentialGeneration,
    expiresAtUnixSeconds: fields.expiresAtUnixSeconds,
    mintedAtUnixSeconds: fields.mintedAtUnixSeconds,
    lastObservedAtUnixSeconds: fields.lastObservedAtUnixSeconds,
    genesisEnrollmentCeremonyHash: fields.genesisEnrollmentCeremonyHash
  });
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

/**
 * Reconstructs and re-checks every invariant from the value alone. All own-key,
 * descriptor, type, canonicality, range, coherence, ordering, and pinned-field
 * checks complete before the trusted hash implementation is called; only then
 * is the stored commitment recomputed and required to match. A caller-computed
 * replacement is never accepted. Returns a deep-frozen normalized record.
 */
export function validatePhilCoreV2GenesisRoleCeremonyRecord(
  value: unknown
): PhilCoreV2GenesisRoleCeremonyRecord {
  const R = E.INVALID_RECORD;
  const snapshot = readExactOwnKeys(value, RECORD_KEYS, RECORD_BOUNDARY);

  const rawState = snapshot.state;
  if (rawState !== "ACTIVE" && rawState !== "ENDED") {
    fail(R);
  }
  const state: PhilCoreV2GenesisRoleCeremonyState = rawState;

  const rawEndReason = snapshot.endReason;
  let endReason: PhilCoreV2GenesisRoleCeremonyEndReason;
  if (state === "ACTIVE") {
    if (rawEndReason !== null) {
      fail(R);
    }
    endReason = null;
  } else {
    if (
      rawEndReason !== "CANCELLED"
      && rawEndReason !== "EXPIRED"
      && rawEndReason !== "CONSUMED"
    ) {
      fail(R);
    }
    endReason = rawEndReason;
  }

  const ceremonyVersion = requireRecordPinned(
    snapshot.ceremonyVersion,
    PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION,
    R
  );
  const ceremonyId = requireLowercaseBytes32(snapshot.ceremonyId, R);
  const genesisDeploymentIntentHash = requireLowercaseBytes32(
    snapshot.genesisDeploymentIntentHash,
    R
  );
  const role = requireRecordRole(snapshot.role, R);
  const credentialGeneration = requireRecordPinned(
    snapshot.credentialGeneration,
    PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION,
    R
  );
  const expiresAtUnixSeconds = requireRecordUint48(snapshot.expiresAtUnixSeconds, R);
  const mintedAtUnixSeconds = requireRecordUint48(snapshot.mintedAtUnixSeconds, R);
  const lastObservedAtUnixSeconds = requireRecordUint48(
    snapshot.lastObservedAtUnixSeconds,
    R
  );
  if (expiresAtUnixSeconds <= mintedAtUnixSeconds) {
    fail(R);
  }
  if (lastObservedAtUnixSeconds < mintedAtUnixSeconds) {
    fail(R);
  }
  const genesisEnrollmentCeremonyHash = requireLowercaseBytes32(
    snapshot.genesisEnrollmentCeremonyHash,
    R
  );

  const recomputed = computeCeremonyHash(
    buildHashInput({
      ceremonyVersion,
      ceremonyId,
      genesisDeploymentIntentHash,
      role,
      credentialGeneration,
      expiresAtUnixSeconds
    })
  );
  if (recomputed !== genesisEnrollmentCeremonyHash) {
    fail(R);
  }

  return freezeRecord({
    state,
    endReason,
    ceremonyVersion,
    ceremonyId,
    genesisDeploymentIntentHash,
    role,
    credentialGeneration,
    expiresAtUnixSeconds,
    mintedAtUnixSeconds,
    lastObservedAtUnixSeconds,
    genesisEnrollmentCeremonyHash
  });
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/**
 * The only sanctioned way to build a `currentRoleCeremony` for the staging
 * journal; nothing may hand-assemble one. Note the deliberate field-name
 * asymmetry: the record key is `expiresAtUnixSeconds`, the projection key is
 * `expiresAt`.
 */
export function toPhilCoreV2GenesisRoleCeremonyHashInput(
  record: unknown
): {
  readonly ceremonyVersion: string;
  readonly ceremonyId: string;
  readonly genesisDeploymentIntentHash: string;
  readonly role: string;
  readonly credentialGeneration: string;
  readonly expiresAt: string;
} {
  const validated = validatePhilCoreV2GenesisRoleCeremonyRecord(record);
  return buildHashInput(validated);
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

/**
 * Mints a new ACTIVE genesis role ceremony into an empty slot. An installed
 * ceremony blocks the mint whether it is ACTIVE or ENDED: an ENDED ceremony
 * must be retired first, for all three end reasons.
 */
export function mintPhilCoreV2GenesisRoleCeremony(input: {
  readonly current: PhilCoreV2GenesisRoleCeremonyRecord | null;
  readonly ceremonyId: string;
  readonly role: bigint | string;
  readonly genesisDeploymentIntentHash: string;
  readonly intentExpiresAtUnixSeconds: bigint | number | string;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisRoleCeremonyRecord {
  const snapshot = readExactOwnKeys(input, MINT_INPUT_KEYS, OPERATION_BOUNDARY);

  const installed = snapshot.current;
  if (installed !== null) {
    const validated = validatePhilCoreV2GenesisRoleCeremonyRecord(installed);
    if (validated.state === "ACTIVE") {
      fail(E.CEREMONY_ALREADY_ACTIVE);
    }
    fail(E.CEREMONY_PENDING_RETIREMENT);
  }

  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = BigInt(nowUnixSeconds);

  const role = requireRoleInput(snapshot.role, E.ROLE_INVALID);
  const ceremonyId = requireLowercaseBytes32(snapshot.ceremonyId, E.CEREMONY_ID_INVALID);
  const genesisDeploymentIntentHash = requireLowercaseBytes32(
    snapshot.genesisDeploymentIntentHash,
    E.INTENT_HASH_INVALID
  );
  const intentExpiry = requireIntentExpiry(
    snapshot.intentExpiresAtUnixSeconds,
    E.INTENT_EXPIRY_INVALID
  );

  if (now > UINT48_MAX_BIGINT - PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS) {
    fail(E.EXPIRY_OVERFLOW);
  }
  const ttlExpiry = now + PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS;
  const expiresAt = ttlExpiry < intentExpiry ? ttlExpiry : intentExpiry;
  // Checked after the minimum, never before: a ceremony's expiry can never
  // exceed the intent expiry it was minted against.
  if (expiresAt <= now) {
    fail(E.EXPIRY_NOT_IN_FUTURE);
  }

  const genesisEnrollmentCeremonyHash = computeCeremonyHash(
    buildHashInput({
      ceremonyVersion: PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION,
      ceremonyId,
      genesisDeploymentIntentHash,
      role,
      credentialGeneration: PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION,
      expiresAtUnixSeconds: expiresAt
    })
  );

  return freezeRecord({
    state: "ACTIVE",
    endReason: null,
    ceremonyVersion: PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION,
    ceremonyId,
    genesisDeploymentIntentHash,
    role,
    credentialGeneration: PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION,
    expiresAtUnixSeconds: expiresAt,
    mintedAtUnixSeconds: now,
    lastObservedAtUnixSeconds: now,
    genesisEnrollmentCeremonyHash
  });
}

/**
 * Observes an installed ceremony at an injected instant. An ACTIVE ceremony at
 * or past its expiry ends as EXPIRED; an already ENDED ceremony advances its
 * observation only, and its end reason is never rewritten.
 */
export function observePhilCoreV2GenesisRoleCeremonyStatus(input: {
  readonly current: PhilCoreV2GenesisRoleCeremonyRecord | null;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisRoleCeremonyRecord {
  const snapshot = readExactOwnKeys(input, CLOCK_INPUT_KEYS, OPERATION_BOUNDARY);

  if (snapshot.current === null) {
    fail(E.CEREMONY_NOT_INSTALLED);
  }
  const current = validatePhilCoreV2GenesisRoleCeremonyRecord(snapshot.current);

  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = BigInt(nowUnixSeconds);

  if (now < current.lastObservedAtUnixSeconds) {
    fail(E.CLOCK_REGRESSION_DETECTED);
  }

  if (current.state === "ACTIVE" && now >= current.expiresAtUnixSeconds) {
    return freezeRecord({
      ...current,
      state: "ENDED",
      endReason: "EXPIRED",
      lastObservedAtUnixSeconds: now
    });
  }

  return freezeRecord({ ...current, lastObservedAtUnixSeconds: now });
}

/**
 * Ends an ACTIVE ceremony the operator abandoned before staging. Expiry
 * outranks cancellation: at or past the expiry instant the ceremony ends as
 * EXPIRED instead.
 */
export function cancelPhilCoreV2GenesisRoleCeremony(input: {
  readonly current: PhilCoreV2GenesisRoleCeremonyRecord | null;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisRoleCeremonyRecord {
  const snapshot = readExactOwnKeys(input, CLOCK_INPUT_KEYS, OPERATION_BOUNDARY);

  if (snapshot.current === null) {
    fail(E.CEREMONY_NOT_INSTALLED);
  }
  const current = validatePhilCoreV2GenesisRoleCeremonyRecord(snapshot.current);
  if (current.state !== "ACTIVE") {
    fail(E.CEREMONY_NOT_ACTIVE);
  }

  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = BigInt(nowUnixSeconds);

  if (now < current.lastObservedAtUnixSeconds) {
    fail(E.CLOCK_REGRESSION_DETECTED);
  }

  if (now >= current.expiresAtUnixSeconds) {
    return freezeRecord({
      ...current,
      state: "ENDED",
      endReason: "EXPIRED",
      lastObservedAtUnixSeconds: now
    });
  }

  return freezeRecord({
    ...current,
    state: "ENDED",
    endReason: "CANCELLED",
    lastObservedAtUnixSeconds: now
  });
}

/**
 * Records that the staging journal durably accepted the ceremony and published
 * a manifest entry for its ceremonyId.
 *
 * There is deliberately NO expiry re-check here. The journal has already proved
 * the ceremony was unexpired at staging time and has already published the
 * manifest entry; re-applying expiry precedence could label a durably-consumed
 * ceremony EXPIRED, contradicting the journal and destroying the discriminator
 * that distinguishes an accounted-for credential from an orphan.
 */
export function consumePhilCoreV2GenesisRoleCeremony(input: {
  readonly current: PhilCoreV2GenesisRoleCeremonyRecord | null;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisRoleCeremonyRecord {
  const snapshot = readExactOwnKeys(input, CLOCK_INPUT_KEYS, OPERATION_BOUNDARY);

  if (snapshot.current === null) {
    fail(E.CEREMONY_NOT_INSTALLED);
  }
  const current = validatePhilCoreV2GenesisRoleCeremonyRecord(snapshot.current);
  if (current.state !== "ACTIVE") {
    fail(E.CEREMONY_NOT_ACTIVE);
  }

  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = BigInt(nowUnixSeconds);

  if (now < current.lastObservedAtUnixSeconds) {
    fail(E.CLOCK_REGRESSION_DETECTED);
  }

  return freezeRecord({
    ...current,
    state: "ENDED",
    endReason: "CONSUMED",
    lastObservedAtUnixSeconds: now
  });
}

/**
 * Retires an ENDED ceremony carrying any of the three end reasons, so the slot
 * can be reused. No clock is involved and no conversion occurs. The retired
 * record is returned; the caller sets its slot to null.
 */
export function retirePhilCoreV2GenesisRoleCeremony(input: {
  readonly current: PhilCoreV2GenesisRoleCeremonyRecord | null;
  readonly expectedCeremonyId: string;
}): PhilCoreV2GenesisRoleCeremonyRecord {
  const snapshot = readExactOwnKeys(input, RETIRE_INPUT_KEYS, OPERATION_BOUNDARY);

  if (snapshot.current === null) {
    fail(E.CEREMONY_NOT_INSTALLED);
  }
  const current = validatePhilCoreV2GenesisRoleCeremonyRecord(snapshot.current);
  if (current.state === "ACTIVE") {
    fail(E.CEREMONY_STILL_ACTIVE);
  }
  if (current.state !== "ENDED") {
    fail(E.INVALID_RECORD);
  }

  const expectedCeremonyId = requireLowercaseBytes32(
    snapshot.expectedCeremonyId,
    E.CEREMONY_ID_INVALID
  );
  if (expectedCeremonyId !== current.ceremonyId) {
    fail(E.CEREMONY_ID_MISMATCH);
  }

  return current;
}
