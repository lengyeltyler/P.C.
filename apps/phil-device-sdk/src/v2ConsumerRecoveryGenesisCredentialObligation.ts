import { createHash } from "node:crypto";
import type { Hex } from "./hashes.ts";
import { computePhilCoreV2LocalGenesisEnrollmentCeremonyHash } from "./v2ConsumerRecoveryGenesisProtocol.ts";
import {
  PhilCoreV2GenesisRoleCeremonyLifecycleError,
  validatePhilCoreV2GenesisRoleCeremonyRecord,
  type PhilCoreV2GenesisRoleCeremonyRecord
} from "./v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts";

// ---------------------------------------------------------------------------
// Pure, dormant genesis credential-creation obligation.
//
// This module belongs wholly to the GENESIS domain. It records a role ceremony
// before credential creation is authorized, records when creation may have
// begun, binds returned public hashes, and never asserts CONSUMED. Consumption
// is a cross-authority outcome that only a matching durable staging-journal
// manifest entry can prove.
//
// The module is pure. It reads no clock, generates no entropy, touches no
// file system, opens no socket, and performs no work when it is first
// evaluated. Every clock value is injected by the caller.
// ---------------------------------------------------------------------------

export const PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION = 1;
export const PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE =
  "philcore-v2-genesis-credential-obligation-v1";
export const PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_CHECKSUM_PREFIX =
  "PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_V1|";
export const MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES = 4096;

const UINT48_MAX_BIGINT = (1n << 48n) - 1n;
const UINT48_MAX_NUMBER = 281474976710655;
const BYTES32_LOWER_RE = /^0x[0-9a-f]{64}$/u;
const CANONICAL_UINT_RE = /^(0|[1-9][0-9]*)$/u;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export const PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE = Object.freeze({
  OBLIGATION_NOT_OBJECT: "OBLIGATION_NOT_OBJECT",
  OBLIGATION_MISSING_KEY: "OBLIGATION_MISSING_KEY",
  OBLIGATION_EXTRA_KEY: "OBLIGATION_EXTRA_KEY",
  OBLIGATION_ENUMERATION_FAILED: "OBLIGATION_ENUMERATION_FAILED",
  OBLIGATION_PROPERTY_READ_FAILED: "OBLIGATION_PROPERTY_READ_FAILED",
  OBLIGATION_SCHEMA_VERSION_UNSUPPORTED: "OBLIGATION_SCHEMA_VERSION_UNSUPPORTED",
  OBLIGATION_FORMAT_PROVENANCE_INVALID: "OBLIGATION_FORMAT_PROVENANCE_INVALID",
  OBLIGATION_STATE_INVALID: "OBLIGATION_STATE_INVALID",
  OBLIGATION_STATE_COHERENCE_INVALID: "OBLIGATION_STATE_COHERENCE_INVALID",
  OBLIGATION_FIELD_INVALID: "OBLIGATION_FIELD_INVALID",
  OBLIGATION_TIMESTAMP_INVALID: "OBLIGATION_TIMESTAMP_INVALID",
  OBLIGATION_CHECKSUM_FORMAT_INVALID: "OBLIGATION_CHECKSUM_FORMAT_INVALID",
  OBLIGATION_CHECKSUM_MISMATCH: "OBLIGATION_CHECKSUM_MISMATCH",
  OBLIGATION_OVERSIZED: "OBLIGATION_OVERSIZED",
  INPUT_NOT_OBJECT: "INPUT_NOT_OBJECT",
  INPUT_MISSING_KEY: "INPUT_MISSING_KEY",
  INPUT_EXTRA_KEY: "INPUT_EXTRA_KEY",
  INPUT_ENUMERATION_FAILED: "INPUT_ENUMERATION_FAILED",
  INPUT_PROPERTY_READ_FAILED: "INPUT_PROPERTY_READ_FAILED",
  INVALID_NOW: "INVALID_NOW",
  CLOCK_REGRESSION_DETECTED: "CLOCK_REGRESSION_DETECTED",
  INVALID_TRANSITION: "INVALID_TRANSITION",
  CEREMONY_VALIDATION_FAILED: "CEREMONY_VALIDATION_FAILED",
  CEREMONY_CONTEXT_MISMATCH: "CEREMONY_CONTEXT_MISMATCH",
  CEREMONY_ID_MISMATCH: "CEREMONY_ID_MISMATCH",
  CREDENTIAL_HASH_INVALID: "CREDENTIAL_HASH_INVALID",
  ORPHAN_REASON_INVALID: "ORPHAN_REASON_INVALID"
} as const);

export type PhilCoreV2GenesisCredentialObligationErrorCode =
  typeof PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE
  ];

type Code = PhilCoreV2GenesisCredentialObligationErrorCode;

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

/**
 * The module's only thrown type. `instanceof` is answered from a private
 * WeakSet brand through a non-writable, non-configurable `Symbol.hasInstance`,
 * so a hostile object cannot forge membership by adopting the prototype, and
 * the check itself cannot be replaced. No thrown value from any inner call is
 * ever retained on an instance -- not as `cause`, not under any other name.
 */
export class PhilCoreV2GenesisCredentialObligationError extends Error {
  readonly code: PhilCoreV2GenesisCredentialObligationErrorCode;

  constructor(code: PhilCoreV2GenesisCredentialObligationErrorCode, message?: string) {
    super(message ?? code);
    this.name = "PhilCoreV2GenesisCredentialObligationError";
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
  PhilCoreV2GenesisCredentialObligationError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2GenesisCredentialObligationError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

export type PhilCoreV2GenesisCredentialObligationState =
  | "ACTIVE"
  | "CREATION_AUTHORIZED"
  | "CREDENTIAL_RECORDED"
  | "ORPHANED";

export type PhilCoreV2GenesisCredentialObligationOrphanReason =
  | "RESTART_DURING_CREATION"
  | "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION"
  | "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION"
  | "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION"
  | "RECORDED_CREDENTIAL_MISMATCH";

export type PhilCoreV2GenesisCredentialObligationRecord = {
  readonly schemaVersion: typeof PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION;
  readonly formatProvenance: typeof PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE;
  readonly intentId: Hex;
  readonly genesisDeploymentIntentHash: Hex;
  readonly ceremonyVersion: string;
  readonly role: string;
  readonly credentialGeneration: string;
  readonly ceremonyId: Hex;
  readonly ceremonyExpiresAtUnixSeconds: string;
  readonly genesisEnrollmentCeremonyHash: Hex;
  readonly state: PhilCoreV2GenesisCredentialObligationState;
  readonly credentialIdHash: Hex | null;
  readonly publicVerificationMaterialHash: Hex | null;
  readonly createdAtUnixSeconds: string;
  readonly updatedAtUnixSeconds: string;
  readonly creationAuthorizedAtUnixSeconds: string | null;
  readonly orphanReason: PhilCoreV2GenesisCredentialObligationOrphanReason | null;
  readonly integrityChecksum: Hex;
};

type CeremonyHashInput = {
  readonly ceremonyVersion: string;
  readonly ceremonyId: string;
  readonly genesisDeploymentIntentHash: string;
  readonly role: string;
  readonly credentialGeneration: string;
  readonly expiresAt: string;
};

const RECORD_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "intentId",
  "genesisDeploymentIntentHash",
  "ceremonyVersion",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "state",
  "credentialIdHash",
  "publicVerificationMaterialHash",
  "createdAtUnixSeconds",
  "updatedAtUnixSeconds",
  "creationAuthorizedAtUnixSeconds",
  "orphanReason",
  "integrityChecksum"
] as const);

const CHECKSUM_OWN_KEYS = Object.freeze(RECORD_KEYS.slice(0, -1));

const CREATE_INPUT_KEYS = Object.freeze([
  "ceremony",
  "intentId",
  "nowUnixSeconds"
] as const);

const AUTHORIZE_INPUT_KEYS = Object.freeze([
  "current",
  "expectedCeremonyId",
  "nowUnixSeconds"
] as const);

const RECORD_INPUT_KEYS = Object.freeze([
  "current",
  "expectedCeremonyId",
  "credentialIdHash",
  "publicVerificationMaterialHash",
  "nowUnixSeconds"
] as const);

const ORPHAN_INPUT_KEYS = Object.freeze([
  "current",
  "reason",
  "nowUnixSeconds"
] as const);

const STATES = Object.freeze({
  ACTIVE: "ACTIVE",
  CREATION_AUTHORIZED: "CREATION_AUTHORIZED",
  CREDENTIAL_RECORDED: "CREDENTIAL_RECORDED",
  ORPHANED: "ORPHANED"
} as const);

const ORPHAN_REASONS = Object.freeze([
  "RESTART_DURING_CREATION",
  "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION",
  "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION",
  "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION",
  "RECORDED_CREDENTIAL_MISMATCH"
] as const);

const E = PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE;

function fail(code: Code, message?: string): never {
  throw new PhilCoreV2GenesisCredentialObligationError(code, message);
}

function isBrandedError(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisCredentialObligationError;
  } catch {
    return false;
  }
}

function failDiscardingThrown(code: Code, thrown: unknown): never {
  if (isBrandedError(thrown)) {
    throw thrown;
  }
  fail(code);
}

function isLifecycleBranded(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisRoleCeremonyLifecycleError;
  } catch {
    return false;
  }
}

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
  notObject: E.OBLIGATION_NOT_OBJECT,
  extraKey: E.OBLIGATION_EXTRA_KEY,
  missingKey: E.OBLIGATION_MISSING_KEY,
  enumerationFailed: E.OBLIGATION_ENUMERATION_FAILED,
  readFailed: E.OBLIGATION_PROPERTY_READ_FAILED
});

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

function requireCredentialIdHash(value: unknown, role: string, code: Code): Hex {
  if (typeof value !== "string") {
    fail(code);
  }
  if (!BYTES32_LOWER_RE.test(value)) {
    fail(code);
  }
  const isZero = value === ZERO_BYTES32;
  if (role === "2") {
    if (!isZero) {
      fail(code);
    }
  } else if (isZero) {
    fail(code);
  }
  return value as Hex;
}

function requireLowercaseBytes32OrNull(value: unknown, code: Code): Hex | null {
  if (value === null) {
    return null;
  }
  return requireLowercaseBytes32(value, code);
}

function requireCredentialIdHashOrNull(value: unknown, role: string, code: Code): Hex | null {
  if (value === null) {
    return null;
  }
  return requireCredentialIdHash(value, role, code);
}

function requireCanonicalUint48String(value: unknown, code: Code): string {
  if (typeof value !== "string" || !CANONICAL_UINT_RE.test(value)) {
    fail(code);
  }
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch (thrown) {
    failDiscardingThrown(code, thrown);
  }
  if (parsed < 1n || parsed > UINT48_MAX_BIGINT) {
    fail(code);
  }
  return value;
}

function requireCanonicalRoleString(value: unknown, code: Code): string {
  if (value !== "0" && value !== "1" && value !== "2") {
    fail(code);
  }
  return value;
}

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

function decimalFromBigint(value: bigint): string {
  return value.toString(10);
}

function parseUint48(value: string): bigint {
  return BigInt(value);
}

function buildHashInput(fields: {
  readonly ceremonyVersion: string;
  readonly ceremonyId: Hex;
  readonly genesisDeploymentIntentHash: Hex;
  readonly role: string;
  readonly credentialGeneration: string;
  readonly ceremonyExpiresAtUnixSeconds: string;
}): CeremonyHashInput {
  const input = Object.create(null) as {
    ceremonyVersion: string;
    ceremonyId: string;
    genesisDeploymentIntentHash: string;
    role: string;
    credentialGeneration: string;
    expiresAt: string;
  };
  input.ceremonyVersion = fields.ceremonyVersion;
  input.ceremonyId = fields.ceremonyId;
  input.genesisDeploymentIntentHash = fields.genesisDeploymentIntentHash;
  input.role = fields.role;
  input.credentialGeneration = fields.credentialGeneration;
  input.expiresAt = fields.ceremonyExpiresAtUnixSeconds;
  return Object.freeze(input);
}

function computeCeremonyHash(input: CeremonyHashInput): Hex {
  try {
    return computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(input);
  } catch (thrown) {
    failDiscardingThrown(E.OBLIGATION_FIELD_INVALID, thrown);
  }
}

function projectForChecksum(
  fields: Omit<PhilCoreV2GenesisCredentialObligationRecord, "integrityChecksum">
): Record<string, unknown> {
  const projection = Object.create(null) as Record<string, unknown>;
  projection.schemaVersion = fields.schemaVersion;
  projection.formatProvenance = fields.formatProvenance;
  projection.intentId = fields.intentId;
  projection.genesisDeploymentIntentHash = fields.genesisDeploymentIntentHash;
  projection.ceremonyVersion = fields.ceremonyVersion;
  projection.role = fields.role;
  projection.credentialGeneration = fields.credentialGeneration;
  projection.ceremonyId = fields.ceremonyId;
  projection.ceremonyExpiresAtUnixSeconds = fields.ceremonyExpiresAtUnixSeconds;
  projection.genesisEnrollmentCeremonyHash = fields.genesisEnrollmentCeremonyHash;
  projection.state = fields.state;
  projection.credentialIdHash = fields.credentialIdHash;
  projection.publicVerificationMaterialHash = fields.publicVerificationMaterialHash;
  projection.createdAtUnixSeconds = fields.createdAtUnixSeconds;
  projection.updatedAtUnixSeconds = fields.updatedAtUnixSeconds;
  projection.creationAuthorizedAtUnixSeconds = fields.creationAuthorizedAtUnixSeconds;
  projection.orphanReason = fields.orphanReason;
  return projection;
}

function computeIntegrityChecksum(
  fields: Omit<PhilCoreV2GenesisCredentialObligationRecord, "integrityChecksum">
): Hex {
  let projection: string;
  try {
    projection = JSON.stringify(projectForChecksum(fields));
  } catch (thrown) {
    failDiscardingThrown(E.OBLIGATION_FIELD_INVALID, thrown);
  }
  const digest = createHash("sha256")
    .update(PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_CHECKSUM_PREFIX, "utf8")
    .update(projection, "utf8")
    .digest("hex");
  return `0x${digest}` as Hex;
}

function freezeRecord(
  fields: PhilCoreV2GenesisCredentialObligationRecord
): PhilCoreV2GenesisCredentialObligationRecord {
  return Object.freeze({
    schemaVersion: fields.schemaVersion,
    formatProvenance: fields.formatProvenance,
    intentId: fields.intentId,
    genesisDeploymentIntentHash: fields.genesisDeploymentIntentHash,
    ceremonyVersion: fields.ceremonyVersion,
    role: fields.role,
    credentialGeneration: fields.credentialGeneration,
    ceremonyId: fields.ceremonyId,
    ceremonyExpiresAtUnixSeconds: fields.ceremonyExpiresAtUnixSeconds,
    genesisEnrollmentCeremonyHash: fields.genesisEnrollmentCeremonyHash,
    state: fields.state,
    credentialIdHash: fields.credentialIdHash,
    publicVerificationMaterialHash: fields.publicVerificationMaterialHash,
    createdAtUnixSeconds: fields.createdAtUnixSeconds,
    updatedAtUnixSeconds: fields.updatedAtUnixSeconds,
    creationAuthorizedAtUnixSeconds: fields.creationAuthorizedAtUnixSeconds,
    orphanReason: fields.orphanReason,
    integrityChecksum: fields.integrityChecksum
  });
}

function assembleRecord(
  fields: Omit<PhilCoreV2GenesisCredentialObligationRecord, "integrityChecksum">
): PhilCoreV2GenesisCredentialObligationRecord {
  return freezeRecord({
    ...fields,
    integrityChecksum: computeIntegrityChecksum(fields)
  });
}

function requireState(
  value: unknown
): PhilCoreV2GenesisCredentialObligationState {
  if (
    value !== STATES.ACTIVE
    && value !== STATES.CREATION_AUTHORIZED
    && value !== STATES.CREDENTIAL_RECORDED
    && value !== STATES.ORPHANED
  ) {
    fail(E.OBLIGATION_STATE_INVALID);
  }
  return value;
}

function requireOrphanReason(
  value: unknown
): PhilCoreV2GenesisCredentialObligationOrphanReason {
  for (const reason of ORPHAN_REASONS) {
    if (value === reason) {
      return reason;
    }
  }
  fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
}

function assertCoherence(fields: {
  readonly state: PhilCoreV2GenesisCredentialObligationState;
  readonly credentialIdHash: Hex | null;
  readonly publicVerificationMaterialHash: Hex | null;
  readonly creationAuthorizedAtUnixSeconds: string | null;
  readonly orphanReason: PhilCoreV2GenesisCredentialObligationOrphanReason | null;
}): void {
  const hashesKnown =
    fields.credentialIdHash !== null && fields.publicVerificationMaterialHash !== null;
  const hashesUnknown =
    fields.credentialIdHash === null && fields.publicVerificationMaterialHash === null;
  if (!hashesKnown && !hashesUnknown) {
    fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
  }

  if (fields.state === STATES.ACTIVE) {
    if (
      !hashesUnknown
      || fields.creationAuthorizedAtUnixSeconds !== null
      || fields.orphanReason !== null
    ) {
      fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
    }
    return;
  }

  if (fields.state === STATES.CREATION_AUTHORIZED) {
    if (
      !hashesUnknown
      || fields.creationAuthorizedAtUnixSeconds === null
      || fields.orphanReason !== null
    ) {
      fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
    }
    return;
  }

  if (fields.state === STATES.CREDENTIAL_RECORDED) {
    if (
      !hashesKnown
      || fields.creationAuthorizedAtUnixSeconds === null
      || fields.orphanReason !== null
    ) {
      fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
    }
    return;
  }

  if (fields.creationAuthorizedAtUnixSeconds === null || fields.orphanReason === null) {
    fail(E.OBLIGATION_STATE_COHERENCE_INVALID);
  }
}

function assertTimestampOrder(fields: {
  readonly createdAtUnixSeconds: string;
  readonly updatedAtUnixSeconds: string;
  readonly creationAuthorizedAtUnixSeconds: string | null;
}): void {
  const created = parseUint48(fields.createdAtUnixSeconds);
  const updated = parseUint48(fields.updatedAtUnixSeconds);
  if (updated < created) {
    fail(E.OBLIGATION_TIMESTAMP_INVALID);
  }
  if (fields.creationAuthorizedAtUnixSeconds !== null) {
    const authorized = parseUint48(fields.creationAuthorizedAtUnixSeconds);
    if (authorized < created || updated < authorized) {
      fail(E.OBLIGATION_TIMESTAMP_INVALID);
    }
  }
}

function compactRecordBytes(
  fields: PhilCoreV2GenesisCredentialObligationRecord
): number {
  const projection = Object.create(null) as Record<string, unknown>;
  for (const key of RECORD_KEYS) {
    projection[key] = fields[key];
  }
  return Buffer.byteLength(JSON.stringify(projection), "utf8");
}

export function validatePhilCoreV2GenesisCredentialObligationRecord(
  value: unknown
): PhilCoreV2GenesisCredentialObligationRecord {
  const snapshot = readExactOwnKeys(value, RECORD_KEYS, RECORD_BOUNDARY);

  const schemaVersionRaw = snapshot.schemaVersion;
  if (typeof schemaVersionRaw !== "number") {
    fail(E.OBLIGATION_FIELD_INVALID);
  }
  const formatProvenanceRaw = snapshot.formatProvenance;
  if (typeof formatProvenanceRaw !== "string") {
    fail(E.OBLIGATION_FIELD_INVALID);
  }
  const intentIdRaw = snapshot.intentId;
  const genesisDeploymentIntentHashRaw = snapshot.genesisDeploymentIntentHash;
  const ceremonyVersionRaw = snapshot.ceremonyVersion;
  const roleRaw = snapshot.role;
  const credentialGenerationRaw = snapshot.credentialGeneration;
  const ceremonyIdRaw = snapshot.ceremonyId;
  const ceremonyExpiresAtUnixSecondsRaw = snapshot.ceremonyExpiresAtUnixSeconds;
  const genesisEnrollmentCeremonyHashRaw = snapshot.genesisEnrollmentCeremonyHash;
  const stateRaw = snapshot.state;
  const credentialIdHashRaw = snapshot.credentialIdHash;
  const publicVerificationMaterialHashRaw = snapshot.publicVerificationMaterialHash;
  const createdAtUnixSecondsRaw = snapshot.createdAtUnixSeconds;
  const updatedAtUnixSecondsRaw = snapshot.updatedAtUnixSeconds;
  const creationAuthorizedAtUnixSecondsRaw = snapshot.creationAuthorizedAtUnixSeconds;
  const orphanReasonRaw = snapshot.orphanReason;
  const integrityChecksumRaw = snapshot.integrityChecksum;

  const owned = Object.create(null) as Record<string, unknown>;
  for (const key of RECORD_KEYS) {
    owned[key] = snapshot[key];
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(owned);
  } catch (thrown) {
    failDiscardingThrown(E.OBLIGATION_FIELD_INVALID, thrown);
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES) {
    fail(E.OBLIGATION_OVERSIZED);
  }

  if (schemaVersionRaw !== PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION) {
    fail(E.OBLIGATION_SCHEMA_VERSION_UNSUPPORTED);
  }
  if (formatProvenanceRaw !== PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE) {
    fail(E.OBLIGATION_FORMAT_PROVENANCE_INVALID);
  }

  const state = requireState(stateRaw);
  const intentId = requireLowercaseBytes32(intentIdRaw, E.OBLIGATION_FIELD_INVALID);
  const genesisDeploymentIntentHash = requireLowercaseBytes32(
    genesisDeploymentIntentHashRaw,
    E.OBLIGATION_FIELD_INVALID
  );
  if (typeof ceremonyVersionRaw !== "string" || ceremonyVersionRaw !== "1") {
    fail(E.OBLIGATION_FIELD_INVALID);
  }
  const ceremonyVersion = ceremonyVersionRaw;
  const role = requireCanonicalRoleString(roleRaw, E.OBLIGATION_FIELD_INVALID);
  if (typeof credentialGenerationRaw !== "string" || credentialGenerationRaw !== "1") {
    fail(E.OBLIGATION_FIELD_INVALID);
  }
  const credentialGeneration = credentialGenerationRaw;
  const ceremonyId = requireLowercaseBytes32(ceremonyIdRaw, E.OBLIGATION_FIELD_INVALID);
  const ceremonyExpiresAtUnixSeconds = requireCanonicalUint48String(
    ceremonyExpiresAtUnixSecondsRaw,
    E.OBLIGATION_TIMESTAMP_INVALID
  );
  const genesisEnrollmentCeremonyHash = requireLowercaseBytes32(
    genesisEnrollmentCeremonyHashRaw,
    E.OBLIGATION_FIELD_INVALID
  );
  const credentialIdHash = requireCredentialIdHashOrNull(
    credentialIdHashRaw,
    role,
    E.OBLIGATION_FIELD_INVALID
  );
  const publicVerificationMaterialHash = requireLowercaseBytes32OrNull(
    publicVerificationMaterialHashRaw,
    E.OBLIGATION_FIELD_INVALID
  );
  const createdAtUnixSeconds = requireCanonicalUint48String(
    createdAtUnixSecondsRaw,
    E.OBLIGATION_TIMESTAMP_INVALID
  );
  const updatedAtUnixSeconds = requireCanonicalUint48String(
    updatedAtUnixSecondsRaw,
    E.OBLIGATION_TIMESTAMP_INVALID
  );
  let creationAuthorizedAtUnixSeconds: string | null;
  if (creationAuthorizedAtUnixSecondsRaw === null) {
    creationAuthorizedAtUnixSeconds = null;
  } else {
    creationAuthorizedAtUnixSeconds = requireCanonicalUint48String(
      creationAuthorizedAtUnixSecondsRaw,
      E.OBLIGATION_TIMESTAMP_INVALID
    );
  }
  let orphanReason: PhilCoreV2GenesisCredentialObligationOrphanReason | null;
  if (orphanReasonRaw === null) {
    orphanReason = null;
  } else {
    orphanReason = requireOrphanReason(orphanReasonRaw);
  }

  assertCoherence({
    state,
    credentialIdHash,
    publicVerificationMaterialHash,
    creationAuthorizedAtUnixSeconds,
    orphanReason
  });
  assertTimestampOrder({
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    creationAuthorizedAtUnixSeconds
  });

  if (typeof integrityChecksumRaw !== "string") {
    fail(E.OBLIGATION_CHECKSUM_FORMAT_INVALID);
  }
  if (!BYTES32_LOWER_RE.test(integrityChecksumRaw)) {
    fail(E.OBLIGATION_CHECKSUM_FORMAT_INVALID);
  }

  const recomputedHash = computeCeremonyHash(
    buildHashInput({
      ceremonyVersion,
      ceremonyId,
      genesisDeploymentIntentHash,
      role,
      credentialGeneration,
      ceremonyExpiresAtUnixSeconds
    })
  );
  if (recomputedHash !== genesisEnrollmentCeremonyHash) {
    fail(E.OBLIGATION_FIELD_INVALID);
  }

  const withoutChecksum: Omit<
    PhilCoreV2GenesisCredentialObligationRecord,
    "integrityChecksum"
  > = {
    schemaVersion: PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE,
    intentId,
    genesisDeploymentIntentHash,
    ceremonyVersion,
    role,
    credentialGeneration,
    ceremonyId,
    ceremonyExpiresAtUnixSeconds,
    genesisEnrollmentCeremonyHash,
    state,
    credentialIdHash,
    publicVerificationMaterialHash,
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    creationAuthorizedAtUnixSeconds,
    orphanReason
  };
  const recomputedChecksum = computeIntegrityChecksum(withoutChecksum);
  if (recomputedChecksum !== integrityChecksumRaw) {
    fail(E.OBLIGATION_CHECKSUM_MISMATCH);
  }

  const frozen = freezeRecord({
    ...withoutChecksum,
    integrityChecksum: integrityChecksumRaw as Hex
  });
  if (compactRecordBytes(frozen) > MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES) {
    fail(E.OBLIGATION_OVERSIZED);
  }
  return frozen;
}

export function toPhilCoreV2GenesisCredentialObligationCeremonyHashInput(
  record: unknown
): CeremonyHashInput {
  const validated = validatePhilCoreV2GenesisCredentialObligationRecord(record);
  return buildHashInput(validated);
}

function validateCeremonyForCreate(
  value: unknown
): PhilCoreV2GenesisRoleCeremonyRecord {
  let validated: PhilCoreV2GenesisRoleCeremonyRecord;
  try {
    validated = validatePhilCoreV2GenesisRoleCeremonyRecord(value);
  } catch (thrown) {
    if (isBrandedError(thrown)) {
      throw thrown;
    }
    if (isLifecycleBranded(thrown)) {
      fail(E.CEREMONY_VALIDATION_FAILED);
    }
    fail(E.CEREMONY_VALIDATION_FAILED);
  }
  if (validated.state !== "ACTIVE") {
    fail(E.CEREMONY_CONTEXT_MISMATCH);
  }
  return validated;
}

function requireExpectedCeremonyId(value: unknown, expected: Hex): Hex {
  const actual = requireLowercaseBytes32(value, E.CEREMONY_ID_MISMATCH);
  if (actual !== expected) {
    fail(E.CEREMONY_ID_MISMATCH);
  }
  return actual;
}

function requireNowAfter(
  nowUnixSeconds: number,
  updatedAtUnixSeconds: string
): bigint {
  const now = BigInt(nowUnixSeconds);
  if (now < parseUint48(updatedAtUnixSeconds)) {
    fail(E.CLOCK_REGRESSION_DETECTED);
  }
  return now;
}

function copyImmutable(
  current: PhilCoreV2GenesisCredentialObligationRecord
): Pick<
  PhilCoreV2GenesisCredentialObligationRecord,
  | "schemaVersion"
  | "formatProvenance"
  | "intentId"
  | "genesisDeploymentIntentHash"
  | "ceremonyVersion"
  | "role"
  | "credentialGeneration"
  | "ceremonyId"
  | "ceremonyExpiresAtUnixSeconds"
  | "genesisEnrollmentCeremonyHash"
  | "createdAtUnixSeconds"
> {
  return {
    schemaVersion: current.schemaVersion,
    formatProvenance: current.formatProvenance,
    intentId: current.intentId,
    genesisDeploymentIntentHash: current.genesisDeploymentIntentHash,
    ceremonyVersion: current.ceremonyVersion,
    role: current.role,
    credentialGeneration: current.credentialGeneration,
    ceremonyId: current.ceremonyId,
    ceremonyExpiresAtUnixSeconds: current.ceremonyExpiresAtUnixSeconds,
    genesisEnrollmentCeremonyHash: current.genesisEnrollmentCeremonyHash,
    createdAtUnixSeconds: current.createdAtUnixSeconds
  };
}

export function createPhilCoreV2GenesisCredentialObligation(input: {
  readonly ceremony: unknown;
  readonly intentId: string;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisCredentialObligationRecord {
  const snapshot = readExactOwnKeys(input, CREATE_INPUT_KEYS, OPERATION_BOUNDARY);
  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = BigInt(nowUnixSeconds);
  const intentId = requireLowercaseBytes32(snapshot.intentId, E.OBLIGATION_FIELD_INVALID);
  const ceremony = validateCeremonyForCreate(snapshot.ceremony);

  if (now < ceremony.lastObservedAtUnixSeconds) {
    fail(E.CLOCK_REGRESSION_DETECTED);
  }
  if (now >= ceremony.expiresAtUnixSeconds) {
    fail(E.CEREMONY_CONTEXT_MISMATCH);
  }

  const ceremonyVersion = decimalFromBigint(ceremony.ceremonyVersion);
  const role = decimalFromBigint(ceremony.role);
  const credentialGeneration = decimalFromBigint(ceremony.credentialGeneration);
  const ceremonyExpiresAtUnixSeconds = decimalFromBigint(ceremony.expiresAtUnixSeconds);
  const createdAtUnixSeconds = decimalFromBigint(now);

  return assembleRecord({
    schemaVersion: PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE,
    intentId,
    genesisDeploymentIntentHash: ceremony.genesisDeploymentIntentHash,
    ceremonyVersion,
    role,
    credentialGeneration,
    ceremonyId: ceremony.ceremonyId,
    ceremonyExpiresAtUnixSeconds,
    genesisEnrollmentCeremonyHash: ceremony.genesisEnrollmentCeremonyHash,
    state: STATES.ACTIVE,
    credentialIdHash: null,
    publicVerificationMaterialHash: null,
    createdAtUnixSeconds,
    updatedAtUnixSeconds: createdAtUnixSeconds,
    creationAuthorizedAtUnixSeconds: null,
    orphanReason: null
  });
}

export function authorizePhilCoreV2GenesisCredentialCreation(input: {
  readonly current: unknown;
  readonly expectedCeremonyId: string;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisCredentialObligationRecord {
  const snapshot = readExactOwnKeys(input, AUTHORIZE_INPUT_KEYS, OPERATION_BOUNDARY);
  const current = validatePhilCoreV2GenesisCredentialObligationRecord(snapshot.current);
  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = requireNowAfter(nowUnixSeconds, current.updatedAtUnixSeconds);
  if (current.state !== STATES.ACTIVE) {
    fail(E.INVALID_TRANSITION);
  }
  requireExpectedCeremonyId(snapshot.expectedCeremonyId, current.ceremonyId);

  const authorizedAt = decimalFromBigint(now);
  return assembleRecord({
    ...copyImmutable(current),
    state: STATES.CREATION_AUTHORIZED,
    credentialIdHash: null,
    publicVerificationMaterialHash: null,
    updatedAtUnixSeconds: authorizedAt,
    creationAuthorizedAtUnixSeconds: authorizedAt,
    orphanReason: null
  });
}

export function recordPhilCoreV2GenesisCreatedCredential(input: {
  readonly current: unknown;
  readonly expectedCeremonyId: string;
  readonly credentialIdHash: string;
  readonly publicVerificationMaterialHash: string;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisCredentialObligationRecord {
  const snapshot = readExactOwnKeys(input, RECORD_INPUT_KEYS, OPERATION_BOUNDARY);
  const current = validatePhilCoreV2GenesisCredentialObligationRecord(snapshot.current);
  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = requireNowAfter(nowUnixSeconds, current.updatedAtUnixSeconds);
  if (current.state !== STATES.CREATION_AUTHORIZED) {
    fail(E.INVALID_TRANSITION);
  }
  requireExpectedCeremonyId(snapshot.expectedCeremonyId, current.ceremonyId);
  const credentialIdHash = requireCredentialIdHash(
    snapshot.credentialIdHash,
    current.role,
    E.CREDENTIAL_HASH_INVALID
  );
  const publicVerificationMaterialHash = requireLowercaseBytes32(
    snapshot.publicVerificationMaterialHash,
    E.CREDENTIAL_HASH_INVALID
  );

  return assembleRecord({
    ...copyImmutable(current),
    state: STATES.CREDENTIAL_RECORDED,
    credentialIdHash,
    publicVerificationMaterialHash,
    updatedAtUnixSeconds: decimalFromBigint(now),
    creationAuthorizedAtUnixSeconds: current.creationAuthorizedAtUnixSeconds,
    orphanReason: null
  });
}

export function orphanPhilCoreV2GenesisCredentialObligation(input: {
  readonly current: unknown;
  readonly reason: string;
  readonly nowUnixSeconds: number;
}): PhilCoreV2GenesisCredentialObligationRecord {
  const snapshot = readExactOwnKeys(input, ORPHAN_INPUT_KEYS, OPERATION_BOUNDARY);
  const current = validatePhilCoreV2GenesisCredentialObligationRecord(snapshot.current);
  const nowUnixSeconds = requireClockSeconds(snapshot.nowUnixSeconds, E.INVALID_NOW);
  const now = requireNowAfter(nowUnixSeconds, current.updatedAtUnixSeconds);
  if (
    current.state !== STATES.CREATION_AUTHORIZED
    && current.state !== STATES.CREDENTIAL_RECORDED
  ) {
    fail(E.INVALID_TRANSITION);
  }
  let reason: PhilCoreV2GenesisCredentialObligationOrphanReason | null = null;
  for (const candidate of ORPHAN_REASONS) {
    if (snapshot.reason === candidate) {
      reason = candidate;
      break;
    }
  }
  if (reason === null) {
    fail(E.ORPHAN_REASON_INVALID);
  }

  return assembleRecord({
    ...copyImmutable(current),
    state: STATES.ORPHANED,
    credentialIdHash: current.credentialIdHash,
    publicVerificationMaterialHash: current.publicVerificationMaterialHash,
    updatedAtUnixSeconds: decimalFromBigint(now),
    creationAuthorizedAtUnixSeconds: current.creationAuthorizedAtUnixSeconds,
    orphanReason: reason
  });
}

void CHECKSUM_OWN_KEYS;
