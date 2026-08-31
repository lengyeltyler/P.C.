import { createHash } from "node:crypto";
import {
  projectPhilCoreV2GenesisManifestBindingConflict,
  type PhilCoreV2GenesisManifestBindingConflictProjection
} from "./v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts";

// Pure, dormant, genesis-domain conflict-evidence format validator. This
// module checks envelope shape, projection binding, SHA-256 challenge-binding
// hash, and caller-clock freshness against ceremony expiry only. It grants no
// possession, replay-store, signature, provider, resolution, or transition
// authority, and it reads no clock of its own.

export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_SCHEMA_VERSION =
  1 as const;
export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_FORMAT_PROVENANCE =
  "PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_V1" as const;

export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_KIND =
  Object.freeze({
    CALLER_CLOCK_FORMAT_ONLY: "CALLER_CLOCK_FORMAT_ONLY"
  } as const);

export type PhilCoreV2GenesisConflictEvidenceValidationKind =
  typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_KIND[
    keyof typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_KIND
  ];

export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_AUTHORITY = Object.freeze({
  NONE: "NONE"
} as const);

export type PhilCoreV2GenesisConflictEvidenceAuthority =
  typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_AUTHORITY[
    keyof typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_AUTHORITY
  ];

export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_BINDING_PREFIX =
  "PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_BINDING_V1|" as const;

export const PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE =
  Object.freeze({
    CONFLICT_EVIDENCE_NOT_OBJECT: "CONFLICT_EVIDENCE_NOT_OBJECT",
    CONFLICT_EVIDENCE_MISSING_KEY: "CONFLICT_EVIDENCE_MISSING_KEY",
    CONFLICT_EVIDENCE_EXTRA_KEY: "CONFLICT_EVIDENCE_EXTRA_KEY",
    CONFLICT_EVIDENCE_KEY_ORDER_INVALID: "CONFLICT_EVIDENCE_KEY_ORDER_INVALID",
    CONFLICT_EVIDENCE_SCHEMA_INVALID: "CONFLICT_EVIDENCE_SCHEMA_INVALID",
    CONFLICT_EVIDENCE_FIELD_INVALID: "CONFLICT_EVIDENCE_FIELD_INVALID",
    CONFLICT_EVIDENCE_PROPERTY_READ_FAILED:
      "CONFLICT_EVIDENCE_PROPERTY_READ_FAILED",
    CONFLICT_EVIDENCE_BINDING_MISMATCH: "CONFLICT_EVIDENCE_BINDING_MISMATCH",
    CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH:
      "CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH",
    CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID:
      "CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID",
    CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY:
      "CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY",
    CONFLICT_EVIDENCE_CLOCK_INVALID: "CONFLICT_EVIDENCE_CLOCK_INVALID",
    CONFLICT_EVIDENCE_NOT_YET_VALID: "CONFLICT_EVIDENCE_NOT_YET_VALID",
    CONFLICT_EVIDENCE_EXPIRED: "CONFLICT_EVIDENCE_EXPIRED",
    CONFLICT_EVIDENCE_INVARIANT_VIOLATION:
      "CONFLICT_EVIDENCE_INVARIANT_VIOLATION"
  } as const);

export type PhilCoreV2GenesisConflictEvidenceValidationErrorCode =
  typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE
  ];

type Code = PhilCoreV2GenesisConflictEvidenceValidationErrorCode;
type Hex = `0x${string}`;
type Role = "0" | "1" | "2";
type JournalState = "STAGING" | "CANCELLED" | "EXPIRED" | "SUPERSEDED";

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2GenesisConflictEvidenceValidationError extends Error {
  readonly code: PhilCoreV2GenesisConflictEvidenceValidationErrorCode;

  constructor(
    code: PhilCoreV2GenesisConflictEvidenceValidationErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2GenesisConflictEvidenceValidationError";
    this.code = code;
    CLASSIFIED_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    if (
      value === null
      || (typeof value !== "object" && typeof value !== "function")
    ) {
      return false;
    }
    return CLASSIFIED_ERROR_BRAND.has(value as object);
  }
}

Object.defineProperty(
  PhilCoreV2GenesisConflictEvidenceValidationError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2GenesisConflictEvidenceValidationError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const E = PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE;
const KIND = PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_KIND;
const AUTHORITY = PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_AUTHORITY;
const PREFIX = PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_BINDING_PREFIX;
const SCHEMA = PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_SCHEMA_VERSION;
const PROVENANCE =
  PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_FORMAT_PROVENANCE;

const UINT48_MAX_BIGINT = (1n << 48n) - 1n;
const UINT48_MAX_NUMBER = 281474976710655;
const BYTES32_LOWER_RE = /^0x[0-9a-f]{64}$/u;
const CANONICAL_UINT_RE = /^(0|[1-9][0-9]*)$/u;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

const ENVELOPE_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "challengeReference",
  "challengeBindingHash",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds",
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "journalIntegrityChecksum",
  "journalState",
  "sidecarCredentialIdHash",
  "sidecarPublicVerificationMaterialHash",
  "manifestCredentialIdHash",
  "manifestPublicVerificationMaterialHash"
] as const);

const BINDING_KEYS = Object.freeze([
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "journalIntegrityChecksum",
  "journalState",
  "sidecarCredentialIdHash",
  "sidecarPublicVerificationMaterialHash",
  "manifestCredentialIdHash",
  "manifestPublicVerificationMaterialHash",
  "challengeReference",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds"
] as const);

export type PhilCoreV2GenesisConflictEvidenceEnvelope = Readonly<{
  schemaVersion: typeof SCHEMA;
  formatProvenance: typeof PROVENANCE;
  challengeReference: Hex;
  challengeBindingHash: Hex;
  issuedAtUnixSeconds: string;
  expiresAtUnixSeconds: string;
  intentId: string;
  genesisDeploymentIntentHash: string;
  role: Role;
  credentialGeneration: "1";
  ceremonyId: string;
  ceremonyExpiresAtUnixSeconds: string;
  genesisEnrollmentCeremonyHash: string;
  journalIntegrityChecksum: string;
  journalState: JournalState;
  sidecarCredentialIdHash: string;
  sidecarPublicVerificationMaterialHash: string;
  manifestCredentialIdHash: string;
  manifestPublicVerificationMaterialHash: string;
}>;

export type PhilCoreV2GenesisConflictEvidenceValidation = Readonly<{
  schemaVersion: typeof SCHEMA;
  formatProvenance: typeof PROVENANCE;
  validationKind: typeof KIND.CALLER_CLOCK_FORMAT_ONLY;
  resolutionAuthority: typeof AUTHORITY.NONE;
  transitionAuthority: typeof AUTHORITY.NONE;
  possessionAuthority: typeof AUTHORITY.NONE;
  replayStateAuthority: typeof AUTHORITY.NONE;
  signatureAuthority: typeof AUTHORITY.NONE;
  providerAuthority: typeof AUTHORITY.NONE;
  replayStoreConsulted: false;
  verifiedPossession: false;
  verifiedSignature: false;
  trustedProvider: false;
  intentId: string;
  genesisDeploymentIntentHash: string;
  role: Role;
  challengeReference: Hex;
  challengeBindingHash: Hex;
  issuedAtUnixSeconds: string;
  expiresAtUnixSeconds: string;
  validatedAtUnixSeconds: string;
  ceremonyExpiresAtUnixSeconds: string;
  journalIntegrityChecksum: string;
  sidecarCredentialIdHash: string;
  manifestCredentialIdHash: string;
  freshnessOutcome: "WITHIN_CALLER_CLOCK_WINDOW";
}>;

function fail(code: Code): never {
  throw new PhilCoreV2GenesisConflictEvidenceValidationError(code);
}

function isBrandedError(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisConflictEvidenceValidationError;
  } catch {
    return false;
  }
}

function failDiscardingThrown(code: Code, thrown: unknown): never {
  if (isBrandedError(thrown)) throw thrown;
  void thrown;
  fail(code);
}

function withinAdapterBoundary<T>(operation: () => T): T {
  try {
    return operation();
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
  }
}

function frozenNullPrototype(
  entries: readonly (readonly [string, unknown])[]
): Readonly<Record<string, unknown>> {
  const result = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of entries) result[key] = value;
  return Object.freeze(result);
}

function readFromDescriptor(
  value: object,
  descriptor: PropertyDescriptor,
  code: Code
): unknown {
  if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    return descriptor.value;
  }
  if (typeof descriptor.get !== "function") {
    fail(code);
  }
  try {
    return descriptor.get.call(value);
  } catch (thrown) {
    failDiscardingThrown(code, thrown);
  }
}

function readExactOwnKeys(
  value: unknown,
  allowedKeys: readonly string[]
): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    fail(E.CONFLICT_EVIDENCE_NOT_OBJECT);
  }

  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
  }
  if (isArray) {
    fail(E.CONFLICT_EVIDENCE_NOT_OBJECT);
  }

  let candidateKeys: readonly (string | symbol)[];
  try {
    candidateKeys = Reflect.ownKeys(value);
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
  }

  let prototype: unknown;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_NOT_OBJECT, thrown);
  }
  if (prototype !== null && prototype !== Object.prototype) {
    fail(E.CONFLICT_EVIDENCE_NOT_OBJECT);
  }

  const allowed = new Set<string>(allowedKeys);
  const candidates: string[] = [];
  for (const key of candidateKeys) {
    if (typeof key === "symbol") {
      fail(E.CONFLICT_EVIDENCE_EXTRA_KEY);
    }
    if (!allowed.has(key)) {
      fail(E.CONFLICT_EVIDENCE_EXTRA_KEY);
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (thrown) {
      failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }

  for (const key of allowedKeys) {
    if (!verified.has(key)) {
      fail(E.CONFLICT_EVIDENCE_MISSING_KEY);
    }
  }

  let enumerableKeys: string[];
  try {
    enumerableKeys = Object.keys(value);
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
  }
  if (
    enumerableKeys.length !== allowedKeys.length
    || enumerableKeys.some((key, index) => key !== allowedKeys[index])
  ) {
    fail(E.CONFLICT_EVIDENCE_KEY_ORDER_INVALID);
  }

  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    snapshot[key] = readFromDescriptor(
      value,
      verified.get(key) as PropertyDescriptor,
      E.CONFLICT_EVIDENCE_PROPERTY_READ_FAILED
    );
  }
  return snapshot;
}

function requireLowercaseBytes32(value: unknown): string {
  if (typeof value !== "string" || !BYTES32_LOWER_RE.test(value)) {
    fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
  }
  return value;
}

function requireNonZeroBytes32(value: unknown): Hex {
  const hex = requireLowercaseBytes32(value);
  if (hex === ZERO_BYTES32) {
    fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
  }
  return hex as Hex;
}

function requireCanonicalUint48String(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_UINT_RE.test(value)) {
    fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
  }
  const parsed = BigInt(value);
  if (parsed < 1n || parsed > UINT48_MAX_BIGINT) {
    fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
  }
  return value;
}

function requireRole(value: unknown): Role {
  if (value === "0" || value === "1" || value === "2") return value;
  fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
}

function requireJournalState(value: unknown): JournalState {
  if (
    value === "STAGING"
    || value === "CANCELLED"
    || value === "EXPIRED"
    || value === "SUPERSEDED"
  ) {
    return value;
  }
  fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
}

function requirePositiveSafeIntegerNow(value: unknown): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 1
    || value > UINT48_MAX_NUMBER
  ) {
    fail(E.CONFLICT_EVIDENCE_CLOCK_INVALID);
  }
  return value;
}

function hashValidated(fields: Record<string, unknown>): Hex {
  const projection = Object.create(null) as Record<string, unknown>;
  for (const key of BINDING_KEYS) {
    projection[key] = fields[key];
  }
  let json: string;
  try {
    json = JSON.stringify(projection);
  } catch (thrown) {
    failDiscardingThrown(E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION, thrown);
  }
  const digest = createHash("sha256")
    .update(PREFIX, "utf8")
    .update(json, "utf8")
    .digest("hex");
  return `0x${digest}` as Hex;
}

function parseBindingFields(
  snapshot: Record<string, unknown>
): Pick<
  PhilCoreV2GenesisConflictEvidenceEnvelope,
  (typeof BINDING_KEYS)[number]
> {
  const role = requireRole(snapshot.role);
  if (snapshot.credentialGeneration !== "1") {
    fail(E.CONFLICT_EVIDENCE_FIELD_INVALID);
  }
  return {
    intentId: requireNonZeroBytes32(snapshot.intentId),
    genesisDeploymentIntentHash: requireNonZeroBytes32(
      snapshot.genesisDeploymentIntentHash
    ),
    role,
    credentialGeneration: "1",
    ceremonyId: requireNonZeroBytes32(snapshot.ceremonyId),
    ceremonyExpiresAtUnixSeconds: requireCanonicalUint48String(
      snapshot.ceremonyExpiresAtUnixSeconds
    ),
    genesisEnrollmentCeremonyHash: requireNonZeroBytes32(
      snapshot.genesisEnrollmentCeremonyHash
    ),
    journalIntegrityChecksum: requireNonZeroBytes32(
      snapshot.journalIntegrityChecksum
    ),
    journalState: requireJournalState(snapshot.journalState),
    // Projection may emit a role-2 zero on either credential-id side.
    // Copy those strings as already-validated hashes; do not re-apply
    // role-2 zero policy here.
    sidecarCredentialIdHash: requireLowercaseBytes32(
      snapshot.sidecarCredentialIdHash
    ),
    sidecarPublicVerificationMaterialHash: requireNonZeroBytes32(
      snapshot.sidecarPublicVerificationMaterialHash
    ),
    manifestCredentialIdHash: requireLowercaseBytes32(
      snapshot.manifestCredentialIdHash
    ),
    manifestPublicVerificationMaterialHash: requireNonZeroBytes32(
      snapshot.manifestPublicVerificationMaterialHash
    ),
    challengeReference: requireNonZeroBytes32(snapshot.challengeReference),
    issuedAtUnixSeconds: requireCanonicalUint48String(
      snapshot.issuedAtUnixSeconds
    ),
    expiresAtUnixSeconds: requireCanonicalUint48String(
      snapshot.expiresAtUnixSeconds
    )
  };
}

function parseValidatedEnvelope(
  snapshot: Record<string, unknown>
): PhilCoreV2GenesisConflictEvidenceEnvelope {
  if (snapshot.schemaVersion !== SCHEMA) {
    fail(E.CONFLICT_EVIDENCE_SCHEMA_INVALID);
  }
  if (snapshot.formatProvenance !== PROVENANCE) {
    fail(E.CONFLICT_EVIDENCE_SCHEMA_INVALID);
  }
  const binding = parseBindingFields(snapshot);
  return {
    schemaVersion: SCHEMA,
    formatProvenance: PROVENANCE,
    challengeBindingHash: requireNonZeroBytes32(snapshot.challengeBindingHash),
    ...binding
  };
}

function requireBindingMatch(
  envelope: PhilCoreV2GenesisConflictEvidenceEnvelope,
  projection: PhilCoreV2GenesisManifestBindingConflictProjection
): void {
  if (
    envelope.intentId !== projection.intentId
    || envelope.genesisDeploymentIntentHash
      !== projection.genesisDeploymentIntentHash
    || envelope.role !== projection.role
    || envelope.credentialGeneration !== projection.credentialGeneration
    || envelope.ceremonyId !== projection.bindingContext.ceremonyId
    || envelope.ceremonyExpiresAtUnixSeconds
      !== projection.bindingContext.ceremonyExpiresAtUnixSeconds
    || envelope.genesisEnrollmentCeremonyHash
      !== projection.bindingContext.genesisEnrollmentCeremonyHash
    || envelope.journalIntegrityChecksum
      !== projection.manifestBinding.journalIntegrityChecksum
    || envelope.journalState !== projection.bindingContext.journalState
    || envelope.sidecarCredentialIdHash
      !== projection.sidecarBinding.credentialIdHash
    || envelope.sidecarPublicVerificationMaterialHash
      !== projection.sidecarBinding.publicVerificationMaterialHash
    || envelope.manifestCredentialIdHash
      !== projection.manifestBinding.credentialIdHash
    || envelope.manifestPublicVerificationMaterialHash
      !== projection.manifestBinding.publicVerificationMaterialHash
  ) {
    fail(E.CONFLICT_EVIDENCE_BINDING_MISMATCH);
  }
}

export function computePhilCoreV2GenesisConflictEvidenceBindingHash(
  fields: unknown
): Hex {
  return withinAdapterBoundary(() => {
    const snapshot = readExactOwnKeys(fields, BINDING_KEYS);
    return hashValidated(parseBindingFields(snapshot));
  });
}

export function validatePhilCoreV2GenesisConflictEvidence(
  evidence: unknown,
  obligation: unknown,
  journal: unknown,
  nowUnixSeconds: unknown
): PhilCoreV2GenesisConflictEvidenceValidation {
  const projection = projectPhilCoreV2GenesisManifestBindingConflict(
    obligation,
    journal
  );

  return withinAdapterBoundary(() => {
    const snapshot = readExactOwnKeys(evidence, ENVELOPE_KEYS);
    const envelope = parseValidatedEnvelope(snapshot);
    requireBindingMatch(envelope, projection);
    const expectedHash = hashValidated(envelope);
    if (envelope.challengeBindingHash !== expectedHash) {
      fail(E.CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH);
    }

    const issued = BigInt(envelope.issuedAtUnixSeconds);
    const expires = BigInt(envelope.expiresAtUnixSeconds);
    const ceremonyExpires = BigInt(envelope.ceremonyExpiresAtUnixSeconds);
    if (issued >= expires) {
      fail(E.CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID);
    }
    if (expires > ceremonyExpires || issued > ceremonyExpires) {
      fail(E.CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY);
    }

    const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
    const nowBig = BigInt(now);
    if (nowBig < issued) {
      fail(E.CONFLICT_EVIDENCE_NOT_YET_VALID);
    }
    if (nowBig >= expires) {
      fail(E.CONFLICT_EVIDENCE_EXPIRED);
    }

    return frozenNullPrototype([
      ["schemaVersion", SCHEMA],
      ["formatProvenance", PROVENANCE],
      ["validationKind", KIND.CALLER_CLOCK_FORMAT_ONLY],
      ["resolutionAuthority", AUTHORITY.NONE],
      ["transitionAuthority", AUTHORITY.NONE],
      ["possessionAuthority", AUTHORITY.NONE],
      ["replayStateAuthority", AUTHORITY.NONE],
      ["signatureAuthority", AUTHORITY.NONE],
      ["providerAuthority", AUTHORITY.NONE],
      ["replayStoreConsulted", false],
      ["verifiedPossession", false],
      ["verifiedSignature", false],
      ["trustedProvider", false],
      ["intentId", envelope.intentId],
      ["genesisDeploymentIntentHash", envelope.genesisDeploymentIntentHash],
      ["role", envelope.role],
      ["challengeReference", envelope.challengeReference],
      ["challengeBindingHash", envelope.challengeBindingHash],
      ["issuedAtUnixSeconds", envelope.issuedAtUnixSeconds],
      ["expiresAtUnixSeconds", envelope.expiresAtUnixSeconds],
      ["validatedAtUnixSeconds", String(now)],
      ["ceremonyExpiresAtUnixSeconds", envelope.ceremonyExpiresAtUnixSeconds],
      ["journalIntegrityChecksum", envelope.journalIntegrityChecksum],
      ["sidecarCredentialIdHash", envelope.sidecarCredentialIdHash],
      ["manifestCredentialIdHash", envelope.manifestCredentialIdHash],
      ["freshnessOutcome", "WITHIN_CALLER_CLOCK_WINDOW"]
    ]) as PhilCoreV2GenesisConflictEvidenceValidation;
  });
}
