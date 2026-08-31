import { createHash } from "node:crypto";

import { isHexString } from "ethers";

import type { Hex } from "./hashes.ts";
import {
  computePhilCoreV2LocalGenesisDeploymentIntentHash,
  computePhilCoreV2LocalGenesisEnrollmentCeremonyHash,
  type PhilCoreV2LocalGenesisDeploymentIntentInput,
  type PhilCoreV2LocalGenesisEnrollmentCeremonyInput
} from "./v2ConsumerRecoveryGenesisProtocol.ts";
import {
  validatePhilCoreV2ConsumerRecoveryFactorPolicy,
  type PhilCoreV2ConsumerRecoveryIndependenceInput
} from "./v2ConsumerRecovery.ts";
import type { PhilCoreV2RecoveryFactorDescriptorInput } from "./v2RecoveryEvidence.ts";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const CANONICAL_UINT_STRING = /^(0|[1-9][0-9]*)$/;

// ---------------------------------------------------------------------------
// Package 5B-0.4 -- pure genesis candidate staging journal. Immutable,
// normalized state transitions only: no filesystem durability, credential
// generation, attestation trust, secure custody, or physical separation
// claim. Every hostile-surface boundary uses guarded Reflect.ownKeys plus
// independently verified Object.getOwnPropertyDescriptor reads (never the
// older Object.keys()/ordinary-property-read pattern), and every thrown
// value collapses to a closed local code with the original fully discarded
// -- never retained as `cause` or under any other property, mirroring the
// corrected genesis-protocol module's failWithCause exactly.
// ---------------------------------------------------------------------------

export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION = 1 as const;
export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE =
  "philcore-v2-genesis-ceremony-staging-journal-v1" as const;
export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_CHECKSUM_PREFIX =
  "PHILCORE_V2_GENESIS_CEREMONY_STAGING_JOURNAL_V1|" as const;

export const MAX_GENESIS_MANIFEST_ENTRY_BYTES = 4096 as const;
export const MAX_GENESIS_JOURNAL_FILE_BYTES = 16384 as const;

export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING = "STAGING" as const;
export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED = "CANCELLED" as const;
export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED = "EXPIRED" as const;
export const PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED = "SUPERSEDED" as const;

export const PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE =
  Object.freeze({
    JOURNAL_NOT_OBJECT: "JOURNAL_NOT_OBJECT",
    JOURNAL_MISSING_KEY: "JOURNAL_MISSING_KEY",
    JOURNAL_EXTRA_KEY: "JOURNAL_EXTRA_KEY",
    JOURNAL_ENUMERATION_FAILED: "JOURNAL_ENUMERATION_FAILED",
    JOURNAL_PROPERTY_READ_FAILED: "JOURNAL_PROPERTY_READ_FAILED",
    JOURNAL_SCHEMA_VERSION_UNSUPPORTED: "JOURNAL_SCHEMA_VERSION_UNSUPPORTED",
    JOURNAL_FORMAT_PROVENANCE_INVALID: "JOURNAL_FORMAT_PROVENANCE_INVALID",
    CANDIDATE_INPUT_NOT_OBJECT: "CANDIDATE_INPUT_NOT_OBJECT",
    CANDIDATE_INPUT_MISSING_KEY: "CANDIDATE_INPUT_MISSING_KEY",
    CANDIDATE_INPUT_EXTRA_KEY: "CANDIDATE_INPUT_EXTRA_KEY",
    CANDIDATE_ENUMERATION_FAILED: "CANDIDATE_ENUMERATION_FAILED",
    CANDIDATE_PROPERTY_READ_FAILED: "CANDIDATE_PROPERTY_READ_FAILED",
    MANIFEST_NOT_OBJECT: "MANIFEST_NOT_OBJECT",
    MANIFEST_MISSING_KEY: "MANIFEST_MISSING_KEY",
    MANIFEST_EXTRA_KEY: "MANIFEST_EXTRA_KEY",
    MANIFEST_ENUMERATION_FAILED: "MANIFEST_ENUMERATION_FAILED",
    MANIFEST_ENTRY_NOT_OBJECT: "MANIFEST_ENTRY_NOT_OBJECT",
    MANIFEST_ENTRY_MISSING_KEY: "MANIFEST_ENTRY_MISSING_KEY",
    MANIFEST_ENTRY_EXTRA_KEY: "MANIFEST_ENTRY_EXTRA_KEY",
    MANIFEST_ENTRY_ENUMERATION_FAILED: "MANIFEST_ENTRY_ENUMERATION_FAILED",
    MANIFEST_ENTRY_PROPERTY_READ_FAILED: "MANIFEST_ENTRY_PROPERTY_READ_FAILED",
    GENESIS_INTENT_VALIDATION_FAILED: "GENESIS_INTENT_VALIDATION_FAILED",
    GENESIS_CEREMONY_VALIDATION_FAILED: "GENESIS_CEREMONY_VALIDATION_FAILED",
    FACTOR_POLICY_VALIDATION_FAILED: "FACTOR_POLICY_VALIDATION_FAILED",
    CEREMONY_ROLE_MISMATCH: "CEREMONY_ROLE_MISMATCH",
    CEREMONY_INTENT_HASH_MISMATCH: "CEREMONY_INTENT_HASH_MISMATCH",
    FACTOR_CEREMONY_HASH_MISMATCH: "FACTOR_CEREMONY_HASH_MISMATCH",
    JOURNAL_CONTEXT_HASH_MISMATCH: "JOURNAL_CONTEXT_HASH_MISMATCH",
    JOURNAL_CEREMONY_HASH_RECOMPUTATION_MISMATCH: "JOURNAL_CEREMONY_HASH_RECOMPUTATION_MISMATCH",
    MANIFEST_ENTRY_FACTOR_COMMITMENT_MISMATCH: "MANIFEST_ENTRY_FACTOR_COMMITMENT_MISMATCH",
    ROLE_INVALID: "ROLE_INVALID",
    ROLE_SEQUENCE_VIOLATION: "ROLE_SEQUENCE_VIOLATION",
    ROLE_SLOT_ALREADY_POPULATED: "ROLE_SLOT_ALREADY_POPULATED",
    MANIFEST_SEQUENCE_INVALID: "MANIFEST_SEQUENCE_INVALID",
    MANIFEST_SLOT_ROLE_MISMATCH: "MANIFEST_SLOT_ROLE_MISMATCH",
    CEREMONY_ID_DUPLICATE: "CEREMONY_ID_DUPLICATE",
    FACTOR_COMMITMENT_DUPLICATE: "FACTOR_COMMITMENT_DUPLICATE",
    CREDENTIAL_ID_HASH_DUPLICATE: "CREDENTIAL_ID_HASH_DUPLICATE",
    PUBLIC_VERIFICATION_MATERIAL_HASH_DUPLICATE: "PUBLIC_VERIFICATION_MATERIAL_HASH_DUPLICATE",
    CUSTODY_DOMAIN_COMMITMENT_DUPLICATE: "CUSTODY_DOMAIN_COMMITMENT_DUPLICATE",
    SIGNER_ALIASES_INITIAL_VALIDATOR: "SIGNER_ALIASES_INITIAL_VALIDATOR",
    MANIFEST_ENTRY_SIGNER_MUST_BE_NULL: "MANIFEST_ENTRY_SIGNER_MUST_BE_NULL",
    INTENT_EXPIRY_INVALID: "INTENT_EXPIRY_INVALID",
    CEREMONY_EXPIRY_INVALID: "CEREMONY_EXPIRY_INVALID",
    CURRENT_ROLE_CEREMONY_EXPIRED: "CURRENT_ROLE_CEREMONY_EXPIRED",
    CREDENTIAL_GENERATION_NOT_ONE: "CREDENTIAL_GENERATION_NOT_ONE",
    CEREMONY_EXPIRY_EXCEEDS_INTENT_EXPIRY: "CEREMONY_EXPIRY_EXCEEDS_INTENT_EXPIRY",
    MANIFEST_ENTRY_STAGED_AT_NOT_BEFORE_CEREMONY_EXPIRY:
      "MANIFEST_ENTRY_STAGED_AT_NOT_BEFORE_CEREMONY_EXPIRY",
    INVALID_NOW: "INVALID_NOW",
    CLOCK_REGRESSION_DETECTED: "CLOCK_REGRESSION_DETECTED",
    JOURNAL_TIMESTAMP_ORDER_INVALID: "JOURNAL_TIMESTAMP_ORDER_INVALID",
    JOURNAL_CREATION_NOT_BEFORE_EXPIRY: "JOURNAL_CREATION_NOT_BEFORE_EXPIRY",
    MANIFEST_ENTRY_STAGED_AT_ORDER_INVALID: "MANIFEST_ENTRY_STAGED_AT_ORDER_INVALID",
    MANIFEST_STAGED_AT_SEQUENCE_INVALID: "MANIFEST_STAGED_AT_SEQUENCE_INVALID",
    JOURNAL_UPDATED_AT_STAGING_MISMATCH: "JOURNAL_UPDATED_AT_STAGING_MISMATCH",
    JOURNAL_UPDATED_AT_TERMINAL_INVALID: "JOURNAL_UPDATED_AT_TERMINAL_INVALID",
    JOURNAL_STATE_INVALID: "JOURNAL_STATE_INVALID",
    JOURNAL_STATE_END_REASON_MISMATCH: "JOURNAL_STATE_END_REASON_MISMATCH",
    JOURNAL_STATE_TIMESTAMP_MISMATCH: "JOURNAL_STATE_TIMESTAMP_MISMATCH",
    JOURNAL_END_REASON_INVALID: "JOURNAL_END_REASON_INVALID",
    JOURNAL_CHECKSUM_FORMAT_INVALID: "JOURNAL_CHECKSUM_FORMAT_INVALID",
    JOURNAL_CHECKSUM_MISMATCH: "JOURNAL_CHECKSUM_MISMATCH",
    MANIFEST_ENTRY_OVERSIZED: "MANIFEST_ENTRY_OVERSIZED",
    JOURNAL_OVERSIZED: "JOURNAL_OVERSIZED",
    JOURNAL_NOT_STAGING: "JOURNAL_NOT_STAGING"
  } as const);

export type PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode =
  typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE[
    keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE
  ];

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2ConsumerRecoveryGenesisStagingJournalError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryGenesisStagingJournalError";
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
  PhilCoreV2ConsumerRecoveryGenesisStagingJournalError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2ConsumerRecoveryGenesisStagingJournalError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const C = PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE;

function fail(
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  message?: string
): never {
  throw new PhilCoreV2ConsumerRecoveryGenesisStagingJournalError(code, message);
}

function isClassifiedError(
  value: unknown
): value is PhilCoreV2ConsumerRecoveryGenesisStagingJournalError {
  try {
    return value instanceof PhilCoreV2ConsumerRecoveryGenesisStagingJournalError;
  } catch {
    return false;
  }
}

// Rethrows a genuine same-module branded error unchanged. Every other
// thrown value -- imported branded errors from other modules, plain
// Errors, hostile objects, spoofed errors, revoked Proxies -- is fully
// discarded: never inspected for .code/.name/.message, never retained as
// `cause` or under any other property, enumerable or not. Only the
// caller-supplied closed code survives.
function failWithCause(
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  cause: unknown
): never {
  if (isClassifiedError(cause)) {
    throw cause;
  }
  fail(code);
}

// ---------------------------------------------------------------------------
// Hostile-surface-safe property access (verified-own-descriptor discipline,
// matching the corrected genesis-protocol and factor-policy modules -- never
// the older Object.keys()/ordinary-property-read pattern).
// ---------------------------------------------------------------------------

function requirePlainObject(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    fail(code);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (error) {
    failWithCause(code, error);
  }
  if (isArray) {
    fail(code);
  }
  return value as Record<string, unknown>;
}

function readValueFromVerifiedDescriptor(
  value: object,
  descriptor: PropertyDescriptor,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): unknown {
  if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    return descriptor.value;
  }
  if (typeof descriptor.get !== "function") {
    fail(code, "accessor own property has no getter");
  }
  try {
    return descriptor.get.call(value);
  } catch (error) {
    failWithCause(code, error);
  }
}

// `Reflect.ownKeys` output is treated as CANDIDATES only, never as proof of
// ownership: each candidate is independently re-verified with a guarded
// `Object.getOwnPropertyDescriptor` call, and only a non-undefined result
// counts as genuine ownership. Returns the verified descriptors so callers
// read values directly from them, never via a second ordinary lookup.
function requireExactOwnKeys(
  value: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  missingCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): ReadonlyMap<string, PropertyDescriptor> {
  const allowed = new Set<string>([...requiredKeys, ...optionalKeys]);
  let keys: readonly (string | symbol)[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    failWithCause(enumerationCode, error);
  }
  const candidates: string[] = [];
  for (const key of keys) {
    if (typeof key === "symbol") {
      fail(extraCode, "unexpected symbol own key");
    }
    if (!allowed.has(key)) {
      fail(extraCode, `unexpected own key: ${key}`);
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      failWithCause(enumerationCode, error);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }

  for (const key of requiredKeys) {
    if (!verified.has(key)) {
      fail(missingCode, `missing own key: ${key}`);
    }
  }
  return verified;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }
  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }
  return Object.freeze(value);
}

// ---------------------------------------------------------------------------
// Value-semantic helpers. Numeric inputs are accepted as bigint | string
// only (the closed ExactUintInput surface) -- a JavaScript number is
// rejected before any delegation, and stored values are always canonical
// decimal strings.
// ---------------------------------------------------------------------------

// Stored-record-only variant: a stored numeric value must already be a
// canonical decimal string -- unlike ExactUintInput's bigint|string
// candidate-input surface, a forged stored bigint, number, or any other
// non-string value is rejected outright, never silently normalized.
function requireStoredCanonicalUintString(
  value: unknown,
  bits: number,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): string {
  if (typeof value !== "string" || !CANONICAL_UINT_STRING.test(value)) {
    fail(code);
  }
  let big: bigint;
  try {
    big = BigInt(value);
  } catch {
    fail(code);
  }
  if (big < 0n || big >= (1n << BigInt(bits))) fail(code);
  return value;
}

// Verifies exact key ownership, then confirms every field is string-typed
// (rejecting a forged stored bigint/number) without performing any deeper
// canonical-format validation -- used both as the stored-only numeric
// boundary for defect 2 and as the type-checked-but-not-format-validated
// snapshot the byte-ceiling guard runs against for defect 5.
function requireStoredFactorFieldsAsStrings(
  value: unknown,
  keys: readonly string[],
  notObjectCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  missingCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  readCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): Readonly<Record<string, string>> {
  const obj = requirePlainObject(value, notObjectCode);
  const verified = requireExactOwnKeys(obj, keys, [], missingCode, extraCode, enumerationCode);
  const out: Record<string, string> = Object.create(null);
  for (const key of keys) {
    const raw = readValueFromVerifiedDescriptor(obj, verified.get(key) as PropertyDescriptor, readCode);
    if (typeof raw !== "string") fail(readCode);
    out[key] = raw;
  }
  return Object.freeze(out);
}

function requirePositiveSafeIntegerNow(value: unknown): bigint {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value <= 0
    || value > 281474976710655
  ) {
    fail(C.INVALID_NOW);
  }
  return BigInt(value);
}

function requireNonZeroBytes32(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): Hex {
  if (typeof value !== "string" || !isHexString(value, 32) || value !== value.toLowerCase()) {
    fail(code);
  }
  if (value === ZERO_BYTES32) fail(code);
  return value as Hex;
}

function requireChecksumBytes32Format(value: unknown): Hex {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-f]{64}$/.test(value)
  ) {
    fail(C.JOURNAL_CHECKSUM_FORMAT_INVALID);
  }
  return value as Hex;
}

// ---------------------------------------------------------------------------
// Exact literal own-key orders (Package 5B-0.3 Revision 6, section 1).
// ---------------------------------------------------------------------------

const INTENT_OWN_KEYS = Object.freeze([
  "intentVersion",
  "intentId",
  "chainId",
  "entryPoint",
  "factoryBinding",
  "confirmationTarget",
  "verifier",
  "verifierRuntimeCodeHash",
  "accountCreationBytecodeHash",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "ownerCommitment",
  "identityBindingCommitment",
  "initialValidator",
  "validatorVerifierKind",
  "validatorKeyIdBinding",
  "validatorCommitment",
  "validatorEpoch",
  "recoveryEpoch",
  "recoveryDelaySeconds",
  "recoveryExpirySeconds",
  "userSalt",
  "expiresAt"
] as const);

const INTENT_NUMERIC_KEYS = Object.freeze(
  new Set<string>([
    "intentVersion",
    "chainId",
    "validatorVerifierKind",
    "validatorEpoch",
    "recoveryEpoch",
    "recoveryDelaySeconds",
    "recoveryExpirySeconds",
    "expiresAt"
  ])
);

const CEREMONY_OWN_KEYS = Object.freeze([
  "ceremonyVersion",
  "ceremonyId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "expiresAt"
] as const);

const CEREMONY_NUMERIC_KEYS = Object.freeze(
  new Set<string>(["ceremonyVersion", "role", "credentialGeneration", "expiresAt"])
);

const JOURNAL_OWN_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  ...INTENT_OWN_KEYS,
  "genesisDeploymentIntentHash",
  "state",
  "createdAtUnixSeconds",
  "updatedAtUnixSeconds",
  "manifest",
  "endReason",
  "integrityChecksum"
] as const);

const CANDIDATE_REQUIRED_OWN_KEYS = Object.freeze([
  "descriptor",
  "independence",
  "currentRoleCeremony"
] as const);
const CANDIDATE_OPTIONAL_OWN_KEYS = Object.freeze(["signer"] as const);

const MANIFEST_SLOT_KEYS = Object.freeze(["0", "1", "2"] as const);

const MANIFEST_ENTRY_OWN_KEYS = Object.freeze([
  "role",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "descriptor",
  "independence",
  "signer",
  "factorCommitment",
  "stagedAtUnixSeconds"
] as const);

const DESCRIPTOR_NUMERIC_KEYS = Object.freeze(
  new Set<string>([
    "descriptorVersion",
    "role",
    "verifierKind",
    "userVerificationPolicy",
    "backupPolicy",
    "authenticatorAttachmentPolicy",
    "attestationPolicy",
    "credentialGeneration"
  ])
);
const DESCRIPTOR_OWN_KEYS = Object.freeze([
  "descriptorVersion",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "role",
  "verifierKind",
  "publicVerificationMaterialHash",
  "credentialIdHash",
  "rpIdHash",
  "originPolicyHash",
  "independenceBindingHash",
  "userVerificationPolicy",
  "backupPolicy",
  "authenticatorAttachmentPolicy",
  "attestationPolicy",
  "credentialGeneration"
] as const);

const INDEPENDENCE_NUMERIC_KEYS = Object.freeze(
  new Set<string>([
    "bindingVersion",
    "role",
    "authenticatorClass",
    "synchronizationClass",
    "independenceAssurance",
    "credentialGeneration"
  ])
);
const INDEPENDENCE_OWN_KEYS = Object.freeze([
  "bindingVersion",
  "role",
  "authenticatorClass",
  "synchronizationClass",
  "independenceAssurance",
  "credentialIdHash",
  "enrollmentCeremonyHash",
  "attestationEvidenceHash",
  "custodyDomainCommitment",
  "credentialGeneration"
] as const);

const VALID_STATES = Object.freeze(
  new Set<string>([
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED
  ])
);
const VALID_END_REASONS = Object.freeze(
  new Set<string | null>([
    null,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED
  ])
);

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

export type GenesisStagingJournalState =
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED;

export type GenesisStagingJournalEndReason =
  | null
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED
  | typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED;

// Exact stored descriptor/independence shapes -- intentionally not exported
// (Package 5B-0.4's public type-only export surface is exactly 11 names);
// referenced only from within StoredGenesisManifestEntry below, which is
// exported. There is no arbitrary Record<string, string> escape hatch: a
// stored descriptor/independence must carry precisely these keys, no more
// and no fewer.
type StoredGenesisFactorDescriptor = Readonly<{
  descriptorVersion: string;
  accountVersionId: Hex;
  securityModelId: Hex;
  recoveryDomainId: Hex;
  role: string;
  verifierKind: string;
  publicVerificationMaterialHash: Hex;
  credentialIdHash: Hex;
  rpIdHash: Hex;
  originPolicyHash: Hex;
  independenceBindingHash: Hex;
  userVerificationPolicy: string;
  backupPolicy: string;
  authenticatorAttachmentPolicy: string;
  attestationPolicy: string;
  credentialGeneration: string;
}>;

type StoredGenesisIndependenceRecord = Readonly<{
  bindingVersion: string;
  role: string;
  authenticatorClass: string;
  synchronizationClass: string;
  independenceAssurance: string;
  credentialIdHash: Hex;
  enrollmentCeremonyHash: Hex;
  attestationEvidenceHash: Hex;
  custodyDomainCommitment: Hex;
  credentialGeneration: string;
}>;

export type StoredGenesisManifestEntry = Readonly<{
  role: "0" | "1" | "2";
  ceremonyId: Hex;
  ceremonyExpiresAtUnixSeconds: string;
  genesisEnrollmentCeremonyHash: Hex;
  descriptor: StoredGenesisFactorDescriptor;
  independence: StoredGenesisIndependenceRecord;
  signer: string | null;
  factorCommitment: Hex;
  stagedAtUnixSeconds: string;
}>;

export type GenesisStagingManifest = Readonly<{
  "0": StoredGenesisManifestEntry | null;
  "1": StoredGenesisManifestEntry | null;
  "2": StoredGenesisManifestEntry | null;
}>;

export type GenesisStagingJournalRecordWithoutChecksum = Readonly<{
  schemaVersion: typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION;
  formatProvenance: typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE;
  intentVersion: string;
  intentId: Hex;
  chainId: string;
  entryPoint: string;
  factoryBinding: string;
  confirmationTarget: string;
  verifier: string;
  verifierRuntimeCodeHash: Hex;
  accountCreationBytecodeHash: Hex;
  accountVersionId: Hex;
  securityModelId: Hex;
  recoveryDomainId: Hex;
  ownerCommitment: Hex;
  identityBindingCommitment: Hex;
  initialValidator: string;
  validatorVerifierKind: string;
  validatorKeyIdBinding: Hex;
  validatorCommitment: Hex;
  validatorEpoch: string;
  recoveryEpoch: string;
  recoveryDelaySeconds: string;
  recoveryExpirySeconds: string;
  userSalt: Hex;
  expiresAt: string;
  genesisDeploymentIntentHash: Hex;
  state: GenesisStagingJournalState;
  createdAtUnixSeconds: string;
  updatedAtUnixSeconds: string;
  manifest: GenesisStagingManifest;
  endReason: GenesisStagingJournalEndReason;
}>;

export type GenesisStagingJournalRecord = GenesisStagingJournalRecordWithoutChecksum &
  Readonly<{
    integrityChecksum: Hex;
  }>;

export type ExactUintInput = bigint | string;

export type GenesisStagingFactorDescriptorInput = Omit<
  PhilCoreV2RecoveryFactorDescriptorInput,
  | "descriptorVersion"
  | "role"
  | "verifierKind"
  | "userVerificationPolicy"
  | "backupPolicy"
  | "authenticatorAttachmentPolicy"
  | "attestationPolicy"
  | "credentialGeneration"
> & {
  readonly descriptorVersion: ExactUintInput;
  readonly role: ExactUintInput;
  readonly verifierKind: ExactUintInput;
  readonly userVerificationPolicy: ExactUintInput;
  readonly backupPolicy: ExactUintInput;
  readonly authenticatorAttachmentPolicy: ExactUintInput;
  readonly attestationPolicy: ExactUintInput;
  readonly credentialGeneration: ExactUintInput;
};

export type GenesisStagingIndependenceInput = Omit<
  PhilCoreV2ConsumerRecoveryIndependenceInput,
  | "bindingVersion"
  | "role"
  | "authenticatorClass"
  | "synchronizationClass"
  | "independenceAssurance"
  | "credentialGeneration"
> & {
  readonly bindingVersion: ExactUintInput;
  readonly role: ExactUintInput;
  readonly authenticatorClass: ExactUintInput;
  readonly synchronizationClass: ExactUintInput;
  readonly independenceAssurance: ExactUintInput;
  readonly credentialGeneration: ExactUintInput;
};

export type GenesisStagingRoleCandidateInput = Readonly<{
  descriptor: GenesisStagingFactorDescriptorInput;
  independence: GenesisStagingIndependenceInput;
  signer?: string;
  currentRoleCeremony: PhilCoreV2LocalGenesisEnrollmentCeremonyInput;
}>;

// ---------------------------------------------------------------------------
// Checksum. SHA-256 of a fixed UTF-8 prefix followed by the compact
// JSON.stringify of the exact 32-key projection (every top-level key except
// integrityChecksum), in the journal's own literal field order, with the
// manifest itself projected key-by-key in a fixed nested order. A single
// guarded read per field -- never a second ordinary lookup -- so a hostile
// getter cannot leak a raw value or mask which field actually failed. Every
// leaf is additionally type-checked to its exact primitive shape (number,
// string, or string|null) the instant it is read, before it is placed into
// the projection -- an object-valued leaf (with a hostile own toJSON,
// getter trap, boxed primitive, etc.) is therefore rejected outright and
// never reaches JSON.stringify. Every projection container -- top-level,
// manifest, entry, descriptor, independence -- is built with a null
// prototype (Object.create(null), never a plain object literal), so a
// hostile globally inherited Object.prototype.toJSON also cannot be found
// by JSON.stringify's own prototype-chain lookup.
// ---------------------------------------------------------------------------

// Every top-level key set except integrityChecksum itself -- the checksum
// API's own boundary is exactly these 32 keys, so a caller-supplied
// integrityChecksum (or any other extra key) is rejected as an extra key,
// never silently ignored.
const CHECKSUM_OWN_KEYS = Object.freeze(JOURNAL_OWN_KEYS.slice(0, -1));

function requireChecksumLeafString(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): string {
  if (typeof value !== "string") fail(code);
  return value;
}

function requireChecksumLeafStringOrNull(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): string | null {
  if (value !== null && typeof value !== "string") fail(code);
  return value as string | null;
}

function requireChecksumLeafNumber(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): number {
  if (typeof value !== "number") fail(code);
  return value;
}

// Recursively rebuilds an already-trusted, already-shaped internal value --
// never raw untrusted caller input; every leaf reaching this point has
// already been read via a guarded descriptor and type-checked -- using
// null-prototype containers throughout, so a globally polluted
// Object.prototype.toJSON cannot be found via the prototype chain by the
// JSON.stringify call that follows. Ordinary Object.keys enumeration is
// safe here specifically because the input is always our own previously
// constructed, already-type-checked data, never a live caller-owned object.
function nullProtoClone(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  const out: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(value as Record<string, unknown>)) {
    out[key] = nullProtoClone((value as Record<string, unknown>)[key]);
  }
  return out;
}

// Verifies exact key ownership at the given boundary, then copies every
// accepted, string-type-checked value into a fresh, fully owned,
// null-prototype plain object in the caller's declared key order -- a
// single guarded read per field, never a second ordinary lookup, and never
// a live caller-owned reference (nor an object-valued leaf of any kind)
// surviving into the returned projection.
function projectExactKeysForChecksum(
  value: unknown,
  keys: readonly string[],
  notObjectCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  missingCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode,
  readCode: PhilCoreV2ConsumerRecoveryGenesisStagingJournalErrorCode
): Record<string, unknown> {
  const obj = requirePlainObject(value, notObjectCode);
  const verified = requireExactOwnKeys(obj, keys, [], missingCode, extraCode, enumerationCode);
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const raw = readValueFromVerifiedDescriptor(obj, verified.get(key) as PropertyDescriptor, readCode);
    out[key] = requireChecksumLeafString(raw, readCode);
  }
  return out;
}

function projectManifestEntryForChecksum(entryValue: unknown): unknown {
  if (entryValue === null) {
    return null;
  }
  const RE = C.MANIFEST_ENTRY_PROPERTY_READ_FAILED;
  const entryObj = requirePlainObject(entryValue, C.MANIFEST_ENTRY_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    entryObj,
    MANIFEST_ENTRY_OWN_KEYS,
    [],
    C.MANIFEST_ENTRY_MISSING_KEY,
    C.MANIFEST_ENTRY_EXTRA_KEY,
    C.MANIFEST_ENTRY_ENUMERATION_FAILED
  );
  const read = (key: string): unknown =>
    readValueFromVerifiedDescriptor(entryObj, verified.get(key) as PropertyDescriptor, RE);

  const descriptorRaw = read("descriptor");
  const independenceRaw = read("independence");
  const out: Record<string, unknown> = Object.create(null);
  out.role = requireChecksumLeafString(read("role"), RE);
  out.ceremonyId = requireChecksumLeafString(read("ceremonyId"), RE);
  out.ceremonyExpiresAtUnixSeconds = requireChecksumLeafString(read("ceremonyExpiresAtUnixSeconds"), RE);
  out.genesisEnrollmentCeremonyHash = requireChecksumLeafString(read("genesisEnrollmentCeremonyHash"), RE);
  out.descriptor = projectExactKeysForChecksum(descriptorRaw, DESCRIPTOR_OWN_KEYS, RE, RE, RE, RE, RE);
  out.independence = projectExactKeysForChecksum(independenceRaw, INDEPENDENCE_OWN_KEYS, RE, RE, RE, RE, RE);
  out.signer = requireChecksumLeafStringOrNull(read("signer"), RE);
  out.factorCommitment = requireChecksumLeafString(read("factorCommitment"), RE);
  out.stagedAtUnixSeconds = requireChecksumLeafString(read("stagedAtUnixSeconds"), RE);
  return out;
}

function projectManifestForChecksum(
  manifestValue: unknown
): { "0": unknown; "1": unknown; "2": unknown } {
  const obj = requirePlainObject(manifestValue, C.MANIFEST_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    obj,
    MANIFEST_SLOT_KEYS,
    [],
    C.MANIFEST_MISSING_KEY,
    C.MANIFEST_EXTRA_KEY,
    C.MANIFEST_ENUMERATION_FAILED
  );
  const R = C.JOURNAL_PROPERTY_READ_FAILED;
  const out = Object.create(null) as { "0": unknown; "1": unknown; "2": unknown };
  out["0"] = projectManifestEntryForChecksum(
    readValueFromVerifiedDescriptor(obj, verified.get("0") as PropertyDescriptor, R)
  );
  out["1"] = projectManifestEntryForChecksum(
    readValueFromVerifiedDescriptor(obj, verified.get("1") as PropertyDescriptor, R)
  );
  out["2"] = projectManifestEntryForChecksum(
    readValueFromVerifiedDescriptor(obj, verified.get("2") as PropertyDescriptor, R)
  );
  return out;
}

export function computeGenesisStagingJournalChecksum(
  record: GenesisStagingJournalRecordWithoutChecksum
): Hex {
  const source = requirePlainObject(record, C.JOURNAL_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    source,
    CHECKSUM_OWN_KEYS,
    [],
    C.JOURNAL_MISSING_KEY,
    C.JOURNAL_EXTRA_KEY,
    C.JOURNAL_ENUMERATION_FAILED
  );
  const R = C.JOURNAL_PROPERTY_READ_FAILED;
  const read = (key: string): unknown =>
    readValueFromVerifiedDescriptor(source, verified.get(key) as PropertyDescriptor, R);
  const readString = (key: string): string => requireChecksumLeafString(read(key), R);

  const schemaVersion = requireChecksumLeafNumber(read("schemaVersion"), R);
  const formatProvenance = readString("formatProvenance");
  const intentVersion = readString("intentVersion");
  const intentId = readString("intentId");
  const chainId = readString("chainId");
  const entryPoint = readString("entryPoint");
  const factoryBinding = readString("factoryBinding");
  const confirmationTarget = readString("confirmationTarget");
  const verifier = readString("verifier");
  const verifierRuntimeCodeHash = readString("verifierRuntimeCodeHash");
  const accountCreationBytecodeHash = readString("accountCreationBytecodeHash");
  const accountVersionId = readString("accountVersionId");
  const securityModelId = readString("securityModelId");
  const recoveryDomainId = readString("recoveryDomainId");
  const ownerCommitment = readString("ownerCommitment");
  const identityBindingCommitment = readString("identityBindingCommitment");
  const initialValidator = readString("initialValidator");
  const validatorVerifierKind = readString("validatorVerifierKind");
  const validatorKeyIdBinding = readString("validatorKeyIdBinding");
  const validatorCommitment = readString("validatorCommitment");
  const validatorEpoch = readString("validatorEpoch");
  const recoveryEpoch = readString("recoveryEpoch");
  const recoveryDelaySeconds = readString("recoveryDelaySeconds");
  const recoveryExpirySeconds = readString("recoveryExpirySeconds");
  const userSalt = readString("userSalt");
  const expiresAt = readString("expiresAt");
  const genesisDeploymentIntentHash = readString("genesisDeploymentIntentHash");
  const state = readString("state");
  const createdAtUnixSeconds = readString("createdAtUnixSeconds");
  const updatedAtUnixSeconds = readString("updatedAtUnixSeconds");
  const manifestRaw = read("manifest");
  const endReason = requireChecksumLeafStringOrNull(read("endReason"), R);

  // Every leaf above has already been type-checked to a primitive shape,
  // and manifest is projected into a fully owned, null-prototype structure
  // -- the object handed to JSON.stringify below therefore never contains
  // a live caller-owned reference, an object-valued leaf, or a
  // plain-prototype container reachable by a polluted Object.prototype.
  const projectionSource: Record<string, unknown> = Object.create(null);
  projectionSource.schemaVersion = schemaVersion;
  projectionSource.formatProvenance = formatProvenance;
  projectionSource.intentVersion = intentVersion;
  projectionSource.intentId = intentId;
  projectionSource.chainId = chainId;
  projectionSource.entryPoint = entryPoint;
  projectionSource.factoryBinding = factoryBinding;
  projectionSource.confirmationTarget = confirmationTarget;
  projectionSource.verifier = verifier;
  projectionSource.verifierRuntimeCodeHash = verifierRuntimeCodeHash;
  projectionSource.accountCreationBytecodeHash = accountCreationBytecodeHash;
  projectionSource.accountVersionId = accountVersionId;
  projectionSource.securityModelId = securityModelId;
  projectionSource.recoveryDomainId = recoveryDomainId;
  projectionSource.ownerCommitment = ownerCommitment;
  projectionSource.identityBindingCommitment = identityBindingCommitment;
  projectionSource.initialValidator = initialValidator;
  projectionSource.validatorVerifierKind = validatorVerifierKind;
  projectionSource.validatorKeyIdBinding = validatorKeyIdBinding;
  projectionSource.validatorCommitment = validatorCommitment;
  projectionSource.validatorEpoch = validatorEpoch;
  projectionSource.recoveryEpoch = recoveryEpoch;
  projectionSource.recoveryDelaySeconds = recoveryDelaySeconds;
  projectionSource.recoveryExpirySeconds = recoveryExpirySeconds;
  projectionSource.userSalt = userSalt;
  projectionSource.expiresAt = expiresAt;
  projectionSource.genesisDeploymentIntentHash = genesisDeploymentIntentHash;
  projectionSource.state = state;
  projectionSource.createdAtUnixSeconds = createdAtUnixSeconds;
  projectionSource.updatedAtUnixSeconds = updatedAtUnixSeconds;
  projectionSource.manifest = projectManifestForChecksum(manifestRaw);
  projectionSource.endReason = endReason;

  let projection: string;
  try {
    projection = JSON.stringify(projectionSource);
  } catch (error) {
    failWithCause(R, error);
  }
  const digest = createHash("sha256")
    .update(PHILCORE_V2_GENESIS_STAGING_JOURNAL_CHECKSUM_PREFIX, "utf8")
    .update(projection, "utf8")
    .digest("hex");
  return `0x${digest}` as Hex;
}

// ---------------------------------------------------------------------------
// Size guards. Applied to an already-owned (never a live caller-owned
// object), already-type-checked value -- never ordinary `JSON.stringify` on
// a still-hostile object. The size check runs before deeper semantic/format
// validation of the same field values, exactly mirroring the landed
// staging-journal precedent's own ordering, so a grossly oversized but
// type-correct hostile string is rejected here rather than reaching a
// later, more expensive check.
// ---------------------------------------------------------------------------

function compactStoredEntryBytes(entry: StoredGenesisManifestEntry): number {
  const projection: Record<string, unknown> = Object.create(null);
  projection.role = entry.role;
  projection.ceremonyId = entry.ceremonyId;
  projection.ceremonyExpiresAtUnixSeconds = entry.ceremonyExpiresAtUnixSeconds;
  projection.genesisEnrollmentCeremonyHash = entry.genesisEnrollmentCeremonyHash;
  projection.descriptor = nullProtoClone(entry.descriptor);
  projection.independence = nullProtoClone(entry.independence);
  projection.signer = entry.signer;
  projection.factorCommitment = entry.factorCommitment;
  projection.stagedAtUnixSeconds = entry.stagedAtUnixSeconds;
  return Buffer.byteLength(JSON.stringify(projection), "utf8");
}

function validateManifestEntryOversized(entry: StoredGenesisManifestEntry): void {
  if (compactStoredEntryBytes(entry) > MAX_GENESIS_MANIFEST_ENTRY_BYTES) {
    fail(C.MANIFEST_ENTRY_OVERSIZED);
  }
}

function validateJournalOversized(record: GenesisStagingJournalRecord): void {
  const bytes = Buffer.byteLength(JSON.stringify(nullProtoClone(record)), "utf8");
  if (bytes > MAX_GENESIS_JOURNAL_FILE_BYTES) {
    fail(C.JOURNAL_OVERSIZED);
  }
}

// ---------------------------------------------------------------------------
// Intent extraction. Every field is read exactly once, via a verified own
// descriptor, from the caller-owned intent object into a fresh, owned
// snapshot; numeric fields are converted to canonical decimal strings here
// (rejecting a JavaScript number outright), hash/address fields are copied
// verbatim. That owned snapshot -- never the caller's original object -- is
// then handed to the landed genesis-protocol hash function, which is the
// sole authority for full semantic validation (pinned values, zero
// rejection, exact bit widths). Any failure there collapses to
// GENESIS_INTENT_VALIDATION_FAILED.
// ---------------------------------------------------------------------------

function extractIntentSnapshot(intentValue: unknown): Record<string, unknown> {
  const intentObj = requirePlainObject(intentValue, C.JOURNAL_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    intentObj,
    INTENT_OWN_KEYS,
    [],
    C.JOURNAL_MISSING_KEY,
    C.JOURNAL_EXTRA_KEY,
    C.JOURNAL_ENUMERATION_FAILED
  );
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of INTENT_OWN_KEYS) {
    const raw = readValueFromVerifiedDescriptor(
      intentObj,
      verified.get(key) as PropertyDescriptor,
      C.JOURNAL_PROPERTY_READ_FAILED
    );
    if (INTENT_NUMERIC_KEYS.has(key)) {
      if (typeof raw === "number") fail(C.JOURNAL_PROPERTY_READ_FAILED);
      if (typeof raw !== "bigint" && typeof raw !== "string") fail(C.JOURNAL_PROPERTY_READ_FAILED);
      snapshot[key] = typeof raw === "bigint" ? raw.toString(10) : raw;
    } else {
      snapshot[key] = raw;
    }
  }
  return Object.freeze(snapshot);
}

function hashIntentSnapshot(snapshot: Record<string, unknown>): Hex {
  try {
    return computePhilCoreV2LocalGenesisDeploymentIntentHash(
      snapshot as unknown as PhilCoreV2LocalGenesisDeploymentIntentInput
    );
  } catch (error) {
    failWithCause(C.GENESIS_INTENT_VALIDATION_FAILED, error);
  }
}

function buildManifestObject(manifest: GenesisStagingManifest): GenesisStagingManifest {
  return Object.freeze({
    "0": manifest["0"] === null ? null : Object.freeze({ ...manifest["0"] }),
    "1": manifest["1"] === null ? null : Object.freeze({ ...manifest["1"] }),
    "2": manifest["2"] === null ? null : Object.freeze({ ...manifest["2"] })
  });
}

function buildJournalRecord(
  fields: GenesisStagingJournalRecordWithoutChecksum
): GenesisStagingJournalRecord {
  const withoutChecksum: GenesisStagingJournalRecordWithoutChecksum = {
    schemaVersion: fields.schemaVersion,
    formatProvenance: fields.formatProvenance,
    intentVersion: fields.intentVersion,
    intentId: fields.intentId,
    chainId: fields.chainId,
    entryPoint: fields.entryPoint,
    factoryBinding: fields.factoryBinding,
    confirmationTarget: fields.confirmationTarget,
    verifier: fields.verifier,
    verifierRuntimeCodeHash: fields.verifierRuntimeCodeHash,
    accountCreationBytecodeHash: fields.accountCreationBytecodeHash,
    accountVersionId: fields.accountVersionId,
    securityModelId: fields.securityModelId,
    recoveryDomainId: fields.recoveryDomainId,
    ownerCommitment: fields.ownerCommitment,
    identityBindingCommitment: fields.identityBindingCommitment,
    initialValidator: fields.initialValidator,
    validatorVerifierKind: fields.validatorVerifierKind,
    validatorKeyIdBinding: fields.validatorKeyIdBinding,
    validatorCommitment: fields.validatorCommitment,
    validatorEpoch: fields.validatorEpoch,
    recoveryEpoch: fields.recoveryEpoch,
    recoveryDelaySeconds: fields.recoveryDelaySeconds,
    recoveryExpirySeconds: fields.recoveryExpirySeconds,
    userSalt: fields.userSalt,
    expiresAt: fields.expiresAt,
    genesisDeploymentIntentHash: fields.genesisDeploymentIntentHash,
    state: fields.state,
    createdAtUnixSeconds: fields.createdAtUnixSeconds,
    updatedAtUnixSeconds: fields.updatedAtUnixSeconds,
    manifest: buildManifestObject(fields.manifest),
    endReason: fields.endReason
  };
  const record: GenesisStagingJournalRecord = {
    ...withoutChecksum,
    integrityChecksum: computeGenesisStagingJournalChecksum(withoutChecksum)
  };
  validateJournalOversized(record);
  return deepFreeze(record);
}

// ---------------------------------------------------------------------------
// Public: creation.
// ---------------------------------------------------------------------------

export function createGenesisStagingJournal(
  intent: PhilCoreV2LocalGenesisDeploymentIntentInput,
  nowUnixSeconds: number
): GenesisStagingJournalRecord {
  const intentSnapshot = extractIntentSnapshot(intent);
  const genesisDeploymentIntentHash = hashIntentSnapshot(intentSnapshot);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  const expiresAt = BigInt(intentSnapshot.expiresAt as string);
  if (now >= expiresAt) {
    fail(C.JOURNAL_CREATION_NOT_BEFORE_EXPIRY);
  }
  const nowString = now.toString(10);
  return buildJournalRecord({
    schemaVersion: PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE,
    ...(intentSnapshot as unknown as Omit<
      GenesisStagingJournalRecordWithoutChecksum,
      | "schemaVersion"
      | "formatProvenance"
      | "genesisDeploymentIntentHash"
      | "state"
      | "createdAtUnixSeconds"
      | "updatedAtUnixSeconds"
      | "manifest"
      | "endReason"
    >),
    genesisDeploymentIntentHash,
    state: PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING,
    createdAtUnixSeconds: nowString,
    updatedAtUnixSeconds: nowString,
    manifest: { "0": null, "1": null, "2": null },
    endReason: null
  });
}

// ---------------------------------------------------------------------------
// Per-role staging.
// ---------------------------------------------------------------------------

function extractCeremonySnapshot(ceremonyValue: unknown): Record<string, unknown> {
  const ceremonyObj = requirePlainObject(ceremonyValue, C.CANDIDATE_INPUT_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    ceremonyObj,
    CEREMONY_OWN_KEYS,
    [],
    C.CANDIDATE_INPUT_MISSING_KEY,
    C.CANDIDATE_INPUT_EXTRA_KEY,
    C.CANDIDATE_ENUMERATION_FAILED
  );
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of CEREMONY_OWN_KEYS) {
    const raw = readValueFromVerifiedDescriptor(
      ceremonyObj,
      verified.get(key) as PropertyDescriptor,
      C.CANDIDATE_PROPERTY_READ_FAILED
    );
    if (CEREMONY_NUMERIC_KEYS.has(key)) {
      if (typeof raw === "number") fail(C.CANDIDATE_PROPERTY_READ_FAILED);
      if (typeof raw !== "bigint" && typeof raw !== "string") fail(C.CANDIDATE_PROPERTY_READ_FAILED);
      snapshot[key] = typeof raw === "bigint" ? raw.toString(10) : raw;
    } else {
      snapshot[key] = raw;
    }
  }
  return Object.freeze(snapshot);
}

function hashCeremonySnapshot(snapshot: Record<string, unknown>): Hex {
  try {
    return computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
      snapshot as unknown as PhilCoreV2LocalGenesisEnrollmentCeremonyInput
    );
  } catch (error) {
    failWithCause(C.GENESIS_CEREMONY_VALIDATION_FAILED, error);
  }
}

// The shared factor-policy validator returns a snapshot whose numeric
// fields may still be bigint or (already-canonical) string, whichever the
// caller originally supplied -- proven canonical by the validator's own
// successful return, never re-validated here, only converted to the
// storage-format canonical decimal string. Hash/address fields are already
// proven canonical and are copied verbatim; this is a transform of an
// already-owned, already-validated intermediate object, never a second
// read of anything caller-owned.
function normalizeFactorFieldsForStorage(
  fields: Record<string, unknown>,
  numericKeys: ReadonlySet<string>,
  keyOrder: readonly string[]
): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  for (const key of keyOrder) {
    const value = fields[key];
    if (numericKeys.has(key)) {
      out[key] = typeof value === "bigint" ? value.toString(10) : (value as string);
    } else {
      out[key] = value as string;
    }
  }
  return Object.freeze(out);
}

function extractRoleCandidateTop(roleInputValue: unknown): {
  readonly descriptorRaw: unknown;
  readonly independenceRaw: unknown;
  readonly signerPresent: boolean;
  readonly signerRaw: unknown;
  readonly currentRoleCeremonyRaw: unknown;
} {
  const obj = requirePlainObject(roleInputValue, C.CANDIDATE_INPUT_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    obj,
    CANDIDATE_REQUIRED_OWN_KEYS,
    CANDIDATE_OPTIONAL_OWN_KEYS,
    C.CANDIDATE_INPUT_MISSING_KEY,
    C.CANDIDATE_INPUT_EXTRA_KEY,
    C.CANDIDATE_ENUMERATION_FAILED
  );
  const descriptorRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("descriptor") as PropertyDescriptor,
    C.CANDIDATE_PROPERTY_READ_FAILED
  );
  const independenceRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("independence") as PropertyDescriptor,
    C.CANDIDATE_PROPERTY_READ_FAILED
  );
  const currentRoleCeremonyRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("currentRoleCeremony") as PropertyDescriptor,
    C.CANDIDATE_PROPERTY_READ_FAILED
  );
  const signerPresent = verified.has("signer");
  const signerRaw = signerPresent
    ? readValueFromVerifiedDescriptor(
      obj,
      verified.get("signer") as PropertyDescriptor,
      C.CANDIDATE_PROPERTY_READ_FAILED
    )
    : undefined;
  return { descriptorRaw, independenceRaw, signerPresent, signerRaw, currentRoleCeremonyRaw };
}

// Guardedly exact-snapshots a candidate descriptor's 16 fields or
// independence's 10 fields before factor-policy delegation: exact key
// ownership is verified, every field is read exactly once via a verified
// own descriptor, and every numeric field is required to be bigint or
// string -- the closed ExactUintInput candidate surface -- rejecting a
// JavaScript number outright. Non-numeric fields are required to be
// string, their expected primitive runtime shape. The returned snapshot is
// a fresh, fully owned, frozen object; only it -- never the caller's
// original descriptor/independence object -- is handed to
// validatePhilCoreV2ConsumerRecoveryFactorPolicy, so the caller's argument
// is never read again after this snapshot completes.
function requireCandidateFactorFieldsSnapshot(
  value: unknown,
  keys: readonly string[],
  numericKeys: ReadonlySet<string>
): Record<string, unknown> {
  const obj = requirePlainObject(value, C.CANDIDATE_INPUT_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    obj,
    keys,
    [],
    C.CANDIDATE_INPUT_MISSING_KEY,
    C.CANDIDATE_INPUT_EXTRA_KEY,
    C.CANDIDATE_ENUMERATION_FAILED
  );
  const RE = C.CANDIDATE_PROPERTY_READ_FAILED;
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const raw = readValueFromVerifiedDescriptor(obj, verified.get(key) as PropertyDescriptor, RE);
    if (numericKeys.has(key)) {
      if (typeof raw !== "bigint" && typeof raw !== "string") fail(RE);
    } else if (typeof raw !== "string") {
      fail(RE);
    }
    out[key] = raw;
  }
  return Object.freeze(out);
}

function assertNoClockRegression(now: bigint, updatedAtUnixSeconds: string): void {
  if (now < BigInt(updatedAtUnixSeconds)) {
    fail(C.CLOCK_REGRESSION_DETECTED);
  }
}

function intentPortion(
  record: GenesisStagingJournalRecordWithoutChecksum
): Omit<
  GenesisStagingJournalRecordWithoutChecksum,
  | "schemaVersion"
  | "formatProvenance"
  | "state"
  | "createdAtUnixSeconds"
  | "updatedAtUnixSeconds"
  | "manifest"
  | "endReason"
> {
  return {
    intentVersion: record.intentVersion,
    intentId: record.intentId,
    chainId: record.chainId,
    entryPoint: record.entryPoint,
    factoryBinding: record.factoryBinding,
    confirmationTarget: record.confirmationTarget,
    verifier: record.verifier,
    verifierRuntimeCodeHash: record.verifierRuntimeCodeHash,
    accountCreationBytecodeHash: record.accountCreationBytecodeHash,
    accountVersionId: record.accountVersionId,
    securityModelId: record.securityModelId,
    recoveryDomainId: record.recoveryDomainId,
    ownerCommitment: record.ownerCommitment,
    identityBindingCommitment: record.identityBindingCommitment,
    initialValidator: record.initialValidator,
    validatorVerifierKind: record.validatorVerifierKind,
    validatorKeyIdBinding: record.validatorKeyIdBinding,
    validatorCommitment: record.validatorCommitment,
    validatorEpoch: record.validatorEpoch,
    recoveryEpoch: record.recoveryEpoch,
    recoveryDelaySeconds: record.recoveryDelaySeconds,
    recoveryExpirySeconds: record.recoveryExpirySeconds,
    userSalt: record.userSalt,
    expiresAt: record.expiresAt,
    genesisDeploymentIntentHash: record.genesisDeploymentIntentHash
  };
}

function buildTransitionedJournal(
  current: GenesisStagingJournalRecord,
  now: bigint,
  nextState: GenesisStagingJournalState,
  nextEndReason: GenesisStagingJournalEndReason,
  manifestOverride?: GenesisStagingManifest
): GenesisStagingJournalRecord {
  return buildJournalRecord({
    schemaVersion: current.schemaVersion,
    formatProvenance: current.formatProvenance,
    ...intentPortion(current),
    state: nextState,
    createdAtUnixSeconds: current.createdAtUnixSeconds,
    updatedAtUnixSeconds: now.toString(10),
    manifest: manifestOverride ?? current.manifest,
    endReason: nextEndReason
  });
}

function requireStagingJournal(journal: unknown): GenesisStagingJournalRecord {
  const validated = validateGenesisStagingJournalRecord(journal);
  if (validated.state !== PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING) {
    fail(C.JOURNAL_NOT_STAGING);
  }
  return validated;
}

export function stageGenesisRoleCandidate(
  journal: GenesisStagingJournalRecord,
  expectedRole: 0 | 1 | 2,
  roleInput: GenesisStagingRoleCandidateInput,
  nowUnixSeconds: number
): GenesisStagingJournalRecord {
  const current = requireStagingJournal(journal);

  if (!(expectedRole === 0 || expectedRole === 1 || expectedRole === 2)) {
    fail(C.ROLE_INVALID);
  }

  const populated: readonly [boolean, boolean, boolean] = [
    current.manifest["0"] !== null,
    current.manifest["1"] !== null,
    current.manifest["2"] !== null
  ];
  const populatedCount = (populated[0] ? 1 : 0) + (populated[1] ? 1 : 0) + (populated[2] ? 1 : 0);
  if (expectedRole !== populatedCount) {
    const slotKey = String(expectedRole) as "0" | "1" | "2";
    if (current.manifest[slotKey] !== null) {
      fail(C.ROLE_SLOT_ALREADY_POPULATED);
    }
    fail(C.ROLE_SEQUENCE_VIOLATION);
  }

  const { descriptorRaw, independenceRaw, signerPresent, signerRaw, currentRoleCeremonyRaw } =
    extractRoleCandidateTop(roleInput);
  const ceremonySnapshot = extractCeremonySnapshot(currentRoleCeremonyRaw);

  const descriptorSnapshot = requireCandidateFactorFieldsSnapshot(
    descriptorRaw,
    DESCRIPTOR_OWN_KEYS,
    DESCRIPTOR_NUMERIC_KEYS
  );
  const independenceSnapshot = requireCandidateFactorFieldsSnapshot(
    independenceRaw,
    INDEPENDENCE_OWN_KEYS,
    INDEPENDENCE_NUMERIC_KEYS
  );
  const factorInput = signerPresent
    ? { descriptor: descriptorSnapshot, independence: independenceSnapshot, signer: signerRaw }
    : { descriptor: descriptorSnapshot, independence: independenceSnapshot };
  let result: {
    factor: { descriptor: Record<string, unknown>; independence: Record<string, unknown>; signer?: string };
    factorCommitment: Hex;
  };
  try {
    result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(
      factorInput as never,
      expectedRole
    ) as never;
  } catch (error) {
    failWithCause(C.FACTOR_POLICY_VALIDATION_FAILED, error);
  }

  const descriptorStored = normalizeFactorFieldsForStorage(
    result.factor.descriptor,
    DESCRIPTOR_NUMERIC_KEYS,
    DESCRIPTOR_OWN_KEYS
  );
  const independenceStored = normalizeFactorFieldsForStorage(
    result.factor.independence,
    INDEPENDENCE_NUMERIC_KEYS,
    INDEPENDENCE_OWN_KEYS
  );
  const factorCommitment = result.factorCommitment;
  const signerStored: string | null = result.factor.signer ?? null;

  const genesisEnrollmentCeremonyHash = hashCeremonySnapshot(ceremonySnapshot);
  if (independenceStored.enrollmentCeremonyHash !== genesisEnrollmentCeremonyHash) {
    fail(C.FACTOR_CEREMONY_HASH_MISMATCH);
  }
  if ((ceremonySnapshot.genesisDeploymentIntentHash as string) !== current.genesisDeploymentIntentHash) {
    fail(C.CEREMONY_INTENT_HASH_MISMATCH);
  }
  if (BigInt(ceremonySnapshot.role as string) !== BigInt(expectedRole)) {
    fail(C.CEREMONY_ROLE_MISMATCH);
  }
  if (descriptorStored.credentialGeneration !== "1" || (ceremonySnapshot.credentialGeneration as string) !== "1") {
    fail(C.CREDENTIAL_GENERATION_NOT_ONE);
  }
  if (BigInt(ceremonySnapshot.expiresAt as string) > BigInt(current.expiresAt)) {
    fail(C.CEREMONY_EXPIRY_EXCEEDS_INTENT_EXPIRY);
  }

  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);

  if (now >= BigInt(current.expiresAt)) {
    return buildTransitionedJournal(
      current,
      now,
      PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED,
      PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED
    );
  }
  if (now >= BigInt(ceremonySnapshot.expiresAt as string)) {
    fail(C.CURRENT_ROLE_CEREMONY_EXPIRED);
  }

  const populatedEntries = [
    current.manifest["0"],
    current.manifest["1"],
    current.manifest["2"]
  ].filter((entry): entry is StoredGenesisManifestEntry => entry !== null);

  for (const entry of populatedEntries) {
    if (entry.ceremonyId === (ceremonySnapshot.ceremonyId as string)) fail(C.CEREMONY_ID_DUPLICATE);
    if (entry.factorCommitment === factorCommitment) fail(C.FACTOR_COMMITMENT_DUPLICATE);
    if (entry.descriptor.publicVerificationMaterialHash === descriptorStored.publicVerificationMaterialHash) {
      fail(C.PUBLIC_VERIFICATION_MATERIAL_HASH_DUPLICATE);
    }
    if (entry.independence.custodyDomainCommitment === independenceStored.custodyDomainCommitment) {
      fail(C.CUSTODY_DOMAIN_COMMITMENT_DUPLICATE);
    }
  }
  if (expectedRole === 1 && current.manifest["0"] !== null) {
    if (current.manifest["0"].independence.credentialIdHash === independenceStored.credentialIdHash) {
      fail(C.CREDENTIAL_ID_HASH_DUPLICATE);
    }
  }

  if (expectedRole === 2) {
    if (signerStored === null) fail(C.FACTOR_POLICY_VALIDATION_FAILED);
    if (signerStored === current.initialValidator) fail(C.SIGNER_ALIASES_INITIAL_VALIDATOR);
  }

  const nowString = now.toString(10);
  const entry: StoredGenesisManifestEntry = {
    role: String(expectedRole) as "0" | "1" | "2",
    ceremonyId: ceremonySnapshot.ceremonyId as Hex,
    ceremonyExpiresAtUnixSeconds: ceremonySnapshot.expiresAt as string,
    genesisEnrollmentCeremonyHash,
    descriptor: descriptorStored as unknown as StoredGenesisManifestEntry["descriptor"],
    independence: independenceStored as unknown as StoredGenesisManifestEntry["independence"],
    signer: signerStored,
    factorCommitment,
    stagedAtUnixSeconds: nowString
  };
  validateManifestEntryOversized(entry);

  const slotKey = String(expectedRole) as "0" | "1" | "2";
  const nextManifest: GenesisStagingManifest = {
    "0": slotKey === "0" ? entry : current.manifest["0"],
    "1": slotKey === "1" ? entry : current.manifest["1"],
    "2": slotKey === "2" ? entry : current.manifest["2"]
  };

  return buildTransitionedJournal(
    current,
    now,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING,
    null,
    nextManifest
  );
}

// ---------------------------------------------------------------------------
// Terminal transitions.
// ---------------------------------------------------------------------------

export function cancelGenesisStagingJournal(
  journal: GenesisStagingJournalRecord,
  nowUnixSeconds: number
): GenesisStagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);
  if (now >= BigInt(current.expiresAt)) {
    return buildTransitionedJournal(
      current,
      now,
      PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED,
      PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED
    );
  }
  return buildTransitionedJournal(
    current,
    now,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED
  );
}

export function expireGenesisStagingJournalIfNeeded(
  journal: GenesisStagingJournalRecord,
  nowUnixSeconds: number
): GenesisStagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);
  if (now < BigInt(current.expiresAt)) {
    return current;
  }
  return buildTransitionedJournal(
    current,
    now,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED
  );
}

export function supersedeGenesisStagingJournal(
  journal: GenesisStagingJournalRecord,
  nowUnixSeconds: number
): GenesisStagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);
  return buildTransitionedJournal(
    current,
    now,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED,
    PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED
  );
}

export function allGenesisStagingSlotsPopulated(
  journal: GenesisStagingJournalRecord
): boolean {
  const current = validateGenesisStagingJournalRecord(journal);
  return (
    current.manifest["0"] !== null
    && current.manifest["1"] !== null
    && current.manifest["2"] !== null
  );
}

// ---------------------------------------------------------------------------
// Stored-record validation. Independently reconstructs and enforces every
// invariant from the stored value alone -- it never trusts that a record
// arrived via `stageGenesisRoleCandidate`. A forged record with a merely
// recomputed checksum cannot bypass a rule that is otherwise only checked
// during live staging.
// ---------------------------------------------------------------------------

// Phase 1 (type-checked, not yet format/semantically validated) result for
// one manifest slot: a tentative StoredGenesisManifestEntry built entirely
// from string-typed fields, plus the individual raw fields so phase 2 can
// finish validation without a second read of the caller's original object.
type TentativeManifestEntryExtraction = Readonly<{
  tentative: StoredGenesisManifestEntry;
  roleSlotString: "0" | "1" | "2";
  signerRaw: string | null;
  ceremonyIdRaw: string;
  ceremonyExpiresAtRaw: string;
  genesisEnrollmentCeremonyHashRaw: string;
  factorCommitmentRaw: string;
  stagedAtRaw: string;
  descriptorTypeChecked: Readonly<Record<string, string>>;
  independenceTypeChecked: Readonly<Record<string, string>>;
}>;

// Phase 1: verify exact key ownership and that every field is string-typed
// (defect 2 -- a forged stored bigint/number is rejected here, never
// silently normalized), without performing canonical-format validation,
// ceremony-hash reconstruction, or factor-policy delegation. The resulting
// tentative entry is a fully owned, type-checked snapshot suitable for the
// byte-ceiling guard to run against before any deeper, more expensive
// validation (defect 5).
function extractTentativeManifestEntry(
  slot: 0 | 1 | 2,
  raw: unknown
): TentativeManifestEntryExtraction | null {
  if (raw === null) {
    return null;
  }
  const entryObj = requirePlainObject(raw, C.MANIFEST_ENTRY_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    entryObj,
    MANIFEST_ENTRY_OWN_KEYS,
    [],
    C.MANIFEST_ENTRY_MISSING_KEY,
    C.MANIFEST_ENTRY_EXTRA_KEY,
    C.MANIFEST_ENTRY_ENUMERATION_FAILED
  );
  const RE = C.MANIFEST_ENTRY_PROPERTY_READ_FAILED;

  const roleRaw = readValueFromVerifiedDescriptor(entryObj, verified.get("role") as PropertyDescriptor, RE);
  const roleSlotString = String(slot) as "0" | "1" | "2";
  if (typeof roleRaw !== "string" || roleRaw !== roleSlotString) {
    fail(C.MANIFEST_SLOT_ROLE_MISMATCH);
  }

  // Explicit stored signer field, read directly and inspected before any
  // further reconstruction -- a forged non-null signer for roles 0/1 is
  // rejected here, never silently omitted while building the object handed
  // to the shared factor-policy validator.
  const signerRawValue = readValueFromVerifiedDescriptor(entryObj, verified.get("signer") as PropertyDescriptor, RE);
  if (slot < 2 && signerRawValue !== null) {
    fail(C.MANIFEST_ENTRY_SIGNER_MUST_BE_NULL);
  }
  if (signerRawValue !== null && typeof signerRawValue !== "string") {
    fail(RE);
  }
  const signerRaw = signerRawValue as string | null;

  const ceremonyIdRaw = readValueFromVerifiedDescriptor(entryObj, verified.get("ceremonyId") as PropertyDescriptor, RE);
  if (typeof ceremonyIdRaw !== "string") fail(RE);
  const ceremonyExpiresAtRaw = readValueFromVerifiedDescriptor(
    entryObj,
    verified.get("ceremonyExpiresAtUnixSeconds") as PropertyDescriptor,
    RE
  );
  if (typeof ceremonyExpiresAtRaw !== "string") fail(RE);
  const genesisEnrollmentCeremonyHashRaw = readValueFromVerifiedDescriptor(
    entryObj,
    verified.get("genesisEnrollmentCeremonyHash") as PropertyDescriptor,
    RE
  );
  if (typeof genesisEnrollmentCeremonyHashRaw !== "string") fail(RE);
  const factorCommitmentRaw = readValueFromVerifiedDescriptor(
    entryObj,
    verified.get("factorCommitment") as PropertyDescriptor,
    RE
  );
  if (typeof factorCommitmentRaw !== "string") fail(RE);
  const stagedAtRaw = readValueFromVerifiedDescriptor(
    entryObj,
    verified.get("stagedAtUnixSeconds") as PropertyDescriptor,
    RE
  );
  if (typeof stagedAtRaw !== "string") fail(RE);

  const descriptorRaw = readValueFromVerifiedDescriptor(entryObj, verified.get("descriptor") as PropertyDescriptor, RE);
  const independenceRaw = readValueFromVerifiedDescriptor(
    entryObj,
    verified.get("independence") as PropertyDescriptor,
    RE
  );
  const descriptorTypeChecked = requireStoredFactorFieldsAsStrings(
    descriptorRaw,
    DESCRIPTOR_OWN_KEYS,
    RE,
    RE,
    RE,
    RE,
    RE
  );
  const independenceTypeChecked = requireStoredFactorFieldsAsStrings(
    independenceRaw,
    INDEPENDENCE_OWN_KEYS,
    RE,
    RE,
    RE,
    RE,
    RE
  );

  const tentative: StoredGenesisManifestEntry = {
    role: roleSlotString,
    ceremonyId: ceremonyIdRaw as Hex,
    ceremonyExpiresAtUnixSeconds: ceremonyExpiresAtRaw,
    genesisEnrollmentCeremonyHash: genesisEnrollmentCeremonyHashRaw as Hex,
    descriptor: descriptorTypeChecked as unknown as StoredGenesisManifestEntry["descriptor"],
    independence: independenceTypeChecked as unknown as StoredGenesisManifestEntry["independence"],
    signer: signerRaw,
    factorCommitment: factorCommitmentRaw as Hex,
    stagedAtUnixSeconds: stagedAtRaw
  };
  // Per-entry byte-ceiling check on the tentative, type-checked-but-not-
  // yet-format-validated entry -- MANIFEST_ENTRY_OVERSIZED is reachable
  // here, before phase 2's format validation of any of this entry's own
  // fields (Revision 5 ordering).
  validateManifestEntryOversized(tentative);

  return {
    tentative,
    roleSlotString,
    signerRaw,
    ceremonyIdRaw,
    ceremonyExpiresAtRaw,
    genesisEnrollmentCeremonyHashRaw,
    factorCommitmentRaw,
    stagedAtRaw,
    descriptorTypeChecked,
    independenceTypeChecked
  };
}

// Phase 2: deep format/semantic validation, reusing only the already
// type-checked values captured by phase 1 above -- the caller's original
// entry object is never read again. Independently reconstructs every
// invariant from the stored value alone; a forged record with a merely
// recomputed checksum cannot bypass a rule that is otherwise only checked
// during live staging.
function completeManifestEntryValidation(
  slot: 0 | 1 | 2,
  extraction: TentativeManifestEntryExtraction | null,
  journalGenesisDeploymentIntentHash: string,
  journalInitialValidator: string,
  journalCreatedAtUnixSeconds: string,
  journalExpiresAt: string
): StoredGenesisManifestEntry | null {
  if (extraction === null) {
    return null;
  }
  const RE = C.MANIFEST_ENTRY_PROPERTY_READ_FAILED;
  const {
    roleSlotString,
    signerRaw,
    ceremonyIdRaw,
    ceremonyExpiresAtRaw,
    genesisEnrollmentCeremonyHashRaw,
    factorCommitmentRaw,
    stagedAtRaw,
    descriptorTypeChecked,
    independenceTypeChecked
  } = extraction;

  const ceremonyId = requireNonZeroBytes32(ceremonyIdRaw, RE);
  const ceremonyExpiresAtUnixSeconds = requireStoredCanonicalUintString(ceremonyExpiresAtRaw, 48, RE);
  const storedCeremonyHash = requireNonZeroBytes32(genesisEnrollmentCeremonyHashRaw, RE);

  // Ceremony reconstruction: only ceremonyId and its own expiry are stored
  // (the two fields not otherwise reconstructible); ceremonyVersion and
  // credentialGeneration are reconstructed constants, role is slot-derived,
  // and genesisDeploymentIntentHash is the journal's own already-proven
  // hash -- never a separately stored, potentially divergent field.
  const reconstructedCeremony = Object.freeze({
    ceremonyVersion: "1",
    ceremonyId,
    genesisDeploymentIntentHash: journalGenesisDeploymentIntentHash,
    role: roleSlotString,
    credentialGeneration: "1",
    expiresAt: ceremonyExpiresAtUnixSeconds
  });
  const recomputedCeremonyHash = hashCeremonySnapshot(reconstructedCeremony);
  if (recomputedCeremonyHash !== storedCeremonyHash) {
    fail(C.JOURNAL_CEREMONY_HASH_RECOMPUTATION_MISMATCH);
  }

  // Ceremony lifetime provenance: the ceremony's own authority window must
  // not exceed the journal's bound intent expiry.
  if (BigInt(ceremonyExpiresAtUnixSeconds) > BigInt(journalExpiresAt)) {
    fail(C.CEREMONY_EXPIRY_EXCEEDS_INTENT_EXPIRY);
  }

  const factorInput = slot === 2
    ? { descriptor: descriptorTypeChecked, independence: independenceTypeChecked, signer: signerRaw }
    : { descriptor: descriptorTypeChecked, independence: independenceTypeChecked };
  let result: {
    factor: { descriptor: Record<string, unknown>; independence: Record<string, unknown>; signer?: string };
    factorCommitment: Hex;
  };
  try {
    result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(factorInput as never, slot) as never;
  } catch (error) {
    failWithCause(C.FACTOR_POLICY_VALIDATION_FAILED, error);
  }

  const descriptorStored = normalizeFactorFieldsForStorage(
    result.factor.descriptor,
    DESCRIPTOR_NUMERIC_KEYS,
    DESCRIPTOR_OWN_KEYS
  );
  const independenceStored = normalizeFactorFieldsForStorage(
    result.factor.independence,
    INDEPENDENCE_NUMERIC_KEYS,
    INDEPENDENCE_OWN_KEYS
  );

  if (independenceStored.enrollmentCeremonyHash !== storedCeremonyHash) {
    fail(C.FACTOR_CEREMONY_HASH_MISMATCH);
  }
  if (descriptorStored.credentialGeneration !== "1") {
    fail(C.CREDENTIAL_GENERATION_NOT_ONE);
  }

  const factorCommitment = requireNonZeroBytes32(factorCommitmentRaw, RE);
  if (result.factorCommitment !== factorCommitment) {
    fail(C.MANIFEST_ENTRY_FACTOR_COMMITMENT_MISMATCH);
  }

  let signerStored: string | null = null;
  if (slot === 2) {
    signerStored = result.factor.signer ?? null;
    if (signerStored === null) fail(C.FACTOR_POLICY_VALIDATION_FAILED);
    if (signerStored === journalInitialValidator) fail(C.SIGNER_ALIASES_INITIAL_VALIDATOR);
  }

  const stagedAtUnixSeconds = requireStoredCanonicalUintString(stagedAtRaw, 48, RE);
  // Historical chronology: a populated entry can never have been staged
  // before the journal itself was created -- the first comparison below,
  // checked before the pre-existing staged-before-ceremony-expiry check.
  if (BigInt(journalCreatedAtUnixSeconds) > BigInt(stagedAtUnixSeconds)) {
    fail(C.MANIFEST_ENTRY_STAGED_AT_ORDER_INVALID);
  }
  if (BigInt(stagedAtUnixSeconds) >= BigInt(ceremonyExpiresAtUnixSeconds)) {
    fail(C.MANIFEST_ENTRY_STAGED_AT_NOT_BEFORE_CEREMONY_EXPIRY);
  }

  const entry: StoredGenesisManifestEntry = {
    role: roleSlotString,
    ceremonyId,
    ceremonyExpiresAtUnixSeconds,
    genesisEnrollmentCeremonyHash: storedCeremonyHash,
    descriptor: descriptorStored as unknown as StoredGenesisManifestEntry["descriptor"],
    independence: independenceStored as unknown as StoredGenesisManifestEntry["independence"],
    signer: signerStored,
    factorCommitment,
    stagedAtUnixSeconds
  };
  validateManifestEntryOversized(entry);
  return entry;
}

export function validateGenesisStagingJournalRecord(
  value: unknown
): GenesisStagingJournalRecord {
  const input = requirePlainObject(value, C.JOURNAL_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    input,
    JOURNAL_OWN_KEYS,
    [],
    C.JOURNAL_MISSING_KEY,
    C.JOURNAL_EXTRA_KEY,
    C.JOURNAL_ENUMERATION_FAILED
  );
  const R = C.JOURNAL_PROPERTY_READ_FAILED;

  const schemaVersion = readValueFromVerifiedDescriptor(input, verified.get("schemaVersion") as PropertyDescriptor, R);
  if (schemaVersion !== PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION) {
    fail(C.JOURNAL_SCHEMA_VERSION_UNSUPPORTED);
  }
  const formatProvenance = readValueFromVerifiedDescriptor(
    input,
    verified.get("formatProvenance") as PropertyDescriptor,
    R
  );
  if (formatProvenance !== PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE) {
    fail(C.JOURNAL_FORMAT_PROVENANCE_INVALID);
  }

  const intentSnapshot = Object.create(null) as Record<string, unknown>;
  for (const key of INTENT_OWN_KEYS) {
    const raw = readValueFromVerifiedDescriptor(input, verified.get(key) as PropertyDescriptor, R);
    if (typeof raw !== "string") fail(R);
    intentSnapshot[key] = raw;
  }
  Object.freeze(intentSnapshot);

  const genesisDeploymentIntentHashRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("genesisDeploymentIntentHash") as PropertyDescriptor,
    R
  );
  if (typeof genesisDeploymentIntentHashRaw !== "string") fail(R);

  const stateRaw = readValueFromVerifiedDescriptor(input, verified.get("state") as PropertyDescriptor, R);
  if (typeof stateRaw !== "string") fail(C.JOURNAL_STATE_INVALID);

  const createdAtRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("createdAtUnixSeconds") as PropertyDescriptor,
    R
  );
  if (typeof createdAtRaw !== "string") fail(R);
  const updatedAtRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("updatedAtUnixSeconds") as PropertyDescriptor,
    R
  );
  if (typeof updatedAtRaw !== "string") fail(R);

  const manifestRaw = readValueFromVerifiedDescriptor(input, verified.get("manifest") as PropertyDescriptor, R);
  const manifestObj = requirePlainObject(manifestRaw, C.MANIFEST_NOT_OBJECT);
  const manifestVerified = requireExactOwnKeys(
    manifestObj,
    MANIFEST_SLOT_KEYS,
    [],
    C.MANIFEST_MISSING_KEY,
    C.MANIFEST_EXTRA_KEY,
    C.MANIFEST_ENUMERATION_FAILED
  );
  const slot0Raw = readValueFromVerifiedDescriptor(manifestObj, manifestVerified.get("0") as PropertyDescriptor, R);
  const slot1Raw = readValueFromVerifiedDescriptor(manifestObj, manifestVerified.get("1") as PropertyDescriptor, R);
  const slot2Raw = readValueFromVerifiedDescriptor(manifestObj, manifestVerified.get("2") as PropertyDescriptor, R);

  // Manifest-prefix shape validated here, immediately after the three slot
  // values are guardedly read and before any per-entry inspection
  // (extractTentativeManifestEntry) runs -- determined only from the
  // already-read slot values' own identity against null, with no deep
  // inspection, enumeration, property access, coercion, serialization, or
  // delegation against a populated entry. This must outrank every
  // per-entry defect (wrong role, non-null signer, malformed nested
  // fields, oversized entry) so a hostile out-of-sequence entry's contents
  // are never read at all.
  const populated0 = slot0Raw !== null;
  const populated1 = slot1Raw !== null;
  const populated2 = slot2Raw !== null;
  const validPrefix =
    (!populated0 && !populated1 && !populated2)
    || (populated0 && !populated1 && !populated2)
    || (populated0 && populated1 && !populated2)
    || (populated0 && populated1 && populated2);
  if (!validPrefix) {
    fail(C.MANIFEST_SEQUENCE_INVALID);
  }

  const tentativeExtraction0 = extractTentativeManifestEntry(0, slot0Raw);
  const tentativeExtraction1 = extractTentativeManifestEntry(1, slot1Raw);
  const tentativeExtraction2 = extractTentativeManifestEntry(2, slot2Raw);

  const endReasonRaw = readValueFromVerifiedDescriptor(input, verified.get("endReason") as PropertyDescriptor, R);
  if (endReasonRaw !== null && typeof endReasonRaw !== "string") fail(R);

  const integrityChecksumRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("integrityChecksum") as PropertyDescriptor,
    R
  );
  if (typeof integrityChecksumRaw !== "string") fail(R);

  // Byte-ceiling check on a fully owned, type-checked-but-not-yet-
  // format/semantically-validated snapshot of every top-level field, so
  // JOURNAL_OVERSIZED is reachable before any hash recomputation, range
  // check, or per-entry ceremony/factor-policy validation runs (Revision 5
  // ordering, mirrored from extractTentativeManifestEntry's own two-phase
  // split above).
  const tentativeJournal: GenesisStagingJournalRecord = {
    schemaVersion: schemaVersion as typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: formatProvenance as typeof PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE,
    intentVersion: intentSnapshot.intentVersion as string,
    intentId: intentSnapshot.intentId as Hex,
    chainId: intentSnapshot.chainId as string,
    entryPoint: intentSnapshot.entryPoint as string,
    factoryBinding: intentSnapshot.factoryBinding as string,
    confirmationTarget: intentSnapshot.confirmationTarget as string,
    verifier: intentSnapshot.verifier as string,
    verifierRuntimeCodeHash: intentSnapshot.verifierRuntimeCodeHash as Hex,
    accountCreationBytecodeHash: intentSnapshot.accountCreationBytecodeHash as Hex,
    accountVersionId: intentSnapshot.accountVersionId as Hex,
    securityModelId: intentSnapshot.securityModelId as Hex,
    recoveryDomainId: intentSnapshot.recoveryDomainId as Hex,
    ownerCommitment: intentSnapshot.ownerCommitment as Hex,
    identityBindingCommitment: intentSnapshot.identityBindingCommitment as Hex,
    initialValidator: intentSnapshot.initialValidator as string,
    validatorVerifierKind: intentSnapshot.validatorVerifierKind as string,
    validatorKeyIdBinding: intentSnapshot.validatorKeyIdBinding as Hex,
    validatorCommitment: intentSnapshot.validatorCommitment as Hex,
    validatorEpoch: intentSnapshot.validatorEpoch as string,
    recoveryEpoch: intentSnapshot.recoveryEpoch as string,
    recoveryDelaySeconds: intentSnapshot.recoveryDelaySeconds as string,
    recoveryExpirySeconds: intentSnapshot.recoveryExpirySeconds as string,
    userSalt: intentSnapshot.userSalt as Hex,
    expiresAt: intentSnapshot.expiresAt as string,
    genesisDeploymentIntentHash: genesisDeploymentIntentHashRaw as Hex,
    state: stateRaw as GenesisStagingJournalState,
    createdAtUnixSeconds: createdAtRaw,
    updatedAtUnixSeconds: updatedAtRaw,
    manifest: {
      "0": tentativeExtraction0?.tentative ?? null,
      "1": tentativeExtraction1?.tentative ?? null,
      "2": tentativeExtraction2?.tentative ?? null
    },
    endReason: endReasonRaw as GenesisStagingJournalEndReason,
    integrityChecksum: integrityChecksumRaw as Hex
  };
  validateJournalOversized(tentativeJournal);

  // Deeper format/semantic validation resumes here, reusing only the
  // already type-checked values extracted above.
  const genesisDeploymentIntentHash = requireNonZeroBytes32(genesisDeploymentIntentHashRaw, R);
  const recomputedIntentHash = hashIntentSnapshot(intentSnapshot);
  if (recomputedIntentHash !== genesisDeploymentIntentHash) {
    fail(C.JOURNAL_CONTEXT_HASH_MISMATCH);
  }

  if (!VALID_STATES.has(stateRaw)) {
    fail(C.JOURNAL_STATE_INVALID);
  }
  const state = stateRaw as GenesisStagingJournalState;

  const createdAtUnixSeconds = requireStoredCanonicalUintString(createdAtRaw, 48, R);
  const updatedAtUnixSeconds = requireStoredCanonicalUintString(updatedAtRaw, 48, R);

  const intentExpiresAt = BigInt(intentSnapshot.expiresAt as string);
  if (BigInt(createdAtUnixSeconds) >= intentExpiresAt) {
    fail(C.JOURNAL_CREATION_NOT_BEFORE_EXPIRY);
  }
  if (BigInt(updatedAtUnixSeconds) < BigInt(createdAtUnixSeconds)) {
    fail(C.JOURNAL_TIMESTAMP_ORDER_INVALID);
  }
  const updated = BigInt(updatedAtUnixSeconds);
  if (
    state === PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING
    || state === PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED
  ) {
    if (updated >= intentExpiresAt) fail(C.JOURNAL_STATE_TIMESTAMP_MISMATCH);
  } else if (state === PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED) {
    if (updated < intentExpiresAt) fail(C.JOURNAL_STATE_TIMESTAMP_MISMATCH);
  }

  const initialValidator = intentSnapshot.initialValidator as string;
  const entry0 = completeManifestEntryValidation(
    0,
    tentativeExtraction0,
    genesisDeploymentIntentHash,
    initialValidator,
    createdAtUnixSeconds,
    intentSnapshot.expiresAt as string
  );
  const entry1 = completeManifestEntryValidation(
    1,
    tentativeExtraction1,
    genesisDeploymentIntentHash,
    initialValidator,
    createdAtUnixSeconds,
    intentSnapshot.expiresAt as string
  );
  const entry2 = completeManifestEntryValidation(
    2,
    tentativeExtraction2,
    genesisDeploymentIntentHash,
    initialValidator,
    createdAtUnixSeconds,
    intentSnapshot.expiresAt as string
  );

  const populatedEntries = [entry0, entry1, entry2].filter(
    (entry): entry is StoredGenesisManifestEntry => entry !== null
  );
  const ceremonyIds = populatedEntries.map((entry) => entry.ceremonyId);
  if (new Set(ceremonyIds).size !== ceremonyIds.length) fail(C.CEREMONY_ID_DUPLICATE);
  const commitments = populatedEntries.map((entry) => entry.factorCommitment);
  if (new Set(commitments).size !== commitments.length) fail(C.FACTOR_COMMITMENT_DUPLICATE);
  const credentialIdHashes = [entry0, entry1]
    .filter((entry): entry is StoredGenesisManifestEntry => entry !== null)
    .map((entry) => entry.independence.credentialIdHash);
  if (new Set(credentialIdHashes).size !== credentialIdHashes.length) fail(C.CREDENTIAL_ID_HASH_DUPLICATE);
  const publicMaterials = populatedEntries.map((entry) => entry.descriptor.publicVerificationMaterialHash);
  if (new Set(publicMaterials).size !== publicMaterials.length) {
    fail(C.PUBLIC_VERIFICATION_MATERIAL_HASH_DUPLICATE);
  }
  const custodyDomains = populatedEntries.map((entry) => entry.independence.custodyDomainCommitment);
  if (new Set(custodyDomains).size !== custodyDomains.length) fail(C.CUSTODY_DOMAIN_COMMITMENT_DUPLICATE);

  if (entry0 !== null && entry1 !== null && BigInt(entry0.stagedAtUnixSeconds) > BigInt(entry1.stagedAtUnixSeconds)) {
    fail(C.MANIFEST_STAGED_AT_SEQUENCE_INVALID);
  }
  if (entry1 !== null && entry2 !== null && BigInt(entry1.stagedAtUnixSeconds) > BigInt(entry2.stagedAtUnixSeconds)) {
    fail(C.MANIFEST_STAGED_AT_SEQUENCE_INVALID);
  }

  if (!VALID_END_REASONS.has(endReasonRaw as string | null)) {
    fail(C.JOURNAL_END_REASON_INVALID);
  }
  const endReason = endReasonRaw as GenesisStagingJournalEndReason;
  if (state === PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING) {
    if (endReason !== null) fail(C.JOURNAL_STATE_END_REASON_MISMATCH);
  } else if (endReason !== state) {
    fail(C.JOURNAL_STATE_END_REASON_MISMATCH);
  }

  const lastPopulated = entry2 ?? entry1 ?? entry0 ?? null;
  if (state === PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING) {
    if (lastPopulated !== null) {
      if (updatedAtUnixSeconds !== lastPopulated.stagedAtUnixSeconds) {
        fail(C.JOURNAL_UPDATED_AT_STAGING_MISMATCH);
      }
    } else if (updatedAtUnixSeconds !== createdAtUnixSeconds) {
      fail(C.JOURNAL_UPDATED_AT_STAGING_MISMATCH);
    }
  } else {
    const floor = lastPopulated !== null ? BigInt(lastPopulated.stagedAtUnixSeconds) : BigInt(createdAtUnixSeconds);
    if (updated < floor) {
      fail(C.JOURNAL_UPDATED_AT_TERMINAL_INVALID);
    }
  }

  const integrityChecksum = requireChecksumBytes32Format(integrityChecksumRaw);

  const withoutChecksum: GenesisStagingJournalRecordWithoutChecksum = {
    schemaVersion: PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE,
    intentVersion: intentSnapshot.intentVersion as string,
    intentId: intentSnapshot.intentId as Hex,
    chainId: intentSnapshot.chainId as string,
    entryPoint: intentSnapshot.entryPoint as string,
    factoryBinding: intentSnapshot.factoryBinding as string,
    confirmationTarget: intentSnapshot.confirmationTarget as string,
    verifier: intentSnapshot.verifier as string,
    verifierRuntimeCodeHash: intentSnapshot.verifierRuntimeCodeHash as Hex,
    accountCreationBytecodeHash: intentSnapshot.accountCreationBytecodeHash as Hex,
    accountVersionId: intentSnapshot.accountVersionId as Hex,
    securityModelId: intentSnapshot.securityModelId as Hex,
    recoveryDomainId: intentSnapshot.recoveryDomainId as Hex,
    ownerCommitment: intentSnapshot.ownerCommitment as Hex,
    identityBindingCommitment: intentSnapshot.identityBindingCommitment as Hex,
    initialValidator: intentSnapshot.initialValidator as string,
    validatorVerifierKind: intentSnapshot.validatorVerifierKind as string,
    validatorKeyIdBinding: intentSnapshot.validatorKeyIdBinding as Hex,
    validatorCommitment: intentSnapshot.validatorCommitment as Hex,
    validatorEpoch: intentSnapshot.validatorEpoch as string,
    recoveryEpoch: intentSnapshot.recoveryEpoch as string,
    recoveryDelaySeconds: intentSnapshot.recoveryDelaySeconds as string,
    recoveryExpirySeconds: intentSnapshot.recoveryExpirySeconds as string,
    userSalt: intentSnapshot.userSalt as Hex,
    expiresAt: intentSnapshot.expiresAt as string,
    genesisDeploymentIntentHash,
    state,
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    manifest: { "0": entry0, "1": entry1, "2": entry2 },
    endReason
  };
  if (computeGenesisStagingJournalChecksum(withoutChecksum) !== integrityChecksum) {
    fail(C.JOURNAL_CHECKSUM_MISMATCH);
  }

  return deepFreeze({ ...withoutChecksum, integrityChecksum });
}
