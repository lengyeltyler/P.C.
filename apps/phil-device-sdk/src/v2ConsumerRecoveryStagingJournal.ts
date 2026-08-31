import { createHash } from "node:crypto";

import { getAddress, isHexString } from "ethers";

import type { Hex } from "./hashes.ts";
import {
  computePhilCoreV2LocalEnrollmentCeremonyHash,
  PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
  PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
  PHILCORE_V2_LOCAL_SECURITY_MODEL_ID
} from "./v2LocalCeremonyProtocol.ts";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const CANONICAL_UINT_STRING = /^(0|[1-9][0-9]*)$/;

export const PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION = 1 as const;
export const PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE =
  "philcore-v2-ceremony-staging-journal-v1" as const;
export const PHILCORE_V2_STAGING_JOURNAL_CHECKSUM_PREFIX =
  "PHILCORE_V2_CEREMONY_STAGING_JOURNAL_V1|" as const;

export const MAX_JOURNAL_FILE_BYTES = 8192 as const;
export const MAX_MANIFEST_ENTRY_BYTES = 512 as const;

export const PHILCORE_V2_STAGING_ROLE0_CANDIDATE_KIND =
  "ROLE0_PUBLIC_CANDIDATE_COMMITMENT_V1" as const;
export const PHILCORE_V2_STAGING_ROLE1_CANDIDATE_KIND =
  "ROLE1_PUBLIC_CANDIDATE_COMMITMENT_V1" as const;
export const PHILCORE_V2_STAGING_ROLE2_CANDIDATE_KIND =
  "ROLE2_PUBLIC_CANDIDATE_COMMITMENT_V1" as const;

export const PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING = "STAGING" as const;
export const PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED = "CANCELLED" as const;
export const PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED = "EXPIRED" as const;
export const PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED =
  "SUPERSEDED" as const;

export const PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE =
  Object.freeze({
    INVALID_NOW: "INVALID_NOW",
    CLOCK_REGRESSION_DETECTED: "CLOCK_REGRESSION_DETECTED",
    CEREMONY_CONTEXT_NOT_OBJECT: "CEREMONY_CONTEXT_NOT_OBJECT",
    CEREMONY_CONTEXT_MISSING_KEY: "CEREMONY_CONTEXT_MISSING_KEY",
    CEREMONY_CONTEXT_EXTRA_KEY: "CEREMONY_CONTEXT_EXTRA_KEY",
    CEREMONY_ID_INVALID: "CEREMONY_ID_INVALID",
    ENROLLMENT_CEREMONY_HASH_INVALID: "ENROLLMENT_CEREMONY_HASH_INVALID",
    ACCOUNT_VERSION_ID_INVALID: "ACCOUNT_VERSION_ID_INVALID",
    ACCOUNT_VERSION_ID_MISMATCH: "ACCOUNT_VERSION_ID_MISMATCH",
    SECURITY_MODEL_ID_INVALID: "SECURITY_MODEL_ID_INVALID",
    SECURITY_MODEL_ID_MISMATCH: "SECURITY_MODEL_ID_MISMATCH",
    RECOVERY_DOMAIN_ID_INVALID: "RECOVERY_DOMAIN_ID_INVALID",
    RECOVERY_DOMAIN_ID_MISMATCH: "RECOVERY_DOMAIN_ID_MISMATCH",
    ACCOUNT_INVALID: "ACCOUNT_INVALID",
    CHAIN_ID_INVALID: "CHAIN_ID_INVALID",
    ENTRY_POINT_INVALID: "ENTRY_POINT_INVALID",
    EXPECTED_RECOVERY_EPOCH_INVALID: "EXPECTED_RECOVERY_EPOCH_INVALID",
    EXPECTED_VALIDATOR_EPOCH_INVALID: "EXPECTED_VALIDATOR_EPOCH_INVALID",
    CEREMONY_EXPIRY_INVALID: "CEREMONY_EXPIRY_INVALID",
    CEREMONY_CONTEXT_HASH_MISMATCH: "CEREMONY_CONTEXT_HASH_MISMATCH",
    CEREMONY_CONTEXT_EXPIRED: "CEREMONY_CONTEXT_EXPIRED",
    STAGE_ROLE_INVALID: "STAGE_ROLE_INVALID",
    CANDIDATE_INPUT_NOT_OBJECT: "CANDIDATE_INPUT_NOT_OBJECT",
    CANDIDATE_INPUT_MISSING_KEY: "CANDIDATE_INPUT_MISSING_KEY",
    CANDIDATE_INPUT_EXTRA_KEY: "CANDIDATE_INPUT_EXTRA_KEY",
    CANDIDATE_INPUT_KIND_TYPE_INVALID: "CANDIDATE_INPUT_KIND_TYPE_INVALID",
    CANDIDATE_INPUT_VERSION_TYPE_INVALID:
      "CANDIDATE_INPUT_VERSION_TYPE_INVALID",
    CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID:
      "CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID",
    CANDIDATE_INPUT_GENERATION_TYPE_INVALID:
      "CANDIDATE_INPUT_GENERATION_TYPE_INVALID",
    CANDIDATE_INPUT_KIND_MISMATCH: "CANDIDATE_INPUT_KIND_MISMATCH",
    CANDIDATE_INPUT_VERSION_INVALID: "CANDIDATE_INPUT_VERSION_INVALID",
    CANDIDATE_INPUT_COMMITMENT_INVALID: "CANDIDATE_INPUT_COMMITMENT_INVALID",
    CANDIDATE_INPUT_GENERATION_INVALID: "CANDIDATE_INPUT_GENERATION_INVALID",
    MANIFEST_ENTRY_OVERSIZED: "MANIFEST_ENTRY_OVERSIZED",
    MANIFEST_ENTRY_NOT_OBJECT: "MANIFEST_ENTRY_NOT_OBJECT",
    MANIFEST_ENTRY_MISSING_KEY: "MANIFEST_ENTRY_MISSING_KEY",
    MANIFEST_ENTRY_EXTRA_KEY: "MANIFEST_ENTRY_EXTRA_KEY",
    MANIFEST_ROLE_INVALID: "MANIFEST_ROLE_INVALID",
    MANIFEST_SLOT_ROLE_MISMATCH: "MANIFEST_SLOT_ROLE_MISMATCH",
    MANIFEST_CANDIDATE_KIND_INVALID: "MANIFEST_CANDIDATE_KIND_INVALID",
    MANIFEST_ROLE_KIND_MISMATCH: "MANIFEST_ROLE_KIND_MISMATCH",
    MANIFEST_CANDIDATE_VERSION_INVALID: "MANIFEST_CANDIDATE_VERSION_INVALID",
    MANIFEST_COMMITMENT_INVALID: "MANIFEST_COMMITMENT_INVALID",
    MANIFEST_CREDENTIAL_GENERATION_INVALID:
      "MANIFEST_CREDENTIAL_GENERATION_INVALID",
    MANIFEST_STAGED_AT_INVALID: "MANIFEST_STAGED_AT_INVALID",
    MANIFEST_STAGED_AT_ORDER_INVALID: "MANIFEST_STAGED_AT_ORDER_INVALID",
    JOURNAL_NOT_OBJECT: "JOURNAL_NOT_OBJECT",
    JOURNAL_MISSING_KEY: "JOURNAL_MISSING_KEY",
    JOURNAL_EXTRA_KEY: "JOURNAL_EXTRA_KEY",
    JOURNAL_SCHEMA_VERSION_UNSUPPORTED: "JOURNAL_SCHEMA_VERSION_UNSUPPORTED",
    JOURNAL_FORMAT_PROVENANCE_INVALID: "JOURNAL_FORMAT_PROVENANCE_INVALID",
    JOURNAL_CEREMONY_ID_INVALID: "JOURNAL_CEREMONY_ID_INVALID",
    JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID:
      "JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID",
    JOURNAL_ACCOUNT_VERSION_ID_INVALID: "JOURNAL_ACCOUNT_VERSION_ID_INVALID",
    JOURNAL_ACCOUNT_VERSION_ID_MISMATCH: "JOURNAL_ACCOUNT_VERSION_ID_MISMATCH",
    JOURNAL_SECURITY_MODEL_ID_INVALID: "JOURNAL_SECURITY_MODEL_ID_INVALID",
    JOURNAL_SECURITY_MODEL_ID_MISMATCH: "JOURNAL_SECURITY_MODEL_ID_MISMATCH",
    JOURNAL_RECOVERY_DOMAIN_ID_INVALID: "JOURNAL_RECOVERY_DOMAIN_ID_INVALID",
    JOURNAL_RECOVERY_DOMAIN_ID_MISMATCH: "JOURNAL_RECOVERY_DOMAIN_ID_MISMATCH",
    JOURNAL_ACCOUNT_INVALID: "JOURNAL_ACCOUNT_INVALID",
    JOURNAL_CHAIN_ID_INVALID: "JOURNAL_CHAIN_ID_INVALID",
    JOURNAL_ENTRY_POINT_INVALID: "JOURNAL_ENTRY_POINT_INVALID",
    JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID:
      "JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID",
    JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID:
      "JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID",
    JOURNAL_EXPIRY_INVALID: "JOURNAL_EXPIRY_INVALID",
    JOURNAL_STATE_INVALID: "JOURNAL_STATE_INVALID",
    JOURNAL_CREATED_AT_INVALID: "JOURNAL_CREATED_AT_INVALID",
    JOURNAL_UPDATED_AT_INVALID: "JOURNAL_UPDATED_AT_INVALID",
    JOURNAL_TIMESTAMP_ORDER_INVALID: "JOURNAL_TIMESTAMP_ORDER_INVALID",
    JOURNAL_CREATION_NOT_BEFORE_EXPIRY: "JOURNAL_CREATION_NOT_BEFORE_EXPIRY",
    JOURNAL_STATE_TIMESTAMP_MISMATCH: "JOURNAL_STATE_TIMESTAMP_MISMATCH",
    JOURNAL_MANIFEST_NOT_OBJECT: "JOURNAL_MANIFEST_NOT_OBJECT",
    JOURNAL_MANIFEST_MISSING_KEY: "JOURNAL_MANIFEST_MISSING_KEY",
    JOURNAL_MANIFEST_EXTRA_KEY: "JOURNAL_MANIFEST_EXTRA_KEY",
    JOURNAL_END_REASON_INVALID: "JOURNAL_END_REASON_INVALID",
    JOURNAL_STATE_END_REASON_MISMATCH: "JOURNAL_STATE_END_REASON_MISMATCH",
    JOURNAL_CONTEXT_HASH_MISMATCH: "JOURNAL_CONTEXT_HASH_MISMATCH",
    JOURNAL_CHECKSUM_FORMAT_INVALID: "JOURNAL_CHECKSUM_FORMAT_INVALID",
    JOURNAL_CHECKSUM_MISMATCH: "JOURNAL_CHECKSUM_MISMATCH",
    JOURNAL_OVERSIZED: "JOURNAL_OVERSIZED",
    JOURNAL_JSON_INVALID: "JOURNAL_JSON_INVALID",
    JOURNAL_FILENAME_ID_MISMATCH: "JOURNAL_FILENAME_ID_MISMATCH",
    JOURNAL_NOT_STAGING: "JOURNAL_NOT_STAGING",
    HOST_DEPENDENCIES_NOT_OBJECT: "HOST_DEPENDENCIES_NOT_OBJECT",
    HOST_DEPENDENCY_MISSING: "HOST_DEPENDENCY_MISSING",
    HOST_DEPENDENCY_EXTRA: "HOST_DEPENDENCY_EXTRA",
    HOST_DEPENDENCY_INVALID: "HOST_DEPENDENCY_INVALID",
    HOST_PROCESS_POISONED: "HOST_PROCESS_POISONED",
    HOST_CLOSED: "HOST_CLOSED",
    STORAGE_ROOT_INVALID: "STORAGE_ROOT_INVALID",
    STORAGE_ROOT_UNSAFE: "STORAGE_ROOT_UNSAFE",
    STORAGE_DIRECTORY_INVALID: "STORAGE_DIRECTORY_INVALID",
    STORAGE_DIRECTORY_OWNER_INVALID: "STORAGE_DIRECTORY_OWNER_INVALID",
    STORAGE_DIRECTORY_MODE_INVALID: "STORAGE_DIRECTORY_MODE_INVALID",
    STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED:
      "STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED",
    STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE:
      "STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE",
    QUARANTINE_DIRECTORY_INVALID: "QUARANTINE_DIRECTORY_INVALID",
    QUARANTINE_DIRECTORY_OWNER_INVALID: "QUARANTINE_DIRECTORY_OWNER_INVALID",
    QUARANTINE_DIRECTORY_MODE_INVALID: "QUARANTINE_DIRECTORY_MODE_INVALID",
    DURABILITY_UNSUPPORTED: "DURABILITY_UNSUPPORTED",
    RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
    RECONCILIATION_FAILED: "RECONCILIATION_FAILED",
    JOURNAL_ALREADY_EXISTS: "JOURNAL_ALREADY_EXISTS",
    JOURNAL_NOT_FOUND: "JOURNAL_NOT_FOUND",
    DISK_STATE_CHANGED: "DISK_STATE_CHANGED",
    LOCK_HELD: "LOCK_HELD",
    LOCK_HELD_OR_AMBIGUOUS: "LOCK_HELD_OR_AMBIGUOUS",
    LOCK_FILE_OVERSIZED: "LOCK_FILE_OVERSIZED",
    LOCK_FILE_JSON_INVALID: "LOCK_FILE_JSON_INVALID",
    LOCK_FILE_NOT_OBJECT: "LOCK_FILE_NOT_OBJECT",
    LOCK_FILE_MISSING_KEY: "LOCK_FILE_MISSING_KEY",
    LOCK_FILE_EXTRA_KEY: "LOCK_FILE_EXTRA_KEY",
    LOCK_PID_INVALID: "LOCK_PID_INVALID",
    LOCK_CREATED_AT_INVALID: "LOCK_CREATED_AT_INVALID",
    LOCK_LIVENESS_RESULT_INVALID: "LOCK_LIVENESS_RESULT_INVALID",
    LOCK_DESCRIPTOR_INVALID: "LOCK_DESCRIPTOR_INVALID",
    LOCK_LOST_OR_REPLACED: "LOCK_LOST_OR_REPLACED",
    LOCK_ACQUISITION_FAILED: "LOCK_ACQUISITION_FAILED",
    LOCK_ACQUISITION_INDETERMINATE: "LOCK_ACQUISITION_INDETERMINATE",
    STALE_LOCK_QUARANTINE_BOUND_EXCEEDED:
      "STALE_LOCK_QUARANTINE_BOUND_EXCEEDED",
    STALE_LOCK_QUARANTINE_INDETERMINATE: "STALE_LOCK_QUARANTINE_INDETERMINATE",
    LOCK_RELEASE_INDETERMINATE: "LOCK_RELEASE_INDETERMINATE",
    MULTIPLE_JOURNALS_FOUND: "MULTIPLE_JOURNALS_FOUND",
    UNEXPECTED_STAGING_ENTRY: "UNEXPECTED_STAGING_ENTRY",
    JOURNAL_DESCRIPTOR_INVALID: "JOURNAL_DESCRIPTOR_INVALID",
    CORRUPT_QUARANTINE_BOUND_EXCEEDED: "CORRUPT_QUARANTINE_BOUND_EXCEEDED",
    CORRUPT_QUARANTINE_INDETERMINATE: "CORRUPT_QUARANTINE_INDETERMINATE",
    TEMP_FILE_BOUND_EXCEEDED: "TEMP_FILE_BOUND_EXCEEDED",
    RECONCILIATION_TEMP_SWEEP_BOUND_EXCEEDED:
      "RECONCILIATION_TEMP_SWEEP_BOUND_EXCEEDED",
    RECONCILIATION_OPERATION_BOUND_EXCEEDED:
      "RECONCILIATION_OPERATION_BOUND_EXCEEDED",
    TEMP_REMOVAL_INDETERMINATE: "TEMP_REMOVAL_INDETERMINATE",
    FILESYSTEM_READ_FAILED: "FILESYSTEM_READ_FAILED",
    FILESYSTEM_MUTATION_FAILED: "FILESYSTEM_MUTATION_FAILED",
    DURABILITY_WRITE_FAILED: "DURABILITY_WRITE_FAILED",
    DURABILITY_INDETERMINATE: "DURABILITY_INDETERMINATE",
    JOURNAL_REMOVAL_INDETERMINATE: "JOURNAL_REMOVAL_INDETERMINATE",
    CEREMONY_RETIREMENT_FAILED: "CEREMONY_RETIREMENT_FAILED",
    CEREMONY_RETIREMENT_THENABLE_REJECTED:
      "CEREMONY_RETIREMENT_THENABLE_REJECTED",
    CEREMONY_RETIREMENT_RESULT_INVALID: "CEREMONY_RETIREMENT_RESULT_INVALID"
  } as const);

export type PhilCoreV2ConsumerRecoveryStagingJournalErrorCode =
  typeof PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE[
    keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE
  ];

// Module-private brand set. `instanceof` alone is forgeable: any caller can
// do `Object.create(PhilCoreV2ConsumerRecoveryStagingJournalError.prototype)`
// (or return that prototype from a Proxy's getPrototypeOf trap) and pass the
// ordinary `instanceof` check without ever having gone through this
// constructor. Membership in this WeakSet is the sole source of truth for
// "is this a genuine instance"; only the constructor below ever adds to it,
// and only real object references (never a Proxy wrapping one) are added,
// so a Proxy wrapping a genuine error is correctly NOT recognized as one.
const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2ConsumerRecoveryStagingJournalError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryStagingJournalError";
    this.code = code;
    CLASSIFIED_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    // Primitive guard: WeakSet#has already returns false (never throws) for
    // a non-object, but this makes that contract explicit rather than
    // relying on engine behavior, and short-circuits before touching the
    // WeakSet at all for the common non-object case.
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return false;
    }
    return CLASSIFIED_ERROR_BRAND.has(value as object);
  }
}

// Lock `Symbol.hasInstance` against replacement: without this, a caller
// could do `PhilCoreV2ConsumerRecoveryStagingJournalError[Symbol.hasInstance]
// = () => true` and defeat the brand check for every future `instanceof`
// use in this module.
Object.defineProperty(
  PhilCoreV2ConsumerRecoveryStagingJournalError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2ConsumerRecoveryStagingJournalError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

export type StagingJournalState =
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED;

export type StagingJournalEndReason =
  | null
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED
  | typeof PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED;

export type StoredManifestEntry = Readonly<{
  role: 0 | 1 | 2;
  candidateKind: string;
  candidateVersion: 1;
  publicCandidateCommitment: Hex;
  credentialGeneration: string;
  stagedAtUnixSeconds: string;
}>;

export type StagingManifest = Readonly<{
  "0": StoredManifestEntry | null;
  "1": StoredManifestEntry | null;
  "2": StoredManifestEntry | null;
}>;

export type StagingJournalRecordWithoutChecksum = Readonly<{
  schemaVersion: typeof PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION;
  formatProvenance: typeof PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE;
  ceremonyId: Hex;
  enrollmentCeremonyHash: Hex;
  accountVersionId: Hex;
  securityModelId: Hex;
  recoveryDomainId: Hex;
  account: string;
  chainId: string;
  entryPoint: string;
  expectedRecoveryEpoch: string;
  expectedValidatorEpoch: string;
  expiresAtUnixSeconds: string;
  state: StagingJournalState;
  createdAtUnixSeconds: string;
  updatedAtUnixSeconds: string;
  manifest: StagingManifest;
  endReason: StagingJournalEndReason;
}>;

export type StagingJournalRecord = StagingJournalRecordWithoutChecksum &
  Readonly<{
    integrityChecksum: Hex;
  }>;

export type ImmutableCeremonyContextInput = Readonly<{
  ceremonyId: string;
  enrollmentCeremonyHash: string;
  accountVersionId: string;
  securityModelId: string;
  recoveryDomainId: string;
  account: string;
  chainId: bigint | string;
  entryPoint: string;
  expectedRecoveryEpoch: bigint | string;
  expectedValidatorEpoch: bigint | string;
  expiresAtUnixSeconds: bigint | string;
}>;

export type StagingCandidateInput = Readonly<{
  candidateKind: string;
  candidateVersion: number;
  publicCandidateCommitment: string;
  credentialGeneration: string;
}>;

type NormalizedCeremonyContext = Readonly<{
  ceremonyId: Hex;
  enrollmentCeremonyHash: Hex;
  accountVersionId: Hex;
  securityModelId: Hex;
  recoveryDomainId: Hex;
  account: string;
  chainId: string;
  entryPoint: string;
  expectedRecoveryEpoch: string;
  expectedValidatorEpoch: string;
  expiresAtUnixSeconds: string;
}>;

const CONTEXT_OWN_KEYS = Object.freeze([
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
  "expiresAtUnixSeconds"
] as const);

const JOURNAL_OWN_KEYS = Object.freeze([
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
] as const);

const CANDIDATE_INPUT_OWN_KEYS = Object.freeze([
  "candidateKind",
  "candidateVersion",
  "publicCandidateCommitment",
  "credentialGeneration"
] as const);

const MANIFEST_ENTRY_OWN_KEYS = Object.freeze([
  "role",
  "candidateKind",
  "candidateVersion",
  "publicCandidateCommitment",
  "credentialGeneration",
  "stagedAtUnixSeconds"
] as const);

const MANIFEST_SLOT_KEYS = Object.freeze(["0", "1", "2"] as const);

const ROLE_KIND_MAP: Readonly<Record<0 | 1 | 2, string>> = Object.freeze({
  0: PHILCORE_V2_STAGING_ROLE0_CANDIDATE_KIND,
  1: PHILCORE_V2_STAGING_ROLE1_CANDIDATE_KIND,
  2: PHILCORE_V2_STAGING_ROLE2_CANDIDATE_KIND
});

const VALID_CANDIDATE_KINDS = Object.freeze(
  new Set<string>([
    PHILCORE_V2_STAGING_ROLE0_CANDIDATE_KIND,
    PHILCORE_V2_STAGING_ROLE1_CANDIDATE_KIND,
    PHILCORE_V2_STAGING_ROLE2_CANDIDATE_KIND
  ])
);

const VALID_END_REASONS = Object.freeze(
  new Set<string | null>([
    null,
    PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED
  ])
);

const VALID_STATES = Object.freeze(
  new Set<string>([
    PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING,
    PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED
  ])
);

const C = PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE;

function fail(
  code: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode,
  message?: string
): never {
  throw new PhilCoreV2ConsumerRecoveryStagingJournalError(code, message);
}

// `cause instanceof PhilCoreV2ConsumerRecoveryStagingJournalError` is itself
// a hostile-surface operation: for a Proxy `cause`, `instanceof` invokes the
// Proxy's getPrototypeOf trap (also triggered by a revoked Proxy), which can
// throw an unrelated raw value. That raw value must never escape here --
// on any such failure, `cause` is conservatively treated as not-already-
// classified (the safe default: it gets wrapped with the caller-supplied
// code below, same as any other unclassified cause).
function isClassifiedError(
  value: unknown
): value is PhilCoreV2ConsumerRecoveryStagingJournalError {
  try {
    return value instanceof PhilCoreV2ConsumerRecoveryStagingJournalError;
  } catch {
    return false;
  }
}

function failWithCause(
  code: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode,
  cause: unknown
): never {
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

// Narrow property-access classifiers. Each wraps exactly one hostile-surface
// operation (enumeration, presence check, or a single read) and converts any
// thrown value into the caller-supplied closed code, with the original value
// retained only as a non-enumerable cause. An already-classified error is
// never double-wrapped (failWithCause rethrows it unchanged). These are used
// surgically, one call at a time, at the exact position each operation is
// needed -- never to snapshot an entire object ahead of validating it, which
// would let a later field's hostile getter mask an earlier field's semantic
// error.
function ownEnumerableStringKeys(
  value: object,
  enumerationCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): string[] {
  try {
    return Object.keys(value);
  } catch (error) {
    failWithCause(enumerationCode, error);
  }
}

function hasOwnStringKey(
  value: object,
  key: string,
  presenceCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): boolean {
  try {
    return Object.prototype.hasOwnProperty.call(value, key);
  } catch (error) {
    failWithCause(presenceCode, error);
  }
}

function readOwnProperty(
  value: object,
  key: string,
  readCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): unknown {
  try {
    return (value as Record<string, unknown>)[key];
  } catch (error) {
    failWithCause(readCode, error);
  }
}

// `Array.isArray` on a revoked Proxy throws a raw TypeError (distinct from
// the `instanceof`/getPrototypeOf hazard above). `typeof`/`=== null` never
// throw, even on a revoked Proxy, so only the Array.isArray call itself
// needs protection. Callers pass the exact existing "not an object" code
// for their surface; a throw here is classified with that code, and the
// original value is retained only as a non-enumerable cause.
function isCallerNotObjectShape(
  value: unknown,
  notObjectCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): boolean {
  if (value === null || typeof value !== "object") {
    return true;
  }
  try {
    return Array.isArray(value);
  } catch (error) {
    failWithCause(notObjectCode, error);
  }
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      deepFreeze(item);
    }
    return Object.freeze(value);
  }
  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }
  return Object.freeze(value);
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
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): Hex {
  if (
    typeof value !== "string"
    || !isHexString(value, 32)
    || value !== value.toLowerCase()
  ) {
    fail(invalidCode);
  }
  if (value === ZERO_BYTES32) {
    fail(invalidCode);
  }
  return value as Hex;
}

function requireNonZeroAddress(
  value: unknown,
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): string {
  if (typeof value !== "string") {
    fail(invalidCode);
  }
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    fail(invalidCode);
  }
  if (normalized !== value || normalized === ZERO_ADDRESS) {
    fail(invalidCode);
  }
  return normalized;
}

function requireCanonicalUintString(
  value: unknown,
  bits: number,
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode,
  options: { rejectZero: boolean } = { rejectZero: false }
): string {
  if (typeof value === "number") {
    fail(invalidCode);
  }
  let asString: string;
  if (typeof value === "bigint") {
    if (value < 0n) {
      fail(invalidCode);
    }
    asString = value.toString(10);
  } else if (typeof value === "string") {
    if (!CANONICAL_UINT_STRING.test(value)) {
      fail(invalidCode);
    }
    asString = value;
  } else {
    fail(invalidCode);
  }
  let parsed: bigint;
  try {
    parsed = BigInt(asString);
  } catch {
    fail(invalidCode);
  }
  if (parsed < 0n || parsed >= 1n << BigInt(bits)) {
    fail(invalidCode);
  }
  if (options.rejectZero && parsed === 0n) {
    fail(invalidCode);
  }
  return parsed.toString(10);
}

function requireNonzeroCanonicalUintString(
  value: unknown,
  bits: number,
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): string {
  return requireCanonicalUintString(value, bits, invalidCode, { rejectZero: true });
}

function requirePositiveCanonicalUintString(
  value: unknown,
  bits: number,
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): string {
  return requireCanonicalUintString(value, bits, invalidCode, { rejectZero: true });
}

function requirePinnedBytes32(
  value: unknown,
  expected: Hex,
  invalidCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode,
  mismatchCode: PhilCoreV2ConsumerRecoveryStagingJournalErrorCode
): Hex {
  if (
    typeof value !== "string"
    || !isHexString(value, 32)
    || value !== value.toLowerCase()
  ) {
    fail(invalidCode);
  }
  if (value === ZERO_BYTES32) {
    fail(invalidCode);
  }
  if (value !== expected.toLowerCase()) {
    fail(mismatchCode);
  }
  return value as Hex;
}

function computeEnrollmentHashFromContext(
  context: NormalizedCeremonyContext
): Hex {
  return computePhilCoreV2LocalEnrollmentCeremonyHash({
    ceremonyId: context.ceremonyId,
    account: context.account,
    chainId: context.chainId,
    entryPoint: context.entryPoint,
    accountVersionId: context.accountVersionId,
    securityModelId: context.securityModelId,
    recoveryDomainId: context.recoveryDomainId,
    expectedRecoveryEpoch: context.expectedRecoveryEpoch,
    expectedValidatorEpoch: context.expectedValidatorEpoch,
    expiresAt: context.expiresAtUnixSeconds
  });
}

function normalizeCeremonyContext(value: unknown): NormalizedCeremonyContext {
  if (isCallerNotObjectShape(value, C.CEREMONY_CONTEXT_NOT_OBJECT)) {
    fail(C.CEREMONY_CONTEXT_NOT_OBJECT);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set<string>(CONTEXT_OWN_KEYS);
  for (const key of ownEnumerableStringKeys(input, C.CEREMONY_CONTEXT_NOT_OBJECT)) {
    if (!allowed.has(key)) {
      fail(C.CEREMONY_CONTEXT_EXTRA_KEY, `unexpected own key: ${key}`);
    }
  }
  for (const key of CONTEXT_OWN_KEYS) {
    if (!hasOwnStringKey(input, key, C.CEREMONY_CONTEXT_MISSING_KEY)) {
      fail(C.CEREMONY_CONTEXT_MISSING_KEY, `missing own key: ${key}`);
    }
  }

  // Each field is read and semantically validated immediately, one at a
  // time, in exact schema order. A later field's own property is never
  // touched until the earlier field's read-and-validate has fully
  // succeeded, so a hostile getter on a later field can never mask an
  // earlier field's semantic error.
  const ceremonyId = requireNonZeroBytes32(
    readOwnProperty(input, "ceremonyId", C.CEREMONY_ID_INVALID),
    C.CEREMONY_ID_INVALID
  );
  const enrollmentCeremonyHash = requireNonZeroBytes32(
    readOwnProperty(input, "enrollmentCeremonyHash", C.ENROLLMENT_CEREMONY_HASH_INVALID),
    C.ENROLLMENT_CEREMONY_HASH_INVALID
  );
  const accountVersionId = requirePinnedBytes32(
    readOwnProperty(input, "accountVersionId", C.ACCOUNT_VERSION_ID_INVALID),
    PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    C.ACCOUNT_VERSION_ID_INVALID,
    C.ACCOUNT_VERSION_ID_MISMATCH
  );
  const securityModelId = requirePinnedBytes32(
    readOwnProperty(input, "securityModelId", C.SECURITY_MODEL_ID_INVALID),
    PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    C.SECURITY_MODEL_ID_INVALID,
    C.SECURITY_MODEL_ID_MISMATCH
  );
  const recoveryDomainId = requirePinnedBytes32(
    readOwnProperty(input, "recoveryDomainId", C.RECOVERY_DOMAIN_ID_INVALID),
    PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    C.RECOVERY_DOMAIN_ID_INVALID,
    C.RECOVERY_DOMAIN_ID_MISMATCH
  );
  const account = requireNonZeroAddress(
    readOwnProperty(input, "account", C.ACCOUNT_INVALID),
    C.ACCOUNT_INVALID
  );
  const chainId = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "chainId", C.CHAIN_ID_INVALID),
    256,
    C.CHAIN_ID_INVALID
  );
  const entryPoint = requireNonZeroAddress(
    readOwnProperty(input, "entryPoint", C.ENTRY_POINT_INVALID),
    C.ENTRY_POINT_INVALID
  );
  const expectedRecoveryEpoch = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "expectedRecoveryEpoch", C.EXPECTED_RECOVERY_EPOCH_INVALID),
    64,
    C.EXPECTED_RECOVERY_EPOCH_INVALID
  );
  const expectedValidatorEpoch = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "expectedValidatorEpoch", C.EXPECTED_VALIDATOR_EPOCH_INVALID),
    64,
    C.EXPECTED_VALIDATOR_EPOCH_INVALID
  );
  const expiresAtUnixSeconds = requirePositiveCanonicalUintString(
    readOwnProperty(input, "expiresAtUnixSeconds", C.CEREMONY_EXPIRY_INVALID),
    48,
    C.CEREMONY_EXPIRY_INVALID
  );

  const normalized: NormalizedCeremonyContext = {
    ceremonyId,
    enrollmentCeremonyHash,
    accountVersionId,
    securityModelId,
    recoveryDomainId,
    account,
    chainId,
    entryPoint,
    expectedRecoveryEpoch,
    expectedValidatorEpoch,
    expiresAtUnixSeconds
  };

  const recomputed = computeEnrollmentHashFromContext(normalized);
  if (recomputed !== enrollmentCeremonyHash) {
    fail(C.CEREMONY_CONTEXT_HASH_MISMATCH);
  }

  return {
    ...normalized,
    enrollmentCeremonyHash: recomputed
  };
}

function projectManifestEntryForChecksum(entry: unknown): unknown {
  if (isCallerNotObjectShape(entry, C.MANIFEST_ENTRY_NOT_OBJECT)) {
    return null;
  }
  const source = entry as object;
  return {
    role: readOwnProperty(source, "role", C.MANIFEST_ROLE_INVALID),
    candidateKind: readOwnProperty(source, "candidateKind", C.MANIFEST_CANDIDATE_KIND_INVALID),
    candidateVersion: readOwnProperty(source, "candidateVersion", C.MANIFEST_CANDIDATE_VERSION_INVALID),
    publicCandidateCommitment: readOwnProperty(
      source,
      "publicCandidateCommitment",
      C.MANIFEST_COMMITMENT_INVALID
    ),
    credentialGeneration: readOwnProperty(
      source,
      "credentialGeneration",
      C.MANIFEST_CREDENTIAL_GENERATION_INVALID
    ),
    stagedAtUnixSeconds: readOwnProperty(source, "stagedAtUnixSeconds", C.MANIFEST_STAGED_AT_INVALID)
  };
}

function projectManifestForChecksum(
  manifest: StagingManifest | null | unknown
): { "0": unknown; "1": unknown; "2": unknown } {
  if (isCallerNotObjectShape(manifest, C.JOURNAL_MANIFEST_NOT_OBJECT)) {
    return { "0": null, "1": null, "2": null };
  }
  const source = manifest as object;
  return {
    "0": projectManifestEntryForChecksum(readOwnProperty(source, "0", C.JOURNAL_MANIFEST_NOT_OBJECT)),
    "1": projectManifestEntryForChecksum(readOwnProperty(source, "1", C.JOURNAL_MANIFEST_NOT_OBJECT)),
    "2": projectManifestEntryForChecksum(readOwnProperty(source, "2", C.JOURNAL_MANIFEST_NOT_OBJECT))
  };
}

export function computeStagingJournalChecksum(
  record: StagingJournalRecordWithoutChecksum
): Hex {
  if (isCallerNotObjectShape(record, C.JOURNAL_NOT_OBJECT)) {
    fail(C.JOURNAL_NOT_OBJECT);
  }
  const source = record as object;
  const schemaVersion = readOwnProperty(source, "schemaVersion", C.JOURNAL_SCHEMA_VERSION_UNSUPPORTED);
  const formatProvenance = readOwnProperty(source, "formatProvenance", C.JOURNAL_FORMAT_PROVENANCE_INVALID);
  const ceremonyId = readOwnProperty(source, "ceremonyId", C.JOURNAL_CEREMONY_ID_INVALID);
  const enrollmentCeremonyHash = readOwnProperty(
    source,
    "enrollmentCeremonyHash",
    C.JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID
  );
  const accountVersionId = readOwnProperty(source, "accountVersionId", C.JOURNAL_ACCOUNT_VERSION_ID_INVALID);
  const securityModelId = readOwnProperty(source, "securityModelId", C.JOURNAL_SECURITY_MODEL_ID_INVALID);
  const recoveryDomainId = readOwnProperty(source, "recoveryDomainId", C.JOURNAL_RECOVERY_DOMAIN_ID_INVALID);
  const account = readOwnProperty(source, "account", C.JOURNAL_ACCOUNT_INVALID);
  const chainId = readOwnProperty(source, "chainId", C.JOURNAL_CHAIN_ID_INVALID);
  const entryPoint = readOwnProperty(source, "entryPoint", C.JOURNAL_ENTRY_POINT_INVALID);
  const expectedRecoveryEpoch = readOwnProperty(
    source,
    "expectedRecoveryEpoch",
    C.JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID
  );
  const expectedValidatorEpoch = readOwnProperty(
    source,
    "expectedValidatorEpoch",
    C.JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID
  );
  const expiresAtUnixSeconds = readOwnProperty(source, "expiresAtUnixSeconds", C.JOURNAL_EXPIRY_INVALID);
  const state = readOwnProperty(source, "state", C.JOURNAL_STATE_INVALID);
  const createdAtUnixSeconds = readOwnProperty(source, "createdAtUnixSeconds", C.JOURNAL_CREATED_AT_INVALID);
  const updatedAtUnixSeconds = readOwnProperty(source, "updatedAtUnixSeconds", C.JOURNAL_UPDATED_AT_INVALID);
  const manifest = readOwnProperty(source, "manifest", C.JOURNAL_MANIFEST_NOT_OBJECT);
  const endReason = readOwnProperty(source, "endReason", C.JOURNAL_END_REASON_INVALID);

  let projection: string;
  try {
    projection = JSON.stringify({
      schemaVersion,
      formatProvenance,
      ceremonyId,
      enrollmentCeremonyHash,
      accountVersionId,
      securityModelId,
      recoveryDomainId,
      account,
      chainId,
      entryPoint,
      expectedRecoveryEpoch,
      expectedValidatorEpoch,
      expiresAtUnixSeconds,
      state,
      createdAtUnixSeconds,
      updatedAtUnixSeconds,
      manifest: projectManifestForChecksum(manifest),
      endReason
    });
  } catch (error) {
    // A hostile toJSON()/Proxy trap surfacing during serialization is
    // classified with the nearest existing journal structural code; the
    // raw thrown value is retained only as a non-enumerable cause.
    failWithCause(C.JOURNAL_NOT_OBJECT, error);
  }
  const digest = createHash("sha256")
    .update(PHILCORE_V2_STAGING_JOURNAL_CHECKSUM_PREFIX, "utf8")
    .update(projection, "utf8")
    .digest("hex");
  return `0x${digest}` as Hex;
}

function compactStoredEntryBytes(entry: StoredManifestEntry): number {
  return Buffer.byteLength(
    JSON.stringify({
      role: entry.role,
      candidateKind: entry.candidateKind,
      candidateVersion: entry.candidateVersion,
      publicCandidateCommitment: entry.publicCandidateCommitment,
      credentialGeneration: entry.credentialGeneration,
      stagedAtUnixSeconds: entry.stagedAtUnixSeconds
    }),
    "utf8"
  );
}

function buildManifestEntryObject(
  entry: StoredManifestEntry
): StoredManifestEntry {
  return {
    role: entry.role,
    candidateKind: entry.candidateKind,
    candidateVersion: entry.candidateVersion,
    publicCandidateCommitment: entry.publicCandidateCommitment,
    credentialGeneration: entry.credentialGeneration,
    stagedAtUnixSeconds: entry.stagedAtUnixSeconds
  };
}

function buildManifestObject(manifest: StagingManifest): StagingManifest {
  return {
    "0": manifest["0"] === null ? null : buildManifestEntryObject(manifest["0"]),
    "1": manifest["1"] === null ? null : buildManifestEntryObject(manifest["1"]),
    "2": manifest["2"] === null ? null : buildManifestEntryObject(manifest["2"])
  };
}

function buildJournalRecord(
  fields: StagingJournalRecordWithoutChecksum
): StagingJournalRecord {
  const withoutChecksum: StagingJournalRecordWithoutChecksum = {
    schemaVersion: fields.schemaVersion,
    formatProvenance: fields.formatProvenance,
    ceremonyId: fields.ceremonyId,
    enrollmentCeremonyHash: fields.enrollmentCeremonyHash,
    accountVersionId: fields.accountVersionId,
    securityModelId: fields.securityModelId,
    recoveryDomainId: fields.recoveryDomainId,
    account: fields.account,
    chainId: fields.chainId,
    entryPoint: fields.entryPoint,
    expectedRecoveryEpoch: fields.expectedRecoveryEpoch,
    expectedValidatorEpoch: fields.expectedValidatorEpoch,
    expiresAtUnixSeconds: fields.expiresAtUnixSeconds,
    state: fields.state,
    createdAtUnixSeconds: fields.createdAtUnixSeconds,
    updatedAtUnixSeconds: fields.updatedAtUnixSeconds,
    manifest: buildManifestObject(fields.manifest),
    endReason: fields.endReason
  };
  const record: StagingJournalRecord = {
    ...withoutChecksum,
    integrityChecksum: computeStagingJournalChecksum(withoutChecksum)
  };
  return deepFreeze(record);
}

function assertNoClockRegression(
  now: bigint,
  updatedAtUnixSeconds: string
): void {
  if (now < BigInt(updatedAtUnixSeconds)) {
    fail(C.CLOCK_REGRESSION_DETECTED);
  }
}

function requireStagingJournal(
  journal: StagingJournalRecord
): StagingJournalRecord {
  const validated = validateStagingJournalRecord(journal);
  if (validated.state !== PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING) {
    fail(C.JOURNAL_NOT_STAGING);
  }
  return validated;
}

function validateManifestEntryOversized(entry: StoredManifestEntry): void {
  if (compactStoredEntryBytes(entry) > MAX_MANIFEST_ENTRY_BYTES) {
    fail(C.MANIFEST_ENTRY_OVERSIZED);
  }
}

function validateCandidateInput(
  role: 0 | 1 | 2,
  value: unknown
): {
  candidateKind: string;
  candidateVersion: 1;
  publicCandidateCommitment: Hex;
  credentialGeneration: string;
} {
  if (isCallerNotObjectShape(value, C.CANDIDATE_INPUT_NOT_OBJECT)) {
    fail(C.CANDIDATE_INPUT_NOT_OBJECT);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set<string>(CANDIDATE_INPUT_OWN_KEYS);
  for (const key of ownEnumerableStringKeys(input, C.CANDIDATE_INPUT_NOT_OBJECT)) {
    if (!allowed.has(key)) {
      fail(C.CANDIDATE_INPUT_EXTRA_KEY, `unexpected own key: ${key}`);
    }
  }
  for (const key of CANDIDATE_INPUT_OWN_KEYS) {
    if (!hasOwnStringKey(input, key, C.CANDIDATE_INPUT_MISSING_KEY)) {
      fail(C.CANDIDATE_INPUT_MISSING_KEY, `missing own key: ${key}`);
    }
  }

  // Sequential read-and-type-check, one field at a time, in exact field
  // order. Once all four are safely captured as plain values, no further
  // property access on the caller's object occurs.
  const candidateKind = readOwnProperty(input, "candidateKind", C.CANDIDATE_INPUT_KIND_TYPE_INVALID);
  if (typeof candidateKind !== "string") {
    fail(C.CANDIDATE_INPUT_KIND_TYPE_INVALID);
  }
  const candidateVersion = readOwnProperty(
    input,
    "candidateVersion",
    C.CANDIDATE_INPUT_VERSION_TYPE_INVALID
  );
  if (typeof candidateVersion !== "number") {
    fail(C.CANDIDATE_INPUT_VERSION_TYPE_INVALID);
  }
  const publicCandidateCommitment = readOwnProperty(
    input,
    "publicCandidateCommitment",
    C.CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID
  );
  if (typeof publicCandidateCommitment !== "string") {
    fail(C.CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID);
  }
  const credentialGenerationRaw = readOwnProperty(
    input,
    "credentialGeneration",
    C.CANDIDATE_INPUT_GENERATION_TYPE_INVALID
  );
  if (typeof credentialGenerationRaw !== "string") {
    fail(C.CANDIDATE_INPUT_GENERATION_TYPE_INVALID);
  }

  const tentativeEntry: StoredManifestEntry = {
    role,
    candidateKind,
    candidateVersion: candidateVersion as 1,
    publicCandidateCommitment: publicCandidateCommitment as Hex,
    credentialGeneration: credentialGenerationRaw,
    stagedAtUnixSeconds: "1"
  };
  validateManifestEntryOversized(tentativeEntry);

  if (candidateKind !== ROLE_KIND_MAP[role]) {
    fail(C.CANDIDATE_INPUT_KIND_MISMATCH);
  }
  if (candidateVersion !== 1) {
    fail(C.CANDIDATE_INPUT_VERSION_INVALID);
  }
  const commitment = requireNonZeroBytes32(
    publicCandidateCommitment,
    C.CANDIDATE_INPUT_COMMITMENT_INVALID
  );
  const credentialGeneration = requireNonzeroCanonicalUintString(
    credentialGenerationRaw,
    64,
    C.CANDIDATE_INPUT_GENERATION_INVALID
  );

  return {
    candidateKind,
    candidateVersion: 1,
    publicCandidateCommitment: commitment,
    credentialGeneration
  };
}

function validateStoredManifestEntry(
  slot: 0 | 1 | 2,
  value: unknown,
  createdAtUnixSeconds: string,
  updatedAtUnixSeconds: string,
  expiresAtUnixSeconds: string
): StoredManifestEntry | null {
  if (value === null) {
    return null;
  }
  if (isCallerNotObjectShape(value, C.MANIFEST_ENTRY_NOT_OBJECT)) {
    fail(C.MANIFEST_ENTRY_NOT_OBJECT);
  }
  const entry = value as Record<string, unknown>;
  const allowed = new Set<string>(MANIFEST_ENTRY_OWN_KEYS);
  for (const key of ownEnumerableStringKeys(entry, C.MANIFEST_ENTRY_NOT_OBJECT)) {
    if (!allowed.has(key)) {
      fail(C.MANIFEST_ENTRY_EXTRA_KEY, `unexpected own key: ${key}`);
    }
  }
  for (const key of MANIFEST_ENTRY_OWN_KEYS) {
    if (!hasOwnStringKey(entry, key, C.MANIFEST_ENTRY_MISSING_KEY)) {
      fail(C.MANIFEST_ENTRY_MISSING_KEY, `missing own key: ${key}`);
    }
  }

  // Revision 2 requires MANIFEST_ENTRY_OVERSIZED to be checked before any
  // per-field semantic error (including MANIFEST_ROLE_INVALID), and the
  // size check needs every field's value. Each field is still read exactly
  // once, one at a time in fixed field order, with its own hostile-getter
  // classification -- a throwing getter on an earlier field (e.g. role)
  // surfaces immediately without ever touching a later field.
  const roleValue = readOwnProperty(entry, "role", C.MANIFEST_ROLE_INVALID);
  const candidateKindRaw = readOwnProperty(entry, "candidateKind", C.MANIFEST_CANDIDATE_KIND_INVALID);
  const candidateVersion = readOwnProperty(
    entry,
    "candidateVersion",
    C.MANIFEST_CANDIDATE_VERSION_INVALID
  );
  const publicCandidateCommitmentRaw = readOwnProperty(
    entry,
    "publicCandidateCommitment",
    C.MANIFEST_COMMITMENT_INVALID
  );
  const credentialGenerationRaw = readOwnProperty(
    entry,
    "credentialGeneration",
    C.MANIFEST_CREDENTIAL_GENERATION_INVALID
  );
  const stagedAtUnixSecondsRaw = readOwnProperty(
    entry,
    "stagedAtUnixSeconds",
    C.MANIFEST_STAGED_AT_INVALID
  );

  const candidateKind = typeof candidateKindRaw === "string" ? candidateKindRaw : "";
  const publicCandidateCommitment =
    typeof publicCandidateCommitmentRaw === "string" ? publicCandidateCommitmentRaw : "";
  const credentialGeneration =
    typeof credentialGenerationRaw === "string" ? credentialGenerationRaw : "";
  const stagedAtUnixSeconds =
    typeof stagedAtUnixSecondsRaw === "string" ? stagedAtUnixSecondsRaw : "";

  const tentative: StoredManifestEntry = {
    role: typeof roleValue === "number" ? (roleValue as 0 | 1 | 2) : (0 as 0),
    candidateKind,
    candidateVersion: typeof candidateVersion === "number" ? (candidateVersion as 1) : 1,
    publicCandidateCommitment: publicCandidateCommitment as Hex,
    credentialGeneration,
    stagedAtUnixSeconds
  };
  validateManifestEntryOversized(tentative);

  if (
    typeof roleValue !== "number"
    || !(roleValue === 0 || roleValue === 1 || roleValue === 2)
  ) {
    fail(C.MANIFEST_ROLE_INVALID);
  }
  const role = roleValue as 0 | 1 | 2;
  if (role !== slot) {
    fail(C.MANIFEST_SLOT_ROLE_MISMATCH);
  }
  if (typeof candidateKind !== "string" || !VALID_CANDIDATE_KINDS.has(candidateKind)) {
    fail(C.MANIFEST_CANDIDATE_KIND_INVALID);
  }
  if (candidateKind !== ROLE_KIND_MAP[role]) {
    fail(C.MANIFEST_ROLE_KIND_MISMATCH);
  }
  if (candidateVersion !== 1) {
    fail(C.MANIFEST_CANDIDATE_VERSION_INVALID);
  }
  const commitment = requireNonZeroBytes32(
    publicCandidateCommitment,
    C.MANIFEST_COMMITMENT_INVALID
  );
  const generation = requireNonzeroCanonicalUintString(
    credentialGeneration,
    64,
    C.MANIFEST_CREDENTIAL_GENERATION_INVALID
  );
  const stagedAt = requirePositiveCanonicalUintString(
    stagedAtUnixSeconds,
    48,
    C.MANIFEST_STAGED_AT_INVALID
  );

  if (
    BigInt(createdAtUnixSeconds) > BigInt(stagedAt)
    || BigInt(stagedAt) > BigInt(updatedAtUnixSeconds)
    || BigInt(stagedAt) > BigInt(expiresAtUnixSeconds)
  ) {
    fail(C.MANIFEST_STAGED_AT_ORDER_INVALID);
  }

  return {
    role,
    candidateKind,
    candidateVersion: 1,
    publicCandidateCommitment: commitment,
    credentialGeneration: generation,
    stagedAtUnixSeconds: stagedAt
  };
}

function validateJournalStateTimestamps(
  state: StagingJournalState,
  createdAtUnixSeconds: string,
  updatedAtUnixSeconds: string,
  expiresAtUnixSeconds: string
): void {
  if (BigInt(createdAtUnixSeconds) >= BigInt(expiresAtUnixSeconds)) {
    fail(C.JOURNAL_CREATION_NOT_BEFORE_EXPIRY);
  }
  if (BigInt(updatedAtUnixSeconds) < BigInt(createdAtUnixSeconds)) {
    fail(C.JOURNAL_TIMESTAMP_ORDER_INVALID);
  }

  const updated = BigInt(updatedAtUnixSeconds);
  const expires = BigInt(expiresAtUnixSeconds);

  if (
    state === PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING
    || state === PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED
  ) {
    if (updated >= expires) {
      fail(C.JOURNAL_STATE_TIMESTAMP_MISMATCH);
    }
  } else if (state === PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED) {
    if (updated < expires) {
      fail(C.JOURNAL_STATE_TIMESTAMP_MISMATCH);
    }
  }
}

function validateJournalContextHash(context: {
  ceremonyId: Hex;
  enrollmentCeremonyHash: Hex;
  accountVersionId: Hex;
  securityModelId: Hex;
  recoveryDomainId: Hex;
  account: string;
  chainId: string;
  entryPoint: string;
  expectedRecoveryEpoch: string;
  expectedValidatorEpoch: string;
  expiresAtUnixSeconds: string;
}): void {
  const recomputed = computeEnrollmentHashFromContext(context);
  if (recomputed !== context.enrollmentCeremonyHash) {
    fail(C.JOURNAL_CONTEXT_HASH_MISMATCH);
  }
}

function validateEndReason(
  state: StagingJournalState,
  endReason: unknown
): StagingJournalEndReason {
  if (!VALID_END_REASONS.has(endReason as string | null)) {
    fail(C.JOURNAL_END_REASON_INVALID);
  }
  const reason = endReason as StagingJournalEndReason;
  if (state === PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING) {
    if (reason !== null) {
      fail(C.JOURNAL_STATE_END_REASON_MISMATCH);
    }
  } else if (reason !== state) {
    fail(C.JOURNAL_STATE_END_REASON_MISMATCH);
  }
  return reason;
}

export function validateStagingJournalRecord(
  value: unknown
): StagingJournalRecord {
  if (isCallerNotObjectShape(value, C.JOURNAL_NOT_OBJECT)) {
    fail(C.JOURNAL_NOT_OBJECT);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set<string>(JOURNAL_OWN_KEYS);
  for (const key of ownEnumerableStringKeys(input, C.JOURNAL_NOT_OBJECT)) {
    if (!allowed.has(key)) {
      fail(C.JOURNAL_EXTRA_KEY, `unexpected own key: ${key}`);
    }
  }
  for (const key of JOURNAL_OWN_KEYS) {
    if (!hasOwnStringKey(input, key, C.JOURNAL_MISSING_KEY)) {
      fail(C.JOURNAL_MISSING_KEY, `missing own key: ${key}`);
    }
  }

  // Sequential, one-field-at-a-time read-and-validate in exact schema
  // order -- a later field's own property is never touched until the
  // earlier field's validation has fully succeeded.
  const schemaVersion = readOwnProperty(input, "schemaVersion", C.JOURNAL_SCHEMA_VERSION_UNSUPPORTED);
  if (schemaVersion !== PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION) {
    fail(C.JOURNAL_SCHEMA_VERSION_UNSUPPORTED);
  }
  const formatProvenance = readOwnProperty(input, "formatProvenance", C.JOURNAL_FORMAT_PROVENANCE_INVALID);
  if (formatProvenance !== PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE) {
    fail(C.JOURNAL_FORMAT_PROVENANCE_INVALID);
  }

  const ceremonyId = requireNonZeroBytes32(
    readOwnProperty(input, "ceremonyId", C.JOURNAL_CEREMONY_ID_INVALID),
    C.JOURNAL_CEREMONY_ID_INVALID
  );
  const enrollmentCeremonyHash = requireNonZeroBytes32(
    readOwnProperty(input, "enrollmentCeremonyHash", C.JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID),
    C.JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID
  );
  const accountVersionId = requireNonZeroBytes32(
    readOwnProperty(input, "accountVersionId", C.JOURNAL_ACCOUNT_VERSION_ID_INVALID),
    C.JOURNAL_ACCOUNT_VERSION_ID_INVALID
  );
  if (accountVersionId !== PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID.toLowerCase()) {
    fail(C.JOURNAL_ACCOUNT_VERSION_ID_MISMATCH);
  }
  const securityModelId = requireNonZeroBytes32(
    readOwnProperty(input, "securityModelId", C.JOURNAL_SECURITY_MODEL_ID_INVALID),
    C.JOURNAL_SECURITY_MODEL_ID_INVALID
  );
  if (securityModelId !== PHILCORE_V2_LOCAL_SECURITY_MODEL_ID.toLowerCase()) {
    fail(C.JOURNAL_SECURITY_MODEL_ID_MISMATCH);
  }
  const recoveryDomainId = requireNonZeroBytes32(
    readOwnProperty(input, "recoveryDomainId", C.JOURNAL_RECOVERY_DOMAIN_ID_INVALID),
    C.JOURNAL_RECOVERY_DOMAIN_ID_INVALID
  );
  if (recoveryDomainId !== PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID.toLowerCase()) {
    fail(C.JOURNAL_RECOVERY_DOMAIN_ID_MISMATCH);
  }
  const account = requireNonZeroAddress(
    readOwnProperty(input, "account", C.JOURNAL_ACCOUNT_INVALID),
    C.JOURNAL_ACCOUNT_INVALID
  );
  const chainId = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "chainId", C.JOURNAL_CHAIN_ID_INVALID),
    256,
    C.JOURNAL_CHAIN_ID_INVALID
  );
  const entryPoint = requireNonZeroAddress(
    readOwnProperty(input, "entryPoint", C.JOURNAL_ENTRY_POINT_INVALID),
    C.JOURNAL_ENTRY_POINT_INVALID
  );
  const expectedRecoveryEpoch = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "expectedRecoveryEpoch", C.JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID),
    64,
    C.JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID
  );
  const expectedValidatorEpoch = requireNonzeroCanonicalUintString(
    readOwnProperty(input, "expectedValidatorEpoch", C.JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID),
    64,
    C.JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID
  );
  const expiresAtUnixSeconds = requirePositiveCanonicalUintString(
    readOwnProperty(input, "expiresAtUnixSeconds", C.JOURNAL_EXPIRY_INVALID),
    48,
    C.JOURNAL_EXPIRY_INVALID
  );

  const stateRaw = readOwnProperty(input, "state", C.JOURNAL_STATE_INVALID);
  if (typeof stateRaw !== "string" || !VALID_STATES.has(stateRaw)) {
    fail(C.JOURNAL_STATE_INVALID);
  }
  const state = stateRaw as StagingJournalState;

  const createdAtUnixSeconds = requirePositiveCanonicalUintString(
    readOwnProperty(input, "createdAtUnixSeconds", C.JOURNAL_CREATED_AT_INVALID),
    48,
    C.JOURNAL_CREATED_AT_INVALID
  );
  const updatedAtUnixSeconds = requirePositiveCanonicalUintString(
    readOwnProperty(input, "updatedAtUnixSeconds", C.JOURNAL_UPDATED_AT_INVALID),
    48,
    C.JOURNAL_UPDATED_AT_INVALID
  );

  validateJournalStateTimestamps(
    state,
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    expiresAtUnixSeconds
  );

  const manifestRaw = readOwnProperty(input, "manifest", C.JOURNAL_MANIFEST_NOT_OBJECT);
  if (isCallerNotObjectShape(manifestRaw, C.JOURNAL_MANIFEST_NOT_OBJECT)) {
    fail(C.JOURNAL_MANIFEST_NOT_OBJECT);
  }
  const manifestInput = manifestRaw as Record<string, unknown>;
  const manifestAllowed = new Set<string>(MANIFEST_SLOT_KEYS);
  for (const key of ownEnumerableStringKeys(manifestInput, C.JOURNAL_MANIFEST_NOT_OBJECT)) {
    if (!manifestAllowed.has(key)) {
      fail(C.JOURNAL_MANIFEST_EXTRA_KEY, `unexpected own key: ${key}`);
    }
  }
  for (const key of MANIFEST_SLOT_KEYS) {
    if (!hasOwnStringKey(manifestInput, key, C.JOURNAL_MANIFEST_MISSING_KEY)) {
      fail(C.JOURNAL_MANIFEST_MISSING_KEY, `missing own key: ${key}`);
    }
  }

  // Each slot's full validation (including its own sequential field
  // reads) completes before the next slot's value is ever read: object
  // literal properties are evaluated in source order.
  const manifest: StagingManifest = {
    "0": validateStoredManifestEntry(
      0,
      readOwnProperty(manifestInput, "0", C.MANIFEST_ENTRY_NOT_OBJECT),
      createdAtUnixSeconds,
      updatedAtUnixSeconds,
      expiresAtUnixSeconds
    ),
    "1": validateStoredManifestEntry(
      1,
      readOwnProperty(manifestInput, "1", C.MANIFEST_ENTRY_NOT_OBJECT),
      createdAtUnixSeconds,
      updatedAtUnixSeconds,
      expiresAtUnixSeconds
    ),
    "2": validateStoredManifestEntry(
      2,
      readOwnProperty(manifestInput, "2", C.MANIFEST_ENTRY_NOT_OBJECT),
      createdAtUnixSeconds,
      updatedAtUnixSeconds,
      expiresAtUnixSeconds
    )
  };

  const endReason = validateEndReason(
    state,
    readOwnProperty(input, "endReason", C.JOURNAL_END_REASON_INVALID)
  );

  const contextFields = {
    ceremonyId,
    enrollmentCeremonyHash,
    accountVersionId,
    securityModelId,
    recoveryDomainId,
    account,
    chainId,
    entryPoint,
    expectedRecoveryEpoch,
    expectedValidatorEpoch,
    expiresAtUnixSeconds
  };

  validateJournalContextHash(contextFields);

  const integrityChecksumRaw = readOwnProperty(
    input,
    "integrityChecksum",
    C.JOURNAL_CHECKSUM_FORMAT_INVALID
  );
  if (
    typeof integrityChecksumRaw !== "string"
    || !/^0x[0-9a-f]{64}$/.test(integrityChecksumRaw)
  ) {
    fail(C.JOURNAL_CHECKSUM_FORMAT_INVALID);
  }
  const integrityChecksum = integrityChecksumRaw as Hex;

  const withoutChecksum: StagingJournalRecordWithoutChecksum = {
    schemaVersion: PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE,
    ...contextFields,
    state,
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    manifest,
    endReason
  };
  if (computeStagingJournalChecksum(withoutChecksum) !== integrityChecksum) {
    fail(C.JOURNAL_CHECKSUM_MISMATCH);
  }

  const record: StagingJournalRecord = {
    schemaVersion: PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE,
    ...contextFields,
    state,
    createdAtUnixSeconds,
    updatedAtUnixSeconds,
    manifest,
    endReason,
    integrityChecksum
  };
  return deepFreeze(record);
}

export function createStagingJournal(
  ceremonyContext: ImmutableCeremonyContextInput,
  nowUnixSeconds: number
): StagingJournalRecord {
  const context = normalizeCeremonyContext(ceremonyContext);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  if (now >= BigInt(context.expiresAtUnixSeconds)) {
    fail(C.CEREMONY_CONTEXT_EXPIRED);
  }
  const nowString = now.toString(10);
  return buildJournalRecord({
    schemaVersion: PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE,
    ceremonyId: context.ceremonyId,
    enrollmentCeremonyHash: context.enrollmentCeremonyHash,
    accountVersionId: context.accountVersionId,
    securityModelId: context.securityModelId,
    recoveryDomainId: context.recoveryDomainId,
    account: context.account,
    chainId: context.chainId,
    entryPoint: context.entryPoint,
    expectedRecoveryEpoch: context.expectedRecoveryEpoch,
    expectedValidatorEpoch: context.expectedValidatorEpoch,
    expiresAtUnixSeconds: context.expiresAtUnixSeconds,
    state: PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING,
    createdAtUnixSeconds: nowString,
    updatedAtUnixSeconds: nowString,
    manifest: { "0": null, "1": null, "2": null },
    endReason: null
  });
}

function transitionJournal(
  journal: StagingJournalRecord,
  nowUnixSeconds: number,
  nextState: StagingJournalState,
  nextEndReason: StagingJournalEndReason,
  manifestOverride?: StagingManifest
): StagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);
  const nowString = now.toString(10);
  return buildJournalRecord({
    schemaVersion: current.schemaVersion,
    formatProvenance: current.formatProvenance,
    ceremonyId: current.ceremonyId,
    enrollmentCeremonyHash: current.enrollmentCeremonyHash,
    accountVersionId: current.accountVersionId,
    securityModelId: current.securityModelId,
    recoveryDomainId: current.recoveryDomainId,
    account: current.account,
    chainId: current.chainId,
    entryPoint: current.entryPoint,
    expectedRecoveryEpoch: current.expectedRecoveryEpoch,
    expectedValidatorEpoch: current.expectedValidatorEpoch,
    expiresAtUnixSeconds: current.expiresAtUnixSeconds,
    state: nextState,
    createdAtUnixSeconds: current.createdAtUnixSeconds,
    updatedAtUnixSeconds: nowString,
    manifest: manifestOverride ?? current.manifest,
    endReason: nextEndReason
  });
}

function classifyExpiryAtNow(
  now: bigint,
  expiresAtUnixSeconds: string
): {
  expired: boolean;
  state: StagingJournalState;
  endReason: StagingJournalEndReason;
} {
  if (now >= BigInt(expiresAtUnixSeconds)) {
    return {
      expired: true,
      state: PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
      endReason: PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED
    };
  }
  return {
    expired: false,
    state: PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING,
    endReason: null
  };
}

export function stageRoleCandidate(
  journal: StagingJournalRecord,
  role: 0 | 1 | 2,
  candidateInput: StagingCandidateInput,
  nowUnixSeconds: number
): StagingJournalRecord {
  if (!(role === 0 || role === 1 || role === 2)) {
    fail(C.STAGE_ROLE_INVALID);
  }
  const current = requireStagingJournal(journal);
  const candidate = validateCandidateInput(role, candidateInput);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);

  const expiry = classifyExpiryAtNow(now, current.expiresAtUnixSeconds);
  if (expiry.expired) {
    return transitionJournal(
      current,
      nowUnixSeconds,
      expiry.state,
      expiry.endReason
    );
  }

  const entry: StoredManifestEntry = {
    role,
    candidateKind: candidate.candidateKind,
    candidateVersion: candidate.candidateVersion,
    publicCandidateCommitment: candidate.publicCandidateCommitment,
    credentialGeneration: candidate.credentialGeneration,
    stagedAtUnixSeconds: now.toString(10)
  };
  validateManifestEntryOversized(entry);

  const manifest: StagingManifest = {
    "0": role === 0 ? entry : current.manifest["0"],
    "1": role === 1 ? entry : current.manifest["1"],
    "2": role === 2 ? entry : current.manifest["2"]
  };

  return buildJournalRecord({
    schemaVersion: current.schemaVersion,
    formatProvenance: current.formatProvenance,
    ceremonyId: current.ceremonyId,
    enrollmentCeremonyHash: current.enrollmentCeremonyHash,
    accountVersionId: current.accountVersionId,
    securityModelId: current.securityModelId,
    recoveryDomainId: current.recoveryDomainId,
    account: current.account,
    chainId: current.chainId,
    entryPoint: current.entryPoint,
    expectedRecoveryEpoch: current.expectedRecoveryEpoch,
    expectedValidatorEpoch: current.expectedValidatorEpoch,
    expiresAtUnixSeconds: current.expiresAtUnixSeconds,
    state: PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING,
    createdAtUnixSeconds: current.createdAtUnixSeconds,
    updatedAtUnixSeconds: now.toString(10),
    manifest,
    endReason: null
  });
}

export function cancelStagingJournal(
  journal: StagingJournalRecord,
  nowUnixSeconds: number
): StagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);

  const expiry = classifyExpiryAtNow(now, current.expiresAtUnixSeconds);
  if (expiry.expired) {
    return transitionJournal(
      current,
      nowUnixSeconds,
      PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
      PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED
    );
  }
  return transitionJournal(
    current,
    nowUnixSeconds,
    PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED
  );
}

export function expireStagingJournalIfNeeded(
  journal: StagingJournalRecord,
  nowUnixSeconds: number
): StagingJournalRecord {
  const current = requireStagingJournal(journal);
  const now = requirePositiveSafeIntegerNow(nowUnixSeconds);
  assertNoClockRegression(now, current.updatedAtUnixSeconds);

  const expiry = classifyExpiryAtNow(now, current.expiresAtUnixSeconds);
  if (!expiry.expired) {
    return current;
  }
  return transitionJournal(
    current,
    nowUnixSeconds,
    PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED
  );
}

export function supersedeStagingJournal(
  journal: StagingJournalRecord,
  nowUnixSeconds: number
): StagingJournalRecord {
  return transitionJournal(
    journal,
    nowUnixSeconds,
    PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED,
    PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED
  );
}
