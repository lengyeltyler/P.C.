import { createHash } from "node:crypto";

import {
  allGenesisStagingSlotsPopulated,
  validateGenesisStagingJournalRecord,
  PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING,
  type GenesisStagingJournalRecord
} from "./v2ConsumerRecoveryGenesisStagingJournal.ts";
import {
  validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile
} from "./v2ConsumerRecoveryGenesisStagingProfile.ts";

type PhilCoreV2ConsumerRecoveryGenesisProfileResult = ReturnType<
  typeof validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile
>;

// Pure, require-time-dormant finalized-profile record builder and stored-record
// validator. No filesystem, clock, host, coordinator, or product access.

export const PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION = 1 as const;
export const PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE =
  "philcore-v2-consumer-recovery-genesis-finalized-profile-v1" as const;
export const PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE = "FINALIZED" as const;
export const PHILCORE_V2_GENESIS_FINALIZED_PROFILE_CHECKSUM_PREFIX =
  "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_V1|" as const;
export const MAX_GENESIS_FINALIZED_PROFILE_FILE_BYTES = 32768 as const;

export const PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE =
  Object.freeze({
    FINALIZED_PROFILE_RECORD_NOT_OBJECT: "FINALIZED_PROFILE_RECORD_NOT_OBJECT",
    FINALIZED_PROFILE_RECORD_MISSING_KEY: "FINALIZED_PROFILE_RECORD_MISSING_KEY",
    FINALIZED_PROFILE_RECORD_EXTRA_KEY: "FINALIZED_PROFILE_RECORD_EXTRA_KEY",
    FINALIZED_PROFILE_RECORD_ENUMERATION_FAILED:
      "FINALIZED_PROFILE_RECORD_ENUMERATION_FAILED",
    FINALIZED_PROFILE_RECORD_PROPERTY_READ_FAILED:
      "FINALIZED_PROFILE_RECORD_PROPERTY_READ_FAILED",
    FINALIZED_PROFILE_SCHEMA_VERSION_UNSUPPORTED:
      "FINALIZED_PROFILE_SCHEMA_VERSION_UNSUPPORTED",
    FINALIZED_PROFILE_FORMAT_PROVENANCE_INVALID:
      "FINALIZED_PROFILE_FORMAT_PROVENANCE_INVALID",
    FINALIZED_PROFILE_STATE_INVALID: "FINALIZED_PROFILE_STATE_INVALID",
    FINALIZED_PROFILE_FINALIZED_AT_INVALID:
      "FINALIZED_PROFILE_FINALIZED_AT_INVALID",
    FINALIZED_PROFILE_SOURCE_TIMESTAMP_INVALID:
      "FINALIZED_PROFILE_SOURCE_TIMESTAMP_INVALID",
    FINALIZED_PROFILE_INTENT_ID_MISMATCH: "FINALIZED_PROFILE_INTENT_ID_MISMATCH",
    FINALIZED_PROFILE_INTENT_HASH_MISMATCH:
      "FINALIZED_PROFILE_INTENT_HASH_MISMATCH",
    FINALIZED_PROFILE_SOURCE_CHECKSUM_MISMATCH:
      "FINALIZED_PROFILE_SOURCE_CHECKSUM_MISMATCH",
    FINALIZED_PROFILE_RESULT_NOT_OBJECT: "FINALIZED_PROFILE_RESULT_NOT_OBJECT",
    FINALIZED_PROFILE_RESULT_MISSING_KEY: "FINALIZED_PROFILE_RESULT_MISSING_KEY",
    FINALIZED_PROFILE_RESULT_EXTRA_KEY: "FINALIZED_PROFILE_RESULT_EXTRA_KEY",
    FINALIZED_PROFILE_RESULT_ENUMERATION_FAILED:
      "FINALIZED_PROFILE_RESULT_ENUMERATION_FAILED",
    FINALIZED_PROFILE_RESULT_PROPERTY_READ_FAILED:
      "FINALIZED_PROFILE_RESULT_PROPERTY_READ_FAILED",
    FINALIZED_PROFILE_RESULT_SHAPE_INVALID:
      "FINALIZED_PROFILE_RESULT_SHAPE_INVALID",
    FINALIZED_PROFILE_RESULT_MISMATCH: "FINALIZED_PROFILE_RESULT_MISMATCH",
    FINALIZED_PROFILE_CHECKSUM_FORMAT_INVALID:
      "FINALIZED_PROFILE_CHECKSUM_FORMAT_INVALID",
    FINALIZED_PROFILE_CHECKSUM_MISMATCH: "FINALIZED_PROFILE_CHECKSUM_MISMATCH",
    FINALIZED_PROFILE_RECORD_OVERSIZED: "FINALIZED_PROFILE_RECORD_OVERSIZED",
    FINALIZED_PROFILE_SERIALIZATION_REJECTED:
      "FINALIZED_PROFILE_SERIALIZATION_REJECTED"
  } as const);

export type PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode =
  typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE[
    keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE
  ];

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError";
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
  PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError,
  Symbol.hasInstance,
  {
    value:
      PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const C = PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE;
const MAX_UINT48 = 281474976710655;
const CANONICAL_UINT_STRING = /^(0|[1-9][0-9]*)$/;
const MAX_FINALIZED_PROFILE_WARNINGS = 2;
const CHECKSUM_BYTES32 = /^0x[0-9a-f]{64}$/;

const RECORD_OWN_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "state",
  "intentId",
  "genesisDeploymentIntentHash",
  "sourceJournalIntegrityChecksum",
  "finalizedAtUnixSeconds",
  "sourceJournal",
  "validationResult",
  "integrityChecksum"
] as const);

const CHECKSUM_OWN_KEYS = Object.freeze(RECORD_OWN_KEYS.slice(0, -1));

const RESULT_OWN_KEYS = Object.freeze([
  "genesisDeploymentIntentHash",
  "genesisEnrollmentCeremonyHashes",
  "profile"
] as const);

const PROFILE_RESULT_OWN_KEYS = Object.freeze([
  "profile",
  "descriptors",
  "commitments",
  "recoveryConfigurationHash",
  "independenceAssurance",
  "warnings"
] as const);

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

export type GenesisFinalizedProfileValidationResult = Readonly<{
  genesisDeploymentIntentHash: string;
  genesisEnrollmentCeremonyHashes: readonly [string, string, string];
  profile: Readonly<{
    profile: string;
    descriptors: readonly [
      Readonly<Record<string, string>>,
      Readonly<Record<string, string>>,
      Readonly<Record<string, string>>
    ];
    commitments: readonly [string, string, string];
    recoveryConfigurationHash: string;
    independenceAssurance: string;
    warnings: readonly string[];
  }>;
}>;

export type GenesisFinalizedProfileRecordWithoutChecksum = Readonly<{
  schemaVersion: typeof PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION;
  formatProvenance: typeof PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE;
  state: typeof PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE;
  intentId: string;
  genesisDeploymentIntentHash: string;
  sourceJournalIntegrityChecksum: string;
  finalizedAtUnixSeconds: string;
  sourceJournal: GenesisStagingJournalRecord;
  validationResult: GenesisFinalizedProfileValidationResult;
}>;

export type GenesisFinalizedProfileRecord = GenesisFinalizedProfileRecordWithoutChecksum &
  Readonly<{
    integrityChecksum: string;
  }>;

function fail(
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode,
  message?: string
): never {
  throw new PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError(code, message);
}

function isClassifiedError(
  value: unknown
): value is PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError {
  try {
    return value instanceof PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError;
  } catch {
    return false;
  }
}

function failWithCause(
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode,
  cause: unknown
): never {
  if (isClassifiedError(cause)) {
    throw cause;
  }
  fail(code);
}

function requireStringArray(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): readonly string[] {
  if (value === null || typeof value !== "object") {
    fail(code);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (error) {
    failWithCause(code, error);
  }
  if (!isArray) {
    fail(code);
  }

  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  } catch (error) {
    failWithCause(code, error);
  }
  if (lengthDescriptor === undefined) {
    fail(code);
  }
  const lengthValue = readValueFromVerifiedDescriptor(value, lengthDescriptor, code);
  if (
    typeof lengthValue !== "number"
    || !Number.isInteger(lengthValue)
    || lengthValue < 0
    || lengthValue > MAX_FINALIZED_PROFILE_WARNINGS
  ) {
    fail(code);
  }
  return requireStringTuple(value, lengthValue, code);
}

function requirePlainObject(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
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
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
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

function requireExactOwnKeys(
  value: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  missingCode: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
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

function requireLeafString(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): string {
  if (typeof value !== "string") fail(code);
  return value;
}

function requireLeafNumber(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): number {
  if (typeof value !== "number") fail(code);
  return value;
}

function requireStoredPositiveUint48String(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): string {
  const raw = requireLeafString(value, code);
  if (!CANONICAL_UINT_STRING.test(raw)) fail(code);
  let big: bigint;
  try {
    big = BigInt(raw);
  } catch {
    fail(code);
  }
  if (big <= 0n || big > BigInt(MAX_UINT48)) fail(code);
  return raw;
}

function requireChecksumBytes32Format(value: unknown): string {
  if (typeof value !== "string" || !CHECKSUM_BYTES32.test(value)) {
    fail(C.FINALIZED_PROFILE_CHECKSUM_FORMAT_INVALID);
  }
  return value;
}

function requireExactThreeTuple(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): readonly [unknown, unknown, unknown] {
  if (value === null || typeof value !== "object") {
    fail(code);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (error) {
    failWithCause(code, error);
  }
  if (!isArray) {
    fail(code);
  }

  let keys: readonly (string | symbol)[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    failWithCause(code, error);
  }
  const allowed = new Set(["0", "1", "2", "length"]);
  const candidates: string[] = [];
  for (const key of keys) {
    if (typeof key === "symbol") {
      fail(code, "unexpected symbol own key on tuple");
    }
    if (!allowed.has(key)) {
      fail(code, `unexpected own key on tuple: ${key}`);
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      failWithCause(code, error);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }
  for (const required of ["0", "1", "2", "length"]) {
    if (!verified.has(required)) {
      fail(code, `missing own key on tuple: ${required}`);
    }
  }

  const length = readValueFromVerifiedDescriptor(
    value,
    verified.get("length") as PropertyDescriptor,
    code
  );
  if (length !== 3) {
    fail(code);
  }

  return Object.freeze([
    readValueFromVerifiedDescriptor(value, verified.get("0") as PropertyDescriptor, code),
    readValueFromVerifiedDescriptor(value, verified.get("1") as PropertyDescriptor, code),
    readValueFromVerifiedDescriptor(value, verified.get("2") as PropertyDescriptor, code)
  ]) as readonly [unknown, unknown, unknown];
}

function requireStringTuple(
  value: unknown,
  length: number,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): readonly string[] {
  if (value === null || typeof value !== "object") {
    fail(code);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (error) {
    failWithCause(code, error);
  }
  if (!isArray) {
    fail(code);
  }

  const indexKeys: string[] = [];
  for (let index = 0; index < length; index += 1) {
    indexKeys.push(String(index));
  }
  const allowed = new Set<string>([...indexKeys, "length"]);
  let keys: readonly (string | symbol)[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    failWithCause(code, error);
  }
  const candidates: string[] = [];
  for (const key of keys) {
    if (typeof key === "symbol") {
      fail(code, "unexpected symbol own key on tuple");
    }
    if (!allowed.has(key)) {
      fail(code, `unexpected own key on tuple: ${key}`);
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      failWithCause(code, error);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }
  for (const required of [...indexKeys, "length"]) {
    if (!verified.has(required)) {
      fail(code, `missing own key on tuple: ${required}`);
    }
  }

  const tupleLength = readValueFromVerifiedDescriptor(
    value,
    verified.get("length") as PropertyDescriptor,
    code
  );
  if (tupleLength !== length) {
    fail(code);
  }

  const out: string[] = [];
  for (const index of indexKeys) {
    out.push(
      requireLeafString(
        readValueFromVerifiedDescriptor(
          value,
          verified.get(index) as PropertyDescriptor,
          code
        ),
        code
      )
    );
  }
  return Object.freeze(out);
}

function nullPrototypeProjection(
  entries: readonly (readonly [string, unknown])[]
): Readonly<Record<string, unknown>> {
  const projection = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of entries) {
    projection[key] = value;
  }
  return Object.freeze(projection);
}

function nullProtoClone(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => nullProtoClone(item)));
  }
  const out: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(value as Record<string, unknown>)) {
    out[key] = nullProtoClone((value as Record<string, unknown>)[key]);
  }
  return out;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (
    value === null
    || (typeof value !== "object" && typeof value !== "function")
  ) {
    return value;
  }
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  if (Array.isArray(object)) {
    for (const item of object) {
      deepFreeze(item, seen);
    }
    Object.freeze(object);
    return value;
  }
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) {
      deepFreeze(descriptor.value, seen);
    }
  }
  Object.freeze(object);
  return value;
}

function canonicalizeDescriptorLeaf(
  key: string,
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): string {
  if (DESCRIPTOR_NUMERIC_KEYS.has(key)) {
    if (typeof value === "bigint") return value.toString(10);
    if (typeof value === "number") fail(code);
    return requireLeafString(value, code);
  }
  return requireLeafString(value, code);
}

function projectDescriptorForCompare(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode
): Readonly<Record<string, string>> {
  const obj = requirePlainObject(value, code);
  const verified = requireExactOwnKeys(obj, DESCRIPTOR_OWN_KEYS, [], code, code, code);
  const out: Record<string, string> = Object.create(null);
  for (const key of DESCRIPTOR_OWN_KEYS) {
    out[key] = canonicalizeDescriptorLeaf(
      key,
      readValueFromVerifiedDescriptor(obj, verified.get(key) as PropertyDescriptor, code),
      code
    );
  }
  return Object.freeze(out);
}

function projectProfileResultForCompare(
  value: unknown,
  resultCodes: {
    readonly notObject: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly missing: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly extra: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly enumeration: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly read: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly shape: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
  }
): GenesisFinalizedProfileValidationResult["profile"] {
  const obj = requirePlainObject(value, resultCodes.notObject);
  const verified = requireExactOwnKeys(
    obj,
    PROFILE_RESULT_OWN_KEYS,
    [],
    resultCodes.missing,
    resultCodes.extra,
    resultCodes.enumeration
  );
  const R = resultCodes.read;

  const profile = requireLeafString(
    readValueFromVerifiedDescriptor(obj, verified.get("profile") as PropertyDescriptor, R),
    R
  );
  const descriptorsRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("descriptors") as PropertyDescriptor,
    R
  );
  const commitmentsRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("commitments") as PropertyDescriptor,
    R
  );
  const recoveryConfigurationHash = requireLeafString(
    readValueFromVerifiedDescriptor(
      obj,
      verified.get("recoveryConfigurationHash") as PropertyDescriptor,
      R
    ),
    R
  );
  const independenceAssurance = requireLeafString(
    readValueFromVerifiedDescriptor(
      obj,
      verified.get("independenceAssurance") as PropertyDescriptor,
      R
    ),
    R
  );
  const warningsRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("warnings") as PropertyDescriptor,
    R
  );

  const descriptorSlots = requireExactThreeTuple(descriptorsRaw, resultCodes.shape);
  const commitmentSlots = requireExactThreeTuple(commitmentsRaw, resultCodes.shape);
  const descriptors = Object.freeze([
    projectDescriptorForCompare(descriptorSlots[0], R),
    projectDescriptorForCompare(descriptorSlots[1], R),
    projectDescriptorForCompare(descriptorSlots[2], R)
  ]) as GenesisFinalizedProfileValidationResult["profile"]["descriptors"];

  const commitments = Object.freeze([
    requireLeafString(commitmentSlots[0], R),
    requireLeafString(commitmentSlots[1], R),
    requireLeafString(commitmentSlots[2], R)
  ]) as readonly [string, string, string];

  const warnings = requireStringArray(warningsRaw, resultCodes.shape);

  return Object.freeze({
    profile,
    descriptors,
    commitments,
    recoveryConfigurationHash,
    independenceAssurance,
    warnings
  });
}

function projectValidationResultForCompare(
  value: unknown,
  resultCodes: {
    readonly notObject: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly missing: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly extra: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly enumeration: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly read: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
    readonly shape: PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileErrorCode;
  }
): GenesisFinalizedProfileValidationResult {
  const obj = requirePlainObject(value, resultCodes.notObject);
  const verified = requireExactOwnKeys(
    obj,
    RESULT_OWN_KEYS,
    [],
    resultCodes.missing,
    resultCodes.extra,
    resultCodes.enumeration
  );
  const R = resultCodes.read;

  const genesisDeploymentIntentHash = requireLeafString(
    readValueFromVerifiedDescriptor(
      obj,
      verified.get("genesisDeploymentIntentHash") as PropertyDescriptor,
      R
    ),
    R
  );
  const ceremonyHashesRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("genesisEnrollmentCeremonyHashes") as PropertyDescriptor,
    R
  );
  const profileRaw = readValueFromVerifiedDescriptor(
    obj,
    verified.get("profile") as PropertyDescriptor,
    R
  );

  const ceremonySlots = requireExactThreeTuple(ceremonyHashesRaw, resultCodes.shape);
  const genesisEnrollmentCeremonyHashes = Object.freeze([
    requireLeafString(ceremonySlots[0], R),
    requireLeafString(ceremonySlots[1], R),
    requireLeafString(ceremonySlots[2], R)
  ]) as readonly [string, string, string];

  const profile = projectProfileResultForCompare(profileRaw, resultCodes);

  return Object.freeze({
    genesisDeploymentIntentHash,
    genesisEnrollmentCeremonyHashes,
    profile
  });
}

function canonicalizeValidationResultForStorage(
  result: PhilCoreV2ConsumerRecoveryGenesisProfileResult
): GenesisFinalizedProfileValidationResult {
  const descriptors = Object.freeze([
    nullPrototypeProjection(
      DESCRIPTOR_OWN_KEYS.map((key) => [
        key,
        canonicalizeDescriptorLeaf(
          key,
          (result.profile.descriptors[0] as unknown as Record<string, unknown>)[key],
          C.FINALIZED_PROFILE_RESULT_SHAPE_INVALID
        )
      ] as const)
    ),
    nullPrototypeProjection(
      DESCRIPTOR_OWN_KEYS.map((key) => [
        key,
        canonicalizeDescriptorLeaf(
          key,
          (result.profile.descriptors[1] as unknown as Record<string, unknown>)[key],
          C.FINALIZED_PROFILE_RESULT_SHAPE_INVALID
        )
      ] as const)
    ),
    nullPrototypeProjection(
      DESCRIPTOR_OWN_KEYS.map((key) => [
        key,
        canonicalizeDescriptorLeaf(
          key,
          (result.profile.descriptors[2] as unknown as Record<string, unknown>)[key],
          C.FINALIZED_PROFILE_RESULT_SHAPE_INVALID
        )
      ] as const)
    )
  ]) as GenesisFinalizedProfileValidationResult["profile"]["descriptors"];

  const profile = Object.freeze({
    profile: result.profile.profile,
    descriptors,
    commitments: Object.freeze([
      result.profile.commitments[0],
      result.profile.commitments[1],
      result.profile.commitments[2]
    ]) as readonly [string, string, string],
    recoveryConfigurationHash: result.profile.recoveryConfigurationHash,
    independenceAssurance: result.profile.independenceAssurance,
    warnings: Object.freeze([...result.profile.warnings])
  });

  return Object.freeze({
    genesisDeploymentIntentHash: result.genesisDeploymentIntentHash,
    genesisEnrollmentCeremonyHashes: Object.freeze([
      result.genesisEnrollmentCeremonyHashes[0],
      result.genesisEnrollmentCeremonyHashes[1],
      result.genesisEnrollmentCeremonyHashes[2]
    ]) as readonly [string, string, string],
    profile
  });
}

function validationResultsExactlyEqual(
  left: GenesisFinalizedProfileValidationResult,
  right: GenesisFinalizedProfileValidationResult
): boolean {
  if (left.genesisDeploymentIntentHash !== right.genesisDeploymentIntentHash) {
    return false;
  }
  for (let index = 0; index < 3; index += 1) {
    if (
      left.genesisEnrollmentCeremonyHashes[index]
      !== right.genesisEnrollmentCeremonyHashes[index]
    ) {
      return false;
    }
  }
  if (left.profile.profile !== right.profile.profile) return false;
  if (left.profile.recoveryConfigurationHash !== right.profile.recoveryConfigurationHash) {
    return false;
  }
  if (left.profile.independenceAssurance !== right.profile.independenceAssurance) {
    return false;
  }
  if (left.profile.warnings.length !== right.profile.warnings.length) return false;
  for (let index = 0; index < left.profile.warnings.length; index += 1) {
    if (left.profile.warnings[index] !== right.profile.warnings[index]) return false;
  }
  for (let index = 0; index < 3; index += 1) {
    if (left.profile.commitments[index] !== right.profile.commitments[index]) return false;
    for (const key of DESCRIPTOR_OWN_KEYS) {
      if (
        left.profile.descriptors[index][key]
        !== right.profile.descriptors[index][key]
      ) {
        return false;
      }
    }
  }
  return true;
}

function validateRecordOversized(record: GenesisFinalizedProfileRecord): void {
  let bytes: number;
  try {
    bytes = Buffer.byteLength(JSON.stringify(nullProtoClone(record)), "utf8");
  } catch {
    fail(C.FINALIZED_PROFILE_SERIALIZATION_REJECTED);
  }
  if (bytes > MAX_GENESIS_FINALIZED_PROFILE_FILE_BYTES) {
    fail(C.FINALIZED_PROFILE_RECORD_OVERSIZED);
  }
}

function buildFinalizedRecord(
  fields: GenesisFinalizedProfileRecordWithoutChecksum
): GenesisFinalizedProfileRecord {
  const withoutChecksum: GenesisFinalizedProfileRecordWithoutChecksum = {
    schemaVersion: fields.schemaVersion,
    formatProvenance: fields.formatProvenance,
    state: fields.state,
    intentId: fields.intentId,
    genesisDeploymentIntentHash: fields.genesisDeploymentIntentHash,
    sourceJournalIntegrityChecksum: fields.sourceJournalIntegrityChecksum,
    finalizedAtUnixSeconds: fields.finalizedAtUnixSeconds,
    sourceJournal: fields.sourceJournal,
    validationResult: fields.validationResult
  };
  const record: GenesisFinalizedProfileRecord = {
    ...withoutChecksum,
    integrityChecksum: computeGenesisFinalizedProfileChecksum(withoutChecksum)
  };
  validateRecordOversized(record);
  return deepFreeze(record);
}

const RESULT_CODES = Object.freeze({
  notObject: C.FINALIZED_PROFILE_RESULT_NOT_OBJECT,
  missing: C.FINALIZED_PROFILE_RESULT_MISSING_KEY,
  extra: C.FINALIZED_PROFILE_RESULT_EXTRA_KEY,
  enumeration: C.FINALIZED_PROFILE_RESULT_ENUMERATION_FAILED,
  read: C.FINALIZED_PROFILE_RESULT_PROPERTY_READ_FAILED,
  shape: C.FINALIZED_PROFILE_RESULT_SHAPE_INVALID
});

export function computeGenesisFinalizedProfileChecksum(
  record: GenesisFinalizedProfileRecordWithoutChecksum
): string {
  const source = requirePlainObject(record, C.FINALIZED_PROFILE_RECORD_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    source,
    CHECKSUM_OWN_KEYS,
    [],
    C.FINALIZED_PROFILE_RECORD_MISSING_KEY,
    C.FINALIZED_PROFILE_RECORD_EXTRA_KEY,
    C.FINALIZED_PROFILE_RECORD_ENUMERATION_FAILED
  );
  const R = C.FINALIZED_PROFILE_RECORD_PROPERTY_READ_FAILED;
  const read = (key: string): unknown =>
    readValueFromVerifiedDescriptor(source, verified.get(key) as PropertyDescriptor, R);

  const projectionSource: Record<string, unknown> = Object.create(null);
  projectionSource.schemaVersion = requireLeafNumber(read("schemaVersion"), R);
  projectionSource.formatProvenance = requireLeafString(read("formatProvenance"), R);
  projectionSource.state = requireLeafString(read("state"), R);
  projectionSource.intentId = requireLeafString(read("intentId"), R);
  projectionSource.genesisDeploymentIntentHash = requireLeafString(
    read("genesisDeploymentIntentHash"),
    R
  );
  projectionSource.sourceJournalIntegrityChecksum = requireLeafString(
    read("sourceJournalIntegrityChecksum"),
    R
  );
  projectionSource.finalizedAtUnixSeconds = requireLeafString(
    read("finalizedAtUnixSeconds"),
    R
  );
  // Never walk a live caller subtree here. The lower journal validator owns
  // the hostile journal boundary and returns a fully owned record; only that
  // record is cloned into null-prototype checksum containers.
  projectionSource.sourceJournal = nullProtoClone(
    validateGenesisStagingJournalRecord(read("sourceJournal"))
  );
  projectionSource.validationResult = projectValidationResultForCompare(
    read("validationResult"),
    RESULT_CODES
  );

  let projection: string;
  try {
    projection = JSON.stringify(projectionSource);
  } catch (error) {
    failWithCause(C.FINALIZED_PROFILE_SERIALIZATION_REJECTED, error);
  }
  const digest = createHash("sha256")
    .update(PHILCORE_V2_GENESIS_FINALIZED_PROFILE_CHECKSUM_PREFIX, "utf8")
    .update(projection, "utf8")
    .digest("hex");
  return `0x${digest}`;
}

export function createGenesisFinalizedProfileRecord(
  journal: unknown,
  expectedValidationResult: unknown,
  nowUnixSeconds: number
): GenesisFinalizedProfileRecord {
  // 1) Authoritative journal/clock/profile validation by exactly one adapter call.
  // Lower thrown values propagate by identity and are never caught here.
  const authoritativeResult = validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
    journal,
    nowUnixSeconds
  );

  // 2) Owned, validated source journal for embedding (adapter already proved validity).
  const validatedJournal = validateGenesisStagingJournalRecord(journal);

  // 3) Hostile-safe exact projection of the caller expectation, only after authority.
  const projectedExpected = projectValidationResultForCompare(
    expectedValidationResult,
    RESULT_CODES
  );
  const canonicalAuthoritative = canonicalizeValidationResultForStorage(authoritativeResult);
  if (!validationResultsExactlyEqual(projectedExpected, canonicalAuthoritative)) {
    fail(C.FINALIZED_PROFILE_RESULT_MISMATCH);
  }

  const finalizedAtUnixSeconds = BigInt(nowUnixSeconds).toString(10);

  return buildFinalizedRecord({
    schemaVersion: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE,
    state: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE,
    intentId: validatedJournal.intentId,
    genesisDeploymentIntentHash: validatedJournal.genesisDeploymentIntentHash,
    sourceJournalIntegrityChecksum: validatedJournal.integrityChecksum,
    finalizedAtUnixSeconds,
    sourceJournal: validatedJournal,
    validationResult: canonicalAuthoritative
  });
}

export function validateGenesisFinalizedProfileRecord(
  record: unknown
): GenesisFinalizedProfileRecord {
  const input = requirePlainObject(record, C.FINALIZED_PROFILE_RECORD_NOT_OBJECT);
  const verified = requireExactOwnKeys(
    input,
    RECORD_OWN_KEYS,
    [],
    C.FINALIZED_PROFILE_RECORD_MISSING_KEY,
    C.FINALIZED_PROFILE_RECORD_EXTRA_KEY,
    C.FINALIZED_PROFILE_RECORD_ENUMERATION_FAILED
  );
  const R = C.FINALIZED_PROFILE_RECORD_PROPERTY_READ_FAILED;

  const schemaVersion = readValueFromVerifiedDescriptor(
    input,
    verified.get("schemaVersion") as PropertyDescriptor,
    R
  );
  if (schemaVersion !== PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION) {
    fail(C.FINALIZED_PROFILE_SCHEMA_VERSION_UNSUPPORTED);
  }

  const formatProvenance = readValueFromVerifiedDescriptor(
    input,
    verified.get("formatProvenance") as PropertyDescriptor,
    R
  );
  if (formatProvenance !== PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE) {
    fail(C.FINALIZED_PROFILE_FORMAT_PROVENANCE_INVALID);
  }

  const stateRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("state") as PropertyDescriptor,
    R
  );
  if (stateRaw !== PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE) {
    fail(C.FINALIZED_PROFILE_STATE_INVALID);
  }

  const intentIdRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("intentId") as PropertyDescriptor,
    R
  );
  if (typeof intentIdRaw !== "string") fail(R);
  const intentId = intentIdRaw;

  const genesisDeploymentIntentHashRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("genesisDeploymentIntentHash") as PropertyDescriptor,
    R
  );
  if (typeof genesisDeploymentIntentHashRaw !== "string") fail(R);
  const genesisDeploymentIntentHash = genesisDeploymentIntentHashRaw;

  const sourceJournalIntegrityChecksumRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("sourceJournalIntegrityChecksum") as PropertyDescriptor,
    R
  );
  if (typeof sourceJournalIntegrityChecksumRaw !== "string") fail(R);
  const sourceJournalIntegrityChecksum = sourceJournalIntegrityChecksumRaw;

  const finalizedAtRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("finalizedAtUnixSeconds") as PropertyDescriptor,
    R
  );
  const finalizedAtUnixSeconds = requireStoredPositiveUint48String(
    finalizedAtRaw,
    C.FINALIZED_PROFILE_FINALIZED_AT_INVALID
  );

  const sourceJournalRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("sourceJournal") as PropertyDescriptor,
    R
  );
  const validationResultRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("validationResult") as PropertyDescriptor,
    R
  );
  const integrityChecksumRaw = readValueFromVerifiedDescriptor(
    input,
    verified.get("integrityChecksum") as PropertyDescriptor,
    R
  );
  if (typeof integrityChecksumRaw !== "string") fail(R);

  const projectedValidationResult = projectValidationResultForCompare(
    validationResultRaw,
    RESULT_CODES
  );

  const tentative: GenesisFinalizedProfileRecord = {
    schemaVersion: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE,
    state: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE,
    intentId,
    genesisDeploymentIntentHash,
    sourceJournalIntegrityChecksum,
    finalizedAtUnixSeconds,
    sourceJournal: sourceJournalRaw as GenesisStagingJournalRecord,
    validationResult: projectedValidationResult,
    integrityChecksum: integrityChecksumRaw
  };
  validateRecordOversized(tentative);

  const validatedSourceJournal = validateGenesisStagingJournalRecord(sourceJournalRaw);

  if (validatedSourceJournal.state !== PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING) {
    fail(C.FINALIZED_PROFILE_STATE_INVALID);
  }
  if (!allGenesisStagingSlotsPopulated(validatedSourceJournal)) {
    fail(C.FINALIZED_PROFILE_STATE_INVALID);
  }

  requireStoredPositiveUint48String(
    validatedSourceJournal.updatedAtUnixSeconds,
    C.FINALIZED_PROFILE_SOURCE_TIMESTAMP_INVALID
  );

  if (intentId !== validatedSourceJournal.intentId) {
    fail(C.FINALIZED_PROFILE_INTENT_ID_MISMATCH);
  }
  if (genesisDeploymentIntentHash !== validatedSourceJournal.genesisDeploymentIntentHash) {
    fail(C.FINALIZED_PROFILE_INTENT_HASH_MISMATCH);
  }
  if (sourceJournalIntegrityChecksum !== validatedSourceJournal.integrityChecksum) {
    fail(C.FINALIZED_PROFILE_SOURCE_CHECKSUM_MISMATCH);
  }

  const recomputedResult = validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
    validatedSourceJournal,
    Number(finalizedAtUnixSeconds)
  );

  const canonicalRecomputed = canonicalizeValidationResultForStorage(recomputedResult);
  if (!validationResultsExactlyEqual(projectedValidationResult, canonicalRecomputed)) {
    fail(C.FINALIZED_PROFILE_RESULT_MISMATCH);
  }

  const integrityChecksum = requireChecksumBytes32Format(integrityChecksumRaw);

  const withoutChecksum: GenesisFinalizedProfileRecordWithoutChecksum = {
    schemaVersion: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION,
    formatProvenance: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE,
    state: PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE,
    intentId: validatedSourceJournal.intentId,
    genesisDeploymentIntentHash: validatedSourceJournal.genesisDeploymentIntentHash,
    sourceJournalIntegrityChecksum: validatedSourceJournal.integrityChecksum,
    finalizedAtUnixSeconds,
    sourceJournal: validatedSourceJournal,
    validationResult: canonicalRecomputed
  };

  if (computeGenesisFinalizedProfileChecksum(withoutChecksum) !== integrityChecksum) {
    fail(C.FINALIZED_PROFILE_CHECKSUM_MISMATCH);
  }

  return deepFreeze({ ...withoutChecksum, integrityChecksum });
}
