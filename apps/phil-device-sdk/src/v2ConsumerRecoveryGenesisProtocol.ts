import {
  AbiCoder,
  getAddress,
  isHexString,
  keccak256,
  toUtf8Bytes
} from "ethers";

import type { Hex } from "./hashes.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "./v2Intent.ts";
import { PHILCORE_V2_VALIDATOR_VERIFIER_KIND } from "./v2Authorization.ts";
import {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  validatePhilCoreV2ConsumerRecoveryProfile,
  type PhilCoreV2ConsumerRecoveryFactor,
  type PhilCoreV2ConsumerRecoveryProfileResult
} from "./v2ConsumerRecovery.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const CANONICAL_UINT_STRING = /^(0|[1-9][0-9]*)$/;

// ---------------------------------------------------------------------------
// Domain-separated literals (Package 5B-0.2). Distinct typehashes from the
// existing account-bound PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_LITERAL --
// genesis ceremonies bind an address-independent deployment intent, never an
// account address, and the two domains must never cross-validate.
// ---------------------------------------------------------------------------

export const PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_LITERAL =
  "PhilCoreV2LocalGenesisDeploymentIntentV1(uint8 intentVersion,bytes32 intentId,uint256 chainId,address entryPoint,address factoryBinding,address confirmationTarget,address verifier,bytes32 verifierRuntimeCodeHash,bytes32 accountCreationBytecodeHash,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,bytes32 ownerCommitment,bytes32 identityBindingCommitment,address initialValidator,uint8 validatorVerifierKind,bytes32 validatorKeyIdBinding,bytes32 validatorCommitment,uint64 validatorEpoch,uint64 recoveryEpoch,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds,bytes32 userSalt,uint48 expiresAt)" as const;

export const PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_LITERAL =
  "PhilCoreV2LocalGenesisEnrollmentCeremonyV1(uint8 ceremonyVersion,bytes32 ceremonyId,bytes32 genesisDeploymentIntentHash,uint8 role,uint64 credentialGeneration,uint48 expiresAt)" as const;

export const PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_TYPEHASH = keccak256(
  toUtf8Bytes(PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_LITERAL)
) as Hex;

export const PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_TYPEHASH = keccak256(
  toUtf8Bytes(PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_LITERAL)
) as Hex;

const INTENT_ABI_TYPES = Object.freeze([
  "bytes32", // typehash
  "uint8",   // intentVersion
  "bytes32", // intentId
  "uint256", // chainId
  "address", // entryPoint
  "address", // factoryBinding
  "address", // confirmationTarget
  "address", // verifier
  "bytes32", // verifierRuntimeCodeHash
  "bytes32", // accountCreationBytecodeHash
  "bytes32", // accountVersionId
  "bytes32", // securityModelId
  "bytes32", // recoveryDomainId
  "bytes32", // ownerCommitment
  "bytes32", // identityBindingCommitment
  "address", // initialValidator
  "uint8",   // validatorVerifierKind
  "bytes32", // validatorKeyIdBinding
  "bytes32", // validatorCommitment
  "uint64",  // validatorEpoch
  "uint64",  // recoveryEpoch
  "uint64",  // recoveryDelaySeconds
  "uint64",  // recoveryExpirySeconds
  "bytes32", // userSalt
  "uint48"   // expiresAt
] as const);

const CEREMONY_ABI_TYPES = Object.freeze([
  "bytes32", // typehash
  "uint8",   // ceremonyVersion
  "bytes32", // ceremonyId
  "bytes32", // genesisDeploymentIntentHash
  "uint8",   // role
  "uint64",  // credentialGeneration
  "uint48"   // expiresAt
] as const);

const PINNED_ACCOUNT_VERSION_ID = PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID;
const PINNED_SECURITY_MODEL_ID = PHILCORE_V2_SECURITY_MODEL_ID;
const PINNED_RECOVERY_DOMAIN_ID = PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID;
const PINNED_VALIDATOR_VERIFIER_KIND = BigInt(
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA
);
const PINNED_VALIDATOR_EPOCH = 1n;
const PINNED_RECOVERY_EPOCH = 1n;
const PINNED_RECOVERY_DELAY_SECONDS = 172800n;
const PINNED_RECOVERY_EXPIRY_SECONDS = 604800n;
const PINNED_INTENT_VERSION = 1n;
const PINNED_CEREMONY_VERSION = 1n;
const PINNED_GENESIS_GENERATION = 1n;

// ---------------------------------------------------------------------------
// Closed error surface, unforgeable brand (mirrors
// v2ConsumerRecoveryStagingJournal.ts's established Round-3 pattern exactly).
// Every intent field, every ceremony field, and every schema/access boundary
// carries its own distinguishable code -- no two unrelated fields ever share
// a code, and no raw caller-thrown value is ever retained anywhere on the
// classified error (see failWithCause below).
// ---------------------------------------------------------------------------

export const PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE =
  Object.freeze({
    // Intent schema / property access.
    INTENT_INPUT_NOT_OBJECT: "INTENT_INPUT_NOT_OBJECT",
    INTENT_EXTRA_OWN_KEY: "INTENT_EXTRA_OWN_KEY",
    INTENT_MISSING_OWN_KEY: "INTENT_MISSING_OWN_KEY",
    INTENT_ENUMERATION_FAILED: "INTENT_ENUMERATION_FAILED",
    INTENT_PROPERTY_READ_FAILED: "INTENT_PROPERTY_READ_FAILED",

    // Ceremony schema / property access.
    CEREMONY_INPUT_NOT_OBJECT: "CEREMONY_INPUT_NOT_OBJECT",
    CEREMONY_EXTRA_OWN_KEY: "CEREMONY_EXTRA_OWN_KEY",
    CEREMONY_MISSING_OWN_KEY: "CEREMONY_MISSING_OWN_KEY",
    CEREMONY_ENUMERATION_FAILED: "CEREMONY_ENUMERATION_FAILED",
    CEREMONY_PROPERTY_READ_FAILED: "CEREMONY_PROPERTY_READ_FAILED",

    // Top-level profile schema / property access.
    PROFILE_INPUT_NOT_OBJECT: "PROFILE_INPUT_NOT_OBJECT",
    PROFILE_EXTRA_OWN_KEY: "PROFILE_EXTRA_OWN_KEY",
    PROFILE_MISSING_OWN_KEY: "PROFILE_MISSING_OWN_KEY",
    PROFILE_ENUMERATION_FAILED: "PROFILE_ENUMERATION_FAILED",
    PROFILE_PROPERTY_READ_FAILED: "PROFILE_PROPERTY_READ_FAILED",

    // Tuple shape (ceremonies / factors).
    CEREMONIES_NOT_TUPLE: "CEREMONIES_NOT_TUPLE",
    FACTORS_NOT_TUPLE: "FACTORS_NOT_TUPLE",

    // Intent fields, in literal order -- each independently distinguishable.
    INTENT_VERSION_INVALID: "INTENT_VERSION_INVALID",
    INTENT_VERSION_MISMATCH: "INTENT_VERSION_MISMATCH",
    INTENT_ID_INVALID: "INTENT_ID_INVALID",
    INTENT_ID_ZERO: "INTENT_ID_ZERO",
    CHAIN_ID_INVALID: "CHAIN_ID_INVALID",
    CHAIN_ID_ZERO: "CHAIN_ID_ZERO",
    ENTRY_POINT_INVALID: "ENTRY_POINT_INVALID",
    ENTRY_POINT_ZERO: "ENTRY_POINT_ZERO",
    FACTORY_BINDING_INVALID: "FACTORY_BINDING_INVALID",
    FACTORY_BINDING_ZERO: "FACTORY_BINDING_ZERO",
    CONFIRMATION_TARGET_INVALID: "CONFIRMATION_TARGET_INVALID",
    CONFIRMATION_TARGET_ZERO: "CONFIRMATION_TARGET_ZERO",
    VERIFIER_INVALID: "VERIFIER_INVALID",
    VERIFIER_ZERO: "VERIFIER_ZERO",
    VERIFIER_RUNTIME_CODE_HASH_INVALID: "VERIFIER_RUNTIME_CODE_HASH_INVALID",
    VERIFIER_RUNTIME_CODE_HASH_ZERO: "VERIFIER_RUNTIME_CODE_HASH_ZERO",
    ACCOUNT_CREATION_BYTECODE_HASH_INVALID: "ACCOUNT_CREATION_BYTECODE_HASH_INVALID",
    ACCOUNT_CREATION_BYTECODE_HASH_ZERO: "ACCOUNT_CREATION_BYTECODE_HASH_ZERO",
    ACCOUNT_VERSION_ID_INVALID: "ACCOUNT_VERSION_ID_INVALID",
    ACCOUNT_VERSION_ID_MISMATCH: "ACCOUNT_VERSION_ID_MISMATCH",
    SECURITY_MODEL_ID_INVALID: "SECURITY_MODEL_ID_INVALID",
    SECURITY_MODEL_ID_MISMATCH: "SECURITY_MODEL_ID_MISMATCH",
    RECOVERY_DOMAIN_ID_INVALID: "RECOVERY_DOMAIN_ID_INVALID",
    RECOVERY_DOMAIN_ID_MISMATCH: "RECOVERY_DOMAIN_ID_MISMATCH",
    OWNER_COMMITMENT_INVALID: "OWNER_COMMITMENT_INVALID",
    OWNER_COMMITMENT_ZERO: "OWNER_COMMITMENT_ZERO",
    IDENTITY_BINDING_COMMITMENT_INVALID: "IDENTITY_BINDING_COMMITMENT_INVALID",
    IDENTITY_BINDING_COMMITMENT_ZERO: "IDENTITY_BINDING_COMMITMENT_ZERO",
    INITIAL_VALIDATOR_INVALID: "INITIAL_VALIDATOR_INVALID",
    INITIAL_VALIDATOR_ZERO: "INITIAL_VALIDATOR_ZERO",
    VALIDATOR_VERIFIER_KIND_INVALID: "VALIDATOR_VERIFIER_KIND_INVALID",
    VALIDATOR_VERIFIER_KIND_MISMATCH: "VALIDATOR_VERIFIER_KIND_MISMATCH",
    VALIDATOR_KEY_ID_BINDING_INVALID: "VALIDATOR_KEY_ID_BINDING_INVALID",
    VALIDATOR_KEY_ID_BINDING_ZERO: "VALIDATOR_KEY_ID_BINDING_ZERO",
    VALIDATOR_COMMITMENT_INVALID: "VALIDATOR_COMMITMENT_INVALID",
    VALIDATOR_COMMITMENT_ZERO: "VALIDATOR_COMMITMENT_ZERO",
    VALIDATOR_EPOCH_INVALID: "VALIDATOR_EPOCH_INVALID",
    VALIDATOR_EPOCH_MISMATCH: "VALIDATOR_EPOCH_MISMATCH",
    RECOVERY_EPOCH_INVALID: "RECOVERY_EPOCH_INVALID",
    RECOVERY_EPOCH_MISMATCH: "RECOVERY_EPOCH_MISMATCH",
    RECOVERY_DELAY_SECONDS_INVALID: "RECOVERY_DELAY_SECONDS_INVALID",
    RECOVERY_DELAY_SECONDS_MISMATCH: "RECOVERY_DELAY_SECONDS_MISMATCH",
    RECOVERY_EXPIRY_SECONDS_INVALID: "RECOVERY_EXPIRY_SECONDS_INVALID",
    RECOVERY_EXPIRY_SECONDS_MISMATCH: "RECOVERY_EXPIRY_SECONDS_MISMATCH",
    USER_SALT_INVALID: "USER_SALT_INVALID",
    USER_SALT_ZERO: "USER_SALT_ZERO",
    INTENT_EXPIRES_AT_INVALID: "INTENT_EXPIRES_AT_INVALID",
    INTENT_EXPIRES_AT_ZERO: "INTENT_EXPIRES_AT_ZERO",

    // Ceremony fields, in literal order.
    CEREMONY_VERSION_INVALID: "CEREMONY_VERSION_INVALID",
    CEREMONY_VERSION_MISMATCH: "CEREMONY_VERSION_MISMATCH",
    CEREMONY_ID_INVALID: "CEREMONY_ID_INVALID",
    CEREMONY_ID_ZERO: "CEREMONY_ID_ZERO",
    CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_INVALID:
      "CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_INVALID",
    CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_ZERO:
      "CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_ZERO",
    CEREMONY_ROLE_INVALID: "CEREMONY_ROLE_INVALID",
    CEREMONY_GENERATION_INVALID: "CEREMONY_GENERATION_INVALID",
    CEREMONY_GENERATION_MISMATCH: "CEREMONY_GENERATION_MISMATCH",
    CEREMONY_EXPIRES_AT_INVALID: "CEREMONY_EXPIRES_AT_INVALID",
    CEREMONY_EXPIRES_AT_ZERO: "CEREMONY_EXPIRES_AT_ZERO",

    // Cross-record provenance (profile level).
    CEREMONY_INTENT_MISMATCH: "CEREMONY_INTENT_MISMATCH",
    CEREMONY_ROLE_ORDER_INVALID: "CEREMONY_ROLE_ORDER_INVALID",
    CEREMONY_ID_DUPLICATE: "CEREMONY_ID_DUPLICATE",
    CEREMONY_EXPIRY_EXCEEDS_INTENT: "CEREMONY_EXPIRY_EXCEEDS_INTENT",

    // Factor schema / property access and provenance.
    FACTOR_INPUT_NOT_OBJECT: "FACTOR_INPUT_NOT_OBJECT",
    FACTOR_DESCRIPTOR_INVALID: "FACTOR_DESCRIPTOR_INVALID",
    FACTOR_INDEPENDENCE_INVALID: "FACTOR_INDEPENDENCE_INVALID",
    FACTOR_ROLE_MISMATCH: "FACTOR_ROLE_MISMATCH",
    FACTOR_GENERATION_MISMATCH: "FACTOR_GENERATION_MISMATCH",
    FACTOR_CEREMONY_HASH_MISMATCH: "FACTOR_CEREMONY_HASH_MISMATCH",

    // Genesis execution-validator provenance.
    EXECUTION_VALIDATOR_INTENT_MISMATCH: "EXECUTION_VALIDATOR_INTENT_MISMATCH",

    // Delegated generic-profile validation.
    GENERIC_PROFILE_VALIDATION_FAILED: "GENERIC_PROFILE_VALIDATION_FAILED"
  } as const);

export type PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode =
  typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE[
    keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE
  ];

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2ConsumerRecoveryGenesisProtocolError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryGenesisProtocolError";
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
  PhilCoreV2ConsumerRecoveryGenesisProtocolError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2ConsumerRecoveryGenesisProtocolError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const C = PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE;

function fail(
  code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  message?: string
): never {
  throw new PhilCoreV2ConsumerRecoveryGenesisProtocolError(code, message);
}

function isClassifiedError(
  value: unknown
): value is PhilCoreV2ConsumerRecoveryGenesisProtocolError {
  try {
    return value instanceof PhilCoreV2ConsumerRecoveryGenesisProtocolError;
  } catch {
    return false;
  }
}

/**
 * Converts any untrusted thrown value into a closed classified error.
 * A genuine branded error is rethrown unchanged (its own code preserved).
 * Anything else -- a hostile marker, a spoofed prototype, a coercion trap --
 * is discarded entirely: the raw value is never inspected (no .code,
 * .message, .name, or prototype read), never retained as `cause`, and never
 * exposed under any other property. Only the caller-supplied closed `code`
 * survives.
 */
function failWithCause(
  code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  cause: unknown
): never {
  if (isClassifiedError(cause)) {
    throw cause;
  }
  fail(code);
}

// ---------------------------------------------------------------------------
// Hostile-surface-safe property access. Exact own-key validation is based on
// Reflect.ownKeys (not Object.keys): every string key is checked whether or
// not it is enumerable, and every symbol key is rejected outright, so a
// hostile caller cannot smuggle an extra own key past validation merely by
// making it non-enumerable or symbol-keyed.
// ---------------------------------------------------------------------------

function requirePlainObject(
  value: unknown,
  code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
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

/**
 * Reads a value strictly from an already-verified own-property descriptor --
 * never via a fresh ordinary property lookup on the caller's object, which a
 * hostile Proxy could route through its prototype chain or a trap. A data
 * property yields `descriptor.value` directly. An accessor property invokes
 * `descriptor.get` exactly once, with `value` as the receiver; an accessor
 * with no getter (set-only) is rejected outright rather than silently
 * yielding `undefined`. Any throw from the getter is classified with `code`
 * and the raw thrown value is never retained or exposed.
 */
function readValueFromVerifiedDescriptor(
  value: object,
  descriptor: PropertyDescriptor,
  code: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
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

/**
 * Requires that `value`'s own-key surface is exactly `requiredKeys` plus,
 * optionally, any subset of `optionalKeys` -- enumerable or not, and no
 * symbol keys at all. `Reflect.ownKeys` is treated as a list of CANDIDATES
 * only, never as proof of ownership: a hostile Proxy can report a name via
 * its `ownKeys` trap while the name resolves only through the prototype
 * chain (or not at all), which is spec-legal whenever the proxy's target is
 * extensible with no non-configurable own properties. Every candidate is
 * therefore independently re-verified with a guarded
 * `Object.getOwnPropertyDescriptor` call; only a non-`undefined` descriptor
 * counts as genuine ownership. The returned map carries those verified
 * descriptors so callers can read values directly from them (see
 * `readValueFromVerifiedDescriptor`) instead of touching the caller's object
 * a second time.
 */
function requireExactOwnKeys(
  value: Record<string, unknown>,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  missingCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
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

function requireBytes32(
  value: unknown,
  invalidCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  zeroCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    fail(invalidCode);
  }
  const normalized = value.toLowerCase() as Hex;
  if (normalized !== value) {
    fail(invalidCode);
  }
  if (normalized === ZERO_BYTES32) {
    fail(zeroCode);
  }
  return normalized;
}

function requirePinnedBytes32(
  value: unknown,
  expected: Hex,
  invalidCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  mismatchCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): Hex {
  const normalized = requireBytes32(value, invalidCode, invalidCode);
  if (normalized !== expected.toLowerCase()) {
    fail(mismatchCode);
  }
  return normalized;
}

function requireCanonicalAddress(
  value: unknown,
  invalidCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  zeroCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
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
  if (normalized !== value) {
    fail(invalidCode);
  }
  if (normalized === ZERO_ADDRESS) {
    fail(zeroCode);
  }
  return normalized;
}

function requireCanonicalUint(
  value: unknown,
  bits: number,
  invalidCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): bigint {
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
  return parsed;
}

function requirePinnedUint(
  value: unknown,
  bits: number,
  expected: bigint,
  invalidCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  mismatchCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): bigint {
  const parsed = requireCanonicalUint(value, bits, invalidCode);
  if (parsed !== expected) {
    fail(mismatchCode);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Public input types. Numeric public inputs are exactly `bigint | string` --
// runtime rejects every JavaScript `number`, and the type surface reflects
// that; no numeric field's declared type may silently invite a rejected
// shape.
// ---------------------------------------------------------------------------

export type PhilCoreV2LocalGenesisDeploymentIntentInput = {
  readonly intentVersion: bigint | string;
  readonly intentId: string;
  readonly chainId: bigint | string;
  readonly entryPoint: string;
  readonly factoryBinding: string;
  readonly confirmationTarget: string;
  readonly verifier: string;
  readonly verifierRuntimeCodeHash: string;
  readonly accountCreationBytecodeHash: string;
  readonly accountVersionId: string;
  readonly securityModelId: string;
  readonly recoveryDomainId: string;
  readonly ownerCommitment: string;
  readonly identityBindingCommitment: string;
  readonly initialValidator: string;
  readonly validatorVerifierKind: bigint | string;
  readonly validatorKeyIdBinding: string;
  readonly validatorCommitment: string;
  readonly validatorEpoch: bigint | string;
  readonly recoveryEpoch: bigint | string;
  readonly recoveryDelaySeconds: bigint | string;
  readonly recoveryExpirySeconds: bigint | string;
  readonly userSalt: string;
  readonly expiresAt: bigint | string;
};

export type PhilCoreV2LocalGenesisEnrollmentCeremonyInput = {
  readonly ceremonyVersion: bigint | string;
  readonly ceremonyId: string;
  readonly genesisDeploymentIntentHash: string;
  readonly role: bigint | string;
  readonly credentialGeneration: bigint | string;
  readonly expiresAt: bigint | string;
};

export interface PhilCoreV2ConsumerRecoveryGenesisProfileResult {
  readonly genesisDeploymentIntentHash: Hex;
  readonly genesisEnrollmentCeremonyHashes: readonly [Hex, Hex, Hex];
  readonly profile: PhilCoreV2ConsumerRecoveryProfileResult;
}

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

const CEREMONY_OWN_KEYS = Object.freeze([
  "ceremonyVersion",
  "ceremonyId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "expiresAt"
] as const);

const PROFILE_OWN_KEYS = Object.freeze([
  "intent",
  "ceremonies",
  "factors",
  "executionValidator"
] as const);

const FACTOR_REQUIRED_OWN_KEYS = Object.freeze(["descriptor", "independence"] as const);
const FACTOR_OPTIONAL_OWN_KEYS = Object.freeze(["signer"] as const);

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

// ---------------------------------------------------------------------------
// Pure hash functions
// ---------------------------------------------------------------------------

/**
 * Raw keccak256(abi.encode(...)) genesis deployment intent hash.
 * No EIP-191 / EIP-712 wrapping. Address-independent: never includes an
 * account, a factor commitment, a recovery configuration hash, or the
 * full-initialization accountCreationCodeHash.
 */
export function computePhilCoreV2LocalGenesisDeploymentIntentHash(
  input: PhilCoreV2LocalGenesisDeploymentIntentInput
): Hex {
  const value = requirePlainObject(input, C.INTENT_INPUT_NOT_OBJECT);
  const valueDescriptors = requireExactOwnKeys(
    value,
    INTENT_OWN_KEYS,
    [],
    C.INTENT_MISSING_OWN_KEY,
    C.INTENT_EXTRA_OWN_KEY,
    C.INTENT_ENUMERATION_FAILED
  );
  const R = C.INTENT_PROPERTY_READ_FAILED;
  const read = (key: string): unknown =>
    readValueFromVerifiedDescriptor(value, valueDescriptors.get(key) as PropertyDescriptor, R);

  const intentVersion = requirePinnedUint(
    read("intentVersion"),
    8,
    PINNED_INTENT_VERSION,
    C.INTENT_VERSION_INVALID,
    C.INTENT_VERSION_MISMATCH
  );
  const intentId = requireBytes32(
    read("intentId"),
    C.INTENT_ID_INVALID,
    C.INTENT_ID_ZERO
  );
  const chainId = requireCanonicalUint(
    read("chainId"),
    256,
    C.CHAIN_ID_INVALID
  );
  if (chainId === 0n) fail(C.CHAIN_ID_ZERO);
  const entryPoint = requireCanonicalAddress(
    read("entryPoint"),
    C.ENTRY_POINT_INVALID,
    C.ENTRY_POINT_ZERO
  );
  const factoryBinding = requireCanonicalAddress(
    read("factoryBinding"),
    C.FACTORY_BINDING_INVALID,
    C.FACTORY_BINDING_ZERO
  );
  const confirmationTarget = requireCanonicalAddress(
    read("confirmationTarget"),
    C.CONFIRMATION_TARGET_INVALID,
    C.CONFIRMATION_TARGET_ZERO
  );
  const verifier = requireCanonicalAddress(
    read("verifier"),
    C.VERIFIER_INVALID,
    C.VERIFIER_ZERO
  );
  const verifierRuntimeCodeHash = requireBytes32(
    read("verifierRuntimeCodeHash"),
    C.VERIFIER_RUNTIME_CODE_HASH_INVALID,
    C.VERIFIER_RUNTIME_CODE_HASH_ZERO
  );
  const accountCreationBytecodeHash = requireBytes32(
    read("accountCreationBytecodeHash"),
    C.ACCOUNT_CREATION_BYTECODE_HASH_INVALID,
    C.ACCOUNT_CREATION_BYTECODE_HASH_ZERO
  );
  const accountVersionId = requirePinnedBytes32(
    read("accountVersionId"),
    PINNED_ACCOUNT_VERSION_ID,
    C.ACCOUNT_VERSION_ID_INVALID,
    C.ACCOUNT_VERSION_ID_MISMATCH
  );
  const securityModelId = requirePinnedBytes32(
    read("securityModelId"),
    PINNED_SECURITY_MODEL_ID,
    C.SECURITY_MODEL_ID_INVALID,
    C.SECURITY_MODEL_ID_MISMATCH
  );
  const recoveryDomainId = requirePinnedBytes32(
    read("recoveryDomainId"),
    PINNED_RECOVERY_DOMAIN_ID,
    C.RECOVERY_DOMAIN_ID_INVALID,
    C.RECOVERY_DOMAIN_ID_MISMATCH
  );
  const ownerCommitment = requireBytes32(
    read("ownerCommitment"),
    C.OWNER_COMMITMENT_INVALID,
    C.OWNER_COMMITMENT_ZERO
  );
  const identityBindingCommitment = requireBytes32(
    read("identityBindingCommitment"),
    C.IDENTITY_BINDING_COMMITMENT_INVALID,
    C.IDENTITY_BINDING_COMMITMENT_ZERO
  );
  const initialValidator = requireCanonicalAddress(
    read("initialValidator"),
    C.INITIAL_VALIDATOR_INVALID,
    C.INITIAL_VALIDATOR_ZERO
  );
  const validatorVerifierKind = requirePinnedUint(
    read("validatorVerifierKind"),
    8,
    PINNED_VALIDATOR_VERIFIER_KIND,
    C.VALIDATOR_VERIFIER_KIND_INVALID,
    C.VALIDATOR_VERIFIER_KIND_MISMATCH
  );
  const validatorKeyIdBinding = requireBytes32(
    read("validatorKeyIdBinding"),
    C.VALIDATOR_KEY_ID_BINDING_INVALID,
    C.VALIDATOR_KEY_ID_BINDING_ZERO
  );
  const validatorCommitment = requireBytes32(
    read("validatorCommitment"),
    C.VALIDATOR_COMMITMENT_INVALID,
    C.VALIDATOR_COMMITMENT_ZERO
  );
  const validatorEpoch = requirePinnedUint(
    read("validatorEpoch"),
    64,
    PINNED_VALIDATOR_EPOCH,
    C.VALIDATOR_EPOCH_INVALID,
    C.VALIDATOR_EPOCH_MISMATCH
  );
  const recoveryEpoch = requirePinnedUint(
    read("recoveryEpoch"),
    64,
    PINNED_RECOVERY_EPOCH,
    C.RECOVERY_EPOCH_INVALID,
    C.RECOVERY_EPOCH_MISMATCH
  );
  const recoveryDelaySeconds = requirePinnedUint(
    read("recoveryDelaySeconds"),
    64,
    PINNED_RECOVERY_DELAY_SECONDS,
    C.RECOVERY_DELAY_SECONDS_INVALID,
    C.RECOVERY_DELAY_SECONDS_MISMATCH
  );
  const recoveryExpirySeconds = requirePinnedUint(
    read("recoveryExpirySeconds"),
    64,
    PINNED_RECOVERY_EXPIRY_SECONDS,
    C.RECOVERY_EXPIRY_SECONDS_INVALID,
    C.RECOVERY_EXPIRY_SECONDS_MISMATCH
  );
  const userSalt = requireBytes32(
    read("userSalt"),
    C.USER_SALT_INVALID,
    C.USER_SALT_ZERO
  );
  const expiresAt = requireCanonicalUint(
    read("expiresAt"),
    48,
    C.INTENT_EXPIRES_AT_INVALID
  );
  if (expiresAt === 0n) fail(C.INTENT_EXPIRES_AT_ZERO);

  return keccak256(
    abiCoder.encode(
      [...INTENT_ABI_TYPES],
      [
        PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_TYPEHASH,
        intentVersion,
        intentId,
        chainId,
        entryPoint,
        factoryBinding,
        confirmationTarget,
        verifier,
        verifierRuntimeCodeHash,
        accountCreationBytecodeHash,
        accountVersionId,
        securityModelId,
        recoveryDomainId,
        ownerCommitment,
        identityBindingCommitment,
        initialValidator,
        validatorVerifierKind,
        validatorKeyIdBinding,
        validatorCommitment,
        validatorEpoch,
        recoveryEpoch,
        recoveryDelaySeconds,
        recoveryExpirySeconds,
        userSalt,
        expiresAt
      ]
    )
  ) as Hex;
}

/**
 * Raw keccak256(abi.encode(...)) genesis enrollment ceremony hash.
 * No EIP-191 / EIP-712 wrapping. Binds the full genesisDeploymentIntentHash
 * (never a bare intentId) plus exactly what is new at ceremony scope.
 */
export function computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
  input: PhilCoreV2LocalGenesisEnrollmentCeremonyInput
): Hex {
  const value = requirePlainObject(input, C.CEREMONY_INPUT_NOT_OBJECT);
  const valueDescriptors = requireExactOwnKeys(
    value,
    CEREMONY_OWN_KEYS,
    [],
    C.CEREMONY_MISSING_OWN_KEY,
    C.CEREMONY_EXTRA_OWN_KEY,
    C.CEREMONY_ENUMERATION_FAILED
  );
  const R = C.CEREMONY_PROPERTY_READ_FAILED;
  const read = (key: string): unknown =>
    readValueFromVerifiedDescriptor(value, valueDescriptors.get(key) as PropertyDescriptor, R);

  const ceremonyVersion = requirePinnedUint(
    read("ceremonyVersion"),
    8,
    PINNED_CEREMONY_VERSION,
    C.CEREMONY_VERSION_INVALID,
    C.CEREMONY_VERSION_MISMATCH
  );
  const ceremonyId = requireBytes32(
    read("ceremonyId"),
    C.CEREMONY_ID_INVALID,
    C.CEREMONY_ID_ZERO
  );
  const genesisDeploymentIntentHash = requireBytes32(
    read("genesisDeploymentIntentHash"),
    C.CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_INVALID,
    C.CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_ZERO
  );
  const roleValue = requireCanonicalUint(
    read("role"),
    8,
    C.CEREMONY_ROLE_INVALID
  );
  if (roleValue !== 0n && roleValue !== 1n && roleValue !== 2n) {
    fail(C.CEREMONY_ROLE_INVALID);
  }
  const credentialGeneration = requirePinnedUint(
    read("credentialGeneration"),
    64,
    PINNED_GENESIS_GENERATION,
    C.CEREMONY_GENERATION_INVALID,
    C.CEREMONY_GENERATION_MISMATCH
  );
  const expiresAt = requireCanonicalUint(
    read("expiresAt"),
    48,
    C.CEREMONY_EXPIRES_AT_INVALID
  );
  if (expiresAt === 0n) fail(C.CEREMONY_EXPIRES_AT_ZERO);

  return keccak256(
    abiCoder.encode(
      [...CEREMONY_ABI_TYPES],
      [
        PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_TYPEHASH,
        ceremonyVersion,
        ceremonyId,
        genesisDeploymentIntentHash,
        roleValue,
        credentialGeneration,
        expiresAt
      ]
    )
  ) as Hex;
}

// ---------------------------------------------------------------------------
// Provenance-aware genesis-profile validator
// ---------------------------------------------------------------------------

/**
 * Reads every own key of a caller-owned plain object exactly once into a
 * fresh, prototype-safe (Object.create(null)) snapshot. Because the key set
 * is taken verbatim from `allowedKeys` -- already confirmed by
 * requireExactOwnKeys to be exactly the object's own-key surface -- no
 * further enumeration of the caller's object is needed to build the
 * snapshot, and no key (including "__proto__") can pollute the snapshot's
 * prototype: a null-prototype target has no inherited `__proto__` setter, so
 * assigning key "__proto__" always creates a genuine own data property.
 */
function snapshotExactObject(
  value: unknown,
  allowedKeys: readonly string[],
  notObjectCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  missingCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  extraCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  enumerationCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode,
  readCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): Record<string, unknown> {
  const object = requirePlainObject(value, notObjectCode);
  const verified = requireExactOwnKeys(object, allowedKeys, [], missingCode, extraCode, enumerationCode);
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    snapshot[key] = readValueFromVerifiedDescriptor(object, verified.get(key) as PropertyDescriptor, readCode);
  }
  return Object.freeze(snapshot);
}

/**
 * Guarded exact-three-tuple reader. Never touches a caller-owned tuple's
 * `length` or numeric indices via an ordinary property read: establishes
 * Array-ness safely, enumerates own-key CANDIDATES with a single guarded
 * Reflect.ownKeys call (rejecting any candidate other than "0", "1", "2",
 * and "length" -- enumerable or not, and no symbols), then independently
 * re-verifies every candidate with a guarded Object.getOwnPropertyDescriptor
 * call exactly like `requireExactOwnKeys`: a name reported by `ownKeys` with
 * no genuine own descriptor (a hole, a fabricated name, or a name that only
 * resolves through the prototype) is rejected as missing, not treated as
 * present. `length` and each of the three indices are then read exactly
 * once directly from their verified descriptors (rejecting set-only
 * accessors), never via a fresh `.length` or index lookup that a hostile
 * Proxy could route elsewhere. Every trap or thrown value collapses to the
 * single closed `notTupleCode` for this tuple; the raw value is never
 * retained or exposed.
 */
function requireExactThreeTuple(
  value: unknown,
  notTupleCode: PhilCoreV2ConsumerRecoveryGenesisProtocolErrorCode
): readonly [unknown, unknown, unknown] {
  if (value === null || typeof value !== "object") {
    fail(notTupleCode);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch (error) {
    failWithCause(notTupleCode, error);
  }
  if (!isArray) {
    fail(notTupleCode);
  }

  let keys: readonly (string | symbol)[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    failWithCause(notTupleCode, error);
  }
  const allowed = new Set(["0", "1", "2", "length"]);
  const candidates: string[] = [];
  for (const key of keys) {
    if (typeof key === "symbol") {
      fail(notTupleCode, "unexpected symbol own key on tuple");
    }
    if (!allowed.has(key)) {
      fail(notTupleCode, `unexpected own key on tuple: ${key}`);
    }
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      failWithCause(notTupleCode, error);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }
  for (const required of ["0", "1", "2", "length"]) {
    if (!verified.has(required)) {
      fail(
        notTupleCode,
        `missing own key on tuple (hole, fabricated key, or truncation): ${required}`
      );
    }
  }

  const length = readValueFromVerifiedDescriptor(
    value,
    verified.get("length") as PropertyDescriptor,
    notTupleCode
  );
  if (length !== 3) {
    fail(notTupleCode);
  }

  const slots: unknown[] = [];
  for (const index of ["0", "1", "2"] as const) {
    slots.push(
      readValueFromVerifiedDescriptor(value, verified.get(index) as PropertyDescriptor, notTupleCode)
    );
  }
  return Object.freeze(slots) as readonly [unknown, unknown, unknown];
}

function snapshotFactor(
  value: unknown,
  slot: 0 | 1 | 2
): {
  readonly descriptor: Record<string, unknown>;
  readonly independence: Record<string, unknown>;
  readonly signer: unknown;
} {
  const factor = requirePlainObject(value, C.FACTOR_INPUT_NOT_OBJECT);
  const factorDescriptors = requireExactOwnKeys(
    factor,
    FACTOR_REQUIRED_OWN_KEYS,
    FACTOR_OPTIONAL_OWN_KEYS,
    C.FACTOR_INPUT_NOT_OBJECT,
    C.FACTOR_INPUT_NOT_OBJECT,
    C.FACTOR_INPUT_NOT_OBJECT
  );

  const descriptorRaw = readValueFromVerifiedDescriptor(
    factor,
    factorDescriptors.get("descriptor") as PropertyDescriptor,
    C.FACTOR_DESCRIPTOR_INVALID
  );
  const independenceRaw = readValueFromVerifiedDescriptor(
    factor,
    factorDescriptors.get("independence") as PropertyDescriptor,
    C.FACTOR_INDEPENDENCE_INVALID
  );
  const descriptor = snapshotExactObject(
    descriptorRaw,
    DESCRIPTOR_OWN_KEYS,
    C.FACTOR_DESCRIPTOR_INVALID,
    C.FACTOR_DESCRIPTOR_INVALID,
    C.FACTOR_DESCRIPTOR_INVALID,
    C.FACTOR_DESCRIPTOR_INVALID,
    C.FACTOR_DESCRIPTOR_INVALID
  );
  const independence = snapshotExactObject(
    independenceRaw,
    INDEPENDENCE_OWN_KEYS,
    C.FACTOR_INDEPENDENCE_INVALID,
    C.FACTOR_INDEPENDENCE_INVALID,
    C.FACTOR_INDEPENDENCE_INVALID,
    C.FACTOR_INDEPENDENCE_INVALID,
    C.FACTOR_INDEPENDENCE_INVALID
  );

  let signer: unknown;
  if (factorDescriptors.has("signer")) {
    signer = readValueFromVerifiedDescriptor(
      factor,
      factorDescriptors.get("signer") as PropertyDescriptor,
      C.FACTOR_INPUT_NOT_OBJECT
    );
  }

  return Object.freeze({ descriptor, independence, signer });
}

export function validatePhilCoreV2ConsumerRecoveryGenesisProfile(input: {
  readonly intent: PhilCoreV2LocalGenesisDeploymentIntentInput;
  readonly ceremonies: readonly [
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput,
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput,
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput
  ];
  readonly factors: readonly [
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor
  ];
  readonly executionValidator: string;
}): PhilCoreV2ConsumerRecoveryGenesisProfileResult {
  // 1) Top-level schema/access.
  const top = requirePlainObject(input, C.PROFILE_INPUT_NOT_OBJECT);
  const topDescriptors = requireExactOwnKeys(
    top,
    PROFILE_OWN_KEYS,
    [],
    C.PROFILE_MISSING_OWN_KEY,
    C.PROFILE_EXTRA_OWN_KEY,
    C.PROFILE_ENUMERATION_FAILED
  );
  const PR = C.PROFILE_PROPERTY_READ_FAILED;
  const intentRaw = readValueFromVerifiedDescriptor(top, topDescriptors.get("intent") as PropertyDescriptor, PR);
  const ceremoniesRaw = readValueFromVerifiedDescriptor(
    top,
    topDescriptors.get("ceremonies") as PropertyDescriptor,
    PR
  );
  const factorsRaw = readValueFromVerifiedDescriptor(top, topDescriptors.get("factors") as PropertyDescriptor, PR);
  const executionValidatorRaw = readValueFromVerifiedDescriptor(
    top,
    topDescriptors.get("executionValidator") as PropertyDescriptor,
    PR
  );

  // 2) Tuple shape/access -- guarded exact-three-tuple reads only; no direct
  // .length or index access on caller-owned arrays anywhere in this module.
  const ceremonySlots = requireExactThreeTuple(ceremoniesRaw, C.CEREMONIES_NOT_TUPLE);
  const factorSlots = requireExactThreeTuple(factorsRaw, C.FACTORS_NOT_TUPLE);

  // 3) Intent schema/access: read the caller's intent object exactly once
  // into a plain, prototype-safe snapshot. Every subsequent use (hashing,
  // expiry comparison) operates on that snapshot, never the caller's live
  // object again.
  const intentSnapshot = snapshotExactObject(
    intentRaw,
    INTENT_OWN_KEYS,
    C.INTENT_INPUT_NOT_OBJECT,
    C.INTENT_MISSING_OWN_KEY,
    C.INTENT_EXTRA_OWN_KEY,
    C.INTENT_ENUMERATION_FAILED,
    C.INTENT_PROPERTY_READ_FAILED
  );
  const genesisDeploymentIntentHash = computePhilCoreV2LocalGenesisDeploymentIntentHash(
    intentSnapshot as unknown as PhilCoreV2LocalGenesisDeploymentIntentInput
  );
  const intentExpiresAt = requireCanonicalUint(
    intentSnapshot.expiresAt,
    48,
    C.INTENT_EXPIRES_AT_INVALID
  );

  // 4) Ceremony tuple/schema/access and ceremonies in role order. Each
  // ceremony is read from the caller exactly once into a plain snapshot;
  // every subsequent use operates on that snapshot only.
  const ceremonyHashes: Hex[] = [];
  const ceremonySnapshots: Record<string, unknown>[] = [];
  for (let slot = 0; slot < 3; slot += 1) {
    const ceremonySnapshot = snapshotExactObject(
      ceremonySlots[slot],
      CEREMONY_OWN_KEYS,
      C.CEREMONY_INPUT_NOT_OBJECT,
      C.CEREMONY_MISSING_OWN_KEY,
      C.CEREMONY_EXTRA_OWN_KEY,
      C.CEREMONY_ENUMERATION_FAILED,
      C.CEREMONY_PROPERTY_READ_FAILED
    );
    ceremonySnapshots.push(ceremonySnapshot);
    const ceremonyHash = computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
      ceremonySnapshot as unknown as PhilCoreV2LocalGenesisEnrollmentCeremonyInput
    );
    ceremonyHashes.push(ceremonyHash);

    const role = requireCanonicalUint(ceremonySnapshot.role, 8, C.CEREMONY_ROLE_INVALID);
    if (role !== BigInt(slot)) {
      fail(C.CEREMONY_ROLE_ORDER_INVALID);
    }
    const ceremonyIntentHash = requireBytes32(
      ceremonySnapshot.genesisDeploymentIntentHash,
      C.CEREMONY_INTENT_MISMATCH,
      C.CEREMONY_INTENT_MISMATCH
    );
    if (ceremonyIntentHash !== genesisDeploymentIntentHash) {
      fail(C.CEREMONY_INTENT_MISMATCH);
    }
    const ceremonyExpiresAt = requireCanonicalUint(
      ceremonySnapshot.expiresAt,
      48,
      C.CEREMONY_EXPIRES_AT_INVALID
    );
    if (ceremonyExpiresAt > intentExpiresAt) {
      fail(C.CEREMONY_EXPIRY_EXCEEDS_INTENT);
    }
  }
  const distinctCeremonyIds = new Set(
    ceremonySnapshots.map((snapshot) =>
      requireBytes32(snapshot.ceremonyId, C.CEREMONY_ID_DUPLICATE, C.CEREMONY_ID_DUPLICATE)
    )
  );
  if (distinctCeremonyIds.size !== 3) fail(C.CEREMONY_ID_DUPLICATE);

  // 5) Factor tuple/schema/access and factors in role order.
  const snapshots = [
    snapshotFactor(factorSlots[0], 0),
    snapshotFactor(factorSlots[1], 1),
    snapshotFactor(factorSlots[2], 2)
  ] as const;

  // 6) Cross-record provenance checks.
  for (let slot = 0; slot < 3; slot += 1) {
    const { descriptor, independence } = snapshots[slot];
    const descriptorRole = requireCanonicalUint(
      descriptor.role,
      8,
      C.FACTOR_ROLE_MISMATCH
    );
    const independenceRole = requireCanonicalUint(
      independence.role,
      8,
      C.FACTOR_ROLE_MISMATCH
    );
    if (descriptorRole !== BigInt(slot) || independenceRole !== BigInt(slot)) {
      fail(C.FACTOR_ROLE_MISMATCH);
    }
    const descriptorGeneration = requireCanonicalUint(
      descriptor.credentialGeneration,
      64,
      C.FACTOR_GENERATION_MISMATCH
    );
    const independenceGeneration = requireCanonicalUint(
      independence.credentialGeneration,
      64,
      C.FACTOR_GENERATION_MISMATCH
    );
    if (
      descriptorGeneration !== PINNED_GENESIS_GENERATION ||
      independenceGeneration !== PINNED_GENESIS_GENERATION
    ) {
      fail(C.FACTOR_GENERATION_MISMATCH);
    }
    const enrollmentCeremonyHash = requireBytes32(
      independence.enrollmentCeremonyHash,
      C.FACTOR_CEREMONY_HASH_MISMATCH,
      C.FACTOR_CEREMONY_HASH_MISMATCH
    );
    if (enrollmentCeremonyHash !== ceremonyHashes[slot]) {
      fail(C.FACTOR_CEREMONY_HASH_MISMATCH);
    }
  }

  // 7) Genesis execution-validator provenance: the intent's own
  // initialValidator is the validator the account installs on-chain at
  // genesis, so the profile's separately supplied executionValidator must
  // bind to it exactly. intentSnapshot.initialValidator has already been
  // validated as a nonzero canonical EIP-55 address by the intent-hash
  // computation above, so this single strict-equality comparison against
  // the already single-read executionValidatorRaw also proves
  // executionValidatorRaw has that same canonical valid shape -- no
  // additional caller-owned property read or re-parsing is needed.
  if (executionValidatorRaw !== intentSnapshot.initialValidator) {
    fail(C.EXECUTION_VALIDATOR_INTENT_MISMATCH);
  }

  // 8) Delegated generic-profile validation, plain snapshots only.
  let profile: PhilCoreV2ConsumerRecoveryProfileResult;
  try {
    profile = validatePhilCoreV2ConsumerRecoveryProfile({
      factors: [
        { descriptor: snapshots[0].descriptor, independence: snapshots[0].independence, ...(snapshots[0].signer !== undefined ? { signer: snapshots[0].signer } : {}) },
        { descriptor: snapshots[1].descriptor, independence: snapshots[1].independence, ...(snapshots[1].signer !== undefined ? { signer: snapshots[1].signer } : {}) },
        { descriptor: snapshots[2].descriptor, independence: snapshots[2].independence, ...(snapshots[2].signer !== undefined ? { signer: snapshots[2].signer } : {}) }
      ] as unknown as [
        PhilCoreV2ConsumerRecoveryFactor,
        PhilCoreV2ConsumerRecoveryFactor,
        PhilCoreV2ConsumerRecoveryFactor
      ],
      executionValidator: executionValidatorRaw as string
    });
  } catch (error) {
    failWithCause(C.GENERIC_PROFILE_VALIDATION_FAILED, error);
  }

  return Object.freeze({
    genesisDeploymentIntentHash,
    genesisEnrollmentCeremonyHashes: Object.freeze([
      ceremonyHashes[0],
      ceremonyHashes[1],
      ceremonyHashes[2]
    ]) as readonly [Hex, Hex, Hex],
    profile
  });
}
