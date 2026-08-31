import {
  AbiCoder,
  Signature,
  getAddress,
  isHexString,
  keccak256,
  recoverAddress,
  toUtf8Bytes
} from "ethers";

import type { Hex } from "./hashes.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "./v2Intent.ts";
import {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID
} from "./v2ConsumerRecovery.ts";
import {
  PHILCORE_O37_2_SECP256K1_HALF_ORDER,
  PHILCORE_O37_2_SECP256K1_ORDER
} from "./v2DeterministicFixtures.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const CANONICAL_UINT_STRING = /^(0|[1-9][0-9]*)$/;

export const PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_LITERAL =
  "PhilCoreV2LocalEnrollmentCeremony(bytes32 ceremonyId,address account,uint256 chainId,address entryPoint,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint64 expectedRecoveryEpoch,uint64 expectedValidatorEpoch,uint48 expiresAt)" as const;

export const PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_LITERAL =
  "PhilCoreV2LocalRole2CeremonyProof(uint8 proofVersion,bytes32 enrollmentCeremonyHash,bytes32 independenceBindingHash,bytes32 factorCommitment,uint64 credentialGeneration,address account,uint256 chainId,address entryPoint,address signer)" as const;

export const PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH = keccak256(
  toUtf8Bytes(PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_LITERAL)
) as Hex;

export const PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_TYPEHASH = keccak256(
  toUtf8Bytes(PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_LITERAL)
) as Hex;

export const PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_ABI_TYPES = Object.freeze([
  "bytes32",
  "bytes32",
  "address",
  "uint256",
  "address",
  "bytes32",
  "bytes32",
  "bytes32",
  "uint64",
  "uint64",
  "uint48"
] as const);

export const PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_ABI_TYPES = Object.freeze([
  "bytes32",
  "uint8",
  "bytes32",
  "bytes32",
  "bytes32",
  "uint64",
  "address",
  "uint256",
  "address",
  "address"
] as const);

export const PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID =
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID;
export const PHILCORE_V2_LOCAL_SECURITY_MODEL_ID =
  PHILCORE_V2_SECURITY_MODEL_ID;
export const PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID =
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID;
export const PHILCORE_V2_LOCAL_ROLE2_PROOF_VERSION = 1 as const;

export const PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE = Object.freeze({
  INPUT_NOT_OBJECT: "INPUT_NOT_OBJECT",
  EXTRA_OWN_KEY: "EXTRA_OWN_KEY",
  MISSING_OWN_KEY: "MISSING_OWN_KEY",
  BYTES32_INVALID: "BYTES32_INVALID",
  BYTES32_ZERO: "BYTES32_ZERO",
  ADDRESS_INVALID: "ADDRESS_INVALID",
  ADDRESS_ZERO: "ADDRESS_ZERO",
  INTEGER_NUMBER_REJECTED: "INTEGER_NUMBER_REJECTED",
  INTEGER_SYNTAX_INVALID: "INTEGER_SYNTAX_INVALID",
  INTEGER_TYPE_INVALID: "INTEGER_TYPE_INVALID",
  UINT_OUT_OF_RANGE: "UINT_OUT_OF_RANGE",
  CHAIN_ID_ZERO: "CHAIN_ID_ZERO",
  EXPECTED_RECOVERY_EPOCH_ZERO: "EXPECTED_RECOVERY_EPOCH_ZERO",
  EXPECTED_VALIDATOR_EPOCH_ZERO: "EXPECTED_VALIDATOR_EPOCH_ZERO",
  EXPIRES_AT_ZERO: "EXPIRES_AT_ZERO",
  CREDENTIAL_GENERATION_ZERO: "CREDENTIAL_GENERATION_ZERO",
  ACCOUNT_VERSION_ID_MISMATCH: "ACCOUNT_VERSION_ID_MISMATCH",
  SECURITY_MODEL_ID_MISMATCH: "SECURITY_MODEL_ID_MISMATCH",
  RECOVERY_DOMAIN_ID_MISMATCH: "RECOVERY_DOMAIN_ID_MISMATCH",
  PROOF_VERSION_MISMATCH: "PROOF_VERSION_MISMATCH",
  DIGEST_SHAPE_INVALID: "DIGEST_SHAPE_INVALID",
  SIGNATURE_SHAPE_INVALID: "SIGNATURE_SHAPE_INVALID",
  SIGNATURE_R_INVALID: "SIGNATURE_R_INVALID",
  SIGNATURE_S_INVALID: "SIGNATURE_S_INVALID",
  SIGNATURE_V_INVALID: "SIGNATURE_V_INVALID",
  SIGNATURE_R_OUT_OF_RANGE: "SIGNATURE_R_OUT_OF_RANGE",
  SIGNATURE_S_OUT_OF_RANGE: "SIGNATURE_S_OUT_OF_RANGE",
  SIGNATURE_HIGH_S: "SIGNATURE_HIGH_S",
  SIGNATURE_RECOVERY_FAILED: "SIGNATURE_RECOVERY_FAILED"
} as const);

export type PhilCoreV2LocalCeremonyErrorCode =
  typeof PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE[
    keyof typeof PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE
  ];

export class PhilCoreV2LocalCeremonyProtocolError extends Error {
  readonly code: PhilCoreV2LocalCeremonyErrorCode;

  constructor(code: PhilCoreV2LocalCeremonyErrorCode, message?: string) {
    super(message ?? code);
    this.name = "PhilCoreV2LocalCeremonyProtocolError";
    this.code = code;
  }
}

export type PhilCoreV2LocalEnrollmentCeremonyInput = {
  readonly ceremonyId: string;
  readonly account: string;
  readonly chainId: bigint | string;
  readonly entryPoint: string;
  readonly accountVersionId: string;
  readonly securityModelId: string;
  readonly recoveryDomainId: string;
  readonly expectedRecoveryEpoch: bigint | string;
  readonly expectedValidatorEpoch: bigint | string;
  readonly expiresAt: bigint | string;
};

export type PhilCoreV2LocalRole2CeremonyProofInput = {
  readonly proofVersion: bigint | string;
  readonly enrollmentCeremonyHash: string;
  readonly independenceBindingHash: string;
  readonly factorCommitment: string;
  readonly credentialGeneration: bigint | string;
  readonly account: string;
  readonly chainId: bigint | string;
  readonly entryPoint: string;
  readonly signer: string;
};

export type PhilCoreV2LocalSecp256k1Signature = {
  readonly r: string;
  readonly s: string;
  readonly v: number;
};

const ENROLLMENT_OWN_KEYS = Object.freeze([
  "ceremonyId",
  "account",
  "chainId",
  "entryPoint",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch",
  "expiresAt"
] as const);

const PROOF_OWN_KEYS = Object.freeze([
  "proofVersion",
  "enrollmentCeremonyHash",
  "independenceBindingHash",
  "factorCommitment",
  "credentialGeneration",
  "account",
  "chainId",
  "entryPoint",
  "signer"
] as const);

const SIGNATURE_OWN_KEYS = Object.freeze(["r", "s", "v"] as const);

function fail(
  code: PhilCoreV2LocalCeremonyErrorCode,
  message?: string
): never {
  throw new PhilCoreV2LocalCeremonyProtocolError(code, message);
}

function requirePlainObject(
  value: unknown,
  code: PhilCoreV2LocalCeremonyErrorCode = PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INPUT_NOT_OBJECT
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code);
  }
  return value as Record<string, unknown>;
}

function requireExactOwnKeys(
  value: Record<string, unknown>,
  allowedKeys: readonly string[],
  missingCode: PhilCoreV2LocalCeremonyErrorCode,
  extraCode: PhilCoreV2LocalCeremonyErrorCode
): void {
  const allowed = new Set<string>(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(extraCode, `unexpected own key: ${key}`);
  }
  for (const key of allowedKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      fail(missingCode, `missing own key: ${key}`);
    }
  }
}

function requireBytes32(
  value: unknown,
  options: { allowZero?: boolean } = {}
): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.BYTES32_INVALID);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!options.allowZero && normalized === ZERO_BYTES32) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.BYTES32_ZERO);
  }
  return normalized;
}

function requireNonZeroAddress(value: unknown): string {
  if (typeof value !== "string") {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.ADDRESS_INVALID);
  }
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.ADDRESS_INVALID);
  }
  if (normalized === ZERO_ADDRESS) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.ADDRESS_ZERO);
  }
  return normalized;
}

function requireCanonicalUint(
  value: unknown,
  bits: number
): bigint {
  if (typeof value === "number") {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INTEGER_NUMBER_REJECTED);
  }
  let asString: string;
  if (typeof value === "bigint") {
    if (value < 0n) {
      fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INTEGER_SYNTAX_INVALID);
    }
    asString = value.toString(10);
  } else if (typeof value === "string") {
    if (!CANONICAL_UINT_STRING.test(value)) {
      fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INTEGER_SYNTAX_INVALID);
    }
    asString = value;
  } else {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INTEGER_TYPE_INVALID);
  }

  let parsed: bigint;
  try {
    parsed = BigInt(asString);
  } catch {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.INTEGER_SYNTAX_INVALID);
  }
  if (parsed < 0n || parsed >= 1n << BigInt(bits)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.UINT_OUT_OF_RANGE);
  }
  return parsed;
}

function requirePinnedBytes32(
  value: unknown,
  expected: Hex,
  mismatchCode: PhilCoreV2LocalCeremonyErrorCode
): Hex {
  const normalized = requireBytes32(value, { allowZero: true });
  if (normalized !== expected.toLowerCase()) {
    fail(mismatchCode);
  }
  return normalized;
}

/**
 * Raw keccak256(abi.encode(...)) enrollment ceremony hash.
 * No EIP-191 / EIP-712 wrapping.
 */
export function computePhilCoreV2LocalEnrollmentCeremonyHash(
  input: PhilCoreV2LocalEnrollmentCeremonyInput | Record<string, unknown>
): Hex {
  const value = requirePlainObject(input);
  requireExactOwnKeys(
    value,
    ENROLLMENT_OWN_KEYS,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.MISSING_OWN_KEY,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.EXTRA_OWN_KEY
  );

  const ceremonyId = requireBytes32(value.ceremonyId);
  const account = requireNonZeroAddress(value.account);
  const chainId = requireCanonicalUint(value.chainId, 256);
  if (chainId === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.CHAIN_ID_ZERO);
  }
  const entryPoint = requireNonZeroAddress(value.entryPoint);
  const accountVersionId = requirePinnedBytes32(
    value.accountVersionId,
    PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.ACCOUNT_VERSION_ID_MISMATCH
  );
  const securityModelId = requirePinnedBytes32(
    value.securityModelId,
    PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SECURITY_MODEL_ID_MISMATCH
  );
  const recoveryDomainId = requirePinnedBytes32(
    value.recoveryDomainId,
    PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.RECOVERY_DOMAIN_ID_MISMATCH
  );
  const expectedRecoveryEpoch = requireCanonicalUint(
    value.expectedRecoveryEpoch,
    64
  );
  if (expectedRecoveryEpoch === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.EXPECTED_RECOVERY_EPOCH_ZERO);
  }
  const expectedValidatorEpoch = requireCanonicalUint(
    value.expectedValidatorEpoch,
    64
  );
  if (expectedValidatorEpoch === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.EXPECTED_VALIDATOR_EPOCH_ZERO);
  }
  const expiresAt = requireCanonicalUint(value.expiresAt, 48);
  if (expiresAt === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.EXPIRES_AT_ZERO);
  }

  return keccak256(
    abiCoder.encode(
      [...PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_ABI_TYPES],
      [
        PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH,
        ceremonyId,
        account,
        chainId,
        entryPoint,
        accountVersionId,
        securityModelId,
        recoveryDomainId,
        expectedRecoveryEpoch,
        expectedValidatorEpoch,
        expiresAt
      ]
    )
  ) as Hex;
}

/**
 * Raw keccak256(abi.encode(...)) Role 2 ceremony proof digest.
 * No EIP-191 / EIP-712 wrapping.
 */
export function computePhilCoreV2LocalRole2CeremonyProofDigest(
  input: PhilCoreV2LocalRole2CeremonyProofInput | Record<string, unknown>
): Hex {
  const value = requirePlainObject(input);
  requireExactOwnKeys(
    value,
    PROOF_OWN_KEYS,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.MISSING_OWN_KEY,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.EXTRA_OWN_KEY
  );

  const proofVersion = requireCanonicalUint(value.proofVersion, 8);
  if (proofVersion !== BigInt(PHILCORE_V2_LOCAL_ROLE2_PROOF_VERSION)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.PROOF_VERSION_MISMATCH);
  }
  const enrollmentCeremonyHash = requireBytes32(value.enrollmentCeremonyHash);
  const independenceBindingHash = requireBytes32(value.independenceBindingHash);
  const factorCommitment = requireBytes32(value.factorCommitment);
  const credentialGeneration = requireCanonicalUint(
    value.credentialGeneration,
    64
  );
  if (credentialGeneration === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.CREDENTIAL_GENERATION_ZERO);
  }
  const account = requireNonZeroAddress(value.account);
  const chainId = requireCanonicalUint(value.chainId, 256);
  if (chainId === 0n) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.CHAIN_ID_ZERO);
  }
  const entryPoint = requireNonZeroAddress(value.entryPoint);
  const signer = requireNonZeroAddress(value.signer);

  return keccak256(
    abiCoder.encode(
      [...PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_ABI_TYPES],
      [
        PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_TYPEHASH,
        proofVersion,
        enrollmentCeremonyHash,
        independenceBindingHash,
        factorCommitment,
        credentialGeneration,
        account,
        chainId,
        entryPoint,
        signer
      ]
    )
  ) as Hex;
}

/**
 * Generic low-S secp256k1 public recovery. Returns checksummed address only.
 * Does not accept or compare an expected signer.
 */
export function recoverCanonicalSecp256k1Signer(
  digest: unknown,
  signature: PhilCoreV2LocalSecp256k1Signature | Record<string, unknown>
): string {
  if (typeof digest !== "string" || !isHexString(digest, 32)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.DIGEST_SHAPE_INVALID);
  }
  const normalizedDigest = digest.toLowerCase() as Hex;

  const value = requirePlainObject(
    signature,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_SHAPE_INVALID
  );
  requireExactOwnKeys(
    value,
    SIGNATURE_OWN_KEYS,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_SHAPE_INVALID,
    PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_SHAPE_INVALID
  );

  if (typeof value.r !== "string" || !isHexString(value.r, 32)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_R_INVALID);
  }
  if (typeof value.s !== "string" || !isHexString(value.s, 32)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_S_INVALID);
  }
  if (typeof value.v !== "number" || !(value.v === 27 || value.v === 28)) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_V_INVALID);
  }

  const r = BigInt(value.r.toLowerCase());
  const s = BigInt(value.s.toLowerCase());
  if (r <= 0n || r >= PHILCORE_O37_2_SECP256K1_ORDER) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_R_OUT_OF_RANGE);
  }
  if (s <= 0n || s >= PHILCORE_O37_2_SECP256K1_ORDER) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_S_OUT_OF_RANGE);
  }
  if (s > PHILCORE_O37_2_SECP256K1_HALF_ORDER) {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_HIGH_S);
  }

  try {
    return recoverAddress(
      normalizedDigest,
      Signature.from({
        r: value.r,
        s: value.s,
        v: value.v
      })
    );
  } catch {
    fail(PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE.SIGNATURE_RECOVERY_FAILED);
  }
}
