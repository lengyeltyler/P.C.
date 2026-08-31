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
const UINT48_MAX = (1n << 48n) - 1n;

export const PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS = 300n;

export const PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID =
  PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID;
export const PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID =
  PHILCORE_V2_LOCAL_SECURITY_MODEL_ID;
export const PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID =
  PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID;

export const PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE = Object.freeze({
  CEREMONY_ALREADY_ACTIVE: "CEREMONY_ALREADY_ACTIVE",
  CEREMONY_NOT_ACTIVE: "CEREMONY_NOT_ACTIVE",
  CLOCK_REGRESSION_DETECTED: "CLOCK_REGRESSION_DETECTED",
  INVALID_INJECTED_CEREMONY_ID: "INVALID_INJECTED_CEREMONY_ID",
  INVALID_EXPECTED_CONTEXT: "INVALID_EXPECTED_CONTEXT",
  INVALID_NOW: "INVALID_NOW",
  EXPIRY_OVERFLOW: "EXPIRY_OVERFLOW",
  INVALID_RECORD: "INVALID_RECORD",
  CEREMONY_PENDING_RETIREMENT: "CEREMONY_PENDING_RETIREMENT",
  RETIREMENT_CEREMONY_ID_INVALID: "RETIREMENT_CEREMONY_ID_INVALID",
  CEREMONY_NOT_INSTALLED: "CEREMONY_NOT_INSTALLED",
  CEREMONY_STILL_ACTIVE: "CEREMONY_STILL_ACTIVE",
  CEREMONY_ID_MISMATCH: "CEREMONY_ID_MISMATCH"
} as const);

export type PhilCoreV2ConsumerRecoveryCeremonyErrorCode =
  typeof PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE[
    keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE
  ];

export class PhilCoreV2ConsumerRecoveryCeremonyLifecycleError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryCeremonyErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryCeremonyErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryCeremonyLifecycleError";
    this.code = code;
  }
}

export type PhilCoreV2ConsumerRecoveryCeremonyState = "ACTIVE" | "ENDED";
export type PhilCoreV2ConsumerRecoveryCeremonyEndReason =
  | null
  | "CANCELLED"
  | "EXPIRED";

export type PhilCoreV2ConsumerRecoveryCeremonyRecord = {
  readonly state: PhilCoreV2ConsumerRecoveryCeremonyState;
  readonly endReason: PhilCoreV2ConsumerRecoveryCeremonyEndReason;
  readonly ceremonyId: Hex;
  readonly mintedAtUnixSeconds: bigint;
  readonly expiresAtUnixSeconds: bigint;
  readonly lastObservedAtUnixSeconds: bigint;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly recoveryDomainId: Hex;
  readonly account: string;
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly expectedRecoveryEpoch: bigint;
  readonly expectedValidatorEpoch: bigint;
  readonly enrollmentCeremonyHash: Hex;
};

export type PhilCoreV2ConsumerRecoveryCeremonyExpectations = {
  readonly account: string;
  readonly chainId: bigint | string;
  readonly entryPoint: string;
  readonly expectedRecoveryEpoch: bigint | string;
  readonly expectedValidatorEpoch: bigint | string;
};

const EXPECTATION_KEYS = Object.freeze([
  "account",
  "chainId",
  "entryPoint",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch"
] as const);

function fail(
  code: PhilCoreV2ConsumerRecoveryCeremonyErrorCode,
  message?: string
): never {
  throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(code, message);
}

function freezeRecord(
  record: PhilCoreV2ConsumerRecoveryCeremonyRecord
): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  return Object.freeze({ ...record });
}

function requirePositiveSafeIntegerNow(value: unknown): bigint {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value <= 0
  ) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_NOW);
  }
  return BigInt(value);
}

function assertNoClockRegression(
  now: bigint,
  lastObservedAtUnixSeconds: bigint
): void {
  if (now < lastObservedAtUnixSeconds) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CLOCK_REGRESSION_DETECTED);
  }
}

function requireCeremonyId(value: unknown): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_INJECTED_CEREMONY_ID);
  }
  const normalized = value.toLowerCase() as Hex;
  if (normalized === ZERO_BYTES32) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_INJECTED_CEREMONY_ID);
  }
  return normalized;
}

function requireCanonicalUint(
  value: unknown,
  bits: number
): bigint {
  if (typeof value === "number") {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  let asString: string;
  if (typeof value === "bigint") {
    if (value < 0n) {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
    }
    asString = value.toString(10);
  } else if (typeof value === "string") {
    if (!CANONICAL_UINT_STRING.test(value)) {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
    }
    asString = value;
  } else {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  let parsed: bigint;
  try {
    parsed = BigInt(asString);
  } catch {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  if (parsed < 0n || parsed >= 1n << BigInt(bits)) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  return parsed;
}

function requireNonZeroAddress(value: unknown): string {
  if (typeof value !== "string") {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  if (normalized === ZERO_ADDRESS) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  return normalized;
}

function normalizeExpectations(
  value: unknown
): {
  account: string;
  chainId: bigint;
  entryPoint: string;
  expectedRecoveryEpoch: bigint;
  expectedValidatorEpoch: bigint;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set<string>(EXPECTATION_KEYS);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
    }
  }
  for (const key of EXPECTATION_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
    }
  }

  const account = requireNonZeroAddress(input.account);
  const chainId = requireCanonicalUint(input.chainId, 256);
  if (chainId === 0n) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  const entryPoint = requireNonZeroAddress(input.entryPoint);
  const expectedRecoveryEpoch = requireCanonicalUint(
    input.expectedRecoveryEpoch,
    64
  );
  if (expectedRecoveryEpoch === 0n) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }
  const expectedValidatorEpoch = requireCanonicalUint(
    input.expectedValidatorEpoch,
    64
  );
  if (expectedValidatorEpoch === 0n) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_EXPECTED_CONTEXT);
  }

  return {
    account,
    chainId,
    entryPoint,
    expectedRecoveryEpoch,
    expectedValidatorEpoch
  };
}

/**
 * Normalize and validate main-caller ceremony expectations.
 * Exported so the host can reject malformed context before consuming randomness.
 */
export function normalizePhilCoreV2ConsumerRecoveryCeremonyExpectations(
  value: unknown
): {
  account: string;
  chainId: bigint;
  entryPoint: string;
  expectedRecoveryEpoch: bigint;
  expectedValidatorEpoch: bigint;
} {
  return normalizeExpectations(value);
}

function requireRecord(
  value: unknown
): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_RECORD);
  }
  return value as PhilCoreV2ConsumerRecoveryCeremonyRecord;
}

function buildActiveRecord(input: {
  ceremonyId: Hex;
  now: bigint;
  expectations: ReturnType<typeof normalizeExpectations>;
}): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  if (input.now > UINT48_MAX - PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS) {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.EXPIRY_OVERFLOW);
  }
  const expiresAtUnixSeconds =
    input.now + PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS;
  const enrollmentCeremonyHash = computePhilCoreV2LocalEnrollmentCeremonyHash({
    ceremonyId: input.ceremonyId,
    account: input.expectations.account,
    chainId: input.expectations.chainId,
    entryPoint: input.expectations.entryPoint,
    accountVersionId: PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID,
    expectedRecoveryEpoch: input.expectations.expectedRecoveryEpoch,
    expectedValidatorEpoch: input.expectations.expectedValidatorEpoch,
    expiresAt: expiresAtUnixSeconds
  });

  return freezeRecord({
    state: "ACTIVE",
    endReason: null,
    ceremonyId: input.ceremonyId,
    mintedAtUnixSeconds: input.now,
    expiresAtUnixSeconds,
    lastObservedAtUnixSeconds: input.now,
    accountVersionId: PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID,
    account: input.expectations.account,
    chainId: input.expectations.chainId,
    entryPoint: input.expectations.entryPoint,
    expectedRecoveryEpoch: input.expectations.expectedRecoveryEpoch,
    expectedValidatorEpoch: input.expectations.expectedValidatorEpoch,
    enrollmentCeremonyHash
  });
}

function withObservation(
  record: PhilCoreV2ConsumerRecoveryCeremonyRecord,
  now: bigint,
  patch: Partial<PhilCoreV2ConsumerRecoveryCeremonyRecord> = {}
): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  return freezeRecord({
    ...record,
    ...patch,
    lastObservedAtUnixSeconds: now
  });
}

function expireIfNeeded(
  record: PhilCoreV2ConsumerRecoveryCeremonyRecord,
  now: bigint
): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  if (record.state !== "ACTIVE") {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_NOT_ACTIVE);
  }
  assertNoClockRegression(now, record.lastObservedAtUnixSeconds);
  if (now >= record.expiresAtUnixSeconds) {
    return withObservation(record, now, {
      state: "ENDED",
      endReason: "EXPIRED"
    });
  }
  return withObservation(record, now);
}

/**
 * Mint a new ACTIVE ceremony only from an absent slot.
 * Installed ACTIVE rejects with CEREMONY_ALREADY_ACTIVE.
 * Installed ENDED rejects with CEREMONY_PENDING_RETIREMENT.
 * Callers must retire terminal records before minting again.
 */
export function mintPhilCoreV2ConsumerRecoveryCeremony(input: {
  readonly current: PhilCoreV2ConsumerRecoveryCeremonyRecord | null;
  readonly ceremonyId: string;
  readonly nowUnixSeconds: number;
  readonly expectations: PhilCoreV2ConsumerRecoveryCeremonyExpectations;
}): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  if (input.current !== null) {
    const current = requireRecord(input.current);
    if (current.state === "ACTIVE") {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_ALREADY_ACTIVE);
    }
    if (current.state === "ENDED") {
      fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_PENDING_RETIREMENT);
    }
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_RECORD);
  }

  const now = requirePositiveSafeIntegerNow(input.nowUnixSeconds);
  const ceremonyId = requireCeremonyId(input.ceremonyId);
  const expectations = normalizeExpectations(input.expectations);
  return buildActiveRecord({ ceremonyId, now, expectations });
}

export function cancelPhilCoreV2ConsumerRecoveryCeremony(input: {
  readonly current: PhilCoreV2ConsumerRecoveryCeremonyRecord;
  readonly nowUnixSeconds: number;
}): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  const now = requirePositiveSafeIntegerNow(input.nowUnixSeconds);
  const current = requireRecord(input.current);
  if (current.state !== "ACTIVE") {
    fail(PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_NOT_ACTIVE);
  }
  assertNoClockRegression(now, current.lastObservedAtUnixSeconds);
  if (now >= current.expiresAtUnixSeconds) {
    return withObservation(current, now, {
      state: "ENDED",
      endReason: "EXPIRED"
    });
  }
  return withObservation(current, now, {
    state: "ENDED",
    endReason: "CANCELLED"
  });
}

export function checkPhilCoreV2ConsumerRecoveryCeremonyExpiry(input: {
  readonly current: PhilCoreV2ConsumerRecoveryCeremonyRecord;
  readonly nowUnixSeconds: number;
}): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  const now = requirePositiveSafeIntegerNow(input.nowUnixSeconds);
  const current = requireRecord(input.current);
  return expireIfNeeded(current, now);
}

/**
 * Status evaluation: ACTIVE may lazily expire; ENDED only advances lastObserved.
 * Clock regression for ACTIVE is enforced inside expireIfNeeded.
 */
export function evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus(input: {
  readonly current: PhilCoreV2ConsumerRecoveryCeremonyRecord;
  readonly nowUnixSeconds: number;
}): PhilCoreV2ConsumerRecoveryCeremonyRecord {
  const now = requirePositiveSafeIntegerNow(input.nowUnixSeconds);
  const current = requireRecord(input.current);
  if (current.state === "ACTIVE") {
    return expireIfNeeded(current, now);
  }
  assertNoClockRegression(now, current.lastObservedAtUnixSeconds);
  return withObservation(current, now);
}
