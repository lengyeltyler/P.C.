import {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_AUTHORIZATION_ENVELOPE_V1_LABEL =
  "PHIL_AUTHORIZATION_ENVELOPE_V1" as const;
export const PHIL_AUTHORIZATION_ENVELOPE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_AUTHORIZATION_ENVELOPE_V1_LABEL)
) as Hex;
export const PHIL_ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;

export type PhilAuthorizationOperationClassV1 = 1 | 2 | 3;

export interface PhilAuthorizationEnvelopeV1 {
  readonly formatVersionHash: Hex;
  readonly operationClass: PhilAuthorizationOperationClassV1;
  readonly scopedOwnerCommitment: Hex;
  readonly scopeId: Hex;
  readonly scopeInstance: Hex;
  readonly scopeEpoch: string;
  readonly principalIdHash: Hex;
  readonly capabilityId: Hex;
  readonly capabilityEpoch: string;
  readonly networkIdHash: Hex;
  readonly accountBindingHash: Hex;
  readonly adapterId: Hex;
  readonly actionTypeHash: Hex;
  readonly parametersHash: Hex;
  readonly intentDigest: Hex;
  readonly policyHash: Hex;
  readonly nonceDomain: Hex;
  readonly nonce: string;
  readonly rootProofNullifier: Hex;
  readonly validAfter: string;
  readonly validUntil: string;
  readonly valueLimit: string;
  readonly feeLimit: string;
  readonly deviceEpoch: string;
  readonly recoveryEpoch: string;
  readonly validatorEpoch: string;
  readonly deviceSignatureSuiteId: Hex;
  readonly proofDescriptorHash: Hex;
  readonly humanPresentationHash: Hex;
}

export class PhilAuthorizationEnvelopeV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilAuthorizationEnvelopeV1Error";
    this.code = code;
  }
}

function normalizeBytes32(value: BytesLike, label: string): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_INVALID_BYTES32",
      `${label} must be bytes32`
    );
  }
  if (getBytes(normalized).length !== 32) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_INVALID_BYTES32",
      `${label} must be bytes32`
    );
  }
  return normalized;
}

function requireNonZeroBytes32(value: BytesLike, label: string): Hex {
  const normalized = normalizeBytes32(value, label);
  if (normalized === PHIL_ZERO_BYTES32) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_ZERO_BYTES32",
      `${label} must be non-zero`
    );
  }
  return normalized;
}

function normalizeUnsigned(
  value: string | number | bigint,
  bits: 64 | 256,
  label: string
): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new Error("unsafe number");
    }
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new Error("non-canonical decimal");
    }
    parsed = BigInt(value);
  } catch {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_INVALID_UNSIGNED",
      `${label} must be a canonical uint${bits} decimal`
    );
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_INVALID_UNSIGNED",
      `${label} must fit uint${bits}`
    );
  }
  return parsed.toString(10);
}

function requirePositiveUInt64(
  value: string | number | bigint,
  label: string
): string {
  const normalized = normalizeUnsigned(value, 64, label);
  if (normalized === "0") {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_ZERO_EPOCH",
      `${label} must be non-zero`
    );
  }
  return normalized;
}

function normalizeOperationClass(value: number): PhilAuthorizationOperationClassV1 {
  if (value === 1 || value === 2 || value === 3) return value;
  throw new PhilAuthorizationEnvelopeV1Error(
    "PHIL_AUTHORIZATION_ENVELOPE_OPERATION_CLASS_UNSUPPORTED",
    "operationClass must be 1, 2, or 3"
  );
}

function normalizeEnvelope(
  input: Omit<PhilAuthorizationEnvelopeV1, "formatVersionHash"> & {
    readonly formatVersionHash?: BytesLike;
    readonly scopeEpoch: string | number | bigint;
    readonly capabilityEpoch: string | number | bigint;
    readonly nonce: string | number | bigint;
    readonly validAfter: string | number | bigint;
    readonly validUntil: string | number | bigint;
    readonly valueLimit: string | number | bigint;
    readonly feeLimit: string | number | bigint;
    readonly deviceEpoch: string | number | bigint;
    readonly recoveryEpoch: string | number | bigint;
    readonly validatorEpoch: string | number | bigint;
  },
  allowPendingExceptionalNullifier: boolean
): PhilAuthorizationEnvelopeV1 {
  const formatVersionHash = normalizeBytes32(
    input.formatVersionHash ?? PHIL_AUTHORIZATION_ENVELOPE_V1_HASH,
    "formatVersionHash"
  );
  if (formatVersionHash !== PHIL_AUTHORIZATION_ENVELOPE_V1_HASH) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_FORMAT_UNSUPPORTED",
      "formatVersionHash is unsupported"
    );
  }

  const operationClass = normalizeOperationClass(input.operationClass);
  const capabilityId = normalizeBytes32(input.capabilityId, "capabilityId");
  const rootProofNullifier = normalizeBytes32(
    input.rootProofNullifier,
    "rootProofNullifier"
  );
  const proofDescriptorHash = normalizeBytes32(
    input.proofDescriptorHash,
    "proofDescriptorHash"
  );

  if (operationClass === 1) {
    if (capabilityId === PHIL_ZERO_BYTES32) {
      throw new PhilAuthorizationEnvelopeV1Error(
        "PHIL_AUTHORIZATION_ENVELOPE_CAPABILITY_REQUIRED",
        "routine actions require capabilityId"
      );
    }
    if (rootProofNullifier !== PHIL_ZERO_BYTES32
      || proofDescriptorHash !== PHIL_ZERO_BYTES32) {
      throw new PhilAuthorizationEnvelopeV1Error(
        "PHIL_AUTHORIZATION_ENVELOPE_ROUTINE_PROOF_FORBIDDEN",
        "routine actions must not carry root-proof fields"
      );
    }
  } else if (capabilityId !== PHIL_ZERO_BYTES32) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_CAPABILITY_FORBIDDEN",
      "exceptional and recovery actions require zero capabilityId"
    );
  }

  if (operationClass === 2) {
    if ((!allowPendingExceptionalNullifier && rootProofNullifier === PHIL_ZERO_BYTES32)
      || proofDescriptorHash === PHIL_ZERO_BYTES32) {
      throw new PhilAuthorizationEnvelopeV1Error(
        "PHIL_AUTHORIZATION_ENVELOPE_EXCEPTIONAL_PROOF_REQUIRED",
        "exceptional actions require proofDescriptorHash and a finalized rootProofNullifier"
      );
    }
  } else if (rootProofNullifier !== PHIL_ZERO_BYTES32
    || proofDescriptorHash !== PHIL_ZERO_BYTES32) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_PROOF_FIELDS_FORBIDDEN",
      "non-exceptional actions must not carry root-proof fields"
    );
  }

  const validAfter = normalizeUnsigned(input.validAfter, 64, "validAfter");
  const validUntil = normalizeUnsigned(input.validUntil, 64, "validUntil");
  if (validUntil === "0" || BigInt(validUntil) < BigInt(validAfter)) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_VALIDITY_INVALID",
      "validUntil must be non-zero and greater than or equal to validAfter"
    );
  }

  const deviceSignatureSuiteId = normalizeBytes32(
    input.deviceSignatureSuiteId,
    "deviceSignatureSuiteId"
  );
  if ((operationClass === 1 || operationClass === 2)
    && deviceSignatureSuiteId === PHIL_ZERO_BYTES32) {
    throw new PhilAuthorizationEnvelopeV1Error(
      "PHIL_AUTHORIZATION_ENVELOPE_DEVICE_SUITE_REQUIRED",
      "routine and exceptional actions require deviceSignatureSuiteId"
    );
  }

  return Object.freeze({
    formatVersionHash,
    operationClass,
    scopedOwnerCommitment: requireNonZeroBytes32(
      input.scopedOwnerCommitment,
      "scopedOwnerCommitment"
    ),
    scopeId: requireNonZeroBytes32(input.scopeId, "scopeId"),
    scopeInstance: requireNonZeroBytes32(input.scopeInstance, "scopeInstance"),
    scopeEpoch: requirePositiveUInt64(input.scopeEpoch, "scopeEpoch"),
    principalIdHash: requireNonZeroBytes32(input.principalIdHash, "principalIdHash"),
    capabilityId,
    capabilityEpoch: requirePositiveUInt64(input.capabilityEpoch, "capabilityEpoch"),
    networkIdHash: requireNonZeroBytes32(input.networkIdHash, "networkIdHash"),
    accountBindingHash: requireNonZeroBytes32(
      input.accountBindingHash,
      "accountBindingHash"
    ),
    adapterId: requireNonZeroBytes32(input.adapterId, "adapterId"),
    actionTypeHash: requireNonZeroBytes32(input.actionTypeHash, "actionTypeHash"),
    parametersHash: requireNonZeroBytes32(input.parametersHash, "parametersHash"),
    intentDigest: requireNonZeroBytes32(input.intentDigest, "intentDigest"),
    policyHash: requireNonZeroBytes32(input.policyHash, "policyHash"),
    nonceDomain: requireNonZeroBytes32(input.nonceDomain, "nonceDomain"),
    nonce: normalizeUnsigned(input.nonce, 256, "nonce"),
    rootProofNullifier,
    validAfter,
    validUntil,
    valueLimit: normalizeUnsigned(input.valueLimit, 256, "valueLimit"),
    feeLimit: normalizeUnsigned(input.feeLimit, 256, "feeLimit"),
    deviceEpoch: requirePositiveUInt64(input.deviceEpoch, "deviceEpoch"),
    recoveryEpoch: requirePositiveUInt64(input.recoveryEpoch, "recoveryEpoch"),
    validatorEpoch: requirePositiveUInt64(input.validatorEpoch, "validatorEpoch"),
    deviceSignatureSuiteId,
    proofDescriptorHash,
    humanPresentationHash: requireNonZeroBytes32(
      input.humanPresentationHash,
      "humanPresentationHash"
    )
  });
}

export function derivePhilAuthorizationEnvelopeDigestV1(
  input: Parameters<typeof normalizeEnvelope>[0]
): Hex {
  const envelope = normalizeEnvelope(input, true);
  return keccak256(
    abiCoder.encode(
      [
        "bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint64",
        "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32",
        "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint256",
        "uint64", "uint64", "uint256", "uint256", "uint64", "uint64",
        "uint64", "bytes32", "bytes32", "bytes32"
      ],
      [
        PHIL_AUTHORIZATION_ENVELOPE_V1_HASH,
        envelope.operationClass,
        envelope.scopedOwnerCommitment,
        envelope.scopeId,
        envelope.scopeInstance,
        BigInt(envelope.scopeEpoch),
        envelope.principalIdHash,
        envelope.capabilityId,
        BigInt(envelope.capabilityEpoch),
        envelope.networkIdHash,
        envelope.accountBindingHash,
        envelope.adapterId,
        envelope.actionTypeHash,
        envelope.parametersHash,
        envelope.intentDigest,
        envelope.policyHash,
        envelope.nonceDomain,
        BigInt(envelope.nonce),
        BigInt(envelope.validAfter),
        BigInt(envelope.validUntil),
        BigInt(envelope.valueLimit),
        BigInt(envelope.feeLimit),
        BigInt(envelope.deviceEpoch),
        BigInt(envelope.recoveryEpoch),
        BigInt(envelope.validatorEpoch),
        envelope.deviceSignatureSuiteId,
        envelope.proofDescriptorHash,
        envelope.humanPresentationHash
      ]
    )
  ) as Hex;
}

export function createPhilAuthorizationEnvelopeV1(
  input: Parameters<typeof normalizeEnvelope>[0]
): PhilAuthorizationEnvelopeV1 {
  return normalizeEnvelope(input, false);
}
