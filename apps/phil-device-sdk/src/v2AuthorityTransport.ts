import {
  AbiCoder,
  getBytes,
  isHexString,
  keccak256,
  toUtf8Bytes
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE,
  PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI
} from "./v2DeterministicFixtures.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION = 1 as const;
export const PHILCORE_O37_4_COMBINED_AUTHORITY_KIND = 3 as const;
export const PHILCORE_O37_4_CONFIG_ROTATION_ACTION = 10 as const;

export const PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE =
  "PhilCoreV2CombinedAuthorityEnvelopeV1(uint8 envelopeVersion,uint8 authorityKind,uint8 actionType,bytes validatorEvidence,bytes recoveryEvidence)" as const;
export const PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH =
  keccak256(toUtf8Bytes(PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE)) as Hex;
export const PHILCORE_O37_4_COMBINED_AUTHORITY_ABI = [
  "uint8",
  "uint8",
  "uint8",
  "bytes",
  "bytes"
] as const;

export const PHILCORE_O37_4_VALIDATOR_EVIDENCE_BYTES = 320 as const;
export const PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MIN_BYTES = 992 as const;
export const PHILCORE_O37_4_WEBAUTHN_EVIDENCE_MAX_BYTES = 3968 as const;
export const PHILCORE_O37_4_SECP256K1_EVIDENCE_BYTES = 672 as const;
export const PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES = 2624 as const;
export const PHILCORE_O37_4_RECOVERY_EVIDENCE_MAX_BYTES = 8896 as const;
export const PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES = 3168 as const;
export const PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES = 9440 as const;

export const PHILCORE_O37_4_AUTHORITY_CLASS = Object.freeze({
  VALIDATOR_ONLY: 1,
  RECOVERY_ONLY: 2,
  VALIDATOR_AND_RECOVERY: 3
} as const);

export type PhilCoreO374AuthorityClass =
  typeof PHILCORE_O37_4_AUTHORITY_CLASS[
    keyof typeof PHILCORE_O37_4_AUTHORITY_CLASS
  ];

export interface PhilCoreO374CombinedAuthorityEnvelope {
  readonly envelopeVersion: number;
  readonly authorityKind: number;
  readonly actionType: number;
  readonly validatorEvidence: Hex;
  readonly recoveryEvidence: Hex;
}

export interface PhilCoreO374DecodedAuthorityTransport {
  readonly authorityClass: PhilCoreO374AuthorityClass;
  readonly actionType: number;
  readonly validatorEvidence: Hex;
  readonly recoveryEvidence: Hex;
  readonly canonicalEncoding: Hex;
}

function bytes(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value)) {
    throw new Error(`${label}_must_be_bytes`);
  }
  return value.toLowerCase() as Hex;
}

function uint8(value: unknown, label: string): number {
  let parsed: bigint;
  try {
    parsed = BigInt(value as string | number | bigint);
  } catch {
    throw new Error(`${label}_must_be_uint8`);
  }
  if (parsed < 0n || parsed > 255n) throw new Error(`${label}_must_be_uint8`);
  return Number(parsed);
}

function equalBytes(left: Hex, right: Hex): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function authorityClassForAction(actionType: number): PhilCoreO374AuthorityClass {
  if (actionType >= 0 && actionType <= 7) {
    return PHILCORE_O37_4_AUTHORITY_CLASS.VALIDATOR_ONLY;
  }
  if ([8, 9, 11].includes(actionType)) {
    return PHILCORE_O37_4_AUTHORITY_CLASS.RECOVERY_ONLY;
  }
  if (actionType === PHILCORE_O37_4_CONFIG_ROTATION_ACTION) {
    return PHILCORE_O37_4_AUTHORITY_CLASS.VALIDATOR_AND_RECOVERY;
  }
  throw new Error("authority_transport_action_unsupported");
}

export function assertPhilCoreO374ValidatorEvidenceCanonical(
  encoded: Hex
): true {
  const value = bytes(encoded, "validatorEvidence");
  if (getBytes(value).length !== PHILCORE_O37_4_VALIDATOR_EVIDENCE_BYTES) {
    throw new Error("validator_evidence_length_invalid");
  }
  let decoded: ReturnType<typeof abiCoder.decode>;
  try {
    decoded = abiCoder.decode(PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI, value);
  } catch {
    throw new Error("validator_evidence_malformed");
  }
  const canonical = abiCoder.encode(
    PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI,
    decoded
  ) as Hex;
  if (!equalBytes(canonical, value)) {
    throw new Error("validator_evidence_noncanonical");
  }
  if (
    BigInt(decoded[0]) !== 1n
    || BigInt(decoded[1]) !== 1n
    || BigInt(decoded[2]) !== 1n
  ) {
    throw new Error("validator_evidence_header_invalid");
  }
  return true;
}

export function decodePhilCoreO374RecoveryEvidence(
  encoded: Hex,
  expectedActionType: number
): {
  readonly context: {
    readonly envelopeVersion: bigint;
    readonly authorityKind: bigint;
    readonly actionType: bigint;
    readonly factorBitmap: bigint;
    readonly validatorEpoch: bigint;
    readonly recoveryEpoch: bigint;
  };
  readonly firstFactorEvidence: Hex;
  readonly secondFactorEvidence: Hex;
  readonly canonicalEncoding: Hex;
} {
  const value = bytes(encoded, "recoveryEvidence");
  const length = getBytes(value).length;
  if (
    length < PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES
    || length > PHILCORE_O37_4_RECOVERY_EVIDENCE_MAX_BYTES
  ) {
    throw new Error("recovery_evidence_length_invalid");
  }
  let decoded: ReturnType<typeof abiCoder.decode>;
  try {
    decoded = abiCoder.decode(
      [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
      value
    );
  } catch {
    throw new Error("recovery_evidence_malformed");
  }
  const canonical = abiCoder.encode(
    [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
    decoded
  ) as Hex;
  if (!equalBytes(canonical, value)) {
    throw new Error("recovery_evidence_noncanonical");
  }
  const envelope = decoded[0];
  const context = envelope.context;
  if (BigInt(context.envelopeVersion) !== 2n) {
    throw new Error("recovery_evidence_version_unsupported");
  }
  if (BigInt(context.authorityKind) !== 2n) {
    throw new Error("recovery_authority_kind_invalid");
  }
  if (BigInt(context.actionType) !== BigInt(expectedActionType)) {
    throw new Error("recovery_evidence_action_mismatch");
  }
  if (![3n, 5n, 6n].includes(BigInt(context.factorBitmap))) {
    throw new Error("recovery_factor_bitmap_invalid");
  }
  const firstFactorEvidence =
    bytes(envelope.firstFactorEvidence, "firstFactorEvidence");
  const secondFactorEvidence =
    bytes(envelope.secondFactorEvidence, "secondFactorEvidence");
  if (
    firstFactorEvidence === "0x"
    || secondFactorEvidence === "0x"
    || equalBytes(firstFactorEvidence, secondFactorEvidence)
  ) {
    throw new Error("recovery_factor_evidence_missing_or_duplicate");
  }
  return {
    context: {
      envelopeVersion: BigInt(context.envelopeVersion),
      authorityKind: BigInt(context.authorityKind),
      actionType: BigInt(context.actionType),
      factorBitmap: BigInt(context.factorBitmap),
      validatorEpoch: BigInt(context.validatorEpoch),
      recoveryEpoch: BigInt(context.recoveryEpoch)
    },
    firstFactorEvidence,
    secondFactorEvidence,
    canonicalEncoding: canonical.toLowerCase() as Hex
  };
}

export function encodePhilCoreO374CombinedAuthorityEnvelope(input: {
  readonly validatorEvidence: Hex;
  readonly recoveryEvidence: Hex;
}): Hex {
  const validatorEvidence =
    bytes(input.validatorEvidence, "validatorEvidence");
  const recoveryEvidence =
    bytes(input.recoveryEvidence, "recoveryEvidence");
  assertPhilCoreO374ValidatorEvidenceCanonical(validatorEvidence);
  decodePhilCoreO374RecoveryEvidence(
    recoveryEvidence,
    PHILCORE_O37_4_CONFIG_ROTATION_ACTION
  );
  const encoded = abiCoder.encode(
    PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
    [
      PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION,
      PHILCORE_O37_4_COMBINED_AUTHORITY_KIND,
      PHILCORE_O37_4_CONFIG_ROTATION_ACTION,
      validatorEvidence,
      recoveryEvidence
    ]
  ) as Hex;
  const expectedLength =
    544 + getBytes(recoveryEvidence).length;
  const actualLength = getBytes(encoded).length;
  if (
    actualLength !== expectedLength
    || actualLength < PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES
    || actualLength > PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES
  ) {
    throw new Error("combined_authority_envelope_length_invalid");
  }
  return encoded.toLowerCase() as Hex;
}

export function decodePhilCoreO374CombinedAuthorityEnvelope(
  encoded: Hex
): PhilCoreO374CombinedAuthorityEnvelope & {
  readonly canonicalEncoding: Hex;
} {
  const value = bytes(encoded, "combinedAuthorityEnvelope");
  const length = getBytes(value).length;
  if (
    length < PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES
    || length > PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES
  ) {
    throw new Error("combined_authority_envelope_length_invalid");
  }
  let decoded: ReturnType<typeof abiCoder.decode>;
  try {
    decoded = abiCoder.decode(
      PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
      value
    );
  } catch {
    throw new Error("combined_authority_envelope_malformed");
  }
  const canonical = abiCoder.encode(
    PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
    decoded
  ) as Hex;
  if (!equalBytes(canonical, value)) {
    throw new Error("combined_authority_envelope_noncanonical");
  }
  const envelopeVersion = uint8(decoded[0], "envelopeVersion");
  const authorityKind = uint8(decoded[1], "authorityKind");
  const actionType = uint8(decoded[2], "actionType");
  if (envelopeVersion !== PHILCORE_O37_4_AUTHORITY_TRANSPORT_VERSION) {
    throw new Error("combined_authority_envelope_version_unsupported");
  }
  if (authorityKind !== PHILCORE_O37_4_COMBINED_AUTHORITY_KIND) {
    throw new Error("combined_authority_kind_invalid");
  }
  if (actionType !== PHILCORE_O37_4_CONFIG_ROTATION_ACTION) {
    throw new Error("combined_authority_action_invalid");
  }
  const validatorEvidence = bytes(decoded[3], "validatorEvidence");
  const recoveryEvidence = bytes(decoded[4], "recoveryEvidence");
  assertPhilCoreO374ValidatorEvidenceCanonical(validatorEvidence);
  decodePhilCoreO374RecoveryEvidence(recoveryEvidence, actionType);
  if (length !== 544 + getBytes(recoveryEvidence).length) {
    throw new Error("combined_authority_envelope_length_invalid");
  }
  return {
    envelopeVersion,
    authorityKind,
    actionType,
    validatorEvidence,
    recoveryEvidence,
    canonicalEncoding: canonical.toLowerCase() as Hex
  };
}

export function decodePhilCoreO374AuthorityTransport(
  actionTypeInput: number,
  signature: Hex
): PhilCoreO374DecodedAuthorityTransport {
  const actionType = uint8(actionTypeInput, "actionType");
  const authorityClass = authorityClassForAction(actionType);
  const value = bytes(signature, "packedUserOperationSignature");
  if (authorityClass === PHILCORE_O37_4_AUTHORITY_CLASS.VALIDATOR_ONLY) {
    assertPhilCoreO374ValidatorEvidenceCanonical(value);
    return {
      authorityClass,
      actionType,
      validatorEvidence: value,
      recoveryEvidence: "0x",
      canonicalEncoding: value
    };
  }
  if (authorityClass === PHILCORE_O37_4_AUTHORITY_CLASS.RECOVERY_ONLY) {
    decodePhilCoreO374RecoveryEvidence(value, actionType);
    return {
      authorityClass,
      actionType,
      validatorEvidence: "0x",
      recoveryEvidence: value,
      canonicalEncoding: value
    };
  }
  const combined = decodePhilCoreO374CombinedAuthorityEnvelope(value);
  return {
    authorityClass,
    actionType,
    validatorEvidence: combined.validatorEvidence,
    recoveryEvidence: combined.recoveryEvidence,
    canonicalEncoding: combined.canonicalEncoding
  };
}
