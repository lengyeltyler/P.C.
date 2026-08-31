import {
  AbiCoder,
  getBytes,
  isHexString
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  decodePhilCoreO374RecoveryEvidence,
  PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES
} from "./v2AuthorityTransport.ts";
import { PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE } from "./v2DeterministicFixtures.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

/** Authoritative WebAuthn factor evidence bounds (unchanged from O.37.4). */
export const PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MIN_BYTES = 992 as const;
export const PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MAX_BYTES = 3968 as const;
/** Authoritative secp256k1 Role 2 evidence length (unchanged from O.37.4). */
export const PHILCORE_V2_CONSUMER_SECP256K1_EVIDENCE_BYTES = 672 as const;
/** Native P-256 Role 1 evidence length (O.43 / O.44 consumer). */
export const PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES = 640 as const;
/** Current consumer recovery-envelope minimum (native Role 1 aware). */
export const PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES = 2272 as const;
/** Existing recovery-envelope maximum (unchanged from O.37.4). */
export const PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MAX_BYTES = 8896 as const;

export type PhilCoreV2ConsumerRecoveryEvidenceDecoded = {
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
};

function bytes(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value)) {
    throw new Error(`${label}_must_be_bytes`);
  }
  return value.toLowerCase() as Hex;
}

function equalBytes(left: Hex, right: Hex): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function rolesForBitmap(bitmap: bigint): readonly [number, number] {
  if (bitmap === 3n) return [0, 1];
  if (bitmap === 5n) return [0, 2];
  if (bitmap === 6n) return [1, 2];
  throw new Error("recovery_factor_bitmap_invalid");
}

function assertFactorEvidenceLengthForRole(
  role: number,
  evidence: Hex,
  label: string
): void {
  const length = getBytes(evidence).length;
  if (role === 0) {
    if (
      length < PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MIN_BYTES
      || length > PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MAX_BYTES
    ) {
      throw new Error(`${label}_webauthn_evidence_length_invalid`);
    }
    return;
  }
  if (role === 1) {
    const webauthnOk =
      length >= PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MIN_BYTES
      && length <= PHILCORE_V2_CONSUMER_WEBAUTHN_EVIDENCE_MAX_BYTES;
    const nativeOk = length === PHILCORE_V2_CONSUMER_NATIVE_P256_EVIDENCE_BYTES;
    if (!webauthnOk && !nativeOk) {
      throw new Error(`${label}_role1_evidence_length_invalid`);
    }
    return;
  }
  if (role === 2) {
    if (length !== PHILCORE_V2_CONSUMER_SECP256K1_EVIDENCE_BYTES) {
      throw new Error(`${label}_secp256k1_evidence_length_invalid`);
    }
    return;
  }
  throw new Error(`${label}_role_unsupported`);
}

function assertRoleEvidenceLengths(
  decoded: PhilCoreV2ConsumerRecoveryEvidenceDecoded
): void {
  const roles = rolesForBitmap(decoded.context.factorBitmap);
  assertFactorEvidenceLengthForRole(
    roles[0],
    decoded.firstFactorEvidence,
    "firstFactorEvidence"
  );
  assertFactorEvidenceLengthForRole(
    roles[1],
    decoded.secondFactorEvidence,
    "secondFactorEvidence"
  );
}

/**
 * Complete current-consumer recovery-envelope decode for envelopes below the
 * frozen O.37.4 historical length floor (and any path that cannot reuse it).
 */
function decodeConsumerRecoveryEvidenceLocal(
  encoded: Hex,
  expectedActionType: number
): PhilCoreV2ConsumerRecoveryEvidenceDecoded {
  const value = bytes(encoded, "recoveryEvidence");
  const length = getBytes(value).length;
  if (
    length < PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES
    || length > PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MAX_BYTES
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
  const factorBitmap = BigInt(context.factorBitmap);
  if (![3n, 5n, 6n].includes(factorBitmap)) {
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
  const result: PhilCoreV2ConsumerRecoveryEvidenceDecoded = {
    context: {
      envelopeVersion: BigInt(context.envelopeVersion),
      authorityKind: BigInt(context.authorityKind),
      actionType: BigInt(context.actionType),
      factorBitmap,
      validatorEpoch: BigInt(context.validatorEpoch),
      recoveryEpoch: BigInt(context.recoveryEpoch)
    },
    firstFactorEvidence,
    secondFactorEvidence,
    canonicalEncoding: canonical.toLowerCase() as Hex
  };
  assertRoleEvidenceLengths(result);
  return result;
}

/**
 * Authoritative current-consumer recovery evidence decoder.
 *
 * Reuses the frozen O.37.4 decoder for envelopes it accepts, then applies
 * native-aware role evidence length checks. For envelopes below the frozen
 * 2624-byte floor but within the current 2272–8896 consumer bounds, catches
 * only the exact frozen length-floor rejection and completes decoding locally.
 */
export function decodePhilCoreV2ConsumerRecoveryEvidence(
  encoded: Hex,
  expectedActionType: number
): PhilCoreV2ConsumerRecoveryEvidenceDecoded {
  const value = bytes(encoded, "recoveryEvidence");
  const length = getBytes(value).length;
  if (
    length < PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MIN_BYTES
    || length > PHILCORE_V2_CONSUMER_RECOVERY_EVIDENCE_MAX_BYTES
  ) {
    throw new Error("recovery_evidence_length_invalid");
  }

  try {
    const frozen = decodePhilCoreO374RecoveryEvidence(
      value,
      expectedActionType
    );
    const result: PhilCoreV2ConsumerRecoveryEvidenceDecoded = {
      context: frozen.context,
      firstFactorEvidence: frozen.firstFactorEvidence,
      secondFactorEvidence: frozen.secondFactorEvidence,
      canonicalEncoding: frozen.canonicalEncoding
    };
    assertRoleEvidenceLengths(result);
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (
      message === "recovery_evidence_length_invalid"
      && length < PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES
    ) {
      return decodeConsumerRecoveryEvidenceLocal(value, expectedActionType);
    }
    throw error;
  }
}
