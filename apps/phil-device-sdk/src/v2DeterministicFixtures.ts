import { p256 } from "@noble/curves/p256";
import {
  AbiCoder,
  Signature,
  concat,
  getAddress,
  getBytes,
  isHexString,
  keccak256,
  recoverAddress,
  sha256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import type {
  PhilCoreV2RecoveryEvidenceContextInput,
  PhilCoreV2RecoveryFactorDescriptorInput
} from "./v2RecoveryEvidence.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;

export const PHILCORE_O37_2_FIXTURE_CLASSIFICATION =
  "TEST_FIXTURE_ONLY" as const;
export const PHILCORE_O37_2_FIXTURE_VERSION = 1 as const;
export const PHILCORE_O37_2_SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const PHILCORE_O37_2_SECP256K1_HALF_ORDER =
  PHILCORE_O37_2_SECP256K1_ORDER / 2n;
export const PHILCORE_O37_2_P256_ORDER = p256.CURVE.n;
export const PHILCORE_O37_2_P256_HALF_ORDER = p256.CURVE.n / 2n;

export const PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI = [
  "uint8",
  "uint8",
  "uint8",
  "address",
  "bytes32",
  "uint64",
  "uint64",
  "bytes32",
  "bytes32",
  "uint8"
] as const;

export const PHILCORE_O37_2_DESCRIPTOR_COMPONENTS =
  "uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdHash,bytes32 rpIdHash,bytes32 originPolicyHash,bytes32 independenceBindingHash,uint8 userVerificationPolicy,uint8 backupPolicy,uint8 authenticatorAttachmentPolicy,uint8 attestationPolicy,uint64 credentialGeneration";
export const PHILCORE_O37_2_CONTEXT_COMPONENTS =
  "uint8 envelopeVersion,uint8 authorityKind,uint8 actionType,uint8 factorBitmap,address account,uint256 chainId,address entryPoint,bytes32 authorizedIntentHash,bytes32 userOperationHash,bytes32 requestId,bytes32 currentRecoveryConfigHash,uint64 validatorEpoch,uint64 recoveryEpoch,uint48 validAfter,uint48 validUntil,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds,bytes32 proposedValidatorCommitment,bytes32 proposedRecoveryConfigHash,uint64 proposedRecoveryEpoch,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment,bytes32 firstFactorCommitment,bytes32 secondFactorCommitment";

export const PHILCORE_O37_2_DESCRIPTOR_TUPLE =
  `tuple(${PHILCORE_O37_2_DESCRIPTOR_COMPONENTS})`;
export const PHILCORE_O37_2_CONTEXT_TUPLE =
  `tuple(${PHILCORE_O37_2_CONTEXT_COMPONENTS})`;
export const PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE =
  `tuple(${PHILCORE_O37_2_DESCRIPTOR_TUPLE} descriptor,bytes32 factorCommitment,bytes32 qx,bytes32 qy,bytes32 r,bytes32 s,uint256 challengeIndex,uint256 typeIndex,bytes authenticatorData,string clientDataJSON)`;
export const PHILCORE_O37_2_SECP256K1_EVIDENCE_TUPLE =
  `tuple(${PHILCORE_O37_2_DESCRIPTOR_TUPLE} descriptor,bytes32 factorCommitment,address signer,bytes32 r,bytes32 s,uint8 v)`;
export const PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE =
  `tuple(${PHILCORE_O37_2_CONTEXT_TUPLE} context,bytes firstFactorEvidence,bytes secondFactorEvidence)`;

export interface PhilCoreO372PackedUserOperation {
  readonly sender: string;
  readonly nonce: BigNumberish;
  readonly initCode: Hex;
  readonly callData: Hex;
  readonly accountGasLimits: Hex;
  readonly preVerificationGas: BigNumberish;
  readonly gasFees: Hex;
  readonly paymasterAndData: Hex;
  readonly signature: Hex;
}

export interface PhilCoreO372ValidatorEnvelope {
  readonly envelopeVersion: BigNumberish;
  readonly authorityKind: BigNumberish;
  readonly verifierKind: BigNumberish;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly r: Hex;
  readonly s: Hex;
  readonly v: BigNumberish;
}

function bytes(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value)) {
    throw new Error(`${label}_must_be_bytes`);
  }
  return value.toLowerCase() as Hex;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === ZERO_BYTES32) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return normalized;
}

function uint(
  value: BigNumberish,
  bits: number,
  label: string,
  allowZero = true
): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (!allowZero && parsed === 0n) throw new Error(`${label}_must_be_nonzero`);
  return parsed;
}

function address(value: string, label: string): string {
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    throw new Error(`${label}_must_be_address`);
  }
  if (normalized === ZERO_ADDRESS) throw new Error(`${label}_must_be_nonzero`);
  return normalized;
}

export function packPhilCoreO372Uint128Pair(
  high: BigNumberish,
  low: BigNumberish
): Hex {
  const packed =
    (uint(high, 128, "high128") << 128n) | uint(low, 128, "low128");
  return zeroPadValue(toBeHex(packed), 32).toLowerCase() as Hex;
}

export function unpackPhilCoreO372Uint128Pair(
  packed: Hex
): readonly [bigint, bigint] {
  const value = BigInt(bytes32(packed, "packedUint128Pair", true));
  return [value >> 128n, value & ((1n << 128n) - 1n)];
}

export function computePhilCoreO372PackedUserOperationStructHash(
  userOperation: PhilCoreO372PackedUserOperation
): Hex {
  return keccak256(abiCoder.encode(
    [
      "address",
      "uint256",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint256",
      "bytes32",
      "bytes32"
    ],
    [
      address(userOperation.sender, "sender"),
      uint(userOperation.nonce, 256, "nonce"),
      keccak256(bytes(userOperation.initCode, "initCode")),
      keccak256(bytes(userOperation.callData, "callData")),
      bytes32(userOperation.accountGasLimits, "accountGasLimits", true),
      uint(userOperation.preVerificationGas, 256, "preVerificationGas"),
      bytes32(userOperation.gasFees, "gasFees", true),
      keccak256(bytes(userOperation.paymasterAndData, "paymasterAndData"))
    ]
  )) as Hex;
}

export function computePhilCoreO372PackedUserOperationHash(
  userOperation: PhilCoreO372PackedUserOperation,
  entryPoint: string,
  chainId: BigNumberish
): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "address", "uint256"],
    [
      computePhilCoreO372PackedUserOperationStructHash(userOperation),
      address(entryPoint, "entryPoint"),
      uint(chainId, 256, "chainId", false)
    ]
  )) as Hex;
}

export function encodePhilCoreO372ValidatorEnvelope(
  envelope: PhilCoreO372ValidatorEnvelope
): Hex {
  const encoded = abiCoder.encode(
    PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI,
    [
      uint(envelope.envelopeVersion, 8, "envelopeVersion"),
      uint(envelope.authorityKind, 8, "authorityKind"),
      uint(envelope.verifierKind, 8, "verifierKind"),
      address(envelope.validator, "validator"),
      bytes32(envelope.validatorKeyIdBinding, "validatorKeyIdBinding"),
      uint(envelope.validatorEpoch, 64, "validatorEpoch", false),
      uint(envelope.recoveryEpoch, 64, "recoveryEpoch", false),
      bytes32(envelope.r, "r", true),
      bytes32(envelope.s, "s", true),
      uint(envelope.v, 8, "v")
    ]
  ) as Hex;
  if (getBytes(encoded).length !== 320) {
    throw new Error("validator_envelope_length_invalid");
  }
  return encoded;
}

export function verifyPhilCoreO372ValidatorEnvelope(input: {
  readonly digest: Hex;
  readonly envelope: PhilCoreO372ValidatorEnvelope;
  readonly expectedValidator: string;
  readonly expectedKeyIdBinding: Hex;
  readonly expectedValidatorEpoch: BigNumberish;
  readonly expectedRecoveryEpoch: BigNumberish;
}): {
  readonly accepted: boolean;
  readonly code: string;
  readonly recoveredAddress?: string;
} {
  let encoded: Hex;
  try {
    encoded = encodePhilCoreO372ValidatorEnvelope(input.envelope);
  } catch {
    return { accepted: false, code: "VALIDATOR_EVIDENCE_MALFORMED" };
  }
  if (getBytes(encoded).length !== 320) {
    return { accepted: false, code: "VALIDATOR_EVIDENCE_LENGTH_INVALID" };
  }
  if (BigInt(input.envelope.envelopeVersion) !== 1n) {
    return { accepted: false, code: "VALIDATOR_ENVELOPE_VERSION_UNSUPPORTED" };
  }
  if (BigInt(input.envelope.authorityKind) !== 1n) {
    return { accepted: false, code: "AUTHORITY_KIND_MISMATCH" };
  }
  if (BigInt(input.envelope.verifierKind) !== 1n) {
    return { accepted: false, code: "VALIDATOR_VERIFIER_UNSUPPORTED" };
  }
  if (
    address(input.envelope.validator, "validator")
    !== address(input.expectedValidator, "expectedValidator")
  ) {
    return { accepted: false, code: "VALIDATOR_ADDRESS_MISMATCH" };
  }
  if (
    bytes32(input.envelope.validatorKeyIdBinding, "validatorKeyIdBinding")
    !== bytes32(input.expectedKeyIdBinding, "expectedKeyIdBinding")
  ) {
    return { accepted: false, code: "VALIDATOR_KEY_BINDING_MISMATCH" };
  }
  if (
    BigInt(input.envelope.validatorEpoch)
    !== BigInt(input.expectedValidatorEpoch)
  ) {
    return { accepted: false, code: "VALIDATOR_EPOCH_MISMATCH" };
  }
  if (
    BigInt(input.envelope.recoveryEpoch)
    !== BigInt(input.expectedRecoveryEpoch)
  ) {
    return { accepted: false, code: "RECOVERY_EPOCH_MISMATCH" };
  }
  const r = BigInt(bytes32(input.envelope.r, "r", true));
  const s = BigInt(bytes32(input.envelope.s, "s", true));
  const v = Number(BigInt(input.envelope.v));
  if (r === 0n || s === 0n || ![27, 28].includes(v)) {
    return { accepted: false, code: "VALIDATOR_SIGNATURE_INVALID" };
  }
  if (s > PHILCORE_O37_2_SECP256K1_HALF_ORDER) {
    return { accepted: false, code: "VALIDATOR_SIGNATURE_MALLEABLE" };
  }
  let recoveredAddress: string;
  try {
    recoveredAddress = recoverAddress(
      bytes32(input.digest, "digest"),
      Signature.from({
        r: input.envelope.r,
        s: input.envelope.s,
        v
      })
    );
  } catch {
    return { accepted: false, code: "VALIDATOR_SIGNATURE_INVALID" };
  }
  if (recoveredAddress !== address(input.expectedValidator, "expectedValidator")) {
    return {
      accepted: false,
      code: "VALIDATOR_SIGNATURE_INVALID",
      recoveredAddress
    };
  }
  return { accepted: true, code: "VALIDATOR_SIGNATURE_ACCEPTED", recoveredAddress };
}

export function computePhilCoreO372RpIdHash(rpId: string): Hex {
  if (typeof rpId !== "string" || rpId.length === 0) {
    throw new Error("rpId_required");
  }
  return sha256(toUtf8Bytes(rpId)) as Hex;
}

export function buildPhilCoreO372WebAuthnClientData(input: {
  readonly challenge: Hex;
  readonly origin: string;
}): {
  readonly clientDataJSON: string;
  readonly challengeBase64Url: string;
  readonly challengeIndex: number;
  readonly typeIndex: number;
} {
  const challenge = bytes32(input.challenge, "challenge");
  if (
    typeof input.origin !== "string"
    || !input.origin.startsWith("https://")
  ) {
    throw new Error("origin_must_be_https");
  }
  const challengeBase64Url = Buffer.from(getBytes(challenge))
    .toString("base64url");
  const clientDataJSON = JSON.stringify({
    type: "webauthn.get",
    challenge: challengeBase64Url,
    origin: input.origin,
    crossOrigin: false
  });
  const challengeIndex = clientDataJSON.indexOf(
    `"challenge":"${challengeBase64Url}"`
  );
  const typeIndex = clientDataJSON.indexOf('"type":"webauthn.get"');
  if (challengeIndex < 0 || typeIndex < 0) {
    throw new Error("clientDataJSON_index_generation_failed");
  }
  return {
    clientDataJSON,
    challengeBase64Url,
    challengeIndex,
    typeIndex
  };
}

export function computePhilCoreO372WebAuthnMessageHash(input: {
  readonly authenticatorData: Hex;
  readonly clientDataJSON: string;
}): Hex {
  const clientHash = sha256(toUtf8Bytes(input.clientDataJSON));
  return sha256(concat([
    bytes(input.authenticatorData, "authenticatorData"),
    clientHash
  ])) as Hex;
}

export function verifyPhilCoreO372P256Signature(input: {
  readonly messageHash: Hex;
  readonly qx: Hex;
  readonly qy: Hex;
  readonly r: Hex;
  readonly s: Hex;
}): {
  readonly accepted: boolean;
  readonly code: string;
} {
  const r = BigInt(bytes32(input.r, "r", true));
  const s = BigInt(bytes32(input.s, "s", true));
  if (r === 0n || s === 0n) {
    return { accepted: false, code: "P256_SIGNATURE_INVALID" };
  }
  if (s > PHILCORE_O37_2_P256_HALF_ORDER) {
    return { accepted: false, code: "P256_SIGNATURE_MALLEABLE" };
  }
  const publicKey = concat([
    "0x04",
    bytes32(input.qx, "qx"),
    bytes32(input.qy, "qy")
  ]);
  let accepted = false;
  try {
    accepted = p256.verify(
      new p256.Signature(r, s),
      getBytes(bytes32(input.messageHash, "messageHash")),
      getBytes(publicKey),
      { lowS: true }
    );
  } catch {
    accepted = false;
  }
  return accepted
    ? { accepted: true, code: "P256_SIGNATURE_ACCEPTED" }
    : { accepted: false, code: "P256_SIGNATURE_INVALID" };
}

export function encodePhilCoreO372WebAuthnEvidence(input: {
  readonly descriptor: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly factorCommitment: Hex;
  readonly qx: Hex;
  readonly qy: Hex;
  readonly r: Hex;
  readonly s: Hex;
  readonly challengeIndex: BigNumberish;
  readonly typeIndex: BigNumberish;
  readonly authenticatorData: Hex;
  readonly clientDataJSON: string;
}): Hex {
  return abiCoder.encode(
    [PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE],
    [{
      ...input,
      factorCommitment: bytes32(
        input.factorCommitment,
        "factorCommitment"
      ),
      qx: bytes32(input.qx, "qx"),
      qy: bytes32(input.qy, "qy"),
      r: bytes32(input.r, "r", true),
      s: bytes32(input.s, "s", true),
      challengeIndex: uint(input.challengeIndex, 256, "challengeIndex"),
      typeIndex: uint(input.typeIndex, 256, "typeIndex"),
      authenticatorData: bytes(input.authenticatorData, "authenticatorData")
    }]
  ) as Hex;
}

export function encodePhilCoreO372Secp256k1Evidence(input: {
  readonly descriptor: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly factorCommitment: Hex;
  readonly signer: string;
  readonly r: Hex;
  readonly s: Hex;
  readonly v: BigNumberish;
}): Hex {
  return abiCoder.encode(
    [PHILCORE_O37_2_SECP256K1_EVIDENCE_TUPLE],
    [{
      ...input,
      factorCommitment: bytes32(
        input.factorCommitment,
        "factorCommitment"
      ),
      signer: address(input.signer, "signer"),
      r: bytes32(input.r, "r", true),
      s: bytes32(input.s, "s", true),
      v: uint(input.v, 8, "v")
    }]
  ) as Hex;
}

export function encodePhilCoreO372RecoveryEnvelope(input: {
  readonly context: PhilCoreV2RecoveryEvidenceContextInput;
  readonly firstFactorEvidence: Hex;
  readonly secondFactorEvidence: Hex;
}): Hex {
  return abiCoder.encode(
    [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
    [{
      context: input.context,
      firstFactorEvidence: bytes(
        input.firstFactorEvidence,
        "firstFactorEvidence"
      ),
      secondFactorEvidence: bytes(
        input.secondFactorEvidence,
        "secondFactorEvidence"
      )
    }]
  ) as Hex;
}
