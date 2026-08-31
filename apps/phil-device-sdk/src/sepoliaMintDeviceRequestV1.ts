import {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
  createPhilSepoliaMintAuthorizationV1,
  derivePhilSepoliaMintBindingsV1,
  type PhilSepoliaMintAuthorizationV1
} from "./sepoliaMintAuthorizationV1.ts";
import {
  derivePhilDeviceApprovalDigestV1,
  type PhilDeviceEnrollmentRecordV1
} from "./deviceApprovalV1.ts";
import {
  decodePhilP256RawSignatureV2,
  encodePhilP256RawSignatureV2,
  verifyPhilP256RawSignatureV2
} from "./p256SignatureWireV2.ts";
import { parsePhilStrictJsonObjectV1 } from "./routineAuthorizationV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
export const PHIL_SEPOLIA_MINT_DEVICE_REQUEST_V1 = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_MINT_DEVICE_REQUEST_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_V1 = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_V1")
) as Hex;
export const PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1 = keccak256(
  toUtf8Bytes("PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_DEVICE_REQUEST_ID_V1 = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_MINT_DEVICE_REQUEST_ID_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_P256_PROVIDER = keccak256(
  toUtf8Bytes("apple-secure-enclave-p256-x962-sha256-digest-der-v1")
) as Hex;
export const PHIL_SEPOLIA_MINT_P256_WIRE = keccak256(
  toUtf8Bytes("phil-p256-signature-rs-64-low-s-v1")
) as Hex;

export interface PhilSepoliaMintDevicePresentationV1 {
  readonly network: "Ethereum Sepolia (chain 11155111)";
  readonly smartAccount: string;
  readonly mintRecipient: string;
  readonly contract: string;
  readonly action: "Mint one harmless, non-transferable Phil test pass";
  readonly value: "0 ETH";
  readonly maximumFeeWei: string;
  readonly expiresAt: string;
  readonly consequence:
    "Ethereum records a public test-pass event; no token, asset, or ETH is transferred.";
  readonly verificationBoundary:
    "Noir proof and iPhone approval are verified locally; Ethereum enforces the restricted account signature and ActionGate.";
}

export interface PhilSepoliaMintDeviceRequestV1 {
  readonly formatVersionHash: Hex;
  readonly protocolContextHash: Hex;
  readonly sessionId: Hex;
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly deviceId: Hex;
  readonly deviceKeyId: Hex;
  readonly deviceEpoch: string;
  readonly approvalNonce: Hex;
  readonly approvedAt: string;
  readonly approvalExpiresAt: string;
  readonly deviceApprovalDigest: Hex;
  readonly humanPresentation: PhilSepoliaMintDevicePresentationV1;
  readonly humanPresentationHash: Hex;
  readonly requestId: Hex;
  readonly platformSigningDigest: Hex;
}

export interface PhilSepoliaMintDeviceResponseV1 {
  readonly formatVersionHash: Hex;
  readonly protocolContextHash: Hex;
  readonly sessionId: Hex;
  readonly requestId: Hex;
  readonly deviceId: Hex;
  readonly deviceKeyId: Hex;
  readonly deviceEpoch: string;
  readonly humanPresentationHash: Hex;
  readonly deviceApprovalDigest: Hex;
  readonly platformSigningDigest: Hex;
  readonly signatureSuiteId: Hex;
  readonly providerProfileId: Hex;
  readonly wireEncodingId: Hex;
  readonly signatureR: Hex;
  readonly signatureS: Hex;
  readonly responseHash: Hex;
}

function fail(code: string): never {
  const error = new Error(code);
  error.name = "PhilSepoliaMintDeviceRequestV1Error";
  Object.assign(error, { code });
  throw error;
}

function b32(value: BytesLike, label: string): Hex {
  try {
    const normalized = hexlify(value).toLowerCase() as Hex;
    if (getBytes(normalized).length !== 32 || /^0x0{64}$/u.test(normalized)) throw new Error("invalid");
    return normalized;
  } catch {
    return fail(`PHIL_SEPOLIA_MINT_DEVICE_${label.toUpperCase()}_INVALID`);
  }
}

function positiveUInt64(value: string | number | bigint, label: string): string {
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^[1-9][0-9]*$/u.test(value)) throw new Error("noncanonical");
    const parsed = BigInt(value);
    if (parsed <= 0n || parsed >= 1n << 64n) throw new Error("range");
    return parsed.toString();
  } catch {
    return fail(`PHIL_SEPOLIA_MINT_DEVICE_${label.toUpperCase()}_INVALID`);
  }
}

function rebuildAuthorization(value: PhilSepoliaMintAuthorizationV1): PhilSepoliaMintAuthorizationV1 {
  const envelope = value.authorizationEnvelope;
  const bindings = derivePhilSepoliaMintBindingsV1({
    factory: value.bindings.factory,
    smartAccount: value.bindings.smartAccount,
    actionGate: value.bindings.actionGate,
    mintConsumer: value.bindings.mintConsumer,
    mintRecipient: value.bindings.mintRecipient,
    accountNonce: value.bindings.accountNonce,
    validAfter: value.bindings.validAfter,
    validUntil: value.bindings.validUntil,
    maximumTotalFeeWei: value.bindings.maximumTotalFeeWei
  });
  if (JSON.stringify(value.bindings) !== JSON.stringify(bindings)) {
    fail("PHIL_SEPOLIA_MINT_DEVICE_BINDINGS_MISMATCH");
  }
  const rebuilt = createPhilSepoliaMintAuthorizationV1({
    scopedOwnerCommitment: envelope.scopedOwnerCommitment,
    proofDescriptorHash: envelope.proofDescriptorHash,
    rootProofNullifier: envelope.rootProofNullifier,
    scopeEpoch: envelope.scopeEpoch,
    deviceEpoch: envelope.deviceEpoch,
    recoveryEpoch: envelope.recoveryEpoch,
    validatorEpoch: envelope.validatorEpoch,
    bindings
  });
  if (JSON.stringify(value) !== JSON.stringify(rebuilt)) fail("PHIL_SEPOLIA_MINT_DEVICE_AUTHORIZATION_MISMATCH");
  return rebuilt;
}

function presentation(authorization: PhilSepoliaMintAuthorizationV1): PhilSepoliaMintDevicePresentationV1 {
  const bindings = authorization.bindings;
  return Object.freeze({
    network: "Ethereum Sepolia (chain 11155111)" as const,
    smartAccount: bindings.smartAccount,
    mintRecipient: bindings.mintRecipient,
    contract: bindings.mintConsumer,
    action: "Mint one harmless, non-transferable Phil test pass" as const,
    value: "0 ETH" as const,
    maximumFeeWei: bindings.maximumTotalFeeWei,
    expiresAt: bindings.validUntil,
    consequence: "Ethereum records a public test-pass event; no token, asset, or ETH is transferred." as const,
    verificationBoundary: "Noir proof and iPhone approval are verified locally; Ethereum enforces the restricted account signature and ActionGate." as const
  });
}

export function createPhilSepoliaMintDeviceRequestV1(input: {
  readonly sessionId: BytesLike;
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly enrollment: PhilDeviceEnrollmentRecordV1;
  readonly approvalNonce: BytesLike;
  readonly approvedAt: string | number | bigint;
  readonly approvalExpiresAt: string | number | bigint;
}): PhilSepoliaMintDeviceRequestV1 {
  const authorization = rebuildAuthorization(input.authorization);
  if (input.enrollment.status !== 1
      || input.enrollment.signatureSuiteId !== PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE
      || input.enrollment.deviceEpoch !== authorization.authorizationEnvelope.deviceEpoch) {
    fail("PHIL_SEPOLIA_MINT_DEVICE_ENROLLMENT_INELIGIBLE");
  }
  const sessionId = b32(input.sessionId, "session_id");
  const approvalNonce = b32(input.approvalNonce, "approval_nonce");
  const approvedAt = positiveUInt64(input.approvedAt, "approved_at");
  const approvalExpiresAt = positiveUInt64(input.approvalExpiresAt, "approval_expires_at");
  if (BigInt(approvalExpiresAt) < BigInt(approvedAt)
      || BigInt(approvalExpiresAt) > BigInt(authorization.bindings.validUntil)) {
    fail("PHIL_SEPOLIA_MINT_DEVICE_APPROVAL_TIME_INVALID");
  }
  const deviceApprovalDigest = derivePhilDeviceApprovalDigestV1({
    authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
    deviceId: input.enrollment.deviceId,
    deviceKeyId: input.enrollment.deviceKeyId,
    deviceEpoch: input.enrollment.deviceEpoch,
    approvalNonce,
    approvedAt,
    approvalExpiresAt
  });
  const requestId = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [PHIL_SEPOLIA_MINT_DEVICE_REQUEST_ID_V1, sessionId,
      authorization.authorizationEnvelopeDigest, approvalNonce, deviceApprovalDigest]
  )) as Hex;
  return Object.freeze({
    formatVersionHash: PHIL_SEPOLIA_MINT_DEVICE_REQUEST_V1,
    protocolContextHash: PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1,
    sessionId,
    authorization,
    deviceId: input.enrollment.deviceId,
    deviceKeyId: input.enrollment.deviceKeyId,
    deviceEpoch: input.enrollment.deviceEpoch,
    approvalNonce,
    approvedAt,
    approvalExpiresAt,
    deviceApprovalDigest,
    humanPresentation: presentation(authorization),
    humanPresentationHash: authorization.bindings.humanPresentationHash,
    requestId,
    // Secure Enclave signs the exact approval digest for this composed path.
    platformSigningDigest: deviceApprovalDigest
  });
}

export function validatePhilSepoliaMintDeviceRequestV1(
  request: PhilSepoliaMintDeviceRequestV1,
  enrollment: PhilDeviceEnrollmentRecordV1
): PhilSepoliaMintDeviceRequestV1 {
  const rebuilt = createPhilSepoliaMintDeviceRequestV1({
    sessionId: request.sessionId,
    authorization: request.authorization,
    enrollment,
    approvalNonce: request.approvalNonce,
    approvedAt: request.approvedAt,
    approvalExpiresAt: request.approvalExpiresAt
  });
  if (JSON.stringify(request) !== JSON.stringify(rebuilt)) fail("PHIL_SEPOLIA_MINT_DEVICE_REQUEST_MISMATCH");
  return rebuilt;
}

export function serializePhilSepoliaMintDeviceRequestJsonV1(
  request: PhilSepoliaMintDeviceRequestV1,
  enrollment: PhilDeviceEnrollmentRecordV1
): string {
  return JSON.stringify(validatePhilSepoliaMintDeviceRequestV1(request, enrollment));
}

export function createPhilSepoliaMintDeviceResponseV1(input: {
  readonly request: PhilSepoliaMintDeviceRequestV1;
  readonly enrollment: PhilDeviceEnrollmentRecordV1;
  readonly signature: BytesLike;
}): PhilSepoliaMintDeviceResponseV1 {
  const request = validatePhilSepoliaMintDeviceRequestV1(input.request, input.enrollment);
  const signature = decodePhilP256RawSignatureV2(input.signature);
  const raw = encodePhilP256RawSignatureV2(signature);
  if (!verifyPhilP256RawSignatureV2({
    digest: request.deviceApprovalDigest,
    signature: raw,
    publicKeyX963: input.enrollment.publicKey
  })) fail("PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_SIGNATURE_INVALID");
  const record = {
    formatVersionHash: PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_V1,
    protocolContextHash: PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1,
    sessionId: request.sessionId,
    requestId: request.requestId,
    deviceId: request.deviceId,
    deviceKeyId: request.deviceKeyId,
    deviceEpoch: request.deviceEpoch,
    humanPresentationHash: request.humanPresentationHash,
    deviceApprovalDigest: request.deviceApprovalDigest,
    platformSigningDigest: request.deviceApprovalDigest,
    signatureSuiteId: PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    providerProfileId: PHIL_SEPOLIA_MINT_P256_PROVIDER,
    wireEncodingId: PHIL_SEPOLIA_MINT_P256_WIRE,
    signatureR: signature.r,
    signatureS: signature.s
  };
  const responseHash = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64",
      "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [record.formatVersionHash, record.protocolContextHash, record.sessionId, record.requestId,
      record.deviceId, record.deviceKeyId, BigInt(record.deviceEpoch), record.humanPresentationHash,
      record.deviceApprovalDigest, record.platformSigningDigest, record.signatureSuiteId,
      record.providerProfileId, record.wireEncodingId, record.signatureR, record.signatureS]
  )) as Hex;
  return Object.freeze({ ...record, responseHash });
}

export function parsePhilSepoliaMintDeviceResponseJsonV1(input: {
  readonly request: PhilSepoliaMintDeviceRequestV1;
  readonly enrollment: PhilDeviceEnrollmentRecordV1;
  readonly json: string | Uint8Array;
}): PhilSepoliaMintDeviceResponseV1 {
  let parsed: unknown;
  try { parsed = parsePhilStrictJsonObjectV1(input.json); }
  catch { return fail("PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_JSON_INVALID"); }
  const candidate = parsed as PhilSepoliaMintDeviceResponseV1;
  const rebuilt = createPhilSepoliaMintDeviceResponseV1({
    request: input.request,
    enrollment: input.enrollment,
    signature: encodePhilP256RawSignatureV2({ r: candidate.signatureR, s: candidate.signatureS })
  });
  if (JSON.stringify(candidate) !== JSON.stringify(rebuilt)) fail("PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_MISMATCH");
  return rebuilt;
}
