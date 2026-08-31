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
  normalizePhilBytes32,
  normalizePhilUInt64,
  requirePhilNonZeroBytes32,
  type PhilUInt64String
} from "./secureIdentityV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_DEVICE_APPROVAL_V1_LABEL = "PHIL_DEVICE_APPROVAL_V1" as const;
export const PHIL_DEVICE_APPROVAL_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_APPROVAL_V1_LABEL)
) as Hex;
export const PHIL_DEVICE_ENROLLMENT_RECORD_V1_LABEL =
  "PHIL_DEVICE_ENROLLMENT_RECORD_V1" as const;
export const PHIL_DEVICE_ENROLLMENT_RECORD_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_ENROLLMENT_RECORD_V1_LABEL)
) as Hex;

export type PhilDeviceStatusV1 = 1 | 2 | 3 | 4;
export type PhilDeviceAssuranceClassV1 = 1 | 2 | 3;

export interface PhilDeviceEnrollmentRecordV1 {
  readonly formatVersionHash: Hex;
  readonly deviceId: Hex;
  readonly deviceKeyId: Hex;
  readonly signatureSuiteId: Hex;
  readonly publicKey: Hex;
  readonly publicKeyHash: Hex;
  readonly deviceEpoch: PhilUInt64String;
  readonly enrolledAt: PhilUInt64String;
  readonly revokedAt: PhilUInt64String;
  readonly status: PhilDeviceStatusV1;
  readonly assuranceClass: PhilDeviceAssuranceClassV1;
  readonly attestationEvidenceHash: Hex;
  readonly policyHash: Hex;
}

export interface PhilDeviceApprovalEvidenceV1 {
  readonly formatVersionHash: Hex;
  readonly authorizationEnvelopeDigest: Hex;
  readonly deviceId: Hex;
  readonly deviceKeyId: Hex;
  readonly deviceEpoch: PhilUInt64String;
  readonly approvalNonce: Hex;
  readonly approvedAt: PhilUInt64String;
  readonly approvalExpiresAt: PhilUInt64String;
  readonly humanPresentationHash: Hex;
  readonly signatureSuiteId: Hex;
  readonly signature: Hex;
}

export interface PhilDeviceApprovalSignatureVerifierV1 {
  readonly verifierId: string;
  verify(input: {
    readonly digest: Hex;
    readonly signature: Hex;
    readonly publicKey: Hex;
    readonly signatureSuiteId: Hex;
  }): boolean | Promise<boolean>;
}

export class PhilDeviceApprovalV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilDeviceApprovalV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilDeviceApprovalV1Error(code, message);
}

function positiveUInt64(value: string | number | bigint, label: string): PhilUInt64String {
  const normalized = normalizePhilUInt64(value, label);
  if (normalized === "0") {
    fail("PHIL_DEVICE_APPROVAL_ZERO_UINT64", `${label} must be non-zero`);
  }
  return normalized;
}

function normalizePublicKey(value: BytesLike): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    return fail("PHIL_DEVICE_APPROVAL_PUBLIC_KEY_INVALID", "public key is invalid");
  }
  if (getBytes(normalized).byteLength < 32) {
    fail("PHIL_DEVICE_APPROVAL_PUBLIC_KEY_INVALID", "public key is too short");
  }
  return normalized;
}

function normalizeSignature(value: BytesLike): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    return fail("PHIL_DEVICE_APPROVAL_SIGNATURE_INVALID", "signature is invalid");
  }
  if (getBytes(normalized).byteLength === 0) {
    fail("PHIL_DEVICE_APPROVAL_SIGNATURE_INVALID", "signature is empty");
  }
  return normalized;
}

function status(value: number): PhilDeviceStatusV1 {
  if (value === 1 || value === 2 || value === 3 || value === 4) return value;
  return fail("PHIL_DEVICE_APPROVAL_STATUS_INVALID", "device status is invalid");
}

function assuranceClass(value: number): PhilDeviceAssuranceClassV1 {
  if (value === 1 || value === 2 || value === 3) return value;
  return fail("PHIL_DEVICE_APPROVAL_ASSURANCE_INVALID", "device assurance class is invalid");
}

export function createPhilDeviceEnrollmentRecordV1(input: {
  deviceId: BytesLike;
  deviceKeyId: BytesLike;
  signatureSuiteId: BytesLike;
  publicKey: BytesLike;
  deviceEpoch: string | number | bigint;
  enrolledAt: string | number | bigint;
  revokedAt?: string | number | bigint;
  status?: number;
  assuranceClass: number;
  attestationEvidenceHash?: BytesLike;
  policyHash: BytesLike;
}): PhilDeviceEnrollmentRecordV1 {
  const publicKey = normalizePublicKey(input.publicKey);
  const normalizedStatus = status(input.status ?? 1);
  const revokedAt = normalizePhilUInt64(input.revokedAt ?? 0, "revokedAt");
  if (normalizedStatus === 3 && revokedAt === "0") {
    fail("PHIL_DEVICE_APPROVAL_REVOCATION_TIME_REQUIRED", "revoked devices require revokedAt");
  }
  if (normalizedStatus !== 3 && revokedAt !== "0") {
    fail("PHIL_DEVICE_APPROVAL_REVOCATION_TIME_FORBIDDEN", "non-revoked devices must have revokedAt=0");
  }
  return Object.freeze({
    formatVersionHash: PHIL_DEVICE_ENROLLMENT_RECORD_V1_HASH,
    deviceId: requirePhilNonZeroBytes32(input.deviceId, "deviceId"),
    deviceKeyId: requirePhilNonZeroBytes32(input.deviceKeyId, "deviceKeyId"),
    signatureSuiteId: requirePhilNonZeroBytes32(input.signatureSuiteId, "signatureSuiteId"),
    publicKey,
    publicKeyHash: keccak256(publicKey) as Hex,
    deviceEpoch: positiveUInt64(input.deviceEpoch, "deviceEpoch"),
    enrolledAt: positiveUInt64(input.enrolledAt, "enrolledAt"),
    revokedAt,
    status: normalizedStatus,
    assuranceClass: assuranceClass(input.assuranceClass),
    attestationEvidenceHash: normalizePhilBytes32(
      input.attestationEvidenceHash ?? keccak256("0x"),
      "attestationEvidenceHash"
    ),
    policyHash: requirePhilNonZeroBytes32(input.policyHash, "policyHash")
  });
}

export function derivePhilDeviceApprovalDigestV1(input: {
  authorizationEnvelopeDigest: BytesLike;
  deviceId: BytesLike;
  deviceKeyId: BytesLike;
  deviceEpoch: string | number | bigint;
  approvalNonce: BytesLike;
  approvedAt: string | number | bigint;
  approvalExpiresAt: string | number | bigint;
}): Hex {
  const approvedAt = positiveUInt64(input.approvedAt, "approvedAt");
  const approvalExpiresAt = positiveUInt64(input.approvalExpiresAt, "approvalExpiresAt");
  if (BigInt(approvalExpiresAt) < BigInt(approvedAt)) {
    fail("PHIL_DEVICE_APPROVAL_TIME_INVALID", "approval expiry precedes approval time");
  }
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "uint64", "uint64"],
      [
        PHIL_DEVICE_APPROVAL_V1_HASH,
        requirePhilNonZeroBytes32(input.authorizationEnvelopeDigest, "authorizationEnvelopeDigest"),
        requirePhilNonZeroBytes32(input.deviceId, "deviceId"),
        requirePhilNonZeroBytes32(input.deviceKeyId, "deviceKeyId"),
        BigInt(positiveUInt64(input.deviceEpoch, "deviceEpoch")),
        requirePhilNonZeroBytes32(input.approvalNonce, "approvalNonce"),
        BigInt(approvedAt),
        BigInt(approvalExpiresAt)
      ]
    )
  ) as Hex;
}

export function createPhilDeviceApprovalEvidenceV1(input: {
  authorizationEnvelopeDigest: BytesLike;
  enrollment: PhilDeviceEnrollmentRecordV1;
  approvalNonce: BytesLike;
  approvedAt: string | number | bigint;
  approvalExpiresAt: string | number | bigint;
  humanPresentationHash: BytesLike;
  signature: BytesLike;
}): PhilDeviceApprovalEvidenceV1 {
  const approvedAt = positiveUInt64(input.approvedAt, "approvedAt");
  const approvalExpiresAt = positiveUInt64(input.approvalExpiresAt, "approvalExpiresAt");
  void derivePhilDeviceApprovalDigestV1({
    authorizationEnvelopeDigest: input.authorizationEnvelopeDigest,
    deviceId: input.enrollment.deviceId,
    deviceKeyId: input.enrollment.deviceKeyId,
    deviceEpoch: input.enrollment.deviceEpoch,
    approvalNonce: input.approvalNonce,
    approvedAt,
    approvalExpiresAt
  });
  return Object.freeze({
    formatVersionHash: PHIL_DEVICE_APPROVAL_V1_HASH,
    authorizationEnvelopeDigest: requirePhilNonZeroBytes32(
      input.authorizationEnvelopeDigest,
      "authorizationEnvelopeDigest"
    ),
    deviceId: input.enrollment.deviceId,
    deviceKeyId: input.enrollment.deviceKeyId,
    deviceEpoch: input.enrollment.deviceEpoch,
    approvalNonce: requirePhilNonZeroBytes32(input.approvalNonce, "approvalNonce"),
    approvedAt,
    approvalExpiresAt,
    humanPresentationHash: requirePhilNonZeroBytes32(
      input.humanPresentationHash,
      "humanPresentationHash"
    ),
    signatureSuiteId: input.enrollment.signatureSuiteId,
    signature: normalizeSignature(input.signature)
  });
}

export async function verifyPhilDeviceApprovalEvidenceV1(input: {
  evidence: PhilDeviceApprovalEvidenceV1;
  enrollment: PhilDeviceEnrollmentRecordV1;
  verifier: PhilDeviceApprovalSignatureVerifierV1;
  expectedAuthorizationEnvelopeDigest: BytesLike;
  expectedHumanPresentationHash: BytesLike;
  currentDeviceEpoch: string | number | bigint;
  now: string | number | bigint;
  consumedApprovalNonces: ReadonlySet<Hex>;
}): Promise<Readonly<{ status: "verified"; deviceApprovalDigest: Hex; verifierId: string }>> {
  if (input.evidence.formatVersionHash !== PHIL_DEVICE_APPROVAL_V1_HASH) {
    fail("PHIL_DEVICE_APPROVAL_FORMAT_UNSUPPORTED", "device approval format is unsupported");
  }
  if (input.enrollment.formatVersionHash !== PHIL_DEVICE_ENROLLMENT_RECORD_V1_HASH) {
    fail("PHIL_DEVICE_APPROVAL_ENROLLMENT_FORMAT_UNSUPPORTED", "enrollment format is unsupported");
  }
  if (input.enrollment.status !== 1) {
    fail("PHIL_DEVICE_APPROVAL_DEVICE_INACTIVE", "device is not active");
  }
  const expectedEnvelope = requirePhilNonZeroBytes32(
    input.expectedAuthorizationEnvelopeDigest,
    "expectedAuthorizationEnvelopeDigest"
  );
  const expectedPresentation = requirePhilNonZeroBytes32(
    input.expectedHumanPresentationHash,
    "expectedHumanPresentationHash"
  );
  const currentDeviceEpoch = positiveUInt64(input.currentDeviceEpoch, "currentDeviceEpoch");
  const now = positiveUInt64(input.now, "now");
  if (input.evidence.authorizationEnvelopeDigest !== expectedEnvelope
    || input.evidence.humanPresentationHash !== expectedPresentation) {
    fail("PHIL_DEVICE_APPROVAL_BINDING_MISMATCH", "approval binding does not match expected action");
  }
  if (input.evidence.deviceId !== input.enrollment.deviceId
    || input.evidence.deviceKeyId !== input.enrollment.deviceKeyId
    || input.evidence.signatureSuiteId !== input.enrollment.signatureSuiteId) {
    fail("PHIL_DEVICE_APPROVAL_DEVICE_MISMATCH", "approval does not match enrolled device");
  }
  if (input.evidence.deviceEpoch !== input.enrollment.deviceEpoch
    || input.evidence.deviceEpoch !== currentDeviceEpoch) {
    fail("PHIL_DEVICE_APPROVAL_EPOCH_MISMATCH", "device epoch is stale or mismatched");
  }
  if (BigInt(now) < BigInt(input.evidence.approvedAt)
    || BigInt(now) > BigInt(input.evidence.approvalExpiresAt)) {
    fail("PHIL_DEVICE_APPROVAL_EXPIRED", "device approval is outside its validity window");
  }
  if (!input.consumedApprovalNonces
    || typeof input.consumedApprovalNonces.has !== "function") {
    fail("PHIL_DEVICE_APPROVAL_NONCE_STORE_REQUIRED", "a consumed approval nonce store is required");
  }
  if (input.consumedApprovalNonces.has(input.evidence.approvalNonce)) {
    fail("PHIL_DEVICE_APPROVAL_REPLAY", "device approval nonce was already consumed");
  }
  const digest = derivePhilDeviceApprovalDigestV1({
    authorizationEnvelopeDigest: input.evidence.authorizationEnvelopeDigest,
    deviceId: input.evidence.deviceId,
    deviceKeyId: input.evidence.deviceKeyId,
    deviceEpoch: input.evidence.deviceEpoch,
    approvalNonce: input.evidence.approvalNonce,
    approvedAt: input.evidence.approvedAt,
    approvalExpiresAt: input.evidence.approvalExpiresAt
  });
  const verified = await input.verifier.verify({
    digest,
    signature: input.evidence.signature,
    publicKey: input.enrollment.publicKey,
    signatureSuiteId: input.enrollment.signatureSuiteId
  });
  if (!verified) {
    fail("PHIL_DEVICE_APPROVAL_SIGNATURE_INVALID", "device approval signature is invalid");
  }
  return Object.freeze({
    status: "verified" as const,
    deviceApprovalDigest: digest,
    verifierId: input.verifier.verifierId
  });
}
