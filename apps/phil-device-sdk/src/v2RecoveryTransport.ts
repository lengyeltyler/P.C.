import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

import { p256 } from "@noble/curves/p256";
import {
  getAddress,
  getBytes,
  isHexString,
  toBeHex,
  zeroPadValue,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import { computePhilCoreV2RecoveryFactorDigest } from "./v2Authorization.ts";
import {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID
} from "./v2ConsumerRecovery.ts";
import {
  decodePhilCoreV2ConsumerRecoveryEvidence
} from "./v2ConsumerRecoveryAuthorityTransport.ts";
import {
  computePhilCoreV2ConsumerRecoveryEvidenceContextHash
} from "./v2ConsumerRecoveryEvidenceContext.ts";
import {
  encodePhilCoreO372RecoveryEnvelope,
  PHILCORE_O37_2_P256_HALF_ORDER,
  PHILCORE_O37_2_P256_ORDER
} from "./v2DeterministicFixtures.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "./v2Intent.ts";
import {
  computePhilCoreNativeIPhoneFactorCommitment,
  computePhilCoreNativeP256PublicMaterialHash,
  encodePhilCoreNativeIPhoneEvidence,
  PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID,
  PHILCORE_NATIVE_IPHONE_ROLE1,
  type PhilCoreNativeIPhoneDescriptorV1
} from "./v2NativeIPhoneRecovery.ts";
import {
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  type PhilCoreV2RecoveryEvidenceContextInput
} from "./v2RecoveryEvidence.ts";

export const PHILCORE_NATIVE_RECOVERY_APPROVAL_TRANSCRIPT_LABEL =
  "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1" as const;
export const PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO =
  "PHILCORE_NATIVE_RECOVERY_APPROVAL_AES256_GCM_V1" as const;
export const PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP =
  "IPHONE_TO_DESKTOP_RECOVERY_APPROVAL_V1" as const;
export const PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE =
  "DESKTOP_TO_IPHONE_RECOVERY_APPROVAL_V1" as const;
export const PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH =
  "/philcore/recovery/v1/complete" as const;
export const PHILCORE_RECOVERY_APPROVAL_MAX_TTL_MS = 5 * 60 * 1000;
export const PHILCORE_RECOVERY_APPROVAL_CLOCK_SKEW_MS = 60 * 1000;
export const PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION = 1 as const;

/** Domain label only — offline private-key derivation lives in the desktop host. */
export const PHIL39_V1_OFFLINE_DERIVATION_DOMAIN_LABEL =
  "PHILCORE_OFFLINE_RECOVERY_FACTOR_V1" as const;
export const PHIL39_V1_OFFLINE_FORMAT_PREFIX = "PHIL39-V1" as const;

export type RecoveryFactorBitmap = 3 | 5 | 6;
export type RecoveryFactorRole = 0 | 1 | 2;
export type NativeRecoveryApprovalBitmap = 3 | 6;

export type RecoveryApprovalDirection =
  | typeof PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP
  | typeof PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE;

export interface PhilCoreRecoveryApprovalRequest {
  readonly protocolVersion: number;
  readonly context: PhilCoreV2RecoveryEvidenceContextInput;
  readonly claimedContextHash: Hex;
  readonly claimedRecoveryFactorDigest: Hex;
  readonly accountVersionId: Hex | string;
  readonly securityModelId: Hex | string;
  readonly nativeRecoveryDomainId: Hex | string;
  readonly applicationIdentity: string;
  readonly localApprovalPolicy: string;
  readonly selectedRole1CredentialIdentifierCommitment: Hex | string;
  readonly selectedRole1CredentialGeneration: BigNumberish;
  readonly trustedRole1Descriptor: PhilCoreNativeIPhoneDescriptorV1;
  readonly trustedRole1PublicKey: { readonly qx: Hex | string; readonly qy: Hex | string };
  readonly sessionId: string;
  readonly sessionChallenge: string;
  readonly desktopEphemeralPublicKey: string;
  readonly issuedAt: string | number | bigint;
  readonly expiresAt: string | number | bigint;
  readonly endpoint: string;
  readonly now: string | number | bigint;
  readonly actionText?: string;
  readonly networkText?: string;
}

export interface PhilCoreEncryptedRecoveryApprovalMessage {
  readonly version: number;
  readonly sessionId: string;
  readonly phoneEphemeralPublicKey?: string | null;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export interface PhilCoreEncryptedNativeRecoveryResponse
  extends PhilCoreEncryptedRecoveryApprovalMessage {
  readonly phoneEphemeralPublicKey: string;
}

export interface PhilCoreEncryptedRecoveryAcknowledgement
  extends PhilCoreEncryptedRecoveryApprovalMessage {
  readonly phoneEphemeralPublicKey?: null;
}

export interface PhilCoreVerifiedRecoveryFactor {
  readonly role: RecoveryFactorRole | number;
  readonly evidence: Hex;
}

export interface PhilCoreRecoveryEnvelopeAssemblyInput {
  readonly request: {
    readonly actionType: BigNumberish;
    readonly account: string;
    readonly chainId: BigNumberish;
    readonly entryPoint: string;
    readonly authorizedIntentHash: Hex;
    readonly userOpHash: Hex;
    readonly requestId: Hex;
    readonly recoveryConfigHash: Hex;
    readonly validatorEpoch: BigNumberish;
    readonly recoveryEpoch: BigNumberish;
    readonly validAfter: BigNumberish;
    readonly validUntil: BigNumberish;
    readonly proposedValidatorCommitment: Hex;
    readonly proposedRecoveryConfigHash: Hex;
    readonly proposedRecoveryEpoch: BigNumberish;
    readonly primaryDeviceCommitment?: Hex;
    readonly hardwareSecurityKeyCommitment?: Hex;
    readonly recoveryFactorCommitment?: Hex;
  };
  readonly commitments: readonly [Hex, Hex, Hex];
  readonly bitmap: RecoveryFactorBitmap | number;
  readonly verifiedFactors: readonly PhilCoreVerifiedRecoveryFactor[];
}

function asBytes(value: Uint8Array | Buffer | string): Uint8Array {
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function requireBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function requireDistinctBytes32(a: Hex, b: Hex, label: string): void {
  const left = Buffer.from(getBytes(a));
  const right = Buffer.from(getBytes(b));
  if (left.length !== 32 || right.length !== 32 || timingSafeEqual(left, right)) {
    throw new Error(`${label}_must_be_distinct_bytes32`);
  }
}

function rejectEmbeddedNewlines(value: string, label: string): void {
  if (value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label}_contains_newline_pin_rejected`);
  }
}

function requireSafeString(
  value: unknown,
  label: string,
  maxLength: number
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new Error(`${label}_invalid`);
  }
  rejectEmbeddedNewlines(value, label);
  return value;
}

function requireCanonicalIntegerString(value: unknown, label: string): string {
  let asString: string;
  if (typeof value === "bigint" || typeof value === "number") {
    if (typeof value === "number" && !Number.isInteger(value)) {
      throw new Error(`${label}_noncanonical_integer`);
    }
    asString = String(value);
  } else if (typeof value === "string") {
    rejectEmbeddedNewlines(value, label);
    asString = value;
  } else {
    throw new Error(`${label}_noncanonical_integer`);
  }
  if (!/^(0|[1-9]\d*)$/u.test(asString)) {
    throw new Error(`${label}_noncanonical_leading_zero_or_invalid`);
  }
  if (String(BigInt(asString)) !== asString) {
    throw new Error(`${label}_noncanonical`);
  }
  return asString;
}

function requireCanonicalAddress(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label}_invalid_address`);
  }
  rejectEmbeddedNewlines(value, label);
  try {
    return getAddress(value).toLowerCase();
  } catch {
    throw new Error(`${label}_invalid_address`);
  }
}

function isRfc1918IPv4(address: string): boolean {
  const octets = address.split(".").map((part) => Number(part));
  if (
    octets.length !== 4
    || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  ) {
    return false;
  }
  if (octets[0] === 127) return false;
  return octets[0] === 10
    || (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31)
    || (octets[0] === 192 && octets[1] === 168);
}

export function isRfc1918RecoveryApprovalEndpoint(endpoint: string): boolean {
  if (typeof endpoint !== "string" || endpoint.length === 0 || endpoint.length > 256) {
    return false;
  }
  if (endpoint.includes("\n") || endpoint.includes("\r")) {
    return false;
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "http:") return false;
  if (url.username || url.password) return false;
  if (url.search !== "" || url.hash !== "") return false;
  if (url.pathname !== PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH) return false;
  if (url.port === "") return false;
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (url.hostname !== url.host.replace(/:\d+$/u, "")) return false;
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(url.hostname)) return false;
  return isRfc1918IPv4(url.hostname);
}

export function rolesForRecoveryFactorBitmap(
  bitmap: number
): readonly [RecoveryFactorRole, RecoveryFactorRole] {
  if (bitmap === 3) return [0, 1];
  if (bitmap === 5) return [0, 2];
  if (bitmap === 6) return [1, 2];
  throw new Error("recovery_factor_bitmap_invalid");
}

function requireNativeRecoveryApprovalBitmap(
  bitmap: number
): NativeRecoveryApprovalBitmap {
  if (bitmap === 3 || bitmap === 6) return bitmap;
  throw new Error("native_recovery_approval_bitmap_requires_role_1");
}

export function derivedRecoveryActionText(
  context: Pick<PhilCoreV2RecoveryEvidenceContextInput, "actionType">
): string {
  const actionType = Number(context.actionType);
  switch (actionType) {
    case 8:
      return "Recovery request";
    case 9:
      return "Recovery cancel";
    case 10:
      return "Recovery config rotation request";
    case 11:
      return "Recovery config rotation cancel";
    default:
      throw new Error("recovery_action_type_unsupported");
  }
}

export function derivedRecoveryNetworkText(
  context: Pick<PhilCoreV2RecoveryEvidenceContextInput, "chainId">
): string {
  return `chain ${requireCanonicalIntegerString(context.chainId, "chainId")}`;
}

function recomputeRecoveryFactorDigest(
  context: PhilCoreV2RecoveryEvidenceContextInput
): Hex {
  return computePhilCoreV2RecoveryFactorDigest(
    { chainId: context.chainId, account: context.account },
    {
      authorizedIntentHash: context.authorizedIntentHash,
      userOperationHash: context.userOperationHash,
      recoveryConfigHash: context.currentRecoveryConfigHash,
      recoveryEpoch: context.recoveryEpoch,
      factorBitmap: context.factorBitmap
    }
  ).digest;
}

function recomputeRecoveryEvidenceContextHash(
  context: PhilCoreV2RecoveryEvidenceContextInput
): Hex {
  return computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
}

function decodeBase64url(value: unknown, exactLength?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,8192}$/u.test(value)) {
    throw new Error("recovery_approval_base64url_invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (exactLength !== undefined && decoded.length !== exactLength) {
    throw new Error("recovery_approval_value_length_invalid");
  }
  return decoded;
}

function encodeBase64url(value: Uint8Array | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

export function validateUncompressedP256PublicKey(
  value: unknown,
  label = "p256_ephemeral"
): Buffer {
  if (typeof value !== "string") {
    throw new Error(`${label}_public_key_invalid`);
  }
  rejectEmbeddedNewlines(value, label);
  let bytes: Buffer;
  try {
    bytes = decodeBase64url(value, 65);
  } catch {
    throw new Error(`${label}_public_key_length_invalid`);
  }
  if (bytes[0] !== 0x04) {
    throw new Error(`${label}_public_key_uncompressed_prefix_invalid`);
  }
  try {
    p256.ProjectivePoint.fromHex(Buffer.from(bytes).toString("hex"));
  } catch {
    throw new Error(`${label}_curve_point_invalid`);
  }
  return bytes;
}

function pinIdentity(request: PhilCoreRecoveryApprovalRequest): void {
  const accountVersionId = requireBytes32(
    request.accountVersionId,
    "accountVersionId"
  );
  const securityModelId = requireBytes32(
    request.securityModelId,
    "securityModelId"
  );
  const nativeRecoveryDomainId = requireBytes32(
    request.nativeRecoveryDomainId,
    "nativeRecoveryDomainId"
  );
  if (
    accountVersionId
      !== PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID.toLowerCase()
  ) {
    throw new Error("accountVersion_identity_pin_mismatch");
  }
  if (securityModelId !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    throw new Error("securityModel_identity_pin_mismatch");
  }
  if (
    nativeRecoveryDomainId
      !== PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID.toLowerCase()
  ) {
    throw new Error("native_recovery_domain_identity_pin_mismatch");
  }

  const applicationIdentity = requireSafeString(
    request.applicationIdentity,
    "applicationIdentity",
    256
  );
  const localApprovalPolicy = requireSafeString(
    request.localApprovalPolicy,
    "localApprovalPolicy",
    256
  );
  if (applicationIdentity !== PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity) {
    throw new Error("application_identity_pin_mismatch");
  }
  if (localApprovalPolicy !== PHILCORE_NATIVE_IPHONE_ROLE1.localApprovalPolicy) {
    throw new Error("local_approval_policy_pin_mismatch");
  }
}

function pinTrustedRole1(request: PhilCoreRecoveryApprovalRequest): Hex {
  const descriptor = request.trustedRole1Descriptor;
  if (!descriptor || typeof descriptor !== "object") {
    throw new Error("trusted_role1_descriptor_required");
  }
  const publicKey = request.trustedRole1PublicKey;
  if (!publicKey || typeof publicKey !== "object") {
    throw new Error("trusted_role1_public_key_required");
  }
  const qx = requireBytes32(publicKey.qx, "trustedRole1PublicKey.qx");
  const qy = requireBytes32(publicKey.qy, "trustedRole1PublicKey.qy");

  if (Number(descriptor.role) !== 1) {
    throw new Error("trusted_role1_descriptor_role_invalid");
  }
  if (Number(descriptor.verifierKind) !== 4) {
    throw new Error("trusted_role1_descriptor_verifierKind_invalid");
  }
  if (descriptor.secureEnclaveRequired !== true) {
    throw new Error("trusted_role1_secure_enclave_required");
  }
  if (descriptor.simulatorCredential !== false) {
    throw new Error("trusted_role1_simulator_credential_forbidden");
  }

  const selectedCredential = requireBytes32(
    request.selectedRole1CredentialIdentifierCommitment,
    "selectedRole1CredentialIdentifierCommitment"
  );
  const selectedGeneration = BigInt(
    requireCanonicalIntegerString(
      request.selectedRole1CredentialGeneration,
      "selectedRole1CredentialGeneration"
    )
  );
  if (
    requireBytes32(
      descriptor.credentialIdentifierCommitment,
      "descriptor.credentialIdentifierCommitment"
    ) !== selectedCredential
  ) {
    throw new Error("role1_credential_identifier_commitment_mismatch");
  }
  if (BigInt(descriptor.credentialGeneration) !== selectedGeneration) {
    throw new Error("role1_credential_generation_descriptor_mismatch");
  }

  const materialHash = computePhilCoreNativeP256PublicMaterialHash({ qx, qy });
  if (
    requireBytes32(
      descriptor.publicVerificationMaterialHash,
      "descriptor.publicVerificationMaterialHash"
    ) !== materialHash
  ) {
    throw new Error("trusted_role1_public_key_descriptor_mismatch");
  }

  const factorCommitment = computePhilCoreNativeIPhoneFactorCommitment(descriptor);
  if (
    factorCommitment
      !== requireBytes32(
        request.context.hardwareSecurityKeyCommitment,
        "hardwareSecurityKeyCommitment"
      )
  ) {
    throw new Error("context_hardware_security_key_commitment_role1_mismatch");
  }
  return factorCommitment;
}

function validateCanonicalContextFields(
  context: PhilCoreV2RecoveryEvidenceContextInput
): {
  readonly account: string;
  readonly entryPoint: string;
  readonly chainId: string;
} {
  const account = requireCanonicalAddress(context.account, "account");
  const entryPoint = requireCanonicalAddress(context.entryPoint, "entryPoint");
  const chainId = requireCanonicalIntegerString(context.chainId, "chainId");
  requireCanonicalIntegerString(context.envelopeVersion, "envelopeVersion");
  requireCanonicalIntegerString(context.authorityKind, "authorityKind");
  requireCanonicalIntegerString(context.actionType, "actionType");
  requireCanonicalIntegerString(context.factorBitmap, "factorBitmap");
  requireCanonicalIntegerString(context.validatorEpoch, "validatorEpoch");
  requireCanonicalIntegerString(context.recoveryEpoch, "recoveryEpoch");
  requireCanonicalIntegerString(context.validAfter, "validAfter");
  requireCanonicalIntegerString(context.validUntil, "validUntil");
  requireCanonicalIntegerString(
    context.recoveryDelaySeconds,
    "recoveryDelaySeconds"
  );
  requireCanonicalIntegerString(
    context.recoveryExpirySeconds,
    "recoveryExpirySeconds"
  );
  requireCanonicalIntegerString(
    context.proposedRecoveryEpoch,
    "proposedRecoveryEpoch"
  );

  requireBytes32(context.authorizedIntentHash, "authorizedIntentHash");
  requireBytes32(context.userOperationHash, "userOperationHash");
  requireBytes32(context.requestId, "requestId");
  requireBytes32(context.currentRecoveryConfigHash, "currentRecoveryConfigHash");
  requireBytes32(
    context.proposedValidatorCommitment,
    "proposedValidatorCommitment"
  );
  requireBytes32(
    context.proposedRecoveryConfigHash,
    "proposedRecoveryConfigHash"
  );
  requireBytes32(context.primaryDeviceCommitment, "primaryDeviceCommitment");
  requireBytes32(
    context.hardwareSecurityKeyCommitment,
    "hardwareSecurityKeyCommitment"
  );
  requireBytes32(context.recoveryFactorCommitment, "recoveryFactorCommitment");
  requireBytes32(context.firstFactorCommitment, "firstFactorCommitment");
  requireBytes32(context.secondFactorCommitment, "secondFactorCommitment");

  return { account, entryPoint, chainId };
}

function validateFreshness(request: PhilCoreRecoveryApprovalRequest): void {
  const issuedAt = BigInt(
    requireCanonicalIntegerString(request.issuedAt, "issuedAt")
  );
  const expiresAt = BigInt(
    requireCanonicalIntegerString(request.expiresAt, "expiresAt")
  );
  const now = BigInt(requireCanonicalIntegerString(request.now, "now"));
  if (expiresAt <= issuedAt) {
    throw new Error("recovery_approval_freshness_window_invalid");
  }
  const lifetime = expiresAt - issuedAt;
  if (lifetime > BigInt(PHILCORE_RECOVERY_APPROVAL_MAX_TTL_MS)) {
    throw new Error("recovery_approval_session_lifetime_invalid");
  }
  if (issuedAt > now + BigInt(PHILCORE_RECOVERY_APPROVAL_CLOCK_SKEW_MS)) {
    throw new Error("recovery_approval_issuedAt_unreasonably_in_future");
  }
  if (now < issuedAt || now > expiresAt) {
    throw new Error("recovery_approval_expired_or_outside_freshness_window");
  }
}

export function validatePhilCoreRecoveryApprovalRequest(
  request: PhilCoreRecoveryApprovalRequest
): {
  readonly digest: Hex;
  readonly contextHash: Hex;
  readonly actionText: string;
  readonly networkText: string;
  readonly role1FactorCommitment: Hex;
} {
  if (
    request.protocolVersion !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION
  ) {
    throw new Error("recovery_approval_protocol_version_unsupported");
  }

  pinIdentity(request);

  const bitmap = Number(request.context.factorBitmap);
  requireNativeRecoveryApprovalBitmap(bitmap);
  rolesForRecoveryFactorBitmap(bitmap);

  const role1FactorCommitment = pinTrustedRole1(request);
  validateCanonicalContextFields(request.context);

  const digest = recomputeRecoveryFactorDigest(request.context);
  if (
    requireBytes32(
      request.claimedRecoveryFactorDigest,
      "claimedRecoveryFactorDigest"
    ) !== digest
  ) {
    throw new Error("recovery_factor_digest_mismatch_recomputed");
  }

  const contextHash = recomputeRecoveryEvidenceContextHash(request.context);
  if (
    requireBytes32(request.claimedContextHash, "claimedContextHash") !== contextHash
  ) {
    throw new Error("recovery_context_hash_mismatch_recomputed");
  }

  const actionText = derivedRecoveryActionText(request.context);
  const networkText = derivedRecoveryNetworkText(request.context);
  if (request.actionText !== undefined) {
    requireSafeString(request.actionText, "actionText", 128);
    if (request.actionText !== actionText) {
      throw new Error("recovery_action_text_mismatch");
    }
  }
  if (request.networkText !== undefined) {
    requireSafeString(request.networkText, "networkText", 128);
    if (request.networkText !== networkText) {
      throw new Error("recovery_network_text_mismatch");
    }
  }

  const sessionId = requireBytes32(request.sessionId, "sessionId");
  const sessionChallenge = requireBytes32(
    request.sessionChallenge,
    "sessionChallenge"
  );
  requireDistinctBytes32(sessionId, sessionChallenge, "session_id_challenge");

  if (!isRfc1918RecoveryApprovalEndpoint(request.endpoint)) {
    throw new Error("recovery_approval_endpoint_invalid");
  }
  requireSafeString(request.endpoint, "endpoint", 256);

  validateFreshness(request);
  validateUncompressedP256PublicKey(
    request.desktopEphemeralPublicKey,
    "desktop_ephemeral"
  );

  return { digest, contextHash, actionText, networkText, role1FactorCommitment };
}

export function buildPhilCoreNativeRecoveryApprovalTranscript(
  request: PhilCoreRecoveryApprovalRequest
): Uint8Array {
  // Validate the ORIGINAL request — never overwrite claimed digests/hashes.
  const validated = validatePhilCoreRecoveryApprovalRequest(request);
  const context = request.context;
  const lines = [
    PHILCORE_NATIVE_RECOVERY_APPROVAL_TRANSCRIPT_LABEL,
    String(PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION),
    requireCanonicalIntegerString(context.envelopeVersion, "envelopeVersion"),
    requireCanonicalIntegerString(context.authorityKind, "authorityKind"),
    requireCanonicalIntegerString(context.actionType, "actionType"),
    requireCanonicalIntegerString(context.factorBitmap, "factorBitmap"),
    requireCanonicalAddress(context.account, "account"),
    requireCanonicalIntegerString(context.chainId, "chainId"),
    requireCanonicalAddress(context.entryPoint, "entryPoint"),
    requireBytes32(context.authorizedIntentHash, "authorizedIntentHash"),
    requireBytes32(context.userOperationHash, "userOperationHash"),
    requireBytes32(context.requestId, "requestId"),
    requireBytes32(context.currentRecoveryConfigHash, "currentRecoveryConfigHash"),
    requireCanonicalIntegerString(context.validatorEpoch, "validatorEpoch"),
    requireCanonicalIntegerString(context.recoveryEpoch, "recoveryEpoch"),
    requireCanonicalIntegerString(context.validAfter, "validAfter"),
    requireCanonicalIntegerString(context.validUntil, "validUntil"),
    requireCanonicalIntegerString(
      context.recoveryDelaySeconds,
      "recoveryDelaySeconds"
    ),
    requireCanonicalIntegerString(
      context.recoveryExpirySeconds,
      "recoveryExpirySeconds"
    ),
    requireBytes32(
      context.proposedValidatorCommitment,
      "proposedValidatorCommitment"
    ),
    requireBytes32(
      context.proposedRecoveryConfigHash,
      "proposedRecoveryConfigHash"
    ),
    requireCanonicalIntegerString(
      context.proposedRecoveryEpoch,
      "proposedRecoveryEpoch"
    ),
    requireBytes32(context.primaryDeviceCommitment, "primaryDeviceCommitment"),
    requireBytes32(
      context.hardwareSecurityKeyCommitment,
      "hardwareSecurityKeyCommitment"
    ),
    requireBytes32(context.recoveryFactorCommitment, "recoveryFactorCommitment"),
    requireBytes32(context.firstFactorCommitment, "firstFactorCommitment"),
    requireBytes32(context.secondFactorCommitment, "secondFactorCommitment"),
    requireBytes32(request.accountVersionId, "accountVersionId"),
    requireBytes32(request.securityModelId, "securityModelId"),
    requireBytes32(request.nativeRecoveryDomainId, "nativeRecoveryDomainId"),
    requireSafeString(request.applicationIdentity, "applicationIdentity", 256),
    requireSafeString(request.localApprovalPolicy, "localApprovalPolicy", 256),
    requireBytes32(
      request.selectedRole1CredentialIdentifierCommitment,
      "selectedRole1CredentialIdentifierCommitment"
    ),
    requireCanonicalIntegerString(
      request.selectedRole1CredentialGeneration,
      "selectedRole1CredentialGeneration"
    ),
    validated.contextHash,
    validated.digest,
    validated.actionText,
    validated.networkText,
    requireBytes32(request.sessionId, "sessionId"),
    requireBytes32(request.sessionChallenge, "sessionChallenge"),
    requireSafeString(
      request.desktopEphemeralPublicKey,
      "desktopEphemeralPublicKey",
      256
    ),
    requireCanonicalIntegerString(request.issuedAt, "issuedAt"),
    requireCanonicalIntegerString(request.expiresAt, "expiresAt"),
    requireSafeString(request.endpoint, "endpoint", 256)
  ];
  return Buffer.from(lines.join("\n"), "utf8");
}

export function hashPhilCoreNativeRecoveryApprovalTranscript(
  transcript: Uint8Array | Buffer | string
): Uint8Array {
  return createHash("sha256").update(asBytes(transcript)).digest();
}

export function displayPhilCoreRecoveryComparisonFingerprint(
  transcriptHash: Uint8Array | Buffer | string
): string {
  const bytes = typeof transcriptHash === "string"
    ? (
      isHexString(transcriptHash)
        ? Buffer.from(getBytes(transcriptHash))
        : Buffer.from(transcriptHash, "utf8")
    )
    : Buffer.from(asBytes(transcriptHash));
  const hex = bytes.subarray(0, 12).toString("hex").toUpperCase();
  return hex.match(/.{4}/gu)!.join(" ");
}

export function deriveRecoveryApprovalAesKey(
  sharedSecret: Uint8Array | Buffer,
  transcriptHash: Uint8Array | Buffer
): Buffer {
  return Buffer.from(hkdfSync(
    "sha256",
    Buffer.from(asBytes(sharedSecret)),
    Buffer.from(asBytes(transcriptHash)),
    Buffer.from(PHILCORE_NATIVE_RECOVERY_APPROVAL_HKDF_INFO, "utf8"),
    32
  ));
}

export function encryptRecoveryApprovalMessage(input: {
  readonly value: unknown;
  readonly sessionId: string;
  readonly key: Uint8Array | Buffer;
  readonly direction: RecoveryApprovalDirection;
  readonly phoneEphemeralPublicKey?: string | null;
}): PhilCoreEncryptedRecoveryApprovalMessage {
  const sessionId = requireBytes32(input.sessionId, "sessionId");
  const key = Buffer.from(asBytes(input.key));
  if (key.length !== 32) {
    throw new Error("recovery_approval_aes_key_invalid");
  }
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`${input.direction}|${sessionId}`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(input.value), "utf8")),
    cipher.final()
  ]);
  return {
    version: PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    phoneEphemeralPublicKey: input.phoneEphemeralPublicKey ?? null,
    nonce: encodeBase64url(nonce),
    ciphertext: encodeBase64url(ciphertext),
    tag: encodeBase64url(cipher.getAuthTag())
  };
}

export function decryptRecoveryApprovalMessage(input: {
  readonly message: PhilCoreEncryptedRecoveryApprovalMessage;
  readonly key: Uint8Array | Buffer;
  readonly direction: RecoveryApprovalDirection;
}): Buffer {
  const message = input.message;
  if (
    message?.version !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION
    || typeof message.sessionId !== "string"
    || typeof message.nonce !== "string"
    || typeof message.ciphertext !== "string"
    || typeof message.tag !== "string"
  ) {
    throw new Error("recovery_approval_message_schema_invalid");
  }
  const sessionId = requireBytes32(message.sessionId, "sessionId");
  const key = Buffer.from(asBytes(input.key));
  if (key.length !== 32) {
    throw new Error("recovery_approval_aes_key_invalid");
  }
  const nonce = decodeBase64url(message.nonce, 12);
  const ciphertext = decodeBase64url(message.ciphertext);
  const tag = decodeBase64url(message.tag, 16);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(Buffer.from(`${input.direction}|${sessionId}`, "utf8"));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("recovery_approval_message_authentication_failed");
  }
}

function assertBoundedPublicString(
  value: unknown,
  label: string,
  maxLength: number
): string {
  return requireSafeString(value, label, maxLength);
}

export function validateEncryptedNativeRecoveryResponse(
  value: unknown
): PhilCoreEncryptedNativeRecoveryResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("recovery_response_schema_invalid");
  }
  const message = value as Record<string, unknown>;
  const allowed = new Set([
    "version",
    "sessionId",
    "phoneEphemeralPublicKey",
    "nonce",
    "ciphertext",
    "tag"
  ]);
  for (const key of Object.keys(message)) {
    if (!allowed.has(key)) {
      throw new Error("recovery_response_unexpected_field");
    }
  }
  if (message.version !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION) {
    throw new Error("recovery_response_version_invalid");
  }
  const sessionId = requireBytes32(message.sessionId, "sessionId");
  const phoneEphemeralPublicKey = assertBoundedPublicString(
    message.phoneEphemeralPublicKey,
    "phoneEphemeralPublicKey",
    256
  );
  validateUncompressedP256PublicKey(phoneEphemeralPublicKey, "phone_ephemeral");
  const nonce = assertBoundedPublicString(message.nonce, "nonce", 32);
  decodeBase64url(nonce, 12);
  const ciphertext = assertBoundedPublicString(
    message.ciphertext,
    "ciphertext",
    8192
  );
  decodeBase64url(ciphertext);
  const tag = assertBoundedPublicString(message.tag, "tag", 64);
  decodeBase64url(tag, 16);
  return {
    version: PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    phoneEphemeralPublicKey,
    nonce,
    ciphertext,
    tag
  };
}

export function validateEncryptedRecoveryAcknowledgement(
  value: unknown
): PhilCoreEncryptedRecoveryAcknowledgement {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("recovery_acknowledgement_schema_invalid");
  }
  const message = value as Record<string, unknown>;
  const allowed = new Set([
    "version",
    "sessionId",
    "phoneEphemeralPublicKey",
    "nonce",
    "ciphertext",
    "tag"
  ]);
  for (const key of Object.keys(message)) {
    if (!allowed.has(key)) {
      throw new Error("recovery_acknowledgement_unexpected_field");
    }
  }
  if (message.version !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION) {
    throw new Error("recovery_acknowledgement_version_invalid");
  }
  const sessionId = requireBytes32(message.sessionId, "sessionId");
  if (
    message.phoneEphemeralPublicKey !== undefined
    && message.phoneEphemeralPublicKey !== null
  ) {
    throw new Error("recovery_acknowledgement_ephemeral_key_invalid");
  }
  const nonce = assertBoundedPublicString(message.nonce, "nonce", 32);
  decodeBase64url(nonce, 12);
  const ciphertext = assertBoundedPublicString(
    message.ciphertext,
    "ciphertext",
    8192
  );
  decodeBase64url(ciphertext);
  const tag = assertBoundedPublicString(message.tag, "tag", 64);
  decodeBase64url(tag, 16);
  return {
    version: PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    phoneEphemeralPublicKey: null,
    nonce,
    ciphertext,
    tag
  };
}

const NATIVE_RESPONSE_ALLOWED_KEYS = [
  "credentialGeneration",
  "credentialIdentifierCommitment",
  "derRecoverySignature",
  "protocolVersion",
  "role1FactorCommitment",
  "sessionId",
  "transcriptHash"
] as const;

export function validateNativeRecoveryResponsePayload(
  plaintext: unknown,
  expected: {
    readonly sessionId: string;
    readonly transcriptHash: Uint8Array | Buffer | string;
    readonly role1FactorCommitment: Hex | string;
    readonly credentialIdentifierCommitment: Hex | string;
    readonly credentialGeneration: number;
  }
): {
  readonly protocolVersion: number;
  readonly sessionId: Hex;
  readonly transcriptHash: Hex;
  readonly role1FactorCommitment: Hex;
  readonly credentialIdentifierCommitment: Hex;
  readonly credentialGeneration: number;
  readonly derRecoverySignature: string;
} {
  if (!plaintext || typeof plaintext !== "object" || Array.isArray(plaintext)) {
    throw new Error("native_recovery_response_payload_schema_invalid");
  }
  const payload = plaintext as Record<string, unknown>;
  const keys = Object.keys(payload).sort();
  if (keys.join(",") !== [...NATIVE_RESPONSE_ALLOWED_KEYS].sort().join(",")) {
    throw new Error("native_recovery_response_payload_unexpected_fields");
  }
  if (payload.protocolVersion !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION) {
    throw new Error("native_recovery_response_protocol_version_invalid");
  }
  const sessionId = requireBytes32(payload.sessionId, "sessionId");
  if (sessionId !== requireBytes32(expected.sessionId, "expected.sessionId")) {
    throw new Error("native_recovery_response_session_mismatch");
  }
  const transcriptHash = requireBytes32(payload.transcriptHash, "transcriptHash");
  const expectedTranscript = typeof expected.transcriptHash === "string"
    ? (
      isHexString(expected.transcriptHash)
        ? requireBytes32(expected.transcriptHash, "expected.transcriptHash")
        : `0x${Buffer.from(expected.transcriptHash, "utf8").toString("hex")}`
    )
    : `0x${Buffer.from(asBytes(expected.transcriptHash)).toString("hex")}`;
  if (transcriptHash !== expectedTranscript.toLowerCase()) {
    throw new Error("native_recovery_response_transcript_mismatch");
  }
  const role1FactorCommitment = requireBytes32(
    payload.role1FactorCommitment,
    "role1FactorCommitment"
  );
  if (
    role1FactorCommitment
      !== requireBytes32(
        expected.role1FactorCommitment,
        "expected.role1FactorCommitment"
      )
  ) {
    throw new Error("native_recovery_response_role1_commitment_mismatch");
  }
  const credentialIdentifierCommitment = requireBytes32(
    payload.credentialIdentifierCommitment,
    "credentialIdentifierCommitment"
  );
  if (
    credentialIdentifierCommitment
      !== requireBytes32(
        expected.credentialIdentifierCommitment,
        "expected.credentialIdentifierCommitment"
      )
  ) {
    throw new Error("native_recovery_response_credential_commitment_mismatch");
  }
  const credentialGeneration = Number(
    requireCanonicalIntegerString(
      payload.credentialGeneration,
      "credentialGeneration"
    )
  );
  if (credentialGeneration !== Number(expected.credentialGeneration)) {
    throw new Error("native_recovery_response_credential_generation_mismatch");
  }
  const derRecoverySignature = requireSafeString(
    payload.derRecoverySignature,
    "derRecoverySignature",
    512
  );
  decodeBase64url(derRecoverySignature);
  return {
    protocolVersion: PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    transcriptHash,
    role1FactorCommitment,
    credentialIdentifierCommitment,
    credentialGeneration,
    derRecoverySignature
  };
}

const ACK_STATUSES = new Set(["ACCEPTED", "REJECTED"]);

export function validateNativeRecoveryAcknowledgementPayload(
  plaintext: unknown,
  expected?: {
    readonly sessionId?: string;
    readonly transcriptHash?: Uint8Array | Buffer | string;
  }
): {
  readonly protocolVersion: number;
  readonly sessionId: Hex;
  readonly transcriptHash: Hex;
  readonly status: "ACCEPTED" | "REJECTED";
} {
  if (!plaintext || typeof plaintext !== "object" || Array.isArray(plaintext)) {
    throw new Error("native_recovery_acknowledgement_payload_schema_invalid");
  }
  const payload = plaintext as Record<string, unknown>;
  const allowed = ["protocolVersion", "sessionId", "status", "transcriptHash"];
  const keys = Object.keys(payload).sort();
  if (keys.join(",") !== [...allowed].sort().join(",")) {
    throw new Error("native_recovery_acknowledgement_unexpected_fields");
  }
  if (payload.protocolVersion !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION) {
    throw new Error("native_recovery_acknowledgement_protocol_version_invalid");
  }
  const sessionId = requireBytes32(payload.sessionId, "sessionId");
  const transcriptHash = requireBytes32(payload.transcriptHash, "transcriptHash");
  const status = requireSafeString(payload.status, "status", 32);
  if (!ACK_STATUSES.has(status)) {
    throw new Error("native_recovery_acknowledgement_status_invalid");
  }
  if (expected?.sessionId !== undefined) {
    if (sessionId !== requireBytes32(expected.sessionId, "expected.sessionId")) {
      throw new Error("native_recovery_acknowledgement_session_mismatch");
    }
  }
  if (expected?.transcriptHash !== undefined) {
    const expectedTranscript = typeof expected.transcriptHash === "string"
      ? (
        isHexString(expected.transcriptHash)
          ? requireBytes32(expected.transcriptHash, "expected.transcriptHash")
          : `0x${Buffer.from(expected.transcriptHash, "utf8").toString("hex")}`
      )
      : `0x${Buffer.from(asBytes(expected.transcriptHash)).toString("hex")}`;
    if (transcriptHash !== expectedTranscript.toLowerCase()) {
      throw new Error("native_recovery_acknowledgement_transcript_mismatch");
    }
  }
  return {
    protocolVersion: PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
    sessionId,
    transcriptHash,
    status: status as "ACCEPTED" | "REJECTED"
  };
}

export function assertDistinctRecoveryApprovalNonces(
  left: Pick<PhilCoreEncryptedRecoveryApprovalMessage, "nonce">,
  right: Pick<PhilCoreEncryptedRecoveryApprovalMessage, "nonce">
): void {
  if (
    typeof left?.nonce !== "string"
    || typeof right?.nonce !== "string"
    || left.nonce.length === 0
    || right.nonce.length === 0
  ) {
    throw new Error("recovery_approval_nonce_invalid");
  }
  if (left.nonce === right.nonce) {
    throw new Error("recovery_approval_nonce_reuse_forbidden");
  }
}

function readDerLength(
  bytes: Uint8Array,
  offset: number
): { length: number; offset: number } {
  if (offset >= bytes.length) {
    throw new Error("invalid_DER_ECDSA_signature_malformed");
  }
  const first = bytes[offset]!;
  if (first < 0x80) {
    return { length: first, offset: offset + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 1) {
    throw new Error("invalid_DER_ECDSA_signature_length_nonminimal");
  }
  if (offset + 1 >= bytes.length) {
    throw new Error("invalid_DER_ECDSA_signature_malformed");
  }
  const length = bytes[offset + 1]!;
  if (length < 0x80) {
    throw new Error("invalid_DER_ECDSA_signature_length_nonminimal");
  }
  return { length, offset: offset + 2 };
}

function readDerInteger(
  bytes: Uint8Array,
  offset: number
): { value: bigint; offset: number } {
  if (offset >= bytes.length || bytes[offset] !== 0x02) {
    throw new Error("invalid_DER_ECDSA_signature_integer");
  }
  const lengthInfo = readDerLength(bytes, offset + 1);
  if (lengthInfo.length < 1 || lengthInfo.length > 33) {
    throw new Error("invalid_DER_ECDSA_signature_integer_length");
  }
  const end = lengthInfo.offset + lengthInfo.length;
  if (end > bytes.length) {
    throw new Error("invalid_DER_ECDSA_signature_malformed");
  }
  const raw = bytes.subarray(lengthInfo.offset, end);
  if ((raw[0]! & 0x80) !== 0) {
    throw new Error("invalid_DER_ECDSA_signature_negative");
  }
  if (raw.length > 1 && raw[0] === 0x00 && (raw[1]! & 0x80) === 0) {
    throw new Error("invalid_DER_ECDSA_signature_nonminimal");
  }
  if (raw.length === 1 && raw[0] === 0x00) {
    throw new Error("invalid_DER_ECDSA_signature_zero");
  }
  let value = 0n;
  for (const byte of raw) {
    value = (value << 8n) | BigInt(byte);
  }
  if (value === 0n || value >= PHILCORE_O37_2_P256_ORDER) {
    throw new Error("invalid_DER_ECDSA_signature_out_of_order");
  }
  return { value, offset: end };
}

export function parseDerEcdsaP256Signature(
  der: Uint8Array | Buffer
): { readonly r: Hex; readonly s: Hex } {
  const bytes = asBytes(der);
  if (bytes.length < 8 || bytes[0] !== 0x30) {
    throw new Error("invalid_DER_ECDSA_signature_malformed");
  }
  const sequence = readDerLength(bytes, 1);
  const sequenceEnd = sequence.offset + sequence.length;
  if (sequenceEnd !== bytes.length) {
    throw new Error("invalid_DER_ECDSA_signature_trailing_bytes");
  }
  const r = readDerInteger(bytes, sequence.offset);
  const s = readDerInteger(bytes, r.offset);
  if (s.offset !== sequenceEnd) {
    throw new Error("invalid_DER_ECDSA_signature_trailing_bytes");
  }
  return {
    r: zeroPadValue(toBeHex(r.value), 32) as Hex,
    s: zeroPadValue(toBeHex(s.value), 32) as Hex
  };
}

export function normalizeP256SignatureLowS(input: {
  readonly r: Hex | string;
  readonly s: Hex | string;
}): { readonly r: Hex; readonly s: Hex; readonly normalized: boolean } {
  let rValue: bigint;
  let sValue: bigint;
  try {
    rValue = BigInt(input.r);
    sValue = BigInt(input.s);
  } catch {
    throw new Error("p256_signature_invalid");
  }
  if (rValue === 0n || sValue === 0n) {
    throw new Error("p256_signature_component_zero_invalid");
  }
  if (
    rValue >= PHILCORE_O37_2_P256_ORDER
    || sValue >= PHILCORE_O37_2_P256_ORDER
  ) {
    throw new Error("p256_signature_out_of_range_order_invalid");
  }
  let normalized = false;
  if (sValue > PHILCORE_O37_2_P256_HALF_ORDER) {
    sValue = PHILCORE_O37_2_P256_ORDER - sValue;
    normalized = true;
  }
  if (rValue === 0n || sValue === 0n) {
    throw new Error("p256_signature_component_zero_invalid");
  }
  if (
    rValue >= PHILCORE_O37_2_P256_ORDER
    || sValue >= PHILCORE_O37_2_P256_ORDER
  ) {
    throw new Error("p256_signature_out_of_range_order_invalid");
  }
  return {
    r: zeroPadValue(toBeHex(rValue), 32) as Hex,
    s: zeroPadValue(toBeHex(sValue), 32) as Hex,
    normalized
  };
}

export function encodeNativeRecoveryEvidenceFromDer(input: {
  readonly descriptor: PhilCoreNativeIPhoneDescriptorV1;
  readonly factorCommitment: Hex;
  readonly qx: Hex;
  readonly qy: Hex;
  readonly derSignature: Uint8Array | Buffer;
  readonly digest: Hex;
}): Hex {
  const parsed = parseDerEcdsaP256Signature(input.derSignature);
  const signature = normalizeP256SignatureLowS(parsed);
  const publicKey = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(getBytes(requireBytes32(input.qx, "qx"))),
    Buffer.from(getBytes(requireBytes32(input.qy, "qy")))
  ]);
  const accepted = p256.verify(
    new p256.Signature(BigInt(signature.r), BigInt(signature.s)),
    getBytes(requireBytes32(input.digest, "digest")),
    publicKey,
    { lowS: true, prehash: false }
  );
  if (!accepted) {
    throw new Error("native_recovery_signature_invalid");
  }
  return encodePhilCoreNativeIPhoneEvidence({
    descriptor: input.descriptor,
    factorCommitment: input.factorCommitment,
    qx: input.qx,
    qy: input.qy,
    r: signature.r,
    s: signature.s
  });
}

export function assemblePhilCoreRecoveryEnvelopeFromVerifiedFactors(
  input: PhilCoreRecoveryEnvelopeAssemblyInput
): Hex {
  const bitmap = Number(input.bitmap);
  const roles = rolesForRecoveryFactorBitmap(bitmap);
  if (!Array.isArray(input.verifiedFactors) || input.verifiedFactors.length !== 2) {
    throw new Error("recovery_verified_factors_count_invalid");
  }
  const sorted = [...input.verifiedFactors].sort(
    (left, right) => Number(left.role) - Number(right.role)
  );
  const seen = new Set<number>();
  for (let index = 0; index < sorted.length; index += 1) {
    const role = Number(sorted[index]!.role);
    if (role !== roles[index]) {
      throw new Error("recovery_verified_factor_role_mismatch");
    }
    if (seen.has(role)) {
      throw new Error("recovery_verified_factor_role_duplicate");
    }
    seen.add(role);
  }
  const commitments = input.commitments.map((value, index) =>
    requireBytes32(value, `commitments[${index}]`)
  ) as [Hex, Hex, Hex];
  const request = input.request;
  const context: PhilCoreV2RecoveryEvidenceContextInput = {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: request.actionType,
    factorBitmap: bitmap,
    account: request.account,
    chainId: request.chainId,
    entryPoint: request.entryPoint,
    authorizedIntentHash: request.authorizedIntentHash,
    userOperationHash: request.userOpHash,
    requestId: request.requestId,
    currentRecoveryConfigHash: request.recoveryConfigHash,
    validatorEpoch: request.validatorEpoch,
    recoveryEpoch: request.recoveryEpoch,
    validAfter: request.validAfter,
    validUntil: request.validUntil,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment: request.proposedValidatorCommitment,
    proposedRecoveryConfigHash: request.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: request.proposedRecoveryEpoch,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: commitments[roles[0]],
    secondFactorCommitment: commitments[roles[1]]
  };
  const envelope = encodePhilCoreO372RecoveryEnvelope({
    context,
    firstFactorEvidence: sorted[0]!.evidence,
    secondFactorEvidence: sorted[1]!.evidence
  });
  decodePhilCoreV2ConsumerRecoveryEvidence(envelope, Number(request.actionType));
  return envelope;
}
