import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

import {
  getAddress,
  getBytes,
  isHexString,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHILCORE_RECOVERY_APPROVAL_CLOCK_SKEW_MS,
  PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH,
  PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
  validatePhilCoreRecoveryApprovalRequest,
  validateUncompressedP256PublicKey,
  type PhilCoreRecoveryApprovalRequest
} from "./v2RecoveryTransport.ts";

export const PHILCORE_RECOVERY_BOOTSTRAP_MAGIC = "PRB1" as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_VERSION = 0x01 as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES = 148 as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX =
  "philcore-recovery:v1:" as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES = 219 as const;
export const PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH =
  "/philcore/recovery/v1/request" as const;
export const PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH =
  PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH;
export const PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION = 1 as const;
export const PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES = 16384 as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_MAX_TTL_SECONDS = 300 as const;
export const PHILCORE_RECOVERY_BOOTSTRAP_CLOCK_SKEW_SECONDS = 60 as const;
export const PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO =
  "PHILCORE_NATIVE_RECOVERY_REQUEST_AES256_GCM_V1" as const;
export const PHILCORE_NATIVE_RECOVERY_REQUEST_AAD_DESKTOP_TO_PHONE =
  "DESKTOP_TO_IPHONE_RECOVERY_REQUEST_V1" as const;

const ZERO_BYTES32 = Buffer.alloc(32, 0);
const CONTEXT_INTEGER_KEYS = [
  "envelopeVersion",
  "authorityKind",
  "actionType",
  "factorBitmap",
  "chainId",
  "validatorEpoch",
  "recoveryEpoch",
  "validAfter",
  "validUntil",
  "recoveryDelaySeconds",
  "recoveryExpirySeconds",
  "proposedRecoveryEpoch"
] as const;
const CONTEXT_BYTES32_KEYS = [
  "authorizedIntentHash",
  "userOperationHash",
  "requestId",
  "currentRecoveryConfigHash",
  "proposedValidatorCommitment",
  "proposedRecoveryConfigHash",
  "primaryDeviceCommitment",
  "hardwareSecurityKeyCommitment",
  "recoveryFactorCommitment",
  "firstFactorCommitment",
  "secondFactorCommitment"
] as const;
const CONTEXT_ADDRESS_KEYS = ["account", "entryPoint"] as const;
const CONTEXT_ALLOWED_KEYS = new Set<string>([
  ...CONTEXT_INTEGER_KEYS,
  ...CONTEXT_BYTES32_KEYS,
  ...CONTEXT_ADDRESS_KEYS
]);
const DESCRIPTOR_INTEGER_KEYS = [
  "descriptorVersion",
  "role",
  "verifierKind",
  "credentialGeneration"
] as const;
const DESCRIPTOR_BYTES32_KEYS = [
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "publicVerificationMaterialHash",
  "credentialIdentifierCommitment",
  "applicationIdentityHash",
  "deviceCustodyCommitment",
  "localApprovalPolicyHash",
  "appAttestCommitment"
] as const;
const DESCRIPTOR_BOOL_KEYS = [
  "secureEnclaveRequired",
  "simulatorCredential"
] as const;
const DESCRIPTOR_ALLOWED_KEYS = new Set<string>([
  ...DESCRIPTOR_INTEGER_KEYS,
  ...DESCRIPTOR_BYTES32_KEYS,
  ...DESCRIPTOR_BOOL_KEYS
]);
const WIRE_TOP_LEVEL_KEYS = [
  "accountVersionId",
  "applicationIdentity",
  "claimedContextHash",
  "claimedRecoveryFactorDigest",
  "context",
  "desktopEphemeralPublicKey",
  "endpoint",
  "expiresAt",
  "issuedAt",
  "localApprovalPolicy",
  "nativeRecoveryDomainId",
  "protocolVersion",
  "securityModelId",
  "selectedRole1CredentialGeneration",
  "selectedRole1CredentialIdentifierCommitment",
  "sessionChallenge",
  "sessionId",
  "trustedRole1Descriptor",
  "trustedRole1PublicKey"
] as const;
const WIRE_TOP_LEVEL_ALLOWED = new Set<string>(WIRE_TOP_LEVEL_KEYS);
const FETCH_INIT_ALLOWED = new Set([
  "protocolVersion",
  "sessionId",
  "phoneEphemeralPublicKey",
  "fetchChallenge"
]);
const DELIVERY_ALLOWED = new Set([
  "protocolVersion",
  "sessionId",
  "nonce",
  "ciphertext",
  "tag"
]);

export interface Prb1Ticket {
  readonly magic: typeof PHILCORE_RECOVERY_BOOTSTRAP_MAGIC;
  readonly version: typeof PHILCORE_RECOVERY_BOOTSTRAP_VERSION;
  readonly sessionId: Buffer;
  readonly expiresAt: bigint;
  readonly ipv4: Buffer;
  readonly port: number;
  readonly desktopEphemeralPublicKey: Buffer;
  readonly requestHash: Buffer;
}

export interface PhilCoreRecoveryFetchInit {
  readonly protocolVersion: number;
  readonly sessionId: string;
  readonly phoneEphemeralPublicKey: string;
  readonly fetchChallenge: string;
}

export interface PhilCoreEncryptedRecoveryRequestDelivery {
  readonly protocolVersion: number;
  readonly sessionId: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

function asBytes(value: Uint8Array | Buffer | string): Uint8Array {
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
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
    if (typeof value === "number" && value < 0) {
      throw new Error(`${label}_negative`);
    }
    if (typeof value === "bigint" && value < 0n) {
      throw new Error(`${label}_negative`);
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

function requireBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function decodeBase64url(value: unknown, exactLength?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,8192}$/u.test(value)) {
    throw new Error("recovery_bootstrap_base64url_invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (exactLength !== undefined && decoded.length !== exactLength) {
    throw new Error("recovery_bootstrap_value_length_invalid");
  }
  const reencoded = decoded.toString("base64url");
  if (reencoded !== value) {
    throw new Error("recovery_bootstrap_base64url_noncanonical");
  }
  return decoded;
}

function encodeBase64url(value: Uint8Array | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function isRfc1918IPv4Octets(octets: readonly number[]): boolean {
  if (
    octets.length !== 4
    || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  ) {
    return false;
  }
  if (octets[0] === 0 || octets[0] === 127) return false;
  if (octets[0]! >= 224) return false; // multicast / reserved
  if (octets[0] === 169 && octets[1] === 254) return false; // link-local
  return octets[0] === 10
    || (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31)
    || (octets[0] === 192 && octets[1] === 168);
}

function parseIpv4Input(value: Uint8Array | Buffer | string): Buffer {
  if (typeof value === "string") {
    rejectEmbeddedNewlines(value, "ipv4");
    // Reject ambiguous leading-zero forms ("01", "001", "00") while allowing
    // canonical single-digit "0". Do not interpret octal/hex or normalize.
    if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(value)) {
      throw new Error("ipv4_address_invalid");
    }
    const octets = value.split(".").map((part) => Number(part));
    if (!isRfc1918IPv4Octets(octets)) {
      throw new Error("ipv4_rfc1918_required");
    }
    return Buffer.from(octets);
  }
  const bytes = Buffer.from(asBytes(value));
  if (bytes.length !== 4) {
    throw new Error("ipv4_length_invalid");
  }
  if (!isRfc1918IPv4Octets([...bytes])) {
    throw new Error("ipv4_rfc1918_required");
  }
  return bytes;
}

function requirePort(port: unknown): number {
  if (typeof port !== "number" || !Number.isInteger(port)) {
    throw new Error("port_noncanonical_integer");
  }
  if (port < 1024 || port > 65535) {
    throw new Error("port_out_of_range");
  }
  return port;
}

function requireNonZeroBytes32(value: Uint8Array | Buffer, label: string): Buffer {
  const bytes = Buffer.from(asBytes(value));
  if (bytes.length !== 32) {
    throw new Error(`${label}_length_invalid`);
  }
  if (timingSafeEqual(bytes, ZERO_BYTES32)) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return bytes;
}

function requireUint64(value: unknown, label: string): bigint {
  const asString = requireCanonicalIntegerString(value, label);
  const parsed = BigInt(asString);
  if (parsed > 0xffffffffffffffffn) {
    throw new Error(`${label}_uint64_overflow`);
  }
  return parsed;
}

function writeUint64BE(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value);
  return out;
}

function readUint64BE(bytes: Buffer, offset: number): bigint {
  return bytes.readBigUInt64BE(offset);
}

function requireUncompressedP256Raw(
  value: Uint8Array | Buffer | string,
  label: string
): Buffer {
  if (typeof value === "string") {
    return validateUncompressedP256PublicKey(value, label);
  }
  const bytes = Buffer.from(asBytes(value));
  if (bytes.length !== 65) {
    throw new Error(`${label}_public_key_length_invalid`);
  }
  return validateUncompressedP256PublicKey(encodeBase64url(bytes), label);
}

function ipv4ToString(ipv4: Buffer): string {
  return `${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.${ipv4[3]}`;
}

function assertPlainJsonSafe(
  value: unknown,
  seen: WeakSet<object>
): void {
  if (value === null) return;
  const type = typeof value;
  if (type === "string" || type === "boolean") return;
  if (type === "number") {
    if (!Number.isFinite(value as number)) {
      throw new Error("canonical_json_non_finite");
    }
    return;
  }
  if (type === "bigint") return;
  if (type === "function" || type === "symbol" || type === "undefined") {
    throw new Error("canonical_json_forbidden_type");
  }
  if (type !== "object") {
    throw new Error("canonical_json_forbidden_type");
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    throw new Error("canonical_json_buffer_forbidden");
  }
  if (seen.has(value as object)) {
    throw new Error("canonical_json_cycle");
  }
  seen.add(value as object);
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) {
      throw new Error("canonical_json_unexpected_prototype");
    }
    for (const entry of value) {
      assertPlainJsonSafe(entry, seen);
    }
    return;
  }
  if (proto !== Object.prototype && proto !== null) {
    throw new Error("canonical_json_unexpected_prototype");
  }
  if (
    Object.prototype.hasOwnProperty.call(value, "toJSON")
    && typeof (value as { toJSON?: unknown }).toJSON === "function"
  ) {
    throw new Error("canonical_json_tojson_forbidden");
  }
  for (const key of Object.keys(value as object)) {
    assertPlainJsonSafe((value as Record<string, unknown>)[key], seen);
  }
}

function canonicalizeForJson(value: unknown): unknown {
  if (value === null) return null;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonical_json_non_finite");
    }
    return value;
  }
  if (typeof value === "bigint") {
    return requireCanonicalIntegerString(value, "bigint");
  }
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeForJson(entry));
  }
  if (!value || typeof value !== "object") {
    throw new Error("canonical_json_forbidden_type");
  }
  const sortedKeys = Object.keys(value as object).sort((a, b) => (
    a < b ? -1 : a > b ? 1 : 0
  ));
  const out: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    out[key] = canonicalizeForJson((value as Record<string, unknown>)[key]);
  }
  return out;
}

function serializeCanonicalJson(value: unknown): Buffer {
  assertPlainJsonSafe(value, new WeakSet());
  const canonical = canonicalizeForJson(value);
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

function normalizeWireContext(
  context: Record<string, unknown>
): Record<string, unknown> {
  for (const key of Object.keys(context)) {
    if (!CONTEXT_ALLOWED_KEYS.has(key)) {
      throw new Error("canonical_request_unknown_context_field");
    }
  }
  for (const key of CONTEXT_ALLOWED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(context, key)) {
      throw new Error(`canonical_request_missing_context_field_${key}`);
    }
  }
  const out: Record<string, unknown> = {};
  for (const key of CONTEXT_INTEGER_KEYS) {
    out[key] = requireCanonicalIntegerString(context[key], key);
  }
  for (const key of CONTEXT_ADDRESS_KEYS) {
    out[key] = requireCanonicalAddress(context[key], key);
  }
  for (const key of CONTEXT_BYTES32_KEYS) {
    out[key] = requireBytes32(context[key], key);
  }
  return out;
}

function normalizeWireDescriptor(
  descriptor: Record<string, unknown>
): Record<string, unknown> {
  for (const key of Object.keys(descriptor)) {
    if (!DESCRIPTOR_ALLOWED_KEYS.has(key)) {
      throw new Error("canonical_request_unknown_descriptor_field");
    }
  }
  for (const key of DESCRIPTOR_ALLOWED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(descriptor, key)) {
      throw new Error(`canonical_request_missing_descriptor_field_${key}`);
    }
  }
  const out: Record<string, unknown> = {};
  for (const key of DESCRIPTOR_INTEGER_KEYS) {
    out[key] = requireCanonicalIntegerString(descriptor[key], key);
  }
  for (const key of DESCRIPTOR_BYTES32_KEYS) {
    out[key] = requireBytes32(descriptor[key], key);
  }
  for (const key of DESCRIPTOR_BOOL_KEYS) {
    if (typeof descriptor[key] !== "boolean") {
      throw new Error(`${key}_must_be_boolean`);
    }
    out[key] = descriptor[key];
  }
  return out;
}

function normalizeWirePublicKey(
  publicKey: Record<string, unknown>
): Record<string, unknown> {
  const allowed = new Set(["qx", "qy"]);
  for (const key of Object.keys(publicKey)) {
    if (!allowed.has(key)) {
      throw new Error("canonical_request_unknown_public_key_field");
    }
  }
  if (!Object.prototype.hasOwnProperty.call(publicKey, "qx")
    || !Object.prototype.hasOwnProperty.call(publicKey, "qy")) {
    throw new Error("canonical_request_public_key_incomplete");
  }
  return {
    qx: requireBytes32(publicKey.qx, "trustedRole1PublicKey.qx"),
    qy: requireBytes32(publicKey.qy, "trustedRole1PublicKey.qy")
  };
}

export function buildCanonicalRecoveryRequestWireObject(
  request: PhilCoreRecoveryApprovalRequest | Record<string, unknown>
): Record<string, unknown> {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("canonical_request_schema_invalid");
  }
  const input = request as Record<string, unknown>;
  for (const key of Object.keys(input)) {
    if (key === "now" || key === "actionText" || key === "networkText") {
      continue;
    }
    if (!WIRE_TOP_LEVEL_ALLOWED.has(key)) {
      throw new Error("canonical_request_unknown_top_level_field");
    }
  }
  for (const key of WIRE_TOP_LEVEL_ALLOWED) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      throw new Error(`canonical_request_missing_field_${key}`);
    }
  }
  if (input.protocolVersion !== PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION
    && input.protocolVersion !== PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION) {
    throw new Error("canonical_request_protocol_version_unsupported");
  }
  if (input.protocolVersion !== 1) {
    throw new Error("canonical_request_protocol_version_unsupported");
  }
  if (!input.context || typeof input.context !== "object" || Array.isArray(input.context)) {
    throw new Error("canonical_request_context_invalid");
  }
  if (
    !input.trustedRole1Descriptor
    || typeof input.trustedRole1Descriptor !== "object"
    || Array.isArray(input.trustedRole1Descriptor)
  ) {
    throw new Error("canonical_request_descriptor_invalid");
  }
  if (
    !input.trustedRole1PublicKey
    || typeof input.trustedRole1PublicKey !== "object"
    || Array.isArray(input.trustedRole1PublicKey)
  ) {
    throw new Error("canonical_request_public_key_invalid");
  }

  const desktopEphemeralPublicKey = requireSafeString(
    input.desktopEphemeralPublicKey,
    "desktopEphemeralPublicKey",
    256
  );
  validateUncompressedP256PublicKey(desktopEphemeralPublicKey, "desktop_ephemeral");
  const endpoint = requireSafeString(input.endpoint, "endpoint", 256);

  return {
    protocolVersion: 1,
    context: normalizeWireContext(input.context as Record<string, unknown>),
    claimedContextHash: requireBytes32(input.claimedContextHash, "claimedContextHash"),
    claimedRecoveryFactorDigest: requireBytes32(
      input.claimedRecoveryFactorDigest,
      "claimedRecoveryFactorDigest"
    ),
    accountVersionId: requireBytes32(input.accountVersionId, "accountVersionId"),
    securityModelId: requireBytes32(input.securityModelId, "securityModelId"),
    nativeRecoveryDomainId: requireBytes32(
      input.nativeRecoveryDomainId,
      "nativeRecoveryDomainId"
    ),
    applicationIdentity: requireSafeString(
      input.applicationIdentity,
      "applicationIdentity",
      256
    ),
    localApprovalPolicy: requireSafeString(
      input.localApprovalPolicy,
      "localApprovalPolicy",
      256
    ),
    selectedRole1CredentialIdentifierCommitment: requireBytes32(
      input.selectedRole1CredentialIdentifierCommitment,
      "selectedRole1CredentialIdentifierCommitment"
    ),
    selectedRole1CredentialGeneration: requireCanonicalIntegerString(
      input.selectedRole1CredentialGeneration,
      "selectedRole1CredentialGeneration"
    ),
    trustedRole1Descriptor: normalizeWireDescriptor(
      input.trustedRole1Descriptor as Record<string, unknown>
    ),
    trustedRole1PublicKey: normalizeWirePublicKey(
      input.trustedRole1PublicKey as Record<string, unknown>
    ),
    sessionId: requireBytes32(input.sessionId, "sessionId"),
    sessionChallenge: requireBytes32(input.sessionChallenge, "sessionChallenge"),
    desktopEphemeralPublicKey,
    issuedAt: requireCanonicalIntegerString(input.issuedAt, "issuedAt"),
    expiresAt: requireCanonicalIntegerString(input.expiresAt, "expiresAt"),
    endpoint
  };
}

export function serializeCanonicalRecoveryRequest(
  request: PhilCoreRecoveryApprovalRequest | Record<string, unknown>
): Buffer {
  const wire = buildCanonicalRecoveryRequestWireObject(request);
  const bytes = serializeCanonicalJson(wire);
  if (bytes.length > PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES) {
    throw new Error("canonical_request_too_large");
  }
  return bytes;
}

export function computePhilCoreRecoveryRequestHash(
  bytesOrRequest:
    | Uint8Array
    | Buffer
    | PhilCoreRecoveryApprovalRequest
    | Record<string, unknown>
): Buffer {
  const bytes = Buffer.isBuffer(bytesOrRequest) || bytesOrRequest instanceof Uint8Array
    ? Buffer.from(asBytes(bytesOrRequest))
    : serializeCanonicalRecoveryRequest(
      bytesOrRequest as PhilCoreRecoveryApprovalRequest | Record<string, unknown>
    );
  return createHash("sha256").update(bytes).digest();
}

export function parseCanonicalRecoveryRequestBytes(
  bytes: Uint8Array | Buffer,
  options: {
    readonly now: bigint | number | string;
    readonly expectedHash?: Uint8Array | Buffer;
  }
): PhilCoreRecoveryApprovalRequest {
  const raw = Buffer.from(asBytes(bytes));
  if (raw.length === 0 || raw.length > PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES) {
    throw new Error("canonical_request_length_invalid");
  }
  if (options.expectedHash !== undefined) {
    const expected = Buffer.from(asBytes(options.expectedHash));
    if (expected.length !== 32) {
      throw new Error("canonical_request_expected_hash_length_invalid");
    }
    const actual = createHash("sha256").update(raw).digest();
    if (!timingSafeEqual(actual, expected)) {
      throw new Error("canonical_request_hash_mismatch");
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("canonical_request_json_invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("canonical_request_schema_invalid");
  }
  const wire = buildCanonicalRecoveryRequestWireObject(
    parsed as Record<string, unknown>
  );
  const reserialized = serializeCanonicalJson(wire);
  if (
    reserialized.length !== raw.length
    || !timingSafeEqual(reserialized, raw)
  ) {
    throw new Error("canonical_request_reserialize_mismatch");
  }

  const now = requireCanonicalIntegerString(options.now, "now");
  const request = {
    ...(wire as unknown as PhilCoreRecoveryApprovalRequest),
    now
  };
  validatePhilCoreRecoveryApprovalRequest(request);
  return request;
}

export function encodePrb1Ticket(ticket: {
  readonly sessionId: Uint8Array | Buffer;
  readonly expiresAt: bigint | number | string;
  readonly ipv4: Uint8Array | Buffer | string;
  readonly port: number;
  readonly desktopEphemeralPublicKey: Uint8Array | Buffer | string;
  readonly requestHash: Uint8Array | Buffer;
}): Buffer {
  const sessionId = requireNonZeroBytes32(ticket.sessionId, "sessionId");
  const expiresAt = requireUint64(ticket.expiresAt, "expiresAt");
  const ipv4 = parseIpv4Input(ticket.ipv4);
  const port = requirePort(ticket.port);
  const desktopEphemeralPublicKey = requireUncompressedP256Raw(
    ticket.desktopEphemeralPublicKey,
    "desktop_ephemeral"
  );
  const requestHash = requireNonZeroBytes32(ticket.requestHash, "requestHash");

  const out = Buffer.alloc(PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES);
  out.write(PHILCORE_RECOVERY_BOOTSTRAP_MAGIC, 0, 4, "ascii");
  out[4] = PHILCORE_RECOVERY_BOOTSTRAP_VERSION;
  sessionId.copy(out, 5);
  writeUint64BE(expiresAt).copy(out, 37);
  ipv4.copy(out, 45);
  out.writeUInt16BE(port, 49);
  desktopEphemeralPublicKey.copy(out, 51);
  requestHash.copy(out, 116);
  return out;
}

export function decodePrb1Ticket(bytes: Uint8Array | Buffer): Prb1Ticket {
  const raw = Buffer.from(asBytes(bytes));
  if (raw.length !== PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES) {
    throw new Error(
      raw.length < PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES
        ? "prb1_ticket_truncated"
        : "prb1_ticket_trailing_bytes"
    );
  }
  const magic = raw.subarray(0, 4).toString("ascii");
  if (magic !== PHILCORE_RECOVERY_BOOTSTRAP_MAGIC) {
    throw new Error("prb1_magic_invalid");
  }
  if (raw[4] !== PHILCORE_RECOVERY_BOOTSTRAP_VERSION) {
    throw new Error("prb1_version_invalid");
  }
  const sessionId = requireNonZeroBytes32(raw.subarray(5, 37), "sessionId");
  const expiresAt = readUint64BE(raw, 37);
  const ipv4 = parseIpv4Input(raw.subarray(45, 49));
  const port = raw.readUInt16BE(49);
  requirePort(port);
  const desktopEphemeralPublicKey = requireUncompressedP256Raw(
    raw.subarray(51, 116),
    "desktop_ephemeral"
  );
  const requestHash = requireNonZeroBytes32(raw.subarray(116, 148), "requestHash");
  return {
    magic: PHILCORE_RECOVERY_BOOTSTRAP_MAGIC,
    version: PHILCORE_RECOVERY_BOOTSTRAP_VERSION,
    sessionId,
    expiresAt,
    ipv4,
    port,
    desktopEphemeralPublicKey,
    requestHash
  };
}

export function formatPrb1Uri(ticketBytes: Uint8Array | Buffer): string {
  const raw = Buffer.from(asBytes(ticketBytes));
  if (raw.length !== PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES) {
    throw new Error("prb1_ticket_length_invalid");
  }
  decodePrb1Ticket(raw);
  const encoded = encodeBase64url(raw);
  if (encoded.includes("=")) {
    throw new Error("prb1_uri_padding_forbidden");
  }
  const uri = `${PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX}${encoded}`;
  if (Buffer.byteLength(uri, "ascii") !== PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES) {
    throw new Error("prb1_uri_length_invalid");
  }
  return uri;
}

export function parsePrb1Uri(uri: string): Buffer {
  if (typeof uri !== "string") {
    throw new Error("prb1_uri_invalid");
  }
  if (uri.includes("\n") || uri.includes("\r") || uri.includes(" ") || uri.includes("\t")) {
    throw new Error("prb1_uri_whitespace_forbidden");
  }
  if (uri.includes("?") || uri.includes("#")) {
    throw new Error("prb1_uri_query_or_fragment_forbidden");
  }
  if (!uri.startsWith(PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX)) {
    throw new Error("prb1_uri_prefix_invalid");
  }
  if (Buffer.byteLength(uri, "ascii") !== PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES) {
    throw new Error("prb1_uri_length_invalid");
  }
  const payload = uri.slice(PHILCORE_RECOVERY_BOOTSTRAP_URI_PREFIX.length);
  if (payload.includes("=")) {
    throw new Error("prb1_uri_padding_forbidden");
  }
  if (!/^[A-Za-z0-9_-]+$/u.test(payload)) {
    throw new Error("prb1_uri_base64url_invalid");
  }
  const decoded = Buffer.from(payload, "base64url");
  if (decoded.toString("base64url") !== payload) {
    throw new Error("prb1_uri_base64url_noncanonical");
  }
  if (decoded.length !== PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES) {
    throw new Error("prb1_uri_ticket_length_invalid");
  }
  decodePrb1Ticket(decoded);
  return decoded;
}

export function validatePrb1TicketPolicy(input: {
  readonly ticket: Prb1Ticket;
  readonly nowSeconds: bigint | number | string;
  readonly boundRequestExpiresAtMs?: bigint | number | string;
}): void {
  const ticket = input.ticket;
  requireNonZeroBytes32(ticket.sessionId, "sessionId");
  requireNonZeroBytes32(ticket.requestHash, "requestHash");
  parseIpv4Input(ticket.ipv4);
  requirePort(ticket.port);
  requireUncompressedP256Raw(ticket.desktopEphemeralPublicKey, "desktop_ephemeral");

  const nowSeconds = requireUint64(input.nowSeconds, "nowSeconds");
  const expiresAt = requireUint64(ticket.expiresAt, "expiresAt");
  if (!(nowSeconds < expiresAt)) {
    throw new Error("prb1_ticket_expired");
  }
  const maxExpiresAt = nowSeconds
    + BigInt(PHILCORE_RECOVERY_BOOTSTRAP_MAX_TTL_SECONDS)
    + BigInt(PHILCORE_RECOVERY_BOOTSTRAP_CLOCK_SKEW_SECONDS);
  if (expiresAt > maxExpiresAt) {
    throw new Error("prb1_ticket_expiry_exceeds_ttl_skew");
  }

  if (input.boundRequestExpiresAtMs !== undefined) {
    const boundMs = requireCanonicalIntegerString(
      input.boundRequestExpiresAtMs,
      "boundRequestExpiresAtMs"
    );
    const boundSeconds = BigInt(boundMs) / 1000n; // floor
    if (expiresAt > boundSeconds) {
      throw new Error("prb1_ticket_expiry_outlives_bound_request");
    }
  }
}

export function buildRequestEndpointFromTicket(ticket: Prb1Ticket): string {
  parseIpv4Input(ticket.ipv4);
  requirePort(ticket.port);
  return `http://${ipv4ToString(ticket.ipv4)}:${ticket.port}${PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`;
}

function decodeFetchChallenge(
  value: Uint8Array | Buffer | string
): Buffer {
  if (typeof value === "string") {
    if (isHexString(value, 32)) {
      return Buffer.from(getBytes(value));
    }
    return decodeBase64url(value, 32);
  }
  const bytes = Buffer.from(asBytes(value));
  if (bytes.length !== 32) {
    throw new Error("fetchChallenge_length_invalid");
  }
  return bytes;
}

export function buildFetchInit(input: {
  readonly sessionId: string;
  readonly phoneEphemeralPublicKey: string;
  readonly fetchChallenge: Uint8Array | Buffer | string;
}): PhilCoreRecoveryFetchInit {
  const sessionId = requireBytes32(input.sessionId, "sessionId");
  const phoneEphemeralPublicKey = requireSafeString(
    input.phoneEphemeralPublicKey,
    "phoneEphemeralPublicKey",
    256
  );
  validateUncompressedP256PublicKey(phoneEphemeralPublicKey, "phone_ephemeral");
  const fetchChallenge = encodeBase64url(decodeFetchChallenge(input.fetchChallenge));
  return {
    protocolVersion: PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
    sessionId,
    phoneEphemeralPublicKey,
    fetchChallenge
  };
}

export function validateFetchInit(value: unknown): PhilCoreRecoveryFetchInit {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("fetch_init_schema_invalid");
  }
  const message = value as Record<string, unknown>;
  for (const key of Object.keys(message)) {
    if (!FETCH_INIT_ALLOWED.has(key)) {
      throw new Error("fetch_init_unexpected_field");
    }
  }
  for (const key of FETCH_INIT_ALLOWED) {
    if (!Object.prototype.hasOwnProperty.call(message, key)) {
      throw new Error(`fetch_init_missing_field_${key}`);
    }
  }
  if (message.protocolVersion !== PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION) {
    throw new Error("fetch_init_protocol_version_invalid");
  }
  return buildFetchInit({
    sessionId: message.sessionId as string,
    phoneEphemeralPublicKey: message.phoneEphemeralPublicKey as string,
    fetchChallenge: message.fetchChallenge as string
  });
}

export function deriveRecoveryRequestAesKey(
  sharedSecret: Uint8Array | Buffer,
  requestHash: Uint8Array | Buffer
): Buffer {
  const ikm = Buffer.from(asBytes(sharedSecret));
  const salt = Buffer.from(asBytes(requestHash));
  if (ikm.length !== 32) {
    throw new Error("recovery_request_shared_secret_length_invalid");
  }
  if (salt.length !== 32) {
    throw new Error("recovery_request_hash_length_invalid");
  }
  return Buffer.from(hkdfSync(
    "sha256",
    ikm,
    salt,
    Buffer.from(PHILCORE_NATIVE_RECOVERY_REQUEST_HKDF_INFO, "utf8"),
    32
  ));
}

function resolvePhoneEphemeralRaw(
  phoneEphemeralPublicKey: string | Uint8Array | Buffer
): Buffer {
  if (typeof phoneEphemeralPublicKey === "string") {
    return validateUncompressedP256PublicKey(
      phoneEphemeralPublicKey,
      "phone_ephemeral"
    );
  }
  return requireUncompressedP256Raw(phoneEphemeralPublicKey, "phone_ephemeral");
}

export function buildRequestDeliveryAad(input: {
  readonly sessionId: string;
  readonly requestHash: Uint8Array | Buffer;
  readonly phoneEphemeralPublicKey: string | Uint8Array | Buffer;
  readonly fetchChallenge: Uint8Array | Buffer | string;
}): Buffer {
  const sessionId = requireBytes32(input.sessionId, "sessionId");
  const requestHash = requireNonZeroBytes32(input.requestHash, "requestHash");
  const phoneRaw = resolvePhoneEphemeralRaw(input.phoneEphemeralPublicKey);
  const fetchChallenge = decodeFetchChallenge(input.fetchChallenge);
  const phoneFingerprint = createHash("sha256").update(phoneRaw).digest("hex");
  const aad = [
    PHILCORE_NATIVE_RECOVERY_REQUEST_AAD_DESKTOP_TO_PHONE,
    sessionId,
    requestHash.toString("hex"),
    phoneFingerprint,
    fetchChallenge.toString("hex")
  ].join("|");
  return Buffer.from(aad, "utf8");
}

function validateEncryptedDeliveryMessage(
  value: unknown
): PhilCoreEncryptedRecoveryRequestDelivery {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("request_delivery_schema_invalid");
  }
  const message = value as Record<string, unknown>;
  for (const key of Object.keys(message)) {
    if (!DELIVERY_ALLOWED.has(key)) {
      throw new Error("request_delivery_unexpected_field");
    }
  }
  if (message.protocolVersion !== PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION) {
    throw new Error("request_delivery_protocol_version_invalid");
  }
  const sessionId = requireBytes32(message.sessionId, "sessionId");
  const nonce = requireSafeString(message.nonce, "nonce", 32);
  decodeBase64url(nonce, 12);
  const ciphertext = requireSafeString(message.ciphertext, "ciphertext", 24576);
  decodeBase64url(ciphertext);
  const tag = requireSafeString(message.tag, "tag", 64);
  decodeBase64url(tag, 16);
  return {
    protocolVersion: PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
    sessionId,
    nonce,
    ciphertext,
    tag
  };
}

export function encryptRecoveryRequestDelivery(input: {
  readonly plaintext: Uint8Array | Buffer;
  readonly sessionId: string;
  readonly key: Uint8Array | Buffer;
  readonly requestHash: Uint8Array | Buffer;
  readonly phoneEphemeralPublicKey: string;
  readonly fetchChallenge: Uint8Array | Buffer | string;
}): PhilCoreEncryptedRecoveryRequestDelivery {
  const sessionId = requireBytes32(input.sessionId, "sessionId");
  const key = Buffer.from(asBytes(input.key));
  if (key.length !== 32) {
    throw new Error("recovery_request_aes_key_invalid");
  }
  const plaintext = Buffer.from(asBytes(input.plaintext));
  if (plaintext.length === 0 || plaintext.length > PHILCORE_RECOVERY_REQUEST_MAX_WIRE_BYTES) {
    throw new Error("recovery_request_plaintext_length_invalid");
  }
  const aad = buildRequestDeliveryAad({
    sessionId,
    requestHash: input.requestHash,
    phoneEphemeralPublicKey: input.phoneEphemeralPublicKey,
    fetchChallenge: input.fetchChallenge
  });
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    protocolVersion: PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
    sessionId,
    nonce: encodeBase64url(nonce),
    ciphertext: encodeBase64url(ciphertext),
    tag: encodeBase64url(cipher.getAuthTag())
  };
}

export function decryptRecoveryRequestDelivery(input: {
  readonly message: PhilCoreEncryptedRecoveryRequestDelivery;
  readonly key: Uint8Array | Buffer;
  readonly sessionId: string;
  readonly requestHash: Uint8Array | Buffer;
  readonly phoneEphemeralPublicKey: string;
  readonly fetchChallenge: Uint8Array | Buffer | string;
}): Buffer {
  const message = validateEncryptedDeliveryMessage(input.message);
  const sessionId = requireBytes32(input.sessionId, "sessionId");
  if (message.sessionId !== sessionId) {
    throw new Error("request_delivery_session_mismatch");
  }
  const key = Buffer.from(asBytes(input.key));
  if (key.length !== 32) {
    throw new Error("recovery_request_aes_key_invalid");
  }
  const aad = buildRequestDeliveryAad({
    sessionId,
    requestHash: input.requestHash,
    phoneEphemeralPublicKey: input.phoneEphemeralPublicKey,
    fetchChallenge: input.fetchChallenge
  });
  const nonce = decodeBase64url(message.nonce, 12);
  const ciphertext = decodeBase64url(message.ciphertext);
  const tag = decodeBase64url(message.tag, 16);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("request_delivery_authentication_failed");
  }
}

/** Exported for tests that need skew constant parity with O.44 ms skew. */
export const PHILCORE_RECOVERY_BOOTSTRAP_O44_SKEW_MS =
  PHILCORE_RECOVERY_APPROVAL_CLOCK_SKEW_MS;

export type { BigNumberish };
