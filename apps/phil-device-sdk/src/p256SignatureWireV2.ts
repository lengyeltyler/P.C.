import { p256 } from "@noble/curves/p256";
import {
  concat,
  getBytes,
  hexlify,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";

export const PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_LABEL =
  "PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2" as const;
export const PHIL_ROUTINE_SIGNATURE_SUITE_V2_NAME =
  "phil-signature-p256-sha256-prehash-raw-rs-low-s-v2" as const;
export const PHIL_ROUTINE_PROVIDER_PROFILE_V2_NAME =
  "apple-secure-enclave-p256-x962-sha256-digest-der-v1" as const;
export const PHIL_ROUTINE_WIRE_ENCODING_V2_NAME =
  "phil-p256-signature-rs-64-low-s-v1" as const;

const domain = (label: string): Hex => keccak256(toUtf8Bytes(label)) as Hex;

export const PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH = domain(
  PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_LABEL
);
export const PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID = domain(
  PHIL_ROUTINE_SIGNATURE_SUITE_V2_NAME
);
export const PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID = domain(
  PHIL_ROUTINE_PROVIDER_PROFILE_V2_NAME
);
export const PHIL_ROUTINE_WIRE_ENCODING_V2_ID = domain(
  PHIL_ROUTINE_WIRE_ENCODING_V2_NAME
);

export const PHIL_P256_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
export const PHIL_P256_HALF_ORDER = PHIL_P256_ORDER >> 1n;

export class PhilP256SignatureWireV2Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilP256SignatureWireV2Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilP256SignatureWireV2Error(code, message);
}

function bytes(value: BytesLike, length: number, label: string): Uint8Array {
  let result: Uint8Array;
  try {
    result = getBytes(value);
  } catch {
    return fail("PHIL_ROUTINE_P256_BYTES_INVALID", `${label} must be bytes`);
  }
  if (result.length !== length) {
    fail("PHIL_ROUTINE_P256_LENGTH_INVALID", `${label} must be ${length} bytes`);
  }
  return result;
}

function scalar(value: BytesLike, label: string, requireLowS = false): bigint {
  const parsed = BigInt(hexlify(bytes(value, 32, label)));
  if (parsed === 0n || parsed >= PHIL_P256_ORDER) {
    fail("PHIL_ROUTINE_P256_SCALAR_INVALID", `${label} is outside the P-256 scalar range`);
  }
  if (requireLowS && parsed > PHIL_P256_HALF_ORDER) {
    fail("PHIL_ROUTINE_P256_HIGH_S_FORBIDDEN", `${label} must use canonical low-S`);
  }
  return parsed;
}

function readDerLength(input: Uint8Array, offset: number): { length: number; next: number } {
  if (offset >= input.length) fail("PHIL_ROUTINE_P256_DER_MALFORMED", "missing DER length");
  const first = input[offset]!;
  if (first < 0x80) return { length: first, next: offset + 1 };
  const octets = first & 0x7f;
  if (octets === 0 || octets > 2 || offset + 1 + octets > input.length) {
    fail("PHIL_ROUTINE_P256_DER_LENGTH_INVALID", "unsupported DER length form");
  }
  if (input[offset + 1] === 0) {
    fail("PHIL_ROUTINE_P256_DER_LENGTH_INVALID", "DER length is not minimal");
  }
  let length = 0;
  for (let i = 0; i < octets; i++) length = (length << 8) | input[offset + 1 + i]!;
  if (length < 0x80) fail("PHIL_ROUTINE_P256_DER_LENGTH_INVALID", "long DER length is not minimal");
  return { length, next: offset + 1 + octets };
}

function readDerInteger(input: Uint8Array, offset: number, label: string): { value: bigint; next: number } {
  if (input[offset] !== 0x02) fail("PHIL_ROUTINE_P256_DER_INTEGER_INVALID", `${label} tag is invalid`);
  const decoded = readDerLength(input, offset + 1);
  const end = decoded.next + decoded.length;
  if (decoded.length === 0 || decoded.length > 33 || end > input.length) {
    fail("PHIL_ROUTINE_P256_DER_INTEGER_INVALID", `${label} length is invalid`);
  }
  const encoded = input.slice(decoded.next, end);
  if ((encoded[0]! & 0x80) !== 0) {
    fail("PHIL_ROUTINE_P256_DER_INTEGER_INVALID", `${label} must be positive`);
  }
  if (encoded.length > 1 && encoded[0] === 0 && (encoded[1]! & 0x80) === 0) {
    fail("PHIL_ROUTINE_P256_DER_INTEGER_INVALID", `${label} has unnecessary sign padding`);
  }
  if (encoded.length === 33 && (encoded[0] !== 0 || (encoded[1]! & 0x80) === 0)) {
    fail("PHIL_ROUTINE_P256_DER_INTEGER_INVALID", `${label} sign padding is invalid`);
  }
  const value = BigInt(hexlify(encoded));
  if (value === 0n || value >= PHIL_P256_ORDER) {
    fail("PHIL_ROUTINE_P256_SCALAR_INVALID", `${label} is outside the P-256 scalar range`);
  }
  return { value, next: end };
}

export interface PhilP256SignatureComponentsV2 {
  readonly r: Hex;
  readonly s: Hex;
}

export function derivePhilDeviceApprovalSigningDigestV2(requestId: BytesLike): Hex {
  return sha256(concat([
    PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH,
    bytes(requestId, 32, "requestId")
  ])) as Hex;
}

export function normalizePhilP256SignatureLowSV2(input: {
  readonly r: BytesLike;
  readonly s: BytesLike;
}): PhilP256SignatureComponentsV2 {
  const r = scalar(input.r, "r");
  let s = scalar(input.s, "s");
  if (s > PHIL_P256_HALF_ORDER) s = PHIL_P256_ORDER - s;
  return Object.freeze({ r: toBeHex(r, 32) as Hex, s: toBeHex(s, 32) as Hex });
}

export function parsePhilP256DerSignatureV2(input: BytesLike): PhilP256SignatureComponentsV2 {
  const encoded = getBytes(input);
  if (encoded.length < 8 || encoded[0] !== 0x30) {
    fail("PHIL_ROUTINE_P256_DER_MALFORMED", "signature must be one DER sequence");
  }
  const sequence = readDerLength(encoded, 1);
  if (sequence.next + sequence.length !== encoded.length) {
    fail("PHIL_ROUTINE_P256_DER_TRAILING_BYTES", "DER sequence length is not exact");
  }
  const r = readDerInteger(encoded, sequence.next, "r");
  const s = readDerInteger(encoded, r.next, "s");
  if (s.next !== encoded.length) {
    fail("PHIL_ROUTINE_P256_DER_TRAILING_BYTES", "DER signature has trailing values");
  }
  return normalizePhilP256SignatureLowSV2({ r: toBeHex(r.value, 32), s: toBeHex(s.value, 32) });
}

export function encodePhilP256RawSignatureV2(input: {
  readonly r: BytesLike;
  readonly s: BytesLike;
}): Hex {
  const normalized = normalizePhilP256SignatureLowSV2(input);
  return hexlify(concat([normalized.r, normalized.s])) as Hex;
}

export function decodePhilP256RawSignatureV2(input: BytesLike): PhilP256SignatureComponentsV2 {
  const raw = bytes(input, 64, "rawSignature");
  const r = hexlify(raw.slice(0, 32)) as Hex;
  const s = hexlify(raw.slice(32)) as Hex;
  scalar(r, "r");
  scalar(s, "s", true);
  return Object.freeze({ r, s });
}

export function validatePhilP256PublicKeyX963V2(input: BytesLike): Readonly<{
  publicKeyX963: Hex;
  publicKeyX: Hex;
  publicKeyY: Hex;
  publicKeyFingerprint: Hex;
}> {
  const raw = bytes(input, 65, "publicKeyX963");
  if (raw[0] !== 0x04) fail("PHIL_ROUTINE_P256_PUBLIC_KEY_INVALID", "public key must be uncompressed X9.63");
  try {
    p256.ProjectivePoint.fromHex(hexlify(raw).slice(2));
  } catch {
    fail("PHIL_ROUTINE_P256_PUBLIC_KEY_INVALID", "public key is not a valid P-256 point");
  }
  return Object.freeze({
    publicKeyX963: hexlify(raw) as Hex,
    publicKeyX: hexlify(raw.slice(1, 33)) as Hex,
    publicKeyY: hexlify(raw.slice(33, 65)) as Hex,
    publicKeyFingerprint: sha256(raw) as Hex
  });
}

export function verifyPhilP256RawSignatureV2(input: {
  readonly digest: BytesLike;
  readonly signature: BytesLike;
  readonly publicKeyX963: BytesLike;
}): boolean {
  const digest = bytes(input.digest, 32, "digest");
  const signature = decodePhilP256RawSignatureV2(input.signature);
  const publicKey = validatePhilP256PublicKeyX963V2(input.publicKeyX963);
  try {
    return p256.verify(
      new p256.Signature(BigInt(signature.r), BigInt(signature.s)),
      digest,
      publicKey.publicKeyX963.slice(2),
      { lowS: true, prehash: false }
    );
  } catch {
    return false;
  }
}
