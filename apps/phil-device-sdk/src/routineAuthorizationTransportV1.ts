import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  hkdfSync,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import { AbiCoder, getBytes, hexlify, keccak256, sha256, toUtf8Bytes, type BytesLike } from "ethers";

import type { Hex } from "./hashes.ts";
import { parsePhilStrictJsonObjectV1 } from "./routineAuthorizationV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const PREFIX = "phil-step6c-routine-v1:";
const MAGIC = Buffer.from("PHIL6C01", "ascii");

export const PHIL_ROUTINE_TRANSPORT_V1 = Object.freeze({
  protocolVersion: 1 as const,
  transcriptLabel: "PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1",
  hkdfInfo: "PHIL_ROUTINE_AUTHORIZATION_AES256_GCM_V1",
  requestAad: "DESKTOP_TO_IPHONE_ROUTINE_AUTHORIZATION_V1",
  responseAad: "IPHONE_TO_DESKTOP_ROUTINE_AUTHORIZATION_V1",
  beginPath: "/philcore/routine/v1/begin",
  completePath: "/philcore/routine/v1/complete",
  terminalPath: "/philcore/routine/v1/terminal",
  terminalAad: "IPHONE_TO_DESKTOP_ROUTINE_TERMINAL_V1",
  terminalAckAad: "DESKTOP_TO_IPHONE_ROUTINE_TERMINAL_ACK_V1",
  qrPrefix: PREFIX,
  bootstrapBytes: 216,
  maximumEncryptedPlaintextBytes: 65503,
  maximumHttpBodyBytes: 65536
});

export class PhilRoutineTransportV1Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilRoutineTransportV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilRoutineTransportV1Error(code, message);
}

function exactBytes(value: BytesLike, length: number, label: string): Buffer {
  let bytes: Buffer;
  try { bytes = Buffer.from(getBytes(value)); }
  catch { return fail("PHIL_ROUTINE_TRANSPORT_BYTES_INVALID", `${label} is not bytes`); }
  if (bytes.length !== length) fail("PHIL_ROUTINE_TRANSPORT_LENGTH_INVALID", `${label} must be ${length} bytes`);
  return bytes;
}

function nonzero32(value: BytesLike, label: string): Buffer {
  const bytes = exactBytes(value, 32, label);
  if (bytes.every((byte) => byte === 0)) fail("PHIL_ROUTINE_TRANSPORT_ZERO_INVALID", `${label} must be non-zero`);
  return bytes;
}

function uint(value: string | number | bigint, bits: 16 | 32 | 64, label: string, positive = false): bigint {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch { return fail("PHIL_ROUTINE_TRANSPORT_UNSIGNED_INVALID", `${label} must be canonical uint${bits}`); }
  if (parsed < 0n || parsed >= (1n << BigInt(bits)) || (positive && parsed === 0n)) {
    fail("PHIL_ROUTINE_TRANSPORT_UNSIGNED_INVALID", `${label} must fit uint${bits}`);
  }
  return parsed;
}

function validateP256PublicKey(value: BytesLike, label: string): Buffer {
  const bytes = exactBytes(value, 65, label);
  if (bytes[0] !== 4) fail("PHIL_ROUTINE_TRANSPORT_PUBLIC_KEY_INVALID", `${label} must be uncompressed X9.63`);
  try { const validator=createECDH("prime256v1");validator.generateKeys();validator.computeSecret(bytes); }
  catch { return fail("PHIL_ROUTINE_TRANSPORT_PUBLIC_KEY_INVALID", `${label} is not a valid P-256 point`); }
  return bytes;
}

export function encodePhilRoutineBase64UrlV1(value: BytesLike): string {
  return Buffer.from(getBytes(value)).toString("base64url");
}

export function decodePhilRoutineBase64UrlV1(value: string, label = "base64url"): Buffer {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return fail("PHIL_ROUTINE_TRANSPORT_BASE64URL_INVALID", `${label} must be canonical unpadded base64url`);
  }
  let decoded: Buffer;
  try { decoded = Buffer.from(value, "base64url"); }
  catch { return fail("PHIL_ROUTINE_TRANSPORT_BASE64URL_INVALID", `${label} is not base64url`); }
  if (decoded.toString("base64url") !== value) {
    fail("PHIL_ROUTINE_TRANSPORT_BASE64URL_INVALID", `${label} is not canonically encoded`);
  }
  return decoded;
}

function ipv4Bytes(value: string): Buffer {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) {
    return fail("PHIL_ROUTINE_TRANSPORT_IPV4_INVALID", "IPv4 must be canonical dotted decimal");
  }
  const octets = value.split(".").map(Number);
  if (octets.some((octet) => octet > 255)) fail("PHIL_ROUTINE_TRANSPORT_IPV4_INVALID", "IPv4 octet is out of range");
  const privateAddress = octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168);
  if (!privateAddress) fail("PHIL_ROUTINE_TRANSPORT_PRIVATE_IPV4_REQUIRED", "routine transport requires RFC1918 IPv4");
  return Buffer.from(octets);
}

function bytesToIpv4(value: Uint8Array): string {
  const result = [...value].join(".");
  ipv4Bytes(result);
  return result;
}

function writeUint(buffer: Buffer, offset: number, value: bigint, bytes: 2 | 4 | 8): void {
  if (bytes === 2) buffer.writeUInt16BE(Number(value), offset);
  else if (bytes === 4) buffer.writeUInt32BE(Number(value), offset);
  else buffer.writeBigUInt64BE(value, offset);
}

export interface PhilRoutineTransportBootstrapV1 {
  readonly sessionId: Hex;
  readonly ipv4: string;
  readonly port: number;
  readonly desktopPublicKeyX963: Hex;
  readonly requestId: Hex;
  readonly expiresAt: string;
}

function normalizeBootstrap(input: PhilRoutineTransportBootstrapV1): PhilRoutineTransportBootstrapV1 {
  const port = uint(input.port, 16, "port", true);
  const expiresAt = uint(input.expiresAt, 64, "expiresAt", true);
  return Object.freeze({
    sessionId: hexlify(nonzero32(input.sessionId, "sessionId")).toLowerCase() as Hex,
    ipv4: bytesToIpv4(ipv4Bytes(input.ipv4)),
    port: Number(port),
    desktopPublicKeyX963: hexlify(validateP256PublicKey(input.desktopPublicKeyX963, "desktopPublicKeyX963")).toLowerCase() as Hex,
    requestId: hexlify(nonzero32(input.requestId, "requestId")).toLowerCase() as Hex,
    expiresAt: expiresAt.toString()
  });
}

export function encodePhilRoutineTransportBootstrapV1(input: PhilRoutineTransportBootstrapV1): string {
  const value = normalizeBootstrap(input);
  const bytes = Buffer.alloc(PHIL_ROUTINE_TRANSPORT_V1.bootstrapBytes);
  MAGIC.copy(bytes, 0);
  bytes[8] = 1;
  nonzero32(value.sessionId, "sessionId").copy(bytes, 9);
  ipv4Bytes(value.ipv4).copy(bytes, 41);
  writeUint(bytes, 45, BigInt(value.port), 2);
  Buffer.from(getBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.beginPath)))).copy(bytes, 47);
  Buffer.from(getBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.completePath)))).copy(bytes, 79);
  validateP256PublicKey(value.desktopPublicKeyX963, "desktopPublicKeyX963").copy(bytes, 111);
  nonzero32(value.requestId, "requestId").copy(bytes, 176);
  writeUint(bytes, 208, BigInt(value.expiresAt), 8);
  return `${PREFIX}${bytes.toString("base64url")}`;
}

export function decodePhilRoutineTransportBootstrapV1(text: string): PhilRoutineTransportBootstrapV1 {
  if (typeof text !== "string" || !text.startsWith(PREFIX) || text.trim() !== text) {
    return fail("PHIL_ROUTINE_TRANSPORT_BOOTSTRAP_INVALID", "routine bootstrap prefix is invalid");
  }
  const encoded = text.slice(PREFIX.length);
  const bytes = decodePhilRoutineBase64UrlV1(encoded, "bootstrap");
  if (bytes.length !== 216 || !timingSafeEqual(bytes.subarray(0, 8), MAGIC) || bytes[8] !== 1) {
    fail("PHIL_ROUTINE_TRANSPORT_BOOTSTRAP_INVALID", "routine bootstrap magic, version, or length is invalid");
  }
  const beginHash = exactBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.beginPath)), 32, "beginPathHash");
  const completeHash = exactBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.completePath)), 32, "completePathHash");
  if (!timingSafeEqual(bytes.subarray(47, 79), beginHash)
    || !timingSafeEqual(bytes.subarray(79, 111), completeHash)) {
    fail("PHIL_ROUTINE_TRANSPORT_BOOTSTRAP_INVALID", "routine bootstrap path hashes are invalid");
  }
  const normalized = normalizeBootstrap({
    sessionId: hexlify(bytes.subarray(9, 41)) as Hex,
    ipv4: bytesToIpv4(bytes.subarray(41, 45)),
    port: bytes.readUInt16BE(45),
    desktopPublicKeyX963: hexlify(bytes.subarray(111, 176)) as Hex,
    requestId: hexlify(bytes.subarray(176, 208)) as Hex,
    expiresAt: bytes.readBigUInt64BE(208).toString()
  });
  if (encodePhilRoutineTransportBootstrapV1(normalized) !== text) {
    fail("PHIL_ROUTINE_TRANSPORT_BOOTSTRAP_INVALID", "routine bootstrap is not canonical");
  }
  return normalized;
}

export function derivePhilRoutineTransportTranscriptHashV1(input: {
  readonly bootstrap: PhilRoutineTransportBootstrapV1;
  readonly iphonePublicKeyX963: BytesLike;
}): Hex {
  const bootstrap = normalizeBootstrap(input.bootstrap);
  const iphoneKey = validateP256PublicKey(input.iphonePublicKeyX963, "iphonePublicKeyX963");
  const encoded = abiCoder.encode(
    ["bytes32","uint8","bytes32","uint32","uint16","bytes32","bytes32","bytes","bytes","bytes32","uint64"],
    [keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.transcriptLabel)),1,bootstrap.sessionId,
      Number(ipv4Bytes(bootstrap.ipv4).readUInt32BE(0)),bootstrap.port,
      keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.beginPath)),
      keccak256(toUtf8Bytes(PHIL_ROUTINE_TRANSPORT_V1.completePath)),
      bootstrap.desktopPublicKeyX963,hexlify(iphoneKey),bootstrap.requestId,BigInt(bootstrap.expiresAt)]
  );
  return sha256(encoded) as Hex;
}

export function formatPhilRoutineTransportFingerprintV1(transcriptHash: BytesLike): string {
  const value = exactBytes(transcriptHash, 32, "transcriptHash").subarray(0, 12).toString("hex").toUpperCase();
  return value.match(/.{4}/g)!.join("-");
}

export function derivePhilRoutineTransportAadV1(input: {
  readonly direction: "request" | "response" | "terminal" | "terminalAck";
  readonly sessionId: BytesLike;
  readonly requestId: BytesLike;
}): Buffer {
  const labels = { request: PHIL_ROUTINE_TRANSPORT_V1.requestAad, response: PHIL_ROUTINE_TRANSPORT_V1.responseAad,
    terminal: PHIL_ROUTINE_TRANSPORT_V1.terminalAad, terminalAck: PHIL_ROUTINE_TRANSPORT_V1.terminalAckAad };
  const label = labels[input.direction];
  if (!label) return fail("PHIL_ROUTINE_TRANSPORT_DIRECTION_INVALID", "unknown direction");
  return Buffer.concat([Buffer.from(label, "utf8"),Buffer.from([0x7c]),nonzero32(input.sessionId,"sessionId"),
    Buffer.from([0x7c]),nonzero32(input.requestId,"requestId")]);
}

export function derivePhilRoutineTransportKeyV1(input: {
  readonly privateKey: BytesLike;
  readonly peerPublicKeyX963: BytesLike;
  readonly transcriptHash: BytesLike;
}): Buffer {
  const ecdh=createECDH("prime256v1");
  const privateKey=exactBytes(input.privateKey,32,"privateKey");
  try { ecdh.setPrivateKey(privateKey); } catch { return fail("PHIL_ROUTINE_TRANSPORT_PRIVATE_KEY_INVALID","privateKey is invalid"); }
  let secret: Buffer;
  try { secret=ecdh.computeSecret(validateP256PublicKey(input.peerPublicKeyX963,"peerPublicKeyX963")); }
  catch { return fail("PHIL_ROUTINE_TRANSPORT_KEY_AGREEMENT_FAILED","P-256 ECDH failed"); }
  return Buffer.from(hkdfSync("sha256",secret,exactBytes(input.transcriptHash,32,"transcriptHash"),
    Buffer.from(PHIL_ROUTINE_TRANSPORT_V1.hkdfInfo,"utf8"),32));
}

export interface PhilRoutineTransportFrameV1 {
  readonly version: 1;
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
  readonly tag: Buffer;
}

export function serializePhilRoutineTransportFrameV1(frame: PhilRoutineTransportFrameV1): Buffer {
  const nonce=exactBytes(frame.nonce,12,"nonce"),tag=exactBytes(frame.tag,16,"tag");
  const ciphertext=Buffer.from(frame.ciphertext);
  if (frame.version!==1 || ciphertext.length<1 || ciphertext.length>65503) {
    fail("PHIL_ROUTINE_TRANSPORT_FRAME_INVALID","frame version or ciphertext length is invalid");
  }
  const output=Buffer.alloc(33+ciphertext.length);output[0]=1;nonce.copy(output,1);
  output.writeUInt32BE(ciphertext.length,13);ciphertext.copy(output,17);tag.copy(output,17+ciphertext.length);
  return output;
}

export function parsePhilRoutineTransportFrameV1(value: BytesLike): PhilRoutineTransportFrameV1 {
  const bytes=Buffer.from(getBytes(value));
  if (bytes.length<34 || bytes.length>65536 || bytes[0]!==1) {
    return fail("PHIL_ROUTINE_TRANSPORT_FRAME_INVALID","frame version or length is invalid");
  }
  const length=bytes.readUInt32BE(13);
  if (length<1 || length>65503 || bytes.length!==33+length) {
    fail("PHIL_ROUTINE_TRANSPORT_FRAME_INVALID","frame ciphertext length is invalid");
  }
  return Object.freeze({version:1,nonce:Buffer.from(bytes.subarray(1,13)),
    ciphertext:Buffer.from(bytes.subarray(17,17+length)),tag:Buffer.from(bytes.subarray(17+length))});
}

export class PhilRoutineTransportCipherV1 {
  readonly #key: Buffer;
  readonly #usedEncryptNonces=new Set<string>();
  readonly #usedDecryptNonces=new Set<string>();
  readonly #nonceSource: () => Buffer;
  #destroyed=false;

  constructor(input: { readonly key: BytesLike; readonly nonceSource?: () => BytesLike }) {
    this.#key=exactBytes(input.key,32,"transportKey");
    this.#nonceSource=()=>exactBytes(input.nonceSource?.() ?? randomBytes(12),12,"nonce");
  }

  encrypt(input: { readonly plaintext: string | Uint8Array; readonly aad: BytesLike }): Buffer {
    if (this.#destroyed) fail("PHIL_ROUTINE_TRANSPORT_KEY_DESTROYED","transport key was destroyed");
    const plaintext=typeof input.plaintext==="string" ? Buffer.from(input.plaintext,"utf8") : Buffer.from(input.plaintext);
    if (plaintext.length<1 || plaintext.length>65503) fail("PHIL_ROUTINE_TRANSPORT_PLAINTEXT_INVALID","plaintext size is invalid");
    const nonce=this.#nonceSource(),nonceId=nonce.toString("hex");
    if (this.#usedEncryptNonces.has(nonceId)) fail("PHIL_ROUTINE_TRANSPORT_NONCE_REUSE","encryption nonce was reused");
    this.#usedEncryptNonces.add(nonceId);
    const cipher=createCipheriv("aes-256-gcm",this.#key,nonce);cipher.setAAD(Buffer.from(getBytes(input.aad)));
    const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
    return serializePhilRoutineTransportFrameV1({version:1,nonce,ciphertext,tag:cipher.getAuthTag()});
  }

  decrypt(input: { readonly frame: BytesLike; readonly aad: BytesLike }): Buffer {
    if (this.#destroyed) fail("PHIL_ROUTINE_TRANSPORT_KEY_DESTROYED","transport key was destroyed");
    const frame=parsePhilRoutineTransportFrameV1(input.frame),nonceId=frame.nonce.toString("hex");
    if (this.#usedDecryptNonces.has(nonceId)) fail("PHIL_ROUTINE_TRANSPORT_NONCE_REUSE","decryption nonce was reused");
    this.#usedDecryptNonces.add(nonceId);
    try {
      const decipher=createDecipheriv("aes-256-gcm",this.#key,frame.nonce);decipher.setAAD(Buffer.from(getBytes(input.aad)));
      decipher.setAuthTag(frame.tag);return Buffer.concat([decipher.update(frame.ciphertext),decipher.final()]);
    } catch { return fail("PHIL_ROUTINE_TRANSPORT_AUTHENTICATION_FAILED","frame authentication failed"); }
  }

  destroy(): void {
    this.#key.fill(0);this.#usedEncryptNonces.clear();this.#usedDecryptNonces.clear();this.#destroyed=true;
  }
}

export interface PhilRoutineTransportBeginV1 {
  readonly protocolVersion: 1;
  readonly sessionId: Hex;
  readonly requestId: Hex;
  readonly iphonePublicKey: Hex;
}

export function parsePhilRoutineTransportBeginJsonV1(input: string | Uint8Array): PhilRoutineTransportBeginV1 {
  const object=parsePhilStrictJsonObjectV1(input);
  if (Object.keys(object).sort().join(",")!=="iphonePublicKey,protocolVersion,requestId,sessionId"
    || object.protocolVersion!==1 || typeof object.sessionId!=="string" || typeof object.requestId!=="string"
    || typeof object.iphonePublicKey!=="string") {
    return fail("PHIL_ROUTINE_TRANSPORT_BEGIN_INVALID","begin JSON schema is invalid");
  }
  return Object.freeze({protocolVersion:1,
    sessionId:hexlify(nonzero32(object.sessionId,"sessionId")).toLowerCase() as Hex,
    requestId:hexlify(nonzero32(object.requestId,"requestId")).toLowerCase() as Hex,
    iphonePublicKey:hexlify(validateP256PublicKey(object.iphonePublicKey,"iphonePublicKey")).toLowerCase() as Hex});
}

export function serializePhilRoutineTransportBeginJsonV1(value: PhilRoutineTransportBeginV1): string {
  const normalized=parsePhilRoutineTransportBeginJsonV1(JSON.stringify(value));
  return JSON.stringify(normalized);
}

// Independently versioned terminal protocol. This conveys only precommit abort,
// never a signature, approval, executable payload, or permission to retry.
export function parsePhilRoutineTerminalV1(input: string | Uint8Array, acknowledgement = false): Readonly<{
  protocolVersion: 1; purpose: string; sessionId: Hex; requestId: Hex; outcome: "rejected" | "cancelled";
}> {
  const value = parsePhilStrictJsonObjectV1(input);
  const purpose = acknowledgement ? "PHIL_ROUTINE_TERMINAL_ACK_V1" : "PHIL_ROUTINE_TERMINAL_RESULT_V1";
  if (Object.keys(value).sort().join(",") !== "outcome,protocolVersion,purpose,requestId,sessionId"
      || value.protocolVersion !== 1 || value.purpose !== purpose
      || !["rejected", "cancelled"].includes(value.outcome as string)
      || typeof value.sessionId !== "string" || typeof value.requestId !== "string"
      || !/^0x[0-9a-f]{64}$/.test(value.sessionId) || !/^0x[0-9a-f]{64}$/.test(value.requestId)) {
    return fail("PHIL_ROUTINE_TERMINAL_INVALID", "terminal schema is invalid");
  }
  nonzero32(value.sessionId, "sessionId"); nonzero32(value.requestId, "requestId");
  return Object.freeze({protocolVersion:1, purpose, sessionId:value.sessionId as Hex,
    requestId:value.requestId as Hex, outcome:value.outcome as "rejected" | "cancelled"});
}
