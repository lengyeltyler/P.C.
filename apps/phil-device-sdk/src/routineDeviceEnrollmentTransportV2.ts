import { createECDH, createHash, timingSafeEqual } from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { getBytes, hexlify, keccak256, toUtf8Bytes, type BytesLike } from "ethers";

import {
  encodePhilP256RawSignatureV2,
  parsePhilP256DerSignatureV2,
  PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
  PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
  PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
  validatePhilP256PublicKeyX963V2,
  verifyPhilP256RawSignatureV2
} from "./p256SignatureWireV2.ts";
import { parsePhilStrictJsonObjectV1 } from "./routineAuthorizationV1.ts";
import type { Hex } from "./hashes.ts";

const MAGIC = Buffer.from("PHIL6CE1", "ascii");
const PREFIX = "phil-step6c-routine-enrollment-v2:";

export const PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2 = Object.freeze({
  protocolVersion: 2 as const,
  transcriptLabel: "PHIL_ROUTINE_DEVICE_ENROLLMENT_PROOF_V2",
  acceptanceLabel: "PHIL_ROUTINE_DEVICE_ENROLLMENT_ACCEPTANCE_V2",
  preflightPath: "/philcore/routine-enrollment/v2/preflight",
  completePath: "/philcore/routine-enrollment/v2/complete",
  qrPrefix: PREFIX,
  bootstrapBytes: 192,
  maximumGeneration: 64,
  maximumHttpBodyBytes: 4096,
  signatureSuiteId:PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
  providerProfileId:PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
  wireEncodingId:PHIL_ROUTINE_WIRE_ENCODING_V2_ID
});

export class PhilRoutineDeviceEnrollmentTransportV2Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message);this.name="PhilRoutineDeviceEnrollmentTransportV2Error";this.code=code; }
}

function fail(code: string, message: string): never { throw new PhilRoutineDeviceEnrollmentTransportV2Error(code,message); }
function bytes(value: BytesLike, length: number, label: string): Buffer {
  let result: Buffer;try { result=Buffer.from(getBytes(value)); } catch { return fail("PHIL_ROUTINE_ENROLLMENT_BYTES_INVALID",`${label} is invalid`); }
  if (result.length!==length) fail("PHIL_ROUTINE_ENROLLMENT_LENGTH_INVALID",`${label} length is invalid`);
  return result;
}
function b32(value: BytesLike, label: string): Buffer {
  const result=bytes(value,32,label);if (result.every((byte)=>byte===0)) fail("PHIL_ROUTINE_ENROLLMENT_ZERO_INVALID",`${label} is zero`);return result;
}
function uint(value: string|number|bigint, bits: 16|64, label: string, positive=true): bigint {
  let parsed: bigint;try {
    if (typeof value==="number"&&!Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value==="string"&&!/^(0|[1-9][0-9]*)$/u.test(value)) throw new Error("noncanonical");
    parsed=BigInt(value);
  } catch { return fail("PHIL_ROUTINE_ENROLLMENT_UINT_INVALID",`${label} is invalid`); }
  if (parsed<0n||parsed>=(1n<<BigInt(bits))||(positive&&parsed===0n)) fail("PHIL_ROUTINE_ENROLLMENT_UINT_INVALID",`${label} is invalid`);
  return parsed;
}
function ipv4(value: string): Buffer {
  if (typeof value!=="string"||!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/u.test(value)) fail("PHIL_ROUTINE_ENROLLMENT_IPV4_INVALID","IPv4 is invalid");
  const octets=value.split(".").map(Number);
  if (octets.some((part)=>part>255)||!(octets[0]===10||(octets[0]===172&&octets[1]>=16&&octets[1]<=31)||(octets[0]===192&&octets[1]===168))) {
    fail("PHIL_ROUTINE_ENROLLMENT_PRIVATE_IPV4_REQUIRED","RFC1918 IPv4 is required");
  }
  return Buffer.from(octets);
}
function validateCurvePoint(value: BytesLike): Buffer {
  const result=bytes(value,65,"publicKeyX963");
  try { const validator=createECDH("prime256v1");validator.generateKeys();validator.computeSecret(result); }
  catch { return fail("PHIL_ROUTINE_ENROLLMENT_PUBLIC_KEY_INVALID","public key is invalid"); }
  return result;
}
function base64url(value: Buffer): string { return value.toString("base64url"); }
function decodeBase64url(value: string): Buffer {
  if (typeof value!=="string"||!/^[A-Za-z0-9_-]+$/u.test(value)) fail("PHIL_ROUTINE_ENROLLMENT_BASE64URL_INVALID","bootstrap is invalid");
  const result=Buffer.from(value,"base64url");if (base64url(result)!==value) fail("PHIL_ROUTINE_ENROLLMENT_BASE64URL_INVALID","bootstrap is noncanonical");return result;
}

export interface PhilRoutineDeviceEnrollmentBootstrapV2 {
  readonly sessionId: Hex;readonly ipv4: string;readonly port: number;readonly challenge: Hex;readonly expiresAt: string;readonly expectedGeneration:string;readonly desktopAckPublicKeyX963:Hex;
}

function normalizeBootstrap(input: PhilRoutineDeviceEnrollmentBootstrapV2): PhilRoutineDeviceEnrollmentBootstrapV2 {
  const address=ipv4(input.ipv4),port=uint(input.port,16,"port"),expiry=uint(input.expiresAt,64,"expiresAt"),generation=uint(input.expectedGeneration,64,"expectedGeneration");
  if (generation>BigInt(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.maximumGeneration)) fail("PHIL_ROUTINE_ENROLLMENT_GENERATION_INVALID","expected generation exceeds the supported limit");
  return Object.freeze({sessionId:hexlify(b32(input.sessionId,"sessionId")) as Hex,ipv4:[...address].join("."),port:Number(port),
    challenge:hexlify(b32(input.challenge,"challenge")) as Hex,expiresAt:expiry.toString(),expectedGeneration:generation.toString(),
    desktopAckPublicKeyX963:hexlify(validateCurvePoint(input.desktopAckPublicKeyX963)) as Hex});
}

function bootstrapBytes(input: PhilRoutineDeviceEnrollmentBootstrapV2): Buffer {
  const value=normalizeBootstrap(input),result=Buffer.alloc(192);MAGIC.copy(result,0);result[8]=2;b32(value.sessionId,"sessionId").copy(result,9);
  ipv4(value.ipv4).copy(result,41);result.writeUInt16BE(value.port,45);
  Buffer.from(getBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath)))).copy(result,47);
  b32(value.challenge,"challenge").copy(result,79);result.writeBigUInt64BE(BigInt(value.expiresAt),111);result.writeBigUInt64BE(BigInt(value.expectedGeneration),119);
  validateCurvePoint(value.desktopAckPublicKeyX963).copy(result,127);return result;
}

export function encodePhilRoutineDeviceEnrollmentBootstrapV2(input: PhilRoutineDeviceEnrollmentBootstrapV2): string {
  return `${PREFIX}${base64url(bootstrapBytes(input))}`;
}

export function decodePhilRoutineDeviceEnrollmentBootstrapV2(text: string): PhilRoutineDeviceEnrollmentBootstrapV2 {
  if (typeof text!=="string"||text.trim()!==text||!text.startsWith(PREFIX)) fail("PHIL_ROUTINE_ENROLLMENT_BOOTSTRAP_INVALID","prefix is invalid");
  const raw=decodeBase64url(text.slice(PREFIX.length));
  if (raw.length!==192||!timingSafeEqual(raw.subarray(0,8),MAGIC)||raw[8]!==2) fail("PHIL_ROUTINE_ENROLLMENT_BOOTSTRAP_INVALID","magic, version, or length is invalid");
  const expectedPath=Buffer.from(getBytes(keccak256(toUtf8Bytes(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath))));
  if (!timingSafeEqual(raw.subarray(47,79),expectedPath)) fail("PHIL_ROUTINE_ENROLLMENT_BOOTSTRAP_INVALID","path binding is invalid");
  const normalized=normalizeBootstrap({sessionId:hexlify(raw.subarray(9,41)) as Hex,ipv4:[...raw.subarray(41,45)].join("."),port:raw.readUInt16BE(45),
    challenge:hexlify(raw.subarray(79,111)) as Hex,expiresAt:raw.readBigUInt64BE(111).toString(),expectedGeneration:raw.readBigUInt64BE(119).toString(),
    desktopAckPublicKeyX963:hexlify(raw.subarray(127,192)) as Hex});
  if (encodePhilRoutineDeviceEnrollmentBootstrapV2(normalized)!==text) fail("PHIL_ROUTINE_ENROLLMENT_BOOTSTRAP_INVALID","bootstrap is noncanonical");
  return normalized;
}

export interface PhilRoutineDevicePublicRecordV2 {
  readonly schemaVersion: 2;readonly generation: string;readonly deviceId: Hex;readonly deviceKeyId: Hex;readonly publicKeyX963: Hex;
  readonly signatureSuiteId:Hex;readonly providerProfileId:Hex;readonly wireEncodingId:Hex;
  readonly publicKeyFingerprint: Hex;readonly secureEnclaveBacked: boolean;readonly userPresenceRequired: boolean;
}

export function validatePhilRoutineDevicePublicRecordV2(input: unknown, allowSynthetic=false): PhilRoutineDevicePublicRecordV2 {
  if (!input||typeof input!=="object"||Array.isArray(input)||Object.keys(input).sort().join(",")!==
    "deviceId,deviceKeyId,generation,providerProfileId,publicKeyFingerprint,publicKeyX963,schemaVersion,secureEnclaveBacked,signatureSuiteId,userPresenceRequired,wireEncodingId") {
    fail("PHIL_ROUTINE_ENROLLMENT_RECORD_INVALID","record schema is not exact");
  }
  const value=input as Record<string,unknown>,generation=uint(value.generation as string,64,"generation"),key=validatePhilP256PublicKeyX963V2(value.publicKeyX963 as string);
  if (generation>BigInt(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.maximumGeneration)) fail("PHIL_ROUTINE_ENROLLMENT_GENERATION_INVALID","generation exceeds the supported limit");
  if (value.schemaVersion!==2||typeof value.secureEnclaveBacked!=="boolean"||typeof value.userPresenceRequired!=="boolean"
    ||(!allowSynthetic&&(!value.secureEnclaveBacked||!value.userPresenceRequired))||key.publicKeyFingerprint!==value.publicKeyFingerprint
    ||value.signatureSuiteId!==PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID||value.providerProfileId!==PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID
    ||value.wireEncodingId!==PHIL_ROUTINE_WIRE_ENCODING_V2_ID) {
    fail("PHIL_ROUTINE_ENROLLMENT_RECORD_INVALID","record binding is invalid");
  }
  return Object.freeze({schemaVersion:2,generation:generation.toString(),deviceId:hexlify(b32(value.deviceId as string,"deviceId")) as Hex,
    deviceKeyId:hexlify(b32(value.deviceKeyId as string,"deviceKeyId")) as Hex,publicKeyX963:key.publicKeyX963,
    signatureSuiteId:PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,providerProfileId:PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,wireEncodingId:PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
    publicKeyFingerprint:key.publicKeyFingerprint,secureEnclaveBacked:value.secureEnclaveBacked,userPresenceRequired:value.userPresenceRequired});
}

export function derivePhilRoutineDeviceEnrollmentProofDigestV2(input: {
  readonly bootstrap: PhilRoutineDeviceEnrollmentBootstrapV2;readonly record: PhilRoutineDevicePublicRecordV2;
}): Hex {
  const bootstrap=normalizeBootstrap(input.bootstrap),record=validatePhilRoutineDevicePublicRecordV2(input.record,true),generation=Buffer.alloc(8);generation.writeBigUInt64BE(BigInt(record.generation));
  if (record.generation!==bootstrap.expectedGeneration) fail("PHIL_ROUTINE_ENROLLMENT_GENERATION_INVALID","record generation does not match bootstrap");
  const preimage=Buffer.concat([Buffer.from(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.transcriptLabel,"utf8"),Buffer.from([0]),bootstrapBytes(input.bootstrap),
    b32(record.deviceId,"deviceId"),b32(record.deviceKeyId,"deviceKeyId"),generation,b32(record.signatureSuiteId,"signatureSuiteId"),
    b32(record.providerProfileId,"providerProfileId"),b32(record.wireEncodingId,"wireEncodingId"),validateCurvePoint(record.publicKeyX963),
    Buffer.from([record.secureEnclaveBacked?1:0,record.userPresenceRequired?1:0])]);
  return `0x${createHash("sha256").update(preimage).digest("hex")}` as Hex;
}

export function derivePhilRoutineDeviceEnrollmentAcceptanceDigestV2(input:{readonly bootstrap:PhilRoutineDeviceEnrollmentBootstrapV2;readonly record:PhilRoutineDevicePublicRecordV2;}):Hex {
  const proofDigest=derivePhilRoutineDeviceEnrollmentProofDigestV2(input);
  return `0x${createHash("sha256").update(Buffer.concat([Buffer.from(PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.acceptanceLabel,"utf8"),Buffer.from([0]),
    bootstrapBytes(input.bootstrap),b32(proofDigest,"proofDigest")])).digest("hex")}` as Hex;
}

export function serializePhilRoutineDeviceEnrollmentAcceptanceV2(input:{readonly bootstrap:PhilRoutineDeviceEnrollmentBootstrapV2;readonly record:PhilRoutineDevicePublicRecordV2;readonly acceptanceSignatureDER:BytesLike;}):string {
  const bootstrap=normalizeBootstrap(input.bootstrap),proofDigest=derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record:input.record});
  return JSON.stringify({protocolVersion:2,sessionId:bootstrap.sessionId,challenge:bootstrap.challenge,enrollmentProofDigest:proofDigest,
    acceptanceSignatureDER:hexlify(getBytes(input.acceptanceSignatureDER)).toLowerCase()});
}

export function parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2(input:{readonly json:string|Uint8Array;readonly bootstrap:PhilRoutineDeviceEnrollmentBootstrapV2;readonly record:PhilRoutineDevicePublicRecordV2;}):Hex {
  const value=parsePhilStrictJsonObjectV1(input.json);
  if (Object.keys(value).sort().join(")")!=="acceptanceSignatureDER)challenge)enrollmentProofDigest)protocolVersion)sessionId") fail("PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID","acceptance schema is not exact");
  const bootstrap=normalizeBootstrap(input.bootstrap),proofDigest=derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record:input.record});
  if (value.protocolVersion!==2||value.sessionId!==bootstrap.sessionId||value.challenge!==bootstrap.challenge||value.enrollmentProofDigest!==proofDigest
    ||typeof value.acceptanceSignatureDER!=="string") fail("PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID","acceptance binding is invalid");
  let components;try { components=parsePhilP256DerSignatureV2(value.acceptanceSignatureDER as string); } catch { return fail("PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID","acceptance DER is invalid"); }
  const originalDer=Buffer.from(getBytes(value.acceptanceSignatureDER as string));
  const canonicalLowSDer=Buffer.from(new p256.Signature(BigInt(components.r),BigInt(components.s)).toDERRawBytes());
  if (originalDer.length!==canonicalLowSDer.length||!timingSafeEqual(originalDer,canonicalLowSDer)) fail("PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID","acceptance DER must be canonical low-S");
  const digest=derivePhilRoutineDeviceEnrollmentAcceptanceDigestV2({bootstrap,record:input.record}),raw=encodePhilP256RawSignatureV2(components);
  if (!verifyPhilP256RawSignatureV2({digest,signature:raw,publicKeyX963:bootstrap.desktopAckPublicKeyX963})) fail("PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID","Desktop acceptance signature failed");
  return digest;
}

export function formatPhilRoutineDeviceEnrollmentFingerprintV2(input: PhilRoutineDeviceEnrollmentBootstrapV2): string {
  const value=createHash("sha256").update(bootstrapBytes(input)).digest("hex").toUpperCase().slice(0,24);return value.match(/.{4}/gu)!.join("-");
}

export function serializePhilRoutineDeviceEnrollmentResponseV2(input: {readonly bootstrap: PhilRoutineDeviceEnrollmentBootstrapV2;
  readonly record: PhilRoutineDevicePublicRecordV2;readonly proofSignatureDER: BytesLike;}): string {
  const record=validatePhilRoutineDevicePublicRecordV2(input.record,true),signature=hexlify(getBytes(input.proofSignatureDER)).toLowerCase();
  return JSON.stringify({protocolVersion:2,sessionId:normalizeBootstrap(input.bootstrap).sessionId,challenge:normalizeBootstrap(input.bootstrap).challenge,
    record,proofSignatureDER:signature});
}

export function parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2(input: {readonly json: string|Uint8Array;
  readonly bootstrap: PhilRoutineDeviceEnrollmentBootstrapV2;readonly allowSynthetic?: boolean;}): PhilRoutineDevicePublicRecordV2 {
  const value=parsePhilStrictJsonObjectV1(input.json);
  if (Object.keys(value).sort().join(")")!=="challenge)proofSignatureDER)protocolVersion)record)sessionId") fail("PHIL_ROUTINE_ENROLLMENT_RESPONSE_INVALID","response schema is not exact");
  const bootstrap=normalizeBootstrap(input.bootstrap);
  if (value.protocolVersion!==2||value.sessionId!==bootstrap.sessionId||value.challenge!==bootstrap.challenge||typeof value.proofSignatureDER!=="string") {
    fail("PHIL_ROUTINE_ENROLLMENT_RESPONSE_INVALID","response binding is invalid");
  }
  const record=validatePhilRoutineDevicePublicRecordV2(value.record,input.allowSynthetic===true);
  let components;try { components=parsePhilP256DerSignatureV2(value.proofSignatureDER as string); } catch { return fail("PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID","proof DER is invalid"); }
  const raw=encodePhilP256RawSignatureV2(components),digest=derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record});
  if (!verifyPhilP256RawSignatureV2({digest,signature:raw,publicKeyX963:record.publicKeyX963})) fail("PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID","proof of possession failed");
  return record;
}
