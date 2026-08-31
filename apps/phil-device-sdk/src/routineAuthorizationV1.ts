import {
  AbiCoder,
  concat,
  dataSlice,
  getAddress,
  getBytes,
  getCreateAddress,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHIL_AUTHORIZATION_ENVELOPE_V1_HASH,
  PHIL_ZERO_BYTES32,
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1,
  type PhilAuthorizationEnvelopeV1
} from "./authorizationEnvelopeV1.ts";
import { derivePhilDeviceApprovalDigestV1 } from "./deviceApprovalV1.ts";
import {
  PHIL_ADAPTER_PQ_CAPABILITY_V1,
  PHIL_ADAPTER_TYPE_V1,
  PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID,
  PHIL_EVM_SINGLE_CALL_CODEC_ID,
  PHIL_EVM_SINGLE_CALL_V1_HASH,
  PHIL_EVM_SCOPE_CANONICALIZATION_ID,
  PHIL_ERC4337_FEE_MODEL_ID,
  PHIL_ERC4337_NONCE_MODEL_ID,
  createPhilAdapterManifestV1,
  derivePhilEvmAccountBindingHashV1,
  derivePhilEvmIntentDigestV1,
  derivePhilEvmNonceDomainV1,
  validatePhilAdapterManifestV1,
  validatePhilEvmSingleCallV1,
  type PhilAdapterManifestV1,
  type PhilEvmAdapterDeviceApprovalV1,
  type PhilEvmSingleCallV1
} from "./networkAdapterV1.ts";
import {
  PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
  PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
  PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
  decodePhilP256RawSignatureV2,
  derivePhilDeviceApprovalSigningDigestV2,
  encodePhilP256RawSignatureV2,
  validatePhilP256PublicKeyX963V2,
  verifyPhilP256RawSignatureV2
} from "./p256SignatureWireV2.ts";
import {
  createPhilRoutineSignatureRegistryV2,
  validatePhilRoutineSignatureRegistryV2,
  type PhilRoutineSignatureRegistryV2
} from "./routineSignatureRegistryV2.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const domain = (label: string): Hex => keccak256(toUtf8Bytes(label)) as Hex;

export const PHIL_ROUTINE_DOMAIN_LABELS_V1 = Object.freeze({
  EXECUTION_ENVIRONMENT: "PHIL_EXECUTION_ENVIRONMENT_V1",
  DEVICE_ENROLLMENT: "PHIL_ROUTINE_DEVICE_ENROLLMENT_V2",
  ACCOUNT_CONFIGURATION: "PHIL_ROUTINE_ACCOUNT_CONFIGURATION_V1",
  APPLICATION_PRINCIPAL: "PHIL_ROUTINE_APPLICATION_PRINCIPAL_V1",
  SCOPE_INSTANCE: "PHIL_ROUTINE_SCOPE_INSTANCE_V1",
  CAPABILITY: "PHIL_ROUTINE_CAPABILITY_V1",
  PARAMETER_SCHEMA: "PHIL_ROUTINE_PARAMETER_SCHEMA_V1",
  CATALOG_ENTRY: "PHIL_ROUTINE_CATALOG_ENTRY_V1",
  CATALOG: "PHIL_ROUTINE_CATALOG_V1",
  CAPABILITY_POLICY: "PHIL_ROUTINE_CAPABILITY_POLICY_V1",
  HUMAN_PRESENTATION: "PHIL_ROUTINE_HUMAN_PRESENTATION_V1",
  AUTHORIZATION_CORE: "PHIL_ROUTINE_AUTHORIZATION_CORE_V1",
  APPROVAL_NONCE: "PHIL_ROUTINE_APPROVAL_NONCE_V1",
  AUTHORIZATION_REQUEST: "PHIL_ROUTINE_AUTHORIZATION_REQUEST_V1",
  AUTHORIZATION_RESPONSE: "PHIL_ROUTINE_AUTHORIZATION_RESPONSE_V1",
  AUTHORIZATION_RECEIPT: "PHIL_ROUTINE_AUTHORIZATION_RECEIPT_V1",
  TRANSPORT: "PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1",
  IMPLEMENTATION_SET: "PHIL_STEP6C_IMPLEMENTATION_SET_V1",
  AUDIT_STATUS: "PHIL_STEP6C_AUDIT_STATUS_V1"
} as const);

export const PHIL_ROUTINE_DOMAIN_HASHES_V1 = Object.freeze(
  Object.fromEntries(Object.entries(PHIL_ROUTINE_DOMAIN_LABELS_V1).map(([key, value]) => [key, domain(value)]))
) as Readonly<Record<keyof typeof PHIL_ROUTINE_DOMAIN_LABELS_V1, Hex>>;

export const PHIL_STEP6C_CHAIN_ID = 31337n;
export const PHIL_STEP6C_NETWORK_ID_HASH = domain("phil-local:step6c:31337");
export const PHIL_STEP6C_EXECUTION_ENVIRONMENT_ID = domain(
  "phil-execution-environment-step6c-local-hardhat-v1"
);
export const PHIL_STEP6C_ADAPTER_ID = domain("phil-adapter-step6c-local-erc4337-v07-v1");
export const PHIL_STEP6C_ENTRYPOINT_VERSION_HASH = domain("erc4337-entrypoint-v0.7.0");
export const PHIL_STEP6C_ADAPTER_VERSION_HASH = domain("phil-step6c-local-erc4337-adapter-v1");
export const PHIL_STEP6C_APPLICATION_ID = domain("phil-application-step6c-local-harmless-v1");
export const PHIL_STEP6C_SCOPE_ID = domain("phil-scope-step6c-local-routine-v1");
export const PHIL_STEP6C_RECORD_SELECTOR = dataSlice(domain("record(bytes32,bool)"), 0, 4) as Hex;
export const PHIL_STEP6C_RECORDED_VALUE = domain("PHIL_STEP6C_HARMLESS_VALUE_V1");
export const PHIL_STEP6C_PARAMETER_SUMMARY_SUCCESS_HASH = domain("Record disclosed harmless value");
export const PHIL_STEP6C_PARAMETER_SUMMARY_FAILURE_HASH = domain("Intentionally revert before recording");
export const PHIL_STEP6C_PROFILE_POLICY_SECONDS = 86400n;
export const PHIL_STEP6C_REQUEST_SECONDS = 120n;

export const PHIL_STEP6C_CATALOG_TEXT = Object.freeze([
  "Phil Step 6C Local Harmless App",
  "Local Hardhat Chain 31337",
  "Disposable Phil Routine Account",
  "Harmless Local Record Target",
  "Record Harmless Local Value",
  "Harmless Record Parameters"
] as const);
export const PHIL_STEP6C_CATALOG_TEXT_HASHES = Object.freeze(
  PHIL_STEP6C_CATALOG_TEXT.map(domain)
);

export class PhilRoutineAuthorizationV1Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilRoutineAuthorizationV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilRoutineAuthorizationV1Error(code, message);
}

function b32(value: BytesLike, label: string, zero = false): Hex {
  let normalized: Hex;
  try { normalized = hexlify(value).toLowerCase() as Hex; }
  catch { return fail("PHIL_ROUTINE_BYTES32_INVALID", `${label} must be bytes32`); }
  if (getBytes(normalized).length !== 32 || (!zero && normalized === PHIL_ZERO_BYTES32)) {
    fail("PHIL_ROUTINE_BYTES32_INVALID", `${label} must be ${zero ? "" : "non-zero "}bytes32`);
  }
  return normalized;
}

function addr(value: string, label: string): string {
  try {
    const normalized = getAddress(value).toLowerCase();
    if (normalized === "0x0000000000000000000000000000000000000000") throw new Error("zero");
    return normalized;
  } catch { return fail("PHIL_ROUTINE_ADDRESS_INVALID", `${label} must be a non-zero EVM address`); }
}

function u(value: string | number | bigint, bits: 8 | 48 | 64 | 192 | 256, label: string, positive = false): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch { return fail("PHIL_ROUTINE_UNSIGNED_INVALID", `${label} must be canonical uint${bits}`); }
  if (parsed < 0n || parsed >= (1n << BigInt(bits)) || (positive && parsed === 0n)) {
    fail("PHIL_ROUTINE_UNSIGNED_INVALID", `${label} must fit uint${bits}`);
  }
  return parsed.toString(10);
}

function bool(value: boolean, label: string): boolean {
  if (typeof value !== "boolean") fail("PHIL_ROUTINE_BOOLEAN_INVALID", `${label} must be boolean`);
  return value;
}

function ascii(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 96
    || value.trim() !== value || value.includes("  ") || /[^\x20-\x7e]/.test(value)
    || /[\\"<>]/.test(value)) {
    fail("PHIL_ROUTINE_CATALOG_TEXT_INVALID", `${label} is not admitted canonical ASCII`);
  }
  return value;
}

function same(actual: unknown, expected: unknown, code: string, label: string): void {
  if (actual !== expected) fail(code, `${label} mismatch`);
}

function strictDeepEqual(actual: unknown, expected: unknown, code: string, label: string): void {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length!==expected.length) fail(code,`${label} array shape mismatch`);
    for (let index=0;index<expected.length;index+=1) strictDeepEqual(actual[index],expected[index],code,`${label}[${index}]`);
    return;
  }
  if (expected!==null && typeof expected==="object") {
    if (actual===null || typeof actual!=="object" || Array.isArray(actual)) fail(code,`${label} object shape mismatch`);
    const actualObject=actual as Record<string,unknown>,expectedObject=expected as Record<string,unknown>;
    const actualKeys=Object.keys(actualObject).sort(),expectedKeys=Object.keys(expectedObject).sort();
    if (actualKeys.join("\u0000")!==expectedKeys.join("\u0000")) fail(code,`${label} key set mismatch`);
    for (const key of expectedKeys) strictDeepEqual(actualObject[key],expectedObject[key],code,`${label}.${key}`);
    return;
  }
  if (actual!==expected) fail(code,`${label} mismatch`);
}

function rejectDuplicateJsonKeys(text: string): void {
  let offset=0;
  const whitespace=()=>{while (/\s/.test(text[offset]??"")) offset+=1;};
  const stringToken=(): string=>{
    if (text[offset]!=="\"") fail("PHIL_ROUTINE_JSON_INVALID","expected JSON string");
    const start=offset++;
    while (offset<text.length) {
      const character=text[offset++];
      if (character==="\\") { offset+=1; continue; }
      if (character==="\"") {
        try { return JSON.parse(text.slice(start,offset)); }
        catch { return fail("PHIL_ROUTINE_JSON_INVALID","invalid JSON string"); }
      }
      if (character.charCodeAt(0)<0x20) fail("PHIL_ROUTINE_JSON_INVALID","control character in JSON string");
    }
    return fail("PHIL_ROUTINE_JSON_INVALID","unterminated JSON string");
  };
  const value=(): void=>{
    whitespace();const character=text[offset];
    if (character==="{") {
      offset+=1;whitespace();const keys=new Set<string>();
      if (text[offset]==="}") {offset+=1;return;}
      while (true) {
        whitespace();const key=stringToken();
        if (keys.has(key)) fail("PHIL_ROUTINE_JSON_DUPLICATE_KEY",`duplicate JSON key ${key}`);
        keys.add(key);whitespace();if (text[offset++]!==":") fail("PHIL_ROUTINE_JSON_INVALID","missing JSON colon");
        value();whitespace();const delimiter=text[offset++];
        if (delimiter==="}") return;
        if (delimiter!==",") fail("PHIL_ROUTINE_JSON_INVALID","invalid JSON object delimiter");
      }
    }
    if (character==="[") {
      offset+=1;whitespace();if (text[offset]==="]") {offset+=1;return;}
      while (true) {value();whitespace();const delimiter=text[offset++];if (delimiter==="]") return;
        if (delimiter!==",") fail("PHIL_ROUTINE_JSON_INVALID","invalid JSON array delimiter");}
    }
    if (character==="\"") {stringToken();return;}
    const remainder=text.slice(offset),match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(remainder);
    if (!match) fail("PHIL_ROUTINE_JSON_INVALID","invalid JSON scalar");
    offset+=match[0].length;
  };
  value();whitespace();if (offset!==text.length) fail("PHIL_ROUTINE_JSON_INVALID","trailing JSON bytes");
}

function strictJsonObject(input: string | Uint8Array): Record<string,unknown> {
  let text: string;
  try { text=typeof input==="string" ? input : new TextDecoder("utf-8",{fatal:true}).decode(input); }
  catch { return fail("PHIL_ROUTINE_JSON_INVALID","JSON must be strict UTF-8"); }
  if (text.startsWith("\ufeff")) fail("PHIL_ROUTINE_JSON_INVALID","JSON BOM is forbidden");
  rejectDuplicateJsonKeys(text);
  let parsed: unknown;
  try { parsed=JSON.parse(text); } catch { return fail("PHIL_ROUTINE_JSON_INVALID","invalid JSON"); }
  if (parsed===null || typeof parsed!=="object" || Array.isArray(parsed)) fail("PHIL_ROUTINE_JSON_INVALID","JSON root must be an object");
  return parsed as Record<string,unknown>;
}

export function parsePhilStrictJsonObjectV1(input: string | Uint8Array): Record<string,unknown> {
  return strictJsonObject(input);
}

export interface PhilExecutionEnvironmentV1 {
  readonly formatVersionHash: Hex;
  readonly environmentClass: 1;
  readonly chainId: string;
  readonly networkIdHash: Hex;
  readonly executionEnvironmentId: Hex;
  readonly adapterId: Hex;
  readonly entryPointVersionHash: Hex;
  readonly entryPoint: string;
  readonly entryPointRuntimeCodeHash: Hex;
  readonly senderCreator: string;
  readonly senderCreatorRuntimeCodeHash: Hex;
  readonly externalNetwork: false;
  readonly productionAuthority: false;
  readonly meaningfulAssets: false;
  readonly executionEnvironmentHash: Hex;
}

export function createPhilExecutionEnvironmentV1(input: {
  readonly entryPoint: string;
  readonly entryPointRuntimeCodeHash: BytesLike;
  readonly senderCreator: string;
  readonly senderCreatorRuntimeCodeHash: BytesLike;
}): PhilExecutionEnvironmentV1 {
  const entryPoint = addr(input.entryPoint, "entryPoint");
  const senderCreator = addr(input.senderCreator, "senderCreator");
  same(senderCreator, getCreateAddress({ from: entryPoint, nonce: 1 }).toLowerCase(),
    "PHIL_ROUTINE_SENDER_CREATOR_MISMATCH", "senderCreator");
  const record = {
    formatVersionHash: PHIL_ROUTINE_DOMAIN_HASHES_V1.EXECUTION_ENVIRONMENT,
    environmentClass: 1 as const,
    chainId: PHIL_STEP6C_CHAIN_ID.toString(),
    networkIdHash: PHIL_STEP6C_NETWORK_ID_HASH,
    executionEnvironmentId: PHIL_STEP6C_EXECUTION_ENVIRONMENT_ID,
    adapterId: PHIL_STEP6C_ADAPTER_ID,
    entryPointVersionHash: PHIL_STEP6C_ENTRYPOINT_VERSION_HASH,
    entryPoint,
    entryPointRuntimeCodeHash: b32(input.entryPointRuntimeCodeHash, "entryPointRuntimeCodeHash"),
    senderCreator,
    senderCreatorRuntimeCodeHash: b32(input.senderCreatorRuntimeCodeHash, "senderCreatorRuntimeCodeHash"),
    externalNetwork: false as const,
    productionAuthority: false as const,
    meaningfulAssets: false as const
  };
  const executionEnvironmentHash = keccak256(abiCoder.encode(
    ["bytes32","uint8","uint256","bytes32","bytes32","bytes32","bytes32","address","bytes32","address","bytes32","bool","bool","bool"],
    [record.formatVersionHash,1,PHIL_STEP6C_CHAIN_ID,record.networkIdHash,record.executionEnvironmentId,
      record.adapterId,record.entryPointVersionHash,record.entryPoint,record.entryPointRuntimeCodeHash,
      record.senderCreator,record.senderCreatorRuntimeCodeHash,false,false,false]
  )) as Hex;
  return Object.freeze({ ...record, executionEnvironmentHash });
}

export function validatePhilExecutionEnvironmentV1(environment: PhilExecutionEnvironmentV1): PhilExecutionEnvironmentV1 {
  const rebuilt = createPhilExecutionEnvironmentV1(environment);
  same(environment.formatVersionHash, rebuilt.formatVersionHash, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "formatVersionHash");
  same(environment.environmentClass, 1, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "environmentClass");
  same(environment.chainId, rebuilt.chainId, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "chainId");
  same(environment.networkIdHash, rebuilt.networkIdHash, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "networkIdHash");
  same(environment.executionEnvironmentId, rebuilt.executionEnvironmentId, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "executionEnvironmentId");
  same(environment.adapterId, rebuilt.adapterId, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "adapterId");
  same(environment.entryPointVersionHash, rebuilt.entryPointVersionHash, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "entryPointVersionHash");
  same(environment.executionEnvironmentHash, rebuilt.executionEnvironmentHash, "PHIL_ROUTINE_ENVIRONMENT_MISMATCH", "executionEnvironmentHash");
  if (environment.externalNetwork || environment.productionAuthority || environment.meaningfulAssets) {
    fail("PHIL_ROUTINE_ENVIRONMENT_CLASSIFICATION_FORBIDDEN", "Step 6C is local, non-production, and asset-free");
  }
  return rebuilt;
}

export function createPhilStep6CLocalAdapterManifestV1(input: {
  readonly implementationHash: BytesLike;
  readonly auditStatusHash: BytesLike;
}): PhilAdapterManifestV1 {
  return createPhilAdapterManifestV1({
    adapterId: PHIL_STEP6C_ADAPTER_ID,
    adapterVersionHash: PHIL_STEP6C_ADAPTER_VERSION_HASH,
    adapterType: PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT,
    networkIdHash: PHIL_STEP6C_NETWORK_ID_HASH,
    accountModelId: PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID,
    scopeCanonicalizationId: PHIL_EVM_SCOPE_CANONICALIZATION_ID,
    actionCodecId: PHIL_EVM_SINGLE_CALL_CODEC_ID,
    replayModelId: PHIL_ERC4337_NONCE_MODEL_ID,
    feeModelId: PHIL_ERC4337_FEE_MODEL_ID,
    supportedDeviceSignatureSuiteIds: [PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID],
    supportedProofSuiteIds: [],
    postQuantumCapability: PHIL_ADAPTER_PQ_CAPABILITY_V1.NONE,
    implementationHash: b32(input.implementationHash, "implementationHash"),
    auditStatusHash: b32(input.auditStatusHash, "auditStatusHash")
  });
}

export function validatePhilStep6CLocalAdapterManifestV1(manifest: PhilAdapterManifestV1): PhilAdapterManifestV1 {
  const normalized = validatePhilAdapterManifestV1(manifest);
  if (normalized.adapterId !== PHIL_STEP6C_ADAPTER_ID
    || normalized.adapterVersionHash !== PHIL_STEP6C_ADAPTER_VERSION_HASH
    || normalized.networkIdHash !== PHIL_STEP6C_NETWORK_ID_HASH
    || normalized.accountModelId !== PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID
    || normalized.scopeCanonicalizationId !== PHIL_EVM_SCOPE_CANONICALIZATION_ID
    || normalized.actionCodecId !== PHIL_EVM_SINGLE_CALL_CODEC_ID
    || normalized.replayModelId !== PHIL_ERC4337_NONCE_MODEL_ID
    || normalized.feeModelId !== PHIL_ERC4337_FEE_MODEL_ID
    || normalized.adapterType !== PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT
    || normalized.postQuantumCapability !== 0
    || normalized.supportedDeviceSignatureSuiteIds.length !== 1
    || normalized.supportedDeviceSignatureSuiteIds[0] !== PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID
    || normalized.supportedProofSuiteIds.length !== 0) {
    fail("PHIL_ROUTINE_ADAPTER_MANIFEST_MISMATCH", "adapter is not the exact Step 6C local profile");
  }
  return normalized;
}

export interface PhilRoutineDeviceEnrollmentV2 {
  readonly formatVersionHash: Hex;
  readonly deviceId: Hex;
  readonly deviceKeyId: Hex;
  readonly deviceEpoch: string;
  readonly generation: string;
  readonly signatureRegistryHash: Hex;
  readonly signatureSuiteId: Hex;
  readonly providerProfileId: Hex;
  readonly wireEncodingId: Hex;
  readonly publicKeyX963: Hex;
  readonly publicKeyFingerprint: Hex;
  readonly publicKeyX: Hex;
  readonly publicKeyY: Hex;
  readonly secureEnclaveBacked: boolean;
  readonly userPresenceRequired: boolean;
  readonly status: 1;
  readonly deviceEnrollmentHash: Hex;
}

export function createPhilRoutineDeviceEnrollmentV2(input: {
  readonly deviceId: BytesLike;
  readonly deviceKeyId: BytesLike;
  readonly deviceEpoch?: string | number | bigint;
  readonly generation?: string | number | bigint;
  readonly signatureRegistry: PhilRoutineSignatureRegistryV2;
  readonly publicKeyX963: BytesLike;
  readonly secureEnclaveBacked: boolean;
  readonly userPresenceRequired: boolean;
}): PhilRoutineDeviceEnrollmentV2 {
  const registry = validatePhilRoutineSignatureRegistryV2(input.signatureRegistry);
  const publicKey = validatePhilP256PublicKeyX963V2(input.publicKeyX963);
  const record = {
    formatVersionHash: PHIL_ROUTINE_DOMAIN_HASHES_V1.DEVICE_ENROLLMENT,
    deviceId: b32(input.deviceId, "deviceId"),
    deviceKeyId: b32(input.deviceKeyId, "deviceKeyId"),
    deviceEpoch: u(input.deviceEpoch ?? 1, 64, "deviceEpoch", true),
    generation: u(input.generation ?? 1, 64, "generation", true),
    signatureRegistryHash: registry.registryHash,
    signatureSuiteId: PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
    providerProfileId: PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
    wireEncodingId: PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
    ...publicKey,
    secureEnclaveBacked: bool(input.secureEnclaveBacked, "secureEnclaveBacked"),
    userPresenceRequired: bool(input.userPresenceRequired, "userPresenceRequired"),
    status: 1 as const
  };
  if (record.deviceEpoch !== "1") {
    fail("PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "Step 6C requires an epoch-1 disposable enrollment");
  }
  const deviceEnrollmentHash = keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes","bytes32","bytes32","bytes32","bool","bool","uint8"],
    [record.formatVersionHash,record.deviceId,record.deviceKeyId,BigInt(record.deviceEpoch),BigInt(record.generation),
      record.signatureRegistryHash,record.signatureSuiteId,record.providerProfileId,record.wireEncodingId,
      record.publicKeyX963,record.publicKeyFingerprint,record.publicKeyX,record.publicKeyY,
      record.secureEnclaveBacked,record.userPresenceRequired,1]
  )) as Hex;
  return Object.freeze({ ...record, deviceEnrollmentHash });
}

export function validatePhilRoutineDeviceEnrollmentV2(input: PhilRoutineDeviceEnrollmentV2): PhilRoutineDeviceEnrollmentV2 {
  const rebuilt = createPhilRoutineDeviceEnrollmentV2({
    ...input,
    signatureRegistry: createPhilRoutineSignatureRegistryV2()
  });
  same(input.deviceEnrollmentHash, rebuilt.deviceEnrollmentHash, "PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "deviceEnrollmentHash");
  same(input.formatVersionHash, rebuilt.formatVersionHash, "PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "formatVersionHash");
  same(input.publicKeyFingerprint, rebuilt.publicKeyFingerprint, "PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "publicKeyFingerprint");
  same(input.publicKeyX, rebuilt.publicKeyX, "PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "publicKeyX");
  same(input.publicKeyY, rebuilt.publicKeyY, "PHIL_ROUTINE_DEVICE_ENROLLMENT_MISMATCH", "publicKeyY");
  return rebuilt;
}

export function derivePhilRoutineApplicationPrincipalIdV1(applicationId: BytesLike = PHIL_STEP6C_APPLICATION_ID): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32","bytes32"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.APPLICATION_PRINCIPAL,b32(applicationId,"applicationId")]
  )) as Hex;
}

export function derivePhilRoutineScopeInstanceV1(input: {
  readonly account: string;
  readonly executionEnvironmentHash: BytesLike;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","address"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.SCOPE_INSTANCE,PHIL_STEP6C_SCOPE_ID,PHIL_STEP6C_APPLICATION_ID,
      b32(input.executionEnvironmentHash,"executionEnvironmentHash"),addr(input.account,"account")]
  )) as Hex;
}

export function derivePhilRoutineParameterSchemaIdV1(input: {
  readonly approvedTarget: string;
  readonly approvedTargetRuntimeCodeHash: BytesLike;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32","address","bytes32","bytes4","bytes32"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.PARAMETER_SCHEMA,addr(input.approvedTarget,"approvedTarget"),
      b32(input.approvedTargetRuntimeCodeHash,"approvedTargetRuntimeCodeHash"),
      PHIL_STEP6C_RECORD_SELECTOR,PHIL_STEP6C_RECORDED_VALUE]
  )) as Hex;
}

export function derivePhilRoutineCapabilityIdV1(input: {
  readonly scopeInstance: BytesLike;
  readonly approvedTarget: string;
  readonly approvedTargetRuntimeCodeHash: BytesLike;
  readonly parameterSchemaId?: BytesLike;
}): Hex {
  const target = addr(input.approvedTarget, "approvedTarget");
  const targetCode = b32(input.approvedTargetRuntimeCodeHash, "approvedTargetRuntimeCodeHash");
  const schema = input.parameterSchemaId
    ? b32(input.parameterSchemaId, "parameterSchemaId")
    : derivePhilRoutineParameterSchemaIdV1({ approvedTarget: target, approvedTargetRuntimeCodeHash: targetCode });
  return keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","address","bytes32","bytes32","bytes32"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.CAPABILITY,PHIL_STEP6C_APPLICATION_ID,b32(input.scopeInstance,"scopeInstance"),
      target,targetCode,PHIL_EVM_SINGLE_CALL_V1_HASH,schema]
  )) as Hex;
}

export function derivePhilRoutineParameterSummaryHashV1(targetCalldata: BytesLike): Hex {
  const raw = getBytes(targetCalldata);
  if (raw.length !== 68 || hexlify(raw.slice(0, 4)) !== PHIL_STEP6C_RECORD_SELECTOR
    || hexlify(raw.slice(4, 36)) !== PHIL_STEP6C_RECORDED_VALUE) {
    fail("PHIL_ROUTINE_TARGET_CALLDATA_INVALID", "target calldata must be the exact admitted 68-byte call");
  }
  const booleanWord = BigInt(hexlify(raw.slice(36, 68)));
  if (booleanWord !== 0n && booleanWord !== 1n) {
    fail("PHIL_ROUTINE_TARGET_CALLDATA_INVALID", "target calldata boolean must be canonical ABI 0 or 1");
  }
  const rebuilt = concat([
    PHIL_STEP6C_RECORD_SELECTOR,
    PHIL_STEP6C_RECORDED_VALUE,
    `0x${booleanWord.toString(16).padStart(64, "0")}`
  ]);
  if (hexlify(rebuilt) !== hexlify(raw)) fail("PHIL_ROUTINE_TARGET_CALLDATA_INVALID", "target calldata is not canonical");
  return booleanWord === 0n
    ? PHIL_STEP6C_PARAMETER_SUMMARY_SUCCESS_HASH
    : PHIL_STEP6C_PARAMETER_SUMMARY_FAILURE_HASH;
}

export interface PhilRoutineAccountConfigurationV1 {
  readonly formatVersionHash: Hex;
  readonly executionEnvironmentHash: Hex;
  readonly adapterManifestHash: Hex;
  readonly applicationId: Hex;
  readonly principalIdHash: Hex;
  readonly scopeId: Hex;
  readonly scopeInstance: Hex;
  readonly scopeEpoch: string;
  readonly recoveryEpoch: string;
  readonly validatorEpoch: string;
  readonly account: string;
  readonly accountRuntimeCodeHash: Hex;
  readonly deviceEnrollmentHash: Hex;
  readonly scopedOwnerCommitment: Hex;
  readonly approvedTarget: string;
  readonly approvedTargetRuntimeCodeHash: Hex;
  readonly actionTypeHash: Hex;
  readonly nonceKey: string;
  readonly maximumValueWei: string;
  readonly maximumTotalFeeWei: string;
  readonly accountConfigurationHash: Hex;
}

export function createPhilRoutineAccountConfigurationV1(input: {
  readonly environment: PhilExecutionEnvironmentV1;
  readonly adapterManifest: PhilAdapterManifestV1;
  readonly enrollment: PhilRoutineDeviceEnrollmentV2;
  readonly account: string;
  readonly accountRuntimeCodeHash: BytesLike;
  readonly scopedOwnerCommitment: BytesLike;
  readonly approvedTarget: string;
  readonly approvedTargetRuntimeCodeHash: BytesLike;
  readonly nonceKey: string | number | bigint;
  readonly maximumValueWei?: string | number | bigint;
  readonly maximumTotalFeeWei: string | number | bigint;
}): PhilRoutineAccountConfigurationV1 {
  const environment = validatePhilExecutionEnvironmentV1(input.environment);
  const manifest = validatePhilStep6CLocalAdapterManifestV1(input.adapterManifest);
  const enrollment = validatePhilRoutineDeviceEnrollmentV2(input.enrollment);
  same(manifest.networkIdHash, environment.networkIdHash, "PHIL_ROUTINE_ACCOUNT_CONFIGURATION_MISMATCH", "networkIdHash");
  same(manifest.adapterId, environment.adapterId, "PHIL_ROUTINE_ACCOUNT_CONFIGURATION_MISMATCH", "adapterId");
  const account = addr(input.account,"account");
  const scopeInstance = derivePhilRoutineScopeInstanceV1({ account, executionEnvironmentHash: environment.executionEnvironmentHash });
  const record = {
    formatVersionHash: PHIL_ROUTINE_DOMAIN_HASHES_V1.ACCOUNT_CONFIGURATION,
    executionEnvironmentHash: environment.executionEnvironmentHash,
    adapterManifestHash: manifest.manifestHash,
    applicationId: PHIL_STEP6C_APPLICATION_ID,
    principalIdHash: derivePhilRoutineApplicationPrincipalIdV1(),
    scopeId: PHIL_STEP6C_SCOPE_ID,
    scopeInstance,
    scopeEpoch: "1",
    recoveryEpoch: "1",
    validatorEpoch: "1",
    account,
    accountRuntimeCodeHash: b32(input.accountRuntimeCodeHash,"accountRuntimeCodeHash"),
    deviceEnrollmentHash: enrollment.deviceEnrollmentHash,
    scopedOwnerCommitment: b32(input.scopedOwnerCommitment,"scopedOwnerCommitment"),
    approvedTarget: addr(input.approvedTarget,"approvedTarget"),
    approvedTargetRuntimeCodeHash: b32(input.approvedTargetRuntimeCodeHash,"approvedTargetRuntimeCodeHash"),
    actionTypeHash: PHIL_EVM_SINGLE_CALL_V1_HASH,
    nonceKey: u(input.nonceKey,192,"nonceKey"),
    maximumValueWei: u(input.maximumValueWei ?? 0,256,"maximumValueWei"),
    maximumTotalFeeWei: u(input.maximumTotalFeeWei,256,"maximumTotalFeeWei",true)
  };
  if (record.maximumValueWei !== "0" || record.account === record.approvedTarget
    || record.account === environment.entryPoint || record.approvedTarget === environment.entryPoint) {
    fail("PHIL_ROUTINE_ACCOUNT_CONFIGURATION_MISMATCH", "account configuration exceeds the harmless profile");
  }
  const accountConfigurationHash = keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","uint64","uint64","address","bytes32","bytes32","bytes32","address","bytes32","bytes32","uint192","uint256","uint256"],
    [record.formatVersionHash,record.executionEnvironmentHash,record.adapterManifestHash,record.applicationId,
      record.principalIdHash,record.scopeId,record.scopeInstance,1n,1n,1n,record.account,
      record.accountRuntimeCodeHash,record.deviceEnrollmentHash,record.scopedOwnerCommitment,
      record.approvedTarget,record.approvedTargetRuntimeCodeHash,record.actionTypeHash,
      BigInt(record.nonceKey),0n,BigInt(record.maximumTotalFeeWei)]
  )) as Hex;
  return Object.freeze({ ...record, accountConfigurationHash });
}

export function validatePhilRoutineAccountConfigurationV1(
  configuration: PhilRoutineAccountConfigurationV1,
  context: Parameters<typeof createPhilRoutineAccountConfigurationV1>[0]
): PhilRoutineAccountConfigurationV1 {
  const rebuilt = createPhilRoutineAccountConfigurationV1(context);
  same(configuration.accountConfigurationHash, rebuilt.accountConfigurationHash,
    "PHIL_ROUTINE_ACCOUNT_CONFIGURATION_MISMATCH", "accountConfigurationHash");
  return rebuilt;
}

export interface PhilRoutineCatalogEntryV1 {
  readonly kind: 1 | 2 | 3 | 4 | 5 | 6;
  readonly entryId: Hex;
  readonly displayText: string;
  readonly displayTextHash: Hex;
  readonly boundValueHash: Hex;
  readonly entryHash: Hex;
}
export interface PhilRoutineCatalogV1 {
  readonly entries: readonly PhilRoutineCatalogEntryV1[];
  readonly catalogHash: Hex;
}

function catalogAddressHash(address: string, codeHash?: BytesLike): Hex {
  return keccak256(abiCoder.encode(codeHash ? ["address","bytes32"] : ["address"],
    codeHash ? [addr(address,"catalogAddress"),b32(codeHash,"catalogCodeHash")] : [addr(address,"catalogAddress")])) as Hex;
}

export function createPhilRoutineCatalogV1(input: {
  readonly environment: PhilExecutionEnvironmentV1;
  readonly configuration: PhilRoutineAccountConfigurationV1;
  readonly parameterSchemaId?: BytesLike;
}): PhilRoutineCatalogV1 {
  const environment = validatePhilExecutionEnvironmentV1(input.environment);
  const config = input.configuration;
  const parameterSchemaId = input.parameterSchemaId
    ? b32(input.parameterSchemaId,"parameterSchemaId")
    : derivePhilRoutineParameterSchemaIdV1(config);
  const accountHash = catalogAddressHash(config.account);
  const targetHash = catalogAddressHash(config.approvedTarget, config.approvedTargetRuntimeCodeHash);
  const ids = [config.applicationId,environment.networkIdHash,accountHash,targetHash,config.actionTypeHash,parameterSchemaId] as Hex[];
  const bound = [config.applicationId,environment.executionEnvironmentHash,accountHash,targetHash,config.actionTypeHash,parameterSchemaId] as Hex[];
  const entries = PHIL_STEP6C_CATALOG_TEXT.map((displayText, index) => {
    ascii(displayText, `catalog[${index}]`);
    const kind = (index + 1) as 1 | 2 | 3 | 4 | 5 | 6;
    const displayTextHash = PHIL_STEP6C_CATALOG_TEXT_HASHES[index]!;
    const entryHash = keccak256(abiCoder.encode(
      ["bytes32","uint8","bytes32","bytes32","bytes32"],
      [PHIL_ROUTINE_DOMAIN_HASHES_V1.CATALOG_ENTRY,kind,ids[index],displayTextHash,bound[index]]
    )) as Hex;
    return Object.freeze({ kind,entryId:ids[index]!,displayText,displayTextHash,boundValueHash:bound[index]!,entryHash });
  });
  const catalogHash = keccak256(abiCoder.encode(
    ["bytes32","bytes32[6]"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.CATALOG,entries.map((entry) => entry.entryHash)]
  )) as Hex;
  return Object.freeze({ entries:Object.freeze(entries),catalogHash });
}

export function validatePhilRoutineCatalogV1(
  catalog: PhilRoutineCatalogV1,
  context: Parameters<typeof createPhilRoutineCatalogV1>[0]
): PhilRoutineCatalogV1 {
  const rebuilt = createPhilRoutineCatalogV1(context);
  same(catalog.catalogHash,rebuilt.catalogHash,"PHIL_ROUTINE_CATALOG_MISMATCH","catalogHash");
  if (catalog.entries.length !== 6) fail("PHIL_ROUTINE_CATALOG_MISMATCH","catalog must have six entries");
  for (let i=0;i<6;i++) {
    const actual=catalog.entries[i]!,expected=rebuilt.entries[i]!;
    same(actual.kind,expected.kind,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].kind`);
    same(actual.entryId,expected.entryId,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].entryId`);
    same(ascii(actual.displayText,`entry[${i}].displayText`),expected.displayText,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].displayText`);
    same(actual.displayTextHash,expected.displayTextHash,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].displayTextHash`);
    same(actual.boundValueHash,expected.boundValueHash,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].boundValueHash`);
    same(actual.entryHash,expected.entryHash,"PHIL_ROUTINE_CATALOG_MISMATCH",`entry[${i}].entryHash`);
  }
  return rebuilt;
}

export interface PhilRoutineCapabilityPolicyV1 {
  readonly formatVersionHash: Hex; readonly scopedOwnerCommitment: Hex; readonly applicationId: Hex;
  readonly principalIdHash: Hex; readonly scopeId: Hex; readonly scopeInstance: Hex;
  readonly scopeEpoch: string; readonly recoveryEpoch: string; readonly validatorEpoch: string;
  readonly capabilityId: Hex; readonly capabilityEpoch: string; readonly policyEpoch: string;
  readonly executionEnvironmentHash: Hex; readonly adapterManifestHash: Hex;
  readonly accountConfigurationHash: Hex; readonly deviceEnrollmentHash: Hex; readonly catalogHash: Hex;
  readonly approvedTarget: string; readonly approvedTargetRuntimeCodeHash: Hex; readonly actionTypeHash: Hex;
  readonly maximumValueWei: string; readonly maximumTotalFeeWei: string;
  readonly validAfter: string; readonly validUntil: string; readonly active: true;
  readonly capabilityPolicyHash: Hex;
}

export function createPhilRoutineCapabilityPolicyV1(input: {
  readonly environment: PhilExecutionEnvironmentV1;
  readonly adapterManifest: PhilAdapterManifestV1;
  readonly enrollment: PhilRoutineDeviceEnrollmentV2;
  readonly configuration: PhilRoutineAccountConfigurationV1;
  readonly catalog: PhilRoutineCatalogV1;
  readonly profilePolicyValidAfter: string | number | bigint;
}): PhilRoutineCapabilityPolicyV1 {
  const environment=validatePhilExecutionEnvironmentV1(input.environment);
  const manifest=validatePhilStep6CLocalAdapterManifestV1(input.adapterManifest);
  const enrollment=validatePhilRoutineDeviceEnrollmentV2(input.enrollment);
  const config=input.configuration;
  const parameterSchemaId=derivePhilRoutineParameterSchemaIdV1(config);
  const catalog=validatePhilRoutineCatalogV1(input.catalog,{environment,configuration:config,parameterSchemaId});
  const validAfter=u(input.profilePolicyValidAfter,48,"profilePolicyValidAfter",true);
  const until=BigInt(validAfter)+PHIL_STEP6C_PROFILE_POLICY_SECONDS;
  if (until >= (1n<<48n)) fail("PHIL_ROUTINE_POLICY_VALIDITY_INVALID","profile policy exceeds uint48");
  const capabilityId=derivePhilRoutineCapabilityIdV1({scopeInstance:config.scopeInstance,
    approvedTarget:config.approvedTarget,approvedTargetRuntimeCodeHash:config.approvedTargetRuntimeCodeHash,parameterSchemaId});
  const record={formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.CAPABILITY_POLICY,
    scopedOwnerCommitment:config.scopedOwnerCommitment,applicationId:config.applicationId,
    principalIdHash:config.principalIdHash,scopeId:config.scopeId,scopeInstance:config.scopeInstance,
    scopeEpoch:"1",recoveryEpoch:"1",validatorEpoch:"1",capabilityId,capabilityEpoch:"1",policyEpoch:"1",
    executionEnvironmentHash:environment.executionEnvironmentHash,adapterManifestHash:manifest.manifestHash,
    accountConfigurationHash:config.accountConfigurationHash,deviceEnrollmentHash:enrollment.deviceEnrollmentHash,
    catalogHash:catalog.catalogHash,approvedTarget:config.approvedTarget,
    approvedTargetRuntimeCodeHash:config.approvedTargetRuntimeCodeHash,actionTypeHash:config.actionTypeHash,
    maximumValueWei:"0",maximumTotalFeeWei:config.maximumTotalFeeWei,validAfter,validUntil:until.toString(),active:true as const};
  const capabilityPolicyHash=keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","uint64","uint64","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","address","bytes32","bytes32","uint256","uint256","uint48","uint48","bool"],
    [record.formatVersionHash,record.scopedOwnerCommitment,record.applicationId,record.principalIdHash,
      record.scopeId,record.scopeInstance,1n,1n,1n,record.capabilityId,1n,1n,record.executionEnvironmentHash,
      record.adapterManifestHash,record.accountConfigurationHash,record.deviceEnrollmentHash,record.catalogHash,
      record.approvedTarget,record.approvedTargetRuntimeCodeHash,record.actionTypeHash,0n,
      BigInt(record.maximumTotalFeeWei),BigInt(record.validAfter),BigInt(record.validUntil),true]
  )) as Hex;
  return Object.freeze({...record,capabilityPolicyHash});
}

export function validatePhilRoutineCapabilityPolicyV1(
  policy: PhilRoutineCapabilityPolicyV1,
  context: Parameters<typeof createPhilRoutineCapabilityPolicyV1>[0]
): PhilRoutineCapabilityPolicyV1 {
  const rebuilt=createPhilRoutineCapabilityPolicyV1(context);
  same(policy.capabilityPolicyHash,rebuilt.capabilityPolicyHash,"PHIL_ROUTINE_POLICY_MISMATCH","capabilityPolicyHash");
  return rebuilt;
}

export interface PhilRoutineHumanPresentationV1 {
  readonly formatVersionHash: Hex; readonly applicationId: Hex; readonly applicationNameHash: Hex;
  readonly principalIdHash: Hex; readonly scopeId: Hex; readonly scopeInstance: Hex; readonly scopeEpoch: string;
  readonly executionEnvironmentHash: Hex; readonly networkLabelHash: Hex; readonly account: string;
  readonly accountLabelHash: Hex; readonly target: string; readonly targetRuntimeCodeHash: Hex;
  readonly targetLabelHash: Hex; readonly actionTypeHash: Hex; readonly actionLabelHash: Hex;
  readonly parametersHash: Hex; readonly parameterSummaryHash: Hex; readonly valueWei: string;
  readonly maximumTotalFeeWei: string; readonly validAfter: string; readonly validUntil: string;
  readonly capabilityId: Hex; readonly capabilityEpoch: string; readonly policyHash: Hex;
  readonly policyEpoch: string; readonly externalNetwork: false; readonly productionAuthority: false;
  readonly meaningfulAssets: false; readonly humanPresentationHash: Hex;
}

export function createPhilRoutineHumanPresentationV1(input: {
  readonly environment: PhilExecutionEnvironmentV1;
  readonly configuration: PhilRoutineAccountConfigurationV1;
  readonly catalog: PhilRoutineCatalogV1;
  readonly capabilityPolicy: PhilRoutineCapabilityPolicyV1;
  readonly action: PhilEvmSingleCallV1;
  readonly targetCalldata: BytesLike;
}): PhilRoutineHumanPresentationV1 {
  const env=validatePhilExecutionEnvironmentV1(input.environment);
  const action=validatePhilEvmSingleCallV1(input.action);
  const config=input.configuration,policy=input.capabilityPolicy;
  const catalog=validatePhilRoutineCatalogV1(input.catalog,{environment:env,configuration:config});
  same(action.chainId,PHIL_STEP6C_CHAIN_ID.toString(),"PHIL_ROUTINE_PRESENTATION_MISMATCH","chainId");
  same(action.account,config.account,"PHIL_ROUTINE_PRESENTATION_MISMATCH","account");
  same(action.entryPoint,env.entryPoint,"PHIL_ROUTINE_PRESENTATION_MISMATCH","entryPoint");
  same(action.target,config.approvedTarget,"PHIL_ROUTINE_PRESENTATION_MISMATCH","target");
  same(action.targetCalldataHash,keccak256(input.targetCalldata),"PHIL_ROUTINE_PRESENTATION_MISMATCH","targetCalldataHash");
  if (action.valueWei!=="0" || BigInt(action.maxTotalFeeWei)>BigInt(policy.maximumTotalFeeWei)
    || BigInt(action.validAfter)<BigInt(policy.validAfter) || BigInt(action.validUntil)>BigInt(policy.validUntil)) {
    fail("PHIL_ROUTINE_PRESENTATION_POLICY_MISMATCH","action exceeds the stable policy");
  }
  const record={formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.HUMAN_PRESENTATION,
    applicationId:config.applicationId,applicationNameHash:catalog.entries[0]!.displayTextHash,
    principalIdHash:config.principalIdHash,scopeId:config.scopeId,scopeInstance:config.scopeInstance,scopeEpoch:"1",
    executionEnvironmentHash:env.executionEnvironmentHash,networkLabelHash:catalog.entries[1]!.displayTextHash,
    account:config.account,accountLabelHash:catalog.entries[2]!.displayTextHash,target:config.approvedTarget,
    targetRuntimeCodeHash:config.approvedTargetRuntimeCodeHash,targetLabelHash:catalog.entries[3]!.displayTextHash,
    actionTypeHash:config.actionTypeHash,actionLabelHash:catalog.entries[4]!.displayTextHash,
    parametersHash:action.actionHash,parameterSummaryHash:derivePhilRoutineParameterSummaryHashV1(input.targetCalldata),
    valueWei:action.valueWei,maximumTotalFeeWei:action.maxTotalFeeWei,validAfter:action.validAfter,
    validUntil:action.validUntil,capabilityId:policy.capabilityId,capabilityEpoch:"1",
    policyHash:policy.capabilityPolicyHash,policyEpoch:"1",externalNetwork:false as const,
    productionAuthority:false as const,meaningfulAssets:false as const};
  const humanPresentationHash=keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","bytes32","bytes32","address","bytes32","address","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","uint256","uint48","uint48","bytes32","uint64","bytes32","uint64","bool","bool","bool"],
    [record.formatVersionHash,record.applicationId,record.applicationNameHash,record.principalIdHash,record.scopeId,
      record.scopeInstance,1n,record.executionEnvironmentHash,record.networkLabelHash,record.account,record.accountLabelHash,
      record.target,record.targetRuntimeCodeHash,record.targetLabelHash,record.actionTypeHash,record.actionLabelHash,
      record.parametersHash,record.parameterSummaryHash,BigInt(record.valueWei),BigInt(record.maximumTotalFeeWei),
      BigInt(record.validAfter),BigInt(record.validUntil),record.capabilityId,1n,record.policyHash,1n,false,false,false]
  )) as Hex;
  return Object.freeze({...record,humanPresentationHash});
}

export interface PhilRoutineAuthorizationCoreV1 {
  readonly formatVersionHash: Hex; readonly protocolContextHash: Hex; readonly sessionId: Hex; readonly nonceSeed: Hex;
  readonly issuedAt: string; readonly expiresAt: string; readonly executionEnvironmentHash: Hex;
  readonly adapterManifestHash: Hex; readonly signatureRegistryHash: Hex; readonly deviceEnrollmentHash: Hex;
  readonly accountConfigurationHash: Hex; readonly catalogHash: Hex; readonly capabilityPolicyHash: Hex;
  readonly actionHash: Hex; readonly targetCalldataHash: Hex; readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex; readonly humanPresentationHash: Hex; readonly authorizationCoreDigest: Hex;
}

export function createPhilRoutineAuthorizationCoreV1(input: Omit<PhilRoutineAuthorizationCoreV1,
  "formatVersionHash"|"protocolContextHash"|"authorizationCoreDigest">): PhilRoutineAuthorizationCoreV1 {
  const issuedAt=u(input.issuedAt,64,"issuedAt",true),expiresAt=u(input.expiresAt,64,"expiresAt",true);
  if (BigInt(expiresAt)!==BigInt(issuedAt)+PHIL_STEP6C_REQUEST_SECONDS) {
    fail("PHIL_ROUTINE_REQUEST_VALIDITY_INVALID","request lifetime must be exactly 120 seconds");
  }
  const record={formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.AUTHORIZATION_CORE,
    protocolContextHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.TRANSPORT,sessionId:b32(input.sessionId,"sessionId"),
    nonceSeed:b32(input.nonceSeed,"nonceSeed"),issuedAt,expiresAt,
    executionEnvironmentHash:b32(input.executionEnvironmentHash,"executionEnvironmentHash"),
    adapterManifestHash:b32(input.adapterManifestHash,"adapterManifestHash"),
    signatureRegistryHash:b32(input.signatureRegistryHash,"signatureRegistryHash"),
    deviceEnrollmentHash:b32(input.deviceEnrollmentHash,"deviceEnrollmentHash"),
    accountConfigurationHash:b32(input.accountConfigurationHash,"accountConfigurationHash"),
    catalogHash:b32(input.catalogHash,"catalogHash"),capabilityPolicyHash:b32(input.capabilityPolicyHash,"capabilityPolicyHash"),
    actionHash:b32(input.actionHash,"actionHash"),targetCalldataHash:b32(input.targetCalldataHash,"targetCalldataHash"),
    authorizationEnvelopeDigest:b32(input.authorizationEnvelopeDigest,"authorizationEnvelopeDigest"),
    rootProofNullifier:b32(input.rootProofNullifier,"rootProofNullifier",true),
    humanPresentationHash:b32(input.humanPresentationHash,"humanPresentationHash")};
  if (record.rootProofNullifier!==PHIL_ZERO_BYTES32) fail("PHIL_ROUTINE_ROOT_PROOF_FORBIDDEN","routine core requires zero root proof");
  const authorizationCoreDigest=keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32"],
    [record.formatVersionHash,record.protocolContextHash,record.sessionId,record.nonceSeed,BigInt(issuedAt),BigInt(expiresAt),
      record.executionEnvironmentHash,record.adapterManifestHash,record.signatureRegistryHash,record.deviceEnrollmentHash,
      record.accountConfigurationHash,record.catalogHash,record.capabilityPolicyHash,record.actionHash,
      record.targetCalldataHash,record.authorizationEnvelopeDigest,record.rootProofNullifier,record.humanPresentationHash]
  )) as Hex;
  return Object.freeze({...record,authorizationCoreDigest});
}

export function validatePhilRoutineAuthorizationCoreV1(core: PhilRoutineAuthorizationCoreV1): PhilRoutineAuthorizationCoreV1 {
  const rebuilt=createPhilRoutineAuthorizationCoreV1(core);
  same(core.authorizationCoreDigest,rebuilt.authorizationCoreDigest,"PHIL_ROUTINE_CORE_MISMATCH","authorizationCoreDigest");
  same(core.formatVersionHash,rebuilt.formatVersionHash,"PHIL_ROUTINE_CORE_MISMATCH","formatVersionHash");
  same(core.protocolContextHash,rebuilt.protocolContextHash,"PHIL_ROUTINE_CORE_MISMATCH","protocolContextHash");
  return rebuilt;
}

export function derivePhilRoutineApprovalNonceV1(input: {
  readonly authorizationCoreDigest: BytesLike; readonly sessionId: BytesLike; readonly nonceSeed: BytesLike;
}): Hex {
  return keccak256(abiCoder.encode(["bytes32","bytes32","bytes32","bytes32"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.APPROVAL_NONCE,b32(input.authorizationCoreDigest,"authorizationCoreDigest"),
      b32(input.sessionId,"sessionId"),b32(input.nonceSeed,"nonceSeed")])) as Hex;
}

export interface PhilRoutineAuthorizationRequestV1 {
  readonly formatVersionHash: Hex; readonly executionEnvironment: PhilExecutionEnvironmentV1;
  readonly adapterManifest: PhilAdapterManifestV1; readonly signatureRegistry: PhilRoutineSignatureRegistryV2;
  readonly deviceEnrollment: PhilRoutineDeviceEnrollmentV2; readonly accountConfiguration: PhilRoutineAccountConfigurationV1;
  readonly catalogEntries: readonly PhilRoutineCatalogEntryV1[]; readonly capabilityPolicy: PhilRoutineCapabilityPolicyV1;
  readonly action: PhilEvmSingleCallV1; readonly targetCalldata: Hex; readonly authorizationEnvelope: PhilAuthorizationEnvelopeV1;
  readonly unsignedDeviceApproval: PhilEvmAdapterDeviceApprovalV1; readonly humanPresentation: PhilRoutineHumanPresentationV1;
  readonly authorizationCore: PhilRoutineAuthorizationCoreV1; readonly executionEnvironmentHash: Hex;
  readonly adapterManifestHash: Hex; readonly signatureRegistryHash: Hex; readonly deviceEnrollmentHash: Hex;
  readonly accountConfigurationHash: Hex; readonly catalogHash: Hex; readonly capabilityPolicyHash: Hex;
  readonly actionHash: Hex; readonly authorizationEnvelopeDigest: Hex; readonly humanPresentationHash: Hex;
  readonly authorizationCoreDigest: Hex; readonly approvalNonce: Hex; readonly deviceApprovalDigest: Hex;
  readonly requestId: Hex; readonly platformSigningDigest: Hex;
}

export function createPhilRoutineAuthorizationRequestV1(input: {
  readonly executionEnvironment: PhilExecutionEnvironmentV1; readonly adapterManifest: PhilAdapterManifestV1;
  readonly signatureRegistry: PhilRoutineSignatureRegistryV2; readonly deviceEnrollment: PhilRoutineDeviceEnrollmentV2;
  readonly accountConfiguration: PhilRoutineAccountConfigurationV1; readonly catalog: PhilRoutineCatalogV1;
  readonly capabilityPolicy: PhilRoutineCapabilityPolicyV1; readonly action: PhilEvmSingleCallV1;
  readonly targetCalldata: BytesLike; readonly sessionId: BytesLike; readonly nonceSeed: BytesLike;
  readonly issuedAt: string | number | bigint; readonly expiresAt: string | number | bigint;
}): PhilRoutineAuthorizationRequestV1 {
  const env=validatePhilExecutionEnvironmentV1(input.executionEnvironment);
  const manifest=validatePhilStep6CLocalAdapterManifestV1(input.adapterManifest);
  const registry=validatePhilRoutineSignatureRegistryV2(input.signatureRegistry);
  const enrollment=validatePhilRoutineDeviceEnrollmentV2(input.deviceEnrollment);
  const config=validatePhilRoutineAccountConfigurationV1(input.accountConfiguration,{
    environment:env,adapterManifest:manifest,enrollment,account:input.accountConfiguration.account,
    accountRuntimeCodeHash:input.accountConfiguration.accountRuntimeCodeHash,
    scopedOwnerCommitment:input.accountConfiguration.scopedOwnerCommitment,
    approvedTarget:input.accountConfiguration.approvedTarget,
    approvedTargetRuntimeCodeHash:input.accountConfiguration.approvedTargetRuntimeCodeHash,
    nonceKey:input.accountConfiguration.nonceKey,maximumValueWei:input.accountConfiguration.maximumValueWei,
    maximumTotalFeeWei:input.accountConfiguration.maximumTotalFeeWei
  });
  const catalog=validatePhilRoutineCatalogV1(input.catalog,{environment:env,configuration:config});
  const policy=validatePhilRoutineCapabilityPolicyV1(input.capabilityPolicy,{
    environment:env,adapterManifest:manifest,enrollment,configuration:config,catalog,
    profilePolicyValidAfter:input.capabilityPolicy.validAfter
  });
  const action=validatePhilEvmSingleCallV1(input.action);
  const issuedAt=u(input.issuedAt,48,"issuedAt",true),expiresAt=u(input.expiresAt,48,"expiresAt",true);
  if (BigInt(expiresAt)!==BigInt(issuedAt)+PHIL_STEP6C_REQUEST_SECONDS
    || action.validAfter!==issuedAt || action.validUntil!==expiresAt
    || BigInt(issuedAt)<BigInt(policy.validAfter) || BigInt(expiresAt)>BigInt(policy.validUntil)) {
    fail("PHIL_ROUTINE_REQUEST_VALIDITY_INVALID","request and action must share one contained 120-second interval");
  }
  const targetCalldata=hexlify(input.targetCalldata) as Hex;
  const presentation=createPhilRoutineHumanPresentationV1({environment:env,configuration:config,catalog,
    capabilityPolicy:policy,action,targetCalldata});
  const accountBindingHash=derivePhilEvmAccountBindingHashV1(manifest,action);
  const nonceDomain=derivePhilEvmNonceDomainV1(manifest,action);
  const authorizationEnvelope=createPhilAuthorizationEnvelopeV1({operationClass:1,
    scopedOwnerCommitment:config.scopedOwnerCommitment,scopeId:config.scopeId,scopeInstance:config.scopeInstance,
    scopeEpoch:"1",principalIdHash:config.principalIdHash,capabilityId:policy.capabilityId,capabilityEpoch:"1",
    networkIdHash:env.networkIdHash,accountBindingHash,adapterId:env.adapterId,actionTypeHash:config.actionTypeHash,
    parametersHash:action.actionHash,intentDigest:derivePhilEvmIntentDigestV1(manifest,action),
    policyHash:policy.capabilityPolicyHash,nonceDomain,nonce:action.userOpNonce,rootProofNullifier:PHIL_ZERO_BYTES32,
    validAfter:issuedAt,validUntil:expiresAt,valueLimit:action.valueWei,feeLimit:action.maxTotalFeeWei,
    deviceEpoch:"1",recoveryEpoch:"1",validatorEpoch:"1",deviceSignatureSuiteId:PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
    proofDescriptorHash:PHIL_ZERO_BYTES32,humanPresentationHash:presentation.humanPresentationHash});
  const authorizationEnvelopeDigest=derivePhilAuthorizationEnvelopeDigestV1(authorizationEnvelope);
  const core=createPhilRoutineAuthorizationCoreV1({sessionId:b32(input.sessionId,"sessionId"),nonceSeed:b32(input.nonceSeed,"nonceSeed"),
    issuedAt,expiresAt,executionEnvironmentHash:env.executionEnvironmentHash,adapterManifestHash:manifest.manifestHash,
    signatureRegistryHash:registry.registryHash,deviceEnrollmentHash:enrollment.deviceEnrollmentHash,
    accountConfigurationHash:config.accountConfigurationHash,catalogHash:catalog.catalogHash,
    capabilityPolicyHash:policy.capabilityPolicyHash,actionHash:action.actionHash,
    targetCalldataHash:keccak256(targetCalldata) as Hex,authorizationEnvelopeDigest,rootProofNullifier:PHIL_ZERO_BYTES32,
    humanPresentationHash:presentation.humanPresentationHash});
  const approvalNonce=derivePhilRoutineApprovalNonceV1(core);
  const unsignedDeviceApproval=Object.freeze({deviceId:enrollment.deviceId,deviceKeyId:enrollment.deviceKeyId,
    deviceEpoch:"1",approvalNonce,approvedAt:issuedAt,approvalExpiresAt:expiresAt});
  const deviceApprovalDigest=derivePhilDeviceApprovalDigestV1({authorizationEnvelopeDigest,...unsignedDeviceApproval});
  const requestId=keccak256(abiCoder.encode(["bytes32","bytes32","bytes32","bytes32"],
    [PHIL_ROUTINE_DOMAIN_HASHES_V1.AUTHORIZATION_REQUEST,core.authorizationCoreDigest,approvalNonce,deviceApprovalDigest])) as Hex;
  const platformSigningDigest=derivePhilDeviceApprovalSigningDigestV2(requestId);
  return Object.freeze({formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.AUTHORIZATION_REQUEST,
    executionEnvironment:env,adapterManifest:manifest,signatureRegistry:registry,deviceEnrollment:enrollment,
    accountConfiguration:config,catalogEntries:catalog.entries,capabilityPolicy:policy,action,targetCalldata,
    authorizationEnvelope,unsignedDeviceApproval,humanPresentation:presentation,authorizationCore:core,
    executionEnvironmentHash:env.executionEnvironmentHash,adapterManifestHash:manifest.manifestHash,
    signatureRegistryHash:registry.registryHash,deviceEnrollmentHash:enrollment.deviceEnrollmentHash,
    accountConfigurationHash:config.accountConfigurationHash,catalogHash:catalog.catalogHash,
    capabilityPolicyHash:policy.capabilityPolicyHash,actionHash:action.actionHash,authorizationEnvelopeDigest,
    humanPresentationHash:presentation.humanPresentationHash,authorizationCoreDigest:core.authorizationCoreDigest,
    approvalNonce,deviceApprovalDigest,requestId,platformSigningDigest});
}

export function validatePhilRoutineAuthorizationRequestV1(
  request: PhilRoutineAuthorizationRequestV1
): PhilRoutineAuthorizationRequestV1 {
  const rebuilt=createPhilRoutineAuthorizationRequestV1({executionEnvironment:request.executionEnvironment,
    adapterManifest:request.adapterManifest,signatureRegistry:request.signatureRegistry,
    deviceEnrollment:request.deviceEnrollment,accountConfiguration:request.accountConfiguration,
    catalog:{entries:request.catalogEntries,catalogHash:request.catalogHash},capabilityPolicy:request.capabilityPolicy,
    action:request.action,targetCalldata:request.targetCalldata,sessionId:request.authorizationCore.sessionId,
    nonceSeed:request.authorizationCore.nonceSeed,issuedAt:request.authorizationCore.issuedAt,
    expiresAt:request.authorizationCore.expiresAt});
  strictDeepEqual(request,rebuilt,"PHIL_ROUTINE_REQUEST_MISMATCH","request");
  return rebuilt;
}

export function parsePhilRoutineAuthorizationRequestJsonV1(input: string | Uint8Array): PhilRoutineAuthorizationRequestV1 {
  return validatePhilRoutineAuthorizationRequestV1(strictJsonObject(input) as unknown as PhilRoutineAuthorizationRequestV1);
}

export function serializePhilRoutineAuthorizationRequestJsonV1(
  input: PhilRoutineAuthorizationRequestV1
): string {
  return JSON.stringify(validatePhilRoutineAuthorizationRequestV1(input));
}

export interface PhilRoutineAuthorizationResponseV1 {
  readonly formatVersionHash: Hex; readonly protocolContextHash: Hex; readonly sessionId: Hex; readonly requestId: Hex;
  readonly deviceId: Hex; readonly deviceKeyId: Hex; readonly deviceEpoch: string; readonly humanPresentationHash: Hex;
  readonly deviceApprovalDigest: Hex; readonly platformSigningDigest: Hex; readonly signatureSuiteId: Hex;
  readonly providerProfileId: Hex; readonly wireEncodingId: Hex; readonly signatureR: Hex; readonly signatureS: Hex;
  readonly responseHash: Hex;
}

export function createPhilRoutineAuthorizationResponseV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly signature: BytesLike;
}): PhilRoutineAuthorizationResponseV1 {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request);
  const sig=decodePhilP256RawSignatureV2(input.signature);
  if (!verifyPhilP256RawSignatureV2({digest:request.platformSigningDigest,signature:input.signature,
    publicKeyX963:request.deviceEnrollment.publicKeyX963})) {
    fail("PHIL_ROUTINE_RESPONSE_SIGNATURE_INVALID","P-256 response signature is invalid");
  }
  const record={formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.AUTHORIZATION_RESPONSE,
    protocolContextHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.TRANSPORT,sessionId:request.authorizationCore.sessionId,
    requestId:request.requestId,deviceId:request.deviceEnrollment.deviceId,deviceKeyId:request.deviceEnrollment.deviceKeyId,
    deviceEpoch:"1",humanPresentationHash:request.humanPresentationHash,deviceApprovalDigest:request.deviceApprovalDigest,
    platformSigningDigest:request.platformSigningDigest,signatureSuiteId:PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
    providerProfileId:PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,wireEncodingId:PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
    signatureR:sig.r,signatureS:sig.s};
  const responseHash=keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32"],
    [record.formatVersionHash,record.protocolContextHash,record.sessionId,record.requestId,record.deviceId,record.deviceKeyId,1n,
      record.humanPresentationHash,record.deviceApprovalDigest,record.platformSigningDigest,record.signatureSuiteId,
      record.providerProfileId,record.wireEncodingId,record.signatureR,record.signatureS]
  )) as Hex;
  return Object.freeze({...record,responseHash});
}

export function verifyPhilRoutineAuthorizationResponseV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly response: PhilRoutineAuthorizationResponseV1;
}): PhilRoutineAuthorizationResponseV1 {
  const rebuilt=createPhilRoutineAuthorizationResponseV1({request:input.request,
    signature:encodePhilP256RawSignatureV2({r:input.response.signatureR,s:input.response.signatureS})});
  strictDeepEqual(input.response,rebuilt,"PHIL_ROUTINE_RESPONSE_MISMATCH","response");
  return rebuilt;
}

export function parsePhilRoutineAuthorizationResponseJsonV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1;
  readonly json: string | Uint8Array;
}): PhilRoutineAuthorizationResponseV1 {
  return verifyPhilRoutineAuthorizationResponseV1({request:input.request,
    response:strictJsonObject(input.json) as unknown as PhilRoutineAuthorizationResponseV1});
}

export function serializePhilRoutineAuthorizationResponseJsonV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1;
  readonly response: PhilRoutineAuthorizationResponseV1;
}): string {
  return JSON.stringify(verifyPhilRoutineAuthorizationResponseV1(input));
}

export interface PhilRoutineAuthorizationReceiptV1 {
  readonly formatVersionHash: Hex; readonly requestId: Hex; readonly authorizationCoreDigest: Hex;
  readonly authorizationEnvelopeDigest: Hex; readonly deviceApprovalDigest: Hex; readonly platformSigningDigest: Hex;
  readonly serializedUserOperationHash: Hex; readonly userOperationHash: Hex; readonly executionEnvironmentHash: Hex;
  readonly entryPointEventCommitment: Hex; readonly accountEventCommitment: Hex; readonly targetEventCommitment: Hex;
  readonly targetPreStateHash: Hex; readonly finalTargetStateHash: Hex; readonly entryPointCodeHash: Hex;
  readonly senderCreatorCodeHash: Hex; readonly accountCodeHash: Hex; readonly targetCodeHash: Hex;
  readonly transactionHash: Hex; readonly blockHash: Hex; readonly entryPointNonceBefore: string;
  readonly entryPointNonceAfter: string; readonly executedAt: string; readonly simulationPassed: true;
  readonly executionSucceeded: true; readonly externalNetwork: false; readonly productionAuthority: false;
  readonly receiptHash: Hex;
}

export interface PhilRoutineReceiptLogV1 {
  readonly address: string;
  readonly topics: readonly Hex[];
  readonly data: Hex;
  readonly index: string | number | bigint;
  readonly transactionHash: Hex;
  readonly blockHash: Hex;
  readonly removed: boolean;
}

export interface PhilRoutineSubmissionCommitEvidenceV1 {
  readonly requestId: BytesLike; readonly sessionId: BytesLike; readonly state: number;
  readonly entryPoint: string; readonly sender: string; readonly userOperationNonce: string | number | bigint;
  readonly serializedUserOperationHash: BytesLike; readonly officialUserOperationHash: BytesLike;
  readonly packedUserOperationBytes: BytesLike; readonly target: string;
  readonly targetRecordedValueBefore: BytesLike; readonly targetRecordedSequenceBefore: string | number | bigint;
  readonly targetPreStateHash: BytesLike; readonly scanStartBlockNumber: string | number | bigint;
  readonly scanStartBlockHash: BytesLike;
}

function addressTopic(value: string): Hex {
  let normalized: string;
  try { normalized=getAddress(value).toLowerCase(); }
  catch { return fail("PHIL_ROUTINE_ADDRESS_INVALID","topicAddress must be an EVM address"); }
  return `0x${"0".repeat(24)}${normalized.slice(2)}` as Hex;
}

function normalizeReceiptLog(log: PhilRoutineReceiptLogV1): Readonly<{
  address: string; topics: readonly Hex[]; data: Hex; index: string;
  transactionHash: Hex; blockHash: Hex; removed: boolean;
}> {
  const expectedKeys=["address","blockHash","data","index","removed","topics","transactionHash"];
  if (Object.keys(log).sort().join("\u0000")!==expectedKeys.join("\u0000")) {
    fail("PHIL_ROUTINE_RECEIPT_LOG_INVALID","receipt log key set is not exact");
  }
  if (!Array.isArray(log.topics) || log.topics.length<1 || log.topics.length>4 || typeof log.removed!=="boolean") {
    fail("PHIL_ROUTINE_RECEIPT_LOG_INVALID","receipt log shape is invalid");
  }
  return Object.freeze({address:addr(log.address,"log.address"),topics:Object.freeze(log.topics.map((topic,index)=>b32(topic,`log.topic[${index}]`,true))),
    data:hexlify(log.data).toLowerCase() as Hex,index:u(log.index,256,"log.index"),
    transactionHash:b32(log.transactionHash,"log.transactionHash"),blockHash:b32(log.blockHash,"log.blockHash"),removed:log.removed});
}

function eventCommitment(log: ReturnType<typeof normalizeReceiptLog>): Hex {
  const topics=[...log.topics,PHIL_ZERO_BYTES32,PHIL_ZERO_BYTES32,PHIL_ZERO_BYTES32].slice(0,4);
  return keccak256(abiCoder.encode(
    ["address","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
    [log.address,topics[0],topics[1],topics[2],topics[3],keccak256(log.data),BigInt(log.index),log.transactionHash,log.blockHash]
  )) as Hex;
}

function decodeCanonicalEventData(types: readonly string[], data: Hex, label: string): ReturnType<typeof abiCoder.decode> {
  let decoded: ReturnType<typeof abiCoder.decode>;
  try { decoded=abiCoder.decode(types,data); }
  catch { return fail("PHIL_ROUTINE_RECEIPT_MISMATCH",`${label} event data malformed`); }
  if (abiCoder.encode(types,[...decoded]).toLowerCase()!==data) {
    fail("PHIL_ROUTINE_RECEIPT_MISMATCH",`${label} event data is not byte-exact canonical ABI`);
  }
  return decoded;
}

export function createPhilRoutineAuthorizationReceiptV1(input: Omit<PhilRoutineAuthorizationReceiptV1,
  "formatVersionHash"|"receiptHash"|"simulationPassed"|"executionSucceeded"|"externalNetwork"|"productionAuthority"> & {
    readonly simulationPassed: boolean; readonly executionSucceeded: boolean;
    readonly externalNetwork: boolean; readonly productionAuthority: boolean;
  }): PhilRoutineAuthorizationReceiptV1 {
  if (!input.simulationPassed || !input.executionSucceeded || input.externalNetwork || input.productionAuthority) {
    fail("PHIL_ROUTINE_RECEIPT_STATUS_INVALID","receipt status must be true,true,false,false");
  }
  const nonceBefore=u(input.entryPointNonceBefore,256,"entryPointNonceBefore"),nonceAfter=u(input.entryPointNonceAfter,256,"entryPointNonceAfter");
  if (BigInt(nonceAfter)!==BigInt(nonceBefore)+1n) fail("PHIL_ROUTINE_RECEIPT_NONCE_INVALID","EntryPoint nonce must advance exactly once");
  const record={formatVersionHash:PHIL_ROUTINE_DOMAIN_HASHES_V1.AUTHORIZATION_RECEIPT,
    requestId:b32(input.requestId,"requestId"),authorizationCoreDigest:b32(input.authorizationCoreDigest,"authorizationCoreDigest"),
    authorizationEnvelopeDigest:b32(input.authorizationEnvelopeDigest,"authorizationEnvelopeDigest"),
    deviceApprovalDigest:b32(input.deviceApprovalDigest,"deviceApprovalDigest"),platformSigningDigest:b32(input.platformSigningDigest,"platformSigningDigest"),
    serializedUserOperationHash:b32(input.serializedUserOperationHash,"serializedUserOperationHash"),userOperationHash:b32(input.userOperationHash,"userOperationHash"),
    executionEnvironmentHash:b32(input.executionEnvironmentHash,"executionEnvironmentHash"),entryPointEventCommitment:b32(input.entryPointEventCommitment,"entryPointEventCommitment"),
    accountEventCommitment:b32(input.accountEventCommitment,"accountEventCommitment"),targetEventCommitment:b32(input.targetEventCommitment,"targetEventCommitment"),
    targetPreStateHash:b32(input.targetPreStateHash,"targetPreStateHash"),finalTargetStateHash:b32(input.finalTargetStateHash,"finalTargetStateHash"),
    entryPointCodeHash:b32(input.entryPointCodeHash,"entryPointCodeHash"),senderCreatorCodeHash:b32(input.senderCreatorCodeHash,"senderCreatorCodeHash"),
    accountCodeHash:b32(input.accountCodeHash,"accountCodeHash"),targetCodeHash:b32(input.targetCodeHash,"targetCodeHash"),
    transactionHash:b32(input.transactionHash,"transactionHash"),blockHash:b32(input.blockHash,"blockHash"),
    entryPointNonceBefore:nonceBefore,entryPointNonceAfter:nonceAfter,executedAt:u(input.executedAt,64,"executedAt",true),
    simulationPassed:true as const,executionSucceeded:true as const,externalNetwork:false as const,productionAuthority:false as const};
  const receiptHash=keccak256(abiCoder.encode(
    ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","uint256","uint64","bool","bool","bool","bool"],
    [record.formatVersionHash,record.requestId,record.authorizationCoreDigest,record.authorizationEnvelopeDigest,
      record.deviceApprovalDigest,record.platformSigningDigest,record.serializedUserOperationHash,record.userOperationHash,
      record.executionEnvironmentHash,record.entryPointEventCommitment,record.accountEventCommitment,record.targetEventCommitment,
      record.targetPreStateHash,record.finalTargetStateHash,record.entryPointCodeHash,record.senderCreatorCodeHash,
      record.accountCodeHash,record.targetCodeHash,record.transactionHash,record.blockHash,BigInt(nonceBefore),BigInt(nonceAfter),
      BigInt(record.executedAt),true,true,false,false]
  )) as Hex;
  return Object.freeze({...record,receiptHash});
}

const PHIL_PACKED_USER_OPERATION_V07_TYPES = Object.freeze([
  "address","uint256","bytes","bytes","bytes32","uint256","bytes32","bytes","bytes"
] as const);

export function derivePhilOfficialUserOperationHashV07(input: {
  readonly packedUserOperationBytes: BytesLike;
  readonly entryPoint: string;
  readonly chainId: string | number | bigint;
}): Hex {
  const packedBytes=hexlify(input.packedUserOperationBytes).toLowerCase() as Hex;
  let decoded: ReturnType<typeof abiCoder.decode>;
  try { decoded=abiCoder.decode(PHIL_PACKED_USER_OPERATION_V07_TYPES,packedBytes); }
  catch { return fail("PHIL_ROUTINE_PACKED_USER_OPERATION_INVALID","packed v0.7 UserOperation ABI is invalid"); }
  const canonical=abiCoder.encode(PHIL_PACKED_USER_OPERATION_V07_TYPES,[...decoded]).toLowerCase() as Hex;
  if (canonical!==packedBytes) {
    fail("PHIL_ROUTINE_PACKED_USER_OPERATION_INVALID","packed v0.7 UserOperation ABI is not canonical");
  }
  const innerHash=keccak256(abiCoder.encode(
    ["address","uint256","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
    [addr(decoded[0],"userOp.sender"),BigInt(decoded[1]),keccak256(decoded[2]),keccak256(decoded[3]),
      b32(decoded[4],"userOp.accountGasLimits"),BigInt(decoded[5]),b32(decoded[6],"userOp.gasFees"),
      keccak256(decoded[7])]
  ));
  return keccak256(abiCoder.encode(["bytes32","address","uint256"],
    [innerHash,addr(input.entryPoint,"entryPoint"),BigInt(u(input.chainId,256,"chainId",true))])) as Hex;
}

export function verifyPhilRoutineAuthorizationReceiptV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly receipt: PhilRoutineAuthorizationReceiptV1;
  readonly submissionCommit: PhilRoutineSubmissionCommitEvidenceV1;
  readonly evidence: {
    readonly packedUserOperationBytes: BytesLike; readonly userOperationHash: BytesLike;
    readonly logs: readonly PhilRoutineReceiptLogV1[]; readonly transactionStatus: string | number | bigint;
    readonly targetRecordedValueBefore: BytesLike; readonly targetRecordedSequenceBefore: string | number | bigint;
    readonly scanStartBlockNumber: string | number | bigint; readonly scanStartBlockHash: BytesLike;
    readonly targetRecordedValueAfter: BytesLike; readonly targetRecordedSequenceAfter: string | number | bigint;
    readonly blockTimestamp: string | number | bigint; readonly entryPointNonceBefore: string | number | bigint;
    readonly entryPointNonceAfter: string | number | bigint; readonly entryPointCodeHash: BytesLike;
    readonly senderCreatorCodeHash: BytesLike; readonly accountCodeHash: BytesLike;
    readonly targetCodeHash: BytesLike; readonly transactionHash: BytesLike; readonly blockHash: BytesLike;
  };
}): PhilRoutineAuthorizationReceiptV1 {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request);
  const committed=input.submissionCommit;
  if (![6,7,8,25].includes(committed.state)) {
    fail("PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","receipt requires a post-commit journal state");
  }
  same(b32(committed.requestId,"submissionCommit.requestId"),request.requestId,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","requestId");
  same(b32(committed.sessionId,"submissionCommit.sessionId"),request.authorizationCore.sessionId,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","sessionId");
  same(addr(committed.entryPoint,"submissionCommit.entryPoint"),request.executionEnvironment.entryPoint,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","entryPoint");
  same(addr(committed.sender,"submissionCommit.sender"),request.action.account,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","sender");
  same(u(committed.userOperationNonce,256,"submissionCommit.userOperationNonce"),request.action.userOpNonce,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","userOperationNonce");
  same(addr(committed.target,"submissionCommit.target"),request.action.target,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","target");
  const committedPacked=hexlify(committed.packedUserOperationBytes).toLowerCase() as Hex;
  const committedSerializedHash=keccak256(committedPacked) as Hex;
  same(b32(committed.serializedUserOperationHash,"submissionCommit.serializedUserOperationHash"),committedSerializedHash,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","serializedUserOperationHash");
  const committedOfficialHash=derivePhilOfficialUserOperationHashV07({packedUserOperationBytes:committedPacked,
    entryPoint:committed.entryPoint,chainId:request.executionEnvironment.chainId});
  same(b32(committed.officialUserOperationHash,"submissionCommit.officialUserOperationHash"),committedOfficialHash,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","officialUserOperationHash");
  const committedPreState=keccak256(abiCoder.encode(["address","bytes32","bytes32","uint64","uint64","bytes32"],
    [request.action.target,request.accountConfiguration.approvedTargetRuntimeCodeHash,
      b32(committed.targetRecordedValueBefore,"submissionCommit.targetRecordedValueBefore",true),
      BigInt(u(committed.targetRecordedSequenceBefore,64,"submissionCommit.targetRecordedSequenceBefore")),
      BigInt(u(committed.scanStartBlockNumber,64,"submissionCommit.scanStartBlockNumber")),
      b32(committed.scanStartBlockHash,"submissionCommit.scanStartBlockHash")])) as Hex;
  same(b32(committed.targetPreStateHash,"submissionCommit.targetPreStateHash"),committedPreState,
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","targetPreStateHash");
  const rebuilt=createPhilRoutineAuthorizationReceiptV1(input.receipt);
  strictDeepEqual(input.receipt,rebuilt,"PHIL_ROUTINE_RECEIPT_MISMATCH","receipt");
  same(rebuilt.requestId,request.requestId,"PHIL_ROUTINE_RECEIPT_MISMATCH","requestId");
  same(rebuilt.authorizationCoreDigest,request.authorizationCoreDigest,"PHIL_ROUTINE_RECEIPT_MISMATCH","authorizationCoreDigest");
  same(rebuilt.authorizationEnvelopeDigest,request.authorizationEnvelopeDigest,"PHIL_ROUTINE_RECEIPT_MISMATCH","authorizationEnvelopeDigest");
  same(rebuilt.deviceApprovalDigest,request.deviceApprovalDigest,"PHIL_ROUTINE_RECEIPT_MISMATCH","deviceApprovalDigest");
  same(rebuilt.platformSigningDigest,request.platformSigningDigest,"PHIL_ROUTINE_RECEIPT_MISMATCH","platformSigningDigest");
  same(rebuilt.executionEnvironmentHash,request.executionEnvironmentHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","executionEnvironmentHash");
  if (hexlify(input.evidence.packedUserOperationBytes).toLowerCase()!==committedPacked) {
    fail("PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","receipt operation bytes differ from durable submission commit");
  }
  const expectedSerializedHash=committedSerializedHash;
  same(rebuilt.serializedUserOperationHash,expectedSerializedHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","serializedUserOperationHash");
  const expectedOfficialHash=derivePhilOfficialUserOperationHashV07({
    packedUserOperationBytes:input.evidence.packedUserOperationBytes,
    entryPoint:request.executionEnvironment.entryPoint,
    chainId:request.executionEnvironment.chainId
  });
  same(rebuilt.userOperationHash,expectedOfficialHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","userOperationHash");
  same(rebuilt.userOperationHash,committedOfficialHash,"PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","committedUserOperationHash");
  same(rebuilt.userOperationHash,b32(input.evidence.userOperationHash,"evidence.userOperationHash"),"PHIL_ROUTINE_RECEIPT_MISMATCH","userOperationHashEvidence");
  const transactionHash=b32(input.evidence.transactionHash,"evidence.transactionHash"),blockHash=b32(input.evidence.blockHash,"evidence.blockHash");
  if (u(input.evidence.transactionStatus,8,"transactionStatus")!=="1") fail("PHIL_ROUTINE_RECEIPT_MISMATCH","transaction status is not success");
  const logs=input.evidence.logs.map(normalizeReceiptLog);
  if (logs.length<3 || logs.some((log)=>log.removed || log.transactionHash!==transactionHash || log.blockHash!==blockHash)) {
    fail("PHIL_ROUTINE_RECEIPT_MISMATCH","receipt logs must be unremoved and bound to one transaction/block");
  }
  const entryTopic=keccak256(toUtf8Bytes("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)")) as Hex;
  const accountTopic=keccak256(toUtf8Bytes("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)")) as Hex;
  const targetTopic=keccak256(toUtf8Bytes("ValueRecorded(bytes32,uint64)")) as Hex;
  const select=(topic: Hex)=>logs.filter((log)=>log.topics[0]===topic);
  const entryLogs=select(entryTopic),accountLogs=select(accountTopic),targetLogs=select(targetTopic);
  if (entryLogs.length!==1 || accountLogs.length!==1 || targetLogs.length!==1) fail("PHIL_ROUTINE_RECEIPT_MISMATCH","expected event count mismatch");
  const entryLog=entryLogs[0]!,accountLog=accountLogs[0]!,targetLog=targetLogs[0]!;
  if (BigInt(accountLog.index)>=BigInt(targetLog.index) || BigInt(targetLog.index)>=BigInt(entryLog.index)) {
    fail("PHIL_ROUTINE_RECEIPT_MISMATCH","expected event order mismatch");
  }
  if (entryLog.address!==request.executionEnvironment.entryPoint || entryLog.topics.length!==4
    || entryLog.topics[1]!==rebuilt.userOperationHash || entryLog.topics[2]!==addressTopic(request.action.account)
    || entryLog.topics[3]!==addressTopic("0x0000000000000000000000000000000000000000")) {
    fail("PHIL_ROUTINE_RECEIPT_MISMATCH","EntryPoint event identity mismatch");
  }
  const entryData=decodeCanonicalEventData(["uint256","bool","uint256","uint256"],entryLog.data,"EntryPoint");
  if (BigInt(entryData[0])!==BigInt(request.action.userOpNonce) || entryData[1]!==true) fail("PHIL_ROUTINE_RECEIPT_MISMATCH","EntryPoint event result mismatch");
  if (accountLog.address!==request.action.account || accountLog.topics.length!==4
    || accountLog.topics[1]!==request.requestId || accountLog.topics[2]!==request.authorizationEnvelopeDigest
    || accountLog.topics[3]!==request.deviceApprovalDigest) fail("PHIL_ROUTINE_RECEIPT_MISMATCH","account event topics mismatch");
  const accountData=decodeCanonicalEventData(["bytes32","bytes32","address"],accountLog.data,"account");
  if (accountData[0]!==request.platformSigningDigest || accountData[1]!==rebuilt.userOperationHash
    || addr(accountData[2],"accountEvent.target")!==request.action.target) fail("PHIL_ROUTINE_RECEIPT_MISMATCH","account event data mismatch");
  if (targetLog.address!==request.action.target || targetLog.topics.length!==2
    || targetLog.topics[1]!==PHIL_STEP6C_RECORDED_VALUE) fail("PHIL_ROUTINE_RECEIPT_MISMATCH","target event topics mismatch");
  const targetData=decodeCanonicalEventData(["uint64"],targetLog.data,"target");
  const beforeSequence=u(input.evidence.targetRecordedSequenceBefore,64,"targetRecordedSequenceBefore");
  same(b32(input.evidence.targetRecordedValueBefore,"targetRecordedValueBefore",true),
    b32(committed.targetRecordedValueBefore,"submissionCommit.targetRecordedValueBefore",true),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","targetRecordedValueBefore");
  same(beforeSequence,u(committed.targetRecordedSequenceBefore,64,"submissionCommit.targetRecordedSequenceBefore"),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","targetRecordedSequenceBefore");
  same(u(input.evidence.scanStartBlockNumber,64,"scanStartBlockNumber"),
    u(committed.scanStartBlockNumber,64,"submissionCommit.scanStartBlockNumber"),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","scanStartBlockNumber");
  same(b32(input.evidence.scanStartBlockHash,"scanStartBlockHash"),
    b32(committed.scanStartBlockHash,"submissionCommit.scanStartBlockHash"),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","scanStartBlockHash");
  const afterSequence=u(input.evidence.targetRecordedSequenceAfter,64,"targetRecordedSequenceAfter");
  if (BigInt(afterSequence)!==BigInt(beforeSequence)+1n || BigInt(targetData[0])!==BigInt(afterSequence)
    || b32(input.evidence.targetRecordedValueAfter,"targetRecordedValueAfter")!==PHIL_STEP6C_RECORDED_VALUE) {
    fail("PHIL_ROUTINE_RECEIPT_MISMATCH","target final state mismatch");
  }
  const expectedPreState=keccak256(abiCoder.encode(["address","bytes32","bytes32","uint64","uint64","bytes32"],
    [request.action.target,request.accountConfiguration.approvedTargetRuntimeCodeHash,
      b32(input.evidence.targetRecordedValueBefore,"targetRecordedValueBefore",true),BigInt(beforeSequence),
      BigInt(u(input.evidence.scanStartBlockNumber,64,"scanStartBlockNumber")),b32(input.evidence.scanStartBlockHash,"scanStartBlockHash")])) as Hex;
  const expectedFinalState=keccak256(abiCoder.encode(["address","bytes32","uint64","bytes32","bytes32"],
    [request.action.target,PHIL_STEP6C_RECORDED_VALUE,BigInt(afterSequence),transactionHash,blockHash])) as Hex;
  same(rebuilt.entryPointEventCommitment,eventCommitment(entryLog),"PHIL_ROUTINE_RECEIPT_MISMATCH","entryPointEventCommitment");
  same(rebuilt.accountEventCommitment,eventCommitment(accountLog),"PHIL_ROUTINE_RECEIPT_MISMATCH","accountEventCommitment");
  same(rebuilt.targetEventCommitment,eventCommitment(targetLog),"PHIL_ROUTINE_RECEIPT_MISMATCH","targetEventCommitment");
  same(rebuilt.targetPreStateHash,expectedPreState,"PHIL_ROUTINE_RECEIPT_MISMATCH","targetPreStateHash");
  same(rebuilt.targetPreStateHash,committedPreState,"PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","committedTargetPreStateHash");
  same(rebuilt.finalTargetStateHash,expectedFinalState,"PHIL_ROUTINE_RECEIPT_MISMATCH","finalTargetStateHash");
  same(rebuilt.transactionHash,transactionHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","transactionHash");
  same(rebuilt.blockHash,blockHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","blockHash");
  same(rebuilt.executedAt,u(input.evidence.blockTimestamp,64,"blockTimestamp",true),"PHIL_ROUTINE_RECEIPT_MISMATCH","executedAt");
  same(rebuilt.entryPointNonceBefore,u(input.evidence.entryPointNonceBefore,256,"entryPointNonceBefore"),"PHIL_ROUTINE_RECEIPT_MISMATCH","entryPointNonceBefore");
  same(rebuilt.entryPointNonceAfter,u(input.evidence.entryPointNonceAfter,256,"entryPointNonceAfter"),"PHIL_ROUTINE_RECEIPT_MISMATCH","entryPointNonceAfter");
  same(rebuilt.entryPointNonceBefore,u(committed.userOperationNonce,256,"submissionCommit.userOperationNonce"),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","committedEntryPointNonceBefore");
  same(rebuilt.entryPointNonceAfter,(BigInt(u(committed.userOperationNonce,256,"submissionCommit.userOperationNonce"))+1n).toString(),
    "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH","committedEntryPointNonceAfter");
  for (const field of ["entryPointCodeHash","senderCreatorCodeHash","accountCodeHash","targetCodeHash"] as const) {
    same(rebuilt[field],b32(input.evidence[field],`evidence.${field}`),"PHIL_ROUTINE_RECEIPT_MISMATCH",field);
  }
  same(rebuilt.entryPointCodeHash,request.executionEnvironment.entryPointRuntimeCodeHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","admittedEntryPointCodeHash");
  same(rebuilt.senderCreatorCodeHash,request.executionEnvironment.senderCreatorRuntimeCodeHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","admittedSenderCreatorCodeHash");
  same(rebuilt.accountCodeHash,request.accountConfiguration.accountRuntimeCodeHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","admittedAccountCodeHash");
  same(rebuilt.targetCodeHash,request.accountConfiguration.approvedTargetRuntimeCodeHash,"PHIL_ROUTINE_RECEIPT_MISMATCH","admittedTargetCodeHash");
  return rebuilt;
}
