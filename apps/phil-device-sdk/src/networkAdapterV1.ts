import {
  AbiCoder,
  getAddress,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1,
  PHIL_ZERO_BYTES32,
  type PhilAuthorizationEnvelopeV1
} from "./authorizationEnvelopeV1.ts";
import { derivePhilDeviceApprovalDigestV1 } from "./deviceApprovalV1.ts";
import { PHIL_CRYPTO_SCHEME_IDS_V1 } from "./postQuantumMigrationV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_ADAPTER_MANIFEST_V1_LABEL = "PHIL_ADAPTER_MANIFEST_V1" as const;
export const PHIL_EVM_SINGLE_CALL_V1_LABEL = "PHIL_EVM_SINGLE_CALL_V1" as const;
export const PHIL_EVM_ACCOUNT_BINDING_V1_LABEL = "PHIL_EVM_ACCOUNT_BINDING_V1" as const;
export const PHIL_EVM_NONCE_DOMAIN_V1_LABEL = "PHIL_EVM_NONCE_DOMAIN_V1" as const;
export const PHIL_EVM_INTENT_V1_LABEL = "PHIL_EVM_INTENT_V1" as const;
export const PHIL_EVM_ADAPTER_AUTHORIZATION_V1_LABEL =
  "PHIL_EVM_ADAPTER_AUTHORIZATION_V1" as const;

function domain(label: string): Hex {
  return keccak256(toUtf8Bytes(label)) as Hex;
}

export const PHIL_ADAPTER_MANIFEST_V1_HASH = domain(PHIL_ADAPTER_MANIFEST_V1_LABEL);
export const PHIL_EVM_SINGLE_CALL_V1_HASH = domain(PHIL_EVM_SINGLE_CALL_V1_LABEL);
export const PHIL_EVM_ACCOUNT_BINDING_V1_HASH = domain(PHIL_EVM_ACCOUNT_BINDING_V1_LABEL);
export const PHIL_EVM_NONCE_DOMAIN_V1_HASH = domain(PHIL_EVM_NONCE_DOMAIN_V1_LABEL);
export const PHIL_EVM_INTENT_V1_HASH = domain(PHIL_EVM_INTENT_V1_LABEL);
export const PHIL_EVM_ADAPTER_AUTHORIZATION_V1_HASH = domain(
  PHIL_EVM_ADAPTER_AUTHORIZATION_V1_LABEL
);

export const PHIL_ADAPTER_TYPE_V1 = Object.freeze({
  NETWORK_ACCOUNT: 1,
  CREDENTIAL: 2,
  DOCUMENT: 3,
  APPLICATION_SERVICE: 4,
  AGENT_EXECUTION: 5
} as const);

export const PHIL_ADAPTER_PQ_CAPABILITY_V1 = Object.freeze({
  NONE: 0,
  LOCAL_POLICY_ONLY: 1,
  ONCHAIN_OR_PROTOCOL_HYBRID: 2,
  ONCHAIN_OR_PROTOCOL_NATIVE: 3
} as const);

export const PHIL_ADAPTER_GUARANTEE_V1 = Object.freeze({
  LOCAL_POLICY_ONLY: 1,
  NETWORK_ENFORCED: 2
} as const);

export const PHIL_BASE_MAINNET_CHAIN_ID = 8453n;
export const PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS =
  "0x0000000071727de22e5e9d8baf0edac6f37da032" as const;
export const PHIL_BASE_MAINNET_NETWORK_ID_HASH = domain("eip155:8453");
export const PHIL_BASE_MAINNET_ADAPTER_ID = domain(
  "phil-adapter-base-mainnet-erc4337-local-reference-v1"
);
export const PHIL_EVM_NETWORK_ACCOUNT_ADAPTER_VERSION_HASH = domain(
  "phil-evm-network-account-adapter-v1"
);
export const PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID = domain(
  "phil-evm-erc4337-narrow-account-binding-v1"
);
export const PHIL_EVM_SCOPE_CANONICALIZATION_ID = domain(
  "phil-scope-eip155-chain-account-v1"
);
export const PHIL_EVM_SINGLE_CALL_CODEC_ID = domain(
  "phil-evm-single-call-hash-codec-v1"
);
export const PHIL_ERC4337_NONCE_MODEL_ID = domain(
  "erc4337-uint192-key-uint64-sequence-v1"
);
export const PHIL_ERC4337_FEE_MODEL_ID = domain(
  "erc4337-no-paymaster-explicit-max-total-fee-v1"
);

export class PhilNetworkAdapterV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilNetworkAdapterV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilNetworkAdapterV1Error(code, message);
}

function bytes32(value: BytesLike, label: string, allowZero = false): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    return fail("PHIL_ADAPTER_INVALID_BYTES32", `${label} must be bytes32`);
  }
  if (getBytes(normalized).length !== 32) {
    fail("PHIL_ADAPTER_INVALID_BYTES32", `${label} must be bytes32`);
  }
  if (!allowZero && normalized === PHIL_ZERO_BYTES32) {
    fail("PHIL_ADAPTER_ZERO_BYTES32", `${label} must be non-zero`);
  }
  return normalized;
}

function address(value: string, label: string): string {
  try {
    const normalized = getAddress(value).toLowerCase();
    if (normalized === "0x0000000000000000000000000000000000000000") {
      fail("PHIL_ADAPTER_ZERO_ADDRESS", `${label} must be non-zero`);
    }
    return normalized;
  } catch (error) {
    if (error instanceof PhilNetworkAdapterV1Error) throw error;
    return fail("PHIL_ADAPTER_INVALID_ADDRESS", `${label} must be a canonical EVM address`);
  }
}

function uint(
  value: string | number | bigint,
  bits: 8 | 48 | 64 | 128 | 192 | 256,
  label: string,
  allowZero = true
): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch {
    return fail("PHIL_ADAPTER_INVALID_UNSIGNED", `${label} must be canonical uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits)) || (!allowZero && parsed === 0n)) {
    fail("PHIL_ADAPTER_INVALID_UNSIGNED", `${label} must be canonical uint${bits}`);
  }
  return parsed.toString(10);
}

function strictBoolean(value: boolean, label: string): boolean {
  if (typeof value !== "boolean") {
    fail("PHIL_ADAPTER_INVALID_BOOLEAN", `${label} must be boolean`);
  }
  return value;
}

function knownEnum(value: number, allowed: readonly number[], label: string): number {
  if (!Number.isInteger(value) || !allowed.includes(value)) {
    fail("PHIL_ADAPTER_INVALID_ENUM", `${label} is unsupported`);
  }
  return value;
}

function schemeSet(values: readonly BytesLike[], label: string, allowEmpty = false): readonly Hex[] {
  const normalized = values.map((value) => bytes32(value, label)).sort();
  if (!allowEmpty && normalized.length === 0) {
    fail("PHIL_ADAPTER_SCHEME_SET_EMPTY", `${label} must not be empty`);
  }
  if (new Set(normalized).size !== normalized.length) {
    fail("PHIL_ADAPTER_SCHEME_SET_DUPLICATE", `${label} contains a duplicate`);
  }
  return Object.freeze(normalized);
}

export interface PhilAdapterManifestV1 {
  readonly adapterId: Hex;
  readonly adapterVersionHash: Hex;
  readonly adapterType: number;
  readonly networkIdHash: Hex;
  readonly accountModelId: Hex;
  readonly scopeCanonicalizationId: Hex;
  readonly actionCodecId: Hex;
  readonly replayModelId: Hex;
  readonly feeModelId: Hex;
  readonly supportedDeviceSignatureSuiteIds: readonly Hex[];
  readonly supportedProofSuiteIds: readonly Hex[];
  readonly postQuantumCapability: number;
  readonly implementationHash: Hex;
  readonly auditStatusHash: Hex;
  readonly manifestHash: Hex;
}

export function createPhilAdapterManifestV1(input: Omit<PhilAdapterManifestV1, "manifestHash">): PhilAdapterManifestV1 {
  const normalized = {
    adapterId: bytes32(input.adapterId, "adapterId"),
    adapterVersionHash: bytes32(input.adapterVersionHash, "adapterVersionHash"),
    adapterType: knownEnum(input.adapterType, Object.values(PHIL_ADAPTER_TYPE_V1), "adapterType"),
    networkIdHash: bytes32(input.networkIdHash, "networkIdHash"),
    accountModelId: bytes32(input.accountModelId, "accountModelId"),
    scopeCanonicalizationId: bytes32(input.scopeCanonicalizationId, "scopeCanonicalizationId"),
    actionCodecId: bytes32(input.actionCodecId, "actionCodecId"),
    replayModelId: bytes32(input.replayModelId, "replayModelId"),
    feeModelId: bytes32(input.feeModelId, "feeModelId"),
    supportedDeviceSignatureSuiteIds: schemeSet(
      input.supportedDeviceSignatureSuiteIds,
      "supportedDeviceSignatureSuiteIds"
    ),
    supportedProofSuiteIds: schemeSet(input.supportedProofSuiteIds, "supportedProofSuiteIds", true),
    postQuantumCapability: knownEnum(
      input.postQuantumCapability,
      Object.values(PHIL_ADAPTER_PQ_CAPABILITY_V1),
      "postQuantumCapability"
    ),
    implementationHash: bytes32(input.implementationHash, "implementationHash"),
    auditStatusHash: bytes32(input.auditStatusHash, "auditStatusHash")
  };
  if (normalized.adapterType !== PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT) {
    fail("PHIL_ADAPTER_TYPE_UNSUPPORTED", "Step 6A admits only a network-account adapter");
  }
  if (normalized.postQuantumCapability > PHIL_ADAPTER_PQ_CAPABILITY_V1.LOCAL_POLICY_ONLY) {
    fail("PHIL_ADAPTER_PQ_OVERCLAIM", "Step 6A has no protocol-enforced PQ path");
  }
  const manifestHash = keccak256(abiCoder.encode(
    [
      "bytes32", "bytes32", "bytes32", "uint8", "bytes32", "bytes32", "bytes32",
      "bytes32", "bytes32", "bytes32", "bytes32[]", "bytes32[]", "uint8", "bytes32", "bytes32"
    ],
    [
      PHIL_ADAPTER_MANIFEST_V1_HASH,
      normalized.adapterId,
      normalized.adapterVersionHash,
      normalized.adapterType,
      normalized.networkIdHash,
      normalized.accountModelId,
      normalized.scopeCanonicalizationId,
      normalized.actionCodecId,
      normalized.replayModelId,
      normalized.feeModelId,
      normalized.supportedDeviceSignatureSuiteIds,
      normalized.supportedProofSuiteIds,
      normalized.postQuantumCapability,
      normalized.implementationHash,
      normalized.auditStatusHash
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, manifestHash });
}

export function validatePhilAdapterManifestV1(manifest: PhilAdapterManifestV1): PhilAdapterManifestV1 {
  const rebuilt = createPhilAdapterManifestV1(manifest);
  if (rebuilt.manifestHash !== manifest.manifestHash) {
    fail("PHIL_ADAPTER_MANIFEST_HASH_MISMATCH", "manifest hash is not canonical");
  }
  return rebuilt;
}

export function validatePhilBaseMainnetAdapterManifestV1(
  manifestInput: PhilAdapterManifestV1
): PhilAdapterManifestV1 {
  const manifest = validatePhilAdapterManifestV1(manifestInput);
  if (
    manifest.adapterId !== PHIL_BASE_MAINNET_ADAPTER_ID
    || manifest.adapterVersionHash !== PHIL_EVM_NETWORK_ACCOUNT_ADAPTER_VERSION_HASH
    || manifest.adapterType !== PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT
    || manifest.networkIdHash !== PHIL_BASE_MAINNET_NETWORK_ID_HASH
    || manifest.accountModelId !== PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID
    || manifest.scopeCanonicalizationId !== PHIL_EVM_SCOPE_CANONICALIZATION_ID
    || manifest.actionCodecId !== PHIL_EVM_SINGLE_CALL_CODEC_ID
    || manifest.replayModelId !== PHIL_ERC4337_NONCE_MODEL_ID
    || manifest.feeModelId !== PHIL_ERC4337_FEE_MODEL_ID
    || manifest.postQuantumCapability !== PHIL_ADAPTER_PQ_CAPABILITY_V1.NONE
    || manifest.supportedDeviceSignatureSuiteIds.length !== 1
    || manifest.supportedDeviceSignatureSuiteIds[0]
      !== PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE
    || manifest.supportedProofSuiteIds.length !== 0
  ) {
    fail("PHIL_ADAPTER_BASE_MANIFEST_MISMATCH", "manifest is not the exact Base Step 6A profile");
  }
  return manifest;
}

export function createPhilBaseMainnetAdapterManifestV1(input: {
  readonly implementationHash: BytesLike;
  readonly auditStatusHash: BytesLike;
}): PhilAdapterManifestV1 {
  return createPhilAdapterManifestV1({
    adapterId: PHIL_BASE_MAINNET_ADAPTER_ID,
    adapterVersionHash: PHIL_EVM_NETWORK_ACCOUNT_ADAPTER_VERSION_HASH,
    adapterType: PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT,
    networkIdHash: PHIL_BASE_MAINNET_NETWORK_ID_HASH,
    accountModelId: PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID,
    scopeCanonicalizationId: PHIL_EVM_SCOPE_CANONICALIZATION_ID,
    actionCodecId: PHIL_EVM_SINGLE_CALL_CODEC_ID,
    replayModelId: PHIL_ERC4337_NONCE_MODEL_ID,
    feeModelId: PHIL_ERC4337_FEE_MODEL_ID,
    supportedDeviceSignatureSuiteIds: [PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE],
    supportedProofSuiteIds: [],
    postQuantumCapability: PHIL_ADAPTER_PQ_CAPABILITY_V1.NONE,
    implementationHash: bytes32(input.implementationHash, "implementationHash"),
    auditStatusHash: bytes32(input.auditStatusHash, "auditStatusHash")
  });
}

export interface PhilEvmSingleCallV1 {
  readonly formatVersionHash: Hex;
  readonly chainId: string;
  readonly account: string;
  readonly entryPoint: string;
  readonly target: string;
  readonly targetCalldataHash: Hex;
  readonly accountCallCommitment: Hex;
  readonly valueWei: string;
  readonly nonceKey: string;
  readonly nonceSequence: string;
  readonly userOpNonce: string;
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxTotalFeeWei: string;
  readonly initCodeHash: Hex;
  readonly paymasterAndDataHash: Hex;
  readonly validAfter: string;
  readonly validUntil: string;
  readonly actionHash: Hex;
}

export function createPhilEvmSingleCallV1(input: {
  readonly chainId: string | number | bigint;
  readonly account: string;
  readonly entryPoint: string;
  readonly target: string;
  readonly targetCalldataHash: BytesLike;
  readonly valueWei: string | number | bigint;
  readonly nonceKey: string | number | bigint;
  readonly nonceSequence: string | number | bigint;
  readonly callGasLimit: string | number | bigint;
  readonly verificationGasLimit: string | number | bigint;
  readonly preVerificationGas: string | number | bigint;
  readonly maxFeePerGas: string | number | bigint;
  readonly maxPriorityFeePerGas: string | number | bigint;
  readonly initCodeHash?: BytesLike;
  readonly paymasterAndDataHash?: BytesLike;
  readonly validAfter: string | number | bigint;
  readonly validUntil: string | number | bigint;
}): PhilEvmSingleCallV1 {
  const chainId = uint(input.chainId, 256, "chainId", false);
  const account = address(input.account, "account");
  const entryPoint = address(input.entryPoint, "entryPoint");
  const target = address(input.target, "target");
  if (target === account || target === entryPoint) {
    fail("PHIL_ADAPTER_TARGET_FORBIDDEN", "target cannot be the account or EntryPoint");
  }
  const targetCalldataHash = bytes32(input.targetCalldataHash, "targetCalldataHash");
  const valueWei = uint(input.valueWei, 256, "valueWei");
  const nonceKey = uint(input.nonceKey, 192, "nonceKey");
  const nonceSequence = uint(input.nonceSequence, 64, "nonceSequence");
  const userOpNonceValue = (BigInt(nonceKey) << 64n) | BigInt(nonceSequence);
  const callGasLimit = uint(input.callGasLimit, 128, "callGasLimit", false);
  const verificationGasLimit = uint(input.verificationGasLimit, 128, "verificationGasLimit", false);
  const preVerificationGas = uint(input.preVerificationGas, 256, "preVerificationGas", false);
  const maxFeePerGas = uint(input.maxFeePerGas, 128, "maxFeePerGas", false);
  const maxPriorityFeePerGas = uint(input.maxPriorityFeePerGas, 128, "maxPriorityFeePerGas");
  if (BigInt(maxPriorityFeePerGas) > BigInt(maxFeePerGas)) {
    fail("PHIL_ADAPTER_FEE_RELATION_INVALID", "maxPriorityFeePerGas exceeds maxFeePerGas");
  }
  const maxTotalFeeValue = (
    BigInt(callGasLimit) + BigInt(verificationGasLimit) + BigInt(preVerificationGas)
  ) * BigInt(maxFeePerGas);
  if (maxTotalFeeValue >= (1n << 256n)) {
    fail("PHIL_ADAPTER_FEE_OVERFLOW", "maximum total fee exceeds uint256");
  }
  const initCodeHash = bytes32(input.initCodeHash ?? PHIL_ZERO_BYTES32, "initCodeHash", true);
  const paymasterAndDataHash = bytes32(
    input.paymasterAndDataHash ?? PHIL_ZERO_BYTES32,
    "paymasterAndDataHash",
    true
  );
  if (initCodeHash !== PHIL_ZERO_BYTES32 || paymasterAndDataHash !== PHIL_ZERO_BYTES32) {
    fail("PHIL_ADAPTER_DYNAMIC_AUTHORITY_FORBIDDEN", "Step 6A forbids initCode and paymasters");
  }
  const validAfter = uint(input.validAfter, 48, "validAfter");
  const validUntil = uint(input.validUntil, 48, "validUntil", false);
  if (BigInt(validUntil) < BigInt(validAfter)) {
    fail("PHIL_ADAPTER_VALIDITY_INVALID", "validUntil precedes validAfter");
  }
  const accountCallCommitment = keccak256(abiCoder.encode(
    ["bytes32", "address", "uint256", "bytes32"],
    [PHIL_EVM_SINGLE_CALL_V1_HASH, target, BigInt(valueWei), targetCalldataHash]
  )) as Hex;
  const normalized = {
    formatVersionHash: PHIL_EVM_SINGLE_CALL_V1_HASH,
    chainId,
    account,
    entryPoint,
    target,
    targetCalldataHash,
    accountCallCommitment,
    valueWei,
    nonceKey,
    nonceSequence,
    userOpNonce: userOpNonceValue.toString(10),
    callGasLimit,
    verificationGasLimit,
    preVerificationGas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    maxTotalFeeWei: maxTotalFeeValue.toString(10),
    initCodeHash,
    paymasterAndDataHash,
    validAfter,
    validUntil
  };
  const actionHash = keccak256(abiCoder.encode(
    [
      "bytes32", "uint256", "address", "address", "address", "bytes32", "bytes32", "uint256",
      "uint192", "uint64", "uint256", "uint128", "uint128", "uint256", "uint128", "uint128",
      "uint256", "bytes32", "bytes32", "uint48", "uint48"
    ],
    [
      PHIL_EVM_SINGLE_CALL_V1_HASH,
      BigInt(chainId),
      account,
      entryPoint,
      target,
      targetCalldataHash,
      accountCallCommitment,
      BigInt(valueWei),
      BigInt(nonceKey),
      BigInt(nonceSequence),
      userOpNonceValue,
      BigInt(callGasLimit),
      BigInt(verificationGasLimit),
      BigInt(preVerificationGas),
      BigInt(maxFeePerGas),
      BigInt(maxPriorityFeePerGas),
      maxTotalFeeValue,
      initCodeHash,
      paymasterAndDataHash,
      BigInt(validAfter),
      BigInt(validUntil)
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, actionHash });
}

export function validatePhilEvmSingleCallV1(action: PhilEvmSingleCallV1): PhilEvmSingleCallV1 {
  if (action.formatVersionHash !== PHIL_EVM_SINGLE_CALL_V1_HASH) {
    fail("PHIL_ADAPTER_ACTION_FORMAT_MISMATCH", "EVM action format is unsupported");
  }
  const rebuilt = createPhilEvmSingleCallV1(action);
  if (
    rebuilt.actionHash !== action.actionHash
    || rebuilt.accountCallCommitment !== action.accountCallCommitment
    || rebuilt.userOpNonce !== action.userOpNonce
    || rebuilt.maxTotalFeeWei !== action.maxTotalFeeWei
  ) {
    fail("PHIL_ADAPTER_ACTION_HASH_MISMATCH", "EVM action is not canonical");
  }
  return rebuilt;
}

export function derivePhilEvmAccountBindingHashV1(
  manifestInput: PhilAdapterManifestV1,
  actionInput: PhilEvmSingleCallV1
): Hex {
  const manifest = validatePhilAdapterManifestV1(manifestInput);
  const action = validatePhilEvmSingleCallV1(actionInput);
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "uint256", "address", "address"],
    [
      PHIL_EVM_ACCOUNT_BINDING_V1_HASH,
      manifest.manifestHash,
      manifest.networkIdHash,
      manifest.accountModelId,
      BigInt(action.chainId),
      action.entryPoint,
      action.account
    ]
  )) as Hex;
}

export function derivePhilEvmNonceDomainV1(
  manifestInput: PhilAdapterManifestV1,
  actionInput: PhilEvmSingleCallV1
): Hex {
  const manifest = validatePhilAdapterManifestV1(manifestInput);
  const action = validatePhilEvmSingleCallV1(actionInput);
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "address", "address", "uint192"],
    [
      PHIL_EVM_NONCE_DOMAIN_V1_HASH,
      manifest.adapterId,
      manifest.networkIdHash,
      action.entryPoint,
      action.account,
      BigInt(action.nonceKey)
    ]
  )) as Hex;
}

export function derivePhilEvmIntentDigestV1(
  manifestInput: PhilAdapterManifestV1,
  actionInput: PhilEvmSingleCallV1
): Hex {
  const manifest = validatePhilAdapterManifestV1(manifestInput);
  const action = validatePhilEvmSingleCallV1(actionInput);
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHIL_EVM_INTENT_V1_HASH,
      manifest.manifestHash,
      action.actionHash,
      derivePhilEvmAccountBindingHashV1(manifest, action),
      derivePhilEvmNonceDomainV1(manifest, action)
    ]
  )) as Hex;
}

export interface PhilEvmAdapterAuthorizationV1 {
  readonly formatVersionHash: Hex;
  readonly manifestHash: Hex;
  readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex;
  readonly actionHash: Hex;
  readonly accountBindingHash: Hex;
  readonly nonceDomain: Hex;
  readonly deviceApprovalDigest: Hex;
  readonly guarantee: number;
  readonly deviceSignatureVerified: false;
  readonly networkAuthorizationPathAvailable: false;
  readonly productionAuthority: false;
  readonly networkActivity: false;
  readonly authorizationHash: Hex;
}

export interface PhilEvmAdapterDeviceApprovalV1 {
  readonly deviceId: BytesLike;
  readonly deviceKeyId: BytesLike;
  readonly deviceEpoch: string | number | bigint;
  readonly approvalNonce: BytesLike;
  readonly approvedAt: string | number | bigint;
  readonly approvalExpiresAt: string | number | bigint;
}

export function createPhilBaseMainnetAdapterAuthorizationV1(input: {
  readonly manifest: PhilAdapterManifestV1;
  readonly trustedManifestHash: BytesLike;
  readonly envelope: PhilAuthorizationEnvelopeV1;
  readonly action: PhilEvmSingleCallV1;
  readonly deviceApproval: PhilEvmAdapterDeviceApprovalV1;
}): PhilEvmAdapterAuthorizationV1 {
  const manifest = validatePhilBaseMainnetAdapterManifestV1(input.manifest);
  if (manifest.manifestHash !== bytes32(input.trustedManifestHash, "trustedManifestHash")) {
    fail("PHIL_ADAPTER_MANIFEST_UNTRUSTED", "manifest does not match the separately pinned trust anchor");
  }
  const action = validatePhilEvmSingleCallV1(input.action);
  if (BigInt(action.chainId) !== PHIL_BASE_MAINNET_CHAIN_ID) {
    fail("PHIL_ADAPTER_CHAIN_MISMATCH", "action is not bound to Base mainnet");
  }
  if (action.entryPoint !== PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS) {
    fail("PHIL_ADAPTER_ENTRYPOINT_MISMATCH", "action is not bound to Base EntryPoint v0.7");
  }
  const envelope = createPhilAuthorizationEnvelopeV1(input.envelope);
  if (envelope.operationClass !== 1) {
    fail("PHIL_ADAPTER_OPERATION_UNSUPPORTED", "Step 6A admits routine capability actions only");
  }
  if (
    envelope.adapterId !== manifest.adapterId
    || envelope.networkIdHash !== manifest.networkIdHash
  ) {
    fail("PHIL_ADAPTER_ENVELOPE_MANIFEST_MISMATCH", "envelope does not bind the adapter manifest");
  }
  const accountBindingHash = derivePhilEvmAccountBindingHashV1(manifest, action);
  const nonceDomain = derivePhilEvmNonceDomainV1(manifest, action);
  const intentDigest = derivePhilEvmIntentDigestV1(manifest, action);
  if (envelope.accountBindingHash !== accountBindingHash) {
    fail("PHIL_ADAPTER_ACCOUNT_BINDING_MISMATCH", "envelope does not bind the exact EVM account");
  }
  if (
    envelope.actionTypeHash !== PHIL_EVM_SINGLE_CALL_V1_HASH
    || envelope.parametersHash !== action.actionHash
    || envelope.intentDigest !== intentDigest
  ) {
    fail("PHIL_ADAPTER_ACTION_BINDING_MISMATCH", "envelope does not bind the exact EVM action");
  }
  if (envelope.nonceDomain !== nonceDomain || envelope.nonce !== action.userOpNonce) {
    fail("PHIL_ADAPTER_NONCE_MISMATCH", "envelope does not bind the ERC-4337 nonce");
  }
  if (envelope.validAfter !== action.validAfter || envelope.validUntil !== action.validUntil) {
    fail("PHIL_ADAPTER_VALIDITY_MISMATCH", "envelope validity does not match the EVM action");
  }
  if (BigInt(action.valueWei) > BigInt(envelope.valueLimit)) {
    fail("PHIL_ADAPTER_VALUE_LIMIT_EXCEEDED", "EVM value exceeds the envelope limit");
  }
  if (BigInt(action.maxTotalFeeWei) > BigInt(envelope.feeLimit)) {
    fail("PHIL_ADAPTER_FEE_LIMIT_EXCEEDED", "EVM maximum fee exceeds the envelope limit");
  }
  if (!manifest.supportedDeviceSignatureSuiteIds.includes(envelope.deviceSignatureSuiteId)) {
    fail("PHIL_ADAPTER_DEVICE_SUITE_UNSUPPORTED", "device signature suite is not supported");
  }
  if (manifest.supportedProofSuiteIds.length !== 0) {
    fail("PHIL_ADAPTER_PROOF_SUPPORT_OVERCLAIM", "Step 6A Base profile must not advertise proof support");
  }
  const authorizationEnvelopeDigest = derivePhilAuthorizationEnvelopeDigestV1(envelope);
  const deviceApprovalEpoch = uint(input.deviceApproval.deviceEpoch, 64, "deviceApproval.deviceEpoch", false);
  const approvedAt = uint(input.deviceApproval.approvedAt, 64, "deviceApproval.approvedAt", false);
  const approvalExpiresAt = uint(
    input.deviceApproval.approvalExpiresAt,
    64,
    "deviceApproval.approvalExpiresAt",
    false
  );
  if (deviceApprovalEpoch !== envelope.deviceEpoch) {
    fail("PHIL_ADAPTER_DEVICE_EPOCH_MISMATCH", "device approval epoch does not match the envelope");
  }
  if (
    BigInt(approvedAt) < BigInt(action.validAfter)
    || BigInt(approvalExpiresAt) > BigInt(action.validUntil)
  ) {
    fail("PHIL_ADAPTER_DEVICE_APPROVAL_WINDOW_INVALID", "device approval is outside the action window");
  }
  const deviceApprovalDigest = derivePhilDeviceApprovalDigestV1({
    authorizationEnvelopeDigest,
    deviceId: bytes32(input.deviceApproval.deviceId, "deviceApproval.deviceId"),
    deviceKeyId: bytes32(input.deviceApproval.deviceKeyId, "deviceApproval.deviceKeyId"),
    deviceEpoch: deviceApprovalEpoch,
    approvalNonce: bytes32(input.deviceApproval.approvalNonce, "deviceApproval.approvalNonce"),
    approvedAt,
    approvalExpiresAt
  });
  const normalized = {
    formatVersionHash: PHIL_EVM_ADAPTER_AUTHORIZATION_V1_HASH,
    manifestHash: manifest.manifestHash,
    authorizationEnvelopeDigest,
    rootProofNullifier: envelope.rootProofNullifier,
    actionHash: action.actionHash,
    accountBindingHash,
    nonceDomain,
    deviceApprovalDigest,
    guarantee: PHIL_ADAPTER_GUARANTEE_V1.LOCAL_POLICY_ONLY,
    deviceSignatureVerified: false as const,
    networkAuthorizationPathAvailable: false as const,
    productionAuthority: false as const,
    networkActivity: false as const
  };
  strictBoolean(normalized.networkAuthorizationPathAvailable, "networkAuthorizationPathAvailable");
  const authorizationHash = keccak256(abiCoder.encode(
    [
      "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
      "bytes32", "uint8", "bool", "bool", "bool", "bool"
    ],
    [
      PHIL_EVM_ADAPTER_AUTHORIZATION_V1_HASH,
      normalized.manifestHash,
      normalized.authorizationEnvelopeDigest,
      normalized.rootProofNullifier,
      normalized.actionHash,
      normalized.accountBindingHash,
      normalized.nonceDomain,
      normalized.deviceApprovalDigest,
      normalized.guarantee,
      normalized.deviceSignatureVerified,
      normalized.networkAuthorizationPathAvailable,
      normalized.productionAuthority,
      normalized.networkActivity
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, authorizationHash });
}
