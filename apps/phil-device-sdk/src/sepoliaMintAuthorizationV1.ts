import {
  AbiCoder,
  getBytes,
  getAddress,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHIL_ZERO_BYTES32,
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1,
  type PhilAuthorizationEnvelopeV1
} from "./authorizationEnvelopeV1.ts";
import { derivePhilDeviceApprovalDigestV1 } from "./deviceApprovalV1.ts";
import { requirePhilNonZeroBytes32 } from "./secureIdentityV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_ETHEREUM_SEPOLIA_CHAIN_ID = 11155111n;
export const PHIL_ETHEREUM_ENTRYPOINT_V07 =
  "0x0000000071727de22e5e9d8baf0edac6f37da032" as const;
export const PHIL_SEPOLIA_MINT_SCOPE_ID = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_MINT_SCOPE_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_NETWORK_ID = keccak256(
  toUtf8Bytes("ETHEREUM_SEPOLIA_CHAIN_11155111")
) as Hex;
export const PHIL_SEPOLIA_MINT_ADAPTER_ID = keccak256(
  toUtf8Bytes("PHIL_ERC4337_V07_SEPOLIA_LOCAL_COMPOSED_MINT_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_ACTION_TYPE = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_ZERO_VALUE_MINT_PASS_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_NONCE_DOMAIN = keccak256(
  toUtf8Bytes("PHIL_SEPOLIA_MINT_ACCOUNT_NONCE_V1")
) as Hex;
export const PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE = keccak256(
  toUtf8Bytes("phil-signature-p256-sha256-prehash-raw-rs-low-s-v2")
) as Hex;

export interface PhilSepoliaMintAuthorizationBindingsV1 {
  readonly chainId: "11155111";
  readonly entryPoint: string;
  readonly factory: string;
  readonly smartAccount: string;
  readonly actionGate: string;
  readonly mintConsumer: string;
  readonly mintRecipient: string;
  readonly accountNonce: string;
  readonly validAfter: string;
  readonly validUntil: string;
  readonly maximumTotalFeeWei: string;
  readonly parametersHash: Hex;
  readonly accountBindingHash: Hex;
  readonly intentDigest: Hex;
  readonly policyHash: Hex;
  readonly humanPresentationHash: Hex;
  readonly scopeInstance: Hex;
}

export interface PhilSepoliaMintAuthorizationV1 {
  readonly bindings: PhilSepoliaMintAuthorizationBindingsV1;
  readonly authorizationEnvelope: PhilAuthorizationEnvelopeV1;
  readonly authorizationEnvelopeDigest: Hex;
}

function address(value: string, label: string): string {
  try {
    const normalized = getAddress(value).toLowerCase();
    if (normalized === "0x0000000000000000000000000000000000000000") throw new Error("zero");
    return normalized;
  } catch {
    throw new Error(`PHIL_SEPOLIA_MINT_${label.toUpperCase()}_INVALID`);
  }
}

function uint(value: string | number | bigint, bits: 64 | 256, label: string): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/u.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch {
    throw new Error(`PHIL_SEPOLIA_MINT_${label.toUpperCase()}_INVALID`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`PHIL_SEPOLIA_MINT_${label.toUpperCase()}_INVALID`);
  }
  return parsed.toString();
}

function bytes32(value: BytesLike, label: string): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    throw new Error(`PHIL_SEPOLIA_MINT_${label.toUpperCase()}_INVALID`);
  }
  if (getBytes(normalized).length !== 32) {
    throw new Error(`PHIL_SEPOLIA_MINT_${label.toUpperCase()}_INVALID`);
  }
  return normalized;
}

export function derivePhilSepoliaMintBindingsV1(input: {
  readonly factory: string;
  readonly smartAccount: string;
  readonly actionGate: string;
  readonly mintConsumer: string;
  readonly mintRecipient: string;
  readonly accountNonce: string | number | bigint;
  readonly validAfter: string | number | bigint;
  readonly validUntil: string | number | bigint;
  readonly maximumTotalFeeWei: string | number | bigint;
}): PhilSepoliaMintAuthorizationBindingsV1 {
  const entryPoint = PHIL_ETHEREUM_ENTRYPOINT_V07;
  const factory = address(input.factory, "factory");
  const smartAccount = address(input.smartAccount, "smart_account");
  const actionGate = address(input.actionGate, "action_gate");
  const mintConsumer = address(input.mintConsumer, "mint_consumer");
  const mintRecipient = address(input.mintRecipient, "mint_recipient");
  const accountNonce = uint(input.accountNonce, 256, "account_nonce");
  const validAfter = uint(input.validAfter, 64, "valid_after");
  const validUntil = uint(input.validUntil, 64, "valid_until");
  const maximumTotalFeeWei = uint(input.maximumTotalFeeWei, 256, "maximum_total_fee_wei");
  if (BigInt(validUntil) <= BigInt(validAfter) || maximumTotalFeeWei === "0") {
    throw new Error("PHIL_SEPOLIA_MINT_POLICY_INVALID");
  }
  const accountBindingHash = keccak256(abiCoder.encode(
    ["bytes32", "uint256", "address", "address", "address", "address"],
    [
      keccak256(toUtf8Bytes("PHIL_SEPOLIA_MINT_ACCOUNT_BINDING_V1")),
      PHIL_ETHEREUM_SEPOLIA_CHAIN_ID,
      entryPoint,
      factory,
      smartAccount,
      actionGate
    ]
  )) as Hex;
  const parametersHash = keccak256(abiCoder.encode(
    ["bytes32", "address", "address", "address", "uint256"],
    [PHIL_SEPOLIA_MINT_ACTION_TYPE, actionGate, mintConsumer, mintRecipient, 0n]
  )) as Hex;
  const scopeInstance = keccak256(abiCoder.encode(
    ["bytes32", "address", "address", "address"],
    [PHIL_SEPOLIA_MINT_SCOPE_ID, smartAccount, mintConsumer, mintRecipient]
  )) as Hex;
  const intentDigest = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "uint256", "uint64", "uint64"],
    [
      keccak256(toUtf8Bytes("PHIL_SEPOLIA_MINT_INTENT_V1")),
      accountBindingHash,
      parametersHash,
      PHIL_SEPOLIA_MINT_NETWORK_ID,
      BigInt(accountNonce),
      BigInt(validAfter),
      BigInt(validUntil)
    ]
  )) as Hex;
  const policyHash = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "uint256", "uint64", "uint64"],
    [
      keccak256(toUtf8Bytes("PHIL_SEPOLIA_ZERO_VALUE_MINT_POLICY_V1")),
      accountBindingHash,
      parametersHash,
      0n,
      BigInt(maximumTotalFeeWei),
      BigInt(validAfter),
      BigInt(validUntil)
    ]
  )) as Hex;
  const humanPresentationHash = keccak256(abiCoder.encode(
    ["bytes32", "uint256", "address", "address", "address", "address", "uint256", "uint64"],
    [
      keccak256(toUtf8Bytes("PHIL_SEPOLIA_MINT_HUMAN_PRESENTATION_V1")),
      PHIL_ETHEREUM_SEPOLIA_CHAIN_ID,
      smartAccount,
      actionGate,
      mintConsumer,
      mintRecipient,
      BigInt(maximumTotalFeeWei),
      BigInt(validUntil)
    ]
  )) as Hex;
  return Object.freeze({
    chainId: "11155111" as const,
    entryPoint,
    factory,
    smartAccount,
    actionGate,
    mintConsumer,
    mintRecipient,
    accountNonce,
    validAfter,
    validUntil,
    maximumTotalFeeWei,
    parametersHash,
    accountBindingHash,
    intentDigest,
    policyHash,
    humanPresentationHash,
    scopeInstance
  });
}

function envelopeInput(input: {
  readonly scopedOwnerCommitment: BytesLike;
  readonly proofDescriptorHash: BytesLike;
  readonly rootProofNullifier?: BytesLike;
  readonly scopeEpoch: string | number | bigint;
  readonly deviceEpoch: string | number | bigint;
  readonly recoveryEpoch: string | number | bigint;
  readonly validatorEpoch: string | number | bigint;
  readonly bindings: PhilSepoliaMintAuthorizationBindingsV1;
}) {
  const principalIdHash = keccak256(abiCoder.encode(
    ["bytes32", "address"],
    [keccak256(toUtf8Bytes("PHIL_SEPOLIA_MINT_PRINCIPAL_V1")), input.bindings.mintConsumer]
  )) as Hex;
  const nonceDomain = keccak256(abiCoder.encode(
    ["bytes32", "uint256", "address", "address"],
    [
      PHIL_SEPOLIA_MINT_NONCE_DOMAIN,
      PHIL_ETHEREUM_SEPOLIA_CHAIN_ID,
      input.bindings.entryPoint,
      input.bindings.smartAccount
    ]
  )) as Hex;
  return {
    operationClass: 2 as const,
    scopedOwnerCommitment: requirePhilNonZeroBytes32(
      input.scopedOwnerCommitment,
      "scopedOwnerCommitment"
    ),
    scopeId: PHIL_SEPOLIA_MINT_SCOPE_ID,
    scopeInstance: input.bindings.scopeInstance,
    scopeEpoch: uint(input.scopeEpoch, 64, "scope_epoch"),
    principalIdHash,
    capabilityId: PHIL_ZERO_BYTES32,
    capabilityEpoch: "1",
    networkIdHash: PHIL_SEPOLIA_MINT_NETWORK_ID,
    accountBindingHash: input.bindings.accountBindingHash,
    adapterId: PHIL_SEPOLIA_MINT_ADAPTER_ID,
    actionTypeHash: PHIL_SEPOLIA_MINT_ACTION_TYPE,
    parametersHash: input.bindings.parametersHash,
    intentDigest: input.bindings.intentDigest,
    policyHash: input.bindings.policyHash,
    nonceDomain,
    nonce: input.bindings.accountNonce,
    rootProofNullifier: bytes32(input.rootProofNullifier ?? PHIL_ZERO_BYTES32, "root_proof_nullifier"),
    validAfter: input.bindings.validAfter,
    validUntil: input.bindings.validUntil,
    valueLimit: "0",
    feeLimit: input.bindings.maximumTotalFeeWei,
    deviceEpoch: uint(input.deviceEpoch, 64, "device_epoch"),
    recoveryEpoch: uint(input.recoveryEpoch, 64, "recovery_epoch"),
    validatorEpoch: uint(input.validatorEpoch, 64, "validator_epoch"),
    deviceSignatureSuiteId: PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    proofDescriptorHash: requirePhilNonZeroBytes32(
      input.proofDescriptorHash,
      "proofDescriptorHash"
    ),
    humanPresentationHash: input.bindings.humanPresentationHash
  };
}

export function derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(input: {
  readonly scopedOwnerCommitment: BytesLike;
  readonly proofDescriptorHash: BytesLike;
  readonly scopeEpoch: string | number | bigint;
  readonly deviceEpoch: string | number | bigint;
  readonly recoveryEpoch: string | number | bigint;
  readonly validatorEpoch: string | number | bigint;
  readonly bindings: PhilSepoliaMintAuthorizationBindingsV1;
}): Hex {
  return derivePhilAuthorizationEnvelopeDigestV1(envelopeInput(input));
}

export function createPhilSepoliaMintAuthorizationV1(input: {
  readonly scopedOwnerCommitment: BytesLike;
  readonly proofDescriptorHash: BytesLike;
  readonly rootProofNullifier: BytesLike;
  readonly scopeEpoch: string | number | bigint;
  readonly deviceEpoch: string | number | bigint;
  readonly recoveryEpoch: string | number | bigint;
  readonly validatorEpoch: string | number | bigint;
  readonly bindings: PhilSepoliaMintAuthorizationBindingsV1;
}): PhilSepoliaMintAuthorizationV1 {
  const authorizationEnvelope = createPhilAuthorizationEnvelopeV1(envelopeInput(input));
  const authorizationEnvelopeDigest = derivePhilAuthorizationEnvelopeDigestV1(authorizationEnvelope);
  return Object.freeze({
    bindings: input.bindings,
    authorizationEnvelope,
    authorizationEnvelopeDigest
  });
}

export function derivePhilSepoliaMintDeviceApprovalDigestV1(input: {
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly deviceId: BytesLike;
  readonly deviceKeyId: BytesLike;
  readonly deviceEpoch: string | number | bigint;
  readonly approvalNonce: BytesLike;
  readonly approvedAt: string | number | bigint;
  readonly approvalExpiresAt: string | number | bigint;
}): Hex {
  return derivePhilDeviceApprovalDigestV1(input);
}
