import {
  Interface,
  Signature,
  concat,
  getAddress,
  getBytes,
  keccak256,
  verifyMessage
} from "ethers";

import type { Hex } from "./hashes.ts";
import type { PhilSepoliaMintAuthorizationV1 } from "./sepoliaMintAuthorizationV1.ts";
import type {
  PhilSepoliaMintComposedAuthorizationReleaseV1,
  PhilSepoliaMintReplayStoreV1
} from "./sepoliaMintComposedAuthorizationV1.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees,
  type PhilCorePackedUserOperation
} from "./runtime/philcore4337UserOperationPreparation.ts";
import type {
  PhilCore4337ValidatorSigner,
  PhilCore4337ValidatorSignerDescriptor
} from "./runtime/philcore4337UserOperationSigning.ts";

const gateInterface = new Interface([
  "function verifyAndConsume(bytes32 authorizationEnvelopeDigest,bytes32 rootProofNullifier,bytes32 deviceApprovalNonce,uint64 validUntil,address mintRecipient)"
]);
const accountInterface = new Interface([
  "function execute(address target,uint256 value,bytes data)"
]);
const factoryInterface = new Interface([
  "function createAccount(address executionOwner,bytes32 ownerCommitment,uint256 salt) returns (address)"
]);
const SECP256K1_N_DIV_2 = BigInt(
  "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
);

export interface PhilSepoliaMintGasPolicyV1 {
  readonly callGasLimit: string | number | bigint;
  readonly verificationGasLimit: string | number | bigint;
  readonly preVerificationGas: string | number | bigint;
  readonly maxFeePerGas: string | number | bigint;
  readonly maxPriorityFeePerGas: string | number | bigint;
}

export interface PhilSepoliaMintPreparedUserOperationV1 {
  readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex;
  readonly deviceApprovalNonce: Hex;
  readonly accountNonce: string;
  readonly executionOwner: string;
  readonly factory: string;
  readonly smartAccount: string;
  readonly actionGate: string;
  readonly gateCalldata: Hex;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly maximumTotalFeeWei: string;
  readonly signatureRequired: true;
  readonly submitted: false;
}

export interface PhilSepoliaMintSignedUserOperationV1
  extends Omit<PhilSepoliaMintPreparedUserOperationV1, "userOperation" | "signatureRequired"> {
  readonly userOperation: PhilCorePackedUserOperation;
  readonly signerDescriptor: PhilCore4337ValidatorSignerDescriptor;
  readonly signatureRequired: false;
  readonly signed: true;
  readonly submitted: false;
}

function fail(code: string): never {
  const error = new Error(code);
  error.name = "PhilSepoliaMintUserOperationV1Error";
  Object.assign(error, { code });
  throw error;
}

function uint(value: string | number | bigint, bits: 128 | 256, label: string): bigint {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/u.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch {
    fail(`PHIL_SEPOLIA_MINT_USER_OPERATION_${label}_INVALID`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    fail(`PHIL_SEPOLIA_MINT_USER_OPERATION_${label}_INVALID`);
  }
  return parsed;
}

function same(actual: string, expected: string, code: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) fail(code);
}

function assertReleaseBinding(input: {
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly release: PhilSepoliaMintComposedAuthorizationReleaseV1;
}): void {
  const { authorization, release } = input;
  const envelope = authorization.authorizationEnvelope;
  const bindings = authorization.bindings;
  if (!release.executionSigningAuthorized) fail("PHIL_SEPOLIA_MINT_SIGNING_NOT_RELEASED");
  same(release.authorizationEnvelopeDigest, authorization.authorizationEnvelopeDigest,
    "PHIL_SEPOLIA_MINT_RELEASE_ENVELOPE_MISMATCH");
  same(release.rootProofNullifier, envelope.rootProofNullifier,
    "PHIL_SEPOLIA_MINT_RELEASE_NULLIFIER_MISMATCH");
  if (release.accountNonce !== bindings.accountNonce) fail("PHIL_SEPOLIA_MINT_RELEASE_NONCE_MISMATCH");
  same(release.smartAccount, bindings.smartAccount, "PHIL_SEPOLIA_MINT_RELEASE_ACCOUNT_MISMATCH");
  same(release.actionGate, bindings.actionGate, "PHIL_SEPOLIA_MINT_RELEASE_GATE_MISMATCH");
  same(release.mintConsumer, bindings.mintConsumer, "PHIL_SEPOLIA_MINT_RELEASE_CONSUMER_MISMATCH");
  same(release.mintRecipient, bindings.mintRecipient, "PHIL_SEPOLIA_MINT_RELEASE_RECIPIENT_MISMATCH");
  if (release.validUntil !== bindings.validUntil) fail("PHIL_SEPOLIA_MINT_RELEASE_EXPIRY_MISMATCH");
  if (release.maximumTotalFeeWei !== bindings.maximumTotalFeeWei) {
    fail("PHIL_SEPOLIA_MINT_RELEASE_FEE_MISMATCH");
  }
}

export function preparePhilSepoliaMintUserOperationV1(input: {
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly release: PhilSepoliaMintComposedAuthorizationReleaseV1;
  readonly executionOwner: string;
  readonly ownerCommitment: Hex;
  readonly accountSalt: string | number | bigint;
  readonly accountDeployed: boolean;
  readonly gas: PhilSepoliaMintGasPolicyV1;
}): PhilSepoliaMintPreparedUserOperationV1 {
  assertReleaseBinding(input);
  const bindings = input.authorization.bindings;
  const executionOwner = getAddress(input.executionOwner).toLowerCase();
  const ownerCommitment = input.ownerCommitment.toLowerCase() as Hex;
  if (!/^0x[0-9a-f]{64}$/u.test(ownerCommitment) || /^0x0{64}$/u.test(ownerCommitment)) {
    fail("PHIL_SEPOLIA_MINT_USER_OPERATION_OWNER_COMMITMENT_INVALID");
  }
  const salt = uint(input.accountSalt, 256, "SALT");
  const callGasLimit = uint(input.gas.callGasLimit, 128, "CALL_GAS");
  const verificationGasLimit = uint(input.gas.verificationGasLimit, 128, "VERIFICATION_GAS");
  const preVerificationGas = uint(input.gas.preVerificationGas, 256, "PRE_VERIFICATION_GAS");
  const maxFeePerGas = uint(input.gas.maxFeePerGas, 128, "MAX_FEE_PER_GAS");
  const maxPriorityFeePerGas = uint(input.gas.maxPriorityFeePerGas, 128, "MAX_PRIORITY_FEE_PER_GAS");
  if (callGasLimit === 0n || verificationGasLimit === 0n || preVerificationGas === 0n
      || maxFeePerGas === 0n || maxPriorityFeePerGas > maxFeePerGas) {
    fail("PHIL_SEPOLIA_MINT_USER_OPERATION_GAS_POLICY_INVALID");
  }
  const maximumTotalFeeWei = maxFeePerGas
    * (callGasLimit + verificationGasLimit + preVerificationGas);
  if (maximumTotalFeeWei > BigInt(input.release.maximumTotalFeeWei)) {
    fail("PHIL_SEPOLIA_MINT_USER_OPERATION_FEE_LIMIT_EXCEEDED");
  }

  const gateCalldata = gateInterface.encodeFunctionData("verifyAndConsume", [
    input.release.authorizationEnvelopeDigest,
    input.release.rootProofNullifier,
    input.release.deviceApprovalNonce,
    BigInt(input.release.validUntil),
    input.release.mintRecipient
  ]) as Hex;
  const callData = accountInterface.encodeFunctionData("execute", [
    input.release.actionGate,
    0n,
    gateCalldata
  ]) as Hex;
  const initCode = input.accountDeployed
    ? PHILCORE_4337_EMPTY_BYTES
    : concat([
      bindings.factory,
      factoryInterface.encodeFunctionData("createAccount", [executionOwner, ownerCommitment, salt])
    ]).toLowerCase() as Hex;
  const userOperation: PhilCorePackedUserOperation = Object.freeze({
    sender: getAddress(bindings.smartAccount).toLowerCase(),
    nonce: bindings.accountNonce,
    initCode,
    callData,
    accountGasLimits: packPhilCore4337AccountGasLimits({ verificationGasLimit, callGasLimit }),
    preVerificationGas: preVerificationGas.toString(),
    gasFees: packPhilCore4337GasFees({ maxPriorityFeePerGas, maxFeePerGas }),
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES
  });
  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: bindings.entryPoint,
    chainId: Number(bindings.chainId)
  });
  return Object.freeze({
    authorizationEnvelopeDigest: input.release.authorizationEnvelopeDigest,
    rootProofNullifier: input.release.rootProofNullifier,
    deviceApprovalNonce: input.release.deviceApprovalNonce,
    accountNonce: bindings.accountNonce,
    executionOwner,
    factory: bindings.factory,
    smartAccount: bindings.smartAccount,
    actionGate: bindings.actionGate,
    gateCalldata,
    userOperation,
    userOperationHash,
    maximumTotalFeeWei: maximumTotalFeeWei.toString(),
    signatureRequired: true as const,
    submitted: false as const
  });
}

export async function signPhilSepoliaMintUserOperationV1(input: {
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly release: PhilSepoliaMintComposedAuthorizationReleaseV1;
  readonly prepared: PhilSepoliaMintPreparedUserOperationV1;
  readonly replayStore: PhilSepoliaMintReplayStoreV1;
  readonly signer: PhilCore4337ValidatorSigner;
}): Promise<PhilSepoliaMintSignedUserOperationV1> {
  assertReleaseBinding(input);
  if (!input.replayStore.hasExactReservation
      || !await input.replayStore.hasExactReservation({
        authorizationEnvelopeDigest: input.release.authorizationEnvelopeDigest,
        rootProofNullifier: input.release.rootProofNullifier,
        deviceApprovalNonce: input.release.deviceApprovalNonce,
        accountNonce: input.release.accountNonce
      })) fail("PHIL_SEPOLIA_MINT_DURABLE_RESERVATION_REQUIRED");
  same(input.prepared.authorizationEnvelopeDigest, input.release.authorizationEnvelopeDigest,
    "PHIL_SEPOLIA_MINT_PREPARED_ENVELOPE_MISMATCH");
  same(input.prepared.rootProofNullifier, input.release.rootProofNullifier,
    "PHIL_SEPOLIA_MINT_PREPARED_NULLIFIER_MISMATCH");
  same(input.prepared.deviceApprovalNonce, input.release.deviceApprovalNonce,
    "PHIL_SEPOLIA_MINT_PREPARED_APPROVAL_NONCE_MISMATCH");
  if (input.prepared.accountNonce !== input.release.accountNonce) {
    fail("PHIL_SEPOLIA_MINT_PREPARED_NONCE_MISMATCH");
  }
  const recomputed = computePhilCore4337UserOperationHash({
    userOperation: input.prepared.userOperation,
    entryPointAddress: input.authorization.bindings.entryPoint,
    chainId: Number(input.authorization.bindings.chainId)
  });
  same(recomputed, input.prepared.userOperationHash, "PHIL_SEPOLIA_MINT_USER_OPERATION_HASH_MISMATCH");
  const descriptor = await input.signer.checkAvailability();
  if (!descriptor.available || descriptor.mode !== "device_vault_beta_ecdsa"
      || descriptor.keyReference.custody !== "device_vault_encrypted"
      || descriptor.keyReference.privateKeyExportable !== false
      || descriptor.keyReference.derivedFromPhilSecret !== false) {
    fail("PHIL_SEPOLIA_MINT_DEVICE_VAULT_SIGNER_REQUIRED");
  }
  same(await input.signer.getOwnerAddress(), input.prepared.executionOwner,
    "PHIL_SEPOLIA_MINT_EXECUTION_OWNER_MISMATCH");
  const result = await input.signer.signUserOperationHash({
    userOperationHash: input.prepared.userOperationHash,
    signingDigest: input.prepared.userOperationHash,
    presentationDigest: input.authorization.bindings.humanPresentationHash,
    expectedOwner: input.prepared.executionOwner,
    chainId: Number(input.authorization.bindings.chainId),
    entryPointAddress: input.authorization.bindings.entryPoint,
    smartAccountAddress: input.prepared.smartAccount,
    nonce: input.prepared.accountNonce,
    callDataHash: keccak256(input.prepared.userOperation.callData) as Hex,
    auditCorrelationId: input.release.authorizationEnvelopeDigest
  });
  if (result.status !== "signed" || !result.signature) {
    fail("PHIL_SEPOLIA_MINT_DEVICE_VAULT_SIGNING_FAILED");
  }
  const signature = Signature.from(result.signature);
  if (BigInt(signature.s) > SECP256K1_N_DIV_2
      || verifyMessage(getBytes(input.prepared.userOperationHash), signature.serialized).toLowerCase()
        !== input.prepared.executionOwner.toLowerCase()) {
    fail("PHIL_SEPOLIA_MINT_EXECUTION_SIGNATURE_INVALID");
  }
  return Object.freeze({
    ...input.prepared,
    userOperation: Object.freeze({ ...input.prepared.userOperation, signature: signature.serialized as Hex }),
    signerDescriptor: descriptor,
    signatureRequired: false as const,
    signed: true as const,
    submitted: false as const
  });
}
