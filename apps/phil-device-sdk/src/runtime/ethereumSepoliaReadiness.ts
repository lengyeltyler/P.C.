import {
  AbiCoder,
  getAddress,
  isHexString,
  keccak256
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  PHILCORE_4337_ENTRYPOINT_VERSION,
  computePhilCore4337UserOperationHash,
  unpackPhilCore4337Uints,
  type PhilCorePackedUserOperation
} from "./philcore4337UserOperationPreparation.ts";
import type {
  PhilCore4337BundlerCapability,
  PhilCore4337BundlerConfiguration,
  PhilCore4337BundlerReference
} from "./philcore4337BundlerSubmission.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const ETHEREUM_SEPOLIA_CHAIN_ID = 11_155_111 as const;
export const ETHEREUM_SEPOLIA_PROFILE_ID = "ethereum_sepolia" as const;
export const ERC4337_V07_CANONICAL_ENTRYPOINT =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as const;
export const PHILCORE_SEPOLIA_AUTHORIZATION_VERSION =
  "philcore-sepolia-userop-authorization-v1" as const;
export const PHILCORE_SEPOLIA_AUTHORIZATION_DOMAIN =
  "PHILCORE_SEPOLIA_USEROP_AUTHORIZATION_V1" as const;
export const PHILCORE_SEPOLIA_FIRST_ACTION_CALL_TYPE = "single" as const;

export type EthereumSepoliaReadOnlyRpcMethod =
  | "eth_chainId"
  | "eth_getCode"
  | "eth_getBalance"
  | "eth_getTransactionCount"
  | "eth_feeHistory"
  | "eth_gasPrice"
  | "eth_call"
  | "eth_estimateGas"
  | "eth_supportedEntryPoints"
  | "eth_estimateUserOperationGas"
  | "eth_getUserOperationByHash"
  | "eth_getUserOperationReceipt";

export type EthereumSepoliaMutationRpcMethod =
  | "eth_sendRawTransaction"
  | "eth_sendUserOperation";

export interface EthereumSepoliaReadOnlyRpcClient {
  request(
    method: EthereumSepoliaReadOnlyRpcMethod,
    params: readonly unknown[]
  ): Promise<unknown>;
}

export interface EthereumSepoliaMutationTransport {
  sendRawTransaction(
    signedTransactionReference: string
  ): Promise<{ readonly transactionHash: Hex }>;
  sendUserOperation(
    signedUserOperationReference: string,
    entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT
  ): Promise<{ readonly userOperationHash: Hex }>;
}

export interface EthereumSepoliaNetworkProfile {
  readonly profileId: typeof ETHEREUM_SEPOLIA_PROFILE_ID;
  readonly networkName: "Ethereum Sepolia";
  readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
  readonly accountAbstractionPackage: "@account-abstraction/contracts";
  readonly accountAbstractionPackageVersion: "0.7.0";
  readonly paymasterAllowed: false;
  readonly firstActionValueWei: "0";
  readonly publicMutationApproved: false;
  readonly baseConfigurationInherited: false;
  readonly requiredEnvironmentReferences: Readonly<{
    rpcUrl: "PHILCORE_SEPOLIA_RPC_URL";
    bundlerUrl: "PHILCORE_SEPOLIA_BUNDLER_URL";
    expectedChainId: "PHILCORE_SEPOLIA_EXPECTED_CHAIN_ID";
    entryPoint: "PHILCORE_SEPOLIA_ENTRYPOINT";
    factory: "PHILCORE_SEPOLIA_FACTORY";
    accountImplementation: "PHILCORE_SEPOLIA_ACCOUNT_IMPLEMENTATION";
    testTarget: "PHILCORE_SEPOLIA_TEST_TARGET";
  }>;
}

export const ETHEREUM_SEPOLIA_NETWORK_PROFILE: EthereumSepoliaNetworkProfile =
  Object.freeze({
    profileId: ETHEREUM_SEPOLIA_PROFILE_ID,
    networkName: "Ethereum Sepolia",
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    accountAbstractionPackage: "@account-abstraction/contracts",
    accountAbstractionPackageVersion: "0.7.0",
    paymasterAllowed: false,
    firstActionValueWei: "0",
    publicMutationApproved: false,
    baseConfigurationInherited: false,
    requiredEnvironmentReferences: Object.freeze({
      rpcUrl: "PHILCORE_SEPOLIA_RPC_URL",
      bundlerUrl: "PHILCORE_SEPOLIA_BUNDLER_URL",
      expectedChainId: "PHILCORE_SEPOLIA_EXPECTED_CHAIN_ID",
      entryPoint: "PHILCORE_SEPOLIA_ENTRYPOINT",
      factory: "PHILCORE_SEPOLIA_FACTORY",
      accountImplementation: "PHILCORE_SEPOLIA_ACCOUNT_IMPLEMENTATION",
      testTarget: "PHILCORE_SEPOLIA_TEST_TARGET"
    })
  });

export interface EthereumSepoliaUserOperationAuthorizationEnvelope {
  readonly authorizationVersion: typeof PHILCORE_SEPOLIA_AUTHORIZATION_VERSION;
  readonly identityReference: Hex;
  readonly ownerCommitment: Hex;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly policyId: string;
  readonly policyCommitment: Hex;
  readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
  readonly smartAccountAddress: string;
  readonly factoryAddress?: string;
  readonly entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
  readonly nonce: string;
  readonly targetContract: string;
  readonly valueWei: "0";
  /** Hash of the terminal allowlisted target calldata. */
  readonly calldataHash: Hex;
  /** Hash of the complete PhilCore4337Account.execute(...) UserOperation calldata. */
  readonly userOperationCallDataHash: Hex;
  readonly callType: typeof PHILCORE_SEPOLIA_FIRST_ACTION_CALL_TYPE;
  readonly verificationGasLimit: string;
  readonly callGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly totalFeeCeilingWei: string;
  readonly validAfter: string;
  readonly expiresAt: string;
  readonly nullifier: Hex;
  readonly proofInputHash: Hex;
  readonly proofType: "stwo-unlock-keccak-v1";
  readonly runtimeAuthorizationVersion: string;
  readonly accountDeploymentIncluded: boolean;
  readonly userOperationHash: Hex;
  readonly approvalPresentationDigest: Hex;
  readonly userPresenceEvidenceDigest: Hex;
  readonly auditCorrelationId: string;
}

export interface EthereumSepoliaAuthorizationArtifactReference {
  readonly artifactKind:
    | "request"
    | "policy"
    | "approval"
    | "user_presence"
    | "stwo_proof"
    | "runtime_authorization"
    | "user_operation"
    | "signing_request";
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly identityReference: Hex;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly smartAccountAddress: string;
  readonly auditCorrelationId: string;
  readonly userOperationHash?: Hex;
  readonly proofInputHash?: Hex;
  readonly approvalPresentationDigest?: Hex;
  readonly userPresenceEvidenceDigest?: Hex;
}

export interface EthereumSepoliaAuthorizationValidationResult {
  readonly valid: boolean;
  readonly authorizationDigest?: Hex;
  readonly errors: readonly string[];
}

export interface EthereumSepoliaExecutionBinding {
  readonly targetContract: string;
  readonly valueWei: string;
  readonly terminalCalldataHash: Hex;
  readonly userOperationCallDataHash: Hex;
}

export type EthereumSepoliaManifestStatus =
  | "proposed"
  | "deployed"
  | "verified"
  | "accepted";

export interface EthereumSepoliaDeploymentManifestSummary {
  readonly status: EthereumSepoliaManifestStatus;
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly deploymentApproved: boolean;
  readonly userOperationSubmissionApproved: boolean;
  readonly productionApproved: boolean;
  readonly acceptedAddressesPresent: boolean;
}

export type EthereumSepoliaMutationOperation =
  | "deploy_test_target"
  | "deploy_l1_fact_verifier"
  | "deploy_action_gate"
  | "deploy_unlock_consumer"
  | "deploy_account_factory"
  | "submit_first_user_operation";

export interface EthereumSepoliaMutationGuardRequest {
  readonly operation: EthereumSepoliaMutationOperation;
  readonly manifest: EthereumSepoliaDeploymentManifestSummary;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly targetAddress?: string;
  readonly allowlistedTargetAddress?: string;
  readonly valueWei?: string;
  readonly paymasterAndData?: Hex;
  readonly maxFeePerGas?: string;
  readonly approvedMaxFeePerGas?: string;
  readonly expiresAt?: string;
  readonly repositoryClean: boolean;
}

export interface EthereumSepoliaMutationGuardResult {
  readonly allowed: boolean;
  readonly mode: "dry_run" | "mutation_blocked" | "mutation_approved";
  readonly errors: readonly string[];
}

export interface EthereumSepoliaDryRunReport {
  readonly profile: EthereumSepoliaNetworkProfile;
  readonly manifestStatus: EthereumSepoliaManifestStatus;
  readonly accountModel: "action_gate_restricted_v0_7";
  readonly factAvailabilityModel:
    "l1_anchored_fact_required_by_current_action_gate";
  readonly localProofOnlyPublicExecutionSupported: false;
  readonly firstActionValueWei: "0";
  readonly paymasterEnabled: false;
  readonly mutationPerformed: false;
  readonly blockers: readonly string[];
}

export function createEthereumSepoliaBundlerConfiguration(input: {
  readonly bundlerId: string;
  readonly endpointReference: string;
  readonly timeoutMs?: number;
  readonly pollingIntervalMs?: number;
}): PhilCore4337BundlerConfiguration {
  const reference: PhilCore4337BundlerReference = Object.freeze({
    bundlerId: input.bundlerId,
    profile: "ethereum_sepolia",
    endpointReference: input.endpointReference,
    liveNetwork: true,
    productionApproved: false,
    credentialsInRepository: false
  });
  return Object.freeze({
    status: "unapproved",
    profile: "ethereum_sepolia",
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    reference,
    supportedMethods: Object.freeze([
      "eth_supportedEntryPoints",
      "eth_chainId",
      "eth_estimateUserOperationGas",
      "eth_sendUserOperation",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ] satisfies PhilCore4337BundlerCapability[]),
    userOperationSerialization: "packed_v0_7",
    policy: Object.freeze({
      baseMainnetAllowed: false,
      paymasterAllowed: false,
      arbitraryUserOperationsAllowed: false,
      requiresSubmissionApproval: true,
      timeoutMs: input.timeoutMs ?? 30_000,
      pollingIntervalMs: input.pollingIntervalMs ?? 1_000,
      maxOperationBytes: 131_072
    })
  });
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function requireHex32(value: string, field: string, errors: string[]): void {
  if (!isHexString(value, 32)) errors.push(`${field}_invalid`);
}

function requireUint(value: string, field: string, errors: string[]): bigint | undefined {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n) errors.push(`${field}_invalid`);
    return parsed;
  } catch {
    errors.push(`${field}_invalid`);
    return undefined;
  }
}

export function computeEthereumSepoliaAuthorizationDigest(
  envelope: EthereumSepoliaUserOperationAuthorizationEnvelope
): Hex {
  const factoryAddress = envelope.factoryAddress
    ? normalizeAddress(envelope.factoryAddress)
    : "0x0000000000000000000000000000000000000000";
  return keccak256(abiCoder.encode(
    [
      "string",
      "string",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "string",
      "bytes32",
      "uint256",
      "address",
      "address",
      "address",
      "uint256",
      "address",
      "uint256",
      "bytes32",
      "bytes32",
      "string",
      "uint128",
      "uint128",
      "uint256",
      "uint128",
      "uint128",
      "uint256",
      "uint64",
      "uint64",
      "bytes32",
      "bytes32",
      "string",
      "string",
      "bool",
      "bytes32",
      "bytes32",
      "bytes32",
      "string"
    ],
    [
      PHILCORE_SEPOLIA_AUTHORIZATION_DOMAIN,
      envelope.authorizationVersion,
      envelope.identityReference,
      envelope.ownerCommitment,
      envelope.actionId,
      envelope.canonicalActionDigest,
      envelope.policyId,
      envelope.policyCommitment,
      BigInt(envelope.chainId),
      normalizeAddress(envelope.smartAccountAddress),
      factoryAddress,
      normalizeAddress(envelope.entryPointAddress),
      BigInt(envelope.nonce),
      normalizeAddress(envelope.targetContract),
      BigInt(envelope.valueWei),
      envelope.calldataHash,
      envelope.userOperationCallDataHash,
      envelope.callType,
      BigInt(envelope.verificationGasLimit),
      BigInt(envelope.callGasLimit),
      BigInt(envelope.preVerificationGas),
      BigInt(envelope.maxFeePerGas),
      BigInt(envelope.maxPriorityFeePerGas),
      BigInt(envelope.totalFeeCeilingWei),
      BigInt(envelope.validAfter),
      BigInt(envelope.expiresAt),
      envelope.nullifier,
      envelope.proofInputHash,
      envelope.proofType,
      envelope.runtimeAuthorizationVersion,
      envelope.accountDeploymentIncluded,
      envelope.userOperationHash,
      envelope.approvalPresentationDigest,
      envelope.userPresenceEvidenceDigest,
      envelope.auditCorrelationId
    ]
  )) as Hex;
}

export function validateEthereumSepoliaAuthorizationEnvelope(input: {
  readonly envelope: EthereumSepoliaUserOperationAuthorizationEnvelope;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly executionBinding: EthereumSepoliaExecutionBinding;
  readonly allowlistedTargetAddress: string;
  readonly nowSeconds?: number;
}): EthereumSepoliaAuthorizationValidationResult {
  const { envelope, userOperation } = input;
  const errors: string[] = [];
  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1000);

  if (envelope.authorizationVersion !== PHILCORE_SEPOLIA_AUTHORIZATION_VERSION) {
    errors.push("authorization_version_invalid");
  }
  if (envelope.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
  try {
    if (normalizeAddress(envelope.entryPointAddress) !== normalizeAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)) {
      errors.push("entry_point_mismatch");
    }
    if (normalizeAddress(envelope.smartAccountAddress) !== normalizeAddress(userOperation.sender)) {
      errors.push("smart_account_mismatch");
    }
    if (normalizeAddress(envelope.targetContract) !== normalizeAddress(input.allowlistedTargetAddress)) {
      errors.push("target_not_allowlisted");
    }
    if (normalizeAddress(envelope.targetContract) !== normalizeAddress(input.executionBinding.targetContract)) {
      errors.push("target_binding_mismatch");
    }
    if (envelope.factoryAddress) normalizeAddress(envelope.factoryAddress);
  } catch {
    errors.push("address_invalid");
  }

  requireHex32(envelope.identityReference, "identity_reference", errors);
  requireHex32(envelope.ownerCommitment, "owner_commitment", errors);
  requireHex32(envelope.actionId, "action_id", errors);
  requireHex32(envelope.canonicalActionDigest, "canonical_action_digest", errors);
  requireHex32(envelope.policyCommitment, "policy_commitment", errors);
  requireHex32(envelope.calldataHash, "calldata_hash", errors);
  requireHex32(envelope.userOperationCallDataHash, "user_operation_calldata_hash", errors);
  requireHex32(envelope.nullifier, "nullifier", errors);
  requireHex32(envelope.proofInputHash, "proof_input_hash", errors);
  requireHex32(envelope.userOperationHash, "user_operation_hash", errors);
  requireHex32(envelope.approvalPresentationDigest, "approval_presentation_digest", errors);
  requireHex32(envelope.userPresenceEvidenceDigest, "user_presence_evidence_digest", errors);

  if (envelope.valueWei !== "0") errors.push("value_must_be_zero");
  const envelopeValue = requireUint(envelope.valueWei, "value", errors);
  const boundValue = requireUint(input.executionBinding.valueWei, "bound_value", errors);
  if (envelopeValue !== undefined && boundValue !== undefined && envelopeValue !== boundValue) {
    errors.push("value_binding_mismatch");
  }
  if (envelope.callType !== PHILCORE_SEPOLIA_FIRST_ACTION_CALL_TYPE) errors.push("call_type_invalid");
  if (envelope.proofType !== "stwo-unlock-keccak-v1") errors.push("proof_type_invalid");
  if (userOperation.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymaster_not_allowed");
  if (input.executionBinding.terminalCalldataHash.toLowerCase() !== envelope.calldataHash.toLowerCase()) {
    errors.push("terminal_calldata_hash_mismatch");
  }
  if (
    input.executionBinding.userOperationCallDataHash.toLowerCase()
      !== envelope.userOperationCallDataHash.toLowerCase()
  ) {
    errors.push("user_operation_calldata_binding_mismatch");
  }
  if (keccak256(userOperation.callData).toLowerCase() !== envelope.userOperationCallDataHash.toLowerCase()) {
    errors.push("user_operation_calldata_hash_mismatch");
  }
  const userOperationNonce = requireUint(userOperation.nonce, "user_operation_nonce", errors);
  const envelopeNonce = requireUint(envelope.nonce, "nonce", errors);
  if (
    userOperationNonce !== undefined
    && envelopeNonce !== undefined
    && userOperationNonce !== envelopeNonce
  ) {
    errors.push("nonce_mismatch");
  }

  const gasLimits = unpackPhilCore4337Uints(userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(userOperation.gasFees);
  const verificationGas = requireUint(envelope.verificationGasLimit, "verification_gas_limit", errors);
  const callGas = requireUint(envelope.callGasLimit, "call_gas_limit", errors);
  const preVerificationGas = requireUint(envelope.preVerificationGas, "pre_verification_gas", errors);
  const maxFee = requireUint(envelope.maxFeePerGas, "max_fee_per_gas", errors);
  const maxPriorityFee = requireUint(
    envelope.maxPriorityFeePerGas,
    "max_priority_fee_per_gas",
    errors
  );
  const totalFeeCeiling = requireUint(envelope.totalFeeCeilingWei, "total_fee_ceiling", errors);
  if (verificationGas !== undefined && gasLimits.high128 !== verificationGas.toString()) {
    errors.push("verification_gas_limit_mismatch");
  }
  if (callGas !== undefined && gasLimits.low128 !== callGas.toString()) {
    errors.push("call_gas_limit_mismatch");
  }
  if (
    preVerificationGas !== undefined
    && BigInt(userOperation.preVerificationGas).toString() !== preVerificationGas.toString()
  ) {
    errors.push("pre_verification_gas_mismatch");
  }
  if (maxFee !== undefined && gasFees.low128 !== maxFee.toString()) {
    errors.push("max_fee_per_gas_mismatch");
  }
  if (maxPriorityFee !== undefined && gasFees.high128 !== maxPriorityFee.toString()) {
    errors.push("max_priority_fee_per_gas_mismatch");
  }

  if (
    maxFee !== undefined
    && totalFeeCeiling !== undefined
    && callGas !== undefined
    && verificationGas !== undefined
    && preVerificationGas !== undefined
    && (callGas + verificationGas + preVerificationGas) * maxFee > totalFeeCeiling
  ) {
    errors.push("fee_ceiling_exceeded");
  }

  const validAfter = requireUint(envelope.validAfter, "valid_after", errors);
  const expiresAt = requireUint(envelope.expiresAt, "expires_at", errors);
  if (validAfter !== undefined && expiresAt !== undefined && validAfter >= expiresAt) {
    errors.push("validity_window_invalid");
  }
  if (expiresAt !== undefined && expiresAt <= BigInt(nowSeconds)) errors.push("authorization_expired");

  const computedUserOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: envelope.entryPointAddress,
    chainId: envelope.chainId
  });
  if (computedUserOperationHash.toLowerCase() !== envelope.userOperationHash.toLowerCase()) {
    errors.push("user_operation_hash_mismatch");
  }

  let authorizationDigest: Hex | undefined;
  try {
    authorizationDigest = computeEthereumSepoliaAuthorizationDigest(envelope);
  } catch {
    errors.push("authorization_digest_encoding_failed");
  }
  return Object.freeze({
    valid: errors.length === 0,
    authorizationDigest,
    errors: Object.freeze(errors)
  });
}

export function validateEthereumSepoliaAuthorizationComposition(input: {
  readonly envelope: EthereumSepoliaUserOperationAuthorizationEnvelope;
  readonly artifacts: readonly EthereumSepoliaAuthorizationArtifactReference[];
}): EthereumSepoliaAuthorizationValidationResult {
  const errors: string[] = [];
  const requiredKinds = new Set<EthereumSepoliaAuthorizationArtifactReference["artifactKind"]>([
    "request",
    "policy",
    "approval",
    "user_presence",
    "stwo_proof",
    "runtime_authorization",
    "user_operation",
    "signing_request"
  ]);
  for (const artifact of input.artifacts) {
    requiredKinds.delete(artifact.artifactKind);
    if (artifact.actionId.toLowerCase() !== input.envelope.actionId.toLowerCase()) {
      errors.push(`${artifact.artifactKind}_action_id_mismatch`);
    }
    if (artifact.canonicalActionDigest.toLowerCase() !== input.envelope.canonicalActionDigest.toLowerCase()) {
      errors.push(`${artifact.artifactKind}_canonical_digest_mismatch`);
    }
    if (artifact.identityReference.toLowerCase() !== input.envelope.identityReference.toLowerCase()) {
      errors.push(`${artifact.artifactKind}_identity_mismatch`);
    }
    if (artifact.ownerCommitment.toLowerCase() !== input.envelope.ownerCommitment.toLowerCase()) {
      errors.push(`${artifact.artifactKind}_owner_commitment_mismatch`);
    }
    if (artifact.chainId !== input.envelope.chainId) errors.push(`${artifact.artifactKind}_chain_mismatch`);
    try {
      if (normalizeAddress(artifact.smartAccountAddress) !== normalizeAddress(input.envelope.smartAccountAddress)) {
        errors.push(`${artifact.artifactKind}_account_mismatch`);
      }
    } catch {
      errors.push(`${artifact.artifactKind}_account_invalid`);
    }
    if (artifact.auditCorrelationId !== input.envelope.auditCorrelationId) {
      errors.push(`${artifact.artifactKind}_audit_correlation_mismatch`);
    }
    if (
      artifact.userOperationHash
      && artifact.userOperationHash.toLowerCase() !== input.envelope.userOperationHash.toLowerCase()
    ) {
      errors.push(`${artifact.artifactKind}_user_operation_hash_mismatch`);
    }
    if (
      artifact.proofInputHash
      && artifact.proofInputHash.toLowerCase() !== input.envelope.proofInputHash.toLowerCase()
    ) {
      errors.push(`${artifact.artifactKind}_proof_input_hash_mismatch`);
    }
    if (
      artifact.approvalPresentationDigest
      && artifact.approvalPresentationDigest.toLowerCase()
        !== input.envelope.approvalPresentationDigest.toLowerCase()
    ) {
      errors.push(`${artifact.artifactKind}_approval_digest_mismatch`);
    }
    if (
      artifact.userPresenceEvidenceDigest
      && artifact.userPresenceEvidenceDigest.toLowerCase()
        !== input.envelope.userPresenceEvidenceDigest.toLowerCase()
    ) {
      errors.push(`${artifact.artifactKind}_user_presence_digest_mismatch`);
    }
  }
  for (const missing of requiredKinds) errors.push(`${missing}_artifact_missing`);

  let authorizationDigest: Hex | undefined;
  try {
    authorizationDigest = computeEthereumSepoliaAuthorizationDigest(input.envelope);
  } catch {
    errors.push("authorization_digest_encoding_failed");
  }
  return Object.freeze({
    valid: errors.length === 0,
    authorizationDigest,
    errors: Object.freeze(errors)
  });
}

export function validateEthereumSepoliaManifestStatus(
  manifest: EthereumSepoliaDeploymentManifestSummary
): EthereumSepoliaAuthorizationValidationResult {
  const errors: string[] = [];
  if (manifest.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("manifest_chain_id_mismatch");
  try {
    if (normalizeAddress(manifest.entryPointAddress) !== normalizeAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)) {
      errors.push("manifest_entry_point_mismatch");
    }
  } catch {
    errors.push("manifest_entry_point_invalid");
  }
  if (manifest.status === "proposed") {
    if (manifest.deploymentApproved) errors.push("proposed_manifest_cannot_approve_deployment");
    if (manifest.userOperationSubmissionApproved) errors.push("proposed_manifest_cannot_approve_submission");
    if (manifest.productionApproved) errors.push("proposed_manifest_cannot_approve_production");
    if (manifest.acceptedAddressesPresent) errors.push("proposed_manifest_cannot_claim_accepted_addresses");
  }
  if (manifest.status !== "accepted" && manifest.userOperationSubmissionApproved) {
    errors.push("submission_requires_accepted_manifest");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export function evaluateEthereumSepoliaMutationGuard(
  request: EthereumSepoliaMutationGuardRequest
): EthereumSepoliaMutationGuardResult {
  const errors: string[] = [];
  const manifestValidation = validateEthereumSepoliaManifestStatus(request.manifest);
  errors.push(...manifestValidation.errors);

  if (request.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
  try {
    if (normalizeAddress(request.entryPointAddress) !== normalizeAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)) {
      errors.push("entry_point_mismatch");
    }
    if (
      request.targetAddress
      && request.allowlistedTargetAddress
      && normalizeAddress(request.targetAddress) !== normalizeAddress(request.allowlistedTargetAddress)
    ) {
      errors.push("target_not_allowlisted");
    }
  } catch {
    errors.push("address_invalid");
  }
  if (request.valueWei !== undefined) {
    try {
      if (BigInt(request.valueWei) !== 0n) errors.push("value_must_be_zero");
    } catch {
      errors.push("value_invalid");
    }
  }
  if (request.paymasterAndData && request.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) {
    errors.push("paymaster_not_allowed");
  }
  if (
    request.maxFeePerGas !== undefined
    && request.approvedMaxFeePerGas !== undefined
  ) {
    try {
      if (BigInt(request.maxFeePerGas) > BigInt(request.approvedMaxFeePerGas)) {
        errors.push("fee_policy_exceeded");
      }
    } catch {
      errors.push("fee_policy_invalid");
    }
  }
  if (request.expiresAt && new Date(request.expiresAt).getTime() <= Date.now()) {
    errors.push("authorization_expired");
  }
  if (!request.repositoryClean) errors.push("repository_not_clean");
  if (request.environment.PHILCORE_PUBLIC_NETWORK_APPROVED !== "1") {
    errors.push("public_network_approval_missing");
  }
  if (request.environment.PHILCORE_ETHEREUM_SEPOLIA_APPROVED !== "1") {
    errors.push("ethereum_sepolia_approval_missing");
  }
  if (request.operation === "submit_first_user_operation") {
    if (request.environment.PHILCORE_USEROP_SUBMISSION_APPROVED !== "1") {
      errors.push("user_operation_submission_approval_missing");
    }
  } else if (request.environment.PHILCORE_ETHEREUM_SEPOLIA_DEPLOYMENT_APPROVED !== "1") {
    errors.push("deployment_approval_missing");
  }
  if (request.manifest.status !== "accepted") errors.push("accepted_manifest_required");
  if (!request.manifest.deploymentApproved) errors.push("manifest_deployment_approval_missing");
  if (
    request.operation === "submit_first_user_operation"
    && !request.manifest.userOperationSubmissionApproved
  ) {
    errors.push("manifest_submission_approval_missing");
  }

  return Object.freeze({
    allowed: errors.length === 0,
    mode: errors.length === 0 ? "mutation_approved" : "mutation_blocked",
    errors: Object.freeze(errors)
  });
}

export function classifyEthereumSepoliaRpcMethod(
  method: EthereumSepoliaReadOnlyRpcMethod | EthereumSepoliaMutationRpcMethod
): "READ_ONLY" | "PUBLIC_MUTATION" {
  return method === "eth_sendRawTransaction" || method === "eth_sendUserOperation"
    ? "PUBLIC_MUTATION"
    : "READ_ONLY";
}

export function createEthereumSepoliaDryRunReport(
  manifestStatus: EthereumSepoliaManifestStatus = "proposed"
): EthereumSepoliaDryRunReport {
  return Object.freeze({
    profile: ETHEREUM_SEPOLIA_NETWORK_PROFILE,
    manifestStatus,
    accountModel: "action_gate_restricted_v0_7",
    factAvailabilityModel: "l1_anchored_fact_required_by_current_action_gate",
    localProofOnlyPublicExecutionSupported: false,
    firstActionValueWei: "0",
    paymasterEnabled: false,
    mutationPerformed: false,
    blockers: Object.freeze([
      "ACP-0002 remains Proposed",
      "Ethereum Sepolia deployments are not accepted",
      "The current ActionGate path requires an Ethereum-visible verified fact for real STWO proofs",
      "RPC, bundler, custody operations, funding, fee caps, and submission approvals are unresolved",
      "All public-network mutation gates are intentionally disabled"
    ])
  });
}
