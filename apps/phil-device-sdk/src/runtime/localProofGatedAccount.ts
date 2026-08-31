import {
  AbiCoder,
  Interface,
  Signature,
  getAddress,
  getBytes,
  isHexString,
  keccak256,
  toUtf8Bytes,
  verifyMessage
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  PHILCORE_SEPOLIA_AUTHORIZATION_VERSION,
  validateEthereumSepoliaAuthorizationComposition,
  validateEthereumSepoliaAuthorizationEnvelope,
  type EthereumSepoliaAuthorizationArtifactReference,
  type EthereumSepoliaExecutionBinding,
  type EthereumSepoliaUserOperationAuthorizationEnvelope
} from "./ethereumSepoliaReadiness.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  unpackPhilCore4337Uints,
  type PhilCorePackedUserOperation
} from "./philcore4337UserOperationPreparation.ts";
import type {
  PhilCore4337SigningResult,
  PhilCore4337ValidatorSigner
} from "./philcore4337UserOperationSigning.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const accountInterface = new Interface([
  "function executeLocalProofAuthorization(bytes32 actionId,bytes32 authorizationDigest,uint64 expiry)"
]);
const confirmationTargetInterface = new Interface([
  "function confirmPhilCoreAction(bytes32 actionId,bytes32 authorizationDigest)"
]);

export const LOCAL_PROOF_GATED_SECURITY_MODEL = "local-proof-gated-v1" as const;
export const ETHEREUM_FACT_ENFORCED_SECURITY_MODEL = "ethereum-fact-enforced-v1" as const;
export const LOCAL_PROOF_GATED_SIGNATURE_VERSION = 1 as const;
export const LOCAL_PROOF_GATED_SECURITY_MODEL_ID =
  keccak256(toUtf8Bytes(LOCAL_PROOF_GATED_SECURITY_MODEL)) as Hex;
export const LOCAL_PROOF_GATED_SIGNATURE_DOMAIN =
  keccak256(toUtf8Bytes("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1")) as Hex;
export const LOCAL_PROOF_GATED_RUNTIME_AUTHORIZATION_DOMAIN =
  keccak256(toUtf8Bytes("PHILCORE_LOCAL_PROOF_GATED_RUNTIME_AUTHORIZATION_V1")) as Hex;
export const LOCAL_PROOF_GATED_UNSIGNED_PREPARATION_SCHEMA =
  "philcore-local-proof-gated-unsigned-user-operation-v1" as const;
export const LOCAL_PROOF_GATED_SIGNED_ARTIFACT_SCHEMA =
  "philcore-local-proof-gated-signed-user-operation-v1" as const;
export const LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE =
  "ethereum_sepolia_local_proof_gated_v1_signing" as const;

export interface LocalProofGatedProofEvidence {
  readonly status: "generated";
  readonly proofType: "stwo-unlock-keccak-v1";
  readonly proofArtifactDigest: Hex;
  readonly proofInputHash: Hex;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly generatedAt: string;
}

export interface LocalProofGatedVerificationEvidence {
  readonly status: "verified";
  readonly valid: true;
  readonly proofType: "stwo-unlock-keccak-v1";
  readonly proofArtifactDigest: Hex;
  readonly proofInputHash: Hex;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly verifiedAt: string;
}

export interface LocalProofGatedApprovalEvidence {
  readonly status: "approved";
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly presentationDigest: Hex;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly oneTime: true;
  readonly consumed: false;
}

export interface LocalProofGatedUserPresenceEvidence {
  readonly status: "verified";
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly evidenceDigest: Hex;
  readonly verifiedAt: string;
  readonly expiresAt: string;
}

export interface LocalProofGatedSigningPolicy {
  readonly maxVerificationGasLimit: string;
  readonly maxCallGasLimit: string;
  readonly maxPreVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxTotalFeeWei: string;
}

export interface LocalProofGatedSigningAuthorizationRequest {
  readonly envelope: EthereumSepoliaUserOperationAuthorizationEnvelope;
  readonly artifacts: readonly EthereumSepoliaAuthorizationArtifactReference[];
  readonly proof: LocalProofGatedProofEvidence;
  readonly verification: LocalProofGatedVerificationEvidence;
  readonly approval: LocalProofGatedApprovalEvidence;
  readonly userPresence: LocalProofGatedUserPresenceEvidence;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly executionBinding: EthereumSepoliaExecutionBinding;
  readonly allowlistedTargetAddress: string;
  readonly expectedFactoryAddress: string;
  readonly expectedOwnerAddress: string;
  readonly validatorKeyId: Hex;
  readonly expectedValidatorKeyId?: Hex;
  /** Final Runtime authorization digest created before the UserOperation is assembled. */
  readonly runtimeAuthorizationDigest: Hex;
  readonly nullifierStatus: "available" | "consumed" | "unknown";
  readonly signingPolicy: LocalProofGatedSigningPolicy;
  /**
   * O.21.2 obtains a separate approval and fresh presence after local proof
   * verification. Older callers retain the original pre-proof sequence.
   */
  readonly approvalSequence?: "pre_proof" | "post_verification";
  readonly nowSeconds?: number;
}

export interface LocalProofGatedSigningAuthorization {
  readonly status: "authorized";
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly signatureVersion: typeof LOCAL_PROOF_GATED_SIGNATURE_VERSION;
  readonly authorizationDigest: Hex;
  readonly accountSignatureDigest: Hex;
  readonly userOperationHash: Hex;
  readonly actionId: Hex;
  readonly validatorKeyId: Hex;
  readonly expiry: string;
  readonly ethereumStarkVerificationPerformed: false;
  readonly factEnforcedOnchain: false;
  readonly localProofVerified: true;
  readonly publicMutationAuthorized: false;
}

export interface LocalProofGatedValidationResult {
  readonly valid: boolean;
  readonly authorization?: LocalProofGatedSigningAuthorization;
  readonly errors: readonly string[];
}

export interface SignedLocalProofGatedUserOperation {
  readonly status: "signed";
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly accountSignatureDigest: Hex;
  readonly authorizationDigest: Hex;
  readonly validatorKeyId: Hex;
  readonly signedAt: string;
  readonly transactionSubmitted: false;
  readonly userOperationSubmitted: false;
  readonly factEnforcedOnchain: false;
  readonly starkVerifiedOnchain: false;
  readonly productionApproved: false;
}

export type LocalProofGatedSigningResult =
  | { readonly status: "signed"; readonly value: SignedLocalProofGatedUserOperation }
  | { readonly status: "rejected"; readonly errors: readonly string[] };

export type LocalProofGatedSepoliaPreflightStatus =
  | "READ_ONLY_RPC_NOT_CONFIGURED"
  | "READ_ONLY_PREFLIGHT_PASSED"
  | "READ_ONLY_PREFLIGHT_FAILED";

export type LocalProofGatedSepoliaUiStatus =
  | "architecture_not_approved"
  | "architecture_preparation_approved"
  | "ready_for_read_only_check"
  | "read_only_check_passed"
  | "ready_for_deployment_approval"
  | "deployment_pending"
  | "experimental_account_deployed"
  | "first_action_prepared"
  | "first_action_submitted"
  | "first_action_confirmed"
  | "failed";

export const LOCAL_PROOF_GATED_USER_SECURITY_NOTE =
  "PhilCore will verify the action on this Mac before signing. Ethereum will verify the PhilCore account and transaction, but will not independently verify the STARK proof." as const;

export interface LocalProofGatedSepoliaUiPreparation {
  readonly networkLabel: "Ethereum Sepolia";
  readonly accountLabel: "Experimental account";
  readonly status: "Preparing";
  readonly securityNote: typeof LOCAL_PROOF_GATED_USER_SECURITY_NOTE;
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly architectureApprovalStatus:
    "Conditionally Approved for Disposable Sepolia Preparation";
  readonly mutationControlsEnabled: false;
  readonly connected: false;
  readonly deployed: false;
}

export const LOCAL_PROOF_GATED_UI_PREPARATION: LocalProofGatedSepoliaUiPreparation =
  Object.freeze({
    networkLabel: "Ethereum Sepolia",
    accountLabel: "Experimental account",
    status: "Preparing",
    securityNote: LOCAL_PROOF_GATED_USER_SECURITY_NOTE,
    securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
    architectureApprovalStatus:
      "Conditionally Approved for Disposable Sepolia Preparation",
    mutationControlsEnabled: false,
    connected: false,
    deployed: false
  });

export interface LocalProofGatedActivityEvidence {
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly statement: "PhilCore verified the action locally before signing.";
  readonly starkVerificationLocation: "local";
  readonly factEnforcedOnchain: false;
  readonly actionId: Hex;
  readonly approvalPresentationDigest: Hex;
  readonly userPresenceEvidenceDigest: Hex;
  readonly proofInputHash: Hex;
  readonly proofArtifactDigest: Hex;
  readonly localVerificationAt: string;
  readonly authorizationDigest: Hex;
  readonly signedUserOperationHash?: Hex;
  readonly publicEvidence?: Readonly<{
    readonly userOperationHash: Hex;
    readonly transactionHash: Hex;
    readonly entryPointAddress: string;
    readonly smartAccountAddress: string;
    readonly targetAddress: string;
    readonly blockNumber: string;
    readonly receiptStatus: "confirmed" | "failed";
  }>;
}

export interface LocalProofGatedRuntimeApprovalEvidence {
  readonly status: "approved";
  readonly approvalArtifactId: string;
  readonly platformUserApprovalDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly presentationDigest: Hex;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly sessionId: string;
  readonly auditCorrelationId: string;
  readonly oneTime: true;
  readonly consumedForPreparation: true;
  readonly authorizesSigning: false;
  readonly authorizesSubmission: false;
}

export interface LocalProofGatedRuntimeAuthorizationDigestInput {
  readonly identityReference: Hex;
  readonly ownerCommitment: Hex;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly proofInputHash: Hex;
  readonly proofArtifactDigest: Hex;
  readonly nullifier: Hex;
  readonly approvalPresentationDigest: Hex;
  readonly targetAddress: string;
  readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
  readonly sessionId: string;
  readonly auditCorrelationId: string;
  readonly expiry: string;
}

export interface LocalProofGatedUnsignedPreparationArtifact {
  readonly schemaVersion: typeof LOCAL_PROOF_GATED_UNSIGNED_PREPARATION_SCHEMA;
  readonly artifactId: string;
  readonly status: "prepared_unsigned";
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
  readonly entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
  readonly smartAccountAddress: string;
  readonly factoryAddress: string;
  readonly targetAddress: string;
  readonly targetCalldata: Hex;
  readonly calldata: Hex;
  readonly authorizationDigest: Hex;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly expiry: string;
  readonly proofInputHash: Hex;
  readonly proofArtifactDigest: Hex;
  readonly publicNullifier: Hex;
  readonly proofVerificationResult: Readonly<{
    readonly status: "verified";
    readonly valid: true;
    readonly proofType: "stwo-unlock-keccak-v1";
    readonly proofInputHash: Hex;
    readonly proofArtifactDigest: Hex;
    readonly verifiedAt: string;
    readonly generatedAt: string;
    readonly freshProof: true;
    readonly proofReused: false;
  }>;
  readonly runtimeApprovalEvidence: LocalProofGatedRuntimeApprovalEvidence;
  readonly identityBinding: Readonly<{
    readonly identityId: string;
    readonly identityReference: Hex;
    readonly ownerCommitment: Hex;
    readonly validatorAddress: string;
    readonly validatorKeyReferenceId: string;
    readonly validatorKeyId: Hex;
    readonly unlockedAtPreparation: true;
  }>;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly preparedAt: string;
  readonly ethereumVerifiedProof: false;
  readonly starkVerificationLocation: "local";
  readonly publicMutationOccurred: false;
  readonly publicMutationAuthorized: false;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly userOperationSigned: false;
  readonly userOperationSubmitted: false;
  readonly ethMoved: false;
  readonly proofBytesIncluded: false;
  readonly witnessMaterialIncluded: false;
  readonly secretMaterialIncluded: false;
}

export interface LocalProofGatedSignedUserOperationArtifact {
  readonly schemaVersion: typeof LOCAL_PROOF_GATED_SIGNED_ARTIFACT_SCHEMA;
  readonly artifactId: string;
  readonly status: "signed_unsubmitted";
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly signingPurpose: typeof LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE;
  readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
  readonly entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
  readonly smartAccountAddress: string;
  readonly targetAddress: string;
  readonly unsignedUserOperation: PhilCorePackedUserOperation;
  readonly signedUserOperation: PhilCorePackedUserOperation;
  readonly signature: Hex;
  readonly userOperationHash: Hex;
  readonly accountSignatureDigest: Hex;
  readonly authorizationDigest: Hex;
  readonly validatorPublicAddress: string;
  readonly validatorKeyReferenceId: string;
  readonly validatorKeyId: Hex;
  readonly proofInputHash: Hex;
  readonly proofArtifactDigest: Hex;
  readonly signingApprovalPresentationDigest: Hex;
  readonly userPresenceEvidenceDigest: Hex;
  readonly signedAt: string;
  readonly expiresAt: string;
  readonly ethereumVerifiedProof: false;
  readonly starkVerificationLocation: "local";
  readonly localProofVerified: true;
  readonly publicMutationOccurred: false;
  readonly publicMutationAuthorized: false;
  readonly transactionSubmitted: false;
  readonly userOperationSubmitted: false;
  readonly ethMoved: false;
  readonly contractsDeployed: false;
  readonly proofBytesIncluded: false;
  readonly witnessMaterialIncluded: false;
  readonly secretMaterialIncluded: false;
}

export interface LocalProofGatedUnsignedPreparationRequest {
  readonly identityId: string;
  readonly identityReference: Hex;
  readonly ownerCommitment: Hex;
  readonly validatorAddress: string;
  readonly validatorKeyReferenceId: string;
  readonly validatorKeyId: Hex;
  readonly identityUnlocked: boolean;
  readonly expectedIdentityId: string;
  readonly expectedOwnerCommitment: Hex;
  readonly expectedValidatorAddress: string;
  readonly expectedValidatorKeyReferenceId: string;
  readonly expectedValidatorKeyId: Hex;
  readonly smartAccountAddress: string;
  readonly factoryAddress: string;
  readonly targetAddress: string;
  readonly expectedTargetAddress: string;
  readonly actionId: Hex;
  readonly canonicalActionDigest: Hex;
  readonly runtimeAuthorizationDigest: Hex;
  readonly expiry: string;
  readonly proof: LocalProofGatedProofEvidence;
  readonly verification: LocalProofGatedVerificationEvidence;
  readonly publicNullifier: Hex;
  readonly proofPreviouslyUsed: boolean;
  readonly nullifierPreviouslyUsed: boolean;
  readonly runtimeApprovalEvidence: LocalProofGatedRuntimeApprovalEvidence;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly preparedAt: string;
  readonly nowSeconds?: number;
}

export type LocalProofGatedUnsignedPreparationResult =
  | {
      readonly status: "prepared_unsigned";
      readonly value: LocalProofGatedUnsignedPreparationArtifact;
      readonly errors: readonly [];
    }
  | {
      readonly status: "rejected";
      readonly errors: readonly string[];
    };

export interface LocalProofGatedSepoliaReadOnlyClient {
  request(method: "eth_chainId" | "eth_getCode", params: readonly unknown[]): Promise<unknown>;
}

export interface LocalProofGatedSepoliaPreflightResult {
  readonly status: LocalProofGatedSepoliaPreflightStatus;
  readonly chainId?: number;
  readonly entryPointCodePresent: boolean;
  readonly proposedAddresses: Readonly<Record<string, "empty" | "code_present" | "not_checked">>;
  readonly rpcMutationMethodsCalled: false;
  readonly errors: readonly string[];
}

function freezeRecord<T>(value: T): T {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as T;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as T;
  }
  return value;
}

function equalHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function addArtifactErrors(
  label: string,
  artifact: { actionId: Hex; canonicalActionDigest: Hex },
  envelope: EthereumSepoliaUserOperationAuthorizationEnvelope,
  errors: string[]
): void {
  if (!equalHex(artifact.actionId, envelope.actionId)) errors.push(`${label}_action_id_mismatch`);
  if (!equalHex(artifact.canonicalActionDigest, envelope.canonicalActionDigest)) {
    errors.push(`${label}_canonical_action_digest_mismatch`);
  }
}

function parseUint(value: string, label: string, errors: string[]): bigint | undefined {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n) errors.push(`${label}_invalid`);
    return parsed;
  } catch {
    errors.push(`${label}_invalid`);
    return undefined;
  }
}

export function encodeLocalProofGatedExecutionCall(input: {
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
  readonly expiry: string;
}): Hex {
  return accountInterface.encodeFunctionData("executeLocalProofAuthorization", [
    input.actionId,
    input.authorizationDigest,
    BigInt(input.expiry)
  ]) as Hex;
}

export function encodeLocalProofGatedConfirmationTargetCall(input: {
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
}): Hex {
  return confirmationTargetInterface.encodeFunctionData("confirmPhilCoreAction", [
    input.actionId,
    input.authorizationDigest
  ]) as Hex;
}

export function computeLocalProofGatedRuntimeAuthorizationDigest(
  input: LocalProofGatedRuntimeAuthorizationDigestInput
): Hex {
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "address",
      "uint256",
      "string",
      "string",
      "uint64"
    ],
    [
      LOCAL_PROOF_GATED_RUNTIME_AUTHORIZATION_DOMAIN,
      input.identityReference,
      input.ownerCommitment,
      input.actionId,
      input.canonicalActionDigest,
      input.proofInputHash,
      input.proofArtifactDigest,
      input.nullifier,
      input.approvalPresentationDigest,
      getAddress(input.targetAddress),
      input.chainId,
      input.sessionId,
      input.auditCorrelationId,
      BigInt(input.expiry)
    ]
  )) as Hex;
}

function validateLocalProofGatedUnsignedPreparationArtifactUnchecked(
  artifact: LocalProofGatedUnsignedPreparationArtifact,
  expected: {
    readonly identityId: string;
    readonly identityReference: Hex;
    readonly ownerCommitment: Hex;
    readonly validatorAddress: string;
    readonly validatorKeyReferenceId: string;
    readonly validatorKeyId: Hex;
    readonly smartAccountAddress: string;
    readonly factoryAddress: string;
    readonly targetAddress: string;
    readonly nowSeconds?: number;
  }
): LocalProofGatedValidationResult {
  const errors: string[] = [];
  const nowSeconds = expected.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (artifact.schemaVersion !== LOCAL_PROOF_GATED_UNSIGNED_PREPARATION_SCHEMA) {
    errors.push("unsigned_preparation_schema_invalid");
  }
  if (artifact.status !== "prepared_unsigned") errors.push("unsigned_preparation_status_invalid");
  if (artifact.securityModel !== LOCAL_PROOF_GATED_SECURITY_MODEL) {
    errors.push("security_model_invalid");
  }
  if (artifact.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
  try {
    if (getAddress(artifact.entryPointAddress) !== getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)) {
      errors.push("entry_point_mismatch");
    }
    if (getAddress(artifact.smartAccountAddress) !== getAddress(expected.smartAccountAddress)) {
      errors.push("smart_account_mismatch");
    }
    if (getAddress(artifact.userOperation.sender) !== getAddress(expected.smartAccountAddress)) {
      errors.push("user_operation_sender_mismatch");
    }
    if (getAddress(artifact.factoryAddress) !== getAddress(expected.factoryAddress)) {
      errors.push("factory_address_mismatch");
    }
    if (getAddress(artifact.targetAddress) !== getAddress(expected.targetAddress)) {
      errors.push("target_address_mismatch");
    }
    if (getAddress(artifact.identityBinding.validatorAddress) !== getAddress(expected.validatorAddress)) {
      errors.push("validator_address_mismatch");
    }
  } catch {
    errors.push("address_invalid");
  }
  if (artifact.identityBinding.identityId !== expected.identityId) errors.push("identity_id_mismatch");
  if (!equalHex(artifact.identityBinding.identityReference, expected.identityReference)) {
    errors.push("identity_reference_mismatch");
  }
  if (!equalHex(artifact.identityBinding.ownerCommitment, expected.ownerCommitment)) {
    errors.push("owner_commitment_mismatch");
  }
  if (artifact.identityBinding.validatorKeyReferenceId !== expected.validatorKeyReferenceId) {
    errors.push("validator_key_reference_mismatch");
  }
  if (!equalHex(artifact.identityBinding.validatorKeyId, expected.validatorKeyId)) {
    errors.push("validator_key_id_mismatch");
  }
  if (!equalHex(artifact.actionId, artifact.canonicalActionDigest)) {
    errors.push("action_digest_mismatch");
  }
  if (!equalHex(artifact.proofInputHash, artifact.proofVerificationResult.proofInputHash)) {
    errors.push("proof_input_hash_mismatch");
  }
  if (!equalHex(
    artifact.proofArtifactDigest,
    artifact.proofVerificationResult.proofArtifactDigest
  )) {
    errors.push("proof_artifact_digest_mismatch");
  }
  if (
    artifact.proofVerificationResult.status !== "verified"
    || artifact.proofVerificationResult.valid !== true
  ) {
    errors.push("proof_not_verified");
  }
  if (!artifact.proofVerificationResult.freshProof) errors.push("proof_not_fresh");
  if (artifact.proofVerificationResult.proofReused) errors.push("proof_reused");
  const generatedAt = Date.parse(artifact.proofVerificationResult.generatedAt);
  const verifiedAt = Date.parse(artifact.proofVerificationResult.verifiedAt);
  const preparedAt = Date.parse(artifact.preparedAt);
  if (![generatedAt, verifiedAt, preparedAt].every(Number.isFinite)) {
    errors.push("artifact_time_invalid");
  } else {
    if (generatedAt > verifiedAt || verifiedAt > preparedAt) {
      errors.push("proof_sequence_invalid");
    }
    if (preparedAt - generatedAt > 10 * 60_000) errors.push("proof_stale");
  }
  try {
    if (BigInt(artifact.expiry) <= BigInt(nowSeconds)) errors.push("authorization_expired");
  } catch {
    errors.push("authorization_expiry_invalid");
  }
  if (artifact.runtimeApprovalEvidence.status !== "approved") errors.push("runtime_approval_missing");
  if (!artifact.runtimeApprovalEvidence.oneTime) errors.push("runtime_approval_not_one_time");
  if (!artifact.runtimeApprovalEvidence.consumedForPreparation) {
    errors.push("runtime_approval_not_consumed");
  }
  if (
    artifact.runtimeApprovalEvidence.authorizesSigning
    || artifact.runtimeApprovalEvidence.authorizesSubmission
  ) {
    errors.push("runtime_approval_scope_invalid");
  }
  const approvalApprovedAt = Date.parse(artifact.runtimeApprovalEvidence.approvedAt);
  const approvalExpiresAt = Date.parse(artifact.runtimeApprovalEvidence.expiresAt);
  if (![approvalApprovedAt, approvalExpiresAt].every(Number.isFinite)) {
    errors.push("runtime_approval_time_invalid");
  } else {
    if (approvalExpiresAt <= nowSeconds * 1000) errors.push("runtime_approval_expired");
    if (approvalApprovedAt >= approvalExpiresAt) errors.push("runtime_approval_sequence_invalid");
    if (Number.isFinite(preparedAt) && approvalApprovedAt > preparedAt) {
      errors.push("runtime_approval_after_preparation");
    }
  }
  try {
    const expectedAuthorizationDigest =
      computeLocalProofGatedRuntimeAuthorizationDigest({
        identityReference: artifact.identityBinding.identityReference,
        ownerCommitment: artifact.identityBinding.ownerCommitment,
        actionId: artifact.actionId,
        canonicalActionDigest: artifact.canonicalActionDigest,
        proofInputHash: artifact.proofInputHash,
        proofArtifactDigest: artifact.proofArtifactDigest,
        nullifier: artifact.publicNullifier,
        approvalPresentationDigest:
          artifact.runtimeApprovalEvidence.presentationDigest,
        targetAddress: artifact.targetAddress,
        chainId: artifact.chainId,
        sessionId: artifact.runtimeApprovalEvidence.sessionId,
        auditCorrelationId:
          artifact.runtimeApprovalEvidence.auditCorrelationId,
        expiry: artifact.expiry
      });
    if (!equalHex(artifact.authorizationDigest, expectedAuthorizationDigest)) {
      errors.push("runtime_authorization_digest_mismatch");
    }
  } catch {
    errors.push("runtime_authorization_digest_invalid");
  }
  const expectedTargetCalldata = encodeLocalProofGatedConfirmationTargetCall({
    actionId: artifact.actionId,
    authorizationDigest: artifact.authorizationDigest
  });
  if (!equalHex(artifact.targetCalldata, expectedTargetCalldata)) {
    errors.push("target_calldata_mismatch");
  }
  const expectedAccountCalldata = encodeLocalProofGatedExecutionCall({
    actionId: artifact.actionId,
    authorizationDigest: artifact.authorizationDigest,
    expiry: artifact.expiry
  });
  if (!equalHex(artifact.calldata, expectedAccountCalldata)) errors.push("calldata_mismatch");
  if (!equalHex(artifact.userOperation.callData, expectedAccountCalldata)) {
    errors.push("user_operation_calldata_mismatch");
  }
  if (!artifact.userOperation.initCode.toLowerCase().startsWith(
    getAddress(expected.factoryAddress).toLowerCase()
  )) {
    errors.push("factory_init_code_mismatch");
  }
  if (artifact.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES) {
    errors.push("signature_present");
  }
  if (artifact.userOperation.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) {
    errors.push("paymaster_not_allowed");
  }
  const computedHash = computePhilCore4337UserOperationHash({
    userOperation: artifact.userOperation,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID
  });
  if (!equalHex(computedHash, artifact.userOperationHash)) {
    errors.push("user_operation_hash_mismatch");
  }
  if (artifact.artifactId !== `unsigned_user_operation_${computedHash.slice(2)}`) {
    errors.push("artifact_id_mismatch");
  }
  const requiredFalse: readonly (keyof LocalProofGatedUnsignedPreparationArtifact)[] = [
    "ethereumVerifiedProof",
    "publicMutationOccurred",
    "publicMutationAuthorized",
    "transactionSigned",
    "transactionSubmitted",
    "userOperationSigned",
    "userOperationSubmitted",
    "ethMoved",
    "proofBytesIncluded",
    "witnessMaterialIncluded",
    "secretMaterialIncluded"
  ];
  for (const key of requiredFalse) {
    if (artifact[key] !== false) errors.push(`${String(key)}_must_be_false`);
  }
  if (artifact.starkVerificationLocation !== "local") {
    errors.push("stark_verification_location_invalid");
  }
  return freezeRecord({ valid: errors.length === 0, errors });
}

export function validateLocalProofGatedUnsignedPreparationArtifact(
  artifact: LocalProofGatedUnsignedPreparationArtifact,
  expected: {
    readonly identityId: string;
    readonly identityReference: Hex;
    readonly ownerCommitment: Hex;
    readonly validatorAddress: string;
    readonly validatorKeyReferenceId: string;
    readonly validatorKeyId: Hex;
    readonly smartAccountAddress: string;
    readonly factoryAddress: string;
    readonly targetAddress: string;
    readonly nowSeconds?: number;
  }
): LocalProofGatedValidationResult {
  try {
    return validateLocalProofGatedUnsignedPreparationArtifactUnchecked(
      artifact,
      expected
    );
  } catch {
    return freezeRecord({
      valid: false,
      errors: ["unsigned_preparation_malformed"]
    });
  }
}

export function createLocalProofGatedUnsignedPreparationArtifact(
  request: LocalProofGatedUnsignedPreparationRequest
): LocalProofGatedUnsignedPreparationResult {
  const errors: string[] = [];
  const nowSeconds = request.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (!request.identityUnlocked) errors.push("identity_locked");
  if (request.identityId !== request.expectedIdentityId) errors.push("incorrect_identity");
  if (!equalHex(request.ownerCommitment, request.expectedOwnerCommitment)) {
    errors.push("owner_commitment_mismatch");
  }
  try {
    if (getAddress(request.validatorAddress) !== getAddress(request.expectedValidatorAddress)) {
      errors.push("validator_address_mismatch");
    }
  } catch {
    errors.push("validator_address_invalid");
  }
  if (request.validatorKeyReferenceId !== request.expectedValidatorKeyReferenceId) {
    errors.push("validator_key_reference_mismatch");
  }
  if (!equalHex(request.validatorKeyId, request.expectedValidatorKeyId)) {
    errors.push("validator_key_id_mismatch");
  }
  if (request.proofPreviouslyUsed) errors.push("proof_reuse_rejected");
  if (request.nullifierPreviouslyUsed) errors.push("nullifier_reuse_rejected");
  if (!equalHex(request.actionId, request.canonicalActionDigest)) {
    errors.push("action_digest_mismatch");
  }
  if (!equalHex(request.proof.actionId, request.actionId)) {
    errors.push("proof_action_id_mismatch");
  }
  if (!equalHex(request.proof.canonicalActionDigest, request.canonicalActionDigest)) {
    errors.push("proof_canonical_action_digest_mismatch");
  }
  if (!equalHex(request.verification.actionId, request.actionId)) {
    errors.push("verification_action_id_mismatch");
  }
  if (!equalHex(
    request.verification.canonicalActionDigest,
    request.canonicalActionDigest
  )) {
    errors.push("verification_canonical_action_digest_mismatch");
  }
  if (request.proof.status !== "generated") errors.push("proof_not_generated");
  if (
    request.verification.status !== "verified"
    || request.verification.valid !== true
  ) {
    errors.push("proof_not_verified");
  }
  if (!equalHex(request.proof.proofArtifactDigest, request.verification.proofArtifactDigest)) {
    errors.push("proof_artifact_digest_mismatch");
  }
  if (!equalHex(request.proof.proofInputHash, request.verification.proofInputHash)) {
    errors.push("proof_input_hash_mismatch");
  }
  if (request.proof.proofType !== "stwo-unlock-keccak-v1") errors.push("proof_type_invalid");
  if (request.verification.proofType !== "stwo-unlock-keccak-v1") {
    errors.push("verification_proof_type_invalid");
  }
  try {
    if (getAddress(request.targetAddress) !== getAddress(request.expectedTargetAddress)) {
      errors.push("target_address_mismatch");
    }
  } catch {
    errors.push("target_address_invalid");
  }
  const computedHash = computePhilCore4337UserOperationHash({
    userOperation: request.userOperation,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID
  });
  if (!equalHex(computedHash, request.userOperationHash)) {
    errors.push("user_operation_hash_mismatch");
  }
  if (request.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES) {
    errors.push("signature_present");
  }
  if (errors.length > 0) return freezeRecord({ status: "rejected", errors });

  const artifact: LocalProofGatedUnsignedPreparationArtifact = {
    schemaVersion: LOCAL_PROOF_GATED_UNSIGNED_PREPARATION_SCHEMA,
    artifactId: `unsigned_user_operation_${computedHash.slice(2)}`,
    status: "prepared_unsigned",
    securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    smartAccountAddress: getAddress(request.smartAccountAddress),
    factoryAddress: getAddress(request.factoryAddress),
    targetAddress: getAddress(request.targetAddress),
    targetCalldata: encodeLocalProofGatedConfirmationTargetCall({
      actionId: request.actionId,
      authorizationDigest: request.runtimeAuthorizationDigest
    }),
    calldata: request.userOperation.callData,
    authorizationDigest: request.runtimeAuthorizationDigest,
    actionId: request.actionId,
    canonicalActionDigest: request.canonicalActionDigest,
    expiry: request.expiry,
    proofInputHash: request.proof.proofInputHash,
    proofArtifactDigest: request.proof.proofArtifactDigest,
    publicNullifier: request.publicNullifier,
    proofVerificationResult: {
      status: "verified",
      valid: true,
      proofType: "stwo-unlock-keccak-v1",
      proofInputHash: request.verification.proofInputHash,
      proofArtifactDigest: request.verification.proofArtifactDigest,
      verifiedAt: request.verification.verifiedAt,
      generatedAt: request.proof.generatedAt,
      freshProof: true,
      proofReused: false
    },
    runtimeApprovalEvidence: request.runtimeApprovalEvidence,
    identityBinding: {
      identityId: request.identityId,
      identityReference: request.identityReference,
      ownerCommitment: request.ownerCommitment,
      validatorAddress: getAddress(request.validatorAddress),
      validatorKeyReferenceId: request.validatorKeyReferenceId,
      validatorKeyId: request.validatorKeyId,
      unlockedAtPreparation: true
    },
    userOperation: request.userOperation,
    userOperationHash: computedHash,
    preparedAt: request.preparedAt,
    ethereumVerifiedProof: false,
    starkVerificationLocation: "local",
    publicMutationOccurred: false,
    publicMutationAuthorized: false,
    transactionSigned: false,
    transactionSubmitted: false,
    userOperationSigned: false,
    userOperationSubmitted: false,
    ethMoved: false,
    proofBytesIncluded: false,
    witnessMaterialIncluded: false,
    secretMaterialIncluded: false
  };
  const validation = validateLocalProofGatedUnsignedPreparationArtifact(artifact, {
    identityId: request.expectedIdentityId,
    identityReference: request.identityReference,
    ownerCommitment: request.expectedOwnerCommitment,
    validatorAddress: request.expectedValidatorAddress,
    validatorKeyReferenceId: request.expectedValidatorKeyReferenceId,
    validatorKeyId: request.expectedValidatorKeyId,
    smartAccountAddress: request.smartAccountAddress,
    factoryAddress: request.factoryAddress,
    targetAddress: request.expectedTargetAddress,
    nowSeconds
  });
  if (!validation.valid) {
    return freezeRecord({ status: "rejected", errors: validation.errors });
  }
  return freezeRecord({ status: "prepared_unsigned", value: artifact, errors: [] as const });
}

export function computeLocalProofGatedAccountSignatureDigest(input: {
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly smartAccountAddress: string;
  readonly userOperationHash: Hex;
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
  readonly expiry: string;
  readonly validatorKeyId: Hex;
}): Hex {
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "bytes32",
      "uint256",
      "address",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint64",
      "bytes32"
    ],
    [
      LOCAL_PROOF_GATED_SIGNATURE_DOMAIN,
      LOCAL_PROOF_GATED_SIGNATURE_VERSION,
      LOCAL_PROOF_GATED_SECURITY_MODEL_ID,
      input.chainId,
      getAddress(input.entryPointAddress),
      getAddress(input.smartAccountAddress),
      input.userOperationHash,
      input.actionId,
      input.authorizationDigest,
      BigInt(input.expiry),
      input.validatorKeyId
    ]
  )) as Hex;
}

export function createLocalProofGatedSigningRequestFromUnsignedArtifact(input: {
  readonly artifact: LocalProofGatedUnsignedPreparationArtifact;
  readonly signingApproval: LocalProofGatedApprovalEvidence;
  readonly userPresence: LocalProofGatedUserPresenceEvidence;
  readonly signingPolicy: LocalProofGatedSigningPolicy;
  readonly expectedFactoryAddress: string;
  readonly expectedOwnerAddress: string;
  readonly validatorKeyId: Hex;
  readonly nowSeconds?: number;
}): LocalProofGatedSigningAuthorizationRequest {
  const artifact = input.artifact;
  const gasLimits = unpackPhilCore4337Uints(artifact.userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(artifact.userOperation.gasFees);
  const totalGas =
    BigInt(gasLimits.high128)
    + BigInt(gasLimits.low128)
    + BigInt(artifact.userOperation.preVerificationGas);
  const envelope: EthereumSepoliaUserOperationAuthorizationEnvelope = freezeRecord({
    authorizationVersion: PHILCORE_SEPOLIA_AUTHORIZATION_VERSION,
    identityReference: artifact.identityBinding.identityReference,
    ownerCommitment: artifact.identityBinding.ownerCommitment,
    actionId: artifact.actionId,
    canonicalActionDigest: artifact.canonicalActionDigest,
    policyId: artifact.runtimeApprovalEvidence.authoritativePolicyDecisionId,
    policyCommitment: keccak256(toUtf8Bytes(
      artifact.runtimeApprovalEvidence.authoritativePolicyDecisionId
    )) as Hex,
    chainId: artifact.chainId,
    smartAccountAddress: artifact.smartAccountAddress,
    factoryAddress: artifact.factoryAddress,
    entryPointAddress: artifact.entryPointAddress,
    nonce: artifact.userOperation.nonce,
    targetContract: artifact.targetAddress,
    valueWei: "0",
    calldataHash: keccak256(artifact.targetCalldata) as Hex,
    userOperationCallDataHash: keccak256(artifact.userOperation.callData) as Hex,
    callType: "single",
    verificationGasLimit: gasLimits.high128,
    callGasLimit: gasLimits.low128,
    preVerificationGas: artifact.userOperation.preVerificationGas,
    maxFeePerGas: gasFees.low128,
    maxPriorityFeePerGas: gasFees.high128,
    totalFeeCeilingWei: (
      totalGas * BigInt(gasFees.low128)
    ).toString(),
    validAfter: String(Math.floor(Date.parse(artifact.preparedAt) / 1000)),
    expiresAt: artifact.expiry,
    nullifier: artifact.publicNullifier,
    proofInputHash: artifact.proofInputHash,
    proofType: "stwo-unlock-keccak-v1",
    runtimeAuthorizationVersion: "runtime-authorization-v1",
    accountDeploymentIncluded: artifact.userOperation.initCode !== PHILCORE_4337_EMPTY_BYTES,
    userOperationHash: artifact.userOperationHash,
    approvalPresentationDigest: input.signingApproval.presentationDigest,
    userPresenceEvidenceDigest: input.userPresence.evidenceDigest,
    auditCorrelationId: artifact.runtimeApprovalEvidence.auditCorrelationId
  });
  const artifactKinds: readonly EthereumSepoliaAuthorizationArtifactReference["artifactKind"][] = [
    "request",
    "policy",
    "approval",
    "user_presence",
    "stwo_proof",
    "runtime_authorization",
    "user_operation",
    "signing_request"
  ];
  const artifacts = artifactKinds.map((artifactKind) => freezeRecord({
    artifactKind,
    actionId: envelope.actionId,
    canonicalActionDigest: envelope.canonicalActionDigest,
    identityReference: envelope.identityReference,
    ownerCommitment: envelope.ownerCommitment,
    chainId: envelope.chainId,
    smartAccountAddress: envelope.smartAccountAddress,
    auditCorrelationId: envelope.auditCorrelationId,
    userOperationHash: envelope.userOperationHash,
    proofInputHash: envelope.proofInputHash,
    approvalPresentationDigest: envelope.approvalPresentationDigest,
    userPresenceEvidenceDigest: envelope.userPresenceEvidenceDigest
  }));
  return freezeRecord({
    envelope,
    artifacts,
    proof: {
      status: "generated",
      proofType: artifact.proofVerificationResult.proofType,
      proofArtifactDigest: artifact.proofArtifactDigest,
      proofInputHash: artifact.proofInputHash,
      actionId: artifact.actionId,
      canonicalActionDigest: artifact.canonicalActionDigest,
      generatedAt: artifact.proofVerificationResult.generatedAt
    },
    verification: {
      status: "verified",
      valid: true,
      proofType: artifact.proofVerificationResult.proofType,
      proofArtifactDigest: artifact.proofArtifactDigest,
      proofInputHash: artifact.proofInputHash,
      actionId: artifact.actionId,
      canonicalActionDigest: artifact.canonicalActionDigest,
      verifiedAt: artifact.proofVerificationResult.verifiedAt
    },
    approval: input.signingApproval,
    userPresence: input.userPresence,
    userOperation: artifact.userOperation,
    executionBinding: {
      targetContract: artifact.targetAddress,
      valueWei: "0",
      terminalCalldataHash: envelope.calldataHash,
      userOperationCallDataHash: envelope.userOperationCallDataHash
    },
    allowlistedTargetAddress: artifact.targetAddress,
    expectedFactoryAddress: input.expectedFactoryAddress,
    expectedOwnerAddress: input.expectedOwnerAddress,
    validatorKeyId: input.validatorKeyId,
    expectedValidatorKeyId: artifact.identityBinding.validatorKeyId,
    runtimeAuthorizationDigest: artifact.authorizationDigest,
    nullifierStatus: "available",
    signingPolicy: input.signingPolicy,
    approvalSequence: "post_verification",
    nowSeconds: input.nowSeconds
  });
}

export function encodeLocalProofGatedSignatureEnvelope(input: {
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
  readonly expiry: string;
  readonly validatorKeyId: Hex;
  readonly signature: Hex;
}): Hex {
  const signature = Signature.from(input.signature);
  return abiCoder.encode(
    ["uint8", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "uint8"],
    [
      LOCAL_PROOF_GATED_SIGNATURE_VERSION,
      LOCAL_PROOF_GATED_SECURITY_MODEL_ID,
      input.actionId,
      input.authorizationDigest,
      BigInt(input.expiry),
      input.validatorKeyId,
      signature.r,
      signature.s,
      signature.v
    ]
  ) as Hex;
}

export function validateLocalProofGatedSigningAuthorization(
  request: LocalProofGatedSigningAuthorizationRequest
): LocalProofGatedValidationResult {
  const errors: string[] = [];
  if (!request.proof) errors.push("proof_missing");
  if (!request.verification) errors.push("proof_verification_missing");
  if (!request.approval) errors.push("approval_missing");
  if (!request.userPresence) errors.push("user_presence_missing");
  if (errors.length > 0) return freezeRecord({ valid: false, errors });
  const nowSeconds = request.nowSeconds ?? Math.floor(Date.now() / 1000);
  const envelopeValidation = validateEthereumSepoliaAuthorizationEnvelope({
    envelope: request.envelope,
    userOperation: request.userOperation,
    executionBinding: request.executionBinding,
    allowlistedTargetAddress: request.allowlistedTargetAddress,
    nowSeconds
  });
  errors.push(...envelopeValidation.errors);
  errors.push(...validateEthereumSepoliaAuthorizationComposition({
    envelope: request.envelope,
    artifacts: request.artifacts
  }).errors);

  addArtifactErrors("proof", request.proof, request.envelope, errors);
  addArtifactErrors("verification", request.verification, request.envelope, errors);
  addArtifactErrors("approval", request.approval, request.envelope, errors);
  addArtifactErrors("user_presence", request.userPresence, request.envelope, errors);
  if (!equalHex(request.proof.proofArtifactDigest, request.verification.proofArtifactDigest)) {
    errors.push("proof_artifact_digest_mismatch");
  }
  if (!equalHex(request.proof.proofInputHash, request.envelope.proofInputHash)) {
    errors.push("proof_input_hash_mismatch");
  }
  if (!equalHex(request.verification.proofInputHash, request.envelope.proofInputHash)) {
    errors.push("verification_proof_input_hash_mismatch");
  }
  if (request.proof.proofType !== "stwo-unlock-keccak-v1") errors.push("proof_type_invalid");
  if (request.verification.proofType !== "stwo-unlock-keccak-v1") {
    errors.push("verification_proof_type_invalid");
  }
  if (request.verification.status !== "verified" || request.verification.valid !== true) {
    errors.push("proof_not_verified");
  }
  if (!equalHex(request.approval.presentationDigest, request.envelope.approvalPresentationDigest)) {
    errors.push("approval_presentation_digest_mismatch");
  }
  if (request.approval.consumed) errors.push("approval_already_consumed");
  if (Date.parse(request.approval.expiresAt) <= nowSeconds * 1000) errors.push("approval_expired");
  if (!equalHex(request.userPresence.evidenceDigest, request.envelope.userPresenceEvidenceDigest)) {
    errors.push("user_presence_digest_mismatch");
  }
  if (Date.parse(request.userPresence.expiresAt) <= nowSeconds * 1000) {
    errors.push("user_presence_expired");
  }
  const approvalTime = Date.parse(request.approval.approvedAt);
  const presenceTime = Date.parse(request.userPresence.verifiedAt);
  const proofTime = Date.parse(request.proof.generatedAt);
  const verificationTime = Date.parse(request.verification.verifiedAt);
  if (
    !Number.isFinite(approvalTime)
    || !Number.isFinite(presenceTime)
    || !Number.isFinite(proofTime)
    || !Number.isFinite(verificationTime)
  ) {
    errors.push("artifact_time_invalid");
  } else if (request.approvalSequence === "post_verification") {
    if (
      proofTime > verificationTime
      || verificationTime > approvalTime
      || approvalTime > presenceTime
    ) {
      errors.push("authorization_sequence_invalid");
    }
  } else if (
    approvalTime > proofTime
    || presenceTime > proofTime
    || proofTime > verificationTime
  ) {
    errors.push("authorization_sequence_invalid");
  }
  const validAfter = parseUint(request.envelope.validAfter, "valid_after", errors);
  if (validAfter !== undefined && validAfter > BigInt(nowSeconds)) {
    errors.push("authorization_not_yet_valid");
  }
  if (request.nullifierStatus !== "available") errors.push("nullifier_unavailable");
  if (request.envelope.factoryAddress === undefined) errors.push("factory_address_missing");
  else {
    try {
      if (getAddress(request.envelope.factoryAddress) !== getAddress(request.expectedFactoryAddress)) {
        errors.push("factory_address_mismatch");
      }
    } catch {
      errors.push("factory_address_invalid");
    }
  }
  if (!isHexString(request.validatorKeyId, 32) || request.validatorKeyId === `0x${"00".repeat(32)}`) {
    errors.push("validator_key_id_invalid");
  }
  if (
    request.expectedValidatorKeyId
    && !equalHex(request.validatorKeyId, request.expectedValidatorKeyId)
  ) {
    errors.push("validator_key_id_mismatch");
  }
  if (request.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES) {
    errors.push("user_operation_already_signed");
  }

  if (!isHexString(request.runtimeAuthorizationDigest, 32)) {
    errors.push("runtime_authorization_digest_invalid");
  }
  const authorizationDigest = request.runtimeAuthorizationDigest;
  const expectedCallData = encodeLocalProofGatedExecutionCall({
    actionId: request.envelope.actionId,
    authorizationDigest,
    expiry: request.envelope.expiresAt
  });
  if (!equalHex(expectedCallData, request.userOperation.callData)) errors.push("account_calldata_mismatch");

  const gasLimits = unpackPhilCore4337Uints(request.userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(request.userOperation.gasFees);
  const checks: readonly [string, bigint, string][] = [
    ["verification_gas_limit_exceeded", BigInt(gasLimits.high128), request.signingPolicy.maxVerificationGasLimit],
    ["call_gas_limit_exceeded", BigInt(gasLimits.low128), request.signingPolicy.maxCallGasLimit],
    ["pre_verification_gas_exceeded", BigInt(request.userOperation.preVerificationGas), request.signingPolicy.maxPreVerificationGas],
    ["max_fee_per_gas_exceeded", BigInt(gasFees.low128), request.signingPolicy.maxFeePerGas],
    ["max_priority_fee_per_gas_exceeded", BigInt(gasFees.high128), request.signingPolicy.maxPriorityFeePerGas]
  ];
  for (const [label, actual, maximum] of checks) {
    const parsed = parseUint(maximum, label, errors);
    if (parsed !== undefined && actual > parsed) errors.push(label);
  }
  const maxTotalFee = parseUint(request.signingPolicy.maxTotalFeeWei, "max_total_fee", errors);
  const envelopeTotal = parseUint(request.envelope.totalFeeCeilingWei, "envelope_total_fee", errors);
  if (maxTotalFee !== undefined && envelopeTotal !== undefined && envelopeTotal > maxTotalFee) {
    errors.push("total_fee_ceiling_exceeded");
  }

  const computedUserOperationHash = computePhilCore4337UserOperationHash({
    userOperation: request.userOperation,
    entryPointAddress: request.envelope.entryPointAddress,
    chainId: request.envelope.chainId
  });
  if (!equalHex(computedUserOperationHash, request.envelope.userOperationHash)) {
    errors.push("user_operation_hash_mismatch");
  }
  if (errors.length > 0) return freezeRecord({ valid: false, errors });

  const accountSignatureDigest = computeLocalProofGatedAccountSignatureDigest({
    chainId: request.envelope.chainId,
    entryPointAddress: request.envelope.entryPointAddress,
    smartAccountAddress: request.envelope.smartAccountAddress,
    userOperationHash: computedUserOperationHash,
    actionId: request.envelope.actionId,
    authorizationDigest,
    expiry: request.envelope.expiresAt,
    validatorKeyId: request.validatorKeyId
  });
  return freezeRecord({
    valid: true,
    authorization: {
      status: "authorized",
      securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
      signatureVersion: LOCAL_PROOF_GATED_SIGNATURE_VERSION,
      authorizationDigest,
      accountSignatureDigest,
      userOperationHash: computedUserOperationHash,
      actionId: request.envelope.actionId,
      validatorKeyId: request.validatorKeyId,
      expiry: request.envelope.expiresAt,
      ethereumStarkVerificationPerformed: false,
      factEnforcedOnchain: false,
      localProofVerified: true,
      publicMutationAuthorized: false
    },
    errors: []
  });
}

export async function signLocalProofGatedUserOperation(input: {
  readonly request: LocalProofGatedSigningAuthorizationRequest;
  readonly signer: PhilCore4337ValidatorSigner;
}): Promise<LocalProofGatedSigningResult> {
  const validation = validateLocalProofGatedSigningAuthorization(input.request);
  if (!validation.valid || !validation.authorization) {
    return freezeRecord({ status: "rejected", errors: validation.errors });
  }
  const descriptor = await input.signer.checkAvailability();
  if (!descriptor.available || getAddress(descriptor.ownerAddress) !== getAddress(input.request.expectedOwnerAddress)) {
    return freezeRecord({ status: "rejected", errors: ["device_vault_owner_binding_mismatch"] });
  }
  const authorization = validation.authorization;
  const signingResult: PhilCore4337SigningResult = await input.signer.signUserOperationHash({
    userOperationHash: authorization.userOperationHash,
    signingDigest: authorization.accountSignatureDigest,
    presentationDigest: input.request.approval.presentationDigest,
    expectedOwner: input.request.expectedOwnerAddress,
    chainId: input.request.envelope.chainId,
    entryPointAddress: input.request.envelope.entryPointAddress,
    smartAccountAddress: input.request.envelope.smartAccountAddress,
    nonce: input.request.envelope.nonce,
    callDataHash: input.request.envelope.userOperationCallDataHash,
    auditCorrelationId: input.request.envelope.auditCorrelationId
  });
  if (signingResult.status !== "signed" || !signingResult.signature) {
    return freezeRecord({
      status: "rejected",
      errors: signingResult.errors ?? ["device_vault_signer_rejected"]
    });
  }
  const recovered = verifyMessage(
    getBytes(authorization.accountSignatureDigest),
    signingResult.signature
  );
  const expectedOwner = input.request.expectedOwnerAddress;
  if (getAddress(recovered) !== getAddress(expectedOwner)) {
    return freezeRecord({ status: "rejected", errors: ["signature_owner_mismatch"] });
  }
  const signature = encodeLocalProofGatedSignatureEnvelope({
    actionId: authorization.actionId,
    authorizationDigest: authorization.authorizationDigest,
    expiry: authorization.expiry,
    validatorKeyId: authorization.validatorKeyId,
    signature: signingResult.signature
  });
  return freezeRecord({
    status: "signed",
    value: {
      status: "signed",
      securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
      userOperation: { ...input.request.userOperation, signature },
      userOperationHash: authorization.userOperationHash,
      accountSignatureDigest: authorization.accountSignatureDigest,
      authorizationDigest: authorization.authorizationDigest,
      validatorKeyId: authorization.validatorKeyId,
      signedAt: signingResult.signedAt,
      transactionSubmitted: false,
      userOperationSubmitted: false,
      factEnforcedOnchain: false,
      starkVerifiedOnchain: false,
      productionApproved: false
    }
  });
}

export function createLocalProofGatedSignedUserOperationArtifact(input: {
  readonly unsignedArtifact: LocalProofGatedUnsignedPreparationArtifact;
  readonly signedUserOperation: SignedLocalProofGatedUserOperation;
  readonly signingApprovalPresentationDigest: Hex;
  readonly userPresenceEvidenceDigest: Hex;
  readonly validatorPublicAddress: string;
}): LocalProofGatedSignedUserOperationArtifact {
  const unsigned = input.unsignedArtifact;
  const signed = input.signedUserOperation;
  const artifact = freezeRecord({
    schemaVersion: LOCAL_PROOF_GATED_SIGNED_ARTIFACT_SCHEMA,
    artifactId: `signed_user_operation_${signed.userOperationHash.slice(2)}`,
    status: "signed_unsubmitted" as const,
    securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
    signingPurpose: LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE,
    chainId: unsigned.chainId,
    entryPointAddress: unsigned.entryPointAddress,
    smartAccountAddress: unsigned.smartAccountAddress,
    targetAddress: unsigned.targetAddress,
    unsignedUserOperation: unsigned.userOperation,
    signedUserOperation: signed.userOperation,
    signature: signed.userOperation.signature,
    userOperationHash: signed.userOperationHash,
    accountSignatureDigest: signed.accountSignatureDigest,
    authorizationDigest: signed.authorizationDigest,
    validatorPublicAddress: getAddress(input.validatorPublicAddress),
    validatorKeyReferenceId: unsigned.identityBinding.validatorKeyReferenceId,
    validatorKeyId: signed.validatorKeyId,
    proofInputHash: unsigned.proofInputHash,
    proofArtifactDigest: unsigned.proofArtifactDigest,
    signingApprovalPresentationDigest: input.signingApprovalPresentationDigest,
    userPresenceEvidenceDigest: input.userPresenceEvidenceDigest,
    signedAt: signed.signedAt,
    expiresAt: new Date(Number(BigInt(unsigned.expiry)) * 1000).toISOString(),
    ethereumVerifiedProof: false as const,
    starkVerificationLocation: "local" as const,
    localProofVerified: true as const,
    publicMutationOccurred: false as const,
    publicMutationAuthorized: false as const,
    transactionSubmitted: false as const,
    userOperationSubmitted: false as const,
    ethMoved: false as const,
    contractsDeployed: false as const,
    proofBytesIncluded: false as const,
    witnessMaterialIncluded: false as const,
    secretMaterialIncluded: false as const
  });
  const validation = validateLocalProofGatedSignedUserOperationArtifact(artifact, {
    unsignedArtifact: unsigned,
    validatorPublicAddress: input.validatorPublicAddress
  });
  if (!validation.valid) {
    throw new Error(`signed artifact invalid: ${validation.errors.join(",")}`);
  }
  return artifact;
}

export function validateLocalProofGatedSignedUserOperationArtifact(
  artifact: LocalProofGatedSignedUserOperationArtifact,
  expected: {
    readonly unsignedArtifact: LocalProofGatedUnsignedPreparationArtifact;
    readonly validatorPublicAddress: string;
    readonly nowSeconds?: number;
  }
): LocalProofGatedValidationResult {
  try {
    const errors: string[] = [];
    const unsigned = expected.unsignedArtifact;
    if (artifact.schemaVersion !== LOCAL_PROOF_GATED_SIGNED_ARTIFACT_SCHEMA) {
      errors.push("signed_artifact_schema_invalid");
    }
    if (artifact.status !== "signed_unsubmitted") errors.push("signed_artifact_status_invalid");
    if (artifact.signingPurpose !== LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE) {
      errors.push("signing_purpose_invalid");
    }
    if (artifact.securityModel !== LOCAL_PROOF_GATED_SECURITY_MODEL) {
      errors.push("security_model_invalid");
    }
    if (artifact.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
    if (!equalHex(artifact.userOperationHash, unsigned.userOperationHash)) {
      errors.push("user_operation_hash_mismatch");
    }
    if (!equalHex(artifact.authorizationDigest, unsigned.authorizationDigest)) {
      errors.push("authorization_digest_mismatch");
    }
    const expectedAccountSignatureDigest =
      computeLocalProofGatedAccountSignatureDigest({
        chainId: artifact.chainId,
        entryPointAddress: artifact.entryPointAddress,
        smartAccountAddress: artifact.smartAccountAddress,
        userOperationHash: artifact.userOperationHash,
        actionId: unsigned.actionId,
        authorizationDigest: artifact.authorizationDigest,
        expiry: unsigned.expiry,
        validatorKeyId: artifact.validatorKeyId
      });
    if (!equalHex(
      artifact.accountSignatureDigest,
      expectedAccountSignatureDigest
    )) {
      errors.push("account_signature_digest_mismatch");
    }
    if (!equalHex(artifact.proofInputHash, unsigned.proofInputHash)) {
      errors.push("proof_input_hash_mismatch");
    }
    if (!equalHex(artifact.proofArtifactDigest, unsigned.proofArtifactDigest)) {
      errors.push("proof_artifact_digest_mismatch");
    }
    if (!equalHex(artifact.validatorKeyId, unsigned.identityBinding.validatorKeyId)) {
      errors.push("validator_key_id_mismatch");
    }
    if (artifact.validatorKeyReferenceId !== unsigned.identityBinding.validatorKeyReferenceId) {
      errors.push("validator_key_reference_mismatch");
    }
    if (getAddress(artifact.validatorPublicAddress) !== getAddress(expected.validatorPublicAddress)) {
      errors.push("validator_address_mismatch");
    }
    if (getAddress(artifact.smartAccountAddress) !== getAddress(unsigned.smartAccountAddress)) {
      errors.push("smart_account_mismatch");
    }
    if (getAddress(artifact.targetAddress) !== getAddress(unsigned.targetAddress)) {
      errors.push("target_address_mismatch");
    }
    if (getAddress(artifact.entryPointAddress) !== getAddress(unsigned.entryPointAddress)) {
      errors.push("entry_point_mismatch");
    }
    if (artifact.signature === PHILCORE_4337_EMPTY_BYTES) errors.push("signature_missing");
    if (!equalHex(artifact.signature, artifact.signedUserOperation.signature)) {
      errors.push("signature_mismatch");
    }
    if (artifact.unsignedUserOperation.signature !== PHILCORE_4337_EMPTY_BYTES) {
      errors.push("unsigned_operation_has_signature");
    }
    const unsignedKeys = Object.keys(unsigned.userOperation) as (keyof PhilCorePackedUserOperation)[];
    for (const key of unsignedKeys) {
      if (key === "signature") continue;
      if (String(artifact.unsignedUserOperation[key]) !== String(unsigned.userOperation[key])) {
        errors.push(`unsigned_${String(key)}_mismatch`);
      }
      if (String(artifact.signedUserOperation[key]) !== String(unsigned.userOperation[key])) {
        errors.push(`signed_${String(key)}_mismatch`);
      }
    }
    const computedHash = computePhilCore4337UserOperationHash({
      userOperation: artifact.signedUserOperation,
      entryPointAddress: artifact.entryPointAddress,
      chainId: artifact.chainId
    });
    if (!equalHex(computedHash, artifact.userOperationHash)) {
      errors.push("signed_user_operation_hash_mismatch");
    }
    if (artifact.artifactId !== `signed_user_operation_${computedHash.slice(2)}`) {
      errors.push("signed_artifact_id_mismatch");
    }
    const nowSeconds = expected.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (BigInt(unsigned.expiry) <= BigInt(nowSeconds)) errors.push("authorization_expired");
    const requiredFalse: readonly (keyof LocalProofGatedSignedUserOperationArtifact)[] = [
      "ethereumVerifiedProof",
      "publicMutationOccurred",
      "publicMutationAuthorized",
      "transactionSubmitted",
      "userOperationSubmitted",
      "ethMoved",
      "contractsDeployed",
      "proofBytesIncluded",
      "witnessMaterialIncluded",
      "secretMaterialIncluded"
    ];
    for (const key of requiredFalse) {
      if (artifact[key] !== false) errors.push(`${String(key)}_must_be_false`);
    }
    if (artifact.starkVerificationLocation !== "local") {
      errors.push("stark_verification_location_invalid");
    }
    if (artifact.localProofVerified !== true) errors.push("local_proof_not_verified");
    return freezeRecord({ valid: errors.length === 0, errors });
  } catch {
    return freezeRecord({ valid: false, errors: ["signed_artifact_malformed"] });
  }
}

export async function runLocalProofGatedSepoliaReadOnlyPreflight(input: {
  readonly client?: LocalProofGatedSepoliaReadOnlyClient;
  readonly proposedAddresses?: Readonly<Record<string, string | undefined>>;
}): Promise<LocalProofGatedSepoliaPreflightResult> {
  const proposedAddresses: Record<string, "empty" | "code_present" | "not_checked"> = {};
  for (const name of Object.keys(input.proposedAddresses ?? {})) proposedAddresses[name] = "not_checked";
  if (!input.client) {
    return freezeRecord({
      status: "READ_ONLY_RPC_NOT_CONFIGURED",
      entryPointCodePresent: false,
      proposedAddresses,
      rpcMutationMethodsCalled: false,
      errors: ["explicit approved Ethereum Sepolia read-only RPC is not configured"]
    });
  }
  const errors: string[] = [];
  let chainId: number | undefined;
  try {
    chainId = Number(BigInt(String(await input.client.request("eth_chainId", []))));
    if (chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
  } catch {
    errors.push("chain_id_read_failed");
  }
  let entryPointCodePresent = false;
  try {
    const code = String(await input.client.request("eth_getCode", [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      "latest"
    ]));
    entryPointCodePresent = code !== "0x" && code !== "0x0";
    if (!entryPointCodePresent) errors.push("entry_point_code_missing");
  } catch {
    errors.push("entry_point_code_read_failed");
  }
  for (const [name, address] of Object.entries(input.proposedAddresses ?? {})) {
    if (!address) continue;
    try {
      const code = String(await input.client.request("eth_getCode", [getAddress(address), "latest"]));
      proposedAddresses[name] = code === "0x" || code === "0x0" ? "empty" : "code_present";
    } catch {
      errors.push(`${name}_code_read_failed`);
    }
  }
  return freezeRecord({
    status: errors.length === 0 ? "READ_ONLY_PREFLIGHT_PASSED" : "READ_ONLY_PREFLIGHT_FAILED",
    chainId,
    entryPointCodePresent,
    proposedAddresses,
    rpcMutationMethodsCalled: false,
    errors
  });
}
