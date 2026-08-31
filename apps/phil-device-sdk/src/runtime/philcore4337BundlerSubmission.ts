import {
  getAddress,
  hexlify,
  isHexString,
  keccak256,
  toBeHex,
  zeroPadValue
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  PHILCORE_4337_ENTRYPOINT_VERSION,
  computePhilCore4337UserOperationHash,
  unpackPhilCore4337Uints,
  verifyPhilCore4337Account,
  type PhilCore4337AccountStateReader,
  type PhilCore4337FoundationConfiguration,
  type PhilCore4337NonceReader,
  type PhilCore4337PrefundReader,
  type PhilCore4337PrefundRequirement,
  type PhilCoreBundlerGasEstimator,
  type PhilCorePackedUserOperation,
  type PhilCoreUserOperationGasEstimateResult
} from "./philcore4337UserOperationPreparation.ts";
import {
  validatePhilCore4337SignatureArtifact,
  verifyPhilCore4337SignerBinding,
  type PhilCore4337SigningRuntimeAuthoritySnapshot,
  type SignedPhilCore4337UserOperation
} from "./philcore4337UserOperationSigning.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import type { RuntimeResult } from "./types.ts";

export type PhilCore4337BundlerProfile =
  | "local_fixture"
  | "local_entrypoint"
  | "ethereum_sepolia"
  | "base_sepolia"
  | "base_mainnet_disabled";

export type PhilCore4337BundlerCapability =
  | "eth_supportedEntryPoints"
  | "eth_chainId"
  | "eth_estimateUserOperationGas"
  | "eth_sendUserOperation"
  | "eth_getUserOperationByHash"
  | "eth_getUserOperationReceipt";

export interface PhilCore4337BundlerReference {
  readonly bundlerId: string;
  readonly profile: PhilCore4337BundlerProfile;
  readonly endpointReference: string;
  readonly liveNetwork: boolean;
  readonly productionApproved: boolean;
  readonly credentialsInRepository: false;
}

export interface PhilCore4337BundlerPolicy {
  readonly baseMainnetAllowed: false;
  readonly paymasterAllowed: false;
  readonly arbitraryUserOperationsAllowed: false;
  readonly requiresSubmissionApproval: true;
  readonly timeoutMs: number;
  readonly pollingIntervalMs: number;
  readonly maxOperationBytes?: number;
}

export interface PhilCore4337BundlerConfiguration {
  readonly status: "local_fixture" | "approved" | "unapproved" | "disabled";
  readonly profile: PhilCore4337BundlerProfile;
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly reference: PhilCore4337BundlerReference;
  readonly supportedMethods: readonly PhilCore4337BundlerCapability[];
  readonly userOperationSerialization: "packed_v0_7";
  readonly policy: PhilCore4337BundlerPolicy;
}

export type PhilCore4337BundlerCapabilityStatus =
  | "bundler_compatible"
  | "bundler_incompatible";

export type PhilCore4337BundlerCapabilityOutcome =
  | "bundler_compatible"
  | "bundler_unavailable"
  | "wrong_chain"
  | "entry_point_unsupported"
  | "v07_unsupported"
  | "required_method_missing"
  | "paymaster_required"
  | "configuration_unapproved"
  | "malformed"
  | "unsupported";

export interface PhilCore4337BundlerCapabilityRequest {
  readonly configuration: PhilCore4337BundlerConfiguration;
  readonly expectedChainId: number;
  readonly expectedEntryPointAddress: string;
  readonly requiredMethods?: readonly PhilCore4337BundlerCapability[];
}

export interface PhilCore4337BundlerCapabilityResult {
  readonly status: PhilCore4337BundlerCapabilityStatus;
  readonly outcome: PhilCore4337BundlerCapabilityOutcome;
  readonly bundler: PhilCore4337BundlerReference;
  readonly chainId?: number;
  readonly supportedEntryPoints?: readonly string[];
  readonly supportedMethods: readonly PhilCore4337BundlerCapability[];
  readonly checkedAt: string;
  readonly errors: readonly string[];
}

export interface PhilCore4337BundlerClient {
  verifyCapabilities(
    request: PhilCore4337BundlerCapabilityRequest
  ): Promise<PhilCore4337BundlerCapabilityResult>;
  sendUserOperation(
    request: PhilCore4337BundlerSubmissionRequest
  ): Promise<PhilCore4337BundlerSubmissionResult>;
  getUserOperationByHash?(
    request: PhilCore4337BundlerReceiptRequest
  ): Promise<PhilCore4337BundlerOperationLookupResult>;
  getUserOperationReceipt(
    request: PhilCore4337BundlerReceiptRequest
  ): Promise<PhilCore4337BundlerReceiptResult>;
}

export type PhilCore4337SubmissionAuthorizationStatus =
  | "submission_authorized"
  | "submission_not_authorized";

export type PhilCore4337SubmissionAuthorizationOutcome =
  | "submission_authorized"
  | "submission_not_authorized"
  | "runtime_authority_ineligible"
  | "signed_operation_ineligible"
  | "bundler_incompatible"
  | "account_binding_mismatch"
  | "entry_point_mismatch"
  | "nonce_changed"
  | "gas_changed"
  | "fee_changed"
  | "prefund_insufficient"
  | "mirrored_fact_missing"
  | "nullifier_unavailable"
  | "approval_required"
  | "approval_rejected"
  | "expired"
  | "malformed"
  | "unsupported";

export type PhilCore4337SubmissionApprovalSource =
  | "authenticated_platform_user"
  | "approved_runtime_policy"
  | "operator_testnet_approval"
  | "developer_fixture";

export interface PhilCore4337SubmissionAuthorizationBinding {
  readonly signedOperationId: string;
  readonly userOperationHash: Hex;
  readonly smartAccountAddress: string;
  readonly entryPointAddress: string;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly bundlerId: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly callDataHash: Hex;
  readonly accountGasLimits: Hex;
  readonly gasFees: Hex;
  readonly capabilityGrantId: string;
  readonly sessionId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly issueTime: string;
  readonly expiry: string;
  readonly auditCorrelationId: string;
}

export interface PhilCore4337SubmissionApprovalArtifact {
  readonly approvalArtifactId: string;
  readonly approvalId: string;
  readonly userOperationHash: Hex;
  readonly bundlerId: string;
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly source: PhilCore4337SubmissionApprovalSource;
  readonly oneTime: true;
  readonly publicNetworkAllowed: boolean;
  readonly consumed?: boolean;
}

export interface PhilCore4337SubmissionApprovalStore {
  consumeApproval(approval: PhilCore4337SubmissionApprovalArtifact): {
    readonly status: "approval_accepted" | "approval_rejected" | "approval_replayed" | "approval_expired";
    readonly approval?: PhilCore4337SubmissionApprovalArtifact;
    readonly errors: readonly string[];
  };
  hasConsumed(approvalId: string): boolean;
  clear(): void;
}

export interface PhilCore4337SubmissionAuthorizationRequest {
  readonly requestId: string;
  readonly signedOperation: SignedPhilCore4337UserOperation;
  readonly foundation: PhilCore4337FoundationConfiguration;
  readonly bundlerConfiguration: PhilCore4337BundlerConfiguration;
  readonly bundlerClient: PhilCore4337BundlerClient;
  readonly runtimeAuthority: PhilCore4337SigningRuntimeAuthoritySnapshot;
  readonly approval: PhilCore4337SubmissionApprovalArtifact;
  readonly nonceReader: PhilCore4337NonceReader;
  readonly gasEstimator?: PhilCoreBundlerGasEstimator;
  readonly prefundReader?: PhilCore4337PrefundReader;
  readonly accountStateReader?: PhilCore4337AccountStateReader;
  readonly approvalStore?: PhilCore4337SubmissionApprovalStore;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface PhilCore4337SubmissionAuthorizationValue {
  readonly status: "submission_authorized";
  readonly outcome: "submission_authorized";
  readonly binding: PhilCore4337SubmissionAuthorizationBinding;
  readonly approval: PhilCore4337SubmissionApprovalArtifact;
  readonly bundlerCapability: PhilCore4337BundlerCapabilityResult;
  readonly limitations: readonly PhilCore4337SubmissionLimitation[];
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type PhilCore4337SubmissionAuthorizationResult =
  RuntimeResult<PhilCore4337SubmissionAuthorizationValue>;

export interface PhilCore4337BundlerSubmissionRequest {
  readonly signedOperation: SignedPhilCore4337UserOperation;
  readonly serializedUserOperation: PhilCore4337BundlerSerializedUserOperation;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly bundler: PhilCore4337BundlerReference;
  readonly authorization: PhilCore4337SubmissionAuthorizationValue;
}

export type PhilCore4337BundlerSubmissionOutcome =
  | "user_operation_submitted"
  | "user_operation_rejected"
  | "user_operation_already_known"
  | "user_operation_hash_mismatch"
  | "nonce_invalid"
  | "signature_invalid"
  | "account_validation_failed"
  | "prefund_insufficient"
  | "execution_simulation_failed"
  | "bundler_unavailable"
  | "submission_timeout"
  | "approval_missing"
  | "expired"
  | "malformed"
  | "unsupported";

export interface PhilCore4337BundlerSubmissionResult {
  readonly status: "submitted" | "already_known" | "rejected" | "timeout" | "unavailable";
  readonly outcome: PhilCore4337BundlerSubmissionOutcome;
  readonly returnedUserOperationHash?: Hex;
  readonly submittedAt?: string;
  readonly error?: string;
}

export type PhilCore4337SubmissionStatus =
  | "user_operation_submitted"
  | "user_operation_submission_rejected";

export type PhilCore4337SubmissionOutcome = PhilCore4337BundlerSubmissionOutcome;

export type PhilCore4337SubmissionReason =
  | "exact_signed_operation_submitted"
  | "returned_hash_matched"
  | "paymaster_disabled"
  | "requires_receipt_monitoring"
  | "no_generic_bundler_access";

export type PhilCore4337SubmissionLimitation =
  | "acp_0002_proposed"
  | "local_fixture_only"
  | "public_ethereum_sepolia_submission_blocked_without_prerequisites"
  | "public_base_sepolia_submission_blocked_without_prerequisites"
  | "base_mainnet_disabled"
  | "paymaster_disabled"
  | "ambiguous_submission_requires_reconciliation"
  | "requires_receipt_monitoring";

export interface SubmittedPhilCore4337UserOperation {
  readonly submittedPhilCore4337UserOperationId: string;
  readonly status: "user_operation_submitted";
  readonly outcome: "user_operation_submitted" | "user_operation_already_known";
  readonly binding: PhilCore4337SubmissionAuthorizationBinding;
  readonly signedOperation: SignedPhilCore4337UserOperation;
  readonly serializedUserOperation: PhilCore4337BundlerSerializedUserOperation;
  readonly bundler: PhilCore4337BundlerReference;
  readonly returnedUserOperationHash: Hex;
  readonly localUserOperationHash: Hex;
  readonly returnedHashMatches: true;
  readonly submittedAt: string;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly reasons: readonly PhilCore4337SubmissionReason[];
  readonly limitations: readonly PhilCore4337SubmissionLimitation[];
  readonly userOperationSigned: true;
  readonly userOperationSubmitted: true;
  readonly bundlerSubmissionPerformed: true;
  readonly paymasterInvoked: false;
  readonly baseMainnetSubmission: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly receiptMonitored: false;
  readonly applicationCanSubmitDirectly: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: PhilCore4337SubmittedOperationCollectionResult;
}

export interface PhilCore4337BundlerSerializedUserOperation {
  readonly shape: "packed_v0_7";
  readonly userOperation: Readonly<Record<string, string>>;
  readonly entryPointAddress: string;
  readonly userOperationHash: Hex;
  readonly byteLengthEstimate: number;
  readonly paymasterDisabled: true;
}

export interface PhilCore4337BundlerReceiptRequest {
  readonly userOperationHash: Hex;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly bundler: PhilCore4337BundlerReference;
}

export interface PhilCore4337BundlerOperationLookupResult {
  readonly status: "found" | "not_found" | "unavailable";
  readonly userOperationHash: Hex;
  readonly transactionHash?: Hex;
  readonly blockNumber?: number;
  readonly checkedAt: string;
  readonly error?: string;
}

export interface PhilCore4337BundlerReceiptResult {
  readonly status: "pending" | "included" | "included_failed" | "rejected" | "dropped" | "unavailable";
  readonly userOperationHash: Hex;
  readonly entryPointAddress: string;
  readonly sender?: string;
  readonly nonce?: string;
  readonly success?: boolean;
  readonly actualGasCost?: string;
  readonly actualGasUsed?: string;
  readonly transactionHash?: Hex;
  readonly blockNumber?: number;
  readonly blockHash?: Hex;
  readonly logs?: readonly PhilCore4337ReceiptLog[];
  readonly paymaster?: string;
  readonly checkedAt: string;
  readonly error?: string;
}

export interface PhilCore4337ReceiptLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export type PhilCore4337UserOperationReceiptStatus =
  | "submitted"
  | "pending"
  | "included_successfully"
  | "included_inner_execution_failed"
  | "rejected_before_inclusion"
  | "dropped_or_expired"
  | "state_unknown";

export type PhilCore4337UserOperationReceiptOutcome =
  | "user_operation_included"
  | "inner_execution_failed"
  | "user_operation_pending"
  | "user_operation_rejected"
  | "user_operation_dropped"
  | "receipt_unavailable"
  | "monitoring_timeout"
  | "entrypoint_event_mismatch"
  | "account_deployment_unverified"
  | "inner_execution_unverified"
  | "nullifier_unverified"
  | "consumer_unverified"
  | "malformed"
  | "unsupported";

export interface PhilCore4337UserOperationInclusionEvidence {
  readonly userOperationHash: Hex;
  readonly entryPointAddress: string;
  readonly sender: string;
  readonly nonce: string;
  readonly transactionHash: Hex;
  readonly blockNumber?: number;
  readonly blockHash?: Hex;
  readonly success: boolean;
  readonly actualGasCost?: string;
  readonly actualGasUsed?: string;
  readonly paymasterEmpty: boolean;
  readonly checkedAt: string;
}

export interface PhilCore4337AccountDeploymentVerificationResult {
  readonly accountWasCounterfactual: boolean;
  readonly accountDeploymentObserved: boolean;
  readonly accountDeploymentVerified: boolean;
  readonly accountAddress: string;
  readonly checkedAt: string;
  readonly errors: readonly string[];
}

export interface PhilCore4337InnerExecutionEvidence {
  readonly status: "inner_execution_verified" | "inner_execution_failed" | "inner_execution_unknown";
  readonly actionGateAddress: string;
  readonly accountAddress: string;
  readonly transactionHash: Hex;
  readonly nullifier: Hex;
  readonly consumerAddress?: string;
  readonly approvedActionMatched: boolean;
  readonly checkedAt: string;
  readonly errors?: readonly string[];
}

export interface PhilCore4337InnerExecutionVerifier {
  verifyInnerExecution(
    request: PhilCore4337InnerExecutionVerificationRequest
  ): Promise<PhilCore4337InnerExecutionEvidence>;
}

export interface PhilCore4337InnerExecutionVerificationRequest {
  readonly submittedOperation: SubmittedPhilCore4337UserOperation;
  readonly receipt: PhilCore4337BundlerReceiptResult;
}

export interface PhilCore4337NullifierStateVerifier {
  verifyNullifierConsumed(
    request: PhilCore4337InnerExecutionVerificationRequest
  ): Promise<{
    readonly status: "nullifier_consumed" | "nullifier_available" | "nullifier_unknown";
    readonly nullifier: Hex;
    readonly checkedAt: string;
    readonly errors?: readonly string[];
  }>;
}

export interface PhilCore4337ConsumerExecutionVerifier {
  verifyConsumerExecuted(
    request: PhilCore4337InnerExecutionVerificationRequest
  ): Promise<{
    readonly status: "consumer_executed" | "consumer_not_executed" | "consumer_unknown";
    readonly approvedActionMatched: boolean;
    readonly checkedAt: string;
    readonly errors?: readonly string[];
  }>;
}

export interface PhilCore4337ExecutionReceipt {
  readonly philCore4337ExecutionReceiptId: string;
  readonly status: "included_successfully";
  readonly outcome: "user_operation_included";
  readonly submittedOperation: SubmittedPhilCore4337UserOperation;
  readonly inclusionEvidence: PhilCore4337UserOperationInclusionEvidence;
  readonly accountDeployment: PhilCore4337AccountDeploymentVerificationResult;
  readonly innerExecution: PhilCore4337InnerExecutionEvidence;
  readonly userOperationIncluded: true;
  readonly accountValidationSucceeded: true;
  readonly innerExecutionSucceeded: true;
  readonly nullifierConsumed: true;
  readonly consumerExecuted: true;
  readonly approvedActionMatched: true;
  readonly paymasterInvoked: false;
  readonly baseMainnetSubmission: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface PhilCore4337ReceiptMonitoringRequest {
  readonly requestId: string;
  readonly submittedOperation: SubmittedPhilCore4337UserOperation;
  readonly bundlerClient: PhilCore4337BundlerClient;
  readonly accountStateReader?: PhilCore4337AccountStateReader;
  readonly innerExecutionVerifier?: PhilCore4337InnerExecutionVerifier;
  readonly nullifierStateVerifier?: PhilCore4337NullifierStateVerifier;
  readonly consumerExecutionVerifier?: PhilCore4337ConsumerExecutionVerifier;
  readonly maxAttempts?: number;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly minConfirmations?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type PhilCore4337ReceiptMonitoringResult =
  RuntimeResult<PhilCore4337ExecutionReceipt>;

export type PhilCore4337SubmittedOperationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface PhilCore4337SubmittedOperationCollection {
  readonly submittedOperations: readonly SubmittedPhilCore4337UserOperation[];
  readonly count: number;
  readonly maxSubmittedOperationCount: number;
}

export interface PhilCore4337SubmittedOperationCollectionResult {
  readonly status: PhilCore4337SubmittedOperationCollectionStatus;
  readonly submittedOperation?: SubmittedPhilCore4337UserOperation;
  readonly removedSubmittedOperation?: SubmittedPhilCore4337UserOperation;
  readonly evictedSubmittedOperations?: readonly SubmittedPhilCore4337UserOperation[];
  readonly collection: PhilCore4337SubmittedOperationCollection;
  readonly reason?: string;
}

export interface PhilCore4337SubmittedOperationStore {
  addSubmittedOperation(submittedOperation: SubmittedPhilCore4337UserOperation): PhilCore4337SubmittedOperationCollectionResult;
  removeSubmittedOperation(id: string): PhilCore4337SubmittedOperationCollectionResult;
  clear(): PhilCore4337SubmittedOperationCollectionResult;
  count(): number;
  getById(id: string): SubmittedPhilCore4337UserOperation | undefined;
  getAll(): readonly SubmittedPhilCore4337UserOperation[];
}

export interface PhilCore4337UserOperationSubmissionRequest extends PhilCore4337SubmissionAuthorizationRequest {
  readonly submittedOperationStore?: PhilCore4337SubmittedOperationStore;
}

export type SubmittedPhilCore4337UserOperationResult =
  RuntimeResult<SubmittedPhilCore4337UserOperation>;

function nowIso(): string {
  return new Date().toISOString();
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, freezeRecord(nested)])
    )) as TValue;
  }
  return value;
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function normalizeHex(value: string, bytes?: number): Hex {
  if (!isHexString(value)) throw new Error("invalid hex");
  return (bytes === undefined ? hexlify(value) : zeroPadValue(value, bytes)).toLowerCase() as Hex;
}

function quantity(value: string | bigint | number): string {
  return toBeHex(BigInt(value));
}

function lowerAddressOrZero(value?: string): string {
  return value ? normalizeAddress(value) : "0x0000000000000000000000000000000000000000";
}

export function createPhilCore4337LocalFixtureBundlerConfiguration(input: {
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly bundlerId?: string;
}): PhilCore4337BundlerConfiguration {
  return freezeRecord({
    status: "local_fixture" as const,
    profile: "local_fixture" as const,
    chainId: input.chainId,
    entryPointAddress: normalizeAddress(input.entryPointAddress),
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    reference: {
      bundlerId: input.bundlerId ?? "local-fixture-bundler",
      profile: "local_fixture" as const,
      endpointReference: "local-hardhat-entrypoint-fixture",
      liveNetwork: false,
      productionApproved: false,
      credentialsInRepository: false as const
    },
    supportedMethods: Object.freeze([
      "eth_supportedEntryPoints",
      "eth_chainId",
      "eth_sendUserOperation",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ] satisfies PhilCore4337BundlerCapability[]),
    userOperationSerialization: "packed_v0_7" as const,
    policy: {
      baseMainnetAllowed: false as const,
      paymasterAllowed: false as const,
      arbitraryUserOperationsAllowed: false as const,
      requiresSubmissionApproval: true as const,
      timeoutMs: 30_000,
      pollingIntervalMs: 1000,
      maxOperationBytes: 131_072
    }
  });
}

export function createPhilCore4337SubmissionApprovalArtifact(input: Omit<
  PhilCore4337SubmissionApprovalArtifact,
  "approvalArtifactId"
>): PhilCore4337SubmissionApprovalArtifact {
  return freezeRecord({
    ...input,
    approvalArtifactId: createAuditCorrelationId([
      input.approvalId,
      input.userOperationHash,
      input.bundlerId,
      "philcore-4337-submission-approval"
    ])
  });
}

export function createInMemoryPhilCore4337SubmissionApprovalStore(): PhilCore4337SubmissionApprovalStore {
  const consumed = new Set<string>();
  return {
    consumeApproval(approval) {
      if (consumed.has(approval.approvalId) || approval.consumed) {
        return freezeRecord({ status: "approval_replayed" as const, errors: Object.freeze(["approval already consumed"]) });
      }
      if (new Date(approval.expiresAt).getTime() <= Date.now()) {
        return freezeRecord({ status: "approval_expired" as const, errors: Object.freeze(["approval expired"]) });
      }
      if (!approval.approved) {
        return freezeRecord({ status: "approval_rejected" as const, errors: Object.freeze(["approval rejected"]) });
      }
      consumed.add(approval.approvalId);
      return freezeRecord({ status: "approval_accepted" as const, approval, errors: Object.freeze([]) });
    },
    hasConsumed(approvalId) {
      return consumed.has(approvalId);
    },
    clear() {
      consumed.clear();
    }
  };
}

export function serializePhilCore4337UserOperationForBundler(
  signedOperation: SignedPhilCore4337UserOperation
): PhilCore4337BundlerSerializedUserOperation {
  const op = signedOperation.userOperation;
  const serialized = freezeRecord({
    sender: normalizeAddress(op.sender),
    nonce: quantity(op.nonce),
    initCode: normalizeHex(op.initCode),
    callData: normalizeHex(op.callData),
    accountGasLimits: normalizeHex(op.accountGasLimits, 32),
    preVerificationGas: quantity(op.preVerificationGas),
    gasFees: normalizeHex(op.gasFees, 32),
    paymasterAndData: normalizeHex(op.paymasterAndData),
    signature: normalizeHex(op.signature)
  });
  return freezeRecord({
    shape: "packed_v0_7" as const,
    userOperation: serialized,
    entryPointAddress: normalizeAddress(signedOperation.binding.entryPointAddress),
    userOperationHash: signedOperation.binding.userOperationHash,
    byteLengthEstimate: JSON.stringify(serialized).length,
    paymasterDisabled: true as const
  });
}

export function validateBundlerUserOperationSerialization(input: {
  readonly signedOperation: SignedPhilCore4337UserOperation;
  readonly serialized: PhilCore4337BundlerSerializedUserOperation;
}): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  const op = input.signedOperation.userOperation;
  const serialized = input.serialized.userOperation;
  if (input.serialized.shape !== "packed_v0_7") errors.push("serialization shape must be packed_v0_7");
  if (normalizeAddress(serialized.sender) !== normalizeAddress(op.sender)) errors.push("sender serialization mismatch");
  if (BigInt(serialized.nonce) !== BigInt(op.nonce)) errors.push("nonce serialization mismatch");
  if (serialized.initCode.toLowerCase() !== op.initCode.toLowerCase()) errors.push("initCode serialization mismatch");
  if (serialized.callData.toLowerCase() !== op.callData.toLowerCase()) errors.push("callData serialization mismatch");
  if (serialized.accountGasLimits.toLowerCase() !== op.accountGasLimits.toLowerCase()) errors.push("accountGasLimits serialization mismatch");
  if (BigInt(serialized.preVerificationGas) !== BigInt(op.preVerificationGas)) errors.push("preVerificationGas serialization mismatch");
  if (serialized.gasFees.toLowerCase() !== op.gasFees.toLowerCase()) errors.push("gasFees serialization mismatch");
  if (serialized.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymasterAndData must remain empty");
  if (serialized.signature.toLowerCase() !== op.signature.toLowerCase()) errors.push("signature serialization mismatch");
  return freezeRecord({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export async function requestPhilCore4337BundlerCapabilityCheck(input: {
  readonly configuration: PhilCore4337BundlerConfiguration;
  readonly bundlerClient: PhilCore4337BundlerClient;
}): Promise<RuntimeResult<PhilCore4337BundlerCapabilityResult>> {
  const result = await input.bundlerClient.verifyCapabilities({
    configuration: input.configuration,
    expectedChainId: input.configuration.chainId,
    expectedEntryPointAddress: input.configuration.entryPointAddress
  });
  if (result.outcome !== "bundler_compatible") {
    return runtimeDenied({
      code: `PHILCORE_4337_BUNDLER_${result.outcome.toUpperCase()}`,
      category: "adapter_unavailable",
      message: "PhilCore ERC-4337 bundler capability check failed.",
      recoverable: true,
      details: { outcome: result.outcome, errors: result.errors }
    });
  }
  return runtimeOk(result);
}

export async function requestPhilCore4337SubmissionAuthorization(
  request: PhilCore4337SubmissionAuthorizationRequest
): Promise<PhilCore4337SubmissionAuthorizationResult> {
  const errors = await validateSubmissionRequest(request);
  if (errors.length > 0) return submissionError(outcomeForErrors(errors), errors, request);

  const capability = await request.bundlerClient.verifyCapabilities({
    configuration: request.bundlerConfiguration,
    expectedChainId: request.signedOperation.binding.chainId,
    expectedEntryPointAddress: request.signedOperation.binding.entryPointAddress
  });
  if (capability.outcome !== "bundler_compatible") {
    return submissionError("bundler_incompatible", capability.errors, request);
  }

  const approvalResult = request.approvalStore
    ? request.approvalStore.consumeApproval(request.approval)
    : validateSubmissionApproval(request.approval);
  if (approvalResult.status !== "approval_accepted" || !approvalResult.approval) {
    return submissionError(
      approvalResult.status === "approval_replayed"
        ? "approval_rejected"
        : "approval_required",
      approvalResult.errors,
      request
    );
  }

  const binding = createSubmissionBinding(request);
  const value: PhilCore4337SubmissionAuthorizationValue = freezeRecord({
    status: "submission_authorized" as const,
    outcome: "submission_authorized" as const,
    binding,
    approval: approvalResult.approval,
    bundlerCapability: capability,
    limitations: submissionLimitations(request.bundlerConfiguration)
  });
  const auditEventDraft = createSubmissionAuditDraft({
    outcome: "submission_authorized",
    summary: "PhilCore ERC-4337 UserOperation submission authorization was created.",
    request,
    authorization: value
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({ ...value, auditEventDraft, auditDraftCollectionResult }), {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export async function submitPhilCore4337UserOperation(
  request: PhilCore4337UserOperationSubmissionRequest
): Promise<SubmittedPhilCore4337UserOperationResult> {
  const authorization = await requestPhilCore4337SubmissionAuthorization(request);
  if (authorization.status !== "approved" || !authorization.value) {
    return runtimeDenied(authorization.error ?? {
      code: "PHILCORE_4337_SUBMISSION_NOT_AUTHORIZED",
      category: "invalid_authorization_package",
      message: "PhilCore ERC-4337 submission authorization was rejected.",
      recoverable: true
    });
  }
  const serialized = serializePhilCore4337UserOperationForBundler(request.signedOperation);
  const serializedValidation = validateBundlerUserOperationSerialization({
    signedOperation: request.signedOperation,
    serialized
  });
  if (!serializedValidation.valid) return submissionError("malformed", serializedValidation.errors, request);

  const result = await request.bundlerClient.sendUserOperation({
    signedOperation: request.signedOperation,
    serializedUserOperation: serialized,
    entryPointAddress: request.signedOperation.binding.entryPointAddress,
    chainId: request.signedOperation.binding.chainId,
    bundler: request.bundlerConfiguration.reference,
    authorization: authorization.value
  });
  if (
    (result.status !== "submitted" && result.status !== "already_known")
    || !result.returnedUserOperationHash
  ) {
    return runtimeDenied({
      code: `PHILCORE_4337_SUBMISSION_${result.outcome.toUpperCase()}`,
      category: "adapter_unavailable",
      message: "PhilCore ERC-4337 UserOperation submission failed.",
      recoverable: true,
      details: { outcome: result.outcome, error: result.error }
    });
  }
  if (result.returnedUserOperationHash.toLowerCase() !== request.signedOperation.binding.userOperationHash.toLowerCase()) {
    return runtimeDenied({
      code: "PHILCORE_4337_SUBMISSION_USER_OPERATION_HASH_MISMATCH",
      category: "invalid_authorization_package",
      message: "Bundler returned a mismatched UserOperation hash.",
      recoverable: false,
      details: {
        returnedUserOperationHash: result.returnedUserOperationHash,
        localUserOperationHash: request.signedOperation.binding.userOperationHash
      }
    });
  }
  const submittedBase = {
    submittedPhilCore4337UserOperationId: createAuditCorrelationId([
      request.signedOperation.signedPhilCore4337UserOperationId,
      result.returnedUserOperationHash,
      request.bundlerConfiguration.reference.bundlerId,
      "submitted"
    ]),
    status: "user_operation_submitted" as const,
    outcome: result.status === "already_known"
      ? "user_operation_already_known" as const
      : "user_operation_submitted" as const,
    binding: authorization.value.binding,
    signedOperation: request.signedOperation,
    serializedUserOperation: serialized,
    bundler: request.bundlerConfiguration.reference,
    returnedUserOperationHash: result.returnedUserOperationHash,
    localUserOperationHash: request.signedOperation.binding.userOperationHash,
    returnedHashMatches: true as const,
    submittedAt: result.submittedAt ?? nowIso(),
    issueTime: request.issuedAt,
    expiresAt: request.expiresAt,
    reasons: Object.freeze([
      "exact_signed_operation_submitted",
      "returned_hash_matched",
      "paymaster_disabled",
      "requires_receipt_monitoring",
      "no_generic_bundler_access"
    ] satisfies PhilCore4337SubmissionReason[]),
    limitations: authorization.value.limitations,
    userOperationSigned: true as const,
    userOperationSubmitted: true as const,
    bundlerSubmissionPerformed: true as const,
    paymasterInvoked: false as const,
    baseMainnetSubmission: false as const,
    nullifierConsumed: false as const,
    consumerExecuted: false as const,
    receiptMonitored: false as const,
    applicationCanSubmitDirectly: false as const
  };
  const auditEventDraft = createSubmissionAuditDraft({
    outcome: submittedBase.outcome,
    summary: "PhilCore ERC-4337 UserOperation was submitted through a restricted bundler boundary.",
    request,
    submitted: submittedBase as SubmittedPhilCore4337UserOperation
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const submitted = freezeRecord({
    ...submittedBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as SubmittedPhilCore4337UserOperation;
  const collectionResult = request.submittedOperationStore?.addSubmittedOperation(submitted);
  return runtimeOk(collectionResult
    ? freezeRecord({ ...submitted, collectionResult }) as SubmittedPhilCore4337UserOperation
    : submitted, { auditEventId: auditEventDraft.eventDraftId });
}

export const requestPhilCore4337UserOperationSubmission = submitPhilCore4337UserOperation;

export async function requestPhilCore4337UserOperationReceiptMonitoring(
  request: PhilCore4337ReceiptMonitoringRequest
): Promise<PhilCore4337ReceiptMonitoringResult> {
  const maxAttempts = Math.max(1, request.maxAttempts ?? 1);
  const timeoutMs = Math.max(1, request.timeoutMs ?? 30_000);
  const startedAt = Date.now();
  let last: PhilCore4337BundlerReceiptResult | undefined;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (Date.now() - startedAt > timeoutMs) break;
    last = await request.bundlerClient.getUserOperationReceipt({
      userOperationHash: request.submittedOperation.localUserOperationHash,
      entryPointAddress: request.submittedOperation.binding.entryPointAddress,
      chainId: request.submittedOperation.binding.chainId,
      bundler: request.submittedOperation.bundler
    });
    if (last.status === "pending" || last.status === "unavailable") {
      if (attempt + 1 < maxAttempts && request.pollIntervalMs) {
        await new Promise((resolve) => setTimeout(resolve, request.pollIntervalMs));
      }
      continue;
    }
    if (last.status !== "included" || last.success !== true) {
      return runtimeDenied({
        code: `PHILCORE_4337_RECEIPT_${receiptOutcome(last).toUpperCase()}`,
        category: "adapter_unavailable",
        message: "PhilCore ERC-4337 UserOperation receipt was not successful.",
        recoverable: true,
        details: { outcome: receiptOutcome(last), receiptStatus: last.status, error: last.error }
      });
    }
    const evidenceValidation = validateInclusionEvidence(request.submittedOperation, last);
    if (evidenceValidation.errors.length > 0) {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_ENTRYPOINT_EVENT_MISMATCH",
        category: "invalid_authorization_package",
        message: "PhilCore ERC-4337 UserOperation receipt binding was invalid.",
        recoverable: true,
        details: { outcome: "entrypoint_event_mismatch", errors: evidenceValidation.errors }
      });
    }
    const accountDeployment = await verifyAccountDeploymentAfterReceipt(request, last);
    if (!accountDeployment.accountDeploymentVerified) {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_ACCOUNT_DEPLOYMENT_UNVERIFIED",
        category: "invalid_authorization_package",
        message: "PhilCore ERC-4337 account deployment could not be verified.",
        recoverable: true,
        details: { outcome: "account_deployment_unverified", errors: accountDeployment.errors }
      });
    }
    if (!request.innerExecutionVerifier || !request.nullifierStateVerifier || !request.consumerExecutionVerifier) {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_EXECUTION_VERIFIERS_REQUIRED",
        category: "proof_required",
        message: "PhilCore ERC-4337 receipt monitoring requires explicit inner execution, nullifier, and consumer verifiers.",
        recoverable: true,
        details: {
          outcome: "inner_execution_unverified",
          innerExecutionVerifier: Boolean(request.innerExecutionVerifier),
          nullifierStateVerifier: Boolean(request.nullifierStateVerifier),
          consumerExecutionVerifier: Boolean(request.consumerExecutionVerifier)
        }
      });
    }
    const inner = await request.innerExecutionVerifier.verifyInnerExecution({
      submittedOperation: request.submittedOperation,
      receipt: last
    });
    if (inner.status !== "inner_execution_verified" || !inner.approvedActionMatched) {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_INNER_EXECUTION_UNVERIFIED",
        category: "proof_failed",
        message: "PhilCore ERC-4337 inner execution could not be verified.",
        recoverable: true,
        details: { outcome: inner.status, errors: inner.errors }
      });
    }
    const nullifier = await request.nullifierStateVerifier.verifyNullifierConsumed({
      submittedOperation: request.submittedOperation,
      receipt: last
    });
    if (nullifier.status !== "nullifier_consumed") {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_NULLIFIER_UNVERIFIED",
        category: "proof_failed",
        message: "PhilCore ERC-4337 nullifier consumption could not be verified.",
        recoverable: true,
        details: { outcome: nullifier.status, errors: nullifier.errors }
      });
    }
    const consumer = await request.consumerExecutionVerifier.verifyConsumerExecuted({
      submittedOperation: request.submittedOperation,
      receipt: last
    });
    if (consumer.status !== "consumer_executed" || !consumer.approvedActionMatched) {
      return runtimeDenied({
        code: "PHILCORE_4337_RECEIPT_CONSUMER_UNVERIFIED",
        category: "proof_failed",
        message: "PhilCore ERC-4337 consumer execution could not be verified.",
        recoverable: true,
        details: { outcome: consumer.status, errors: consumer.errors }
      });
    }
    const inclusionEvidence = freezeRecord({
      userOperationHash: last.userOperationHash,
      entryPointAddress: last.entryPointAddress,
      sender: normalizeAddress(last.sender!),
      nonce: BigInt(last.nonce!).toString(),
      transactionHash: normalizeHex(last.transactionHash!, 32),
      blockNumber: last.blockNumber,
      blockHash: last.blockHash,
      success: true,
      actualGasCost: last.actualGasCost,
      actualGasUsed: last.actualGasUsed,
      paymasterEmpty: lowerAddressOrZero(last.paymaster) === "0x0000000000000000000000000000000000000000",
      checkedAt: last.checkedAt
    } satisfies PhilCore4337UserOperationInclusionEvidence);
    const auditEventDraft = createSubmissionAuditDraft({
      outcome: "user_operation_included",
      summary: "PhilCore ERC-4337 UserOperation receipt was included and bounded execution evidence was verified.",
      submitted: request.submittedOperation,
      receipt: last,
      auditCorrelationId: request.auditCorrelationId
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeOk(freezeRecord({
      philCore4337ExecutionReceiptId: createAuditCorrelationId([
        request.submittedOperation.localUserOperationHash,
        last.transactionHash!,
        "philcore-4337-execution-receipt"
      ]),
      status: "included_successfully" as const,
      outcome: "user_operation_included" as const,
      submittedOperation: request.submittedOperation,
      inclusionEvidence,
      accountDeployment,
      innerExecution: inner,
      userOperationIncluded: true as const,
      accountValidationSucceeded: true as const,
      innerExecutionSucceeded: true as const,
      nullifierConsumed: true as const,
      consumerExecuted: true as const,
      approvedActionMatched: true as const,
      paymasterInvoked: false as const,
      baseMainnetSubmission: false as const,
      auditEventDraft,
      auditDraftCollectionResult
    }), { auditEventId: auditEventDraft.eventDraftId });
  }
  return runtimeDenied({
    code: "PHILCORE_4337_RECEIPT_MONITORING_TIMEOUT",
    category: "network_unavailable",
    message: "PhilCore ERC-4337 UserOperation receipt monitoring timed out.",
    recoverable: true,
    details: { outcome: "monitoring_timeout", lastReceiptStatus: last?.status }
  });
}

export const requestPhilCore4337InnerExecutionVerification = requestPhilCore4337UserOperationReceiptMonitoring;

export function inspectSubmittedPhilCore4337UserOperation(
  submitted: SubmittedPhilCore4337UserOperation
): Readonly<Record<string, unknown>> {
  return freezeRecord({
    submittedPhilCore4337UserOperationId: submitted.submittedPhilCore4337UserOperationId,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    sender: submitted.signedOperation.userOperation.sender,
    nonce: submitted.signedOperation.userOperation.nonce,
    userOperationHash: submitted.localUserOperationHash,
    bundlerId: submitted.bundler.bundlerId,
    userOperationSigned: submitted.userOperationSigned,
    userOperationSubmitted: submitted.userOperationSubmitted,
    bundlerSubmissionPerformed: submitted.bundlerSubmissionPerformed,
    paymasterInvoked: submitted.paymasterInvoked,
    receiptMonitored: submitted.receiptMonitored,
    nullifierConsumed: submitted.nullifierConsumed,
    consumerExecuted: submitted.consumerExecuted,
    applicationCanSubmitDirectly: submitted.applicationCanSubmitDirectly
  });
}

async function validateSubmissionRequest(
  request: PhilCore4337SubmissionAuthorizationRequest
): Promise<readonly string[]> {
  const errors: string[] = [];
  const signed = request.signedOperation;
  if (new Date(request.expiresAt).getTime() <= Date.now()) errors.push("submission request expired");
  if (new Date(signed.expiresAt).getTime() <= Date.now()) errors.push("signed operation expired");
  if (request.foundation.acpStatus !== "Proposed") errors.push("ACP-0002 must remain proposed");
  if (request.foundation.network.chainId !== signed.binding.chainId) errors.push("wrong chain");
  if (request.bundlerConfiguration.profile === "base_mainnet_disabled") errors.push("Base mainnet disabled");
  if (request.bundlerConfiguration.chainId !== signed.binding.chainId) errors.push("bundler chain mismatch");
  if (request.bundlerConfiguration.entryPointVersion !== PHILCORE_4337_ENTRYPOINT_VERSION) errors.push("EntryPoint v0.7 required");
  if (normalizeAddress(request.bundlerConfiguration.entryPointAddress) !== normalizeAddress(signed.binding.entryPointAddress)) errors.push("EntryPoint mismatch");
  if (normalizeAddress(request.foundation.entryPoint.address) !== normalizeAddress(signed.binding.entryPointAddress)) errors.push("EntryPoint mismatch");
  if (signed.userOperation.signature === PHILCORE_4337_EMPTY_BYTES) errors.push("signed operation missing signature");
  if (signed.userOperation.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymaster data not allowed");
  if (signed.userOperationSubmitted || signed.bundlerSubmissionPerformed) errors.push("signed operation already submitted");
  validateAuthority(request.runtimeAuthority, errors);

  const computedHash = computePhilCore4337UserOperationHash({
    userOperation: signed.userOperation,
    entryPointAddress: signed.binding.entryPointAddress,
    chainId: signed.binding.chainId
  });
  if (computedHash.toLowerCase() !== signed.binding.userOperationHash.toLowerCase()) errors.push("UserOperation hash mismatch");
  const signatureArtifact = verifyPhilCore4337SignerBinding({
    signature: signed.userOperation.signature,
    userOperationHash: signed.binding.userOperationHash,
    expectedOwner: signed.binding.owner
  });
  const signatureValidation = validatePhilCore4337SignatureArtifact(signatureArtifact);
  if (!signatureValidation.valid) errors.push(...signatureValidation.errors);

  const nonce = await request.nonceReader.readNonce({
    entryPointAddress: signed.binding.entryPointAddress,
    accountAddress: signed.binding.smartAccountAddress,
    nonceKey: "0",
    chainId: signed.binding.chainId
  });
  if (nonce.status !== "resolved" || nonce.nonce !== signed.userOperation.nonce) errors.push("nonce changed");
  if (request.gasEstimator) {
    const gas = await request.gasEstimator.estimateUserOperationGas({
      userOperation: signed.userOperation,
      entryPointAddress: signed.binding.entryPointAddress,
      chainId: signed.binding.chainId
    });
    compareGasToSignedOperation(gas, signed.userOperation, errors);
  }
  if (request.prefundReader) {
    const prefund = await request.prefundReader.readPrefundRequirement({
      userOperation: signed.userOperation,
      entryPointAddress: signed.binding.entryPointAddress,
      chainId: signed.binding.chainId
    });
    comparePrefund(prefund, errors);
  }
  if (request.accountStateReader) {
    const verification = await verifyPhilCore4337Account({
      request: {
        accountAddress: signed.binding.smartAccountAddress,
        expectedEntryPoint: signed.binding.entryPointAddress,
        expectedOwner: signed.binding.owner,
        expectedOwnerCommitment: signed.binding.ownerCommitment,
        expectedApprovedActionGate: signed.binding.actionGateAddress,
        expectedChainId: signed.binding.chainId,
        configurationApproved: request.foundation.status === "local_fixture" || request.foundation.status === "approved"
      },
      reader: request.accountStateReader
    });
    if (verification.outcome !== "account_verified") errors.push(...verification.errors);
  }
  if (request.approval.userOperationHash.toLowerCase() !== signed.binding.userOperationHash.toLowerCase()) errors.push("submission approval hash mismatch");
  if (request.approval.bundlerId !== request.bundlerConfiguration.reference.bundlerId) errors.push("submission approval bundler mismatch");
  if (request.approval.chainId !== signed.binding.chainId) errors.push("submission approval chain mismatch");
  if (normalizeAddress(request.approval.entryPointAddress) !== normalizeAddress(signed.binding.entryPointAddress)) errors.push("submission approval EntryPoint mismatch");
  if (request.bundlerConfiguration.reference.liveNetwork && !request.approval.publicNetworkAllowed) errors.push("public network submission approval missing");
  return Object.freeze(errors);
}

function validateAuthority(
  authority: PhilCore4337SigningRuntimeAuthoritySnapshot,
  errors: string[]
): void {
  if (authority.capabilityGrantStatus !== "active") errors.push("capability ineligible");
  if (authority.sessionStatus !== "eligible") errors.push("session ineligible");
  if (authority.platformApprovalStatus !== "valid") errors.push("platform approval ineligible");
  if (authority.baseExecutionApprovalStatus !== "valid") errors.push("base execution approval ineligible");
  if (authority.finalizedPackageStatus !== "valid") errors.push("package ineligible");
  if (authority.mirroredFactStatus !== "present") errors.push("mirrored fact missing");
  if (authority.nullifierStatus !== "available") errors.push("nullifier unavailable");
}

function compareGasToSignedOperation(
  gas: PhilCoreUserOperationGasEstimateResult,
  op: PhilCorePackedUserOperation,
  errors: string[]
): void {
  if (gas.status === "failed") errors.push("gas estimation failed");
  const gasLimits = unpackPhilCore4337Uints(op.accountGasLimits);
  const fees = unpackPhilCore4337Uints(op.gasFees);
  if (gas.callGasLimit && gas.callGasLimit !== gasLimits.low128) errors.push("gas changed");
  if (gas.verificationGasLimit && gas.verificationGasLimit !== gasLimits.high128) errors.push("gas changed");
  if (gas.preVerificationGas && gas.preVerificationGas !== op.preVerificationGas) errors.push("gas changed");
  if (gas.maxFeePerGas && gas.maxFeePerGas !== fees.low128) errors.push("fee changed");
  if (gas.maxPriorityFeePerGas && gas.maxPriorityFeePerGas !== fees.high128) errors.push("fee changed");
}

function comparePrefund(
  prefund: PhilCore4337PrefundRequirement,
  errors: string[]
): void {
  if (prefund.status === "prefund_insufficient") errors.push("prefund insufficient");
}

function validateSubmissionApproval(approval: PhilCore4337SubmissionApprovalArtifact): ReturnType<PhilCore4337SubmissionApprovalStore["consumeApproval"]> {
  if (new Date(approval.expiresAt).getTime() <= Date.now()) {
    return freezeRecord({ status: "approval_expired" as const, errors: Object.freeze(["approval expired"]) });
  }
  if (!approval.approved || approval.consumed) {
    return freezeRecord({ status: approval.consumed ? "approval_replayed" as const : "approval_rejected" as const, errors: Object.freeze(["approval rejected"]) });
  }
  return freezeRecord({ status: "approval_accepted" as const, approval, errors: Object.freeze([]) });
}

function createSubmissionBinding(request: PhilCore4337SubmissionAuthorizationRequest): PhilCore4337SubmissionAuthorizationBinding {
  const signed = request.signedOperation;
  return freezeRecord({
    signedOperationId: signed.signedPhilCore4337UserOperationId,
    userOperationHash: signed.binding.userOperationHash,
    smartAccountAddress: signed.binding.smartAccountAddress,
    entryPointAddress: signed.binding.entryPointAddress,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    bundlerId: request.bundlerConfiguration.reference.bundlerId,
    chainId: signed.binding.chainId,
    nonce: signed.userOperation.nonce,
    callDataHash: keccak256(signed.userOperation.callData) as Hex,
    accountGasLimits: signed.userOperation.accountGasLimits,
    gasFees: signed.userOperation.gasFees,
    capabilityGrantId: signed.binding.capabilityGrantId,
    sessionId: signed.binding.sessionId,
    finalizedAuthorizationPackageId: signed.binding.finalizedAuthorizationPackageId,
    issueTime: request.issuedAt,
    expiry: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId
  });
}

function submissionLimitations(
  configuration: PhilCore4337BundlerConfiguration
): readonly PhilCore4337SubmissionLimitation[] {
  const limitations: PhilCore4337SubmissionLimitation[] = [
    "acp_0002_proposed",
    "base_mainnet_disabled",
    "paymaster_disabled",
    "ambiguous_submission_requires_reconciliation",
    "requires_receipt_monitoring"
  ];
  if (configuration.profile === "local_fixture" || configuration.profile === "local_entrypoint") {
    limitations.push("local_fixture_only");
  } else if (configuration.profile === "ethereum_sepolia") {
    limitations.push("public_ethereum_sepolia_submission_blocked_without_prerequisites");
  } else {
    limitations.push("public_base_sepolia_submission_blocked_without_prerequisites");
  }
  return Object.freeze(limitations);
}

function submissionError(
  outcome: PhilCore4337SubmissionAuthorizationOutcome,
  errors: readonly string[],
  request: PhilCore4337SubmissionAuthorizationRequest
): RuntimeResult<never> {
  const auditEventDraft = createSubmissionAuditDraft({
    outcome,
    summary: "PhilCore ERC-4337 UserOperation submission was rejected.",
    request,
    errors
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: `PHILCORE_4337_SUBMISSION_${outcome.toUpperCase()}`,
    category: outcome.includes("approval")
      ? "user_cancelled"
      : outcome.includes("bundler")
        ? "adapter_unavailable"
        : "invalid_authorization_package",
    message: "PhilCore ERC-4337 UserOperation submission was rejected.",
    recoverable: true,
    details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
  }, { auditEventId: auditEventDraft.eventDraftId });
}

function createSubmissionAuditDraft(input: {
  readonly outcome: string;
  readonly summary: string;
  readonly request?: PhilCore4337SubmissionAuthorizationRequest;
  readonly authorization?: PhilCore4337SubmissionAuthorizationValue;
  readonly submitted?: SubmittedPhilCore4337UserOperation;
  readonly receipt?: PhilCore4337BundlerReceiptResult;
  readonly errors?: readonly string[];
  readonly auditCorrelationId?: string;
}): AuditEventDraft {
  const signed = input.request?.signedOperation ?? input.submitted?.signedOperation;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "submission_authorized"
      || input.outcome === "user_operation_submitted"
      || input.outcome === "user_operation_already_known"
      || input.outcome === "user_operation_included"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestPhilCore4337UserOperationSubmission",
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId
      ?? input.request?.auditCorrelationId
      ?? input.authorization?.binding.auditCorrelationId
      ?? input.submitted?.binding.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      bundler: input.request?.bundlerConfiguration.reference.bundlerId ?? input.submitted?.bundler.bundlerId,
      entryPoint: signed?.binding.entryPointAddress,
      account: signed?.binding.smartAccountAddress,
      userOperationHash: signed?.binding.userOperationHash,
      nonce: signed?.userOperation.nonce,
      callDataHash: signed ? keccak256(signed.userOperation.callData) : undefined,
      signature: signed ? "present_redacted" : "not_present",
      paymaster: "disabled",
      transactionHash: input.receipt?.transactionHash,
      blockNumber: input.receipt?.blockNumber,
      submitted: input.submitted?.userOperationSubmitted ?? false,
      receiptMonitored: Boolean(input.receipt),
      nullifierConsumed: input.outcome === "user_operation_included",
      consumerExecuted: input.outcome === "user_operation_included",
      applicationCanSubmitDirectly: false
    }
  });
}

function outcomeForErrors(errors: readonly string[]): PhilCore4337SubmissionAuthorizationOutcome {
  const joined = errors.join(" ").toLowerCase();
  if (joined.includes("signed operation") || joined.includes("signature") || joined.includes("hash")) return "signed_operation_ineligible";
  if (joined.includes("bundler")) return "bundler_incompatible";
  if (joined.includes("entrypoint")) return "entry_point_mismatch";
  if (joined.includes("nonce")) return "nonce_changed";
  if (joined.includes("gas")) return "gas_changed";
  if (joined.includes("fee")) return "fee_changed";
  if (joined.includes("prefund")) return "prefund_insufficient";
  if (joined.includes("mirrored fact")) return "mirrored_fact_missing";
  if (joined.includes("nullifier")) return "nullifier_unavailable";
  if (joined.includes("approval")) return "approval_required";
  if (joined.includes("expired")) return "expired";
  if (joined.includes("chain") || joined.includes("mainnet")) return "unsupported";
  return "runtime_authority_ineligible";
}

function receiptOutcome(receipt: PhilCore4337BundlerReceiptResult): PhilCore4337UserOperationReceiptOutcome {
  if (receipt.status === "included_failed") return "inner_execution_failed";
  if (receipt.status === "pending") return "user_operation_pending";
  if (receipt.status === "rejected") return "user_operation_rejected";
  if (receipt.status === "dropped") return "user_operation_dropped";
  if (receipt.status === "unavailable") return "receipt_unavailable";
  return "entrypoint_event_mismatch";
}

function validateInclusionEvidence(
  submitted: SubmittedPhilCore4337UserOperation,
  receipt: PhilCore4337BundlerReceiptResult
): { readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (receipt.userOperationHash.toLowerCase() !== submitted.localUserOperationHash.toLowerCase()) errors.push("UserOperation hash mismatch");
  if (normalizeAddress(receipt.entryPointAddress) !== normalizeAddress(submitted.binding.entryPointAddress)) errors.push("EntryPoint mismatch");
  if (receipt.sender && normalizeAddress(receipt.sender) !== normalizeAddress(submitted.binding.smartAccountAddress)) errors.push("sender mismatch");
  if (receipt.nonce !== undefined && BigInt(receipt.nonce) !== BigInt(submitted.binding.nonce)) errors.push("nonce mismatch");
  if (!receipt.transactionHash) errors.push("transaction hash missing");
  if (lowerAddressOrZero(receipt.paymaster) !== "0x0000000000000000000000000000000000000000") errors.push("paymaster must be empty");
  return freezeRecord({ errors: Object.freeze(errors) });
}

async function verifyAccountDeploymentAfterReceipt(
  request: PhilCore4337ReceiptMonitoringRequest,
  receipt: PhilCore4337BundlerReceiptResult
): Promise<PhilCore4337AccountDeploymentVerificationResult> {
  const signed = request.submittedOperation.signedOperation;
  const accountWasCounterfactual = signed.userOperation.initCode !== PHILCORE_4337_EMPTY_BYTES;
  if (!accountWasCounterfactual && !request.accountStateReader) {
    return freezeRecord({
      accountWasCounterfactual,
      accountDeploymentObserved: false,
      accountDeploymentVerified: true,
      accountAddress: signed.binding.smartAccountAddress,
      checkedAt: receipt.checkedAt,
      errors: Object.freeze([])
    });
  }
  if (!request.accountStateReader) {
    return freezeRecord({
      accountWasCounterfactual,
      accountDeploymentObserved: false,
      accountDeploymentVerified: false,
      accountAddress: signed.binding.smartAccountAddress,
      checkedAt: receipt.checkedAt,
      errors: Object.freeze(["account state reader required"])
    });
  }
  const result = await verifyPhilCore4337Account({
    request: {
      accountAddress: signed.binding.smartAccountAddress,
      expectedEntryPoint: signed.binding.entryPointAddress,
      expectedOwner: signed.binding.owner,
      expectedOwnerCommitment: signed.binding.ownerCommitment,
      expectedApprovedActionGate: signed.binding.actionGateAddress,
      expectedChainId: signed.binding.chainId,
      configurationApproved: true
    },
    reader: request.accountStateReader
  });
  return freezeRecord({
    accountWasCounterfactual,
    accountDeploymentObserved: result.codeExists,
    accountDeploymentVerified: result.outcome === "account_verified",
    accountAddress: signed.binding.smartAccountAddress,
    checkedAt: result.checkedAt,
    errors: result.errors
  });
}

export function createInMemoryPhilCore4337SubmittedOperationStore(
  options: { readonly maxSubmittedOperationCount?: number } = {}
): PhilCore4337SubmittedOperationStore {
  const maxSubmittedOperationCount = Math.max(1, Math.floor(options.maxSubmittedOperationCount ?? 25));
  const submittedOperations = new Map<string, SubmittedPhilCore4337UserOperation>();
  const all = () => Object.freeze(Array.from(submittedOperations.values()));
  const collection = (): PhilCore4337SubmittedOperationCollection => Object.freeze({
    submittedOperations: all(),
    count: submittedOperations.size,
    maxSubmittedOperationCount
  });
  return {
    addSubmittedOperation(submittedOperation) {
      if (submittedOperations.has(submittedOperation.submittedPhilCore4337UserOperationId)) {
        return freezeRecord({
          status: "rejected_duplicate" as const,
          submittedOperation: submittedOperations.get(submittedOperation.submittedPhilCore4337UserOperationId),
          collection: collection(),
          reason: "duplicate submitted UserOperation id"
        });
      }
      const evictedSubmittedOperations: SubmittedPhilCore4337UserOperation[] = [];
      while (submittedOperations.size >= maxSubmittedOperationCount) {
        const oldest = submittedOperations.keys().next().value as string | undefined;
        if (!oldest) break;
        const evicted = submittedOperations.get(oldest);
        submittedOperations.delete(oldest);
        if (evicted) evictedSubmittedOperations.push(evicted);
      }
      const stored = freezeRecord(submittedOperation);
      submittedOperations.set(stored.submittedPhilCore4337UserOperationId, stored);
      return freezeRecord({
        status: evictedSubmittedOperations.length > 0 ? "evicted_oldest" as const : "collected" as const,
        submittedOperation: stored,
        evictedSubmittedOperations: Object.freeze(evictedSubmittedOperations),
        collection: collection()
      });
    },
    removeSubmittedOperation(id) {
      const removedSubmittedOperation = submittedOperations.get(id);
      if (!removedSubmittedOperation) {
        return freezeRecord({ status: "not_found" as const, collection: collection(), reason: "submitted operation not found" });
      }
      submittedOperations.delete(id);
      return freezeRecord({ status: "removed" as const, removedSubmittedOperation, collection: collection() });
    },
    clear() {
      submittedOperations.clear();
      return freezeRecord({ status: "cleared" as const, collection: collection() });
    },
    count() {
      return submittedOperations.size;
    },
    getById(id) {
      return submittedOperations.get(id);
    },
    getAll() {
      return all();
    }
  };
}
