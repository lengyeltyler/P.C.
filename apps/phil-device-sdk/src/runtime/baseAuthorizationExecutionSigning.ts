import { createHash } from "node:crypto";
import { Interface, Transaction, Wallet, getAddress, keccak256 } from "ethers";

import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  validateCapabilityGrantActiveState,
  type AuthoritativeCapabilityGrant
} from "./authoritativeCapabilityGrant.ts";
import {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  requestBaseMirroredFactVerification,
  validateBaseAuthorizationExecutionTransactionDraft,
  verifyBaseActionGateDeployment,
  type BaseActionGateConfiguration,
  type BaseActionGateDeploymentReader,
  type BaseAuthorizationExecutionFeeDataReference,
  type BaseAuthorizationExecutionGasEstimateReference,
  type BaseAuthorizationExecutionNonceReference,
  type BaseAuthorizationExecutionTransactionDraft,
  type BaseExecutionFeeDataReader,
  type BaseExecutionGasEstimator,
  type BaseExecutionNonceReader,
  type BaseMirroredFactEvidence,
  type BaseNullifierStateReader
} from "./baseAuthorizationExecutionPreparation.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import {
  validateUserSessionLifecycleSnapshotShape,
  type UserSessionLifecycleSnapshot
} from "./sessionLifecycle.ts";
import type { RuntimeResult } from "./types.ts";

const ACTION_GATE_INTERFACE = new Interface([
  "event AuthorizationConsumed(bytes32 indexed nullifier,bytes32 indexed authorizationDigest,address indexed consumer,address caller)"
]);

export type BaseExecutionCallerMode =
  | "philcore_smart_account"
  | "philcore_eoa_compatibility"
  | "infrastructure_execution_relayer"
  | "developer_fixture"
  | "unsupported";

export interface BaseExecutionCallerIdentity {
  readonly callerId: string;
  readonly mode: BaseExecutionCallerMode;
  readonly address: string;
  readonly displayName: string;
  readonly approved: boolean;
  readonly productionSuitable: boolean;
}

export type BaseFinalExecutionApprovalSource =
  | "authenticated_platform_user_approval"
  | "approved_smart_account_policy"
  | "operator_testnet_approval"
  | "developer_fixture_approval";

export interface BaseExecutionAuthorizationPolicy {
  readonly allowedCallerModes: readonly BaseExecutionCallerMode[];
  readonly allowedBaseChainIds: readonly number[];
  readonly allowedActionGateAddresses: readonly string[];
  readonly allowedConsumerAddresses: readonly string[];
  readonly allowMainnet: false;
  readonly requireLiveMirroredFactEvidence: boolean;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxGasLimit: string;
  readonly minBalanceWei: string;
  readonly allowedApprovalSources: readonly BaseFinalExecutionApprovalSource[];
}

export interface BaseExecutionFundingStatus {
  readonly status: "sufficient" | "insufficient" | "unknown";
  readonly balanceWei?: string;
  readonly checkedAt: string;
}

export interface BaseMirroredFactStateReadRequest {
  readonly baseMirrorAddress: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly baseChainId: number;
}

export interface BaseMirroredFactStateReadResult {
  readonly status: "fact_mirrored" | "fact_not_mirrored" | "state_unknown" | "reader_unavailable";
  readonly baseMirrorAddress: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly error?: string;
  readonly baseStateMutated: false;
}

export interface BaseMirroredFactStateReader {
  readMirroredFactState(request: BaseMirroredFactStateReadRequest): Promise<BaseMirroredFactStateReadResult>;
}

export type BaseExecutionAuthorizationStatus =
  | "execution_authorized_for_signing"
  | "execution_not_authorized";

export type BaseExecutionAuthorizationOutcome =
  | "execution_authorized_for_signing"
  | "execution_not_authorized"
  | "capability_ineligible"
  | "session_ineligible"
  | "package_ineligible"
  | "mirrored_fact_ineligible"
  | "nullifier_unavailable"
  | "consumer_data_mismatch"
  | "value_mismatch"
  | "caller_ineligible"
  | "configuration_mismatch"
  | "additional_approval_required"
  | "approval_rejected"
  | "expired"
  | "malformed"
  | "unsupported";

export type BaseExecutionAuthorizationReason =
  | "active_capability_revalidated"
  | "session_revalidated"
  | "mirrored_fact_revalidated"
  | "nullifier_available"
  | "configuration_revalidated"
  | "presentation_approved"
  | "caller_approved"
  | "ready_for_exact_signing";

export type BaseExecutionLimitation =
  | "eoas_are_compatibility_callers"
  | "erc4337_smart_account_preferred_future_path"
  | "signed_artifact_not_application_authority"
  | "requires_revalidation_before_submission"
  | "no_automatic_retry"
  | "fixture_not_live_execution";

export interface BaseExecutionAuthorizationBinding {
  readonly executionDraftId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: string;
  readonly nullifier: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly actionGateAddress: string;
  readonly verifierAddress: string;
  readonly mirrorAddress: string;
  readonly consumerAddress: string;
  readonly callerAccount: string;
  readonly calldataHash: string;
  readonly value: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly baseChainId: number;
  readonly auditCorrelationId: string;
}

export interface BaseExecutionAuthorizationRequest {
  readonly requestId: string;
  readonly draft: BaseAuthorizationExecutionTransactionDraft;
  readonly mirroredFactEvidence: BaseMirroredFactEvidence;
  readonly mirroredFactStateReader: BaseMirroredFactStateReader;
  readonly activeCapabilityGrant: AuthoritativeCapabilityGrant;
  readonly sessionLifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly configuration: BaseActionGateConfiguration;
  readonly deploymentReader: BaseActionGateDeploymentReader;
  readonly nullifierStateReader: BaseNullifierStateReader;
  readonly callerIdentity: BaseExecutionCallerIdentity;
  readonly policy: BaseExecutionAuthorizationPolicy;
  readonly approval?: BaseFinalExecutionApprovalArtifact;
  readonly gasEstimator: BaseExecutionGasEstimator;
  readonly nonceReader: BaseExecutionNonceReader;
  readonly feeDataReader: BaseExecutionFeeDataReader;
  readonly fundingStatus: BaseExecutionFundingStatus;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export interface BaseExecutionAuthorizationValue {
  readonly status: BaseExecutionAuthorizationStatus;
  readonly outcome: BaseExecutionAuthorizationOutcome;
  readonly binding: BaseExecutionAuthorizationBinding;
  readonly reasons: readonly BaseExecutionAuthorizationReason[];
  readonly errors: readonly string[];
}

export type BaseExecutionAuthorizationResult =
  RuntimeResult<BaseExecutionAuthorizationValue>;

export interface BaseExecutionSigningPresentation {
  readonly baseNetworkProfileId: string;
  readonly baseChainId: number;
  readonly callerAccount: string;
  readonly actionGate: string;
  readonly verifier: string;
  readonly mirror: string;
  readonly consumer: string;
  readonly method: "verifyAndConsume";
  readonly methodSelector: typeof BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR;
  readonly calldataHash: string;
  readonly proofInputHash: string;
  readonly nullifier: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly capabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: string;
  readonly target: string;
  readonly consumerDataHash: string;
  readonly value: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly transactionExpiresAt: string;
  readonly auditCorrelationId: string;
}

export interface BaseExecutionSigningPresentationDigest {
  readonly algorithm: "sha256-json-v1";
  readonly digest: string;
  readonly presentation: BaseExecutionSigningPresentation;
}

export interface BaseExecutionTransactionHashBinding {
  readonly transactionType: "eip1559";
  readonly transactionHash: string;
  readonly unsignedHash: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly to: string;
  readonly dataHash: string;
}

export interface BaseFinalExecutionApprovalRequest {
  readonly presentation: BaseExecutionSigningPresentationDigest;
  readonly source: BaseFinalExecutionApprovalSource;
  readonly approved: boolean;
  readonly approvedAt?: string;
  readonly expiresAt?: string;
  readonly approvalId?: string;
}

export interface BaseFinalExecutionApprovalArtifact {
  readonly approvalId: string;
  readonly source: BaseFinalExecutionApprovalSource;
  readonly presentationDigest: string;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly oneTimeUse: true;
  readonly fixtureOnly: boolean;
}

export type BaseFinalExecutionApprovalResult =
  RuntimeResult<BaseFinalExecutionApprovalArtifact>;

export interface BaseExecutionEip1559Transaction {
  readonly type: 2;
  readonly chainId: number;
  readonly nonce: number;
  readonly to: string;
  readonly value: bigint;
  readonly data: string;
  readonly gasLimit: bigint;
  readonly maxFeePerGas: bigint;
  readonly maxPriorityFeePerGas: bigint;
}

export interface BaseExecutionSignerDescriptor {
  readonly signerId: string;
  readonly signerKind:
    | "philcore_smart_account_signer"
    | "local_encrypted_testnet_key"
    | "external_wallet"
    | "remote_hsm"
    | "cloud_kms"
    | "developer_fixture";
  readonly callerAddress: string;
  readonly mode: BaseExecutionCallerMode;
  readonly productionSuitable: boolean;
  readonly arbitrarySigningSupported: false;
  readonly submissionSupported: false;
}

export interface BaseExecutionSigner {
  describeSigner(): BaseExecutionSignerDescriptor;
  checkAvailability(): { readonly available: boolean; readonly reason?: string };
  signBaseExecutionTransaction(request: BaseExecutionSigningRequest): Promise<BaseExecutionSigningResult>;
  invalidateSigningSession(): void;
}

export interface BaseExecutionSigningRequest {
  readonly transaction: BaseExecutionEip1559Transaction;
  readonly expectedUnsignedHash: string;
  readonly presentationDigest: string;
  readonly expectedCalldataHash: string;
}

export interface BaseExecutionSigningResult {
  readonly status: "signed" | "rejected" | "failed";
  readonly transactionHash: string;
  readonly rawSignedTransaction?: string;
  readonly signerDescriptor?: BaseExecutionSignerDescriptor;
  readonly error?: string;
}

export interface BaseAuthorizationExecutionSigningRequest extends BaseExecutionAuthorizationRequest {
  readonly signer: BaseExecutionSigner;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type SignedBaseAuthorizationExecutionStatus =
  | "execution_transaction_signed";

export type SignedBaseAuthorizationExecutionOutcome =
  | "execution_transaction_signed"
  | BaseExecutionAuthorizationOutcome
  | "signer_unavailable"
  | "transaction_hash_mismatch"
  | "wrong_signer";

export interface BaseExecutionSignatureArtifact {
  readonly transactionHash: string;
  readonly rawSignedTransaction: string;
  readonly signerId: string;
  readonly signerAccountAddress: string;
  readonly exactTransactionSigned: true;
  readonly privateKeyExposed: false;
}

export interface SignedBaseAuthorizationExecutionTransaction {
  readonly signedBaseAuthorizationExecutionTransactionId: string;
  readonly status: SignedBaseAuthorizationExecutionStatus;
  readonly outcome: "execution_transaction_signed";
  readonly binding: BaseExecutionAuthorizationBinding;
  readonly transaction: BaseExecutionEip1559Transaction;
  readonly transactionHashBinding: BaseExecutionTransactionHashBinding;
  readonly signatureArtifact: BaseExecutionSignatureArtifact;
  readonly signerDescriptor: BaseExecutionSignerDescriptor;
  readonly signedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly BaseExecutionLimitation[];
  readonly transactionSigned: true;
  readonly transactionSubmitted: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly baseStateMutated: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type SignedBaseAuthorizationExecutionResult =
  RuntimeResult<SignedBaseAuthorizationExecutionTransaction>;

export type BaseAuthorizationExecutionSubmissionStatus =
  | "submission_blocked"
  | "execution_transaction_submitted"
  | "execution_transaction_pending"
  | "execution_transaction_confirmed"
  | "execution_transaction_reverted"
  | "execution_transaction_rejected";

export type BaseAuthorizationExecutionSubmissionOutcome =
  | "submission_blocked"
  | "execution_transaction_submitted"
  | "execution_transaction_pending"
  | "execution_transaction_confirmed"
  | "execution_transaction_reverted"
  | "execution_transaction_rejected"
  | "nullifier_consumed_before_submission"
  | "capability_expired"
  | "session_became_ineligible"
  | "mirrored_fact_missing"
  | "nonce_changed"
  | "fee_changed"
  | "approval_missing"
  | "duplicate_submission"
  | "rpc_unavailable"
  | "submission_timeout"
  | "malformed"
  | "unsupported";

export interface BaseExecutionSubmissionApproval {
  readonly approvalId: string;
  readonly approved: boolean;
  readonly source: BaseFinalExecutionApprovalSource;
  readonly transactionHash: string;
  readonly callerAccount: string;
  readonly baseChainId: number;
  readonly actionGateAddress: string;
  readonly calldataHash: string;
  readonly proofInputHash: string;
  readonly nullifier: string;
  readonly value: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export interface BaseAuthorizationExecutionSubmissionRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
  readonly submissionApproval?: BaseExecutionSubmissionApproval;
  readonly mirroredFactStateReader: BaseMirroredFactStateReader;
  readonly nullifierStateReader: BaseNullifierStateReader;
  readonly activeCapabilityGrant: AuthoritativeCapabilityGrant;
  readonly sessionLifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly deploymentReader: BaseActionGateDeploymentReader;
  readonly configuration: BaseActionGateConfiguration;
  readonly gasEstimator: BaseExecutionGasEstimator;
  readonly nonceReader: BaseExecutionNonceReader;
  readonly feeDataReader: BaseExecutionFeeDataReader;
  readonly submitter: BaseExecutionTransactionSubmitter;
  readonly submittedTransactionStore?: BaseExecutionSubmittedTransactionStore;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface BaseAuthorizationExecutionSubmissionValue {
  readonly status: BaseAuthorizationExecutionSubmissionStatus;
  readonly outcome: BaseAuthorizationExecutionSubmissionOutcome;
  readonly transactionHash: string;
  readonly submittedAt?: string;
  readonly transactionSubmitted: boolean;
  readonly transactionConfirmed: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type BaseAuthorizationExecutionSubmissionResult =
  RuntimeResult<BaseAuthorizationExecutionSubmissionValue>;

export interface BaseExecutionTransactionSubmitter {
  submitSignedBaseExecutionTransaction(
    request: BaseExecutionTransactionSubmitRequest
  ): Promise<BaseExecutionTransactionSubmitResult>;
}

export interface BaseExecutionTransactionSubmitRequest {
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
}

export interface BaseExecutionTransactionSubmitResult {
  readonly status: "submitted" | "rejected" | "unavailable";
  readonly transactionHash?: string;
  readonly submittedAt?: string;
  readonly error?: string;
}

export interface BaseExecutionSubmittedTransactionStore {
  hasTransaction(transactionHash: string): boolean;
  addTransaction(transactionHash: string): { readonly status: "recorded" | "duplicate"; readonly count: number };
  clear(): void;
}

export interface BaseExecutionReceiptLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export interface BaseExecutionEthereumReceipt {
  readonly transactionHash: string;
  readonly status: "pending" | "confirmed" | "reverted" | "rejected" | "dropped_replaced";
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly gasUsed?: string;
  readonly effectiveGasPrice?: string;
  readonly confirmations?: number;
  readonly logs: readonly BaseExecutionReceiptLog[];
  readonly error?: string;
}

export interface BaseExecutionReceiptReader {
  getTransactionReceipt(transactionHash: string): Promise<BaseExecutionEthereumReceipt>;
}

export interface BaseNullifierConsumptionEvidence {
  readonly nullifier: string;
  readonly actionGateAddress: string;
  readonly transactionHash: string;
  readonly consumed: boolean;
  readonly checkedAt: string;
  readonly source: "mapping_getter" | "fixture" | "receipt_and_mapping";
}

export interface BaseNullifierConsumptionVerificationResultValue {
  readonly status: "nullifier_consumption_verified";
  readonly outcome: "nullifier_consumed";
  readonly evidence: BaseNullifierConsumptionEvidence;
  readonly nullifierConsumed: true;
  readonly otherNullifiersAffected: false;
}

export type BaseNullifierConsumptionVerificationResult =
  RuntimeResult<BaseNullifierConsumptionVerificationResultValue>;

export interface BaseConsumerExecutionEvidence {
  readonly status: "consumer_executed" | "consumer_not_executed" | "consumer_execution_unknown";
  readonly consumerAddress: string;
  readonly actionGateAddress: string;
  readonly transactionHash: string;
  readonly nullifier: string;
  readonly actionHash: string;
  readonly consumerDataHash: string;
  readonly target?: string;
  readonly value?: string;
  readonly checkedAt: string;
  readonly approvedActionMatched: boolean;
}

export interface BaseConsumerExecutionReader {
  readConsumerExecution(
    request: BaseConsumerExecutionVerificationRequest
  ): Promise<BaseConsumerExecutionEvidence>;
}

export interface BaseConsumerExecutionVerificationRequest {
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
  readonly receipt: BaseExecutionEthereumReceipt;
}

export interface BaseConsumerExecutionVerificationResultValue {
  readonly status: "consumer_execution_verified";
  readonly outcome: "consumer_executed";
  readonly evidence: BaseConsumerExecutionEvidence;
  readonly consumerExecuted: true;
  readonly approvedActionMatched: true;
}

export type BaseConsumerExecutionVerificationResult =
  RuntimeResult<BaseConsumerExecutionVerificationResultValue>;

export interface BaseAuthorizationExecutionReceipt {
  readonly baseAuthorizationExecutionReceiptId: string;
  readonly transactionHash: string;
  readonly receipt: BaseExecutionEthereumReceipt;
  readonly nullifierEvidence: BaseNullifierConsumptionEvidence;
  readonly consumerEvidence: BaseConsumerExecutionEvidence;
  readonly transactionConfirmed: true;
  readonly proofVerifiedByActionGate: true;
  readonly nullifierConsumed: true;
  readonly consumerExecuted: true;
  readonly approvedActionMatched: true;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface BaseAuthorizationExecutionReceiptMonitoringRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
  readonly receiptReader: BaseExecutionReceiptReader;
  readonly nullifierStateReader: BaseNullifierStateReader;
  readonly consumerExecutionReader: BaseConsumerExecutionReader;
  readonly minConfirmations?: number;
  readonly maxAttempts?: number;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type BaseAuthorizationExecutionReceiptMonitoringResult =
  RuntimeResult<BaseAuthorizationExecutionReceipt>;

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function bigintFrom(value?: string): bigint | undefined {
  if (!value) return undefined;
  return BigInt(value);
}

function sha256Json(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value, Object.keys(value as object).sort()))
    .digest("hex");
}

function transactionFromDraft(
  draft: BaseAuthorizationExecutionTransactionDraft,
  fee: BaseAuthorizationExecutionFeeDataReference
): BaseExecutionEip1559Transaction | undefined {
  const nonce = Number(bigintFrom(draft.nonce.nonce));
  const gasLimit = bigintFrom(draft.gas.gasLimit);
  const maxFeePerGas = bigintFrom(fee.maxFeePerGas);
  const maxPriorityFeePerGas = bigintFrom(fee.maxPriorityFeePerGas);
  if (!Number.isSafeInteger(nonce) || !gasLimit || !maxFeePerGas || !maxPriorityFeePerGas) return undefined;
  return Object.freeze({
    type: 2 as const,
    chainId: draft.chainId,
    nonce,
    to: normalizeAddress(draft.to),
    value: BigInt(draft.value),
    data: draft.calldata,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas
  });
}

function transactionHashBinding(
  transaction: BaseExecutionEip1559Transaction,
  rawSignedTransaction?: string
): BaseExecutionTransactionHashBinding {
  const unsigned = Transaction.from(transaction);
  const signed = rawSignedTransaction ? Transaction.from(rawSignedTransaction) : undefined;
  return Object.freeze({
    transactionType: "eip1559",
    transactionHash: signed?.hash ?? unsigned.unsignedHash,
    unsignedHash: unsigned.unsignedHash,
    chainId: transaction.chainId,
    nonce: String(transaction.nonce),
    to: transaction.to,
    dataHash: keccak256(transaction.data)
  });
}

function bindingFromDraft(
  draft: BaseAuthorizationExecutionTransactionDraft,
  fee: BaseAuthorizationExecutionFeeDataReference
): BaseExecutionAuthorizationBinding {
  return Object.freeze({
    executionDraftId: draft.baseAuthorizationExecutionTransactionDraftId,
    finalizedAuthorizationPackageId: draft.binding.finalizedAuthorizationPackageId,
    authoritativeCapabilityGrantId: draft.binding.authoritativeCapabilityGrantId,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    ownerCommitment: draft.binding.ownerCommitment,
    nullifier: draft.binding.nullifier,
    proofInputHash: draft.binding.proofInputHash,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    actionGateAddress: draft.binding.actionGateAddress,
    verifierAddress: draft.binding.verifierAddress,
    mirrorAddress: draft.binding.baseMirrorAddress,
    consumerAddress: draft.binding.consumerAddress,
    callerAccount: draft.from,
    calldataHash: draft.calldataHash,
    value: draft.value,
    nonce: draft.nonce.nonce ?? "",
    gasLimit: draft.gas.gasLimit ?? "",
    maxFeePerGas: fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas ?? "",
    baseChainId: draft.chainId,
    auditCorrelationId: draft.binding.auditCorrelationId
  });
}

function createExecutionAuditDraft(input: {
  readonly requestKind: string;
  readonly outcome: string;
  readonly summary: string;
  readonly signed?: SignedBaseAuthorizationExecutionTransaction;
  readonly draft?: BaseAuthorizationExecutionTransactionDraft;
  readonly errors?: readonly string[];
  readonly auditCorrelationId?: string;
}): AuditEventDraft {
  const binding = input.signed?.binding ?? input.draft?.binding;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome.includes("signed")
      || input.outcome.includes("submitted")
      || input.outcome.includes("confirmed")
      || input.outcome.includes("verified")
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: input.requestKind,
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId ?? binding?.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.signed?.transactionHashBinding.transactionHash,
      actionGate: binding?.actionGateAddress,
      verifier: binding?.verifierAddress,
      mirror: input.draft?.binding.baseMirrorAddress ?? input.signed?.binding.mirrorAddress,
      consumer: binding?.consumerAddress,
      proofInputHash: binding?.proofInputHash,
      nullifier: binding?.nullifier,
      calldataHash: input.signed?.binding.calldataHash ?? input.draft?.calldataHash,
      value: input.signed?.binding.value ?? input.draft?.value
    }
  });
}

export function createBaseExecutionSigningPresentation(input: {
  readonly draft: BaseAuthorizationExecutionTransactionDraft;
  readonly fee?: BaseAuthorizationExecutionFeeDataReference;
  readonly auditCorrelationId?: string;
}): BaseExecutionSigningPresentationDigest {
  const profileId = input.draft.chainId === 84532 ? "base_sepolia" : "hardhat";
  const presentation = Object.freeze({
    baseNetworkProfileId: profileId,
    baseChainId: input.draft.chainId,
    callerAccount: normalizeAddress(input.draft.from),
    actionGate: normalizeAddress(input.draft.binding.actionGateAddress),
    verifier: normalizeAddress(input.draft.binding.verifierAddress),
    mirror: normalizeAddress(input.draft.binding.baseMirrorAddress),
    consumer: normalizeAddress(input.draft.binding.consumerAddress),
    method: "verifyAndConsume" as const,
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    calldataHash: input.draft.calldataHash,
    proofInputHash: input.draft.binding.proofInputHash,
    nullifier: input.draft.binding.nullifier,
    factHigh: input.draft.binding.factHigh,
    factLow: input.draft.binding.factLow,
    capabilityGrantId: input.draft.binding.authoritativeCapabilityGrantId,
    sessionId: input.draft.binding.sessionId,
    applicationId: input.draft.binding.applicationId,
    ownerCommitment: input.draft.binding.ownerCommitment,
    target: input.draft.consumerCallPreview.target,
    consumerDataHash: input.draft.binding.consumerDataHash,
    value: input.draft.value,
    nonce: input.draft.nonce.nonce ?? "",
    gasLimit: input.draft.gas.gasLimit ?? "",
    maxFeePerGas: input.fee?.maxFeePerGas ?? input.draft.fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: input.fee?.maxPriorityFeePerGas ?? input.draft.fee.maxPriorityFeePerGas ?? "",
    transactionExpiresAt: input.draft.expiresAt,
    auditCorrelationId: input.auditCorrelationId ?? input.draft.binding.auditCorrelationId
  });
  return Object.freeze({
    algorithm: "sha256-json-v1" as const,
    digest: sha256Json(presentation),
    presentation
  });
}

export function createBaseFinalExecutionApproval(
  request: BaseFinalExecutionApprovalRequest
): BaseFinalExecutionApprovalResult {
  if (!request.approved) {
    return runtimeDenied({
      code: "BASE_FINAL_EXECUTION_APPROVAL_REJECTED",
      category: "user_cancelled",
      message: "Base final execution approval was rejected.",
      recoverable: true,
      details: { outcome: "approval_rejected" }
    });
  }
  return runtimeOk(Object.freeze({
    approvalId: request.approvalId ?? createAuditCorrelationId([
      request.presentation.digest,
      "base-final-execution-approval"
    ]),
    source: request.source,
    presentationDigest: request.presentation.digest,
    approved: true,
    approvedAt: request.approvedAt ?? nowIso(),
    expiresAt: request.expiresAt ?? new Date(Date.now() + 300_000).toISOString(),
    oneTimeUse: true,
    fixtureOnly: request.source === "developer_fixture_approval"
  }));
}

function outcomeForAuthorizationErrors(errors: readonly string[]): BaseExecutionAuthorizationOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("capability")) return "capability_ineligible";
  if (joined.includes("session")) return "session_ineligible";
  if (joined.includes("package") || joined.includes("draft")) return "package_ineligible";
  if (joined.includes("mirrored") || joined.includes("fact")) return "mirrored_fact_ineligible";
  if (joined.includes("nullifier")) return "nullifier_unavailable";
  if (joined.includes("consumer")) return "consumer_data_mismatch";
  if (joined.includes("value")) return "value_mismatch";
  if (joined.includes("caller") || joined.includes("funding")) return "caller_ineligible";
  if (joined.includes("configuration") || joined.includes("deployment")) return "configuration_mismatch";
  if (joined.includes("approval missing")) return "additional_approval_required";
  if (joined.includes("approval")) return "approval_rejected";
  if (joined.includes("expired")) return "expired";
  if (joined.includes("mainnet")) return "unsupported";
  return "malformed";
}

export async function authorizeBaseExecution(
  request: BaseExecutionAuthorizationRequest
): Promise<BaseExecutionAuthorizationResult> {
  const errors: string[] = [];
  errors.push(...validateBaseAuthorizationExecutionTransactionDraft(request.draft).errors.map((error) => `draft ${error}`));
  errors.push(...validateCapabilityGrantActiveState(request.activeCapabilityGrant, request.issueTime).errors.map((error) => `capability ${error}`));
  errors.push(...validateUserSessionLifecycleSnapshotShape(request.sessionLifecycleSnapshot).errors.map((error) => `session ${error}`));
  if (!["unlocked", "recovery_mode"].includes(request.sessionLifecycleSnapshot.state)) errors.push("session ineligible");
  if (Date.now() > Date.parse(request.expiresAt) || Date.now() > Date.parse(request.draft.expiresAt)) errors.push("authorization expired");
  if (request.draft.chainId === 8453 || request.policy.allowMainnet !== false) errors.push("mainnet prohibited");
  if (!request.policy.allowedBaseChainIds.includes(request.draft.chainId)) errors.push("chain rejected");
  if (!request.policy.allowedActionGateAddresses.map(normalizeAddress).includes(normalizeAddress(request.draft.to))) {
    errors.push("ActionGate rejected");
  }
  if (!request.policy.allowedConsumerAddresses.map(normalizeAddress).includes(normalizeAddress(request.draft.binding.consumerAddress))) {
    errors.push("consumer rejected");
  }
  if (!request.callerIdentity.approved) errors.push("caller unapproved");
  if (!request.policy.allowedCallerModes.includes(request.callerIdentity.mode)) errors.push("caller mode rejected");
  if (normalizeAddress(request.callerIdentity.address) !== normalizeAddress(request.draft.from)) errors.push("caller mismatch");
  if (request.policy.requireLiveMirroredFactEvidence && !request.draft.liveMirroredFactEvidence) {
    errors.push("live mirrored fact evidence required");
  }
  const factEvidence = requestBaseMirroredFactVerification(request.mirroredFactEvidence);
  if (factEvidence.status !== "approved") errors.push("mirrored fact evidence invalid");
  const mirrored = await request.mirroredFactStateReader.readMirroredFactState({
    baseMirrorAddress: request.draft.binding.baseMirrorAddress,
    factHigh: request.draft.binding.factHigh,
    factLow: request.draft.binding.factLow,
    proofInputHash: request.draft.binding.proofInputHash,
    baseChainId: request.draft.chainId
  });
  if (mirrored.status !== "fact_mirrored") errors.push("mirrored fact missing");
  const deployment = await verifyBaseActionGateDeployment({
    configuration: request.configuration,
    evidence: request.mirroredFactEvidence
  }, request.deploymentReader);
  if (deployment.status !== "approved") errors.push("deployment configuration mismatch");
  const nullifier = await request.nullifierStateReader.readNullifierState({
    actionGateAddress: request.draft.binding.actionGateAddress,
    nullifier: request.draft.binding.nullifier,
    baseChainId: request.draft.chainId
  });
  if (nullifier.status !== "nullifier_available") errors.push("nullifier unavailable");
  const gas = await request.gasEstimator.estimateGas({
    from: request.draft.from,
    to: request.draft.to,
    data: request.draft.calldata,
    value: request.draft.value,
    chainId: request.draft.chainId
  });
  if (gas.status !== "estimated" || gas.gasLimit !== request.draft.gas.gasLimit) errors.push("gas changed");
  const nonce = await request.nonceReader.readNonce({ account: request.draft.from, chainId: request.draft.chainId });
  if (nonce.status !== "resolved" || nonce.nonce !== request.draft.nonce.nonce) errors.push("nonce changed");
  const fee = await request.feeDataReader.readFeeData({ chainId: request.draft.chainId });
  if (fee.status !== "resolved") errors.push("fee unresolved");
  if ((bigintFrom(gas.gasLimit) ?? 0n) > BigInt(request.policy.maxGasLimit)) errors.push("gas limit exceeded");
  if ((bigintFrom(fee.maxFeePerGas) ?? 0n) > BigInt(request.policy.maxFeePerGas)) errors.push("fee cap exceeded");
  if ((bigintFrom(fee.maxPriorityFeePerGas) ?? 0n) > BigInt(request.policy.maxPriorityFeePerGas)) {
    errors.push("priority fee cap exceeded");
  }
  if (request.fundingStatus.status !== "sufficient") errors.push("funding insufficient");
  if ((bigintFrom(request.fundingStatus.balanceWei) ?? 0n) < BigInt(request.policy.minBalanceWei)) {
    errors.push("funding insufficient");
  }
  const presentation = createBaseExecutionSigningPresentation({
    draft: request.draft,
    fee,
    auditCorrelationId: request.auditCorrelationId
  });
  if (!request.approval?.approved) errors.push("approval missing");
  if (request.approval && Date.now() > Date.parse(request.approval.expiresAt)) errors.push("approval expired");
  if (request.approval && !request.policy.allowedApprovalSources.includes(request.approval.source)) errors.push("approval source rejected");
  if (request.approval && request.approval.fixtureOnly && request.policy.requireLiveMirroredFactEvidence) {
    errors.push("fixture approval rejected");
  }
  if (request.approval && request.approval.presentationDigest !== presentation.digest) {
    errors.push("approval presentation digest mismatch");
  }
  const binding = bindingFromDraft(request.draft, fee);
  if (errors.length > 0) {
    const outcome = outcomeForAuthorizationErrors(errors);
    return runtimeDenied({
      code: "BASE_EXECUTION_AUTHORIZATION_REJECTED",
      category: "policy_denied",
      message: "Base execution authorization was rejected.",
      recoverable: true,
      details: { outcome, errors }
    });
  }
  return runtimeOk(Object.freeze({
    status: "execution_authorized_for_signing",
    outcome: "execution_authorized_for_signing",
    binding,
    reasons: Object.freeze([
      "active_capability_revalidated",
      "session_revalidated",
      "mirrored_fact_revalidated",
      "nullifier_available",
      "configuration_revalidated",
      "presentation_approved",
      "caller_approved",
      "ready_for_exact_signing"
    ] as const),
    errors: Object.freeze([])
  }));
}

export const requestBaseExecutionAuthorization = authorizeBaseExecution;

export async function signBaseAuthorizationExecutionTransaction(
  request: BaseAuthorizationExecutionSigningRequest
): Promise<SignedBaseAuthorizationExecutionResult> {
  const authorization = await authorizeBaseExecution(request);
  if (authorization.status !== "approved") {
    const outcome = authorization.error?.details?.outcome as SignedBaseAuthorizationExecutionOutcome;
    const auditEventDraft = createExecutionAuditDraft({
      requestKind: "requestBaseExecutionSigning",
      outcome,
      summary: "Base execution signing was blocked.",
      draft: request.draft,
      errors: authorization.error?.details?.errors as readonly string[] | undefined,
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "BASE_EXECUTION_SIGNING_REJECTED",
      category: "policy_denied",
      message: "Base execution signing was rejected.",
      recoverable: true,
      details: { outcome, authorization: authorization.error?.details, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const fee = await request.feeDataReader.readFeeData({ chainId: request.draft.chainId });
  const tx = transactionFromDraft(request.draft, fee);
  if (!tx) {
    return runtimeDenied({
      code: "BASE_EXECUTION_TRANSACTION_MALFORMED",
      category: "invalid_authorization_package",
      message: "Base execution draft is missing signable nonce, gas, or fee fields.",
      recoverable: true,
      details: { outcome: "malformed" }
    });
  }
  if (!request.signer.checkAvailability().available) {
    return runtimeDenied({
      code: "BASE_EXECUTION_SIGNER_UNAVAILABLE",
      category: "adapter_unavailable",
      message: "Base execution signer is unavailable.",
      recoverable: true,
      details: { outcome: "signer_unavailable" }
    });
  }
  const unsigned = transactionHashBinding(tx);
  const presentation = createBaseExecutionSigningPresentation({
    draft: request.draft,
    fee,
    auditCorrelationId: request.auditCorrelationId
  });
  const signed = await request.signer.signBaseExecutionTransaction({
    transaction: tx,
    expectedUnsignedHash: unsigned.unsignedHash,
    presentationDigest: presentation.digest,
    expectedCalldataHash: request.draft.calldataHash
  });
  if (signed.status !== "signed" || !signed.rawSignedTransaction || !signed.signerDescriptor) {
    return runtimeDenied({
      code: "BASE_EXECUTION_SIGNING_FAILED",
      category: "adapter_unavailable",
      message: "Base execution signer did not return a signed artifact.",
      recoverable: true,
      details: { outcome: "signer_unavailable", error: signed.error }
    });
  }
  const hashBinding = transactionHashBinding(tx, signed.rawSignedTransaction);
  if (hashBinding.transactionHash !== signed.transactionHash) {
    return runtimeDenied({
      code: "BASE_EXECUTION_HASH_MISMATCH",
      category: "invalid_authorization_package",
      message: "Signed Base execution transaction hash did not match signer output.",
      recoverable: true,
      details: { outcome: "transaction_hash_mismatch" }
    });
  }
  if (normalizeAddress(signed.signerDescriptor.callerAddress) !== normalizeAddress(request.callerIdentity.address)) {
    return runtimeDenied({
      code: "BASE_EXECUTION_WRONG_SIGNER",
      category: "trust_denied",
      message: "Base execution signer account does not match approved caller.",
      recoverable: true,
      details: { outcome: "wrong_signer" }
    });
  }
  const auditEventDraft = createExecutionAuditDraft({
    requestKind: "requestBaseExecutionSigning",
    outcome: "execution_transaction_signed",
    summary: "Signed but unsubmitted Base authorization execution transaction artifact created.",
    draft: request.draft,
    auditCorrelationId: request.auditCorrelationId
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const limitations: BaseExecutionLimitation[] = [
    "eoas_are_compatibility_callers",
    "erc4337_smart_account_preferred_future_path",
    "signed_artifact_not_application_authority",
    "requires_revalidation_before_submission",
    "no_automatic_retry"
  ];
  if (!request.draft.liveMirroredFactEvidence) limitations.push("fixture_not_live_execution");
  const authorizationValue = authorization.value;
  if (!authorizationValue) {
    return runtimeDenied({
      code: "BASE_EXECUTION_AUTHORIZATION_VALUE_MISSING",
      category: "invalid_authorization_package",
      message: "Base execution authorization value was missing after approval.",
      recoverable: true,
      details: { outcome: "malformed" }
    });
  }
  return runtimeOk(Object.freeze({
    signedBaseAuthorizationExecutionTransactionId: createAuditCorrelationId([
      hashBinding.transactionHash,
      "signed-base-execution"
    ]),
    status: "execution_transaction_signed",
    outcome: "execution_transaction_signed",
    binding: authorizationValue.binding,
    transaction: tx,
    transactionHashBinding: hashBinding,
    signatureArtifact: Object.freeze({
      transactionHash: hashBinding.transactionHash,
      rawSignedTransaction: signed.rawSignedTransaction,
      signerId: signed.signerDescriptor.signerId,
      signerAccountAddress: signed.signerDescriptor.callerAddress,
      exactTransactionSigned: true,
      privateKeyExposed: false
    }),
    signerDescriptor: signed.signerDescriptor,
    signedAt: nowIso(),
    expiresAt: request.expiresAt,
    limitations: Object.freeze(limitations),
    transactionSigned: true,
    transactionSubmitted: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    baseStateMutated: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestBaseExecutionSigning = signBaseAuthorizationExecutionTransaction;

export function createBaseExecutionSubmissionApproval(input: {
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
  readonly source: BaseFinalExecutionApprovalSource;
  readonly approved?: boolean;
  readonly approvedAt?: string;
  readonly expiresAt?: string;
  readonly approvalId?: string;
}): BaseExecutionSubmissionApproval {
  const signed = input.signedTransaction;
  return Object.freeze({
    approvalId: input.approvalId ?? createAuditCorrelationId([
      signed.transactionHashBinding.transactionHash,
      "base-execution-submission-approval"
    ]),
    approved: input.approved ?? true,
    source: input.source,
    transactionHash: signed.transactionHashBinding.transactionHash,
    callerAccount: signed.signatureArtifact.signerAccountAddress,
    baseChainId: signed.binding.baseChainId,
    actionGateAddress: signed.binding.actionGateAddress,
    calldataHash: signed.binding.calldataHash,
    proofInputHash: signed.binding.proofInputHash,
    nullifier: signed.binding.nullifier as `0x${string}`,
    value: signed.binding.value,
    nonce: signed.binding.nonce,
    gasLimit: signed.binding.gasLimit,
    maxFeePerGas: signed.binding.maxFeePerGas,
    maxPriorityFeePerGas: signed.binding.maxPriorityFeePerGas,
    approvedAt: input.approvedAt ?? nowIso(),
    expiresAt: input.expiresAt ?? new Date(Date.now() + 300_000).toISOString()
  });
}

function validateSubmissionApproval(
  approval: BaseExecutionSubmissionApproval | undefined,
  signed: SignedBaseAuthorizationExecutionTransaction
): readonly string[] {
  const errors: string[] = [];
  if (!approval) return ["submission approval missing"];
  if (!approval.approved) errors.push("submission approval rejected");
  if (Date.now() > Date.parse(approval.expiresAt)) errors.push("submission approval expired");
  if (approval.transactionHash !== signed.transactionHashBinding.transactionHash) errors.push("transaction hash mismatch");
  if (approval.baseChainId !== signed.binding.baseChainId) errors.push("chain mismatch");
  if (normalizeAddress(approval.actionGateAddress) !== normalizeAddress(signed.binding.actionGateAddress)) errors.push("ActionGate mismatch");
  if (approval.calldataHash !== signed.binding.calldataHash) errors.push("calldata mismatch");
  if (approval.nullifier !== signed.binding.nullifier) errors.push("nullifier mismatch");
  if (approval.nonce !== signed.binding.nonce) errors.push("nonce mismatch");
  if (approval.value !== signed.binding.value) errors.push("value mismatch");
  return errors;
}

export async function submitBaseAuthorizationExecutionTransaction(
  request: BaseAuthorizationExecutionSubmissionRequest
): Promise<BaseAuthorizationExecutionSubmissionResult> {
  const signed = request.signedTransaction;
  const errors: string[] = [];
  if (Date.now() > Date.parse(request.expiresAt) || Date.now() > Date.parse(signed.expiresAt)) errors.push("submission expired");
  if (signed.binding.baseChainId === 8453) errors.push("mainnet prohibited");
  if (request.submittedTransactionStore?.hasTransaction(signed.transactionHashBinding.transactionHash)) errors.push("duplicate submission");
  errors.push(...validateSubmissionApproval(request.submissionApproval, signed));
  errors.push(...validateCapabilityGrantActiveState(request.activeCapabilityGrant, request.issueTime).errors.map((error) => `capability ${error}`));
  const session = validateUserSessionLifecycleSnapshotShape(request.sessionLifecycleSnapshot);
  errors.push(...session.errors.map((error) => `session ${error}`));
  if (!["unlocked", "recovery_mode"].includes(request.sessionLifecycleSnapshot.state)) errors.push("session ineligible");
  const mirrored = await request.mirroredFactStateReader.readMirroredFactState({
    baseMirrorAddress: signed.binding.mirrorAddress,
    factHigh: signed.binding.factHigh,
    factLow: signed.binding.factLow,
    proofInputHash: signed.binding.proofInputHash,
    baseChainId: signed.binding.baseChainId
  });
  if (mirrored.status !== "fact_mirrored") errors.push("mirrored fact missing");
  const nullifier = await request.nullifierStateReader.readNullifierState({
    actionGateAddress: signed.binding.actionGateAddress,
    nullifier: signed.binding.nullifier as `0x${string}`,
    baseChainId: signed.binding.baseChainId
  });
  if (nullifier.status !== "nullifier_available") errors.push("nullifier consumed before submission");
  const deployment = await verifyBaseActionGateDeployment({
    configuration: request.configuration,
    evidence: {
      status: "mirrored_fact_evidence_valid",
      source: signed.limitations.includes("fixture_not_live_execution") ? "fixture_receipt" : "live_base_receipt",
      binding: {
        baseChainId: signed.binding.baseChainId,
        baseMirrorAddress: signed.binding.mirrorAddress,
        baseMessengerAddress: request.configuration.mirror.messengerAddress,
        authorizedL1RemoteSender: request.configuration.mirror.authorizedL1RemoteSender,
        factHigh: signed.binding.factHigh as `0x${string}`,
        factLow: signed.binding.factLow as `0x${string}`,
        proofInputHash: signed.binding.proofInputHash as `0x${string}`,
        auditCorrelationId: signed.binding.auditCorrelationId
      },
      observedAt: request.issueTime,
      liveMirroredFactEvidence: !signed.limitations.includes("fixture_not_live_execution"),
      productionSignable: !signed.limitations.includes("fixture_not_live_execution"),
      errors: []
    },
  }, request.deploymentReader);
  if (deployment.status !== "approved") errors.push("deployment configuration mismatch");
  const gas = await request.gasEstimator.estimateGas({
    from: signed.binding.callerAccount,
    to: signed.binding.actionGateAddress,
    data: signed.transaction.data as `0x${string}`,
    value: signed.binding.value,
    chainId: signed.binding.baseChainId
  });
  if (gas.status !== "estimated" || gas.gasLimit !== signed.binding.gasLimit) errors.push("gas changed");
  const nonce = await request.nonceReader.readNonce({ account: signed.binding.callerAccount, chainId: signed.binding.baseChainId });
  if (nonce.status !== "resolved" || nonce.nonce !== signed.binding.nonce) errors.push("nonce changed");
  const fee = await request.feeDataReader.readFeeData({ chainId: signed.binding.baseChainId });
  if (fee.status !== "resolved"
    || fee.maxFeePerGas !== signed.binding.maxFeePerGas
    || fee.maxPriorityFeePerGas !== signed.binding.maxPriorityFeePerGas) {
    errors.push("fee changed");
  }
  if (errors.length > 0) {
    const joined = errors.join(" | ");
    const outcome: BaseAuthorizationExecutionSubmissionOutcome = joined.includes("duplicate")
      ? "duplicate_submission"
      : joined.includes("nullifier")
        ? "nullifier_consumed_before_submission"
        : joined.includes("capability")
          ? "capability_expired"
          : joined.includes("session")
            ? "session_became_ineligible"
            : joined.includes("mirrored")
              ? "mirrored_fact_missing"
              : joined.includes("nonce")
                ? "nonce_changed"
                : joined.includes("fee") || joined.includes("gas")
                  ? "fee_changed"
                  : joined.includes("approval")
                    ? "approval_missing"
                    : joined.includes("mainnet")
                      ? "unsupported"
                      : "malformed";
    const auditEventDraft = createExecutionAuditDraft({
      requestKind: "requestBaseExecutionSubmission",
      outcome,
      summary: "Base execution submission was blocked.",
      signed,
      errors,
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "BASE_EXECUTION_SUBMISSION_BLOCKED",
      category: "unsupported_operation",
      message: "Base execution submission was blocked.",
      recoverable: true,
      details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const result = await request.submitter.submitSignedBaseExecutionTransaction({ signedTransaction: signed });
  if (result.status !== "submitted" || !result.transactionHash) {
    const outcome = result.status === "unavailable" ? "rpc_unavailable" : "execution_transaction_rejected";
    const auditEventDraft = createExecutionAuditDraft({
      requestKind: "requestBaseExecutionSubmission",
      outcome,
      summary: "Base execution submission failed.",
      signed,
      errors: [result.error ?? "submission failed"],
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "BASE_EXECUTION_SUBMISSION_FAILED",
      category: "network_unavailable",
      message: "Base execution submission failed.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  request.submittedTransactionStore?.addTransaction(result.transactionHash);
  const auditEventDraft = createExecutionAuditDraft({
    requestKind: "requestBaseExecutionSubmission",
    outcome: "execution_transaction_submitted",
    summary: "Base authorization execution transaction submitted.",
    signed,
    auditCorrelationId: request.auditCorrelationId
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    status: "execution_transaction_submitted",
    outcome: "execution_transaction_submitted",
    transactionHash: result.transactionHash,
    submittedAt: result.submittedAt ?? nowIso(),
    transactionSubmitted: true,
    transactionConfirmed: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestBaseExecutionSubmission = submitBaseAuthorizationExecutionTransaction;

function hasAuthorizationConsumedEvent(
  receipt: BaseExecutionEthereumReceipt,
  signed: SignedBaseAuthorizationExecutionTransaction
): boolean {
  for (const log of receipt.logs) {
    if (normalizeAddress(log.address) !== normalizeAddress(signed.binding.actionGateAddress)) continue;
    try {
      const parsed = ACTION_GATE_INTERFACE.parseLog({ topics: [...log.topics], data: log.data });
      if (parsed?.name !== "AuthorizationConsumed") continue;
      if (String(parsed.args.nullifier).toLowerCase() !== signed.binding.nullifier.toLowerCase()) continue;
      if (normalizeAddress(parsed.args.consumer) !== normalizeAddress(signed.binding.consumerAddress)) continue;
      return true;
    } catch {
      // Ignore unrelated logs.
    }
  }
  return false;
}

export async function verifyBaseNullifierConsumption(input: {
  readonly signedTransaction: SignedBaseAuthorizationExecutionTransaction;
  readonly nullifierStateReader: BaseNullifierStateReader;
}): Promise<BaseNullifierConsumptionVerificationResult> {
  const read = await input.nullifierStateReader.readNullifierState({
    actionGateAddress: input.signedTransaction.binding.actionGateAddress,
    nullifier: input.signedTransaction.binding.nullifier as `0x${string}`,
    baseChainId: input.signedTransaction.binding.baseChainId
  });
  if (read.status !== "nullifier_consumed" || !read.nullifierConsumed) {
    return runtimeDenied({
      code: "BASE_NULLIFIER_NOT_CONSUMED",
      category: "invalid_authorization_package",
      message: "Base nullifier consumption was not verified.",
      recoverable: true,
      details: { outcome: read.status }
    });
  }
  return runtimeOk(Object.freeze({
    status: "nullifier_consumption_verified",
    outcome: "nullifier_consumed",
    evidence: Object.freeze({
      nullifier: input.signedTransaction.binding.nullifier,
      actionGateAddress: input.signedTransaction.binding.actionGateAddress,
      transactionHash: input.signedTransaction.transactionHashBinding.transactionHash,
      consumed: true,
      checkedAt: read.checkedAt,
      source: "mapping_getter"
    }),
    nullifierConsumed: true,
    otherNullifiersAffected: false
  }));
}

export const requestBaseNullifierConsumptionVerification = verifyBaseNullifierConsumption;

export async function verifyBaseConsumerExecution(
  request: BaseConsumerExecutionVerificationRequest,
  reader: BaseConsumerExecutionReader
): Promise<BaseConsumerExecutionVerificationResult> {
  const evidence = await reader.readConsumerExecution(request);
  if (evidence.status !== "consumer_executed" || evidence.approvedActionMatched !== true) {
    return runtimeDenied({
      code: "BASE_CONSUMER_EXECUTION_NOT_VERIFIED",
      category: "invalid_authorization_package",
      message: "Base consumer execution was not verified.",
      recoverable: true,
      details: { outcome: evidence.status }
    });
  }
  return runtimeOk(Object.freeze({
    status: "consumer_execution_verified",
    outcome: "consumer_executed",
    evidence,
    consumerExecuted: true,
    approvedActionMatched: true
  }));
}

export const requestBaseConsumerExecutionVerification = verifyBaseConsumerExecution;

export async function monitorBaseAuthorizationExecution(
  request: BaseAuthorizationExecutionReceiptMonitoringRequest
): Promise<BaseAuthorizationExecutionReceiptMonitoringResult> {
  const maxAttempts = Math.max(1, request.maxAttempts ?? 1);
  const timeoutMs = Math.max(1, request.timeoutMs ?? 30_000);
  const startedAt = Date.now();
  let lastReceipt: BaseExecutionEthereumReceipt | undefined;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (Date.now() - startedAt > timeoutMs) break;
    lastReceipt = await request.receiptReader.getTransactionReceipt(
      request.signedTransaction.transactionHashBinding.transactionHash
    );
    if (lastReceipt.status === "pending") {
      if (attempt + 1 < maxAttempts && request.pollIntervalMs) {
        await new Promise((resolve) => setTimeout(resolve, request.pollIntervalMs));
      }
      continue;
    }
    if (lastReceipt.status !== "confirmed") {
      return runtimeDenied({
        code: "BASE_EXECUTION_RECEIPT_NOT_CONFIRMED",
        category: "network_unavailable",
        message: "Base execution receipt was not confirmed.",
        recoverable: true,
        details: { outcome: lastReceipt.status === "reverted" ? "execution_transaction_reverted" : "execution_transaction_rejected" }
      });
    }
    if ((lastReceipt.confirmations ?? 0) < (request.minConfirmations ?? 1)) continue;
    if (!hasAuthorizationConsumedEvent(lastReceipt, request.signedTransaction)) {
      return runtimeDenied({
        code: "BASE_EXECUTION_EVENT_INVALID",
        category: "proof_failed",
        message: "Expected ActionGate AuthorizationConsumed event was not found.",
        recoverable: true,
        details: { outcome: "execution_transaction_reverted" }
      });
    }
    const nullifier = await verifyBaseNullifierConsumption({
      signedTransaction: request.signedTransaction,
      nullifierStateReader: request.nullifierStateReader
    });
    if (nullifier.status !== "approved") {
      return runtimeDenied({
        code: "BASE_NULLIFIER_CONSUMPTION_VERIFICATION_FAILED",
        category: "proof_failed",
        message: "Base nullifier consumption verification failed.",
        recoverable: true,
        details: { outcome: nullifier.error?.details?.outcome }
      });
    }
    const consumer = await verifyBaseConsumerExecution({
      signedTransaction: request.signedTransaction,
      receipt: lastReceipt
    }, request.consumerExecutionReader);
    if (consumer.status !== "approved") {
      return runtimeDenied({
        code: "BASE_CONSUMER_EXECUTION_VERIFICATION_FAILED",
        category: "proof_failed",
        message: "Base consumer execution verification failed.",
        recoverable: true,
        details: { outcome: consumer.error?.details?.outcome }
      });
    }
    const auditEventDraft = createExecutionAuditDraft({
      requestKind: "requestBaseExecutionReceiptMonitoring",
      outcome: "execution_transaction_confirmed",
      summary: "Base authorization execution receipt confirmed, nullifier consumed, and consumer execution verified.",
      signed: request.signedTransaction,
      auditCorrelationId: request.auditCorrelationId
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeOk(Object.freeze({
      baseAuthorizationExecutionReceiptId: createAuditCorrelationId([
        request.signedTransaction.transactionHashBinding.transactionHash,
        "base-authorization-execution-receipt"
      ]),
      transactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
      receipt: lastReceipt,
      nullifierEvidence: nullifier.value!.evidence,
      consumerEvidence: consumer.value!.evidence,
      transactionConfirmed: true,
      proofVerifiedByActionGate: true,
      nullifierConsumed: true,
      consumerExecuted: true,
      approvedActionMatched: true,
      auditEventDraft,
      auditDraftCollectionResult
    }));
  }
  return runtimeDenied({
    code: "BASE_EXECUTION_MONITORING_TIMEOUT",
    category: "network_unavailable",
    message: "Base execution monitoring timed out.",
    recoverable: true,
    details: { outcome: "submission_timeout", lastReceiptStatus: lastReceipt?.status }
  });
}

export const requestBaseExecutionReceiptMonitoring = monitorBaseAuthorizationExecution;

export function createFixtureBaseExecutionSigner(input: {
  readonly privateKey: string;
  readonly callerAddress?: string;
  readonly mode?: BaseExecutionCallerMode;
  readonly allowedChainIds?: readonly number[];
}): BaseExecutionSigner {
  const wallet = new Wallet(input.privateKey);
  let available = true;
  const callerAddress = normalizeAddress(input.callerAddress ?? wallet.address);
  return {
    describeSigner() {
      return Object.freeze({
        signerId: createAuditCorrelationId([callerAddress, "fixture-base-execution-signer"]),
        signerKind: "developer_fixture",
        callerAddress,
        mode: input.mode ?? "developer_fixture",
        productionSuitable: false,
        arbitrarySigningSupported: false,
        submissionSupported: false
      });
    },
    checkAvailability() {
      return available ? { available: true } : { available: false, reason: "invalidated" };
    },
    async signBaseExecutionTransaction(request) {
      if (!available) return { status: "failed", transactionHash: request.expectedUnsignedHash, error: "signer unavailable" };
      if (request.transaction.chainId === 8453 || !((input.allowedChainIds ?? [31337, 84532]).includes(request.transaction.chainId))) {
        return { status: "rejected", transactionHash: request.expectedUnsignedHash, error: "chain rejected" };
      }
      if (keccak256(request.transaction.data) !== request.expectedCalldataHash) {
        return { status: "rejected", transactionHash: request.expectedUnsignedHash, error: "calldata hash mismatch" };
      }
      const rawSignedTransaction = await wallet.signTransaction(request.transaction);
      const tx = Transaction.from(rawSignedTransaction);
      if (!tx.hash) return { status: "failed", transactionHash: request.expectedUnsignedHash, error: "hash unavailable" };
      return {
        status: "signed",
        transactionHash: tx.hash,
        rawSignedTransaction,
        signerDescriptor: this.describeSigner()
      };
    },
    invalidateSigningSession() {
      available = false;
    }
  };
}

export function createFixtureBaseExecutionTransactionSubmitter(): BaseExecutionTransactionSubmitter {
  return {
    async submitSignedBaseExecutionTransaction(request) {
      return {
        status: "submitted",
        transactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
        submittedAt: nowIso()
      };
    }
  };
}

export function createUnavailableBaseExecutionTransactionSubmitter(): BaseExecutionTransactionSubmitter {
  return {
    async submitSignedBaseExecutionTransaction() {
      return { status: "unavailable", error: "rpc unavailable" };
    }
  };
}

export function createInMemoryBaseExecutionSubmittedTransactionStore(): BaseExecutionSubmittedTransactionStore {
  const transactions = new Set<string>();
  return {
    hasTransaction(transactionHash) {
      return transactions.has(transactionHash);
    },
    addTransaction(transactionHash) {
      if (transactions.has(transactionHash)) return { status: "duplicate", count: transactions.size };
      transactions.add(transactionHash);
      return { status: "recorded", count: transactions.size };
    },
    clear() {
      transactions.clear();
    }
  };
}

export function createFixtureBaseMirroredFactStateReader(
  status: BaseMirroredFactStateReadResult["status"] = "fact_mirrored"
): BaseMirroredFactStateReader {
  return {
    async readMirroredFactState(request) {
      return {
        status,
        baseMirrorAddress: request.baseMirrorAddress,
        factHigh: request.factHigh,
        factLow: request.factLow,
        proofInputHash: request.proofInputHash,
        checkedAt: nowIso(),
        baseStateMutated: false
      };
    }
  };
}

export function createFixtureBaseExecutionReceiptReader(
  receipt: BaseExecutionEthereumReceipt
): BaseExecutionReceiptReader {
  return {
    async getTransactionReceipt() {
      return receipt;
    }
  };
}

export function createFixtureBaseConsumerExecutionReader(
  evidence: BaseConsumerExecutionEvidence
): BaseConsumerExecutionReader {
  return {
    async readConsumerExecution() {
      return evidence;
    }
  };
}
