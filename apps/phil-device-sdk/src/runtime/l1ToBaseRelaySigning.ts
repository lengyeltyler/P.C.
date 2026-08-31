import { createHash } from "node:crypto";
import { Interface, Transaction, Wallet, getAddress, keccak256 } from "ethers";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import {
  BASE_FACT_MIRROR_METHOD_SELECTOR,
  L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR,
  encodeL1ToBaseFactRelayCalldata,
  requestL1AnchoredFactVerification,
  validateL1ToBaseFactRelayTransactionDraft,
  verifyL1ToBaseRelayDeployment,
  type L1AnchoredFactStateReader,
  type L1ToBaseFactRelayGasEstimateReference,
  type L1ToBaseFactRelayNonceReference,
  type L1ToBaseFactRelayTransactionDraft,
  type L1ToBaseRelayDeploymentReader,
  type L1ToBaseRelayGasEstimator,
  type L1ToBaseRelayNonceReader
} from "./l1ToBaseRelayPreparation.ts";
import type { RuntimeResult } from "./types.ts";

const RELAY_INTERFACE = new Interface([
  "function relayProofInputHashFactToBase(address baseMirror,uint256 factHigh,uint256 factLow)",
  "event ProofInputHashFactRelayedToBase(address indexed baseMirror,uint256 indexed factHigh,uint256 indexed factLow)"
]);
const MIRROR_INTERFACE = new Interface([
  "event ProofInputHashFactMirrored(address indexed messenger,address remoteSender,uint256 indexed factHigh,uint256 indexed factLow)"
]);

export type L1ToBaseRelayerMode =
  | "infrastructure_cross_domain_relayer"
  | "permissionless_external_relayer"
  | "operator_account"
  | "sponsored_relay_service"
  | "developer_fixture"
  | "unsupported";

export interface ApprovedBaseFactMirrorBinding {
  readonly baseChainId: number;
  readonly baseMirrorAddress: string;
  readonly deployedCodeHash?: string;
  readonly abiSha256?: string;
  readonly messengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly deploymentReference: string;
  readonly approvalStatus: "approved" | "draft" | "rejected";
  readonly configurationVersion: string;
  readonly fixtureOnly: boolean;
}

export interface BaseFactMirrorApprovalPolicy {
  readonly allowedBaseChainIds: readonly number[];
  readonly approvedMirrorAddresses: readonly string[];
  readonly approvedMessengerAddresses: readonly string[];
  readonly approvedAuthorizedL1RemoteSenders: readonly string[];
  readonly allowMainnet: false;
  readonly requireLiveDeployment: boolean;
}

export interface BaseFactMirrorTargetValidationResult {
  readonly status: "approved" | "rejected";
  readonly binding: ApprovedBaseFactMirrorBinding;
  readonly errors: readonly string[];
}

export interface L1ToBaseRelayerIdentity {
  readonly relayerId: string;
  readonly mode: L1ToBaseRelayerMode;
  readonly address: string;
  readonly displayName: string;
  readonly approved: boolean;
  readonly productionSuitable: boolean;
}

export interface L1ToBaseRelayerPolicy {
  readonly allowedModes: readonly L1ToBaseRelayerMode[];
  readonly allowedL1ChainIds: readonly number[];
  readonly allowedBaseChainIds: readonly number[];
  readonly allowedRelayContracts: readonly string[];
  readonly allowMainnet: false;
  readonly requireLiveAnchoredFactEvidence: boolean;
  readonly requireApprovedMirrorBinding: boolean;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxGasLimit: string;
  readonly minBalanceWei: string;
  readonly allowedApprovalSources: readonly L1ToBaseRelayApprovalSource[];
}

export type L1ToBaseRelayApprovalSource =
  | "operator_approval"
  | "infrastructure_policy"
  | "testnet_relayer_policy"
  | "developer_fixture_approval";

export interface L1ToBaseRelayFundingStatus {
  readonly status: "sufficient" | "insufficient" | "unknown";
  readonly balanceWei?: string;
  readonly checkedAt: string;
}

export interface L1ToBaseRelayFeeDataReference {
  readonly status: "resolved" | "unresolved" | "unavailable";
  readonly maxFeePerGas?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc" | "none";
}

export interface L1ToBaseRelayFeeDataReader {
  readFeeData(request: L1ToBaseRelaySigningRequest | L1ToBaseRelaySubmissionRequest): Promise<L1ToBaseRelayFeeDataReference>;
}

export interface L1ToBaseRelaySigningPresentation {
  readonly l1NetworkProfileId: string;
  readonly l1ChainId: number;
  readonly baseChainId: number;
  readonly relayer: string;
  readonly l1RelayContract: string;
  readonly l1Messenger: string;
  readonly baseMessenger: string;
  readonly approvedBaseMirror: string;
  readonly authorizedL1RemoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly calldataHash: string;
  readonly baseMirrorCalldataHash: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly value: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly transactionExpiresAt: string;
  readonly auditCorrelationId: string;
}

export interface L1ToBaseRelaySigningPresentationDigest {
  readonly algorithm: "sha256-json-v1";
  readonly digest: string;
  readonly presentation: L1ToBaseRelaySigningPresentation;
}

export interface L1ToBaseRelayApproval {
  readonly approvalId: string;
  readonly source: L1ToBaseRelayApprovalSource;
  readonly presentationDigest: string;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export type L1ToBaseRelayAuthorizationStatus =
  | "relayer_authorized"
  | "relayer_rejected";

export type L1ToBaseRelayAuthorizationOutcome =
  | "relayer_authorized"
  | "relayer_unapproved"
  | "fixture_evidence_rejected"
  | "chain_rejected"
  | "relay_contract_rejected"
  | "mirror_target_rejected"
  | "fee_cap_exceeded"
  | "gas_limit_exceeded"
  | "nonce_unresolved"
  | "funding_insufficient"
  | "approval_missing"
  | "presentation_digest_mismatch"
  | "expired"
  | "malformed";

export interface L1ToBaseRelayerBinding {
  readonly relayDraftId: string;
  readonly l1AnchorTransactionHash: string;
  readonly l1AnchorAddress: string;
  readonly l1RelayContract: string;
  readonly approvedBaseMirror: string;
  readonly l1Messenger: string;
  readonly baseMessenger: string;
  readonly authorizedL1RemoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly value: string;
  readonly l1ChainId: number;
  readonly baseChainId: number;
  readonly calldataHash: string;
  readonly baseMirrorCalldataHash: string;
  readonly auditCorrelationId: string;
}

export interface L1ToBaseRelayAuthorizationRequest {
  readonly draft: L1ToBaseFactRelayTransactionDraft;
  readonly mirrorBinding: ApprovedBaseFactMirrorBinding;
  readonly mirrorPolicy: BaseFactMirrorApprovalPolicy;
  readonly relayerIdentity: L1ToBaseRelayerIdentity;
  readonly policy: L1ToBaseRelayerPolicy;
  readonly approval?: L1ToBaseRelayApproval;
  readonly nonce: L1ToBaseFactRelayNonceReference;
  readonly gas: L1ToBaseFactRelayGasEstimateReference;
  readonly fee: L1ToBaseRelayFeeDataReference;
  readonly fundingStatus: L1ToBaseRelayFundingStatus;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export interface L1ToBaseRelayAuthorizationValue {
  readonly status: L1ToBaseRelayAuthorizationStatus;
  readonly outcome: L1ToBaseRelayAuthorizationOutcome;
  readonly binding: L1ToBaseRelayerBinding;
  readonly errors: readonly string[];
}

export type L1ToBaseRelayAuthorizationResult =
  RuntimeResult<L1ToBaseRelayAuthorizationValue>;

export interface L1ToBaseRelayEip1559Transaction {
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

export interface L1ToBaseRelaySignerDescriptor {
  readonly signerId: string;
  readonly signerKind:
    | "local_encrypted_testnet_key"
    | "external_wallet"
    | "remote_hsm"
    | "cloud_kms"
    | "developer_fixture";
  readonly relayerAddress: string;
  readonly mode: L1ToBaseRelayerMode;
  readonly productionSuitable: boolean;
  readonly arbitrarySigningSupported: false;
  readonly submissionSupported: false;
}

export interface L1ToBaseRelaySigner {
  describeSigner(): L1ToBaseRelaySignerDescriptor;
  checkAvailability(): { readonly available: boolean; readonly reason?: string };
  signL1ToBaseRelayTransaction(request: L1ToBaseRelaySignerRequest): Promise<L1ToBaseRelaySignerResult>;
  invalidateSigningSession(): void;
}

export interface L1ToBaseRelaySignerRequest {
  readonly transaction: L1ToBaseRelayEip1559Transaction;
  readonly expectedUnsignedHash: string;
  readonly presentationDigest: string;
  readonly approvedBaseMirror: string;
}

export interface L1ToBaseRelaySignerResult {
  readonly status: "signed" | "rejected" | "failed";
  readonly transactionHash: string;
  readonly rawSignedTransaction?: string;
  readonly signerDescriptor?: L1ToBaseRelaySignerDescriptor;
  readonly error?: string;
}

export interface L1ToBaseRelaySigningRequest {
  readonly requestId: string;
  readonly draft: L1ToBaseFactRelayTransactionDraft;
  readonly mirrorBinding: ApprovedBaseFactMirrorBinding;
  readonly mirrorPolicy: BaseFactMirrorApprovalPolicy;
  readonly relayerIdentity: L1ToBaseRelayerIdentity;
  readonly policy: L1ToBaseRelayerPolicy;
  readonly approval?: L1ToBaseRelayApproval;
  readonly signer: L1ToBaseRelaySigner;
  readonly anchoredFactStateReader: L1AnchoredFactStateReader;
  readonly deploymentReader: L1ToBaseRelayDeploymentReader;
  readonly gasEstimator: L1ToBaseRelayGasEstimator;
  readonly nonceReader: L1ToBaseRelayNonceReader;
  readonly feeDataReader: L1ToBaseRelayFeeDataReader;
  readonly fundingStatus: L1ToBaseRelayFundingStatus;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type SignedL1ToBaseRelayOutcome =
  | "relay_transaction_signed"
  | L1ToBaseRelayAuthorizationOutcome
  | "fact_not_anchored"
  | "deployment_invalid"
  | "signer_unavailable"
  | "transaction_hash_mismatch"
  | "wrong_signer"
  | "mirror_target_changed";

export type SignedL1ToBaseRelayStatus =
  | "relay_transaction_signed";

export type SignedL1ToBaseRelayLimitation =
  | "signed_but_unsubmitted"
  | "not_application_signing_authority"
  | "anchoring_must_be_revalidated_before_submission"
  | "deployment_must_be_revalidated_before_submission"
  | "nonce_fee_must_be_revalidated_before_submission"
  | "no_base_authorization_execution"
  | "no_nullifier_consumption"
  | "fixture_not_live_submission";

export interface L1ToBaseRelayTransactionHashBinding {
  readonly transactionType: "eip1559";
  readonly transactionHash: string;
  readonly unsignedHash: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly to: string;
  readonly dataHash: string;
}

export interface L1ToBaseRelaySignatureArtifact {
  readonly transactionHash: string;
  readonly rawSignedTransaction: string;
  readonly signerId: string;
  readonly signerAccountAddress: string;
  readonly exactTransactionSigned: true;
  readonly privateKeyExposed: false;
}

export interface SignedL1ToBaseRelayTransaction {
  readonly signedL1ToBaseRelayTransactionId: string;
  readonly status: SignedL1ToBaseRelayStatus;
  readonly outcome: "relay_transaction_signed";
  readonly binding: L1ToBaseRelayerBinding;
  readonly transaction: L1ToBaseRelayEip1559Transaction;
  readonly transactionHashBinding: L1ToBaseRelayTransactionHashBinding;
  readonly signatureArtifact: L1ToBaseRelaySignatureArtifact;
  readonly signerDescriptor: L1ToBaseRelaySignerDescriptor;
  readonly signedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly SignedL1ToBaseRelayLimitation[];
  readonly transactionSigned: true;
  readonly transactionSubmitted: false;
  readonly crossDomainMessageSent: false;
  readonly baseMirrorCalled: false;
  readonly baseFactMirrored: false;
  readonly baseExecutionPrepared: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type SignedL1ToBaseRelayResult =
  RuntimeResult<SignedL1ToBaseRelayTransaction>;

export interface L1ToBaseRelaySubmissionApproval {
  readonly approvalId: string;
  readonly approved: boolean;
  readonly source: L1ToBaseRelayApprovalSource;
  readonly transactionHash: string;
  readonly relayerAccount: string;
  readonly l1ChainId: number;
  readonly baseChainId: number;
  readonly l1RelayContract: string;
  readonly approvedBaseMirror: string;
  readonly calldataHash: string;
  readonly baseMirrorCalldataHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly value: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export type L1ToBaseRelaySubmissionStatus =
  | "submission_blocked"
  | "relay_transaction_submitted"
  | "relay_transaction_pending"
  | "relay_transaction_confirmed"
  | "relay_transaction_reverted"
  | "relay_transaction_rejected";

export type L1ToBaseRelaySubmissionOutcome =
  | "submission_blocked"
  | "relay_transaction_submitted"
  | "relay_transaction_pending"
  | "relay_transaction_confirmed"
  | "relay_transaction_reverted"
  | "relay_transaction_rejected"
  | "fact_not_anchored"
  | "mirror_target_changed"
  | "messenger_configuration_changed"
  | "nonce_changed"
  | "fee_changed"
  | "approval_missing"
  | "duplicate_submission"
  | "rpc_unavailable"
  | "submission_timeout"
  | "malformed"
  | "unsupported";

export interface L1ToBaseRelaySubmissionRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
  readonly submissionApproval?: L1ToBaseRelaySubmissionApproval;
  readonly anchoredFactStateReader: L1AnchoredFactStateReader;
  readonly deploymentReader: L1ToBaseRelayDeploymentReader;
  readonly gasEstimator: L1ToBaseRelayGasEstimator;
  readonly nonceReader: L1ToBaseRelayNonceReader;
  readonly feeDataReader: L1ToBaseRelayFeeDataReader;
  readonly submitter: EthereumRelayTransactionSubmitter;
  readonly submittedTransactionStore?: L1ToBaseRelaySubmittedTransactionStore;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1ToBaseRelaySubmissionValue {
  readonly status: L1ToBaseRelaySubmissionStatus;
  readonly outcome: L1ToBaseRelaySubmissionOutcome;
  readonly transactionHash: string;
  readonly submittedAt?: string;
  readonly transactionSubmitted: boolean;
  readonly l1RelayConfirmed: false;
  readonly crossDomainMessageSent: false;
  readonly crossDomainMessageRelayed: false;
  readonly baseFactMirrored: false;
  readonly baseAuthorizationExecutionPrepared: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1ToBaseRelaySubmissionResult =
  RuntimeResult<L1ToBaseRelaySubmissionValue>;

export interface EthereumRelayTransactionSubmitter {
  submitSignedL1ToBaseRelayTransaction(
    request: EthereumRelayTransactionSubmitRequest
  ): Promise<EthereumRelayTransactionSubmitResult>;
}

export interface EthereumRelayTransactionSubmitRequest {
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
}

export interface EthereumRelayTransactionSubmitResult {
  readonly status: "submitted" | "rejected" | "unavailable";
  readonly transactionHash?: string;
  readonly submittedAt?: string;
  readonly error?: string;
}

export interface L1ToBaseRelayEthereumReceipt {
  readonly transactionHash: string;
  readonly status: "pending" | "confirmed" | "reverted" | "rejected" | "dropped_replaced";
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly gasUsed?: string;
  readonly effectiveGasPrice?: string;
  readonly confirmations?: number;
  readonly logs: readonly L1ToBaseRelayReceiptLog[];
  readonly error?: string;
}

export interface L1ToBaseRelayReceiptLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export interface L1ToBaseRelayReceiptReader {
  getTransactionReceipt(transactionHash: string): Promise<L1ToBaseRelayEthereumReceipt>;
}

export type L1ToBaseCrossDomainMessageStatus =
  | "message_emitted_on_l1"
  | "message_pending"
  | "message_relayed_on_base"
  | "message_failed"
  | "message_state_unknown";

export interface L1ToBaseCrossDomainMessageEvidence {
  readonly status: L1ToBaseCrossDomainMessageStatus;
  readonly l1TransactionHash: string;
  readonly l1RelayContract: string;
  readonly l1Messenger: string;
  readonly baseMessenger: string;
  readonly baseMirror: string;
  readonly calldataHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly authorizedL1RemoteSender: string;
  readonly observedAt: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly messageReference?: string;
}

export interface L1ToBaseCrossDomainMessageMonitor {
  readMessageStatus(
    request: L1ToBaseCrossDomainMessageMonitorRequest
  ): Promise<L1ToBaseCrossDomainMessageEvidence>;
}

export interface L1ToBaseCrossDomainMessageMonitorRequest {
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
  readonly l1Receipt: L1ToBaseRelayEthereumReceipt;
}

export interface BaseFactMirrorStateReader {
  readBaseFactMirrorState(request: BaseFactMirrorVerificationRequest): Promise<BaseFactMirrorVerificationReadResult>;
}

export interface BaseFactMirrorVerificationRequest {
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
  readonly messageEvidence: L1ToBaseCrossDomainMessageEvidence;
}

export interface BaseFactMirrorVerificationReadResult {
  readonly status: "fact_mirrored" | "fact_not_mirrored" | "mirror_unavailable" | "state_unknown";
  readonly baseMirror: string;
  readonly baseMessenger: string;
  readonly authorizedL1RemoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly event?: BaseFactMirroredEvent;
  readonly error?: string;
}

export interface BaseFactMirroredEvent {
  readonly contractAddress: string;
  readonly messenger: string;
  readonly remoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly transactionHash?: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
}

export interface BaseFactMirroredReceipt {
  readonly baseFactMirroredReceiptId: string;
  readonly l1TransactionHash: string;
  readonly baseMirror: string;
  readonly baseMessenger: string;
  readonly authorizedL1RemoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly l1RelayConfirmed: true;
  readonly crossDomainMessageRelayed: true;
  readonly baseFactMirrored: true;
  readonly baseAuthorizationExecutionPrepared: false;
  readonly baseAuthorizationExecutionSubmitted: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly observedAt: string;
}

export interface L1ToBaseRelayMonitoringRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
  readonly receiptReader: L1ToBaseRelayReceiptReader;
  readonly messageMonitor: L1ToBaseCrossDomainMessageMonitor;
  readonly baseMirrorStateReader: BaseFactMirrorStateReader;
  readonly minConfirmations?: number;
  readonly maxAttempts?: number;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1ToBaseRelayDeliveryReceipt {
  readonly relayDeliveryReceiptId: string;
  readonly transactionHash: string;
  readonly l1Receipt: L1ToBaseRelayEthereumReceipt;
  readonly messageEvidence: L1ToBaseCrossDomainMessageEvidence;
  readonly baseMirrorReceipt?: BaseFactMirroredReceipt;
  readonly l1RelayConfirmed: boolean;
  readonly crossDomainMessageRelayed: boolean;
  readonly baseFactMirrored: boolean;
  readonly baseAuthorizationExecutionPrepared: false;
  readonly baseAuthorizationExecutionSubmitted: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1ToBaseRelayMonitoringResult =
  RuntimeResult<L1ToBaseRelayDeliveryReceipt>;

export interface L1ToBaseRelaySubmittedTransactionStore {
  hasTransaction(transactionHash: string): boolean;
  addTransaction(transactionHash: string): { readonly status: "recorded" | "duplicate"; readonly count: number };
  clear(): void;
}

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeHex(value: string): string {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.replace(/^0+/, "") || "0";
  return `0x${normalized.toLowerCase()}`;
}

function normalizeNumberishHex(value: bigint | number | string): string {
  if (typeof value === "string" && value.startsWith("0x")) return normalizeHex(value);
  return `0x${BigInt(value).toString(16)}`;
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

function bindingFromDraft(
  draft: L1ToBaseFactRelayTransactionDraft,
  relayer: string,
  fee: L1ToBaseRelayFeeDataReference
): L1ToBaseRelayerBinding {
  return Object.freeze({
    relayDraftId: draft.l1ToBaseFactRelayTransactionDraftId,
    l1AnchorTransactionHash: draft.binding.l1AnchorTransactionHash,
    l1AnchorAddress: draft.binding.l1AnchorAddress,
    l1RelayContract: draft.binding.l1RelayAddress,
    approvedBaseMirror: draft.binding.baseMirrorAddress,
    l1Messenger: draft.binding.l1MessengerAddress,
    baseMessenger: draft.binding.baseMessengerAddress,
    authorizedL1RemoteSender: draft.binding.authorizedL1RemoteSender,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    proofInputHash: draft.binding.proofInputHash,
    nonce: draft.nonce.nonce ?? "",
    gasLimit: draft.gas.gasLimit ?? "",
    maxFeePerGas: fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas ?? "",
    value: draft.value,
    l1ChainId: draft.binding.l1ChainId,
    baseChainId: draft.binding.baseChainId,
    calldataHash: draft.calldataHash,
    baseMirrorCalldataHash: draft.baseMirrorCallPreview.calldataHash,
    auditCorrelationId: draft.binding.auditCorrelationId
  });
}

function txFromDraft(
  draft: L1ToBaseFactRelayTransactionDraft,
  fee: L1ToBaseRelayFeeDataReference
): L1ToBaseRelayEip1559Transaction | undefined {
  const nonce = Number(bigintFrom(draft.nonce.nonce));
  const gasLimit = bigintFrom(draft.gas.gasLimit);
  const maxFeePerGas = bigintFrom(fee.maxFeePerGas);
  const maxPriorityFeePerGas = bigintFrom(fee.maxPriorityFeePerGas);
  if (!Number.isSafeInteger(nonce) || !gasLimit || !maxFeePerGas || !maxPriorityFeePerGas) {
    return undefined;
  }
  return Object.freeze({
    type: 2 as const,
    chainId: draft.binding.l1ChainId,
    nonce,
    to: normalizeAddress(draft.to),
    value: BigInt(draft.value),
    data: draft.calldata,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas
  });
}

function txHashBinding(
  transaction: L1ToBaseRelayEip1559Transaction,
  rawSignedTransaction?: string
): L1ToBaseRelayTransactionHashBinding {
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

export function validateApprovedBaseFactMirrorTarget(
  binding: ApprovedBaseFactMirrorBinding,
  policy: BaseFactMirrorApprovalPolicy
): BaseFactMirrorTargetValidationResult {
  const errors: string[] = [];
  if (binding.approvalStatus !== "approved") errors.push("mirror not approved");
  if (binding.baseChainId === 8453 || policy.allowMainnet !== false) errors.push("mainnet prohibited");
  if (!policy.allowedBaseChainIds.includes(binding.baseChainId)) errors.push("Base chain rejected");
  if (!policy.approvedMirrorAddresses.map(normalizeAddress).includes(normalizeAddress(binding.baseMirrorAddress))) {
    errors.push("Base mirror rejected");
  }
  if (!policy.approvedMessengerAddresses.map(normalizeAddress).includes(normalizeAddress(binding.messengerAddress))) {
    errors.push("Base messenger rejected");
  }
  if (!policy.approvedAuthorizedL1RemoteSenders.map(normalizeAddress).includes(normalizeAddress(binding.authorizedL1RemoteSender))) {
    errors.push("authorized remote sender rejected");
  }
  if (binding.fixtureOnly && policy.requireLiveDeployment) errors.push("live mirror deployment required");
  return Object.freeze({
    status: errors.length === 0 ? "approved" : "rejected",
    binding,
    errors: Object.freeze(errors)
  });
}

export function createL1ToBaseRelaySigningPresentation(input: {
  readonly draft: L1ToBaseFactRelayTransactionDraft;
  readonly relayer: string;
  readonly fee: L1ToBaseRelayFeeDataReference;
  readonly auditCorrelationId?: string;
}): L1ToBaseRelaySigningPresentationDigest {
  const profileId = input.draft.binding.l1ChainId === 11155111 ? "ethereum_sepolia" : "hardhat";
  const presentation = Object.freeze({
    l1NetworkProfileId: profileId,
    l1ChainId: input.draft.binding.l1ChainId,
    baseChainId: input.draft.binding.baseChainId,
    relayer: normalizeAddress(input.relayer),
    l1RelayContract: normalizeAddress(input.draft.binding.l1RelayAddress),
    l1Messenger: normalizeAddress(input.draft.binding.l1MessengerAddress),
    baseMessenger: normalizeAddress(input.draft.binding.baseMessengerAddress),
    approvedBaseMirror: normalizeAddress(input.draft.binding.baseMirrorAddress),
    authorizedL1RemoteSender: normalizeAddress(input.draft.binding.authorizedL1RemoteSender),
    factHigh: input.draft.binding.factHigh,
    factLow: input.draft.binding.factLow,
    proofInputHash: input.draft.binding.proofInputHash,
    calldataHash: input.draft.calldataHash,
    baseMirrorCalldataHash: input.draft.baseMirrorCallPreview.calldataHash,
    nonce: input.draft.nonce.nonce ?? "",
    gasLimit: input.draft.gas.gasLimit ?? "",
    value: input.draft.value,
    maxFeePerGas: input.fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: input.fee.maxPriorityFeePerGas ?? "",
    transactionExpiresAt: input.draft.expiresAt,
    auditCorrelationId: input.auditCorrelationId ?? input.draft.binding.auditCorrelationId
  });
  return Object.freeze({
    algorithm: "sha256-json-v1" as const,
    digest: sha256Json(presentation),
    presentation
  });
}

export function authorizeL1ToBaseRelay(
  request: L1ToBaseRelayAuthorizationRequest
): L1ToBaseRelayAuthorizationResult {
  const errors: string[] = [];
  errors.push(...validateL1ToBaseFactRelayTransactionDraft(request.draft).errors);
  const mirror = validateApprovedBaseFactMirrorTarget(request.mirrorBinding, request.mirrorPolicy);
  errors.push(...mirror.errors);
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("authorization expired");
  if (!request.relayerIdentity.approved) errors.push("relayer unapproved");
  if (!request.policy.allowedModes.includes(request.relayerIdentity.mode)) errors.push("relayer mode rejected");
  if (!request.policy.allowedL1ChainIds.includes(request.draft.binding.l1ChainId)) errors.push("chain rejected");
  if (!request.policy.allowedBaseChainIds.includes(request.draft.binding.baseChainId)) errors.push("chain rejected");
  if (request.draft.binding.l1ChainId === 1 || request.draft.binding.baseChainId === 8453 || request.policy.allowMainnet !== false) {
    errors.push("mainnet prohibited");
  }
  if (!request.policy.allowedRelayContracts.map(normalizeAddress).includes(normalizeAddress(request.draft.binding.l1RelayAddress))) {
    errors.push("relay contract rejected");
  }
  if (request.policy.requireLiveAnchoredFactEvidence && !request.draft.liveAnchoredFactEvidence) {
    errors.push("live anchored fact evidence required");
  }
  if (request.policy.requireApprovedMirrorBinding && mirror.status !== "approved") errors.push("mirror target rejected");
  if (normalizeAddress(request.draft.binding.baseMirrorAddress) !== normalizeAddress(request.mirrorBinding.baseMirrorAddress)) {
    errors.push("mirror target changed");
  }
  if (request.nonce.status !== "resolved" || request.nonce.nonce !== request.draft.nonce.nonce) errors.push("nonce unresolved");
  if (request.gas.status !== "estimated" || request.gas.gasLimit !== request.draft.gas.gasLimit) errors.push("gas estimate unavailable");
  if (request.fee.status !== "resolved") errors.push("fee unresolved");
  if ((bigintFrom(request.draft.gas.gasLimit) ?? 0n) > BigInt(request.policy.maxGasLimit)) errors.push("gas limit exceeded");
  if ((bigintFrom(request.fee.maxFeePerGas) ?? 0n) > BigInt(request.policy.maxFeePerGas)) errors.push("fee cap exceeded");
  if ((bigintFrom(request.fee.maxPriorityFeePerGas) ?? 0n) > BigInt(request.policy.maxPriorityFeePerGas)) {
    errors.push("priority fee cap exceeded");
  }
  if (request.fundingStatus.status !== "sufficient") errors.push("funding insufficient");
  if ((bigintFrom(request.fundingStatus.balanceWei) ?? 0n) < BigInt(request.policy.minBalanceWei)) errors.push("funding insufficient");
  const presentation = createL1ToBaseRelaySigningPresentation({
    draft: request.draft,
    relayer: request.relayerIdentity.address,
    fee: request.fee,
    auditCorrelationId: request.auditCorrelationId
  });
  if (!request.approval?.approved) errors.push("approval missing");
  if (request.approval && Date.now() > Date.parse(request.approval.expiresAt)) errors.push("approval expired");
  if (request.approval && !request.policy.allowedApprovalSources.includes(request.approval.source)) {
    errors.push("approval source rejected");
  }
  if (request.approval && request.approval.presentationDigest !== presentation.digest) {
    errors.push("presentation digest mismatch");
  }
  const joined = errors.join(" | ");
  const outcome: L1ToBaseRelayAuthorizationOutcome = errors.length === 0
    ? "relayer_authorized"
    : joined.includes("relayer unapproved")
      ? "relayer_unapproved"
      : joined.includes("live anchored")
        ? "fixture_evidence_rejected"
        : joined.includes("chain") || joined.includes("mainnet")
          ? "chain_rejected"
          : joined.includes("relay contract")
            ? "relay_contract_rejected"
            : joined.includes("mirror") || joined.includes("target")
              ? "mirror_target_rejected"
              : joined.includes("fee")
                ? "fee_cap_exceeded"
                : joined.includes("gas")
                  ? "gas_limit_exceeded"
                  : joined.includes("nonce")
                    ? "nonce_unresolved"
                    : joined.includes("funding")
                      ? "funding_insufficient"
                      : joined.includes("approval") && !joined.includes("presentation")
                        ? "approval_missing"
                        : joined.includes("presentation")
                          ? "presentation_digest_mismatch"
                          : joined.includes("expired")
                            ? "expired"
                            : "malformed";
  const value = Object.freeze({
    status: errors.length === 0 ? "relayer_authorized" as const : "relayer_rejected" as const,
    outcome,
    binding: bindingFromDraft(request.draft, request.relayerIdentity.address, request.fee),
    errors: Object.freeze(errors)
  });
  return errors.length === 0
    ? runtimeOk(value)
    : runtimeDenied({
      code: "L1_TO_BASE_RELAY_AUTHORIZATION_REJECTED",
      category: "policy_denied",
      message: "L1-to-Base relay authorization was rejected.",
      recoverable: true,
      details: { outcome, errors }
    });
}

function createRelayAuditDraft(input: {
  readonly requestKind: string;
  readonly outcome: string;
  readonly summary: string;
  readonly draft?: L1ToBaseFactRelayTransactionDraft;
  readonly signed?: SignedL1ToBaseRelayTransaction;
  readonly errors?: readonly string[];
  readonly auditCorrelationId?: string;
}): AuditEventDraft {
  const draftBinding = input.draft?.binding;
  const signedBinding = input.signed?.binding;
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome.includes("signed")
      || input.outcome.includes("submitted")
      || input.outcome.includes("confirmed")
      || input.outcome.includes("mirrored")
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: input.requestKind,
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      relayContract: draftBinding?.l1RelayAddress ?? signedBinding?.l1RelayContract,
      baseMirror: draftBinding?.baseMirrorAddress ?? signedBinding?.approvedBaseMirror,
      proofInputHash: draftBinding?.proofInputHash ?? signedBinding?.proofInputHash,
      factPair: draftBinding
        ? [draftBinding.factHigh, draftBinding.factLow]
        : signedBinding
          ? [signedBinding.factHigh, signedBinding.factLow]
          : undefined,
      calldataHash: input.draft?.calldataHash ?? input.signed?.binding.calldataHash,
      transactionHash: input.signed?.transactionHashBinding.transactionHash
    }
  });
}

export async function signL1ToBaseRelayTransaction(
  request: L1ToBaseRelaySigningRequest
): Promise<SignedL1ToBaseRelayResult> {
  const fact = await requestL1AnchoredFactVerification({
    requestId: `${request.requestId}:anchored-fact`,
    evidence: {
      status: "anchored_fact_evidence_valid",
      source: request.draft.liveAnchoredFactEvidence ? "live_l1_receipt" : "fixture_receipt",
      binding: {
        l1AnchorTransactionHash: request.draft.binding.l1AnchorTransactionHash,
        anchorContract: request.draft.binding.l1AnchorAddress,
        factHigh: request.draft.binding.factHigh,
        factLow: request.draft.binding.factLow,
        proofInputHash: request.draft.binding.proofInputHash,
        starknetMessageHash: request.draft.binding.starknetMessageHash,
        expectedStarknetSender: "0x0",
        ethereumNetworkProfileId: request.draft.binding.l1ChainId === 11155111 ? "ethereum_sepolia" : "hardhat",
        ethereumChainId: request.draft.binding.l1ChainId,
        confirmationCount: 1,
        auditCorrelationId: request.draft.binding.auditCorrelationId
      },
      observedAt: request.issueTime,
      liveAnchoredFactEvidence: request.draft.liveAnchoredFactEvidence,
      productionSignable: request.draft.productionSignable,
      errors: []
    },
    stateReader: request.anchoredFactStateReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    freshnessMs: 60_000,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  });
  if (fact.status !== "approved") {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_FACT_NOT_ANCHORED",
      category: "network_unavailable",
      message: "L1-to-Base relay signing requires anchored fact verification.",
      recoverable: true,
      details: { outcome: "fact_not_anchored" }
    });
  }
  const deployment = await verifyL1ToBaseRelayDeployment({
    requestId: `${request.requestId}:deployment`,
    configuration: {
      configurationId: "signing-derived",
      approvalStatus: "accepted",
      activeProfileId: request.draft.binding.l1ChainId === 11155111 ? "sepolia-base-sepolia" : "hardhat-base-local",
      networkProfiles: {
        [request.draft.binding.l1ChainId === 11155111 ? "sepolia-base-sepolia" : "hardhat-base-local"]: {
          profileId: request.draft.binding.l1ChainId === 11155111 ? "sepolia-base-sepolia" : "hardhat-base-local",
          l1Network: request.draft.binding.l1ChainId === 11155111 ? "ethereum_sepolia" : "hardhat",
          l1ChainId: request.draft.binding.l1ChainId,
          baseNetwork: request.draft.binding.baseChainId === 84532 ? "base_sepolia" : "hardhat",
          baseChainId: request.draft.binding.baseChainId,
          enabled: true
        }
      },
      l1AnchorAddress: request.draft.binding.l1AnchorAddress,
      l1RelayContract: { address: request.draft.binding.l1RelayAddress, approved: true, methodSelector: L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR },
      l1Messenger: { address: request.draft.binding.l1MessengerAddress, interfaceName: "IPhilCrossDomainMessenger", sendMessageSignature: "sendMessage(address,bytes)" },
      baseMessenger: { address: request.draft.binding.baseMessengerAddress, interfaceName: "IBaseCrossDomainMessenger", sendMessageSignature: "sendMessage(address,bytes,uint32)" },
      baseMirror: { address: request.draft.binding.baseMirrorAddress, approved: true, methodSelector: BASE_FACT_MIRROR_METHOD_SELECTOR },
      authorizedL1RemoteSender: { address: request.draft.binding.authorizedL1RemoteSender, expectedOnBaseMirror: true },
      gasPolicy: { minGasLimit: request.draft.remoteGasLimit, maxGasLimit: request.draft.remoteGasLimit },
      feePolicy: { valuePolicy: "nonpayable_zero_value", requiredValueWei: "0", maxValueWei: "0" },
      messageEncodingVersion: "base-mirror-proof-input-hash-v1",
      mainnetAllowed: false
    },
    deploymentReader: request.deploymentReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt
  });
  if (deployment.status !== "approved") {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "L1-to-Base relay deployment revalidation failed.",
      recoverable: true,
      details: { outcome: "deployment_invalid", deployment: deployment.error?.details }
    });
  }
  const gas = await request.gasEstimator.estimateGas({} as never);
  const nonce = await request.nonceReader.readNonce({} as never);
  const fee = await request.feeDataReader.readFeeData(request);
  const authorization = authorizeL1ToBaseRelay({
    draft: request.draft,
    mirrorBinding: request.mirrorBinding,
    mirrorPolicy: request.mirrorPolicy,
    relayerIdentity: request.relayerIdentity,
    policy: request.policy,
    approval: request.approval,
    nonce,
    gas,
    fee,
    fundingStatus: request.fundingStatus,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId
  });
  if (authorization.status !== "approved") {
    const outcome = authorization.error?.details?.outcome as SignedL1ToBaseRelayOutcome;
    const auditEventDraft = createRelayAuditDraft({
      requestKind: "requestL1ToBaseRelaySigning",
      outcome,
      summary: "L1-to-Base relay signing was blocked.",
      draft: request.draft,
      errors: authorization.error?.details?.errors as readonly string[] | undefined,
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_SIGNING_REJECTED",
      category: "policy_denied",
      message: "L1-to-Base relay signing was rejected.",
      recoverable: true,
      details: { outcome, authorization: authorization.error?.details, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const expectedCalldata = encodeL1ToBaseFactRelayCalldata({
    baseMirror: request.mirrorBinding.baseMirrorAddress,
    factHigh: request.draft.binding.factHigh,
    factLow: request.draft.binding.factLow
  });
  if (request.draft.calldata !== expectedCalldata) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_MIRROR_CHANGED",
      category: "invalid_authorization_package",
      message: "Relay calldata does not target the approved Base mirror.",
      recoverable: true,
      details: { outcome: "mirror_target_changed" }
    });
  }
  const tx = txFromDraft(request.draft, fee);
  if (!tx) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_TRANSACTION_MALFORMED",
      category: "invalid_intent",
      message: "Relay draft is missing signable nonce, gas, or fee fields.",
      recoverable: true,
      details: { outcome: "malformed" }
    });
  }
  if (!request.signer.checkAvailability().available) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_SIGNER_UNAVAILABLE",
      category: "adapter_unavailable",
      message: "L1-to-Base relay signer is unavailable.",
      recoverable: true,
      details: { outcome: "signer_unavailable" }
    });
  }
  const unsigned = txHashBinding(tx);
  const presentation = createL1ToBaseRelaySigningPresentation({
    draft: request.draft,
    relayer: request.relayerIdentity.address,
    fee,
    auditCorrelationId: request.auditCorrelationId
  });
  const signed = await request.signer.signL1ToBaseRelayTransaction({
    transaction: tx,
    expectedUnsignedHash: unsigned.unsignedHash,
    presentationDigest: presentation.digest,
    approvedBaseMirror: request.mirrorBinding.baseMirrorAddress
  });
  if (signed.status !== "signed" || !signed.rawSignedTransaction || !signed.signerDescriptor) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_SIGNING_FAILED",
      category: "adapter_unavailable",
      message: "L1-to-Base relay signer did not return a signed artifact.",
      recoverable: true,
      details: { outcome: "signer_unavailable", error: signed.error }
    });
  }
  const hashBinding = txHashBinding(tx, signed.rawSignedTransaction);
  if (hashBinding.transactionHash !== signed.transactionHash) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_HASH_MISMATCH",
      category: "invalid_authorization_package",
      message: "Signed relay transaction hash did not match signer output.",
      recoverable: true,
      details: { outcome: "transaction_hash_mismatch" }
    });
  }
  if (normalizeAddress(signed.signerDescriptor.relayerAddress) !== normalizeAddress(request.relayerIdentity.address)) {
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_WRONG_SIGNER",
      category: "trust_denied",
      message: "L1-to-Base relay signer account does not match approved relayer.",
      recoverable: true,
      details: { outcome: "wrong_signer" }
    });
  }
  const binding = bindingFromDraft(request.draft, request.relayerIdentity.address, fee);
  const auditEventDraft = createRelayAuditDraft({
    requestKind: "requestL1ToBaseRelaySigning",
    outcome: "relay_transaction_signed",
    summary: "Signed but unsubmitted L1-to-Base relay transaction artifact created.",
    draft: request.draft,
    auditCorrelationId: request.auditCorrelationId
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const limitations: SignedL1ToBaseRelayLimitation[] = [
    "signed_but_unsubmitted",
    "not_application_signing_authority",
    "anchoring_must_be_revalidated_before_submission",
    "deployment_must_be_revalidated_before_submission",
    "nonce_fee_must_be_revalidated_before_submission",
    "no_base_authorization_execution",
    "no_nullifier_consumption"
  ];
  if (!request.draft.liveAnchoredFactEvidence) limitations.push("fixture_not_live_submission");
  return runtimeOk(Object.freeze({
    signedL1ToBaseRelayTransactionId: createAuditCorrelationId([
      hashBinding.transactionHash,
      "signed-l1-to-base-relay"
    ]),
    status: "relay_transaction_signed",
    outcome: "relay_transaction_signed",
    binding,
    transaction: tx,
    transactionHashBinding: hashBinding,
    signatureArtifact: Object.freeze({
      transactionHash: hashBinding.transactionHash,
      rawSignedTransaction: signed.rawSignedTransaction,
      signerId: signed.signerDescriptor.signerId,
      signerAccountAddress: signed.signerDescriptor.relayerAddress,
      exactTransactionSigned: true,
      privateKeyExposed: false
    }),
    signerDescriptor: signed.signerDescriptor,
    signedAt: nowIso(),
    expiresAt: request.expiresAt,
    limitations: Object.freeze(limitations),
    transactionSigned: true,
    transactionSubmitted: false,
    crossDomainMessageSent: false,
    baseMirrorCalled: false,
    baseFactMirrored: false,
    baseExecutionPrepared: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1ToBaseRelaySigning = signL1ToBaseRelayTransaction;

export function createL1ToBaseRelaySubmissionApproval(input: {
  readonly signedTransaction: SignedL1ToBaseRelayTransaction;
  readonly source: L1ToBaseRelayApprovalSource;
  readonly approved?: boolean;
  readonly approvedAt?: string;
  readonly expiresAt?: string;
  readonly approvalId?: string;
}): L1ToBaseRelaySubmissionApproval {
  const signed = input.signedTransaction;
  return Object.freeze({
    approvalId: input.approvalId ?? createAuditCorrelationId([
      signed.transactionHashBinding.transactionHash,
      "l1-to-base-relay-submission-approval"
    ]),
    approved: input.approved ?? true,
    source: input.source,
    transactionHash: signed.transactionHashBinding.transactionHash,
    relayerAccount: signed.signatureArtifact.signerAccountAddress,
    l1ChainId: signed.binding.l1ChainId,
    baseChainId: signed.binding.baseChainId,
    l1RelayContract: signed.binding.l1RelayContract,
    approvedBaseMirror: signed.binding.approvedBaseMirror,
    calldataHash: signed.binding.calldataHash,
    baseMirrorCalldataHash: signed.binding.baseMirrorCalldataHash,
    proofInputHash: signed.binding.proofInputHash,
    factHigh: signed.binding.factHigh,
    factLow: signed.binding.factLow,
    nonce: signed.binding.nonce,
    gasLimit: signed.binding.gasLimit,
    value: signed.binding.value,
    maxFeePerGas: signed.binding.maxFeePerGas,
    maxPriorityFeePerGas: signed.binding.maxPriorityFeePerGas,
    approvedAt: input.approvedAt ?? nowIso(),
    expiresAt: input.expiresAt ?? new Date(Date.now() + 300_000).toISOString()
  });
}

function validateSubmissionApproval(
  approval: L1ToBaseRelaySubmissionApproval | undefined,
  signed: SignedL1ToBaseRelayTransaction
): readonly string[] {
  const errors: string[] = [];
  if (!approval) return ["submission approval missing"];
  if (!approval.approved) errors.push("submission approval rejected");
  if (Date.now() > Date.parse(approval.expiresAt)) errors.push("submission approval expired");
  if (approval.transactionHash !== signed.transactionHashBinding.transactionHash) errors.push("transaction hash mismatch");
  if (approval.l1ChainId !== signed.binding.l1ChainId) errors.push("chain mismatch");
  if (approval.baseChainId !== signed.binding.baseChainId) errors.push("chain mismatch");
  if (normalizeAddress(approval.l1RelayContract) !== normalizeAddress(signed.binding.l1RelayContract)) errors.push("relay mismatch");
  if (normalizeAddress(approval.approvedBaseMirror) !== normalizeAddress(signed.binding.approvedBaseMirror)) errors.push("mirror mismatch");
  if (approval.calldataHash !== signed.binding.calldataHash) errors.push("calldata mismatch");
  if (approval.baseMirrorCalldataHash !== signed.binding.baseMirrorCalldataHash) errors.push("mirror calldata mismatch");
  if (approval.nonce !== signed.binding.nonce) errors.push("nonce mismatch");
  if (approval.value !== signed.binding.value) errors.push("value mismatch");
  return errors;
}

export async function submitL1ToBaseRelayTransaction(
  request: L1ToBaseRelaySubmissionRequest
): Promise<L1ToBaseRelaySubmissionResult> {
  const signed = request.signedTransaction;
  const errors: string[] = [];
  if (Date.now() > Date.parse(request.expiresAt) || Date.now() > Date.parse(signed.expiresAt)) errors.push("submission expired");
  if (signed.binding.l1ChainId === 1 || signed.binding.baseChainId === 8453) errors.push("mainnet prohibited");
  if (request.submittedTransactionStore?.hasTransaction(signed.transactionHashBinding.transactionHash)) errors.push("duplicate submission");
  errors.push(...validateSubmissionApproval(request.submissionApproval, signed));
  const fact = await request.anchoredFactStateReader.readAnchoredFact({
    anchorAddress: signed.binding.l1AnchorAddress,
    factHigh: signed.binding.factHigh,
    factLow: signed.binding.factLow
  });
  if (fact.status !== "fact_anchored") errors.push("fact not anchored");
  const gas = await request.gasEstimator.estimateGas({} as never);
  if (gas.status !== "estimated" || gas.gasLimit !== signed.binding.gasLimit) errors.push("gas changed");
  const nonce = await request.nonceReader.readNonce({} as never);
  if (nonce.status !== "resolved" || nonce.nonce !== signed.binding.nonce) errors.push("nonce changed");
  const fee = await request.feeDataReader.readFeeData(request);
  if (fee.status !== "resolved"
    || fee.maxFeePerGas !== signed.binding.maxFeePerGas
    || fee.maxPriorityFeePerGas !== signed.binding.maxPriorityFeePerGas) {
    errors.push("fee changed");
  }
  if (errors.length > 0) {
    const joined = errors.join(" | ");
    const outcome: L1ToBaseRelaySubmissionOutcome = joined.includes("duplicate")
      ? "duplicate_submission"
      : joined.includes("fact")
        ? "fact_not_anchored"
        : joined.includes("nonce")
          ? "nonce_changed"
          : joined.includes("fee") || joined.includes("gas")
            ? "fee_changed"
            : joined.includes("approval")
              ? "approval_missing"
              : joined.includes("mirror")
                ? "mirror_target_changed"
                : joined.includes("mainnet")
                  ? "unsupported"
                  : "malformed";
    const auditEventDraft = createRelayAuditDraft({
      requestKind: "requestL1ToBaseRelaySubmission",
      outcome,
      summary: "L1-to-Base relay submission was blocked.",
      signed,
      errors,
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_SUBMISSION_BLOCKED",
      category: "unsupported_operation",
      message: "L1-to-Base relay submission was blocked.",
      recoverable: true,
      details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const result = await request.submitter.submitSignedL1ToBaseRelayTransaction({ signedTransaction: signed });
  if (result.status !== "submitted" || !result.transactionHash) {
    const outcome = result.status === "unavailable" ? "rpc_unavailable" : "relay_transaction_rejected";
    const auditEventDraft = createRelayAuditDraft({
      requestKind: "requestL1ToBaseRelaySubmission",
      outcome,
      summary: "L1-to-Base relay submission failed.",
      signed,
      errors: [result.error ?? "submission failed"],
      auditCorrelationId: request.auditCorrelationId
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_SUBMISSION_FAILED",
      category: "network_unavailable",
      message: "L1-to-Base relay submission failed.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  request.submittedTransactionStore?.addTransaction(result.transactionHash);
  const auditEventDraft = createRelayAuditDraft({
    requestKind: "requestL1ToBaseRelaySubmission",
    outcome: "relay_transaction_submitted",
    summary: "L1-to-Base relay transaction submitted.",
    signed,
    auditCorrelationId: request.auditCorrelationId
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    status: "relay_transaction_submitted",
    outcome: "relay_transaction_submitted",
    transactionHash: result.transactionHash,
    submittedAt: result.submittedAt ?? nowIso(),
    transactionSubmitted: true,
    l1RelayConfirmed: false,
    crossDomainMessageSent: false,
    crossDomainMessageRelayed: false,
    baseFactMirrored: false,
    baseAuthorizationExecutionPrepared: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1ToBaseRelaySubmission = submitL1ToBaseRelayTransaction;

function parseRelayEvent(
  receipt: L1ToBaseRelayEthereumReceipt,
  signed: SignedL1ToBaseRelayTransaction
): boolean {
  for (const log of receipt.logs) {
    if (normalizeAddress(log.address) !== normalizeAddress(signed.binding.l1RelayContract)) continue;
    try {
      const parsed = RELAY_INTERFACE.parseLog({ topics: [...log.topics], data: log.data });
      if (parsed?.name !== "ProofInputHashFactRelayedToBase") continue;
      if (normalizeAddress(parsed.args.baseMirror) !== normalizeAddress(signed.binding.approvedBaseMirror)) continue;
      if (normalizeNumberishHex(parsed.args.factHigh) !== normalizeHex(signed.binding.factHigh)) continue;
      if (normalizeNumberishHex(parsed.args.factLow) !== normalizeHex(signed.binding.factLow)) continue;
      return true;
    } catch {
      // Ignore unrelated logs.
    }
  }
  return false;
}

export async function verifyBaseFactMirror(
  request: BaseFactMirrorVerificationRequest,
  reader: BaseFactMirrorStateReader
): Promise<RuntimeResult<BaseFactMirroredReceipt>> {
  const read = await reader.readBaseFactMirrorState(request);
  if (read.status !== "fact_mirrored") {
    return runtimeDenied({
      code: "BASE_FACT_NOT_MIRRORED",
      category: "network_unavailable",
      message: "Base fact mirror state does not contain the expected fact.",
      recoverable: true,
      details: { outcome: read.status }
    });
  }
  if (normalizeAddress(read.baseMirror) !== normalizeAddress(request.signedTransaction.binding.approvedBaseMirror)
    || normalizeAddress(read.baseMessenger) !== normalizeAddress(request.signedTransaction.binding.baseMessenger)
    || normalizeAddress(read.authorizedL1RemoteSender) !== normalizeAddress(request.signedTransaction.binding.authorizedL1RemoteSender)
    || normalizeHex(read.factHigh) !== normalizeHex(request.signedTransaction.binding.factHigh)
    || normalizeHex(read.factLow) !== normalizeHex(request.signedTransaction.binding.factLow)) {
    return runtimeDenied({
      code: "BASE_FACT_MIRROR_MISMATCH",
      category: "proof_failed",
      message: "Base mirror state did not match the signed relay binding.",
      recoverable: true,
      details: { outcome: "mirror_mismatch" }
    });
  }
  return runtimeOk(Object.freeze({
    baseFactMirroredReceiptId: createAuditCorrelationId([
      request.signedTransaction.transactionHashBinding.transactionHash,
      "base-fact-mirrored"
    ]),
    l1TransactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
    baseMirror: read.baseMirror,
    baseMessenger: read.baseMessenger,
    authorizedL1RemoteSender: read.authorizedL1RemoteSender,
    factHigh: read.factHigh,
    factLow: read.factLow,
    proofInputHash: request.signedTransaction.binding.proofInputHash,
    l1RelayConfirmed: true,
    crossDomainMessageRelayed: true,
    baseFactMirrored: true,
    baseAuthorizationExecutionPrepared: false,
    baseAuthorizationExecutionSubmitted: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    observedAt: read.checkedAt
  }));
}

export const requestBaseFactMirrorVerification = verifyBaseFactMirror;

export async function monitorL1ToBaseRelay(
  request: L1ToBaseRelayMonitoringRequest
): Promise<L1ToBaseRelayMonitoringResult> {
  const maxAttempts = Math.max(1, request.maxAttempts ?? 1);
  const timeoutMs = Math.max(1, request.timeoutMs ?? 30_000);
  const startedAt = Date.now();
  let lastReceipt: L1ToBaseRelayEthereumReceipt | undefined;
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
        code: "L1_TO_BASE_RELAY_RECEIPT_NOT_CONFIRMED",
        category: "network_unavailable",
        message: "L1-to-Base relay receipt was not confirmed.",
        recoverable: true,
        details: { outcome: lastReceipt.status === "reverted" ? "relay_transaction_reverted" : "relay_transaction_rejected" }
      });
    }
    if ((lastReceipt.confirmations ?? 0) < (request.minConfirmations ?? 1)) continue;
    if (!parseRelayEvent(lastReceipt, request.signedTransaction)) {
      return runtimeDenied({
        code: "L1_TO_BASE_RELAY_EVENT_INVALID",
        category: "proof_failed",
        message: "Expected L1 relay event was not found.",
        recoverable: true,
        details: { outcome: "relay_transaction_reverted" }
      });
    }
    const messageEvidence = await request.messageMonitor.readMessageStatus({
      signedTransaction: request.signedTransaction,
      l1Receipt: lastReceipt
    });
    if (messageEvidence.status !== "message_relayed_on_base") {
      return runtimeDenied({
        code: "L1_TO_BASE_MESSAGE_NOT_DELIVERED",
        category: "network_unavailable",
        message: "Cross-domain relay message has not been delivered to Base.",
        recoverable: true,
        details: { outcome: messageEvidence.status }
      });
    }
    const baseMirror = await verifyBaseFactMirror({
      signedTransaction: request.signedTransaction,
      messageEvidence
    }, request.baseMirrorStateReader);
    if (baseMirror.status !== "approved") {
      return runtimeDenied({
        code: "BASE_FACT_MIRROR_VERIFICATION_FAILED",
        category: "proof_failed",
        message: "Base fact mirror verification failed.",
        recoverable: true,
        details: { outcome: baseMirror.error?.details?.outcome }
      });
    }
    const auditEventDraft = createRelayAuditDraft({
      requestKind: "requestL1ToBaseRelayMonitoring",
      outcome: "base_fact_mirrored",
      summary: "L1-to-Base relay confirmed and Base mirror verified.",
      signed: request.signedTransaction,
      auditCorrelationId: request.auditCorrelationId
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeOk(Object.freeze({
      relayDeliveryReceiptId: createAuditCorrelationId([
        request.signedTransaction.transactionHashBinding.transactionHash,
        "l1-to-base-relay-delivery"
      ]),
      transactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
      l1Receipt: lastReceipt,
      messageEvidence,
      baseMirrorReceipt: baseMirror.value,
      l1RelayConfirmed: true,
      crossDomainMessageRelayed: true,
      baseFactMirrored: true,
      baseAuthorizationExecutionPrepared: false,
      baseAuthorizationExecutionSubmitted: false,
      nullifierConsumed: false,
      consumerExecuted: false,
      auditEventDraft,
      auditDraftCollectionResult
    }));
  }
  return runtimeDenied({
    code: "L1_TO_BASE_RELAY_MONITORING_TIMEOUT",
    category: "network_unavailable",
    message: "L1-to-Base relay monitoring timed out.",
    recoverable: true,
    details: { outcome: "submission_timeout", lastReceiptStatus: lastReceipt?.status }
  });
}

export const requestL1ToBaseRelayMonitoring = monitorL1ToBaseRelay;

export function createFixtureL1ToBaseRelaySigner(input: {
  readonly privateKey: string;
  readonly relayerAddress?: string;
  readonly mode?: L1ToBaseRelayerMode;
  readonly allowedChainIds?: readonly number[];
}): L1ToBaseRelaySigner {
  const wallet = new Wallet(input.privateKey);
  let available = true;
  const relayerAddress = normalizeAddress(input.relayerAddress ?? wallet.address);
  return {
    describeSigner() {
      return Object.freeze({
        signerId: createAuditCorrelationId([relayerAddress, "fixture-l1-to-base-relay-signer"]),
        signerKind: "developer_fixture",
        relayerAddress,
        mode: input.mode ?? "developer_fixture",
        productionSuitable: false,
        arbitrarySigningSupported: false,
        submissionSupported: false
      });
    },
    checkAvailability() {
      return available ? { available: true } : { available: false, reason: "invalidated" };
    },
    async signL1ToBaseRelayTransaction(request) {
      if (!available) return { status: "failed", transactionHash: request.expectedUnsignedHash, error: "signer unavailable" };
      if (request.transaction.chainId === 1 || !((input.allowedChainIds ?? [31337, 11155111]).includes(request.transaction.chainId))) {
        return { status: "rejected", transactionHash: request.expectedUnsignedHash, error: "chain rejected" };
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

export function createFixtureL1ToBaseRelayFeeDataReader(): L1ToBaseRelayFeeDataReader {
  return {
    async readFeeData() {
      return {
        status: "resolved",
        maxFeePerGas: "1000000000",
        maxPriorityFeePerGas: "100000000",
        checkedAt: nowIso(),
        source: "fixture"
      };
    }
  };
}

export function createFixtureEthereumRelayTransactionSubmitter(): EthereumRelayTransactionSubmitter {
  return {
    async submitSignedL1ToBaseRelayTransaction(request) {
      return {
        status: "submitted",
        transactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
        submittedAt: nowIso()
      };
    }
  };
}

export function createUnavailableEthereumRelayTransactionSubmitter(): EthereumRelayTransactionSubmitter {
  return {
    async submitSignedL1ToBaseRelayTransaction() {
      return { status: "unavailable", error: "rpc unavailable" };
    }
  };
}

export function createFixtureL1ToBaseRelayReceiptReader(
  receipt: L1ToBaseRelayEthereumReceipt
): L1ToBaseRelayReceiptReader {
  return {
    async getTransactionReceipt() {
      return receipt;
    }
  };
}

export function createFixtureL1ToBaseMessageMonitor(
  status: L1ToBaseCrossDomainMessageStatus = "message_relayed_on_base"
): L1ToBaseCrossDomainMessageMonitor {
  return {
    async readMessageStatus(request) {
      const signed = request.signedTransaction;
      return {
        status,
        l1TransactionHash: signed.transactionHashBinding.transactionHash,
        l1RelayContract: signed.binding.l1RelayContract,
        l1Messenger: signed.binding.l1Messenger,
        baseMessenger: signed.binding.baseMessenger,
        baseMirror: signed.binding.approvedBaseMirror,
        calldataHash: signed.binding.calldataHash,
        factHigh: signed.binding.factHigh,
        factLow: signed.binding.factLow,
        proofInputHash: signed.binding.proofInputHash,
        authorizedL1RemoteSender: signed.binding.authorizedL1RemoteSender,
        observedAt: nowIso(),
        messageReference: createAuditCorrelationId([
          signed.transactionHashBinding.transactionHash,
          "cross-domain-message"
        ])
      };
    }
  };
}

export function createFixtureBaseFactMirrorStateReader(
  status: BaseFactMirrorVerificationReadResult["status"] = "fact_mirrored"
): BaseFactMirrorStateReader {
  return {
    async readBaseFactMirrorState(request) {
      const signed = request.signedTransaction;
      return {
        status,
        baseMirror: signed.binding.approvedBaseMirror,
        baseMessenger: signed.binding.baseMessenger,
        authorizedL1RemoteSender: signed.binding.authorizedL1RemoteSender,
        factHigh: signed.binding.factHigh,
        factLow: signed.binding.factLow,
        checkedAt: nowIso(),
        blockNumber: 1
      };
    }
  };
}

export function createInMemoryL1ToBaseRelaySubmittedTransactionStore(): L1ToBaseRelaySubmittedTransactionStore {
  const hashes = new Set<string>();
  return {
    hasTransaction(transactionHash) {
      return hashes.has(normalizeHex(transactionHash));
    },
    addTransaction(transactionHash) {
      const normalized = normalizeHex(transactionHash);
      if (hashes.has(normalized)) return { status: "duplicate", count: hashes.size };
      hashes.add(normalized);
      return { status: "recorded", count: hashes.size };
    },
    clear() {
      hashes.clear();
    }
  };
}
