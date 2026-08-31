import { createHash } from "node:crypto";
import {
  Interface,
  Transaction,
  Wallet,
  getAddress,
  keccak256,
  recoverAddress,
  toUtf8Bytes
} from "ethers";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  L1_FACT_ANCHOR_METHOD_SELECTOR,
  encodeL1FactAnchorCalldata,
  requestL1MessageAvailability,
  validateL1FactAnchorTransactionDraft,
  verifyL1FactAnchorDeployment,
  type EthereumL1FeeDataReader,
  type EthereumL1GasEstimator,
  type EthereumL1MessageAvailabilityReader,
  type EthereumL1NonceReader,
  type L1FactAnchorDeploymentReader,
  type L1FactAnchorFeeDataReference,
  type L1FactAnchorGasEstimateReference,
  type L1FactAnchorNonceReference,
  type L1FactAnchorTransactionDraft
} from "./l1FactAnchorPreparation.ts";
import type { RuntimeResult } from "./types.ts";

const ANCHOR_INTERFACE = new Interface([
  "event ProofInputHashFactAnchored(uint256 indexed sourceL2Verifier, uint256 indexed factHigh, uint256 indexed factLow)",
  "function consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow) returns (bytes32)"
]);

export type L1FactAnchorRelayerMode =
  | "infrastructure_relayer"
  | "permissionless_external_relayer"
  | "operator_account"
  | "user_smart_account"
  | "developer_fixture"
  | "unsupported";

export interface L1FactAnchorRelayerModeProfile {
  readonly mode: L1FactAnchorRelayerMode;
  readonly signerOwner: string;
  readonly feePayer: string;
  readonly nonceOwner: string;
  readonly submissionActor: string;
  readonly keyCustody: string;
  readonly censorshipRisk: string;
  readonly frontRunningBehavior: string;
  readonly duplicateCallBehavior: string;
  readonly productionSuitability:
    | "recommended_initial_beta"
    | "candidate"
    | "development_only"
    | "not_recommended"
    | "unsupported";
}

export const L1_FACT_ANCHOR_RELAYER_MODE_PROFILES: readonly L1FactAnchorRelayerModeProfile[] = Object.freeze([
  Object.freeze({
    mode: "infrastructure_relayer",
    signerOwner: "PhilCore proof-publication infrastructure or delegated operator",
    feePayer: "infrastructure operator",
    nonceOwner: "relayer account",
    submissionActor: "Ethereum Adapter / proof-publication infrastructure",
    keyCustody: "external signer, encrypted operator key, HSM, or KMS",
    censorshipRisk: "operator availability and policy risk",
    frontRunningBehavior: "any caller can anchor the same valid message first",
    duplicateCallBehavior: "duplicates should fail once the Starknet message is consumed",
    productionSuitability: "recommended_initial_beta"
  }),
  Object.freeze({
    mode: "permissionless_external_relayer",
    signerOwner: "external relayer",
    feePayer: "external relayer",
    nonceOwner: "external relayer",
    submissionActor: "external relayer",
    keyCustody: "external",
    censorshipRisk: "external availability risk",
    frontRunningBehavior: "permissionless anchoring is acceptable for valid messages",
    duplicateCallBehavior: "duplicates fail after message consumption",
    productionSuitability: "candidate"
  }),
  Object.freeze({
    mode: "operator_account",
    signerOwner: "operator",
    feePayer: "operator",
    nonceOwner: "operator",
    submissionActor: "operator service",
    keyCustody: "operator-managed",
    censorshipRisk: "operator risk",
    frontRunningBehavior: "same valid message may be anchored by another caller",
    duplicateCallBehavior: "duplicates fail after consumption",
    productionSuitability: "candidate"
  }),
  Object.freeze({
    mode: "user_smart_account",
    signerOwner: "user",
    feePayer: "user",
    nonceOwner: "user smart account",
    submissionActor: "future user execution path",
    keyCustody: "user wallet",
    censorshipRisk: "user wallet availability",
    frontRunningBehavior: "another relayer may anchor first",
    duplicateCallBehavior: "duplicates fail after consumption",
    productionSuitability: "not_recommended"
  }),
  Object.freeze({
    mode: "developer_fixture",
    signerOwner: "local fixture",
    feePayer: "fixture",
    nonceOwner: "fixture",
    submissionActor: "tests and diagnostics only",
    keyCustody: "deterministic test key",
    censorshipRisk: "not applicable",
    frontRunningBehavior: "not applicable",
    duplicateCallBehavior: "fixture-only",
    productionSuitability: "development_only"
  }),
  Object.freeze({
    mode: "unsupported",
    signerOwner: "unresolved",
    feePayer: "unresolved",
    nonceOwner: "unresolved",
    submissionActor: "unresolved",
    keyCustody: "unresolved",
    censorshipRisk: "unbounded",
    frontRunningBehavior: "unsupported",
    duplicateCallBehavior: "unsupported",
    productionSuitability: "unsupported"
  })
]);

export interface L1FactAnchorRelayerIdentity {
  readonly relayerId: string;
  readonly mode: L1FactAnchorRelayerMode;
  readonly address: string;
  readonly displayName: string;
  readonly approved: boolean;
  readonly productionSuitable: boolean;
  readonly expectedSignerAddress?: string;
}

export interface L1FactAnchorRelayerBinding {
  readonly draftId: string;
  readonly messageHash: string;
  readonly sourceL2Verifier: string;
  readonly l1Recipient: string;
  readonly ethereumNetworkProfileId: string;
  readonly messagingCoreAddress: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly anchorAddress: string;
  readonly relayerAccount: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly chainId: number;
  readonly calldataHash: string;
  readonly auditCorrelationId: string;
}

export interface L1FactAnchorRelayerPolicy {
  readonly allowedModes: readonly L1FactAnchorRelayerMode[];
  readonly allowedChainIds: readonly number[];
  readonly allowedAnchorAddresses: readonly string[];
  readonly allowMainnet: false;
  readonly requireLiveMessageEvidence: boolean;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxGasLimit: string;
  readonly minBalanceWei: string;
  readonly allowedApprovalSources: readonly L1FactAnchorApprovalSource[];
}

export type L1FactAnchorApprovalSource =
  | "operator_approval"
  | "infrastructure_policy"
  | "testnet_relayer_policy"
  | "developer_fixture_approval";

export interface L1FactAnchorRelayerApproval {
  readonly approvalId: string;
  readonly source: L1FactAnchorApprovalSource;
  readonly presentationDigest: string;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export interface L1FactAnchorRelayerFundingStatus {
  readonly status: "sufficient" | "insufficient" | "unknown";
  readonly balanceWei?: string;
  readonly checkedAt: string;
}

export interface L1FactAnchorRelayerAuthorizationRequest {
  readonly draft: L1FactAnchorTransactionDraft;
  readonly relayerIdentity: L1FactAnchorRelayerIdentity;
  readonly policy: L1FactAnchorRelayerPolicy;
  readonly nonce: L1FactAnchorNonceReference;
  readonly gas: L1FactAnchorGasEstimateReference;
  readonly fee: L1FactAnchorFeeDataReference;
  readonly fundingStatus: L1FactAnchorRelayerFundingStatus;
  readonly approval?: L1FactAnchorRelayerApproval;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export type L1FactAnchorRelayerAuthorizationStatus =
  | "relayer_authorized"
  | "relayer_rejected"
  | "relayer_malformed";

export type L1FactAnchorRelayerAuthorizationOutcome =
  | "relayer_authorized"
  | "relayer_unapproved"
  | "fixture_evidence_rejected"
  | "fixture_relayer_rejected"
  | "chain_rejected"
  | "anchor_rejected"
  | "fee_cap_exceeded"
  | "gas_limit_exceeded"
  | "nonce_unresolved"
  | "funding_insufficient"
  | "approval_missing"
  | "presentation_digest_mismatch"
  | "expired"
  | "malformed"
  | "unsupported";

export interface L1FactAnchorRelayerAuthorizationResultValue {
  readonly status: L1FactAnchorRelayerAuthorizationStatus;
  readonly outcome: L1FactAnchorRelayerAuthorizationOutcome;
  readonly binding: L1FactAnchorRelayerBinding;
  readonly relayerIdentity: L1FactAnchorRelayerIdentity;
  readonly auditCorrelationId: string;
  readonly errors: readonly string[];
}

export type L1FactAnchorRelayerAuthorizationResult =
  RuntimeResult<L1FactAnchorRelayerAuthorizationResultValue>;

export interface L1FactAnchorSigningPresentation {
  readonly ethereumNetworkProfileId: string;
  readonly chainId: number;
  readonly relayer: string;
  readonly anchorContract: string;
  readonly method: "consumeProofInputHashFactFromL2";
  readonly selector: string;
  readonly messageHash: string;
  readonly sourceL2Verifier: string;
  readonly l1Recipient: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly transactionExpiresAt: string;
  readonly auditCorrelationId: string;
}

export interface L1FactAnchorSigningPresentationDigest {
  readonly algorithm: "sha256-json-v1";
  readonly digest: string;
  readonly presentation: L1FactAnchorSigningPresentation;
}

export interface L1FactAnchorTransactionHashBinding {
  readonly transactionType: "eip1559";
  readonly transactionHash: string;
  readonly unsignedHash: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly to: string;
  readonly dataHash: string;
}

export interface L1FactAnchorSignerDescriptor {
  readonly signerId: string;
  readonly signerKind:
    | "local_encrypted_testnet_key"
    | "external_wallet"
    | "remote_hsm"
    | "cloud_kms"
    | "developer_fixture";
  readonly relayerAddress: string;
  readonly mode: L1FactAnchorRelayerMode;
  readonly productionSuitable: boolean;
  readonly arbitrarySigningSupported: false;
  readonly submissionSupported: false;
}

export interface L1FactAnchorSigner {
  describeSigner(): L1FactAnchorSignerDescriptor;
  checkAvailability(): { readonly available: boolean; readonly reason?: string };
  signL1FactAnchorTransaction(
    request: L1FactAnchorSignerRequest
  ): Promise<L1FactAnchorSignerResult>;
  invalidateSigningSession(): void;
}

export interface L1FactAnchorSignerRequest {
  readonly transaction: L1FactAnchorEip1559Transaction;
  readonly expectedTransactionHash: string;
  readonly presentationDigest: string;
}

export interface L1FactAnchorSignerResult {
  readonly status: "signed" | "rejected" | "failed";
  readonly transactionHash: string;
  readonly rawSignedTransaction?: string;
  readonly signerDescriptor?: L1FactAnchorSignerDescriptor;
  readonly error?: string;
}

export interface L1FactAnchorEip1559Transaction {
  readonly type: 2;
  readonly chainId: number;
  readonly nonce: number;
  readonly to: string;
  readonly value: 0n;
  readonly data: string;
  readonly gasLimit: bigint;
  readonly maxFeePerGas: bigint;
  readonly maxPriorityFeePerGas: bigint;
}

export interface L1FactAnchorSigningRequest {
  readonly requestId: string;
  readonly draft: L1FactAnchorTransactionDraft;
  readonly relayerIdentity: L1FactAnchorRelayerIdentity;
  readonly policy: L1FactAnchorRelayerPolicy;
  readonly approval?: L1FactAnchorRelayerApproval;
  readonly signer: L1FactAnchorSigner;
  readonly availabilityReader: EthereumL1MessageAvailabilityReader;
  readonly deploymentReader: L1FactAnchorDeploymentReader;
  readonly gasEstimator: EthereumL1GasEstimator;
  readonly nonceReader: EthereumL1NonceReader;
  readonly feeDataReader: EthereumL1FeeDataReader;
  readonly fundingStatus: L1FactAnchorRelayerFundingStatus;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1FactAnchorSignatureArtifact {
  readonly transactionHash: string;
  readonly rawSignedTransaction: string;
  readonly signerId: string;
  readonly signerAccountAddress: string;
  readonly exactTransactionSigned: true;
  readonly privateKeyExposed: false;
}

export interface SignedL1FactAnchorTransaction {
  readonly signedL1FactAnchorTransactionId: string;
  readonly status: "transaction_signed";
  readonly outcome: "transaction_signed";
  readonly binding: L1FactAnchorRelayerBinding;
  readonly transaction: L1FactAnchorEip1559Transaction;
  readonly transactionHashBinding: L1FactAnchorTransactionHashBinding;
  readonly signatureArtifact: L1FactAnchorSignatureArtifact;
  readonly signerDescriptor: L1FactAnchorSignerDescriptor;
  readonly signedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly SignedL1FactAnchorTransactionLimitation[];
  readonly transactionSigned: true;
  readonly transactionSubmitted: false;
  readonly messageConsumed: false;
  readonly factAnchored: false;
  readonly l1ToBaseRelayPrepared: false;
  readonly baseStateChanged: false;
  readonly nullifierConsumed: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type SignedL1FactAnchorTransactionLimitation =
  | "signed_but_unsubmitted"
  | "not_application_signing_authority"
  | "message_must_be_revalidated_before_submission"
  | "nonce_fee_must_be_revalidated_before_submission"
  | "no_l1_to_base_relay"
  | "no_base_execution"
  | "no_nullifier_consumption"
  | "fixture_not_live_submission";

export type SignedL1FactAnchorTransactionResult =
  RuntimeResult<SignedL1FactAnchorTransaction>;

export interface L1FactAnchorSubmissionApproval {
  readonly approvalId: string;
  readonly approved: boolean;
  readonly source: L1FactAnchorApprovalSource;
  readonly transactionHash: string;
  readonly relayerAccount: string;
  readonly chainId: number;
  readonly anchorAddress: string;
  readonly calldataHash: string;
  readonly messageHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly nonce: string;
  readonly gasLimit: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export interface L1FactAnchorSubmissionApprovalResult {
  readonly status: "approved" | "rejected" | "expired";
  readonly approval?: L1FactAnchorSubmissionApproval;
  readonly errors: readonly string[];
}

export interface L1FactAnchorSubmissionRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedL1FactAnchorTransaction;
  readonly submissionApproval?: L1FactAnchorSubmissionApproval;
  readonly availabilityReader: EthereumL1MessageAvailabilityReader;
  readonly deploymentReader: L1FactAnchorDeploymentReader;
  readonly nonceReader: EthereumL1NonceReader;
  readonly gasEstimator: EthereumL1GasEstimator;
  readonly feeDataReader: EthereumL1FeeDataReader;
  readonly submitter: EthereumTransactionSubmitter;
  readonly submittedTransactionStore?: L1FactAnchorSubmittedTransactionStore;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type L1FactAnchorSubmissionStatus =
  | "submission_blocked"
  | "transaction_submitted"
  | "transaction_pending"
  | "transaction_confirmed"
  | "transaction_reverted"
  | "transaction_rejected";

export type L1FactAnchorSubmissionOutcome =
  | "submission_blocked"
  | "transaction_submitted"
  | "transaction_pending"
  | "transaction_confirmed"
  | "transaction_reverted"
  | "transaction_rejected"
  | "message_already_consumed"
  | "nonce_changed"
  | "fee_changed"
  | "approval_missing"
  | "duplicate_submission"
  | "rpc_unavailable"
  | "submission_timeout"
  | "malformed"
  | "unsupported";

export interface L1FactAnchorSubmissionResultValue {
  readonly status: L1FactAnchorSubmissionStatus;
  readonly outcome: L1FactAnchorSubmissionOutcome;
  readonly transactionHash: string;
  readonly submittedAt?: string;
  readonly transactionSubmitted: boolean;
  readonly transactionConfirmed: false;
  readonly l2ToL1MessageConsumed: false;
  readonly l1FactAnchored: false;
  readonly l1ToBaseRelayPrepared: false;
  readonly l1ToBaseRelaySubmitted: false;
  readonly baseFactMirrored: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1FactAnchorSubmissionResult =
  RuntimeResult<L1FactAnchorSubmissionResultValue>;

export interface EthereumTransactionSubmitter {
  submitSignedL1FactAnchorTransaction(
    request: EthereumTransactionSubmitRequest
  ): Promise<EthereumTransactionSubmitResult>;
}

export interface EthereumTransactionSubmitRequest {
  readonly signedTransaction: SignedL1FactAnchorTransaction;
}

export interface EthereumTransactionSubmitResult {
  readonly status: "submitted" | "rejected" | "unavailable";
  readonly transactionHash?: string;
  readonly submittedAt?: string;
  readonly error?: string;
}

export interface EthereumTransactionReceiptReader {
  getTransactionReceipt(transactionHash: string): Promise<L1FactAnchorEthereumReceipt>;
}

export interface L1FactAnchorEthereumReceipt {
  readonly transactionHash: string;
  readonly status: "pending" | "confirmed" | "reverted" | "rejected" | "dropped_replaced";
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly gasUsed?: string;
  readonly effectiveGasPrice?: string;
  readonly confirmations?: number;
  readonly logs: readonly L1FactAnchorReceiptLog[];
  readonly error?: string;
}

export interface L1FactAnchorReceiptLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

export interface L1FactAnchoredEvent {
  readonly contractAddress: string;
  readonly sourceL2Verifier: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly transactionHash: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
}

export interface L1FactAnchorStateReader {
  readAnchoredFact(
    request: L1FactAnchorStateReadRequest
  ): Promise<L1FactAnchorStateVerificationResult>;
}

export interface L1FactAnchorStateReadRequest {
  readonly anchorAddress: string;
  readonly factHigh: string;
  readonly factLow: string;
}

export interface L1FactAnchorStateVerificationResult {
  readonly status: "anchored" | "not_anchored" | "unknown" | "unavailable";
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly error?: string;
}

export interface L1FactAnchorReceipt {
  readonly l1FactAnchorReceiptId: string;
  readonly transactionHash: string;
  readonly chainId: number;
  readonly anchorAddress: string;
  readonly relayerAccount: string;
  readonly messageHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly event: L1FactAnchoredEvent;
  readonly stateVerification?: L1FactAnchorStateVerificationResult;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly gasUsed?: string;
  readonly effectiveGasPrice?: string;
  readonly confirmations: number;
  readonly observedAt: string;
  readonly transactionConfirmed: true;
  readonly l2ToL1MessageConsumed: true;
  readonly l1FactAnchored: true;
  readonly l1ToBaseRelayPrepared: false;
  readonly l1ToBaseRelaySubmitted: false;
  readonly baseFactMirrored: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1FactAnchorReceiptMonitoringResult =
  RuntimeResult<L1FactAnchorReceipt>;

export interface L1FactAnchorReceiptMonitoringRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedL1FactAnchorTransaction;
  readonly receiptReader: EthereumTransactionReceiptReader;
  readonly stateReader?: L1FactAnchorStateReader;
  readonly minConfirmations?: number;
  readonly maxAttempts?: number;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1FactAnchorSubmittedTransactionStore {
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

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function sha256Json(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value, Object.keys(value as object).sort()))
    .digest("hex");
}

function bigintFrom(value?: string): bigint | undefined {
  if (!value) return undefined;
  return BigInt(value);
}

function txFromDraft(draft: L1FactAnchorTransactionDraft): L1FactAnchorEip1559Transaction | undefined {
  const nonce = Number(bigintFrom(draft.nonce.nonce));
  const gasLimit = bigintFrom(draft.gas.gasLimit);
  const maxFeePerGas = bigintFrom(draft.fee.maxFeePerGas);
  const maxPriorityFeePerGas = bigintFrom(draft.fee.maxPriorityFeePerGas);
  if (!Number.isSafeInteger(nonce) || !gasLimit || !maxFeePerGas || !maxPriorityFeePerGas) {
    return undefined;
  }
  return Object.freeze({
    type: 2 as const,
    chainId: draft.binding.ethereumChainId,
    nonce,
    to: normalizeAddress(draft.to),
    value: 0n,
    data: draft.calldata,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas
  });
}

function transactionHashBinding(
  transaction: L1FactAnchorEip1559Transaction,
  rawSignedTransaction?: string
): L1FactAnchorTransactionHashBinding {
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

export function createL1FactAnchorSigningPresentation(
  input: {
    readonly draft: L1FactAnchorTransactionDraft;
    readonly relayer: string;
    readonly auditCorrelationId?: string;
  }
): L1FactAnchorSigningPresentationDigest {
  const presentation: L1FactAnchorSigningPresentation = Object.freeze({
    ethereumNetworkProfileId: input.draft.binding.ethereumNetworkProfileId,
    chainId: input.draft.binding.ethereumChainId,
    relayer: normalizeAddress(input.relayer),
    anchorContract: input.draft.binding.anchorAddress,
    method: "consumeProofInputHashFactFromL2",
    selector: input.draft.methodSelector,
    messageHash: input.draft.binding.messageHash,
    sourceL2Verifier: input.draft.binding.sourceL2Verifier,
    l1Recipient: input.draft.binding.l1Recipient,
    factHigh: input.draft.binding.factHigh,
    factLow: input.draft.binding.factLow,
    proofInputHash: input.draft.binding.proofInputHash,
    nonce: input.draft.nonce.nonce ?? "",
    gasLimit: input.draft.gas.gasLimit ?? "",
    maxFeePerGas: input.draft.fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: input.draft.fee.maxPriorityFeePerGas ?? "",
    transactionExpiresAt: input.draft.expiresAt,
    auditCorrelationId: input.auditCorrelationId ?? input.draft.binding.auditCorrelationId
  });
  return Object.freeze({
    algorithm: "sha256-json-v1",
    digest: sha256Json(presentation),
    presentation
  });
}

function bindingFromDraft(
  draft: L1FactAnchorTransactionDraft,
  relayer: string
): L1FactAnchorRelayerBinding {
  return Object.freeze({
    draftId: draft.l1FactAnchorTransactionDraftId,
    messageHash: draft.binding.messageHash,
    sourceL2Verifier: draft.binding.sourceL2Verifier,
    l1Recipient: draft.binding.l1Recipient,
    ethereumNetworkProfileId: draft.binding.ethereumNetworkProfileId,
    messagingCoreAddress: draft.binding.messagingCoreAddress,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    proofInputHash: draft.binding.proofInputHash,
    anchorAddress: draft.binding.anchorAddress,
    relayerAccount: normalizeAddress(relayer),
    nonce: draft.nonce.nonce ?? "",
    gasLimit: draft.gas.gasLimit ?? "",
    maxFeePerGas: draft.fee.maxFeePerGas ?? "",
    maxPriorityFeePerGas: draft.fee.maxPriorityFeePerGas ?? "",
    chainId: draft.binding.ethereumChainId,
    calldataHash: draft.calldataHash,
    auditCorrelationId: draft.binding.auditCorrelationId
  });
}

export function authorizeL1FactAnchorRelayer(
  request: L1FactAnchorRelayerAuthorizationRequest
): L1FactAnchorRelayerAuthorizationResult {
  const errors: string[] = [];
  const draftValidation = validateL1FactAnchorTransactionDraft(request.draft);
  errors.push(...draftValidation.errors);
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("authorization expired");
  if (!request.relayerIdentity.approved) errors.push("relayer unapproved");
  if (!request.policy.allowedModes.includes(request.relayerIdentity.mode)) errors.push("relayer mode rejected");
  if (!request.policy.allowedChainIds.includes(request.draft.binding.ethereumChainId)) errors.push("chain rejected");
  if (request.draft.binding.ethereumChainId === 1 || request.policy.allowMainnet !== false) errors.push("mainnet prohibited");
  if (!request.policy.allowedAnchorAddresses.map(normalizeAddress).includes(normalizeAddress(request.draft.binding.anchorAddress))) {
    errors.push("anchor rejected");
  }
  if (request.policy.requireLiveMessageEvidence && !request.draft.liveMessageEvidence) {
    errors.push("live message evidence required");
  }
  if (request.relayerIdentity.mode === "developer_fixture" && request.draft.liveMessageEvidence) {
    errors.push("fixture relayer rejected for live evidence");
  }
  if (request.nonce.status !== "resolved" || request.nonce.nonce !== request.draft.nonce.nonce) errors.push("nonce unresolved");
  if (request.gas.status !== "estimated" || request.gas.gasLimit !== request.draft.gas.gasLimit) errors.push("gas estimate unavailable");
  if (request.fee.status !== "resolved") errors.push("fee unresolved");
  if ((bigintFrom(request.draft.gas.gasLimit) ?? 0n) > BigInt(request.policy.maxGasLimit)) errors.push("gas limit exceeded");
  if ((bigintFrom(request.draft.fee.maxFeePerGas) ?? 0n) > BigInt(request.policy.maxFeePerGas)) errors.push("fee cap exceeded");
  if ((bigintFrom(request.draft.fee.maxPriorityFeePerGas) ?? 0n) > BigInt(request.policy.maxPriorityFeePerGas)) {
    errors.push("priority fee cap exceeded");
  }
  if (request.fundingStatus.status !== "sufficient") errors.push("funding insufficient");
  if ((bigintFrom(request.fundingStatus.balanceWei) ?? 0n) < BigInt(request.policy.minBalanceWei)) errors.push("funding insufficient");
  const presentation = createL1FactAnchorSigningPresentation({
    draft: request.draft,
    relayer: request.relayerIdentity.address,
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
  const outcome = errors.length === 0
    ? "relayer_authorized"
    : errors.join(" | ").includes("relayer unapproved")
      ? "relayer_unapproved"
    : errors.join(" | ").includes("live message")
      ? "fixture_evidence_rejected"
      : errors.join(" | ").includes("fixture relayer")
        ? "fixture_relayer_rejected"
        : errors.join(" | ").includes("chain") || errors.join(" | ").includes("mainnet")
          ? "chain_rejected"
          : errors.join(" | ").includes("anchor")
            ? "anchor_rejected"
            : errors.join(" | ").includes("fee")
              ? "fee_cap_exceeded"
              : errors.join(" | ").includes("gas")
                ? "gas_limit_exceeded"
                : errors.join(" | ").includes("nonce")
                  ? "nonce_unresolved"
                  : errors.join(" | ").includes("funding")
                    ? "funding_insufficient"
                    : errors.join(" | ").includes("approval") && !errors.join(" | ").includes("presentation")
                      ? "approval_missing"
                      : errors.join(" | ").includes("presentation")
                        ? "presentation_digest_mismatch"
                        : errors.join(" | ").includes("expired")
                          ? "expired"
                          : "malformed";
  const value = Object.freeze({
    status: errors.length === 0 ? "relayer_authorized" as const : "relayer_rejected" as const,
    outcome,
    binding: bindingFromDraft(request.draft, request.relayerIdentity.address),
    relayerIdentity: request.relayerIdentity,
    auditCorrelationId: request.auditCorrelationId ?? request.draft.binding.auditCorrelationId,
    errors: Object.freeze(errors)
  });
  return errors.length === 0
    ? runtimeOk(value)
    : runtimeDenied({
      code: "L1_FACT_ANCHOR_RELAYER_REJECTED",
      category: "policy_denied",
      message: "L1 fact-anchor relayer authorization was rejected.",
      recoverable: true,
      details: { outcome, errors }
    });
}

function createSigningAuditDraft(input: {
  readonly request: L1FactAnchorSigningRequest;
  readonly outcome: SignedL1FactAnchorTransactionOutcome;
  readonly transactionHash?: string;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "transaction_signed" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1FactAnchorTransactionSigning",
    summary: input.outcome === "transaction_signed"
      ? "Signed but unsubmitted Ethereum L1 fact-anchor transaction artifact created."
      : "Ethereum L1 fact-anchor signing was blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.transactionHash,
      relayer: input.request.relayerIdentity.address,
      anchorAddress: input.request.draft.binding.anchorAddress,
      messageHash: input.request.draft.binding.messageHash,
      proofInputHash: input.request.draft.binding.proofInputHash,
      factPair: [input.request.draft.binding.factHigh, input.request.draft.binding.factLow],
      nonce: input.request.draft.nonce.nonce,
      gasLimit: input.request.draft.gas.gasLimit
    }
  });
}

export type SignedL1FactAnchorTransactionOutcome =
  | "transaction_signed"
  | L1FactAnchorRelayerAuthorizationOutcome
  | "message_unavailable"
  | "deployment_invalid"
  | "signer_unavailable"
  | "transaction_mutation_detected"
  | "transaction_hash_mismatch"
  | "wrong_signer"
  | "malformed_signature";

export async function signL1FactAnchorTransaction(
  request: L1FactAnchorSigningRequest
): Promise<SignedL1FactAnchorTransactionResult> {
  const availability = await requestL1MessageAvailability({
    requestId: `${request.requestId}:availability`,
    messageIdentity: {
      status: "message_identity_valid",
      source: {
        evidenceClass: request.draft.liveMessageEvidence ? "live_starknet_receipt" : "fixture_receipt",
        starknetNetworkProfileId: request.draft.binding.ethereumNetworkProfileId,
        starknetTransactionHash: request.draft.binding.starknetTransactionHash,
        publicationEventObserved: true
      },
      binding: {
        l2Sender: request.draft.binding.sourceL2Verifier,
        l1Recipient: request.draft.binding.l1Recipient,
        payload: {
          payloadLength: 2,
          factHigh: request.draft.binding.factHigh,
          factLow: request.draft.binding.factLow
        },
        proofInputHash: request.draft.binding.proofInputHash,
        messageHash: {
          algorithm: "starknet-l2-to-l1-keccak-abi-packed-v1",
          value: request.draft.binding.messageHash
        },
        auditCorrelationId: request.draft.binding.auditCorrelationId
      },
      liveMessageEvidence: request.draft.liveMessageEvidence,
      productionSignable: request.draft.productionSignable,
      errors: []
    },
    ethereumNetworkProfileId: request.draft.binding.ethereumNetworkProfileId,
    ethereumChainId: request.draft.binding.ethereumChainId,
    messagingCoreAddress: request.draft.binding.messagingCoreAddress,
    anchorAddress: request.draft.binding.anchorAddress,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    freshnessMs: 60_000,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  }, request.availabilityReader);
  if (availability.status !== "approved") {
    const auditEventDraft = createSigningAuditDraft({ request, outcome: "message_unavailable" });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_MESSAGE_UNAVAILABLE",
      category: "network_unavailable",
      message: "L1 anchor signing requires available message evidence.",
      recoverable: true,
      details: { outcome: "message_unavailable" }
    });
  }
  const deployment = await verifyL1FactAnchorDeployment({
    requestId: `${request.requestId}:deployment`,
    configuration: {
      configurationId: "signing-derived",
      approvalStatus: "accepted",
      activeProfileId: request.draft.binding.ethereumNetworkProfileId,
      networkProfiles: {
        [request.draft.binding.ethereumNetworkProfileId]: {
          profileId: request.draft.binding.ethereumNetworkProfileId,
          ethereumNetwork: request.draft.binding.ethereumChainId === 11155111 ? "ethereum_sepolia" : "hardhat",
          ethereumChainId: request.draft.binding.ethereumChainId,
          enabled: true
        }
      },
      anchorDeployment: {
        address: request.draft.binding.anchorAddress,
        approved: true,
        methodSelector: request.draft.methodSelector
      },
      messagingCore: {
        address: request.draft.binding.messagingCoreAddress,
        exposesReadOnlyMessageCount: true,
        consumeMethodSignature: "consumeMessageFromL2(uint256,uint256[])"
      },
      expectedStarknetSender: {
        starknetNetworkProfileId: request.draft.binding.ethereumNetworkProfileId,
        sourceL2Verifier: request.draft.binding.sourceL2Verifier,
        l1Recipient: request.draft.binding.l1Recipient,
        payloadShape: "[fact_high,fact_low]"
      },
      mainnetAllowed: false
    },
    deploymentReader: request.deploymentReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt
  });
  if (deployment.status !== "approved") {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "L1 anchor deployment revalidation failed.",
      recoverable: true,
      details: { outcome: "deployment_invalid" }
    });
  }
  const gas = await request.gasEstimator.estimateGas({} as never);
  const nonce = await request.nonceReader.readNonce({} as never);
  const fee = await request.feeDataReader.readFeeData({} as never);
  const authorization = authorizeL1FactAnchorRelayer({
    draft: request.draft,
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
    const authorizationError = authorization.error;
    const outcome = authorizationError?.details?.outcome as SignedL1FactAnchorTransactionOutcome;
    const auditEventDraft = createSigningAuditDraft({
      request,
      outcome,
      errors: authorizationError?.details?.errors as readonly string[] | undefined
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_SIGNING_REJECTED",
      category: "policy_denied",
      message: "L1 fact-anchor signing was rejected.",
      recoverable: true,
      details: { outcome, authorization: authorizationError?.details, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const transaction = txFromDraft(request.draft);
  if (!transaction) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_TRANSACTION_MALFORMED",
      category: "invalid_intent",
      message: "L1 fact-anchor transaction draft is missing signable gas, fee, or nonce fields.",
      recoverable: true,
      details: { outcome: "malformed" }
    });
  }
  const presentation = createL1FactAnchorSigningPresentation({
    draft: request.draft,
    relayer: request.relayerIdentity.address,
    auditCorrelationId: request.auditCorrelationId
  });
  if (!request.signer.checkAvailability().available) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_SIGNER_UNAVAILABLE",
      category: "adapter_unavailable",
      message: "L1 fact-anchor signer is unavailable.",
      recoverable: true,
      details: { outcome: "signer_unavailable" }
    });
  }
  const unsignedBinding = transactionHashBinding(transaction);
  const signed = await request.signer.signL1FactAnchorTransaction({
    transaction,
    expectedTransactionHash: unsignedBinding.unsignedHash,
    presentationDigest: presentation.digest
  });
  if (signed.status !== "signed" || !signed.rawSignedTransaction || !signed.signerDescriptor) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_SIGNING_FAILED",
      category: "adapter_unavailable",
      message: "L1 fact-anchor signer did not return a signed artifact.",
      recoverable: true,
      details: { outcome: "signer_unavailable", error: signed.error }
    });
  }
  const hashBinding = transactionHashBinding(transaction, signed.rawSignedTransaction);
  if (hashBinding.transactionHash !== signed.transactionHash) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_HASH_MISMATCH",
      category: "invalid_authorization_package",
      message: "Signed L1 fact-anchor transaction hash did not match signer output.",
      recoverable: true,
      details: { outcome: "transaction_hash_mismatch" }
    });
  }
  if (normalizeAddress(signed.signerDescriptor.relayerAddress) !== normalizeAddress(request.relayerIdentity.address)) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_WRONG_SIGNER",
      category: "trust_denied",
      message: "L1 fact-anchor signer account does not match approved relayer.",
      recoverable: true,
      details: { outcome: "wrong_signer" }
    });
  }
  const auditEventDraft = createSigningAuditDraft({
    request,
    outcome: "transaction_signed",
    transactionHash: hashBinding.transactionHash
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const limitations: SignedL1FactAnchorTransactionLimitation[] = [
    "signed_but_unsubmitted",
    "not_application_signing_authority",
    "message_must_be_revalidated_before_submission",
    "nonce_fee_must_be_revalidated_before_submission",
    "no_l1_to_base_relay",
    "no_base_execution",
    "no_nullifier_consumption"
  ];
  if (!request.draft.liveMessageEvidence) limitations.push("fixture_not_live_submission");
  return runtimeOk(Object.freeze({
    signedL1FactAnchorTransactionId: createAuditCorrelationId([
      hashBinding.transactionHash,
      "signed-l1-fact-anchor"
    ]),
    status: "transaction_signed",
    outcome: "transaction_signed",
    binding: bindingFromDraft(request.draft, request.relayerIdentity.address),
    transaction,
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
    messageConsumed: false,
    factAnchored: false,
    l1ToBaseRelayPrepared: false,
    baseStateChanged: false,
    nullifierConsumed: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1FactAnchorTransactionSigning = signL1FactAnchorTransaction;

export function createL1FactAnchorSubmissionApproval(
  input: {
    readonly signedTransaction: SignedL1FactAnchorTransaction;
    readonly source: L1FactAnchorApprovalSource;
    readonly approved?: boolean;
    readonly approvedAt?: string;
    readonly expiresAt?: string;
    readonly approvalId?: string;
  }
): L1FactAnchorSubmissionApproval {
  const tx = input.signedTransaction;
  return Object.freeze({
    approvalId: input.approvalId ?? createAuditCorrelationId([
      tx.transactionHashBinding.transactionHash,
      "l1-anchor-submission-approval"
    ]),
    approved: input.approved ?? true,
    source: input.source,
    transactionHash: tx.transactionHashBinding.transactionHash,
    relayerAccount: tx.binding.relayerAccount,
    chainId: tx.binding.chainId,
    anchorAddress: tx.binding.anchorAddress,
    calldataHash: tx.binding.calldataHash,
    messageHash: tx.binding.messageHash,
    proofInputHash: tx.binding.proofInputHash,
    factHigh: tx.binding.factHigh,
    factLow: tx.binding.factLow,
    nonce: tx.binding.nonce,
    gasLimit: tx.binding.gasLimit,
    maxFeePerGas: tx.binding.maxFeePerGas,
    maxPriorityFeePerGas: tx.binding.maxPriorityFeePerGas,
    approvedAt: input.approvedAt ?? nowIso(),
    expiresAt: input.expiresAt ?? new Date(Date.now() + 300_000).toISOString()
  });
}

export function validateL1FactAnchorSubmissionApproval(
  approval: L1FactAnchorSubmissionApproval | undefined,
  signed: SignedL1FactAnchorTransaction
): L1FactAnchorSubmissionApprovalResult {
  const errors: string[] = [];
  if (!approval) return { status: "rejected", errors: ["submission approval missing"] };
  if (!approval.approved) errors.push("submission approval rejected");
  if (Date.now() > Date.parse(approval.expiresAt)) errors.push("submission approval expired");
  if (approval.transactionHash !== signed.transactionHashBinding.transactionHash) errors.push("transaction hash mismatch");
  if (normalizeAddress(approval.relayerAccount) !== normalizeAddress(signed.binding.relayerAccount)) errors.push("relayer mismatch");
  if (approval.chainId !== signed.binding.chainId) errors.push("chain mismatch");
  if (normalizeAddress(approval.anchorAddress) !== normalizeAddress(signed.binding.anchorAddress)) errors.push("anchor mismatch");
  if (approval.calldataHash !== signed.binding.calldataHash) errors.push("calldata mismatch");
  if (approval.messageHash !== signed.binding.messageHash) errors.push("message hash mismatch");
  if (approval.nonce !== signed.binding.nonce) errors.push("nonce mismatch");
  return {
    status: errors.length === 0 ? "approved" : "rejected",
    approval: errors.length === 0 ? approval : undefined,
    errors
  };
}

function createSubmissionAuditDraft(input: {
  readonly request: L1FactAnchorSubmissionRequest;
  readonly outcome: L1FactAnchorSubmissionOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "transaction_submitted" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1FactAnchorSubmission",
    summary: input.outcome === "transaction_submitted"
      ? "Ethereum L1 fact-anchor transaction submitted."
      : "Ethereum L1 fact-anchor submission was blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.request.signedTransaction.transactionHashBinding.transactionHash,
      anchorAddress: input.request.signedTransaction.binding.anchorAddress,
      messageHash: input.request.signedTransaction.binding.messageHash,
      proofInputHash: input.request.signedTransaction.binding.proofInputHash,
      factPair: [
        input.request.signedTransaction.binding.factHigh,
        input.request.signedTransaction.binding.factLow
      ]
    }
  });
}

export async function submitL1FactAnchorTransaction(
  request: L1FactAnchorSubmissionRequest
): Promise<L1FactAnchorSubmissionResult> {
  const errors: string[] = [];
  const signed = request.signedTransaction;
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("submission request expired");
  if (Date.now() > Date.parse(signed.expiresAt)) errors.push("signed artifact expired");
  if (signed.binding.chainId === 1) errors.push("mainnet prohibited");
  if (request.submittedTransactionStore?.hasTransaction(signed.transactionHashBinding.transactionHash)) {
    errors.push("duplicate submission");
  }
  const availability = await requestL1MessageAvailability({
    requestId: `${request.requestId}:availability`,
    messageIdentity: {
      status: "message_identity_valid",
      source: {
        evidenceClass: signed.limitations.includes("fixture_not_live_submission")
          ? "fixture_receipt"
          : "live_starknet_receipt",
        starknetNetworkProfileId: signed.binding.chainId === 11155111 ? "starknet_sepolia" : "local_devnet",
        starknetTransactionHash: "0x0",
        publicationEventObserved: true
      },
      binding: {
        l2Sender: signed.binding.sourceL2Verifier,
        l1Recipient: signed.binding.l1Recipient,
        payload: {
          payloadLength: 2,
          factHigh: signed.binding.factHigh,
          factLow: signed.binding.factLow
        },
        proofInputHash: signed.binding.proofInputHash,
        messageHash: {
          algorithm: "starknet-l2-to-l1-keccak-abi-packed-v1",
          value: signed.binding.messageHash
        },
        auditCorrelationId: signed.binding.auditCorrelationId
      },
      liveMessageEvidence: !signed.limitations.includes("fixture_not_live_submission"),
      productionSignable: !signed.limitations.includes("fixture_not_live_submission"),
      errors: []
    },
    ethereumNetworkProfileId: signed.binding.ethereumNetworkProfileId,
    ethereumChainId: signed.binding.chainId,
    messagingCoreAddress: signed.binding.messagingCoreAddress,
    anchorAddress: signed.binding.anchorAddress,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    freshnessMs: 60_000,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  }, request.availabilityReader);
  if (availability.status !== "approved") {
    const outcome = availability.error?.details?.outcome === "message_already_consumed"
      ? "message_already_consumed"
      : "submission_blocked";
    errors.push(outcome);
  }
  const deployment = await verifyL1FactAnchorDeployment({
    requestId: `${request.requestId}:deployment`,
    configuration: {
      configurationId: "submission-derived",
      approvalStatus: "accepted",
      activeProfileId: signed.binding.ethereumNetworkProfileId,
      networkProfiles: {
        [signed.binding.ethereumNetworkProfileId]: {
          profileId: signed.binding.ethereumNetworkProfileId,
          ethereumNetwork: signed.binding.chainId === 11155111 ? "ethereum_sepolia" : "hardhat",
          ethereumChainId: signed.binding.chainId,
          enabled: true
        }
      },
      anchorDeployment: {
        address: signed.binding.anchorAddress,
        approved: true,
        methodSelector: L1_FACT_ANCHOR_METHOD_SELECTOR
      },
      messagingCore: {
        address: signed.binding.messagingCoreAddress,
        exposesReadOnlyMessageCount: true,
        consumeMethodSignature: "consumeMessageFromL2(uint256,uint256[])"
      },
      expectedStarknetSender: {
        starknetNetworkProfileId: "local_devnet",
        sourceL2Verifier: signed.binding.sourceL2Verifier,
        l1Recipient: signed.binding.l1Recipient,
        payloadShape: "[fact_high,fact_low]"
      },
      mainnetAllowed: false
    },
    deploymentReader: request.deploymentReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt
  });
  if (deployment.status !== "approved") errors.push("deployment changed");
  const approval = validateL1FactAnchorSubmissionApproval(request.submissionApproval, signed);
  errors.push(...approval.errors);
  const nonce = await request.nonceReader.readNonce({} as never);
  if (nonce.status !== "resolved" || nonce.nonce !== signed.binding.nonce) errors.push("nonce changed");
  const gas = await request.gasEstimator.estimateGas({} as never);
  if (gas.status !== "estimated" || gas.gasLimit !== signed.binding.gasLimit) errors.push("gas changed");
  const fee = await request.feeDataReader.readFeeData({} as never);
  if (fee.status !== "resolved"
    || fee.maxFeePerGas !== signed.binding.maxFeePerGas
    || fee.maxPriorityFeePerGas !== signed.binding.maxPriorityFeePerGas) {
    errors.push("fee changed");
  }
  if (errors.length > 0) {
    const joined = errors.join(" | ");
    const outcome = joined.includes("duplicate")
      ? "duplicate_submission"
      : joined.includes("already_consumed")
        ? "message_already_consumed"
      : joined.includes("nonce")
        ? "nonce_changed"
      : joined.includes("fee") || joined.includes("gas")
          ? "fee_changed"
          : joined.includes("approval")
            ? "approval_missing"
            : joined.includes("mainnet")
              ? "unsupported"
              : "malformed";
    const auditEventDraft = createSubmissionAuditDraft({ request, outcome, errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_SUBMISSION_BLOCKED",
      category: "unsupported_operation",
      message: "Ethereum L1 fact-anchor submission was blocked.",
      recoverable: true,
      details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const result = await request.submitter.submitSignedL1FactAnchorTransaction({ signedTransaction: signed });
  if (result.status !== "submitted" || !result.transactionHash) {
    const outcome = result.status === "unavailable" ? "rpc_unavailable" : "transaction_rejected";
    const auditEventDraft = createSubmissionAuditDraft({ request, outcome, errors: [result.error ?? "submission failed"] });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_SUBMISSION_FAILED",
      category: "network_unavailable",
      message: "Ethereum L1 fact-anchor submission failed.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  request.submittedTransactionStore?.addTransaction(result.transactionHash);
  const auditEventDraft = createSubmissionAuditDraft({ request, outcome: "transaction_submitted" });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    status: "transaction_submitted",
    outcome: "transaction_submitted",
    transactionHash: result.transactionHash,
    submittedAt: result.submittedAt ?? nowIso(),
    transactionSubmitted: true,
    transactionConfirmed: false,
    l2ToL1MessageConsumed: false,
    l1FactAnchored: false,
    l1ToBaseRelayPrepared: false,
    l1ToBaseRelaySubmitted: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1FactAnchorSubmission = submitL1FactAnchorTransaction;

function createReceiptAuditDraft(input: {
  readonly request: L1FactAnchorReceiptMonitoringRequest;
  readonly outcome: L1FactAnchorSubmissionOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "transaction_confirmed" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1FactAnchorReceiptMonitoring",
    summary: input.outcome === "transaction_confirmed"
      ? "Ethereum L1 fact-anchor receipt confirmed."
      : "Ethereum L1 fact-anchor receipt monitoring did not confirm anchoring.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.request.signedTransaction.transactionHashBinding.transactionHash,
      anchorAddress: input.request.signedTransaction.binding.anchorAddress,
      messageHash: input.request.signedTransaction.binding.messageHash
    }
  });
}

export function verifyL1FactAnchoredEvent(
  receipt: L1FactAnchorEthereumReceipt,
  signed: SignedL1FactAnchorTransaction
): RuntimeResult<L1FactAnchoredEvent> {
  for (const log of receipt.logs) {
    if (normalizeAddress(log.address) !== normalizeAddress(signed.binding.anchorAddress)) continue;
    try {
      const parsed = ANCHOR_INTERFACE.parseLog({
        topics: [...log.topics],
        data: log.data
      });
      if (parsed?.name !== "ProofInputHashFactAnchored") continue;
      const sourceL2Verifier = normalizeNumberishHex(parsed.args.sourceL2Verifier);
      const factHigh = normalizeNumberishHex(parsed.args.factHigh);
      const factLow = normalizeNumberishHex(parsed.args.factLow);
      if (sourceL2Verifier !== normalizeHex(signed.binding.sourceL2Verifier)) continue;
      if (factHigh !== normalizeHex(signed.binding.factHigh)) continue;
      if (factLow !== normalizeHex(signed.binding.factLow)) continue;
      return runtimeOk(Object.freeze({
        contractAddress: normalizeAddress(log.address),
        sourceL2Verifier,
        factHigh,
        factLow,
        transactionHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash
      }));
    } catch {
      // Ignore unrelated logs.
    }
  }
  return runtimeDenied({
    code: "L1_FACT_ANCHOR_EVENT_MISSING",
    category: "proof_failed",
    message: "Expected L1 fact-anchor event was not found.",
    recoverable: true,
    details: { outcome: "transaction_reverted" }
  });
}

export async function monitorL1FactAnchorReceipt(
  request: L1FactAnchorReceiptMonitoringRequest
): Promise<L1FactAnchorReceiptMonitoringResult> {
  const maxAttempts = Math.max(1, request.maxAttempts ?? 1);
  const timeoutMs = Math.max(1, request.timeoutMs ?? 30_000);
  const startedAt = Date.now();
  let lastReceipt: L1FactAnchorEthereumReceipt | undefined;
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
        code: "L1_FACT_ANCHOR_RECEIPT_NOT_CONFIRMED",
        category: "network_unavailable",
        message: "Ethereum L1 fact-anchor receipt was not confirmed.",
        recoverable: true,
        details: {
          outcome: lastReceipt.status === "reverted" ? "transaction_reverted" : "transaction_rejected"
        }
      });
    }
    if ((lastReceipt.confirmations ?? 0) < (request.minConfirmations ?? 1)) {
      continue;
    }
    const event = verifyL1FactAnchoredEvent(lastReceipt, request.signedTransaction);
    if (event.status !== "approved" || !event.value) {
      return runtimeDenied({
        code: "L1_FACT_ANCHOR_EVENT_INVALID",
        category: "proof_failed",
        message: "Ethereum L1 fact-anchor event did not match the signed artifact.",
        recoverable: true,
        details: { outcome: "transaction_reverted" }
      });
    }
    const stateVerification = request.stateReader
      ? await request.stateReader.readAnchoredFact({
        anchorAddress: request.signedTransaction.binding.anchorAddress,
        factHigh: request.signedTransaction.binding.factHigh,
        factLow: request.signedTransaction.binding.factLow
      })
      : undefined;
    if (stateVerification && stateVerification.status !== "anchored") {
      return runtimeDenied({
        code: "L1_FACT_ANCHOR_STATE_INVALID",
        category: "proof_failed",
        message: "Ethereum L1 fact-anchor state verification failed.",
        recoverable: true,
        details: { outcome: "transaction_reverted", state: stateVerification.status }
      });
    }
    const auditEventDraft = createReceiptAuditDraft({ request, outcome: "transaction_confirmed" });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeOk(Object.freeze({
      l1FactAnchorReceiptId: createAuditCorrelationId([
        lastReceipt.transactionHash,
        "l1-fact-anchor-receipt"
      ]),
      transactionHash: lastReceipt.transactionHash,
      chainId: request.signedTransaction.binding.chainId,
      anchorAddress: request.signedTransaction.binding.anchorAddress,
      relayerAccount: request.signedTransaction.binding.relayerAccount,
      messageHash: request.signedTransaction.binding.messageHash,
      proofInputHash: request.signedTransaction.binding.proofInputHash,
      factHigh: request.signedTransaction.binding.factHigh,
      factLow: request.signedTransaction.binding.factLow,
      event: event.value,
      stateVerification,
      blockNumber: lastReceipt.blockNumber,
      blockHash: lastReceipt.blockHash,
      gasUsed: lastReceipt.gasUsed,
      effectiveGasPrice: lastReceipt.effectiveGasPrice,
      confirmations: lastReceipt.confirmations ?? 0,
      observedAt: nowIso(),
      transactionConfirmed: true,
      l2ToL1MessageConsumed: true,
      l1FactAnchored: true,
      l1ToBaseRelayPrepared: false,
      l1ToBaseRelaySubmitted: false,
      baseFactMirrored: false,
      nullifierConsumed: false,
      consumerExecuted: false,
      auditEventDraft,
      auditDraftCollectionResult
    }));
  }
  const auditEventDraft = createReceiptAuditDraft({
    request,
    outcome: "submission_timeout",
    errors: ["receipt monitoring timeout"]
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: "L1_FACT_ANCHOR_RECEIPT_TIMEOUT",
    category: "network_unavailable",
    message: "Ethereum L1 fact-anchor receipt monitoring timed out.",
    recoverable: true,
    details: { outcome: "submission_timeout", lastReceiptStatus: lastReceipt?.status }
  });
}

export const requestL1FactAnchorReceiptMonitoring = monitorL1FactAnchorReceipt;

export function createFixtureL1FactAnchorSigner(input: {
  readonly privateKey: string;
  readonly relayerAddress?: string;
  readonly mode?: L1FactAnchorRelayerMode;
  readonly allowedChainIds?: readonly number[];
}): L1FactAnchorSigner {
  const wallet = new Wallet(input.privateKey);
  let available = true;
  const relayerAddress = normalizeAddress(input.relayerAddress ?? wallet.address);
  return {
    describeSigner() {
      return Object.freeze({
        signerId: createAuditCorrelationId([relayerAddress, "fixture-l1-anchor-signer"]),
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
    async signL1FactAnchorTransaction(request) {
      if (!available) return { status: "failed", transactionHash: request.expectedTransactionHash, error: "signer unavailable" };
      if (request.transaction.chainId === 1 || !((input.allowedChainIds ?? [31337, 11155111]).includes(request.transaction.chainId))) {
        return { status: "rejected", transactionHash: request.expectedTransactionHash, error: "chain rejected" };
      }
      const rawSignedTransaction = await wallet.signTransaction(request.transaction);
      const tx = Transaction.from(rawSignedTransaction);
      if (!tx.hash) {
        return { status: "failed", transactionHash: request.expectedTransactionHash, error: "signed transaction hash unavailable" };
      }
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

export function createFixtureEthereumTransactionSubmitter(): EthereumTransactionSubmitter {
  return {
    async submitSignedL1FactAnchorTransaction(request) {
      return {
        status: "submitted",
        transactionHash: request.signedTransaction.transactionHashBinding.transactionHash,
        submittedAt: nowIso()
      };
    }
  };
}

export function createUnavailableEthereumTransactionSubmitter(): EthereumTransactionSubmitter {
  return {
    async submitSignedL1FactAnchorTransaction() {
      return { status: "unavailable", error: "rpc unavailable" };
    }
  };
}

export function createFixtureEthereumReceiptReader(
  receipt: L1FactAnchorEthereumReceipt
): EthereumTransactionReceiptReader {
  return {
    async getTransactionReceipt() {
      return receipt;
    }
  };
}

export function createFixtureL1FactAnchorStateReader(
  status: L1FactAnchorStateVerificationResult["status"] = "anchored"
): L1FactAnchorStateReader {
  return {
    async readAnchoredFact() {
      return {
        status,
        checkedAt: nowIso(),
        blockNumber: 1
      };
    }
  };
}

export function createInMemoryL1FactAnchorSubmittedTransactionStore(): L1FactAnchorSubmittedTransactionStore {
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
