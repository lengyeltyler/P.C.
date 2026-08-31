import { hash as starknetHash } from "starknet";
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
import type {
  StarknetNonceReader,
  StarknetPublicationReadinessManifest
} from "./starknetFactPublicationPreparation.ts";
import {
  computeUnsignedStarknetInvokeV3Hash,
  type SignedStarknetFactPublicationTransaction,
  type StarknetInvokeV3HashInput,
  type StarknetSigningFeeValidation
} from "./starknetPublisherSigning.ts";
import type { RuntimeResult } from "./types.ts";

const ENTRYPOINT = "verify_proof_input_hash_slice_and_send_to_l1";
const FELT_MAX = (1n << 252n) - 1n;

export type StarknetPublicationDeploymentStatus =
  | "deployment_verified"
  | "deployment_prepared"
  | "deployment_submitted"
  | "deployment_accepted"
  | "deployment_rejected";

export type StarknetPublicationDeploymentOutcome =
  | "existing_deployment_verified"
  | "deployment_prepared"
  | "deployment_submitted"
  | "deployment_accepted"
  | "deployment_reverted"
  | "deployment_address_mismatch"
  | "class_hash_mismatch"
  | "compiled_class_hash_mismatch"
  | "abi_hash_mismatch"
  | "publisher_unapproved"
  | "funding_insufficient"
  | "rpc_unavailable"
  | "approval_missing"
  | "malformed"
  | "unsupported";

export type StarknetPublicationDeploymentLimitation =
  | "testnet_or_local_only"
  | "not_mainnet"
  | "deployment_verification_only"
  | "no_l1_or_base_behavior";

export interface StarknetPublicationContractDeployment {
  readonly deploymentId: string;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly contractAddress: string;
  readonly classHash: string;
  readonly compiledClassHash: string;
  readonly abiSha256: string;
  readonly deploymentStatus: "configured" | "verified" | "submitted" | "accepted";
  readonly approved: boolean;
}

export interface StarknetPublicationDeploymentBinding {
  readonly packageName: string;
  readonly contractName: string;
  readonly entrypoint: typeof ENTRYPOINT;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly contractAddress: string;
  readonly classHash: string;
  readonly compiledClassHash: string;
  readonly abiSha256: string;
  readonly l1Recipient: string;
}

export interface StarknetPublicationDeploymentReceipt {
  readonly transactionHash?: string;
  readonly status: StarknetPublicationDeploymentStatus;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly acceptedAt?: string;
}

export interface StarknetPublicationDeploymentRequest {
  readonly requestId: string;
  readonly publicationConfig: StarknetPublicationRuntimeConfig;
  readonly readinessManifest: StarknetPublicationReadinessManifest;
  readonly deployment?: StarknetPublicationContractDeployment;
  readonly deploymentReader?: StarknetPublicationDeploymentReader;
  readonly deploymentApproval?: StarknetPublicationDeploymentApproval;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface StarknetPublicationDeploymentApproval {
  readonly approvalId: string;
  readonly approved: boolean;
  readonly source: "operator_approval" | "infrastructure_policy" | "testnet_deployment_policy";
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export interface StarknetPublicationDeploymentResultValue {
  readonly status: StarknetPublicationDeploymentStatus;
  readonly outcome: StarknetPublicationDeploymentOutcome;
  readonly binding: StarknetPublicationDeploymentBinding;
  readonly deployment: StarknetPublicationContractDeployment;
  readonly receipt?: StarknetPublicationDeploymentReceipt;
  readonly limitations: readonly StarknetPublicationDeploymentLimitation[];
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type StarknetPublicationDeploymentResult =
  RuntimeResult<StarknetPublicationDeploymentResultValue>;

export interface StarknetPublicationDeploymentReader {
  getClassHash(contractAddress: string): Promise<StarknetClassHashReadResult>;
}

export interface StarknetClassHashReadResult {
  readonly status: "found" | "not_found" | "unavailable";
  readonly classHash?: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly error?: string;
}

export interface StarknetPublicationRuntimeConfig {
  readonly profileId: string;
  readonly configurationApprovalStatus?: string;
  readonly artifactBinding: Readonly<Record<string, unknown>>;
  readonly l1RecipientBinding: Readonly<Record<string, unknown>>;
  readonly expectedL2SenderBinding: Readonly<Record<string, unknown>>;
  readonly accountCallerModel: Readonly<Record<string, unknown>>;
  readonly networkProfiles: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}

export interface StarknetPublisherAccountConfiguration {
  readonly accountAddress: string;
  readonly networkProfileId: string;
  readonly approved: boolean;
  readonly custody: StarknetPublisherKeyCustodyConfiguration;
}

export interface StarknetPublisherKeyCustodyConfiguration {
  readonly custodyId: string;
  readonly model:
    | "disposable_encrypted_testnet_key"
    | "external_signer"
    | "operator_wallet"
    | "remote_signing_service"
    | "developer_fixture";
  readonly approvedForPublicTestnet: boolean;
  readonly plaintextKeyInRepository: false;
  readonly commandLineSecretAllowed: false;
}

export interface StarknetPublisherFundingStatus {
  readonly status: "sufficient" | "insufficient" | "unknown";
  readonly feeToken: string;
  readonly checkedAt: string;
  readonly balance?: string;
  readonly requiredMaximumFee?: string;
}

export interface StarknetPublisherSubmissionAuthorization {
  readonly publisherAccount: StarknetPublisherAccountConfiguration;
  readonly fundingStatus: StarknetPublisherFundingStatus;
  readonly approved: boolean;
}

export type StarknetPublicationSubmissionApprovalSource =
  | "operator_approval"
  | "infrastructure_policy"
  | "testnet_deployment_policy"
  | "fixture_submission_policy";

export interface StarknetPublicationSubmissionApproval {
  readonly approvalId: string;
  readonly approved: boolean;
  readonly source: StarknetPublicationSubmissionApprovalSource;
  readonly transactionHash: string;
  readonly senderAccount: string;
  readonly networkProfileId: string;
  readonly publicationContract: string;
  readonly calldataHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly l1Recipient: string;
  readonly nonce: string;
  readonly resourceBoundsDigest: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
}

export interface StarknetPublicationSubmissionApprovalRequest {
  readonly signedTransaction: SignedStarknetFactPublicationTransaction;
  readonly requestedAt: string;
  readonly expiresAt: string;
}

export interface StarknetPublicationSubmissionApprovalResult {
  readonly status: "approved" | "rejected" | "expired";
  readonly approval?: StarknetPublicationSubmissionApproval;
  readonly errors: readonly string[];
}

export type StarknetFactPublicationSubmissionStatus =
  | "submission_blocked"
  | "transaction_submitted"
  | "transaction_received"
  | "transaction_accepted_on_l2"
  | "transaction_rejected"
  | "transaction_reverted"
  | "transaction_not_received";

export type StarknetFactPublicationSubmissionOutcome =
  | "submission_blocked"
  | "transaction_submitted"
  | "transaction_received"
  | "transaction_accepted_on_l2"
  | "transaction_rejected"
  | "transaction_reverted"
  | "transaction_not_received"
  | "nonce_changed"
  | "fee_changed"
  | "signature_invalid"
  | "rpc_unavailable"
  | "submission_timeout"
  | "approval_missing"
  | "duplicate_submission"
  | "malformed"
  | "unsupported";

export type StarknetFactPublicationSubmissionLimitation =
  | "starknet_testnet_or_local_only"
  | "no_l1_anchor_call"
  | "no_l1_to_base_relay"
  | "no_base_execution"
  | "no_nullifier_consumption"
  | "l1_message_availability_not_confirmed";

export interface StarknetFactPublicationTransactionReference {
  readonly transactionHash: string;
  readonly senderAccount: string;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly publicationContract: string;
  readonly calldataHash: string;
}

export interface StarknetFactPublicationSubmissionRequest {
  readonly requestId: string;
  readonly signedTransaction: SignedStarknetFactPublicationTransaction;
  readonly deploymentResult: StarknetPublicationDeploymentResultValue;
  readonly publisherAuthorization: StarknetPublisherSubmissionAuthorization;
  readonly submissionApproval?: StarknetPublicationSubmissionApproval;
  readonly nonceReader: StarknetNonceReader;
  readonly feeValidation: StarknetSigningFeeValidation;
  readonly hashInput: StarknetInvokeV3HashInput;
  readonly submitter: StarknetTransactionSubmitter;
  readonly submittedTransactionStore?: StarknetSubmittedTransactionStore;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface StarknetFactPublicationSubmissionResultValue {
  readonly status: StarknetFactPublicationSubmissionStatus;
  readonly outcome: StarknetFactPublicationSubmissionOutcome;
  readonly reference: StarknetFactPublicationTransactionReference;
  readonly transactionHash: string;
  readonly submittedAt?: string;
  readonly limitations: readonly StarknetFactPublicationSubmissionLimitation[];
  readonly transactionSubmitted: boolean;
  readonly transactionAcceptedOnL2: false;
  readonly verificationEventObserved: false;
  readonly l2ToL1MessageObserved: false;
  readonly l1MessageAvailabilityConfirmed: false;
  readonly l1MessageConsumed: false;
  readonly l1FactAnchored: false;
  readonly baseFactMirrored: false;
  readonly nullifierConsumed: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly submissionStoreResult?: StarknetSubmittedTransactionStoreResult;
}

export type StarknetFactPublicationSubmissionResult =
  RuntimeResult<StarknetFactPublicationSubmissionResultValue>;

export interface StarknetTransactionSubmitter {
  submitSignedPublicationTransaction(
    request: StarknetTransactionSubmitRequest
  ): Promise<StarknetTransactionSubmitResult>;
}

export interface StarknetTransactionSubmitRequest {
  readonly signedTransaction: SignedStarknetFactPublicationTransaction;
  readonly transactionHash: string;
}

export interface StarknetTransactionSubmitResult {
  readonly status: "submitted" | "rejected" | "unavailable";
  readonly transactionHash?: string;
  readonly submittedAt?: string;
  readonly error?: string;
}

export interface StarknetTransactionReceiptReader {
  getTransactionReceipt(transactionHash: string): Promise<StarknetFactPublicationTransactionReceipt>;
}

export interface StarknetFactPublicationTransactionReceipt {
  readonly transactionHash: string;
  readonly finalityStatus:
    | "RECEIVED"
    | "ACCEPTED_ON_L2"
    | "ACCEPTED_ON_L1"
    | "REJECTED"
    | "NOT_RECEIVED";
  readonly executionStatus?: "SUCCEEDED" | "REVERTED" | "REJECTED";
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly events: readonly StarknetReceiptEvent[];
  readonly messagesSent: readonly StarknetReceiptL2ToL1Message[];
  readonly error?: string;
}

export interface StarknetReceiptEvent {
  readonly fromAddress: string;
  readonly keys: readonly string[];
  readonly data: readonly string[];
}

export interface StarknetReceiptL2ToL1Message {
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly payload: readonly string[];
  readonly messageHash?: string;
}

export interface StarknetFactVerificationEvent {
  readonly contractAddress: string;
  readonly transactionHash: string;
  readonly eventSelector: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
}

export interface StarknetFactVerificationEventResult {
  readonly status: "observed" | "missing" | "mismatch";
  readonly event?: StarknetFactVerificationEvent;
  readonly errors: readonly string[];
}

export interface StarknetL2ToL1MessageEvidence {
  readonly senderContract: string;
  readonly l1Recipient: string;
  readonly payloadLength: 2;
  readonly factHigh: string;
  readonly factLow: string;
  readonly transactionHash: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly messageHash?: string;
}

export interface StarknetL2ToL1MessageEvidenceResult {
  readonly status: "observed" | "missing" | "mismatch";
  readonly evidence?: StarknetL2ToL1MessageEvidence;
  readonly errors: readonly string[];
}

export interface StarknetFactPublicationFinalityResult {
  readonly status: StarknetFactPublicationSubmissionStatus;
  readonly outcome: StarknetFactPublicationSubmissionOutcome;
  readonly receipt?: StarknetFactPublicationTransactionReceipt;
  readonly eventResult?: StarknetFactVerificationEventResult;
  readonly messageResult?: StarknetL2ToL1MessageEvidenceResult;
  readonly checkedAt: string;
}

export interface StarknetFactPublicationReceiptArtifact {
  readonly receiptArtifactId: string;
  readonly submissionId: string;
  readonly transactionHash: string;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly publicationContract: string;
  readonly senderAccount: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly l1Recipient: string;
  readonly transactionStatus: StarknetFactPublicationSubmissionStatus;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly event?: StarknetFactVerificationEvent;
  readonly l2ToL1Message?: StarknetL2ToL1MessageEvidence;
  readonly observedAt: string;
  readonly auditCorrelationId: string;
  readonly limitations: readonly StarknetFactPublicationSubmissionLimitation[];
  readonly transactionAcceptedOnL2: boolean;
  readonly verificationEventObserved: boolean;
  readonly l2ToL1MessageObserved: boolean;
  readonly l1MessageAvailabilityConfirmed: false;
  readonly l1MessageConsumed: false;
  readonly l1FactAnchored: false;
  readonly baseFactMirrored: false;
  readonly nullifierConsumed: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface StarknetFactPublicationReceiptMonitorRequest {
  readonly requestId: string;
  readonly submission: StarknetFactPublicationSubmissionResultValue;
  readonly signedTransaction: SignedStarknetFactPublicationTransaction;
  readonly receiptReader: StarknetTransactionReceiptReader;
  readonly maxAttempts?: number;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type StarknetFactPublicationReceiptMonitorResult =
  RuntimeResult<StarknetFactPublicationReceiptArtifact>;

export interface StarknetSubmittedTransactionStore {
  hasTransaction(transactionHash: string): boolean;
  addTransaction(transactionHash: string): StarknetSubmittedTransactionStoreResult;
  clear(): void;
}

export interface StarknetSubmittedTransactionStoreResult {
  readonly status: "recorded" | "duplicate";
  readonly transactionHash: string;
  readonly count: number;
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeHex(value: string): string {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.replace(/^0+/, "") || "0";
  return `0x${normalized.toLowerCase()}`;
}

function isFelt(value: unknown): value is string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) return false;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= FELT_MAX;
  } catch {
    return false;
  }
}

function isNonZeroFelt(value: unknown): value is string {
  return isFelt(value) && BigInt(value) !== 0n;
}

function nowIso(): string {
  return new Date().toISOString();
}

function digest(value: unknown): string {
  return createAuditCorrelationId([JSON.stringify(value)]);
}

function isAllowedProfile(profileId: string): boolean {
  return profileId === "starknet_sepolia" || profileId === "local_devnet";
}

function isMainnetProfile(profileId: string, chainId?: string): boolean {
  return profileId.includes("mainnet") || chainId === "SN_MAIN";
}

function safeLimitations(): readonly StarknetFactPublicationSubmissionLimitation[] {
  return Object.freeze([
    "starknet_testnet_or_local_only",
    "no_l1_anchor_call",
    "no_l1_to_base_relay",
    "no_base_execution",
    "no_nullifier_consumption",
    "l1_message_availability_not_confirmed"
  ]);
}

function createDeploymentAuditDraft(input: {
  readonly request: StarknetPublicationDeploymentRequest;
  readonly outcome: StarknetPublicationDeploymentOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "existing_deployment_verified" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestStarknetPublicationDeploymentVerification",
    summary: input.outcome === "existing_deployment_verified"
      ? "Starknet publication deployment verified."
      : "Starknet publication deployment verification blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      profileId: input.request.publicationConfig.profileId,
      contractAddress: input.request.deployment?.contractAddress
    }
  });
}

function createSubmissionAuditDraft(input: {
  readonly request: StarknetFactPublicationSubmissionRequest;
  readonly outcome: StarknetFactPublicationSubmissionOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "transaction_submitted" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestStarknetFactPublicationSubmission",
    summary: input.outcome === "transaction_submitted"
      ? "Starknet fact-publication transaction submitted."
      : "Starknet fact-publication transaction submission blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.request.signedTransaction.transactionHash,
      contract: input.request.signedTransaction.binding.publicationContractAddress,
      account: input.request.signedTransaction.binding.accountAddress,
      proofInputHash: input.request.signedTransaction.binding.proofInputHash,
      factPair: [
        input.request.signedTransaction.binding.factHigh,
        input.request.signedTransaction.binding.factLow
      ],
      l1Recipient: input.request.signedTransaction.binding.l1Recipient
    }
  });
}

function createReceiptAuditDraft(input: {
  readonly request: StarknetFactPublicationReceiptMonitorRequest;
  readonly outcome: StarknetFactPublicationSubmissionOutcome;
  readonly receipt?: StarknetFactPublicationTransactionReceipt;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "transaction_accepted_on_l2" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestStarknetFactPublicationReceiptMonitoring",
    summary: input.outcome === "transaction_accepted_on_l2"
      ? "Starknet fact-publication receipt accepted on L2."
      : "Starknet fact-publication receipt monitoring did not reach accepted-on-L2.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      transactionHash: input.request.signedTransaction.transactionHash,
      finalityStatus: input.receipt?.finalityStatus,
      executionStatus: input.receipt?.executionStatus,
      blockNumber: input.receipt?.blockNumber,
      blockHash: input.receipt?.blockHash
    }
  });
}

export function validateStarknetPublicationPreflight(
  config: StarknetPublicationRuntimeConfig
): RuntimeValidationResult {
  const errors: string[] = [];
  const profile = config.networkProfiles?.[config.profileId];
  const chainId = profile?.starknetChainId as string | undefined;
  if (!profile) errors.push("network profile missing");
  if (!isAllowedProfile(config.profileId)) errors.push("profile must be Starknet Sepolia or explicitly configured local devnet");
  if (isMainnetProfile(config.profileId, chainId)) errors.push("mainnet prohibited");
  if (profile?.enabled !== true) errors.push("network profile not enabled");
  if (config.profileId === "starknet_sepolia" && chainId !== "SN_SEPOLIA") {
    errors.push("Starknet Sepolia chain ID mismatch");
  }
  if (profile?.rpcReference === "environment_reference_required" || !profile?.rpcReference) {
    errors.push("working RPC reference missing");
  }
  if (typeof config.artifactBinding?.starknetClassHash !== "string") {
    errors.push("publication class hash missing");
  }
  if (typeof config.artifactBinding?.compiledClassHash !== "string") {
    errors.push("compiled class hash missing");
  }
  if (typeof config.artifactBinding?.abiSha256 !== "string") errors.push("ABI hash missing");
  if (!isNonZeroFelt(config.expectedL2SenderBinding?.publicationContractAddress)) {
    errors.push("accepted deployment address missing");
  }
  if (!isNonZeroFelt(config.l1RecipientBinding?.configuredL1RecipientAddress)) {
    errors.push("nonzero L1 recipient missing");
  }
  if (config.accountCallerModel?.status !== "resolved") errors.push("approved publisher account missing");
  if (!isNonZeroFelt(config.accountCallerModel?.accountAddress)) {
    errors.push("publisher account address missing");
  }
  if (config.configurationApprovalStatus !== "accepted") {
    errors.push("configuration approval missing");
  }
  return validation(errors);
}

export async function verifyExistingStarknetPublicationDeployment(
  request: StarknetPublicationDeploymentRequest
): Promise<StarknetPublicationDeploymentResult> {
  const errors: string[] = [];
  const preflight = validateStarknetPublicationPreflight(request.publicationConfig);
  errors.push(...preflight.errors);
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("deployment request expired");
  if (!request.deployment) errors.push("deployment record missing");
  if (!request.deploymentReader) errors.push("deployment reader missing");
  if (!request.deploymentApproval?.approved) errors.push("deployment approval missing");
  if (request.deploymentApproval && Date.now() > Date.parse(request.deploymentApproval.expiresAt)) {
    errors.push("deployment approval expired");
  }
  const config = request.publicationConfig;
  const deployment = request.deployment;
  const profile = config.networkProfiles?.[config.profileId];
  if (deployment && config.profileId !== deployment.networkProfileId) errors.push("deployment profile mismatch");
  if (deployment && profile?.starknetChainId !== deployment.chainId) errors.push("deployment chain mismatch");
  if (deployment && normalizeHex(deployment.contractAddress) !== normalizeHex(String(config.expectedL2SenderBinding.publicationContractAddress))) {
    errors.push("deployment address mismatch");
  }
  if (deployment && deployment.classHash !== config.artifactBinding.starknetClassHash) {
    errors.push("class hash mismatch");
  }
  if (deployment && deployment.compiledClassHash !== config.artifactBinding.compiledClassHash) {
    errors.push("compiled class hash mismatch");
  }
  if (deployment && deployment.abiSha256 !== config.artifactBinding.abiSha256) {
    errors.push("abi hash mismatch");
  }
  let classHashRead: StarknetClassHashReadResult | undefined;
  if (errors.length === 0 && deployment && request.deploymentReader) {
    classHashRead = await request.deploymentReader.getClassHash(deployment.contractAddress);
    if (classHashRead.status !== "found") errors.push("rpc unavailable or deployment not found");
    if (classHashRead.classHash && normalizeHex(classHashRead.classHash) !== normalizeHex(deployment.classHash)) {
      errors.push("class hash mismatch");
    }
  }
  if (errors.length > 0 || !deployment) {
    const outcome = deploymentOutcomeForErrors(errors);
    const auditEventDraft = createDeploymentAuditDraft({ request, outcome, errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_PUBLICATION_DEPLOYMENT_NOT_VERIFIED",
      category: "unsupported_operation",
      message: "Starknet publication deployment verification is blocked.",
      recoverable: true,
      details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const binding: StarknetPublicationDeploymentBinding = Object.freeze({
    packageName: String(config.artifactBinding.packageName),
    contractName: String(config.artifactBinding.contractName),
    entrypoint: ENTRYPOINT,
    networkProfileId: config.profileId,
    chainId: deployment.chainId,
    contractAddress: normalizeHex(deployment.contractAddress),
    classHash: normalizeHex(deployment.classHash),
    compiledClassHash: normalizeHex(deployment.compiledClassHash),
    abiSha256: deployment.abiSha256,
    l1Recipient: normalizeHex(String(config.l1RecipientBinding.configuredL1RecipientAddress))
  });
  const auditEventDraft = createDeploymentAuditDraft({
    request,
    outcome: "existing_deployment_verified"
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    status: "deployment_verified",
    outcome: "existing_deployment_verified",
    binding,
    deployment: Object.freeze({ ...deployment, deploymentStatus: "verified" as const }),
    receipt: classHashRead ? Object.freeze({
      status: "deployment_verified" as const,
      blockNumber: classHashRead.blockNumber,
      blockHash: classHashRead.blockHash,
      acceptedAt: nowIso()
    }) : undefined,
    limitations: Object.freeze([
      "testnet_or_local_only",
      "not_mainnet",
      "deployment_verification_only",
      "no_l1_or_base_behavior"
    ] satisfies readonly StarknetPublicationDeploymentLimitation[]),
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

function deploymentOutcomeForErrors(errors: readonly string[]): StarknetPublicationDeploymentOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("compiled")) return "compiled_class_hash_mismatch";
  if (joined.includes("class hash")) return "class_hash_mismatch";
  if (joined.includes("abi")) return "abi_hash_mismatch";
  if (joined.includes("address")) return "deployment_address_mismatch";
  if (joined.includes("approval")) return "approval_missing";
  if (joined.includes("RPC") || joined.includes("rpc")) return "rpc_unavailable";
  if (joined.includes("publisher")) return "publisher_unapproved";
  return "malformed";
}

export function validateStarknetPublicationSubmissionApproval(
  approval: StarknetPublicationSubmissionApproval | undefined,
  signedTransaction: SignedStarknetFactPublicationTransaction
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!approval) return validation(["submission approval missing"]);
  if (!approval.approved) errors.push("submission approval rejected");
  if (Date.now() > Date.parse(approval.expiresAt)) errors.push("submission approval expired");
  if (normalizeHex(approval.transactionHash) !== normalizeHex(signedTransaction.transactionHash)) {
    errors.push("approval transaction hash mismatch");
  }
  if (normalizeHex(approval.senderAccount) !== normalizeHex(signedTransaction.binding.accountAddress)) {
    errors.push("approval sender mismatch");
  }
  if (approval.networkProfileId !== signedTransaction.binding.networkProfileId) {
    errors.push("approval network mismatch");
  }
  if (normalizeHex(approval.publicationContract) !== normalizeHex(signedTransaction.binding.publicationContractAddress)) {
    errors.push("approval contract mismatch");
  }
  if (approval.calldataHash !== signedTransaction.binding.calldataHash) errors.push("approval calldata mismatch");
  if (approval.proofInputHash !== signedTransaction.binding.proofInputHash) {
    errors.push("approval proofInputHash mismatch");
  }
  if (approval.factHigh !== signedTransaction.binding.factHigh) errors.push("approval fact high mismatch");
  if (approval.factLow !== signedTransaction.binding.factLow) errors.push("approval fact low mismatch");
  if (normalizeHex(approval.l1Recipient) !== normalizeHex(signedTransaction.binding.l1Recipient)) {
    errors.push("approval l1 recipient mismatch");
  }
  if (normalizeHex(approval.nonce) !== normalizeHex(signedTransaction.binding.nonce)) {
    errors.push("approval nonce mismatch");
  }
  if (approval.resourceBoundsDigest !== digest(signedTransaction.binding.resourceBounds)) {
    errors.push("approval resource bounds mismatch");
  }
  return validation(errors);
}

export function createStarknetPublicationSubmissionApproval(
  input: {
    readonly signedTransaction: SignedStarknetFactPublicationTransaction;
    readonly source: StarknetPublicationSubmissionApprovalSource;
    readonly approved?: boolean;
    readonly approvalId?: string;
    readonly approvedAt?: string;
    readonly expiresAt?: string;
  }
): StarknetPublicationSubmissionApproval {
  const tx = input.signedTransaction;
  return Object.freeze({
    approvalId: input.approvalId ?? createAuditCorrelationId([
      tx.transactionHash,
      "starknet-publication-submission-approval"
    ]),
    approved: input.approved ?? true,
    source: input.source,
    transactionHash: tx.transactionHash,
    senderAccount: tx.binding.accountAddress,
    networkProfileId: tx.binding.networkProfileId,
    publicationContract: tx.binding.publicationContractAddress,
    calldataHash: tx.binding.calldataHash,
    proofInputHash: tx.binding.proofInputHash,
    factHigh: tx.binding.factHigh,
    factLow: tx.binding.factLow,
    l1Recipient: tx.binding.l1Recipient,
    nonce: tx.binding.nonce,
    resourceBoundsDigest: digest(tx.binding.resourceBounds),
    approvedAt: input.approvedAt ?? nowIso(),
    expiresAt: input.expiresAt ?? new Date(Date.now() + 60_000).toISOString()
  });
}

function validateSubmissionRequest(
  request: StarknetFactPublicationSubmissionRequest
): RuntimeValidationResult {
  const errors: string[] = [];
  const signed = request.signedTransaction;
  if (!request.requestId) errors.push("requestId is required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("submission request expired");
  if (Date.now() > Date.parse(signed.expiresAt)) errors.push("signed artifact expired");
  if (signed.transactionSubmitted !== false) errors.push("signed artifact already submitted");
  if (isMainnetProfile(signed.binding.networkProfileId, signed.binding.chainId)) errors.push("mainnet prohibited");
  if (!isAllowedProfile(signed.binding.networkProfileId)) errors.push("unsupported network profile");
  if (request.deploymentResult.outcome !== "existing_deployment_verified" && request.deploymentResult.outcome !== "deployment_accepted") {
    errors.push("deployment not verified");
  }
  if (normalizeHex(request.deploymentResult.binding.contractAddress) !== normalizeHex(signed.binding.publicationContractAddress)) {
    errors.push("deployment contract mismatch");
  }
  const publisherAccount = request.publisherAuthorization.publisherAccount;
  const custody = publisherAccount?.custody;
  if (!request.publisherAuthorization.approved) errors.push("publisher unapproved");
  if (!publisherAccount?.approved) errors.push("publisher account unapproved");
  if (!custody) errors.push("publisher key custody missing");
  if (custody?.plaintextKeyInRepository !== false) {
    errors.push("invalid key custody");
  }
  if (
    signed.binding.networkProfileId !== "local_devnet"
    && custody?.model === "developer_fixture"
    && custody.approvedForPublicTestnet !== true
  ) {
    errors.push("fixture signer not approved for public testnet");
  }
  if (request.publisherAuthorization.fundingStatus.status !== "sufficient") errors.push("funding insufficient");
  const approvalValidation = validateStarknetPublicationSubmissionApproval(
    request.submissionApproval,
    signed
  );
  errors.push(...approvalValidation.errors);
  const nonceRead = request.nonceReader.readNonce({
    accountAddress: signed.binding.accountAddress,
    networkProfileId: signed.binding.networkProfileId
  });
  if (nonceRead.status !== "resolved" || !nonceRead.nonce) {
    errors.push("nonce reader unavailable");
  } else if (normalizeHex(nonceRead.nonce) !== normalizeHex(signed.binding.nonce)) {
    errors.push("nonce changed");
  }
  if (request.feeValidation.status !== "fee_fresh") errors.push("fee changed");
  const hashValidation = validateHashBindingForSubmission(request.hashInput, signed);
  errors.push(...hashValidation.errors);
  if (request.submittedTransactionStore?.hasTransaction(signed.transactionHash)) {
    errors.push("duplicate submission");
  }
  if (!isNonZeroFelt(signed.binding.l1Recipient)) errors.push("l1 recipient missing");
  return validation(errors);
}

function validateHashBindingForSubmission(
  hashInput: StarknetInvokeV3HashInput,
  signed: SignedStarknetFactPublicationTransaction
): RuntimeValidationResult {
  const errors: string[] = [];
  let computed: string | undefined;
  try {
    computed = computeUnsignedStarknetInvokeV3Hash(hashInput);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "hash computation failed");
  }
  if (computed && normalizeHex(computed) !== normalizeHex(signed.transactionHash)) {
    errors.push("transaction hash mismatch");
  }
  return validation(errors);
}

function submissionOutcomeForErrors(errors: readonly string[]): StarknetFactPublicationSubmissionOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("approval")) return "approval_missing";
  if (joined.includes("nonce changed")) return "nonce_changed";
  if (joined.includes("nonce")) return "nonce_changed";
  if (joined.includes("fee")) return "fee_changed";
  if (joined.includes("hash") || joined.includes("signature")) return "signature_invalid";
  if (joined.includes("duplicate")) return "duplicate_submission";
  if (joined.includes("unsupported") || joined.includes("mainnet")) return "unsupported";
  if (joined.includes("publisher")) return "submission_blocked";
  if (joined.includes("funding")) return "submission_blocked";
  return "malformed";
}

export async function submitStarknetFactPublicationTransaction(
  request: StarknetFactPublicationSubmissionRequest
): Promise<StarknetFactPublicationSubmissionResult> {
  const validationResult = validateSubmissionRequest(request);
  if (!validationResult.valid) {
    const outcome = submissionOutcomeForErrors(validationResult.errors);
    const auditEventDraft = createSubmissionAuditDraft({
      request,
      outcome,
      errors: validationResult.errors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SUBMISSION_BLOCKED",
      category: "unsupported_operation",
      message: "Starknet fact-publication submission is blocked.",
      recoverable: true,
      details: { outcome, errors: validationResult.errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const submitResult = await request.submitter.submitSignedPublicationTransaction({
    signedTransaction: request.signedTransaction,
    transactionHash: request.signedTransaction.transactionHash
  });
  if (submitResult.status !== "submitted" || !submitResult.transactionHash) {
    const outcome = submitResult.status === "unavailable" ? "rpc_unavailable" : "transaction_rejected";
    const auditEventDraft = createSubmissionAuditDraft({
      request,
      outcome,
      errors: [submitResult.error ?? "submission failed"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SUBMISSION_FAILED",
      category: "network_unavailable",
      message: "Starknet fact-publication submission failed.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const storeResult = request.submittedTransactionStore?.addTransaction(submitResult.transactionHash);
  const auditEventDraft = createSubmissionAuditDraft({
    request,
    outcome: "transaction_submitted"
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    status: "transaction_submitted",
    outcome: "transaction_submitted",
    reference: Object.freeze({
      transactionHash: normalizeHex(submitResult.transactionHash),
      senderAccount: request.signedTransaction.binding.accountAddress,
      networkProfileId: request.signedTransaction.binding.networkProfileId,
      chainId: request.signedTransaction.binding.chainId,
      publicationContract: request.signedTransaction.binding.publicationContractAddress,
      calldataHash: request.signedTransaction.binding.calldataHash
    }),
    transactionHash: normalizeHex(submitResult.transactionHash),
    submittedAt: submitResult.submittedAt ?? nowIso(),
    limitations: safeLimitations(),
    transactionSubmitted: true,
    transactionAcceptedOnL2: false,
    verificationEventObserved: false,
    l2ToL1MessageObserved: false,
    l1MessageAvailabilityConfirmed: false,
    l1MessageConsumed: false,
    l1FactAnchored: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    auditEventDraft,
    auditDraftCollectionResult,
    submissionStoreResult: storeResult
  }));
}

export const requestStarknetFactPublicationSubmission =
  submitStarknetFactPublicationTransaction;

export async function monitorStarknetFactPublicationReceipt(
  request: StarknetFactPublicationReceiptMonitorRequest
): Promise<StarknetFactPublicationReceiptMonitorResult> {
  const maxAttempts = Math.max(1, Math.floor(request.maxAttempts ?? 1));
  const timeoutMs = Math.max(1, Math.floor(request.timeoutMs ?? 30_000));
  const start = Date.now();
  let lastReceipt: StarknetFactPublicationTransactionReceipt | undefined;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (Date.now() - start > timeoutMs) break;
    lastReceipt = await request.receiptReader.getTransactionReceipt(request.submission.transactionHash);
    const finality = evaluateReceiptFinality(lastReceipt);
    if (finality.outcome !== "transaction_not_received") {
      return finalizeReceiptMonitor(request, lastReceipt, finality);
    }
    if (attempt + 1 < maxAttempts && request.pollIntervalMs) {
      await new Promise((resolve) => setTimeout(resolve, request.pollIntervalMs));
    }
  }
  const auditEventDraft = createReceiptAuditDraft({
    request,
    outcome: "submission_timeout",
    receipt: lastReceipt,
    errors: ["receipt monitoring timeout"]
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: "STARKNET_FACT_PUBLICATION_RECEIPT_TIMEOUT",
    category: "network_unavailable",
    message: "Starknet fact-publication receipt monitoring timed out.",
    recoverable: true,
    details: { outcome: "submission_timeout", auditEventId: auditEventDraft.eventDraftId }
  });
}

export const requestStarknetFactPublicationReceiptMonitoring =
  monitorStarknetFactPublicationReceipt;

function evaluateReceiptFinality(
  receipt: StarknetFactPublicationTransactionReceipt
): StarknetFactPublicationFinalityResult {
  if (receipt.finalityStatus === "NOT_RECEIVED") {
    return Object.freeze({
      status: "transaction_not_received",
      outcome: "transaction_not_received",
      receipt,
      checkedAt: nowIso()
    });
  }
  if (receipt.finalityStatus === "REJECTED" || receipt.executionStatus === "REJECTED") {
    return Object.freeze({
      status: "transaction_rejected",
      outcome: "transaction_rejected",
      receipt,
      checkedAt: nowIso()
    });
  }
  if (receipt.executionStatus === "REVERTED") {
    return Object.freeze({
      status: "transaction_reverted",
      outcome: "transaction_reverted",
      receipt,
      checkedAt: nowIso()
    });
  }
  if (receipt.finalityStatus === "ACCEPTED_ON_L2" || receipt.finalityStatus === "ACCEPTED_ON_L1") {
    return Object.freeze({
      status: "transaction_accepted_on_l2",
      outcome: "transaction_accepted_on_l2",
      receipt,
      checkedAt: nowIso()
    });
  }
  return Object.freeze({
    status: "transaction_received",
    outcome: "transaction_received",
    receipt,
    checkedAt: nowIso()
  });
}

function finalizeReceiptMonitor(
  request: StarknetFactPublicationReceiptMonitorRequest,
  receipt: StarknetFactPublicationTransactionReceipt,
  finality: StarknetFactPublicationFinalityResult
): StarknetFactPublicationReceiptMonitorResult {
  if (finality.outcome !== "transaction_accepted_on_l2") {
    const auditEventDraft = createReceiptAuditDraft({ request, outcome: finality.outcome, receipt });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_RECEIPT_NOT_ACCEPTED",
      category: "network_unavailable",
      message: "Starknet fact-publication receipt is not accepted on L2.",
      recoverable: true,
      details: { outcome: finality.outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const eventResult = verifyStarknetFactVerificationEvent(
    receipt,
    request.signedTransaction
  );
  const messageResult = verifyStarknetL2ToL1MessageEvidence(
    receipt,
    request.signedTransaction
  );
  if (eventResult.status !== "observed" || messageResult.status !== "observed") {
    const errors = [...eventResult.errors, ...messageResult.errors];
    const auditEventDraft = createReceiptAuditDraft({
      request,
      outcome: "transaction_reverted",
      receipt,
      errors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_RECEIPT_EVIDENCE_MISMATCH",
      category: "proof_failed",
      message: "Starknet fact-publication receipt evidence did not match the expected event/message.",
      recoverable: true,
      details: { outcome: "transaction_reverted", errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const auditCorrelationId = request.auditCorrelationId
    ?? request.signedTransaction.binding.auditCorrelationId;
  const auditEventDraft = createReceiptAuditDraft({
    request: { ...request, auditCorrelationId },
    outcome: "transaction_accepted_on_l2",
    receipt
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    receiptArtifactId: createAuditCorrelationId([
      request.submission.transactionHash,
      "starknet-publication-receipt"
    ]),
    submissionId: request.submission.reference.transactionHash,
    transactionHash: request.submission.transactionHash,
    networkProfileId: request.signedTransaction.binding.networkProfileId,
    chainId: request.signedTransaction.binding.chainId,
    publicationContract: request.signedTransaction.binding.publicationContractAddress,
    senderAccount: request.signedTransaction.binding.accountAddress,
    proofInputHash: request.signedTransaction.binding.proofInputHash,
    factHigh: request.signedTransaction.binding.factHigh,
    factLow: request.signedTransaction.binding.factLow,
    l1Recipient: request.signedTransaction.binding.l1Recipient,
    transactionStatus: "transaction_accepted_on_l2",
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    event: eventResult.event,
    l2ToL1Message: messageResult.evidence,
    observedAt: nowIso(),
    auditCorrelationId,
    limitations: safeLimitations(),
    transactionAcceptedOnL2: true,
    verificationEventObserved: true,
    l2ToL1MessageObserved: true,
    l1MessageAvailabilityConfirmed: false,
    l1MessageConsumed: false,
    l1FactAnchored: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export function verifyStarknetFactVerificationEvent(
  receipt: StarknetFactPublicationTransactionReceipt,
  signedTransaction: SignedStarknetFactPublicationTransaction
): StarknetFactVerificationEventResult {
  const eventSelector = normalizeHex(starknetHash.getSelectorFromName("ProofInputHashFactVerified"));
  const errors: string[] = [];
  const match = receipt.events.find((event) =>
    normalizeHex(event.fromAddress) === normalizeHex(signedTransaction.binding.publicationContractAddress)
    && event.keys.map(normalizeHex).includes(eventSelector)
  );
  if (!match) return Object.freeze({ status: "missing", errors: ["verification event missing"] });
  const [factHigh, factLow] = match.data.map(normalizeHex);
  if (factHigh !== normalizeHex(signedTransaction.binding.factHigh)) errors.push("event fact high mismatch");
  if (factLow !== normalizeHex(signedTransaction.binding.factLow)) errors.push("event fact low mismatch");
  if (errors.length > 0) return Object.freeze({ status: "mismatch", errors });
  return Object.freeze({
    status: "observed",
    event: Object.freeze({
      contractAddress: normalizeHex(match.fromAddress),
      transactionHash: normalizeHex(receipt.transactionHash),
      eventSelector,
      factHigh,
      factLow,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash
    }),
    errors: Object.freeze([])
  });
}

export function verifyStarknetL2ToL1MessageEvidence(
  receipt: StarknetFactPublicationTransactionReceipt,
  signedTransaction: SignedStarknetFactPublicationTransaction
): StarknetL2ToL1MessageEvidenceResult {
  const errors: string[] = [];
  const match = receipt.messagesSent.find((message) =>
    normalizeHex(message.fromAddress) === normalizeHex(signedTransaction.binding.publicationContractAddress)
    && normalizeHex(message.toAddress) === normalizeHex(signedTransaction.binding.l1Recipient)
  );
  if (!match) return Object.freeze({ status: "missing", errors: ["L2-to-L1 message missing"] });
  if (match.payload.length !== 2) errors.push("message payload length mismatch");
  const [factHigh, factLow] = match.payload.map(normalizeHex);
  if (factHigh !== normalizeHex(signedTransaction.binding.factHigh)) errors.push("message fact high mismatch");
  if (factLow !== normalizeHex(signedTransaction.binding.factLow)) errors.push("message fact low mismatch");
  if (errors.length > 0) return Object.freeze({ status: "mismatch", errors });
  return Object.freeze({
    status: "observed",
    evidence: Object.freeze({
      senderContract: normalizeHex(match.fromAddress),
      l1Recipient: normalizeHex(match.toAddress),
      payloadLength: 2,
      factHigh,
      factLow,
      transactionHash: normalizeHex(receipt.transactionHash),
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      messageHash: match.messageHash
    }),
    errors: Object.freeze([])
  });
}

export function createFixtureStarknetPublicationDeploymentReader(
  classHash: string,
  blockNumber = 1
): StarknetPublicationDeploymentReader {
  return {
    async getClassHash() {
      return {
        status: "found",
        classHash,
        blockNumber,
        blockHash: "0xabc"
      };
    }
  };
}

export function createUnavailableStarknetPublicationDeploymentReader(): StarknetPublicationDeploymentReader {
  return {
    async getClassHash() {
      return { status: "unavailable", error: "rpc unavailable" };
    }
  };
}

export function createFixtureStarknetTransactionSubmitter(): StarknetTransactionSubmitter {
  return {
    async submitSignedPublicationTransaction(request) {
      return {
        status: "submitted",
        transactionHash: request.transactionHash,
        submittedAt: nowIso()
      };
    }
  };
}

export function createUnavailableStarknetTransactionSubmitter(): StarknetTransactionSubmitter {
  return {
    async submitSignedPublicationTransaction() {
      return { status: "unavailable", error: "rpc unavailable" };
    }
  };
}

export function createFixtureStarknetReceiptReader(
  receipt: StarknetFactPublicationTransactionReceipt
): StarknetTransactionReceiptReader {
  return {
    async getTransactionReceipt() {
      return receipt;
    }
  };
}

export function createInMemoryStarknetSubmittedTransactionStore(): StarknetSubmittedTransactionStore {
  const hashes = new Set<string>();
  return {
    hasTransaction(transactionHash) {
      return hashes.has(normalizeHex(transactionHash));
    },
    addTransaction(transactionHash) {
      const normalized = normalizeHex(transactionHash);
      if (hashes.has(normalized)) {
        return { status: "duplicate", transactionHash: normalized, count: hashes.size };
      }
      hashes.add(normalized);
      return { status: "recorded", transactionHash: normalized, count: hashes.size };
    },
    clear() {
      hashes.clear();
    }
  };
}
