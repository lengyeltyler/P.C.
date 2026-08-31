import { Interface, getAddress, keccak256, solidityPacked, solidityPackedKeccak256 } from "ethers";
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
  StarknetFactPublicationReceiptArtifact,
  StarknetL2ToL1MessageEvidence
} from "./starknetSubmissionMonitoring.ts";
import type { RuntimeResult } from "./types.ts";

const FELT_MAX = (1n << 252n) - 1n;
const UINT128_MAX = (1n << 128n) - 1n;
const ANCHOR_METHOD = "consumeProofInputHashFactFromL2";
const ANCHOR_SIGNATURE = "consumeProofInputHashFactFromL2(uint256,uint256)";
const ANCHOR_INTERFACE = new Interface([
  "function consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow) returns (bytes32)",
  "function starknetMessaging() view returns (address)",
  "function sourceL2Verifier() view returns (uint256)"
]);
export const L1_FACT_ANCHOR_METHOD_SELECTOR = ANCHOR_INTERFACE.getFunction(ANCHOR_METHOD)?.selector
  ?? "0x00000000";

export type StarknetL2ToL1MessageEvidenceClass =
  | "live_starknet_receipt"
  | "local_devnet_receipt"
  | "fixture_receipt"
  | "manual_reference"
  | "unsupported";

export type StarknetL2ToL1MessageEvidenceStatus =
  | "message_identity_valid"
  | "message_identity_invalid"
  | "message_identity_untrusted";

export interface StarknetL2ToL1MessageSource {
  readonly evidenceClass: StarknetL2ToL1MessageEvidenceClass;
  readonly starknetNetworkProfileId: string;
  readonly starknetTransactionHash: string;
  readonly starknetBlockNumber?: number;
  readonly starknetBlockHash?: string;
  readonly publicationEventObserved: boolean;
}

export interface StarknetL2ToL1MessagePayload {
  readonly payloadLength: 2;
  readonly factHigh: string;
  readonly factLow: string;
}

export interface StarknetL2ToL1MessageHash {
  readonly algorithm: "starknet-l2-to-l1-keccak-abi-packed-v1";
  readonly value: string;
}

export interface StarknetL2ToL1MessageBinding {
  readonly l2Sender: string;
  readonly l1Recipient: string;
  readonly payload: StarknetL2ToL1MessagePayload;
  readonly proofInputHash: string;
  readonly messageHash: StarknetL2ToL1MessageHash;
  readonly auditCorrelationId: string;
}

export interface StarknetL2ToL1MessageIdentity {
  readonly status: StarknetL2ToL1MessageEvidenceStatus;
  readonly source: StarknetL2ToL1MessageSource;
  readonly binding: StarknetL2ToL1MessageBinding;
  readonly liveMessageEvidence: boolean;
  readonly productionSignable: boolean;
  readonly errors: readonly string[];
}

export interface StarknetL2ToL1MessageIdentityInput {
  readonly receiptArtifact: StarknetFactPublicationReceiptArtifact;
  readonly evidenceClass: StarknetL2ToL1MessageEvidenceClass;
  readonly expectedStarknetNetworkProfileId?: string;
  readonly expectedL2Sender?: string;
  readonly expectedL1Recipient?: string;
  readonly expectedProofInputHash?: string;
  readonly auditCorrelationId?: string;
}

export type EthereumL1MessageAvailabilityStatus =
  | "message_available"
  | "message_not_available"
  | "message_already_consumed"
  | "message_state_unknown"
  | "messaging_core_unavailable";

export type EthereumL1MessageAvailabilityOutcome =
  | "message_available"
  | "message_not_available"
  | "message_already_consumed"
  | "message_state_unknown"
  | "messaging_core_unavailable"
  | "message_identity_mismatch"
  | "wrong_l2_sender"
  | "wrong_l1_recipient"
  | "wrong_payload"
  | "network_mismatch"
  | "stale_read"
  | "malformed"
  | "unsupported";

export type EthereumL1MessageAvailabilityReason =
  | "read_only_message_count_available"
  | "read_only_message_count_zero"
  | "message_count_consumed_or_absent"
  | "reader_unavailable"
  | "identity_rejected"
  | "freshness_rejected";

export interface EthereumL1MessageAvailabilityRequest {
  readonly requestId: string;
  readonly messageIdentity: StarknetL2ToL1MessageIdentity;
  readonly ethereumNetworkProfileId: string;
  readonly ethereumChainId: number;
  readonly messagingCoreAddress: string;
  readonly anchorAddress: string;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly freshnessMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface EthereumL1MessageAvailabilityResultValue {
  readonly status: EthereumL1MessageAvailabilityStatus;
  readonly outcome: EthereumL1MessageAvailabilityOutcome;
  readonly reason: EthereumL1MessageAvailabilityReason;
  readonly messageIdentity: StarknetL2ToL1MessageIdentity;
  readonly messageHash: string;
  readonly messageCount?: string;
  readonly checkedAt: string;
  readonly ethereumNetworkProfileId: string;
  readonly ethereumChainId: number;
  readonly messagingCoreAddress: string;
  readonly anchorAddress: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly readerSource: "fixture" | "rpc_view" | "manual" | "unavailable";
  readonly stale: boolean;
  readonly raceWarning: string;
  readonly l2ToL1MessageConsumed: false;
  readonly l1FactAnchored: false;
  readonly chainStateMutated: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type EthereumL1MessageAvailabilityResult =
  RuntimeResult<EthereumL1MessageAvailabilityResultValue>;

export interface EthereumL1MessageAvailabilityReader {
  readMessageAvailability(
    request: EthereumL1MessageAvailabilityRequest
  ): Promise<EthereumL1MessageAvailabilityReaderResult>;
}

export interface EthereumL1MessageAvailabilityReaderResult {
  readonly status: EthereumL1MessageAvailabilityStatus;
  readonly messageHash: string;
  readonly messageCount?: string;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly readerSource: "fixture" | "rpc_view" | "manual" | "unavailable";
  readonly error?: string;
}

export interface L1FactAnchorNetworkProfile {
  readonly profileId: string;
  readonly ethereumNetwork: "hardhat" | "ethereum_sepolia" | "ethereum_mainnet" | "local_devnet";
  readonly ethereumChainId: number;
  readonly enabled: boolean;
  readonly rpcReference?: string;
}

export interface L1StarknetMessagingCoreReference {
  readonly address: string;
  readonly exposesReadOnlyMessageCount: boolean;
  readonly consumeMethodSignature: "consumeMessageFromL2(uint256,uint256[])";
}

export interface L1ExpectedStarknetSenderBinding {
  readonly starknetNetworkProfileId: string;
  readonly sourceL2Verifier: string;
  readonly l1Recipient: string;
  readonly payloadShape: "[fact_high,fact_low]";
}

export interface L1FactAnchorDeploymentReference {
  readonly address: string;
  readonly approved: boolean;
  readonly deployedCodeHash?: string;
  readonly abiSha256?: string;
  readonly methodSelector: string;
}

export interface L1FactAnchorConfiguration {
  readonly configurationId: string;
  readonly approvalStatus: "accepted" | "draft" | "rejected";
  readonly activeProfileId: string;
  readonly networkProfiles: Readonly<Record<string, L1FactAnchorNetworkProfile>>;
  readonly anchorDeployment: L1FactAnchorDeploymentReference;
  readonly messagingCore: L1StarknetMessagingCoreReference;
  readonly expectedStarknetSender: L1ExpectedStarknetSenderBinding;
  readonly mainnetAllowed: false;
}

export type L1AnchorConfigurationStatus =
  | "configuration_valid"
  | "configuration_invalid";

export interface L1FactAnchorDeploymentVerificationRequest {
  readonly requestId: string;
  readonly configuration: L1FactAnchorConfiguration;
  readonly deploymentReader: L1FactAnchorDeploymentReader;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1FactAnchorDeploymentVerificationResultValue {
  readonly status: "deployment_verified" | "deployment_invalid";
  readonly outcome:
    | "deployment_verified"
    | "anchor_address_missing"
    | "anchor_code_missing"
    | "anchor_code_hash_mismatch"
    | "messaging_core_mismatch"
    | "source_l2_verifier_mismatch"
    | "selector_mismatch"
    | "network_mismatch"
    | "approval_missing"
    | "reader_unavailable"
    | "malformed";
  readonly configuration: L1FactAnchorConfiguration;
  readonly anchorAddress: string;
  readonly messagingCoreAddress: string;
  readonly sourceL2Verifier: string;
  readonly methodSelector: string;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1FactAnchorDeploymentVerificationResult =
  RuntimeResult<L1FactAnchorDeploymentVerificationResultValue>;

export interface L1FactAnchorDeploymentReader {
  readDeployment(
    request: L1FactAnchorDeploymentVerificationRequest
  ): Promise<L1FactAnchorDeploymentReadResult>;
}

export interface L1FactAnchorDeploymentReadResult {
  readonly status: "found" | "not_found" | "unavailable";
  readonly anchorAddress: string;
  readonly codeHash?: string;
  readonly starknetMessagingAddress?: string;
  readonly sourceL2Verifier?: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly error?: string;
}

export type L1FactAnchorTransactionStatus =
  | "anchor_transaction_draft_created"
  | "anchor_transaction_draft_rejected";

export type L1FactAnchorTransactionOutcome =
  | "anchor_transaction_draft_created"
  | "message_evidence_ineligible"
  | "message_not_available"
  | "message_already_consumed"
  | "message_state_unknown"
  | "anchor_configuration_invalid"
  | "anchor_deployment_invalid"
  | "wrong_sender"
  | "wrong_recipient"
  | "payload_mismatch"
  | "proof_input_hash_mismatch"
  | "network_mismatch"
  | "calldata_encoding_failed"
  | "gas_estimate_unavailable"
  | "nonce_unresolved"
  | "expired"
  | "malformed"
  | "unsupported";

export type L1FactAnchorTransactionReason =
  | "ready_for_future_l1_signing_review"
  | "message_or_availability_rejected"
  | "configuration_or_deployment_rejected"
  | "calldata_encoded"
  | "gas_nonce_fee_unresolved";

export type L1FactAnchorTransactionLimitation =
  | "unsigned_draft_only"
  | "not_submittable"
  | "message_not_consumed"
  | "fact_not_anchored"
  | "availability_read_is_snapshot"
  | "revalidate_before_signing_or_submission"
  | "no_l1_to_base_relay"
  | "no_base_execution"
  | "no_nullifier_consumption"
  | "fixture_not_production_signable";

export interface L1FactAnchorGasEstimateReference {
  readonly status: "estimated" | "unavailable" | "unresolved";
  readonly gasLimit?: string;
  readonly checkedAt?: string;
  readonly source: "fixture" | "rpc_estimate" | "none";
}

export interface L1FactAnchorNonceReference {
  readonly status: "resolved" | "unresolved";
  readonly nonce?: string;
  readonly checkedAt?: string;
  readonly source: "fixture" | "rpc" | "none";
  readonly nonceReserved: false;
}

export interface L1FactAnchorFeeDataReference {
  readonly status: "resolved" | "unresolved";
  readonly maxFeePerGas?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly checkedAt?: string;
  readonly source: "fixture" | "rpc" | "none";
}

export interface L1FactAnchorTransactionBinding {
  readonly ethereumNetworkProfileId: string;
  readonly ethereumChainId: number;
  readonly anchorAddress: string;
  readonly messagingCoreAddress: string;
  readonly sourceL2Verifier: string;
  readonly l1Recipient: string;
  readonly starknetTransactionHash: string;
  readonly messageHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly auditCorrelationId: string;
}

export interface L1FactAnchorTransactionDraft {
  readonly l1FactAnchorTransactionDraftId: string;
  readonly status: "anchor_transaction_draft_created";
  readonly outcome: "anchor_transaction_draft_created";
  readonly binding: L1FactAnchorTransactionBinding;
  readonly to: string;
  readonly value: "0";
  readonly methodName: typeof ANCHOR_METHOD;
  readonly methodSignature: typeof ANCHOR_SIGNATURE;
  readonly methodSelector: string;
  readonly calldata: string;
  readonly calldataHash: string;
  readonly gas: L1FactAnchorGasEstimateReference;
  readonly nonce: L1FactAnchorNonceReference;
  readonly fee: L1FactAnchorFeeDataReference;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly availabilityCheckedAt: string;
  readonly availabilityBlockNumber?: number;
  readonly availabilityBlockHash?: string;
  readonly raceWarning: string;
  readonly limitations: readonly L1FactAnchorTransactionLimitation[];
  readonly liveMessageEvidence: boolean;
  readonly productionSignable: boolean;
  readonly transactionPrepared: true;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly l2ToL1MessageConsumed: false;
  readonly l1FactAnchored: false;
  readonly l1ToBaseRelayPrepared: false;
  readonly baseFactMirrored: false;
  readonly nullifierConsumed: false;
  readonly chainStateMutated: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1FactAnchorTransactionPreparationResult =
  RuntimeResult<L1FactAnchorTransactionDraft>;

export interface L1FactAnchorTransactionPreparationRequest {
  readonly requestId: string;
  readonly messageIdentity: StarknetL2ToL1MessageIdentity;
  readonly availabilityReader: EthereumL1MessageAvailabilityReader;
  readonly deploymentReader: L1FactAnchorDeploymentReader;
  readonly configuration: L1FactAnchorConfiguration;
  readonly senderAccount?: string;
  readonly value?: string;
  readonly gasEstimator?: EthereumL1GasEstimator;
  readonly nonceReader?: EthereumL1NonceReader;
  readonly feeDataReader?: EthereumL1FeeDataReader;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface EthereumL1GasEstimator {
  estimateGas(request: L1FactAnchorTransactionPreparationRequest): Promise<L1FactAnchorGasEstimateReference>;
}

export interface EthereumL1NonceReader {
  readNonce(request: L1FactAnchorTransactionPreparationRequest): Promise<L1FactAnchorNonceReference>;
}

export interface EthereumL1FeeDataReader {
  readFeeData(request: L1FactAnchorTransactionPreparationRequest): Promise<L1FactAnchorFeeDataReference>;
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeHex(value: string): string {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.replace(/^0+/, "") || "0";
  return `0x${normalized.toLowerCase()}`;
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function isHex(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value);
}

function isFelt(value: unknown): value is string {
  if (!isHex(value)) return false;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= FELT_MAX;
  } catch {
    return false;
  }
}

function splitProofInputHash(proofInputHash: string): readonly [string, string] | undefined {
  if (!isHex(proofInputHash)) return undefined;
  const value = BigInt(proofInputHash);
  const high = value >> 128n;
  const low = value & UINT128_MAX;
  return [`0x${high.toString(16)}`, `0x${low.toString(16)}`];
}

function addressesEqual(a: string, b: string): boolean {
  try {
    return normalizeAddress(a) === normalizeAddress(b);
  } catch {
    return normalizeHex(a) === normalizeHex(b);
  }
}

export function deriveCanonicalStarknetL2ToL1MessageHash(input: {
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly payload: readonly [string, string];
}): string {
  const packed = solidityPacked(
    ["uint256", "uint256", "uint256", "uint256[]"],
    [BigInt(input.fromAddress), BigInt(input.toAddress), 2n, input.payload.map((item) => BigInt(item))]
  );
  return keccak256(packed);
}

export function encodeL1FactAnchorCalldata(input: {
  readonly factHigh: string;
  readonly factLow: string;
}): string {
  return ANCHOR_INTERFACE.encodeFunctionData(ANCHOR_METHOD, [
    BigInt(input.factHigh),
    BigInt(input.factLow)
  ]);
}

export function validateStarknetL2ToL1MessageIdentity(
  identity: StarknetL2ToL1MessageIdentity
): RuntimeValidationResult {
  const errors: string[] = [];
  if (identity.status !== "message_identity_valid") errors.push("message identity is not valid");
  if (!isFelt(identity.binding.l2Sender)) errors.push("L2 sender must be a felt");
  try {
    normalizeAddress(identity.binding.l1Recipient);
  } catch {
    errors.push("L1 recipient must be an Ethereum address");
  }
  if (identity.binding.payload.payloadLength !== 2) errors.push("payload length must be 2");
  if (!isFelt(identity.binding.payload.factHigh)) errors.push("factHigh must be a felt");
  if (!isFelt(identity.binding.payload.factLow)) errors.push("factLow must be a felt");
  const split = splitProofInputHash(identity.binding.proofInputHash);
  if (!split) {
    errors.push("proofInputHash invalid");
  } else {
    const [expectedHigh, expectedLow] = split;
    if (normalizeHex(expectedHigh) !== normalizeHex(identity.binding.payload.factHigh)) {
      errors.push("proofInputHash high split mismatch");
    }
    if (normalizeHex(expectedLow) !== normalizeHex(identity.binding.payload.factLow)) {
      errors.push("proofInputHash low split mismatch");
    }
  }
  const derivedHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: identity.binding.l2Sender,
    toAddress: identity.binding.l1Recipient,
    payload: [identity.binding.payload.factHigh, identity.binding.payload.factLow]
  });
  if (normalizeHex(derivedHash) !== normalizeHex(identity.binding.messageHash.value)) {
    errors.push("message hash mismatch");
  }
  return validation(errors);
}

export function createStarknetL2ToL1MessageIdentity(
  input: StarknetL2ToL1MessageIdentityInput
): StarknetL2ToL1MessageIdentity {
  const errors: string[] = [];
  const artifact = input.receiptArtifact;
  const message: StarknetL2ToL1MessageEvidence | undefined = artifact.l2ToL1Message;
  if (!artifact.verificationEventObserved) errors.push("verification event not observed");
  if (!artifact.l2ToL1MessageObserved) errors.push("L2-to-L1 message not observed");
  if (!message) errors.push("message evidence missing");
  if (input.expectedStarknetNetworkProfileId && artifact.networkProfileId !== input.expectedStarknetNetworkProfileId) {
    errors.push("Starknet network profile mismatch");
  }
  if (message && input.expectedL2Sender && normalizeHex(message.senderContract) !== normalizeHex(input.expectedL2Sender)) {
    errors.push("L2 sender mismatch");
  }
  if (message && input.expectedL1Recipient && !addressesEqual(message.l1Recipient, input.expectedL1Recipient)) {
    errors.push("L1 recipient mismatch");
  }
  if (input.expectedProofInputHash && normalizeHex(artifact.proofInputHash) !== normalizeHex(input.expectedProofInputHash)) {
    errors.push("proofInputHash mismatch");
  }
  if (message?.payloadLength !== 2) errors.push("payload length mismatch");
  const factHigh = message?.factHigh ?? artifact.factHigh;
  const factLow = message?.factLow ?? artifact.factLow;
  if (normalizeHex(factHigh) !== normalizeHex(artifact.factHigh)) errors.push("fact high mismatch");
  if (normalizeHex(factLow) !== normalizeHex(artifact.factLow)) errors.push("fact low mismatch");
  const derivedHash = message ? deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: message.senderContract,
    toAddress: message.l1Recipient,
    payload: [message.factHigh, message.factLow]
  }) : "0x0";
  if (message?.messageHash && normalizeHex(message.messageHash) !== normalizeHex(derivedHash)) {
    errors.push("message hash mismatch");
  }
  const liveMessageEvidence = input.evidenceClass === "live_starknet_receipt";
  const productionSignable = liveMessageEvidence && errors.length === 0;
  const auditCorrelationId = input.auditCorrelationId ?? artifact.auditCorrelationId;
  const identity: StarknetL2ToL1MessageIdentity = Object.freeze({
    status: errors.length === 0
      ? "message_identity_valid"
      : input.evidenceClass === "manual_reference"
        ? "message_identity_untrusted"
        : "message_identity_invalid",
    source: Object.freeze({
      evidenceClass: input.evidenceClass,
      starknetNetworkProfileId: artifact.networkProfileId,
      starknetTransactionHash: artifact.transactionHash,
      starknetBlockNumber: artifact.blockNumber,
      starknetBlockHash: artifact.blockHash,
      publicationEventObserved: artifact.verificationEventObserved
    }),
    binding: Object.freeze({
      l2Sender: normalizeHex(message?.senderContract ?? "0x0"),
      l1Recipient: message?.l1Recipient ? normalizeAddress(message.l1Recipient) : "0x0000000000000000000000000000000000000000",
      payload: Object.freeze({
        payloadLength: 2,
        factHigh: normalizeHex(factHigh),
        factLow: normalizeHex(factLow)
      }),
      proofInputHash: normalizeHex(artifact.proofInputHash),
      messageHash: Object.freeze({
        algorithm: "starknet-l2-to-l1-keccak-abi-packed-v1" as const,
        value: normalizeHex(message?.messageHash ?? derivedHash)
      }),
      auditCorrelationId
    }),
    liveMessageEvidence,
    productionSignable,
    errors: Object.freeze(errors)
  });
  const validationResult = validateStarknetL2ToL1MessageIdentity(identity);
  if (!validationResult.valid && errors.length === 0) {
    return Object.freeze({ ...identity, status: "message_identity_invalid", errors: Object.freeze(validationResult.errors) });
  }
  return identity;
}

function createAvailabilityAuditDraft(input: {
  readonly request: EthereumL1MessageAvailabilityRequest;
  readonly outcome: EthereumL1MessageAvailabilityOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "message_available" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1MessageAvailability",
    summary: input.outcome === "message_available"
      ? "Ethereum L1 message availability read succeeded."
      : "Ethereum L1 message availability read was blocked or unavailable.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      messageHash: input.request.messageIdentity.binding.messageHash.value,
      l2Sender: input.request.messageIdentity.binding.l2Sender,
      l1Recipient: input.request.messageIdentity.binding.l1Recipient,
      proofInputHash: input.request.messageIdentity.binding.proofInputHash,
      factPair: [
        input.request.messageIdentity.binding.payload.factHigh,
        input.request.messageIdentity.binding.payload.factLow
      ],
      ethereumChainId: input.request.ethereumChainId,
      anchorAddress: input.request.anchorAddress
    }
  });
}

function createPreparationAuditDraft(input: {
  readonly request: L1FactAnchorTransactionPreparationRequest;
  readonly outcome: L1FactAnchorTransactionOutcome;
  readonly calldataHash?: string;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "anchor_transaction_draft_created" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1FactAnchorTransactionPreparation",
    summary: input.outcome === "anchor_transaction_draft_created"
      ? "Unsigned Ethereum L1 fact-anchor transaction draft created."
      : "Ethereum L1 fact-anchor transaction preparation was blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      messageHash: input.request.messageIdentity.binding.messageHash.value,
      anchorAddress: input.request.configuration.anchorDeployment.address,
      methodSelector: L1_FACT_ANCHOR_METHOD_SELECTOR,
      calldataHash: input.calldataHash,
      proofInputHash: input.request.messageIdentity.binding.proofInputHash,
      factPair: [
        input.request.messageIdentity.binding.payload.factHigh,
        input.request.messageIdentity.binding.payload.factLow
      ]
    }
  });
}

function availabilityOutcomeForStatus(
  status: EthereumL1MessageAvailabilityStatus
): EthereumL1MessageAvailabilityOutcome {
  if (status === "message_available") return "message_available";
  if (status === "message_not_available") return "message_not_available";
  if (status === "message_already_consumed") return "message_already_consumed";
  if (status === "messaging_core_unavailable") return "messaging_core_unavailable";
  return "message_state_unknown";
}

export async function requestL1MessageAvailability(
  request: EthereumL1MessageAvailabilityRequest,
  reader: EthereumL1MessageAvailabilityReader
): Promise<EthereumL1MessageAvailabilityResult> {
  const errors: string[] = [];
  if (!request.requestId) errors.push("requestId is required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("availability request expired");
  const identityValidation = validateStarknetL2ToL1MessageIdentity(request.messageIdentity);
  errors.push(...identityValidation.errors);
  if (request.messageIdentity.status !== "message_identity_valid") errors.push("message identity invalid");
  if (!addressesEqual(request.anchorAddress, request.messageIdentity.binding.l1Recipient)) {
    errors.push("anchor address and message recipient mismatch");
  }
  if (errors.length > 0) {
    const auditEventDraft = createAvailabilityAuditDraft({ request, outcome: "message_identity_mismatch", errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_MESSAGE_AVAILABILITY_REJECTED",
      category: "invalid_intent",
      message: "Ethereum L1 message availability request is malformed or mismatched.",
      recoverable: true,
      details: { outcome: "message_identity_mismatch", errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const read = await reader.readMessageAvailability(request);
  const stale = Boolean(request.freshnessMs && Date.now() - Date.parse(read.checkedAt) > request.freshnessMs);
  const outcome = stale ? "stale_read" : availabilityOutcomeForStatus(read.status);
  const auditEventDraft = createAvailabilityAuditDraft({ request, outcome, errors: read.error ? [read.error] : [] });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const value: EthereumL1MessageAvailabilityResultValue = Object.freeze({
    status: read.status,
    outcome,
    reason: read.status === "message_available"
      ? "read_only_message_count_available"
      : read.status === "message_not_available"
        ? "read_only_message_count_zero"
        : read.status === "message_already_consumed"
          ? "message_count_consumed_or_absent"
          : read.status === "messaging_core_unavailable"
            ? "reader_unavailable"
            : "reader_unavailable",
    messageIdentity: request.messageIdentity,
    messageHash: normalizeHex(read.messageHash),
    messageCount: read.messageCount,
    checkedAt: read.checkedAt,
    ethereumNetworkProfileId: request.ethereumNetworkProfileId,
    ethereumChainId: request.ethereumChainId,
    messagingCoreAddress: normalizeAddress(request.messagingCoreAddress),
    anchorAddress: normalizeAddress(request.anchorAddress),
    blockNumber: read.blockNumber,
    blockHash: read.blockHash,
    readerSource: read.readerSource,
    stale,
    raceWarning: "Message availability is a read-only snapshot. Revalidate before signing or submission.",
    l2ToL1MessageConsumed: false,
    l1FactAnchored: false,
    chainStateMutated: false,
    auditEventDraft,
    auditDraftCollectionResult
  });
  if (outcome !== "message_available") {
    return runtimeDenied({
      code: "L1_MESSAGE_NOT_AVAILABLE",
      category: "network_unavailable",
      message: "Ethereum L1 message is not available for anchoring.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  return runtimeOk(value);
}

function validateL1FactAnchorConfiguration(
  config: L1FactAnchorConfiguration
): RuntimeValidationResult {
  const errors: string[] = [];
  const profile = config.networkProfiles[config.activeProfileId];
  if (!profile) errors.push("active network profile missing");
  if (profile?.enabled !== true) errors.push("network profile not enabled");
  if (profile?.ethereumNetwork === "ethereum_mainnet") errors.push("mainnet prohibited");
  if (config.mainnetAllowed !== false) errors.push("mainnetAllowed must be false");
  if (config.approvalStatus !== "accepted") errors.push("configuration approval missing");
  if (!config.anchorDeployment.approved) errors.push("anchor deployment approval missing");
  try {
    normalizeAddress(config.anchorDeployment.address);
  } catch {
    errors.push("anchor address invalid");
  }
  try {
    normalizeAddress(config.messagingCore.address);
  } catch {
    errors.push("messaging core address invalid");
  }
  try {
    normalizeAddress(config.expectedStarknetSender.l1Recipient);
  } catch {
    errors.push("expected L1 recipient invalid");
  }
  if (!isFelt(config.expectedStarknetSender.sourceL2Verifier)) errors.push("source L2 verifier invalid");
  if (config.expectedStarknetSender.payloadShape !== "[fact_high,fact_low]") {
    errors.push("payload shape invalid");
  }
  if (normalizeHex(config.anchorDeployment.methodSelector) !== normalizeHex(L1_FACT_ANCHOR_METHOD_SELECTOR)) {
    errors.push("method selector mismatch");
  }
  return validation(errors);
}

export async function verifyL1FactAnchorDeployment(
  request: L1FactAnchorDeploymentVerificationRequest
): Promise<L1FactAnchorDeploymentVerificationResult> {
  const errors: string[] = [];
  errors.push(...validateL1FactAnchorConfiguration(request.configuration).errors);
  if (!request.requestId) errors.push("requestId is required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("deployment verification expired");
  let read: L1FactAnchorDeploymentReadResult | undefined;
  if (errors.length === 0) {
    read = await request.deploymentReader.readDeployment(request);
    if (read.status !== "found") errors.push("anchor code missing or reader unavailable");
    if (read.codeHash && request.configuration.anchorDeployment.deployedCodeHash
      && normalizeHex(read.codeHash) !== normalizeHex(request.configuration.anchorDeployment.deployedCodeHash)) {
      errors.push("anchor code hash mismatch");
    }
    if (read.starknetMessagingAddress && !addressesEqual(read.starknetMessagingAddress, request.configuration.messagingCore.address)) {
      errors.push("messaging core mismatch");
    }
    if (read.sourceL2Verifier && normalizeHex(read.sourceL2Verifier) !== normalizeHex(request.configuration.expectedStarknetSender.sourceL2Verifier)) {
      errors.push("source L2 verifier mismatch");
    }
  }
  const outcome = errors.length === 0
    ? "deployment_verified"
    : errors.join(" | ").includes("messaging")
      ? "messaging_core_mismatch"
      : errors.join(" | ").includes("source L2")
        ? "source_l2_verifier_mismatch"
        : errors.join(" | ").includes("selector")
          ? "selector_mismatch"
          : errors.join(" | ").includes("approval")
            ? "approval_missing"
            : errors.join(" | ").includes("network")
              ? "network_mismatch"
              : errors.join(" | ").includes("code hash")
                ? "anchor_code_hash_mismatch"
                : errors.join(" | ").includes("code missing")
                  ? "anchor_code_missing"
                  : "malformed";
  const value = Object.freeze({
    status: errors.length === 0 ? "deployment_verified" as const : "deployment_invalid" as const,
    outcome,
    configuration: request.configuration,
    anchorAddress: normalizeAddress(request.configuration.anchorDeployment.address),
    messagingCoreAddress: normalizeAddress(request.configuration.messagingCore.address),
    sourceL2Verifier: normalizeHex(request.configuration.expectedStarknetSender.sourceL2Verifier),
    methodSelector: normalizeHex(request.configuration.anchorDeployment.methodSelector),
    checkedAt: nowIso(),
    blockNumber: read?.blockNumber,
    blockHash: read?.blockHash
  });
  if (errors.length > 0) {
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "Ethereum L1 fact-anchor deployment verification failed.",
      recoverable: true,
      details: { outcome, errors }
    });
  }
  return runtimeOk(value);
}

export function validateL1FactAnchorPreparationRequest(
  request: L1FactAnchorTransactionPreparationRequest
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!request.requestId) errors.push("requestId is required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("preparation request expired");
  if (request.value && request.value !== "0") errors.push("nonpayable anchor value must be zero");
  const identity = request.messageIdentity;
  errors.push(...validateStarknetL2ToL1MessageIdentity(identity).errors);
  const configValidation = validateL1FactAnchorConfiguration(request.configuration);
  errors.push(...configValidation.errors);
  const profile = request.configuration.networkProfiles[request.configuration.activeProfileId];
  if (profile && profile.ethereumChainId <= 0) errors.push("chain ID invalid");
  if (normalizeHex(identity.binding.l2Sender) !== normalizeHex(request.configuration.expectedStarknetSender.sourceL2Verifier)) {
    errors.push("wrong sender");
  }
  if (!addressesEqual(identity.binding.l1Recipient, request.configuration.expectedStarknetSender.l1Recipient)) {
    errors.push("wrong recipient");
  }
  if (!addressesEqual(identity.binding.l1Recipient, request.configuration.anchorDeployment.address)) {
    errors.push("message recipient must equal L1 anchor address");
  }
  if (identity.source.starknetNetworkProfileId !== request.configuration.expectedStarknetSender.starknetNetworkProfileId) {
    errors.push("Starknet network mismatch");
  }
  return validation(errors);
}

function outcomeForPreparationErrors(errors: readonly string[]): L1FactAnchorTransactionOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("expired")) return "expired";
  if (joined.includes("sender")) return "wrong_sender";
  if (joined.includes("recipient")) return "wrong_recipient";
  if (joined.includes("payload")) return "payload_mismatch";
  if (joined.includes("proofInputHash")) return "proof_input_hash_mismatch";
  if (joined.includes("network")) return "network_mismatch";
  if (joined.includes("selector") || joined.includes("configuration") || joined.includes("approval")) {
    return "anchor_configuration_invalid";
  }
  if (joined.includes("value")) return "malformed";
  return "malformed";
}

export async function prepareL1FactAnchorTransaction(
  request: L1FactAnchorTransactionPreparationRequest
): Promise<L1FactAnchorTransactionPreparationResult> {
  const validationResult = validateL1FactAnchorPreparationRequest(request);
  if (!validationResult.valid) {
    const outcome = outcomeForPreparationErrors(validationResult.errors);
    const auditEventDraft = createPreparationAuditDraft({ request, outcome, errors: validationResult.errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_PREPARATION_REJECTED",
      category: "invalid_intent",
      message: "Ethereum L1 fact-anchor transaction preparation was rejected.",
      recoverable: true,
      details: { outcome, errors: validationResult.errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const profile = request.configuration.networkProfiles[request.configuration.activeProfileId];
  const availability = await requestL1MessageAvailability({
    requestId: `${request.requestId}:availability`,
    messageIdentity: request.messageIdentity,
    ethereumNetworkProfileId: profile.profileId,
    ethereumChainId: profile.ethereumChainId,
    messagingCoreAddress: request.configuration.messagingCore.address,
    anchorAddress: request.configuration.anchorDeployment.address,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    freshnessMs: 60_000,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  }, request.availabilityReader);
  if (availability.status !== "approved") {
    const availabilityDetails = availability.error?.details;
    const outcome = availabilityDetails?.outcome === "message_already_consumed"
      ? "message_already_consumed"
      : availabilityDetails?.outcome === "message_state_unknown"
        ? "message_state_unknown"
        : "message_not_available";
    const auditEventDraft = createPreparationAuditDraft({ request, outcome });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_MESSAGE_UNAVAILABLE",
      category: "network_unavailable",
      message: "Ethereum L1 message is not available for anchor transaction preparation.",
      recoverable: true,
      details: { outcome, availability: availabilityDetails, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const deployment = await verifyL1FactAnchorDeployment({
    requestId: `${request.requestId}:deployment`,
    configuration: request.configuration,
    deploymentReader: request.deploymentReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  });
  if (deployment.status !== "approved") {
    const deploymentDetails = deployment.error?.details;
    const auditEventDraft = createPreparationAuditDraft({
      request,
      outcome: "anchor_deployment_invalid",
      errors: deploymentDetails?.errors as readonly string[] | undefined
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "Ethereum L1 fact-anchor deployment is invalid.",
      recoverable: true,
      details: { outcome: "anchor_deployment_invalid", deployment: deploymentDetails }
    });
  }
  const availabilityValue = availability.value;
  if (!availabilityValue) {
    return runtimeDenied({
      code: "L1_MESSAGE_AVAILABILITY_MISSING_VALUE",
      category: "network_unavailable",
      message: "Ethereum L1 message availability result did not include a value.",
      recoverable: true,
      details: { outcome: "message_state_unknown" }
    });
  }
  let calldata: string;
  try {
    calldata = encodeL1FactAnchorCalldata({
      factHigh: request.messageIdentity.binding.payload.factHigh,
      factLow: request.messageIdentity.binding.payload.factLow
    });
  } catch (error) {
    const auditEventDraft = createPreparationAuditDraft({
      request,
      outcome: "calldata_encoding_failed",
      errors: [error instanceof Error ? error.message : "calldata encoding failed"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_FACT_ANCHOR_CALLDATA_ENCODING_FAILED",
      category: "invalid_intent",
      message: "Ethereum L1 fact-anchor calldata encoding failed.",
      recoverable: true,
      details: { outcome: "calldata_encoding_failed", auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const gas = request.gasEstimator
    ? await request.gasEstimator.estimateGas(request)
    : Object.freeze({ status: "unresolved" as const, source: "none" as const });
  const nonce = request.nonceReader
    ? await request.nonceReader.readNonce(request)
    : Object.freeze({ status: "unresolved" as const, source: "none" as const, nonceReserved: false as const });
  const fee = request.feeDataReader
    ? await request.feeDataReader.readFeeData(request)
    : Object.freeze({ status: "unresolved" as const, source: "none" as const });
  const calldataHash = keccak256(calldata);
  const auditEventDraft = createPreparationAuditDraft({
    request,
    outcome: "anchor_transaction_draft_created",
    calldataHash
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const limitations: L1FactAnchorTransactionLimitation[] = [
    "unsigned_draft_only",
    "not_submittable",
    "message_not_consumed",
    "fact_not_anchored",
    "availability_read_is_snapshot",
    "revalidate_before_signing_or_submission",
    "no_l1_to_base_relay",
    "no_base_execution",
    "no_nullifier_consumption"
  ];
  if (!request.messageIdentity.liveMessageEvidence) limitations.push("fixture_not_production_signable");
  return runtimeOk(Object.freeze({
    l1FactAnchorTransactionDraftId: createAuditCorrelationId([
      request.messageIdentity.binding.messageHash.value,
      "l1-fact-anchor-draft"
    ]),
    status: "anchor_transaction_draft_created",
    outcome: "anchor_transaction_draft_created",
    binding: Object.freeze({
      ethereumNetworkProfileId: profile.profileId,
      ethereumChainId: profile.ethereumChainId,
      anchorAddress: normalizeAddress(request.configuration.anchorDeployment.address),
      messagingCoreAddress: normalizeAddress(request.configuration.messagingCore.address),
      sourceL2Verifier: normalizeHex(request.configuration.expectedStarknetSender.sourceL2Verifier),
      l1Recipient: normalizeAddress(request.configuration.expectedStarknetSender.l1Recipient),
      starknetTransactionHash: request.messageIdentity.source.starknetTransactionHash,
      messageHash: request.messageIdentity.binding.messageHash.value,
      proofInputHash: request.messageIdentity.binding.proofInputHash,
      factHigh: request.messageIdentity.binding.payload.factHigh,
      factLow: request.messageIdentity.binding.payload.factLow,
      auditCorrelationId: request.auditCorrelationId ?? request.messageIdentity.binding.auditCorrelationId
    }),
    to: normalizeAddress(request.configuration.anchorDeployment.address),
    value: "0",
    methodName: ANCHOR_METHOD,
    methodSignature: ANCHOR_SIGNATURE,
    methodSelector: normalizeHex(L1_FACT_ANCHOR_METHOD_SELECTOR),
    calldata,
    calldataHash,
    gas,
    nonce,
    fee,
    issuedAt: request.issueTime,
    expiresAt: request.expiresAt,
    availabilityCheckedAt: availabilityValue.checkedAt,
    availabilityBlockNumber: availabilityValue.blockNumber,
    availabilityBlockHash: availabilityValue.blockHash,
    raceWarning: availabilityValue.raceWarning,
    limitations: Object.freeze(limitations),
    liveMessageEvidence: request.messageIdentity.liveMessageEvidence,
    productionSignable: request.messageIdentity.productionSignable
      && gas.status === "estimated"
      && nonce.status === "resolved"
      && fee.status === "resolved",
    transactionPrepared: true,
    transactionSigned: false,
    transactionSubmitted: false,
    l2ToL1MessageConsumed: false,
    l1FactAnchored: false,
    l1ToBaseRelayPrepared: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    chainStateMutated: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1FactAnchorTransactionPreparation = prepareL1FactAnchorTransaction;

export function validateL1FactAnchorTransactionDraft(
  draft: L1FactAnchorTransactionDraft
): RuntimeValidationResult {
  const errors: string[] = [];
  if (draft.status !== "anchor_transaction_draft_created") errors.push("invalid status");
  if (draft.methodSelector !== normalizeHex(L1_FACT_ANCHOR_METHOD_SELECTOR)) errors.push("selector mismatch");
  if (draft.value !== "0") errors.push("value must be zero");
  if (draft.transactionSigned !== false) errors.push("draft must be unsigned");
  if (draft.transactionSubmitted !== false) errors.push("draft must be unsubmitted");
  if (draft.l2ToL1MessageConsumed !== false) errors.push("message must not be consumed");
  if (draft.l1FactAnchored !== false) errors.push("fact must not be anchored");
  if (draft.chainStateMutated !== false) errors.push("chain state must not be mutated");
  const expected = encodeL1FactAnchorCalldata({
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow
  });
  if (draft.calldata !== expected) errors.push("calldata mismatch");
  return validation(errors);
}

export function isL1FactAnchorTransactionStatus(
  value: unknown
): value is L1FactAnchorTransactionStatus {
  return value === "anchor_transaction_draft_created" || value === "anchor_transaction_draft_rejected";
}

export function isL1FactAnchorTransactionOutcome(
  value: unknown
): value is L1FactAnchorTransactionOutcome {
  return typeof value === "string" && [
    "anchor_transaction_draft_created",
    "message_evidence_ineligible",
    "message_not_available",
    "message_already_consumed",
    "message_state_unknown",
    "anchor_configuration_invalid",
    "anchor_deployment_invalid",
    "wrong_sender",
    "wrong_recipient",
    "payload_mismatch",
    "proof_input_hash_mismatch",
    "network_mismatch",
    "calldata_encoding_failed",
    "gas_estimate_unavailable",
    "nonce_unresolved",
    "expired",
    "malformed",
    "unsupported"
  ].includes(value);
}

export function createFixtureEthereumL1MessageAvailabilityReader(
  options: {
    readonly available?: boolean;
    readonly alreadyConsumed?: boolean;
    readonly unavailable?: boolean;
    readonly messageCount?: string;
    readonly blockNumber?: number;
  } = {}
): EthereumL1MessageAvailabilityReader {
  return {
    async readMessageAvailability(request) {
      const messageHash = request.messageIdentity.binding.messageHash.value;
      if (options.unavailable) {
        return {
          status: "messaging_core_unavailable",
          messageHash,
          checkedAt: nowIso(),
          readerSource: "unavailable",
          error: "reader unavailable"
        };
      }
      if (options.alreadyConsumed) {
        return {
          status: "message_already_consumed",
          messageHash,
          messageCount: "0",
          checkedAt: nowIso(),
          blockNumber: options.blockNumber ?? 1,
          readerSource: "fixture"
        };
      }
      const count = options.messageCount ?? (options.available === false ? "0" : "1");
      return {
        status: BigInt(count) > 0n ? "message_available" : "message_not_available",
        messageHash,
        messageCount: count,
        checkedAt: nowIso(),
        blockNumber: options.blockNumber ?? 1,
        readerSource: "fixture"
      };
    }
  };
}

export function createFixtureL1FactAnchorDeploymentReader(
  options: {
    readonly anchorAddress: string;
    readonly messagingCoreAddress: string;
    readonly sourceL2Verifier: string;
    readonly codeHash?: string;
    readonly unavailable?: boolean;
  }
): L1FactAnchorDeploymentReader {
  return {
    async readDeployment() {
      if (options.unavailable) {
        return {
          status: "unavailable",
          anchorAddress: options.anchorAddress,
          error: "reader unavailable"
        };
      }
      return {
        status: "found",
        anchorAddress: options.anchorAddress,
        codeHash: options.codeHash,
        starknetMessagingAddress: options.messagingCoreAddress,
        sourceL2Verifier: options.sourceL2Verifier,
        blockNumber: 1
      };
    }
  };
}

export function createFixtureL1GasEstimator(
  gasLimit = "210000"
): EthereumL1GasEstimator {
  return {
    async estimateGas() {
      return {
        status: "estimated",
        gasLimit,
        checkedAt: nowIso(),
        source: "fixture"
      };
    }
  };
}

export function createUnavailableL1GasEstimator(): EthereumL1GasEstimator {
  return {
    async estimateGas() {
      return { status: "unavailable", source: "none", checkedAt: nowIso() };
    }
  };
}

export function createFixtureL1NonceReader(nonce = "0"): EthereumL1NonceReader {
  return {
    async readNonce() {
      return {
        status: "resolved",
        nonce,
        checkedAt: nowIso(),
        source: "fixture",
        nonceReserved: false
      };
    }
  };
}

export function createFixtureL1FeeDataReader(): EthereumL1FeeDataReader {
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

export function createL1FactAnchorFixtureConfiguration(input: {
  readonly anchorAddress: string;
  readonly messagingCoreAddress: string;
  readonly sourceL2Verifier: string;
  readonly starknetNetworkProfileId?: string;
  readonly ethereumChainId?: number;
  readonly approvalStatus?: "accepted" | "draft" | "rejected";
}): L1FactAnchorConfiguration {
  return Object.freeze({
    configurationId: "fixture-l1-anchor-config",
    approvalStatus: input.approvalStatus ?? "accepted",
    activeProfileId: "hardhat",
    networkProfiles: Object.freeze({
      hardhat: Object.freeze({
        profileId: "hardhat",
        ethereumNetwork: "hardhat",
        ethereumChainId: input.ethereumChainId ?? 31337,
        enabled: true,
        rpcReference: "fixture"
      })
    }),
    anchorDeployment: Object.freeze({
      address: normalizeAddress(input.anchorAddress),
      approved: true,
      methodSelector: normalizeHex(L1_FACT_ANCHOR_METHOD_SELECTOR)
    }),
    messagingCore: Object.freeze({
      address: normalizeAddress(input.messagingCoreAddress),
      exposesReadOnlyMessageCount: true,
      consumeMethodSignature: "consumeMessageFromL2(uint256,uint256[])"
    }),
    expectedStarknetSender: Object.freeze({
      starknetNetworkProfileId: input.starknetNetworkProfileId ?? "local_devnet",
      sourceL2Verifier: normalizeHex(input.sourceL2Verifier),
      l1Recipient: normalizeAddress(input.anchorAddress),
      payloadShape: "[fact_high,fact_low]"
    }),
    mainnetAllowed: false
  });
}
