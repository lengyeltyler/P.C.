import { Interface, getAddress, keccak256 } from "ethers";
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
import type { L1FactAnchorReceipt } from "./l1FactAnchorSigning.ts";
import type { RuntimeResult } from "./types.ts";

const UINT128_MAX = (1n << 128n) - 1n;

const RELAY_METHOD = "relayProofInputHashFactToBase";
const RELAY_INTERFACE = new Interface([
  "function relayProofInputHashFactToBase(address baseMirror,uint256 factHigh,uint256 factLow)",
  "function trustAnchor() view returns (address)",
  "function crossDomainMessenger() view returns (address)",
  "event ProofInputHashFactRelayedToBase(address indexed baseMirror,uint256 indexed factHigh,uint256 indexed factLow)"
]);
const MIRROR_METHOD = "mirrorProofInputHashFact";
const MIRROR_INTERFACE = new Interface([
  "function mirrorProofInputHashFact(uint256 factHigh,uint256 factLow)",
  "function crossDomainMessenger() view returns (address)",
  "function authorizedL1Messenger() view returns (address)",
  "event ProofInputHashFactMirrored(address indexed messenger,address remoteSender,uint256 indexed factHigh,uint256 indexed factLow)"
]);

export const L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR =
  RELAY_INTERFACE.getFunction(RELAY_METHOD)?.selector ?? "0x00000000";
export const BASE_FACT_MIRROR_METHOD_SELECTOR =
  MIRROR_INTERFACE.getFunction(MIRROR_METHOD)?.selector ?? "0x00000000";

export type L1AnchoredFactEvidenceSource =
  | "live_l1_receipt"
  | "local_hardhat_receipt"
  | "fixture_receipt"
  | "manual_reference"
  | "unsupported";

export type L1AnchoredFactStatus =
  | "anchored_fact_evidence_valid"
  | "anchored_fact_evidence_invalid"
  | "anchored_fact_evidence_untrusted";

export interface L1AnchoredFactBinding {
  readonly l1AnchorTransactionHash: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly anchorContract: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly starknetMessageHash: string;
  readonly expectedStarknetSender: string;
  readonly ethereumNetworkProfileId: string;
  readonly ethereumChainId: number;
  readonly confirmationCount: number;
  readonly auditCorrelationId: string;
}

export interface L1AnchoredFactEvidence {
  readonly status: L1AnchoredFactStatus;
  readonly source: L1AnchoredFactEvidenceSource;
  readonly binding: L1AnchoredFactBinding;
  readonly observedAt: string;
  readonly liveAnchoredFactEvidence: boolean;
  readonly productionSignable: boolean;
  readonly errors: readonly string[];
}

export interface L1AnchoredFactEvidenceInput {
  readonly receipt: L1FactAnchorReceipt;
  readonly source: L1AnchoredFactEvidenceSource;
  readonly expectedAnchorContract?: string;
  readonly expectedFactHigh?: string;
  readonly expectedFactLow?: string;
  readonly expectedProofInputHash?: string;
  readonly expectedStarknetMessageHash?: string;
  readonly expectedStarknetSender?: string;
  readonly expectedEthereumChainId?: number;
  readonly ethereumNetworkProfileId?: string;
  readonly auditCorrelationId?: string;
}

export type L1AnchoredFactVerificationOutcome =
  | "fact_anchored"
  | "fact_not_anchored"
  | "fact_state_unknown"
  | "anchor_unavailable"
  | "receipt_mismatch"
  | "event_mismatch"
  | "network_mismatch"
  | "stale_read"
  | "malformed"
  | "unsupported";

export interface L1AnchoredFactVerificationRequest {
  readonly requestId: string;
  readonly evidence: L1AnchoredFactEvidence;
  readonly stateReader: L1AnchoredFactStateReader;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly freshnessMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface L1AnchoredFactVerificationValue {
  readonly outcome: L1AnchoredFactVerificationOutcome;
  readonly evidence: L1AnchoredFactEvidence;
  readonly state: L1AnchoredFactStateReadResult;
  readonly checkedAt: string;
  readonly stale: boolean;
  readonly raceWarning: string;
  readonly l1FactAnchored: boolean;
  readonly l1ToBaseRelayPrepared: false;
  readonly baseFactMirrored: false;
  readonly chainStateMutated: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1AnchoredFactVerificationResult =
  RuntimeResult<L1AnchoredFactVerificationValue>;

export interface L1AnchoredFactStateReader {
  readAnchoredFact(request: L1AnchoredFactStateReadRequest): Promise<L1AnchoredFactStateReadResult>;
}

export interface L1AnchoredFactStateReadRequest {
  readonly anchorAddress: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly blockNumber?: number;
}

export interface L1AnchoredFactStateReadResult {
  readonly status: "fact_anchored" | "fact_not_anchored" | "fact_state_unknown" | "anchor_unavailable";
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly blockHash?: string;
  readonly readerSource: "fixture" | "rpc_view" | "manual" | "unavailable";
  readonly error?: string;
}

export interface L1ToBaseRelayNetworkProfile {
  readonly profileId: string;
  readonly l1Network: "hardhat" | "ethereum_sepolia" | "ethereum_mainnet" | "local_devnet";
  readonly l1ChainId: number;
  readonly baseNetwork: "hardhat" | "base_sepolia" | "base_mainnet" | "local_devnet";
  readonly baseChainId: number;
  readonly enabled: boolean;
}

export interface L1CrossDomainMessengerReference {
  readonly address: string;
  readonly interfaceName: "IPhilCrossDomainMessenger";
  readonly sendMessageSignature: "sendMessage(address,bytes)";
}

export interface BaseCrossDomainMessengerReference {
  readonly address: string;
  readonly interfaceName: "IBaseCrossDomainMessenger";
  readonly sendMessageSignature: "sendMessage(address,bytes,uint32)";
}

export interface BaseFactMirrorReference {
  readonly address: string;
  readonly approved: boolean;
  readonly methodSelector: string;
  readonly abiSha256?: string;
}

export interface AuthorizedL1RemoteSenderReference {
  readonly address: string;
  readonly expectedOnBaseMirror: true;
}

export interface L1ToBaseRelayGasPolicy {
  readonly minGasLimit: string;
  readonly maxGasLimit: string;
}

export interface L1ToBaseRelayFeePolicy {
  readonly valuePolicy: "nonpayable_zero_value" | "fee_quote_required" | "unsupported";
  readonly requiredValueWei?: string;
  readonly maxValueWei: string;
}

export interface L1ToBaseFactRelayConfiguration {
  readonly configurationId: string;
  readonly approvalStatus: "accepted" | "draft" | "rejected";
  readonly activeProfileId: string;
  readonly networkProfiles: Readonly<Record<string, L1ToBaseRelayNetworkProfile>>;
  readonly l1AnchorAddress: string;
  readonly l1RelayContract: {
    readonly address: string;
    readonly approved: boolean;
    readonly methodSelector: string;
    readonly abiSha256?: string;
  };
  readonly l1Messenger: L1CrossDomainMessengerReference;
  readonly baseMessenger: BaseCrossDomainMessengerReference;
  readonly baseMirror: BaseFactMirrorReference;
  readonly authorizedL1RemoteSender: AuthorizedL1RemoteSenderReference;
  readonly gasPolicy: L1ToBaseRelayGasPolicy;
  readonly feePolicy: L1ToBaseRelayFeePolicy;
  readonly messageEncodingVersion: "base-mirror-proof-input-hash-v1";
  readonly mainnetAllowed: false;
}

export type L1ToBaseRelayDeploymentVerificationOutcome =
  | "deployment_valid"
  | "relay_configuration_invalid"
  | "relay_deployment_invalid"
  | "mirror_deployment_invalid"
  | "messenger_pair_invalid"
  | "remote_sender_mismatch"
  | "base_mirror_mismatch"
  | "network_mismatch"
  | "unsupported";

export interface L1ToBaseRelayDeploymentVerificationRequest {
  readonly requestId: string;
  readonly configuration: L1ToBaseFactRelayConfiguration;
  readonly deploymentReader: L1ToBaseRelayDeploymentReader;
  readonly issueTime: string;
  readonly expiresAt: string;
}

export interface L1ToBaseRelayDeploymentReadResult {
  readonly status: "found" | "missing" | "mismatch" | "unavailable";
  readonly l1RelayAddress: string;
  readonly l1AnchorAddress?: string;
  readonly l1MessengerAddress?: string;
  readonly baseMirrorAddress?: string;
  readonly baseMessengerAddress?: string;
  readonly authorizedL1RemoteSender?: string;
  readonly relayMethodSelector?: string;
  readonly mirrorMethodSelector?: string;
  readonly relayCodeHash?: string;
  readonly mirrorCodeHash?: string;
  readonly blockNumber?: number;
  readonly error?: string;
}

export interface L1ToBaseRelayDeploymentReader {
  readRelayDeployment(
    request: L1ToBaseRelayDeploymentVerificationRequest
  ): Promise<L1ToBaseRelayDeploymentReadResult>;
}

export interface L1ToBaseRelayDeploymentVerificationValue {
  readonly outcome: L1ToBaseRelayDeploymentVerificationOutcome;
  readonly configuration: L1ToBaseFactRelayConfiguration;
  readonly read: L1ToBaseRelayDeploymentReadResult;
  readonly l1RelayAddress: string;
  readonly baseMirrorAddress: string;
  readonly l1MessengerAddress: string;
  readonly baseMessengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly errors: readonly string[];
}

export type L1ToBaseRelayDeploymentVerificationResult =
  RuntimeResult<L1ToBaseRelayDeploymentVerificationValue>;

export interface BaseFactMirrorCallPreview {
  readonly baseMirror: string;
  readonly selector: string;
  readonly calldata: string;
  readonly calldataHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly authorizedL1Sender: string;
  readonly l1Messenger: string;
  readonly baseMessenger: string;
  readonly baseChainId: number;
  readonly messageSent: false;
  readonly baseMirrorCalled: false;
  readonly baseFactMirrored: false;
}

export interface L1ToBaseCrossDomainMessagePreview {
  readonly l1Messenger: string;
  readonly baseMessenger: string;
  readonly target: string;
  readonly payload: BaseFactMirrorCallPreview;
  readonly payloadHash: string;
  readonly remoteGasLimit: string;
  readonly value: string;
  readonly messageSent: false;
  readonly baseMirrorCalled: false;
  readonly baseFactMirrored: false;
}

export interface L1ToBaseRelayFeeQuoteRequest {
  readonly configuration: L1ToBaseFactRelayConfiguration;
  readonly evidence: L1AnchoredFactEvidence;
  readonly baseMirrorCall: BaseFactMirrorCallPreview;
}

export interface L1ToBaseRelayFeeQuoteResult {
  readonly status: "resolved" | "unresolved" | "unsupported";
  readonly valueWei?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc_view" | "configuration" | "unavailable";
  readonly error?: string;
}

export interface L1ToBaseRelayFeeQuoter {
  quoteRelayFee(request: L1ToBaseRelayFeeQuoteRequest): Promise<L1ToBaseRelayFeeQuoteResult>;
}

export interface L1ToBaseFactRelayGasEstimateReference {
  readonly status: "estimated" | "unresolved" | "unavailable";
  readonly gasLimit?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc_estimate" | "none";
}

export interface L1ToBaseFactRelayNonceReference {
  readonly status: "resolved" | "unresolved" | "unavailable";
  readonly nonce?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc" | "none";
  readonly nonceReserved: false;
}

export interface L1ToBaseRelayGasEstimator {
  estimateGas(request: L1ToBaseFactRelayPreparationRequest): Promise<L1ToBaseFactRelayGasEstimateReference>;
}

export interface L1ToBaseRelayNonceReader {
  readNonce(request: L1ToBaseFactRelayPreparationRequest): Promise<L1ToBaseFactRelayNonceReference>;
}

export type L1ToBaseFactRelayStatus =
  | "relay_transaction_draft_created"
  | "relay_transaction_rejected";

export type L1ToBaseFactRelayOutcome =
  | "relay_transaction_draft_created"
  | "fact_not_anchored"
  | "anchored_fact_evidence_ineligible"
  | "relay_configuration_invalid"
  | "relay_deployment_invalid"
  | "mirror_deployment_invalid"
  | "messenger_pair_invalid"
  | "remote_sender_mismatch"
  | "base_mirror_mismatch"
  | "fact_pair_mismatch"
  | "proof_input_hash_mismatch"
  | "fee_unresolved"
  | "fee_policy_violation"
  | "gas_limit_unresolved"
  | "network_mismatch"
  | "calldata_encoding_failed"
  | "nonce_unresolved"
  | "expired"
  | "malformed"
  | "unsupported";

export type L1ToBaseFactRelayLimitation =
  | "unsigned_relay_draft_only"
  | "unsubmitted_relay_draft_only"
  | "no_cross_domain_message_sent"
  | "no_base_mirror_call"
  | "no_base_fact_mirroring"
  | "no_base_execution"
  | "no_nullifier_consumption"
  | "fixture_not_production_signable"
  | "read_state_is_snapshot";

export interface L1ToBaseFactRelayBinding {
  readonly evidenceId: string;
  readonly l1AnchorTransactionHash: string;
  readonly l1AnchorAddress: string;
  readonly l1RelayAddress: string;
  readonly l1MessengerAddress: string;
  readonly baseMessengerAddress: string;
  readonly baseMirrorAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly proofInputHash: string;
  readonly starknetMessageHash: string;
  readonly l1ChainId: number;
  readonly baseChainId: number;
  readonly auditCorrelationId: string;
}

export interface L1ToBaseFactRelayTransactionDraft {
  readonly l1ToBaseFactRelayTransactionDraftId: string;
  readonly status: "relay_transaction_draft_created";
  readonly outcome: "relay_transaction_draft_created";
  readonly binding: L1ToBaseFactRelayBinding;
  readonly to: string;
  readonly methodName: "relayProofInputHashFactToBase";
  readonly methodSelector: string;
  readonly calldata: string;
  readonly calldataHash: string;
  readonly value: string;
  readonly remoteGasLimit: string;
  readonly baseMirrorCallPreview: BaseFactMirrorCallPreview;
  readonly crossDomainMessagePreview: L1ToBaseCrossDomainMessagePreview;
  readonly gas: L1ToBaseFactRelayGasEstimateReference;
  readonly nonce: L1ToBaseFactRelayNonceReference;
  readonly preparedAt: string;
  readonly expiresAt: string;
  readonly liveAnchoredFactEvidence: boolean;
  readonly productionSignable: boolean;
  readonly limitations: readonly L1ToBaseFactRelayLimitation[];
  readonly transactionPrepared: true;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly crossDomainMessageSent: false;
  readonly baseMirrorCalled: false;
  readonly baseFactMirrored: false;
  readonly baseExecutionPrepared: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly chainStateMutated: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type L1ToBaseFactRelayPreparationResult =
  RuntimeResult<L1ToBaseFactRelayTransactionDraft>;

export interface L1ToBaseFactRelayPreparationRequest {
  readonly requestId: string;
  readonly anchoredFactEvidence: L1AnchoredFactEvidence;
  readonly stateReader: L1AnchoredFactStateReader;
  readonly deploymentReader: L1ToBaseRelayDeploymentReader;
  readonly configuration: L1ToBaseFactRelayConfiguration;
  readonly relayerAccount?: string;
  readonly value?: string;
  readonly feeQuoter?: L1ToBaseRelayFeeQuoter;
  readonly gasEstimator?: L1ToBaseRelayGasEstimator;
  readonly nonceReader?: L1ToBaseRelayNonceReader;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly freshnessMs?: number;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
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

function addressesEqual(a: string, b: string): boolean {
  try {
    return normalizeAddress(a) === normalizeAddress(b);
  } catch {
    return normalizeHex(a) === normalizeHex(b);
  }
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function splitProofInputHash(proofInputHash: string): readonly [string, string] | undefined {
  try {
    const value = BigInt(proofInputHash);
    const high = value >> 128n;
    const low = value & UINT128_MAX;
    return [`0x${high.toString(16)}`, `0x${low.toString(16)}`];
  } catch {
    return undefined;
  }
}

function proofInputHashMatchesFactPair(proofInputHash: string, factHigh: string, factLow: string): boolean {
  const split = splitProofInputHash(proofInputHash);
  return Boolean(split
    && normalizeHex(split[0]) === normalizeHex(factHigh)
    && normalizeHex(split[1]) === normalizeHex(factLow));
}

export function createL1AnchoredFactEvidence(input: L1AnchoredFactEvidenceInput): L1AnchoredFactEvidence {
  const errors: string[] = [];
  const receipt = input.receipt;
  if (!receipt.transactionConfirmed) errors.push("receipt is not confirmed");
  if (!receipt.l2ToL1MessageConsumed) errors.push("L2-to-L1 message was not consumed");
  if (!receipt.l1FactAnchored) errors.push("L1 fact was not anchored");
  if (input.expectedAnchorContract && !addressesEqual(receipt.anchorAddress, input.expectedAnchorContract)) {
    errors.push("anchor contract mismatch");
  }
  if (input.expectedFactHigh && normalizeHex(receipt.factHigh) !== normalizeHex(input.expectedFactHigh)) {
    errors.push("factHigh mismatch");
  }
  if (input.expectedFactLow && normalizeHex(receipt.factLow) !== normalizeHex(input.expectedFactLow)) {
    errors.push("factLow mismatch");
  }
  if (input.expectedProofInputHash && normalizeHex(receipt.proofInputHash) !== normalizeHex(input.expectedProofInputHash)) {
    errors.push("proofInputHash mismatch");
  }
  if (input.expectedStarknetMessageHash && normalizeHex(receipt.messageHash) !== normalizeHex(input.expectedStarknetMessageHash)) {
    errors.push("message hash mismatch");
  }
  if (input.expectedStarknetSender && normalizeHex(receipt.event.sourceL2Verifier) !== normalizeHex(input.expectedStarknetSender)) {
    errors.push("Starknet sender mismatch");
  }
  if (input.expectedEthereumChainId && receipt.chainId !== input.expectedEthereumChainId) {
    errors.push("L1 chain mismatch");
  }
  if (!proofInputHashMatchesFactPair(receipt.proofInputHash, receipt.factHigh, receipt.factLow)) {
    errors.push("proofInputHash split mismatch");
  }
  const live = input.source === "live_l1_receipt";
  const binding = Object.freeze({
    l1AnchorTransactionHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    anchorContract: normalizeAddress(receipt.anchorAddress),
    factHigh: normalizeHex(receipt.factHigh),
    factLow: normalizeHex(receipt.factLow),
    proofInputHash: normalizeHex(receipt.proofInputHash),
    starknetMessageHash: normalizeHex(receipt.messageHash),
    expectedStarknetSender: normalizeHex(receipt.event.sourceL2Verifier),
    ethereumNetworkProfileId: input.ethereumNetworkProfileId ?? (receipt.chainId === 11155111 ? "ethereum_sepolia" : "hardhat"),
    ethereumChainId: receipt.chainId,
    confirmationCount: receipt.confirmations,
    auditCorrelationId: input.auditCorrelationId ?? receipt.auditEventDraft?.auditCorrelationId ?? createAuditCorrelationId([
      receipt.transactionHash,
      "l1-anchored-fact"
    ])
  });
  return Object.freeze({
    status: errors.length === 0
      ? "anchored_fact_evidence_valid"
      : input.source === "manual_reference"
        ? "anchored_fact_evidence_untrusted"
        : "anchored_fact_evidence_invalid",
    source: input.source,
    binding,
    observedAt: receipt.observedAt,
    liveAnchoredFactEvidence: live && errors.length === 0,
    productionSignable: live && errors.length === 0,
    errors: Object.freeze(errors)
  });
}

export function validateL1AnchoredFactEvidence(evidence: L1AnchoredFactEvidence): RuntimeValidationResult {
  const errors: string[] = [];
  if (evidence.status !== "anchored_fact_evidence_valid") errors.push("anchored fact evidence invalid");
  try { normalizeAddress(evidence.binding.anchorContract); } catch { errors.push("anchor contract invalid"); }
  if (!proofInputHashMatchesFactPair(evidence.binding.proofInputHash, evidence.binding.factHigh, evidence.binding.factLow)) {
    errors.push("proofInputHash split mismatch");
  }
  if (!evidence.binding.l1AnchorTransactionHash?.startsWith("0x")) errors.push("transaction hash invalid");
  if (evidence.binding.confirmationCount < 1) errors.push("confirmations missing");
  return validation(errors);
}

function createAnchoredFactAuditDraft(input: {
  readonly request: L1AnchoredFactVerificationRequest;
  readonly outcome: L1AnchoredFactVerificationOutcome;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "fact_anchored" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1AnchoredFactVerification",
    summary: input.outcome === "fact_anchored"
      ? "L1 anchored fact verified read-only."
      : "L1 anchored fact verification was blocked or unavailable.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      anchorTransactionHash: input.request.evidence.binding.l1AnchorTransactionHash,
      anchorAddress: input.request.evidence.binding.anchorContract,
      proofInputHash: input.request.evidence.binding.proofInputHash,
      factPair: [
        input.request.evidence.binding.factHigh,
        input.request.evidence.binding.factLow
      ]
    }
  });
}

export async function requestL1AnchoredFactVerification(
  request: L1AnchoredFactVerificationRequest
): Promise<L1AnchoredFactVerificationResult> {
  const errors: string[] = [];
  if (!request.requestId) errors.push("requestId required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("verification request expired");
  errors.push(...validateL1AnchoredFactEvidence(request.evidence).errors);
  if (errors.length > 0) {
    const auditEventDraft = createAnchoredFactAuditDraft({ request, outcome: "malformed", errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_ANCHORED_FACT_EVIDENCE_REJECTED",
      category: "invalid_intent",
      message: "L1 anchored fact evidence is malformed or mismatched.",
      recoverable: true,
      details: { outcome: "malformed", errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  const state = await request.stateReader.readAnchoredFact({
    anchorAddress: request.evidence.binding.anchorContract,
    factHigh: request.evidence.binding.factHigh,
    factLow: request.evidence.binding.factLow,
    blockNumber: request.evidence.binding.blockNumber
  });
  const stale = Boolean(request.freshnessMs && Date.now() - Date.parse(state.checkedAt) > request.freshnessMs);
  const outcome: L1AnchoredFactVerificationOutcome = stale
    ? "stale_read"
    : state.status === "fact_anchored"
      ? "fact_anchored"
      : state.status === "fact_not_anchored"
        ? "fact_not_anchored"
        : state.status === "anchor_unavailable"
          ? "anchor_unavailable"
          : "fact_state_unknown";
  const auditEventDraft = createAnchoredFactAuditDraft({
    request,
    outcome,
    errors: state.error ? [state.error] : []
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const value = Object.freeze({
    outcome,
    evidence: request.evidence,
    state,
    checkedAt: state.checkedAt,
    stale,
    raceWarning: "Anchored fact reads are snapshots. Revalidate before relay signing or submission.",
    l1FactAnchored: outcome === "fact_anchored",
    l1ToBaseRelayPrepared: false as const,
    baseFactMirrored: false as const,
    chainStateMutated: false as const,
    auditEventDraft,
    auditDraftCollectionResult
  });
  if (outcome !== "fact_anchored") {
    return runtimeDenied({
      code: "L1_ANCHORED_FACT_NOT_VERIFIED",
      category: "network_unavailable",
      message: "L1 anchored fact could not be verified read-only.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  return runtimeOk(value);
}

export function encodeBaseFactMirrorCalldata(input: {
  readonly factHigh: string;
  readonly factLow: string;
}): string {
  return MIRROR_INTERFACE.encodeFunctionData(MIRROR_METHOD, [
    BigInt(input.factHigh),
    BigInt(input.factLow)
  ]);
}

export function encodeL1ToBaseFactRelayCalldata(input: {
  readonly baseMirror: string;
  readonly factHigh: string;
  readonly factLow: string;
}): string {
  return RELAY_INTERFACE.encodeFunctionData(RELAY_METHOD, [
    normalizeAddress(input.baseMirror),
    BigInt(input.factHigh),
    BigInt(input.factLow)
  ]);
}

export function createBaseFactMirrorCallPreview(input: {
  readonly configuration: L1ToBaseFactRelayConfiguration;
  readonly evidence: L1AnchoredFactEvidence;
}): BaseFactMirrorCallPreview {
  const calldata = encodeBaseFactMirrorCalldata({
    factHigh: input.evidence.binding.factHigh,
    factLow: input.evidence.binding.factLow
  });
  const profile = input.configuration.networkProfiles[input.configuration.activeProfileId];
  return Object.freeze({
    baseMirror: normalizeAddress(input.configuration.baseMirror.address),
    selector: BASE_FACT_MIRROR_METHOD_SELECTOR,
    calldata,
    calldataHash: keccak256(calldata),
    factHigh: input.evidence.binding.factHigh,
    factLow: input.evidence.binding.factLow,
    proofInputHash: input.evidence.binding.proofInputHash,
    authorizedL1Sender: normalizeAddress(input.configuration.authorizedL1RemoteSender.address),
    l1Messenger: normalizeAddress(input.configuration.l1Messenger.address),
    baseMessenger: normalizeAddress(input.configuration.baseMessenger.address),
    baseChainId: profile.baseChainId,
    messageSent: false,
    baseMirrorCalled: false,
    baseFactMirrored: false
  });
}

function validateRelayConfiguration(config: L1ToBaseFactRelayConfiguration): RuntimeValidationResult {
  const errors: string[] = [];
  const profile = config.networkProfiles[config.activeProfileId];
  if (!profile || !profile.enabled) errors.push("network profile disabled");
  if (profile?.l1ChainId === 1 || profile?.baseChainId === 8453 || config.mainnetAllowed !== false) {
    errors.push("mainnet prohibited");
  }
  if (config.approvalStatus !== "accepted") errors.push("configuration not accepted");
  if (!config.l1RelayContract.approved) errors.push("relay deployment not approved");
  if (!config.baseMirror.approved) errors.push("Base mirror not approved");
  if (normalizeHex(config.l1RelayContract.methodSelector) !== normalizeHex(L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR)) {
    errors.push("relay selector mismatch");
  }
  if (normalizeHex(config.baseMirror.methodSelector) !== normalizeHex(BASE_FACT_MIRROR_METHOD_SELECTOR)) {
    errors.push("mirror selector mismatch");
  }
  for (const [label, value] of [
    ["relay", config.l1RelayContract.address],
    ["anchor", config.l1AnchorAddress],
    ["l1 messenger", config.l1Messenger.address],
    ["base messenger", config.baseMessenger.address],
    ["base mirror", config.baseMirror.address],
    ["authorized remote sender", config.authorizedL1RemoteSender.address]
  ]) {
    try {
      if (normalizeAddress(value) === "0x0000000000000000000000000000000000000000") errors.push(`${label} zero address`);
    } catch {
      errors.push(`${label} address invalid`);
    }
  }
  if (config.feePolicy.valuePolicy === "unsupported") errors.push("fee policy unsupported");
  return validation(errors);
}

export async function verifyL1ToBaseRelayDeployment(
  request: L1ToBaseRelayDeploymentVerificationRequest
): Promise<L1ToBaseRelayDeploymentVerificationResult> {
  const errors: string[] = [...validateRelayConfiguration(request.configuration).errors];
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("deployment verification expired");
  const read = await request.deploymentReader.readRelayDeployment(request);
  if (read.status !== "found") errors.push("relay deployment missing");
  const config = request.configuration;
  if (!addressesEqual(read.l1RelayAddress, config.l1RelayContract.address)) errors.push("relay address mismatch");
  if (read.l1AnchorAddress && !addressesEqual(read.l1AnchorAddress, config.l1AnchorAddress)) errors.push("anchor address mismatch");
  if (read.l1MessengerAddress && !addressesEqual(read.l1MessengerAddress, config.l1Messenger.address)) {
    errors.push("L1 messenger mismatch");
  }
  if (read.baseMirrorAddress && !addressesEqual(read.baseMirrorAddress, config.baseMirror.address)) {
    errors.push("Base mirror mismatch");
  }
  if (read.baseMessengerAddress && !addressesEqual(read.baseMessengerAddress, config.baseMessenger.address)) {
    errors.push("Base messenger mismatch");
  }
  if (read.authorizedL1RemoteSender && !addressesEqual(read.authorizedL1RemoteSender, config.authorizedL1RemoteSender.address)) {
    errors.push("authorized remote sender mismatch");
  }
  if (read.relayMethodSelector && normalizeHex(read.relayMethodSelector) !== normalizeHex(L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR)) {
    errors.push("relay selector mismatch");
  }
  if (read.mirrorMethodSelector && normalizeHex(read.mirrorMethodSelector) !== normalizeHex(BASE_FACT_MIRROR_METHOD_SELECTOR)) {
    errors.push("mirror selector mismatch");
  }
  const joined = errors.join(" | ");
  const outcome: L1ToBaseRelayDeploymentVerificationOutcome = errors.length === 0
    ? "deployment_valid"
    : joined.includes("Base mirror")
      ? "mirror_deployment_invalid"
      : joined.includes("messenger") || joined.includes("remote sender")
        ? "messenger_pair_invalid"
        : joined.includes("configuration") || joined.includes("selector") || joined.includes("mainnet")
          ? "relay_configuration_invalid"
          : "relay_deployment_invalid";
  const value = Object.freeze({
    outcome,
    configuration: config,
    read,
    l1RelayAddress: normalizeAddress(config.l1RelayContract.address),
    baseMirrorAddress: normalizeAddress(config.baseMirror.address),
    l1MessengerAddress: normalizeAddress(config.l1Messenger.address),
    baseMessengerAddress: normalizeAddress(config.baseMessenger.address),
    authorizedL1RemoteSender: normalizeAddress(config.authorizedL1RemoteSender.address),
    errors: Object.freeze(errors)
  });
  return errors.length === 0
    ? runtimeOk(value)
    : runtimeDenied({
      code: "L1_TO_BASE_RELAY_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "L1-to-Base relay deployment/configuration verification failed.",
      recoverable: true,
      details: { outcome, errors }
    });
}

function outcomeForRelayErrors(errors: readonly string[]): L1ToBaseFactRelayOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("fact_not_anchored")) return "fact_not_anchored";
  if (joined.includes("evidence")) return "anchored_fact_evidence_ineligible";
  if (joined.includes("Base mirror")) return "mirror_deployment_invalid";
  if (joined.includes("mirror_deployment_invalid")) return "mirror_deployment_invalid";
  if (joined.includes("messenger")) return "messenger_pair_invalid";
  if (joined.includes("remote sender")) return "remote_sender_mismatch";
  if (joined.includes("deployment")) return "relay_deployment_invalid";
  if (joined.includes("proofInputHash")) return "proof_input_hash_mismatch";
  if (joined.includes("fact")) return "fact_pair_mismatch";
  if (joined.includes("fee unresolved")) return "fee_unresolved";
  if (joined.includes("fee policy")) return "fee_policy_violation";
  if (joined.includes("gas")) return "gas_limit_unresolved";
  if (joined.includes("nonce")) return "nonce_unresolved";
  if (joined.includes("network") || joined.includes("mainnet")) return "network_mismatch";
  if (joined.includes("expired")) return "expired";
  return "malformed";
}

function createRelayAuditDraft(input: {
  readonly request: L1ToBaseFactRelayPreparationRequest;
  readonly outcome: L1ToBaseFactRelayOutcome;
  readonly calldataHash?: string;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "adapter",
    outcome: input.outcome === "relay_transaction_draft_created" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestL1ToBaseFactRelayPreparation",
    summary: input.outcome === "relay_transaction_draft_created"
      ? "Unsigned Ethereum L1-to-Base fact relay transaction draft created."
      : "Ethereum L1-to-Base fact relay preparation was blocked.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      anchorTransactionHash: input.request.anchoredFactEvidence.binding.l1AnchorTransactionHash,
      proofInputHash: input.request.anchoredFactEvidence.binding.proofInputHash,
      factPair: [
        input.request.anchoredFactEvidence.binding.factHigh,
        input.request.anchoredFactEvidence.binding.factLow
      ],
      l1RelayContract: input.request.configuration.l1RelayContract.address,
      l1Messenger: input.request.configuration.l1Messenger.address,
      baseMessenger: input.request.configuration.baseMessenger.address,
      baseMirror: input.request.configuration.baseMirror.address,
      methodSelector: L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR,
      calldataHash: input.calldataHash
    }
  });
}

export function validateL1ToBaseFactRelayPreparationRequest(
  request: L1ToBaseFactRelayPreparationRequest
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!request.requestId) errors.push("requestId required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("request expired");
  errors.push(...validateL1AnchoredFactEvidence(request.anchoredFactEvidence).errors);
  errors.push(...validateRelayConfiguration(request.configuration).errors);
  const profile = request.configuration.networkProfiles[request.configuration.activeProfileId];
  if (profile && profile.l1ChainId !== request.anchoredFactEvidence.binding.ethereumChainId) {
    errors.push("network mismatch");
  }
  if (!addressesEqual(request.configuration.l1AnchorAddress, request.anchoredFactEvidence.binding.anchorContract)) {
    errors.push("anchor address mismatch");
  }
  return validation(errors);
}

export async function prepareL1ToBaseFactRelayTransaction(
  request: L1ToBaseFactRelayPreparationRequest
): Promise<L1ToBaseFactRelayPreparationResult> {
  const errors: string[] = [...validateL1ToBaseFactRelayPreparationRequest(request).errors];
  const fact = await requestL1AnchoredFactVerification({
    requestId: `${request.requestId}:anchored-fact`,
    evidence: request.anchoredFactEvidence,
    stateReader: request.stateReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    freshnessMs: request.freshnessMs ?? 60_000,
    auditCorrelationId: request.auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  });
  if (fact.status !== "approved") errors.push(String(fact.error?.details?.outcome ?? "fact_not_anchored"));

  const deployment = await verifyL1ToBaseRelayDeployment({
    requestId: `${request.requestId}:deployment`,
    configuration: request.configuration,
    deploymentReader: request.deploymentReader,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt
  });
  if (deployment.status !== "approved") errors.push(String(deployment.error?.details?.outcome ?? "relay_deployment_invalid"));

  let baseMirrorCall: BaseFactMirrorCallPreview | undefined;
  let crossDomainPreview: L1ToBaseCrossDomainMessagePreview | undefined;
  let calldata = "";
  let calldataHash = "";
  try {
    baseMirrorCall = createBaseFactMirrorCallPreview({
      configuration: request.configuration,
      evidence: request.anchoredFactEvidence
    });
    const quoted = request.feeQuoter
      ? await request.feeQuoter.quoteRelayFee({ configuration: request.configuration, evidence: request.anchoredFactEvidence, baseMirrorCall })
      : {
        status: request.configuration.feePolicy.valuePolicy === "nonpayable_zero_value" ? "resolved" as const : "unresolved" as const,
        valueWei: "0",
        checkedAt: nowIso(),
        source: "configuration" as const
      };
    if (quoted.status !== "resolved" || quoted.valueWei === undefined) errors.push("fee unresolved");
    const value = request.value ?? quoted.valueWei ?? "";
    if (request.configuration.feePolicy.valuePolicy === "nonpayable_zero_value" && value !== "0") {
      errors.push("fee policy violation");
    }
    if (BigInt(value || "0") > BigInt(request.configuration.feePolicy.maxValueWei)) {
      errors.push("fee policy violation");
    }
    const remoteGasLimit = request.configuration.gasPolicy.minGasLimit;
    if (!remoteGasLimit || BigInt(remoteGasLimit) <= 0n) errors.push("gas limit unresolved");
    if (BigInt(remoteGasLimit || "0") > BigInt(request.configuration.gasPolicy.maxGasLimit)) {
      errors.push("gas limit unresolved");
    }
    crossDomainPreview = Object.freeze({
      l1Messenger: request.configuration.l1Messenger.address,
      baseMessenger: request.configuration.baseMessenger.address,
      target: request.configuration.baseMirror.address,
      payload: baseMirrorCall,
      payloadHash: baseMirrorCall.calldataHash,
      remoteGasLimit,
      value,
      messageSent: false,
      baseMirrorCalled: false,
      baseFactMirrored: false
    });
    calldata = encodeL1ToBaseFactRelayCalldata({
      baseMirror: request.configuration.baseMirror.address,
      factHigh: request.anchoredFactEvidence.binding.factHigh,
      factLow: request.anchoredFactEvidence.binding.factLow
    });
    calldataHash = keccak256(calldata);
  } catch {
    errors.push("calldata_encoding_failed");
  }

  const gas = request.gasEstimator
    ? await request.gasEstimator.estimateGas(request)
    : { status: "unresolved" as const, checkedAt: nowIso(), source: "none" as const };
  if (gas.status !== "estimated") errors.push("gas limit unresolved");
  const nonce = request.nonceReader
    ? await request.nonceReader.readNonce(request)
    : { status: "unresolved" as const, checkedAt: nowIso(), source: "none" as const, nonceReserved: false as const };
  if (nonce.status !== "resolved") errors.push("nonce unresolved");

  if (errors.length > 0 || !baseMirrorCall || !crossDomainPreview || !calldata) {
    const outcome = outcomeForRelayErrors(errors);
    const auditEventDraft = createRelayAuditDraft({ request, outcome, calldataHash, errors });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "L1_TO_BASE_RELAY_PREPARATION_REJECTED",
      category: "unsupported_operation",
      message: "L1-to-Base relay transaction preparation was rejected.",
      recoverable: true,
      details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const profile = request.configuration.networkProfiles[request.configuration.activeProfileId];
  const auditEventDraft = createRelayAuditDraft({
    request,
    outcome: "relay_transaction_draft_created",
    calldataHash
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const limitations: L1ToBaseFactRelayLimitation[] = [
    "unsigned_relay_draft_only",
    "unsubmitted_relay_draft_only",
    "no_cross_domain_message_sent",
    "no_base_mirror_call",
    "no_base_fact_mirroring",
    "no_base_execution",
    "no_nullifier_consumption",
    "read_state_is_snapshot"
  ];
  if (!request.anchoredFactEvidence.liveAnchoredFactEvidence) limitations.push("fixture_not_production_signable");
  return runtimeOk(Object.freeze({
    l1ToBaseFactRelayTransactionDraftId: createAuditCorrelationId([
      request.anchoredFactEvidence.binding.l1AnchorTransactionHash,
      request.configuration.l1RelayContract.address,
      request.configuration.baseMirror.address,
      "l1-to-base-relay-draft"
    ]),
    status: "relay_transaction_draft_created",
    outcome: "relay_transaction_draft_created",
    binding: Object.freeze({
      evidenceId: createAuditCorrelationId([
        request.anchoredFactEvidence.binding.l1AnchorTransactionHash,
        "anchored-fact-evidence"
      ]),
      l1AnchorTransactionHash: request.anchoredFactEvidence.binding.l1AnchorTransactionHash,
      l1AnchorAddress: request.anchoredFactEvidence.binding.anchorContract,
      l1RelayAddress: request.configuration.l1RelayContract.address,
      l1MessengerAddress: request.configuration.l1Messenger.address,
      baseMessengerAddress: request.configuration.baseMessenger.address,
      baseMirrorAddress: request.configuration.baseMirror.address,
      authorizedL1RemoteSender: request.configuration.authorizedL1RemoteSender.address,
      factHigh: request.anchoredFactEvidence.binding.factHigh,
      factLow: request.anchoredFactEvidence.binding.factLow,
      proofInputHash: request.anchoredFactEvidence.binding.proofInputHash,
      starknetMessageHash: request.anchoredFactEvidence.binding.starknetMessageHash,
      l1ChainId: profile.l1ChainId,
      baseChainId: profile.baseChainId,
      auditCorrelationId: request.auditCorrelationId ?? request.anchoredFactEvidence.binding.auditCorrelationId
    }),
    to: normalizeAddress(request.configuration.l1RelayContract.address),
    methodName: "relayProofInputHashFactToBase",
    methodSelector: L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR,
    calldata,
    calldataHash,
    value: crossDomainPreview.value,
    remoteGasLimit: crossDomainPreview.remoteGasLimit,
    baseMirrorCallPreview: baseMirrorCall,
    crossDomainMessagePreview: crossDomainPreview,
    gas,
    nonce,
    preparedAt: nowIso(),
    expiresAt: request.expiresAt,
    liveAnchoredFactEvidence: request.anchoredFactEvidence.liveAnchoredFactEvidence,
    productionSignable: request.anchoredFactEvidence.productionSignable && profile.l1ChainId === 11155111,
    limitations: Object.freeze(limitations),
    transactionPrepared: true,
    transactionSigned: false,
    transactionSubmitted: false,
    crossDomainMessageSent: false,
    baseMirrorCalled: false,
    baseFactMirrored: false,
    baseExecutionPrepared: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    chainStateMutated: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export const requestL1ToBaseFactRelayPreparation = prepareL1ToBaseFactRelayTransaction;

export function validateL1ToBaseFactRelayTransactionDraft(
  draft: L1ToBaseFactRelayTransactionDraft
): RuntimeValidationResult {
  const errors: string[] = [];
  if (draft.methodSelector !== L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR) errors.push("relay selector mismatch");
  const expected = encodeL1ToBaseFactRelayCalldata({
    baseMirror: draft.binding.baseMirrorAddress,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow
  });
  if (draft.calldata !== expected) errors.push("relay calldata mismatch");
  if (draft.calldataHash !== keccak256(draft.calldata)) errors.push("calldata hash mismatch");
  if (draft.value !== "0") errors.push("unexpected relay value");
  if (draft.transactionSigned || draft.transactionSubmitted || draft.crossDomainMessageSent || draft.baseMirrorCalled) {
    errors.push("draft claims execution");
  }
  return validation(errors);
}

export function isL1ToBaseFactRelayStatus(value: unknown): value is L1ToBaseFactRelayStatus {
  return value === "relay_transaction_draft_created" || value === "relay_transaction_rejected";
}

export function isL1ToBaseFactRelayOutcome(value: unknown): value is L1ToBaseFactRelayOutcome {
  return [
    "relay_transaction_draft_created",
    "fact_not_anchored",
    "anchored_fact_evidence_ineligible",
    "relay_configuration_invalid",
    "relay_deployment_invalid",
    "mirror_deployment_invalid",
    "messenger_pair_invalid",
    "remote_sender_mismatch",
    "base_mirror_mismatch",
    "fact_pair_mismatch",
    "proof_input_hash_mismatch",
    "fee_unresolved",
    "fee_policy_violation",
    "gas_limit_unresolved",
    "network_mismatch",
    "calldata_encoding_failed",
    "nonce_unresolved",
    "expired",
    "malformed",
    "unsupported"
  ].includes(String(value));
}

export function createFixtureL1AnchoredFactStateReader(
  status: L1AnchoredFactStateReadResult["status"] = "fact_anchored"
): L1AnchoredFactStateReader {
  return {
    async readAnchoredFact() {
      return {
        status,
        checkedAt: nowIso(),
        blockNumber: 1,
        readerSource: status === "anchor_unavailable" ? "unavailable" : "fixture"
      };
    }
  };
}

export function createFixtureL1ToBaseRelayDeploymentReader(input: {
  readonly l1RelayAddress: string;
  readonly l1AnchorAddress: string;
  readonly l1MessengerAddress: string;
  readonly baseMirrorAddress: string;
  readonly baseMessengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly unavailable?: boolean;
}): L1ToBaseRelayDeploymentReader {
  return {
    async readRelayDeployment() {
      if (input.unavailable) {
        return {
          status: "unavailable",
          l1RelayAddress: input.l1RelayAddress,
          error: "reader unavailable"
        };
      }
      return {
        status: "found",
        l1RelayAddress: normalizeAddress(input.l1RelayAddress),
        l1AnchorAddress: normalizeAddress(input.l1AnchorAddress),
        l1MessengerAddress: normalizeAddress(input.l1MessengerAddress),
        baseMirrorAddress: normalizeAddress(input.baseMirrorAddress),
        baseMessengerAddress: normalizeAddress(input.baseMessengerAddress),
        authorizedL1RemoteSender: normalizeAddress(input.authorizedL1RemoteSender),
        relayMethodSelector: L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR,
        mirrorMethodSelector: BASE_FACT_MIRROR_METHOD_SELECTOR,
        blockNumber: 1
      };
    }
  };
}

export function createFixtureL1ToBaseRelayFeeQuoter(
  valueWei = "0"
): L1ToBaseRelayFeeQuoter {
  return {
    async quoteRelayFee() {
      return {
        status: "resolved",
        valueWei,
        checkedAt: nowIso(),
        source: "fixture"
      };
    }
  };
}

export function createFixtureL1ToBaseRelayGasEstimator(
  gasLimit = "300000"
): L1ToBaseRelayGasEstimator {
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

export function createFixtureL1ToBaseRelayNonceReader(
  nonce = "0"
): L1ToBaseRelayNonceReader {
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

export function createL1ToBaseRelayFixtureConfiguration(input: {
  readonly l1AnchorAddress: string;
  readonly l1RelayAddress: string;
  readonly l1MessengerAddress: string;
  readonly baseMessengerAddress: string;
  readonly baseMirrorAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly l1ChainId?: number;
  readonly baseChainId?: number;
  readonly minGasLimit?: string;
  readonly approvalStatus?: "accepted" | "draft" | "rejected";
}): L1ToBaseFactRelayConfiguration {
  return Object.freeze({
    configurationId: "fixture-l1-to-base-relay-config",
    approvalStatus: input.approvalStatus ?? "accepted",
    activeProfileId: "hardhat-base-local",
    networkProfiles: Object.freeze({
      "hardhat-base-local": Object.freeze({
        profileId: "hardhat-base-local",
        l1Network: "hardhat",
        l1ChainId: input.l1ChainId ?? 31337,
        baseNetwork: "hardhat",
        baseChainId: input.baseChainId ?? 31337,
        enabled: true
      })
    }),
    l1AnchorAddress: normalizeAddress(input.l1AnchorAddress),
    l1RelayContract: Object.freeze({
      address: normalizeAddress(input.l1RelayAddress),
      approved: true,
      methodSelector: L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR
    }),
    l1Messenger: Object.freeze({
      address: normalizeAddress(input.l1MessengerAddress),
      interfaceName: "IPhilCrossDomainMessenger",
      sendMessageSignature: "sendMessage(address,bytes)"
    }),
    baseMessenger: Object.freeze({
      address: normalizeAddress(input.baseMessengerAddress),
      interfaceName: "IBaseCrossDomainMessenger",
      sendMessageSignature: "sendMessage(address,bytes,uint32)"
    }),
    baseMirror: Object.freeze({
      address: normalizeAddress(input.baseMirrorAddress),
      approved: true,
      methodSelector: BASE_FACT_MIRROR_METHOD_SELECTOR
    }),
    authorizedL1RemoteSender: Object.freeze({
      address: normalizeAddress(input.authorizedL1RemoteSender),
      expectedOnBaseMirror: true
    }),
    gasPolicy: Object.freeze({
      minGasLimit: input.minGasLimit ?? "200000",
      maxGasLimit: "1000000"
    }),
    feePolicy: Object.freeze({
      valuePolicy: "nonpayable_zero_value",
      requiredValueWei: "0",
      maxValueWei: "0"
    }),
    messageEncodingVersion: "base-mirror-proof-input-hash-v1",
    mainnetAllowed: false
  });
}
