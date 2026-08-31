import { AbiCoder, Interface, getAddress, hexlify, keccak256 } from "ethers";

import {
  dataHash,
  normalizeBaseActionAuthorization,
  normalizeUnlockProofPackage,
  normalizeUnlockRequest,
  type BaseActionAuthorization,
  type Hex,
  type UnlockProofPackage,
  type UnlockRequest
} from "../hashes.ts";
import { assertValidUnlockProofPackage } from "../proof/publicInputs.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  type FinalizedAuthorizationPackage,
  validateFinalizedAuthorizationPackageShape
} from "./actionUnlockProofFinalization.ts";
import {
  validateCapabilityGrantActiveState,
  type AuthoritativeCapabilityGrant
} from "./authoritativeCapabilityGrant.ts";
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

const abiCoder = AbiCoder.defaultAbiCoder();
const ACTION_GATE_INTERFACE = new Interface([
  "function verifyAndConsume((address consumer,bytes32 ownerCommitment,bytes32 actionHash,bytes32 policyHash,bytes32 nullifier,bytes32 consumerDataHash,uint64 expiry) authorization,(string version,string proofType,(bytes32 ownerCommitment,bytes32 actionHash,bytes32 policyHash,bytes32 nullifier,bytes32 consumerDataHash,uint64 expiry) publicInputs,bytes32 proofInputHash,bytes proofBlob) proofPackage,bytes consumerData) payable returns (bytes)",
  "event AuthorizationConsumed(bytes32 indexed nullifier,bytes32 indexed authorizationDigest,address indexed consumer,address caller)"
]);

export const BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR = "0xb1952061" as const;

export type BaseMirroredFactEvidenceSource =
  | "live_base_receipt"
  | "local_hardhat_receipt"
  | "fixture_receipt"
  | "manual_reference"
  | "unsupported";

export interface BaseMirroredFactBinding {
  readonly baseChainId: number;
  readonly baseMirrorAddress: string;
  readonly baseMessengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly mirrorTransactionHash?: string;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly proofInputHash: Hex;
  readonly auditCorrelationId: string;
}

export interface BaseMirroredFactEvidence {
  readonly status: "mirrored_fact_evidence_valid" | "mirrored_fact_evidence_invalid";
  readonly source: BaseMirroredFactEvidenceSource;
  readonly binding: BaseMirroredFactBinding;
  readonly observedAt: string;
  readonly liveMirroredFactEvidence: boolean;
  readonly productionSignable: boolean;
  readonly errors: readonly string[];
}

export interface BaseMirroredFactVerificationResultValue {
  readonly status: "mirrored_fact_verified";
  readonly outcome: "mirrored_fact_verified";
  readonly binding: BaseMirroredFactBinding;
  readonly liveMirroredFactEvidence: boolean;
  readonly productionSignable: boolean;
  readonly factMirrored: true;
  readonly baseStateMutated: false;
  readonly observedAt: string;
}

export type BaseMirroredFactVerificationResult =
  RuntimeResult<BaseMirroredFactVerificationResultValue>;

export type BaseExecutionEvidenceStatus =
  | "execution_evidence_valid"
  | "execution_evidence_invalid"
  | "execution_evidence_stale"
  | "execution_evidence_unsupported";

export interface BaseExecutionAuthorizationEvidence {
  readonly status: BaseExecutionEvidenceStatus;
  readonly mirroredFactEvidence: BaseMirroredFactEvidence;
  readonly finalizedAuthorizationPackageId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: Hex;
  readonly actionHash: Hex;
  readonly consumerAddress: string;
  readonly auditCorrelationId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly errors: readonly string[];
}

export interface BaseActionGateNetworkProfile {
  readonly profileId: "hardhat-base-local" | "base-sepolia" | "base-mainnet-disabled";
  readonly network: "hardhat" | "base_sepolia" | "base";
  readonly chainId: number;
  readonly enabled: boolean;
}

export interface BaseVerifierReference {
  readonly address: string;
  readonly expectedProofType: "stwo-unlock-keccak-v1";
  readonly baseMirrorAddress: string;
  readonly approved: boolean;
}

export interface BaseExecutionFactMirrorReference {
  readonly address: string;
  readonly messengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly approved: boolean;
}

export interface BaseAuthorizationConsumerReference {
  readonly address: string;
  readonly consumerKind: "PhilUnlockConsumer";
  readonly actionGateAddress: string;
  readonly approved: boolean;
  readonly payable: true;
}

export interface BaseNullifierRegistryReference {
  readonly actionGateAddress: string;
  readonly storageKind: "consumedNullifier_mapping";
  readonly readerKind: "public_mapping_getter" | "fixture" | "rpc_view";
  readonly approved: boolean;
}

export interface BaseActionExecutionPolicy {
  readonly policyId: string;
  readonly supportedActionTypes: readonly string[];
  readonly allowedConsumerAddresses: readonly string[];
  readonly allowedTargetAddresses?: readonly string[];
  readonly maxValueWei?: string;
  readonly requireActiveCapabilityGrant: true;
  readonly requireEligibleSessionLifecycle: true;
  readonly requireFreshNullifierRead: true;
  readonly requireFreshMirroredFactEvidence: true;
  readonly applicationsMaySubmitDirectly: false;
}

export interface BaseActionGateConfiguration {
  readonly configurationId: string;
  readonly approvalStatus: "accepted" | "draft" | "rejected";
  readonly activeProfile: BaseActionGateNetworkProfile;
  readonly actionGateAddress: string;
  readonly verifier: BaseVerifierReference;
  readonly mirror: BaseExecutionFactMirrorReference;
  readonly consumer: BaseAuthorizationConsumerReference;
  readonly methodSelector: typeof BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR;
  readonly abiVersion: "phil-base-action-gate-v1";
  readonly supportedProofType: "stwo-unlock-keccak-v1";
  readonly valuePolicy: "exact_authorized_value";
  readonly mainnetAllowed: false;
  readonly nullifierRegistry?: BaseNullifierRegistryReference;
  readonly executionPolicy?: BaseActionExecutionPolicy;
}

export interface BaseActionGateDeploymentReadResult {
  readonly status: "deployment_valid" | "deployment_invalid" | "reader_unavailable";
  readonly chainId: number;
  readonly actionGateAddress: string;
  readonly verifierAddress: string;
  readonly mirrorAddress: string;
  readonly consumerAddress: string;
  readonly baseMessengerAddress: string;
  readonly authorizedL1RemoteSender: string;
  readonly methodSelector: string;
  readonly checkedAt: string;
  readonly error?: string;
}

export interface BaseActionGateDeploymentReader {
  readBaseActionGateDeployment(
    request: BaseActionGateDeploymentVerificationRequest
  ): Promise<BaseActionGateDeploymentReadResult>;
}

export interface BaseActionGateDeploymentVerificationRequest {
  readonly configuration: BaseActionGateConfiguration;
  readonly evidence: BaseMirroredFactEvidence;
}

export interface BaseActionGateDeploymentVerificationValue {
  readonly outcome: "deployment_valid";
  readonly read: BaseActionGateDeploymentReadResult;
}

export type BaseActionGateDeploymentVerificationResult =
  RuntimeResult<BaseActionGateDeploymentVerificationValue>;

export type BaseNullifierStateStatus =
  | "nullifier_available"
  | "nullifier_consumed"
  | "nullifier_state_unknown"
  | "reader_unavailable"
  | "configuration_mismatch"
  | "stale_read";

export interface BaseNullifierStateReadRequest {
  readonly actionGateAddress: string;
  readonly nullifier: Hex;
  readonly baseChainId: number;
}

export interface BaseNullifierStateReadResult {
  readonly status: BaseNullifierStateStatus;
  readonly actionGateAddress: string;
  readonly nullifier: Hex;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly error?: string;
  readonly nullifierConsumed: boolean;
  readonly nullifierReserved: false;
  readonly baseStateMutated: false;
}

export interface BaseNullifierFreshnessRequirement {
  readonly maxAgeMs: number;
  readonly recheckBeforeSigning: true;
  readonly recheckBeforeSubmission: true;
  readonly reservationPerformed: false;
}

export interface BaseNullifierStateReader {
  readNullifierState(request: BaseNullifierStateReadRequest): Promise<BaseNullifierStateReadResult>;
}

export interface BaseAuthorizationConsumerData {
  readonly encoded: Hex;
  readonly consumerDataHash: Hex;
  readonly encoding: "UnlockRequest";
  readonly rawCalldataExposedToAudit: false;
}

export interface BaseAuthorizationConsumerCall {
  readonly account: string;
  readonly target: string;
  readonly value: string;
  readonly callData: Hex;
  readonly consumerData: Hex;
  readonly consumerDataHash: Hex;
  readonly actionHash: Hex;
  readonly callDataHash: Hex;
}

export type BaseAuthorizationConsumerCallPreview = BaseAuthorizationConsumerCall;

export type BaseConsumerValuePolicy =
  | "exact_authorized_value"
  | "zero_value_only"
  | "policy_limited_value";

export interface BaseConsumerCallBinding {
  readonly consumerAddress: string;
  readonly account: string;
  readonly target: string;
  readonly value: string;
  readonly callDataHash: Hex;
  readonly consumerDataHash: Hex;
  readonly actionHash: Hex;
  readonly policyHash: Hex;
  readonly ownerCommitment: Hex;
  readonly expiry: string;
  readonly valuePolicy: BaseConsumerValuePolicy;
}

export interface BaseAuthorizationExecutionGasEstimateReference {
  readonly status: "estimated" | "unavailable" | "failed";
  readonly gasLimit?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "eth_estimateGas" | "none";
  readonly error?: string;
}

export interface BaseAuthorizationExecutionNonceReference {
  readonly status: "resolved" | "unresolved" | "unavailable";
  readonly nonce?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc" | "none";
}

export interface BaseAuthorizationExecutionFeeDataReference {
  readonly status: "resolved" | "unresolved" | "unavailable";
  readonly maxFeePerGas?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "rpc" | "none";
}

export interface BaseAuthorizationExecutionSimulationRequest {
  readonly from: string;
  readonly to: string;
  readonly data: Hex;
  readonly value: string;
  readonly chainId: number;
}

export interface BaseAuthorizationExecutionSimulationResult {
  readonly status:
    | "simulation_succeeded"
    | "simulation_reverted"
    | "simulation_unavailable"
    | "nullifier_consumed"
    | "fact_missing"
    | "verifier_rejected"
    | "consumer_reverted"
    | "configuration_mismatch"
    | "state_changed_since_read"
    | "unknown_failure";
  readonly checkedAt: string;
  readonly returnData?: Hex;
  readonly error?: string;
  readonly stateMutated: false;
}

export interface BaseAuthorizationExecutionSimulator {
  simulateBaseAuthorizationExecution(
    request: BaseAuthorizationExecutionSimulationRequest
  ): Promise<BaseAuthorizationExecutionSimulationResult>;
}

export interface BaseExecutionGasEstimator {
  estimateGas(request: BaseAuthorizationExecutionSimulationRequest): Promise<BaseAuthorizationExecutionGasEstimateReference>;
}

export interface BaseExecutionNonceReader {
  readNonce(request: { readonly account: string; readonly chainId: number }): Promise<BaseAuthorizationExecutionNonceReference>;
}

export interface BaseExecutionFeeDataReader {
  readFeeData(request: { readonly chainId: number }): Promise<BaseAuthorizationExecutionFeeDataReference>;
}

export type BaseAuthorizationExecutionStatus =
  | "execution_transaction_draft_created"
  | "execution_transaction_rejected";

export type BaseAuthorizationExecutionOutcome =
  | "execution_transaction_draft_created"
  | "mirrored_fact_missing"
  | "mirrored_fact_mismatch"
  | "package_ineligible"
  | "capability_ineligible"
  | "session_ineligible"
  | "approval_ineligible"
  | "nullifier_consumed"
  | "nullifier_state_unknown"
  | "action_gate_configuration_invalid"
  | "verifier_configuration_invalid"
  | "consumer_configuration_invalid"
  | "consumer_data_mismatch"
  | "proof_input_hash_mismatch"
  | "value_policy_violation"
  | "simulation_failed"
  | "gas_estimate_unavailable"
  | "nonce_unresolved"
  | "expired"
  | "malformed"
  | "unsupported";

export type BaseAuthorizationExecutionReason =
  | "mirrored_fact_verified"
  | "finalized_package_validated"
  | "capability_grant_active"
  | "session_lifecycle_eligible"
  | "nullifier_available"
  | "configuration_verified"
  | "consumer_data_bound"
  | "calldata_encoded"
  | "simulation_succeeded"
  | "gas_fee_nonce_referenced"
  | "unsigned_draft_created";

export type BaseAuthorizationExecutionLimitation =
  | "preparation_only"
  | "unsigned_transaction_only"
  | "unsubmitted_transaction_only"
  | "read_only_nullifier_snapshot"
  | "read_only_simulation_only"
  | "gas_estimate_not_execution_guarantee"
  | "requires_revalidation_before_signing"
  | "requires_revalidation_before_submission"
  | "no_user_operation_created"
  | "no_application_submission_authority";

export interface BaseAuthorizationExecutionBinding {
  readonly finalizedAuthorizationPackageId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: Hex;
  readonly actionHash: Hex;
  readonly policyHash: Hex;
  readonly nullifier: Hex;
  readonly proofInputHash: Hex;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly actionGateAddress: string;
  readonly verifierAddress: string;
  readonly baseMirrorAddress: string;
  readonly consumerAddress: string;
  readonly senderAccount: string;
  readonly value: string;
  readonly calldataHash: Hex;
  readonly consumerDataHash: Hex;
  readonly auditCorrelationId: string;
}

export interface BaseAuthorizationExecutionTransactionDraft {
  readonly baseAuthorizationExecutionTransactionDraftId: string;
  readonly status: "execution_transaction_draft_created";
  readonly outcome: "execution_transaction_draft_created";
  readonly binding: BaseAuthorizationExecutionBinding;
  readonly to: string;
  readonly from: string;
  readonly chainId: number;
  readonly methodName: "verifyAndConsume";
  readonly methodSelector: typeof BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR;
  readonly calldata: Hex;
  readonly calldataHash: Hex;
  readonly value: string;
  readonly consumerCallPreview: BaseAuthorizationConsumerCall;
  readonly nullifierState: BaseNullifierStateReadResult;
  readonly simulation?: BaseAuthorizationExecutionSimulationResult;
  readonly gas: BaseAuthorizationExecutionGasEstimateReference;
  readonly nonce: BaseAuthorizationExecutionNonceReference;
  readonly fee: BaseAuthorizationExecutionFeeDataReference;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly transactionPrepared: true;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly simulationPerformed: boolean;
  readonly simulationSucceeded: boolean;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly baseStateMutated: false;
  readonly userOperationCreated: false;
  readonly applicationCanSubmitDirectly: false;
  readonly liveMirroredFactEvidence: boolean;
  readonly productionSignable: boolean;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface BaseAuthorizationExecutionPreparationRequest {
  readonly requestId: string;
  readonly finalizedAuthorizationPackage: FinalizedAuthorizationPackage;
  readonly baseActionAuthorization: BaseActionAuthorization;
  readonly proofPackage: UnlockProofPackage;
  readonly consumerData: Hex;
  readonly mirroredFactEvidence: BaseMirroredFactEvidence;
  readonly activeCapabilityGrant: AuthoritativeCapabilityGrant;
  readonly sessionLifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly configuration: BaseActionGateConfiguration;
  readonly deploymentReader: BaseActionGateDeploymentReader;
  readonly nullifierStateReader: BaseNullifierStateReader;
  readonly senderAccount: string;
  readonly simulator?: BaseAuthorizationExecutionSimulator;
  readonly gasEstimator?: BaseExecutionGasEstimator;
  readonly nonceReader?: BaseExecutionNonceReader;
  readonly feeDataReader?: BaseExecutionFeeDataReader;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type BaseAuthorizationExecutionPreparationResult =
  RuntimeResult<BaseAuthorizationExecutionTransactionDraft>;

const EXECUTION_OUTCOMES = new Set<BaseAuthorizationExecutionOutcome>([
  "execution_transaction_draft_created",
  "mirrored_fact_missing",
  "mirrored_fact_mismatch",
  "package_ineligible",
  "capability_ineligible",
  "session_ineligible",
  "approval_ineligible",
  "nullifier_consumed",
  "nullifier_state_unknown",
  "action_gate_configuration_invalid",
  "verifier_configuration_invalid",
  "consumer_configuration_invalid",
  "consumer_data_mismatch",
  "proof_input_hash_mismatch",
  "value_policy_violation",
  "simulation_failed",
  "gas_estimate_unavailable",
  "nonce_unresolved",
  "expired",
  "malformed",
  "unsupported"
]);

const EXECUTION_STATUSES = new Set<BaseAuthorizationExecutionStatus>([
  "execution_transaction_draft_created",
  "execution_transaction_rejected"
]);

function nowIso(): string {
  return new Date().toISOString();
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function normalizeHex(value: string): Hex {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  return `0x${raw.toLowerCase()}` as Hex;
}

function factHighLowFromProofInputHash(proofInputHash: Hex): { factHigh: Hex; factLow: Hex } {
  const raw = proofInputHash.slice(2).padStart(64, "0");
  return {
    factHigh: `0x${raw.slice(0, 32)}` as Hex,
    factLow: `0x${raw.slice(32)}` as Hex
  };
}

function createExecutionAuditDraft(input: {
  readonly requestKind: string;
  readonly outcome: string;
  readonly summary: string;
  readonly request?: BaseAuthorizationExecutionPreparationRequest;
  readonly draft?: BaseAuthorizationExecutionTransactionDraft;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "execution_transaction_draft_created"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: input.requestKind,
    summary: input.summary,
    auditCorrelationId: input.request?.auditCorrelationId ?? input.draft?.binding.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      packageId: input.request?.finalizedAuthorizationPackage.finalizedAuthorizationPackageId
        ?? input.draft?.binding.finalizedAuthorizationPackageId,
      proofInputHash: input.request?.finalizedAuthorizationPackage.actionUnlockAuthorization.proofInputHash
        ?? input.draft?.binding.proofInputHash,
      factPair: input.request
        ? [
          input.request.mirroredFactEvidence.binding.factHigh,
          input.request.mirroredFactEvidence.binding.factLow
        ]
        : input.draft
          ? [input.draft.binding.factHigh, input.draft.binding.factLow]
          : undefined,
      nullifier: input.request?.baseActionAuthorization.nullifier ?? input.draft?.binding.nullifier,
      actionGate: input.request?.configuration.actionGateAddress ?? input.draft?.binding.actionGateAddress,
      verifier: input.request?.configuration.verifier.address ?? input.draft?.binding.verifierAddress,
      consumer: input.request?.configuration.consumer.address ?? input.draft?.binding.consumerAddress,
      methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
      calldataHash: input.draft?.calldataHash,
      value: input.draft?.value,
      simulation: input.draft?.simulation?.status,
      gas: input.draft?.gas.status,
      nonce: input.draft?.nonce.status
    }
  });
}

function deny(
  outcome: BaseAuthorizationExecutionOutcome,
  errors: readonly string[],
  request: BaseAuthorizationExecutionPreparationRequest,
  auditDraftCollector?: AuditDraftCollector
): RuntimeResult<never> {
  const auditEventDraft = createExecutionAuditDraft({
    requestKind: "requestBaseAuthorizationExecutionPreparation",
    outcome,
    summary: "Base authorization execution preparation was rejected; no transaction was signed or submitted.",
    request,
    errors
  });
  auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: `BASE_AUTHORIZATION_EXECUTION_${outcome.toUpperCase()}`,
    category: outcome.includes("configuration")
      ? "unsupported_operation"
      : outcome.includes("nullifier")
        ? "invalid_authorization_package"
        : outcome.includes("session")
          ? "session_expired"
          : outcome.includes("capability")
            ? "capability_denied"
            : "invalid_authorization_package",
    message: "Base authorization execution preparation was rejected.",
    recoverable: true,
    details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
  }, { auditEventId: auditEventDraft.eventDraftId });
}

export function isBaseAuthorizationExecutionOutcome(
  value: unknown
): value is BaseAuthorizationExecutionOutcome {
  return EXECUTION_OUTCOMES.has(value as BaseAuthorizationExecutionOutcome);
}

export function isBaseAuthorizationExecutionStatus(
  value: unknown
): value is BaseAuthorizationExecutionStatus {
  return EXECUTION_STATUSES.has(value as BaseAuthorizationExecutionStatus);
}

export function validateBaseAuthorizationExecutionPreparationRequest(
  request: BaseAuthorizationExecutionPreparationRequest
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (!request || typeof request !== "object") {
    return Object.freeze({ valid: false, errors: Object.freeze(["request must be an object"]) });
  }
  if (!request.requestId) errors.push("requestId is required");
  if (!request.finalizedAuthorizationPackage) errors.push("finalizedAuthorizationPackage is required");
  if (!request.baseActionAuthorization) errors.push("baseActionAuthorization is required");
  if (!request.proofPackage) errors.push("proofPackage is required");
  if (!request.consumerData) errors.push("consumerData is required");
  if (!request.mirroredFactEvidence) errors.push("mirroredFactEvidence is required");
  if (!request.activeCapabilityGrant) errors.push("activeCapabilityGrant is required");
  if (!request.sessionLifecycleSnapshot) errors.push("sessionLifecycleSnapshot is required");
  if (!request.configuration) errors.push("configuration is required");
  if (!request.deploymentReader) errors.push("deploymentReader is required");
  if (!request.nullifierStateReader) errors.push("nullifierStateReader is required");
  if (!request.senderAccount) errors.push("senderAccount is required");
  if (!request.issuedAt || Number.isNaN(Date.parse(request.issuedAt))) {
    errors.push("issuedAt must be a parseable date");
  }
  if (!request.expiresAt || Number.isNaN(Date.parse(request.expiresAt))) {
    errors.push("expiresAt must be a parseable date");
  }
  if (!request.auditCorrelationId) errors.push("auditCorrelationId is required");
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export function createBaseMirroredFactEvidence(input: {
  readonly source: BaseMirroredFactEvidenceSource;
  readonly binding: BaseMirroredFactBinding;
  readonly observedAt?: string;
  readonly errors?: readonly string[];
}): BaseMirroredFactEvidence {
  const errors = [...(input.errors ?? [])];
  if (input.source === "unsupported") errors.push("unsupported evidence source");
  return Object.freeze({
    status: errors.length === 0
      ? "mirrored_fact_evidence_valid"
      : "mirrored_fact_evidence_invalid",
    source: input.source,
    binding: Object.freeze(input.binding),
    observedAt: input.observedAt ?? nowIso(),
    liveMirroredFactEvidence: input.source === "live_base_receipt",
    productionSignable: input.source === "live_base_receipt" && errors.length === 0,
    errors: Object.freeze(errors)
  });
}

export function requestBaseMirroredFactVerification(
  evidence: BaseMirroredFactEvidence
): BaseMirroredFactVerificationResult {
  if (evidence.status !== "mirrored_fact_evidence_valid") {
    return runtimeDenied({
      code: "BASE_MIRRORED_FACT_EVIDENCE_INVALID",
      category: "proof_failed",
      message: "Base mirrored fact evidence is invalid.",
      recoverable: true,
      details: { outcome: "mirrored_fact_missing", errors: evidence.errors }
    });
  }
  return runtimeOk(Object.freeze({
    status: "mirrored_fact_verified" as const,
    outcome: "mirrored_fact_verified" as const,
    binding: evidence.binding,
    liveMirroredFactEvidence: evidence.liveMirroredFactEvidence,
    productionSignable: evidence.productionSignable,
    factMirrored: true as const,
    baseStateMutated: false as const,
    observedAt: evidence.observedAt
  }));
}

export async function requestBaseNullifierState(
  reader: BaseNullifierStateReader,
  request: BaseNullifierStateReadRequest
): Promise<RuntimeResult<BaseNullifierStateReadResult>> {
  const read = await reader.readNullifierState(request);
  if (read.status !== "nullifier_available") {
    return runtimeDenied({
      code: "BASE_NULLIFIER_UNAVAILABLE",
      category: "invalid_authorization_package",
      message: "Base nullifier state is not available for execution preparation.",
      recoverable: true,
      details: { outcome: read.status }
    });
  }
  return runtimeOk(Object.freeze(read));
}

export async function verifyBaseActionGateDeployment(
  request: BaseActionGateDeploymentVerificationRequest,
  reader: BaseActionGateDeploymentReader
): Promise<BaseActionGateDeploymentVerificationResult> {
  const read = await reader.readBaseActionGateDeployment(request);
  const config = request.configuration;
  const errors: string[] = [];
  if (read.status !== "deployment_valid") errors.push(read.error ?? "deployment invalid");
  if (read.chainId !== config.activeProfile.chainId) errors.push("chain mismatch");
  if (normalizeAddress(read.actionGateAddress) !== normalizeAddress(config.actionGateAddress)) {
    errors.push("action gate mismatch");
  }
  if (normalizeAddress(read.verifierAddress) !== normalizeAddress(config.verifier.address)) {
    errors.push("verifier mismatch");
  }
  if (normalizeAddress(read.mirrorAddress) !== normalizeAddress(config.mirror.address)) {
    errors.push("mirror mismatch");
  }
  if (normalizeAddress(read.consumerAddress) !== normalizeAddress(config.consumer.address)) {
    errors.push("consumer mismatch");
  }
  if (normalizeAddress(read.baseMessengerAddress) !== normalizeAddress(config.mirror.messengerAddress)) {
    errors.push("base messenger mismatch");
  }
  if (normalizeAddress(read.authorizedL1RemoteSender) !== normalizeAddress(config.mirror.authorizedL1RemoteSender)) {
    errors.push("authorized remote sender mismatch");
  }
  if (read.methodSelector !== BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR) errors.push("selector mismatch");
  if (config.approvalStatus !== "accepted") errors.push("configuration not accepted");
  if (config.activeProfile.chainId === 8453 || config.mainnetAllowed !== false) errors.push("mainnet prohibited");
  if (errors.length > 0) {
    return runtimeDenied({
      code: "BASE_ACTION_GATE_DEPLOYMENT_INVALID",
      category: "unsupported_operation",
      message: "Base ActionGate deployment verification failed.",
      recoverable: true,
      details: { outcome: "action_gate_configuration_invalid", errors }
    });
  }
  return runtimeOk(Object.freeze({ outcome: "deployment_valid" as const, read }));
}

export function encodeBaseVerifyAndConsumeCalldata(input: {
  readonly authorization: BaseActionAuthorization;
  readonly proofPackage: UnlockProofPackage;
  readonly consumerData: Hex;
}): Hex {
  const authorization = normalizeBaseActionAuthorization(input.authorization);
  const proofPackage = normalizeUnlockProofPackage(input.proofPackage);
  return ACTION_GATE_INTERFACE.encodeFunctionData("verifyAndConsume", [
    authorization,
    proofPackage,
    input.consumerData
  ]) as Hex;
}

function decodeConsumerData(consumerData: Hex): BaseAuthorizationConsumerCall {
  const [decoded] = abiCoder.decode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    consumerData
  ) as unknown as [UnlockRequest];
  const request = normalizeUnlockRequest(decoded);
  const callData = hexlify(request.callData) as Hex;
  return Object.freeze({
    account: request.account,
    target: request.target,
    value: request.value.toString(),
    callData,
    consumerData,
    consumerDataHash: dataHash(consumerData),
    actionHash: "0x" as Hex,
    callDataHash: dataHash(callData)
  });
}

function outcomeForErrors(errors: readonly string[]): BaseAuthorizationExecutionOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("mirrored fact")) return "mirrored_fact_mismatch";
  if (joined.includes("package")) return "package_ineligible";
  if (joined.includes("capability")) return "capability_ineligible";
  if (joined.includes("session")) return "session_ineligible";
  if (joined.includes("approval")) return "approval_ineligible";
  if (joined.includes("nullifier consumed")) return "nullifier_consumed";
  if (joined.includes("nullifier")) return "nullifier_state_unknown";
  if (joined.includes("verifier")) return "verifier_configuration_invalid";
  if (joined.includes("consumer")) return "consumer_configuration_invalid";
  if (joined.includes("proofInputHash")) return "proof_input_hash_mismatch";
  if (joined.includes("value")) return "value_policy_violation";
  if (joined.includes("simulation")) return "simulation_failed";
  if (joined.includes("gas")) return "gas_estimate_unavailable";
  if (joined.includes("nonce")) return "nonce_unresolved";
  if (joined.includes("expired")) return "expired";
  if (joined.includes("configuration") || joined.includes("ActionGate")) {
    return "action_gate_configuration_invalid";
  }
  return "malformed";
}

export async function prepareBaseAuthorizationExecutionTransaction(
  request: BaseAuthorizationExecutionPreparationRequest
): Promise<BaseAuthorizationExecutionPreparationResult> {
  const errors: string[] = [];
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("request expired");
  const finalizedShape = validateFinalizedAuthorizationPackageShape(request.finalizedAuthorizationPackage);
  errors.push(...finalizedShape.errors.map((error) => `package ${error}`));
  const grantShape = validateCapabilityGrantActiveState(request.activeCapabilityGrant, request.issuedAt);
  errors.push(...grantShape.errors.map((error) => `capability ${error}`));
  const sessionShape = validateUserSessionLifecycleSnapshotShape(request.sessionLifecycleSnapshot);
  errors.push(...sessionShape.errors.map((error) => `session ${error}`));
  if (!["unlocked", "recovery_mode"].includes(request.sessionLifecycleSnapshot.state)) {
    errors.push("session state ineligible");
  }
  const mirrored = requestBaseMirroredFactVerification(request.mirroredFactEvidence);
  if (mirrored.status !== "approved") errors.push("mirrored fact missing");

  let normalizedAuthorization: BaseActionAuthorization;
  let normalizedProofPackage: UnlockProofPackage;
  let consumerCall: BaseAuthorizationConsumerCall;
  try {
    normalizedAuthorization = normalizeBaseActionAuthorization(request.baseActionAuthorization);
    normalizedProofPackage = normalizeUnlockProofPackage(request.proofPackage);
    assertValidUnlockProofPackage({
      chainId: request.configuration.activeProfile.chainId,
      authorization: normalizedAuthorization,
      consumerData: request.consumerData,
      proofPackage: normalizedProofPackage,
      requireProofArtifact: true
    });
    consumerCall = decodeConsumerData(request.consumerData);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "package malformed");
    normalizedAuthorization = request.baseActionAuthorization;
    normalizedProofPackage = request.proofPackage;
    consumerCall = {
      account: "0x0000000000000000000000000000000000000000",
      target: "0x0000000000000000000000000000000000000000",
      value: "0",
      callData: "0x",
      consumerData: request.consumerData,
      consumerDataHash: dataHash(request.consumerData),
      actionHash: "0x",
      callDataHash: "0x"
    };
  }
  const finalized = request.finalizedAuthorizationPackage;
  const finalAuth = finalized.actionUnlockAuthorization;
  if (finalized.authorizationPackageFinalized !== true
    || finalized.proofGenerated !== true
    || finalized.proofVerifiedLocally !== true) {
    errors.push("package is not finalized");
  }
  if (normalizedAuthorization.ownerCommitment !== finalAuth.ownerCommitment
    || normalizedAuthorization.actionHash !== finalAuth.actionHash
    || normalizedAuthorization.policyHash !== finalAuth.policyHash
    || normalizedAuthorization.nullifier !== finalAuth.nullifier
    || normalizedAuthorization.consumerDataHash !== finalAuth.consumerDataHash
    || BigInt(normalizedAuthorization.expiry) !== BigInt(finalAuth.expiry)) {
    errors.push("package authorization tuple mismatch");
  }
  if (normalizedProofPackage.proofInputHash !== finalAuth.proofInputHash) errors.push("proofInputHash mismatch");
  if (normalizedProofPackage.proofType !== "stwo-unlock-keccak-v1") errors.push("proof type mismatch");
  if (normalizedProofPackage.proofBlob === "0x") errors.push("proof blob missing");
  const expectedFact = factHighLowFromProofInputHash(finalAuth.proofInputHash);
  if (request.mirroredFactEvidence.binding.factHigh !== expectedFact.factHigh
    || request.mirroredFactEvidence.binding.factLow !== expectedFact.factLow
    || request.mirroredFactEvidence.binding.proofInputHash !== finalAuth.proofInputHash) {
    errors.push("mirrored fact mismatch");
  }
  if (normalizeAddress(normalizedAuthorization.consumer) !== normalizeAddress(request.configuration.consumer.address)) {
    errors.push("consumer mismatch");
  }
  if (request.activeCapabilityGrant.binding.sessionId !== finalized.binding.sessionId
    || request.activeCapabilityGrant.binding.applicationId !== finalized.binding.applicationId
    || request.activeCapabilityGrant.binding.ownerCommitment !== finalized.binding.ownerCommitment) {
    errors.push("capability binding mismatch");
  }
  if (request.sessionLifecycleSnapshot.sessionId !== finalized.binding.sessionId) {
    errors.push("session binding mismatch");
  }
  if (BigInt(consumerCall.value) < 0n) errors.push("value invalid");
  const deployment = await verifyBaseActionGateDeployment({
    configuration: request.configuration,
    evidence: request.mirroredFactEvidence
  }, request.deploymentReader);
  if (deployment.status !== "approved") {
    errors.push(...((deployment.error?.details?.errors as string[] | undefined) ?? ["ActionGate configuration invalid"]));
  }
  const nullifier = await request.nullifierStateReader.readNullifierState({
    actionGateAddress: request.configuration.actionGateAddress,
    nullifier: normalizedAuthorization.nullifier,
    baseChainId: request.configuration.activeProfile.chainId
  });
  if (nullifier.status === "nullifier_consumed") errors.push("nullifier consumed");
  if (nullifier.status !== "nullifier_available") errors.push("nullifier state unavailable");

  if (errors.length > 0) {
    return deny(outcomeForErrors(errors), errors, request, request.auditDraftCollector);
  }

  const calldata = encodeBaseVerifyAndConsumeCalldata({
    authorization: normalizedAuthorization,
    proofPackage: normalizedProofPackage,
    consumerData: request.consumerData
  });
  const calldataHash = keccak256(calldata) as Hex;
  const simulationRequest = {
    from: normalizeAddress(request.senderAccount),
    to: normalizeAddress(request.configuration.actionGateAddress),
    data: calldata,
    value: consumerCall.value,
    chainId: request.configuration.activeProfile.chainId
  };
  const simulation = request.simulator
    ? await request.simulator.simulateBaseAuthorizationExecution(simulationRequest)
    : undefined;
  if (simulation && simulation.status !== "simulation_succeeded") {
    return deny("simulation_failed", [`simulation ${simulation.status}`], request, request.auditDraftCollector);
  }
  const gas = request.gasEstimator
    ? await request.gasEstimator.estimateGas(simulationRequest)
    : { status: "unavailable" as const, checkedAt: nowIso(), source: "none" as const };
  if (gas.status === "failed") {
    return deny("gas_estimate_unavailable", [gas.error ?? "gas estimate failed"], request, request.auditDraftCollector);
  }
  const nonce = request.nonceReader
    ? await request.nonceReader.readNonce({
      account: request.senderAccount,
      chainId: request.configuration.activeProfile.chainId
    })
    : { status: "unresolved" as const, checkedAt: nowIso(), source: "none" as const };
  const fee = request.feeDataReader
    ? await request.feeDataReader.readFeeData({ chainId: request.configuration.activeProfile.chainId })
    : { status: "unresolved" as const, checkedAt: nowIso(), source: "none" as const };
  if (nonce.status !== "resolved") {
    return deny("nonce_unresolved", ["nonce unresolved"], request, request.auditDraftCollector);
  }
  const draftBase = {
    baseAuthorizationExecutionTransactionDraftId: createAuditCorrelationId([
      finalized.finalizedAuthorizationPackageId,
      calldataHash,
      "base-authorization-execution-draft"
    ]),
    status: "execution_transaction_draft_created" as const,
    outcome: "execution_transaction_draft_created" as const,
    binding: {
      finalizedAuthorizationPackageId: finalized.finalizedAuthorizationPackageId,
      authoritativeCapabilityGrantId: request.activeCapabilityGrant.authoritativeCapabilityGrantId,
      sessionId: finalized.binding.sessionId,
      applicationId: finalized.binding.applicationId,
      ownerCommitment: finalized.binding.ownerCommitment,
      actionHash: normalizedAuthorization.actionHash,
      policyHash: normalizedAuthorization.policyHash,
      nullifier: normalizedAuthorization.nullifier,
      proofInputHash: finalAuth.proofInputHash,
      factHigh: expectedFact.factHigh,
      factLow: expectedFact.factLow,
      actionGateAddress: request.configuration.actionGateAddress,
      verifierAddress: request.configuration.verifier.address,
      baseMirrorAddress: request.configuration.mirror.address,
      consumerAddress: request.configuration.consumer.address,
      senderAccount: request.senderAccount,
      value: consumerCall.value,
      calldataHash,
      consumerDataHash: normalizedAuthorization.consumerDataHash,
      auditCorrelationId: request.auditCorrelationId
    },
    to: normalizeAddress(request.configuration.actionGateAddress),
    from: normalizeAddress(request.senderAccount),
    chainId: request.configuration.activeProfile.chainId,
    methodName: "verifyAndConsume" as const,
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    calldata,
    calldataHash,
    value: consumerCall.value,
    consumerCallPreview: Object.freeze({
      ...consumerCall,
      actionHash: normalizedAuthorization.actionHash
    }),
    nullifierState: Object.freeze(nullifier),
    simulation,
    gas,
    nonce,
    fee,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    transactionPrepared: true as const,
    transactionSigned: false as const,
    transactionSubmitted: false as const,
    simulationPerformed: simulation !== undefined,
    simulationSucceeded: simulation?.status === "simulation_succeeded",
    nullifierConsumed: false as const,
    consumerExecuted: false as const,
    baseStateMutated: false as const,
    userOperationCreated: false as const,
    applicationCanSubmitDirectly: false as const,
    liveMirroredFactEvidence: request.mirroredFactEvidence.liveMirroredFactEvidence,
    productionSignable: request.mirroredFactEvidence.productionSignable
  };
  const auditEventDraft = createExecutionAuditDraft({
    requestKind: "requestBaseAuthorizationExecutionPreparation",
    outcome: "execution_transaction_draft_created",
    summary: "Unsigned Base authorization execution transaction draft created; no signing, submission, nullifier consumption, or consumer execution occurred.",
    request,
    draft: draftBase as BaseAuthorizationExecutionTransactionDraft
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(Object.freeze({
    ...draftBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as BaseAuthorizationExecutionTransactionDraft);
}

export const requestBaseAuthorizationExecutionPreparation =
  prepareBaseAuthorizationExecutionTransaction;

export function validateBaseAuthorizationExecutionTransactionDraft(
  draft: BaseAuthorizationExecutionTransactionDraft
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (draft.status !== "execution_transaction_draft_created") errors.push("status invalid");
  if (draft.methodSelector !== BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR) errors.push("selector invalid");
  if (!draft.calldata.startsWith(BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR)) errors.push("calldata selector mismatch");
  if (draft.transactionSigned !== false || draft.transactionSubmitted !== false) errors.push("draft must be unsigned and unsubmitted");
  if (draft.nullifierConsumed !== false || draft.consumerExecuted !== false || draft.baseStateMutated !== false) {
    errors.push("draft must not mutate execution state");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export function createFixtureBaseActionGateDeploymentReader(input: {
  readonly chainId: number;
  readonly actionGateAddress: string;
  readonly verifierAddress: string;
  readonly mirrorAddress: string;
  readonly consumerAddress: string;
  readonly baseMessengerAddress: string;
  readonly authorizedL1RemoteSender: string;
}): BaseActionGateDeploymentReader {
  return {
    async readBaseActionGateDeployment() {
      return {
        status: "deployment_valid",
        chainId: input.chainId,
        actionGateAddress: input.actionGateAddress,
        verifierAddress: input.verifierAddress,
        mirrorAddress: input.mirrorAddress,
        consumerAddress: input.consumerAddress,
        baseMessengerAddress: input.baseMessengerAddress,
        authorizedL1RemoteSender: input.authorizedL1RemoteSender,
        methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
        checkedAt: nowIso()
      };
    }
  };
}

export function createFixtureBaseNullifierStateReader(
  status: BaseNullifierStateStatus = "nullifier_available"
): BaseNullifierStateReader {
  return {
    async readNullifierState(request) {
      return {
        status,
        actionGateAddress: request.actionGateAddress,
        nullifier: request.nullifier,
        checkedAt: nowIso(),
        nullifierConsumed: status === "nullifier_consumed",
        nullifierReserved: false,
        baseStateMutated: false
      };
    }
  };
}

export function createFixtureBaseAuthorizationExecutionSimulator(
  status: BaseAuthorizationExecutionSimulationResult["status"] = "simulation_succeeded"
): BaseAuthorizationExecutionSimulator {
  return {
    async simulateBaseAuthorizationExecution() {
      return { status, checkedAt: nowIso(), returnData: "0x", stateMutated: false };
    }
  };
}

export function createFixtureBaseExecutionGasEstimator(
  gasLimit = "500000"
): BaseExecutionGasEstimator {
  return {
    async estimateGas() {
      return { status: "estimated", gasLimit, checkedAt: nowIso(), source: "fixture" };
    }
  };
}

export function createFixtureBaseExecutionNonceReader(
  nonce = "0"
): BaseExecutionNonceReader {
  return {
    async readNonce() {
      return { status: "resolved", nonce, checkedAt: nowIso(), source: "fixture" };
    }
  };
}

export function createFixtureBaseExecutionFeeDataReader(): BaseExecutionFeeDataReader {
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
