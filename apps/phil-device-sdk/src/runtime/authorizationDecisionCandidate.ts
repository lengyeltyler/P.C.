import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { AuthoritativeCapabilityGrant } from "./authoritativeCapabilityGrant.ts";
import { validateAuthoritativeCapabilityGrantShape } from "./authoritativeCapabilityGrant.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionLifecycleSnapshot,
  UserSessionLifecycleState
} from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  Intent,
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext
} from "./types.ts";

export type AuthorizationActionType =
  | "message_signature"
  | "transaction_preparation"
  | "transaction_submission"
  | "contract_call"
  | "smart_account_deployment"
  | "session_key_management"
  | "credential_rotation"
  | "credential_revocation"
  | "encrypted_backup_export"
  | "recovery_start"
  | "recovery_approval"
  | "audit_review";

export type AuthorizationDecisionCandidateStatus =
  | "candidate_created"
  | "candidate_rejected"
  | "candidate_malformed"
  | "candidate_replayed"
  | "candidate_expired"
  | "candidate_unsupported";

export type AuthorizationDecisionCandidateOutcome =
  | "authorization_candidate_created"
  | "capability_grant_ineligible"
  | "capability_missing"
  | "capability_expired"
  | "capability_revoked"
  | "action_not_permitted"
  | "scope_exceeded"
  | "target_not_permitted"
  | "value_limit_exceeded"
  | "method_not_permitted"
  | "duration_ineligible"
  | "session_state_ineligible"
  | "application_mismatch"
  | "owner_mismatch"
  | "correlation_mismatch"
  | "additional_user_approval_required"
  | "proof_required"
  | "unsupported_action"
  | "evidence_replayed"
  | "expired"
  | "malformed"
  | "unsupported";

export type AuthorizationDecisionCandidateReason =
  | "active-capability-grant-accepted"
  | "exact-action-intent-accepted"
  | "action-capability-mapping-matched"
  | "scope-within-grant"
  | "target-within-grant"
  | "method-within-grant"
  | "value-within-grant"
  | "network-within-grant"
  | "duration-within-grant"
  | "authorization-engine-candidate-only"
  | "no-action-authorization"
  | "no-authorization-package"
  | "no-proof-input-hash"
  | "no-execution"
  | (string & {});

export type AuthorizationDecisionCandidateRequirement =
  | "active_authoritative_capability_grant"
  | "exact_action_intent"
  | "current_user_session_context"
  | "eligible_lifecycle_state"
  | "capability_mapping_match"
  | "scope_within_capability_grant"
  | "target_within_capability_grant"
  | "method_within_capability_grant"
  | "value_within_capability_grant"
  | "network_within_capability_grant"
  | "bounded_validity_window";

export type AuthorizationDecisionCandidateLimitation =
  | "authorization_candidate_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "no_action_authorization"
  | "no_authorization_package"
  | "no_action_unlock_assembly"
  | "no_proof_input_hash"
  | "no_proof_execution"
  | "no_signature"
  | "no_session_key"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "no_world_id_verification"
  | "no_vault_access"
  | "no_durable_candidate_persistence";

export type AuthorizationProofRequirementClassification =
  | "proof_not_required"
  | "proof_required_by_policy"
  | "proof_required_by_capability"
  | "proof_required_by_action"
  | "proof_requirement_unresolved";

export interface AuthorizationDecisionCandidateActionSummary {
  readonly intentId: string;
  readonly actionType: AuthorizationActionType;
  readonly applicationId: ApplicationId;
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly requiredCapability: CapabilityName;
  readonly target?: string;
  readonly method?: string;
  readonly value?: string;
  readonly scope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly consumerDataReference?: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
}

export interface AuthorizationDecisionCandidateConsumerDataSummary {
  readonly consumerDataReference?: string;
  readonly rawConsumerDataIncluded: false;
  readonly adapterPayloadIncluded: false;
}

export interface AuthorizationActionCanonicalInput {
  readonly version: "philcore-authorization-action-preview-v1";
  readonly action: AuthorizationDecisionCandidateActionSummary;
}

export interface AuthorizationActionDigestPreview {
  readonly digestPreview: string;
  readonly digestAlgorithm: "philcore-authorization-action-preview-v1";
  readonly canonicalInput: AuthorizationActionCanonicalInput;
  readonly previewOnly: true;
  readonly actionUnlockAssembled: false;
  readonly proofInputHashCreated: false;
  readonly authorizationPackageCreated: false;
}

export interface AuthorizationDecisionCandidateBinding {
  readonly authoritativeCapabilityGrantId: string;
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly platformUserApprovalDecisionId: string;
  readonly sessionLifecycleId: string;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly intentId: string;
  readonly actionType: AuthorizationActionType;
  readonly requiredCapability: CapabilityName;
  readonly auditCorrelationId: string;
  readonly validityWindowId: string;
}

export interface AuthorizationDecisionCandidateEvidence {
  readonly activeCapabilityGrantAccepted: true;
  readonly activeCapabilityGrantId: string;
  readonly actionDigestPreview: AuthorizationActionDigestPreview;
  readonly rawTrustEvidenceIncluded: false;
  readonly rawPolicyEvidenceIncluded: false;
  readonly rawApprovalArtifactIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly vaultHandleIncluded: false;
  readonly privateMaterialIncluded: false;
  readonly signatureIncluded: false;
  readonly proofDataIncluded: false;
  readonly authorizationPackageIncluded: false;
  readonly adapterPayloadIncluded: false;
}

export interface AuthorizationDecisionCandidateConstraint {
  readonly constraintId: string;
  readonly kind:
    | "capability"
    | "scope"
    | "duration"
    | "target"
    | "method"
    | "value"
    | "network"
    | "consumer_data";
  readonly value?: unknown;
}

export interface AuthorizationDecisionCandidateValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly invalidatedByCapabilityGrantExpiry: true;
  readonly invalidatedByCapabilityGrantRevocation: true;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedBySessionClose: true;
}

export interface AuthorizationDecisionCandidate {
  readonly authorizationDecisionCandidateId: string;
  readonly requestId: string;
  readonly status: "candidate_created";
  readonly outcome: "authorization_candidate_created";
  readonly binding: AuthorizationDecisionCandidateBinding;
  readonly actionSummary: AuthorizationDecisionCandidateActionSummary;
  readonly consumerDataSummary: AuthorizationDecisionCandidateConsumerDataSummary;
  readonly evidence: AuthorizationDecisionCandidateEvidence;
  readonly constraints: readonly AuthorizationDecisionCandidateConstraint[];
  readonly requirements: readonly AuthorizationDecisionCandidateRequirement[];
  readonly limitations: readonly AuthorizationDecisionCandidateLimitation[];
  readonly reasons: readonly AuthorizationDecisionCandidateReason[];
  readonly validity: AuthorizationDecisionCandidateValidity;
  readonly proofRequirement: AuthorizationProofRequirementClassification;
  readonly additionalUserApprovalRequired: false;
  readonly authorizationDecisionCandidateCreated: true;
  readonly activeCapabilityGrantAccepted: true;
  readonly authorizationPackageCreated: false;
  readonly actionAuthorized: false;
  readonly proofInputHashCreated: false;
  readonly proofExecuted: false;
  readonly signatureCreated: false;
  readonly sessionKeyCreated: false;
  readonly adapterExecutionAllowed: false;
  readonly transactionSubmitted: false;
  readonly vaultAccessed: false;
  readonly worldIdVerified: false;
  readonly persisted: false;
  readonly persistedAsAuthority: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: AuthorizationDecisionCandidateCollectionResult;
}

export interface AuthorizationDecisionCandidateRequest<TPayload = unknown> {
  readonly requestId: string;
  readonly activeCapabilityGrant?: AuthoritativeCapabilityGrant;
  readonly intent: Intent<TPayload>;
  readonly actionType: AuthorizationActionType;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly userSessionContext: UserSessionContext;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly target?: string;
  readonly method?: string;
  readonly value?: string;
  readonly scope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly consumerDataReference?: string;
  readonly approvedActionDigestPreview?: string;
  readonly proofRequirement?: AuthorizationProofRequirementClassification;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthorizationDecisionCandidateResult =
  RuntimeResult<AuthorizationDecisionCandidate>;

export interface AuthorizationCandidateConsumptionRecord {
  readonly authorizationCandidateEvidenceChainId: string;
  readonly authorizationDecisionCandidateId?: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly intentId: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly actionType: AuthorizationActionType;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralAuthorizationCandidateConsumptionStore {
  consume(record: AuthorizationCandidateConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: AuthorizationCandidateConsumptionRecord;
    readonly records: readonly AuthorizationCandidateConsumptionRecord[];
    readonly reason?: string;
  };
  has(authorizationCandidateEvidenceChainId: string): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly AuthorizationCandidateConsumptionRecord[];
  };
  getAll(): readonly AuthorizationCandidateConsumptionRecord[];
}

export type AuthorizationDecisionCandidateCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "evicted"
  | "cleared";

export interface AuthorizationDecisionCandidateCollectionResult {
  readonly status: AuthorizationDecisionCandidateCollectionStatus;
  readonly candidate?: AuthorizationDecisionCandidate;
  readonly candidates: readonly AuthorizationDecisionCandidate[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface AuthorizationDecisionCandidateStore {
  addCandidate(candidate: AuthorizationDecisionCandidate):
    AuthorizationDecisionCandidateCollectionResult;
  getById(candidateId: string): AuthorizationDecisionCandidate | undefined;
  listForSession(sessionId: string): readonly AuthorizationDecisionCandidate[];
  listForGrant(grantId: string): readonly AuthorizationDecisionCandidate[];
  getAll(): readonly AuthorizationDecisionCandidate[];
  count(): number;
  clear(): AuthorizationDecisionCandidateCollectionResult;
}

export interface InMemoryAuthorizationDecisionCandidateStoreOptions {
  readonly maxCandidateCount?: number;
}

export interface AuthorizationDecisionCandidateConsumer {
  acceptCandidateForPackageConstruction(input: AuthorizationPackageConstructionInput):
    AuthorizationPackageConstructionPreviewResult;
}

export interface AuthorizationPackageConstructionInput {
  readonly candidate: AuthorizationDecisionCandidate;
  readonly activeCapabilityGrant: AuthoritativeCapabilityGrant;
  readonly requestedAt: string;
}

export interface ActionUnlockConstructionInputPreview {
  readonly candidateId: string;
  readonly actionDigestPreview: string;
  readonly actionUnlockNotAssembled: true;
  readonly proofInputHashNotCreated: true;
}

export interface ProofRequirementResolutionInput {
  readonly candidate: AuthorizationDecisionCandidate;
  readonly proofRequirement: AuthorizationProofRequirementClassification;
  readonly proofNotExecuted: true;
}

export interface AuthorizationPackageConstructionPreviewResult {
  readonly status: "accepted_for_future_package_construction" | "rejected";
  readonly candidateId?: string;
  readonly actionUnlockPreview?: ActionUnlockConstructionInputPreview;
  readonly proofRequirementResolution?: ProofRequirementResolutionInput;
  readonly authorizationPackageCreated: false;
  readonly actionUnlockAssembled: false;
  readonly proofInputHashCreated: false;
  readonly proofExecuted: false;
  readonly adapterExecutionAllowed: false;
  readonly errors: readonly string[];
}

const CANDIDATE_STATUSES = new Set<AuthorizationDecisionCandidateStatus>([
  "candidate_created",
  "candidate_rejected",
  "candidate_malformed",
  "candidate_replayed",
  "candidate_expired",
  "candidate_unsupported"
]);

const CANDIDATE_OUTCOMES = new Set<AuthorizationDecisionCandidateOutcome>([
  "authorization_candidate_created",
  "capability_grant_ineligible",
  "capability_missing",
  "capability_expired",
  "capability_revoked",
  "action_not_permitted",
  "scope_exceeded",
  "target_not_permitted",
  "value_limit_exceeded",
  "method_not_permitted",
  "duration_ineligible",
  "session_state_ineligible",
  "application_mismatch",
  "owner_mismatch",
  "correlation_mismatch",
  "additional_user_approval_required",
  "proof_required",
  "unsupported_action",
  "evidence_replayed",
  "expired",
  "malformed",
  "unsupported"
]);

const ELIGIBLE_LIFECYCLE_STATES = new Set<UserSessionLifecycleState>([
  "unlocked",
  "recovery_mode"
]);

const ACTION_CAPABILITY_MAP = Object.freeze({
  message_signature: "request_message_signature",
  transaction_preparation: "request_transaction_preparation",
  transaction_submission: "request_transaction_submission",
  contract_call: "request_contract_call",
  smart_account_deployment: "request_smart_account_deployment",
  session_key_management: "request_session_key_management",
  credential_rotation: "request_credential_rotation",
  credential_revocation: "request_credential_revocation",
  encrypted_backup_export: "request_encrypted_backup_export",
  recovery_start: "start_recovery",
  recovery_approval: "approve_recovery",
  audit_review: "view_audit_events"
} satisfies Record<AuthorizationActionType, CapabilityName>);

const PROOF_REQUIRED_ACTIONS = new Set<AuthorizationActionType>([
  "transaction_submission",
  "contract_call",
  "smart_account_deployment"
]);

const LIMITATIONS: readonly AuthorizationDecisionCandidateLimitation[] = Object.freeze([
  "authorization_candidate_only",
  "process_local_replay_protection_only",
  "process_local_store_only",
  "no_action_authorization",
  "no_authorization_package",
  "no_action_unlock_assembly",
  "no_proof_input_hash",
  "no_proof_execution",
  "no_signature",
  "no_session_key",
  "no_adapter_execution",
  "no_transaction_submission",
  "no_world_id_verification",
  "no_vault_access",
  "no_durable_candidate_persistence"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function expired(value: string | undefined, now = Date.now()): boolean {
  return value !== undefined && Date.parse(value) <= now;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (isRecord(value)) {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)]))
    ) as TValue;
  }
  return value;
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors: Object.freeze([...new Set(errors)]) };
}

function arraysEqual(left: readonly string[] = [], right: readonly string[] = []): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function normalizeUnknown(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
    return String(value);
  }
  return stableJson(value);
}

function payloadTarget(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined;
  return normalizeUnknown(payload.target)
    ?? normalizeUnknown(payload.credentialId)
    ?? normalizeUnknown(payload.recoverySessionId)
    ?? normalizeUnknown(payload.destinationHint);
}

function payloadMethod(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined;
  return normalizeUnknown(payload.method)
    ?? normalizeUnknown(payload.operation)
    ?? normalizeUnknown(payload.action)
    ?? (payload.callData ? "calldata" : undefined);
}

function payloadValue(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined;
  return normalizeUnknown(payload.value)
    ?? normalizeUnknown(payload.requestedValue)
    ?? normalizeUnknown(payload.amount);
}

function payloadChainId(payload: unknown): string | number | undefined {
  if (!isRecord(payload)) return undefined;
  const value = payload.chainId;
  if (typeof value === "number" || typeof value === "string") return value;
  if (typeof value === "bigint") return value.toString();
  return undefined;
}

function payloadConsumerDataReference(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined;
  return normalizeUnknown(payload.consumerDataReference)
    ?? normalizeUnknown(payload.messageHash)
    ?? normalizeUnknown(payload.callData)
    ?? normalizeUnknown(payload.encryptionProfile)
    ?? normalizeUnknown(payload.reason);
}

function actionSummaryFromRequest(
  request: AuthorizationDecisionCandidateRequest
): AuthorizationDecisionCandidateActionSummary {
  const payload = request.intent.payload;
  return freezeRecord({
    intentId: request.intent.intentId,
    actionType: request.actionType,
    applicationId: request.applicationId,
    sessionId: request.sessionId,
    ownerCommitment: request.ownerCommitment,
    requiredCapability: mapActionTypeToRequiredCapability(request.actionType),
    target: request.target ?? payloadTarget(payload),
    method: request.method ?? payloadMethod(payload),
    value: request.value ?? payloadValue(payload),
    scope: request.scope,
    requestedDurationSeconds: request.requestedDurationSeconds,
    chainId: request.chainId ?? payloadChainId(payload),
    network: request.network,
    consumerDataReference: request.consumerDataReference ?? payloadConsumerDataReference(payload),
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId
  });
}

function candidateError(
  code: string,
  outcome: AuthorizationDecisionCandidateOutcome,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_authorization_package",
    code,
    message: "authorization decision candidate request was rejected",
    boundary: "authorization-engine",
    recoverable: true,
    details: { outcome, errors }
  };
}

function requirements(): readonly AuthorizationDecisionCandidateRequirement[] {
  return Object.freeze([
    "active_authoritative_capability_grant",
    "exact_action_intent",
    "current_user_session_context",
    "eligible_lifecycle_state",
    "capability_mapping_match",
    "scope_within_capability_grant",
    "target_within_capability_grant",
    "method_within_capability_grant",
    "value_within_capability_grant",
    "network_within_capability_grant",
    "bounded_validity_window"
  ]);
}

function proofClassification(
  request: AuthorizationDecisionCandidateRequest,
  grant: AuthoritativeCapabilityGrant
): AuthorizationProofRequirementClassification {
  if (request.proofRequirement) return request.proofRequirement;
  if (PROOF_REQUIRED_ACTIONS.has(request.actionType)) return "proof_required_by_action";
  if (grant.usagePolicy.proofMayBeRequiredLater) return "proof_required_by_capability";
  return "proof_not_required";
}

function constraintsForSummary(
  summary: AuthorizationDecisionCandidateActionSummary
): readonly AuthorizationDecisionCandidateConstraint[] {
  const constraints: AuthorizationDecisionCandidateConstraint[] = [{
    constraintId: `capability:${summary.requiredCapability}`,
    kind: "capability",
    value: summary.requiredCapability
  }];
  if (summary.scope !== undefined) {
    constraints.push({ constraintId: "scope", kind: "scope", value: summary.scope });
  }
  if (summary.requestedDurationSeconds !== undefined) {
    constraints.push({
      constraintId: "duration",
      kind: "duration",
      value: summary.requestedDurationSeconds
    });
  }
  if (summary.target !== undefined) {
    constraints.push({ constraintId: `target:${summary.target}`, kind: "target", value: summary.target });
  }
  if (summary.method !== undefined) {
    constraints.push({ constraintId: `method:${summary.method}`, kind: "method", value: summary.method });
  }
  if (summary.value !== undefined) {
    constraints.push({ constraintId: "value", kind: "value", value: summary.value });
  }
  if (summary.network !== undefined || summary.chainId !== undefined) {
    constraints.push({
      constraintId: "network",
      kind: "network",
      value: { chainId: summary.chainId, network: summary.network }
    });
  }
  if (summary.consumerDataReference !== undefined) {
    constraints.push({
      constraintId: "consumer-data",
      kind: "consumer_data",
      value: summary.consumerDataReference
    });
  }
  return Object.freeze(constraints.map(freezeRecord));
}

function auditDraftForCandidate(input: {
  readonly request: AuthorizationDecisionCandidateRequest;
  readonly outcome: AuthorizationDecisionCandidateOutcome;
  readonly summary?: AuthorizationDecisionCandidateActionSummary;
  readonly candidate?: AuthorizationDecisionCandidate;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.candidate ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    intentId: input.request.intent?.intentId,
    capability: input.summary?.requiredCapability,
    summary: input.candidate
      ? "Authorization Decision Candidate created; no Authorization Package, proof, signature, adapter call, or execution occurred."
      : "Authorization Decision Candidate request rejected; no Authorization Package, proof, signature, adapter call, or execution occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationDecisionCandidateId: input.candidate?.authorizationDecisionCandidateId,
      authoritativeCapabilityGrantId:
        input.request.activeCapabilityGrant?.authoritativeCapabilityGrantId,
      sessionId: input.request.sessionId,
      applicationId: input.request.applicationId,
      ownerCommitment: input.request.ownerCommitment,
      intentId: input.request.intent?.intentId,
      actionType: input.request.actionType,
      requiredCapability: input.summary?.requiredCapability,
      target: input.summary?.target,
      method: input.summary?.method,
      value: input.summary?.value,
      scope: input.summary?.scope,
      chainId: input.summary?.chainId,
      network: input.summary?.network,
      consumerDataReference: input.summary?.consumerDataReference,
      actionDigestPreview: input.candidate?.evidence.actionDigestPreview.digestPreview,
      proofRequirement: input.candidate?.proofRequirement,
      outcome: input.outcome,
      authorizationPackageCreated: false,
      actionAuthorized: false,
      proofInputHashCreated: false,
      proofExecuted: false,
      signatureCreated: false,
      sessionKeyCreated: false,
      adapterExecutionAllowed: false,
      transactionSubmitted: false,
      vaultAccessed: false,
      worldIdVerified: false,
      persistedAsAuthority: false,
      errors: input.errors ?? []
    }
  });
}

function outcomeForErrors(errors: readonly string[]): AuthorizationDecisionCandidateOutcome {
  if (errors.some((error) => error.includes("replay") || error.includes("consumed"))) {
    return "evidence_replayed";
  }
  if (errors.some((error) => error.includes("missing capability"))) return "capability_missing";
  if (errors.some((error) => error.includes("revoked"))) return "capability_revoked";
  if (errors.some((error) => error.includes("grant expired"))) return "capability_expired";
  if (errors.some((error) => error.includes("additional user approval"))) {
    return "additional_user_approval_required";
  }
  if (errors.some((error) => error.includes("target"))) return "target_not_permitted";
  if (errors.some((error) => error.includes("method"))) return "method_not_permitted";
  if (errors.some((error) => error.includes("value"))) return "value_limit_exceeded";
  if (errors.some((error) => error.includes("scope"))) return "scope_exceeded";
  if (errors.some((error) => error.includes("duration"))) return "duration_ineligible";
  if (errors.some((error) => error.includes("network") || error.includes("chain"))) return "correlation_mismatch";
  if (errors.some((error) => error.includes("session state") || error.includes("context"))) {
    return "session_state_ineligible";
  }
  if (errors.some((error) => error.includes("application"))) return "application_mismatch";
  if (errors.some((error) => error.includes("owner"))) return "owner_mismatch";
  if (errors.some((error) => error.includes("capability") || error.includes("action"))) {
    return "action_not_permitted";
  }
  if (errors.some((error) => error.includes("expired"))) return "expired";
  if (errors.some((error) => error.includes("unsupported"))) return "unsupported_action";
  if (errors.some((error) => error.includes("mismatch"))) return "correlation_mismatch";
  return "malformed";
}

function actionEligibilityErrors(
  request: AuthorizationDecisionCandidateRequest,
  summary: AuthorizationDecisionCandidateActionSummary
): readonly string[] {
  const errors: string[] = [];
  const grant = request.activeCapabilityGrant;
  if (!grant) {
    errors.push("missing capability grant");
    return Object.freeze(errors);
  }
  const grantShape = validateAuthoritativeCapabilityGrantShape(grant);
  errors.push(...grantShape.errors.map((error) => `grant.${error}`));
  if (grant.status !== "active") errors.push("capability grant is not active");
  if (grant.revocation.revoked) errors.push("capability grant is revoked");
  if (expired(grant.validity.expiresAt)) errors.push("capability grant expired");
  if (expired(request.expiresAt)) errors.push("authorization candidate request expired");
  if (!ELIGIBLE_LIFECYCLE_STATES.has(request.lifecycleSnapshot.state)) {
    errors.push("session state ineligible");
  }
  if (request.userSessionContext.status !== "unlocked" && request.userSessionContext.status !== "recovery") {
    errors.push("session context ineligible");
  }
  if (request.lifecycleSnapshot.sessionId !== request.sessionId) errors.push("lifecycle session mismatch");
  if (request.userSessionContext.sessionId !== request.sessionId) errors.push("context session mismatch");
  if (request.userSessionContext.ownerCommitment !== request.ownerCommitment) {
    errors.push("context owner mismatch");
  }
  if (grant.binding.sessionId !== request.sessionId) errors.push("grant session mismatch");
  if (grant.binding.applicationId !== request.applicationId) errors.push("grant application mismatch");
  if (grant.binding.ownerCommitment !== request.ownerCommitment) errors.push("grant owner mismatch");
  if (grant.binding.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("grant audit correlation mismatch");
  }
  if (request.intent.applicationId !== request.applicationId) errors.push("intent application mismatch");
  if (!request.intent.requestedCapabilities.includes(summary.requiredCapability)) {
    errors.push("intent missing capability");
  }
  if (grant.scope.capabilityName !== summary.requiredCapability) {
    errors.push("action capability mismatch");
  }
  if (!grant.scope.actionTypes.includes(summary.actionType)
    && !grant.scope.actionTypes.includes(summary.method ?? "")
    && !grant.scope.actionTypes.includes("send_eth")) {
    errors.push("action type not permitted by grant");
  }
  if (summary.scope !== undefined
    && stableJson(summary.scope) !== stableJson(grant.scope.effectiveScope)) {
    errors.push("scope exceeded");
  }
  if (summary.requestedDurationSeconds !== undefined
    && grant.scope.effectiveDurationSeconds !== undefined
    && summary.requestedDurationSeconds > grant.scope.effectiveDurationSeconds) {
    errors.push("duration exceeds grant");
  }
  if (summary.target !== undefined
    && grant.scope.allowedTargets.length > 0
    && !grant.scope.allowedTargets.includes(summary.target)) {
    errors.push("target not permitted");
  }
  if (summary.method !== undefined
    && grant.scope.actionTypes.length > 0
    && !grant.scope.actionTypes.includes(summary.method)
    && !grant.scope.actionTypes.includes(summary.actionType)
    && !(summary.method === "send_eth" && grant.scope.actionTypes.includes("send_eth"))) {
    errors.push("method not permitted");
  }
  if (summary.value !== undefined
    && grant.scope.valueLimit !== undefined
    && summary.value !== grant.scope.valueLimit) {
    errors.push("value limit exceeded");
  }
  if (summary.chainId !== undefined
    && grant.scope.chainId !== undefined
    && String(summary.chainId) !== String(grant.scope.chainId)) {
    errors.push("chain context mismatch");
  }
  if (summary.network !== undefined
    && grant.scope.network !== undefined
    && summary.network !== grant.scope.network) {
    errors.push("network context mismatch");
  }
  const preview = createAuthorizationActionDigestPreview(summary);
  if (request.approvedActionDigestPreview !== undefined
    && request.approvedActionDigestPreview !== preview.digestPreview) {
    errors.push("additional user approval required for material action mutation");
  }
  if (Date.parse(request.expiresAt) > Date.parse(grant.validity.expiresAt)) {
    errors.push("expiry extends beyond capability grant");
  }
  return Object.freeze([...new Set(errors)]);
}

export function isAuthorizationDecisionCandidateStatus(
  value: unknown
): value is AuthorizationDecisionCandidateStatus {
  return CANDIDATE_STATUSES.has(value as AuthorizationDecisionCandidateStatus);
}

export function isAuthorizationDecisionCandidateOutcome(
  value: unknown
): value is AuthorizationDecisionCandidateOutcome {
  return CANDIDATE_OUTCOMES.has(value as AuthorizationDecisionCandidateOutcome);
}

export function mapActionTypeToRequiredCapability(
  actionType: AuthorizationActionType
): CapabilityName {
  return ACTION_CAPABILITY_MAP[actionType];
}

export function validateAuthorizationDecisionCandidateRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["authorization decision candidate request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.intent)) {
    errors.push("intent is required");
  } else {
    if (!isNonEmptyString(request.intent.intentId)) errors.push("intent.intentId is required");
    if (!isNonEmptyString(request.intent.applicationId)) errors.push("intent.applicationId is required");
    if (!Array.isArray(request.intent.requestedCapabilities)) {
      errors.push("intent.requestedCapabilities must be an array");
    }
  }
  if (!Object.prototype.hasOwnProperty.call(ACTION_CAPABILITY_MAP, request.actionType as string)) {
    errors.push("actionType is unsupported");
  }
  errors.push(...validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot).errors.map(
    (error) => `lifecycleSnapshot.${error}`
  ));
  for (const field of [
    "ownerCommitment",
    "sessionId",
    "applicationId",
    "issuedAt",
    "expiresAt",
    "auditCorrelationId"
  ] as const) {
    if (!isNonEmptyString(request[field])) errors.push(`${field} is required`);
  }
  if (!isRecord(request.userSessionContext)) errors.push("userSessionContext is required");
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (request.requestedDurationSeconds !== undefined
    && typeof request.requestedDurationSeconds !== "number") {
    errors.push("requestedDurationSeconds must be a number");
  }
  errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

export function validateAuthorizationDecisionCandidateShape(
  candidate: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(candidate)) return validation(["authorization decision candidate must be an object"]);
  if (!isNonEmptyString(candidate.authorizationDecisionCandidateId)) {
    errors.push("authorizationDecisionCandidateId is required");
  }
  if (candidate.status !== "candidate_created") errors.push("status must be candidate_created");
  if (candidate.outcome !== "authorization_candidate_created") {
    errors.push("outcome must be authorization_candidate_created");
  }
  if (!isRecord(candidate.binding)) errors.push("binding is required");
  if (!isRecord(candidate.actionSummary)) errors.push("actionSummary is required");
  if (!isRecord(candidate.evidence)) errors.push("evidence is required");
  if (!Array.isArray(candidate.constraints)) errors.push("constraints must be an array");
  if (!Array.isArray(candidate.requirements)) errors.push("requirements must be an array");
  if (!Array.isArray(candidate.limitations)) errors.push("limitations must be an array");
  if (candidate.authorizationDecisionCandidateCreated !== true) {
    errors.push("authorizationDecisionCandidateCreated must be true");
  }
  if (candidate.activeCapabilityGrantAccepted !== true) {
    errors.push("activeCapabilityGrantAccepted must be true");
  }
  for (const field of [
    "authorizationPackageCreated",
    "actionAuthorized",
    "proofInputHashCreated",
    "proofExecuted",
    "signatureCreated",
    "sessionKeyCreated",
    "adapterExecutionAllowed",
    "transactionSubmitted",
    "vaultAccessed",
    "worldIdVerified",
    "persisted",
    "persistedAsAuthority"
  ]) {
    if (candidate[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function createAuthorizationActionDigestPreview(
  summary: AuthorizationDecisionCandidateActionSummary
): AuthorizationActionDigestPreview {
  const canonicalInput = freezeRecord({
    version: "philcore-authorization-action-preview-v1" as const,
    action: summary
  });
  return freezeRecord({
    digestPreview: createAuditCorrelationId([
      "philcore-authorization-action-preview-v1",
      summary.intentId,
      summary.actionType,
      summary.applicationId,
      summary.sessionId,
      summary.ownerCommitment,
      summary.requiredCapability,
      summary.target ?? "",
      summary.method ?? "",
      summary.value ?? "",
      stableJson(summary.scope),
      String(summary.requestedDurationSeconds ?? ""),
      String(summary.chainId ?? ""),
      summary.network ?? "",
      summary.consumerDataReference ?? "",
      summary.issuedAt,
      summary.expiresAt,
      summary.auditCorrelationId
    ]),
    digestAlgorithm: "philcore-authorization-action-preview-v1" as const,
    canonicalInput,
    previewOnly: true as const,
    actionUnlockAssembled: false as const,
    proofInputHashCreated: false as const,
    authorizationPackageCreated: false as const
  });
}

export function evaluateAuthorizationDecisionCandidate(
  request: AuthorizationDecisionCandidateRequest,
  consumptionStore?: EphemeralAuthorizationCandidateConsumptionStore,
  candidateStore?: AuthorizationDecisionCandidateStore,
  auditDraftCollector?: AuditDraftCollector
): AuthorizationDecisionCandidateResult {
  const shape = validateAuthorizationDecisionCandidateRequest(request);
  const summary = isRecord(request) && isRecord(request.intent)
    ? actionSummaryFromRequest(request)
    : undefined;
  if (!shape.valid || !summary) {
    const outcome = "malformed";
    const auditEventDraft = auditDraftForCandidate({ request, outcome, summary, errors: shape.errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      "AUTHORIZATION_DECISION_CANDIDATE_MALFORMED",
      outcome,
      shape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const errors = actionEligibilityErrors(request, summary);
  if (errors.length > 0) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForCandidate({ request, outcome, summary, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      outcome === "evidence_replayed"
        ? "AUTHORIZATION_DECISION_CANDIDATE_REPLAYED"
        : "AUTHORIZATION_DECISION_CANDIDATE_REJECTED",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const grant = request.activeCapabilityGrant as AuthoritativeCapabilityGrant;
  const actionDigestPreview = createAuthorizationActionDigestPreview(summary);
  const authorizationCandidateEvidenceChainId = createAuditCorrelationId([
    grant.authoritativeCapabilityGrantId,
    summary.intentId,
    summary.actionType,
    actionDigestPreview.digestPreview,
    summary.auditCorrelationId,
    "authorization-decision-candidate-evidence-chain"
  ]);
  if (consumptionStore?.has(authorizationCandidateEvidenceChainId)) {
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForCandidate({
      request,
      outcome,
      summary,
      errors: ["authorization candidate evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      "AUTHORIZATION_DECISION_CANDIDATE_REPLAYED",
      outcome,
      ["authorization candidate evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const proofRequirement = proofClassification(request, grant);
  const candidateId = createAuditCorrelationId([
    authorizationCandidateEvidenceChainId,
    request.issuedAt,
    request.expiresAt,
    "authorization-decision-candidate"
  ]);
  const candidateBase = {
    authorizationDecisionCandidateId: candidateId,
    requestId: request.requestId,
    status: "candidate_created" as const,
    outcome: "authorization_candidate_created" as const,
    binding: {
      authoritativeCapabilityGrantId: grant.authoritativeCapabilityGrantId,
      authoritativeTrustDecisionId: grant.binding.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId: grant.binding.authoritativePolicyDecisionId,
      platformUserApprovalDecisionId: grant.binding.platformUserApprovalDecisionId,
      sessionLifecycleId: request.lifecycleSnapshot.lifecycleId,
      sessionLifecycleState: request.lifecycleSnapshot.state,
      ownerCommitment: request.ownerCommitment,
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      intentId: summary.intentId,
      actionType: summary.actionType,
      requiredCapability: summary.requiredCapability,
      auditCorrelationId: request.auditCorrelationId,
      validityWindowId: createAuditCorrelationId([
        request.sessionId,
        summary.intentId,
        request.issuedAt,
        request.expiresAt,
        "authorization-candidate-validity-window"
      ])
    },
    actionSummary: summary,
    consumerDataSummary: {
      consumerDataReference: summary.consumerDataReference,
      rawConsumerDataIncluded: false as const,
      adapterPayloadIncluded: false as const
    },
    evidence: {
      activeCapabilityGrantAccepted: true as const,
      activeCapabilityGrantId: grant.authoritativeCapabilityGrantId,
      actionDigestPreview,
      rawTrustEvidenceIncluded: false as const,
      rawPolicyEvidenceIncluded: false as const,
      rawApprovalArtifactIncluded: false as const,
      credentialRecordIncluded: false as const,
      vaultHandleIncluded: false as const,
      privateMaterialIncluded: false as const,
      signatureIncluded: false as const,
      proofDataIncluded: false as const,
      authorizationPackageIncluded: false as const,
      adapterPayloadIncluded: false as const
    },
    constraints: constraintsForSummary(summary),
    requirements: requirements(),
    limitations: LIMITATIONS,
    reasons: Object.freeze([
      "active-capability-grant-accepted",
      "exact-action-intent-accepted",
      "action-capability-mapping-matched",
      "scope-within-grant",
      "target-within-grant",
      "method-within-grant",
      "value-within-grant",
      "network-within-grant",
      "duration-within-grant",
      "authorization-engine-candidate-only",
      "no-action-authorization",
      "no-authorization-package",
      "no-proof-input-hash",
      "no-execution"
    ]),
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false,
      invalidatedByCapabilityGrantExpiry: true as const,
      invalidatedByCapabilityGrantRevocation: true as const,
      invalidatedBySessionLock: true as const,
      invalidatedBySessionClose: true as const
    },
    proofRequirement,
    additionalUserApprovalRequired: false as const,
    authorizationDecisionCandidateCreated: true as const,
    activeCapabilityGrantAccepted: true as const,
    authorizationPackageCreated: false as const,
    actionAuthorized: false as const,
    proofInputHashCreated: false as const,
    proofExecuted: false as const,
    signatureCreated: false as const,
    sessionKeyCreated: false as const,
    adapterExecutionAllowed: false as const,
    transactionSubmitted: false as const,
    vaultAccessed: false as const,
    worldIdVerified: false as const,
    persisted: false as const,
    persistedAsAuthority: false as const
  };
  const candidate = freezeRecord(candidateBase) as AuthorizationDecisionCandidate;
  const candidateShape = validateAuthorizationDecisionCandidateShape(candidate);
  if (!candidateShape.valid) {
    const outcome = "malformed";
    const auditEventDraft = auditDraftForCandidate({
      request,
      outcome,
      summary,
      errors: candidateShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      "AUTHORIZATION_DECISION_CANDIDATE_SHAPE_INVALID",
      outcome,
      candidateShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const consumed = consumptionStore?.consume({
    authorizationCandidateEvidenceChainId,
    authorizationDecisionCandidateId: candidateId,
    authoritativeCapabilityGrantId: grant.authoritativeCapabilityGrantId,
    intentId: summary.intentId,
    sessionId: request.sessionId,
    applicationId: request.applicationId,
    actionType: summary.actionType,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForCandidate({
      request,
      outcome,
      summary,
      errors: ["authorization candidate evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      "AUTHORIZATION_DECISION_CANDIDATE_REPLAYED",
      outcome,
      ["authorization candidate evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const auditEventDraft = auditDraftForCandidate({
    request,
    outcome: proofRequirement === "proof_not_required"
      ? "authorization_candidate_created"
      : "proof_required",
    summary,
    candidate
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = candidateStore?.addCandidate(candidate);
  return runtimeOk(freezeRecord({
    ...candidateBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as AuthorizationDecisionCandidate);
}

export function createAuthorizationDecisionCandidate(
  request: AuthorizationDecisionCandidateRequest,
  consumptionStore?: EphemeralAuthorizationCandidateConsumptionStore,
  candidateStore?: AuthorizationDecisionCandidateStore,
  auditDraftCollector?: AuditDraftCollector
): AuthorizationDecisionCandidateResult {
  return evaluateAuthorizationDecisionCandidate(
    request,
    consumptionStore,
    candidateStore,
    auditDraftCollector
  );
}

export function createEphemeralAuthorizationCandidateConsumptionStore():
  EphemeralAuthorizationCandidateConsumptionStore {
  const records = new Map<string, AuthorizationCandidateConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.authorizationCandidateEvidenceChainId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.authorizationCandidateEvidenceChainId),
          records: all(),
          reason: "authorization candidate evidence chain was already consumed"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.authorizationCandidateEvidenceChainId, frozen);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(authorizationCandidateEvidenceChainId) {
      return records.has(authorizationCandidateEvidenceChainId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

export function createInMemoryAuthorizationDecisionCandidateStore(
  options: InMemoryAuthorizationDecisionCandidateStoreOptions = {}
): AuthorizationDecisionCandidateStore {
  const maxCandidateCount = Math.max(1, Math.floor(options.maxCandidateCount ?? 100));
  const candidates = new Map<string, AuthorizationDecisionCandidate>();
  function all() {
    return Object.freeze(Array.from(candidates.values()).map(freezeRecord));
  }
  function collectionResult(input: {
    readonly status: AuthorizationDecisionCandidateCollectionStatus;
    readonly candidate?: AuthorizationDecisionCandidate;
    readonly reason?: string;
  }): AuthorizationDecisionCandidateCollectionResult {
    return freezeRecord({
      status: input.status,
      candidate: input.candidate,
      candidates: all(),
      count: candidates.size,
      persisted: false as const,
      reason: input.reason
    });
  }
  return {
    addCandidate(candidate) {
      if (candidates.has(candidate.authorizationDecisionCandidateId)) {
        return collectionResult({
          status: "duplicate_rejected",
          candidate,
          reason: "authorization decision candidate ID already exists"
        });
      }
      if (candidates.size >= maxCandidateCount) {
        const oldest = candidates.keys().next().value as string | undefined;
        if (oldest) candidates.delete(oldest);
      }
      const frozen = freezeRecord(candidate);
      candidates.set(candidate.authorizationDecisionCandidateId, frozen);
      return collectionResult({ status: "collected", candidate: frozen });
    },
    getById(candidateId) {
      return candidates.get(candidateId);
    },
    listForSession(sessionId) {
      return Object.freeze(all().filter(
        (candidate) => candidate.binding.sessionId === sessionId
      ));
    },
    listForGrant(grantId) {
      return Object.freeze(all().filter(
        (candidate) => candidate.binding.authoritativeCapabilityGrantId === grantId
      ));
    },
    getAll: all,
    count() {
      return candidates.size;
    },
    clear() {
      candidates.clear();
      return collectionResult({ status: "cleared" });
    }
  };
}

export function createFixtureAuthorizationDecisionCandidateConsumer():
  AuthorizationDecisionCandidateConsumer {
  return {
    acceptCandidateForPackageConstruction(input) {
      const errors: string[] = [];
      const candidateShape = validateAuthorizationDecisionCandidateShape(input.candidate);
      errors.push(...candidateShape.errors);
      if (input.candidate.binding.authoritativeCapabilityGrantId
        !== input.activeCapabilityGrant.authoritativeCapabilityGrantId) {
        errors.push("candidate and active capability grant mismatch");
      }
      if (input.candidate.authorizationPackageCreated !== false
        || input.candidate.actionAuthorized !== false) {
        errors.push("candidate already implies authorization");
      }
      if (errors.length > 0) {
        return freezeRecord({
          status: "rejected" as const,
          errors,
          authorizationPackageCreated: false as const,
          actionUnlockAssembled: false as const,
          proofInputHashCreated: false as const,
          proofExecuted: false as const,
          adapterExecutionAllowed: false as const
        });
      }
      return freezeRecord({
        status: "accepted_for_future_package_construction" as const,
        candidateId: input.candidate.authorizationDecisionCandidateId,
        actionUnlockPreview: {
          candidateId: input.candidate.authorizationDecisionCandidateId,
          actionDigestPreview: input.candidate.evidence.actionDigestPreview.digestPreview,
          actionUnlockNotAssembled: true as const,
          proofInputHashNotCreated: true as const
        },
        proofRequirementResolution: {
          candidate: input.candidate,
          proofRequirement: input.candidate.proofRequirement,
          proofNotExecuted: true as const
        },
        errors: [],
        authorizationPackageCreated: false as const,
        actionUnlockAssembled: false as const,
        proofInputHashCreated: false as const,
        proofExecuted: false as const,
        adapterExecutionAllowed: false as const
      });
    }
  };
}
