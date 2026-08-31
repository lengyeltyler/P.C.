import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { AuthoritativePolicyDecision } from "./authoritativePolicyDecision.ts";
import { validateAuthoritativePolicyDecisionShape } from "./authoritativePolicyDecision.ts";
import type { AuthoritativeTrustDecision } from "./authoritativeTrustDecision.ts";
import { validateAuthoritativeTrustDecisionShape } from "./authoritativeTrustDecision.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { PlatformUserApprovalDecision } from "./platformUserApprovalDecision.ts";
import { validatePlatformUserApprovalDecisionShape } from "./platformUserApprovalDecision.ts";
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
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext
} from "./types.ts";

export type AuthoritativeCapabilityGrantStatus =
  | "active"
  | "revoked"
  | "expired";

export type AuthoritativeCapabilityActivationOutcome =
  | "capability_granted"
  | "trust_decision_ineligible"
  | "policy_decision_ineligible"
  | "approval_decision_ineligible"
  | "approval_not_granted"
  | "scope_mismatch"
  | "duration_mismatch"
  | "target_restriction_mismatch"
  | "value_restriction_mismatch"
  | "session_state_ineligible"
  | "application_mismatch"
  | "correlation_mismatch"
  | "evidence_expired"
  | "evidence_replayed"
  | "world_id_requirement_unresolved"
  | "malformed"
  | "unsupported";

export type AuthoritativeCapabilityActivationReason =
  | "authoritative-trust-decision-valid"
  | "authoritative-policy-decision-valid"
  | "platform-user-approval-decision-approved"
  | "least-privilege-scope-preserved"
  | "policy-restrictions-preserved"
  | "session-context-eligible"
  | "active-capability-created"
  | "capability-authority-only"
  | "no-action-authorization"
  | "no-authorization-package"
  | "no-execution"
  | (string & {});

export type AuthoritativeCapabilityGrantRequirement =
  | "authoritative_trust_decision"
  | "authoritative_policy_decision"
  | "approved_platform_user_approval_decision"
  | "exact_capability_activation_request"
  | "current_user_session_context"
  | "eligible_lifecycle_state"
  | "scope_within_policy"
  | "duration_within_policy"
  | "restrictions_preserved"
  | "bounded_validity_window";

export type AuthoritativeCapabilityGrantLimitation =
  | "capability_authority_only"
  | "process_local_authority_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "session_bound"
  | "application_bound"
  | "owner_bound"
  | "capability_bound"
  | "scope_bound"
  | "no_action_authorization"
  | "no_authorization_package"
  | "no_session_key"
  | "no_execution"
  | "no_proof_execution"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "no_world_id_verification"
  | "no_vault_access"
  | "no_durable_capability_persistence";

export type AuthoritativeCapabilityGrantRevocationReason =
  | "user_revoked"
  | "session_locked"
  | "session_closed"
  | "grant_expired"
  | "application_uninstalled"
  | "policy_invalidated"
  | "trust_decision_invalidated"
  | "approval_invalidated"
  | "security_event"
  | "recovery_mode_entered";

export interface AuthoritativeCapabilityGrantScope {
  readonly capabilityName: CapabilityName;
  readonly effectiveScope?: CapabilityScope;
  readonly effectiveDurationSeconds?: number;
  readonly allowedTargets: readonly string[];
  readonly valueLimit?: string;
  readonly actionTypes: readonly string[];
  readonly chainId?: string | number;
  readonly network?: string;
}

export interface AuthoritativeCapabilityGrantConstraint {
  readonly constraintId: string;
  readonly kind:
    | "scope"
    | "duration"
    | "target"
    | "value"
    | "action_type"
    | "network"
    | "usage_count"
    | "recovery_context"
    | "experimental_feature";
  readonly value?: unknown;
}

export interface AuthoritativeCapabilityGrantBinding {
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly platformUserApprovalDecisionId: string;
  readonly sessionLifecycleId: string;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly auditCorrelationId: string;
  readonly validityWindowId: string;
  readonly reusableAcrossOwners: false;
  readonly reusableAcrossSessions: false;
  readonly reusableAcrossApplications: false;
  readonly reusableAcrossCapabilities: false;
  readonly reusableAcrossScopes: false;
  readonly reusableAcrossTimeWindows: false;
}

export interface AuthoritativeCapabilityGrantUsagePolicy {
  readonly mayRequestFutureActions: true;
  readonly actionAuthorizationStillRequired: true;
  readonly authorizationEngineRequired: true;
  readonly proofMayBeRequiredLater: boolean;
  readonly adapterExecutionAllowed: false;
  readonly unrestrictedWalletAuthority: false;
  readonly usageCountLimit?: number;
  readonly usageCountConsumed: number;
}

export interface AuthoritativeCapabilityGrantValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedBySessionClose: true;
  readonly invalidatedByExplicitRevocation: true;
  readonly invalidatedByTrustDecisionExpiry: true;
  readonly invalidatedByPolicyDecisionExpiry: true;
  readonly invalidatedByApprovalDecisionExpiry: true;
}

export interface AuthoritativeCapabilityGrantRevocation {
  readonly revoked: boolean;
  readonly revokedAt?: string;
  readonly reason?: AuthoritativeCapabilityGrantRevocationReason;
  readonly durableRevocationImplemented: false;
  readonly processLocalOnly: true;
}

export interface AuthoritativeCapabilityGrant {
  readonly authoritativeCapabilityGrantId: string;
  readonly requestId: string;
  readonly status: AuthoritativeCapabilityGrantStatus;
  readonly outcome: "capability_granted";
  readonly scope: AuthoritativeCapabilityGrantScope;
  readonly binding: AuthoritativeCapabilityGrantBinding;
  readonly constraints: readonly AuthoritativeCapabilityGrantConstraint[];
  readonly requirements: readonly AuthoritativeCapabilityGrantRequirement[];
  readonly limitations: readonly AuthoritativeCapabilityGrantLimitation[];
  readonly reasons: readonly AuthoritativeCapabilityActivationReason[];
  readonly validity: AuthoritativeCapabilityGrantValidity;
  readonly revocation: AuthoritativeCapabilityGrantRevocation;
  readonly usagePolicy: AuthoritativeCapabilityGrantUsagePolicy;
  readonly capabilityGranted: true;
  readonly activeCapabilityCreated: boolean;
  readonly actionAuthorized: false;
  readonly authorizationCreated: false;
  readonly authorizationPackageCreated: false;
  readonly sessionKeyCreated: false;
  readonly executionAllowed: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly transactionSubmitted: false;
  readonly vaultAccessed: false;
  readonly worldIdVerified: false;
  readonly rawTrustEvidenceIncluded: false;
  readonly rawApprovalArtifactIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly privateMaterialIncluded: false;
  readonly persisted: false;
  readonly persistedAsAuthority: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface AuthoritativeCapabilityActivationRequest {
  readonly requestId: string;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly authoritativePolicyDecision: AuthoritativePolicyDecision;
  readonly platformUserApprovalDecision: PlatformUserApprovalDecision;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly userSessionContext: UserSessionContext;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly requestedScope?: CapabilityScope;
  readonly effectiveScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly effectiveDurationSeconds?: number;
  readonly allowedTargets?: readonly string[];
  readonly valueLimit?: string;
  readonly actionTypes?: readonly string[];
  readonly chainId?: string | number;
  readonly network?: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthoritativeCapabilityActivationResult =
  RuntimeResult<AuthoritativeCapabilityGrant>;

export interface CapabilityActivationConsumptionRecord {
  readonly capabilityActivationEvidenceChainId: string;
  readonly authoritativeCapabilityGrantId?: string;
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly platformUserApprovalDecisionId: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralCapabilityActivationEvidenceConsumptionStore {
  consume(record: CapabilityActivationConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: CapabilityActivationConsumptionRecord;
    readonly records: readonly CapabilityActivationConsumptionRecord[];
    readonly reason?: string;
  };
  has(capabilityActivationEvidenceChainId: string): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly CapabilityActivationConsumptionRecord[];
  };
  getAll(): readonly CapabilityActivationConsumptionRecord[];
}

export type UserSessionCapabilityMutationStatus =
  | "activated"
  | "rejected_duplicate"
  | "rejected_overlap"
  | "rejected_invalid"
  | "revoked"
  | "expired"
  | "cleared"
  | "not_found";

export interface UserSessionCapabilityState {
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly activeGrants: readonly AuthoritativeCapabilityGrant[];
  readonly updatedAt: string;
  readonly persisted: false;
}

export interface UserSessionCapabilityMutationRequest {
  readonly grant: AuthoritativeCapabilityGrant;
  readonly sessionState: UserSessionCapabilityState;
  readonly requestedAt: string;
  readonly auditCorrelationId: string;
}

export interface UserSessionCapabilityMutationResult {
  readonly status: UserSessionCapabilityMutationStatus;
  readonly grant?: AuthoritativeCapabilityGrant;
  readonly state: UserSessionCapabilityState;
  readonly reason?: string;
  readonly errors?: readonly string[];
  readonly activeCapabilityCreated: boolean;
  readonly authorizationCreated: false;
  readonly sessionKeyCreated: false;
  readonly executionAllowed: false;
  readonly persisted: false;
}

export interface AuthoritativeCapabilityGrantStore {
  activate(grant: AuthoritativeCapabilityGrant): UserSessionCapabilityMutationResult;
  getById(grantId: string): AuthoritativeCapabilityGrant | undefined;
  listForSession(sessionId: string): readonly AuthoritativeCapabilityGrant[];
  listForApplication(applicationId: ApplicationId): readonly AuthoritativeCapabilityGrant[];
  findActiveCapability(input: {
    readonly sessionId: string;
    readonly applicationId: ApplicationId;
    readonly ownerCommitment: Hex;
    readonly capabilityName: CapabilityName;
  }): AuthoritativeCapabilityGrant | undefined;
  revoke(
    grantId: string,
    reason: AuthoritativeCapabilityGrantRevocationReason,
    revokedAt?: string
  ): UserSessionCapabilityMutationResult;
  expire(grantId: string, expiredAt?: string): UserSessionCapabilityMutationResult;
  clearSession(
    sessionId: string,
    reason?: AuthoritativeCapabilityGrantRevocationReason
  ): UserSessionCapabilityMutationResult;
  count(): number;
  getState(sessionId: string): UserSessionCapabilityState | undefined;
  getAll(): readonly AuthoritativeCapabilityGrant[];
}

export interface InMemoryAuthoritativeCapabilityGrantStoreOptions {
  readonly maxGrantCount?: number;
}

export interface CapabilityGrantRevocationRequest {
  readonly requestId: string;
  readonly grantId: string;
  readonly reason: AuthoritativeCapabilityGrantRevocationReason;
  readonly requestedAt: string;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ActiveCapabilityGrantInspectionRequest {
  readonly requestId: string;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly capabilityName?: CapabilityName;
  readonly ownerCommitment?: Hex;
  readonly requestedAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ActiveCapabilityGrantInspectionResultValue {
  readonly status: "inspected";
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly capabilityName?: CapabilityName;
  readonly count: number;
  readonly grants: readonly AuthoritativeCapabilityGrant[];
  readonly authorizationCreated: false;
  readonly executionAllowed: false;
  readonly persisted: false;
}

export interface CapabilityGrantUsageRequest {
  readonly requestId: string;
  readonly grant: AuthoritativeCapabilityGrant;
  readonly applicationId: ApplicationId;
  readonly sessionId: string;
  readonly capabilityName: CapabilityName;
  readonly requestedAt: string;
}

export interface CapabilityGrantUsageResult {
  readonly status: "accepted_for_authorization_review" | "rejected";
  readonly grantId?: string;
  readonly authorizationEngineStillRequired: true;
  readonly authorizationPackageCreated: false;
  readonly executionAllowed: false;
  readonly errors: readonly string[];
}

export interface CapabilityGrantConsumer {
  acceptCapabilityGrantForAuthorizationReview(
    request: CapabilityGrantUsageRequest
  ): CapabilityGrantUsageResult;
}

export interface AuthorizationEngineCapabilityInput {
  readonly authoritativeCapabilityGrantId: string;
  readonly capabilityName: CapabilityName;
  readonly actionAuthorizationStillRequired: true;
  readonly createsAuthorizationPackage: false;
}

const GRANT_STATUSES = new Set<AuthoritativeCapabilityGrantStatus>([
  "active",
  "revoked",
  "expired"
]);

const ACTIVATION_OUTCOMES = new Set<AuthoritativeCapabilityActivationOutcome>([
  "capability_granted",
  "trust_decision_ineligible",
  "policy_decision_ineligible",
  "approval_decision_ineligible",
  "approval_not_granted",
  "scope_mismatch",
  "duration_mismatch",
  "target_restriction_mismatch",
  "value_restriction_mismatch",
  "session_state_ineligible",
  "application_mismatch",
  "correlation_mismatch",
  "evidence_expired",
  "evidence_replayed",
  "world_id_requirement_unresolved",
  "malformed",
  "unsupported"
]);

const ELIGIBLE_LIFECYCLE_STATES = new Set<UserSessionLifecycleState>([
  "unlocked",
  "recovery_mode"
]);

const LIMITATIONS: readonly AuthoritativeCapabilityGrantLimitation[] = Object.freeze([
  "capability_authority_only",
  "process_local_authority_only",
  "process_local_replay_protection_only",
  "process_local_store_only",
  "session_bound",
  "application_bound",
  "owner_bound",
  "capability_bound",
  "scope_bound",
  "no_action_authorization",
  "no_authorization_package",
  "no_session_key",
  "no_execution",
  "no_proof_execution",
  "no_adapter_execution",
  "no_transaction_submission",
  "no_world_id_verification",
  "no_vault_access",
  "no_durable_capability_persistence"
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
  return { valid: errors.length === 0, errors };
}

function activationError(
  code: string,
  outcome: AuthoritativeCapabilityActivationOutcome,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "capability_denied",
    code,
    message: "authoritative capability activation request was rejected",
    boundary: "runtime-api",
    recoverable: true,
    details: { outcome, errors }
  };
}

function requirements(): readonly AuthoritativeCapabilityGrantRequirement[] {
  return Object.freeze([
    "authoritative_trust_decision",
    "authoritative_policy_decision",
    "approved_platform_user_approval_decision",
    "exact_capability_activation_request",
    "current_user_session_context",
    "eligible_lifecycle_state",
    "scope_within_policy",
    "duration_within_policy",
    "restrictions_preserved",
    "bounded_validity_window"
  ]);
}

function arraysEqual(left: readonly string[] = [], right: readonly string[] = []): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function targetRestrictions(policy: AuthoritativePolicyDecision): readonly string[] {
  if (policy.effectiveTargetRestrictions.length > 0) return policy.effectiveTargetRestrictions;
  return policy.scope.targetReference ? [policy.scope.targetReference] : [];
}

function actionTypesForPolicy(policy: AuthoritativePolicyDecision): readonly string[] {
  return Object.freeze([policy.scope.actionType]);
}

function policyScope(policy: AuthoritativePolicyDecision): CapabilityScope | undefined {
  return policy.effectiveScope ?? policy.scope.requestedScope;
}

function policyDuration(policy: AuthoritativePolicyDecision): number | undefined {
  return policy.effectiveDurationSeconds ?? policy.scope.requestedDurationSeconds;
}

function scopeWithinPolicy(
  requested: CapabilityScope | undefined,
  policy: CapabilityScope | undefined
): boolean {
  if (policy === undefined) return requested === undefined;
  return stableJson(requested) === stableJson(policy);
}

function correlationErrors(request: AuthoritativeCapabilityActivationRequest): readonly string[] {
  const errors: string[] = [];
  const trust = request.authoritativeTrustDecision;
  const policy = request.authoritativePolicyDecision;
  const approval = request.platformUserApprovalDecision;
  if (policy.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("Policy Decision Trust Decision mismatch");
  }
  if (approval.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("Approval Decision Trust Decision mismatch");
  }
  if (approval.binding.authoritativePolicyDecisionId !== policy.authoritativePolicyDecisionId) {
    errors.push("Approval Decision Policy Decision mismatch");
  }
  for (const [label, expected, actual] of [
    ["session", trust.scope.sessionId, request.sessionId],
    ["application", trust.scope.applicationId, request.applicationId],
    ["owner", trust.scope.ownerCommitment, request.ownerCommitment],
    ["audit", trust.scope.auditCorrelationId, request.auditCorrelationId],
    ["policy session", policy.scope.sessionId, request.sessionId],
    ["policy application", policy.scope.applicationId, request.applicationId],
    ["policy owner", policy.scope.ownerCommitment, request.ownerCommitment],
    ["policy capability", policy.scope.capabilityName, request.capabilityName],
    ["policy audit", policy.scope.auditCorrelationId, request.auditCorrelationId],
    ["approval session", approval.actionRequest.sessionId, request.sessionId],
    ["approval application", approval.actionRequest.applicationId, request.applicationId],
    ["approval owner", approval.actionRequest.ownerCommitment, request.ownerCommitment],
    ["approval capability", approval.actionRequest.capabilityName, request.capabilityName],
    ["approval audit", approval.actionRequest.auditCorrelationId, request.auditCorrelationId],
    ["lifecycle session", request.lifecycleSnapshot.sessionId, request.sessionId],
    ["context session", request.userSessionContext.sessionId, request.sessionId],
    ["context owner", request.userSessionContext.ownerCommitment, request.ownerCommitment]
  ] as const) {
    if (expected !== actual) errors.push(`${label} mismatch`);
  }
  if (!scopeWithinPolicy(request.effectiveScope, policyScope(policy))) errors.push("scope mismatch");
  if (!scopeWithinPolicy(request.effectiveScope, approval.actionRequest.effectiveScope)) {
    errors.push("approval scope mismatch");
  }
  const effectiveDuration = policyDuration(policy);
  if ((request.effectiveDurationSeconds ?? -1) !== (effectiveDuration ?? -1)) {
    errors.push("duration mismatch");
  }
  if ((request.effectiveDurationSeconds ?? -1)
    !== (approval.actionRequest.effectiveDurationSeconds ?? -1)) {
    errors.push("approval duration mismatch");
  }
  if ((request.valueLimit ?? "") !== (policy.effectiveValueLimit ?? "")) {
    errors.push("value restriction mismatch");
  }
  if ((request.valueLimit ?? "") !== (approval.actionRequest.requestedValue ?? "")) {
    errors.push("approval value mismatch");
  }
  const expectedTargets = targetRestrictions(policy);
  if (!arraysEqual([...(request.allowedTargets ?? [])].sort(), [...expectedTargets].sort())) {
    errors.push("target restriction mismatch");
  }
  if (!arraysEqual([...(request.actionTypes ?? [])].sort(), [...actionTypesForPolicy(policy)].sort())) {
    errors.push("action type mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

function eligibilityErrors(request: AuthoritativeCapabilityActivationRequest): readonly string[] {
  const errors: string[] = [];
  const trust = request.authoritativeTrustDecision;
  const policy = request.authoritativePolicyDecision;
  const approval = request.platformUserApprovalDecision;
  if (trust.status !== "trust_decision_created" || trust.outcome !== "trust_decision_created") {
    errors.push("trust decision ineligible");
  }
  if (policy.status !== "policy_decision_created" || policy.policyDecisionCreated !== true) {
    errors.push("policy decision ineligible");
  }
  if (policy.requiresWorldIdEnrollment) errors.push("world id requirement unresolved");
  if (!policy.requiresUserApproval && !policy.eligibleForCapabilityActivationReview) {
    errors.push("policy decision not eligible for capability activation");
  }
  if (approval.status !== "approval_decision_created") errors.push("approval decision ineligible");
  if (!approval.userApproved || approval.outcome !== "user_approved") {
    errors.push("approval not granted");
  }
  if (approval.fixtureOnly || !approval.productionBound) errors.push("fixture approval ineligible");
  if (expired(trust.validity.expiresAt)
    || expired(policy.validity.expiresAt)
    || expired(approval.validity.expiresAt)
    || expired(request.expiresAt)) {
    errors.push("evidence expired");
  }
  if (!ELIGIBLE_LIFECYCLE_STATES.has(request.lifecycleSnapshot.state)) {
    errors.push("session state ineligible");
  }
  if (request.userSessionContext.status !== "unlocked" && request.userSessionContext.status !== "recovery") {
    errors.push("session context ineligible");
  }
  if (Date.parse(request.expiresAt) <= Date.parse(request.issuedAt)) {
    errors.push("grant expiry must be after issue time");
  }
  return Object.freeze([...new Set(errors)]);
}

function outcomeForErrors(errors: readonly string[]): AuthoritativeCapabilityActivationOutcome {
  if (errors.some((error) => error.includes("replay") || error.includes("consumed"))) {
    return "evidence_replayed";
  }
  if (errors.some((error) => error.includes("world id"))) return "world_id_requirement_unresolved";
  if (errors.some((error) => error.includes("trust decision"))) return "trust_decision_ineligible";
  if (errors.some((error) => error.includes("policy decision") || error.includes("Policy Decision"))) return "policy_decision_ineligible";
  if (errors.some((error) => error.includes("approval not granted"))) return "approval_not_granted";
  if (errors.some((error) => error.includes("approval"))) return "approval_decision_ineligible";
  if (errors.some((error) => error.includes("scope"))) return "scope_mismatch";
  if (errors.some((error) => error.includes("duration"))) return "duration_mismatch";
  if (errors.some((error) => error.includes("target"))) return "target_restriction_mismatch";
  if (errors.some((error) => error.includes("value"))) return "value_restriction_mismatch";
  if (errors.some((error) => error.includes("session state") || error.includes("context"))) return "session_state_ineligible";
  if (errors.some((error) => error.includes("application"))) return "application_mismatch";
  if (errors.some((error) => error.includes("expired"))) return "evidence_expired";
  if (errors.some((error) => error.includes("mismatch"))) return "correlation_mismatch";
  return "malformed";
}

function auditDraftForActivation(input: {
  readonly request: AuthoritativeCapabilityActivationRequest;
  readonly outcome: AuthoritativeCapabilityActivationOutcome;
  readonly grant?: AuthoritativeCapabilityGrant;
  readonly mutation?: UserSessionCapabilityMutationResult;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "capability",
    outcome: input.grant ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    capability: input.request.capabilityName,
    summary: input.grant
      ? "Authoritative scoped capability grant activated for one session; no action authorization or execution was created."
      : "Authoritative capability activation rejected; no active capability, authorization, or execution was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authoritativeCapabilityGrantId: input.grant?.authoritativeCapabilityGrantId,
      authoritativeTrustDecisionId: input.request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId: input.request.authoritativePolicyDecision.authoritativePolicyDecisionId,
      platformUserApprovalDecisionId:
        input.request.platformUserApprovalDecision.platformUserApprovalDecisionId,
      applicationId: input.request.applicationId,
      sessionId: input.request.sessionId,
      ownerCommitment: input.request.ownerCommitment,
      capabilityName: input.request.capabilityName,
      effectiveScope: input.request.effectiveScope,
      effectiveDurationSeconds: input.request.effectiveDurationSeconds,
      allowedTargets: input.request.allowedTargets,
      valueLimit: input.request.valueLimit,
      actionTypes: input.request.actionTypes,
      outcome: input.outcome,
      mutationStatus: input.mutation?.status,
      capabilityGranted: input.grant?.capabilityGranted ?? false,
      activeCapabilityCreated: input.mutation?.activeCapabilityCreated ?? false,
      actionAuthorized: false,
      authorizationCreated: false,
      authorizationPackageCreated: false,
      sessionKeyCreated: false,
      executionAllowed: false,
      proofExecuted: false,
      adapterExecuted: false,
      transactionSubmitted: false,
      vaultAccessed: false,
      worldIdVerified: false,
      persistedAsAuthority: false,
      errors: input.errors ?? []
    }
  });
}

export function isAuthoritativeCapabilityGrantStatus(
  value: unknown
): value is AuthoritativeCapabilityGrantStatus {
  return GRANT_STATUSES.has(value as AuthoritativeCapabilityGrantStatus);
}

export function isAuthoritativeCapabilityActivationOutcome(
  value: unknown
): value is AuthoritativeCapabilityActivationOutcome {
  return ACTIVATION_OUTCOMES.has(value as AuthoritativeCapabilityActivationOutcome);
}

export function validateAuthoritativeCapabilityActivationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["authoritative capability activation request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  errors.push(...validateAuthoritativeTrustDecisionShape(request.authoritativeTrustDecision).errors.map((error) => `authoritativeTrustDecision.${error}`));
  errors.push(...validateAuthoritativePolicyDecisionShape(request.authoritativePolicyDecision).errors.map((error) => `authoritativePolicyDecision.${error}`));
  errors.push(...validatePlatformUserApprovalDecisionShape(request.platformUserApprovalDecision).errors.map((error) => `platformUserApprovalDecision.${error}`));
  errors.push(...validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot).errors.map((error) => `lifecycleSnapshot.${error}`));
  for (const field of ["ownerCommitment", "sessionId", "applicationId", "capabilityName", "issuedAt", "expiresAt", "auditCorrelationId"] as const) {
    if (!isNonEmptyString(request[field])) errors.push(`${field} is required`);
  }
  if (!isRecord(request.userSessionContext)) errors.push("userSessionContext is required");
  if (request.effectiveDurationSeconds !== undefined && typeof request.effectiveDurationSeconds !== "number") {
    errors.push("effectiveDurationSeconds must be a number");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (request.allowedTargets !== undefined && !Array.isArray(request.allowedTargets)) {
    errors.push("allowedTargets must be an array when provided");
  }
  if (request.actionTypes !== undefined && !Array.isArray(request.actionTypes)) {
    errors.push("actionTypes must be an array when provided");
  }
  errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation([...new Set(errors)]);
}

export function validateAuthoritativeCapabilityGrantShape(
  grant: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(grant)) return validation(["authoritative capability grant must be an object"]);
  if (!isNonEmptyString(grant.authoritativeCapabilityGrantId)) {
    errors.push("authoritativeCapabilityGrantId is required");
  }
  if (!isAuthoritativeCapabilityGrantStatus(grant.status)) errors.push("status is invalid");
  if (grant.outcome !== "capability_granted") errors.push("outcome must be capability_granted");
  if (!isRecord(grant.scope)) errors.push("scope is required");
  if (!isRecord(grant.binding)) errors.push("binding is required");
  if (!Array.isArray(grant.constraints)) errors.push("constraints must be an array");
  if (!Array.isArray(grant.requirements)) errors.push("requirements must be an array");
  if (!Array.isArray(grant.limitations)) errors.push("limitations must be an array");
  if (!isRecord(grant.validity)) errors.push("validity is required");
  if (!isRecord(grant.revocation)) errors.push("revocation is required");
  if (grant.capabilityGranted !== true) errors.push("capabilityGranted must be true");
  for (const field of [
    "actionAuthorized",
    "authorizationCreated",
    "authorizationPackageCreated",
    "sessionKeyCreated",
    "executionAllowed",
    "proofExecuted",
    "adapterExecuted",
    "transactionSubmitted",
    "vaultAccessed",
    "worldIdVerified",
    "rawTrustEvidenceIncluded",
    "rawApprovalArtifactIncluded",
    "credentialRecordIncluded",
    "privateMaterialIncluded",
    "persisted",
    "persistedAsAuthority"
  ]) {
    if (grant[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

function constraintsForRequest(
  request: AuthoritativeCapabilityActivationRequest
): readonly AuthoritativeCapabilityGrantConstraint[] {
  const constraints: AuthoritativeCapabilityGrantConstraint[] = [];
  if (request.effectiveScope !== undefined) {
    constraints.push({ constraintId: "scope", kind: "scope", value: request.effectiveScope });
  }
  if (request.effectiveDurationSeconds !== undefined) {
    constraints.push({ constraintId: "duration", kind: "duration", value: request.effectiveDurationSeconds });
  }
  for (const target of request.allowedTargets ?? []) {
    constraints.push({ constraintId: `target:${target}`, kind: "target", value: target });
  }
  if (request.valueLimit !== undefined) {
    constraints.push({ constraintId: "value", kind: "value", value: request.valueLimit });
  }
  for (const actionType of request.actionTypes ?? []) {
    constraints.push({ constraintId: `action:${actionType}`, kind: "action_type", value: actionType });
  }
  if (request.network !== undefined || request.chainId !== undefined) {
    constraints.push({
      constraintId: "network",
      kind: "network",
      value: { chainId: request.chainId, network: request.network }
    });
  }
  return Object.freeze(constraints.map(freezeRecord));
}

export function evaluateAuthoritativeCapabilityActivation(
  request: AuthoritativeCapabilityActivationRequest,
  consumptionStore?: EphemeralCapabilityActivationEvidenceConsumptionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativeCapabilityActivationResult {
  const shape = validateAuthoritativeCapabilityActivationRequest(request);
  if (!shape.valid) {
    const outcome = "malformed";
    const auditEventDraft = auditDraftForActivation({ request, outcome, errors: shape.errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(activationError(
      "AUTHORITATIVE_CAPABILITY_ACTIVATION_MALFORMED",
      outcome,
      shape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const errors = [...correlationErrors(request), ...eligibilityErrors(request)];
  if (errors.length > 0) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForActivation({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(activationError(
      outcome === "evidence_replayed"
        ? "AUTHORITATIVE_CAPABILITY_ACTIVATION_REPLAYED"
        : "AUTHORITATIVE_CAPABILITY_ACTIVATION_REJECTED",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const capabilityActivationEvidenceChainId = createAuditCorrelationId([
    request.authoritativeTrustDecision.authoritativeTrustDecisionId,
    request.authoritativePolicyDecision.authoritativePolicyDecisionId,
    request.platformUserApprovalDecision.platformUserApprovalDecisionId,
    request.sessionId,
    request.applicationId,
    request.capabilityName,
    stableJson(request.effectiveScope),
    String(request.effectiveDurationSeconds ?? ""),
    request.auditCorrelationId,
    "authoritative-capability-activation-evidence-chain"
  ]);
  if (consumptionStore?.has(capabilityActivationEvidenceChainId)) {
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForActivation({
      request,
      outcome,
      errors: ["capability activation evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(activationError(
      "AUTHORITATIVE_CAPABILITY_ACTIVATION_REPLAYED",
      outcome,
      ["capability activation evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const grantId = createAuditCorrelationId([
    capabilityActivationEvidenceChainId,
    request.issuedAt,
    request.expiresAt,
    "authoritative-capability-grant"
  ]);
  const grantBase = {
    authoritativeCapabilityGrantId: grantId,
    requestId: request.requestId,
    status: "active" as const,
    outcome: "capability_granted" as const,
    scope: {
      capabilityName: request.capabilityName,
      effectiveScope: request.effectiveScope,
      effectiveDurationSeconds: request.effectiveDurationSeconds,
      allowedTargets: Object.freeze([...(request.allowedTargets ?? [])]),
      valueLimit: request.valueLimit,
      actionTypes: Object.freeze([...(request.actionTypes ?? [])]),
      chainId: request.chainId,
      network: request.network
    },
    binding: {
      authoritativeTrustDecisionId: request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId: request.authoritativePolicyDecision.authoritativePolicyDecisionId,
      platformUserApprovalDecisionId:
        request.platformUserApprovalDecision.platformUserApprovalDecisionId,
      sessionLifecycleId: request.lifecycleSnapshot.lifecycleId,
      sessionLifecycleState: request.lifecycleSnapshot.state,
      ownerCommitment: request.ownerCommitment,
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      capabilityName: request.capabilityName,
      auditCorrelationId: request.auditCorrelationId,
      validityWindowId: createAuditCorrelationId([
        request.sessionId,
        request.applicationId,
        request.capabilityName,
        request.issuedAt,
        request.expiresAt,
        "capability-grant-validity-window"
      ]),
      reusableAcrossOwners: false as const,
      reusableAcrossSessions: false as const,
      reusableAcrossApplications: false as const,
      reusableAcrossCapabilities: false as const,
      reusableAcrossScopes: false as const,
      reusableAcrossTimeWindows: false as const
    },
    constraints: constraintsForRequest(request),
    requirements: requirements(),
    limitations: LIMITATIONS,
    reasons: Object.freeze([
      "authoritative-trust-decision-valid",
      "authoritative-policy-decision-valid",
      "platform-user-approval-decision-approved",
      "least-privilege-scope-preserved",
      "policy-restrictions-preserved",
      "session-context-eligible",
      "capability-authority-only",
      "no-action-authorization",
      "no-authorization-package",
      "no-execution"
    ]),
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false,
      invalidatedBySessionLock: true as const,
      invalidatedBySessionClose: true as const,
      invalidatedByExplicitRevocation: true as const,
      invalidatedByTrustDecisionExpiry: true as const,
      invalidatedByPolicyDecisionExpiry: true as const,
      invalidatedByApprovalDecisionExpiry: true as const
    },
    revocation: {
      revoked: false,
      durableRevocationImplemented: false as const,
      processLocalOnly: true as const
    },
    usagePolicy: {
      mayRequestFutureActions: true as const,
      actionAuthorizationStillRequired: true as const,
      authorizationEngineRequired: true as const,
      proofMayBeRequiredLater: true,
      adapterExecutionAllowed: false as const,
      unrestrictedWalletAuthority: false as const,
      usageCountConsumed: 0
    },
    capabilityGranted: true as const,
    activeCapabilityCreated: false,
    actionAuthorized: false as const,
    authorizationCreated: false as const,
    authorizationPackageCreated: false as const,
    sessionKeyCreated: false as const,
    executionAllowed: false as const,
    proofExecuted: false as const,
    adapterExecuted: false as const,
    transactionSubmitted: false as const,
    vaultAccessed: false as const,
    worldIdVerified: false as const,
    rawTrustEvidenceIncluded: false as const,
    rawApprovalArtifactIncluded: false as const,
    credentialRecordIncluded: false as const,
    privateMaterialIncluded: false as const,
    persisted: false as const,
    persistedAsAuthority: false as const
  };
  const grant = freezeRecord(grantBase) as AuthoritativeCapabilityGrant;
  const grantShape = validateAuthoritativeCapabilityGrantShape(grant);
  if (!grantShape.valid) {
    const outcome = "malformed";
    const auditEventDraft = auditDraftForActivation({ request, outcome, errors: grantShape.errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(activationError(
      "AUTHORITATIVE_CAPABILITY_GRANT_SHAPE_INVALID",
      outcome,
      grantShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const consumed = consumptionStore?.consume({
    capabilityActivationEvidenceChainId,
    authoritativeCapabilityGrantId: grantId,
    authoritativeTrustDecisionId: request.authoritativeTrustDecision.authoritativeTrustDecisionId,
    authoritativePolicyDecisionId: request.authoritativePolicyDecision.authoritativePolicyDecisionId,
    platformUserApprovalDecisionId:
      request.platformUserApprovalDecision.platformUserApprovalDecisionId,
    sessionId: request.sessionId,
    applicationId: request.applicationId,
    capabilityName: request.capabilityName,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForActivation({
      request,
      outcome,
      errors: ["capability activation evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(activationError(
      "AUTHORITATIVE_CAPABILITY_ACTIVATION_REPLAYED",
      outcome,
      ["capability activation evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const auditEventDraft = auditDraftForActivation({ request, outcome: "capability_granted", grant });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    ...grantBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as AuthoritativeCapabilityGrant);
}

export function createAuthoritativeCapabilityGrant(
  request: AuthoritativeCapabilityActivationRequest,
  consumptionStore?: EphemeralCapabilityActivationEvidenceConsumptionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativeCapabilityActivationResult {
  return evaluateAuthoritativeCapabilityActivation(request, consumptionStore, auditDraftCollector);
}

export function createEphemeralCapabilityActivationEvidenceConsumptionStore():
  EphemeralCapabilityActivationEvidenceConsumptionStore {
  const records = new Map<string, CapabilityActivationConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.capabilityActivationEvidenceChainId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.capabilityActivationEvidenceChainId),
          records: all(),
          reason: "capability activation evidence chain was already consumed"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.capabilityActivationEvidenceChainId, frozen);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(capabilityActivationEvidenceChainId) {
      return records.has(capabilityActivationEvidenceChainId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

function createEmptyCapabilityState(input: {
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly grants?: readonly AuthoritativeCapabilityGrant[];
}): UserSessionCapabilityState {
  return freezeRecord({
    sessionId: input.sessionId,
    ownerCommitment: input.ownerCommitment,
    activeGrants: input.grants ?? [],
    updatedAt: new Date().toISOString(),
    persisted: false as const
  });
}

function mutationResult(input: {
  readonly status: UserSessionCapabilityMutationStatus;
  readonly grant?: AuthoritativeCapabilityGrant;
  readonly state: UserSessionCapabilityState;
  readonly reason?: string;
  readonly errors?: readonly string[];
  readonly activeCapabilityCreated?: boolean;
}): UserSessionCapabilityMutationResult {
  return freezeRecord({
    status: input.status,
    grant: input.grant,
    state: input.state,
    reason: input.reason,
    errors: input.errors,
    activeCapabilityCreated: input.activeCapabilityCreated ?? false,
    authorizationCreated: false as const,
    sessionKeyCreated: false as const,
    executionAllowed: false as const,
    persisted: false as const
  });
}

function sameCapabilityBinding(
  left: AuthoritativeCapabilityGrant,
  right: AuthoritativeCapabilityGrant
): boolean {
  return left.binding.sessionId === right.binding.sessionId
    && left.binding.ownerCommitment === right.binding.ownerCommitment
    && left.binding.applicationId === right.binding.applicationId
    && left.binding.capabilityName === right.binding.capabilityName;
}

export function activateCapabilityForUserSession(
  request: UserSessionCapabilityMutationRequest
): UserSessionCapabilityMutationResult {
  const shape = validateAuthoritativeCapabilityGrantShape(request.grant);
  if (!shape.valid) {
    return mutationResult({
      status: "rejected_invalid",
      state: request.sessionState,
      errors: shape.errors
    });
  }
  if (request.sessionState.sessionId !== request.grant.binding.sessionId
    || request.sessionState.ownerCommitment !== request.grant.binding.ownerCommitment) {
    return mutationResult({
      status: "rejected_invalid",
      state: request.sessionState,
      errors: ["grant must match session capability state"]
    });
  }
  if (expired(request.grant.validity.expiresAt, Date.parse(request.requestedAt))) {
    return mutationResult({
      status: "expired",
      grant: expireAuthoritativeCapabilityGrant(request.grant, request.requestedAt),
      state: request.sessionState,
      reason: "grant expired before activation"
    });
  }
  if (request.sessionState.activeGrants.some(
    (grant) => grant.authoritativeCapabilityGrantId === request.grant.authoritativeCapabilityGrantId
  )) {
    return mutationResult({
      status: "rejected_duplicate",
      grant: request.grant,
      state: request.sessionState,
      reason: "active grant ID already exists"
    });
  }
  if (request.sessionState.activeGrants.some((grant) => sameCapabilityBinding(grant, request.grant))) {
    return mutationResult({
      status: "rejected_overlap",
      grant: request.grant,
      state: request.sessionState,
      reason: "overlapping active capability grant for same session/application/capability is rejected"
    });
  }
  const activatedGrant = freezeRecord({
    ...request.grant,
    activeCapabilityCreated: true
  }) as AuthoritativeCapabilityGrant;
  const state = createEmptyCapabilityState({
    sessionId: request.sessionState.sessionId,
    ownerCommitment: request.sessionState.ownerCommitment,
    grants: [...request.sessionState.activeGrants, activatedGrant]
  });
  return mutationResult({
    status: "activated",
    grant: activatedGrant,
    state,
    activeCapabilityCreated: true
  });
}

export function deriveUserSessionContextWithCapabilityGrant(
  context: UserSessionContext,
  grant: AuthoritativeCapabilityGrant
): UserSessionContext {
  const ids = new Set(context.activeCapabilityIds ?? []);
  ids.add(grant.authoritativeCapabilityGrantId);
  return freezeRecord({
    ...context,
    activeCapabilityIds: Object.freeze([...ids]),
    metadata: {
      ...context.metadata,
      activeCapabilitiesAvailable: false,
      requestMetadata: {
        ...context.metadata?.requestMetadata,
        latestAuthoritativeCapabilityGrantId: grant.authoritativeCapabilityGrantId
      }
    }
  }) as UserSessionContext;
}

export function revokeAuthoritativeCapabilityGrant(
  grant: AuthoritativeCapabilityGrant,
  reason: AuthoritativeCapabilityGrantRevocationReason = "user_revoked",
  revokedAt = new Date().toISOString()
): AuthoritativeCapabilityGrant {
  return freezeRecord({
    ...grant,
    status: "revoked" as const,
    revocation: {
      revoked: true,
      revokedAt,
      reason,
      durableRevocationImplemented: false as const,
      processLocalOnly: true as const
    },
    activeCapabilityCreated: false
  }) as AuthoritativeCapabilityGrant;
}

export function expireAuthoritativeCapabilityGrant(
  grant: AuthoritativeCapabilityGrant,
  expiredAt = new Date().toISOString()
): AuthoritativeCapabilityGrant {
  return freezeRecord({
    ...grant,
    status: "expired" as const,
    validity: {
      ...grant.validity,
      expiresAt: expiredAt,
      expired: true
    },
    revocation: {
      revoked: true,
      revokedAt: expiredAt,
      reason: "grant_expired" as const,
      durableRevocationImplemented: false as const,
      processLocalOnly: true as const
    },
    activeCapabilityCreated: false
  }) as AuthoritativeCapabilityGrant;
}

export function validateCapabilityGrantActiveState(
  grant: AuthoritativeCapabilityGrant,
  now = new Date().toISOString()
): RuntimeValidationResult {
  const errors = validateAuthoritativeCapabilityGrantShape(grant).errors.slice();
  if (grant.status !== "active") errors.push("grant is not active");
  if (grant.revocation.revoked) errors.push("grant is revoked");
  if (expired(grant.validity.expiresAt, Date.parse(now))) errors.push("grant is expired");
  return validation(errors);
}

export function createInMemoryAuthoritativeCapabilityGrantStore(
  options: InMemoryAuthoritativeCapabilityGrantStoreOptions = {}
): AuthoritativeCapabilityGrantStore {
  const maxGrantCount = Math.max(1, Math.floor(options.maxGrantCount ?? 100));
  const states = new Map<string, UserSessionCapabilityState>();

  function allGrants(): readonly AuthoritativeCapabilityGrant[] {
    return Object.freeze(Array.from(states.values()).flatMap((state) => [...state.activeGrants]));
  }

  function stateForGrant(grant: AuthoritativeCapabilityGrant): UserSessionCapabilityState {
    return states.get(grant.binding.sessionId) ?? createEmptyCapabilityState({
      sessionId: grant.binding.sessionId,
      ownerCommitment: grant.binding.ownerCommitment
    });
  }

  function saveState(state: UserSessionCapabilityState): void {
    states.set(state.sessionId, state);
  }

  return {
    activate(grant) {
      if (allGrants().length >= maxGrantCount) {
        return mutationResult({
          status: "rejected_invalid",
          state: stateForGrant(grant),
          grant,
          reason: "maximum process-local capability grant count reached"
        });
      }
      const result = activateCapabilityForUserSession({
        grant,
        sessionState: stateForGrant(grant),
        requestedAt: new Date().toISOString(),
        auditCorrelationId: grant.binding.auditCorrelationId
      });
      if (result.status === "activated") saveState(result.state);
      return result;
    },
    getById(grantId) {
      return allGrants().find((grant) => grant.authoritativeCapabilityGrantId === grantId);
    },
    listForSession(sessionId) {
      return Object.freeze([...(states.get(sessionId)?.activeGrants ?? [])]);
    },
    listForApplication(applicationId) {
      return Object.freeze(allGrants().filter(
        (grant) => grant.binding.applicationId === applicationId
      ));
    },
    findActiveCapability(input) {
      return allGrants().find((grant) =>
        grant.status === "active"
        && grant.binding.sessionId === input.sessionId
        && grant.binding.applicationId === input.applicationId
        && grant.binding.ownerCommitment === input.ownerCommitment
        && grant.binding.capabilityName === input.capabilityName
        && !expired(grant.validity.expiresAt)
      );
    },
    revoke(grantId, reason, revokedAt = new Date().toISOString()) {
      for (const state of states.values()) {
        const index = state.activeGrants.findIndex(
          (grant) => grant.authoritativeCapabilityGrantId === grantId
        );
        if (index !== -1) {
          const grant = state.activeGrants[index];
          const revoked = revokeAuthoritativeCapabilityGrant(grant, reason, revokedAt);
          const activeGrants = state.activeGrants.filter((_, grantIndex) => grantIndex !== index);
          const nextState = createEmptyCapabilityState({
            sessionId: state.sessionId,
            ownerCommitment: state.ownerCommitment,
            grants: activeGrants
          });
          saveState(nextState);
          return mutationResult({
            status: "revoked",
            grant: revoked,
            state: nextState,
            reason
          });
        }
      }
      return mutationResult({
        status: "not_found",
        state: createEmptyCapabilityState({ sessionId: "", ownerCommitment: "" as Hex }),
        reason: "grant not found"
      });
    },
    expire(grantId, expiredAt = new Date().toISOString()) {
      for (const state of states.values()) {
        const grant = state.activeGrants.find(
          (entry) => entry.authoritativeCapabilityGrantId === grantId
        );
        if (grant) {
          const expiredGrant = expireAuthoritativeCapabilityGrant(grant, expiredAt);
          const nextState = createEmptyCapabilityState({
            sessionId: state.sessionId,
            ownerCommitment: state.ownerCommitment,
            grants: state.activeGrants.filter(
              (entry) => entry.authoritativeCapabilityGrantId !== grantId
            )
          });
          saveState(nextState);
          return mutationResult({
            status: "expired",
            grant: expiredGrant,
            state: nextState,
            reason: "grant expired"
          });
        }
      }
      return mutationResult({
        status: "not_found",
        state: createEmptyCapabilityState({ sessionId: "", ownerCommitment: "" as Hex }),
        reason: "grant not found"
      });
    },
    clearSession(sessionId, reason = "session_locked") {
      const state = states.get(sessionId);
      if (!state) {
        return mutationResult({
          status: "not_found",
          state: createEmptyCapabilityState({ sessionId, ownerCommitment: "" as Hex }),
          reason: "session not found"
        });
      }
      const nextState = createEmptyCapabilityState({
        sessionId: state.sessionId,
        ownerCommitment: state.ownerCommitment,
        grants: []
      });
      states.set(sessionId, nextState);
      return mutationResult({
        status: "cleared",
        state: nextState,
        reason
      });
    },
    count() {
      return allGrants().length;
    },
    getState(sessionId) {
      return states.get(sessionId);
    },
    getAll: allGrants
  };
}

export function createFixtureCapabilityGrantConsumer(): CapabilityGrantConsumer {
  return {
    acceptCapabilityGrantForAuthorizationReview(request) {
      const validationResult = validateCapabilityGrantActiveState(request.grant, request.requestedAt);
      const matches = request.grant.binding.applicationId === request.applicationId
        && request.grant.binding.sessionId === request.sessionId
        && request.grant.binding.capabilityName === request.capabilityName;
      if (!validationResult.valid || !matches) {
        return freezeRecord({
          status: "rejected" as const,
          errors: matches ? validationResult.errors : [...validationResult.errors, "request mismatch"],
          authorizationEngineStillRequired: true as const,
          authorizationPackageCreated: false as const,
          executionAllowed: false as const
        });
      }
      return freezeRecord({
        status: "accepted_for_authorization_review" as const,
        grantId: request.grant.authoritativeCapabilityGrantId,
        errors: [],
        authorizationEngineStillRequired: true as const,
        authorizationPackageCreated: false as const,
        executionAllowed: false as const
      });
    }
  };
}
