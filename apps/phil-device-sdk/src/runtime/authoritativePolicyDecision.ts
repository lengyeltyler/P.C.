import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type {
  AuthoritativeTrustDecision
} from "./authoritativeTrustDecision.ts";
import { validateAuthoritativeTrustDecisionShape } from "./authoritativeTrustDecision.ts";
import type {
  RuntimePolicyConstraint,
  RuntimePolicyRequirement,
  RuntimePolicyRule,
  RuntimePolicyRuleEffect,
  RuntimePolicyRuleScope,
  RuntimePolicyRuleType
} from "./boundedPolicyEvaluation.ts";
import { validateRuntimePolicySet } from "./boundedPolicyEvaluation.ts";
import type { CapabilityGrantDraft } from "./capabilityDrafts.ts";
import { validateCapabilityGrantDraftShape } from "./capabilityDrafts.ts";
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
  CapabilityRequest,
  CapabilityScope,
  Intent,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type AuthoritativePolicyRuleType =
  | RuntimePolicyRuleType
  | "allow_for_user_approval"
  | "restrict_target";

export type AuthoritativePolicyRuleEffect =
  | RuntimePolicyRuleEffect
  | "allow_for_user_approval"
  | "allow_for_capability_activation_review"
  | "restrict_target"
  | "restrict_value"
  | "restrict_duration";

export interface AuthoritativePolicyRule
  extends Omit<RuntimePolicyRule, "type" | "effect" | "scope"> {
  readonly type: AuthoritativePolicyRuleType;
  readonly effect: AuthoritativePolicyRuleEffect;
  readonly scope?: RuntimePolicyRuleScope & {
    readonly actionTypes?: readonly string[];
    readonly targetReferences?: readonly string[];
  };
}

export interface AuthoritativePolicySet {
  readonly policySetId: string;
  readonly version: string;
  readonly mode?: string;
  readonly rules: readonly AuthoritativePolicyRule[];
  readonly createdAt?: string;
  readonly expiresAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthoritativePolicyDecisionStatus =
  | "policy_decision_created"
  | "policy_decision_rejected"
  | "policy_decision_malformed"
  | "policy_decision_replayed"
  | "policy_decision_expired"
  | "policy_decision_unsupported";

export type AuthoritativePolicyDecisionOutcome =
  | "policy_decision_created"
  | "allowed_for_user_approval"
  | "allowed_for_capability_activation_review"
  | "denied"
  | "requires_user_approval"
  | "requires_stronger_trust"
  | "requires_production_authentication"
  | "requires_world_id_enrollment"
  | "requires_recovery_context"
  | "scope_restricted"
  | "duration_restricted"
  | "value_restricted"
  | "application_restricted"
  | "target_restricted"
  | "session_state_ineligible"
  | "trust_decision_ineligible"
  | "correlation_mismatch"
  | "expired"
  | "malformed"
  | "unsupported";

export type AuthoritativePolicyDecisionReason =
  | "authoritative-trust-decision-valid"
  | "explicit-policy-set-valid"
  | "explicit-request-context-valid"
  | "policy-rule-applicable"
  | "policy-rule-not-applicable"
  | "deny-precedence"
  | "recovery-context-required"
  | "world-id-enrollment-required"
  | "production-authentication-required"
  | "stronger-trust-required"
  | "user-approval-required"
  | "scope-restriction-applied"
  | "duration-restriction-applied"
  | "value-restriction-applied"
  | "target-restriction-applied"
  | "application-restricted"
  | "session-state-ineligible"
  | "eligible-for-capability-activation-review"
  | "security-policy-authority-only"
  | "no-capability-grant"
  | "no-user-approval"
  | "no-authorization"
  | "no-execution"
  | (string & {});

export type AuthoritativePolicyDecisionRequirement =
  | "authoritative_trust_decision"
  | "explicit_capability_or_action_request"
  | "explicit_policy_set"
  | "session_context_eligible"
  | "owner_session_application_audit_correlation"
  | "deterministic_rule_evaluation"
  | "bounded_validity_window";

export type AuthoritativePolicyDecisionLimitation =
  | "security_policy_authority_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "explicit_policy_rules_only"
  | "request_bound"
  | "session_bound"
  | "capability_bound"
  | "action_bound"
  | "no_capability_grant"
  | "no_user_approval"
  | "no_authorization_package"
  | "no_session_key"
  | "no_execution"
  | "no_proof_execution"
  | "no_adapter_execution"
  | "no_world_id_verification"
  | "no_vault_access"
  | "no_durable_policy_database";

export interface AuthoritativePolicyActionContext {
  readonly actionType: string;
  readonly targetReference?: string;
  readonly requestedValue?: string;
  readonly requestedDurationSeconds?: number;
  readonly requestedScope?: CapabilityScope;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly canonicalPhilActivation?: boolean;
  readonly recoveryContext?: boolean;
  readonly experimentalFeatures?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthoritativePolicyDecisionScope {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly authenticationPurpose: string;
  readonly requestedAssurance: readonly string[];
  readonly requestedScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly requestedValue?: string;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly auditCorrelationId: string;
}

export interface AuthoritativePolicyDecisionBinding {
  readonly authoritativeTrustDecisionId: string;
  readonly capabilityRequestId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly intentId?: string;
  readonly policySetId: string;
  readonly policySetVersion: string;
  readonly sessionLifecycleId: string;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly validityWindowId: string;
  readonly reusableAcrossTrustDecisions: false;
  readonly reusableAcrossSessions: false;
  readonly reusableAcrossApplications: false;
  readonly reusableAcrossCapabilities: false;
  readonly reusableAcrossActions: false;
  readonly reusableAcrossTargets: false;
  readonly reusableAcrossTimeWindows: false;
}

export interface AuthoritativePolicyDecisionConstraint {
  readonly constraintId: string;
  readonly kind:
    | "scope"
    | "duration"
    | "value"
    | "application"
    | "target"
    | "session_state"
    | "recovery_context"
    | "world_id"
    | "custom";
  readonly value?: unknown;
  readonly sourceRuleId?: string;
}

export interface AuthoritativePolicyDecisionRuleResult {
  readonly ruleId: string;
  readonly type: AuthoritativePolicyRuleType;
  readonly effect: AuthoritativePolicyRuleEffect;
  readonly applicable: boolean;
  readonly outcome?: AuthoritativePolicyDecisionOutcome;
  readonly constraints: readonly AuthoritativePolicyDecisionConstraint[];
  readonly requirements: readonly string[];
  readonly reasons: readonly AuthoritativePolicyDecisionReason[];
}

export interface AuthoritativePolicyDecisionEvidence {
  readonly trustDecisionAccepted: true;
  readonly trustDecisionId: string;
  readonly policySetId: string;
  readonly policySetVersion: string;
  readonly rulesEvaluated: true;
  readonly ruleCount: number;
  readonly applicableRuleCount: number;
  readonly rawTrustEvidenceIncluded: false;
  readonly rawWebAuthnPayloadIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly vaultHandleIncluded: false;
  readonly adapterPayloadIncluded: false;
  readonly worldIdProofIncluded: false;
}

export interface AuthoritativePolicyDecisionValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedBySessionClose: true;
  readonly invalidatedByTrustDecisionExpiry: true;
  readonly invalidatedByPolicySetVersionChange: true;
  readonly invalidatedByRequestExpiry: true;
}

export interface AuthoritativePolicyDecision {
  readonly authoritativePolicyDecisionId: string;
  readonly requestId: string;
  readonly status: "policy_decision_created";
  readonly outcome: AuthoritativePolicyDecisionOutcome;
  readonly scope: AuthoritativePolicyDecisionScope;
  readonly binding: AuthoritativePolicyDecisionBinding;
  readonly evidence: AuthoritativePolicyDecisionEvidence;
  readonly validity: AuthoritativePolicyDecisionValidity;
  readonly ruleResults: readonly AuthoritativePolicyDecisionRuleResult[];
  readonly constraints: readonly AuthoritativePolicyDecisionConstraint[];
  readonly requirements: readonly AuthoritativePolicyDecisionRequirement[];
  readonly limitations: readonly AuthoritativePolicyDecisionLimitation[];
  readonly reasons: readonly AuthoritativePolicyDecisionReason[];
  readonly effectiveScope?: CapabilityScope;
  readonly effectiveDurationSeconds?: number;
  readonly effectiveValueLimit?: string;
  readonly effectiveTargetRestrictions: readonly string[];
  readonly requiresUserApproval: boolean;
  readonly requiresStrongerTrust: boolean;
  readonly requiresProductionAuthentication: boolean;
  readonly requiresWorldIdEnrollment: boolean;
  readonly requiresRecoveryContext: boolean;
  readonly eligibleForCapabilityActivationReview: boolean;
  readonly policyDecisionCreated: true;
  readonly trustDecisionAccepted: true;
  readonly rulesEvaluated: true;
  readonly capabilityGranted: false;
  readonly userApprovalCollected: false;
  readonly authorizationCreated: false;
  readonly sessionKeyCreated: false;
  readonly executionAllowed: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly worldIdVerified: false;
  readonly vaultAccessed: false;
  readonly persistedAsAuthority: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: AuthoritativePolicyDecisionCollectionResult;
}

export interface AuthoritativePolicyDecisionRequest {
  readonly requestId: string;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly capabilityRequest?: CapabilityRequest;
  readonly capabilityGrantDraft?: CapabilityGrantDraft;
  readonly intent?: Intent;
  readonly actionContext: AuthoritativePolicyActionContext;
  readonly policySet: AuthoritativePolicySet;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly sessionId: string;
  readonly lifecycleState: UserSessionLifecycleState;
  readonly ownerCommitment: Hex;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly requestedScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly requestedValue?: string;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly authenticationPurpose: string;
  readonly requestedAssurance: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly recoveryContext?: boolean;
  readonly canonicalPhilActivationContext?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthoritativePolicyDecisionResult =
  RuntimeResult<AuthoritativePolicyDecision>;

export interface AuthoritativePolicyDecisionConsumptionRecord {
  readonly policyEvidenceChainId: string;
  readonly authoritativePolicyDecisionId?: string;
  readonly authoritativeTrustDecisionId: string;
  readonly policySetId: string;
  readonly policySetVersion: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export type AuthoritativePolicyDecisionConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface AuthoritativePolicyDecisionConsumptionResult {
  readonly status: AuthoritativePolicyDecisionConsumptionStatus;
  readonly record?: AuthoritativePolicyDecisionConsumptionRecord;
  readonly records: readonly AuthoritativePolicyDecisionConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralPolicyDecisionEvidenceConsumptionStore {
  consume(record: AuthoritativePolicyDecisionConsumptionRecord):
    AuthoritativePolicyDecisionConsumptionResult;
  has(policyEvidenceChainId: string): boolean;
  clear(): AuthoritativePolicyDecisionConsumptionResult;
  getAll(): readonly AuthoritativePolicyDecisionConsumptionRecord[];
}

export type AuthoritativePolicyDecisionCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface AuthoritativePolicyDecisionCollection {
  readonly decisions: readonly AuthoritativePolicyDecision[];
  readonly count: number;
  readonly maxDecisionCount: number;
}

export interface AuthoritativePolicyDecisionCollectionResult {
  readonly status: AuthoritativePolicyDecisionCollectionStatus;
  readonly decision?: AuthoritativePolicyDecision;
  readonly removedDecision?: AuthoritativePolicyDecision;
  readonly evictedDecisions?: readonly AuthoritativePolicyDecision[];
  readonly collection: AuthoritativePolicyDecisionCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface AuthoritativePolicyDecisionStore {
  addDecision(decision: AuthoritativePolicyDecision): AuthoritativePolicyDecisionCollectionResult;
  removeDecision(decisionId: string): AuthoritativePolicyDecisionCollectionResult;
  clear(): AuthoritativePolicyDecisionCollectionResult;
  count(): number;
  getById(decisionId: string): AuthoritativePolicyDecision | undefined;
  getAll(): readonly AuthoritativePolicyDecision[];
  getUnexpired(now?: string): readonly AuthoritativePolicyDecision[];
}

export interface InMemoryAuthoritativePolicyDecisionStoreOptions {
  readonly maxDecisionCount?: number;
}

export interface PolicyDecisionConsumerRequest {
  readonly consumerId: string;
  readonly authoritativePolicyDecision: AuthoritativePolicyDecision;
  readonly requestedAt: string;
}

export interface PolicyDecisionConsumerResult {
  readonly status: "accepted_shape" | "rejected_shape";
  readonly authoritativePolicyDecisionId?: string;
  readonly errors: readonly string[];
  readonly capabilityGranted: false;
  readonly userApprovalCollected: false;
  readonly authorizationCreated: false;
}

export interface PolicyDecisionConsumer {
  acceptPolicyDecisionShape(request: PolicyDecisionConsumerRequest):
    PolicyDecisionConsumerResult;
}

export interface CapabilityActivationPolicyInput {
  readonly authoritativePolicyDecisionId: string;
  readonly eligibleForCapabilityActivationReview: boolean;
  readonly grantsCapability: false;
  readonly createsAuthorization: false;
  readonly requiresUserApproval: boolean;
}

export interface UserApprovalPolicyInput {
  readonly authoritativePolicyDecisionId: string;
  readonly requiresUserApproval: boolean;
  readonly productionUserApprovalCollected: false;
  readonly createsAuthorization: false;
}

const RULE_TYPES = new Set<AuthoritativePolicyRuleType>([
  "require_trust_level",
  "require_production_possession_verification",
  "require_user_approval",
  "require_world_id_enrollment",
  "deny_capability",
  "allow_capability_for_review",
  "allow_for_user_approval",
  "limit_scope",
  "limit_duration",
  "limit_value",
  "restrict_application",
  "restrict_target",
  "restrict_session_state",
  "recovery_only",
  "experimental_feature_required"
]);

const RULE_EFFECTS = new Set<AuthoritativePolicyRuleEffect>([
  "allow_for_further_review",
  "allow_for_user_approval",
  "allow_for_capability_activation_review",
  "deny",
  "require_stronger_trust",
  "require_user_approval",
  "require_production_verification",
  "require_world_id_enrollment",
  "restrict_scope",
  "restrict_target",
  "restrict_value",
  "restrict_duration",
  "unsupported"
]);

const STATUSES = new Set<AuthoritativePolicyDecisionStatus>([
  "policy_decision_created",
  "policy_decision_rejected",
  "policy_decision_malformed",
  "policy_decision_replayed",
  "policy_decision_expired",
  "policy_decision_unsupported"
]);

const OUTCOMES = new Set<AuthoritativePolicyDecisionOutcome>([
  "policy_decision_created",
  "allowed_for_user_approval",
  "allowed_for_capability_activation_review",
  "denied",
  "requires_user_approval",
  "requires_stronger_trust",
  "requires_production_authentication",
  "requires_world_id_enrollment",
  "requires_recovery_context",
  "scope_restricted",
  "duration_restricted",
  "value_restricted",
  "application_restricted",
  "target_restricted",
  "session_state_ineligible",
  "trust_decision_ineligible",
  "correlation_mismatch",
  "expired",
  "malformed",
  "unsupported"
]);

const LIMITATIONS: readonly AuthoritativePolicyDecisionLimitation[] = Object.freeze([
  "security_policy_authority_only",
  "process_local_replay_protection_only",
  "process_local_store_only",
  "explicit_policy_rules_only",
  "request_bound",
  "session_bound",
  "capability_bound",
  "action_bound",
  "no_capability_grant",
  "no_user_approval",
  "no_authorization_package",
  "no_session_key",
  "no_execution",
  "no_proof_execution",
  "no_adapter_execution",
  "no_world_id_verification",
  "no_vault_access",
  "no_durable_policy_database"
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

function addUnique<TValue extends string>(values: TValue[], value: TValue): void {
  if (!values.includes(value)) values.push(value);
}

function policyError(code: string, errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "policy_denied",
    code,
    message: "authoritative Security Policy Decision request was rejected",
    boundary: "security-policy-engine",
    recoverable: true,
    details: { errors }
  };
}

function validatePolicyRule(rule: unknown, index: number): readonly string[] {
  const errors: string[] = [];
  if (!isRecord(rule)) return [`policySet.rules[${index}] must be an object`];
  if (!isNonEmptyString(rule.ruleId)) errors.push(`policySet.rules[${index}].ruleId is required`);
  if (!RULE_TYPES.has(rule.type as AuthoritativePolicyRuleType)) {
    errors.push(`policySet.rules[${index}].type is invalid`);
  }
  if (!RULE_EFFECTS.has(rule.effect as AuthoritativePolicyRuleEffect)) {
    errors.push(`policySet.rules[${index}].effect is invalid`);
  }
  if (rule.expiresAt !== undefined && !hasValidDateShape(rule.expiresAt)) {
    errors.push(`policySet.rules[${index}].expiresAt must be a parseable date string`);
  }
  if (rule.constraints !== undefined && !Array.isArray(rule.constraints)) {
    errors.push(`policySet.rules[${index}].constraints must be an array when provided`);
  }
  if (rule.requirements !== undefined && !Array.isArray(rule.requirements)) {
    errors.push(`policySet.rules[${index}].requirements must be an array when provided`);
  }
  return errors;
}

function validateAuthoritativePolicySet(policySet: unknown): RuntimeValidationResult {
  const legacyValidation = validateRuntimePolicySet(policySet);
  const errors: string[] = [];
  if (!isRecord(policySet)) return validation(["policySet must be an object"]);
  if (!isNonEmptyString(policySet.policySetId)) errors.push("policySet.policySetId is required");
  if (!isNonEmptyString(policySet.version)) errors.push("policySet.version is required");
  if (!Array.isArray(policySet.rules)) {
    errors.push("policySet.rules must be an array");
  } else {
    policySet.rules.forEach((rule, index) => {
      errors.push(...validatePolicyRule(rule, index));
    });
  }
  if (!hasValidDateShape(policySet.expiresAt)) {
    errors.push("policySet.expiresAt must be a parseable date string");
  }
  if (policySet.createdAt !== undefined && !hasValidDateShape(policySet.createdAt)) {
    errors.push("policySet.createdAt must be a parseable date string");
  }
  for (const error of legacyValidation.errors) {
    if (!error.includes(".type is invalid") && !error.includes(".effect is invalid")) {
      errors.push(error);
    }
  }
  return validation([...new Set(errors)]);
}

function requirements(): readonly AuthoritativePolicyDecisionRequirement[] {
  return Object.freeze([
    "authoritative_trust_decision",
    "explicit_capability_or_action_request",
    "explicit_policy_set",
    "session_context_eligible",
    "owner_session_application_audit_correlation",
    "deterministic_rule_evaluation",
    "bounded_validity_window"
  ]);
}

function ruleConstraint(
  rule: AuthoritativePolicyRule,
  kind: AuthoritativePolicyDecisionConstraint["kind"]
): RuntimePolicyConstraint | undefined {
  return rule.constraints?.find((constraint) => constraint.kind === kind);
}

function ruleApplies(
  rule: AuthoritativePolicyRule,
  request: AuthoritativePolicyDecisionRequest
): boolean {
  if (rule.enabled === false || expired(rule.expiresAt)) return false;
  const scope = rule.scope;
  if (!scope) return true;
  if (scope.applicationIds !== undefined && !scope.applicationIds.includes(request.applicationId)) {
    return false;
  }
  if (scope.capabilityNames !== undefined && !scope.capabilityNames.includes(request.capabilityName)) {
    return false;
  }
  if (scope.sessionIds !== undefined && !scope.sessionIds.includes(request.sessionId)) {
    return false;
  }
  if (scope.sessionStatuses !== undefined && !scope.sessionStatuses.includes(request.lifecycleState as never)) {
    return false;
  }
  if (scope.actionTypes !== undefined && !scope.actionTypes.includes(request.actionType)) {
    return false;
  }
  if (
    scope.targetReferences !== undefined
    && (request.targetReference === undefined || !scope.targetReferences.includes(request.targetReference))
  ) {
    return false;
  }
  if (scope.recoveryOnly === true && request.recoveryContext !== true) return false;
  if (
    rule.type === "require_world_id_enrollment"
    && request.canonicalPhilActivationContext !== true
    && request.actionContext.canonicalPhilActivation !== true
  ) {
    return false;
  }
  return true;
}

function resultForRule(
  rule: AuthoritativePolicyRule,
  request: AuthoritativePolicyDecisionRequest
): AuthoritativePolicyDecisionRuleResult {
  const constraints: AuthoritativePolicyDecisionConstraint[] = [];
  const requirementsForRule: string[] = [];
  const reasons: AuthoritativePolicyDecisionReason[] = ["policy-rule-applicable"];
  let outcome: AuthoritativePolicyDecisionOutcome = "allowed_for_capability_activation_review";

  if (rule.type === "deny_capability" || rule.effect === "deny") {
    outcome = "denied";
    reasons.push("deny-precedence");
  } else if (rule.type === "recovery_only" && request.recoveryContext !== true) {
    outcome = "requires_recovery_context";
    requirementsForRule.push("recovery_context");
    reasons.push("recovery-context-required");
  } else if (
    rule.type === "require_world_id_enrollment"
    || rule.effect === "require_world_id_enrollment"
  ) {
    outcome = "requires_world_id_enrollment";
    requirementsForRule.push("world_id_enrollment");
    constraints.push({
      constraintId: `${rule.ruleId}:world-id`,
      kind: "world_id",
      sourceRuleId: rule.ruleId
    });
    reasons.push("world-id-enrollment-required");
  } else if (
    rule.type === "require_production_possession_verification"
    || rule.effect === "require_production_verification"
  ) {
    if (!request.authoritativeTrustDecision.productionAssertionVerified) {
      outcome = "requires_production_authentication";
      requirementsForRule.push("production_authentication");
      reasons.push("production-authentication-required");
    }
  } else if (rule.type === "require_trust_level" || rule.effect === "require_stronger_trust") {
    outcome = "requires_stronger_trust";
    requirementsForRule.push("stronger_trust");
    reasons.push("stronger-trust-required");
  } else if (rule.type === "require_user_approval" || rule.effect === "require_user_approval") {
    outcome = "requires_user_approval";
    requirementsForRule.push("user_approval");
    reasons.push("user-approval-required");
  } else if (rule.type === "restrict_application") {
    outcome = "application_restricted";
    constraints.push({
      constraintId: `${rule.ruleId}:application`,
      kind: "application",
      value: ruleConstraint(rule, "application")?.value,
      sourceRuleId: rule.ruleId
    });
    reasons.push("application-restricted");
  } else if (rule.type === "restrict_target" || rule.effect === "restrict_target") {
    outcome = "target_restricted";
    constraints.push({
      constraintId: `${rule.ruleId}:target`,
      kind: "target",
      value: ruleConstraint(rule, "target" as never)?.value ?? request.targetReference,
      sourceRuleId: rule.ruleId
    });
    reasons.push("target-restriction-applied");
  } else if (rule.type === "restrict_session_state") {
    outcome = "session_state_ineligible";
    constraints.push({
      constraintId: `${rule.ruleId}:session-state`,
      kind: "session_state",
      value: request.lifecycleState,
      sourceRuleId: rule.ruleId
    });
    reasons.push("session-state-ineligible");
  } else if (rule.type === "limit_duration" || rule.effect === "restrict_duration") {
    outcome = "duration_restricted";
    requirementsForRule.push("duration_restriction");
    constraints.push({
      constraintId: `${rule.ruleId}:duration`,
      kind: "duration",
      value: ruleConstraint(rule, "duration")?.value,
      sourceRuleId: rule.ruleId
    });
    reasons.push("duration-restriction-applied");
  } else if (rule.type === "limit_value" || rule.effect === "restrict_value") {
    outcome = "value_restricted";
    constraints.push({
      constraintId: `${rule.ruleId}:value`,
      kind: "value",
      value: ruleConstraint(rule, "value")?.value,
      sourceRuleId: rule.ruleId
    });
    reasons.push("value-restriction-applied");
  } else if (rule.type === "limit_scope" || rule.effect === "restrict_scope") {
    outcome = "scope_restricted";
    requirementsForRule.push("scope_restriction");
    constraints.push({
      constraintId: `${rule.ruleId}:scope`,
      kind: "scope",
      value: ruleConstraint(rule, "scope")?.value ?? request.requestedScope,
      sourceRuleId: rule.ruleId
    });
    reasons.push("scope-restriction-applied");
  } else if (rule.type === "experimental_feature_required") {
    const feature = ruleConstraint(rule, "custom")?.value;
    if (
      typeof feature === "string"
      && !(request.actionContext.experimentalFeatures ?? []).includes(feature)
    ) {
      outcome = "unsupported";
    }
  } else if (rule.type === "allow_for_user_approval" || rule.effect === "allow_for_user_approval") {
    outcome = "allowed_for_user_approval";
    requirementsForRule.push("user_approval");
    reasons.push("user-approval-required");
  } else {
    outcome = "allowed_for_capability_activation_review";
    reasons.push("eligible-for-capability-activation-review");
  }

  return freezeRecord({
    ruleId: rule.ruleId,
    type: rule.type,
    effect: rule.effect,
    applicable: true,
    outcome,
    constraints,
    requirements: requirementsForRule,
    reasons
  });
}

const PRECEDENCE: readonly AuthoritativePolicyDecisionOutcome[] = Object.freeze([
  "denied",
  "requires_recovery_context",
  "requires_world_id_enrollment",
  "requires_production_authentication",
  "requires_stronger_trust",
  "requires_user_approval",
  "target_restricted",
  "value_restricted",
  "scope_restricted",
  "duration_restricted",
  "application_restricted",
  "session_state_ineligible",
  "unsupported",
  "allowed_for_user_approval",
  "allowed_for_capability_activation_review"
]);

function highestPrecedence(
  outcomes: readonly AuthoritativePolicyDecisionOutcome[]
): AuthoritativePolicyDecisionOutcome {
  for (const candidate of PRECEDENCE) {
    if (outcomes.includes(candidate)) return candidate;
  }
  return "allowed_for_capability_activation_review";
}

function correlationErrors(request: AuthoritativePolicyDecisionRequest): readonly string[] {
  const trust = request.authoritativeTrustDecision;
  const errors: string[] = [];
  if (trust.scope.ownerCommitment !== request.ownerCommitment) errors.push("owner mismatch");
  if (trust.scope.sessionId !== request.sessionId) errors.push("session mismatch");
  if (trust.scope.applicationId !== request.applicationId) errors.push("application mismatch");
  if (trust.scope.authenticationPurpose !== request.authenticationPurpose) {
    errors.push("purpose mismatch");
  }
  if (trust.scope.auditCorrelationId !== request.auditCorrelationId) errors.push("audit mismatch");
  if (!request.requestedAssurance.every((assurance) =>
    trust.scope.requestedAssurance.includes(assurance)
  )) {
    errors.push("assurance mismatch");
  }
  if (request.lifecycleSnapshot.sessionId !== request.sessionId) {
    errors.push("lifecycle session mismatch");
  }
  if (request.lifecycleSnapshot.state !== request.lifecycleState) {
    errors.push("lifecycle state mismatch");
  }
  if (
    request.capabilityRequest
    && (
      request.capabilityRequest.applicationId !== request.applicationId
      || request.capabilityRequest.capability !== request.capabilityName
      || request.capabilityRequest.requestId.trim().length === 0
    )
  ) {
    errors.push("capability request mismatch");
  }
  if (
    request.capabilityGrantDraft
    && (
      request.capabilityGrantDraft.applicationId !== request.applicationId
      || request.capabilityGrantDraft.capabilityName !== request.capabilityName
      || (
        request.capabilityGrantDraft.sessionId !== undefined
        && request.capabilityGrantDraft.sessionId !== request.sessionId
      )
    )
  ) {
    errors.push("capability draft mismatch");
  }
  if (
    request.intent
    && (
      request.intent.applicationId !== request.applicationId
      || request.intent.intentId.trim().length === 0
    )
  ) {
    errors.push("intent mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

function preflightErrors(request: AuthoritativePolicyDecisionRequest): readonly string[] {
  const errors: string[] = [];
  const trust = request.authoritativeTrustDecision;
  if (
    trust.status !== "trust_decision_created"
    || trust.outcome !== "trust_decision_created"
    || trust.trustDecisionCreated !== true
    || trust.capabilityGranted !== false
    || trust.authorizationCreated !== false
  ) {
    errors.push("trust decision ineligible");
  }
  if (expired(trust.validity.expiresAt) || expired(request.expiresAt)) {
    errors.push("expired");
  }
  if (expired(request.policySet.expiresAt)) errors.push("policy set expired");
  if (Date.parse(request.expiresAt) <= Date.parse(request.issuedAt)) {
    errors.push("request expiry must be after issue time");
  }
  if (request.lifecycleState !== "unlocked" && request.lifecycleState !== "recovery_mode") {
    errors.push("session state ineligible");
  }
  return Object.freeze([...new Set(errors)]);
}

function outcomeForErrors(errors: readonly string[]): AuthoritativePolicyDecisionOutcome {
  if (errors.some((error) => error.includes("trust"))) return "trust_decision_ineligible";
  if (errors.some((error) => error.includes("expired") || error.includes("expiry"))) return "expired";
  if (errors.some((error) => error.includes("session state"))) return "session_state_ineligible";
  if (errors.some((error) => error.includes("world id"))) return "requires_world_id_enrollment";
  if (errors.some((error) => error.includes("mismatch"))) return "correlation_mismatch";
  return "malformed";
}

function auditDraftForPolicy(input: {
  readonly request: AuthoritativePolicyDecisionRequest;
  readonly outcome: AuthoritativePolicyDecisionOutcome;
  readonly decision?: AuthoritativePolicyDecision;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.decision ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    summary: input.decision
      ? "Authoritative Security Policy Decision created for one bounded request; no capability, approval, authorization, or execution was created."
      : "Authoritative Security Policy Decision request rejected; no capability, approval, authorization, or execution was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authoritativePolicyDecisionId: input.decision?.authoritativePolicyDecisionId,
      authoritativeTrustDecisionId:
        input.request.authoritativeTrustDecision?.authoritativeTrustDecisionId,
      policySetId: input.request.policySet?.policySetId,
      policySetVersion: input.request.policySet?.version,
      applicationId: input.request.applicationId,
      capabilityName: input.request.capabilityName,
      actionType: input.request.actionType,
      targetReference: input.request.targetReference,
      outcome: input.outcome,
      requiresUserApproval: input.decision?.requiresUserApproval ?? false,
      eligibleForCapabilityActivationReview:
        input.decision?.eligibleForCapabilityActivationReview ?? false,
      effectiveDurationSeconds: input.decision?.effectiveDurationSeconds,
      effectiveValueLimit: input.decision?.effectiveValueLimit,
      effectiveTargetRestrictions: input.decision?.effectiveTargetRestrictions,
      capabilityGranted: false,
      userApprovalCollected: false,
      authorizationCreated: false,
      sessionKeyCreated: false,
      executionAllowed: false,
      proofExecuted: false,
      adapterExecuted: false,
      worldIdVerified: false,
      vaultAccessed: false,
      persistedAsAuthority: false,
      errors: input.errors ?? []
    }
  });
}

export function isAuthoritativePolicyDecisionStatus(
  value: unknown
): value is AuthoritativePolicyDecisionStatus {
  return STATUSES.has(value as AuthoritativePolicyDecisionStatus);
}

export function isAuthoritativePolicyDecisionOutcome(
  value: unknown
): value is AuthoritativePolicyDecisionOutcome {
  return OUTCOMES.has(value as AuthoritativePolicyDecisionOutcome);
}

export function validateAuthoritativePolicyDecisionRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["authoritative policy decision request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  const trustValidation =
    validateAuthoritativeTrustDecisionShape(request.authoritativeTrustDecision);
  if (!trustValidation.valid) {
    errors.push(...trustValidation.errors.map((error) => `authoritativeTrustDecision.${error}`));
  }
  if (request.capabilityRequest === undefined
    && request.capabilityGrantDraft === undefined
    && request.intent === undefined) {
    errors.push("capabilityRequest, capabilityGrantDraft, or intent is required");
  }
  if (request.capabilityGrantDraft !== undefined) {
    const result = validateCapabilityGrantDraftShape(request.capabilityGrantDraft);
    errors.push(...result.errors.map((error) => `capabilityGrantDraft.${error}`));
  }
  const policyValidation = validateAuthoritativePolicySet(request.policySet);
  errors.push(...policyValidation.errors);
  const lifecycleValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  errors.push(...lifecycleValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  if (!isNonEmptyString(request.sessionId)) errors.push("sessionId is required");
  if (!isNonEmptyString(request.ownerCommitment)) errors.push("ownerCommitment is required");
  if (!isNonEmptyString(request.applicationId)) errors.push("applicationId is required");
  if (!isNonEmptyString(request.capabilityName)) errors.push("capabilityName is required");
  if (!isRecord(request.actionContext)) errors.push("actionContext is required");
  if (!isNonEmptyString(request.actionType)) errors.push("actionType is required");
  if (!isNonEmptyString(request.authenticationPurpose)) {
    errors.push("authenticationPurpose is required");
  }
  if (!Array.isArray(request.requestedAssurance) || request.requestedAssurance.length === 0) {
    errors.push("requestedAssurance is required");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  errors.push(...validateNoSensitiveMetadataKeys(request.actionContext).errors);
  return validation([...new Set(errors)]);
}

export function validateAuthoritativePolicyDecisionShape(
  decision: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(decision)) return validation(["authoritative policy decision must be an object"]);
  if (!isNonEmptyString(decision.authoritativePolicyDecisionId)) {
    errors.push("authoritativePolicyDecisionId is required");
  }
  if (decision.status !== "policy_decision_created") {
    errors.push("status must be policy_decision_created");
  }
  if (!isAuthoritativePolicyDecisionOutcome(decision.outcome)) errors.push("outcome is invalid");
  if (!isRecord(decision.scope)) errors.push("scope is required");
  if (!isRecord(decision.binding)) errors.push("binding is required");
  if (!isRecord(decision.evidence)) errors.push("evidence is required");
  if (!Array.isArray(decision.ruleResults)) errors.push("ruleResults must be an array");
  if (!Array.isArray(decision.constraints)) errors.push("constraints must be an array");
  for (const field of ["policyDecisionCreated", "trustDecisionAccepted", "rulesEvaluated"]) {
    if (decision[field] !== true) errors.push(`${field} must be true`);
  }
  for (const field of [
    "capabilityGranted",
    "userApprovalCollected",
    "authorizationCreated",
    "sessionKeyCreated",
    "executionAllowed",
    "proofExecuted",
    "adapterExecuted",
    "worldIdVerified",
    "vaultAccessed",
    "persistedAsAuthority",
    "persisted"
  ]) {
    if (decision[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function createAuthoritativePolicyDecision(
  request: AuthoritativePolicyDecisionRequest,
  consumptionStore?: EphemeralPolicyDecisionEvidenceConsumptionStore,
  decisionStore?: AuthoritativePolicyDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativePolicyDecisionResult {
  return evaluateAuthoritativeSecurityPolicy(
    request,
    consumptionStore,
    decisionStore,
    auditDraftCollector
  );
}

export function evaluateAuthoritativeSecurityPolicy(
  request: AuthoritativePolicyDecisionRequest,
  consumptionStore?: EphemeralPolicyDecisionEvidenceConsumptionStore,
  decisionStore?: AuthoritativePolicyDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativePolicyDecisionResult {
  const validationResult = validateAuthoritativePolicyDecisionRequest(request);
  if (!validationResult.valid) {
    const auditEventDraft = auditDraftForPolicy({
      request,
      outcome: "malformed",
      errors: validationResult.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(policyError(
      "AUTHORITATIVE_POLICY_DECISION_MALFORMED",
      validationResult.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const preflight = [...correlationErrors(request), ...preflightErrors(request)];
  if (preflight.length > 0) {
    const outcome = outcomeForErrors(preflight);
    const auditEventDraft = auditDraftForPolicy({ request, outcome, errors: preflight });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(policyError(
      "AUTHORITATIVE_POLICY_DECISION_REJECTED",
      preflight
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const policyEvidenceChainId = createAuditCorrelationId([
    request.authoritativeTrustDecision.authoritativeTrustDecisionId,
    request.capabilityRequest?.requestId ?? request.capabilityGrantDraft?.capabilityRequestId ?? "",
    request.intent?.intentId ?? "",
    request.policySet.policySetId,
    request.policySet.version,
    request.sessionId,
    request.applicationId,
    request.capabilityName,
    request.actionType,
    request.targetReference ?? "",
    request.auditCorrelationId,
    "authoritative-policy-decision-evidence-chain"
  ]);
  if (consumptionStore?.has(policyEvidenceChainId)) {
    const auditEventDraft = auditDraftForPolicy({
      request,
      outcome: "expired",
      errors: ["policy evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(policyError(
      "AUTHORITATIVE_POLICY_DECISION_REPLAYED",
      ["policy evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const ruleResults: AuthoritativePolicyDecisionRuleResult[] = [];
  const outcomes: AuthoritativePolicyDecisionOutcome[] = [];
  const constraints: AuthoritativePolicyDecisionConstraint[] = [];
  const reasons: AuthoritativePolicyDecisionReason[] = [
    "authoritative-trust-decision-valid",
    "explicit-policy-set-valid",
    "explicit-request-context-valid",
    "security-policy-authority-only",
    "no-capability-grant",
    "no-user-approval",
    "no-authorization",
    "no-execution"
  ];
  for (const rule of request.policySet.rules) {
    if (!ruleApplies(rule, request)) {
      ruleResults.push(freezeRecord({
        ruleId: rule.ruleId,
        type: rule.type,
        effect: rule.effect,
        applicable: false,
        constraints: [],
        requirements: [],
        reasons: ["policy-rule-not-applicable"]
      }));
      continue;
    }
    const evaluated = resultForRule(rule, request);
    ruleResults.push(evaluated);
    if (evaluated.outcome) outcomes.push(evaluated.outcome);
    constraints.push(...evaluated.constraints);
    for (const reason of evaluated.reasons) addUnique(reasons, reason);
  }
  if (
    (request.canonicalPhilActivationContext === true
      || request.actionContext.canonicalPhilActivation === true
      || request.authenticationPurpose === "canonical_phil_activation")
    && !outcomes.includes("requires_world_id_enrollment")
  ) {
    outcomes.push("requires_world_id_enrollment");
    constraints.push({
      constraintId: "canonical-activation:world-id",
      kind: "world_id",
      value: "real_world_id_enrollment_required"
    });
    addUnique(reasons, "world-id-enrollment-required");
  }
  if (outcomes.length === 0) outcomes.push("allowed_for_capability_activation_review");
  const outcome = highestPrecedence(outcomes);
  if (outcome === "denied") addUnique(reasons, "deny-precedence");

  const effectiveScopeConstraint = constraints.find((constraint) => constraint.kind === "scope");
  const effectiveDurationConstraint =
    constraints.find((constraint) => constraint.kind === "duration");
  const effectiveValueConstraint = constraints.find((constraint) => constraint.kind === "value");
  const targetRestrictions = constraints
    .filter((constraint) => constraint.kind === "target")
    .map((constraint) => String(constraint.value ?? request.targetReference ?? "restricted-target"));
  const decisionId = createAuditCorrelationId([
    policyEvidenceChainId,
    request.issuedAt,
    request.expiresAt,
    "authoritative-policy-decision"
  ]);
  const decisionBase = {
    authoritativePolicyDecisionId: decisionId,
    requestId: request.requestId,
    status: "policy_decision_created" as const,
    outcome,
    scope: {
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      ownerCommitment: request.ownerCommitment,
      capabilityName: request.capabilityName,
      actionType: request.actionType,
      targetReference: request.targetReference,
      authenticationPurpose: request.authenticationPurpose,
      requestedAssurance: Object.freeze([...request.requestedAssurance]),
      requestedScope: request.requestedScope,
      requestedDurationSeconds: request.requestedDurationSeconds,
      requestedValue: request.requestedValue,
      chainId: request.chainId,
      network: request.network,
      auditCorrelationId: request.auditCorrelationId
    },
    binding: {
      authoritativeTrustDecisionId:
        request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      capabilityRequestId: request.capabilityRequest?.requestId,
      capabilityGrantDraftId: request.capabilityGrantDraft?.capabilityGrantDraftId,
      intentId: request.intent?.intentId,
      policySetId: request.policySet.policySetId,
      policySetVersion: request.policySet.version,
      sessionLifecycleId: request.lifecycleSnapshot.lifecycleId,
      sessionLifecycleState: request.lifecycleState,
      validityWindowId: createAuditCorrelationId([
        request.sessionId,
        request.capabilityName,
        request.actionType,
        request.issuedAt,
        request.expiresAt,
        "policy-decision-validity-window"
      ]),
      reusableAcrossTrustDecisions: false as const,
      reusableAcrossSessions: false as const,
      reusableAcrossApplications: false as const,
      reusableAcrossCapabilities: false as const,
      reusableAcrossActions: false as const,
      reusableAcrossTargets: false as const,
      reusableAcrossTimeWindows: false as const
    },
    evidence: {
      trustDecisionAccepted: true as const,
      trustDecisionId: request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      policySetId: request.policySet.policySetId,
      policySetVersion: request.policySet.version,
      rulesEvaluated: true as const,
      ruleCount: request.policySet.rules.length,
      applicableRuleCount: ruleResults.filter((result) => result.applicable).length,
      rawTrustEvidenceIncluded: false as const,
      rawWebAuthnPayloadIncluded: false as const,
      credentialRecordIncluded: false as const,
      vaultHandleIncluded: false as const,
      adapterPayloadIncluded: false as const,
      worldIdProofIncluded: false as const
    },
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false,
      invalidatedBySessionLock: true as const,
      invalidatedBySessionClose: true as const,
      invalidatedByTrustDecisionExpiry: true as const,
      invalidatedByPolicySetVersionChange: true as const,
      invalidatedByRequestExpiry: true as const
    },
    ruleResults: Object.freeze(ruleResults),
    constraints: Object.freeze(constraints),
    requirements: requirements(),
    limitations: LIMITATIONS,
    reasons: Object.freeze(reasons),
    effectiveScope: (effectiveScopeConstraint?.value ?? request.requestedScope) as CapabilityScope | undefined,
    effectiveDurationSeconds:
      typeof effectiveDurationConstraint?.value === "number"
        ? effectiveDurationConstraint.value
        : request.requestedDurationSeconds,
    effectiveValueLimit:
      effectiveValueConstraint?.value !== undefined
        ? String(effectiveValueConstraint.value)
        : undefined,
    effectiveTargetRestrictions: Object.freeze(targetRestrictions),
    requiresUserApproval:
      outcome === "requires_user_approval" || outcome === "allowed_for_user_approval",
    requiresStrongerTrust: outcome === "requires_stronger_trust",
    requiresProductionAuthentication: outcome === "requires_production_authentication",
    requiresWorldIdEnrollment: outcome === "requires_world_id_enrollment",
    requiresRecoveryContext: outcome === "requires_recovery_context",
    eligibleForCapabilityActivationReview:
      outcome === "allowed_for_capability_activation_review",
    policyDecisionCreated: true as const,
    trustDecisionAccepted: true as const,
    rulesEvaluated: true as const,
    capabilityGranted: false as const,
    userApprovalCollected: false as const,
    authorizationCreated: false as const,
    sessionKeyCreated: false as const,
    executionAllowed: false as const,
    proofExecuted: false as const,
    adapterExecuted: false as const,
    worldIdVerified: false as const,
    vaultAccessed: false as const,
    persistedAsAuthority: false as const,
    persisted: false as const
  };
  const decisionWithoutAudit = freezeRecord(decisionBase) as AuthoritativePolicyDecision;
  const shapeValidation = validateAuthoritativePolicyDecisionShape(decisionWithoutAudit);
  if (!shapeValidation.valid) {
    const auditEventDraft = auditDraftForPolicy({
      request,
      outcome: "malformed",
      errors: shapeValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(policyError(
      "AUTHORITATIVE_POLICY_DECISION_SHAPE_INVALID",
      shapeValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    policyEvidenceChainId,
    authoritativePolicyDecisionId: decisionId,
    authoritativeTrustDecisionId:
      request.authoritativeTrustDecision.authoritativeTrustDecisionId,
    policySetId: request.policySet.policySetId,
    policySetVersion: request.policySet.version,
    sessionId: request.sessionId,
    applicationId: request.applicationId,
    capabilityName: request.capabilityName,
    actionType: request.actionType,
    targetReference: request.targetReference,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const auditEventDraft = auditDraftForPolicy({
      request,
      outcome: "expired",
      errors: ["policy evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(policyError(
      "AUTHORITATIVE_POLICY_DECISION_REPLAYED",
      ["policy evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = auditDraftForPolicy({
    request,
    outcome,
    decision: decisionWithoutAudit
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const decisionWithAudit = freezeRecord({
    ...decisionBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as AuthoritativePolicyDecision;
  const collectionResult = decisionStore?.addDecision(decisionWithAudit);
  return runtimeOk(freezeRecord({
    ...decisionWithAudit,
    collectionResult
  }) as AuthoritativePolicyDecision);
}

export function createEphemeralPolicyDecisionEvidenceConsumptionStore():
  EphemeralPolicyDecisionEvidenceConsumptionStore {
  const records = new Map<string, AuthoritativePolicyDecisionConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.policyEvidenceChainId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.policyEvidenceChainId),
          records: all(),
          reason: "authoritative policy evidence chain was already consumed"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.policyEvidenceChainId, frozen);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(policyEvidenceChainId) {
      return records.has(policyEvidenceChainId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

export function createInMemoryAuthoritativePolicyDecisionStore(
  options: InMemoryAuthoritativePolicyDecisionStoreOptions = {}
): AuthoritativePolicyDecisionStore {
  const maxDecisionCount = Math.max(1, options.maxDecisionCount ?? 100);
  const decisions = new Map<string, AuthoritativePolicyDecision>();
  const snapshot = (): AuthoritativePolicyDecisionCollection => freezeRecord({
    decisions: Array.from(decisions.values()),
    count: decisions.size,
    maxDecisionCount
  });
  const result = (
    status: AuthoritativePolicyDecisionCollectionStatus,
    extra: Omit<AuthoritativePolicyDecisionCollectionResult, "status" | "collection"> = {}
  ): AuthoritativePolicyDecisionCollectionResult => freezeRecord({
    status,
    collection: snapshot(),
    ...extra
  });
  return {
    addDecision(decision) {
      const validationResult = validateAuthoritativePolicyDecisionShape(decision);
      if (!validationResult.valid) return result("rejected_invalid", { errors: validationResult.errors });
      if (decisions.has(decision.authoritativePolicyDecisionId)) {
        return result("rejected_duplicate", {
          decision,
          reason: "authoritative policy decision ID already exists"
        });
      }
      let evictedDecisions: AuthoritativePolicyDecision[] = [];
      if (decisions.size >= maxDecisionCount) {
        const oldestKey = decisions.keys().next().value;
        if (typeof oldestKey === "string") {
          const evicted = decisions.get(oldestKey);
          decisions.delete(oldestKey);
          if (evicted) evictedDecisions = [evicted];
        }
      }
      const frozen = freezeRecord(decision);
      decisions.set(frozen.authoritativePolicyDecisionId, frozen);
      return result(evictedDecisions.length > 0 ? "evicted_oldest" : "collected", {
        decision: frozen,
        evictedDecisions
      });
    },
    removeDecision(decisionId) {
      const removedDecision = decisions.get(decisionId);
      if (!removedDecision) return result("not_found", { reason: "decision not found" });
      decisions.delete(decisionId);
      return result("removed", { removedDecision });
    },
    clear() {
      decisions.clear();
      return result("cleared");
    },
    count() {
      return decisions.size;
    },
    getById(decisionId) {
      const decision = decisions.get(decisionId);
      return decision ? freezeRecord(decision) : undefined;
    },
    getAll() {
      return snapshot().decisions;
    },
    getUnexpired(now = new Date().toISOString()) {
      const cutoff = Date.parse(now);
      return freezeRecord(
        Array.from(decisions.values()).filter((decision) =>
          Date.parse(decision.validity.expiresAt) > cutoff
        )
      );
    }
  };
}

export function createFixturePolicyDecisionConsumer(): PolicyDecisionConsumer {
  return {
    acceptPolicyDecisionShape(request) {
      const result = validateAuthoritativePolicyDecisionShape(
        request.authoritativePolicyDecision
      );
      return freezeRecord({
        status: result.valid ? "accepted_shape" as const : "rejected_shape" as const,
        authoritativePolicyDecisionId: result.valid
          ? request.authoritativePolicyDecision.authoritativePolicyDecisionId
          : undefined,
        errors: result.errors,
        capabilityGranted: false as const,
        userApprovalCollected: false as const,
        authorizationCreated: false as const
      });
    }
  };
}
