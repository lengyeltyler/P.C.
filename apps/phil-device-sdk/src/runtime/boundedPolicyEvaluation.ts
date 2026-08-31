import {
  validateCapabilityGrantDraftShape,
  type CapabilityGrantDraft
} from "./capabilityDrafts.ts";
import {
  validateBoundedTrustEvaluationResultShape,
  type BoundedTrustEvaluationContext,
  type BoundedTrustEvaluationResult
} from "./boundedTrustEvaluation.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  PolicyMode,
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContextStatus
} from "./types.ts";

export type RuntimePolicyRuleId = string;

export type RuntimePolicyRuleType =
  | "require_trust_level"
  | "require_production_possession_verification"
  | "require_user_approval"
  | "require_world_id_enrollment"
  | "deny_capability"
  | "allow_capability_for_review"
  | "limit_scope"
  | "limit_duration"
  | "limit_value"
  | "restrict_application"
  | "restrict_session_state"
  | "recovery_only"
  | "experimental_feature_required";

export type RuntimePolicyRuleEffect =
  | "allow_for_further_review"
  | "deny"
  | "require_stronger_trust"
  | "require_user_approval"
  | "require_production_verification"
  | "require_world_id_enrollment"
  | "restrict_scope"
  | "unsupported";

export interface RuntimePolicyRuleScope {
  readonly applicationIds?: readonly ApplicationId[];
  readonly capabilityNames?: readonly CapabilityName[];
  readonly sessionIds?: readonly string[];
  readonly policyModes?: readonly PolicyMode[];
  readonly evaluationContexts?: readonly BoundedTrustEvaluationContext[];
  readonly sessionStatuses?: readonly UserSessionContextStatus[];
  readonly recoveryOnly?: boolean;
}

export interface RuntimePolicyConstraint {
  readonly constraintId: string;
  readonly kind:
    | "scope"
    | "duration"
    | "value"
    | "application"
    | "session_state"
    | "trust"
    | "world_id"
    | "custom";
  readonly value?: unknown;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimePolicyRequirement {
  readonly requirementId: string;
  readonly kind:
    | "stronger_trust"
    | "production_possession_verification"
    | "user_approval"
    | "world_id_enrollment"
    | "recovery_context"
    | "scope_restriction"
    | "duration_restriction";
  readonly description?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimePolicyRule {
  readonly ruleId: RuntimePolicyRuleId;
  readonly type: RuntimePolicyRuleType;
  readonly effect: RuntimePolicyRuleEffect;
  readonly scope?: RuntimePolicyRuleScope;
  readonly constraints?: readonly RuntimePolicyConstraint[];
  readonly requirements?: readonly RuntimePolicyRequirement[];
  readonly reason?: string;
  readonly enabled?: boolean;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimePolicySet {
  readonly policySetId: string;
  readonly version?: string;
  readonly mode?: PolicyMode;
  readonly rules: readonly RuntimePolicyRule[];
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimePolicyActionContext {
  readonly actionId?: string;
  readonly actionKind?: string;
  readonly requestedValue?: string;
  readonly requestedDurationSeconds?: number;
  readonly requestedScope?: CapabilityScope;
  readonly canonicalPhilActivation?: boolean;
  readonly humanUniquenessProviderKind?: "world_id" | "development_fixture" | "unsupported";
  readonly experimentalFeatures?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimePolicyContext {
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly sessionStatus?: UserSessionContextStatus;
  readonly policyMode?: PolicyMode;
  readonly evaluationContext?: BoundedTrustEvaluationContext;
  readonly requestedAt?: string;
  readonly action?: RuntimePolicyActionContext;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type BoundedPolicyEvaluationStatus =
  | "evaluated"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "expired";

export type BoundedPolicyEvaluationOutcome =
  | "eligible_for_user_approval"
  | "eligible_for_future_authorization"
  | "denied_by_policy"
  | "requires_stronger_trust"
  | "requires_production_possession_verification"
  | "requires_world_id_enrollment"
  | "requires_recovery_context"
  | "scope_restricted"
  | "duration_restricted"
  | "application_restricted"
  | "session_state_ineligible"
  | "malformed"
  | "unsupported"
  | "expired";

export type BoundedPolicyEvaluationReason =
  | "capability-draft-valid"
  | "bounded-trust-result-valid"
  | "policy-set-valid"
  | "policy-rule-applicable"
  | "policy-rule-not-applicable"
  | "deny-precedence"
  | "recovery-context-required"
  | "world-id-enrollment-required"
  | "production-possession-verification-required"
  | "stronger-trust-required"
  | "user-approval-required"
  | "scope-restriction-required"
  | "duration-restriction-required"
  | "application-restricted"
  | "session-state-ineligible"
  | "eligible-for-future-review"
  | "trust-limitations-preserved"
  | "non-authoritative-result"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type BoundedPolicyResolutionRequirement =
  | "stronger_trust"
  | "production_possession_verification"
  | "user_approval"
  | "world_id_enrollment"
  | "recovery_context"
  | "scope_restriction"
  | "duration_restriction"
  | "future_authorization";

export type BoundedPolicyLimitation =
  | "no_capability_grant"
  | "no_user_approval"
  | "no_authorization"
  | "no_execution"
  | "no_production_authentication"
  | "no_world_id_verification"
  | "no_vault_access"
  | "explicit_policy_rules_only"
  | "trust_result_non_authoritative";

export interface BoundedPolicyRuleEvaluation {
  readonly ruleId: RuntimePolicyRuleId;
  readonly type: RuntimePolicyRuleType;
  readonly effect: RuntimePolicyRuleEffect;
  readonly applicable: boolean;
  readonly outcome?: BoundedPolicyEvaluationOutcome;
  readonly requirements: readonly BoundedPolicyResolutionRequirement[];
  readonly reasons: readonly BoundedPolicyEvaluationReason[];
}

export interface BoundedPolicyRequirementSummary {
  readonly requiresStrongerTrust: boolean;
  readonly requiresProductionPossessionVerification: boolean;
  readonly requiresUserApproval: boolean;
  readonly requiresWorldIdEnrollment: boolean;
  readonly requiresRecoveryContext: boolean;
  readonly requiresScopeRestriction: boolean;
  readonly requiresDurationRestriction: boolean;
}

export interface BoundedPolicyEvaluationRequest {
  readonly requestId: string;
  readonly capabilityGrantDraft: CapabilityGrantDraft;
  readonly boundedTrustEvaluationResult: BoundedTrustEvaluationResult;
  readonly policySet: RuntimePolicySet;
  readonly context: RuntimePolicyContext;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly capabilityName?: CapabilityName;
  readonly requestedScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly actionContext?: RuntimePolicyActionContext;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface BoundedPolicyEvaluationResult {
  readonly boundedPolicyEvaluationResultId: string;
  readonly requestId: string;
  readonly capabilityGrantDraftId: string;
  readonly boundedTrustEvaluationResultId: string;
  readonly policySetId: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly capabilityName: CapabilityName;
  readonly status: BoundedPolicyEvaluationStatus;
  readonly outcome: BoundedPolicyEvaluationOutcome;
  readonly ruleEvaluations: readonly BoundedPolicyRuleEvaluation[];
  readonly requirementSummary: BoundedPolicyRequirementSummary;
  readonly resolutionRequirements: readonly BoundedPolicyResolutionRequirement[];
  readonly limitations: readonly BoundedPolicyLimitation[];
  readonly reasons: readonly BoundedPolicyEvaluationReason[];
  readonly evaluatedAt: string;
  readonly auditCorrelationId: string;
  readonly eligibleForUserApproval: boolean;
  readonly eligibleForFutureAuthorization: boolean;
  readonly policyRulesLoadedFromStorage: false;
  readonly providesPolicyDecision: false;
  readonly grantsAuthority: false;
  readonly createsCapabilityGrant: false;
  readonly createsAuthorizationPackage: false;
  readonly requestsUserApproval: false;
  readonly productionAuthenticationPerformed: false;
  readonly worldIdVerified: false;
  readonly persisted: false;
}

export type BoundedPolicyEvaluationRuntimeResult =
  RuntimeResult<BoundedPolicyEvaluationResult>;

export type BoundedPolicyEvaluationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface BoundedPolicyEvaluationFilter {
  readonly boundedPolicyEvaluationResultId?: string;
  readonly requestId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly boundedTrustEvaluationResultId?: string;
  readonly policySetId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly capabilityName?: CapabilityName;
  readonly status?: BoundedPolicyEvaluationStatus;
  readonly outcome?: BoundedPolicyEvaluationOutcome;
  readonly eligibleForUserApproval?: boolean;
  readonly eligibleForFutureAuthorization?: boolean;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface BoundedPolicyEvaluationQuery {
  readonly filter?: BoundedPolicyEvaluationFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface BoundedPolicyEvaluationCollection {
  readonly results: readonly BoundedPolicyEvaluationResult[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface BoundedPolicyEvaluationCollectionResult {
  readonly status: BoundedPolicyEvaluationCollectionStatus;
  readonly result?: BoundedPolicyEvaluationResult;
  readonly removedResult?: BoundedPolicyEvaluationResult;
  readonly evictedResults?: readonly BoundedPolicyEvaluationResult[];
  readonly collection: BoundedPolicyEvaluationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface BoundedPolicyEvaluationResultCollector {
  addResult(result: BoundedPolicyEvaluationResult): BoundedPolicyEvaluationCollectionResult;
  removeResult(boundedPolicyEvaluationResultId: string): BoundedPolicyEvaluationCollectionResult;
  clear(): BoundedPolicyEvaluationCollectionResult;
  count(): number;
  getById(boundedPolicyEvaluationResultId: string): BoundedPolicyEvaluationResult | undefined;
  getAll(): readonly BoundedPolicyEvaluationResult[];
  query(query: BoundedPolicyEvaluationQuery): readonly BoundedPolicyEvaluationResult[];
  filter(filter: BoundedPolicyEvaluationFilter): readonly BoundedPolicyEvaluationResult[];
}

export interface InMemoryBoundedPolicyEvaluationResultCollectorOptions {
  readonly maxResultCount?: number;
}

const POLICY_RULE_TYPES = new Set<RuntimePolicyRuleType>([
  "require_trust_level",
  "require_production_possession_verification",
  "require_user_approval",
  "require_world_id_enrollment",
  "deny_capability",
  "allow_capability_for_review",
  "limit_scope",
  "limit_duration",
  "limit_value",
  "restrict_application",
  "restrict_session_state",
  "recovery_only",
  "experimental_feature_required"
]);

const POLICY_RULE_EFFECTS = new Set<RuntimePolicyRuleEffect>([
  "allow_for_further_review",
  "deny",
  "require_stronger_trust",
  "require_user_approval",
  "require_production_verification",
  "require_world_id_enrollment",
  "restrict_scope",
  "unsupported"
]);

const POLICY_OUTCOMES = new Set<BoundedPolicyEvaluationOutcome>([
  "eligible_for_user_approval",
  "eligible_for_future_authorization",
  "denied_by_policy",
  "requires_stronger_trust",
  "requires_production_possession_verification",
  "requires_world_id_enrollment",
  "requires_recovery_context",
  "scope_restricted",
  "duration_restricted",
  "application_restricted",
  "session_state_ineligible",
  "malformed",
  "unsupported",
  "expired"
]);

const ACTIVE_AUTHORITY_OR_PRIVATE_FIELDS = new Set([
  "philsecret",
  "privatekey",
  "signingkey",
  "vaultkey",
  "rawvaultkey",
  "password",
  "passphrase",
  "seed",
  "seedphrase",
  "mnemonic",
  "recoverysecret",
  "approved",
  "authorized",
  "capabilitygrant",
  "authorizationpackage",
  "authoritytoken",
  "userapprovalresult",
  "executionallowed",
  "worldidverified",
  "productionauthentication"
]);

const POLICY_LIMITATIONS: readonly BoundedPolicyLimitation[] = Object.freeze([
  "no_capability_grant",
  "no_user_approval",
  "no_authorization",
  "no_execution",
  "no_production_authentication",
  "no_world_id_verification",
  "no_vault_access",
  "explicit_policy_rules_only",
  "trust_result_non_authoritative"
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

function isExpiredDate(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
}

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function findBlockedFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findBlockedFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) {
    return [];
  }
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (ACTIVE_AUTHORITY_OR_PRIVATE_FIELDS.has(normalizeFieldName(key)) && entry !== false) {
      findings.push(childPath);
    }
    findings.push(...findBlockedFields(entry, childPath));
  }
  return findings;
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) {
    return Object.freeze(value.map(freezeRecord)) as TValue;
  }
  if (isRecord(value)) {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)]))
    ) as TValue;
  }
  return value;
}

function secretValidationErrors(input: unknown): readonly string[] {
  return validateNoSensitiveMetadataKeys(input).errors.map(
    (error) => `secret-shaped metadata is not allowed: ${error}`
  );
}

// policySet -> rules -> rule -> constraints/requirements -> constraint/requirement -> value
// is 5 levels deep before any consumer-supplied content begins; this allows four more
// levels of legitimate nesting inside that unknown-typed content before failing closed.
const POLICY_SET_SENSITIVE_SCAN_MAX_DEPTH = 9;

function policySetSecretValidationErrors(policySet: unknown): readonly string[] {
  return validateNoSensitiveMetadataKeys(policySet, {
    maxDepth: POLICY_SET_SENSITIVE_SCAN_MAX_DEPTH
  }).errors.map(
    (error) => `secret-shaped metadata is not allowed: ${error}`
  );
}

function malformedBoundedPolicyEvaluationError(
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "BOUNDED_POLICY_EVALUATION_INVALID",
    message: "bounded policy evaluation request failed validation",
    boundary: "security-policy-engine",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isBoundedPolicyEvaluationOutcome(
  value: unknown
): value is BoundedPolicyEvaluationOutcome {
  return POLICY_OUTCOMES.has(value as BoundedPolicyEvaluationOutcome);
}

function validatePolicyRule(rule: unknown, index: number): readonly string[] {
  const errors: string[] = [];
  if (!isRecord(rule)) {
    return [`policySet.rules[${index}] must be an object`];
  }
  if (!isNonEmptyString(rule.ruleId)) {
    errors.push(`policySet.rules[${index}].ruleId is required`);
  }
  if (!POLICY_RULE_TYPES.has(rule.type as RuntimePolicyRuleType)) {
    errors.push(`policySet.rules[${index}].type is invalid`);
  }
  if (!POLICY_RULE_EFFECTS.has(rule.effect as RuntimePolicyRuleEffect)) {
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

export function validateRuntimePolicySet(policySet: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(policySet)) {
    return validation(["policySet must be an object"]);
  }
  if (!isNonEmptyString(policySet.policySetId)) {
    errors.push("policySet.policySetId is required");
  }
  if (!Array.isArray(policySet.rules)) {
    errors.push("policySet.rules must be an array");
  } else {
    policySet.rules.forEach((rule, index) => {
      errors.push(...validatePolicyRule(rule, index));
    });
  }
  if (policySet.createdAt !== undefined && !hasValidDateShape(policySet.createdAt)) {
    errors.push("policySet.createdAt must be a parseable date string");
  }
  if (policySet.expiresAt !== undefined && !hasValidDateShape(policySet.expiresAt)) {
    errors.push("policySet.expiresAt must be a parseable date string");
  }
  const blockedFields = findBlockedFields(policySet);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...policySetSecretValidationErrors(policySet));
  return validation(errors);
}

export function validateBoundedPolicyEvaluationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["bounded policy evaluation request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  const capabilityValidation = validateCapabilityGrantDraftShape(request.capabilityGrantDraft);
  if (!capabilityValidation.valid) {
    errors.push(...capabilityValidation.errors.map((error) => `capabilityGrantDraft.${error}`));
  }
  const trustValidation = validateBoundedTrustEvaluationResultShape(
    request.boundedTrustEvaluationResult
  );
  if (!trustValidation.valid) {
    errors.push(...trustValidation.errors.map((error) => `boundedTrustEvaluationResult.${error}`));
  }
  const policyValidation = validateRuntimePolicySet(request.policySet);
  if (!policyValidation.valid) {
    errors.push(...policyValidation.errors);
  }
  if (!isRecord(request.context)) {
    errors.push("context is required");
  } else if (!isNonEmptyString(request.context.applicationId)) {
    errors.push("context.applicationId is required");
  }
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (isRecord(request.capabilityGrantDraft) && isExpiredDate(request.capabilityGrantDraft.expiresAt as string | undefined)) {
    errors.push("capabilityGrantDraft is expired");
  }
  if (isRecord(request.policySet) && isExpiredDate(request.policySet.expiresAt as string | undefined)) {
    errors.push("policySet is expired");
  }
  if (isExpiredDate(request.expiresAt as string | undefined)) {
    errors.push("bounded policy evaluation request is expired");
  }
  if (
    isRecord(request.boundedTrustEvaluationResult)
    && (
      request.boundedTrustEvaluationResult.providesTrustDecision !== false
      || request.boundedTrustEvaluationResult.grantsAuthority !== false
      || request.boundedTrustEvaluationResult.worldIdEnrollmentVerified !== false
    )
  ) {
    errors.push("boundedTrustEvaluationResult must remain non-authoritative and must not claim World ID verification");
  }
  if (
    capabilityValidation.valid
    && trustValidation.valid
    && isRecord(request.context)
  ) {
    const capability = request.capabilityGrantDraft as CapabilityGrantDraft;
    const trust = request.boundedTrustEvaluationResult as BoundedTrustEvaluationResult;
    const applicationId = request.applicationId ?? request.context.applicationId;
    const sessionId = request.sessionId ?? request.context.sessionId;
    const capabilityName = request.capabilityName ?? capability.capabilityName;
    if (capability.capabilityGrantDraftId !== trust.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with boundedTrustEvaluationResult.capabilityGrantDraftId");
    }
    if (capability.applicationId !== trust.applicationId || applicationId !== capability.applicationId) {
      errors.push("applicationId must correlate across capability draft, trust result, and policy context");
    }
    if (
      sessionId !== undefined
      && capability.sessionId !== undefined
      && capability.sessionId !== sessionId
    ) {
      errors.push("sessionId must match capabilityGrantDraft.sessionId");
    }
    if (
      sessionId !== undefined
      && trust.sessionId !== undefined
      && trust.sessionId !== sessionId
    ) {
      errors.push("sessionId must match boundedTrustEvaluationResult.sessionId");
    }
    if (capabilityName !== capability.capabilityName) {
      errors.push("capabilityName must match capabilityGrantDraft.capabilityName");
    }
  }
  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(request.metadata));
  errors.push(...secretValidationErrors(isRecord(request.context) ? request.context.metadata : undefined));
  errors.push(...secretValidationErrors(isRecord(request.actionContext) ? request.actionContext.metadata : undefined));
  return validation(errors);
}

export function validateBoundedPolicyEvaluationResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) {
    return validation(["bounded policy evaluation result must be an object"]);
  }
  if (!isNonEmptyString(result.boundedPolicyEvaluationResultId)) {
    errors.push("boundedPolicyEvaluationResultId is required");
  }
  if (!isNonEmptyString(result.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(result.capabilityGrantDraftId)) {
    errors.push("capabilityGrantDraftId is required");
  }
  if (!isNonEmptyString(result.boundedTrustEvaluationResultId)) {
    errors.push("boundedTrustEvaluationResultId is required");
  }
  if (!isNonEmptyString(result.policySetId)) {
    errors.push("policySetId is required");
  }
  if (!isNonEmptyString(result.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isNonEmptyString(result.capabilityName)) {
    errors.push("capabilityName is required");
  }
  if (!isBoundedPolicyEvaluationOutcome(result.outcome)) {
    errors.push("outcome is invalid");
  }
  if (!Array.isArray(result.ruleEvaluations)) {
    errors.push("ruleEvaluations must be an array");
  }
  if (!Array.isArray(result.resolutionRequirements)) {
    errors.push("resolutionRequirements must be an array");
  }
  if (!Array.isArray(result.limitations)) {
    errors.push("limitations must be an array");
  }
  if (!Array.isArray(result.reasons)) {
    errors.push("reasons must be an array");
  }
  for (const [field, expected] of [
    ["policyRulesLoadedFromStorage", false],
    ["providesPolicyDecision", false],
    ["grantsAuthority", false],
    ["createsCapabilityGrant", false],
    ["createsAuthorizationPackage", false],
    ["requestsUserApproval", false],
    ["productionAuthenticationPerformed", false],
    ["worldIdVerified", false],
    ["persisted", false]
  ] as const) {
    if (result[field] !== expected) {
      errors.push(`${field} must be false`);
    }
  }
  if (typeof result.eligibleForUserApproval !== "boolean") {
    errors.push("eligibleForUserApproval must be boolean");
  }
  if (typeof result.eligibleForFutureAuthorization !== "boolean") {
    errors.push("eligibleForFutureAuthorization must be boolean");
  }
  if (!hasValidDateShape(result.evaluatedAt)) {
    errors.push("evaluatedAt must be a parseable date string");
  }
  if (!isNonEmptyString(result.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  const blockedFields = findBlockedFields(result);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(result));
  return validation(errors);
}

function addUnique<TValue extends string>(values: TValue[], value: TValue): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

function ruleApplies(
  rule: RuntimePolicyRule,
  request: BoundedPolicyEvaluationRequest
): boolean {
  if (rule.enabled === false || isExpiredDate(rule.expiresAt)) {
    return false;
  }
  const scope = rule.scope;
  if (!scope) {
    return true;
  }
  const capability = request.capabilityGrantDraft;
  const trust = request.boundedTrustEvaluationResult;
  const context = request.context;
  const actionContext = request.actionContext ?? context.action;
  if (scope.applicationIds !== undefined && !scope.applicationIds.includes(context.applicationId)) {
    return false;
  }
  if (scope.capabilityNames !== undefined && !scope.capabilityNames.includes(capability.capabilityName)) {
    return false;
  }
  if (
    scope.sessionIds !== undefined
    && (context.sessionId === undefined || !scope.sessionIds.includes(context.sessionId))
  ) {
    return false;
  }
  if (
    scope.policyModes !== undefined
    && (context.policyMode === undefined || !scope.policyModes.includes(context.policyMode))
  ) {
    return false;
  }
  if (
    scope.evaluationContexts !== undefined
    && !scope.evaluationContexts.includes(trust.evaluationContext)
  ) {
    return false;
  }
  if (
    scope.sessionStatuses !== undefined
    && (context.sessionStatus === undefined || !scope.sessionStatuses.includes(context.sessionStatus))
  ) {
    return false;
  }
  if (scope.recoveryOnly === true && trust.evaluationContext !== "recovery") {
    return false;
  }
  if (
    rule.type === "require_world_id_enrollment"
    && actionContext?.canonicalPhilActivation !== true
    && trust.evaluationContext !== "canonical_phil_activation"
  ) {
    return false;
  }
  return true;
}

function ruleOutcome(
  rule: RuntimePolicyRule,
  request: BoundedPolicyEvaluationRequest
): {
  readonly outcome: BoundedPolicyEvaluationOutcome;
  readonly requirements: readonly BoundedPolicyResolutionRequirement[];
  readonly reasons: readonly BoundedPolicyEvaluationReason[];
} {
  const trust = request.boundedTrustEvaluationResult;
  const context = request.context;
  const actionContext = request.actionContext ?? context.action;

  if (rule.type === "deny_capability" || rule.effect === "deny") {
    return {
      outcome: "denied_by_policy",
      requirements: [],
      reasons: ["deny-precedence"]
    };
  }
  if (rule.type === "recovery_only" && trust.evaluationContext !== "recovery") {
    return {
      outcome: "requires_recovery_context",
      requirements: ["recovery_context"],
      reasons: ["recovery-context-required"]
    };
  }
  if (
    rule.type === "require_world_id_enrollment"
    || rule.effect === "require_world_id_enrollment"
  ) {
    return {
      outcome: "requires_world_id_enrollment",
      requirements: ["world_id_enrollment"],
      reasons: ["world-id-enrollment-required"]
    };
  }
  if (
    rule.type === "require_production_possession_verification"
    || rule.effect === "require_production_verification"
  ) {
    if (
      trust.fixtureOnlyEvidence === true
      || trust.possessionVerifiedForProduction === false
      || actionContext?.humanUniquenessProviderKind === "development_fixture"
    ) {
      return {
        outcome: "requires_production_possession_verification",
        requirements: ["production_possession_verification"],
        reasons: ["production-possession-verification-required"]
      };
    }
  }
  if (
    rule.type === "require_trust_level"
    || rule.effect === "require_stronger_trust"
    || trust.eligibleForPolicyReview !== true
  ) {
    if (trust.eligibleForPolicyReview !== true || trust.providesTrustDecision !== false) {
      return {
        outcome: "requires_stronger_trust",
        requirements: ["stronger_trust"],
        reasons: ["stronger-trust-required"]
      };
    }
  }
  if (rule.type === "restrict_application") {
    return {
      outcome: "application_restricted",
      requirements: [],
      reasons: ["application-restricted"]
    };
  }
  if (rule.type === "restrict_session_state") {
    return {
      outcome: "session_state_ineligible",
      requirements: [],
      reasons: ["session-state-ineligible"]
    };
  }
  if (rule.type === "limit_duration") {
    return {
      outcome: "duration_restricted",
      requirements: ["duration_restriction"],
      reasons: ["duration-restriction-required"]
    };
  }
  if (rule.type === "limit_scope" || rule.type === "limit_value" || rule.effect === "restrict_scope") {
    return {
      outcome: "scope_restricted",
      requirements: ["scope_restriction"],
      reasons: ["scope-restriction-required"]
    };
  }
  if (rule.type === "require_user_approval" || rule.effect === "require_user_approval") {
    return {
      outcome: "eligible_for_user_approval",
      requirements: ["user_approval"],
      reasons: ["user-approval-required"]
    };
  }
  if (rule.type === "experimental_feature_required") {
    const feature = rule.constraints?.find((constraint) => constraint.kind === "custom")?.value;
    if (
      typeof feature === "string"
      && !(actionContext?.experimentalFeatures ?? []).includes(feature)
    ) {
      return {
        outcome: "unsupported",
        requirements: [],
        reasons: ["policy-rule-applicable"]
      };
    }
  }
  return {
    outcome: "eligible_for_future_authorization",
    requirements: ["future_authorization"],
    reasons: ["eligible-for-future-review"]
  };
}

const OUTCOME_PRECEDENCE: readonly BoundedPolicyEvaluationOutcome[] = Object.freeze([
  "denied_by_policy",
  "requires_recovery_context",
  "requires_world_id_enrollment",
  "requires_production_possession_verification",
  "requires_stronger_trust",
  "eligible_for_user_approval",
  "scope_restricted",
  "duration_restricted",
  "application_restricted",
  "session_state_ineligible",
  "unsupported",
  "eligible_for_future_authorization"
]);

function highestPrecedence(
  outcomes: readonly BoundedPolicyEvaluationOutcome[]
): BoundedPolicyEvaluationOutcome {
  for (const candidate of OUTCOME_PRECEDENCE) {
    if (outcomes.includes(candidate)) {
      return candidate;
    }
  }
  return "eligible_for_future_authorization";
}

function requirementSummary(
  requirements: readonly BoundedPolicyResolutionRequirement[]
): BoundedPolicyRequirementSummary {
  return Object.freeze({
    requiresStrongerTrust: requirements.includes("stronger_trust"),
    requiresProductionPossessionVerification:
      requirements.includes("production_possession_verification"),
    requiresUserApproval: requirements.includes("user_approval"),
    requiresWorldIdEnrollment: requirements.includes("world_id_enrollment"),
    requiresRecoveryContext: requirements.includes("recovery_context"),
    requiresScopeRestriction: requirements.includes("scope_restriction"),
    requiresDurationRestriction: requirements.includes("duration_restriction")
  });
}

export function evaluateBoundedRuntimePolicy(
  request: BoundedPolicyEvaluationRequest
): BoundedPolicyEvaluationRuntimeResult {
  const validationResult = validateBoundedPolicyEvaluationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedBoundedPolicyEvaluationError(validationResult.errors));
  }

  const ruleEvaluations: BoundedPolicyRuleEvaluation[] = [];
  const outcomes: BoundedPolicyEvaluationOutcome[] = [];
  const requirements: BoundedPolicyResolutionRequirement[] = [];
  const reasons: BoundedPolicyEvaluationReason[] = [
    "capability-draft-valid",
    "bounded-trust-result-valid",
    "policy-set-valid",
    "trust-limitations-preserved",
    "non-authoritative-result"
  ];

  if (request.boundedTrustEvaluationResult.eligibleForPolicyReview !== true) {
    if (
      request.boundedTrustEvaluationResult.lifecycleAssessment.credentialLifecycleStatus === "recovery-only"
      && request.boundedTrustEvaluationResult.evaluationContext !== "recovery"
    ) {
      outcomes.push("requires_recovery_context");
      addUnique(requirements, "recovery_context");
      addUnique(reasons, "recovery-context-required");
    } else {
      outcomes.push("requires_stronger_trust");
      addUnique(requirements, "stronger_trust");
      addUnique(reasons, "stronger-trust-required");
    }
  }

  for (const rule of request.policySet.rules) {
    const applicable = ruleApplies(rule, request);
    if (!applicable) {
      ruleEvaluations.push(Object.freeze({
        ruleId: rule.ruleId,
        type: rule.type,
        effect: rule.effect,
        applicable: false,
        requirements: Object.freeze([]),
        reasons: Object.freeze(["policy-rule-not-applicable"])
      }));
      continue;
    }
    const evaluated = ruleOutcome(rule, request);
    outcomes.push(evaluated.outcome);
    for (const requirement of evaluated.requirements) {
      addUnique(requirements, requirement);
    }
    for (const reason of evaluated.reasons) {
      addUnique(reasons, reason);
    }
    ruleEvaluations.push(Object.freeze({
      ruleId: rule.ruleId,
      type: rule.type,
      effect: rule.effect,
      applicable: true,
      outcome: evaluated.outcome,
      requirements: Object.freeze([...evaluated.requirements]),
      reasons: Object.freeze(["policy-rule-applicable", ...evaluated.reasons])
    }));
  }

  if (outcomes.length === 0) {
    outcomes.push("eligible_for_future_authorization");
    addUnique(requirements, "future_authorization");
    addUnique(reasons, "eligible-for-future-review");
  }

  const outcome = highestPrecedence(outcomes);
  if (outcome === "denied_by_policy") {
    addUnique(reasons, "deny-precedence");
  }
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.context.applicationId,
    request.context.sessionId ?? "",
    request.capabilityGrantDraft.capabilityGrantDraftId,
    request.boundedTrustEvaluationResult.boundedTrustEvaluationResultId,
    request.policySet.policySetId,
    "bounded-policy-evaluation"
  ]);
  const result: BoundedPolicyEvaluationResult = Object.freeze({
    boundedPolicyEvaluationResultId: `${auditCorrelationId}:bounded-policy-evaluation`,
    requestId: request.requestId,
    capabilityGrantDraftId: request.capabilityGrantDraft.capabilityGrantDraftId,
    boundedTrustEvaluationResultId:
      request.boundedTrustEvaluationResult.boundedTrustEvaluationResultId,
    policySetId: request.policySet.policySetId,
    applicationId: request.context.applicationId,
    sessionId: request.context.sessionId,
    capabilityName: request.capabilityGrantDraft.capabilityName,
    status: "evaluated",
    outcome,
    ruleEvaluations: Object.freeze(ruleEvaluations),
    requirementSummary: requirementSummary(requirements),
    resolutionRequirements: Object.freeze(requirements),
    limitations: POLICY_LIMITATIONS,
    reasons: Object.freeze(reasons),
    evaluatedAt: new Date().toISOString(),
    auditCorrelationId,
    eligibleForUserApproval: outcome === "eligible_for_user_approval",
    eligibleForFutureAuthorization: outcome === "eligible_for_future_authorization",
    policyRulesLoadedFromStorage: false,
    providesPolicyDecision: false,
    grantsAuthority: false,
    createsCapabilityGrant: false,
    createsAuthorizationPackage: false,
    requestsUserApproval: false,
    productionAuthenticationPerformed: false,
    worldIdVerified: false,
    persisted: false
  });

  return runtimeOk(result);
}

function emptyCollection(
  maxResultCount: number,
  results: readonly BoundedPolicyEvaluationResult[] = []
): BoundedPolicyEvaluationCollection {
  return Object.freeze({
    results: Object.freeze([...results]),
    count: results.length,
    maxResultCount
  });
}

function collectionResult(input: {
  readonly status: BoundedPolicyEvaluationCollectionStatus;
  readonly results: readonly BoundedPolicyEvaluationResult[];
  readonly maxResultCount: number;
  readonly result?: BoundedPolicyEvaluationResult;
  readonly removedResult?: BoundedPolicyEvaluationResult;
  readonly evictedResults?: readonly BoundedPolicyEvaluationResult[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): BoundedPolicyEvaluationCollectionResult {
  return Object.freeze({
    status: input.status,
    result: input.result,
    removedResult: input.removedResult,
    evictedResults: input.evictedResults,
    collection: emptyCollection(input.maxResultCount, input.results),
    errors: input.errors,
    reason: input.reason
  });
}

function matchesFilter(
  result: BoundedPolicyEvaluationResult,
  filter: BoundedPolicyEvaluationFilter
): boolean {
  if (filter.boundedPolicyEvaluationResultId !== undefined && result.boundedPolicyEvaluationResultId !== filter.boundedPolicyEvaluationResultId) return false;
  if (filter.requestId !== undefined && result.requestId !== filter.requestId) return false;
  if (filter.capabilityGrantDraftId !== undefined && result.capabilityGrantDraftId !== filter.capabilityGrantDraftId) return false;
  if (filter.boundedTrustEvaluationResultId !== undefined && result.boundedTrustEvaluationResultId !== filter.boundedTrustEvaluationResultId) return false;
  if (filter.policySetId !== undefined && result.policySetId !== filter.policySetId) return false;
  if (filter.applicationId !== undefined && result.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && result.sessionId !== filter.sessionId) return false;
  if (filter.capabilityName !== undefined && result.capabilityName !== filter.capabilityName) return false;
  if (filter.status !== undefined && result.status !== filter.status) return false;
  if (filter.outcome !== undefined && result.outcome !== filter.outcome) return false;
  if (filter.eligibleForUserApproval !== undefined && result.eligibleForUserApproval !== filter.eligibleForUserApproval) return false;
  if (filter.eligibleForFutureAuthorization !== undefined && result.eligibleForFutureAuthorization !== filter.eligibleForFutureAuthorization) return false;
  if (filter.auditCorrelationId !== undefined && result.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(result.evaluatedAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(result.evaluatedAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryBoundedPolicyEvaluationResultCollector(
  options: InMemoryBoundedPolicyEvaluationResultCollectorOptions = {}
): BoundedPolicyEvaluationResultCollector {
  const maxResultCount = Math.max(1, Math.floor(options.maxResultCount ?? 100));
  const results: BoundedPolicyEvaluationResult[] = [];

  return Object.freeze({
    addResult(result: BoundedPolicyEvaluationResult) {
      const validationResult = validateBoundedPolicyEvaluationResultShape(result);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          results,
          maxResultCount,
          errors: validationResult.errors
        });
      }
      if (results.some((entry) => entry.boundedPolicyEvaluationResultId === result.boundedPolicyEvaluationResultId)) {
        return collectionResult({
          status: "rejected_duplicate",
          results,
          maxResultCount,
          result,
          reason: "bounded policy evaluation result ID already exists"
        });
      }
      const evictedResults: BoundedPolicyEvaluationResult[] = [];
      if (results.length >= maxResultCount) {
        const evicted = results.shift();
        if (evicted) {
          evictedResults.push(evicted);
        }
      }
      const frozenResult = freezeRecord(result);
      results.push(frozenResult);
      return collectionResult({
        status: evictedResults.length > 0 ? "evicted_oldest" : "collected",
        results,
        maxResultCount,
        result: frozenResult,
        evictedResults: evictedResults.length > 0 ? Object.freeze(evictedResults) : undefined
      });
    },
    removeResult(boundedPolicyEvaluationResultId: string) {
      const index = results.findIndex(
        (entry) => entry.boundedPolicyEvaluationResultId === boundedPolicyEvaluationResultId
      );
      if (index === -1) {
        return collectionResult({
          status: "not_found",
          results,
          maxResultCount
        });
      }
      const [removedResult] = results.splice(index, 1);
      return collectionResult({
        status: "removed",
        results,
        maxResultCount,
        removedResult
      });
    },
    clear() {
      results.splice(0, results.length);
      return collectionResult({
        status: "cleared",
        results,
        maxResultCount
      });
    },
    count() {
      return results.length;
    },
    getById(boundedPolicyEvaluationResultId: string) {
      return results.find(
        (entry) => entry.boundedPolicyEvaluationResultId === boundedPolicyEvaluationResultId
      );
    },
    getAll() {
      return Object.freeze([...results]);
    },
    query(query: BoundedPolicyEvaluationQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? results
        : results.filter((result) => matchesFilter(result, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: BoundedPolicyEvaluationFilter) {
      return Object.freeze(results.filter((result) => matchesFilter(result, filter)));
    }
  });
}
