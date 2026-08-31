import {
  type BoundedPolicyEvaluationResult,
  validateBoundedPolicyEvaluationResultShape
} from "./boundedPolicyEvaluation.ts";
import {
  type BoundedTrustEvaluationResult,
  validateBoundedTrustEvaluationResultShape
} from "./boundedTrustEvaluation.ts";
import {
  type CapabilityGrantDraft,
  validateCapabilityGrantDraftShape
} from "./capabilityDrafts.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type UserApprovalRequestDraftStatus =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_user_presentation"
  | "pending_user_decision"
  | "expired";

export type UserApprovalRequestDraftOutcome = UserApprovalRequestDraftStatus;

export type UserApprovalRequestDraftReason =
  | "capability-draft-valid"
  | "bounded-trust-result-valid"
  | "bounded-policy-result-valid"
  | "policy-eligible-for-user-approval"
  | "policy-eligible-for-future-authorization"
  | "policy-restrictions-preserved"
  | "trust-limitations-preserved"
  | "fixture-only-evidence-disclosed"
  | "no-user-decision-collected"
  | "non-authoritative-draft"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type UserApprovalRequestDraftSurface =
  | "desktop"
  | "mobile"
  | "browser_extension"
  | "hardware_confirmation"
  | "recovery_surface"
  | "developer_fixture"
  | "unsupported";

export type UserApprovalRequestDraftRequirement =
  | "present_to_user"
  | "collect_future_user_decision"
  | "preserve_policy_restrictions"
  | "preserve_trust_limitations"
  | "future_authorization_required";

export interface UserApprovalRequestDraftActionSummary {
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly title: string;
  readonly description?: string;
  readonly actionKind?: string;
  readonly requestedValue?: string;
  readonly externalTarget?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserApprovalRequestDraftRiskSummary {
  readonly labels: readonly string[];
  readonly highValueAction?: boolean;
  readonly externalContractCall?: boolean;
  readonly messageSignatureRisk?: boolean;
  readonly experimentalCapability?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserApprovalRequestDraftDisclosure {
  readonly disclosureId: string;
  readonly kind:
    | "trust_limitation"
    | "policy_restriction"
    | "world_id_requirement"
    | "recovery_context"
    | "production_verification"
    | "risk"
    | "custom";
  readonly summary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserApprovalRequestDraftInput {
  readonly requestId: string;
  readonly capabilityGrantDraft: CapabilityGrantDraft;
  readonly boundedTrustEvaluationResult: BoundedTrustEvaluationResult;
  readonly boundedPolicyEvaluationResult: BoundedPolicyEvaluationResult;
  readonly approvalSurface?: UserApprovalRequestDraftSurface;
  readonly requestedScope?: CapabilityScope;
  readonly effectiveScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly effectiveDurationSeconds?: number;
  readonly actionSummary?: UserApprovalRequestDraftActionSummary;
  readonly riskSummary?: UserApprovalRequestDraftRiskSummary;
  readonly disclosures?: readonly UserApprovalRequestDraftDisclosure[];
  readonly requirements?: readonly UserApprovalRequestDraftRequirement[];
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly auditCorrelationId?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly status?: UserApprovalRequestDraftStatus;
  readonly outcome?: UserApprovalRequestDraftOutcome;
}

export interface UserApprovalRequestDraft {
  readonly userApprovalRequestDraftId: string;
  readonly requestId: string;
  readonly capabilityGrantDraftId: string;
  readonly boundedTrustEvaluationResultId: string;
  readonly boundedPolicyEvaluationResultId: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly capabilityName: CapabilityName;
  readonly requestedScope?: CapabilityScope;
  readonly effectiveScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly effectiveDurationSeconds?: number;
  readonly actionSummary: UserApprovalRequestDraftActionSummary;
  readonly riskSummary: UserApprovalRequestDraftRiskSummary;
  readonly disclosures: readonly UserApprovalRequestDraftDisclosure[];
  readonly requirements: readonly UserApprovalRequestDraftRequirement[];
  readonly approvalSurface: UserApprovalRequestDraftSurface;
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly status: UserApprovalRequestDraftStatus;
  readonly outcome: UserApprovalRequestDraftOutcome;
  readonly reasons: readonly UserApprovalRequestDraftReason[];
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly collectsUserDecision: false;
  readonly userDecisionPresent: false;
  readonly authenticatesUser: false;
  readonly invokesBiometrics: false;
  readonly invokesWebAuthn: false;
  readonly grantsAuthority: false;
  readonly createsCapabilityGrant: false;
  readonly createsAuthorizationPackage: false;
  readonly allowsExecution: false;
  readonly persisted: false;
}

export type UserApprovalRequestDraftResult = RuntimeResult<UserApprovalRequestDraft>;

export type UserApprovalRequestDraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface UserApprovalRequestDraftFilter {
  readonly userApprovalRequestDraftId?: string;
  readonly requestId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly boundedPolicyEvaluationResultId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly capabilityName?: CapabilityName;
  readonly approvalSurface?: UserApprovalRequestDraftSurface;
  readonly status?: UserApprovalRequestDraftStatus;
  readonly outcome?: UserApprovalRequestDraftOutcome;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface UserApprovalRequestDraftQuery {
  readonly filter?: UserApprovalRequestDraftFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface UserApprovalRequestDraftCollection {
  readonly drafts: readonly UserApprovalRequestDraft[];
  readonly count: number;
  readonly maxDraftCount: number;
}

export interface UserApprovalRequestDraftCollectionResult {
  readonly status: UserApprovalRequestDraftCollectionStatus;
  readonly draft?: UserApprovalRequestDraft;
  readonly removedDraft?: UserApprovalRequestDraft;
  readonly evictedDrafts?: readonly UserApprovalRequestDraft[];
  readonly collection: UserApprovalRequestDraftCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface UserApprovalRequestDraftCollector {
  addDraft(draft: UserApprovalRequestDraft): UserApprovalRequestDraftCollectionResult;
  removeDraft(userApprovalRequestDraftId: string): UserApprovalRequestDraftCollectionResult;
  clear(): UserApprovalRequestDraftCollectionResult;
  count(): number;
  getById(userApprovalRequestDraftId: string): UserApprovalRequestDraft | undefined;
  getAll(): readonly UserApprovalRequestDraft[];
  query(query: UserApprovalRequestDraftQuery): readonly UserApprovalRequestDraft[];
  filter(filter: UserApprovalRequestDraftFilter): readonly UserApprovalRequestDraft[];
}

export interface InMemoryUserApprovalRequestDraftCollectorOptions {
  readonly maxDraftCount?: number;
}

const APPROVAL_DRAFT_STATUSES = new Set<UserApprovalRequestDraftStatus>([
  "draft_created",
  "validation_failed",
  "malformed",
  "unsupported",
  "pending_user_presentation",
  "pending_user_decision",
  "expired"
]);

const APPROVAL_SURFACES = new Set<UserApprovalRequestDraftSurface>([
  "desktop",
  "mobile",
  "browser_extension",
  "hardware_confirmation",
  "recovery_surface",
  "developer_fixture",
  "unsupported"
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
  "webauthnassertion",
  "authenticatordata",
  "clientdatajson",
  "signature",
  "worldidproof",
  "authorizationpackage",
  "adapterpayload",
  "approved",
  "deniedbyuser",
  "authorized",
  "executed",
  "capabilitygrant",
  "authoritytoken",
  "userdecision"
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

function malformedApprovalDraftError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "USER_APPROVAL_REQUEST_DRAFT_INVALID",
    message: "user approval request draft input failed validation",
    boundary: "security-policy-engine",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isUserApprovalRequestDraftStatus(
  value: unknown
): value is UserApprovalRequestDraftStatus {
  return APPROVAL_DRAFT_STATUSES.has(value as UserApprovalRequestDraftStatus);
}

export function isUserApprovalRequestDraftSurface(
  value: unknown
): value is UserApprovalRequestDraftSurface {
  return APPROVAL_SURFACES.has(value as UserApprovalRequestDraftSurface);
}

function approvalEligibilityErrors(
  policy: BoundedPolicyEvaluationResult
): readonly string[] {
  if (
    policy.outcome === "eligible_for_user_approval"
    || policy.outcome === "eligible_for_future_authorization"
  ) {
    return Object.freeze([]);
  }
  return Object.freeze([
    `boundedPolicyEvaluationResult outcome ${policy.outcome} is not eligible for a user approval request draft`
  ]);
}

export function validateUserApprovalRequestDraftInput(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["user approval request draft input must be an object"]);
  }
  if (!isNonEmptyString(input.requestId)) {
    errors.push("requestId is required");
  }
  const capabilityValidation = validateCapabilityGrantDraftShape(input.capabilityGrantDraft);
  if (!capabilityValidation.valid) {
    errors.push(...capabilityValidation.errors.map((error) => `capabilityGrantDraft.${error}`));
  }
  const trustValidation = validateBoundedTrustEvaluationResultShape(
    input.boundedTrustEvaluationResult
  );
  if (!trustValidation.valid) {
    errors.push(...trustValidation.errors.map((error) => `boundedTrustEvaluationResult.${error}`));
  }
  const policyValidation = validateBoundedPolicyEvaluationResultShape(
    input.boundedPolicyEvaluationResult
  );
  if (!policyValidation.valid) {
    errors.push(...policyValidation.errors.map((error) => `boundedPolicyEvaluationResult.${error}`));
  }
  if (
    input.approvalSurface !== undefined
    && !isUserApprovalRequestDraftSurface(input.approvalSurface)
  ) {
    errors.push("approvalSurface is invalid");
  }
  if (input.status !== undefined && !isUserApprovalRequestDraftStatus(input.status)) {
    errors.push("status is invalid");
  }
  if (input.outcome !== undefined && !isUserApprovalRequestDraftStatus(input.outcome)) {
    errors.push("outcome is invalid");
  }
  if (input.createdAt !== undefined && !hasValidDateShape(input.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (input.expiresAt !== undefined && !hasValidDateShape(input.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (isExpiredDate(input.expiresAt as string | undefined)) {
    errors.push("user approval request draft input is expired");
  }

  if (capabilityValidation.valid && trustValidation.valid && policyValidation.valid) {
    const capability = input.capabilityGrantDraft as CapabilityGrantDraft;
    const trust = input.boundedTrustEvaluationResult as BoundedTrustEvaluationResult;
    const policy = input.boundedPolicyEvaluationResult as BoundedPolicyEvaluationResult;
    if (capability.capabilityGrantDraftId !== policy.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with boundedPolicyEvaluationResult.capabilityGrantDraftId");
    }
    if (trust.boundedTrustEvaluationResultId !== policy.boundedTrustEvaluationResultId) {
      errors.push("boundedTrustEvaluationResult must correlate with boundedPolicyEvaluationResult.boundedTrustEvaluationResultId");
    }
    if (capability.applicationId !== policy.applicationId || trust.applicationId !== policy.applicationId) {
      errors.push("applicationId must correlate across capability, trust, and policy results");
    }
    if (
      input.applicationId !== undefined
      && input.applicationId !== policy.applicationId
    ) {
      errors.push("applicationId must match boundedPolicyEvaluationResult.applicationId");
    }
    const sessionId = input.sessionId ?? capability.sessionId ?? trust.sessionId ?? policy.sessionId;
    for (const [label, value] of [
      ["capabilityGrantDraft.sessionId", capability.sessionId],
      ["boundedTrustEvaluationResult.sessionId", trust.sessionId],
      ["boundedPolicyEvaluationResult.sessionId", policy.sessionId]
    ] as const) {
      if (sessionId !== undefined && value !== undefined && value !== sessionId) {
        errors.push(`${label} must match request/session correlation`);
      }
    }
    if (
      input.ownerCommitment !== undefined
      && trust.ownerCommitment !== undefined
      && input.ownerCommitment !== trust.ownerCommitment
    ) {
      errors.push("ownerCommitment must match boundedTrustEvaluationResult.ownerCommitment");
    }
    errors.push(...approvalEligibilityErrors(policy));
  }

  const blockedFields = findBlockedFields(input);
  if (blockedFields.length > 0) {
    errors.push(`private material, active authority, or user-decision fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(input.metadata));
  errors.push(...secretValidationErrors(input.actionSummary));
  errors.push(...secretValidationErrors(input.riskSummary));
  errors.push(...secretValidationErrors(input.disclosures));
  return validation(errors);
}

export function validateUserApprovalRequestDraftShape(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) {
    return validation(["user approval request draft must be an object"]);
  }
  if (!isNonEmptyString(draft.userApprovalRequestDraftId)) {
    errors.push("userApprovalRequestDraftId is required");
  }
  if (!isNonEmptyString(draft.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(draft.capabilityGrantDraftId)) {
    errors.push("capabilityGrantDraftId is required");
  }
  if (!isNonEmptyString(draft.boundedTrustEvaluationResultId)) {
    errors.push("boundedTrustEvaluationResultId is required");
  }
  if (!isNonEmptyString(draft.boundedPolicyEvaluationResultId)) {
    errors.push("boundedPolicyEvaluationResultId is required");
  }
  if (!isNonEmptyString(draft.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isNonEmptyString(draft.capabilityName)) {
    errors.push("capabilityName is required");
  }
  if (!isRecord(draft.actionSummary)) {
    errors.push("actionSummary is required");
  }
  if (!isRecord(draft.riskSummary)) {
    errors.push("riskSummary is required");
  }
  if (!Array.isArray(draft.disclosures)) {
    errors.push("disclosures must be an array");
  }
  if (!Array.isArray(draft.requirements)) {
    errors.push("requirements must be an array");
  }
  if (!isUserApprovalRequestDraftSurface(draft.approvalSurface)) {
    errors.push("approvalSurface is invalid");
  }
  if (!isUserApprovalRequestDraftStatus(draft.status)) {
    errors.push("status is invalid");
  }
  if (!isUserApprovalRequestDraftStatus(draft.outcome)) {
    errors.push("outcome is invalid");
  }
  if (!hasValidDateShape(draft.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (draft.expiresAt !== undefined && !hasValidDateShape(draft.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  for (const [field, expected] of [
    ["collectsUserDecision", false],
    ["userDecisionPresent", false],
    ["authenticatesUser", false],
    ["invokesBiometrics", false],
    ["invokesWebAuthn", false],
    ["grantsAuthority", false],
    ["createsCapabilityGrant", false],
    ["createsAuthorizationPackage", false],
    ["allowsExecution", false],
    ["persisted", false]
  ] as const) {
    if (draft[field] !== expected) {
      errors.push(`${field} must be false`);
    }
  }
  if (!isNonEmptyString(draft.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  if (!isNonEmptyString(draft.humanReadableSummary)) {
    errors.push("humanReadableSummary is required");
  }
  const blockedFields = findBlockedFields(draft);
  if (blockedFields.length > 0) {
    errors.push(`private material, active authority, or user-decision fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(draft));
  return validation(errors);
}

function defaultActionSummary(input: UserApprovalRequestDraftInput): UserApprovalRequestDraftActionSummary {
  const policy = input.boundedPolicyEvaluationResult;
  const metadata = input.actionSummary?.metadata
    ? redactRuntimeMetadata(input.actionSummary.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  return freezeRecord({
    applicationId: input.applicationId ?? policy.applicationId,
    capabilityName: policy.capabilityName,
    title: input.actionSummary?.title ?? `Review ${policy.capabilityName}`,
    description: input.actionSummary?.description
      ?? "A future user decision may be required before this request can proceed.",
    actionKind: input.actionSummary?.actionKind,
    requestedValue: input.actionSummary?.requestedValue,
    externalTarget: input.actionSummary?.externalTarget,
    metadata
  });
}

function derivedRiskLabels(input: UserApprovalRequestDraftInput): string[] {
  const labels = new Set<string>(input.riskSummary?.labels ?? []);
  const trust = input.boundedTrustEvaluationResult;
  const policy = input.boundedPolicyEvaluationResult;
  if (trust.fixtureOnlyEvidence) labels.add("fixture-only possession evidence");
  if (!trust.productionAuthenticationPerformed) labels.add("production authentication not performed");
  if (policy.requirementSummary.requiresProductionPossessionVerification) {
    labels.add("stronger production possession verification required");
  }
  if (policy.requirementSummary.requiresWorldIdEnrollment) {
    labels.add("World ID enrollment required for canonical activation");
  }
  if (trust.lifecycleAssessment.credentialLifecycleStatus === "recovery-only") {
    labels.add("recovery-only credential context");
  }
  if (policy.requirementSummary.requiresScopeRestriction) labels.add("restricted scope");
  if (policy.requirementSummary.requiresDurationRestriction) labels.add("restricted duration");
  return [...labels];
}

function defaultRiskSummary(input: UserApprovalRequestDraftInput): UserApprovalRequestDraftRiskSummary {
  const metadata = input.riskSummary?.metadata
    ? redactRuntimeMetadata(input.riskSummary.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  return freezeRecord({
    labels: Object.freeze(derivedRiskLabels(input)),
    highValueAction: input.riskSummary?.highValueAction,
    externalContractCall: input.riskSummary?.externalContractCall,
    messageSignatureRisk: input.riskSummary?.messageSignatureRisk,
    experimentalCapability: input.riskSummary?.experimentalCapability,
    metadata
  });
}

function disclosure(
  disclosureId: string,
  kind: UserApprovalRequestDraftDisclosure["kind"],
  summary: string
): UserApprovalRequestDraftDisclosure {
  return Object.freeze({
    disclosureId,
    kind,
    summary
  });
}

function defaultDisclosures(input: UserApprovalRequestDraftInput): readonly UserApprovalRequestDraftDisclosure[] {
  const policy = input.boundedPolicyEvaluationResult;
  const trust = input.boundedTrustEvaluationResult;
  const disclosures: UserApprovalRequestDraftDisclosure[] = [];
  if (trust.fixtureOnlyEvidence) {
    disclosures.push(disclosure(
      "fixture-only-evidence",
      "trust_limitation",
      "Possession evidence is fixture-only and is not production authentication."
    ));
  }
  if (!trust.productionAuthenticationPerformed) {
    disclosures.push(disclosure(
      "production-authentication-not-performed",
      "production_verification",
      "Production authentication has not been performed."
    ));
  }
  if (policy.requirementSummary.requiresWorldIdEnrollment) {
    disclosures.push(disclosure(
      "world-id-enrollment-required",
      "world_id_requirement",
      "World ID enrollment remains a separate future requirement."
    ));
  }
  if (policy.requirementSummary.requiresScopeRestriction) {
    disclosures.push(disclosure(
      "scope-restriction",
      "policy_restriction",
      "Policy restrictions must be preserved before future authorization."
    ));
  }
  if (policy.requirementSummary.requiresDurationRestriction) {
    disclosures.push(disclosure(
      "duration-restriction",
      "policy_restriction",
      "Policy duration restrictions must be preserved before future authorization."
    ));
  }
  if (trust.lifecycleAssessment.credentialLifecycleStatus === "recovery-only") {
    disclosures.push(disclosure(
      "recovery-only-credential",
      "recovery_context",
      "This evidence is tied to a recovery-only credential context."
    ));
  }
  const provided = input.disclosures ?? [];
  return Object.freeze([
    ...disclosures,
    ...provided.map((entry) => freezeRecord(
      redactRuntimeMetadata(entry).value as UserApprovalRequestDraftDisclosure
    ))
  ]);
}

function defaultRequirements(
  input: UserApprovalRequestDraftInput
): readonly UserApprovalRequestDraftRequirement[] {
  const requirements = new Set<UserApprovalRequestDraftRequirement>([
    "present_to_user",
    "collect_future_user_decision",
    "preserve_trust_limitations",
    "future_authorization_required"
  ]);
  if (
    input.boundedPolicyEvaluationResult.requirementSummary.requiresScopeRestriction
    || input.boundedPolicyEvaluationResult.requirementSummary.requiresDurationRestriction
  ) {
    requirements.add("preserve_policy_restrictions");
  }
  for (const requirement of input.requirements ?? []) {
    requirements.add(requirement);
  }
  return Object.freeze([...requirements]);
}

export function createUserApprovalRequestDraft(
  input: UserApprovalRequestDraftInput
): UserApprovalRequestDraftResult {
  const validationResult = validateUserApprovalRequestDraftInput(input);
  if (!validationResult.valid) {
    return runtimeDenied(malformedApprovalDraftError(validationResult.errors));
  }
  const policy = input.boundedPolicyEvaluationResult;
  const trust = input.boundedTrustEvaluationResult;
  const capability = input.capabilityGrantDraft;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const sessionId = input.sessionId ?? policy.sessionId ?? trust.sessionId ?? capability.sessionId;
  const applicationId = input.applicationId ?? policy.applicationId;
  const auditCorrelationId = input.auditCorrelationId ?? createAuditCorrelationId([
    applicationId,
    sessionId ?? "",
    capability.capabilityGrantDraftId,
    policy.boundedPolicyEvaluationResultId,
    "user-approval-request-draft"
  ]);
  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  const status = input.status ?? "pending_user_presentation";
  const outcome = input.outcome ?? status;
  const draft: UserApprovalRequestDraft = Object.freeze({
    userApprovalRequestDraftId: `${auditCorrelationId}:user-approval-request-draft`,
    requestId: input.requestId,
    capabilityGrantDraftId: capability.capabilityGrantDraftId,
    boundedTrustEvaluationResultId: trust.boundedTrustEvaluationResultId,
    boundedPolicyEvaluationResultId: policy.boundedPolicyEvaluationResultId,
    applicationId,
    sessionId,
    ownerCommitment: input.ownerCommitment ?? trust.ownerCommitment,
    capabilityName: policy.capabilityName,
    requestedScope: input.requestedScope ?? capability.scope,
    effectiveScope: input.effectiveScope ?? input.requestedScope ?? capability.scope,
    requestedDurationSeconds: input.requestedDurationSeconds,
    effectiveDurationSeconds: input.effectiveDurationSeconds ?? input.requestedDurationSeconds,
    actionSummary: defaultActionSummary(input),
    riskSummary: defaultRiskSummary(input),
    disclosures: defaultDisclosures(input),
    requirements: defaultRequirements(input),
    approvalSurface: input.approvalSurface ?? "desktop",
    createdAt,
    expiresAt: input.expiresAt,
    status,
    outcome,
    reasons: Object.freeze([
      "capability-draft-valid",
      "bounded-trust-result-valid",
      "bounded-policy-result-valid",
      policy.outcome === "eligible_for_user_approval"
        ? "policy-eligible-for-user-approval"
        : "policy-eligible-for-future-authorization",
      "policy-restrictions-preserved",
      "trust-limitations-preserved",
      "fixture-only-evidence-disclosed",
      "no-user-decision-collected",
      "non-authoritative-draft"
    ]),
    auditCorrelationId,
    humanReadableSummary: input.humanReadableSummary
      ?? `User approval request draft ${input.requestId} is ready for future presentation; no user decision was collected.`,
    metadata,
    collectsUserDecision: false,
    userDecisionPresent: false,
    authenticatesUser: false,
    invokesBiometrics: false,
    invokesWebAuthn: false,
    grantsAuthority: false,
    createsCapabilityGrant: false,
    createsAuthorizationPackage: false,
    allowsExecution: false,
    persisted: false
  });
  return runtimeOk(draft);
}

function emptyCollection(
  maxDraftCount: number,
  drafts: readonly UserApprovalRequestDraft[] = []
): UserApprovalRequestDraftCollection {
  return Object.freeze({
    drafts: Object.freeze([...drafts]),
    count: drafts.length,
    maxDraftCount
  });
}

function collectionResult(input: {
  readonly status: UserApprovalRequestDraftCollectionStatus;
  readonly drafts: readonly UserApprovalRequestDraft[];
  readonly maxDraftCount: number;
  readonly draft?: UserApprovalRequestDraft;
  readonly removedDraft?: UserApprovalRequestDraft;
  readonly evictedDrafts?: readonly UserApprovalRequestDraft[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): UserApprovalRequestDraftCollectionResult {
  return Object.freeze({
    status: input.status,
    draft: input.draft,
    removedDraft: input.removedDraft,
    evictedDrafts: input.evictedDrafts,
    collection: emptyCollection(input.maxDraftCount, input.drafts),
    errors: input.errors,
    reason: input.reason
  });
}

function matchesFilter(
  draft: UserApprovalRequestDraft,
  filter: UserApprovalRequestDraftFilter
): boolean {
  if (filter.userApprovalRequestDraftId !== undefined && draft.userApprovalRequestDraftId !== filter.userApprovalRequestDraftId) return false;
  if (filter.requestId !== undefined && draft.requestId !== filter.requestId) return false;
  if (filter.capabilityGrantDraftId !== undefined && draft.capabilityGrantDraftId !== filter.capabilityGrantDraftId) return false;
  if (filter.boundedPolicyEvaluationResultId !== undefined && draft.boundedPolicyEvaluationResultId !== filter.boundedPolicyEvaluationResultId) return false;
  if (filter.applicationId !== undefined && draft.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && draft.sessionId !== filter.sessionId) return false;
  if (filter.capabilityName !== undefined && draft.capabilityName !== filter.capabilityName) return false;
  if (filter.approvalSurface !== undefined && draft.approvalSurface !== filter.approvalSurface) return false;
  if (filter.status !== undefined && draft.status !== filter.status) return false;
  if (filter.outcome !== undefined && draft.outcome !== filter.outcome) return false;
  if (filter.auditCorrelationId !== undefined && draft.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(draft.createdAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(draft.createdAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryUserApprovalRequestDraftCollector(
  options: InMemoryUserApprovalRequestDraftCollectorOptions = {}
): UserApprovalRequestDraftCollector {
  const maxDraftCount = Math.max(1, Math.floor(options.maxDraftCount ?? 100));
  const drafts: UserApprovalRequestDraft[] = [];

  return Object.freeze({
    addDraft(draft: UserApprovalRequestDraft) {
      const validationResult = validateUserApprovalRequestDraftShape(draft);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          drafts,
          maxDraftCount,
          errors: validationResult.errors
        });
      }
      if (drafts.some((entry) => entry.userApprovalRequestDraftId === draft.userApprovalRequestDraftId)) {
        return collectionResult({
          status: "rejected_duplicate",
          drafts,
          maxDraftCount,
          draft,
          reason: "user approval request draft ID already exists"
        });
      }
      const evictedDrafts: UserApprovalRequestDraft[] = [];
      if (drafts.length >= maxDraftCount) {
        const evicted = drafts.shift();
        if (evicted) {
          evictedDrafts.push(evicted);
        }
      }
      const frozenDraft = freezeRecord(draft);
      drafts.push(frozenDraft);
      return collectionResult({
        status: evictedDrafts.length > 0 ? "evicted_oldest" : "collected",
        drafts,
        maxDraftCount,
        draft: frozenDraft,
        evictedDrafts: evictedDrafts.length > 0 ? Object.freeze(evictedDrafts) : undefined
      });
    },
    removeDraft(userApprovalRequestDraftId: string) {
      const index = drafts.findIndex(
        (entry) => entry.userApprovalRequestDraftId === userApprovalRequestDraftId
      );
      if (index === -1) {
        return collectionResult({
          status: "not_found",
          drafts,
          maxDraftCount
        });
      }
      const [removedDraft] = drafts.splice(index, 1);
      return collectionResult({
        status: "removed",
        drafts,
        maxDraftCount,
        removedDraft
      });
    },
    clear() {
      drafts.splice(0, drafts.length);
      return collectionResult({
        status: "cleared",
        drafts,
        maxDraftCount
      });
    },
    count() {
      return drafts.length;
    },
    getById(userApprovalRequestDraftId: string) {
      return drafts.find((entry) => entry.userApprovalRequestDraftId === userApprovalRequestDraftId);
    },
    getAll() {
      return Object.freeze([...drafts]);
    },
    query(query: UserApprovalRequestDraftQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? drafts
        : drafts.filter((draft) => matchesFilter(draft, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: UserApprovalRequestDraftFilter) {
      return Object.freeze(drafts.filter((draft) => matchesFilter(draft, filter)));
    }
  });
}
