import {
  validateBoundedPolicyEvaluationResultShape,
  type BoundedPolicyLimitation,
  type BoundedPolicyEvaluationResult
} from "./boundedPolicyEvaluation.ts";
import {
  validateBoundedTrustEvaluationResultShape,
  type BoundedTrustLimitation,
  type BoundedTrustEvaluationResult
} from "./boundedTrustEvaluation.ts";
import {
  validateCapabilityGrantDraftShape,
  type CapabilityGrantDraft,
  type CapabilityGrantDraftConstraint,
  type CapabilityGrantDraftRequirement
} from "./capabilityDrafts.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import {
  validateUserApprovalRequestDraftShape,
  type UserApprovalRequestDraft
} from "./userApprovalDrafts.ts";
import {
  validateUserDecisionFixtureArtifactShape,
  type UserDecisionFixtureArtifact
} from "./userDecisionFixtures.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type CapabilityActivationCandidateStatus =
  | "candidate_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "expired"
  | "ineligible"
  | "pending_production_consent"
  | "pending_production_authentication"
  | "pending_capability_activation";

export type CapabilityActivationCandidateOutcome = CapabilityActivationCandidateStatus;

export type CapabilityActivationCandidateReason =
  | "capability-draft-valid"
  | "bounded-trust-result-valid"
  | "bounded-policy-result-valid"
  | "user-approval-request-draft-valid"
  | "approved-fixture-valid"
  | "fixture-approval-not-production-consent"
  | "trust-limitations-preserved"
  | "policy-limitations-preserved"
  | "pending-production-consent"
  | "pending-production-authentication"
  | "pending-capability-activation"
  | "world-id-context-specific"
  | "non-authoritative-candidate"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type CapabilityActivationCandidateLimitation =
  | "fixture_only_user_decision"
  | "no_production_user_consent"
  | "no_production_authentication"
  | "no_capability_grant"
  | "no_active_capability"
  | "no_session_key"
  | "no_authorization"
  | "no_execution"
  | "no_persistence"
  | "no_world_id_verification"
  | "trust_fixture_only_evidence"
  | "trust_production_authentication_not_performed"
  | "policy_restrictions_preserved"
  | "world_id_context_specific"
  | BoundedTrustLimitation
  | BoundedPolicyLimitation
  | (string & {});

export interface CapabilityActivationCandidateScope {
  readonly requestedScope?: CapabilityScope;
  readonly effectiveScope?: CapabilityScope;
  readonly scopeRestricted: boolean;
}

export interface CapabilityActivationCandidateDuration {
  readonly requestedDurationSeconds?: number;
  readonly effectiveDurationSeconds?: number;
  readonly durationRestricted: boolean;
}

export interface CapabilityActivationCandidateEvidence {
  readonly capabilityGrantDraftId: string;
  readonly boundedTrustEvaluationResultId: string;
  readonly boundedPolicyEvaluationResultId: string;
  readonly userApprovalRequestDraftId: string;
  readonly userDecisionFixtureArtifactId: string;
  readonly fixtureOnlyUserDecision: true;
  readonly productionUserConsentCollected: false;
  readonly productionAuthenticationPerformed: false;
  readonly worldIdEnrollmentVerified: false;
}

export interface CapabilityActivationCandidateRequest {
  readonly requestId: string;
  readonly capabilityGrantDraft: CapabilityGrantDraft;
  readonly boundedTrustEvaluationResult: BoundedTrustEvaluationResult;
  readonly boundedPolicyEvaluationResult: BoundedPolicyEvaluationResult;
  readonly userApprovalRequestDraft: UserApprovalRequestDraft;
  readonly userDecisionFixtureArtifact: UserDecisionFixtureArtifact;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly capabilityName?: CapabilityName;
  readonly requestedScope?: CapabilityScope;
  readonly effectiveScope?: CapabilityScope;
  readonly requestedDurationSeconds?: number;
  readonly effectiveDurationSeconds?: number;
  readonly auditCorrelationId?: string;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CapabilityActivationCandidate {
  readonly capabilityActivationCandidateId: string;
  readonly requestId: string;
  readonly capabilityGrantDraftId: string;
  readonly boundedTrustEvaluationResultId: string;
  readonly boundedPolicyEvaluationResultId: string;
  readonly userApprovalRequestDraftId: string;
  readonly userDecisionFixtureArtifactId: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly capabilityName: CapabilityName;
  readonly scope: CapabilityActivationCandidateScope;
  readonly duration: CapabilityActivationCandidateDuration;
  readonly constraints: readonly CapabilityGrantDraftConstraint[];
  readonly requirements: readonly CapabilityGrantDraftRequirement[];
  readonly limitations: readonly CapabilityActivationCandidateLimitation[];
  readonly evidence: CapabilityActivationCandidateEvidence;
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly status: CapabilityActivationCandidateStatus;
  readonly outcome: CapabilityActivationCandidateOutcome;
  readonly reasons: readonly CapabilityActivationCandidateReason[];
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly fixtureOnlyUserDecision: true;
  readonly productionUserConsentCollected: false;
  readonly productionAuthenticationPerformed: false;
  readonly grantsAuthority: false;
  readonly activeCapabilityCreated: false;
  readonly createsCapabilityGrant: false;
  readonly sessionKeyIssued: false;
  readonly authorizationCreated: false;
  readonly createsAuthorizationPackage: false;
  readonly allowsExecution: false;
  readonly worldIdEnrollmentVerified: false;
  readonly persisted: false;
}

export type CapabilityActivationCandidateResult =
  RuntimeResult<CapabilityActivationCandidate>;

export type CapabilityActivationCandidateCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface CapabilityActivationCandidateFilter {
  readonly capabilityActivationCandidateId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly boundedTrustEvaluationResultId?: string;
  readonly boundedPolicyEvaluationResultId?: string;
  readonly userApprovalRequestDraftId?: string;
  readonly userDecisionFixtureArtifactId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly capabilityName?: CapabilityName;
  readonly status?: CapabilityActivationCandidateStatus;
  readonly outcome?: CapabilityActivationCandidateOutcome;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface CapabilityActivationCandidateQuery {
  readonly filter?: CapabilityActivationCandidateFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface CapabilityActivationCandidateCollection {
  readonly candidates: readonly CapabilityActivationCandidate[];
  readonly count: number;
  readonly maxCandidateCount: number;
}

export interface CapabilityActivationCandidateCollectionResult {
  readonly status: CapabilityActivationCandidateCollectionStatus;
  readonly candidate?: CapabilityActivationCandidate;
  readonly removedCandidate?: CapabilityActivationCandidate;
  readonly evictedCandidates?: readonly CapabilityActivationCandidate[];
  readonly collection: CapabilityActivationCandidateCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface CapabilityActivationCandidateCollector {
  addCandidate(candidate: CapabilityActivationCandidate): CapabilityActivationCandidateCollectionResult;
  removeCandidate(capabilityActivationCandidateId: string): CapabilityActivationCandidateCollectionResult;
  clear(): CapabilityActivationCandidateCollectionResult;
  count(): number;
  getById(capabilityActivationCandidateId: string): CapabilityActivationCandidate | undefined;
  getAll(): readonly CapabilityActivationCandidate[];
  query(query: CapabilityActivationCandidateQuery): readonly CapabilityActivationCandidate[];
  filter(filter: CapabilityActivationCandidateFilter): readonly CapabilityActivationCandidate[];
}

export interface InMemoryCapabilityActivationCandidateCollectorOptions {
  readonly maxCandidateCount?: number;
}

const CANDIDATE_STATUSES = new Set<CapabilityActivationCandidateStatus>([
  "candidate_created",
  "validation_failed",
  "malformed",
  "unsupported",
  "expired",
  "ineligible",
  "pending_production_consent",
  "pending_production_authentication",
  "pending_capability_activation"
]);

const ELIGIBLE_POLICY_OUTCOMES = new Set([
  "eligible_for_user_approval",
  "eligible_for_future_authorization"
]);

const ACTIVE_AUTHORITY_OR_PRIVATE_FIELDS = new Set([
  "philsecret",
  "privatekey",
  "signingkey",
  "sessionkey",
  "sessionkeyissued",
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
  "worldidproof",
  "authorizationpackage",
  "adapterpayload",
  "authoritytoken",
  "activecapabilityid",
  "activecapabilitycreated",
  "capabilitygrant",
  "productionuserconsentcollected",
  "productionauthenticationperformed",
  "grantsauthority",
  "createsauthorizationpackage",
  "authorizationcreated",
  "allowsexecution",
  "worldidenrollmentverified",
  "persisted"
]);

const NON_AUTHORITATIVE_LIMITATIONS: readonly CapabilityActivationCandidateLimitation[] = Object.freeze([
  "fixture_only_user_decision",
  "no_production_user_consent",
  "no_production_authentication",
  "no_capability_grant",
  "no_active_capability",
  "no_session_key",
  "no_authorization",
  "no_execution",
  "no_persistence",
  "no_world_id_verification",
  "trust_fixture_only_evidence",
  "trust_production_authentication_not_performed",
  "policy_restrictions_preserved",
  "world_id_context_specific"
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

function isExpiredAt(expiresAt: string | undefined, at: string): boolean {
  return expiresAt !== undefined && Date.parse(expiresAt) <= Date.parse(at);
}

function malformedCandidateError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "CAPABILITY_ACTIVATION_CANDIDATE_INVALID",
    message: "capability activation candidate request failed validation",
    boundary: "runtime-api",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isCapabilityActivationCandidateStatus(
  value: unknown
): value is CapabilityActivationCandidateStatus {
  return CANDIDATE_STATUSES.has(value as CapabilityActivationCandidateStatus);
}

export function isCapabilityActivationCandidateOutcome(
  value: unknown
): value is CapabilityActivationCandidateOutcome {
  return isCapabilityActivationCandidateStatus(value);
}

export function validateCapabilityActivationCandidateRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["capability activation candidate request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  if (request.createdAt !== undefined && !hasValidDateShape(request.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }

  const capabilityValidation = validateCapabilityGrantDraftShape(request.capabilityGrantDraft);
  const trustValidation = validateBoundedTrustEvaluationResultShape(
    request.boundedTrustEvaluationResult
  );
  const policyValidation = validateBoundedPolicyEvaluationResultShape(
    request.boundedPolicyEvaluationResult
  );
  const approvalValidation = validateUserApprovalRequestDraftShape(
    request.userApprovalRequestDraft
  );
  const fixtureValidation = validateUserDecisionFixtureArtifactShape(
    request.userDecisionFixtureArtifact
  );
  if (!capabilityValidation.valid) {
    errors.push(...capabilityValidation.errors.map((error) => `capabilityGrantDraft.${error}`));
  }
  if (!trustValidation.valid) {
    errors.push(...trustValidation.errors.map((error) => `boundedTrustEvaluationResult.${error}`));
  }
  if (!policyValidation.valid) {
    errors.push(...policyValidation.errors.map((error) => `boundedPolicyEvaluationResult.${error}`));
  }
  if (!approvalValidation.valid) {
    errors.push(...approvalValidation.errors.map((error) => `userApprovalRequestDraft.${error}`));
  }
  if (!fixtureValidation.valid) {
    errors.push(...fixtureValidation.errors.map((error) => `userDecisionFixtureArtifact.${error}`));
  }

  if (
    capabilityValidation.valid
    && trustValidation.valid
    && policyValidation.valid
    && approvalValidation.valid
    && fixtureValidation.valid
  ) {
    const capability = request.capabilityGrantDraft as CapabilityGrantDraft;
    const trust = request.boundedTrustEvaluationResult as BoundedTrustEvaluationResult;
    const policy = request.boundedPolicyEvaluationResult as BoundedPolicyEvaluationResult;
    const approval = request.userApprovalRequestDraft as UserApprovalRequestDraft;
    const fixture = request.userDecisionFixtureArtifact as UserDecisionFixtureArtifact;
    const createdAt = request.createdAt as string | undefined ?? new Date().toISOString();

    if (isExpiredAt(capability.expiresAt, createdAt)) {
      errors.push("capabilityGrantDraft is expired");
    }
    if (isExpiredAt(approval.expiresAt, createdAt) || approval.status === "expired" || approval.outcome === "expired") {
      errors.push("userApprovalRequestDraft is expired");
    }
    if (fixture.status === "expired" || fixture.outcome === "expired") {
      errors.push("userDecisionFixtureArtifact is expired and cannot create a candidate");
    }
    if (request.expiresAt !== undefined && isExpiredAt(request.expiresAt as string, createdAt)) {
      errors.push("capability activation candidate request is expired");
    }
    if (fixture.outcome !== "approve") {
      errors.push("userDecisionFixtureArtifact outcome must be approve");
    }
    if (fixture.fixtureOnly !== true || fixture.productionUserConsentCollected !== false) {
      errors.push("userDecisionFixtureArtifact must remain fixture-only and must not claim production consent");
    }
    if (trust.eligibleForPolicyReview !== true) {
      errors.push("boundedTrustEvaluationResult must be structurally sufficient for policy review");
    }
    if (!ELIGIBLE_POLICY_OUTCOMES.has(policy.outcome)) {
      errors.push("boundedPolicyEvaluationResult outcome is not eligible for capability activation candidacy");
    }
    if (policy.requirementSummary.requiresStrongerTrust) {
      errors.push("unresolved stronger Trust requirement blocks capability activation candidacy");
    }
    if (policy.requirementSummary.requiresWorldIdEnrollment || trust.requiresWorldIdEnrollment) {
      errors.push("unresolved World ID enrollment blocks capability activation candidacy");
    }
    if (
      trust.evaluationContext === "canonical_phil_activation"
      && trust.worldIdEnrollmentVerified === false
    ) {
      errors.push("canonical Phil activation requires future real World ID enrollment before candidacy");
    }
    if (capability.capabilityGrantDraftId !== trust.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with boundedTrustEvaluationResult.capabilityGrantDraftId");
    }
    if (capability.capabilityGrantDraftId !== policy.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with boundedPolicyEvaluationResult.capabilityGrantDraftId");
    }
    if (capability.capabilityGrantDraftId !== approval.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with userApprovalRequestDraft.capabilityGrantDraftId");
    }
    if (capability.capabilityGrantDraftId !== fixture.capabilityGrantDraftId) {
      errors.push("capabilityGrantDraft must correlate with userDecisionFixtureArtifact.capabilityGrantDraftId");
    }
    if (trust.boundedTrustEvaluationResultId !== policy.boundedTrustEvaluationResultId) {
      errors.push("boundedTrustEvaluationResult must correlate with boundedPolicyEvaluationResult.boundedTrustEvaluationResultId");
    }
    if (trust.boundedTrustEvaluationResultId !== approval.boundedTrustEvaluationResultId) {
      errors.push("boundedTrustEvaluationResult must correlate with userApprovalRequestDraft.boundedTrustEvaluationResultId");
    }
    if (trust.boundedTrustEvaluationResultId !== fixture.boundedTrustEvaluationResultId) {
      errors.push("boundedTrustEvaluationResult must correlate with userDecisionFixtureArtifact.boundedTrustEvaluationResultId");
    }
    if (policy.boundedPolicyEvaluationResultId !== approval.boundedPolicyEvaluationResultId) {
      errors.push("boundedPolicyEvaluationResult must correlate with userApprovalRequestDraft.boundedPolicyEvaluationResultId");
    }
    if (policy.boundedPolicyEvaluationResultId !== fixture.boundedPolicyEvaluationResultId) {
      errors.push("boundedPolicyEvaluationResult must correlate with userDecisionFixtureArtifact.boundedPolicyEvaluationResultId");
    }
    if (approval.userApprovalRequestDraftId !== fixture.userApprovalRequestDraftId) {
      errors.push("userApprovalRequestDraft must correlate with userDecisionFixtureArtifact.userApprovalRequestDraftId");
    }
    const applicationId = request.applicationId as string | undefined ?? capability.applicationId;
    if (
      capability.applicationId !== applicationId
      || trust.applicationId !== applicationId
      || policy.applicationId !== applicationId
      || approval.applicationId !== applicationId
      || fixture.applicationId !== applicationId
    ) {
      errors.push("applicationId must correlate across all activation candidate artifacts");
    }
    const sessionId = request.sessionId as string | undefined
      ?? capability.sessionId
      ?? trust.sessionId
      ?? policy.sessionId
      ?? approval.sessionId
      ?? fixture.sessionId;
    for (const [label, value] of [
      ["capabilityGrantDraft.sessionId", capability.sessionId],
      ["boundedTrustEvaluationResult.sessionId", trust.sessionId],
      ["boundedPolicyEvaluationResult.sessionId", policy.sessionId],
      ["userApprovalRequestDraft.sessionId", approval.sessionId],
      ["userDecisionFixtureArtifact.sessionId", fixture.sessionId]
    ] as const) {
      if (sessionId !== undefined && value !== undefined && value !== sessionId) {
        errors.push(`${label} must match request/session correlation`);
      }
    }
    const ownerCommitment = request.ownerCommitment as string | undefined
      ?? trust.ownerCommitment
      ?? approval.ownerCommitment
      ?? fixture.ownerCommitment;
    for (const [label, value] of [
      ["boundedTrustEvaluationResult.ownerCommitment", trust.ownerCommitment],
      ["userApprovalRequestDraft.ownerCommitment", approval.ownerCommitment],
      ["userDecisionFixtureArtifact.ownerCommitment", fixture.ownerCommitment]
    ] as const) {
      if (ownerCommitment !== undefined && value !== undefined && value !== ownerCommitment) {
        errors.push(`${label} must match request ownerCommitment correlation`);
      }
    }
    const capabilityName = request.capabilityName as string | undefined ?? capability.capabilityName;
    if (
      capability.capabilityName !== capabilityName
      || policy.capabilityName !== capabilityName
      || approval.capabilityName !== capabilityName
    ) {
      errors.push("capabilityName must correlate across capability draft, policy result, and approval draft");
    }
    if (
      request.auditCorrelationId !== undefined
      && request.auditCorrelationId !== fixture.auditCorrelationId
    ) {
      errors.push("request auditCorrelationId must match userDecisionFixtureArtifact.auditCorrelationId when provided");
    }
    if (policy.grantsAuthority !== false || trust.grantsAuthority !== false || fixture.grantsAuthority !== false) {
      errors.push("input artifacts must remain non-authoritative");
    }
  }

  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material, production consent, active authority, or execution fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(request.metadata));
  return validation(errors);
}

export function validateCapabilityActivationCandidateShape(
  candidate: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(candidate)) {
    return validation(["capability activation candidate must be an object"]);
  }
  for (const field of [
    "capabilityActivationCandidateId",
    "requestId",
    "capabilityGrantDraftId",
    "boundedTrustEvaluationResultId",
    "boundedPolicyEvaluationResultId",
    "userApprovalRequestDraftId",
    "userDecisionFixtureArtifactId",
    "applicationId",
    "capabilityName",
    "createdAt",
    "status",
    "outcome",
    "auditCorrelationId",
    "humanReadableSummary"
  ] as const) {
    if (!isNonEmptyString(candidate[field])) {
      errors.push(`${field} is required`);
    }
  }
  if (!isRecord(candidate.scope)) errors.push("scope is required");
  if (!isRecord(candidate.duration)) errors.push("duration is required");
  if (!Array.isArray(candidate.constraints)) errors.push("constraints must be an array");
  if (!Array.isArray(candidate.requirements)) errors.push("requirements must be an array");
  if (!Array.isArray(candidate.limitations)) errors.push("limitations must be an array");
  if (!Array.isArray(candidate.reasons)) errors.push("reasons must be an array");
  if (!isRecord(candidate.evidence)) errors.push("evidence is required");
  if (!isCapabilityActivationCandidateStatus(candidate.status)) {
    errors.push("status is invalid");
  }
  if (!isCapabilityActivationCandidateOutcome(candidate.outcome)) {
    errors.push("outcome is invalid");
  }
  if (candidate.status === "candidate_created") {
    errors.push("candidate must remain pending and must not use candidate_created as an active state");
  }
  if (!hasValidDateShape(candidate.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (candidate.expiresAt !== undefined && !hasValidDateShape(candidate.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  for (const [field, expected] of [
    ["fixtureOnlyUserDecision", true],
    ["productionUserConsentCollected", false],
    ["productionAuthenticationPerformed", false],
    ["grantsAuthority", false],
    ["activeCapabilityCreated", false],
    ["createsCapabilityGrant", false],
    ["sessionKeyIssued", false],
    ["authorizationCreated", false],
    ["createsAuthorizationPackage", false],
    ["allowsExecution", false],
    ["worldIdEnrollmentVerified", false],
    ["persisted", false]
  ] as const) {
    if (candidate[field] !== expected) {
      errors.push(`${field} must be ${String(expected)}`);
    }
  }
  const blockedFields = findBlockedFields(candidate);
  if (blockedFields.length > 0) {
    errors.push(`private material, production consent, active authority, or execution fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(candidate.metadata));
  return validation(errors);
}

function candidateStatus(
  policy: BoundedPolicyEvaluationResult
): CapabilityActivationCandidateStatus {
  if (policy.requirementSummary.requiresProductionPossessionVerification) {
    return "pending_production_authentication";
  }
  return "pending_production_consent";
}

function candidateReasons(
  status: CapabilityActivationCandidateStatus
): readonly CapabilityActivationCandidateReason[] {
  const reasons: CapabilityActivationCandidateReason[] = [
    "capability-draft-valid",
    "bounded-trust-result-valid",
    "bounded-policy-result-valid",
    "user-approval-request-draft-valid",
    "approved-fixture-valid",
    "fixture-approval-not-production-consent",
    "trust-limitations-preserved",
    "policy-limitations-preserved",
    "world-id-context-specific",
    "non-authoritative-candidate"
  ];
  if (status === "pending_production_authentication") {
    reasons.push("pending-production-authentication");
  } else if (status === "pending_capability_activation") {
    reasons.push("pending-capability-activation");
  } else {
    reasons.push("pending-production-consent");
  }
  return Object.freeze(reasons);
}

function mergedLimitations(
  trust: BoundedTrustEvaluationResult,
  policy: BoundedPolicyEvaluationResult,
  fixture: UserDecisionFixtureArtifact
): readonly CapabilityActivationCandidateLimitation[] {
  return Object.freeze([
    ...new Set<CapabilityActivationCandidateLimitation>([
      ...NON_AUTHORITATIVE_LIMITATIONS,
      ...trust.limitations,
      ...policy.limitations,
      ...fixture.limitations
    ])
  ]);
}

function scopeFromRequest(
  request: CapabilityActivationCandidateRequest
): CapabilityActivationCandidateScope {
  const requestedScope = request.requestedScope
    ?? request.userApprovalRequestDraft.requestedScope
    ?? request.capabilityGrantDraft.scope;
  const effectiveScope = request.effectiveScope
    ?? request.userApprovalRequestDraft.effectiveScope
    ?? requestedScope;
  return freezeRecord({
    requestedScope: requestedScope
      ? redactRuntimeMetadata(requestedScope).value as CapabilityScope
      : undefined,
    effectiveScope: effectiveScope
      ? redactRuntimeMetadata(effectiveScope).value as CapabilityScope
      : undefined,
    scopeRestricted: request.boundedPolicyEvaluationResult.requirementSummary.requiresScopeRestriction
  });
}

function durationFromRequest(
  request: CapabilityActivationCandidateRequest
): CapabilityActivationCandidateDuration {
  const requestedDurationSeconds = request.requestedDurationSeconds
    ?? request.userApprovalRequestDraft.requestedDurationSeconds;
  const effectiveDurationSeconds = request.effectiveDurationSeconds
    ?? request.userApprovalRequestDraft.effectiveDurationSeconds
    ?? requestedDurationSeconds;
  return Object.freeze({
    requestedDurationSeconds,
    effectiveDurationSeconds,
    durationRestricted: request.boundedPolicyEvaluationResult.requirementSummary.requiresDurationRestriction
  });
}

export function createCapabilityActivationCandidate(
  request: CapabilityActivationCandidateRequest
): CapabilityActivationCandidateResult {
  const validationResult = validateCapabilityActivationCandidateRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedCandidateError(validationResult.errors));
  }
  const capability = request.capabilityGrantDraft;
  const trust = request.boundedTrustEvaluationResult;
  const policy = request.boundedPolicyEvaluationResult;
  const approval = request.userApprovalRequestDraft;
  const fixture = request.userDecisionFixtureArtifact;
  const createdAt = request.createdAt ?? new Date().toISOString();
  const applicationId = request.applicationId ?? capability.applicationId;
  const sessionId = request.sessionId
    ?? capability.sessionId
    ?? trust.sessionId
    ?? policy.sessionId
    ?? approval.sessionId
    ?? fixture.sessionId;
  const ownerCommitment = request.ownerCommitment
    ?? trust.ownerCommitment
    ?? approval.ownerCommitment
    ?? fixture.ownerCommitment;
  const capabilityName = request.capabilityName ?? capability.capabilityName;
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    applicationId,
    sessionId ?? "",
    capability.capabilityGrantDraftId,
    fixture.userDecisionFixtureArtifactId,
    "capability-activation-candidate"
  ]);
  const status = candidateStatus(policy);
  const metadata = request.metadata
    ? redactRuntimeMetadata(request.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  const candidate: CapabilityActivationCandidate = Object.freeze({
    capabilityActivationCandidateId: `${auditCorrelationId}:capability-activation-candidate`,
    requestId: request.requestId,
    capabilityGrantDraftId: capability.capabilityGrantDraftId,
    boundedTrustEvaluationResultId: trust.boundedTrustEvaluationResultId,
    boundedPolicyEvaluationResultId: policy.boundedPolicyEvaluationResultId,
    userApprovalRequestDraftId: approval.userApprovalRequestDraftId,
    userDecisionFixtureArtifactId: fixture.userDecisionFixtureArtifactId,
    applicationId,
    sessionId,
    ownerCommitment,
    capabilityName,
    scope: scopeFromRequest(request),
    duration: durationFromRequest(request),
    constraints: Object.freeze([...capability.constraints].map(freezeRecord)),
    requirements: Object.freeze([...capability.requirements].map(freezeRecord)),
    limitations: mergedLimitations(trust, policy, fixture),
    evidence: Object.freeze({
      capabilityGrantDraftId: capability.capabilityGrantDraftId,
      boundedTrustEvaluationResultId: trust.boundedTrustEvaluationResultId,
      boundedPolicyEvaluationResultId: policy.boundedPolicyEvaluationResultId,
      userApprovalRequestDraftId: approval.userApprovalRequestDraftId,
      userDecisionFixtureArtifactId: fixture.userDecisionFixtureArtifactId,
      fixtureOnlyUserDecision: true,
      productionUserConsentCollected: false,
      productionAuthenticationPerformed: false,
      worldIdEnrollmentVerified: false
    }),
    createdAt,
    expiresAt: request.expiresAt ?? approval.expiresAt ?? capability.expiresAt,
    status,
    outcome: status,
    reasons: candidateReasons(status),
    auditCorrelationId,
    humanReadableSummary: request.humanReadableSummary
      ?? `Capability activation candidate ${request.requestId} is structurally eligible for future activation; no active capability was created.`,
    metadata,
    fixtureOnlyUserDecision: true,
    productionUserConsentCollected: false,
    productionAuthenticationPerformed: false,
    grantsAuthority: false,
    activeCapabilityCreated: false,
    createsCapabilityGrant: false,
    sessionKeyIssued: false,
    authorizationCreated: false,
    createsAuthorizationPackage: false,
    allowsExecution: false,
    worldIdEnrollmentVerified: false,
    persisted: false
  });
  return runtimeOk(candidate);
}

function emptyCollection(
  maxCandidateCount: number,
  candidates: readonly CapabilityActivationCandidate[] = []
): CapabilityActivationCandidateCollection {
  return Object.freeze({
    candidates: Object.freeze([...candidates]),
    count: candidates.length,
    maxCandidateCount
  });
}

function collectionResult(input: {
  readonly status: CapabilityActivationCandidateCollectionStatus;
  readonly candidates: readonly CapabilityActivationCandidate[];
  readonly maxCandidateCount: number;
  readonly candidate?: CapabilityActivationCandidate;
  readonly removedCandidate?: CapabilityActivationCandidate;
  readonly evictedCandidates?: readonly CapabilityActivationCandidate[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): CapabilityActivationCandidateCollectionResult {
  return Object.freeze({
    status: input.status,
    candidate: input.candidate,
    removedCandidate: input.removedCandidate,
    evictedCandidates: input.evictedCandidates,
    collection: emptyCollection(input.maxCandidateCount, input.candidates),
    errors: input.errors,
    reason: input.reason
  });
}

function matchesFilter(
  candidate: CapabilityActivationCandidate,
  filter: CapabilityActivationCandidateFilter
): boolean {
  if (filter.capabilityActivationCandidateId !== undefined && candidate.capabilityActivationCandidateId !== filter.capabilityActivationCandidateId) return false;
  if (filter.capabilityGrantDraftId !== undefined && candidate.capabilityGrantDraftId !== filter.capabilityGrantDraftId) return false;
  if (filter.boundedTrustEvaluationResultId !== undefined && candidate.boundedTrustEvaluationResultId !== filter.boundedTrustEvaluationResultId) return false;
  if (filter.boundedPolicyEvaluationResultId !== undefined && candidate.boundedPolicyEvaluationResultId !== filter.boundedPolicyEvaluationResultId) return false;
  if (filter.userApprovalRequestDraftId !== undefined && candidate.userApprovalRequestDraftId !== filter.userApprovalRequestDraftId) return false;
  if (filter.userDecisionFixtureArtifactId !== undefined && candidate.userDecisionFixtureArtifactId !== filter.userDecisionFixtureArtifactId) return false;
  if (filter.applicationId !== undefined && candidate.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && candidate.sessionId !== filter.sessionId) return false;
  if (filter.ownerCommitment !== undefined && candidate.ownerCommitment !== filter.ownerCommitment) return false;
  if (filter.capabilityName !== undefined && candidate.capabilityName !== filter.capabilityName) return false;
  if (filter.status !== undefined && candidate.status !== filter.status) return false;
  if (filter.outcome !== undefined && candidate.outcome !== filter.outcome) return false;
  if (filter.auditCorrelationId !== undefined && candidate.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(candidate.createdAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(candidate.createdAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryCapabilityActivationCandidateCollector(
  options: InMemoryCapabilityActivationCandidateCollectorOptions = {}
): CapabilityActivationCandidateCollector {
  const maxCandidateCount = Math.max(1, Math.floor(options.maxCandidateCount ?? 100));
  const candidates: CapabilityActivationCandidate[] = [];

  return Object.freeze({
    addCandidate(candidate: CapabilityActivationCandidate) {
      const validationResult = validateCapabilityActivationCandidateShape(candidate);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          candidates,
          maxCandidateCount,
          errors: validationResult.errors
        });
      }
      if (candidates.some((entry) => entry.capabilityActivationCandidateId === candidate.capabilityActivationCandidateId)) {
        return collectionResult({
          status: "rejected_duplicate",
          candidates,
          maxCandidateCount,
          candidate,
          reason: "capability activation candidate ID already exists"
        });
      }
      const evictedCandidates: CapabilityActivationCandidate[] = [];
      if (candidates.length >= maxCandidateCount) {
        const evicted = candidates.shift();
        if (evicted) {
          evictedCandidates.push(evicted);
        }
      }
      const frozenCandidate = freezeRecord(candidate);
      candidates.push(frozenCandidate);
      return collectionResult({
        status: evictedCandidates.length > 0 ? "evicted_oldest" : "collected",
        candidates,
        maxCandidateCount,
        candidate: frozenCandidate,
        evictedCandidates: evictedCandidates.length > 0
          ? Object.freeze(evictedCandidates)
          : undefined
      });
    },
    removeCandidate(capabilityActivationCandidateId: string) {
      const index = candidates.findIndex(
        (entry) => entry.capabilityActivationCandidateId === capabilityActivationCandidateId
      );
      if (index === -1) {
        return collectionResult({
          status: "not_found",
          candidates,
          maxCandidateCount
        });
      }
      const [removedCandidate] = candidates.splice(index, 1);
      return collectionResult({
        status: "removed",
        candidates,
        maxCandidateCount,
        removedCandidate
      });
    },
    clear() {
      candidates.splice(0, candidates.length);
      return collectionResult({
        status: "cleared",
        candidates,
        maxCandidateCount
      });
    },
    count() {
      return candidates.length;
    },
    getById(capabilityActivationCandidateId: string) {
      return candidates.find((entry) => entry.capabilityActivationCandidateId === capabilityActivationCandidateId);
    },
    getAll() {
      return Object.freeze([...candidates]);
    },
    query(query: CapabilityActivationCandidateQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? candidates
        : candidates.filter((candidate) => matchesFilter(candidate, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: CapabilityActivationCandidateFilter) {
      return Object.freeze(candidates.filter((candidate) => matchesFilter(candidate, filter)));
    }
  });
}
