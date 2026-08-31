import {
  validateBoundedPolicyEvaluationResultShape,
  type BoundedPolicyEvaluationResult
} from "./boundedPolicyEvaluation.ts";
import {
  validateBoundedTrustEvaluationResultShape,
  type BoundedTrustEvaluationResult
} from "./boundedTrustEvaluation.ts";
import {
  validateCapabilityGrantDraftShape,
  type CapabilityGrantDraft
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
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type UserDecisionFixtureStatus =
  | "fixture_recorded"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "expired";

export type UserDecisionFixtureOutcome =
  | "approve"
  | "deny"
  | "cancel"
  | "expired";

export type UserDecisionFixtureReason =
  | "approval-request-draft-valid"
  | "bounded-policy-result-valid"
  | "bounded-trust-result-valid"
  | "capability-draft-valid"
  | "fixture-outcome-recorded"
  | "fixture-approval-not-production-consent"
  | "draft-expired"
  | "non-authoritative-fixture"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type UserDecisionFixtureSource =
  | "developer_fixture"
  | "local_test_harness"
  | "unsupported";

export type UserDecisionFixtureLimitation =
  | "fixture_only"
  | "no_production_user_consent"
  | "no_authentication"
  | "no_biometric_verification"
  | "no_webauthn_execution"
  | "no_capability_grant"
  | "no_authorization"
  | "no_execution"
  | "no_persistence"
  | "no_world_id_verification";

export interface UserDecisionFixtureRequest {
  readonly requestId: string;
  readonly userApprovalRequestDraft: UserApprovalRequestDraft;
  readonly boundedPolicyEvaluationResult: BoundedPolicyEvaluationResult;
  readonly boundedTrustEvaluationResult: BoundedTrustEvaluationResult;
  readonly capabilityGrantDraft: CapabilityGrantDraft;
  readonly outcome: UserDecisionFixtureOutcome;
  readonly source?: UserDecisionFixtureSource;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly auditCorrelationId?: string;
  readonly recordedAt?: string;
  readonly reason?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserDecisionFixtureArtifact {
  readonly userDecisionFixtureArtifactId: string;
  readonly requestId: string;
  readonly userApprovalRequestDraftId: string;
  readonly boundedPolicyEvaluationResultId: string;
  readonly boundedTrustEvaluationResultId: string;
  readonly capabilityGrantDraftId: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly outcome: UserDecisionFixtureOutcome;
  readonly source: UserDecisionFixtureSource;
  readonly status: UserDecisionFixtureStatus;
  readonly recordedAt: string;
  readonly approvalDraftExpiresAt?: string;
  readonly reason?: string;
  readonly reasons: readonly UserDecisionFixtureReason[];
  readonly limitations: readonly UserDecisionFixtureLimitation[];
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly fixtureOnly: true;
  readonly productionUserConsentCollected: false;
  readonly authenticationPerformed: false;
  readonly biometricVerificationPerformed: false;
  readonly webauthnPerformed: false;
  readonly grantsAuthority: false;
  readonly createsCapabilityGrant: false;
  readonly createsAuthorization: false;
  readonly createsAuthorizationPackage: false;
  readonly allowsExecution: false;
  readonly worldIdVerified: false;
  readonly persisted: false;
}

export type UserDecisionFixtureResult = RuntimeResult<UserDecisionFixtureArtifact>;

export type UserDecisionFixtureCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface UserDecisionFixtureArtifactFilter {
  readonly userDecisionFixtureArtifactId?: string;
  readonly userApprovalRequestDraftId?: string;
  readonly boundedPolicyEvaluationResultId?: string;
  readonly boundedTrustEvaluationResultId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: string;
  readonly outcome?: UserDecisionFixtureOutcome;
  readonly source?: UserDecisionFixtureSource;
  readonly status?: UserDecisionFixtureStatus;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface UserDecisionFixtureArtifactQuery {
  readonly filter?: UserDecisionFixtureArtifactFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface UserDecisionFixtureArtifactCollection {
  readonly artifacts: readonly UserDecisionFixtureArtifact[];
  readonly count: number;
  readonly maxArtifactCount: number;
}

export interface UserDecisionFixtureArtifactCollectionResult {
  readonly status: UserDecisionFixtureCollectionStatus;
  readonly artifact?: UserDecisionFixtureArtifact;
  readonly removedArtifact?: UserDecisionFixtureArtifact;
  readonly evictedArtifacts?: readonly UserDecisionFixtureArtifact[];
  readonly collection: UserDecisionFixtureArtifactCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface UserDecisionFixtureArtifactCollector {
  addArtifact(artifact: UserDecisionFixtureArtifact): UserDecisionFixtureArtifactCollectionResult;
  removeArtifact(userDecisionFixtureArtifactId: string): UserDecisionFixtureArtifactCollectionResult;
  clear(): UserDecisionFixtureArtifactCollectionResult;
  count(): number;
  getById(userDecisionFixtureArtifactId: string): UserDecisionFixtureArtifact | undefined;
  getAll(): readonly UserDecisionFixtureArtifact[];
  query(query: UserDecisionFixtureArtifactQuery): readonly UserDecisionFixtureArtifact[];
  filter(filter: UserDecisionFixtureArtifactFilter): readonly UserDecisionFixtureArtifact[];
}

export interface InMemoryUserDecisionFixtureArtifactCollectorOptions {
  readonly maxArtifactCount?: number;
}

const FIXTURE_STATUSES = new Set<UserDecisionFixtureStatus>([
  "fixture_recorded",
  "validation_failed",
  "malformed",
  "unsupported",
  "expired"
]);

const FIXTURE_OUTCOMES = new Set<UserDecisionFixtureOutcome>([
  "approve",
  "deny",
  "cancel",
  "expired"
]);

const FIXTURE_SOURCES = new Set<UserDecisionFixtureSource>([
  "developer_fixture",
  "local_test_harness",
  "unsupported"
]);

const PENDING_APPROVAL_DRAFT_STATUSES = new Set([
  "pending_user_presentation",
  "pending_user_decision"
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
  "biometricdata",
  "rawbiometricdata",
  "webauthnpayload",
  "webauthnassertion",
  "authenticatordata",
  "clientdatajson",
  "worldidproof",
  "authorizationpackage",
  "adapterpayload",
  "capabilitygrant",
  "authoritytoken",
  "productionuserconsentcollected",
  "authenticationperformed",
  "biometricverificationperformed",
  "webauthnperformed",
  "worldidverified",
  "grantsauthority",
  "createsauthorization",
  "createsauthorizationpackage",
  "allowsexecution",
  "persisted"
]);

const NON_AUTHORITATIVE_LIMITATIONS: readonly UserDecisionFixtureLimitation[] = Object.freeze([
  "fixture_only",
  "no_production_user_consent",
  "no_authentication",
  "no_biometric_verification",
  "no_webauthn_execution",
  "no_capability_grant",
  "no_authorization",
  "no_execution",
  "no_persistence",
  "no_world_id_verification"
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

function isExpiredAt(expiresAt: string | undefined, recordedAt: string): boolean {
  return expiresAt !== undefined && Date.parse(expiresAt) <= Date.parse(recordedAt);
}

function malformedFixtureError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "USER_DECISION_FIXTURE_ARTIFACT_INVALID",
    message: "user decision fixture request failed validation",
    boundary: "runtime-api",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isUserDecisionFixtureStatus(
  value: unknown
): value is UserDecisionFixtureStatus {
  return FIXTURE_STATUSES.has(value as UserDecisionFixtureStatus);
}

export function isUserDecisionFixtureOutcome(
  value: unknown
): value is UserDecisionFixtureOutcome {
  return FIXTURE_OUTCOMES.has(value as UserDecisionFixtureOutcome);
}

export function validateUserDecisionFixtureRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["user decision fixture request must be an object"]);
  }

  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  if (!isUserDecisionFixtureOutcome(request.outcome)) {
    errors.push("outcome is invalid");
  }
  if (request.source !== undefined && !FIXTURE_SOURCES.has(request.source as UserDecisionFixtureSource)) {
    errors.push("source is invalid");
  }
  if (request.source === "unsupported") {
    errors.push("unsupported fixture source cannot record a user decision fixture artifact");
  }
  if (request.recordedAt !== undefined && !hasValidDateShape(request.recordedAt)) {
    errors.push("recordedAt must be a parseable date string");
  }

  const approvalValidation = validateUserApprovalRequestDraftShape(
    request.userApprovalRequestDraft
  );
  if (!approvalValidation.valid) {
    errors.push(...approvalValidation.errors.map((error) => `userApprovalRequestDraft.${error}`));
  }
  const policyValidation = validateBoundedPolicyEvaluationResultShape(
    request.boundedPolicyEvaluationResult
  );
  if (!policyValidation.valid) {
    errors.push(...policyValidation.errors.map((error) => `boundedPolicyEvaluationResult.${error}`));
  }
  const trustValidation = validateBoundedTrustEvaluationResultShape(
    request.boundedTrustEvaluationResult
  );
  if (!trustValidation.valid) {
    errors.push(...trustValidation.errors.map((error) => `boundedTrustEvaluationResult.${error}`));
  }
  const capabilityValidation = validateCapabilityGrantDraftShape(request.capabilityGrantDraft);
  if (!capabilityValidation.valid) {
    errors.push(...capabilityValidation.errors.map((error) => `capabilityGrantDraft.${error}`));
  }

  if (
    approvalValidation.valid
    && policyValidation.valid
    && trustValidation.valid
    && capabilityValidation.valid
  ) {
    const approval = request.userApprovalRequestDraft as UserApprovalRequestDraft;
    const policy = request.boundedPolicyEvaluationResult as BoundedPolicyEvaluationResult;
    const trust = request.boundedTrustEvaluationResult as BoundedTrustEvaluationResult;
    const capability = request.capabilityGrantDraft as CapabilityGrantDraft;
    const recordedAt = request.recordedAt as string | undefined ?? new Date().toISOString();
    const approvalExpired = approval.status === "expired"
      || approval.outcome === "expired"
      || isExpiredAt(approval.expiresAt, recordedAt);

    if (approval.capabilityGrantDraftId !== capability.capabilityGrantDraftId) {
      errors.push("userApprovalRequestDraft must correlate with capabilityGrantDraft.capabilityGrantDraftId");
    }
    if (approval.boundedPolicyEvaluationResultId !== policy.boundedPolicyEvaluationResultId) {
      errors.push("userApprovalRequestDraft must correlate with boundedPolicyEvaluationResult.boundedPolicyEvaluationResultId");
    }
    if (approval.boundedTrustEvaluationResultId !== trust.boundedTrustEvaluationResultId) {
      errors.push("userApprovalRequestDraft must correlate with boundedTrustEvaluationResult.boundedTrustEvaluationResultId");
    }
    if (policy.capabilityGrantDraftId !== capability.capabilityGrantDraftId) {
      errors.push("boundedPolicyEvaluationResult must correlate with capabilityGrantDraft.capabilityGrantDraftId");
    }
    if (policy.boundedTrustEvaluationResultId !== trust.boundedTrustEvaluationResultId) {
      errors.push("boundedPolicyEvaluationResult must correlate with boundedTrustEvaluationResult.boundedTrustEvaluationResultId");
    }
    if (
      trust.capabilityGrantDraftId !== undefined
      && trust.capabilityGrantDraftId !== capability.capabilityGrantDraftId
    ) {
      errors.push("boundedTrustEvaluationResult must correlate with capabilityGrantDraft.capabilityGrantDraftId");
    }
    const applicationId = request.applicationId as string | undefined ?? approval.applicationId;
    if (
      approval.applicationId !== applicationId
      || policy.applicationId !== applicationId
      || trust.applicationId !== applicationId
      || capability.applicationId !== applicationId
    ) {
      errors.push("applicationId must correlate across approval draft, policy result, trust result, and capability draft");
    }
    const sessionId = request.sessionId as string | undefined
      ?? approval.sessionId
      ?? policy.sessionId
      ?? trust.sessionId
      ?? capability.sessionId;
    for (const [label, value] of [
      ["userApprovalRequestDraft.sessionId", approval.sessionId],
      ["boundedPolicyEvaluationResult.sessionId", policy.sessionId],
      ["boundedTrustEvaluationResult.sessionId", trust.sessionId],
      ["capabilityGrantDraft.sessionId", capability.sessionId]
    ] as const) {
      if (sessionId !== undefined && value !== undefined && value !== sessionId) {
        errors.push(`${label} must match request/session correlation`);
      }
    }
    const ownerCommitment = request.ownerCommitment as string | undefined
      ?? approval.ownerCommitment
      ?? trust.ownerCommitment;
    if (
      ownerCommitment !== undefined
      && approval.ownerCommitment !== undefined
      && approval.ownerCommitment !== ownerCommitment
    ) {
      errors.push("ownerCommitment must match userApprovalRequestDraft.ownerCommitment");
    }
    if (
      ownerCommitment !== undefined
      && trust.ownerCommitment !== undefined
      && trust.ownerCommitment !== ownerCommitment
    ) {
      errors.push("ownerCommitment must match boundedTrustEvaluationResult.ownerCommitment");
    }
    if (approval.grantsAuthority !== false || approval.collectsUserDecision !== false) {
      errors.push("userApprovalRequestDraft must remain non-authoritative and must not contain a user decision");
    }
    if (!PENDING_APPROVAL_DRAFT_STATUSES.has(approval.status) && request.outcome !== "expired") {
      errors.push("active fixture outcomes require a pending user approval request draft");
    }
    if (request.outcome === "approve" && approvalExpired) {
      errors.push("approve fixture cannot be recorded against an expired approval request draft");
    }
    if ((request.outcome === "deny" || request.outcome === "cancel") && approvalExpired) {
      errors.push(`${request.outcome} fixture cannot be recorded against an expired approval request draft`);
    }
    if (request.outcome === "expired" && !approvalExpired) {
      errors.push("expired fixture outcome requires an actually expired approval request draft");
    }
  }

  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material, production consent, active authority, or execution fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(request.metadata));
  return validation(errors);
}

export function validateUserDecisionFixtureArtifactShape(
  artifact: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(artifact)) {
    return validation(["user decision fixture artifact must be an object"]);
  }
  for (const field of [
    "userDecisionFixtureArtifactId",
    "requestId",
    "userApprovalRequestDraftId",
    "boundedPolicyEvaluationResultId",
    "boundedTrustEvaluationResultId",
    "capabilityGrantDraftId",
    "applicationId",
    "outcome",
    "source",
    "status",
    "recordedAt",
    "auditCorrelationId",
    "humanReadableSummary"
  ] as const) {
    if (!isNonEmptyString(artifact[field])) {
      errors.push(`${field} is required`);
    }
  }
  if (!isUserDecisionFixtureOutcome(artifact.outcome)) {
    errors.push("outcome is invalid");
  }
  if (!FIXTURE_SOURCES.has(artifact.source as UserDecisionFixtureSource)) {
    errors.push("source is invalid");
  }
  if (!isUserDecisionFixtureStatus(artifact.status)) {
    errors.push("status is invalid");
  }
  if (artifact.source === "unsupported") {
    errors.push("source must not be unsupported");
  }
  if (!hasValidDateShape(artifact.recordedAt)) {
    errors.push("recordedAt must be a parseable date string");
  }
  if (artifact.approvalDraftExpiresAt !== undefined && !hasValidDateShape(artifact.approvalDraftExpiresAt)) {
    errors.push("approvalDraftExpiresAt must be a parseable date string");
  }
  if (!Array.isArray(artifact.reasons)) {
    errors.push("reasons must be an array");
  }
  if (!Array.isArray(artifact.limitations)) {
    errors.push("limitations must be an array");
  }
  for (const [field, expected] of [
    ["fixtureOnly", true],
    ["productionUserConsentCollected", false],
    ["authenticationPerformed", false],
    ["biometricVerificationPerformed", false],
    ["webauthnPerformed", false],
    ["grantsAuthority", false],
    ["createsCapabilityGrant", false],
    ["createsAuthorization", false],
    ["createsAuthorizationPackage", false],
    ["allowsExecution", false],
    ["worldIdVerified", false],
    ["persisted", false]
  ] as const) {
    if (artifact[field] !== expected) {
      errors.push(`${field} must be ${String(expected)}`);
    }
  }
  const blockedFields = findBlockedFields(artifact);
  if (blockedFields.length > 0) {
    errors.push(`private material, production consent, active authority, or execution fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(artifact.metadata));
  return validation(errors);
}

function statusForOutcome(outcome: UserDecisionFixtureOutcome): UserDecisionFixtureStatus {
  return outcome === "expired" ? "expired" : "fixture_recorded";
}

function reasonsForOutcome(outcome: UserDecisionFixtureOutcome): readonly UserDecisionFixtureReason[] {
  const reasons: UserDecisionFixtureReason[] = [
    "approval-request-draft-valid",
    "bounded-policy-result-valid",
    "bounded-trust-result-valid",
    "capability-draft-valid",
    "non-authoritative-fixture"
  ];
  if (outcome === "expired") {
    reasons.push("draft-expired");
  } else {
    reasons.push("fixture-outcome-recorded");
  }
  if (outcome === "approve") {
    reasons.push("fixture-approval-not-production-consent");
  }
  return Object.freeze(reasons);
}

export function createUserDecisionFixtureArtifact(
  request: UserDecisionFixtureRequest
): UserDecisionFixtureResult {
  const validationResult = validateUserDecisionFixtureRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedFixtureError(validationResult.errors));
  }
  const approval = request.userApprovalRequestDraft;
  const policy = request.boundedPolicyEvaluationResult;
  const trust = request.boundedTrustEvaluationResult;
  const capability = request.capabilityGrantDraft;
  const recordedAt = request.recordedAt ?? new Date().toISOString();
  const applicationId = request.applicationId ?? approval.applicationId;
  const sessionId = request.sessionId
    ?? approval.sessionId
    ?? policy.sessionId
    ?? trust.sessionId
    ?? capability.sessionId;
  const ownerCommitment = request.ownerCommitment ?? approval.ownerCommitment ?? trust.ownerCommitment;
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    applicationId,
    sessionId ?? "",
    approval.userApprovalRequestDraftId,
    request.outcome,
    "user-decision-fixture"
  ]);
  const metadata = request.metadata
    ? redactRuntimeMetadata(request.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  const artifact: UserDecisionFixtureArtifact = Object.freeze({
    userDecisionFixtureArtifactId: `${auditCorrelationId}:user-decision-fixture-artifact`,
    requestId: request.requestId,
    userApprovalRequestDraftId: approval.userApprovalRequestDraftId,
    boundedPolicyEvaluationResultId: policy.boundedPolicyEvaluationResultId,
    boundedTrustEvaluationResultId: trust.boundedTrustEvaluationResultId,
    capabilityGrantDraftId: capability.capabilityGrantDraftId,
    applicationId,
    sessionId,
    ownerCommitment,
    outcome: request.outcome,
    source: request.source ?? "developer_fixture",
    status: statusForOutcome(request.outcome),
    recordedAt,
    approvalDraftExpiresAt: approval.expiresAt,
    reason: request.reason,
    reasons: reasonsForOutcome(request.outcome),
    limitations: NON_AUTHORITATIVE_LIMITATIONS,
    auditCorrelationId,
    humanReadableSummary: request.humanReadableSummary
      ?? `Local ${request.outcome} fixture recorded for approval draft ${approval.userApprovalRequestDraftId}; no production consent or authority was created.`,
    metadata,
    fixtureOnly: true,
    productionUserConsentCollected: false,
    authenticationPerformed: false,
    biometricVerificationPerformed: false,
    webauthnPerformed: false,
    grantsAuthority: false,
    createsCapabilityGrant: false,
    createsAuthorization: false,
    createsAuthorizationPackage: false,
    allowsExecution: false,
    worldIdVerified: false,
    persisted: false
  });
  return runtimeOk(artifact);
}

function emptyCollection(
  maxArtifactCount: number,
  artifacts: readonly UserDecisionFixtureArtifact[] = []
): UserDecisionFixtureArtifactCollection {
  return Object.freeze({
    artifacts: Object.freeze([...artifacts]),
    count: artifacts.length,
    maxArtifactCount
  });
}

function collectionResult(input: {
  readonly status: UserDecisionFixtureCollectionStatus;
  readonly artifacts: readonly UserDecisionFixtureArtifact[];
  readonly maxArtifactCount: number;
  readonly artifact?: UserDecisionFixtureArtifact;
  readonly removedArtifact?: UserDecisionFixtureArtifact;
  readonly evictedArtifacts?: readonly UserDecisionFixtureArtifact[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): UserDecisionFixtureArtifactCollectionResult {
  return Object.freeze({
    status: input.status,
    artifact: input.artifact,
    removedArtifact: input.removedArtifact,
    evictedArtifacts: input.evictedArtifacts,
    collection: emptyCollection(input.maxArtifactCount, input.artifacts),
    errors: input.errors,
    reason: input.reason
  });
}

function matchesFilter(
  artifact: UserDecisionFixtureArtifact,
  filter: UserDecisionFixtureArtifactFilter
): boolean {
  if (filter.userDecisionFixtureArtifactId !== undefined && artifact.userDecisionFixtureArtifactId !== filter.userDecisionFixtureArtifactId) return false;
  if (filter.userApprovalRequestDraftId !== undefined && artifact.userApprovalRequestDraftId !== filter.userApprovalRequestDraftId) return false;
  if (filter.boundedPolicyEvaluationResultId !== undefined && artifact.boundedPolicyEvaluationResultId !== filter.boundedPolicyEvaluationResultId) return false;
  if (filter.boundedTrustEvaluationResultId !== undefined && artifact.boundedTrustEvaluationResultId !== filter.boundedTrustEvaluationResultId) return false;
  if (filter.capabilityGrantDraftId !== undefined && artifact.capabilityGrantDraftId !== filter.capabilityGrantDraftId) return false;
  if (filter.applicationId !== undefined && artifact.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && artifact.sessionId !== filter.sessionId) return false;
  if (filter.ownerCommitment !== undefined && artifact.ownerCommitment !== filter.ownerCommitment) return false;
  if (filter.outcome !== undefined && artifact.outcome !== filter.outcome) return false;
  if (filter.source !== undefined && artifact.source !== filter.source) return false;
  if (filter.status !== undefined && artifact.status !== filter.status) return false;
  if (filter.auditCorrelationId !== undefined && artifact.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(artifact.recordedAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(artifact.recordedAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryUserDecisionFixtureArtifactCollector(
  options: InMemoryUserDecisionFixtureArtifactCollectorOptions = {}
): UserDecisionFixtureArtifactCollector {
  const maxArtifactCount = Math.max(1, Math.floor(options.maxArtifactCount ?? 100));
  const artifacts: UserDecisionFixtureArtifact[] = [];

  return Object.freeze({
    addArtifact(artifact: UserDecisionFixtureArtifact) {
      const validationResult = validateUserDecisionFixtureArtifactShape(artifact);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          artifacts,
          maxArtifactCount,
          errors: validationResult.errors
        });
      }
      if (artifacts.some((entry) => entry.userDecisionFixtureArtifactId === artifact.userDecisionFixtureArtifactId)) {
        return collectionResult({
          status: "rejected_duplicate",
          artifacts,
          maxArtifactCount,
          artifact,
          reason: "user decision fixture artifact ID already exists"
        });
      }
      const evictedArtifacts: UserDecisionFixtureArtifact[] = [];
      if (artifacts.length >= maxArtifactCount) {
        const evicted = artifacts.shift();
        if (evicted) {
          evictedArtifacts.push(evicted);
        }
      }
      const frozenArtifact = freezeRecord(artifact);
      artifacts.push(frozenArtifact);
      return collectionResult({
        status: evictedArtifacts.length > 0 ? "evicted_oldest" : "collected",
        artifacts,
        maxArtifactCount,
        artifact: frozenArtifact,
        evictedArtifacts: evictedArtifacts.length > 0
          ? Object.freeze(evictedArtifacts)
          : undefined
      });
    },
    removeArtifact(userDecisionFixtureArtifactId: string) {
      const index = artifacts.findIndex(
        (entry) => entry.userDecisionFixtureArtifactId === userDecisionFixtureArtifactId
      );
      if (index === -1) {
        return collectionResult({
          status: "not_found",
          artifacts,
          maxArtifactCount
        });
      }
      const [removedArtifact] = artifacts.splice(index, 1);
      return collectionResult({
        status: "removed",
        artifacts,
        maxArtifactCount,
        removedArtifact
      });
    },
    clear() {
      artifacts.splice(0, artifacts.length);
      return collectionResult({
        status: "cleared",
        artifacts,
        maxArtifactCount
      });
    },
    count() {
      return artifacts.length;
    },
    getById(userDecisionFixtureArtifactId: string) {
      return artifacts.find((entry) => entry.userDecisionFixtureArtifactId === userDecisionFixtureArtifactId);
    },
    getAll() {
      return Object.freeze([...artifacts]);
    },
    query(query: UserDecisionFixtureArtifactQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? artifacts
        : artifacts.filter((artifact) => matchesFilter(artifact, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: UserDecisionFixtureArtifactFilter) {
      return Object.freeze(artifacts.filter((artifact) => matchesFilter(artifact, filter)));
    }
  });
}
