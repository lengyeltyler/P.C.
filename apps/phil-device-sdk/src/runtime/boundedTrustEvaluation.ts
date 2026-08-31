import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  validatePossessionEvaluationResultShape,
  type PossessionEvaluationResult
} from "./possessionEvaluation.ts";
import {
  validatePublicTrustMetadataEvaluationResultShape,
  type PublicCredentialLifecycleStatus,
  type PublicTrustMetadataEvaluationResult
} from "./publicTrustMetadata.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import {
  validateTrustEvaluationDraftShape,
  type TrustEvaluationDraft
} from "./trustDrafts.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type BoundedTrustEvaluationContext =
  | "ordinary_runtime"
  | "recovery"
  | "canonical_phil_activation";

export type BoundedTrustEvaluationStatus =
  | "evaluated"
  | "validation_failed"
  | "malformed"
  | "unsupported";

export type BoundedTrustEvaluationOutcome =
  | "evaluation_sufficient_for_policy_review"
  | "metadata_insufficient"
  | "possession_evidence_insufficient"
  | "credential_lifecycle_ineligible"
  | "correlation_mismatch"
  | "fixture_only_evidence"
  | "pending_production_possession_verification"
  | "pending_credential_resolution"
  | "pending_device_resolution"
  | "expired"
  | "malformed"
  | "unsupported";

export type BoundedTrustEvaluationReason =
  | "trust-evaluation-draft-valid"
  | "public-metadata-evaluation-valid"
  | "possession-evaluation-valid"
  | "credential-lifecycle-active"
  | "credential-lifecycle-pending"
  | "credential-lifecycle-revoked"
  | "credential-lifecycle-archived"
  | "credential-lifecycle-rotated"
  | "credential-lifecycle-recovery-only"
  | "credential-lifecycle-unknown"
  | "metadata-sufficient-for-further-evaluation"
  | "metadata-insufficient-for-further-evaluation"
  | "fixture-possession-checks-satisfied"
  | "fixture-possession-checks-insufficient"
  | "fixture-only-evidence"
  | "production-possession-verification-required"
  | "world-id-enrollment-future-only"
  | "ordinary-runtime-does-not-require-world-id"
  | "recovery-context-allows-recovery-only-credential"
  | "non-authoritative-result"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type BoundedTrustResolutionRequirement =
  | "credential_resolution"
  | "device_resolution"
  | "production_possession_verification"
  | "policy_review"
  | "world_id_enrollment"
  | "recovery_policy_review";

export type BoundedTrustLimitation =
  | "fixture_only_evidence"
  | "no_production_authentication"
  | "no_production_possession_verification"
  | "credential_not_loaded_from_vault"
  | "counter_not_persisted"
  | "world_id_not_verified"
  | "no_trust_decision"
  | "no_capability_grant"
  | "no_authorization"
  | "no_policy_evaluation";

export interface BoundedTrustEvidenceSummary {
  readonly trustEvaluationDraftId: string;
  readonly publicTrustMetadataEvaluationId: string;
  readonly possessionEvaluationResultId: string;
  readonly metadataOutcome: PublicTrustMetadataEvaluationResult["outcome"];
  readonly metadataEligibleForFurtherEvaluation: boolean;
  readonly possessionOutcome: PossessionEvaluationResult["outcome"];
  readonly fixtureOnlyEvidence: true;
  readonly credentialLifecycleStatus: PublicCredentialLifecycleStatus;
}

export interface BoundedTrustLifecycleAssessment {
  readonly credentialLifecycleStatus: PublicCredentialLifecycleStatus;
  readonly eligibleForOrdinaryUse: boolean;
  readonly eligibleForRecoveryUse: boolean;
  readonly pendingCredentialResolution: boolean;
  readonly ineligible: boolean;
  readonly reason: BoundedTrustEvaluationReason;
}

export interface BoundedTrustEvaluationRequest {
  readonly requestId: string;
  readonly trustEvaluationDraft: TrustEvaluationDraft;
  readonly publicTrustMetadataEvaluation: PublicTrustMetadataEvaluationResult;
  readonly possessionEvaluationResult: PossessionEvaluationResult;
  readonly credentialLifecycleStatus: PublicCredentialLifecycleStatus;
  readonly evaluationContext?: BoundedTrustEvaluationContext;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly ownerCommitment?: Hex;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface BoundedTrustEvaluationResult {
  readonly boundedTrustEvaluationResultId: string;
  readonly requestId: string;
  readonly trustEvaluationDraftId: string;
  readonly publicTrustMetadataEvaluationId: string;
  readonly possessionEvaluationResultId: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly ownerCommitment?: Hex;
  readonly evaluationContext: BoundedTrustEvaluationContext;
  readonly status: BoundedTrustEvaluationStatus;
  readonly outcome: BoundedTrustEvaluationOutcome;
  readonly evidenceSummary: BoundedTrustEvidenceSummary;
  readonly lifecycleAssessment: BoundedTrustLifecycleAssessment;
  readonly resolutionRequirements: readonly BoundedTrustResolutionRequirement[];
  readonly limitations: readonly BoundedTrustLimitation[];
  readonly reasons: readonly BoundedTrustEvaluationReason[];
  readonly fixtureOnlyEvidence: true;
  readonly productionAuthenticationPerformed: false;
  readonly possessionVerifiedForProduction: false;
  readonly credentialLoadedFromVault: false;
  readonly counterPersisted: false;
  readonly worldIdEnrollmentVerified: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly eligibleForPolicyReview: boolean;
  readonly requiresProductionPossessionVerification: boolean;
  readonly requiresWorldIdEnrollment: boolean;
  readonly evaluatedAt: string;
  readonly auditCorrelationId: string;
  readonly persisted: false;
}

export type BoundedTrustEvaluationRuntimeResult =
  RuntimeResult<BoundedTrustEvaluationResult>;

export type BoundedTrustEvaluationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface BoundedTrustEvaluationFilter {
  readonly boundedTrustEvaluationResultId?: string;
  readonly requestId?: string;
  readonly trustEvaluationDraftId?: string;
  readonly publicTrustMetadataEvaluationId?: string;
  readonly possessionEvaluationResultId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly ownerCommitment?: Hex;
  readonly evaluationContext?: BoundedTrustEvaluationContext;
  readonly status?: BoundedTrustEvaluationStatus;
  readonly outcome?: BoundedTrustEvaluationOutcome;
  readonly eligibleForPolicyReview?: boolean;
  readonly requiresWorldIdEnrollment?: boolean;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface BoundedTrustEvaluationQuery {
  readonly filter?: BoundedTrustEvaluationFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface BoundedTrustEvaluationCollection {
  readonly results: readonly BoundedTrustEvaluationResult[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface BoundedTrustEvaluationCollectionResult {
  readonly status: BoundedTrustEvaluationCollectionStatus;
  readonly result?: BoundedTrustEvaluationResult;
  readonly removedResult?: BoundedTrustEvaluationResult;
  readonly evictedResults?: readonly BoundedTrustEvaluationResult[];
  readonly collection: BoundedTrustEvaluationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface BoundedTrustEvaluationResultCollector {
  addResult(result: BoundedTrustEvaluationResult): BoundedTrustEvaluationCollectionResult;
  removeResult(boundedTrustEvaluationResultId: string): BoundedTrustEvaluationCollectionResult;
  clear(): BoundedTrustEvaluationCollectionResult;
  count(): number;
  getById(boundedTrustEvaluationResultId: string): BoundedTrustEvaluationResult | undefined;
  getAll(): readonly BoundedTrustEvaluationResult[];
  query(query: BoundedTrustEvaluationQuery): readonly BoundedTrustEvaluationResult[];
  filter(filter: BoundedTrustEvaluationFilter): readonly BoundedTrustEvaluationResult[];
}

export interface InMemoryBoundedTrustEvaluationResultCollectorOptions {
  readonly maxResultCount?: number;
}

const BOUNDED_TRUST_EVALUATION_STATUSES = new Set<BoundedTrustEvaluationStatus>([
  "evaluated",
  "validation_failed",
  "malformed",
  "unsupported"
]);

const BOUNDED_TRUST_EVALUATION_OUTCOMES = new Set<BoundedTrustEvaluationOutcome>([
  "evaluation_sufficient_for_policy_review",
  "metadata_insufficient",
  "possession_evidence_insufficient",
  "credential_lifecycle_ineligible",
  "correlation_mismatch",
  "fixture_only_evidence",
  "pending_production_possession_verification",
  "pending_credential_resolution",
  "pending_device_resolution",
  "expired",
  "malformed",
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
  "assertionsecret",
  "webauthnprivatematerial",
  "trusted",
  "approved",
  "authenticated",
  "authorized",
  "capabilitygrant",
  "authorizationpackage",
  "authoritytoken",
  "worldidverified",
  "humanverified",
  "productionauthenticationperformed",
  "possessionverifiedforproduction",
  "credentialloadedfromvault"
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

function malformedBoundedTrustEvaluationError(
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "BOUNDED_TRUST_EVALUATION_INVALID",
    message: "bounded Trust evaluation request failed validation",
    boundary: "trust-manager",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isBoundedTrustEvaluationStatus(
  value: unknown
): value is BoundedTrustEvaluationStatus {
  return BOUNDED_TRUST_EVALUATION_STATUSES.has(value as BoundedTrustEvaluationStatus);
}

export function isBoundedTrustEvaluationOutcome(
  value: unknown
): value is BoundedTrustEvaluationOutcome {
  return BOUNDED_TRUST_EVALUATION_OUTCOMES.has(value as BoundedTrustEvaluationOutcome);
}

function isCredentialLifecycleStatus(value: unknown): value is PublicCredentialLifecycleStatus {
  return value === "active"
    || value === "pending"
    || value === "revoked"
    || value === "archived"
    || value === "recovery-only"
    || value === "rotated"
    || value === "unknown";
}

function isExpiredDate(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function correlationErrors(request: BoundedTrustEvaluationRequest): readonly string[] {
  const errors: string[] = [];
  const draft = request.trustEvaluationDraft;
  const metadata = request.publicTrustMetadataEvaluation;
  const possession = request.possessionEvaluationResult;

  if (metadata.trustEvaluationDraftId !== draft.trustEvaluationDraftId) {
    errors.push("publicTrustMetadataEvaluation.trustEvaluationDraftId must match trustEvaluationDraft.trustEvaluationDraftId");
  }
  if (possession.trustEvaluationDraftId !== draft.trustEvaluationDraftId) {
    errors.push("possessionEvaluationResult.trustEvaluationDraftId must match trustEvaluationDraft.trustEvaluationDraftId");
  }
  if (possession.publicTrustMetadataEvaluationId !== metadata.evaluationId) {
    errors.push("possessionEvaluationResult.publicTrustMetadataEvaluationId must match publicTrustMetadataEvaluation.evaluationId");
  }
  if (metadata.applicationId !== draft.applicationId || possession.applicationId !== draft.applicationId) {
    errors.push("applicationId must correlate across trust draft, metadata evaluation, and possession evaluation");
  }
  if (
    request.applicationId !== undefined
    && request.applicationId !== draft.applicationId
  ) {
    errors.push("request.applicationId must match trustEvaluationDraft.applicationId");
  }
  const sessionId = request.sessionId ?? draft.sessionId ?? metadata.sessionId ?? possession.sessionId;
  for (const [label, value] of [
    ["trustEvaluationDraft.sessionId", draft.sessionId],
    ["publicTrustMetadataEvaluation.sessionId", metadata.sessionId],
    ["possessionEvaluationResult.sessionId", possession.sessionId]
  ] as const) {
    if (sessionId !== undefined && value !== undefined && value !== sessionId) {
      errors.push(`${label} must match request/session correlation`);
    }
  }
  const credentialId = request.credentialId ?? draft.credentialId ?? metadata.credentialId ?? possession.credentialId;
  for (const [label, value] of [
    ["trustEvaluationDraft.credentialId", draft.credentialId],
    ["publicTrustMetadataEvaluation.credentialId", metadata.credentialId],
    ["possessionEvaluationResult.credentialId", possession.credentialId]
  ] as const) {
    if (credentialId !== undefined && value !== undefined && value !== credentialId) {
      errors.push(`${label} must match request/credential correlation`);
    }
  }
  const deviceId = request.deviceId ?? draft.deviceId ?? metadata.deviceId ?? possession.deviceId;
  for (const [label, value] of [
    ["trustEvaluationDraft.deviceId", draft.deviceId],
    ["publicTrustMetadataEvaluation.deviceId", metadata.deviceId],
    ["possessionEvaluationResult.deviceId", possession.deviceId]
  ] as const) {
    if (deviceId !== undefined && value !== undefined && value !== deviceId) {
      errors.push(`${label} must match request/device correlation`);
    }
  }
  const ownerCommitment = request.ownerCommitment
    ?? draft.ownerCommitment
    ?? metadata.ownerCommitment
    ?? possession.ownerCommitment;
  for (const [label, value] of [
    ["trustEvaluationDraft.ownerCommitment", draft.ownerCommitment],
    ["publicTrustMetadataEvaluation.ownerCommitment", metadata.ownerCommitment],
    ["possessionEvaluationResult.ownerCommitment", possession.ownerCommitment]
  ] as const) {
    if (ownerCommitment !== undefined && value !== undefined && value !== ownerCommitment) {
      errors.push(`${label} must match request/ownerCommitment correlation`);
    }
  }

  return Object.freeze(errors);
}

export function validateBoundedTrustEvaluationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["bounded Trust evaluation request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  const draftValidation = validateTrustEvaluationDraftShape(request.trustEvaluationDraft);
  if (!draftValidation.valid) {
    errors.push(...draftValidation.errors.map((error) => `trustEvaluationDraft.${error}`));
  }
  const metadataValidation = validatePublicTrustMetadataEvaluationResultShape(
    request.publicTrustMetadataEvaluation
  );
  if (!metadataValidation.valid) {
    errors.push(...metadataValidation.errors.map((error) => `publicTrustMetadataEvaluation.${error}`));
  }
  const possessionValidation = validatePossessionEvaluationResultShape(
    request.possessionEvaluationResult
  );
  if (!possessionValidation.valid) {
    errors.push(...possessionValidation.errors.map((error) => `possessionEvaluationResult.${error}`));
  }
  if (!isCredentialLifecycleStatus(request.credentialLifecycleStatus)) {
    errors.push("credentialLifecycleStatus is invalid");
  }
  if (
    request.evaluationContext !== undefined
    && request.evaluationContext !== "ordinary_runtime"
    && request.evaluationContext !== "recovery"
    && request.evaluationContext !== "canonical_phil_activation"
  ) {
    errors.push("evaluationContext is invalid");
  }
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (
    isRecord(request.possessionEvaluationResult)
    && (
      request.possessionEvaluationResult.productionAuthentication !== false
      || request.possessionEvaluationResult.verifiesProductionPossession !== false
      || request.possessionEvaluationResult.providesTrustDecision !== false
      || request.possessionEvaluationResult.grantsAuthority !== false
    )
  ) {
    errors.push("possessionEvaluationResult must not claim production authentication, production possession, trust decision, or authority");
  }
  if (
    isRecord(request.publicTrustMetadataEvaluation)
    && (
      request.publicTrustMetadataEvaluation.providesTrustDecision !== false
      || request.publicTrustMetadataEvaluation.grantsAuthority !== false
    )
  ) {
    errors.push("publicTrustMetadataEvaluation must not claim trust decision or authority");
  }
  if (
    isRecord(request.trustEvaluationDraft)
    && request.trustEvaluationDraft.providesTrustDecision !== false
  ) {
    errors.push("trustEvaluationDraft must not claim trust decision");
  }
  if (
    isRecord(request.publicTrustMetadataEvaluation)
    && Array.isArray(request.publicTrustMetadataEvaluation.reasons)
    && request.publicTrustMetadataEvaluation.reasons.includes("request-expired")
  ) {
    errors.push("publicTrustMetadataEvaluation is expired");
  }
  if (
    isRecord(request.trustEvaluationDraft)
    && typeof request.trustEvaluationDraft.expiresAt === "string"
    && isExpiredDate(request.trustEvaluationDraft.expiresAt)
  ) {
    errors.push("trustEvaluationDraft is expired");
  }
  if (
    isRecord(request.possessionEvaluationResult)
    && typeof request.possessionEvaluationResult.evaluatedAt === "string"
    && !hasValidDateShape(request.possessionEvaluationResult.evaluatedAt)
  ) {
    errors.push("possessionEvaluationResult.evaluatedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && isExpiredDate(request.expiresAt as string)) {
    errors.push("bounded Trust evaluation request is expired");
  }
  if (
    request.credentialLifecycleStatus !== undefined
    && isRecord(request.publicTrustMetadataEvaluation)
    && request.publicTrustMetadataEvaluation.outcome === "credential_status_ineligible"
    && request.credentialLifecycleStatus === "active"
  ) {
    errors.push("credentialLifecycleStatus is inconsistent with ineligible public metadata outcome");
  }

  if (draftValidation.valid && metadataValidation.valid && possessionValidation.valid) {
    errors.push(...correlationErrors(request as unknown as BoundedTrustEvaluationRequest));
  }

  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(request));
  return validation(errors);
}

export function validateBoundedTrustEvaluationResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) {
    return validation(["bounded Trust evaluation result must be an object"]);
  }
  if (!isNonEmptyString(result.boundedTrustEvaluationResultId)) {
    errors.push("boundedTrustEvaluationResultId is required");
  }
  if (!isNonEmptyString(result.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(result.trustEvaluationDraftId)) {
    errors.push("trustEvaluationDraftId is required");
  }
  if (!isNonEmptyString(result.publicTrustMetadataEvaluationId)) {
    errors.push("publicTrustMetadataEvaluationId is required");
  }
  if (!isNonEmptyString(result.possessionEvaluationResultId)) {
    errors.push("possessionEvaluationResultId is required");
  }
  if (!isNonEmptyString(result.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isBoundedTrustEvaluationStatus(result.status)) {
    errors.push("status is invalid");
  }
  if (!isBoundedTrustEvaluationOutcome(result.outcome)) {
    errors.push("outcome is invalid");
  }
  if (!isRecord(result.evidenceSummary)) {
    errors.push("evidenceSummary is required");
  }
  if (!isRecord(result.lifecycleAssessment)) {
    errors.push("lifecycleAssessment is required");
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
  if (result.fixtureOnlyEvidence !== true) {
    errors.push("fixtureOnlyEvidence must be true");
  }
  if (result.productionAuthenticationPerformed !== false) {
    errors.push("productionAuthenticationPerformed must be false");
  }
  if (result.possessionVerifiedForProduction !== false) {
    errors.push("possessionVerifiedForProduction must be false");
  }
  if (result.credentialLoadedFromVault !== false) {
    errors.push("credentialLoadedFromVault must be false");
  }
  if (result.counterPersisted !== false) {
    errors.push("counterPersisted must be false");
  }
  if (result.worldIdEnrollmentVerified !== false) {
    errors.push("worldIdEnrollmentVerified must be false");
  }
  if (result.providesTrustDecision !== false) {
    errors.push("providesTrustDecision must be false");
  }
  if (result.grantsAuthority !== false) {
    errors.push("grantsAuthority must be false");
  }
  if (typeof result.eligibleForPolicyReview !== "boolean") {
    errors.push("eligibleForPolicyReview must be boolean");
  }
  if (typeof result.requiresProductionPossessionVerification !== "boolean") {
    errors.push("requiresProductionPossessionVerification must be boolean");
  }
  if (typeof result.requiresWorldIdEnrollment !== "boolean") {
    errors.push("requiresWorldIdEnrollment must be boolean");
  }
  if (!hasValidDateShape(result.evaluatedAt)) {
    errors.push("evaluatedAt must be a parseable date string");
  }
  if (!isNonEmptyString(result.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  if (result.persisted !== false) {
    errors.push("persisted must be false");
  }
  const blockedFields = findBlockedFields(result);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(result));
  return validation(errors);
}

function lifecycleAssessment(
  lifecycle: PublicCredentialLifecycleStatus,
  context: BoundedTrustEvaluationContext
): BoundedTrustLifecycleAssessment {
  if (lifecycle === "active") {
    return Object.freeze({
      credentialLifecycleStatus: lifecycle,
      eligibleForOrdinaryUse: true,
      eligibleForRecoveryUse: true,
      pendingCredentialResolution: false,
      ineligible: false,
      reason: "credential-lifecycle-active"
    });
  }
  if (lifecycle === "pending" || lifecycle === "unknown") {
    return Object.freeze({
      credentialLifecycleStatus: lifecycle,
      eligibleForOrdinaryUse: false,
      eligibleForRecoveryUse: false,
      pendingCredentialResolution: true,
      ineligible: false,
      reason: lifecycle === "pending"
        ? "credential-lifecycle-pending"
        : "credential-lifecycle-unknown"
    });
  }
  if (lifecycle === "recovery-only") {
    return Object.freeze({
      credentialLifecycleStatus: lifecycle,
      eligibleForOrdinaryUse: false,
      eligibleForRecoveryUse: context === "recovery",
      pendingCredentialResolution: false,
      ineligible: context !== "recovery",
      reason: "credential-lifecycle-recovery-only"
    });
  }
  return Object.freeze({
    credentialLifecycleStatus: lifecycle,
    eligibleForOrdinaryUse: false,
    eligibleForRecoveryUse: false,
    pendingCredentialResolution: false,
    ineligible: true,
    reason: lifecycle === "revoked"
      ? "credential-lifecycle-revoked"
      : lifecycle === "archived"
        ? "credential-lifecycle-archived"
        : "credential-lifecycle-rotated"
  });
}

function addUnique<TValue extends string>(values: TValue[], value: TValue): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

function classifyOutcome(input: {
  readonly metadata: PublicTrustMetadataEvaluationResult;
  readonly possession: PossessionEvaluationResult;
  readonly lifecycle: BoundedTrustLifecycleAssessment;
  readonly context: BoundedTrustEvaluationContext;
  readonly reasons: BoundedTrustEvaluationReason[];
  readonly requirements: BoundedTrustResolutionRequirement[];
}): {
  readonly outcome: BoundedTrustEvaluationOutcome;
  readonly eligibleForPolicyReview: boolean;
} {
  const { metadata, possession, lifecycle, context, reasons, requirements } = input;

  if (metadata.requiresCredentialResolution || metadata.outcome === "pending_credential_resolution") {
    addUnique(reasons, "metadata-insufficient-for-further-evaluation");
    addUnique(requirements, "credential_resolution");
    return {
      outcome: "pending_credential_resolution",
      eligibleForPolicyReview: false
    };
  }
  if (metadata.requiresDeviceResolution || metadata.outcome === "pending_device_resolution") {
    addUnique(reasons, "metadata-insufficient-for-further-evaluation");
    addUnique(requirements, "device_resolution");
    return {
      outcome: "pending_device_resolution",
      eligibleForPolicyReview: false
    };
  }
  if (!metadata.eligibleForFurtherEvaluation || metadata.outcome !== "metadata_sufficient") {
    addUnique(reasons, "metadata-insufficient-for-further-evaluation");
    return {
      outcome: metadata.status === "unsupported" ? "unsupported" : "metadata_insufficient",
      eligibleForPolicyReview: false
    };
  }
  addUnique(reasons, "metadata-sufficient-for-further-evaluation");

  if (lifecycle.pendingCredentialResolution) {
    addUnique(requirements, "credential_resolution");
    return {
      outcome: "pending_credential_resolution",
      eligibleForPolicyReview: false
    };
  }
  if (lifecycle.ineligible) {
    if (lifecycle.credentialLifecycleStatus === "recovery-only" && context !== "recovery") {
      addUnique(requirements, "recovery_policy_review");
    }
    return {
      outcome: "credential_lifecycle_ineligible",
      eligibleForPolicyReview: false
    };
  }
  if (lifecycle.credentialLifecycleStatus === "recovery-only" && context === "recovery") {
    addUnique(reasons, "recovery-context-allows-recovery-only-credential");
    addUnique(requirements, "recovery_policy_review");
  }

  if (possession.outcome !== "fixture_possession_checks_satisfied") {
    addUnique(reasons, "fixture-possession-checks-insufficient");
    return {
      outcome: possession.outcome === "pending_production_verification"
        ? "pending_production_possession_verification"
        : "possession_evidence_insufficient",
      eligibleForPolicyReview: false
    };
  }
  addUnique(reasons, "fixture-possession-checks-satisfied");
  addUnique(reasons, "fixture-only-evidence");
  addUnique(reasons, "production-possession-verification-required");
  addUnique(requirements, "production_possession_verification");
  addUnique(requirements, "policy_review");

  if (context === "canonical_phil_activation") {
    addUnique(reasons, "world-id-enrollment-future-only");
    addUnique(requirements, "world_id_enrollment");
  } else {
    addUnique(reasons, "ordinary-runtime-does-not-require-world-id");
  }

  return {
    outcome: "evaluation_sufficient_for_policy_review",
    eligibleForPolicyReview: true
  };
}

const BOUNDED_TRUST_LIMITATIONS: readonly BoundedTrustLimitation[] = Object.freeze([
  "fixture_only_evidence",
  "no_production_authentication",
  "no_production_possession_verification",
  "credential_not_loaded_from_vault",
  "counter_not_persisted",
  "world_id_not_verified",
  "no_trust_decision",
  "no_capability_grant",
  "no_authorization",
  "no_policy_evaluation"
]);

export function evaluateBoundedTrustEvidence(
  request: BoundedTrustEvaluationRequest
): BoundedTrustEvaluationRuntimeResult {
  const validationResult = validateBoundedTrustEvaluationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedBoundedTrustEvaluationError(validationResult.errors));
  }

  const context = request.evaluationContext ?? "ordinary_runtime";
  const draft = request.trustEvaluationDraft;
  const metadata = request.publicTrustMetadataEvaluation;
  const possession = request.possessionEvaluationResult;
  const lifecycle = lifecycleAssessment(request.credentialLifecycleStatus, context);
  const reasons: BoundedTrustEvaluationReason[] = [
    "trust-evaluation-draft-valid",
    "public-metadata-evaluation-valid",
    "possession-evaluation-valid",
    lifecycle.reason,
    "non-authoritative-result"
  ];
  const resolutionRequirements: BoundedTrustResolutionRequirement[] = [];
  const classified = classifyOutcome({
    metadata,
    possession,
    lifecycle,
    context,
    reasons,
    requirements: resolutionRequirements
  });
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    draft.applicationId,
    draft.sessionId ?? "",
    draft.trustEvaluationDraftId,
    metadata.evaluationId,
    possession.possessionEvaluationResultId,
    "bounded-trust-evaluation"
  ]);
  const requiresWorldIdEnrollment = context === "canonical_phil_activation";
  const result: BoundedTrustEvaluationResult = Object.freeze({
    boundedTrustEvaluationResultId: `${auditCorrelationId}:bounded-trust-evaluation`,
    requestId: request.requestId,
    trustEvaluationDraftId: draft.trustEvaluationDraftId,
    publicTrustMetadataEvaluationId: metadata.evaluationId,
    possessionEvaluationResultId: possession.possessionEvaluationResultId,
    capabilityGrantDraftId: draft.capabilityGrantDraftId,
    applicationId: draft.applicationId,
    sessionId: request.sessionId ?? draft.sessionId ?? metadata.sessionId ?? possession.sessionId,
    credentialId: request.credentialId ?? draft.credentialId ?? metadata.credentialId ?? possession.credentialId,
    deviceId: request.deviceId ?? draft.deviceId ?? metadata.deviceId ?? possession.deviceId,
    ownerCommitment: request.ownerCommitment
      ?? draft.ownerCommitment
      ?? metadata.ownerCommitment
      ?? possession.ownerCommitment,
    evaluationContext: context,
    status: "evaluated",
    outcome: classified.outcome,
    evidenceSummary: Object.freeze({
      trustEvaluationDraftId: draft.trustEvaluationDraftId,
      publicTrustMetadataEvaluationId: metadata.evaluationId,
      possessionEvaluationResultId: possession.possessionEvaluationResultId,
      metadataOutcome: metadata.outcome,
      metadataEligibleForFurtherEvaluation: metadata.eligibleForFurtherEvaluation,
      possessionOutcome: possession.outcome,
      fixtureOnlyEvidence: true,
      credentialLifecycleStatus: request.credentialLifecycleStatus
    }),
    lifecycleAssessment: lifecycle,
    resolutionRequirements: Object.freeze(resolutionRequirements),
    limitations: BOUNDED_TRUST_LIMITATIONS,
    reasons: Object.freeze(reasons),
    fixtureOnlyEvidence: true,
    productionAuthenticationPerformed: false,
    possessionVerifiedForProduction: false,
    credentialLoadedFromVault: false,
    counterPersisted: false,
    worldIdEnrollmentVerified: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    eligibleForPolicyReview: classified.eligibleForPolicyReview,
    requiresProductionPossessionVerification:
      possession.outcome === "fixture_possession_checks_satisfied",
    requiresWorldIdEnrollment,
    evaluatedAt: new Date().toISOString(),
    auditCorrelationId,
    persisted: false
  });

  return runtimeOk(result);
}

function emptyCollection(
  maxResultCount: number,
  results: readonly BoundedTrustEvaluationResult[] = []
): BoundedTrustEvaluationCollection {
  return Object.freeze({
    results: Object.freeze([...results]),
    count: results.length,
    maxResultCount
  });
}

function collectionResult(input: {
  readonly status: BoundedTrustEvaluationCollectionStatus;
  readonly results: readonly BoundedTrustEvaluationResult[];
  readonly maxResultCount: number;
  readonly result?: BoundedTrustEvaluationResult;
  readonly removedResult?: BoundedTrustEvaluationResult;
  readonly evictedResults?: readonly BoundedTrustEvaluationResult[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): BoundedTrustEvaluationCollectionResult {
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
  result: BoundedTrustEvaluationResult,
  filter: BoundedTrustEvaluationFilter
): boolean {
  if (filter.boundedTrustEvaluationResultId !== undefined && result.boundedTrustEvaluationResultId !== filter.boundedTrustEvaluationResultId) return false;
  if (filter.requestId !== undefined && result.requestId !== filter.requestId) return false;
  if (filter.trustEvaluationDraftId !== undefined && result.trustEvaluationDraftId !== filter.trustEvaluationDraftId) return false;
  if (filter.publicTrustMetadataEvaluationId !== undefined && result.publicTrustMetadataEvaluationId !== filter.publicTrustMetadataEvaluationId) return false;
  if (filter.possessionEvaluationResultId !== undefined && result.possessionEvaluationResultId !== filter.possessionEvaluationResultId) return false;
  if (filter.applicationId !== undefined && result.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && result.sessionId !== filter.sessionId) return false;
  if (filter.credentialId !== undefined && result.credentialId !== filter.credentialId) return false;
  if (filter.deviceId !== undefined && result.deviceId !== filter.deviceId) return false;
  if (filter.ownerCommitment !== undefined && result.ownerCommitment !== filter.ownerCommitment) return false;
  if (filter.evaluationContext !== undefined && result.evaluationContext !== filter.evaluationContext) return false;
  if (filter.status !== undefined && result.status !== filter.status) return false;
  if (filter.outcome !== undefined && result.outcome !== filter.outcome) return false;
  if (filter.eligibleForPolicyReview !== undefined && result.eligibleForPolicyReview !== filter.eligibleForPolicyReview) return false;
  if (filter.requiresWorldIdEnrollment !== undefined && result.requiresWorldIdEnrollment !== filter.requiresWorldIdEnrollment) return false;
  if (filter.auditCorrelationId !== undefined && result.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(result.evaluatedAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(result.evaluatedAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryBoundedTrustEvaluationResultCollector(
  options: InMemoryBoundedTrustEvaluationResultCollectorOptions = {}
): BoundedTrustEvaluationResultCollector {
  const maxResultCount = Math.max(1, Math.floor(options.maxResultCount ?? 100));
  const results: BoundedTrustEvaluationResult[] = [];

  return Object.freeze({
    addResult(result: BoundedTrustEvaluationResult) {
      const validationResult = validateBoundedTrustEvaluationResultShape(result);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          results,
          maxResultCount,
          errors: validationResult.errors
        });
      }
      if (results.some((entry) => entry.boundedTrustEvaluationResultId === result.boundedTrustEvaluationResultId)) {
        return collectionResult({
          status: "rejected_duplicate",
          results,
          maxResultCount,
          result,
          reason: "bounded Trust evaluation result ID already exists"
        });
      }
      const evictedResults: BoundedTrustEvaluationResult[] = [];
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
    removeResult(boundedTrustEvaluationResultId: string) {
      const index = results.findIndex(
        (entry) => entry.boundedTrustEvaluationResultId === boundedTrustEvaluationResultId
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
    getById(boundedTrustEvaluationResultId: string) {
      return results.find(
        (entry) => entry.boundedTrustEvaluationResultId === boundedTrustEvaluationResultId
      );
    },
    getAll() {
      return Object.freeze([...results]);
    },
    query(query: BoundedTrustEvaluationQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? results
        : results.filter((result) => matchesFilter(result, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: BoundedTrustEvaluationFilter) {
      return Object.freeze(results.filter((result) => matchesFilter(result, filter)));
    }
  });
}
