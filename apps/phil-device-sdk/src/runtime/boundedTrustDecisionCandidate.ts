import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type {
  AuthenticationProviderAssurance,
  ProductionAuthenticationPurpose
} from "./authenticationEvidence.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { UserSessionLifecycleState } from "./sessionLifecycle.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  TrustManagerProductionVerificationCounterStatus,
  TrustManagerProductionVerificationResultValue
} from "./trustManagerProductionVerification.ts";
import { validateTrustManagerProductionVerificationResultShape } from "./trustManagerProductionVerification.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type BoundedTrustDecisionCredentialLifecycleStatus =
  | "active"
  | "pending"
  | "revoked"
  | "archived"
  | "rotated"
  | "recovery-only"
  | "unknown";

export type BoundedTrustDecisionCandidateStatus =
  | "candidate_created"
  | "candidate_rejected"
  | "candidate_malformed"
  | "candidate_unsupported";

export type BoundedTrustDecisionCandidateOutcome =
  | "candidate_created"
  | "verification_ineligible"
  | "credential_lifecycle_ineligible"
  | "session_state_ineligible"
  | "assurance_insufficient"
  | "purpose_ineligible"
  | "correlation_mismatch"
  | "evidence_expired"
  | "evidence_replayed"
  | "counter_persistence_required"
  | "pending_policy_review"
  | "pending_user_approval"
  | "malformed"
  | "unsupported";

export type BoundedTrustDecisionCandidateReason =
  | "production-verification-result-required"
  | "production-assertion-verified"
  | "production-verifier-used"
  | "fixture-only-evidence-rejected"
  | "credential-lifecycle-active"
  | "credential-lifecycle-pending"
  | "credential-lifecycle-revoked"
  | "credential-lifecycle-archived"
  | "credential-lifecycle-rotated"
  | "credential-lifecycle-recovery-only"
  | "credential-lifecycle-unknown"
  | "recovery-context-required"
  | "recovery-context-allows-recovery-only-credential"
  | "session-state-eligible"
  | "session-state-ineligible"
  | "assurance-requirements-met"
  | "assurance-insufficient"
  | "counter-persistence-required"
  | "counter-rollback-rejected"
  | "counter-clone-risk-rejected"
  | "world-id-enrollment-required-for-canonical-activation"
  | "pending-policy-review"
  | "pending-user-approval"
  | "no-active-trust-decision"
  | "no-authority"
  | "no-vault-access"
  | "no-persistence"
  | (string & {});

export type BoundedTrustDecisionCandidateRequirement =
  | "production_assertion_verification"
  | "credential_lifecycle_eligible"
  | "session_context_eligible"
  | "assurance_met"
  | "counter_persistence"
  | "policy_review"
  | "user_approval"
  | "world_id_enrollment";

export type BoundedTrustDecisionCandidateLimitation =
  | "candidate_only"
  | "counter_not_persisted"
  | "no_authoritative_trust_decision"
  | "no_capability_grant"
  | "no_authorization"
  | "no_policy_execution"
  | "no_user_approval"
  | "no_world_id_verification"
  | "no_vault_access"
  | "no_persistence";

export interface BoundedTrustDecisionCandidateEvidence {
  readonly productionVerificationResultId: string;
  readonly trustManagerVerificationInputId?: string;
  readonly verifiedEvidenceReferenceId?: string;
  readonly productionAssertionVerified: true;
  readonly productionVerifierUsed: true;
  readonly fixtureOnlyEvidence: false;
  readonly credentialSafeReference: Hex;
  readonly providerKind: "webauthn_passkey";
  readonly publicKeyAlgorithm: "ES256";
  readonly userPresenceVerified: true;
  readonly userVerificationVerified: true;
  readonly challengeVerified: true;
  readonly originVerified: true;
  readonly rpIdHashVerified: true;
  readonly signatureVerified: true;
  readonly counterStatus: TrustManagerProductionVerificationCounterStatus;
  readonly counterPersisted: false;
  readonly rawAssertionMaterialIncluded: false;
  readonly publicKeyBytesIncluded: false;
}

export interface BoundedTrustDecisionCandidateCorrelation {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly providerKind: "webauthn_passkey";
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly auditCorrelationId: string;
}

export interface BoundedTrustDecisionCandidateAssurance {
  readonly requestedAssurance: readonly AuthenticationProviderAssurance[];
  readonly metAssurance: readonly AuthenticationProviderAssurance[];
  readonly userPresenceRequired: boolean;
  readonly userPresenceMet: boolean;
  readonly userVerificationRequired: boolean;
  readonly userVerificationMet: boolean;
  readonly phishingResistantRequired: boolean;
  readonly phishingResistantMet: boolean;
  readonly sufficient: boolean;
}

export interface BoundedTrustDecisionCandidateLifecycleAssessment {
  readonly credentialLifecycleStatus: BoundedTrustDecisionCredentialLifecycleStatus;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly recoveryContext: boolean;
  readonly canonicalPhilActivationContext: boolean;
  readonly eligibleForOrdinaryUse: boolean;
  readonly eligibleForRecoveryUse: boolean;
  readonly eligibleForCandidate: boolean;
  readonly requiresWorldIdEnrollment: boolean;
  readonly reason: BoundedTrustDecisionCandidateReason;
}

export interface BoundedTrustDecisionCandidateRequest {
  readonly requestId: string;
  readonly productionVerificationResult: TrustManagerProductionVerificationResultValue;
  readonly credentialLifecycleStatus: BoundedTrustDecisionCredentialLifecycleStatus;
  readonly credentialId: string;
  readonly providerKind: "webauthn_passkey";
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly lifecycleState: UserSessionLifecycleState;
  readonly applicationId: ApplicationId;
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly requestedAssurance: readonly AuthenticationProviderAssurance[];
  readonly verificationTimestamp: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly recoveryContext?: boolean;
  readonly canonicalPhilActivationContext?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface BoundedTrustDecisionCandidate {
  readonly boundedTrustDecisionCandidateId: string;
  readonly requestId: string;
  readonly status: BoundedTrustDecisionCandidateStatus;
  readonly outcome: BoundedTrustDecisionCandidateOutcome;
  readonly evidence: BoundedTrustDecisionCandidateEvidence;
  readonly correlation: BoundedTrustDecisionCandidateCorrelation;
  readonly assurance: BoundedTrustDecisionCandidateAssurance;
  readonly lifecycleAssessment: BoundedTrustDecisionCandidateLifecycleAssessment;
  readonly requirements: readonly BoundedTrustDecisionCandidateRequirement[];
  readonly limitations: readonly BoundedTrustDecisionCandidateLimitation[];
  readonly reasons: readonly BoundedTrustDecisionCandidateReason[];
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly eligibleForAuthoritativeTrustDecision: false;
  readonly requiresCounterPersistence: boolean;
  readonly requiresPolicyReview: true;
  readonly requiresUserApproval: true;
  readonly requiresWorldIdEnrollment: boolean;
  readonly productionAssertionVerified: true;
  readonly credentialLifecycleMutationPerformed: false;
  readonly counterPersisted: false;
  readonly activeTrustDecisionCreated: false;
  readonly capabilityGranted: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly vaultAccessGranted: false;
  readonly persisted: false;
  readonly worldIdVerified: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly rawAssertionMaterialIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: BoundedTrustDecisionCandidateCollectionResult;
}

export type BoundedTrustDecisionCandidateResult =
  RuntimeResult<BoundedTrustDecisionCandidate>;

export interface TrustDecisionCandidateConsumerResult {
  readonly status: "accepted_shape" | "rejected_shape";
  readonly boundedTrustDecisionCandidateId?: string;
  readonly errors: readonly string[];
  readonly activeTrustDecisionCreated: false;
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
}

export interface TrustDecisionCandidateConsumer {
  acceptCandidateShape(candidate: BoundedTrustDecisionCandidate):
    TrustDecisionCandidateConsumerResult;
}

export interface AuthoritativeTrustDecisionInput {
  readonly candidate: BoundedTrustDecisionCandidate;
  readonly requiresSeparateAuthoritativeDecision: true;
  readonly requiresCounterPersistence: boolean;
  readonly requiresPolicyReview: true;
  readonly requiresUserApproval: true;
  readonly grantsAuthority: false;
}

export type BoundedTrustDecisionCandidateCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface BoundedTrustDecisionCandidateCollection {
  readonly candidates: readonly BoundedTrustDecisionCandidate[];
  readonly count: number;
  readonly maxCandidateCount: number;
}

export interface BoundedTrustDecisionCandidateCollectionResult {
  readonly status: BoundedTrustDecisionCandidateCollectionStatus;
  readonly candidate?: BoundedTrustDecisionCandidate;
  readonly removedCandidate?: BoundedTrustDecisionCandidate;
  readonly evictedCandidates?: readonly BoundedTrustDecisionCandidate[];
  readonly collection: BoundedTrustDecisionCandidateCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface BoundedTrustDecisionCandidateCollector {
  addCandidate(candidate: BoundedTrustDecisionCandidate):
    BoundedTrustDecisionCandidateCollectionResult;
  removeCandidate(candidateId: string): BoundedTrustDecisionCandidateCollectionResult;
  clear(): BoundedTrustDecisionCandidateCollectionResult;
  count(): number;
  getById(candidateId: string): BoundedTrustDecisionCandidate | undefined;
  getAll(): readonly BoundedTrustDecisionCandidate[];
}

export interface InMemoryBoundedTrustDecisionCandidateCollectorOptions {
  readonly maxCandidateCount?: number;
}

const CANDIDATE_STATUSES = new Set<BoundedTrustDecisionCandidateStatus>([
  "candidate_created",
  "candidate_rejected",
  "candidate_malformed",
  "candidate_unsupported"
]);

const CANDIDATE_OUTCOMES = new Set<BoundedTrustDecisionCandidateOutcome>([
  "candidate_created",
  "verification_ineligible",
  "credential_lifecycle_ineligible",
  "session_state_ineligible",
  "assurance_insufficient",
  "purpose_ineligible",
  "correlation_mismatch",
  "evidence_expired",
  "evidence_replayed",
  "counter_persistence_required",
  "pending_policy_review",
  "pending_user_approval",
  "malformed",
  "unsupported"
]);

const ACTIVE_AUTHORITY_OR_PRIVATE_FIELDS = new Set([
  "philsecret",
  "privatekey",
  "signingkey",
  "vaultkey",
  "rawvaultkey",
  "seedphrase",
  "mnemonic",
  "credentialrecord",
  "authenticatordata",
  "clientdatajson",
  "signature",
  "authorizationpackage",
  "sessionkey",
  "trustdecision",
  "capabilitygrant",
  "authoritytoken"
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
  return { valid: errors.length === 0, errors };
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

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function findBlockedFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findBlockedFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) return [];
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

function isCredentialLifecycleStatus(
  value: unknown
): value is BoundedTrustDecisionCredentialLifecycleStatus {
  return value === "active"
    || value === "pending"
    || value === "revoked"
    || value === "archived"
    || value === "rotated"
    || value === "recovery-only"
    || value === "unknown";
}

function isProductionPurpose(value: unknown): value is ProductionAuthenticationPurpose {
  return value === "session_unlock"
    || value === "session_resume"
    || value === "high_risk_action"
    || value === "credential_rotation"
    || value === "credential_revocation"
    || value === "backup_export"
    || value === "recovery_approval"
    || value === "canonical_phil_activation"
    || value === "unsupported";
}

function isAssurance(value: unknown): value is AuthenticationProviderAssurance {
  return value === "none"
    || value === "user_presence"
    || value === "user_verification"
    || value === "hardware_backed"
    || value === "phishing_resistant"
    || value === "recovery_ceremony"
    || value === "developer_fixture";
}

function isAssuranceArray(value: unknown): value is readonly AuthenticationProviderAssurance[] {
  return Array.isArray(value) && value.length > 0 && value.every(isAssurance);
}

function isLifecycleState(value: unknown): value is UserSessionLifecycleState {
  return value === "uninitialized"
    || value === "locked"
    || value === "unlocking"
    || value === "partially_unlocked"
    || value === "unlocked"
    || value === "suspending"
    || value === "suspended"
    || value === "resuming"
    || value === "expiring"
    || value === "expired"
    || value === "recovery_mode"
    || value === "closing"
    || value === "closed";
}

function candidateError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "BOUNDED_TRUST_DECISION_CANDIDATE_INVALID",
    message: "bounded Trust Decision candidate request failed validation",
    boundary: "trust-manager",
    recoverable: true,
    details: { errors }
  };
}

export function isBoundedTrustDecisionCandidateStatus(
  value: unknown
): value is BoundedTrustDecisionCandidateStatus {
  return CANDIDATE_STATUSES.has(value as BoundedTrustDecisionCandidateStatus);
}

export function isBoundedTrustDecisionCandidateOutcome(
  value: unknown
): value is BoundedTrustDecisionCandidateOutcome {
  return CANDIDATE_OUTCOMES.has(value as BoundedTrustDecisionCandidateOutcome);
}

export function validateBoundedTrustDecisionCandidateRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["Bounded Trust Decision candidate request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.productionVerificationResult)) {
    errors.push("productionVerificationResult is required");
  } else {
    const verificationValidation =
      validateTrustManagerProductionVerificationResultShape(request.productionVerificationResult);
    if (!verificationValidation.valid) {
      errors.push(...verificationValidation.errors.map((error) =>
        `productionVerificationResult.${error}`
      ));
    }
  }
  if (!isCredentialLifecycleStatus(request.credentialLifecycleStatus)) {
    errors.push("credentialLifecycleStatus is invalid");
  }
  if (!isNonEmptyString(request.credentialId)) errors.push("credentialId is required");
  if (request.providerKind !== "webauthn_passkey") errors.push("providerKind must be webauthn_passkey");
  if (!isNonEmptyString(request.ownerCommitment)) errors.push("ownerCommitment is required");
  if (!isNonEmptyString(request.sessionId)) errors.push("sessionId is required");
  if (!isLifecycleState(request.lifecycleState)) errors.push("lifecycleState is invalid");
  if (!isNonEmptyString(request.applicationId)) errors.push("applicationId is required");
  if (!isProductionPurpose(request.authenticationPurpose) || request.authenticationPurpose === "unsupported") {
    errors.push("authenticationPurpose is invalid or unsupported");
  }
  if (!isAssuranceArray(request.requestedAssurance)) {
    errors.push("requestedAssurance must contain supported assurance strings");
  }
  if (!hasValidDateShape(request.verificationTimestamp)) {
    errors.push("verificationTimestamp must be a parseable date string");
  }
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
    errors.push(...findBlockedFields(request.metadata).map((field) =>
      `metadata.${field} must not contain private material or active authority`
    ));
  }
  return validation(errors);
}

function assuranceFromRequest(
  request: BoundedTrustDecisionCandidateRequest
): BoundedTrustDecisionCandidateAssurance {
  const required = new Set(request.requestedAssurance);
  const metAssurance = new Set<AuthenticationProviderAssurance>();
  if (request.productionVerificationResult.evidenceSummary.userPresenceVerified) {
    metAssurance.add("user_presence");
  }
  if (request.productionVerificationResult.evidenceSummary.userVerificationVerified) {
    metAssurance.add("user_verification");
  }
  if (request.productionVerificationResult.productionVerifierUsed) {
    metAssurance.add("phishing_resistant");
  }
  const userPresenceRequired = required.has("user_presence");
  const userVerificationRequired = required.has("user_verification");
  const phishingResistantRequired = required.has("phishing_resistant");
  const sufficient = [...required].every((assurance) =>
    assurance === "none" || metAssurance.has(assurance)
  );
  return freezeRecord({
    requestedAssurance: Object.freeze([...request.requestedAssurance]),
    metAssurance: Object.freeze([...metAssurance]),
    userPresenceRequired,
    userPresenceMet: !userPresenceRequired
      || request.productionVerificationResult.evidenceSummary.userPresenceVerified,
    userVerificationRequired,
    userVerificationMet: !userVerificationRequired
      || request.productionVerificationResult.evidenceSummary.userVerificationVerified,
    phishingResistantRequired,
    phishingResistantMet: !phishingResistantRequired
      || request.productionVerificationResult.productionVerifierUsed,
    sufficient
  });
}

function lifecycleAssessment(
  request: BoundedTrustDecisionCandidateRequest
): BoundedTrustDecisionCandidateLifecycleAssessment {
  const recoveryContext = request.recoveryContext === true
    || request.authenticationPurpose === "recovery_approval";
  const canonicalPhilActivationContext = request.canonicalPhilActivationContext === true
    || request.authenticationPurpose === "canonical_phil_activation";
  const sessionEligible = request.lifecycleState === "partially_unlocked"
    || request.lifecycleState === "unlocked"
    || (recoveryContext && request.lifecycleState === "recovery_mode");
  const ordinaryPurpose = request.authenticationPurpose !== "recovery_approval";
  const eligibleForOrdinaryUse = request.credentialLifecycleStatus === "active" && ordinaryPurpose;
  const eligibleForRecoveryUse =
    (request.credentialLifecycleStatus === "active" || request.credentialLifecycleStatus === "recovery-only")
    && recoveryContext;
  let reason: BoundedTrustDecisionCandidateReason = "credential-lifecycle-active";
  if (request.credentialLifecycleStatus === "pending") reason = "credential-lifecycle-pending";
  if (request.credentialLifecycleStatus === "revoked") reason = "credential-lifecycle-revoked";
  if (request.credentialLifecycleStatus === "archived") reason = "credential-lifecycle-archived";
  if (request.credentialLifecycleStatus === "rotated") reason = "credential-lifecycle-rotated";
  if (request.credentialLifecycleStatus === "recovery-only") {
    reason = eligibleForRecoveryUse
      ? "recovery-context-allows-recovery-only-credential"
      : "credential-lifecycle-recovery-only";
  }
  if (request.credentialLifecycleStatus === "unknown") reason = "credential-lifecycle-unknown";
  if (!sessionEligible) reason = "session-state-ineligible";
  return freezeRecord({
    credentialLifecycleStatus: request.credentialLifecycleStatus,
    sessionLifecycleState: request.lifecycleState,
    recoveryContext,
    canonicalPhilActivationContext,
    eligibleForOrdinaryUse,
    eligibleForRecoveryUse,
    eligibleForCandidate: sessionEligible && (eligibleForOrdinaryUse || eligibleForRecoveryUse),
    requiresWorldIdEnrollment: canonicalPhilActivationContext,
    reason
  });
}

function correlationErrors(request: BoundedTrustDecisionCandidateRequest): readonly string[] {
  const verification = request.productionVerificationResult;
  const errors: string[] = [];
  if (verification.correlation.credentialId !== request.credentialId) errors.push("credential correlation mismatch");
  if (verification.correlation.providerKind !== request.providerKind) errors.push("provider correlation mismatch");
  if (verification.correlation.ownerCommitment !== request.ownerCommitment) errors.push("owner correlation mismatch");
  if (verification.correlation.sessionId !== request.sessionId) errors.push("session correlation mismatch");
  if (verification.correlation.applicationId !== request.applicationId) errors.push("application correlation mismatch");
  if (verification.correlation.authenticationPurpose !== request.authenticationPurpose) {
    errors.push("purpose correlation mismatch");
  }
  if (verification.auditCorrelationId !== request.auditCorrelationId
    || verification.correlation.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  return errors;
}

function outcomeForRequest(
  request: BoundedTrustDecisionCandidateRequest,
  assurance: BoundedTrustDecisionCandidateAssurance,
  lifecycle: BoundedTrustDecisionCandidateLifecycleAssessment,
  correlations: readonly string[]
): BoundedTrustDecisionCandidateOutcome {
  const verification = request.productionVerificationResult;
  if (verification.status === "verification_replayed" || verification.outcome === "evidence_replayed") {
    return "evidence_replayed";
  }
  if (expired(verification.expiresAt) || expired(request.expiresAt)) return "evidence_expired";
  if (verification.status !== "verification_succeeded"
    || verification.outcome !== "assertion_verified"
    || !verification.assertionCryptographicallyVerified
    || !verification.signatureVerified
    || !verification.challengeBindingVerified
    || !verification.originVerified
    || !verification.rpIdHashVerified) {
    return "verification_ineligible";
  }
  if (!verification.productionVerifierUsed) return "verification_ineligible";
  if (verification.worldIdVerified) return "unsupported";
  if (verification.evidenceSummary.verifierKind.includes("fixture")) return "verification_ineligible";
  if (correlations.length > 0) return "correlation_mismatch";
  if (!assurance.sufficient) return "assurance_insufficient";
  if (!assurance.userPresenceMet) return "assurance_insufficient";
  if (!assurance.userVerificationMet) return "assurance_insufficient";
  if (verification.counterAssessment.rollbackDetected) return "verification_ineligible";
  if (verification.counterAssessment.cloneSuspected) return "verification_ineligible";
  if (!lifecycle.eligibleForCandidate) {
    if (!lifecycle.sessionLifecycleState
      || !["partially_unlocked", "unlocked", "recovery_mode"].includes(lifecycle.sessionLifecycleState)) {
      return "session_state_ineligible";
    }
    return lifecycle.credentialLifecycleStatus === "pending" || lifecycle.credentialLifecycleStatus === "unknown"
      ? "unsupported"
      : "credential_lifecycle_ineligible";
  }
  if (verification.counterAssessment.futurePersistenceRequired && !verification.counterPersisted) {
    return "counter_persistence_required";
  }
  return "pending_policy_review";
}

function reasonsFor(
  outcome: BoundedTrustDecisionCandidateOutcome,
  request: BoundedTrustDecisionCandidateRequest,
  assurance: BoundedTrustDecisionCandidateAssurance,
  lifecycle: BoundedTrustDecisionCandidateLifecycleAssessment
): readonly BoundedTrustDecisionCandidateReason[] {
  const reasons = new Set<BoundedTrustDecisionCandidateReason>([
    "production-verification-result-required",
    "production-assertion-verified",
    "production-verifier-used",
    lifecycle.reason,
    assurance.sufficient ? "assurance-requirements-met" : "assurance-insufficient",
    lifecycle.eligibleForCandidate ? "session-state-eligible" : "session-state-ineligible",
    "pending-policy-review",
    "pending-user-approval",
    "no-active-trust-decision",
    "no-authority",
    "no-vault-access",
    "no-persistence"
  ]);
  if (request.productionVerificationResult.counterAssessment.futurePersistenceRequired) {
    reasons.add("counter-persistence-required");
  }
  if (request.productionVerificationResult.counterAssessment.rollbackDetected) {
    reasons.add("counter-rollback-rejected");
  }
  if (request.productionVerificationResult.counterAssessment.cloneSuspected) {
    reasons.add("counter-clone-risk-rejected");
  }
  if (lifecycle.requiresWorldIdEnrollment) {
    reasons.add("world-id-enrollment-required-for-canonical-activation");
  }
  if (outcome === "verification_ineligible" && !request.productionVerificationResult.productionVerifierUsed) {
    reasons.add("fixture-only-evidence-rejected");
  }
  return Object.freeze([...reasons]);
}

function requirementsFor(
  request: BoundedTrustDecisionCandidateRequest,
  lifecycle: BoundedTrustDecisionCandidateLifecycleAssessment
): readonly BoundedTrustDecisionCandidateRequirement[] {
  return Object.freeze([
    "production_assertion_verification",
    "credential_lifecycle_eligible",
    "session_context_eligible",
    "assurance_met",
    ...(request.productionVerificationResult.counterAssessment.futurePersistenceRequired
      ? ["counter_persistence" as const]
      : []),
    "policy_review",
    "user_approval",
    ...(lifecycle.requiresWorldIdEnrollment ? ["world_id_enrollment" as const] : [])
  ]);
}

function limitations(): readonly BoundedTrustDecisionCandidateLimitation[] {
  return Object.freeze([
    "candidate_only",
    "counter_not_persisted",
    "no_authoritative_trust_decision",
    "no_capability_grant",
    "no_authorization",
    "no_policy_execution",
    "no_user_approval",
    "no_world_id_verification",
    "no_vault_access",
    "no_persistence"
  ]);
}

function statusFromOutcome(
  outcome: BoundedTrustDecisionCandidateOutcome
): BoundedTrustDecisionCandidateStatus {
  if (outcome === "malformed") return "candidate_malformed";
  if (outcome === "unsupported") return "candidate_unsupported";
  if (
    outcome === "verification_ineligible"
    || outcome === "credential_lifecycle_ineligible"
    || outcome === "session_state_ineligible"
    || outcome === "assurance_insufficient"
    || outcome === "purpose_ineligible"
    || outcome === "correlation_mismatch"
    || outcome === "evidence_expired"
    || outcome === "evidence_replayed"
  ) {
    return "candidate_rejected";
  }
  return "candidate_created";
}

function evidenceFrom(
  request: BoundedTrustDecisionCandidateRequest
): BoundedTrustDecisionCandidateEvidence {
  const verification = request.productionVerificationResult;
  return freezeRecord({
    productionVerificationResultId: verification.trustManagerProductionVerificationResultId,
    trustManagerVerificationInputId:
      verification.verifiedEvidenceReference?.trustManagerVerificationInputId,
    verifiedEvidenceReferenceId:
      verification.verifiedEvidenceReference?.verifiedEvidenceReferenceId,
    productionAssertionVerified: true,
    productionVerifierUsed: true,
    fixtureOnlyEvidence: false,
    credentialSafeReference: verification.correlation.credentialSafeReference,
    providerKind: verification.correlation.providerKind,
    publicKeyAlgorithm: verification.evidenceSummary.publicKeyAlgorithm,
    userPresenceVerified: true,
    userVerificationVerified: true,
    challengeVerified: true,
    originVerified: true,
    rpIdHashVerified: true,
    signatureVerified: true,
    counterStatus: verification.counterAssessment.counterStatus,
    counterPersisted: false,
    rawAssertionMaterialIncluded: false,
    publicKeyBytesIncluded: false
  });
}

function auditDraftForCandidate(input: {
  readonly request: BoundedTrustDecisionCandidateRequest;
  readonly candidate?: BoundedTrustDecisionCandidate;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "trust",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    summary: input.candidate
      ? "Bounded Trust Decision candidate evaluated; no authoritative Trust Decision or authority was created."
      : "Bounded Trust Decision candidate request failed validation; no authority was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      requestId: input.request.requestId,
      candidateId: input.candidate?.boundedTrustDecisionCandidateId,
      outcome: input.candidate?.outcome,
      credentialSafeReference:
        input.request.productionVerificationResult?.correlation.credentialSafeReference,
      providerKind: input.request.providerKind,
      credentialLifecycleStatus: input.request.credentialLifecycleStatus,
      authenticationPurpose: input.request.authenticationPurpose,
      assuranceSufficient: input.candidate?.assurance.sufficient,
      sessionLifecycleState: input.request.lifecycleState,
      counterStatus:
        input.request.productionVerificationResult?.counterAssessment.counterStatus,
      requiresCounterPersistence: input.candidate?.requiresCounterPersistence,
      activeTrustDecisionCreated: false,
      capabilityGranted: false,
      authorizationCreated: false,
      vaultAccessGranted: false,
      worldIdVerified: false,
      persisted: false,
      rawAssertionMaterialIncluded: false,
      publicKeyBytesIncluded: false,
      errors: input.errors ?? []
    }
  });
}

export function createBoundedTrustDecisionCandidate(
  request: BoundedTrustDecisionCandidateRequest,
  collector?: BoundedTrustDecisionCandidateCollector,
  auditDraftCollector?: AuditDraftCollector
): BoundedTrustDecisionCandidateResult {
  return evaluateBoundedTrustDecisionCandidate(request, collector, auditDraftCollector);
}

export function evaluateBoundedTrustDecisionCandidate(
  request: BoundedTrustDecisionCandidateRequest,
  collector?: BoundedTrustDecisionCandidateCollector,
  auditDraftCollector?: AuditDraftCollector
): BoundedTrustDecisionCandidateResult {
  const validationResult = validateBoundedTrustDecisionCandidateRequest(request);
  if (!validationResult.valid) {
    const auditEventDraft = auditDraftForCandidate({
      request,
      outcome: "malformed",
      errors: validationResult.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(validationResult.errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }

  const assurance = assuranceFromRequest(request);
  const lifecycle = lifecycleAssessment(request);
  const correlations = correlationErrors(request);
  const outcome = outcomeForRequest(request, assurance, lifecycle, correlations);
  const status = statusFromOutcome(outcome);
  const createdAt = request.verificationTimestamp;
  const candidateId = createAuditCorrelationId([
    request.productionVerificationResult.trustManagerProductionVerificationResultId,
    request.credentialId,
    request.authenticationPurpose,
    request.auditCorrelationId,
    "bounded-trust-decision-candidate"
  ]);
  const candidateBase = {
    boundedTrustDecisionCandidateId: candidateId,
    requestId: request.requestId,
    status,
    outcome,
    evidence: evidenceFrom(request),
    correlation: {
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      ownerCommitment: request.ownerCommitment,
      credentialId: request.credentialId,
      providerKind: request.providerKind,
      authenticationPurpose: request.authenticationPurpose,
      auditCorrelationId: request.auditCorrelationId
    },
    assurance,
    lifecycleAssessment: lifecycle,
    requirements: requirementsFor(request, lifecycle),
    limitations: limitations(),
    reasons: reasonsFor(outcome, request, assurance, lifecycle),
    createdAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId,
    eligibleForAuthoritativeTrustDecision: false as const,
    requiresCounterPersistence:
      request.productionVerificationResult.counterAssessment.futurePersistenceRequired
      && !request.productionVerificationResult.counterPersisted,
    requiresPolicyReview: true as const,
    requiresUserApproval: true as const,
    requiresWorldIdEnrollment: lifecycle.requiresWorldIdEnrollment,
    productionAssertionVerified: true as const,
    credentialLifecycleMutationPerformed: false as const,
    counterPersisted: false as const,
    activeTrustDecisionCreated: false as const,
    capabilityGranted: false as const,
    sessionKeyCreated: false as const,
    authorizationCreated: false as const,
    vaultAccessGranted: false as const,
    persisted: false as const,
    worldIdVerified: false as const,
    proofExecuted: false as const,
    adapterExecuted: false as const,
    rawAssertionMaterialIncluded: false as const,
    credentialRecordIncluded: false as const
  };
  const candidateWithoutAudit = freezeRecord(candidateBase) as BoundedTrustDecisionCandidate;
  const shapeValidation = validateBoundedTrustDecisionCandidateShape(candidateWithoutAudit);
  if (!shapeValidation.valid) {
    const auditEventDraft = auditDraftForCandidate({
      request,
      outcome: "validation_failed",
      errors: shapeValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(shapeValidation.errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }
  const auditEventDraft = auditDraftForCandidate({
    request,
    candidate: candidateWithoutAudit,
    outcome: status === "candidate_created" ? "validation_succeeded" : "validation_failed",
    errors: correlations
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const candidateWithAudit = freezeRecord({
    ...candidateBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as BoundedTrustDecisionCandidate;
  const collectionResult = collector?.addCandidate(candidateWithAudit);
  const candidate = freezeRecord({
    ...candidateWithAudit,
    collectionResult
  }) as BoundedTrustDecisionCandidate;
  return runtimeOk(candidate);
}

export function validateBoundedTrustDecisionCandidateShape(
  candidate: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(candidate)) return validation(["Bounded Trust Decision candidate must be an object"]);
  if (!isNonEmptyString(candidate.boundedTrustDecisionCandidateId)) {
    errors.push("boundedTrustDecisionCandidateId is required");
  }
  if (!isBoundedTrustDecisionCandidateStatus(candidate.status)) errors.push("status is invalid");
  if (!isBoundedTrustDecisionCandidateOutcome(candidate.outcome)) errors.push("outcome is invalid");
  if (!isRecord(candidate.evidence)) errors.push("evidence is required");
  if (!isRecord(candidate.correlation)) errors.push("correlation is required");
  if (!isRecord(candidate.assurance)) errors.push("assurance is required");
  if (!isRecord(candidate.lifecycleAssessment)) errors.push("lifecycleAssessment is required");
  const expectedFalseFields = [
    "credentialLifecycleMutationPerformed",
    "counterPersisted",
    "activeTrustDecisionCreated",
    "capabilityGranted",
    "sessionKeyCreated",
    "authorizationCreated",
    "vaultAccessGranted",
    "persisted",
    "worldIdVerified",
    "proofExecuted",
    "adapterExecuted",
    "rawAssertionMaterialIncluded",
    "credentialRecordIncluded"
  ];
  for (const field of expectedFalseFields) {
    if (candidate[field] !== false) errors.push(`${field} must be false`);
  }
  if (candidate.productionAssertionVerified !== true) {
    errors.push("productionAssertionVerified must be true");
  }
  if (candidate.eligibleForAuthoritativeTrustDecision !== false) {
    errors.push("eligibleForAuthoritativeTrustDecision must be false until a later milestone");
  }
  errors.push(...findBlockedFields(candidate).map((field) =>
    `${field} must not contain private material or active authority`
  ));
  return validation(errors);
}

export function createFixtureTrustDecisionCandidateConsumer():
  TrustDecisionCandidateConsumer {
  return {
    acceptCandidateShape(candidate) {
      const result = validateBoundedTrustDecisionCandidateShape(candidate);
      return freezeRecord({
        status: result.valid ? "accepted_shape" as const : "rejected_shape" as const,
        boundedTrustDecisionCandidateId: result.valid
          ? candidate.boundedTrustDecisionCandidateId
          : undefined,
        errors: result.errors,
        activeTrustDecisionCreated: false as const,
        capabilityGranted: false as const,
        authorizationCreated: false as const,
        persisted: false as const
      });
    }
  };
}

function collectionFrom(
  candidates: readonly BoundedTrustDecisionCandidate[],
  maxCandidateCount: number
): BoundedTrustDecisionCandidateCollection {
  return freezeRecord({ candidates, count: candidates.length, maxCandidateCount });
}

export function createInMemoryBoundedTrustDecisionCandidateCollector(
  options: InMemoryBoundedTrustDecisionCandidateCollectorOptions = {}
): BoundedTrustDecisionCandidateCollector {
  const maxCandidateCount = Math.max(1, Math.floor(options.maxCandidateCount ?? 100));
  const candidates = new Map<string, BoundedTrustDecisionCandidate>();
  function all() {
    return Object.freeze(Array.from(candidates.values()).map(freezeRecord));
  }
  function collectionResult(
    status: BoundedTrustDecisionCandidateCollectionStatus,
    extras: Omit<BoundedTrustDecisionCandidateCollectionResult, "status" | "collection"> = {}
  ): BoundedTrustDecisionCandidateCollectionResult {
    return freezeRecord({
      status,
      ...extras,
      collection: collectionFrom(all(), maxCandidateCount)
    });
  }
  return {
    addCandidate(candidate) {
      const validationResult = validateBoundedTrustDecisionCandidateShape(candidate);
      if (!validationResult.valid) {
        return collectionResult("rejected_invalid", { errors: validationResult.errors });
      }
      if (candidates.has(candidate.boundedTrustDecisionCandidateId)) {
        return collectionResult("rejected_duplicate", { candidate });
      }
      const evictedCandidates: BoundedTrustDecisionCandidate[] = [];
      while (candidates.size >= maxCandidateCount) {
        const oldestKey = candidates.keys().next().value as string | undefined;
        if (!oldestKey) break;
        const evicted = candidates.get(oldestKey);
        candidates.delete(oldestKey);
        if (evicted) evictedCandidates.push(evicted);
      }
      candidates.set(candidate.boundedTrustDecisionCandidateId, freezeRecord(candidate));
      return collectionResult(evictedCandidates.length > 0 ? "evicted_oldest" : "collected", {
        candidate,
        evictedCandidates
      });
    },
    removeCandidate(candidateId) {
      const removedCandidate = candidates.get(candidateId);
      if (!removedCandidate) return collectionResult("not_found");
      candidates.delete(candidateId);
      return collectionResult("removed", { removedCandidate });
    },
    clear() {
      candidates.clear();
      return collectionResult("cleared");
    },
    count() {
      return candidates.size;
    },
    getById(candidateId) {
      const candidate = candidates.get(candidateId);
      return candidate ? freezeRecord(candidate) : undefined;
    },
    getAll: all
  };
}
