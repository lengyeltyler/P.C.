import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type {
  BoundedTrustDecisionCandidate,
  BoundedTrustDecisionCredentialLifecycleStatus
} from "./boundedTrustDecisionCandidate.ts";
import { validateBoundedTrustDecisionCandidateShape } from "./boundedTrustDecisionCandidate.ts";
import type {
  CredentialCounterPersistenceReceipt,
  TrustDecisionCandidateCounterResolution
} from "./credentialCounterPersistence.ts";
import { validateCredentialCounterPersistenceReceipt } from "./credentialCounterPersistence.ts";
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
  TrustManagerProductionVerificationResultValue
} from "./trustManagerProductionVerification.ts";
import { validateTrustManagerProductionVerificationResultShape } from "./trustManagerProductionVerification.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type AuthoritativeTrustDecisionStatus =
  | "trust_decision_created"
  | "trust_decision_rejected"
  | "trust_decision_malformed"
  | "trust_decision_replayed"
  | "trust_decision_expired"
  | "trust_decision_unsupported";

export type AuthoritativeTrustDecisionOutcome =
  | "trust_decision_created"
  | "verification_ineligible"
  | "candidate_ineligible"
  | "counter_receipt_ineligible"
  | "credential_lifecycle_ineligible"
  | "session_state_ineligible"
  | "assurance_insufficient"
  | "purpose_ineligible"
  | "correlation_mismatch"
  | "counter_state_mismatch"
  | "evidence_expired"
  | "evidence_replayed"
  | "world_id_requirement_unresolved"
  | "malformed"
  | "unsupported";

export type AuthoritativeTrustDecisionReason =
  | "production-verification-succeeded"
  | "bounded-candidate-accepted"
  | "counter-receipt-verified"
  | "accepted-zero-counter-semantics"
  | "credential-lifecycle-eligible"
  | "session-context-eligible"
  | "assurance-satisfied"
  | "purpose-bound"
  | "world-id-activation-requirement-unresolved"
  | "process-local-consumption"
  | "trust-manager-authority-only"
  | "no-capability-grant"
  | "no-policy-approval"
  | "no-user-approval"
  | "no-authorization"
  | "no-session-key"
  | "no-execution"
  | "no-vault-material"
  | (string & {});

export type AuthoritativeTrustDecisionRequirement =
  | "successful_production_verification"
  | "bounded_trust_decision_candidate"
  | "verified_counter_persistence_receipt"
  | "credential_lifecycle_eligible"
  | "session_context_eligible"
  | "assurance_satisfied"
  | "purpose_bound"
  | "audit_correlation"
  | "bounded_validity_window";

export type AuthoritativeTrustDecisionLimitation =
  | "trust_manager_authority_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "purpose_bound"
  | "session_bound"
  | "credential_bound"
  | "no_capability_grant"
  | "no_policy_approval"
  | "no_user_approval"
  | "no_authorization_package"
  | "no_session_key"
  | "no_execution"
  | "no_world_id_verification"
  | "no_vault_material_exposure"
  | "no_durable_trust_database";

export interface AuthoritativeTrustDecisionScope {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerKind: "webauthn_passkey";
  readonly authenticationPurpose: string;
  readonly requestedAssurance: readonly string[];
  readonly auditCorrelationId: string;
}

export interface AuthoritativeTrustDecisionBinding {
  readonly productionVerificationResultId: string;
  readonly boundedTrustDecisionCandidateId: string;
  readonly credentialCounterPersistenceReceiptId: string;
  readonly counterResolutionId?: string;
  readonly sessionLifecycleId: string;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly challengeReferenceId: string;
  readonly validityWindowId: string;
  readonly reusableAcrossSessions: false;
  readonly reusableAcrossCredentials: false;
  readonly reusableAcrossApplications: false;
  readonly reusableAcrossPurposes: false;
  readonly reusableAcrossOwners: false;
  readonly reusableAcrossChallenges: false;
  readonly reusableAcrossTimeWindows: false;
}

export interface AuthoritativeTrustDecisionEvidence {
  readonly productionAssertionVerified: true;
  readonly productionVerifierUsed: true;
  readonly fixtureOnlyEvidence: false;
  readonly credentialCounterCommitted: boolean;
  readonly acceptedZeroCounterSemantics: boolean;
  readonly persistedCounter: number;
  readonly verifiedReturnedCounter: number;
  readonly counterStatus: string;
  readonly credentialLifecycleEligible: true;
  readonly sessionContextEligible: true;
  readonly assuranceSatisfied: true;
  readonly userPresenceVerified: true;
  readonly userVerificationVerified: true;
  readonly challengeVerified: true;
  readonly originVerified: true;
  readonly rpIdHashVerified: true;
  readonly signatureVerified: true;
  readonly rawAssertionMaterialIncluded: false;
  readonly publicKeyBytesIncluded: false;
  readonly credentialRecordIncluded: false;
}

export interface AuthoritativeTrustDecisionValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedBySessionClose: true;
  readonly invalidatedByCredentialRevocation: true;
  readonly invalidatedByOwnerMismatch: true;
}

export interface AuthoritativeTrustDecisionRevocationReference {
  readonly referenceId: string;
  readonly durableRevocationImplemented: false;
  readonly futureRevocationRequired: true;
}

export interface AuthoritativeTrustDecision {
  readonly authoritativeTrustDecisionId: string;
  readonly requestId: string;
  readonly status: "trust_decision_created";
  readonly outcome: "trust_decision_created";
  readonly scope: AuthoritativeTrustDecisionScope;
  readonly binding: AuthoritativeTrustDecisionBinding;
  readonly evidence: AuthoritativeTrustDecisionEvidence;
  readonly validity: AuthoritativeTrustDecisionValidity;
  readonly requirements: readonly AuthoritativeTrustDecisionRequirement[];
  readonly limitations: readonly AuthoritativeTrustDecisionLimitation[];
  readonly reasons: readonly AuthoritativeTrustDecisionReason[];
  readonly revocationReference: AuthoritativeTrustDecisionRevocationReference;
  readonly trustDecisionCreated: true;
  readonly productionAssertionVerified: true;
  readonly credentialCounterCommitted: boolean;
  readonly acceptedZeroCounterSemantics: boolean;
  readonly credentialLifecycleEligible: true;
  readonly sessionContextEligible: true;
  readonly assuranceSatisfied: true;
  readonly validForSpecifiedPurposeOnly: true;
  readonly capabilityGranted: false;
  readonly policyApproved: false;
  readonly userApprovalCollected: false;
  readonly authorizationCreated: false;
  readonly sessionKeyCreated: false;
  readonly executionAllowed: false;
  readonly worldIdVerified: false;
  readonly vaultMaterialExposed: false;
  readonly registryPlaintextExposed: false;
  readonly rawAssertionMaterialIncluded: false;
  readonly credentialPrivateMaterialExposed: false;
  readonly persistedAsAuthority: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: AuthoritativeTrustDecisionCollectionResult;
}

export interface AuthoritativeTrustDecisionRequest {
  readonly requestId: string;
  readonly productionVerificationResult: TrustManagerProductionVerificationResultValue;
  readonly boundedTrustDecisionCandidate: BoundedTrustDecisionCandidate;
  readonly counterPersistenceReceipt: CredentialCounterPersistenceReceipt;
  readonly counterResolution?: TrustDecisionCandidateCounterResolution;
  readonly credentialLifecycleStatus: BoundedTrustDecisionCredentialLifecycleStatus;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly credentialId: string;
  readonly providerKind: "webauthn_passkey";
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly authenticationPurpose: string;
  readonly requestedAssurance: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly recoveryContext?: boolean;
  readonly canonicalPhilActivationContext?: boolean;
  readonly worldIdEnrollmentVerified?: false;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthoritativeTrustDecisionResult =
  RuntimeResult<AuthoritativeTrustDecision>;

export interface AuthoritativeTrustDecisionConsumptionRecord {
  readonly evidenceChainId: string;
  readonly authoritativeTrustDecisionId?: string;
  readonly sessionId: string;
  readonly credentialId: string;
  readonly applicationId: ApplicationId;
  readonly authenticationPurpose: string;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export type AuthoritativeTrustDecisionConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface AuthoritativeTrustDecisionConsumptionResult {
  readonly status: AuthoritativeTrustDecisionConsumptionStatus;
  readonly record?: AuthoritativeTrustDecisionConsumptionRecord;
  readonly records: readonly AuthoritativeTrustDecisionConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralTrustDecisionEvidenceConsumptionStore {
  consume(record: AuthoritativeTrustDecisionConsumptionRecord):
    AuthoritativeTrustDecisionConsumptionResult;
  has(evidenceChainId: string): boolean;
  clear(): AuthoritativeTrustDecisionConsumptionResult;
  getAll(): readonly AuthoritativeTrustDecisionConsumptionRecord[];
}

export type AuthoritativeTrustDecisionCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface AuthoritativeTrustDecisionCollection {
  readonly decisions: readonly AuthoritativeTrustDecision[];
  readonly count: number;
  readonly maxDecisionCount: number;
}

export interface AuthoritativeTrustDecisionCollectionResult {
  readonly status: AuthoritativeTrustDecisionCollectionStatus;
  readonly decision?: AuthoritativeTrustDecision;
  readonly removedDecision?: AuthoritativeTrustDecision;
  readonly evictedDecisions?: readonly AuthoritativeTrustDecision[];
  readonly collection: AuthoritativeTrustDecisionCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface AuthoritativeTrustDecisionStore {
  addDecision(decision: AuthoritativeTrustDecision): AuthoritativeTrustDecisionCollectionResult;
  removeDecision(decisionId: string): AuthoritativeTrustDecisionCollectionResult;
  clear(): AuthoritativeTrustDecisionCollectionResult;
  count(): number;
  getById(decisionId: string): AuthoritativeTrustDecision | undefined;
  getAll(): readonly AuthoritativeTrustDecision[];
  getUnexpired(now?: string): readonly AuthoritativeTrustDecision[];
}

export interface InMemoryAuthoritativeTrustDecisionStoreOptions {
  readonly maxDecisionCount?: number;
}

export interface TrustDecisionConsumerRequest {
  readonly consumerId: string;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly requestedAt: string;
}

export interface TrustDecisionConsumerResult {
  readonly status: "accepted_shape" | "rejected_shape";
  readonly authoritativeTrustDecisionId?: string;
  readonly errors: readonly string[];
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
  readonly policyApproved: false;
}

export interface TrustDecisionConsumer {
  acceptTrustDecisionShape(request: TrustDecisionConsumerRequest):
    TrustDecisionConsumerResult;
}

export interface SecurityPolicyTrustDecisionInput {
  readonly authoritativeTrustDecisionId: string;
  readonly scope: AuthoritativeTrustDecisionScope;
  readonly binding: AuthoritativeTrustDecisionBinding;
  readonly validity: AuthoritativeTrustDecisionValidity;
  readonly grantsCapability: false;
  readonly createsAuthorization: false;
  readonly exposesSecrets: false;
}

const STATUSES = new Set<AuthoritativeTrustDecisionStatus>([
  "trust_decision_created",
  "trust_decision_rejected",
  "trust_decision_malformed",
  "trust_decision_replayed",
  "trust_decision_expired",
  "trust_decision_unsupported"
]);

const OUTCOMES = new Set<AuthoritativeTrustDecisionOutcome>([
  "trust_decision_created",
  "verification_ineligible",
  "candidate_ineligible",
  "counter_receipt_ineligible",
  "credential_lifecycle_ineligible",
  "session_state_ineligible",
  "assurance_insufficient",
  "purpose_ineligible",
  "correlation_mismatch",
  "counter_state_mismatch",
  "evidence_expired",
  "evidence_replayed",
  "world_id_requirement_unresolved",
  "malformed",
  "unsupported"
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

function decisionError(
  code: string,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "trust_denied",
    code,
    message: "authoritative Trust Decision request was rejected",
    boundary: "trust-manager",
    recoverable: true,
    details: { errors }
  };
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

function credentialLifecycleEligible(input: {
  readonly status: BoundedTrustDecisionCredentialLifecycleStatus;
  readonly purpose: string;
  readonly recoveryContext?: boolean;
}): boolean {
  if (input.status === "active") return true;
  if (input.status === "recovery-only") {
    return input.recoveryContext === true || input.purpose === "recovery_approval";
  }
  return false;
}

function sessionStateEligible(state: UserSessionLifecycleState, recoveryContext?: boolean): boolean {
  return state === "unlocked" || (recoveryContext === true && state === "recovery_mode");
}

function requirements(): readonly AuthoritativeTrustDecisionRequirement[] {
  return Object.freeze([
    "successful_production_verification",
    "bounded_trust_decision_candidate",
    "verified_counter_persistence_receipt",
    "credential_lifecycle_eligible",
    "session_context_eligible",
    "assurance_satisfied",
    "purpose_bound",
    "audit_correlation",
    "bounded_validity_window"
  ]);
}

function limitations(): readonly AuthoritativeTrustDecisionLimitation[] {
  return Object.freeze([
    "trust_manager_authority_only",
    "process_local_replay_protection_only",
    "process_local_store_only",
    "purpose_bound",
    "session_bound",
    "credential_bound",
    "no_capability_grant",
    "no_policy_approval",
    "no_user_approval",
    "no_authorization_package",
    "no_session_key",
    "no_execution",
    "no_world_id_verification",
    "no_vault_material_exposure",
    "no_durable_trust_database"
  ]);
}

function correlationErrors(request: AuthoritativeTrustDecisionRequest): readonly string[] {
  const errors: string[] = [];
  const verification = request.productionVerificationResult;
  const candidate = request.boundedTrustDecisionCandidate;
  const receipt = request.counterPersistenceReceipt;
  const checks: Array<readonly [unknown, unknown, string]> = [
    [verification.correlation.ownerCommitment, request.ownerCommitment, "verification owner mismatch"],
    [candidate.correlation.ownerCommitment, request.ownerCommitment, "candidate owner mismatch"],
    [receipt.correlation.ownerCommitment, request.ownerCommitment, "receipt owner mismatch"],
    [verification.correlation.sessionId, request.sessionId, "verification session mismatch"],
    [candidate.correlation.sessionId, request.sessionId, "candidate session mismatch"],
    [receipt.correlation.sessionId, request.sessionId, "receipt session mismatch"],
    [request.lifecycleSnapshot.sessionId, request.sessionId, "lifecycle session mismatch"],
    [verification.correlation.applicationId, request.applicationId, "verification application mismatch"],
    [candidate.correlation.applicationId, request.applicationId, "candidate application mismatch"],
    [receipt.correlation.applicationId, request.applicationId, "receipt application mismatch"],
    [verification.correlation.credentialId, request.credentialId, "verification credential mismatch"],
    [candidate.correlation.credentialId, request.credentialId, "candidate credential mismatch"],
    [receipt.correlation.credentialId, request.credentialId, "receipt credential mismatch"],
    [verification.correlation.providerKind, request.providerKind, "verification provider mismatch"],
    [candidate.correlation.providerKind, request.providerKind, "candidate provider mismatch"],
    [verification.correlation.authenticationPurpose, request.authenticationPurpose, "verification purpose mismatch"],
    [candidate.correlation.authenticationPurpose, request.authenticationPurpose, "candidate purpose mismatch"],
    [verification.auditCorrelationId, request.auditCorrelationId, "verification audit mismatch"],
    [verification.correlation.auditCorrelationId, request.auditCorrelationId, "verification audit mismatch"],
    [candidate.auditCorrelationId, request.auditCorrelationId, "candidate audit mismatch"],
    [candidate.correlation.auditCorrelationId, request.auditCorrelationId, "candidate audit mismatch"],
    [receipt.auditCorrelationId, request.auditCorrelationId, "receipt audit mismatch"],
    [receipt.correlation.auditCorrelationId, request.auditCorrelationId, "receipt audit mismatch"]
  ];
  for (const [actual, expected, message] of checks) {
    if (actual !== expected) errors.push(message);
  }
  if (
    verification.trustManagerProductionVerificationResultId
      !== candidate.evidence.productionVerificationResultId
  ) {
    errors.push("candidate verification reference mismatch");
  }
  if (
    receipt.correlation.credentialSafeReference
      !== verification.correlation.credentialSafeReference
    || candidate.evidence.credentialSafeReference
      !== verification.correlation.credentialSafeReference
  ) {
    errors.push("credential safe reference mismatch");
  }
  if (
    request.counterResolution
    && (
      request.counterResolution.boundedTrustDecisionCandidateId
        !== candidate.boundedTrustDecisionCandidateId
      || request.counterResolution.credentialCounterPersistenceReceiptId
        !== receipt.credentialCounterPersistenceReceiptId
    )
  ) {
    errors.push("counter resolution reference mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

function eligibilityErrors(request: AuthoritativeTrustDecisionRequest): readonly string[] {
  const errors: string[] = [];
  const verification = request.productionVerificationResult;
  const candidate = request.boundedTrustDecisionCandidate;
  const receipt = request.counterPersistenceReceipt;
  if (
    verification.status !== "verification_succeeded"
    || verification.outcome !== "assertion_verified"
    || !verification.productionVerifierUsed
    || !verification.assertionCryptographicallyVerified
    || !verification.signatureVerified
    || !verification.challengeBindingVerified
    || !verification.originVerified
    || !verification.rpIdHashVerified
  ) {
    errors.push("production verification ineligible");
  }
  if (verification.evidenceSummary.verifierKind.includes("fixture")) {
    errors.push("fixture-only evidence rejected");
  }
  if (verification.counterAssessment.rollbackDetected
    || verification.counterAssessment.cloneSuspected
    || verification.counterAssessment.counterStatus === "rollback"
    || verification.counterAssessment.counterStatus === "clone-suspected") {
    errors.push("counter replay or clone risk rejected");
  }
  if (candidate.status !== "candidate_created") errors.push("candidate ineligible");
  if (
    candidate.outcome !== "counter_persistence_required"
    && candidate.outcome !== "pending_policy_review"
    && candidate.outcome !== "pending_user_approval"
  ) {
    errors.push("candidate outcome ineligible");
  }
  if (!candidate.productionAssertionVerified) errors.push("candidate production evidence missing");
  if (!candidate.assurance.sufficient) errors.push("assurance insufficient");
  if (candidate.requiresWorldIdEnrollment
    || request.canonicalPhilActivationContext === true
    || request.authenticationPurpose === "canonical_phil_activation") {
    errors.push("world id requirement unresolved");
  }
  if (
    receipt.status !== "persistence_succeeded"
    || (receipt.outcome !== "counter_persisted"
      && receipt.outcome !== "counter_unchanged_accepted")
    || !receipt.registryIntegrityVerified
    || !receipt.writeVerified
  ) {
    errors.push("counter receipt ineligible");
  }
  if (receipt.trustDecisionCreated !== false || receipt.capabilityGranted !== false) {
    errors.push("receipt already carries authority");
  }
  const counterCommitted = receipt.outcome === "counter_persisted"
    && receipt.counterPersisted
    && receipt.mutationSummary.persistedCounter
      === verification.counterAssessment.returnedCounter
    && receipt.counterState.verifiedReturnedCounter
      === verification.counterAssessment.returnedCounter;
  const acceptedZero = receipt.outcome === "counter_unchanged_accepted"
    && receipt.counterPersisted === false
    && verification.counterAssessment.counterStatus === "unchanged-zero"
    && receipt.counterState.verifiedReturnedCounter === 0
    && receipt.mutationSummary.persistedCounter === 0;
  if (!counterCommitted && !acceptedZero) errors.push("counter state mismatch");
  if (!credentialLifecycleEligible({
    status: request.credentialLifecycleStatus,
    purpose: request.authenticationPurpose,
    recoveryContext: request.recoveryContext
  })) {
    errors.push("credential lifecycle ineligible");
  }
  if (!sessionStateEligible(request.lifecycleSnapshot.state, request.recoveryContext)) {
    errors.push("session state ineligible");
  }
  if (!request.requestedAssurance.every((assurance) =>
    candidate.assurance.metAssurance.includes(assurance as never) || assurance === "none"
  )) {
    errors.push("assurance mismatch");
  }
  if (
    expired(verification.expiresAt)
    || expired(candidate.expiresAt)
    || expired(request.expiresAt)
  ) {
    errors.push("evidence expired");
  }
  if (Date.parse(request.expiresAt) <= Date.parse(request.issuedAt)) {
    errors.push("decision expiry must be after issue time");
  }
  return Object.freeze([...new Set(errors)]);
}

function outcomeFromErrors(errors: readonly string[]): AuthoritativeTrustDecisionOutcome {
  if (errors.some((error) => error.includes("fixture"))) return "verification_ineligible";
  if (errors.some((error) => error.includes("verification"))) return "verification_ineligible";
  if (errors.some((error) => error.includes("candidate"))) return "candidate_ineligible";
  if (errors.some((error) => error.includes("receipt"))) return "counter_receipt_ineligible";
  if (errors.some((error) => error.includes("credential lifecycle"))) {
    return "credential_lifecycle_ineligible";
  }
  if (errors.some((error) => error.includes("session state"))) return "session_state_ineligible";
  if (errors.some((error) => error.includes("assurance"))) return "assurance_insufficient";
  if (errors.some((error) => error.includes("purpose"))) return "purpose_ineligible";
  if (errors.some((error) => error.includes("correlation") || error.includes("mismatch"))) {
    return "correlation_mismatch";
  }
  if (errors.some((error) => error.includes("counter state"))) return "counter_state_mismatch";
  if (errors.some((error) => error.includes("expired") || error.includes("expiry"))) {
    return "evidence_expired";
  }
  if (errors.some((error) => error.includes("replay") || error.includes("clone"))) {
    return "evidence_replayed";
  }
  if (errors.some((error) => error.includes("world id"))) {
    return "world_id_requirement_unresolved";
  }
  return "malformed";
}

function statusFromOutcome(
  outcome: AuthoritativeTrustDecisionOutcome
): AuthoritativeTrustDecisionStatus {
  if (outcome === "trust_decision_created") return "trust_decision_created";
  if (outcome === "malformed") return "trust_decision_malformed";
  if (outcome === "unsupported") return "trust_decision_unsupported";
  if (outcome === "evidence_expired") return "trust_decision_expired";
  if (outcome === "evidence_replayed") return "trust_decision_replayed";
  return "trust_decision_rejected";
}

function auditDraftForDecision(input: {
  readonly request: AuthoritativeTrustDecisionRequest;
  readonly outcome: AuthoritativeTrustDecisionOutcome;
  readonly decision?: AuthoritativeTrustDecision;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "trust",
    outcome: input.decision ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    summary: input.decision
      ? "Authoritative Trust Manager decision created for one bounded evidence chain; no capability or authorization was created."
      : "Authoritative Trust Manager decision request rejected; no capability or authorization was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authoritativeTrustDecisionId: input.decision?.authoritativeTrustDecisionId,
      productionVerificationResultId:
        input.request.productionVerificationResult?.trustManagerProductionVerificationResultId,
      boundedTrustDecisionCandidateId:
        input.request.boundedTrustDecisionCandidate?.boundedTrustDecisionCandidateId,
      credentialCounterPersistenceReceiptId:
        input.request.counterPersistenceReceipt?.credentialCounterPersistenceReceiptId,
      credentialSafeReference:
        input.request.productionVerificationResult?.correlation.credentialSafeReference,
      providerKind: input.request.providerKind,
      credentialLifecycleStatus: input.request.credentialLifecycleStatus,
      sessionLifecycleState: input.request.lifecycleSnapshot?.state,
      authenticationPurpose: input.request.authenticationPurpose,
      requestedAssurance: input.request.requestedAssurance,
      outcome: input.outcome,
      expiresAt: input.request.expiresAt,
      trustDecisionCreated: input.decision?.trustDecisionCreated ?? false,
      capabilityGranted: false,
      policyApproved: false,
      userApprovalCollected: false,
      authorizationCreated: false,
      sessionKeyCreated: false,
      executionAllowed: false,
      worldIdVerified: false,
      vaultMaterialExposed: false,
      registryPlaintextExposed: false,
      rawAssertionMaterialIncluded: false,
      credentialPrivateMaterialExposed: false,
      persistedAsAuthority: false,
      errors: input.errors ?? []
    }
  });
}

export function isAuthoritativeTrustDecisionStatus(
  value: unknown
): value is AuthoritativeTrustDecisionStatus {
  return STATUSES.has(value as AuthoritativeTrustDecisionStatus);
}

export function isAuthoritativeTrustDecisionOutcome(
  value: unknown
): value is AuthoritativeTrustDecisionOutcome {
  return OUTCOMES.has(value as AuthoritativeTrustDecisionOutcome);
}

export function validateAuthoritativeTrustDecisionRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["authoritative Trust Decision request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.productionVerificationResult)) {
    errors.push("productionVerificationResult is required");
  } else {
    const result =
      validateTrustManagerProductionVerificationResultShape(request.productionVerificationResult);
    errors.push(...result.errors.map((error) => `productionVerificationResult.${error}`));
  }
  if (!isRecord(request.boundedTrustDecisionCandidate)) {
    errors.push("boundedTrustDecisionCandidate is required");
  } else {
    const result =
      validateBoundedTrustDecisionCandidateShape(request.boundedTrustDecisionCandidate);
    errors.push(...result.errors.map((error) => `boundedTrustDecisionCandidate.${error}`));
  }
  if (!isRecord(request.counterPersistenceReceipt)) {
    errors.push("counterPersistenceReceipt is required");
  } else {
    const result = validateCredentialCounterPersistenceReceipt(request.counterPersistenceReceipt);
    errors.push(...result.errors.map((error) => `counterPersistenceReceipt.${error}`));
  }
  if (!isCredentialLifecycleStatus(request.credentialLifecycleStatus)) {
    errors.push("credentialLifecycleStatus is invalid");
  }
  if (!isRecord(request.lifecycleSnapshot)) {
    errors.push("lifecycleSnapshot is required");
  } else {
    const result = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
    errors.push(...result.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isNonEmptyString(request.credentialId)) errors.push("credentialId is required");
  if (request.providerKind !== "webauthn_passkey") errors.push("providerKind must be webauthn_passkey");
  if (!isNonEmptyString(request.ownerCommitment)) errors.push("ownerCommitment is required");
  if (!isNonEmptyString(request.sessionId)) errors.push("sessionId is required");
  if (!isNonEmptyString(request.applicationId)) errors.push("applicationId is required");
  if (!isNonEmptyString(request.authenticationPurpose)
    || request.authenticationPurpose === "unsupported") {
    errors.push("authenticationPurpose is invalid or unsupported");
  }
  if (!Array.isArray(request.requestedAssurance) || request.requestedAssurance.length === 0) {
    errors.push("requestedAssurance is required");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (request.worldIdEnrollmentVerified !== undefined
    && request.worldIdEnrollmentVerified !== false) {
    errors.push("worldIdEnrollmentVerified cannot be true in K.9");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

export function validateAuthoritativeTrustDecisionShape(
  decision: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(decision)) return validation(["authoritative Trust Decision must be an object"]);
  if (!isNonEmptyString(decision.authoritativeTrustDecisionId)) {
    errors.push("authoritativeTrustDecisionId is required");
  }
  if (decision.status !== "trust_decision_created") errors.push("status must be trust_decision_created");
  if (decision.outcome !== "trust_decision_created") errors.push("outcome must be trust_decision_created");
  if (!isRecord(decision.scope)) errors.push("scope is required");
  if (!isRecord(decision.binding)) errors.push("binding is required");
  if (!isRecord(decision.evidence)) errors.push("evidence is required");
  if (!isRecord(decision.validity)) errors.push("validity is required");
  const trueFields = [
    "trustDecisionCreated",
    "productionAssertionVerified",
    "credentialLifecycleEligible",
    "sessionContextEligible",
    "assuranceSatisfied",
    "validForSpecifiedPurposeOnly"
  ];
  for (const field of trueFields) {
    if (decision[field] !== true) errors.push(`${field} must be true`);
  }
  const falseFields = [
    "capabilityGranted",
    "policyApproved",
    "userApprovalCollected",
    "authorizationCreated",
    "sessionKeyCreated",
    "executionAllowed",
    "worldIdVerified",
    "vaultMaterialExposed",
    "registryPlaintextExposed",
    "rawAssertionMaterialIncluded",
    "credentialPrivateMaterialExposed",
    "persistedAsAuthority",
    "persisted"
  ];
  for (const field of falseFields) {
    if (decision[field] !== false) errors.push(`${field} must be false`);
  }
  if (
    decision.credentialCounterCommitted !== true
    && decision.acceptedZeroCounterSemantics !== true
  ) {
    errors.push("credentialCounterCommitted or acceptedZeroCounterSemantics must be true");
  }
  return validation(errors);
}

export function createAuthoritativeTrustDecision(
  request: AuthoritativeTrustDecisionRequest,
  consumptionStore?: EphemeralTrustDecisionEvidenceConsumptionStore,
  decisionStore?: AuthoritativeTrustDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativeTrustDecisionResult {
  return evaluateAuthoritativeTrustDecision(
    request,
    consumptionStore,
    decisionStore,
    auditDraftCollector
  );
}

export function evaluateAuthoritativeTrustDecision(
  request: AuthoritativeTrustDecisionRequest,
  consumptionStore?: EphemeralTrustDecisionEvidenceConsumptionStore,
  decisionStore?: AuthoritativeTrustDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): AuthoritativeTrustDecisionResult {
  const requestValidation = validateAuthoritativeTrustDecisionRequest(request);
  if (!requestValidation.valid) {
    const auditEventDraft = auditDraftForDecision({
      request,
      outcome: "malformed",
      errors: requestValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(decisionError(
      "AUTHORITATIVE_TRUST_DECISION_MALFORMED",
      requestValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const errors = [
    ...correlationErrors(request),
    ...eligibilityErrors(request)
  ];
  if (errors.length > 0) {
    const outcome = outcomeFromErrors(errors);
    const auditEventDraft = auditDraftForDecision({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(decisionError(
      statusFromOutcome(outcome) === "trust_decision_replayed"
        ? "AUTHORITATIVE_TRUST_DECISION_REPLAYED"
        : "AUTHORITATIVE_TRUST_DECISION_REJECTED",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const evidenceChainId = createAuditCorrelationId([
    request.productionVerificationResult.trustManagerProductionVerificationResultId,
    request.boundedTrustDecisionCandidate.boundedTrustDecisionCandidateId,
    request.counterPersistenceReceipt.credentialCounterPersistenceReceiptId,
    request.sessionId,
    request.credentialId,
    request.applicationId,
    request.authenticationPurpose,
    request.auditCorrelationId,
    "authoritative-trust-decision-evidence-chain"
  ]);
  if (consumptionStore?.has(evidenceChainId)) {
    const auditEventDraft = auditDraftForDecision({
      request,
      outcome: "evidence_replayed",
      errors: ["evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(decisionError(
      "AUTHORITATIVE_TRUST_DECISION_REPLAYED",
      ["evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const acceptedZeroCounterSemantics =
    request.counterPersistenceReceipt.outcome === "counter_unchanged_accepted";
  const credentialCounterCommitted =
    request.counterPersistenceReceipt.outcome === "counter_persisted";
  const decisionId = createAuditCorrelationId([
    evidenceChainId,
    request.issuedAt,
    request.expiresAt,
    "authoritative-trust-decision"
  ]);
  const decisionBase = {
    authoritativeTrustDecisionId: decisionId,
    requestId: request.requestId,
    status: "trust_decision_created" as const,
    outcome: "trust_decision_created" as const,
    scope: {
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      ownerCommitment: request.ownerCommitment,
      credentialId: request.credentialId,
      credentialSafeReference:
        request.productionVerificationResult.correlation.credentialSafeReference,
      providerKind: request.providerKind,
      authenticationPurpose: request.authenticationPurpose,
      requestedAssurance: Object.freeze([...request.requestedAssurance]),
      auditCorrelationId: request.auditCorrelationId
    },
    binding: {
      productionVerificationResultId:
        request.productionVerificationResult.trustManagerProductionVerificationResultId,
      boundedTrustDecisionCandidateId:
        request.boundedTrustDecisionCandidate.boundedTrustDecisionCandidateId,
      credentialCounterPersistenceReceiptId:
        request.counterPersistenceReceipt.credentialCounterPersistenceReceiptId,
      counterResolutionId: request.counterResolution?.resolutionId,
      sessionLifecycleId: request.lifecycleSnapshot.lifecycleId,
      sessionLifecycleState: request.lifecycleSnapshot.state,
      challengeReferenceId:
        request.productionVerificationResult.correlation.challengeReferenceId,
      validityWindowId: createAuditCorrelationId([
        request.sessionId,
        request.credentialId,
        request.authenticationPurpose,
        request.issuedAt,
        request.expiresAt,
        "trust-decision-validity-window"
      ]),
      reusableAcrossSessions: false as const,
      reusableAcrossCredentials: false as const,
      reusableAcrossApplications: false as const,
      reusableAcrossPurposes: false as const,
      reusableAcrossOwners: false as const,
      reusableAcrossChallenges: false as const,
      reusableAcrossTimeWindows: false as const
    },
    evidence: {
      productionAssertionVerified: true as const,
      productionVerifierUsed: true as const,
      fixtureOnlyEvidence: false as const,
      credentialCounterCommitted,
      acceptedZeroCounterSemantics,
      persistedCounter:
        request.counterPersistenceReceipt.mutationSummary.persistedCounter,
      verifiedReturnedCounter:
        request.counterPersistenceReceipt.counterState.verifiedReturnedCounter,
      counterStatus:
        request.counterPersistenceReceipt.counterState.counterStatus,
      credentialLifecycleEligible: true as const,
      sessionContextEligible: true as const,
      assuranceSatisfied: true as const,
      userPresenceVerified: true as const,
      userVerificationVerified: true as const,
      challengeVerified: true as const,
      originVerified: true as const,
      rpIdHashVerified: true as const,
      signatureVerified: true as const,
      rawAssertionMaterialIncluded: false as const,
      publicKeyBytesIncluded: false as const,
      credentialRecordIncluded: false as const
    },
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false,
      invalidatedBySessionLock: true as const,
      invalidatedBySessionClose: true as const,
      invalidatedByCredentialRevocation: true as const,
      invalidatedByOwnerMismatch: true as const
    },
    requirements: requirements(),
    limitations: limitations(),
    reasons: Object.freeze([
      "production-verification-succeeded",
      "bounded-candidate-accepted",
      acceptedZeroCounterSemantics
        ? "accepted-zero-counter-semantics"
        : "counter-receipt-verified",
      "credential-lifecycle-eligible",
      "session-context-eligible",
      "assurance-satisfied",
      "purpose-bound",
      "process-local-consumption",
      "trust-manager-authority-only",
      "no-capability-grant",
      "no-policy-approval",
      "no-user-approval",
      "no-authorization",
      "no-session-key",
      "no-execution",
      "no-vault-material"
    ] satisfies readonly AuthoritativeTrustDecisionReason[]),
    revocationReference: {
      referenceId: createAuditCorrelationId([
        decisionId,
        "future-revocation-reference"
      ]),
      durableRevocationImplemented: false as const,
      futureRevocationRequired: true as const
    },
    trustDecisionCreated: true as const,
    productionAssertionVerified: true as const,
    credentialCounterCommitted,
    acceptedZeroCounterSemantics,
    credentialLifecycleEligible: true as const,
    sessionContextEligible: true as const,
    assuranceSatisfied: true as const,
    validForSpecifiedPurposeOnly: true as const,
    capabilityGranted: false as const,
    policyApproved: false as const,
    userApprovalCollected: false as const,
    authorizationCreated: false as const,
    sessionKeyCreated: false as const,
    executionAllowed: false as const,
    worldIdVerified: false as const,
    vaultMaterialExposed: false as const,
    registryPlaintextExposed: false as const,
    rawAssertionMaterialIncluded: false as const,
    credentialPrivateMaterialExposed: false as const,
    persistedAsAuthority: false as const,
    persisted: false as const
  };
  const decisionWithoutAudit = freezeRecord(decisionBase) as AuthoritativeTrustDecision;
  const shapeValidation = validateAuthoritativeTrustDecisionShape(decisionWithoutAudit);
  if (!shapeValidation.valid) {
    const auditEventDraft = auditDraftForDecision({
      request,
      outcome: "malformed",
      errors: shapeValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(decisionError(
      "AUTHORITATIVE_TRUST_DECISION_SHAPE_INVALID",
      shapeValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    evidenceChainId,
    authoritativeTrustDecisionId: decisionId,
    sessionId: request.sessionId,
    credentialId: request.credentialId,
    applicationId: request.applicationId,
    authenticationPurpose: request.authenticationPurpose,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const auditEventDraft = auditDraftForDecision({
      request,
      outcome: "evidence_replayed",
      errors: ["evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(decisionError(
      "AUTHORITATIVE_TRUST_DECISION_REPLAYED",
      ["evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = auditDraftForDecision({
    request,
    outcome: "trust_decision_created",
    decision: decisionWithoutAudit
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const decisionWithAudit = freezeRecord({
    ...decisionBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as AuthoritativeTrustDecision;
  const collectionResult = decisionStore?.addDecision(decisionWithAudit);
  const decision = freezeRecord({
    ...decisionWithAudit,
    collectionResult
  }) as AuthoritativeTrustDecision;
  return runtimeOk(decision);
}

export function createEphemeralTrustDecisionEvidenceConsumptionStore():
  EphemeralTrustDecisionEvidenceConsumptionStore {
  const records = new Map<string, AuthoritativeTrustDecisionConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.evidenceChainId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.evidenceChainId),
          records: all(),
          reason: "authoritative Trust Decision evidence chain was already consumed"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.evidenceChainId, frozen);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(evidenceChainId) {
      return records.has(evidenceChainId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

export function createInMemoryAuthoritativeTrustDecisionStore(
  options: InMemoryAuthoritativeTrustDecisionStoreOptions = {}
): AuthoritativeTrustDecisionStore {
  const maxDecisionCount = Math.max(1, options.maxDecisionCount ?? 100);
  const decisions = new Map<string, AuthoritativeTrustDecision>();
  const snapshot = (): AuthoritativeTrustDecisionCollection => freezeRecord({
    decisions: Array.from(decisions.values()),
    count: decisions.size,
    maxDecisionCount
  });
  const result = (
    status: AuthoritativeTrustDecisionCollectionStatus,
    extra: Omit<AuthoritativeTrustDecisionCollectionResult, "status" | "collection"> = {}
  ): AuthoritativeTrustDecisionCollectionResult => freezeRecord({
    status,
    collection: snapshot(),
    ...extra
  });
  return {
    addDecision(decision) {
      const validationResult = validateAuthoritativeTrustDecisionShape(decision);
      if (!validationResult.valid) {
        return result("rejected_invalid", { errors: validationResult.errors });
      }
      if (decisions.has(decision.authoritativeTrustDecisionId)) {
        return result("rejected_duplicate", {
          decision,
          reason: "authoritative Trust Decision ID already exists"
        });
      }
      let evictedDecisions: AuthoritativeTrustDecision[] = [];
      if (decisions.size >= maxDecisionCount) {
        const oldestKey = decisions.keys().next().value;
        if (typeof oldestKey === "string") {
          const evicted = decisions.get(oldestKey);
          decisions.delete(oldestKey);
          if (evicted) evictedDecisions = [evicted];
        }
      }
      const frozen = freezeRecord(decision);
      decisions.set(frozen.authoritativeTrustDecisionId, frozen);
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

export function createFixtureTrustDecisionConsumer(): TrustDecisionConsumer {
  return {
    acceptTrustDecisionShape(request) {
      const result = validateAuthoritativeTrustDecisionShape(
        request.authoritativeTrustDecision
      );
      return freezeRecord({
        status: result.valid ? "accepted_shape" as const : "rejected_shape" as const,
        authoritativeTrustDecisionId: result.valid
          ? request.authoritativeTrustDecision.authoritativeTrustDecisionId
          : undefined,
        errors: result.errors,
        capabilityGranted: false as const,
        authorizationCreated: false as const,
        policyApproved: false as const
      });
    }
  };
}
