import { createAuditEventDraft, type AuditDraftCollectionResult, type AuditDraftCollector, type AuditEventDraft } from "./audit.ts";
import type { AuthenticationProviderAssurance } from "./authenticationEvidence.ts";
import { createAuditCorrelationId, createUserSessionContext, runtimeDenied, runtimeOk, type RuntimeValidationResult } from "./helpers.ts";
import type {
  LifecycleTransitionEligibility,
  ProductionAuthenticationVerificationResultValue
} from "./productionAuthenticationVerification.ts";
import {
  validateProductionAuthenticationVerificationResult
} from "./productionAuthenticationVerification.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionLifecycleEvidenceReference,
  UserSessionLifecycleLimitation,
  UserSessionLifecycleSnapshot,
  UserSessionLifecycleState,
  UserSessionTransitionRequest,
  UserSessionTransitionResult
} from "./sessionLifecycle.ts";
import {
  validateUserSessionLifecycleSnapshotShape,
  validateUserSessionTransitionRequestShape
} from "./sessionLifecycle.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext,
  UserSessionContextInput,
  UserSessionContextResult
} from "./types.ts";

export type LifecycleTransitionCandidateStatus =
  | "candidate_created"
  | "candidate_rejected"
  | "candidate_malformed"
  | "candidate_unsupported";

export type LifecycleTransitionCandidateOutcome =
  | "candidate_created"
  | "verification_ineligible"
  | "correlation_mismatch"
  | "evidence_expired"
  | "evidence_replayed"
  | "assurance_insufficient"
  | "transition_unsupported"
  | "lifecycle_state_ineligible"
  | "malformed"
  | "unsupported";

export type LifecycleTransitionCandidateReason =
  | "production-webauthn-verification-succeeded"
  | "lifecycle-eligibility-valid"
  | "partial-unlock-only"
  | "verification-result-invalid"
  | "verification-not-successful"
  | "lifecycle-eligibility-missing"
  | "session-mismatch"
  | "owner-commitment-mismatch"
  | "credential-mismatch"
  | "provider-mismatch"
  | "transition-request-mismatch"
  | "challenge-reference-mismatch"
  | "assurance-insufficient"
  | "verification-expired"
  | "verification-replayed"
  | "lifecycle-state-ineligible"
  | "transition-unsupported"
  | "request-shape-invalid"
  | (string & {});

export interface LifecycleTransitionCandidateRequirement {
  readonly requirementId: string;
  readonly satisfied: boolean;
  readonly description: string;
}

export interface LifecycleTransitionCandidateLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface LifecycleTransitionEvidenceSummary {
  readonly verificationId: string;
  readonly verificationOutcome: ProductionAuthenticationVerificationResultValue["outcome"];
  readonly verificationStatus: ProductionAuthenticationVerificationResultValue["status"];
  readonly lifecycleEligibilityId: string;
  readonly credentialId: string;
  readonly providerId: string;
  readonly sessionId: string;
  readonly ownerCommitment?: string;
  readonly challengeReferenceId?: string;
  readonly productionVerified: boolean;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly signatureVerified: boolean;
  readonly counterStatus: ProductionAuthenticationVerificationResultValue["evidenceSummary"]["counterStatus"];
}

export interface LifecycleTransitionCandidateRequest {
  readonly requestId: string;
  readonly productionAuthenticationVerification: ProductionAuthenticationVerificationResultValue;
  readonly lifecycleEligibility?: LifecycleTransitionEligibility;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly transitionRequest: UserSessionTransitionRequest;
  readonly expectedSessionId?: string;
  readonly expectedOwnerCommitment?: string;
  readonly expectedCredentialId?: string;
  readonly expectedProviderId?: string;
  readonly expectedChallengeReferenceId?: string;
  readonly requestedAssurance?: readonly AuthenticationProviderAssurance[];
  readonly targetState?: "partially_unlocked";
  readonly applicationId?: ApplicationId;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface LifecycleTransitionCandidate {
  readonly lifecycleTransitionCandidateId: string;
  readonly requestId: string;
  readonly status: LifecycleTransitionCandidateStatus;
  readonly outcome: LifecycleTransitionCandidateOutcome;
  readonly reasons: readonly LifecycleTransitionCandidateReason[];
  readonly requirements: readonly LifecycleTransitionCandidateRequirement[];
  readonly limitations: readonly LifecycleTransitionCandidateLimitation[];
  readonly evidenceSummary: LifecycleTransitionEvidenceSummary;
  readonly lifecycleEligibility: LifecycleTransitionEligibility;
  readonly sessionId: string;
  readonly ownerCommitment?: string;
  readonly credentialId: string;
  readonly providerId: string;
  readonly challengeReferenceId?: string;
  readonly transitionRequestId: string;
  readonly lifecycleEvent: "unlock_succeeded";
  readonly previousState: "unlocking";
  readonly targetState: "partially_unlocked";
  readonly applicationId?: ApplicationId;
  readonly createdAt: string;
  readonly auditCorrelationId: string;
  readonly productionWebAuthnVerificationPerformed: true;
  readonly browserWebAuthnInvocationPerformed: false;
  readonly credentialLoadedFromVault: false;
  readonly deviceVaultUnlocked: false;
  readonly grantsAuthority: false;
  readonly activeCapabilityCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
}

export type LifecycleTransitionCandidateResult = RuntimeResult<LifecycleTransitionCandidate>;

export interface ProductionVerificationConsumptionRecord {
  readonly verificationId: string;
  readonly consumedAt: string;
  readonly auditCorrelationId?: string;
}

export type ProductionVerificationConsumptionStatus = "consumed" | "replayed" | "cleared";

export interface ProductionVerificationConsumptionResult {
  readonly status: ProductionVerificationConsumptionStatus;
  readonly record?: ProductionVerificationConsumptionRecord;
  readonly records: readonly ProductionVerificationConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralProductionVerificationConsumptionStore {
  consume(verificationId: string, auditCorrelationId?: string): ProductionVerificationConsumptionResult;
  has(verificationId: string): boolean;
  get(verificationId: string): ProductionVerificationConsumptionRecord | undefined;
  getAll(): readonly ProductionVerificationConsumptionRecord[];
  clear(): ProductionVerificationConsumptionResult;
}

export interface ProductionVerifiedPartialUnlockRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly transitionRequest: UserSessionTransitionRequest;
  readonly candidate: LifecycleTransitionCandidate;
  readonly consumptionStore?: EphemeralProductionVerificationConsumptionStore;
  readonly auditDraftCollector?: AuditDraftCollector;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ProductionVerifiedPartialUnlockResultValue {
  readonly transitionResult: UserSessionTransitionResult;
  readonly candidate: LifecycleTransitionCandidate;
  readonly consumed?: ProductionVerificationConsumptionResult;
  readonly auditEventDraft: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly productionWebAuthnVerificationPerformed: true;
  readonly browserWebAuthnInvocationPerformed: false;
  readonly credentialLoadedFromVault: false;
  readonly deviceVaultUnlocked: false;
  readonly protectedIdentityStateAvailable: false;
  readonly activeCapabilitiesAvailable: false;
  readonly sessionKeysCreated: false;
  readonly grantsAuthority: false;
  readonly activeCapabilityCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
}

export type ProductionVerifiedPartialUnlockResult =
  RuntimeResult<ProductionVerifiedPartialUnlockResultValue>;

export interface ProductionVerifiedPartialUnlockContextInput {
  readonly userSessionContext: UserSessionContext;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly candidate?: LifecycleTransitionCandidate;
}

const CANDIDATE_STATUSES = new Set<LifecycleTransitionCandidateStatus>([
  "candidate_created",
  "candidate_rejected",
  "candidate_malformed",
  "candidate_unsupported"
]);

const CANDIDATE_OUTCOMES = new Set<LifecycleTransitionCandidateOutcome>([
  "candidate_created",
  "verification_ineligible",
  "correlation_mismatch",
  "evidence_expired",
  "evidence_replayed",
  "assurance_insufficient",
  "transition_unsupported",
  "lifecycle_state_ineligible",
  "malformed",
  "unsupported"
]);

const DEFAULT_LIMITATIONS: readonly LifecycleTransitionCandidateLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "partial_unlock_only",
    description: "Successful production verification can only reach partially_unlocked."
  }),
  Object.freeze({
    limitationId: "vault_remains_locked",
    description: "Device Vault remains locked and protected identity state remains unavailable."
  }),
  Object.freeze({
    limitationId: "explicit_inputs_only",
    description: "The bridge consumes explicit in-memory WebAuthn inputs; it does not invoke browser credential APIs."
  }),
  Object.freeze({
    limitationId: "no_authority",
    description: "No active capability, session key, authorization package, proof, or adapter execution is created."
  }),
  Object.freeze({
    limitationId: "process_local_replay_tracking",
    description: "Replay consumption is process-local only and is not durable production replay prevention."
  })
]);

const PARTIAL_UNLOCK_SNAPSHOT_LIMITATIONS: readonly UserSessionLifecycleLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "production_webauthn_factor_verified",
    description: "A production WebAuthn assertion was verified from explicit inputs."
  }),
  Object.freeze({
    limitationId: "device_vault_locked",
    description: "Device Vault remains locked; protected identity state is unavailable."
  }),
  Object.freeze({
    limitationId: "partial_session_only",
    description: "Session is partially unlocked only and cannot grant capabilities or authorization."
  }),
  Object.freeze({
    limitationId: "no_persistence",
    description: "Partial unlock state is process-local unless a future reviewed storage boundary is added."
  })
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

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
}

function candidateError(
  code: string,
  message: string,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code,
    message,
    boundary: "user-session",
    recoverable: true,
    details: {
      errors
    }
  };
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function providedAssurance(
  verification: ProductionAuthenticationVerificationResultValue
): readonly AuthenticationProviderAssurance[] {
  const assurance: AuthenticationProviderAssurance[] = [];
  if (verification.evidenceSummary.userPresent) assurance.push("user_presence");
  if (verification.evidenceSummary.userVerified) assurance.push("user_verification");
  if (verification.evidenceSummary.productionVerified) assurance.push("phishing_resistant");
  return Object.freeze(assurance);
}

function assuranceSufficient(
  provided: readonly AuthenticationProviderAssurance[],
  requested: readonly AuthenticationProviderAssurance[] = []
): boolean {
  return requested.every((entry) => provided.includes(entry));
}

function requirementsFor(errors: readonly string[]): readonly LifecycleTransitionCandidateRequirement[] {
  return freezeRecord([
    {
      requirementId: "successful-production-verification",
      satisfied: !errors.some((error) => error.includes("verification")),
      description: "Production WebAuthn verification must have succeeded."
    },
    {
      requirementId: "valid-lifecycle-eligibility",
      satisfied: !errors.some((error) => error.includes("eligibility")),
      description: "Lifecycle transition eligibility must correlate to the verification result."
    },
    {
      requirementId: "unlocking-to-partially-unlocked",
      satisfied: !errors.some((error) => error.includes("lifecycle state") || error.includes("transition")),
      description: "Only unlocking + unlock_succeeded -> partially_unlocked is supported."
    },
    {
      requirementId: "correlation",
      satisfied: !errors.some((error) => error.includes("mismatch")),
      description: "Session, owner, credential, provider, challenge, and transition references must match."
    }
  ]);
}

function outcomeForErrors(errors: readonly string[], verification: ProductionAuthenticationVerificationResultValue):
  LifecycleTransitionCandidateOutcome {
  if (errors.length === 0) return "candidate_created";
  if (errors.some((error) => error.includes("expired"))) return "evidence_expired";
  if (errors.some((error) => error.includes("replayed"))) return "evidence_replayed";
  if (errors.some((error) => error.includes("assurance"))) return "assurance_insufficient";
  if (errors.some((error) => error.includes("lifecycle state"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("transition"))) return "transition_unsupported";
  if (errors.some((error) => error.includes("mismatch"))) return "correlation_mismatch";
  if (
    verification.status !== "verification_succeeded"
    || verification.outcome !== "webauthn_assertion_verified"
  ) return "verification_ineligible";
  return "malformed";
}

function reasonsForErrors(errors: readonly string[]): readonly LifecycleTransitionCandidateReason[] {
  const reasons: LifecycleTransitionCandidateReason[] = ["partial-unlock-only"];
  if (errors.length === 0) {
    reasons.push("production-webauthn-verification-succeeded", "lifecycle-eligibility-valid");
    return Object.freeze(reasons);
  }
  if (errors.some((error) => error.includes("verification result"))) reasons.push("verification-result-invalid");
  if (errors.some((error) => error.includes("not successful"))) reasons.push("verification-not-successful");
  if (errors.some((error) => error.includes("eligibility"))) reasons.push("lifecycle-eligibility-missing");
  if (errors.some((error) => error.includes("session"))) reasons.push("session-mismatch");
  if (errors.some((error) => error.includes("owner"))) reasons.push("owner-commitment-mismatch");
  if (errors.some((error) => error.includes("credential"))) reasons.push("credential-mismatch");
  if (errors.some((error) => error.includes("provider"))) reasons.push("provider-mismatch");
  if (errors.some((error) => error.includes("transition request"))) reasons.push("transition-request-mismatch");
  if (errors.some((error) => error.includes("challenge"))) reasons.push("challenge-reference-mismatch");
  if (errors.some((error) => error.includes("assurance"))) reasons.push("assurance-insufficient");
  if (errors.some((error) => error.includes("expired"))) reasons.push("verification-expired");
  if (errors.some((error) => error.includes("replayed"))) reasons.push("verification-replayed");
  if (errors.some((error) => error.includes("lifecycle state"))) reasons.push("lifecycle-state-ineligible");
  if (errors.some((error) => error.includes("transition unsupported"))) reasons.push("transition-unsupported");
  if (errors.some((error) => error.includes("request"))) reasons.push("request-shape-invalid");
  return Object.freeze(reasons);
}

function evidenceSummaryFor(
  verification: ProductionAuthenticationVerificationResultValue,
  eligibility: LifecycleTransitionEligibility
): LifecycleTransitionEvidenceSummary {
  return freezeRecord({
    verificationId: verification.verificationId,
    verificationOutcome: verification.outcome,
    verificationStatus: verification.status,
    lifecycleEligibilityId: eligibility.eligibilityId,
    credentialId: verification.evidenceSummary.credentialId,
    providerId: verification.providerId,
    sessionId: verification.correlation.sessionId,
    ownerCommitment: verification.correlation.ownerCommitment,
    challengeReferenceId: verification.correlation.challengeReferenceId,
    productionVerified: verification.evidenceSummary.productionVerified,
    userPresent: verification.evidenceSummary.userPresent,
    userVerified: verification.evidenceSummary.userVerified,
    signatureVerified: verification.evidenceSummary.signatureVerified,
    counterStatus: verification.evidenceSummary.counterStatus
  });
}

export function isLifecycleTransitionCandidateStatus(
  value: unknown
): value is LifecycleTransitionCandidateStatus {
  return CANDIDATE_STATUSES.has(value as LifecycleTransitionCandidateStatus);
}

export function isLifecycleTransitionCandidateOutcome(
  value: unknown
): value is LifecycleTransitionCandidateOutcome {
  return CANDIDATE_OUTCOMES.has(value as LifecycleTransitionCandidateOutcome);
}

export function validateLifecycleTransitionCandidateRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["lifecycle transition candidate request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  const verificationValidation = validateProductionAuthenticationVerificationResult(
    request.productionAuthenticationVerification
  );
  if (!verificationValidation.valid) {
    errors.push(...verificationValidation.errors.map((error) => `productionAuthenticationVerification.${error}`));
  }
  if (!isRecord(request.lifecycleEligibility)) errors.push("lifecycleEligibility is required");
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!snapshotValidation.valid) {
    errors.push(...snapshotValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  const transitionValidation = validateUserSessionTransitionRequestShape(request.transitionRequest);
  if (!transitionValidation.valid) {
    errors.push(...transitionValidation.errors.map((error) => `transitionRequest.${error}`));
  }
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (
    request.requestedAssurance !== undefined
    && !Array.isArray(request.requestedAssurance)
  ) errors.push("requestedAssurance must be an array when provided");
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

export function validateLifecycleTransitionCandidateShape(
  candidate: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(candidate)) return validation(["lifecycle transition candidate must be an object"]);
  if (!isNonEmptyString(candidate.lifecycleTransitionCandidateId)) {
    errors.push("lifecycleTransitionCandidateId is required");
  }
  if (!isLifecycleTransitionCandidateStatus(candidate.status)) errors.push("candidate status is invalid");
  if (!isLifecycleTransitionCandidateOutcome(candidate.outcome)) errors.push("candidate outcome is invalid");
  if (candidate.outcome !== "candidate_created") errors.push("only created candidates may be used for partial unlock");
  if (candidate.previousState !== "unlocking") errors.push("previousState must be unlocking");
  if (candidate.targetState !== "partially_unlocked") errors.push("targetState must be partially_unlocked");
  if (candidate.lifecycleEvent !== "unlock_succeeded") errors.push("lifecycleEvent must be unlock_succeeded");
  if (candidate.productionWebAuthnVerificationPerformed !== true) {
    errors.push("productionWebAuthnVerificationPerformed must be true");
  }
  if (candidate.browserWebAuthnInvocationPerformed !== false) {
    errors.push("browserWebAuthnInvocationPerformed must be false");
  }
  if (candidate.credentialLoadedFromVault !== false) errors.push("credentialLoadedFromVault must be false");
  if (candidate.deviceVaultUnlocked !== false) errors.push("deviceVaultUnlocked must be false");
  if (candidate.grantsAuthority !== false) errors.push("grantsAuthority must be false");
  if (candidate.activeCapabilityCreated !== false) errors.push("activeCapabilityCreated must be false");
  if (candidate.authorizationCreated !== false) errors.push("authorizationCreated must be false");
  if (candidate.persisted !== false) errors.push("persisted must be false");
  if (isRecord(candidate)) {
    errors.push(...validateNoSensitiveMetadataKeys(candidate).errors);
  }
  return validation(errors);
}

export function createLifecycleTransitionCandidate(
  request: LifecycleTransitionCandidateRequest
): LifecycleTransitionCandidateResult {
  const requestValidation = validateLifecycleTransitionCandidateRequest(request);
  if (!requestValidation.valid) {
    return runtimeDenied(candidateError(
      "LIFECYCLE_TRANSITION_CANDIDATE_INVALID",
      "lifecycle transition candidate request failed validation",
      requestValidation.errors
    ));
  }

  const verification = request.productionAuthenticationVerification;
  const eligibility = request.lifecycleEligibility ?? verification.lifecycleEligibility;
  const errors: string[] = [];
  if (!eligibility) errors.push("lifecycle eligibility is missing");
  if (verification.status !== "verification_succeeded" || verification.outcome !== "webauthn_assertion_verified") {
    errors.push("production verification result is not successful");
  }
  if (verification.status === "verification_replayed" || verification.outcome === "replay_detected") {
    errors.push("production verification evidence was replayed");
  }
  if (expired(verification.expiresAt)) errors.push("production verification result is expired");
  if (request.lifecycleSnapshot.state !== "unlocking") errors.push("lifecycle state must be unlocking");
  if (request.transitionRequest.event !== "unlock_succeeded") {
    errors.push("transition unsupported: only unlock_succeeded is permitted");
  }
  if (!request.transitionRequest.transitionRequestId) {
    errors.push("transition request id is required");
  }
  if (eligibility) {
    if (eligibility.sessionId !== request.lifecycleSnapshot.sessionId) errors.push("session mismatch");
    if (eligibility.sessionId !== verification.correlation.sessionId) errors.push("session mismatch");
    if (eligibility.providerId !== verification.providerId) errors.push("provider mismatch");
    if (eligibility.credentialId !== verification.evidenceSummary.credentialId) errors.push("credential mismatch");
    if (
      request.transitionRequest.transitionRequestId !== undefined
      && eligibility.lifecycleTransitionRequestId !== request.transitionRequest.transitionRequestId
    ) errors.push("transition request mismatch");
  }
  if (request.expectedSessionId !== undefined && verification.correlation.sessionId !== request.expectedSessionId) {
    errors.push("session mismatch");
  }
  if (
    request.expectedOwnerCommitment !== undefined
    && verification.correlation.ownerCommitment !== request.expectedOwnerCommitment
  ) errors.push("owner commitment mismatch");
  if (
    request.expectedCredentialId !== undefined
    && verification.evidenceSummary.credentialId !== request.expectedCredentialId
  ) errors.push("credential mismatch");
  if (request.expectedProviderId !== undefined && verification.providerId !== request.expectedProviderId) {
    errors.push("provider mismatch");
  }
  if (
    request.expectedChallengeReferenceId !== undefined
    && verification.correlation.challengeReferenceId !== request.expectedChallengeReferenceId
  ) errors.push("challenge reference mismatch");
  if (!assuranceSufficient(providedAssurance(verification), request.requestedAssurance)) {
    errors.push("assurance insufficient");
  }

  const outcome = outcomeForErrors(errors, verification);
  if (outcome !== "candidate_created" || !eligibility) {
    return runtimeDenied(candidateError(
      "LIFECYCLE_TRANSITION_CANDIDATE_REJECTED",
      "lifecycle transition candidate was rejected",
      errors
    ));
  }

  const auditCorrelationId = request.auditCorrelationId
    ?? verification.auditCorrelationId
    ?? createAuditCorrelationId([
      verification.correlation.sessionId,
      request.requestId,
      "production-verified-partial-unlock-candidate"
    ]);
  const createdAt = request.requestedAt ?? new Date().toISOString();
  const transitionRequestId = request.transitionRequest.transitionRequestId ?? "";
  const candidate: LifecycleTransitionCandidate = freezeRecord({
    lifecycleTransitionCandidateId: `${auditCorrelationId}:lifecycle-candidate`,
    requestId: request.requestId,
    status: "candidate_created",
    outcome,
    reasons: reasonsForErrors(errors),
    requirements: requirementsFor(errors),
    limitations: DEFAULT_LIMITATIONS,
    evidenceSummary: evidenceSummaryFor(verification, eligibility),
    lifecycleEligibility: eligibility,
    sessionId: verification.correlation.sessionId,
    ownerCommitment: verification.correlation.ownerCommitment,
    credentialId: verification.evidenceSummary.credentialId,
    providerId: verification.providerId,
    challengeReferenceId: verification.correlation.challengeReferenceId,
    transitionRequestId,
    lifecycleEvent: "unlock_succeeded",
    previousState: "unlocking",
    targetState: "partially_unlocked",
    applicationId: request.applicationId ?? verification.correlation.applicationId,
    createdAt,
    auditCorrelationId,
    productionWebAuthnVerificationPerformed: true,
    browserWebAuthnInvocationPerformed: false,
    credentialLoadedFromVault: false,
    deviceVaultUnlocked: false,
    grantsAuthority: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    persisted: false
  });
  const candidateValidation = validateLifecycleTransitionCandidateShape(candidate);
  if (!candidateValidation.valid) {
    return runtimeDenied(candidateError(
      "LIFECYCLE_TRANSITION_CANDIDATE_INVALID",
      "lifecycle transition candidate failed shape validation",
      candidateValidation.errors
    ));
  }
  return runtimeOk(candidate);
}

export function createEphemeralProductionVerificationConsumptionStore():
  EphemeralProductionVerificationConsumptionStore {
  const records = new Map<string, ProductionVerificationConsumptionRecord>();

  function all(): readonly ProductionVerificationConsumptionRecord[] {
    return Object.freeze(Array.from(records.values()));
  }

  return {
    consume(verificationId, auditCorrelationId) {
      if (records.has(verificationId)) {
        return freezeRecord({
          status: "replayed",
          record: records.get(verificationId),
          records: all(),
          reason: "Production verification result was already consumed in this process-local store."
        });
      }
      const record = freezeRecord({
        verificationId,
        consumedAt: new Date().toISOString(),
        auditCorrelationId
      });
      records.set(verificationId, record);
      return freezeRecord({
        status: "consumed",
        record,
        records: all()
      });
    },
    has(verificationId) {
      return records.has(verificationId);
    },
    get(verificationId) {
      return records.get(verificationId);
    },
    getAll: all,
    clear() {
      records.clear();
      return freezeRecord({
        status: "cleared",
        records: all()
      });
    }
  };
}

function transitionAuditDraft(input: {
  readonly request: ProductionVerifiedPartialUnlockRequest;
  readonly status: "validation_succeeded" | "validation_failed";
  readonly outcome: string;
  readonly nextSnapshot?: UserSessionLifecycleSnapshot;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.status,
    requestKind: "generic",
    sessionId: input.request.lifecycleSnapshot.sessionId,
    applicationId: input.request.candidate.applicationId,
    summary: input.status === "validation_succeeded"
      ? "Production-verified partial session unlock completed; Device Vault remains locked."
      : "Production-verified partial session unlock was rejected.",
    auditCorrelationId: input.request.auditCorrelationId ?? input.request.candidate.auditCorrelationId,
    redactedDetails: {
      partialUnlockOutcome: input.outcome,
      candidateId: input.request.candidate.lifecycleTransitionCandidateId,
      verificationId: input.request.candidate.evidenceSummary.verificationId,
      lifecycleEligibilityId: input.request.candidate.lifecycleEligibility.eligibilityId,
      previousState: input.request.lifecycleSnapshot.state,
      requestedEvent: input.request.transitionRequest.event,
      nextState: input.nextSnapshot?.state,
      transitionRequestId: input.request.transitionRequest.transitionRequestId,
      productionWebAuthnVerificationPerformed: true,
      browserWebAuthnInvocationPerformed: false,
      credentialLoadedFromVault: false,
      deviceVaultUnlocked: false,
      protectedIdentityStateAvailable: false,
      activeCapabilitiesAvailable: false,
      authorizationCreated: false,
      persisted: false,
      errors: input.errors ?? []
    }
  });
}

function evidenceReferenceForCandidate(candidate: LifecycleTransitionCandidate):
  UserSessionLifecycleEvidenceReference {
  return freezeRecord({
    referenceId: `${candidate.lifecycleTransitionCandidateId}:evidence-reference`,
    kind: "authentication_evidence",
    source: "production-webauthn-verification",
    capturedAt: candidate.createdAt,
    metadata: {
      verificationId: candidate.evidenceSummary.verificationId,
      lifecycleEligibilityId: candidate.lifecycleEligibility.eligibilityId,
      credentialId: candidate.credentialId,
      providerId: candidate.providerId,
      challengeReferenceId: candidate.challengeReferenceId,
      productionWebAuthnVerificationPerformed: true,
      deviceVaultUnlocked: false
    },
    verified: false,
    rawEvidenceIncluded: false
  });
}

export function transitionUserSessionWithProductionVerification(
  request: ProductionVerifiedPartialUnlockRequest
): ProductionVerifiedPartialUnlockResult {
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  const transitionValidation = validateUserSessionTransitionRequestShape(request.transitionRequest);
  const candidateValidation = validateLifecycleTransitionCandidateShape(request.candidate);
  const errors = [
    ...snapshotValidation.errors,
    ...transitionValidation.errors,
    ...candidateValidation.errors
  ];
  if (request.lifecycleSnapshot.state !== "unlocking") errors.push("lifecycle state must be unlocking");
  if (request.transitionRequest.event !== "unlock_succeeded") {
    errors.push("transition unsupported: only unlock_succeeded is permitted");
  }
  if (request.transitionRequest.transitionRequestId !== request.candidate.transitionRequestId) {
    errors.push("transition request mismatch");
  }
  if (request.lifecycleSnapshot.sessionId !== request.candidate.sessionId) errors.push("session mismatch");
  if (request.candidate.targetState !== "partially_unlocked") {
    errors.push("target state must be partially_unlocked");
  }

  let consumed: ProductionVerificationConsumptionResult | undefined;
  if (errors.length === 0) {
    consumed = request.consumptionStore?.consume(
      request.candidate.evidenceSummary.verificationId,
      request.auditCorrelationId ?? request.candidate.auditCorrelationId
    );
    if (consumed?.status === "replayed") {
      errors.push("production verification result was replayed");
    }
  }

  if (errors.length > 0) {
    const auditEventDraft = transitionAuditDraft({
      request,
      status: "validation_failed",
      outcome: "partial_unlock_rejected",
      errors
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(candidateError(
      "PRODUCTION_VERIFIED_PARTIAL_UNLOCK_REJECTED",
      "production-verified partial unlock was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const transitionedAt = request.requestedAt ?? new Date().toISOString();
  const metadata = freezeRecord({
    ...(request.lifecycleSnapshot.metadata ?? {}),
    updatedAt: transitionedAt,
    lastTransitionAt: transitionedAt,
    lastTransitionRequestId: request.transitionRequest.transitionRequestId,
    lastTransitionEvent: "unlock_succeeded" as const,
    lastTransitionReason: "production-verification-partial-unlock",
    lifecycleAuthenticationFactorVerified: true,
    authenticationEvidenceReferenceId: request.candidate.evidenceSummary.verificationId,
    deviceVaultUnlocked: false as const,
    protectedStateAvailable: false as const,
    activeCapabilitiesAvailable: false as const,
    authorizationAvailable: false as const,
    strongerVaultUnlockRequired: true as const,
    persisted: false as const,
    requestMetadata: {
      ...(request.lifecycleSnapshot.metadata?.requestMetadata ?? {}),
      ...(request.metadata ? redactRuntimeMetadata(request.metadata).value : {}),
      productionWebAuthnVerificationPerformed: true,
      browserWebAuthnInvocationPerformed: false,
      credentialLoadedFromVault: false,
      deviceVaultUnlocked: false,
      protectedIdentityStateAvailable: false,
      activeCapabilitiesAvailable: false,
      authorizationCreated: false,
      persisted: false
    }
  });
  const nextSnapshot: UserSessionLifecycleSnapshot = freezeRecord({
    lifecycleId: request.lifecycleSnapshot.lifecycleId,
    sessionId: request.lifecycleSnapshot.sessionId,
    state: "partially_unlocked" as UserSessionLifecycleState,
    sequence: request.lifecycleSnapshot.sequence + 1,
    version: request.lifecycleSnapshot.version + 1,
    createdAt: request.lifecycleSnapshot.createdAt,
    updatedAt: transitionedAt,
    lastTransition: {
      event: "unlock_succeeded",
      previousState: "unlocking",
      nextState: "partially_unlocked",
      reason: "production-verification-partial-unlock",
      transitionedAt,
      transitionRequestId: request.transitionRequest.transitionRequestId
    },
    metadata,
    limitations: PARTIAL_UNLOCK_SNAPSHOT_LIMITATIONS,
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  });
  const evidenceReferences = Object.freeze([evidenceReferenceForCandidate(request.candidate)]);
  const transitionResult: UserSessionTransitionResult = freezeRecord({
    status: "transitioned",
    previousState: "unlocking",
    nextState: "partially_unlocked",
    event: "unlock_succeeded",
    reason: "production-verification-partial-unlock",
    transitionedAt,
    auditCorrelationId: request.auditCorrelationId ?? request.candidate.auditCorrelationId,
    snapshot: nextSnapshot,
    futureRequirements: Object.freeze([{
      requirementId: "device-vault-unlock",
      evidenceKind: "unlock_evidence",
      satisfiedByReference: false,
      verified: false
    }]),
    evidenceReferences,
    evidenceReferencesVerified: false,
    limitations: PARTIAL_UNLOCK_SNAPSHOT_LIMITATIONS
  });
  const auditEventDraft = transitionAuditDraft({
    request,
    status: "validation_succeeded",
    outcome: "partially_unlocked",
    nextSnapshot
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    transitionResult,
    candidate: request.candidate,
    consumed,
    auditEventDraft,
    auditDraftCollectionResult,
    productionWebAuthnVerificationPerformed: true,
    browserWebAuthnInvocationPerformed: false,
    credentialLoadedFromVault: false,
    deviceVaultUnlocked: false,
    protectedIdentityStateAvailable: false,
    activeCapabilitiesAvailable: false,
    sessionKeysCreated: false,
    grantsAuthority: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    persisted: false
  }));
}

export function deriveUserSessionContextFromProductionVerifiedPartialUnlock(
  input: ProductionVerifiedPartialUnlockContextInput
): UserSessionContextResult {
  const metadata = input.userSessionContext.metadata ?? {};
  const contextInput: UserSessionContextInput = {
    sessionId: input.userSessionContext.sessionId,
    ownerCommitment: input.userSessionContext.ownerCommitment,
    status: input.lifecycleSnapshot.state === "partially_unlocked"
      ? "partially-unlocked"
      : input.userSessionContext.status,
    activeApplicationId: input.userSessionContext.activeApplicationId,
    activeCapabilityIds: input.userSessionContext.activeCapabilityIds,
    pendingIntentIds: input.userSessionContext.pendingIntentIds,
    policyMode: input.userSessionContext.policyMode,
    recoveryState: input.userSessionContext.recoveryState,
    timeout: input.userSessionContext.timeout,
    metadata: {
      ...metadata,
      lifecycleState: input.lifecycleSnapshot.state,
      lifecycleTransitionSequence: input.lifecycleSnapshot.sequence,
      lastLifecycleTransitionAt: input.lifecycleSnapshot.metadata?.lastTransitionAt,
      authenticationEvidenceReferenceId:
        input.lifecycleSnapshot.metadata?.authenticationEvidenceReferenceId
        ?? input.candidate?.evidenceSummary.verificationId,
      deviceVaultUnlocked: false,
      protectedStateAvailable: false,
      activeCapabilitiesAvailable: false,
      authorizationAvailable: false,
      strongerVaultUnlockRequired: true,
      requestMetadata: {
        ...(isRecord(metadata.requestMetadata) ? metadata.requestMetadata : {}),
        lifecycleState: input.lifecycleSnapshot.state,
        lifecycleAuthenticationFactorVerified:
          input.lifecycleSnapshot.metadata?.lifecycleAuthenticationFactorVerified === true,
        deviceVaultUnlocked: false,
        protectedStateAvailable: false,
        activeCapabilitiesAvailable: false,
        authorizationAvailable: false,
        fullUnlockClaimed: false
      }
    }
  };
  return createUserSessionContext(contextInput);
}
