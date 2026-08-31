import { createAuditEventDraft, type AuditEventDraft } from "./audit.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type {
  AuthenticationProviderAssurance,
  ProductionAuthenticationEvidence,
  ProductionAuthenticationRequest
} from "./authenticationEvidence.ts";
import {
  validateAuthenticationEvidenceAssurance,
  validateAuthenticationEvidenceCorrelation,
  validateAuthenticationEvidenceFreshness,
  validateProductionAuthenticationEvidenceShape,
  validateProductionAuthenticationRequest
} from "./authenticationEvidence.ts";
import type {
  UserSessionLifecycleSnapshot,
  UserSessionLifecycleState,
  UserSessionTransitionRequest,
  UserSessionTransitionResult
} from "./sessionLifecycle.ts";
import {
  transitionUserSessionLifecycle,
  validateUserSessionLifecycleSnapshotShape,
  validateUserSessionTransitionRequestShape
} from "./sessionLifecycle.ts";
import type {
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type FixtureAuthenticationVerificationStatus =
  | "fixture_verified"
  | "fixture_rejected"
  | "fixture_malformed"
  | "fixture_expired"
  | "fixture_replayed"
  | "fixture_provider_unsupported";

export type FixtureAuthenticationVerificationOutcome =
  | "fixture_evidence_verified"
  | "fixture_evidence_rejected"
  | "fixture_evidence_malformed"
  | "fixture_evidence_expired"
  | "fixture_evidence_replayed"
  | "fixture_challenge_mismatch"
  | "fixture_correlation_mismatch"
  | "fixture_assurance_insufficient"
  | "fixture_provider_unsupported";

export type FixtureAuthenticationVerificationReason =
  | "developer-fixture-evidence-valid"
  | "fixture-verification-succeeded"
  | "request-shape-invalid"
  | "evidence-shape-invalid"
  | "provider-not-developer-fixture"
  | "session-correlation-mismatch"
  | "transition-correlation-mismatch"
  | "owner-commitment-mismatch"
  | "provider-correlation-mismatch"
  | "challenge-reference-mismatch"
  | "audit-correlation-mismatch"
  | "evidence-expired"
  | "evidence-stale"
  | "assurance-insufficient"
  | "fixture-evidence-replayed"
  | "fixture-only-boundary"
  | (string & {});

export interface FixtureAuthenticationVerificationLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface FixtureEvidenceConsumptionRecord {
  readonly evidenceId: string;
  readonly consumedAt: string;
  readonly auditCorrelationId?: string;
}

export type FixtureEvidenceConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface FixtureEvidenceConsumptionResult {
  readonly status: FixtureEvidenceConsumptionStatus;
  readonly record?: FixtureEvidenceConsumptionRecord;
  readonly records: readonly FixtureEvidenceConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralFixtureEvidenceConsumptionStore {
  consume(evidenceId: string, auditCorrelationId?: string): FixtureEvidenceConsumptionResult;
  has(evidenceId: string): boolean;
  get(evidenceId: string): FixtureEvidenceConsumptionRecord | undefined;
  getAll(): readonly FixtureEvidenceConsumptionRecord[];
  clear(): FixtureEvidenceConsumptionResult;
}

export interface VerifiedFixtureAuthenticationEvidenceReference {
  readonly referenceId: string;
  readonly verificationArtifactId: string;
  readonly evidenceId: string;
  readonly requestId: string;
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: UserSessionTransitionRequest["event"];
  readonly ownerCommitment?: string;
  readonly providerId: string;
  readonly challengeReferenceId: string;
  readonly auditCorrelationId: string;
  readonly assurance: readonly AuthenticationProviderAssurance[];
  readonly verifiedAt: string;
  readonly fixtureOnly: true;
  readonly verified: true;
  readonly productionAuthenticationPerformed: false;
  readonly vaultUnlocked: false;
  readonly biometricVerificationPerformed: false;
  readonly platformWebAuthnPerformed: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export interface FixtureAuthenticationVerificationRequest {
  readonly requestId: string;
  readonly authenticationRequest: ProductionAuthenticationRequest;
  readonly evidence: ProductionAuthenticationEvidence;
  readonly expectedSessionId: string;
  readonly expectedLifecycleTransitionRequestId?: string;
  readonly expectedOwnerCommitment?: string;
  readonly expectedChallengeReferenceId: string;
  readonly expectedProviderId: string;
  readonly expectedAuditCorrelationId?: string;
  readonly expectedAssurance?: readonly AuthenticationProviderAssurance[];
  readonly verifiedAt?: string;
  readonly auditCorrelationId?: string;
  readonly replayStore?: EphemeralFixtureEvidenceConsumptionStore;
}

export interface FixtureAuthenticationVerificationArtifact {
  readonly artifactId: string;
  readonly requestId: string;
  readonly authenticationRequestId: string;
  readonly evidenceId: string;
  readonly status: FixtureAuthenticationVerificationStatus;
  readonly outcome: FixtureAuthenticationVerificationOutcome;
  readonly reasons: readonly FixtureAuthenticationVerificationReason[];
  readonly verifiedFixtureEvidenceReference?: VerifiedFixtureAuthenticationEvidenceReference;
  readonly limitations: readonly FixtureAuthenticationVerificationLimitation[];
  readonly auditEventDraft: AuditEventDraft;
  readonly verifiedAt: string;
  readonly auditCorrelationId: string;
  readonly errors: readonly string[];
  readonly fixtureOnly: true;
  readonly productionAuthenticationPerformed: false;
  readonly vaultUnlocked: false;
  readonly biometricVerificationPerformed: false;
  readonly platformWebAuthnPerformed: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type FixtureAuthenticationVerificationResult =
  RuntimeResult<FixtureAuthenticationVerificationArtifact>;

export interface FixtureAuthenticatedLifecycleTransitionRequest {
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly transitionRequest: UserSessionTransitionRequest;
  readonly verifiedFixtureEvidenceReference: VerifiedFixtureAuthenticationEvidenceReference;
  readonly replayStore?: EphemeralFixtureEvidenceConsumptionStore;
  readonly auditCorrelationId?: string;
}

export interface FixtureAuthenticatedLifecycleTransitionResultValue {
  readonly transitionResult: UserSessionTransitionResult;
  readonly verifiedFixtureEvidenceReference: VerifiedFixtureAuthenticationEvidenceReference;
  readonly auditEventDraft: AuditEventDraft;
  readonly consumed?: FixtureEvidenceConsumptionResult;
  readonly fixtureOnly: true;
  readonly productionAuthenticationPerformed: false;
  readonly vaultUnlocked: false;
  readonly activeCapabilityCreated: false;
  readonly authorizationCreated: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type FixtureAuthenticatedLifecycleTransitionResult =
  RuntimeResult<FixtureAuthenticatedLifecycleTransitionResultValue>;

const DEFAULT_FIXTURE_LIMITATIONS: readonly FixtureAuthenticationVerificationLimitation[] =
  Object.freeze([
    Object.freeze({
      limitationId: "fixture_only",
      description: "Verification is restricted to explicit developer/test fixtures."
    }),
    Object.freeze({
      limitationId: "no_production_authentication",
      description: "No production authentication was performed."
    }),
    Object.freeze({
      limitationId: "vault_remains_locked",
      description: "Device Vault remains locked; lifecycle state does not imply vault unlock."
    }),
    Object.freeze({
      limitationId: "no_authority",
      description: "No active capability, session key, or authorization was created."
    }),
    Object.freeze({
      limitationId: "no_persistence",
      description: "Fixture verification and replay tracking are process-local only."
    })
  ]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
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

function fixtureError(
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

function artifactStatusForOutcome(
  outcome: FixtureAuthenticationVerificationOutcome
): FixtureAuthenticationVerificationStatus {
  if (outcome === "fixture_evidence_verified") return "fixture_verified";
  if (outcome === "fixture_evidence_expired") return "fixture_expired";
  if (outcome === "fixture_evidence_replayed") return "fixture_replayed";
  if (outcome === "fixture_provider_unsupported") return "fixture_provider_unsupported";
  if (outcome === "fixture_evidence_malformed") return "fixture_malformed";
  return "fixture_rejected";
}

function auditOutcomeForFixture(
  outcome: FixtureAuthenticationVerificationOutcome
): AuditEventDraft["outcome"] {
  return outcome === "fixture_evidence_verified"
    ? "validation_succeeded"
    : "validation_failed";
}

function verificationArtifact(input: {
  readonly request: FixtureAuthenticationVerificationRequest;
  readonly outcome: FixtureAuthenticationVerificationOutcome;
  readonly reasons: readonly FixtureAuthenticationVerificationReason[];
  readonly errors?: readonly string[];
  readonly verifiedReference?: VerifiedFixtureAuthenticationEvidenceReference;
}): FixtureAuthenticationVerificationArtifact {
  const verifiedAt = input.request.verifiedAt ?? new Date().toISOString();
  const auditCorrelationId = input.request.auditCorrelationId
    ?? input.request.expectedAuditCorrelationId
    ?? input.request.authenticationRequest.auditCorrelationId
    ?? createAuditCorrelationId([
      input.request.expectedSessionId,
      input.request.requestId,
      "fixture-authentication-verification"
    ]);
  const status = artifactStatusForOutcome(input.outcome);
  const auditEventDraft = createAuditEventDraft({
    category: "runtime",
    outcome: auditOutcomeForFixture(input.outcome),
    requestKind: "generic",
    sessionId: input.request.expectedSessionId,
    applicationId: input.request.authenticationRequest.correlation.applicationId,
    summary: input.outcome === "fixture_evidence_verified"
      ? "Fixture authentication evidence verified for controlled lifecycle testing."
      : "Fixture authentication evidence verification failed.",
    auditCorrelationId,
    redactedDetails: {
      fixtureOnly: true,
      productionAuthenticationPerformed: false,
      vaultUnlocked: false,
      evidenceId: input.request.evidence.evidenceId,
      authenticationRequestId: input.request.authenticationRequest.requestId,
      verificationOutcome: input.outcome,
      verificationStatus: status,
      reasons: input.reasons,
      errors: input.errors ?? []
    }
  });

  return freezeRecord({
    artifactId: `${auditCorrelationId}:fixture-authentication-verification`,
    requestId: input.request.requestId,
    authenticationRequestId: input.request.authenticationRequest.requestId,
    evidenceId: input.request.evidence.evidenceId,
    status,
    outcome: input.outcome,
    reasons: input.reasons,
    verifiedFixtureEvidenceReference: input.verifiedReference,
    limitations: DEFAULT_FIXTURE_LIMITATIONS,
    auditEventDraft,
    verifiedAt,
    auditCorrelationId,
    errors: input.errors ?? [],
    fixtureOnly: true,
    productionAuthenticationPerformed: false,
    vaultUnlocked: false,
    biometricVerificationPerformed: false,
    platformWebAuthnPerformed: false,
    grantsAuthority: false,
    persisted: false
  });
}

function consumeFixtureEvidence(
  store: EphemeralFixtureEvidenceConsumptionStore | undefined,
  evidenceId: string,
  auditCorrelationId?: string
): FixtureEvidenceConsumptionResult | undefined {
  return store?.consume(evidenceId, auditCorrelationId);
}

export function createEphemeralFixtureEvidenceConsumptionStore():
  EphemeralFixtureEvidenceConsumptionStore {
  const records = new Map<string, FixtureEvidenceConsumptionRecord>();

  function all(): readonly FixtureEvidenceConsumptionRecord[] {
    return Object.freeze(Array.from(records.values()));
  }

  return {
    consume(evidenceId, auditCorrelationId) {
      if (records.has(evidenceId)) {
        return freezeRecord({
          status: "replayed",
          record: records.get(evidenceId),
          records: all(),
          reason: "Fixture evidence was already consumed in this process-local store."
        });
      }
      const record: FixtureEvidenceConsumptionRecord = freezeRecord({
        evidenceId,
        consumedAt: new Date().toISOString(),
        auditCorrelationId
      });
      records.set(evidenceId, record);
      return freezeRecord({
        status: "consumed",
        record,
        records: all()
      });
    },
    has(evidenceId) {
      return records.has(evidenceId);
    },
    get(evidenceId) {
      return records.get(evidenceId);
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

export function validateFixtureAuthenticationVerificationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["fixture authentication verification request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  const authRequestValidation = validateProductionAuthenticationRequest(
    request.authenticationRequest
  );
  if (!authRequestValidation.valid) {
    errors.push(...authRequestValidation.errors.map((error) => `authenticationRequest.${error}`));
  }
  const evidenceValidation = validateProductionAuthenticationEvidenceShape(request.evidence);
  if (!evidenceValidation.valid) {
    errors.push(...evidenceValidation.errors.map((error) => `evidence.${error}`));
  }
  if (!isNonEmptyString(request.expectedSessionId)) {
    errors.push("expectedSessionId is required");
  }
  if (
    request.expectedLifecycleTransitionRequestId !== undefined
    && !isNonEmptyString(request.expectedLifecycleTransitionRequestId)
  ) {
    errors.push("expectedLifecycleTransitionRequestId must be non-empty when provided");
  }
  if (!isNonEmptyString(request.expectedChallengeReferenceId)) {
    errors.push("expectedChallengeReferenceId is required");
  }
  if (!isNonEmptyString(request.expectedProviderId)) {
    errors.push("expectedProviderId is required");
  }
  if (
    request.expectedAuditCorrelationId !== undefined
    && !isNonEmptyString(request.expectedAuditCorrelationId)
  ) {
    errors.push("expectedAuditCorrelationId must be non-empty when provided");
  }
  if (
    request.expectedAssurance !== undefined
    && (!Array.isArray(request.expectedAssurance) || request.expectedAssurance.length === 0)
  ) {
    errors.push("expectedAssurance must be a non-empty array when provided");
  }
  return validation(errors);
}

export function verifyDeveloperFixtureAuthenticationEvidence(
  request: FixtureAuthenticationVerificationRequest
): FixtureAuthenticationVerificationResult {
  const requestValidation = validateFixtureAuthenticationVerificationRequest(request);
  const errors: string[] = [...requestValidation.errors];
  const reasons: FixtureAuthenticationVerificationReason[] = ["fixture-only-boundary"];

  if (!requestValidation.valid) {
    reasons.push("request-shape-invalid");
    const artifact = verificationArtifact({
      request,
      outcome: "fixture_evidence_malformed",
      reasons,
      errors
    });
    return runtimeDenied(fixtureError(
      "FIXTURE_AUTHENTICATION_VERIFICATION_INVALID",
      "fixture authentication verification request failed validation",
      errors
    ), { auditEventId: artifact.auditEventDraft.eventDraftId });
  }

  const { authenticationRequest, evidence } = request;
  if (
    authenticationRequest.providerKind !== "developer_fixture"
    || evidence.source.providerKind !== "developer_fixture"
    || evidence.source.fixtureOnly !== true
  ) {
    errors.push("only developer_fixture evidence may use the fixture verification bridge");
    reasons.push("provider-not-developer-fixture");
  }

  const correlation = validateAuthenticationEvidenceCorrelation(authenticationRequest, evidence);
  if (!correlation.valid) {
    errors.push(...correlation.errors);
    if (correlation.errors.some((error) => error.includes("sessionId"))) {
      reasons.push("session-correlation-mismatch");
    }
    if (correlation.errors.some((error) => error.includes("lifecycleTransitionRequestId"))) {
      reasons.push("transition-correlation-mismatch");
    }
    if (correlation.errors.some((error) => error.includes("ownerCommitment"))) {
      reasons.push("owner-commitment-mismatch");
    }
    if (correlation.errors.some((error) => error.includes("providerId"))) {
      reasons.push("provider-correlation-mismatch");
    }
    if (correlation.errors.some((error) => error.includes("challengeReferenceId"))) {
      reasons.push("challenge-reference-mismatch");
    }
  }

  if (evidence.binding.sessionId !== request.expectedSessionId) {
    errors.push("expected session ID does not match evidence binding");
    reasons.push("session-correlation-mismatch");
  }
  if (
    request.expectedLifecycleTransitionRequestId !== undefined
    && evidence.binding.lifecycleTransitionRequestId !== request.expectedLifecycleTransitionRequestId
  ) {
    errors.push("expected lifecycle transition request ID does not match evidence binding");
    reasons.push("transition-correlation-mismatch");
  }
  if (
    request.expectedOwnerCommitment !== undefined
    && evidence.binding.ownerCommitment !== request.expectedOwnerCommitment
  ) {
    errors.push("expected owner commitment does not match evidence binding");
    reasons.push("owner-commitment-mismatch");
  }
  if (evidence.binding.challengeReferenceId !== request.expectedChallengeReferenceId) {
    errors.push("expected challenge reference does not match evidence binding");
    reasons.push("challenge-reference-mismatch");
  }
  if (evidence.binding.providerId !== request.expectedProviderId) {
    errors.push("expected provider ID does not match evidence binding");
    reasons.push("provider-correlation-mismatch");
  }
  if (
    request.expectedAuditCorrelationId !== undefined
    && evidence.auditCorrelationId !== request.expectedAuditCorrelationId
  ) {
    errors.push("expected audit correlation ID does not match evidence");
    reasons.push("audit-correlation-mismatch");
  }

  const freshness = validateAuthenticationEvidenceFreshness(evidence);
  if (!freshness.valid) {
    errors.push(...freshness.errors);
    if (freshness.errors.some((error) => error.includes("expired"))) {
      reasons.push("evidence-expired");
    }
    if (freshness.errors.some((error) => error.includes("stale"))) {
      reasons.push("evidence-stale");
    }
  }

  const assurance = validateAuthenticationEvidenceAssurance(
    evidence,
    request.expectedAssurance ?? authenticationRequest.requirement.requestedAssurance ?? []
  );
  if (!assurance.valid) {
    errors.push(...assurance.errors);
    reasons.push("assurance-insufficient");
  }

  const consumed = consumeFixtureEvidence(
    request.replayStore,
    evidence.evidenceId,
    request.auditCorrelationId ?? evidence.auditCorrelationId
  );
  if (consumed?.status === "replayed") {
    errors.push("fixture evidence was already consumed");
    reasons.push("fixture-evidence-replayed");
  }

  if (errors.length > 0) {
    let outcome: FixtureAuthenticationVerificationOutcome = "fixture_evidence_rejected";
    if (reasons.includes("provider-not-developer-fixture")) outcome = "fixture_provider_unsupported";
    else if (reasons.includes("fixture-evidence-replayed")) outcome = "fixture_evidence_replayed";
    else if (reasons.includes("evidence-expired")) outcome = "fixture_evidence_expired";
    else if (reasons.includes("evidence-stale")) outcome = "fixture_evidence_replayed";
    else if (reasons.includes("challenge-reference-mismatch")) outcome = "fixture_challenge_mismatch";
    else if (reasons.includes("session-correlation-mismatch")
      || reasons.includes("transition-correlation-mismatch")
      || reasons.includes("owner-commitment-mismatch")
      || reasons.includes("provider-correlation-mismatch")
      || reasons.includes("audit-correlation-mismatch")) outcome = "fixture_correlation_mismatch";
    else if (reasons.includes("assurance-insufficient")) outcome = "fixture_assurance_insufficient";

    const artifact = verificationArtifact({
      request,
      outcome,
      reasons,
      errors
    });
    return runtimeDenied(fixtureError(
      "FIXTURE_AUTHENTICATION_VERIFICATION_REJECTED",
      "fixture authentication evidence was rejected",
      errors
    ), { auditEventId: artifact.auditEventDraft.eventDraftId });
  }

  reasons.push("developer-fixture-evidence-valid", "fixture-verification-succeeded");
  const verifiedAt = request.verifiedAt ?? new Date().toISOString();
  const auditCorrelationId = request.auditCorrelationId
    ?? request.expectedAuditCorrelationId
    ?? evidence.auditCorrelationId;
  const verifiedReference: VerifiedFixtureAuthenticationEvidenceReference = freezeRecord({
    referenceId: `${evidence.evidenceId}:verified-fixture-reference`,
    verificationArtifactId: `${auditCorrelationId}:fixture-authentication-verification`,
    evidenceId: evidence.evidenceId,
    requestId: authenticationRequest.requestId,
    sessionId: evidence.binding.sessionId,
    lifecycleTransitionRequestId: evidence.binding.lifecycleTransitionRequestId,
    lifecycleEvent: evidence.binding.lifecycleEvent,
    ownerCommitment: evidence.binding.ownerCommitment,
    providerId: evidence.binding.providerId,
    challengeReferenceId: evidence.binding.challengeReferenceId,
    auditCorrelationId,
    assurance: evidence.assurance.provided,
    verifiedAt,
    fixtureOnly: true,
    verified: true,
    productionAuthenticationPerformed: false,
    vaultUnlocked: false,
    biometricVerificationPerformed: false,
    platformWebAuthnPerformed: false,
    grantsAuthority: false,
    persisted: false
  });
  const artifact = verificationArtifact({
    request: {
      ...request,
      verifiedAt,
      auditCorrelationId
    },
    outcome: "fixture_evidence_verified",
    reasons,
    verifiedReference
  });
  return runtimeOk(artifact, {
    auditEventId: artifact.auditEventDraft.eventDraftId
  });
}

function fixtureLifecycleTransitionAllowed(
  state: UserSessionLifecycleState,
  event: UserSessionTransitionRequest["event"]
): boolean {
  return (state === "unlocking" && event === "unlock_succeeded")
    || (state === "resuming" && event === "resume_succeeded");
}

export function transitionUserSessionWithVerifiedFixtureEvidence(
  request: FixtureAuthenticatedLifecycleTransitionRequest
): FixtureAuthenticatedLifecycleTransitionResult {
  const errors: string[] = [];
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!snapshotValidation.valid) {
    errors.push(...snapshotValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  const transitionValidation = validateUserSessionTransitionRequestShape(request.transitionRequest);
  if (!transitionValidation.valid) {
    errors.push(...transitionValidation.errors.map((error) => `transitionRequest.${error}`));
  }
  const reference = request.verifiedFixtureEvidenceReference;
  if (reference.fixtureOnly !== true || reference.verified !== true) {
    errors.push("verified fixture evidence reference is required");
  }
  if (reference.productionAuthenticationPerformed !== false) {
    errors.push("fixture reference must not claim production authentication");
  }
  if (reference.vaultUnlocked !== false) {
    errors.push("fixture reference must not claim vault unlock");
  }
  if (reference.sessionId !== request.lifecycleSnapshot.sessionId) {
    errors.push("fixture evidence session does not match lifecycle snapshot");
  }
  if (
    reference.lifecycleTransitionRequestId !== undefined
    && request.transitionRequest.transitionRequestId !== reference.lifecycleTransitionRequestId
  ) {
    errors.push("fixture evidence transition request does not match lifecycle transition request");
  }
  if (reference.lifecycleEvent !== undefined && request.transitionRequest.event !== reference.lifecycleEvent) {
    errors.push("fixture evidence lifecycle event does not match transition event");
  }
  if (!fixtureLifecycleTransitionAllowed(request.lifecycleSnapshot.state, request.transitionRequest.event)) {
    errors.push("fixture evidence may only support unlock_succeeded or resume_succeeded transitions");
  }
  if (request.replayStore?.has(reference.evidenceId)) {
    errors.push("fixture evidence was already consumed");
  }
  if (errors.length > 0) {
    const auditCorrelationId = request.auditCorrelationId
      ?? reference.auditCorrelationId
      ?? createAuditCorrelationId([
        request.lifecycleSnapshot.sessionId,
        request.transitionRequest.transitionRequestId ?? "",
        "fixture-lifecycle-transition"
      ]);
    const auditEventDraft = createAuditEventDraft({
      category: "runtime",
      outcome: "validation_failed",
      requestKind: "generic",
      sessionId: request.lifecycleSnapshot.sessionId,
      summary: "Fixture-authenticated lifecycle transition was rejected.",
      auditCorrelationId,
      redactedDetails: {
        fixtureOnly: true,
        productionAuthenticationPerformed: false,
        vaultUnlocked: false,
        previousState: request.lifecycleSnapshot.state,
        requestedEvent: request.transitionRequest.event,
        errors
      }
    });
    return runtimeDenied(fixtureError(
      "FIXTURE_AUTHENTICATED_LIFECYCLE_TRANSITION_REJECTED",
      "fixture-authenticated lifecycle transition was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = request.replayStore?.consume(reference.evidenceId, reference.auditCorrelationId);
  if (consumed?.status === "replayed") {
    return runtimeDenied(fixtureError(
      "FIXTURE_AUTHENTICATED_LIFECYCLE_TRANSITION_REPLAYED",
      "fixture evidence was already consumed",
      ["fixture evidence was already consumed"]
    ));
  }

  const transitionResult = transitionUserSessionLifecycle(request.lifecycleSnapshot, {
    ...request.transitionRequest,
    auditCorrelationId: request.auditCorrelationId ?? reference.auditCorrelationId,
    evidenceReferences: [{
      referenceId: reference.referenceId,
      kind: request.transitionRequest.event === "resume_succeeded"
        ? "user_presence_evidence"
        : "unlock_evidence",
      source: "developer_fixture",
      capturedAt: reference.verifiedAt,
      metadata: {
        verifiedFixtureEvidenceReferenceId: reference.referenceId,
        fixtureEvidenceVerified: true,
        productionAuthenticationPerformed: false,
        vaultUnlocked: false,
        grantsAuthority: false
      },
      verified: false,
      rawEvidenceIncluded: false
    }],
    metadata: {
      ...(request.transitionRequest.metadata ?? {}),
      fixtureOnly: true,
      productionAuthenticationPerformed: false,
      vaultUnlocked: false,
      activeCapabilityCreated: false,
      authorizationCreated: false
    }
  });

  if (transitionResult.status !== "transitioned" || !transitionResult.snapshot) {
    return runtimeDenied(fixtureError(
      "FIXTURE_AUTHENTICATED_LIFECYCLE_TRANSITION_FAILED",
      "fixture-authenticated lifecycle transition failed",
      transitionResult.errors ?? ["lifecycle transition failed"]
    ), { auditEventId: transitionResult.auditEventDraft?.eventDraftId });
  }

  const nextSnapshot = freezeRecord({
    ...transitionResult.snapshot,
    metadata: {
      ...(transitionResult.snapshot.metadata ?? {}),
      requestMetadata: {
        ...(transitionResult.snapshot.metadata?.requestMetadata ?? {}),
        fixtureOnlyLifecycleTransition: true,
        productionAuthenticationPerformed: false,
        vaultUnlocked: false,
        activeCapabilityCreated: false,
        authorizationCreated: false,
        grantsAuthority: false
      }
    },
    limitations: [
      ...transitionResult.snapshot.limitations,
      {
        limitationId: "fixture_lifecycle_state_changed",
        description: "Lifecycle state changed through a controlled fixture-only test path."
      },
      {
        limitationId: "vault_remains_locked",
        description: "Unlocked lifecycle state does not imply Device Vault unlock."
      },
      {
        limitationId: "no_production_authentication",
        description: "No production authentication occurred."
      },
      {
        limitationId: "no_authority",
        description: "No active capabilities or authorization packages were created."
      }
    ]
  });
  const patchedTransitionResult: UserSessionTransitionResult = freezeRecord({
    ...transitionResult,
    snapshot: nextSnapshot,
    limitations: nextSnapshot.limitations
  });
  const auditEventDraft = createAuditEventDraft({
    category: "runtime",
    outcome: "validation_succeeded",
    requestKind: "generic",
    sessionId: nextSnapshot.sessionId,
    summary: "Fixture-authenticated lifecycle transition completed for controlled testing.",
    auditCorrelationId: request.auditCorrelationId ?? reference.auditCorrelationId,
    redactedDetails: {
      fixtureOnly: true,
      productionAuthenticationPerformed: false,
      vaultUnlocked: false,
      activeCapabilityCreated: false,
      authorizationCreated: false,
      previousState: request.lifecycleSnapshot.state,
      requestedEvent: request.transitionRequest.event,
      nextState: nextSnapshot.state,
      evidenceReferenceId: reference.referenceId
    }
  });

  return runtimeOk({
    transitionResult: patchedTransitionResult,
    verifiedFixtureEvidenceReference: reference,
    auditEventDraft,
    consumed,
    fixtureOnly: true,
    productionAuthenticationPerformed: false,
    vaultUnlocked: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    grantsAuthority: false,
    persisted: false
  }, {
    auditEventId: auditEventDraft.eventDraftId
  });
}
