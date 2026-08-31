import {
  createWebAuthnAssertionVerifier,
  type PhilWebAuthnAssertion,
  type PhilWebAuthnVerificationResult
} from "../deviceIdentityWebAuthn.ts";
import type { Hex } from "../hashes.ts";
import { createAuditEventDraft, type AuditDraftCollectionResult, type AuditDraftCollector, type AuditEventDraft } from "./audit.ts";
import { createAuditCorrelationId, runtimeDenied, runtimeOk, type RuntimeValidationResult } from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  TrustManagerVerificationInput
} from "./trustManagerVerificationInput.ts";
import { validateTrustManagerVerificationInputShape } from "./trustManagerVerificationInput.ts";
import type { RuntimeErrorDescriptor, RuntimeResult } from "./types.ts";

export type TrustManagerProductionVerificationStatus =
  | "verification_succeeded"
  | "verification_rejected"
  | "verification_malformed"
  | "verification_expired"
  | "verification_replayed"
  | "verification_unsupported";

export type TrustManagerProductionVerificationOutcome =
  | "assertion_verified"
  | "assertion_rejected"
  | "assertion_malformed"
  | "signature_invalid"
  | "challenge_mismatch"
  | "origin_mismatch"
  | "rp_id_hash_mismatch"
  | "credential_mismatch"
  | "provider_mismatch"
  | "user_presence_missing"
  | "user_verification_missing"
  | "counter_invalid"
  | "counter_rollback_detected"
  | "evidence_expired"
  | "evidence_replayed"
  | "correlation_mismatch"
  | "assurance_insufficient"
  | "unsupported";

export type TrustManagerProductionVerificationReason =
  | "bounded-trust-manager-input-used"
  | "explicit-webauthn-assertion-used"
  | "existing-webauthn-verifier-used"
  | "assertion-verified"
  | "assertion-rejected"
  | "replay-rejected"
  | "counter-persisted-false"
  | "no-trust-decision"
  | "no-authority"
  | "no-vault-access"
  | (string & {});

export interface TrustManagerProductionVerificationCorrelation {
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerId: string;
  readonly providerKind: "webauthn_passkey";
  readonly challengeReferenceId: string;
  readonly authenticationPurpose: string;
  readonly auditCorrelationId: string;
}

export type TrustManagerProductionVerificationCounterStatus =
  | "advanced"
  | "unsupported"
  | "unchanged-zero"
  | "rollback"
  | "clone-suspected";

export interface TrustManagerProductionVerificationCounterAssessment {
  readonly previousCounter: number;
  readonly returnedCounter: number;
  readonly counterStatus: TrustManagerProductionVerificationCounterStatus;
  readonly counterAdvanced: boolean;
  readonly counterUnchanged: boolean;
  readonly rollbackDetected: boolean;
  readonly cloneSuspected: boolean;
  readonly counterPersisted: false;
  readonly futurePersistenceRequired: boolean;
}

export interface TrustManagerProductionVerificationEvidenceSummary {
  readonly verifierKind: string;
  readonly productionVerifierUsed: true;
  readonly assertionCryptographicallyVerified: boolean;
  readonly challengeBindingVerified: boolean;
  readonly originVerified: boolean;
  readonly rpIdHashVerified: boolean;
  readonly signatureVerified: boolean;
  readonly userPresenceVerified: boolean;
  readonly userVerificationVerified: boolean;
  readonly credentialId: string;
  readonly providerKind: "webauthn_passkey";
  readonly publicKeyAlgorithm: "ES256";
  readonly warnings: readonly string[];
  readonly errors: readonly string[];
}

export interface TrustManagerProductionVerificationLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface TrustManagerProductionVerificationRequirement {
  readonly requirementId: string;
  readonly satisfied: boolean;
  readonly description: string;
}

export interface TrustManagerProductionVerificationRequest {
  readonly requestId: string;
  readonly verificationInput: TrustManagerVerificationInput;
  readonly assertion: PhilWebAuthnAssertion;
  readonly expectedChallenge: string;
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly previousSignCounter: number;
  readonly expectedSessionId?: string;
  readonly expectedOwnerCommitment?: Hex;
  readonly expectedApplicationId?: string;
  readonly expectedAuthenticationPurpose?: string;
  readonly expectedProviderId?: string;
  readonly expectedAuditCorrelationId?: string;
  readonly collectedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface TrustManagerVerifiedEvidenceReference {
  readonly verifiedEvidenceReferenceId: string;
  readonly productionVerificationResultId: string;
  readonly trustManagerVerificationInputId: string;
  readonly credentialSafeReference: Hex;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly challengeReferenceId: string;
  readonly mayBecomeTrustDecisionEvidence: true;
  readonly isTrustDecision: false;
  readonly grantsAuthority: false;
}

export interface TrustManagerVerifiedEvidenceSummary {
  readonly assertionVerified: boolean;
  readonly credentialSafeReference: Hex;
  readonly counterStatus: TrustManagerProductionVerificationCounterStatus;
  readonly trustDecisionCreated: false;
  readonly grantsAuthority: false;
}

export interface TrustManagerTrustDecisionInput {
  readonly verifiedEvidenceReference: TrustManagerVerifiedEvidenceReference;
  readonly verifiedEvidenceSummary: TrustManagerVerifiedEvidenceSummary;
  readonly requiresSeparateTrustDecision: true;
  readonly grantsAuthority: false;
}

export interface TrustManagerProductionVerificationResultValue {
  readonly trustManagerProductionVerificationResultId: string;
  readonly requestId: string;
  readonly status: TrustManagerProductionVerificationStatus;
  readonly outcome: TrustManagerProductionVerificationOutcome;
  readonly correlation: TrustManagerProductionVerificationCorrelation;
  readonly evidenceSummary: TrustManagerProductionVerificationEvidenceSummary;
  readonly counterAssessment: TrustManagerProductionVerificationCounterAssessment;
  readonly verifiedEvidenceReference?: TrustManagerVerifiedEvidenceReference;
  readonly futureTrustDecisionInput?: TrustManagerTrustDecisionInput;
  readonly requirements: readonly TrustManagerProductionVerificationRequirement[];
  readonly limitations: readonly TrustManagerProductionVerificationLimitation[];
  readonly reasons: readonly TrustManagerProductionVerificationReason[];
  readonly verifiedAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly assertionCryptographicallyVerified: boolean;
  readonly challengeBindingVerified: boolean;
  readonly originVerified: boolean;
  readonly rpIdHashVerified: boolean;
  readonly signatureVerified: boolean;
  readonly productionVerifierUsed: true;
  readonly trustDecisionCreated: false;
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
  readonly deviceVaultAccessed: false;
  readonly credentialLoadedFromVault: false;
  readonly counterPersisted: false;
  readonly persisted: false;
  readonly browserCredentialPrompted: false;
  readonly biometricsInvoked: false;
  readonly worldIdVerified: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: TrustManagerProductionVerificationCollectionResult;
}

export type TrustManagerProductionVerificationResult =
  RuntimeResult<TrustManagerProductionVerificationResultValue>;

export interface TrustManagerVerificationConsumptionRecord {
  readonly consumptionId: string;
  readonly trustManagerVerificationInputId: string;
  readonly assertionCredentialId: string;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export type TrustManagerVerificationConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface TrustManagerVerificationConsumptionResult {
  readonly status: TrustManagerVerificationConsumptionStatus;
  readonly record?: TrustManagerVerificationConsumptionRecord;
  readonly records: readonly TrustManagerVerificationConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralTrustManagerVerificationConsumptionStore {
  consume(inputId: string, assertionCredentialId: string, auditCorrelationId: string): TrustManagerVerificationConsumptionResult;
  has(inputId: string, assertionCredentialId: string): boolean;
  clear(): TrustManagerVerificationConsumptionResult;
  getAll(): readonly TrustManagerVerificationConsumptionRecord[];
}

export type TrustManagerProductionVerificationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface TrustManagerProductionVerificationCollection {
  readonly results: readonly TrustManagerProductionVerificationResultValue[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface TrustManagerProductionVerificationCollectionResult {
  readonly status: TrustManagerProductionVerificationCollectionStatus;
  readonly result?: TrustManagerProductionVerificationResultValue;
  readonly removedResult?: TrustManagerProductionVerificationResultValue;
  readonly evictedResults?: readonly TrustManagerProductionVerificationResultValue[];
  readonly collection: TrustManagerProductionVerificationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface TrustManagerProductionVerificationResultCollector {
  addResult(result: TrustManagerProductionVerificationResultValue): TrustManagerProductionVerificationCollectionResult;
  removeResult(resultId: string): TrustManagerProductionVerificationCollectionResult;
  clear(): TrustManagerProductionVerificationCollectionResult;
  count(): number;
  getById(resultId: string): TrustManagerProductionVerificationResultValue | undefined;
  getAll(): readonly TrustManagerProductionVerificationResultValue[];
}

export interface InMemoryTrustManagerProductionVerificationCollectorOptions {
  readonly maxResultCount?: number;
}

const LIMITATIONS: readonly TrustManagerProductionVerificationLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "no-trust-decision",
    description: "Production assertion verification is evidence only and is not a Trust Decision."
  }),
  Object.freeze({
    limitationId: "no-vault-or-registry-access",
    description: "The bridge uses a bounded verification input and never accesses Device Vault or credential registry storage."
  }),
  Object.freeze({
    limitationId: "no-browser-ui",
    description: "The bridge consumes an explicit assertion and never invokes browser, platform, or biometric UI."
  }),
  Object.freeze({
    limitationId: "counter-not-persisted",
    description: "Counter findings are reported but never persisted or written back to credentials."
  }),
  Object.freeze({
    limitationId: "process-local-replay-only",
    description: "Replay protection is process-local and is not a durable production replay guarantee."
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

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
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

function verificationError(code: string, message: string, errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code,
    message,
    boundary: "trust-manager",
    recoverable: true,
    details: { errors }
  };
}

function resultFlags() {
  return {
    trustDecisionCreated: false as const,
    capabilityGranted: false as const,
    authorizationCreated: false as const,
    deviceVaultAccessed: false as const,
    credentialLoadedFromVault: false as const,
    counterPersisted: false as const,
    persisted: false as const,
    browserCredentialPrompted: false as const,
    biometricsInvoked: false as const,
    worldIdVerified: false as const,
    proofExecuted: false as const,
    adapterExecuted: false as const
  };
}

function requirements(satisfied: boolean): readonly TrustManagerProductionVerificationRequirement[] {
  return Object.freeze([
    "bounded verification input valid",
    "explicit assertion shape valid",
    "correlation checks passed",
    "existing WebAuthn verifier used",
    "no authority created"
  ].map((description, index) => Object.freeze({
    requirementId: `trust-manager-production-verification:${index + 1}`,
    satisfied,
    description
  })));
}

function outcomeFromVerification(
  verification: PhilWebAuthnVerificationResult,
  replayed: boolean
): TrustManagerProductionVerificationOutcome {
  if (replayed) return "evidence_replayed";
  if (verification.verified) return "assertion_verified";
  if (!verification.challengeMatched) return "challenge_mismatch";
  if (!verification.originMatched) return "origin_mismatch";
  if (!verification.rpIdHashMatched) return "rp_id_hash_mismatch";
  if (verification.credentialId === "") return "credential_mismatch";
  if (!verification.userPresent) return "user_presence_missing";
  if (!verification.userVerified) return "user_verification_missing";
  if (verification.counterStatus === "rollback") return "counter_rollback_detected";
  if (verification.counterStatus === "clone-suspected") return "counter_invalid";
  if (!verification.signatureVerified) return "signature_invalid";
  return "assertion_rejected";
}

function statusFromOutcome(
  outcome: TrustManagerProductionVerificationOutcome
): TrustManagerProductionVerificationStatus {
  if (outcome === "assertion_verified") return "verification_succeeded";
  if (outcome === "assertion_malformed") return "verification_malformed";
  if (outcome === "evidence_expired") return "verification_expired";
  if (outcome === "evidence_replayed") return "verification_replayed";
  if (outcome === "unsupported" || outcome === "provider_mismatch") return "verification_unsupported";
  return "verification_rejected";
}

function counterAssessment(
  previousCounter: number,
  verification: PhilWebAuthnVerificationResult
): TrustManagerProductionVerificationCounterAssessment {
  return freezeRecord({
    previousCounter,
    returnedCounter: verification.newSignCount,
    counterStatus: verification.counterStatus,
    counterAdvanced: verification.counterStatus === "advanced",
    counterUnchanged: verification.counterStatus === "unchanged-zero",
    rollbackDetected: verification.counterStatus === "rollback",
    cloneSuspected: verification.counterStatus === "clone-suspected",
    counterPersisted: false,
    futurePersistenceRequired: verification.verified && verification.counterStatus === "advanced"
  });
}

function evidenceSummary(
  input: TrustManagerVerificationInput,
  verification: PhilWebAuthnVerificationResult
): TrustManagerProductionVerificationEvidenceSummary {
  return freezeRecord({
    verifierKind: verification.verifierKind,
    productionVerifierUsed: true,
    assertionCryptographicallyVerified: verification.verified,
    challengeBindingVerified: verification.challengeMatched,
    originVerified: verification.originMatched,
    rpIdHashVerified: verification.rpIdHashMatched,
    signatureVerified: verification.signatureVerified,
    userPresenceVerified: verification.userPresent,
    userVerificationVerified: verification.userVerified,
    credentialId: verification.credentialId,
    providerKind: input.providerKind,
    publicKeyAlgorithm: input.publicKeyAlgorithm,
    warnings: Object.freeze([...verification.warnings]),
    errors: Object.freeze([...verification.errors])
  });
}

function correlation(input: TrustManagerVerificationInput): TrustManagerProductionVerificationCorrelation {
  return freezeRecord({
    sessionId: input.correlation.sessionId,
    applicationId: input.correlation.applicationId,
    ownerCommitment: input.correlation.ownerCommitment,
    credentialId: input.correlation.credentialId,
    credentialSafeReference: input.correlation.credentialSafeReference,
    providerId: input.correlation.providerId,
    providerKind: input.correlation.providerKind,
    challengeReferenceId: input.correlation.challengeReferenceId,
    authenticationPurpose: input.correlation.authenticationPurpose,
    auditCorrelationId: input.correlation.auditCorrelationId
  });
}

function validateAssertionShape(assertion: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(assertion)) return validation(["assertion must be an object"]);
  if (!isNonEmptyString(assertion.rawId)) errors.push("assertion.rawId is required");
  if (assertion.type !== "public-key") errors.push("assertion.type must be public-key");
  if (!isRecord(assertion.response)) {
    errors.push("assertion.response is required");
  } else {
    if (!isNonEmptyString(assertion.response.authenticatorData)) {
      errors.push("assertion.response.authenticatorData is required");
    }
    if (!isNonEmptyString(assertion.response.clientDataJSON)) {
      errors.push("assertion.response.clientDataJSON is required");
    }
    if (!isNonEmptyString(assertion.response.signature)) {
      errors.push("assertion.response.signature is required");
    }
  }
  return validation(errors);
}

export function validateTrustManagerProductionVerificationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["Trust Manager production verification request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.verificationInput)) {
    errors.push("verificationInput is required");
  } else {
    const inputValidation = validateTrustManagerVerificationInputShape({
      trustManagerVerificationInputResultId: `${request.verificationInput.trustManagerVerificationInputId ?? "unknown"}:validation`,
      requestId: request.verificationInput.requestId,
      status: "verification_input_created",
      outcome: "verification_input_created",
      verificationInput: request.verificationInput,
      verificationPerformed: false,
      trustDecisionCreated: false,
      authenticationPerformed: false,
      grantsAuthority: false,
      vaultHandleExposed: false,
      registryAccessProvided: false,
      privateMaterialIncluded: false,
      credentialRecordIncluded: false,
      rawAssertionPayloadIncluded: false,
      rawRegistrationPayloadIncluded: false,
      persisted: false
    });
    if (!inputValidation.valid) {
      errors.push(...inputValidation.errors.map((error) => `verificationInput.${error}`));
    }
  }
  errors.push(...validateAssertionShape(request.assertion).errors);
  if (!isNonEmptyString(request.expectedChallenge)) errors.push("expectedChallenge is required");
  if (!isNonEmptyString(request.expectedOrigin)) errors.push("expectedOrigin is required");
  if (!isNonEmptyString(request.expectedRpId)) errors.push("expectedRpId is required");
  if (typeof request.previousSignCounter !== "number" || request.previousSignCounter < 0) {
    errors.push("previousSignCounter must be non-negative");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (request.collectedAt !== undefined && !hasValidDateShape(request.collectedAt)) {
    errors.push("collectedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

function correlationErrors(request: TrustManagerProductionVerificationRequest): readonly string[] {
  const input = request.verificationInput;
  const errors: string[] = [];
  if (request.expectedSessionId !== undefined && request.expectedSessionId !== input.correlation.sessionId) {
    errors.push("session correlation mismatch");
  }
  if (request.expectedOwnerCommitment !== undefined && request.expectedOwnerCommitment !== input.correlation.ownerCommitment) {
    errors.push("owner correlation mismatch");
  }
  if (request.expectedApplicationId !== undefined && request.expectedApplicationId !== input.correlation.applicationId) {
    errors.push("application correlation mismatch");
  }
  if (request.expectedAuthenticationPurpose !== undefined && request.expectedAuthenticationPurpose !== input.correlation.authenticationPurpose) {
    errors.push("purpose correlation mismatch");
  }
  if (request.expectedProviderId !== undefined && request.expectedProviderId !== input.correlation.providerId) {
    errors.push("provider correlation mismatch");
  }
  if (request.expectedAuditCorrelationId !== undefined && request.expectedAuditCorrelationId !== request.auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (request.assertion.rawId !== input.correlation.credentialId) {
    errors.push("credential correlation mismatch");
  }
  if (request.expectedChallenge !== input.challengeBinding.challengeReferenceId) {
    errors.push("challenge correlation mismatch");
  }
  if (request.expectedOrigin !== input.origin) errors.push("origin correlation mismatch");
  if (request.expectedRpId !== input.rpId) errors.push("RP ID correlation mismatch");
  if (input.providerKind !== "webauthn_passkey") errors.push("provider mismatch");
  if (input.publicKeyAlgorithm !== "ES256") errors.push("unsupported algorithm");
  if (!input.assuranceRequirement.sufficient) errors.push("assurance insufficient");
  return errors;
}

function preflightOutcome(errors: readonly string[]): TrustManagerProductionVerificationOutcome {
  if (errors.some((error) => error.includes("expired"))) return "evidence_expired";
  if (errors.some((error) => error.includes("assertion"))) return "assertion_malformed";
  if (errors.some((error) => error.includes("provider"))) return "provider_mismatch";
  if (errors.some((error) => error.includes("challenge"))) return "challenge_mismatch";
  if (errors.some((error) => error.includes("origin"))) return "origin_mismatch";
  if (errors.some((error) => error.includes("RP ID"))) return "rp_id_hash_mismatch";
  if (errors.some((error) => error.includes("credential"))) return "credential_mismatch";
  if (errors.some((error) => error.includes("assurance"))) return "assurance_insufficient";
  if (errors.some((error) => error.includes("unsupported"))) return "unsupported";
  if (errors.length > 0) return "correlation_mismatch";
  return "assertion_verified";
}

export async function verifyTrustManagerProductionAssertion(
  request: TrustManagerProductionVerificationRequest,
  consumptionStore?: EphemeralTrustManagerVerificationConsumptionStore,
  collector?: TrustManagerProductionVerificationResultCollector,
  auditDraftCollector?: AuditDraftCollector
): Promise<TrustManagerProductionVerificationResult> {
  const requestValidation = validateTrustManagerProductionVerificationRequest(request);
  if (!requestValidation.valid) {
    const auditEventDraft = auditDraftForProductionVerification({
      request,
      outcome: "malformed",
      errors: requestValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(verificationError(
      "TRUST_MANAGER_PRODUCTION_VERIFICATION_INVALID",
      "Trust Manager production verification request failed validation",
      requestValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const preflightErrors = [
    ...correlationErrors(request),
    ...(expired(request.verificationInput.expiresAt) || expired(request.expiresAt)
      ? ["evidence expired"]
      : [])
  ];
  const replayResult = consumptionStore?.consume(
    request.verificationInput.trustManagerVerificationInputId,
    request.assertion.rawId,
    request.auditCorrelationId
  );
  if (replayResult?.status === "replayed") preflightErrors.push("evidence replayed");

  if (preflightErrors.length > 0) {
    const outcome = preflightErrors.includes("evidence replayed")
      ? "evidence_replayed"
      : preflightOutcome(preflightErrors);
    const auditEventDraft = auditDraftForProductionVerification({
      request,
      outcome: outcome === "unsupported" ? "unsupported" : "validation_failed",
      errors: preflightErrors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(verificationError(
      "TRUST_MANAGER_PRODUCTION_VERIFICATION_REJECTED",
      "Trust Manager production verification request was rejected",
      preflightErrors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const verifier = createWebAuthnAssertionVerifier();
  const verification = await verifier.verifyAssertion({
    assertion: request.assertion,
    credential: {
      credentialId: request.verificationInput.correlation.credentialId,
      credentialIdHash: request.verificationInput.credentialSafeReference,
      rawId: request.verificationInput.correlation.credentialId,
      publicKey: request.verificationInput.verificationKey.publicKey,
      publicKeyAlgorithm: -7,
      signCount: request.previousSignCounter
    },
    expectedChallenge: request.expectedChallenge,
    expectedOrigin: request.expectedOrigin,
    expectedRpId: request.expectedRpId,
    expectedUserVerification: "required",
    storedSignCount: request.previousSignCounter
  });
  const outcome = outcomeFromVerification(verification, false);
  const status = statusFromOutcome(outcome);
  const verifiedAt = request.collectedAt ?? new Date().toISOString();
  const correlationValue = correlation(request.verificationInput);
  const counter = counterAssessment(request.previousSignCounter, verification);
  const summary = evidenceSummary(request.verificationInput, verification);
  const resultId = createAuditCorrelationId([
    request.verificationInput.trustManagerVerificationInputId,
    request.assertion.rawId,
    request.auditCorrelationId,
    "trust-manager-production-verification"
  ]);
  const verifiedEvidenceReference = outcome === "assertion_verified"
    ? freezeRecord({
      verifiedEvidenceReferenceId: `${resultId}:verified-evidence`,
      productionVerificationResultId: resultId,
      trustManagerVerificationInputId: request.verificationInput.trustManagerVerificationInputId,
      credentialSafeReference: request.verificationInput.credentialSafeReference,
      sessionId: request.verificationInput.correlation.sessionId,
      applicationId: request.verificationInput.correlation.applicationId,
      challengeReferenceId: request.verificationInput.challengeBinding.challengeReferenceId,
      mayBecomeTrustDecisionEvidence: true as const,
      isTrustDecision: false as const,
      grantsAuthority: false as const
    })
    : undefined;
  const futureTrustDecisionInput = verifiedEvidenceReference
    ? freezeRecord({
      verifiedEvidenceReference,
      verifiedEvidenceSummary: {
        assertionVerified: true,
        credentialSafeReference: request.verificationInput.credentialSafeReference,
        counterStatus: counter.counterStatus,
        trustDecisionCreated: false as const,
        grantsAuthority: false as const
      },
      requiresSeparateTrustDecision: true as const,
      grantsAuthority: false as const
    })
    : undefined;
  const auditEventDraft = auditDraftForProductionVerification({
    request,
    outcome: outcome === "assertion_verified" ? "validation_succeeded" : "validation_failed",
    verificationOutcome: outcome,
    counterStatus: counter.counterStatus
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const value: TrustManagerProductionVerificationResultValue = freezeRecord({
    trustManagerProductionVerificationResultId: resultId,
    requestId: request.requestId,
    status,
    outcome,
    correlation: correlationValue,
    evidenceSummary: summary,
    counterAssessment: counter,
    verifiedEvidenceReference,
    futureTrustDecisionInput,
    requirements: requirements(outcome === "assertion_verified"),
    limitations: LIMITATIONS,
    reasons: Object.freeze([
      "bounded-trust-manager-input-used",
      "explicit-webauthn-assertion-used",
      "existing-webauthn-verifier-used",
      outcome === "assertion_verified" ? "assertion-verified" : "assertion-rejected",
      "counter-persisted-false",
      "no-trust-decision",
      "no-authority",
      "no-vault-access"
    ]),
    verifiedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId,
    assertionCryptographicallyVerified: verification.verified,
    challengeBindingVerified: verification.challengeMatched,
    originVerified: verification.originMatched,
    rpIdHashVerified: verification.rpIdHashMatched,
    signatureVerified: verification.signatureVerified,
    productionVerifierUsed: true,
    ...resultFlags(),
    auditEventDraft,
    auditDraftCollectionResult
  });
  const resultValidation = validateTrustManagerProductionVerificationResultShape(value);
  if (!resultValidation.valid) {
    return runtimeDenied(verificationError(
      "TRUST_MANAGER_PRODUCTION_VERIFICATION_RESULT_INVALID",
      "Trust Manager production verification result failed validation",
      resultValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const collectionResult = collector?.addResult(value);
  const valueWithCollection = freezeRecord({
    ...value,
    collectionResult
  });
  return outcome === "assertion_verified"
    ? runtimeOk(valueWithCollection)
    : runtimeDenied(verificationError(
      "TRUST_MANAGER_PRODUCTION_VERIFICATION_REJECTED",
      "Trust Manager production verification failed",
      verification.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
}

function auditDraftForProductionVerification(input: {
  readonly request: TrustManagerProductionVerificationRequest;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly errors?: readonly string[];
  readonly verificationOutcome?: TrustManagerProductionVerificationOutcome;
  readonly counterStatus?: TrustManagerProductionVerificationCounterStatus;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.verificationInput?.correlation.sessionId,
    applicationId: input.request.verificationInput?.correlation.applicationId,
    summary: input.outcome === "validation_succeeded"
      ? "Trust Manager production assertion verification succeeded as bounded evidence only; no Trust Decision or authority was created."
      : "Trust Manager production assertion verification failed or was rejected; no Trust Decision or authority was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      requestId: input.request.requestId,
      credentialSafeReference: input.request.verificationInput?.credentialSafeReference,
      providerKind: input.request.verificationInput?.providerKind,
      algorithm: input.request.verificationInput?.publicKeyAlgorithm,
      authenticationPurpose: input.request.verificationInput?.authenticationPurpose,
      challengeReferenceId: input.request.verificationInput?.challengeBinding.challengeReferenceId,
      outcome: input.verificationOutcome,
      counterStatus: input.counterStatus,
      publicKeyBytesIncluded: false,
      signatureBytesIncluded: false,
      authenticatorDataIncluded: false,
      clientDataJsonIncluded: false,
      vaultMaterialIncluded: false,
      privateMaterialIncluded: false,
      trustDecisionCreated: false,
      capabilityGranted: false,
      authorizationCreated: false,
      persisted: false,
      errors: input.errors ?? []
    }
  });
}

export function validateTrustManagerProductionVerificationResultShape(
  value: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) return validation(["Trust Manager production verification result must be an object"]);
  if (!isNonEmptyString(value.trustManagerProductionVerificationResultId)) {
    errors.push("trustManagerProductionVerificationResultId is required");
  }
  if (value.productionVerifierUsed !== true) errors.push("productionVerifierUsed must be true");
  for (const [key, expected] of Object.entries(resultFlags())) {
    if (value[key] !== expected) errors.push(`${key} must be ${String(expected)}`);
  }
  if (!isRecord(value.evidenceSummary)) errors.push("evidenceSummary is required");
  if (!isRecord(value.counterAssessment)) errors.push("counterAssessment is required");
  return validation(errors);
}

export function createEphemeralTrustManagerVerificationConsumptionStore():
  EphemeralTrustManagerVerificationConsumptionStore {
  const records = new Map<string, TrustManagerVerificationConsumptionRecord>();
  function key(inputId: string, assertionCredentialId: string): string {
    return `${inputId}:${assertionCredentialId}`;
  }
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(inputId, assertionCredentialId, auditCorrelationId) {
      const id = key(inputId, assertionCredentialId);
      if (records.has(id)) {
        return freezeRecord({
          status: "replayed",
          record: records.get(id),
          records: all(),
          reason: "Trust Manager production verification input/assertion combination was already consumed in this process."
        });
      }
      const record = freezeRecord({
        consumptionId: id,
        trustManagerVerificationInputId: inputId,
        assertionCredentialId,
        auditCorrelationId,
        consumedAt: new Date().toISOString()
      });
      records.set(id, record);
      return freezeRecord({ status: "consumed", record, records: all() });
    },
    has(inputId, assertionCredentialId) {
      return records.has(key(inputId, assertionCredentialId));
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared", records: all() });
    },
    getAll: all
  };
}

function collectionFrom(
  results: readonly TrustManagerProductionVerificationResultValue[],
  maxResultCount: number
): TrustManagerProductionVerificationCollection {
  return freezeRecord({ results, count: results.length, maxResultCount });
}

export function createInMemoryTrustManagerProductionVerificationResultCollector(
  options: InMemoryTrustManagerProductionVerificationCollectorOptions = {}
): TrustManagerProductionVerificationResultCollector {
  const maxResultCount = options.maxResultCount ?? 100;
  const results = new Map<string, TrustManagerProductionVerificationResultValue>();
  function all() {
    return Object.freeze(Array.from(results.values()).map(freezeRecord));
  }
  function collectionResult(
    status: TrustManagerProductionVerificationCollectionStatus,
    extras: Omit<TrustManagerProductionVerificationCollectionResult, "status" | "collection"> = {}
  ): TrustManagerProductionVerificationCollectionResult {
    return freezeRecord({
      status,
      ...extras,
      collection: collectionFrom(all(), maxResultCount)
    });
  }
  return {
    addResult(result) {
      const validationResult = validateTrustManagerProductionVerificationResultShape(result);
      if (!validationResult.valid) {
        return collectionResult("rejected_invalid", { errors: validationResult.errors });
      }
      if (results.has(result.trustManagerProductionVerificationResultId)) {
        return collectionResult("rejected_duplicate", { result });
      }
      const evictedResults: TrustManagerProductionVerificationResultValue[] = [];
      while (results.size >= maxResultCount) {
        const oldestKey = results.keys().next().value as string | undefined;
        if (!oldestKey) break;
        const evicted = results.get(oldestKey);
        results.delete(oldestKey);
        if (evicted) evictedResults.push(evicted);
      }
      results.set(result.trustManagerProductionVerificationResultId, freezeRecord(result));
      return collectionResult(evictedResults.length > 0 ? "evicted_oldest" : "collected", {
        result,
        evictedResults
      });
    },
    removeResult(resultId) {
      const removedResult = results.get(resultId);
      if (!removedResult) return collectionResult("not_found");
      results.delete(resultId);
      return collectionResult("removed", { removedResult });
    },
    clear() {
      results.clear();
      return collectionResult("cleared");
    },
    count() {
      return results.size;
    },
    getById(resultId) {
      const result = results.get(resultId);
      return result ? freezeRecord(result) : undefined;
    },
    getAll: all
  };
}
