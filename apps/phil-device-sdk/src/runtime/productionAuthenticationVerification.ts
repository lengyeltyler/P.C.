import {
  createWebAuthnAssertionVerifier,
  type PhilWebAuthnAssertion,
  type PhilWebAuthnCredentialMetadata,
  type PhilWebAuthnVerificationResult,
  type WebAuthnUserVerification
} from "../deviceIdentityWebAuthn.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  type AuthenticationProviderAssurance,
  type AuthenticationProviderId,
  type AuthenticationProviderKind,
  type ProductionAuthenticationEvidenceFreshness
} from "./authenticationEvidence.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type ProductionAuthenticationVerificationStatus =
  | "verification_succeeded"
  | "verification_rejected"
  | "verification_malformed"
  | "verification_expired"
  | "verification_replayed"
  | "verification_unsupported";

export type ProductionAuthenticationVerificationOutcome =
  | "webauthn_assertion_verified"
  | "invalid_signature"
  | "rp_mismatch"
  | "challenge_mismatch"
  | "origin_mismatch"
  | "stale_assertion"
  | "replay_detected"
  | "unsupported_provider"
  | "malformed_payload"
  | "user_presence_missing"
  | "user_verification_missing"
  | "counter_invalid"
  | "verification_failed";

export type ProductionAuthenticationVerificationReason =
  | "existing-webauthn-assertion-verifier-used"
  | "explicit-inputs-only"
  | "webauthn-verifier-succeeded"
  | "webauthn-verifier-rejected"
  | "request-shape-invalid"
  | "unsupported-provider-kind"
  | "session-correlation-valid"
  | "session-correlation-mismatch"
  | "challenge-mismatch"
  | "origin-mismatch"
  | "rp-id-mismatch"
  | "signature-invalid"
  | "counter-replay-detected"
  | "assertion-stale"
  | "assertion-expired"
  | "assurance-insufficient"
  | "lifecycle-eligibility-created"
  | "no-runtime-authentication"
  | (string & {});

export interface ProductionAuthenticationVerificationCorrelation {
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: "unlock_succeeded" | "resume_succeeded" | (string & {});
  readonly ownerCommitment?: Hex;
  readonly applicationId?: ApplicationId;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerId: AuthenticationProviderId;
  readonly challengeReferenceId?: string;
  readonly auditCorrelationId?: string;
}

export interface ProductionAuthenticationVerificationEvidenceSummary {
  readonly verifierKind: string;
  readonly productionVerified: boolean;
  readonly credentialId: string;
  readonly newSignCount: number;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly rpIdHashMatched: boolean;
  readonly challengeMatched: boolean;
  readonly originMatched: boolean;
  readonly signatureVerified: boolean;
  readonly counterStatus: PhilWebAuthnVerificationResult["counterStatus"];
  readonly warnings: readonly string[];
  readonly errors: readonly string[];
}

export interface ProductionAuthenticationVerificationLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface LifecycleTransitionEligibility {
  readonly eligibilityId: string;
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId: string;
  readonly providerId: AuthenticationProviderId;
  readonly auditCorrelationId: string;
  readonly statement: "This verification result would allow a future authenticated lifecycle transition.";
  readonly eligibleForFutureLifecycleTransition: true;
  readonly performsTransitionNow: false;
  readonly unlocksVault: false;
  readonly authenticatesRuntime: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export interface ProductionAuthenticationVerificationRequest {
  readonly requestId: string;
  readonly providerKind: AuthenticationProviderKind;
  readonly providerId: AuthenticationProviderId;
  readonly assertion: PhilWebAuthnAssertion;
  readonly credential: PhilWebAuthnCredentialMetadata;
  readonly expectedChallenge: string;
  readonly expectedRpId: string;
  readonly expectedOrigin: string;
  readonly expectedUserVerification: WebAuthnUserVerification;
  readonly storedSignCount: number;
  readonly correlation: ProductionAuthenticationVerificationCorrelation;
  readonly requestedAssurance?: readonly AuthenticationProviderAssurance[];
  readonly freshness?: ProductionAuthenticationEvidenceFreshness;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ProductionAuthenticationVerificationResultValue {
  readonly verificationId: string;
  readonly requestId: string;
  readonly providerKind: AuthenticationProviderKind;
  readonly providerId: AuthenticationProviderId;
  readonly status: ProductionAuthenticationVerificationStatus;
  readonly outcome: ProductionAuthenticationVerificationOutcome;
  readonly reasons: readonly ProductionAuthenticationVerificationReason[];
  readonly correlation: ProductionAuthenticationVerificationCorrelation;
  readonly evidenceSummary: ProductionAuthenticationVerificationEvidenceSummary;
  readonly lifecycleEligibility?: LifecycleTransitionEligibility;
  readonly limitations: readonly ProductionAuthenticationVerificationLimitation[];
  readonly verifiedAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly authenticatesRuntime: false;
  readonly productionAuthenticationPerformed: false;
  readonly browserCredentialPrompted: false;
  readonly vaultUnlocked: false;
  readonly counterPersisted: false;
  readonly grantsCapability: false;
  readonly createsAuthorizationPackage: false;
  readonly performsTrustDecision: false;
  readonly performsPolicyDecision: false;
  readonly executesAdapter: false;
  readonly persisted: false;
}

export type ProductionAuthenticationVerificationResult =
  RuntimeResult<ProductionAuthenticationVerificationResultValue>;

export type ProductionAuthenticationVerificationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface ProductionAuthenticationVerificationFilter {
  readonly verificationId?: string;
  readonly requestId?: string;
  readonly providerKind?: AuthenticationProviderKind;
  readonly providerId?: AuthenticationProviderId;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly outcome?: ProductionAuthenticationVerificationOutcome;
  readonly status?: ProductionAuthenticationVerificationStatus;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface ProductionAuthenticationVerificationQuery {
  readonly filter?: ProductionAuthenticationVerificationFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface ProductionAuthenticationVerificationCollection {
  readonly results: readonly ProductionAuthenticationVerificationResultValue[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface ProductionAuthenticationVerificationCollectionResult {
  readonly status: ProductionAuthenticationVerificationCollectionStatus;
  readonly result?: ProductionAuthenticationVerificationResultValue;
  readonly removedResult?: ProductionAuthenticationVerificationResultValue;
  readonly evictedResults?: readonly ProductionAuthenticationVerificationResultValue[];
  readonly collection: ProductionAuthenticationVerificationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface ProductionAuthenticationVerificationResultCollector {
  addResult(
    result: ProductionAuthenticationVerificationResultValue
  ): ProductionAuthenticationVerificationCollectionResult;
  removeResult(verificationId: string): ProductionAuthenticationVerificationCollectionResult;
  clear(): ProductionAuthenticationVerificationCollectionResult;
  count(): number;
  getById(verificationId: string): ProductionAuthenticationVerificationResultValue | undefined;
  getAll(): readonly ProductionAuthenticationVerificationResultValue[];
  query(
    query: ProductionAuthenticationVerificationQuery
  ): readonly ProductionAuthenticationVerificationResultValue[];
  filter(
    filter: ProductionAuthenticationVerificationFilter
  ): readonly ProductionAuthenticationVerificationResultValue[];
}

export interface InMemoryProductionAuthenticationVerificationCollectorOptions {
  readonly maxResultCount?: number;
}

export type ProductionAuthenticationVerificationGroupMap =
  Readonly<Record<string, readonly ProductionAuthenticationVerificationResultValue[]>>;

export interface ProductionAuthenticationVerificationReviewSummary {
  readonly totalResultCount: number;
  readonly resultsByProvider: Readonly<Record<string, number>>;
  readonly resultsByOutcome: Readonly<Record<string, number>>;
  readonly resultsBySession: Readonly<Record<string, number>>;
  readonly resultsByCredential: Readonly<Record<string, number>>;
  readonly successfulVerifications: readonly ProductionAuthenticationVerificationResultValue[];
  readonly expiredVerifications: readonly ProductionAuthenticationVerificationResultValue[];
  readonly replayFailures: readonly ProductionAuthenticationVerificationResultValue[];
  readonly earliestVerifiedAt?: string;
  readonly latestVerifiedAt?: string;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

const DEFAULT_LIMITATIONS: readonly ProductionAuthenticationVerificationLimitation[] =
  Object.freeze([
    Object.freeze({
      limitationId: "no_device_vault_access",
      description: "Verification does not access or unlock Device Vault."
    }),
    Object.freeze({
      limitationId: "no_browser_prompt",
      description: "Verification consumes an explicit assertion and does not call browser credential UI."
    }),
    Object.freeze({
      limitationId: "no_runtime_authentication",
      description: "Verification does not authenticate the PhilCore runtime or mutate User Session."
    }),
    Object.freeze({
      limitationId: "no_authority",
      description: "Verification creates no capabilities, authorization packages, policy decisions, or adapter execution."
    }),
    Object.freeze({
      limitationId: "no_persistence",
      description: "Verification does not persist counters, evidence, or session state."
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

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
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

function malformedError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "PRODUCTION_AUTHENTICATION_VERIFICATION_INVALID",
    message: "production authentication verification request failed validation",
    boundary: "user-session",
    recoverable: true,
    details: {
      errors
    }
  };
}

function secretValidationErrors(input: unknown): readonly string[] {
  return validateNoSensitiveMetadataKeys(input).errors.map(
    (error) => `secret-shaped metadata is not allowed: ${error}`
  );
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function stale(freshness: ProductionAuthenticationEvidenceFreshness | undefined): boolean {
  if (!freshness) return false;
  if (freshness.staleAfter !== undefined) {
    return Date.parse(freshness.staleAfter) <= Date.now();
  }
  if (
    freshness.collectedAt !== undefined
    && freshness.maxAgeMs !== undefined
    && Number.isFinite(freshness.maxAgeMs)
  ) {
    return Date.now() - Date.parse(freshness.collectedAt) > freshness.maxAgeMs;
  }
  return false;
}

function assuranceSufficient(
  provided: readonly AuthenticationProviderAssurance[],
  requested: readonly AuthenticationProviderAssurance[] = []
): boolean {
  return requested.every((entry) => provided.includes(entry));
}

function providedAssuranceFromVerification(
  verification: PhilWebAuthnVerificationResult
): readonly AuthenticationProviderAssurance[] {
  const assurance: AuthenticationProviderAssurance[] = [];
  if (verification.userPresent) assurance.push("user_presence");
  if (verification.userVerified) assurance.push("user_verification");
  if (verification.productionVerified) assurance.push("phishing_resistant");
  return Object.freeze(assurance);
}

function outcomeFromVerification(
  verification: PhilWebAuthnVerificationResult,
  input: ProductionAuthenticationVerificationRequest
): ProductionAuthenticationVerificationOutcome {
  if (input.providerKind !== "webauthn_passkey") return "unsupported_provider";
  if (expired(input.freshness?.expiresAt)) return "stale_assertion";
  if (stale(input.freshness)) return "stale_assertion";
  if (!verification.challengeMatched) return "challenge_mismatch";
  if (!verification.originMatched) return "origin_mismatch";
  if (!verification.rpIdHashMatched) return "rp_mismatch";
  if (!verification.userPresent) return "user_presence_missing";
  if (!verification.userVerified && input.expectedUserVerification === "required") {
    return "user_verification_missing";
  }
  if (
    verification.counterStatus === "rollback"
    || verification.counterStatus === "clone-suspected"
  ) return "replay_detected";
  if (!verification.signatureVerified) return "invalid_signature";
  if (!assuranceSufficient(providedAssuranceFromVerification(verification), input.requestedAssurance)) {
    return "verification_failed";
  }
  return verification.verified ? "webauthn_assertion_verified" : "verification_failed";
}

function statusFromOutcome(
  outcome: ProductionAuthenticationVerificationOutcome
): ProductionAuthenticationVerificationStatus {
  if (outcome === "webauthn_assertion_verified") return "verification_succeeded";
  if (outcome === "stale_assertion") return "verification_expired";
  if (outcome === "replay_detected") return "verification_replayed";
  if (outcome === "unsupported_provider") return "verification_unsupported";
  if (outcome === "malformed_payload") return "verification_malformed";
  return "verification_rejected";
}

function reasonsFromOutcome(
  outcome: ProductionAuthenticationVerificationOutcome
): readonly ProductionAuthenticationVerificationReason[] {
  const reasons: ProductionAuthenticationVerificationReason[] = [
    "existing-webauthn-assertion-verifier-used",
    "explicit-inputs-only",
    "no-runtime-authentication"
  ];
  if (outcome === "webauthn_assertion_verified") {
    reasons.push("webauthn-verifier-succeeded", "session-correlation-valid", "lifecycle-eligibility-created");
  } else {
    reasons.push("webauthn-verifier-rejected");
  }
  if (outcome === "unsupported_provider") reasons.push("unsupported-provider-kind");
  if (outcome === "challenge_mismatch") reasons.push("challenge-mismatch");
  if (outcome === "origin_mismatch") reasons.push("origin-mismatch");
  if (outcome === "rp_mismatch") reasons.push("rp-id-mismatch");
  if (outcome === "invalid_signature") reasons.push("signature-invalid");
  if (outcome === "replay_detected") reasons.push("counter-replay-detected");
  if (outcome === "stale_assertion") reasons.push("assertion-stale");
  if (outcome === "verification_failed") reasons.push("assurance-insufficient");
  return Object.freeze(reasons);
}

function verificationSummary(
  verification: PhilWebAuthnVerificationResult
): ProductionAuthenticationVerificationEvidenceSummary {
  return freezeRecord({
    verifierKind: verification.verifierKind,
    productionVerified: verification.productionVerified,
    credentialId: verification.credentialId,
    newSignCount: verification.newSignCount,
    userPresent: verification.userPresent,
    userVerified: verification.userVerified,
    rpIdHashMatched: verification.rpIdHashMatched,
    challengeMatched: verification.challengeMatched,
    originMatched: verification.originMatched,
    signatureVerified: verification.signatureVerified,
    counterStatus: verification.counterStatus,
    warnings: Object.freeze([...verification.warnings]),
    errors: Object.freeze([...verification.errors])
  });
}

function unsupportedProviderSummary(
  request: ProductionAuthenticationVerificationRequest
): ProductionAuthenticationVerificationEvidenceSummary {
  return freezeRecord({
    verifierKind: "unsupported-provider",
    productionVerified: false,
    credentialId: request.credential.credentialId,
    newSignCount: request.credential.signCount ?? request.storedSignCount,
    userPresent: false,
    userVerified: false,
    rpIdHashMatched: false,
    challengeMatched: false,
    originMatched: false,
    signatureVerified: false,
    counterStatus: "unsupported",
    warnings: Object.freeze(["provider kind is not supported by the production WebAuthn verifier bridge"]),
    errors: Object.freeze(["unsupported provider kind"])
  });
}

export function validateProductionAuthenticationVerificationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["production authentication verification request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isNonEmptyString(request.providerKind)) errors.push("providerKind is required");
  if (!isNonEmptyString(request.providerId)) errors.push("providerId is required");
  if (!isRecord(request.assertion)) errors.push("assertion is required");
  if (!isRecord(request.credential)) errors.push("credential is required");
  if (!isNonEmptyString(request.expectedChallenge)) errors.push("expectedChallenge is required");
  if (!isNonEmptyString(request.expectedRpId)) errors.push("expectedRpId is required");
  if (!isNonEmptyString(request.expectedOrigin)) errors.push("expectedOrigin is required");
  if (
    request.expectedUserVerification !== "required"
    && request.expectedUserVerification !== "preferred"
    && request.expectedUserVerification !== "discouraged"
  ) errors.push("expectedUserVerification is invalid");
  if (
    typeof request.storedSignCount !== "number"
    || !Number.isFinite(request.storedSignCount)
    || request.storedSignCount < 0
  ) errors.push("storedSignCount must be a non-negative number");
  if (!isRecord(request.correlation)) {
    errors.push("correlation is required");
  } else {
    if (!isNonEmptyString(request.correlation.sessionId)) errors.push("correlation.sessionId is required");
    if (!isNonEmptyString(request.correlation.providerId)) errors.push("correlation.providerId is required");
  }
  if (isRecord(request.credential) && isRecord(request.correlation)) {
    if (
      request.correlation.credentialId !== undefined
      && request.credential.credentialId !== request.correlation.credentialId
    ) errors.push("credentialId correlation mismatch");
  }
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (isRecord(request.freshness)) {
    if (request.freshness.collectedAt !== undefined && !hasValidDateShape(request.freshness.collectedAt)) {
      errors.push("freshness.collectedAt must be a parseable date string");
    }
    if (request.freshness.expiresAt !== undefined && !hasValidDateShape(request.freshness.expiresAt)) {
      errors.push("freshness.expiresAt must be a parseable date string");
    }
    if (request.freshness.staleAfter !== undefined && !hasValidDateShape(request.freshness.staleAfter)) {
      errors.push("freshness.staleAfter must be a parseable date string");
    }
  }
  if (
    request.requestedAssurance !== undefined
    && !Array.isArray(request.requestedAssurance)
  ) errors.push("requestedAssurance must be an array when provided");
  errors.push(...secretValidationErrors(request.metadata));
  return validation(errors);
}

export function validateProductionAuthenticationVerificationResult(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["production authentication verification result must be an object"]);
  if (!isNonEmptyString(result.verificationId)) errors.push("verificationId is required");
  if (!isNonEmptyString(result.requestId)) errors.push("requestId is required");
  if (!isNonEmptyString(result.providerId)) errors.push("providerId is required");
  if (!isNonEmptyString(result.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (!isRecord(result.correlation)) errors.push("correlation is required");
  if (!isRecord(result.evidenceSummary)) errors.push("evidenceSummary is required");
  if (result.authenticatesRuntime !== false) errors.push("authenticatesRuntime must be false");
  if (result.productionAuthenticationPerformed !== false) errors.push("productionAuthenticationPerformed must be false");
  if (result.browserCredentialPrompted !== false) errors.push("browserCredentialPrompted must be false");
  if (result.vaultUnlocked !== false) errors.push("vaultUnlocked must be false");
  if (result.counterPersisted !== false) errors.push("counterPersisted must be false");
  if (result.grantsCapability !== false) errors.push("grantsCapability must be false");
  if (result.createsAuthorizationPackage !== false) errors.push("createsAuthorizationPackage must be false");
  if (result.performsTrustDecision !== false) errors.push("performsTrustDecision must be false");
  if (result.performsPolicyDecision !== false) errors.push("performsPolicyDecision must be false");
  if (result.executesAdapter !== false) errors.push("executesAdapter must be false");
  if (result.persisted !== false) errors.push("persisted must be false");
  return validation(errors);
}

export function validateProductionAuthenticationVerificationCorrelation(
  request: ProductionAuthenticationVerificationRequest,
  result: ProductionAuthenticationVerificationResultValue
): RuntimeValidationResult {
  const errors: string[] = [];
  if (result.requestId !== request.requestId) errors.push("requestId correlation mismatch");
  if (result.correlation.sessionId !== request.correlation.sessionId) {
    errors.push("sessionId correlation mismatch");
  }
  if (result.correlation.providerId !== request.providerId) {
    errors.push("providerId correlation mismatch");
  }
  if (
    request.correlation.credentialId !== undefined
    && result.correlation.credentialId !== request.correlation.credentialId
  ) errors.push("credentialId correlation mismatch");
  if (
    request.correlation.ownerCommitment !== undefined
    && result.correlation.ownerCommitment !== request.correlation.ownerCommitment
  ) errors.push("ownerCommitment correlation mismatch");
  return validation(errors);
}

export async function verifyProductionWebAuthnAuthentication(
  request: ProductionAuthenticationVerificationRequest
): Promise<ProductionAuthenticationVerificationResult> {
  const validationResult = validateProductionAuthenticationVerificationRequest(request);
  if (!validationResult.valid) return runtimeDenied(malformedError(validationResult.errors));
  const auditCorrelationId = request.auditCorrelationId
    ?? request.correlation.auditCorrelationId
    ?? createAuditCorrelationId([
      request.correlation.sessionId,
      request.requestId,
      "production-authentication-verification"
    ]);
  const verification = request.providerKind === "webauthn_passkey"
    ? await createWebAuthnAssertionVerifier().verifyAssertion({
      assertion: request.assertion,
      credential: request.credential,
      expectedChallenge: request.expectedChallenge,
      expectedOrigin: request.expectedOrigin,
      expectedRpId: request.expectedRpId,
      expectedUserVerification: request.expectedUserVerification,
      storedSignCount: request.storedSignCount
    })
    : undefined;
  const outcome = verification
    ? outcomeFromVerification(verification, request)
    : "unsupported_provider";
  const status = statusFromOutcome(outcome);
  const verifiedAt = new Date().toISOString();
  const summary = verification
    ? verificationSummary(verification)
    : unsupportedProviderSummary(request);
  const lifecycleEligibility = outcome === "webauthn_assertion_verified"
    ? freezeRecord({
      eligibilityId: `${auditCorrelationId}:lifecycle-eligibility`,
      sessionId: request.correlation.sessionId,
      lifecycleTransitionRequestId: request.correlation.lifecycleTransitionRequestId,
      lifecycleEvent: request.correlation.lifecycleEvent,
      ownerCommitment: request.correlation.ownerCommitment,
      credentialId: request.credential.credentialId,
      providerId: request.providerId,
      auditCorrelationId,
      statement: "This verification result would allow a future authenticated lifecycle transition.",
      eligibleForFutureLifecycleTransition: true,
      performsTransitionNow: false,
      unlocksVault: false,
      authenticatesRuntime: false,
      grantsAuthority: false,
      persisted: false
    } satisfies LifecycleTransitionEligibility)
    : undefined;
  const result: ProductionAuthenticationVerificationResultValue = freezeRecord({
    verificationId: `${auditCorrelationId}:verification`,
    requestId: request.requestId,
    providerKind: request.providerKind,
    providerId: request.providerId,
    status,
    outcome,
    reasons: reasonsFromOutcome(outcome),
    correlation: freezeRecord({
      ...request.correlation,
      providerId: request.providerId,
      credentialId: request.correlation.credentialId ?? request.credential.credentialId,
      auditCorrelationId
    }),
    evidenceSummary: summary,
    lifecycleEligibility,
    limitations: DEFAULT_LIMITATIONS,
    verifiedAt,
    expiresAt: request.freshness?.expiresAt,
    auditCorrelationId,
    authenticatesRuntime: false,
    productionAuthenticationPerformed: false,
    browserCredentialPrompted: false,
    vaultUnlocked: false,
    counterPersisted: false,
    grantsCapability: false,
    createsAuthorizationPackage: false,
    performsTrustDecision: false,
    performsPolicyDecision: false,
    executesAdapter: false,
    persisted: false
  });
  const resultValidation = validateProductionAuthenticationVerificationResult(result);
  if (!resultValidation.valid) return runtimeDenied(malformedError(resultValidation.errors));
  return runtimeOk(result);
}

function normalizeMaxResultCount(maxResultCount?: number): number {
  if (maxResultCount === undefined) return 100;
  if (!Number.isFinite(maxResultCount)) return 100;
  return Math.max(1, Math.floor(maxResultCount));
}

function matchesFilter(
  result: ProductionAuthenticationVerificationResultValue,
  filter: ProductionAuthenticationVerificationFilter
): boolean {
  if (filter.verificationId !== undefined && result.verificationId !== filter.verificationId) return false;
  if (filter.requestId !== undefined && result.requestId !== filter.requestId) return false;
  if (filter.providerKind !== undefined && result.providerKind !== filter.providerKind) return false;
  if (filter.providerId !== undefined && result.providerId !== filter.providerId) return false;
  if (filter.sessionId !== undefined && result.correlation.sessionId !== filter.sessionId) return false;
  if (filter.credentialId !== undefined && result.evidenceSummary.credentialId !== filter.credentialId) return false;
  if (filter.outcome !== undefined && result.outcome !== filter.outcome) return false;
  if (filter.status !== undefined && result.status !== filter.status) return false;
  if (filter.auditCorrelationId !== undefined && result.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && result.verifiedAt < filter.since) return false;
  if (filter.until !== undefined && result.verifiedAt > filter.until) return false;
  return true;
}

export function createInMemoryProductionAuthenticationVerificationCollector(
  options: InMemoryProductionAuthenticationVerificationCollectorOptions = {}
): ProductionAuthenticationVerificationResultCollector {
  const maxResultCount = normalizeMaxResultCount(options.maxResultCount);
  const results = new Map<string, ProductionAuthenticationVerificationResultValue>();

  function getAll(): readonly ProductionAuthenticationVerificationResultValue[] {
    return Object.freeze(Array.from(results.values()));
  }

  function collection(): ProductionAuthenticationVerificationCollection {
    return freezeRecord({
      results: getAll(),
      count: results.size,
      maxResultCount
    });
  }

  function filterResults(
    filter: ProductionAuthenticationVerificationFilter
  ): readonly ProductionAuthenticationVerificationResultValue[] {
    return Object.freeze(getAll().filter((result) => matchesFilter(result, filter)));
  }

  return {
    addResult(result) {
      const validationResult = validateProductionAuthenticationVerificationResult(result);
      if (!validationResult.valid) {
        return {
          status: "rejected_invalid",
          collection: collection(),
          errors: validationResult.errors,
          reason: "Production authentication verification result failed validation."
        };
      }
      if (results.has(result.verificationId)) {
        return {
          status: "rejected_duplicate",
          result: results.get(result.verificationId),
          collection: collection(),
          reason: "Verification result IDs must be unique within an in-memory collector."
        };
      }
      const evictedResults: ProductionAuthenticationVerificationResultValue[] = [];
      if (results.size >= maxResultCount) {
        const oldestId = results.keys().next().value as string | undefined;
        if (oldestId !== undefined) {
          const oldest = results.get(oldestId);
          results.delete(oldestId);
          if (oldest) evictedResults.push(oldest);
        }
      }
      const frozen = freezeRecord(result);
      results.set(frozen.verificationId, frozen);
      return {
        status: evictedResults.length > 0 ? "evicted_oldest" : "collected",
        result: frozen,
        evictedResults: Object.freeze(evictedResults),
        collection: collection()
      };
    },
    removeResult(verificationId) {
      const removedResult = results.get(verificationId);
      if (!removedResult) {
        return {
          status: "not_found",
          collection: collection(),
          reason: "No verification result with that ID exists."
        };
      }
      results.delete(verificationId);
      return {
        status: "removed",
        removedResult,
        collection: collection()
      };
    },
    clear() {
      results.clear();
      return {
        status: "cleared",
        collection: collection()
      };
    },
    count() {
      return results.size;
    },
    getById(verificationId) {
      return results.get(verificationId);
    },
    getAll,
    query(query) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined ? undefined : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter ? filterResults(query.filter) : getAll();
      return Object.freeze(limit === undefined
        ? filtered.slice(offset)
        : filtered.slice(offset, offset + limit));
    },
    filter: filterResults
  };
}

function groupBy(
  results: readonly ProductionAuthenticationVerificationResultValue[],
  keyFor: (result: ProductionAuthenticationVerificationResultValue) => string | undefined
): ProductionAuthenticationVerificationGroupMap {
  const groups: Record<string, ProductionAuthenticationVerificationResultValue[]> = {};
  for (const result of results) {
    const key = keyFor(result) ?? "unknown";
    groups[key] = groups[key] ?? [];
    groups[key].push(result);
  }
  return freezeRecord(Object.fromEntries(
    Object.entries(groups).map(([key, value]) => [key, Object.freeze([...value])])
  ));
}

function counts(
  groups: ProductionAuthenticationVerificationGroupMap
): Readonly<Record<string, number>> {
  return freezeRecord(Object.fromEntries(
    Object.entries(groups).map(([key, value]) => [key, value.length])
  ));
}

export function groupProductionAuthenticationVerificationsByProvider(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): ProductionAuthenticationVerificationGroupMap {
  return groupBy(results, (result) => result.providerId);
}

export function groupProductionAuthenticationVerificationsByOutcome(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): ProductionAuthenticationVerificationGroupMap {
  return groupBy(results, (result) => result.outcome);
}

export function groupProductionAuthenticationVerificationsBySession(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): ProductionAuthenticationVerificationGroupMap {
  return groupBy(results, (result) => result.correlation.sessionId);
}

export function groupProductionAuthenticationVerificationsByCredential(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): ProductionAuthenticationVerificationGroupMap {
  return groupBy(results, (result) => result.evidenceSummary.credentialId);
}

export function getSuccessfulProductionAuthenticationVerifications(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): readonly ProductionAuthenticationVerificationResultValue[] {
  return Object.freeze(results.filter((result) => result.outcome === "webauthn_assertion_verified"));
}

export function getExpiredProductionAuthenticationVerifications(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): readonly ProductionAuthenticationVerificationResultValue[] {
  return Object.freeze(results.filter((result) => result.outcome === "stale_assertion"));
}

export function getReplayFailureProductionAuthenticationVerifications(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): readonly ProductionAuthenticationVerificationResultValue[] {
  return Object.freeze(results.filter((result) => result.outcome === "replay_detected"));
}

export function summarizeProductionAuthenticationVerifications(
  results: readonly ProductionAuthenticationVerificationResultValue[]
): ProductionAuthenticationVerificationReviewSummary {
  const byProvider = groupProductionAuthenticationVerificationsByProvider(results);
  const byOutcome = groupProductionAuthenticationVerificationsByOutcome(results);
  const bySession = groupProductionAuthenticationVerificationsBySession(results);
  const byCredential = groupProductionAuthenticationVerificationsByCredential(results);
  const sortedDates = results.map((result) => result.verifiedAt).sort();
  return freezeRecord({
    totalResultCount: results.length,
    resultsByProvider: counts(byProvider),
    resultsByOutcome: counts(byOutcome),
    resultsBySession: counts(bySession),
    resultsByCredential: counts(byCredential),
    successfulVerifications: getSuccessfulProductionAuthenticationVerifications(results),
    expiredVerifications: getExpiredProductionAuthenticationVerifications(results),
    replayFailures: getReplayFailureProductionAuthenticationVerifications(results),
    earliestVerifiedAt: sortedDates[0],
    latestVerifiedAt: sortedDates.at(-1),
    grantsAuthority: false,
    persisted: false
  });
}

export const groupByProvider = groupProductionAuthenticationVerificationsByProvider;
export const groupByOutcome = groupProductionAuthenticationVerificationsByOutcome;
export const groupBySession = groupProductionAuthenticationVerificationsBySession;
export const groupByCredential = groupProductionAuthenticationVerificationsByCredential;
export const getSuccessfulVerifications = getSuccessfulProductionAuthenticationVerifications;
export const getExpiredVerifications = getExpiredProductionAuthenticationVerifications;
export const getReplayFailures = getReplayFailureProductionAuthenticationVerifications;
