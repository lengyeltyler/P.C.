import type { PhilDeviceIdentityProviderKind } from "../deviceIdentity.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  validatePossessionVerificationRequestDraftShape,
  type PossessionVerificationRequestDraft
} from "./possessionVerification.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import {
  type WebAuthnFixtureVerificationArtifact
} from "./webauthnFixtureVerification.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type PossessionEvaluationStatus =
  | "evaluated"
  | "validation_failed"
  | "malformed"
  | "unsupported";

export type PossessionEvaluationOutcome =
  | "fixture_possession_checks_satisfied"
  | "fixture_possession_checks_failed"
  | "fixture_malformed"
  | "fixture_unsupported"
  | "challenge_binding_failed"
  | "authenticator_requirements_failed"
  | "counter_check_failed"
  | "pending_production_verification";

export type PossessionEvaluationReason =
  | "possession-verification-draft-valid"
  | "webauthn-fixture-artifact-valid"
  | "fixture-checks-satisfied"
  | "fixture-checks-failed"
  | "fixture-only-evidence"
  | "non-authoritative-result"
  | "challenge-correlation-mismatch"
  | "application-correlation-mismatch"
  | "session-correlation-mismatch"
  | "credential-correlation-mismatch"
  | "audit-correlation-mismatch"
  | "counter-persistence-not-performed"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type PossessionEvaluationRequirement =
  | "challenge_match"
  | "origin_match"
  | "rp_id_hash_match"
  | "user_presence"
  | "user_verification"
  | "signature_verification"
  | "counter_check";

export interface PossessionEvaluationEvidenceReference {
  readonly evidenceKind: "webauthn_fixture_verification_artifact";
  readonly artifactId: string;
  readonly fixtureId: string;
  readonly fixtureOnly: true;
  readonly productionAuthentication: false;
}

export interface PossessionEvaluationCounterAssessment {
  readonly counterStatus: WebAuthnFixtureVerificationArtifact["counterStatus"];
  readonly previousSignCount: number;
  readonly newSignCount?: number;
  readonly counterPersisted: false;
}

export interface PossessionEvaluationRequest {
  readonly requestId: string;
  readonly possessionVerificationRequestDraft: PossessionVerificationRequestDraft;
  readonly webAuthnFixtureVerificationArtifact: WebAuthnFixtureVerificationArtifact;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PossessionEvaluationResult {
  readonly possessionEvaluationResultId: string;
  readonly requestId: string;
  readonly possessionVerificationRequestDraftId: string;
  readonly webAuthnFixtureVerificationArtifactId: string;
  readonly publicTrustMetadataEvaluationId: string;
  readonly trustEvaluationDraftId: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly status: PossessionEvaluationStatus;
  readonly outcome: PossessionEvaluationOutcome;
  readonly evidence: PossessionEvaluationEvidenceReference;
  readonly requirements: readonly PossessionEvaluationRequirement[];
  readonly challengeMatched: boolean;
  readonly originMatched: boolean;
  readonly rpIdHashMatched: boolean;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly signatureVerified: boolean;
  readonly counterAssessment: PossessionEvaluationCounterAssessment;
  readonly reasons: readonly PossessionEvaluationReason[];
  readonly evaluatedAt: string;
  readonly auditCorrelationId: string;
  readonly fixtureOnly: true;
  readonly productionAuthentication: false;
  readonly authenticatesUser: false;
  readonly verifiesProductionPossession: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type PossessionEvaluationRuntimeResult = RuntimeResult<PossessionEvaluationResult>;

export type PossessionEvaluationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface PossessionEvaluationFilter {
  readonly possessionEvaluationResultId?: string;
  readonly requestId?: string;
  readonly possessionVerificationRequestDraftId?: string;
  readonly webAuthnFixtureVerificationArtifactId?: string;
  readonly publicTrustMetadataEvaluationId?: string;
  readonly trustEvaluationDraftId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly status?: PossessionEvaluationStatus;
  readonly outcome?: PossessionEvaluationOutcome;
  readonly fixtureOnly?: true;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface PossessionEvaluationQuery {
  readonly filter?: PossessionEvaluationFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface PossessionEvaluationCollection {
  readonly results: readonly PossessionEvaluationResult[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface PossessionEvaluationCollectionResult {
  readonly status: PossessionEvaluationCollectionStatus;
  readonly result?: PossessionEvaluationResult;
  readonly removedResult?: PossessionEvaluationResult;
  readonly evictedResults?: readonly PossessionEvaluationResult[];
  readonly collection: PossessionEvaluationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface PossessionEvaluationResultCollector {
  addResult(result: PossessionEvaluationResult): PossessionEvaluationCollectionResult;
  removeResult(possessionEvaluationResultId: string): PossessionEvaluationCollectionResult;
  clear(): PossessionEvaluationCollectionResult;
  count(): number;
  getById(possessionEvaluationResultId: string): PossessionEvaluationResult | undefined;
  getAll(): readonly PossessionEvaluationResult[];
  query(query: PossessionEvaluationQuery): readonly PossessionEvaluationResult[];
  filter(filter: PossessionEvaluationFilter): readonly PossessionEvaluationResult[];
}

export interface InMemoryPossessionEvaluationResultCollectorOptions {
  readonly maxResultCount?: number;
}

const POSSESSION_EVALUATION_STATUSES = new Set<PossessionEvaluationStatus>([
  "evaluated",
  "validation_failed",
  "malformed",
  "unsupported"
]);

const POSSESSION_EVALUATION_OUTCOMES = new Set<PossessionEvaluationOutcome>([
  "fixture_possession_checks_satisfied",
  "fixture_possession_checks_failed",
  "fixture_malformed",
  "fixture_unsupported",
  "challenge_binding_failed",
  "authenticator_requirements_failed",
  "counter_check_failed",
  "pending_production_verification"
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

function secretValidationErrors(input: unknown): readonly string[] {
  return validateNoSensitiveMetadataKeys(input).errors.map(
    (error) => `secret-shaped metadata is not allowed: ${error}`
  );
}

function malformedPossessionEvaluationError(
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "POSSESSION_EVALUATION_INVALID",
    message: "possession evaluation request failed validation",
    boundary: "trust-manager",
    recoverable: true,
    details: {
      errors
    }
  };
}

function validateFixtureArtifactShape(
  artifact: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(artifact)) {
    return validation(["webAuthnFixtureVerificationArtifact must be an object"]);
  }
  if (!isNonEmptyString(artifact.artifactId)) {
    errors.push("webAuthnFixtureVerificationArtifact.artifactId is required");
  }
  if (!isNonEmptyString(artifact.requestId)) {
    errors.push("webAuthnFixtureVerificationArtifact.requestId is required");
  }
  if (!isNonEmptyString(artifact.possessionVerificationRequestDraftId)) {
    errors.push("webAuthnFixtureVerificationArtifact.possessionVerificationRequestDraftId is required");
  }
  if (!isNonEmptyString(artifact.publicTrustMetadataEvaluationId)) {
    errors.push("webAuthnFixtureVerificationArtifact.publicTrustMetadataEvaluationId is required");
  }
  if (!isNonEmptyString(artifact.trustEvaluationDraftId)) {
    errors.push("webAuthnFixtureVerificationArtifact.trustEvaluationDraftId is required");
  }
  if (!isNonEmptyString(artifact.applicationId)) {
    errors.push("webAuthnFixtureVerificationArtifact.applicationId is required");
  }
  if (!isNonEmptyString(artifact.fixtureId)) {
    errors.push("webAuthnFixtureVerificationArtifact.fixtureId is required");
  }
  if (!isNonEmptyString(artifact.status)) {
    errors.push("webAuthnFixtureVerificationArtifact.status is required");
  }
  if (!isNonEmptyString(artifact.outcome)) {
    errors.push("webAuthnFixtureVerificationArtifact.outcome is required");
  }
  for (const field of [
    "challengeMatched",
    "originMatched",
    "rpIdHashMatched",
    "userPresent",
    "userVerified",
    "signatureVerified"
  ]) {
    if (typeof artifact[field] !== "boolean") {
      errors.push(`webAuthnFixtureVerificationArtifact.${field} must be boolean`);
    }
  }
  if (typeof artifact.previousSignCount !== "number") {
    errors.push("webAuthnFixtureVerificationArtifact.previousSignCount must be number");
  }
  if (artifact.counterPersisted !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.counterPersisted must be false");
  }
  if (!Array.isArray(artifact.verificationErrors)) {
    errors.push("webAuthnFixtureVerificationArtifact.verificationErrors must be an array");
  }
  if (!Array.isArray(artifact.verificationWarnings)) {
    errors.push("webAuthnFixtureVerificationArtifact.verificationWarnings must be an array");
  }
  if (!hasValidDateShape(artifact.verifiedAt)) {
    errors.push("webAuthnFixtureVerificationArtifact.verifiedAt must be a parseable date string");
  }
  if (!isNonEmptyString(artifact.auditCorrelationId)) {
    errors.push("webAuthnFixtureVerificationArtifact.auditCorrelationId is required");
  }
  if (artifact.fixtureOnly !== true) {
    errors.push("webAuthnFixtureVerificationArtifact.fixtureOnly must be true");
  }
  if (artifact.productionAuthentication !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.productionAuthentication must be false");
  }
  if (artifact.authenticatesUser !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.authenticatesUser must be false");
  }
  if (artifact.verifiesProductionPossession !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.verifiesProductionPossession must be false");
  }
  if (artifact.providesTrustDecision !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.providesTrustDecision must be false");
  }
  if (artifact.grantsAuthority !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.grantsAuthority must be false");
  }
  if (artifact.persisted !== false) {
    errors.push("webAuthnFixtureVerificationArtifact.persisted must be false");
  }
  errors.push(...secretValidationErrors(artifact));
  return validation(errors);
}

export function isPossessionEvaluationStatus(
  value: unknown
): value is PossessionEvaluationStatus {
  return POSSESSION_EVALUATION_STATUSES.has(value as PossessionEvaluationStatus);
}

export function validatePossessionEvaluationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["possession evaluation request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  const draftValidation = validatePossessionVerificationRequestDraftShape(
    request.possessionVerificationRequestDraft
  );
  if (!draftValidation.valid) {
    errors.push(...draftValidation.errors.map(
      (error) => `possessionVerificationRequestDraft.${error}`
    ));
  }
  const artifactValidation = validateFixtureArtifactShape(
    request.webAuthnFixtureVerificationArtifact
  );
  if (!artifactValidation.valid) {
    errors.push(...artifactValidation.errors);
  }
  errors.push(...secretValidationErrors(request.metadata));
  return validation(errors);
}

export function validatePossessionEvaluationResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) {
    return validation(["possession evaluation result must be an object"]);
  }
  if (!isNonEmptyString(result.possessionEvaluationResultId)) {
    errors.push("possessionEvaluationResultId is required");
  }
  if (!isNonEmptyString(result.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(result.possessionVerificationRequestDraftId)) {
    errors.push("possessionVerificationRequestDraftId is required");
  }
  if (!isNonEmptyString(result.webAuthnFixtureVerificationArtifactId)) {
    errors.push("webAuthnFixtureVerificationArtifactId is required");
  }
  if (!isNonEmptyString(result.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isPossessionEvaluationStatus(result.status)) {
    errors.push("status is invalid");
  }
  if (!POSSESSION_EVALUATION_OUTCOMES.has(result.outcome as PossessionEvaluationOutcome)) {
    errors.push("outcome is invalid");
  }
  if (!Array.isArray(result.reasons)) {
    errors.push("reasons must be an array");
  }
  if (!isRecord(result.evidence)) {
    errors.push("evidence is required");
  }
  if (!isRecord(result.counterAssessment)) {
    errors.push("counterAssessment is required");
  } else if (result.counterAssessment.counterPersisted !== false) {
    errors.push("counterAssessment.counterPersisted must be false");
  }
  if (!hasValidDateShape(result.evaluatedAt)) {
    errors.push("evaluatedAt must be a parseable date string");
  }
  if (!isNonEmptyString(result.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  if (result.fixtureOnly !== true) {
    errors.push("fixtureOnly must be true");
  }
  if (result.productionAuthentication !== false) {
    errors.push("productionAuthentication must be false");
  }
  if (result.authenticatesUser !== false) {
    errors.push("authenticatesUser must be false");
  }
  if (result.verifiesProductionPossession !== false) {
    errors.push("verifiesProductionPossession must be false");
  }
  if (result.providesTrustDecision !== false) {
    errors.push("providesTrustDecision must be false");
  }
  if (result.grantsAuthority !== false) {
    errors.push("grantsAuthority must be false");
  }
  if (result.persisted !== false) {
    errors.push("persisted must be false");
  }
  errors.push(...secretValidationErrors(result));
  return validation(errors);
}

function correlationErrors(
  draft: PossessionVerificationRequestDraft,
  artifact: WebAuthnFixtureVerificationArtifact
): readonly PossessionEvaluationReason[] {
  const reasons: PossessionEvaluationReason[] = [];
  if (artifact.possessionVerificationRequestDraftId !== draft.possessionVerificationRequestDraftId) {
    reasons.push("challenge-correlation-mismatch");
  }
  if (artifact.publicTrustMetadataEvaluationId !== draft.publicTrustMetadataEvaluationId) {
    reasons.push("challenge-correlation-mismatch");
  }
  if (artifact.trustEvaluationDraftId !== draft.trustEvaluationDraftId) {
    reasons.push("challenge-correlation-mismatch");
  }
  if (artifact.applicationId !== draft.applicationId) {
    reasons.push("application-correlation-mismatch");
  }
  if (draft.sessionId !== undefined && artifact.sessionId !== draft.sessionId) {
    reasons.push("session-correlation-mismatch");
  }
  if (draft.credentialId !== undefined && artifact.credentialId !== draft.credentialId) {
    reasons.push("credential-correlation-mismatch");
  }
  return Object.freeze(reasons);
}

function outcomeFromArtifact(
  artifact: WebAuthnFixtureVerificationArtifact,
  correlationFailure: boolean
): PossessionEvaluationOutcome {
  if (correlationFailure) return "challenge_binding_failed";
  if (artifact.outcome === "fixture_verified") {
    return "fixture_possession_checks_satisfied";
  }
  if (artifact.outcome === "fixture_malformed") return "fixture_malformed";
  if (artifact.outcome === "fixture_unsupported") return "fixture_unsupported";
  if (artifact.outcome === "challenge_mismatch") return "challenge_binding_failed";
  if (
    artifact.outcome === "user_presence_missing"
    || artifact.outcome === "user_verification_missing"
  ) {
    return "authenticator_requirements_failed";
  }
  if (artifact.outcome === "counter_invalid") return "counter_check_failed";
  return "fixture_possession_checks_failed";
}

const POSSESSION_EVALUATION_REQUIREMENTS: readonly PossessionEvaluationRequirement[] =
  Object.freeze([
    "challenge_match",
    "origin_match",
    "rp_id_hash_match",
    "user_presence",
    "user_verification",
    "signature_verification",
    "counter_check"
  ]);

export function createPossessionEvaluationResultFromWebAuthnFixture(
  request: PossessionEvaluationRequest
): PossessionEvaluationRuntimeResult {
  const validationResult = validatePossessionEvaluationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedPossessionEvaluationError(validationResult.errors));
  }

  const draft = request.possessionVerificationRequestDraft;
  const artifact = request.webAuthnFixtureVerificationArtifact;
  const correlation = correlationErrors(draft, artifact);
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    draft.applicationId,
    draft.sessionId ?? "",
    draft.possessionVerificationRequestDraftId,
    artifact.artifactId,
    "fixture-possession-evaluation"
  ]);
  const outcome = outcomeFromArtifact(artifact, correlation.length > 0);
  const result: PossessionEvaluationResult = Object.freeze({
    possessionEvaluationResultId: `${auditCorrelationId}:possession-evaluation`,
    requestId: request.requestId,
    possessionVerificationRequestDraftId: draft.possessionVerificationRequestDraftId,
    webAuthnFixtureVerificationArtifactId: artifact.artifactId,
    publicTrustMetadataEvaluationId: draft.publicTrustMetadataEvaluationId,
    trustEvaluationDraftId: draft.trustEvaluationDraftId,
    capabilityGrantDraftId: draft.capabilityGrantDraftId,
    applicationId: draft.applicationId,
    sessionId: draft.sessionId,
    ownerCommitment: draft.subject.ownerCommitment,
    credentialId: draft.credentialId,
    deviceId: draft.deviceId,
    providerKind: draft.providerKind,
    status: "evaluated",
    outcome,
    evidence: Object.freeze({
      evidenceKind: "webauthn_fixture_verification_artifact",
      artifactId: artifact.artifactId,
      fixtureId: artifact.fixtureId,
      fixtureOnly: true,
      productionAuthentication: false
    }),
    requirements: POSSESSION_EVALUATION_REQUIREMENTS,
    challengeMatched: artifact.challengeMatched && !correlation.includes("challenge-correlation-mismatch"),
    originMatched: artifact.originMatched,
    rpIdHashMatched: artifact.rpIdHashMatched,
    userPresent: artifact.userPresent,
    userVerified: artifact.userVerified,
    signatureVerified: artifact.signatureVerified,
    counterAssessment: Object.freeze({
      counterStatus: artifact.counterStatus,
      previousSignCount: artifact.previousSignCount,
      newSignCount: artifact.newSignCount,
      counterPersisted: false
    }),
    reasons: Object.freeze([
      "possession-verification-draft-valid",
      "webauthn-fixture-artifact-valid",
      artifact.outcome === "fixture_verified" ? "fixture-checks-satisfied" : "fixture-checks-failed",
      "fixture-only-evidence",
      "non-authoritative-result",
      "counter-persistence-not-performed",
      ...correlation
    ]),
    evaluatedAt: new Date().toISOString(),
    auditCorrelationId,
    fixtureOnly: true,
    productionAuthentication: false,
    authenticatesUser: false,
    verifiesProductionPossession: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });

  return runtimeOk(result);
}

function emptyCollection(
  maxResultCount: number,
  results: readonly PossessionEvaluationResult[] = []
): PossessionEvaluationCollection {
  return Object.freeze({
    results: Object.freeze([...results]),
    count: results.length,
    maxResultCount
  });
}

function collectionResult(input: {
  readonly status: PossessionEvaluationCollectionStatus;
  readonly results: readonly PossessionEvaluationResult[];
  readonly maxResultCount: number;
  readonly result?: PossessionEvaluationResult;
  readonly removedResult?: PossessionEvaluationResult;
  readonly evictedResults?: readonly PossessionEvaluationResult[];
  readonly errors?: readonly string[];
  readonly reason?: string;
}): PossessionEvaluationCollectionResult {
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
  result: PossessionEvaluationResult,
  filter: PossessionEvaluationFilter
): boolean {
  if (filter.possessionEvaluationResultId !== undefined && result.possessionEvaluationResultId !== filter.possessionEvaluationResultId) return false;
  if (filter.requestId !== undefined && result.requestId !== filter.requestId) return false;
  if (filter.possessionVerificationRequestDraftId !== undefined && result.possessionVerificationRequestDraftId !== filter.possessionVerificationRequestDraftId) return false;
  if (filter.webAuthnFixtureVerificationArtifactId !== undefined && result.webAuthnFixtureVerificationArtifactId !== filter.webAuthnFixtureVerificationArtifactId) return false;
  if (filter.publicTrustMetadataEvaluationId !== undefined && result.publicTrustMetadataEvaluationId !== filter.publicTrustMetadataEvaluationId) return false;
  if (filter.trustEvaluationDraftId !== undefined && result.trustEvaluationDraftId !== filter.trustEvaluationDraftId) return false;
  if (filter.applicationId !== undefined && result.applicationId !== filter.applicationId) return false;
  if (filter.sessionId !== undefined && result.sessionId !== filter.sessionId) return false;
  if (filter.ownerCommitment !== undefined && result.ownerCommitment !== filter.ownerCommitment) return false;
  if (filter.credentialId !== undefined && result.credentialId !== filter.credentialId) return false;
  if (filter.deviceId !== undefined && result.deviceId !== filter.deviceId) return false;
  if (filter.providerKind !== undefined && result.providerKind !== filter.providerKind) return false;
  if (filter.status !== undefined && result.status !== filter.status) return false;
  if (filter.outcome !== undefined && result.outcome !== filter.outcome) return false;
  if (filter.fixtureOnly !== undefined && result.fixtureOnly !== filter.fixtureOnly) return false;
  if (filter.auditCorrelationId !== undefined && result.auditCorrelationId !== filter.auditCorrelationId) return false;
  if (filter.since !== undefined && Date.parse(result.evaluatedAt) < Date.parse(filter.since)) return false;
  if (filter.until !== undefined && Date.parse(result.evaluatedAt) > Date.parse(filter.until)) return false;
  return true;
}

export function createInMemoryPossessionEvaluationResultCollector(
  options: InMemoryPossessionEvaluationResultCollectorOptions = {}
): PossessionEvaluationResultCollector {
  const maxResultCount = Math.max(1, Math.floor(options.maxResultCount ?? 100));
  const results: PossessionEvaluationResult[] = [];

  return Object.freeze({
    addResult(result: PossessionEvaluationResult) {
      const validationResult = validatePossessionEvaluationResultShape(result);
      if (!validationResult.valid) {
        return collectionResult({
          status: "rejected_invalid",
          results,
          maxResultCount,
          errors: validationResult.errors
        });
      }
      if (results.some((entry) => entry.possessionEvaluationResultId === result.possessionEvaluationResultId)) {
        return collectionResult({
          status: "rejected_duplicate",
          results,
          maxResultCount,
          result,
          reason: "possession evaluation result ID already exists"
        });
      }
      const evictedResults: PossessionEvaluationResult[] = [];
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
    removeResult(possessionEvaluationResultId: string) {
      const index = results.findIndex(
        (entry) => entry.possessionEvaluationResultId === possessionEvaluationResultId
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
    getById(possessionEvaluationResultId: string) {
      return results.find(
        (entry) => entry.possessionEvaluationResultId === possessionEvaluationResultId
      );
    },
    getAll() {
      return Object.freeze([...results]);
    },
    query(query: PossessionEvaluationQuery) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter === undefined
        ? results
        : results.filter((result) => matchesFilter(result, query.filter ?? {}));
      return Object.freeze(filtered.slice(offset, limit === undefined ? undefined : offset + limit));
    },
    filter(filter: PossessionEvaluationFilter) {
      return Object.freeze(results.filter((result) => matchesFilter(result, filter)));
    }
  });
}
