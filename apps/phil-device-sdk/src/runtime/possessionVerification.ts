import type { PhilDeviceIdentityProviderKind } from "../deviceIdentity.ts";
import {
  PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND
} from "../deviceIdentity.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  validatePublicTrustMetadataEvaluationResultShape,
  type PublicTrustMetadataEvaluationResult
} from "./publicTrustMetadata.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext
} from "./types.ts";

export type PossessionVerificationMethod =
  | "webauthn_assertion"
  | "device_signature"
  | "hardware_key_assertion"
  | "unsupported";

export type PossessionVerificationRequestDraftStatus =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_challenge_construction"
  | "pending_possession_verification";

export type PossessionVerificationRequestDraftOutcome =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_challenge_construction"
  | "pending_possession_verification";

export type PossessionVerificationRequestDraftReason =
  | "public-trust-metadata-evaluation-valid"
  | "possession-verification-required"
  | "challenge-construction-pending"
  | "future-possession-verification-required"
  | "metadata-evaluation-not-eligible"
  | "verification-method-unsupported"
  | "request-expired"
  | "missing-required-correlation"
  | "secret-shaped-metadata-not-allowed"
  | "active-authority-field-present"
  | (string & {});

export interface PossessionVerificationSubject {
  readonly applicationId: ApplicationId;
  readonly publicTrustMetadataEvaluationId: string;
  readonly trustEvaluationDraftId: string;
  readonly capabilityGrantDraftId?: string;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly ownerCommitment?: Hex;
}

export interface PossessionVerificationChallengeDescriptor {
  readonly challengePurpose: "credential_possession_verification";
  readonly challengeReference: string;
  readonly challengeBindingHash?: string;
  readonly expectedApplicationId: ApplicationId;
  readonly expectedSessionId?: string;
  readonly expectedCredentialId?: string;
  readonly expectedDeviceId?: string;
  readonly verificationMethod: PossessionVerificationMethod;
  readonly expiresAt?: string;
  readonly generatedChallenge: false;
}

export interface PossessionVerificationRequirementDraft {
  readonly requirementId: string;
  readonly method: PossessionVerificationMethod;
  readonly description?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PossessionVerificationRequestDraftInput {
  readonly requestId: string;
  readonly publicTrustMetadataEvaluation: PublicTrustMetadataEvaluationResult;
  readonly userSessionContext?: UserSessionContext;
  readonly verificationMethod?: PossessionVerificationMethod;
  readonly challengeDescriptor?: PossessionVerificationChallengeDescriptor;
  readonly requirements?: readonly PossessionVerificationRequirementDraft[];
  readonly auditCorrelationId?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly status?: PossessionVerificationRequestDraftStatus;
  readonly outcome?: PossessionVerificationRequestDraftOutcome;
}

export interface PossessionVerificationRequestDraft {
  readonly possessionVerificationRequestDraftId: string;
  readonly requestId: string;
  readonly publicTrustMetadataEvaluationId: string;
  readonly trustEvaluationDraftId: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly verificationMethod: PossessionVerificationMethod;
  readonly subject: PossessionVerificationSubject;
  readonly challengeDescriptor: PossessionVerificationChallengeDescriptor;
  readonly requirements: readonly PossessionVerificationRequirementDraft[];
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly status: PossessionVerificationRequestDraftStatus;
  readonly outcome: PossessionVerificationRequestDraftOutcome;
  readonly reasons: readonly PossessionVerificationRequestDraftReason[];
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly verifiesPossession: false;
  readonly authenticatesUser: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type PossessionVerificationRequestDraftResult =
  RuntimeResult<PossessionVerificationRequestDraft>;

const POSSESSION_VERIFICATION_METHODS = new Set<PossessionVerificationMethod>([
  "webauthn_assertion",
  "device_signature",
  "hardware_key_assertion",
  "unsupported"
]);

const POSSESSION_VERIFICATION_REQUEST_DRAFT_STATUSES =
  new Set<PossessionVerificationRequestDraftStatus>([
    "draft_created",
    "validation_failed",
    "malformed",
    "unsupported",
    "pending_challenge_construction",
    "pending_possession_verification"
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
  "assertionresponse",
  "webauthnprivatematerial",
  "rawchallenge",
  "clientdatajson",
  "authenticatordata",
  "signature",
  "trusted",
  "approved",
  "authenticated",
  "verified",
  "authorized",
  "trustdecision",
  "authorizationpackage",
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

function malformedPossessionVerificationDraftError(
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "POSSESSION_VERIFICATION_REQUEST_DRAFT_INVALID",
    message: "possession verification request draft input failed validation",
    boundary: "trust-manager",
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

export function isPossessionVerificationMethod(
  value: unknown
): value is PossessionVerificationMethod {
  return POSSESSION_VERIFICATION_METHODS.has(value as PossessionVerificationMethod);
}

export function isPossessionVerificationRequestDraftStatus(
  value: unknown
): value is PossessionVerificationRequestDraftStatus {
  return POSSESSION_VERIFICATION_REQUEST_DRAFT_STATUSES.has(
    value as PossessionVerificationRequestDraftStatus
  );
}

function defaultVerificationMethod(
  providerKind: string | undefined
): PossessionVerificationMethod {
  if (providerKind === PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND) {
    return "webauthn_assertion";
  }
  if (providerKind === PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND) {
    return "device_signature";
  }
  if (
    providerKind === PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND
    || providerKind === PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND
  ) {
    return "hardware_key_assertion";
  }
  return "unsupported";
}

function isEvaluationExpired(evaluation: PublicTrustMetadataEvaluationResult): boolean {
  return evaluation.reasons.includes("request-expired");
}

function evaluationRequiresPossession(
  evaluation: PublicTrustMetadataEvaluationResult
): boolean {
  return evaluation.requiresPossessionVerification
    || evaluation.resolutionRequirements.includes("possession_verification")
    || evaluation.outcome === "pending_possession_verification";
}

function validateChallengeDescriptorShape(
  descriptor: unknown
): readonly string[] {
  const errors: string[] = [];
  if (!isRecord(descriptor)) {
    return ["challengeDescriptor must be an object"];
  }
  if (descriptor.challengePurpose !== "credential_possession_verification") {
    errors.push("challengeDescriptor.challengePurpose is invalid");
  }
  if (!isNonEmptyString(descriptor.challengeReference)) {
    errors.push("challengeDescriptor.challengeReference is required");
  }
  if (!isNonEmptyString(descriptor.expectedApplicationId)) {
    errors.push("challengeDescriptor.expectedApplicationId is required");
  }
  if (!isPossessionVerificationMethod(descriptor.verificationMethod)) {
    errors.push("challengeDescriptor.verificationMethod is invalid");
  }
  if (descriptor.generatedChallenge !== false) {
    errors.push("challengeDescriptor.generatedChallenge must be false");
  }
  if (descriptor.expiresAt !== undefined && !hasValidDateShape(descriptor.expiresAt)) {
    errors.push("challengeDescriptor.expiresAt must be a parseable date string");
  }
  return errors;
}

export function validatePossessionVerificationRequestDraftInput(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["possession verification request draft input must be an object"]);
  }

  if (!isNonEmptyString(input.requestId)) {
    errors.push("requestId is required");
  }

  const evaluationValidation = validatePublicTrustMetadataEvaluationResultShape(
    input.publicTrustMetadataEvaluation
  );
  if (!evaluationValidation.valid) {
    errors.push(...evaluationValidation.errors.map(
      (error) => `publicTrustMetadataEvaluation.${error}`
    ));
  }

  if (
    input.verificationMethod !== undefined
    && !isPossessionVerificationMethod(input.verificationMethod)
  ) {
    errors.push("verificationMethod is invalid");
  }
  if (input.status !== undefined && !isPossessionVerificationRequestDraftStatus(input.status)) {
    errors.push("status is invalid");
  }
  if (input.outcome !== undefined && !isPossessionVerificationRequestDraftStatus(input.outcome)) {
    errors.push("outcome is invalid");
  }
  if (input.createdAt !== undefined && !hasValidDateShape(input.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (input.expiresAt !== undefined && !hasValidDateShape(input.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (input.challengeDescriptor !== undefined) {
    errors.push(...validateChallengeDescriptorShape(input.challengeDescriptor));
  }
  if (Array.isArray(input.requirements)) {
    input.requirements.forEach((requirement, index) => {
      if (!isRecord(requirement)) {
        errors.push(`requirements[${index}] must be an object`);
        return;
      }
      if (!isNonEmptyString(requirement.requirementId)) {
        errors.push(`requirements[${index}].requirementId is required`);
      }
      if (!isPossessionVerificationMethod(requirement.method)) {
        errors.push(`requirements[${index}].method is invalid`);
      }
    });
  }

  const blockedFields = findBlockedFields(input);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(input));

  return validation(errors);
}

export function validatePossessionVerificationRequestDraftShape(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) {
    return validation(["possession verification request draft must be an object"]);
  }

  if (!isNonEmptyString(draft.possessionVerificationRequestDraftId)) {
    errors.push("possessionVerificationRequestDraftId is required");
  }
  if (!isNonEmptyString(draft.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(draft.publicTrustMetadataEvaluationId)) {
    errors.push("publicTrustMetadataEvaluationId is required");
  }
  if (!isNonEmptyString(draft.trustEvaluationDraftId)) {
    errors.push("trustEvaluationDraftId is required");
  }
  if (!isNonEmptyString(draft.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isPossessionVerificationMethod(draft.verificationMethod)) {
    errors.push("verificationMethod is invalid");
  }
  if (!isRecord(draft.challengeDescriptor)) {
    errors.push("challengeDescriptor is required");
  } else {
    errors.push(...validateChallengeDescriptorShape(draft.challengeDescriptor));
  }
  if (!isPossessionVerificationRequestDraftStatus(draft.status)) {
    errors.push("status is invalid");
  }
  if (!isPossessionVerificationRequestDraftStatus(draft.outcome)) {
    errors.push("outcome is invalid");
  }
  if (
    draft.status === "verified"
    || draft.status === "authenticated"
    || draft.status === "trusted"
    || draft.status === "approved"
  ) {
    errors.push("possession verification request drafts must never use active verification statuses");
  }
  if (draft.verifiesPossession !== false) {
    errors.push("verifiesPossession must be false");
  }
  if (draft.authenticatesUser !== false) {
    errors.push("authenticatesUser must be false");
  }
  if (draft.providesTrustDecision !== false) {
    errors.push("providesTrustDecision must be false");
  }
  if (draft.grantsAuthority !== false) {
    errors.push("grantsAuthority must be false");
  }
  if (draft.persisted !== false) {
    errors.push("persisted must be false");
  }
  if (!hasValidDateShape(draft.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (draft.expiresAt !== undefined && !hasValidDateShape(draft.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }

  const blockedFields = findBlockedFields(draft);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(draft));

  return validation(errors);
}

function derivePossessionVerificationPreconditions(
  evaluation: PublicTrustMetadataEvaluationResult,
  method: PossessionVerificationMethod
): readonly string[] {
  const errors: string[] = [];
  if (!evaluationRequiresPossession(evaluation)) {
    errors.push("publicTrustMetadataEvaluation does not require possession verification");
  }
  if (!evaluation.eligibleForFurtherEvaluation) {
    errors.push("publicTrustMetadataEvaluation is not eligible for further evaluation");
  }
  if (evaluation.outcome !== "metadata_sufficient") {
    errors.push("publicTrustMetadataEvaluation outcome must be metadata_sufficient");
  }
  if (evaluation.status === "unsupported" || evaluation.outcome === "provider_unsupported") {
    errors.push("unsupported provider evaluations cannot produce possession verification drafts");
  }
  if (
    evaluation.outcome === "credential_status_ineligible"
    || evaluation.outcome === "device_status_ineligible"
    || evaluation.eligibility === "ineligible_for_ordinary_use"
    || evaluation.eligibility === "recovery_only"
  ) {
    errors.push("ineligible lifecycle evaluations cannot produce possession verification drafts");
  }
  if (evaluation.outcome === "metadata_malformed" || evaluation.eligibility === "malformed") {
    errors.push("malformed metadata evaluations cannot produce possession verification drafts");
  }
  if (isEvaluationExpired(evaluation)) {
    errors.push("expired evaluations cannot produce possession verification drafts");
  }
  if (!isNonEmptyString(evaluation.evaluationId)) {
    errors.push("publicTrustMetadataEvaluation.evaluationId is required");
  }
  if (!isNonEmptyString(evaluation.trustEvaluationDraftId)) {
    errors.push("publicTrustMetadataEvaluation.trustEvaluationDraftId is required");
  }
  if (!isNonEmptyString(evaluation.applicationId)) {
    errors.push("publicTrustMetadataEvaluation.applicationId is required");
  }
  if (!isNonEmptyString(evaluation.credentialId)) {
    errors.push("publicTrustMetadataEvaluation.credentialId is required");
  }
  if (!isNonEmptyString(evaluation.deviceId)) {
    errors.push("publicTrustMetadataEvaluation.deviceId is required");
  }
  if (method === "unsupported") {
    errors.push("verificationMethod is unsupported");
  }
  return Object.freeze(errors);
}

function createChallengeDescriptor(input: {
  readonly requestId: string;
  readonly evaluation: PublicTrustMetadataEvaluationResult;
  readonly verificationMethod: PossessionVerificationMethod;
  readonly expiresAt?: string;
  readonly challengeDescriptor?: PossessionVerificationChallengeDescriptor;
}): PossessionVerificationChallengeDescriptor {
  if (input.challengeDescriptor) {
    return freezeRecord(input.challengeDescriptor);
  }

  return Object.freeze({
    challengePurpose: "credential_possession_verification",
    challengeReference: `${input.evaluation.evaluationId}:challenge-reference`,
    challengeBindingHash: createAuditCorrelationId([
      input.evaluation.applicationId,
      input.evaluation.sessionId ?? "",
      input.evaluation.evaluationId,
      input.requestId,
      "possession-verification-challenge-placeholder"
    ]),
    expectedApplicationId: input.evaluation.applicationId,
    expectedSessionId: input.evaluation.sessionId,
    expectedCredentialId: input.evaluation.credentialId,
    expectedDeviceId: input.evaluation.deviceId,
    verificationMethod: input.verificationMethod,
    expiresAt: input.expiresAt,
    generatedChallenge: false
  });
}

export function createPossessionVerificationRequestDraft(
  input: PossessionVerificationRequestDraftInput
): PossessionVerificationRequestDraftResult {
  const validationResult = validatePossessionVerificationRequestDraftInput(input);
  if (!validationResult.valid) {
    return runtimeDenied(malformedPossessionVerificationDraftError(validationResult.errors));
  }

  const evaluation = input.publicTrustMetadataEvaluation;
  const verificationMethod = input.verificationMethod
    ?? defaultVerificationMethod(evaluation.providerKind);
  const preconditionErrors = derivePossessionVerificationPreconditions(
    evaluation,
    verificationMethod
  );
  if (preconditionErrors.length > 0) {
    return runtimeDenied(malformedPossessionVerificationDraftError(preconditionErrors));
  }

  const sessionId = input.userSessionContext?.sessionId ?? evaluation.sessionId;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const auditCorrelationId = input.auditCorrelationId ?? createAuditCorrelationId([
    evaluation.applicationId,
    sessionId ?? "",
    evaluation.evaluationId,
    input.requestId,
    "possession-verification-request-draft"
  ]);
  const status = input.status ?? "pending_challenge_construction";
  const outcome = input.outcome ?? status;
  const challengeDescriptor = createChallengeDescriptor({
    requestId: input.requestId,
    evaluation,
    verificationMethod,
    expiresAt: input.expiresAt,
    challengeDescriptor: input.challengeDescriptor
  });
  const subject: PossessionVerificationSubject = freezeRecord({
    applicationId: evaluation.applicationId,
    publicTrustMetadataEvaluationId: evaluation.evaluationId,
    trustEvaluationDraftId: evaluation.trustEvaluationDraftId,
    capabilityGrantDraftId: evaluation.capabilityGrantDraftId,
    sessionId,
    credentialId: evaluation.credentialId,
    deviceId: evaluation.deviceId,
    providerKind: evaluation.providerKind,
    ownerCommitment: evaluation.ownerCommitment
  });
  const requirements = Object.freeze([...(input.requirements ?? [{
    requirementId: `${input.requestId}:possession-verification-required`,
    method: verificationMethod,
    description: "Future possession verification is required before trust can be evaluated."
  }])].map((requirement) => freezeRecord(
    redactRuntimeMetadata(requirement).value as PossessionVerificationRequirementDraft
  )));
  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;

  const draft: PossessionVerificationRequestDraft = Object.freeze({
    possessionVerificationRequestDraftId: `${auditCorrelationId}:draft`,
    requestId: input.requestId,
    publicTrustMetadataEvaluationId: evaluation.evaluationId,
    trustEvaluationDraftId: evaluation.trustEvaluationDraftId,
    capabilityGrantDraftId: evaluation.capabilityGrantDraftId,
    applicationId: evaluation.applicationId,
    sessionId,
    credentialId: evaluation.credentialId,
    deviceId: evaluation.deviceId,
    providerKind: evaluation.providerKind,
    verificationMethod,
    subject,
    challengeDescriptor,
    requirements,
    createdAt,
    expiresAt: input.expiresAt,
    status,
    outcome,
    reasons: Object.freeze([
      "public-trust-metadata-evaluation-valid",
      "possession-verification-required",
      "challenge-construction-pending",
      "future-possession-verification-required"
    ]),
    auditCorrelationId,
    humanReadableSummary: input.humanReadableSummary
      ?? `Possession verification request ${input.requestId} is drafted for future ${verificationMethod} handling; no verification was executed.`,
    metadata,
    verifiesPossession: false,
    authenticatesUser: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });

  return runtimeOk(draft);
}
