import {
  createWebAuthnAssertionVerifier,
  type PhilWebAuthnAssertion,
  type PhilWebAuthnCounterStatus,
  type PhilWebAuthnCredentialMetadata,
  type PhilWebAuthnVerificationInput,
  type PhilWebAuthnVerificationResult,
  type WebAuthnUserVerification
} from "../deviceIdentityWebAuthn.ts";
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
import type {
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type WebAuthnFixtureVerificationStatus =
  | "fixture_verified"
  | "fixture_rejected"
  | "fixture_malformed"
  | "fixture_unsupported"
  | "challenge_mismatch"
  | "origin_mismatch"
  | "rp_id_hash_mismatch"
  | "user_presence_missing"
  | "user_verification_missing"
  | "signature_invalid"
  | "counter_invalid"
  | "verification_failed";

export type WebAuthnFixtureVerificationOutcome = WebAuthnFixtureVerificationStatus;

export type WebAuthnFixtureVerificationReason =
  | "possession-verification-draft-valid"
  | "fixture-input-valid"
  | "fixture-challenge-bound-to-draft"
  | "existing-webauthn-assertion-verifier-used"
  | "fixture-verification-succeeded"
  | "fixture-verification-failed"
  | "challenge-binding-mismatch"
  | "unsupported-verification-method"
  | "draft-expired"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export interface WebAuthnFixtureDescriptor {
  readonly fixtureId: string;
  readonly challengeBindingReference: string;
  readonly expectedChallenge: string;
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
  readonly expectedUserVerification: WebAuthnUserVerification;
  readonly previousSignCount: number;
  readonly requireUserPresence?: boolean;
  readonly requireUserVerification?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface WebAuthnFixtureVerificationInput {
  readonly assertion: PhilWebAuthnAssertion;
  readonly credential: PhilWebAuthnCredentialMetadata;
  readonly descriptor: WebAuthnFixtureDescriptor;
}

export interface WebAuthnFixtureVerificationRequest {
  readonly requestId: string;
  readonly possessionVerificationRequestDraft: PossessionVerificationRequestDraft;
  readonly fixture: WebAuthnFixtureVerificationInput;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface WebAuthnFixtureVerificationArtifact {
  readonly artifactId: string;
  readonly requestId: string;
  readonly possessionVerificationRequestDraftId: string;
  readonly publicTrustMetadataEvaluationId: string;
  readonly trustEvaluationDraftId: string;
  readonly applicationId: string;
  readonly sessionId?: string;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly fixtureId: string;
  readonly verifierKind?: string;
  readonly status: WebAuthnFixtureVerificationStatus;
  readonly outcome: WebAuthnFixtureVerificationOutcome;
  readonly reasons: readonly WebAuthnFixtureVerificationReason[];
  readonly challengeMatched: boolean;
  readonly originMatched: boolean;
  readonly rpIdHashMatched: boolean;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly signatureVerified: boolean;
  readonly counterStatus: PhilWebAuthnCounterStatus | "unavailable";
  readonly previousSignCount: number;
  readonly newSignCount?: number;
  readonly counterPersisted: false;
  readonly verificationErrors: readonly string[];
  readonly verificationWarnings: readonly string[];
  readonly verifiedAt: string;
  readonly auditCorrelationId: string;
  readonly fixtureOnly: true;
  readonly productionAuthentication: false;
  readonly authenticatesUser: false;
  readonly verifiesProductionPossession: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type WebAuthnFixtureVerificationResult =
  RuntimeResult<WebAuthnFixtureVerificationArtifact>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function malformedWebAuthnFixtureError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "WEBAUTHN_FIXTURE_VERIFICATION_INVALID",
    message: "WebAuthn fixture possession verification request failed validation",
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

function expiredDraft(draft: PossessionVerificationRequestDraft): boolean {
  return draft.expiresAt !== undefined && Date.parse(draft.expiresAt) <= Date.now();
}

export function validateWebAuthnFixtureVerificationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["WebAuthn fixture verification request must be an object"]);
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

  if (!isRecord(request.fixture)) {
    errors.push("fixture is required");
  } else {
    if (!isRecord(request.fixture.assertion)) {
      errors.push("fixture.assertion is required");
    }
    if (!isRecord(request.fixture.credential)) {
      errors.push("fixture.credential is required");
    }
    if (!isRecord(request.fixture.descriptor)) {
      errors.push("fixture.descriptor is required");
    } else {
      if (!isNonEmptyString(request.fixture.descriptor.fixtureId)) {
        errors.push("fixture.descriptor.fixtureId is required");
      }
      if (!isNonEmptyString(request.fixture.descriptor.challengeBindingReference)) {
        errors.push("fixture.descriptor.challengeBindingReference is required");
      }
      if (!isNonEmptyString(request.fixture.descriptor.expectedChallenge)) {
        errors.push("fixture.descriptor.expectedChallenge is required");
      }
      if (!isNonEmptyString(request.fixture.descriptor.expectedOrigin)) {
        errors.push("fixture.descriptor.expectedOrigin is required");
      }
      if (!isNonEmptyString(request.fixture.descriptor.expectedRpId)) {
        errors.push("fixture.descriptor.expectedRpId is required");
      }
      if (
        request.fixture.descriptor.expectedUserVerification !== "required"
        && request.fixture.descriptor.expectedUserVerification !== "preferred"
        && request.fixture.descriptor.expectedUserVerification !== "discouraged"
      ) {
        errors.push("fixture.descriptor.expectedUserVerification is invalid");
      }
      if (
        typeof request.fixture.descriptor.previousSignCount !== "number"
        || !Number.isFinite(request.fixture.descriptor.previousSignCount)
        || request.fixture.descriptor.previousSignCount < 0
      ) {
        errors.push("fixture.descriptor.previousSignCount must be a non-negative number");
      }
    }
  }

  if (
    isRecord(request.possessionVerificationRequestDraft)
    && request.possessionVerificationRequestDraft.expiresAt !== undefined
    && !hasValidDateShape(request.possessionVerificationRequestDraft.expiresAt)
  ) {
    errors.push("possessionVerificationRequestDraft.expiresAt must be a parseable date string");
  }

  errors.push(...secretValidationErrors(request.metadata));
  if (isRecord(request.fixture) && isRecord(request.fixture.descriptor)) {
    errors.push(...secretValidationErrors(request.fixture.descriptor.metadata));
  }

  return validation(errors);
}

function outcomeFromVerification(
  verification: PhilWebAuthnVerificationResult
): WebAuthnFixtureVerificationOutcome {
  if (verification.verified) return "fixture_verified";
  if (!verification.challengeMatched) return "challenge_mismatch";
  if (!verification.originMatched) return "origin_mismatch";
  if (!verification.rpIdHashMatched) return "rp_id_hash_mismatch";
  if (!verification.userPresent) return "user_presence_missing";
  if (!verification.userVerified) return "user_verification_missing";
  if (
    verification.counterStatus === "rollback"
    || verification.counterStatus === "clone-suspected"
  ) return "counter_invalid";
  if (!verification.signatureVerified) return "signature_invalid";
  return "verification_failed";
}

function artifactFromFixtureFailure(input: {
  readonly request: WebAuthnFixtureVerificationRequest;
  readonly outcome: WebAuthnFixtureVerificationOutcome;
  readonly errors: readonly string[];
  readonly warnings?: readonly string[];
  readonly auditCorrelationId: string;
}): WebAuthnFixtureVerificationArtifact {
  const draft = input.request.possessionVerificationRequestDraft;
  return Object.freeze({
    artifactId: `${input.auditCorrelationId}:artifact`,
    requestId: input.request.requestId,
    possessionVerificationRequestDraftId: draft.possessionVerificationRequestDraftId,
    publicTrustMetadataEvaluationId: draft.publicTrustMetadataEvaluationId,
    trustEvaluationDraftId: draft.trustEvaluationDraftId,
    applicationId: draft.applicationId,
    sessionId: draft.sessionId,
    credentialId: draft.credentialId,
    deviceId: draft.deviceId,
    fixtureId: input.request.fixture.descriptor.fixtureId,
    status: input.outcome,
    outcome: input.outcome,
    reasons: Object.freeze([
      "possession-verification-draft-valid",
      "fixture-input-valid",
      "fixture-verification-failed"
    ]),
    challengeMatched: input.outcome !== "challenge_mismatch",
    originMatched: input.outcome !== "origin_mismatch",
    rpIdHashMatched: input.outcome !== "rp_id_hash_mismatch",
    userPresent: input.outcome !== "user_presence_missing",
    userVerified: input.outcome !== "user_verification_missing",
    signatureVerified: false,
    counterStatus: "unavailable",
    previousSignCount: input.request.fixture.descriptor.previousSignCount,
    counterPersisted: false,
    verificationErrors: Object.freeze([...input.errors]),
    verificationWarnings: Object.freeze([...(input.warnings ?? [])]),
    verifiedAt: new Date().toISOString(),
    auditCorrelationId: input.auditCorrelationId,
    fixtureOnly: true,
    productionAuthentication: false,
    authenticatesUser: false,
    verifiesProductionPossession: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });
}

export async function verifyPossessionDraftWithWebAuthnFixture(
  request: WebAuthnFixtureVerificationRequest
): Promise<WebAuthnFixtureVerificationResult> {
  const validationResult = validateWebAuthnFixtureVerificationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedWebAuthnFixtureError(validationResult.errors));
  }

  const draft = request.possessionVerificationRequestDraft;
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    draft.applicationId,
    draft.sessionId ?? "",
    draft.possessionVerificationRequestDraftId,
    request.fixture.descriptor.fixtureId,
    "webauthn-fixture-possession-verification"
  ]);

  if (draft.verificationMethod !== "webauthn_assertion") {
    return runtimeOk(artifactFromFixtureFailure({
      request,
      outcome: "fixture_unsupported",
      errors: ["possession verification draft method is not webauthn_assertion"],
      auditCorrelationId
    }));
  }

  if (expiredDraft(draft)) {
    return runtimeOk(artifactFromFixtureFailure({
      request,
      outcome: "fixture_rejected",
      errors: ["possession verification request draft is expired"],
      auditCorrelationId
    }));
  }

  if (
    request.fixture.descriptor.challengeBindingReference
    !== draft.challengeDescriptor.challengeReference
  ) {
    return runtimeOk(artifactFromFixtureFailure({
      request,
      outcome: "challenge_mismatch",
      errors: ["fixture challenge binding reference does not match possession draft challenge reference"],
      auditCorrelationId
    }));
  }

  if (
    draft.credentialId !== undefined
    && (
      request.fixture.credential.credentialId !== draft.credentialId
      || request.fixture.assertion.rawId !== draft.credentialId
    )
  ) {
    return runtimeOk(artifactFromFixtureFailure({
      request,
      outcome: "fixture_rejected",
      errors: ["fixture credential correlation does not match possession verification draft"],
      auditCorrelationId
    }));
  }

  const verifier = createWebAuthnAssertionVerifier();
  const verificationInput: PhilWebAuthnVerificationInput = {
    assertion: request.fixture.assertion,
    credential: request.fixture.credential,
    expectedChallenge: request.fixture.descriptor.expectedChallenge,
    expectedOrigin: request.fixture.descriptor.expectedOrigin,
    expectedRpId: request.fixture.descriptor.expectedRpId,
    expectedUserVerification: request.fixture.descriptor.expectedUserVerification,
    storedSignCount: request.fixture.descriptor.previousSignCount
  };
  const verification = await verifier.verifyAssertion(verificationInput);
  const outcome = outcomeFromVerification(verification);
  const artifact: WebAuthnFixtureVerificationArtifact = Object.freeze({
    artifactId: `${auditCorrelationId}:artifact`,
    requestId: request.requestId,
    possessionVerificationRequestDraftId: draft.possessionVerificationRequestDraftId,
    publicTrustMetadataEvaluationId: draft.publicTrustMetadataEvaluationId,
    trustEvaluationDraftId: draft.trustEvaluationDraftId,
    applicationId: draft.applicationId,
    sessionId: draft.sessionId,
    credentialId: draft.credentialId,
    deviceId: draft.deviceId,
    fixtureId: request.fixture.descriptor.fixtureId,
    verifierKind: verification.verifierKind,
    status: outcome,
    outcome,
    reasons: Object.freeze([
      "possession-verification-draft-valid",
      "fixture-input-valid",
      "fixture-challenge-bound-to-draft",
      "existing-webauthn-assertion-verifier-used",
      verification.verified ? "fixture-verification-succeeded" : "fixture-verification-failed"
    ]),
    challengeMatched: verification.challengeMatched,
    originMatched: verification.originMatched,
    rpIdHashMatched: verification.rpIdHashMatched,
    userPresent: verification.userPresent,
    userVerified: verification.userVerified,
    signatureVerified: verification.signatureVerified,
    counterStatus: verification.counterStatus,
    previousSignCount: request.fixture.descriptor.previousSignCount,
    newSignCount: verification.newSignCount,
    counterPersisted: false,
    verificationErrors: Object.freeze([...verification.errors]),
    verificationWarnings: Object.freeze([...verification.warnings]),
    verifiedAt: new Date().toISOString(),
    auditCorrelationId,
    fixtureOnly: true,
    productionAuthentication: false,
    authenticatesUser: false,
    verifiesProductionPossession: false,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  });

  return runtimeOk(artifact);
}
