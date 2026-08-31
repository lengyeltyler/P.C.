import type { PhilDeviceIdentityProviderKind } from "../deviceIdentity.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionEvidenceReferenceKind,
  UserSessionLifecycleEvidenceReference,
  UserSessionLifecycleEvent
} from "./sessionLifecycle.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimePlatform,
  RuntimeResult
} from "./types.ts";

export type AuthenticationProviderId = string;

export type AuthenticationProviderKind =
  | "webauthn_passkey"
  | "platform_biometric"
  | "hardware_security_key"
  | "device_signature"
  | "local_pin"
  | "recovery_credential"
  | "developer_fixture"
  | "unsupported";

export type AuthenticationProviderStatus =
  | "available"
  | "unavailable"
  | "unsupported"
  | "disabled"
  | "fixture_only";

export type AuthenticationProviderAvailability =
  | "available"
  | "unavailable"
  | "unsupported"
  | "requires_platform_setup"
  | "fixture_only";

export type AuthenticationProviderAssurance =
  | "none"
  | "user_presence"
  | "user_verification"
  | "hardware_backed"
  | "phishing_resistant"
  | "recovery_ceremony"
  | "developer_fixture";

export interface AuthenticationProviderCapabilities {
  readonly supportsSessionUnlock: boolean;
  readonly supportsSessionResume: boolean;
  readonly supportsHighRiskAction: boolean;
  readonly supportsCredentialLifecycle: boolean;
  readonly supportsRecovery: boolean;
  readonly supportsChallengeBinding: boolean;
  readonly fixtureOnly: boolean;
  readonly productionAuthentication: boolean;
}

export interface AuthenticationProviderDescriptor {
  readonly providerId: AuthenticationProviderId;
  readonly kind: AuthenticationProviderKind;
  readonly displayName: string;
  readonly status: AuthenticationProviderStatus;
  readonly availability: AuthenticationProviderAvailability;
  readonly assurance: readonly AuthenticationProviderAssurance[];
  readonly capabilities: AuthenticationProviderCapabilities;
  readonly platform?: RuntimePlatform;
  readonly deviceIdentityProviderKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthenticationProviderRequirement {
  readonly providerKind?: AuthenticationProviderKind;
  readonly providerId?: AuthenticationProviderId;
  readonly minimumAssurance?: readonly AuthenticationProviderAssurance[];
  readonly userPresenceRequired?: boolean;
  readonly userVerificationRequired?: boolean;
  readonly hardwareBackedRequired?: boolean;
  readonly phishingResistantRequired?: boolean;
  readonly recoveryCeremonyRequired?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthenticationProviderRequestContext {
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: UserSessionLifecycleEvent;
  readonly ownerCommitment?: Hex;
  readonly applicationId?: ApplicationId;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly requestedAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthenticationProvider {
  readonly descriptor: AuthenticationProviderDescriptor;
}

export type ProductionAuthenticationRequestId = string;

export type ProductionAuthenticationPurpose =
  | "session_unlock"
  | "session_resume"
  | "high_risk_action"
  | "credential_rotation"
  | "credential_revocation"
  | "backup_export"
  | "recovery_approval"
  | "canonical_phil_activation"
  | "unsupported";

export interface ProductionAuthenticationChallengeReference {
  readonly challengeReferenceId: string;
  readonly challengeBindingHash?: Hex | string;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly generatedChallenge: false;
}

export interface ProductionAuthenticationCorrelation {
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: UserSessionLifecycleEvent;
  readonly ownerCommitment?: Hex;
  readonly applicationId?: ApplicationId;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerId?: AuthenticationProviderId;
  readonly auditCorrelationId?: string;
}

export interface ProductionAuthenticationRequirement {
  readonly purpose: ProductionAuthenticationPurpose;
  readonly provider: AuthenticationProviderRequirement;
  readonly challengeReference: ProductionAuthenticationChallengeReference;
  readonly correlation: ProductionAuthenticationCorrelation;
  readonly expiresAt?: string;
  readonly requestedAssurance?: readonly AuthenticationProviderAssurance[];
}

export interface ProductionAuthenticationRequest {
  readonly requestId: ProductionAuthenticationRequestId;
  readonly purpose: ProductionAuthenticationPurpose;
  readonly providerId: AuthenticationProviderId;
  readonly providerKind: AuthenticationProviderKind;
  readonly requirement: ProductionAuthenticationRequirement;
  readonly challengeReference: ProductionAuthenticationChallengeReference;
  readonly correlation: ProductionAuthenticationCorrelation;
  readonly requestedAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly invokesProvider: false;
  readonly authenticatesUser: false;
  readonly unlocksVault: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type ProductionAuthenticationEvidenceId = string;

export type ProductionAuthenticationEvidenceStatus =
  | "evidence_bounded"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "expired"
  | "stale"
  | "pending_verification";

export type ProductionAuthenticationEvidenceOutcome =
  | "evidence_present"
  | "evidence_missing"
  | "evidence_malformed"
  | "evidence_expired"
  | "evidence_replayed"
  | "provider_unsupported"
  | "provider_unavailable"
  | "challenge_mismatch"
  | "correlation_mismatch"
  | "assurance_insufficient"
  | "verification_pending";

export type ProductionAuthenticationEvidenceReason =
  | "provider-specific-response-represented"
  | "future-verification-required"
  | "request-shape-valid"
  | "evidence-shape-valid"
  | "request-expired"
  | "evidence-expired"
  | "evidence-stale"
  | "challenge-reference-mismatch"
  | "correlation-mismatch"
  | "assurance-insufficient"
  | "provider-unsupported"
  | "provider-unavailable"
  | "secret-shaped-metadata-not-allowed"
  | "raw-evidence-material-not-allowed"
  | (string & {});

export interface ProductionAuthenticationEvidenceSource {
  readonly providerId: AuthenticationProviderId;
  readonly providerKind: AuthenticationProviderKind;
  readonly fixtureOnly: boolean;
  readonly productionAuthentication: false;
  readonly platform?: RuntimePlatform;
}

export interface ProductionAuthenticationEvidenceLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface ProductionAuthenticationEvidenceBinding {
  readonly requestId: ProductionAuthenticationRequestId;
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: UserSessionLifecycleEvent;
  readonly ownerCommitment?: Hex;
  readonly applicationId?: ApplicationId;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerId: AuthenticationProviderId;
  readonly challengeReferenceId: string;
  readonly auditCorrelationId?: string;
}

export interface ProductionAuthenticationEvidenceFreshness {
  readonly collectedAt?: string;
  readonly expiresAt?: string;
  readonly maxAgeMs?: number;
  readonly staleAfter?: string;
}

export interface ProductionAuthenticationEvidenceAssurance {
  readonly provided: readonly AuthenticationProviderAssurance[];
  readonly required?: readonly AuthenticationProviderAssurance[];
  readonly sufficient: boolean;
}

export interface WebAuthnAuthenticationEvidenceReference {
  readonly kind: "webauthn";
  readonly credentialId: string;
  readonly authenticatorDataReference?: string;
  readonly clientDataHashReference?: string;
  readonly signatureReference?: string;
  readonly signCounter?: number;
  readonly userPresent?: boolean;
  readonly userVerified?: boolean;
  readonly origin?: string;
  readonly rpId?: string;
  readonly challengeBindingReference: string;
}

export interface PlatformBiometricAuthenticationEvidenceReference {
  readonly kind: "platform_biometric";
  readonly platformEvaluationReference: string;
  readonly userPresenceReference?: string;
  readonly secureHardwareReference?: string;
  readonly evaluatedAt?: string;
  readonly platformProviderId: string;
}

export interface HardwareKeyAuthenticationEvidenceReference {
  readonly kind: "hardware_key";
  readonly credentialId: string;
  readonly assertionReference?: string;
  readonly signatureReference?: string;
  readonly challengeReferenceId: string;
  readonly userPresenceReference?: string;
  readonly deviceProviderId?: string;
}

export interface RecoveryCredentialAuthenticationEvidenceReference {
  readonly kind: "recovery_credential";
  readonly recoveryCredentialId: string;
  readonly recoveryModeReference?: string;
  readonly recoveryCeremonyReference?: string;
  readonly requiredDelayReference?: string;
  readonly additionalFactorRequirements?: readonly AuthenticationProviderRequirement[];
}

export type ProviderSpecificAuthenticationEvidenceReference =
  | WebAuthnAuthenticationEvidenceReference
  | PlatformBiometricAuthenticationEvidenceReference
  | HardwareKeyAuthenticationEvidenceReference
  | RecoveryCredentialAuthenticationEvidenceReference;

export interface ProductionAuthenticationEvidence {
  readonly evidenceId: ProductionAuthenticationEvidenceId;
  readonly requestId: ProductionAuthenticationRequestId;
  readonly status: ProductionAuthenticationEvidenceStatus;
  readonly outcome: ProductionAuthenticationEvidenceOutcome;
  readonly reasons: readonly ProductionAuthenticationEvidenceReason[];
  readonly source: ProductionAuthenticationEvidenceSource;
  readonly binding: ProductionAuthenticationEvidenceBinding;
  readonly freshness: ProductionAuthenticationEvidenceFreshness;
  readonly assurance: ProductionAuthenticationEvidenceAssurance;
  readonly providerEvidence?: ProviderSpecificAuthenticationEvidenceReference;
  readonly limitations: readonly ProductionAuthenticationEvidenceLimitation[];
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly createdAt: string;
  readonly verifiesEvidence: false;
  readonly authenticatesUser: false;
  readonly trusted: false;
  readonly approved: false;
  readonly authorized: false;
  readonly unlocksVault: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type ProductionAuthenticationRequestResult =
  RuntimeResult<ProductionAuthenticationRequest>;

export type ProductionAuthenticationEvidenceResult =
  RuntimeResult<ProductionAuthenticationEvidence>;

export interface AuthenticationProviderAdapterRequest {
  readonly request: ProductionAuthenticationRequest;
  readonly providerResponseReference?: ProviderSpecificAuthenticationEvidenceReference;
  readonly collectedAt?: string;
  readonly expiresAt?: string;
  readonly providedAssurance?: readonly AuthenticationProviderAssurance[];
  readonly outcome?: ProductionAuthenticationEvidenceOutcome;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthenticationProviderAdapterResult<TValue = unknown> {
  readonly status: "ok" | "unavailable" | "unsupported" | "invalid";
  readonly value?: TValue;
  readonly error?: AuthenticationProviderAdapterError;
}

export interface AuthenticationProviderAdapterError {
  readonly code: string;
  readonly message: string;
  readonly providerId?: AuthenticationProviderId;
  readonly providerKind?: AuthenticationProviderKind;
  readonly recoverable: boolean;
}

export interface AuthenticationProviderAdapterAvailabilityResult {
  readonly providerId: AuthenticationProviderId;
  readonly providerKind: AuthenticationProviderKind;
  readonly availability: AuthenticationProviderAvailability;
  readonly status: AuthenticationProviderStatus;
  readonly reason?: string;
  readonly fixtureOnly: boolean;
  readonly productionAuthentication: false;
}

export interface AuthenticationProviderAdapter {
  describeProvider(): AuthenticationProviderDescriptor;
  checkAvailability(
    context?: AuthenticationProviderRequestContext
  ): AuthenticationProviderAdapterAvailabilityResult;
  createAuthenticationRequest(
    requirement: ProductionAuthenticationRequirement
  ): ProductionAuthenticationRequestResult;
  normalizeEvidence(
    request: AuthenticationProviderAdapterRequest
  ): ProductionAuthenticationEvidenceResult;
  validateEvidenceShape(evidence: unknown): RuntimeValidationResult;
}

export interface SessionLifecycleAuthenticationEvidenceReference {
  readonly referenceId: string;
  readonly evidenceId: ProductionAuthenticationEvidenceId;
  readonly requestId: ProductionAuthenticationRequestId;
  readonly sessionId: string;
  readonly lifecycleTransitionRequestId?: string;
  readonly lifecycleEvent?: UserSessionLifecycleEvent;
  readonly evidenceKind: UserSessionEvidenceReferenceKind;
  readonly verificationPending: true;
  readonly verified: false;
  readonly rawEvidenceIncluded: false;
}

export interface SessionLifecycleAuthenticationRequirement {
  readonly lifecycleEvent: UserSessionLifecycleEvent;
  readonly purpose: ProductionAuthenticationPurpose;
  readonly requiredEvidenceKind: UserSessionEvidenceReferenceKind;
  readonly providerRequirement: AuthenticationProviderRequirement;
  readonly verificationRequiredLater: true;
}

export interface SessionLifecycleEvidenceValidationResult {
  readonly valid: boolean;
  readonly reference?: SessionLifecycleAuthenticationEvidenceReference;
  readonly lifecycleEvidenceReference?: UserSessionLifecycleEvidenceReference;
  readonly errors: readonly string[];
  readonly permitsLifecycleTransition: false;
}

export interface DeveloperFixtureAuthenticationProviderAdapterOptions {
  readonly providerId?: AuthenticationProviderId;
  readonly displayName?: string;
  readonly availability?: AuthenticationProviderAvailability;
  readonly assurance?: readonly AuthenticationProviderAssurance[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

const AUTHENTICATION_PROVIDER_KINDS = new Set<AuthenticationProviderKind>([
  "webauthn_passkey",
  "platform_biometric",
  "hardware_security_key",
  "device_signature",
  "local_pin",
  "recovery_credential",
  "developer_fixture",
  "unsupported"
]);

const AUTHENTICATION_PROVIDER_STATUSES = new Set<AuthenticationProviderStatus>([
  "available",
  "unavailable",
  "unsupported",
  "disabled",
  "fixture_only"
]);

const AUTHENTICATION_PROVIDER_AVAILABILITIES = new Set<AuthenticationProviderAvailability>([
  "available",
  "unavailable",
  "unsupported",
  "requires_platform_setup",
  "fixture_only"
]);

const AUTHENTICATION_PROVIDER_ASSURANCES = new Set<AuthenticationProviderAssurance>([
  "none",
  "user_presence",
  "user_verification",
  "hardware_backed",
  "phishing_resistant",
  "recovery_ceremony",
  "developer_fixture"
]);

const PRODUCTION_AUTHENTICATION_PURPOSES = new Set<ProductionAuthenticationPurpose>([
  "session_unlock",
  "session_resume",
  "high_risk_action",
  "credential_rotation",
  "credential_revocation",
  "backup_export",
  "recovery_approval",
  "canonical_phil_activation",
  "unsupported"
]);

const PRODUCTION_AUTHENTICATION_EVIDENCE_STATUSES =
  new Set<ProductionAuthenticationEvidenceStatus>([
    "evidence_bounded",
    "validation_failed",
    "malformed",
    "unsupported",
    "expired",
    "stale",
    "pending_verification"
  ]);

const PRODUCTION_AUTHENTICATION_EVIDENCE_OUTCOMES =
  new Set<ProductionAuthenticationEvidenceOutcome>([
    "evidence_present",
    "evidence_missing",
    "evidence_malformed",
    "evidence_expired",
    "evidence_replayed",
    "provider_unsupported",
    "provider_unavailable",
    "challenge_mismatch",
    "correlation_mismatch",
    "assurance_insufficient",
    "verification_pending"
  ]);

const RAW_OR_AUTHORITY_FIELD_NAMES = new Set([
  "assertion",
  "authenticatordata",
  "biometrictemplate",
  "clientdatajson",
  "credentialprivatekey",
  "evidencepayload",
  "philsecret",
  "privatekey",
  "rawevidence",
  "rawsignature",
  "rawvaultkey",
  "recoverysecret",
  "seedphrase",
  "sessionkey",
  "signature",
  "signingkey",
  "vaultkey",
  "webauthnassertion",
  "worldidproof",
  "authorizationpackage",
  "capabilitygrant",
  "authoritytoken"
]);

const DEFAULT_EVIDENCE_LIMITATIONS: readonly ProductionAuthenticationEvidenceLimitation[] =
  Object.freeze([
    Object.freeze({
      limitationId: "future_verification_required",
      description: "Evidence is bounded for future verification and is not verified here."
    }),
    Object.freeze({
      limitationId: "not_authentication",
      description: "Evidence presence is not a production authentication outcome."
    }),
    Object.freeze({
      limitationId: "no_lifecycle_transition",
      description: "Provider adapters cannot mutate User Session lifecycle state."
    }),
    Object.freeze({
      limitationId: "no_authority",
      description: "Evidence artifacts do not grant capabilities or authorization."
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
    if (RAW_OR_AUTHORITY_FIELD_NAMES.has(normalizeFieldName(key)) && entry !== false) {
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

function blockedFieldErrors(input: unknown): readonly string[] {
  return findBlockedFields(input).map(
    (field) => `raw evidence, secret, or authority field is not allowed: ${field}`
  );
}

function malformedError(code: string, message: string, errors: readonly string[]): RuntimeErrorDescriptor {
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

function assuranceSufficient(
  provided: readonly AuthenticationProviderAssurance[] = [],
  required: readonly AuthenticationProviderAssurance[] = []
): boolean {
  return required.every((assurance) => provided.includes(assurance));
}

function sanitizeMetadata(
  metadata: Readonly<Record<string, unknown>> | undefined
): Readonly<Record<string, unknown>> | undefined {
  return metadata
    ? freezeRecord(redactRuntimeMetadata(metadata).value)
    : undefined;
}

function expired(expiresAt: string | undefined): boolean {
  return expiresAt !== undefined && Date.parse(expiresAt) <= Date.now();
}

function stale(freshness: ProductionAuthenticationEvidenceFreshness): boolean {
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

export function isAuthenticationProviderKind(
  value: unknown
): value is AuthenticationProviderKind {
  return AUTHENTICATION_PROVIDER_KINDS.has(value as AuthenticationProviderKind);
}

export function isProductionAuthenticationEvidenceStatus(
  value: unknown
): value is ProductionAuthenticationEvidenceStatus {
  return PRODUCTION_AUTHENTICATION_EVIDENCE_STATUSES.has(
    value as ProductionAuthenticationEvidenceStatus
  );
}

export function validateAuthenticationProviderDescriptor(
  descriptor: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(descriptor)) {
    return validation(["authentication provider descriptor must be an object"]);
  }
  if (!isNonEmptyString(descriptor.providerId)) {
    errors.push("providerId is required");
  }
  if (!AUTHENTICATION_PROVIDER_KINDS.has(descriptor.kind as AuthenticationProviderKind)) {
    errors.push("provider kind is invalid");
  }
  if (!isNonEmptyString(descriptor.displayName)) {
    errors.push("displayName is required");
  }
  if (!AUTHENTICATION_PROVIDER_STATUSES.has(descriptor.status as AuthenticationProviderStatus)) {
    errors.push("provider status is invalid");
  }
  if (
    !AUTHENTICATION_PROVIDER_AVAILABILITIES.has(
      descriptor.availability as AuthenticationProviderAvailability
    )
  ) {
    errors.push("provider availability is invalid");
  }
  if (!Array.isArray(descriptor.assurance)) {
    errors.push("assurance must be an array");
  } else if (
    !descriptor.assurance.every((assurance) => AUTHENTICATION_PROVIDER_ASSURANCES.has(assurance))
  ) {
    errors.push("assurance contains an invalid value");
  }
  if (!isRecord(descriptor.capabilities)) {
    errors.push("capabilities are required");
  }
  errors.push(...secretValidationErrors(descriptor.metadata));
  errors.push(...blockedFieldErrors(descriptor.metadata));
  return validation(errors);
}

export function validateProductionAuthenticationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["production authentication request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }
  if (!PRODUCTION_AUTHENTICATION_PURPOSES.has(request.purpose as ProductionAuthenticationPurpose)) {
    errors.push("purpose is invalid");
  }
  if (!isNonEmptyString(request.providerId)) {
    errors.push("providerId is required");
  }
  if (!AUTHENTICATION_PROVIDER_KINDS.has(request.providerKind as AuthenticationProviderKind)) {
    errors.push("providerKind is invalid");
  }
  if (!isRecord(request.challengeReference)) {
    errors.push("challengeReference is required");
  } else {
    if (!isNonEmptyString(request.challengeReference.challengeReferenceId)) {
      errors.push("challengeReference.challengeReferenceId is required");
    }
    if (request.challengeReference.generatedChallenge !== false) {
      errors.push("challengeReference.generatedChallenge must be false");
    }
    if (
      request.challengeReference.createdAt !== undefined
      && !hasValidDateShape(request.challengeReference.createdAt)
    ) {
      errors.push("challengeReference.createdAt must be a parseable date string");
    }
    if (
      request.challengeReference.expiresAt !== undefined
      && !hasValidDateShape(request.challengeReference.expiresAt)
    ) {
      errors.push("challengeReference.expiresAt must be a parseable date string");
    }
  }
  if (!isRecord(request.correlation)) {
    errors.push("correlation is required");
  } else {
    if (!isNonEmptyString(request.correlation.sessionId)) {
      errors.push("correlation.sessionId is required");
    }
  }
  if (!hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (request.invokesProvider !== false) {
    errors.push("invokesProvider must be false");
  }
  if (request.authenticatesUser !== false) {
    errors.push("authenticatesUser must be false");
  }
  if (request.unlocksVault !== false) {
    errors.push("unlocksVault must be false");
  }
  if (request.grantsAuthority !== false) {
    errors.push("grantsAuthority must be false");
  }
  if (request.persisted !== false) {
    errors.push("persisted must be false");
  }
  errors.push(...secretValidationErrors(request.metadata));
  errors.push(...blockedFieldErrors(request));
  return validation(errors);
}

export function validateProductionAuthenticationEvidenceShape(
  evidence: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(evidence)) {
    return validation(["production authentication evidence must be an object"]);
  }
  if (!isNonEmptyString(evidence.evidenceId)) {
    errors.push("evidenceId is required");
  }
  if (!isNonEmptyString(evidence.requestId)) {
    errors.push("requestId is required");
  }
  if (!PRODUCTION_AUTHENTICATION_EVIDENCE_STATUSES.has(
    evidence.status as ProductionAuthenticationEvidenceStatus
  )) {
    errors.push("status is invalid");
  }
  if (!PRODUCTION_AUTHENTICATION_EVIDENCE_OUTCOMES.has(
    evidence.outcome as ProductionAuthenticationEvidenceOutcome
  )) {
    errors.push("outcome is invalid");
  }
  if (!isRecord(evidence.source)) {
    errors.push("source is required");
  } else {
    if (!isNonEmptyString(evidence.source.providerId)) {
      errors.push("source.providerId is required");
    }
    if (!AUTHENTICATION_PROVIDER_KINDS.has(evidence.source.providerKind as AuthenticationProviderKind)) {
      errors.push("source.providerKind is invalid");
    }
    if (evidence.source.productionAuthentication !== false) {
      errors.push("source.productionAuthentication must be false");
    }
  }
  if (!isRecord(evidence.binding)) {
    errors.push("binding is required");
  } else {
    if (!isNonEmptyString(evidence.binding.requestId)) errors.push("binding.requestId is required");
    if (!isNonEmptyString(evidence.binding.sessionId)) errors.push("binding.sessionId is required");
    if (!isNonEmptyString(evidence.binding.providerId)) errors.push("binding.providerId is required");
    if (!isNonEmptyString(evidence.binding.challengeReferenceId)) {
      errors.push("binding.challengeReferenceId is required");
    }
  }
  if (!isRecord(evidence.freshness)) {
    errors.push("freshness is required");
  } else {
    if (evidence.freshness.collectedAt !== undefined && !hasValidDateShape(evidence.freshness.collectedAt)) {
      errors.push("freshness.collectedAt must be a parseable date string");
    }
    if (evidence.freshness.expiresAt !== undefined && !hasValidDateShape(evidence.freshness.expiresAt)) {
      errors.push("freshness.expiresAt must be a parseable date string");
    }
    if (evidence.freshness.staleAfter !== undefined && !hasValidDateShape(evidence.freshness.staleAfter)) {
      errors.push("freshness.staleAfter must be a parseable date string");
    }
  }
  if (!isRecord(evidence.assurance)) {
    errors.push("assurance is required");
  } else if (!Array.isArray(evidence.assurance.provided)) {
    errors.push("assurance.provided must be an array");
  }
  if (evidence.verifiesEvidence !== false) errors.push("verifiesEvidence must be false");
  if (evidence.authenticatesUser !== false) errors.push("authenticatesUser must be false");
  if (evidence.trusted !== false) errors.push("trusted must be false");
  if (evidence.approved !== false) errors.push("approved must be false");
  if (evidence.authorized !== false) errors.push("authorized must be false");
  if (evidence.unlocksVault !== false) errors.push("unlocksVault must be false");
  if (evidence.grantsAuthority !== false) errors.push("grantsAuthority must be false");
  if (evidence.persisted !== false) errors.push("persisted must be false");
  errors.push(...secretValidationErrors(evidence.metadata));
  errors.push(...blockedFieldErrors(evidence));
  return validation(errors);
}

export function validateAuthenticationEvidenceCorrelation(
  request: ProductionAuthenticationRequest,
  evidence: ProductionAuthenticationEvidence
): RuntimeValidationResult {
  const errors: string[] = [];
  if (evidence.requestId !== request.requestId || evidence.binding.requestId !== request.requestId) {
    errors.push("requestId correlation mismatch");
  }
  if (evidence.binding.sessionId !== request.correlation.sessionId) {
    errors.push("sessionId correlation mismatch");
  }
  if (
    request.correlation.lifecycleTransitionRequestId !== undefined
    && evidence.binding.lifecycleTransitionRequestId !== request.correlation.lifecycleTransitionRequestId
  ) {
    errors.push("lifecycleTransitionRequestId correlation mismatch");
  }
  if (
    request.correlation.ownerCommitment !== undefined
    && evidence.binding.ownerCommitment !== request.correlation.ownerCommitment
  ) {
    errors.push("ownerCommitment correlation mismatch");
  }
  if (
    request.correlation.applicationId !== undefined
    && evidence.binding.applicationId !== request.correlation.applicationId
  ) {
    errors.push("applicationId correlation mismatch");
  }
  if (
    request.correlation.credentialId !== undefined
    && evidence.binding.credentialId !== request.correlation.credentialId
  ) {
    errors.push("credentialId correlation mismatch");
  }
  if (
    request.correlation.deviceId !== undefined
    && evidence.binding.deviceId !== request.correlation.deviceId
  ) {
    errors.push("deviceId correlation mismatch");
  }
  if (evidence.binding.providerId !== request.providerId) {
    errors.push("providerId correlation mismatch");
  }
  if (evidence.binding.challengeReferenceId !== request.challengeReference.challengeReferenceId) {
    errors.push("challengeReferenceId correlation mismatch");
  }
  return validation(errors);
}

export function validateAuthenticationEvidenceFreshness(
  evidence: ProductionAuthenticationEvidence
): RuntimeValidationResult {
  const errors: string[] = [];
  if (expired(evidence.freshness.expiresAt)) {
    errors.push("evidence is expired");
  }
  if (stale(evidence.freshness)) {
    errors.push("evidence is stale");
  }
  return validation(errors);
}

export function validateAuthenticationEvidenceAssurance(
  evidence: ProductionAuthenticationEvidence,
  required: readonly AuthenticationProviderAssurance[] = []
): RuntimeValidationResult {
  if (assuranceSufficient(evidence.assurance.provided, required)) {
    return validation([]);
  }
  return validation(["evidence assurance is insufficient"]);
}

export function createProductionAuthenticationRequest(
  input: {
    readonly requestId: ProductionAuthenticationRequestId;
    readonly purpose: ProductionAuthenticationPurpose;
    readonly providerId: AuthenticationProviderId;
    readonly providerKind: AuthenticationProviderKind;
    readonly requirement: ProductionAuthenticationRequirement;
    readonly requestedAt?: string;
    readonly expiresAt?: string;
    readonly metadata?: Readonly<Record<string, unknown>>;
  }
): ProductionAuthenticationRequestResult {
  const requestedAt = input.requestedAt ?? new Date().toISOString();
  const auditCorrelationId = input.requirement.correlation.auditCorrelationId ?? createAuditCorrelationId([
    input.requirement.correlation.sessionId,
    input.requestId,
    input.purpose,
    "production-authentication-request"
  ]);
  const request: ProductionAuthenticationRequest = freezeRecord({
    requestId: input.requestId,
    purpose: input.purpose,
    providerId: input.providerId,
    providerKind: input.providerKind,
    requirement: input.requirement,
    challengeReference: input.requirement.challengeReference,
    correlation: {
      ...input.requirement.correlation,
      providerId: input.providerId,
      auditCorrelationId
    },
    requestedAt,
    expiresAt: input.expiresAt ?? input.requirement.expiresAt,
    auditCorrelationId,
    metadata: sanitizeMetadata(input.metadata),
    invokesProvider: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false,
    persisted: false
  });
  const validationResult = validateProductionAuthenticationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedError(
      "PRODUCTION_AUTHENTICATION_REQUEST_INVALID",
      "production authentication request failed shape validation",
      validationResult.errors
    ));
  }
  return runtimeOk(request);
}

function outcomeForEvidence(
  request: ProductionAuthenticationRequest,
  evidence: ProductionAuthenticationEvidence
): ProductionAuthenticationEvidenceOutcome {
  const correlation = validateAuthenticationEvidenceCorrelation(request, evidence);
  if (!correlation.valid) {
    if (correlation.errors.some((error) => error.includes("challengeReferenceId"))) {
      return "challenge_mismatch";
    }
    return "correlation_mismatch";
  }
  const freshness = validateAuthenticationEvidenceFreshness(evidence);
  if (!freshness.valid) {
    if (freshness.errors.some((error) => error.includes("expired"))) {
      return "evidence_expired";
    }
    return "evidence_replayed";
  }
  const requiredAssurance = request.requirement.requestedAssurance ?? [];
  if (!assuranceSufficient(evidence.assurance.provided, requiredAssurance)) {
    return "assurance_insufficient";
  }
  return "verification_pending";
}

function statusForOutcome(
  outcome: ProductionAuthenticationEvidenceOutcome
): ProductionAuthenticationEvidenceStatus {
  if (outcome === "evidence_expired") return "expired";
  if (outcome === "evidence_replayed") return "stale";
  if (outcome === "provider_unsupported") return "unsupported";
  if (outcome === "evidence_malformed") return "malformed";
  if (
    outcome === "correlation_mismatch"
    || outcome === "challenge_mismatch"
    || outcome === "assurance_insufficient"
  ) return "validation_failed";
  if (outcome === "verification_pending") return "pending_verification";
  return "evidence_bounded";
}

function reasonsForOutcome(
  outcome: ProductionAuthenticationEvidenceOutcome
): readonly ProductionAuthenticationEvidenceReason[] {
  const base: ProductionAuthenticationEvidenceReason[] = [
    "provider-specific-response-represented",
    "future-verification-required"
  ];
  if (outcome === "challenge_mismatch") base.push("challenge-reference-mismatch");
  if (outcome === "correlation_mismatch") base.push("correlation-mismatch");
  if (outcome === "assurance_insufficient") base.push("assurance-insufficient");
  if (outcome === "evidence_expired") base.push("evidence-expired");
  if (outcome === "evidence_replayed") base.push("evidence-stale");
  if (outcome === "provider_unsupported") base.push("provider-unsupported");
  if (outcome === "provider_unavailable") base.push("provider-unavailable");
  return Object.freeze(base);
}

export function createProductionAuthenticationEvidence(
  input: {
    readonly request: ProductionAuthenticationRequest;
    readonly source: ProductionAuthenticationEvidenceSource;
    readonly providerEvidence?: ProviderSpecificAuthenticationEvidenceReference;
    readonly collectedAt?: string;
    readonly expiresAt?: string;
    readonly staleAfter?: string;
    readonly maxAgeMs?: number;
    readonly providedAssurance?: readonly AuthenticationProviderAssurance[];
    readonly outcome?: ProductionAuthenticationEvidenceOutcome;
    readonly metadata?: Readonly<Record<string, unknown>>;
  }
): ProductionAuthenticationEvidenceResult {
  const collectedAt = input.collectedAt ?? new Date().toISOString();
  const requiredAssurance = input.request.requirement.requestedAssurance ?? [];
  const binding: ProductionAuthenticationEvidenceBinding = freezeRecord({
    requestId: input.request.requestId,
    sessionId: input.request.correlation.sessionId,
    lifecycleTransitionRequestId: input.request.correlation.lifecycleTransitionRequestId,
    lifecycleEvent: input.request.correlation.lifecycleEvent,
    ownerCommitment: input.request.correlation.ownerCommitment,
    applicationId: input.request.correlation.applicationId,
    credentialId: input.request.correlation.credentialId,
    deviceId: input.request.correlation.deviceId,
    providerId: input.request.providerId,
    challengeReferenceId: input.request.challengeReference.challengeReferenceId,
    auditCorrelationId: input.request.auditCorrelationId
  });
  const providedAssurance = Object.freeze([...(input.providedAssurance ?? [])]);
  const draftEvidence: ProductionAuthenticationEvidence = freezeRecord({
    evidenceId: `${input.request.auditCorrelationId}:evidence`,
    requestId: input.request.requestId,
    status: "pending_verification",
    outcome: input.outcome ?? "verification_pending",
    reasons: [],
    source: {
      ...input.source,
      productionAuthentication: false
    },
    binding,
    freshness: {
      collectedAt,
      expiresAt: input.expiresAt,
      staleAfter: input.staleAfter,
      maxAgeMs: input.maxAgeMs
    },
    assurance: {
      provided: providedAssurance,
      required: requiredAssurance,
      sufficient: assuranceSufficient(providedAssurance, requiredAssurance)
    },
    providerEvidence: input.providerEvidence ? freezeRecord(input.providerEvidence) : undefined,
    limitations: DEFAULT_EVIDENCE_LIMITATIONS,
    auditCorrelationId: input.request.auditCorrelationId,
    metadata: sanitizeMetadata(input.metadata),
    createdAt: collectedAt,
    verifiesEvidence: false,
    authenticatesUser: false,
    trusted: false,
    approved: false,
    authorized: false,
    unlocksVault: false,
    grantsAuthority: false,
    persisted: false
  });
  const outcome = input.outcome ?? outcomeForEvidence(input.request, draftEvidence);
  const evidence: ProductionAuthenticationEvidence = freezeRecord({
    ...draftEvidence,
    status: statusForOutcome(outcome),
    outcome,
    reasons: reasonsForOutcome(outcome)
  });
  const validationResult = validateProductionAuthenticationEvidenceShape(evidence);
  if (!validationResult.valid) {
    return runtimeDenied(malformedError(
      "PRODUCTION_AUTHENTICATION_EVIDENCE_INVALID",
      "production authentication evidence failed shape validation",
      validationResult.errors
    ));
  }
  return runtimeOk(evidence);
}

export function createSessionLifecycleAuthenticationEvidenceReference(
  evidence: ProductionAuthenticationEvidence
): SessionLifecycleEvidenceValidationResult {
  const evidenceValidation = validateProductionAuthenticationEvidenceShape(evidence);
  if (!evidenceValidation.valid) {
    return {
      valid: false,
      errors: evidenceValidation.errors,
      permitsLifecycleTransition: false
    };
  }
  const reference: SessionLifecycleAuthenticationEvidenceReference = freezeRecord({
    referenceId: `${evidence.evidenceId}:lifecycle-reference`,
    evidenceId: evidence.evidenceId,
    requestId: evidence.requestId,
    sessionId: evidence.binding.sessionId,
    lifecycleTransitionRequestId: evidence.binding.lifecycleTransitionRequestId,
    lifecycleEvent: evidence.binding.lifecycleEvent,
    evidenceKind: "authentication_evidence",
    verificationPending: true,
    verified: false,
    rawEvidenceIncluded: false
  });
  const lifecycleEvidenceReference: UserSessionLifecycleEvidenceReference = freezeRecord({
    referenceId: reference.referenceId,
    kind: "authentication_evidence",
    source: evidence.source.providerKind,
    capturedAt: evidence.createdAt,
    metadata: {
      evidenceId: evidence.evidenceId,
      requestId: evidence.requestId,
      outcome: evidence.outcome,
      verificationPending: true
    },
    verified: false,
    rawEvidenceIncluded: false
  });
  return {
    valid: true,
    reference,
    lifecycleEvidenceReference,
    errors: [],
    permitsLifecycleTransition: false
  };
}

export function createDeveloperFixtureAuthenticationProviderAdapter(
  options: DeveloperFixtureAuthenticationProviderAdapterOptions = {}
): AuthenticationProviderAdapter {
  const descriptor: AuthenticationProviderDescriptor = freezeRecord({
    providerId: options.providerId ?? "developer-fixture-authentication-provider",
    kind: "developer_fixture",
    displayName: options.displayName ?? "Developer Fixture Authentication Provider",
    status: "fixture_only",
    availability: options.availability ?? "fixture_only",
    assurance: options.assurance ?? ["developer_fixture", "user_presence"],
    capabilities: {
      supportsSessionUnlock: true,
      supportsSessionResume: true,
      supportsHighRiskAction: true,
      supportsCredentialLifecycle: true,
      supportsRecovery: true,
      supportsChallengeBinding: true,
      fixtureOnly: true,
      productionAuthentication: false
    },
    platform: "local-dev",
    metadata: sanitizeMetadata(options.metadata)
  });

  return {
    describeProvider() {
      return descriptor;
    },
    checkAvailability() {
      return freezeRecord({
        providerId: descriptor.providerId,
        providerKind: descriptor.kind,
        availability: descriptor.availability,
        status: descriptor.status,
        reason: "Developer fixture provider is available only for explicit local test inputs.",
        fixtureOnly: true,
        productionAuthentication: false
      });
    },
    createAuthenticationRequest(requirement) {
      return createProductionAuthenticationRequest({
        requestId: `${requirement.correlation.sessionId}:${requirement.purpose}:fixture-request`,
        purpose: requirement.purpose,
        providerId: descriptor.providerId,
        providerKind: descriptor.kind,
        requirement,
        expiresAt: requirement.expiresAt,
        metadata: {
          fixtureOnly: true
        }
      });
    },
    normalizeEvidence(request) {
      const requestValidation = validateProductionAuthenticationRequest(request.request);
      if (!requestValidation.valid) {
        return runtimeDenied(malformedError(
          "DEVELOPER_FIXTURE_AUTHENTICATION_REQUEST_INVALID",
          "developer fixture authentication request failed validation",
          requestValidation.errors
        ));
      }
      return createProductionAuthenticationEvidence({
        request: request.request,
        source: {
          providerId: descriptor.providerId,
          providerKind: descriptor.kind,
          fixtureOnly: true,
          productionAuthentication: false,
          platform: "local-dev"
        },
        providerEvidence: request.providerResponseReference,
        collectedAt: request.collectedAt,
        expiresAt: request.expiresAt,
        providedAssurance: request.providedAssurance ?? descriptor.assurance,
        outcome: request.outcome,
        metadata: {
          ...(request.metadata ?? {}),
          fixtureOnly: true,
          productionAuthentication: false
        }
      });
    },
    validateEvidenceShape(evidence) {
      return validateProductionAuthenticationEvidenceShape(evidence);
    }
  };
}
