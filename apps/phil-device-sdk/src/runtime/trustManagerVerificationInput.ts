import type { Hex } from "../hashes.ts";
import { createAuditEventDraft, type AuditDraftCollectionResult, type AuditDraftCollector, type AuditEventDraft } from "./audit.ts";
import type {
  AuthenticationProviderAssurance,
  ProductionAuthenticationPurpose,
  ProductionAuthenticationRequest
} from "./authenticationEvidence.ts";
import { validateProductionAuthenticationRequest } from "./authenticationEvidence.ts";
import { createAuditCorrelationId, runtimeDenied, runtimeOk, type RuntimeValidationResult } from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  SelectedCredentialVerificationHandleMetadata,
  SelectedCredentialVerificationProfile,
  TrustManagerCredentialVerificationContext as SelectedCredentialTrustContext
} from "./selectedCredentialPublicMaterial.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext
} from "./types.ts";

export type TrustManagerVerificationInputStatus =
  | "verification_input_created"
  | "verification_input_rejected"
  | "verification_input_malformed"
  | "verification_input_expired"
  | "verification_input_unsupported";

export type TrustManagerVerificationInputOutcome =
  | "verification_input_created"
  | "profile_invalid"
  | "authentication_request_invalid"
  | "credential_ineligible"
  | "provider_mismatch"
  | "algorithm_mismatch"
  | "session_correlation_mismatch"
  | "owner_correlation_mismatch"
  | "application_correlation_mismatch"
  | "challenge_correlation_mismatch"
  | "purpose_correlation_mismatch"
  | "lifecycle_state_ineligible"
  | "assurance_requirement_unsupported"
  | "expired"
  | "malformed"
  | "unsupported";

export type TrustManagerVerificationInputReason =
  | "selected-credential-profile-used"
  | "explicit-production-authentication-request-used"
  | "session-correlation-valid"
  | "owner-correlation-valid"
  | "application-correlation-valid"
  | "challenge-correlation-valid"
  | "assurance-requirement-supported"
  | "no-authentication"
  | "no-webauthn-execution"
  | "no-signature-verification"
  | "no-trust-decision"
  | "no-vault-handle-exposed"
  | "no-registry-access"
  | "no-authority"
  | (string & {});

export interface TrustManagerVerificationInputCorrelation {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerId: string;
  readonly providerKind: "webauthn_passkey";
  readonly challengeReferenceId: string;
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly auditCorrelationId: string;
}

export interface TrustManagerVerificationInputRequirement {
  readonly requirementId: string;
  readonly satisfied: boolean;
  readonly description: string;
}

export interface TrustManagerVerificationInputLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface TrustManagerChallengeBinding {
  readonly challengeReferenceId: string;
  readonly challengeBindingHash?: Hex | string;
  readonly generatedChallenge: false;
  readonly createdAt?: string;
  readonly expiresAt?: string;
}

export interface TrustManagerAssuranceRequirement {
  readonly requiredAssurance: readonly AuthenticationProviderAssurance[];
  readonly supportedBySelectedCredential: readonly AuthenticationProviderAssurance[];
  readonly sufficient: boolean;
}

export interface TrustManagerVerificationInputContext {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerId: string;
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly verificationMethod: "webauthn_assertion";
  readonly publicMaterialOnly: true;
  readonly vaultHandleAvailableToTrustManager: false;
  readonly registryEnumerationAllowed: false;
  readonly trustDecisionDeferred: true;
}

export interface TrustManagerVerificationInput {
  readonly trustManagerVerificationInputId: string;
  readonly requestId: string;
  readonly verificationProfileId: string;
  readonly selectedCredentialHandleId: string;
  readonly credentialSafeReference: Hex;
  readonly providerKind: "webauthn_passkey";
  readonly providerId: string;
  readonly publicKeyAlgorithm: "ES256";
  readonly publicKeyFingerprint: Hex;
  readonly verificationKey: {
    readonly materialKind: "webauthn_spki_public_key_hex";
    readonly publicKey: Hex;
    readonly publicKeyFingerprint: Hex;
    readonly encoding: "hex";
    readonly containsPrivateMaterial: false;
  };
  readonly rpId?: string;
  readonly origin?: string;
  readonly challengeBinding: TrustManagerChallengeBinding;
  readonly userPresenceRequired: true;
  readonly userVerificationRequired: true;
  readonly publicCounter?: number;
  readonly lifecycleClassification: SelectedCredentialVerificationProfile["credentialLifecycleStatus"];
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly assuranceRequirement: TrustManagerAssuranceRequirement;
  readonly correlation: TrustManagerVerificationInputCorrelation;
  readonly credentialVerificationContext: TrustManagerVerificationInputContext;
  readonly selectedCredentialTrustContext: SelectedCredentialTrustContext;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly processLocal: true;
  readonly serializable: false;
  readonly verificationPerformed: false;
  readonly trustDecisionCreated: false;
  readonly authenticationPerformed: false;
  readonly webAuthnInvoked: false;
  readonly signatureVerified: false;
  readonly credentialCounterMutated: false;
  readonly grantsAuthority: false;
  readonly vaultHandleExposed: false;
  readonly registryAccessProvided: false;
  readonly privateMaterialIncluded: false;
  readonly rawAssertionPayloadIncluded: false;
  readonly rawRegistrationPayloadIncluded: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
}

export interface TrustManagerVerificationInputRequest {
  readonly requestId: string;
  readonly selectedCredentialVerificationProfile: SelectedCredentialVerificationProfile;
  readonly selectedCredentialVerificationHandle: SelectedCredentialVerificationHandleMetadata;
  readonly productionAuthenticationRequest: ProductionAuthenticationRequest;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly userSessionContext: UserSessionContext;
  readonly applicationId: ApplicationId;
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly providerId: string;
  readonly authenticationPurpose: ProductionAuthenticationPurpose;
  readonly challengeReferenceId: string;
  readonly requiredAssurance: readonly AuthenticationProviderAssurance[];
  readonly expiresAt?: string;
  readonly requestedAt?: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface TrustManagerVerificationInputResultValue {
  readonly trustManagerVerificationInputResultId: string;
  readonly requestId: string;
  readonly status: TrustManagerVerificationInputStatus;
  readonly outcome: TrustManagerVerificationInputOutcome;
  readonly verificationInput: TrustManagerVerificationInput;
  readonly requirements: readonly TrustManagerVerificationInputRequirement[];
  readonly limitations: readonly TrustManagerVerificationInputLimitation[];
  readonly reasons: readonly TrustManagerVerificationInputReason[];
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly verificationPerformed: false;
  readonly trustDecisionCreated: false;
  readonly authenticationPerformed: false;
  readonly grantsAuthority: false;
  readonly vaultHandleExposed: false;
  readonly registryAccessProvided: false;
  readonly privateMaterialIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly rawAssertionPayloadIncluded: false;
  readonly rawRegistrationPayloadIncluded: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type TrustManagerVerificationInputResult =
  RuntimeResult<TrustManagerVerificationInputResultValue>;

export interface TrustManagerVerificationInputConsumerResult {
  readonly status: "accepted" | "rejected";
  readonly inputId?: string;
  readonly errors: readonly string[];
  readonly trustDecisionCreated: false;
  readonly authenticationPerformed: false;
  readonly grantsAuthority: false;
  readonly vaultHandleAccessed: false;
  readonly registryEnumerated: false;
  readonly persisted: false;
}

export interface TrustManagerVerificationInputConsumer {
  acceptVerificationInput(
    input: TrustManagerVerificationInput
  ): TrustManagerVerificationInputConsumerResult;
}

const LIMITATIONS: readonly TrustManagerVerificationInputLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "input-only-boundary",
    description: "The bridge constructs a bounded Trust Manager input only; no verification or Trust Decision occurs."
  }),
  Object.freeze({
    limitationId: "no-vault-handle",
    description: "Trust Manager receives no Device Vault handle, registry, credential record, or vault access."
  }),
  Object.freeze({
    limitationId: "single-credential",
    description: "The input is bound to exactly one selected credential profile and handle."
  }),
  Object.freeze({
    limitationId: "process-local-expiring",
    description: "Inputs are process-local, expiry-bound, and invalidated by future lifecycle/handle invalidation."
  }),
  Object.freeze({
    limitationId: "no-authority",
    description: "Inputs do not grant capabilities, session keys, authorization, policy decisions, or adapter execution."
  })
]);

const STATUS_VALUES = new Set<TrustManagerVerificationInputStatus>([
  "verification_input_created",
  "verification_input_rejected",
  "verification_input_malformed",
  "verification_input_expired",
  "verification_input_unsupported"
]);

const OUTCOME_VALUES = new Set<TrustManagerVerificationInputOutcome>([
  "verification_input_created",
  "profile_invalid",
  "authentication_request_invalid",
  "credential_ineligible",
  "provider_mismatch",
  "algorithm_mismatch",
  "session_correlation_mismatch",
  "owner_correlation_mismatch",
  "application_correlation_mismatch",
  "challenge_correlation_mismatch",
  "purpose_correlation_mismatch",
  "lifecycle_state_ineligible",
  "assurance_requirement_unsupported",
  "expired",
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

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
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
  return { valid: errors.length === 0, errors };
}

function bridgeError(
  code: string,
  message: string,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code,
    message,
    boundary: "trust-manager",
    recoverable: true,
    details: { errors }
  };
}

function assuranceSupportedByProfile(
  profile: SelectedCredentialVerificationProfile
): readonly AuthenticationProviderAssurance[] {
  const assurance: AuthenticationProviderAssurance[] = ["phishing_resistant"];
  if (profile.userPresenceRequired) assurance.push("user_presence");
  if (profile.userVerificationRequired) assurance.push("user_verification");
  return Object.freeze(assurance);
}

function assuranceSufficient(
  provided: readonly AuthenticationProviderAssurance[],
  required: readonly AuthenticationProviderAssurance[]
): boolean {
  return required.every((assurance) => provided.includes(assurance));
}

function invariantFlags() {
  return {
    verificationPerformed: false as const,
    trustDecisionCreated: false as const,
    authenticationPerformed: false as const,
    grantsAuthority: false as const,
    vaultHandleExposed: false as const,
    registryAccessProvided: false as const,
    privateMaterialIncluded: false as const,
    persisted: false as const
  };
}

function inputFlags() {
  return {
    ...invariantFlags(),
    webAuthnInvoked: false as const,
    signatureVerified: false as const,
    credentialCounterMutated: false as const,
    rawAssertionPayloadIncluded: false as const,
    rawRegistrationPayloadIncluded: false as const,
    activeCapabilityCreated: false as const,
    sessionKeyCreated: false as const,
    authorizationCreated: false as const
  };
}

function resultFlags() {
  return {
    ...invariantFlags(),
    credentialRecordIncluded: false as const,
    rawAssertionPayloadIncluded: false as const,
    rawRegistrationPayloadIncluded: false as const
  };
}

function outcomeForErrors(errors: readonly string[]): TrustManagerVerificationInputOutcome {
  if (errors.length === 0) return "verification_input_created";
  if (errors.some((error) => error.includes("profile"))) return "profile_invalid";
  if (errors.some((error) => error.includes("authentication request"))) return "authentication_request_invalid";
  if (errors.some((error) => error.includes("provider"))) return "provider_mismatch";
  if (errors.some((error) => error.includes("algorithm"))) return "algorithm_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_correlation_mismatch";
  if (errors.some((error) => error.includes("owner"))) return "owner_correlation_mismatch";
  if (errors.some((error) => error.includes("application"))) return "application_correlation_mismatch";
  if (errors.some((error) => error.includes("challenge"))) return "challenge_correlation_mismatch";
  if (errors.some((error) => error.includes("purpose"))) return "purpose_correlation_mismatch";
  if (errors.some((error) => error.includes("lifecycle"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("assurance"))) return "assurance_requirement_unsupported";
  if (errors.some((error) => error.includes("expired"))) return "expired";
  if (errors.some((error) => error.includes("credential"))) return "credential_ineligible";
  return "malformed";
}

function statusForOutcome(
  outcome: TrustManagerVerificationInputOutcome
): TrustManagerVerificationInputStatus {
  if (outcome === "verification_input_created") return "verification_input_created";
  if (outcome === "expired") return "verification_input_expired";
  if (
    outcome === "provider_mismatch"
    || outcome === "algorithm_mismatch"
    || outcome === "assurance_requirement_unsupported"
  ) return "verification_input_unsupported";
  if (outcome === "malformed" || outcome === "profile_invalid" || outcome === "authentication_request_invalid") {
    return "verification_input_malformed";
  }
  return "verification_input_rejected";
}

function requirementsFromErrors(errors: readonly string[]): readonly TrustManagerVerificationInputRequirement[] {
  const names = [
    "eligible lifecycle and vault metadata",
    "selected credential profile correlation",
    "production authentication request correlation",
    "challenge and purpose binding",
    "supported assurance"
  ];
  return Object.freeze(names.map((description, index) => Object.freeze({
    requirementId: `trust-manager-verification-input:${index + 1}`,
    satisfied: errors.length === 0,
    description
  })));
}

export function isTrustManagerVerificationInputStatus(
  value: unknown
): value is TrustManagerVerificationInputStatus {
  return typeof value === "string" && STATUS_VALUES.has(value as TrustManagerVerificationInputStatus);
}

export function isTrustManagerVerificationInputOutcome(
  value: unknown
): value is TrustManagerVerificationInputOutcome {
  return typeof value === "string" && OUTCOME_VALUES.has(value as TrustManagerVerificationInputOutcome);
}

export function validateTrustManagerVerificationInputRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["Trust Manager verification input request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.selectedCredentialVerificationProfile)) {
    errors.push("selected credential profile is required");
  }
  if (!isRecord(request.selectedCredentialVerificationHandle)) {
    errors.push("selected credential handle is required");
  }
  if (!isRecord(request.productionAuthenticationRequest)) {
    errors.push("production authentication request is required");
  } else {
    const authValidation = validateProductionAuthenticationRequest(request.productionAuthenticationRequest);
    if (!authValidation.valid) {
      errors.push(...authValidation.errors.map((error) => `authentication request.${error}`));
    }
  }
  const lifecycleValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!lifecycleValidation.valid) {
    errors.push(...lifecycleValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isRecord(request.userSessionContext)) errors.push("userSessionContext is required");
  if (!isNonEmptyString(request.applicationId)) errors.push("applicationId is required");
  if (!isNonEmptyString(request.sessionId)) errors.push("sessionId is required");
  if (!isNonEmptyString(request.ownerCommitment)) errors.push("ownerCommitment is required");
  if (!isNonEmptyString(request.credentialId)) errors.push("credentialId is required");
  if (!isNonEmptyString(request.providerId)) errors.push("providerId is required");
  if (!isNonEmptyString(request.authenticationPurpose)) errors.push("authenticationPurpose is required");
  if (!isNonEmptyString(request.challengeReferenceId)) errors.push("challengeReferenceId is required");
  if (!Array.isArray(request.requiredAssurance)) errors.push("requiredAssurance must be an array");
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

function validateProfile(profile: SelectedCredentialVerificationProfile): readonly string[] {
  const errors: string[] = [];
  if (profile.providerKind !== "webauthn_passkey") errors.push("profile provider kind is unsupported");
  if (profile.publicKeyAlgorithm !== "ES256") errors.push("profile algorithm is unsupported");
  if (profile.verificationKey.materialKind !== "webauthn_spki_public_key_hex") {
    errors.push("profile verification key material kind is unsupported");
  }
  if (profile.verificationPerformed !== false) errors.push("profile verificationPerformed must be false");
  if (profile.containsPrivateMaterial !== false || profile.containsVaultKey !== false) {
    errors.push("profile must be public material only");
  }
  if (
    profile.credentialLifecycleStatus !== "active"
    && profile.credentialLifecycleStatus !== "recovery-only"
  ) errors.push("credential lifecycle is ineligible");
  return errors;
}

export function createTrustManagerVerificationInput(
  request: TrustManagerVerificationInputRequest,
  auditDraftCollector?: AuditDraftCollector
): TrustManagerVerificationInputResult {
  const requestValidation = validateTrustManagerVerificationInputRequest(request);
  if (!requestValidation.valid) {
    const auditEventDraft = auditDraftForTrustManagerVerificationInput({
      request,
      outcome: "malformed",
      errors: requestValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(bridgeError(
      "TRUST_MANAGER_VERIFICATION_INPUT_INVALID",
      "Trust Manager verification input request failed validation",
      requestValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const profile = request.selectedCredentialVerificationProfile;
  const handle = request.selectedCredentialVerificationHandle;
  const authRequest = request.productionAuthenticationRequest;
  const errors: string[] = [];
  errors.push(...validateProfile(profile));
  if (request.lifecycleSnapshot.state !== "unlocked") errors.push("lifecycle state is ineligible");
  if (request.lifecycleSnapshot.metadata?.deviceVaultUnlocked !== true) {
    errors.push("lifecycle device vault metadata is ineligible");
  }
  if (request.lifecycleSnapshot.metadata?.protectedStateAvailable !== true) {
    errors.push("lifecycle protected state metadata is ineligible");
  }
  if (request.lifecycleSnapshot.sessionId !== request.sessionId) errors.push("session correlation mismatch");
  if (request.userSessionContext.sessionId !== request.sessionId) errors.push("session context mismatch");
  if (request.userSessionContext.ownerCommitment !== request.ownerCommitment) {
    errors.push("owner context mismatch");
  }
  if (handle.sessionId !== request.sessionId) errors.push("session handle mismatch");
  if (handle.ownerCommitment !== request.ownerCommitment) errors.push("owner handle mismatch");
  if (handle.credentialId !== request.credentialId) errors.push("credential handle mismatch");
  if (handle.verificationProfileId !== profile.verificationProfileId) {
    errors.push("profile handle mismatch");
  }
  if (expired(handle.expiresAt) || expired(authRequest.expiresAt) || expired(authRequest.challengeReference.expiresAt) || expired(request.expiresAt)) {
    errors.push("expired input");
  }
  if (profile.credentialId !== request.credentialId) errors.push("credential profile mismatch");
  if (authRequest.correlation.credentialId !== request.credentialId) {
    errors.push("credential authentication request mismatch");
  }
  if (authRequest.providerKind !== profile.providerKind) errors.push("provider kind mismatch");
  if (authRequest.providerId !== request.providerId) errors.push("provider ID mismatch");
  if (authRequest.correlation.providerId !== request.providerId) errors.push("provider correlation mismatch");
  if (authRequest.correlation.sessionId !== request.sessionId) errors.push("session authentication request mismatch");
  if (authRequest.correlation.ownerCommitment !== request.ownerCommitment) {
    errors.push("owner authentication request mismatch");
  }
  if (authRequest.correlation.applicationId !== request.applicationId) {
    errors.push("application authentication request mismatch");
  }
  if (authRequest.challengeReference.challengeReferenceId !== request.challengeReferenceId) {
    errors.push("challenge correlation mismatch");
  }
  if (authRequest.requirement.challengeReference.challengeReferenceId !== request.challengeReferenceId) {
    errors.push("challenge requirement mismatch");
  }
  if (authRequest.purpose !== request.authenticationPurpose || authRequest.requirement.purpose !== request.authenticationPurpose) {
    errors.push("purpose correlation mismatch");
  }
  if (authRequest.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (profile.recoveryOnly && request.authenticationPurpose !== "recovery_approval") {
    errors.push("credential recovery context is required");
  }
  if (!profile.recoveryOnly && profile.credentialLifecycleStatus !== "active") {
    errors.push("credential lifecycle is ineligible");
  }
  const supportedAssurance = assuranceSupportedByProfile(profile);
  if (!assuranceSufficient(supportedAssurance, request.requiredAssurance)) {
    errors.push("assurance requirement unsupported");
  }

  if (errors.length > 0) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForTrustManagerVerificationInput({
      request,
      outcome: outcome === "unsupported" ? "unsupported" : "validation_failed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(bridgeError(
      "TRUST_MANAGER_VERIFICATION_INPUT_REJECTED",
      "Trust Manager verification input request was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const createdAt = request.requestedAt ?? new Date().toISOString();
  const expiresAt = request.expiresAt
    ?? authRequest.expiresAt
    ?? handle.expiresAt;
  const correlation: TrustManagerVerificationInputCorrelation = freezeRecord({
    sessionId: request.sessionId,
    applicationId: request.applicationId,
    ownerCommitment: request.ownerCommitment,
    credentialId: request.credentialId,
    credentialSafeReference: profile.credentialSafeReference,
    providerId: request.providerId,
    providerKind: profile.providerKind,
    challengeReferenceId: request.challengeReferenceId,
    authenticationPurpose: request.authenticationPurpose,
    auditCorrelationId: request.auditCorrelationId
  });
  const inputId = createAuditCorrelationId([
    request.sessionId,
    request.credentialId,
    request.challengeReferenceId,
    request.authenticationPurpose,
    "trust-manager-verification-input"
  ]);
  const verificationInput: TrustManagerVerificationInput = freezeRecord({
    trustManagerVerificationInputId: inputId,
    requestId: request.requestId,
    verificationProfileId: profile.verificationProfileId,
    selectedCredentialHandleId: handle.handleId,
    credentialSafeReference: profile.credentialSafeReference,
    providerKind: profile.providerKind,
    providerId: request.providerId,
    publicKeyAlgorithm: profile.publicKeyAlgorithm,
    publicKeyFingerprint: profile.publicKeyFingerprint,
    verificationKey: {
      materialKind: profile.verificationKey.materialKind,
      publicKey: profile.verificationKey.publicKey,
      publicKeyFingerprint: profile.verificationKey.publicKeyFingerprint,
      encoding: profile.verificationKey.encoding,
      containsPrivateMaterial: false
    },
    rpId: authRequest.metadata?.rpId as string | undefined,
    origin: authRequest.metadata?.origin as string | undefined,
    challengeBinding: {
      challengeReferenceId: authRequest.challengeReference.challengeReferenceId,
      challengeBindingHash: authRequest.challengeReference.challengeBindingHash,
      generatedChallenge: false,
      createdAt: authRequest.challengeReference.createdAt,
      expiresAt: authRequest.challengeReference.expiresAt
    },
    userPresenceRequired: true,
    userVerificationRequired: true,
    publicCounter: profile.signCounter,
    lifecycleClassification: profile.credentialLifecycleStatus,
    authenticationPurpose: request.authenticationPurpose,
    assuranceRequirement: {
      requiredAssurance: Object.freeze([...request.requiredAssurance]),
      supportedBySelectedCredential: supportedAssurance,
      sufficient: true
    },
    correlation,
    credentialVerificationContext: {
      sessionId: request.sessionId,
      applicationId: request.applicationId,
      ownerCommitment: request.ownerCommitment,
      credentialId: request.credentialId,
      credentialSafeReference: profile.credentialSafeReference,
      providerId: request.providerId,
      authenticationPurpose: request.authenticationPurpose,
      verificationMethod: "webauthn_assertion",
      publicMaterialOnly: true,
      vaultHandleAvailableToTrustManager: false,
      registryEnumerationAllowed: false,
      trustDecisionDeferred: true
    },
    selectedCredentialTrustContext: {
      sessionId: request.sessionId,
      ownerCommitment: request.ownerCommitment,
      credentialId: request.credentialId,
      verificationProfileId: profile.verificationProfileId,
      expectedVerificationMethod: "webauthn_assertion",
      publicMaterialOnly: true,
      trustDecisionDeferred: true
    },
    createdAt,
    expiresAt,
    processLocal: true,
    serializable: false,
    ...inputFlags()
  });
  const auditEventDraft = auditDraftForTrustManagerVerificationInput({
    request,
    outcome: "validation_succeeded",
    verificationInput
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const value: TrustManagerVerificationInputResultValue = freezeRecord({
    trustManagerVerificationInputResultId: `${inputId}:result`,
    requestId: request.requestId,
    status: "verification_input_created",
    outcome: "verification_input_created",
    verificationInput,
    requirements: requirementsFromErrors([]),
    limitations: LIMITATIONS,
    reasons: Object.freeze([
      "selected-credential-profile-used",
      "explicit-production-authentication-request-used",
      "session-correlation-valid",
      "owner-correlation-valid",
      "application-correlation-valid",
      "challenge-correlation-valid",
      "assurance-requirement-supported",
      "no-authentication",
      "no-webauthn-execution",
      "no-signature-verification",
      "no-trust-decision",
      "no-vault-handle-exposed",
      "no-registry-access",
      "no-authority"
    ]),
    createdAt,
    expiresAt,
    auditCorrelationId: request.auditCorrelationId,
    ...resultFlags(),
    auditEventDraft,
    auditDraftCollectionResult
  });
  const resultValidation = validateTrustManagerVerificationInputShape(value);
  if (!resultValidation.valid) {
    return runtimeDenied(bridgeError(
      "TRUST_MANAGER_VERIFICATION_INPUT_RESULT_INVALID",
      "Trust Manager verification input result failed validation",
      resultValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  return runtimeOk(value);
}

function auditDraftForTrustManagerVerificationInput(input: {
  readonly request: TrustManagerVerificationInputRequest;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly errors?: readonly string[];
  readonly verificationInput?: TrustManagerVerificationInput;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    summary: input.outcome === "validation_succeeded"
      ? "Trust Manager verification input was constructed from bounded public material; no verification, Trust Decision, or authority was created."
      : "Trust Manager verification input request was rejected; no authentication or Trust Decision occurred.",
    auditCorrelationId: input.request.auditCorrelationId
      ?? createAuditCorrelationId([
        input.request.sessionId,
        input.request.requestId,
        "trust-manager-verification-input"
      ]),
    redactedDetails: {
      requestId: input.request.requestId,
      credentialSafeReference: input.request.selectedCredentialVerificationProfile?.credentialSafeReference,
      providerKind: input.request.selectedCredentialVerificationProfile?.providerKind,
      algorithm: input.request.selectedCredentialVerificationProfile?.publicKeyAlgorithm,
      authenticationPurpose: input.request.authenticationPurpose,
      requiredAssurance: input.request.requiredAssurance,
      challengeReferenceId: input.request.challengeReferenceId,
      challengeCorrelationValid: input.verificationInput !== undefined,
      lifecycleEligible: input.verificationInput !== undefined,
      inputExpiresAt: input.verificationInput?.expiresAt,
      publicKeyBytesIncluded: false,
      rawAssertionDataIncluded: false,
      vaultHandleExposed: false,
      registryAccessProvided: false,
      privateMaterialIncluded: false,
      credentialRecordIncluded: false,
      authenticationPerformed: false,
      verificationPerformed: false,
      trustDecisionCreated: false,
      grantsAuthority: false,
      persisted: false,
      requestMetadata: input.request.metadata
        ? redactRuntimeMetadata(input.request.metadata).value
        : undefined,
      errors: input.errors ?? []
    }
  });
}

export function validateTrustManagerVerificationInputShape(
  value: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) return validation(["Trust Manager verification input result must be an object"]);
  if (!isNonEmptyString(value.trustManagerVerificationInputResultId)) {
    errors.push("trustManagerVerificationInputResultId is required");
  }
  if (!isTrustManagerVerificationInputStatus(value.status)) errors.push("status is invalid");
  if (!isTrustManagerVerificationInputOutcome(value.outcome)) errors.push("outcome is invalid");
  if (!isRecord(value.verificationInput)) {
    errors.push("verificationInput is required");
  } else {
    if (!isNonEmptyString(value.verificationInput.trustManagerVerificationInputId)) {
      errors.push("verificationInput.trustManagerVerificationInputId is required");
    }
    if (value.verificationInput.vaultHandleExposed !== false) {
      errors.push("verificationInput.vaultHandleExposed must be false");
    }
    if (value.verificationInput.registryAccessProvided !== false) {
      errors.push("verificationInput.registryAccessProvided must be false");
    }
    if (value.verificationInput.trustDecisionCreated !== false) {
      errors.push("verificationInput.trustDecisionCreated must be false");
    }
    if (value.verificationInput.authenticationPerformed !== false) {
      errors.push("verificationInput.authenticationPerformed must be false");
    }
    if (value.verificationInput.grantsAuthority !== false) {
      errors.push("verificationInput.grantsAuthority must be false");
    }
  }
  for (const [key, expected] of Object.entries(resultFlags())) {
    if (value[key] !== expected) errors.push(`${key} must be ${String(expected)}`);
  }
  return validation(errors);
}

export function createFixtureTrustManagerVerificationInputConsumer():
  TrustManagerVerificationInputConsumer {
  return {
    acceptVerificationInput(input) {
      const validationResult = validateTrustManagerVerificationInputShape({
        trustManagerVerificationInputResultId: `${input.trustManagerVerificationInputId}:fixture-consumer`,
        requestId: input.requestId,
        status: "verification_input_created",
        outcome: "verification_input_created",
        verificationInput: input,
        ...resultFlags()
      });
      if (!validationResult.valid) {
        return freezeRecord({
          status: "rejected",
          errors: validationResult.errors,
          trustDecisionCreated: false,
          authenticationPerformed: false,
          grantsAuthority: false,
          vaultHandleAccessed: false,
          registryEnumerated: false,
          persisted: false
        });
      }
      return freezeRecord({
        status: "accepted",
        inputId: input.trustManagerVerificationInputId,
        errors: Object.freeze([]),
        trustDecisionCreated: false,
        authenticationPerformed: false,
        grantsAuthority: false,
        vaultHandleAccessed: false,
        registryEnumerated: false,
        persisted: false
      });
    }
  };
}
