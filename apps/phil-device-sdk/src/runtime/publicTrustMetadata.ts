import {
  PHIL_DEVICE_IDENTITY_VERSION,
  PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  type PhilDeviceIdentityProviderKind,
  type PhilDevicePublicMetadata
} from "../deviceIdentity.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  RuntimeErrorDescriptor,
  RuntimeResult,
  TrustCredentialSummary
} from "./types.ts";
import {
  validateTrustEvaluationDraftShape,
  type TrustEvaluationDraft
} from "./trustDrafts.ts";

export type PublicCredentialLifecycleStatus =
  | TrustCredentialSummary["state"]
  | "pending"
  | "archived";

export type PublicDeviceLifecycleStatus =
  | "active"
  | "pending"
  | "revoked"
  | "archived"
  | "unknown";

export type PublicTrustMetadataEvaluationStatus =
  | "evaluated"
  | "validation_failed"
  | "malformed"
  | "unsupported";

export type PublicTrustMetadataEvaluationOutcome =
  | "metadata_sufficient"
  | "metadata_missing"
  | "metadata_malformed"
  | "provider_unsupported"
  | "credential_status_ineligible"
  | "device_status_ineligible"
  | "pending_credential_resolution"
  | "pending_device_resolution"
  | "pending_possession_verification"
  | "pending_authenticator_verification";

export type PublicTrustMetadataEvaluationReason =
  | "trust-evaluation-draft-valid"
  | "public-credential-metadata-present"
  | "public-device-metadata-present"
  | "credential-metadata-missing"
  | "device-metadata-missing"
  | "credential-metadata-malformed"
  | "device-metadata-malformed"
  | "provider-kind-unsupported"
  | "credential-status-active"
  | "credential-status-pending"
  | "credential-status-revoked"
  | "credential-status-rotated"
  | "credential-status-archived"
  | "credential-status-recovery-only"
  | "credential-status-unknown"
  | "device-status-ineligible"
  | "owner-commitment-mismatch"
  | "request-expired"
  | "pending-possession-verification"
  | "pending-authenticator-verification"
  | "secret-shaped-metadata-not-allowed"
  | (string & {});

export type PublicTrustEligibility =
  | "eligible_for_further_evaluation"
  | "pending_resolution"
  | "ineligible_for_ordinary_use"
  | "recovery_only"
  | "unsupported"
  | "malformed";

export type PublicTrustResolutionRequirement =
  | "credential_resolution"
  | "device_resolution"
  | "possession_verification"
  | "authenticator_verification"
  | "stronger_trust_evaluation";

export interface PublicCredentialEvaluationInput {
  readonly credentialId?: string;
  readonly credentialKind?: TrustCredentialSummary["credentialKind"];
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly lifecycleStatus?: PublicCredentialLifecycleStatus;
  readonly ownerCommitment?: Hex;
  readonly publicMetadata?: Readonly<Record<string, unknown>>;
}

export interface PublicDeviceEvaluationInput {
  readonly deviceId?: string;
  readonly deviceIdentityId?: Hex;
  readonly deviceKeyId?: Hex;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly lifecycleStatus?: PublicDeviceLifecycleStatus;
  readonly ownerCommitment?: Hex;
  readonly publicMetadata?: PhilDevicePublicMetadata;
}

export interface PublicTrustMetadataEvaluationRequest {
  readonly requestId: string;
  readonly trustEvaluationDraft: TrustEvaluationDraft;
  readonly credential?: PublicCredentialEvaluationInput;
  readonly device?: PublicDeviceEvaluationInput;
  readonly ownerCommitment?: Hex;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PublicTrustMetadataEvaluationResult {
  readonly evaluationId: string;
  readonly requestId: string;
  readonly trustEvaluationDraftId: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId: string;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly status: PublicTrustMetadataEvaluationStatus;
  readonly outcome: PublicTrustMetadataEvaluationOutcome;
  readonly eligibility: PublicTrustEligibility;
  readonly eligibleForFurtherEvaluation: boolean;
  readonly requiresPossessionVerification: boolean;
  readonly requiresAuthenticatorVerification: boolean;
  readonly requiresCredentialResolution: boolean;
  readonly requiresDeviceResolution: boolean;
  readonly resolutionRequirements: readonly PublicTrustResolutionRequirement[];
  readonly reasons: readonly PublicTrustMetadataEvaluationReason[];
  readonly evaluatedAt: string;
  readonly auditCorrelationId: string;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly persisted: false;
}

export type PublicTrustMetadataEvaluationRuntimeResult =
  RuntimeResult<PublicTrustMetadataEvaluationResult>;

export type PublicTrustMetadataEvaluationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface PublicTrustMetadataEvaluationFilter {
  readonly evaluationId?: string;
  readonly requestId?: string;
  readonly trustEvaluationDraftId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId?: string;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind | (string & {});
  readonly status?: PublicTrustMetadataEvaluationStatus;
  readonly outcome?: PublicTrustMetadataEvaluationOutcome;
  readonly eligibility?: PublicTrustEligibility;
  readonly eligibleForFurtherEvaluation?: boolean;
  readonly requiresPossessionVerification?: boolean;
  readonly requiresAuthenticatorVerification?: boolean;
  readonly requiresCredentialResolution?: boolean;
  readonly requiresDeviceResolution?: boolean;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface PublicTrustMetadataEvaluationQuery {
  readonly filter?: PublicTrustMetadataEvaluationFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface PublicTrustMetadataEvaluationCollection {
  readonly results: readonly PublicTrustMetadataEvaluationResult[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface PublicTrustMetadataEvaluationCollectionResult {
  readonly status: PublicTrustMetadataEvaluationCollectionStatus;
  readonly result?: PublicTrustMetadataEvaluationResult;
  readonly removedResult?: PublicTrustMetadataEvaluationResult;
  readonly evictedResults?: readonly PublicTrustMetadataEvaluationResult[];
  readonly collection: PublicTrustMetadataEvaluationCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface PublicTrustMetadataEvaluationCollector {
  addResult(
    result: PublicTrustMetadataEvaluationResult
  ): PublicTrustMetadataEvaluationCollectionResult;
  removeResult(evaluationId: string): PublicTrustMetadataEvaluationCollectionResult;
  clear(): PublicTrustMetadataEvaluationCollectionResult;
  count(): number;
  getById(evaluationId: string): PublicTrustMetadataEvaluationResult | undefined;
  getAll(): readonly PublicTrustMetadataEvaluationResult[];
  query(
    query: PublicTrustMetadataEvaluationQuery
  ): readonly PublicTrustMetadataEvaluationResult[];
  filter(
    filter: PublicTrustMetadataEvaluationFilter
  ): readonly PublicTrustMetadataEvaluationResult[];
}

export interface InMemoryPublicTrustMetadataEvaluationCollectorOptions {
  readonly maxResultCount?: number;
}

export type PublicTrustMetadataEvaluationGroup =
  Readonly<Record<string, readonly PublicTrustMetadataEvaluationResult[]>>;

export type PublicTrustMetadataEvaluationReviewSource =
  | PublicTrustMetadataEvaluationCollector
  | PublicTrustMetadataEvaluationCollection
  | readonly PublicTrustMetadataEvaluationResult[];

export interface PublicTrustMetadataEvaluationSummary {
  readonly totalResultCount: number;
  readonly resultsByApplication: Readonly<Record<string, number>>;
  readonly resultsBySession: Readonly<Record<string, number>>;
  readonly resultsByCredential: Readonly<Record<string, number>>;
  readonly resultsByDevice: Readonly<Record<string, number>>;
  readonly resultsByProviderKind: Readonly<Record<string, number>>;
  readonly resultsByOutcome: Readonly<Record<string, number>>;
  readonly metadataSufficientCount: number;
  readonly missingMetadataCount: number;
  readonly malformedMetadataCount: number;
  readonly unsupportedProviderCount: number;
  readonly pendingPossessionVerificationCount: number;
  readonly pendingAuthenticatorVerificationCount: number;
  readonly pendingStrongerEvaluationCount: number;
  readonly expiredCount: number;
  readonly earliestEvaluatedAt?: string;
  readonly latestEvaluatedAt?: string;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
}

const SUPPORTED_PROVIDER_KINDS = new Set<string>([
  PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND,
  PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND
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

const PUBLIC_TRUST_METADATA_EVALUATION_STATUSES =
  new Set<PublicTrustMetadataEvaluationStatus>([
    "evaluated",
    "validation_failed",
    "malformed",
    "unsupported"
  ]);

const PUBLIC_TRUST_METADATA_EVALUATION_OUTCOMES =
  new Set<PublicTrustMetadataEvaluationOutcome>([
    "metadata_sufficient",
    "metadata_missing",
    "metadata_malformed",
    "provider_unsupported",
    "credential_status_ineligible",
    "device_status_ineligible",
    "pending_credential_resolution",
    "pending_device_resolution",
    "pending_possession_verification",
    "pending_authenticator_verification"
  ]);

const PUBLIC_TRUST_ELIGIBILITIES = new Set<PublicTrustEligibility>([
  "eligible_for_further_evaluation",
  "pending_resolution",
  "ineligible_for_ordinary_use",
  "recovery_only",
  "unsupported",
  "malformed"
]);

const TRUST_AUTHORITY_OR_PRIVATE_FIELDS = new Set([
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
  "webauthnprivatematerial",
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

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function findBlockedAuthorityFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findBlockedAuthorityFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) {
    return [];
  }
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (TRUST_AUTHORITY_OR_PRIVATE_FIELDS.has(normalizeFieldName(key)) && entry !== false) {
      findings.push(childPath);
    }
    findings.push(...findBlockedAuthorityFields(entry, childPath));
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

function malformedPublicMetadataEvaluationError(
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "PUBLIC_TRUST_METADATA_EVALUATION_INVALID",
    message: "public Trust metadata evaluation request failed validation",
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

function validatePublicDeviceMetadataShape(
  metadata: unknown
): readonly string[] {
  const errors: string[] = [];
  if (!isRecord(metadata)) {
    return ["device.publicMetadata must be an object"];
  }
  if (metadata.version !== PHIL_DEVICE_IDENTITY_VERSION) {
    errors.push("device.publicMetadata.version is invalid");
  }
  if (!isNonEmptyString(metadata.providerKind)) {
    errors.push("device.publicMetadata.providerKind is required");
  }
  if (!isNonEmptyString(metadata.deviceIdentityId)) {
    errors.push("device.publicMetadata.deviceIdentityId is required");
  }
  if (!isNonEmptyString(metadata.deviceKeyId)) {
    errors.push("device.publicMetadata.deviceKeyId is required");
  }
  if (!isRecord(metadata.philIdentity)) {
    errors.push("device.publicMetadata.philIdentity is required");
  } else if (!isNonEmptyString(metadata.philIdentity.ownerCommitment)) {
    errors.push("device.publicMetadata.philIdentity.ownerCommitment is required");
  }
  if (typeof metadata.productionSafe !== "boolean") {
    errors.push("device.publicMetadata.productionSafe must be boolean");
  }
  if (metadata.privateMaterialExportable !== false) {
    errors.push("device.publicMetadata.privateMaterialExportable must be false");
  }
  if (typeof metadata.hardwareBacked !== "boolean") {
    errors.push("device.publicMetadata.hardwareBacked must be boolean");
  }
  return errors;
}

export function validatePublicTrustMetadataEvaluationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["public Trust metadata evaluation request must be an object"]);
  }

  if (!isNonEmptyString(request.requestId)) {
    errors.push("requestId is required");
  }

  const draftValidation = validateTrustEvaluationDraftShape(request.trustEvaluationDraft);
  if (!draftValidation.valid) {
    errors.push(...draftValidation.errors.map((error) => `trustEvaluationDraft.${error}`));
  }

  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }

  errors.push(...secretValidationErrors(request));

  return validation(errors);
}

export function validatePublicTrustMetadataEvaluationResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) {
    return validation(["public Trust metadata evaluation result must be an object"]);
  }

  if (!isNonEmptyString(result.evaluationId)) {
    errors.push("evaluationId is required");
  }
  if (!isNonEmptyString(result.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(result.trustEvaluationDraftId)) {
    errors.push("trustEvaluationDraftId is required");
  }
  if (
    result.capabilityGrantDraftId !== undefined
    && !isNonEmptyString(result.capabilityGrantDraftId)
  ) {
    errors.push("capabilityGrantDraftId must be a non-empty string when provided");
  }
  if (!isNonEmptyString(result.applicationId)) {
    errors.push("applicationId is required");
  }
  if (
    !PUBLIC_TRUST_METADATA_EVALUATION_STATUSES.has(
      result.status as PublicTrustMetadataEvaluationStatus
    )
  ) {
    errors.push("status is invalid");
  }
  if (
    !PUBLIC_TRUST_METADATA_EVALUATION_OUTCOMES.has(
      result.outcome as PublicTrustMetadataEvaluationOutcome
    )
  ) {
    errors.push("outcome is invalid");
  }
  if (!PUBLIC_TRUST_ELIGIBILITIES.has(result.eligibility as PublicTrustEligibility)) {
    errors.push("eligibility is invalid");
  }
  if (typeof result.eligibleForFurtherEvaluation !== "boolean") {
    errors.push("eligibleForFurtherEvaluation must be boolean");
  }
  if (typeof result.requiresPossessionVerification !== "boolean") {
    errors.push("requiresPossessionVerification must be boolean");
  }
  if (typeof result.requiresAuthenticatorVerification !== "boolean") {
    errors.push("requiresAuthenticatorVerification must be boolean");
  }
  if (typeof result.requiresCredentialResolution !== "boolean") {
    errors.push("requiresCredentialResolution must be boolean");
  }
  if (typeof result.requiresDeviceResolution !== "boolean") {
    errors.push("requiresDeviceResolution must be boolean");
  }
  if (!Array.isArray(result.resolutionRequirements)) {
    errors.push("resolutionRequirements must be an array");
  }
  if (!Array.isArray(result.reasons)) {
    errors.push("reasons must be an array");
  }
  if (!hasValidDateShape(result.evaluatedAt)) {
    errors.push("evaluatedAt must be a parseable date string");
  }
  if (!isNonEmptyString(result.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
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

  const blockedFields = findBlockedAuthorityFields(result);
  if (blockedFields.length > 0) {
    errors.push(`private material or trust authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  errors.push(...secretValidationErrors(result));

  return validation(errors);
}

function ownerCommitmentFromDeviceInput(
  device?: PublicDeviceEvaluationInput
): Hex | undefined {
  return device?.ownerCommitment
    ?? device?.publicMetadata?.philIdentity.ownerCommitment;
}

function providerKindFromRequest(
  request: PublicTrustMetadataEvaluationRequest
): string | undefined {
  return request.credential?.providerKind
    ?? request.device?.providerKind
    ?? request.device?.publicMetadata?.providerKind
    ?? request.trustEvaluationDraft.providerKind;
}

function isProviderSupported(providerKind: string | undefined): boolean {
  return providerKind === undefined || SUPPORTED_PROVIDER_KINDS.has(providerKind);
}

function credentialStatusFromRequest(
  request: PublicTrustMetadataEvaluationRequest
): PublicCredentialLifecycleStatus | undefined {
  return request.credential?.lifecycleStatus
    ?? request.trustEvaluationDraft.credentialStatusReference;
}

function addUnique<TValue extends string>(
  values: TValue[],
  value: TValue
): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

function isExpired(request: PublicTrustMetadataEvaluationRequest): boolean {
  const expiresAt = request.expiresAt ?? request.trustEvaluationDraft.expiresAt;
  return expiresAt !== undefined && Date.parse(expiresAt) <= Date.now();
}

function classifyCredentialStatus(
  status: PublicCredentialLifecycleStatus | undefined,
  reasons: PublicTrustMetadataEvaluationReason[]
): {
  readonly outcome?: PublicTrustMetadataEvaluationOutcome;
  readonly eligibility?: PublicTrustEligibility;
} {
  if (status === undefined || status === "unknown") {
    addUnique(reasons, "credential-status-unknown");
    return {
      outcome: "pending_credential_resolution",
      eligibility: "pending_resolution"
    };
  }
  if (status === "active") {
    addUnique(reasons, "credential-status-active");
    return {};
  }
  if (status === "pending") {
    addUnique(reasons, "credential-status-pending");
    return {
      outcome: "pending_credential_resolution",
      eligibility: "pending_resolution"
    };
  }
  if (status === "recovery-only") {
    addUnique(reasons, "credential-status-recovery-only");
    return {
      outcome: "credential_status_ineligible",
      eligibility: "recovery_only"
    };
  }
  if (status === "revoked") {
    addUnique(reasons, "credential-status-revoked");
  } else if (status === "rotated") {
    addUnique(reasons, "credential-status-rotated");
  } else if (status === "archived") {
    addUnique(reasons, "credential-status-archived");
  }
  return {
    outcome: "credential_status_ineligible",
    eligibility: "ineligible_for_ordinary_use"
  };
}

function classifyDeviceStatus(
  status: PublicDeviceLifecycleStatus | undefined,
  reasons: PublicTrustMetadataEvaluationReason[]
): {
  readonly outcome?: PublicTrustMetadataEvaluationOutcome;
  readonly eligibility?: PublicTrustEligibility;
} {
  if (status === undefined || status === "active") {
    return {};
  }
  if (status === "pending" || status === "unknown") {
    return {
      outcome: "pending_device_resolution",
      eligibility: "pending_resolution"
    };
  }
  addUnique(reasons, "device-status-ineligible");
  return {
    outcome: "device_status_ineligible",
    eligibility: "ineligible_for_ordinary_use"
  };
}

export function evaluatePublicTrustMetadata(
  request: PublicTrustMetadataEvaluationRequest
): PublicTrustMetadataEvaluationRuntimeResult {
  const validationResult = validatePublicTrustMetadataEvaluationRequest(request);
  if (!validationResult.valid) {
    return runtimeDenied(malformedPublicMetadataEvaluationError(validationResult.errors));
  }

  const reasons: PublicTrustMetadataEvaluationReason[] = [
    "trust-evaluation-draft-valid"
  ];
  const resolutionRequirements: PublicTrustResolutionRequirement[] = [];
  const providerKind = providerKindFromRequest(request);
  const expectedOwnerCommitment = request.ownerCommitment
    ?? request.trustEvaluationDraft.ownerCommitment
    ?? request.trustEvaluationDraft.subject.ownerCommitment;
  const credentialOwnerCommitment = request.credential?.ownerCommitment;
  const deviceOwnerCommitment = ownerCommitmentFromDeviceInput(request.device);
  const credentialId = request.credential?.credentialId
    ?? request.trustEvaluationDraft.credentialId;
  const deviceId = request.device?.deviceId
    ?? request.device?.publicMetadata?.deviceIdentityId
    ?? request.trustEvaluationDraft.deviceId;
  const deviceMetadataShapeErrors = request.device?.publicMetadata === undefined
    ? []
    : validatePublicDeviceMetadataShape(request.device.publicMetadata);
  let outcome: PublicTrustMetadataEvaluationOutcome = "metadata_sufficient";
  let eligibility: PublicTrustEligibility = "eligible_for_further_evaluation";

  if (isExpired(request)) {
    addUnique(reasons, "request-expired");
    outcome = "metadata_malformed";
    eligibility = "malformed";
  } else if (!isProviderSupported(providerKind)) {
    addUnique(reasons, "provider-kind-unsupported");
    outcome = "provider_unsupported";
    eligibility = "unsupported";
  } else if (
    expectedOwnerCommitment !== undefined
    && (
      (credentialOwnerCommitment !== undefined && credentialOwnerCommitment !== expectedOwnerCommitment)
      || (deviceOwnerCommitment !== undefined && deviceOwnerCommitment !== expectedOwnerCommitment)
    )
  ) {
    addUnique(reasons, "owner-commitment-mismatch");
    outcome = "metadata_malformed";
    eligibility = "malformed";
  } else if (request.device?.publicMetadata !== undefined && deviceMetadataShapeErrors.length > 0) {
    addUnique(reasons, "device-metadata-malformed");
    outcome = "metadata_malformed";
    eligibility = "malformed";
  } else if (request.credential !== undefined && !credentialId) {
    addUnique(reasons, "credential-metadata-malformed");
    outcome = "metadata_malformed";
    eligibility = "malformed";
  } else if (!request.credential) {
    addUnique(reasons, "credential-metadata-missing");
    addUnique(resolutionRequirements, "credential_resolution");
    outcome = "metadata_missing";
    eligibility = "pending_resolution";
  } else if (!request.device) {
    addUnique(reasons, "device-metadata-missing");
    addUnique(resolutionRequirements, "device_resolution");
    outcome = "metadata_missing";
    eligibility = "pending_resolution";
  } else if (request.device && !request.device.publicMetadata) {
    addUnique(reasons, "device-metadata-missing");
    addUnique(resolutionRequirements, "device_resolution");
    outcome = "metadata_missing";
    eligibility = "pending_resolution";
  } else {
    if (request.credential || credentialId) {
      addUnique(reasons, "public-credential-metadata-present");
    }
    if (request.device?.publicMetadata) {
      addUnique(reasons, "public-device-metadata-present");
    }

    const credentialClassification = classifyCredentialStatus(
      credentialStatusFromRequest(request),
      reasons
    );
    const deviceClassification = classifyDeviceStatus(request.device?.lifecycleStatus, reasons);
    outcome = credentialClassification.outcome
      ?? deviceClassification.outcome
      ?? "metadata_sufficient";
    eligibility = credentialClassification.eligibility
      ?? deviceClassification.eligibility
      ?? "eligible_for_further_evaluation";
  }

  const eligibleForFurtherEvaluation = outcome === "metadata_sufficient";
  const requiresCredentialResolution = outcome === "metadata_missing"
    && reasons.includes("credential-metadata-missing")
    || outcome === "pending_credential_resolution";
  const requiresDeviceResolution = outcome === "metadata_missing"
    && reasons.includes("device-metadata-missing")
    || outcome === "pending_device_resolution";
  const requiresPossessionVerification = eligibleForFurtherEvaluation;
  const requiresAuthenticatorVerification = eligibleForFurtherEvaluation;

  if (requiresCredentialResolution) {
    addUnique(resolutionRequirements, "credential_resolution");
  }
  if (requiresDeviceResolution) {
    addUnique(resolutionRequirements, "device_resolution");
  }
  if (requiresPossessionVerification) {
    addUnique(resolutionRequirements, "possession_verification");
    addUnique(reasons, "pending-possession-verification");
  }
  if (requiresAuthenticatorVerification) {
    addUnique(resolutionRequirements, "authenticator_verification");
    addUnique(reasons, "pending-authenticator-verification");
  }
  if (eligibleForFurtherEvaluation) {
    addUnique(resolutionRequirements, "stronger_trust_evaluation");
  }

  const evaluatedAt = new Date().toISOString();
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.trustEvaluationDraft.applicationId,
    request.trustEvaluationDraft.sessionId ?? "",
    request.trustEvaluationDraft.trustEvaluationDraftId,
    request.requestId,
    "public-trust-metadata-evaluation"
  ]);

  return runtimeOk(Object.freeze({
    evaluationId: `${auditCorrelationId}:evaluation`,
    requestId: request.requestId,
    trustEvaluationDraftId: request.trustEvaluationDraft.trustEvaluationDraftId,
    capabilityGrantDraftId: request.trustEvaluationDraft.capabilityGrantDraftId,
    applicationId: request.trustEvaluationDraft.applicationId,
    sessionId: request.trustEvaluationDraft.sessionId,
    ownerCommitment: expectedOwnerCommitment,
    credentialId,
    deviceId,
    providerKind,
    status: outcome === "provider_unsupported" ? "unsupported" : "evaluated",
    outcome,
    eligibility,
    eligibleForFurtherEvaluation,
    requiresPossessionVerification,
    requiresAuthenticatorVerification,
    requiresCredentialResolution,
    requiresDeviceResolution,
    resolutionRequirements: Object.freeze([...resolutionRequirements]),
    reasons: Object.freeze(reasons),
    evaluatedAt,
    auditCorrelationId,
    providesTrustDecision: false,
    grantsAuthority: false,
    persisted: false
  }));
}

function normalizeMaxResultCount(maxResultCount?: number): number {
  if (maxResultCount === undefined) {
    return 100;
  }
  if (!Number.isFinite(maxResultCount)) {
    return 100;
  }
  return Math.max(1, Math.floor(maxResultCount));
}

function freezeEvaluationResult(
  result: PublicTrustMetadataEvaluationResult
): PublicTrustMetadataEvaluationResult {
  return freezeRecord(result);
}

function matchesFilter(
  result: PublicTrustMetadataEvaluationResult,
  filter: PublicTrustMetadataEvaluationFilter
): boolean {
  if (filter.evaluationId !== undefined && result.evaluationId !== filter.evaluationId) {
    return false;
  }
  if (filter.requestId !== undefined && result.requestId !== filter.requestId) return false;
  if (
    filter.trustEvaluationDraftId !== undefined
    && result.trustEvaluationDraftId !== filter.trustEvaluationDraftId
  ) return false;
  if (
    filter.capabilityGrantDraftId !== undefined
    && result.capabilityGrantDraftId !== filter.capabilityGrantDraftId
  ) return false;
  if (filter.applicationId !== undefined && result.applicationId !== filter.applicationId) {
    return false;
  }
  if (filter.sessionId !== undefined && result.sessionId !== filter.sessionId) return false;
  if (
    filter.ownerCommitment !== undefined
    && result.ownerCommitment !== filter.ownerCommitment
  ) return false;
  if (filter.credentialId !== undefined && result.credentialId !== filter.credentialId) {
    return false;
  }
  if (filter.deviceId !== undefined && result.deviceId !== filter.deviceId) return false;
  if (filter.providerKind !== undefined && result.providerKind !== filter.providerKind) {
    return false;
  }
  if (filter.status !== undefined && result.status !== filter.status) return false;
  if (filter.outcome !== undefined && result.outcome !== filter.outcome) return false;
  if (filter.eligibility !== undefined && result.eligibility !== filter.eligibility) return false;
  if (
    filter.eligibleForFurtherEvaluation !== undefined
    && result.eligibleForFurtherEvaluation !== filter.eligibleForFurtherEvaluation
  ) return false;
  if (
    filter.requiresPossessionVerification !== undefined
    && result.requiresPossessionVerification !== filter.requiresPossessionVerification
  ) return false;
  if (
    filter.requiresAuthenticatorVerification !== undefined
    && result.requiresAuthenticatorVerification !== filter.requiresAuthenticatorVerification
  ) return false;
  if (
    filter.requiresCredentialResolution !== undefined
    && result.requiresCredentialResolution !== filter.requiresCredentialResolution
  ) return false;
  if (
    filter.requiresDeviceResolution !== undefined
    && result.requiresDeviceResolution !== filter.requiresDeviceResolution
  ) return false;
  if (
    filter.auditCorrelationId !== undefined
    && result.auditCorrelationId !== filter.auditCorrelationId
  ) return false;
  if (filter.since !== undefined && result.evaluatedAt < filter.since) return false;
  if (filter.until !== undefined && result.evaluatedAt > filter.until) return false;
  return true;
}

export function createInMemoryPublicTrustMetadataEvaluationCollector(
  options: InMemoryPublicTrustMetadataEvaluationCollectorOptions = {}
): PublicTrustMetadataEvaluationCollector {
  const maxResultCount = normalizeMaxResultCount(options.maxResultCount);
  const results = new Map<string, PublicTrustMetadataEvaluationResult>();

  function getAll(): readonly PublicTrustMetadataEvaluationResult[] {
    return Object.freeze(Array.from(results.values()));
  }

  function collection(): PublicTrustMetadataEvaluationCollection {
    return Object.freeze({
      results: getAll(),
      count: results.size,
      maxResultCount
    });
  }

  function filterResults(
    filter: PublicTrustMetadataEvaluationFilter
  ): readonly PublicTrustMetadataEvaluationResult[] {
    return Object.freeze(getAll().filter((result) => matchesFilter(result, filter)));
  }

  return {
    addResult(result) {
      const validationResult = validatePublicTrustMetadataEvaluationResultShape(result);
      if (!validationResult.valid) {
        return {
          status: "rejected_invalid",
          collection: collection(),
          errors: validationResult.errors,
          reason: "Only valid public Trust metadata evaluation results may be collected."
        };
      }

      if (results.has(result.evaluationId)) {
        return {
          status: "rejected_duplicate",
          result: results.get(result.evaluationId),
          collection: collection(),
          reason: "Public Trust metadata evaluation result IDs must be unique within an in-memory collector."
        };
      }

      const evictedResults: PublicTrustMetadataEvaluationResult[] = [];
      if (results.size >= maxResultCount) {
        const oldestResultId = results.keys().next().value as string | undefined;
        if (oldestResultId !== undefined) {
          const oldestResult = results.get(oldestResultId);
          results.delete(oldestResultId);
          if (oldestResult) {
            evictedResults.push(oldestResult);
          }
        }
      }

      const storedResult = freezeEvaluationResult(result);
      results.set(storedResult.evaluationId, storedResult);

      return {
        status: evictedResults.length > 0 ? "evicted_oldest" : "collected",
        result: storedResult,
        evictedResults: Object.freeze(evictedResults),
        collection: collection()
      };
    },
    removeResult(evaluationId) {
      const removedResult = results.get(evaluationId);
      if (!removedResult) {
        return {
          status: "not_found",
          collection: collection(),
          reason: "No public Trust metadata evaluation result with that ID exists in this in-memory collector."
        };
      }
      results.delete(evaluationId);
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
    getById(evaluationId) {
      return results.get(evaluationId);
    },
    getAll,
    query(query) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter ? filterResults(query.filter) : getAll();
      const sliced = limit === undefined
        ? filtered.slice(offset)
        : filtered.slice(offset, offset + limit);
      return Object.freeze(sliced);
    },
    filter: filterResults
  };
}

function resultArrayFromReviewSource(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  if (Array.isArray(source)) {
    return source;
  }
  if ("getAll" in source && typeof source.getAll === "function") {
    return source.getAll();
  }
  return (source as PublicTrustMetadataEvaluationCollection).results;
}

function freezeGroupMap(
  groups: Record<string, PublicTrustMetadataEvaluationResult[]>
): PublicTrustMetadataEvaluationGroup {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, Object.freeze([...value])])
    )
  );
}

function groupPublicTrustMetadataEvaluationsBy(
  source: PublicTrustMetadataEvaluationReviewSource,
  keyForResult: (result: PublicTrustMetadataEvaluationResult) => string
): PublicTrustMetadataEvaluationGroup {
  const groups: Record<string, PublicTrustMetadataEvaluationResult[]> = {};
  for (const result of resultArrayFromReviewSource(source)) {
    const key = keyForResult(result);
    groups[key] ??= [];
    groups[key].push(result);
  }
  return freezeGroupMap(groups);
}

function countGroups(
  groups: PublicTrustMetadataEvaluationGroup
): Readonly<Record<string, number>> {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, value.length])
    )
  );
}

function evaluationRange(results: readonly PublicTrustMetadataEvaluationResult[]): {
  readonly earliestEvaluatedAt?: string;
  readonly latestEvaluatedAt?: string;
} {
  const evaluatedAtValues = results.map((result) => result.evaluatedAt).filter(Boolean).sort();
  return {
    earliestEvaluatedAt: evaluatedAtValues[0],
    latestEvaluatedAt: evaluatedAtValues[evaluatedAtValues.length - 1]
  };
}

function isExpiredPublicTrustMetadataEvaluation(
  result: PublicTrustMetadataEvaluationResult
): boolean {
  return result.reasons.includes("request-expired");
}

export function groupPublicTrustMetadataEvaluationsByApplication(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(source, (result) => result.applicationId);
}

export function groupPublicTrustMetadataEvaluationsBySession(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(source, (result) => result.sessionId ?? "no-session");
}

export function groupPublicTrustMetadataEvaluationsByCredential(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(
    source,
    (result) => result.credentialId ?? "no-credential"
  );
}

export function groupPublicTrustMetadataEvaluationsByDevice(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(
    source,
    (result) => result.deviceId ?? "no-device"
  );
}

export function groupPublicTrustMetadataEvaluationsByProviderKind(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(
    source,
    (result) => result.providerKind ?? "no-provider-kind"
  );
}

export function groupPublicTrustMetadataEvaluationsByOutcome(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationGroup {
  return groupPublicTrustMetadataEvaluationsBy(source, (result) => result.outcome);
}

export function getMetadataSufficientEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.outcome === "metadata_sufficient"
    )
  );
}

export function getMissingMetadataEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.outcome === "metadata_missing"
    )
  );
}

export function getMalformedMetadataEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.outcome === "metadata_malformed"
    )
  );
}

export function getUnsupportedProviderEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.outcome === "provider_unsupported"
    )
  );
}

export function getPendingPossessionVerificationEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.requiresPossessionVerification
    )
  );
}

export function getPendingAuthenticatorVerificationEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(
    resultArrayFromReviewSource(source).filter(
      (result) => result.requiresAuthenticatorVerification
    )
  );
}

export function getExpiredPublicTrustMetadataEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): readonly PublicTrustMetadataEvaluationResult[] {
  return Object.freeze(resultArrayFromReviewSource(source).filter(
    isExpiredPublicTrustMetadataEvaluation
  ));
}

export function summarizePublicTrustMetadataEvaluations(
  source: PublicTrustMetadataEvaluationReviewSource
): PublicTrustMetadataEvaluationSummary {
  const results = resultArrayFromReviewSource(source);
  const byApplication = groupPublicTrustMetadataEvaluationsByApplication(results);
  const bySession = groupPublicTrustMetadataEvaluationsBySession(results);
  const byCredential = groupPublicTrustMetadataEvaluationsByCredential(results);
  const byDevice = groupPublicTrustMetadataEvaluationsByDevice(results);
  const byProviderKind = groupPublicTrustMetadataEvaluationsByProviderKind(results);
  const byOutcome = groupPublicTrustMetadataEvaluationsByOutcome(results);
  const metadataSufficient = getMetadataSufficientEvaluations(results);
  const missingMetadata = getMissingMetadataEvaluations(results);
  const malformedMetadata = getMalformedMetadataEvaluations(results);
  const unsupportedProvider = getUnsupportedProviderEvaluations(results);
  const pendingPossession = getPendingPossessionVerificationEvaluations(results);
  const pendingAuthenticator = getPendingAuthenticatorVerificationEvaluations(results);
  const expired = getExpiredPublicTrustMetadataEvaluations(results);
  const range = evaluationRange(results);

  return Object.freeze({
    totalResultCount: results.length,
    resultsByApplication: countGroups(byApplication),
    resultsBySession: countGroups(bySession),
    resultsByCredential: countGroups(byCredential),
    resultsByDevice: countGroups(byDevice),
    resultsByProviderKind: countGroups(byProviderKind),
    resultsByOutcome: countGroups(byOutcome),
    metadataSufficientCount: metadataSufficient.length,
    missingMetadataCount: missingMetadata.length,
    malformedMetadataCount: malformedMetadata.length,
    unsupportedProviderCount: unsupportedProvider.length,
    pendingPossessionVerificationCount: pendingPossession.length,
    pendingAuthenticatorVerificationCount: pendingAuthenticator.length,
    pendingStrongerEvaluationCount: metadataSufficient.length,
    expiredCount: expired.length,
    earliestEvaluatedAt: range.earliestEvaluatedAt,
    latestEvaluatedAt: range.latestEvaluatedAt,
    providesTrustDecision: false,
    grantsAuthority: false
  });
}
