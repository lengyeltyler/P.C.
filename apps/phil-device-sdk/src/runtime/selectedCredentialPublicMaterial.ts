import { keccak256, toUtf8Bytes } from "ethers";

import {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import type {
  PhilCredentialRecord,
  PhilCredentialRegistrySnapshot,
  PhilCredentialStatus
} from "../deviceIdentityLifecycle.ts";
import type { PhilIdentityPublic } from "../identity.ts";
import type { Hex } from "../hashes.ts";
import { createAuditEventDraft, type AuditDraftCollectionResult, type AuditDraftCollector, type AuditEventDraft } from "./audit.ts";
import type {
  DeviceVaultEnvelopeReference,
  DeviceVaultUnlockMaterialReference,
  UnlockedDeviceVaultHandleMetadata
} from "./deviceVaultUnlock.ts";
import { createAuditCorrelationId, runtimeDenied, runtimeOk, type RuntimeValidationResult } from "./helpers.ts";
import type {
  PublicCredentialDirectoryResultValue,
  PublicCredentialLifecycleClassification
} from "./publicCredentialDirectory.ts";
import { sanitizeCredentialRecordToPublicDescriptor } from "./publicCredentialDirectory.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import type { RuntimeErrorDescriptor, RuntimeResult } from "./types.ts";

export type SelectedCredentialPublicMaterialOperation =
  "materialize_selected_credential_public_data";

export type SelectedCredentialPublicMaterialStatus =
  | "material_created"
  | "material_rejected"
  | "material_malformed"
  | "material_expired"
  | "material_unsupported";

export type SelectedCredentialPublicMaterialOutcome =
  | "material_created"
  | "request_malformed"
  | "unsupported_operation"
  | "invalid_handle"
  | "expired_handle"
  | "owner_mismatch"
  | "session_mismatch"
  | "audit_correlation_mismatch"
  | "lifecycle_state_ineligible"
  | "credential_not_found"
  | "credential_selector_invalid"
  | "credential_lifecycle_ineligible"
  | "credential_recovery_context_required"
  | "unsupported_provider"
  | "unsupported_algorithm"
  | "malformed_public_verification_material"
  | "directory_correlation_mismatch"
  | "vault_read_failed";

export type SelectedCredentialPublicMaterialReason =
  | "exactly-one-credential-selected"
  | "allowlisted-verification-profile"
  | "existing-registry-load-reused"
  | "existing-public-directory-required"
  | "existing-webauthn-verifier-requires-public-key"
  | "no-authentication"
  | "no-webauthn-execution"
  | "no-signature-verification"
  | "no-trust-decision"
  | "no-authority"
  | "no-private-material"
  | (string & {});

export type SelectedCredentialPublicMaterialLimitation =
  | "single_credential_only"
  | "process_local_result"
  | "bounded_expiry"
  | "public_material_only"
  | "no_bulk_export"
  | "no_trust_decision"
  | "no_authentication"
  | "no_authority"
  | "no_persistence"
  | (string & {});

export interface SelectedCredentialVerificationKeyMaterial {
  readonly materialKind: "webauthn_spki_public_key_hex";
  readonly algorithm: "ES256";
  readonly publicKey: Hex;
  readonly publicKeyFingerprint: Hex;
  readonly encoding: "hex";
  readonly requiredBy: "existing-webauthn-assertion-verifier";
  readonly exportPolicy: "bounded-selected-credential-only";
  readonly containsPrivateMaterial: false;
}

export interface SelectedCredentialVerificationProfile {
  readonly verificationProfileId: string;
  readonly verificationProfileVersion: "selected-credential-public-material-v1";
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerKind: "webauthn_passkey";
  readonly publicKeyAlgorithm: "ES256";
  readonly publicKeyFingerprint: Hex;
  readonly verificationKey: SelectedCredentialVerificationKeyMaterial;
  readonly supportedVerificationMethods: readonly ["webauthn_assertion"];
  readonly credentialLifecycleStatus: PublicCredentialLifecycleClassification;
  readonly recoveryOnly: boolean;
  readonly ordinaryUseEligible: boolean;
  readonly recoveryUseEligible: boolean;
  readonly userPresenceRequired: true;
  readonly userVerificationRequired: true;
  readonly signCounter?: number;
  readonly deviceReference?: string;
  readonly deviceType: string;
  readonly ownerCommitment: Hex;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly lastUsedAt?: string;
  readonly containsPrivateMaterial: false;
  readonly containsVaultKey: false;
  readonly containsPhilSecret: false;
  readonly containsRawAssertionPayload: false;
  readonly containsRawRegistrationPayload: false;
  readonly containsAuthorization: false;
  readonly grantsAuthority: false;
  readonly verificationPerformed: false;
}

export type SelectedCredentialVerificationHandleId = string;

export interface SelectedCredentialVerificationHandleMetadata {
  readonly handleId: SelectedCredentialVerificationHandleId;
  readonly verificationProfileId: string;
  readonly credentialId: string;
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly processLocal: true;
  readonly serializable: false;
  readonly persistent: false;
  readonly singleCredentialOnly: true;
  readonly containsPrivateMaterial: false;
  readonly containsVaultKey: false;
  readonly containsPhilSecret: false;
  readonly grantsAuthority: false;
}

export interface SelectedCredentialPublicMaterialSummary {
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly providerKind: "webauthn_passkey";
  readonly publicKeyAlgorithm: "ES256";
  readonly publicKeyFingerprint: Hex;
  readonly lifecycleStatus: PublicCredentialLifecycleClassification;
  readonly recoveryOnly: boolean;
  readonly supportedVerificationMethods: readonly ["webauthn_assertion"];
  readonly verificationHandleCreated: boolean;
  readonly publicKeyReturnedForVerifier: true;
  readonly containsPrivateMaterial: false;
  readonly containsVaultKey: false;
  readonly containsPhilSecret: false;
  readonly containsRawAssertionPayload: false;
  readonly containsRawRegistrationPayload: false;
  readonly containsAuthorization: false;
  readonly grantsAuthority: false;
  readonly verificationPerformed: false;
}

export interface SelectedCredentialPublicMaterialEvidence {
  readonly directoryResultId: string;
  readonly descriptorId: string;
  readonly vaultHandleId: string;
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly credentialSafeReference: Hex;
  readonly registryRecordReturned: false;
  readonly verifierReadyPublicKeyIncluded: true;
  readonly privateMaterialIncluded: false;
}

export interface SelectedCredentialPublicMaterialRequest {
  readonly requestId: string;
  readonly operation: SelectedCredentialPublicMaterialOperation | string;
  readonly credentialId?: string;
  readonly credentialIds?: readonly string[];
  readonly wildcardSelector?: boolean;
  readonly verificationContext?: "ordinary" | "recovery";
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly publicCredentialDirectory: PublicCredentialDirectoryResultValue;
  readonly identity: PhilIdentityPublic;
  readonly envelope: DeviceVaultEnvelopeReference;
  readonly unlockMaterial: DeviceVaultUnlockMaterialReference;
  readonly expectedOwnerCommitment?: Hex;
  readonly expectedSessionId?: string;
  readonly expectedAuditCorrelationId?: string;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly handleExpiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface SelectedCredentialPublicMaterialResultValue {
  readonly selectedCredentialPublicMaterialResultId: string;
  readonly requestId: string;
  readonly status: SelectedCredentialPublicMaterialStatus;
  readonly outcome: SelectedCredentialPublicMaterialOutcome;
  readonly operation: SelectedCredentialPublicMaterialOperation;
  readonly verificationContext: "ordinary" | "recovery";
  readonly verificationProfile: SelectedCredentialVerificationProfile;
  readonly verificationHandle: SelectedCredentialVerificationHandleMetadata;
  readonly summary: SelectedCredentialPublicMaterialSummary;
  readonly evidence: SelectedCredentialPublicMaterialEvidence;
  readonly reasons: readonly SelectedCredentialPublicMaterialReason[];
  readonly limitations: readonly SelectedCredentialPublicMaterialLimitation[];
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly containsPrivateMaterial: false;
  readonly containsVaultKey: false;
  readonly containsPhilSecret: false;
  readonly containsRawAssertionPayload: false;
  readonly containsRawRegistrationPayload: false;
  readonly containsAuthorization: false;
  readonly grantsAuthority: false;
  readonly verificationPerformed: false;
  readonly authenticationPerformed: false;
  readonly webAuthnInvoked: false;
  readonly signatureVerified: false;
  readonly credentialCounterMutated: false;
  readonly trustDecisionCreated: false;
  readonly policyDecisionCreated: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type SelectedCredentialPublicMaterialResult =
  RuntimeResult<SelectedCredentialPublicMaterialResultValue>;

export interface TrustManagerCredentialPublicMaterialInput {
  readonly verificationProfile: SelectedCredentialVerificationProfile;
  readonly verificationHandle?: SelectedCredentialVerificationHandleMetadata;
  readonly vaultHandleAvailableToTrustManager: false;
  readonly registryEnumerationAllowed: false;
  readonly makesTrustDecision: false;
}

export interface TrustManagerCredentialVerificationContext {
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly verificationProfileId: string;
  readonly expectedVerificationMethod: "webauthn_assertion";
  readonly publicMaterialOnly: true;
  readonly trustDecisionDeferred: true;
}

const OPERATION: SelectedCredentialPublicMaterialOperation =
  "materialize_selected_credential_public_data";

const DEFAULT_HANDLE_TTL_MS = 5 * 60 * 1000;

const LIMITATIONS: readonly SelectedCredentialPublicMaterialLimitation[] = Object.freeze([
  "single_credential_only",
  "process_local_result",
  "bounded_expiry",
  "public_material_only",
  "no_bulk_export",
  "no_trust_decision",
  "no_authentication",
  "no_authority",
  "no_persistence"
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
  return { valid: errors.length === 0, errors };
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function materialError(
  code: string,
  message: string,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "vault_unavailable",
    code,
    message,
    boundary: "device-vault",
    recoverable: true,
    details: { errors }
  };
}

function resultFlags() {
  return {
    containsPrivateMaterial: false as const,
    containsVaultKey: false as const,
    containsPhilSecret: false as const,
    containsRawAssertionPayload: false as const,
    containsRawRegistrationPayload: false as const,
    containsAuthorization: false as const,
    grantsAuthority: false as const,
    verificationPerformed: false as const
  };
}

function authorityFlags() {
  return {
    authenticationPerformed: false as const,
    webAuthnInvoked: false as const,
    signatureVerified: false as const,
    credentialCounterMutated: false as const,
    trustDecisionCreated: false as const,
    policyDecisionCreated: false as const,
    activeCapabilityCreated: false as const,
    sessionKeyCreated: false as const,
    authorizationCreated: false as const,
    persisted: false as const
  };
}

function classify(status: PhilCredentialStatus | string): PublicCredentialLifecycleClassification {
  if (
    status === "active"
    || status === "pending"
    || status === "recovery-only"
    || status === "revoked"
    || status === "archived"
  ) return status;
  return "unknown";
}

function credentialSafeReference(credentialId: string, ownerCommitment: Hex): Hex {
  return keccak256(toUtf8Bytes(`${ownerCommitment}:${credentialId}`)) as Hex;
}

function normalizeAlgorithm(algorithm: string): "ES256" | undefined {
  return algorithm === "ES256" || algorithm === "-7" ? "ES256" : undefined;
}

function isHex(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/u.test(value) && value.length > 2;
}

function isSupportedPublicVerificationKey(value: unknown): value is Hex {
  if (!isHex(value)) return false;
  const byteLength = (value.length - 2) / 2;
  return Number.isInteger(byteLength) && byteLength >= 65 && byteLength <= 256;
}

function keyFingerprint(publicKey: Hex, fallback?: Hex): Hex {
  return fallback ?? keccak256(publicKey) as Hex;
}

function selectedCredentialId(request: SelectedCredentialPublicMaterialRequest): string | undefined {
  const ids = [
    ...(isNonEmptyString(request.credentialId) ? [request.credentialId] : []),
    ...(Array.isArray(request.credentialIds) ? request.credentialIds.filter(isNonEmptyString) : [])
  ];
  return ids.length === 1 && request.wildcardSelector !== true ? ids[0] : undefined;
}

function selectorErrors(request: SelectedCredentialPublicMaterialRequest): readonly string[] {
  const errors: string[] = [];
  const explicitIds = [
    ...(isNonEmptyString(request.credentialId) ? [request.credentialId] : []),
    ...(Array.isArray(request.credentialIds) ? request.credentialIds.filter(isNonEmptyString) : [])
  ];
  if (request.wildcardSelector === true) errors.push("wildcard credential selector is not supported");
  if (Array.isArray(request.credentialIds) && request.credentialIds.length !== 1) {
    errors.push("exactly one credential ID must be supplied");
  }
  if (explicitIds.length !== 1) errors.push("exactly one credential ID must be supplied");
  return errors;
}

export function sanitizeCredentialRecordToVerificationProfile(input: {
  readonly credential: PhilCredentialRecord;
  readonly ownerCommitment: Hex;
  readonly verificationContext?: "ordinary" | "recovery";
}): SelectedCredentialVerificationProfile {
  const algorithm = normalizeAlgorithm(input.credential.algorithm);
  if (input.credential.providerKind !== "webauthn_passkey") {
    throw new Error("unsupported provider kind");
  }
  if (algorithm !== "ES256") {
    throw new Error("unsupported public key algorithm");
  }
  if (!isSupportedPublicVerificationKey(input.credential.publicKey)) {
    throw new Error("malformed public verification material");
  }
  const lifecycleStatus = classify(input.credential.status);
  const publicKeyFingerprint = keyFingerprint(
    input.credential.publicKey,
    input.credential.publicKeyHash
  );
  const safeReference = credentialSafeReference(
    input.credential.credentialId,
    input.ownerCommitment
  );

  return freezeRecord({
    verificationProfileId: `selected-credential-profile:${safeReference}`,
    verificationProfileVersion: "selected-credential-public-material-v1",
    credentialId: input.credential.credentialId,
    credentialSafeReference: safeReference,
    providerKind: "webauthn_passkey",
    publicKeyAlgorithm: algorithm,
    publicKeyFingerprint,
    verificationKey: {
      materialKind: "webauthn_spki_public_key_hex",
      algorithm,
      publicKey: input.credential.publicKey,
      publicKeyFingerprint,
      encoding: "hex",
      requiredBy: "existing-webauthn-assertion-verifier",
      exportPolicy: "bounded-selected-credential-only",
      containsPrivateMaterial: false
    },
    supportedVerificationMethods: Object.freeze(["webauthn_assertion"] as const),
    credentialLifecycleStatus: lifecycleStatus,
    recoveryOnly: lifecycleStatus === "recovery-only",
    ordinaryUseEligible: lifecycleStatus === "active",
    recoveryUseEligible: lifecycleStatus === "active" || lifecycleStatus === "recovery-only",
    userPresenceRequired: true,
    userVerificationRequired: true,
    signCounter: input.credential.signCount,
    deviceReference: input.credential.deviceKeyId ?? input.credential.credentialId,
    deviceType: input.credential.deviceType,
    ownerCommitment: input.ownerCommitment,
    createdAt: input.credential.createdAt,
    lastUsedAt: input.credential.lastUsedAt,
    ...resultFlags()
  });
}

export function validateSelectedCredentialPublicMaterialRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) {
    return validation(["selected credential public material request must be an object"]);
  }
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (request.operation !== OPERATION) errors.push("unsupported operation");
  errors.push(...selectorErrors(request as unknown as SelectedCredentialPublicMaterialRequest));
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!snapshotValidation.valid) {
    errors.push(...snapshotValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isRecord(request.unlockedVaultHandle)) {
    errors.push("unlocked vault handle is required");
  } else {
    if (!isNonEmptyString(request.unlockedVaultHandle.handleId)) errors.push("handle id is required");
    if (request.unlockedVaultHandle.applicationAccessible !== false) {
      errors.push("handle must not be application accessible");
    }
    if (request.unlockedVaultHandle.containsPlaintext !== false) {
      errors.push("handle must not contain plaintext");
    }
    if (request.unlockedVaultHandle.containsRawVaultKey !== false) {
      errors.push("handle must not contain raw vault key");
    }
    if (request.unlockedVaultHandle.containsPhilSecret !== false) {
      errors.push("handle must not contain Phil root secret");
    }
  }
  if (!isRecord(request.publicCredentialDirectory)) {
    errors.push("publicCredentialDirectory is required");
  }
  if (!isRecord(request.identity)) errors.push("identity is required");
  if (!isRecord(request.envelope) || !isNonEmptyString(request.envelope.encryptedBlob)) {
    errors.push("envelope.encryptedBlob is required");
  }
  if (!isRecord(request.unlockMaterial) || !isRecord(request.unlockMaterial.keyProvider)) {
    errors.push("unlock material keyProvider is required");
  }
  if (
    request.verificationContext !== undefined
    && request.verificationContext !== "ordinary"
    && request.verificationContext !== "recovery"
  ) errors.push("verificationContext is unsupported");
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (request.expiresAt !== undefined && !hasValidDateShape(request.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (request.handleExpiresAt !== undefined && !hasValidDateShape(request.handleExpiresAt)) {
    errors.push("handleExpiresAt must be a parseable date string");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

function outcomeForErrors(errors: readonly string[]): SelectedCredentialPublicMaterialOutcome {
  if (errors.length === 0) return "material_created";
  if (errors.some((error) => error.includes("unsupported operation"))) return "unsupported_operation";
  if (errors.some((error) => error.includes("wildcard") || error.includes("exactly one"))) {
    return "credential_selector_invalid";
  }
  if (errors.some((error) => error.includes("expired"))) return "expired_handle";
  if (errors.some((error) => error.includes("owner"))) return "owner_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_mismatch";
  if (errors.some((error) => error.includes("audit"))) return "audit_correlation_mismatch";
  if (errors.some((error) => error.includes("directory"))) return "directory_correlation_mismatch";
  if (errors.some((error) => error.includes("unlocked lifecycle"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("not found"))) return "credential_not_found";
  if (errors.some((error) => error.includes("recovery context"))) {
    return "credential_recovery_context_required";
  }
  if (errors.some((error) => error.includes("lifecycle"))) return "credential_lifecycle_ineligible";
  if (errors.some((error) => error.includes("provider"))) return "unsupported_provider";
  if (errors.some((error) => error.includes("algorithm"))) return "unsupported_algorithm";
  if (errors.some((error) => error.includes("verification material"))) {
    return "malformed_public_verification_material";
  }
  if (errors.some((error) => error.includes("vault read"))) return "vault_read_failed";
  if (errors.some((error) => error.includes("handle"))) return "invalid_handle";
  return "request_malformed";
}

function statusForOutcome(
  outcome: SelectedCredentialPublicMaterialOutcome
): SelectedCredentialPublicMaterialStatus {
  if (outcome === "material_created") return "material_created";
  if (outcome === "request_malformed" || outcome === "credential_selector_invalid") {
    return "material_malformed";
  }
  if (outcome === "expired_handle") return "material_expired";
  if (outcome === "unsupported_operation" || outcome === "unsupported_provider" || outcome === "unsupported_algorithm") {
    return "material_unsupported";
  }
  return "material_rejected";
}

function auditDraftForSelectedCredential(input: {
  readonly request: SelectedCredentialPublicMaterialRequest;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly errors?: readonly string[];
  readonly profile?: SelectedCredentialVerificationProfile;
  readonly handle?: SelectedCredentialVerificationHandleMetadata;
}): AuditEventDraft {
  const auditCorrelationId = input.request.auditCorrelationId
    ?? input.request.expectedAuditCorrelationId
    ?? createAuditCorrelationId([
      input.request.lifecycleSnapshot?.sessionId ?? "unknown-session",
      input.request.requestId,
      "selected-credential-public-material"
    ]);
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.lifecycleSnapshot?.sessionId,
    applicationId: "ethereum-net",
    summary: input.outcome === "validation_succeeded"
      ? "Selected credential public material was materialized for future verification; no authentication, Trust Decision, or authority was created."
      : "Selected credential public material request was rejected; no credential material was exposed.",
    auditCorrelationId,
    redactedDetails: {
      requestId: input.request.requestId,
      operation: input.request.operation,
      credentialSafeReference: input.profile?.credentialSafeReference,
      providerKind: input.profile?.providerKind,
      lifecycleStatus: input.profile?.credentialLifecycleStatus,
      verificationHandleCreated: input.handle !== undefined,
      verificationHandleId: input.handle?.handleId,
      containsPublicKeyBytes: false,
      containsPrivateMaterial: false,
      containsVaultKey: false,
      containsPhilSecret: false,
      containsRawAssertionPayload: false,
      containsRawRegistrationPayload: false,
      containsAuthorization: false,
      grantsAuthority: false,
      verificationPerformed: false,
      authenticationPerformed: false,
      trustDecisionCreated: false,
      persisted: false,
      requestMetadata: input.request.metadata
        ? redactRuntimeMetadata(input.request.metadata).value
        : undefined,
      errors: input.errors ?? []
    }
  });
}

export function validateSelectedCredentialPublicMaterialResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) {
    return validation(["selected credential public material result must be an object"]);
  }
  if (!isNonEmptyString(result.selectedCredentialPublicMaterialResultId)) {
    errors.push("selectedCredentialPublicMaterialResultId is required");
  }
  if (result.operation !== OPERATION) errors.push("operation is unsupported");
  if (!isRecord(result.verificationProfile)) errors.push("verificationProfile is required");
  if (!isRecord(result.verificationHandle)) errors.push("verificationHandle is required");
  for (const [key, value] of Object.entries({ ...resultFlags(), ...authorityFlags() })) {
    if (result[key] !== value) errors.push(`${key} must be ${String(value)}`);
  }
  if (isRecord(result.verificationProfile)) {
    if (result.verificationProfile.providerKind !== "webauthn_passkey") {
      errors.push("verificationProfile.providerKind must be webauthn_passkey");
    }
    if (result.verificationProfile.verificationPerformed !== false) {
      errors.push("verificationProfile.verificationPerformed must be false");
    }
    if (!isRecord(result.verificationProfile.verificationKey)) {
      errors.push("verificationProfile.verificationKey is required");
    } else {
      if (!isHex(result.verificationProfile.verificationKey.publicKey)) {
        errors.push("verification key publicKey must be normalized hex");
      }
      if (result.verificationProfile.verificationKey.containsPrivateMaterial !== false) {
        errors.push("verification key must not contain private material");
      }
    }
  }
  return validation(errors);
}

export async function materializeSelectedCredentialPublicData(
  request: SelectedCredentialPublicMaterialRequest
): Promise<{
  readonly snapshot?: PhilCredentialRegistrySnapshot;
  readonly credential?: PhilCredentialRecord;
  readonly profile?: SelectedCredentialVerificationProfile;
  readonly errors: readonly string[];
}> {
  const errors: string[] = [];
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend: createInMemoryDeviceIdentityRegistryStorageBackend(request.envelope.encryptedBlob),
    keyProvider: request.unlockMaterial.keyProvider
  });
  let snapshot: PhilCredentialRegistrySnapshot | undefined;
  try {
    snapshot = await store.loadRegistry(request.identity);
  } catch {
    return { errors: Object.freeze(["vault read failed"]) };
  }

  const credentialId = selectedCredentialId(request);
  const credential = snapshot.credentials.find((entry) => entry.credentialId === credentialId);
  if (!credential) {
    return { snapshot, errors: Object.freeze(["credential not found"]) };
  }

  try {
    const descriptor = sanitizeCredentialRecordToPublicDescriptor(credential);
    const profile = sanitizeCredentialRecordToVerificationProfile({
      credential,
      ownerCommitment: request.identity.ownerCommitment,
      verificationContext: request.verificationContext
    });
    if (descriptor.credentialId !== profile.credentialId) {
      errors.push("directory descriptor correlation mismatch");
    }
    return { snapshot, credential, profile, errors: Object.freeze(errors) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "malformed public verification material";
    return { snapshot, credential, errors: Object.freeze([message]) };
  }
}

export async function requestSelectedCredentialPublicMaterial(
  request: SelectedCredentialPublicMaterialRequest,
  auditDraftCollector?: AuditDraftCollector
): Promise<SelectedCredentialPublicMaterialResult> {
  const requestValidation = validateSelectedCredentialPublicMaterialRequest(request);
  if (!requestValidation.valid || request.operation !== OPERATION) {
    const errors = requestValidation.errors;
    const outcome = request.operation === OPERATION ? "malformed" : "unsupported";
    const auditEventDraft = auditDraftForSelectedCredential({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(materialError(
      "SELECTED_CREDENTIAL_PUBLIC_MATERIAL_INVALID",
      "selected credential public material request failed validation",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const errors: string[] = [];
  const handle = request.unlockedVaultHandle;
  const directory = request.publicCredentialDirectory;
  const credentialId = selectedCredentialId(request);
  const verificationContext = request.verificationContext ?? "ordinary";
  if (request.lifecycleSnapshot.state !== "unlocked") {
    errors.push("unlocked lifecycle snapshot is required");
  }
  if (request.lifecycleSnapshot.metadata?.deviceVaultUnlocked !== true) {
    errors.push("device vault unlocked metadata is required");
  }
  if (request.lifecycleSnapshot.metadata?.protectedStateAvailable !== true) {
    errors.push("protected state available metadata is required");
  }
  if (request.lifecycleSnapshot.sessionId !== handle.sessionId) errors.push("session mismatch");
  if (request.expectedSessionId !== undefined && request.expectedSessionId !== handle.sessionId) {
    errors.push("session mismatch");
  }
  if (request.identity.ownerCommitment !== handle.ownerCommitment) errors.push("owner mismatch");
  if (request.expectedOwnerCommitment !== undefined
    && request.expectedOwnerCommitment !== handle.ownerCommitment) {
    errors.push("owner mismatch");
  }
  if (request.envelope.ownerCommitment !== undefined
    && request.envelope.ownerCommitment !== handle.ownerCommitment) {
    errors.push("owner mismatch");
  }
  const auditCorrelationId = request.auditCorrelationId
    ?? request.expectedAuditCorrelationId
    ?? createAuditCorrelationId([
      handle.sessionId,
      request.requestId,
      "selected-credential-public-material"
    ]);
  if (request.expectedAuditCorrelationId !== undefined
    && request.expectedAuditCorrelationId !== auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (directory.auditCorrelationId !== auditCorrelationId) {
    errors.push("directory audit correlation mismatch");
  }
  if (directory.containsPrivateMaterial !== false || directory.grantsAuthority !== false) {
    errors.push("directory result must be sanitized and non-authoritative");
  }
  if (directory.descriptors.filter((descriptor) => descriptor.credentialId === credentialId).length !== 1) {
    errors.push("directory descriptor for selected credential not found");
  }
  if (expired(handle.expiresAt) || expired(request.expiresAt)) errors.push("expired handle");

  let profile: SelectedCredentialVerificationProfile | undefined;
  if (errors.length === 0) {
    const materialized = await materializeSelectedCredentialPublicData(request);
    errors.push(...materialized.errors);
    profile = materialized.profile;
  }
  if (profile) {
    if (profile.credentialLifecycleStatus === "revoked" || profile.credentialLifecycleStatus === "archived") {
      errors.push("credential lifecycle status is ineligible");
    }
    if (profile.credentialLifecycleStatus === "recovery-only" && verificationContext !== "recovery") {
      errors.push("recovery-only credential requires explicit recovery context");
    }
    if (profile.credentialLifecycleStatus !== "active"
      && !(profile.credentialLifecycleStatus === "recovery-only" && verificationContext === "recovery")) {
      errors.push("credential lifecycle status is ineligible");
    }
  }

  if (!profile || errors.length > 0) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForSelectedCredential({
      request,
      outcome: outcome === "unsupported_operation" ? "unsupported" : "validation_failed",
      errors,
      profile
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(materialError(
      "SELECTED_CREDENTIAL_PUBLIC_MATERIAL_REJECTED",
      "selected credential public material request was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const createdAt = request.requestedAt ?? new Date().toISOString();
  const expiresAt = request.handleExpiresAt
    ?? new Date(Date.parse(createdAt) + DEFAULT_HANDLE_TTL_MS).toISOString();
  const handleMetadata: SelectedCredentialVerificationHandleMetadata = freezeRecord({
    handleId: createAuditCorrelationId([
      auditCorrelationId,
      profile.credentialId,
      "selected-credential-verification-handle"
    ]),
    verificationProfileId: profile.verificationProfileId,
    credentialId: profile.credentialId,
    sessionId: handle.sessionId,
    ownerCommitment: handle.ownerCommitment,
    createdAt,
    expiresAt,
    processLocal: true,
    serializable: false,
    persistent: false,
    singleCredentialOnly: true,
    containsPrivateMaterial: false,
    containsVaultKey: false,
    containsPhilSecret: false,
    grantsAuthority: false
  });
  const auditEventDraft = auditDraftForSelectedCredential({
    request,
    outcome: "validation_succeeded",
    profile,
    handle: handleMetadata
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const value: SelectedCredentialPublicMaterialResultValue = freezeRecord({
    selectedCredentialPublicMaterialResultId: `${auditCorrelationId}:${profile.credentialSafeReference}`,
    requestId: request.requestId,
    status: "material_created",
    outcome: "material_created",
    operation: OPERATION,
    verificationContext,
    verificationProfile: profile,
    verificationHandle: handleMetadata,
    summary: {
      credentialId: profile.credentialId,
      credentialSafeReference: profile.credentialSafeReference,
      providerKind: profile.providerKind,
      publicKeyAlgorithm: profile.publicKeyAlgorithm,
      publicKeyFingerprint: profile.publicKeyFingerprint,
      lifecycleStatus: profile.credentialLifecycleStatus,
      recoveryOnly: profile.recoveryOnly,
      supportedVerificationMethods: profile.supportedVerificationMethods,
      verificationHandleCreated: true,
      publicKeyReturnedForVerifier: true,
      ...resultFlags()
    },
    evidence: {
      directoryResultId: directory.publicCredentialDirectoryResultId,
      descriptorId: `public-credential:${profile.credentialId}`,
      vaultHandleId: handle.handleId,
      sessionId: handle.sessionId,
      ownerCommitment: handle.ownerCommitment,
      credentialSafeReference: profile.credentialSafeReference,
      registryRecordReturned: false,
      verifierReadyPublicKeyIncluded: true,
      privateMaterialIncluded: false
    },
    reasons: Object.freeze([
      "exactly-one-credential-selected",
      "allowlisted-verification-profile",
      "existing-registry-load-reused",
      "existing-public-directory-required",
      "existing-webauthn-verifier-requires-public-key",
      "no-authentication",
      "no-webauthn-execution",
      "no-signature-verification",
      "no-trust-decision",
      "no-authority",
      "no-private-material"
    ]),
    limitations: LIMITATIONS,
    createdAt,
    expiresAt,
    auditCorrelationId,
    ...resultFlags(),
    ...authorityFlags(),
    auditEventDraft,
    auditDraftCollectionResult
  });

  const resultValidation = validateSelectedCredentialPublicMaterialResultShape(value);
  if (!resultValidation.valid) {
    return runtimeDenied(materialError(
      "SELECTED_CREDENTIAL_PUBLIC_MATERIAL_RESULT_INVALID",
      "selected credential public material result failed validation",
      resultValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  return runtimeOk(value);
}
