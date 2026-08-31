import { keccak256, toUtf8Bytes } from "ethers";

import { createAuditEventDraft, type AuditDraftCollectionResult, type AuditDraftCollector, type AuditEventDraft } from "./audit.ts";
import {
  createAuditCorrelationId,
  createUserSessionContext,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionLifecycleEvidenceReference,
  UserSessionLifecycleLimitation,
  UserSessionLifecycleSnapshot,
  UserSessionLifecycleState,
  UserSessionTransitionRequest,
  UserSessionTransitionResult
} from "./sessionLifecycle.ts";
import {
  validateUserSessionLifecycleSnapshotShape,
  validateUserSessionTransitionRequestShape
} from "./sessionLifecycle.ts";
import {
  PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT,
  PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend,
  encryptedBlobOwnerCommitment,
  type PhilDeviceIdentityRegistryKeyProvider
} from "../deviceIdentityStorage.ts";
import type {
  PhilDeviceIdentityKeyLifecycleState,
  PhilDeviceIdentityStorageKeyMetadata
} from "../deviceIdentityKeyLifecycle.ts";
import type { PhilIdentityPublic } from "../identity.ts";
import type { Hex } from "../hashes.ts";
import type {
  RuntimeErrorDescriptor,
  RuntimeResult,
  UserSessionContext,
  UserSessionContextInput,
  UserSessionContextResult
} from "./types.ts";

export type DeviceVaultUnlockStatus =
  | "vault_unlock_verified"
  | "vault_unlock_rejected"
  | "vault_unlock_malformed"
  | "vault_unlock_expired"
  | "vault_unlock_replayed"
  | "vault_unlock_unsupported";

export type DeviceVaultUnlockOutcome =
  | "vault_unlock_verified"
  | "vault_unlock_rejected"
  | "vault_envelope_malformed"
  | "unlock_material_malformed"
  | "unlock_material_incorrect"
  | "owner_binding_mismatch"
  | "session_correlation_mismatch"
  | "audit_correlation_mismatch"
  | "lifecycle_state_ineligible"
  | "key_lifecycle_ineligible"
  | "vault_version_unsupported"
  | "vault_integrity_failed"
  | "vault_unlock_expired"
  | "vault_unlock_replayed"
  | "unsupported";

export type DeviceVaultUnlockReason =
  | "explicit-in-memory-vault-envelope"
  | "explicit-unlock-material"
  | "existing-encrypted-registry-validation-reused"
  | "vault-unlock-verified"
  | "request-shape-invalid"
  | "lifecycle-state-ineligible"
  | "owner-binding-mismatch"
  | "session-correlation-mismatch"
  | "audit-correlation-mismatch"
  | "vault-envelope-malformed"
  | "vault-version-unsupported"
  | "key-lifecycle-ineligible"
  | "unlock-material-incorrect"
  | "vault-integrity-failed"
  | "vault-unlock-expired"
  | "vault-unlock-replayed"
  | (string & {});

export interface DeviceVaultEnvelopeReference {
  readonly envelopeId: string;
  readonly encryptedBlob: string;
  readonly format?: string;
  readonly version?: number;
  readonly ownerCommitment?: Hex;
  readonly keyVersion?: number;
  readonly integrityHash?: Hex;
  readonly createdAt?: string;
  readonly expiresAt?: string;
}

export interface DeviceVaultUnlockMaterialReference {
  readonly materialId: string;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyVersion?: number;
  readonly providerKind?: string;
  readonly unsafeForProduction?: boolean;
  readonly expiresAt?: string;
}

export interface DeviceVaultUnlockCorrelation {
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly lifecycleTransitionRequestId?: string;
  readonly applicationId?: string;
  readonly auditCorrelationId?: string;
}

export interface DeviceVaultUnlockRequirement {
  readonly requirementId: string;
  readonly satisfied: boolean;
  readonly description: string;
}

export interface DeviceVaultUnlockLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface DeviceVaultUnlockEvidenceSummary {
  readonly envelopeId: string;
  readonly envelopeFormat?: string;
  readonly envelopeVersion?: number;
  readonly envelopeOwnerCommitment?: Hex;
  readonly envelopeIntegrityHash: Hex;
  readonly keyProviderKind: string;
  readonly keyProviderUnsafeForProduction: boolean;
  readonly keyVersion?: number;
  readonly keyStatus?: PhilDeviceIdentityStorageKeyMetadata["status"];
  readonly registryAuthenticated: boolean;
  readonly plaintextReturned: false;
}

export type UnlockedDeviceVaultHandleId = string;

export interface UnlockedDeviceVaultHandleMetadata {
  readonly handleId: UnlockedDeviceVaultHandleId;
  readonly sessionId: string;
  readonly ownerCommitment: Hex;
  readonly envelopeId: string;
  readonly unlockResultId: string;
  readonly unlockedAt: string;
  readonly expiresAt?: string;
  readonly processLocal: true;
  readonly serializable: false;
  readonly exportable: false;
  readonly containsPlaintext: false;
  readonly containsRawVaultKey: false;
  readonly containsPhilSecret: false;
  readonly applicationAccessible: false;
}

export interface DeviceVaultUnlockRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly userSessionContext?: UserSessionContext;
  readonly identity: PhilIdentityPublic;
  readonly envelope: DeviceVaultEnvelopeReference;
  readonly unlockMaterial: DeviceVaultUnlockMaterialReference;
  readonly correlation: DeviceVaultUnlockCorrelation;
  readonly keyLifecycle?: PhilDeviceIdentityKeyLifecycleState;
  readonly expectedOwnerCommitment?: Hex;
  readonly expectedSessionId?: string;
  readonly expectedAuditCorrelationId?: string;
  readonly expectedIntegrityHash?: Hex;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface DeviceVaultUnlockResultValue {
  readonly vaultUnlockResultId: string;
  readonly requestId: string;
  readonly status: DeviceVaultUnlockStatus;
  readonly outcome: DeviceVaultUnlockOutcome;
  readonly reasons: readonly DeviceVaultUnlockReason[];
  readonly requirements: readonly DeviceVaultUnlockRequirement[];
  readonly limitations: readonly DeviceVaultUnlockLimitation[];
  readonly evidenceSummary: DeviceVaultUnlockEvidenceSummary;
  readonly correlation: DeviceVaultUnlockCorrelation;
  readonly unlockedVaultHandle?: UnlockedDeviceVaultHandleMetadata;
  readonly verifiedAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly deviceVaultUnlocked: boolean;
  readonly protectedStateAvailable: boolean;
  readonly philSecretExposed: false;
  readonly rawVaultKeyExposed: false;
  readonly applicationCredentialsLoaded: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persistedRuntimeState: false;
}

export type DeviceVaultUnlockResult = RuntimeResult<DeviceVaultUnlockResultValue>;

export interface VaultUnlockConsumptionRecord {
  readonly vaultUnlockResultId: string;
  readonly consumedAt: string;
  readonly auditCorrelationId?: string;
}

export type VaultUnlockConsumptionStatus = "consumed" | "replayed" | "cleared";

export interface VaultUnlockConsumptionResult {
  readonly status: VaultUnlockConsumptionStatus;
  readonly record?: VaultUnlockConsumptionRecord;
  readonly records: readonly VaultUnlockConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralVaultUnlockConsumptionStore {
  consume(vaultUnlockResultId: string, auditCorrelationId?: string): VaultUnlockConsumptionResult;
  has(vaultUnlockResultId: string): boolean;
  get(vaultUnlockResultId: string): VaultUnlockConsumptionRecord | undefined;
  getAll(): readonly VaultUnlockConsumptionRecord[];
  clear(): VaultUnlockConsumptionResult;
}

export interface VerifiedVaultSessionUnlockRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly transitionRequest: UserSessionTransitionRequest;
  readonly vaultUnlockResult: DeviceVaultUnlockResultValue;
  readonly consumptionStore?: EphemeralVaultUnlockConsumptionStore;
  readonly auditDraftCollector?: AuditDraftCollector;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface VerifiedVaultSessionUnlockResultValue {
  readonly transitionResult: UserSessionTransitionResult;
  readonly vaultUnlockResult: DeviceVaultUnlockResultValue;
  readonly consumed?: VaultUnlockConsumptionResult;
  readonly auditEventDraft: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly deviceVaultUnlocked: true;
  readonly protectedStateAvailable: true;
  readonly philSecretExposed: false;
  readonly rawVaultKeyExposed: false;
  readonly applicationCredentialsLoaded: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persistedRuntimeState: false;
}

export type VerifiedVaultSessionUnlockResult =
  RuntimeResult<VerifiedVaultSessionUnlockResultValue>;

export interface VerifiedVaultUnlockContextInput {
  readonly userSessionContext: UserSessionContext;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly vaultUnlockResult: DeviceVaultUnlockResultValue;
}

const DEFAULT_LIMITATIONS: readonly DeviceVaultUnlockLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "explicit_inputs_only",
    description: "Vault unlock consumes explicit in-memory envelope and unlock material only."
  }),
  Object.freeze({
    limitationId: "no_secret_export",
    description: "The result does not expose root identity secrets, vault key material, decrypted registry plaintext, or credential private material."
  }),
  Object.freeze({
    limitationId: "no_application_authority",
    description: "Unlocking the vault does not create active capabilities, session keys, authorization packages, or adapter execution."
  }),
  Object.freeze({
    limitationId: "process_local_handle",
    description: "Unlocked vault handle metadata is opaque, process-local, non-serializable, and not application-accessible."
  }),
  Object.freeze({
    limitationId: "process_local_replay_tracking",
    description: "Replay consumption is process-local only and is not durable replay prevention."
  })
]);

const UNLOCKED_SNAPSHOT_LIMITATIONS: readonly UserSessionLifecycleLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "device_vault_unlocked",
    description: "Device Vault was authenticated from explicit in-memory unlock material."
  }),
  Object.freeze({
    limitationId: "protected_state_handle_only",
    description: "Protected state is available only through an opaque process-local handle."
  }),
  Object.freeze({
    limitationId: "no_application_authority",
    description: "No active capability, session key, authorization, proof, or adapter execution was created."
  }),
  Object.freeze({
    limitationId: "no_persistence",
    description: "Unlocked runtime session state is process-local in this milestone."
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

function vaultError(
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

function hashEnvelope(encryptedBlob: string): Hex {
  return keccak256(toUtf8Bytes(encryptedBlob)) as Hex;
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function parseEnvelope(encryptedBlob: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(encryptedBlob);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function keyMetadataFor(
  lifecycle: PhilDeviceIdentityKeyLifecycleState | undefined,
  keyVersion: number | undefined
): PhilDeviceIdentityStorageKeyMetadata | undefined {
  if (!lifecycle || keyVersion === undefined) return undefined;
  return lifecycle.storageKeys.find((key) => key.keyVersion === keyVersion);
}

function requirementsFor(errors: readonly string[]): readonly DeviceVaultUnlockRequirement[] {
  return freezeRecord([
    {
      requirementId: "partial-session",
      satisfied: !errors.some((error) => error.includes("partially_unlocked")),
      description: "Current lifecycle state must be partially_unlocked."
    },
    {
      requirementId: "owner-bound-envelope",
      satisfied: !errors.some((error) => error.includes("owner")),
      description: "Vault envelope must be bound to the expected owner commitment."
    },
    {
      requirementId: "active-key-lifecycle",
      satisfied: !errors.some((error) => error.includes("key lifecycle")),
      description: "The supplied vault key lifecycle metadata must be active."
    },
    {
      requirementId: "authenticated-decrypt",
      satisfied: !errors.some((error) => error.includes("decrypt") || error.includes("integrity")),
      description: "Existing encrypted registry validation must authenticate the envelope."
    }
  ]);
}

function outcomeForErrors(errors: readonly string[]): DeviceVaultUnlockOutcome {
  if (errors.length === 0) return "vault_unlock_verified";
  if (errors.some((error) => error.includes("envelope malformed"))) return "vault_envelope_malformed";
  if (errors.some((error) => error.includes("unlock material"))) return "unlock_material_malformed";
  if (errors.some((error) => error.includes("incorrect"))) return "unlock_material_incorrect";
  if (errors.some((error) => error.includes("owner"))) return "owner_binding_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_correlation_mismatch";
  if (errors.some((error) => error.includes("audit"))) return "audit_correlation_mismatch";
  if (errors.some((error) => error.includes("partially_unlocked"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("key lifecycle"))) return "key_lifecycle_ineligible";
  if (errors.some((error) => error.includes("version"))) return "vault_version_unsupported";
  if (errors.some((error) => error.includes("integrity"))) return "vault_integrity_failed";
  if (errors.some((error) => error.includes("expired"))) return "vault_unlock_expired";
  if (errors.some((error) => error.includes("replayed"))) return "vault_unlock_replayed";
  return "vault_unlock_rejected";
}

function statusForOutcome(outcome: DeviceVaultUnlockOutcome): DeviceVaultUnlockStatus {
  if (outcome === "vault_unlock_verified") return "vault_unlock_verified";
  if (outcome === "vault_envelope_malformed" || outcome === "unlock_material_malformed") {
    return "vault_unlock_malformed";
  }
  if (outcome === "vault_unlock_expired") return "vault_unlock_expired";
  if (outcome === "vault_unlock_replayed") return "vault_unlock_replayed";
  if (outcome === "unsupported") return "vault_unlock_unsupported";
  return "vault_unlock_rejected";
}

function reasonsForErrors(errors: readonly string[]): readonly DeviceVaultUnlockReason[] {
  const reasons: DeviceVaultUnlockReason[] = [
    "explicit-in-memory-vault-envelope",
    "explicit-unlock-material",
    "existing-encrypted-registry-validation-reused"
  ];
  if (errors.length === 0) {
    reasons.push("vault-unlock-verified");
    return Object.freeze(reasons);
  }
  if (errors.some((error) => error.includes("request"))) reasons.push("request-shape-invalid");
  if (errors.some((error) => error.includes("partially_unlocked"))) reasons.push("lifecycle-state-ineligible");
  if (errors.some((error) => error.includes("owner"))) reasons.push("owner-binding-mismatch");
  if (errors.some((error) => error.includes("session"))) reasons.push("session-correlation-mismatch");
  if (errors.some((error) => error.includes("audit"))) reasons.push("audit-correlation-mismatch");
  if (errors.some((error) => error.includes("envelope"))) reasons.push("vault-envelope-malformed");
  if (errors.some((error) => error.includes("version"))) reasons.push("vault-version-unsupported");
  if (errors.some((error) => error.includes("key lifecycle"))) reasons.push("key-lifecycle-ineligible");
  if (errors.some((error) => error.includes("incorrect"))) reasons.push("unlock-material-incorrect");
  if (errors.some((error) => error.includes("integrity"))) reasons.push("vault-integrity-failed");
  if (errors.some((error) => error.includes("expired"))) reasons.push("vault-unlock-expired");
  if (errors.some((error) => error.includes("replayed"))) reasons.push("vault-unlock-replayed");
  return Object.freeze(reasons);
}

function evidenceSummary(input: {
  request: DeviceVaultUnlockRequest;
  registryAuthenticated: boolean;
  envelopeOwner?: Hex;
  keyStatus?: PhilDeviceIdentityStorageKeyMetadata["status"];
}): DeviceVaultUnlockEvidenceSummary {
  return freezeRecord({
    envelopeId: input.request.envelope.envelopeId,
    envelopeFormat: input.request.envelope.format,
    envelopeVersion: input.request.envelope.version,
    envelopeOwnerCommitment: input.envelopeOwner ?? input.request.envelope.ownerCommitment,
    envelopeIntegrityHash: input.request.envelope.integrityHash
      ?? hashEnvelope(input.request.envelope.encryptedBlob),
    keyProviderKind: input.request.unlockMaterial.providerKind
      ?? input.request.unlockMaterial.keyProvider.providerKind,
    keyProviderUnsafeForProduction: input.request.unlockMaterial.unsafeForProduction
      ?? input.request.unlockMaterial.keyProvider.unsafeForProduction,
    keyVersion: input.request.unlockMaterial.keyVersion,
    keyStatus: input.keyStatus,
    registryAuthenticated: input.registryAuthenticated,
    plaintextReturned: false
  });
}

function handleFor(input: {
  request: DeviceVaultUnlockRequest;
  vaultUnlockResultId: string;
  verifiedAt: string;
  expiresAt?: string;
}): UnlockedDeviceVaultHandleMetadata {
  return freezeRecord({
    handleId: `${input.vaultUnlockResultId}:vault-handle`,
    sessionId: input.request.correlation.sessionId,
    ownerCommitment: input.request.identity.ownerCommitment,
    envelopeId: input.request.envelope.envelopeId,
    unlockResultId: input.vaultUnlockResultId,
    unlockedAt: input.verifiedAt,
    expiresAt: input.expiresAt,
    processLocal: true,
    serializable: false,
    exportable: false,
    containsPlaintext: false,
    containsRawVaultKey: false,
    containsPhilSecret: false,
    applicationAccessible: false
  });
}

export function validateDeviceVaultUnlockRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["device vault unlock request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!snapshotValidation.valid) {
    errors.push(...snapshotValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isRecord(request.identity)) errors.push("identity is required");
  if (isRecord(request.identity)) {
    if (!isNonEmptyString(request.identity.ownerCommitment)) errors.push("identity.ownerCommitment is required");
    if (!isNonEmptyString(request.identity.identityRoot)) errors.push("identity.identityRoot is required");
  }
  if (!isRecord(request.envelope)) {
    errors.push("envelope is required");
  } else {
    if (!isNonEmptyString(request.envelope.envelopeId)) errors.push("envelope.envelopeId is required");
    if (!isNonEmptyString(request.envelope.encryptedBlob)) errors.push("envelope.encryptedBlob is required");
    if (request.envelope.expiresAt !== undefined && !hasValidDateShape(request.envelope.expiresAt)) {
      errors.push("envelope.expiresAt must be a parseable date string");
    }
  }
  if (!isRecord(request.unlockMaterial)) {
    errors.push("unlock material is required");
  } else {
    if (!isNonEmptyString(request.unlockMaterial.materialId)) errors.push("unlock material id is required");
    if (!isRecord(request.unlockMaterial.keyProvider)) errors.push("unlock material keyProvider is required");
  }
  if (!isRecord(request.correlation)) {
    errors.push("correlation is required");
  } else {
    if (!isNonEmptyString(request.correlation.sessionId)) errors.push("correlation.sessionId is required");
    if (!isNonEmptyString(request.correlation.ownerCommitment)) {
      errors.push("correlation.ownerCommitment is required");
    }
  }
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

export function validateDeviceVaultUnlockResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["device vault unlock result must be an object"]);
  if (!isNonEmptyString(result.vaultUnlockResultId)) errors.push("vaultUnlockResultId is required");
  if (!isNonEmptyString(result.requestId)) errors.push("requestId is required");
  if (result.outcome === "vault_unlock_verified") {
    if (result.deviceVaultUnlocked !== true) errors.push("deviceVaultUnlocked must be true");
    if (result.protectedStateAvailable !== true) errors.push("protectedStateAvailable must be true");
    if (!isRecord(result.unlockedVaultHandle)) errors.push("unlockedVaultHandle is required");
  }
  if (result.philSecretExposed !== false) errors.push("philSecretExposed must be false");
  if (result.rawVaultKeyExposed !== false) errors.push("rawVaultKeyExposed must be false");
  if (result.applicationCredentialsLoaded !== false) errors.push("applicationCredentialsLoaded must be false");
  if (result.activeCapabilityCreated !== false) errors.push("activeCapabilityCreated must be false");
  if (result.sessionKeyCreated !== false) errors.push("sessionKeyCreated must be false");
  if (result.authorizationCreated !== false) errors.push("authorizationCreated must be false");
  if (result.persistedRuntimeState !== false) errors.push("persistedRuntimeState must be false");
  return validation(errors);
}

export async function verifyDeviceVaultUnlock(
  request: DeviceVaultUnlockRequest
): Promise<DeviceVaultUnlockResult> {
  const requestValidation = validateDeviceVaultUnlockRequest(request);
  if (!requestValidation.valid) {
    return runtimeDenied(vaultError(
      "DEVICE_VAULT_UNLOCK_INVALID",
      "device vault unlock request failed validation",
      requestValidation.errors
    ));
  }

  const errors: string[] = [];
  const parsedEnvelope = parseEnvelope(request.envelope.encryptedBlob);
  const envelopeHash = hashEnvelope(request.envelope.encryptedBlob);
  let envelopeOwner: Hex | undefined;
  if (!parsedEnvelope) {
    errors.push("vault envelope malformed");
  } else {
    if (parsedEnvelope.format !== PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT) {
      errors.push("vault envelope malformed format");
    }
    if (parsedEnvelope.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
      errors.push("vault version unsupported");
    }
    try {
      envelopeOwner = encryptedBlobOwnerCommitment(request.envelope.encryptedBlob);
    } catch {
      errors.push("vault envelope malformed owner");
    }
  }
  if (request.lifecycleSnapshot.state !== "partially_unlocked") {
    errors.push("lifecycle state must be partially_unlocked");
  }
  if (request.correlation.sessionId !== request.lifecycleSnapshot.sessionId) errors.push("session mismatch");
  if (request.expectedSessionId !== undefined && request.expectedSessionId !== request.correlation.sessionId) {
    errors.push("session mismatch");
  }
  if (request.correlation.ownerCommitment !== request.identity.ownerCommitment) errors.push("owner mismatch");
  if (request.expectedOwnerCommitment !== undefined && request.expectedOwnerCommitment !== request.identity.ownerCommitment) {
    errors.push("owner mismatch");
  }
  if (request.envelope.ownerCommitment !== undefined && request.envelope.ownerCommitment !== request.identity.ownerCommitment) {
    errors.push("owner mismatch");
  }
  if (envelopeOwner !== undefined && envelopeOwner !== request.identity.ownerCommitment) {
    errors.push("owner mismatch");
  }
  if (
    request.expectedAuditCorrelationId !== undefined
    && request.correlation.auditCorrelationId !== request.expectedAuditCorrelationId
  ) errors.push("audit correlation mismatch");
  if (request.expectedIntegrityHash !== undefined && request.expectedIntegrityHash !== envelopeHash) {
    errors.push("vault integrity failed");
  }
  if (request.envelope.integrityHash !== undefined && request.envelope.integrityHash !== envelopeHash) {
    errors.push("vault integrity failed");
  }
  if (expired(request.expiresAt) || expired(request.envelope.expiresAt) || expired(request.unlockMaterial.expiresAt)) {
    errors.push("vault unlock expired");
  }
  const keyMetadata = keyMetadataFor(
    request.keyLifecycle,
    request.unlockMaterial.keyVersion ?? request.envelope.keyVersion
  );
  if (request.keyLifecycle !== undefined) {
    if (keyMetadata === undefined) {
      errors.push("key lifecycle missing supplied key version");
    } else if (keyMetadata.status !== "active") {
      errors.push("key lifecycle ineligible");
    }
  }

  if (errors.length === 0) {
    try {
      const store = createEncryptedDeviceIdentityRegistryStore({
        backend: createInMemoryDeviceIdentityRegistryStorageBackend(request.envelope.encryptedBlob),
        keyProvider: request.unlockMaterial.keyProvider
      });
      await store.validateRegistry(request.identity);
    } catch {
      errors.push("unlock material incorrect or vault integrity failed");
    }
  }

  const outcome = outcomeForErrors(errors);
  const status = statusForOutcome(outcome);
  const verifiedAt = request.requestedAt ?? new Date().toISOString();
  const auditCorrelationId = request.auditCorrelationId
    ?? request.correlation.auditCorrelationId
    ?? createAuditCorrelationId([
      request.correlation.sessionId,
      request.requestId,
      "device-vault-unlock"
    ]);
  const vaultUnlockResultId = `${auditCorrelationId}:device-vault-unlock`;
  const handle = outcome === "vault_unlock_verified"
    ? handleFor({
      request,
      vaultUnlockResultId,
      verifiedAt,
      expiresAt: request.expiresAt
    })
    : undefined;
  const result: DeviceVaultUnlockResultValue = freezeRecord({
    vaultUnlockResultId,
    requestId: request.requestId,
    status,
    outcome,
    reasons: reasonsForErrors(errors),
    requirements: requirementsFor(errors),
    limitations: DEFAULT_LIMITATIONS,
    evidenceSummary: evidenceSummary({
      request,
      registryAuthenticated: outcome === "vault_unlock_verified",
      envelopeOwner,
      keyStatus: keyMetadata?.status
    }),
    correlation: freezeRecord({
      ...request.correlation,
      auditCorrelationId
    }),
    unlockedVaultHandle: handle,
    verifiedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId,
    deviceVaultUnlocked: outcome === "vault_unlock_verified",
    protectedStateAvailable: outcome === "vault_unlock_verified",
    philSecretExposed: false,
    rawVaultKeyExposed: false,
    applicationCredentialsLoaded: false,
    activeCapabilityCreated: false,
    sessionKeyCreated: false,
    authorizationCreated: false,
    persistedRuntimeState: false
  });
  const resultValidation = validateDeviceVaultUnlockResultShape(result);
  if (!resultValidation.valid) {
    return runtimeDenied(vaultError(
      "DEVICE_VAULT_UNLOCK_RESULT_INVALID",
      "device vault unlock result failed validation",
      resultValidation.errors
    ));
  }
  if (outcome !== "vault_unlock_verified") {
    return runtimeDenied(vaultError(
      "DEVICE_VAULT_UNLOCK_REJECTED",
      "device vault unlock was rejected",
      errors
    ));
  }
  return runtimeOk(result);
}

export function createEphemeralVaultUnlockConsumptionStore():
  EphemeralVaultUnlockConsumptionStore {
  const records = new Map<string, VaultUnlockConsumptionRecord>();

  function all(): readonly VaultUnlockConsumptionRecord[] {
    return Object.freeze(Array.from(records.values()));
  }

  return {
    consume(vaultUnlockResultId, auditCorrelationId) {
      if (records.has(vaultUnlockResultId)) {
        return freezeRecord({
          status: "replayed",
          record: records.get(vaultUnlockResultId),
          records: all(),
          reason: "Device Vault unlock result was already consumed in this process-local store."
        });
      }
      const record = freezeRecord({
        vaultUnlockResultId,
        consumedAt: new Date().toISOString(),
        auditCorrelationId
      });
      records.set(vaultUnlockResultId, record);
      return freezeRecord({
        status: "consumed",
        record,
        records: all()
      });
    },
    has(vaultUnlockResultId) {
      return records.has(vaultUnlockResultId);
    },
    get(vaultUnlockResultId) {
      return records.get(vaultUnlockResultId);
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

function evidenceReferenceForVaultUnlock(
  result: DeviceVaultUnlockResultValue
): UserSessionLifecycleEvidenceReference {
  return freezeRecord({
    referenceId: `${result.vaultUnlockResultId}:evidence-reference`,
    kind: "unlock_evidence",
    source: "device-vault-unlock",
    capturedAt: result.verifiedAt,
    metadata: {
      vaultUnlockResultId: result.vaultUnlockResultId,
      vaultHandleId: result.unlockedVaultHandle?.handleId,
      envelopeId: result.evidenceSummary.envelopeId,
      deviceVaultUnlocked: true,
      protectedStateAvailable: true,
      philSecretExposed: false,
      rawVaultKeyExposed: false,
      applicationCredentialsLoaded: false
    },
    verified: false,
    rawEvidenceIncluded: false
  });
}

function transitionAuditDraft(input: {
  readonly request: VerifiedVaultSessionUnlockRequest;
  readonly status: "validation_succeeded" | "validation_failed";
  readonly nextSnapshot?: UserSessionLifecycleSnapshot;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.status,
    requestKind: "generic",
    sessionId: input.request.lifecycleSnapshot.sessionId,
    summary: input.status === "validation_succeeded"
      ? "Device Vault unlock lifecycle transition completed; no capability or authorization was created."
      : "Device Vault unlock lifecycle transition was rejected.",
    auditCorrelationId: input.request.auditCorrelationId
      ?? input.request.vaultUnlockResult.auditCorrelationId,
    redactedDetails: {
      vaultUnlockResultId: input.request.vaultUnlockResult.vaultUnlockResultId,
      vaultHandleId: input.request.vaultUnlockResult.unlockedVaultHandle?.handleId,
      previousState: input.request.lifecycleSnapshot.state,
      requestedEvent: input.request.transitionRequest.event,
      nextState: input.nextSnapshot?.state,
      transitionRequestId: input.request.transitionRequest.transitionRequestId,
      deviceVaultUnlocked: input.status === "validation_succeeded",
      protectedStateAvailable: input.status === "validation_succeeded",
      philSecretExposed: false,
      rawVaultKeyExposed: false,
      applicationCredentialsLoaded: false,
      activeCapabilityCreated: false,
      sessionKeyCreated: false,
      authorizationCreated: false,
      persistedRuntimeState: false,
      errors: input.errors ?? []
    }
  });
}

export function transitionUserSessionWithVerifiedVaultUnlock(
  request: VerifiedVaultSessionUnlockRequest
): VerifiedVaultSessionUnlockResult {
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  const transitionValidation = validateUserSessionTransitionRequestShape(request.transitionRequest);
  const unlockValidation = validateDeviceVaultUnlockResultShape(request.vaultUnlockResult);
  const errors = [
    ...snapshotValidation.errors,
    ...transitionValidation.errors,
    ...unlockValidation.errors
  ];
  if (request.lifecycleSnapshot.state !== "partially_unlocked") {
    errors.push("lifecycle state must be partially_unlocked");
  }
  if (request.transitionRequest.event !== "unlock_succeeded") {
    errors.push("transition unsupported: only unlock_succeeded is permitted");
  }
  if (request.vaultUnlockResult.outcome !== "vault_unlock_verified") {
    errors.push("vault unlock result was not verified");
  }
  if (request.vaultUnlockResult.deviceVaultUnlocked !== true) {
    errors.push("vault unlock result did not unlock Device Vault");
  }
  if (request.vaultUnlockResult.correlation.sessionId !== request.lifecycleSnapshot.sessionId) {
    errors.push("session mismatch");
  }
  if (
    request.vaultUnlockResult.correlation.lifecycleTransitionRequestId !== undefined
    && request.transitionRequest.transitionRequestId !== undefined
    && request.vaultUnlockResult.correlation.lifecycleTransitionRequestId
      !== request.transitionRequest.transitionRequestId
  ) errors.push("transition request mismatch");
  if (expired(request.vaultUnlockResult.expiresAt)) errors.push("vault unlock expired");

  let consumed: VaultUnlockConsumptionResult | undefined;
  if (errors.length === 0) {
    consumed = request.consumptionStore?.consume(
      request.vaultUnlockResult.vaultUnlockResultId,
      request.auditCorrelationId ?? request.vaultUnlockResult.auditCorrelationId
    );
    if (consumed?.status === "replayed") errors.push("vault unlock replayed");
  }
  if (errors.length > 0) {
    const auditEventDraft = transitionAuditDraft({
      request,
      status: "validation_failed",
      errors
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(vaultError(
      "VERIFIED_VAULT_SESSION_UNLOCK_REJECTED",
      "verified vault session unlock was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const transitionedAt = request.requestedAt ?? new Date().toISOString();
  const handle = request.vaultUnlockResult.unlockedVaultHandle;
  const metadata = freezeRecord({
    ...(request.lifecycleSnapshot.metadata ?? {}),
    updatedAt: transitionedAt,
    lastTransitionAt: transitionedAt,
    lastTransitionRequestId: request.transitionRequest.transitionRequestId,
    lastTransitionEvent: "unlock_succeeded" as const,
    lastTransitionReason: "device-vault-unlock",
    lifecycleAuthenticationFactorVerified: true,
    deviceVaultUnlocked: true,
    protectedStateAvailable: true,
    activeCapabilitiesAvailable: false as const,
    authorizationAvailable: false as const,
    vaultHandleId: handle?.handleId,
    vaultUnlockedAt: transitionedAt,
    persisted: false as const,
    requestMetadata: {
      ...(request.lifecycleSnapshot.metadata?.requestMetadata ?? {}),
      ...(request.metadata ? redactRuntimeMetadata(request.metadata).value : {}),
      vaultUnlockResultId: request.vaultUnlockResult.vaultUnlockResultId,
      vaultHandleId: handle?.handleId,
      deviceVaultUnlocked: true,
      protectedStateAvailable: true,
      applicationCredentialsLoaded: false,
      activeCapabilityCreated: false,
      sessionKeyCreated: false,
      authorizationCreated: false,
      persistedRuntimeState: false
    }
  });
  const nextSnapshot: UserSessionLifecycleSnapshot = freezeRecord({
    lifecycleId: request.lifecycleSnapshot.lifecycleId,
    sessionId: request.lifecycleSnapshot.sessionId,
    state: "unlocked" as UserSessionLifecycleState,
    sequence: request.lifecycleSnapshot.sequence + 1,
    version: request.lifecycleSnapshot.version + 1,
    createdAt: request.lifecycleSnapshot.createdAt,
    updatedAt: transitionedAt,
    lastTransition: {
      event: "unlock_succeeded",
      previousState: "partially_unlocked",
      nextState: "unlocked",
      reason: "device-vault-unlock",
      transitionedAt,
      transitionRequestId: request.transitionRequest.transitionRequestId
    },
    metadata,
    limitations: UNLOCKED_SNAPSHOT_LIMITATIONS,
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: true,
    grantsAuthority: false
  });
  const transitionResult: UserSessionTransitionResult = freezeRecord({
    status: "transitioned",
    previousState: "partially_unlocked",
    nextState: "unlocked",
    event: "unlock_succeeded",
    reason: "device-vault-unlock",
    transitionedAt,
    auditCorrelationId: request.auditCorrelationId ?? request.vaultUnlockResult.auditCorrelationId,
    snapshot: nextSnapshot,
    futureRequirements: Object.freeze([]),
    evidenceReferences: Object.freeze([evidenceReferenceForVaultUnlock(request.vaultUnlockResult)]),
    evidenceReferencesVerified: false,
    limitations: UNLOCKED_SNAPSHOT_LIMITATIONS
  });
  const auditEventDraft = transitionAuditDraft({
    request,
    status: "validation_succeeded",
    nextSnapshot
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    transitionResult,
    vaultUnlockResult: request.vaultUnlockResult,
    consumed,
    auditEventDraft,
    auditDraftCollectionResult,
    deviceVaultUnlocked: true,
    protectedStateAvailable: true,
    philSecretExposed: false,
    rawVaultKeyExposed: false,
    applicationCredentialsLoaded: false,
    activeCapabilityCreated: false,
    sessionKeyCreated: false,
    authorizationCreated: false,
    persistedRuntimeState: false
  }));
}

export function deriveUserSessionContextFromVerifiedVaultUnlock(
  input: VerifiedVaultUnlockContextInput
): UserSessionContextResult {
  const metadata = input.userSessionContext.metadata ?? {};
  const handle = input.vaultUnlockResult.unlockedVaultHandle;
  const contextInput: UserSessionContextInput = {
    sessionId: input.userSessionContext.sessionId,
    ownerCommitment: input.userSessionContext.ownerCommitment,
    status: input.lifecycleSnapshot.state === "unlocked"
      ? "unlocked"
      : input.userSessionContext.status,
    activeApplicationId: input.userSessionContext.activeApplicationId,
    activeCapabilityIds: input.userSessionContext.activeCapabilityIds,
    pendingIntentIds: input.userSessionContext.pendingIntentIds,
    policyMode: input.userSessionContext.policyMode,
    recoveryState: input.userSessionContext.recoveryState,
    timeout: input.userSessionContext.timeout,
    metadata: {
      ...metadata,
      lifecycleState: input.lifecycleSnapshot.state,
      lifecycleTransitionSequence: input.lifecycleSnapshot.sequence,
      lastLifecycleTransitionAt: input.lifecycleSnapshot.metadata?.lastTransitionAt,
      deviceVaultUnlocked: true,
      protectedStateAvailable: true,
      activeCapabilitiesAvailable: false,
      authorizationAvailable: false,
      vaultHandleId: handle?.handleId,
      vaultUnlockedAt: handle?.unlockedAt,
      strongerVaultUnlockRequired: false,
      requestMetadata: {
        ...(isRecord(metadata.requestMetadata) ? metadata.requestMetadata : {}),
        lifecycleState: input.lifecycleSnapshot.state,
        deviceVaultUnlocked: true,
        protectedStateAvailable: true,
        applicationCredentialsLoaded: false,
        activeCapabilityCreated: false,
        sessionKeyCreated: false,
        authorizationCreated: false,
        persistedRuntimeState: false
      }
    }
  };
  return createUserSessionContext(contextInput);
}
