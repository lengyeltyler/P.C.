import { keccak256, toUtf8Bytes } from "ethers";

import {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import type { PhilDeviceIdentityKeyLifecycleState } from "../deviceIdentityKeyLifecycle.ts";
import type {
  PhilCredentialAuditEventType,
  PhilCredentialDeviceType,
  PhilCredentialRegistrySnapshot,
  PhilCredentialStatus
} from "../deviceIdentityLifecycle.ts";
import type { PhilIdentityPublic } from "../identity.ts";
import type { Hex } from "../hashes.ts";
import type { AuditDraftCollectionResult, AuditDraftCollector, AuditEventDraft } from "./audit.ts";
import { createAuditEventDraft } from "./audit.ts";
import type {
  DeviceVaultEnvelopeReference,
  DeviceVaultUnlockMaterialReference,
  UnlockedDeviceVaultHandleMetadata
} from "./deviceVaultUnlock.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type { RuntimeErrorDescriptor, RuntimeResult } from "./types.ts";

export type ProtectedStateViewType =
  | "identity_summary"
  | "credential_summary"
  | "device_summary"
  | "recovery_summary"
  | "audit_summary"
  | "registry_summary"
  | "key_lifecycle_summary"
  | "runtime_summary";

export type ProtectedStateViewStatus =
  | "view_created"
  | "view_rejected"
  | "view_malformed"
  | "view_expired"
  | "view_replayed"
  | "view_unsupported";

export type ProtectedStateViewOutcome =
  | "view_created"
  | "request_malformed"
  | "unsupported_view"
  | "invalid_handle"
  | "expired_handle"
  | "replayed_handle"
  | "owner_mismatch"
  | "session_mismatch"
  | "audit_correlation_mismatch"
  | "lifecycle_state_ineligible"
  | "vault_read_failed";

export interface ProtectedStateViewLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface ProtectedStateViewEvidence {
  readonly handleId: string;
  readonly envelopeId: string;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly viewType: ProtectedStateViewType;
  readonly registryLoadedForSummary: boolean;
  readonly plaintextReturned: false;
  readonly credentialRecordsReturned: false;
}

export interface ProtectedStateViewMetadata {
  readonly containsSecrets: false;
  readonly containsCredentials: false;
  readonly containsPrivateKeys: false;
  readonly containsAuthorization: false;
  readonly containsSessionKeys: false;
  readonly persisted: false;
}

export type ProtectedStateViewSummary =
  | {
    readonly viewType: "identity_summary";
    readonly ownerCommitment: Hex;
    readonly identityRootAvailable: boolean;
    readonly credentialCount: number;
    readonly recoveryState: string;
  }
  | {
    readonly viewType: "credential_summary";
    readonly totalCredentials: number;
    readonly credentialsByStatus: Readonly<Record<string, number>>;
    readonly providerKindCount: number;
    readonly deviceTypeCount: number;
  }
  | {
    readonly viewType: "device_summary";
    readonly devicesByType: Readonly<Record<string, number>>;
    readonly hardwareBackedDeviceCount: number;
    readonly providerKindCount: number;
  }
  | {
    readonly viewType: "recovery_summary";
    readonly recoveryState: string;
    readonly mechanismCount: number;
    readonly hasPendingRecovery: boolean;
    readonly requiresStrongerThanOrdinaryAuthentication: boolean;
  }
  | {
    readonly viewType: "audit_summary";
    readonly auditEventCount: number;
    readonly auditEventsByType: Readonly<Record<string, number>>;
    readonly firstAuditEventAt?: string;
    readonly latestAuditEventAt?: string;
  }
  | {
    readonly viewType: "registry_summary";
    readonly registryVersion: string;
    readonly ownerCommitment: Hex;
    readonly credentialCount: number;
    readonly auditEventCount: number;
    readonly warningCount: number;
  }
  | {
    readonly viewType: "key_lifecycle_summary";
    readonly keyLifecycleProvided: boolean;
    readonly storageKeyCount: number;
    readonly backupKeyCount: number;
    readonly storageKeysByStatus: Readonly<Record<string, number>>;
    readonly backupKeysByStatus: Readonly<Record<string, number>>;
    readonly activeStorageKeyCount: number;
  }
  | {
    readonly viewType: "runtime_summary";
    readonly sessionId: string;
    readonly lifecycleState: string;
    readonly deviceVaultUnlocked: boolean;
    readonly protectedStateAvailable: boolean;
    readonly activeCapabilityCreated: false;
    readonly authorizationCreated: false;
    readonly persisted: false;
  };

export interface ProtectedStateViewRequest {
  readonly requestId: string;
  readonly viewType: ProtectedStateViewType | string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly identity: PhilIdentityPublic;
  readonly envelope: DeviceVaultEnvelopeReference;
  readonly unlockMaterial: DeviceVaultUnlockMaterialReference;
  readonly keyLifecycle?: PhilDeviceIdentityKeyLifecycleState;
  readonly replayStore?: EphemeralProtectedStateViewReplayStore;
  readonly expectedOwnerCommitment?: Hex;
  readonly expectedSessionId?: string;
  readonly expectedAuditCorrelationId?: string;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ProtectedStateViewResultValue {
  readonly protectedStateViewId: string;
  readonly requestId: string;
  readonly status: ProtectedStateViewStatus;
  readonly outcome: ProtectedStateViewOutcome;
  readonly viewType: ProtectedStateViewType;
  readonly summary: ProtectedStateViewSummary;
  readonly metadata: ProtectedStateViewMetadata;
  readonly limitations: readonly ProtectedStateViewLimitation[];
  readonly evidence: ProtectedStateViewEvidence;
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly containsSecrets: false;
  readonly containsCredentials: false;
  readonly containsPrivateKeys: false;
  readonly containsAuthorization: false;
  readonly containsSessionKeys: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly protectedStateViewCollectionResult?: ProtectedStateViewCollectionResult;
}

export type ProtectedStateViewResult = RuntimeResult<ProtectedStateViewResultValue>;

export type ProtectedStateViewCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface ProtectedStateViewFilter {
  readonly viewType?: ProtectedStateViewType;
  readonly outcome?: ProtectedStateViewOutcome;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly auditCorrelationId?: string;
}

export interface ProtectedStateViewQuery {
  readonly filter?: ProtectedStateViewFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface ProtectedStateViewCollection {
  readonly views: readonly ProtectedStateViewResultValue[];
  readonly count: number;
  readonly maxViewCount: number;
}

export interface ProtectedStateViewCollectionResult {
  readonly status: ProtectedStateViewCollectionStatus;
  readonly view?: ProtectedStateViewResultValue;
  readonly removedView?: ProtectedStateViewResultValue;
  readonly evictedViews?: readonly ProtectedStateViewResultValue[];
  readonly collection: ProtectedStateViewCollection;
  readonly reason?: string;
}

export interface ProtectedStateViewCollector {
  addView(view: ProtectedStateViewResultValue): ProtectedStateViewCollectionResult;
  removeView(protectedStateViewId: string): ProtectedStateViewCollectionResult;
  clear(): ProtectedStateViewCollectionResult;
  count(): number;
  getById(protectedStateViewId: string): ProtectedStateViewResultValue | undefined;
  getAll(): readonly ProtectedStateViewResultValue[];
  query(query: ProtectedStateViewQuery): readonly ProtectedStateViewResultValue[];
  filter(filter: ProtectedStateViewFilter): readonly ProtectedStateViewResultValue[];
}

export interface InMemoryProtectedStateViewCollectorOptions {
  readonly maxViewCount?: number;
}

export type ProtectedStateViewReplayStatus = "consumed" | "replayed" | "cleared";

export interface ProtectedStateViewReplayRecord {
  readonly handleId: string;
  readonly viewType: ProtectedStateViewType;
  readonly consumedAt: string;
  readonly auditCorrelationId?: string;
}

export interface ProtectedStateViewReplayResult {
  readonly status: ProtectedStateViewReplayStatus;
  readonly record?: ProtectedStateViewReplayRecord;
  readonly records: readonly ProtectedStateViewReplayRecord[];
  readonly reason?: string;
}

export interface EphemeralProtectedStateViewReplayStore {
  consume(handleId: string, viewType: ProtectedStateViewType, auditCorrelationId?: string):
    ProtectedStateViewReplayResult;
  has(handleId: string, viewType?: ProtectedStateViewType): boolean;
  getAll(): readonly ProtectedStateViewReplayRecord[];
  clear(): ProtectedStateViewReplayResult;
}

export interface ProtectedStateViewReviewSummary {
  readonly totalViewCount: number;
  readonly viewsByView: Readonly<Record<string, number>>;
  readonly viewsBySession: Readonly<Record<string, number>>;
  readonly viewsByOutcome: Readonly<Record<string, number>>;
  readonly viewsByOwner: Readonly<Record<string, number>>;
  readonly expiredViewCount: number;
  readonly earliestCreatedAt?: string;
  readonly latestCreatedAt?: string;
}

const VIEW_TYPES = new Set<ProtectedStateViewType>([
  "identity_summary",
  "credential_summary",
  "device_summary",
  "recovery_summary",
  "audit_summary",
  "registry_summary",
  "key_lifecycle_summary",
  "runtime_summary"
]);

const DEFAULT_LIMITATIONS: readonly ProtectedStateViewLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "explicit_view_only",
    description: "Each request returns exactly one named non-secret protected-state view."
  }),
  Object.freeze({
    limitationId: "no_raw_vault_contents",
    description: "The view never returns decrypted registry plaintext, private key material, or raw vault contents."
  }),
  Object.freeze({
    limitationId: "no_authority",
    description: "The view does not create capabilities, session keys, authorization packages, policy decisions, proofs, or adapter execution."
  }),
  Object.freeze({
    limitationId: "process_local_only",
    description: "View collection and replay tracking are process-local only and are not persisted."
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

function viewError(
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

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function isProtectedStateViewType(value: unknown): value is ProtectedStateViewType {
  return typeof value === "string" && VIEW_TYPES.has(value as ProtectedStateViewType);
}

function increment<T extends string>(values: readonly T[]): Readonly<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const value of values) {
    out[value] = (out[value] ?? 0) + 1;
  }
  return Object.freeze(out);
}

function statusForOutcome(outcome: ProtectedStateViewOutcome): ProtectedStateViewStatus {
  if (outcome === "view_created") return "view_created";
  if (outcome === "request_malformed") return "view_malformed";
  if (outcome === "unsupported_view") return "view_unsupported";
  if (outcome === "expired_handle") return "view_expired";
  if (outcome === "replayed_handle") return "view_replayed";
  return "view_rejected";
}

function outcomeForErrors(errors: readonly string[]): ProtectedStateViewOutcome {
  if (errors.length === 0) return "view_created";
  if (errors.some((error) => error.includes("unsupported view"))) return "unsupported_view";
  if (errors.some((error) => error.includes("expired"))) return "expired_handle";
  if (errors.some((error) => error.includes("replayed"))) return "replayed_handle";
  if (errors.some((error) => error.includes("owner"))) return "owner_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_mismatch";
  if (errors.some((error) => error.includes("audit"))) return "audit_correlation_mismatch";
  if (errors.some((error) => error.includes("unlocked lifecycle"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("handle"))) return "invalid_handle";
  if (errors.some((error) => error.includes("vault read"))) return "vault_read_failed";
  return "request_malformed";
}

function metadata(): ProtectedStateViewMetadata {
  return Object.freeze({
    containsSecrets: false,
    containsCredentials: false,
    containsPrivateKeys: false,
    containsAuthorization: false,
    containsSessionKeys: false,
    persisted: false
  });
}

function baseResultFlags() {
  return {
    containsSecrets: false as const,
    containsCredentials: false as const,
    containsPrivateKeys: false as const,
    containsAuthorization: false as const,
    containsSessionKeys: false as const,
    activeCapabilityCreated: false as const,
    sessionKeyCreated: false as const,
    authorizationCreated: false as const,
    persisted: false as const
  };
}

function viewId(input: {
  readonly requestId: string;
  readonly handleId: string;
  readonly viewType: ProtectedStateViewType;
  readonly auditCorrelationId: string;
}): string {
  return `${input.auditCorrelationId}:${input.viewType}:${keccak256(toUtf8Bytes(`${input.requestId}:${input.handleId}:${input.viewType}`)).slice(2, 10)}`;
}

function summarizeSnapshot(
  snapshot: PhilCredentialRegistrySnapshot,
  request: ProtectedStateViewRequest,
  viewType: ProtectedStateViewType
): ProtectedStateViewSummary {
  if (viewType === "identity_summary") {
    return freezeRecord({
      viewType,
      ownerCommitment: snapshot.philIdentity.ownerCommitment,
      identityRootAvailable: isNonEmptyString(snapshot.philIdentity.identityRoot),
      credentialCount: snapshot.credentials.length,
      recoveryState: snapshot.recoveryPolicy.state
    });
  }
  if (viewType === "credential_summary") {
    return freezeRecord({
      viewType,
      totalCredentials: snapshot.credentials.length,
      credentialsByStatus: increment(snapshot.credentials.map((credential) =>
        credential.status as PhilCredentialStatus)),
      providerKindCount: new Set(snapshot.credentials.map((credential) =>
        credential.providerKind)).size,
      deviceTypeCount: new Set(snapshot.credentials.map((credential) =>
        credential.deviceType)).size
    });
  }
  if (viewType === "device_summary") {
    return freezeRecord({
      viewType,
      devicesByType: increment(snapshot.credentials.map((credential) =>
        credential.deviceType as PhilCredentialDeviceType)),
      hardwareBackedDeviceCount: snapshot.credentials.filter((credential) =>
        credential.deviceType === "hardware-security-key"
        || credential.deviceType === "secure-enclave"
        || credential.deviceType === "platform"
      ).length,
      providerKindCount: new Set(snapshot.credentials.map((credential) =>
        credential.providerKind)).size
    });
  }
  if (viewType === "recovery_summary") {
    return freezeRecord({
      viewType,
      recoveryState: snapshot.recoveryPolicy.state,
      mechanismCount: snapshot.recoveryPolicy.mechanisms.length,
      hasPendingRecovery: snapshot.recoveryPolicy.pending !== undefined,
      requiresStrongerThanOrdinaryAuthentication:
        snapshot.recoveryPolicy.requiresStrongerThanOrdinaryAuthentication
    });
  }
  if (viewType === "audit_summary") {
    const dates = snapshot.auditTrail
      .map((event) => event.occurredAt)
      .filter(isNonEmptyString)
      .sort();
    return freezeRecord({
      viewType,
      auditEventCount: snapshot.auditTrail.length,
      auditEventsByType: increment(snapshot.auditTrail.map((event) =>
        event.eventType as PhilCredentialAuditEventType)),
      firstAuditEventAt: dates[0],
      latestAuditEventAt: dates.at(-1)
    });
  }
  if (viewType === "registry_summary") {
    return freezeRecord({
      viewType,
      registryVersion: snapshot.version,
      ownerCommitment: snapshot.philIdentity.ownerCommitment,
      credentialCount: snapshot.credentials.length,
      auditEventCount: snapshot.auditTrail.length,
      warningCount: snapshot.warnings.length
    });
  }
  if (viewType === "key_lifecycle_summary") {
    return freezeRecord({
      viewType,
      keyLifecycleProvided: request.keyLifecycle !== undefined,
      storageKeyCount: request.keyLifecycle?.storageKeys.length ?? 0,
      backupKeyCount: request.keyLifecycle?.backupKeys.length ?? 0,
      storageKeysByStatus: increment((request.keyLifecycle?.storageKeys ?? []).map((key) =>
        key.status)),
      backupKeysByStatus: increment((request.keyLifecycle?.backupKeys ?? []).map((key) =>
        key.status)),
      activeStorageKeyCount: (request.keyLifecycle?.storageKeys ?? []).filter((key) =>
        key.status === "active"
      ).length
    });
  }
  return freezeRecord({
    viewType: "runtime_summary",
    sessionId: request.lifecycleSnapshot.sessionId,
    lifecycleState: request.lifecycleSnapshot.state,
    deviceVaultUnlocked: request.lifecycleSnapshot.metadata?.deviceVaultUnlocked === true,
    protectedStateAvailable: request.lifecycleSnapshot.metadata?.protectedStateAvailable === true,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    persisted: false
  });
}

function auditDraftForView(input: {
  readonly request: ProtectedStateViewRequest;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly viewType?: ProtectedStateViewType;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.lifecycleSnapshot.sessionId,
    applicationId: input.request.unlockedVaultHandle.applicationAccessible ? undefined : "ethereum-net",
    summary: input.outcome === "validation_succeeded"
      ? "Protected state view created; no raw vault contents, credentials, authorization, or session keys were exposed."
      : "Protected state view request was rejected; no raw vault contents were exposed.",
    auditCorrelationId: input.request.auditCorrelationId
      ?? input.request.expectedAuditCorrelationId
      ?? createAuditCorrelationId([
        input.request.lifecycleSnapshot.sessionId,
        input.request.requestId,
        "protected-state-view"
      ]),
    redactedDetails: {
      requestId: input.request.requestId,
      viewType: input.viewType ?? input.request.viewType,
      handleId: input.request.unlockedVaultHandle.handleId,
      ownerCommitment: input.request.unlockedVaultHandle.ownerCommitment,
      containsSecrets: false,
      containsCredentials: false,
      containsPrivateKeys: false,
      containsAuthorization: false,
      containsSessionKeys: false,
      activeCapabilityCreated: false,
      sessionKeyCreated: false,
      authorizationCreated: false,
      persisted: false,
      requestMetadata: input.request.metadata
        ? redactRuntimeMetadata(input.request.metadata).value
        : undefined,
      errors: input.errors ?? []
    }
  });
}

export function validateProtectedStateViewRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["protected state view request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isProtectedStateViewType(request.viewType)) errors.push("unsupported view type");
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!snapshotValidation.valid) {
    errors.push(...snapshotValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isRecord(request.unlockedVaultHandle)) {
    errors.push("unlocked vault handle is required");
  } else {
    if (!isNonEmptyString(request.unlockedVaultHandle.handleId)) errors.push("handle id is required");
    if (request.unlockedVaultHandle.processLocal !== true) errors.push("handle must be process-local");
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
  if (!isRecord(request.identity)) {
    errors.push("identity is required");
  } else {
    if (!isNonEmptyString(request.identity.ownerCommitment)) {
      errors.push("identity.ownerCommitment is required");
    }
    if (!isNonEmptyString(request.identity.identityRoot)) {
      errors.push("identity.identityRoot is required");
    }
  }
  if (!isRecord(request.envelope)) {
    errors.push("envelope is required");
  } else {
    if (!isNonEmptyString(request.envelope.encryptedBlob)) {
      errors.push("envelope.encryptedBlob is required");
    }
  }
  if (!isRecord(request.unlockMaterial) || !isRecord(request.unlockMaterial.keyProvider)) {
    errors.push("unlock material keyProvider is required");
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

export function validateProtectedStateViewResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["protected state view result must be an object"]);
  if (!isNonEmptyString(result.protectedStateViewId)) errors.push("protectedStateViewId is required");
  if (!isProtectedStateViewType(result.viewType)) errors.push("viewType is unsupported");
  if (!isRecord(result.summary)) errors.push("summary is required");
  if (result.containsSecrets !== false) errors.push("containsSecrets must be false");
  if (result.containsCredentials !== false) errors.push("containsCredentials must be false");
  if (result.containsPrivateKeys !== false) errors.push("containsPrivateKeys must be false");
  if (result.containsAuthorization !== false) errors.push("containsAuthorization must be false");
  if (result.containsSessionKeys !== false) errors.push("containsSessionKeys must be false");
  if (result.activeCapabilityCreated !== false) errors.push("activeCapabilityCreated must be false");
  if (result.sessionKeyCreated !== false) errors.push("sessionKeyCreated must be false");
  if (result.authorizationCreated !== false) errors.push("authorizationCreated must be false");
  if (result.persisted !== false) errors.push("persisted must be false");
  return validation(errors);
}

export async function createProtectedStateView(
  request: ProtectedStateViewRequest,
  collector?: ProtectedStateViewCollector,
  auditDraftCollector?: AuditDraftCollector
): Promise<ProtectedStateViewResult> {
  const requestValidation = validateProtectedStateViewRequest(request);
  if (!requestValidation.valid || !isProtectedStateViewType(request.viewType)) {
    const errors = requestValidation.errors;
    const auditEventDraft = auditDraftForView({
      request,
      outcome: isProtectedStateViewType(request.viewType) ? "malformed" : "unsupported",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(viewError(
      "PROTECTED_STATE_VIEW_INVALID",
      "protected state view request failed validation",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const errors: string[] = [];
  const viewType = request.viewType;
  const handle = request.unlockedVaultHandle;
  if (request.lifecycleSnapshot.state !== "unlocked") {
    errors.push("unlocked lifecycle snapshot is required");
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
      "protected-state-view"
    ]);
  if (request.expectedAuditCorrelationId !== undefined
    && request.expectedAuditCorrelationId !== auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (expired(handle.expiresAt) || expired(request.expiresAt)) errors.push("expired handle");
  const replay = request.replayStore?.consume(handle.handleId, viewType, auditCorrelationId);
  if (replay?.status === "replayed") errors.push("replayed handle");

  let snapshot: PhilCredentialRegistrySnapshot | undefined;
  if (errors.length === 0) {
    try {
      const store = createEncryptedDeviceIdentityRegistryStore({
        backend: createInMemoryDeviceIdentityRegistryStorageBackend(request.envelope.encryptedBlob),
        keyProvider: request.unlockMaterial.keyProvider
      });
      snapshot = await store.loadRegistry(request.identity);
    } catch {
      errors.push("vault read failed");
    }
  }

  if (errors.length > 0 || snapshot === undefined) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForView({
      request,
      outcome: outcome === "unsupported_view" ? "unsupported" : "validation_failed",
      viewType,
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(viewError(
      "PROTECTED_STATE_VIEW_REJECTED",
      "protected state view request was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const createdAt = request.requestedAt ?? new Date().toISOString();
  const auditEventDraft = auditDraftForView({
    request,
    outcome: "validation_succeeded",
    viewType
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const value: ProtectedStateViewResultValue = freezeRecord({
    protectedStateViewId: viewId({
      requestId: request.requestId,
      handleId: handle.handleId,
      viewType,
      auditCorrelationId
    }),
    requestId: request.requestId,
    status: "view_created",
    outcome: "view_created",
    viewType,
    summary: summarizeSnapshot(snapshot, request, viewType),
    metadata: metadata(),
    limitations: DEFAULT_LIMITATIONS,
    evidence: {
      handleId: handle.handleId,
      envelopeId: handle.envelopeId,
      ownerCommitment: handle.ownerCommitment,
      sessionId: handle.sessionId,
      viewType,
      registryLoadedForSummary: true,
      plaintextReturned: false,
      credentialRecordsReturned: false
    },
    createdAt,
    expiresAt: request.expiresAt,
    auditCorrelationId,
    ...baseResultFlags(),
    auditEventDraft,
    auditDraftCollectionResult
  });
  const resultValidation = validateProtectedStateViewResultShape(value);
  if (!resultValidation.valid) {
    return runtimeDenied(viewError(
      "PROTECTED_STATE_VIEW_RESULT_INVALID",
      "protected state view result failed validation",
      resultValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const collectionResult = collector?.addView(value);
  return runtimeOk(freezeRecord({
    ...value,
    auditDraftCollectionResult,
    protectedStateViewCollectionResult: collectionResult
  }));
}

function collectionFrom(
  views: readonly ProtectedStateViewResultValue[],
  maxViewCount: number
): ProtectedStateViewCollection {
  return freezeRecord({
    views,
    count: views.length,
    maxViewCount
  });
}

function matchesFilter(
  view: ProtectedStateViewResultValue,
  filter: ProtectedStateViewFilter
): boolean {
  if (filter.viewType !== undefined && view.viewType !== filter.viewType) return false;
  if (filter.outcome !== undefined && view.outcome !== filter.outcome) return false;
  if (filter.sessionId !== undefined && view.evidence.sessionId !== filter.sessionId) return false;
  if (filter.ownerCommitment !== undefined && view.evidence.ownerCommitment !== filter.ownerCommitment) {
    return false;
  }
  if (filter.auditCorrelationId !== undefined && view.auditCorrelationId !== filter.auditCorrelationId) {
    return false;
  }
  return true;
}

export function createInMemoryProtectedStateViewCollector(
  options: InMemoryProtectedStateViewCollectorOptions = {}
): ProtectedStateViewCollector {
  const maxViewCount = options.maxViewCount ?? 100;
  const views = new Map<string, ProtectedStateViewResultValue>();

  function all(): readonly ProtectedStateViewResultValue[] {
    return Object.freeze(Array.from(views.values()).map(freezeRecord));
  }

  function result(
    status: ProtectedStateViewCollectionStatus,
    extras: Omit<ProtectedStateViewCollectionResult, "status" | "collection"> = {}
  ): ProtectedStateViewCollectionResult {
    return freezeRecord({
      status,
      ...extras,
      collection: collectionFrom(all(), maxViewCount)
    });
  }

  return {
    addView(view) {
      if (views.has(view.protectedStateViewId)) {
        return result("rejected_duplicate", {
          view,
          reason: "Protected state view already exists in this process-local collector."
        });
      }
      const evictedViews: ProtectedStateViewResultValue[] = [];
      while (views.size >= maxViewCount) {
        const oldestKey = views.keys().next().value as string | undefined;
        if (oldestKey === undefined) break;
        const evicted = views.get(oldestKey);
        views.delete(oldestKey);
        if (evicted) evictedViews.push(evicted);
      }
      views.set(view.protectedStateViewId, freezeRecord(view));
      return result(evictedViews.length > 0 ? "evicted_oldest" : "collected", {
        view,
        evictedViews
      });
    },
    removeView(protectedStateViewId) {
      const removedView = views.get(protectedStateViewId);
      if (!removedView) return result("not_found");
      views.delete(protectedStateViewId);
      return result("removed", { removedView });
    },
    clear() {
      views.clear();
      return result("cleared");
    },
    count() {
      return views.size;
    },
    getById(protectedStateViewId) {
      const view = views.get(protectedStateViewId);
      return view ? freezeRecord(view) : undefined;
    },
    getAll: all,
    query(query) {
      const filtered = query.filter ? all().filter((view) => matchesFilter(view, query.filter ?? {})) : all();
      const offset = query.offset ?? 0;
      const limit = query.limit ?? filtered.length;
      return Object.freeze(filtered.slice(offset, offset + limit));
    },
    filter(filter) {
      return Object.freeze(all().filter((view) => matchesFilter(view, filter)));
    }
  };
}

export function createEphemeralProtectedStateViewReplayStore():
  EphemeralProtectedStateViewReplayStore {
  const records = new Map<string, ProtectedStateViewReplayRecord>();

  function key(handleId: string, viewType: ProtectedStateViewType) {
    return `${handleId}:${viewType}`;
  }

  function all(): readonly ProtectedStateViewReplayRecord[] {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }

  return {
    consume(handleId, viewType, auditCorrelationId) {
      const recordKey = key(handleId, viewType);
      if (records.has(recordKey)) {
        return freezeRecord({
          status: "replayed",
          record: records.get(recordKey),
          records: all(),
          reason: "Protected state view handle/view pair was already consumed in this process-local store."
        });
      }
      const record = freezeRecord({
        handleId,
        viewType,
        consumedAt: new Date().toISOString(),
        auditCorrelationId
      });
      records.set(recordKey, record);
      return freezeRecord({
        status: "consumed",
        record,
        records: all()
      });
    },
    has(handleId, viewType) {
      if (viewType !== undefined) return records.has(key(handleId, viewType));
      return Array.from(records.keys()).some((recordKey) => recordKey.startsWith(`${handleId}:`));
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

function groupBy(
  views: readonly ProtectedStateViewResultValue[],
  selector: (view: ProtectedStateViewResultValue) => string | undefined
): Readonly<Record<string, readonly ProtectedStateViewResultValue[]>> {
  const groups: Record<string, ProtectedStateViewResultValue[]> = {};
  for (const view of views) {
    const key = selector(view) ?? "unknown";
    groups[key] = [...(groups[key] ?? []), view];
  }
  return freezeRecord(groups);
}

export function groupProtectedStateViewsByView(
  views: readonly ProtectedStateViewResultValue[]
): Readonly<Record<string, readonly ProtectedStateViewResultValue[]>> {
  return groupBy(views, (view) => view.viewType);
}

export function groupProtectedStateViewsBySession(
  views: readonly ProtectedStateViewResultValue[]
): Readonly<Record<string, readonly ProtectedStateViewResultValue[]>> {
  return groupBy(views, (view) => view.evidence.sessionId);
}

export function groupProtectedStateViewsByOutcome(
  views: readonly ProtectedStateViewResultValue[]
): Readonly<Record<string, readonly ProtectedStateViewResultValue[]>> {
  return groupBy(views, (view) => view.outcome);
}

export function groupProtectedStateViewsByOwner(
  views: readonly ProtectedStateViewResultValue[]
): Readonly<Record<string, readonly ProtectedStateViewResultValue[]>> {
  return groupBy(views, (view) => view.evidence.ownerCommitment);
}

export function getExpiredProtectedStateViews(
  views: readonly ProtectedStateViewResultValue[],
  now = new Date()
): readonly ProtectedStateViewResultValue[] {
  return Object.freeze(views.filter((view) =>
    view.expiresAt !== undefined && Date.parse(view.expiresAt) <= now.getTime()
  ));
}

export function summarizeProtectedStateViews(
  views: readonly ProtectedStateViewResultValue[]
): ProtectedStateViewReviewSummary {
  const createdDates = views.map((view) => view.createdAt).filter(isNonEmptyString).sort();
  return freezeRecord({
    totalViewCount: views.length,
    viewsByView: increment(views.map((view) => view.viewType)),
    viewsBySession: increment(views.map((view) => view.evidence.sessionId)),
    viewsByOutcome: increment(views.map((view) => view.outcome)),
    viewsByOwner: increment(views.map((view) => view.evidence.ownerCommitment)),
    expiredViewCount: getExpiredProtectedStateViews(views).length,
    earliestCreatedAt: createdDates[0],
    latestCreatedAt: createdDates.at(-1)
  });
}
