import { keccak256, toUtf8Bytes } from "ethers";

import {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import type {
  PhilCredentialDeviceType,
  PhilCredentialRecord,
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
import { createAuditCorrelationId, runtimeDenied, runtimeOk, type RuntimeValidationResult } from "./helpers.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type { RuntimeErrorDescriptor, RuntimeResult } from "./types.ts";

export type PublicCredentialDirectoryOperation =
  | "list_credentials"
  | "get_credential_descriptor"
  | "summarize_credentials";

export type PublicCredentialLifecycleClassification =
  | "active"
  | "pending"
  | "recovery-only"
  | "rotated"
  | "revoked"
  | "archived"
  | "unknown";

export type PublicCredentialDirectoryStatus =
  | "directory_created"
  | "directory_rejected"
  | "directory_malformed"
  | "directory_expired"
  | "directory_unsupported"
  | "directory_over_limit";

export type PublicCredentialDirectoryOutcome =
  | "directory_created"
  | "request_malformed"
  | "unsupported_operation"
  | "invalid_handle"
  | "expired_handle"
  | "owner_mismatch"
  | "session_mismatch"
  | "audit_correlation_mismatch"
  | "lifecycle_state_ineligible"
  | "malformed_filter"
  | "over_limit"
  | "credential_not_found"
  | "vault_read_failed";

export type PublicCredentialDirectoryReason =
  | "explicit-directory-request"
  | "allowlisted-public-descriptors"
  | "existing-registry-load-reused"
  | "no-trust-decision"
  | "no-credential-private-material"
  | "no-raw-assertion-data"
  | (string & {});

export interface PublicCredentialDescriptorLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface PublicCredentialDescriptor {
  readonly descriptorId: string;
  readonly credentialId: string;
  readonly displayLabel: string;
  readonly providerKind: string;
  readonly publicKeyAlgorithm: string;
  readonly publicLifecycleStatus: PublicCredentialLifecycleClassification;
  readonly deviceReference?: string;
  readonly deviceType: PhilCredentialDeviceType | string;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly lastUsedAt?: string;
  readonly recoveryOnly: boolean;
  readonly eligibleForOrdinaryEvaluation: boolean;
  readonly eligibleForRecoveryEvaluation: boolean;
  readonly requiresStrongerVerification: boolean;
  readonly userVerificationCapable?: boolean;
  readonly backupEligible?: boolean;
  readonly publicCounter?: number;
  readonly publicKeyReference?: Hex;
  readonly containsPrivateMaterial: false;
  readonly containsRawAssertionData: false;
  readonly containsVaultKeys: false;
  readonly containsPhilSecret: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
}

export interface PublicCredentialDirectoryFilter {
  readonly providerKind?: string;
  readonly lifecycleStatus?: PublicCredentialLifecycleClassification;
  readonly deviceId?: string;
  readonly recoveryOnly?: boolean;
  readonly ordinaryUseEligible?: boolean;
}

export interface PublicCredentialDirectoryQuery {
  readonly credentialId?: string;
  readonly filter?: PublicCredentialDirectoryFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface PublicCredentialDirectorySummary {
  readonly totalCredentialCount: number;
  readonly returnedCredentialCount: number;
  readonly providerKinds: readonly string[];
  readonly lifecycleStatuses: Readonly<Record<string, number>>;
  readonly recoveryOnlyCount: number;
  readonly ordinaryUseEligibleCount: number;
  readonly resultLimit: number;
  readonly truncated: boolean;
  readonly containsPrivateMaterial: false;
  readonly containsRawAssertionData: false;
  readonly containsVaultKeys: false;
  readonly containsPhilSecret: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
}

export interface PublicCredentialDirectoryRequest {
  readonly requestId: string;
  readonly operation: PublicCredentialDirectoryOperation | string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly identity: PhilIdentityPublic;
  readonly envelope: DeviceVaultEnvelopeReference;
  readonly unlockMaterial: DeviceVaultUnlockMaterialReference;
  readonly query?: PublicCredentialDirectoryQuery;
  readonly expectedOwnerCommitment?: Hex;
  readonly expectedSessionId?: string;
  readonly expectedAuditCorrelationId?: string;
  readonly auditCorrelationId?: string;
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PublicCredentialDirectoryResultValue {
  readonly publicCredentialDirectoryResultId: string;
  readonly requestId: string;
  readonly status: PublicCredentialDirectoryStatus;
  readonly outcome: PublicCredentialDirectoryOutcome;
  readonly operation: PublicCredentialDirectoryOperation;
  readonly descriptors: readonly PublicCredentialDescriptor[];
  readonly summary: PublicCredentialDirectorySummary;
  readonly reasons: readonly PublicCredentialDirectoryReason[];
  readonly limitations: readonly PublicCredentialDescriptorLimitation[];
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId: string;
  readonly containsPrivateMaterial: false;
  readonly containsRawAssertionData: false;
  readonly containsVaultKeys: false;
  readonly containsPhilSecret: false;
  readonly providesTrustDecision: false;
  readonly grantsAuthority: false;
  readonly activeCapabilityCreated: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: PublicCredentialDirectoryCollectionResult;
}

export type PublicCredentialDirectoryResult = RuntimeResult<PublicCredentialDirectoryResultValue>;

export type PublicCredentialDirectoryCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface PublicCredentialDirectoryCollection {
  readonly results: readonly PublicCredentialDirectoryResultValue[];
  readonly count: number;
  readonly maxResultCount: number;
}

export interface PublicCredentialDirectoryCollectionResult {
  readonly status: PublicCredentialDirectoryCollectionStatus;
  readonly result?: PublicCredentialDirectoryResultValue;
  readonly removedResult?: PublicCredentialDirectoryResultValue;
  readonly evictedResults?: readonly PublicCredentialDirectoryResultValue[];
  readonly collection: PublicCredentialDirectoryCollection;
  readonly reason?: string;
}

export interface PublicCredentialDirectoryResultCollector {
  addResult(result: PublicCredentialDirectoryResultValue): PublicCredentialDirectoryCollectionResult;
  removeResult(publicCredentialDirectoryResultId: string): PublicCredentialDirectoryCollectionResult;
  clear(): PublicCredentialDirectoryCollectionResult;
  count(): number;
  getById(publicCredentialDirectoryResultId: string): PublicCredentialDirectoryResultValue | undefined;
  getAll(): readonly PublicCredentialDirectoryResultValue[];
}

export interface InMemoryPublicCredentialDirectoryResultCollectorOptions {
  readonly maxResultCount?: number;
}

const OPERATIONS = new Set<PublicCredentialDirectoryOperation>([
  "list_credentials",
  "get_credential_descriptor",
  "summarize_credentials"
]);

const MAX_DIRECTORY_LIMIT = 50;
const DEFAULT_DIRECTORY_LIMIT = 25;

const DEFAULT_LIMITATIONS: readonly PublicCredentialDescriptorLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "public-descriptor-allowlist",
    description: "Descriptors are built from an explicit public-field allowlist."
  }),
  Object.freeze({
    limitationId: "no-private-material",
    description: "No credential private material, raw assertion data, vault keys, root secrets, or registry plaintext are returned."
  }),
  Object.freeze({
    limitationId: "no-trust-decision",
    description: "Lifecycle classifications are metadata only and are not Trust Manager decisions."
  }),
  Object.freeze({
    limitationId: "bounded-directory-read",
    description: "Directory reads are bounded and audited; they do not consume the vault handle permanently."
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
  return { valid: errors.length === 0, errors };
}

function directoryError(
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

function isOperation(value: unknown): value is PublicCredentialDirectoryOperation {
  return typeof value === "string" && OPERATIONS.has(value as PublicCredentialDirectoryOperation);
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function classification(status: PhilCredentialStatus | string): PublicCredentialLifecycleClassification {
  if (
    status === "active"
    || status === "pending"
    || status === "recovery-only"
    || status === "revoked"
    || status === "archived"
  ) return status;
  return "unknown";
}

function publicKeyReference(credential: PhilCredentialRecord): Hex | undefined {
  if (credential.publicKeyHash) return credential.publicKeyHash;
  if (credential.publicKey) {
    return keccak256(toUtf8Bytes(credential.publicKey)) as Hex;
  }
  return undefined;
}

function descriptorFlags() {
  return {
    containsPrivateMaterial: false as const,
    containsRawAssertionData: false as const,
    containsVaultKeys: false as const,
    containsPhilSecret: false as const,
    providesTrustDecision: false as const,
    grantsAuthority: false as const
  };
}

function resultFlags() {
  return {
    ...descriptorFlags(),
    activeCapabilityCreated: false as const,
    sessionKeyCreated: false as const,
    authorizationCreated: false as const,
    persisted: false as const
  };
}

export function sanitizeCredentialRecordToPublicDescriptor(
  credential: PhilCredentialRecord
): PublicCredentialDescriptor {
  const publicLifecycleStatus = classification(credential.status);
  const recoveryOnly = publicLifecycleStatus === "recovery-only";
  const eligibleForOrdinaryEvaluation = publicLifecycleStatus === "active";
  const eligibleForRecoveryEvaluation = recoveryOnly || publicLifecycleStatus === "active";

  return freezeRecord({
    descriptorId: `public-credential:${credential.credentialId}`,
    credentialId: credential.credentialId,
    displayLabel: credential.label,
    providerKind: credential.providerKind,
    publicKeyAlgorithm: credential.algorithm,
    publicLifecycleStatus,
    deviceReference: credential.deviceKeyId ?? credential.credentialId,
    deviceType: credential.deviceType,
    createdAt: credential.createdAt,
    lastUsedAt: credential.lastUsedAt,
    recoveryOnly,
    eligibleForOrdinaryEvaluation,
    eligibleForRecoveryEvaluation,
    requiresStrongerVerification: recoveryOnly,
    userVerificationCapable: credential.transport.authenticatorAttachment === "platform"
      || credential.transport.transports.includes("internal"),
    backupEligible: credential.deviceType !== "local-dev",
    publicCounter: credential.signCount,
    publicKeyReference: publicKeyReference(credential),
    ...descriptorFlags()
  });
}

export function validatePublicCredentialDescriptorShape(
  descriptor: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(descriptor)) return validation(["public credential descriptor must be an object"]);
  if (!isNonEmptyString(descriptor.descriptorId)) errors.push("descriptorId is required");
  if (!isNonEmptyString(descriptor.credentialId)) errors.push("credentialId is required");
  if (!isNonEmptyString(descriptor.providerKind)) errors.push("providerKind is required");
  if (descriptor.containsPrivateMaterial !== false) errors.push("containsPrivateMaterial must be false");
  if (descriptor.containsRawAssertionData !== false) errors.push("containsRawAssertionData must be false");
  if (descriptor.containsVaultKeys !== false) errors.push("containsVaultKeys must be false");
  if (descriptor.containsPhilSecret !== false) errors.push("containsPhilSecret must be false");
  if (descriptor.providesTrustDecision !== false) errors.push("providesTrustDecision must be false");
  if (descriptor.grantsAuthority !== false) errors.push("grantsAuthority must be false");
  return validation(errors);
}

function validateFilter(filter: unknown): string[] {
  const errors: string[] = [];
  if (filter === undefined) return errors;
  if (!isRecord(filter)) return ["filter must be an object"];
  if (filter.providerKind !== undefined && !isNonEmptyString(filter.providerKind)) {
    errors.push("filter.providerKind must be a string");
  }
  if (filter.lifecycleStatus !== undefined && ![
    "active",
    "pending",
    "recovery-only",
    "rotated",
    "revoked",
    "archived",
    "unknown"
  ].includes(String(filter.lifecycleStatus))) {
    errors.push("filter.lifecycleStatus is unsupported");
  }
  if (filter.deviceId !== undefined && !isNonEmptyString(filter.deviceId)) {
    errors.push("filter.deviceId must be a string");
  }
  if (filter.recoveryOnly !== undefined && typeof filter.recoveryOnly !== "boolean") {
    errors.push("filter.recoveryOnly must be boolean");
  }
  if (filter.ordinaryUseEligible !== undefined && typeof filter.ordinaryUseEligible !== "boolean") {
    errors.push("filter.ordinaryUseEligible must be boolean");
  }
  return errors;
}

export function validatePublicCredentialDirectoryRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["public credential directory request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isOperation(request.operation)) errors.push("unsupported operation");
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
  if (!isRecord(request.identity)) errors.push("identity is required");
  if (!isRecord(request.envelope) || !isNonEmptyString(request.envelope.encryptedBlob)) {
    errors.push("envelope.encryptedBlob is required");
  }
  if (!isRecord(request.unlockMaterial) || !isRecord(request.unlockMaterial.keyProvider)) {
    errors.push("unlock material keyProvider is required");
  }
  if (isRecord(request.query)) {
    errors.push(...validateFilter(request.query.filter));
    if (request.query.limit !== undefined) {
      if (typeof request.query.limit !== "number"
        || !Number.isInteger(request.query.limit)
        || request.query.limit < 1) {
        errors.push("query.limit must be a positive integer");
      } else if (request.query.limit > MAX_DIRECTORY_LIMIT) {
        errors.push("query.limit exceeds maximum");
      }
    }
    if (request.query.offset !== undefined
      && (typeof request.query.offset !== "number"
        || !Number.isInteger(request.query.offset)
        || request.query.offset < 0)) {
      errors.push("query.offset must be a non-negative integer");
    }
    if (request.operation === "get_credential_descriptor"
      && !isNonEmptyString(request.query.credentialId)) {
      errors.push("query.credentialId is required for get_credential_descriptor");
    }
  } else if (request.operation === "get_credential_descriptor") {
    errors.push("query.credentialId is required for get_credential_descriptor");
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

function matchesFilter(
  descriptor: PublicCredentialDescriptor,
  filter: PublicCredentialDirectoryFilter | undefined
): boolean {
  if (!filter) return true;
  if (filter.providerKind !== undefined && descriptor.providerKind !== filter.providerKind) return false;
  if (filter.lifecycleStatus !== undefined
    && descriptor.publicLifecycleStatus !== filter.lifecycleStatus) return false;
  if (filter.deviceId !== undefined && descriptor.deviceReference !== filter.deviceId) return false;
  if (filter.recoveryOnly !== undefined && descriptor.recoveryOnly !== filter.recoveryOnly) return false;
  if (filter.ordinaryUseEligible !== undefined
    && descriptor.eligibleForOrdinaryEvaluation !== filter.ordinaryUseEligible) return false;
  return true;
}

function increment(values: readonly string[]): Readonly<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const value of values) {
    out[value] = (out[value] ?? 0) + 1;
  }
  return Object.freeze(out);
}

function directorySummary(input: {
  readonly allDescriptors: readonly PublicCredentialDescriptor[];
  readonly returnedDescriptors: readonly PublicCredentialDescriptor[];
  readonly limit: number;
  readonly truncated: boolean;
}): PublicCredentialDirectorySummary {
  return freezeRecord({
    totalCredentialCount: input.allDescriptors.length,
    returnedCredentialCount: input.returnedDescriptors.length,
    providerKinds: Object.freeze([...new Set(input.returnedDescriptors.map((descriptor) =>
      descriptor.providerKind
    ))].sort()),
    lifecycleStatuses: increment(input.returnedDescriptors.map((descriptor) =>
      descriptor.publicLifecycleStatus)),
    recoveryOnlyCount: input.returnedDescriptors.filter((descriptor) => descriptor.recoveryOnly).length,
    ordinaryUseEligibleCount: input.returnedDescriptors.filter((descriptor) =>
      descriptor.eligibleForOrdinaryEvaluation
    ).length,
    resultLimit: input.limit,
    truncated: input.truncated,
    ...descriptorFlags()
  });
}

function outcomeForErrors(errors: readonly string[]): PublicCredentialDirectoryOutcome {
  if (errors.length === 0) return "directory_created";
  if (errors.some((error) => error.includes("unsupported operation"))) return "unsupported_operation";
  if (errors.some((error) => error.includes("expired"))) return "expired_handle";
  if (errors.some((error) => error.includes("owner"))) return "owner_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_mismatch";
  if (errors.some((error) => error.includes("audit"))) return "audit_correlation_mismatch";
  if (errors.some((error) => error.includes("unlocked lifecycle"))) return "lifecycle_state_ineligible";
  if (errors.some((error) => error.includes("filter"))) return "malformed_filter";
  if (errors.some((error) => error.includes("maximum") || error.includes("limit"))) return "over_limit";
  if (errors.some((error) => error.includes("not found"))) return "credential_not_found";
  if (errors.some((error) => error.includes("vault read"))) return "vault_read_failed";
  if (errors.some((error) => error.includes("handle"))) return "invalid_handle";
  return "request_malformed";
}

function statusForOutcome(outcome: PublicCredentialDirectoryOutcome): PublicCredentialDirectoryStatus {
  if (outcome === "directory_created") return "directory_created";
  if (outcome === "request_malformed" || outcome === "malformed_filter") return "directory_malformed";
  if (outcome === "expired_handle") return "directory_expired";
  if (outcome === "unsupported_operation") return "directory_unsupported";
  if (outcome === "over_limit") return "directory_over_limit";
  return "directory_rejected";
}

function auditDraftForDirectory(input: {
  readonly request: PublicCredentialDirectoryRequest;
  readonly outcome: "validation_succeeded" | "validation_failed" | "unsupported" | "malformed";
  readonly errors?: readonly string[];
  readonly descriptorCount?: number;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome,
    requestKind: "generic",
    sessionId: input.request.lifecycleSnapshot.sessionId,
    applicationId: "ethereum-net",
    summary: input.outcome === "validation_succeeded"
      ? "Public credential directory returned sanitized public descriptors; no trust decision or authority was created."
      : "Public credential directory request was rejected; no private credential material was exposed.",
    auditCorrelationId: input.request.auditCorrelationId
      ?? input.request.expectedAuditCorrelationId
      ?? createAuditCorrelationId([
        input.request.lifecycleSnapshot.sessionId,
        input.request.requestId,
        "public-credential-directory"
      ]),
    redactedDetails: {
      requestId: input.request.requestId,
      operation: input.request.operation,
      descriptorCount: input.descriptorCount ?? 0,
      containsPrivateMaterial: false,
      containsRawAssertionData: false,
      containsVaultKeys: false,
      containsPhilSecret: false,
      providesTrustDecision: false,
      grantsAuthority: false,
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

export function validatePublicCredentialDirectoryResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["public credential directory result must be an object"]);
  if (!isNonEmptyString(result.publicCredentialDirectoryResultId)) {
    errors.push("publicCredentialDirectoryResultId is required");
  }
  if (!Array.isArray(result.descriptors)) errors.push("descriptors must be an array");
  if (Array.isArray(result.descriptors)) {
    for (const descriptor of result.descriptors) {
      errors.push(...validatePublicCredentialDescriptorShape(descriptor).errors);
    }
  }
  for (const [key, value] of Object.entries(resultFlags())) {
    if (result[key] !== value) errors.push(`${key} must be ${String(value)}`);
  }
  return validation(errors);
}

export async function requestPublicCredentialDirectory(
  request: PublicCredentialDirectoryRequest,
  collector?: PublicCredentialDirectoryResultCollector,
  auditDraftCollector?: AuditDraftCollector
): Promise<PublicCredentialDirectoryResult> {
  const requestValidation = validatePublicCredentialDirectoryRequest(request);
  if (!requestValidation.valid || !isOperation(request.operation)) {
    const errors = requestValidation.errors;
    const auditEventDraft = auditDraftForDirectory({
      request,
      outcome: isOperation(request.operation) ? "malformed" : "unsupported",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(directoryError(
      "PUBLIC_CREDENTIAL_DIRECTORY_INVALID",
      "public credential directory request failed validation",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const errors: string[] = [];
  const handle = request.unlockedVaultHandle;
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
      "public-credential-directory"
    ]);
  if (request.expectedAuditCorrelationId !== undefined
    && request.expectedAuditCorrelationId !== auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (expired(handle.expiresAt) || expired(request.expiresAt)) errors.push("expired handle");

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

  if (snapshot === undefined || errors.length > 0) {
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForDirectory({
      request,
      outcome: outcome === "unsupported_operation" ? "unsupported" : "validation_failed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(directoryError(
      "PUBLIC_CREDENTIAL_DIRECTORY_REJECTED",
      "public credential directory request was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const allDescriptors = snapshot.credentials.map(sanitizeCredentialRecordToPublicDescriptor);
  let filtered = allDescriptors.filter((descriptor) => matchesFilter(descriptor, request.query?.filter));
  if (request.operation === "get_credential_descriptor") {
    filtered = filtered.filter((descriptor) => descriptor.credentialId === request.query?.credentialId);
    if (filtered.length === 0) errors.push("credential not found");
  }
  const offset = request.query?.offset ?? 0;
  const limit = request.operation === "summarize_credentials"
    ? 0
    : request.query?.limit ?? DEFAULT_DIRECTORY_LIMIT;
  const returnedDescriptors = request.operation === "summarize_credentials"
    ? []
    : filtered.slice(offset, offset + limit);
  const truncated = request.operation !== "summarize_credentials" && offset + limit < filtered.length;

  if (errors.length > 0) {
    const auditEventDraft = auditDraftForDirectory({
      request,
      outcome: "validation_failed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(directoryError(
      "PUBLIC_CREDENTIAL_DIRECTORY_REJECTED",
      "public credential directory request was rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const createdAt = request.requestedAt ?? new Date().toISOString();
  const auditEventDraft = auditDraftForDirectory({
    request,
    outcome: "validation_succeeded",
    descriptorCount: returnedDescriptors.length
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const value: PublicCredentialDirectoryResultValue = freezeRecord({
    publicCredentialDirectoryResultId: `${auditCorrelationId}:${request.operation}`,
    requestId: request.requestId,
    status: "directory_created",
    outcome: "directory_created",
    operation: request.operation,
    descriptors: Object.freeze(returnedDescriptors),
    summary: directorySummary({
      allDescriptors,
      returnedDescriptors: request.operation === "summarize_credentials" ? filtered : returnedDescriptors,
      limit,
      truncated
    }),
    reasons: Object.freeze([
      "explicit-directory-request",
      "allowlisted-public-descriptors",
      "existing-registry-load-reused",
      "no-trust-decision",
      "no-credential-private-material",
      "no-raw-assertion-data"
    ]),
    limitations: DEFAULT_LIMITATIONS,
    createdAt,
    expiresAt: request.expiresAt,
    auditCorrelationId,
    ...resultFlags(),
    auditEventDraft,
    auditDraftCollectionResult
  });
  const resultValidation = validatePublicCredentialDirectoryResultShape(value);
  if (!resultValidation.valid) {
    return runtimeDenied(directoryError(
      "PUBLIC_CREDENTIAL_DIRECTORY_RESULT_INVALID",
      "public credential directory result failed validation",
      resultValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const collectionResult = collector?.addResult(value);
  return runtimeOk(freezeRecord({
    ...value,
    collectionResult
  }));
}

function collectionFrom(
  results: readonly PublicCredentialDirectoryResultValue[],
  maxResultCount: number
): PublicCredentialDirectoryCollection {
  return freezeRecord({
    results,
    count: results.length,
    maxResultCount
  });
}

export function createInMemoryPublicCredentialDirectoryResultCollector(
  options: InMemoryPublicCredentialDirectoryResultCollectorOptions = {}
): PublicCredentialDirectoryResultCollector {
  const maxResultCount = options.maxResultCount ?? 100;
  const results = new Map<string, PublicCredentialDirectoryResultValue>();

  function all(): readonly PublicCredentialDirectoryResultValue[] {
    return Object.freeze(Array.from(results.values()).map(freezeRecord));
  }

  function collectionResult(
    status: PublicCredentialDirectoryCollectionStatus,
    extras: Omit<PublicCredentialDirectoryCollectionResult, "status" | "collection"> = {}
  ): PublicCredentialDirectoryCollectionResult {
    return freezeRecord({
      status,
      ...extras,
      collection: collectionFrom(all(), maxResultCount)
    });
  }

  return {
    addResult(result) {
      if (results.has(result.publicCredentialDirectoryResultId)) {
        return collectionResult("rejected_duplicate", {
          result,
          reason: "Public credential directory result already exists in this process-local collector."
        });
      }
      const evictedResults: PublicCredentialDirectoryResultValue[] = [];
      while (results.size >= maxResultCount) {
        const oldestKey = results.keys().next().value as string | undefined;
        if (oldestKey === undefined) break;
        const evicted = results.get(oldestKey);
        results.delete(oldestKey);
        if (evicted) evictedResults.push(evicted);
      }
      results.set(result.publicCredentialDirectoryResultId, freezeRecord(result));
      return collectionResult(evictedResults.length > 0 ? "evicted_oldest" : "collected", {
        result,
        evictedResults
      });
    },
    removeResult(publicCredentialDirectoryResultId) {
      const removedResult = results.get(publicCredentialDirectoryResultId);
      if (!removedResult) return collectionResult("not_found");
      results.delete(publicCredentialDirectoryResultId);
      return collectionResult("removed", { removedResult });
    },
    clear() {
      results.clear();
      return collectionResult("cleared");
    },
    count() {
      return results.size;
    },
    getById(publicCredentialDirectoryResultId) {
      const result = results.get(publicCredentialDirectoryResultId);
      return result ? freezeRecord(result) : undefined;
    },
    getAll: all
  };
}
