import { keccak256, toUtf8Bytes } from "ethers";

import type { PhilIdentityPublic } from "./identity.ts";
import {
  createPhilCredentialRegistry,
  type PhilCredentialAuditEvent,
  type PhilCredentialRegistrySnapshot
} from "./deviceIdentityLifecycle.ts";
import {
  createEncryptedDeviceIdentityRegistryStore,
  type PhilDeviceIdentityRegistryKeyProvider,
  type PhilDeviceIdentityRegistryStorageBackend
} from "./deviceIdentityStorage.ts";
import type { Hex } from "./hashes.ts";

export const PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION =
  "phil-device-identity-key-lifecycle-v1" as const;
export const PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_DOMAIN_LABEL =
  "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_V1" as const;
export const PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_DOMAIN_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_DOMAIN_LABEL)
) as Hex;

export type PhilDeviceIdentityStorageKeyStatus =
  | "active"
  | "retiring"
  | "retired"
  | "revoked";

export type PhilDeviceIdentityStorageKeyAuditEventType =
  | "storage-key-created"
  | "storage-key-rotation-started"
  | "storage-key-rotation-completed"
  | "storage-key-rotation-failed"
  | "storage-key-retired"
  | "storage-key-revoked";

export interface PhilDeviceIdentityStorageKeyMetadata {
  readonly keyVersion: number;
  readonly createdAt: string;
  readonly rotatedAt?: string;
  readonly status: PhilDeviceIdentityStorageKeyStatus;
  readonly providerType: string;
  readonly algorithm: string;
  readonly registryVersion: number;
}

export interface PhilDeviceIdentityBackupKeyMetadata {
  readonly backupKeyVersion: number;
  readonly createdAt: string;
  readonly rotatedAt?: string;
  readonly status: PhilDeviceIdentityStorageKeyStatus;
  readonly providerType: string;
  readonly algorithm: string;
}

export interface PhilDeviceIdentityRotationPolicy {
  readonly recommendedRotationIntervalDays: number;
  readonly maxKeyAgeDays: number;
  readonly requireBackupBeforeRotation: boolean;
  readonly requireAuditEvent: true;
  readonly allowEmergencyRotation: boolean;
}

export interface PhilDeviceIdentityKeyLifecycleState {
  readonly version: typeof PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION;
  readonly storageKeys: readonly PhilDeviceIdentityStorageKeyMetadata[];
  readonly backupKeys: readonly PhilDeviceIdentityBackupKeyMetadata[];
  readonly policy: PhilDeviceIdentityRotationPolicy;
  readonly migrationVersion: number;
}

export interface PhilDeviceIdentityEnvelopeKeyLifecycleMetadata {
  readonly keyVersion: number;
  readonly encryptionAlgorithm: "aes-256-gcm";
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly migrationVersion: number;
}

export interface PhilDeviceIdentityEnvelopeBackupLifecycleMetadata {
  readonly backupKeyVersion: number;
  readonly encryptionAlgorithm: "aes-256-gcm";
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly migrationVersion: number;
}

export interface PhilDeviceIdentityVersionedKeyProvider {
  readonly metadata: PhilDeviceIdentityStorageKeyMetadata;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
}

export interface PhilDeviceIdentityVersionedBackupKeyProvider {
  readonly metadata: PhilDeviceIdentityBackupKeyMetadata;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
}

export interface PhilDeviceIdentityStorageKeyRotationInput {
  readonly backend: PhilDeviceIdentityRegistryStorageBackend;
  readonly identity: PhilIdentityPublic;
  readonly currentKey: PhilDeviceIdentityVersionedKeyProvider;
  readonly nextKey: PhilDeviceIdentityVersionedKeyProvider;
  readonly lifecycle: PhilDeviceIdentityKeyLifecycleState;
  readonly now?: () => string;
  readonly requireBackupCompleted?: boolean;
  readonly simulateCommitFailure?: boolean;
}

export interface PhilDeviceIdentityStorageKeyRotationResult {
  readonly lifecycle: PhilDeviceIdentityKeyLifecycleState;
  readonly snapshot: PhilCredentialRegistrySnapshot;
  readonly rotatedEncryptedBlob: string;
}

export interface PhilDeviceIdentityBackupKeyRotationInput {
  readonly encryptedBackupBlob: string;
  readonly identity: PhilIdentityPublic;
  readonly currentBackupKey: PhilDeviceIdentityVersionedBackupKeyProvider;
  readonly nextBackupKey: PhilDeviceIdentityVersionedBackupKeyProvider;
  readonly lifecycle: PhilDeviceIdentityKeyLifecycleState;
  readonly now?: () => string;
}

export interface PhilDeviceIdentityBackupKeyRotationResult {
  readonly lifecycle: PhilDeviceIdentityKeyLifecycleState;
  readonly encryptedBackupBlob: string;
  readonly snapshot: PhilCredentialRegistrySnapshot;
}

export interface PhilDeviceIdentityStorageKeyringEntry {
  readonly key: PhilDeviceIdentityVersionedKeyProvider;
}

export class PhilDeviceIdentityKeyLifecycleError extends Error {
  readonly code: string;
  readonly auditEvent?: PhilCredentialAuditEvent;

  constructor(
    code: string,
    message: string,
    auditEvent?: PhilCredentialAuditEvent
  ) {
    super(message);
    this.name = "PhilDeviceIdentityKeyLifecycleError";
    this.code = code;
    this.auditEvent = auditEvent;
  }
}

export const DEFAULT_PHIL_DEVICE_IDENTITY_ROTATION_POLICY: PhilDeviceIdentityRotationPolicy =
  Object.freeze({
    recommendedRotationIntervalDays: 90,
    maxKeyAgeDays: 365,
    requireBackupBeforeRotation: true,
    requireAuditEvent: true,
    allowEmergencyRotation: true
  });

function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, candidate) => {
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return Object.fromEntries(
        Object.entries(candidate as Record<string, unknown>).sort(([left], [right]) =>
          left.localeCompare(right)
        )
      );
    }
    return candidate;
  });
}

function storageEvent(input: {
  ownerCommitment: Hex;
  eventType: PhilDeviceIdentityStorageKeyAuditEventType;
  occurredAt: string;
  sequence: number;
  details?: Readonly<Record<string, unknown>>;
}): PhilCredentialAuditEvent {
  return Object.freeze({
    eventId: keccak256(toUtf8Bytes(stableJson({
      domain: PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_DOMAIN_HASH,
      ownerCommitment: input.ownerCommitment,
      eventType: input.eventType,
      occurredAt: input.occurredAt,
      sequence: input.sequence
    }))) as Hex,
    eventType: input.eventType,
    ownerCommitment: input.ownerCommitment,
    occurredAt: input.occurredAt,
    details: Object.freeze({ ...(input.details ?? {}) })
  });
}

export function appendStorageKeyLifecycleAuditEvent(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  eventType: PhilDeviceIdentityStorageKeyAuditEventType;
  occurredAt: string;
  details?: Readonly<Record<string, unknown>>;
}): PhilCredentialRegistrySnapshot {
  const auditTrail = [
    ...input.snapshot.auditTrail,
    storageEvent({
      ownerCommitment: input.snapshot.philIdentity.ownerCommitment,
      eventType: input.eventType,
      occurredAt: input.occurredAt,
      sequence: input.snapshot.auditTrail.length,
      details: input.details
    })
  ];
  return createPhilCredentialRegistry({
    philIdentity: input.snapshot.philIdentity,
    credentials: input.snapshot.credentials,
    recoveryPolicy: input.snapshot.recoveryPolicy,
    auditTrail
  }).getSnapshot();
}

function keyRecord(input: {
  keyVersion: number;
  providerType: string;
  createdAt: string;
  status?: PhilDeviceIdentityStorageKeyStatus;
  rotatedAt?: string;
  registryVersion?: number;
  algorithm?: string;
}): PhilDeviceIdentityStorageKeyMetadata {
  return Object.freeze({
    keyVersion: input.keyVersion,
    createdAt: input.createdAt,
    rotatedAt: input.rotatedAt,
    status: input.status ?? "active",
    providerType: input.providerType,
    algorithm: input.algorithm ?? "aes-256-gcm",
    registryVersion: input.registryVersion ?? 1
  });
}

function backupKeyRecord(input: {
  backupKeyVersion: number;
  providerType: string;
  createdAt: string;
  status?: PhilDeviceIdentityStorageKeyStatus;
  rotatedAt?: string;
  algorithm?: string;
}): PhilDeviceIdentityBackupKeyMetadata {
  return Object.freeze({
    backupKeyVersion: input.backupKeyVersion,
    createdAt: input.createdAt,
    rotatedAt: input.rotatedAt,
    status: input.status ?? "active",
    providerType: input.providerType,
    algorithm: input.algorithm ?? "aes-256-gcm"
  });
}

function assertSingleActiveStorageKey(lifecycle: PhilDeviceIdentityKeyLifecycleState) {
  const active = lifecycle.storageKeys.filter((key) => key.status === "active");
  if (active.length !== 1) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_INVALID_ACTIVE_KEY_COUNT",
      "Exactly one active storage key is required"
    );
  }
}

function assertKeyCanLoad(metadata: PhilDeviceIdentityStorageKeyMetadata) {
  if (metadata.status === "retired" || metadata.status === "revoked") {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_KEY_NOT_ALLOWED",
      `Storage key version ${metadata.keyVersion} cannot load while ${metadata.status}`
    );
  }
}

function parseLifecycleMetadata(serialized: string): {
  readonly keyLifecycle?: PhilDeviceIdentityEnvelopeKeyLifecycleMetadata;
  readonly backupLifecycle?: PhilDeviceIdentityEnvelopeBackupLifecycleMetadata;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_CORRUPTED_ENVELOPE",
      "Encrypted registry lifecycle envelope JSON is corrupted"
    );
  }
  if (!parsed || typeof parsed !== "object") {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_INVALID_ENVELOPE",
      "Encrypted registry lifecycle envelope must be an object"
    );
  }
  return parsed as {
    readonly keyLifecycle?: PhilDeviceIdentityEnvelopeKeyLifecycleMetadata;
    readonly backupLifecycle?: PhilDeviceIdentityEnvelopeBackupLifecycleMetadata;
  };
}

function assertEnvelopeMatchesLifecycle(input: {
  serialized: string;
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  keyVersion: number;
}) {
  const metadata = parseLifecycleMetadata(input.serialized).keyLifecycle;
  if (metadata === undefined) {
    if (input.lifecycle.migrationVersion > 1) {
      throw new PhilDeviceIdentityKeyLifecycleError(
        "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROLLBACK_DETECTED",
        "Encrypted registry is missing lifecycle metadata required by the local key lifecycle state"
      );
    }
    return;
  }
  if (metadata.keyVersion !== input.keyVersion) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_KEY_VERSION_MISMATCH",
      `Encrypted registry was written for storage key version ${metadata.keyVersion}, not ${input.keyVersion}`
    );
  }
  if (metadata.migrationVersion < input.lifecycle.migrationVersion) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROLLBACK_DETECTED",
      "Encrypted registry migration version is older than the local key lifecycle state"
    );
  }
}

function replaceStorageKey(
  lifecycle: PhilDeviceIdentityKeyLifecycleState,
  replacement: PhilDeviceIdentityStorageKeyMetadata
): readonly PhilDeviceIdentityStorageKeyMetadata[] {
  const keys = lifecycle.storageKeys.filter(
    (key) => key.keyVersion !== replacement.keyVersion
  );
  return Object.freeze([...keys, replacement].sort((left, right) =>
    left.keyVersion - right.keyVersion
  ));
}

function replaceBackupKey(
  lifecycle: PhilDeviceIdentityKeyLifecycleState,
  replacement: PhilDeviceIdentityBackupKeyMetadata
): readonly PhilDeviceIdentityBackupKeyMetadata[] {
  const keys = lifecycle.backupKeys.filter(
    (key) => key.backupKeyVersion !== replacement.backupKeyVersion
  );
  return Object.freeze([...keys, replacement].sort((left, right) =>
    left.backupKeyVersion - right.backupKeyVersion
  ));
}

function lifecycleWith(input: {
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  storageKeys?: readonly PhilDeviceIdentityStorageKeyMetadata[];
  backupKeys?: readonly PhilDeviceIdentityBackupKeyMetadata[];
  migrationVersion?: number;
}): PhilDeviceIdentityKeyLifecycleState {
  return Object.freeze({
    version: PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION,
    storageKeys: Object.freeze([...(input.storageKeys ?? input.lifecycle.storageKeys)]),
    backupKeys: Object.freeze([...(input.backupKeys ?? input.lifecycle.backupKeys)]),
    policy: input.lifecycle.policy,
    migrationVersion: input.migrationVersion ?? input.lifecycle.migrationVersion
  });
}

function annotateEncryptedBlobWithKeyLifecycle(input: {
  encryptedBlob: string;
  keyVersion: number;
  createdAt: string;
  updatedAt: string;
  migrationVersion: number;
}): string {
  const parsed = JSON.parse(input.encryptedBlob) as Record<string, unknown>;
  return stableJson({
    ...parsed,
    keyLifecycle: {
      keyVersion: input.keyVersion,
      encryptionAlgorithm: "aes-256-gcm" as const,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
      migrationVersion: input.migrationVersion
    }
  });
}

function annotateEncryptedBlobWithBackupLifecycle(input: {
  encryptedBlob: string;
  backupKeyVersion: number;
  createdAt: string;
  updatedAt: string;
  migrationVersion: number;
}): string {
  const parsed = JSON.parse(input.encryptedBlob) as Record<string, unknown>;
  return stableJson({
    ...parsed,
    backupLifecycle: {
      backupKeyVersion: input.backupKeyVersion,
      encryptionAlgorithm: "aes-256-gcm" as const,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
      migrationVersion: input.migrationVersion
    }
  });
}

export function createInitialStorageKeyLifecycle(input: {
  storageKeyProvider: PhilDeviceIdentityRegistryKeyProvider;
  backupKeyProvider?: PhilDeviceIdentityRegistryKeyProvider;
  createdAt: string;
  policy?: Partial<PhilDeviceIdentityRotationPolicy>;
}): PhilDeviceIdentityKeyLifecycleState {
  return Object.freeze({
    version: PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION,
    storageKeys: Object.freeze([
      keyRecord({
        keyVersion: 1,
        providerType: input.storageKeyProvider.providerKind,
        createdAt: input.createdAt,
        status: "active"
      })
    ]),
    backupKeys: Object.freeze(input.backupKeyProvider === undefined
      ? []
      : [
          backupKeyRecord({
            backupKeyVersion: 1,
            providerType: input.backupKeyProvider.providerKind,
            createdAt: input.createdAt,
            status: "active"
          })
        ]),
    policy: Object.freeze({
      ...DEFAULT_PHIL_DEVICE_IDENTITY_ROTATION_POLICY,
      ...input.policy,
      requireAuditEvent: true as const
    }),
    migrationVersion: 1
  });
}

export function createVersionedStorageKeyProvider(input: {
  keyVersion: number;
  keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  createdAt: string;
  status?: PhilDeviceIdentityStorageKeyStatus;
  rotatedAt?: string;
}): PhilDeviceIdentityVersionedKeyProvider {
  return Object.freeze({
    keyProvider: input.keyProvider,
    metadata: keyRecord({
      keyVersion: input.keyVersion,
      providerType: input.keyProvider.providerKind,
      createdAt: input.createdAt,
      status: input.status,
      rotatedAt: input.rotatedAt
    })
  });
}

export function createVersionedBackupKeyProvider(input: {
  backupKeyVersion: number;
  keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  createdAt: string;
  status?: PhilDeviceIdentityStorageKeyStatus;
  rotatedAt?: string;
}): PhilDeviceIdentityVersionedBackupKeyProvider {
  return Object.freeze({
    keyProvider: input.keyProvider,
    metadata: backupKeyRecord({
      backupKeyVersion: input.backupKeyVersion,
      providerType: input.keyProvider.providerKind,
      createdAt: input.createdAt,
      status: input.status,
      rotatedAt: input.rotatedAt
    })
  });
}

export async function loadRegistryWithStorageKeyVersion(input: {
  backend: PhilDeviceIdentityRegistryStorageBackend;
  identity: PhilIdentityPublic;
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  key: PhilDeviceIdentityVersionedKeyProvider;
  now?: () => string;
}): Promise<PhilCredentialRegistrySnapshot> {
  const metadata = input.lifecycle.storageKeys.find(
    (key) => key.keyVersion === input.key.metadata.keyVersion
  );
  if (metadata === undefined) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_UNKNOWN_KEY_VERSION",
      `Unknown storage key version ${input.key.metadata.keyVersion}`
    );
  }
  assertKeyCanLoad(metadata);
  const serialized = await input.backend.read();
  if (serialized === null) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_MISSING_REGISTRY",
      "Cannot load storage-key version without an encrypted registry"
    );
  }
  assertEnvelopeMatchesLifecycle({
    serialized,
    lifecycle: input.lifecycle,
    keyVersion: input.key.metadata.keyVersion
  });
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend: input.backend,
    keyProvider: input.key.keyProvider,
    now: input.now
  });
  return store.loadRegistry(input.identity);
}

export async function loadRegistryWithStorageKeyVersions(input: {
  backend: PhilDeviceIdentityRegistryStorageBackend;
  identity: PhilIdentityPublic;
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  keyring: readonly PhilDeviceIdentityStorageKeyringEntry[];
  now?: () => string;
}): Promise<PhilCredentialRegistrySnapshot> {
  const serialized = await input.backend.read();
  if (serialized === null) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_MISSING_REGISTRY",
      "Cannot load storage-key versions without an encrypted registry"
    );
  }
  const envelope = parseLifecycleMetadata(serialized).keyLifecycle;
  if (
    envelope === undefined
      ? input.lifecycle.migrationVersion > 1
      : envelope.migrationVersion < input.lifecycle.migrationVersion
  ) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROLLBACK_DETECTED",
      "Encrypted registry migration metadata is older than the local key lifecycle state"
    );
  }
  const allowedVersions = new Set(
    input.lifecycle.storageKeys
      .filter((key) => key.status === "active" || key.status === "retiring")
      .map((key) => key.keyVersion)
  );
  const orderedKeyring = [...input.keyring].sort((left, right) => {
    if (envelope !== undefined) {
      return Number(right.key.metadata.keyVersion === envelope.keyVersion)
        - Number(left.key.metadata.keyVersion === envelope.keyVersion);
    }
    const leftStatus = input.lifecycle.storageKeys.find(
      (key) => key.keyVersion === left.key.metadata.keyVersion
    )?.status;
    const rightStatus = input.lifecycle.storageKeys.find(
      (key) => key.keyVersion === right.key.metadata.keyVersion
    )?.status;
    return Number(rightStatus === "active") - Number(leftStatus === "active");
  });
  let lastError: unknown;
  for (const entry of orderedKeyring) {
    const keyVersion = entry.key.metadata.keyVersion;
    if (!allowedVersions.has(keyVersion)) {
      continue;
    }
    if (envelope !== undefined && envelope.keyVersion !== keyVersion) {
      continue;
    }
    try {
      return await loadRegistryWithStorageKeyVersion({
        backend: input.backend,
        identity: input.identity,
        lifecycle: input.lifecycle,
        key: entry.key,
        now: input.now
      });
    } catch (error) {
      lastError = error;
    }
  }
  throw new PhilDeviceIdentityKeyLifecycleError(
    "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_NO_LOADABLE_KEY",
    `No active or retiring storage key could load the encrypted registry${
      lastError instanceof Error ? `: ${lastError.message}` : ""
    }`
  );
}

export function markStorageKeyRetired(input: {
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  keyVersion: number;
  retiredAt: string;
}): PhilDeviceIdentityKeyLifecycleState {
  const current = input.lifecycle.storageKeys.find((key) => key.keyVersion === input.keyVersion);
  if (current === undefined) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_UNKNOWN_KEY_VERSION",
      `Unknown storage key version ${input.keyVersion}`
    );
  }
  return lifecycleWith({
    lifecycle: input.lifecycle,
    storageKeys: replaceStorageKey(input.lifecycle, {
      ...current,
      status: "retired",
      rotatedAt: input.retiredAt
    })
  });
}

export function markStorageKeyRevoked(input: {
  lifecycle: PhilDeviceIdentityKeyLifecycleState;
  keyVersion: number;
  revokedAt: string;
}): PhilDeviceIdentityKeyLifecycleState {
  const current = input.lifecycle.storageKeys.find((key) => key.keyVersion === input.keyVersion);
  if (current === undefined) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_UNKNOWN_KEY_VERSION",
      `Unknown storage key version ${input.keyVersion}`
    );
  }
  return lifecycleWith({
    lifecycle: input.lifecycle,
    storageKeys: replaceStorageKey(input.lifecycle, {
      ...current,
      status: "revoked",
      rotatedAt: input.revokedAt
    })
  });
}

export async function rotateStorageKey(
  input: PhilDeviceIdentityStorageKeyRotationInput
): Promise<PhilDeviceIdentityStorageKeyRotationResult> {
  const now = input.now ?? (() => new Date().toISOString());
  assertSingleActiveStorageKey(input.lifecycle);
  const currentMetadata = input.lifecycle.storageKeys.find(
    (key) => key.keyVersion === input.currentKey.metadata.keyVersion
  );
  if (!currentMetadata || currentMetadata.status !== "active") {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_CURRENT_KEY_NOT_ACTIVE",
      "Storage-key rotation requires the current key to be active"
    );
  }
  if (input.lifecycle.policy.requireBackupBeforeRotation && input.requireBackupCompleted !== true) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_BACKUP_REQUIRED",
      "Storage-key rotation requires a completed encrypted backup"
    );
  }
  const beforeBlob = await input.backend.read();
  if (beforeBlob === null) {
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_MISSING_REGISTRY",
      "Cannot rotate storage key without an existing encrypted registry"
    );
  }

  const currentStore = createEncryptedDeviceIdentityRegistryStore({
    backend: input.backend,
    keyProvider: input.currentKey.keyProvider,
    now
  });
  const loaded = await currentStore.loadRegistry(input.identity);
  const started = appendStorageKeyLifecycleAuditEvent({
    snapshot: loaded,
    eventType: "storage-key-rotation-started",
    occurredAt: now(),
    details: {
      fromKeyVersion: input.currentKey.metadata.keyVersion,
      toKeyVersion: input.nextKey.metadata.keyVersion
    }
  });
  const nextStore = createEncryptedDeviceIdentityRegistryStore({
    backend: input.backend,
    keyProvider: input.nextKey.keyProvider,
    now
  });
  const completed = appendStorageKeyLifecycleAuditEvent({
    snapshot: started,
    eventType: "storage-key-rotation-completed",
    occurredAt: now(),
    details: {
      fromKeyVersion: input.currentKey.metadata.keyVersion,
      toKeyVersion: input.nextKey.metadata.keyVersion,
      rollbackProtection: "original blob preserved until re-encryption verifies"
    }
  });

  let saved: PhilCredentialRegistrySnapshot;
  try {
    saved = await nextStore.saveRegistry(completed);
    const savedBlob = await input.backend.read();
    if (savedBlob === null) {
      throw new Error("storage-key rotation produced no encrypted registry");
    }
    await input.backend.write(annotateEncryptedBlobWithKeyLifecycle({
      encryptedBlob: savedBlob,
      keyVersion: input.nextKey.metadata.keyVersion,
      createdAt: saved.auditTrail[0]?.occurredAt ?? now(),
      updatedAt: now(),
      migrationVersion: input.lifecycle.migrationVersion + 1
    }));
    if (input.simulateCommitFailure === true) {
      throw new Error("simulated storage-key rotation commit failure");
    }
    await nextStore.loadRegistry(input.identity);
  } catch (error) {
    await input.backend.write(beforeBlob);
    const failureAuditEvent = storageEvent({
      ownerCommitment: input.identity.ownerCommitment,
      eventType: "storage-key-rotation-failed",
      occurredAt: now(),
      sequence: completed.auditTrail.length,
      details: {
        fromKeyVersion: input.currentKey.metadata.keyVersion,
        toKeyVersion: input.nextKey.metadata.keyVersion,
        rollbackProtection: "original encrypted blob restored",
        reason: error instanceof Error ? error.message : String(error)
      }
    });
    throw new PhilDeviceIdentityKeyLifecycleError(
      "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROTATION_FAILED",
      `Storage-key rotation failed and original registry was preserved: ${
        error instanceof Error ? error.message : String(error)
      }`,
      failureAuditEvent
    );
  }

  const rotatedAt = now();
  const retiringCurrent = keyRecord({
    ...currentMetadata,
    status: "retiring",
    rotatedAt
  });
  const activeNext = keyRecord({
    ...input.nextKey.metadata,
    status: "active",
    rotatedAt
  });
  const lifecycle = lifecycleWith({
    lifecycle: input.lifecycle,
    migrationVersion: input.lifecycle.migrationVersion + 1,
    storageKeys: Object.freeze([
      ...input.lifecycle.storageKeys.filter(
        (key) =>
          key.keyVersion !== retiringCurrent.keyVersion
          && key.keyVersion !== activeNext.keyVersion
      ),
      retiringCurrent,
      activeNext
    ].sort((left, right) => left.keyVersion - right.keyVersion))
  });
  assertSingleActiveStorageKey(lifecycle);
  return {
    lifecycle,
    snapshot: saved,
    rotatedEncryptedBlob: await input.backend.read() ?? ""
  };
}

export async function rotateBackupKey(
  input: PhilDeviceIdentityBackupKeyRotationInput
): Promise<PhilDeviceIdentityBackupKeyRotationResult> {
  const now = input.now ?? (() => new Date().toISOString());
  const currentStore = createEncryptedDeviceIdentityRegistryStore({
    backend: {
      async exists() { return true; },
      async read() { return input.encryptedBackupBlob; },
      async write() {}
    },
    keyProvider: input.currentBackupKey.keyProvider,
    now
  });
  const loaded = await currentStore.loadRegistry(input.identity);
  const started = appendStorageKeyLifecycleAuditEvent({
    snapshot: loaded,
    eventType: "storage-key-rotation-started",
    occurredAt: now(),
    details: {
      backupKeyRotation: true,
      fromBackupKeyVersion: input.currentBackupKey.metadata.backupKeyVersion,
      toBackupKeyVersion: input.nextBackupKey.metadata.backupKeyVersion
    }
  });
  const nextStore = createEncryptedDeviceIdentityRegistryStore({
    backend: {
      async exists() { return false; },
      async read() { return null; },
      async write() {}
    },
    keyProvider: input.nextBackupKey.keyProvider,
    now
  });
  const completed = appendStorageKeyLifecycleAuditEvent({
    snapshot: started,
    eventType: "storage-key-rotation-completed",
    occurredAt: now(),
    details: {
      backupKeyRotation: true,
      fromBackupKeyVersion: input.currentBackupKey.metadata.backupKeyVersion,
      toBackupKeyVersion: input.nextBackupKey.metadata.backupKeyVersion
    }
  });
  const encryptedBackupBlob = await nextStore.exportEncryptedBackupBlob(completed);
  const versionedEncryptedBackupBlob = annotateEncryptedBlobWithBackupLifecycle({
    encryptedBlob: encryptedBackupBlob,
    backupKeyVersion: input.nextBackupKey.metadata.backupKeyVersion,
    createdAt: completed.auditTrail[0]?.occurredAt ?? now(),
    updatedAt: now(),
    migrationVersion: input.lifecycle.migrationVersion + 1
  });
  const verifyStore = createEncryptedDeviceIdentityRegistryStore({
    backend: {
      async exists() { return true; },
      async read() { return versionedEncryptedBackupBlob; },
      async write() {}
    },
    keyProvider: input.nextBackupKey.keyProvider,
    now
  });
  const verified = await verifyStore.loadRegistry(input.identity);
  const rotatedAt = now();
  const retiringCurrent = backupKeyRecord({
    ...input.currentBackupKey.metadata,
    status: "retiring",
    rotatedAt
  });
  const activeNext = backupKeyRecord({
    ...input.nextBackupKey.metadata,
    status: "active",
    rotatedAt
  });
  return {
    lifecycle: lifecycleWith({
      lifecycle: input.lifecycle,
      migrationVersion: input.lifecycle.migrationVersion + 1,
      backupKeys: Object.freeze([
        ...input.lifecycle.backupKeys.filter(
          (key) =>
            key.backupKeyVersion !== retiringCurrent.backupKeyVersion
            && key.backupKeyVersion !== activeNext.backupKeyVersion
        ),
        retiringCurrent,
        activeNext
      ].sort((left, right) => left.backupKeyVersion - right.backupKeyVersion))
    }),
    encryptedBackupBlob: versionedEncryptedBackupBlob,
    snapshot: verified
  };
}
