import { promises as fs } from "node:fs";
import { dirname } from "node:path";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";
import { keccak256, toUtf8Bytes } from "ethers";

import type { PhilIdentityPublic } from "./identity.ts";
import {
  PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION,
  createPhilCredentialRegistry,
  type PhilCredentialAuditEvent,
  type PhilCredentialAuditEventType,
  type PhilCredentialRegistrySnapshot,
  type PhilCredentialRecord,
  type PhilRecoveryPolicy
} from "./deviceIdentityLifecycle.ts";
import type { Hex } from "./hashes.ts";

export const PHIL_DEVICE_IDENTITY_STORAGE_FORMAT =
  "phil-device-identity-registry" as const;
export const PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT =
  "phil-device-identity-registry-encrypted" as const;
export const PHIL_DEVICE_IDENTITY_STORAGE_VERSION = 1 as const;
export const PHIL_DEVICE_IDENTITY_STORAGE_DOMAIN_LABEL =
  "PHIL_DEVICE_IDENTITY_STORAGE_V1" as const;
export const PHIL_DEVICE_IDENTITY_STORAGE_DOMAIN_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_IDENTITY_STORAGE_DOMAIN_LABEL)
) as Hex;

export type PhilDeviceIdentityStorageEventType = Extract<
  PhilCredentialAuditEventType,
  | "registry-created"
  | "registry-loaded"
  | "registry-saved"
  | "registry-migrated"
  | "registry-exported"
  | "registry-imported"
  | "registry-load-failed"
  | "registry-tamper-detected"
>;

export interface PhilDeviceIdentityRegistryPlaintextV1 {
  readonly format: typeof PHIL_DEVICE_IDENTITY_STORAGE_FORMAT;
  readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
  readonly ownerCommitment: Hex;
  readonly identityRootHash: Hex;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly credentials: readonly PhilCredentialRecord[];
  readonly recoveryState: PhilRecoveryPolicy;
  readonly auditEvents: readonly PhilCredentialAuditEvent[];
  readonly storageMetadata: {
    readonly storageVersion: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
    readonly encryptedAtRest: true;
    readonly warning: string;
  };
}

export interface PhilDeviceIdentityEncryptedRegistryBlob {
  readonly format: typeof PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT;
  readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
  readonly encryption: {
    readonly algorithm: "aes-256-gcm";
    readonly iv: string;
    readonly tag: string;
    readonly kdf: PhilDeviceIdentityKeyDerivationMetadata;
  };
  readonly associatedData: {
    readonly format: typeof PHIL_DEVICE_IDENTITY_STORAGE_FORMAT;
    readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
    readonly ownerCommitment: Hex;
  };
  readonly ciphertext: string;
}

export interface PhilDeviceIdentityKeyDerivationMetadata {
  readonly providerKind: string;
  readonly unsafeForProduction: boolean;
  readonly salt?: string;
  readonly scrypt?: {
    readonly N: number;
    readonly r: number;
    readonly p: number;
    readonly keyLength: number;
  };
}

export interface PhilDeviceIdentityKeyProviderInput {
  readonly ownerCommitment: Hex;
  readonly salt?: Uint8Array;
  readonly purpose: "encrypt" | "decrypt";
}

export interface PhilDeviceIdentityResolvedKey {
  readonly key: Uint8Array;
  readonly metadata: PhilDeviceIdentityKeyDerivationMetadata;
}

export interface PhilDeviceIdentityRegistryKeyProvider {
  readonly providerKind: string;
  readonly unsafeForProduction: boolean;
  resolveKey(input: PhilDeviceIdentityKeyProviderInput): PhilDeviceIdentityResolvedKey;
}

export interface PhilDeviceIdentityRegistryStorageBackend {
  exists(): Promise<boolean>;
  read(): Promise<string | null>;
  write(serialized: string): Promise<void>;
}

export interface PhilDeviceIdentityRegistryStoreOptions {
  readonly backend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly now?: () => string;
}

export interface PhilImportEncryptedRegistryOptions {
  readonly encryptedBackupBlob: string;
  readonly expectedIdentity: PhilIdentityPublic;
  readonly replaceExisting?: boolean;
}

export class PhilDeviceIdentityStorageError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilDeviceIdentityStorageError";
    this.code = code;
  }
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return new Uint8Array(Buffer.from(padded, "base64"));
}

function normalizeKey(value: Uint8Array): Buffer {
  const key = Buffer.from(value);
  if (key.byteLength !== 32) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_KEY",
      "Device Identity registry encryption key must be 32 bytes"
    );
  }
  return key;
}

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

function identityRootHash(identity: PhilIdentityPublic): Hex {
  return keccak256(identity.identityRoot) as Hex;
}

function assertOwner(expected: PhilIdentityPublic, ownerCommitment: string) {
  if (ownerCommitment.toLowerCase() !== expected.ownerCommitment.toLowerCase()) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_OWNER_MISMATCH",
      "Encrypted registry owner commitment does not match expected Phil identity"
    );
  }
}

function assertNoPlaintextSecrets(serializedPlaintext: string) {
  if (/phil_secret|mnemonic|privateKey|private key/i.test(serializedPlaintext)) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_SECRET_FIELD_REJECTED",
      "Registry plaintext contains a forbidden secret-bearing field name"
    );
  }
}

function deriveEventId(input: {
  ownerCommitment: Hex;
  eventType: PhilDeviceIdentityStorageEventType;
  occurredAt: string;
  sequence: number;
}): Hex {
  return keccak256(
    toUtf8Bytes(stableJson({
      domain: PHIL_DEVICE_IDENTITY_STORAGE_DOMAIN_HASH,
      ownerCommitment: input.ownerCommitment,
      eventType: input.eventType,
      occurredAt: input.occurredAt,
      sequence: input.sequence
    }))
  ) as Hex;
}

function storageEvent(input: {
  ownerCommitment: Hex;
  eventType: PhilDeviceIdentityStorageEventType;
  occurredAt: string;
  sequence: number;
  details?: Readonly<Record<string, unknown>>;
}): PhilCredentialAuditEvent {
  return Object.freeze({
    eventId: deriveEventId(input),
    eventType: input.eventType,
    ownerCommitment: input.ownerCommitment,
    occurredAt: input.occurredAt,
    details: Object.freeze({ ...(input.details ?? {}) })
  });
}

function snapshotWithStorageEvent(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  eventType: PhilDeviceIdentityStorageEventType;
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

function plaintextFromSnapshot(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  createdAt: string;
  updatedAt: string;
}): PhilDeviceIdentityRegistryPlaintextV1 {
  const plaintext: PhilDeviceIdentityRegistryPlaintextV1 = Object.freeze({
    format: PHIL_DEVICE_IDENTITY_STORAGE_FORMAT,
    version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
    ownerCommitment: input.snapshot.philIdentity.ownerCommitment,
    identityRootHash: identityRootHash(input.snapshot.philIdentity),
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    credentials: input.snapshot.credentials,
    recoveryState: input.snapshot.recoveryPolicy,
    auditEvents: input.snapshot.auditTrail,
    storageMetadata: {
      storageVersion: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
      encryptedAtRest: true as const,
      warning:
        "Local/dev encrypted storage baseline; not a production vault or final key-management design"
    }
  });
  assertNoPlaintextSecrets(stableJson(plaintext));
  return plaintext;
}

function validatePlaintextV1(
  plaintext: unknown,
  expectedIdentity: PhilIdentityPublic
): PhilDeviceIdentityRegistryPlaintextV1 {
  if (!plaintext || typeof plaintext !== "object") {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_REGISTRY",
      "Registry plaintext must be an object"
    );
  }
  const candidate = plaintext as Partial<PhilDeviceIdentityRegistryPlaintextV1>;
  if (candidate.format !== PHIL_DEVICE_IDENTITY_STORAGE_FORMAT) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_FORMAT",
      "Registry plaintext format is invalid"
    );
  }
  if (candidate.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_VERSION",
      `Unsupported registry version: ${String(candidate.version)}`
    );
  }
  if (candidate.ownerCommitment === undefined) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_REGISTRY",
      "Registry owner commitment is required"
    );
  }
  assertOwner(expectedIdentity, candidate.ownerCommitment);
  if (candidate.identityRootHash !== identityRootHash(expectedIdentity)) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_OWNER_MISMATCH",
      "Registry identity root hash does not match expected Phil identity"
    );
  }
  if (!Array.isArray(candidate.credentials) || !Array.isArray(candidate.auditEvents)) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_REGISTRY",
      "Registry credentials and audit events must be arrays"
    );
  }
  if (!candidate.recoveryState || typeof candidate.recoveryState !== "object") {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_REGISTRY",
      "Registry recovery state is required"
    );
  }
  return candidate as PhilDeviceIdentityRegistryPlaintextV1;
}

function parseEncryptedBlob(serialized: string): PhilDeviceIdentityEncryptedRegistryBlob {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_CORRUPTED_REGISTRY",
      "Encrypted registry JSON is corrupted"
    );
  }
  if (!parsed || typeof parsed !== "object") {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_ENVELOPE",
      "Encrypted registry envelope must be an object"
    );
  }
  const blob = parsed as Partial<PhilDeviceIdentityEncryptedRegistryBlob>;
  if (blob.format !== PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_FORMAT",
      "Encrypted registry format is invalid"
    );
  }
  if (blob.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_VERSION",
      `Unsupported encrypted registry version: ${String(blob.version)}`
    );
  }
  if (!blob.encryption || !blob.associatedData || typeof blob.ciphertext !== "string") {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_INVALID_ENVELOPE",
      "Encrypted registry envelope is missing required fields"
    );
  }
  return blob as PhilDeviceIdentityEncryptedRegistryBlob;
}

function encryptSnapshot(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  createdAt: string;
  updatedAt: string;
}): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = input.keyProvider.resolveKey({
    ownerCommitment: input.snapshot.philIdentity.ownerCommitment,
    salt,
    purpose: "encrypt"
  });
  const metadata: PhilDeviceIdentityKeyDerivationMetadata = {
    ...key.metadata,
    salt: base64Url(salt)
  };
  const aad = {
    format: PHIL_DEVICE_IDENTITY_STORAGE_FORMAT,
    version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
    ownerCommitment: input.snapshot.philIdentity.ownerCommitment
  } as const;
  const plaintext = Buffer.from(
    stableJson(plaintextFromSnapshot(input)),
    "utf8"
  );
  const cipher = createCipheriv("aes-256-gcm", normalizeKey(key.key), iv);
  cipher.setAAD(Buffer.from(stableJson(aad), "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const blob: PhilDeviceIdentityEncryptedRegistryBlob = Object.freeze({
    format: PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT,
    version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
    encryption: {
      algorithm: "aes-256-gcm" as const,
      iv: base64Url(iv),
      tag: base64Url(cipher.getAuthTag()),
      kdf: metadata
    },
    associatedData: aad,
    ciphertext: base64Url(ciphertext)
  });
  return stableJson(blob);
}

function decryptBlob(input: {
  serialized: string;
  expectedIdentity: PhilIdentityPublic;
  keyProvider: PhilDeviceIdentityRegistryKeyProvider;
}): PhilDeviceIdentityRegistryPlaintextV1 {
  const blob = parseEncryptedBlob(input.serialized);
  assertOwner(input.expectedIdentity, blob.associatedData.ownerCommitment);
  if (blob.encryption.algorithm !== "aes-256-gcm") {
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_ENCRYPTION",
      "Unsupported registry encryption algorithm"
    );
  }
  const salt = blob.encryption.kdf.salt === undefined
    ? undefined
    : base64UrlBytes(blob.encryption.kdf.salt);
  const key = input.keyProvider.resolveKey({
    ownerCommitment: input.expectedIdentity.ownerCommitment,
    salt,
    purpose: "decrypt"
  });

  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      normalizeKey(key.key),
      Buffer.from(base64UrlBytes(blob.encryption.iv))
    );
    decipher.setAAD(Buffer.from(stableJson(blob.associatedData), "utf8"));
    decipher.setAuthTag(Buffer.from(base64UrlBytes(blob.encryption.tag)));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(base64UrlBytes(blob.ciphertext))),
      decipher.final()
    ]);
    return validatePlaintextV1(JSON.parse(plaintext.toString("utf8")), input.expectedIdentity);
  } catch (error) {
    if (error instanceof PhilDeviceIdentityStorageError) {
      throw error;
    }
    throw new PhilDeviceIdentityStorageError(
      "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED",
      "Encrypted registry authentication failed or decrypted JSON was invalid"
    );
  }
}

export function createLocalDevPassphraseKeyProvider(input: {
  passphrase: string;
  scrypt?: {
    N?: number;
    r?: number;
    p?: number;
    keyLength?: number;
  };
}): PhilDeviceIdentityRegistryKeyProvider {
  const scrypt = {
    N: input.scrypt?.N ?? 32_768,
    r: input.scrypt?.r ?? 8,
    p: input.scrypt?.p ?? 1,
    keyLength: input.scrypt?.keyLength ?? 32
  };
  return Object.freeze({
    providerKind: "local-dev-passphrase-scrypt-device-registry-key-test-only-v1",
    unsafeForProduction: true,
    resolveKey(keyInput: PhilDeviceIdentityKeyProviderInput): PhilDeviceIdentityResolvedKey {
      const salt = keyInput.salt ?? randomBytes(16);
      const key = scryptSync(
        input.passphrase,
        Buffer.concat([
          Buffer.from(salt),
          Buffer.from(keyInput.ownerCommitment.slice(2), "hex")
        ]),
        scrypt.keyLength,
        {
          N: scrypt.N,
          r: scrypt.r,
          p: scrypt.p
        }
      );
      return {
        key: new Uint8Array(key),
        metadata: {
          providerKind: this.providerKind,
          unsafeForProduction: true,
          scrypt
        }
      };
    }
  });
}

export function createInjectedRawKeyProvider(input: {
  key: Uint8Array;
}): PhilDeviceIdentityRegistryKeyProvider {
  const key = normalizeKey(input.key);
  return Object.freeze({
    providerKind: "injected-raw-aes256-device-registry-key-v1",
    unsafeForProduction: false,
    resolveKey(): PhilDeviceIdentityResolvedKey {
      return {
        key: new Uint8Array(key),
        metadata: {
          providerKind: this.providerKind,
          unsafeForProduction: false
        }
      };
    }
  });
}

export function createFuturePlatformKeychainProviderScaffold(): PhilDeviceIdentityRegistryKeyProvider {
  return Object.freeze({
    providerKind: "future-platform-keychain-device-registry-key-scaffold-v1",
    unsafeForProduction: false,
    resolveKey(): PhilDeviceIdentityResolvedKey {
      throw new PhilDeviceIdentityStorageError(
        "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_KEY_PROVIDER",
        "Platform keychain registry key provider is a future scaffold"
      );
    }
  });
}

export function createFutureSecureEnclaveKeyProviderScaffold(): PhilDeviceIdentityRegistryKeyProvider {
  return Object.freeze({
    providerKind: "future-secure-enclave-device-registry-key-scaffold-v1",
    unsafeForProduction: false,
    resolveKey(): PhilDeviceIdentityResolvedKey {
      throw new PhilDeviceIdentityStorageError(
        "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_KEY_PROVIDER",
        "Secure Enclave registry key provider is a future scaffold"
      );
    }
  });
}

export function createInMemoryDeviceIdentityRegistryStorageBackend(
  initialValue?: string
): PhilDeviceIdentityRegistryStorageBackend {
  let value: string | null = initialValue ?? null;
  return Object.freeze({
    async exists(): Promise<boolean> {
      return value !== null;
    },
    async read(): Promise<string | null> {
      return value;
    },
    async write(serialized: string): Promise<void> {
      value = serialized;
    }
  });
}

export function createFileDeviceIdentityRegistryStorageBackend(input: {
  filePath: string;
}): PhilDeviceIdentityRegistryStorageBackend {
  return Object.freeze({
    async exists(): Promise<boolean> {
      try {
        await fs.access(input.filePath);
        return true;
      } catch {
        return false;
      }
    },
    async read(): Promise<string | null> {
      try {
        return await fs.readFile(input.filePath, "utf8");
      } catch (error) {
        if (
          error
          && typeof error === "object"
          && (error as { code?: unknown }).code === "ENOENT"
        ) {
          return null;
        }
        throw error;
      }
    },
    async write(serialized: string): Promise<void> {
      await fs.mkdir(dirname(input.filePath), { recursive: true });
      await fs.writeFile(input.filePath, serialized, {
        encoding: "utf8",
        mode: 0o600
      });
    }
  });
}

export function createEncryptedDeviceIdentityRegistryStore(
  options: PhilDeviceIdentityRegistryStoreOptions
) {
  const now = options.now ?? (() => new Date().toISOString());
  let volatileStorageAuditEvents: PhilCredentialAuditEvent[] = [];

  function recordVolatileStorageEvent(input: {
    expectedIdentity: PhilIdentityPublic;
    eventType: "registry-load-failed" | "registry-tamper-detected";
    details?: Readonly<Record<string, unknown>>;
  }) {
    volatileStorageAuditEvents = [
      ...volatileStorageAuditEvents,
      storageEvent({
        ownerCommitment: input.expectedIdentity.ownerCommitment,
        eventType: input.eventType,
        occurredAt: now(),
        sequence: volatileStorageAuditEvents.length,
        details: input.details
      })
    ];
  }

  async function loadPlaintext(expectedIdentity: PhilIdentityPublic): Promise<PhilDeviceIdentityRegistryPlaintextV1> {
    const serialized = await options.backend.read();
    if (serialized === null) {
      throw new PhilDeviceIdentityStorageError(
        "PHIL_DEVICE_IDENTITY_STORAGE_MISSING_REGISTRY",
        "Encrypted Device Identity registry is missing"
      );
    }
    return decryptBlob({
      serialized,
      expectedIdentity,
      keyProvider: options.keyProvider
    });
  }

  function snapshotFromPlaintextForIdentity(
    plaintext: PhilDeviceIdentityRegistryPlaintextV1,
    identity: PhilIdentityPublic
  ): PhilCredentialRegistrySnapshot {
    return createPhilCredentialRegistry({
      philIdentity: identity,
      credentials: plaintext.credentials,
      recoveryPolicy: plaintext.recoveryState,
      auditTrail: plaintext.auditEvents
    }).getSnapshot();
  }

  return Object.freeze({
    async exists(): Promise<boolean> {
      return options.backend.exists();
    },

    async createNewRegistry(
      philIdentity: PhilIdentityPublic
    ): Promise<PhilCredentialRegistrySnapshot> {
      return snapshotWithStorageEvent({
        snapshot: createPhilCredentialRegistry({ philIdentity }).getSnapshot(),
        eventType: "registry-created",
        occurredAt: now(),
        details: {
          storageFormat: PHIL_DEVICE_IDENTITY_STORAGE_FORMAT,
          storageVersion: PHIL_DEVICE_IDENTITY_STORAGE_VERSION
        }
      });
    },

    async saveRegistry(
      snapshot: PhilCredentialRegistrySnapshot
    ): Promise<PhilCredentialRegistrySnapshot> {
      const saved = snapshotWithStorageEvent({
        snapshot,
        eventType: "registry-saved",
        occurredAt: now(),
        details: {
          encryption: "aes-256-gcm",
          keyProviderKind: options.keyProvider.providerKind,
          keyProviderUnsafeForProduction: options.keyProvider.unsafeForProduction
        }
      });
      const serialized = encryptSnapshot({
        snapshot: saved,
        keyProvider: options.keyProvider,
        createdAt: saved.auditTrail[0]?.occurredAt ?? now(),
        updatedAt: now()
      });
      await options.backend.write(serialized);
      return saved;
    },

    async loadRegistry(
      expectedIdentity: PhilIdentityPublic
    ): Promise<PhilCredentialRegistrySnapshot> {
      try {
        const plaintext = await loadPlaintext(expectedIdentity);
        return snapshotWithStorageEvent({
          snapshot: snapshotFromPlaintextForIdentity(plaintext, expectedIdentity),
          eventType: "registry-loaded",
          occurredAt: now(),
          details: {
            storageVersion: plaintext.version
          }
        });
      } catch (error) {
        const code = error instanceof PhilDeviceIdentityStorageError
          ? error.code
          : "PHIL_DEVICE_IDENTITY_STORAGE_UNKNOWN_LOAD_ERROR";
        if (
          error instanceof PhilDeviceIdentityStorageError
          && error.code === "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED"
        ) {
          recordVolatileStorageEvent({
            expectedIdentity,
            eventType: "registry-tamper-detected",
            details: { code }
          });
          throw new PhilDeviceIdentityStorageError(
            "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED",
            "Encrypted Device Identity registry failed authenticated integrity checks"
          );
        }
        recordVolatileStorageEvent({
          expectedIdentity,
          eventType: "registry-load-failed",
          details: { code }
        });
        throw error;
      }
    },

    async validateRegistry(expectedIdentity: PhilIdentityPublic): Promise<boolean> {
      await loadPlaintext(expectedIdentity);
      return true;
    },

    async migrateRegistry(
      expectedIdentity: PhilIdentityPublic
    ): Promise<PhilCredentialRegistrySnapshot> {
      const plaintext = await loadPlaintext(expectedIdentity);
      if (plaintext.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
        throw new PhilDeviceIdentityStorageError(
          "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_VERSION",
          `Unsupported registry version: ${String(plaintext.version)}`
        );
      }
      return snapshotWithStorageEvent({
        snapshot: snapshotFromPlaintextForIdentity(plaintext, expectedIdentity),
        eventType: "registry-migrated",
        occurredAt: now(),
        details: {
          fromVersion: 1,
          toVersion: 1,
          migration: "none-required"
        }
      });
    },

    async exportEncryptedBackupBlob(
      snapshot: PhilCredentialRegistrySnapshot
    ): Promise<string> {
      const exported = snapshotWithStorageEvent({
        snapshot,
        eventType: "registry-exported",
        occurredAt: now(),
        details: {
          encrypted: true
        }
      });
      return encryptSnapshot({
        snapshot: exported,
        keyProvider: options.keyProvider,
        createdAt: exported.auditTrail[0]?.occurredAt ?? now(),
        updatedAt: now()
      });
    },

    async importEncryptedBackupBlob(
      input: PhilImportEncryptedRegistryOptions
    ): Promise<PhilCredentialRegistrySnapshot> {
      if (input.replaceExisting !== true && await options.backend.exists()) {
        throw new PhilDeviceIdentityStorageError(
          "PHIL_DEVICE_IDENTITY_STORAGE_REPLACE_REQUIRED",
          "Encrypted registry import would overwrite an existing registry; pass replaceExisting: true"
        );
      }
      const plaintext = decryptBlob({
        serialized: input.encryptedBackupBlob,
        expectedIdentity: input.expectedIdentity,
        keyProvider: options.keyProvider
      });
      const imported = snapshotWithStorageEvent({
        snapshot: snapshotFromPlaintextForIdentity(plaintext, input.expectedIdentity),
        eventType: "registry-imported",
        occurredAt: now(),
        details: {
          importedAuditEventCount: plaintext.auditEvents.length
        }
      });
      await options.backend.write(encryptSnapshot({
        snapshot: imported,
        keyProvider: options.keyProvider,
        createdAt: plaintext.createdAt,
        updatedAt: now()
      }));
      return imported;
    },

    async readEncryptedBlobForTests(): Promise<string | null> {
      return options.backend.read();
    },

    getVolatileStorageAuditEvents(): readonly PhilCredentialAuditEvent[] {
      return Object.freeze([...volatileStorageAuditEvents]);
    }
  });
}

export function encryptedBlobOwnerCommitment(serialized: string): Hex {
  const blob = parseEncryptedBlob(serialized);
  return blob.associatedData.ownerCommitment;
}

export function constantTimeEqualBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
}
