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

export const PHIL_DEVICE_IDENTITY_INDEXEDDB_DATABASE =
  "phil_device_identity" as const;
export const PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE =
  "registries" as const;
export const PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE =
  "registry_metadata" as const;
export const PHIL_DEVICE_IDENTITY_STORAGE_FORMAT =
  "phil-device-identity-registry" as const;
export const PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT =
  "phil-device-identity-registry-encrypted" as const;
export const PHIL_DEVICE_IDENTITY_STORAGE_VERSION = 1 as const;
export const PHIL_DEVICE_IDENTITY_INDEXEDDB_STORAGE_DOMAIN_LABEL =
  "PHIL_DEVICE_IDENTITY_INDEXEDDB_STORAGE_V1" as const;
export const PHIL_DEVICE_IDENTITY_INDEXEDDB_STORAGE_DOMAIN_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_IDENTITY_INDEXEDDB_STORAGE_DOMAIN_LABEL)
) as Hex;

export type PhilDeviceIdentityBrowserRuntimeKind =
  | "browser"
  | "node"
  | "unsupported";

export type PhilDeviceIdentityBrowserStorageEventType = Extract<
  PhilCredentialAuditEventType,
  | "registry-created"
  | "registry-loaded"
  | "registry-saved"
  | "registry-exported"
  | "registry-imported"
  | "registry-load-failed"
  | "registry-tamper-detected"
>;

export interface PhilDeviceIdentityBrowserCryptoLike {
  readonly subtle: SubtleCrypto;
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
}

export interface PhilDeviceIdentityBrowserCryptoAdapter {
  readonly cryptoKind: "webcrypto";
  randomBytes(length: number): Uint8Array;
  sha256(value: string | Uint8Array): Promise<Uint8Array>;
  importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey>;
  derivePbkdf2AesGcmKey(input: {
    passphrase: string;
    salt: Uint8Array;
    iterations: number;
  }): Promise<CryptoKey>;
  encryptAesGcm(input: {
    key: CryptoKey;
    iv: Uint8Array;
    plaintext: Uint8Array;
    additionalData: Uint8Array;
  }): Promise<{
    ciphertext: Uint8Array;
    tag: Uint8Array;
  }>;
  decryptAesGcm(input: {
    key: CryptoKey;
    iv: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
    additionalData: Uint8Array;
  }): Promise<Uint8Array>;
}

export interface PhilDeviceIdentityBrowserKeyDerivationMetadata {
  readonly providerKind: string;
  readonly unsafeForProduction: boolean;
  readonly salt?: string;
  readonly pbkdf2?: {
    readonly hash: "SHA-256";
    readonly iterations: number;
    readonly keyLength: 256;
  };
}

export interface PhilDeviceIdentityBrowserKeyProviderInput {
  readonly ownerCommitment: Hex;
  readonly salt?: Uint8Array;
  readonly purpose: "encrypt" | "decrypt";
  readonly crypto: PhilDeviceIdentityBrowserCryptoAdapter;
}

export interface PhilDeviceIdentityBrowserResolvedKey {
  readonly key: CryptoKey;
  readonly metadata: PhilDeviceIdentityBrowserKeyDerivationMetadata;
}

export interface PhilDeviceIdentityBrowserRegistryKeyProvider {
  readonly providerKind: string;
  readonly unsafeForProduction: boolean;
  readonly rawKeyExportable: boolean;
  resolveKey(
    input: PhilDeviceIdentityBrowserKeyProviderInput
  ): Promise<PhilDeviceIdentityBrowserResolvedKey>;
}

export interface PhilDeviceIdentityBrowserRegistryPlaintextV1 {
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
    readonly runtime: "browser-indexeddb";
    readonly warning: string;
  };
}

export interface PhilDeviceIdentityBrowserEncryptedRegistryBlob {
  readonly format: typeof PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT;
  readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
  readonly encryption: {
    readonly algorithm: "aes-256-gcm-webcrypto";
    readonly iv: string;
    readonly tag: string;
    readonly kdf: PhilDeviceIdentityBrowserKeyDerivationMetadata;
  };
  readonly associatedData: {
    readonly format: typeof PHIL_DEVICE_IDENTITY_STORAGE_FORMAT;
    readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
    readonly ownerCommitment: Hex;
  };
  readonly ciphertext: string;
}

export interface PhilDeviceIdentityIndexedDbRegistryRecord {
  readonly ownerCommitment: Hex;
  readonly encryptedBlob: string;
  readonly updatedAt: string;
}

export interface PhilDeviceIdentityIndexedDbRegistryMetadata {
  readonly ownerCommitment: Hex;
  readonly format: typeof PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT;
  readonly version: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
  readonly encrypted: true;
  readonly updatedAt: string;
}

export interface PhilDeviceIdentityIndexedDbLike {
  open(name: string, version?: number): IDBOpenDBRequest;
}

export interface PhilDeviceIdentityIndexedDbStorageOptions {
  readonly indexedDb?: PhilDeviceIdentityIndexedDbLike;
  readonly dbName?: string;
  readonly version?: number;
}

export interface PhilDeviceIdentityIndexedDbRegistryStorage {
  saveEncryptedBlob(input: {
    ownerCommitment: Hex;
    encryptedBlob: string;
    updatedAt: string;
  }): Promise<void>;
  loadEncryptedBlob(ownerCommitment: Hex): Promise<string | null>;
  deleteRegistry(ownerCommitment: Hex): Promise<void>;
  listRegistryMetadata(): Promise<readonly PhilDeviceIdentityIndexedDbRegistryMetadata[]>;
}

export interface PhilDeviceIdentityBrowserRegistryStoreOptions {
  readonly storage: PhilDeviceIdentityIndexedDbRegistryStorage;
  readonly keyProvider: PhilDeviceIdentityBrowserRegistryKeyProvider;
  readonly crypto?: PhilDeviceIdentityBrowserCryptoAdapter;
  readonly now?: () => string;
}

export interface PhilDeviceIdentityBrowserImportOptions {
  readonly encryptedBackupBlob: string;
  readonly expectedIdentity: PhilIdentityPublic;
  readonly replaceExisting?: boolean;
}

export class PhilDeviceIdentityBrowserStorageError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilDeviceIdentityBrowserStorageError";
    this.code = code;
  }
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function textFromBytes(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = typeof btoa === "function"
    ? btoa(binary)
    : Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = typeof atob === "function"
    ? atob(padded)
    : Buffer.from(padded, "base64").toString("binary");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
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

function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out.buffer;
}

function detectGlobalCrypto(): PhilDeviceIdentityBrowserCryptoLike | undefined {
  const candidate = globalThis.crypto;
  if (
    candidate
    && candidate.subtle
    && typeof candidate.getRandomValues === "function"
  ) {
    return candidate as PhilDeviceIdentityBrowserCryptoLike;
  }
  return undefined;
}

export function detectPhilDeviceIdentityBrowserRuntime(input: {
  indexedDb?: PhilDeviceIdentityIndexedDbLike;
  crypto?: PhilDeviceIdentityBrowserCryptoLike;
} = {}): PhilDeviceIdentityBrowserRuntimeKind {
  const hasIndexedDb = Boolean(input.indexedDb ?? (globalThis as { indexedDB?: unknown }).indexedDB);
  const hasCrypto = Boolean(input.crypto ?? detectGlobalCrypto());
  if (hasIndexedDb && hasCrypto) {
    return "browser";
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    return "node";
  }
  return "unsupported";
}

export function createBrowserWebCryptoAdapter(
  cryptoLike?: PhilDeviceIdentityBrowserCryptoLike
): PhilDeviceIdentityBrowserCryptoAdapter {
  const crypto = cryptoLike ?? detectGlobalCrypto();
  if (
    !crypto
    || !crypto.subtle
    || typeof crypto.getRandomValues !== "function"
  ) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_BROWSER_CRYPTO_UNSUPPORTED",
      "WebCrypto crypto.subtle and getRandomValues are required"
    );
  }
  return Object.freeze({
    cryptoKind: "webcrypto" as const,
    randomBytes(length: number): Uint8Array {
      const out = new Uint8Array(length);
      crypto.getRandomValues(out);
      return out;
    },
    async sha256(value: string | Uint8Array): Promise<Uint8Array> {
      const bytes = typeof value === "string" ? textBytes(value) : value;
      return new Uint8Array(
        await crypto.subtle.digest("SHA-256", ownedArrayBuffer(bytes))
      );
    },
    async importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey> {
      if (rawKey.byteLength !== 32) {
        throw new PhilDeviceIdentityBrowserStorageError(
          "PHIL_DEVICE_IDENTITY_BROWSER_STORAGE_INVALID_KEY",
          "Browser registry AES-GCM key must be 32 bytes"
        );
      }
      return crypto.subtle.importKey(
        "raw",
        ownedArrayBuffer(rawKey),
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    },
    async derivePbkdf2AesGcmKey(input: {
      passphrase: string;
      salt: Uint8Array;
      iterations: number;
    }): Promise<CryptoKey> {
      const baseKey = await crypto.subtle.importKey(
        "raw",
        ownedArrayBuffer(textBytes(input.passphrase)),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: ownedArrayBuffer(input.salt),
          iterations: input.iterations,
          hash: "SHA-256"
        },
        baseKey,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["encrypt", "decrypt"]
      );
    },
    async encryptAesGcm(input: {
      key: CryptoKey;
      iv: Uint8Array;
      plaintext: Uint8Array;
      additionalData: Uint8Array;
    }): Promise<{
      ciphertext: Uint8Array;
      tag: Uint8Array;
    }> {
      const combined = new Uint8Array(await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: ownedArrayBuffer(input.iv),
          additionalData: ownedArrayBuffer(input.additionalData),
          tagLength: 128
        },
        input.key,
        ownedArrayBuffer(input.plaintext)
      ));
      return {
        ciphertext: combined.slice(0, combined.byteLength - 16),
        tag: combined.slice(combined.byteLength - 16)
      };
    },
    async decryptAesGcm(input: {
      key: CryptoKey;
      iv: Uint8Array;
      ciphertext: Uint8Array;
      tag: Uint8Array;
      additionalData: Uint8Array;
    }): Promise<Uint8Array> {
      return new Uint8Array(await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ownedArrayBuffer(input.iv),
          additionalData: ownedArrayBuffer(input.additionalData),
          tagLength: 128
        },
        input.key,
        ownedArrayBuffer(concatBytes(input.ciphertext, input.tag))
      ));
    }
  });
}

function identityRootHash(identity: PhilIdentityPublic): Hex {
  return keccak256(identity.identityRoot) as Hex;
}

function assertOwner(expected: PhilIdentityPublic, ownerCommitment: string) {
  if (ownerCommitment.toLowerCase() !== expected.ownerCommitment.toLowerCase()) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_OWNER_MISMATCH",
      "IndexedDB encrypted registry owner commitment does not match expected Phil identity"
    );
  }
}

function assertNoPlaintextSecrets(serializedPlaintext: string) {
  if (/phil_secret|mnemonic|privateKey|private key/i.test(serializedPlaintext)) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_SECRET_FIELD_REJECTED",
      "Browser registry plaintext contains a forbidden secret-bearing field name"
    );
  }
}

function storageEvent(input: {
  ownerCommitment: Hex;
  eventType: PhilDeviceIdentityBrowserStorageEventType;
  occurredAt: string;
  sequence: number;
  details?: Readonly<Record<string, unknown>>;
}): PhilCredentialAuditEvent {
  return Object.freeze({
    eventId: keccak256(toUtf8Bytes(stableJson({
      domain: PHIL_DEVICE_IDENTITY_INDEXEDDB_STORAGE_DOMAIN_HASH,
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

function snapshotWithStorageEvent(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  eventType: PhilDeviceIdentityBrowserStorageEventType;
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
}): PhilDeviceIdentityBrowserRegistryPlaintextV1 {
  const plaintext: PhilDeviceIdentityBrowserRegistryPlaintextV1 = Object.freeze({
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
      runtime: "browser-indexeddb" as const,
      warning:
        "Browser-oriented encrypted storage baseline; not a production vault or final key-management design"
    }
  });
  assertNoPlaintextSecrets(stableJson(plaintext));
  return plaintext;
}

function validatePlaintext(
  plaintext: unknown,
  expectedIdentity: PhilIdentityPublic
): PhilDeviceIdentityBrowserRegistryPlaintextV1 {
  if (!plaintext || typeof plaintext !== "object") {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_REGISTRY",
      "Browser registry plaintext must be an object"
    );
  }
  const candidate = plaintext as Partial<PhilDeviceIdentityBrowserRegistryPlaintextV1>;
  if (candidate.format !== PHIL_DEVICE_IDENTITY_STORAGE_FORMAT) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_FORMAT",
      "Browser registry plaintext format is invalid"
    );
  }
  if (candidate.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_VERSION",
      `Unsupported browser registry version: ${String(candidate.version)}`
    );
  }
  if (candidate.ownerCommitment === undefined) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_REGISTRY",
      "Browser registry owner commitment is required"
    );
  }
  assertOwner(expectedIdentity, candidate.ownerCommitment);
  if (candidate.identityRootHash !== identityRootHash(expectedIdentity)) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_OWNER_MISMATCH",
      "Browser registry identity root hash does not match expected Phil identity"
    );
  }
  if (!Array.isArray(candidate.credentials) || !Array.isArray(candidate.auditEvents)) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_REGISTRY",
      "Browser registry credentials and audit events must be arrays"
    );
  }
  if (!candidate.recoveryState || typeof candidate.recoveryState !== "object") {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_REGISTRY",
      "Browser registry recovery state is required"
    );
  }
  return candidate as PhilDeviceIdentityBrowserRegistryPlaintextV1;
}

function parseEncryptedBlob(serialized: string): PhilDeviceIdentityBrowserEncryptedRegistryBlob {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_CORRUPTED_REGISTRY",
      "IndexedDB encrypted registry JSON is corrupted"
    );
  }
  if (!parsed || typeof parsed !== "object") {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_ENVELOPE",
      "IndexedDB encrypted registry envelope must be an object"
    );
  }
  const blob = parsed as Partial<PhilDeviceIdentityBrowserEncryptedRegistryBlob>;
  if (blob.format !== PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_FORMAT",
      "IndexedDB encrypted registry format is invalid"
    );
  }
  if (blob.version !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_VERSION",
      `Unsupported IndexedDB encrypted registry version: ${String(blob.version)}`
    );
  }
  if (!blob.encryption || !blob.associatedData || typeof blob.ciphertext !== "string") {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_INVALID_ENVELOPE",
      "IndexedDB encrypted registry envelope is missing required fields"
    );
  }
  return blob as PhilDeviceIdentityBrowserEncryptedRegistryBlob;
}

async function encryptSnapshot(input: {
  snapshot: PhilCredentialRegistrySnapshot;
  keyProvider: PhilDeviceIdentityBrowserRegistryKeyProvider;
  crypto: PhilDeviceIdentityBrowserCryptoAdapter;
  createdAt: string;
  updatedAt: string;
}): Promise<string> {
  const salt = input.crypto.randomBytes(16);
  const iv = input.crypto.randomBytes(12);
  const resolved = await input.keyProvider.resolveKey({
    ownerCommitment: input.snapshot.philIdentity.ownerCommitment,
    salt,
    purpose: "encrypt",
    crypto: input.crypto
  });
  const aad = {
    format: PHIL_DEVICE_IDENTITY_STORAGE_FORMAT,
    version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
    ownerCommitment: input.snapshot.philIdentity.ownerCommitment
  } as const;
  const encrypted = await input.crypto.encryptAesGcm({
    key: resolved.key,
    iv,
    plaintext: textBytes(stableJson(plaintextFromSnapshot(input))),
    additionalData: textBytes(stableJson(aad))
  });
  return stableJson({
    format: PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT,
    version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
    encryption: {
      algorithm: "aes-256-gcm-webcrypto",
      iv: base64Url(iv),
      tag: base64Url(encrypted.tag),
      kdf: {
        ...resolved.metadata,
        salt: base64Url(salt)
      }
    },
    associatedData: aad,
    ciphertext: base64Url(encrypted.ciphertext)
  } satisfies PhilDeviceIdentityBrowserEncryptedRegistryBlob);
}

async function decryptBlob(input: {
  serialized: string;
  expectedIdentity: PhilIdentityPublic;
  keyProvider: PhilDeviceIdentityBrowserRegistryKeyProvider;
  crypto: PhilDeviceIdentityBrowserCryptoAdapter;
}): Promise<PhilDeviceIdentityBrowserRegistryPlaintextV1> {
  const blob = parseEncryptedBlob(input.serialized);
  assertOwner(input.expectedIdentity, blob.associatedData.ownerCommitment);
  if (blob.encryption.algorithm !== "aes-256-gcm-webcrypto") {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_ENCRYPTION",
      "Unsupported browser registry encryption algorithm"
    );
  }
  const salt = blob.encryption.kdf.salt === undefined
    ? undefined
    : base64UrlBytes(blob.encryption.kdf.salt);
  const resolved = await input.keyProvider.resolveKey({
    ownerCommitment: input.expectedIdentity.ownerCommitment,
    salt,
    purpose: "decrypt",
    crypto: input.crypto
  });

  try {
    const plaintext = await input.crypto.decryptAesGcm({
      key: resolved.key,
      iv: base64UrlBytes(blob.encryption.iv),
      ciphertext: base64UrlBytes(blob.ciphertext),
      tag: base64UrlBytes(blob.encryption.tag),
      additionalData: textBytes(stableJson(blob.associatedData))
    });
    return validatePlaintext(JSON.parse(textFromBytes(plaintext)), input.expectedIdentity);
  } catch (error) {
    if (error instanceof PhilDeviceIdentityBrowserStorageError) {
      throw error;
    }
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_TAMPER_DETECTED",
      "IndexedDB encrypted registry authentication failed or decrypted JSON was invalid"
    );
  }
}

export function createBrowserPassphraseKeyProvider(input: {
  passphrase: string;
  iterations?: number;
}): PhilDeviceIdentityBrowserRegistryKeyProvider {
  const iterations = input.iterations ?? 310_000;
  return Object.freeze({
    providerKind: "browser-passphrase-pbkdf2-device-registry-key-local-v1",
    unsafeForProduction: true,
    rawKeyExportable: false,
    async resolveKey(
      keyInput: PhilDeviceIdentityBrowserKeyProviderInput
    ): Promise<PhilDeviceIdentityBrowserResolvedKey> {
      const salt = keyInput.salt ?? keyInput.crypto.randomBytes(16);
      return {
        key: await keyInput.crypto.derivePbkdf2AesGcmKey({
          passphrase: input.passphrase,
          salt,
          iterations
        }),
        metadata: {
          providerKind: this.providerKind,
          unsafeForProduction: true,
          pbkdf2: {
            hash: "SHA-256",
            iterations,
            keyLength: 256
          }
        }
      };
    }
  });
}

export function createBrowserInjectedRawKeyProvider(input: {
  key: Uint8Array;
  unsafeForProduction?: boolean;
}): PhilDeviceIdentityBrowserRegistryKeyProvider {
  const rawKey = new Uint8Array(input.key);
  return Object.freeze({
    providerKind: "browser-injected-raw-aes256-device-registry-key-v1",
    unsafeForProduction: input.unsafeForProduction ?? false,
    rawKeyExportable: false,
    async resolveKey(
      keyInput: PhilDeviceIdentityBrowserKeyProviderInput
    ): Promise<PhilDeviceIdentityBrowserResolvedKey> {
      return {
        key: await keyInput.crypto.importAesGcmKey(rawKey),
        metadata: {
          providerKind: this.providerKind,
          unsafeForProduction: this.unsafeForProduction
        }
      };
    }
  });
}

export function createFutureBrowserPlatformKeychainProviderScaffold(): PhilDeviceIdentityBrowserRegistryKeyProvider {
  return Object.freeze({
    providerKind: "future-browser-platform-keychain-device-registry-key-scaffold-v1",
    unsafeForProduction: false,
    rawKeyExportable: false,
    async resolveKey(): Promise<PhilDeviceIdentityBrowserResolvedKey> {
      throw new PhilDeviceIdentityBrowserStorageError(
        "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_KEY_PROVIDER",
        "Browser platform keychain registry key provider is a future scaffold"
      );
    }
  });
}

export function createFutureBrowserSecureEnclaveKeyProviderScaffold(): PhilDeviceIdentityBrowserRegistryKeyProvider {
  return Object.freeze({
    providerKind: "future-browser-secure-enclave-device-registry-key-scaffold-v1",
    unsafeForProduction: false,
    rawKeyExportable: false,
    async resolveKey(): Promise<PhilDeviceIdentityBrowserResolvedKey> {
      throw new PhilDeviceIdentityBrowserStorageError(
        "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_KEY_PROVIDER",
        "Browser Secure Enclave registry key provider is a future scaffold"
      );
    }
  });
}

export function createFutureMobileSecureStorageKeyProviderScaffold(): PhilDeviceIdentityBrowserRegistryKeyProvider {
  return Object.freeze({
    providerKind: "future-mobile-secure-storage-device-registry-key-scaffold-v1",
    unsafeForProduction: false,
    rawKeyExportable: false,
    async resolveKey(): Promise<PhilDeviceIdentityBrowserResolvedKey> {
      throw new PhilDeviceIdentityBrowserStorageError(
        "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_KEY_PROVIDER",
        "Mobile secure storage registry key provider is a future scaffold"
      );
    }
  });
}

function requestPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function openDatabase(input: {
  indexedDb: PhilDeviceIdentityIndexedDbLike;
  dbName: string;
  version: number;
}): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = input.indexedDb.open(input.dbName, input.version);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE)) {
        db.createObjectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE, {
          keyPath: "ownerCommitment"
        });
      }
      if (!db.objectStoreNames.contains(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE)) {
        db.createObjectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE, {
          keyPath: "ownerCommitment"
        });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
  });
}

export function createIndexedDbDeviceIdentityRegistryStorage(
  options: PhilDeviceIdentityIndexedDbStorageOptions = {}
): PhilDeviceIdentityIndexedDbRegistryStorage {
  const indexedDb = options.indexedDb
    ?? ((globalThis as { indexedDB?: PhilDeviceIdentityIndexedDbLike }).indexedDB);
  if (!indexedDb) {
    throw new PhilDeviceIdentityBrowserStorageError(
      "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_RUNTIME",
      "IndexedDB is required for browser Device Identity registry storage"
    );
  }
  const dbName = options.dbName ?? PHIL_DEVICE_IDENTITY_INDEXEDDB_DATABASE;
  const version = options.version ?? 1;
  const resolvedIndexedDb = indexedDb;

  async function db(): Promise<IDBDatabase> {
    return openDatabase({ indexedDb: resolvedIndexedDb, dbName, version });
  }

  return Object.freeze({
    async saveEncryptedBlob(input: {
      ownerCommitment: Hex;
      encryptedBlob: string;
      updatedAt: string;
    }): Promise<void> {
      const database = await db();
      const transaction = database.transaction([
        PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE,
        PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE
      ], "readwrite");
      await requestPromise(transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE).put({
        ownerCommitment: input.ownerCommitment,
        encryptedBlob: input.encryptedBlob,
        updatedAt: input.updatedAt
      } satisfies PhilDeviceIdentityIndexedDbRegistryRecord));
      await requestPromise(transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE).put({
        ownerCommitment: input.ownerCommitment,
        format: PHIL_DEVICE_IDENTITY_ENCRYPTED_STORAGE_FORMAT,
        version: PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
        encrypted: true,
        updatedAt: input.updatedAt
      } satisfies PhilDeviceIdentityIndexedDbRegistryMetadata));
    },
    async loadEncryptedBlob(ownerCommitment: Hex): Promise<string | null> {
      const database = await db();
      const transaction = database.transaction(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE, "readonly");
      const record = await requestPromise<PhilDeviceIdentityIndexedDbRegistryRecord | undefined>(
        transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE).get(ownerCommitment)
      );
      return record?.encryptedBlob ?? null;
    },
    async deleteRegistry(ownerCommitment: Hex): Promise<void> {
      const database = await db();
      const transaction = database.transaction([
        PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE,
        PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE
      ], "readwrite");
      await requestPromise(transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_REGISTRIES_STORE).delete(ownerCommitment));
      await requestPromise(transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE).delete(ownerCommitment));
    },
    async listRegistryMetadata(): Promise<readonly PhilDeviceIdentityIndexedDbRegistryMetadata[]> {
      const database = await db();
      const transaction = database.transaction(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE, "readonly");
      return Object.freeze(await requestPromise<PhilDeviceIdentityIndexedDbRegistryMetadata[]>(
        transaction.objectStore(PHIL_DEVICE_IDENTITY_INDEXEDDB_METADATA_STORE).getAll()
      ));
    }
  });
}

function snapshotFromPlaintext(
  plaintext: PhilDeviceIdentityBrowserRegistryPlaintextV1,
  identity: PhilIdentityPublic
): PhilCredentialRegistrySnapshot {
  return createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: plaintext.credentials,
    recoveryPolicy: plaintext.recoveryState,
    auditTrail: plaintext.auditEvents
  }).getSnapshot();
}

export function createBrowserEncryptedDeviceIdentityRegistryStore(
  options: PhilDeviceIdentityBrowserRegistryStoreOptions
) {
  const now = options.now ?? (() => new Date().toISOString());
  const crypto = options.crypto ?? createBrowserWebCryptoAdapter();
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

  async function loadPlaintext(
    expectedIdentity: PhilIdentityPublic
  ): Promise<PhilDeviceIdentityBrowserRegistryPlaintextV1> {
    const encryptedBlob = await options.storage.loadEncryptedBlob(expectedIdentity.ownerCommitment);
    if (encryptedBlob === null) {
      throw new PhilDeviceIdentityBrowserStorageError(
        "PHIL_DEVICE_IDENTITY_INDEXEDDB_MISSING_REGISTRY",
        "IndexedDB Device Identity registry is missing"
      );
    }
    return decryptBlob({
      serialized: encryptedBlob,
      expectedIdentity,
      keyProvider: options.keyProvider,
      crypto
    });
  }

  return Object.freeze({
    async createNewRegistry(
      philIdentity: PhilIdentityPublic
    ): Promise<PhilCredentialRegistrySnapshot> {
      return snapshotWithStorageEvent({
        snapshot: createPhilCredentialRegistry({ philIdentity }).getSnapshot(),
        eventType: "registry-created",
        occurredAt: now(),
        details: {
          storageRuntime: "browser-indexeddb",
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
          encryption: "aes-256-gcm-webcrypto",
          keyProviderKind: options.keyProvider.providerKind,
          keyProviderUnsafeForProduction: options.keyProvider.unsafeForProduction
        }
      });
      const encryptedBlob = await encryptSnapshot({
        snapshot: saved,
        keyProvider: options.keyProvider,
        crypto,
        createdAt: saved.auditTrail[0]?.occurredAt ?? now(),
        updatedAt: now()
      });
      await options.storage.saveEncryptedBlob({
        ownerCommitment: saved.philIdentity.ownerCommitment,
        encryptedBlob,
        updatedAt: now()
      });
      return saved;
    },
    async loadRegistry(
      expectedIdentity: PhilIdentityPublic
    ): Promise<PhilCredentialRegistrySnapshot> {
      try {
        const plaintext = await loadPlaintext(expectedIdentity);
        return snapshotWithStorageEvent({
          snapshot: snapshotFromPlaintext(plaintext, expectedIdentity),
          eventType: "registry-loaded",
          occurredAt: now(),
          details: {
            storageRuntime: "browser-indexeddb",
            storageVersion: plaintext.version
          }
        });
      } catch (error) {
        const code = error instanceof PhilDeviceIdentityBrowserStorageError
          ? error.code
          : "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNKNOWN_LOAD_ERROR";
        if (
          error instanceof PhilDeviceIdentityBrowserStorageError
          && error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_TAMPER_DETECTED"
        ) {
          recordVolatileStorageEvent({
            expectedIdentity,
            eventType: "registry-tamper-detected",
            details: { code }
          });
        } else {
          recordVolatileStorageEvent({
            expectedIdentity,
            eventType: "registry-load-failed",
            details: { code }
          });
        }
        throw error;
      }
    },
    async deleteRegistry(ownerCommitment: Hex): Promise<void> {
      await options.storage.deleteRegistry(ownerCommitment);
    },
    async listRegistryMetadata(): Promise<readonly PhilDeviceIdentityIndexedDbRegistryMetadata[]> {
      return options.storage.listRegistryMetadata();
    },
    async exportEncryptedBackupBlob(
      snapshot: PhilCredentialRegistrySnapshot
    ): Promise<string> {
      const exported = snapshotWithStorageEvent({
        snapshot,
        eventType: "registry-exported",
        occurredAt: now(),
        details: {
          encrypted: true,
          storageRuntime: "browser-indexeddb"
        }
      });
      return encryptSnapshot({
        snapshot: exported,
        keyProvider: options.keyProvider,
        crypto,
        createdAt: exported.auditTrail[0]?.occurredAt ?? now(),
        updatedAt: now()
      });
    },
    async importEncryptedBackupBlob(
      input: PhilDeviceIdentityBrowserImportOptions
    ): Promise<PhilCredentialRegistrySnapshot> {
      if (
        input.replaceExisting !== true
        && await options.storage.loadEncryptedBlob(input.expectedIdentity.ownerCommitment) !== null
      ) {
        throw new PhilDeviceIdentityBrowserStorageError(
          "PHIL_DEVICE_IDENTITY_INDEXEDDB_REPLACE_REQUIRED",
          "IndexedDB registry import would overwrite an existing registry; pass replaceExisting: true"
        );
      }
      const plaintext = await decryptBlob({
        serialized: input.encryptedBackupBlob,
        expectedIdentity: input.expectedIdentity,
        keyProvider: options.keyProvider,
        crypto
      });
      const imported = snapshotWithStorageEvent({
        snapshot: snapshotFromPlaintext(plaintext, input.expectedIdentity),
        eventType: "registry-imported",
        occurredAt: now(),
        details: {
          importedAuditEventCount: plaintext.auditEvents.length,
          storageRuntime: "browser-indexeddb"
        }
      });
      await options.storage.saveEncryptedBlob({
        ownerCommitment: input.expectedIdentity.ownerCommitment,
        encryptedBlob: await encryptSnapshot({
          snapshot: imported,
          keyProvider: options.keyProvider,
          crypto,
          createdAt: plaintext.createdAt,
          updatedAt: now()
        }),
        updatedAt: now()
      });
      return imported;
    },
    getVolatileStorageAuditEvents(): readonly PhilCredentialAuditEvent[] {
      return Object.freeze([...volatileStorageAuditEvents]);
    }
  });
}
