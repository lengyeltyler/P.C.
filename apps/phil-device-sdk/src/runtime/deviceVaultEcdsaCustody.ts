import {
  createCipheriv,
  createDecipheriv,
  randomBytes
} from "node:crypto";
import {
  Wallet,
  computeAddress,
  getAddress,
  getBytes,
  hexlify,
  isHexString,
  keccak256,
  toUtf8Bytes,
  verifyMessage
} from "ethers";

import type {
  PhilDeviceIdentityKeyDerivationMetadata,
  PhilDeviceIdentityRegistryKeyProvider,
  PhilDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { UnlockedDeviceVaultHandleMetadata } from "./deviceVaultUnlock.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type {
  PhilCore4337SigningRequest,
  PhilCore4337SigningResult,
  PhilCore4337ValidatorSigner,
  PhilCore4337ValidatorSignerDescriptor
} from "./philcore4337UserOperationSigning.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import type { RuntimeResult } from "./types.ts";

export const DEVICE_VAULT_ECDSA_VALIDATOR_COLLECTION_FORMAT =
  "phil-device-vault-ecdsa-validator-collection" as const;
export const DEVICE_VAULT_ECDSA_VALIDATOR_RECORD_FORMAT =
  "phil-device-vault-ecdsa-validator-record-encrypted" as const;
export const DEVICE_VAULT_ECDSA_VALIDATOR_VERSION = 1 as const;

export type DeviceVaultEcdsaValidatorStatus =
  | "active"
  | "pending_rotation"
  | "rotated"
  | "revoked"
  | "expired";

export type DeviceVaultEcdsaValidatorPurpose =
  | "erc4337_owner_validator_base_sepolia_beta"
  | "erc4337_owner_validator_local_alpha"
  | "erc4337_recovery_authority_base_sepolia_beta"
  | "erc4337_recovery_authority_local_alpha"
  | "unsupported";

export type DeviceVaultEcdsaSigningPurpose =
  | DeviceVaultEcdsaValidatorPurpose
  | "ethereum_sepolia_local_proof_gated_v1_signing";

export type DeviceVaultEcdsaValidatorLifecycleState =
  | "generated"
  | "stored_encrypted"
  | "resolved"
  | "signing_session_active"
  | "signing_session_used"
  | "signing_session_invalidated"
  | "pending_rotation"
  | "revoked";

export interface DeviceVaultEcdsaValidatorKeyReference {
  readonly keyReferenceId: string;
  readonly recordId: string;
  readonly ownerCommitment: Hex;
  readonly ownerAddress: string;
  readonly purpose: DeviceVaultEcdsaValidatorPurpose;
  readonly accountAddress?: string;
  readonly chainId?: number;
  readonly encryptedEnvelopeHash: Hex;
  readonly privateKeyExportable: false;
  readonly privateKeyReturned: false;
  readonly derivedFromPhilSecret: false;
  readonly derivedFromIdentityRoot: false;
  readonly storedEncrypted: true;
}

export interface DeviceVaultEcdsaValidatorMetadata {
  readonly recordId: string;
  readonly keyReferenceId: string;
  readonly ownerCommitment: Hex;
  readonly ownerAddress: string;
  readonly purpose: DeviceVaultEcdsaValidatorPurpose;
  readonly status: DeviceVaultEcdsaValidatorStatus;
  readonly lifecycleState: DeviceVaultEcdsaValidatorLifecycleState;
  readonly accountAddress?: string;
  readonly chainId?: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt?: string;
  readonly rotatedFromRecordId?: string;
  readonly revokedAt?: string;
  readonly keyProviderKind: string;
  readonly keyProviderUnsafeForProduction: boolean;
  readonly publicKeyAlgorithm: "secp256k1";
  readonly privateKeyExportable: false;
  readonly privateKeyReturned: false;
  readonly derivedFromPhilSecret: false;
  readonly derivedFromIdentityRoot: false;
  readonly storedEncrypted: true;
}

export interface DeviceVaultEcdsaValidatorRecord {
  readonly format: typeof DEVICE_VAULT_ECDSA_VALIDATOR_RECORD_FORMAT;
  readonly version: typeof DEVICE_VAULT_ECDSA_VALIDATOR_VERSION;
  readonly metadata: DeviceVaultEcdsaValidatorMetadata;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly encryption: {
    readonly algorithm: "aes-256-gcm";
    readonly iv: string;
    readonly tag: string;
    readonly kdf: PhilDeviceIdentityKeyDerivationMetadata;
  };
  readonly associatedData: DeviceVaultEcdsaValidatorAssociatedData;
  readonly ciphertext: string;
}

export interface DeviceVaultEcdsaValidatorAssociatedData {
  readonly format: typeof DEVICE_VAULT_ECDSA_VALIDATOR_RECORD_FORMAT;
  readonly version: typeof DEVICE_VAULT_ECDSA_VALIDATOR_VERSION;
  readonly recordId: string;
  readonly keyReferenceId: string;
  readonly ownerCommitment: Hex;
  readonly ownerAddress: string;
  readonly purpose: DeviceVaultEcdsaSigningPurpose;
  readonly status: DeviceVaultEcdsaValidatorStatus;
  readonly accountAddress?: string;
  readonly chainId?: number;
}

interface DeviceVaultEcdsaValidatorPrivatePayload {
  readonly format: "phil-device-vault-ecdsa-validator-private-payload";
  readonly version: 1;
  readonly privateKey: Hex;
  readonly ownerAddress: string;
  readonly publicKeyAlgorithm: "secp256k1";
  readonly generatedAt: string;
}

interface DeviceVaultEcdsaValidatorCollection {
  readonly format: typeof DEVICE_VAULT_ECDSA_VALIDATOR_COLLECTION_FORMAT;
  readonly version: typeof DEVICE_VAULT_ECDSA_VALIDATOR_VERSION;
  readonly updatedAt: string;
  readonly records: readonly DeviceVaultEcdsaValidatorRecord[];
}

export type DeviceVaultEcdsaKeyGenerationStatus =
  | "validator_generated"
  | "validator_generation_rejected";

export type DeviceVaultEcdsaKeyGenerationOutcome =
  | "validator_generated"
  | "vault_ineligible"
  | "session_ineligible"
  | "metadata_rejected"
  | "storage_failed"
  | "malformed";

export interface DeviceVaultEcdsaKeyGenerationRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly ownerCommitment: Hex;
  readonly purpose: DeviceVaultEcdsaValidatorPurpose;
  readonly accountAddress?: string;
  readonly chainId?: number;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface DeviceVaultEcdsaKeyGenerationResultValue {
  readonly status: "validator_generated";
  readonly outcome: "validator_generated";
  readonly record: DeviceVaultEcdsaValidatorRecord;
  readonly metadata: DeviceVaultEcdsaValidatorMetadata;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly ownerAddress: string;
  readonly generatedAt: string;
  readonly auditCorrelationId: string;
  readonly privateKeyReturned: false;
  readonly privateKeyExportable: false;
  readonly storedEncrypted: true;
  readonly derivedFromPhilSecret: false;
  readonly derivedFromIdentityRoot: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type DeviceVaultEcdsaKeyGenerationResult =
  RuntimeResult<DeviceVaultEcdsaKeyGenerationResultValue>;

export interface DeviceVaultEcdsaValidatorResolutionRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly expectedOwnerCommitment: Hex;
  readonly expectedOwnerAddress?: string;
  readonly expectedAccountAddress?: string;
  readonly expectedChainId?: number;
  readonly expectedPurpose: DeviceVaultEcdsaValidatorPurpose;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
}

export interface DeviceVaultEcdsaValidatorResolution {
  readonly status: "validator_resolved";
  readonly record: DeviceVaultEcdsaValidatorRecord;
  readonly metadata: DeviceVaultEcdsaValidatorMetadata;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly ownerAddress: string;
  readonly resolvedAt: string;
  readonly privateKeyReturned: false;
  readonly privateKeyExportable: false;
}

export type DeviceVaultEcdsaValidatorResolutionResult =
  RuntimeResult<DeviceVaultEcdsaValidatorResolution>;

export interface DeviceVaultEcdsaSigningSessionBinding {
  readonly keyReferenceId: string;
  readonly recordId: string;
  readonly ownerCommitment: Hex;
  readonly ownerAddress: string;
  readonly sessionId: string;
  readonly vaultHandleId: string;
  readonly smartAccountAddress: string;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly userOperationHash: Hex;
  readonly signingDigest: Hex;
  readonly presentationDigest: Hex;
  readonly callDataHash: Hex;
  readonly purpose: DeviceVaultEcdsaSigningPurpose;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
}

export interface DeviceVaultEcdsaSigningSessionSnapshot {
  readonly signingSessionId: string;
  readonly binding: DeviceVaultEcdsaSigningSessionBinding;
  readonly status: "active" | "used" | "invalidated" | "expired";
  readonly processLocal: true;
  readonly oneTime: true;
  readonly serializable: false;
  readonly privateKeyReturned: false;
  readonly arbitraryMessageSigning: false;
  readonly arbitraryTransactionSigning: false;
}

export interface DeviceVaultEcdsaSigningSession {
  readonly signingSessionId: string;
  inspect(): DeviceVaultEcdsaSigningSessionSnapshot;
  signUserOperationHash(request: PhilCore4337SigningRequest): Promise<PhilCore4337SigningResult>;
  invalidate(reason?: string): void;
  toJSON(): never;
}

export interface DeviceVaultEcdsaSigningSessionRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly ownerCommitment: Hex;
  readonly smartAccountAddress: string;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly userOperationHash: Hex;
  /** Purpose-bound digest after Runtime has validated the canonical UserOperation hash. */
  readonly signingDigest?: Hex;
  readonly presentationDigest: Hex;
  readonly callDataHash: Hex;
  readonly purpose: DeviceVaultEcdsaValidatorPurpose;
  readonly issuedAt?: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export interface DeviceVaultEcdsaProtectedSigningSessionRequest {
  readonly requestId: string;
  readonly identityUnlocked: boolean;
  readonly activeSession: boolean;
  readonly recentUserPresence: boolean;
  readonly currentApproval: boolean;
  readonly keyReferenceId: string;
  readonly recordId: string;
  readonly ownerCommitment: Hex;
  readonly ownerAddress: string;
  readonly sessionId: string;
  readonly vaultHandleId: string;
  readonly smartAccountAddress: string;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly userOperationHash: Hex;
  readonly signingDigest: Hex;
  readonly presentationDigest: Hex;
  readonly callDataHash: Hex;
  readonly signingPurpose: DeviceVaultEcdsaSigningPurpose;
  readonly issuedAt?: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly checkAuthorityAvailable: () => boolean | Promise<boolean>;
  /**
   * Main-process Device Vault implementation. The callback receives only the
   * exact, purpose-bound digest and must never return private key material.
   */
  readonly signBoundDigest: (digest: Hex) => Promise<Hex>;
}

export type DeviceVaultEcdsaSigningSessionResult =
  RuntimeResult<{
    readonly status: "signing_session_created";
    readonly signingSession: DeviceVaultEcdsaSigningSession;
    readonly snapshot: DeviceVaultEcdsaSigningSessionSnapshot;
    readonly auditEventDraft?: AuditEventDraft;
  }>;

export interface DeviceVaultEcdsaRotationResult {
  readonly status: "rotation_blocked" | "rotation_marked_pending";
  readonly oldRecord?: DeviceVaultEcdsaValidatorRecord;
  readonly reason: string;
  readonly onChainOwnerChanged: false;
  readonly futureAccountOwnerRotationRequired: true;
}

export interface DeviceVaultEcdsaRevocationResult {
  readonly status: "revoked" | "not_found" | "rejected";
  readonly record?: DeviceVaultEcdsaValidatorRecord;
  readonly reason?: string;
  readonly onChainOwnerChanged: false;
}

export interface DeviceVaultEcdsaAccountBindingResult {
  readonly status: "account_reference_bound" | "not_found" | "rejected";
  readonly record?: DeviceVaultEcdsaValidatorRecord;
  readonly reason?: string;
  readonly onChainOwnerChanged: false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (isRecord(value)) {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as TValue;
  }
  return value;
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

function normalizeHex(value: string, bytes?: number): Hex {
  if (!isHexString(value, bytes)) throw new Error("invalid hex");
  return hexlify(value).toLowerCase() as Hex;
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function normalizeKey(key: Uint8Array): Buffer {
  const normalized = Buffer.from(key);
  if (normalized.byteLength !== 32) throw new Error("validator custody key provider must resolve a 32-byte key");
  return normalized;
}

function nowIso(): string {
  return new Date().toISOString();
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
}

function collectionNow(input?: { readonly now?: string }): string {
  return input?.now ?? nowIso();
}

async function readCollection(
  backend: PhilDeviceIdentityRegistryStorageBackend
): Promise<DeviceVaultEcdsaValidatorCollection> {
  const serialized = await backend.read();
  if (serialized === null) {
    return freezeRecord({
      format: DEVICE_VAULT_ECDSA_VALIDATOR_COLLECTION_FORMAT,
      version: DEVICE_VAULT_ECDSA_VALIDATOR_VERSION,
      updatedAt: nowIso(),
      records: Object.freeze([])
    });
  }
  const parsed = JSON.parse(serialized) as Partial<DeviceVaultEcdsaValidatorCollection>;
  if (parsed.format !== DEVICE_VAULT_ECDSA_VALIDATOR_COLLECTION_FORMAT) {
    throw new Error("invalid validator collection format");
  }
  if (parsed.version !== DEVICE_VAULT_ECDSA_VALIDATOR_VERSION) {
    throw new Error("unsupported validator collection version");
  }
  if (!Array.isArray(parsed.records)) throw new Error("invalid validator collection records");
  return freezeRecord(parsed as DeviceVaultEcdsaValidatorCollection);
}

async function writeCollection(
  backend: PhilDeviceIdentityRegistryStorageBackend,
  records: readonly DeviceVaultEcdsaValidatorRecord[],
  updatedAt = nowIso()
): Promise<void> {
  await backend.write(stableJson({
    format: DEVICE_VAULT_ECDSA_VALIDATOR_COLLECTION_FORMAT,
    version: DEVICE_VAULT_ECDSA_VALIDATOR_VERSION,
    updatedAt,
    records
  }));
}

function validateUnlockedVaultContext(input: {
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly ownerCommitment: Hex;
}): readonly string[] {
  const errors: string[] = [];
  if (input.lifecycleSnapshot.state !== "unlocked") {
    errors.push(`session state ${input.lifecycleSnapshot.state} is not eligible for validator custody signing`);
  }
  if (input.lifecycleSnapshot.sessionId !== input.unlockedVaultHandle.sessionId) {
    errors.push("session does not match unlocked vault handle");
  }
  if (input.unlockedVaultHandle.ownerCommitment.toLowerCase() !== input.ownerCommitment.toLowerCase()) {
    errors.push("owner commitment does not match unlocked vault handle");
  }
  if (expired(input.unlockedVaultHandle.expiresAt)) errors.push("unlocked vault handle expired");
  return Object.freeze(errors);
}

function validateMetadata(metadata: Readonly<Record<string, unknown>> | undefined): readonly string[] {
  if (!metadata) return Object.freeze([]);
  return Object.freeze(validateNoSensitiveMetadataKeys(metadata).errors);
}

function runtimeError(code: string, errors: readonly string[]) {
  return {
    code,
    category: "vault_unavailable" as const,
    message: "Device Vault ECDSA validator custody request was rejected.",
    recoverable: true,
    details: { errors }
  };
}

function createCustodyAuditDraft(input: {
  readonly outcome: string;
  readonly summary: string;
  readonly auditCorrelationId?: string;
  readonly details?: Readonly<Record<string, unknown>>;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "runtime",
    outcome: input.outcome.includes("generated")
      || input.outcome.includes("created")
      || input.outcome.includes("signed")
      || input.outcome.includes("revoked")
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestDeviceVaultEcdsaValidatorCustody",
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId,
    redactedDetails: {
      ...(input.details ? redactRuntimeMetadata(input.details).value : {}),
      privateKeyReturned: false,
      rawPrivateKeyIncluded: false,
      philSecretExposed: false,
      vaultKeyExposed: false
    }
  });
}

function generatePrivateKey(): Hex {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const candidate = hexlify(randomBytes(32)) as Hex;
    try {
      computeAddress(candidate);
      return candidate;
    } catch {
      // Try again; invalid secp256k1 scalars are vanishingly unlikely.
    }
  }
  throw new Error("failed to generate a valid secp256k1 private key");
}

function encryptedEnvelopeHash(record: Omit<DeviceVaultEcdsaValidatorRecord, "metadata" | "keyReference">): Hex {
  return keccak256(toUtf8Bytes(stableJson({
    format: record.format,
    version: record.version,
    encryption: record.encryption,
    associatedData: record.associatedData,
    ciphertext: record.ciphertext
  }))) as Hex;
}

function encryptPrivatePayload(input: {
  readonly privateKey: Hex;
  readonly metadata: Omit<DeviceVaultEcdsaValidatorMetadata, "keyProviderKind" | "keyProviderUnsafeForProduction">;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
}): DeviceVaultEcdsaValidatorRecord {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = input.keyProvider.resolveKey({
    ownerCommitment: input.metadata.ownerCommitment,
    salt,
    purpose: "encrypt"
  });
  const metadata: DeviceVaultEcdsaValidatorMetadata = freezeRecord({
    ...input.metadata,
    keyProviderKind: input.keyProvider.providerKind,
    keyProviderUnsafeForProduction: input.keyProvider.unsafeForProduction
  });
  const associatedData: DeviceVaultEcdsaValidatorAssociatedData = freezeRecord({
    format: DEVICE_VAULT_ECDSA_VALIDATOR_RECORD_FORMAT,
    version: DEVICE_VAULT_ECDSA_VALIDATOR_VERSION,
    recordId: metadata.recordId,
    keyReferenceId: metadata.keyReferenceId,
    ownerCommitment: metadata.ownerCommitment,
    ownerAddress: metadata.ownerAddress,
    purpose: metadata.purpose,
    status: metadata.status,
    accountAddress: metadata.accountAddress,
    chainId: metadata.chainId
  });
  const payload: DeviceVaultEcdsaValidatorPrivatePayload = {
    format: "phil-device-vault-ecdsa-validator-private-payload",
    version: 1,
    privateKey: input.privateKey,
    ownerAddress: metadata.ownerAddress,
    publicKeyAlgorithm: "secp256k1",
    generatedAt: metadata.createdAt
  };
  const cipher = createCipheriv("aes-256-gcm", normalizeKey(key.key), iv);
  cipher.setAAD(Buffer.from(stableJson(associatedData), "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(stableJson(payload), "utf8")),
    cipher.final()
  ]);
  const recordBase = {
    format: DEVICE_VAULT_ECDSA_VALIDATOR_RECORD_FORMAT,
    version: DEVICE_VAULT_ECDSA_VALIDATOR_VERSION,
    encryption: {
      algorithm: "aes-256-gcm" as const,
      iv: base64Url(iv),
      tag: base64Url(cipher.getAuthTag()),
      kdf: {
        ...key.metadata,
        salt: base64Url(salt)
      }
    },
    associatedData,
    ciphertext: base64Url(ciphertext)
  };
  const hash = encryptedEnvelopeHash(recordBase);
  const keyReference: DeviceVaultEcdsaValidatorKeyReference = freezeRecord({
    keyReferenceId: metadata.keyReferenceId,
    recordId: metadata.recordId,
    ownerCommitment: metadata.ownerCommitment,
    ownerAddress: metadata.ownerAddress,
    purpose: metadata.purpose,
    accountAddress: metadata.accountAddress,
    chainId: metadata.chainId,
    encryptedEnvelopeHash: hash,
    privateKeyExportable: false,
    privateKeyReturned: false,
    derivedFromPhilSecret: false,
    derivedFromIdentityRoot: false,
    storedEncrypted: true
  });
  return freezeRecord({
    ...recordBase,
    metadata,
    keyReference
  });
}

function decryptPrivatePayload(input: {
  readonly record: DeviceVaultEcdsaValidatorRecord;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
}): DeviceVaultEcdsaValidatorPrivatePayload {
  const salt = input.record.encryption.kdf.salt === undefined
    ? undefined
    : base64UrlBytes(input.record.encryption.kdf.salt);
  const key = input.keyProvider.resolveKey({
    ownerCommitment: input.record.metadata.ownerCommitment,
    salt,
    purpose: "decrypt"
  });
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      normalizeKey(key.key),
      Buffer.from(base64UrlBytes(input.record.encryption.iv))
    );
    decipher.setAAD(Buffer.from(stableJson(input.record.associatedData), "utf8"));
    decipher.setAuthTag(Buffer.from(base64UrlBytes(input.record.encryption.tag)));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(base64UrlBytes(input.record.ciphertext))),
      decipher.final()
    ]);
    const parsed = JSON.parse(plaintext.toString("utf8")) as Partial<DeviceVaultEcdsaValidatorPrivatePayload>;
    if (
      parsed.format !== "phil-device-vault-ecdsa-validator-private-payload"
      || parsed.version !== 1
      || typeof parsed.privateKey !== "string"
      || normalizeAddress(parsed.ownerAddress ?? "") !== normalizeAddress(input.record.metadata.ownerAddress)
    ) {
      throw new Error("invalid validator private payload");
    }
    return parsed as DeviceVaultEcdsaValidatorPrivatePayload;
  } catch {
    throw new Error("validator encrypted record authentication failed");
  }
}

function validateRecordBinding(
  record: DeviceVaultEcdsaValidatorRecord,
  request: DeviceVaultEcdsaValidatorResolutionRequest
): readonly string[] {
  const errors: string[] = [];
  if (record.metadata.status !== "active") errors.push(`validator status ${record.metadata.status} is not active`);
  if (record.metadata.ownerCommitment.toLowerCase() !== request.expectedOwnerCommitment.toLowerCase()) {
    errors.push("owner commitment mismatch");
  }
  if (request.expectedOwnerAddress && normalizeAddress(record.metadata.ownerAddress) !== normalizeAddress(request.expectedOwnerAddress)) {
    errors.push("owner address mismatch");
  }
  if (request.expectedAccountAddress) {
    if (!record.metadata.accountAddress) {
      errors.push("account address missing from validator record");
    } else if (normalizeAddress(record.metadata.accountAddress) !== normalizeAddress(request.expectedAccountAddress)) {
      errors.push("account address mismatch");
    }
  }
  if (request.expectedChainId !== undefined && record.metadata.chainId !== request.expectedChainId) errors.push("chain id mismatch");
  if (record.metadata.purpose !== request.expectedPurpose) errors.push("purpose mismatch");
  if (expired(record.metadata.expiresAt)) errors.push("validator record expired");
  if (record.keyReference.encryptedEnvelopeHash !== request.keyReference.encryptedEnvelopeHash) {
    errors.push("encrypted envelope hash mismatch");
  }
  return Object.freeze(errors);
}

export function validateDeviceVaultEcdsaKeyGenerationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return { valid: false, errors: ["request must be an object"] };
  for (const field of ["requestId", "ownerCommitment", "purpose"]) {
    if (typeof request[field] !== "string" || request[field].trim().length === 0) errors.push(`${field} is required`);
  }
  if (!isRecord(request.lifecycleSnapshot)) errors.push("lifecycleSnapshot is required");
  if (!isRecord(request.unlockedVaultHandle)) errors.push("unlockedVaultHandle is required");
  if (!isRecord(request.storageBackend)) errors.push("storageBackend is required");
  if (!isRecord(request.keyProvider)) errors.push("keyProvider is required");
  if (request.accountAddress !== undefined) {
    try {
      normalizeAddress(String(request.accountAddress));
    } catch {
      errors.push("accountAddress must be a valid address");
    }
  }
  if (request.chainId !== undefined) {
    const chainId = request.chainId;
    if (typeof chainId !== "number" || !Number.isInteger(chainId) || chainId <= 0) {
    errors.push("chainId must be a positive integer");
    }
  }
  errors.push(...validateMetadata(request.metadata as Readonly<Record<string, unknown>> | undefined));
  return { valid: errors.length === 0, errors };
}

export async function generateDeviceVaultEcdsaValidator(
  request: DeviceVaultEcdsaKeyGenerationRequest
): Promise<DeviceVaultEcdsaKeyGenerationResult> {
  const requestValidation = validateDeviceVaultEcdsaKeyGenerationRequest(request);
  const contextErrors = validateUnlockedVaultContext({
    lifecycleSnapshot: request.lifecycleSnapshot,
    unlockedVaultHandle: request.unlockedVaultHandle,
    ownerCommitment: request.ownerCommitment
  });
  const errors = [...requestValidation.errors, ...contextErrors];
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.ownerCommitment,
    "device-vault-ecdsa-generation"
  ]);
  if (errors.length > 0) {
    const audit = createCustodyAuditDraft({
      outcome: "validator_generation_rejected",
      summary: "Device Vault ECDSA validator generation was rejected.",
      auditCorrelationId,
      details: { errors }
    });
    request.auditDraftCollector?.addDraft(audit);
    return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_GENERATION_REJECTED", errors), {
      auditEventId: audit.eventDraftId
    });
  }

  try {
    const generatedAt = request.issuedAt ?? nowIso();
    const privateKey = generatePrivateKey();
    const ownerAddress = normalizeAddress(computeAddress(privateKey));
    const recordId = createAuditCorrelationId([
      request.requestId,
      ownerAddress,
      generatedAt,
      "device-vault-ecdsa-validator-record"
    ]);
    const keyReferenceId = createAuditCorrelationId([
      recordId,
      request.ownerCommitment,
      "device-vault-ecdsa-validator-key-reference"
    ]);
    const record = encryptPrivatePayload({
      privateKey,
      keyProvider: request.keyProvider,
      metadata: {
        recordId,
        keyReferenceId,
        ownerCommitment: normalizeHex(request.ownerCommitment, 32),
        ownerAddress,
        purpose: request.purpose,
        status: "active",
        lifecycleState: "stored_encrypted",
        accountAddress: request.accountAddress ? normalizeAddress(request.accountAddress) : undefined,
        chainId: request.chainId,
        createdAt: generatedAt,
        updatedAt: generatedAt,
        expiresAt: request.expiresAt,
        publicKeyAlgorithm: "secp256k1",
        privateKeyExportable: false,
        privateKeyReturned: false,
        derivedFromPhilSecret: false,
        derivedFromIdentityRoot: false,
        storedEncrypted: true
      }
    });
    const collection = await readCollection(request.storageBackend);
    await writeCollection(request.storageBackend, [...collection.records, record], generatedAt);
    const auditEventDraft = createCustodyAuditDraft({
      outcome: "validator_generated",
      summary: "Device Vault ECDSA validator key was generated and stored encrypted.",
      auditCorrelationId,
      details: {
        recordId,
        keyReferenceId,
        ownerCommitment: request.ownerCommitment,
        ownerAddress,
        purpose: request.purpose,
        accountAddress: record.metadata.accountAddress,
        chainId: record.metadata.chainId,
        storedEncrypted: true,
        privateKeyReturned: false,
        derivedFromPhilSecret: false
      }
    });
    const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeOk(freezeRecord({
      status: "validator_generated",
      outcome: "validator_generated",
      record,
      metadata: record.metadata,
      keyReference: record.keyReference,
      ownerAddress,
      generatedAt,
      auditCorrelationId,
      privateKeyReturned: false,
      privateKeyExportable: false,
      storedEncrypted: true,
      derivedFromPhilSecret: false,
      derivedFromIdentityRoot: false,
      auditEventDraft,
      auditDraftCollectionResult
    }), { auditEventId: auditEventDraft.eventDraftId });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown storage error";
    const audit = createCustodyAuditDraft({
      outcome: "storage_failed",
      summary: "Device Vault ECDSA validator generation failed before returning authority.",
      auditCorrelationId,
      details: { error: message }
    });
    request.auditDraftCollector?.addDraft(audit);
    return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_STORAGE_FAILED", [message]), {
      auditEventId: audit.eventDraftId
    });
  }
}

export async function resolveDeviceVaultEcdsaValidator(
  request: DeviceVaultEcdsaValidatorResolutionRequest
): Promise<DeviceVaultEcdsaValidatorResolutionResult> {
  const contextErrors = validateUnlockedVaultContext({
    lifecycleSnapshot: request.lifecycleSnapshot,
    unlockedVaultHandle: request.unlockedVaultHandle,
    ownerCommitment: request.expectedOwnerCommitment
  });
  if (contextErrors.length > 0) {
    return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_RESOLUTION_REJECTED", contextErrors));
  }
  try {
    const collection = await readCollection(request.storageBackend);
    const record = collection.records.find((candidate) =>
      candidate.metadata.recordId === request.keyReference.recordId
      && candidate.metadata.keyReferenceId === request.keyReference.keyReferenceId
    );
    if (!record) return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_RECORD_NOT_FOUND", ["validator record not found"]));
    const bindingErrors = validateRecordBinding(record, request);
    if (bindingErrors.length > 0) {
      return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_BINDING_REJECTED", bindingErrors));
    }
    decryptPrivatePayload({ record, keyProvider: request.keyProvider });
    return runtimeOk(freezeRecord({
      status: "validator_resolved",
      record,
      metadata: record.metadata,
      keyReference: record.keyReference,
      ownerAddress: record.metadata.ownerAddress,
      resolvedAt: request.requestedAt ?? nowIso(),
      privateKeyReturned: false,
      privateKeyExportable: false
    }));
  } catch (error) {
    const message = error instanceof Error ? error.message : "validator resolution failed";
    return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_RESOLUTION_FAILED", [message]));
  }
}

export async function createDeviceVaultEcdsaSigningSession(
  request: DeviceVaultEcdsaSigningSessionRequest
): Promise<DeviceVaultEcdsaSigningSessionResult> {
  const resolution = await resolveDeviceVaultEcdsaValidator({
    requestId: `${request.requestId}:resolve`,
    lifecycleSnapshot: request.lifecycleSnapshot,
    unlockedVaultHandle: request.unlockedVaultHandle,
    storageBackend: request.storageBackend,
    keyProvider: request.keyProvider,
    keyReference: request.keyReference,
    expectedOwnerCommitment: request.ownerCommitment,
    expectedAccountAddress: request.smartAccountAddress,
    expectedChainId: request.chainId,
    expectedPurpose: request.purpose,
    requestedAt: request.issuedAt,
    auditCorrelationId: request.auditCorrelationId
  });
  if (resolution.status !== "approved" || !resolution.value) {
    return runtimeDenied(resolution.error ?? runtimeError("DEVICE_VAULT_ECDSA_SESSION_REJECTED", ["validator resolution failed"]));
  }
  if (expired(request.expiresAt)) {
    return runtimeDenied(runtimeError("DEVICE_VAULT_ECDSA_SESSION_EXPIRED", ["signing session expiry is already in the past"]));
  }
  const payload = decryptPrivatePayload({
    record: resolution.value.record,
    keyProvider: request.keyProvider
  });
  const issuedAt = request.issuedAt ?? nowIso();
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.userOperationHash,
    "device-vault-ecdsa-signing-session"
  ]);
  const binding: DeviceVaultEcdsaSigningSessionBinding = freezeRecord({
    keyReferenceId: request.keyReference.keyReferenceId,
    recordId: request.keyReference.recordId,
    ownerCommitment: normalizeHex(request.ownerCommitment, 32),
    ownerAddress: resolution.value.ownerAddress,
    sessionId: request.lifecycleSnapshot.sessionId,
    vaultHandleId: request.unlockedVaultHandle.handleId,
    smartAccountAddress: normalizeAddress(request.smartAccountAddress),
    entryPointAddress: normalizeAddress(request.entryPointAddress),
    chainId: request.chainId,
    userOperationHash: normalizeHex(request.userOperationHash, 32),
    signingDigest: normalizeHex(request.signingDigest ?? request.userOperationHash, 32),
    presentationDigest: normalizeHex(request.presentationDigest, 32),
    callDataHash: normalizeHex(request.callDataHash, 32),
    purpose: request.purpose,
    issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId
  });
  let state: "active" | "used" | "invalidated" = "active";
  const signingSessionId = createAuditCorrelationId([
    request.requestId,
    binding.userOperationHash,
    binding.keyReferenceId,
    "device-vault-ecdsa-signing-session"
  ]);
  const descriptor: PhilCore4337ValidatorSignerDescriptor = freezeRecord({
    signerId: `device-vault-ecdsa:${binding.keyReferenceId}`,
    mode: "device_vault_beta_ecdsa",
    ownerAddress: binding.ownerAddress,
    keyReference: {
      keyReferenceId: binding.keyReferenceId,
      mode: "device_vault_beta_ecdsa",
      custody: "device_vault_encrypted",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available: true,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  });
  const snapshot = (): DeviceVaultEcdsaSigningSessionSnapshot => freezeRecord({
    signingSessionId,
    binding,
    status: expired(binding.expiresAt) ? "expired" : state,
    processLocal: true,
    oneTime: true,
    serializable: false,
    privateKeyReturned: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  });
  const session: DeviceVaultEcdsaSigningSession = Object.freeze({
    signingSessionId,
    inspect: snapshot,
    async signUserOperationHash(signingRequest: PhilCore4337SigningRequest): Promise<PhilCore4337SigningResult> {
      const errors: string[] = [];
      if (state !== "active") errors.push(`signing session is ${state}`);
      if (expired(binding.expiresAt)) errors.push("signing session expired");
      if (normalizeHex(signingRequest.userOperationHash, 32) !== binding.userOperationHash) errors.push("UserOperation hash mismatch");
      if (
        normalizeHex(signingRequest.signingDigest ?? signingRequest.userOperationHash, 32)
          !== binding.signingDigest
      ) errors.push("purpose-bound signing digest mismatch");
      if (normalizeHex(signingRequest.presentationDigest, 32) !== binding.presentationDigest) errors.push("presentation digest mismatch");
      if (normalizeAddress(signingRequest.expectedOwner) !== normalizeAddress(binding.ownerAddress)) errors.push("owner mismatch");
      if (normalizeAddress(signingRequest.entryPointAddress) !== normalizeAddress(binding.entryPointAddress)) errors.push("EntryPoint mismatch");
      if (normalizeAddress(signingRequest.smartAccountAddress) !== normalizeAddress(binding.smartAccountAddress)) errors.push("smart account mismatch");
      if (signingRequest.chainId !== binding.chainId) errors.push("chain id mismatch");
      if (String(signingRequest.callDataHash).toLowerCase() !== binding.callDataHash.toLowerCase()) errors.push("calldata hash mismatch");
      try {
        const collection = await readCollection(request.storageBackend);
        const currentRecord = collection.records.find((candidate) =>
          candidate.metadata.recordId === binding.recordId
          && candidate.metadata.keyReferenceId === binding.keyReferenceId
        );
        if (!currentRecord) errors.push("validator record not found");
        if (currentRecord && currentRecord.metadata.status !== "active") {
          errors.push(`validator record is ${currentRecord.metadata.status}`);
        }
      } catch {
        errors.push("validator record status unavailable");
      }
      if (errors.length > 0) {
        return freezeRecord({
          status: "rejected" as const,
          signerDescriptor: { ...descriptor, available: false },
          signedAt: nowIso(),
          errors: Object.freeze(errors)
        });
      }
      const wallet = new Wallet(payload.privateKey);
      const signature = await wallet.signMessage(getBytes(binding.signingDigest));
      state = "used";
      return freezeRecord({
        status: "signed" as const,
        signature: signature as Hex,
        signerDescriptor: descriptor,
        signedAt: nowIso()
      });
    },
    invalidate() {
      state = "invalidated";
    },
    toJSON(): never {
      throw new Error("Device Vault ECDSA signing sessions are process-local and non-serializable");
    }
  });
  const auditEventDraft = createCustodyAuditDraft({
    outcome: "signing_session_created",
    summary: "Device Vault ECDSA signing session was created for one exact UserOperation hash.",
    auditCorrelationId,
    details: {
      signingSessionId,
      keyReferenceId: binding.keyReferenceId,
      ownerAddress: binding.ownerAddress,
      smartAccountAddress: binding.smartAccountAddress,
      entryPointAddress: binding.entryPointAddress,
      chainId: binding.chainId,
      userOperationHash: binding.userOperationHash,
      expiresAt: binding.expiresAt,
      oneTime: true
    }
  });
  return runtimeOk(freezeRecord({
    status: "signing_session_created",
    signingSession: session,
    snapshot: snapshot(),
    auditEventDraft
  }));
}

export async function createDeviceVaultEcdsaProtectedSigningSession(
  request: DeviceVaultEcdsaProtectedSigningSessionRequest
): Promise<DeviceVaultEcdsaSigningSessionResult> {
  const errors: string[] = [];
  if (!request.identityUnlocked) errors.push("identity_locked");
  if (!request.activeSession) errors.push("session_inactive");
  if (!request.recentUserPresence) errors.push("fresh_user_presence_missing");
  if (!request.currentApproval) errors.push("current_signing_approval_missing");
  if (
    request.signingPurpose === "ethereum_sepolia_local_proof_gated_v1_signing"
    && request.chainId !== 11_155_111
  ) {
    errors.push("signing_purpose_chain_mismatch");
  }
  if (expired(request.expiresAt)) errors.push("signing_session_expired");
  if (!isHexString(request.userOperationHash, 32)) errors.push("user_operation_hash_invalid");
  if (!isHexString(request.signingDigest, 32)) errors.push("signing_digest_invalid");
  if (!isHexString(request.presentationDigest, 32)) errors.push("presentation_digest_invalid");
  if (!isHexString(request.callDataHash, 32)) errors.push("calldata_hash_invalid");
  try {
    if (!(await request.checkAuthorityAvailable())) errors.push("signing_authority_unavailable");
    getAddress(request.ownerAddress);
    getAddress(request.smartAccountAddress);
    getAddress(request.entryPointAddress);
  } catch {
    errors.push("signing_authority_validation_failed");
  }
  if (errors.length > 0) {
    return runtimeDenied(runtimeError(
      "DEVICE_VAULT_ECDSA_PROTECTED_SESSION_REJECTED",
      errors
    ));
  }

  const issuedAt = request.issuedAt ?? nowIso();
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.userOperationHash,
    request.signingPurpose
  ]);
  const binding: DeviceVaultEcdsaSigningSessionBinding = freezeRecord({
    keyReferenceId: request.keyReferenceId,
    recordId: request.recordId,
    ownerCommitment: normalizeHex(request.ownerCommitment, 32),
    ownerAddress: normalizeAddress(request.ownerAddress),
    sessionId: request.sessionId,
    vaultHandleId: request.vaultHandleId,
    smartAccountAddress: normalizeAddress(request.smartAccountAddress),
    entryPointAddress: normalizeAddress(request.entryPointAddress),
    chainId: request.chainId,
    userOperationHash: normalizeHex(request.userOperationHash, 32),
    signingDigest: normalizeHex(request.signingDigest, 32),
    presentationDigest: normalizeHex(request.presentationDigest, 32),
    callDataHash: normalizeHex(request.callDataHash, 32),
    purpose: request.signingPurpose,
    issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId
  });
  let state: "active" | "used" | "invalidated" = "active";
  const signingSessionId = createAuditCorrelationId([
    request.requestId,
    binding.userOperationHash,
    binding.keyReferenceId,
    binding.purpose
  ]);
  const descriptor: PhilCore4337ValidatorSignerDescriptor = freezeRecord({
    signerId: `device-vault-ecdsa:${binding.keyReferenceId}`,
    mode: "device_vault_beta_ecdsa",
    ownerAddress: binding.ownerAddress,
    keyReference: {
      keyReferenceId: binding.keyReferenceId,
      mode: "device_vault_beta_ecdsa",
      custody: "device_vault_encrypted",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available: true,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  });
  const snapshot = (): DeviceVaultEcdsaSigningSessionSnapshot => freezeRecord({
    signingSessionId,
    binding,
    status: expired(binding.expiresAt) ? "expired" : state,
    processLocal: true,
    oneTime: true,
    serializable: false,
    privateKeyReturned: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  });
  const session: DeviceVaultEcdsaSigningSession = Object.freeze({
    signingSessionId,
    inspect: snapshot,
    async signUserOperationHash(signingRequest: PhilCore4337SigningRequest) {
      const requestErrors: string[] = [];
      if (state !== "active") requestErrors.push(`signing session is ${state}`);
      if (expired(binding.expiresAt)) requestErrors.push("signing session expired");
      if (normalizeHex(signingRequest.userOperationHash, 32) !== binding.userOperationHash) {
        requestErrors.push("UserOperation hash mismatch");
      }
      if (
        normalizeHex(signingRequest.signingDigest ?? signingRequest.userOperationHash, 32)
        !== binding.signingDigest
      ) {
        requestErrors.push("purpose-bound signing digest mismatch");
      }
      if (normalizeHex(signingRequest.presentationDigest, 32) !== binding.presentationDigest) {
        requestErrors.push("presentation digest mismatch");
      }
      if (normalizeAddress(signingRequest.expectedOwner) !== binding.ownerAddress) {
        requestErrors.push("owner mismatch");
      }
      if (normalizeAddress(signingRequest.entryPointAddress) !== binding.entryPointAddress) {
        requestErrors.push("EntryPoint mismatch");
      }
      if (normalizeAddress(signingRequest.smartAccountAddress) !== binding.smartAccountAddress) {
        requestErrors.push("smart account mismatch");
      }
      if (signingRequest.chainId !== binding.chainId) requestErrors.push("chain id mismatch");
      if (normalizeHex(signingRequest.callDataHash, 32) !== binding.callDataHash) {
        requestErrors.push("calldata hash mismatch");
      }
      if (!(await request.checkAuthorityAvailable())) {
        requestErrors.push("signing authority unavailable");
      }
      if (requestErrors.length > 0) {
        return freezeRecord({
          status: "rejected" as const,
          signerDescriptor: { ...descriptor, available: false },
          signedAt: nowIso(),
          errors: Object.freeze(requestErrors)
        });
      }
      const signature = await request.signBoundDigest(binding.signingDigest);
      const recovered = verifyMessage(getBytes(binding.signingDigest), signature);
      if (normalizeAddress(recovered) !== binding.ownerAddress) {
        state = "invalidated";
        return freezeRecord({
          status: "rejected" as const,
          signerDescriptor: { ...descriptor, available: false },
          signedAt: nowIso(),
          errors: Object.freeze(["signature owner mismatch"])
        });
      }
      state = "used";
      return freezeRecord({
        status: "signed" as const,
        signature,
        signerDescriptor: descriptor,
        signedAt: nowIso()
      });
    },
    invalidate() {
      state = "invalidated";
    },
    toJSON(): never {
      throw new Error("Device Vault ECDSA signing sessions are process-local and non-serializable");
    }
  });
  const auditEventDraft = createCustodyAuditDraft({
    outcome: "signing_session_created",
    summary: "Purpose-bound Device Vault ECDSA signing session was created.",
    auditCorrelationId,
    details: {
      signingSessionId,
      keyReferenceId: binding.keyReferenceId,
      ownerAddress: binding.ownerAddress,
      smartAccountAddress: binding.smartAccountAddress,
      entryPointAddress: binding.entryPointAddress,
      chainId: binding.chainId,
      userOperationHash: binding.userOperationHash,
      signingPurpose: binding.purpose,
      expiresAt: binding.expiresAt,
      oneTime: true
    }
  });
  return runtimeOk(freezeRecord({
    status: "signing_session_created",
    signingSession: session,
    snapshot: snapshot(),
    auditEventDraft
  }));
}

export function createDeviceVaultEcdsaValidatorSigner(
  signingSession: DeviceVaultEcdsaSigningSession
): PhilCore4337ValidatorSigner {
  return Object.freeze({
    async describeSigner(): Promise<PhilCore4337ValidatorSignerDescriptor> {
      const snapshot = signingSession.inspect();
      return freezeRecord({
        signerId: `device-vault-ecdsa:${snapshot.binding.keyReferenceId}`,
        mode: "device_vault_beta_ecdsa" as const,
        ownerAddress: snapshot.binding.ownerAddress,
        keyReference: {
          keyReferenceId: snapshot.binding.keyReferenceId,
          mode: "device_vault_beta_ecdsa" as const,
          custody: "device_vault_encrypted" as const,
          privateKeyExportable: false as const,
          derivedFromPhilSecret: false as const
        },
        available: snapshot.status === "active",
        productionApproved: false,
        arbitraryMessageSigning: false as const,
        arbitraryTransactionSigning: false as const
      });
    },
    async checkAvailability() {
      return this.describeSigner();
    },
    async getOwnerAddress() {
      return signingSession.inspect().binding.ownerAddress;
    },
    async signUserOperationHash(request: PhilCore4337SigningRequest) {
      return signingSession.signUserOperationHash(request);
    },
    async invalidateSigningSession(reason?: string) {
      signingSession.invalidate(reason);
    }
  });
}

async function updateRecord(
  backend: PhilDeviceIdentityRegistryStorageBackend,
  recordId: string,
  update: (record: DeviceVaultEcdsaValidatorRecord) => DeviceVaultEcdsaValidatorRecord
): Promise<DeviceVaultEcdsaValidatorRecord | undefined> {
  const collection = await readCollection(backend);
  let updated: DeviceVaultEcdsaValidatorRecord | undefined;
  const records = collection.records.map((record) => {
    if (record.metadata.recordId !== recordId) return record;
    updated = update(record);
    return updated;
  });
  if (updated) await writeCollection(backend, records);
  return updated;
}

export async function markDeviceVaultEcdsaValidatorPendingRotation(input: {
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly requestedAt?: string;
}): Promise<DeviceVaultEcdsaRotationResult> {
  const requestedAt = input.requestedAt ?? nowIso();
  const updated = await updateRecord(input.storageBackend, input.keyReference.recordId, (record) => {
    const payload = decryptPrivatePayload({ record, keyProvider: input.keyProvider });
    return encryptPrivatePayload({
      privateKey: payload.privateKey,
      keyProvider: input.keyProvider,
      metadata: {
        ...record.metadata,
        status: "pending_rotation",
        lifecycleState: "pending_rotation",
        updatedAt: requestedAt
      }
    });
  });
  if (!updated) {
    return freezeRecord({
      status: "rotation_blocked",
      reason: "validator record not found",
      onChainOwnerChanged: false,
      futureAccountOwnerRotationRequired: true
    });
  }
  return freezeRecord({
    status: "rotation_marked_pending",
    oldRecord: updated,
    reason: "local validator record marked pending rotation; PhilCore4337Account has no owner-rotation method",
    onChainOwnerChanged: false,
    futureAccountOwnerRotationRequired: true
  });
}

export async function bindDeviceVaultEcdsaValidatorAccountReference(input: {
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly accountAddress: string;
  readonly chainId: number;
  readonly requestedAt?: string;
}): Promise<DeviceVaultEcdsaAccountBindingResult> {
  const requestedAt = input.requestedAt ?? nowIso();
  let accountAddress: string;
  try {
    accountAddress = normalizeAddress(input.accountAddress);
  } catch {
    return freezeRecord({
      status: "rejected",
      reason: "invalid account address",
      onChainOwnerChanged: false
    });
  }
  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    return freezeRecord({
      status: "rejected",
      reason: "invalid chain id",
      onChainOwnerChanged: false
    });
  }
  const updated = await updateRecord(input.storageBackend, input.keyReference.recordId, (record) => {
    if (record.metadata.status !== "active") return record;
    const payload = decryptPrivatePayload({ record, keyProvider: input.keyProvider });
    return encryptPrivatePayload({
      privateKey: payload.privateKey,
      keyProvider: input.keyProvider,
      metadata: {
        ...record.metadata,
        accountAddress,
        chainId: input.chainId,
        updatedAt: requestedAt
      }
    });
  });
  if (!updated) {
    return freezeRecord({
      status: "not_found",
      reason: "validator record not found",
      onChainOwnerChanged: false
    });
  }
  return freezeRecord({
    status: "account_reference_bound",
    record: updated,
    onChainOwnerChanged: false
  });
}

export async function revokeDeviceVaultEcdsaValidator(input: {
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly keyReference: DeviceVaultEcdsaValidatorKeyReference;
  readonly requestedAt?: string;
}): Promise<DeviceVaultEcdsaRevocationResult> {
  const requestedAt = input.requestedAt ?? nowIso();
  const updated = await updateRecord(input.storageBackend, input.keyReference.recordId, (record) => {
    const payload = decryptPrivatePayload({ record, keyProvider: input.keyProvider });
    return encryptPrivatePayload({
      privateKey: payload.privateKey,
      keyProvider: input.keyProvider,
      metadata: {
        ...record.metadata,
        status: "revoked",
        lifecycleState: "revoked",
        revokedAt: requestedAt,
        updatedAt: requestedAt
      }
    });
  });
  if (!updated) {
    return freezeRecord({
      status: "not_found",
      reason: "validator record not found",
      onChainOwnerChanged: false
    });
  }
  return freezeRecord({
    status: "revoked",
    record: updated,
    onChainOwnerChanged: false
  });
}
