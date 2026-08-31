import {
  createCipheriv,
  createDecipheriv,
  randomBytes as nodeRandomBytes
} from "node:crypto";
import {
  AbiCoder,
  concat,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_IDENTITY_SCOPE_V1_LABEL = "PHIL_IDENTITY_SCOPE_V1" as const;
export const PHIL_SCOPED_OWNER_COMMITMENT_V1_LABEL =
  "PHIL_SCOPED_OWNER_COMMITMENT_V1" as const;
export const PHIL_DATA_RECORD_AAD_V1_LABEL = "PHIL_DATA_RECORD_AAD_V1" as const;
export const PHIL_DATA_RECORD_FORMAT_V1_LABEL = "PHIL_DATA_RECORD_V1" as const;
export const PHIL_AES_256_GCM_V1_SUITE_LABEL = "phil-aes-256-gcm-v1" as const;

export const PHIL_IDENTITY_SCOPE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_IDENTITY_SCOPE_V1_LABEL)
) as Hex;
export const PHIL_SCOPED_OWNER_COMMITMENT_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_SCOPED_OWNER_COMMITMENT_V1_LABEL)
) as Hex;
export const PHIL_DATA_RECORD_AAD_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_DATA_RECORD_AAD_V1_LABEL)
) as Hex;
export const PHIL_DATA_RECORD_FORMAT_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_DATA_RECORD_FORMAT_V1_LABEL)
) as Hex;
export const PHIL_AES_256_GCM_V1_SUITE_ID = keccak256(
  toUtf8Bytes(PHIL_AES_256_GCM_V1_SUITE_LABEL)
) as Hex;

export type PhilScopeKindV1 = 1 | 2 | 3 | 4 | 5 | 255;
export type PhilUInt64String = string;

export interface PhilScopeDescriptorV1 {
  readonly scopeKind: PhilScopeKindV1;
  readonly namespaceHash: Hex;
  readonly contextHash: Hex;
}

export interface PhilScopedIdentityV1 extends PhilScopeDescriptorV1 {
  readonly scopeId: Hex;
  readonly scopeInstance: Hex;
  readonly scopeEpoch: PhilUInt64String;
  readonly scopedOwnerCommitment: Hex;
}

export interface PhilEncryptedRecordHeaderV1 {
  readonly formatVersionHash: Hex;
  readonly encryptionSuiteId: Hex;
  readonly recordId: Hex;
  readonly recordTypeHash: Hex;
  readonly recordVersion: PhilUInt64String;
  readonly dataEpoch: PhilUInt64String;
  readonly scopedOwnerCommitmentOrZero: Hex;
}

export interface PhilEncryptedDataRecordV1 {
  readonly format: "phil-encrypted-data-record-v1";
  readonly header: PhilEncryptedRecordHeaderV1;
  readonly recordAadHash: Hex;
  readonly iv: string;
  readonly authenticationTag: string;
  readonly ciphertext: string;
  readonly ciphertextHash: Hex;
}

export class PhilSecureIdentityV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilSecureIdentityV1Error";
    this.code = code;
  }
}

export function normalizePhilBytes32(value: BytesLike, label: string): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_BYTES32",
      `${label} must be bytes32`
    );
  }
  if (getBytes(normalized).byteLength !== 32) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_BYTES32",
      `${label} must be bytes32`
    );
  }
  return normalized;
}

export function requirePhilNonZeroBytes32(value: BytesLike, label: string): Hex {
  const normalized = normalizePhilBytes32(value, label);
  if (BigInt(normalized) === 0n) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_ZERO_BYTES32",
      `${label} must be non-zero`
    );
  }
  return normalized;
}

export function normalizePhilUInt64(value: string | number | bigint, label: string): PhilUInt64String {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new Error("unsafe number");
    }
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new Error("non-canonical decimal");
    }
    parsed = BigInt(value);
  } catch {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_UINT64",
      `${label} must be a canonical uint64 decimal`
    );
  }
  if (parsed < 0n || parsed > 0xffff_ffff_ffff_ffffn) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_UINT64",
      `${label} must fit uint64`
    );
  }
  return parsed.toString(10);
}

function requirePositiveUInt64(value: string | number | bigint, label: string): PhilUInt64String {
  const normalized = normalizePhilUInt64(value, label);
  if (normalized === "0") {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_ZERO_UINT64",
      `${label} must be non-zero`
    );
  }
  return normalized;
}

function requireScopeKind(value: number): PhilScopeKindV1 {
  if (value === 1 || value === 2 || value === 3 || value === 4 || value === 5 || value === 255) {
    return value;
  }
  throw new PhilSecureIdentityV1Error(
    "PHIL_SECURE_IDENTITY_SCOPE_KIND_RESERVED",
    "scopeKind is reserved in Phil V1"
  );
}

export function createPhilScopeDescriptorV1(input: {
  scopeKind: number;
  namespaceHash: BytesLike;
  contextHash: BytesLike;
}): PhilScopeDescriptorV1 {
  return Object.freeze({
    scopeKind: requireScopeKind(input.scopeKind),
    namespaceHash: requirePhilNonZeroBytes32(input.namespaceHash, "namespaceHash"),
    contextHash: requirePhilNonZeroBytes32(input.contextHash, "contextHash")
  });
}

export function derivePhilScopeIdV1(descriptor: PhilScopeDescriptorV1): Hex {
  const normalized = createPhilScopeDescriptorV1(descriptor);
  return keccak256(
    abiCoder.encode(
      ["bytes32", "uint8", "bytes32", "bytes32"],
      [
        PHIL_IDENTITY_SCOPE_V1_HASH,
        normalized.scopeKind,
        normalized.namespaceHash,
        normalized.contextHash
      ]
    )
  ) as Hex;
}

export function derivePhilScopedOwnerCommitmentV1(input: {
  identityRoot: BytesLike;
  scopeId: BytesLike;
  scopeInstance: BytesLike;
  scopeEpoch: string | number | bigint;
}): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
      [
        PHIL_SCOPED_OWNER_COMMITMENT_V1_HASH,
        requirePhilNonZeroBytes32(input.identityRoot, "identityRoot"),
        requirePhilNonZeroBytes32(input.scopeId, "scopeId"),
        requirePhilNonZeroBytes32(input.scopeInstance, "scopeInstance"),
        BigInt(requirePositiveUInt64(input.scopeEpoch, "scopeEpoch"))
      ]
    )
  ) as Hex;
}

export function createPhilScopedIdentityV1(input: {
  identityRoot: BytesLike;
  descriptor: PhilScopeDescriptorV1;
  scopeInstance?: BytesLike;
  scopeEpoch?: string | number | bigint;
}): PhilScopedIdentityV1 {
  const descriptor = createPhilScopeDescriptorV1(input.descriptor);
  const scopeId = derivePhilScopeIdV1(descriptor);
  const scopeInstance = input.scopeInstance === undefined
    ? requirePhilNonZeroBytes32(nodeRandomBytes(32), "scopeInstance")
    : requirePhilNonZeroBytes32(input.scopeInstance, "scopeInstance");
  const scopeEpoch = requirePositiveUInt64(input.scopeEpoch ?? 1, "scopeEpoch");
  return Object.freeze({
    ...descriptor,
    scopeId,
    scopeInstance,
    scopeEpoch,
    scopedOwnerCommitment: derivePhilScopedOwnerCommitmentV1({
      identityRoot: input.identityRoot,
      scopeId,
      scopeInstance,
      scopeEpoch
    })
  });
}

export function createPhilEncryptedRecordHeaderV1(
  input: Omit<PhilEncryptedRecordHeaderV1, "formatVersionHash" | "encryptionSuiteId"> & {
    formatVersionHash?: BytesLike;
    encryptionSuiteId?: BytesLike;
  }
): PhilEncryptedRecordHeaderV1 {
  const formatVersionHash = normalizePhilBytes32(
    input.formatVersionHash ?? PHIL_DATA_RECORD_FORMAT_V1_HASH,
    "formatVersionHash"
  );
  const encryptionSuiteId = normalizePhilBytes32(
    input.encryptionSuiteId ?? PHIL_AES_256_GCM_V1_SUITE_ID,
    "encryptionSuiteId"
  );
  if (formatVersionHash !== PHIL_DATA_RECORD_FORMAT_V1_HASH) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_RECORD_FORMAT_UNSUPPORTED",
      "Encrypted data record format is unsupported"
    );
  }
  if (encryptionSuiteId !== PHIL_AES_256_GCM_V1_SUITE_ID) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_ENCRYPTION_SUITE_UNSUPPORTED",
      "Encrypted data record suite is unsupported"
    );
  }
  return Object.freeze({
    formatVersionHash,
    encryptionSuiteId,
    recordId: requirePhilNonZeroBytes32(input.recordId, "recordId"),
    recordTypeHash: requirePhilNonZeroBytes32(input.recordTypeHash, "recordTypeHash"),
    recordVersion: requirePositiveUInt64(input.recordVersion, "recordVersion"),
    dataEpoch: requirePositiveUInt64(input.dataEpoch, "dataEpoch"),
    scopedOwnerCommitmentOrZero: normalizePhilBytes32(
      input.scopedOwnerCommitmentOrZero,
      "scopedOwnerCommitmentOrZero"
    )
  });
}

export function derivePhilDataRecordAadHashV1(header: PhilEncryptedRecordHeaderV1): Hex {
  const normalized = createPhilEncryptedRecordHeaderV1(header);
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint64", "bytes32"],
      [
        PHIL_DATA_RECORD_AAD_V1_HASH,
        normalized.formatVersionHash,
        normalized.encryptionSuiteId,
        normalized.recordId,
        normalized.recordTypeHash,
        BigInt(normalized.recordVersion),
        BigInt(normalized.dataEpoch),
        normalized.scopedOwnerCommitmentOrZero
      ]
    )
  ) as Hex;
}

function normalizeAesKey(value: BytesLike, label: string): Buffer {
  const key = Buffer.from(getBytes(value));
  if (key.byteLength !== 32) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_AES_KEY",
      `${label} must be 32 bytes`
    );
  }
  return key;
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_BASE64URL",
      `${label} must be unpadded base64url`
    );
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_BASE64URL",
      `${label} must be canonical base64url`
    );
  }
  return decoded;
}

export function encryptPhilDataRecordV1(input: {
  dataRootKey: BytesLike;
  header: PhilEncryptedRecordHeaderV1;
  plaintext: Uint8Array;
  iv?: Uint8Array;
}): PhilEncryptedDataRecordV1 {
  const header = createPhilEncryptedRecordHeaderV1(input.header);
  if (header.encryptionSuiteId !== PHIL_AES_256_GCM_V1_SUITE_ID) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_ENCRYPTION_SUITE_UNSUPPORTED",
      "Only phil-aes-256-gcm-v1 is implemented"
    );
  }
  const key = normalizeAesKey(input.dataRootKey, "dataRootKey");
  const iv = Buffer.from(input.iv ?? nodeRandomBytes(12));
  if (iv.byteLength !== 12) {
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_INVALID_IV",
      "AES-GCM IV must be 12 bytes"
    );
  }
  try {
    const aadHash = derivePhilDataRecordAadHashV1(header);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(getBytes(aadHash)));
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(input.plaintext)),
      cipher.final()
    ]);
    const authenticationTag = cipher.getAuthTag();
    return Object.freeze({
      format: "phil-encrypted-data-record-v1",
      header,
      recordAadHash: aadHash,
      iv: base64Url(iv),
      authenticationTag: base64Url(authenticationTag),
      ciphertext: base64Url(ciphertext),
      ciphertextHash: keccak256(concat([iv, authenticationTag, ciphertext])) as Hex
    });
  } finally {
    key.fill(0);
  }
}

export function decryptPhilDataRecordV1(input: {
  dataRootKey: BytesLike;
  record: PhilEncryptedDataRecordV1;
  expectedHeader?: PhilEncryptedRecordHeaderV1;
}): Uint8Array {
  try {
    if (input.record.format !== "phil-encrypted-data-record-v1") {
      throw new Error("format mismatch");
    }
    const header = createPhilEncryptedRecordHeaderV1(input.record.header);
    const aadHash = derivePhilDataRecordAadHashV1(header);
    if (aadHash !== normalizePhilBytes32(input.record.recordAadHash, "recordAadHash")) {
      throw new Error("AAD mismatch");
    }
    if (input.expectedHeader) {
      const expectedAadHash = derivePhilDataRecordAadHashV1(input.expectedHeader);
      if (expectedAadHash !== aadHash) {
        throw new Error("expected header mismatch");
      }
    }
    const iv = decodeBase64Url(input.record.iv, "iv");
    const tag = decodeBase64Url(input.record.authenticationTag, "authenticationTag");
    const ciphertext = decodeBase64Url(input.record.ciphertext, "ciphertext");
    if (iv.byteLength !== 12 || tag.byteLength !== 16) {
      throw new Error("invalid AES-GCM shape");
    }
    const ciphertextHash = keccak256(concat([iv, tag, ciphertext])) as Hex;
    if (ciphertextHash !== normalizePhilBytes32(input.record.ciphertextHash, "ciphertextHash")) {
      throw new Error("ciphertext hash mismatch");
    }
    const key = normalizeAesKey(input.dataRootKey, "dataRootKey");
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAAD(Buffer.from(getBytes(aadHash)));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return new Uint8Array(plaintext);
    } finally {
      key.fill(0);
    }
  } catch (error) {
    if (error instanceof PhilSecureIdentityV1Error) {
      throw error;
    }
    throw new PhilSecureIdentityV1Error(
      "PHIL_SECURE_IDENTITY_RECORD_AUTHENTICATION_FAILED",
      "Encrypted data record authentication failed"
    );
  }
}
