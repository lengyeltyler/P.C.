import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes as nodeRandomBytes
} from "node:crypto";
import {
  AbiCoder,
  concat,
  getBytes,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import {
  deriveOwnerCommitmentFromPhilSecret,
  derivePhilIdentityRoot,
  normalizePhilSecret,
  type PhilSecret
} from "./identity.ts";
import type { Hex } from "./hashes.ts";
import {
  PHIL_AES_256_GCM_V1_SUITE_ID,
  derivePhilScopeIdV1,
  derivePhilScopedOwnerCommitmentV1,
  normalizePhilBytes32,
  normalizePhilUInt64,
  requirePhilNonZeroBytes32,
  type PhilScopedIdentityV1,
  type PhilUInt64String
} from "./secureIdentityV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_LABEL =
  "PHIL_IDENTITY_CONTINUITY_PACKAGE_V1" as const;
export const PHIL_RECOVERY_PACKAGE_AAD_V1_LABEL =
  "PHIL_RECOVERY_PACKAGE_AAD_V1" as const;
export const PHIL_RECOVERY_KEY_WRAP_V1_LABEL = "PHIL_RECOVERY_KEY_WRAP_V1" as const;
export const PHIL_RECOVERY_SHARE_V1_LABEL = "PHIL_RECOVERY_SHARE_V1" as const;
export const PHIL_RECOVERY_REQUEST_V1_LABEL = "PHIL_RECOVERY_REQUEST_V1" as const;
export const PHIL_RECOVERY_COMPLETION_V1_LABEL = "PHIL_RECOVERY_COMPLETION_V1" as const;
export const PHIL_RECOVERY_SET_REPLACEMENT_V1_LABEL =
  "PHIL_RECOVERY_SET_REPLACEMENT_V1" as const;
export const PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_LABEL =
  "phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1" as const;
export const PHIL_IDENTITY_KECCAK_ABI_V1_SUITE_LABEL =
  "phil-identity-keccak256-abi-v1" as const;

export const PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_PACKAGE_AAD_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_PACKAGE_AAD_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_KEY_WRAP_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_KEY_WRAP_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_SHARE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_SHARE_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_REQUEST_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_REQUEST_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_COMPLETION_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_COMPLETION_V1_LABEL)
) as Hex;
export const PHIL_RECOVERY_SET_REPLACEMENT_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_RECOVERY_SET_REPLACEMENT_V1_LABEL)
) as Hex;
export const PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID = keccak256(
  toUtf8Bytes(PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_LABEL)
) as Hex;
export const PHIL_IDENTITY_KECCAK_ABI_V1_SUITE_ID = keccak256(
  toUtf8Bytes(PHIL_IDENTITY_KECCAK_ABI_V1_SUITE_LABEL)
) as Hex;

export type PhilRecoveryHolderIndexV1 = 1 | 2 | 3;
export type PhilRecoveryPairV1 = "1-2" | "1-3" | "2-3";
export type PhilContinuityRecordStatusV1 = "active" | "suspended" | "revoked";
export type PhilAccountBindingStatusV1 = "active" | "suspended" | "pending_reconciliation";
export type PhilRecoveryOperationV1 =
  | "identity_data_recovery"
  | "recovery_set_replacement";

export interface PhilScopeRecordV1 extends PhilScopedIdentityV1 {
  readonly status: PhilContinuityRecordStatusV1;
}

export interface PhilAccountBindingRecordV1 {
  readonly accountBindingId: Hex;
  readonly scopedOwnerCommitment: Hex;
  readonly networkIdHash: Hex;
  readonly accountBindingHash: Hex;
  readonly validatorEpoch: PhilUInt64String;
  readonly status: PhilAccountBindingStatusV1;
}

export interface PhilCredentialRecordV1 {
  readonly credentialIdHash: Hex;
  readonly credentialTypeHash: Hex;
  readonly publicKeyHash: Hex;
  readonly deviceEpoch: PhilUInt64String;
  readonly status: PhilContinuityRecordStatusV1;
}

export interface PhilPolicyStateV1 {
  readonly policyVersion: PhilUInt64String;
  readonly policyHash: Hex;
}

export interface PhilCapabilityRevocationStateV1 {
  readonly capabilityEpoch: PhilUInt64String;
  readonly revocationRoot: Hex;
  readonly revokedCapabilityIds: readonly Hex[];
}

export interface PhilAuditContinuityStateV1 {
  readonly eventCount: PhilUInt64String;
  readonly auditHeadHash: Hex;
}

export interface PhilIdentityContinuityPackageV1 {
  readonly formatVersionHash: Hex;
  readonly identitySuiteId: Hex;
  readonly philSecret: PhilSecret;
  readonly identityRoot: Hex;
  readonly rootOwnerCommitment: Hex;
  readonly dataRootKey: Hex;
  readonly dataEpoch: PhilUInt64String;
  readonly deviceEpoch: PhilUInt64String;
  readonly recoveryEpoch: PhilUInt64String;
  readonly validatorEpoch: PhilUInt64String;
  readonly capabilityEpoch: PhilUInt64String;
  readonly scopeRegistry: readonly PhilScopeRecordV1[];
  readonly accountBindings: readonly PhilAccountBindingRecordV1[];
  readonly credentialRegistry: readonly PhilCredentialRecordV1[];
  readonly policyState: PhilPolicyStateV1;
  readonly capabilityRevocationState: PhilCapabilityRevocationStateV1;
  readonly auditContinuityState: PhilAuditContinuityStateV1;
}

export interface PhilRecoveryEnvelopeV1 {
  readonly formatVersionHash: Hex;
  readonly encryptionSuiteId: Hex;
  readonly sharingSuiteId: Hex;
  readonly recoverySetId: Hex;
  readonly recoveryEpoch: PhilUInt64String;
  readonly packageCounter: PhilUInt64String;
  readonly createdAt: PhilUInt64String;
  readonly ciphertextHash: Hex;
}

export interface PhilRecoveryEncryptedPayloadV1 {
  readonly iv: string;
  readonly authenticationTag: string;
  readonly ciphertext: string;
}

export interface PhilRecoveryKeyWrapperV1 extends PhilRecoveryEncryptedPayloadV1 {
  readonly pair: PhilRecoveryPairV1;
  readonly wrapperHash: Hex;
}

export interface PhilIdentityDataRecoveryBundleV1 {
  readonly format: "phil-identity-data-recovery-bundle-v1";
  readonly envelope: PhilRecoveryEnvelopeV1;
  readonly encryptedPackage: PhilRecoveryEncryptedPayloadV1;
  readonly keyWrappers: readonly PhilRecoveryKeyWrapperV1[];
}

export interface PhilRecoveryShareContributionV1 {
  readonly pair: PhilRecoveryPairV1;
  readonly material: string;
}

export interface PhilRecoveryShareV1 {
  readonly format: "phil-recovery-share-v1";
  readonly sharingSuiteId: Hex;
  readonly recoverySetId: Hex;
  readonly recoveryEpoch: PhilUInt64String;
  readonly holderIndex: PhilRecoveryHolderIndexV1;
  readonly contributions: readonly PhilRecoveryShareContributionV1[];
  readonly checksum: Hex;
  readonly warning: "SECRET_RECOVERY_FACTOR_MATERIAL";
}

export interface PhilRecoveryAntiRollbackFloorV1 {
  readonly recoveryEpoch: PhilUInt64String;
  readonly packageCounter: PhilUInt64String;
}

export interface PhilRecoveryRequestV1 {
  readonly format: "phil-recovery-request-v1";
  readonly operation: PhilRecoveryOperationV1;
  readonly requestId: Hex;
  readonly bundleHash: Hex;
  readonly requestedAt: PhilUInt64String;
  readonly notBefore: PhilUInt64String;
  readonly expiresAt: PhilUInt64String;
  readonly destructiveApprovalDigest: Hex;
  readonly notificationTargetHashes: readonly Hex[];
  readonly notificationEvidenceHashes: readonly Hex[];
  readonly status: "pending_delay" | "cancelled" | "completed";
  readonly cancellationReasonHash?: Hex;
  readonly completionHash?: Hex;
}

export interface PhilRecoveryCompletionV1 {
  readonly request: PhilRecoveryRequestV1;
  readonly recoveredPackage: PhilIdentityContinuityPackageV1;
  readonly nextPackage: PhilIdentityContinuityPackageV1;
  readonly nextBundle: PhilIdentityDataRecoveryBundleV1;
  readonly nextShares: readonly PhilRecoveryShareV1[];
  readonly auditEventHash: Hex;
}

export interface PhilRecoverySetReplacementV1 {
  readonly request: PhilRecoveryRequestV1;
  readonly nextBundle: PhilIdentityDataRecoveryBundleV1;
  readonly nextShares: readonly PhilRecoveryShareV1[];
  readonly replacementAuditHash: Hex;
}

export class PhilIdentityDataRecoveryV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilIdentityDataRecoveryV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilIdentityDataRecoveryV1Error(code, message);
}

function recoveryOperationCode(operation: PhilRecoveryOperationV1): 1 | 2 {
  if (operation === "identity_data_recovery") return 1;
  if (operation === "recovery_set_replacement") return 2;
  return fail("PHIL_RECOVERY_OPERATION_INVALID", "recovery operation is invalid");
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, candidate) => {
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return Object.fromEntries(
        Object.entries(candidate as Record<string, unknown>).sort(([left], [right]) =>
          left < right ? -1 : left > right ? 1 : 0
        )
      );
    }
    return candidate;
  });
}

function exactKeys(value: object, expected: readonly string[], label: string) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("PHIL_RECOVERY_NON_CANONICAL_OBJECT", `${label} has unexpected or missing fields`);
  }
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value: string, label: string, expectedLength?: number): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    fail("PHIL_RECOVERY_INVALID_BASE64URL", `${label} must be unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    fail("PHIL_RECOVERY_INVALID_BASE64URL", `${label} must be canonical base64url`);
  }
  if (expectedLength !== undefined && decoded.byteLength !== expectedLength) {
    fail("PHIL_RECOVERY_INVALID_LENGTH", `${label} has the wrong length`);
  }
  return decoded;
}

function normalizePositiveUInt64(
  value: string | number | bigint,
  label: string
): PhilUInt64String {
  const normalized = normalizePhilUInt64(value, label);
  if (normalized === "0") {
    fail("PHIL_RECOVERY_ZERO_UINT64", `${label} must be non-zero`);
  }
  return normalized;
}

function incrementUInt64(value: PhilUInt64String, label: string): PhilUInt64String {
  const next = BigInt(value) + 1n;
  if (next > 0xffff_ffff_ffff_ffffn) {
    fail("PHIL_RECOVERY_UINT64_OVERFLOW", `${label} cannot be incremented`);
  }
  return next.toString(10);
}

function normalizeKey(value: BytesLike, label: string): Buffer {
  const key = Buffer.from(getBytes(value));
  if (key.byteLength !== 32) {
    fail("PHIL_RECOVERY_INVALID_KEY", `${label} must be 32 bytes`);
  }
  return key;
}

function hashJson(value: unknown): Hex {
  return keccak256(toUtf8Bytes(stableJson(value))) as Hex;
}

function normalizeStatus(value: string): PhilContinuityRecordStatusV1 {
  if (value === "active" || value === "suspended" || value === "revoked") {
    return value;
  }
  return fail("PHIL_RECOVERY_INVALID_STATUS", "continuity status is invalid");
}

function normalizeAccountStatus(value: string): PhilAccountBindingStatusV1 {
  if (value === "active" || value === "suspended" || value === "pending_reconciliation") {
    return value;
  }
  return fail("PHIL_RECOVERY_INVALID_STATUS", "account binding status is invalid");
}

function assertSortedUnique(values: readonly Hex[], label: string) {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1] >= values[index]) {
      fail("PHIL_RECOVERY_NON_CANONICAL_ORDER", `${label} must be sorted and unique`);
    }
  }
}

function normalizeScopeRecord(
  value: PhilScopeRecordV1,
  identityRoot: Hex
): PhilScopeRecordV1 {
  const scopeId = requirePhilNonZeroBytes32(value.scopeId, "scopeId");
  const scopeInstance = requirePhilNonZeroBytes32(value.scopeInstance, "scopeInstance");
  const scopeEpoch = normalizePositiveUInt64(value.scopeEpoch, "scopeEpoch");
  const scopedOwnerCommitment = requirePhilNonZeroBytes32(
    value.scopedOwnerCommitment,
    "scopedOwnerCommitment"
  );
  const expectedScopeId = derivePhilScopeIdV1(value);
  if (expectedScopeId !== scopeId) {
    fail("PHIL_RECOVERY_SCOPE_ID_MISMATCH", "scope ID does not match its descriptor");
  }
  const expectedCommitment = derivePhilScopedOwnerCommitmentV1({
    identityRoot,
    scopeId,
    scopeInstance,
    scopeEpoch
  });
  if (expectedCommitment !== scopedOwnerCommitment) {
    fail("PHIL_RECOVERY_SCOPE_COMMITMENT_MISMATCH", "scope commitment does not match root");
  }
  return Object.freeze({
    scopeKind: value.scopeKind,
    namespaceHash: requirePhilNonZeroBytes32(value.namespaceHash, "namespaceHash"),
    contextHash: requirePhilNonZeroBytes32(value.contextHash, "contextHash"),
    scopeId,
    scopeInstance,
    scopeEpoch,
    scopedOwnerCommitment,
    status: normalizeStatus(value.status)
  });
}

export function createPhilIdentityContinuityPackageV1(input: {
  philSecret: BytesLike;
  dataRootKey: BytesLike;
  dataEpoch?: string | number | bigint;
  deviceEpoch?: string | number | bigint;
  recoveryEpoch?: string | number | bigint;
  validatorEpoch?: string | number | bigint;
  capabilityEpoch?: string | number | bigint;
  scopeRegistry?: readonly PhilScopeRecordV1[];
  accountBindings?: readonly PhilAccountBindingRecordV1[];
  credentialRegistry?: readonly PhilCredentialRecordV1[];
  policyState?: PhilPolicyStateV1;
  capabilityRevocationState?: PhilCapabilityRevocationStateV1;
  auditContinuityState?: PhilAuditContinuityStateV1;
}): PhilIdentityContinuityPackageV1 {
  const philSecret = normalizePhilSecret(input.philSecret);
  const identityRoot = derivePhilIdentityRoot(philSecret);
  const rootOwnerCommitment = deriveOwnerCommitmentFromPhilSecret(philSecret);
  const dataRootKey = requirePhilNonZeroBytes32(input.dataRootKey, "dataRootKey");
  const dataEpoch = normalizePositiveUInt64(input.dataEpoch ?? 1, "dataEpoch");
  const deviceEpoch = normalizePositiveUInt64(input.deviceEpoch ?? 1, "deviceEpoch");
  const recoveryEpoch = normalizePositiveUInt64(input.recoveryEpoch ?? 1, "recoveryEpoch");
  const validatorEpoch = normalizePositiveUInt64(input.validatorEpoch ?? 1, "validatorEpoch");
  const capabilityEpoch = normalizePositiveUInt64(input.capabilityEpoch ?? 1, "capabilityEpoch");

  const scopeRegistry = [...(input.scopeRegistry ?? [])]
    .map((value) => normalizeScopeRecord(value, identityRoot))
    .sort((left, right) => left.scopedOwnerCommitment < right.scopedOwnerCommitment
      ? -1
      : left.scopedOwnerCommitment > right.scopedOwnerCommitment ? 1 : 0);
  assertSortedUnique(
    scopeRegistry.map((record) => record.scopedOwnerCommitment),
    "scopeRegistry"
  );

  const scopeCommitments = new Set(scopeRegistry.map((record) => record.scopedOwnerCommitment));
  const accountBindings = [...(input.accountBindings ?? [])]
    .map((value) => {
      const scopedOwnerCommitment = requirePhilNonZeroBytes32(
        value.scopedOwnerCommitment,
        "accountBinding.scopedOwnerCommitment"
      );
      if (!scopeCommitments.has(scopedOwnerCommitment)) {
        fail("PHIL_RECOVERY_ACCOUNT_SCOPE_MISSING", "account binding references an unknown scope");
      }
      return Object.freeze({
        accountBindingId: requirePhilNonZeroBytes32(value.accountBindingId, "accountBindingId"),
        scopedOwnerCommitment,
        networkIdHash: requirePhilNonZeroBytes32(value.networkIdHash, "networkIdHash"),
        accountBindingHash: requirePhilNonZeroBytes32(value.accountBindingHash, "accountBindingHash"),
        validatorEpoch: normalizePositiveUInt64(value.validatorEpoch, "account.validatorEpoch"),
        status: normalizeAccountStatus(value.status)
      });
    })
    .sort((left, right) => left.accountBindingId < right.accountBindingId
      ? -1
      : left.accountBindingId > right.accountBindingId ? 1 : 0);
  assertSortedUnique(accountBindings.map((record) => record.accountBindingId), "accountBindings");

  const credentialRegistry = [...(input.credentialRegistry ?? [])]
    .map((value) => Object.freeze({
      credentialIdHash: requirePhilNonZeroBytes32(value.credentialIdHash, "credentialIdHash"),
      credentialTypeHash: requirePhilNonZeroBytes32(value.credentialTypeHash, "credentialTypeHash"),
      publicKeyHash: requirePhilNonZeroBytes32(value.publicKeyHash, "publicKeyHash"),
      deviceEpoch: normalizePositiveUInt64(value.deviceEpoch, "credential.deviceEpoch"),
      status: normalizeStatus(value.status)
    }))
    .sort((left, right) => left.credentialIdHash < right.credentialIdHash
      ? -1
      : left.credentialIdHash > right.credentialIdHash ? 1 : 0);
  assertSortedUnique(
    credentialRegistry.map((record) => record.credentialIdHash),
    "credentialRegistry"
  );

  const policyState = Object.freeze({
    policyVersion: normalizePositiveUInt64(input.policyState?.policyVersion ?? 1, "policyVersion"),
    policyHash: normalizePhilBytes32(input.policyState?.policyHash ?? keccak256("0x"), "policyHash")
  });
  const revokedCapabilityIds = [...(input.capabilityRevocationState?.revokedCapabilityIds ?? [])]
    .map((value) => requirePhilNonZeroBytes32(value, "revokedCapabilityId"))
    .sort();
  assertSortedUnique(revokedCapabilityIds, "revokedCapabilityIds");
  const capabilityRevocationState = Object.freeze({
    capabilityEpoch: normalizePositiveUInt64(
      input.capabilityRevocationState?.capabilityEpoch ?? capabilityEpoch,
      "capabilityRevocationState.capabilityEpoch"
    ),
    revocationRoot: normalizePhilBytes32(
      input.capabilityRevocationState?.revocationRoot ?? keccak256("0x"),
      "revocationRoot"
    ),
    revokedCapabilityIds: Object.freeze(revokedCapabilityIds)
  });
  if (capabilityRevocationState.capabilityEpoch !== capabilityEpoch) {
    fail("PHIL_RECOVERY_CAPABILITY_EPOCH_MISMATCH", "capability epochs must match");
  }
  const auditContinuityState = Object.freeze({
    eventCount: normalizePhilUInt64(input.auditContinuityState?.eventCount ?? 0, "eventCount"),
    auditHeadHash: normalizePhilBytes32(
      input.auditContinuityState?.auditHeadHash ?? keccak256("0x"),
      "auditHeadHash"
    )
  });

  return Object.freeze({
    formatVersionHash: PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_HASH,
    identitySuiteId: PHIL_IDENTITY_KECCAK_ABI_V1_SUITE_ID,
    philSecret,
    identityRoot,
    rootOwnerCommitment,
    dataRootKey,
    dataEpoch,
    deviceEpoch,
    recoveryEpoch,
    validatorEpoch,
    capabilityEpoch,
    scopeRegistry: Object.freeze(scopeRegistry),
    accountBindings: Object.freeze(accountBindings),
    credentialRegistry: Object.freeze(credentialRegistry),
    policyState,
    capabilityRevocationState,
    auditContinuityState
  });
}

function validateContinuityPackage(value: PhilIdentityContinuityPackageV1): PhilIdentityContinuityPackageV1 {
  exactKeys(value, [
    "formatVersionHash",
    "identitySuiteId",
    "philSecret",
    "identityRoot",
    "rootOwnerCommitment",
    "dataRootKey",
    "dataEpoch",
    "deviceEpoch",
    "recoveryEpoch",
    "validatorEpoch",
    "capabilityEpoch",
    "scopeRegistry",
    "accountBindings",
    "credentialRegistry",
    "policyState",
    "capabilityRevocationState",
    "auditContinuityState"
  ], "continuity package");
  if (normalizePhilBytes32(value.formatVersionHash, "formatVersionHash")
    !== PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_HASH) {
    fail("PHIL_RECOVERY_FORMAT_UNSUPPORTED", "continuity package format is unsupported");
  }
  if (normalizePhilBytes32(value.identitySuiteId, "identitySuiteId")
    !== PHIL_IDENTITY_KECCAK_ABI_V1_SUITE_ID) {
    fail("PHIL_RECOVERY_IDENTITY_SUITE_UNSUPPORTED", "identity suite is unsupported");
  }
  const normalized = createPhilIdentityContinuityPackageV1(value);
  if (normalized.identityRoot !== normalizePhilBytes32(value.identityRoot, "identityRoot")
    || normalized.rootOwnerCommitment
      !== normalizePhilBytes32(value.rootOwnerCommitment, "rootOwnerCommitment")) {
    fail("PHIL_RECOVERY_IDENTITY_MISMATCH", "continuity identity derivation mismatch");
  }
  if (stableJson(value) !== stableJson(normalized)) {
    fail("PHIL_RECOVERY_PACKAGE_NON_CANONICAL", "continuity package codec is non-canonical");
  }
  return normalized;
}

function derivePackageAadHash(envelope: Omit<PhilRecoveryEnvelopeV1, "ciphertextHash">): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint64"],
      [
        PHIL_RECOVERY_PACKAGE_AAD_V1_HASH,
        envelope.formatVersionHash,
        envelope.encryptionSuiteId,
        envelope.sharingSuiteId,
        envelope.recoverySetId,
        BigInt(envelope.recoveryEpoch),
        BigInt(envelope.packageCounter),
        BigInt(envelope.createdAt)
      ]
    )
  ) as Hex;
}

function pairIndices(pair: PhilRecoveryPairV1): readonly [PhilRecoveryHolderIndexV1, PhilRecoveryHolderIndexV1] {
  if (pair === "1-2") return [1, 2];
  if (pair === "1-3") return [1, 3];
  if (pair === "2-3") return [2, 3];
  return fail("PHIL_RECOVERY_INVALID_PAIR", "recovery pair is invalid");
}

function pairsForHolder(holderIndex: PhilRecoveryHolderIndexV1): readonly PhilRecoveryPairV1[] {
  if (holderIndex === 1) return ["1-2", "1-3"];
  if (holderIndex === 2) return ["1-2", "2-3"];
  if (holderIndex === 3) return ["1-3", "2-3"];
  return fail("PHIL_RECOVERY_INVALID_HOLDER", "recovery holder is invalid");
}

function deriveShareChecksum(share: Omit<PhilRecoveryShareV1, "checksum" | "warning">): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint8", "bytes32"],
      [
        PHIL_RECOVERY_SHARE_V1_HASH,
        share.sharingSuiteId,
        share.recoverySetId,
        BigInt(share.recoveryEpoch),
        share.holderIndex,
        hashJson(share.contributions)
      ]
    )
  ) as Hex;
}

function createShares(input: {
  recoverySetId: Hex;
  recoveryEpoch: PhilUInt64String;
}): readonly PhilRecoveryShareV1[] {
  return Object.freeze(([1, 2, 3] as const).map((holderIndex) => {
    const contributions = Object.freeze(pairsForHolder(holderIndex).map((pair) => Object.freeze({
      pair,
      material: base64Url(nodeRandomBytes(32))
    })));
    const core = {
      format: "phil-recovery-share-v1" as const,
      sharingSuiteId: PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID,
      recoverySetId: input.recoverySetId,
      recoveryEpoch: input.recoveryEpoch,
      holderIndex,
      contributions
    };
    return Object.freeze({
      ...core,
      checksum: deriveShareChecksum(core),
      warning: "SECRET_RECOVERY_FACTOR_MATERIAL" as const
    });
  }));
}

function validateShare(share: PhilRecoveryShareV1): PhilRecoveryShareV1 {
  exactKeys(share, [
    "format",
    "sharingSuiteId",
    "recoverySetId",
    "recoveryEpoch",
    "holderIndex",
    "contributions",
    "checksum",
    "warning"
  ], "recovery share");
  if (share.format !== "phil-recovery-share-v1"
    || share.warning !== "SECRET_RECOVERY_FACTOR_MATERIAL") {
    fail("PHIL_RECOVERY_SHARE_FORMAT_INVALID", "recovery share format is invalid");
  }
  if (normalizePhilBytes32(share.sharingSuiteId, "sharingSuiteId")
      !== PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID) {
    fail("PHIL_RECOVERY_SHARING_SUITE_UNSUPPORTED", "sharing suite is unsupported");
  }
  if (share.holderIndex !== 1 && share.holderIndex !== 2 && share.holderIndex !== 3) {
    fail("PHIL_RECOVERY_INVALID_HOLDER", "recovery holder is invalid");
  }
  const expectedPairs = pairsForHolder(share.holderIndex);
  if (share.contributions.length !== 2
    || share.contributions.some((entry, index) => entry.pair !== expectedPairs[index])) {
    fail("PHIL_RECOVERY_SHARE_CONTRIBUTIONS_INVALID", "share contributions are invalid");
  }
  for (const contribution of share.contributions) {
    exactKeys(contribution, ["pair", "material"], "share contribution");
    decodeBase64Url(contribution.material, "share contribution", 32);
  }
  const core = {
    format: share.format,
    sharingSuiteId: normalizePhilBytes32(share.sharingSuiteId, "sharingSuiteId"),
    recoverySetId: requirePhilNonZeroBytes32(share.recoverySetId, "recoverySetId"),
    recoveryEpoch: normalizePositiveUInt64(share.recoveryEpoch, "recoveryEpoch"),
    holderIndex: share.holderIndex,
    contributions: share.contributions
  };
  if (deriveShareChecksum(core) !== normalizePhilBytes32(share.checksum, "share.checksum")) {
    fail("PHIL_RECOVERY_SHARE_CHECKSUM_MISMATCH", "recovery share checksum mismatch");
  }
  return Object.freeze({ ...core, checksum: share.checksum, warning: share.warning });
}

function contributionFor(share: PhilRecoveryShareV1, pair: PhilRecoveryPairV1): Buffer {
  const contribution = share.contributions.find((entry) => entry.pair === pair);
  if (!contribution) {
    return fail("PHIL_RECOVERY_SHARE_PAIR_MISSING", "share does not contain pair contribution");
  }
  return decodeBase64Url(contribution.material, "share contribution", 32);
}

function derivePairKek(input: {
  pair: PhilRecoveryPairV1;
  leftShare: PhilRecoveryShareV1;
  rightShare: PhilRecoveryShareV1;
  recoverySetId: Hex;
  recoveryEpoch: PhilUInt64String;
}): Buffer {
  const [leftIndex, rightIndex] = pairIndices(input.pair);
  if (input.leftShare.holderIndex !== leftIndex || input.rightShare.holderIndex !== rightIndex) {
    fail("PHIL_RECOVERY_PAIR_ORDER_INVALID", "recovery shares do not match pair order");
  }
  const material = Buffer.concat([
    contributionFor(input.leftShare, input.pair),
    contributionFor(input.rightShare, input.pair)
  ]);
  const info = Buffer.from(getBytes(keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "uint64", "uint8", "uint8"],
      [
        PHIL_RECOVERY_KEY_WRAP_V1_HASH,
        input.recoverySetId,
        BigInt(input.recoveryEpoch),
        leftIndex,
        rightIndex
      ]
    )
  )));
  const key = Buffer.from(hkdfSync(
    "sha256",
    material,
    Buffer.from(getBytes(input.recoverySetId)),
    info,
    32
  ));
  material.fill(0);
  return key;
}

function wrapperAadHash(envelope: PhilRecoveryEnvelopeV1, pair: PhilRecoveryPairV1): Hex {
  const [left, right] = pairIndices(pair);
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "bytes32", "uint8", "uint8"],
      [
        PHIL_RECOVERY_KEY_WRAP_V1_HASH,
        envelope.sharingSuiteId,
        envelope.recoverySetId,
        BigInt(envelope.recoveryEpoch),
        BigInt(envelope.packageCounter),
        envelope.ciphertextHash,
        left,
        right
      ]
    )
  ) as Hex;
}

function encryptAesGcm(key: Buffer, plaintext: Buffer, aadHash: Hex): PhilRecoveryEncryptedPayloadV1 {
  const iv = nodeRandomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(getBytes(aadHash)));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Object.freeze({
    iv: base64Url(iv),
    authenticationTag: base64Url(cipher.getAuthTag()),
    ciphertext: base64Url(ciphertext)
  });
}

function decryptAesGcm(
  key: Buffer,
  payload: PhilRecoveryEncryptedPayloadV1,
  aadHash: Hex,
  failureCode: string
): Buffer {
  try {
    exactKeys(payload, ["iv", "authenticationTag", "ciphertext"], "encrypted payload");
    const iv = decodeBase64Url(payload.iv, "iv", 12);
    const tag = decodeBase64Url(payload.authenticationTag, "authenticationTag", 16);
    const ciphertext = decodeBase64Url(payload.ciphertext, "ciphertext");
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from(getBytes(aadHash)));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    if (error instanceof PhilIdentityDataRecoveryV1Error) throw error;
    return fail(failureCode, "authenticated decryption failed");
  }
}

function encryptedPayloadHash(payload: PhilRecoveryEncryptedPayloadV1): Hex {
  return keccak256(concat([
    decodeBase64Url(payload.iv, "iv", 12),
    decodeBase64Url(payload.authenticationTag, "authenticationTag", 16),
    decodeBase64Url(payload.ciphertext, "ciphertext")
  ])) as Hex;
}

function normalizeEnvelope(envelope: PhilRecoveryEnvelopeV1): PhilRecoveryEnvelopeV1 {
  exactKeys(envelope, [
    "formatVersionHash",
    "encryptionSuiteId",
    "sharingSuiteId",
    "recoverySetId",
    "recoveryEpoch",
    "packageCounter",
    "createdAt",
    "ciphertextHash"
  ], "recovery envelope");
  const normalized = Object.freeze({
    formatVersionHash: normalizePhilBytes32(envelope.formatVersionHash, "formatVersionHash"),
    encryptionSuiteId: normalizePhilBytes32(envelope.encryptionSuiteId, "encryptionSuiteId"),
    sharingSuiteId: normalizePhilBytes32(envelope.sharingSuiteId, "sharingSuiteId"),
    recoverySetId: requirePhilNonZeroBytes32(envelope.recoverySetId, "recoverySetId"),
    recoveryEpoch: normalizePositiveUInt64(envelope.recoveryEpoch, "recoveryEpoch"),
    packageCounter: normalizePositiveUInt64(envelope.packageCounter, "packageCounter"),
    createdAt: normalizePositiveUInt64(envelope.createdAt, "createdAt"),
    ciphertextHash: normalizePhilBytes32(envelope.ciphertextHash, "ciphertextHash")
  });
  if (normalized.formatVersionHash !== PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_HASH
    || normalized.encryptionSuiteId !== PHIL_AES_256_GCM_V1_SUITE_ID
    || normalized.sharingSuiteId !== PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID) {
    fail("PHIL_RECOVERY_SUITE_UNSUPPORTED", "recovery envelope suite is unsupported");
  }
  return normalized;
}

export function createPhilIdentityDataRecoveryBundleV1(input: {
  continuityPackage: PhilIdentityContinuityPackageV1;
  packageCounter?: string | number | bigint;
  createdAt: string | number | bigint;
}): {
  readonly bundle: PhilIdentityDataRecoveryBundleV1;
  readonly shares: readonly PhilRecoveryShareV1[];
} {
  const continuityPackage = validateContinuityPackage(input.continuityPackage);
  const recoverySetId = requirePhilNonZeroBytes32(nodeRandomBytes(32), "recoverySetId");
  const preliminaryEnvelope = Object.freeze({
    formatVersionHash: PHIL_IDENTITY_CONTINUITY_PACKAGE_V1_HASH,
    encryptionSuiteId: PHIL_AES_256_GCM_V1_SUITE_ID,
    sharingSuiteId: PHIL_PAIRWISE_2_OF_3_SHARING_SUITE_ID,
    recoverySetId,
    recoveryEpoch: continuityPackage.recoveryEpoch,
    packageCounter: normalizePositiveUInt64(input.packageCounter ?? 1, "packageCounter"),
    createdAt: normalizePositiveUInt64(input.createdAt, "createdAt")
  });
  const packageKey = nodeRandomBytes(32);
  const continuityPlaintext = Buffer.from(stableJson(continuityPackage), "utf8");
  try {
    const encryptedPackage = encryptAesGcm(
      packageKey,
      continuityPlaintext,
      derivePackageAadHash(preliminaryEnvelope)
    );
    const envelope = Object.freeze({
      ...preliminaryEnvelope,
      ciphertextHash: encryptedPayloadHash(encryptedPackage)
    });
    const shares = createShares({ recoverySetId, recoveryEpoch: envelope.recoveryEpoch });
    const keyWrappers = Object.freeze((["1-2", "1-3", "2-3"] as const).map((pair) => {
      const [leftIndex, rightIndex] = pairIndices(pair);
      const leftShare = shares[leftIndex - 1];
      const rightShare = shares[rightIndex - 1];
      const kek = derivePairKek({
        pair,
        leftShare,
        rightShare,
        recoverySetId,
        recoveryEpoch: envelope.recoveryEpoch
      });
      try {
        const encrypted = encryptAesGcm(kek, packageKey, wrapperAadHash(envelope, pair));
        return Object.freeze({
          pair,
          ...encrypted,
          wrapperHash: hashJson({ pair, ...encrypted })
        });
      } finally {
        kek.fill(0);
      }
    }));
    const bundle = Object.freeze({
      format: "phil-identity-data-recovery-bundle-v1" as const,
      envelope,
      encryptedPackage,
      keyWrappers
    });
    assertPhilIdentityDataRecoveryBundlePublicSafeV1(bundle);
    return Object.freeze({ bundle, shares });
  } finally {
    continuityPlaintext.fill(0);
    packageKey.fill(0);
  }
}

export function assertPhilIdentityDataRecoveryBundlePublicSafeV1(
  bundle: PhilIdentityDataRecoveryBundleV1
): void {
  exactKeys(bundle, ["format", "envelope", "encryptedPackage", "keyWrappers"], "recovery bundle");
  if (bundle.format !== "phil-identity-data-recovery-bundle-v1") {
    fail("PHIL_RECOVERY_BUNDLE_FORMAT_INVALID", "recovery bundle format is invalid");
  }
  const envelope = normalizeEnvelope(bundle.envelope);
  if (encryptedPayloadHash(bundle.encryptedPackage) !== envelope.ciphertextHash) {
    fail("PHIL_RECOVERY_CIPHERTEXT_HASH_MISMATCH", "recovery ciphertext hash mismatch");
  }
  if (bundle.keyWrappers.length !== 3) {
    fail("PHIL_RECOVERY_WRAPPER_SET_INVALID", "exactly three pair wrappers are required");
  }
  const pairs: PhilRecoveryPairV1[] = ["1-2", "1-3", "2-3"];
  bundle.keyWrappers.forEach((wrapper, index) => {
    exactKeys(wrapper, [
      "pair",
      "iv",
      "authenticationTag",
      "ciphertext",
      "wrapperHash"
    ], "key wrapper");
    if (wrapper.pair !== pairs[index]) {
      fail("PHIL_RECOVERY_WRAPPER_SET_INVALID", "key wrappers are not canonical");
    }
    decodeBase64Url(wrapper.iv, "wrapper.iv", 12);
    decodeBase64Url(wrapper.authenticationTag, "wrapper.authenticationTag", 16);
    decodeBase64Url(wrapper.ciphertext, "wrapper.ciphertext", 32);
    if (hashJson({
      pair: wrapper.pair,
      iv: wrapper.iv,
      authenticationTag: wrapper.authenticationTag,
      ciphertext: wrapper.ciphertext
    }) !== normalizePhilBytes32(wrapper.wrapperHash, "wrapperHash")) {
      fail("PHIL_RECOVERY_WRAPPER_HASH_MISMATCH", "key wrapper hash mismatch");
    }
  });
  const serialized = stableJson(bundle);
  if (/philSecret|identityRoot|rootOwnerCommitment|dataRootKey|contributions|material|privateKey/i
    .test(serialized)) {
    fail("PHIL_RECOVERY_PUBLIC_SECRET_FIELD_REJECTED", "public recovery bundle contains a secret field");
  }
}

export function summarizePhilIdentityDataRecoveryBundleV1(
  bundle: PhilIdentityDataRecoveryBundleV1
): Readonly<{
  format: string;
  recoverySetId: Hex;
  recoveryEpoch: PhilUInt64String;
  packageCounter: PhilUInt64String;
  createdAt: PhilUInt64String;
  ciphertextHash: Hex;
  sharingSuiteId: Hex;
  pairCount: 3;
}> {
  assertPhilIdentityDataRecoveryBundlePublicSafeV1(bundle);
  return Object.freeze({
    format: bundle.format,
    recoverySetId: bundle.envelope.recoverySetId,
    recoveryEpoch: bundle.envelope.recoveryEpoch,
    packageCounter: bundle.envelope.packageCounter,
    createdAt: bundle.envelope.createdAt,
    ciphertextHash: bundle.envelope.ciphertextHash,
    sharingSuiteId: bundle.envelope.sharingSuiteId,
    pairCount: 3 as const
  });
}

function selectExactPair(shares: readonly PhilRecoveryShareV1[]): {
  pair: PhilRecoveryPairV1;
  leftShare: PhilRecoveryShareV1;
  rightShare: PhilRecoveryShareV1;
} {
  if (shares.length !== 2) {
    fail("PHIL_RECOVERY_EXACT_TWO_SHARES_REQUIRED", "exactly two recovery shares are required");
  }
  const normalized = shares.map(validateShare).sort((left, right) => left.holderIndex - right.holderIndex);
  if (normalized[0].holderIndex === normalized[1].holderIndex) {
    fail("PHIL_RECOVERY_DUPLICATE_SHARE", "duplicate recovery holder is not allowed");
  }
  const pair = `${normalized[0].holderIndex}-${normalized[1].holderIndex}` as PhilRecoveryPairV1;
  pairIndices(pair);
  return { pair, leftShare: normalized[0], rightShare: normalized[1] };
}

function enforceAntiRollback(
  envelope: PhilRecoveryEnvelopeV1,
  floor?: PhilRecoveryAntiRollbackFloorV1
) {
  if (!floor) return;
  const floorEpoch = BigInt(normalizePositiveUInt64(floor.recoveryEpoch, "floor.recoveryEpoch"));
  const floorCounter = BigInt(normalizePositiveUInt64(floor.packageCounter, "floor.packageCounter"));
  const epoch = BigInt(envelope.recoveryEpoch);
  const counter = BigInt(envelope.packageCounter);
  if (epoch < floorEpoch || (epoch === floorEpoch && counter < floorCounter)) {
    fail("PHIL_RECOVERY_ROLLBACK_REJECTED", "recovery package is older than the accepted floor");
  }
}

export function restorePhilIdentityDataRecoveryBundleV1(input: {
  bundle: PhilIdentityDataRecoveryBundleV1;
  shares: readonly PhilRecoveryShareV1[];
  antiRollbackFloor?: PhilRecoveryAntiRollbackFloorV1;
}): PhilIdentityContinuityPackageV1 {
  assertPhilIdentityDataRecoveryBundlePublicSafeV1(input.bundle);
  const envelope = normalizeEnvelope(input.bundle.envelope);
  enforceAntiRollback(envelope, input.antiRollbackFloor);
  const selected = selectExactPair(input.shares);
  for (const share of [selected.leftShare, selected.rightShare]) {
    if (share.recoverySetId !== envelope.recoverySetId
      || share.recoveryEpoch !== envelope.recoveryEpoch
      || share.sharingSuiteId !== envelope.sharingSuiteId) {
      fail("PHIL_RECOVERY_MIXED_SHARE_SET", "recovery share does not match package set and epoch");
    }
  }
  const wrapper = input.bundle.keyWrappers.find((candidate) => candidate.pair === selected.pair);
  if (!wrapper) {
    return fail("PHIL_RECOVERY_WRAPPER_MISSING", "matching key wrapper is missing");
  }
  const kek = derivePairKek({
    ...selected,
    recoverySetId: envelope.recoverySetId,
    recoveryEpoch: envelope.recoveryEpoch
  });
  let packageKey: Buffer | undefined;
  try {
    packageKey = decryptAesGcm(
      kek,
      {
        iv: wrapper.iv,
        authenticationTag: wrapper.authenticationTag,
        ciphertext: wrapper.ciphertext
      },
      wrapperAadHash(envelope, selected.pair),
      "PHIL_RECOVERY_KEY_UNWRAP_FAILED"
    );
    if (packageKey.byteLength !== 32) {
      fail("PHIL_RECOVERY_KEY_UNWRAP_FAILED", "unwrapped recovery package key is invalid");
    }
    const preliminary = {
      formatVersionHash: envelope.formatVersionHash,
      encryptionSuiteId: envelope.encryptionSuiteId,
      sharingSuiteId: envelope.sharingSuiteId,
      recoverySetId: envelope.recoverySetId,
      recoveryEpoch: envelope.recoveryEpoch,
      packageCounter: envelope.packageCounter,
      createdAt: envelope.createdAt
    };
    const plaintext = decryptAesGcm(
      packageKey,
      input.bundle.encryptedPackage,
      derivePackageAadHash(preliminary),
      "PHIL_RECOVERY_PACKAGE_AUTHENTICATION_FAILED"
    );
    let parsed: PhilIdentityContinuityPackageV1;
    try {
      parsed = JSON.parse(plaintext.toString("utf8")) as PhilIdentityContinuityPackageV1;
    } catch {
      return fail("PHIL_RECOVERY_PACKAGE_CODEC_INVALID", "continuity package JSON is invalid");
    } finally {
      plaintext.fill(0);
    }
    const restored = validateContinuityPackage(parsed);
    if (restored.recoveryEpoch !== envelope.recoveryEpoch) {
      fail("PHIL_RECOVERY_EPOCH_MISMATCH", "continuity and envelope recovery epochs differ");
    }
    return restored;
  } finally {
    kek.fill(0);
    packageKey?.fill(0);
  }
}

export function createPhilRecoveryRequestV1(input: {
  bundle: PhilIdentityDataRecoveryBundleV1;
  operation: PhilRecoveryOperationV1;
  requestedAt: string | number | bigint;
  delaySeconds: string | number | bigint;
  expiresAfterSeconds: string | number | bigint;
  destructiveApprovalDigest: BytesLike;
  notificationTargetHashes: readonly BytesLike[];
  notificationEvidenceHashes: readonly BytesLike[];
}): PhilRecoveryRequestV1 {
  assertPhilIdentityDataRecoveryBundlePublicSafeV1(input.bundle);
  const operation = input.operation;
  const operationCode = recoveryOperationCode(operation);
  const requestedAt = normalizePositiveUInt64(input.requestedAt, "requestedAt");
  const delaySeconds = normalizePositiveUInt64(input.delaySeconds, "delaySeconds");
  const expiresAfter = normalizePositiveUInt64(input.expiresAfterSeconds, "expiresAfterSeconds");
  if (BigInt(expiresAfter) <= BigInt(delaySeconds)) {
    fail("PHIL_RECOVERY_INVALID_DELAY_POLICY", "expiry must be later than recovery delay");
  }
  if (input.notificationTargetHashes.length === 0) {
    fail("PHIL_RECOVERY_NOTIFICATION_REQUIRED", "at least one recovery notification is required");
  }
  const notificationTargetHashes = input.notificationTargetHashes
    .map((value) => requirePhilNonZeroBytes32(value, "notificationTargetHash"))
    .sort();
  assertSortedUnique(notificationTargetHashes, "notificationTargetHashes");
  const notificationEvidenceHashes = input.notificationEvidenceHashes
    .map((value) => requirePhilNonZeroBytes32(value, "notificationEvidenceHash"))
    .sort();
  assertSortedUnique(notificationEvidenceHashes, "notificationEvidenceHashes");
  if (notificationEvidenceHashes.length !== notificationTargetHashes.length) {
    fail(
      "PHIL_RECOVERY_NOTIFICATION_EVIDENCE_REQUIRED",
      "each recovery notification target requires delivery evidence"
    );
  }
  const bundleHash = hashJson(input.bundle);
  const destructiveApprovalDigest = requirePhilNonZeroBytes32(
    input.destructiveApprovalDigest,
    "destructiveApprovalDigest"
  );
  const notBefore = normalizePhilUInt64(BigInt(requestedAt) + BigInt(delaySeconds), "notBefore");
  const expiresAt = normalizePhilUInt64(BigInt(requestedAt) + BigInt(expiresAfter), "expiresAt");
  const requestId = keccak256(
    abiCoder.encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "uint64",
        "uint64",
        "uint64",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        PHIL_RECOVERY_REQUEST_V1_HASH,
        operationCode,
        bundleHash,
        BigInt(requestedAt),
        BigInt(notBefore),
        BigInt(expiresAt),
        destructiveApprovalDigest,
        hashJson(notificationTargetHashes),
        hashJson(notificationEvidenceHashes)
      ]
    )
  ) as Hex;
  return Object.freeze({
    format: "phil-recovery-request-v1",
    operation,
    requestId,
    bundleHash,
    requestedAt,
    notBefore,
    expiresAt,
    destructiveApprovalDigest,
    notificationTargetHashes: Object.freeze(notificationTargetHashes),
    notificationEvidenceHashes: Object.freeze(notificationEvidenceHashes),
    status: "pending_delay"
  });
}

function validateRecoveryRequest(request: PhilRecoveryRequestV1): PhilRecoveryRequestV1 {
  const expectedKeys = [
    "format",
    "operation",
    "requestId",
    "bundleHash",
    "requestedAt",
    "notBefore",
    "expiresAt",
    "destructiveApprovalDigest",
    "notificationTargetHashes",
    "notificationEvidenceHashes",
    "status"
  ];
  if (request.status === "cancelled") expectedKeys.push("cancellationReasonHash");
  if (request.status === "completed") expectedKeys.push("completionHash");
  exactKeys(request, expectedKeys, "recovery request");
  if (request.format !== "phil-recovery-request-v1"
    || (request.status !== "pending_delay"
      && request.status !== "cancelled"
      && request.status !== "completed")) {
    fail("PHIL_RECOVERY_REQUEST_FORMAT_INVALID", "recovery request format is invalid");
  }
  const requestedAt = normalizePositiveUInt64(request.requestedAt, "requestedAt");
  const operationCode = recoveryOperationCode(request.operation);
  const notBefore = normalizePositiveUInt64(request.notBefore, "notBefore");
  const expiresAt = normalizePositiveUInt64(request.expiresAt, "expiresAt");
  if (BigInt(notBefore) <= BigInt(requestedAt) || BigInt(expiresAt) <= BigInt(notBefore)) {
    fail("PHIL_RECOVERY_REQUEST_TIME_INVALID", "recovery request time window is invalid");
  }
  const notificationTargetHashes = request.notificationTargetHashes
    .map((value) => requirePhilNonZeroBytes32(value, "notificationTargetHash"));
  const notificationEvidenceHashes = request.notificationEvidenceHashes
    .map((value) => requirePhilNonZeroBytes32(value, "notificationEvidenceHash"));
  assertSortedUnique(notificationTargetHashes, "notificationTargetHashes");
  assertSortedUnique(notificationEvidenceHashes, "notificationEvidenceHashes");
  if (notificationTargetHashes.length === 0
    || notificationTargetHashes.length !== notificationEvidenceHashes.length) {
    fail("PHIL_RECOVERY_NOTIFICATION_EVIDENCE_REQUIRED", "notification evidence is incomplete");
  }
  const bundleHash = normalizePhilBytes32(request.bundleHash, "bundleHash");
  const destructiveApprovalDigest = requirePhilNonZeroBytes32(
    request.destructiveApprovalDigest,
    "destructiveApprovalDigest"
  );
  const expectedRequestId = keccak256(
    abiCoder.encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "uint64",
        "uint64",
        "uint64",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        PHIL_RECOVERY_REQUEST_V1_HASH,
        operationCode,
        bundleHash,
        BigInt(requestedAt),
        BigInt(notBefore),
        BigInt(expiresAt),
        destructiveApprovalDigest,
        hashJson(notificationTargetHashes),
        hashJson(notificationEvidenceHashes)
      ]
    )
  ) as Hex;
  if (expectedRequestId !== normalizePhilBytes32(request.requestId, "requestId")) {
    fail("PHIL_RECOVERY_REQUEST_BINDING_INVALID", "recovery request binding is invalid");
  }
  if (request.status === "cancelled") {
    requirePhilNonZeroBytes32(request.cancellationReasonHash ?? "0x", "cancellationReasonHash");
  }
  if (request.status === "completed") {
    requirePhilNonZeroBytes32(request.completionHash ?? "0x", "completionHash");
  }
  return request;
}

function validatePendingRecoveryRequestForOperation(input: {
  request: PhilRecoveryRequestV1;
  bundle: PhilIdentityDataRecoveryBundleV1;
  operation: PhilRecoveryOperationV1;
  completedAt: string | number | bigint;
}): { request: PhilRecoveryRequestV1; completedAt: PhilUInt64String } {
  const request = validateRecoveryRequest(input.request);
  if (request.status !== "pending_delay") {
    fail("PHIL_RECOVERY_REQUEST_NOT_PENDING", "recovery request is not pending");
  }
  if (request.operation !== input.operation) {
    fail("PHIL_RECOVERY_REQUEST_OPERATION_MISMATCH", "recovery request binds another operation");
  }
  const completedAt = normalizePositiveUInt64(input.completedAt, "completedAt");
  if (BigInt(completedAt) < BigInt(request.notBefore)) {
    fail("PHIL_RECOVERY_DELAY_ACTIVE", "recovery delay has not elapsed");
  }
  if (BigInt(completedAt) > BigInt(request.expiresAt)) {
    fail("PHIL_RECOVERY_REQUEST_EXPIRED", "recovery request has expired");
  }
  if (hashJson(input.bundle) !== request.bundleHash) {
    fail("PHIL_RECOVERY_REQUEST_BUNDLE_MISMATCH", "recovery request binds a different bundle");
  }
  return { request, completedAt };
}

export function cancelPhilRecoveryRequestV1(input: {
  request: PhilRecoveryRequestV1;
  cancellationReasonHash: BytesLike;
}): PhilRecoveryRequestV1 {
  const request = validateRecoveryRequest(input.request);
  if (request.status !== "pending_delay") {
    fail("PHIL_RECOVERY_REQUEST_NOT_PENDING", "only a pending recovery request can be cancelled");
  }
  return Object.freeze({
    ...request,
    status: "cancelled",
    cancellationReasonHash: requirePhilNonZeroBytes32(
      input.cancellationReasonHash,
      "cancellationReasonHash"
    )
  });
}

function nextAuditState(input: {
  previous: PhilAuditContinuityStateV1;
  requestId: Hex;
  recoveryEpoch: PhilUInt64String;
}): { state: PhilAuditContinuityStateV1; eventHash: Hex } {
  const eventHash = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint64"],
      [
        PHIL_RECOVERY_COMPLETION_V1_HASH,
        input.previous.auditHeadHash,
        input.requestId,
        BigInt(input.recoveryEpoch),
        BigInt(input.previous.eventCount) + 1n
      ]
    )
  ) as Hex;
  return {
    eventHash,
    state: Object.freeze({
      eventCount: incrementUInt64(input.previous.eventCount, "audit event count"),
      auditHeadHash: eventHash
    })
  };
}

export function completePhilIdentityDataRecoveryV1(input: {
  request: PhilRecoveryRequestV1;
  bundle: PhilIdentityDataRecoveryBundleV1;
  shares: readonly PhilRecoveryShareV1[];
  completedAt: string | number | bigint;
  antiRollbackFloor?: PhilRecoveryAntiRollbackFloorV1;
}): PhilRecoveryCompletionV1 {
  const validated = validatePendingRecoveryRequestForOperation({
    request: input.request,
    bundle: input.bundle,
    operation: "identity_data_recovery",
    completedAt: input.completedAt
  });
  const validatedRequest = validated.request;
  const completedAt = validated.completedAt;
  const recoveredPackage = restorePhilIdentityDataRecoveryBundleV1({
    bundle: input.bundle,
    shares: input.shares,
    antiRollbackFloor: input.antiRollbackFloor
  });
  const nextRecoveryEpoch = incrementUInt64(recoveredPackage.recoveryEpoch, "recoveryEpoch");
  const nextDeviceEpoch = incrementUInt64(recoveredPackage.deviceEpoch, "deviceEpoch");
  const nextCapabilityEpoch = incrementUInt64(recoveredPackage.capabilityEpoch, "capabilityEpoch");
  const audit = nextAuditState({
    previous: recoveredPackage.auditContinuityState,
    requestId: validatedRequest.requestId,
    recoveryEpoch: nextRecoveryEpoch
  });
  const nextPackage = createPhilIdentityContinuityPackageV1({
    ...recoveredPackage,
    deviceEpoch: nextDeviceEpoch,
    recoveryEpoch: nextRecoveryEpoch,
    capabilityEpoch: nextCapabilityEpoch,
    accountBindings: recoveredPackage.accountBindings.map((record) => ({
      ...record,
      status: "pending_reconciliation" as const
    })),
    credentialRegistry: recoveredPackage.credentialRegistry.map((record) => ({
      ...record,
      deviceEpoch: nextDeviceEpoch,
      status: "revoked" as const
    })),
    capabilityRevocationState: {
      ...recoveredPackage.capabilityRevocationState,
      capabilityEpoch: nextCapabilityEpoch,
      revocationRoot: keccak256(
        abiCoder.encode(
          ["bytes32", "bytes32", "uint64"],
          [
            PHIL_RECOVERY_COMPLETION_V1_HASH,
            recoveredPackage.capabilityRevocationState.revocationRoot,
            BigInt(nextCapabilityEpoch)
          ]
        )
      ) as Hex
    },
    auditContinuityState: audit.state
  });
  const next = createPhilIdentityDataRecoveryBundleV1({
    continuityPackage: nextPackage,
    packageCounter: 1,
    createdAt: completedAt
  });
  const completionHash = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
      [
        PHIL_RECOVERY_COMPLETION_V1_HASH,
        validatedRequest.requestId,
        input.bundle.envelope.recoverySetId,
        next.bundle.envelope.recoverySetId,
        BigInt(completedAt)
      ]
    )
  ) as Hex;
  const request = Object.freeze({
    ...validatedRequest,
    status: "completed" as const,
    completionHash
  });
  return Object.freeze({
    request,
    recoveredPackage,
    nextPackage,
    nextBundle: next.bundle,
    nextShares: next.shares,
    auditEventHash: audit.eventHash
  });
}

export function replacePhilIdentityDataRecoverySetV1(input: {
  request: PhilRecoveryRequestV1;
  bundle: PhilIdentityDataRecoveryBundleV1;
  shares: readonly PhilRecoveryShareV1[];
  replacedAt: string | number | bigint;
  antiRollbackFloor?: PhilRecoveryAntiRollbackFloorV1;
}): PhilRecoverySetReplacementV1 {
  const validated = validatePendingRecoveryRequestForOperation({
    request: input.request,
    bundle: input.bundle,
    operation: "recovery_set_replacement",
    completedAt: input.replacedAt
  });
  const restored = restorePhilIdentityDataRecoveryBundleV1({
    bundle: input.bundle,
    shares: input.shares,
    antiRollbackFloor: input.antiRollbackFloor
  });
  const nextRecoveryEpoch = incrementUInt64(restored.recoveryEpoch, "recoveryEpoch");
  const replacementAuditHash = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64"],
      [
        PHIL_RECOVERY_SET_REPLACEMENT_V1_HASH,
        restored.auditContinuityState.auditHeadHash,
        validated.request.requestId,
        BigInt(nextRecoveryEpoch)
      ]
    )
  ) as Hex;
  const nextPackage = createPhilIdentityContinuityPackageV1({
    ...restored,
    recoveryEpoch: nextRecoveryEpoch,
    auditContinuityState: {
      eventCount: incrementUInt64(restored.auditContinuityState.eventCount, "eventCount"),
      auditHeadHash: replacementAuditHash
    }
  });
  const next = createPhilIdentityDataRecoveryBundleV1({
    continuityPackage: nextPackage,
    packageCounter: 1,
    createdAt: validated.completedAt
  });
  const completionHash = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
      [
        PHIL_RECOVERY_SET_REPLACEMENT_V1_HASH,
        validated.request.requestId,
        input.bundle.envelope.recoverySetId,
        next.bundle.envelope.recoverySetId,
        BigInt(validated.completedAt)
      ]
    )
  ) as Hex;
  return Object.freeze({
    request: Object.freeze({
      ...validated.request,
      status: "completed" as const,
      completionHash
    }),
    nextBundle: next.bundle,
    nextShares: next.shares,
    replacementAuditHash
  });
}
