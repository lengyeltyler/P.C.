import {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_CRYPTO_SCHEME_REGISTRY_V1_LABEL =
  "PHIL_CRYPTO_SCHEME_REGISTRY_V1" as const;
export const PHIL_CRYPTO_SCHEME_RECORD_V1_LABEL =
  "PHIL_CRYPTO_SCHEME_RECORD_V1" as const;
export const PHIL_NETWORK_CRYPTO_CAPABILITY_V1_LABEL =
  "PHIL_NETWORK_CRYPTO_CAPABILITY_V1" as const;
export const PHIL_CRYPTO_POLICY_BUNDLE_V1_LABEL =
  "PHIL_CRYPTO_POLICY_BUNDLE_V1" as const;
export const PHIL_CRYPTO_MIGRATION_CEREMONY_V1_LABEL =
  "PHIL_CRYPTO_MIGRATION_CEREMONY_V1" as const;
export const PHIL_CRYPTO_SCHEME_SET_V1_LABEL =
  "PHIL_CRYPTO_SCHEME_SET_V1" as const;
export const PHIL_CRYPTO_TRUSTED_STATE_V1_LABEL =
  "PHIL_CRYPTO_TRUSTED_STATE_V1" as const;

export const PHIL_CRYPTO_SCHEME_REGISTRY_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_SCHEME_REGISTRY_V1_LABEL)
) as Hex;
export const PHIL_CRYPTO_SCHEME_RECORD_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_SCHEME_RECORD_V1_LABEL)
) as Hex;
export const PHIL_NETWORK_CRYPTO_CAPABILITY_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_NETWORK_CRYPTO_CAPABILITY_V1_LABEL)
) as Hex;
export const PHIL_CRYPTO_POLICY_BUNDLE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_POLICY_BUNDLE_V1_LABEL)
) as Hex;
export const PHIL_CRYPTO_MIGRATION_CEREMONY_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_MIGRATION_CEREMONY_V1_LABEL)
) as Hex;
export const PHIL_CRYPTO_SCHEME_SET_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_SCHEME_SET_V1_LABEL)
) as Hex;
export const PHIL_CRYPTO_TRUSTED_STATE_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_CRYPTO_TRUSTED_STATE_V1_LABEL)
) as Hex;

export const PHIL_CRYPTO_SCHEME_KIND_V1 = Object.freeze({
  SIGNATURE: 1,
  KEY_ESTABLISHMENT: 2,
  HASH: 3,
  PROOF: 4,
  VERIFIER: 5,
  SYMMETRIC: 6,
  KDF: 7,
  RECOVERY_PROTECTION: 8
} as const);

export const PHIL_QUANTUM_POSTURE_V1 = Object.freeze({
  QUANTUM_VULNERABLE: 1,
  QUANTUM_RESISTANT: 2,
  HYBRID: 3,
  UNASSESSED: 4
} as const);

export const PHIL_SCHEME_LIFECYCLE_V1 = Object.freeze({
  ACTIVE_REFERENCE: 1,
  SPECIFIED_CANDIDATE: 2,
  DEPRECATED: 3,
  RETIRED: 4,
  FORBIDDEN: 5
} as const);

export const PHIL_SCHEME_EVIDENCE_LEVEL_V1 = Object.freeze({
  SPECIFIED_ONLY: 1,
  IMPLEMENTED_LOCAL: 2,
  PLATFORM_DOCUMENTED: 3,
  NETWORK_ENFORCED: 4,
  INDEPENDENTLY_REVIEWED: 5
} as const);

export const PHIL_CRYPTO_SECURITY_MODE_V1 = Object.freeze({
  CLASSICAL_ONLY: 1,
  HYBRID_AND: 2,
  POST_QUANTUM_ONLY: 3
} as const);

export const PHIL_NETWORK_ENFORCEMENT_V1 = Object.freeze({
  LOCAL_ONLY: 1,
  CONTRACT_CANDIDATE: 2,
  NETWORK_ENFORCED: 3,
  UNSUPPORTED: 4
} as const);

export const PHIL_MIGRATION_CEREMONY_KIND_V1 = Object.freeze({
  ENROLL_HYBRID: 1,
  ROTATE_WITHIN_MODE: 2,
  RETIRE_CLASSICAL: 3,
  EMERGENCY_MIGRATE_AND_FREEZE: 4
} as const);

type ValueOf<T> = T[keyof T];

export type PhilCryptoSchemeKindV1 = ValueOf<typeof PHIL_CRYPTO_SCHEME_KIND_V1>;
export type PhilQuantumPostureV1 = ValueOf<typeof PHIL_QUANTUM_POSTURE_V1>;
export type PhilSchemeLifecycleV1 = ValueOf<typeof PHIL_SCHEME_LIFECYCLE_V1>;
export type PhilSchemeEvidenceLevelV1 = ValueOf<typeof PHIL_SCHEME_EVIDENCE_LEVEL_V1>;
export type PhilCryptoSecurityModeV1 = ValueOf<typeof PHIL_CRYPTO_SECURITY_MODE_V1>;
export type PhilNetworkEnforcementV1 = ValueOf<typeof PHIL_NETWORK_ENFORCEMENT_V1>;
export type PhilMigrationCeremonyKindV1 = ValueOf<typeof PHIL_MIGRATION_CEREMONY_KIND_V1>;

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const UINT64_MAX = (1n << 64n) - 1n;

function id(label: string): Hex {
  return keccak256(toUtf8Bytes(label)) as Hex;
}

export const PHIL_CRYPTO_SCHEME_LABELS_V1 = Object.freeze({
  P256_SHA256_SIGNATURE: "phil-signature-p256-sha256-v1",
  SECP256K1_KECCAK256_SIGNATURE: "phil-signature-secp256k1-keccak256-v1",
  ML_DSA_65_SIGNATURE: "nist-fips-204-ml-dsa-65",
  SLH_DSA_SHA2_128S_SIGNATURE: "nist-fips-205-slh-dsa-sha2-128s",
  P256_ECIES_X963_SHA256_AESGCM: "phil-key-wrap-p256-ecies-cofactor-x963-sha256-aesgcm-v1",
  ML_KEM_768: "nist-fips-203-ml-kem-768",
  ML_KEM_1024: "nist-fips-203-ml-kem-1024",
  SHA256: "sha-256",
  KECCAK256: "keccak-256",
  AES256_GCM: "aes-256-gcm",
  HKDF_SHA256: "hkdf-sha256",
  PAIRWISE_HKDF_AES256GCM_2OF3_RECOVERY: "phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1",
  NOIR_ULTRAHONK_KECCAK_STEP3: "phil-proof-noir-ultrahonk-keccak-step3-v1",
  TRANSPARENT_HASH_STARK_RESERVED: "phil-proof-transparent-hash-stark-reserved-v1",
  STWO_EXPERIMENTAL_QUARANTINED: "phil-proof-stwo-experimental-quarantined-v1",
  STEP3_GARAGA_VERIFIER: "phil-verifier-step3-garaga-1.0.1-v1",
  TRANSPARENT_STARK_VERIFIER_RESERVED: "phil-verifier-transparent-stark-reserved-v1"
} as const);

export const PHIL_CRYPTO_SCHEME_IDS_V1 = Object.freeze(
  Object.fromEntries(
    Object.entries(PHIL_CRYPTO_SCHEME_LABELS_V1).map(([name, label]) => [name, id(label)])
  ) as Record<keyof typeof PHIL_CRYPTO_SCHEME_LABELS_V1, Hex>
);

export class PhilPostQuantumMigrationV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilPostQuantumMigrationV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilPostQuantumMigrationV1Error(code, message);
}

function bytes32(value: BytesLike, label: string, allowZero = false): Hex {
  let normalized: Hex;
  try {
    normalized = hexlify(value).toLowerCase() as Hex;
  } catch {
    return fail("PHIL_PQ_INVALID_BYTES32", `${label} must be bytes32`);
  }
  if (getBytes(normalized).length !== 32) {
    fail("PHIL_PQ_INVALID_BYTES32", `${label} must be bytes32`);
  }
  if (!allowZero && normalized === ZERO_BYTES32) {
    fail("PHIL_PQ_ZERO_BYTES32", `${label} must be non-zero`);
  }
  return normalized;
}

function uint64(value: string | number | bigint, label: string, positive = true): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new Error("noncanonical");
    }
    parsed = BigInt(value);
  } catch {
    return fail("PHIL_PQ_INVALID_UINT64", `${label} must be a canonical uint64`);
  }
  if (parsed < 0n || parsed > UINT64_MAX || (positive && parsed === 0n)) {
    fail("PHIL_PQ_INVALID_UINT64", `${label} must be a ${positive ? "positive " : ""}uint64`);
  }
  return parsed.toString(10);
}

function knownEnum<T extends number>(value: number, allowed: readonly T[], label: string): T {
  if (!allowed.includes(value as T)) fail("PHIL_PQ_ENUM_UNSUPPORTED", `${label} is unsupported`);
  return value as T;
}

function canonicalBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") fail("PHIL_PQ_INVALID_BOOLEAN", `${label} must be boolean`);
  return value;
}

export interface PhilCryptoSchemeRecordV1 {
  readonly schemeId: Hex;
  readonly label: string;
  readonly kind: PhilCryptoSchemeKindV1;
  readonly quantumPosture: PhilQuantumPostureV1;
  readonly lifecycle: PhilSchemeLifecycleV1;
  readonly evidenceLevel: PhilSchemeEvidenceLevelV1;
  readonly standardReferenceHash: Hex;
  readonly implementationBindingHash: Hex;
  readonly compatibleProofSchemeIds: readonly Hex[];
  readonly introducedRegistryEpoch: string;
  readonly retiredRegistryEpoch: string;
}

function scheme(input: {
  label: string;
  kind: PhilCryptoSchemeKindV1;
  quantumPosture: PhilQuantumPostureV1;
  lifecycle: PhilSchemeLifecycleV1;
  evidenceLevel: PhilSchemeEvidenceLevelV1;
  standardReference: string;
  implementationBinding?: string;
  compatibleProofLabels?: readonly string[];
  introducedRegistryEpoch?: number;
  retiredRegistryEpoch?: number;
}): PhilCryptoSchemeRecordV1 {
  const lifecycle = input.lifecycle;
  const retired = input.retiredRegistryEpoch ?? 0;
  if ((lifecycle === PHIL_SCHEME_LIFECYCLE_V1.RETIRED
      || lifecycle === PHIL_SCHEME_LIFECYCLE_V1.FORBIDDEN) !== (retired > 0)) {
    fail("PHIL_PQ_RETIREMENT_STATE_INVALID", "retired/forbidden records require a retirement epoch only");
  }
  const compatibleProofSchemeIds = Object.freeze(
    [...(input.compatibleProofLabels ?? [])].map(id).sort()
  );
  if ((input.kind === PHIL_CRYPTO_SCHEME_KIND_V1.VERIFIER) !== (compatibleProofSchemeIds.length > 0)) {
    fail("PHIL_PQ_VERIFIER_COMPATIBILITY_INVALID", "only verifier records require compatible proof IDs");
  }
  return Object.freeze({
    schemeId: id(input.label),
    label: input.label,
    kind: input.kind,
    quantumPosture: input.quantumPosture,
    lifecycle,
    evidenceLevel: input.evidenceLevel,
    standardReferenceHash: id(input.standardReference),
    implementationBindingHash: input.implementationBinding
      ? id(input.implementationBinding)
      : ZERO_BYTES32,
    compatibleProofSchemeIds,
    introducedRegistryEpoch: uint64(input.introducedRegistryEpoch ?? 1, "introducedRegistryEpoch"),
    retiredRegistryEpoch: uint64(retired, "retiredRegistryEpoch", false)
  });
}

const K = PHIL_CRYPTO_SCHEME_KIND_V1;
const Q = PHIL_QUANTUM_POSTURE_V1;
const L = PHIL_SCHEME_LIFECYCLE_V1;
const E = PHIL_SCHEME_EVIDENCE_LEVEL_V1;

export const PHIL_CRYPTO_SCHEME_REGISTRY_V1: readonly PhilCryptoSchemeRecordV1[] = Object.freeze([
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.P256_SHA256_SIGNATURE, kind: K.SIGNATURE, quantumPosture: Q.QUANTUM_VULNERABLE, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "nist-fips-186-5-p256-ecdsa-sha256", implementationBinding: "git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blob-78391d7e93bda3ab390134ec4eae6f380833b8cc" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.SECP256K1_KECCAK256_SIGNATURE, kind: K.SIGNATURE, quantumPosture: Q.QUANTUM_VULNERABLE, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.IMPLEMENTED_LOCAL, standardReference: "secg-sec1-secp256k1-ethereum-keccak256", implementationBinding: "git-blob-6da1f68e5a039c99245517fa647df0ac39a81c85:apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts:computePhilCoreV2LocalRole2CeremonyProofDigest+recoverCanonicalSecp256k1Signer:sha256-package-lock-030f8a95dc90b91d939da1c8d7735553320b2b3c3f0a4e0f0fac54c8114dc3ec:ethers-6.17.0" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.ML_DSA_65_SIGNATURE, kind: K.SIGNATURE, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.PLATFORM_DOCUMENTED, standardReference: "nist-fips-204-2024-ml-dsa-65", implementationBinding: "apple-cryptokit-ios-26-secureenclave-mldsa65-privatekey-documented-not-phil-verified" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.SLH_DSA_SHA2_128S_SIGNATURE, kind: K.SIGNATURE, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.SPECIFIED_ONLY, standardReference: "nist-fips-205-2024-slh-dsa-sha2-128s" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.P256_ECIES_X963_SHA256_AESGCM, kind: K.KEY_ESTABLISHMENT, quantumPosture: Q.QUANTUM_VULNERABLE, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "apple-seckeyalgorithm-ecies-encryption-cofactor-x963-sha256-aesgcm", implementationBinding: "git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blob-78391d7e93bda3ab390134ec4eae6f380833b8cc:SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.ML_KEM_768, kind: K.KEY_ESTABLISHMENT, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.PLATFORM_DOCUMENTED, standardReference: "nist-fips-203-2024-ml-kem-768", implementationBinding: "apple-cryptokit-secureenclave-mlkem768-documented-not-phil-verified" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.ML_KEM_1024, kind: K.KEY_ESTABLISHMENT, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.PLATFORM_DOCUMENTED, standardReference: "nist-fips-203-2024-ml-kem-1024", implementationBinding: "apple-cryptokit-secureenclave-mlkem1024-documented-not-phil-verified" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.SHA256, kind: K.HASH, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.IMPLEMENTED_LOCAL, standardReference: "nist-fips-180-4-sha256", implementationBinding: "git-blob-e59264255b0abdc51f488f5565e15dd6fd776088:apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts:ethers-sha256:sha256-package-lock-030f8a95dc90b91d939da1c8d7735553320b2b3c3f0a4e0f0fac54c8114dc3ec:ethers-6.17.0" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.KECCAK256, kind: K.HASH, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "keccak-256-ethereum-legacy-padding", implementationBinding: "sha256-package-lock-030f8a95dc90b91d939da1c8d7735553320b2b3c3f0a4e0f0fac54c8114dc3ec:ethers-6.17.0" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.AES256_GCM, kind: K.SYMMETRIC, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "nist-sp800-38d-aes-256-gcm", implementationBinding: "git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blobs-d3dee5d14dcdc82bda0ef109eb37f9f30d0b6bb8+f0d9cd160ac0c7a2147b81362eb6f4d0572db58e" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.HKDF_SHA256, kind: K.KDF, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "rfc5869-hkdf-sha256", implementationBinding: "git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blob-f0d9cd160ac0c7a2147b81362eb6f4d0572db58e" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.PAIRWISE_HKDF_AES256GCM_2OF3_RECOVERY, kind: K.RECOVERY_PROTECTION, quantumPosture: Q.QUANTUM_RESISTANT, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.IMPLEMENTED_LOCAL, standardReference: "phil-v1-step2-exact-2of3-recovery-composition-not-externally-audited", implementationBinding: "git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blob-f0d9cd160ac0c7a2147b81362eb6f4d0572db58e" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.NOIR_ULTRAHONK_KECCAK_STEP3, kind: K.PROOF, quantumPosture: Q.QUANTUM_VULNERABLE, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "noir-ultrahonk-keccak-barretenberg-beta-reference", implementationBinding: "git-commit-11234ea623a6b8883eed0036f3d95174cef90627:tree-9ff5177d11525df640cf103fdf982d73fb47a4f1" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.TRANSPARENT_HASH_STARK_RESERVED, kind: K.PROOF, quantumPosture: Q.UNASSESSED, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.SPECIFIED_ONLY, standardReference: "transparent-hash-stark-instantiation-required" }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.STWO_EXPERIMENTAL_QUARANTINED, kind: K.PROOF, quantumPosture: Q.UNASSESSED, lifecycle: L.FORBIDDEN, evidenceLevel: E.IMPLEMENTED_LOCAL, standardReference: "phil-stwo-secret-bearing-artifact-quarantined", implementationBinding: "git-commit-fc6514394f5f1ff540c10ac87704a3c24e5f3a4b:stwo-forbidden-registry-record", retiredRegistryEpoch: 1 }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.STEP3_GARAGA_VERIFIER, kind: K.VERIFIER, quantumPosture: Q.QUANTUM_VULNERABLE, lifecycle: L.ACTIVE_REFERENCE, evidenceLevel: E.INDEPENDENTLY_REVIEWED, standardReference: "garaga-1.0.1-aa91b650-step3", implementationBinding: "git-commit-11234ea623a6b8883eed0036f3d95174cef90627:starknet-class-0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd", compatibleProofLabels: [PHIL_CRYPTO_SCHEME_LABELS_V1.NOIR_ULTRAHONK_KECCAK_STEP3] }),
  scheme({ label: PHIL_CRYPTO_SCHEME_LABELS_V1.TRANSPARENT_STARK_VERIFIER_RESERVED, kind: K.VERIFIER, quantumPosture: Q.UNASSESSED, lifecycle: L.SPECIFIED_CANDIDATE, evidenceLevel: E.SPECIFIED_ONLY, standardReference: "transparent-stark-verifier-artifact-required", compatibleProofLabels: [PHIL_CRYPTO_SCHEME_LABELS_V1.TRANSPARENT_HASH_STARK_RESERVED] })
]);

const SCHEMES_BY_ID = new Map(PHIL_CRYPTO_SCHEME_REGISTRY_V1.map((record) => [record.schemeId, record]));

export function validatePhilCryptoSchemeRegistryV1(): Readonly<{
  registryEpoch: "1";
  schemeCount: number;
  registryHash: Hex;
}> {
  const ids = new Set<string>();
  const labels = new Set<string>();
  for (const record of PHIL_CRYPTO_SCHEME_REGISTRY_V1) {
    if (ids.has(record.schemeId) || labels.has(record.label)) {
      fail("PHIL_PQ_REGISTRY_DUPLICATE", "scheme IDs and labels must be unique");
    }
    ids.add(record.schemeId);
    labels.add(record.label);
    if (record.schemeId !== id(record.label)) {
      fail("PHIL_PQ_SCHEME_ID_MISMATCH", "schemeId must be the label hash");
    }
    const retired = BigInt(record.retiredRegistryEpoch) > 0n;
    const inactive = record.lifecycle === L.RETIRED || record.lifecycle === L.FORBIDDEN;
    if (retired !== inactive) {
      fail("PHIL_PQ_RETIREMENT_STATE_INVALID", "retirement epoch and lifecycle disagree");
    }
    if (record.kind === K.VERIFIER) {
      for (const proofId of record.compatibleProofSchemeIds) {
        const proof = PHIL_CRYPTO_SCHEME_REGISTRY_V1.find((candidate) => candidate.schemeId === proofId);
        if (!proof || proof.kind !== K.PROOF) {
          fail("PHIL_PQ_VERIFIER_COMPATIBILITY_INVALID", "verifier compatibility must reference a registered proof");
        }
      }
    }
  }
  if (SCHEMES_BY_ID.size !== PHIL_CRYPTO_SCHEME_REGISTRY_V1.length) {
    fail("PHIL_PQ_REGISTRY_DUPLICATE", "scheme registry map lost a duplicate ID");
  }
  return Object.freeze({
    registryEpoch: "1",
    schemeCount: PHIL_CRYPTO_SCHEME_REGISTRY_V1.length,
    registryHash: derivePhilCryptoSchemeRegistryHashV1(1)
  });
}

export function getPhilCryptoSchemeRecordV1(schemeId: BytesLike): PhilCryptoSchemeRecordV1 {
  const normalized = bytes32(schemeId, "schemeId");
  return SCHEMES_BY_ID.get(normalized)
    ?? fail("PHIL_PQ_SCHEME_UNKNOWN", "schemeId is not in the frozen registry");
}

export function derivePhilCryptoSchemeRecordHashV1(record: PhilCryptoSchemeRecordV1): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "uint8", "uint8", "uint8", "uint8", "bytes32", "bytes32", "bytes32[]", "uint64", "uint64"],
    [
      PHIL_CRYPTO_SCHEME_RECORD_V1_HASH,
      record.schemeId,
      record.kind,
      record.quantumPosture,
      record.lifecycle,
      record.evidenceLevel,
      record.standardReferenceHash,
      record.implementationBindingHash,
      record.compatibleProofSchemeIds,
      BigInt(record.introducedRegistryEpoch),
      BigInt(record.retiredRegistryEpoch)
    ]
  )) as Hex;
}

export function derivePhilCryptoSchemeRegistryHashV1(
  registryEpoch: string | number | bigint = 1
): Hex {
  const recordHashes = [...PHIL_CRYPTO_SCHEME_REGISTRY_V1]
    .sort((left, right) => left.schemeId.localeCompare(right.schemeId))
    .map(derivePhilCryptoSchemeRecordHashV1);
  return keccak256(abiCoder.encode(
    ["bytes32", "uint64", "bytes32[]"],
    [PHIL_CRYPTO_SCHEME_REGISTRY_V1_HASH, BigInt(uint64(registryEpoch, "registryEpoch")), recordHashes]
  )) as Hex;
}

function normalizedSchemeIds(
  values: readonly BytesLike[],
  kind: PhilCryptoSchemeKindV1,
  label: string,
  allowEmpty = false
): readonly Hex[] {
  if (!allowEmpty && values.length === 0) fail("PHIL_PQ_SCHEME_SET_EMPTY", `${label} must not be empty`);
  const normalized = values.map((value) => bytes32(value, label));
  if (new Set(normalized).size !== normalized.length) {
    fail("PHIL_PQ_SCHEME_SET_DUPLICATE", `${label} contains a duplicate scheme`);
  }
  for (const schemeId of normalized) {
    const record = getPhilCryptoSchemeRecordV1(schemeId);
    if (record.kind !== kind) fail("PHIL_PQ_SCHEME_KIND_MISMATCH", `${label} has a wrong-kind scheme`);
    if (record.lifecycle === L.FORBIDDEN || record.lifecycle === L.RETIRED) {
      fail("PHIL_PQ_SCHEME_NOT_ADMISSIBLE", `${label} contains a forbidden or retired scheme`);
    }
  }
  return Object.freeze([...normalized].sort());
}

function deriveSchemeSetHash(kind: PhilCryptoSchemeKindV1, ids: readonly Hex[]): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "bytes32[]"],
    [PHIL_CRYPTO_SCHEME_SET_V1_HASH, kind, ids]
  )) as Hex;
}

function postures(ids: readonly Hex[]): ReadonlySet<PhilQuantumPostureV1> {
  return new Set(ids.map((schemeId) => getPhilCryptoSchemeRecordV1(schemeId).quantumPosture));
}

function requireHybridSet(ids: readonly Hex[], label: string): void {
  const values = postures(ids);
  if (!values.has(Q.QUANTUM_VULNERABLE)
      || !values.has(Q.QUANTUM_RESISTANT)) {
    fail("PHIL_PQ_HYBRID_COMPONENTS_REQUIRED", `${label} requires classical and PQ components`);
  }
}

function requirePostQuantumSet(ids: readonly Hex[], label: string): void {
  if (ids.some((schemeId) => getPhilCryptoSchemeRecordV1(schemeId).quantumPosture !== Q.QUANTUM_RESISTANT)) {
    fail("PHIL_PQ_CLASSICAL_COMPONENT_FORBIDDEN", `${label} must contain only PQ schemes`);
  }
}

function requireActiveSet(ids: readonly Hex[], label: string): void {
  if (ids.some((schemeId) => getPhilCryptoSchemeRecordV1(schemeId).lifecycle !== L.ACTIVE_REFERENCE)) {
    fail("PHIL_PQ_CANDIDATE_NOT_ACTIVATABLE", `${label} contains a scheme that is not active`);
  }
}

function requireCompatibleProofVerifierSets(
  proofSchemeIds: readonly Hex[],
  verifierSchemeIds: readonly Hex[]
): void {
  for (const proofSchemeId of proofSchemeIds) {
    if (!verifierSchemeIds.some((verifierSchemeId) =>
      getPhilCryptoSchemeRecordV1(verifierSchemeId).compatibleProofSchemeIds.includes(proofSchemeId))) {
      fail("PHIL_PQ_PROOF_VERIFIER_INCOMPATIBLE", "a proof has no compatible admitted verifier");
    }
  }
  for (const verifierSchemeId of verifierSchemeIds) {
    const verifier = getPhilCryptoSchemeRecordV1(verifierSchemeId);
    if (!proofSchemeIds.some((proofSchemeId) => verifier.compatibleProofSchemeIds.includes(proofSchemeId))) {
      fail("PHIL_PQ_PROOF_VERIFIER_INCOMPATIBLE", "a verifier has no compatible admitted proof");
    }
  }
}

export interface PhilNetworkCryptoCapabilityV1 {
  readonly formatVersionHash: Hex;
  readonly networkIdHash: Hex;
  readonly registryEpoch: string;
  readonly registryHash: Hex;
  readonly capabilityEpoch: string;
  readonly accountModelHash: Hex;
  readonly enforcement: PhilNetworkEnforcementV1;
  readonly maximumSecurityMode: PhilCryptoSecurityModeV1;
  readonly signatureSchemeIds: readonly Hex[];
  readonly proofSchemeIds: readonly Hex[];
  readonly verifierSchemeIds: readonly Hex[];
  readonly authorizationPathAvailable: boolean;
  readonly capabilityAuthorityHash: Hex;
  readonly implementationBindingHash: Hex;
  readonly evidenceHash: Hex;
  readonly capabilityHash: Hex;
}

export function createPhilNetworkCryptoCapabilityV1(input: {
  readonly networkIdHash: BytesLike;
  readonly registryEpoch: string | number | bigint;
  readonly registryHash: BytesLike;
  readonly capabilityEpoch: string | number | bigint;
  readonly accountModelHash: BytesLike;
  readonly enforcement: number;
  readonly maximumSecurityMode: number;
  readonly signatureSchemeIds: readonly BytesLike[];
  readonly proofSchemeIds: readonly BytesLike[];
  readonly verifierSchemeIds: readonly BytesLike[];
  readonly authorizationPathAvailable: boolean;
  readonly capabilityAuthorityHash: BytesLike;
  readonly implementationBindingHash: BytesLike;
  readonly evidenceHash: BytesLike;
}): PhilNetworkCryptoCapabilityV1 {
  const signatureSchemeIds = normalizedSchemeIds(input.signatureSchemeIds, K.SIGNATURE, "signatureSchemeIds");
  const proofSchemeIds = normalizedSchemeIds(input.proofSchemeIds, K.PROOF, "proofSchemeIds", true);
  const verifierSchemeIds = normalizedSchemeIds(input.verifierSchemeIds, K.VERIFIER, "verifierSchemeIds", true);
  if ((proofSchemeIds.length === 0) !== (verifierSchemeIds.length === 0)) {
    fail("PHIL_PQ_PROOF_VERIFIER_INCOMPATIBLE", "proof and verifier sets must both be empty or compatible");
  }
  requireCompatibleProofVerifierSets(proofSchemeIds, verifierSchemeIds);
  const registryEpoch = uint64(input.registryEpoch, "registryEpoch");
  const registryHash = bytes32(input.registryHash, "registryHash");
  const currentRegistry = validatePhilCryptoSchemeRegistryV1();
  if (registryEpoch !== currentRegistry.registryEpoch || registryHash !== currentRegistry.registryHash) {
    fail("PHIL_PQ_REGISTRY_TRUST_MISMATCH", "network capability must bind the exact admitted registry");
  }
  const normalized = {
    formatVersionHash: PHIL_NETWORK_CRYPTO_CAPABILITY_V1_HASH,
    networkIdHash: bytes32(input.networkIdHash, "networkIdHash"),
    registryEpoch,
    registryHash,
    capabilityEpoch: uint64(input.capabilityEpoch, "capabilityEpoch"),
    accountModelHash: bytes32(input.accountModelHash, "accountModelHash"),
    enforcement: knownEnum(input.enforcement, Object.values(PHIL_NETWORK_ENFORCEMENT_V1), "enforcement"),
    maximumSecurityMode: knownEnum(input.maximumSecurityMode, Object.values(PHIL_CRYPTO_SECURITY_MODE_V1), "maximumSecurityMode"),
    signatureSchemeIds,
    proofSchemeIds,
    verifierSchemeIds,
    authorizationPathAvailable: canonicalBoolean(input.authorizationPathAvailable, "authorizationPathAvailable"),
    capabilityAuthorityHash: bytes32(input.capabilityAuthorityHash, "capabilityAuthorityHash"),
    implementationBindingHash: bytes32(input.implementationBindingHash, "implementationBindingHash"),
    evidenceHash: bytes32(input.evidenceHash, "evidenceHash")
  };
  if (normalized.maximumSecurityMode !== PHIL_CRYPTO_SECURITY_MODE_V1.CLASSICAL_ONLY
      && normalized.enforcement !== PHIL_NETWORK_ENFORCEMENT_V1.NETWORK_ENFORCED) {
    fail("PHIL_PQ_NETWORK_MODE_OVERCLAIM", "hybrid or PQ network mode requires network enforcement evidence");
  }
  if (normalized.authorizationPathAvailable
      && normalized.enforcement !== PHIL_NETWORK_ENFORCEMENT_V1.NETWORK_ENFORCED) {
    fail("PHIL_PQ_NETWORK_PATH_OVERCLAIM", "an available authorization path requires network enforcement evidence");
  }
  if (normalized.maximumSecurityMode === PHIL_CRYPTO_SECURITY_MODE_V1.HYBRID_AND) {
    requireActiveSet(signatureSchemeIds, "network signature schemes");
    requireActiveSet(proofSchemeIds, "network proof schemes");
    requireActiveSet(verifierSchemeIds, "network verifier schemes");
    requireHybridSet(signatureSchemeIds, "network signatures");
    if (postures(proofSchemeIds).has(Q.QUANTUM_RESISTANT) === false
        || postures(verifierSchemeIds).has(Q.QUANTUM_RESISTANT) === false) {
      fail("PHIL_PQ_NETWORK_COMPONENTS_INCOMPLETE", "hybrid network mode requires active PQ proof and verifier support");
    }
  }
  if (normalized.maximumSecurityMode === PHIL_CRYPTO_SECURITY_MODE_V1.POST_QUANTUM_ONLY) {
    requireActiveSet(signatureSchemeIds, "network signature schemes");
    requireActiveSet(proofSchemeIds, "network proof schemes");
    requireActiveSet(verifierSchemeIds, "network verifier schemes");
    requirePostQuantumSet(signatureSchemeIds, "network signatures");
    requirePostQuantumSet(proofSchemeIds, "network proofs");
    requirePostQuantumSet(verifierSchemeIds, "network verifiers");
  }
  const capabilityHash = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "uint64", "bytes32", "uint64", "bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
    [
      PHIL_NETWORK_CRYPTO_CAPABILITY_V1_HASH,
      normalized.networkIdHash,
      BigInt(normalized.registryEpoch),
      normalized.registryHash,
      BigInt(normalized.capabilityEpoch),
      normalized.accountModelHash,
      normalized.enforcement,
      normalized.maximumSecurityMode,
      deriveSchemeSetHash(K.SIGNATURE, signatureSchemeIds),
      deriveSchemeSetHash(K.PROOF, proofSchemeIds),
      deriveSchemeSetHash(K.VERIFIER, verifierSchemeIds),
      normalized.authorizationPathAvailable,
      normalized.capabilityAuthorityHash,
      normalized.implementationBindingHash,
      normalized.evidenceHash
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, capabilityHash });
}

export interface PhilCryptoTrustedStateV1 {
  readonly formatVersionHash: Hex;
  readonly registryEpoch: string;
  readonly registryHash: Hex;
  readonly networkIdHash: Hex;
  readonly capabilityAuthorityHash: Hex;
  readonly greatestAcceptedCapabilityEpoch: string;
  readonly expectedCapabilityHash: Hex;
  readonly greatestAcceptedPolicyEpoch: string;
  readonly expectedPolicyHash: Hex;
  readonly trustedStateHash: Hex;
}

export function createPhilCryptoTrustedStateV1(input: {
  readonly registryEpoch: string | number | bigint;
  readonly registryHash: BytesLike;
  readonly networkIdHash: BytesLike;
  readonly capabilityAuthorityHash: BytesLike;
  readonly greatestAcceptedCapabilityEpoch: string | number | bigint;
  readonly expectedCapabilityHash: BytesLike;
  readonly greatestAcceptedPolicyEpoch: string | number | bigint;
  readonly expectedPolicyHash: BytesLike;
}): PhilCryptoTrustedStateV1 {
  const normalized = {
    formatVersionHash: PHIL_CRYPTO_TRUSTED_STATE_V1_HASH,
    registryEpoch: uint64(input.registryEpoch, "registryEpoch"),
    registryHash: bytes32(input.registryHash, "registryHash"),
    networkIdHash: bytes32(input.networkIdHash, "networkIdHash"),
    capabilityAuthorityHash: bytes32(input.capabilityAuthorityHash, "capabilityAuthorityHash"),
    greatestAcceptedCapabilityEpoch: uint64(input.greatestAcceptedCapabilityEpoch, "greatestAcceptedCapabilityEpoch"),
    expectedCapabilityHash: bytes32(input.expectedCapabilityHash, "expectedCapabilityHash"),
    greatestAcceptedPolicyEpoch: uint64(input.greatestAcceptedPolicyEpoch, "greatestAcceptedPolicyEpoch"),
    expectedPolicyHash: bytes32(input.expectedPolicyHash, "expectedPolicyHash")
  };
  const trustedStateHash = keccak256(abiCoder.encode(
    ["bytes32", "uint64", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "uint64", "bytes32"],
    [
      PHIL_CRYPTO_TRUSTED_STATE_V1_HASH,
      BigInt(normalized.registryEpoch),
      normalized.registryHash,
      normalized.networkIdHash,
      normalized.capabilityAuthorityHash,
      BigInt(normalized.greatestAcceptedCapabilityEpoch),
      normalized.expectedCapabilityHash,
      BigInt(normalized.greatestAcceptedPolicyEpoch),
      normalized.expectedPolicyHash
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, trustedStateHash });
}

export function validatePhilCryptoTrustedStateV1(
  trustedState: PhilCryptoTrustedStateV1
): PhilCryptoTrustedStateV1 {
  if (trustedState.formatVersionHash !== PHIL_CRYPTO_TRUSTED_STATE_V1_HASH) {
    fail("PHIL_PQ_TRUSTED_STATE_FORMAT_MISMATCH", "trusted state format is unsupported");
  }
  const rebuilt = createPhilCryptoTrustedStateV1(trustedState);
  if (rebuilt.trustedStateHash !== trustedState.trustedStateHash) {
    fail("PHIL_PQ_TRUSTED_STATE_HASH_MISMATCH", "trusted state hash is not canonical");
  }
  return rebuilt;
}

function canonicalizePhilNetworkCryptoCapabilityV1(
  record: PhilNetworkCryptoCapabilityV1
): PhilNetworkCryptoCapabilityV1 {
  if (record.formatVersionHash !== PHIL_NETWORK_CRYPTO_CAPABILITY_V1_HASH) {
    fail("PHIL_PQ_NETWORK_FORMAT_MISMATCH", "network capability format is unsupported");
  }
  const rebuilt = createPhilNetworkCryptoCapabilityV1({
    networkIdHash: record.networkIdHash,
    registryEpoch: record.registryEpoch,
    registryHash: record.registryHash,
    capabilityEpoch: record.capabilityEpoch,
    accountModelHash: record.accountModelHash,
    enforcement: record.enforcement,
    maximumSecurityMode: record.maximumSecurityMode,
    signatureSchemeIds: record.signatureSchemeIds,
    proofSchemeIds: record.proofSchemeIds,
    verifierSchemeIds: record.verifierSchemeIds,
    authorizationPathAvailable: record.authorizationPathAvailable,
    capabilityAuthorityHash: record.capabilityAuthorityHash,
    implementationBindingHash: record.implementationBindingHash,
    evidenceHash: record.evidenceHash
  });
  if (rebuilt.capabilityHash !== record.capabilityHash) {
    fail("PHIL_PQ_NETWORK_CAPABILITY_HASH_MISMATCH", "network capability hash is not canonical");
  }
  return rebuilt;
}

export function validatePhilNetworkCryptoCapabilityV1(
  record: PhilNetworkCryptoCapabilityV1,
  trustedState: PhilCryptoTrustedStateV1
): PhilNetworkCryptoCapabilityV1 {
  const rebuilt = canonicalizePhilNetworkCryptoCapabilityV1(record);
  const trusted = validatePhilCryptoTrustedStateV1(trustedState);
  if (trusted.registryEpoch !== rebuilt.registryEpoch
      || trusted.registryHash !== rebuilt.registryHash) {
    fail("PHIL_PQ_REGISTRY_TRUST_MISMATCH", "trusted state does not admit the capability registry");
  }
  if (trusted.networkIdHash !== rebuilt.networkIdHash
      || trusted.capabilityAuthorityHash !== rebuilt.capabilityAuthorityHash) {
    fail("PHIL_PQ_CAPABILITY_PROVENANCE_MISMATCH", "trusted network or capability authority does not match");
  }
  if (BigInt(rebuilt.capabilityEpoch) < BigInt(trusted.greatestAcceptedCapabilityEpoch)) {
    fail("PHIL_PQ_CAPABILITY_STALE", "capability epoch is below the trusted freshness floor");
  }
  if (rebuilt.capabilityHash !== trusted.expectedCapabilityHash) {
    fail("PHIL_PQ_CAPABILITY_UNTRUSTED", "capability hash is not the trusted current record");
  }
  return rebuilt;
}

export interface PhilCryptoPolicyBundleV1 {
  readonly formatVersionHash: Hex;
  readonly registryEpoch: string;
  readonly registryHash: Hex;
  readonly policyEpoch: string;
  readonly securityMode: PhilCryptoSecurityModeV1;
  readonly signatureCombiner: "all";
  readonly deviceSignatureSchemeIds: readonly Hex[];
  readonly validatorSignatureSchemeIds: readonly Hex[];
  readonly recoveryProtectionSchemeIds: readonly Hex[];
  readonly keyEstablishmentSchemeIds: readonly Hex[];
  readonly hashSchemeIds: readonly Hex[];
  readonly symmetricSchemeIds: readonly Hex[];
  readonly kdfSchemeIds: readonly Hex[];
  readonly proofSchemeId: Hex;
  readonly verifierSchemeId: Hex;
  readonly networkCapabilityHash: Hex;
  readonly recoveryIndependenceHash: Hex;
  readonly bundleHash: Hex;
}

export interface PhilCryptoPolicyBundleDraftV1 {
  readonly policyEpoch: string | number | bigint;
  readonly securityMode: number;
  readonly signatureCombiner: "all";
  readonly deviceSignatureSchemeIds: readonly BytesLike[];
  readonly validatorSignatureSchemeIds: readonly BytesLike[];
  readonly recoveryProtectionSchemeIds: readonly BytesLike[];
  readonly keyEstablishmentSchemeIds: readonly BytesLike[];
  readonly hashSchemeIds: readonly BytesLike[];
  readonly symmetricSchemeIds: readonly BytesLike[];
  readonly kdfSchemeIds: readonly BytesLike[];
  readonly proofSchemeId: BytesLike;
  readonly verifierSchemeId: BytesLike;
  readonly networkCapability: PhilNetworkCryptoCapabilityV1;
  readonly recoveryIndependenceHash: BytesLike;
}

export interface PhilCryptoPolicyBundleInputV1 extends PhilCryptoPolicyBundleDraftV1 {
  readonly trustedState: PhilCryptoTrustedStateV1;
}

function buildPhilCryptoPolicyBundleV1(
  input: PhilCryptoPolicyBundleDraftV1
): PhilCryptoPolicyBundleV1 {
  if (input.signatureCombiner !== "all") {
    fail("PHIL_PQ_SIGNATURE_OR_FORBIDDEN", "multi-scheme signatures require fail-closed AND semantics");
  }
  const securityMode = knownEnum(input.securityMode, Object.values(PHIL_CRYPTO_SECURITY_MODE_V1), "securityMode");
  const networkCapability = canonicalizePhilNetworkCryptoCapabilityV1(input.networkCapability);
  const device = normalizedSchemeIds(input.deviceSignatureSchemeIds, K.SIGNATURE, "deviceSignatureSchemeIds");
  const validator = normalizedSchemeIds(input.validatorSignatureSchemeIds, K.SIGNATURE, "validatorSignatureSchemeIds");
  const recovery = normalizedSchemeIds(input.recoveryProtectionSchemeIds, K.RECOVERY_PROTECTION, "recoveryProtectionSchemeIds");
  const kem = normalizedSchemeIds(input.keyEstablishmentSchemeIds, K.KEY_ESTABLISHMENT, "keyEstablishmentSchemeIds");
  const hashes = normalizedSchemeIds(input.hashSchemeIds, K.HASH, "hashSchemeIds");
  const symmetric = normalizedSchemeIds(input.symmetricSchemeIds, K.SYMMETRIC, "symmetricSchemeIds");
  const kdfs = normalizedSchemeIds(input.kdfSchemeIds, K.KDF, "kdfSchemeIds");
  const proofSchemeId = normalizedSchemeIds([input.proofSchemeId], K.PROOF, "proofSchemeId")[0]!;
  const verifierSchemeId = normalizedSchemeIds([input.verifierSchemeId], K.VERIFIER, "verifierSchemeId")[0]!;

  for (const [ids, label] of [
    [device, "device signatures"],
    [validator, "validator signatures"],
    [recovery, "recovery protection"],
    [kem, "key establishment"],
    [hashes, "hash schemes"],
    [symmetric, "symmetric schemes"],
    [kdfs, "KDF schemes"],
    [[proofSchemeId], "proof scheme"],
    [[verifierSchemeId], "verifier scheme"]
  ] as const) {
    requireActiveSet(ids, label);
  }
  const policyEpoch = uint64(input.policyEpoch, "policyEpoch");
  if (securityMode > networkCapability.maximumSecurityMode) {
    fail("PHIL_PQ_POLICY_EXCEEDS_NETWORK", "policy security mode exceeds the bound network capability");
  }
  const networkSignatures = new Set(networkCapability.signatureSchemeIds);
  for (const schemeId of [...device, ...validator]) {
    if (!networkSignatures.has(schemeId)) {
      fail("PHIL_PQ_NETWORK_SCHEME_UNSUPPORTED", "network does not admit a required authorization signature scheme");
    }
  }
  if (!networkCapability.proofSchemeIds.includes(proofSchemeId)
      || !networkCapability.verifierSchemeIds.includes(verifierSchemeId)) {
    fail("PHIL_PQ_NETWORK_SCHEME_UNSUPPORTED", "network does not admit the required proof and verifier");
  }
  const verifier = getPhilCryptoSchemeRecordV1(verifierSchemeId);
  if (!verifier.compatibleProofSchemeIds.includes(proofSchemeId)) {
    fail("PHIL_PQ_PROOF_VERIFIER_INCOMPATIBLE", "selected verifier is not bound to the selected proof");
  }

  if (securityMode === PHIL_CRYPTO_SECURITY_MODE_V1.HYBRID_AND) {
    requireHybridSet(device, "device signatures");
    requireHybridSet(validator, "validator signatures");
    requirePostQuantumSet(recovery, "recovery protection");
    requireHybridSet(kem, "key establishment");
    if (getPhilCryptoSchemeRecordV1(proofSchemeId).quantumPosture !== Q.QUANTUM_RESISTANT
        || getPhilCryptoSchemeRecordV1(verifierSchemeId).quantumPosture !== Q.QUANTUM_RESISTANT) {
      fail("PHIL_PQ_PROOF_VERIFIER_NOT_PQ", "hybrid mode requires an admitted PQ proof and verifier");
    }
  } else if (securityMode === PHIL_CRYPTO_SECURITY_MODE_V1.POST_QUANTUM_ONLY) {
    requirePostQuantumSet(device, "device signatures");
    requirePostQuantumSet(validator, "validator signatures");
    requirePostQuantumSet(recovery, "recovery protection");
    requirePostQuantumSet(kem, "key establishment");
    requirePostQuantumSet([proofSchemeId], "proof scheme");
    requirePostQuantumSet([verifierSchemeId], "verifier scheme");
  } else {
    for (const ids of [device, validator, kem]) {
      if (postures(ids).has(Q.QUANTUM_RESISTANT) || postures(ids).has(Q.HYBRID)) {
        fail("PHIL_PQ_CLASSICAL_MODE_MISMATCH", "classical-only mode cannot advertise PQ components");
      }
    }
  }

  const normalized = {
    formatVersionHash: PHIL_CRYPTO_POLICY_BUNDLE_V1_HASH,
    registryEpoch: networkCapability.registryEpoch,
    registryHash: networkCapability.registryHash,
    policyEpoch,
    securityMode,
    signatureCombiner: "all" as const,
    deviceSignatureSchemeIds: device,
    validatorSignatureSchemeIds: validator,
    recoveryProtectionSchemeIds: recovery,
    keyEstablishmentSchemeIds: kem,
    hashSchemeIds: hashes,
    symmetricSchemeIds: symmetric,
    kdfSchemeIds: kdfs,
    proofSchemeId,
    verifierSchemeId,
    networkCapabilityHash: networkCapability.capabilityHash,
    recoveryIndependenceHash: bytes32(input.recoveryIndependenceHash, "recoveryIndependenceHash")
  };
  const bundleHash = keccak256(abiCoder.encode(
    ["bytes32", "uint64", "bytes32", "uint64", "uint8", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHIL_CRYPTO_POLICY_BUNDLE_V1_HASH,
      BigInt(normalized.registryEpoch),
      normalized.registryHash,
      BigInt(normalized.policyEpoch),
      normalized.securityMode,
      id("all-signatures-required"),
      deriveSchemeSetHash(K.SIGNATURE, device),
      deriveSchemeSetHash(K.SIGNATURE, validator),
      deriveSchemeSetHash(K.RECOVERY_PROTECTION, recovery),
      deriveSchemeSetHash(K.KEY_ESTABLISHMENT, kem),
      deriveSchemeSetHash(K.HASH, hashes),
      deriveSchemeSetHash(K.SYMMETRIC, symmetric),
      deriveSchemeSetHash(K.KDF, kdfs),
      proofSchemeId,
      verifierSchemeId,
      keccak256(abiCoder.encode(["bytes32", "bytes32"], [normalized.networkCapabilityHash, normalized.recoveryIndependenceHash]))
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, bundleHash });
}

/**
 * Derives the candidate policy identity needed to initialize trusted state.
 * The result grants no authority until create/validate binds it to trusted state.
 */
export function deriveUntrustedPhilCryptoPolicyBundleHashV1(
  input: PhilCryptoPolicyBundleDraftV1
): Hex {
  return buildPhilCryptoPolicyBundleV1(input).bundleHash;
}

export function createPhilCryptoPolicyBundleV1(
  input: PhilCryptoPolicyBundleInputV1
): PhilCryptoPolicyBundleV1 {
  const trusted = validatePhilCryptoTrustedStateV1(input.trustedState);
  const networkCapability = validatePhilNetworkCryptoCapabilityV1(
    input.networkCapability,
    trusted
  );
  const bundle = buildPhilCryptoPolicyBundleV1({ ...input, networkCapability });
  if (bundle.policyEpoch !== trusted.greatestAcceptedPolicyEpoch) {
    fail("PHIL_PQ_POLICY_EPOCH_UNTRUSTED", "policy epoch is not the exact trusted current epoch");
  }
  if (bundle.bundleHash !== trusted.expectedPolicyHash) {
    fail("PHIL_PQ_POLICY_UNTRUSTED", "policy hash is not the trusted current policy");
  }
  return bundle;
}

export function validatePhilCryptoPolicyBundleV1(
  bundle: PhilCryptoPolicyBundleV1,
  networkCapability: PhilNetworkCryptoCapabilityV1,
  trustedState: PhilCryptoTrustedStateV1
): PhilCryptoPolicyBundleV1 {
  if (bundle.formatVersionHash !== PHIL_CRYPTO_POLICY_BUNDLE_V1_HASH) {
    fail("PHIL_PQ_POLICY_FORMAT_MISMATCH", "policy bundle format is unsupported");
  }
  const rebuilt = createPhilCryptoPolicyBundleV1({
    policyEpoch: bundle.policyEpoch,
    securityMode: bundle.securityMode,
    signatureCombiner: bundle.signatureCombiner,
    deviceSignatureSchemeIds: bundle.deviceSignatureSchemeIds,
    validatorSignatureSchemeIds: bundle.validatorSignatureSchemeIds,
    recoveryProtectionSchemeIds: bundle.recoveryProtectionSchemeIds,
    keyEstablishmentSchemeIds: bundle.keyEstablishmentSchemeIds,
    hashSchemeIds: bundle.hashSchemeIds,
    symmetricSchemeIds: bundle.symmetricSchemeIds,
    kdfSchemeIds: bundle.kdfSchemeIds,
    proofSchemeId: bundle.proofSchemeId,
    verifierSchemeId: bundle.verifierSchemeId,
    networkCapability,
    trustedState,
    recoveryIndependenceHash: bundle.recoveryIndependenceHash
  });
  if (rebuilt.bundleHash !== bundle.bundleHash) {
    fail("PHIL_PQ_POLICY_BUNDLE_HASH_MISMATCH", "policy bundle hash is not canonical");
  }
  if (rebuilt.registryEpoch !== bundle.registryEpoch || rebuilt.registryHash !== bundle.registryHash) {
    fail("PHIL_PQ_REGISTRY_TRUST_MISMATCH", "policy does not bind the admitted registry");
  }
  return rebuilt;
}

export interface PhilCryptoMigrationCeremonyV1 {
  readonly formatVersionHash: Hex;
  readonly ceremonyKind: PhilMigrationCeremonyKindV1;
  readonly fromBundleHash: Hex;
  readonly toBundleHash: Hex;
  readonly fromNetworkCapabilityHash: Hex;
  readonly toNetworkCapabilityHash: Hex;
  readonly fromTrustedStateHash: Hex;
  readonly toTrustedStateHash: Hex;
  readonly fromDeviceEpoch: string;
  readonly toDeviceEpoch: string;
  readonly fromValidatorEpoch: string;
  readonly toValidatorEpoch: string;
  readonly fromRecoveryEpoch: string;
  readonly toRecoveryEpoch: string;
  readonly newKeySetHash: Hex;
  readonly userApprovalDigest: Hex;
  readonly recoveryApprovalDigest: Hex;
  readonly independentReviewHash: Hex;
  readonly notBefore: string;
  readonly expiresAt: string;
  readonly emergencyFreeze: boolean;
  readonly ceremonyHash: Hex;
}

export function createPhilCryptoMigrationCeremonyV1(input: {
  readonly ceremonyKind: number;
  readonly fromBundle: PhilCryptoPolicyBundleV1;
  readonly toBundle: PhilCryptoPolicyBundleV1;
  readonly fromNetworkCapability: PhilNetworkCryptoCapabilityV1;
  readonly toNetworkCapability: PhilNetworkCryptoCapabilityV1;
  readonly fromTrustedState: PhilCryptoTrustedStateV1;
  readonly toTrustedState: PhilCryptoTrustedStateV1;
  readonly fromDeviceEpoch: string | number | bigint;
  readonly toDeviceEpoch: string | number | bigint;
  readonly fromValidatorEpoch: string | number | bigint;
  readonly toValidatorEpoch: string | number | bigint;
  readonly fromRecoveryEpoch: string | number | bigint;
  readonly toRecoveryEpoch: string | number | bigint;
  readonly newKeySetHash: BytesLike;
  readonly userApprovalDigest: BytesLike;
  readonly recoveryApprovalDigest: BytesLike;
  readonly independentReviewHash: BytesLike;
  readonly notBefore: string | number | bigint;
  readonly expiresAt: string | number | bigint;
  readonly emergencyFreeze: boolean;
}): PhilCryptoMigrationCeremonyV1 {
  const ceremonyKind = knownEnum(input.ceremonyKind, Object.values(PHIL_MIGRATION_CEREMONY_KIND_V1), "ceremonyKind");
  if (BigInt(input.toBundle.policyEpoch) !== BigInt(input.fromBundle.policyEpoch) + 1n) {
    fail("PHIL_PQ_POLICY_EPOCH_TRANSITION", "policy epoch must increment exactly once");
  }
  if (BigInt(input.toBundle.registryEpoch) < BigInt(input.fromBundle.registryEpoch)) {
    fail("PHIL_PQ_REGISTRY_DOWNGRADE", "registry epoch cannot decrease");
  }
  if (input.toBundle.securityMode < input.fromBundle.securityMode) {
    fail("PHIL_PQ_SECURITY_DOWNGRADE", "migration cannot reduce the enforced security mode");
  }
  const fromNetworkCapability = validatePhilNetworkCryptoCapabilityV1(
    input.fromNetworkCapability,
    input.fromTrustedState
  );
  const toNetworkCapability = validatePhilNetworkCryptoCapabilityV1(
    input.toNetworkCapability,
    input.toTrustedState
  );
  const fromBundle = validatePhilCryptoPolicyBundleV1(
    input.fromBundle,
    fromNetworkCapability,
    input.fromTrustedState
  );
  const toBundle = validatePhilCryptoPolicyBundleV1(
    input.toBundle,
    toNetworkCapability,
    input.toTrustedState
  );
  if (fromNetworkCapability.networkIdHash !== toNetworkCapability.networkIdHash) {
    fail("PHIL_PQ_CROSS_NETWORK_CEREMONY_FORBIDDEN", "one migration ceremony cannot cross networks");
  }
  if (fromNetworkCapability.capabilityAuthorityHash !== toNetworkCapability.capabilityAuthorityHash) {
    fail("PHIL_PQ_CAPABILITY_AUTHORITY_ROTATION_UNSUPPORTED", "capability authority rotation requires a separate architecture gate");
  }
  if (BigInt(toNetworkCapability.capabilityEpoch) < BigInt(fromNetworkCapability.capabilityEpoch)) {
    fail("PHIL_PQ_CAPABILITY_DOWNGRADE", "capability epoch cannot decrease");
  }
  if (toNetworkCapability.capabilityHash !== fromNetworkCapability.capabilityHash
      && BigInt(toNetworkCapability.capabilityEpoch) <= BigInt(fromNetworkCapability.capabilityEpoch)) {
    fail("PHIL_PQ_CAPABILITY_EPOCH_TRANSITION", "a changed capability requires a higher epoch");
  }
  if (BigInt(input.toTrustedState.greatestAcceptedCapabilityEpoch)
        < BigInt(input.fromTrustedState.greatestAcceptedCapabilityEpoch)
      || BigInt(input.toTrustedState.greatestAcceptedPolicyEpoch)
        < BigInt(input.fromTrustedState.greatestAcceptedPolicyEpoch)) {
    fail("PHIL_PQ_TRUSTED_STATE_DOWNGRADE", "trusted freshness floors cannot decrease");
  }
  const epochPairs = [
    [uint64(input.fromDeviceEpoch, "fromDeviceEpoch"), uint64(input.toDeviceEpoch, "toDeviceEpoch")],
    [uint64(input.fromValidatorEpoch, "fromValidatorEpoch"), uint64(input.toValidatorEpoch, "toValidatorEpoch")],
    [uint64(input.fromRecoveryEpoch, "fromRecoveryEpoch"), uint64(input.toRecoveryEpoch, "toRecoveryEpoch")]
  ] as const;
  for (const [from, to] of epochPairs) {
    if (BigInt(to) !== BigInt(from) + 1n) {
      fail("PHIL_PQ_AUTHORITY_EPOCH_TRANSITION", "device, validator, and recovery epochs must each increment exactly once");
    }
  }
  if (ceremonyKind === PHIL_MIGRATION_CEREMONY_KIND_V1.ENROLL_HYBRID
      && (input.fromBundle.securityMode !== PHIL_CRYPTO_SECURITY_MODE_V1.CLASSICAL_ONLY
        || input.toBundle.securityMode !== PHIL_CRYPTO_SECURITY_MODE_V1.HYBRID_AND)) {
    fail("PHIL_PQ_HYBRID_ENROLLMENT_TRANSITION", "hybrid enrollment must move classical-only to hybrid-AND");
  }
  if (ceremonyKind === PHIL_MIGRATION_CEREMONY_KIND_V1.ROTATE_WITHIN_MODE
      && input.fromBundle.securityMode !== input.toBundle.securityMode) {
    fail("PHIL_PQ_ROTATION_MODE_CHANGE", "ordinary rotation must preserve security mode");
  }
  if (ceremonyKind === PHIL_MIGRATION_CEREMONY_KIND_V1.RETIRE_CLASSICAL
      && (input.fromBundle.securityMode !== PHIL_CRYPTO_SECURITY_MODE_V1.HYBRID_AND
        || input.toBundle.securityMode !== PHIL_CRYPTO_SECURITY_MODE_V1.POST_QUANTUM_ONLY)) {
    fail("PHIL_PQ_RETIREMENT_TRANSITION", "classical retirement must move hybrid-AND to PQ-only");
  }
  const emergency = ceremonyKind === PHIL_MIGRATION_CEREMONY_KIND_V1.EMERGENCY_MIGRATE_AND_FREEZE;
  const emergencyFreeze = canonicalBoolean(input.emergencyFreeze, "emergencyFreeze");
  if (emergencyFreeze !== emergency) {
    fail("PHIL_PQ_EMERGENCY_FREEZE_REQUIRED", "only emergency migration requires immediate freeze");
  }
  const notBefore = uint64(input.notBefore, "notBefore", false);
  const expiresAt = uint64(input.expiresAt, "expiresAt");
  if (BigInt(expiresAt) < BigInt(notBefore)) {
    fail("PHIL_PQ_CEREMONY_WINDOW_INVALID", "ceremony expiry precedes activation");
  }
  const normalized = {
    formatVersionHash: PHIL_CRYPTO_MIGRATION_CEREMONY_V1_HASH,
    ceremonyKind,
    fromBundleHash: input.fromBundle.bundleHash,
    toBundleHash: input.toBundle.bundleHash,
    fromNetworkCapabilityHash: fromNetworkCapability.capabilityHash,
    toNetworkCapabilityHash: toNetworkCapability.capabilityHash,
    fromTrustedStateHash: input.fromTrustedState.trustedStateHash,
    toTrustedStateHash: input.toTrustedState.trustedStateHash,
    fromDeviceEpoch: epochPairs[0][0],
    toDeviceEpoch: epochPairs[0][1],
    fromValidatorEpoch: epochPairs[1][0],
    toValidatorEpoch: epochPairs[1][1],
    fromRecoveryEpoch: epochPairs[2][0],
    toRecoveryEpoch: epochPairs[2][1],
    newKeySetHash: bytes32(input.newKeySetHash, "newKeySetHash"),
    userApprovalDigest: bytes32(input.userApprovalDigest, "userApprovalDigest"),
    recoveryApprovalDigest: bytes32(input.recoveryApprovalDigest, "recoveryApprovalDigest"),
    independentReviewHash: bytes32(input.independentReviewHash, "independentReviewHash"),
    notBefore,
    expiresAt,
    emergencyFreeze
  };
  const ceremonyHash = keccak256(abiCoder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint64", "bool"],
    [
      PHIL_CRYPTO_MIGRATION_CEREMONY_V1_HASH,
      normalized.ceremonyKind,
      normalized.fromBundleHash,
      normalized.toBundleHash,
      normalized.fromNetworkCapabilityHash,
      normalized.toNetworkCapabilityHash,
      normalized.fromTrustedStateHash,
      normalized.toTrustedStateHash,
      BigInt(normalized.fromDeviceEpoch),
      BigInt(normalized.toDeviceEpoch),
      BigInt(normalized.fromValidatorEpoch),
      BigInt(normalized.toValidatorEpoch),
      BigInt(normalized.fromRecoveryEpoch),
      BigInt(normalized.toRecoveryEpoch),
      normalized.newKeySetHash,
      normalized.userApprovalDigest,
      normalized.recoveryApprovalDigest,
      normalized.independentReviewHash,
      BigInt(normalized.notBefore),
      BigInt(normalized.expiresAt),
      normalized.emergencyFreeze
    ]
  )) as Hex;
  return Object.freeze({ ...normalized, ceremonyHash });
}

export function assessPhilPostQuantumClaimV1(input: {
  readonly bundle: PhilCryptoPolicyBundleV1;
  readonly network: PhilNetworkCryptoCapabilityV1;
  readonly trustedState: PhilCryptoTrustedStateV1;
}): Readonly<{
  claim: "algorithm_agile_only" | "local_hybrid" | "network_hybrid" | "post_quantum_scope";
  wholeSystemPostQuantum: false;
  reasons: readonly string[];
}> {
  const reasons: string[] = [];
  const network = validatePhilNetworkCryptoCapabilityV1(input.network, input.trustedState);
  const bundle = validatePhilCryptoPolicyBundleV1(input.bundle, network, input.trustedState);
  if (bundle.networkCapabilityHash !== network.capabilityHash) {
    fail("PHIL_PQ_NETWORK_CAPABILITY_MISMATCH", "bundle does not bind the supplied network record");
  }
  const allIds = [
    ...bundle.deviceSignatureSchemeIds,
    ...bundle.validatorSignatureSchemeIds,
    ...bundle.recoveryProtectionSchemeIds,
    ...bundle.keyEstablishmentSchemeIds,
    ...bundle.hashSchemeIds,
    ...bundle.symmetricSchemeIds,
    ...bundle.kdfSchemeIds,
    bundle.proofSchemeId,
    bundle.verifierSchemeId
  ];
  const locallyImplemented = allIds.every((schemeId) => {
    const record = getPhilCryptoSchemeRecordV1(schemeId);
    return record.lifecycle === L.ACTIVE_REFERENCE
      && (record.evidenceLevel === E.IMPLEMENTED_LOCAL
        || record.evidenceLevel === E.NETWORK_ENFORCED
        || record.evidenceLevel === E.INDEPENDENTLY_REVIEWED);
  });
  if (!locallyImplemented) reasons.push("one or more required schemes are specified candidates rather than admitted implementations");
  if (network.maximumSecurityMode < bundle.securityMode) reasons.push("network does not enforce the bundle security mode");
  if (!network.authorizationPathAvailable) reasons.push("network authorization path is not deployed and independently verified");
  if (bundle.securityMode === PHIL_CRYPTO_SECURITY_MODE_V1.CLASSICAL_ONLY) {
    reasons.push("authorization still depends on quantum-vulnerable signature or proof components");
    return Object.freeze({ claim: "algorithm_agile_only", wholeSystemPostQuantum: false, reasons: Object.freeze(reasons) });
  }
  if (!locallyImplemented) {
    return Object.freeze({ claim: "algorithm_agile_only", wholeSystemPostQuantum: false, reasons: Object.freeze(reasons) });
  }
  if (network.enforcement !== PHIL_NETWORK_ENFORCEMENT_V1.NETWORK_ENFORCED
      || !network.authorizationPathAvailable
      || network.maximumSecurityMode < bundle.securityMode) {
    return Object.freeze({ claim: "local_hybrid", wholeSystemPostQuantum: false, reasons: Object.freeze(reasons) });
  }
  return Object.freeze({
    claim: bundle.securityMode === PHIL_CRYPTO_SECURITY_MODE_V1.POST_QUANTUM_ONLY
      ? "post_quantum_scope"
      : "network_hybrid",
    wholeSystemPostQuantum: false,
    reasons: Object.freeze(reasons)
  });
}
