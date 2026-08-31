import {
  AbiCoder,
  getAddress,
  isHexString,
  keccak256,
  toUtf8Bytes,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_BACKUP_POLICY,
  PHILCORE_V2_ZERO_BYTES32,
  type PhilCoreV2RecoveryFactorDescriptorInput
} from "./v2RecoveryEvidence.ts";
import {
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY
} from "./v2Authorization.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "./v2Intent.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION = 3 as const;
export const PHILCORE_V2_CONSUMER_RECOVERY_CONFIGURATION_VERSION = 3 as const;
export const PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION = 2 as const;
export const PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION =
  "philcore-v2-minimal-account-v3-consumer-recovery" as const;
export const PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID =
  keccak256(toUtf8Bytes(
    PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION
  )) as Hex;
export const PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN =
  "PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V3" as const;
export const PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID =
  keccak256(toUtf8Bytes(PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN)) as Hex;

export const PHILCORE_V2_CONSUMER_RECOVERY_ROLE = Object.freeze({
  PRIMARY_DEVICE: 0,
  SECONDARY_AUTHENTICATOR: 1,
  OFFLINE_RECOVERY_FACTOR: 2
} as const);

export const PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS = Object.freeze({
  PRIMARY_PLATFORM_DEVICE: 1,
  SECONDARY_PLATFORM_DEVICE: 2,
  EXTERNAL_HARDWARE_KEY: 3,
  OFFLINE_SECP256K1_EXPORT: 4
} as const);

export const PHILCORE_V2_CONSUMER_SYNC_CLASS = Object.freeze({
  NOT_APPLICABLE: 0,
  DEVICE_BOUND: 1,
  SYNCED_MULTI_DEVICE: 2,
  UNKNOWN: 3
} as const);

export const PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE = Object.freeze({
  ENFORCED: 1,
  DEGRADED_UNVERIFIED: 2
} as const);

export const PHILCORE_V2_CONSUMER_RECOVERY_PROFILE = Object.freeze({
  STANDARD: "STANDARD",
  ENHANCED: "ENHANCED"
} as const);

export const PHILCORE_V2_CONSUMER_RECOVERY_TYPE = Object.freeze({
  INDEPENDENCE_BINDING:
    "PhilCoreV2RecoveryIndependenceBindingV2(uint8 bindingVersion,uint8 role,uint8 authenticatorClass,uint8 synchronizationClass,uint8 independenceAssurance,bytes32 credentialIdHash,bytes32 enrollmentCeremonyHash,bytes32 attestationEvidenceHash,bytes32 custodyDomainCommitment,uint64 credentialGeneration)",
  FACTOR_DESCRIPTOR:
    "PhilCoreV2RecoveryFactorDescriptorV3(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdHash,bytes32 rpIdHash,bytes32 originPolicyHash,bytes32 independenceBindingHash,uint8 userVerificationPolicy,uint8 backupPolicy,uint8 authenticatorAttachmentPolicy,uint8 attestationPolicy,uint64 credentialGeneration)",
  RECOVERY_CONFIGURATION:
    "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
} as const);

export const PHILCORE_V2_CONSUMER_RECOVERY_TYPEHASH = Object.freeze(
  Object.fromEntries(
    Object.entries(PHILCORE_V2_CONSUMER_RECOVERY_TYPE).map(([key, value]) => [
      key,
      keccak256(toUtf8Bytes(value))
    ])
  ) as Record<keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_TYPE, Hex>
);

export interface PhilCoreV2ConsumerRecoveryIndependenceInput {
  readonly bindingVersion: BigNumberish;
  readonly role: BigNumberish;
  readonly authenticatorClass: BigNumberish;
  readonly synchronizationClass: BigNumberish;
  readonly independenceAssurance: BigNumberish;
  readonly credentialIdHash: Hex;
  readonly enrollmentCeremonyHash: Hex;
  readonly attestationEvidenceHash: Hex;
  readonly custodyDomainCommitment: Hex;
  readonly credentialGeneration: BigNumberish;
}

export interface PhilCoreV2ConsumerRecoveryFactor {
  readonly descriptor: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly independence: PhilCoreV2ConsumerRecoveryIndependenceInput;
  readonly signer?: string;
}

export interface PhilCoreV2ConsumerRecoveryFactorPolicyResult {
  readonly factor: PhilCoreV2ConsumerRecoveryFactor;
  readonly factorCommitment: Hex;
}

export interface PhilCoreV2ConsumerRecoveryProfileResult {
  readonly profile: keyof typeof PHILCORE_V2_CONSUMER_RECOVERY_PROFILE;
  readonly descriptors: readonly [
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput
  ];
  readonly commitments: readonly [Hex, Hex, Hex];
  readonly recoveryConfigurationHash: Hex;
  readonly independenceAssurance: "ENFORCED";
  readonly warnings: readonly string[];
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === PHILCORE_V2_ZERO_BYTES32) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return normalized;
}

function uint(value: BigNumberish, bits: number, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  return parsed;
}

function exact(value: BigNumberish, expected: number, label: string): bigint {
  const parsed = uint(value, 8, label);
  if (parsed !== BigInt(expected)) throw new Error(`${label}_unsupported`);
  return parsed;
}

function normalizeIndependence(
  input: PhilCoreV2ConsumerRecoveryIndependenceInput
): {
  readonly bindingVersion: bigint;
  readonly role: bigint;
  readonly authenticatorClass: bigint;
  readonly synchronizationClass: bigint;
  readonly independenceAssurance: bigint;
  readonly credentialIdHash: Hex;
  readonly enrollmentCeremonyHash: Hex;
  readonly attestationEvidenceHash: Hex;
  readonly custodyDomainCommitment: Hex;
  readonly credentialGeneration: bigint;
} {
  const role = uint(input.role, 8, "independence.role");
  if (role > 2n) throw new Error("independence.role_unsupported");
  const generation = uint(
    input.credentialGeneration,
    64,
    "independence.credentialGeneration"
  );
  if (generation === 0n) throw new Error("credentialGeneration_must_be_nonzero");
  return {
    bindingVersion: exact(
      input.bindingVersion,
      PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
      "independence.bindingVersion"
    ),
    role,
    authenticatorClass: uint(
      input.authenticatorClass,
      8,
      "independence.authenticatorClass"
    ),
    synchronizationClass: uint(
      input.synchronizationClass,
      8,
      "independence.synchronizationClass"
    ),
    independenceAssurance: uint(
      input.independenceAssurance,
      8,
      "independence.independenceAssurance"
    ),
    credentialIdHash: bytes32(
      input.credentialIdHash,
      "independence.credentialIdHash",
      role === 2n
    ),
    enrollmentCeremonyHash: bytes32(
      input.enrollmentCeremonyHash,
      "independence.enrollmentCeremonyHash"
    ),
    attestationEvidenceHash: bytes32(
      input.attestationEvidenceHash,
      "independence.attestationEvidenceHash"
    ),
    custodyDomainCommitment: bytes32(
      input.custodyDomainCommitment,
      "independence.custodyDomainCommitment"
    ),
    credentialGeneration: generation
  };
}

function normalizeDescriptorForPolicy(
  descriptor: PhilCoreV2RecoveryFactorDescriptorInput
): {
  readonly role: bigint;
  readonly verifierKind: bigint;
  readonly publicVerificationMaterialHash: Hex;
  readonly credentialIdHash: Hex;
  readonly rpIdHash: Hex;
  readonly originPolicyHash: Hex;
  readonly independenceBindingHash: Hex;
  readonly userVerificationPolicy: bigint;
  readonly backupPolicy: bigint;
  readonly authenticatorAttachmentPolicy: bigint;
  readonly attestationPolicy: bigint;
  readonly credentialGeneration: bigint;
} {
  const role = uint(descriptor.role, 8, "descriptor.role");
  if (role > 2n) throw new Error("descriptor.role_unsupported");
  const allowZero = role === 2n;
  return {
    role,
    verifierKind: uint(descriptor.verifierKind, 8, "descriptor.verifierKind"),
    publicVerificationMaterialHash: bytes32(
      descriptor.publicVerificationMaterialHash,
      "descriptor.publicVerificationMaterialHash"
    ),
    credentialIdHash: bytes32(
      descriptor.credentialIdHash,
      "descriptor.credentialIdHash",
      allowZero
    ),
    rpIdHash: bytes32(descriptor.rpIdHash, "descriptor.rpIdHash", allowZero),
    originPolicyHash: bytes32(
      descriptor.originPolicyHash,
      "descriptor.originPolicyHash",
      allowZero
    ),
    independenceBindingHash: bytes32(
      descriptor.independenceBindingHash,
      "descriptor.independenceBindingHash"
    ),
    userVerificationPolicy: uint(
      descriptor.userVerificationPolicy,
      8,
      "descriptor.userVerificationPolicy"
    ),
    backupPolicy: uint(descriptor.backupPolicy, 8, "descriptor.backupPolicy"),
    authenticatorAttachmentPolicy: uint(
      descriptor.authenticatorAttachmentPolicy,
      8,
      "descriptor.authenticatorAttachmentPolicy"
    ),
    attestationPolicy: uint(
      descriptor.attestationPolicy,
      8,
      "descriptor.attestationPolicy"
    ),
    credentialGeneration: uint(
      descriptor.credentialGeneration,
      64,
      "descriptor.credentialGeneration"
    )
  };
}

export function computePhilCoreV2ConsumerRecoveryIndependenceBinding(
  input: PhilCoreV2ConsumerRecoveryIndependenceInput
): Hex {
  const normalized = normalizeIndependence(input);
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "uint8",
      "uint8",
      "uint8",
      "uint8",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint64"
    ],
    [
      PHILCORE_V2_CONSUMER_RECOVERY_TYPEHASH.INDEPENDENCE_BINDING,
      normalized.bindingVersion,
      normalized.role,
      normalized.authenticatorClass,
      normalized.synchronizationClass,
      normalized.independenceAssurance,
      normalized.credentialIdHash,
      normalized.enrollmentCeremonyHash,
      normalized.attestationEvidenceHash,
      normalized.custodyDomainCommitment,
      normalized.credentialGeneration
    ]
  )) as Hex;
}

export function computePhilCoreV2ConsumerRecoveryFactorCommitment(
  descriptor: PhilCoreV2RecoveryFactorDescriptorInput
): Hex {
  const fields = [
    exact(
      descriptor.descriptorVersion,
      PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
      "descriptorVersion"
    ),
    bytes32(descriptor.accountVersionId, "accountVersionId"),
    bytes32(descriptor.securityModelId, "securityModelId"),
    bytes32(descriptor.recoveryDomainId, "recoveryDomainId"),
    uint(descriptor.role, 8, "role"),
    uint(descriptor.verifierKind, 8, "verifierKind"),
    bytes32(
      descriptor.publicVerificationMaterialHash,
      "publicVerificationMaterialHash"
    ),
    bytes32(
      descriptor.credentialIdHash,
      "credentialIdHash",
      BigInt(descriptor.role) === 2n
    ),
    bytes32(descriptor.rpIdHash, "rpIdHash", BigInt(descriptor.role) === 2n),
    bytes32(
      descriptor.originPolicyHash,
      "originPolicyHash",
      BigInt(descriptor.role) === 2n
    ),
    bytes32(descriptor.independenceBindingHash, "independenceBindingHash"),
    uint(descriptor.userVerificationPolicy, 8, "userVerificationPolicy"),
    uint(descriptor.backupPolicy, 8, "backupPolicy"),
    uint(
      descriptor.authenticatorAttachmentPolicy,
      8,
      "authenticatorAttachmentPolicy"
    ),
    uint(descriptor.attestationPolicy, 8, "attestationPolicy"),
    uint(descriptor.credentialGeneration, 64, "credentialGeneration")
  ] as const;
  if (fields[1] !== PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID) {
    throw new Error("accountVersionId_unsupported");
  }
  if (fields[2] !== PHILCORE_V2_SECURITY_MODEL_ID) {
    throw new Error("securityModelId_unsupported");
  }
  if (fields[3] !== PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID) {
    throw new Error("recoveryDomainId_unsupported");
  }
  if (fields[4] > 2n || fields[15] === 0n) {
    throw new Error("descriptor_role_or_generation_invalid");
  }
  return keccak256(abiCoder.encode(
    [
      "bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint8",
      "uint8", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
      "uint8", "uint8", "uint8", "uint8", "uint64"
    ],
    [PHILCORE_V2_CONSUMER_RECOVERY_TYPEHASH.FACTOR_DESCRIPTOR, ...fields]
  )) as Hex;
}

// ---------------------------------------------------------------------------
// Hostile-surface-safe property access for the shared per-role factor policy
// validator. This module keeps its existing plain-Error convention (no
// branded error class) -- every hostile-surface rejection throws a stable,
// pre-existing-style message; the raw caller-thrown value is never retained
// as `cause` or any other property, and its `.code`/`.name`/`.message` are
// never inspected.
//
// `Reflect.ownKeys` alone is not proof of ownership: for an extensible
// target with no non-configurable own properties, a Proxy's `ownKeys` trap
// may report any set of names with no correspondence to what the target
// actually owns, while ordinary property reads still silently resolve
// inherited prototype values. Every name `ownKeys` reports is therefore
// only a *candidate*; a name is genuinely own only once a guarded
// `Object.getOwnPropertyDescriptor` call returns a non-`undefined`
// descriptor for it. Values are then taken from that verified descriptor
// itself (its own `value`, or a single guarded invocation of its own
// `get`), never from a fresh, separately-trappable property read that could
// contradict what the descriptor reported.
// ---------------------------------------------------------------------------

function requirePlainObject(value: unknown, message: string): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    throw new Error(message);
  }
  let isArray: boolean;
  try {
    isArray = Array.isArray(value);
  } catch {
    throw new Error(message);
  }
  if (isArray) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

/**
 * Reads the value of an already-verified own property descriptor. For an
 * own data property, the descriptor's own `value` is used directly -- no
 * further hostile operation is needed, since it was already captured
 * atomically by the guarded `getOwnPropertyDescriptor` call that produced
 * this descriptor. For an own accessor property, its own `get` function is
 * invoked exactly once, with the original object as receiver; an accessor
 * with no getter (set-only) is rejected, never silently treated as
 * `undefined`.
 */
function readValueFromVerifiedDescriptor(
  value: object,
  descriptor: PropertyDescriptor,
  message: string
): unknown {
  if ("value" in descriptor) {
    return descriptor.value;
  }
  if (typeof descriptor.get !== "function") {
    throw new Error(message);
  }
  try {
    return descriptor.get.call(value);
  } catch {
    throw new Error(message);
  }
}

/**
 * Validates the exact own-key surface of `value` and returns a map of only
 * the keys that are genuinely own, each with its verified property
 * descriptor. A name reported by `ownKeys` but lacking a real own
 * descriptor is never added to the returned map -- for a required key,
 * this means it is treated as missing exactly as if `ownKeys` had never
 * reported it at all.
 */
function requireExactOwnKeys(
  value: object,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  message: string
): ReadonlyMap<string, PropertyDescriptor> {
  const allowed = new Set<string>([...requiredKeys, ...optionalKeys]);
  let keys: readonly (string | symbol)[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    throw new Error(message);
  }

  const candidates: string[] = [];
  for (const key of keys) {
    if (typeof key === "symbol") throw new Error(message);
    if (!allowed.has(key)) throw new Error(message);
    candidates.push(key);
  }

  const verified = new Map<string, PropertyDescriptor>();
  for (const key of candidates) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      throw new Error(message);
    }
    if (descriptor !== undefined) {
      verified.set(key, descriptor);
    }
  }

  for (const key of requiredKeys) {
    if (!verified.has(key)) throw new Error(message);
  }
  return verified;
}

function snapshotExactObject(
  value: unknown,
  allowedKeys: readonly string[],
  message: string
): Record<string, unknown> {
  const object = requirePlainObject(value, message);
  const verified = requireExactOwnKeys(object, allowedKeys, [], message);
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    // `allowedKeys` was passed as the exact `requiredKeys` list above, so
    // `requireExactOwnKeys` already guarantees a verified descriptor exists
    // for every one of them here.
    const descriptor = verified.get(key) as PropertyDescriptor;
    snapshot[key] = readValueFromVerifiedDescriptor(object, descriptor, message);
  }
  return Object.freeze(snapshot);
}

const FACTOR_REQUIRED_OWN_KEYS = Object.freeze(["descriptor", "independence"] as const);
const FACTOR_OPTIONAL_OWN_KEYS = Object.freeze(["signer"] as const);

const DESCRIPTOR_OWN_KEYS = Object.freeze([
  "descriptorVersion",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "role",
  "verifierKind",
  "publicVerificationMaterialHash",
  "credentialIdHash",
  "rpIdHash",
  "originPolicyHash",
  "independenceBindingHash",
  "userVerificationPolicy",
  "backupPolicy",
  "authenticatorAttachmentPolicy",
  "attestationPolicy",
  "credentialGeneration"
] as const);

const INDEPENDENCE_OWN_KEYS = Object.freeze([
  "bindingVersion",
  "role",
  "authenticatorClass",
  "synchronizationClass",
  "independenceAssurance",
  "credentialIdHash",
  "enrollmentCeremonyHash",
  "attestationEvidenceHash",
  "custodyDomainCommitment",
  "credentialGeneration"
] as const);

/**
 * Sole authoritative per-role factor policy implementation. Used by both
 * `validatePhilCoreV2ConsumerRecoveryProfile` (generic enrollment/rotation)
 * and, later, genesis staging -- there is no second, private copy of this
 * logic anywhere in this module.
 *
 * Hostile-surface-hardened: `expectedRole` is validated before any factor
 * property is read; the factor, descriptor, and independence objects are
 * each read via a single guarded `Reflect.ownKeys` exact-key check and a
 * single guarded read per field into a fresh, prototype-safe, frozen
 * snapshot (`Object.create(null)`); every subsequent computation operates
 * only on those snapshots, never the caller-owned originals. A revoked or
 * hostile Proxy, a throwing getter, or a hostile `ownKeys`/enumeration trap
 * is contained: only the stable, pre-existing-style plain-Error message
 * survives, never the raw thrown value (no `cause`, no other property, and
 * `.code`/`.name`/`.message` on a hostile thrown value are never read).
 */
export function validatePhilCoreV2ConsumerRecoveryFactorPolicy(
  factor: PhilCoreV2ConsumerRecoveryFactor,
  expectedRole: 0 | 1 | 2
): PhilCoreV2ConsumerRecoveryFactorPolicyResult {
  if (
    typeof expectedRole !== "number"
    || !(expectedRole === 0 || expectedRole === 1 || expectedRole === 2)
  ) {
    throw new Error("recovery_factor_expected_role_invalid");
  }

  const factorObject = requirePlainObject(factor, "recovery_factor_input_invalid");
  const factorDescriptors = requireExactOwnKeys(
    factorObject,
    FACTOR_REQUIRED_OWN_KEYS,
    FACTOR_OPTIONAL_OWN_KEYS,
    "recovery_factor_input_invalid"
  );

  // Presence is decided solely by a verified own descriptor -- a "signer"
  // name merely fabricated by a hostile `ownKeys` trap, with no real own
  // descriptor behind it, is not present here.
  const signerPresent = factorDescriptors.has("signer");
  if (expectedRole < 2 && signerPresent) {
    throw new Error("webauthn_recovery_factor_signer_forbidden");
  }
  if (expectedRole === 2 && !signerPresent) {
    throw new Error("offline_recovery_signer_required");
  }

  const descriptorRaw = readValueFromVerifiedDescriptor(
    factorObject,
    factorDescriptors.get("descriptor") as PropertyDescriptor,
    "recovery_factor_descriptor_input_invalid"
  );
  const independenceRaw = readValueFromVerifiedDescriptor(
    factorObject,
    factorDescriptors.get("independence") as PropertyDescriptor,
    "recovery_factor_independence_input_invalid"
  );

  const descriptorSnapshot = snapshotExactObject(
    descriptorRaw,
    DESCRIPTOR_OWN_KEYS,
    "recovery_factor_descriptor_input_invalid"
  ) as unknown as PhilCoreV2RecoveryFactorDescriptorInput;

  const independenceSnapshot = snapshotExactObject(
    independenceRaw,
    INDEPENDENCE_OWN_KEYS,
    "recovery_factor_independence_input_invalid"
  ) as unknown as PhilCoreV2ConsumerRecoveryIndependenceInput;

  const independence = normalizeIndependence(independenceSnapshot);
  const descriptor = normalizeDescriptorForPolicy(descriptorSnapshot);

  if (
    descriptor.role !== BigInt(expectedRole)
    || independence.role !== BigInt(expectedRole)
    || descriptor.credentialGeneration !== independence.credentialGeneration
    || descriptor.independenceBindingHash
      !== computePhilCoreV2ConsumerRecoveryIndependenceBinding(independenceSnapshot)
  ) {
    throw new Error("recovery_factor_role_or_independence_binding_invalid");
  }

  if (
    independence.independenceAssurance
      !== BigInt(PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.ENFORCED)
  ) {
    throw new Error("degraded_independence_not_deployable");
  }

  // Structurally normalized on both sides (bytes32-shape-checked, lowercase,
  // zero-allowed only for Role 2) before this comparison, and before any
  // role-specific policy check below.
  if (descriptor.credentialIdHash !== independence.credentialIdHash) {
    throw new Error("descriptor_independence_credential_id_hash_mismatch");
  }

  if (expectedRole < 2) {
    if (
      descriptor.verifierKind !== BigInt(PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256)
      || descriptor.userVerificationPolicy
        !== BigInt(PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED)
      || descriptor.backupPolicy !== BigInt(PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED)
      || independence.synchronizationClass !== BigInt(PHILCORE_V2_CONSUMER_SYNC_CLASS.DEVICE_BOUND)
    ) {
      throw new Error("webauthn_recovery_factor_policy_invalid");
    }
  }

  let signer: string | undefined;

  if (expectedRole === 0) {
    if (
      independence.authenticatorClass
        !== BigInt(PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE)
      || descriptor.authenticatorAttachmentPolicy
        !== BigInt(PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED)
      || descriptor.attestationPolicy
        !== BigInt(PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND)
    ) {
      throw new Error("primary_device_policy_invalid");
    }
  } else if (expectedRole === 1) {
    const platform =
      independence.authenticatorClass
        === BigInt(PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.SECONDARY_PLATFORM_DEVICE)
      && descriptor.authenticatorAttachmentPolicy
        === BigInt(PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED)
      && descriptor.attestationPolicy
        === BigInt(PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND);
    const hardware =
      independence.authenticatorClass
        === BigInt(PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY)
      && descriptor.authenticatorAttachmentPolicy
        === BigInt(PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED)
      && descriptor.attestationPolicy
        === BigInt(PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE);
    if (!platform && !hardware) {
      throw new Error("secondary_authenticator_classification_invalid");
    }
  } else {
    if (
      independence.authenticatorClass
        !== BigInt(PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.OFFLINE_SECP256K1_EXPORT)
      || independence.synchronizationClass !== BigInt(PHILCORE_V2_CONSUMER_SYNC_CLASS.NOT_APPLICABLE)
      || descriptor.verifierKind !== BigInt(PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1)
      || descriptor.credentialIdHash !== PHILCORE_V2_ZERO_BYTES32
      || descriptor.rpIdHash !== PHILCORE_V2_ZERO_BYTES32
      || descriptor.originPolicyHash !== PHILCORE_V2_ZERO_BYTES32
      || descriptor.userVerificationPolicy !== 0n
      || descriptor.backupPolicy !== 0n
      || descriptor.authenticatorAttachmentPolicy !== 0n
      || descriptor.attestationPolicy !== 0n
    ) {
      throw new Error("offline_recovery_factor_policy_invalid");
    }

    const signerRaw = readValueFromVerifiedDescriptor(
      factorObject,
      factorDescriptors.get("signer") as PropertyDescriptor,
      "offline_recovery_signer_invalid"
    );
    if (typeof signerRaw !== "string") {
      throw new Error("offline_recovery_signer_invalid");
    }
    let normalizedSigner: string;
    try {
      normalizedSigner = getAddress(signerRaw);
    } catch {
      throw new Error("offline_recovery_signer_invalid");
    }
    if (normalizedSigner !== signerRaw || normalizedSigner === ZERO_ADDRESS) {
      throw new Error("offline_recovery_signer_invalid");
    }
    if (
      computePhilCoreV2Secp256k1PublicMaterialHash({ signer: normalizedSigner })
        !== descriptor.publicVerificationMaterialHash
    ) {
      throw new Error("offline_recovery_signer_binding_invalid");
    }
    signer = normalizedSigner;
  }

  const factorCommitment = computePhilCoreV2ConsumerRecoveryFactorCommitment(descriptorSnapshot);

  return Object.freeze({
    factor: Object.freeze({
      descriptor: descriptorSnapshot,
      independence: independenceSnapshot,
      ...(signer !== undefined ? { signer } : {})
    }),
    factorCommitment
  });
}

export function computePhilCoreV2ConsumerRecoveryConfigurationHash(
  commitments: readonly [Hex, Hex, Hex]
): Hex {
  const normalized = commitments.map((value, index) =>
    bytes32(value, `role${index}Commitment`)
  ) as [Hex, Hex, Hex];
  if (new Set(normalized).size !== 3) {
    throw new Error("recovery_factor_commitments_must_be_unique");
  }
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_CONSUMER_RECOVERY_TYPEHASH.RECOVERY_CONFIGURATION,
      PHILCORE_V2_CONSUMER_RECOVERY_CONFIGURATION_VERSION,
      PHILCORE_V2_RECOVERY_THRESHOLD,
      ...normalized
    ]
  )) as Hex;
}

export function validatePhilCoreV2ConsumerRecoveryProfile(input: {
  readonly factors: readonly [
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor
  ];
  readonly executionValidator: string;
}): PhilCoreV2ConsumerRecoveryProfileResult {
  const executionValidator = getAddress(input.executionValidator);

  // 1) Validate and snapshot each role through the sole shared per-factor
  // validator. Every subsequent step in this function uses only the
  // returned snapshots and returned commitments -- the original
  // caller-owned `input.factors` entries are never read again below.
  const results = [
    validatePhilCoreV2ConsumerRecoveryFactorPolicy(input.factors[0], 0),
    validatePhilCoreV2ConsumerRecoveryFactorPolicy(input.factors[1], 1),
    validatePhilCoreV2ConsumerRecoveryFactorPolicy(input.factors[2], 2)
  ] as const;

  const descriptors = results.map((result) => result.factor.descriptor) as [
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput
  ];
  const independence = results.map((result) =>
    normalizeIndependence(result.factor.independence)
  );

  // 2) Cross-role uniqueness checks, from the returned snapshots only.
  const credentialIds = independence.slice(0, 2).map(
    (value) => value.credentialIdHash
  );
  if (new Set(credentialIds).size !== 2) {
    throw new Error("primary_and_secondary_credential_must_be_distinct");
  }
  const publicMaterial = descriptors.map(
    (value) => value.publicVerificationMaterialHash.toLowerCase()
  );
  if (new Set(publicMaterial).size !== 3) {
    throw new Error("recovery_public_material_must_be_unique");
  }
  const custodyDomains = independence.map(
    (value) => value.custodyDomainCommitment
  );
  if (new Set(custodyDomains).size !== 3) {
    throw new Error("recovery_custody_domains_must_be_unique");
  }

  // 3) Execution-validator alias prevention remains profile-level: the
  // per-factor function intentionally has no executionValidator parameter.
  // The Role 2 signer is already a validated canonical address from the
  // shared per-factor result, so no re-parsing or caller reread is needed.
  const offlineSigner = results[2].factor.signer;
  if (offlineSigner === executionValidator) {
    throw new Error("execution_validator_cannot_be_recovery_factor");
  }

  // 4) Recovery-configuration computation and profile selection, using only
  // the already-returned commitments -- never recomputed.
  const commitments = results.map((result) => result.factorCommitment) as [Hex, Hex, Hex];
  const profile =
    BigInt(results[1].factor.independence.authenticatorClass)
      === BigInt(
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY
      )
      ? "ENHANCED"
      : "STANDARD";
  return Object.freeze({
    profile,
    descriptors: Object.freeze(descriptors),
    commitments: Object.freeze(commitments),
    recoveryConfigurationHash:
      computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments),
    independenceAssurance: "ENFORCED",
    warnings: Object.freeze([
      "Custody-domain separation is commitment-bound but remains user-attested.",
      "WebAuthn cannot prove separate cloud, password-manager, or backup accounts."
    ])
  });
}

export function validatePhilCoreV2ConsumerRecoveryRotation(input: {
  readonly current: readonly [
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor
  ];
  readonly proposed: readonly [
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor,
    PhilCoreV2ConsumerRecoveryFactor
  ];
  readonly executionValidator: string;
}): {
  readonly changedRole: 0 | 1 | 2;
  readonly currentRecoveryConfigurationHash: Hex;
  readonly proposedRecoveryConfigurationHash: Hex;
} {
  const current = validatePhilCoreV2ConsumerRecoveryProfile({
    factors: input.current,
    executionValidator: input.executionValidator
  });
  const proposed = validatePhilCoreV2ConsumerRecoveryProfile({
    factors: input.proposed,
    executionValidator: input.executionValidator
  });
  const changed = current.commitments.flatMap((commitment, role) =>
    commitment === proposed.commitments[role] ? [] : [role]
  );
  if (changed.length !== 1) {
    throw new Error("recovery_rotation_must_replace_exactly_one_role");
  }
  const changedRole = changed[0] as 0 | 1 | 2;
  for (const role of [0, 1, 2] as const) {
    const currentGeneration = BigInt(
      input.current[role].descriptor.credentialGeneration
    );
    const proposedGeneration = BigInt(
      input.proposed[role].descriptor.credentialGeneration
    );
    if (
      (role === changedRole && proposedGeneration !== currentGeneration + 1n)
      || (role !== changedRole && proposedGeneration !== currentGeneration)
    ) {
      throw new Error("recovery_rotation_generation_invalid");
    }
  }
  return Object.freeze({
    changedRole,
    currentRecoveryConfigurationHash: current.recoveryConfigurationHash,
    proposedRecoveryConfigurationHash: proposed.recoveryConfigurationHash
  });
}

export {
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash
};
