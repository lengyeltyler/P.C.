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
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_SECURITY_MODEL_ID
} from "./v2Intent.ts";
import {
  PHILCORE_V2_RECOVERY_FACTOR_BITMAP,
  PHILCORE_V2_RECOVERY_FACTOR_ROLE,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY
} from "./v2Authorization.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHILCORE_V2_ZERO_BYTES32 =
  `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION = 2 as const;
export const PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2 = 2 as const;
export const PHILCORE_V2_RECOVERY_EVIDENCE_VERSION = 2 as const;
export const PHILCORE_V2_RECOVERY_AUTHORITY_KIND = 2 as const;
export const PHILCORE_V2_RECOVERY_DELAY_SECONDS = 172800 as const;
export const PHILCORE_V2_RECOVERY_EXPIRY_SECONDS = 604800 as const;

export const PHILCORE_V2_RECOVERY_DOMAIN_LABEL =
  "PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V2" as const;
export const PHILCORE_V2_RECOVERY_DOMAIN_ID =
  keccak256(toUtf8Bytes(PHILCORE_V2_RECOVERY_DOMAIN_LABEL)) as Hex;

export const PHILCORE_V2_BACKUP_POLICY = Object.freeze({
  NOT_APPLICABLE: 0,
  SINGLE_DEVICE_REQUIRED: 1
} as const);

export const PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY = Object.freeze({
  NOT_APPLICABLE: 0,
  PLATFORM_REQUIRED: 1,
  CROSS_PLATFORM_REQUIRED: 2
} as const);

export const PHILCORE_V2_ATTESTATION_POLICY = Object.freeze({
  NOT_APPLICABLE: 0,
  VERIFIED_DEVICE_BOUND: 1,
  VERIFIED_EXTERNAL_HARDWARE: 2
} as const);

export const PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE = Object.freeze({
  WEBAUTHN_PUBLIC_MATERIAL:
    "PhilCoreV2WebAuthnPublicMaterial(bytes32 qx,bytes32 qy)",
  SECP256K1_PUBLIC_MATERIAL:
    "PhilCoreV2Secp256k1PublicMaterial(address signer)",
  INDEPENDENCE_BINDING:
    "PhilCoreV2RecoveryIndependenceBinding(uint8 bindingVersion,uint8 role,bytes32 credentialIdHash,bytes32 enrollmentCeremonyHash,bytes32 attestationEvidenceHash,bytes32 custodyDomainId)",
  FACTOR_DESCRIPTOR:
    "PhilCoreV2RecoveryFactorDescriptorV2(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdHash,bytes32 rpIdHash,bytes32 originPolicyHash,bytes32 independenceBindingHash,uint8 userVerificationPolicy,uint8 backupPolicy,uint8 authenticatorAttachmentPolicy,uint8 attestationPolicy,uint64 credentialGeneration)",
  RECOVERY_CONFIGURATION:
    "PhilCoreV2RecoveryConfigurationV2(uint8 configurationVersion,uint8 threshold,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment)",
  EVIDENCE_CONTEXT:
    "PhilCoreV2RecoveryEvidenceContextV2(uint8 envelopeVersion,uint8 authorityKind,uint8 actionType,uint8 factorBitmap,address account,uint256 chainId,address entryPoint,bytes32 authorizedIntentHash,bytes32 userOpHash,bytes32 requestId,bytes32 currentRecoveryConfigHash,uint64 validatorEpoch,uint64 recoveryEpoch,uint48 validAfter,uint48 validUntil,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds,bytes32 proposedValidatorCommitment,bytes32 proposedRecoveryConfigHash,uint64 proposedRecoveryEpoch,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment,bytes32 firstFactorCommitment,bytes32 secondFactorCommitment)"
} as const);

export const PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH = Object.freeze(
  Object.fromEntries(
    Object.entries(PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE).map(([key, value]) => [
      key,
      keccak256(toUtf8Bytes(value))
    ])
  ) as Record<keyof typeof PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE, Hex>
);

export interface PhilCoreV2RecoveryIndependenceBindingInput {
  readonly bindingVersion: BigNumberish;
  readonly role: BigNumberish;
  readonly credentialIdHash: Hex;
  readonly enrollmentCeremonyHash: Hex;
  readonly attestationEvidenceHash: Hex;
  readonly custodyDomainId: Hex;
}

export interface PhilCoreV2RecoveryFactorDescriptorInput {
  readonly descriptorVersion: BigNumberish;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly recoveryDomainId: Hex;
  readonly role: BigNumberish;
  readonly verifierKind: BigNumberish;
  readonly publicVerificationMaterialHash: Hex;
  readonly credentialIdHash: Hex;
  readonly rpIdHash: Hex;
  readonly originPolicyHash: Hex;
  readonly independenceBindingHash: Hex;
  readonly userVerificationPolicy: BigNumberish;
  readonly backupPolicy: BigNumberish;
  readonly authenticatorAttachmentPolicy: BigNumberish;
  readonly attestationPolicy: BigNumberish;
  readonly credentialGeneration: BigNumberish;
}

export interface PhilCoreV2RecoveryConfigurationV2Input {
  readonly configurationVersion: BigNumberish;
  readonly threshold: BigNumberish;
  readonly primaryDeviceCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly recoveryFactorCommitment: Hex;
}

export interface PhilCoreV2RecoveryEvidenceContextInput {
  readonly envelopeVersion: BigNumberish;
  readonly authorityKind: BigNumberish;
  readonly actionType: BigNumberish;
  readonly factorBitmap: BigNumberish;
  readonly account: string;
  readonly chainId: BigNumberish;
  readonly entryPoint: string;
  readonly authorizedIntentHash: Hex;
  readonly userOperationHash: Hex;
  readonly requestId: Hex;
  readonly currentRecoveryConfigHash: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly validAfter: BigNumberish;
  readonly validUntil: BigNumberish;
  readonly recoveryDelaySeconds: BigNumberish;
  readonly recoveryExpirySeconds: BigNumberish;
  readonly proposedValidatorCommitment: Hex;
  readonly proposedRecoveryConfigHash: Hex;
  readonly proposedRecoveryEpoch: BigNumberish;
  readonly primaryDeviceCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly recoveryFactorCommitment: Hex;
  readonly firstFactorCommitment: Hex;
  readonly secondFactorCommitment: Hex;
}

export interface PhilCoreV2RecoveryRotationInput {
  readonly currentRecoveryEpoch: BigNumberish;
  readonly proposedRecoveryEpoch: BigNumberish;
  readonly currentDescriptors: readonly [
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput
  ];
  readonly proposedDescriptors: readonly [
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput
  ];
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

function uint(
  value: BigNumberish,
  bits: number,
  label: string,
  options: { readonly nonzero?: boolean } = {}
): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (options.nonzero === true && parsed === 0n) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return parsed;
}

function address(value: string, label: string): string {
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    throw new Error(`${label}_must_be_address`);
  }
  if (normalized === ZERO_ADDRESS) throw new Error(`${label}_must_be_nonzero`);
  return normalized;
}

function exactUint8(
  value: BigNumberish,
  expected: number,
  label: string
): bigint {
  const parsed = uint(value, 8, label);
  if (parsed !== BigInt(expected)) throw new Error(`${label}_unsupported`);
  return parsed;
}

function factorRole(value: BigNumberish): number {
  const parsed = Number(uint(value, 8, "factorRole"));
  if (![0, 1, 2].includes(parsed)) throw new Error("factorRole_unsupported");
  return parsed;
}

function factorBitmap(value: BigNumberish): number {
  const parsed = Number(uint(value, 8, "factorBitmap"));
  if (![3, 5, 6].includes(parsed)) {
    throw new Error("recovery_factor_bitmap_invalid");
  }
  return parsed;
}

function expectedRoles(bitmap: number): readonly [number, number] {
  if (bitmap === PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE) {
    return [0, 1];
  }
  if (bitmap === PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_RECOVERY) {
    return [0, 2];
  }
  return [1, 2];
}

export function computePhilCoreV2WebAuthnPublicMaterialHash(input: {
  readonly qx: Hex;
  readonly qy: Hex;
}): Hex {
  const qx = bytes32(input.qx, "qx");
  const qy = bytes32(input.qy, "qy");
  if (qx === qy) throw new Error("webauthn_public_point_coordinates_duplicate");
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.WEBAUTHN_PUBLIC_MATERIAL,
      qx,
      qy
    ]
  )) as Hex;
}

export function computePhilCoreV2Secp256k1PublicMaterialHash(input: {
  readonly signer: string;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "address"],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.SECP256K1_PUBLIC_MATERIAL,
      address(input.signer, "signer")
    ]
  )) as Hex;
}

export function computePhilCoreV2RecoveryIndependenceBinding(
  input: PhilCoreV2RecoveryIndependenceBindingInput
): Hex {
  const role = factorRole(input.role);
  const credentialIdHash = bytes32(
    input.credentialIdHash,
    "credentialIdHash",
    role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
  );
  const attestationEvidenceHash = bytes32(
    input.attestationEvidenceHash,
    "attestationEvidenceHash",
    role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
  );
  if (
    role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
    && credentialIdHash !== PHILCORE_V2_ZERO_BYTES32
  ) {
    throw new Error("secp256k1_credentialIdHash_must_be_zero");
  }
  if (
    role !== PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
    && attestationEvidenceHash === PHILCORE_V2_ZERO_BYTES32
  ) {
    throw new Error("webauthn_attestation_evidence_required");
  }
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.INDEPENDENCE_BINDING,
      exactUint8(input.bindingVersion, 1, "independenceBindingVersion"),
      role,
      credentialIdHash,
      bytes32(input.enrollmentCeremonyHash, "enrollmentCeremonyHash"),
      attestationEvidenceHash,
      bytes32(input.custodyDomainId, "custodyDomainId")
    ]
  )) as Hex;
}

function normalizedDescriptor(
  input: PhilCoreV2RecoveryFactorDescriptorInput
) {
  const descriptorVersion = exactUint8(
    input.descriptorVersion,
    PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    "descriptorVersion"
  );
  const accountVersionId = bytes32(input.accountVersionId, "accountVersionId");
  const securityModelId = bytes32(input.securityModelId, "securityModelId");
  const recoveryDomainId = bytes32(input.recoveryDomainId, "recoveryDomainId");
  if (accountVersionId !== PHILCORE_V2_ACCOUNT_VERSION_ID.toLowerCase()) {
    throw new Error("accountVersionId_unsupported");
  }
  if (securityModelId !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    throw new Error("securityModelId_unsupported");
  }
  if (recoveryDomainId !== PHILCORE_V2_RECOVERY_DOMAIN_ID.toLowerCase()) {
    throw new Error("recoveryDomainId_unsupported");
  }

  const role = factorRole(input.role);
  const verifierKind = Number(uint(
    input.verifierKind,
    8,
    "verifierKind",
    { nonzero: true }
  ));
  const publicVerificationMaterialHash = bytes32(
    input.publicVerificationMaterialHash,
    "publicVerificationMaterialHash"
  );
  const credentialIdHash = bytes32(
    input.credentialIdHash,
    "credentialIdHash",
    true
  );
  const rpIdHash = bytes32(input.rpIdHash, "rpIdHash", true);
  const originPolicyHash = bytes32(
    input.originPolicyHash,
    "originPolicyHash",
    true
  );
  const independenceBindingHash = bytes32(
    input.independenceBindingHash,
    "independenceBindingHash"
  );
  const userVerificationPolicy = Number(uint(
    input.userVerificationPolicy,
    8,
    "userVerificationPolicy"
  ));
  const backupPolicy = Number(uint(input.backupPolicy, 8, "backupPolicy"));
  const authenticatorAttachmentPolicy = Number(uint(
    input.authenticatorAttachmentPolicy,
    8,
    "authenticatorAttachmentPolicy"
  ));
  const attestationPolicy = Number(uint(
    input.attestationPolicy,
    8,
    "attestationPolicy"
  ));
  const credentialGeneration = uint(
    input.credentialGeneration,
    64,
    "credentialGeneration",
    { nonzero: true }
  );

  if (role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE) {
    if (verifierKind !== PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256) {
      throw new Error("primary_device_verifierKind_invalid");
    }
    if (
      credentialIdHash === PHILCORE_V2_ZERO_BYTES32
      || rpIdHash === PHILCORE_V2_ZERO_BYTES32
      || originPolicyHash === PHILCORE_V2_ZERO_BYTES32
    ) {
      throw new Error("primary_device_descriptor_incomplete");
    }
    if (
      userVerificationPolicy
        !== PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED
      || backupPolicy !== PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED
      || authenticatorAttachmentPolicy
        !== PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED
      || attestationPolicy
        !== PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
    ) {
      throw new Error("primary_device_policy_invalid");
    }
  } else if (
    role === PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY
  ) {
    if (verifierKind !== PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256) {
      throw new Error("hardware_security_key_verifierKind_invalid");
    }
    if (
      credentialIdHash === PHILCORE_V2_ZERO_BYTES32
      || rpIdHash === PHILCORE_V2_ZERO_BYTES32
      || originPolicyHash === PHILCORE_V2_ZERO_BYTES32
    ) {
      throw new Error("hardware_security_key_descriptor_incomplete");
    }
    if (
      userVerificationPolicy
        !== PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED
      || backupPolicy !== PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED
      || authenticatorAttachmentPolicy
        !== PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED
      || attestationPolicy
        !== PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE
    ) {
      throw new Error("hardware_security_key_policy_invalid");
    }
  } else {
    if (
      verifierKind
        !== PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1
    ) {
      throw new Error("recovery_factor_verifierKind_invalid");
    }
    if (
      credentialIdHash !== PHILCORE_V2_ZERO_BYTES32
      || rpIdHash !== PHILCORE_V2_ZERO_BYTES32
      || originPolicyHash !== PHILCORE_V2_ZERO_BYTES32
    ) {
      throw new Error("secp256k1_webauthn_fields_must_be_zero");
    }
    if (
      userVerificationPolicy
        !== PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE
      || backupPolicy !== PHILCORE_V2_BACKUP_POLICY.NOT_APPLICABLE
      || authenticatorAttachmentPolicy
        !== PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.NOT_APPLICABLE
      || attestationPolicy
        !== PHILCORE_V2_ATTESTATION_POLICY.NOT_APPLICABLE
    ) {
      throw new Error("recovery_factor_policy_invalid");
    }
  }

  return {
    descriptorVersion,
    accountVersionId,
    securityModelId,
    recoveryDomainId,
    role,
    verifierKind,
    publicVerificationMaterialHash,
    credentialIdHash,
    rpIdHash,
    originPolicyHash,
    independenceBindingHash,
    userVerificationPolicy,
    backupPolicy,
    authenticatorAttachmentPolicy,
    attestationPolicy,
    credentialGeneration
  };
}

export function computePhilCoreV2RecoveryDescriptorCommitment(
  input: PhilCoreV2RecoveryFactorDescriptorInput
): Hex {
  const descriptor = normalizedDescriptor(input);
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint8",
      "uint8",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint8",
      "uint8",
      "uint8",
      "uint8",
      "uint64"
    ],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.FACTOR_DESCRIPTOR,
      descriptor.descriptorVersion,
      descriptor.accountVersionId,
      descriptor.securityModelId,
      descriptor.recoveryDomainId,
      descriptor.role,
      descriptor.verifierKind,
      descriptor.publicVerificationMaterialHash,
      descriptor.credentialIdHash,
      descriptor.rpIdHash,
      descriptor.originPolicyHash,
      descriptor.independenceBindingHash,
      descriptor.userVerificationPolicy,
      descriptor.backupPolicy,
      descriptor.authenticatorAttachmentPolicy,
      descriptor.attestationPolicy,
      descriptor.credentialGeneration
    ]
  )) as Hex;
}

export function computePhilCoreV2RecoveryConfigurationHashV2(
  input: PhilCoreV2RecoveryConfigurationV2Input
): Hex {
  const configurationVersion = exactUint8(
    input.configurationVersion,
    PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
    "configurationVersion"
  );
  const threshold = exactUint8(
    input.threshold,
    PHILCORE_V2_RECOVERY_THRESHOLD,
    "recoveryThreshold"
  );
  const commitments = [
    bytes32(input.primaryDeviceCommitment, "primaryDeviceCommitment"),
    bytes32(
      input.hardwareSecurityKeyCommitment,
      "hardwareSecurityKeyCommitment"
    ),
    bytes32(input.recoveryFactorCommitment, "recoveryFactorCommitment")
  ] as const;
  if (new Set(commitments).size !== commitments.length) {
    throw new Error("recovery_factor_commitments_must_be_unique");
  }
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.RECOVERY_CONFIGURATION,
      configurationVersion,
      threshold,
      ...commitments
    ]
  )) as Hex;
}

export function validatePhilCoreV2RecoveryDescriptorSet(
  descriptors: readonly [
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput,
    PhilCoreV2RecoveryFactorDescriptorInput
  ]
): {
  readonly commitments: readonly [Hex, Hex, Hex];
  readonly recoveryConfigHash: Hex;
} {
  const normalized = descriptors.map(normalizedDescriptor);
  normalized.forEach((descriptor, index) => {
    if (descriptor.role !== index) {
      throw new Error("recovery_factor_role_order_invalid");
    }
  });
  for (const field of [
    "publicVerificationMaterialHash",
    "independenceBindingHash"
  ] as const) {
    if (new Set(normalized.map((descriptor) => descriptor[field])).size !== 3) {
      throw new Error(`recovery_factor_${field}_must_be_unique`);
    }
  }
  if (normalized[0].credentialIdHash === normalized[1].credentialIdHash) {
    throw new Error("webauthn_credentialIdHash_must_be_unique");
  }

  const commitments = descriptors.map(
    computePhilCoreV2RecoveryDescriptorCommitment
  ) as [Hex, Hex, Hex];
  const recoveryConfigHash = computePhilCoreV2RecoveryConfigurationHashV2({
    configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
    threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2]
  });
  return { commitments, recoveryConfigHash };
}

export function validatePhilCoreV2RecoveryRotation(
  input: PhilCoreV2RecoveryRotationInput
): {
  readonly changedRoles: readonly number[];
  readonly currentRecoveryConfigHash: Hex;
  readonly proposedRecoveryConfigHash: Hex;
} {
  const currentEpoch = uint(
    input.currentRecoveryEpoch,
    64,
    "currentRecoveryEpoch",
    { nonzero: true }
  );
  const proposedEpoch = uint(
    input.proposedRecoveryEpoch,
    64,
    "proposedRecoveryEpoch",
    { nonzero: true }
  );
  if (proposedEpoch !== currentEpoch + 1n) {
    throw new Error("proposedRecoveryEpoch_must_equal_current_plus_one");
  }

  const currentSet = validatePhilCoreV2RecoveryDescriptorSet(
    input.currentDescriptors
  );
  const proposedSet = validatePhilCoreV2RecoveryDescriptorSet(
    input.proposedDescriptors
  );
  const current = input.currentDescriptors.map(normalizedDescriptor);
  const proposed = input.proposedDescriptors.map(normalizedDescriptor);
  const changedRoles: number[] = [];

  for (let role = 0; role < 3; role += 1) {
    if (currentSet.commitments[role] === proposedSet.commitments[role]) continue;
    changedRoles.push(role);
    if (
      proposed[role].credentialGeneration
      !== current[role].credentialGeneration + 1n
    ) {
      throw new Error("rotated_factor_generation_must_increment_once");
    }
    if (
      proposed[role].publicVerificationMaterialHash
      === current[role].publicVerificationMaterialHash
    ) {
      throw new Error("rotated_factor_public_material_must_change");
    }
    if (
      proposed[role].independenceBindingHash
      === current[role].independenceBindingHash
    ) {
      throw new Error("rotated_factor_independence_binding_must_change");
    }
    if (
      role !== PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
      && proposed[role].credentialIdHash === current[role].credentialIdHash
    ) {
      throw new Error("rotated_webauthn_credential_must_change");
    }
  }
  if (changedRoles.length === 0) {
    throw new Error("recovery_rotation_must_change_factor");
  }
  return {
    changedRoles,
    currentRecoveryConfigHash: currentSet.recoveryConfigHash,
    proposedRecoveryConfigHash: proposedSet.recoveryConfigHash
  };
}

function normalizedEvidenceContext(
  input: PhilCoreV2RecoveryEvidenceContextInput
) {
  const envelopeVersion = exactUint8(
    input.envelopeVersion,
    PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
    "recoveryEvidenceVersion"
  );
  const authorityKind = exactUint8(
    input.authorityKind,
    PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
    "recoveryAuthorityKind"
  );
  const actionType = Number(uint(input.actionType, 8, "actionType"));
  const allowedActions = [
    PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
    PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL,
    PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
    PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL
  ];
  if (!allowedActions.includes(actionType as typeof allowedActions[number])) {
    throw new Error("recovery_evidence_action_invalid");
  }
  const bitmap = factorBitmap(input.factorBitmap);
  const chainId = uint(input.chainId, 256, "chainId", { nonzero: true });
  const validatorEpoch = uint(
    input.validatorEpoch,
    64,
    "validatorEpoch",
    { nonzero: true }
  );
  const recoveryEpoch = uint(
    input.recoveryEpoch,
    64,
    "recoveryEpoch",
    { nonzero: true }
  );
  const validAfter = uint(input.validAfter, 48, "validAfter");
  const validUntil = uint(
    input.validUntil,
    48,
    "validUntil",
    { nonzero: true }
  );
  if (validUntil <= validAfter) throw new Error("validity_window_invalid");
  const recoveryDelaySeconds = uint(
    input.recoveryDelaySeconds,
    64,
    "recoveryDelaySeconds",
    { nonzero: true }
  );
  const recoveryExpirySeconds = uint(
    input.recoveryExpirySeconds,
    64,
    "recoveryExpirySeconds",
    { nonzero: true }
  );
  if (recoveryDelaySeconds !== BigInt(PHILCORE_V2_RECOVERY_DELAY_SECONDS)) {
    throw new Error("recoveryDelaySeconds_invalid");
  }
  if (recoveryExpirySeconds !== BigInt(PHILCORE_V2_RECOVERY_EXPIRY_SECONDS)) {
    throw new Error("recoveryExpirySeconds_invalid");
  }

  const primaryDeviceCommitment = bytes32(
    input.primaryDeviceCommitment,
    "primaryDeviceCommitment"
  );
  const hardwareSecurityKeyCommitment = bytes32(
    input.hardwareSecurityKeyCommitment,
    "hardwareSecurityKeyCommitment"
  );
  const recoveryFactorCommitment = bytes32(
    input.recoveryFactorCommitment,
    "recoveryFactorCommitment"
  );
  const currentRecoveryConfigHash = bytes32(
    input.currentRecoveryConfigHash,
    "currentRecoveryConfigHash"
  );
  const computedConfigHash = computePhilCoreV2RecoveryConfigurationHashV2({
    configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
    threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment
  });
  if (currentRecoveryConfigHash !== computedConfigHash) {
    throw new Error("current_recovery_config_hash_mismatch");
  }

  const roleCommitments = [
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment
  ] as const;
  const roles = expectedRoles(bitmap);
  const firstFactorCommitment = bytes32(
    input.firstFactorCommitment,
    "firstFactorCommitment"
  );
  const secondFactorCommitment = bytes32(
    input.secondFactorCommitment,
    "secondFactorCommitment"
  );
  if (
    firstFactorCommitment !== roleCommitments[roles[0]]
    || secondFactorCommitment !== roleCommitments[roles[1]]
  ) {
    throw new Error("factor_commitment_order_or_membership_invalid");
  }

  const proposedValidatorCommitment = bytes32(
    input.proposedValidatorCommitment,
    "proposedValidatorCommitment",
    true
  );
  const proposedRecoveryConfigHash = bytes32(
    input.proposedRecoveryConfigHash,
    "proposedRecoveryConfigHash",
    true
  );
  const proposedRecoveryEpoch = uint(
    input.proposedRecoveryEpoch,
    64,
    "proposedRecoveryEpoch",
    { nonzero: true }
  );
  if (proposedRecoveryEpoch !== recoveryEpoch + 1n) {
    throw new Error("proposedRecoveryEpoch_must_equal_current_plus_one");
  }
  const validatorRecovery =
    actionType === PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST
    || actionType === PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL;
  if (
    validatorRecovery
    && (
      proposedValidatorCommitment === PHILCORE_V2_ZERO_BYTES32
      || proposedRecoveryConfigHash !== PHILCORE_V2_ZERO_BYTES32
    )
  ) {
    throw new Error("validator_recovery_action_context_invalid");
  }
  if (
    !validatorRecovery
    && (
      proposedValidatorCommitment !== PHILCORE_V2_ZERO_BYTES32
      || proposedRecoveryConfigHash === PHILCORE_V2_ZERO_BYTES32
    )
  ) {
    throw new Error("config_rotation_action_context_invalid");
  }
  const authorizedIntentHash = bytes32(
    input.authorizedIntentHash,
    "authorizedIntentHash"
  );
  const requestId = bytes32(input.requestId, "requestId");
  const isRequest =
    actionType === PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST
    || actionType === PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST;
  if (isRequest && requestId !== authorizedIntentHash) {
    throw new Error("recovery_request_id_must_equal_authorized_intent_hash");
  }

  return {
    envelopeVersion,
    authorityKind,
    actionType,
    bitmap,
    account: address(input.account, "account"),
    chainId,
    entryPoint: address(input.entryPoint, "entryPoint"),
    authorizedIntentHash,
    userOperationHash: bytes32(input.userOperationHash, "userOperationHash"),
    requestId,
    currentRecoveryConfigHash,
    validatorEpoch,
    recoveryEpoch,
    validAfter,
    validUntil,
    recoveryDelaySeconds,
    recoveryExpirySeconds,
    proposedValidatorCommitment,
    proposedRecoveryConfigHash,
    proposedRecoveryEpoch,
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment,
    firstFactorCommitment,
    secondFactorCommitment,
    roles
  };
}

export function computePhilCoreV2RecoveryEvidenceContextHash(
  input: PhilCoreV2RecoveryEvidenceContextInput
): Hex {
  const context = normalizedEvidenceContext(input);
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "uint8",
      "uint8",
      "uint8",
      "address",
      "uint256",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint64",
      "uint64",
      "uint48",
      "uint48",
      "uint64",
      "uint64",
      "bytes32",
      "bytes32",
      "uint64",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32"
    ],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.EVIDENCE_CONTEXT,
      context.envelopeVersion,
      context.authorityKind,
      context.actionType,
      context.bitmap,
      context.account,
      context.chainId,
      context.entryPoint,
      context.authorizedIntentHash,
      context.userOperationHash,
      context.requestId,
      context.currentRecoveryConfigHash,
      context.validatorEpoch,
      context.recoveryEpoch,
      context.validAfter,
      context.validUntil,
      context.recoveryDelaySeconds,
      context.recoveryExpirySeconds,
      context.proposedValidatorCommitment,
      context.proposedRecoveryConfigHash,
      context.proposedRecoveryEpoch,
      context.primaryDeviceCommitment,
      context.hardwareSecurityKeyCommitment,
      context.recoveryFactorCommitment,
      context.firstFactorCommitment,
      context.secondFactorCommitment
    ]
  )) as Hex;
}

export function assertPhilCoreV2RecoveryEvidenceMembership(input: {
  readonly context: PhilCoreV2RecoveryEvidenceContextInput;
  readonly firstDescriptor: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly secondDescriptor: PhilCoreV2RecoveryFactorDescriptorInput;
}): true {
  const context = normalizedEvidenceContext(input.context);
  const first = normalizedDescriptor(input.firstDescriptor);
  const second = normalizedDescriptor(input.secondDescriptor);
  if (first.role !== context.roles[0] || second.role !== context.roles[1]) {
    throw new Error("factor_evidence_role_order_invalid");
  }
  if (
    computePhilCoreV2RecoveryDescriptorCommitment(input.firstDescriptor)
      !== context.firstFactorCommitment
    || computePhilCoreV2RecoveryDescriptorCommitment(input.secondDescriptor)
      !== context.secondFactorCommitment
  ) {
    throw new Error("factor_evidence_commitment_mismatch");
  }
  return true;
}

export function assertPhilCoreV2RecoveryEvidenceState(input: {
  readonly context: PhilCoreV2RecoveryEvidenceContextInput;
  readonly expectedAccount: string;
  readonly expectedChainId: BigNumberish;
  readonly expectedEntryPoint: string;
  readonly currentValidatorEpoch: BigNumberish;
  readonly currentRecoveryEpoch: BigNumberish;
}): true {
  const context = normalizedEvidenceContext(input.context);
  if (context.account !== address(input.expectedAccount, "expectedAccount")) {
    throw new Error("recovery_evidence_account_mismatch");
  }
  if (context.chainId !== uint(
    input.expectedChainId,
    256,
    "expectedChainId",
    { nonzero: true }
  )) {
    throw new Error("recovery_evidence_chain_mismatch");
  }
  if (
    context.entryPoint
    !== address(input.expectedEntryPoint, "expectedEntryPoint")
  ) {
    throw new Error("recovery_evidence_entryPoint_mismatch");
  }
  const currentValidatorEpoch = uint(
    input.currentValidatorEpoch,
    64,
    "currentValidatorEpoch",
    { nonzero: true }
  );
  if (context.validatorEpoch < currentValidatorEpoch) {
    throw new Error("validator_epoch_stale");
  }
  if (context.validatorEpoch > currentValidatorEpoch) {
    throw new Error("validator_epoch_future");
  }
  const currentRecoveryEpoch = uint(
    input.currentRecoveryEpoch,
    64,
    "currentRecoveryEpoch",
    { nonzero: true }
  );
  if (context.recoveryEpoch < currentRecoveryEpoch) {
    throw new Error("recovery_epoch_stale");
  }
  if (context.recoveryEpoch > currentRecoveryEpoch) {
    throw new Error("recovery_epoch_future");
  }
  return true;
}
