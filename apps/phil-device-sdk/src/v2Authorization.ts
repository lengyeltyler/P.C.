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
  PHILCORE_V2_SECURITY_MODEL_ID,
  computePhilCoreV2DomainSeparator,
  computePhilCoreV2TypedDataDigest
} from "./v2Intent.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_AUTHORIZATION_TYPE = Object.freeze({
  PROOF_BINDING:
    "PhilCoreV2ProofBinding(bytes32 proofTypeHash,bytes32 proofInputHash,bytes32 proofArtifactDigest,bytes32 nullifier)",
  RUNTIME_AUTHORIZATION:
    "PhilCoreV2RuntimeAuthorization(bytes32 intentCoreHash,bytes32 proofBindingHash,bytes32 policyDecisionHash,bytes32 approvalEvidenceHash,bytes32 userPresenceEvidenceHash)",
  AUTHORIZED_INTENT:
    "PhilCoreV2AuthorizedIntent(bytes32 intentCoreHash,bytes32 runtimeAuthorizationDigest)",
  VALIDATOR_COMMITMENT:
    "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)",
  VALIDATOR_AUTHORIZATION:
    "PhilCoreV2Authorization(bytes32 authorizedIntentHash,bytes32 userOpHash,address validator,bytes32 validatorKeyIdBinding,uint64 validatorEpoch,uint64 recoveryEpoch)",
  RECOVERY_FACTOR:
    "PhilCoreV2RecoveryFactor(bytes32 accountVersionId,bytes32 securityModelId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 rpIdHash,bytes32 originPolicyHash,uint8 userVerificationPolicy,uint64 credentialGeneration)",
  RECOVERY_CONFIGURATION:
    "PhilCoreV2RecoveryConfiguration(uint8 configurationVersion,uint8 threshold,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment)",
  RECOVERY_AUTHORIZATION:
    "PhilCoreV2RecoveryAuthorization(bytes32 authorizedIntentHash,bytes32 userOpHash,bytes32 recoveryConfigHash,uint64 recoveryEpoch,uint8 factorBitmap)",
  COMBINED_CANCELLATION:
    "PhilCoreV2CombinedCancellation(bytes32 authorizedIntentHash,bytes32 userOpHash,address validator,uint64 validatorEpoch,bytes32 recoveryConfigHash,uint64 recoveryEpoch,uint8 factorBitmap)",
  CONFIG_ROTATION_AUTHORIZATION:
    "PhilCoreV2ConfigRotationAuthorization(bytes32 authorizedIntentHash,bytes32 userOpHash,address validator,uint64 validatorEpoch,bytes32 recoveryConfigHash,uint64 recoveryEpoch,bytes32 proposedRecoveryConfigHash,uint64 proposedRecoveryEpoch,uint8 factorBitmap)"
} as const);

export const PHILCORE_V2_AUTHORIZATION_TYPEHASH = Object.freeze(
  Object.fromEntries(
    Object.entries(PHILCORE_V2_AUTHORIZATION_TYPE).map(([key, value]) => [
      key,
      keccak256(toUtf8Bytes(value))
    ])
  ) as Record<keyof typeof PHILCORE_V2_AUTHORIZATION_TYPE, Hex>
);

export const PHILCORE_V2_VALIDATOR_VERIFIER_KIND = Object.freeze({
  SECP256K1_ECDSA: 1
} as const);

export const PHILCORE_V2_RECOVERY_FACTOR_ROLE = Object.freeze({
  PRIMARY_DEVICE: 0,
  HARDWARE_SECURITY_KEY: 1,
  RECOVERY_FACTOR: 2
} as const);

export type PhilCoreV2RecoveryFactorRole =
  typeof PHILCORE_V2_RECOVERY_FACTOR_ROLE[
    keyof typeof PHILCORE_V2_RECOVERY_FACTOR_ROLE
  ];

export const PHILCORE_V2_RECOVERY_VERIFIER_KIND = Object.freeze({
  WEBAUTHN_P256: 1,
  PURPOSE_BOUND_SECP256K1: 2,
  THRESHOLD_COMMITMENT: 3,
  NATIVE_DEVICE_P256: 4
} as const);

export type PhilCoreV2RecoveryVerifierKind =
  typeof PHILCORE_V2_RECOVERY_VERIFIER_KIND[
    keyof typeof PHILCORE_V2_RECOVERY_VERIFIER_KIND
  ];

export const PHILCORE_V2_USER_VERIFICATION_POLICY = Object.freeze({
  NOT_APPLICABLE: 0,
  USER_PRESENCE_REQUIRED: 1,
  USER_VERIFICATION_REQUIRED: 2
} as const);

export type PhilCoreV2UserVerificationPolicy =
  typeof PHILCORE_V2_USER_VERIFICATION_POLICY[
    keyof typeof PHILCORE_V2_USER_VERIFICATION_POLICY
  ];

export const PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION = 1 as const;
export const PHILCORE_V2_RECOVERY_THRESHOLD = 2 as const;
export const PHILCORE_V2_RECOVERY_FACTOR_BITMAP = Object.freeze({
  PRIMARY_AND_HARDWARE: 0b011,
  PRIMARY_AND_RECOVERY: 0b101,
  HARDWARE_AND_RECOVERY: 0b110
} as const);

export interface PhilCoreV2ProofBindingInput {
  readonly proofTypeHash: Hex;
  readonly proofInputHash: Hex;
  readonly proofArtifactDigest: Hex;
  readonly nullifier: Hex;
}

export interface PhilCoreV2RuntimeAuthorizationInput {
  readonly intentCoreHash: Hex;
  readonly proofBindingHash: Hex;
  readonly policyDecisionHash: Hex;
  readonly approvalEvidenceHash: Hex;
  readonly userPresenceEvidenceHash: Hex;
}

export interface PhilCoreV2ValidatorCommitmentInput {
  readonly verifierKind: BigNumberish;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
}

export interface PhilCoreV2ValidatorAuthorizationInput {
  readonly authorizedIntentHash: Hex;
  readonly userOperationHash: Hex;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
}

export interface PhilCoreV2RecoveryFactorInput {
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly role: BigNumberish;
  readonly verifierKind: BigNumberish;
  readonly publicVerificationMaterialHash: Hex;
  readonly rpIdHash: Hex;
  readonly originPolicyHash: Hex;
  readonly userVerificationPolicy: BigNumberish;
  readonly credentialGeneration: BigNumberish;
}

export interface PhilCoreV2RecoveryConfigurationInput {
  readonly configurationVersion: BigNumberish;
  readonly threshold: BigNumberish;
  readonly primaryDeviceCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly recoveryFactorCommitment: Hex;
}

export interface PhilCoreV2RecoveryAuthorizationInput {
  readonly authorizedIntentHash: Hex;
  readonly userOperationHash: Hex;
  readonly recoveryConfigHash: Hex;
  readonly recoveryEpoch: BigNumberish;
  readonly factorBitmap: BigNumberish;
}

export interface PhilCoreV2CombinedCancellationInput
  extends PhilCoreV2RecoveryAuthorizationInput {
  readonly validator: string;
  readonly validatorEpoch: BigNumberish;
}

export interface PhilCoreV2ConfigRotationAuthorizationInput
  extends PhilCoreV2CombinedCancellationInput {
  readonly proposedRecoveryConfigHash: Hex;
  readonly proposedRecoveryEpoch: BigNumberish;
}

export interface PhilCoreV2DigestResult {
  readonly domainSeparator: Hex;
  readonly structHash: Hex;
  readonly digest: Hex;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === ZERO_BYTES32) {
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

function role(value: BigNumberish): PhilCoreV2RecoveryFactorRole {
  const parsed = Number(uint(value, 8, "factorRole"));
  if (!Object.values(PHILCORE_V2_RECOVERY_FACTOR_ROLE).includes(
    parsed as PhilCoreV2RecoveryFactorRole
  )) {
    throw new Error("factorRole_unsupported");
  }
  return parsed as PhilCoreV2RecoveryFactorRole;
}

function verifierKind(value: BigNumberish): PhilCoreV2RecoveryVerifierKind {
  const parsed = Number(uint(value, 8, "verifierKind", { nonzero: true }));
  if (!Object.values(PHILCORE_V2_RECOVERY_VERIFIER_KIND).includes(
    parsed as PhilCoreV2RecoveryVerifierKind
  )) {
    throw new Error("verifierKind_unsupported");
  }
  return parsed as PhilCoreV2RecoveryVerifierKind;
}

function userVerificationPolicy(
  value: BigNumberish
): PhilCoreV2UserVerificationPolicy {
  const parsed = Number(uint(value, 8, "userVerificationPolicy"));
  if (!Object.values(PHILCORE_V2_USER_VERIFICATION_POLICY).includes(
    parsed as PhilCoreV2UserVerificationPolicy
  )) {
    throw new Error("userVerificationPolicy_unsupported");
  }
  return parsed as PhilCoreV2UserVerificationPolicy;
}

function factorBitmap(value: BigNumberish): number {
  const parsed = Number(uint(value, 8, "factorBitmap", { nonzero: true }));
  if (!Object.values(PHILCORE_V2_RECOVERY_FACTOR_BITMAP).includes(parsed as 3 | 5 | 6)) {
    throw new Error("factorBitmap_must_select_exactly_two_roles");
  }
  return parsed;
}

function typedDigest(
  domain: { readonly chainId: BigNumberish; readonly account: string },
  structHash: Hex
): PhilCoreV2DigestResult {
  const domainSeparator = computePhilCoreV2DomainSeparator(domain);
  return Object.freeze({
    domainSeparator,
    structHash,
    digest: computePhilCoreV2TypedDataDigest({ domainSeparator, structHash })
  });
}

export function computePhilCoreV2ProofBindingHash(
  input: PhilCoreV2ProofBindingInput
): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.PROOF_BINDING,
      bytes32(input.proofTypeHash, "proofTypeHash"),
      bytes32(input.proofInputHash, "proofInputHash"),
      bytes32(input.proofArtifactDigest, "proofArtifactDigest"),
      bytes32(input.nullifier, "nullifier")
    ]
  )) as Hex;
}

export function computePhilCoreV2RuntimeAuthorizationDigest(
  input: PhilCoreV2RuntimeAuthorizationInput
): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RUNTIME_AUTHORIZATION,
      bytes32(input.intentCoreHash, "intentCoreHash"),
      bytes32(input.proofBindingHash, "proofBindingHash"),
      bytes32(input.policyDecisionHash, "policyDecisionHash"),
      bytes32(input.approvalEvidenceHash, "approvalEvidenceHash"),
      bytes32(input.userPresenceEvidenceHash, "userPresenceEvidenceHash")
    ]
  )) as Hex;
}

export function computePhilCoreV2AuthorizedIntentHash(input: {
  readonly intentCoreHash: Hex;
  readonly runtimeAuthorizationDigest: Hex;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.AUTHORIZED_INTENT,
      bytes32(input.intentCoreHash, "intentCoreHash"),
      bytes32(input.runtimeAuthorizationDigest, "runtimeAuthorizationDigest")
    ]
  )) as Hex;
}

export function computePhilCoreV2ValidatorCommitment(
  input: PhilCoreV2ValidatorCommitmentInput
): Hex {
  const kind = uint(input.verifierKind, 8, "validatorVerifierKind", {
    nonzero: true
  });
  if (kind !== BigInt(PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA)) {
    throw new Error("validatorVerifierKind_unsupported");
  }
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "address", "bytes32"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.VALIDATOR_COMMITMENT,
      kind,
      address(input.validator, "validator"),
      bytes32(input.validatorKeyIdBinding, "validatorKeyIdBinding")
    ]
  )) as Hex;
}

export function computePhilCoreV2ValidatorDigest(
  domain: { readonly chainId: BigNumberish; readonly account: string },
  input: PhilCoreV2ValidatorAuthorizationInput
): PhilCoreV2DigestResult {
  const structHash = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "address", "bytes32", "uint64", "uint64"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.VALIDATOR_AUTHORIZATION,
      bytes32(input.authorizedIntentHash, "authorizedIntentHash"),
      bytes32(input.userOperationHash, "userOperationHash"),
      address(input.validator, "validator"),
      bytes32(input.validatorKeyIdBinding, "validatorKeyIdBinding"),
      uint(input.validatorEpoch, 64, "validatorEpoch", { nonzero: true }),
      uint(input.recoveryEpoch, 64, "recoveryEpoch", { nonzero: true })
    ]
  )) as Hex;
  return typedDigest(domain, structHash);
}

export function computePhilCoreV2RecoveryFactorCommitment(
  input: PhilCoreV2RecoveryFactorInput
): Hex {
  const normalizedRole = role(input.role);
  const normalizedVerifierKind = verifierKind(input.verifierKind);
  const normalizedUserVerificationPolicy =
    userVerificationPolicy(input.userVerificationPolicy);
  const rpIdHash = bytes32(input.rpIdHash, "rpIdHash", true);
  const originPolicyHash = bytes32(
    input.originPolicyHash,
    "originPolicyHash",
    true
  );

  if (bytes32(input.accountVersionId, "accountVersionId")
      !== PHILCORE_V2_ACCOUNT_VERSION_ID.toLowerCase()) {
    throw new Error("accountVersionId_unsupported");
  }
  if (bytes32(input.securityModelId, "securityModelId")
      !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    throw new Error("securityModelId_unsupported");
  }
  if (
    normalizedRole === PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE
    && normalizedVerifierKind ===
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.THRESHOLD_COMMITMENT
  ) {
    throw new Error("primary_device_verifierKind_not_allowed");
  }
  if (
    normalizedRole === PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY
    && normalizedVerifierKind ===
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.THRESHOLD_COMMITMENT
  ) {
    throw new Error("hardware_security_key_verifierKind_not_allowed");
  }
  if (
    normalizedRole === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
    && normalizedVerifierKind ===
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256
  ) {
    throw new Error("recovery_factor_verifierKind_not_allowed");
  }
  if (
    normalizedVerifierKind === PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256
  ) {
    if (rpIdHash === ZERO_BYTES32 || originPolicyHash === ZERO_BYTES32) {
      throw new Error("webauthn_policy_hashes_required");
    }
    if (
      normalizedUserVerificationPolicy !==
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED
    ) {
      throw new Error("webauthn_user_verification_required");
    }
  } else {
    if (rpIdHash !== ZERO_BYTES32 || originPolicyHash !== ZERO_BYTES32) {
      throw new Error("non_webauthn_policy_hashes_must_be_zero");
    }
    if (
      normalizedRole === PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR
      && normalizedUserVerificationPolicy !==
        PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE
    ) {
      throw new Error("recovery_factor_user_verification_not_applicable");
    }
  }

  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "bytes32",
      "bytes32",
      "uint8",
      "uint8",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint8",
      "uint64"
    ],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RECOVERY_FACTOR,
      PHILCORE_V2_ACCOUNT_VERSION_ID,
      PHILCORE_V2_SECURITY_MODEL_ID,
      normalizedRole,
      normalizedVerifierKind,
      bytes32(
        input.publicVerificationMaterialHash,
        "publicVerificationMaterialHash"
      ),
      rpIdHash,
      originPolicyHash,
      normalizedUserVerificationPolicy,
      uint(input.credentialGeneration, 64, "credentialGeneration", {
        nonzero: true
      })
    ]
  )) as Hex;
}

export function computePhilCoreV2RecoveryConfigurationHash(
  input: PhilCoreV2RecoveryConfigurationInput
): Hex {
  const configurationVersion = uint(
    input.configurationVersion,
    8,
    "configurationVersion",
    { nonzero: true }
  );
  const threshold = uint(input.threshold, 8, "threshold", { nonzero: true });
  if (configurationVersion !== BigInt(PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION)) {
    throw new Error("configurationVersion_unsupported");
  }
  if (threshold !== BigInt(PHILCORE_V2_RECOVERY_THRESHOLD)) {
    throw new Error("recovery_threshold_must_equal_two");
  }
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
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RECOVERY_CONFIGURATION,
      configurationVersion,
      threshold,
      ...commitments
    ]
  )) as Hex;
}

export function computePhilCoreV2RecoveryFactorDigest(
  domain: { readonly chainId: BigNumberish; readonly account: string },
  input: PhilCoreV2RecoveryAuthorizationInput
): PhilCoreV2DigestResult {
  const structHash = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint8"],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RECOVERY_AUTHORIZATION,
      bytes32(input.authorizedIntentHash, "authorizedIntentHash"),
      bytes32(input.userOperationHash, "userOperationHash"),
      bytes32(input.recoveryConfigHash, "recoveryConfigHash"),
      uint(input.recoveryEpoch, 64, "recoveryEpoch", { nonzero: true }),
      factorBitmap(input.factorBitmap)
    ]
  )) as Hex;
  return typedDigest(domain, structHash);
}

export function computePhilCoreV2CombinedCancellationDigest(
  domain: { readonly chainId: BigNumberish; readonly account: string },
  input: PhilCoreV2CombinedCancellationInput
): PhilCoreV2DigestResult {
  const structHash = keccak256(abiCoder.encode(
    [
      "bytes32",
      "bytes32",
      "bytes32",
      "address",
      "uint64",
      "bytes32",
      "uint64",
      "uint8"
    ],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.COMBINED_CANCELLATION,
      bytes32(input.authorizedIntentHash, "authorizedIntentHash"),
      bytes32(input.userOperationHash, "userOperationHash"),
      address(input.validator, "validator"),
      uint(input.validatorEpoch, 64, "validatorEpoch", { nonzero: true }),
      bytes32(input.recoveryConfigHash, "recoveryConfigHash"),
      uint(input.recoveryEpoch, 64, "recoveryEpoch", { nonzero: true }),
      factorBitmap(input.factorBitmap)
    ]
  )) as Hex;
  return typedDigest(domain, structHash);
}

export function computePhilCoreV2ConfigRotationDigest(
  domain: { readonly chainId: BigNumberish; readonly account: string },
  input: PhilCoreV2ConfigRotationAuthorizationInput
): PhilCoreV2DigestResult {
  const currentRecoveryEpoch = uint(
    input.recoveryEpoch,
    64,
    "recoveryEpoch",
    { nonzero: true }
  );
  const proposedRecoveryEpoch = uint(
    input.proposedRecoveryEpoch,
    64,
    "proposedRecoveryEpoch",
    { nonzero: true }
  );
  if (proposedRecoveryEpoch !== currentRecoveryEpoch + 1n) {
    throw new Error("proposedRecoveryEpoch_must_equal_current_plus_one");
  }
  const structHash = keccak256(abiCoder.encode(
    [
      "bytes32",
      "bytes32",
      "bytes32",
      "address",
      "uint64",
      "bytes32",
      "uint64",
      "bytes32",
      "uint64",
      "uint8"
    ],
    [
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.CONFIG_ROTATION_AUTHORIZATION,
      bytes32(input.authorizedIntentHash, "authorizedIntentHash"),
      bytes32(input.userOperationHash, "userOperationHash"),
      address(input.validator, "validator"),
      uint(input.validatorEpoch, 64, "validatorEpoch", { nonzero: true }),
      bytes32(input.recoveryConfigHash, "recoveryConfigHash"),
      currentRecoveryEpoch,
      bytes32(input.proposedRecoveryConfigHash, "proposedRecoveryConfigHash"),
      proposedRecoveryEpoch,
      factorBitmap(input.factorBitmap)
    ]
  )) as Hex;
  return typedDigest(domain, structHash);
}

export function assertPhilCoreV2AuthorityEpoch(input: {
  readonly currentValidatorEpoch: BigNumberish;
  readonly currentRecoveryEpoch: BigNumberish;
  readonly suppliedValidatorEpoch: BigNumberish;
  readonly suppliedRecoveryEpoch: BigNumberish;
}): true {
  const currentValidatorEpoch = uint(
    input.currentValidatorEpoch,
    64,
    "currentValidatorEpoch",
    { nonzero: true }
  );
  const currentRecoveryEpoch = uint(
    input.currentRecoveryEpoch,
    64,
    "currentRecoveryEpoch",
    { nonzero: true }
  );
  const suppliedValidatorEpoch = uint(
    input.suppliedValidatorEpoch,
    64,
    "suppliedValidatorEpoch",
    { nonzero: true }
  );
  const suppliedRecoveryEpoch = uint(
    input.suppliedRecoveryEpoch,
    64,
    "suppliedRecoveryEpoch",
    { nonzero: true }
  );

  if (suppliedValidatorEpoch < currentValidatorEpoch) {
    throw new Error("validator_epoch_stale");
  }
  if (suppliedValidatorEpoch > currentValidatorEpoch) {
    throw new Error("validator_epoch_future");
  }
  if (suppliedRecoveryEpoch < currentRecoveryEpoch) {
    throw new Error("recovery_epoch_stale");
  }
  if (suppliedRecoveryEpoch > currentRecoveryEpoch) {
    throw new Error("recovery_epoch_future");
  }
  return true;
}
