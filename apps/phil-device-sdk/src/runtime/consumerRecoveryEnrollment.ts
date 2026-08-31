import {
  SigningKey,
  computeAddress,
  getBytes,
  hexlify,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_BACKUP_POLICY,
  PHILCORE_V2_ZERO_BYTES32,
  type PhilCoreV2RecoveryFactorDescriptorInput
} from "../v2RecoveryEvidence.ts";
import {
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY
} from "../v2Authorization.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "../v2Intent.ts";
import {
  computePhilCoreV2ConsumerRecoveryIndependenceBinding,
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS,
  PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE,
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
  PHILCORE_V2_CONSUMER_RECOVERY_ROLE,
  PHILCORE_V2_CONSUMER_SYNC_CLASS,
  type PhilCoreV2ConsumerRecoveryFactor,
  type PhilCoreV2ConsumerRecoveryIndependenceInput
} from "../v2ConsumerRecovery.ts";

const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const OFFLINE_FORMAT_PREFIX = "PHIL39-V1";
const OFFLINE_DERIVATION_DOMAIN =
  keccak256(toUtf8Bytes("PHILCORE_V2_OFFLINE_RECOVERY_FACTOR_V1"));
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type PhilCoreConsumerRecoveryWebAuthnRole =
  | typeof PHILCORE_V2_CONSUMER_RECOVERY_ROLE.PRIMARY_DEVICE
  | typeof PHILCORE_V2_CONSUMER_RECOVERY_ROLE.SECONDARY_AUTHENTICATOR;

export type PhilCoreConsumerRecoveryAuthenticatorClass =
  | typeof PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE
  | typeof PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.SECONDARY_PLATFORM_DEVICE
  | typeof PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY;

export interface PhilCoreConsumerRecoveryRegistrationPolicy {
  readonly role: PhilCoreConsumerRecoveryWebAuthnRole;
  readonly authenticatorClass: PhilCoreConsumerRecoveryAuthenticatorClass;
  readonly authenticatorAttachment: "platform" | "cross-platform";
  readonly residentKey: "required";
  readonly userVerification: "required";
  readonly attestation: "direct";
  readonly backupPolicy: "DEVICE_BOUND_REQUIRED";
}

export interface PhilCoreConsumerRecoveryEnrollmentObservation {
  readonly role: PhilCoreConsumerRecoveryWebAuthnRole;
  readonly authenticatorClass: PhilCoreConsumerRecoveryAuthenticatorClass;
  readonly registrationVerified: boolean;
  readonly productionVerified: boolean;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly credentialPublicKeySpki: Hex;
  readonly credentialId: Uint8Array;
  readonly rpId: string;
  readonly origin: string;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  readonly attestationVerified: boolean;
  readonly enrollmentCeremonyHash: Hex;
  readonly attestationEvidenceHash: Hex;
  readonly custodyDomainCommitment: Hex;
  readonly credentialGeneration: bigint;
  readonly storeCredentialId: (input: {
    readonly role: PhilCoreConsumerRecoveryWebAuthnRole;
    readonly credentialId: Uint8Array;
    readonly credentialIdHash: Hex;
  }) => string;
}

export interface PhilCoreConsumerRecoveryEnrollmentResult {
  readonly deployable: true;
  readonly factor: PhilCoreV2ConsumerRecoveryFactor;
  readonly commitmentInput: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly credentialIdHash: Hex;
  readonly secureStorageReference: string;
  readonly cryptographicallyEnforced: readonly string[];
  readonly locallyObserved: readonly string[];
  readonly userAttested: readonly string[];
  readonly warnings: readonly string[];
}

export interface PhilCoreOfflineRecoveryExport {
  readonly classification: "PRIVATE_RECOVERY_AUTHORITY";
  readonly formatVersion: 1;
  readonly recoveryCode: string;
  readonly qrPayload: string;
  readonly warning: string;
}

export interface PhilCoreOfflineRecoveryEnrollmentResult {
  readonly factor: PhilCoreV2ConsumerRecoveryFactor;
  readonly signer: string;
  readonly export: PhilCoreOfflineRecoveryExport;
  readonly restorationCheck: {
    readonly signer: string;
    readonly publicVerificationMaterialHash: Hex;
    readonly matched: true;
  };
  readonly normalDeviceVaultStoragePermitted: false;
}

export function consumerRecoveryRegistrationPolicy(input: {
  readonly role: PhilCoreConsumerRecoveryWebAuthnRole;
  readonly authenticatorClass: PhilCoreConsumerRecoveryAuthenticatorClass;
}): PhilCoreConsumerRecoveryRegistrationPolicy {
  const primary =
    input.role === PHILCORE_V2_CONSUMER_RECOVERY_ROLE.PRIMARY_DEVICE
    && input.authenticatorClass
      === PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE;
  const secondaryPlatform =
    input.role === PHILCORE_V2_CONSUMER_RECOVERY_ROLE.SECONDARY_AUTHENTICATOR
    && input.authenticatorClass
      === PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.SECONDARY_PLATFORM_DEVICE;
  const hardware =
    input.role === PHILCORE_V2_CONSUMER_RECOVERY_ROLE.SECONDARY_AUTHENTICATOR
    && input.authenticatorClass
      === PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY;
  if (!primary && !secondaryPlatform && !hardware) {
    throw new Error("consumer_recovery_role_authenticator_class_invalid");
  }
  return Object.freeze({
    role: input.role,
    authenticatorClass: input.authenticatorClass,
    authenticatorAttachment: hardware ? "cross-platform" : "platform",
    residentKey: "required",
    userVerification: "required",
    attestation: "direct",
    backupPolicy: "DEVICE_BOUND_REQUIRED"
  });
}

function p256CoordinatesFromSpki(spki: Hex): { readonly qx: Hex; readonly qy: Hex } {
  const bytes = getBytes(spki);
  if (bytes.length !== 91 || bytes[26] !== 4) {
    throw new Error("credential_public_key_must_be_p256_spki");
  }
  return {
    qx: hexlify(bytes.slice(27, 59)) as Hex,
    qy: hexlify(bytes.slice(59, 91)) as Hex
  };
}

function validateEnrollmentObservation(
  input: PhilCoreConsumerRecoveryWebAuthnFactorDescriptorObservation
): void {
  consumerRecoveryRegistrationPolicy(input);
  if (
    !input.registrationVerified
    || !input.productionVerified
    || !input.userPresent
    || !input.userVerified
    || !input.attestationVerified
  ) throw new Error("consumer_recovery_registration_not_production_verified");
  if (input.credentialId.byteLength < 16) {
    throw new Error("consumer_recovery_credential_id_too_short");
  }
  if (!input.rpId || !input.origin) {
    throw new Error("consumer_recovery_rp_or_origin_missing");
  }
  if (input.backupEligible || input.backupState) {
    throw new Error("synced_or_backup_eligible_recovery_credential_prohibited");
  }
  if (input.credentialGeneration <= 0n) {
    throw new Error("credential_generation_must_be_positive");
  }
}

export type PhilCoreConsumerRecoveryWebAuthnFactorDescriptorObservation =
  Omit<PhilCoreConsumerRecoveryEnrollmentObservation, "storeCredentialId">;

export interface PhilCoreConsumerRecoveryWebAuthnFactorDescriptorResult {
  readonly factor: PhilCoreV2ConsumerRecoveryFactor;
  readonly commitmentInput: PhilCoreV2RecoveryFactorDescriptorInput;
  readonly credentialIdHash: Hex;
}

export function buildConsumerRecoveryWebAuthnFactorDescriptor(
  input: PhilCoreConsumerRecoveryWebAuthnFactorDescriptorObservation
): PhilCoreConsumerRecoveryWebAuthnFactorDescriptorResult {
  validateEnrollmentObservation(input);
  const credentialIdHash = keccak256(input.credentialId) as Hex;
  const publicMaterial = p256CoordinatesFromSpki(input.credentialPublicKeySpki);
  const independence: PhilCoreV2ConsumerRecoveryIndependenceInput = {
    bindingVersion: PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
    role: input.role,
    authenticatorClass: input.authenticatorClass,
    synchronizationClass: PHILCORE_V2_CONSUMER_SYNC_CLASS.DEVICE_BOUND,
    independenceAssurance:
      PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.ENFORCED,
    credentialIdHash,
    enrollmentCeremonyHash: input.enrollmentCeremonyHash,
    attestationEvidenceHash: input.attestationEvidenceHash,
    custodyDomainCommitment: input.custodyDomainCommitment,
    credentialGeneration: input.credentialGeneration
  };
  const hardware =
    input.authenticatorClass
      === PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY;
  const descriptor: PhilCoreV2RecoveryFactorDescriptorInput = {
    descriptorVersion: PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    role: input.role,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash(publicMaterial),
    credentialIdHash,
    rpIdHash: sha256(toUtf8Bytes(input.rpId)) as Hex,
    originPolicyHash: keccak256(toUtf8Bytes(input.origin)) as Hex,
    independenceBindingHash:
      computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED,
    authenticatorAttachmentPolicy: hardware
      ? PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED
      : PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    attestationPolicy: hardware
      ? PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE
      : PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND,
    credentialGeneration: input.credentialGeneration
  };
  return Object.freeze({
    factor: Object.freeze({ descriptor, independence }),
    commitmentInput: descriptor,
    credentialIdHash
  });
}

export function finalizeConsumerRecoveryWebAuthnEnrollment(
  input: PhilCoreConsumerRecoveryEnrollmentObservation
): PhilCoreConsumerRecoveryEnrollmentResult {
  const { factor, commitmentInput, credentialIdHash } =
    buildConsumerRecoveryWebAuthnFactorDescriptor(input);
  const hardware =
    commitmentInput.authenticatorAttachmentPolicy
      === PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED;
  const secureStorageReference = input.storeCredentialId({
    role: input.role,
    credentialId: input.credentialId.slice(),
    credentialIdHash
  });
  if (!secureStorageReference) {
    throw new Error("secure_credential_storage_reference_required");
  }
  return Object.freeze({
    deployable: true,
    factor,
    commitmentInput,
    credentialIdHash,
    secureStorageReference,
    cryptographicallyEnforced: Object.freeze([
      "distinct credential public material and identifier commitment",
      "RP ID, origin policy, role, account/security version and generation",
      "user verification, device-bound backup flags and descriptor commitment"
    ]),
    locallyObserved: Object.freeze([
      hardware ? "cross-platform attachment" : "platform attachment",
      "backup eligibility and backup state were both false",
      "approved attestation evidence was verified"
    ]),
    userAttested: Object.freeze([
      "custody domain is independently controlled",
      "credential is not restored from the primary cloud or password-manager domain"
    ]),
    warnings: Object.freeze([
      "WebAuthn cannot prove separate Apple, Google, password-manager, or cloud-backup accounts."
    ])
  });
}

function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value: string): Uint8Array {
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const character of value) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("offline_recovery_code_invalid_base32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}

function offlineChecksum(entropy: Uint8Array): string {
  return encodeBase32(getBytes(keccak256(entropy)).slice(0, 5));
}

function formatOfflineCode(entropy: Uint8Array): string {
  const body = encodeBase32(entropy);
  const groups = body.match(/.{1,4}/g) ?? [];
  return `${OFFLINE_FORMAT_PREFIX}-${groups.join("-")}-${offlineChecksum(entropy)}`;
}

function parseOfflineCode(code: string): Uint8Array {
  const normalized = code.trim().toUpperCase();
  const prefix = `${OFFLINE_FORMAT_PREFIX}-`;
  if (!normalized.startsWith(prefix)) {
    throw new Error("offline_recovery_code_version_invalid");
  }
  const segments = normalized.slice(prefix.length).split("-");
  if (segments.length < 2) throw new Error("offline_recovery_code_malformed");
  const checksum = segments.pop()!;
  const entropy = decodeBase32(segments.join(""));
  if (entropy.byteLength !== 32 || checksum !== offlineChecksum(entropy)) {
    throw new Error("offline_recovery_code_checksum_invalid");
  }
  return entropy;
}

function deriveOfflinePrivateKey(entropy: Uint8Array): Hex {
  const digest = BigInt(keccak256(
    new Uint8Array([...getBytes(OFFLINE_DERIVATION_DOMAIN), ...entropy])
  ));
  return toBeHex((digest % (SECP256K1_ORDER - 1n)) + 1n, 32) as Hex;
}

export function inspectOfflineRecoveryExport(
  recoveryCode: string
): {
  readonly signer: string;
  readonly publicVerificationMaterialHash: Hex;
} {
  const entropy = parseOfflineCode(recoveryCode);
  const privateKey = deriveOfflinePrivateKey(entropy);
  const signer = computeAddress(new SigningKey(privateKey).publicKey);
  return Object.freeze({
    signer,
    publicVerificationMaterialHash:
      computePhilCoreV2Secp256k1PublicMaterialHash({ signer })
  });
}

export function enrollOfflineRecoveryFactor(input: {
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly custodyDomainCommitment: Hex;
  readonly enrollmentCeremonyHash: Hex;
  readonly credentialGeneration: bigint;
  readonly executionValidator: string;
}): PhilCoreOfflineRecoveryEnrollmentResult {
  const randomBytes = input.randomBytes ?? ((length: number) => {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  });
  const entropy = randomBytes(32);
  if (entropy.byteLength !== 32 || entropy.every((byte) => byte === 0)) {
    throw new Error("offline_recovery_entropy_invalid");
  }
  const recoveryCode = formatOfflineCode(entropy);
  const restored = inspectOfflineRecoveryExport(recoveryCode);
  if (restored.signer.toLowerCase() === input.executionValidator.toLowerCase()) {
    throw new Error("execution_validator_cannot_be_offline_recovery_factor");
  }
  const independence: PhilCoreV2ConsumerRecoveryIndependenceInput = {
    bindingVersion: PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
    role: PHILCORE_V2_CONSUMER_RECOVERY_ROLE.OFFLINE_RECOVERY_FACTOR,
    authenticatorClass:
      PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.OFFLINE_SECP256K1_EXPORT,
    synchronizationClass: PHILCORE_V2_CONSUMER_SYNC_CLASS.NOT_APPLICABLE,
    independenceAssurance:
      PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.ENFORCED,
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    enrollmentCeremonyHash: input.enrollmentCeremonyHash,
    attestationEvidenceHash: keccak256(
      toUtf8Bytes("PHILCORE_OFFLINE_EXPORT_SELF_VERIFICATION_V1")
    ) as Hex,
    custodyDomainCommitment: input.custodyDomainCommitment,
    credentialGeneration: input.credentialGeneration
  };
  const descriptor: PhilCoreV2RecoveryFactorDescriptorInput = {
    descriptorVersion: PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    role: PHILCORE_V2_CONSUMER_RECOVERY_ROLE.OFFLINE_RECOVERY_FACTOR,
    verifierKind:
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash: restored.publicVerificationMaterialHash,
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    rpIdHash: PHILCORE_V2_ZERO_BYTES32,
    originPolicyHash: PHILCORE_V2_ZERO_BYTES32,
    independenceBindingHash:
      computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
    userVerificationPolicy: 0,
    backupPolicy: 0,
    authenticatorAttachmentPolicy: 0,
    attestationPolicy: 0,
    credentialGeneration: input.credentialGeneration
  };
  const factor = Object.freeze({
    descriptor,
    independence,
    signer: restored.signer
  });
  return Object.freeze({
    factor,
    signer: restored.signer,
    export: Object.freeze({
      classification: "PRIVATE_RECOVERY_AUTHORITY",
      formatVersion: 1,
      recoveryCode,
      qrPayload: recoveryCode,
      warning:
        "Keep offline, out of normal device backups, and separate from both recovery devices."
    }),
    restorationCheck: Object.freeze({
      ...restored,
      matched: true
    }),
    normalDeviceVaultStoragePermitted: false
  });
}
