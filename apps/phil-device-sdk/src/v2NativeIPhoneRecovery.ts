import {
  AbiCoder,
  isHexString,
  keccak256,
  sha256,
  toUtf8Bytes,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import { PHILCORE_V2_RECOVERY_VERIFIER_KIND } from "./v2Authorization.ts";
import { PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID } from "./v2ConsumerRecovery.ts";
import { PHILCORE_V2_SECURITY_MODEL_ID } from "./v2Intent.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHILCORE_NATIVE_IPHONE_ROLE1 = Object.freeze({
  descriptorVersion: 1,
  role: 1,
  verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.NATIVE_DEVICE_P256,
  recoveryDomain:
    "PHILCORE_NATIVE_DEVICE_P256_ROLE1_V1",
  applicationIdentity:
    "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha",
  localApprovalPolicy:
    "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST",
  appAttestStatus: "DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION"
} as const);

export const PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID =
  keccak256(toUtf8Bytes(
    PHILCORE_NATIVE_IPHONE_ROLE1.recoveryDomain
  )) as Hex;

export const PHILCORE_NATIVE_IPHONE_TYPE = Object.freeze({
  PUBLIC_MATERIAL:
    "PhilCoreV2NativeDeviceP256PublicMaterial(bytes32 qx,bytes32 qy)",
  DESCRIPTOR:
    "PhilCoreV2NativeDeviceP256DescriptorV1(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdentifierCommitment,bytes32 applicationIdentityHash,bytes32 deviceCustodyCommitment,bytes32 localApprovalPolicyHash,bytes32 appAttestCommitment,uint64 credentialGeneration,bool secureEnclaveRequired,bool simulatorCredential)"
} as const);

export const PHILCORE_NATIVE_IPHONE_TYPEHASH = Object.freeze({
  PUBLIC_MATERIAL:
    keccak256(toUtf8Bytes(PHILCORE_NATIVE_IPHONE_TYPE.PUBLIC_MATERIAL)) as Hex,
  DESCRIPTOR:
    keccak256(toUtf8Bytes(PHILCORE_NATIVE_IPHONE_TYPE.DESCRIPTOR)) as Hex
});

export const PHILCORE_NATIVE_IPHONE_DESCRIPTOR_TUPLE =
  "tuple(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdentifierCommitment,bytes32 applicationIdentityHash,bytes32 deviceCustodyCommitment,bytes32 localApprovalPolicyHash,bytes32 appAttestCommitment,uint64 credentialGeneration,bool secureEnclaveRequired,bool simulatorCredential)" as const;

export const PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE =
  `tuple(${PHILCORE_NATIVE_IPHONE_DESCRIPTOR_TUPLE} descriptor,bytes32 factorCommitment,bytes32 qx,bytes32 qy,bytes32 r,bytes32 s)` as const;

export interface PhilCoreNativeIPhoneDescriptorV1 {
  readonly descriptorVersion: BigNumberish;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly recoveryDomainId: Hex;
  readonly role: BigNumberish;
  readonly verifierKind: BigNumberish;
  readonly publicVerificationMaterialHash: Hex;
  readonly credentialIdentifierCommitment: Hex;
  readonly applicationIdentityHash: Hex;
  readonly deviceCustodyCommitment: Hex;
  readonly localApprovalPolicyHash: Hex;
  readonly appAttestCommitment: Hex;
  readonly credentialGeneration: BigNumberish;
  readonly secureEnclaveRequired: boolean;
  readonly simulatorCredential: boolean;
}

export interface PhilCoreNativeIPhoneEvidenceV1 {
  readonly descriptor: PhilCoreNativeIPhoneDescriptorV1;
  readonly factorCommitment: Hex;
  readonly qx: Hex;
  readonly qy: Hex;
  readonly r: Hex;
  readonly s: Hex;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === `0x${"00".repeat(32)}`) {
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

export function computePhilCoreNativeP256PublicMaterialHash(input: {
  readonly qx: Hex;
  readonly qy: Hex;
}): Hex {
  const qx = bytes32(input.qx, "qx");
  const qy = bytes32(input.qy, "qy");
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32"],
    [PHILCORE_NATIVE_IPHONE_TYPEHASH.PUBLIC_MATERIAL, qx, qy]
  )) as Hex;
}

export function applicationIdentityHash(
  applicationIdentity = PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity
): Hex {
  if (applicationIdentity !== PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity) {
    throw new Error("native_application_identity_unsupported");
  }
  return sha256(toUtf8Bytes(applicationIdentity)) as Hex;
}

export function localApprovalPolicyHash(
  policy = PHILCORE_NATIVE_IPHONE_ROLE1.localApprovalPolicy
): Hex {
  if (policy !== PHILCORE_NATIVE_IPHONE_ROLE1.localApprovalPolicy) {
    throw new Error("native_local_approval_policy_unsupported");
  }
  return sha256(toUtf8Bytes(policy)) as Hex;
}

export function normalizePhilCoreNativeIPhoneDescriptor(
  input: PhilCoreNativeIPhoneDescriptorV1,
  options: { readonly simulatorTest?: boolean } = {}
): PhilCoreNativeIPhoneDescriptorV1 {
  const exact = (value: BigNumberish, expected: number, label: string) => {
    const parsed = uint(value, 8, label);
    if (parsed !== BigInt(expected)) throw new Error(`${label}_unsupported`);
    return parsed;
  };
  const generation = uint(input.credentialGeneration, 64, "credentialGeneration");
  if (generation === 0n) throw new Error("credentialGeneration_must_be_nonzero");
  const simulatorTest = options.simulatorTest === true;
  if (simulatorTest) {
    if (!input.simulatorCredential || input.secureEnclaveRequired) {
      throw new Error("simulator_descriptor_class_invalid");
    }
  } else if (input.simulatorCredential || !input.secureEnclaveRequired) {
    throw new Error("production_descriptor_requires_secure_enclave");
  }
  const accountVersionId = bytes32(input.accountVersionId, "accountVersionId");
  const securityModelId = bytes32(input.securityModelId, "securityModelId");
  const recoveryDomainId = bytes32(input.recoveryDomainId, "recoveryDomainId");
  const exactApplicationIdentityHash =
    bytes32(input.applicationIdentityHash, "applicationIdentityHash");
  const exactLocalApprovalPolicyHash =
    bytes32(input.localApprovalPolicyHash, "localApprovalPolicyHash");
  if (
    accountVersionId !== PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID.toLowerCase()
  ) throw new Error("accountVersionId_unsupported");
  if (securityModelId !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    throw new Error("securityModelId_unsupported");
  }
  if (recoveryDomainId !== PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID.toLowerCase()) {
    throw new Error("recoveryDomainId_unsupported");
  }
  if (exactApplicationIdentityHash !== applicationIdentityHash()) {
    throw new Error("applicationIdentityHash_unsupported");
  }
  if (exactLocalApprovalPolicyHash !== localApprovalPolicyHash()) {
    throw new Error("localApprovalPolicyHash_unsupported");
  }
  return Object.freeze({
    descriptorVersion: exact(input.descriptorVersion, 1, "descriptorVersion"),
    accountVersionId,
    securityModelId,
    recoveryDomainId,
    role: exact(input.role, 1, "role"),
    verifierKind: exact(
      input.verifierKind,
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.NATIVE_DEVICE_P256,
      "verifierKind"
    ),
    publicVerificationMaterialHash:
      bytes32(input.publicVerificationMaterialHash, "publicVerificationMaterialHash"),
    credentialIdentifierCommitment:
      bytes32(input.credentialIdentifierCommitment, "credentialIdentifierCommitment"),
    applicationIdentityHash: exactApplicationIdentityHash,
    deviceCustodyCommitment:
      bytes32(input.deviceCustodyCommitment, "deviceCustodyCommitment"),
    localApprovalPolicyHash: exactLocalApprovalPolicyHash,
    appAttestCommitment:
      bytes32(input.appAttestCommitment, "appAttestCommitment", true),
    credentialGeneration: generation,
    secureEnclaveRequired: input.secureEnclaveRequired,
    simulatorCredential: input.simulatorCredential
  });
}

export function computePhilCoreNativeIPhoneFactorCommitment(
  input: PhilCoreNativeIPhoneDescriptorV1,
  options: { readonly simulatorTest?: boolean } = {}
): Hex {
  const descriptor = normalizePhilCoreNativeIPhoneDescriptor(input, options);
  return keccak256(abiCoder.encode(
    [
      "bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint8", "uint8",
      "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
      "uint64", "bool", "bool"
    ],
    [
      PHILCORE_NATIVE_IPHONE_TYPEHASH.DESCRIPTOR,
      descriptor.descriptorVersion,
      descriptor.accountVersionId,
      descriptor.securityModelId,
      descriptor.recoveryDomainId,
      descriptor.role,
      descriptor.verifierKind,
      descriptor.publicVerificationMaterialHash,
      descriptor.credentialIdentifierCommitment,
      descriptor.applicationIdentityHash,
      descriptor.deviceCustodyCommitment,
      descriptor.localApprovalPolicyHash,
      descriptor.appAttestCommitment,
      descriptor.credentialGeneration,
      descriptor.secureEnclaveRequired,
      descriptor.simulatorCredential
    ]
  )) as Hex;
}

export function buildPhilCoreNativeIPhoneDescriptor(input: {
  readonly qx: Hex;
  readonly qy: Hex;
  readonly credentialIdentifierCommitment: Hex;
  readonly deviceCustodyCommitment: Hex;
  readonly generation: BigNumberish;
  readonly appAttestCommitment?: Hex;
  readonly simulatorTest?: boolean;
}): PhilCoreNativeIPhoneDescriptorV1 {
  const simulatorTest = input.simulatorTest === true;
  return normalizePhilCoreNativeIPhoneDescriptor({
    descriptorVersion: 1,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_NATIVE_IPHONE_RECOVERY_DOMAIN_ID,
    role: 1,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.NATIVE_DEVICE_P256,
    publicVerificationMaterialHash:
      computePhilCoreNativeP256PublicMaterialHash(input),
    credentialIdentifierCommitment: input.credentialIdentifierCommitment,
    applicationIdentityHash: applicationIdentityHash(),
    deviceCustodyCommitment: input.deviceCustodyCommitment,
    localApprovalPolicyHash: localApprovalPolicyHash(),
    appAttestCommitment:
      input.appAttestCommitment || `0x${"00".repeat(32)}`,
    credentialGeneration: input.generation,
    secureEnclaveRequired: !simulatorTest,
    simulatorCredential: simulatorTest
  }, { simulatorTest });
}

export function encodePhilCoreNativeIPhoneEvidence(
  input: PhilCoreNativeIPhoneEvidenceV1
): Hex {
  const descriptor = normalizePhilCoreNativeIPhoneDescriptor(input.descriptor);
  const factorCommitment = bytes32(input.factorCommitment, "factorCommitment");
  if (factorCommitment !== computePhilCoreNativeIPhoneFactorCommitment(descriptor)) {
    throw new Error("native_factor_commitment_mismatch");
  }
  return abiCoder.encode(
    [PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE],
    [[
      descriptor,
      factorCommitment,
      bytes32(input.qx, "qx"),
      bytes32(input.qy, "qy"),
      bytes32(input.r, "r"),
      bytes32(input.s, "s")
    ]]
  ) as Hex;
}
