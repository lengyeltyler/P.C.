import {
  AbiCoder,
  getAddress,
  hexlify,
  keccak256,
  toUtf8Bytes,
  zeroPadValue,
  type BigNumberish,
  type BytesLike
} from "ethers";

const abiCoder = AbiCoder.defaultAbiCoder();

export type Hex = `0x${string}`;

export const DOMAIN_LABELS = {
  legacyOwnerCommitment: "PHIL_OWNER_COMMITMENT_V1",
  identityRoot: "PHIL_IDENTITY_ROOT_V1",
  canonicalOwnerCommitment: "PHIL_OWNER_COMMITMENT_CANONICAL_V1",
  worldSignal: "PHIL_WORLD_SIGNAL_V1",
  actionUnlock: "PHIL_ACTION_UNLOCK_V1",
  policy: "PHIL_POLICY_V1",
  nullifier: "PHIL_NULLIFIER_V1",
  baseAuthorization: "PHIL_BASE_AUTHORIZATION_V1",
  unlockProofInputs: "PHIL_UNLOCK_PROOF_INPUTS_V1",
  worldIdBinding: "PHIL_WORLD_ID_BINDING_V1"
} as const;

export const DOMAIN_HASHES = {
  legacyOwnerCommitment: keccak256(toUtf8Bytes(DOMAIN_LABELS.legacyOwnerCommitment)),
  identityRoot: keccak256(toUtf8Bytes(DOMAIN_LABELS.identityRoot)),
  canonicalOwnerCommitment: keccak256(toUtf8Bytes(DOMAIN_LABELS.canonicalOwnerCommitment)),
  worldSignal: keccak256(toUtf8Bytes(DOMAIN_LABELS.worldSignal)),
  actionUnlock: keccak256(toUtf8Bytes(DOMAIN_LABELS.actionUnlock)),
  policy: keccak256(toUtf8Bytes(DOMAIN_LABELS.policy)),
  nullifier: keccak256(toUtf8Bytes(DOMAIN_LABELS.nullifier)),
  baseAuthorization: keccak256(toUtf8Bytes(DOMAIN_LABELS.baseAuthorization)),
  unlockProofInputs: keccak256(toUtf8Bytes(DOMAIN_LABELS.unlockProofInputs)),
  worldIdBinding: keccak256(toUtf8Bytes(DOMAIN_LABELS.worldIdBinding))
} as const;

export const UNLOCK_PROOF_SCHEMA_VERSION = "v1" as const;
export const UNLOCK_PROOF_TYPE = "stwo-unlock-keccak-v1" as const;

export interface BaseActionAuthorization {
  consumer: string;
  ownerCommitment: Hex;
  actionHash: Hex;
  policyHash: Hex;
  nullifier: Hex;
  consumerDataHash: Hex;
  expiry: BigNumberish;
}

export interface UnlockRequest {
  account: string;
  target: string;
  value: BigNumberish;
  callData: BytesLike;
}

export interface UnlockProofPublicInputs {
  ownerCommitment: Hex;
  actionHash: Hex;
  policyHash: Hex;
  nullifier: Hex;
  consumerDataHash: Hex;
  expiry: BigNumberish;
}

export interface UnlockProofPackage {
  version: string;
  proofType: string;
  publicInputs: UnlockProofPublicInputs;
  proofInputHash: Hex;
  proofBlob: Hex;
}

function hashAbiEncoded(types: readonly string[], values: readonly unknown[]): Hex {
  return keccak256(abiCoder.encode([...types], [...values])) as Hex;
}

function normalizeBytes32(value: BytesLike): Hex {
  return zeroPadValue(hexlify(value), 32) as Hex;
}

function normalizeBytes(value: BytesLike): Hex {
  return hexlify(value) as Hex;
}

export function dataHash(data: BytesLike): Hex {
  return keccak256(data) as Hex;
}

export function legacyOwnerCommitmentFromAddressSalt(owner: string, salt: BytesLike): Hex {
  return hashAbiEncoded(
    ["bytes32", "address", "bytes32"],
    [DOMAIN_HASHES.legacyOwnerCommitment, getAddress(owner), normalizeBytes32(salt)]
  );
}

export function identityRootFromPhilSecret(philSecret: BytesLike): Hex {
  return hashAbiEncoded(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.identityRoot, normalizeBytes32(philSecret)]
  );
}

export function canonicalOwnerCommitmentFromIdentityRoot(identityRoot: BytesLike): Hex {
  return hashAbiEncoded(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.canonicalOwnerCommitment, normalizeBytes32(identityRoot)]
  );
}

export function worldSignal(input: {
  ownerCommitment: BytesLike;
  appId: string;
  action: string;
}): Hex {
  return hashAbiEncoded(
    ["bytes32", "bytes32", "string", "string"],
    [
      DOMAIN_HASHES.worldSignal,
      normalizeBytes32(input.ownerCommitment),
      String(input.appId),
      String(input.action)
    ]
  );
}

export function unlockActionHash(input: {
  chainId: BigNumberish;
  consumer: string;
  account: string;
  target: string;
  value: BigNumberish;
  callDataHash: BytesLike;
}): Hex {
  return hashAbiEncoded(
    ["bytes32", "uint256", "address", "address", "address", "uint256", "bytes32"],
    [
      DOMAIN_HASHES.actionUnlock,
      BigInt(input.chainId),
      getAddress(input.consumer),
      getAddress(input.account),
      getAddress(input.target),
      BigInt(input.value),
      normalizeBytes32(input.callDataHash)
    ]
  );
}

export function policyHash(input: {
  chainId: BigNumberish;
  consumer: string;
  target: string;
  expiry: BigNumberish;
  policyDataHash: BytesLike;
}): Hex {
  return hashAbiEncoded(
    ["bytes32", "uint256", "address", "address", "uint64", "bytes32"],
    [
      DOMAIN_HASHES.policy,
      BigInt(input.chainId),
      getAddress(input.consumer),
      getAddress(input.target),
      BigInt(input.expiry),
      normalizeBytes32(input.policyDataHash)
    ]
  );
}

export function nullifier(input: {
  ownerCommitment: BytesLike;
  actionHash: BytesLike;
  policyHash: BytesLike;
  nullifierSeed: BytesLike;
}): Hex {
  return hashAbiEncoded(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      DOMAIN_HASHES.nullifier,
      normalizeBytes32(input.ownerCommitment),
      normalizeBytes32(input.actionHash),
      normalizeBytes32(input.policyHash),
      normalizeBytes32(input.nullifierSeed)
    ]
  );
}

export function authorizationDigest(authorization: BaseActionAuthorization): Hex {
  const normalized = normalizeBaseActionAuthorization(authorization);
  return hashAbiEncoded(
    ["bytes32", "address", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
    [
      DOMAIN_HASHES.baseAuthorization,
      normalized.consumer,
      normalized.ownerCommitment,
      normalized.actionHash,
      normalized.policyHash,
      normalized.nullifier,
      normalized.consumerDataHash,
      BigInt(normalized.expiry)
    ]
  );
}

export function proofInputHash(input: {
  version: string;
  proofType: string;
  publicInputs: UnlockProofPublicInputs;
}): Hex {
  const normalized = normalizeUnlockProofPublicInputs(input.publicInputs);
  return hashAbiEncoded(
    ["bytes32", "string", "string", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
    [
      DOMAIN_HASHES.unlockProofInputs,
      String(input.version),
      String(input.proofType),
      normalized.ownerCommitment,
      normalized.actionHash,
      normalized.policyHash,
      normalized.nullifier,
      normalized.consumerDataHash,
      BigInt(normalized.expiry)
    ]
  );
}

export function worldIdBindingHash(input: {
  ownerCommitment: BytesLike;
  signal: BytesLike;
  nullifierHash: BytesLike;
  appId: string;
  action: string;
  verificationLevel: string;
}): Hex {
  return hashAbiEncoded(
    ["bytes32", "bytes32", "bytes32", "bytes32", "string", "string", "string"],
    [
      DOMAIN_HASHES.worldIdBinding,
      normalizeBytes32(input.ownerCommitment),
      normalizeBytes32(input.signal),
      normalizeBytes32(input.nullifierHash),
      String(input.appId),
      String(input.action),
      String(input.verificationLevel)
    ]
  );
}

export function normalizeUnlockRequest(request: UnlockRequest) {
  return {
    account: getAddress(request.account),
    target: getAddress(request.target),
    value: BigInt(request.value),
    callData: normalizeBytes(request.callData)
  };
}

export function normalizeUnlockProofPublicInputs(
  publicInputs: UnlockProofPublicInputs
): UnlockProofPublicInputs {
  return {
    ownerCommitment: normalizeBytes32(publicInputs.ownerCommitment),
    actionHash: normalizeBytes32(publicInputs.actionHash),
    policyHash: normalizeBytes32(publicInputs.policyHash),
    nullifier: normalizeBytes32(publicInputs.nullifier),
    consumerDataHash: normalizeBytes32(publicInputs.consumerDataHash),
    expiry: BigInt(publicInputs.expiry)
  };
}

export function normalizeUnlockProofPackage(proofPackage: UnlockProofPackage): UnlockProofPackage {
  const publicInputs = normalizeUnlockProofPublicInputs(proofPackage.publicInputs);
  const version = String(proofPackage.version ?? "").trim();
  const proofType = String(proofPackage.proofType ?? "").trim();
  const normalizedProofInputHash = normalizeBytes32(proofPackage.proofInputHash);

  return {
    version,
    proofType,
    publicInputs,
    proofInputHash: normalizedProofInputHash,
    proofBlob: normalizeBytes(proofPackage.proofBlob ?? "0x")
  };
}

export function normalizeBaseActionAuthorization(
  authorization: BaseActionAuthorization
): BaseActionAuthorization {
  return {
    consumer: getAddress(authorization.consumer),
    ownerCommitment: normalizeBytes32(authorization.ownerCommitment),
    actionHash: normalizeBytes32(authorization.actionHash),
    policyHash: normalizeBytes32(authorization.policyHash),
    nullifier: normalizeBytes32(authorization.nullifier),
    consumerDataHash: normalizeBytes32(authorization.consumerDataHash),
    expiry: BigInt(authorization.expiry)
  };
}
