import { AbiCoder, hexlify, zeroPadValue, type BytesLike } from "ethers";

import {
  DOMAIN_HASHES,
  canonicalOwnerCommitmentFromIdentityRoot,
  identityRootFromPhilSecret,
  normalizeUnlockProofPublicInputs,
  nullifier,
  proofInputHash,
  type Hex,
  type UnlockProofPublicInputs
} from "../../hashes.ts";
import { normalizePhilSecret } from "../../identity.ts";
import { STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION } from "./constants.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

function normalizeBytes32(value: BytesLike): Hex {
  return zeroPadValue(hexlify(value), 32) as Hex;
}

export function encodeIdentityRootPreimage(philSecret: BytesLike): Hex {
  return abiCoder.encode(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.identityRoot, normalizePhilSecret(philSecret)]
  ) as Hex;
}

export function encodeOwnerCommitmentPreimage(identityRoot: BytesLike): Hex {
  return abiCoder.encode(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.canonicalOwnerCommitment, normalizeBytes32(identityRoot)]
  ) as Hex;
}

export function encodeNullifierPreimage(input: {
  ownerCommitment: BytesLike;
  actionHash: BytesLike;
  policyHash: BytesLike;
  nullifierSeed: BytesLike;
}): Hex {
  return abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      DOMAIN_HASHES.nullifier,
      normalizeBytes32(input.ownerCommitment),
      normalizeBytes32(input.actionHash),
      normalizeBytes32(input.policyHash),
      normalizeBytes32(input.nullifierSeed)
    ]
  ) as Hex;
}

export function encodeUnlockProofInputPreimage(input: {
  version?: string;
  proofType?: string;
  publicInputs: UnlockProofPublicInputs;
}): Hex {
  const version = String(input.version ?? STWO_UNLOCK_PROOF_VERSION).trim();
  const proofType = String(input.proofType ?? STWO_UNLOCK_PROOF_TYPE).trim();
  const normalized = normalizeUnlockProofPublicInputs(input.publicInputs);

  return abiCoder.encode(
    ["bytes32", "string", "string", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
    [
      DOMAIN_HASHES.unlockProofInputs,
      version,
      proofType,
      normalized.ownerCommitment,
      normalized.actionHash,
      normalized.policyHash,
      normalized.nullifier,
      normalized.consumerDataHash,
      BigInt(normalized.expiry)
    ]
  ) as Hex;
}

export interface UnlockKeccakFixtureVector {
  version: string;
  proofType: string;
  publicInputs: UnlockProofPublicInputs;
  philSecret: Hex;
  identityRootPreimage: Hex;
  identityRootHash: Hex;
  ownerCommitmentPreimage: Hex;
  ownerCommitmentHash: Hex;
  nullifierSeed: Hex;
  nullifierPreimage: Hex;
  nullifierHash: Hex;
  proofInputHashPreimage: Hex;
  proofInputHashValue: Hex;
}

export function buildUnlockKeccakFixtureVector(input: {
  philSecret: BytesLike;
  actionHash: BytesLike;
  policyHash: BytesLike;
  nullifierSeed: BytesLike;
  consumerDataHash: BytesLike;
  expiry: bigint;
  version?: string;
  proofType?: string;
}): UnlockKeccakFixtureVector {
  const version = String(input.version ?? STWO_UNLOCK_PROOF_VERSION).trim();
  const proofType = String(input.proofType ?? STWO_UNLOCK_PROOF_TYPE).trim();
  const philSecret = normalizePhilSecret(input.philSecret);
  const identityRootHash = identityRootFromPhilSecret(philSecret);
  const ownerCommitmentHash = canonicalOwnerCommitmentFromIdentityRoot(identityRootHash);
  const normalizedNullifierSeed = normalizeBytes32(input.nullifierSeed);
  const nullifierHash = nullifier({
    ownerCommitment: ownerCommitmentHash,
    actionHash: input.actionHash,
    policyHash: input.policyHash,
    nullifierSeed: normalizedNullifierSeed
  });
  const publicInputs = normalizeUnlockProofPublicInputs({
    ownerCommitment: ownerCommitmentHash,
    actionHash: normalizeBytes32(input.actionHash),
    policyHash: normalizeBytes32(input.policyHash),
    nullifier: nullifierHash,
    consumerDataHash: normalizeBytes32(input.consumerDataHash),
    expiry: BigInt(input.expiry)
  });

  return {
    version,
    proofType,
    publicInputs,
    philSecret,
    identityRootPreimage: encodeIdentityRootPreimage(philSecret),
    identityRootHash,
    ownerCommitmentPreimage: encodeOwnerCommitmentPreimage(identityRootHash),
    ownerCommitmentHash,
    nullifierSeed: normalizedNullifierSeed,
    nullifierPreimage: encodeNullifierPreimage({
      ownerCommitment: ownerCommitmentHash,
      actionHash: publicInputs.actionHash,
      policyHash: publicInputs.policyHash,
      nullifierSeed: normalizedNullifierSeed
    }),
    nullifierHash,
    proofInputHashPreimage: encodeUnlockProofInputPreimage({
      version,
      proofType,
      publicInputs
    }),
    proofInputHashValue: proofInputHash({
      version,
      proofType,
      publicInputs
    })
  };
}
