import { AbiCoder, hexlify, type BigNumberish, type BytesLike } from "ethers";

import {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  dataHash,
  normalizeBaseActionAuthorization,
  normalizeUnlockProofPackage,
  normalizeUnlockProofPublicInputs,
  normalizeUnlockRequest,
  proofInputHash,
  unlockActionHash,
  type BaseActionAuthorization,
  type UnlockProofPackage,
  type UnlockProofPublicInputs,
  type UnlockRequest
} from "../hashes.ts";
import type { UnlockAuthorizationAssembly } from "../authorization.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

function decodeUnlockConsumerData(consumerData: BytesLike): ReturnType<typeof normalizeUnlockRequest> {
  const [decoded] = abiCoder.decode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    consumerData
  ) as unknown as [UnlockRequest];

  return normalizeUnlockRequest(decoded);
}

function recomputeUnlockActionHash(input: {
  chainId: BigNumberish;
  authorization: BaseActionAuthorization;
  consumerData: BytesLike;
}) {
  const request = decodeUnlockConsumerData(input.consumerData);
  return {
    request,
    actionHash: unlockActionHash({
      chainId: input.chainId,
      consumer: input.authorization.consumer,
      account: request.account,
      target: request.target,
      value: request.value,
      callDataHash: dataHash(request.callData)
    })
  };
}

export function buildUnlockProofPublicInputsFromAuthorization(
  authorization: BaseActionAuthorization
): UnlockProofPublicInputs {
  const normalized = normalizeBaseActionAuthorization(authorization);
  return normalizeUnlockProofPublicInputs({
    ownerCommitment: normalized.ownerCommitment,
    actionHash: normalized.actionHash,
    policyHash: normalized.policyHash,
    nullifier: normalized.nullifier,
    consumerDataHash: normalized.consumerDataHash,
    expiry: normalized.expiry
  });
}

export function buildUnlockProofPublicInputs(
  assembly: UnlockAuthorizationAssembly
): UnlockProofPublicInputs {
  return buildUnlockProofPublicInputsFromAuthorization(assembly.authorization);
}

export function buildUnlockProofPackage(input: {
  publicInputs: UnlockProofPublicInputs;
  version?: string;
  proofType?: string;
  proofBlob?: BytesLike;
}): UnlockProofPackage {
  const version = String(input.version ?? UNLOCK_PROOF_SCHEMA_VERSION).trim();
  const proofType = String(input.proofType ?? UNLOCK_PROOF_TYPE).trim();
  const publicInputs = normalizeUnlockProofPublicInputs(input.publicInputs);

  return normalizeUnlockProofPackage({
    version,
    proofType,
    publicInputs,
    proofInputHash: proofInputHash({
      version,
      proofType,
      publicInputs
    }),
    proofBlob: hexlify(input.proofBlob ?? "0x") as `0x${string}`
  });
}

export function buildUnlockProofPackageFromAuthorization(
  authorization: BaseActionAuthorization,
  overrides: {
    version?: string;
    proofType?: string;
    proofBlob?: BytesLike;
  } = {}
): UnlockProofPackage {
  return buildUnlockProofPackage({
    publicInputs: buildUnlockProofPublicInputsFromAuthorization(authorization),
    ...overrides
  });
}

export function buildUnlockProofPackageFromAssembly(
  assembly: UnlockAuthorizationAssembly,
  overrides: {
    version?: string;
    proofType?: string;
    proofBlob?: BytesLike;
  } = {}
): UnlockProofPackage {
  return buildUnlockProofPackageFromAuthorization(assembly.authorization, overrides);
}

export function assertValidUnlockProofPackage(input: {
  chainId: BigNumberish;
  authorization: BaseActionAuthorization;
  consumerData: BytesLike;
  proofPackage: UnlockProofPackage;
  requireProofArtifact?: boolean;
}) {
  const authorization = normalizeBaseActionAuthorization(input.authorization);
  const consumerData = hexlify(input.consumerData) as `0x${string}`;
  const proofPackage = normalizeUnlockProofPackage(input.proofPackage);

  if (proofPackage.version !== UNLOCK_PROOF_SCHEMA_VERSION) {
    throw new Error(`unsupported proof schema version: ${proofPackage.version}`);
  }
  if (proofPackage.proofType !== UNLOCK_PROOF_TYPE) {
    throw new Error(`unsupported proof type: ${proofPackage.proofType}`);
  }

  const expectedPublicInputs = buildUnlockProofPublicInputsFromAuthorization(authorization);
  const fields = [
    "ownerCommitment",
    "actionHash",
    "policyHash",
    "nullifier",
    "consumerDataHash",
    "expiry"
  ] as const;

  for (const field of fields) {
    if (proofPackage.publicInputs[field] !== expectedPublicInputs[field]) {
      throw new Error(`proof package ${field} does not match authorization`);
    }
  }

  const expectedProofInputHash = proofInputHash({
    version: proofPackage.version,
    proofType: proofPackage.proofType,
    publicInputs: proofPackage.publicInputs
  });
  if (proofPackage.proofInputHash !== expectedProofInputHash) {
    throw new Error("proof package proofInputHash does not match public inputs");
  }

  if (dataHash(consumerData) !== proofPackage.publicInputs.consumerDataHash) {
    throw new Error("consumerData does not match proof package consumerDataHash");
  }

  const { actionHash } = recomputeUnlockActionHash({
    chainId: input.chainId,
    authorization,
    consumerData
  });
  if (actionHash !== proofPackage.publicInputs.actionHash) {
    throw new Error("consumerData does not match proof package actionHash");
  }

  if (proofPackage.proofBlob === "0x" && input.requireProofArtifact === true) {
    throw new Error("proof artifact is required for local verifier integration");
  }

  return {
    authorization,
    consumerData,
    proofPackage,
    expectedPublicInputs,
    expectedProofInputHash,
    proofVerification: false,
    chainSubmissionProofPackage: proofPackage
  };
}
