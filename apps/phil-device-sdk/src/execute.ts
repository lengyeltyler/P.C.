import { hexlify, type BigNumberish, type BytesLike } from "ethers";

import {
  normalizeBaseActionAuthorization,
  normalizeUnlockProofPackage,
  type BaseActionAuthorization,
  type UnlockProofPackage
} from "./hashes.ts";
import { assertValidUnlockProofPackage } from "./proof/publicInputs.ts";

export interface UnlockExecutionPayload {
  chainId: bigint;
  authorization: BaseActionAuthorization;
  proofPackage: UnlockProofPackage;
  consumerData: `0x${string}`;
  value: bigint;
}

export function assembleUnlockExecutionPayload(input: {
  chainId: BigNumberish;
  authorization: BaseActionAuthorization;
  proofPackage: UnlockProofPackage;
  consumerData: BytesLike;
  value?: BigNumberish;
}): UnlockExecutionPayload {
  const chainId = BigInt(input.chainId);
  const authorization = normalizeBaseActionAuthorization(input.authorization);
  const consumerData = hexlify(input.consumerData) as `0x${string}`;
  const proofPackage = normalizeUnlockProofPackage(input.proofPackage);
  const value = BigInt(input.value ?? 0);
  const validation = assertValidUnlockProofPackage({
    chainId,
    authorization,
    consumerData,
    proofPackage
  });

  return {
    chainId,
    authorization,
    proofPackage: validation.chainSubmissionProofPackage,
    consumerData,
    value
  };
}
