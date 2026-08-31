import { hexlify, type BytesLike } from "ethers";

import { nullifier } from "./hashes.ts";

export function buildNullifier(input: {
  ownerCommitment: BytesLike;
  actionHash: BytesLike;
  policyHash: BytesLike;
  nullifierSeed: BytesLike;
}) {
  const nullifierSeed = hexlify(input.nullifierSeed);
  return {
    nullifierSeed,
    nullifier: nullifier({
      ownerCommitment: input.ownerCommitment,
      actionHash: input.actionHash,
      policyHash: input.policyHash,
      nullifierSeed
    })
  };
}
