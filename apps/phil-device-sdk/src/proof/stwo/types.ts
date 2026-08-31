import type { BigNumberish } from "ethers";

import type { Hex } from "../../hashes.ts";

export interface StwoUnlockPublicInputTuple {
  ownerCommitment: Hex;
  actionHash: Hex;
  policyHash: Hex;
  nullifier: Hex;
  consumerDataHash: Hex;
  expiry: BigNumberish;
}

export interface StwoUnlockProofStatement {
  version: string;
  proofType: string;
  publicInputs: StwoUnlockPublicInputTuple;
}

export interface StwoUnlockProofEnvelope {
  artifactVersion: string;
  verifierKeyId: Hex;
  proofBytes: Hex;
}
