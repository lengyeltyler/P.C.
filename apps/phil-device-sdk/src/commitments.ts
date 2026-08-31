import {
  getAddress,
  hexlify,
  zeroPadValue,
  type BigNumberish,
  type BytesLike
} from "ethers";

import {
  dataHash,
  legacyOwnerCommitmentFromAddressSalt,
  policyHash
} from "./hashes.ts";

export interface LegacyOwnerCommitmentInput {
  legacyOwner: string;
  legacyOwnerSalt: BytesLike;
}

export interface LegacyOwnerCommitment {
  ownerCommitment: `0x${string}`;
  mode: "legacy-address-salt";
  legacyOwner: string;
  legacyOwnerSalt: `0x${string}`;
}

/**
 * @deprecated Canonical Phil identity commitments must be derived from phil_secret.
 * LEGACY ONLY / TEST ONLY: this address-plus-salt helper is retained only for
 * compatibility with older tests and transitional tooling.
 */
export function buildLegacyOwnerCommitmentFromAddressSalt(
  input: LegacyOwnerCommitmentInput
): LegacyOwnerCommitment {
  const normalizedOwner = getAddress(input.legacyOwner);
  const salt = zeroPadValue(hexlify(input.legacyOwnerSalt), 32) as `0x${string}`;
  return {
    legacyOwner: normalizedOwner,
    legacyOwnerSalt: salt,
    ownerCommitment: legacyOwnerCommitmentFromAddressSalt(normalizedOwner, salt),
    mode: "legacy-address-salt"
  };
}

export function buildUnlockPolicy(input: {
  chainId: BigNumberish;
  consumer: string;
  target: string;
  expiry?: BigNumberish;
  policyData?: BytesLike;
}) {
  const expiry = BigInt(input.expiry ?? 0);
  const policyData = hexlify(input.policyData ?? "0x");
  const policyDataHash = dataHash(policyData);

  return {
    chainId: BigInt(input.chainId),
    consumer: getAddress(input.consumer),
    target: getAddress(input.target),
    expiry,
    policyData,
    policyDataHash,
    policyHash: policyHash({
      chainId: input.chainId,
      consumer: input.consumer,
      target: input.target,
      expiry,
      policyDataHash
    })
  };
}
