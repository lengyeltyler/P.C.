import { keccak256, toUtf8Bytes } from "ethers";

import type { Hex } from "../../hashes.ts";

export const STWO_UNLOCK_PROOF_VERSION = "v1" as const;
export const STWO_UNLOCK_PROOF_TYPE = "stwo-unlock-keccak-v1" as const;
export const STWO_UNLOCK_ARTIFACT_VERSION = "phil-s2-proof-envelope-v1" as const;
export const STWO_UNLOCK_VERIFIER_KEY_ID = keccak256(
  toUtf8Bytes("PHIL_STWO_UNLOCK_VERIFIER_KEY_V1")
) as Hex;
