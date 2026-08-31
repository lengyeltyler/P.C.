import { keccak256, toUtf8Bytes } from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHILCORE_V2_SECURITY_MODEL,
  PHILCORE_V2_SECURITY_MODEL_ID
} from "./v2Intent.ts";

/**
 * Deployable identity constants for the PhilCore V2 account that is
 * actually deployed on Sepolia (and any other live network).
 *
 * `v2Intent.ts` exports `PHILCORE_V2_ACCOUNT_VERSION_ID`, which is a
 * *historical* account version id kept for backwards-compatible intent
 * encoding/decoding of older deployments. It MUST NOT be used to deploy new
 * accounts. The currently deployable account version is
 * `PhilCoreV2MinimalAccountV2` / `PhilCoreV2MinimalAccountFactoryV2`, whose
 * on-chain `ACCOUNT_VERSION_ID` constant is the id derived below (and is
 * identical to `PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID` exported by
 * `v2ConsumerRecovery.ts`).
 */
export const PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION =
  "philcore-v2-minimal-account-v3-consumer-recovery" as const;
export const PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID = keccak256(
  toUtf8Bytes(PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION)
) as Hex;

/**
 * The security model is unchanged between the historical and deployable
 * account versions, so it is re-exported (not redefined) from `v2Intent.ts`
 * to avoid any risk of drift between the two modules.
 */
export {
  PHILCORE_V2_SECURITY_MODEL,
  PHILCORE_V2_SECURITY_MODEL_ID
};

/** Canonical Ethereum Sepolia chain id. */
export const PHILCORE_V2_SEPOLIA_CHAIN_ID = 11_155_111 as const;

/** Canonical ERC-4337 EntryPoint v0.7 address, deployed identically across networks. */
export const PHILCORE_ENTRY_POINT_V07_ADDRESS =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as const;

/**
 * Domain separator used by `PhilCoreV2MinimalAccountFactoryV2.deploymentSalt`
 * to derive the CREATE2 salt for account deployments. Matches the on-chain
 * `CREATE2_SALT_DOMAIN` constant exactly.
 */
export const PHILCORE_V2_CREATE2_SALT_DOMAIN = keccak256(
  toUtf8Bytes("PHILCORE_V2_CREATE2_SALT_V1")
) as Hex;
