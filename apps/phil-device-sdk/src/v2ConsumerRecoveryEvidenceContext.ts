import {
  AbiCoder,
  getAddress,
  isHexString,
  keccak256,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import { PHILCORE_V2_RECOVERY_THRESHOLD } from "./v2Authorization.ts";
import {
  computePhilCoreV2ConsumerRecoveryConfigurationHash
} from "./v2ConsumerRecovery.ts";
import {
  computePhilCoreV2RecoveryConfigurationHashV2,
  computePhilCoreV2RecoveryEvidenceContextHash,
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH,
  type PhilCoreV2RecoveryEvidenceContextInput
} from "./v2RecoveryEvidence.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

function requireBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  return value.toLowerCase() as Hex;
}

/**
 * Canonical O.37.1 evidence-context field encoding (typehash + exact field order).
 * Used for parity with the frozen hasher and for hashing the original V3-bearing
 * context after the frozen invariant gate succeeds.
 */
export function hashPhilCoreV2RecoveryEvidenceContextFields(
  context: PhilCoreV2RecoveryEvidenceContextInput
): Hex {
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "uint8",
      "uint8",
      "uint8",
      "address",
      "uint256",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint64",
      "uint64",
      "uint48",
      "uint48",
      "uint64",
      "uint64",
      "bytes32",
      "bytes32",
      "uint64",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32"
    ],
    [
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.EVIDENCE_CONTEXT,
      BigInt(context.envelopeVersion as BigNumberish),
      BigInt(context.authorityKind as BigNumberish),
      BigInt(context.actionType as BigNumberish),
      BigInt(context.factorBitmap as BigNumberish),
      getAddress(String(context.account)),
      BigInt(context.chainId as BigNumberish),
      getAddress(String(context.entryPoint)),
      requireBytes32(context.authorizedIntentHash, "authorizedIntentHash"),
      requireBytes32(context.userOperationHash, "userOperationHash"),
      requireBytes32(context.requestId, "requestId"),
      requireBytes32(
        context.currentRecoveryConfigHash,
        "currentRecoveryConfigHash"
      ),
      BigInt(context.validatorEpoch as BigNumberish),
      BigInt(context.recoveryEpoch as BigNumberish),
      BigInt(context.validAfter as BigNumberish),
      BigInt(context.validUntil as BigNumberish),
      BigInt(context.recoveryDelaySeconds as BigNumberish),
      BigInt(context.recoveryExpirySeconds as BigNumberish),
      requireBytes32(
        context.proposedValidatorCommitment,
        "proposedValidatorCommitment"
      ),
      requireBytes32(
        context.proposedRecoveryConfigHash,
        "proposedRecoveryConfigHash"
      ),
      BigInt(context.proposedRecoveryEpoch as BigNumberish),
      requireBytes32(context.primaryDeviceCommitment, "primaryDeviceCommitment"),
      requireBytes32(
        context.hardwareSecurityKeyCommitment,
        "hardwareSecurityKeyCommitment"
      ),
      requireBytes32(
        context.recoveryFactorCommitment,
        "recoveryFactorCommitment"
      ),
      requireBytes32(context.firstFactorCommitment, "firstFactorCommitment"),
      requireBytes32(context.secondFactorCommitment, "secondFactorCommitment")
    ]
  )) as Hex;
}

/**
 * Authoritative current consumer-V3 recovery-evidence-context hash.
 *
 * Independently requires the consumer-V3 configuration hash, runs the complete
 * frozen O.37.1 invariant pipeline on a validation-only V2-hash copy, then
 * returns the context hash over the original V3-bearing context.
 */
export function computePhilCoreV2ConsumerRecoveryEvidenceContextHash(
  input: PhilCoreV2RecoveryEvidenceContextInput
): Hex {
  const primaryDeviceCommitment = requireBytes32(
    input.primaryDeviceCommitment,
    "primaryDeviceCommitment"
  );
  const hardwareSecurityKeyCommitment = requireBytes32(
    input.hardwareSecurityKeyCommitment,
    "hardwareSecurityKeyCommitment"
  );
  const recoveryFactorCommitment = requireBytes32(
    input.recoveryFactorCommitment,
    "recoveryFactorCommitment"
  );
  const suppliedConfigHash = requireBytes32(
    input.currentRecoveryConfigHash,
    "currentRecoveryConfigHash"
  );

  const expectedV3ConfigHash = computePhilCoreV2ConsumerRecoveryConfigurationHash([
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment
  ]);
  if (suppliedConfigHash !== expectedV3ConfigHash) {
    throw new Error("current_recovery_config_hash_mismatch");
  }

  const legacyV2ConfigHash = computePhilCoreV2RecoveryConfigurationHashV2({
    configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
    threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment
  });

  const validationOnlyCopy: PhilCoreV2RecoveryEvidenceContextInput = {
    ...input,
    currentRecoveryConfigHash: legacyV2ConfigHash
  };

  // Authoritative frozen invariant gate. Result discarded.
  computePhilCoreV2RecoveryEvidenceContextHash(validationOnlyCopy);

  // Hash the original consumer-V3 context (retained V3 configuration hash).
  return hashPhilCoreV2RecoveryEvidenceContextFields({
    ...input,
    currentRecoveryConfigHash: expectedV3ConfigHash,
    primaryDeviceCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment
  });
}
