// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationTypes} from "./interfaces/IPhilAuthorizationTypes.sol";

library PhilAuthorizationHashing {
    bytes32 internal constant IDENTITY_ROOT_DOMAIN = keccak256("PHIL_IDENTITY_ROOT_V1");
    bytes32 internal constant CANONICAL_OWNER_COMMITMENT_DOMAIN =
        keccak256("PHIL_OWNER_COMMITMENT_CANONICAL_V1");
    bytes32 internal constant OWNER_COMMITMENT_DOMAIN = keccak256("PHIL_OWNER_COMMITMENT_V1");
    bytes32 internal constant ACTION_UNLOCK_DOMAIN = keccak256("PHIL_ACTION_UNLOCK_V1");
    bytes32 internal constant POLICY_DOMAIN = keccak256("PHIL_POLICY_V1");
    bytes32 internal constant NULLIFIER_DOMAIN = keccak256("PHIL_NULLIFIER_V1");
    bytes32 internal constant BASE_AUTHORIZATION_DOMAIN = keccak256("PHIL_BASE_AUTHORIZATION_V1");
    bytes32 internal constant UNLOCK_PROOF_INPUTS_DOMAIN = keccak256("PHIL_UNLOCK_PROOF_INPUTS_V1");

    function legacyOwnerCommitmentFromAddressSalt(address owner, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(OWNER_COMMITMENT_DOMAIN, owner, salt));
    }

    function identityRoot(bytes32 philSecret) internal pure returns (bytes32) {
        return keccak256(abi.encode(IDENTITY_ROOT_DOMAIN, philSecret));
    }

    function canonicalOwnerCommitment(bytes32 identityRootHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(CANONICAL_OWNER_COMMITMENT_DOMAIN, identityRootHash));
    }

    function unlockActionHash(
        uint256 chainId,
        address consumer,
        address account,
        address target,
        uint256 value,
        bytes32 callDataHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(ACTION_UNLOCK_DOMAIN, chainId, consumer, account, target, value, callDataHash)
        );
    }

    function policyHash(
        uint256 chainId,
        address consumer,
        address target,
        uint64 expiry,
        bytes32 policyDataHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(POLICY_DOMAIN, chainId, consumer, target, expiry, policyDataHash)
        );
    }

    function nullifier(
        bytes32 ownerCommitmentHash,
        bytes32 actionHashValue,
        bytes32 policyHashValue,
        bytes32 nullifierSeed
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(NULLIFIER_DOMAIN, ownerCommitmentHash, actionHashValue, policyHashValue, nullifierSeed)
        );
    }

    function authorizationDigest(IPhilAuthorizationTypes.BaseActionAuthorization memory authorization)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                BASE_AUTHORIZATION_DOMAIN,
                authorization.consumer,
                authorization.ownerCommitment,
                authorization.actionHash,
                authorization.policyHash,
                authorization.nullifier,
                authorization.consumerDataHash,
                authorization.expiry
            )
        );
    }

    function unlockProofInputHash(IPhilAuthorizationTypes.UnlockProofPackage memory proofPackage)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                UNLOCK_PROOF_INPUTS_DOMAIN,
                proofPackage.version,
                proofPackage.proofType,
                proofPackage.publicInputs.ownerCommitment,
                proofPackage.publicInputs.actionHash,
                proofPackage.publicInputs.policyHash,
                proofPackage.publicInputs.nullifier,
                proofPackage.publicInputs.consumerDataHash,
                proofPackage.publicInputs.expiry
            )
        );
    }
}
