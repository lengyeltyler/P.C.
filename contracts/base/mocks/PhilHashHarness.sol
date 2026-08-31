// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationTypes} from "../interfaces/IPhilAuthorizationTypes.sol";
import {PhilAuthorizationHashing} from "../PhilAuthorizationHashing.sol";

contract PhilHashHarness is IPhilAuthorizationTypes {
    function computeLegacyOwnerCommitment(address owner, bytes32 salt) external pure returns (bytes32) {
        return PhilAuthorizationHashing.legacyOwnerCommitmentFromAddressSalt(owner, salt);
    }

    function computeIdentityRoot(bytes32 philSecret) external pure returns (bytes32) {
        return PhilAuthorizationHashing.identityRoot(philSecret);
    }

    function computeCanonicalOwnerCommitment(bytes32 identityRootHash) external pure returns (bytes32) {
        return PhilAuthorizationHashing.canonicalOwnerCommitment(identityRootHash);
    }

    function computeUnlockActionHash(
        uint256 chainId,
        address consumer,
        address account,
        address target,
        uint256 value,
        bytes32 callDataHash
    ) external pure returns (bytes32) {
        return
            PhilAuthorizationHashing.unlockActionHash(
                chainId,
                consumer,
                account,
                target,
                value,
                callDataHash
            );
    }

    function computePolicyHash(
        uint256 chainId,
        address consumer,
        address target,
        uint64 expiry,
        bytes32 policyDataHash
    ) external pure returns (bytes32) {
        return
            PhilAuthorizationHashing.policyHash(
                chainId,
                consumer,
                target,
                expiry,
                policyDataHash
            );
    }

    function computeNullifier(
        bytes32 ownerCommitmentHash,
        bytes32 actionHashValue,
        bytes32 policyHashValue,
        bytes32 nullifierSeed
    ) external pure returns (bytes32) {
        return
            PhilAuthorizationHashing.nullifier(
                ownerCommitmentHash,
                actionHashValue,
                policyHashValue,
                nullifierSeed
            );
    }

    function computeAuthorizationDigest(BaseActionAuthorization calldata authorization)
        external
        pure
        returns (bytes32)
    {
        return PhilAuthorizationHashing.authorizationDigest(authorization);
    }

    function computeUnlockProofInputHash(UnlockProofPackage calldata proofPackage)
        external
        pure
        returns (bytes32)
    {
        return PhilAuthorizationHashing.unlockProofInputHash(proofPackage);
    }
}
