// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationTypes} from "./interfaces/IPhilAuthorizationTypes.sol";
import {IPhilUnlockProofVerifier} from "./interfaces/IPhilUnlockProofVerifier.sol";
import {IPhilBaseProofInputHashMirror} from "./interfaces/IPhilBaseProofInputHashMirror.sol";
import {PhilAuthorizationHashing} from "./PhilAuthorizationHashing.sol";

contract PhilBaseMirroredFactUnlockProofVerifier is IPhilUnlockProofVerifier {
    IPhilBaseProofInputHashMirror public immutable baseMirror;

    string private constant _UNLOCK_PROOF_VERSION = "v1";
    string private constant _UNLOCK_PROOF_TYPE = "stwo-unlock-keccak-v1";

    error InvalidBaseMirror();
    error InvalidFactPayload();

    constructor(address baseMirror_) {
        if (baseMirror_ == address(0)) revert InvalidBaseMirror();
        baseMirror = IPhilBaseProofInputHashMirror(baseMirror_);
    }

    function verifyUnlockProof(bytes calldata proof, UnlockProofPublicInputs calldata publicInputs)
        external
        view
        override
        returns (bool)
    {
        if (proof.length != 64) revert InvalidFactPayload();

        (uint256 factHigh, uint256 factLow) = abi.decode(proof, (uint256, uint256));
        if (factHigh > type(uint128).max || factLow > type(uint128).max) {
            return false;
        }

        if (_composeProofInputHash(factHigh, factLow) != _computeProofInputHash(publicInputs)) {
            return false;
        }

        return baseMirror.mirroredProofInputHashFact(factHigh, factLow);
    }

    function _computeProofInputHash(UnlockProofPublicInputs calldata publicInputs) internal pure returns (bytes32) {
        UnlockProofPackage memory proofPackage = UnlockProofPackage({
            version: _UNLOCK_PROOF_VERSION,
            proofType: _UNLOCK_PROOF_TYPE,
            publicInputs: IPhilAuthorizationTypes.UnlockProofPublicInputs({
                ownerCommitment: publicInputs.ownerCommitment,
                actionHash: publicInputs.actionHash,
                policyHash: publicInputs.policyHash,
                nullifier: publicInputs.nullifier,
                consumerDataHash: publicInputs.consumerDataHash,
                expiry: publicInputs.expiry
            }),
            proofInputHash: bytes32(0),
            proofBlob: ""
        });

        return PhilAuthorizationHashing.unlockProofInputHash(proofPackage);
    }

    function _composeProofInputHash(uint256 factHigh, uint256 factLow) internal pure returns (bytes32) {
        return bytes32((factHigh << 128) | factLow);
    }
}
