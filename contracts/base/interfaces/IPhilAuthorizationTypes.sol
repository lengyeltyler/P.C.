// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPhilAuthorizationTypes {
    struct BaseActionAuthorization {
        address consumer;
        bytes32 ownerCommitment;
        bytes32 actionHash;
        bytes32 policyHash;
        bytes32 nullifier;
        bytes32 consumerDataHash;
        uint64 expiry;
    }

    struct UnlockProofPublicInputs {
        bytes32 ownerCommitment;
        bytes32 actionHash;
        bytes32 policyHash;
        bytes32 nullifier;
        bytes32 consumerDataHash;
        uint64 expiry;
    }

    struct UnlockProofPackage {
        string version;
        string proofType;
        UnlockProofPublicInputs publicInputs;
        bytes32 proofInputHash;
        bytes proofBlob;
    }

    struct UnlockRequest {
        address account;
        address target;
        uint256 value;
        bytes callData;
    }
}
