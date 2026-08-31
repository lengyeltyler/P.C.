// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationConsumer} from "./interfaces/IPhilAuthorizationConsumer.sol";
import {IPhilAuthorizationTypes} from "./interfaces/IPhilAuthorizationTypes.sol";
import {IPhilUnlockProofVerifier} from "./interfaces/IPhilUnlockProofVerifier.sol";
import {PhilAuthorizationHashing} from "./PhilAuthorizationHashing.sol";

contract PhilBaseActionGate is IPhilAuthorizationTypes {
    IPhilUnlockProofVerifier public immutable unlockProofVerifier;
    mapping(bytes32 => bool) public consumedNullifier;

    event AuthorizationConsumed(
        bytes32 indexed nullifier,
        bytes32 indexed authorizationDigest,
        address indexed consumer,
        address caller
    );

    error InvalidConsumer();
    error AuthorizationExpired();
    error ConsumerDataHashMismatch();
    error InvalidProofVersion();
    error InvalidProofType();
    error InvalidProofPublicInputs();
    error InvalidProofInputHash();
    error InvalidProofBlob();
    error InvalidProof();
    error NullifierAlreadyConsumed();
    error ProofVerifierNotConfigured();

    bytes32 private constant _UNLOCK_PROOF_SCHEMA_VERSION_HASH = keccak256("v1");
    bytes32 private constant _UNLOCK_PROOF_TYPE_STUB_HASH = keccak256("s-two");
    bytes32 private constant _UNLOCK_PROOF_TYPE_STWO_UNLOCK_HASH = keccak256("stwo-unlock-keccak-v1");

    constructor(address unlockProofVerifier_) {
        unlockProofVerifier = IPhilUnlockProofVerifier(unlockProofVerifier_);
    }

    function computeAuthorizationDigest(BaseActionAuthorization calldata authorization)
        public
        pure
        returns (bytes32)
    {
        return PhilAuthorizationHashing.authorizationDigest(authorization);
    }

    function computeProofInputHash(UnlockProofPackage calldata proofPackage) public pure returns (bytes32) {
        return PhilAuthorizationHashing.unlockProofInputHash(proofPackage);
    }

    function verifyAndConsume(
        BaseActionAuthorization calldata authorization,
        UnlockProofPackage calldata proofPackage,
        bytes calldata consumerData
    ) external payable returns (bytes memory result) {
        if (authorization.consumer == address(0) || authorization.consumer.code.length == 0) {
            revert InvalidConsumer();
        }
        if (authorization.expiry != 0 && block.timestamp > authorization.expiry) {
            revert AuthorizationExpired();
        }
        if (keccak256(consumerData) != authorization.consumerDataHash) {
            revert ConsumerDataHashMismatch();
        }
        if (keccak256(bytes(proofPackage.version)) != _UNLOCK_PROOF_SCHEMA_VERSION_HASH) {
            revert InvalidProofVersion();
        }
        bytes32 proofTypeHash = keccak256(bytes(proofPackage.proofType));
        if (
            proofTypeHash != _UNLOCK_PROOF_TYPE_STUB_HASH
                && proofTypeHash != _UNLOCK_PROOF_TYPE_STWO_UNLOCK_HASH
        ) {
            revert InvalidProofType();
        }
        if (
            proofPackage.publicInputs.ownerCommitment != authorization.ownerCommitment
                || proofPackage.publicInputs.actionHash != authorization.actionHash
                || proofPackage.publicInputs.policyHash != authorization.policyHash
                || proofPackage.publicInputs.nullifier != authorization.nullifier
                || proofPackage.publicInputs.consumerDataHash != authorization.consumerDataHash
                || proofPackage.publicInputs.expiry != authorization.expiry
        ) revert InvalidProofPublicInputs();

        bytes32 proofInputHashValue = computeProofInputHash(proofPackage);
        if (proofPackage.proofInputHash != proofInputHashValue) revert InvalidProofInputHash();
        if (consumedNullifier[authorization.nullifier]) revert NullifierAlreadyConsumed();

        if (proofTypeHash == _UNLOCK_PROOF_TYPE_STUB_HASH) {
            if (proofPackage.proofBlob.length != 0) revert InvalidProofBlob();
        } else {
            if (address(unlockProofVerifier) == address(0)) revert ProofVerifierNotConfigured();
            if (proofPackage.proofBlob.length == 0) revert InvalidProofBlob();

            try unlockProofVerifier.verifyUnlockProof(proofPackage.proofBlob, proofPackage.publicInputs) returns (
                bool valid
            ) {
                if (!valid) revert InvalidProof();
            } catch {
                revert InvalidProof();
            }
        }

        consumedNullifier[authorization.nullifier] = true;
        result = IPhilAuthorizationConsumer(authorization.consumer).consumePhilAuthorization{value: msg.value}(
            authorization,
            consumerData
        );

        emit AuthorizationConsumed(
            authorization.nullifier,
            computeAuthorizationDigest(authorization),
            authorization.consumer,
            msg.sender
        );
    }
}
