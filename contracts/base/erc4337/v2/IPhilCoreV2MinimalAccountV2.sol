// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

struct PhilCoreV2IntentCoreHeaderV1 {
    uint8 specificationVersion;
    bytes32 securityModelId;
    uint8 actionType;
    bytes32 actionId;
    bytes32 purpose;
    bytes32 ownerCommitment;
    uint256 chainId;
    address entryPoint;
    address account;
    uint192 nonceKey;
    uint64 nonceSequence;
    uint64 validatorEpoch;
    uint64 recoveryEpoch;
    bytes32 applicationContextHash;
    bytes32 fundLifecycleDigest;
    uint256 maxTotalFeeWei;
    uint48 validAfter;
    uint48 validUntil;
}

struct PhilCoreV2AuthorizedIntentV1 {
    PhilCoreV2IntentCoreHeaderV1 core;
    bytes32 runtimeAuthorizationDigest;
}

struct PhilCoreV2AccountInitializationV1 {
    IEntryPoint entryPoint;
    uint256 deploymentChainId;
    bytes32 ownerCommitment;
    bytes32 identityBindingCommitment;
    address factoryBinding;
    bytes32 accountVersionId;
    bytes32 securityModelId;
    address confirmationTarget;
    address initialValidator;
    uint8 validatorVerifierKind;
    bytes32 validatorKeyIdBinding;
    bytes32 validatorCommitment;
    uint64 validatorEpoch;
    bytes32 primaryDeviceRecoveryCommitment;
    bytes32 hardwareSecurityKeyCommitment;
    bytes32 independentRecoveryFactorCommitment;
    bytes32 recoveryConfigurationHash;
    uint64 recoveryEpoch;
    uint64 recoveryDelaySeconds;
    uint64 recoveryExpirySeconds;
}

interface IPhilCoreV2MinimalAccountV2 {
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);

    function confirmIntent(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 confirmationDigest
    ) external;

    function transferNative(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address payable recipient,
        uint256 amountWei
    ) external;

    function withdrawEntryPointDeposit(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address payable recipient,
        uint256 amountWei
    ) external;

    function rotateValidator(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address proposedValidator,
        bytes32 proposedValidatorKeyIdBinding,
        uint64 proposedValidatorEpoch
    ) external;

    function requestRecovery(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address proposedValidator,
        bytes32 proposedValidatorKeyIdBinding,
        uint64 proposedValidatorEpoch,
        bytes32 recoveryRequestSalt
    ) external;

    function cancelRecovery(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 recoveryRequestId
    ) external;

    function settleRecovery(bytes32 recoveryRequestId) external;

    function requestRecoveryConfigRotation(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 proposedPrimaryDeviceCommitment,
        bytes32 proposedHardwareSecurityKeyCommitment,
        bytes32 proposedRecoveryFactorCommitment,
        uint64 proposedRecoveryEpoch
    ) external;

    function cancelRecoveryConfigRotation(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 rotationRequestId
    ) external;

    function settleRecoveryConfigRotation(bytes32 rotationRequestId) external;

    function accountConfiguration()
        external
        view
        returns (
            IEntryPoint entryPoint,
            uint256 deploymentChainId,
            bytes32 ownerCommitment,
            bytes32 identityBindingCommitment,
            address factoryBinding,
            bytes32 accountVersionId,
            bytes32 securityModelId,
            address confirmationTarget
        );

    function accountSecurityState()
        external
        view
        returns (
            address activeValidator,
            bytes32 validatorCommitment,
            bytes32 validatorKeyIdBinding,
            uint64 validatorEpoch,
            uint8 validatorVerifierKind,
            uint8 recoveryState,
            uint64 recoveryEpoch,
            bytes32 recoveryConfigurationHash,
            bytes32 primaryDeviceCommitment,
            bytes32 hardwareSecurityKeyCommitment,
            bytes32 recoveryFactorCommitment,
            bool executionLocked
        );

    function pendingRecovery()
        external
        view
        returns (
            bytes32 requestId,
            address proposedValidator,
            bytes32 proposedValidatorKeyIdBinding,
            bytes32 proposedValidatorCommitment,
            uint64 proposedValidatorEpoch,
            uint64 sourceValidatorEpoch,
            uint64 sourceRecoveryEpoch,
            uint48 requestedAt,
            uint48 executableAfter,
            uint48 expiresAt
        );

    function pendingRecoveryConfigRotation()
        external
        view
        returns (
            bytes32 requestId,
            bytes32 proposedRecoveryConfigHash,
            bytes32 proposedPrimaryDeviceCommitment,
            bytes32 proposedHardwareSecurityKeyCommitment,
            bytes32 proposedRecoveryFactorCommitment,
            uint64 proposedRecoveryEpoch,
            uint64 sourceValidatorEpoch,
            uint64 sourceRecoveryEpoch,
            uint48 requestedAt,
            uint48 executableAfter,
            uint48 expiresAt
        );
}
