// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Test-only mocks for `PhilCoreV2ConfirmationTargetV1`. Each mock plays
///      the role of a calling "account" contract so tests can drive every
///      `accountConfiguration()` shape (correct, mismatched, reverting,
///      missing, and malformed) without deploying a full V2 account.
interface IPhilCoreV2ConfirmationTargetV1ForMocks {
    function confirmPhilCoreAction(
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external;
}

/// @notice Fully configurable caller mock. Every `accountConfiguration()`
///         field is set at construction and individually mutable so tests
///         can flip exactly one field away from a known-good baseline.
contract PhilCoreV2ConfirmationTargetConfigMock {
    address public entryPoint;
    uint256 public deploymentChainId;
    bytes32 public ownerCommitment;
    bytes32 public identityBindingCommitment;
    address public factoryBinding;
    bytes32 public accountVersionId;
    bytes32 public securityModelId;
    address public confirmationTarget;

    constructor(
        address entryPoint_,
        uint256 deploymentChainId_,
        bytes32 ownerCommitment_,
        bytes32 identityBindingCommitment_,
        address factoryBinding_,
        bytes32 accountVersionId_,
        bytes32 securityModelId_,
        address confirmationTarget_
    ) {
        entryPoint = entryPoint_;
        deploymentChainId = deploymentChainId_;
        ownerCommitment = ownerCommitment_;
        identityBindingCommitment = identityBindingCommitment_;
        factoryBinding = factoryBinding_;
        accountVersionId = accountVersionId_;
        securityModelId = securityModelId_;
        confirmationTarget = confirmationTarget_;
    }

    function setDeploymentChainId(uint256 value) external {
        deploymentChainId = value;
    }

    function setConfirmationTarget(address value) external {
        confirmationTarget = value;
    }

    function setAccountVersionId(bytes32 value) external {
        accountVersionId = value;
    }

    function setSecurityModelId(bytes32 value) external {
        securityModelId = value;
    }

    function accountConfiguration()
        external
        view
        returns (
            address,
            uint256,
            bytes32,
            bytes32,
            address,
            bytes32,
            bytes32,
            address
        )
    {
        return (
            entryPoint,
            deploymentChainId,
            ownerCommitment,
            identityBindingCommitment,
            factoryBinding,
            accountVersionId,
            securityModelId,
            confirmationTarget
        );
    }

    function confirm(
        address target,
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        IPhilCoreV2ConfirmationTargetV1ForMocks(target).confirmPhilCoreAction(
            actionId,
            authorizationDigest
        );
    }
}

/// @notice Caller mock whose `accountConfiguration()` always reverts.
contract PhilCoreV2ConfirmationTargetRevertingConfigMock {
    error MockConfigurationReverted();

    function accountConfiguration()
        external
        pure
        returns (
            address,
            uint256,
            bytes32,
            bytes32,
            address,
            bytes32,
            bytes32,
            address
        )
    {
        revert MockConfigurationReverted();
    }

    function confirm(
        address target,
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        IPhilCoreV2ConfirmationTargetV1ForMocks(target).confirmPhilCoreAction(
            actionId,
            authorizationDigest
        );
    }
}

/// @notice Caller mock with no `accountConfiguration()` function at all and
///         no fallback, so calling it reverts exactly as a missing
///         configuration view should.
contract PhilCoreV2ConfirmationTargetNoConfigMock {
    function confirm(
        address target,
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        IPhilCoreV2ConfirmationTargetV1ForMocks(target).confirmPhilCoreAction(
            actionId,
            authorizationDigest
        );
    }
}

/// @notice Caller mock whose `accountConfiguration()` returns far less data
///         than the expected 8-field static tuple, simulating a malformed /
///         wrong-shaped configuration view.
contract PhilCoreV2ConfirmationTargetMalformedConfigMock {
    function accountConfiguration() external pure {
        assembly ("memory-safe") {
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }

    function confirm(
        address target,
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external {
        IPhilCoreV2ConfirmationTargetV1ForMocks(target).confirmPhilCoreAction(
            actionId,
            authorizationDigest
        );
    }
}
