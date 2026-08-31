// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Harmless zero-value target for the first controlled PhilCore testnet action.
/// @dev Calls must arrive through the immutable PhilUnlockConsumer selected for this deployment.
contract PhilCoreAuthorizationConfirmationTarget {
    address public immutable unlockConsumer;

    mapping(bytes32 actionId => bool confirmed) public confirmedAction;
    bytes32 public lastActionId;
    bytes32 public lastNullifier;
    address public lastAccount;
    uint256 public confirmationCount;

    event PhilCoreAuthorizationConfirmed(
        bytes32 indexed actionId,
        bytes32 indexed nullifier,
        address indexed account
    );

    error InvalidUnlockConsumer();
    error OnlyUnlockConsumer();
    error InvalidAccount();
    error InvalidActionId();
    error ActionAlreadyConfirmed();

    constructor(address unlockConsumer_) {
        if (unlockConsumer_ == address(0)) revert InvalidUnlockConsumer();
        unlockConsumer = unlockConsumer_;
    }

    function onPhilUnlock(address account, bytes32 nullifier, bytes calldata callData)
        external
        returns (bytes32 actionId)
    {
        if (msg.sender != unlockConsumer) revert OnlyUnlockConsumer();
        if (account == address(0)) revert InvalidAccount();

        actionId = abi.decode(callData, (bytes32));
        if (actionId == bytes32(0)) revert InvalidActionId();
        if (confirmedAction[actionId]) revert ActionAlreadyConfirmed();

        confirmedAction[actionId] = true;
        lastActionId = actionId;
        lastNullifier = nullifier;
        lastAccount = account;
        confirmationCount += 1;

        emit PhilCoreAuthorizationConfirmed(actionId, nullifier, account);
    }
}
