// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilCoreLocalProofAccountV1} from "./interfaces/IPhilCoreLocalProofAccountV1.sol";

/// @notice Harmless confirmation target dedicated to local-proof-gated-v1 accounts.
/// @dev This target is evidence, not proof verification or authorization authority.
contract PhilCoreLocalProofConfirmationTargetV1 {
    bytes32 public constant SECURITY_MODEL_ID = keccak256("local-proof-gated-v1");

    mapping(address account => mapping(bytes32 actionId => bool confirmed)) public confirmedAction;
    address public lastAccount;
    bytes32 public lastActionId;
    bytes32 public lastAuthorizationDigest;
    uint256 public confirmationCount;

    event PhilCoreLocalProofActionConfirmed(
        address indexed account,
        bytes32 indexed actionId,
        bytes32 indexed authorizationDigest
    );

    error CallerIsNotContract();
    error UnsupportedSecurityModel();
    error TargetBindingMismatch();
    error ChainBindingMismatch();
    error InvalidActionId();
    error InvalidAuthorizationDigest();
    error ActionAlreadyConfirmed();

    function confirmPhilCoreAction(bytes32 actionId, bytes32 authorizationDigest) external {
        if (msg.sender.code.length == 0) revert CallerIsNotContract();
        IPhilCoreLocalProofAccountV1 account = IPhilCoreLocalProofAccountV1(msg.sender);
        if (account.securityModelId() != SECURITY_MODEL_ID) revert UnsupportedSecurityModel();
        if (account.approvedConfirmationTarget() != address(this)) revert TargetBindingMismatch();
        if (account.expectedChainId() != block.chainid) revert ChainBindingMismatch();
        if (actionId == bytes32(0)) revert InvalidActionId();
        if (authorizationDigest == bytes32(0)) revert InvalidAuthorizationDigest();
        if (confirmedAction[msg.sender][actionId]) revert ActionAlreadyConfirmed();

        confirmedAction[msg.sender][actionId] = true;
        lastAccount = msg.sender;
        lastActionId = actionId;
        lastAuthorizationDigest = authorizationDigest;
        confirmationCount += 1;

        emit PhilCoreLocalProofActionConfirmed(msg.sender, actionId, authorizationDigest);
    }
}
