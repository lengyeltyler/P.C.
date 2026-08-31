// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";
import {IPhilSepoliaLocalComposedActionGateV1} from "./interfaces/IPhilSepoliaLocalComposedActionGateV1.sol";

/// @notice Non-upgradeable ERC-4337 account for one bounded Sepolia mint demo.
/// @dev The execution owner is separate from the Phil identity root. The
///      account verifies only its ERC-4337 execution signature, not Noir/P-256.
contract PhilSepoliaMintAccountV1 is BaseAccount {
    IEntryPoint private immutable _entryPoint;
    address public immutable executionOwner;
    bytes32 public immutable ownerCommitment;
    address public immutable actionGate;

    event PhilSepoliaMintAccountInitialized(
        address indexed account,
        address indexed executionOwner,
        bytes32 indexed ownerCommitment,
        address entryPoint,
        address actionGate
    );

    error InvalidConfiguration();
    error OnlyEntryPoint();
    error InvalidTarget();
    error NonZeroValueForbidden();
    error InvalidSelector();
    error GateCallFailed(bytes reason);

    constructor(
        IEntryPoint entryPoint_,
        address executionOwner_,
        bytes32 ownerCommitment_,
        address actionGate_
    ) {
        if (
            address(entryPoint_) == address(0) || executionOwner_ == address(0)
                || ownerCommitment_ == bytes32(0) || actionGate_ == address(0)
        ) revert InvalidConfiguration();
        _entryPoint = entryPoint_;
        executionOwner = executionOwner_;
        ownerCommitment = ownerCommitment_;
        actionGate = actionGate_;
        emit PhilSepoliaMintAccountInitialized(
            address(this), executionOwner_, ownerCommitment_, address(entryPoint_), actionGate_
        );
    }

    receive() external payable {}

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        _requireFromEntryPoint();
        if (target != actionGate) revert InvalidTarget();
        if (value != 0) revert NonZeroValueForbidden();
        if (
            data.length < 4
                || bytes4(data[:4]) != IPhilSepoliaLocalComposedActionGateV1.verifyAndConsume.selector
        ) revert InvalidSelector();
        (bool success, bytes memory result) = target.call(data);
        if (!success) revert GateCallFailed(result);
    }

    function _requireFromEntryPoint() internal view override {
        if (msg.sender != address(_entryPoint)) revert OnlyEntryPoint();
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        if (userOp.callData.length < 4 || bytes4(userOp.callData[:4]) != this.execute.selector) {
            return SIG_VALIDATION_FAILED;
        }
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, userOp.signature);
        return error == ECDSA.RecoverError.NoError && recovered == executionOwner
            ? SIG_VALIDATION_SUCCESS
            : SIG_VALIDATION_FAILED;
    }
}
