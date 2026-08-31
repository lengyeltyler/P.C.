// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";

/// @notice Stateless local test harness installed at the Base EntryPoint v0.7 address.
/// @dev It proves account validation/execution coupling only; it is not an EntryPoint implementation.
contract PhilV1Step6BLocalEntryPointHarness {
    using UserOperationLib for PackedUserOperation;

    error PhilStep6BHarnessSignatureFailed();
    error PhilStep6BHarnessOutsideValidity();
    error PhilStep6BHarnessExecutionFailed(bytes reason);

    function getUserOpHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    function validateAndExecute(PackedUserOperation calldata userOp) external {
        uint256 validationData = IAccount(userOp.sender).validateUserOp(userOp, getUserOpHash(userOp), 0);
        if (address(uint160(validationData)) == address(1)) revert PhilStep6BHarnessSignatureFailed();
        uint48 validUntil = uint48(validationData >> 160);
        uint48 validAfter = uint48(validationData >> 208);
        if (block.timestamp < validAfter || (validUntil != 0 && block.timestamp > validUntil)) {
            revert PhilStep6BHarnessOutsideValidity();
        }
        (bool success, bytes memory result) = userOp.sender.call(userOp.callData);
        if (!success) revert PhilStep6BHarnessExecutionFailed(result);
    }

    function validateOnlyFor(
        address account,
        PackedUserOperation calldata userOp,
        bytes32 suppliedUserOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        return IAccount(account).validateUserOp(userOp, suppliedUserOpHash, missingAccountFunds);
    }

    function executeOnly(address account, bytes calldata callData) external {
        (bool success, bytes memory result) = account.call(callData);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 0x20), mload(result))
            }
        }
    }
}
