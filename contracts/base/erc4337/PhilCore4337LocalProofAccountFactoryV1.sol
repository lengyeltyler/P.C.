// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PhilCore4337LocalProofAccountV1} from "./PhilCore4337LocalProofAccountV1.sol";

/// @notice Deterministic factory dedicated to disposable local-proof-gated-v1 accounts.
contract PhilCore4337LocalProofAccountFactoryV1 {
    IEntryPoint public immutable entryPoint;
    address public immutable approvedConfirmationTarget;
    uint256 public immutable expectedChainId;

    event PhilCoreLocalProofAccountCreated(
        address indexed account,
        address indexed owner,
        bytes32 indexed ownerCommitment,
        bytes32 validatorKeyId,
        uint256 salt
    );

    error InvalidEntryPoint();
    error InvalidConfirmationTarget();
    error WrongDeploymentChain();

    constructor(
        IEntryPoint entryPoint_,
        address approvedConfirmationTarget_,
        uint256 expectedChainId_
    ) {
        if (address(entryPoint_) == address(0)) revert InvalidEntryPoint();
        if (approvedConfirmationTarget_ == address(0)) revert InvalidConfirmationTarget();
        if (expectedChainId_ != block.chainid) revert WrongDeploymentChain();
        entryPoint = entryPoint_;
        approvedConfirmationTarget = approvedConfirmationTarget_;
        expectedChainId = expectedChainId_;
    }

    function createAccount(
        address owner,
        bytes32 ownerCommitment,
        bytes32 validatorKeyId,
        uint256 salt
    ) external returns (PhilCore4337LocalProofAccountV1 account) {
        address accountAddress = getAddress(owner, ownerCommitment, validatorKeyId, salt);
        if (accountAddress.code.length != 0) {
            return PhilCore4337LocalProofAccountV1(payable(accountAddress));
        }
        account = new PhilCore4337LocalProofAccountV1{salt: bytes32(salt)}(
            entryPoint,
            owner,
            ownerCommitment,
            approvedConfirmationTarget,
            validatorKeyId,
            expectedChainId
        );
        emit PhilCoreLocalProofAccountCreated(
            address(account), owner, ownerCommitment, validatorKeyId, salt
        );
    }

    function getAddress(
        address owner,
        bytes32 ownerCommitment,
        bytes32 validatorKeyId,
        uint256 salt
    ) public view returns (address) {
        bytes memory creationCode = abi.encodePacked(
            type(PhilCore4337LocalProofAccountV1).creationCode,
            abi.encode(
                entryPoint,
                owner,
                ownerCommitment,
                approvedConfirmationTarget,
                validatorKeyId,
                expectedChainId
            )
        );
        return Create2.computeAddress(bytes32(salt), keccak256(creationCode), address(this));
    }
}
