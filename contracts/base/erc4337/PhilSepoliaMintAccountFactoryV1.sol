// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PhilSepoliaMintAccountV1} from "./PhilSepoliaMintAccountV1.sol";
import {IPhilSepoliaMintAccountFactoryV1} from "./interfaces/IPhilSepoliaMintAccountFactoryV1.sol";

contract PhilSepoliaMintAccountFactoryV1 is IPhilSepoliaMintAccountFactoryV1 {
    IEntryPoint public immutable entryPoint;
    address public immutable actionGate;
    mapping(address => bool) public override isPhilSepoliaMintAccount;

    event PhilSepoliaMintAccountCreated(
        address indexed account,
        address indexed executionOwner,
        bytes32 indexed ownerCommitment,
        uint256 salt
    );

    error InvalidConfiguration();

    constructor(IEntryPoint entryPoint_, address actionGate_) {
        if (address(entryPoint_) == address(0) || actionGate_ == address(0)) {
            revert InvalidConfiguration();
        }
        entryPoint = entryPoint_;
        actionGate = actionGate_;
    }

    function createAccount(address executionOwner, bytes32 ownerCommitment, uint256 salt)
        external
        returns (PhilSepoliaMintAccountV1 account)
    {
        address predicted = getAddress(executionOwner, ownerCommitment, salt);
        if (predicted.code.length != 0) {
            isPhilSepoliaMintAccount[predicted] = true;
            return PhilSepoliaMintAccountV1(payable(predicted));
        }
        account = new PhilSepoliaMintAccountV1{salt: bytes32(salt)}(
            entryPoint, executionOwner, ownerCommitment, actionGate
        );
        isPhilSepoliaMintAccount[address(account)] = true;
        emit PhilSepoliaMintAccountCreated(address(account), executionOwner, ownerCommitment, salt);
    }

    function getAddress(address executionOwner, bytes32 ownerCommitment, uint256 salt)
        public
        view
        returns (address)
    {
        bytes memory initCode = abi.encodePacked(
            type(PhilSepoliaMintAccountV1).creationCode,
            abi.encode(entryPoint, executionOwner, ownerCommitment, actionGate)
        );
        return Create2.computeAddress(bytes32(salt), keccak256(initCode), address(this));
    }
}
