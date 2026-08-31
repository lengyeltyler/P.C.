// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilCrossDomainMessenger} from "../interfaces/IPhilCrossDomainMessenger.sol";

contract MockPhilCrossDomainMessenger is IPhilCrossDomainMessenger {
    address private _xDomainMessageSender;

    event MessageSent(address indexed target, address indexed remoteSender, bytes message);

    error TargetCallFailed(bytes reason);

    function sendMessage(address target, bytes calldata message) external override {
        _xDomainMessageSender = msg.sender;
        (bool ok, bytes memory reason) = target.call(message);
        _xDomainMessageSender = address(0);

        if (!ok) revert TargetCallFailed(reason);

        emit MessageSent(target, msg.sender, message);
    }

    function xDomainMessageSender() external view override returns (address) {
        return _xDomainMessageSender;
    }
}
