// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBaseCrossDomainMessenger} from "../interfaces/IBaseCrossDomainMessenger.sol";

contract MockBaseCrossDomainMessenger is IBaseCrossDomainMessenger {
    address private _xDomainMessageSender;

    address public lastTarget;
    bytes public lastMessage;
    uint32 public lastMinGasLimit;

    event MessageSent(address indexed target, address indexed remoteSender, bytes message, uint32 minGasLimit);

    error TargetCallFailed(bytes reason);

    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable override {
        lastTarget = target;
        lastMessage = message;
        lastMinGasLimit = minGasLimit;

        _xDomainMessageSender = msg.sender;
        (bool ok, bytes memory reason) = target.call(message);
        _xDomainMessageSender = address(0);

        if (!ok) revert TargetCallFailed(reason);

        emit MessageSent(target, msg.sender, message, minGasLimit);
    }

    function xDomainMessageSender() external view override returns (address) {
        return _xDomainMessageSender;
    }
}
