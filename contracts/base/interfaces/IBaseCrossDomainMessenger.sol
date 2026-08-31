// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBaseCrossDomainMessenger {
    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable;

    function xDomainMessageSender() external view returns (address);
}
