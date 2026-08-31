// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPhilCrossDomainMessenger {
    function sendMessage(address target, bytes calldata message) external;

    function xDomainMessageSender() external view returns (address);
}
