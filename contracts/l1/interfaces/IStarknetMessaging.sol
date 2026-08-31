// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IStarknetMessaging {
    function consumeMessageFromL2(uint256 fromAddress, uint256[] calldata payload) external returns (bytes32);
}
