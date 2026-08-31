// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStarknetMessaging} from "../interfaces/IStarknetMessaging.sol";

contract MockStarknetMessaging is IStarknetMessaging {
    mapping(bytes32 messageHash => uint256 count) public messageCount;

    error InvalidMessageToConsume();

    event MessageRegistered(bytes32 indexed messageHash, uint256 indexed fromAddress, address indexed toAddress);
    event MessageConsumed(bytes32 indexed messageHash, uint256 indexed fromAddress, address indexed toAddress);

    function registerMessageFromL2(uint256 fromAddress, address toAddress, uint256[] calldata payload)
        external
        returns (bytes32 messageHash)
    {
        messageHash = l2ToL1MessageHash(fromAddress, toAddress, payload);
        messageCount[messageHash] += 1;

        emit MessageRegistered(messageHash, fromAddress, toAddress);
    }

    function consumeMessageFromL2(uint256 fromAddress, uint256[] calldata payload)
        external
        override
        returns (bytes32 messageHash)
    {
        messageHash = l2ToL1MessageHash(fromAddress, msg.sender, payload);
        uint256 count = messageCount[messageHash];
        if (count == 0) revert InvalidMessageToConsume();

        unchecked {
            messageCount[messageHash] = count - 1;
        }

        emit MessageConsumed(messageHash, fromAddress, msg.sender);
    }

    function l2ToL1MessageHash(uint256 fromAddress, address toAddress, uint256[] memory payload)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(fromAddress, uint256(uint160(toAddress)), payload.length, payload));
    }
}
