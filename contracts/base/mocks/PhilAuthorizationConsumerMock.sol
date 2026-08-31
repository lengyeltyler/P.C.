// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationConsumer} from "../interfaces/IPhilAuthorizationConsumer.sol";

contract PhilAuthorizationConsumerMock is IPhilAuthorizationConsumer {
    bytes32 public lastNullifier;
    bytes32 public lastActionHash;
    bytes public lastConsumerData;
    uint256 public consumeCount;

    event AuthorizationObserved(bytes32 indexed nullifier, bytes32 indexed actionHash, bytes consumerData);

    function consumePhilAuthorization(BaseActionAuthorization calldata authorization, bytes calldata consumerData)
        external
        payable
        override
        returns (bytes memory result)
    {
        lastNullifier = authorization.nullifier;
        lastActionHash = authorization.actionHash;
        lastConsumerData = consumerData;
        consumeCount += 1;

        emit AuthorizationObserved(authorization.nullifier, authorization.actionHash, consumerData);
        return consumerData;
    }
}
