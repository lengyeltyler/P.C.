// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationTypes} from "./IPhilAuthorizationTypes.sol";

interface IPhilAuthorizationConsumer is IPhilAuthorizationTypes {
    function consumePhilAuthorization(
        BaseActionAuthorization calldata authorization,
        bytes calldata consumerData
    ) external payable returns (bytes memory result);
}
