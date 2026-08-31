// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilCrossDomainMessenger} from "../base/interfaces/IPhilCrossDomainMessenger.sol";
import {IBaseCrossDomainMessenger} from "../base/interfaces/IBaseCrossDomainMessenger.sol";

contract PhilBaseCrossDomainMessengerAdapter is IPhilCrossDomainMessenger {
    IBaseCrossDomainMessenger public immutable baseCrossDomainMessenger;
    uint32 public immutable minGasLimit;

    error InvalidBaseCrossDomainMessenger();

    constructor(address baseCrossDomainMessenger_, uint32 minGasLimit_) {
        if (baseCrossDomainMessenger_ == address(0)) revert InvalidBaseCrossDomainMessenger();
        baseCrossDomainMessenger = IBaseCrossDomainMessenger(baseCrossDomainMessenger_);
        minGasLimit = minGasLimit_;
    }

    function sendMessage(address target, bytes calldata message) external override {
        baseCrossDomainMessenger.sendMessage(target, message, minGasLimit);
    }

    function xDomainMessageSender() external view override returns (address) {
        return baseCrossDomainMessenger.xDomainMessageSender();
    }
}
