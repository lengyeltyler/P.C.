// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

interface IPhilSepoliaMintAccountFactoryV1 {
    function isPhilSepoliaMintAccount(address account) external view returns (bool);
}
