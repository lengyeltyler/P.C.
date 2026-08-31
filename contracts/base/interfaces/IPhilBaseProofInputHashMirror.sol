// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPhilBaseProofInputHashMirror {
    function mirroredProofInputHashFact(uint256 factHigh, uint256 factLow) external view returns (bool);

    function mirrorProofInputHashFact(uint256 factHigh, uint256 factLow) external;
}
