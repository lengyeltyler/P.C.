// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPhilL1ProofInputHashAnchor {
    function anchoredProofInputHashFact(uint256 factHigh, uint256 factLow) external view returns (bool);
}
