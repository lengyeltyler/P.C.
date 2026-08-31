// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPhilCoreLocalProofAccountV1 {
    function securityModelId() external pure returns (bytes32);
    function approvedConfirmationTarget() external view returns (address);
    function expectedChainId() external view returns (uint256);
}
