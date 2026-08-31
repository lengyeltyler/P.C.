// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

interface IPhilSepoliaLocalComposedActionGateV1 {
    function verifyAndConsume(
        bytes32 authorizationEnvelopeDigest,
        bytes32 rootProofNullifier,
        bytes32 deviceApprovalNonce,
        uint64 validUntil,
        address mintRecipient
    ) external returns (uint256 tokenId);
}
