// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStarknetMessaging} from "./interfaces/IStarknetMessaging.sol";

contract PhilL1ProofInputHashAnchor {
    IStarknetMessaging public immutable starknetMessaging;
    uint256 public immutable sourceL2Verifier;

    mapping(uint256 factHigh => mapping(uint256 factLow => bool anchored)) public anchoredProofInputHashFact;

    uint256 public latestFactHigh;
    uint256 public latestFactLow;

    event ProofInputHashFactAnchored(
        uint256 indexed sourceL2Verifier,
        uint256 indexed factHigh,
        uint256 indexed factLow
    );

    error InvalidStarknetMessaging();

    constructor(address starknetMessaging_, uint256 sourceL2Verifier_) {
        if (starknetMessaging_ == address(0)) revert InvalidStarknetMessaging();
        starknetMessaging = IStarknetMessaging(starknetMessaging_);
        sourceL2Verifier = sourceL2Verifier_;
    }

    function consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow) external returns (bytes32 messageHash) {
        uint256[] memory payload = new uint256[](2);
        payload[0] = factHigh;
        payload[1] = factLow;

        messageHash = starknetMessaging.consumeMessageFromL2(sourceL2Verifier, payload);
        anchoredProofInputHashFact[factHigh][factLow] = true;
        latestFactHigh = factHigh;
        latestFactLow = factLow;

        emit ProofInputHashFactAnchored(sourceL2Verifier, factHigh, factLow);
    }
}
