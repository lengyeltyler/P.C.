// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilL1ProofInputHashAnchor} from "../base/interfaces/IPhilL1ProofInputHashAnchor.sol";
import {IPhilBaseProofInputHashMirror} from "../base/interfaces/IPhilBaseProofInputHashMirror.sol";
import {IPhilCrossDomainMessenger} from "../base/interfaces/IPhilCrossDomainMessenger.sol";

contract PhilL1ToBaseProofInputHashMessenger {
    IPhilL1ProofInputHashAnchor public immutable trustAnchor;
    IPhilCrossDomainMessenger public immutable crossDomainMessenger;

    event ProofInputHashFactRelayedToBase(
        address indexed baseMirror,
        uint256 indexed factHigh,
        uint256 indexed factLow
    );

    error InvalidTrustAnchor();
    error InvalidCrossDomainMessenger();
    error InvalidBaseMirror();
    error UnanchoredFact();

    constructor(address trustAnchor_, address crossDomainMessenger_) {
        if (trustAnchor_ == address(0)) revert InvalidTrustAnchor();
        if (crossDomainMessenger_ == address(0)) revert InvalidCrossDomainMessenger();
        trustAnchor = IPhilL1ProofInputHashAnchor(trustAnchor_);
        crossDomainMessenger = IPhilCrossDomainMessenger(crossDomainMessenger_);
    }

    function relayProofInputHashFactToBase(address baseMirror, uint256 factHigh, uint256 factLow) external {
        if (baseMirror == address(0)) revert InvalidBaseMirror();
        if (!trustAnchor.anchoredProofInputHashFact(factHigh, factLow)) revert UnanchoredFact();

        crossDomainMessenger.sendMessage(
            baseMirror,
            abi.encodeCall(IPhilBaseProofInputHashMirror.mirrorProofInputHashFact, (factHigh, factLow))
        );

        emit ProofInputHashFactRelayedToBase(baseMirror, factHigh, factLow);
    }
}
