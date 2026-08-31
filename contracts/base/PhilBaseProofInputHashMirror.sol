// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilBaseProofInputHashMirror} from "./interfaces/IPhilBaseProofInputHashMirror.sol";
import {IBaseCrossDomainMessenger} from "./interfaces/IBaseCrossDomainMessenger.sol";

contract PhilBaseProofInputHashMirror is IPhilBaseProofInputHashMirror {
    address public immutable crossDomainMessenger;
    address public immutable authorizedL1Messenger;

    mapping(uint256 factHigh => mapping(uint256 factLow => bool mirrored)) public mirroredProofInputHashFact;

    uint256 public latestFactHigh;
    uint256 public latestFactLow;

    event ProofInputHashFactMirrored(
        address indexed messenger,
        address remoteSender,
        uint256 indexed factHigh,
        uint256 indexed factLow
    );

    error InvalidCrossDomainMessenger();
    error InvalidAuthorizedL1Messenger();
    error OnlyCrossDomainMessenger();
    error InvalidCrossDomainSender();

    constructor(address crossDomainMessenger_, address authorizedL1Messenger_) {
        if (crossDomainMessenger_ == address(0)) revert InvalidCrossDomainMessenger();
        if (authorizedL1Messenger_ == address(0)) revert InvalidAuthorizedL1Messenger();
        crossDomainMessenger = crossDomainMessenger_;
        authorizedL1Messenger = authorizedL1Messenger_;
    }

    function mirrorProofInputHashFact(uint256 factHigh, uint256 factLow) external override {
        if (msg.sender != crossDomainMessenger) revert OnlyCrossDomainMessenger();

        address remoteSender = IBaseCrossDomainMessenger(crossDomainMessenger).xDomainMessageSender();
        if (remoteSender != authorizedL1Messenger) revert InvalidCrossDomainSender();

        mirroredProofInputHashFact[factHigh][factLow] = true;
        latestFactHigh = factHigh;
        latestFactLow = factLow;

        emit ProofInputHashFactMirrored(msg.sender, remoteSender, factHigh, factLow);
    }
}
