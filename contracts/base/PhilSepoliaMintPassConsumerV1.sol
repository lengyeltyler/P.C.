// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// @notice Harmless, non-transferable pass used only by the bounded Sepolia demo.
/// @dev This is not an ERC-721 implementation and represents no asset or value.
contract PhilSepoliaMintPassConsumerV1 {
    address public immutable actionGate;
    uint256 public nextTokenId = 1;

    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(bytes32 => uint256) public tokenIdByEnvelopeDigest;
    mapping(bytes32 => uint256) public tokenIdByRootNullifier;

    event PhilSepoliaMintPassIssued(
        bytes32 indexed authorizationEnvelopeDigest,
        bytes32 indexed rootProofNullifier,
        address indexed recipient,
        uint256 tokenId
    );

    error OnlyActionGate();
    error InvalidRecipient();
    error EnvelopeAlreadyMinted();
    error NullifierAlreadyMinted();

    constructor(address actionGate_) {
        if (actionGate_ == address(0)) revert OnlyActionGate();
        actionGate = actionGate_;
    }

    function consumeComposedMint(
        bytes32 authorizationEnvelopeDigest,
        bytes32 rootProofNullifier,
        address recipient
    ) external returns (uint256 tokenId) {
        if (msg.sender != actionGate) revert OnlyActionGate();
        if (recipient == address(0)) revert InvalidRecipient();
        if (tokenIdByEnvelopeDigest[authorizationEnvelopeDigest] != 0) revert EnvelopeAlreadyMinted();
        if (tokenIdByRootNullifier[rootProofNullifier] != 0) revert NullifierAlreadyMinted();

        tokenId = nextTokenId++;
        tokenIdByEnvelopeDigest[authorizationEnvelopeDigest] = tokenId;
        tokenIdByRootNullifier[rootProofNullifier] = tokenId;
        ownerOf[tokenId] = recipient;
        balanceOf[recipient] += 1;

        emit PhilSepoliaMintPassIssued(
            authorizationEnvelopeDigest,
            rootProofNullifier,
            recipient,
            tokenId
        );
    }
}
