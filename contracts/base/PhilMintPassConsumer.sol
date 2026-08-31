// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationConsumer} from "./interfaces/IPhilAuthorizationConsumer.sol";

contract PhilMintPassConsumer is IPhilAuthorizationConsumer {
    address public immutable actionGate;

    uint256 public nextTokenId = 1;
    bytes32 public lastMintedNullifier;
    uint256 public lastMintedTokenId;
    bytes public lastConsumerData;
    address public lastMintRecipient;

    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(bytes32 => bool) public mintedNullifier;
    mapping(bytes32 => uint256) public mintedTokenIdByNullifier;
    mapping(bytes32 => address) public mintedRecipientByNullifier;

    event MintPassIssued(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 indexed tokenId,
        bytes consumerData
    );

    error OnlyActionGate();
    error InvalidMintRecipient();
    error NullifierAlreadyMinted();
    error UnexpectedMintPassValue();

    bytes32 private constant _MINT_RECIPIENT_BINDING_DOMAIN =
        keccak256("PHIL_MINT_RECIPIENT_BINDING_V1");

    constructor(address actionGate_) {
        if (actionGate_ == address(0)) revert OnlyActionGate();

        actionGate = actionGate_;
    }

    function previewBoundMintRecipient(
        BaseActionAuthorization calldata authorization,
        bytes calldata consumerData
    ) public pure returns (address) {
        address recipient = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encode(
                            _MINT_RECIPIENT_BINDING_DOMAIN,
                            authorization.ownerCommitment,
                            consumerData
                        )
                    )
                )
            )
        );

        if (recipient == address(0)) revert InvalidMintRecipient();
        return recipient;
    }

    function assertBoundMintRecipient(
        BaseActionAuthorization calldata authorization,
        bytes calldata consumerData,
        address expectedRecipient
    ) external pure returns (address) {
        address recipient = previewBoundMintRecipient(authorization, consumerData);
        if (recipient != expectedRecipient) revert InvalidMintRecipient();
        return recipient;
    }

    function previewMintClaim(
        BaseActionAuthorization calldata authorization,
        bytes calldata consumerData
    ) external view returns (address recipient, uint256 tokenId) {
        recipient = previewBoundMintRecipient(authorization, consumerData);
        tokenId = nextTokenId;
    }

    function getMintClaim(bytes32 nullifier) external view returns (bool minted, address recipient, uint256 tokenId) {
        minted = mintedNullifier[nullifier];
        recipient = mintedRecipientByNullifier[nullifier];
        tokenId = mintedTokenIdByNullifier[nullifier];
    }

    function consumePhilAuthorization(BaseActionAuthorization calldata authorization, bytes calldata consumerData)
        external
        payable
        override
        returns (bytes memory result)
    {
        if (msg.sender != actionGate) revert OnlyActionGate();
        if (msg.value != 0) revert UnexpectedMintPassValue();
        if (mintedNullifier[authorization.nullifier]) revert NullifierAlreadyMinted();

        address mintRecipient = previewBoundMintRecipient(authorization, consumerData);

        uint256 tokenId = nextTokenId;
        nextTokenId = tokenId + 1;

        mintedNullifier[authorization.nullifier] = true;
        mintedTokenIdByNullifier[authorization.nullifier] = tokenId;
        mintedRecipientByNullifier[authorization.nullifier] = mintRecipient;
        ownerOf[tokenId] = mintRecipient;
        balanceOf[mintRecipient] += 1;
        lastMintedNullifier = authorization.nullifier;
        lastMintedTokenId = tokenId;
        lastConsumerData = consumerData;
        lastMintRecipient = mintRecipient;

        emit MintPassIssued(authorization.nullifier, mintRecipient, tokenId, consumerData);

        return abi.encode(tokenId, mintRecipient, authorization.nullifier);
    }
}
