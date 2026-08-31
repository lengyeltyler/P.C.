// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {IPhilSepoliaMintAccountFactoryV1} from "./erc4337/interfaces/IPhilSepoliaMintAccountFactoryV1.sol";
import {PhilSepoliaMintPassConsumerV1} from "./PhilSepoliaMintPassConsumerV1.sol";

interface IPhilSepoliaMintAccountOwnerV1 {
    function owner() external view returns (address);
}

interface IPhilSepoliaLegacyMintAccountOwnerV1 {
    function executionOwner() external view returns (address);
}

/// @notice Restricted on-chain enforcement for the local-composed Sepolia demo.
/// @dev Noir and P-256 are NOT verified here. This gate trusts only the ERC-4337
///      account signature that PhilCore releases after local composed authorization.
contract PhilSepoliaLocalComposedActionGateV1 {
    uint256 public immutable expectedChainId;
    IPhilSepoliaMintAccountFactoryV1 public immutable accountFactory;
    PhilSepoliaMintPassConsumerV1 public immutable mintConsumer;
    address public immutable authorizedAccount;

    mapping(bytes32 => bool) public consumedEnvelopeDigest;
    mapping(bytes32 => bool) public consumedRootNullifier;
    mapping(bytes32 => bool) public consumedDeviceApprovalNonce;

    event PhilSepoliaLocalComposedAuthorizationConsumed(
        bytes32 indexed authorizationEnvelopeDigest,
        bytes32 indexed rootProofNullifier,
        bytes32 indexed deviceApprovalNonce,
        address account,
        address recipient,
        uint256 tokenId
    );

    error WrongChain();
    error UnauthorizedAccount();
    error UnauthorizedAccountBinding();
    error AuthorizationExpired();
    error InvalidAuthorizationField();
    error MintRecipientNotCurrentOwner();
    error EnvelopeAlreadyConsumed();
    error RootNullifierAlreadyConsumed();
    error DeviceApprovalNonceAlreadyConsumed();

    constructor(
        uint256 expectedChainId_,
        address accountFactory_,
        address mintConsumer_,
        address authorizedAccount_
    ) {
        if (
            expectedChainId_ == 0 || accountFactory_ == address(0) || mintConsumer_ == address(0)
                || authorizedAccount_ == address(0)
        ) {
            revert InvalidAuthorizationField();
        }
        expectedChainId = expectedChainId_;
        accountFactory = IPhilSepoliaMintAccountFactoryV1(accountFactory_);
        mintConsumer = PhilSepoliaMintPassConsumerV1(mintConsumer_);
        authorizedAccount = authorizedAccount_;
    }

    function verifyAndConsume(
        bytes32 authorizationEnvelopeDigest,
        bytes32 rootProofNullifier,
        bytes32 deviceApprovalNonce,
        uint64 validUntil,
        address mintRecipient
    ) external returns (uint256 tokenId) {
        if (block.chainid != expectedChainId) revert WrongChain();
        if (!accountFactory.isPhilSepoliaMintAccount(msg.sender)) revert UnauthorizedAccount();
        if (msg.sender != authorizedAccount) revert UnauthorizedAccountBinding();
        if (
            authorizationEnvelopeDigest == bytes32(0) || rootProofNullifier == bytes32(0)
                || deviceApprovalNonce == bytes32(0) || validUntil == 0 || mintRecipient == address(0)
        ) revert InvalidAuthorizationField();
        if (mintRecipient != _currentExecutionOwner(msg.sender)) {
            revert MintRecipientNotCurrentOwner();
        }
        if (block.timestamp > validUntil) revert AuthorizationExpired();
        if (consumedEnvelopeDigest[authorizationEnvelopeDigest]) revert EnvelopeAlreadyConsumed();
        if (consumedRootNullifier[rootProofNullifier]) revert RootNullifierAlreadyConsumed();
        if (consumedDeviceApprovalNonce[deviceApprovalNonce]) revert DeviceApprovalNonceAlreadyConsumed();

        consumedEnvelopeDigest[authorizationEnvelopeDigest] = true;
        consumedRootNullifier[rootProofNullifier] = true;
        consumedDeviceApprovalNonce[deviceApprovalNonce] = true;
        tokenId = mintConsumer.consumeComposedMint(
            authorizationEnvelopeDigest,
            rootProofNullifier,
            mintRecipient
        );

        emit PhilSepoliaLocalComposedAuthorizationConsumed(
            authorizationEnvelopeDigest,
            rootProofNullifier,
            deviceApprovalNonce,
            msg.sender,
            mintRecipient,
            tokenId
        );
    }

    function _currentExecutionOwner(address account) private view returns (address currentOwner) {
        (bool success, bytes memory result) = account.staticcall(
            abi.encodeWithSelector(IPhilSepoliaMintAccountOwnerV1.owner.selector)
        );
        if (!success || result.length != 32) {
            (success, result) = account.staticcall(
                abi.encodeWithSelector(IPhilSepoliaLegacyMintAccountOwnerV1.executionOwner.selector)
            );
        }
        if (!success || result.length != 32) revert UnauthorizedAccount();
        currentOwner = abi.decode(result, (address));
    }
}
