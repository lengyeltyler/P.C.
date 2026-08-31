// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationConsumer} from "./interfaces/IPhilAuthorizationConsumer.sol";
import {PhilAuthorizationHashing} from "./PhilAuthorizationHashing.sol";

contract PhilUnlockConsumer is IPhilAuthorizationConsumer {
    address public immutable actionGate;

    event UnlockForwarded(
        bytes32 indexed nullifier,
        address indexed account,
        address indexed target,
        bytes32 actionHash
    );

    error OnlyActionGate();
    error InvalidAccount();
    error InvalidTarget();
    error IncorrectValue();
    error InvalidActionHash();
    error DownstreamCallFailed(bytes reason);

    constructor(address actionGate_) {
        if (actionGate_ == address(0)) revert InvalidTarget();
        actionGate = actionGate_;
    }

    function computeUnlockActionHash(UnlockRequest calldata request) public view returns (bytes32) {
        return
            PhilAuthorizationHashing.unlockActionHash(
                block.chainid,
                address(this),
                request.account,
                request.target,
                request.value,
                keccak256(request.callData)
            );
    }

    function consumePhilAuthorization(BaseActionAuthorization calldata authorization, bytes calldata consumerData)
        external
        payable
        override
        returns (bytes memory result)
    {
        if (msg.sender != actionGate) revert OnlyActionGate();

        UnlockRequest memory request = abi.decode(consumerData, (UnlockRequest));
        if (request.account == address(0)) revert InvalidAccount();
        if (request.target == address(0)) revert InvalidTarget();
        if (msg.value != request.value) revert IncorrectValue();

        bytes32 actionHash = PhilAuthorizationHashing.unlockActionHash(
            block.chainid,
            address(this),
            request.account,
            request.target,
            request.value,
            keccak256(request.callData)
        );
        if (actionHash != authorization.actionHash) revert InvalidActionHash();

        (bool ok, bytes memory returnData) = request.target.call{value: request.value}(
            abi.encodeWithSignature(
                "onPhilUnlock(address,bytes32,bytes)",
                request.account,
                authorization.nullifier,
                request.callData
            )
        );
        if (!ok) revert DownstreamCallFailed(returnData);

        emit UnlockForwarded(authorization.nullifier, request.account, request.target, actionHash);
        return returnData;
    }
}
