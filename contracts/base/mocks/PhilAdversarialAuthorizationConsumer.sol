// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPhilAuthorizationConsumer} from "../interfaces/IPhilAuthorizationConsumer.sol";
import {IPhilAuthorizationTypes} from "../interfaces/IPhilAuthorizationTypes.sol";
import {PhilAuthorizationHashing} from "../PhilAuthorizationHashing.sol";

interface IPhilBaseActionGateLike is IPhilAuthorizationTypes {
    function verifyAndConsume(
        BaseActionAuthorization calldata authorization,
        UnlockProofPackage calldata proofPackage,
        bytes calldata consumerData
    ) external payable returns (bytes memory result);
}

contract PhilAdversarialAuthorizationConsumer is IPhilAuthorizationConsumer {
    enum Mode {
        RecordOnly,
        ReenterSameNullifier,
        CallAccountExecute,
        RevertAfterObserve,
        ReturnLargeData
    }

    Mode public mode;
    address public immutable actionGate;

    uint256 public consumeCount;
    uint256 public observedValue;
    bytes32 public lastNullifier;
    bool public reentryAttempted;
    bool public reentryFailed;
    bool public accountExecuteAttempted;
    bool public accountExecuteFailed;

    event AdversarialConsume(Mode mode, bytes32 indexed nullifier, uint256 value);

    error OnlyActionGate();
    error ForcedAdversarialRevert();

    constructor(address actionGate_) {
        actionGate = actionGate_;
    }

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function consumePhilAuthorization(BaseActionAuthorization calldata authorization, bytes calldata consumerData)
        external
        payable
        override
        returns (bytes memory result)
    {
        if (msg.sender != actionGate) revert OnlyActionGate();

        consumeCount += 1;
        observedValue = msg.value;
        lastNullifier = authorization.nullifier;

        if (mode == Mode.ReenterSameNullifier) {
            reentryAttempted = true;
            UnlockProofPackage memory proofPackage = _stubProofPackage(authorization);
            try IPhilBaseActionGateLike(actionGate).verifyAndConsume(authorization, proofPackage, consumerData) {
                reentryFailed = false;
            } catch {
                reentryFailed = true;
            }
        }

        if (mode == Mode.CallAccountExecute) {
            accountExecuteAttempted = true;
            (address account, address target, bytes memory data) = abi.decode(consumerData, (address, address, bytes));
            (bool ok,) = account.call(abi.encodeWithSignature("execute(address,uint256,bytes)", target, uint256(0), data));
            accountExecuteFailed = !ok;
        }

        emit AdversarialConsume(mode, authorization.nullifier, msg.value);

        if (mode == Mode.RevertAfterObserve) revert ForcedAdversarialRevert();
        if (mode == Mode.ReturnLargeData) return new bytes(8192);
        return abi.encode(mode, authorization.nullifier, msg.value);
    }

    function _stubProofPackage(BaseActionAuthorization calldata authorization)
        private
        pure
        returns (UnlockProofPackage memory proofPackage)
    {
        UnlockProofPublicInputs memory publicInputs = UnlockProofPublicInputs({
            ownerCommitment: authorization.ownerCommitment,
            actionHash: authorization.actionHash,
            policyHash: authorization.policyHash,
            nullifier: authorization.nullifier,
            consumerDataHash: authorization.consumerDataHash,
            expiry: authorization.expiry
        });
        proofPackage = UnlockProofPackage({
            version: "v1",
            proofType: "s-two",
            publicInputs: publicInputs,
            proofInputHash: bytes32(0),
            proofBlob: ""
        });
        proofPackage.proofInputHash = PhilAuthorizationHashing.unlockProofInputHash(proofPackage);
    }
}
