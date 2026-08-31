// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, _packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";

interface IPhilCoreLocalProofConfirmationTargetV1 {
    function confirmPhilCoreAction(bytes32 actionId, bytes32 authorizationDigest) external;
}

/// @notice Disposable-testnet ERC-4337 account for PhilCore local-proof-gated-v1.
/// @dev Ethereum validates this bounded signature and call, not the local STWO proof.
contract PhilCore4337LocalProofAccountV1 is BaseAccount {
    uint8 public constant SIGNATURE_SCHEME_VERSION = 1;
    bytes32 public constant SECURITY_MODEL_ID = keccak256("local-proof-gated-v1");
    bytes32 public constant SIGNATURE_DOMAIN =
        keccak256("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1");
    uint256 public constant SIGNATURE_ENVELOPE_LENGTH = 9 * 32;

    IEntryPoint private immutable _entryPoint;
    address public immutable owner;
    bytes32 public immutable ownerCommitment;
    address public immutable approvedConfirmationTarget;
    bytes32 public immutable validatorKeyId;
    uint256 public immutable expectedChainId;

    event PhilCoreLocalProofAccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner,
        bytes32 indexed ownerCommitment,
        address approvedConfirmationTarget,
        bytes32 validatorKeyId,
        uint256 expectedChainId,
        bytes32 securityModelId
    );
    event PhilCoreLocalProofActionExecuted(
        bytes32 indexed actionId,
        bytes32 indexed authorizationDigest,
        address indexed confirmationTarget
    );

    error InvalidEntryPoint();
    error InvalidOwner();
    error InvalidOwnerCommitment();
    error InvalidConfirmationTarget();
    error InvalidValidatorKeyId();
    error WrongDeploymentChain();
    error UnauthorizedExecuteCaller();
    error AuthorizationExpired();

    constructor(
        IEntryPoint entryPoint_,
        address owner_,
        bytes32 ownerCommitment_,
        address approvedConfirmationTarget_,
        bytes32 validatorKeyId_,
        uint256 expectedChainId_
    ) {
        if (address(entryPoint_) == address(0)) revert InvalidEntryPoint();
        if (owner_ == address(0)) revert InvalidOwner();
        if (ownerCommitment_ == bytes32(0)) revert InvalidOwnerCommitment();
        if (approvedConfirmationTarget_ == address(0)) revert InvalidConfirmationTarget();
        if (validatorKeyId_ == bytes32(0)) revert InvalidValidatorKeyId();
        if (expectedChainId_ != block.chainid) revert WrongDeploymentChain();

        _entryPoint = entryPoint_;
        owner = owner_;
        ownerCommitment = ownerCommitment_;
        approvedConfirmationTarget = approvedConfirmationTarget_;
        validatorKeyId = validatorKeyId_;
        expectedChainId = expectedChainId_;

        emit PhilCoreLocalProofAccountInitialized(
            entryPoint_,
            owner_,
            ownerCommitment_,
            approvedConfirmationTarget_,
            validatorKeyId_,
            expectedChainId_,
            SECURITY_MODEL_ID
        );
    }

    receive() external payable {}

    function securityModelId() external pure returns (bytes32) {
        return SECURITY_MODEL_ID;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function executeLocalProofAuthorization(
        bytes32 actionId,
        bytes32 authorizationDigest,
        uint64 expiry
    ) external {
        _requireFromEntryPoint();
        if (block.timestamp > expiry) revert AuthorizationExpired();
        IPhilCoreLocalProofConfirmationTargetV1(approvedConfirmationTarget)
            .confirmPhilCoreAction(actionId, authorizationDigest);
        emit PhilCoreLocalProofActionExecuted(actionId, authorizationDigest, approvedConfirmationTarget);
    }

    function getAuthorizationDigest(
        bytes32 userOpHash,
        bytes32 actionId,
        bytes32 authorizationDigest,
        uint64 expiry
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNATURE_DOMAIN,
                SIGNATURE_SCHEME_VERSION,
                SECURITY_MODEL_ID,
                block.chainid,
                address(entryPoint()),
                address(this),
                userOpHash,
                actionId,
                authorizationDigest,
                expiry,
                validatorKeyId
            )
        );
    }

    function _requireFromEntryPoint() internal view override {
        if (msg.sender != address(entryPoint())) revert UnauthorizedExecuteCaller();
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        if (userOp.paymasterAndData.length != 0) return SIG_VALIDATION_FAILED;
        if (userOp.callData.length != 100) return SIG_VALIDATION_FAILED;
        if (bytes4(userOp.callData[:4]) != this.executeLocalProofAuthorization.selector) {
            return SIG_VALIDATION_FAILED;
        }
        if (userOp.signature.length != SIGNATURE_ENVELOPE_LENGTH) return SIG_VALIDATION_FAILED;

        (bytes32 actionId, bytes32 authorizationDigest, uint64 expiry) =
            abi.decode(userOp.callData[4:], (bytes32, bytes32, uint64));
        (
            uint8 version,
            bytes32 modelId,
            bytes32 signedActionId,
            bytes32 signedAuthorizationDigest,
            uint64 signedExpiry,
            bytes32 signedValidatorKeyId,
            bytes32 r,
            bytes32 s,
            uint8 v
        ) = abi.decode(
            userOp.signature,
            (uint8, bytes32, bytes32, bytes32, uint64, bytes32, bytes32, bytes32, uint8)
        );
        if (
            version != SIGNATURE_SCHEME_VERSION
                || modelId != SECURITY_MODEL_ID
                || signedActionId != actionId
                || signedAuthorizationDigest != authorizationDigest
                || signedExpiry != expiry
                || signedValidatorKeyId != validatorKeyId
                || expiry > type(uint48).max
        ) return SIG_VALIDATION_FAILED;

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            getAuthorizationDigest(userOpHash, actionId, authorizationDigest, expiry)
        );
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, v, r, s);
        if (error != ECDSA.RecoverError.NoError || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, uint48(expiry), 0);
    }
}
