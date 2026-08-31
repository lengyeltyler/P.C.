// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";

/// @notice Minimal ERC-4337 account foundation for PhilCore local/Beta validation.
/// @dev This account is intentionally non-upgradeable, single-call only, and unaudited.
contract PhilCore4337Account is BaseAccount {
    IEntryPoint private immutable _entryPoint;

    address private _owner;
    address private _recoveryAuthority;
    bytes32 public immutable ownerCommitment;
    address public immutable approvedActionGate;
    uint64 public immutable recoveryDelaySeconds;
    uint64 public immutable recoveryExpirySeconds;

    bytes4 public constant VERIFY_AND_CONSUME_SELECTOR = 0xb1952061;
    bytes4 public constant COMPOSED_VERIFY_AND_CONSUME_SELECTOR = 0xfa724deb;

    struct RecoveryRequest {
        address pendingOwner;
        uint64 requestedAt;
        uint64 executableAfter;
        uint64 expiresAt;
        bytes32 requestId;
        bool active;
    }

    struct RecoveryAuthorityRotationRequest {
        address pendingRecoveryAuthority;
        address proposer;
        uint64 requestedAt;
        uint64 executableAfter;
        uint64 expiresAt;
        bytes32 requestId;
        bool active;
    }

    RecoveryRequest private _recoveryRequest;
    RecoveryAuthorityRotationRequest private _recoveryAuthorityRotationRequest;
    bool public frozen;

    event PhilCore4337AccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner,
        bytes32 indexed ownerCommitment,
        address approvedActionGate,
        address recoveryAuthority,
        uint64 recoveryDelaySeconds,
        uint64 recoveryExpirySeconds
    );
    event ExecutionOwnerRotated(address indexed previousOwner, address indexed newOwner, bytes32 indexed ownerCommitment);
    event RecoveryRequested(
        bytes32 indexed requestId,
        address indexed recoveryAuthority,
        address indexed pendingOwner,
        uint64 requestedAt,
        uint64 executableAfter,
        uint64 expiresAt
    );
    event RecoveryCancelled(bytes32 indexed requestId, address indexed cancelledBy);
    event RecoveryCompleted(bytes32 indexed requestId, address indexed previousOwner, address indexed newOwner);
    event RecoveryFrozen(bytes32 indexed requestId);
    event RecoveryUnfrozen(bytes32 indexed requestId);
    event RecoveryAuthorityRotationRequested(
        bytes32 indexed requestId,
        address indexed proposer,
        address indexed pendingRecoveryAuthority,
        uint64 requestedAt,
        uint64 executableAfter,
        uint64 expiresAt
    );
    event RecoveryAuthorityRotationCancelled(bytes32 indexed requestId, address indexed cancelledBy);
    event RecoveryAuthorityRotationCompleted(
        bytes32 indexed requestId,
        address indexed previousRecoveryAuthority,
        address indexed newRecoveryAuthority
    );
    event TestFundsReleased(
        address indexed recipient,
        uint256 nativeAmountWei,
        uint256 entryPointDepositAmountWei
    );

    error InvalidEntryPoint();
    error InvalidOwner();
    error InvalidActionGate();
    error InvalidRecoveryAuthority();
    error InvalidRecoveryDelay();
    error UnauthorizedExecuteCaller();
    error UnauthorizedMaintenanceCaller();
    error UnauthorizedExecutionTarget();
    error UnauthorizedExecutionSelector();
    error NonZeroActionValueForbidden();
    error PaymasterForbidden();
    error AccountFrozen();
    error InvalidTestFundRelease();
    error TestFundReleaseFailed();
    error RecoveryAlreadyActive();
    error RecoveryNotActive();
    error RecoveryDelayNotElapsed();
    error RecoveryExpired();
    error RecoveryRequestIdMismatch();
    error RecoveryPendingOwnerMismatch();
    error RecoveryAuthorityRotationAlreadyActive();
    error RecoveryAuthorityRotationNotActive();
    error RecoveryAuthorityRotationDelayNotElapsed();
    error RecoveryAuthorityRotationExpired();
    error RecoveryAuthorityRotationRequestIdMismatch();
    error RecoveryAuthorityRotationPendingAuthorityMismatch();
    error RecoveryAuthorityRotationUnauthorizedCanceller();
    error ExecutionFailed(bytes reason);

    constructor(
        IEntryPoint entryPoint_,
        address owner_,
        bytes32 ownerCommitment_,
        address approvedActionGate_,
        address recoveryAuthority_,
        uint64 recoveryDelaySeconds_,
        uint64 recoveryExpirySeconds_
    ) {
        if (address(entryPoint_) == address(0)) revert InvalidEntryPoint();
        if (owner_ == address(0)) revert InvalidOwner();
        if (ownerCommitment_ == bytes32(0)) revert InvalidOwner();
        if (approvedActionGate_ == address(0)) revert InvalidActionGate();
        if (recoveryAuthority_ == address(0) || recoveryAuthority_ == owner_) revert InvalidRecoveryAuthority();
        if (recoveryDelaySeconds_ == 0 || recoveryExpirySeconds_ <= recoveryDelaySeconds_) revert InvalidRecoveryDelay();

        _entryPoint = entryPoint_;
        _owner = owner_;
        ownerCommitment = ownerCommitment_;
        approvedActionGate = approvedActionGate_;
        _recoveryAuthority = recoveryAuthority_;
        recoveryDelaySeconds = recoveryDelaySeconds_;
        recoveryExpirySeconds = recoveryExpirySeconds_;

        emit PhilCore4337AccountInitialized(
            entryPoint_,
            owner_,
            ownerCommitment_,
            approvedActionGate_,
            recoveryAuthority_,
            recoveryDelaySeconds_,
            recoveryExpirySeconds_
        );
    }

    receive() external payable {}

    function owner() public view returns (address) {
        return _owner;
    }

    function recoveryAuthority() public view returns (address) {
        return _recoveryAuthority;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        _requireFromEntryPoint();
        if (userOp.paymasterAndData.length != 0) revert PaymasterForbidden();
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        _requireFromEntryPoint();
        if (frozen) revert AccountFrozen();
        if (target != approvedActionGate) revert UnauthorizedExecutionTarget();
        if (value != 0) revert NonZeroActionValueForbidden();
        if (
            data.length < 4
                || (
                    bytes4(data[:4]) != VERIFY_AND_CONSUME_SELECTOR
                        && bytes4(data[:4]) != COMPOSED_VERIFY_AND_CONSUME_SELECTOR
                )
        ) {
            revert UnauthorizedExecutionSelector();
        }
        (bool success, bytes memory result) = target.call(data);
        if (!success) revert ExecutionFailed(result);
    }

    /// @notice Returns bounded disposable Beta funds to the current execution owner.
    /// @dev This is an EntryPoint-only maintenance action. It cannot choose an
    ///      arbitrary recipient and the recovery authority cannot authorize it.
    function releaseTestFunds(uint256 nativeAmountWei, uint256 entryPointDepositAmountWei)
        external
    {
        _requireFromEntryPoint();
        if (frozen) revert AccountFrozen();
        if (
            (nativeAmountWei == 0 && entryPointDepositAmountWei == 0)
                || nativeAmountWei > address(this).balance
                || entryPointDepositAmountWei > entryPoint().balanceOf(address(this))
        ) revert InvalidTestFundRelease();

        address payable recipient = payable(_owner);
        if (entryPointDepositAmountWei != 0) {
            entryPoint().withdrawTo(recipient, entryPointDepositAmountWei);
        }
        if (nativeAmountWei != 0) {
            (bool success,) = recipient.call{value: nativeAmountWei}("");
            if (!success) revert TestFundReleaseFailed();
        }
        emit TestFundsReleased(recipient, nativeAmountWei, entryPointDepositAmountWei);
    }

    function rotateExecutionOwner(address newOwner) external {
        _requireOwnerMaintenanceCaller();
        if (frozen) revert AccountFrozen();
        _rotateOwner(newOwner);
    }

    function requestRecovery(address pendingOwner) external returns (bytes32 requestId) {
        if (msg.sender != _recoveryAuthority && msg.sender != address(entryPoint())) revert UnauthorizedMaintenanceCaller();
        if (_recoveryRequest.active) revert RecoveryAlreadyActive();
        if (pendingOwner == address(0) || pendingOwner == _owner) revert InvalidOwner();

        uint64 requestedAt = uint64(block.timestamp);
        uint64 executableAfter = requestedAt + recoveryDelaySeconds;
        uint64 expiresAt = requestedAt + recoveryExpirySeconds;
        requestId = keccak256(
            abi.encode(
                address(this),
                _owner,
                pendingOwner,
                _recoveryAuthority,
                ownerCommitment,
                requestedAt,
                block.chainid
            )
        );

        _recoveryRequest = RecoveryRequest({
            pendingOwner: pendingOwner,
            requestedAt: requestedAt,
            executableAfter: executableAfter,
            expiresAt: expiresAt,
            requestId: requestId,
            active: true
        });
        frozen = true;

        emit RecoveryRequested(requestId, _recoveryAuthority, pendingOwner, requestedAt, executableAfter, expiresAt);
        emit RecoveryFrozen(requestId);
    }

    function cancelRecovery(bytes32 requestId) external {
        _requireRecoveryActiveNoExpiry(requestId);
        if (msg.sender != _owner && msg.sender != address(entryPoint())) {
            revert UnauthorizedMaintenanceCaller();
        }
        bytes32 cancelledRequestId = _recoveryRequest.requestId;
        delete _recoveryRequest;
        frozen = false;
        emit RecoveryCancelled(cancelledRequestId, msg.sender);
        emit RecoveryUnfrozen(cancelledRequestId);
    }

    function completeRecovery(bytes32 requestId, address expectedPendingOwner) external {
        if (msg.sender != _recoveryAuthority && msg.sender != address(entryPoint())) revert UnauthorizedMaintenanceCaller();
        _requireRecoveryActive(requestId);
        RecoveryRequest memory pending = _recoveryRequest;
        if (pending.pendingOwner != expectedPendingOwner) revert RecoveryPendingOwnerMismatch();
        if (block.timestamp < pending.executableAfter) revert RecoveryDelayNotElapsed();
        if (block.timestamp > pending.expiresAt) revert RecoveryExpired();

        address previousOwner = _owner;
        _owner = pending.pendingOwner;
        delete _recoveryRequest;
        frozen = false;

        emit RecoveryCompleted(pending.requestId, previousOwner, _owner);
        emit ExecutionOwnerRotated(previousOwner, _owner, ownerCommitment);
        emit RecoveryUnfrozen(pending.requestId);
    }

    function requestRecoveryAuthorityRotation(address pendingRecoveryAuthority, address expectedProposer)
        external
        returns (bytes32 requestId)
    {
        if (frozen) revert AccountFrozen();
        if (msg.sender != expectedProposer && msg.sender != address(entryPoint())) revert UnauthorizedMaintenanceCaller();
        if (expectedProposer != _owner && expectedProposer != _recoveryAuthority) {
            revert UnauthorizedMaintenanceCaller();
        }
        if (_recoveryAuthorityRotationRequest.active) revert RecoveryAuthorityRotationAlreadyActive();
        if (
            pendingRecoveryAuthority == address(0)
                || pendingRecoveryAuthority == _recoveryAuthority
                || pendingRecoveryAuthority == _owner
        ) revert InvalidRecoveryAuthority();

        uint64 requestedAt = uint64(block.timestamp);
        uint64 executableAfter = requestedAt + recoveryDelaySeconds;
        uint64 expiresAt = requestedAt + recoveryExpirySeconds;
        requestId = keccak256(
            abi.encode(
                address(this),
                _owner,
                _recoveryAuthority,
                pendingRecoveryAuthority,
                expectedProposer,
                ownerCommitment,
                requestedAt,
                block.chainid
            )
        );

        _recoveryAuthorityRotationRequest = RecoveryAuthorityRotationRequest({
            pendingRecoveryAuthority: pendingRecoveryAuthority,
            proposer: expectedProposer,
            requestedAt: requestedAt,
            executableAfter: executableAfter,
            expiresAt: expiresAt,
            requestId: requestId,
            active: true
        });

        emit RecoveryAuthorityRotationRequested(
            requestId,
            expectedProposer,
            pendingRecoveryAuthority,
            requestedAt,
            executableAfter,
            expiresAt
        );
    }

    function cancelRecoveryAuthorityRotation(bytes32 requestId, address expectedCanceller) external {
        if (msg.sender != expectedCanceller && msg.sender != address(entryPoint())) revert UnauthorizedMaintenanceCaller();
        _requireRecoveryAuthorityRotationActiveNoExpiry(requestId);
        RecoveryAuthorityRotationRequest memory pending = _recoveryAuthorityRotationRequest;
        address requiredCanceller = pending.proposer == _owner ? _recoveryAuthority : _owner;
        if (expectedCanceller != requiredCanceller) revert RecoveryAuthorityRotationUnauthorizedCanceller();

        delete _recoveryAuthorityRotationRequest;
        emit RecoveryAuthorityRotationCancelled(pending.requestId, expectedCanceller);
    }

    function completeRecoveryAuthorityRotation(bytes32 requestId, address expectedPendingRecoveryAuthority) external {
        if (frozen) revert AccountFrozen();
        _requireRecoveryAuthorityRotationActive(requestId);
        RecoveryAuthorityRotationRequest memory pending = _recoveryAuthorityRotationRequest;
        if (pending.pendingRecoveryAuthority != expectedPendingRecoveryAuthority) {
            revert RecoveryAuthorityRotationPendingAuthorityMismatch();
        }
        if (block.timestamp < pending.executableAfter) revert RecoveryAuthorityRotationDelayNotElapsed();
        if (block.timestamp > pending.expiresAt) revert RecoveryAuthorityRotationExpired();

        address previousRecoveryAuthority = _recoveryAuthority;
        _recoveryAuthority = pending.pendingRecoveryAuthority;
        delete _recoveryAuthorityRotationRequest;

        emit RecoveryAuthorityRotationCompleted(pending.requestId, previousRecoveryAuthority, _recoveryAuthority);
    }

    function recoveryRequest()
        external
        view
        returns (
            address pendingOwner,
            uint64 requestedAt,
            uint64 executableAfter,
            uint64 expiresAt,
            bytes32 requestId,
            bool active
        )
    {
        RecoveryRequest memory pending = _recoveryRequest;
        return (
            pending.pendingOwner,
            pending.requestedAt,
            pending.executableAfter,
            pending.expiresAt,
            pending.requestId,
            pending.active
        );
    }

    function recoveryAuthorityRotationRequest()
        external
        view
        returns (
            address pendingRecoveryAuthority,
            address proposer,
            uint64 requestedAt,
            uint64 executableAfter,
            uint64 expiresAt,
            bytes32 requestId,
            bool active
        )
    {
        RecoveryAuthorityRotationRequest memory pending = _recoveryAuthorityRotationRequest;
        return (
            pending.pendingRecoveryAuthority,
            pending.proposer,
            pending.requestedAt,
            pending.executableAfter,
            pending.expiresAt,
            pending.requestId,
            pending.active
        );
    }

    function _requireFromEntryPoint() internal view override {
        if (msg.sender != address(entryPoint())) {
            revert UnauthorizedExecuteCaller();
        }
    }

    function _requireOwnerMaintenanceCaller() internal view {
        if (msg.sender != _owner && msg.sender != address(entryPoint())) {
            revert UnauthorizedMaintenanceCaller();
        }
    }

    function _requireRecoveryActive(bytes32 requestId) internal view {
        _requireRecoveryActiveNoExpiry(requestId);
        if (block.timestamp > _recoveryRequest.expiresAt) revert RecoveryExpired();
    }

    function _requireRecoveryActiveNoExpiry(bytes32 requestId) internal view {
        if (!_recoveryRequest.active) revert RecoveryNotActive();
        if (_recoveryRequest.requestId != requestId) revert RecoveryRequestIdMismatch();
    }

    function _requireRecoveryAuthorityRotationActive(bytes32 requestId) internal view {
        _requireRecoveryAuthorityRotationActiveNoExpiry(requestId);
        if (block.timestamp > _recoveryAuthorityRotationRequest.expiresAt) {
            revert RecoveryAuthorityRotationExpired();
        }
    }

    function _requireRecoveryAuthorityRotationActiveNoExpiry(bytes32 requestId) internal view {
        if (!_recoveryAuthorityRotationRequest.active) revert RecoveryAuthorityRotationNotActive();
        if (_recoveryAuthorityRotationRequest.requestId != requestId) {
            revert RecoveryAuthorityRotationRequestIdMismatch();
        }
    }

    function _rotateOwner(address newOwner) internal {
        if (newOwner == address(0) || newOwner == _owner) revert InvalidOwner();
        address previousOwner = _owner;
        _owner = newOwner;
        emit ExecutionOwnerRotated(previousOwner, newOwner, ownerCommitment);
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        if (userOp.callData.length < 4) {
            return SIG_VALIDATION_FAILED;
        }
        bytes4 selector = bytes4(userOp.callData[:4]);
        if (frozen && selector != this.cancelRecovery.selector && selector != this.completeRecovery.selector) {
            return SIG_VALIDATION_FAILED;
        }
        address expectedSigner = _owner;
        if (selector == this.requestRecovery.selector || selector == this.completeRecovery.selector) {
            expectedSigner = _recoveryAuthority;
        } else if (selector == this.requestRecoveryAuthorityRotation.selector) {
            expectedSigner = _expectedRotationProposer(userOp.callData);
        } else if (selector == this.cancelRecoveryAuthorityRotation.selector) {
            expectedSigner = _expectedRotationCanceller(userOp.callData);
        } else if (selector == this.completeRecoveryAuthorityRotation.selector) {
            expectedSigner = address(0);
        }
        if (expectedSigner == address(0)) {
            return SIG_VALIDATION_FAILED;
        }
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        if (expectedSigner != ECDSA.recover(hash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _expectedRotationProposer(bytes calldata callData) internal view returns (address) {
        if (callData.length < 68) return address(0);
        (, address expectedProposer) = abi.decode(callData[4:], (address, address));
        if (expectedProposer == _owner || expectedProposer == _recoveryAuthority) return expectedProposer;
        return address(0);
    }

    function _expectedRotationCanceller(bytes calldata callData) internal view returns (address) {
        if (callData.length < 68) return address(0);
        (, address expectedCanceller) = abi.decode(callData[4:], (bytes32, address));
        if (expectedCanceller == _owner || expectedCanceller == _recoveryAuthority) return expectedCanceller;
        return address(0);
    }
}
