// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {
    IPhilCoreV2StaticAuthorityVerifier,
    PhilCoreV2VerifierRequestV1
} from "./IPhilCoreV2StaticAuthorityVerifier.sol";
import {
    IPhilCoreV2MinimalAccountV2,
    PhilCoreV2AccountInitializationV1,
    PhilCoreV2AuthorizedIntentV1,
    PhilCoreV2IntentCoreHeaderV1
} from "./IPhilCoreV2MinimalAccountV2.sol";

interface IPhilCoreV2FactoryVerifierBinding {
    function verifierBinding()
        external
        view
        returns (address verifier, bytes32 verifierRuntimeCodeHash);
}

interface IPhilCoreV2ConfirmationTarget {
    function confirmPhilCoreAction(
        bytes32 actionId,
        bytes32 authorizationDigest
    ) external;
}

contract PhilCoreV2MinimalAccountV2 is IPhilCoreV2MinimalAccountV2 {
    using UserOperationLib for PackedUserOperation;

    uint8 private constant INTENT_SPECIFICATION_VERSION = 1;
    uint8 private constant VALIDATOR_VERIFIER_KIND = 1;
    uint64 private constant RECOVERY_DELAY_SECONDS = 172800;
    uint64 private constant RECOVERY_EXPIRY_SECONDS = 604800;
    bytes32 private constant ACCOUNT_VERSION_ID =
        0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f;
    bytes32 private constant SECURITY_MODEL_ID =
        keccak256("philcore-v2-typed-intent-local-proof-gated-v1");
    bytes4 private constant VERIFIER_SUCCESS_MAGIC = 0x15c57f54;
    bytes4 private constant VERIFIER_BINDING_SELECTOR = 0xa7d16353;

    uint8 private constant ACTION_CONFIRM = 1;
    uint8 private constant ACTION_NATIVE_TRANSFER = 2;
    uint8 private constant ACTION_DEPOSIT_WITHDRAWAL = 6;
    uint8 private constant ACTION_VALIDATOR_ROTATION = 7;
    uint8 private constant ACTION_RECOVERY_REQUEST = 8;
    uint8 private constant ACTION_RECOVERY_CANCEL = 9;
    uint8 private constant ACTION_CONFIG_ROTATION_REQUEST = 10;
    uint8 private constant ACTION_CONFIG_ROTATION_CANCEL = 11;

    bytes32 private constant PURPOSE_CONFIRM =
        keccak256("PHILCORE_V2_PURPOSE_CONFIRM_ACTION");
    bytes32 private constant PURPOSE_TRANSFER =
        keccak256("PHILCORE_V2_PURPOSE_TRANSFER_ASSET");
    bytes32 private constant PURPOSE_RELEASE =
        keccak256("PHILCORE_V2_PURPOSE_RELEASE_RESIDUAL");
    bytes32 private constant PURPOSE_MIGRATE =
        keccak256("PHILCORE_V2_PURPOSE_MIGRATE_ASSET");
    bytes32 private constant PURPOSE_WITHDRAW =
        keccak256("PHILCORE_V2_PURPOSE_WITHDRAW_DEPOSIT");
    bytes32 private constant PURPOSE_ROTATE_VALIDATOR =
        keccak256("PHILCORE_V2_PURPOSE_ROTATE_VALIDATOR");
    bytes32 private constant PURPOSE_REQUEST_RECOVERY =
        keccak256("PHILCORE_V2_PURPOSE_REQUEST_RECOVERY");
    bytes32 private constant PURPOSE_CANCEL_RECOVERY =
        keccak256("PHILCORE_V2_PURPOSE_CANCEL_RECOVERY");
    bytes32 private constant PURPOSE_ROTATE_RECOVERY_CONFIG =
        keccak256("PHILCORE_V2_PURPOSE_ROTATE_RECOVERY_CONFIG");
    bytes32 private constant PURPOSE_CANCEL_RECOVERY_CONFIG =
        keccak256("PHILCORE_V2_PURPOSE_CANCEL_RECOVERY_CONFIG_ROTATION");

    bytes32 private constant INTENT_CORE_HEADER_TYPEHASH = keccak256(
        "PhilCoreV2IntentCoreHeader(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)"
    );
    bytes32 private constant AUTHORIZED_INTENT_TYPEHASH = keccak256(
        "PhilCoreV2AuthorizedIntent(bytes32 intentCoreHash,bytes32 runtimeAuthorizationDigest)"
    );
    bytes32 private constant CONFIRM_TYPEHASH = keccak256(
        "PhilCoreV2ConfirmIntent(bytes32 coreHeaderHash,address confirmationTarget,bytes32 confirmationDigest)"
    );
    bytes32 private constant NATIVE_TRANSFER_TYPEHASH = keccak256(
        "PhilCoreV2NativeTransferIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)"
    );
    bytes32 private constant DEPOSIT_WITHDRAWAL_TYPEHASH = keccak256(
        "PhilCoreV2EntryPointDepositWithdrawalIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)"
    );
    bytes32 private constant VALIDATOR_ROTATION_TYPEHASH = keccak256(
        "PhilCoreV2ValidatorRotationIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch)"
    );
    bytes32 private constant RECOVERY_REQUEST_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryRequestIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch,bytes32 recoveryRequestSalt)"
    );
    bytes32 private constant RECOVERY_CANCEL_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryRequestId)"
    );
    bytes32 private constant CONFIG_ROTATION_REQUEST_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryConfigRotationRequestIntent(bytes32 coreHeaderHash,bytes32 proposedRecoveryConfigHash,bytes32 proposedPrimaryDeviceCommitment,bytes32 proposedHardwareSecurityKeyCommitment,bytes32 proposedRecoveryFactorCommitment,uint64 proposedRecoveryEpoch)"
    );
    bytes32 private constant CONFIG_ROTATION_CANCEL_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryConfigRotationCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryConfigRotationRequestId)"
    );
    bytes32 private constant VALIDATOR_COMMITMENT_TYPEHASH = keccak256(
        "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
    );
    bytes32 private constant RECOVERY_CONFIGURATION_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
    );
    bytes32 private constant IDENTITY_BINDING_TYPEHASH =
        0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8;
    bytes32 private constant OWNER_COMMITMENT_SCHEME_ID =
        0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e;

    IEntryPoint private immutable _entryPoint;
    uint256 private immutable _deploymentChainId;
    bytes32 private immutable _ownerCommitment;
    address private immutable _factoryBinding;
    address private immutable _confirmationTarget;

    // Slots 0-14 are frozen by O.37.9.
    address private _activeValidator;
    uint64 private _validatorEpoch;
    uint8 private _recoveryState;
    uint8 private _validatorVerifierKind;
    bool private _executionLock;
    bytes32 private _validatorKeyIdBinding;
    bytes32 private _primaryDeviceRecoveryCommitment;
    bytes32 private _hardwareSecurityKeyCommitment;
    bytes32 private _independentRecoveryFactorCommitment;
    uint64 private _recoveryEpoch;
    bytes32 private _pendingRecoveryRequestId;
    address private _pendingValidator;
    uint64 private _pendingValidatorEpoch;
    bytes32 private _pendingValidatorKeyIdBinding;
    uint64 private _pendingRecoverySourceValidatorEpoch;
    uint64 private _pendingRecoverySourceRecoveryEpoch;
    uint48 private _pendingRecoveryRequestedAt;
    bytes32 private _pendingConfigRequestId;
    bytes32 private _proposedPrimaryDeviceCommitment;
    bytes32 private _proposedHardwareSecurityKeyCommitment;
    bytes32 private _proposedRecoveryFactorCommitment;
    uint64 private _proposedRecoveryEpoch;
    uint64 private _pendingConfigSourceValidatorEpoch;
    uint64 private _pendingConfigSourceRecoveryEpoch;
    uint48 private _pendingConfigRequestedAt;

    event ActionExecuted(
        bytes32 indexed actionId,
        uint8 indexed actionType,
        address indexed target,
        uint256 value,
        bytes32 postStateHash
    );
    event AuthorityTransition(
        bytes32 indexed requestId,
        uint8 indexed actionType,
        uint64 validatorEpoch,
        uint64 recoveryEpoch,
        bytes32 postStateHash
    );

    error UnauthorizedEntryPoint();
    error InvalidInitialization(uint8 reason);
    error InvalidUserOperation(uint8 reason);
    error InvalidIntent(uint8 reason);
    error InvalidRecoveryState(uint8 reason);
    error InvalidExecution(uint8 reason);
    error VerifierBindingInvalid(uint8 reason);
    error ExternalCallFailed(uint8 reason);

    constructor(PhilCoreV2AccountInitializationV1 memory initialization) {
        if (
            initialization.deploymentChainId != block.chainid
                || address(initialization.entryPoint) == address(0)
        ) revert InvalidInitialization(1);
        if (
            initialization.factoryBinding == address(0)
                || msg.sender != initialization.factoryBinding
                || initialization.factoryBinding.code.length == 0
                || initialization.confirmationTarget == address(0)
                || initialization.ownerCommitment == bytes32(0)
                || initialization.initialValidator == address(0)
                || initialization.validatorKeyIdBinding == bytes32(0)
        ) revert InvalidInitialization(2);
        if (
            initialization.accountVersionId != ACCOUNT_VERSION_ID
                || initialization.securityModelId != SECURITY_MODEL_ID
                || initialization.validatorVerifierKind
                    != VALIDATOR_VERIFIER_KIND
                || initialization.validatorEpoch != 1
                || initialization.recoveryEpoch != 1
                || initialization.recoveryDelaySeconds
                    != RECOVERY_DELAY_SECONDS
                || initialization.recoveryExpirySeconds
                    != RECOVERY_EXPIRY_SECONDS
        ) revert InvalidInitialization(3);
        if (
            initialization.identityBindingCommitment
                != _identityBinding(initialization.ownerCommitment)
                || initialization.validatorCommitment
                    != _validatorCommitment(
                        initialization.initialValidator,
                        initialization.validatorKeyIdBinding
                    )
        ) revert InvalidInitialization(4);
        if (
            !_validRoleCommitments(
                initialization.primaryDeviceRecoveryCommitment,
                initialization.hardwareSecurityKeyCommitment,
                initialization.independentRecoveryFactorCommitment
            )
                || initialization.recoveryConfigurationHash
                    != _recoveryConfigurationHash(
                        initialization.primaryDeviceRecoveryCommitment,
                        initialization.hardwareSecurityKeyCommitment,
                        initialization.independentRecoveryFactorCommitment
                    )
        ) revert InvalidInitialization(5);

        _entryPoint = initialization.entryPoint;
        _deploymentChainId = initialization.deploymentChainId;
        _ownerCommitment = initialization.ownerCommitment;
        _factoryBinding = initialization.factoryBinding;
        _confirmationTarget = initialization.confirmationTarget;
        _activeValidator = initialization.initialValidator;
        _validatorEpoch = initialization.validatorEpoch;
        _validatorVerifierKind = initialization.validatorVerifierKind;
        _validatorKeyIdBinding = initialization.validatorKeyIdBinding;
        _primaryDeviceRecoveryCommitment =
            initialization.primaryDeviceRecoveryCommitment;
        _hardwareSecurityKeyCommitment =
            initialization.hardwareSecurityKeyCommitment;
        _independentRecoveryFactorCommitment =
            initialization.independentRecoveryFactorCommitment;
        _recoveryEpoch = initialization.recoveryEpoch;
    }

    receive() external payable {}

    fallback() external payable {
        revert InvalidExecution(1);
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        if (msg.sender != address(_entryPoint)) revert UnauthorizedEntryPoint();
        if (
            block.chainid != _deploymentChainId
                || userOp.sender != address(this) || userOpHash == bytes32(0)
        ) revert InvalidUserOperation(1);
        if (userOp.paymasterAndData.length != 0) {
            revert InvalidUserOperation(2);
        }
        if (
            userOp.initCode.length != 0
                && (
                    userOp.initCode.length < 20
                        || address(bytes20(userOp.initCode[:20]))
                            != _factoryBinding
                )
        ) revert InvalidUserOperation(3);

        (
            PhilCoreV2AuthorizedIntentV1 memory intent,
            PhilCoreV2VerifierRequestV1 memory request
        ) = _decodeAndBindUserOperation(userOp, userOpHash);
        _verifyAuthority(request, userOp.signature);

        if (missingAccountFunds != 0) {
            if (missingAccountFunds > intent.core.maxTotalFeeWei) {
                revert InvalidUserOperation(4);
            }
            bool paid;
            assembly ("memory-safe") {
                paid :=
                    call(not(0), caller(), missingAccountFunds, 0, 0, 0, 0)
            }
            if (!paid) revert InvalidUserOperation(4);
        }
        return _packValidationData(
            false,
            intent.core.validUntil,
            intent.core.validAfter
        );
    }

    function confirmIntent(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 confirmationDigest
    ) external {
        _requireEntryPoint();
        if (confirmationDigest == bytes32(0)) revert InvalidExecution(2);
        _enterExecution();
        try IPhilCoreV2ConfirmationTarget(_confirmationTarget)
            .confirmPhilCoreAction(intent.core.actionId, confirmationDigest)
        {} catch {
            revert ExternalCallFailed(2);
        }
        _executionLock = false;
        emit ActionExecuted(
            intent.core.actionId,
            ACTION_CONFIRM,
            _confirmationTarget,
            0,
            _stateHash()
        );
    }

    function transferNative(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address payable recipient,
        uint256 amountWei
    ) external {
        _requireEntryPoint();
        if (
            recipient == address(0) || recipient == address(this)
                || amountWei == 0 || amountWei > address(this).balance
        ) revert InvalidExecution(3);
        _enterExecution();
        (bool success,) = recipient.call{value: amountWei}("");
        if (!success) revert ExternalCallFailed(3);
        _executionLock = false;
        emit ActionExecuted(
            intent.core.actionId,
            ACTION_NATIVE_TRANSFER,
            recipient,
            amountWei,
            _stateHash()
        );
    }

    function withdrawEntryPointDeposit(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address payable recipient,
        uint256 amountWei
    ) external {
        _requireEntryPoint();
        if (
            recipient == address(0) || recipient == address(this)
                || amountWei == 0
        ) revert InvalidExecution(4);
        _enterExecution();
        try _entryPoint.withdrawTo(recipient, amountWei) {} catch {
            revert ExternalCallFailed(4);
        }
        _executionLock = false;
        emit ActionExecuted(
            intent.core.actionId,
            ACTION_DEPOSIT_WITHDRAWAL,
            recipient,
            amountWei,
            _stateHash()
        );
    }

    function rotateValidator(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address proposedValidator,
        bytes32 proposedValidatorKeyIdBinding,
        uint64 proposedValidatorEpoch
    ) external {
        _requireEntryPoint();
        if (_anyRecoveryPending()) revert InvalidRecoveryState(1);
        if (
            proposedValidator == address(0)
                || proposedValidator == _activeValidator
                || proposedValidatorKeyIdBinding == bytes32(0)
                || proposedValidatorEpoch != _validatorEpoch + 1
        ) revert InvalidExecution(5);
        _activeValidator = proposedValidator;
        _validatorKeyIdBinding = proposedValidatorKeyIdBinding;
        _validatorEpoch = proposedValidatorEpoch;
        emit AuthorityTransition(
            intent.core.actionId,
            ACTION_VALIDATOR_ROTATION,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function requestRecovery(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        address proposedValidator,
        bytes32 proposedValidatorKeyIdBinding,
        uint64 proposedValidatorEpoch,
        bytes32 recoveryRequestSalt
    ) external {
        _requireEntryPoint();
        if (_anyRecoveryPending()) revert InvalidRecoveryState(2);
        if (
            proposedValidator == address(0)
                || proposedValidator == _activeValidator
                || proposedValidatorKeyIdBinding == bytes32(0)
                || proposedValidatorEpoch != _validatorEpoch + 1
                || recoveryRequestSalt == bytes32(0)
        ) revert InvalidExecution(6);
        bytes32 requestId = _authorizedIntentHash(
            intent,
            keccak256(
                abi.encode(
                    RECOVERY_REQUEST_TYPEHASH,
                    _coreHeaderHash(intent.core),
                    proposedValidator,
                    proposedValidatorKeyIdBinding,
                    proposedValidatorEpoch,
                    recoveryRequestSalt
                )
            )
        );
        _pendingRecoveryRequestId = requestId;
        _pendingValidator = proposedValidator;
        _pendingValidatorEpoch = proposedValidatorEpoch;
        _pendingValidatorKeyIdBinding = proposedValidatorKeyIdBinding;
        _pendingRecoverySourceValidatorEpoch = _validatorEpoch;
        _pendingRecoverySourceRecoveryEpoch = _recoveryEpoch;
        _pendingRecoveryRequestedAt = uint48(block.timestamp);
        _recoveryState = 1;
        emit AuthorityTransition(
            requestId,
            ACTION_RECOVERY_REQUEST,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function cancelRecovery(
        PhilCoreV2AuthorizedIntentV1 calldata,
        bytes32 recoveryRequestId
    ) external {
        _requireEntryPoint();
        if (
            recoveryRequestId == bytes32(0)
                || recoveryRequestId != _pendingRecoveryRequestId
        ) revert InvalidRecoveryState(3);
        _clearPendingRecovery();
        _recoveryState = 3;
        emit AuthorityTransition(
            recoveryRequestId,
            ACTION_RECOVERY_CANCEL,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function settleRecovery(bytes32 recoveryRequestId) external {
        if (_executionLock) revert InvalidExecution(7);
        if (
            recoveryRequestId == bytes32(0)
                || recoveryRequestId != _pendingRecoveryRequestId
        ) revert InvalidRecoveryState(4);
        uint48 requestedAt = _pendingRecoveryRequestedAt;
        if (block.timestamp < uint256(requestedAt) + RECOVERY_DELAY_SECONDS) {
            revert InvalidRecoveryState(5);
        }
        if (
            block.timestamp
                >= uint256(requestedAt) + RECOVERY_EXPIRY_SECONDS
        ) {
            _clearPendingRecovery();
            _recoveryState = 0;
        } else {
            if (
                _validatorEpoch != _pendingRecoverySourceValidatorEpoch
                    || _recoveryEpoch
                        != _pendingRecoverySourceRecoveryEpoch
            ) revert InvalidRecoveryState(6);
            _activeValidator = _pendingValidator;
            _validatorKeyIdBinding = _pendingValidatorKeyIdBinding;
            _validatorEpoch = _pendingValidatorEpoch;
            unchecked {
                ++_recoveryEpoch;
            }
            _clearPendingRecovery();
            _recoveryState = 2;
        }
        emit AuthorityTransition(
            recoveryRequestId,
            ACTION_RECOVERY_REQUEST,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function requestRecoveryConfigRotation(
        PhilCoreV2AuthorizedIntentV1 calldata intent,
        bytes32 proposedPrimaryDeviceCommitment,
        bytes32 proposedHardwareSecurityKeyCommitment,
        bytes32 proposedRecoveryFactorCommitment,
        uint64 proposedRecoveryEpoch
    ) external {
        _requireEntryPoint();
        if (_anyRecoveryPending()) revert InvalidRecoveryState(7);
        bytes32 proposedHash = _validateProposedRecoveryConfiguration(
            proposedPrimaryDeviceCommitment,
            proposedHardwareSecurityKeyCommitment,
            proposedRecoveryFactorCommitment,
            proposedRecoveryEpoch
        );
        bytes32 requestId = _authorizedIntentHash(
            intent,
            keccak256(
                abi.encode(
                    CONFIG_ROTATION_REQUEST_TYPEHASH,
                    _coreHeaderHash(intent.core),
                    proposedHash,
                    proposedPrimaryDeviceCommitment,
                    proposedHardwareSecurityKeyCommitment,
                    proposedRecoveryFactorCommitment,
                    proposedRecoveryEpoch
                )
            )
        );
        _pendingConfigRequestId = requestId;
        _proposedPrimaryDeviceCommitment =
            proposedPrimaryDeviceCommitment;
        _proposedHardwareSecurityKeyCommitment =
            proposedHardwareSecurityKeyCommitment;
        _proposedRecoveryFactorCommitment =
            proposedRecoveryFactorCommitment;
        _proposedRecoveryEpoch = proposedRecoveryEpoch;
        _pendingConfigSourceValidatorEpoch = _validatorEpoch;
        _pendingConfigSourceRecoveryEpoch = _recoveryEpoch;
        _pendingConfigRequestedAt = uint48(block.timestamp);
        emit AuthorityTransition(
            requestId,
            ACTION_CONFIG_ROTATION_REQUEST,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function cancelRecoveryConfigRotation(
        PhilCoreV2AuthorizedIntentV1 calldata,
        bytes32 rotationRequestId
    ) external {
        _requireEntryPoint();
        if (
            rotationRequestId == bytes32(0)
                || rotationRequestId != _pendingConfigRequestId
        ) revert InvalidRecoveryState(8);
        _clearPendingConfig();
        emit AuthorityTransition(
            rotationRequestId,
            ACTION_CONFIG_ROTATION_CANCEL,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function settleRecoveryConfigRotation(bytes32 rotationRequestId) external {
        if (_executionLock) revert InvalidExecution(7);
        if (
            rotationRequestId == bytes32(0)
                || rotationRequestId != _pendingConfigRequestId
        ) revert InvalidRecoveryState(9);
        uint48 requestedAt = _pendingConfigRequestedAt;
        if (block.timestamp < uint256(requestedAt) + RECOVERY_DELAY_SECONDS) {
            revert InvalidRecoveryState(10);
        }
        if (
            block.timestamp
                >= uint256(requestedAt) + RECOVERY_EXPIRY_SECONDS
        ) {
            _clearPendingConfig();
        } else {
            if (
                _validatorEpoch != _pendingConfigSourceValidatorEpoch
                    || _recoveryEpoch != _pendingConfigSourceRecoveryEpoch
            ) revert InvalidRecoveryState(11);
            _primaryDeviceRecoveryCommitment =
                _proposedPrimaryDeviceCommitment;
            _hardwareSecurityKeyCommitment =
                _proposedHardwareSecurityKeyCommitment;
            _independentRecoveryFactorCommitment =
                _proposedRecoveryFactorCommitment;
            _recoveryEpoch = _proposedRecoveryEpoch;
            _clearPendingConfig();
        }
        emit AuthorityTransition(
            rotationRequestId,
            ACTION_CONFIG_ROTATION_REQUEST,
            _validatorEpoch,
            _recoveryEpoch,
            _stateHash()
        );
    }

    function accountConfiguration()
        external
        view
        returns (
            IEntryPoint entryPoint,
            uint256 deploymentChainId,
            bytes32 ownerCommitment,
            bytes32 identityBindingCommitment,
            address factoryBinding,
            bytes32 accountVersionId,
            bytes32 securityModelId,
            address confirmationTarget
        )
    {
        return (
            _entryPoint,
            _deploymentChainId,
            _ownerCommitment,
            _identityBinding(_ownerCommitment),
            _factoryBinding,
            ACCOUNT_VERSION_ID,
            SECURITY_MODEL_ID,
            _confirmationTarget
        );
    }

    function accountSecurityState()
        external
        view
        returns (
            address activeValidator,
            bytes32 validatorCommitment,
            bytes32 validatorKeyIdBinding,
            uint64 validatorEpoch,
            uint8 validatorVerifierKind,
            uint8 recoveryState,
            uint64 recoveryEpoch,
            bytes32 recoveryConfigurationHash,
            bytes32 primaryDeviceCommitment,
            bytes32 hardwareSecurityKeyCommitment,
            bytes32 recoveryFactorCommitment,
            bool executionLocked
        )
    {
        return (
            _activeValidator,
            _validatorCommitment(_activeValidator, _validatorKeyIdBinding),
            _validatorKeyIdBinding,
            _validatorEpoch,
            _validatorVerifierKind,
            _recoveryState,
            _recoveryEpoch,
            _recoveryConfigurationHash(
                _primaryDeviceRecoveryCommitment,
                _hardwareSecurityKeyCommitment,
                _independentRecoveryFactorCommitment
            ),
            _primaryDeviceRecoveryCommitment,
            _hardwareSecurityKeyCommitment,
            _independentRecoveryFactorCommitment,
            _executionLock
        );
    }

    function pendingRecovery()
        external
        view
        returns (
            bytes32 requestId,
            address proposedValidator,
            bytes32 proposedValidatorKeyIdBinding,
            bytes32 proposedValidatorCommitment,
            uint64 proposedValidatorEpoch,
            uint64 sourceValidatorEpoch,
            uint64 sourceRecoveryEpoch,
            uint48 requestedAt,
            uint48 executableAfter,
            uint48 expiresAt
        )
    {
        uint48 requested = _pendingRecoveryRequestedAt;
        return (
            _pendingRecoveryRequestId,
            _pendingValidator,
            _pendingValidatorKeyIdBinding,
            _pendingRecoveryRequestId == bytes32(0)
                ? bytes32(0)
                : _validatorCommitment(
                    _pendingValidator,
                    _pendingValidatorKeyIdBinding
                ),
            _pendingValidatorEpoch,
            _pendingRecoverySourceValidatorEpoch,
            _pendingRecoverySourceRecoveryEpoch,
            requested,
            requested == 0
                ? 0
                : uint48(uint256(requested) + RECOVERY_DELAY_SECONDS),
            requested == 0
                ? 0
                : uint48(uint256(requested) + RECOVERY_EXPIRY_SECONDS)
        );
    }

    function pendingRecoveryConfigRotation()
        external
        view
        returns (
            bytes32 requestId,
            bytes32 proposedRecoveryConfigHash,
            bytes32 proposedPrimaryDeviceCommitment,
            bytes32 proposedHardwareSecurityKeyCommitment,
            bytes32 proposedRecoveryFactorCommitment,
            uint64 proposedRecoveryEpoch,
            uint64 sourceValidatorEpoch,
            uint64 sourceRecoveryEpoch,
            uint48 requestedAt,
            uint48 executableAfter,
            uint48 expiresAt
        )
    {
        uint48 requested = _pendingConfigRequestedAt;
        return (
            _pendingConfigRequestId,
            _pendingConfigRequestId == bytes32(0)
                ? bytes32(0)
                : _recoveryConfigurationHash(
                    _proposedPrimaryDeviceCommitment,
                    _proposedHardwareSecurityKeyCommitment,
                    _proposedRecoveryFactorCommitment
                ),
            _proposedPrimaryDeviceCommitment,
            _proposedHardwareSecurityKeyCommitment,
            _proposedRecoveryFactorCommitment,
            _proposedRecoveryEpoch,
            _pendingConfigSourceValidatorEpoch,
            _pendingConfigSourceRecoveryEpoch,
            requested,
            requested == 0
                ? 0
                : uint48(uint256(requested) + RECOVERY_DELAY_SECONDS),
            requested == 0
                ? 0
                : uint48(uint256(requested) + RECOVERY_EXPIRY_SECONDS)
        );
    }

    function _decodeAndBindUserOperation(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        private
        view
        returns (
            PhilCoreV2AuthorizedIntentV1 memory intent,
            PhilCoreV2VerifierRequestV1 memory request
        )
    {
        if (userOp.callData.length < 612) revert InvalidUserOperation(5);
        bytes4 selector = bytes4(userOp.callData[:4]);
        intent = abi.decode(
            userOp.callData[4:612],
            (PhilCoreV2AuthorizedIntentV1)
        );
        bytes32 coreHeaderHash = _coreHeaderHash(intent.core);
        bytes32 intentCoreHash = bytes32(0);
        bytes32 requestId = bytes32(0);
        bytes32 proposedValidatorCommitment = bytes32(0);
        bytes32 proposedRecoveryConfigHash = bytes32(0);
        uint64 proposedRecoveryEpoch = 0;
        uint8 decodedActionType = 0;

        if (selector == this.confirmIntent.selector) {
            decodedActionType = ACTION_CONFIRM;
            _requireCallDataLength(userOp.callData, 644);
            bytes32 digest = _word(userOp.callData, 19);
            if (digest == bytes32(0)) revert InvalidIntent(1);
            intentCoreHash = keccak256(
                abi.encode(
                    CONFIRM_TYPEHASH,
                    coreHeaderHash,
                    _confirmationTarget,
                    digest
                )
            );
        } else if (
            selector == this.transferNative.selector
                || selector == this.withdrawEntryPointDeposit.selector
        ) {
            decodedActionType = selector == this.transferNative.selector
                ? ACTION_NATIVE_TRANSFER
                : ACTION_DEPOSIT_WITHDRAWAL;
            _requireCallDataLength(userOp.callData, 676);
            address recipient = _addressWord(userOp.callData, 19);
            uint256 amount = uint256(_word(userOp.callData, 20));
            if (
                recipient == address(0) || recipient == address(this)
                    || amount == 0
            ) revert InvalidIntent(2);
            intentCoreHash = keccak256(
                abi.encode(
                    selector == this.transferNative.selector
                        ? NATIVE_TRANSFER_TYPEHASH
                        : DEPOSIT_WITHDRAWAL_TYPEHASH,
                    coreHeaderHash,
                    recipient,
                    amount
                )
            );
        } else if (selector == this.rotateValidator.selector) {
            decodedActionType = ACTION_VALIDATOR_ROTATION;
            _requireCallDataLength(userOp.callData, 708);
            address proposed = _addressWord(userOp.callData, 19);
            bytes32 proposedKey = _word(userOp.callData, 20);
            uint64 proposedEpoch = _uint64Word(userOp.callData, 21);
            proposedValidatorCommitment =
                _validateProposedValidator(proposed, proposedKey, proposedEpoch);
            intentCoreHash = keccak256(
                abi.encode(
                    VALIDATOR_ROTATION_TYPEHASH,
                    coreHeaderHash,
                    proposed,
                    proposedKey,
                    proposedEpoch
                )
            );
        } else if (selector == this.requestRecovery.selector) {
            decodedActionType = ACTION_RECOVERY_REQUEST;
            _requireCallDataLength(userOp.callData, 740);
            address proposed = _addressWord(userOp.callData, 19);
            bytes32 proposedKey = _word(userOp.callData, 20);
            uint64 proposedEpoch = _uint64Word(userOp.callData, 21);
            bytes32 requestSalt = _word(userOp.callData, 22);
            if (requestSalt == bytes32(0)) revert InvalidIntent(3);
            proposedValidatorCommitment =
                _validateProposedValidator(proposed, proposedKey, proposedEpoch);
            intentCoreHash = keccak256(
                abi.encode(
                    RECOVERY_REQUEST_TYPEHASH,
                    coreHeaderHash,
                    proposed,
                    proposedKey,
                    proposedEpoch,
                    requestSalt
                )
            );
            requestId = _authorizedIntentHash(intent, intentCoreHash);
            proposedRecoveryEpoch = _recoveryEpoch + 1;
        } else if (selector == this.cancelRecovery.selector) {
            decodedActionType = ACTION_RECOVERY_CANCEL;
            _requireCallDataLength(userOp.callData, 644);
            requestId = _word(userOp.callData, 19);
            if (
                requestId == bytes32(0)
                    || requestId != _pendingRecoveryRequestId
            ) revert InvalidRecoveryState(12);
            proposedValidatorCommitment = _validatorCommitment(
                _pendingValidator,
                _pendingValidatorKeyIdBinding
            );
            proposedRecoveryEpoch = _recoveryEpoch + 1;
            intentCoreHash = keccak256(
                abi.encode(RECOVERY_CANCEL_TYPEHASH, coreHeaderHash, requestId)
            );
        } else if (selector == this.requestRecoveryConfigRotation.selector) {
            decodedActionType = ACTION_CONFIG_ROTATION_REQUEST;
            _requireCallDataLength(userOp.callData, 740);
            bytes32 primary = _word(userOp.callData, 19);
            bytes32 hardware = _word(userOp.callData, 20);
            bytes32 independent = _word(userOp.callData, 21);
            proposedRecoveryEpoch = _uint64Word(userOp.callData, 22);
            proposedRecoveryConfigHash = _validateProposedRecoveryConfiguration(
                primary,
                hardware,
                independent,
                proposedRecoveryEpoch
            );
            intentCoreHash = keccak256(
                abi.encode(
                    CONFIG_ROTATION_REQUEST_TYPEHASH,
                    coreHeaderHash,
                    proposedRecoveryConfigHash,
                    primary,
                    hardware,
                    independent,
                    proposedRecoveryEpoch
                )
            );
            requestId = _authorizedIntentHash(intent, intentCoreHash);
        } else if (
            selector == this.cancelRecoveryConfigRotation.selector
        ) {
            decodedActionType = ACTION_CONFIG_ROTATION_CANCEL;
            _requireCallDataLength(userOp.callData, 644);
            requestId = _word(userOp.callData, 19);
            if (
                requestId == bytes32(0)
                    || requestId != _pendingConfigRequestId
            ) revert InvalidRecoveryState(13);
            proposedRecoveryConfigHash = _recoveryConfigurationHash(
                _proposedPrimaryDeviceCommitment,
                _proposedHardwareSecurityKeyCommitment,
                _proposedRecoveryFactorCommitment
            );
            proposedRecoveryEpoch = _proposedRecoveryEpoch;
            intentCoreHash = keccak256(
                abi.encode(
                    CONFIG_ROTATION_CANCEL_TYPEHASH,
                    coreHeaderHash,
                    requestId
                )
            );
        } else {
            revert InvalidUserOperation(6);
        }
        if (intent.core.actionType != decodedActionType) {
            revert InvalidIntent(11);
        }

        bytes32 authorizedIntentHash =
            _authorizedIntentHash(intent, intentCoreHash);
        _validateHeaderAndOperation(intent.core, userOp, intentCoreHash);
        _validateRecoveryState(intent.core.actionType);

        request = PhilCoreV2VerifierRequestV1({
            actionType: intent.core.actionType,
            account: address(this),
            chainId: _deploymentChainId,
            entryPoint: address(_entryPoint),
            accountVersionId: ACCOUNT_VERSION_ID,
            securityModelId: SECURITY_MODEL_ID,
            authorizedIntentHash: authorizedIntentHash,
            userOpHash: userOpHash,
            validator: _activeValidator,
            validatorKeyIdBinding: _validatorKeyIdBinding,
            validatorEpoch: _validatorEpoch,
            recoveryEpoch: _recoveryEpoch,
            recoveryConfigHash: _recoveryConfigurationHash(
                _primaryDeviceRecoveryCommitment,
                _hardwareSecurityKeyCommitment,
                _independentRecoveryFactorCommitment
            ),
            requestId: requestId,
            validAfter: intent.core.validAfter,
            validUntil: intent.core.validUntil,
            proposedValidatorCommitment: proposedValidatorCommitment,
            proposedRecoveryConfigHash: proposedRecoveryConfigHash,
            proposedRecoveryEpoch: proposedRecoveryEpoch,
            primaryDeviceCommitment: _primaryDeviceRecoveryCommitment,
            hardwareSecurityKeyCommitment: _hardwareSecurityKeyCommitment,
            recoveryFactorCommitment: _independentRecoveryFactorCommitment
        });
    }

    function _verifyAuthority(
        PhilCoreV2VerifierRequestV1 memory request,
        bytes calldata authorityEnvelope
    ) private view {
        bool bindingSuccess;
        uint256 bindingResultLength;
        uint256 verifierWord;
        bytes32 verifierCodeHash;
        address factoryBinding = _factoryBinding;
        uint32 bindingSelector = uint32(VERIFIER_BINDING_SELECTOR);
        assembly ("memory-safe") {
            let pointer := mload(0x40)
            mstore(pointer, shl(224, bindingSelector))
            bindingSuccess :=
                staticcall(not(0), factoryBinding, pointer, 4, pointer, 64)
            bindingResultLength := returndatasize()
            verifierWord := mload(pointer)
            verifierCodeHash := mload(add(pointer, 32))
            mstore(0x40, add(pointer, 96))
        }
        if (!bindingSuccess || bindingResultLength != 64) {
            revert VerifierBindingInvalid(1);
        }
        if (
            verifierWord > type(uint160).max || verifierWord == 0
                || verifierCodeHash == bytes32(0)
        ) revert VerifierBindingInvalid(2);
        address verifier = address(uint160(verifierWord));
        if (verifier.codehash != verifierCodeHash) {
            revert VerifierBindingInvalid(3);
        }
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeCall(
                IPhilCoreV2StaticAuthorityVerifier.verifyAuthority,
                (request, authorityEnvelope)
            )
        );
        if (
            !success || result.length != 32
                || bytes32(result) != bytes32(VERIFIER_SUCCESS_MAGIC)
        ) revert VerifierBindingInvalid(4);
    }

    function _validateHeaderAndOperation(
        PhilCoreV2IntentCoreHeaderV1 memory header,
        PackedUserOperation calldata userOp,
        bytes32 intentCoreHash
    ) private view {
        if (
            header.specificationVersion != INTENT_SPECIFICATION_VERSION
                || header.securityModelId != SECURITY_MODEL_ID
                || header.actionId == bytes32(0)
                || header.purpose == bytes32(0)
                || header.ownerCommitment != _ownerCommitment
                || header.chainId != _deploymentChainId
                || header.entryPoint != address(_entryPoint)
                || header.account != address(this)
                || header.validatorEpoch != _validatorEpoch
                || header.recoveryEpoch != _recoveryEpoch
                || header.applicationContextHash == bytes32(0)
                || header.fundLifecycleDigest == bytes32(0)
                || header.maxTotalFeeWei == 0
                || header.validUntil <= header.validAfter
                || intentCoreHash == bytes32(0)
        ) revert InvalidIntent(4);
        uint48 maximumLifetime =
            header.actionType >= ACTION_RECOVERY_REQUEST ? 3600 : 600;
        if (header.validUntil - header.validAfter > maximumLifetime) {
            revert InvalidIntent(5);
        }
        uint192 nonceKey = uint192(userOp.nonce >> 64);
        uint64 nonceSequence = uint64(userOp.nonce);
        if (
            header.nonceKey != nonceKey
                || header.nonceSequence != nonceSequence
                || nonceKey != _expectedNonceLane(header.actionType)
        ) revert InvalidUserOperation(7);
        if (!_purposeAllowed(header.actionType, header.purpose)) {
            revert InvalidIntent(6);
        }
        (uint256 verificationGasLimit, uint256 callGasLimit) =
            UserOperationLib.unpackUints(userOp.accountGasLimits);
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) =
            UserOperationLib.unpackUints(userOp.gasFees);
        if (maxPriorityFeePerGas > maxFeePerGas) {
            revert InvalidUserOperation(8);
        }
        uint256 maximumFee =
            (verificationGasLimit + callGasLimit + userOp.preVerificationGas)
                * maxFeePerGas;
        if (maximumFee > header.maxTotalFeeWei) {
            revert InvalidUserOperation(8);
        }
    }

    function _validateRecoveryState(uint8 actionType) private view {
        if (_pendingRecoveryRequestId != bytes32(0)) {
            if (actionType != ACTION_RECOVERY_CANCEL) {
                revert InvalidRecoveryState(14);
            }
        } else if (_pendingConfigRequestId != bytes32(0)) {
            if (
                actionType == ACTION_VALIDATOR_ROTATION
                    || actionType == ACTION_RECOVERY_REQUEST
                    || actionType == ACTION_CONFIG_ROTATION_REQUEST
                    || actionType == ACTION_RECOVERY_CANCEL
            ) revert InvalidRecoveryState(15);
        } else if (
            actionType == ACTION_RECOVERY_CANCEL
                || actionType == ACTION_CONFIG_ROTATION_CANCEL
        ) {
            revert InvalidRecoveryState(16);
        }
    }

    function _validateProposedValidator(
        address proposed,
        bytes32 proposedKey,
        uint64 proposedEpoch
    ) private view returns (bytes32) {
        if (
            proposed == address(0) || proposed == _activeValidator
                || proposedKey == bytes32(0)
                || proposedEpoch != _validatorEpoch + 1
        ) revert InvalidIntent(7);
        return _validatorCommitment(proposed, proposedKey);
    }

    function _validateProposedRecoveryConfiguration(
        bytes32 primary,
        bytes32 hardware,
        bytes32 independent,
        uint64 proposedEpoch
    ) private view returns (bytes32 proposedHash) {
        if (
            !_validRoleCommitments(primary, hardware, independent)
                || proposedEpoch != _recoveryEpoch + 1
        ) revert InvalidIntent(8);
        uint8 changed = 0;
        if (primary != _primaryDeviceRecoveryCommitment) ++changed;
        if (hardware != _hardwareSecurityKeyCommitment) ++changed;
        if (independent != _independentRecoveryFactorCommitment) ++changed;
        if (changed != 1) revert InvalidIntent(9);
        return _recoveryConfigurationHash(primary, hardware, independent);
    }

    function _coreHeaderHash(
        PhilCoreV2IntentCoreHeaderV1 memory header
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                INTENT_CORE_HEADER_TYPEHASH,
                header.specificationVersion,
                header.securityModelId,
                header.actionType,
                header.actionId,
                header.purpose,
                header.ownerCommitment,
                header.chainId,
                header.entryPoint,
                header.account,
                header.nonceKey,
                header.nonceSequence,
                header.validatorEpoch,
                header.recoveryEpoch,
                header.applicationContextHash,
                header.fundLifecycleDigest,
                header.maxTotalFeeWei,
                header.validAfter,
                header.validUntil
            )
        );
    }

    function _authorizedIntentHash(
        PhilCoreV2AuthorizedIntentV1 memory intent,
        bytes32 intentCoreHash
    ) private pure returns (bytes32) {
        if (intent.runtimeAuthorizationDigest == bytes32(0)) {
            revert InvalidIntent(10);
        }
        return keccak256(
            abi.encode(
                AUTHORIZED_INTENT_TYPEHASH,
                intentCoreHash,
                intent.runtimeAuthorizationDigest
            )
        );
    }

    function _validatorCommitment(
        address validator,
        bytes32 keyBinding
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VALIDATOR_COMMITMENT_TYPEHASH,
                VALIDATOR_VERIFIER_KIND,
                validator,
                keyBinding
            )
        );
    }

    function _recoveryConfigurationHash(
        bytes32 primary,
        bytes32 hardware,
        bytes32 independent
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                RECOVERY_CONFIGURATION_TYPEHASH,
                uint8(3),
                uint8(2),
                primary,
                hardware,
                independent
            )
        );
    }

    function _identityBinding(
        bytes32 owner
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                IDENTITY_BINDING_TYPEHASH,
                uint8(1),
                owner,
                OWNER_COMMITMENT_SCHEME_ID
            )
        );
    }

    function _validRoleCommitments(
        bytes32 primary,
        bytes32 hardware,
        bytes32 independent
    ) private pure returns (bool) {
        return primary != bytes32(0) && hardware != bytes32(0)
            && independent != bytes32(0) && primary != hardware
            && primary != independent && hardware != independent;
    }

    function _purposeAllowed(
        uint8 actionType,
        bytes32 purpose
    ) private pure returns (bool) {
        if (actionType == ACTION_CONFIRM) return purpose == PURPOSE_CONFIRM;
        if (actionType == ACTION_NATIVE_TRANSFER) {
            return purpose == PURPOSE_TRANSFER || purpose == PURPOSE_RELEASE
                || purpose == PURPOSE_MIGRATE;
        }
        if (actionType == ACTION_DEPOSIT_WITHDRAWAL) {
            return purpose == PURPOSE_WITHDRAW || purpose == PURPOSE_RELEASE
                || purpose == PURPOSE_MIGRATE;
        }
        if (actionType == ACTION_VALIDATOR_ROTATION) {
            return purpose == PURPOSE_ROTATE_VALIDATOR;
        }
        if (actionType == ACTION_RECOVERY_REQUEST) {
            return purpose == PURPOSE_REQUEST_RECOVERY;
        }
        if (actionType == ACTION_RECOVERY_CANCEL) {
            return purpose == PURPOSE_CANCEL_RECOVERY;
        }
        if (actionType == ACTION_CONFIG_ROTATION_REQUEST) {
            return purpose == PURPOSE_ROTATE_RECOVERY_CONFIG;
        }
        if (actionType == ACTION_CONFIG_ROTATION_CANCEL) {
            return purpose == PURPOSE_CANCEL_RECOVERY_CONFIG;
        }
        return false;
    }

    function _expectedNonceLane(
        uint8 actionType
    ) private pure returns (uint192) {
        if (
            actionType == ACTION_CONFIRM
                || actionType == ACTION_NATIVE_TRANSFER
                || actionType == ACTION_DEPOSIT_WITHDRAWAL
        ) return 0;
        if (actionType == ACTION_VALIDATOR_ROTATION) return 1;
        if (
            actionType == ACTION_RECOVERY_REQUEST
                || actionType == ACTION_RECOVERY_CANCEL
                || actionType == ACTION_CONFIG_ROTATION_REQUEST
                || actionType == ACTION_CONFIG_ROTATION_CANCEL
        ) return 2;
        revert InvalidUserOperation(9);
    }

    function _stateHash() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                _activeValidator,
                _validatorKeyIdBinding,
                _validatorEpoch,
                _recoveryEpoch,
                _pendingRecoveryRequestId,
                _pendingConfigRequestId
            )
        );
    }

    function _requireEntryPoint() private view {
        if (msg.sender != address(_entryPoint)) revert UnauthorizedEntryPoint();
        if (_executionLock) revert InvalidExecution(7);
    }

    function _enterExecution() private {
        _executionLock = true;
    }

    function _anyRecoveryPending() private view returns (bool) {
        return _pendingRecoveryRequestId != bytes32(0)
            || _pendingConfigRequestId != bytes32(0);
    }

    function _clearPendingRecovery() private {
        _pendingRecoveryRequestId = bytes32(0);
        _pendingValidator = address(0);
        _pendingValidatorEpoch = 0;
        _pendingValidatorKeyIdBinding = bytes32(0);
        _pendingRecoverySourceValidatorEpoch = 0;
        _pendingRecoverySourceRecoveryEpoch = 0;
        _pendingRecoveryRequestedAt = 0;
    }

    function _clearPendingConfig() private {
        _pendingConfigRequestId = bytes32(0);
        _proposedPrimaryDeviceCommitment = bytes32(0);
        _proposedHardwareSecurityKeyCommitment = bytes32(0);
        _proposedRecoveryFactorCommitment = bytes32(0);
        _proposedRecoveryEpoch = 0;
        _pendingConfigSourceValidatorEpoch = 0;
        _pendingConfigSourceRecoveryEpoch = 0;
        _pendingConfigRequestedAt = 0;
    }

    function _requireCallDataLength(
        bytes calldata callData,
        uint256 expected
    ) private pure {
        if (callData.length != expected) revert InvalidUserOperation(10);
    }

    function _word(
        bytes calldata callData,
        uint256 index
    ) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := calldataload(add(add(callData.offset, 4), mul(index, 32)))
        }
    }

    function _addressWord(
        bytes calldata callData,
        uint256 index
    ) private pure returns (address value) {
        bytes32 encoded = _word(callData, index);
        if (uint256(encoded) > type(uint160).max) {
            revert InvalidUserOperation(11);
        }
        value = address(uint160(uint256(encoded)));
    }

    function _uint64Word(
        bytes calldata callData,
        uint256 index
    ) private pure returns (uint64 value) {
        bytes32 encoded = _word(callData, index);
        if (uint256(encoded) > type(uint64).max) {
            revert InvalidUserOperation(12);
        }
        value = uint64(uint256(encoded));
    }
}
