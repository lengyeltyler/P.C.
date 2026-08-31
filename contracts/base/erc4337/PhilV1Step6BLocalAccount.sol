// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Local-only Step 6B reference account proving that a Step 6A binding can be enforced.
/// @dev This is not deployed, audited, upgradeable, recovery-capable, or production-authorized.
contract PhilV1Step6BLocalAccount is IAccount {
    using UserOperationLib for PackedUserOperation;

    bytes32 public constant AUTHORIZATION_ENVELOPE_V1 = keccak256("PHIL_AUTHORIZATION_ENVELOPE_V1");
    bytes32 public constant DEVICE_APPROVAL_V1 = keccak256("PHIL_DEVICE_APPROVAL_V1");
    bytes32 public constant EVM_SINGLE_CALL_V1 = keccak256("PHIL_EVM_SINGLE_CALL_V1");
    bytes32 public constant EVM_ACCOUNT_BINDING_V1 = keccak256("PHIL_EVM_ACCOUNT_BINDING_V1");
    bytes32 public constant EVM_NONCE_DOMAIN_V1 = keccak256("PHIL_EVM_NONCE_DOMAIN_V1");
    bytes32 public constant EVM_INTENT_V1 = keccak256("PHIL_EVM_INTENT_V1");
    bytes32 public constant EVM_ADAPTER_AUTHORIZATION_V1 = keccak256("PHIL_EVM_ADAPTER_AUTHORIZATION_V1");
    bytes32 public constant STEP6B_CAPABILITY_BINDING_V1 = keccak256("PHIL_STEP6B_CAPABILITY_BINDING_V1");

    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;
    address public constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    bytes32 public constant BASE_MAINNET_NETWORK_ID_HASH = keccak256("eip155:8453");
    bytes32 public constant BASE_MAINNET_ADAPTER_ID =
        keccak256("phil-adapter-base-mainnet-erc4337-local-reference-v1");
    bytes32 public constant ERC4337_ACCOUNT_MODEL_ID =
        keccak256("phil-evm-erc4337-narrow-account-binding-v1");
    bytes32 public constant P256_SHA256_SIGNATURE_SUITE_ID =
        keccak256("phil-signature-p256-sha256-v1");

    struct PhilEvmSingleCallV1 {
        address target;
        bytes32 targetCalldataHash;
        uint256 valueWei;
        uint192 nonceKey;
        uint64 nonceSequence;
        uint128 callGasLimit;
        uint128 verificationGasLimit;
        uint256 preVerificationGas;
        uint128 maxFeePerGas;
        uint128 maxPriorityFeePerGas;
        uint48 validAfter;
        uint48 validUntil;
    }

    struct PhilAuthorizationEnvelopeV1 {
        uint8 operationClass;
        bytes32 scopedOwnerCommitment;
        bytes32 scopeId;
        bytes32 scopeInstance;
        uint64 scopeEpoch;
        bytes32 principalIdHash;
        bytes32 capabilityId;
        uint64 capabilityEpoch;
        bytes32 networkIdHash;
        bytes32 accountBindingHash;
        bytes32 adapterId;
        bytes32 actionTypeHash;
        bytes32 parametersHash;
        bytes32 intentDigest;
        bytes32 policyHash;
        bytes32 nonceDomain;
        uint256 nonce;
        bytes32 rootProofNullifier;
        uint64 validAfter;
        uint64 validUntil;
        uint256 valueLimit;
        uint256 feeLimit;
        uint64 deviceEpoch;
        uint64 recoveryEpoch;
        uint64 validatorEpoch;
        bytes32 deviceSignatureSuiteId;
        bytes32 proofDescriptorHash;
        bytes32 humanPresentationHash;
    }

    struct PhilDeviceApprovalV1 {
        bytes32 deviceId;
        bytes32 deviceKeyId;
        uint64 deviceEpoch;
        bytes32 approvalNonce;
        uint64 approvedAt;
        uint64 approvalExpiresAt;
    }

    bytes32 public immutable trustedManifestHash;
    bytes32 public immutable enrolledDeviceId;
    bytes32 public immutable enrolledDeviceKeyId;
    bytes32 public immutable enrolledScopedOwnerCommitment;
    bytes32 public immutable enforcedPolicyHash;
    bytes32 public immutable trustedCapabilityBindingHash;
    bytes32 public immutable devicePublicKeyX;
    bytes32 public immutable devicePublicKeyY;
    address public immutable approvedTarget;
    uint256 public immutable policyMaxValueWei;
    uint256 public immutable policyMaxFeeWei;
    uint64 public immutable enrolledDeviceEpoch;

    mapping(uint192 nonceKey => uint64 nextSequence) public nextNonceSequence;
    mapping(bytes32 authorizationHash => bool consumed) public consumedAuthorization;

    event PhilV1Step6BAuthorizationConsumed(
        bytes32 indexed authorizationHash,
        bytes32 indexed authorizationEnvelopeDigest,
        bytes32 indexed deviceApprovalDigest,
        uint256 userOpNonce,
        address target
    );

    error PhilStep6BInvalidConstructor();
    error PhilStep6BOnlyEntryPoint();
    error PhilStep6BMalformedCallData();
    error PhilStep6BUserOperationHashMismatch();
    error PhilStep6BUserOperationMismatch();
    error PhilStep6BBindingMismatch();
    error PhilStep6BPolicyMismatch();
    error PhilStep6BValidityMismatch();
    error PhilStep6BFeeOverflow();
    error PhilStep6BNonceMismatch();
    error PhilStep6BAuthorizationAlreadyConsumed();
    error PhilStep6BExecutionOutsideValidity();
    error PhilStep6BExecutionFailed(bytes reason);

    constructor(
        bytes32 trustedManifestHash_,
        bytes32 enrolledDeviceId_,
        bytes32 enrolledDeviceKeyId_,
        uint64 enrolledDeviceEpoch_,
        bytes32 enrolledScopedOwnerCommitment_,
        bytes32 enforcedPolicyHash_,
        bytes32 trustedCapabilityBindingHash_,
        address approvedTarget_,
        uint256 policyMaxValueWei_,
        uint256 policyMaxFeeWei_,
        bytes32 devicePublicKeyX_,
        bytes32 devicePublicKeyY_
    ) {
        if (
            block.chainid != BASE_MAINNET_CHAIN_ID || trustedManifestHash_ == bytes32(0)
                || enrolledDeviceId_ == bytes32(0) || enrolledDeviceKeyId_ == bytes32(0)
                || enrolledDeviceEpoch_ == 0 || enrolledScopedOwnerCommitment_ == bytes32(0)
                || enforcedPolicyHash_ == bytes32(0) || trustedCapabilityBindingHash_ == bytes32(0)
                || approvedTarget_ == address(0) || approvedTarget_ == ENTRY_POINT_V07
                || policyMaxFeeWei_ == 0
                || !P256.isValidPublicKey(devicePublicKeyX_, devicePublicKeyY_)
        ) revert PhilStep6BInvalidConstructor();

        trustedManifestHash = trustedManifestHash_;
        enrolledDeviceId = enrolledDeviceId_;
        enrolledDeviceKeyId = enrolledDeviceKeyId_;
        enrolledDeviceEpoch = enrolledDeviceEpoch_;
        enrolledScopedOwnerCommitment = enrolledScopedOwnerCommitment_;
        enforcedPolicyHash = enforcedPolicyHash_;
        trustedCapabilityBindingHash = trustedCapabilityBindingHash_;
        approvedTarget = approvedTarget_;
        policyMaxValueWei = policyMaxValueWei_;
        policyMaxFeeWei = policyMaxFeeWei_;
        devicePublicKeyX = devicePublicKeyX_;
        devicePublicKeyY = devicePublicKeyY_;
    }

    receive() external payable {}

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external view override returns (uint256 validationData) {
        _requireEntryPoint();
        if (missingAccountFunds != 0) revert PhilStep6BUserOperationMismatch();
        if (userOpHash != keccak256(abi.encode(userOp.hash(), ENTRY_POINT_V07, block.chainid))) {
            revert PhilStep6BUserOperationHashMismatch();
        }

        (
            PhilEvmSingleCallV1 memory action,
            PhilAuthorizationEnvelopeV1 memory envelope,
            PhilDeviceApprovalV1 memory approval,
            bytes memory targetCalldata
        ) = _decodeExecuteCall(userOp.callData);

        (bytes32 deviceApprovalDigest,, bytes32 authorizationHash) =
            _validateBindings(action, envelope, approval, targetCalldata);
        if (
            keccak256(userOp.callData)
                != keccak256(abi.encodeWithSelector(this.executeAuthorized.selector, action, envelope, approval, targetCalldata))
        ) revert PhilStep6BMalformedCallData();
        _validateUserOperationFields(userOp, action);
        if (consumedAuthorization[authorizationHash]) revert PhilStep6BAuthorizationAlreadyConsumed();
        if (nextNonceSequence[action.nonceKey] != action.nonceSequence) revert PhilStep6BNonceMismatch();

        if (userOp.signature.length != 64) {
            return _packValidationData(
                true,
                _minimum(action.validUntil, approval.approvalExpiresAt),
                _maximum(action.validAfter, approval.approvedAt)
            );
        }
        (bytes32 signatureR, bytes32 signatureS) = abi.decode(userOp.signature, (bytes32, bytes32));
        bool signatureValid = P256.verify(
            deviceApprovalDigest,
            signatureR,
            signatureS,
            devicePublicKeyX,
            devicePublicKeyY
        );
        return _packValidationData(
            !signatureValid,
            _minimum(action.validUntil, approval.approvalExpiresAt),
            _maximum(action.validAfter, approval.approvedAt)
        );
    }

    function executeAuthorized(
        PhilEvmSingleCallV1 calldata action,
        PhilAuthorizationEnvelopeV1 calldata envelope,
        PhilDeviceApprovalV1 calldata approval,
        bytes calldata targetCalldata
    ) external {
        _requireEntryPoint();
        (bytes32 deviceApprovalDigest, bytes32 envelopeDigest, bytes32 authorizationHash) =
            _validateBindings(action, envelope, approval, targetCalldata);
        if (
            block.timestamp < action.validAfter || block.timestamp > action.validUntil
                || block.timestamp < approval.approvedAt || block.timestamp > approval.approvalExpiresAt
        ) {
            revert PhilStep6BExecutionOutsideValidity();
        }
        if (consumedAuthorization[authorizationHash]) revert PhilStep6BAuthorizationAlreadyConsumed();
        if (nextNonceSequence[action.nonceKey] != action.nonceSequence) revert PhilStep6BNonceMismatch();

        consumedAuthorization[authorizationHash] = true;
        nextNonceSequence[action.nonceKey] = action.nonceSequence + 1;

        (bool success, bytes memory result) = action.target.call{value: action.valueWei}(targetCalldata);
        if (!success) revert PhilStep6BExecutionFailed(result);
        emit PhilV1Step6BAuthorizationConsumed(
            authorizationHash,
            envelopeDigest,
            deviceApprovalDigest,
            envelope.nonce,
            action.target
        );
    }

    /// @notice Reproduces the three binding hashes without granting execution authority.
    function previewAuthorization(
        PhilEvmSingleCallV1 calldata action,
        PhilAuthorizationEnvelopeV1 calldata envelope,
        PhilDeviceApprovalV1 calldata approval,
        bytes calldata targetCalldata
    ) external view returns (bytes32 deviceApprovalDigest, bytes32 envelopeDigest, bytes32 authorizationHash) {
        return _validateBindings(action, envelope, approval, targetCalldata);
    }

    function _decodeExecuteCall(bytes calldata callData)
        private
        pure
        returns (
            PhilEvmSingleCallV1 memory action,
            PhilAuthorizationEnvelopeV1 memory envelope,
            PhilDeviceApprovalV1 memory approval,
            bytes memory targetCalldata
        )
    {
        if (callData.length < 4 || bytes4(callData[:4]) != this.executeAuthorized.selector) {
            revert PhilStep6BMalformedCallData();
        }
        return abi.decode(
            callData[4:],
            (PhilEvmSingleCallV1, PhilAuthorizationEnvelopeV1, PhilDeviceApprovalV1, bytes)
        );
    }

    function _validateUserOperationFields(PackedUserOperation calldata userOp, PhilEvmSingleCallV1 memory action)
        private
        view
    {
        (uint256 verificationGasLimit, uint256 callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(userOp.gasFees);
        if (
            userOp.sender != address(this) || userOp.nonce != _userOpNonce(action)
                || userOp.initCode.length != 0 || userOp.paymasterAndData.length != 0
                || verificationGasLimit != action.verificationGasLimit || callGasLimit != action.callGasLimit
                || userOp.preVerificationGas != action.preVerificationGas
                || maxFeePerGas != action.maxFeePerGas || maxPriorityFeePerGas != action.maxPriorityFeePerGas
        ) revert PhilStep6BUserOperationMismatch();
    }

    function _validateBindings(
        PhilEvmSingleCallV1 memory action,
        PhilAuthorizationEnvelopeV1 memory envelope,
        PhilDeviceApprovalV1 memory approval,
        bytes memory targetCalldata
    ) private view returns (bytes32 deviceApprovalDigest, bytes32 envelopeDigest, bytes32 authorizationHash) {
        if (
            action.target != approvedTarget || action.target == address(this)
                || keccak256(targetCalldata) != action.targetCalldataHash
                || action.callGasLimit == 0 || action.verificationGasLimit == 0 || action.preVerificationGas == 0
                || action.maxFeePerGas == 0 || action.maxPriorityFeePerGas > action.maxFeePerGas
                || action.validUntil == 0 || action.validUntil < action.validAfter
        ) revert PhilStep6BBindingMismatch();

        uint256 userOpNonce = _userOpNonce(action);
        uint256 maximumFee;
        unchecked {
            uint256 gasTotal = uint256(action.callGasLimit) + uint256(action.verificationGasLimit);
            gasTotal += action.preVerificationGas;
            maximumFee = gasTotal * uint256(action.maxFeePerGas);
            if (gasTotal < action.preVerificationGas || maximumFee / uint256(action.maxFeePerGas) != gasTotal) {
                revert PhilStep6BFeeOverflow();
            }
        }

        bytes32 accountCallCommitment = keccak256(
            abi.encode(EVM_SINGLE_CALL_V1, action.target, action.valueWei, action.targetCalldataHash)
        );
        bytes32 actionHash = keccak256(
            abi.encode(
                EVM_SINGLE_CALL_V1,
                block.chainid,
                address(this),
                ENTRY_POINT_V07,
                action.target,
                action.targetCalldataHash,
                accountCallCommitment,
                action.valueWei,
                action.nonceKey,
                action.nonceSequence,
                userOpNonce,
                action.callGasLimit,
                action.verificationGasLimit,
                action.preVerificationGas,
                action.maxFeePerGas,
                action.maxPriorityFeePerGas,
                maximumFee,
                bytes32(0),
                bytes32(0),
                action.validAfter,
                action.validUntil
            )
        );
        bytes32 accountBindingHash = keccak256(
            abi.encode(
                EVM_ACCOUNT_BINDING_V1,
                trustedManifestHash,
                BASE_MAINNET_NETWORK_ID_HASH,
                ERC4337_ACCOUNT_MODEL_ID,
                block.chainid,
                ENTRY_POINT_V07,
                address(this)
            )
        );
        bytes32 nonceDomain = keccak256(
            abi.encode(
                EVM_NONCE_DOMAIN_V1,
                BASE_MAINNET_ADAPTER_ID,
                BASE_MAINNET_NETWORK_ID_HASH,
                ENTRY_POINT_V07,
                address(this),
                action.nonceKey
            )
        );
        bytes32 intentDigest = keccak256(
            abi.encode(EVM_INTENT_V1, trustedManifestHash, actionHash, accountBindingHash, nonceDomain)
        );

        if (
            envelope.operationClass != 1 || envelope.rootProofNullifier != bytes32(0)
                || envelope.proofDescriptorHash != bytes32(0) || envelope.capabilityId == bytes32(0)
                || envelope.scopeId == bytes32(0) || envelope.scopeInstance == bytes32(0)
                || envelope.principalIdHash == bytes32(0) || envelope.humanPresentationHash == bytes32(0)
                || envelope.scopeEpoch == 0 || envelope.capabilityEpoch == 0
                || envelope.recoveryEpoch == 0 || envelope.validatorEpoch == 0
                || _capabilityBindingHash(envelope) != trustedCapabilityBindingHash
                || envelope.scopedOwnerCommitment != enrolledScopedOwnerCommitment
                || envelope.networkIdHash != BASE_MAINNET_NETWORK_ID_HASH
                || envelope.accountBindingHash != accountBindingHash || envelope.adapterId != BASE_MAINNET_ADAPTER_ID
                || envelope.actionTypeHash != EVM_SINGLE_CALL_V1 || envelope.parametersHash != actionHash
                || envelope.intentDigest != intentDigest || envelope.nonceDomain != nonceDomain
                || envelope.nonce != userOpNonce || envelope.validAfter != action.validAfter
                || envelope.validUntil != action.validUntil || action.valueWei > envelope.valueLimit
                || maximumFee > envelope.feeLimit || action.valueWei > policyMaxValueWei
                || maximumFee > policyMaxFeeWei
        ) revert PhilStep6BBindingMismatch();
        if (
            envelope.policyHash != enforcedPolicyHash || envelope.deviceEpoch != enrolledDeviceEpoch
                || envelope.deviceSignatureSuiteId != P256_SHA256_SIGNATURE_SUITE_ID
                || approval.deviceId != enrolledDeviceId || approval.deviceKeyId != enrolledDeviceKeyId
                || approval.deviceEpoch != enrolledDeviceEpoch || approval.deviceEpoch != envelope.deviceEpoch
        ) revert PhilStep6BPolicyMismatch();
        if (
            approval.approvedAt == 0 || approval.approvalExpiresAt < approval.approvedAt
                || approval.approvalNonce == bytes32(0)
                || approval.approvedAt < action.validAfter || approval.approvalExpiresAt > action.validUntil
        ) revert PhilStep6BValidityMismatch();

        envelopeDigest = _authorizationEnvelopeDigest(envelope);
        deviceApprovalDigest = keccak256(
            abi.encode(
                DEVICE_APPROVAL_V1,
                envelopeDigest,
                approval.deviceId,
                approval.deviceKeyId,
                approval.deviceEpoch,
                approval.approvalNonce,
                approval.approvedAt,
                approval.approvalExpiresAt
            )
        );
        authorizationHash = keccak256(
            abi.encode(
                EVM_ADAPTER_AUTHORIZATION_V1,
                trustedManifestHash,
                envelopeDigest,
                bytes32(0),
                actionHash,
                accountBindingHash,
                nonceDomain,
                deviceApprovalDigest,
                uint8(1),
                false,
                false,
                false,
                false
            )
        );
    }

    function _authorizationEnvelopeDigest(PhilAuthorizationEnvelopeV1 memory envelope)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                AUTHORIZATION_ENVELOPE_V1,
                envelope.operationClass,
                envelope.scopedOwnerCommitment,
                envelope.scopeId,
                envelope.scopeInstance,
                envelope.scopeEpoch,
                envelope.principalIdHash,
                envelope.capabilityId,
                envelope.capabilityEpoch,
                envelope.networkIdHash,
                envelope.accountBindingHash,
                envelope.adapterId,
                envelope.actionTypeHash,
                envelope.parametersHash,
                envelope.intentDigest,
                envelope.policyHash,
                envelope.nonceDomain,
                envelope.nonce,
                envelope.validAfter,
                envelope.validUntil,
                envelope.valueLimit,
                envelope.feeLimit,
                envelope.deviceEpoch,
                envelope.recoveryEpoch,
                envelope.validatorEpoch,
                envelope.deviceSignatureSuiteId,
                envelope.proofDescriptorHash,
                envelope.humanPresentationHash
            )
        );
    }

    function _userOpNonce(PhilEvmSingleCallV1 memory action) private pure returns (uint256) {
        return (uint256(action.nonceKey) << 64) | uint256(action.nonceSequence);
    }

    function _capabilityBindingHash(PhilAuthorizationEnvelopeV1 memory envelope) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                STEP6B_CAPABILITY_BINDING_V1,
                envelope.scopeId,
                envelope.scopeInstance,
                envelope.scopeEpoch,
                envelope.principalIdHash,
                envelope.capabilityId,
                envelope.capabilityEpoch
            )
        );
    }

    function _minimum(uint48 left, uint64 right) private pure returns (uint48) {
        return left < right ? left : uint48(right);
    }

    function _maximum(uint48 left, uint64 right) private pure returns (uint48) {
        return left > right ? left : uint48(right);
    }

    function _requireEntryPoint() private view {
        if (msg.sender != ENTRY_POINT_V07) revert PhilStep6BOnlyEntryPoint();
    }
}
