// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Local-only Step 6C account proving one device-present routine authorization.
/// @dev No owner bypass, generic execution, upgrade, recovery, proof, RPC, or production authority exists.
contract PhilV1Step6CAccount is IAccount {
    using UserOperationLib for PackedUserOperation;

    bytes32 public constant AUTHORIZATION_ENVELOPE_V1 = keccak256("PHIL_AUTHORIZATION_ENVELOPE_V1");
    bytes32 public constant DEVICE_APPROVAL_V1 = keccak256("PHIL_DEVICE_APPROVAL_V1");
    bytes32 public constant EVM_SINGLE_CALL_V1 = keccak256("PHIL_EVM_SINGLE_CALL_V1");
    bytes32 public constant EVM_ACCOUNT_BINDING_V1 = keccak256("PHIL_EVM_ACCOUNT_BINDING_V1");
    bytes32 public constant EVM_NONCE_DOMAIN_V1 = keccak256("PHIL_EVM_NONCE_DOMAIN_V1");
    bytes32 public constant EVM_INTENT_V1 = keccak256("PHIL_EVM_INTENT_V1");
    bytes32 public constant EXECUTION_ENVIRONMENT_V1 = keccak256("PHIL_EXECUTION_ENVIRONMENT_V1");
    bytes32 public constant ROUTINE_ACCOUNT_CONFIGURATION_V1 = keccak256("PHIL_ROUTINE_ACCOUNT_CONFIGURATION_V1");
    bytes32 public constant ROUTINE_APPLICATION_PRINCIPAL_V1 = keccak256("PHIL_ROUTINE_APPLICATION_PRINCIPAL_V1");
    bytes32 public constant ROUTINE_SCOPE_INSTANCE_V1 = keccak256("PHIL_ROUTINE_SCOPE_INSTANCE_V1");
    bytes32 public constant ROUTINE_CAPABILITY_V1 = keccak256("PHIL_ROUTINE_CAPABILITY_V1");
    bytes32 public constant ROUTINE_PARAMETER_SCHEMA_V1 = keccak256("PHIL_ROUTINE_PARAMETER_SCHEMA_V1");
    bytes32 public constant ROUTINE_CATALOG_ENTRY_V1 = keccak256("PHIL_ROUTINE_CATALOG_ENTRY_V1");
    bytes32 public constant ROUTINE_CATALOG_V1 = keccak256("PHIL_ROUTINE_CATALOG_V1");
    bytes32 public constant ROUTINE_CAPABILITY_POLICY_V1 = keccak256("PHIL_ROUTINE_CAPABILITY_POLICY_V1");
    bytes32 public constant ROUTINE_HUMAN_PRESENTATION_V1 = keccak256("PHIL_ROUTINE_HUMAN_PRESENTATION_V1");
    bytes32 public constant ROUTINE_AUTHORIZATION_CORE_V1 = keccak256("PHIL_ROUTINE_AUTHORIZATION_CORE_V1");
    bytes32 public constant ROUTINE_APPROVAL_NONCE_V1 = keccak256("PHIL_ROUTINE_APPROVAL_NONCE_V1");
    bytes32 public constant ROUTINE_AUTHORIZATION_REQUEST_V1 = keccak256("PHIL_ROUTINE_AUTHORIZATION_REQUEST_V1");
    bytes32 public constant ROUTINE_AUTHORIZATION_TRANSPORT_V1 = keccak256("PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1");
    bytes32 public constant DEVICE_APPROVAL_SIGNING_PREHASH_V2 =
        keccak256("PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2");

    bytes32 public constant LOCAL_NETWORK_ID = keccak256("phil-local:step6c:31337");
    bytes32 public constant LOCAL_ADAPTER_ID = keccak256("phil-adapter-step6c-local-erc4337-v07-v1");
    bytes32 public constant APPLICATION_ID = keccak256("phil-application-step6c-local-harmless-v1");
    bytes32 public constant SCOPE_ID = keccak256("phil-scope-step6c-local-routine-v1");
    bytes32 public constant SIGNATURE_SUITE_ID =
        keccak256("phil-signature-p256-sha256-prehash-raw-rs-low-s-v2");
    bytes32 public constant PROVIDER_PROFILE_ID =
        keccak256("apple-secure-enclave-p256-x962-sha256-digest-der-v1");
    bytes32 public constant WIRE_ENCODING_ID = keccak256("phil-p256-signature-rs-64-low-s-v1");
    bytes32 public constant RECORDED_VALUE = keccak256("PHIL_STEP6C_HARMLESS_VALUE_V1");
    bytes4 public constant RECORD_SELECTOR = bytes4(keccak256("record(bytes32,bool)"));
    bytes32 public constant SUCCESS_SUMMARY_HASH = keccak256("Record disclosed harmless value");
    bytes32 public constant FAILURE_SUMMARY_HASH = keccak256("Intentionally revert before recording");
    bytes32 public constant CATALOG_APPLICATION_LABEL_HASH = keccak256("Phil Step 6C Local Harmless App");
    bytes32 public constant CATALOG_NETWORK_LABEL_HASH = keccak256("Local Hardhat Chain 31337");
    bytes32 public constant CATALOG_ACCOUNT_LABEL_HASH = keccak256("Disposable Phil Routine Account");
    bytes32 public constant CATALOG_TARGET_LABEL_HASH = keccak256("Harmless Local Record Target");
    bytes32 public constant CATALOG_ACTION_LABEL_HASH = keccak256("Record Harmless Local Value");
    bytes32 public constant CATALOG_PARAMETERS_LABEL_HASH = keccak256("Harmless Record Parameters");
    uint256 public constant LOCAL_CHAIN_ID = 31337;

    struct PhilStep6CAccountActionV1 {
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

    struct PhilStep6CEnvelopeV1 {
        bytes32 formatVersionHash;
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

    struct PhilStep6CApprovalV1 {
        bytes32 formatVersionHash;
        bytes32 authorizationEnvelopeDigest;
        bytes32 deviceId;
        bytes32 deviceKeyId;
        uint64 deviceEpoch;
        bytes32 approvalNonce;
        uint64 approvedAt;
        uint64 approvalExpiresAt;
    }

    struct PhilStep6CPresentationV1 {
        bytes32 formatVersionHash;
        bytes32 applicationId;
        bytes32 applicationNameHash;
        bytes32 principalIdHash;
        bytes32 scopeId;
        bytes32 scopeInstance;
        uint64 scopeEpoch;
        bytes32 executionEnvironmentHash;
        bytes32 networkLabelHash;
        address account;
        bytes32 accountLabelHash;
        address target;
        bytes32 targetRuntimeCodeHash;
        bytes32 targetLabelHash;
        bytes32 actionTypeHash;
        bytes32 actionLabelHash;
        bytes32 parametersHash;
        bytes32 parameterSummaryHash;
        uint256 valueWei;
        uint256 maximumTotalFeeWei;
        uint48 validAfter;
        uint48 validUntil;
        bytes32 capabilityId;
        uint64 capabilityEpoch;
        bytes32 policyHash;
        uint64 policyEpoch;
        bool externalNetwork;
        bool productionAuthority;
        bool meaningfulAssets;
    }

    struct PhilStep6CCoreV1 {
        bytes32 formatVersionHash;
        bytes32 protocolContextHash;
        bytes32 sessionId;
        bytes32 nonceSeed;
        uint64 issuedAt;
        uint64 expiresAt;
        bytes32 executionEnvironmentHash;
        bytes32 adapterManifestHash;
        bytes32 signatureRegistryHash;
        bytes32 deviceEnrollmentHash;
        bytes32 accountConfigurationHash;
        bytes32 catalogHash;
        bytes32 capabilityPolicyHash;
        bytes32 actionHash;
        bytes32 targetCalldataHash;
        bytes32 authorizationEnvelopeDigest;
        bytes32 rootProofNullifier;
        bytes32 humanPresentationHash;
    }

    struct ConstructorConfigV1 {
        address entryPoint;
        bytes32 executionEnvironmentHash;
        bytes32 adapterManifestHash;
        bytes32 signatureRegistryHash;
        bytes32 deviceEnrollmentHash;
        bytes32 accountConfigurationHash;
        bytes32 catalogHash;
        bytes32 capabilityPolicyHash;
        bytes32[6] catalogDisplayTextHashes;
        bytes32 accountRuntimeCodeHash;
        bytes32 applicationId;
        bytes32 principalIdHash;
        bytes32 scopedOwnerCommitment;
        bytes32 scopeId;
        bytes32 scopeInstance;
        uint64 scopeEpoch;
        bytes32 capabilityId;
        uint64 capabilityEpoch;
        uint64 policyEpoch;
        bytes32 deviceId;
        bytes32 deviceKeyId;
        uint64 deviceEpoch;
        bytes32 signatureSuiteId;
        bytes32 providerProfileId;
        bytes32 wireEncodingId;
        bytes32 publicKeyX;
        bytes32 publicKeyY;
        uint64 recoveryEpoch;
        uint64 validatorEpoch;
        address approvedTarget;
        bytes32 approvedTargetRuntimeCodeHash;
        bytes32 actionTypeHash;
        bytes32 parameterSchemaId;
        uint192 nonceKey;
        uint256 maximumValueWei;
        uint256 maximumTotalFeeWei;
        uint48 profilePolicyValidAfter;
        uint48 profilePolicyValidUntil;
    }

    address public entryPoint;
    uint256 public chainId;
    bytes32 public executionEnvironmentHash;
    bytes32 public adapterManifestHash;
    bytes32 public signatureRegistryHash;
    bytes32 public deviceEnrollmentHash;
    bytes32 public accountConfigurationHash;
    bytes32 public catalogHash;
    bytes32 public capabilityPolicyHash;
    bytes32[6] public catalogDisplayTextHashes;
    bytes32 public accountRuntimeCodeHash;
    bytes32 public applicationId;
    bytes32 public principalIdHash;
    bytes32 public scopedOwnerCommitment;
    bytes32 public scopeId;
    bytes32 public scopeInstance;
    uint64 public scopeEpoch;
    bytes32 public capabilityId;
    uint64 public capabilityEpoch;
    uint64 public policyEpoch;
    bytes32 public deviceId;
    bytes32 public deviceKeyId;
    uint64 public deviceEpoch;
    bytes32 public signatureSuiteId;
    bytes32 public providerProfileId;
    bytes32 public wireEncodingId;
    bytes32 public devicePublicKeyX;
    bytes32 public devicePublicKeyY;
    uint64 public recoveryEpoch;
    uint64 public validatorEpoch;
    address public approvedTarget;
    bytes32 public approvedTargetRuntimeCodeHash;
    bytes32 public actionTypeHash;
    bytes32 public parameterSchemaId;
    uint192 public nonceKey;
    uint256 public maximumValueWei;
    uint256 public maximumTotalFeeWei;
    uint48 public profilePolicyValidAfter;
    uint48 public profilePolicyValidUntil;

    mapping(bytes32 requestId => bytes32 userOperationHash) public validatedUserOperationHash;

    event PhilV1Step6CAuthorizationConsumed(
        bytes32 indexed requestId,
        bytes32 indexed authorizationEnvelopeDigest,
        bytes32 indexed deviceApprovalDigest,
        bytes32 platformSigningDigest,
        bytes32 userOperationHash,
        address target
    );

    error PhilStep6CInvalidConstructor();
    error PhilStep6COnlyEntryPoint();
    error PhilStep6CMalformedCallData();
    error PhilStep6CUserOperationMismatch();
    error PhilStep6CBindingMismatch();
    error PhilStep6CPolicyMismatch();
    error PhilStep6CValidityMismatch();
    error PhilStep6CFeeOverflow();
    error PhilStep6CValidationHandoffMismatch();
    error PhilStep6CExecutionFailed(bytes reason);

    constructor(ConstructorConfigV1 memory c) {
        if (block.chainid != LOCAL_CHAIN_ID || c.entryPoint == address(0) || c.entryPoint == address(this)
            || c.applicationId != APPLICATION_ID || c.scopeId != SCOPE_ID || c.scopeEpoch != 1
            || c.capabilityEpoch != 1 || c.policyEpoch != 1 || c.deviceEpoch != 1
            || c.recoveryEpoch != 1 || c.validatorEpoch != 1 || c.signatureSuiteId != SIGNATURE_SUITE_ID
            || c.providerProfileId != PROVIDER_PROFILE_ID || c.wireEncodingId != WIRE_ENCODING_ID
            || c.approvedTarget == address(0) || c.approvedTarget == c.entryPoint
            || c.approvedTarget == address(this) || c.maximumValueWei != 0 || c.maximumTotalFeeWei == 0
            || c.profilePolicyValidAfter == 0
            || uint256(c.profilePolicyValidUntil) != uint256(c.profilePolicyValidAfter) + 86400
            || c.approvedTarget.code.length == 0 || c.approvedTarget.codehash != c.approvedTargetRuntimeCodeHash
            || c.catalogDisplayTextHashes[0] != CATALOG_APPLICATION_LABEL_HASH
            || c.catalogDisplayTextHashes[1] != CATALOG_NETWORK_LABEL_HASH
            || c.catalogDisplayTextHashes[2] != CATALOG_ACCOUNT_LABEL_HASH
            || c.catalogDisplayTextHashes[3] != CATALOG_TARGET_LABEL_HASH
            || c.catalogDisplayTextHashes[4] != CATALOG_ACTION_LABEL_HASH
            || c.catalogDisplayTextHashes[5] != CATALOG_PARAMETERS_LABEL_HASH
            || !P256.isValidPublicKey(c.publicKeyX, c.publicKeyY)) revert PhilStep6CInvalidConstructor();

        bytes32 expectedPrincipal = keccak256(abi.encode(ROUTINE_APPLICATION_PRINCIPAL_V1, APPLICATION_ID));
        bytes32 expectedScopeInstance = keccak256(abi.encode(
            ROUTINE_SCOPE_INSTANCE_V1, SCOPE_ID, APPLICATION_ID, c.executionEnvironmentHash, address(this)
        ));
        bytes32 expectedSchema = keccak256(abi.encode(
            ROUTINE_PARAMETER_SCHEMA_V1, c.approvedTarget, c.approvedTargetRuntimeCodeHash, RECORD_SELECTOR, RECORDED_VALUE
        ));
        bytes32 expectedCapability = keccak256(abi.encode(
            ROUTINE_CAPABILITY_V1, APPLICATION_ID, expectedScopeInstance, c.approvedTarget,
            c.approvedTargetRuntimeCodeHash, EVM_SINGLE_CALL_V1, expectedSchema
        ));
        if (c.principalIdHash != expectedPrincipal || c.scopeInstance != expectedScopeInstance
            || c.parameterSchemaId != expectedSchema || c.capabilityId != expectedCapability
            || c.actionTypeHash != EVM_SINGLE_CALL_V1) revert PhilStep6CInvalidConstructor();

        bytes32 accountId = keccak256(abi.encode(address(this)));
        bytes32 targetId = keccak256(abi.encode(c.approvedTarget, c.approvedTargetRuntimeCodeHash));
        bytes32[6] memory entryHashes;
        entryHashes[0] = _catalogEntryHash(1, APPLICATION_ID, c.catalogDisplayTextHashes[0], APPLICATION_ID);
        entryHashes[1] = _catalogEntryHash(2, LOCAL_NETWORK_ID, c.catalogDisplayTextHashes[1], c.executionEnvironmentHash);
        entryHashes[2] = _catalogEntryHash(3, accountId, c.catalogDisplayTextHashes[2], accountId);
        entryHashes[3] = _catalogEntryHash(4, targetId, c.catalogDisplayTextHashes[3], targetId);
        entryHashes[4] = _catalogEntryHash(5, EVM_SINGLE_CALL_V1, c.catalogDisplayTextHashes[4], EVM_SINGLE_CALL_V1);
        entryHashes[5] = _catalogEntryHash(6, expectedSchema, c.catalogDisplayTextHashes[5], expectedSchema);
        bytes32 expectedCatalog = keccak256(abi.encode(ROUTINE_CATALOG_V1, entryHashes));
        if (expectedCatalog != c.catalogHash) revert PhilStep6CInvalidConstructor();

        bytes32 expectedConfiguration = keccak256(abi.encode(
            ROUTINE_ACCOUNT_CONFIGURATION_V1, c.executionEnvironmentHash, c.adapterManifestHash, APPLICATION_ID,
            expectedPrincipal, SCOPE_ID, expectedScopeInstance, uint64(1), uint64(1), uint64(1), address(this),
            c.accountRuntimeCodeHash, c.deviceEnrollmentHash, c.scopedOwnerCommitment, c.approvedTarget,
            c.approvedTargetRuntimeCodeHash, EVM_SINGLE_CALL_V1, c.nonceKey, uint256(0), c.maximumTotalFeeWei
        ));
        if (expectedConfiguration != c.accountConfigurationHash) revert PhilStep6CInvalidConstructor();

        bytes32 expectedPolicy = keccak256(abi.encode(
            ROUTINE_CAPABILITY_POLICY_V1, c.scopedOwnerCommitment, APPLICATION_ID, expectedPrincipal, SCOPE_ID,
            expectedScopeInstance, uint64(1), uint64(1), uint64(1), expectedCapability, uint64(1), uint64(1),
            c.executionEnvironmentHash, c.adapterManifestHash, expectedConfiguration, c.deviceEnrollmentHash,
            expectedCatalog, c.approvedTarget, c.approvedTargetRuntimeCodeHash, EVM_SINGLE_CALL_V1, uint256(0),
            c.maximumTotalFeeWei, c.profilePolicyValidAfter, c.profilePolicyValidUntil, true
        ));
        if (expectedPolicy != c.capabilityPolicyHash) revert PhilStep6CInvalidConstructor();

        entryPoint = c.entryPoint;
        chainId = block.chainid;
        executionEnvironmentHash = c.executionEnvironmentHash;
        adapterManifestHash = c.adapterManifestHash;
        signatureRegistryHash = c.signatureRegistryHash;
        deviceEnrollmentHash = c.deviceEnrollmentHash;
        accountConfigurationHash = c.accountConfigurationHash;
        catalogHash = c.catalogHash;
        capabilityPolicyHash = c.capabilityPolicyHash;
        catalogDisplayTextHashes = c.catalogDisplayTextHashes;
        accountRuntimeCodeHash = c.accountRuntimeCodeHash;
        applicationId = APPLICATION_ID;
        principalIdHash = expectedPrincipal;
        scopedOwnerCommitment = c.scopedOwnerCommitment;
        scopeId = SCOPE_ID;
        scopeInstance = expectedScopeInstance;
        scopeEpoch = 1;
        capabilityId = expectedCapability;
        capabilityEpoch = 1;
        policyEpoch = 1;
        deviceId = c.deviceId;
        deviceKeyId = c.deviceKeyId;
        deviceEpoch = 1;
        signatureSuiteId = SIGNATURE_SUITE_ID;
        providerProfileId = PROVIDER_PROFILE_ID;
        wireEncodingId = WIRE_ENCODING_ID;
        devicePublicKeyX = c.publicKeyX;
        devicePublicKeyY = c.publicKeyY;
        recoveryEpoch = 1;
        validatorEpoch = 1;
        approvedTarget = c.approvedTarget;
        approvedTargetRuntimeCodeHash = c.approvedTargetRuntimeCodeHash;
        actionTypeHash = EVM_SINGLE_CALL_V1;
        parameterSchemaId = expectedSchema;
        nonceKey = c.nonceKey;
        maximumValueWei = 0;
        maximumTotalFeeWei = c.maximumTotalFeeWei;
        profilePolicyValidAfter = c.profilePolicyValidAfter;
        profilePolicyValidUntil = c.profilePolicyValidUntil;
    }

    receive() external payable {}

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external override returns (uint256 validationData)
    {
        _requireEntryPoint();
        if (missingAccountFunds != 0 || userOp.sender != address(this) || userOp.initCode.length != 0
            || userOp.paymasterAndData.length != 0
            || userOpHash != keccak256(abi.encode(userOp.hash(), entryPoint, block.chainid))) {
            revert PhilStep6CUserOperationMismatch();
        }
        (PhilStep6CAccountActionV1 memory action, PhilStep6CEnvelopeV1 memory envelope,
            PhilStep6CApprovalV1 memory approval, PhilStep6CPresentationV1 memory presentation,
            PhilStep6CCoreV1 memory core, bytes memory targetCalldata) = _decodeExecuteCall(userOp.callData);
        if (keccak256(userOp.callData) != keccak256(abi.encodeWithSelector(
            this.executeAuthorized.selector, action, envelope, approval, presentation, core, targetCalldata
        ))) revert PhilStep6CMalformedCallData();
        _validateUserOperationFields(userOp, action);
        (bytes32 requestId, bytes32 platformDigest,) =
            _validateBindings(action, envelope, approval, presentation, core, targetCalldata);
        if (userOp.signature.length != 64) {
            return _packValidationData(true, action.validUntil, action.validAfter);
        }
        bytes calldata signature = userOp.signature;
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
        }
        bool valid = P256.verify(platformDigest, r, s, devicePublicKeyX, devicePublicKeyY);
        if (valid) {
            bytes32 existing = validatedUserOperationHash[requestId];
            if (existing != bytes32(0) && existing != userOpHash) revert PhilStep6CValidationHandoffMismatch();
            validatedUserOperationHash[requestId] = userOpHash;
        }
        return _packValidationData(!valid, action.validUntil, action.validAfter);
    }

    function executeAuthorized(
        PhilStep6CAccountActionV1 calldata action,
        PhilStep6CEnvelopeV1 calldata envelope,
        PhilStep6CApprovalV1 calldata approval,
        PhilStep6CPresentationV1 calldata presentation,
        PhilStep6CCoreV1 calldata core,
        bytes calldata targetCalldata
    ) external {
        _requireEntryPoint();
        (bytes32 requestId, bytes32 platformDigest, bytes32 approvalDigest) =
            _validateBindings(action, envelope, approval, presentation, core, targetCalldata);
        if (block.timestamp < action.validAfter || block.timestamp > action.validUntil) {
            revert PhilStep6CValidityMismatch();
        }
        bytes32 userOpHash = validatedUserOperationHash[requestId];
        if (userOpHash == bytes32(0)) revert PhilStep6CValidationHandoffMismatch();
        // Consume the one-operation validation handoff before entering the
        // target. A target failure reverts this deletion with the transaction,
        // while a successful target cannot observe reusable authorization.
        delete validatedUserOperationHash[requestId];
        emit PhilV1Step6CAuthorizationConsumed(
            requestId, core.authorizationEnvelopeDigest, approvalDigest, platformDigest, userOpHash, action.target
        );
        (bool success, bytes memory result) = action.target.call{value: 0}(targetCalldata);
        if (!success) revert PhilStep6CExecutionFailed(result);
    }

    function previewAuthorization(
        PhilStep6CAccountActionV1 calldata action,
        PhilStep6CEnvelopeV1 calldata envelope,
        PhilStep6CApprovalV1 calldata approval,
        PhilStep6CPresentationV1 calldata presentation,
        PhilStep6CCoreV1 calldata core,
        bytes calldata targetCalldata
    ) external view returns (bytes32 requestId, bytes32 platformDigest, bytes32 approvalDigest) {
        return _validateBindings(action, envelope, approval, presentation, core, targetCalldata);
    }

    function _validateUserOperationFields(PackedUserOperation calldata userOp, PhilStep6CAccountActionV1 memory action)
        internal view
    {
        uint256 expectedNonce = (uint256(action.nonceKey) << 64) | uint256(action.nonceSequence);
        uint128 verificationGas = uint128(uint256(userOp.accountGasLimits) >> 128);
        uint128 callGas = uint128(uint256(userOp.accountGasLimits));
        uint128 priorityFee = uint128(uint256(userOp.gasFees) >> 128);
        uint128 maxFee = uint128(uint256(userOp.gasFees));
        if (action.nonceKey != nonceKey || userOp.nonce != expectedNonce || action.callGasLimit != callGas
            || action.verificationGasLimit != verificationGas || action.preVerificationGas != userOp.preVerificationGas
            || action.maxFeePerGas != maxFee || action.maxPriorityFeePerGas != priorityFee) {
            revert PhilStep6CUserOperationMismatch();
        }
    }

    function _validateBindings(
        PhilStep6CAccountActionV1 memory action,
        PhilStep6CEnvelopeV1 memory envelope,
        PhilStep6CApprovalV1 memory approval,
        PhilStep6CPresentationV1 memory presentation,
        PhilStep6CCoreV1 memory core,
        bytes memory targetCalldata
    ) internal view returns (bytes32 requestId, bytes32 platformDigest, bytes32 approvalDigest) {
        if (action.target != approvedTarget || action.target.code.length == 0
            || action.target.codehash != approvedTargetRuntimeCodeHash || action.valueWei != 0
            || action.nonceKey != nonceKey || action.validAfter == 0 || action.validUntil != action.validAfter + 120
            || action.validAfter < profilePolicyValidAfter || action.validUntil > profilePolicyValidUntil
            || keccak256(targetCalldata) != action.targetCalldataHash) revert PhilStep6CBindingMismatch();
        bytes32 parameterSummaryHash = _validateTargetCalldata(targetCalldata);
        uint256 maxTotalFee = _maximumTotalFee(action);
        if (maxTotalFee > maximumTotalFeeWei) revert PhilStep6CPolicyMismatch();

        bytes32 actionHash = _actionHash(action, maxTotalFee);
        bytes32 accountBindingHash = keccak256(abi.encode(
            EVM_ACCOUNT_BINDING_V1, adapterManifestHash, LOCAL_NETWORK_ID,
            keccak256("phil-evm-erc4337-narrow-account-binding-v1"), block.chainid, entryPoint, address(this)
        ));
        bytes32 nonceDomainHash = keccak256(abi.encode(
            EVM_NONCE_DOMAIN_V1, LOCAL_ADAPTER_ID, LOCAL_NETWORK_ID, entryPoint, address(this), action.nonceKey
        ));
        bytes32 intentDigest = keccak256(abi.encode(
            EVM_INTENT_V1, adapterManifestHash, actionHash, accountBindingHash, nonceDomainHash
        ));

        _validatePresentation(presentation, action, actionHash, parameterSummaryHash, maxTotalFee);
        bytes32 presentationHash = _presentationHash(presentation);
        _validateEnvelope(envelope, action, actionHash, accountBindingHash, nonceDomainHash, intentDigest, presentationHash, maxTotalFee);
        bytes32 envelopeDigest = _envelopeDigest(envelope);
        if (approval.formatVersionHash != DEVICE_APPROVAL_V1 || approval.authorizationEnvelopeDigest != envelopeDigest
            || approval.deviceId != deviceId || approval.deviceKeyId != deviceKeyId || approval.deviceEpoch != deviceEpoch
            || approval.approvedAt != action.validAfter || approval.approvalExpiresAt != action.validUntil) {
            revert PhilStep6CBindingMismatch();
        }
        _validateCore(core, action, actionHash, envelopeDigest, presentationHash);
        bytes32 coreDigest = _coreDigest(core);
        bytes32 approvalNonce = keccak256(abi.encode(
            ROUTINE_APPROVAL_NONCE_V1, coreDigest, core.sessionId, core.nonceSeed
        ));
        if (approval.approvalNonce != approvalNonce) revert PhilStep6CBindingMismatch();
        approvalDigest = keccak256(abi.encode(
            DEVICE_APPROVAL_V1, envelopeDigest, approval.deviceId, approval.deviceKeyId, approval.deviceEpoch,
            approvalNonce, approval.approvedAt, approval.approvalExpiresAt
        ));
        requestId = keccak256(abi.encode(
            ROUTINE_AUTHORIZATION_REQUEST_V1, coreDigest, approvalNonce, approvalDigest
        ));
        platformDigest = sha256(abi.encodePacked(DEVICE_APPROVAL_SIGNING_PREHASH_V2, requestId));
    }

    function _validatePresentation(
        PhilStep6CPresentationV1 memory p,
        PhilStep6CAccountActionV1 memory a,
        bytes32 actionHash,
        bytes32 summaryHash,
        uint256 maxTotalFee
    ) internal view {
        if (p.formatVersionHash != ROUTINE_HUMAN_PRESENTATION_V1 || p.applicationId != APPLICATION_ID
            || p.applicationNameHash != catalogDisplayTextHashes[0] || p.principalIdHash != principalIdHash
            || p.scopeId != SCOPE_ID || p.scopeInstance != scopeInstance || p.scopeEpoch != 1
            || p.executionEnvironmentHash != executionEnvironmentHash || p.networkLabelHash != catalogDisplayTextHashes[1]
            || p.account != address(this) || p.accountLabelHash != catalogDisplayTextHashes[2]
            || p.target != approvedTarget || p.targetRuntimeCodeHash != approvedTargetRuntimeCodeHash
            || p.targetLabelHash != catalogDisplayTextHashes[3] || p.actionTypeHash != EVM_SINGLE_CALL_V1
            || p.actionLabelHash != catalogDisplayTextHashes[4] || p.parametersHash != actionHash
            || p.parameterSummaryHash != summaryHash || p.valueWei != 0 || p.maximumTotalFeeWei != maxTotalFee
            || p.validAfter != a.validAfter || p.validUntil != a.validUntil || p.capabilityId != capabilityId
            || p.capabilityEpoch != 1 || p.policyHash != capabilityPolicyHash || p.policyEpoch != 1
            || p.externalNetwork || p.productionAuthority || p.meaningfulAssets) revert PhilStep6CBindingMismatch();
    }

    function _validateEnvelope(
        PhilStep6CEnvelopeV1 memory e,
        PhilStep6CAccountActionV1 memory a,
        bytes32 actionHash,
        bytes32 accountBindingHash,
        bytes32 nonceDomainHash,
        bytes32 intentDigest,
        bytes32 presentationHash,
        uint256 maxTotalFee
    ) internal view {
        uint256 packedNonce = (uint256(a.nonceKey) << 64) | uint256(a.nonceSequence);
        if (e.formatVersionHash != AUTHORIZATION_ENVELOPE_V1 || e.operationClass != 1
            || e.scopedOwnerCommitment != scopedOwnerCommitment || e.scopeId != SCOPE_ID
            || e.scopeInstance != scopeInstance || e.scopeEpoch != 1 || e.principalIdHash != principalIdHash
            || e.capabilityId != capabilityId || e.capabilityEpoch != 1 || e.networkIdHash != LOCAL_NETWORK_ID
            || e.accountBindingHash != accountBindingHash || e.adapterId != LOCAL_ADAPTER_ID
            || e.actionTypeHash != EVM_SINGLE_CALL_V1 || e.parametersHash != actionHash
            || e.intentDigest != intentDigest || e.policyHash != capabilityPolicyHash
            || e.nonceDomain != nonceDomainHash || e.nonce != packedNonce || e.rootProofNullifier != bytes32(0)
            || e.validAfter != a.validAfter || e.validUntil != a.validUntil || e.valueLimit != 0
            || e.feeLimit != maxTotalFee || e.deviceEpoch != 1 || e.recoveryEpoch != 1 || e.validatorEpoch != 1
            || e.deviceSignatureSuiteId != SIGNATURE_SUITE_ID || e.proofDescriptorHash != bytes32(0)
            || e.humanPresentationHash != presentationHash) revert PhilStep6CBindingMismatch();
    }

    function _validateCore(
        PhilStep6CCoreV1 memory c,
        PhilStep6CAccountActionV1 memory a,
        bytes32 actionHash,
        bytes32 envelopeDigest,
        bytes32 presentationHash
    ) internal view {
        if (c.formatVersionHash != ROUTINE_AUTHORIZATION_CORE_V1
            || c.protocolContextHash != ROUTINE_AUTHORIZATION_TRANSPORT_V1 || c.sessionId == bytes32(0)
            || c.nonceSeed == bytes32(0) || c.issuedAt != a.validAfter || c.expiresAt != a.validUntil
            || c.expiresAt != c.issuedAt + 120 || c.executionEnvironmentHash != executionEnvironmentHash
            || c.adapterManifestHash != adapterManifestHash || c.signatureRegistryHash != signatureRegistryHash
            || c.deviceEnrollmentHash != deviceEnrollmentHash || c.accountConfigurationHash != accountConfigurationHash
            || c.catalogHash != catalogHash || c.capabilityPolicyHash != capabilityPolicyHash
            || c.actionHash != actionHash || c.targetCalldataHash != a.targetCalldataHash
            || c.authorizationEnvelopeDigest != envelopeDigest || c.rootProofNullifier != bytes32(0)
            || c.humanPresentationHash != presentationHash) revert PhilStep6CBindingMismatch();
    }

    function _actionHash(PhilStep6CAccountActionV1 memory a, uint256 maxTotalFee) internal view returns (bytes32) {
        bytes32 accountCallCommitment = keccak256(abi.encode(EVM_SINGLE_CALL_V1, a.target, a.valueWei, a.targetCalldataHash));
        uint256 packedNonce = (uint256(a.nonceKey) << 64) | uint256(a.nonceSequence);
        return keccak256(abi.encode(
            EVM_SINGLE_CALL_V1, block.chainid, address(this), entryPoint, a.target, a.targetCalldataHash,
            accountCallCommitment, a.valueWei, a.nonceKey, a.nonceSequence, packedNonce, a.callGasLimit,
            a.verificationGasLimit, a.preVerificationGas, a.maxFeePerGas, a.maxPriorityFeePerGas,
            maxTotalFee, bytes32(0), bytes32(0), a.validAfter, a.validUntil
        ));
    }

    function _maximumTotalFee(PhilStep6CAccountActionV1 memory a) internal pure returns (uint256) {
        uint256 gasTotal = uint256(a.callGasLimit) + uint256(a.verificationGasLimit);
        if (type(uint256).max - gasTotal < a.preVerificationGas) revert PhilStep6CFeeOverflow();
        gasTotal += a.preVerificationGas;
        if (a.maxFeePerGas != 0 && gasTotal > type(uint256).max / uint256(a.maxFeePerGas)) {
            revert PhilStep6CFeeOverflow();
        }
        return gasTotal * uint256(a.maxFeePerGas);
    }

    function _validateTargetCalldata(bytes memory targetCalldata) internal pure returns (bytes32 summaryHash) {
        if (targetCalldata.length != 68) revert PhilStep6CMalformedCallData();
        bytes4 selector;
        bytes32 value;
        uint256 shouldRevertWord;
        assembly ("memory-safe") {
            selector := mload(add(targetCalldata, 32))
            value := mload(add(targetCalldata, 36))
            shouldRevertWord := mload(add(targetCalldata, 68))
        }
        if (selector != RECORD_SELECTOR || value != RECORDED_VALUE || shouldRevertWord > 1
            || keccak256(targetCalldata) != keccak256(abi.encodeWithSelector(RECORD_SELECTOR, value, shouldRevertWord == 1))) {
            revert PhilStep6CMalformedCallData();
        }
        return shouldRevertWord == 1 ? FAILURE_SUMMARY_HASH : SUCCESS_SUMMARY_HASH;
    }

    function _presentationHash(PhilStep6CPresentationV1 memory p) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            p.formatVersionHash,p.applicationId,p.applicationNameHash,p.principalIdHash,p.scopeId,p.scopeInstance,
            p.scopeEpoch,p.executionEnvironmentHash,p.networkLabelHash,p.account,p.accountLabelHash,p.target,
            p.targetRuntimeCodeHash,p.targetLabelHash,p.actionTypeHash,p.actionLabelHash,p.parametersHash,
            p.parameterSummaryHash,p.valueWei,p.maximumTotalFeeWei,p.validAfter,p.validUntil,p.capabilityId,
            p.capabilityEpoch,p.policyHash,p.policyEpoch,p.externalNetwork,p.productionAuthority,p.meaningfulAssets
        ));
    }

    function _envelopeDigest(PhilStep6CEnvelopeV1 memory e) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            e.formatVersionHash,e.operationClass,e.scopedOwnerCommitment,e.scopeId,e.scopeInstance,e.scopeEpoch,
            e.principalIdHash,e.capabilityId,e.capabilityEpoch,e.networkIdHash,e.accountBindingHash,e.adapterId,
            e.actionTypeHash,e.parametersHash,e.intentDigest,e.policyHash,e.nonceDomain,e.nonce,e.validAfter,e.validUntil,
            e.valueLimit,e.feeLimit,e.deviceEpoch,e.recoveryEpoch,e.validatorEpoch,e.deviceSignatureSuiteId,
            e.proofDescriptorHash,e.humanPresentationHash
        ));
    }

    function _coreDigest(PhilStep6CCoreV1 memory c) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            c.formatVersionHash,c.protocolContextHash,c.sessionId,c.nonceSeed,c.issuedAt,c.expiresAt,
            c.executionEnvironmentHash,c.adapterManifestHash,c.signatureRegistryHash,c.deviceEnrollmentHash,
            c.accountConfigurationHash,c.catalogHash,c.capabilityPolicyHash,c.actionHash,c.targetCalldataHash,
            c.authorizationEnvelopeDigest,c.rootProofNullifier,c.humanPresentationHash
        ));
    }

    function _catalogEntryHash(uint8 kind, bytes32 entryId, bytes32 textHash, bytes32 boundValueHash)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(ROUTINE_CATALOG_ENTRY_V1, kind, entryId, textHash, boundValueHash));
    }

    function _decodeExecuteCall(bytes calldata callData) internal pure returns (
        PhilStep6CAccountActionV1 memory action,
        PhilStep6CEnvelopeV1 memory envelope,
        PhilStep6CApprovalV1 memory approval,
        PhilStep6CPresentationV1 memory presentation,
        PhilStep6CCoreV1 memory core,
        bytes memory targetCalldata
    ) {
        if (callData.length < 4 || bytes4(callData[:4]) != this.executeAuthorized.selector) {
            revert PhilStep6CMalformedCallData();
        }
        return abi.decode(callData[4:], (
            PhilStep6CAccountActionV1,PhilStep6CEnvelopeV1,PhilStep6CApprovalV1,
            PhilStep6CPresentationV1,PhilStep6CCoreV1,bytes
        ));
    }

    function _requireEntryPoint() internal view {
        if (msg.sender != entryPoint) revert PhilStep6COnlyEntryPoint();
    }
}
