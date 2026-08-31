// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {
    PhilCoreV2AccountInitializationV1
} from "./IPhilCoreV2MinimalAccountV2.sol";
import {
    IPhilCoreV2FactoryVerifierBinding,
    PhilCoreV2MinimalAccountV2
} from "./PhilCoreV2MinimalAccountV2.sol";

contract PhilCoreV2MinimalAccountFactoryV2 is
    IPhilCoreV2FactoryVerifierBinding
{
    bytes32 private constant ACCOUNT_VERSION_ID =
        0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f;
    bytes32 private constant SECURITY_MODEL_ID =
        keccak256("philcore-v2-typed-intent-local-proof-gated-v1");
    bytes32 private constant CREATE2_SALT_DOMAIN =
        keccak256("PHILCORE_V2_CREATE2_SALT_V1");
    bytes32 private constant IDENTITY_BINDING_TYPEHASH =
        0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8;
    bytes32 private constant OWNER_COMMITMENT_SCHEME_ID =
        0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e;
    bytes32 private constant VALIDATOR_COMMITMENT_TYPEHASH = keccak256(
        "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
    );
    bytes32 private constant RECOVERY_CONFIGURATION_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
    );

    IEntryPoint private immutable _entryPoint;
    uint256 private immutable _deploymentChainId;
    address private immutable _confirmationTarget;
    address private immutable _verifier;
    bytes32 private immutable _verifierRuntimeCodeHash;

    error InvalidFactoryConfiguration(uint8 reason);
    error InvalidAccountInitialization(uint8 reason);
    error AccountAlreadyDeployed();
    error AccountDeploymentFailed();

    event AccountCreated(
        address indexed account,
        bytes32 indexed deploymentSalt,
        bytes32 indexed ownerCommitment
    );

    constructor(
        IEntryPoint entryPoint_,
        uint256 deploymentChainId_,
        address confirmationTarget_,
        address verifier_,
        bytes32 verifierRuntimeCodeHash_
    ) {
        if (
            address(entryPoint_) == address(0)
                || confirmationTarget_ == address(0)
                || verifier_ == address(0)
                || verifierRuntimeCodeHash_ == bytes32(0)
                || deploymentChainId_ != block.chainid
        ) revert InvalidFactoryConfiguration(1);
        if (verifier_.codehash != verifierRuntimeCodeHash_) {
            revert InvalidFactoryConfiguration(2);
        }
        _entryPoint = entryPoint_;
        _deploymentChainId = deploymentChainId_;
        _confirmationTarget = confirmationTarget_;
        _verifier = verifier_;
        _verifierRuntimeCodeHash = verifierRuntimeCodeHash_;
    }

    function verifierBinding()
        external
        view
        override
        returns (address verifier, bytes32 verifierRuntimeCodeHash)
    {
        return (_verifier, _verifierRuntimeCodeHash);
    }

    function createAccount(
        PhilCoreV2AccountInitializationV1 calldata initialization,
        bytes32 userSalt
    ) external returns (address account) {
        _validateInitialization(initialization, userSalt);
        bytes32 salt = deploymentSalt(initialization, userSalt);
        address predicted = getAddress(initialization, userSalt);
        if (predicted.code.length != 0) revert AccountAlreadyDeployed();
        try new PhilCoreV2MinimalAccountV2{salt: salt}(initialization) returns (
            PhilCoreV2MinimalAccountV2 deployed
        ) {
            account = address(deployed);
        } catch {
            revert AccountDeploymentFailed();
        }
        if (account != predicted) revert AccountDeploymentFailed();
        emit AccountCreated(account, salt, initialization.ownerCommitment);
    }

    function getAddress(
        PhilCoreV2AccountInitializationV1 calldata initialization,
        bytes32 userSalt
    ) public view returns (address) {
        bytes32 salt = deploymentSalt(initialization, userSalt);
        bytes32 initCodeHash = accountCreationCodeHash(initialization);
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt,
                            initCodeHash
                        )
                    )
                )
            )
        );
    }

    function deploymentSalt(
        PhilCoreV2AccountInitializationV1 calldata initialization,
        bytes32 userSalt
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CREATE2_SALT_DOMAIN,
                initialization.deploymentChainId,
                ACCOUNT_VERSION_ID,
                SECURITY_MODEL_ID,
                initialization.ownerCommitment,
                initialization.identityBindingCommitment,
                userSalt
            )
        );
    }

    function accountCreationCodeHash(
        PhilCoreV2AccountInitializationV1 calldata initialization
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                type(PhilCoreV2MinimalAccountV2).creationCode,
                abi.encode(initialization)
            )
        );
    }

    function _validateInitialization(
        PhilCoreV2AccountInitializationV1 calldata initialization,
        bytes32 userSalt
    ) private view {
        if (
            userSalt == bytes32(0)
                || initialization.entryPoint != _entryPoint
                || initialization.deploymentChainId != _deploymentChainId
                || initialization.factoryBinding != address(this)
                || initialization.confirmationTarget != _confirmationTarget
        ) revert InvalidAccountInitialization(1);
        if (
            initialization.accountVersionId != ACCOUNT_VERSION_ID
                || initialization.securityModelId != SECURITY_MODEL_ID
                || initialization.ownerCommitment == bytes32(0)
                || initialization.initialValidator == address(0)
                || initialization.validatorVerifierKind != 1
                || initialization.validatorKeyIdBinding == bytes32(0)
                || initialization.validatorEpoch != 1
                || initialization.recoveryEpoch != 1
                || initialization.recoveryDelaySeconds != 172800
                || initialization.recoveryExpirySeconds != 604800
        ) revert InvalidAccountInitialization(2);
        if (
            initialization.identityBindingCommitment
                != keccak256(
                    abi.encode(
                        IDENTITY_BINDING_TYPEHASH,
                        uint8(1),
                        initialization.ownerCommitment,
                        OWNER_COMMITMENT_SCHEME_ID
                    )
                )
                || initialization.validatorCommitment
                    != keccak256(
                        abi.encode(
                            VALIDATOR_COMMITMENT_TYPEHASH,
                            uint8(1),
                            initialization.initialValidator,
                            initialization.validatorKeyIdBinding
                        )
                    )
        ) revert InvalidAccountInitialization(3);
        bytes32 primary =
            initialization.primaryDeviceRecoveryCommitment;
        bytes32 hardware = initialization.hardwareSecurityKeyCommitment;
        bytes32 independent =
            initialization.independentRecoveryFactorCommitment;
        if (
            primary == bytes32(0) || hardware == bytes32(0)
                || independent == bytes32(0) || primary == hardware
                || primary == independent || hardware == independent
                || initialization.recoveryConfigurationHash
                    != keccak256(
                        abi.encode(
                            RECOVERY_CONFIGURATION_TYPEHASH,
                            uint8(3),
                            uint8(2),
                            primary,
                            hardware,
                            independent
                        )
                    )
        ) revert InvalidAccountInitialization(4);
    }
}
