// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {
    IPhilCoreV2StaticAuthorityVerifier,
    PhilCoreV2VerifierRequestV1
} from "./IPhilCoreV2StaticAuthorityVerifier.sol";

struct ValidatorAuthorityEnvelopeV1 {
    uint8 envelopeVersion;
    uint8 authorityKind;
    uint8 verifierKind;
    address validator;
    bytes32 validatorKeyIdBinding;
    uint64 validatorEpoch;
    uint64 recoveryEpoch;
    bytes32 r;
    bytes32 s;
    uint8 v;
}

struct RecoveryFactorDescriptorV2 {
    uint8 descriptorVersion;
    bytes32 accountVersionId;
    bytes32 securityModelId;
    bytes32 recoveryDomainId;
    uint8 role;
    uint8 verifierKind;
    bytes32 publicVerificationMaterialHash;
    bytes32 credentialIdHash;
    bytes32 rpIdHash;
    bytes32 originPolicyHash;
    bytes32 independenceBindingHash;
    uint8 userVerificationPolicy;
    uint8 backupPolicy;
    uint8 authenticatorAttachmentPolicy;
    uint8 attestationPolicy;
    uint64 credentialGeneration;
}

struct RecoveryEvidenceContextV2 {
    uint8 envelopeVersion;
    uint8 authorityKind;
    uint8 actionType;
    uint8 factorBitmap;
    address account;
    uint256 chainId;
    address entryPoint;
    bytes32 authorizedIntentHash;
    bytes32 userOpHash;
    bytes32 requestId;
    bytes32 currentRecoveryConfigHash;
    uint64 validatorEpoch;
    uint64 recoveryEpoch;
    uint48 validAfter;
    uint48 validUntil;
    uint64 recoveryDelaySeconds;
    uint64 recoveryExpirySeconds;
    bytes32 proposedValidatorCommitment;
    bytes32 proposedRecoveryConfigHash;
    uint64 proposedRecoveryEpoch;
    bytes32 primaryDeviceCommitment;
    bytes32 hardwareSecurityKeyCommitment;
    bytes32 recoveryFactorCommitment;
    bytes32 firstFactorCommitment;
    bytes32 secondFactorCommitment;
}

struct WebAuthnFactorEvidenceV2 {
    RecoveryFactorDescriptorV2 descriptor;
    bytes32 factorCommitment;
    bytes32 qx;
    bytes32 qy;
    bytes32 r;
    bytes32 s;
    uint256 challengeIndex;
    uint256 typeIndex;
    bytes authenticatorData;
    string clientDataJSON;
}

struct Secp256k1FactorEvidenceV2 {
    RecoveryFactorDescriptorV2 descriptor;
    bytes32 factorCommitment;
    address signer;
    bytes32 r;
    bytes32 s;
    uint8 v;
}

struct NativeDeviceP256DescriptorV1 {
    uint8 descriptorVersion;
    bytes32 accountVersionId;
    bytes32 securityModelId;
    bytes32 recoveryDomainId;
    uint8 role;
    uint8 verifierKind;
    bytes32 publicVerificationMaterialHash;
    bytes32 credentialIdentifierCommitment;
    bytes32 applicationIdentityHash;
    bytes32 deviceCustodyCommitment;
    bytes32 localApprovalPolicyHash;
    bytes32 appAttestCommitment;
    uint64 credentialGeneration;
    bool secureEnclaveRequired;
    bool simulatorCredential;
}

struct NativeDeviceP256FactorEvidenceV1 {
    NativeDeviceP256DescriptorV1 descriptor;
    bytes32 factorCommitment;
    bytes32 qx;
    bytes32 qy;
    bytes32 r;
    bytes32 s;
}

struct RecoveryAuthorityEnvelopeV2 {
    RecoveryEvidenceContextV2 context;
    bytes firstFactorEvidence;
    bytes secondFactorEvidence;
}

contract PhilCoreV2StaticAuthorityVerifier is
    IPhilCoreV2StaticAuthorityVerifier
{
    bytes32 public constant VERIFIER_VERSION_ID = keccak256(
        "philcore-v2-native-iphone-recovery-static-authority-verifier-v3"
    );
    bytes4 public constant SUCCESS_MAGIC =
        bytes4(keccak256("PHILCORE_V2_STATIC_AUTHORITY_VERIFIER_V1_SUCCESS"));

    uint8 private constant VALIDATOR_ENVELOPE_VERSION = 1;
    uint8 private constant VALIDATOR_AUTHORITY_KIND = 1;
    uint8 private constant VALIDATOR_VERIFIER_KIND = 1;
    uint8 private constant RECOVERY_ENVELOPE_VERSION = 2;
    uint8 private constant RECOVERY_AUTHORITY_KIND = 2;
    uint8 private constant RECOVERY_DESCRIPTOR_VERSION = 3;
    uint8 private constant RECOVERY_CONFIGURATION_VERSION = 3;
    uint8 private constant RECOVERY_THRESHOLD = 2;
    uint64 private constant RECOVERY_DELAY_SECONDS = 172800;
    uint64 private constant RECOVERY_EXPIRY_SECONDS = 604800;

    uint256 private constant VALIDATOR_ENVELOPE_LENGTH = 320;
    uint256 private constant WEBAUTHN_EVIDENCE_MIN_LENGTH = 992;
    uint256 private constant WEBAUTHN_EVIDENCE_MAX_LENGTH = 3968;
    uint256 private constant SECP256K1_EVIDENCE_LENGTH = 672;
    uint256 private constant NATIVE_P256_EVIDENCE_LENGTH = 640;
    uint256 private constant RECOVERY_ENVELOPE_MIN_LENGTH = 2272;
    uint256 private constant RECOVERY_ENVELOPE_MAX_LENGTH = 8896;
    uint256 private constant COMBINED_ENVELOPE_MIN_LENGTH = 2816;
    uint256 private constant COMBINED_ENVELOPE_MAX_LENGTH = 9440;

    bytes32 private constant RECOVERY_DOMAIN_ID =
        keccak256("PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V3");
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant EIP712_NAME_HASH =
        keccak256("PhilCore V2 Account");
    bytes32 private constant EIP712_VERSION_HASH = keccak256("1");
    bytes32 private constant VALIDATOR_AUTHORIZATION_TYPEHASH = keccak256(
        "PhilCoreV2Authorization(bytes32 authorizedIntentHash,bytes32 userOpHash,address validator,bytes32 validatorKeyIdBinding,uint64 validatorEpoch,uint64 recoveryEpoch)"
    );
    bytes32 private constant RECOVERY_AUTHORIZATION_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryAuthorization(bytes32 authorizedIntentHash,bytes32 userOpHash,bytes32 recoveryConfigHash,uint64 recoveryEpoch,uint8 factorBitmap)"
    );
    bytes32 private constant CONFIG_ROTATION_AUTHORIZATION_TYPEHASH = keccak256(
        "PhilCoreV2ConfigRotationAuthorization(bytes32 authorizedIntentHash,bytes32 userOpHash,address validator,uint64 validatorEpoch,bytes32 recoveryConfigHash,uint64 recoveryEpoch,bytes32 proposedRecoveryConfigHash,uint64 proposedRecoveryEpoch,uint8 factorBitmap)"
    );
    bytes32 private constant RECOVERY_CONFIGURATION_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
    );
    bytes32 private constant FACTOR_DESCRIPTOR_TYPEHASH = keccak256(
        "PhilCoreV2RecoveryFactorDescriptorV3(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdHash,bytes32 rpIdHash,bytes32 originPolicyHash,bytes32 independenceBindingHash,uint8 userVerificationPolicy,uint8 backupPolicy,uint8 authenticatorAttachmentPolicy,uint8 attestationPolicy,uint64 credentialGeneration)"
    );
    bytes32 private constant WEBAUTHN_PUBLIC_MATERIAL_TYPEHASH = keccak256(
        "PhilCoreV2WebAuthnPublicMaterial(bytes32 qx,bytes32 qy)"
    );
    bytes32 private constant SECP256K1_PUBLIC_MATERIAL_TYPEHASH = keccak256(
        "PhilCoreV2Secp256k1PublicMaterial(address signer)"
    );
    bytes32 private constant NATIVE_P256_RECOVERY_DOMAIN_ID =
        keccak256("PHILCORE_NATIVE_DEVICE_P256_ROLE1_V1");
    bytes32 private constant NATIVE_P256_PUBLIC_MATERIAL_TYPEHASH = keccak256(
        "PhilCoreV2NativeDeviceP256PublicMaterial(bytes32 qx,bytes32 qy)"
    );
    bytes32 private constant NATIVE_P256_DESCRIPTOR_TYPEHASH = keccak256(
        "PhilCoreV2NativeDeviceP256DescriptorV1(uint8 descriptorVersion,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,bytes32 publicVerificationMaterialHash,bytes32 credentialIdentifierCommitment,bytes32 applicationIdentityHash,bytes32 deviceCustodyCommitment,bytes32 localApprovalPolicyHash,bytes32 appAttestCommitment,uint64 credentialGeneration,bool secureEnclaveRequired,bool simulatorCredential)"
    );
    bytes32 private constant NATIVE_APPLICATION_IDENTITY_HASH =
        0x473ae62bc3a5d82179f761c917682fe2c606befedd5b08d9abb55e4670f02111;
    bytes32 private constant NATIVE_LOCAL_APPROVAL_POLICY_HASH =
        0x8678ec5d37841e2cde6cfb76a0caa012b4e6a36e803895f317b9ee5874450c86;

    error CallerAccountMismatch();
    error VerificationRequestInvalid();
    error UnsupportedAction();
    error AuthorityEnvelopeMalformed();
    error AuthorityEnvelopeNonCanonical();
    error AuthorityEnvelopeHeaderInvalid();
    error ValidatorAuthorityInvalid();
    error RecoveryContextInvalid();
    error RecoveryFactorBitmapInvalid();
    error RecoveryFactorOrderInvalid();
    error RecoveryFactorCommitmentInvalid();
    error RecoveryFactorEvidenceInvalid();
    error RecoveryFactorSignatureInvalid();

    function verifyAuthority(
        PhilCoreV2VerifierRequestV1 calldata request,
        bytes calldata authorityEnvelope
    ) external view returns (bytes4) {
        _verifyRequest(request);
        if (_isValidatorAction(request.actionType)) {
            _verifyValidatorEnvelope(
                authorityEnvelope,
                _validatorDigest(request),
                request
            );
        } else if (_isRecoveryAction(request.actionType)) {
            _verifyRecoveryEnvelope(authorityEnvelope, request);
        } else if (request.actionType == 10) {
            (
                bytes memory validatorEvidence,
                bytes memory recoveryEvidence
            ) = _decodeCombinedEnvelope(authorityEnvelope);
            RecoveryEvidenceContextV2 memory context =
                _verifyRecoveryEnvelope(recoveryEvidence, request);
            _verifyValidatorEnvelope(
                validatorEvidence,
                _configRotationValidatorDigest(request, context.factorBitmap),
                request
            );
        } else {
            revert UnsupportedAction();
        }
        return SUCCESS_MAGIC;
    }

    function _verifyRequest(
        PhilCoreV2VerifierRequestV1 calldata request
    ) private view {
        if (request.account != msg.sender) revert CallerAccountMismatch();
        if (
            request.account == address(0)
                || request.chainId == 0
                || request.entryPoint == address(0)
                || request.accountVersionId == bytes32(0)
                || request.securityModelId == bytes32(0)
                || request.authorizedIntentHash == bytes32(0)
                || request.userOpHash == bytes32(0)
                || request.validator == address(0)
                || request.validatorKeyIdBinding == bytes32(0)
                || request.validatorEpoch == 0
                || request.recoveryEpoch == 0
        ) {
            revert VerificationRequestInvalid();
        }
    }

    function _isValidatorAction(uint8 actionType) private pure returns (bool) {
        return actionType == 1 || actionType == 2 || actionType == 6
            || actionType == 7;
    }

    function _isRecoveryAction(uint8 actionType) private pure returns (bool) {
        return actionType == 8 || actionType == 9 || actionType == 11;
    }

    function _domainSeparator(
        uint256 chainId,
        address account
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                EIP712_NAME_HASH,
                EIP712_VERSION_HASH,
                chainId,
                account
            )
        );
    }

    function _typedDigest(
        uint256 chainId,
        address account,
        bytes32 structHash
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator(chainId, account),
                structHash
            )
        );
    }

    function _validatorDigest(
        PhilCoreV2VerifierRequestV1 calldata request
    ) private pure returns (bytes32) {
        return _typedDigest(
            request.chainId,
            request.account,
            keccak256(
                abi.encode(
                    VALIDATOR_AUTHORIZATION_TYPEHASH,
                    request.authorizedIntentHash,
                    request.userOpHash,
                    request.validator,
                    request.validatorKeyIdBinding,
                    request.validatorEpoch,
                    request.recoveryEpoch
                )
            )
        );
    }

    function _recoveryDigest(
        PhilCoreV2VerifierRequestV1 calldata request,
        uint8 factorBitmap
    ) private pure returns (bytes32) {
        return _typedDigest(
            request.chainId,
            request.account,
            keccak256(
                abi.encode(
                    RECOVERY_AUTHORIZATION_TYPEHASH,
                    request.authorizedIntentHash,
                    request.userOpHash,
                    request.recoveryConfigHash,
                    request.recoveryEpoch,
                    factorBitmap
                )
            )
        );
    }

    function _configRotationValidatorDigest(
        PhilCoreV2VerifierRequestV1 calldata request,
        uint8 factorBitmap
    ) private pure returns (bytes32) {
        return _typedDigest(
            request.chainId,
            request.account,
            keccak256(
                abi.encode(
                    CONFIG_ROTATION_AUTHORIZATION_TYPEHASH,
                    request.authorizedIntentHash,
                    request.userOpHash,
                    request.validator,
                    request.validatorEpoch,
                    request.recoveryConfigHash,
                    request.recoveryEpoch,
                    request.proposedRecoveryConfigHash,
                    request.proposedRecoveryEpoch,
                    factorBitmap
                )
            )
        );
    }

    function _verifyValidatorEnvelope(
        bytes memory encoded,
        bytes32 digest,
        PhilCoreV2VerifierRequestV1 calldata request
    ) private pure {
        if (encoded.length != VALIDATOR_ENVELOPE_LENGTH) {
            revert AuthorityEnvelopeMalformed();
        }
        ValidatorAuthorityEnvelopeV1 memory envelope =
            abi.decode(encoded, (ValidatorAuthorityEnvelopeV1));
        if (keccak256(encoded) != keccak256(abi.encode(envelope))) {
            revert AuthorityEnvelopeNonCanonical();
        }
        if (
            envelope.envelopeVersion != VALIDATOR_ENVELOPE_VERSION
                || envelope.authorityKind != VALIDATOR_AUTHORITY_KIND
                || envelope.verifierKind != VALIDATOR_VERIFIER_KIND
                || envelope.validator != request.validator
                || envelope.validatorKeyIdBinding
                    != request.validatorKeyIdBinding
                || envelope.validatorEpoch != request.validatorEpoch
                || envelope.recoveryEpoch != request.recoveryEpoch
        ) {
            revert AuthorityEnvelopeHeaderInvalid();
        }
        (address recovered, ECDSA.RecoverError recoverError,) =
            ECDSA.tryRecover(digest, envelope.v, envelope.r, envelope.s);
        if (
            recoverError != ECDSA.RecoverError.NoError
                || recovered != request.validator
        ) {
            revert ValidatorAuthorityInvalid();
        }
    }

    function _decodeCombinedEnvelope(
        bytes memory encoded
    )
        private
        pure
        returns (bytes memory validatorEvidence, bytes memory recoveryEvidence)
    {
        if (
            encoded.length < COMBINED_ENVELOPE_MIN_LENGTH
                || encoded.length > COMBINED_ENVELOPE_MAX_LENGTH
        ) {
            revert AuthorityEnvelopeMalformed();
        }
        uint8 version;
        uint8 kind;
        uint8 action;
        (version, kind, action, validatorEvidence, recoveryEvidence) =
            abi.decode(encoded, (uint8, uint8, uint8, bytes, bytes));
        if (
            keccak256(encoded)
                != keccak256(
                    abi.encode(
                        version,
                        kind,
                        action,
                        validatorEvidence,
                        recoveryEvidence
                    )
                )
        ) {
            revert AuthorityEnvelopeNonCanonical();
        }
        if (version != 1 || kind != 3 || action != 10) {
            revert AuthorityEnvelopeHeaderInvalid();
        }
    }

    function _verifyRecoveryEnvelope(
        bytes memory encoded,
        PhilCoreV2VerifierRequestV1 calldata request
    ) private view returns (RecoveryEvidenceContextV2 memory context) {
        if (
            encoded.length < RECOVERY_ENVELOPE_MIN_LENGTH
                || encoded.length > RECOVERY_ENVELOPE_MAX_LENGTH
        ) {
            revert AuthorityEnvelopeMalformed();
        }
        RecoveryAuthorityEnvelopeV2 memory envelope =
            abi.decode(encoded, (RecoveryAuthorityEnvelopeV2));
        if (keccak256(encoded) != keccak256(abi.encode(envelope))) {
            revert AuthorityEnvelopeNonCanonical();
        }
        context = envelope.context;
        _verifyRecoveryContext(context, request);
        bytes32 digest = _recoveryDigest(request, context.factorBitmap);
        (uint8 firstRole, uint8 secondRole) =
            _factorRoles(context.factorBitmap);
        _verifyFactorEvidence(
            envelope.firstFactorEvidence,
            firstRole,
            context.firstFactorCommitment,
            digest,
            request.accountVersionId,
            request.securityModelId
        );
        _verifyFactorEvidence(
            envelope.secondFactorEvidence,
            secondRole,
            context.secondFactorCommitment,
            digest,
            request.accountVersionId,
            request.securityModelId
        );
        if (
            keccak256(envelope.firstFactorEvidence)
                == keccak256(envelope.secondFactorEvidence)
        ) {
            revert RecoveryFactorEvidenceInvalid();
        }
    }

    function _factorRoles(
        uint8 bitmap
    ) private pure returns (uint8 firstRole, uint8 secondRole) {
        if (bitmap == 3) return (0, 1);
        if (bitmap == 5) return (0, 2);
        if (bitmap == 6) return (1, 2);
        revert RecoveryFactorBitmapInvalid();
    }

    function _verifyRecoveryContext(
        RecoveryEvidenceContextV2 memory context,
        PhilCoreV2VerifierRequestV1 calldata request
    ) private pure {
        if (
            context.envelopeVersion != RECOVERY_ENVELOPE_VERSION
                || context.authorityKind != RECOVERY_AUTHORITY_KIND
                || context.actionType != request.actionType
                || context.account != request.account
                || context.chainId != request.chainId
                || context.entryPoint != request.entryPoint
                || context.authorizedIntentHash
                    != request.authorizedIntentHash
                || context.userOpHash != request.userOpHash
                || context.requestId != request.requestId
                || context.currentRecoveryConfigHash
                    != request.recoveryConfigHash
                || context.validatorEpoch != request.validatorEpoch
                || context.recoveryEpoch != request.recoveryEpoch
                || context.validAfter != request.validAfter
                || context.validUntil != request.validUntil
                || context.recoveryDelaySeconds != RECOVERY_DELAY_SECONDS
                || context.recoveryExpirySeconds != RECOVERY_EXPIRY_SECONDS
                || context.proposedValidatorCommitment
                    != request.proposedValidatorCommitment
                || context.proposedRecoveryConfigHash
                    != request.proposedRecoveryConfigHash
                || context.proposedRecoveryEpoch
                    != request.proposedRecoveryEpoch
                || context.primaryDeviceCommitment
                    != request.primaryDeviceCommitment
                || context.hardwareSecurityKeyCommitment
                    != request.hardwareSecurityKeyCommitment
                || context.recoveryFactorCommitment
                    != request.recoveryFactorCommitment
                || context.validUntil <= context.validAfter
                || context.proposedRecoveryEpoch != context.recoveryEpoch + 1
        ) {
            revert RecoveryContextInvalid();
        }
        if (
            context.primaryDeviceCommitment == bytes32(0)
                || context.hardwareSecurityKeyCommitment == bytes32(0)
                || context.recoveryFactorCommitment == bytes32(0)
                || context.primaryDeviceCommitment
                    == context.hardwareSecurityKeyCommitment
                || context.primaryDeviceCommitment
                    == context.recoveryFactorCommitment
                || context.hardwareSecurityKeyCommitment
                    == context.recoveryFactorCommitment
                || _recoveryConfigurationHash(context)
                    != context.currentRecoveryConfigHash
        ) {
            revert RecoveryContextInvalid();
        }
        _verifyActionContext(context);
        (uint8 firstRole, uint8 secondRole) =
            _factorRoles(context.factorBitmap);
        bytes32[3] memory commitments = [
            context.primaryDeviceCommitment,
            context.hardwareSecurityKeyCommitment,
            context.recoveryFactorCommitment
        ];
        if (
            context.firstFactorCommitment != commitments[firstRole]
                || context.secondFactorCommitment != commitments[secondRole]
                || context.firstFactorCommitment
                    == context.secondFactorCommitment
        ) {
            revert RecoveryFactorOrderInvalid();
        }
    }

    function _verifyActionContext(
        RecoveryEvidenceContextV2 memory context
    ) private pure {
        bool validatorRecovery =
            context.actionType == 8 || context.actionType == 9;
        if (
            validatorRecovery
                && (
                    context.proposedValidatorCommitment == bytes32(0)
                        || context.proposedRecoveryConfigHash != bytes32(0)
                )
        ) {
            revert RecoveryContextInvalid();
        }
        if (
            !validatorRecovery
                && (
                    context.proposedValidatorCommitment != bytes32(0)
                        || context.proposedRecoveryConfigHash == bytes32(0)
                )
        ) {
            revert RecoveryContextInvalid();
        }
        bool requestAction =
            context.actionType == 8 || context.actionType == 10;
        if (
            requestAction
                && context.requestId != context.authorizedIntentHash
        ) {
            revert RecoveryContextInvalid();
        }
    }

    function _recoveryConfigurationHash(
        RecoveryEvidenceContextV2 memory context
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                RECOVERY_CONFIGURATION_TYPEHASH,
                RECOVERY_CONFIGURATION_VERSION,
                RECOVERY_THRESHOLD,
                context.primaryDeviceCommitment,
                context.hardwareSecurityKeyCommitment,
                context.recoveryFactorCommitment
            )
        );
    }

    function _verifyFactorEvidence(
        bytes memory encoded,
        uint8 expectedRole,
        bytes32 expectedCommitment,
        bytes32 digest,
        bytes32 accountVersionId,
        bytes32 securityModelId
    ) private view {
        if (
            expectedRole == 1
                && encoded.length == NATIVE_P256_EVIDENCE_LENGTH
        ) {
            NativeDeviceP256FactorEvidenceV1 memory nativeEvidence =
                abi.decode(encoded, (NativeDeviceP256FactorEvidenceV1));
            if (
                keccak256(encoded)
                    != keccak256(abi.encode(nativeEvidence))
            ) {
                revert AuthorityEnvelopeNonCanonical();
            }
            _verifyNativeDescriptor(
                nativeEvidence.descriptor,
                nativeEvidence.factorCommitment,
                expectedCommitment,
                accountVersionId,
                securityModelId
            );
            if (
                nativeEvidence.descriptor.publicVerificationMaterialHash
                    != keccak256(
                        abi.encode(
                            NATIVE_P256_PUBLIC_MATERIAL_TYPEHASH,
                            nativeEvidence.qx,
                            nativeEvidence.qy
                        )
                    )
                    || !P256.verify(
                        digest,
                        nativeEvidence.r,
                        nativeEvidence.s,
                        nativeEvidence.qx,
                        nativeEvidence.qy
                    )
            ) {
                revert RecoveryFactorSignatureInvalid();
            }
            return;
        }
        if (expectedRole < 2) {
            if (
                encoded.length < WEBAUTHN_EVIDENCE_MIN_LENGTH
                    || encoded.length > WEBAUTHN_EVIDENCE_MAX_LENGTH
            ) {
                revert RecoveryFactorEvidenceInvalid();
            }
            WebAuthnFactorEvidenceV2 memory webAuthnEvidence =
                abi.decode(encoded, (WebAuthnFactorEvidenceV2));
            if (
                keccak256(encoded)
                    != keccak256(abi.encode(webAuthnEvidence))
            ) {
                revert AuthorityEnvelopeNonCanonical();
            }
            _verifyDescriptor(
                webAuthnEvidence.descriptor,
                expectedRole,
                webAuthnEvidence.factorCommitment,
                expectedCommitment,
                accountVersionId,
                securityModelId
            );
            if (
                webAuthnEvidence.descriptor.publicVerificationMaterialHash
                    != keccak256(
                        abi.encode(
                            WEBAUTHN_PUBLIC_MATERIAL_TYPEHASH,
                            webAuthnEvidence.qx,
                            webAuthnEvidence.qy
                        )
                    )
                    || webAuthnEvidence.authenticatorData.length < 37
                    || webAuthnEvidence.authenticatorData.length > 1024
                    || bytes(webAuthnEvidence.clientDataJSON).length == 0
                    || bytes(webAuthnEvidence.clientDataJSON).length > 2048
            ) {
                revert RecoveryFactorEvidenceInvalid();
            }
            bytes32 observedRpIdHash;
            bytes memory authenticatorData =
                webAuthnEvidence.authenticatorData;
            assembly ("memory-safe") {
                observedRpIdHash := mload(add(authenticatorData, 0x20))
            }
            uint8 flags = uint8(authenticatorData[32]);
            if (
                observedRpIdHash != webAuthnEvidence.descriptor.rpIdHash
                    || (flags & 0x01) == 0
                    || (flags & 0x04) == 0
                    || (flags & 0x18) != 0
                    || !_verifyOriginPolicy(
                        bytes(webAuthnEvidence.clientDataJSON),
                        webAuthnEvidence.descriptor.originPolicyHash
                    )
                    || !_verifyWebAuthn(digest, webAuthnEvidence)
            ) {
                revert RecoveryFactorSignatureInvalid();
            }
            return;
        }

        if (encoded.length != SECP256K1_EVIDENCE_LENGTH) {
            revert RecoveryFactorEvidenceInvalid();
        }
        Secp256k1FactorEvidenceV2 memory secp256k1Evidence =
            abi.decode(encoded, (Secp256k1FactorEvidenceV2));
        if (
            keccak256(encoded)
                != keccak256(abi.encode(secp256k1Evidence))
        ) {
            revert AuthorityEnvelopeNonCanonical();
        }
        _verifyDescriptor(
            secp256k1Evidence.descriptor,
            expectedRole,
            secp256k1Evidence.factorCommitment,
            expectedCommitment,
            accountVersionId,
            securityModelId
        );
        if (
            secp256k1Evidence.signer == address(0)
                || secp256k1Evidence.descriptor.publicVerificationMaterialHash
                    != keccak256(
                        abi.encode(
                            SECP256K1_PUBLIC_MATERIAL_TYPEHASH,
                            secp256k1Evidence.signer
                        )
                    )
        ) {
            revert RecoveryFactorEvidenceInvalid();
        }
        (address recovered, ECDSA.RecoverError recoverError,) =
            ECDSA.tryRecover(
                digest,
                secp256k1Evidence.v,
                secp256k1Evidence.r,
                secp256k1Evidence.s
            );
        if (
            recoverError != ECDSA.RecoverError.NoError
                || recovered != secp256k1Evidence.signer
        ) {
            revert RecoveryFactorSignatureInvalid();
        }
    }

    function _verifyNativeDescriptor(
        NativeDeviceP256DescriptorV1 memory descriptor,
        bytes32 suppliedCommitment,
        bytes32 expectedCommitment,
        bytes32 accountVersionId,
        bytes32 securityModelId
    ) private pure {
        if (
            descriptor.descriptorVersion != 1
                || descriptor.accountVersionId != accountVersionId
                || descriptor.securityModelId != securityModelId
                || descriptor.recoveryDomainId
                    != NATIVE_P256_RECOVERY_DOMAIN_ID
                || descriptor.role != 1
                || descriptor.verifierKind != 4
                || descriptor.publicVerificationMaterialHash == bytes32(0)
                || descriptor.credentialIdentifierCommitment == bytes32(0)
                || descriptor.applicationIdentityHash == bytes32(0)
                || descriptor.applicationIdentityHash
                    != NATIVE_APPLICATION_IDENTITY_HASH
                || descriptor.deviceCustodyCommitment == bytes32(0)
                || descriptor.localApprovalPolicyHash == bytes32(0)
                || descriptor.localApprovalPolicyHash
                    != NATIVE_LOCAL_APPROVAL_POLICY_HASH
                || descriptor.credentialGeneration == 0
                || !descriptor.secureEnclaveRequired
                || descriptor.simulatorCredential
        ) {
            revert RecoveryFactorEvidenceInvalid();
        }
        bytes32 commitment = keccak256(
            abi.encode(
                NATIVE_P256_DESCRIPTOR_TYPEHASH,
                descriptor.descriptorVersion,
                descriptor.accountVersionId,
                descriptor.securityModelId,
                descriptor.recoveryDomainId,
                descriptor.role,
                descriptor.verifierKind,
                descriptor.publicVerificationMaterialHash,
                descriptor.credentialIdentifierCommitment,
                descriptor.applicationIdentityHash,
                descriptor.deviceCustodyCommitment,
                descriptor.localApprovalPolicyHash,
                descriptor.appAttestCommitment,
                descriptor.credentialGeneration,
                descriptor.secureEnclaveRequired,
                descriptor.simulatorCredential
            )
        );
        if (
            commitment != suppliedCommitment
                || commitment != expectedCommitment
        ) {
            revert RecoveryFactorCommitmentInvalid();
        }
    }

    function _verifyOriginPolicy(
        bytes memory clientData,
        bytes32 expectedOriginHash
    ) private pure returns (bool) {
        bytes memory prefix = bytes('"origin":"');
        uint256 start = type(uint256).max;
        for (uint256 i; i + prefix.length <= clientData.length; ++i) {
            if (_matchesAt(clientData, i, prefix)) {
                if (start != type(uint256).max) return false;
                start = i + prefix.length;
            }
        }
        if (start == type(uint256).max || start >= clientData.length) {
            return false;
        }
        uint256 end = start;
        while (end < clientData.length && clientData[end] != bytes1('"')) {
            if (clientData[end] == bytes1("\\")) return false;
            ++end;
        }
        if (end == start || end == clientData.length) return false;
        bytes32 observed;
        assembly ("memory-safe") {
            observed := keccak256(add(add(clientData, 0x20), start), sub(end, start))
        }
        return observed == expectedOriginHash;
    }

    function _verifyWebAuthn(
        bytes32 challenge,
        WebAuthnFactorEvidenceV2 memory evidence
    ) private view returns (bool) {
        bytes memory clientData = bytes(evidence.clientDataJSON);
        bytes memory expectedType = bytes('"type":"webauthn.get"');
        bytes memory expectedChallenge = bytes(
            string.concat(
                '"challenge":"',
                Base64.encodeURL(abi.encodePacked(challenge)),
                '"'
            )
        );
        if (
            !_matchesAt(clientData, evidence.typeIndex, expectedType)
                || !_matchesAt(
                    clientData,
                    evidence.challengeIndex,
                    expectedChallenge
                )
        ) {
            return false;
        }
        return P256.verify(
            sha256(
                abi.encodePacked(
                    evidence.authenticatorData,
                    sha256(clientData)
                )
            ),
            evidence.r,
            evidence.s,
            evidence.qx,
            evidence.qy
        );
    }

    function _matchesAt(
        bytes memory source,
        uint256 index,
        bytes memory expected
    ) private pure returns (bool) {
        if (
            index > source.length
                || expected.length > source.length - index
        ) {
            return false;
        }
        for (uint256 i; i < expected.length; ++i) {
            if (source[index + i] != expected[i]) return false;
        }
        return true;
    }

    function _verifyDescriptor(
        RecoveryFactorDescriptorV2 memory descriptor,
        uint8 expectedRole,
        bytes32 suppliedCommitment,
        bytes32 expectedCommitment,
        bytes32 accountVersionId,
        bytes32 securityModelId
    ) private pure {
        if (
            descriptor.descriptorVersion != RECOVERY_DESCRIPTOR_VERSION
                || descriptor.accountVersionId != accountVersionId
                || descriptor.securityModelId != securityModelId
                || descriptor.recoveryDomainId != RECOVERY_DOMAIN_ID
                || descriptor.role != expectedRole
                || descriptor.credentialGeneration == 0
                || descriptor.publicVerificationMaterialHash == bytes32(0)
                || descriptor.independenceBindingHash == bytes32(0)
        ) {
            revert RecoveryFactorEvidenceInvalid();
        }
        if (expectedRole == 0) {
            if (
                descriptor.verifierKind != 1
                    || descriptor.credentialIdHash == bytes32(0)
                    || descriptor.rpIdHash == bytes32(0)
                    || descriptor.originPolicyHash == bytes32(0)
                    || descriptor.userVerificationPolicy != 2
                    || descriptor.backupPolicy != 1
                    || descriptor.authenticatorAttachmentPolicy != 1
                    || descriptor.attestationPolicy != 1
            ) {
                revert RecoveryFactorEvidenceInvalid();
            }
        } else if (expectedRole == 1) {
            if (
                descriptor.verifierKind != 1
                    || descriptor.credentialIdHash == bytes32(0)
                    || descriptor.rpIdHash == bytes32(0)
                    || descriptor.originPolicyHash == bytes32(0)
                    || descriptor.userVerificationPolicy != 2
                    || descriptor.backupPolicy != 1
                    || !(
                        (
                            descriptor.authenticatorAttachmentPolicy == 1
                                && descriptor.attestationPolicy == 1
                        )
                            || (
                                descriptor.authenticatorAttachmentPolicy == 2
                                    && descriptor.attestationPolicy == 2
                            )
                    )
            ) {
                revert RecoveryFactorEvidenceInvalid();
            }
        } else {
            if (
                descriptor.verifierKind != 2
                    || descriptor.credentialIdHash != bytes32(0)
                    || descriptor.rpIdHash != bytes32(0)
                    || descriptor.originPolicyHash != bytes32(0)
                    || descriptor.userVerificationPolicy != 0
                    || descriptor.backupPolicy != 0
                    || descriptor.authenticatorAttachmentPolicy != 0
                    || descriptor.attestationPolicy != 0
            ) {
                revert RecoveryFactorEvidenceInvalid();
            }
        }
        bytes32 commitment = keccak256(
            abi.encode(
                FACTOR_DESCRIPTOR_TYPEHASH,
                descriptor.descriptorVersion,
                descriptor.accountVersionId,
                descriptor.securityModelId,
                descriptor.recoveryDomainId,
                descriptor.role,
                descriptor.verifierKind,
                descriptor.publicVerificationMaterialHash,
                descriptor.credentialIdHash,
                descriptor.rpIdHash,
                descriptor.originPolicyHash,
                descriptor.independenceBindingHash,
                descriptor.userVerificationPolicy,
                descriptor.backupPolicy,
                descriptor.authenticatorAttachmentPolicy,
                descriptor.attestationPolicy,
                descriptor.credentialGeneration
            )
        );
        if (
            commitment != suppliedCommitment
                || commitment != expectedCommitment
        ) {
            revert RecoveryFactorCommitmentInvalid();
        }
    }
}
