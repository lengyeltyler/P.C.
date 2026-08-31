// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;

struct PhilCoreV2VerifierRequestV1 {
    uint8 actionType;
    address account;
    uint256 chainId;
    address entryPoint;
    bytes32 accountVersionId;
    bytes32 securityModelId;
    bytes32 authorizedIntentHash;
    bytes32 userOpHash;
    address validator;
    bytes32 validatorKeyIdBinding;
    uint64 validatorEpoch;
    uint64 recoveryEpoch;
    bytes32 recoveryConfigHash;
    bytes32 requestId;
    uint48 validAfter;
    uint48 validUntil;
    bytes32 proposedValidatorCommitment;
    bytes32 proposedRecoveryConfigHash;
    uint64 proposedRecoveryEpoch;
    bytes32 primaryDeviceCommitment;
    bytes32 hardwareSecurityKeyCommitment;
    bytes32 recoveryFactorCommitment;
}

interface IPhilCoreV2StaticAuthorityVerifier {
    function verifyAuthority(
        PhilCoreV2VerifierRequestV1 calldata request,
        bytes calldata authorityEnvelope
    ) external view returns (bytes4);
}
