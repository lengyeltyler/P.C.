import CryptoKit
import Foundation

struct RecoveryWireContext: Equatable {
    let envelopeVersion: String
    let authorityKind: String
    let actionType: String
    let factorBitmap: String
    let account: String
    let chainId: String
    let entryPoint: String
    let authorizedIntentHash: String
    let userOperationHash: String
    let requestId: String
    let currentRecoveryConfigHash: String
    let validatorEpoch: String
    let recoveryEpoch: String
    let validAfter: String
    let validUntil: String
    let recoveryDelaySeconds: String
    let recoveryExpirySeconds: String
    let proposedValidatorCommitment: String
    let proposedRecoveryConfigHash: String
    let proposedRecoveryEpoch: String
    let primaryDeviceCommitment: String
    let hardwareSecurityKeyCommitment: String
    let recoveryFactorCommitment: String
    let firstFactorCommitment: String
    let secondFactorCommitment: String
}

struct RecoveryWireDescriptor: Equatable {
    let descriptorVersion: String
    let accountVersionId: String
    let securityModelId: String
    let recoveryDomainId: String
    let role: String
    let verifierKind: String
    let publicVerificationMaterialHash: String
    let credentialIdentifierCommitment: String
    let applicationIdentityHash: String
    let deviceCustodyCommitment: String
    let localApprovalPolicyHash: String
    let appAttestCommitment: String
    let credentialGeneration: String
    let secureEnclaveRequired: Bool
    let simulatorCredential: Bool
}

struct RecoveryWirePublicKey: Equatable {
    let qx: String
    let qy: String
}

struct RecoveryWireRequest: Equatable {
    let protocolVersion: Int
    let context: RecoveryWireContext
    let claimedContextHash: String
    let claimedRecoveryFactorDigest: String
    let accountVersionId: String
    let securityModelId: String
    let nativeRecoveryDomainId: String
    let applicationIdentity: String
    let localApprovalPolicy: String
    let selectedRole1CredentialIdentifierCommitment: String
    let selectedRole1CredentialGeneration: String
    let trustedRole1Descriptor: RecoveryWireDescriptor
    let trustedRole1PublicKey: RecoveryWirePublicKey
    let sessionId: String
    let sessionChallenge: String
    let desktopEphemeralPublicKey: String
    let issuedAt: String
    let expiresAt: String
    let endpoint: String
}

struct RecoveryApprovalValidation: Equatable {
    let request: RecoveryWireRequest
    let wireBytes: Data
    let requestHash: Data
    let contextHash: Data
    let recoveryFactorDigest: Data
    let role1FactorCommitment: Data
    let actionText: String
    let networkText: String
    let transcript: Data
    let transcriptHash: Data
    let comparisonFingerprint: String
}

/// Consumer-V3 native iPhone recovery approval request codec.
///
/// Every hash here is a minimal ABI word encoding (32-byte big-endian words,
/// no dynamic tails) fed to Ethereum Keccak-256, which is exactly what the
/// TypeScript source of truth produces through `AbiCoder` for these
/// fixed-width struct encodings.
enum RecoveryCanonicalRequest {
    static let maxWireBytes = 16384
    static let transcriptLabel = "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1"
    static let transcriptLineCount = 44
    static let approvalMaxTTLMilliseconds: UInt64 = 300_000
    static let approvalClockSkewMilliseconds: UInt64 = 60_000
    static let nonWireFields = ["actionText", "networkText", "now"]
    static let completionEndpointPath = "/philcore/recovery/v1/complete"
    static let requestEndpointPath = "/philcore/recovery/v1/request"
    static let wireTopLevelFieldCount = 19
    static let contextFieldCount = 25
    static let descriptorFieldCount = 15
    static let protocolVersion = 1

    static let applicationIdentity =
        "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha"
    static let localApprovalPolicy =
        "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST"

    static let accountVersionId =
        hex32(RecoveryKeccak.keccak256(utf8: "philcore-v2-minimal-account-v3-consumer-recovery"))
    static let securityModelId =
        hex32(RecoveryKeccak.keccak256(utf8: "philcore-v2-typed-intent-local-proof-gated-v1"))
    static let nativeRecoveryDomainId =
        hex32(RecoveryKeccak.keccak256(utf8: "PHILCORE_NATIVE_DEVICE_P256_ROLE1_V1"))

    static let recoveryDelaySeconds: UInt64 = 172_800
    static let recoveryExpirySeconds: UInt64 = 604_800
    static let recoveryThreshold: UInt64 = 2
    static let consumerConfigurationVersion: UInt64 = 3
    static let legacyConfigurationVersion: UInt64 = 2

    // MARK: - Type hashes

    private static let evidenceContextTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2RecoveryEvidenceContextV2(uint8 envelopeVersion,uint8 authorityKind,"
        + "uint8 actionType,uint8 factorBitmap,address account,uint256 chainId,"
        + "address entryPoint,bytes32 authorizedIntentHash,bytes32 userOpHash,"
        + "bytes32 requestId,bytes32 currentRecoveryConfigHash,uint64 validatorEpoch,"
        + "uint64 recoveryEpoch,uint48 validAfter,uint48 validUntil,"
        + "uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds,"
        + "bytes32 proposedValidatorCommitment,bytes32 proposedRecoveryConfigHash,"
        + "uint64 proposedRecoveryEpoch,bytes32 primaryDeviceCommitment,"
        + "bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment,"
        + "bytes32 firstFactorCommitment,bytes32 secondFactorCommitment)")

    private static let legacyConfigurationTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2RecoveryConfigurationV2(uint8 configurationVersion,uint8 threshold,"
        + "bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,"
        + "bytes32 recoveryFactorCommitment)")

    private static let consumerConfigurationTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,"
        + "bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)")

    private static let recoveryAuthorizationTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2RecoveryAuthorization(bytes32 authorizedIntentHash,bytes32 userOpHash,"
        + "bytes32 recoveryConfigHash,uint64 recoveryEpoch,uint8 factorBitmap)")

    private static let eip712DomainTypehash = RecoveryKeccak.keccak256(utf8:
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

    private static let nativePublicMaterialTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2NativeDeviceP256PublicMaterial(bytes32 qx,bytes32 qy)")

    private static let nativeDescriptorTypehash = RecoveryKeccak.keccak256(utf8:
        "PhilCoreV2NativeDeviceP256DescriptorV1(uint8 descriptorVersion,bytes32 accountVersionId,"
        + "bytes32 securityModelId,bytes32 recoveryDomainId,uint8 role,uint8 verifierKind,"
        + "bytes32 publicVerificationMaterialHash,bytes32 credentialIdentifierCommitment,"
        + "bytes32 applicationIdentityHash,bytes32 deviceCustodyCommitment,"
        + "bytes32 localApprovalPolicyHash,bytes32 appAttestCommitment,"
        + "uint64 credentialGeneration,bool secureEnclaveRequired,bool simulatorCredential)")

    private static let eip712NameHash = RecoveryKeccak.keccak256(utf8: "PhilCore V2 Account")
    private static let eip712VersionHash = RecoveryKeccak.keccak256(utf8: "1")

    // MARK: - Wire schema

    static let contextKeys = [
        "envelopeVersion", "authorityKind", "actionType", "factorBitmap", "account", "chainId",
        "entryPoint", "authorizedIntentHash", "userOperationHash", "requestId",
        "currentRecoveryConfigHash", "validatorEpoch", "recoveryEpoch", "validAfter", "validUntil",
        "recoveryDelaySeconds", "recoveryExpirySeconds", "proposedValidatorCommitment",
        "proposedRecoveryConfigHash", "proposedRecoveryEpoch", "primaryDeviceCommitment",
        "hardwareSecurityKeyCommitment", "recoveryFactorCommitment", "firstFactorCommitment",
        "secondFactorCommitment"
    ]

    static let descriptorKeys = [
        "descriptorVersion", "accountVersionId", "securityModelId", "recoveryDomainId", "role",
        "verifierKind", "publicVerificationMaterialHash", "credentialIdentifierCommitment",
        "applicationIdentityHash", "deviceCustodyCommitment", "localApprovalPolicyHash",
        "appAttestCommitment", "credentialGeneration", "secureEnclaveRequired",
        "simulatorCredential"
    ]

    static let publicKeyKeys = ["qx", "qy"]

    static let wireKeys = [
        "protocolVersion", "context", "claimedContextHash", "claimedRecoveryFactorDigest",
        "accountVersionId", "securityModelId", "nativeRecoveryDomainId", "applicationIdentity",
        "localApprovalPolicy", "selectedRole1CredentialIdentifierCommitment",
        "selectedRole1CredentialGeneration", "trustedRole1Descriptor", "trustedRole1PublicKey",
        "sessionId", "sessionChallenge", "desktopEphemeralPublicKey", "issuedAt", "expiresAt",
        "endpoint"
    ]

    struct EcdsaP256Signature: Equatable {
        let r: String
        let s: String
    }

    // MARK: - Raw-byte gate and parsing

    static func requestHash(_ bytes: Data) -> Data {
        Data(SHA256.hash(data: bytes))
    }

    static func parse(
        rawBytes: Data,
        nowMilliseconds: String,
        expectedRequestHash: Data?
    ) throws -> RecoveryApprovalValidation {
        guard !rawBytes.isEmpty, rawBytes.count <= maxWireBytes else {
            throw RecoveryCodecError("canonical_request_raw_length_invalid")
        }
        let hash = requestHash(rawBytes)
        if let expected = expectedRequestHash {
            guard expected.count == 32 else {
                throw RecoveryCodecError("canonical_request_expected_hash_length_invalid")
            }
            guard constantTimeEqual(hash, expected) else {
                throw RecoveryCodecError("canonical_request_hash_mismatch")
            }
        }

        let request = try buildWireRequest(jsonBytes: rawBytes)
        let wireBytes = try serializeCanonical(request)
        guard wireBytes == rawBytes else {
            throw RecoveryCodecError("canonical_request_reserialize_mismatch")
        }

        let validated = try validate(request, nowMilliseconds: nowMilliseconds)
        let transcript = try buildTranscript(request)
        let transcriptHash = Data(SHA256.hash(data: transcript))
        return RecoveryApprovalValidation(
            request: request,
            wireBytes: wireBytes,
            requestHash: hash,
            contextHash: validated.contextHash,
            recoveryFactorDigest: validated.digest,
            role1FactorCommitment: validated.role1FactorCommitment,
            actionText: validated.actionText,
            networkText: validated.networkText,
            transcript: transcript,
            transcriptHash: transcriptHash,
            comparisonFingerprint: comparisonFingerprint(transcriptHash: transcriptHash)
        )
    }

    static func buildWireRequest(jsonBytes: Data) throws -> RecoveryWireRequest {
        let value = try RecoveryJSON.parse(jsonBytes)
        guard let root = value.objectValue else {
            throw RecoveryCodecError("canonical_request_schema_invalid")
        }
        try requireKeys(root, allowed: wireKeys + nonWireFields, required: wireKeys, "canonical_request")

        guard let versionLiteral = root["protocolVersion"]?.numberLiteral,
              let version = Int(versionLiteral) else {
            throw RecoveryCodecError("canonical_request_protocol_version_invalid")
        }
        guard let contextObject = root["context"]?.objectValue else {
            throw RecoveryCodecError("context_schema_invalid")
        }
        guard let descriptorObject = root["trustedRole1Descriptor"]?.objectValue else {
            throw RecoveryCodecError("trusted_role1_descriptor_required")
        }
        guard let publicKeyObject = root["trustedRole1PublicKey"]?.objectValue else {
            throw RecoveryCodecError("trusted_role1_public_key_required")
        }

        return RecoveryWireRequest(
            protocolVersion: version,
            context: try buildContext(contextObject),
            claimedContextHash: try RecoveryCodec.requireBytes32(
                root["claimedContextHash"], "claimedContextHash"
            ),
            claimedRecoveryFactorDigest: try RecoveryCodec.requireBytes32(
                root["claimedRecoveryFactorDigest"], "claimedRecoveryFactorDigest"
            ),
            accountVersionId: try RecoveryCodec.requireBytes32(
                root["accountVersionId"], "accountVersionId"
            ),
            securityModelId: try RecoveryCodec.requireBytes32(
                root["securityModelId"], "securityModelId"
            ),
            nativeRecoveryDomainId: try RecoveryCodec.requireBytes32(
                root["nativeRecoveryDomainId"], "nativeRecoveryDomainId"
            ),
            applicationIdentity: try RecoveryCodec.requireSafeString(
                root["applicationIdentity"], "applicationIdentity", maxLength: 256
            ),
            localApprovalPolicy: try RecoveryCodec.requireSafeString(
                root["localApprovalPolicy"], "localApprovalPolicy", maxLength: 256
            ),
            selectedRole1CredentialIdentifierCommitment: try RecoveryCodec.requireBytes32(
                root["selectedRole1CredentialIdentifierCommitment"],
                "selectedRole1CredentialIdentifierCommitment"
            ),
            selectedRole1CredentialGeneration: try RecoveryCodec.requireCanonicalIntegerString(
                root["selectedRole1CredentialGeneration"], "selectedRole1CredentialGeneration"
            ),
            trustedRole1Descriptor: try buildDescriptor(descriptorObject),
            trustedRole1PublicKey: try buildPublicKey(publicKeyObject),
            sessionId: try RecoveryCodec.requireBytes32(root["sessionId"], "sessionId"),
            sessionChallenge: try RecoveryCodec.requireBytes32(
                root["sessionChallenge"], "sessionChallenge"
            ),
            desktopEphemeralPublicKey: try RecoveryCodec.requireSafeString(
                root["desktopEphemeralPublicKey"], "desktopEphemeralPublicKey", maxLength: 256
            ),
            issuedAt: try RecoveryCodec.requireCanonicalIntegerString(root["issuedAt"], "issuedAt"),
            expiresAt: try RecoveryCodec.requireCanonicalIntegerString(
                root["expiresAt"], "expiresAt"
            ),
            endpoint: try RecoveryCodec.requireSafeString(root["endpoint"], "endpoint", maxLength: 256)
        )
    }

    private static func buildContext(
        _ object: [String: RecoveryJSONValue]
    ) throws -> RecoveryWireContext {
        try requireKeys(object, allowed: contextKeys, required: contextKeys, "context")
        return RecoveryWireContext(
            envelopeVersion: try integer(object, "envelopeVersion"),
            authorityKind: try integer(object, "authorityKind"),
            actionType: try integer(object, "actionType"),
            factorBitmap: try integer(object, "factorBitmap"),
            account: try RecoveryCodec.requireCanonicalAddress(object["account"], "account"),
            chainId: try integer(object, "chainId"),
            entryPoint: try RecoveryCodec.requireCanonicalAddress(object["entryPoint"], "entryPoint"),
            authorizedIntentHash: try word(object, "authorizedIntentHash"),
            userOperationHash: try word(object, "userOperationHash"),
            requestId: try word(object, "requestId"),
            currentRecoveryConfigHash: try word(object, "currentRecoveryConfigHash"),
            validatorEpoch: try integer(object, "validatorEpoch"),
            recoveryEpoch: try integer(object, "recoveryEpoch"),
            validAfter: try integer(object, "validAfter"),
            validUntil: try integer(object, "validUntil"),
            recoveryDelaySeconds: try integer(object, "recoveryDelaySeconds"),
            recoveryExpirySeconds: try integer(object, "recoveryExpirySeconds"),
            proposedValidatorCommitment: try word(object, "proposedValidatorCommitment"),
            proposedRecoveryConfigHash: try word(object, "proposedRecoveryConfigHash"),
            proposedRecoveryEpoch: try integer(object, "proposedRecoveryEpoch"),
            primaryDeviceCommitment: try word(object, "primaryDeviceCommitment"),
            hardwareSecurityKeyCommitment: try word(object, "hardwareSecurityKeyCommitment"),
            recoveryFactorCommitment: try word(object, "recoveryFactorCommitment"),
            firstFactorCommitment: try word(object, "firstFactorCommitment"),
            secondFactorCommitment: try word(object, "secondFactorCommitment")
        )
    }

    private static func buildDescriptor(
        _ object: [String: RecoveryJSONValue]
    ) throws -> RecoveryWireDescriptor {
        try requireKeys(
            object,
            allowed: descriptorKeys,
            required: descriptorKeys,
            "trusted_role1_descriptor"
        )
        return RecoveryWireDescriptor(
            descriptorVersion: try integer(object, "descriptorVersion"),
            accountVersionId: try word(object, "accountVersionId"),
            securityModelId: try word(object, "securityModelId"),
            recoveryDomainId: try word(object, "recoveryDomainId"),
            role: try integer(object, "role"),
            verifierKind: try integer(object, "verifierKind"),
            publicVerificationMaterialHash: try word(object, "publicVerificationMaterialHash"),
            credentialIdentifierCommitment: try word(object, "credentialIdentifierCommitment"),
            applicationIdentityHash: try word(object, "applicationIdentityHash"),
            deviceCustodyCommitment: try word(object, "deviceCustodyCommitment"),
            localApprovalPolicyHash: try word(object, "localApprovalPolicyHash"),
            appAttestCommitment: try word(object, "appAttestCommitment"),
            credentialGeneration: try integer(object, "credentialGeneration"),
            secureEnclaveRequired: try boolean(object, "secureEnclaveRequired"),
            simulatorCredential: try boolean(object, "simulatorCredential")
        )
    }

    private static func buildPublicKey(
        _ object: [String: RecoveryJSONValue]
    ) throws -> RecoveryWirePublicKey {
        try requireKeys(
            object,
            allowed: publicKeyKeys,
            required: publicKeyKeys,
            "trusted_role1_public_key"
        )
        return RecoveryWirePublicKey(
            qx: try word(object, "trustedRole1PublicKey.qx", key: "qx"),
            qy: try word(object, "trustedRole1PublicKey.qy", key: "qy")
        )
    }

    private static func requireKeys(
        _ object: [String: RecoveryJSONValue],
        allowed: [String],
        required: [String],
        _ label: String
    ) throws {
        let allowedSet = Set(allowed)
        for key in object.keys.sorted() where !allowedSet.contains(key) {
            throw RecoveryCodecError("\(label)_unknown_field_\(key)")
        }
        for key in required where object[key] == nil {
            throw RecoveryCodecError("\(label)_missing_field_\(key)")
        }
    }

    private static func integer(
        _ object: [String: RecoveryJSONValue],
        _ key: String
    ) throws -> String {
        try RecoveryCodec.requireCanonicalIntegerString(object[key], key)
    }

    private static func word(
        _ object: [String: RecoveryJSONValue],
        _ label: String,
        key: String? = nil
    ) throws -> String {
        try RecoveryCodec.requireBytes32(object[key ?? label], label)
    }

    private static func boolean(
        _ object: [String: RecoveryJSONValue],
        _ key: String
    ) throws -> Bool {
        guard let value = object[key]?.boolValue else {
            throw RecoveryCodecError("\(key)_must_be_boolean")
        }
        return value
    }

    // MARK: - Canonical serialisation

    static func serializeCanonical(jsonBytes: Data) throws -> Data {
        try serializeCanonical(try buildWireRequest(jsonBytes: jsonBytes))
    }

    static func serializeCanonical(_ request: RecoveryWireRequest) throws -> Data {
        let context = request.context
        let contextText = RecoveryCodec.canonicalObject([
            ("envelopeVersion", literal(context.envelopeVersion)),
            ("authorityKind", literal(context.authorityKind)),
            ("actionType", literal(context.actionType)),
            ("factorBitmap", literal(context.factorBitmap)),
            ("account", literal(context.account)),
            ("chainId", literal(context.chainId)),
            ("entryPoint", literal(context.entryPoint)),
            ("authorizedIntentHash", literal(context.authorizedIntentHash)),
            ("userOperationHash", literal(context.userOperationHash)),
            ("requestId", literal(context.requestId)),
            ("currentRecoveryConfigHash", literal(context.currentRecoveryConfigHash)),
            ("validatorEpoch", literal(context.validatorEpoch)),
            ("recoveryEpoch", literal(context.recoveryEpoch)),
            ("validAfter", literal(context.validAfter)),
            ("validUntil", literal(context.validUntil)),
            ("recoveryDelaySeconds", literal(context.recoveryDelaySeconds)),
            ("recoveryExpirySeconds", literal(context.recoveryExpirySeconds)),
            ("proposedValidatorCommitment", literal(context.proposedValidatorCommitment)),
            ("proposedRecoveryConfigHash", literal(context.proposedRecoveryConfigHash)),
            ("proposedRecoveryEpoch", literal(context.proposedRecoveryEpoch)),
            ("primaryDeviceCommitment", literal(context.primaryDeviceCommitment)),
            ("hardwareSecurityKeyCommitment", literal(context.hardwareSecurityKeyCommitment)),
            ("recoveryFactorCommitment", literal(context.recoveryFactorCommitment)),
            ("firstFactorCommitment", literal(context.firstFactorCommitment)),
            ("secondFactorCommitment", literal(context.secondFactorCommitment))
        ])

        let descriptor = request.trustedRole1Descriptor
        let descriptorText = RecoveryCodec.canonicalObject([
            ("descriptorVersion", literal(descriptor.descriptorVersion)),
            ("accountVersionId", literal(descriptor.accountVersionId)),
            ("securityModelId", literal(descriptor.securityModelId)),
            ("recoveryDomainId", literal(descriptor.recoveryDomainId)),
            ("role", literal(descriptor.role)),
            ("verifierKind", literal(descriptor.verifierKind)),
            ("publicVerificationMaterialHash", literal(descriptor.publicVerificationMaterialHash)),
            ("credentialIdentifierCommitment", literal(descriptor.credentialIdentifierCommitment)),
            ("applicationIdentityHash", literal(descriptor.applicationIdentityHash)),
            ("deviceCustodyCommitment", literal(descriptor.deviceCustodyCommitment)),
            ("localApprovalPolicyHash", literal(descriptor.localApprovalPolicyHash)),
            ("appAttestCommitment", literal(descriptor.appAttestCommitment)),
            ("credentialGeneration", literal(descriptor.credentialGeneration)),
            ("secureEnclaveRequired", descriptor.secureEnclaveRequired ? "true" : "false"),
            ("simulatorCredential", descriptor.simulatorCredential ? "true" : "false")
        ])

        let publicKeyText = RecoveryCodec.canonicalObject([
            ("qx", literal(request.trustedRole1PublicKey.qx)),
            ("qy", literal(request.trustedRole1PublicKey.qy))
        ])

        let text = RecoveryCodec.canonicalObject([
            ("protocolVersion", String(request.protocolVersion)),
            ("context", contextText),
            ("claimedContextHash", literal(request.claimedContextHash)),
            ("claimedRecoveryFactorDigest", literal(request.claimedRecoveryFactorDigest)),
            ("accountVersionId", literal(request.accountVersionId)),
            ("securityModelId", literal(request.securityModelId)),
            ("nativeRecoveryDomainId", literal(request.nativeRecoveryDomainId)),
            ("applicationIdentity", literal(request.applicationIdentity)),
            ("localApprovalPolicy", literal(request.localApprovalPolicy)),
            (
                "selectedRole1CredentialIdentifierCommitment",
                literal(request.selectedRole1CredentialIdentifierCommitment)
            ),
            (
                "selectedRole1CredentialGeneration",
                literal(request.selectedRole1CredentialGeneration)
            ),
            ("trustedRole1Descriptor", descriptorText),
            ("trustedRole1PublicKey", publicKeyText),
            ("sessionId", literal(request.sessionId)),
            ("sessionChallenge", literal(request.sessionChallenge)),
            ("desktopEphemeralPublicKey", literal(request.desktopEphemeralPublicKey)),
            ("issuedAt", literal(request.issuedAt)),
            ("expiresAt", literal(request.expiresAt)),
            ("endpoint", literal(request.endpoint))
        ])
        let data = Data(text.utf8)
        guard data.count <= maxWireBytes else {
            throw RecoveryCodecError("canonical_request_serialized_length_invalid")
        }
        return data
    }

    private static func literal(_ value: String) -> String {
        RecoveryCodec.jsonStringLiteral(value)
    }

    // MARK: - Validation

    struct Validated {
        let digest: Data
        let contextHash: Data
        let actionText: String
        let networkText: String
        let role1FactorCommitment: Data
    }

    @discardableResult
    static func validate(
        _ request: RecoveryWireRequest,
        nowMilliseconds: String
    ) throws -> Validated {
        guard request.protocolVersion == protocolVersion else {
            throw RecoveryCodecError("recovery_approval_protocol_version_unsupported")
        }

        try pinIdentity(request)

        let bitmap = try requireUInt(request.context.factorBitmap, bits: 8, label: "factorBitmap")
        guard bitmap == 3 || bitmap == 6 else {
            throw RecoveryCodecError("native_recovery_approval_bitmap_requires_role_1")
        }
        _ = try rolesForBitmap(bitmap)

        let role1FactorCommitment = try pinTrustedRole1(request)
        try validateCanonicalContextFields(request.context)

        let digest = try recoveryFactorDigest(request.context)
        guard request.claimedRecoveryFactorDigest == hex32(digest) else {
            throw RecoveryCodecError("recovery_factor_digest_mismatch_recomputed")
        }

        let contextHash = try consumerEvidenceContextHash(request.context)
        guard request.claimedContextHash == hex32(contextHash) else {
            throw RecoveryCodecError("recovery_context_hash_mismatch_recomputed")
        }

        let actionText = try derivedActionText(request.context)
        let networkText = try derivedNetworkText(request.context)

        guard !constantTimeEqual(
            try RecoveryCodec.hexBytes(request.sessionId, expecting: 32),
            try RecoveryCodec.hexBytes(request.sessionChallenge, expecting: 32)
        ) else {
            throw RecoveryCodecError("session_id_challenge_must_be_distinct_bytes32")
        }

        guard isRfc1918ApprovalEndpoint(request.endpoint) else {
            throw RecoveryCodecError("recovery_approval_endpoint_invalid")
        }

        try validateFreshness(request, nowMilliseconds: nowMilliseconds)
        try RecoveryBootstrap.validateUncompressedP256PublicKey(
            request.desktopEphemeralPublicKey,
            label: "desktop_ephemeral"
        )

        return Validated(
            digest: digest,
            contextHash: contextHash,
            actionText: actionText,
            networkText: networkText,
            role1FactorCommitment: role1FactorCommitment
        )
    }

    private static func pinIdentity(_ request: RecoveryWireRequest) throws {
        guard request.accountVersionId == accountVersionId else {
            throw RecoveryCodecError("accountVersion_identity_pin_mismatch")
        }
        guard request.securityModelId == securityModelId else {
            throw RecoveryCodecError("securityModel_identity_pin_mismatch")
        }
        guard request.nativeRecoveryDomainId == nativeRecoveryDomainId else {
            throw RecoveryCodecError("native_recovery_domain_identity_pin_mismatch")
        }
        guard request.applicationIdentity == applicationIdentity else {
            throw RecoveryCodecError("application_identity_pin_mismatch")
        }
        guard request.localApprovalPolicy == localApprovalPolicy else {
            throw RecoveryCodecError("local_approval_policy_pin_mismatch")
        }
    }

    private static func pinTrustedRole1(_ request: RecoveryWireRequest) throws -> Data {
        let descriptor = request.trustedRole1Descriptor
        guard try requireUInt(descriptor.role, bits: 8, label: "role") == 1 else {
            throw RecoveryCodecError("trusted_role1_descriptor_role_invalid")
        }
        guard try requireUInt(descriptor.verifierKind, bits: 8, label: "verifierKind") == 4 else {
            throw RecoveryCodecError("trusted_role1_descriptor_verifierKind_invalid")
        }
        guard descriptor.secureEnclaveRequired else {
            throw RecoveryCodecError("trusted_role1_secure_enclave_required")
        }
        guard !descriptor.simulatorCredential else {
            throw RecoveryCodecError("trusted_role1_simulator_credential_forbidden")
        }
        guard descriptor.credentialIdentifierCommitment
            == request.selectedRole1CredentialIdentifierCommitment else {
            throw RecoveryCodecError("role1_credential_identifier_commitment_mismatch")
        }
        let selectedGeneration = try requireUInt(
            request.selectedRole1CredentialGeneration,
            bits: 64,
            label: "selectedRole1CredentialGeneration"
        )
        guard try requireUInt(
            descriptor.credentialGeneration,
            bits: 64,
            label: "credentialGeneration"
        ) == selectedGeneration else {
            throw RecoveryCodecError("role1_credential_generation_descriptor_mismatch")
        }
        let materialHash = try nativeP256PublicMaterialHash(
            qx: request.trustedRole1PublicKey.qx,
            qy: request.trustedRole1PublicKey.qy
        )
        guard descriptor.publicVerificationMaterialHash == hex32(materialHash) else {
            throw RecoveryCodecError("trusted_role1_public_key_descriptor_mismatch")
        }
        let factorCommitment = try nativeRole1FactorCommitment(descriptor)
        guard request.context.hardwareSecurityKeyCommitment == hex32(factorCommitment) else {
            throw RecoveryCodecError("context_hardware_security_key_commitment_role1_mismatch")
        }
        return factorCommitment
    }

    private static func validateCanonicalContextFields(_ context: RecoveryWireContext) throws {
        _ = try requireUInt(context.envelopeVersion, bits: 8, label: "envelopeVersion")
        _ = try requireUInt(context.authorityKind, bits: 8, label: "authorityKind")
        _ = try requireUInt(context.actionType, bits: 8, label: "actionType")
        _ = try requireUInt(context.factorBitmap, bits: 8, label: "factorBitmap")
        _ = try requireUInt(context.validatorEpoch, bits: 64, label: "validatorEpoch")
        _ = try requireUInt(context.recoveryEpoch, bits: 64, label: "recoveryEpoch")
        _ = try requireUInt(context.validAfter, bits: 48, label: "validAfter")
        _ = try requireUInt(context.validUntil, bits: 48, label: "validUntil")
        _ = try requireUInt(context.recoveryDelaySeconds, bits: 64, label: "recoveryDelaySeconds")
        _ = try requireUInt(context.recoveryExpirySeconds, bits: 64, label: "recoveryExpirySeconds")
        _ = try requireUInt(context.proposedRecoveryEpoch, bits: 64, label: "proposedRecoveryEpoch")
        _ = try uint256Word(context.chainId, label: "chainId")
    }

    private static func validateFreshness(
        _ request: RecoveryWireRequest,
        nowMilliseconds: String
    ) throws {
        let issuedAt = try RecoveryCodec.requireUInt64(request.issuedAt, "issuedAt")
        let expiresAt = try RecoveryCodec.requireUInt64(request.expiresAt, "expiresAt")
        let now = try RecoveryCodec.requireUInt64(nowMilliseconds, "now")
        guard expiresAt > issuedAt else {
            throw RecoveryCodecError("recovery_approval_freshness_window_invalid")
        }
        guard expiresAt - issuedAt <= approvalMaxTTLMilliseconds else {
            throw RecoveryCodecError("recovery_approval_session_lifetime_invalid")
        }
        guard issuedAt <= now + approvalClockSkewMilliseconds else {
            throw RecoveryCodecError("recovery_approval_issuedAt_unreasonably_in_future")
        }
        guard now >= issuedAt, now <= expiresAt else {
            throw RecoveryCodecError("recovery_approval_expired_or_outside_freshness_window")
        }
    }

    static func derivedActionText(_ context: RecoveryWireContext) throws -> String {
        switch try requireUInt(context.actionType, bits: 8, label: "actionType") {
        case 8: return "Recovery request"
        case 9: return "Recovery cancel"
        case 10: return "Recovery config rotation request"
        case 11: return "Recovery config rotation cancel"
        default: throw RecoveryCodecError("recovery_action_type_unsupported")
        }
    }

    static func derivedNetworkText(_ context: RecoveryWireContext) throws -> String {
        "chain " + (try RecoveryCodec.requireCanonicalIntegerString(context.chainId, "chainId"))
    }

    // MARK: - Transcript

    static func buildTranscript(_ request: RecoveryWireRequest) throws -> Data {
        let context = request.context
        let contextHash = try consumerEvidenceContextHash(context)
        let digest = try recoveryFactorDigest(context)
        let lines: [String] = [
            transcriptLabel,
            String(protocolVersion),
            context.envelopeVersion,
            context.authorityKind,
            context.actionType,
            context.factorBitmap,
            context.account,
            context.chainId,
            context.entryPoint,
            context.authorizedIntentHash,
            context.userOperationHash,
            context.requestId,
            context.currentRecoveryConfigHash,
            context.validatorEpoch,
            context.recoveryEpoch,
            context.validAfter,
            context.validUntil,
            context.recoveryDelaySeconds,
            context.recoveryExpirySeconds,
            context.proposedValidatorCommitment,
            context.proposedRecoveryConfigHash,
            context.proposedRecoveryEpoch,
            context.primaryDeviceCommitment,
            context.hardwareSecurityKeyCommitment,
            context.recoveryFactorCommitment,
            context.firstFactorCommitment,
            context.secondFactorCommitment,
            request.accountVersionId,
            request.securityModelId,
            request.nativeRecoveryDomainId,
            request.applicationIdentity,
            request.localApprovalPolicy,
            request.selectedRole1CredentialIdentifierCommitment,
            request.selectedRole1CredentialGeneration,
            hex32(contextHash),
            hex32(digest),
            try derivedActionText(context),
            try derivedNetworkText(context),
            request.sessionId,
            request.sessionChallenge,
            request.desktopEphemeralPublicKey,
            request.issuedAt,
            request.expiresAt,
            request.endpoint
        ]
        guard lines.count == transcriptLineCount else {
            throw RecoveryCodecError("native_recovery_transcript_line_count_invalid")
        }
        guard lines.allSatisfy({ !$0.contains("\n") && !$0.contains("\r") }) else {
            throw RecoveryCodecError("native_recovery_transcript_line_contains_newline")
        }
        return Data(lines.joined(separator: "\n").utf8)
    }

    static func comparisonFingerprint(transcriptHash: Data) -> String {
        let hex = RecoveryCodec.hexString(transcriptHash.prefix(12)).uppercased()
        return stride(from: 0, to: hex.count, by: 4).map { offset -> String in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            let end = hex.index(start, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[start..<end])
        }.joined(separator: " ")
    }

    // MARK: - Evidence-context and digest hashing

    static func consumerEvidenceContextHash(_ context: RecoveryWireContext) throws -> Data {
        let primary = try nonZeroWord(context.primaryDeviceCommitment, "primaryDeviceCommitment")
        let hardware = try nonZeroWord(
            context.hardwareSecurityKeyCommitment,
            "hardwareSecurityKeyCommitment"
        )
        let recovery = try nonZeroWord(
            context.recoveryFactorCommitment,
            "recoveryFactorCommitment"
        )
        let supplied = try nonZeroWord(
            context.currentRecoveryConfigHash,
            "currentRecoveryConfigHash"
        )
        let expectedV3 = try consumerRecoveryConfigurationHashV3([
            context.primaryDeviceCommitment,
            context.hardwareSecurityKeyCommitment,
            context.recoveryFactorCommitment
        ])
        guard supplied == expectedV3 else {
            throw RecoveryCodecError("current_recovery_config_hash_mismatch")
        }
        let legacyV2 = try legacyRecoveryConfigurationHashV2(
            primary: primary,
            hardware: hardware,
            recovery: recovery
        )
        try frozenEvidenceContextGate(context, legacyConfigHash: legacyV2)
        return try evidenceContextFieldsHash(context, configHash: expectedV3)
    }

    /// Frozen O.37.1 invariant gate. The V2-hash copy is validated only; the
    /// hash it would produce is never used, exactly as in the TypeScript.
    private static func frozenEvidenceContextGate(
        _ context: RecoveryWireContext,
        legacyConfigHash: Data
    ) throws {
        guard try requireUInt(context.envelopeVersion, bits: 8, label: "recoveryEvidenceVersion")
            == 2 else {
            throw RecoveryCodecError("recoveryEvidenceVersion_unsupported")
        }
        guard try requireUInt(context.authorityKind, bits: 8, label: "recoveryAuthorityKind")
            == 2 else {
            throw RecoveryCodecError("recoveryAuthorityKind_unsupported")
        }
        let actionType = try requireUInt(context.actionType, bits: 8, label: "actionType")
        guard [8, 9, 10, 11].contains(actionType) else {
            throw RecoveryCodecError("recovery_evidence_action_invalid")
        }
        let bitmap = try requireUInt(context.factorBitmap, bits: 8, label: "factorBitmap")
        guard [3, 5, 6].contains(bitmap) else {
            throw RecoveryCodecError("recovery_factor_bitmap_invalid")
        }
        let chainId = try uint256Word(context.chainId, label: "chainId")
        guard chainId != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("chainId_must_be_nonzero")
        }
        _ = try requireUInt(context.validatorEpoch, bits: 64, label: "validatorEpoch", nonzero: true)
        let recoveryEpoch = try requireUInt(
            context.recoveryEpoch, bits: 64, label: "recoveryEpoch", nonzero: true
        )
        let validAfter = try requireUInt(context.validAfter, bits: 48, label: "validAfter")
        let validUntil = try requireUInt(
            context.validUntil, bits: 48, label: "validUntil", nonzero: true
        )
        guard validUntil > validAfter else {
            throw RecoveryCodecError("validity_window_invalid")
        }
        guard try requireUInt(
            context.recoveryDelaySeconds, bits: 64, label: "recoveryDelaySeconds", nonzero: true
        ) == recoveryDelaySeconds else {
            throw RecoveryCodecError("recoveryDelaySeconds_invalid")
        }
        guard try requireUInt(
            context.recoveryExpirySeconds, bits: 64, label: "recoveryExpirySeconds", nonzero: true
        ) == recoveryExpirySeconds else {
            throw RecoveryCodecError("recoveryExpirySeconds_invalid")
        }

        let primary = try nonZeroWord(context.primaryDeviceCommitment, "primaryDeviceCommitment")
        let hardware = try nonZeroWord(
            context.hardwareSecurityKeyCommitment, "hardwareSecurityKeyCommitment"
        )
        let recovery = try nonZeroWord(context.recoveryFactorCommitment, "recoveryFactorCommitment")
        let computed = try legacyRecoveryConfigurationHashV2(
            primary: primary, hardware: hardware, recovery: recovery
        )
        guard legacyConfigHash == computed else {
            throw RecoveryCodecError("current_recovery_config_hash_mismatch")
        }

        let roleCommitments = [primary, hardware, recovery]
        let roles = try rolesForBitmap(bitmap)
        let first = try nonZeroWord(context.firstFactorCommitment, "firstFactorCommitment")
        let second = try nonZeroWord(context.secondFactorCommitment, "secondFactorCommitment")
        guard first == roleCommitments[roles.0], second == roleCommitments[roles.1] else {
            throw RecoveryCodecError("factor_commitment_order_or_membership_invalid")
        }

        let proposedValidatorCommitment = try RecoveryCodec.hexBytes(
            context.proposedValidatorCommitment, expecting: 32
        )
        let proposedRecoveryConfigHash = try RecoveryCodec.hexBytes(
            context.proposedRecoveryConfigHash, expecting: 32
        )
        guard try requireUInt(
            context.proposedRecoveryEpoch, bits: 64, label: "proposedRecoveryEpoch", nonzero: true
        ) == recoveryEpoch + 1 else {
            throw RecoveryCodecError("proposedRecoveryEpoch_must_equal_current_plus_one")
        }
        let validatorRecovery = actionType == 8 || actionType == 9
        if validatorRecovery {
            guard proposedValidatorCommitment != RecoveryCodec.zeroBytes32,
                  proposedRecoveryConfigHash == RecoveryCodec.zeroBytes32 else {
                throw RecoveryCodecError("validator_recovery_action_context_invalid")
            }
        } else {
            guard proposedValidatorCommitment == RecoveryCodec.zeroBytes32,
                  proposedRecoveryConfigHash != RecoveryCodec.zeroBytes32 else {
                throw RecoveryCodecError("config_rotation_action_context_invalid")
            }
        }

        _ = try nonZeroWord(context.authorizedIntentHash, "authorizedIntentHash")
        _ = try nonZeroWord(context.requestId, "requestId")
        let isRequest = actionType == 8 || actionType == 10
        if isRequest, context.requestId != context.authorizedIntentHash {
            throw RecoveryCodecError("recovery_request_id_must_equal_authorized_intent_hash")
        }
        _ = try nonZeroAddressWord(context.account, "account")
        _ = try nonZeroAddressWord(context.entryPoint, "entryPoint")
        _ = try nonZeroWord(context.userOperationHash, "userOperationHash")
    }

    private static func evidenceContextFieldsHash(
        _ context: RecoveryWireContext,
        configHash: Data
    ) throws -> Data {
        var buffer = Data()
        buffer.append(evidenceContextTypehash)
        buffer.append(try uintWord(context.envelopeVersion, bits: 8, label: "envelopeVersion"))
        buffer.append(try uintWord(context.authorityKind, bits: 8, label: "authorityKind"))
        buffer.append(try uintWord(context.actionType, bits: 8, label: "actionType"))
        buffer.append(try uintWord(context.factorBitmap, bits: 8, label: "factorBitmap"))
        buffer.append(try addressWord(context.account, "account"))
        buffer.append(try uint256Word(context.chainId, label: "chainId"))
        buffer.append(try addressWord(context.entryPoint, "entryPoint"))
        buffer.append(try RecoveryCodec.hexBytes(context.authorizedIntentHash, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(context.userOperationHash, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(context.requestId, expecting: 32))
        buffer.append(configHash)
        buffer.append(try uintWord(context.validatorEpoch, bits: 64, label: "validatorEpoch"))
        buffer.append(try uintWord(context.recoveryEpoch, bits: 64, label: "recoveryEpoch"))
        buffer.append(try uintWord(context.validAfter, bits: 48, label: "validAfter"))
        buffer.append(try uintWord(context.validUntil, bits: 48, label: "validUntil"))
        buffer.append(
            try uintWord(context.recoveryDelaySeconds, bits: 64, label: "recoveryDelaySeconds")
        )
        buffer.append(
            try uintWord(context.recoveryExpirySeconds, bits: 64, label: "recoveryExpirySeconds")
        )
        buffer.append(try RecoveryCodec.hexBytes(context.proposedValidatorCommitment, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(context.proposedRecoveryConfigHash, expecting: 32))
        buffer.append(
            try uintWord(context.proposedRecoveryEpoch, bits: 64, label: "proposedRecoveryEpoch")
        )
        buffer.append(try RecoveryCodec.hexBytes(context.primaryDeviceCommitment, expecting: 32))
        buffer.append(
            try RecoveryCodec.hexBytes(context.hardwareSecurityKeyCommitment, expecting: 32)
        )
        buffer.append(try RecoveryCodec.hexBytes(context.recoveryFactorCommitment, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(context.firstFactorCommitment, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(context.secondFactorCommitment, expecting: 32))
        return RecoveryKeccak.keccak256(buffer)
    }

    static func recoveryFactorDigest(_ context: RecoveryWireContext) throws -> Data {
        var structBuffer = Data()
        structBuffer.append(recoveryAuthorizationTypehash)
        structBuffer.append(try nonZeroWord(context.authorizedIntentHash, "authorizedIntentHash"))
        structBuffer.append(try nonZeroWord(context.userOperationHash, "userOperationHash"))
        structBuffer.append(
            try nonZeroWord(context.currentRecoveryConfigHash, "recoveryConfigHash")
        )
        structBuffer.append(
            try uintWord(context.recoveryEpoch, bits: 64, label: "recoveryEpoch", nonzero: true)
        )
        let bitmap = try requireUInt(context.factorBitmap, bits: 8, label: "factorBitmap", nonzero: true)
        guard [3, 5, 6].contains(bitmap) else {
            throw RecoveryCodecError("factorBitmap_must_select_exactly_two_roles")
        }
        structBuffer.append(try uintWord(context.factorBitmap, bits: 8, label: "factorBitmap"))
        let structHash = RecoveryKeccak.keccak256(structBuffer)

        var domainBuffer = Data()
        domainBuffer.append(eip712DomainTypehash)
        domainBuffer.append(eip712NameHash)
        domainBuffer.append(eip712VersionHash)
        let chainId = try uint256Word(context.chainId, label: "chainId")
        guard chainId != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("chainId_must_be_nonzero")
        }
        domainBuffer.append(chainId)
        domainBuffer.append(try nonZeroAddressWord(context.account, "account"))
        let domainSeparator = RecoveryKeccak.keccak256(domainBuffer)

        var digestBuffer = Data([0x19, 0x01])
        digestBuffer.append(domainSeparator)
        digestBuffer.append(structHash)
        return RecoveryKeccak.keccak256(digestBuffer)
    }

    // MARK: - Role 1 commitments

    static func nativeP256PublicMaterialHash(qx: String, qy: String) throws -> Data {
        var buffer = Data()
        buffer.append(nativePublicMaterialTypehash)
        buffer.append(try nonZeroWord(qx, "qx"))
        buffer.append(try nonZeroWord(qy, "qy"))
        return RecoveryKeccak.keccak256(buffer)
    }

    static func nativeRole1FactorCommitment(_ descriptor: RecoveryWireDescriptor) throws -> Data {
        let generation = try requireUInt(
            descriptor.credentialGeneration, bits: 64, label: "credentialGeneration"
        )
        guard generation != 0 else {
            throw RecoveryCodecError("credentialGeneration_must_be_nonzero")
        }
        guard descriptor.secureEnclaveRequired, !descriptor.simulatorCredential else {
            throw RecoveryCodecError("production_descriptor_requires_secure_enclave")
        }
        guard try nonZeroWord(descriptor.accountVersionId, "accountVersionId")
            == (try RecoveryCodec.hexBytes(accountVersionId, expecting: 32)) else {
            throw RecoveryCodecError("accountVersionId_unsupported")
        }
        guard try nonZeroWord(descriptor.securityModelId, "securityModelId")
            == (try RecoveryCodec.hexBytes(securityModelId, expecting: 32)) else {
            throw RecoveryCodecError("securityModelId_unsupported")
        }
        guard try nonZeroWord(descriptor.recoveryDomainId, "recoveryDomainId")
            == (try RecoveryCodec.hexBytes(nativeRecoveryDomainId, expecting: 32)) else {
            throw RecoveryCodecError("recoveryDomainId_unsupported")
        }
        let expectedApplicationIdentityHash = Data(
            SHA256.hash(data: Data(applicationIdentity.utf8))
        )
        guard try nonZeroWord(descriptor.applicationIdentityHash, "applicationIdentityHash")
            == expectedApplicationIdentityHash else {
            throw RecoveryCodecError("applicationIdentityHash_unsupported")
        }
        let expectedLocalApprovalPolicyHash = Data(
            SHA256.hash(data: Data(localApprovalPolicy.utf8))
        )
        guard try nonZeroWord(descriptor.localApprovalPolicyHash, "localApprovalPolicyHash")
            == expectedLocalApprovalPolicyHash else {
            throw RecoveryCodecError("localApprovalPolicyHash_unsupported")
        }
        guard try requireUInt(descriptor.descriptorVersion, bits: 8, label: "descriptorVersion")
            == 1 else {
            throw RecoveryCodecError("descriptorVersion_unsupported")
        }
        guard try requireUInt(descriptor.role, bits: 8, label: "role") == 1 else {
            throw RecoveryCodecError("role_unsupported")
        }
        guard try requireUInt(descriptor.verifierKind, bits: 8, label: "verifierKind") == 4 else {
            throw RecoveryCodecError("verifierKind_unsupported")
        }

        var buffer = Data()
        buffer.append(nativeDescriptorTypehash)
        buffer.append(try uintWord(descriptor.descriptorVersion, bits: 8, label: "descriptorVersion"))
        buffer.append(try RecoveryCodec.hexBytes(descriptor.accountVersionId, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(descriptor.securityModelId, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(descriptor.recoveryDomainId, expecting: 32))
        buffer.append(try uintWord(descriptor.role, bits: 8, label: "role"))
        buffer.append(try uintWord(descriptor.verifierKind, bits: 8, label: "verifierKind"))
        buffer.append(
            try nonZeroWord(
                descriptor.publicVerificationMaterialHash, "publicVerificationMaterialHash"
            )
        )
        buffer.append(
            try nonZeroWord(
                descriptor.credentialIdentifierCommitment, "credentialIdentifierCommitment"
            )
        )
        buffer.append(try RecoveryCodec.hexBytes(descriptor.applicationIdentityHash, expecting: 32))
        buffer.append(
            try nonZeroWord(descriptor.deviceCustodyCommitment, "deviceCustodyCommitment")
        )
        buffer.append(try RecoveryCodec.hexBytes(descriptor.localApprovalPolicyHash, expecting: 32))
        buffer.append(try RecoveryCodec.hexBytes(descriptor.appAttestCommitment, expecting: 32))
        buffer.append(
            try uintWord(descriptor.credentialGeneration, bits: 64, label: "credentialGeneration")
        )
        buffer.append(boolWord(descriptor.secureEnclaveRequired))
        buffer.append(boolWord(descriptor.simulatorCredential))
        return RecoveryKeccak.keccak256(buffer)
    }

    static func consumerRecoveryConfigurationHashV3(_ commitments: [String]) throws -> Data {
        guard commitments.count == 3 else {
            throw RecoveryCodecError("recovery_factor_commitments_count_invalid")
        }
        var normalized = [Data]()
        for (index, value) in commitments.enumerated() {
            normalized.append(try nonZeroWord(value, "role\(index)Commitment"))
        }
        guard Set(normalized).count == 3 else {
            throw RecoveryCodecError("recovery_factor_commitments_must_be_unique")
        }
        var buffer = Data()
        buffer.append(consumerConfigurationTypehash)
        buffer.append(uintWord(consumerConfigurationVersion))
        buffer.append(uintWord(recoveryThreshold))
        normalized.forEach { buffer.append($0) }
        return RecoveryKeccak.keccak256(buffer)
    }

    private static func legacyRecoveryConfigurationHashV2(
        primary: Data,
        hardware: Data,
        recovery: Data
    ) throws -> Data {
        guard Set([primary, hardware, recovery]).count == 3 else {
            throw RecoveryCodecError("recovery_factor_commitments_must_be_unique")
        }
        var buffer = Data()
        buffer.append(legacyConfigurationTypehash)
        buffer.append(uintWord(legacyConfigurationVersion))
        buffer.append(uintWord(recoveryThreshold))
        buffer.append(primary)
        buffer.append(hardware)
        buffer.append(recovery)
        return RecoveryKeccak.keccak256(buffer)
    }

    static func rolesForBitmap(_ bitmap: UInt64) throws -> (Int, Int) {
        switch bitmap {
        case 3: return (0, 1)
        case 5: return (0, 2)
        case 6: return (1, 2)
        default: throw RecoveryCodecError("recovery_factor_bitmap_invalid")
        }
    }

    // MARK: - Endpoint policy

    static func isRfc1918ApprovalEndpoint(_ endpoint: String) -> Bool {
        guard !endpoint.isEmpty, endpoint.count <= 256 else { return false }
        guard endpoint.allSatisfy({ $0.isASCII }) else { return false }
        guard !endpoint.contains("\n"), !endpoint.contains("\r") else { return false }
        guard endpoint.hasPrefix("http://") else { return false }
        let remainder = endpoint.dropFirst("http://".count)
        guard let separator = remainder.firstIndex(of: "/") else { return false }
        let authority = remainder[remainder.startIndex..<separator]
        let path = String(remainder[separator...])
        guard path == completionEndpointPath else { return false }
        guard !authority.isEmpty, !authority.contains("@") else { return false }
        let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        guard let portText = try? RecoveryCodec.requireCanonicalIntegerString(
            String(parts[1]), "port"
        ), let port = Int(portText), port >= 1, port <= 65535 else {
            return false
        }
        return (try? RecoveryBootstrap.parseIPv4(text: String(parts[0]))) != nil
    }

    // MARK: - Strict DER + low-S

    private static let curveOrder = Data([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ])

    private static let curveHalfOrder = shiftRightOne(curveOrder)

    static func parseDerEcdsaP256Signature(_ der: Data) throws -> EcdsaP256Signature {
        let bytes = Array(der)
        guard bytes.count >= 8, bytes[0] == 0x30 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_malformed")
        }
        let sequence = try readDerLength(bytes, 1)
        let sequenceEnd = sequence.offset + sequence.length
        guard sequenceEnd == bytes.count else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_trailing_bytes")
        }
        let r = try readDerInteger(bytes, sequence.offset)
        let s = try readDerInteger(bytes, r.offset)
        guard s.offset == sequenceEnd else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_trailing_bytes")
        }
        return EcdsaP256Signature(r: hex32(r.value), s: hex32(s.value))
    }

    private static func readDerLength(
        _ bytes: [UInt8],
        _ offset: Int
    ) throws -> (length: Int, offset: Int) {
        guard offset < bytes.count else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_malformed")
        }
        let first = bytes[offset]
        if first < 0x80 {
            return (Int(first), offset + 1)
        }
        let count = Int(first & 0x7f)
        guard count == 1 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_length_nonminimal")
        }
        guard offset + 1 < bytes.count else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_malformed")
        }
        let length = bytes[offset + 1]
        guard length >= 0x80 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_length_nonminimal")
        }
        return (Int(length), offset + 2)
    }

    private static func readDerInteger(
        _ bytes: [UInt8],
        _ offset: Int
    ) throws -> (value: Data, offset: Int) {
        guard offset < bytes.count, bytes[offset] == 0x02 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_integer")
        }
        let lengthInfo = try readDerLength(bytes, offset + 1)
        guard lengthInfo.length >= 1, lengthInfo.length <= 33 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_integer_length")
        }
        let end = lengthInfo.offset + lengthInfo.length
        guard end <= bytes.count else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_malformed")
        }
        let raw = Array(bytes[lengthInfo.offset..<end])
        guard raw[0] & 0x80 == 0 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_negative")
        }
        if raw.count > 1, raw[0] == 0x00, raw[1] & 0x80 == 0 {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_nonminimal")
        }
        if raw.count == 1, raw[0] == 0x00 {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_zero")
        }
        let value = leftPad32(Data(raw.drop(while: { $0 == 0x00 })))
        guard value != RecoveryCodec.zeroBytes32, compare(value, curveOrder) < 0 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_out_of_order")
        }
        return (value, end)
    }

    static func normalizeLowS(
        _ signature: EcdsaP256Signature
    ) throws -> (signature: EcdsaP256Signature, normalized: Bool) {
        let r: Data
        var s: Data
        do {
            r = try RecoveryCodec.hexBytes(signature.r, expecting: 32)
            s = try RecoveryCodec.hexBytes(signature.s, expecting: 32)
        } catch {
            throw RecoveryCodecError("p256_signature_invalid")
        }
        guard r != RecoveryCodec.zeroBytes32, s != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("p256_signature_component_zero_invalid")
        }
        guard compare(r, curveOrder) < 0, compare(s, curveOrder) < 0 else {
            throw RecoveryCodecError("p256_signature_out_of_range_order_invalid")
        }
        var normalized = false
        if compare(s, curveHalfOrder) > 0 {
            s = subtract(curveOrder, s)
            normalized = true
        }
        guard s != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("p256_signature_component_zero_invalid")
        }
        return (EcdsaP256Signature(r: hex32(r), s: hex32(s)), normalized)
    }

    // MARK: - Minimal ABI word helpers

    private static func uintWord(_ value: UInt64) -> Data {
        var word = [UInt8](repeating: 0, count: 32)
        var remaining = value
        var index = 31
        while remaining > 0 {
            word[index] = UInt8(remaining & 0xff)
            remaining >>= 8
            index -= 1
        }
        return Data(word)
    }

    private static func uintWord(
        _ text: String,
        bits: Int,
        label: String,
        nonzero: Bool = false
    ) throws -> Data {
        uintWord(try requireUInt(text, bits: bits, label: label, nonzero: nonzero))
    }

    private static func uint256Word(_ text: String, label: String) throws -> Data {
        let canonical = try RecoveryCodec.requireCanonicalIntegerString(text, label)
        var word = [UInt8](repeating: 0, count: 32)
        for scalar in canonical.unicodeScalars {
            var carry = UInt32(scalar.value - 48)
            var index = 31
            while index >= 0 {
                let product = UInt32(word[index]) * 10 + carry
                word[index] = UInt8(product & 0xff)
                carry = product >> 8
                index -= 1
            }
            guard carry == 0 else {
                throw RecoveryCodecError("\(label)_must_be_uint256")
            }
        }
        return Data(word)
    }

    private static func requireUInt(
        _ text: String,
        bits: Int,
        label: String,
        nonzero: Bool = false
    ) throws -> UInt64 {
        let canonical = try RecoveryCodec.requireCanonicalIntegerString(text, label)
        guard let value = UInt64(canonical) else {
            throw RecoveryCodecError("\(label)_must_be_uint\(bits)")
        }
        if bits < 64, value >= (UInt64(1) << UInt64(bits)) {
            throw RecoveryCodecError("\(label)_must_be_uint\(bits)")
        }
        if nonzero, value == 0 {
            throw RecoveryCodecError("\(label)_must_be_nonzero")
        }
        return value
    }

    private static func addressWord(_ text: String, _ label: String) throws -> Data {
        let canonical = try RecoveryCodec.requireCanonicalAddress(text, label)
        var word = Data(repeating: 0, count: 12)
        word.append(try RecoveryCodec.hexBytes(canonical, expecting: 20))
        return word
    }

    private static func nonZeroAddressWord(_ text: String, _ label: String) throws -> Data {
        let word = try addressWord(text, label)
        guard word != Data(repeating: 0, count: 32) else {
            throw RecoveryCodecError("\(label)_must_be_nonzero")
        }
        return word
    }

    private static func boolWord(_ value: Bool) -> Data {
        var word = Data(repeating: 0, count: 32)
        word[31] = value ? 1 : 0
        return word
    }

    private static func nonZeroWord(_ text: String, _ label: String) throws -> Data {
        let normalized = try RecoveryCodec.requireBytes32(text, label)
        let bytes = try RecoveryCodec.hexBytes(normalized, expecting: 32)
        guard bytes != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("\(label)_must_be_nonzero")
        }
        return bytes
    }

    // MARK: - Small byte helpers

    private static func hex32(_ data: Data) -> String {
        "0x" + RecoveryCodec.hexString(data)
    }

    private static func leftPad32(_ data: Data) -> Data {
        guard data.count < 32 else { return Data(data.suffix(32)) }
        return Data(repeating: 0, count: 32 - data.count) + data
    }

    private static func compare(_ left: Data, _ right: Data) -> Int {
        let a = Array(left)
        let b = Array(right)
        for index in 0..<min(a.count, b.count) {
            if a[index] != b[index] { return a[index] < b[index] ? -1 : 1 }
        }
        return 0
    }

    private static func subtract(_ left: Data, _ right: Data) -> Data {
        let a = Array(left)
        let b = Array(right)
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            let difference = Int(a[index]) - Int(b[index]) - borrow
            if difference < 0 {
                out[index] = UInt8(difference + 256)
                borrow = 1
            } else {
                out[index] = UInt8(difference)
                borrow = 0
            }
        }
        return Data(out)
    }

    private static func shiftRightOne(_ data: Data) -> Data {
        var out = [UInt8](repeating: 0, count: data.count)
        var carry: UInt8 = 0
        for (index, byte) in data.enumerated() {
            out[index] = (byte >> 1) | (carry << 7)
            carry = byte & 1
        }
        return Data(out)
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(left, right) { difference |= a ^ b }
        return difference == 0
    }
}
