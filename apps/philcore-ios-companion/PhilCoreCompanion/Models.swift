import Foundation

enum CompanionTab: Hashable {
    case home, pair, routine, approval, settings
}

enum EnrollmentState: String, Codable {
    case notEnrolled = "NOT_ENROLLED"
    case disposableTest = "DISPOSABLE_TEST"
    case pairedTest = "PAIRED_TEST"
    case production = "PRODUCTION"
    case invalidated = "INVALIDATED"
}

struct PublicCredentialRecord: Codable, Equatable {
    let schemaVersion: Int
    let generation: UInt64
    let keyTag: String
    let publicKeyX963: String
    let publicFingerprint: String
    let simulatorOnly: Bool
    let secureEnclaveBacked: Bool
    var enrollmentState: EnrollmentState
    var pairedIdentityCommitment: String?
    var lastSuccessfulTestAt: Date?
}

struct PairingRequest: Codable, Equatable {
    let protocolVersion: Int
    let sessionId: String
    let expiresAt: String
    let endpoint: String
    let desktopEphemeralPublicKey: String
    let challenge: String
    let philCoreIdentityCommitment: String
    let accountVersionId: String
    let securityModelId: String
    let recoveryEpoch: UInt64
    let requestedGeneration: UInt64
    let applicationIdentity: String

    var canonicalTranscript: Data {
        [
            "PHILCORE_NATIVE_PAIRING_V1",
            String(protocolVersion),
            sessionId,
            expiresAt,
            endpoint,
            desktopEphemeralPublicKey,
            challenge,
            philCoreIdentityCommitment,
            accountVersionId,
            securityModelId,
            String(recoveryEpoch),
            String(requestedGeneration),
            applicationIdentity
        ].joined(separator: "\n").data(using: .utf8)!
    }
}

struct PairingResponsePayload: Codable {
    let protocolVersion: Int
    let sessionId: String
    let phoneEphemeralPublicKey: String
    let transcriptHash: String
    let credentialPublicKey: String
    let credentialFingerprint: String
    let credentialIdentifierCommitment: String
    let applicationIdentity: String
    let applicationIdentityHash: String
    let deviceCustodyCommitment: String
    let localApprovalPolicyHash: String
    let generation: UInt64
    let secureEnclaveBacked: Bool
    let simulatorOnly: Bool
    let enrollmentSignatureDER: String
}

struct EncryptedPairingMessage: Codable {
    let version: Int
    let sessionId: String
    let phoneEphemeralPublicKey: String?
    let nonce: String
    let ciphertext: String
    let tag: String
}

struct RecoveryApprovalRequest: Codable, Identifiable {
    let id: String
    let action: String
    let account: String
    let network: String
    let recoveryEpoch: UInt64
    let digestHex: String
    let expiresAt: Date
}

enum CompanionFailure: LocalizedError, Equatable {
    case invalidRequest
    case expiredRequest
    case unsupportedVersion
    case insecureEndpoint
    case secureEnclaveUnavailable
    case deviceSecurityUnavailable
    case userCancelled
    case userDenied
    case approvalInvalidated
    case keyCreationFailed
    case keyNotFound
    case signingFailed
    case transportFailed
    case desktopRejected

    var errorDescription: String? {
        switch self {
        case .invalidRequest: "The pairing request is malformed or was changed."
        case .expiredRequest: "The pairing request has expired."
        case .unsupportedVersion: "This request uses an unsupported PhilCore version."
        case .insecureEndpoint: "The desktop endpoint is not a private local-network address."
        case .secureEnclaveUnavailable: "Secure Enclave is unavailable on this device."
        case .deviceSecurityUnavailable: "Face ID, Touch ID, or a device passcode is required."
        case .userCancelled: "Approval was cancelled. Nothing was signed."
        case .userDenied: "Approval was denied. Nothing was signed."
        case .approvalInvalidated: "The request was invalidated when the app left the foreground."
        case .keyCreationFailed: "The device-bound recovery credential could not be created."
        case .keyNotFound: "The recovery credential is not available on this iPhone."
        case .signingFailed: "The exact recovery digest could not be signed."
        case .transportFailed: "The encrypted response did not reach PhilCore Desktop."
        case .desktopRejected: "PhilCore Desktop rejected the enrollment response."
        }
    }
}
