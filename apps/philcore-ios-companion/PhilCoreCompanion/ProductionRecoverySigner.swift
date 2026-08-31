import Foundation
import LocalAuthentication

// MARK: - Approval seam
//
// Defined here so LocalApprovalManager.swift stays untouched. Production and
// tests share the same MainActor-isolated surface; tests inject a double that
// never evaluates a LocalAuthentication policy.

@MainActor
protocol LocalRecoveryApproving: AnyObject {
    func approve(reason: String) async throws -> LAContext
    func finish()
    func invalidate()
}

extension LocalApprovalManager: LocalRecoveryApproving {}

// MARK: - Recovery credential-access seam
//
// Recovery-specific methods intentionally do not weaken or repurpose the
// existing pairing / disposable `signDigest` path. The production query
// constrains the exact application tag, EC P-256 key type, Secure Enclave
// token identity where the Security API supports it, and exactly one result.

@MainActor
protocol RecoveryCredentialAccessing: AnyObject {
    func loadActiveRecoveryPublicRecord() -> PublicCredentialRecord?
    func copyActualProductionRecoveryPublicKeyBytes(tag: String) throws -> Data
    func signProductionRecoveryDigest(
        _ digest: Data,
        tag: String,
        authenticationContext: LAContext
    ) throws -> Data
}

// MARK: - Pure credential validation
//
// The signer validates local production metadata before prompting. It does not
// know the remote request's expected Role 1 key: after signing, existing
// `RecoveryClient.verifyTrustedRole1Signature` still owns the O.44 trusted-key
// binding and will reject a mismatched active key before encryption or
// `/complete`.

enum ProductionRecoveryCredentialValidator {
    struct ValidatedRecord: Equatable {
        let record: PublicCredentialRecord
        let decodedPublicKeyBytes: Data
    }

    static func expectedProductionTag(generation: UInt64) -> String {
        "\(SecureEnclaveCredentialManager.productionTagPrefix).g\(generation)"
    }

    static func validateForSigning(record: PublicCredentialRecord?) throws -> ValidatedRecord {
        guard let record else {
            throw RecoveryClientError.signer("recovery_credential_missing")
        }
        guard record.schemaVersion == 1 else {
            throw RecoveryClientError.signer("recovery_credential_schema_unsupported")
        }
        guard record.enrollmentState == .production else {
            throw RecoveryClientError.signer("recovery_credential_nonproduction")
        }
        guard record.simulatorOnly == false else {
            throw RecoveryClientError.signer("recovery_credential_simulator_only")
        }
        guard record.secureEnclaveBacked else {
            throw RecoveryClientError.signer("recovery_credential_not_secure_enclave")
        }
        guard record.generation > 0 else {
            throw RecoveryClientError.signer("recovery_credential_generation_zero")
        }
        try validateProductionTag(record)
        try validatePairedIdentityCommitment(record.pairedIdentityCommitment)
        let publicKeyBytes = try decodeStrictPublicKeyX963(record.publicKeyX963)
        let expectedFingerprint = CryptoSupport.fingerprint(publicKeyBytes)
        guard record.publicFingerprint == expectedFingerprint else {
            throw RecoveryClientError.signer("recovery_credential_fingerprint_mismatch")
        }
        return ValidatedRecord(record: record, decodedPublicKeyBytes: publicKeyBytes)
    }

    static func bindActualPublicKey(
        validated: ValidatedRecord,
        actualPublicKeyBytes: Data?
    ) throws {
        guard let actualPublicKeyBytes else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        guard actualPublicKeyBytes == validated.decodedPublicKeyBytes else {
            throw RecoveryClientError.signer("recovery_credential_public_key_mismatch")
        }
        let fingerprint = CryptoSupport.fingerprint(actualPublicKeyBytes)
        guard fingerprint == validated.record.publicFingerprint else {
            throw RecoveryClientError.signer("recovery_credential_fingerprint_mismatch")
        }
    }

    private static func validateProductionTag(_ record: PublicCredentialRecord) throws {
        if record.keyTag == SecureEnclaveCredentialManager.disposableTag {
            throw RecoveryClientError.signer("recovery_credential_disposable_tag")
        }
        let expected = expectedProductionTag(generation: record.generation)
        if record.keyTag == expected { return }

        let generationPrefix = "\(SecureEnclaveCredentialManager.productionTagPrefix).g"
        if record.keyTag.hasPrefix(generationPrefix) {
            let suffix = String(record.keyTag.dropFirst(generationPrefix.count))
            if let parsed = UInt64(suffix),
               parsed == record.generation,
               String(parsed) != suffix {
                throw RecoveryClientError.signer("recovery_credential_tag_noncanonical")
            }
            if suffix.isEmpty || suffix.contains(where: { !$0.isNumber }) {
                throw RecoveryClientError.signer("recovery_credential_tag_noncanonical")
            }
            throw RecoveryClientError.signer("recovery_credential_tag_mismatch")
        }
        throw RecoveryClientError.signer("recovery_credential_tag_mismatch")
    }

    private static func validatePairedIdentityCommitment(_ value: String?) throws {
        guard let value else {
            throw RecoveryClientError.signer("recovery_credential_commitment_invalid")
        }
        // Desktop pairing stores philCoreIdentityCommitment as exactly 64
        // lowercase hexadecimal characters with no `0x` prefix.
        guard value.count == 64 else {
            throw RecoveryClientError.signer("recovery_credential_commitment_invalid")
        }
        guard value.allSatisfy({ $0.isHexDigit && $0.isASCII && ($0.isNumber || $0.isLowercase) })
        else {
            throw RecoveryClientError.signer("recovery_credential_commitment_invalid")
        }
        guard value.contains(where: { $0 != "0" }) else {
            throw RecoveryClientError.signer("recovery_credential_commitment_invalid")
        }
    }

    private static func decodeStrictPublicKeyX963(_ value: String) throws -> Data {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard !value.isEmpty, value.allSatisfy({ alphabet.contains($0) }) else {
            throw RecoveryClientError.signer("recovery_credential_public_key_invalid")
        }
        guard !value.contains("="), !value.contains("+"), !value.contains("/") else {
            throw RecoveryClientError.signer("recovery_credential_public_key_invalid")
        }
        guard let decoded = CryptoSupport.decodeBase64URL(value) else {
            throw RecoveryClientError.signer("recovery_credential_public_key_invalid")
        }
        guard CryptoSupport.base64URL(decoded) == value else {
            throw RecoveryClientError.signer("recovery_credential_public_key_invalid")
        }
        guard decoded.count == 65, decoded.first == 0x04 else {
            throw RecoveryClientError.signer("recovery_credential_public_key_invalid")
        }
        return decoded
    }
}

// MARK: - MainActor coordinator

@MainActor
protocol ProductionRecoverySigningCoordinating: AnyObject {
    func approveAndSignRecoveryDigest(_ digest: Data) async throws -> Data
}

/// MainActor-isolated production coordinator.
///
/// Flow:
/// `RecoveryClient` → `ProductionRecoverySigner` → this coordinator →
/// validate credential → `LocalApprovalManager.approve` → sign with the
/// returned `LAContext` → `finish` → return only DER `Data`.
///
/// `LAContext` never leaves this MainActor-isolated operation. The signer does
/// not claim knowledge of the remote account, generation, or trusted Role 1
/// key; post-signature O.44 trusted-key binding remains owned by
/// `RecoveryClient`.
@MainActor
final class ProductionRecoverySigningCoordinator: ProductionRecoverySigningCoordinating {
    static let approvalReason =
        "Approve the exact PhilCore recovery action shown on screen."

    private let credentials: any RecoveryCredentialAccessing
    private let approval: any LocalRecoveryApproving

    init(
        credentials: any RecoveryCredentialAccessing,
        approval: any LocalRecoveryApproving
    ) {
        self.credentials = credentials
        self.approval = approval
    }

    convenience init(
        credentialManager: SecureEnclaveCredentialManager,
        approvalManager: LocalApprovalManager
    ) {
        self.init(credentials: credentialManager, approval: approvalManager)
    }

    convenience init() {
        self.init(
            credentials: SecureEnclaveCredentialManager(),
            approval: LocalApprovalManager()
        )
    }

    func approveAndSignRecoveryDigest(_ digest: Data) async throws -> Data {
        guard digest.count == 32 else {
            throw RecoveryClientError.signer("recovery_client_signer_failed")
        }

        let validated = try ProductionRecoveryCredentialValidator.validateForSigning(
            record: credentials.loadActiveRecoveryPublicRecord()
        )

        let actualPublicKeyBytes: Data
        do {
            actualPublicKeyBytes = try credentials.copyActualProductionRecoveryPublicKeyBytes(
                tag: validated.record.keyTag
            )
        } catch let error as RecoveryClientError {
            throw error
        } catch {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        try ProductionRecoveryCredentialValidator.bindActualPublicKey(
            validated: validated,
            actualPublicKeyBytes: actualPublicKeyBytes
        )

        let context: LAContext
        do {
            context = try await approval.approve(reason: Self.approvalReason)
        } catch let error as RecoveryClientError {
            approval.finish()
            throw error
        } catch let failure as CompanionFailure {
            approval.finish()
            throw Self.mapApprovalFailure(failure)
        } catch {
            approval.finish()
            throw RecoveryClientError.signer("recovery_client_signer_failed")
        }

        defer { approval.finish() }

        do {
            return try credentials.signProductionRecoveryDigest(
                digest,
                tag: validated.record.keyTag,
                authenticationContext: context
            )
        } catch let error as RecoveryClientError {
            throw error
        } catch let failure as CompanionFailure {
            throw Self.mapApprovalFailure(failure)
        } catch {
            throw RecoveryClientError.signer("recovery_client_signer_failed")
        }
    }

    private static func mapApprovalFailure(_ failure: CompanionFailure) -> RecoveryClientError {
        switch failure {
        case .userCancelled, .approvalInvalidated:
            return .cancelled
        case .userDenied:
            return .signer("biometric_approval_denied")
        default:
            return .signer("recovery_client_signer_failed")
        }
    }
}

// MARK: - RecoverySigner actor

/// Actor boundary in front of the MainActor coordinator. Only the exact
/// 32-byte recomputed digest crosses in; only DER `Data` crosses back. No
/// `@unchecked Sendable`, no detached task, and no blocking async bridge.
///
/// Construct the MainActor coordinator on the MainActor (for example from
/// `CompanionModel`), then hand it to this actor. Default production wiring:
/// `ProductionRecoverySigner(coordinator: ProductionRecoverySigningCoordinator())`.
actor ProductionRecoverySigner: RecoverySigner {
    private let coordinator: any ProductionRecoverySigningCoordinating

    init(coordinator: any ProductionRecoverySigningCoordinating) {
        self.coordinator = coordinator
    }

    func signRecoveryDigest(_ digest: Data) async throws -> Data {
        try await coordinator.approveAndSignRecoveryDigest(digest)
    }
}

// MARK: - Secure Enclave production recovery accessors

extension SecureEnclaveCredentialManager: RecoveryCredentialAccessing {}
