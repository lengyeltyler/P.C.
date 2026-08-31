import CryptoKit
import Foundation
import LocalAuthentication
import XCTest
@testable import PhilCoreCompanion

// MARK: - Test-only approval and credential doubles
//
// These types live in the unit-test target only. They never evaluate a
// LocalAuthentication policy, never touch the real Keychain, and never open a
// network socket. Shipping-binary isolation is enforced by Package 3B/4 gates.

@MainActor
final class TestRecoveryApprovalManager: LocalRecoveryApproving {
    enum Behavior {
        case approve
        case cancel
        case deny
        case unavailable
    }

    private(set) var approveCallCount = 0
    private(set) var finishCallCount = 0
    private(set) var invalidateCallCount = 0
    var behavior: Behavior = .approve
    private var activeContext: LAContext?

    func approve(reason: String) async throws -> LAContext {
        approveCallCount += 1
        _ = reason
        switch behavior {
        case .approve:
            let context = LAContext()
            activeContext = context
            return context
        case .cancel:
            throw CompanionFailure.userCancelled
        case .deny:
            throw CompanionFailure.userDenied
        case .unavailable:
            throw CompanionFailure.deviceSecurityUnavailable
        }
    }

    func finish() {
        finishCallCount += 1
        activeContext = nil
    }

    func invalidate() {
        invalidateCallCount += 1
        activeContext?.invalidate()
        activeContext = nil
    }
}

@MainActor
final class InMemoryRecoveryCredentialAccess: RecoveryCredentialAccessing {
    var record: PublicCredentialRecord?
    var actualPublicKeyBytes: Data?
    var privateKey: P256.Signing.PrivateKey?
    private(set) var signCallCount = 0
    private(set) var lastSignedDigest: Data?
    var missingExactKey = false

    func loadActiveRecoveryPublicRecord() -> PublicCredentialRecord? {
        record
    }

    func copyActualProductionRecoveryPublicKeyBytes(tag: String) throws -> Data {
        guard !missingExactKey else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        guard let record, record.keyTag == tag, let actualPublicKeyBytes else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        return actualPublicKeyBytes
    }

    func signProductionRecoveryDigest(
        _ digest: Data,
        tag: String,
        authenticationContext: LAContext
    ) throws -> Data {
        _ = authenticationContext
        guard !missingExactKey else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        guard let record, record.keyTag == tag, let privateKey else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        guard digest.count == 32 else {
            throw RecoveryClientError.signer("recovery_client_signer_failed")
        }
        signCallCount += 1
        lastSignedDigest = digest
        return try privateKey.signature(for: digest).derRepresentation
    }
}

enum ProductionRecoverySignerTestSupport {
    static func validCommitment() -> String {
        String(repeating: "11", count: 32) // exactly 64 lowercase hex chars
    }

    /// Desktop pairing producer shape: exactly 64 lowercase hex chars, no `0x`.
    static func desktopProducerCommitment() -> String {
        String(repeating: "11", count: 32)
    }

    static func productionRecord(
        generation: UInt64 = 1,
        keyTag: String? = nil,
        publicKeyX963: String,
        publicFingerprint: String,
        schemaVersion: Int = 1,
        enrollmentState: EnrollmentState = .production,
        simulatorOnly: Bool = false,
        secureEnclaveBacked: Bool = true,
        pairedIdentityCommitment: String? = validCommitment()
    ) -> PublicCredentialRecord {
        PublicCredentialRecord(
            schemaVersion: schemaVersion,
            generation: generation,
            keyTag: keyTag
                ?? "\(SecureEnclaveCredentialManager.productionTagPrefix).g\(generation)",
            publicKeyX963: publicKeyX963,
            publicFingerprint: publicFingerprint,
            simulatorOnly: simulatorOnly,
            secureEnclaveBacked: secureEnclaveBacked,
            enrollmentState: enrollmentState,
            pairedIdentityCommitment: pairedIdentityCommitment,
            lastSuccessfulTestAt: nil
        )
    }

    static func softwareKeyMaterial() -> (P256.Signing.PrivateKey, Data, String, String) {
        let privateKey = P256.Signing.PrivateKey()
        let bytes = privateKey.publicKey.x963Representation
        return (
            privateKey,
            bytes,
            CryptoSupport.base64URL(bytes),
            CryptoSupport.fingerprint(bytes)
        )
    }
}

// MARK: - RG3 — Credential invariants

final class ProductionRecoveryCredentialValidationTests: XCTestCase {
    func testRejectsMissingRecord() {
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: nil)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_missing")
            )
        }
    }

    func testRejectsUnsupportedSchema() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            schemaVersion: 2
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_schema_unsupported")
            )
        }
    }

    func testRejectsNonproductionEnrollment() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            enrollmentState: .pairedTest
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_nonproduction")
            )
        }
    }

    func testRejectsSimulatorOnlyCredential() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            simulatorOnly: true
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_simulator_only")
            )
        }
    }

    func testRejectsNonSecureEnclaveBackedCredential() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            secureEnclaveBacked: false
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_not_secure_enclave")
            )
        }
    }

    func testRejectsGenerationZero() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            generation: 0,
            keyTag: "\(SecureEnclaveCredentialManager.productionTagPrefix).g0",
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_generation_zero")
            )
        }
    }

    func testRejectsTagGenerationMismatch() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            generation: 2,
            keyTag: "\(SecureEnclaveCredentialManager.productionTagPrefix).g1",
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_tag_mismatch")
            )
        }
    }

    func testRejectsLeadingZeroNoncanonicalGenerationTag() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            generation: 1,
            keyTag: "\(SecureEnclaveCredentialManager.productionTagPrefix).g01",
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_tag_noncanonical")
            )
        }
    }

    func testRejectsDisposableTag() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            keyTag: SecureEnclaveCredentialManager.disposableTag,
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_disposable_tag")
            )
        }
    }

    func testRejectsMissingMalformedUppercaseNonhexOrZeroCommitment() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let cases: [(String?, String)] = [
            (nil, "recovery_credential_commitment_invalid"),
            ("", "recovery_credential_commitment_invalid"),
            ("0x" + String(repeating: "11", count: 32), "recovery_credential_commitment_invalid"),
            (String(repeating: "11", count: 31), "recovery_credential_commitment_invalid"),
            (String(repeating: "gg", count: 32), "recovery_credential_commitment_invalid"),
            (String(repeating: "AA", count: 32), "recovery_credential_commitment_invalid"),
            (String(repeating: "0", count: 64), "recovery_credential_commitment_invalid")
        ]
        for (commitment, token) in cases {
            let record = ProductionRecoverySignerTestSupport.productionRecord(
                publicKeyX963: material.2,
                publicFingerprint: material.3,
                pairedIdentityCommitment: commitment
            )
            XCTAssertThrowsError(
                try ProductionRecoveryCredentialValidator.validateForSigning(record: record),
                "commitment case \(String(describing: commitment))"
            ) { error in
                XCTAssertEqual(
                    error as? RecoveryClientError,
                    RecoveryClientError.signer(token),
                    "commitment case \(String(describing: commitment))"
                )
            }
        }
    }

    /// Commit 3 RG — Desktop stores a bare 64-lowercase-hex commitment. The
    /// Commit 2 validator incorrectly requires a `0x` prefix and rejects the
    /// real producer shape.
    func testAcceptsDesktopProducerBareLowercaseCommitment() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            pairedIdentityCommitment: ProductionRecoverySignerTestSupport.desktopProducerCommitment()
        )
        XCTAssertNoThrow(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        )
    }

    /// Commit 3 RG — a `0x`-prefixed commitment must be rejected; it is not the
    /// Desktop pairing producer canonical form.
    func testRejectsPrefixedPairedIdentityCommitment() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            pairedIdentityCommitment: "0x" + String(repeating: "11", count: 32)
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_commitment_invalid")
            )
        }
    }

    /// Commit 3 RG — concrete Simulator production path must refuse before any
    /// Keychain query, even when metadata looks production-ready.
    func testConcreteSimulatorProductionPathFailsClosedBeforeKeychain() throws {
#if !targetEnvironment(simulator)
        throw XCTSkip("Simulator-only fail-closed gate")
#else
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let manager = SecureEnclaveCredentialManager()
        let tag = "\(SecureEnclaveCredentialManager.productionTagPrefix).g1"
        // Forged production-looking metadata must not authorize the concrete path.
        _ = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3,
            pairedIdentityCommitment: ProductionRecoverySignerTestSupport.desktopProducerCommitment()
        )
        XCTAssertThrowsError(
            try manager.copyActualProductionRecoveryPublicKeyBytes(tag: tag)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_simulator_production_forbidden")
            )
        }
        XCTAssertThrowsError(
            try manager.signProductionRecoveryDigest(
                Data(repeating: 0x42, count: 32),
                tag: tag,
                authenticationContext: LAContext()
            )
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_simulator_production_forbidden")
            )
        }
#endif
    }

    /// Commit 3 RG — pre-prompt lookup must explicitly skip authentication UI;
    /// signing lookup must bind the provided context instead.
    func testProductionRecoveryKeyQueryPolicies() throws {
        let tag = "\(SecureEnclaveCredentialManager.productionTagPrefix).g1"
        let preflight = SecureEnclaveCredentialManager.productionRecoveryKeyQuery(
            tag: tag,
            authenticationContext: nil
        )
        XCTAssertEqual(
            preflight[kSecUseAuthenticationUI as String] as? String,
            kSecUseAuthenticationUISkip as String
        )
        XCTAssertNil(preflight[kSecUseAuthenticationContext as String])

        let context = LAContext()
        let signing = SecureEnclaveCredentialManager.productionRecoveryKeyQuery(
            tag: tag,
            authenticationContext: context
        )
        XCTAssertTrue(
            (signing[kSecUseAuthenticationContext as String] as AnyObject) === context
        )
        XCTAssertNil(
            signing[kSecUseAuthenticationUI as String],
            "context-bearing query must not reuse the preflight skip policy"
        )
    }

    func testMapsInteractionNotAllowedDistinctlyFromMissingKey() throws {
        XCTAssertEqual(
            SecureEnclaveCredentialManager.mapProductionRecoveryKeyStatus(errSecInteractionNotAllowed),
            RecoveryClientError.signer("recovery_credential_preflight_authentication_required")
        )
        XCTAssertEqual(
            SecureEnclaveCredentialManager.mapProductionRecoveryKeyStatus(errSecItemNotFound),
            RecoveryClientError.signer("recovery_credential_key_missing")
        )
    }

    func testRejectsMalformedOrNoncanonicalPublicKeyBase64URL() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let padded = material.2 + "=="
        let withPlus = material.2 + "+"
        let withSlash = "/" + material.2
        for bad in [padded, withPlus, withSlash, "%%%", ""] {
            let record = ProductionRecoverySignerTestSupport.productionRecord(
                publicKeyX963: bad,
                publicFingerprint: material.3
            )
            XCTAssertThrowsError(
                try ProductionRecoveryCredentialValidator.validateForSigning(record: record),
                "public key case \(bad)"
            ) { error in
                XCTAssertEqual(
                    error as? RecoveryClientError,
                    RecoveryClientError.signer("recovery_credential_public_key_invalid")
                )
            }
        }
    }

    func testRejectsWrongPublicKeyLengthOrPrefix() throws {
        let shortBytes = Data(repeating: 0x04, count: 32)
        let badPrefix = Data([0x02]) + Data(repeating: 0x11, count: 64)
        for bytes in [shortBytes, badPrefix] {
            let encoded = CryptoSupport.base64URL(bytes)
            let record = ProductionRecoverySignerTestSupport.productionRecord(
                publicKeyX963: encoded,
                publicFingerprint: CryptoSupport.fingerprint(bytes)
            )
            XCTAssertThrowsError(
                try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
            ) { error in
                XCTAssertEqual(
                    error as? RecoveryClientError,
                    RecoveryClientError.signer("recovery_credential_public_key_invalid")
                )
            }
        }
    }

    func testRejectsStoredVersusActualPublicKeyMismatch() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let other = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        let validated = try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.bindActualPublicKey(
                validated: validated,
                actualPublicKeyBytes: other.1
            )
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_public_key_mismatch")
            )
        }
    }

    func testRejectsFingerprintMismatch() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: "DEAD BEEF CAFE"
        )
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_fingerprint_mismatch")
            )
        }
    }

    func testRejectsMissingExactKeyDuringBind() throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        let validated = try ProductionRecoveryCredentialValidator.validateForSigning(record: record)
        XCTAssertThrowsError(
            try ProductionRecoveryCredentialValidator.bindActualPublicKey(
                validated: validated,
                actualPublicKeyBytes: nil
            )
        ) { error in
            XCTAssertEqual(
                error as? RecoveryClientError,
                RecoveryClientError.signer("recovery_credential_key_missing")
            )
        }
    }
}

// MARK: - Coordinator / actor isolation and RG4 mismatched active key

@MainActor
final class ProductionRecoverySignerCoordinatorTests: XCTestCase {
    func testCancelMapsToTypedCancelledWithoutPromptReuse() async throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let credentials = InMemoryRecoveryCredentialAccess()
        credentials.record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        credentials.actualPublicKeyBytes = material.1
        credentials.privateKey = material.0
        let approval = TestRecoveryApprovalManager()
        approval.behavior = .cancel
        let coordinator = ProductionRecoverySigningCoordinator(
            credentials: credentials,
            approval: approval
        )
        let digest = Data(repeating: 0x42, count: 32)
        do {
            _ = try await coordinator.approveAndSignRecoveryDigest(digest)
            XCTFail("expected cancellation")
        } catch let error as RecoveryClientError {
            XCTAssertEqual(error, .cancelled)
        }
        XCTAssertEqual(approval.approveCallCount, 1)
        XCTAssertEqual(approval.finishCallCount, 1)
        XCTAssertEqual(credentials.signCallCount, 0)
    }

    func testDenialMapsToBiometricApprovalDenied() async throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let credentials = InMemoryRecoveryCredentialAccess()
        credentials.record = ProductionRecoverySignerTestSupport.productionRecord(
            publicKeyX963: material.2,
            publicFingerprint: material.3
        )
        credentials.actualPublicKeyBytes = material.1
        credentials.privateKey = material.0
        let approval = TestRecoveryApprovalManager()
        approval.behavior = .deny
        let coordinator = ProductionRecoverySigningCoordinator(
            credentials: credentials,
            approval: approval
        )
        do {
            _ = try await coordinator.approveAndSignRecoveryDigest(Data(repeating: 0x7, count: 32))
            XCTFail("expected denial")
        } catch let error as RecoveryClientError {
            XCTAssertEqual(error, .signer("biometric_approval_denied"))
        }
        XCTAssertEqual(credentials.signCallCount, 0)
        XCTAssertEqual(approval.finishCallCount, 1)
    }

    func testInvalidCredentialDoesNotPrompt() async throws {
        let credentials = InMemoryRecoveryCredentialAccess()
        credentials.record = nil
        let approval = TestRecoveryApprovalManager()
        let coordinator = ProductionRecoverySigningCoordinator(
            credentials: credentials,
            approval: approval
        )
        do {
            _ = try await coordinator.approveAndSignRecoveryDigest(Data(repeating: 0x1, count: 32))
            XCTFail("expected missing credential")
        } catch let error as RecoveryClientError {
            XCTAssertEqual(error, .signer("recovery_credential_missing"))
        }
        XCTAssertEqual(approval.approveCallCount, 0)
        XCTAssertEqual(approval.finishCallCount, 0)
    }
}

final class ProductionRecoverySignerMismatchTests: XCTestCase {
    /// RG4 — local production metadata can be satisfied by an in-memory software
    /// P-256 key, but RecoveryClient still owns the O.44 trusted-key binding and
    /// must reject a mismatch before any approval encryption or `/complete`.
    func testMismatchedActiveKeyIsRejectedBeforeComplete() async throws {
        let material = ProductionRecoverySignerTestSupport.softwareKeyMaterial()
        let credentials = await MainActor.run { () -> InMemoryRecoveryCredentialAccess in
            let access = InMemoryRecoveryCredentialAccess()
            access.record = ProductionRecoverySignerTestSupport.productionRecord(
                publicKeyX963: material.2,
                publicFingerprint: material.3
            )
            access.actualPublicKeyBytes = material.1
            access.privateKey = material.0
            return access
        }
        let approval = await MainActor.run { TestRecoveryApprovalManager() }
        let coordinator = await MainActor.run {
            ProductionRecoverySigningCoordinator(credentials: credentials, approval: approval)
        }
        let productionSigner = ProductionRecoverySigner(coordinator: coordinator)

        // Trusted Role 1 key is a different P-256 key than the local signer.
        let trustedForeign = P256.Signing.PrivateKey().publicKey
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: trustedForeign
        )
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: productionSigner)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        let prePresentation = await client.status().presentation
        XCTAssertNotNil(prePresentation)

        await assertClientFailure(
            "mismatched active key",
            kind: .signer,
            matching: "^recovery_client_signer_public_key_mismatch$"
        ) {
            try await client.approve()
        }

        let signCount = await MainActor.run { credentials.signCallCount }
        let approveCount = await MainActor.run { approval.approveCallCount }
        XCTAssertEqual(signCount, 1, "local signer must be invoked once")
        XCTAssertEqual(approveCount, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
        XCTAssertNil(
            simulator.lastApprovalPlaintext,
            "fake Desktop must never process approval encryption"
        )
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertEqual(status.failureReason, "recovery_client_signer_public_key_mismatch")
        XCTAssertNil(status.presentation, "terminal presentation must be cleared")
    }

    func testExpandedPresentationUsesOnlyValidatedContext() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: simulator)
        let status = await client.status()
        let presentation = try XCTUnwrap(status.presentation)

        XCTAssertEqual(
            presentation.accountAddress,
            simulator.validation.request.context.account
        )
        XCTAssertEqual(
            presentation.chainId,
            simulator.validation.request.context.chainId
        )
        XCTAssertEqual(
            presentation.recoveryEpoch,
            simulator.validation.request.context.recoveryEpoch
        )
        XCTAssertEqual(presentation.sessionId, simulator.sessionId)
        XCTAssertEqual(presentation.actionText, simulator.validation.actionText)
        XCTAssertEqual(presentation.networkText, simulator.validation.networkText)
        XCTAssertEqual(
            presentation.comparisonFingerprint,
            simulator.validation.comparisonFingerprint
        )
        XCTAssertEqual(
            presentation.factorBitmap,
            simulator.validation.request.context.factorBitmap
        )
        XCTAssertEqual(presentation.completionEndpoint, simulator.completionEndpoint)

        let mirrored = String(describing: presentation)
        XCTAssertFalse(mirrored.contains(simulator.canonicalRequest.prefix(8).map { String(format: "%02x", $0) }.joined()))
        XCTAssertFalse(mirrored.contains("derRecoverySignature"))
        XCTAssertFalse(mirrored.contains("ciphertext"))
    }
}
