import Foundation
import LocalAuthentication
import Security
import UIKit
import XCTest
@testable import PhilCoreCompanion

/// Manual physical-device evidence for Phil V1 Step 2.
///
/// Run each method individually and in order. These tests create only one
/// disposable Secure Enclave key, synthetic digests, and one random in-memory
/// local-vault key. They never use a Phil root, recovery factor, account key,
/// network, external signer, or production authority.
final class PhilDeviceApprovalPhysicalCeremonyTests: XCTestCase {
    private static let generation: UInt64 = 2_026_082_101
    private let manager = PhilDeviceApprovalKeyManager()

    private struct Observation: Encodable {
        let schema: String
        let step: String
        let result: String
        let deviceClass: String
        let operatingSystem: String
        let secureEnclaveBacked: Bool
        let userPresenceRequired: Bool
        let elapsedMilliseconds: Int
        let batteryPercent: Int?
        let lowPowerMode: Bool
        let thermalState: String
        let physicalMemoryMiB: UInt64
        let networkActivity: Bool
        let realAuthorityUsed: Bool
    }

    private func requirePhysicalDevice() throws {
#if targetEnvironment(simulator)
        throw XCTSkip("Physical Secure Enclave ceremony only")
#endif
    }

    private func requiredRecord() throws -> PhilDeviceApprovalPublicRecord {
        let record = try XCTUnwrap(manager.loadPublicRecord(), "Ceremony candidate is missing")
        XCTAssertEqual(record.generation, Self.generation)
        XCTAssertTrue(record.secureEnclaveBacked)
        XCTAssertTrue(record.userPresenceRequired)
        XCTAssertEqual(record.signatureSuite, PhilDeviceApprovalKeyManager.signatureSuite)
        return record
    }

    private func context(_ reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        return context
    }

    private func syntheticDigest(_ label: String) -> Data {
        CryptoSupport.sha256(Data(label.utf8))
    }

    private func randomLocalVaultKey() throws -> Data {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
        guard status == errSecSuccess else { throw CompanionFailure.deviceSecurityUnavailable }
        return bytes
    }

    private func verifySignature(
        _ signature: Data,
        digest: Data,
        record: PhilDeviceApprovalPublicRecord
    ) throws -> Bool {
        let publicData = try XCTUnwrap(CryptoSupport.decodeBase64URL(record.publicKeyX963))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        let publicKey = try XCTUnwrap(
            SecKeyCreateWithData(publicData as CFData, attributes as CFDictionary, &error)
        )
        return SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            signature as CFData,
            &error
        )
    }

    private func thermalState() -> String {
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: "nominal"
        case .fair: "fair"
        case .serious: "serious"
        case .critical: "critical"
        @unknown default: "unknown"
        }
    }

    private func emit(
        step: String,
        elapsed: TimeInterval,
        record: PhilDeviceApprovalPublicRecord
    ) throws {
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        let batteryPercent = level < 0 ? nil : Int((level * 100).rounded())
        let observation = Observation(
            schema: "phil-step2-device-ceremony-observation-v1",
            step: step,
            result: "pass",
            deviceClass: UIDevice.current.model,
            operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString,
            secureEnclaveBacked: record.secureEnclaveBacked,
            userPresenceRequired: record.userPresenceRequired,
            elapsedMilliseconds: Int((elapsed * 1_000).rounded()),
            batteryPercent: batteryPercent,
            lowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
            thermalState: thermalState(),
            physicalMemoryMiB: ProcessInfo.processInfo.physicalMemory / 1_048_576,
            networkActivity: false,
            realAuthorityUsed: false
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(observation)
        print("PHIL_STEP2_CEREMONY_OBSERVATION \(String(decoding: data, as: UTF8.self))")
    }

    func test01CreateDisposableCandidateAndVerifyPresence() throws {
        try requirePhysicalDevice()
        let started = Date()
        let record = try manager.createProductionCandidate(generation: Self.generation)
        XCTAssertTrue(record.secureEnclaveBacked)
        XCTAssertTrue(record.userPresenceRequired)
        XCTAssertTrue(try manager.candidateExistsForTest(record: record))
        XCTAssertEqual(manager.loadPublicRecord(), record)
        try emit(step: "create-and-presence", elapsed: Date().timeIntervalSince(started), record: record)
    }

    func test02CancelUserPresenceWithoutSigning() throws {
        try requirePhysicalDevice()
        let record = try requiredRecord()
        let started = Date()
        do {
            _ = try manager.signApprovalDigest(
                syntheticDigest("PHIL_STEP2_CANCEL_SYNTHETIC_DIGEST_V1"),
                record: record,
                authenticationContext: context(
                    "Step 2 cancellation test: cancel this prompt. No Phil or account action is being approved."
                )
            )
            XCTFail("Cancellation prompt unexpectedly produced a signature")
            return
        } catch let failure as CompanionFailure {
            guard failure == .userCancelled || failure == .userDenied else {
                XCTFail("Cancellation returned an unexpected failure classification")
                return
            }
        }
        XCTAssertTrue(try manager.candidateExistsForTest(record: record))
        try emit(step: "user-presence-cancelled", elapsed: Date().timeIntervalSince(started), record: record)
    }

    func test03SignWrapUnwrapAndNonExportability() throws {
        try requirePhysicalDevice()
        let record = try requiredRecord()
        let started = Date()
        let digest = syntheticDigest("PHIL_STEP2_APPROVAL_SYNTHETIC_DIGEST_V1")
        let signature = try manager.signApprovalDigest(
            digest,
            record: record,
            authenticationContext: context(
                "Step 2 synthetic approval test. This does not authorize Phil, an account, or a network action."
            )
        )
        XCTAssertTrue(try verifySignature(signature, digest: digest, record: record))

        var localVaultKey = try randomLocalVaultKey()
        defer { localVaultKey.resetBytes(in: 0..<localVaultKey.count) }
        let wrapped = try manager.wrapLocalVaultKey(localVaultKey, record: record)
        XCTAssertNotEqual(wrapped, localVaultKey)
        var unwrapped = try manager.unwrapLocalVaultKey(
            wrapped,
            record: record,
            authenticationContext: context(
                "Step 2 synthetic local-vault unwrap test. No identity or recovery package is involved."
            )
        )
        defer { unwrapped.resetBytes(in: 0..<unwrapped.count) }
        XCTAssertEqual(unwrapped, localVaultKey)

        let exportPossible = try manager.privateKeyExportPossibleForTest(
            record: record,
            authenticationContext: context(
                "Step 2 non-exportability test. The private key must remain inside Secure Enclave."
            )
        )
        XCTAssertFalse(exportPossible)
        try emit(step: "sign-wrap-unwrap-nonexportable", elapsed: Date().timeIntervalSince(started), record: record)
    }

    /// Run after the app has been backgrounded/terminated and the phone has
    /// been locked/unlocked. Run the same method again after reboot/unlock.
    func test04VerifyPersistenceAfterInterruption() throws {
        try requirePhysicalDevice()
        let record = try requiredRecord()
        let started = Date()
        XCTAssertTrue(try manager.candidateExistsForTest(record: record))
        let digest = syntheticDigest("PHIL_STEP2_INTERRUPTION_SYNTHETIC_DIGEST_V1")
        let signature = try manager.signApprovalDigest(
            digest,
            record: record,
            authenticationContext: context(
                "Step 2 interruption recovery test. This signs only a synthetic test digest."
            )
        )
        XCTAssertTrue(try verifySignature(signature, digest: digest, record: record))
        try emit(step: "persistence-after-interruption", elapsed: Date().timeIntervalSince(started), record: record)
    }

    func test05DeleteCandidateAndVerifyAbsence() throws {
        try requirePhysicalDevice()
        let record = try requiredRecord()
        let started = Date()
        XCTAssertTrue(try manager.candidateExistsForTest(record: record))
        try manager.deleteProductionCandidate(record: record)
        XCTAssertFalse(try manager.candidateExistsForTest(record: record))
        XCTAssertNil(manager.loadPublicRecord())
        try emit(step: "delete-and-absence", elapsed: Date().timeIntervalSince(started), record: record)
    }
}
