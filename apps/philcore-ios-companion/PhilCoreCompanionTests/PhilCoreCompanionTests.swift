import CryptoKit
import XCTest
@testable import PhilCoreCompanion

final class PhilCoreCompanionTests: XCTestCase {
    func testPassCStatePresentationUsesExplicitLabelsAndDistinctIcons() {
        let states: [(PhilStateTone, String)] = [
            (.success, "Success"),
            (.warning, "Warning"),
            (.blocked, "Blocked"),
            (.rejected, "Rejected"),
            (.failed, "Failed"),
            (.unknown, "Status unknown")
        ]
        XCTAssertEqual(states.map { $0.0.label }, states.map { $0.1 })
        XCTAssertEqual(Set(states.map { $0.0.icon }).count, states.count)
    }

    func testPassBPhilGuidanceAndFailureCopyRemainPlainAndFailClosed() {
        XCTAssertTrue(PhilBetaGuidance.identity.contains("security sidekick"))
        XCTAssertTrue(PhilBetaGuidance.controlledBeta.contains("test-only assets"))
        XCTAssertTrue(PhilBetaGuidance.controlledBeta.contains("not mainnet or production custody"))
        XCTAssertTrue(PhilBetaGuidance.reviewOnPhone.contains("maximum cost"))
        XCTAssertTrue(PhilBetaGuidance.localProof.contains("matches your protected identity"))
        XCTAssertTrue(PhilBetaGuidance.protectedSigning.contains("only for the action you approved"))
        XCTAssertEqual(PhilBetaGuidance.failureMessage(.userDenied), PhilBetaGuidance.rejected)
        XCTAssertEqual(PhilBetaGuidance.failureMessage(.expired), PhilBetaGuidance.expired)
        XCTAssertTrue(PhilBetaGuidance.failureMessage(.presentationMismatch).contains("did not match"))
        XCTAssertTrue(PhilBetaGuidance.providerDisagreement.contains("do not retry"))
        XCTAssertTrue(PhilBetaGuidance.ambiguousPublicStatus.contains("Do not retry"))
        XCTAssertFalse(PhilBetaGuidance.failureMessage(.transportFailure).localizedCaseInsensitiveContains("failed safely"))
        XCTAssertEqual(PhilBetaGuidance.recoveryDeferred, "Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared.")
        let expiry = PhilBetaGuidance.expiryText(1_900_000_000)
        XCTAssertTrue(expiry.contains("2030"))
        XCTAssertFalse(expiry.contains("1900000000"))
    }

    func testControlledBetaClaimLock() {
        XCTAssertEqual(ControlledBetaRelease.title, "Controlled Sepolia Beta")
        XCTAssertEqual(ControlledBetaRelease.network, "Ethereum Sepolia")
        XCTAssertEqual(ControlledBetaRelease.stage, "Completed")
        XCTAssertEqual(ControlledBetaRelease.finalNonce, "3")
        XCTAssertEqual(ControlledBetaRelease.entryPointDeposit, "0.001297280743685756 ETH")
        XCTAssertEqual(ControlledBetaRelease.recovery, "Deferred")
        XCTAssertTrue(ControlledBetaRelease.safetyBoundary.contains("Not mainnet"))
        XCTAssertTrue(ControlledBetaRelease.cryptographyBoundary.contains("not currently post-quantum secure"))
        XCTAssertEqual(Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String, "Phil — Controlled Sepolia Beta")
    }

    func testPassDFinalAboutEvidenceIsCanonicalAndSecretFree() {
        XCTAssertEqual(ControlledBetaEvidence.release, "controlled-sepolia-beta-2026-08-29")
        XCTAssertEqual(ControlledBetaEvidence.smartAccount, "0xb72053013089F089502B075009c0BD807349eCC6")
        XCTAssertEqual(ControlledBetaEvidence.entryPoint, "0x0000000071727De22E5E9d8BAf0edAc6f37da032 · v0.7")
        XCTAssertEqual(ControlledBetaEvidence.p2Block, "11573471")
        XCTAssertEqual(ControlledBetaEvidence.p3Block, "11579252")
        XCTAssertEqual(ControlledBetaEvidence.p5Lineage, "p5-attempt-0002")
        XCTAssertTrue(ControlledBetaEvidence.reconciliation.contains("independent provider agreed"))
        XCTAssertEqual(ControlledBetaRelease.nativeBalance, "0 ETH")
        XCTAssertEqual(ControlledBetaRelease.passBalance, "2 test passes")

        let publicEvidence = [
            ControlledBetaEvidence.release,
            ControlledBetaEvidence.smartAccount,
            ControlledBetaEvidence.entryPoint,
            ControlledBetaEvidence.p2Transaction,
            ControlledBetaEvidence.p2UserOperation,
            ControlledBetaEvidence.p3Transaction,
            ControlledBetaEvidence.p3UserOperation,
            ControlledBetaEvidence.p5Transaction,
            ControlledBetaEvidence.p5UserOperation,
            ControlledBetaEvidence.reconciliation
        ].joined(separator: "\n").lowercased()
        for forbidden in ["private key", "api key", "authenticated url", "phil_secret", "witness", "nullifier seed", "recovery secret"] {
            XCTAssertFalse(publicEvidence.contains(forbidden), forbidden)
        }
    }

    private func request(
        expiresAt: Date = Date().addingTimeInterval(180),
        endpoint: String = "http://192.168.1.22:49321/philcore/pair/v1/complete"
    ) -> PairingRequest {
        PairingRequest(
            protocolVersion: 1,
            sessionId: String(repeating: "a", count: 43),
            expiresAt: ISO8601DateFormatter().string(from: expiresAt),
            endpoint: endpoint,
            desktopEphemeralPublicKey:
                CryptoSupport.base64URL(P256.KeyAgreement.PrivateKey().publicKey.x963Representation),
            challenge: CryptoSupport.base64URL(Data(repeating: 0x43, count: 32)),
            philCoreIdentityCommitment: String(repeating: "b", count: 64),
            accountVersionId: "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f",
            securityModelId: String(repeating: "c", count: 66),
            recoveryEpoch: 1,
            requestedGeneration: 1,
            applicationIdentity: PairingClient.applicationIdentity
        )
    }

    private func uri(_ request: PairingRequest) throws -> String {
        let encoded = CryptoSupport.base64URL(try JSONEncoder().encode(request))
        return "philcore://pair/v1?request=\(encoded)"
    }

    func testPairingRequestAcceptsOnlyPrivateIPv4Endpoint() async throws {
        let client = PairingClient()
        _ = try await client.parse(uri(request()))
        for endpoint in [
            "http://8.8.8.8:49321/philcore/pair/v1/complete",
            "https://192.168.1.22/philcore/pair/v1/complete",
            "http://127.0.0.1:49321/philcore/pair/v1/complete",
            "http://192.168.1.22:49321/not-philcore"
        ] {
            do {
                _ = try await client.parse(uri(request(endpoint: endpoint)))
                XCTFail("Unsafe endpoint accepted: \(endpoint)")
            } catch {
                XCTAssertEqual(error as? CompanionFailure, .insecureEndpoint)
            }
        }
    }

    func testPairingURLAcceptsCanonicalSingleRequestQuery() async throws {
        let client = PairingClient()
        let value = try uri(request())
        _ = try await client.parse(value)
    }

    func testPairingURLRejectsUnknownQueryItem() async throws {
        let client = PairingClient()
        let value = try uri(request()) + "&extra=1"
        do {
            _ = try await client.parse(value)
            XCTFail("Unknown query item accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsUnknownQueryItemBeforeRequest() async throws {
        let client = PairingClient()
        let encoded = CryptoSupport.base64URL(try JSONEncoder().encode(request()))
        let value = "philcore://pair/v1?extra=1&request=\(encoded)"
        do {
            _ = try await client.parse(value)
            XCTFail("Unknown leading query item accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsDuplicateRequestQueryItems() async throws {
        let client = PairingClient()
        let encoded = CryptoSupport.base64URL(try JSONEncoder().encode(request()))
        let value = "philcore://pair/v1?request=\(encoded)&request=\(encoded)"
        do {
            _ = try await client.parse(value)
            XCTFail("Duplicate request query items accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsDuplicateRequestWhenFirstIsValid() async throws {
        let client = PairingClient()
        let encoded = CryptoSupport.base64URL(try JSONEncoder().encode(request()))
        let value = "philcore://pair/v1?request=\(encoded)&request=not-valid"
        do {
            _ = try await client.parse(value)
            XCTFail("Duplicate request with valid first item accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsNonemptyFragment() async throws {
        let client = PairingClient()
        let value = try uri(request()) + "#frag"
        do {
            _ = try await client.parse(value)
            XCTFail("Nonempty fragment accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsEmptyFragment() async throws {
        let client = PairingClient()
        let value = try uri(request()) + "#"
        do {
            _ = try await client.parse(value)
            XCTFail("Empty fragment accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsMissingRequestValue() async throws {
        let client = PairingClient()
        do {
            _ = try await client.parse("philcore://pair/v1?request=")
            XCTFail("Empty request value accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .invalidRequest)
        }
    }

    func testPairingURLRejectsMalformedURLs() async throws {
        let client = PairingClient()
        for value in [
            "philcore://pair/v1",
            "philcore://pair/v1?other=abc",
            "https://pair/v1?request=abc",
            "philcore://pair/v2?request=abc",
            "philcore://other/v1?request=abc",
            "not-a-url"
        ] {
            do {
                _ = try await client.parse(value)
                XCTFail("Malformed pairing URL accepted: \(value)")
            } catch {
                XCTAssertEqual(error as? CompanionFailure, .invalidRequest, value)
            }
        }
    }

    func testExpiredRequestFailsClosed() async throws {
        let client = PairingClient()
        do {
            _ = try await client.parse(uri(request(expiresAt: Date().addingTimeInterval(-1))))
            XCTFail("Expired request accepted")
        } catch {
            XCTAssertEqual(error as? CompanionFailure, .expiredRequest)
        }
    }

    func testTranscriptAndFingerprintAreDeterministic() async {
        let client = PairingClient()
        let value = request()
        let first = await client.fingerprint(for: value)
        let second = await client.fingerprint(for: value)
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.split(separator: " ").count, 6)
        XCTAssertTrue(String(data: value.canonicalTranscript, encoding: .utf8)!
            .hasPrefix("PHILCORE_NATIVE_PAIRING_V1\n1\n"))
    }

    func testApplicationIdentityIsExactLocalAlphaDomain() {
        XCTAssertEqual(
            PairingClient.applicationIdentity,
            "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha"
        )
    }

    func testSimulatorCannotCreateProductionCandidate() throws {
#if targetEnvironment(simulator)
        XCTAssertThrowsError(
            try SecureEnclaveCredentialManager().createProductionCandidate(generation: 1)
        ) { error in
            XCTAssertEqual(error as? CompanionFailure, .secureEnclaveUnavailable)
        }
#endif
    }

    func testDisposableKeyExportBoundary() throws {
        let manager = SecureEnclaveCredentialManager()
        let record = try manager.createDisposableCredential(generation: 1)
#if targetEnvironment(simulator)
        XCTAssertTrue(record.simulatorOnly)
        XCTAssertFalse(record.secureEnclaveBacked)
#else
        XCTAssertFalse(manager.privateKeyExportPossibleForTest(record: record))
        XCTAssertTrue(record.secureEnclaveBacked)
#endif
        try manager.deleteActiveCredential()
        XCTAssertNil(manager.loadPublicRecord())
    }

    func testBase64URLRoundTrip() {
        let input = Data((0..<255).map(UInt8.init))
        let encoded = CryptoSupport.base64URL(input)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(CryptoSupport.decodeBase64URL(encoded), input)
    }
}
