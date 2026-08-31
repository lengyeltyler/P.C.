import CryptoKit
import XCTest
@testable import PhilCoreCompanion

final class RecoveryTranscriptFixtureTests: XCTestCase {
    private var o44: [String: Any] = [:]
    private var o45: [String: Any] = [:]
    private var bitmaps: [String: [String: Any]] = [:]

    /// Matches `approvalRequest.now` in O.44 and the `now` used by the O.45
    /// canonical-request negatives.
    private static let fixtureNow = "1700000100000"

    override func setUpWithError() throws {
        try super.setUpWithError()
        o44 = try RecoveryFixtures.fixtureObject(RecoveryFixtures.o44Resource, for: Self.self)
        o45 = try RecoveryFixtures.fixtureObject(RecoveryFixtures.o45Resource, for: Self.self)
        let raw = try XCTUnwrap(o45["bitmaps"] as? [String: Any])
        bitmaps = raw.compactMapValues { $0 as? [String: Any] }
    }

    private func approvalRequest() throws -> [String: Any] {
        try XCTUnwrap(o44["approvalRequest"] as? [String: Any])
    }

    private func canonicalBytes(from request: [String: Any]) throws -> Data {
        try RecoveryCanonicalRequest.serializeCanonical(
            jsonBytes: try RecoveryFixtures.canonicalJSON(request)
        )
    }

    private func o44Validated() throws -> RecoveryApprovalValidation {
        try RecoveryCanonicalRequest.parse(
            rawBytes: try canonicalBytes(from: try approvalRequest()),
            nowMilliseconds: Self.fixtureNow,
            expectedRequestHash: nil
        )
    }

    private func o45CanonicalBytes(_ key: String) throws -> Data {
        let entry = try XCTUnwrap(bitmaps[key])
        return RecoveryFixtures.hex(try XCTUnwrap(entry["canonicalRequestHex"] as? String))
    }

    private func o45CanonicalText(_ key: String) throws -> String {
        try XCTUnwrap(String(data: try o45CanonicalBytes(key), encoding: .utf8))
    }

    /// Flips the final hex nibble of a lowercase `0x…` value so a mutation stays
    /// well-formed (still bytes32) but no longer equals the recomputed value.
    private func flipLastNibble(_ hexValue: String) -> String {
        guard let last = hexValue.last, let digit = UInt8(String(last), radix: 16) else {
            return hexValue
        }
        return String(hexValue.dropLast()) + String(digit ^ 1, radix: 16)
    }

    // MARK: - Keccak-256 (Ethereum) known-answer vectors

    func testKeccak256KnownAnswerVectors() {
        let vectors: [(Data, String)] = [
            (Data(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (Data("abc".utf8), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
            (Data(String(repeating: "a", count: 1).utf8),
             "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"),
            (Data(String(repeating: "a", count: 135).utf8),
             "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),
            (Data(String(repeating: "a", count: 136).utf8),
             "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
            (Data(String(repeating: "a", count: 137).utf8),
             "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"),
            (Data(String(repeating: "a", count: 255).utf8),
             "d44e86b57c34f27dd6e59f94c47033054a745cb3266556066ea4bf687c70a568")
        ]
        for (input, expected) in vectors {
            XCTAssertEqual(
                RecoveryFixtures.hexString(RecoveryKeccak.keccak256(input)),
                expected,
                "keccak256 over \(input.count) byte input"
            )
        }
        // Ethereum Keccak-256 is not SHA3-256; the padding byte differs.
        XCTAssertNotEqual(
            RecoveryFixtures.hexString(RecoveryKeccak.keccak256(Data())),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        XCTAssertEqual(
            RecoveryFixtures.hexString(RecoveryKeccak.keccak256(utf8: "abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )
    }

    func testDerivedIdentityPinsMatchLockedLiterals() {
        XCTAssertEqual(
            RecoveryCanonicalRequest.accountVersionId,
            "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f"
        )
        XCTAssertEqual(
            RecoveryCanonicalRequest.securityModelId,
            "0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44"
        )
        XCTAssertEqual(
            RecoveryCanonicalRequest.nativeRecoveryDomainId,
            "0x61d93fd8e3d81d19a8ba4138c852ffa660d0e0ea23dc1dec452a43560b722f68"
        )
        XCTAssertEqual(
            RecoveryCanonicalRequest.applicationIdentity,
            "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha"
        )
        XCTAssertEqual(
            RecoveryCanonicalRequest.localApprovalPolicy,
            "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST"
        )
        XCTAssertEqual(RecoveryCanonicalRequest.wireTopLevelFieldCount, 19)
        XCTAssertEqual(RecoveryCanonicalRequest.contextFieldCount, 25)
        XCTAssertEqual(RecoveryCanonicalRequest.descriptorFieldCount, 15)
        XCTAssertEqual(RecoveryCanonicalRequest.nonWireFields, ["actionText", "networkText", "now"])
        XCTAssertEqual(RecoveryCanonicalRequest.transcriptLineCount, 44)
        XCTAssertEqual(RecoveryCanonicalRequest.maxWireBytes, 16384)
        XCTAssertEqual(
            RecoveryCanonicalRequest.completionEndpointPath,
            "/philcore/recovery/v1/complete"
        )
    }

    // MARK: - O.44 approval-request parity

    func testO44ApprovalRequestMatchesFixtureHashesAndTranscript() throws {
        let request = try approvalRequest()
        let bytes = try canonicalBytes(from: request)
        let validated = try RecoveryCanonicalRequest.parse(
            rawBytes: bytes,
            nowMilliseconds: Self.fixtureNow,
            expectedRequestHash: Data(SHA256.hash(data: bytes))
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(validated.contextHash),
            o44["contextHash"] as? String
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(validated.recoveryFactorDigest),
            o44["recoveryFactorDigest"] as? String
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(validated.transcriptHash),
            o44["transcriptHash"] as? String
        )
        XCTAssertEqual(validated.comparisonFingerprint, o44["comparisonFingerprint"] as? String)
        XCTAssertEqual(validated.actionText, request["actionText"] as? String)
        XCTAssertEqual(validated.networkText, request["networkText"] as? String)
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(validated.role1FactorCommitment),
            validated.request.context.hardwareSecurityKeyCommitment
        )
        XCTAssertEqual(validated.wireBytes, bytes)
        // Canonicalisation lowercases the mixed-case fixture entryPoint.
        XCTAssertEqual(
            validated.request.context.entryPoint,
            "0x00000000000000000000000000000000000f4337"
        )
    }

    func testTranscriptIsExactly44NewlineSeparatedLines() throws {
        let validated = try o44Validated()
        let text = try XCTUnwrap(String(data: validated.transcript, encoding: .utf8))
        let lines = text.components(separatedBy: "\n")
        XCTAssertEqual(lines.count, RecoveryCanonicalRequest.transcriptLineCount)
        XCTAssertEqual(lines.count, 44)
        XCTAssertEqual(lines[0], "PHILCORE_NATIVE_RECOVERY_APPROVAL_V1")
        XCTAssertEqual(lines[1], "1")
        XCTAssertEqual(lines[2], validated.request.context.envelopeVersion)
        XCTAssertEqual(lines[5], validated.request.context.factorBitmap)
        XCTAssertEqual(lines[27], RecoveryCanonicalRequest.accountVersionId)
        XCTAssertEqual(lines[30], RecoveryCanonicalRequest.applicationIdentity)
        XCTAssertEqual(lines[33], validated.request.selectedRole1CredentialGeneration)
        XCTAssertEqual(lines[34], "0x" + RecoveryFixtures.hexString(validated.contextHash))
        XCTAssertEqual(lines[35], "0x" + RecoveryFixtures.hexString(validated.recoveryFactorDigest))
        XCTAssertEqual(lines[36], validated.actionText)
        XCTAssertEqual(lines[37], validated.networkText)
        XCTAssertEqual(lines[41], validated.request.issuedAt)
        XCTAssertEqual(lines[42], validated.request.expiresAt)
        XCTAssertEqual(lines[43], validated.request.endpoint)
        XCTAssertFalse(lines.contains(where: { $0.contains("\r") }))
        XCTAssertEqual(
            RecoveryFixtures.hexString(Data(SHA256.hash(data: validated.transcript))),
            RecoveryFixtures.hexString(validated.transcriptHash)
        )
        XCTAssertEqual(
            RecoveryCanonicalRequest.comparisonFingerprint(
                transcriptHash: validated.transcriptHash
            ),
            validated.comparisonFingerprint
        )
        XCTAssertEqual(validated.comparisonFingerprint.split(separator: " ").count, 6)
        XCTAssertEqual(validated.comparisonFingerprint.replacingOccurrences(of: " ", with: "").count, 24)
    }

    // MARK: - O.45 canonical requests (bitmaps 3 and 6)

    func testO45CanonicalRequestsMatchFixtureTranscriptsForBothBitmaps() throws {
        for key in ["3", "6"] {
            let entry = try XCTUnwrap(bitmaps[key])
            let raw = try o45CanonicalBytes(key)
            let expectedHash = RecoveryFixtures.hex(
                try XCTUnwrap(entry["requestHashHex"] as? String)
            )
            let validated = try RecoveryCanonicalRequest.parse(
                rawBytes: raw,
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: expectedHash
            )
            XCTAssertEqual(validated.wireBytes, raw, "bitmap \(key) reserialize")
            XCTAssertEqual(validated.requestHash, expectedHash)
            XCTAssertEqual(
                "0x" + RecoveryFixtures.hexString(validated.transcriptHash),
                entry["o44TranscriptHash"] as? String,
                "bitmap \(key) transcript hash"
            )
            XCTAssertEqual(
                validated.comparisonFingerprint,
                entry["o44ComparisonFingerprint"] as? String
            )
            XCTAssertEqual(
                "0x" + RecoveryFixtures.hexString(validated.contextHash),
                validated.request.claimedContextHash
            )
            XCTAssertEqual(
                "0x" + RecoveryFixtures.hexString(validated.recoveryFactorDigest),
                validated.request.claimedRecoveryFactorDigest
            )
            XCTAssertEqual(
                "0x" + RecoveryFixtures.hexString(validated.role1FactorCommitment),
                validated.request.context.hardwareSecurityKeyCommitment
            )
            XCTAssertEqual(validated.request.context.factorBitmap, key)
            XCTAssertEqual(validated.actionText, "Recovery request")
            XCTAssertEqual(validated.networkText, "chain 31337")
            XCTAssertEqual(
                RecoveryBootstrap.encodeBase64URL(raw),
                entry["canonicalRequestBase64url"] as? String
            )
            XCTAssertEqual(
                validated.request.endpoint,
                entry["completionEndpoint"] as? String
            )
            XCTAssertEqual(
                try XCTUnwrap(entry["approvalRequestWireOmits"] as? [String]).sorted(),
                RecoveryCanonicalRequest.nonWireFields.sorted()
            )
        }
    }

    func testRole1PinsAndMinimalAbiWordHashes() throws {
        let validated = try o44Validated()
        let descriptor = validated.request.trustedRole1Descriptor
        XCTAssertEqual(descriptor.descriptorVersion, "1")
        XCTAssertEqual(descriptor.role, "1")
        XCTAssertEqual(descriptor.verifierKind, "4")
        XCTAssertTrue(descriptor.secureEnclaveRequired)
        XCTAssertFalse(descriptor.simulatorCredential)
        XCTAssertEqual(descriptor.accountVersionId, RecoveryCanonicalRequest.accountVersionId)
        XCTAssertEqual(descriptor.securityModelId, RecoveryCanonicalRequest.securityModelId)
        XCTAssertEqual(descriptor.recoveryDomainId, RecoveryCanonicalRequest.nativeRecoveryDomainId)
        XCTAssertEqual(
            descriptor.applicationIdentityHash,
            "0x" + RecoveryFixtures.hexString(
                Data(SHA256.hash(data: Data(RecoveryCanonicalRequest.applicationIdentity.utf8)))
            )
        )
        XCTAssertEqual(
            descriptor.localApprovalPolicyHash,
            "0x" + RecoveryFixtures.hexString(
                Data(SHA256.hash(data: Data(RecoveryCanonicalRequest.localApprovalPolicy.utf8)))
            )
        )
        XCTAssertEqual(
            descriptor.credentialIdentifierCommitment,
            validated.request.selectedRole1CredentialIdentifierCommitment
        )
        XCTAssertEqual(
            descriptor.credentialGeneration,
            validated.request.selectedRole1CredentialGeneration
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(
                try RecoveryCanonicalRequest.nativeP256PublicMaterialHash(
                    qx: validated.request.trustedRole1PublicKey.qx,
                    qy: validated.request.trustedRole1PublicKey.qy
                )
            ),
            descriptor.publicVerificationMaterialHash
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(
                try RecoveryCanonicalRequest.nativeRole1FactorCommitment(descriptor)
            ),
            validated.request.context.hardwareSecurityKeyCommitment
        )
        let context = validated.request.context
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(
                try RecoveryCanonicalRequest.consumerRecoveryConfigurationHashV3([
                    context.primaryDeviceCommitment,
                    context.hardwareSecurityKeyCommitment,
                    context.recoveryFactorCommitment
                ])
            ),
            context.currentRecoveryConfigHash
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(
                try RecoveryCanonicalRequest.consumerEvidenceContextHash(context)
            ),
            validated.request.claimedContextHash
        )
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(
                try RecoveryCanonicalRequest.recoveryFactorDigest(context)
            ),
            validated.request.claimedRecoveryFactorDigest
        )
    }

    // MARK: - Raw-byte gate (runs before any JSON parsing)

    func testRawByteGatePrecedesJsonParsing() throws {
        let bytes = try canonicalBytes(from: try approvalRequest())
        assertRecoveryFailure("empty body", matching: "length") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: Data(),
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: nil
            )
        }
        assertRecoveryFailure("oversized body", matching: "length") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: Data(repeating: 0x20, count: 16385),
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: nil
            )
        }
        assertRecoveryFailure("expected hash mismatch", matching: "hash_mismatch") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: bytes,
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: Data(repeating: 0x11, count: 32)
            )
        }
        assertRecoveryFailure("expected hash length", matching: "length") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: bytes,
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: Data(repeating: 0x11, count: 31)
            )
        }
        // Invalid UTF-8 must be rejected before any structural interpretation.
        assertRecoveryFailure("invalid utf8", matching: "utf8|json") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: Data([0x7b, 0xff, 0x7d]),
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: nil
            )
        }
        assertRecoveryFailure("array root", matching: "schema|json") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: Data("[]".utf8),
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: nil
            )
        }
    }

    // MARK: - Strict JSON policy

    func testDuplicateKeysRejectedAtTopLevelAndNestedLevels() throws {
        let text = try o45CanonicalText("6")
        let mutations: [(String, String, String)] = [
            ("top level", "\"protocolVersion\":1,",
             "\"protocolVersion\":1,\"protocolVersion\":1,"),
            ("nested context", "\"chainId\":\"31337\",",
             "\"chainId\":\"31337\",\"chainId\":\"31337\","),
            ("nested descriptor", "\"secureEnclaveRequired\":true,",
             "\"secureEnclaveRequired\":true,\"secureEnclaveRequired\":true,"),
            ("nested public key", "\"qx\":\"0xe835d314d0f2af818923659e61e301847df12c1b658b84305658a6acc9029643\",",
             "\"qx\":\"0xe835d314d0f2af818923659e61e301847df12c1b658b84305658a6acc9029643\",\"qx\":\"0xe835d314d0f2af818923659e61e301847df12c1b658b84305658a6acc9029643\",")
        ]
        for (label, needle, replacement) in mutations {
            let mutated = text.replacingOccurrences(of: needle, with: replacement)
            XCTAssertNotEqual(mutated, text, "mutation \(label) did not apply")
            assertRecoveryFailure("duplicate key \(label)", matching: "duplicate") {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: Data(mutated.utf8),
                    nowMilliseconds: Self.fixtureNow,
                    expectedRequestHash: nil
                )
            }
        }
    }

    func testNonWireFieldsAreRejectedWhenPresentInRawBytes() throws {
        let text = try o45CanonicalText("6")
        for field in RecoveryCanonicalRequest.nonWireFields {
            let mutated = text.replacingOccurrences(
                of: "\"protocolVersion\":1,",
                with: "\"\(field)\":\"1700000100000\",\"protocolVersion\":1,"
            )
            XCTAssertNotEqual(mutated, text)
            assertRecoveryFailure("non-wire field \(field)", matching: "reserialize|mismatch") {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: Data(mutated.utf8),
                    nowMilliseconds: Self.fixtureNow,
                    expectedRequestHash: nil
                )
            }
        }
    }

    func testUnknownMissingWrongTypeUppercaseAndNoncanonicalRejections() throws {
        let text = try o45CanonicalText("6")
        let cases: [(String, String, String, String)] = [
            ("unknown top-level field", "\"protocolVersion\":1,",
             "\"extraField\":\"forbidden\",\"protocolVersion\":1,", "unknown|unexpected"),
            ("unknown context field", "\"chainId\":\"31337\",",
             "\"chainId\":\"31337\",\"chainIdExtra\":\"1\",", "unknown|unexpected"),
            ("unknown descriptor field", "\"role\":\"1\",",
             "\"role\":\"1\",\"roleExtra\":\"1\",", "unknown|unexpected"),
            ("unknown public-key field", "\"qy\":",
             "\"qz\":\"0x00\",\"qy\":", "unknown|unexpected"),
            ("boolean field as string", "\"secureEnclaveRequired\":true",
             "\"secureEnclaveRequired\":\"true\"", "boolean"),
            ("boolean field as integer", "\"simulatorCredential\":false",
             "\"simulatorCredential\":0", "boolean"),
            ("noncanonical integer string", "\"chainId\":\"31337\"",
             "\"chainId\":\"031337\"", "noncanonical"),
            ("integer-shaped field as JSON number", "\"chainId\":\"31337\"",
             "\"chainId\":31337", "reserialize|mismatch"),
            ("null integer field", "\"chainId\":\"31337\"",
             "\"chainId\":null", "noncanonical|integer"),
            ("uppercase bytes32", "\"nativeRecoveryDomainId\":\"0x61d93fd8",
             "\"nativeRecoveryDomainId\":\"0x61D93FD8", "reserialize|mismatch"),
            ("checksummed mixed-case address",
             "\"entryPoint\":\"0x00000000000000000000000000000000000f4337\"",
             "\"entryPoint\":\"0x00000000000000000000000000000000000F4337\"",
             "reserialize|mismatch"),
            ("missing top-level field",
             "\"endpoint\":\"http://192.168.1.45:8787/philcore/recovery/v1/complete\",", "",
             "missing"),
            ("missing context field", ",\"validatorEpoch\":\"1\"", "", "missing")
        ]
        for (label, needle, replacement, pattern) in cases {
            let mutated = text.replacingOccurrences(of: needle, with: replacement)
            XCTAssertNotEqual(mutated, text, "mutation \(label) did not apply")
            assertRecoveryFailure(label, matching: pattern) {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: Data(mutated.utf8),
                    nowMilliseconds: Self.fixtureNow,
                    expectedRequestHash: nil
                )
            }
        }
    }

    func testClaimedValuesMustEqualRecomputedValues() throws {
        let text = try o45CanonicalText("6")
        let validated = try RecoveryCanonicalRequest.parse(
            rawBytes: Data(text.utf8),
            nowMilliseconds: Self.fixtureNow,
            expectedRequestHash: nil
        )
        let claimedPairs: [(String, String, String)] = [
            ("claimedContextHash", validated.request.claimedContextHash,
             "context_hash_mismatch|mismatch"),
            ("claimedRecoveryFactorDigest", validated.request.claimedRecoveryFactorDigest,
             "digest_mismatch|mismatch")
        ]
        for (label, value, pattern) in claimedPairs {
            let mutated = text.replacingOccurrences(
                of: "\"\(label)\":\"\(value)\"",
                with: "\"\(label)\":\"\(flipLastNibble(value))\""
            )
            XCTAssertNotEqual(mutated, text, "mutation \(label) did not apply")
            assertRecoveryFailure("claimed \(label)", matching: pattern) {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: Data(mutated.utf8),
                    nowMilliseconds: Self.fixtureNow,
                    expectedRequestHash: nil
                )
            }
        }
    }

    func testIdentityPinsAndBitmapAreEnforced() throws {
        let text = try o45CanonicalText("6")
        let pins: [(String, String, String)] = [
            ("nativeRecoveryDomainId", RecoveryCanonicalRequest.nativeRecoveryDomainId,
             "pin_mismatch|mismatch"),
            ("accountVersionId", RecoveryCanonicalRequest.accountVersionId, "pin_mismatch|mismatch"),
            ("securityModelId", RecoveryCanonicalRequest.securityModelId, "pin_mismatch|mismatch")
        ]
        for (field, value, pattern) in pins {
            let mutated = text.replacingOccurrences(
                of: "\"\(field)\":\"\(value)\"",
                with: "\"\(field)\":\"\(flipLastNibble(value))\""
            )
            XCTAssertNotEqual(mutated, text, "mutation \(field) did not apply")
            assertRecoveryFailure("pin \(field)", matching: pattern) {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: Data(mutated.utf8),
                    nowMilliseconds: Self.fixtureNow,
                    expectedRequestHash: nil
                )
            }
        }
        // Bitmap 5 excludes role 1, so the native phone path must refuse it.
        let bitmapFive = text.replacingOccurrences(
            of: "\"factorBitmap\":\"6\"",
            with: "\"factorBitmap\":\"5\""
        )
        XCTAssertNotEqual(bitmapFive, text)
        assertRecoveryFailure("bitmap 5", matching: "bitmap|mismatch|role") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: Data(bitmapFive.utf8),
                nowMilliseconds: Self.fixtureNow,
                expectedRequestHash: nil
            )
        }
    }

    func testFreshnessWindowBoundaries() throws {
        let raw = try o45CanonicalBytes("6")
        // issuedAt 1700000000000, expiresAt 1700000300000.
        for now in ["1700000000000", "1700000300000"] {
            XCTAssertNoThrow(
                try RecoveryCanonicalRequest.parse(
                    rawBytes: raw,
                    nowMilliseconds: now,
                    expectedRequestHash: nil
                ),
                "now \(now) should sit inside the freshness window"
            )
        }
        for now in ["1699999999999", "1700000300001"] {
            assertRecoveryFailure("now \(now)", matching: "expir|fresh|window") {
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: raw,
                    nowMilliseconds: now,
                    expectedRequestHash: nil
                )
            }
        }
        assertRecoveryFailure("noncanonical now", matching: "noncanonical") {
            _ = try RecoveryCanonicalRequest.parse(
                rawBytes: raw,
                nowMilliseconds: "01700000100000",
                expectedRequestHash: nil
            )
        }
    }

    func testEndpointPolicyIsPrivateHttpCompletionPathOnly() {
        XCTAssertTrue(
            RecoveryCanonicalRequest.isRfc1918ApprovalEndpoint(
                "http://192.168.1.45:8787/philcore/recovery/v1/complete"
            )
        )
        XCTAssertTrue(
            RecoveryCanonicalRequest.isRfc1918ApprovalEndpoint(
                "http://10.0.0.7:1024/philcore/recovery/v1/complete"
            )
        )
        for endpoint in [
            "https://192.168.1.45:8787/philcore/recovery/v1/complete",
            "http://8.8.8.8:8787/philcore/recovery/v1/complete",
            "http://127.0.0.1:8787/philcore/recovery/v1/complete",
            "http://169.254.1.1:8787/philcore/recovery/v1/complete",
            "http://192.168.1.45/philcore/recovery/v1/complete",
            "http://192.168.1.45:0/philcore/recovery/v1/complete",
            "http://192.168.1.45:8787/philcore/recovery/v1/request",
            "http://192.168.1.45:8787/philcore/recovery/v1/complete/",
            "http://192.168.1.45:8787/philcore/recovery/v1/complete?x=1",
            "http://192.168.1.45:8787/philcore/recovery/v1/complete#x",
            "http://user@192.168.1.45:8787/philcore/recovery/v1/complete",
            "http://user:pass@192.168.1.45:8787/philcore/recovery/v1/complete",
            "http://example.test:8787/philcore/recovery/v1/complete",
            "http://192.168.001.45:8787/philcore/recovery/v1/complete",
            "HTTP://192.168.1.45:8787/philcore/recovery/v1/complete",
            "http://192.168.1.45:8787/philcore/recovery/v1/complete\n",
            ""
        ] {
            XCTAssertFalse(
                RecoveryCanonicalRequest.isRfc1918ApprovalEndpoint(endpoint),
                "endpoint \(endpoint) must be rejected"
            )
        }
    }

    // MARK: - Every O.44 negative mutation

    func testAllO44NegativeMutations() throws {
        let negatives = try XCTUnwrap(o44["negativeMutations"] as? [[String: Any]])
        XCTAssertEqual(negatives.count, 16)
        for negative in negatives {
            let field = try XCTUnwrap(negative["field"] as? String)
            let pattern = try XCTUnwrap(negative["expectedError"] as? String)
            let request = try XCTUnwrap(negative["request"] as? [String: Any])
            let now = (request["now"] as? String) ?? Self.fixtureNow
            let json = try RecoveryFixtures.canonicalJSON(request)
            assertRecoveryFailure("o44 negative \(field)", matching: pattern) {
                let bytes = try RecoveryCanonicalRequest.serializeCanonical(jsonBytes: json)
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: bytes,
                    nowMilliseconds: now,
                    expectedRequestHash: nil
                )
            }
        }
    }

    /// The O.44 static-verifier negatives are scoped to the on-chain verifier.
    /// Only the four that mutate context fields the phone independently
    /// recomputes are applicable; the two envelope-byte cases are skipped
    /// because the Consumer-V3 phone path carries no recovery-envelope codec.
    func testApplicableStaticVerifierNegatives() throws {
        let negatives = try XCTUnwrap(o44["staticVerifierNegatives"] as? [[String: Any]])
        XCTAssertEqual(negatives.count, 6)
        let contextFieldForVerifierField = [
            "account": "account",
            "chainId": "chainId",
            "recoveryEpoch": "recoveryEpoch",
            "recoveryConfigHash": "currentRecoveryConfigHash"
        ]
        var applied: [String] = []
        var skipped: [String] = []
        for negative in negatives {
            let label = try XCTUnwrap(negative["label"] as? String)
            guard let override = negative["requestOverride"] as? [String: Any] else {
                skipped.append(label)
                continue
            }
            var request = try approvalRequest()
            var context = try XCTUnwrap(request["context"] as? [String: Any])
            var mapped = 0
            for (key, value) in override {
                guard let contextKey = contextFieldForVerifierField[key] else { continue }
                context[contextKey] = value
                mapped += 1
            }
            guard mapped == override.count else {
                skipped.append(label)
                continue
            }
            request["context"] = context
            let json = try RecoveryFixtures.canonicalJSON(request)
            let now = (request["now"] as? String) ?? Self.fixtureNow
            assertRecoveryFailure("static verifier \(label)", matching: "mismatch|invalid|must") {
                let bytes = try RecoveryCanonicalRequest.serializeCanonical(jsonBytes: json)
                _ = try RecoveryCanonicalRequest.parse(
                    rawBytes: bytes,
                    nowMilliseconds: now,
                    expectedRequestHash: nil
                )
            }
            applied.append(label)
        }
        XCTAssertEqual(
            applied.sorted(),
            ["wrong_account", "wrong_chain", "wrong_config_hash", "wrong_recovery_epoch"]
        )
        XCTAssertEqual(skipped.sorted(), ["truncated_envelope", "wrong_bitmap_via_byte_flip"])
    }

    // MARK: - Strict DER + low-S (parse only, never sign)

    func testDerLowSMatchesFixture() throws {
        let derLowS = try XCTUnwrap(o44["derLowS"] as? [String: Any])
        let alreadyLow = try XCTUnwrap(derLowS["alreadyLow"] as? [String: Any])
        let parsedLow = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(
            RecoveryFixtures.hex(try XCTUnwrap(alreadyLow["derHex"] as? String))
        )
        XCTAssertEqual(parsedLow.r, alreadyLow["r"] as? String)
        XCTAssertEqual(parsedLow.s, alreadyLow["s"] as? String)
        let normalizedLow = try RecoveryCanonicalRequest.normalizeLowS(parsedLow)
        XCTAssertEqual(normalizedLow.normalized, alreadyLow["normalized"] as? Bool)
        XCTAssertFalse(normalizedLow.normalized)
        XCTAssertEqual(normalizedLow.signature, parsedLow)

        let high = try XCTUnwrap(derLowS["initiallyHigh"] as? [String: Any])
        let parsedHigh = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(
            RecoveryFixtures.hex(try XCTUnwrap(high["derHex"] as? String))
        )
        XCTAssertEqual(parsedHigh.r, high["r"] as? String)
        XCTAssertEqual(parsedHigh.s, high["sBefore"] as? String)
        let normalizedHigh = try RecoveryCanonicalRequest.normalizeLowS(parsedHigh)
        XCTAssertEqual(normalizedHigh.normalized, high["normalized"] as? Bool)
        XCTAssertTrue(normalizedHigh.normalized)
        XCTAssertEqual(normalizedHigh.signature.r, high["r"] as? String)
        XCTAssertEqual(normalizedHigh.signature.s, high["sAfter"] as? String)
        // Normalisation is idempotent once low-S.
        XCTAssertFalse(
            try RecoveryCanonicalRequest.normalizeLowS(normalizedHigh.signature).normalized
        )
    }

    func testDerBoundaryRejections() throws {
        let derLowS = try XCTUnwrap(o44["derLowS"] as? [String: Any])
        let alreadyLow = try XCTUnwrap(derLowS["alreadyLow"] as? [String: Any])
        let valid = RecoveryFixtures.hex(try XCTUnwrap(alreadyLow["derHex"] as? String))
        XCTAssertEqual(valid.count, 71)

        var trailing = valid
        trailing.append(0x00)
        var wrongTag = valid
        wrongTag[0] = 0x31
        var nonMinimalLength = Data([0x30, 0x81, valid[1]])
        nonMinimalLength.append(valid[2...])

        let cases: [(String, Data, String)] = [
            ("trailing bytes", trailing, "trailing"),
            ("wrong sequence tag", wrongTag, "malformed"),
            ("non-minimal sequence length", nonMinimalLength, "nonminimal|malformed|trailing"),
            ("too short", Data(valid.prefix(6)), "malformed"),
            ("non-minimal integer", RecoveryFixtures.hex("30080202000102020001"), "nonminimal"),
            ("zero integer", RecoveryFixtures.hex("3006020100020101"), "zero|integer"),
            ("negative integer", RecoveryFixtures.hex("3006020180020101"), "negative"),
            ("integer at curve order", RecoveryFixtures.hex(
                "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
            ), "order")
        ]
        for (label, der, pattern) in cases {
            assertRecoveryFailure("der \(label)", matching: pattern) {
                _ = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(der)
            }
        }

        let zero = "0x" + String(repeating: "00", count: 32)
        let order = "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        let one = "0x" + String(repeating: "00", count: 31) + "01"
        assertRecoveryFailure("zero r", matching: "zero") {
            _ = try RecoveryCanonicalRequest.normalizeLowS(
                RecoveryCanonicalRequest.EcdsaP256Signature(r: zero, s: one)
            )
        }
        assertRecoveryFailure("zero s", matching: "zero") {
            _ = try RecoveryCanonicalRequest.normalizeLowS(
                RecoveryCanonicalRequest.EcdsaP256Signature(r: one, s: zero)
            )
        }
        assertRecoveryFailure("s at order", matching: "order|range") {
            _ = try RecoveryCanonicalRequest.normalizeLowS(
                RecoveryCanonicalRequest.EcdsaP256Signature(r: one, s: order)
            )
        }
        assertRecoveryFailure("r at order", matching: "order|range") {
            _ = try RecoveryCanonicalRequest.normalizeLowS(
                RecoveryCanonicalRequest.EcdsaP256Signature(r: order, s: one)
            )
        }
    }
}
