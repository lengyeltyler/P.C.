import CryptoKit
import XCTest
@testable import PhilCoreCompanion

/// Shared fixture access for the Package 3A parity suites. Fixtures are
/// referenced from `config/cryptography` by the Xcode project and copied into
/// the unit-test bundle unmodified; they are never edited by these tests.
enum RecoveryFixtures {
    static let o44Resource = "O44_RECOVERY_TRANSPORT_FIXTURES"
    static let o45Resource = "O45_RECOVERY_BOOTSTRAP_FIXTURES"
    static let o44Sha256Hex =
        "50482c8e532db528b20eceed76eac181f0c94ca018d414f3a5f45add1942a98a"
    static let o45Sha256Hex =
        "e553c795561f0416754248a0746a70598c7680743ec6cb52b30769e4e4204fd2"

    static func fixtureData(_ resource: String, for owner: AnyClass) throws -> Data {
        guard let url = Bundle(for: owner).url(forResource: resource, withExtension: "json") else {
            throw RecoveryCodecError("fixture_resource_missing_\(resource)")
        }
        return try Data(contentsOf: url)
    }

    static func fixtureObject(_ resource: String, for owner: AnyClass) throws -> [String: Any] {
        let raw = try fixtureData(resource, for: owner)
        guard let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
            throw RecoveryCodecError("fixture_root_not_object_\(resource)")
        }
        return object
    }

    static func hex(_ value: String) -> Data {
        var text = Substring(value)
        if text.hasPrefix("0x") || text.hasPrefix("0X") {
            text = text.dropFirst(2)
        }
        var out = Data()
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2, limitedBy: text.endIndex) ?? text.endIndex
            guard next > index, let byte = UInt8(text[index..<next], radix: 16) else { return Data() }
            out.append(byte)
            index = next
        }
        return out
    }

    static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func canonicalJSON(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
    }
}

extension XCTestCase {
    func assertRecoveryFailure(
        _ label: String,
        matching pattern: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            XCTFail("\(label): expected rejection matching /\(pattern)/", file: file, line: line)
        } catch let error as RecoveryCodecError {
            XCTAssertNotNil(
                error.reason.range(of: pattern, options: [.regularExpression, .caseInsensitive]),
                "\(label): reason '\(error.reason)' does not match /\(pattern)/",
                file: file,
                line: line
            )
        } catch {
            XCTFail("\(label): unexpected error type \(error)", file: file, line: line)
        }
    }
}

final class RecoveryBootstrapFixtureTests: XCTestCase {
    private var o45: [String: Any] = [:]
    private var bitmaps: [String: [String: Any]] = [:]

    override func setUpWithError() throws {
        try super.setUpWithError()
        o45 = try RecoveryFixtures.fixtureObject(RecoveryFixtures.o45Resource, for: Self.self)
        let raw = try XCTUnwrap(o45["bitmaps"] as? [String: Any])
        bitmaps = raw.compactMapValues { $0 as? [String: Any] }
    }

    private func bitmap(_ key: String) throws -> [String: Any] {
        try XCTUnwrap(bitmaps[key], "missing bitmap fixture \(key)")
    }

    private func ticketFixture(_ key: String) throws -> [String: Any] {
        try XCTUnwrap(try bitmap(key)["ticket"] as? [String: Any])
    }

    // MARK: - Fixture integrity

    func testFixtureFilesAreByteIdenticalToRepositoryDigests() throws {
        let o44 = try RecoveryFixtures.fixtureData(RecoveryFixtures.o44Resource, for: Self.self)
        let o45Raw = try RecoveryFixtures.fixtureData(RecoveryFixtures.o45Resource, for: Self.self)
        XCTAssertEqual(
            RecoveryFixtures.hexString(Data(SHA256.hash(data: o44))),
            RecoveryFixtures.o44Sha256Hex
        )
        XCTAssertEqual(
            RecoveryFixtures.hexString(Data(SHA256.hash(data: o45Raw))),
            RecoveryFixtures.o45Sha256Hex
        )
    }

    func testProtocolConstantsMatchFixture() throws {
        let constants = try XCTUnwrap(o45["protocolConstants"] as? [String: Any])
        XCTAssertEqual(constants["magic"] as? String, RecoveryBootstrap.magic)
        XCTAssertEqual(constants["version"] as? Int, Int(RecoveryBootstrap.version))
        XCTAssertEqual(constants["ticketBytes"] as? Int, RecoveryBootstrap.ticketByteCount)
        XCTAssertEqual(constants["uriPrefix"] as? String, RecoveryBootstrap.uriPrefix)
        XCTAssertEqual(constants["uriBytes"] as? Int, RecoveryBootstrap.uriByteCount)
        XCTAssertEqual(constants["requestPath"] as? String, RecoveryBootstrap.requestEndpointPath)
        XCTAssertEqual(
            constants["completionPath"] as? String,
            RecoveryBootstrap.completionEndpointPath
        )
        XCTAssertEqual(constants["hkdfInfo"] as? String, RecoveryBootstrap.requestHKDFInfo)
        XCTAssertEqual(
            constants["aadDesktopToPhone"] as? String,
            RecoveryBootstrap.requestAADDesktopToPhone
        )
        XCTAssertEqual(constants["maxTtlSeconds"] as? Int, Int(RecoveryBootstrap.maxTicketTTLSeconds))
        XCTAssertEqual(
            constants["clockSkewSeconds"] as? Int,
            Int(RecoveryBootstrap.ticketClockSkewSeconds)
        )
        XCTAssertEqual(constants["maxWireBytes"] as? Int, RecoveryBootstrap.maxRequestWireBytes)
        XCTAssertEqual(constants["protocolVersion"] as? Int, RecoveryBootstrap.protocolVersion)
        XCTAssertEqual(o45["nativeApprovalBitmaps"] as? [Int], [3, 6])
        XCTAssertEqual(RecoveryBootstrap.uriPrefix.utf8.count, 21)
    }

    // MARK: - PRB1 ticket + URI parity (bitmaps 3 and 6)

    func testTicketEncodeDecodeAndUriParityForBothBitmaps() throws {
        for key in ["3", "6"] {
            let entry = try bitmap(key)
            let ticketFields = try ticketFixture(key)
            let expectedTicket = RecoveryFixtures.hex(try XCTUnwrap(entry["rawTicketHex"] as? String))
            let expectedURI = try XCTUnwrap(entry["uri"] as? String)

            let encoded = try RecoveryBootstrap.encodeTicket(
                sessionId: RecoveryFixtures.hex(try XCTUnwrap(ticketFields["sessionIdHex"] as? String)),
                expiresAt: try XCTUnwrap(UInt64(try XCTUnwrap(ticketFields["expiresAt"] as? String))),
                ipv4Text: try XCTUnwrap(ticketFields["ipv4"] as? String),
                port: try XCTUnwrap(ticketFields["port"] as? Int),
                desktopEphemeralPublicKeyBase64URL:
                    try XCTUnwrap(ticketFields["desktopEphemeralPublicKeyBase64url"] as? String),
                requestHash: RecoveryFixtures.hex(
                    try XCTUnwrap(ticketFields["requestHashHex"] as? String)
                )
            )
            XCTAssertEqual(encoded, expectedTicket, "bitmap \(key) ticket bytes")
            XCTAssertEqual(encoded.count, 148)

            let decoded = try RecoveryBootstrap.decodeTicket(expectedTicket)
            XCTAssertEqual(decoded.magic, "PRB1")
            XCTAssertEqual(decoded.version, 1)
            XCTAssertEqual(
                RecoveryFixtures.hexString(decoded.sessionId),
                try XCTUnwrap(ticketFields["sessionIdHex"] as? String)
            )
            XCTAssertEqual(String(decoded.expiresAt), try XCTUnwrap(ticketFields["expiresAt"] as? String))
            XCTAssertEqual(decoded.ipv4Text, try XCTUnwrap(ticketFields["ipv4"] as? String))
            XCTAssertEqual(Int(decoded.port), try XCTUnwrap(ticketFields["port"] as? Int))
            XCTAssertEqual(
                RecoveryBootstrap.encodeBase64URL(decoded.desktopEphemeralPublicKey),
                try XCTUnwrap(ticketFields["desktopEphemeralPublicKeyBase64url"] as? String)
            )
            XCTAssertEqual(
                RecoveryFixtures.hexString(decoded.requestHash),
                try XCTUnwrap(ticketFields["requestHashHex"] as? String)
            )
            XCTAssertEqual(try RecoveryBootstrap.encodeTicket(decoded), expectedTicket)

            let uri = try RecoveryBootstrap.formatURI(ticketBytes: expectedTicket)
            XCTAssertEqual(uri, expectedURI, "bitmap \(key) uri")
            XCTAssertEqual(uri.utf8.count, 219)
            XCTAssertTrue(uri.hasPrefix(RecoveryBootstrap.uriPrefix))
            XCTAssertEqual(uri.utf8.count - RecoveryBootstrap.uriPrefix.utf8.count, 198)
            XCTAssertEqual(try RecoveryBootstrap.parseURI(uri), expectedTicket)
            XCTAssertEqual(
                RecoveryBootstrap.encodeBase64URL(expectedTicket),
                try XCTUnwrap(entry["rawTicketBase64url"] as? String)
            )

            let sizes = try XCTUnwrap(entry["sizes"] as? [String: Any])
            XCTAssertEqual(sizes["rawTicketBytes"] as? Int, 148)
            XCTAssertEqual(sizes["uriBytes"] as? Int, 219)
        }
    }

    func testTicketRequestHashBindsCanonicalRequestForBothBitmaps() throws {
        for key in ["3", "6"] {
            let entry = try bitmap(key)
            let canonical = RecoveryFixtures.hex(
                try XCTUnwrap(entry["canonicalRequestHex"] as? String)
            )
            let expected = try XCTUnwrap(entry["requestHashHex"] as? String)
            XCTAssertEqual(
                RecoveryFixtures.hexString(Data(SHA256.hash(data: canonical))),
                expected,
                "bitmap \(key) request hash"
            )
            let ticket = try RecoveryBootstrap.decodeTicket(
                RecoveryFixtures.hex(try XCTUnwrap(entry["rawTicketHex"] as? String))
            )
            XCTAssertEqual(RecoveryFixtures.hexString(ticket.requestHash), expected)
            let sizes = try XCTUnwrap(entry["sizes"] as? [String: Any])
            XCTAssertEqual(sizes["requestBytes"] as? Int, canonical.count)
        }
    }

    func testEndpointsDerivedFromTicket() throws {
        for key in ["3", "6"] {
            let entry = try bitmap(key)
            let ticket = try RecoveryBootstrap.decodeTicket(
                RecoveryFixtures.hex(try XCTUnwrap(entry["rawTicketHex"] as? String))
            )
            XCTAssertEqual(
                try RecoveryBootstrap.requestEndpoint(ticket: ticket),
                try XCTUnwrap(entry["requestEndpoint"] as? String)
            )
            XCTAssertEqual(
                try RecoveryBootstrap.completionEndpoint(ticket: ticket),
                try XCTUnwrap(entry["completionEndpoint"] as? String)
            )
        }
    }

    // MARK: - Expiry, TTL, skew and bound-request policy

    func testTicketPolicyBoundariesUseInjectedClock() throws {
        let entry = try bitmap("6")
        let ticket = try RecoveryBootstrap.decodeTicket(
            RecoveryFixtures.hex(try XCTUnwrap(entry["rawTicketHex"] as? String))
        )
        let expiresAt = ticket.expiresAt

        try RecoveryBootstrap.validateTicketPolicy(
            ticket: ticket,
            nowSeconds: expiresAt - 1,
            boundRequestExpiresAtMilliseconds: nil
        )
        assertRecoveryFailure("now == expiresAt", matching: "expir") {
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: ticket,
                nowSeconds: expiresAt,
                boundRequestExpiresAtMilliseconds: nil
            )
        }
        assertRecoveryFailure("now > expiresAt", matching: "expir") {
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: ticket,
                nowSeconds: expiresAt + 1,
                boundRequestExpiresAtMilliseconds: nil
            )
        }

        // TTL (300) + skew (60) upper bound is inclusive.
        try RecoveryBootstrap.validateTicketPolicy(
            ticket: ticket,
            nowSeconds: expiresAt - 360,
            boundRequestExpiresAtMilliseconds: nil
        )
        assertRecoveryFailure("ttl+skew exceeded", matching: "ttl|skew") {
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: ticket,
                nowSeconds: expiresAt - 361,
                boundRequestExpiresAtMilliseconds: nil
            )
        }

        // Bound request floors milliseconds to whole seconds.
        try RecoveryBootstrap.validateTicketPolicy(
            ticket: ticket,
            nowSeconds: expiresAt - 100,
            boundRequestExpiresAtMilliseconds: String(expiresAt * 1000 + 999)
        )
        assertRecoveryFailure("bound request outlived", matching: "bound|outlive") {
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: ticket,
                nowSeconds: expiresAt - 100,
                boundRequestExpiresAtMilliseconds: String(expiresAt * 1000 - 1)
            )
        }
    }

    // MARK: - Strict base64url

    func testStrictBase64UrlRejectsPaddingAlphabetAndNonCanonicalTails() throws {
        let sample = Data([0x01, 0x02, 0x03, 0x04])
        let encoded = RecoveryBootstrap.encodeBase64URL(sample)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(try RecoveryBootstrap.decodeBase64URLCanonical(encoded, exactLength: 4), sample)

        // 65-byte P-256 encodings end on a 2-bit remainder; "BQ" is canonical, "BR" is not.
        XCTAssertEqual(try RecoveryBootstrap.decodeBase64URLCanonical("BQ", exactLength: 1), Data([0x05]))
        for invalid in ["BR", "AQ==", "AQ=", "A+/A", "AQ ", "AQ\n", "", "AQI/"] {
            assertRecoveryFailure("base64url '\(invalid)'", matching: "base64url|length") {
                _ = try RecoveryBootstrap.decodeBase64URLCanonical(invalid, exactLength: nil)
            }
        }
        assertRecoveryFailure("wrong exact length", matching: "length") {
            _ = try RecoveryBootstrap.decodeBase64URLCanonical(encoded, exactLength: 5)
        }
    }

    // MARK: - Independent strict IPv4

    func testStrictPrivateIPv4Policy() throws {
        for accepted in ["10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.4", "192.168.1.45"] {
            XCTAssertEqual(try RecoveryBootstrap.parseIPv4(text: accepted).count, 4, accepted)
        }
        let rejected: [(String, String)] = [
            ("127.0.0.1", "rfc1918|invalid"),
            ("0.0.0.0", "rfc1918|invalid"),
            ("169.254.1.1", "rfc1918|invalid"),
            ("8.8.8.8", "rfc1918|invalid"),
            ("172.15.0.1", "rfc1918|invalid"),
            ("172.32.0.1", "rfc1918|invalid"),
            ("192.169.1.1", "rfc1918|invalid"),
            ("224.0.0.1", "rfc1918|invalid"),
            ("192.168.001.1", "invalid"),
            ("010.0.0.1", "invalid"),
            ("192.168.1.256", "invalid"),
            ("192.168.1", "invalid"),
            ("192.168.1.1.1", "invalid"),
            ("192.168.1.1 ", "invalid"),
            ("192.168.1.0x1", "invalid")
        ]
        for (value, pattern) in rejected {
            assertRecoveryFailure("ipv4 '\(value)'", matching: pattern) {
                _ = try RecoveryBootstrap.parseIPv4(text: value)
            }
        }
        assertRecoveryFailure("ipv4 byte length", matching: "length") {
            _ = try RecoveryBootstrap.parseIPv4(bytes: Data([10, 0, 0]))
        }
        assertRecoveryFailure("ipv4 public bytes", matching: "rfc1918") {
            _ = try RecoveryBootstrap.parseIPv4(bytes: Data([8, 8, 8, 8]))
        }
        XCTAssertEqual(try RecoveryBootstrap.parseIPv4(bytes: Data([192, 168, 1, 45])).count, 4)
    }

    func testTicketRejectsOutOfRangePortAndZeroFields() throws {
        let entry = try bitmap("6")
        let ticketFields = try ticketFixture("6")
        let sessionId = RecoveryFixtures.hex(
            try XCTUnwrap(ticketFields["sessionIdHex"] as? String)
        )
        let requestHash = RecoveryFixtures.hex(
            try XCTUnwrap(ticketFields["requestHashHex"] as? String)
        )
        let publicKey = try XCTUnwrap(
            ticketFields["desktopEphemeralPublicKeyBase64url"] as? String
        )
        _ = entry

        for port in [0, 1023, 65536] {
            assertRecoveryFailure("port \(port)", matching: "port") {
                _ = try RecoveryBootstrap.encodeTicket(
                    sessionId: sessionId,
                    expiresAt: 1_700_000_220,
                    ipv4Text: "192.168.1.45",
                    port: port,
                    desktopEphemeralPublicKeyBase64URL: publicKey,
                    requestHash: requestHash
                )
            }
        }
        assertRecoveryFailure("zero sessionId", matching: "sessionId") {
            _ = try RecoveryBootstrap.encodeTicket(
                sessionId: Data(repeating: 0, count: 32),
                expiresAt: 1_700_000_220,
                ipv4Text: "192.168.1.45",
                port: 8787,
                desktopEphemeralPublicKeyBase64URL: publicKey,
                requestHash: requestHash
            )
        }
        assertRecoveryFailure("zero requestHash", matching: "requestHash") {
            _ = try RecoveryBootstrap.encodeTicket(
                sessionId: sessionId,
                expiresAt: 1_700_000_220,
                ipv4Text: "192.168.1.45",
                port: 8787,
                desktopEphemeralPublicKeyBase64URL: publicKey,
                requestHash: Data(repeating: 0, count: 32)
            )
        }
    }

    // MARK: - P-256 public key validation

    func testUncompressedP256ValidationRejectsOffCurveAndBadPrefix() throws {
        let ticketFields = try ticketFixture("6")
        let valid = try XCTUnwrap(
            ticketFields["desktopEphemeralPublicKeyBase64url"] as? String
        )
        let raw = try RecoveryBootstrap.validateUncompressedP256PublicKey(
            valid,
            label: "desktop_ephemeral"
        )
        XCTAssertEqual(raw.count, 65)
        XCTAssertEqual(raw[raw.startIndex], 0x04)

        var offCurve = raw
        offCurve[offCurve.index(offCurve.startIndex, offsetBy: 64)] ^= 0x01
        assertRecoveryFailure("off curve", matching: "curve|point") {
            _ = try RecoveryBootstrap.validateUncompressedP256PublicKey(
                RecoveryBootstrap.encodeBase64URL(offCurve),
                label: "desktop_ephemeral"
            )
        }

        var badPrefix = raw
        badPrefix[badPrefix.startIndex] = 0x02
        assertRecoveryFailure("bad prefix", matching: "prefix|curve|point") {
            _ = try RecoveryBootstrap.validateUncompressedP256PublicKey(
                RecoveryBootstrap.encodeBase64URL(badPrefix),
                label: "desktop_ephemeral"
            )
        }
        assertRecoveryFailure("short key", matching: "length") {
            _ = try RecoveryBootstrap.validateUncompressedP256PublicKey(
                RecoveryBootstrap.encodeBase64URL(raw.dropLast()),
                label: "desktop_ephemeral"
            )
        }
    }

    // MARK: - Fetch-init

    func testFetchInitBuildAndValidateMatchFixture() throws {
        for key in ["3", "6"] {
            let entry = try bitmap(key)
            let expected = try XCTUnwrap(entry["fetchInit"] as? [String: Any])
            let challenge = try RecoveryBootstrap.decodeFetchChallenge(
                try XCTUnwrap(expected["fetchChallenge"] as? String)
            )
            XCTAssertEqual(challenge.count, 32)

            let built = try RecoveryBootstrap.buildFetchInit(
                sessionId: try XCTUnwrap(expected["sessionId"] as? String),
                phoneEphemeralPublicKey:
                    try XCTUnwrap(expected["phoneEphemeralPublicKey"] as? String),
                fetchChallenge: challenge
            )
            XCTAssertEqual(built.protocolVersion, 1)
            XCTAssertEqual(built.sessionId, expected["sessionId"] as? String)
            XCTAssertEqual(built.phoneEphemeralPublicKey, expected["phoneEphemeralPublicKey"] as? String)
            XCTAssertEqual(built.fetchChallenge, expected["fetchChallenge"] as? String)

            let validated = try RecoveryBootstrap.validateFetchInit(
                jsonBytes: try RecoveryFixtures.canonicalJSON(expected)
            )
            XCTAssertEqual(validated, built)

            let serialized = try RecoveryBootstrap.serializeFetchInit(built)
            XCTAssertEqual(try RecoveryBootstrap.validateFetchInit(jsonBytes: serialized), built)
        }
    }

    func testFetchInitRejectsMissingFieldsAndDuplicateKeys() throws {
        let expected = try XCTUnwrap(try bitmap("6")["fetchInit"] as? [String: Any])
        var missing = expected
        missing.removeValue(forKey: "fetchChallenge")
        assertRecoveryFailure("missing fetchChallenge", matching: "missing|field") {
            _ = try RecoveryBootstrap.validateFetchInit(
                jsonBytes: try RecoveryFixtures.canonicalJSON(missing)
            )
        }
        let duplicate = Data(
            #"{"protocolVersion":1,"sessionId":"0x45","sessionId":"0x45","phoneEphemeralPublicKey":"a","fetchChallenge":"b"}"#
                .utf8
        )
        assertRecoveryFailure("duplicate key", matching: "duplicate") {
            _ = try RecoveryBootstrap.validateFetchInit(jsonBytes: duplicate)
        }
    }

    // MARK: - Encrypted delivery envelope

    func testEncryptedDeliverySchemaValidation() throws {
        for key in ["3", "6"] {
            let entry = try bitmap(key)
            let message = try XCTUnwrap(entry["encryptedRequestDelivery"] as? [String: Any])
            let validated = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                jsonBytes: try RecoveryFixtures.canonicalJSON(message)
            )
            XCTAssertEqual(validated.protocolVersion, 1)
            XCTAssertEqual(validated.sessionId, message["sessionId"] as? String)
            XCTAssertEqual(validated.nonce, message["nonce"] as? String)
            XCTAssertEqual(validated.tag, message["tag"] as? String)
            XCTAssertEqual(
                try RecoveryBootstrap.decodeBase64URLCanonical(validated.nonce, exactLength: 12).count,
                12
            )
            XCTAssertEqual(
                try RecoveryBootstrap.decodeBase64URLCanonical(validated.tag, exactLength: 16).count,
                16
            )

            var extra = message
            extra["extra"] = true
            assertRecoveryFailure("delivery extra field", matching: "unexpected|field") {
                _ = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                    jsonBytes: try RecoveryFixtures.canonicalJSON(extra)
                )
            }
            var badVersion = message
            badVersion["protocolVersion"] = 2
            assertRecoveryFailure("delivery version", matching: "protocol|version") {
                _ = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                    jsonBytes: try RecoveryFixtures.canonicalJSON(badVersion)
                )
            }
            var badNonce = message
            badNonce["nonce"] = "AAAA"
            assertRecoveryFailure("delivery nonce length", matching: "length") {
                _ = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                    jsonBytes: try RecoveryFixtures.canonicalJSON(badNonce)
                )
            }
        }
    }

    func testRequestDeliveryAadHasExactPinnedShape() throws {
        let entry = try bitmap("6")
        let fetchInit = try XCTUnwrap(entry["fetchInit"] as? [String: Any])
        let sessionId = try XCTUnwrap(fetchInit["sessionId"] as? String)
        let phoneKey = try XCTUnwrap(fetchInit["phoneEphemeralPublicKey"] as? String)
        let challenge = try RecoveryBootstrap.decodeFetchChallenge(
            try XCTUnwrap(fetchInit["fetchChallenge"] as? String)
        )
        let requestHash = RecoveryFixtures.hex(try XCTUnwrap(entry["requestHashHex"] as? String))
        let phoneRaw = try RecoveryBootstrap.validateUncompressedP256PublicKey(
            phoneKey,
            label: "phone_ephemeral"
        )
        let expected = [
            "DESKTOP_TO_IPHONE_RECOVERY_REQUEST_V1",
            sessionId,
            RecoveryFixtures.hexString(requestHash),
            RecoveryFixtures.hexString(Data(SHA256.hash(data: phoneRaw))),
            RecoveryFixtures.hexString(challenge)
        ].joined(separator: "|")

        let aad = try RecoveryBootstrap.buildRequestDeliveryAad(
            sessionId: sessionId,
            requestHash: requestHash,
            phoneEphemeralPublicKey: phoneKey,
            fetchChallenge: challenge
        )
        XCTAssertEqual(String(data: aad, encoding: .utf8), expected)
        XCTAssertEqual(
            "0x" + RecoveryFixtures.hexString(Data(SHA256.hash(data: phoneRaw))),
            entry["phoneEphemeralPublicKeyFingerprint"] as? String
        )
    }

    /// The fixture intentionally commits no shared secret, so the success lane
    /// uses ephemeral Swift-local key agreement material generated in-test.
    func testEphemeralLocalHkdfAndAesGcmRoundTrip() throws {
        let desktop = P256.KeyAgreement.PrivateKey()
        let phone = P256.KeyAgreement.PrivateKey()
        let shared = try desktop.sharedSecretFromKeyAgreement(with: phone.publicKey)
        let ikm = shared.withUnsafeBytes { Data($0) }
        XCTAssertEqual(ikm.count, 32)

        let sessionId = "0x" + String(repeating: "45", count: 32)
        let plaintext = Data("ephemeral-swift-local-test-only".utf8)
        let requestHash = Data(SHA256.hash(data: plaintext))
        let challenge = Data(repeating: 0x7a, count: 32)
        let phoneKey = RecoveryBootstrap.encodeBase64URL(phone.publicKey.x963Representation)

        let key = try RecoveryBootstrap.deriveRequestAesKey(
            sharedSecret: ikm,
            requestHash: requestHash
        )
        XCTAssertEqual(key.count, 32)
        let aad = try RecoveryBootstrap.buildRequestDeliveryAad(
            sessionId: sessionId,
            requestHash: requestHash,
            phoneEphemeralPublicKey: phoneKey,
            fetchChallenge: challenge
        )
        let nonce = Data(repeating: 0x11, count: 12)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        let message = RecoveryBootstrap.EncryptedRequestDelivery(
            protocolVersion: 1,
            sessionId: sessionId,
            nonce: RecoveryBootstrap.encodeBase64URL(nonce),
            ciphertext: RecoveryBootstrap.encodeBase64URL(sealed.ciphertext),
            tag: RecoveryBootstrap.encodeBase64URL(sealed.tag)
        )
        XCTAssertEqual(
            try RecoveryBootstrap.decryptRequestDelivery(
                message: message,
                key: key,
                sessionId: sessionId,
                requestHash: requestHash,
                phoneEphemeralPublicKey: phoneKey,
                fetchChallenge: challenge
            ),
            plaintext
        )

        assertRecoveryFailure("wrong aad challenge", matching: "authentication") {
            _ = try RecoveryBootstrap.decryptRequestDelivery(
                message: message,
                key: key,
                sessionId: sessionId,
                requestHash: requestHash,
                phoneEphemeralPublicKey: phoneKey,
                fetchChallenge: Data(repeating: 0x7b, count: 32)
            )
        }
        assertRecoveryFailure("session mismatch", matching: "session") {
            _ = try RecoveryBootstrap.decryptRequestDelivery(
                message: message,
                key: key,
                sessionId: "0x" + String(repeating: "46", count: 32),
                requestHash: requestHash,
                phoneEphemeralPublicKey: phoneKey,
                fetchChallenge: challenge
            )
        }
        let otherKey = try RecoveryBootstrap.deriveRequestAesKey(
            sharedSecret: Data(repeating: 0x11, count: 32),
            requestHash: requestHash
        )
        XCTAssertNotEqual(otherKey, key)
        assertRecoveryFailure("wrong key", matching: "authentication") {
            _ = try RecoveryBootstrap.decryptRequestDelivery(
                message: message,
                key: otherKey,
                sessionId: sessionId,
                requestHash: requestHash,
                phoneEphemeralPublicKey: phoneKey,
                fetchChallenge: challenge
            )
        }
    }

    // MARK: - Every O.45 negative mutation

    func testAllO45NegativeMutations() throws {
        let negatives = try XCTUnwrap(o45["negativeMutations"] as? [[String: Any]])
        XCTAssertEqual(negatives.count, 18)
        var executed = 0
        for negative in negatives {
            let category = try XCTUnwrap(negative["category"] as? String)
            let kind = try XCTUnwrap(negative["kind"] as? String)
            let pattern = try XCTUnwrap(negative["expectedError"] as? String)
            switch kind {
            case "decodeTicket":
                let bytes = RecoveryFixtures.hex(try XCTUnwrap(negative["bytesHex"] as? String))
                assertRecoveryFailure(category, matching: pattern) {
                    _ = try RecoveryBootstrap.decodeTicket(bytes)
                }
            case "parseUri":
                let uri = try XCTUnwrap(negative["uri"] as? String)
                assertRecoveryFailure(category, matching: pattern) {
                    _ = try RecoveryBootstrap.parseURI(uri)
                }
            case "validateTicket":
                var ticket = try RecoveryBootstrap.decodeTicket(
                    RecoveryFixtures.hex(try XCTUnwrap(negative["ticketHex"] as? String))
                )
                if let overrides = negative["ticketOverrides"] as? [String: Any],
                   let expiresAt = overrides["expiresAt"] as? String {
                    ticket = try RecoveryBootstrap.decodeTicket(
                        try RecoveryBootstrap.encodeTicket(
                            sessionId: ticket.sessionId,
                            expiresAt: try XCTUnwrap(UInt64(expiresAt)),
                            ipv4Text: ticket.ipv4Text,
                            port: Int(ticket.port),
                            desktopEphemeralPublicKeyBase64URL:
                                RecoveryBootstrap.encodeBase64URL(ticket.desktopEphemeralPublicKey),
                            requestHash: ticket.requestHash
                        )
                    )
                }
                let now = try XCTUnwrap(negative["nowSeconds"] as? Int)
                let bound = (negative["boundRequestExpiresAtMs"] as? NSNumber).map { "\($0)" }
                assertRecoveryFailure(category, matching: pattern) {
                    try RecoveryBootstrap.validateTicketPolicy(
                        ticket: ticket,
                        nowSeconds: UInt64(now),
                        boundRequestExpiresAtMilliseconds: bound
                    )
                }
            case "parseCanonical":
                let bytes = RecoveryFixtures.hex(try XCTUnwrap(negative["bytesHex"] as? String))
                let now = try XCTUnwrap(negative["now"] as? String)
                assertRecoveryFailure(category, matching: pattern) {
                    _ = try RecoveryCanonicalRequest.parse(
                        rawBytes: bytes,
                        nowMilliseconds: now,
                        expectedRequestHash: nil
                    )
                }
            case "validateFetchInit":
                let value = try XCTUnwrap(negative["value"] as? [String: Any])
                assertRecoveryFailure(category, matching: pattern) {
                    _ = try RecoveryBootstrap.validateFetchInit(
                        jsonBytes: try RecoveryFixtures.canonicalJSON(value)
                    )
                }
            case "decryptDelivery":
                let value = try XCTUnwrap(negative["message"] as? [String: Any])
                let message = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                    jsonBytes: try RecoveryFixtures.canonicalJSON(value)
                )
                let key = RecoveryFixtures.hex(try XCTUnwrap(negative["keyHex"] as? String))
                let sessionId = try XCTUnwrap(negative["sessionId"] as? String)
                let requestHash = RecoveryFixtures.hex(
                    try XCTUnwrap(negative["requestHashHex"] as? String)
                )
                let phoneKey = try XCTUnwrap(negative["phoneEphemeralPublicKey"] as? String)
                let challenge = RecoveryFixtures.hex(
                    try XCTUnwrap(negative["fetchChallengeHex"] as? String)
                )
                assertRecoveryFailure(category, matching: pattern) {
                    _ = try RecoveryBootstrap.decryptRequestDelivery(
                        message: message,
                        key: key,
                        sessionId: sessionId,
                        requestHash: requestHash,
                        phoneEphemeralPublicKey: phoneKey,
                        fetchChallenge: challenge
                    )
                }
            default:
                XCTFail("unhandled O.45 negative kind \(kind)")
            }
            executed += 1
        }
        XCTAssertEqual(executed, 18)
    }
}
