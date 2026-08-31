import CryptoKit
import Foundation
import XCTest
@testable import PhilCoreCompanion

// MARK: - Non-networked desktop half

/// Deterministic, socket-free stand-in for the desktop peer.
///
/// The O.45 canonical request fixtures are reused verbatim except for the two
/// fields that must be bound to freshly generated in-test material (the desktop
/// ephemeral public key, and optionally the session id so two live sessions can
/// be told apart). The fixture files themselves are never written to.
final class RecoveryDesktopSimulator: @unchecked Sendable {
    static let nowSeconds: UInt64 = 1_700_000_100
    static let nowMilliseconds: UInt64 = 1_700_000_100_000
    static let ticketExpiresAtUnixSeconds: UInt64 = 1_700_000_300

    struct AckOverrides {
        var status = "ACCEPTED"
        var wrapperUsesProtocolVersionKey = false
        var wrapperPhoneKey: String?
        var wrapperOmitsPhoneKey = true
        var extraPlaintextField = false
        var omitPlaintextField: String?
        var transcriptHashOverride: String?
        var sessionIdOverride: String?
        var reuseNonce: Data?
        var encryptWithWrongKey = false
    }

    let bitmap: String
    let desktopPrivateKey: P256.KeyAgreement.PrivateKey
    let canonicalRequest: Data
    let requestHash: Data
    let ticketBytes: Data
    let ticket: RecoveryBootstrap.Ticket
    let uri: String
    let sessionId: String
    let validation: RecoveryApprovalValidation
    let requestEndpoint: String
    let completionEndpoint: String

    private let lock = NSLock()
    private var sharedSecretStorage: Data?
    private var lastFetchInitStorage: RecoveryBootstrap.FetchInit?
    private var lastApprovalPlaintextStorage: Data?
    private var lastDeliveryNonceStorage: Data?

    init(
        bitmap: String,
        owner: AnyClass,
        sessionIdOverride: String? = nil,
        role1SigningPublicKey: P256.Signing.PublicKey? = nil,
        ticketExpiresAtUnixSeconds: UInt64 = RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds,
        requestExpiresAtMilliseconds: String? = nil
    ) throws {
        self.bitmap = bitmap
        let fixture = try RecoveryFixtures.fixtureObject(
            RecoveryFixtures.o45Resource,
            for: owner
        )
        let bitmaps = try XCTUnwrap(fixture["bitmaps"] as? [String: Any])
        let entry = try XCTUnwrap(bitmaps[bitmap] as? [String: Any])
        let originalBytes = RecoveryFixtures.hex(
            try XCTUnwrap(entry["canonicalRequestHex"] as? String)
        )
        let original = try RecoveryCanonicalRequest.buildWireRequest(jsonBytes: originalBytes)

        let desktopKey = P256.KeyAgreement.PrivateKey()
        self.desktopPrivateKey = desktopKey
        let desktopPublic = RecoveryCodec.encodeBase64URL(
            desktopKey.publicKey.x963Representation
        )

        let expiresAt = requestExpiresAtMilliseconds ?? original.expiresAt
        let reboundIdentity = try Self.rebindTrustedRole1(
            original: original,
            role1SigningPublicKey: role1SigningPublicKey
        )

        let rebound = RecoveryWireRequest(
            protocolVersion: original.protocolVersion,
            context: reboundIdentity.context,
            claimedContextHash: reboundIdentity.claimedContextHash,
            claimedRecoveryFactorDigest: reboundIdentity.claimedRecoveryFactorDigest,
            accountVersionId: original.accountVersionId,
            securityModelId: original.securityModelId,
            nativeRecoveryDomainId: original.nativeRecoveryDomainId,
            applicationIdentity: original.applicationIdentity,
            localApprovalPolicy: original.localApprovalPolicy,
            selectedRole1CredentialIdentifierCommitment:
                original.selectedRole1CredentialIdentifierCommitment,
            selectedRole1CredentialGeneration: original.selectedRole1CredentialGeneration,
            trustedRole1Descriptor: reboundIdentity.descriptor,
            trustedRole1PublicKey: reboundIdentity.publicKey,
            sessionId: sessionIdOverride ?? original.sessionId,
            sessionChallenge: original.sessionChallenge,
            desktopEphemeralPublicKey: desktopPublic,
            issuedAt: original.issuedAt,
            expiresAt: expiresAt,
            endpoint: original.endpoint
        )

        let canonical = try RecoveryCanonicalRequest.serializeCanonical(rebound)
        self.canonicalRequest = canonical
        self.requestHash = Data(SHA256.hash(data: canonical))
        self.sessionId = rebound.sessionId

        let authority = try Self.parseAuthority(rebound.endpoint)
        let encoded = try RecoveryBootstrap.encodeTicket(
            sessionId: try RecoveryCodec.hexBytes(rebound.sessionId, expecting: 32),
            expiresAt: ticketExpiresAtUnixSeconds,
            ipv4Text: authority.host,
            port: authority.port,
            desktopEphemeralPublicKeyBase64URL: desktopPublic,
            requestHash: requestHash
        )
        self.ticketBytes = encoded
        self.ticket = try RecoveryBootstrap.decodeTicket(encoded)
        self.uri = try RecoveryBootstrap.formatURI(ticketBytes: encoded)
        self.requestEndpoint = try RecoveryBootstrap.requestEndpoint(ticket: ticket)
        self.completionEndpoint = try RecoveryBootstrap.completionEndpoint(ticket: ticket)
        self.validation = try RecoveryCanonicalRequest.parse(
            rawBytes: canonical,
            nowMilliseconds: String(Self.nowMilliseconds),
            expectedRequestHash: requestHash
        )
    }

    /// Rebinds the O.44 trusted Role 1 public material to a live mock-signer
    /// key without mutating the committed fixture files. When `nil`, the
    /// fixture key material is preserved for non-approval paths.
    private static func rebindTrustedRole1(
        original: RecoveryWireRequest,
        role1SigningPublicKey: P256.Signing.PublicKey?
    ) throws -> (
        context: RecoveryWireContext,
        descriptor: RecoveryWireDescriptor,
        publicKey: RecoveryWirePublicKey,
        claimedContextHash: String,
        claimedRecoveryFactorDigest: String
    ) {
        guard let role1SigningPublicKey else {
            return (
                original.context,
                original.trustedRole1Descriptor,
                original.trustedRole1PublicKey,
                original.claimedContextHash,
                original.claimedRecoveryFactorDigest
            )
        }

        let x963 = role1SigningPublicKey.x963Representation
        guard x963.count == 65, x963[x963.startIndex] == 0x04 else {
            throw RecoveryCodecError("mock_signer_public_key_invalid")
        }
        let qxBytes = Data(x963[(x963.startIndex + 1)..<(x963.startIndex + 33)])
        let qyBytes = Data(x963[(x963.startIndex + 33)..<(x963.startIndex + 65)])
        let qx = "0x" + RecoveryCodec.hexString(qxBytes)
        let qy = "0x" + RecoveryCodec.hexString(qyBytes)
        let publicKey = RecoveryWirePublicKey(qx: qx, qy: qy)

        let materialHash = try RecoveryCanonicalRequest.nativeP256PublicMaterialHash(
            qx: qx,
            qy: qy
        )
        let materialHashHex = "0x" + RecoveryCodec.hexString(materialHash)
        let descriptor = RecoveryWireDescriptor(
            descriptorVersion: original.trustedRole1Descriptor.descriptorVersion,
            accountVersionId: original.trustedRole1Descriptor.accountVersionId,
            securityModelId: original.trustedRole1Descriptor.securityModelId,
            recoveryDomainId: original.trustedRole1Descriptor.recoveryDomainId,
            role: original.trustedRole1Descriptor.role,
            verifierKind: original.trustedRole1Descriptor.verifierKind,
            publicVerificationMaterialHash: materialHashHex,
            credentialIdentifierCommitment:
                original.trustedRole1Descriptor.credentialIdentifierCommitment,
            applicationIdentityHash: original.trustedRole1Descriptor.applicationIdentityHash,
            deviceCustodyCommitment: original.trustedRole1Descriptor.deviceCustodyCommitment,
            localApprovalPolicyHash: original.trustedRole1Descriptor.localApprovalPolicyHash,
            appAttestCommitment: original.trustedRole1Descriptor.appAttestCommitment,
            credentialGeneration: original.trustedRole1Descriptor.credentialGeneration,
            secureEnclaveRequired: original.trustedRole1Descriptor.secureEnclaveRequired,
            simulatorCredential: original.trustedRole1Descriptor.simulatorCredential
        )

        let factorCommitment = try RecoveryCanonicalRequest.nativeRole1FactorCommitment(
            descriptor
        )
        let hardwareHex = "0x" + RecoveryCodec.hexString(factorCommitment)
        let primary = original.context.primaryDeviceCommitment
        let recovery = original.context.recoveryFactorCommitment
        guard hardwareHex != primary, hardwareHex != recovery else {
            throw RecoveryCodecError("mock_signer_commitment_collision")
        }
        let roleCommitments = [primary, hardwareHex, recovery]
        let roles = try RecoveryCanonicalRequest.rolesForBitmap(
            try XCTUnwrap(UInt64(original.context.factorBitmap))
        )
        let configHash = try RecoveryCanonicalRequest.consumerRecoveryConfigurationHashV3(
            [primary, hardwareHex, recovery]
        )
        let context = RecoveryWireContext(
            envelopeVersion: original.context.envelopeVersion,
            authorityKind: original.context.authorityKind,
            actionType: original.context.actionType,
            factorBitmap: original.context.factorBitmap,
            account: original.context.account,
            chainId: original.context.chainId,
            entryPoint: original.context.entryPoint,
            authorizedIntentHash: original.context.authorizedIntentHash,
            userOperationHash: original.context.userOperationHash,
            requestId: original.context.requestId,
            currentRecoveryConfigHash: "0x" + RecoveryCodec.hexString(configHash),
            validatorEpoch: original.context.validatorEpoch,
            recoveryEpoch: original.context.recoveryEpoch,
            validAfter: original.context.validAfter,
            validUntil: original.context.validUntil,
            recoveryDelaySeconds: original.context.recoveryDelaySeconds,
            recoveryExpirySeconds: original.context.recoveryExpirySeconds,
            proposedValidatorCommitment: original.context.proposedValidatorCommitment,
            proposedRecoveryConfigHash: original.context.proposedRecoveryConfigHash,
            proposedRecoveryEpoch: original.context.proposedRecoveryEpoch,
            primaryDeviceCommitment: primary,
            hardwareSecurityKeyCommitment: hardwareHex,
            recoveryFactorCommitment: recovery,
            firstFactorCommitment: roleCommitments[roles.0],
            secondFactorCommitment: roleCommitments[roles.1]
        )
        let digest = try RecoveryCanonicalRequest.recoveryFactorDigest(context)
        let contextHash = try RecoveryCanonicalRequest.consumerEvidenceContextHash(context)
        return (
            context,
            descriptor,
            publicKey,
            "0x" + RecoveryCodec.hexString(contextHash),
            "0x" + RecoveryCodec.hexString(digest)
        )
    }

    // MARK: Observations

    var sharedSecret: Data? {
        lock.lock(); defer { lock.unlock() }
        return sharedSecretStorage
    }

    var lastFetchInit: RecoveryBootstrap.FetchInit? {
        lock.lock(); defer { lock.unlock() }
        return lastFetchInitStorage
    }

    var lastApprovalPlaintext: Data? {
        lock.lock(); defer { lock.unlock() }
        return lastApprovalPlaintextStorage
    }

    var lastDeliveryNonce: Data? {
        lock.lock(); defer { lock.unlock() }
        return lastDeliveryNonceStorage
    }

    // MARK: `/request`

    /// Encrypts the canonical request exactly as the desktop would.
    func deliveryBody(
        for fetchInitBody: Data,
        tamperCiphertext: Bool = false,
        sessionIdOverride: String? = nil,
        plaintextOverride: Data? = nil
    ) throws -> Data {
        let fetchInit = try RecoveryBootstrap.validateFetchInit(jsonBytes: fetchInitBody)
        let phoneRaw = try RecoveryBootstrap.validateUncompressedP256PublicKey(
            fetchInit.phoneEphemeralPublicKey,
            label: "phone_ephemeral"
        )
        let agreed = try desktopPrivateKey.sharedSecretFromKeyAgreement(
            with: try P256.KeyAgreement.PublicKey(x963Representation: phoneRaw)
        )
        let ikm = agreed.withUnsafeBytes { Data($0) }
        let challenge = try RecoveryBootstrap.decodeFetchChallenge(fetchInit.fetchChallenge)
        let key = try RecoveryBootstrap.deriveRequestAesKey(
            sharedSecret: ikm,
            requestHash: requestHash
        )
        let aad = try RecoveryBootstrap.buildRequestDeliveryAad(
            sessionId: sessionId,
            requestHash: requestHash,
            phoneEphemeralPublicKey: fetchInit.phoneEphemeralPublicKey,
            fetchChallenge: challenge
        )
        let sealed = try AES.GCM.seal(
            plaintextOverride ?? canonicalRequest,
            using: SymmetricKey(data: key),
            authenticating: aad
        )
        var ciphertext = sealed.ciphertext
        if tamperCiphertext, !ciphertext.isEmpty {
            ciphertext[ciphertext.startIndex] ^= 0x01
        }

        lock.lock()
        sharedSecretStorage = ikm
        lastFetchInitStorage = fetchInit
        lastDeliveryNonceStorage = Data(sealed.nonce)
        lock.unlock()

        return Self.jsonObject([
            ("protocolVersion", "1"),
            ("sessionId", Self.quote(sessionIdOverride ?? sessionId)),
            ("nonce", Self.quote(RecoveryCodec.encodeBase64URL(Data(sealed.nonce)))),
            ("ciphertext", Self.quote(RecoveryCodec.encodeBase64URL(ciphertext))),
            ("tag", Self.quote(RecoveryCodec.encodeBase64URL(sealed.tag)))
        ])
    }

    // MARK: `/complete`

    /// Decrypts the phone's approval, records the plaintext for inspection, and
    /// produces the encrypted acknowledgement.
    func acknowledgementBody(
        for approvalBody: Data,
        overrides: AckOverrides = AckOverrides()
    ) throws -> Data {
        let parsed = try RecoveryJSON.parse(approvalBody)
        let wrapper = try XCTUnwrap(parsed.objectValue)
        let wrapperSession = try XCTUnwrap(wrapper["sessionId"]?.stringValue)
        let nonce = try RecoveryCodec.decodeBase64URLCanonical(
            try XCTUnwrap(wrapper["nonce"]?.stringValue),
            exactLength: 12
        )
        let ciphertext = try RecoveryCodec.decodeBase64URLCanonical(
            try XCTUnwrap(wrapper["ciphertext"]?.stringValue),
            exactLength: nil
        )
        let tag = try RecoveryCodec.decodeBase64URLCanonical(
            try XCTUnwrap(wrapper["tag"]?.stringValue),
            exactLength: 16
        )
        let secret = try XCTUnwrap(sharedSecret, "desktop never completed key agreement")
        let approvalKey = try RecoveryApprovalCodec.deriveApprovalAesKey(
            sharedSecret: secret,
            transcriptHash: validation.transcriptHash
        )
        let plaintext = try AES.GCM.open(
            try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            ),
            using: SymmetricKey(data: approvalKey),
            authenticating: try RecoveryApprovalCodec.buildAad(
                direction: RecoveryApprovalCodec.aadPhoneToDesktop,
                sessionId: wrapperSession
            )
        )
        lock.lock()
        lastApprovalPlaintextStorage = plaintext
        lock.unlock()

        var members: [(String, String)] = [
            ("protocolVersion", "1"),
            ("sessionId", Self.quote(overrides.sessionIdOverride ?? sessionId)),
            (
                "transcriptHash",
                Self.quote(
                    overrides.transcriptHashOverride
                        ?? RecoveryApprovalCodec.hex32(validation.transcriptHash)
                )
            ),
            ("status", Self.quote(overrides.status))
        ]
        if let omit = overrides.omitPlaintextField {
            members.removeAll { $0.0 == omit }
        }
        if overrides.extraPlaintextField {
            members.append(("unexpected", "true"))
        }
        let ackPlaintext = Self.jsonObject(members)

        let ackKey = overrides.encryptWithWrongKey
            ? Data(repeating: 0x5a, count: 32)
            : approvalKey
        let sealed: AES.GCM.SealedBox
        let aad = try RecoveryApprovalCodec.buildAad(
            direction: RecoveryApprovalCodec.aadDesktopToPhone,
            sessionId: sessionId
        )
        if let reuse = overrides.reuseNonce {
            sealed = try AES.GCM.seal(
                ackPlaintext,
                using: SymmetricKey(data: ackKey),
                nonce: try AES.GCM.Nonce(data: reuse),
                authenticating: aad
            )
        } else {
            sealed = try AES.GCM.seal(
                ackPlaintext,
                using: SymmetricKey(data: ackKey),
                authenticating: aad
            )
        }

        var wrapperMembers: [(String, String)] = [
            (overrides.wrapperUsesProtocolVersionKey ? "protocolVersion" : "version", "1"),
            ("sessionId", Self.quote(sessionId))
        ]
        if let phoneKey = overrides.wrapperPhoneKey {
            wrapperMembers.append(("phoneEphemeralPublicKey", Self.quote(phoneKey)))
        } else if !overrides.wrapperOmitsPhoneKey {
            wrapperMembers.append(("phoneEphemeralPublicKey", "null"))
        }
        wrapperMembers.append(
            ("nonce", Self.quote(RecoveryCodec.encodeBase64URL(Data(sealed.nonce))))
        )
        wrapperMembers.append(
            ("ciphertext", Self.quote(RecoveryCodec.encodeBase64URL(sealed.ciphertext)))
        )
        wrapperMembers.append(("tag", Self.quote(RecoveryCodec.encodeBase64URL(sealed.tag))))
        return Self.jsonObject(wrapperMembers)
    }

    // MARK: Helpers

    static func quote(_ value: String) -> String {
        RecoveryCodec.jsonStringLiteral(value)
    }

    static func jsonObject(_ members: [(String, String)]) -> Data {
        let text = "{" + members.map { "\(quote($0.0)):\($0.1)" }.joined(separator: ",") + "}"
        return Data(text.utf8)
    }

    static func sessionId(fromBody body: Data) throws -> String {
        let parsed = try RecoveryJSON.parse(body)
        return try XCTUnwrap(parsed.objectValue?["sessionId"]?.stringValue)
    }

    private static func parseAuthority(_ endpoint: String) throws -> (host: String, port: Int) {
        let remainder = endpoint.dropFirst("http://".count)
        let separator = try XCTUnwrap(remainder.firstIndex(of: "/"))
        let authority = remainder[remainder.startIndex..<separator]
        let parts = authority.split(separator: ":")
        return (String(parts[0]), try XCTUnwrap(Int(parts[1])))
    }
}

// MARK: - Socket-free transport doubles

/// In-memory transport. Never touches URLSession or a socket.
final class FakeRecoveryTransport: RecoveryTransporting, @unchecked Sendable {
    typealias Handler = @Sendable (RecoveryTransportRequest) async throws
        -> RecoveryTransportResponse

    private let lock = NSLock()
    private var handlers: [RecoveryTransportRoute: Handler] = [:]
    private var recorded: [RecoveryTransportRequest] = []

    func setHandler(_ route: RecoveryTransportRoute, _ handler: @escaping Handler) {
        lock.lock()
        handlers[route] = handler
        lock.unlock()
    }

    var requests: [RecoveryTransportRequest] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    func requests(for route: RecoveryTransportRoute) -> [RecoveryTransportRequest] {
        requests.filter { $0.route == route }
    }

    func send(_ request: RecoveryTransportRequest) async throws -> RecoveryTransportResponse {
        lock.lock()
        recorded.append(request)
        let handler = handlers[request.route]
        lock.unlock()
        guard let handler else { throw RecoveryTransportError.unavailable }
        return try await handler(request)
    }

    static func ok(_ body: Data, endpoint: String) -> RecoveryTransportResponse {
        RecoveryTransportResponse(
            statusCode: 200,
            contentType: RecoveryTransportRequest.contentType,
            body: body,
            finalEndpoint: endpoint
        )
    }
}

/// Async gate used to hold a transport attempt open while the test drives a
/// concurrent replacement or cancellation.
final class RecoveryTestGate: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)

    func open() { semaphore.signal() }

    func wait() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                self.semaphore.wait()
                continuation.resume()
            }
        }
    }
}

/// Loopback `URLProtocol` so the real `URLSession` code path can be exercised
/// without ever opening a socket.
final class RecoveryLoopbackControl: @unchecked Sendable {
    struct Stub {
        var statusCode = 200
        var contentType: String? = RecoveryTransportRequest.contentType
        var declaresContentLength = true
        var body = Data()
        var chunkCount = 1
        var failWith: URLError.Code?
        var responseURLOverride: String?
        var delayNanoseconds: UInt64 = 0
    }

    static let shared = RecoveryLoopbackControl()

    private let lock = NSLock()
    private var stubStorage = Stub()
    private var handledStorage = 0
    private var bodiesStorage: [Data] = []

    var stub: Stub {
        get { lock.lock(); defer { lock.unlock() }; return stubStorage }
        set { lock.lock(); stubStorage = newValue; lock.unlock() }
    }

    var handledCount: Int {
        lock.lock(); defer { lock.unlock() }
        return handledStorage
    }

    var bodies: [Data] {
        lock.lock(); defer { lock.unlock() }
        return bodiesStorage
    }

    func reset() {
        lock.lock()
        stubStorage = Stub()
        handledStorage = 0
        bodiesStorage = []
        lock.unlock()
    }

    func record(_ body: Data) {
        lock.lock()
        handledStorage += 1
        bodiesStorage.append(body)
        lock.unlock()
    }
}

final class RecoveryLoopbackURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let control = RecoveryLoopbackControl.shared
        let stub = control.stub
        control.record(Self.bodyBytes(of: request))

        if stub.delayNanoseconds > 0 {
            Thread.sleep(forTimeInterval: Double(stub.delayNanoseconds) / 1_000_000_000)
        }
        if let failure = stub.failWith {
            client?.urlProtocol(self, didFailWithError: URLError(failure))
            return
        }

        var headers: [String: String] = [:]
        if let contentType = stub.contentType {
            headers["Content-Type"] = contentType
        }
        if stub.declaresContentLength {
            headers["Content-Length"] = String(stub.body.count)
        }
        let responseURL = stub.responseURLOverride.flatMap { URL(string: $0) }
            ?? request.url
            ?? URL(string: "http://10.0.0.1:1024/")!
        guard let response = HTTPURLResponse(
            url: responseURL,
            statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        ) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)

        let chunks = max(1, stub.chunkCount)
        let size = max(1, Int((Double(stub.body.count) / Double(chunks)).rounded(.up)))
        var offset = 0
        while offset < stub.body.count {
            let end = min(offset + size, stub.body.count)
            client?.urlProtocol(self, didLoad: stub.body.subdata(in: offset..<end))
            offset = end
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func bodyBytes(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var out = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: bufferSize)
            if read <= 0 { break }
            out.append(contentsOf: buffer[0..<read])
        }
        return out
    }
}

// MARK: - Shared assertions

extension XCTestCase {
    /// Asserts an async body throws a `RecoveryClientError` of the expected
    /// kind whose sanitized reason matches the pattern.
    func assertClientFailure(
        _ label: String,
        kind: RecoveryClientError.Kind? = nil,
        matching pattern: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("\(label): expected RecoveryClientError", file: file, line: line)
        } catch let error as RecoveryClientError {
            if let kind {
                XCTAssertEqual(error.kind, kind, "\(label): kind", file: file, line: line)
            }
            if let pattern {
                XCTAssertNotNil(
                    error.reason.range(
                        of: pattern,
                        options: [.regularExpression, .caseInsensitive]
                    ),
                    "\(label): reason '\(error.reason)' does not match /\(pattern)/",
                    file: file,
                    line: line
                )
            }
        } catch {
            XCTFail("\(label): unexpected error \(error)", file: file, line: line)
        }
    }

    func assertTransportFailure(
        _ label: String,
        matching pattern: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("\(label): expected RecoveryTransportError", file: file, line: line)
        } catch let error as RecoveryTransportError {
            XCTAssertNotNil(
                error.reason.range(of: pattern, options: [.regularExpression, .caseInsensitive]),
                "\(label): reason '\(error.reason)' does not match /\(pattern)/",
                file: file,
                line: line
            )
        } catch {
            XCTFail("\(label): unexpected error \(error)", file: file, line: line)
        }
    }
}

/// Shared driver: wires a simulator to a fake transport and runs the session up
/// to a requested stage.
enum RecoveryScenario {
    static func router(
        _ simulators: [RecoveryDesktopSimulator],
        acknowledgement: @escaping @Sendable (RecoveryDesktopSimulator, Data) throws -> Data
    ) -> FakeRecoveryTransport {
        let transport = FakeRecoveryTransport()
        let index = Dictionary(uniqueKeysWithValues: simulators.map { ($0.sessionId, $0) })
        transport.setHandler(.request) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            return FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            return FakeRecoveryTransport.ok(
                try acknowledgement(simulator, request.body),
                endpoint: simulator.completionEndpoint
            )
        }
        return transport
    }

    static func standard(
        _ simulator: RecoveryDesktopSimulator,
        overrides: RecoveryDesktopSimulator.AckOverrides = RecoveryDesktopSimulator.AckOverrides()
    ) -> FakeRecoveryTransport {
        router([simulator]) { sim, body in
            try sim.acknowledgementBody(for: body, overrides: overrides)
        }
    }

    /// Runs start -> fetch -> prepare and leaves the client in
    /// `awaitingApproval`.
    static func driveToAwaitingApproval(
        client: RecoveryClient,
        simulator: RecoveryDesktopSimulator
    ) async throws {
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        try await client.fetchRequest(
            nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
        )
        try await client.prepareApproval()
    }
}

// MARK: - Happy paths

final class RecoveryClientHappyPathTests: XCTestCase {
    private func runAcceptedFlow(bitmap: String) async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: bitmap, owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)

        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        var status = await client.status()
        XCTAssertEqual(status.state, .bootstrapValidated)
        XCTAssertEqual(status.sessionId, simulator.sessionId)
        XCTAssertEqual(status.generation, 1)
        XCTAssertNil(status.presentation)
        XCTAssertEqual(signer.callCount, 0)

        try await client.fetchRequest(
            nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
        )
        status = await client.status()
        XCTAssertEqual(status.state, .requestValidated)
        XCTAssertEqual(signer.callCount, 0, "fetch must never invoke the signer")

        try await client.prepareApproval()
        status = await client.status()
        XCTAssertEqual(status.state, .awaitingApproval)
        let presentation = try XCTUnwrap(status.presentation)
        XCTAssertEqual(presentation.sessionId, simulator.sessionId)
        XCTAssertEqual(presentation.factorBitmap, bitmap)
        XCTAssertEqual(presentation.actionText, simulator.validation.actionText)
        XCTAssertEqual(presentation.networkText, simulator.validation.networkText)
        XCTAssertEqual(
            presentation.comparisonFingerprint,
            simulator.validation.comparisonFingerprint
        )
        XCTAssertEqual(
            presentation.comparisonFingerprint,
            RecoveryCanonicalRequest.comparisonFingerprint(
                transcriptHash: simulator.validation.transcriptHash
            )
        )
        XCTAssertEqual(presentation.completionEndpoint, simulator.completionEndpoint)
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
        XCTAssertEqual(
            presentation.expiresAtUnixSeconds,
            RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds
        )
        XCTAssertEqual(signer.callCount, 0, "presentation must never invoke the signer")

        try await client.approve()
        status = await client.status()
        XCTAssertEqual(status.state, .accepted)
        XCTAssertEqual(status.acknowledgedStatus, "ACCEPTED")
        XCTAssertNil(status.failureReason)
        XCTAssertNil(
            status.presentation,
            "terminal accepted must clear presentation without reset()"
        )

        // Signer contract: invoked exactly once, with the recomputed digest.
        XCTAssertEqual(signer.callCount, 1)
        let expectedDigest = try RecoveryCanonicalRequest.recoveryFactorDigest(
            simulator.validation.request.context
        )
        XCTAssertEqual(signer.lastDigest, expectedDigest)
        XCTAssertEqual(signer.lastDigest, simulator.validation.recoveryFactorDigest)

        // Exactly one POST per route, no retries.
        XCTAssertEqual(transport.requests(for: .request).count, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 1)
        for request in transport.requests {
            XCTAssertEqual(request.method, "POST")
            XCTAssertEqual(request.contentType, "application/json; charset=utf-8")
            XCTAssertLessThanOrEqual(request.body.count, request.route.maxOutgoingBytes)
        }

        // The submitted plaintext is exactly the seven pinned fields, with a
        // numeric credentialGeneration and a low-S DER signature.
        let plaintext = try XCTUnwrap(simulator.lastApprovalPlaintext)
        let parsed = try XCTUnwrap(try RecoveryJSON.parse(plaintext).objectValue)
        XCTAssertEqual(
            Set(parsed.keys),
            [
                "protocolVersion", "sessionId", "transcriptHash", "role1FactorCommitment",
                "credentialIdentifierCommitment", "credentialGeneration", "derRecoverySignature"
            ]
        )
        XCTAssertEqual(parsed["protocolVersion"]?.numberLiteral, "1")
        XCTAssertEqual(parsed["credentialGeneration"]?.numberLiteral, "1")
        XCTAssertNil(
            parsed["credentialGeneration"]?.stringValue,
            "credentialGeneration must be a JSON number"
        )
        XCTAssertEqual(parsed["sessionId"]?.stringValue, simulator.sessionId)
        XCTAssertEqual(
            parsed["transcriptHash"]?.stringValue,
            RecoveryApprovalCodec.hex32(simulator.validation.transcriptHash)
        )
        XCTAssertEqual(
            parsed["role1FactorCommitment"]?.stringValue,
            simulator.validation.request.context.hardwareSecurityKeyCommitment
        )
        XCTAssertEqual(
            parsed["credentialIdentifierCommitment"]?.stringValue,
            simulator.validation.request.selectedRole1CredentialIdentifierCommitment
        )

        let der = try RecoveryCodec.decodeBase64URLCanonical(
            try XCTUnwrap(parsed["derRecoverySignature"]?.stringValue),
            exactLength: nil
        )
        XCTAssertTrue(try RecoveryMockSigner.isLowS(der: der), "submitted DER must be low-S")
        XCTAssertTrue(
            try signer.verifyNormalized(der: der, digest: expectedDigest),
            "submitted signature must verify against the signer key over the digest"
        )
    }

    func testHappyPathBitmap3ReachesAcceptedWithSingleSignerInvocation() async throws {
        try await runAcceptedFlow(bitmap: "3")
    }

    func testHappyPathBitmap6ReachesAcceptedWithSingleSignerInvocation() async throws {
        try await runAcceptedFlow(bitmap: "6")
    }

    func testHighSSignatureIsNormalizedToLowSBeforeSubmission() async throws {
        let signer = RecoveryMockSigner(behavior: .signHighS)
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        try await client.approve()

        let plaintext = try XCTUnwrap(simulator.lastApprovalPlaintext)
        let parsed = try XCTUnwrap(try RecoveryJSON.parse(plaintext).objectValue)
        let der = try RecoveryCodec.decodeBase64URLCanonical(
            try XCTUnwrap(parsed["derRecoverySignature"]?.stringValue),
            exactLength: nil
        )
        XCTAssertTrue(try RecoveryMockSigner.isLowS(der: der))
        XCTAssertTrue(
            try signer.verifyNormalized(der: der, digest: try XCTUnwrap(signer.lastDigest))
        )
    }

    func testRejectedAcknowledgementSettlesRejectedWithoutAcceptance() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.status = "REJECTED"
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator, overrides: overrides),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure("desktop rejected", kind: .rejected, matching: "rejected") {
            try await client.approve()
        }
        let status = await client.status()
        XCTAssertEqual(status.state, .rejected)
        XCTAssertEqual(status.acknowledgedStatus, "REJECTED")
        XCTAssertEqual(signer.callCount, 1)
        XCTAssertNil(status.presentation, "desktop REJECTED must clear presentation")
    }

    func testLocalRejectIsTerminalAndNeverInvokesTheSigner() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        try await client.reject()

        let status = await client.status()
        XCTAssertEqual(status.state, .rejected)
        XCTAssertNil(status.acknowledgedStatus)
        XCTAssertEqual(signer.callCount, 0)
        XCTAssertEqual(transport.requests(for: .complete).count, 0, "reject must not POST")
        XCTAssertNil(status.presentation, "local reject must clear presentation")

        await assertClientFailure("approve after reject", kind: .invalidState) {
            try await client.approve()
        }
        XCTAssertEqual(signer.callCount, 0)
    }
}

// MARK: - Pre-signature failures

final class RecoveryClientPreSignatureFailureTests: XCTestCase {
    /// Every listed pre-approval failure must leave the signer untouched.
    func testAllPreApprovalFailuresLeaveSignerCallCountAtZero() async throws {
        let ticketExpiry = RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds
        let now = RecoveryDesktopSimulator.nowSeconds
        let nowMs = RecoveryDesktopSimulator.nowMilliseconds

        // 1. Malformed PRB1 URI.
        try await withScenario { simulator, signer, _, client in
            await self.assertClientFailure("bad uri", kind: .protocolViolation) {
                try await client.startSession(uri: "philcore-recovery:v1:zzz", nowSeconds: now)
            }
            _ = simulator
        }

        // 2. Expired ticket at bootstrap.
        try await withScenario { simulator, _, _, client in
            await self.assertClientFailure("expired ticket", kind: .protocolViolation) {
                try await client.startSession(uri: simulator.uri, nowSeconds: ticketExpiry)
            }
        }

        // 3. Fetch with no session.
        try await withScenario { _, _, _, client in
            await self.assertClientFailure("fetch without session", kind: .invalidState) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 4. Prepare before fetch.
        try await withScenario { simulator, _, _, client in
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure("prepare before fetch", kind: .invalidState) {
                try await client.prepareApproval()
            }
        }

        // 5. Approve before prepare.
        try await withScenario { simulator, _, _, client in
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            try await client.fetchRequest(nowMilliseconds: nowMs)
            await self.assertClientFailure("approve before prepare", kind: .invalidState) {
                try await client.approve()
            }
        }

        // 6. Double fetch on the same session.
        try await withScenario { simulator, _, _, client in
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            try await client.fetchRequest(nowMilliseconds: nowMs)
            await self.assertClientFailure("second fetch", kind: .invalidState) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 7. Cancel then approve.
        try await withScenario { simulator, _, _, client in
            try await RecoveryScenario.driveToAwaitingApproval(
                client: client,
                simulator: simulator
            )
            await client.cancel()
            await self.assertClientFailure("approve after cancel", kind: .invalidState) {
                try await client.approve()
            }
        }

        // 8. Transport status not 200.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { _ in
                RecoveryTransportResponse(
                    statusCode: 500,
                    contentType: RecoveryTransportRequest.contentType,
                    body: Data("{}".utf8),
                    finalEndpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure("status 500", kind: .transport, matching: "status") {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 9. Wrong content type.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { request in
                RecoveryTransportResponse(
                    statusCode: 200,
                    contentType: "text/html",
                    body: try simulator.deliveryBody(for: request.body),
                    finalEndpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure(
                "content type",
                kind: .transport,
                matching: "content_type"
            ) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 10. Final endpoint mismatch.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { request in
                RecoveryTransportResponse(
                    statusCode: 200,
                    contentType: RecoveryTransportRequest.contentType,
                    body: try simulator.deliveryBody(for: request.body),
                    finalEndpoint: "http://10.1.2.3:9999/philcore/recovery/v1/request"
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure("url mismatch", kind: .transport, matching: "url") {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 11. Oversized delivery body.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { _ in
                FakeRecoveryTransport.ok(
                    Data(repeating: 0x20, count: RecoveryTransportRoute.request.maxIncomingBytes + 1),
                    endpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure("oversize", kind: .transport, matching: "too_large") {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 12. Tampered ciphertext fails authentication.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { request in
                FakeRecoveryTransport.ok(
                    try simulator.deliveryBody(for: request.body, tamperCiphertext: true),
                    endpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure(
                "tampered ciphertext",
                kind: .protocolViolation,
                matching: "authentication"
            ) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 13. Delivery session id mismatch.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { request in
                FakeRecoveryTransport.ok(
                    try simulator.deliveryBody(
                        for: request.body,
                        sessionIdOverride: "0x" + String(repeating: "ab", count: 32)
                    ),
                    endpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure(
                "delivery session mismatch",
                kind: .protocolViolation,
                matching: "session"
            ) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 14. Plaintext whose hash does not match the ticket request hash.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { request in
                var mutated = simulator.canonicalRequest
                mutated.append(contentsOf: [0x20])
                return FakeRecoveryTransport.ok(
                    try simulator.deliveryBody(for: request.body, plaintextOverride: mutated),
                    endpoint: simulator.requestEndpoint
                )
            }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure(
                "request hash mismatch",
                kind: .protocolViolation,
                matching: "hash_mismatch"
            ) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }

        // 15. Transport refuses to connect.
        try await withCustomTransport { simulator, _, transport, client in
            transport.setHandler(.request) { _ in throw RecoveryTransportError.unavailable }
            try await client.startSession(uri: simulator.uri, nowSeconds: now)
            await self.assertClientFailure(
                "unavailable",
                kind: .transport,
                matching: "unavailable"
            ) {
                try await client.fetchRequest(nowMilliseconds: nowMs)
            }
        }
    }

    func testApprovalAfterExpiryFailsClosedWithoutSigning() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        // Anchor the injected clock 60 ms before ticket expiry, then let real
        // monotonic time carry the session past it.
        let expiryMilliseconds = RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds * 1000
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds - 1
        )
        try await client.fetchRequest(nowMilliseconds: expiryMilliseconds - 60)
        try await client.prepareApproval()
        try await Task.sleep(nanoseconds: 200_000_000)

        await assertClientFailure("approve after expiry", kind: .expired, matching: "expired") {
            try await client.approve()
        }
        XCTAssertEqual(signer.callCount, 0, "expired session must not reach the signer")
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
    }

    // MARK: Harness

    private func withScenario(
        _ body: (
            RecoveryDesktopSimulator,
            RecoveryMockSigner,
            FakeRecoveryTransport,
            RecoveryClient
        ) async throws -> Void
    ) async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await body(simulator, signer, transport, client)
        XCTAssertEqual(signer.callCount, 0, "pre-approval failure invoked the signer")
    }

    private func withCustomTransport(
        _ body: (
            RecoveryDesktopSimulator,
            RecoveryMockSigner,
            FakeRecoveryTransport,
            RecoveryClient
        ) async throws -> Void
    ) async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = FakeRecoveryTransport()
        let client = RecoveryClient(transport: transport, signer: signer)
        try await body(simulator, signer, transport, client)
        XCTAssertEqual(signer.callCount, 0, "pre-approval failure invoked the signer")
    }
}

// MARK: - Completion failures

final class RecoveryClientCompletionFailureTests: XCTestCase {
    private func drive(
        overrides: RecoveryDesktopSimulator.AckOverrides
    ) async throws -> (RecoveryClient, RecoveryMockSigner, RecoveryDesktopSimulator) {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator, overrides: overrides),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        return (client, signer, simulator)
    }

    func testAcknowledgementWrapperMustUseVersionKey() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.wrapperUsesProtocolVersionKey = true
        let (client, signer, _) = try await drive(overrides: overrides)
        await assertClientFailure(
            "protocolVersion wrapper key",
            kind: .protocolViolation,
            matching: "acknowledgement"
        ) {
            try await client.approve()
        }
        XCTAssertEqual(signer.callCount, 1)
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
    }

    func testAcknowledgementWrapperRejectsNonNullPhoneEphemeralKey() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.wrapperPhoneKey = RecoveryCodec.encodeBase64URL(
            P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        )
        let (client, _, _) = try await drive(overrides: overrides)
        await assertClientFailure(
            "non-null phone key",
            kind: .protocolViolation,
            matching: "ephemeral_key_invalid"
        ) {
            try await client.approve()
        }
    }

    func testAcknowledgementWrapperAcceptsExplicitNullPhoneEphemeralKey() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.wrapperOmitsPhoneKey = false
        let (client, _, _) = try await drive(overrides: overrides)
        try await client.approve()
        let status = await client.status()
        XCTAssertEqual(status.state, .accepted, "desktop emits an explicit null and that is valid")
    }

    func testAcknowledgementPlaintextMustCarryExactlyFourFields() async throws {
        var extra = RecoveryDesktopSimulator.AckOverrides()
        extra.extraPlaintextField = true
        let (extraClient, _, _) = try await drive(overrides: extra)
        await assertClientFailure(
            "extra ack field",
            kind: .protocolViolation,
            matching: "unexpected_field"
        ) {
            try await extraClient.approve()
        }

        var missing = RecoveryDesktopSimulator.AckOverrides()
        missing.omitPlaintextField = "transcriptHash"
        let (missingClient, _, _) = try await drive(overrides: missing)
        await assertClientFailure(
            "missing ack field",
            kind: .protocolViolation,
            matching: "missing_field"
        ) {
            try await missingClient.approve()
        }
    }

    func testAcknowledgementStatusIsRestrictedToAcceptedOrRejected() async throws {
        for status in ["PENDING", "accepted", "", "ACCEPTED "] {
            var overrides = RecoveryDesktopSimulator.AckOverrides()
            overrides.status = status
            let (client, _, _) = try await drive(overrides: overrides)
            await assertClientFailure(
                "status '\(status)'",
                kind: .protocolViolation
            ) {
                try await client.approve()
            }
        }
    }

    func testAcknowledgementTranscriptHashMustMatch() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.transcriptHashOverride = "0x" + String(repeating: "cd", count: 32)
        let (client, _, _) = try await drive(overrides: overrides)
        await assertClientFailure(
            "transcript mismatch",
            kind: .protocolViolation,
            matching: "transcript"
        ) {
            try await client.approve()
        }
    }

    func testAcknowledgementSessionIdMustMatch() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.sessionIdOverride = "0x" + String(repeating: "ef", count: 32)
        let (client, _, _) = try await drive(overrides: overrides)
        await assertClientFailure(
            "ack session mismatch",
            kind: .protocolViolation,
            matching: "session"
        ) {
            try await client.approve()
        }
    }

    func testAcknowledgementEncryptedUnderWrongKeyFailsAuthentication() async throws {
        var overrides = RecoveryDesktopSimulator.AckOverrides()
        overrides.encryptWithWrongKey = true
        let (client, _, _) = try await drive(overrides: overrides)
        await assertClientFailure(
            "wrong ack key",
            kind: .protocolViolation,
            matching: "authentication"
        ) {
            try await client.approve()
        }
    }

    func testAcknowledgementReusingTheDeliveryNonceIsRejected() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.router([simulator]) { sim, body in
            var overrides = RecoveryDesktopSimulator.AckOverrides()
            overrides.reuseNonce = sim.lastDeliveryNonce
            return try sim.acknowledgementBody(for: body, overrides: overrides)
        }
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure(
            "nonce reuse",
            kind: .protocolViolation,
            matching: "nonce_reuse"
        ) {
            try await client.approve()
        }
    }

    func testCompletionTransportFailureIsSanitizedAndTerminal() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = FakeRecoveryTransport()
        transport.setHandler(.request) { request in
            FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { _ in
            RecoveryTransportResponse(
                statusCode: 503,
                contentType: RecoveryTransportRequest.contentType,
                body: Data("{}".utf8),
                finalEndpoint: simulator.completionEndpoint
            )
        }
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure("complete 503", kind: .transport, matching: "status") {
            try await client.approve()
        }
        XCTAssertEqual(signer.callCount, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 1, "no retry is permitted")
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertNil(status.acknowledgedStatus)
    }

    func testSignerFailureIsSanitizedAndLeavesSessionFailed() async throws {
        let signer = RecoveryMockSigner(behavior: .failure)
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure("signer refused", kind: .signer, matching: "signer") {
            try await client.approve()
        }
        XCTAssertEqual(signer.callCount, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 0, "no POST after signer failure")
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertEqual(status.failureReason, "recovery_client_signer_failed")
    }

    /// Package 4 RG1 — typed cancellation from the signer must become `.cancelled`
    /// with the fixed cancellation reason and must never reach `/complete`.
    func testTypedSignerCancellationPreservesCancelledTerminal() async throws {
        let typed = TypedErrorRecoverySigner(error: .cancelled)
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: typed.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: typed)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure(
            "typed cancel",
            kind: .cancelled,
            matching: "^recovery_client_cancelled$"
        ) {
            try await client.approve()
        }
        XCTAssertEqual(typed.callCount, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
        XCTAssertNil(simulator.lastApprovalPlaintext)
        let status = await client.status()
        XCTAssertEqual(status.state, .cancelled)
        XCTAssertEqual(status.failureReason, "recovery_client_cancelled")
        XCTAssertNil(status.presentation)
    }

    /// Package 4 RG1 — fixed `.signer("biometric_approval_denied")` must be
    /// preserved verbatim rather than collapsed to the opaque failure token.
    func testTypedSignerDenialPreservesExactReason() async throws {
        let typed = TypedErrorRecoverySigner(
            error: .signer("biometric_approval_denied")
        )
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: typed.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: typed)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure(
            "typed denial",
            kind: .signer,
            matching: "^biometric_approval_denied$"
        ) {
            try await client.approve()
        }
        XCTAssertEqual(typed.callCount, 1)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
        XCTAssertNil(simulator.lastApprovalPlaintext)
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertEqual(status.failureReason, "biometric_approval_denied")
        XCTAssertNil(status.presentation)
    }

    /// Package 4 RG1 — a replaced session during a suspended signer must still
    /// surface `.sessionReplaced` rather than mutating the live session.
    func testTypedSignerErrorOnStaleSessionRemainsSessionReplaced() async throws {
        let typed = TypedErrorRecoverySigner(error: .cancelled)
        let first = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: typed.publicKey
        )
        let second = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "ab", count: 32),
            role1SigningPublicKey: typed.publicKey
        )
        let gate = RecoveryTestGate()
        let transport = RecoveryScenario.router([first, second]) { simulator, body in
            try simulator.acknowledgementBody(for: body)
        }
        let client = RecoveryClient(transport: transport, signer: typed)
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: first)

        typed.setOnSign { await gate.wait() }
        let approveTask = Task { [client] in
            try await client.approve()
        }
        try await Task.sleep(nanoseconds: 80_000_000)
        try await client.startSession(
            uri: second.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        gate.open()
        await assertClientFailure(
            "stale typed cancel",
            kind: .sessionReplaced,
            matching: "^recovery_client_session_replaced$"
        ) {
            _ = try await approveTask.value
        }
        let status = await client.status()
        XCTAssertEqual(status.state, .bootstrapValidated)
        XCTAssertEqual(status.sessionId, second.sessionId)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
    }

    func testMalformedSignerOutputIsRejectedBeforeAnyPost() async throws {
        let signer = RecoveryMockSigner(behavior: .malformedDer)
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        await assertClientFailure("malformed der", kind: .protocolViolation, matching: "DER") {
            try await client.approve()
        }
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
    }
}

/// Test-target-only signer that throws typed `RecoveryClientError` values so
/// Package 4 can prove RecoveryClient preserves cancellation and fixed signer
/// reasons without modifying `RecoveryMockSigner`.
final class TypedErrorRecoverySigner: RecoverySigner, @unchecked Sendable {
    private let lock = NSLock()
    private let privateKey = P256.Signing.PrivateKey()
    private let error: RecoveryClientError
    private var callCountStorage = 0
    private var onSign: (@Sendable () async -> Void)?

    init(error: RecoveryClientError) {
        self.error = error
    }

    var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    var callCount: Int {
        lock.lock(); defer { lock.unlock() }
        return callCountStorage
    }

    func setOnSign(_ handler: (@Sendable () async -> Void)?) {
        lock.lock()
        onSign = handler
        lock.unlock()
    }

    func signRecoveryDigest(_ digest: Data) async throws -> Data {
        lock.lock()
        callCountStorage += 1
        let handler = onSign
        lock.unlock()
        _ = digest
        if let handler { await handler() }
        throw error
    }
}

// MARK: - Concurrency, replacement, late results

final class RecoveryClientConcurrencyTests: XCTestCase {
    func testStartSessionDuringFetchReplacesSessionAndDiscardsLateResult() async throws {
        let signer = RecoveryMockSigner()
        let first = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let second = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "77", count: 32),
            role1SigningPublicKey: signer.publicKey
        )
        XCTAssertNotEqual(first.sessionId, second.sessionId)

        let gate = RecoveryTestGate()
        let transport = FakeRecoveryTransport()
        let index = [first.sessionId: first, second.sessionId: second]
        transport.setHandler(.request) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            if simulator === first { await gate.wait() }
            return FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            return FakeRecoveryTransport.ok(
                try simulator.acknowledgementBody(for: request.body),
                endpoint: simulator.completionEndpoint
            )
        }
        let client = RecoveryClient(transport: transport, signer: signer)

        try await client.startSession(
            uri: first.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        let stale = Task { [client] in
            try await client.fetchRequest(
                nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
            )
        }
        try await Task.sleep(nanoseconds: 120_000_000)

        // Replacement happens while the first fetch is suspended.
        try await client.startSession(
            uri: second.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        var status = await client.status()
        XCTAssertEqual(status.state, .bootstrapValidated)
        XCTAssertEqual(status.generation, 2)
        XCTAssertEqual(status.sessionId, second.sessionId)

        gate.open()
        do {
            try await stale.value
            XCTFail("stale fetch must not succeed")
        } catch let error as RecoveryClientError {
            XCTAssertEqual(error.kind, .sessionReplaced)
        }

        // The late result must not have disturbed the replacement session,
        // which still completes a full flow.
        status = await client.status()
        XCTAssertEqual(status.state, .bootstrapValidated)
        XCTAssertEqual(status.sessionId, second.sessionId)

        try await client.fetchRequest(
            nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
        )
        try await client.prepareApproval()
        try await client.approve()
        status = await client.status()
        XCTAssertEqual(status.state, .accepted)
        XCTAssertEqual(status.generation, 2)
        XCTAssertEqual(signer.callCount, 1)
    }

    func testCancelDuringFetchIsTerminalAndIdempotent() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let gate = RecoveryTestGate()
        let transport = FakeRecoveryTransport()
        transport.setHandler(.request) { request in
            await gate.wait()
            return FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        let client = RecoveryClient(transport: transport, signer: signer)
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        let fetch = Task { [client] in
            try await client.fetchRequest(
                nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
            )
        }
        try await Task.sleep(nanoseconds: 120_000_000)

        await client.cancel()
        await client.cancel()
        await client.cancelForBackground()

        gate.open()
        do {
            try await fetch.value
            XCTFail("cancelled fetch must not succeed")
        } catch let error as RecoveryClientError {
            XCTAssertTrue(
                [.cancelled, .sessionReplaced].contains(error.kind),
                "unexpected kind \(error.kind)"
            )
        }
        let status = await client.status()
        XCTAssertEqual(status.state, .cancelled)
        XCTAssertEqual(signer.callCount, 0)
    }

    func testSessionReplacementDuringSigningDiscardsTheApproval() async throws {
        let signer = RecoveryMockSigner()
        let first = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let second = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "21", count: 32),
            role1SigningPublicKey: signer.publicKey
        )
        let gate = RecoveryTestGate()
        let transport = RecoveryScenario.router([first, second]) { sim, body in
            try sim.acknowledgementBody(for: body)
        }
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: first)

        signer.setOnSign { await gate.wait() }
        let approval = Task { [client] in try await client.approve() }
        try await Task.sleep(nanoseconds: 120_000_000)

        try await client.startSession(
            uri: second.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        gate.open()
        do {
            try await approval.value
            XCTFail("approval on a replaced session must not succeed")
        } catch let error as RecoveryClientError {
            XCTAssertEqual(error.kind, .sessionReplaced)
        }

        XCTAssertEqual(signer.callCount, 1)
        XCTAssertEqual(
            transport.requests(for: .complete).count,
            0,
            "a replaced session must never POST its approval"
        )
        let status = await client.status()
        XCTAssertEqual(status.state, .bootstrapValidated)
        XCTAssertEqual(status.sessionId, second.sessionId)
        XCTAssertEqual(status.generation, 2)
    }

    func testResetIsTerminalOnlyAndReturnsToIdle() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "6", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        await assertClientFailure("reset from idle", kind: .invalidState) {
            try await client.reset()
        }
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        await assertClientFailure("reset while active", kind: .invalidState) {
            try await client.reset()
        }
        await client.cancel()
        try await client.reset()

        let status = await client.status()
        XCTAssertEqual(status.state, .idle)
        XCTAssertNil(status.sessionId)
        XCTAssertNil(status.presentation)
        XCTAssertNil(status.failureReason)
    }

    func testNewSessionMayReplaceATerminalSession() async throws {
        let signer = RecoveryMockSigner()
        let first = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let second = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "13", count: 32),
            role1SigningPublicKey: signer.publicKey
        )
        let transport = RecoveryScenario.router([first, second]) { sim, body in
            try sim.acknowledgementBody(for: body)
        }
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: first)
        try await client.reject()
        let rejectedState = await client.status().state
        XCTAssertEqual(rejectedState, .rejected)

        try await client.startSession(
            uri: second.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        try await client.fetchRequest(
            nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
        )
        try await client.prepareApproval()
        try await client.approve()

        let status = await client.status()
        XCTAssertEqual(status.state, .accepted)
        XCTAssertEqual(status.generation, 2)
        XCTAssertEqual(status.sessionId, second.sessionId)
        XCTAssertEqual(signer.callCount, 1)
    }

    func testConcurrentApprovalsInvokeTheSignerAtMostOncePerSession() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let gate = RecoveryTestGate()
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: simulator)

        signer.setOnSign { await gate.wait() }
        let firstApproval = Task { [client] in try await client.approve() }
        try await Task.sleep(nanoseconds: 120_000_000)

        await assertClientFailure("second approve", kind: .invalidState) {
            try await client.approve()
        }
        gate.open()
        try await firstApproval.value

        XCTAssertEqual(signer.callCount, 1)
        let finalState = await client.status().state
        XCTAssertEqual(finalState, .accepted)
    }
}

// MARK: - Corrective Commit 3 red gates

final class RecoveryClientCorrectiveCommit3Tests: XCTestCase {
    /// RG1 — foreign DER is structurally valid but must not bind to the
    /// trusted Role 1 public key carried by the validated request.
    func testForeignSignerKeyFailsClosedBeforeComplete() async throws {
        let signer = RecoveryMockSigner(behavior: .foreignKey)
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await RecoveryScenario.driveToAwaitingApproval(
            client: client,
            simulator: simulator
        )
        let preTerminalPresentation = await client.status().presentation
        XCTAssertNotNil(preTerminalPresentation)

        await assertClientFailure(
            "foreign key",
            kind: .signer,
            matching: "^recovery_client_signer_public_key_mismatch$"
        ) {
            try await client.approve()
        }

        XCTAssertEqual(signer.callCount, 1)
        XCTAssertEqual(transport.requests(for: .request).count, 1)
        XCTAssertEqual(
            transport.requests(for: .complete).count,
            0,
            "foreign-key failure must never reach /complete"
        )
        XCTAssertNil(simulator.lastApprovalPlaintext, "approval plaintext must not be processed")
        let status = await client.status()
        XCTAssertTrue(status.state.isTerminal)
        XCTAssertEqual(status.state, .failed)
        XCTAssertEqual(status.failureReason, "recovery_client_signer_public_key_mismatch")
        XCTAssertNil(status.presentation)
        XCTAssertNil(status.acknowledgedStatus)
    }

    /// RG2 — ticket and request are each fresh, but the ticket outlives the
    /// bound request expiry and must fail closed at fetch.
    func testTicketExpiryOutlivingBoundRequestFailsAtFetch() async throws {
        let signer = RecoveryMockSigner()
        // Request expires at second 1_700_000_200; ticket at 1_700_000_300.
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey,
            ticketExpiresAtUnixSeconds: 1_700_000_300,
            requestExpiresAtMilliseconds: "1700000200000"
        )
        XCTAssertEqual(simulator.ticket.expiresAt, 1_700_000_300)
        XCTAssertEqual(simulator.validation.request.expiresAt, "1700000200000")
        XCTAssertGreaterThan(
            simulator.ticket.expiresAt,
            UInt64(simulator.validation.request.expiresAt)! / 1000
        )

        let transport = RecoveryScenario.standard(simulator)
        let client = RecoveryClient(transport: transport, signer: signer)
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.nowSeconds
        )
        await assertClientFailure(
            "ticket outlives request",
            kind: .protocolViolation,
            matching: "prb1_ticket_expiry_outlives_bound_request"
        ) {
            try await client.fetchRequest(
                nowMilliseconds: RecoveryDesktopSimulator.nowMilliseconds
            )
        }

        XCTAssertEqual(signer.callCount, 0)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
        XCTAssertEqual(transport.requests(for: .request).count, 1)
        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertNil(status.presentation)
        XCTAssertTrue(status.state.isTerminal)
    }

    /// RG3 — an acknowledgement that arrives after ticket expiry must not be
    /// accepted, even though /complete already returned.
    func testExpiryAfterCompleteAwaitRejectsAcknowledgement() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let gate = RecoveryTestGate()
        let transport = FakeRecoveryTransport()
        transport.setHandler(.request) { request in
            FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { request in
            await gate.wait()
            return FakeRecoveryTransport.ok(
                try simulator.acknowledgementBody(for: request.body),
                endpoint: simulator.completionEndpoint
            )
        }
        let client = RecoveryClient(transport: transport, signer: signer)

        let expiryMilliseconds = RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds * 1000
        try await client.startSession(
            uri: simulator.uri,
            nowSeconds: RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds - 1
        )
        try await client.fetchRequest(nowMilliseconds: expiryMilliseconds - 80)
        try await client.prepareApproval()
        let preTerminalPresentation = await client.status().presentation
        XCTAssertNotNil(preTerminalPresentation)

        let approval = Task { [client] in
            try await client.approve()
        }
        // Let approve pass the signer and suspend on /complete, then let the
        // injected session clock cross ticket expiry before releasing the ack.
        try await Task.sleep(nanoseconds: 120_000_000)
        XCTAssertEqual(transport.requests(for: .complete).count, 1)
        try await Task.sleep(nanoseconds: 200_000_000)
        gate.open()

        await assertClientFailure(
            "ack after expiry",
            kind: .expired,
            matching: "expired"
        ) {
            try await approval.value
        }

        let status = await client.status()
        XCTAssertEqual(status.state, .failed)
        XCTAssertNil(status.acknowledgedStatus)
        XCTAssertNil(status.presentation)
        XCTAssertEqual(transport.requests(for: .complete).count, 1, "no retry after expiry")
        XCTAssertEqual(signer.callCount, 1)
    }

    /// RG4 — every terminal class clears presentation immediately, without
    /// requiring `reset()`.
    func testTerminalOutcomesClearPresentationImmediately() async throws {
        enum TerminalCase: String, CaseIterable {
            case accepted
            case desktopRejected
            case localReject
            case cancel
            case backgroundCancel
            case protocolAfterPresentation
            case expiryAfterPresentation
        }

        for terminalCase in TerminalCase.allCases {
            let signer = RecoveryMockSigner()
            let simulator = try RecoveryDesktopSimulator(
                bitmap: "3",
                owner: Self.self,
                role1SigningPublicKey: signer.publicKey
            )

            switch terminalCase {
            case .accepted:
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                let preTerminalPresentation = await client.status().presentation
                XCTAssertNotNil(preTerminalPresentation)
                try await client.approve()
                let status = await client.status()
                XCTAssertEqual(status.state, .accepted)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .desktopRejected:
                var overrides = RecoveryDesktopSimulator.AckOverrides()
                overrides.status = "REJECTED"
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator, overrides: overrides),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                await assertClientFailure("\(terminalCase)", kind: .rejected) {
                    try await client.approve()
                }
                let status = await client.status()
                XCTAssertEqual(status.state, .rejected)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .localReject:
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                try await client.reject()
                let status = await client.status()
                XCTAssertEqual(status.state, .rejected)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .cancel:
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                await client.cancel()
                let status = await client.status()
                XCTAssertEqual(status.state, .cancelled)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .backgroundCancel:
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                await client.cancelForBackground()
                let status = await client.status()
                XCTAssertEqual(status.state, .cancelled)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .protocolAfterPresentation:
                var overrides = RecoveryDesktopSimulator.AckOverrides()
                overrides.wrapperUsesProtocolVersionKey = true
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator, overrides: overrides),
                    signer: signer
                )
                try await RecoveryScenario.driveToAwaitingApproval(
                    client: client,
                    simulator: simulator
                )
                await assertClientFailure("\(terminalCase)", kind: .protocolViolation) {
                    try await client.approve()
                }
                let status = await client.status()
                XCTAssertEqual(status.state, .failed)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")

            case .expiryAfterPresentation:
                let client = RecoveryClient(
                    transport: RecoveryScenario.standard(simulator),
                    signer: signer
                )
                let expiryMilliseconds =
                    RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds * 1000
                try await client.startSession(
                    uri: simulator.uri,
                    nowSeconds: RecoveryDesktopSimulator.ticketExpiresAtUnixSeconds - 1
                )
                try await client.fetchRequest(nowMilliseconds: expiryMilliseconds - 60)
                try await client.prepareApproval()
                let preTerminalPresentation = await client.status().presentation
                XCTAssertNotNil(preTerminalPresentation)
                try await Task.sleep(nanoseconds: 200_000_000)
                await assertClientFailure("\(terminalCase)", kind: .expired) {
                    try await client.approve()
                }
                let status = await client.status()
                XCTAssertEqual(status.state, .failed)
                XCTAssertNil(status.presentation, "\(terminalCase.rawValue)")
            }
        }
    }
}

// MARK: - Static boundary and policy gates

final class RecoveryTransportBoundaryTests: XCTestCase {
    override func setUp() {
        super.setUp()
        RecoveryLoopbackControl.shared.reset()
    }

    override func tearDown() {
        RecoveryLoopbackControl.shared.reset()
        super.tearDown()
    }

    // MARK: URLSession policy

    func testEphemeralSessionConfigurationPinsTheHardenedPolicy() throws {
        let configuration = URLSessionRecoveryTransport.makeConfiguration()
        XCTAssertFalse(configuration.waitsForConnectivity)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertEqual(configuration.httpCookieAcceptPolicy, .never)
        XCTAssertNil(configuration.httpCookieStorage)
        XCTAssertNil(configuration.urlCache)
        XCTAssertEqual(configuration.requestCachePolicy, .reloadIgnoringLocalAndRemoteCacheData)
        XCTAssertEqual(configuration.connectionProxyDictionary?.count, 0)
        XCTAssertFalse(configuration.allowsCellularAccess)
        XCTAssertFalse(configuration.allowsExpensiveNetworkAccess)
        XCTAssertFalse(configuration.allowsConstrainedNetworkAccess)
        XCTAssertFalse(configuration.httpShouldUsePipelining)
        XCTAssertFalse(configuration.shouldUseExtendedBackgroundIdleMode)
        XCTAssertEqual(configuration.httpMaximumConnectionsPerHost, 1)
        XCTAssertEqual(
            configuration.identifier,
            nil,
            "an ephemeral configuration must not be a background session"
        )
    }

    func testRedirectDelegateAlwaysResolvesToNil() throws {
        let delegate = URLSessionRecoveryTransport.RedirectBlockingDelegate()
        let session = URLSession(configuration: .ephemeral)
        let url = try XCTUnwrap(URL(string: "http://192.168.1.45:8787/philcore/recovery/v1/request"))
        let task = session.dataTask(with: url)
        let redirect = try XCTUnwrap(
            HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: nil)
        )
        let expectation = expectation(description: "redirect resolved")
        var resolved: URLRequest? = URLRequest(url: url)
        delegate.urlSession(
            session,
            task: task,
            willPerformHTTPRedirection: redirect,
            newRequest: URLRequest(url: url)
        ) { value in
            resolved = value
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 2)
        XCTAssertNil(resolved, "the client must never follow a redirect")
        task.cancel()
        session.invalidateAndCancel()
    }

    // MARK: Route ceilings

    func testRouteByteCeilingsArePinned() {
        XCTAssertEqual(RecoveryTransportRoute.request.maxOutgoingBytes, 1024)
        XCTAssertEqual(RecoveryTransportRoute.complete.maxOutgoingBytes, 16384)
        XCTAssertEqual(RecoveryTransportRoute.request.maxIncomingBytes, 32768)
        XCTAssertEqual(RecoveryTransportRoute.complete.maxIncomingBytes, 16384)
        XCTAssertEqual(RecoveryTransportRoute.request.path, "/philcore/recovery/v1/request")
        XCTAssertEqual(RecoveryTransportRoute.complete.path, "/philcore/recovery/v1/complete")
        XCTAssertEqual(RecoveryTransportRequest.method, "POST")
        XCTAssertEqual(RecoveryTransportRequest.contentType, "application/json; charset=utf-8")
    }

    func testAccumulatorRefusesToCrossItsCeiling() throws {
        var accumulator = RecoveryByteAccumulator(limit: 4)
        try accumulator.append(contentsOf: Data([1, 2, 3]))
        XCTAssertEqual(accumulator.count, 3)
        try accumulator.append(0x04)
        XCTAssertEqual(accumulator.count, 4)
        XCTAssertThrowsError(try accumulator.append(0x05)) { error in
            XCTAssertEqual(error as? RecoveryTransportError, .responseTooLarge)
        }
        XCTAssertEqual(accumulator.count, 4, "a rejected append must not grow the buffer")

        var chunked = RecoveryByteAccumulator(limit: 4)
        XCTAssertThrowsError(try chunked.append(contentsOf: Data(repeating: 0, count: 5)))
        XCTAssertEqual(chunked.count, 0)
    }

    // MARK: Endpoint allowlist

    func testEndpointPolicyAcceptsOnlyLiteralPrivateIPv4Routes() throws {
        for endpoint in [
            "http://192.168.1.45:8787/philcore/recovery/v1/request",
            "http://10.0.0.1:1024/philcore/recovery/v1/request",
            "http://172.16.9.9:65535/philcore/recovery/v1/request"
        ] {
            XCTAssertNoThrow(
                try RecoveryEndpointPolicy.validate(endpoint, route: .request),
                endpoint
            )
        }
        let rejected = [
            "https://192.168.1.45:8787/philcore/recovery/v1/request",
            "http://desktop.local:8787/philcore/recovery/v1/request",
            "http://192.168.1.45/philcore/recovery/v1/request",
            "http://[fd00::1]:8787/philcore/recovery/v1/request",
            "http://8.8.8.8:8787/philcore/recovery/v1/request",
            "http://127.0.0.1:8787/philcore/recovery/v1/request",
            "http://169.254.1.1:8787/philcore/recovery/v1/request",
            "http://user@192.168.1.45:8787/philcore/recovery/v1/request",
            "http://192.168.1.45:8787/philcore/recovery/v1/complete",
            "http://192.168.1.45:8787/philcore/recovery/v1/request?x=1",
            "http://192.168.1.45:8787/philcore/recovery/v1/request#f",
            "http://192.168.1.45:8787/philcore/recovery/v1/../request",
            "http://192.168.1.45:80/philcore/recovery/v1/request",
            "http://192.168.001.45:8787/philcore/recovery/v1/request",
            "http://192.168.1.45:8787/philcore/recovery/v1/requestx",
            "http://192.168.1.45:8787/"
        ]
        for endpoint in rejected {
            XCTAssertThrowsError(
                try RecoveryEndpointPolicy.validate(endpoint, route: .request),
                endpoint
            ) { error in
                XCTAssertEqual(error as? RecoveryTransportError, .endpointInvalid, endpoint)
            }
        }
        XCTAssertNoThrow(
            try RecoveryEndpointPolicy.validate(
                "http://192.168.1.45:8787/philcore/recovery/v1/complete",
                route: .complete
            )
        )
    }

    // MARK: Deadlines

    func testDeadlinesNeverOutliveTheTicket() throws {
        let expiry: UInt64 = 1_700_000_300
        let request = try RecoveryTransportDeadline.forRequest(
            nowMilliseconds: 1_700_000_100_000,
            ticketExpiresAtUnixSeconds: expiry
        )
        XCTAssertEqual(request.timeoutSeconds, 10, accuracy: 0.001)
        XCTAssertEqual(request.expiresAtUnixMilliseconds, 1_700_000_110_000)

        // Close to expiry the ten second budget is clamped by the ticket.
        let clamped = try RecoveryTransportDeadline.forRequest(
            nowMilliseconds: 1_700_000_297_000,
            ticketExpiresAtUnixSeconds: expiry
        )
        XCTAssertEqual(clamped.timeoutSeconds, 3, accuracy: 0.001)
        XCTAssertEqual(clamped.expiresAtUnixMilliseconds, expiry * 1000)

        let completion = try RecoveryTransportDeadline.forCompletion(
            nowMilliseconds: 1_700_000_100_000,
            ticketExpiresAtUnixSeconds: expiry
        )
        XCTAssertEqual(completion.timeoutSeconds, 200, accuracy: 0.001)
        XCTAssertEqual(completion.expiresAtUnixMilliseconds, expiry * 1000)

        for now in [expiry * 1000, expiry * 1000 + 1] {
            XCTAssertThrowsError(
                try RecoveryTransportDeadline.forCompletion(
                    nowMilliseconds: now,
                    ticketExpiresAtUnixSeconds: expiry
                )
            ) { error in
                XCTAssertEqual(error as? RecoveryTransportError, .deadlineExceeded)
            }
        }
    }

    // MARK: Real URLSession path, injected protocol, no socket

    private func loopbackTransport() -> URLSessionRecoveryTransport {
        URLSessionRecoveryTransport(
            additionalProtocolClasses: [RecoveryLoopbackURLProtocol.self]
        )
    }

    private func sampleRequest(
        route: RecoveryTransportRoute = .request,
        body: Data = Data("{}".utf8)
    ) throws -> RecoveryTransportRequest {
        RecoveryTransportRequest(
            endpoint: "http://192.168.1.45:8787" + route.path,
            route: route,
            body: body,
            deadline: try RecoveryTransportDeadline.forRequest(
                nowMilliseconds: 1_700_000_100_000,
                ticketExpiresAtUnixSeconds: 1_700_000_300
            )
        )
    }

    func testURLSessionTransportAcceptsAWellFormedResponse() async throws {
        var stub = RecoveryLoopbackControl.Stub()
        stub.body = Data(#"{"ok":true}"#.utf8)
        RecoveryLoopbackControl.shared.stub = stub

        let transport = loopbackTransport()
        let response = try await transport.send(try sampleRequest(body: Data(#"{"a":1}"#.utf8)))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.contentType, RecoveryTransportRequest.contentType)
        XCTAssertEqual(response.body, stub.body)
        XCTAssertEqual(
            response.finalEndpoint,
            "http://192.168.1.45:8787/philcore/recovery/v1/request"
        )
        XCTAssertEqual(RecoveryLoopbackControl.shared.handledCount, 1)
        XCTAssertEqual(RecoveryLoopbackControl.shared.bodies.first, Data(#"{"a":1}"#.utf8))
    }

    func testURLSessionTransportRejectsRedirectStatusWithoutFollowingIt() async throws {
        var stub = RecoveryLoopbackControl.Stub()
        stub.statusCode = 302
        stub.body = Data()
        RecoveryLoopbackControl.shared.stub = stub

        let transport = loopbackTransport()
        await assertTransportFailure("302", matching: "redirect_forbidden") {
            _ = try await transport.send(try self.sampleRequest())
        }
        XCTAssertEqual(
            RecoveryLoopbackControl.shared.handledCount,
            1,
            "exactly one attempt, the redirect was never followed"
        )
    }

    func testURLSessionTransportRejectsWrongStatusAndContentType() async throws {
        var badStatus = RecoveryLoopbackControl.Stub()
        badStatus.statusCode = 500
        RecoveryLoopbackControl.shared.stub = badStatus
        let transport = loopbackTransport()
        await assertTransportFailure("500", matching: "status_not_ok") {
            _ = try await transport.send(try self.sampleRequest())
        }

        var badType = RecoveryLoopbackControl.Stub()
        badType.contentType = "application/json"
        RecoveryLoopbackControl.shared.stub = badType
        await assertTransportFailure("charset missing", matching: "content_type") {
            _ = try await transport.send(try self.sampleRequest())
        }

        var noType = RecoveryLoopbackControl.Stub()
        noType.contentType = nil
        RecoveryLoopbackControl.shared.stub = noType
        await assertTransportFailure("no content type", matching: "content_type") {
            _ = try await transport.send(try self.sampleRequest())
        }
    }

    func testURLSessionTransportRejectsDeclaredAndStreamedOversizeBodies() async throws {
        let limit = RecoveryTransportRoute.complete.maxIncomingBytes

        var declared = RecoveryLoopbackControl.Stub()
        declared.body = Data(repeating: 0x20, count: limit + 1)
        declared.declaresContentLength = true
        RecoveryLoopbackControl.shared.stub = declared
        let transport = loopbackTransport()
        await assertTransportFailure("declared oversize", matching: "too_large") {
            _ = try await transport.send(try self.sampleRequest(route: .complete))
        }

        // Undeclared length forces the streaming accumulator to catch it.
        RecoveryLoopbackControl.shared.reset()
        var streamed = RecoveryLoopbackControl.Stub()
        streamed.body = Data(repeating: 0x20, count: limit + 512)
        streamed.declaresContentLength = false
        streamed.chunkCount = 16
        RecoveryLoopbackControl.shared.stub = streamed
        await assertTransportFailure("streamed oversize", matching: "too_large") {
            _ = try await transport.send(try self.sampleRequest(route: .complete))
        }
    }

    func testURLSessionTransportRejectsOversizeOutgoingBodyBeforeSending() async throws {
        RecoveryLoopbackControl.shared.reset()
        let transport = loopbackTransport()
        let oversize = Data(
            repeating: 0x20,
            count: RecoveryTransportRoute.request.maxOutgoingBytes + 1
        )
        await assertTransportFailure("outgoing oversize", matching: "request_body_too_large") {
            _ = try await transport.send(try self.sampleRequest(body: oversize))
        }
        XCTAssertEqual(
            RecoveryLoopbackControl.shared.handledCount,
            0,
            "an oversize body must never reach the socket layer"
        )
    }

    func testURLSessionTransportRejectsAResponseFromADifferentURL() async throws {
        var stub = RecoveryLoopbackControl.Stub()
        stub.body = Data("{}".utf8)
        stub.responseURLOverride = "http://10.9.9.9:8787/philcore/recovery/v1/request"
        RecoveryLoopbackControl.shared.stub = stub
        let transport = loopbackTransport()
        await assertTransportFailure("url mismatch", matching: "url_mismatch") {
            _ = try await transport.send(try self.sampleRequest())
        }
    }

    func testCancellingOneAttemptLeavesTheTransportReusable() async throws {
        var slow = RecoveryLoopbackControl.Stub()
        slow.body = Data("{}".utf8)
        slow.delayNanoseconds = 2_000_000_000
        RecoveryLoopbackControl.shared.stub = slow

        let transport = loopbackTransport()
        let attempt = Task { [transport] in
            try await transport.send(try self.sampleRequest())
        }
        try await Task.sleep(nanoseconds: 150_000_000)
        attempt.cancel()
        do {
            _ = try await attempt.value
            XCTFail("cancelled attempt must not succeed")
        } catch {
            XCTAssertTrue(
                error is RecoveryTransportError || error is CancellationError,
                "unexpected error \(error)"
            )
        }

        // The same transport instance must still work: the session was never
        // invalidated, only the captured task was cancelled.
        var fast = RecoveryLoopbackControl.Stub()
        fast.body = Data(#"{"second":true}"#.utf8)
        RecoveryLoopbackControl.shared.stub = fast
        let response = try await transport.send(try sampleRequest())
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.body, fast.body)
    }
}

// MARK: - Source, binary, and fixture gates

final class RecoveryPackage3BIsolationTests: XCTestCase {
    private static let productionSources = ["RecoveryTransport.swift", "RecoveryClient.swift"]

    private static func productionSource(
        _ name: String,
        file: StaticString = #filePath
    ) throws -> String {
        let url = URL(fileURLWithPath: String(describing: file))
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("PhilCoreCompanion")
            .appendingPathComponent(name)
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testProductionSourcesDoNotReferenceTheTestOnlySigner() throws {
        for name in Self.productionSources {
            let text = try Self.productionSource(name)
            XCTAssertFalse(
                text.contains("RecoveryMockSigner"),
                "\(name) must not reference the test-only signer"
            )
            XCTAssertFalse(text.contains("import XCTest"), "\(name) must not import XCTest")
        }
    }

    func testProductionSourcesAvoidKeychainSecureEnclaveAndLocalAuthentication() throws {
        let forbidden = [
            "import Security", "import LocalAuthentication", "import Network",
            "SecItemAdd", "SecItemCopyMatching", "SecItemDelete", "kSecAttr", "kSecClass",
            "SecureEnclave", "LAContext", "LAPolicy",
            "NWConnection", "NWListener", "CFSocket", "Socket(", "sockaddr"
        ]
        for name in Self.productionSources {
            let text = try Self.productionSource(name)
            for needle in forbidden {
                XCTAssertFalse(
                    text.contains(needle),
                    "\(name) must not reference \(needle)"
                )
            }
        }
    }

    func testProductionTransportOpensNoSocketOfItsOwn() throws {
        let text = try Self.productionSource("RecoveryTransport.swift")
        XCTAssertTrue(text.contains("URLSessionConfiguration.ephemeral"))
        XCTAssertFalse(
            text.contains("invalidateAndCancel"),
            "cancelling an attempt must never invalidate the reusable session"
        )
        XCTAssertFalse(text.contains("URLSessionConfiguration.background"))
    }

    func testTestOnlySignerIsAbsentFromTheBuiltAppBinary() throws {
        let executable = try XCTUnwrap(Bundle.main.executableURL)
        XCTAssertEqual(executable.lastPathComponent, "PhilCoreCompanion")
        let binary = try Data(contentsOf: executable)
        XCTAssertGreaterThan(binary.count, 1024)

        // Positive control: a production Package 3A/3B symbol is present, so a
        // negative result below is meaningful rather than vacuous.
        XCTAssertTrue(
            Self.contains(binary, Data("RecoveryCanonicalRequest".utf8)),
            "scan is vacuous: no production symbol found in the app binary"
        )
        XCTAssertTrue(Self.contains(binary, Data("RecoveryClient".utf8)))
        XCTAssertFalse(
            Self.contains(binary, Data("RecoveryMockSigner".utf8)),
            "the test-only signer must never ship inside the app binary"
        )
    }

    func testFixturesAreNotCopiedIntoTheAppBundle() throws {
        XCTAssertNil(
            Bundle.main.url(forResource: RecoveryFixtures.o44Resource, withExtension: "json"),
            "O.44 fixtures must stay out of the app bundle"
        )
        XCTAssertNil(
            Bundle.main.url(forResource: RecoveryFixtures.o45Resource, withExtension: "json"),
            "O.45 fixtures must stay out of the app bundle"
        )
        // They remain available to the unit-test bundle only.
        XCTAssertNotNil(
            Bundle(for: Self.self).url(
                forResource: RecoveryFixtures.o45Resource,
                withExtension: "json"
            )
        )
    }

    func testFixtureBytesAreUnchangedByPackage3B() throws {
        let o44 = try RecoveryFixtures.fixtureData(RecoveryFixtures.o44Resource, for: Self.self)
        let o45 = try RecoveryFixtures.fixtureData(RecoveryFixtures.o45Resource, for: Self.self)
        XCTAssertEqual(
            RecoveryFixtures.hexString(Data(SHA256.hash(data: o44))),
            "50482c8e532db528b20eceed76eac181f0c94ca018d414f3a5f45add1942a98a"
        )
        XCTAssertEqual(
            RecoveryFixtures.hexString(Data(SHA256.hash(data: o45))),
            "e553c795561f0416754248a0746a70598c7680743ec6cb52b30769e4e4204fd2"
        )
    }

    func testApprovalConstantsMatchTheO44Fixture() throws {
        let o44 = try RecoveryFixtures.fixtureObject(RecoveryFixtures.o44Resource, for: Self.self)
        let constants = try XCTUnwrap(o44["protocolConstants"] as? [String: Any])
        XCTAssertEqual(
            constants["hkdfInfo"] as? String,
            RecoveryApprovalCodec.hkdfInfo
        )
        XCTAssertEqual(
            constants["aadPhoneToDesktop"] as? String,
            RecoveryApprovalCodec.aadPhoneToDesktop
        )
        XCTAssertEqual(
            constants["aadDesktopToPhone"] as? String,
            RecoveryApprovalCodec.aadDesktopToPhone
        )
        XCTAssertEqual(
            constants["endpointPath"] as? String,
            RecoveryTransportRoute.complete.path
        )
        XCTAssertEqual(
            constants["transcriptLabel"] as? String,
            RecoveryCanonicalRequest.transcriptLabel
        )
    }

    /// Request and approval keys are derived from the same shared secret but
    /// with different salts and infos, so they must never collide.
    func testRequestAndApprovalKeysAreDomainSeparated() throws {
        let desktop = P256.KeyAgreement.PrivateKey()
        let phone = P256.KeyAgreement.PrivateKey()
        let shared = try desktop.sharedSecretFromKeyAgreement(with: phone.publicKey)
            .withUnsafeBytes { Data($0) }
        let requestHash = Data(SHA256.hash(data: Data("request".utf8)))
        let transcriptHash = Data(SHA256.hash(data: Data("transcript".utf8)))

        let requestKey = try RecoveryBootstrap.deriveRequestAesKey(
            sharedSecret: shared,
            requestHash: requestHash
        )
        let approvalKey = try RecoveryApprovalCodec.deriveApprovalAesKey(
            sharedSecret: shared,
            transcriptHash: transcriptHash
        )
        XCTAssertEqual(requestKey.count, 32)
        XCTAssertEqual(approvalKey.count, 32)
        XCTAssertNotEqual(requestKey, approvalKey)

        // Even with an identical salt the info strings keep them apart.
        let sameSalt = try RecoveryApprovalCodec.deriveApprovalAesKey(
            sharedSecret: shared,
            transcriptHash: requestHash
        )
        XCTAssertNotEqual(sameSalt, requestKey)
    }

    /// O.45 request HKDF uses the request hash as salt, never the session id.
    func testRequestHkdfUsesRequestHashAsSalt() throws {
        let shared = Data(repeating: 0x11, count: 32)
        let requestHash = Data(repeating: 0x22, count: 32)
        let sessionId = Data(repeating: 0x33, count: 32)
        let derived = try RecoveryBootstrap.deriveRequestAesKey(
            sharedSecret: shared,
            requestHash: requestHash
        )
        let expected = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared),
            salt: requestHash,
            info: Data("PHILCORE_NATIVE_RECOVERY_REQUEST_AES256_GCM_V1".utf8),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
        XCTAssertEqual(derived, expected)

        let sessionSalted = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared),
            salt: sessionId,
            info: Data("PHILCORE_NATIVE_RECOVERY_REQUEST_AES256_GCM_V1".utf8),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(derived, sessionSalted, "salt must be requestHash, not sessionId")
    }

    func testApprovalAadShapeIsExact() throws {
        let sessionId = "0x" + String(repeating: "45", count: 32)
        XCTAssertEqual(
            String(
                data: try RecoveryApprovalCodec.buildAad(
                    direction: RecoveryApprovalCodec.aadPhoneToDesktop,
                    sessionId: sessionId
                ),
                encoding: .utf8
            ),
            "IPHONE_TO_DESKTOP_RECOVERY_APPROVAL_V1|\(sessionId)"
        )
        XCTAssertEqual(
            String(
                data: try RecoveryApprovalCodec.buildAad(
                    direction: RecoveryApprovalCodec.aadDesktopToPhone,
                    sessionId: sessionId.uppercased().replacingOccurrences(of: "0X", with: "0x")
                ),
                encoding: .utf8
            ),
            "DESKTOP_TO_IPHONE_RECOVERY_APPROVAL_V1|\(sessionId)",
            "the session id is normalised to lowercase inside the AAD"
        )
    }

    func testStatusSnapshotCarriesNoSecretMaterial() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(bitmap: "3", owner: Self.self, role1SigningPublicKey: signer.publicKey)
        let client = RecoveryClient(
            transport: RecoveryScenario.standard(simulator),
            signer: signer
        )
        try await RecoveryScenario.driveToAwaitingApproval(client: client, simulator: simulator)

        var status = await client.status()
        let presentation = try XCTUnwrap(status.presentation)
        XCTAssertEqual(presentation.sessionId, simulator.sessionId)
        XCTAssertEqual(
            presentation.comparisonFingerprint,
            simulator.validation.comparisonFingerprint
        )

        try await client.approve()
        status = await client.status()
        let mirrored = String(describing: status)
        for secret in [
            RecoveryCodec.hexString(simulator.canonicalRequest.prefix(16)),
            RecoveryCodec.encodeBase64URL(try XCTUnwrap(simulator.sharedSecret)),
            RecoveryCodec.hexString(try XCTUnwrap(simulator.sharedSecret))
        ] {
            XCTAssertFalse(mirrored.contains(secret), "snapshot leaked secret material")
        }
        XCTAssertFalse(mirrored.lowercased().contains("privatekey"))
        XCTAssertFalse(mirrored.lowercased().contains("ciphertext"))
        XCTAssertFalse(mirrored.lowercased().contains("sharedsecret"))
        XCTAssertNil(status.presentation, "accepted status must not retain presentation")
    }

    private static func contains(_ haystack: Data, _ needle: Data) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        return haystack.range(of: needle) != nil
    }
}
