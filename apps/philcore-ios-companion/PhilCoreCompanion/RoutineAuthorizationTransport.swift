import CryptoKit
import Foundation

/// Only source-controlled schema field names are emitted; never raw values.
struct RoutineBindingMismatch: Error, Equatable {
    let field: String
}

enum RoutineAuthorizationFailure: String, Error, LocalizedError, Equatable {
    case malformedBootstrap = "routine_bootstrap_malformed"
    case expired = "routine_request_expired"
    case bindingMismatch = "routine_binding_mismatch"
    case outcomeUnknown = "routine_submission_outcome_unknown"
    case transportFailure = "routine_transport_failed"
    case localNetworkUnavailable = "routine_local_network_unavailable"
    case desktopUnavailable = "routine_desktop_unavailable"
    case authenticationFailure = "routine_transport_authentication_failed"
    case routineKeyUnavailable = "routine_key_unavailable"
    case routineKeyMismatch = "routine_key_metadata_mismatch"
    case routineKeyGenerationMismatch = "routine_key_generation_mismatch"
    case routineKeyActivationFailed = "routine_key_activation_failed"
    case routineKeyCommitFailed = "routine_key_commit_failed"
    case routineSigningFailed = "routine_signing_failed"
    case desktopRejected = "routine_desktop_rejected"
    case malformedRequest = "routine_request_malformed"
    case presentationMismatch = "routine_presentation_mismatch"
    case userCancelled = "routine_user_cancelled"
    case userDenied = "routine_user_denied"
    case sessionReplaced = "routine_session_replaced"

    var errorDescription: String? {
        switch self {
        case .outcomeUnknown: return "The request may have been submitted. Do not retry; reconcile its status on Desktop first."
        case .expired: return "This routine request expired."
        case .userCancelled: return "Routine authorization was cancelled."
        case .userDenied: return "Routine authorization was denied."
        case .localNetworkUnavailable: return "PhilCore cannot use this iPhone's local network. Enable PhilCore Companion in Settings > Privacy & Security > Local Network, confirm Wi-Fi is on, and try again."
        case .desktopUnavailable: return "PhilCore Desktop is not reachable on this Wi-Fi network. Keep both devices on the same Wi-Fi network and leave the Desktop request open."
        case .routineKeyUnavailable: return "The saved routine-key record does not have a usable Secure Enclave key. No enrollment response was sent."
        case .routineKeyMismatch: return "The Secure Enclave key does not match the saved routine-key record. No enrollment response was sent."
        case .routineKeyGenerationMismatch: return "This disposable routine key belongs to a different Desktop enrollment generation. Delete only the disposable routine key, create a new one, then scan a fresh Desktop enrollment request. Phil identity and recovery keys are not changed."
        case .routineKeyActivationFailed: return "The signed routine key could not be activated safely on this iPhone. No enrollment response was sent."
        case .routineKeyCommitFailed: return "PhilCore Desktop accepted the routine key, but this iPhone could not finalize its local enrollment metadata. Do not repeat enrollment until this state is reviewed."
        case .routineSigningFailed: return "Face ID completed, but the Secure Enclave could not sign the routine enrollment proof. No enrollment response was sent."
        case .desktopRejected: return "The routine-enrollment endpoint did not accept the signed response. The unsigned rejection cannot be attributed to PhilCore Desktop."
        case .bindingMismatch: return "The request binding did not match. No approval was submitted. Check the field diagnostic before trying again."
        case .sessionReplaced: return "This request was superseded by a newer request."
        default: return "Phil could not confirm the request outcome. Check Desktop status before trying again."
        }
    }
}

struct RoutineAuthorizationBootstrap: Equatable, Sendable {
    static let prefix = "phil-step6c-routine-v1:"
    static let magic = Data("PHIL6C01".utf8)
    static let beginPath = "/philcore/routine/v1/begin"
    static let completePath = "/philcore/routine/v1/complete"
    static let terminalPath = "/philcore/routine/v1/terminal"
    static let transcriptLabel = "PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1"
    static let hkdfInfo = "PHIL_ROUTINE_AUTHORIZATION_AES256_GCM_V1"

    let sessionId: Data
    let ipv4: UInt32
    let port: UInt16
    let desktopPublicKey: Data
    let requestId: Data
    let expiresAt: UInt64

    var dottedIPv4: String {
        [24, 16, 8, 0].map { String((ipv4 >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    var origin: String { "http://\(dottedIPv4):\(port)" }

    static func decode(_ text: String, now: UInt64) throws -> RoutineAuthorizationBootstrap {
        guard !text.contains(where: { $0.isWhitespace }), text.hasPrefix(prefix) else {
            throw RoutineAuthorizationFailure.malformedBootstrap
        }
        let encoded = String(text.dropFirst(prefix.count))
        guard !encoded.isEmpty, !encoded.contains("="), !encoded.contains("+"), !encoded.contains("/"),
              encoded.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }),
              let raw = Data(base64URLEncoded: encoded), raw.count == 216,
              raw.base64URLString == encoded else {
            throw RoutineAuthorizationFailure.malformedBootstrap
        }
        guard raw.prefix(8) == magic, raw[8] == 1 else { throw RoutineAuthorizationFailure.malformedBootstrap }
        let session = raw.subdata(in: 9..<41)
        let ipv4 = raw.readUInt32BE(at: 41)
        let port = raw.readUInt16BE(at: 45)
        let beginHash = raw.subdata(in: 47..<79)
        let completeHash = raw.subdata(in: 79..<111)
        let desktopKey = raw.subdata(in: 111..<176)
        let request = raw.subdata(in: 176..<208)
        let expires = raw.readUInt64BE(at: 208)
        guard session != Data(repeating: 0, count: 32), request != Data(repeating: 0, count: 32), port != 0,
              beginHash == Data(SHA256OrKeccak.keccak256(Data(beginPath.utf8))),
              completeHash == Data(SHA256OrKeccak.keccak256(Data(completePath.utf8))),
              isRFC1918(ipv4),
              (try? P256.KeyAgreement.PublicKey(x963Representation: desktopKey)) != nil else {
            throw RoutineAuthorizationFailure.malformedBootstrap
        }
        guard expires > now else { throw RoutineAuthorizationFailure.expired }
        let value = RoutineAuthorizationBootstrap(
            sessionId: session, ipv4: ipv4, port: port, desktopPublicKey: desktopKey,
            requestId: request, expiresAt: expires
        )
        guard value.encode() == text else { throw RoutineAuthorizationFailure.malformedBootstrap }
        return value
    }

    func encode() -> String {
        var raw = Data(); raw.append(Self.magic); raw.append(1); raw.append(sessionId)
        raw.appendUInt32BE(ipv4); raw.appendUInt16BE(port)
        raw.append(Data(SHA256OrKeccak.keccak256(Data(Self.beginPath.utf8))))
        raw.append(Data(SHA256OrKeccak.keccak256(Data(Self.completePath.utf8))))
        raw.append(desktopPublicKey); raw.append(requestId); raw.appendUInt64BE(expiresAt)
        return Self.prefix + raw.base64URLString
    }

    private static func isRFC1918(_ value: UInt32) -> Bool {
        let a = UInt8((value >> 24) & 0xff), b = UInt8((value >> 16) & 0xff)
        return a == 10 || (a == 172 && (16...31).contains(b)) || (a == 192 && b == 168)
    }
}

private enum SHA256OrKeccak {
    static func keccak256(_ data: Data) -> [UInt8] { Array(RecoveryKeccak.keccak256(data)) }
}

struct RoutineAuthorizationHandshake: Sendable {
    let bootstrap: RoutineAuthorizationBootstrap
    let privateKey: P256.KeyAgreement.PrivateKey
    let iphonePublicKey: Data
    let transcriptHash: Data
    let fingerprint: String
    let trafficKey: SymmetricKey

    init(bootstrap: RoutineAuthorizationBootstrap, privateKey: P256.KeyAgreement.PrivateKey = .init()) throws {
        self.bootstrap = bootstrap
        self.privateKey = privateKey
        iphonePublicKey = privateKey.publicKey.x963Representation
        transcriptHash = Self.transcriptHash(bootstrap: bootstrap, iphonePublicKey: iphonePublicKey)
        fingerprint = transcriptHash.prefix(12).map { String(format: "%02X", $0) }
            .chunked(every: 4).joined(separator: "-")
        let desktop = try P256.KeyAgreement.PublicKey(x963Representation: bootstrap.desktopPublicKey)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: desktop)
        trafficKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: transcriptHash,
            sharedInfo: Data(RoutineAuthorizationBootstrap.hkdfInfo.utf8),
            outputByteCount: 32
        )
    }

    static func transcriptHash(bootstrap: RoutineAuthorizationBootstrap, iphonePublicKey: Data) -> Data {
        let domain = RecoveryKeccak.keccak256(Data(RoutineAuthorizationBootstrap.transcriptLabel.utf8))
        var head = Data()
        head.append(domain)
        head.appendABIUnsigned(UInt64(1))
        head.append(bootstrap.sessionId)
        head.appendABIUnsigned(UInt64(bootstrap.ipv4))
        head.appendABIUnsigned(UInt64(bootstrap.port))
        head.append(RecoveryKeccak.keccak256(Data(RoutineAuthorizationBootstrap.beginPath.utf8)))
        head.append(RecoveryKeccak.keccak256(Data(RoutineAuthorizationBootstrap.completePath.utf8)))
        head.appendABIUnsigned(352)
        head.appendABIUnsigned(480)
        head.append(bootstrap.requestId)
        head.appendABIUnsigned(bootstrap.expiresAt)
        var tail = Data(); tail.appendABIDynamic(bootstrap.desktopPublicKey); tail.appendABIDynamic(iphonePublicKey)
        head.append(tail)
        return Data(SHA256.hash(data: head))
    }

    func aad(direction: RoutineAuthorizationDirection) -> Data {
        var value = Data(direction.label.utf8); value.append(0x7c); value.append(bootstrap.sessionId)
        value.append(0x7c); value.append(bootstrap.requestId); return value
    }
}

enum RoutineAuthorizationDirection { case request, response, terminal, terminalAck
    var label: String {
        switch self {
        case .request: return "DESKTOP_TO_IPHONE_ROUTINE_AUTHORIZATION_V1"
        case .response: return "IPHONE_TO_DESKTOP_ROUTINE_AUTHORIZATION_V1"
        case .terminal: return "IPHONE_TO_DESKTOP_ROUTINE_TERMINAL_V1"
        case .terminalAck: return "DESKTOP_TO_IPHONE_ROUTINE_TERMINAL_ACK_V1"
        }
    }
}

enum RoutineAuthorizationFrame {
    static let maximumPlaintextBytes = 65_503
    static let maximumBodyBytes = 65_536

    static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data, nonce: AES.GCM.Nonce = AES.GCM.Nonce()) throws -> Data {
        guard (1...maximumPlaintextBytes).contains(plaintext.count) else { throw RoutineAuthorizationFailure.transportFailure }
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        var frame = Data([1]); frame.append(contentsOf: sealed.nonce); frame.appendUInt32BE(UInt32(sealed.ciphertext.count))
        frame.append(sealed.ciphertext); frame.append(sealed.tag)
        guard frame.count <= maximumBodyBytes else { throw RoutineAuthorizationFailure.transportFailure }
        return frame
    }

    static func open(_ frame: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard frame.count >= 34, frame.count <= maximumBodyBytes, frame[0] == 1 else {
            throw RoutineAuthorizationFailure.transportFailure
        }
        let length = Int(frame.readUInt32BE(at: 13))
        guard (1...maximumPlaintextBytes).contains(length), frame.count == 33 + length else {
            throw RoutineAuthorizationFailure.transportFailure
        }
        do {
            let nonce = try AES.GCM.Nonce(data: frame.subdata(in: 1..<13))
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: frame.subdata(in: 17..<(17 + length)),
                tag: frame.suffix(16)
            )
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch { throw RoutineAuthorizationFailure.authenticationFailure }
    }
}

struct RoutineTransportExchange: Sendable {
    let statusCode: Int
    let contentType: String?
    let contentLength: Int?
    let cacheControl: String?
    let connection: String?
    let contentEncoding: String?
    let transferEncoding: String?
    let finalURL: String
    let body: Data
}

protocol RoutineAuthorizationTransporting: Sendable {
    func preflight(url: String, sessionId: String, expiresAt: UInt64) async throws
    func post(url: String, contentType: String, body: Data, expiresAt: UInt64) async throws -> RoutineTransportExchange
    func postBound(url: String, contentType: String, body: Data, expiresAt: UInt64, requestId: String) async throws -> RoutineTransportExchange
    func cancel()
}

// Test transports may implement post only; the production transport always
// implements request routing, with cryptographic request binding unchanged.
extension RoutineAuthorizationTransporting {
    func postBound(url: String, contentType: String, body: Data, expiresAt: UInt64, requestId: String) async throws -> RoutineTransportExchange {
        try await post(url:url, contentType:contentType, body:body, expiresAt:expiresAt)
    }
}

final class URLSessionRoutineAuthorizationTransport: RoutineAuthorizationTransporting, @unchecked Sendable {
    private let lock = NSLock()
    private var activeLoader: RoutineBoundedDataLoader?
    private let additionalProtocolClasses: [AnyClass]

    init(additionalProtocolClasses: [AnyClass] = []) { self.additionalProtocolClasses = additionalProtocolClasses }

    static func makeConfiguration(additionalProtocolClasses: [AnyClass] = []) -> URLSessionConfiguration {
        let c = URLSessionConfiguration.ephemeral
        c.waitsForConnectivity = true; c.httpShouldSetCookies = false; c.httpCookieAcceptPolicy = .never
        c.httpCookieStorage = nil; c.urlCache = nil; c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        c.connectionProxyDictionary = [:]; c.allowsCellularAccess = false; c.allowsExpensiveNetworkAccess = false
        c.allowsConstrainedNetworkAccess = false; c.httpMaximumConnectionsPerHost = 1; c.httpShouldUsePipelining = false
        c.timeoutIntervalForRequest = 10; c.timeoutIntervalForResource = 15
        if !additionalProtocolClasses.isEmpty { c.protocolClasses = additionalProtocolClasses + (c.protocolClasses ?? []) }
        return c
    }

    func preflight(url text:String,sessionId:String,expiresAt:UInt64) async throws {
        guard let url=URL(string:text),url.absoluteString==text,url.scheme=="http",url.host != nil,url.user==nil,url.password==nil,
              url.query==nil,url.fragment==nil,url.port != nil,
              sessionId.count==66,sessionId.hasPrefix("0x"),sessionId.dropFirst(2).allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw RoutineAuthorizationFailure.transportFailure
        }
        let now=Date().timeIntervalSince1970
        guard now<TimeInterval(expiresAt) else { throw RoutineAuthorizationFailure.expired }
        var request=URLRequest(url:url);request.httpMethod="HEAD";request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("no-store",forHTTPHeaderField:"Cache-Control");request.setValue("close",forHTTPHeaderField:"Connection")
        request.setValue(sessionId,forHTTPHeaderField:"X-PhilCore-Enrollment-Session")
        request.timeoutInterval=min(15,TimeInterval(expiresAt)-now)
        let loader=RoutineBoundedDataLoader(configuration:Self.makeConfiguration(additionalProtocolClasses:additionalProtocolClasses))
        lock.withLock { activeLoader=loader }
        defer { lock.withLock { if activeLoader===loader { activeLoader=nil } } }
        let (data,response)=try await loader.load(request)
        guard data.isEmpty,let http=response as? HTTPURLResponse,http.statusCode==204,
              http.value(forHTTPHeaderField:"Content-Type")==nil,http.value(forHTTPHeaderField:"Content-Length")=="0",
              http.value(forHTTPHeaderField:"Cache-Control")=="no-store",http.value(forHTTPHeaderField:"Connection")?.lowercased()=="close",
              http.value(forHTTPHeaderField:"Content-Encoding")==nil,http.value(forHTTPHeaderField:"Transfer-Encoding")==nil,
              http.url?.absoluteString==text else { throw RoutineAuthorizationFailure.desktopUnavailable }
    }

    func post(url text: String, contentType: String, body: Data, expiresAt: UInt64) async throws -> RoutineTransportExchange {
        try await send(url:text, contentType:contentType, body:body, expiresAt:expiresAt, requestId:nil)
    }
    func postBound(url text: String, contentType: String, body: Data, expiresAt: UInt64, requestId: String) async throws -> RoutineTransportExchange {
        guard requestId.range(of:"^0x[0-9a-f]{64}$",options:.regularExpression) != nil else { throw RoutineAuthorizationFailure.transportFailure }
        return try await send(url:text, contentType:contentType, body:body, expiresAt:expiresAt, requestId:requestId)
    }
    private func send(url text: String, contentType: String, body: Data, expiresAt: UInt64, requestId: String?) async throws -> RoutineTransportExchange {
        guard body.count <= RoutineAuthorizationFrame.maximumBodyBytes,
              let url = URL(string: text), url.absoluteString == text,
              url.scheme == "http", url.host != nil, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.port != nil,
              UInt64(Date().timeIntervalSince1970) < expiresAt else { throw RoutineAuthorizationFailure.transportFailure }
        var request = URLRequest(url: url)
        if let requestId { request.setValue(requestId, forHTTPHeaderField:"X-PhilCore-Routine-Request") }
        request.httpMethod = "POST"; request.httpBody = body; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("close", forHTTPHeaderField: "Connection")
        request.timeoutInterval = min(10, TimeInterval(expiresAt) - Date().timeIntervalSince1970)
        let loader = RoutineBoundedDataLoader(configuration: Self.makeConfiguration(additionalProtocolClasses: additionalProtocolClasses))
        lock.withLock { activeLoader = loader }
        defer { lock.withLock { if activeLoader === loader { activeLoader = nil } } }
        let (data, response) = try await loader.load(request)
        guard data.count <= RoutineAuthorizationFrame.maximumBodyBytes, let http = response as? HTTPURLResponse else {
            throw RoutineAuthorizationFailure.transportFailure
        }
        return RoutineTransportExchange(
            statusCode: http.statusCode, contentType: http.value(forHTTPHeaderField: "Content-Type"),
            contentLength: http.value(forHTTPHeaderField: "Content-Length").flatMap(Int.init),
            cacheControl: http.value(forHTTPHeaderField: "Cache-Control"),
            connection: http.value(forHTTPHeaderField: "Connection"),
            contentEncoding: http.value(forHTTPHeaderField: "Content-Encoding"),
            transferEncoding: http.value(forHTTPHeaderField: "Transfer-Encoding"),
            finalURL: http.url?.absoluteString ?? "", body: data
        )
    }

    func cancel() { lock.withLock { activeLoader?.cancel(); activeLoader = nil } }
}

private final class RoutineBoundedDataLoader: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let configuration: URLSessionConfiguration
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var continuation: CheckedContinuation<(Data, URLResponse), Error>?
    private var response: URLResponse?
    private var body = Data()
    private var finished = false

    init(configuration: URLSessionConfiguration) { self.configuration = configuration }

    func load(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                lock.withLock {
                    self.continuation = continuation
                    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
                    self.session = session
                    let task = session.dataTask(with: request); self.task = task; task.resume()
                }
            }
        }, onCancel: { self.cancel() })
    }

    func cancel() { finish(.failure(RoutineAuthorizationFailure.userCancelled)) }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.withLock { self.response = response }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let overflow = lock.withLock { () -> Bool in
            guard !finished else { return false }
            guard body.count + data.count <= RoutineAuthorizationFrame.maximumBodyBytes else { return true }
            body.append(data); return false
        }
        if overflow { finish(.failure(RoutineAuthorizationFailure.transportFailure)) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(Self.classify(error))); return }
        let value = lock.withLock { response.map { (body, $0) } }
        guard let value else { finish(.failure(RoutineAuthorizationFailure.transportFailure)); return }
        finish(.success(value))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil); finish(.failure(RoutineAuthorizationFailure.transportFailure))
    }

    private func finish(_ result: Result<(Data, URLResponse), Error>) {
        let captured = lock.withLock { () -> CheckedContinuation<(Data, URLResponse), Error>? in
            guard !finished else { return nil }; finished = true
            let value = continuation; continuation = nil; task?.cancel(); task = nil
            session?.invalidateAndCancel(); session = nil; return value
        }
        captured?.resume(with: result)
    }

    private static func classify(_ error: Error) -> RoutineAuthorizationFailure {
        let value=error as NSError
        guard value.domain==NSURLErrorDomain else { return .transportFailure }
        let code=value.code
        switch code {
        case NSURLErrorNotConnectedToInternet, NSURLErrorDataNotAllowed:
            return .localNetworkUnavailable
        case NSURLErrorTimedOut, NSURLErrorCannotFindHost, NSURLErrorCannotConnectToHost,
             NSURLErrorNetworkConnectionLost, NSURLErrorDNSLookupFailed:
            return .desktopUnavailable
        case NSURLErrorCancelled:
            return .userCancelled
        default:
            return .transportFailure
        }
    }
}

private extension Data {
    init?(base64URLEncoded text: String) {
        let base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - text.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
    var base64URLString: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    func readUInt16BE(at offset: Int) -> UInt16 { (UInt16(self[offset]) << 8) | UInt16(self[offset + 1]) }
    func readUInt32BE(at offset: Int) -> UInt32 { (0..<4).reduce(0) { ($0 << 8) | UInt32(self[offset + $1]) } }
    func readUInt64BE(at offset: Int) -> UInt64 { (0..<8).reduce(0) { ($0 << 8) | UInt64(self[offset + $1]) } }
    mutating func appendUInt16BE(_ value: UInt16) { append(UInt8(value >> 8)); append(UInt8(value & 0xff)) }
    mutating func appendUInt32BE(_ value: UInt32) { for shift in stride(from: 24, through: 0, by: -8) { append(UInt8((value >> UInt32(shift)) & 0xff)) } }
    mutating func appendUInt64BE(_ value: UInt64) { for shift in stride(from: 56, through: 0, by: -8) { append(UInt8((value >> UInt64(shift)) & 0xff)) } }
    mutating func appendABIUnsigned(_ value: UInt64) { append(Data(repeating: 0, count: 24)); appendUInt64BE(value) }
    mutating func appendABIDynamic(_ value: Data) { appendABIUnsigned(UInt64(value.count)); append(value); append(Data(repeating: 0, count: (32 - value.count % 32) % 32)) }
}

private extension Array where Element == String {
    func chunked(every size: Int) -> [String] {
        let joined = self.joined(); return stride(from: 0, to: joined.count, by: size).map { offset in
            let start = joined.index(joined.startIndex, offsetBy: offset)
            let end = joined.index(start, offsetBy: Swift.min(size, joined.count - offset)); return String(joined[start..<end])
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T { lock(); defer { unlock() }; return body() }
}
