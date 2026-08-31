import Foundation

/// Sanitized transport failure. The reason is always one of the fixed tokens
/// declared below so no server-controlled bytes, header text, or socket detail
/// can ever reach a caller, a log, or the UI.
struct RecoveryTransportError: Error, Equatable, CustomStringConvertible {
    let reason: String

    init(_ reason: String) {
        self.reason = reason
    }

    var description: String { reason }

    static let bodyTooLarge = RecoveryTransportError("recovery_transport_request_body_too_large")
    static let responseTooLarge = RecoveryTransportError("recovery_transport_response_too_large")
    static let endpointInvalid = RecoveryTransportError("recovery_transport_endpoint_invalid")
    static let notHTTP = RecoveryTransportError("recovery_transport_response_not_http")
    static let urlMismatch = RecoveryTransportError("recovery_transport_response_url_mismatch")
    static let redirectForbidden = RecoveryTransportError("recovery_transport_redirect_forbidden")
    static let statusNotOK = RecoveryTransportError("recovery_transport_status_not_ok")
    static let contentTypeInvalid = RecoveryTransportError("recovery_transport_content_type_invalid")
    static let unavailable = RecoveryTransportError("recovery_transport_unavailable")
    static let streamFailed = RecoveryTransportError("recovery_transport_stream_failed")
    static let cancelled = RecoveryTransportError("recovery_transport_cancelled")
    static let deadlineExceeded = RecoveryTransportError("recovery_transport_deadline_exceeded")
    static let deadlineInvalid = RecoveryTransportError("recovery_transport_deadline_invalid")
}

/// The only two routes this client will ever open, each with its own byte
/// ceilings in both directions. Nothing else is reachable.
enum RecoveryTransportRoute: String, Sendable, CaseIterable {
    case request
    case complete

    var path: String {
        switch self {
        case .request: return RecoveryBootstrap.requestEndpointPath
        case .complete: return RecoveryBootstrap.completionEndpointPath
        }
    }

    /// Largest body the phone is ever allowed to send on this route.
    var maxOutgoingBytes: Int {
        switch self {
        case .request: return 1024
        case .complete: return 16384
        }
    }

    /// Largest body the phone is ever allowed to read on this route. The stream
    /// is cancelled the moment this is exceeded, before any buffer is completed
    /// and long before anything is handed to a JSON parser.
    var maxIncomingBytes: Int {
        switch self {
        case .request: return 32768
        case .complete: return 16384
        }
    }
}

/// Absolute wall-clock deadline plus the derived budget the socket is allowed
/// to consume. The absolute value is always expressed against the injected
/// clock, never against `Date()`, so replaying fixed fixture timestamps stays
/// deterministic.
struct RecoveryTransportDeadline: Sendable, Equatable {
    /// Latest injected-clock instant at which a response is still acceptable.
    let expiresAtUnixMilliseconds: UInt64
    /// Monotonic budget handed to URLSession for this single attempt.
    let timeoutSeconds: Double

    /// `/request` aims for a short interactive budget.
    static let requestBudgetSeconds: Double = 10

    /// `/request`: roughly ten seconds, but never a millisecond beyond the
    /// PRB1 ticket expiry.
    static func forRequest(
        nowMilliseconds: UInt64,
        ticketExpiresAtUnixSeconds: UInt64
    ) throws -> RecoveryTransportDeadline {
        try make(
            nowMilliseconds: nowMilliseconds,
            ticketExpiresAtUnixSeconds: ticketExpiresAtUnixSeconds,
            budgetSeconds: requestBudgetSeconds
        )
    }

    /// `/complete`: whatever is left of the ticket lifetime, single attempt,
    /// no retry budget on top.
    static func forCompletion(
        nowMilliseconds: UInt64,
        ticketExpiresAtUnixSeconds: UInt64
    ) throws -> RecoveryTransportDeadline {
        try make(
            nowMilliseconds: nowMilliseconds,
            ticketExpiresAtUnixSeconds: ticketExpiresAtUnixSeconds,
            budgetSeconds: nil
        )
    }

    private static func make(
        nowMilliseconds: UInt64,
        ticketExpiresAtUnixSeconds: UInt64,
        budgetSeconds: Double?
    ) throws -> RecoveryTransportDeadline {
        guard ticketExpiresAtUnixSeconds <= UInt64.max / 1000 else {
            throw RecoveryTransportError.deadlineInvalid
        }
        let ticketExpiryMilliseconds = ticketExpiresAtUnixSeconds * 1000
        guard ticketExpiryMilliseconds > nowMilliseconds else {
            throw RecoveryTransportError.deadlineExceeded
        }
        let remainingSeconds = Double(ticketExpiryMilliseconds - nowMilliseconds) / 1000
        let seconds = min(remainingSeconds, budgetSeconds ?? remainingSeconds)
        guard seconds > 0 else { throw RecoveryTransportError.deadlineExceeded }
        return RecoveryTransportDeadline(
            expiresAtUnixMilliseconds: nowMilliseconds + UInt64((seconds * 1000).rounded(.down)),
            timeoutSeconds: seconds
        )
    }
}

/// One POST. The method, content type, and route are fixed by construction so a
/// caller cannot widen them.
struct RecoveryTransportRequest: Sendable, Equatable {
    static let method = "POST"
    static let contentType = "application/json; charset=utf-8"

    /// Absolute endpoint text derived from the validated PRB1 ticket only.
    let endpoint: String
    let route: RecoveryTransportRoute
    let body: Data
    let deadline: RecoveryTransportDeadline

    var method: String { Self.method }
    var contentType: String { Self.contentType }
}

/// The complete allowlist of what the transport is permitted to hand back.
/// Headers other than content type, cookies, metrics, and the task itself are
/// dropped at this boundary.
struct RecoveryTransportResponse: Sendable, Equatable {
    let statusCode: Int
    let contentType: String?
    let body: Data
    let finalEndpoint: String
}

protocol RecoveryTransporting: Sendable {
    func send(_ request: RecoveryTransportRequest) async throws -> RecoveryTransportResponse
}

/// Strict endpoint policy. Only a literal RFC1918 IPv4 authority with an
/// explicit port and one of the two exact route paths is reachable. No
/// hostname, no DNS name, no IPv6 literal, no userinfo, no query, no fragment,
/// no default port, no path traversal.
enum RecoveryEndpointPolicy {
    static let scheme = "http://"
    static let maxEndpointLength = 256

    @discardableResult
    static func validate(_ endpoint: String, route: RecoveryTransportRoute) throws -> URL {
        guard !endpoint.isEmpty, endpoint.utf8.count <= maxEndpointLength else {
            throw RecoveryTransportError.endpointInvalid
        }
        guard endpoint.allSatisfy({ $0.isASCII }) else {
            throw RecoveryTransportError.endpointInvalid
        }
        for scalar in endpoint.unicodeScalars where scalar.value <= 0x20 || scalar.value == 0x7f {
            throw RecoveryTransportError.endpointInvalid
        }
        guard !endpoint.contains("?"), !endpoint.contains("#"), !endpoint.contains("@") else {
            throw RecoveryTransportError.endpointInvalid
        }
        guard !endpoint.contains(".."), !endpoint.contains("//philcore") else {
            throw RecoveryTransportError.endpointInvalid
        }
        guard endpoint.hasPrefix(scheme) else { throw RecoveryTransportError.endpointInvalid }
        let remainder = endpoint.dropFirst(scheme.count)
        guard let separator = remainder.firstIndex(of: "/") else {
            throw RecoveryTransportError.endpointInvalid
        }
        let authority = remainder[remainder.startIndex..<separator]
        let path = String(remainder[separator...])
        guard path == route.path else { throw RecoveryTransportError.endpointInvalid }
        guard !authority.contains("["), !authority.contains("]") else {
            throw RecoveryTransportError.endpointInvalid
        }
        let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { throw RecoveryTransportError.endpointInvalid }
        guard (try? RecoveryBootstrap.parseIPv4(text: String(parts[0]))) != nil else {
            throw RecoveryTransportError.endpointInvalid
        }
        guard let portText = try? RecoveryCodec.requireCanonicalIntegerString(
            String(parts[1]),
            "port"
        ), let port = Int(portText), port >= 1024, port <= 65535 else {
            throw RecoveryTransportError.endpointInvalid
        }
        guard let url = URL(string: endpoint), url.absoluteString == endpoint else {
            throw RecoveryTransportError.endpointInvalid
        }
        return url
    }
}

/// Bounded accumulator. Every append is checked before the byte lands, so the
/// ceiling can never be crossed even transiently.
struct RecoveryByteAccumulator {
    let limit: Int
    private(set) var bytes: Data

    init(limit: Int) {
        self.limit = limit
        self.bytes = Data()
        bytes.reserveCapacity(min(limit, 4096))
    }

    var count: Int { bytes.count }

    mutating func append(_ byte: UInt8) throws {
        guard bytes.count + 1 <= limit else { throw RecoveryTransportError.responseTooLarge }
        bytes.append(byte)
    }

    mutating func append(contentsOf chunk: Data) throws {
        guard bytes.count + chunk.count <= limit else {
            throw RecoveryTransportError.responseTooLarge
        }
        bytes.append(chunk)
    }
}

/// Production transport.
///
/// The session is ephemeral and reusable: cancelling one attempt cancels only
/// the captured `URLSessionTask` and never invalidates the session, so the same
/// instance stays usable for the next attempt.
final class URLSessionRecoveryTransport: RecoveryTransporting, @unchecked Sendable {
    /// Locked-down configuration. Kept static so the policy itself is testable
    /// without opening a socket.
    static func makeConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = false
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.connectionProxyDictionary = [:]
        configuration.allowsCellularAccess = false
        configuration.allowsExpensiveNetworkAccess = false
        configuration.allowsConstrainedNetworkAccess = false
        configuration.httpMaximumConnectionsPerHost = 1
        configuration.httpShouldUsePipelining = false
        configuration.shouldUseExtendedBackgroundIdleMode = false
        configuration.networkServiceType = .responsiveData
        return configuration
    }

    /// Always refuses to follow a redirect. The 3xx response is surfaced to the
    /// status gate instead, which rejects it.
    final class RedirectBlockingDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    /// Holds exactly the task belonging to the current attempt. A cancel that
    /// arrives before the task exists is remembered and applied on capture.
    private final class TaskBox: @unchecked Sendable {
        private let lock = NSLock()
        private var task: URLSessionTask?
        private var cancelRequested = false

        func capture(_ value: URLSessionTask) {
            lock.lock()
            let shouldCancel = cancelRequested
            task = value
            lock.unlock()
            if shouldCancel { value.cancel() }
        }

        func cancelCaptured() {
            lock.lock()
            cancelRequested = true
            let captured = task
            lock.unlock()
            captured?.cancel()
        }

        func release() {
            lock.lock()
            task = nil
            lock.unlock()
        }
    }

    private let session: URLSession

    /// `additionalProtocolClasses` exists so the unit suite can drive the real
    /// URLSession code path through an injected `URLProtocol` and never open a
    /// socket. Production callers use the no-argument initializer.
    init(additionalProtocolClasses: [AnyClass] = []) {
        let configuration = Self.makeConfiguration()
        if !additionalProtocolClasses.isEmpty {
            configuration.protocolClasses =
                additionalProtocolClasses + (configuration.protocolClasses ?? [])
        }
        session = URLSession(configuration: configuration)
    }

    func send(_ request: RecoveryTransportRequest) async throws -> RecoveryTransportResponse {
        guard request.body.count <= request.route.maxOutgoingBytes else {
            throw RecoveryTransportError.bodyTooLarge
        }
        guard request.deadline.timeoutSeconds > 0 else {
            throw RecoveryTransportError.deadlineExceeded
        }
        let url = try RecoveryEndpointPolicy.validate(request.endpoint, route: request.route)

        var urlRequest = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
            timeoutInterval: request.deadline.timeoutSeconds
        )
        urlRequest.httpMethod = RecoveryTransportRequest.method
        urlRequest.setValue(
            RecoveryTransportRequest.contentType,
            forHTTPHeaderField: "Content-Type"
        )
        urlRequest.setValue(String(request.body.count), forHTTPHeaderField: "Content-Length")
        urlRequest.httpBody = request.body
        urlRequest.httpShouldHandleCookies = false
        urlRequest.allowsCellularAccess = false
        urlRequest.allowsExpensiveNetworkAccess = false
        urlRequest.allowsConstrainedNetworkAccess = false
        urlRequest.assumesHTTP3Capable = false

        let box = TaskBox()
        return try await withTaskCancellationHandler {
            try await perform(urlRequest, request: request, box: box)
        } onCancel: {
            box.cancelCaptured()
        }
    }

    private func perform(
        _ urlRequest: URLRequest,
        request: RecoveryTransportRequest,
        box: TaskBox
    ) async throws -> RecoveryTransportResponse {
        let started = ContinuousClock.now
        let delegate = RedirectBlockingDelegate()
        let stream: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (stream, response) = try await session.bytes(for: urlRequest, delegate: delegate)
        } catch is CancellationError {
            throw RecoveryTransportError.cancelled
        } catch let error as URLError where error.code == .cancelled {
            throw RecoveryTransportError.cancelled
        } catch let error as URLError where error.code == .timedOut {
            throw RecoveryTransportError.deadlineExceeded
        } catch {
            throw RecoveryTransportError.unavailable
        }
        box.capture(stream.task)
        defer { box.release() }

        guard let http = response as? HTTPURLResponse else {
            stream.task.cancel()
            throw RecoveryTransportError.notHTTP
        }
        guard let finalURL = http.url,
              finalURL.absoluteString == request.endpoint,
              finalURL == urlRequest.url else {
            stream.task.cancel()
            throw RecoveryTransportError.urlMismatch
        }
        if (300...399).contains(http.statusCode) {
            stream.task.cancel()
            throw RecoveryTransportError.redirectForbidden
        }
        guard http.statusCode == 200 else {
            stream.task.cancel()
            throw RecoveryTransportError.statusNotOK
        }
        let contentType = http.value(forHTTPHeaderField: "Content-Type")
        guard contentType == RecoveryTransportRequest.contentType else {
            stream.task.cancel()
            throw RecoveryTransportError.contentTypeInvalid
        }
        if http.expectedContentLength > Int64(request.route.maxIncomingBytes) {
            stream.task.cancel()
            throw RecoveryTransportError.responseTooLarge
        }

        var accumulator = RecoveryByteAccumulator(limit: request.route.maxIncomingBytes)
        do {
            for try await byte in stream {
                try accumulator.append(byte)
            }
        } catch let error as RecoveryTransportError {
            stream.task.cancel()
            throw error
        } catch is CancellationError {
            stream.task.cancel()
            throw RecoveryTransportError.cancelled
        } catch let error as URLError where error.code == .cancelled {
            throw RecoveryTransportError.cancelled
        } catch let error as URLError where error.code == .timedOut {
            throw RecoveryTransportError.deadlineExceeded
        } catch {
            stream.task.cancel()
            throw RecoveryTransportError.streamFailed
        }

        // Monotonic budget check: a body that only finished arriving after the
        // attempt budget elapsed is discarded rather than accepted late.
        guard started.duration(to: .now) <= .seconds(request.deadline.timeoutSeconds) else {
            throw RecoveryTransportError.deadlineExceeded
        }

        return RecoveryTransportResponse(
            statusCode: http.statusCode,
            contentType: contentType,
            body: accumulator.bytes,
            finalEndpoint: finalURL.absoluteString
        )
    }
}
