import CryptoKit
import Foundation

/// Observable lifecycle of a single native recovery approval session.
enum RecoveryClientState: String, Sendable, Equatable, CaseIterable {
    case idle
    case bootstrapValidated
    case fetchingRequest
    case requestValidated
    case awaitingApproval
    case submittingApproval
    case awaitingAcknowledgement
    case accepted
    case rejected
    case cancelled
    case failed

    /// Terminal states never transition again except through `reset()` or a
    /// brand new `startSession(...)`.
    var isTerminal: Bool {
        switch self {
        case .accepted, .rejected, .cancelled, .failed: return true
        default: return false
        }
    }
}

/// Sanitized client failure. `reason` is always a fixed token from this file or
/// from the Package 3A / transport token sets, so nothing derived from
/// attacker-controlled bytes is ever surfaced.
struct RecoveryClientError: Error, Equatable, CustomStringConvertible {
    enum Kind: String, Sendable, Equatable {
        case invalidState
        case sessionReplaced
        case cancelled
        case expired
        case transport
        case protocolViolation
        case signer
        case rejected
    }

    let kind: Kind
    let reason: String

    var description: String { "\(kind.rawValue):\(reason)" }

    static func invalidState(_ reason: String) -> RecoveryClientError {
        RecoveryClientError(kind: .invalidState, reason: reason)
    }

    static func protocolViolation(_ reason: String) -> RecoveryClientError {
        RecoveryClientError(kind: .protocolViolation, reason: reason)
    }

    static func transport(_ reason: String) -> RecoveryClientError {
        RecoveryClientError(kind: .transport, reason: reason)
    }

    static func signer(_ reason: String) -> RecoveryClientError {
        RecoveryClientError(kind: .signer, reason: reason)
    }

    static let sessionReplaced = RecoveryClientError(
        kind: .sessionReplaced,
        reason: "recovery_client_session_replaced"
    )
    static let cancelled = RecoveryClientError(
        kind: .cancelled,
        reason: "recovery_client_cancelled"
    )
    static let expired = RecoveryClientError(
        kind: .expired,
        reason: "recovery_client_session_expired"
    )
    static let rejectedByDesktop = RecoveryClientError(
        kind: .rejected,
        reason: "recovery_client_rejected_by_desktop"
    )
}

/// Everything the UI is allowed to render. Contains no key material, no
/// decrypted request bytes, no ciphertext, and no signature. Account, chain,
/// and epoch come only from the already validated request context — never from
/// unvalidated prose or raw request bytes. `completionEndpoint` remains a
/// technical/internal field and must not appear in the ordinary approval card.
struct RecoveryPresentation: Sendable, Equatable {
    let sessionId: String
    let expiresAtUnixSeconds: UInt64
    let actionText: String
    let networkText: String
    let comparisonFingerprint: String
    let factorBitmap: String
    let completionEndpoint: String
    let accountAddress: String
    let chainId: String
    let recoveryEpoch: String
}

/// Immutable allowlisted snapshot.
struct RecoveryClientStatus: Sendable, Equatable {
    let state: RecoveryClientState
    let generation: UInt64
    let sessionId: String?
    let expiresAtUnixSeconds: UInt64?
    let presentation: RecoveryPresentation?
    let acknowledgedStatus: String?
    let failureReason: String?
}

/// The signing boundary. The actor hands over exactly the recomputed
/// `recoveryFactorDigest` and receives a DER ECDSA P-256 signature. No wire
/// bytes, no transcript, and no session state cross this line.
protocol RecoverySigner: Sendable {
    func signRecoveryDigest(_ digest: Data) async throws -> Data
}

/// Wire codec for the `/complete` leg. `/request` reuses the Package 3A codec
/// verbatim; only the approval and acknowledgement shapes live here.
enum RecoveryApprovalCodec {
    static let protocolVersion = 1
    static let hkdfInfo = "PHILCORE_NATIVE_RECOVERY_APPROVAL_AES256_GCM_V1"
    static let aadPhoneToDesktop = "IPHONE_TO_DESKTOP_RECOVERY_APPROVAL_V1"
    static let aadDesktopToPhone = "DESKTOP_TO_IPHONE_RECOVERY_APPROVAL_V1"
    static let maxWrapperBytes = 16384
    static let acknowledgementStatuses: Set<String> = ["ACCEPTED", "REJECTED"]

    struct Acknowledgement: Equatable {
        let version: Int
        let sessionId: String
        let nonce: String
        let ciphertext: String
        let tag: String
    }

    struct AcknowledgementPlaintext: Equatable {
        let protocolVersion: Int
        let sessionId: String
        let transcriptHash: String
        let status: String
    }

    static func hex32(_ data: Data) -> String {
        "0x" + RecoveryCodec.hexString(data)
    }

    /// HKDF-SHA256 with the transcript hash as salt. Deliberately a different
    /// salt and info pair from the request key so the two can never collide.
    static func deriveApprovalAesKey(sharedSecret: Data, transcriptHash: Data) throws -> Data {
        guard sharedSecret.count == 32 else {
            throw RecoveryCodecError("recovery_approval_shared_secret_length_invalid")
        }
        guard transcriptHash.count == 32 else {
            throw RecoveryCodecError("recovery_approval_transcript_hash_length_invalid")
        }
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: transcriptHash,
            info: Data(hkdfInfo.utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    static func buildAad(direction: String, sessionId: String) throws -> Data {
        let normalized = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        return Data("\(direction)|\(normalized)".utf8)
    }

    // MARK: - Outgoing approval

    /// Exactly seven fields. `credentialGeneration` is emitted as a JSON number
    /// while every other scalar stays a string, matching the desktop reference
    /// plaintext byte for byte.
    static func serializeApprovalPlaintext(
        sessionId: String,
        transcriptHash: Data,
        role1FactorCommitment: Data,
        credentialIdentifierCommitment: String,
        credentialGeneration: String,
        derSignatureBase64URL: String
    ) throws -> Data {
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        let normalizedCommitment = try RecoveryCodec.requireBytes32(
            credentialIdentifierCommitment,
            "credentialIdentifierCommitment"
        )
        let generation = try RecoveryCodec.requireCanonicalIntegerString(
            credentialGeneration,
            "credentialGeneration"
        )
        guard transcriptHash.count == 32 else {
            throw RecoveryCodecError("recovery_approval_transcript_hash_length_invalid")
        }
        guard role1FactorCommitment.count == 32 else {
            throw RecoveryCodecError("recovery_approval_role1_commitment_length_invalid")
        }
        let members: [(String, String)] = [
            ("protocolVersion", String(protocolVersion)),
            ("sessionId", RecoveryCodec.jsonStringLiteral(normalizedSession)),
            ("transcriptHash", RecoveryCodec.jsonStringLiteral(hex32(transcriptHash))),
            (
                "role1FactorCommitment",
                RecoveryCodec.jsonStringLiteral(hex32(role1FactorCommitment))
            ),
            (
                "credentialIdentifierCommitment",
                RecoveryCodec.jsonStringLiteral(normalizedCommitment)
            ),
            ("credentialGeneration", generation),
            (
                "derRecoverySignature",
                RecoveryCodec.jsonStringLiteral(derSignatureBase64URL)
            )
        ]
        let text = "{" + members.map {
            "\(RecoveryCodec.jsonStringLiteral($0.0)):\($0.1)"
        }.joined(separator: ",") + "}"
        return Data(text.utf8)
    }

    /// The `/complete` request wrapper. Uses `version`, not `protocolVersion`,
    /// and always carries the phone ephemeral public key.
    static func serializeApprovalWrapper(
        sessionId: String,
        phoneEphemeralPublicKey: String,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) throws -> Data {
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        try RecoveryBootstrap.validateUncompressedP256PublicKey(
            phoneEphemeralPublicKey,
            label: "phone_ephemeral"
        )
        guard nonce.count == 12 else {
            throw RecoveryCodecError("recovery_approval_nonce_length_invalid")
        }
        guard tag.count == 16 else {
            throw RecoveryCodecError("recovery_approval_tag_length_invalid")
        }
        let members: [(String, String)] = [
            ("version", String(protocolVersion)),
            ("sessionId", RecoveryCodec.jsonStringLiteral(normalizedSession)),
            (
                "phoneEphemeralPublicKey",
                RecoveryCodec.jsonStringLiteral(phoneEphemeralPublicKey)
            ),
            ("nonce", RecoveryCodec.jsonStringLiteral(RecoveryCodec.encodeBase64URL(nonce))),
            (
                "ciphertext",
                RecoveryCodec.jsonStringLiteral(RecoveryCodec.encodeBase64URL(ciphertext))
            ),
            ("tag", RecoveryCodec.jsonStringLiteral(RecoveryCodec.encodeBase64URL(tag)))
        ]
        let text = "{" + members.map {
            "\(RecoveryCodec.jsonStringLiteral($0.0)):\($0.1)"
        }.joined(separator: ",") + "}"
        return Data(text.utf8)
    }

    // MARK: - Incoming acknowledgement

    /// Wrapper uses `version`. `phoneEphemeralPublicKey` must be absent or
    /// explicitly null; the desktop emits null.
    static func validateAcknowledgementWrapper(jsonBytes: Data) throws -> Acknowledgement {
        guard !jsonBytes.isEmpty, jsonBytes.count <= maxWrapperBytes else {
            throw RecoveryCodecError("recovery_acknowledgement_length_invalid")
        }
        let parsed = try RecoveryJSON.parse(jsonBytes)
        guard let message = parsed.objectValue else {
            throw RecoveryCodecError("recovery_acknowledgement_schema_invalid")
        }
        let allowed: Set<String> = [
            "version", "sessionId", "phoneEphemeralPublicKey", "nonce", "ciphertext", "tag"
        ]
        for key in message.keys where !allowed.contains(key) {
            throw RecoveryCodecError("recovery_acknowledgement_unexpected_field")
        }
        for key in ["version", "sessionId", "nonce", "ciphertext", "tag"]
        where message[key] == nil {
            throw RecoveryCodecError("recovery_acknowledgement_missing_field_\(key)")
        }
        if let phoneKey = message["phoneEphemeralPublicKey"], phoneKey != .null {
            throw RecoveryCodecError("recovery_acknowledgement_ephemeral_key_invalid")
        }
        guard message["version"]?.numberLiteral == String(protocolVersion) else {
            throw RecoveryCodecError("recovery_acknowledgement_version_invalid")
        }
        let sessionId = try RecoveryCodec.requireBytes32(message["sessionId"], "sessionId")
        let nonce = try RecoveryCodec.requireSafeString(message["nonce"], "nonce", maxLength: 32)
        _ = try RecoveryCodec.decodeBase64URLCanonical(nonce, exactLength: 12)
        let ciphertext = try RecoveryCodec.requireSafeString(
            message["ciphertext"],
            "ciphertext",
            maxLength: 8192
        )
        _ = try RecoveryCodec.decodeBase64URLCanonical(ciphertext, exactLength: nil)
        let tag = try RecoveryCodec.requireSafeString(message["tag"], "tag", maxLength: 64)
        _ = try RecoveryCodec.decodeBase64URLCanonical(tag, exactLength: 16)
        return Acknowledgement(
            version: protocolVersion,
            sessionId: sessionId,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }

    static func decryptAcknowledgement(
        message: Acknowledgement,
        key: Data,
        sessionId: String
    ) throws -> Data {
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        guard message.sessionId == normalizedSession else {
            throw RecoveryCodecError("recovery_acknowledgement_session_mismatch")
        }
        guard key.count == 32 else {
            throw RecoveryCodecError("recovery_approval_aes_key_invalid")
        }
        let aad = try buildAad(direction: aadDesktopToPhone, sessionId: normalizedSession)
        let nonce = try RecoveryCodec.decodeBase64URLCanonical(message.nonce, exactLength: 12)
        let ciphertext = try RecoveryCodec.decodeBase64URLCanonical(
            message.ciphertext,
            exactLength: nil
        )
        let tag = try RecoveryCodec.decodeBase64URLCanonical(message.tag, exactLength: 16)
        do {
            let sealed = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            return try AES.GCM.open(sealed, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw RecoveryCodecError("recovery_acknowledgement_authentication_failed")
        }
    }

    /// Exactly four fields, and only two statuses are recognised.
    static func validateAcknowledgementPlaintext(
        jsonBytes: Data
    ) throws -> AcknowledgementPlaintext {
        let parsed = try RecoveryJSON.parse(jsonBytes)
        guard let message = parsed.objectValue else {
            throw RecoveryCodecError("recovery_acknowledgement_plaintext_schema_invalid")
        }
        let allowed = ["protocolVersion", "sessionId", "status", "transcriptHash"]
        let allowedSet = Set(allowed)
        for key in message.keys where !allowedSet.contains(key) {
            throw RecoveryCodecError("recovery_acknowledgement_plaintext_unexpected_field")
        }
        for key in allowed where message[key] == nil {
            throw RecoveryCodecError("recovery_acknowledgement_plaintext_missing_field_\(key)")
        }
        guard message["protocolVersion"]?.numberLiteral == String(protocolVersion) else {
            throw RecoveryCodecError("recovery_acknowledgement_plaintext_version_invalid")
        }
        let status = try RecoveryCodec.requireSafeString(
            message["status"],
            "status",
            maxLength: 16
        )
        guard acknowledgementStatuses.contains(status) else {
            throw RecoveryCodecError("recovery_acknowledgement_status_unsupported")
        }
        return AcknowledgementPlaintext(
            protocolVersion: protocolVersion,
            sessionId: try RecoveryCodec.requireBytes32(message["sessionId"], "sessionId"),
            transcriptHash: try RecoveryCodec.requireBytes32(
                message["transcriptHash"],
                "transcriptHash"
            ),
            status: status
        )
    }

    // MARK: - DER re-encoding

    /// Re-encodes a normalised low-S (r, s) pair as minimal DER.
    static func encodeDerSignature(r: Data, s: Data) throws -> Data {
        guard r.count == 32, s.count == 32 else {
            throw RecoveryCodecError("p256_signature_invalid")
        }
        let body = try derInteger(r) + derInteger(s)
        guard body.count <= 127 else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_malformed")
        }
        return Data([0x30, UInt8(body.count)]) + body
    }

    private static func derInteger(_ value: Data) throws -> Data {
        var trimmed = Array(value.drop(while: { $0 == 0x00 }))
        guard !trimmed.isEmpty else {
            throw RecoveryCodecError("invalid_DER_ECDSA_signature_zero")
        }
        if trimmed[0] & 0x80 != 0 { trimmed.insert(0x00, at: 0) }
        return Data([0x02, UInt8(trimmed.count)] + trimmed)
    }
}

/// Native iPhone recovery approval client.
///
/// All mutable state is owned by an actor-private `Session` object. Every
/// suspension point captures the session reference and its generation before
/// awaiting and revalidates identity, generation, terminality, and expiry after
/// resuming, so a late result from a replaced or cancelled session can never
/// mutate the live one.
actor RecoveryClient {
    /// Actor-private session. Never escapes the actor and is never surfaced in
    /// any snapshot.
    private final class Session {
        let generation: UInt64
        let ticket: RecoveryBootstrap.Ticket
        let sessionId: String
        let requestEndpoint: String
        let completionEndpoint: String

        /// Injected clock anchor. Elapsed time is measured monotonically from
        /// this anchor so expiry rechecks never depend on `Date()`.
        var anchorMilliseconds: UInt64
        var anchorInstant: ContinuousClock.Instant

        var ephemeralPrivateKey: P256.KeyAgreement.PrivateKey?
        var phoneEphemeralPublicKey: String?
        var fetchChallenge: Data?
        var sharedSecret: Data?
        var requestKey: Data?
        var approvalKey: Data?
        var validated: RecoveryApprovalValidation?
        var presentation: RecoveryPresentation?
        var acknowledgedStatus: String?

        var nonceHistory: Set<Data> = []
        var transportTask: Task<RecoveryTransportResponse, Error>?

        var isTerminal = false
        var fetchInFlight = false
        var approvalInFlight = false
        var signerInvoked = false

        init(
            generation: UInt64,
            ticket: RecoveryBootstrap.Ticket,
            sessionId: String,
            requestEndpoint: String,
            completionEndpoint: String,
            anchorMilliseconds: UInt64
        ) {
            self.generation = generation
            self.ticket = ticket
            self.sessionId = sessionId
            self.requestEndpoint = requestEndpoint
            self.completionEndpoint = completionEndpoint
            self.anchorMilliseconds = anchorMilliseconds
            self.anchorInstant = ContinuousClock.now
        }

        /// Injected anchor advanced by monotonic elapsed time.
        var nowMilliseconds: UInt64 {
            let elapsed = anchorInstant.duration(to: .now)
            let seconds = Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
            guard seconds > 0 else { return anchorMilliseconds }
            return anchorMilliseconds &+ UInt64(seconds * 1000)
        }

        var expiresAtMilliseconds: UInt64 { ticket.expiresAt * 1000 }

        func reanchor(_ milliseconds: UInt64) {
            anchorMilliseconds = milliseconds
            anchorInstant = ContinuousClock.now
        }

        /// Best-effort scrub of mutable secret buffers plus release of the
        /// CryptoKit key handles. Swift cannot guarantee that no copy of a
        /// `Data` value ever existed elsewhere, so this is explicitly
        /// best-effort and is not claimed as guaranteed zeroization.
        func releaseSecrets() {
            Session.scrub(&sharedSecret)
            Session.scrub(&requestKey)
            Session.scrub(&approvalKey)
            Session.scrub(&fetchChallenge)
            ephemeralPrivateKey = nil
            validated = nil
            nonceHistory.removeAll()
            // Presentation is not secret material; clearing it is a lifecycle
            // correctness requirement so terminal status never retains UI state.
            presentation = nil
        }

        private static func scrub(_ value: inout Data?) {
            guard var buffer = value else { return }
            if !buffer.isEmpty {
                buffer.resetBytes(in: 0..<buffer.count)
            }
            value = nil
        }
    }

    private let transport: RecoveryTransporting
    private let signer: RecoverySigner

    private var session: Session?
    private var state: RecoveryClientState = .idle
    private var generationCounter: UInt64 = 0
    private var failureReason: String?

    init(transport: RecoveryTransporting, signer: RecoverySigner) {
        self.transport = transport
        self.signer = signer
    }

    // MARK: - Snapshot

    func status() -> RecoveryClientStatus {
        RecoveryClientStatus(
            state: state,
            generation: session?.generation ?? generationCounter,
            sessionId: session?.sessionId,
            expiresAtUnixSeconds: session?.ticket.expiresAt,
            presentation: session?.presentation,
            acknowledgedStatus: session?.acknowledgedStatus,
            failureReason: failureReason
        )
    }

    // MARK: - Bootstrap

    /// Parses and validates a PRB1 URI with Package 3A and replaces any prior
    /// session synchronously. A new session is always allowed, whether the
    /// previous one was active or terminal.
    func startSession(uri: String, nowSeconds: UInt64) throws {
        let ticketBytes: Data
        let ticket: RecoveryBootstrap.Ticket
        do {
            ticketBytes = try RecoveryBootstrap.parseURI(uri)
            ticket = try RecoveryBootstrap.decodeTicket(ticketBytes)
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: ticket,
                nowSeconds: nowSeconds,
                boundRequestExpiresAtMilliseconds: nil
            )
        } catch let error as RecoveryCodecError {
            // The prior session is intentionally left untouched: an invalid
            // scan must never corrupt a healthy session.
            throw RecoveryClientError.protocolViolation(error.reason)
        }

        let requestEndpoint: String
        let completionEndpoint: String
        do {
            requestEndpoint = try RecoveryBootstrap.requestEndpoint(ticket: ticket)
            completionEndpoint = try RecoveryBootstrap.completionEndpoint(ticket: ticket)
            try RecoveryEndpointPolicy.validate(requestEndpoint, route: .request)
            try RecoveryEndpointPolicy.validate(completionEndpoint, route: .complete)
        } catch let error as RecoveryCodecError {
            throw RecoveryClientError.protocolViolation(error.reason)
        } catch let error as RecoveryTransportError {
            throw RecoveryClientError.protocolViolation(error.reason)
        }

        retireCurrentSession()
        generationCounter &+= 1
        let replacement = Session(
            generation: generationCounter,
            ticket: ticket,
            sessionId: "0x" + RecoveryCodec.hexString(ticket.sessionId),
            requestEndpoint: requestEndpoint,
            completionEndpoint: completionEndpoint,
            anchorMilliseconds: nowSeconds * 1000
        )
        session = replacement
        state = .bootstrapValidated
        failureReason = nil
    }

    // MARK: - Request fetch

    /// Fetches, decrypts, and fully validates the canonical recovery request.
    ///
    /// Ordered contract:
    ///  1. require a live, non-terminal, bootstrap-validated session
    ///  2. reject a concurrent fetch on the same session
    ///  3. reanchor the injected clock and recheck ticket expiry
    ///  4. generate a fresh ephemeral P-256 key agreement key
    ///  5. publish the phone public key as canonical base64url of the 65-byte
    ///     uncompressed point
    ///  6. draw a 32-byte fetch challenge from `SystemRandomNumberGenerator`
    ///  7. build and canonically serialize the fetch-init with Package 3A
    ///  8. enforce the 1024-byte outgoing ceiling for `/request`
    ///  9. derive a deadline that is ~10s but never beyond ticket expiry
    /// 10. enter `fetchingRequest` and own the transport task
    /// 11. POST once to the ticket-derived `/request` endpoint
    /// 12. revalidate session identity, generation, terminality, and expiry
    /// 13. enforce the 32768-byte incoming ceiling and response allowlist
    /// 14. validate the encrypted delivery wrapper (`protocolVersion`)
    /// 15. bind the wrapper session id to the ticket and reject nonce reuse
    /// 16. ECDH against the desktop key carried by the QR ticket only
    /// 17. derive the request AES key with salt = requestHash
    /// 18. decrypt under the Package 3A AAD, then hash the raw plaintext bytes
    ///     and compare to the ticket request hash before any JSON is parsed
    /// 19. run full consumer-V3 validation, bind session/endpoint/desktop key,
    ///     build the transcript, and enter `requestValidated`
    func fetchRequest(nowMilliseconds: UInt64) async throws {
        guard let captured = session else {
            throw RecoveryClientError.invalidState("recovery_client_no_session")
        }
        guard !captured.isTerminal else {
            throw RecoveryClientError.invalidState("recovery_client_session_terminal")
        }
        guard state == .bootstrapValidated else {
            throw RecoveryClientError.invalidState("recovery_client_fetch_state_invalid")
        }
        guard !captured.fetchInFlight else {
            throw RecoveryClientError.invalidState("recovery_client_fetch_already_in_flight")
        }
        let capturedGeneration = captured.generation
        captured.reanchor(nowMilliseconds)
        guard nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }

        let privateKey = P256.KeyAgreement.PrivateKey()
        let phonePublicKey = RecoveryCodec.encodeBase64URL(
            privateKey.publicKey.x963Representation
        )
        let challenge = Self.randomBytes(32)

        let body: Data
        let deadline: RecoveryTransportDeadline
        do {
            let fetchInit = try RecoveryBootstrap.buildFetchInit(
                sessionId: captured.sessionId,
                phoneEphemeralPublicKey: phonePublicKey,
                fetchChallenge: challenge
            )
            body = try RecoveryBootstrap.serializeFetchInit(fetchInit)
            guard body.count <= RecoveryTransportRoute.request.maxOutgoingBytes else {
                throw RecoveryTransportError.bodyTooLarge
            }
            deadline = try RecoveryTransportDeadline.forRequest(
                nowMilliseconds: nowMilliseconds,
                ticketExpiresAtUnixSeconds: captured.ticket.expiresAt
            )
        } catch let error as RecoveryCodecError {
            throw fail(captured, RecoveryClientError.protocolViolation(error.reason))
        } catch let error as RecoveryTransportError {
            throw fail(captured, RecoveryClientError.transport(error.reason))
        }

        captured.ephemeralPrivateKey = privateKey
        captured.phoneEphemeralPublicKey = phonePublicKey
        captured.fetchChallenge = challenge
        captured.fetchInFlight = true
        state = .fetchingRequest

        let request = RecoveryTransportRequest(
            endpoint: captured.requestEndpoint,
            route: .request,
            body: body,
            deadline: deadline
        )
        let transport = self.transport
        let task = Task { try await transport.send(request) }
        captured.transportTask = task

        // Cleanup touches only the captured session, never a replacement.
        defer {
            captured.fetchInFlight = false
            captured.transportTask = nil
        }

        let response: RecoveryTransportResponse
        do {
            response = try await task.value
        } catch let error as RecoveryTransportError {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            if error == RecoveryTransportError.cancelled {
                throw fail(captured, RecoveryClientError.cancelled)
            }
            throw fail(captured, RecoveryClientError.transport(error.reason))
        } catch is CancellationError {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            throw fail(captured, RecoveryClientError.cancelled)
        } catch {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            throw fail(captured, RecoveryClientError.transport("recovery_transport_unavailable"))
        }

        guard isCurrent(captured, capturedGeneration) else {
            throw RecoveryClientError.sessionReplaced
        }
        guard captured.nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }

        do {
            try Self.requireAllowedResponse(response, route: .request, endpoint: captured.requestEndpoint)

            let delivery = try RecoveryBootstrap.validateEncryptedRequestDelivery(
                jsonBytes: response.body
            )
            guard delivery.sessionId == captured.sessionId else {
                throw RecoveryCodecError("request_delivery_session_mismatch")
            }
            let deliveryNonce = try RecoveryCodec.decodeBase64URLCanonical(
                delivery.nonce,
                exactLength: 12
            )
            guard captured.nonceHistory.insert(deliveryNonce).inserted else {
                throw RecoveryCodecError("recovery_nonce_reuse_forbidden")
            }

            let desktopKey = try P256.KeyAgreement.PublicKey(
                x963Representation: captured.ticket.desktopEphemeralPublicKey
            )
            let agreed = try privateKey.sharedSecretFromKeyAgreement(with: desktopKey)
            let sharedSecret = agreed.withUnsafeBytes { Data($0) }
            let requestKey = try RecoveryBootstrap.deriveRequestAesKey(
                sharedSecret: sharedSecret,
                requestHash: captured.ticket.requestHash
            )

            let plaintext = try RecoveryBootstrap.decryptRequestDelivery(
                message: delivery,
                key: requestKey,
                sessionId: captured.sessionId,
                requestHash: captured.ticket.requestHash,
                phoneEphemeralPublicKey: phonePublicKey,
                fetchChallenge: challenge
            )

            // Raw-byte gate strictly before any JSON parsing.
            guard Self.constantTimeEqual(
                Data(SHA256.hash(data: plaintext)),
                captured.ticket.requestHash
            ) else {
                throw RecoveryCodecError("canonical_request_hash_mismatch")
            }

            let validated = try RecoveryCanonicalRequest.parse(
                rawBytes: plaintext,
                nowMilliseconds: String(captured.nowMilliseconds),
                expectedRequestHash: captured.ticket.requestHash
            )
            guard validated.request.sessionId == captured.sessionId else {
                throw RecoveryCodecError("canonical_request_session_mismatch")
            }
            guard validated.request.endpoint == captured.completionEndpoint else {
                throw RecoveryCodecError("canonical_request_endpoint_mismatch")
            }
            guard try RecoveryBootstrap.validateUncompressedP256PublicKey(
                validated.request.desktopEphemeralPublicKey,
                label: "desktop_ephemeral"
            ) == captured.ticket.desktopEphemeralPublicKey else {
                throw RecoveryCodecError("canonical_request_desktop_key_mismatch")
            }

            // Bind ticket expiry to the validated request using the injected
            // session clock. The ticket must not outlive floor(request.expiresAt/1000).
            try RecoveryBootstrap.validateTicketPolicy(
                ticket: captured.ticket,
                nowSeconds: captured.nowMilliseconds / 1000,
                boundRequestExpiresAtMilliseconds: validated.request.expiresAt
            )

            captured.sharedSecret = sharedSecret
            captured.requestKey = requestKey
            captured.validated = validated
            state = .requestValidated
        } catch let error as RecoveryCodecError {
            throw fail(captured, RecoveryClientError.protocolViolation(error.reason))
        } catch let error as RecoveryTransportError {
            throw fail(captured, RecoveryClientError.transport(error.reason))
        } catch let error as RecoveryClientError {
            throw fail(captured, error)
        } catch {
            throw fail(captured, RecoveryClientError.protocolViolation("recovery_client_internal"))
        }
    }

    // MARK: - Approval presentation

    /// Publishes the safe comparison presentation. Reads nothing secret.
    func prepareApproval() throws {
        guard let captured = session else {
            throw RecoveryClientError.invalidState("recovery_client_no_session")
        }
        guard !captured.isTerminal else {
            throw RecoveryClientError.invalidState("recovery_client_session_terminal")
        }
        guard state == .requestValidated, let validated = captured.validated else {
            throw RecoveryClientError.invalidState("recovery_client_prepare_state_invalid")
        }
        guard captured.nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }
        captured.presentation = RecoveryPresentation(
            sessionId: captured.sessionId,
            expiresAtUnixSeconds: captured.ticket.expiresAt,
            actionText: validated.actionText,
            networkText: validated.networkText,
            comparisonFingerprint: validated.comparisonFingerprint,
            factorBitmap: validated.request.context.factorBitmap,
            completionEndpoint: captured.completionEndpoint,
            accountAddress: validated.request.context.account,
            chainId: validated.request.context.chainId,
            recoveryEpoch: validated.request.context.recoveryEpoch
        )
        state = .awaitingApproval
    }

    // MARK: - Approval

    /// The only method that ever invokes the signer.
    ///
    /// Ordered contract:
    ///  1. require a live, non-terminal session in `awaitingApproval`
    ///  2. reject a concurrent approval on the same session
    ///  3. recheck expiry against the anchored clock
    ///  4. recompute `recoveryFactorDigest` from the validated context and
    ///     confirm it still matches the claimed value
    ///  5. hand only that digest to the signer
    ///  6. revalidate identity, generation, terminality, and expiry on resume
    ///  7. parse the returned DER strictly
    ///  8. normalise to low-S with Package 3A
    ///  9. re-encode minimal DER from the normalised pair
    /// 10. derive the approval AES key from the same ECDH secret with
    ///     salt = transcriptHash
    /// 11. assert the approval key differs from the request key
    /// 12. build the seven-field plaintext with a numeric credentialGeneration
    /// 13. seal under the IPHONE_TO_DESKTOP AAD with a system nonce
    /// 14. record the nonce and reject any reuse
    /// 15. build the `version:1` wrapper carrying the phone ephemeral key
    /// 16. enforce the 16384-byte outgoing ceiling for `/complete`
    /// 17. derive a deadline equal to the remaining ticket lifetime
    /// 18. enter `awaitingAcknowledgement` before suspending
    /// 19. POST exactly once, with no retry
    /// 20. validate the ack wrapper (`version`, optional null phone key),
    ///     reject nonce reuse, decrypt under DESKTOP_TO_IPHONE
    /// 21. validate the four-field plaintext and settle ACCEPTED or REJECTED
    func approve() async throws {
        guard let captured = session else {
            throw RecoveryClientError.invalidState("recovery_client_no_session")
        }
        guard !captured.isTerminal else {
            throw RecoveryClientError.invalidState("recovery_client_session_terminal")
        }
        guard state == .awaitingApproval else {
            throw RecoveryClientError.invalidState("recovery_client_approve_state_invalid")
        }
        guard !captured.approvalInFlight else {
            throw RecoveryClientError.invalidState("recovery_client_approval_already_in_flight")
        }
        guard let validated = captured.validated,
              let sharedSecret = captured.sharedSecret,
              let requestKey = captured.requestKey,
              let phonePublicKey = captured.phoneEphemeralPublicKey else {
            throw RecoveryClientError.invalidState("recovery_client_approve_state_invalid")
        }
        let capturedGeneration = captured.generation
        guard captured.nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }

        let digest: Data
        do {
            digest = try RecoveryCanonicalRequest.recoveryFactorDigest(validated.request.context)
            guard Self.constantTimeEqual(digest, validated.recoveryFactorDigest) else {
                throw RecoveryCodecError("recovery_factor_digest_mismatch_recomputed")
            }
        } catch let error as RecoveryCodecError {
            throw fail(captured, RecoveryClientError.protocolViolation(error.reason))
        }

        captured.approvalInFlight = true
        state = .submittingApproval
        defer {
            captured.approvalInFlight = false
            captured.transportTask = nil
        }

        captured.signerInvoked = true
        let derSignature: Data
        do {
            derSignature = try await signer.signRecoveryDigest(digest)
        } catch let error as RecoveryClientError {
            // Revalidate identity after the signer await. Preserve typed
            // cancellation and fixed `.signer(reason)` failures; map every
            // other RecoveryClientError kind and all unknown errors to the
            // opaque signer failure token. Never surface LAError, NSError,
            // CompanionFailure, or localized strings.
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            switch error.kind {
            case .cancelled:
                throw fail(captured, RecoveryClientError.cancelled)
            case .signer:
                throw fail(captured, error)
            case .sessionReplaced:
                throw RecoveryClientError.sessionReplaced
            default:
                throw fail(captured, RecoveryClientError.signer("recovery_client_signer_failed"))
            }
        } catch {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            throw fail(captured, RecoveryClientError.signer("recovery_client_signer_failed"))
        }

        guard isCurrent(captured, capturedGeneration) else {
            throw RecoveryClientError.sessionReplaced
        }
        guard captured.nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }

        let body: Data
        let deadline: RecoveryTransportDeadline
        let approvalKey: Data
        do {
            let parsedSignature = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(
                derSignature
            )
            let normalized = try RecoveryCanonicalRequest.normalizeLowS(parsedSignature)
            let rBytes = try RecoveryCodec.hexBytes(normalized.signature.r, expecting: 32)
            let sBytes = try RecoveryCodec.hexBytes(normalized.signature.s, expecting: 32)
            let canonicalDer = try RecoveryApprovalCodec.encodeDerSignature(
                r: rBytes,
                s: sBytes
            )

            // Verify the normalised signature against the trusted Role 1 public
            // key from the validated request before any approval ciphertext or
            // /complete transport work begins.
            try Self.verifyTrustedRole1Signature(
                digest: digest,
                r: rBytes,
                s: sBytes,
                trustedPublicKey: validated.request.trustedRole1PublicKey
            )

            approvalKey = try RecoveryApprovalCodec.deriveApprovalAesKey(
                sharedSecret: sharedSecret,
                transcriptHash: validated.transcriptHash
            )
            guard approvalKey != requestKey else {
                throw RecoveryCodecError("recovery_approval_key_collision_forbidden")
            }

            let plaintext = try RecoveryApprovalCodec.serializeApprovalPlaintext(
                sessionId: captured.sessionId,
                transcriptHash: validated.transcriptHash,
                role1FactorCommitment: validated.role1FactorCommitment,
                credentialIdentifierCommitment:
                    validated.request.selectedRole1CredentialIdentifierCommitment,
                credentialGeneration: validated.request.selectedRole1CredentialGeneration,
                derSignatureBase64URL: RecoveryCodec.encodeBase64URL(canonicalDer)
            )

            // Nonce is generated inside CryptoKit and is never caller supplied.
            let sealed = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: approvalKey),
                authenticating: try RecoveryApprovalCodec.buildAad(
                    direction: RecoveryApprovalCodec.aadPhoneToDesktop,
                    sessionId: captured.sessionId
                )
            )
            let nonceBytes = Data(sealed.nonce)
            guard captured.nonceHistory.insert(nonceBytes).inserted else {
                throw RecoveryCodecError("recovery_nonce_reuse_forbidden")
            }

            body = try RecoveryApprovalCodec.serializeApprovalWrapper(
                sessionId: captured.sessionId,
                phoneEphemeralPublicKey: phonePublicKey,
                nonce: nonceBytes,
                ciphertext: sealed.ciphertext,
                tag: sealed.tag
            )
            guard body.count <= RecoveryTransportRoute.complete.maxOutgoingBytes else {
                throw RecoveryTransportError.bodyTooLarge
            }
            deadline = try RecoveryTransportDeadline.forCompletion(
                nowMilliseconds: captured.nowMilliseconds,
                ticketExpiresAtUnixSeconds: captured.ticket.expiresAt
            )
        } catch let error as RecoveryClientError {
            throw fail(captured, error)
        } catch let error as RecoveryCodecError {
            throw fail(captured, RecoveryClientError.protocolViolation(error.reason))
        } catch let error as RecoveryTransportError {
            throw fail(captured, RecoveryClientError.transport(error.reason))
        } catch {
            throw fail(captured, RecoveryClientError.protocolViolation("recovery_client_internal"))
        }

        captured.approvalKey = approvalKey

        let request = RecoveryTransportRequest(
            endpoint: captured.completionEndpoint,
            route: .complete,
            body: body,
            deadline: deadline
        )
        let transport = self.transport
        let task = Task { try await transport.send(request) }
        captured.transportTask = task

        // The wait is entered before suspending, and there is exactly one
        // attempt: no retry loop exists on this path.
        state = .awaitingAcknowledgement

        let response: RecoveryTransportResponse
        do {
            response = try await task.value
        } catch let error as RecoveryTransportError {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            if error == RecoveryTransportError.cancelled {
                throw fail(captured, RecoveryClientError.cancelled)
            }
            throw fail(captured, RecoveryClientError.transport(error.reason))
        } catch is CancellationError {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            throw fail(captured, RecoveryClientError.cancelled)
        } catch {
            guard isCurrent(captured, capturedGeneration) else {
                throw RecoveryClientError.sessionReplaced
            }
            throw fail(captured, RecoveryClientError.transport("recovery_transport_unavailable"))
        }

        guard isCurrent(captured, capturedGeneration) else {
            throw RecoveryClientError.sessionReplaced
        }
        guard captured.nowMilliseconds < captured.expiresAtMilliseconds else {
            throw fail(captured, RecoveryClientError.expired)
        }

        do {
            try Self.requireAllowedResponse(
                response,
                route: .complete,
                endpoint: captured.completionEndpoint
            )
            let acknowledgement = try RecoveryApprovalCodec.validateAcknowledgementWrapper(
                jsonBytes: response.body
            )
            guard acknowledgement.sessionId == captured.sessionId else {
                throw RecoveryCodecError("recovery_acknowledgement_session_mismatch")
            }
            let ackNonce = try RecoveryCodec.decodeBase64URLCanonical(
                acknowledgement.nonce,
                exactLength: 12
            )
            guard captured.nonceHistory.insert(ackNonce).inserted else {
                throw RecoveryCodecError("recovery_nonce_reuse_forbidden")
            }
            let plaintext = try RecoveryApprovalCodec.decryptAcknowledgement(
                message: acknowledgement,
                key: approvalKey,
                sessionId: captured.sessionId
            )
            let ack = try RecoveryApprovalCodec.validateAcknowledgementPlaintext(
                jsonBytes: plaintext
            )
            guard ack.sessionId == captured.sessionId else {
                throw RecoveryCodecError("recovery_acknowledgement_session_mismatch")
            }
            guard ack.transcriptHash
                == RecoveryApprovalCodec.hex32(validated.transcriptHash) else {
                throw RecoveryCodecError("recovery_acknowledgement_transcript_mismatch")
            }

            captured.acknowledgedStatus = ack.status
            captured.isTerminal = true
            captured.releaseSecrets()
            if ack.status == "ACCEPTED" {
                state = .accepted
                failureReason = nil
            } else {
                state = .rejected
                failureReason = RecoveryClientError.rejectedByDesktop.reason
                throw RecoveryClientError.rejectedByDesktop
            }
        } catch let error as RecoveryClientError {
            throw error
        } catch let error as RecoveryCodecError {
            throw fail(captured, RecoveryClientError.protocolViolation(error.reason))
        } catch let error as RecoveryTransportError {
            throw fail(captured, RecoveryClientError.transport(error.reason))
        } catch {
            throw fail(captured, RecoveryClientError.protocolViolation("recovery_client_internal"))
        }
    }

    // MARK: - Local terminal transitions

    /// Local rejection. Never touches the signer and never opens a socket.
    func reject() throws {
        guard let captured = session else {
            throw RecoveryClientError.invalidState("recovery_client_no_session")
        }
        guard !captured.isTerminal else {
            throw RecoveryClientError.invalidState("recovery_client_session_terminal")
        }
        guard state == .requestValidated || state == .awaitingApproval else {
            throw RecoveryClientError.invalidState("recovery_client_reject_state_invalid")
        }
        captured.transportTask?.cancel()
        captured.transportTask = nil
        captured.acknowledgedStatus = nil
        captured.isTerminal = true
        captured.releaseSecrets()
        state = .rejected
        failureReason = "recovery_client_rejected_locally"
    }

    /// Idempotent. Cancels only the captured session's own transport task.
    func cancel() {
        cancel(reason: "recovery_client_cancelled")
    }

    /// Backgrounding tears the session down on the same idempotent path.
    func cancelForBackground() {
        cancel(reason: "recovery_client_cancelled_background")
    }

    private func cancel(reason: String) {
        guard let captured = session else {
            state = .cancelled
            failureReason = reason
            return
        }
        guard !captured.isTerminal else { return }
        captured.transportTask?.cancel()
        captured.transportTask = nil
        captured.isTerminal = true
        captured.releaseSecrets()
        state = .cancelled
        failureReason = reason
    }

    /// Only a terminal client can be reset, and it always lands on `idle`.
    func reset() throws {
        guard state.isTerminal else {
            throw RecoveryClientError.invalidState("recovery_client_reset_state_invalid")
        }
        retireCurrentSession()
        session = nil
        state = .idle
        failureReason = nil
    }

    // MARK: - Internals

    private func retireCurrentSession() {
        guard let previous = session else { return }
        previous.isTerminal = true
        previous.transportTask?.cancel()
        previous.transportTask = nil
        previous.releaseSecrets()
    }

    private func isCurrent(_ candidate: Session, _ generation: UInt64) -> Bool {
        guard let live = session else { return false }
        return live === candidate && live.generation == generation && !live.isTerminal
    }

    /// Marks the captured session failed. If it is no longer the live session
    /// the live one is left completely untouched and the caller receives the
    /// sanitized replacement error instead.
    private func fail(_ candidate: Session, _ error: RecoveryClientError) -> RecoveryClientError {
        guard let live = session, live === candidate, !live.isTerminal else {
            return RecoveryClientError.sessionReplaced
        }
        candidate.isTerminal = true
        candidate.releaseSecrets()
        state = error.kind == .cancelled ? .cancelled : .failed
        failureReason = error.reason
        return error
    }

    private static func requireAllowedResponse(
        _ response: RecoveryTransportResponse,
        route: RecoveryTransportRoute,
        endpoint: String
    ) throws {
        guard response.statusCode == 200 else { throw RecoveryTransportError.statusNotOK }
        guard response.contentType == RecoveryTransportRequest.contentType else {
            throw RecoveryTransportError.contentTypeInvalid
        }
        guard response.finalEndpoint == endpoint else {
            throw RecoveryTransportError.urlMismatch
        }
        guard !response.body.isEmpty, response.body.count <= route.maxIncomingBytes else {
            throw RecoveryTransportError.responseTooLarge
        }
    }

    /// Reconstructs the trusted Role 1 P-256 verifying key from the validated
    /// request and checks the normalised low-S signature over the recovery
    /// digest. Failures are always reported as a fixed signer token.
    private static func verifyTrustedRole1Signature(
        digest: Data,
        r: Data,
        s: Data,
        trustedPublicKey: RecoveryWirePublicKey
    ) throws {
        do {
            let qx = try RecoveryCodec.hexBytes(trustedPublicKey.qx, expecting: 32)
            let qy = try RecoveryCodec.hexBytes(trustedPublicKey.qy, expecting: 32)
            var x963 = Data([0x04])
            x963.append(qx)
            x963.append(qy)
            let publicKey = try P256.Signing.PublicKey(x963Representation: x963)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: r + s)
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw RecoveryClientError.signer("recovery_client_signer_public_key_mismatch")
            }
        } catch let error as RecoveryClientError {
            throw error
        } catch {
            throw RecoveryClientError.signer("recovery_client_signer_public_key_mismatch")
        }
    }

    private static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        var out = Data()
        out.reserveCapacity(count)
        while out.count < count {
            var word = UInt64.random(in: UInt64.min...UInt64.max, using: &generator)
            withUnsafeBytes(of: &word) { raw in
                for byte in raw where out.count < count {
                    out.append(byte)
                }
            }
        }
        return out
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(left, right) { difference |= a ^ b }
        return difference == 0
    }
}
