import CryptoKit
import CoreFoundation
import Foundation

struct RoutineAuthorizationPresentation: Equatable, Sendable {
    let application: String
    let action: String
    let network: String
    let account: String
    let target: String
    let parameters: String
    let value: String
    let maximumFee: String
    let expiresAt: UInt64
    let comparisonFingerprint: String
}

enum RoutineAuthorizationPhase: Equatable, Sendable {
    case idle, exchangingKeys, comparingFingerprint, reviewing, signing, submitting, accepted
    case denied, cancelled, expired, failed
}

struct RoutineAuthorizationStatus: Equatable, Sendable {
    let phase: RoutineAuthorizationPhase
    let fingerprint: String?
    let presentation: RoutineAuthorizationPresentation?
    let failure: RoutineAuthorizationFailure?
    var bindingField: String? = nil
    var terminalDecision: String? = nil
}

private struct ParsedRoutineRequest {
    let raw: [String: Any]
    let requestId: Data
    let requestIdHex: String
    let sessionId: Data
    let sessionIdHex: String
    let expiresAt: UInt64
    let platformSigningDigest: Data
    let platformSigningDigestHex: String
    let deviceId: String
    let deviceKeyId: String
    let humanPresentationHash: String
    let deviceApprovalDigest: String
    let responseFormatVersionHash: String
    let deviceEpoch: String
    let presentation: RoutineAuthorizationPresentation
}

@MainActor
final class RoutineAuthorizationClient: ObservableObject {
    @Published private(set) var status = RoutineAuthorizationStatus(phase: .idle, fingerprint: nil, presentation: nil, failure: nil)

    private let transport: any RoutineAuthorizationTransporting
    private let signer: any RoutineApprovalSigning
    private var submittedApproval = false
    private var generation: UInt64 = 0
    private var bootstrap: RoutineAuthorizationBootstrap?
    private var handshake: RoutineAuthorizationHandshake?
    private var beginExchange: Task<RoutineTransportExchange, Error>?
    private var encryptedRequest: Data?
    private var parsedRequest: ParsedRoutineRequest?

    init(transport: any RoutineAuthorizationTransporting, signer: any RoutineApprovalSigning) {
        self.transport = transport; self.signer = signer
    }

    // Restored ambiguity is a durable stop, not a transient presentation. There
    // is deliberately no local reset: reconciliation needs a separate workflow.
    func restoreUnknownOutcome() {
        submittedApproval = true
        fail(.outcomeUnknown)
    }

    func start(scannedValue: String, now: UInt64) async {
        guard !submittedApproval && status.failure != .outcomeUnknown else { return }
        terminate(next: .idle)
        generation &+= 1; let operation = generation
        do {
            let decoded = try RoutineAuthorizationBootstrap.decode(scannedValue, now: now)
            let exchange = try RoutineAuthorizationHandshake(bootstrap: decoded)
            bootstrap = decoded; handshake = exchange
            status = RoutineAuthorizationStatus(phase: .exchangingKeys, fingerprint: nil, presentation: nil, failure: nil)
            let begin = Self.beginJSON(bootstrap: decoded, iphonePublicKey: exchange.iphonePublicKey)
            let pending = Task { try await transport.post(
                url: decoded.origin + RoutineAuthorizationBootstrap.beginPath,
                contentType: "application/json", body: begin, expiresAt: decoded.expiresAt
            ) }
            beginExchange = pending
            let result = try await pending.value
            guard operation == generation else { throw RoutineAuthorizationFailure.sessionReplaced }
            guard result.statusCode == 200, result.finalURL == decoded.origin + RoutineAuthorizationBootstrap.beginPath,
                  result.contentType == "application/octet-stream", result.contentLength == result.body.count,
                  result.cacheControl == "no-store", result.connection?.lowercased() == "close",
                  result.contentEncoding == nil, result.transferEncoding == nil,
                  result.body.count <= RoutineAuthorizationFrame.maximumBodyBytes else {
                throw RoutineAuthorizationFailure.transportFailure
            }
            encryptedRequest = result.body
            status = RoutineAuthorizationStatus(
                phase: .comparingFingerprint, fingerprint: exchange.fingerprint, presentation: nil, failure: nil
            )
        } catch let failure as RoutineAuthorizationFailure {
            if operation == generation { fail(failure) }
        } catch {
            if operation == generation { fail(.transportFailure) }
        }
    }

    /// No request plaintext is opened before this explicit comparison step.
    func confirmFingerprint(now: UInt64) {
        guard status.phase == .comparingFingerprint, let bootstrap, let handshake, let encryptedRequest else { return }
        var bindingStage = "request"
        do {
            guard now < bootstrap.expiresAt else { throw RoutineAuthorizationFailure.expired }
            let plaintext = try RoutineAuthorizationFrame.open(
                encryptedRequest, key: handshake.trafficKey, aad: handshake.aad(direction: .request)
            )
            bindingStage = "signer.activeRecord"
            let record = try signer.activeRecord()
            bindingStage = "request"
            let request = try Self.parseRequest(
                plaintext, bootstrap: bootstrap, record: record, fingerprint: handshake.fingerprint, now: now
            )
            parsedRequest = request
            self.encryptedRequest = nil
            status = RoutineAuthorizationStatus(phase: .reviewing, fingerprint: handshake.fingerprint, presentation: request.presentation, failure: nil)
        } catch let mismatch as RoutineBindingMismatch { fail(.bindingMismatch, bindingField: mismatch.field) }
        catch let failure as RoutineAuthorizationFailure { fail(failure,bindingField:failure == .bindingMismatch ? bindingStage : nil) }
        catch { fail(.malformedRequest) }
    }

    func approve(now: UInt64) async {
        guard status.phase == .reviewing, let bootstrap, let handshake, let request = parsedRequest else { return }
        guard now < bootstrap.expiresAt else { fail(.expired); return }
        generation &+= 1; let operation = generation
        status = RoutineAuthorizationStatus(phase: .signing, fingerprint: handshake.fingerprint, presentation: request.presentation, failure: nil)
        var bindingStage = "signer.signRoutineDigest"
        do {
            let der = try await signer.signRoutineDigest(request.platformSigningDigest)
            guard operation == generation else { throw RoutineAuthorizationFailure.sessionReplaced }
            bindingStage = "signature.der"
            let signature = try RoutineP256DER.parseAndNormalize(der)
            bindingStage = "response"
            let response = try Self.responseJSON(request: request, signature: signature)
            let frame = try RoutineAuthorizationFrame.seal(
                response, key: handshake.trafficKey, aad: handshake.aad(direction: .response)
            )
            status = RoutineAuthorizationStatus(phase: .submitting, fingerprint: handshake.fingerprint, presentation: request.presentation, failure: nil)
            submittedApproval = true
            let result = try await transport.postBound(
                url: bootstrap.origin + RoutineAuthorizationBootstrap.completePath,
                contentType: "application/octet-stream", body: frame, expiresAt: bootstrap.expiresAt, requestId: request.requestIdHex
            )
            guard operation == generation else { throw RoutineAuthorizationFailure.sessionReplaced }
            guard result.statusCode == 204, result.finalURL == bootstrap.origin + RoutineAuthorizationBootstrap.completePath,
                  result.body.isEmpty, result.contentType == nil, result.contentLength == 0,
                  result.cacheControl == "no-store", result.connection?.lowercased() == "close",
                  result.contentEncoding == nil, result.transferEncoding == nil else { throw RoutineAuthorizationFailure.transportFailure }
            status = RoutineAuthorizationStatus(phase: .accepted, fingerprint: handshake.fingerprint, presentation: request.presentation, failure: nil)
            submittedApproval = false
            clearSecrets()
        } catch let mismatch as RoutineBindingMismatch {
            if operation == generation { fail(.bindingMismatch,bindingField:mismatch.field) }
        } catch let failure as RoutineAuthorizationFailure {
            if operation == generation { fail(failure,bindingField:failure == .bindingMismatch ? bindingStage : nil) }
        } catch {
            if operation == generation { fail(.transportFailure) }
        }
    }

    func deny() async { await sendTerminal(outcome:"rejected") }
    func cancelOnDesktop() async {
        guard status.phase != .submitting else { return }
        await sendTerminal(outcome:"cancelled")
    }

    private func sendTerminal(outcome: String) async {
        let cancellable = outcome == "cancelled" && [.exchangingKeys,.comparingFingerprint,.reviewing].contains(status.phase)
        guard status.phase == .reviewing || cancellable, let bootstrap, let handshake else {
            // No authenticated exchange exists. Local cancellation is not a phone rejection.
            terminate(next:.cancelled); return
        }
        let pending = beginExchange
        let requestIdHex = Self.hex(bootstrap.requestId), sessionIdHex = Self.hex(bootstrap.sessionId)
        generation &+= 1; let operation = generation
        signer.invalidate()
        status = RoutineAuthorizationStatus(phase:.submitting,fingerprint:handshake.fingerprint,presentation:nil,failure:nil,terminalDecision:outcome)
        do {
            // During an in-flight begin, wait for that same exchange to finish.
            // Never silently drop the request or invent a remote cancellation.
            if let pending { _ = try await pending.value }
            guard operation == generation else { return }
            let value:[String:Any] = ["protocolVersion":1,"purpose":"PHIL_ROUTINE_TERMINAL_RESULT_V1",
                "sessionId":sessionIdHex,"requestId":requestIdHex,"outcome":outcome]
            let body = try JSONSerialization.data(withJSONObject:value,options:.sortedKeys)
            let frame = try RoutineAuthorizationFrame.seal(body,key:handshake.trafficKey,aad:handshake.aad(direction:.terminal))
            let url = bootstrap.origin + RoutineAuthorizationBootstrap.terminalPath
            let result = try await transport.postBound(url:url,contentType:"application/octet-stream",body:frame,
                expiresAt:bootstrap.expiresAt,requestId:requestIdHex)
            guard operation == generation else { return }
            guard result.statusCode == 200, result.finalURL == url, result.contentType == "application/octet-stream",
                  result.contentLength == result.body.count, result.cacheControl == "no-store",
                  result.connection?.lowercased() == "close", result.contentEncoding == nil,
                  result.transferEncoding == nil else { throw RoutineAuthorizationFailure.transportFailure }
            let ack = try RoutineAuthorizationFrame.open(result.body,key:handshake.trafficKey,aad:handshake.aad(direction:.terminalAck))
            try RoutineStrictJSON.rejectDuplicateKeys(ack)
            guard let object = try JSONSerialization.jsonObject(with:ack) as? [String:Any],
                  Set(object.keys) == Set(value.keys), let version=object["protocolVersion"] as? NSNumber,
                  CFGetTypeID(version) != CFBooleanGetTypeID(), version.stringValue == "1" else {
                throw RoutineAuthorizationFailure.malformedRequest
            }
            for (field,expected) in [("purpose","PHIL_ROUTINE_TERMINAL_ACK_V1"),("sessionId",sessionIdHex),
                                     ("requestId",requestIdHex),("outcome",outcome)] {
                guard object[field] as? String == expected else { throw RoutineBindingMismatch(field:"terminalAck."+field) }
            }
            terminate(next:outcome == "rejected" ? .denied : .cancelled)
        } catch let mismatch as RoutineBindingMismatch { if operation == generation { fail(.bindingMismatch,bindingField:mismatch.field) } }
        catch let failure as RoutineAuthorizationFailure { if operation == generation { fail(failure) } }
        catch { if operation == generation { fail(.transportFailure) } }
    }
    func cancel() { terminate(next: .cancelled) }
    func invalidateForBackgroundOrLock() {
        guard [.exchangingKeys,.comparingFingerprint,.reviewing,.signing,.submitting].contains(status.phase) else { return }
        signer.invalidate(); terminate(next: .cancelled)
    }

    private func terminate(next: RoutineAuthorizationPhase) {
        if submittedApproval { generation &+= 1; fail(.outcomeUnknown); return }
        generation &+= 1; transport.cancel(); signer.invalidate(); clearSecrets()
        status = RoutineAuthorizationStatus(phase: next, fingerprint: nil, presentation: nil,
            failure: next == .cancelled ? .userCancelled : next == .denied ? .userDenied : nil)
    }

    private func fail(_ failure: RoutineAuthorizationFailure, bindingField: String? = nil) {
        transport.cancel(); signer.invalidate(); clearSecrets()
        let failure = submittedApproval ? RoutineAuthorizationFailure.outcomeUnknown : failure
        let phase: RoutineAuthorizationPhase = failure == .expired ? .expired : failure == .userDenied ? .denied : failure == .userCancelled ? .cancelled : .failed
        status = RoutineAuthorizationStatus(phase: phase, fingerprint: nil, presentation: nil, failure: failure, bindingField: bindingField)
    }

    private func clearSecrets() { beginExchange = nil; bootstrap = nil; handshake = nil; encryptedRequest = nil; parsedRequest = nil }

    private static func beginJSON(bootstrap: RoutineAuthorizationBootstrap, iphonePublicKey: Data) -> Data {
        Data("{\"protocolVersion\":1,\"sessionId\":\"\(hex(bootstrap.sessionId))\",\"requestId\":\"\(hex(bootstrap.requestId))\",\"iphonePublicKey\":\"\(hex(iphonePublicKey))\"}".utf8)
    }

    private static let topKeys = Set(["formatVersionHash","executionEnvironment","adapterManifest","signatureRegistry","deviceEnrollment","accountConfiguration","catalogEntries","capabilityPolicy","action","targetCalldata","authorizationEnvelope","unsignedDeviceApproval","humanPresentation","authorizationCore","executionEnvironmentHash","adapterManifestHash","signatureRegistryHash","deviceEnrollmentHash","accountConfigurationHash","catalogHash","capabilityPolicyHash","actionHash","authorizationEnvelopeDigest","humanPresentationHash","authorizationCoreDigest","approvalNonce","deviceApprovalDigest","requestId","platformSigningDigest"])
    private static let sepoliaTopKeys = Set(["formatVersionHash","protocolContextHash","sessionId","authorization","deviceId","deviceKeyId","deviceEpoch","approvalNonce","approvedAt","approvalExpiresAt","deviceApprovalDigest","humanPresentation","humanPresentationHash","requestId","platformSigningDigest"])

    private static func parseRequest(_ data: Data, bootstrap: RoutineAuthorizationBootstrap, record: RoutineApprovalPublicRecord, fingerprint: String, now: UInt64) throws -> ParsedRoutineRequest {
        try RoutineStrictJSON.rejectDuplicateKeys(data)
        guard data.count <= RoutineAuthorizationFrame.maximumPlaintextBytes,
              let object = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
              (Set(object.keys) == topKeys || Set(object.keys) == sepoliaTopKeys) else {
            throw RoutineAuthorizationFailure.malformedRequest
        }
        let verified = try Set(object.keys) == sepoliaTopKeys
            ? RoutineAuthorizationCanonicalVerifier.verifySepoliaMint(object,bootstrap:bootstrap,record:record,fingerprint:fingerprint,now:now)
            : RoutineAuthorizationCanonicalVerifier.verify(object,bootstrap:bootstrap,record:record,fingerprint:fingerprint,now:now)
        return ParsedRoutineRequest(raw: object, requestId: verified.requestId,
            requestIdHex: hex(verified.requestId), sessionId: verified.sessionId,
            sessionIdHex: hex(verified.sessionId), expiresAt: verified.expiresAt,
            platformSigningDigest: verified.signingDigest,
            platformSigningDigestHex: hex(verified.signingDigest), deviceId: verified.deviceId,
            deviceKeyId: verified.deviceKeyId, humanPresentationHash: verified.presentationHash,
            deviceApprovalDigest: verified.approvalDigest,
            responseFormatVersionHash: verified.responseFormatVersionHash,
            deviceEpoch: verified.deviceEpoch,presentation: verified.presentation)
    }

    private static func responseJSON(request: ParsedRoutineRequest, signature: (r: Data, s: Data)) throws -> Data {
        let fields: [(String, String)] = [
            ("formatVersionHash", request.responseFormatVersionHash),
            ("protocolContextHash", domain("PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1")),
            ("sessionId", request.sessionIdHex), ("requestId", request.requestIdHex),
            ("deviceId", request.deviceId), ("deviceKeyId", request.deviceKeyId), ("deviceEpoch", request.deviceEpoch),
            ("humanPresentationHash", request.humanPresentationHash), ("deviceApprovalDigest", request.deviceApprovalDigest),
            ("platformSigningDigest", request.platformSigningDigestHex),
            ("signatureSuiteId", domain("phil-signature-p256-sha256-prehash-raw-rs-low-s-v2")),
            ("providerProfileId", domain("apple-secure-enclave-p256-x962-sha256-digest-der-v1")),
            ("wireEncodingId", domain("phil-p256-signature-rs-64-low-s-v1")),
            ("signatureR", hex(signature.r)), ("signatureS", hex(signature.s))
        ]
        var abi = Data()
        for (index, field) in fields.enumerated() {
            if index == 6 { guard let epoch=UInt64(request.deviceEpoch) else { throw RoutineBindingMismatch(field:"response.deviceEpoch") };abi.appendABIUnsigned(epoch) }
            else { guard let value = bytes32(field.1) else { throw RoutineBindingMismatch(field:"response."+field.0) }; abi.append(value) }
        }
        let responseHash = hex(RecoveryKeccak.keccak256(abi))
        let json = (fields + [("responseHash", responseHash)]).map { "\"\($0.0)\":\"\($0.1)\"" }.joined(separator: ",")
        return Data("{\(json)}".utf8)
    }

    private static func domain(_ label: String) -> String { hex(RecoveryKeccak.keccak256(Data(label.utf8))) }
    private static func bytes32(_ value: String) -> Data? { RoutineApprovalKeyManager.bytes32(value) }
    private static func hex(_ data: Data) -> String { RoutineApprovalKeyManager.hex(data) }
}

enum RoutineStrictJSON {
    static func rejectDuplicateKeys(_ data: Data) throws {
        guard !data.starts(with: [0xef, 0xbb, 0xbf]) else { throw RoutineAuthorizationFailure.malformedRequest }
        var parser = Parser(bytes: [UInt8](data)); try parser.value(); parser.space()
        guard parser.index == parser.bytes.count else { throw RoutineAuthorizationFailure.malformedRequest }
    }

    private struct Parser {
        let bytes: [UInt8]; var index = 0
        mutating func space() { while index < bytes.count && [9,10,13,32].contains(bytes[index]) { index += 1 } }
        mutating func value() throws {
            space(); guard index < bytes.count else { throw RoutineAuthorizationFailure.malformedRequest }
            switch bytes[index] {
            case 0x7b: try object()
            case 0x5b: try array()
            case 0x22: _ = try string()
            case 0x74: try literal("true")
            case 0x66: try literal("false")
            case 0x6e: try literal("null")
            default: try number()
            }
        }
        mutating func object() throws {
            index += 1; space(); var keys = Set<String>()
            if take(0x7d) { return }
            while true {
                space(); guard index < bytes.count, bytes[index] == 0x22 else { throw RoutineAuthorizationFailure.malformedRequest }
                let key = try string(); guard keys.insert(key).inserted else { throw RoutineAuthorizationFailure.malformedRequest }
                space(); guard take(0x3a) else { throw RoutineAuthorizationFailure.malformedRequest }
                try value(); space()
                if take(0x7d) { return }; guard take(0x2c) else { throw RoutineAuthorizationFailure.malformedRequest }
            }
        }
        mutating func array() throws {
            index += 1; space(); if take(0x5d) { return }
            while true { try value(); space(); if take(0x5d) { return }; guard take(0x2c) else { throw RoutineAuthorizationFailure.malformedRequest } }
        }
        mutating func string() throws -> String {
            let start = index; index += 1; var escaped = false
            while index < bytes.count {
                let byte = bytes[index]
                if escaped { escaped = false; index += 1; continue }
                if byte == 0x5c { escaped = true; index += 1; continue }
                if byte == 0x22 {
                    index += 1; let token = Data(bytes[start..<index])
                    guard let decoded = try? JSONSerialization.jsonObject(with: Data([0x5b]) + token + Data([0x5d])) as? [String], decoded.count == 1 else { throw RoutineAuthorizationFailure.malformedRequest }
                    return decoded[0]
                }
                guard byte >= 0x20 else { throw RoutineAuthorizationFailure.malformedRequest }; index += 1
            }
            throw RoutineAuthorizationFailure.malformedRequest
        }
        mutating func literal(_ text: String) throws {
            let expected = [UInt8](text.utf8); guard index + expected.count <= bytes.count,
                Array(bytes[index..<(index + expected.count)]) == expected else { throw RoutineAuthorizationFailure.malformedRequest }
            index += expected.count
        }
        mutating func number() throws {
            let start = index
            while index < bytes.count && [UInt8]("-+0123456789.eE".utf8).contains(bytes[index]) { index += 1 }
            guard index > start, (try? JSONSerialization.jsonObject(with: Data(bytes[start..<index]), options: [.fragmentsAllowed])) is NSNumber else { throw RoutineAuthorizationFailure.malformedRequest }
        }
        mutating func take(_ byte: UInt8) -> Bool { if index < bytes.count && bytes[index] == byte { index += 1; return true }; return false }
    }
}

enum RoutineP256DER {
    private static let order = Data([0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51])
    private static let half = Data([0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8])
    static func parseAndNormalize(_ der: Data) throws -> (r: Data, s: Data) {
        let bytes = [UInt8](der); guard bytes.count >= 8, bytes[0] == 0x30, Int(bytes[1]) == bytes.count - 2 else { throw RoutineAuthorizationFailure.bindingMismatch }
        var offset = 2
        func integer() throws -> Data {
            guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else { throw RoutineAuthorizationFailure.bindingMismatch }
            let length = Int(bytes[offset + 1]); offset += 2
            guard (1...33).contains(length), offset + length <= bytes.count else { throw RoutineAuthorizationFailure.bindingMismatch }
            let encoded = Data(bytes[offset..<(offset + length)]); offset += length
            guard encoded.first! & 0x80 == 0, !(encoded.count > 1 && encoded[0] == 0 && encoded[1] & 0x80 == 0),
                  !(encoded.count == 33 && encoded[0] != 0) else { throw RoutineAuthorizationFailure.bindingMismatch }
            let scalar = encoded.count == 33 ? encoded.dropFirst() : encoded[encoded.startIndex...]
            let padded = Data(repeating: 0, count: 32 - scalar.count) + scalar
            guard padded != Data(repeating: 0, count: 32), padded.lexicographicallyPrecedes(order) else { throw RoutineAuthorizationFailure.bindingMismatch }
            return padded
        }
        let r = try integer(); var s = try integer(); guard offset == bytes.count else { throw RoutineAuthorizationFailure.bindingMismatch }
        if half.lexicographicallyPrecedes(s) { s = subtract(order, s) }
        return (r, s)
    }
    private static func subtract(_ lhs: Data, _ rhs: Data) -> Data {
        var out = [UInt8](repeating: 0, count: 32), borrow = 0
        for i in stride(from: 31, through: 0, by: -1) { var value = Int(lhs[i]) - Int(rhs[i]) - borrow; if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }; out[i] = UInt8(value) }
        return Data(out)
    }
}

private extension Data {
    mutating func appendABIUnsigned(_ value: UInt64) { append(Data(repeating: 0, count: 24)); for shift in stride(from: 56, through: 0, by: -8) { append(UInt8((value >> UInt64(shift)) & 0xff)) } }
}
