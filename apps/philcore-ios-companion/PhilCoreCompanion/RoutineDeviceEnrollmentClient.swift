import CryptoKit
import Foundation
import Security

struct RoutineDeviceEnrollmentBootstrap: Equatable, Sendable {
    static let prefix = "phil-step6c-routine-enrollment-v2:"
    static let magic = Data("PHIL6CE1".utf8)
    static let preflightPath = "/philcore/routine-enrollment/v2/preflight"
    static let completePath = "/philcore/routine-enrollment/v2/complete"
    static let transcriptLabel = "PHIL_ROUTINE_DEVICE_ENROLLMENT_PROOF_V2"

    let sessionId: Data
    let ipv4: UInt32
    let port: UInt16
    let challenge: Data
    let expiresAt: UInt64
    let expectedGeneration: UInt64
    let desktopAckPublicKeyX963: Data

    var dottedIPv4: String { [24,16,8,0].map { String((ipv4 >> UInt32($0)) & 0xff) }.joined(separator: ".") }
    var origin: String { "http://\(dottedIPv4):\(port)" }
    var raw: Data {
        var value=Data();value.append(Self.magic);value.append(2);value.append(sessionId);value.appendEnrollmentUInt32BE(ipv4);value.appendEnrollmentUInt16BE(port)
        value.append(RecoveryKeccak.keccak256(Data(Self.completePath.utf8)));value.append(challenge);value.appendEnrollmentUInt64BE(expiresAt);value.appendEnrollmentUInt64BE(expectedGeneration);value.append(desktopAckPublicKeyX963);return value
    }
    var encoded: String { Self.prefix + raw.enrollmentBase64URLString }
    var fingerprint: String {
        let text=Data(SHA256.hash(data:raw)).prefix(12).map { String(format:"%02X",$0) }.joined()
        return stride(from:0,to:text.count,by:4).map { offset in
            let start=text.index(text.startIndex,offsetBy:offset),end=text.index(start,offsetBy:min(4,text.count-offset));return String(text[start..<end])
        }.joined(separator:"-")
    }

    static func decode(_ text: String, now: UInt64) throws -> RoutineDeviceEnrollmentBootstrap {
        guard !text.contains(where:{$0.isWhitespace}),text.hasPrefix(prefix) else { throw RoutineAuthorizationFailure.malformedBootstrap }
        let encoded=String(text.dropFirst(prefix.count))
        guard !encoded.isEmpty,!encoded.contains("="),!encoded.contains("+"),!encoded.contains("/"),
              let raw=Data(enrollmentBase64URLEncoded:encoded),raw.count==192,raw.enrollmentBase64URLString==encoded,
              raw.prefix(8)==magic,raw[8]==2 else { throw RoutineAuthorizationFailure.malformedBootstrap }
        let value=RoutineDeviceEnrollmentBootstrap(sessionId:raw.subdata(in:9..<41),ipv4:raw.readEnrollmentUInt32BE(at:41),port:raw.readEnrollmentUInt16BE(at:45),
            challenge:raw.subdata(in:79..<111),expiresAt:raw.readEnrollmentUInt64BE(at:111),expectedGeneration:raw.readEnrollmentUInt64BE(at:119),desktopAckPublicKeyX963:raw.subdata(in:127..<192))
        let a=UInt8((value.ipv4>>24)&0xff),b=UInt8((value.ipv4>>16)&0xff)
        guard value.sessionId != Data(repeating:0,count:32),value.challenge != Data(repeating:0,count:32),value.port != 0,
              raw.subdata(in:47..<79)==RecoveryKeccak.keccak256(Data(completePath.utf8)),
              a==10||(a==172&&(16...31).contains(b))||(a==192&&b==168),value.expiresAt>now,
              (1...64).contains(value.expectedGeneration),value.desktopAckPublicKeyX963.count==65,value.desktopAckPublicKeyX963.first==4,
              (try? P256.Signing.PublicKey(x963Representation:value.desktopAckPublicKeyX963)) != nil,value.encoded==text else {
            throw RoutineAuthorizationFailure.malformedBootstrap
        }
        return value
    }
}

@MainActor
final class RoutineDeviceEnrollmentClient {
    private let transport: any RoutineAuthorizationTransporting
    private let signer: any RoutineApprovalSigning
    private let currentUnixSeconds: () -> UInt64
    private(set) var status=RoutineAuthorizationStatus(phase:.idle,fingerprint:nil,presentation:nil,failure:nil)
    private var statusObserver: ((RoutineAuthorizationStatus) -> Void)?
    private var bootstrap: RoutineDeviceEnrollmentBootstrap?
    private var generation: UInt64=0
    private var preparedGeneration: UInt64?
    private var rollbackEligibleGeneration: UInt64?

    init(transport: any RoutineAuthorizationTransporting, signer: any RoutineApprovalSigning,
         currentUnixSeconds: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }) {
        self.transport=transport;self.signer=signer;self.currentUnixSeconds=currentUnixSeconds
    }

    func observeStatus(_ observer: @escaping (RoutineAuthorizationStatus) -> Void) {
        statusObserver=observer
    }

    private func publish(_ value: RoutineAuthorizationStatus) {
        status=value;statusObserver?(value)
    }

    func start(scannedValue: String, now: UInt64) {
        cancel();generation &+= 1
        do {
            let value=try RoutineDeviceEnrollmentBootstrap.decode(scannedValue,now:now);bootstrap=value
            publish(RoutineAuthorizationStatus(phase:.comparingFingerprint,fingerprint:value.fingerprint,presentation:nil,failure:nil))
        } catch let failure as RoutineAuthorizationFailure { fail(failure) }
        catch { fail(.malformedBootstrap) }
    }

    func confirmAndEnroll(now: UInt64) async {
        guard status.phase == .comparingFingerprint,let bootstrap else { return }
        guard now < bootstrap.expiresAt else { fail(.expired);return }
        generation &+= 1;let operation=generation;var requestPublished=false
        do {
            publish(RoutineAuthorizationStatus(phase:.exchangingKeys,fingerprint:bootstrap.fingerprint,presentation:nil,failure:nil))
            try await transport.preflight(url:bootstrap.origin+RoutineDeviceEnrollmentBootstrap.preflightPath,
                sessionId:RoutineApprovalKeyManager.hex(bootstrap.sessionId),expiresAt:bootstrap.expiresAt)
            guard operation==generation else { throw RoutineAuthorizationFailure.sessionReplaced }
            guard currentUnixSeconds()<bootstrap.expiresAt else { throw RoutineAuthorizationFailure.expired }
            let record:RoutineApprovalPublicRecord
            let active=try signer.activeRecordIfPresent()
            if let pending=try signer.preparedDisposableRecord(generation:bootstrap.expectedGeneration) {
                record=pending;preparedGeneration=bootstrap.expectedGeneration
                rollbackEligibleGeneration=active?.generation==bootstrap.expectedGeneration ? nil:bootstrap.expectedGeneration
            }
            else if let active,active.generation==bootstrap.expectedGeneration { record=active;preparedGeneration=nil;rollbackEligibleGeneration=nil }
            else if let active,bootstrap.expectedGeneration != active.generation+1 { throw RoutineAuthorizationFailure.routineKeyGenerationMismatch }
            else { record=try signer.prepareDisposableRecord(generation:bootstrap.expectedGeneration);preparedGeneration=bootstrap.expectedGeneration;rollbackEligibleGeneration=bootstrap.expectedGeneration }
            let digest=try Self.proofDigest(bootstrap:bootstrap,record:record)
            publish(RoutineAuthorizationStatus(phase:.signing,fingerprint:bootstrap.fingerprint,presentation:nil,failure:nil))
            guard currentUnixSeconds()<bootstrap.expiresAt else { throw RoutineAuthorizationFailure.expired }
            let signature=try await signer.signRoutineEnrollmentDigest(digest,generation:record.generation)
            guard operation==generation else { throw RoutineAuthorizationFailure.sessionReplaced }
            guard currentUnixSeconds()<bootstrap.expiresAt else { throw RoutineAuthorizationFailure.expired }
            if let preparedGeneration {
                do { try signer.activatePreparedDisposableRecord(generation:preparedGeneration) }
                catch { throw RoutineAuthorizationFailure.routineKeyActivationFailed }
            }
            let body=try Self.responseJSON(bootstrap:bootstrap,record:record,signature:signature)
            publish(RoutineAuthorizationStatus(phase:.submitting,fingerprint:bootstrap.fingerprint,presentation:nil,failure:nil))
            requestPublished=true;rollbackEligibleGeneration=nil
            let result:RoutineTransportExchange
            do { result=try await transport.post(url:bootstrap.origin+RoutineDeviceEnrollmentBootstrap.completePath,contentType:"application/json",body:body,expiresAt:bootstrap.expiresAt) }
            catch let failure as RoutineAuthorizationFailure {
                guard operation==generation else { throw RoutineAuthorizationFailure.sessionReplaced }
                guard failure == .desktopUnavailable || failure == .transportFailure else { throw failure }
                result=try await transport.post(url:bootstrap.origin+RoutineDeviceEnrollmentBootstrap.completePath,contentType:"application/json",body:body,expiresAt:bootstrap.expiresAt)
            }
            guard result.statusCode == 200 else { throw RoutineAuthorizationFailure.desktopRejected }
            try Self.verifyAcceptance(result:result,bootstrap:bootstrap,record:record)
            guard operation==generation,result.statusCode==200,result.finalURL==bootstrap.origin+RoutineDeviceEnrollmentBootstrap.completePath,
                  result.contentType=="application/json",result.contentLength==result.body.count,result.cacheControl=="no-store",
                  result.connection?.lowercased()=="close",result.contentEncoding==nil,result.transferEncoding==nil else {
                throw RoutineAuthorizationFailure.transportFailure
            }
            if let preparedGeneration {
                do { try signer.commitPreparedDisposableRecord(generation:preparedGeneration);self.preparedGeneration=nil }
                catch { throw RoutineAuthorizationFailure.routineKeyCommitFailed }
            }
            rollbackEligibleGeneration=nil;self.bootstrap=nil;publish(RoutineAuthorizationStatus(phase:.accepted,fingerprint:nil,presentation:nil,failure:nil))
        } catch let failure as RoutineAuthorizationFailure { if operation==generation { handleEnrollmentFailure(failure,published:requestPublished) } }
        catch { if operation==generation { handleEnrollmentFailure(.transportFailure,published:requestPublished) } }
    }

    func cancel() { generation &+= 1;transport.cancel();signer.invalidate();rollbackPreparedIfEligible();preparedGeneration=nil;bootstrap=nil;publish(RoutineAuthorizationStatus(phase:.cancelled,fingerprint:nil,presentation:nil,failure:.userCancelled)) }

    private func handleEnrollmentFailure(_ failure:RoutineAuthorizationFailure,published:Bool) {
        if !published { rollbackPreparedIfEligible() }
        preparedGeneration=nil;rollbackEligibleGeneration=nil
        fail(failure)
    }

    private func rollbackPreparedIfEligible() {
        guard let preparedGeneration,rollbackEligibleGeneration==preparedGeneration else { return }
        try? signer.rollbackPreparedDisposableRecord(generation:preparedGeneration);rollbackEligibleGeneration=nil
    }

    private func fail(_ failure: RoutineAuthorizationFailure) {
        transport.cancel();signer.invalidate();bootstrap=nil
        publish(RoutineAuthorizationStatus(phase:failure == .expired ? .expired : failure == .userDenied ? .denied : failure == .userCancelled ? .cancelled : .failed,
            fingerprint:nil,presentation:nil,failure:failure,bindingField:failure == .bindingMismatch ? "enrollment.keyRecord" : nil))
    }

    nonisolated static func proofDigest(bootstrap: RoutineDeviceEnrollmentBootstrap, record: RoutineApprovalPublicRecord) throws -> Data {
        guard record.schemaVersion==2,record.generation==bootstrap.expectedGeneration,let deviceId=RoutineApprovalKeyManager.hexData(record.deviceId),deviceId.count==32,
              let keyId=RoutineApprovalKeyManager.hexData(record.deviceKeyId),keyId.count==32,
              let publicKey=RoutineApprovalKeyManager.hexData(record.publicKeyX963),publicKey.count==65 else { throw RoutineAuthorizationFailure.bindingMismatch }
        var preimage=Data(Self.transcriptLabel.utf8);preimage.append(0);preimage.append(bootstrap.raw);preimage.append(deviceId);preimage.append(keyId)
        preimage.appendEnrollmentUInt64BE(record.generation)
        for name in ["phil-signature-p256-sha256-prehash-raw-rs-low-s-v2","apple-secure-enclave-p256-x962-sha256-digest-der-v1","phil-p256-signature-rs-64-low-s-v1"] {
            preimage.append(RecoveryKeccak.keccak256(Data(name.utf8)))
        }
        preimage.append(publicKey);preimage.append(record.secureEnclaveBacked ? 1:0);preimage.append(record.userPresenceRequired ? 1:0)
        return Data(SHA256.hash(data:preimage))
    }

    nonisolated static func acceptanceDigest(bootstrap:RoutineDeviceEnrollmentBootstrap,record:RoutineApprovalPublicRecord)throws->Data {
        var preimage=Data("PHIL_ROUTINE_DEVICE_ENROLLMENT_ACCEPTANCE_V2".utf8);preimage.append(0);preimage.append(bootstrap.raw);preimage.append(try proofDigest(bootstrap:bootstrap,record:record));return Data(SHA256.hash(data:preimage))
    }

    nonisolated static func verifyAcceptance(result:RoutineTransportExchange,bootstrap:RoutineDeviceEnrollmentBootstrap,record:RoutineApprovalPublicRecord)throws {
        try RoutineStrictJSON.rejectDuplicateKeys(result.body)
        guard result.statusCode==200,result.contentType=="application/json",result.contentLength==result.body.count,!result.body.isEmpty,
              let object=try JSONSerialization.jsonObject(with:result.body) as? [String:Any],Set(object.keys)==Set(["protocolVersion","sessionId","challenge","enrollmentProofDigest","acceptanceSignatureDER"]),
              object["protocolVersion"] as? Int==2,object["sessionId"] as? String==RoutineApprovalKeyManager.hex(bootstrap.sessionId),
              object["challenge"] as? String==RoutineApprovalKeyManager.hex(bootstrap.challenge),
              object["enrollmentProofDigest"] as? String==RoutineApprovalKeyManager.hex(try proofDigest(bootstrap:bootstrap,record:record)),
              let signatureHex=object["acceptanceSignatureDER"] as? String,let signatureData=RoutineApprovalKeyManager.hexData(signatureHex),
              verifyPrehashedAcceptance(signatureDER:signatureData,digest:try acceptanceDigest(bootstrap:bootstrap,record:record),publicKeyX963:bootstrap.desktopAckPublicKeyX963) else { throw RoutineAuthorizationFailure.transportFailure }
    }

    nonisolated static func verifyPrehashedAcceptance(signatureDER:Data,digest:Data,publicKeyX963:Data)->Bool {
        guard digest.count==32,publicKeyX963.count==65,publicKeyX963.first==4,
              let signature=try? P256.Signing.ECDSASignature(derRepresentation:signatureDER),signature.derRepresentation==signatureDER else { return false }
        let raw=signature.rawRepresentation,s=Array(raw.suffix(32)),half=Array(RoutineApprovalKeyManager.hexData("0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!)
        guard s.contains(where:{$0 != 0}),!half.lexicographicallyPrecedes(s) else { return false }
        let attributes:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeyClass as String:kSecAttrKeyClassPublic,kSecAttrKeySizeInBits as String:256]
        var createError:Unmanaged<CFError>?
        guard let key=SecKeyCreateWithData(publicKeyX963 as CFData,attributes as CFDictionary,&createError) else { return false }
        var verifyError:Unmanaged<CFError>?
        return SecKeyVerifySignature(key,.ecdsaSignatureDigestX962SHA256,digest as CFData,signatureDER as CFData,&verifyError)
    }

    private nonisolated static var transcriptLabel: String { RoutineDeviceEnrollmentBootstrap.transcriptLabel }
    static func responseJSON(bootstrap: RoutineDeviceEnrollmentBootstrap, record: RoutineApprovalPublicRecord, signature: Data) throws -> Data {
        let transportRecord:[String:Any]=["schemaVersion":2,"generation":String(record.generation),"deviceId":record.deviceId,"deviceKeyId":record.deviceKeyId,
            "signatureSuiteId":RoutineApprovalKeyManager.hex(RecoveryKeccak.keccak256(Data("phil-signature-p256-sha256-prehash-raw-rs-low-s-v2".utf8))),
            "providerProfileId":RoutineApprovalKeyManager.hex(RecoveryKeccak.keccak256(Data("apple-secure-enclave-p256-x962-sha256-digest-der-v1".utf8))),
            "wireEncodingId":RoutineApprovalKeyManager.hex(RecoveryKeccak.keccak256(Data("phil-p256-signature-rs-64-low-s-v1".utf8))),
            "publicKeyX963":record.publicKeyX963,"publicKeyFingerprint":record.publicKeyFingerprint,"secureEnclaveBacked":record.secureEnclaveBacked,
            "userPresenceRequired":record.userPresenceRequired]
        return try JSONSerialization.data(withJSONObject:["protocolVersion":2,"sessionId":RoutineApprovalKeyManager.hex(bootstrap.sessionId),
            "challenge":RoutineApprovalKeyManager.hex(bootstrap.challenge),"record":transportRecord,"proofSignatureDER":RoutineApprovalKeyManager.hex(signature)],options:[.sortedKeys])
    }
}

private extension Data {
    init?(enrollmentBase64URLEncoded text:String) {
        let value=text.replacingOccurrences(of:"-",with:"+").replacingOccurrences(of:"_",with:"/")
            + String(repeating:"=",count:(4-text.count%4)%4)
        self.init(base64Encoded:value)
    }
    var enrollmentBase64URLString:String { base64EncodedString().replacingOccurrences(of:"+",with:"-").replacingOccurrences(of:"/",with:"_").replacingOccurrences(of:"=",with:"") }
    func readEnrollmentUInt16BE(at offset:Int)->UInt16 { (UInt16(self[offset])<<8)|UInt16(self[offset+1]) }
    func readEnrollmentUInt32BE(at offset:Int)->UInt32 { (0..<4).reduce(0) { ($0<<8)|UInt32(self[offset+$1]) } }
    func readEnrollmentUInt64BE(at offset:Int)->UInt64 { (0..<8).reduce(0) { ($0<<8)|UInt64(self[offset+$1]) } }
    mutating func appendEnrollmentUInt16BE(_ value:UInt16) { append(UInt8(value>>8));append(UInt8(value&0xff)) }
    mutating func appendEnrollmentUInt32BE(_ value:UInt32) { for shift in stride(from:24,through:0,by:-8) { append(UInt8((value>>UInt32(shift))&0xff)) } }
    mutating func appendEnrollmentUInt64BE(_ value:UInt64) { for shift in stride(from:56,through:0,by:-8) { append(UInt8((value>>UInt64(shift))&0xff)) } }
}
