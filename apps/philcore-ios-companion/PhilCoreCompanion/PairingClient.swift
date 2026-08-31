import CryptoKit
import Foundation
import LocalAuthentication

struct PairingResult {
    let record: PublicCredentialRecord
    let desktopFingerprint: String
}

actor PairingClient {
    static let applicationIdentity =
        "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha"
    static let localApprovalPolicy =
        "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST"

    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private var activeSession: URLSession?

    func parse(_ scannedValue: String, now: Date = Date()) throws -> PairingRequest {
        guard let components = URLComponents(string: scannedValue),
              components.scheme == "philcore",
              components.host == "pair",
              components.path == "/v1",
              components.fragment == nil,
              let queryItems = components.queryItems,
              queryItems.count == 1,
              queryItems[0].name == "request",
              let encoded = queryItems[0].value,
              !encoded.isEmpty,
              let data = CryptoSupport.decodeBase64URL(encoded),
              let request = try? decoder.decode(PairingRequest.self, from: data)
        else { throw CompanionFailure.invalidRequest }
        guard request.protocolVersion == 1,
              request.applicationIdentity == Self.applicationIdentity,
              let expiry = ISO8601DateFormatter().date(from: request.expiresAt),
              expiry > now,
              expiry.timeIntervalSince(now) <= 5 * 60 + 5
        else {
            if request.protocolVersion != 1 { throw CompanionFailure.unsupportedVersion }
            throw CompanionFailure.expiredRequest
        }
        guard let endpoint = URL(string: request.endpoint),
              endpoint.scheme == "http",
              isPrivateIPv4(endpoint.host ?? ""),
              endpoint.path == "/philcore/pair/v1/complete"
        else { throw CompanionFailure.insecureEndpoint }
        guard CryptoSupport.decodeBase64URL(request.desktopEphemeralPublicKey)?.count == 65,
              CryptoSupport.decodeBase64URL(request.challenge)?.count == 32,
              request.sessionId.count >= 32
        else { throw CompanionFailure.invalidRequest }
        return request
    }

    func fingerprint(for request: PairingRequest) -> String {
        CryptoSupport.fingerprint(request.canonicalTranscript)
    }

    func complete(
        request: PairingRequest,
        credentialManager: SecureEnclaveCredentialManager,
        record: PublicCredentialRecord,
        authenticationContext: LAContext
    ) async throws -> PairingResult {
        let transcriptHash = CryptoSupport.sha256(request.canonicalTranscript)
        guard let desktopBytes = CryptoSupport.decodeBase64URL(request.desktopEphemeralPublicKey),
              let desktopPublic = try? P256.KeyAgreement.PublicKey(x963Representation: desktopBytes),
              let enrollmentSignature = try? credentialManager.signDigest(
                transcriptHash,
                record: record,
                authenticationContext: authenticationContext
              )
        else { throw CompanionFailure.signingFailed }

        let phonePrivate = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try phonePrivate.sharedSecretFromKeyAgreement(with: desktopPublic)
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: transcriptHash,
            sharedInfo: Data("PHILCORE_NATIVE_PAIRING_AES256_GCM_V1".utf8),
            outputByteCount: 32
        )
        let publicKey = CryptoSupport.decodeBase64URL(record.publicKeyX963)!
        let credentialCommitment = CryptoSupport.sha256(
            Data("PHILCORE_NATIVE_CREDENTIAL_ID_V1".utf8) + publicKey
        )
        let appHash = CryptoSupport.sha256(Data(Self.applicationIdentity.utf8))
        let custody = CryptoSupport.sha256(
            Data("PHILCORE_NATIVE_DEVICE_CUSTODY_V1".utf8)
                + publicKey
                + withUnsafeBytes(of: record.generation.bigEndian) { Data($0) }
        )
        let approvalHash = CryptoSupport.sha256(Data(Self.localApprovalPolicy.utf8))
        let payload = PairingResponsePayload(
            protocolVersion: 1,
            sessionId: request.sessionId,
            phoneEphemeralPublicKey:
                CryptoSupport.base64URL(phonePrivate.publicKey.x963Representation),
            transcriptHash: CryptoSupport.base64URL(transcriptHash),
            credentialPublicKey: record.publicKeyX963,
            credentialFingerprint: record.publicFingerprint,
            credentialIdentifierCommitment: CryptoSupport.base64URL(credentialCommitment),
            applicationIdentity: Self.applicationIdentity,
            applicationIdentityHash: CryptoSupport.base64URL(appHash),
            deviceCustodyCommitment: CryptoSupport.base64URL(custody),
            localApprovalPolicyHash: CryptoSupport.base64URL(approvalHash),
            generation: record.generation,
            secureEnclaveBacked: record.secureEnclaveBacked,
            simulatorOnly: record.simulatorOnly,
            enrollmentSignatureDER: CryptoSupport.base64URL(enrollmentSignature)
        )
        let plaintext = try encoder.encode(payload)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: key,
            authenticating: Data("PHONE_TO_DESKTOP|\(request.sessionId)".utf8)
        )
        let message = EncryptedPairingMessage(
            version: 1,
            sessionId: request.sessionId,
            phoneEphemeralPublicKey:
                CryptoSupport.base64URL(phonePrivate.publicKey.x963Representation),
            nonce: CryptoSupport.base64URL(sealed.nonce.withUnsafeBytes { Data($0) }),
            ciphertext: CryptoSupport.base64URL(sealed.ciphertext),
            tag: CryptoSupport.base64URL(sealed.tag)
        )
        var urlRequest = URLRequest(url: URL(string: request.endpoint)!)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "content-type")
        urlRequest.httpBody = try encoder.encode(message)
        urlRequest.timeoutInterval = 12
        let session = URLSession(configuration: .ephemeral)
        activeSession = session
        defer {
            session.finishTasksAndInvalidate()
            activeSession = nil
        }
        let (responseData, response) = try await session.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let acknowledgement = try? decoder.decode(EncryptedPairingMessage.self, from: responseData),
              acknowledgement.sessionId == request.sessionId,
              let nonceData = CryptoSupport.decodeBase64URL(acknowledgement.nonce),
              let ciphertext = CryptoSupport.decodeBase64URL(acknowledgement.ciphertext),
              let tag = CryptoSupport.decodeBase64URL(acknowledgement.tag),
              let nonce = try? AES.GCM.Nonce(data: nonceData),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
              let acknowledgementPlaintext = try? AES.GCM.open(
                box,
                using: key,
                authenticating: Data("DESKTOP_TO_PHONE|\(request.sessionId)".utf8)
              ),
              let acknowledgementObject = try? JSONSerialization.jsonObject(
                with: acknowledgementPlaintext
              ) as? [String: Any],
              acknowledgementObject["status"] as? String == "VERIFIED"
        else { throw CompanionFailure.desktopRejected }

        var updated = record
        updated.enrollmentState = record.simulatorOnly ? .pairedTest : .production
        updated.pairedIdentityCommitment = request.philCoreIdentityCommitment
        updated.lastSuccessfulTestAt = Date()
        try credentialManager.updatePublicRecord(updated)
        return PairingResult(record: updated, desktopFingerprint: fingerprint(for: request))
    }

    func cancelPending() {
        activeSession?.invalidateAndCancel()
        activeSession = nil
    }

    private func isPrivateIPv4(_ host: String) -> Bool {
        let octets = host.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { return false }
        return octets[0] == 10
            || (octets[0] == 172 && (16...31).contains(octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
    }
}
