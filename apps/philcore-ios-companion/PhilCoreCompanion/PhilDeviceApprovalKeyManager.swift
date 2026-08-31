import Foundation
import LocalAuthentication
import Security

/// Public metadata for a replaceable Phil V1 device approval key.
///
/// This record contains no Phil root, data key, recovery share, account key,
/// or private device key. App Attest is deliberately not used as identity or
/// recovery authority.
struct PhilDeviceApprovalPublicRecord: Codable, Equatable {
    let schemaVersion: UInt64
    let generation: UInt64
    let keyTag: String
    let publicKeyX963: String
    let publicKeyFingerprint: String
    let signatureSuite: String
    let secureEnclaveBacked: Bool
    let userPresenceRequired: Bool
}

/// Secure Enclave boundary for device approval and local-vault-key wrapping.
///
/// The P-256 private key is generated in the Secure Enclave, is marked
/// ThisDeviceOnly, requires user presence for private-key use, and is never
/// exported. It is a replaceable device factor, not Phil identity. Recovery
/// bundles remain protected by independent 2-of-3 factors and never depend on
/// this key.
final class PhilDeviceApprovalKeyManager {
    static let productionTagPrefix = "com.philcore.ios.companion.device-approval.v1"
    static let signatureSuite = "p256-secure-enclave-sha256-digest-v1"

    private let metadataService = "com.philcore.ios.companion.device-approval.public-metadata.v1"

    var secureEnclaveAvailable: Bool {
#if targetEnvironment(simulator)
        false
#else
        true
#endif
    }

    func createProductionCandidate(generation: UInt64) throws -> PhilDeviceApprovalPublicRecord {
        guard generation > 0 else { throw CompanionFailure.keyCreationFailed }
#if targetEnvironment(simulator)
        throw CompanionFailure.secureEnclaveUnavailable
#else
        let tag = "\(Self.productionTagPrefix).g\(generation)"
        let tagData = Data(tag.utf8)
        try deleteKeyIfPresent(tag: tag)

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else {
            throw CompanionFailure.deviceSecurityUnavailable
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: access,
                kSecAttrSynchronizable as String: false
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &createError),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw CompanionFailure.keyCreationFailed
        }
        let record = PhilDeviceApprovalPublicRecord(
            schemaVersion: 1,
            generation: generation,
            keyTag: tag,
            publicKeyX963: CryptoSupport.base64URL(publicData),
            publicKeyFingerprint: CryptoSupport.fingerprint(publicData),
            signatureSuite: Self.signatureSuite,
            secureEnclaveBacked: true,
            userPresenceRequired: true
        )
        do {
            try savePublicRecord(record)
        } catch let metadataError {
            // SecKeyCreateRandomKey persisted the private key before metadata
            // storage. Roll it back so a metadata failure cannot leave an
            // undiscoverable Secure Enclave key behind.
            do {
                try deleteKeyIfPresent(tag: tag)
            } catch {
                throw CompanionFailure.keyCreationFailed
            }
            throw metadataError
        }
        return record
#endif
    }

    func loadPublicRecord() -> PhilDeviceApprovalPublicRecord? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataService,
            kSecAttrAccount as String: "active-device-approval",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data
        else { return nil }
        return try? JSONDecoder().decode(PhilDeviceApprovalPublicRecord.self, from: data)
    }

    func signApprovalDigest(
        _ digest: Data,
        record: PhilDeviceApprovalPublicRecord,
        authenticationContext: LAContext
    ) throws -> Data {
        guard digest.count == 32 else { throw CompanionFailure.invalidRequest }
        let privateKey = try copyPrivateKey(
            record: record,
            authenticationContext: authenticationContext
        )
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            if let failure = mapUserPresenceFailure(error) { throw failure }
            throw CompanionFailure.signingFailed
        }
        return signature
    }

    /// Wraps only a random local vault/wrapping key. This method must never be
    /// used to make the identity/data recovery package device-dependent.
    func wrapLocalVaultKey(
        _ key: Data,
        record: PhilDeviceApprovalPublicRecord
    ) throws -> Data {
        guard key.count == 32 else { throw CompanionFailure.invalidRequest }
        let publicData = try decodeAndValidatePublicKey(record)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var keyError: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            publicData as CFData,
            attributes as CFDictionary,
            &keyError
        ) else { throw CompanionFailure.keyCreationFailed }
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw CompanionFailure.deviceSecurityUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            key as CFData,
            &error
        ) as Data? else {
            throw CompanionFailure.deviceSecurityUnavailable
        }
        return wrapped
    }

    func unwrapLocalVaultKey(
        _ wrapped: Data,
        record: PhilDeviceApprovalPublicRecord,
        authenticationContext: LAContext
    ) throws -> Data {
        let privateKey = try copyPrivateKey(
            record: record,
            authenticationContext: authenticationContext
        )
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw CompanionFailure.deviceSecurityUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            wrapped as CFData,
            &error
        ) as Data?, key.count == 32 else {
            if let failure = mapUserPresenceFailure(error) { throw failure }
            throw CompanionFailure.deviceSecurityUnavailable
        }
        return key
    }

    func privateKeyExportPossibleForTest(record: PhilDeviceApprovalPublicRecord) -> Bool {
        guard let privateKey = try? copyPrivateKey(record: record, authenticationContext: nil) else {
            return false
        }
        return SecKeyCopyExternalRepresentation(privateKey, nil) != nil
    }

    /// Physical-ceremony-only export check after explicit user presence. A
    /// Secure Enclave private key must still return no external representation.
    func privateKeyExportPossibleForTest(
        record: PhilDeviceApprovalPublicRecord,
        authenticationContext: LAContext
    ) throws -> Bool {
        let privateKey = try copyPrivateKey(
            record: record,
            authenticationContext: authenticationContext
        )
        return SecKeyCopyExternalRepresentation(privateKey, nil) != nil
    }

    /// Read-only physical-ceremony probe. It returns only key presence and
    /// never requests or exports private-key material.
    func candidateExistsForTest(record: PhilDeviceApprovalPublicRecord) throws -> Bool {
        try validateRecord(record)
#if targetEnvironment(simulator)
        throw CompanionFailure.secureEnclaveUnavailable
#else
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: Data(record.keyTag.utf8),
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return false }
        if status == errSecInteractionNotAllowed { return true }
        guard status == errSecSuccess else {
            throw CompanionFailure.keyNotFound
        }
        return true
#endif
    }

    /// Deletes only the exact disposable candidate represented by `record`.
    /// It does not delete identity, recovery, account, or legacy companion keys.
    func deleteProductionCandidate(record: PhilDeviceApprovalPublicRecord) throws {
        try validateRecord(record)
        let status = SecItemDelete(exactPrivateKeyQuery(record: record) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionFailure.keyCreationFailed
        }
        if loadPublicRecord() == record {
            let metadataStatus = SecItemDelete([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: metadataService,
                kSecAttrAccount as String: "active-device-approval"
            ] as CFDictionary)
            guard metadataStatus == errSecSuccess || metadataStatus == errSecItemNotFound else {
                throw CompanionFailure.keyCreationFailed
            }
        }
    }

    private func copyPrivateKey(
        record: PhilDeviceApprovalPublicRecord,
        authenticationContext: LAContext?
    ) throws -> SecKey {
#if targetEnvironment(simulator)
        throw CompanionFailure.secureEnclaveUnavailable
#else
        try validateRecord(record)
        var query = exactPrivateKeyQuery(record: record)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        } else {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            if status == errSecUserCanceled { throw CompanionFailure.userCancelled }
            if status == errSecAuthFailed { throw CompanionFailure.userDenied }
            if status == errSecInteractionNotAllowed {
                throw CompanionFailure.deviceSecurityUnavailable
            }
            throw CompanionFailure.keyNotFound
        }
        return key as! SecKey
#endif
    }

    private func decodeAndValidatePublicKey(_ record: PhilDeviceApprovalPublicRecord) throws -> Data {
        try validateRecord(record)
        guard let data = CryptoSupport.decodeBase64URL(record.publicKeyX963),
              data.count == 65,
              data.first == 0x04,
              CryptoSupport.base64URL(data) == record.publicKeyX963,
              CryptoSupport.fingerprint(data) == record.publicKeyFingerprint
        else { throw CompanionFailure.keyNotFound }
        return data
    }

    private func validateRecord(_ record: PhilDeviceApprovalPublicRecord) throws {
        guard record.schemaVersion == 1,
              record.generation > 0,
              record.secureEnclaveBacked,
              record.userPresenceRequired,
              record.signatureSuite == Self.signatureSuite,
              record.keyTag == "\(Self.productionTagPrefix).g\(record.generation)"
        else { throw CompanionFailure.keyNotFound }
    }

    private func mapUserPresenceFailure(
        _ error: Unmanaged<CFError>?
    ) -> CompanionFailure? {
        guard let error else { return nil }
        let nsError = error.takeRetainedValue() as Error as NSError
        if nsError.code == errSecUserCanceled { return .userCancelled }
        if nsError.code == errSecAuthFailed { return .userDenied }
        guard nsError.domain == LAError.errorDomain,
              let code = LAError.Code(rawValue: nsError.code)
        else { return nil }
        switch code {
        case .userCancel, .appCancel, .systemCancel:
            return .userCancelled
        case .authenticationFailed, .userFallback:
            return .userDenied
        default:
            return nil
        }
    }

    private func exactPrivateKeyQuery(
        record: PhilDeviceApprovalPublicRecord
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(record.keyTag.utf8)
        ]
#if !targetEnvironment(simulator)
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
#endif
        return query
    }

    private func savePublicRecord(_ record: PhilDeviceApprovalPublicRecord) throws {
        let data = try JSONEncoder().encode(record)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataService,
            kSecAttrAccount as String: "active-device-approval"
        ]
        let update: [String: Any] = [
            kSecValueData as String: data
        ]

        // Updating the existing item is atomic and preserves the prior active
        // record if the write fails. It also allows a later generation to
        // replace the fixed active-record slot without a delete/add gap.
        let updateStatus = SecItemUpdate(
            base as CFDictionary,
            update as CFDictionary
        )
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw CompanionFailure.keyCreationFailed
        }

        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecSuccess { return }

        // Another writer may have populated the fixed slot after the first
        // update observed it missing. Resolve only that race with one atomic
        // update; every other failure remains fail-closed.
        if addStatus == errSecDuplicateItem,
           SecItemUpdate(base as CFDictionary, update as CFDictionary) == errSecSuccess {
            return
        }
        throw CompanionFailure.keyCreationFailed
    }

    private func deleteKeyIfPresent(tag: String) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8)
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionFailure.keyCreationFailed
        }
    }
}
