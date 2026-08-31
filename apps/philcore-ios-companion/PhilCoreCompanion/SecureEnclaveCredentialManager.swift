import Foundation
import LocalAuthentication
import Security

final class SecureEnclaveCredentialManager {
    static let productionTagPrefix = "com.philcore.ios.companion.localalpha.role1.v1"
    static let disposableTag = "com.philcore.ios.companion.localalpha.O43_DISPOSABLE_IOS_SECURE_ENCLAVE_RECOVERY_TEST_ONLY"

    private let metadataService = "com.philcore.ios.companion.localalpha.public-metadata"

    var secureEnclaveAvailable: Bool {
#if targetEnvironment(simulator)
        false
#else
        true
#endif
    }

    func loadPublicRecord() -> PublicCredentialRecord? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataService,
            kSecAttrAccount as String: "active-role1",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(PublicCredentialRecord.self, from: data)
    }

    func createDisposableCredential(generation: UInt64 = 1) throws -> PublicCredentialRecord {
        try deleteCredential(tag: Self.disposableTag)
        return try createCredential(
            tag: Self.disposableTag,
            generation: generation,
            productionRequested: false
        )
    }

    func createProductionCandidate(generation: UInt64) throws -> PublicCredentialRecord {
        guard generation > 0 else { throw CompanionFailure.keyCreationFailed }
        return try createCredential(
            tag: "\(Self.productionTagPrefix).g\(generation)",
            generation: generation,
            productionRequested: true
        )
    }

    private func createCredential(
        tag: String,
        generation: UInt64,
        productionRequested: Bool
    ) throws -> PublicCredentialRecord {
        let tagData = Data(tag.utf8)
#if targetEnvironment(simulator)
        if productionRequested { throw CompanionFailure.secureEnclaveUnavailable }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
#else
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else { throw CompanionFailure.deviceSecurityUnavailable }
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
#endif
        var createError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &createError),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw CompanionFailure.keyCreationFailed
        }
#if targetEnvironment(simulator)
        let simulatorOnly = true
        let secureEnclaveBacked = false
#else
        let simulatorOnly = false
        let secureEnclaveBacked = true
#endif
        let record = PublicCredentialRecord(
            schemaVersion: 1,
            generation: generation,
            keyTag: tag,
            publicKeyX963: CryptoSupport.base64URL(publicData),
            publicFingerprint: CryptoSupport.fingerprint(publicData),
            simulatorOnly: simulatorOnly,
            secureEnclaveBacked: secureEnclaveBacked,
            enrollmentState: .disposableTest,
            pairedIdentityCommitment: nil,
            lastSuccessfulTestAt: nil
        )
        try savePublicRecord(record)
        return record
    }

    func signDigest(
        _ digest: Data,
        record: PublicCredentialRecord,
        authenticationContext: LAContext? = nil
    ) throws -> Data {
        guard digest.count == 32 else { throw CompanionFailure.invalidRequest }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(record.keyTag.utf8),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var authorizedQuery = query
        let signingContext = authenticationContext ?? LAContext()
        if authenticationContext == nil {
            signingContext.localizedReason =
                "Approve the exact PhilCore recovery action shown on screen."
        }
        authorizedQuery[kSecUseAuthenticationContext as String] = signingContext
        var item: CFTypeRef?
        let status = SecItemCopyMatching(authorizedQuery as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            if status == errSecUserCanceled { throw CompanionFailure.userCancelled }
            throw CompanionFailure.keyNotFound
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key as! SecKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            if let nsError = error?.takeRetainedValue() as Error? {
                let code = (nsError as NSError).code
                if code == errSecUserCanceled { throw CompanionFailure.userCancelled }
            }
            throw CompanionFailure.signingFailed
        }
        return signature
    }

    func updatePublicRecord(_ record: PublicCredentialRecord) throws {
        try savePublicRecord(record)
    }

    func privateKeyExportPossibleForTest(record: PublicCredentialRecord) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(record.keyTag.utf8),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let key = item else { return false }
        var error: Unmanaged<CFError>?
        let exported = SecKeyCopyExternalRepresentation(
            key as! SecKey,
            &error
        )
        return exported != nil
    }

    func deleteActiveCredential() throws {
        guard let record = loadPublicRecord() else { return }
        try deleteCredential(tag: record.keyTag)
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataService,
            kSecAttrAccount as String: "active-role1"
        ] as CFDictionary)
    }

    func deleteCredential(tag: String) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8)
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionFailure.keyCreationFailed
        }
    }

    private func savePublicRecord(_ record: PublicCredentialRecord) throws {
        let data = try JSONEncoder().encode(record)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: metadataService,
            kSecAttrAccount as String: "active-role1"
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw CompanionFailure.keyCreationFailed
        }
    }

    // MARK: - Recovery-specific credential access
    //
    // These methods deliberately do not alter pairing/disposable `signDigest`
    // semantics. The production recovery query constrains the exact application
    // tag, EC P-256 key type, Secure Enclave token identity where supported,
    // and exactly one result. Do not rely only on `record.secureEnclaveBacked`.

    func loadActiveRecoveryPublicRecord() -> PublicCredentialRecord? {
        loadPublicRecord()
    }

    func copyActualProductionRecoveryPublicKeyBytes(tag: String) throws -> Data {
        try Self.requireConcreteProductionRecoveryEnvironment()
        let privateKey = try copyExactProductionRecoveryPrivateKey(tag: tag)
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw RecoveryClientError.signer("recovery_credential_key_missing")
        }
        return publicData
    }

    func signProductionRecoveryDigest(
        _ digest: Data,
        tag: String,
        authenticationContext: LAContext
    ) throws -> Data {
        try Self.requireConcreteProductionRecoveryEnvironment()
        guard digest.count == 32 else {
            throw RecoveryClientError.signer("recovery_client_signer_failed")
        }
        let privateKey = try copyExactProductionRecoveryPrivateKey(
            tag: tag,
            authenticationContext: authenticationContext
        )
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            if let nsError = error?.takeRetainedValue() as Error? {
                let code = (nsError as NSError).code
                if code == errSecUserCanceled {
                    throw CompanionFailure.userCancelled
                }
            }
            throw CompanionFailure.signingFailed
        }
        return signature
    }

    /// Builds the production recovery private-key query. When no authentication
    /// context is supplied (pre-prompt public-key inspection), authentication UI
    /// is explicitly prohibited. When a context is supplied for signing, that
    /// context is bound and the preflight skip policy is not applied.
    static func productionRecoveryKeyQuery(
        tag: String,
        authenticationContext: LAContext?
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
#if !targetEnvironment(simulator)
        query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
#endif
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        } else {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        return query
    }

    static func mapProductionRecoveryKeyStatus(_ status: OSStatus) -> RecoveryClientError {
        switch status {
        case errSecInteractionNotAllowed:
            return .signer("recovery_credential_preflight_authentication_required")
        default:
            return .signer("recovery_credential_key_missing")
        }
    }

    private static func requireConcreteProductionRecoveryEnvironment() throws {
#if targetEnvironment(simulator)
        throw RecoveryClientError.signer("recovery_credential_simulator_production_forbidden")
#endif
    }

    private func copyExactProductionRecoveryPrivateKey(
        tag: String,
        authenticationContext: LAContext? = nil
    ) throws -> SecKey {
        try Self.requireConcreteProductionRecoveryEnvironment()
        let query = Self.productionRecoveryKeyQuery(
            tag: tag,
            authenticationContext: authenticationContext
        )
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            if status == errSecUserCanceled {
                throw CompanionFailure.userCancelled
            }
            throw Self.mapProductionRecoveryKeyStatus(status)
        }
        return (item as! SecKey)
    }
}
