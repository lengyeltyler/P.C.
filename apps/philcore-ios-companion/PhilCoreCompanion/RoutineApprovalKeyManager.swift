import Foundation
import CryptoKit
import LocalAuthentication
import Security

struct RoutineApprovalPublicRecord: Codable, Equatable, Sendable {
    let schemaVersion: UInt64
    let generation: UInt64
    let deviceId: String
    let deviceKeyId: String
    let keyTag: String
    let publicKeyX963: String
    let publicKeyFingerprint: String
    let secureEnclaveBacked: Bool
    let userPresenceRequired: Bool
}

@MainActor
protocol RoutineApprovalSigning: AnyObject {
    func activeRecord() throws -> RoutineApprovalPublicRecord
    func activeRecordIfPresent() throws -> RoutineApprovalPublicRecord?
    func activeRecordWithKeyPreflight() throws -> RoutineApprovalPublicRecord?
    func createDisposableRecord() throws -> RoutineApprovalPublicRecord
    func preparedDisposableRecord(generation: UInt64) throws -> RoutineApprovalPublicRecord?
    func prepareDisposableRecord(generation: UInt64) throws -> RoutineApprovalPublicRecord
    func activatePreparedDisposableRecord(generation: UInt64) throws
    func commitPreparedDisposableRecord(generation: UInt64) throws
    func rollbackPreparedDisposableRecord(generation: UInt64) throws
    func deleteDisposableRecord() throws
    func signRoutineDigest(_ digest: Data) async throws -> Data
    func signRoutineEnrollmentDigest(_ digest: Data, generation:UInt64) async throws -> Data
    func invalidate()
}

extension RoutineApprovalSigning {
    /// Test and non-production signers have no separate hardware-item lookup.
    /// Production overrides this with a no-prompt Secure Enclave preflight.
    func activeRecordWithKeyPreflight() throws -> RoutineApprovalPublicRecord? {
        try activeRecordIfPresent()
    }
}

/// Separate disposable V2 routine authority. It never queries or mutates the
/// recovery, Phil identity, vault, pairing, or legacy device-approval tags.
@MainActor
final class RoutineApprovalKeyManager: RoutineApprovalSigning {
    static let keyTagPrefix = "com.philcore.ios.companion.routine-approval.v2"
    private static let metadataService = "com.philcore.ios.companion.routine-approval.public.v2"
    private static let activeMetadataAccount = "active-routine-v2"
    private static let pendingMetadataAccount = "pending-routine-v2"
    private static let rollbackMetadataAccount = "rollback-routine-v2"
    private let approval: LocalApprovalManager

    init(approval: LocalApprovalManager) { self.approval = approval }

    func createDisposableV2(generation: UInt64 = 1) throws -> RoutineApprovalPublicRecord {
        guard (1...64).contains(generation) else { throw RoutineAuthorizationFailure.bindingMismatch }
#if targetEnvironment(simulator)
        throw RoutineAuthorizationFailure.bindingMismatch
#else
        let tag = "\(Self.keyTagPrefix).g\(generation)"
        _ = SecItemDelete(exactKeyQuery(tag: tag) as CFDictionary)
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &accessError
        ) else { throw RoutineAuthorizationFailure.bindingMismatch }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
                kSecAttrSynchronizable as String: false
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(key),
              let publicBytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, publicBytes.count == 65 else {
            throw RoutineAuthorizationFailure.bindingMismatch
        }
        let record = RoutineApprovalPublicRecord(
            schemaVersion: 2, generation: generation,
            deviceId: try Self.randomBytes32(), deviceKeyId: try Self.randomBytes32(), keyTag: tag,
            publicKeyX963: Self.hex(publicBytes),
            publicKeyFingerprint: Self.hex(Data(SHA256.hash(data: publicBytes))),
            secureEnclaveBacked: true, userPresenceRequired: true
        )
        do { try save(record, account: Self.activeMetadataAccount) }
        catch { _ = SecItemDelete(exactKeyQuery(tag: tag) as CFDictionary); throw error }
        return record
#endif
    }

    func activeRecord() throws -> RoutineApprovalPublicRecord {
        guard let record = try metadataRecord(account: Self.activeMetadataAccount) else {
            throw RoutineAuthorizationFailure.bindingMismatch
        }
        return record
    }

    func activeRecordIfPresent() throws -> RoutineApprovalPublicRecord? {
        try metadataRecord(account: Self.activeMetadataAccount)
    }

    /// Confirms that public metadata still has a matching Secure Enclave item
    /// without presenting Face ID or requesting a signature.
    func activeRecordWithKeyPreflight() throws -> RoutineApprovalPublicRecord? {
        guard let record = try activeRecordIfPresent() else { return nil }
#if targetEnvironment(simulator)
        return record
#else
        var query = exactKeyQuery(tag: record.keyTag)
        query[kSecReturnAttributes as String] = true
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess || status == errSecInteractionNotAllowed { return record }
        if status == errSecItemNotFound { throw RoutineAuthorizationFailure.routineKeyUnavailable }
        throw RoutineAuthorizationFailure.routineSigningFailed
#endif
    }

    private func metadataRecord(account: String) throws -> RoutineApprovalPublicRecord? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = item as? Data, let record = try? JSONDecoder().decode(RoutineApprovalPublicRecord.self, from: data) else {
            throw RoutineAuthorizationFailure.bindingMismatch
        }
        try validate(record)
        return record
    }

    func createDisposableRecord() throws -> RoutineApprovalPublicRecord { try createDisposableV2(generation: 1) }
    func preparedDisposableRecord(generation:UInt64)throws->RoutineApprovalPublicRecord? {
        guard let pending=try metadataRecord(account:Self.pendingMetadataAccount) else { return nil }
        return pending.generation==generation ? pending:nil
    }
    func prepareDisposableRecord(generation: UInt64) throws -> RoutineApprovalPublicRecord {
        guard (1...64).contains(generation) else { throw RoutineAuthorizationFailure.bindingMismatch }
        if let pending=try metadataRecord(account:Self.pendingMetadataAccount) {
            let active=try activeRecordIfPresent()
            if pending.generation==generation { return pending }
            if active?.generation==pending.generation,pending.generation<64,generation==pending.generation+1 {
                try commitPreparedDisposableRecord(generation:pending.generation)
            } else { throw RoutineAuthorizationFailure.bindingMismatch }
        }
        let active=try activeRecordIfPresent()
        guard active?.generation != generation,generation==(active?.generation ?? 0)+1 else { throw RoutineAuthorizationFailure.bindingMismatch }
#if targetEnvironment(simulator)
        throw RoutineAuthorizationFailure.bindingMismatch
#else
        let tag="\(Self.keyTagPrefix).g\(generation)";_ = SecItemDelete(exactKeyQuery(tag:tag) as CFDictionary)
        var accessError:Unmanaged<CFError>?
        guard let access=SecAccessControlCreateWithFlags(nil,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,[.privateKeyUsage,.userPresence],&accessError) else { throw RoutineAuthorizationFailure.bindingMismatch }
        let attributes:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits as String:256,kSecAttrTokenID as String:kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String:[kSecAttrIsPermanent as String:true,kSecAttrApplicationTag as String:Data(tag.utf8),kSecAttrAccessControl as String:access,kSecAttrSynchronizable as String:false]]
        var error:Unmanaged<CFError>?
        guard let key=SecKeyCreateRandomKey(attributes as CFDictionary,&error),let publicKey=SecKeyCopyPublicKey(key),
              let publicBytes=SecKeyCopyExternalRepresentation(publicKey,nil) as Data?,publicBytes.count==65 else { throw RoutineAuthorizationFailure.bindingMismatch }
        let record=RoutineApprovalPublicRecord(schemaVersion:2,generation:generation,deviceId:try Self.randomBytes32(),deviceKeyId:try Self.randomBytes32(),keyTag:tag,
            publicKeyX963:Self.hex(publicBytes),publicKeyFingerprint:Self.hex(Data(SHA256.hash(data:publicBytes))),secureEnclaveBacked:true,userPresenceRequired:true)
        do { try save(record,account:Self.pendingMetadataAccount) }
        catch { _ = SecItemDelete(exactKeyQuery(tag:tag) as CFDictionary);throw error }
        return record
#endif
    }

    func activatePreparedDisposableRecord(generation: UInt64) throws {
        guard let pending=try metadataRecord(account:Self.pendingMetadataAccount),pending.generation==generation else { throw RoutineAuthorizationFailure.bindingMismatch }
        if try activeRecordIfPresent()?.generation==generation { return }
        if let active=try activeRecordIfPresent() { try save(active,account:Self.rollbackMetadataAccount) }
        else { try deleteMetadata(account:Self.rollbackMetadataAccount) }
        try save(pending,account:Self.activeMetadataAccount)
    }

    func commitPreparedDisposableRecord(generation:UInt64)throws {
        guard let pending=try metadataRecord(account:Self.pendingMetadataAccount),pending.generation==generation,
              try activeRecordIfPresent()?.generation==generation else { throw RoutineAuthorizationFailure.bindingMismatch }
        if let retired=try metadataRecord(account:Self.rollbackMetadataAccount) {
            guard retired.generation < generation, retired.keyTag != pending.keyTag else {
                throw RoutineAuthorizationFailure.bindingMismatch
            }
            let status=SecItemDelete(exactKeyQuery(tag:retired.keyTag) as CFDictionary)
            guard status==errSecSuccess||status==errSecItemNotFound else {
                throw RoutineAuthorizationFailure.bindingMismatch
            }
        }
        // Keep pending metadata until every earlier cleanup step succeeds so a
        // failed commit remains retryable after Desktop has accepted the key.
        try deleteMetadata(account:Self.rollbackMetadataAccount)
        try deleteMetadata(account:Self.pendingMetadataAccount)
    }

    func rollbackPreparedDisposableRecord(generation: UInt64) throws {
        guard let pending=try metadataRecord(account:Self.pendingMetadataAccount) else { return }
        guard pending.generation==generation else { throw RoutineAuthorizationFailure.bindingMismatch }
        if let prior=try metadataRecord(account:Self.rollbackMetadataAccount) { try save(prior,account:Self.activeMetadataAccount) }
        else if try activeRecordIfPresent()?.generation==generation { try deleteMetadata(account:Self.activeMetadataAccount) }
        try deleteMetadata(account:Self.pendingMetadataAccount);try deleteMetadata(account:Self.rollbackMetadataAccount)
        let status=SecItemDelete(exactKeyQuery(tag:pending.keyTag) as CFDictionary)
        guard status==errSecSuccess||status==errSecItemNotFound else { throw RoutineAuthorizationFailure.bindingMismatch }
    }

    func signRoutineDigest(_ digest: Data) async throws -> Data {
        try await signDigest(digest, record:try activeRecord(), reason: "Approve the exact harmless local PhilCore action shown on screen.")
    }

    func signRoutineEnrollmentDigest(_ digest: Data, generation:UInt64) async throws -> Data {
        let record:RoutineApprovalPublicRecord
        if let pending=try metadataRecord(account:Self.pendingMetadataAccount),pending.generation==generation { record=pending }
        else { let active=try activeRecord();guard active.generation==generation else { throw RoutineAuthorizationFailure.bindingMismatch };record=active }
        return try await signDigest(digest, record:record, reason: "Enroll this disposable routine key with the PhilCore Desktop fingerprint shown on screen.")
    }

    private func signDigest(_ digest: Data, record:RoutineApprovalPublicRecord, reason: String) async throws -> Data {
        guard digest.count == 32 else { throw RoutineAuthorizationFailure.bindingMismatch }
        let context: LAContext
        do { context = try await approval.approve(reason: reason) }
        catch let failure as CompanionFailure {
            approval.finish()
            if failure == .userDenied { throw RoutineAuthorizationFailure.userDenied }
            throw RoutineAuthorizationFailure.userCancelled
        }
        defer { approval.finish() }
        var query = exactKeyQuery(tag: record.keyTag)
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let lookupStatus = SecItemCopyMatching(query as CFDictionary, &item)
        guard lookupStatus == errSecSuccess, let item else {
            if lookupStatus == errSecItemNotFound { throw RoutineAuthorizationFailure.routineKeyUnavailable }
            throw RoutineAuthorizationFailure.routineSigningFailed
        }
        let privateKey = item as! SecKey
        guard let actualPublicKey = SecKeyCopyPublicKey(privateKey),
              let actualPublicBytes = SecKeyCopyExternalRepresentation(actualPublicKey, nil) as Data?,
              actualPublicBytes.count == 65,
              Self.hex(actualPublicBytes) == record.publicKeyX963,
              Self.hex(Data(SHA256.hash(data: actualPublicBytes))) == record.publicKeyFingerprint else {
            throw RoutineAuthorizationFailure.routineKeyMismatch
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error
        ) as Data? else { throw RoutineAuthorizationFailure.routineSigningFailed }
        return signature
    }

    func invalidate() { approval.invalidate() }

    func deleteDisposableV2() throws {
        let tags = (1...64).map { "\(Self.keyTagPrefix).g\($0)" }
        for tag in tags {
            let keyStatus = SecItemDelete(exactKeyQuery(tag: tag) as CFDictionary)
            guard keyStatus == errSecSuccess || keyStatus == errSecItemNotFound else { throw RoutineAuthorizationFailure.bindingMismatch }
        }
        try deleteMetadata(account:Self.activeMetadataAccount);try deleteMetadata(account:Self.pendingMetadataAccount);try deleteMetadata(account:Self.rollbackMetadataAccount)
    }

    func deleteDisposableRecord() throws { try deleteDisposableV2() }

    private func validate(_ record: RoutineApprovalPublicRecord) throws {
        guard record.schemaVersion == 2, (1...64).contains(record.generation),
              record.keyTag == "\(Self.keyTagPrefix).g\(record.generation)",
              record.secureEnclaveBacked, record.userPresenceRequired,
              Self.bytes32(record.deviceId) != nil, Self.bytes32(record.deviceKeyId) != nil,
              let key = Self.hexData(record.publicKeyX963), key.count == 65, key.first == 4,
              record.publicKeyFingerprint == Self.hex(Data(SHA256.hash(data: key))) else {
            throw RoutineAuthorizationFailure.bindingMismatch
        }
    }

    private func exactKeyQuery(tag: String) -> [String: Any] {
        [kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, kSecAttrApplicationTag as String: Data(tag.utf8)]
    }

    private func save(_ record: RoutineApprovalPublicRecord, account:String) throws {
        let encoded = try JSONEncoder().encode(record)
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService, kSecAttrAccount as String: account]
        let update=SecItemUpdate(base as CFDictionary,[kSecValueData as String:encoded] as CFDictionary)
        if update==errSecSuccess { return }
        guard update==errSecItemNotFound else { throw RoutineAuthorizationFailure.bindingMismatch }
        var add=base;add[kSecValueData as String]=encoded;add[kSecAttrAccessible as String]=kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(add as CFDictionary,nil)==errSecSuccess else { throw RoutineAuthorizationFailure.bindingMismatch }
    }

    private func deleteMetadata(account:String)throws {
        let status=SecItemDelete([kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:Self.metadataService,kSecAttrAccount as String:account] as CFDictionary)
        guard status==errSecSuccess||status==errSecItemNotFound else { throw RoutineAuthorizationFailure.bindingMismatch }
    }

    static func randomBytes32() throws -> String {
        var data = Data(count: 32)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess, data != Data(repeating: 0, count: 32) else {
            throw RoutineAuthorizationFailure.bindingMismatch
        }
        return hex(data)
    }
    nonisolated static func hex(_ data: Data) -> String { "0x" + data.map { String(format: "%02x", $0) }.joined() }
    nonisolated static func bytes32(_ value: String) -> Data? { guard let data = hexData(value), data.count == 32 else { return nil }; return data }
    nonisolated static func hexData(_ value: String) -> Data? {
        guard value.count >= 2, value.hasPrefix("0x"), value == value.lowercased(), value.count % 2 == 0 else { return nil }
        var bytes = Data(); var index = value.index(value.startIndex, offsetBy: 2)
        while index < value.endIndex { let end = value.index(index, offsetBy: 2); guard let byte = UInt8(value[index..<end], radix: 16) else { return nil }; bytes.append(byte); index = end }
        return bytes
    }
}
