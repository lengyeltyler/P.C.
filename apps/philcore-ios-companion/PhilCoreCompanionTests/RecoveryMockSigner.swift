import CryptoKit
import Foundation
import XCTest
@testable import PhilCoreCompanion

/// XCTest-only Role 1 signer double.
///
/// This file is a member of the unit-test target only. It imports XCTest so it
/// can never be linked into the shipping app, and a dedicated boundary test
/// scans the built app binary to prove the symbol is absent.
///
/// A fresh P-256 signing key is generated per instance, so no private scalar is
/// ever committed to the repository and no key is shared between tests.
final class RecoveryMockSigner: RecoverySigner, @unchecked Sendable {
    /// P-256 group order, used only to synthesise a deliberately high-S
    /// signature so the actor's low-S normalisation can be observed.
    static let curveOrder = Data([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    ])

    enum Behavior: Sendable {
        /// Normal low-S DER signature over the supplied digest.
        case sign
        /// Deliberately high-S DER, to prove the actor normalises it.
        case signHighS
        /// Signer refuses.
        case failure
        /// Structurally invalid DER.
        case malformedDer
        /// Well-formed DER produced by a different key.
        case foreignKey
        /// Suspends before returning, so replacement races can be driven.
        case delayed(nanoseconds: UInt64)
    }

    private let lock = NSLock()
    private let privateKey: P256.Signing.PrivateKey
    private var behavior: Behavior
    private var callCountStorage = 0
    private var lastDigestStorage: Data?
    private var onSign: (@Sendable () async -> Void)?

    init(behavior: Behavior = .sign) {
        self.privateKey = P256.Signing.PrivateKey()
        self.behavior = behavior
    }

    var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    /// Thread-safe. Any pre-approval failure must leave this at zero.
    var callCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return callCountStorage
    }

    /// Thread-safe capture of the exact bytes handed to the signer.
    var lastDigest: Data? {
        lock.lock()
        defer { lock.unlock() }
        return lastDigestStorage
    }

    func setBehavior(_ value: Behavior) {
        lock.lock()
        behavior = value
        lock.unlock()
    }

    /// Hook used by the replacement/late-result races to interleave actor work
    /// while the signer is suspended.
    func setOnSign(_ handler: (@Sendable () async -> Void)?) {
        lock.lock()
        onSign = handler
        lock.unlock()
    }

    func signRecoveryDigest(_ digest: Data) async throws -> Data {
        lock.lock()
        callCountStorage += 1
        lastDigestStorage = digest
        let currentBehavior = behavior
        let handler = onSign
        lock.unlock()

        if let handler { await handler() }

        switch currentBehavior {
        case .sign:
            return try privateKey.signature(for: digest).derRepresentation
        case .signHighS:
            return try Self.highSVariant(
                of: try privateKey.signature(for: digest).derRepresentation
            )
        case .failure:
            throw RecoveryCodecError("mock_signer_refused")
        case .malformedDer:
            return Data([0x30, 0x02, 0x02, 0x00])
        case .foreignKey:
            return try P256.Signing.PrivateKey().signature(for: digest).derRepresentation
        case .delayed(let nanoseconds):
            try? await Task.sleep(nanoseconds: nanoseconds)
            return try privateKey.signature(for: digest).derRepresentation
        }
    }

    /// Verifies a normalised DER signature against this instance's public key.
    /// Accepts either S parity because low-S normalisation rewrites the value.
    func verifyNormalized(der: Data, digest: Data) throws -> Bool {
        let parsed = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(der)
        let r = try RecoveryCodec.hexBytes(parsed.r, expecting: 32)
        let s = try RecoveryCodec.hexBytes(parsed.s, expecting: 32)
        let flipped = Self.subtract(Self.curveOrder, s)
        for candidate in [s, flipped] {
            let raw = r + candidate
            if let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw),
               privateKey.publicKey.isValidSignature(signature, for: digest) {
                return true
            }
        }
        return false
    }

    static func isLowS(der: Data) throws -> Bool {
        let parsed = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(der)
        let s = try RecoveryCodec.hexBytes(parsed.s, expecting: 32)
        return compare(s, halfOrder) <= 0
    }

    // MARK: - Big-endian helpers

    static let halfOrder = shiftRightOne(curveOrder)

    private static func highSVariant(of der: Data) throws -> Data {
        let parsed = try RecoveryCanonicalRequest.parseDerEcdsaP256Signature(der)
        let r = try RecoveryCodec.hexBytes(parsed.r, expecting: 32)
        var s = try RecoveryCodec.hexBytes(parsed.s, expecting: 32)
        if compare(s, halfOrder) <= 0 {
            s = subtract(curveOrder, s)
        }
        return try RecoveryApprovalCodec.encodeDerSignature(r: r, s: s)
    }

    static func compare(_ left: Data, _ right: Data) -> Int {
        let a = Array(left)
        let b = Array(right)
        for index in 0..<min(a.count, b.count) where a[index] != b[index] {
            return a[index] < b[index] ? -1 : 1
        }
        return 0
    }

    static func subtract(_ left: Data, _ right: Data) -> Data {
        let a = Array(left)
        let b = Array(right)
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            let difference = Int(a[index]) - Int(b[index]) - borrow
            if difference < 0 {
                out[index] = UInt8(difference + 256)
                borrow = 1
            } else {
                out[index] = UInt8(difference)
                borrow = 0
            }
        }
        return Data(out)
    }

    private static func shiftRightOne(_ data: Data) -> Data {
        var out = [UInt8](repeating: 0, count: data.count)
        var carry: UInt8 = 0
        for (index, byte) in data.enumerated() {
            out[index] = (byte >> 1) | (carry << 7)
            carry = byte & 1
        }
        return Data(out)
    }
}
