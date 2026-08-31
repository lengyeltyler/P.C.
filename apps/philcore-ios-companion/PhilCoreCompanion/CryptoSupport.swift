import CryptoKit
import Foundation

enum CryptoSupport {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func fingerprint(_ data: Data) -> String {
        let hex = sha256(data).map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: 24, by: 4)
            .map { start in
                let a = hex.index(hex.startIndex, offsetBy: start)
                let b = hex.index(a, offsetBy: 4)
                return String(hex[a..<b])
            }
            .joined(separator: " ")
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decodeBase64URL(_ value: String) -> Data? {
        var normalized = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        return Data(base64Encoded: normalized)
    }
}
