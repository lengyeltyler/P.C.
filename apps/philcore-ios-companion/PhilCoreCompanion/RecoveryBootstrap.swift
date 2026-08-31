import CryptoKit
import Foundation

struct RecoveryCodecError: Error, Equatable, CustomStringConvertible {
    let reason: String

    init(_ reason: String) {
        self.reason = reason
    }

    var description: String { reason }
}

/// Strict JSON value tree. Numbers keep their raw literal so integer-shaped
/// fields are never coerced, and objects reject duplicate keys at every level.
indirect enum RecoveryJSONValue: Equatable {
    case string(String)
    case number(String)
    case bool(Bool)
    case null
    case object([String: RecoveryJSONValue])
    case array([RecoveryJSONValue])

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    var numberLiteral: String? {
        if case .number(let value) = self { return value }
        return nil
    }

    var objectValue: [String: RecoveryJSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }
}

enum RecoveryJSON {
    static func parse(_ data: Data) throws -> RecoveryJSONValue {
        guard let text = String(data: data, encoding: .utf8) else {
            throw RecoveryCodecError("json_invalid_utf8")
        }
        var scanner = JSONScanner(Array(text.unicodeScalars))
        scanner.skipWhitespace()
        let value = try scanner.parseValue()
        scanner.skipWhitespace()
        guard scanner.isAtEnd else {
            throw RecoveryCodecError("json_trailing_content")
        }
        return value
    }

    private struct JSONScanner {
        private let scalars: [Unicode.Scalar]
        private var index: Int = 0
        private var depth: Int = 0

        init(_ scalars: [Unicode.Scalar]) {
            self.scalars = scalars
        }

        var isAtEnd: Bool { index >= scalars.count }

        private func peek() -> Unicode.Scalar? {
            index < scalars.count ? scalars[index] : nil
        }

        mutating func skipWhitespace() {
            while let scalar = peek(),
                  scalar == " " || scalar == "\t" || scalar == "\n" || scalar == "\r" {
                index += 1
            }
        }

        mutating func parseValue() throws -> RecoveryJSONValue {
            guard let scalar = peek() else {
                throw RecoveryCodecError("json_unexpected_end")
            }
            switch scalar {
            case "{": return try parseObject()
            case "[": return try parseArray()
            case "\"": return .string(try parseString())
            case "t", "f": return .bool(try parseBool())
            case "n":
                try expect("null")
                return .null
            default: return .number(try parseNumber())
            }
        }

        private mutating func parseObject() throws -> RecoveryJSONValue {
            depth += 1
            defer { depth -= 1 }
            guard depth <= 32 else { throw RecoveryCodecError("json_depth_exceeded") }
            index += 1
            var members: [String: RecoveryJSONValue] = [:]
            skipWhitespace()
            if peek() == "}" {
                index += 1
                return .object(members)
            }
            while true {
                skipWhitespace()
                guard peek() == "\"" else { throw RecoveryCodecError("json_object_key_invalid") }
                let key = try parseString()
                if members[key] != nil {
                    throw RecoveryCodecError("json_duplicate_key_\(key)")
                }
                skipWhitespace()
                guard peek() == ":" else { throw RecoveryCodecError("json_object_colon_missing") }
                index += 1
                skipWhitespace()
                members[key] = try parseValue()
                skipWhitespace()
                switch peek() {
                case ",": index += 1
                case "}":
                    index += 1
                    return .object(members)
                default: throw RecoveryCodecError("json_object_delimiter_invalid")
                }
            }
        }

        private mutating func parseArray() throws -> RecoveryJSONValue {
            depth += 1
            defer { depth -= 1 }
            guard depth <= 32 else { throw RecoveryCodecError("json_depth_exceeded") }
            index += 1
            var elements: [RecoveryJSONValue] = []
            skipWhitespace()
            if peek() == "]" {
                index += 1
                return .array(elements)
            }
            while true {
                skipWhitespace()
                elements.append(try parseValue())
                skipWhitespace()
                switch peek() {
                case ",": index += 1
                case "]":
                    index += 1
                    return .array(elements)
                default: throw RecoveryCodecError("json_array_delimiter_invalid")
                }
            }
        }

        private mutating func parseString() throws -> String {
            index += 1
            var out = String.UnicodeScalarView()
            while true {
                guard index < scalars.count else {
                    throw RecoveryCodecError("json_string_unterminated")
                }
                let scalar = scalars[index]
                index += 1
                if scalar == "\"" {
                    return String(out)
                }
                if scalar == "\\" {
                    out.append(try parseEscape())
                    continue
                }
                if scalar.value < 0x20 {
                    throw RecoveryCodecError("json_string_control_character")
                }
                out.append(scalar)
            }
        }

        private mutating func parseEscape() throws -> Unicode.Scalar {
            guard index < scalars.count else {
                throw RecoveryCodecError("json_string_unterminated")
            }
            let scalar = scalars[index]
            index += 1
            switch scalar {
            case "\"": return "\""
            case "\\": return "\\"
            case "/": return "/"
            case "b": return Unicode.Scalar(0x08)!
            case "f": return Unicode.Scalar(0x0c)!
            case "n": return "\n"
            case "r": return "\r"
            case "t": return "\t"
            case "u":
                let first = try parseHex4()
                if first >= 0xd800 && first <= 0xdbff {
                    guard index + 1 < scalars.count,
                          scalars[index] == "\\",
                          scalars[index + 1] == "u" else {
                        throw RecoveryCodecError("json_string_lone_surrogate")
                    }
                    index += 2
                    let second = try parseHex4()
                    guard second >= 0xdc00 && second <= 0xdfff else {
                        throw RecoveryCodecError("json_string_lone_surrogate")
                    }
                    let combined = 0x10000
                        + ((first - 0xd800) << 10)
                        + (second - 0xdc00)
                    guard let value = Unicode.Scalar(UInt32(combined)) else {
                        throw RecoveryCodecError("json_string_invalid_escape")
                    }
                    return value
                }
                guard first < 0xd800 || first > 0xdfff,
                      let value = Unicode.Scalar(UInt32(first)) else {
                    throw RecoveryCodecError("json_string_lone_surrogate")
                }
                return value
            default:
                throw RecoveryCodecError("json_string_invalid_escape")
            }
        }

        private mutating func parseHex4() throws -> Int {
            guard index + 4 <= scalars.count else {
                throw RecoveryCodecError("json_string_invalid_escape")
            }
            var value = 0
            for _ in 0..<4 {
                let scalar = scalars[index]
                index += 1
                guard let digit = hexDigit(scalar) else {
                    throw RecoveryCodecError("json_string_invalid_escape")
                }
                value = value * 16 + digit
            }
            return value
        }

        private func hexDigit(_ scalar: Unicode.Scalar) -> Int? {
            switch scalar {
            case "0"..."9": return Int(scalar.value - 0x30)
            case "a"..."f": return Int(scalar.value - 0x61) + 10
            case "A"..."F": return Int(scalar.value - 0x41) + 10
            default: return nil
            }
        }

        private mutating func parseBool() throws -> Bool {
            if peek() == "t" {
                try expect("true")
                return true
            }
            try expect("false")
            return false
        }

        private mutating func expect(_ literal: String) throws {
            for scalar in literal.unicodeScalars {
                guard index < scalars.count, scalars[index] == scalar else {
                    throw RecoveryCodecError("json_literal_invalid")
                }
                index += 1
            }
        }

        private mutating func parseNumber() throws -> String {
            let start = index
            if peek() == "-" { index += 1 }
            guard let first = peek() else { throw RecoveryCodecError("json_number_invalid") }
            if first == "0" {
                index += 1
            } else if first >= "1" && first <= "9" {
                while let scalar = peek(), scalar >= "0", scalar <= "9" { index += 1 }
            } else {
                throw RecoveryCodecError("json_number_invalid")
            }
            if peek() == "." {
                index += 1
                var digits = 0
                while let scalar = peek(), scalar >= "0", scalar <= "9" {
                    index += 1
                    digits += 1
                }
                guard digits > 0 else { throw RecoveryCodecError("json_number_invalid") }
            }
            if let scalar = peek(), scalar == "e" || scalar == "E" {
                index += 1
                if let sign = peek(), sign == "+" || sign == "-" { index += 1 }
                var digits = 0
                while let scalar = peek(), scalar >= "0", scalar <= "9" {
                    index += 1
                    digits += 1
                }
                guard digits > 0 else { throw RecoveryCodecError("json_number_invalid") }
            }
            guard index > start else { throw RecoveryCodecError("json_number_invalid") }
            return String(String.UnicodeScalarView(scalars[start..<index]))
        }
    }
}

/// Shared primitives used by both the bootstrap ticket layer and the canonical
/// request layer.
enum RecoveryCodec {
    static let zeroBytes32 = Data(repeating: 0, count: 32)

    static func hexString(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func hexBytes(_ value: String, expecting byteCount: Int?) throws -> Data {
        var text = Substring(value)
        if text.hasPrefix("0x") { text = text.dropFirst(2) }
        guard text.count % 2 == 0 else { throw RecoveryCodecError("hex_length_invalid") }
        var out = Data()
        out.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else {
                throw RecoveryCodecError("hex_digit_invalid")
            }
            out.append(byte)
            index = next
        }
        if let byteCount, out.count != byteCount {
            throw RecoveryCodecError("hex_length_invalid")
        }
        return out
    }

    static func isLowercaseHex(_ text: Substring) -> Bool {
        text.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// Mirrors `isHexString(value, 32)` plus the `toLowerCase()` normalisation
    /// applied by the TypeScript `requireBytes32` helper.
    static func requireBytes32(_ value: RecoveryJSONValue?, _ label: String) throws -> String {
        guard let text = value?.stringValue else {
            throw RecoveryCodecError("\(label)_must_be_bytes32")
        }
        return try requireBytes32(text, label)
    }

    static func requireBytes32(_ text: String, _ label: String) throws -> String {
        guard text.hasPrefix("0x"), text.count == 66 else {
            throw RecoveryCodecError("\(label)_must_be_bytes32")
        }
        let body = text.dropFirst(2)
        guard body.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
            throw RecoveryCodecError("\(label)_must_be_bytes32")
        }
        return "0x" + body.lowercased()
    }

    static func requireNonZeroBytes32(_ text: String, _ label: String) throws -> String {
        let normalized = try requireBytes32(text, label)
        if try hexBytes(normalized, expecting: 32) == zeroBytes32 {
            throw RecoveryCodecError("\(label)_must_be_nonzero")
        }
        return normalized
    }

    /// Canonical decimal integer string. A JSON number is only accepted when its
    /// literal is already a canonical non-negative integer, so nothing is ever
    /// coerced through a floating-point or exponent form. The canonical wire
    /// itself still has to carry these fields as strings, which the
    /// reserialize-equality gate enforces separately.
    static func requireCanonicalIntegerString(
        _ value: RecoveryJSONValue?,
        _ label: String
    ) throws -> String {
        switch value {
        case .string(let text): return try requireCanonicalIntegerString(text, label)
        case .number(let literal): return try requireCanonicalIntegerString(literal, label)
        default: throw RecoveryCodecError("\(label)_noncanonical_integer")
        }
    }

    static func requireCanonicalIntegerString(_ text: String, _ label: String) throws -> String {
        guard !text.isEmpty, text.count <= 78 else {
            throw RecoveryCodecError("\(label)_noncanonical_leading_zero_or_invalid")
        }
        guard text.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw RecoveryCodecError("\(label)_noncanonical_leading_zero_or_invalid")
        }
        if text.count > 1 && text.hasPrefix("0") {
            throw RecoveryCodecError("\(label)_noncanonical_leading_zero_or_invalid")
        }
        return text
    }

    static func requireUInt64(_ text: String, _ label: String) throws -> UInt64 {
        let canonical = try requireCanonicalIntegerString(text, label)
        guard let value = UInt64(canonical) else {
            throw RecoveryCodecError("\(label)_uint64_overflow")
        }
        return value
    }

    static func requireSafeString(
        _ value: RecoveryJSONValue?,
        _ label: String,
        maxLength: Int
    ) throws -> String {
        guard let text = value?.stringValue else {
            throw RecoveryCodecError("\(label)_invalid")
        }
        return try requireSafeString(text, label, maxLength: maxLength)
    }

    static func requireSafeString(
        _ text: String,
        _ label: String,
        maxLength: Int
    ) throws -> String {
        guard !text.isEmpty, text.count <= maxLength else {
            throw RecoveryCodecError("\(label)_invalid")
        }
        guard !text.contains("\n"), !text.contains("\r") else {
            throw RecoveryCodecError("\(label)_contains_newline_pin_rejected")
        }
        return text
    }

    /// Canonical (all lowercase) 20-byte address. Mixed-case input must carry a
    /// valid EIP-55 checksum, matching ethers' `getAddress`.
    static func requireCanonicalAddress(
        _ value: RecoveryJSONValue?,
        _ label: String
    ) throws -> String {
        guard let text = value?.stringValue else {
            throw RecoveryCodecError("\(label)_invalid_address")
        }
        return try requireCanonicalAddress(text, label)
    }

    static func requireCanonicalAddress(_ text: String, _ label: String) throws -> String {
        guard text.hasPrefix("0x"), text.count == 42 else {
            throw RecoveryCodecError("\(label)_invalid_address")
        }
        let body = text.dropFirst(2)
        guard body.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
            throw RecoveryCodecError("\(label)_invalid_address")
        }
        let lowercased = body.lowercased()
        let isSingleCase = body == Substring(lowercased) || body == Substring(body.uppercased())
        if !isSingleCase, checksumAddress(lowercased) != String(body) {
            throw RecoveryCodecError("\(label)_invalid_address")
        }
        return "0x" + lowercased
    }

    private static func checksumAddress(_ lowercaseBody: String) -> String {
        let digest = RecoveryKeccak.keccak256(utf8: lowercaseBody)
        let nibbles = hexString(digest)
        var out = ""
        for (offset, character) in lowercaseBody.enumerated() {
            let hashNibble = nibbles[nibbles.index(nibbles.startIndex, offsetBy: offset)]
            if character.isLetter, let value = hashNibble.hexDigitValue, value >= 8 {
                out.append(Character(String(character).uppercased()))
            } else {
                out.append(character)
            }
        }
        return out
    }

    static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict, canonical base64url: no padding, url alphabet only, and the
    /// decoded bytes must re-encode to exactly the supplied text.
    static func decodeBase64URLCanonical(_ value: String, exactLength: Int?) throws -> Data {
        guard !value.isEmpty, value.count <= 8192 else {
            throw RecoveryCodecError("recovery_bootstrap_base64url_invalid")
        }
        var accumulator: UInt32 = 0
        var bits = 0
        var out = Data()
        out.reserveCapacity(value.count * 3 / 4 + 1)
        for character in value.unicodeScalars {
            guard let sextet = base64URLValue(character) else {
                throw RecoveryCodecError("recovery_bootstrap_base64url_invalid")
            }
            accumulator = (accumulator << 6) | UInt32(sextet)
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((accumulator >> UInt32(bits)) & 0xff))
            }
        }
        guard encodeBase64URL(out) == value else {
            throw RecoveryCodecError("recovery_bootstrap_base64url_noncanonical")
        }
        if let exactLength, out.count != exactLength {
            throw RecoveryCodecError("recovery_bootstrap_value_length_invalid")
        }
        return out
    }

    private static func base64URLValue(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar {
        case "A"..."Z": return UInt8(scalar.value - 0x41)
        case "a"..."z": return UInt8(scalar.value - 0x61) + 26
        case "0"..."9": return UInt8(scalar.value - 0x30) + 52
        case "-": return 62
        case "_": return 63
        default: return nil
        }
    }

    /// Escapes exactly like `JSON.stringify` for the ASCII-safe values that
    /// appear on this wire, plus the general control-character rules.
    static func jsonStringLiteral(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0c}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }

    static func canonicalObject(_ members: [(String, String)]) -> String {
        let sorted = members.sorted { $0.0 < $1.0 }
        return "{" + sorted.map { "\(jsonStringLiteral($0.0)):\($0.1)" }.joined(separator: ",") + "}"
    }
}

/// Pure, non-networked PRB1 bootstrap codec. Nothing here opens a socket,
/// generates a nonce, or touches the Secure Enclave.
enum RecoveryBootstrap {
    static let magic = "PRB1"
    static let version: UInt8 = 0x01
    static let ticketByteCount = 148
    static let uriPrefix = "philcore-recovery:v1:"
    static let uriByteCount = 219
    static let requestEndpointPath = "/philcore/recovery/v1/request"
    static let completionEndpointPath = "/philcore/recovery/v1/complete"
    static let protocolVersion = 1
    static let maxRequestWireBytes = 16384
    static let maxTicketTTLSeconds: UInt64 = 300
    static let ticketClockSkewSeconds: UInt64 = 60
    static let requestHKDFInfo = "PHILCORE_NATIVE_RECOVERY_REQUEST_AES256_GCM_V1"
    static let requestAADDesktopToPhone = "DESKTOP_TO_IPHONE_RECOVERY_REQUEST_V1"

    private static let sessionIdOffset = 5
    private static let expiresAtOffset = 37
    private static let ipv4Offset = 45
    private static let portOffset = 49
    private static let publicKeyOffset = 51
    private static let requestHashOffset = 116

    struct Ticket: Equatable {
        let sessionId: Data
        let expiresAt: UInt64
        let ipv4: Data
        let port: UInt16
        let desktopEphemeralPublicKey: Data
        let requestHash: Data

        var magic: String { RecoveryBootstrap.magic }
        var version: UInt8 { RecoveryBootstrap.version }
        var ipv4Text: String { ipv4.map { String($0) }.joined(separator: ".") }
    }

    struct FetchInit: Equatable {
        let protocolVersion: Int
        let sessionId: String
        let phoneEphemeralPublicKey: String
        let fetchChallenge: String
    }

    struct EncryptedRequestDelivery: Equatable {
        let protocolVersion: Int
        let sessionId: String
        let nonce: String
        let ciphertext: String
        let tag: String
    }

    // MARK: - Base64url

    static func encodeBase64URL(_ data: Data) -> String {
        RecoveryCodec.encodeBase64URL(data)
    }

    static func decodeBase64URLCanonical(_ value: String, exactLength: Int?) throws -> Data {
        try RecoveryCodec.decodeBase64URLCanonical(value, exactLength: exactLength)
    }

    /// Alphabet/length checked but not required to be the canonical encoding of
    /// its own bytes. Only used where the transport layer is deliberately
    /// laxer than the bootstrap layer.
    static func decodeBase64URLLenient(_ value: String, exactLength: Int?) throws -> Data {
        guard !value.isEmpty, value.count <= 8192 else {
            throw RecoveryCodecError("recovery_bootstrap_base64url_invalid")
        }
        do {
            return try RecoveryCodec.decodeBase64URLCanonical(value, exactLength: exactLength)
        } catch let error as RecoveryCodecError
            where error.reason == "recovery_bootstrap_base64url_noncanonical" {
            var accumulator: UInt32 = 0
            var bits = 0
            var out = Data()
            for scalar in value.unicodeScalars {
                guard let sextet = base64URLSextet(scalar) else {
                    throw RecoveryCodecError("recovery_bootstrap_base64url_invalid")
                }
                accumulator = (accumulator << 6) | UInt32(sextet)
                bits += 6
                if bits >= 8 {
                    bits -= 8
                    out.append(UInt8((accumulator >> UInt32(bits)) & 0xff))
                }
            }
            if let exactLength, out.count != exactLength {
                throw RecoveryCodecError("recovery_bootstrap_value_length_invalid")
            }
            return out
        }
    }

    private static func base64URLSextet(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar {
        case "A"..."Z": return UInt8(scalar.value - 0x41)
        case "a"..."z": return UInt8(scalar.value - 0x61) + 26
        case "0"..."9": return UInt8(scalar.value - 0x30) + 52
        case "-": return 62
        case "_": return 63
        default: return nil
        }
    }

    // MARK: - Strict IPv4

    static func parseIPv4(text: String) throws -> Data {
        guard !text.contains("\n"), !text.contains("\r") else {
            throw RecoveryCodecError("ipv4_address_invalid")
        }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw RecoveryCodecError("ipv4_address_invalid") }
        var octets = [UInt8]()
        for part in parts {
            guard !part.isEmpty, part.count <= 3,
                  part.allSatisfy({ $0.isASCII && $0.isNumber }) else {
                throw RecoveryCodecError("ipv4_address_invalid")
            }
            if part.count > 1 && part.hasPrefix("0") {
                throw RecoveryCodecError("ipv4_address_invalid")
            }
            guard let value = UInt16(part), value <= 255 else {
                throw RecoveryCodecError("ipv4_address_invalid")
            }
            octets.append(UInt8(value))
        }
        guard isRfc1918(octets) else { throw RecoveryCodecError("ipv4_rfc1918_required") }
        return Data(octets)
    }

    static func parseIPv4(bytes: Data) throws -> Data {
        guard bytes.count == 4 else { throw RecoveryCodecError("ipv4_length_invalid") }
        guard isRfc1918(Array(bytes)) else {
            throw RecoveryCodecError("ipv4_rfc1918_required")
        }
        return bytes
    }

    private static func isRfc1918(_ octets: [UInt8]) -> Bool {
        guard octets.count == 4 else { return false }
        if octets[0] == 0 || octets[0] == 127 { return false }
        if octets[0] >= 224 { return false }
        if octets[0] == 169 && octets[1] == 254 { return false }
        if octets[0] == 10 { return true }
        if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 { return true }
        return octets[0] == 192 && octets[1] == 168
    }

    private static func requirePort(_ port: Int) throws -> UInt16 {
        guard port >= 1024, port <= 65535 else {
            throw RecoveryCodecError("port_out_of_range")
        }
        return UInt16(port)
    }

    // MARK: - P-256 public keys

    @discardableResult
    static func validateUncompressedP256PublicKey(
        _ value: String,
        label: String
    ) throws -> Data {
        guard !value.contains("\n"), !value.contains("\r") else {
            throw RecoveryCodecError("\(label)_contains_newline_pin_rejected")
        }
        let bytes: Data
        do {
            bytes = try RecoveryCodec.decodeBase64URLCanonical(value, exactLength: 65)
        } catch {
            throw RecoveryCodecError("\(label)_public_key_length_invalid")
        }
        guard bytes.first == 0x04 else {
            throw RecoveryCodecError("\(label)_public_key_uncompressed_prefix_invalid")
        }
        guard (try? P256.KeyAgreement.PublicKey(x963Representation: bytes)) != nil else {
            throw RecoveryCodecError("\(label)_curve_point_invalid")
        }
        return bytes
    }

    private static func requireUncompressedP256Raw(_ bytes: Data, label: String) throws -> Data {
        guard bytes.count == 65 else {
            throw RecoveryCodecError("\(label)_public_key_length_invalid")
        }
        return try validateUncompressedP256PublicKey(
            RecoveryCodec.encodeBase64URL(bytes),
            label: label
        )
    }

    // MARK: - PRB1 ticket

    static func encodeTicket(
        sessionId: Data,
        expiresAt: UInt64,
        ipv4Text: String,
        port: Int,
        desktopEphemeralPublicKeyBase64URL: String,
        requestHash: Data
    ) throws -> Data {
        guard sessionId.count == 32 else {
            throw RecoveryCodecError("sessionId_length_invalid")
        }
        guard sessionId != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("sessionId_must_be_nonzero")
        }
        guard requestHash.count == 32 else {
            throw RecoveryCodecError("requestHash_length_invalid")
        }
        guard requestHash != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("requestHash_must_be_nonzero")
        }
        let ipv4 = try parseIPv4(text: ipv4Text)
        let portValue = try requirePort(port)
        let publicKey = try validateUncompressedP256PublicKey(
            desktopEphemeralPublicKeyBase64URL,
            label: "desktop_ephemeral"
        )

        var out = Data(repeating: 0, count: ticketByteCount)
        out.replaceSubrange(0..<4, with: Data(magic.utf8))
        out[4] = version
        out.replaceSubrange(sessionIdOffset..<(sessionIdOffset + 32), with: sessionId)
        for offset in 0..<8 {
            out[expiresAtOffset + offset] = UInt8((expiresAt >> (8 * UInt64(7 - offset))) & 0xff)
        }
        out.replaceSubrange(ipv4Offset..<(ipv4Offset + 4), with: ipv4)
        out[portOffset] = UInt8(portValue >> 8)
        out[portOffset + 1] = UInt8(portValue & 0xff)
        out.replaceSubrange(publicKeyOffset..<(publicKeyOffset + 65), with: publicKey)
        out.replaceSubrange(requestHashOffset..<(requestHashOffset + 32), with: requestHash)
        return out
    }

    static func encodeTicket(_ ticket: Ticket) throws -> Data {
        try encodeTicket(
            sessionId: ticket.sessionId,
            expiresAt: ticket.expiresAt,
            ipv4Text: ticket.ipv4Text,
            port: Int(ticket.port),
            desktopEphemeralPublicKeyBase64URL:
                RecoveryCodec.encodeBase64URL(ticket.desktopEphemeralPublicKey),
            requestHash: ticket.requestHash
        )
    }

    static func decodeTicket(_ bytes: Data) throws -> Ticket {
        guard bytes.count == ticketByteCount else {
            throw RecoveryCodecError(
                bytes.count < ticketByteCount
                    ? "prb1_ticket_truncated"
                    : "prb1_ticket_trailing_bytes"
            )
        }
        let raw = Array(bytes)
        guard String(decoding: raw[0..<4], as: UTF8.self) == magic else {
            throw RecoveryCodecError("prb1_magic_invalid")
        }
        guard raw[4] == version else {
            throw RecoveryCodecError("prb1_version_invalid")
        }
        let sessionId = Data(raw[sessionIdOffset..<(sessionIdOffset + 32)])
        guard sessionId != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("sessionId_must_be_nonzero")
        }
        var expiresAt: UInt64 = 0
        for offset in 0..<8 {
            expiresAt = (expiresAt << 8) | UInt64(raw[expiresAtOffset + offset])
        }
        let ipv4 = try parseIPv4(bytes: Data(raw[ipv4Offset..<(ipv4Offset + 4)]))
        let port = (Int(raw[portOffset]) << 8) | Int(raw[portOffset + 1])
        let portValue = try requirePort(port)
        let publicKey = try requireUncompressedP256Raw(
            Data(raw[publicKeyOffset..<(publicKeyOffset + 65)]),
            label: "desktop_ephemeral"
        )
        let requestHash = Data(raw[requestHashOffset..<(requestHashOffset + 32)])
        guard requestHash != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("requestHash_must_be_nonzero")
        }
        return Ticket(
            sessionId: sessionId,
            expiresAt: expiresAt,
            ipv4: ipv4,
            port: portValue,
            desktopEphemeralPublicKey: publicKey,
            requestHash: requestHash
        )
    }

    // MARK: - Opaque URI (no URL/URLComponents anywhere)

    static func formatURI(ticketBytes: Data) throws -> String {
        guard ticketBytes.count == ticketByteCount else {
            throw RecoveryCodecError("prb1_ticket_length_invalid")
        }
        _ = try decodeTicket(ticketBytes)
        let encoded = RecoveryCodec.encodeBase64URL(ticketBytes)
        guard !encoded.contains("=") else {
            throw RecoveryCodecError("prb1_uri_padding_forbidden")
        }
        let uri = uriPrefix + encoded
        guard uri.utf8.count == uriByteCount else {
            throw RecoveryCodecError("prb1_uri_length_invalid")
        }
        return uri
    }

    static func parseURI(_ uri: String) throws -> Data {
        for scalar in uri.unicodeScalars where scalar.value <= 0x20 || scalar.value == 0x7f {
            throw RecoveryCodecError("prb1_uri_whitespace_forbidden")
        }
        guard !uri.contains("?"), !uri.contains("#") else {
            throw RecoveryCodecError("prb1_uri_query_or_fragment_forbidden")
        }
        guard uri.hasPrefix(uriPrefix) else {
            throw RecoveryCodecError("prb1_uri_prefix_invalid")
        }
        guard uri.utf8.count == uriByteCount else {
            throw RecoveryCodecError("prb1_uri_length_invalid")
        }
        let payload = String(uri.dropFirst(uriPrefix.count))
        guard !payload.contains("=") else {
            throw RecoveryCodecError("prb1_uri_padding_forbidden")
        }
        guard payload.unicodeScalars.allSatisfy({ base64URLSextet($0) != nil }) else {
            throw RecoveryCodecError("prb1_uri_base64url_invalid")
        }
        let decoded: Data
        do {
            decoded = try RecoveryCodec.decodeBase64URLCanonical(payload, exactLength: nil)
        } catch {
            throw RecoveryCodecError("prb1_uri_base64url_noncanonical")
        }
        guard decoded.count == ticketByteCount else {
            throw RecoveryCodecError("prb1_uri_ticket_length_invalid")
        }
        _ = try decodeTicket(decoded)
        return decoded
    }

    // MARK: - Ticket policy (clock is always injected)

    static func validateTicketPolicy(
        ticket: Ticket,
        nowSeconds: UInt64,
        boundRequestExpiresAtMilliseconds: String?
    ) throws {
        guard ticket.sessionId.count == 32, ticket.sessionId != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("sessionId_must_be_nonzero")
        }
        guard ticket.requestHash.count == 32, ticket.requestHash != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("requestHash_must_be_nonzero")
        }
        _ = try parseIPv4(bytes: ticket.ipv4)
        _ = try requirePort(Int(ticket.port))
        _ = try requireUncompressedP256Raw(
            ticket.desktopEphemeralPublicKey,
            label: "desktop_ephemeral"
        )

        guard nowSeconds < ticket.expiresAt else {
            throw RecoveryCodecError("prb1_ticket_expired")
        }
        let maxExpiresAt = nowSeconds + maxTicketTTLSeconds + ticketClockSkewSeconds
        guard ticket.expiresAt <= maxExpiresAt else {
            throw RecoveryCodecError("prb1_ticket_expiry_exceeds_ttl_skew")
        }

        if let boundRequestExpiresAtMilliseconds {
            let bound = try RecoveryCodec.requireUInt64(
                boundRequestExpiresAtMilliseconds,
                "boundRequestExpiresAtMs"
            )
            let boundSeconds = bound / 1000
            guard ticket.expiresAt <= boundSeconds else {
                throw RecoveryCodecError("prb1_ticket_expiry_outlives_bound_request")
            }
        }
    }

    static func requestEndpoint(ticket: Ticket) throws -> String {
        try endpoint(ticket: ticket, path: requestEndpointPath)
    }

    static func completionEndpoint(ticket: Ticket) throws -> String {
        try endpoint(ticket: ticket, path: completionEndpointPath)
    }

    private static func endpoint(ticket: Ticket, path: String) throws -> String {
        let ipv4 = try parseIPv4(bytes: ticket.ipv4)
        let port = try requirePort(Int(ticket.port))
        let text = ipv4.map { String($0) }.joined(separator: ".")
        return "http://\(text):\(port)\(path)"
    }

    // MARK: - Fetch init

    static func decodeFetchChallenge(_ value: String) throws -> Data {
        if value.hasPrefix("0x") {
            return try RecoveryCodec.hexBytes(value, expecting: 32)
        }
        return try RecoveryCodec.decodeBase64URLCanonical(value, exactLength: 32)
    }

    static func buildFetchInit(
        sessionId: String,
        phoneEphemeralPublicKey: String,
        fetchChallenge: Data
    ) throws -> FetchInit {
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        let phoneKey = try RecoveryCodec.requireSafeString(
            phoneEphemeralPublicKey,
            "phoneEphemeralPublicKey",
            maxLength: 256
        )
        try validateUncompressedP256PublicKey(phoneKey, label: "phone_ephemeral")
        guard fetchChallenge.count == 32 else {
            throw RecoveryCodecError("fetchChallenge_length_invalid")
        }
        return FetchInit(
            protocolVersion: protocolVersion,
            sessionId: normalizedSession,
            phoneEphemeralPublicKey: phoneKey,
            fetchChallenge: RecoveryCodec.encodeBase64URL(fetchChallenge)
        )
    }

    static func validateFetchInit(jsonBytes: Data) throws -> FetchInit {
        let parsed = try RecoveryJSON.parse(jsonBytes)
        guard let message = parsed.objectValue else {
            throw RecoveryCodecError("fetch_init_schema_invalid")
        }
        let allowed: Set<String> = [
            "protocolVersion", "sessionId", "phoneEphemeralPublicKey", "fetchChallenge"
        ]
        for key in message.keys where !allowed.contains(key) {
            throw RecoveryCodecError("fetch_init_unexpected_field")
        }
        for key in allowed.sorted() where message[key] == nil {
            throw RecoveryCodecError("fetch_init_missing_field_\(key)")
        }
        guard message["protocolVersion"]?.numberLiteral == String(protocolVersion) else {
            throw RecoveryCodecError("fetch_init_protocol_version_invalid")
        }
        let challengeText = try RecoveryCodec.requireSafeString(
            message["fetchChallenge"],
            "fetchChallenge",
            maxLength: 128
        )
        return try buildFetchInit(
            sessionId: try RecoveryCodec.requireBytes32(message["sessionId"], "sessionId"),
            phoneEphemeralPublicKey: try RecoveryCodec.requireSafeString(
                message["phoneEphemeralPublicKey"],
                "phoneEphemeralPublicKey",
                maxLength: 256
            ),
            fetchChallenge: try decodeFetchChallenge(challengeText)
        )
    }

    static func serializeFetchInit(_ value: FetchInit) throws -> Data {
        let text = RecoveryCodec.canonicalObject([
            ("protocolVersion", String(value.protocolVersion)),
            ("sessionId", RecoveryCodec.jsonStringLiteral(value.sessionId)),
            ("phoneEphemeralPublicKey",
             RecoveryCodec.jsonStringLiteral(value.phoneEphemeralPublicKey)),
            ("fetchChallenge", RecoveryCodec.jsonStringLiteral(value.fetchChallenge))
        ])
        return Data(text.utf8)
    }

    // MARK: - Encrypted request delivery

    static func validateEncryptedRequestDelivery(
        jsonBytes: Data
    ) throws -> EncryptedRequestDelivery {
        let parsed = try RecoveryJSON.parse(jsonBytes)
        guard let message = parsed.objectValue else {
            throw RecoveryCodecError("request_delivery_schema_invalid")
        }
        let allowed: Set<String> = [
            "protocolVersion", "sessionId", "nonce", "ciphertext", "tag"
        ]
        for key in message.keys where !allowed.contains(key) {
            throw RecoveryCodecError("request_delivery_unexpected_field")
        }
        for key in allowed.sorted() where message[key] == nil {
            throw RecoveryCodecError("request_delivery_missing_field_\(key)")
        }
        guard message["protocolVersion"]?.numberLiteral == String(protocolVersion) else {
            throw RecoveryCodecError("request_delivery_protocol_version_invalid")
        }
        let sessionId = try RecoveryCodec.requireBytes32(message["sessionId"], "sessionId")
        let nonce = try RecoveryCodec.requireSafeString(message["nonce"], "nonce", maxLength: 32)
        _ = try RecoveryCodec.decodeBase64URLCanonical(nonce, exactLength: 12)
        let ciphertext = try RecoveryCodec.requireSafeString(
            message["ciphertext"],
            "ciphertext",
            maxLength: 24576
        )
        _ = try RecoveryCodec.decodeBase64URLCanonical(ciphertext, exactLength: nil)
        let tag = try RecoveryCodec.requireSafeString(message["tag"], "tag", maxLength: 64)
        _ = try RecoveryCodec.decodeBase64URLCanonical(tag, exactLength: 16)
        return EncryptedRequestDelivery(
            protocolVersion: protocolVersion,
            sessionId: sessionId,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }

    static func deriveRequestAesKey(sharedSecret: Data, requestHash: Data) throws -> Data {
        guard sharedSecret.count == 32 else {
            throw RecoveryCodecError("recovery_request_shared_secret_length_invalid")
        }
        guard requestHash.count == 32 else {
            throw RecoveryCodecError("recovery_request_hash_length_invalid")
        }
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: requestHash,
            info: Data(requestHKDFInfo.utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    static func buildRequestDeliveryAad(
        sessionId: String,
        requestHash: Data,
        phoneEphemeralPublicKey: String,
        fetchChallenge: Data
    ) throws -> Data {
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        guard requestHash.count == 32, requestHash != RecoveryCodec.zeroBytes32 else {
            throw RecoveryCodecError("requestHash_must_be_nonzero")
        }
        guard fetchChallenge.count == 32 else {
            throw RecoveryCodecError("fetchChallenge_length_invalid")
        }
        let phoneRaw = try validateUncompressedP256PublicKey(
            phoneEphemeralPublicKey,
            label: "phone_ephemeral"
        )
        let fingerprint = RecoveryCodec.hexString(Data(SHA256.hash(data: phoneRaw)))
        let joined = [
            requestAADDesktopToPhone,
            normalizedSession,
            RecoveryCodec.hexString(requestHash),
            fingerprint,
            RecoveryCodec.hexString(fetchChallenge)
        ].joined(separator: "|")
        return Data(joined.utf8)
    }

    static func decryptRequestDelivery(
        message: EncryptedRequestDelivery,
        key: Data,
        sessionId: String,
        requestHash: Data,
        phoneEphemeralPublicKey: String,
        fetchChallenge: Data
    ) throws -> Data {
        guard message.protocolVersion == protocolVersion else {
            throw RecoveryCodecError("request_delivery_protocol_version_invalid")
        }
        let normalizedSession = try RecoveryCodec.requireBytes32(sessionId, "sessionId")
        guard try RecoveryCodec.requireBytes32(message.sessionId, "sessionId")
            == normalizedSession else {
            throw RecoveryCodecError("request_delivery_session_mismatch")
        }
        guard key.count == 32 else {
            throw RecoveryCodecError("recovery_request_aes_key_invalid")
        }
        let aad = try buildRequestDeliveryAad(
            sessionId: normalizedSession,
            requestHash: requestHash,
            phoneEphemeralPublicKey: phoneEphemeralPublicKey,
            fetchChallenge: fetchChallenge
        )
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
            return try AES.GCM.open(
                sealed,
                using: SymmetricKey(data: key),
                authenticating: aad
            )
        } catch {
            throw RecoveryCodecError("request_delivery_authentication_failed")
        }
    }
}
