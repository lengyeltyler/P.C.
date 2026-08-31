import Foundation

/// Ethereum Keccak-256 (original Keccak padding `0x01`), not FIPS-202 SHA3-256.
///
/// Pure Swift with byte-wise little-endian lane packing so it makes no
/// assumptions about host endianness or pointer alignment.
enum RecoveryKeccak {
    private static let rate = 136
    private static let laneCount = 25

    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082,
        0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808b, 0x0000_0000_8000_0001,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008a, 0x0000_0000_0000_0088,
        0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
        0x0000_0000_8000_808b, 0x8000_0000_0000_008b,
        0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
        0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080,
        0x0000_0000_8000_0001, 0x8000_0000_8000_8008
    ]

    private static let rotationOffsets: [Int] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    ]

    private static let piLane: [Int] = {
        // Destination lane for each source lane under rho-pi.
        var destination = [Int](repeating: 0, count: laneCount)
        for x in 0..<5 {
            for y in 0..<5 {
                destination[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5)
            }
        }
        return destination
    }()

    static func keccak256(_ data: Data) -> Data {
        var state = [UInt64](repeating: 0, count: laneCount)
        var block = [UInt8](repeating: 0, count: rate)
        var filled = 0

        for byte in data {
            block[filled] = byte
            filled += 1
            if filled == rate {
                absorb(block, into: &state)
                filled = 0
            }
        }

        for index in filled..<rate {
            block[index] = 0
        }
        block[filled] ^= 0x01
        block[rate - 1] ^= 0x80
        absorb(block, into: &state)

        var digest = Data(capacity: 32)
        for lane in 0..<4 {
            let value = state[lane]
            for shift in 0..<8 {
                digest.append(UInt8((value >> (8 * UInt64(shift))) & 0xff))
            }
        }
        return digest
    }

    static func keccak256(utf8 text: String) -> Data {
        keccak256(Data(text.utf8))
    }

    private static func absorb(_ block: [UInt8], into state: inout [UInt64]) {
        for lane in 0..<(rate / 8) {
            var value: UInt64 = 0
            for shift in 0..<8 {
                value |= UInt64(block[lane * 8 + shift]) << (8 * UInt64(shift))
            }
            state[lane] ^= value
        }
        permute(&state)
    }

    private static func permute(_ state: inout [UInt64]) {
        var lanes = state
        for round in 0..<24 {
            // Theta
            var parity = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 {
                parity[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10]
                    ^ lanes[x + 15] ^ lanes[x + 20]
            }
            for x in 0..<5 {
                let delta = parity[(x + 4) % 5] ^ rotateLeft(parity[(x + 1) % 5], 1)
                for y in 0..<5 {
                    lanes[x + 5 * y] ^= delta
                }
            }

            // Rho and pi
            var permuted = [UInt64](repeating: 0, count: laneCount)
            for index in 0..<laneCount {
                permuted[piLane[index]] = rotateLeft(lanes[index], rotationOffsets[index])
            }

            // Chi
            for y in 0..<5 {
                let row = 5 * y
                let a = permuted[row]
                let b = permuted[row + 1]
                let c = permuted[row + 2]
                let d = permuted[row + 3]
                let e = permuted[row + 4]
                lanes[row] = a ^ (~b & c)
                lanes[row + 1] = b ^ (~c & d)
                lanes[row + 2] = c ^ (~d & e)
                lanes[row + 3] = d ^ (~e & a)
                lanes[row + 4] = e ^ (~a & b)
            }

            // Iota
            lanes[0] ^= roundConstants[round]
        }
        state = lanes
    }

    private static func rotateLeft(_ value: UInt64, _ amount: Int) -> UInt64 {
        let shift = UInt64(amount % 64)
        if shift == 0 { return value }
        return (value << shift) | (value >> (64 - shift))
    }
}