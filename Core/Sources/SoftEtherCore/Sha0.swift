// SHA-0, ported from kittoku/mvc cipher/sha0.kt (needed for SoftEther's
// secure-password hashing; the server rejects plain SHA-1 here).

import Foundation

private func f(_ t: Int, _ B: UInt32, _ C: UInt32, _ D: UInt32) -> UInt32 {
    switch t {
    case 0 ... 19: return (B & C) | (~B & D)
    case 20 ... 39, 60 ... 79: return B ^ C ^ D
    case 40 ... 59: return (B & C) | (B & D) | (C & D)
    default: preconditionFailure("unreachable")
    }
}

private func K(_ t: Int) -> UInt32 {
    switch t {
    case 0 ... 19: return 0x5A827999
    case 20 ... 39: return 0x6ED9EBA1
    case 40 ... 59: return 0x8F1BBCDC
    case 60 ... 79: return 0xCA62C1D6
    default: preconditionFailure("unreachable")
    }
}

private func S(_ n: UInt32, _ x: UInt32) -> UInt32 {
    (x << n) | (x >> (32 - n))
}

public func hashSha0(_ input: [UInt8]) -> [UInt8] {
    let blockSize = (input.count + 9) / 64 + 1
    let paddedSize = blockSize * 64
    var padded = [UInt8](repeating: 0, count: paddedSize)
    padded.replaceSubrange(0 ..< input.count, with: input)
    padded[input.count] = 0b1000_0000
    let bitLength = UInt64(input.count) * 8
    withUnsafeBytes(of: bitLength.bigEndian) { raw in
        padded.replaceSubrange((paddedSize - 8) ..< paddedSize, with: Array(raw))
    }

    var W = [UInt32](repeating: 0, count: 80)
    var H0: UInt32 = 0x67452301
    var H1: UInt32 = 0xEFCDAB89
    var H2: UInt32 = 0x98BADCFE
    var H3: UInt32 = 0x10325476
    var H4: UInt32 = 0xC3D2E1F0

    var offset = 0
    for _ in 0 ..< blockSize {
        for i in 0 ... 15 {
            let base = offset + i * 4
            W[i] = UInt32(padded[base]) << 24 | UInt32(padded[base + 1]) << 16
                | UInt32(padded[base + 2]) << 8 | UInt32(padded[base + 3])
        }

        for i in 16 ... 79 {
            W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]
        }

        var A = H0, B = H1, C = H2, D = H3, E = H4

        for t in 0 ... 79 {
            let temp = S(5, A) &+ f(t, B, C, D) &+ E &+ W[t] &+ K(t)
            E = D
            D = C
            C = S(30, B)
            B = A
            A = temp
        }

        H0 = H0 &+ A
        H1 = H1 &+ B
        H2 = H2 &+ C
        H3 = H3 &+ D
        H4 = H4 &+ E
        offset += 64
    }

    var out = [UInt8]()
    out.reserveCapacity(20)
    for h in [H0, H1, H2, H3, H4] {
        withUnsafeBytes(of: h.bigEndian) { raw in out.append(contentsOf: Array(raw)) }
    }
    return out
}
