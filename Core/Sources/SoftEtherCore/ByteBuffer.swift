// Port of the java.nio.ByteBuffer semantics used by the mvc protocol layer.
// Big-endian for all multi-byte integers. Reference semantics: the terminal
// code shares one buffer between the read loop and the parsers.

import Foundation

public final class ByteBuffer {
    public internal(set) var bytes: [UInt8]
    public var position: Int
    public var limit: Int

    public var capacity: Int { bytes.count }
    public var remaining: Int { limit - position }
    public var capacityAfterPayload: Int { capacity - limit }
    public var hasRemaining: Bool { remaining > 0 }

    public init(capacity: Int) {
        bytes = [UInt8](repeating: 0, count: capacity)
        position = 0
        limit = capacity
    }

    public static func wrap(_ array: [UInt8]) -> ByteBuffer {
        let buffer = ByteBuffer(capacity: array.count)
        buffer.bytes = array
        buffer.limit = array.count
        return buffer
    }

    // MARK: bulk access

    @discardableResult
    public func get(_ count: Int) -> [UInt8] {
        precondition(count <= remaining)
        let result = Array(bytes[position ..< position + count])
        position += count
        return result
    }

    public func get(_ destination: inout [UInt8], _ count: Int) {
        precondition(count <= remaining && count <= destination.count)
        for i in 0 ..< count { destination[i] = bytes[position + i] }
        position += count
    }

    public func put(_ array: [UInt8]) {
        precondition(position + array.count <= limit)
        bytes.replaceSubrange(position ..< position + array.count, with: array)
        position += array.count
    }

    public func put(_ array: [UInt8], from: Int, length: Int) {
        precondition(position + length <= limit)
        bytes.replaceSubrange(position ..< position + length, with: array[from ..< from + length])
        position += length
    }

    // MARK: u8

    @discardableResult public func getU8() -> UInt8 {
        let v = bytes[position]; position += 1; return v
    }

    public func putU8(_ v: UInt8) {
        bytes[position] = v; position += 1
    }

    public func probeU8(_ diff: Int) -> UInt8 { bytes[position + diff] }

    // MARK: u16 big-endian

    @discardableResult public func getU16() -> UInt16 {
        let v = UInt16(bytes[position]) << 8 | UInt16(bytes[position + 1])
        position += 2
        return v
    }

    public func putU16(_ v: UInt16) {
        bytes[position] = UInt8(v >> 8); bytes[position + 1] = UInt8(v & 0xFF)
        position += 2
    }

    public func probeU16(_ diff: Int) -> UInt16 {
        UInt16(bytes[position + diff]) << 8 | UInt16(bytes[position + diff + 1])
    }

    // MARK: u32 big-endian

    @discardableResult public func getU32() -> UInt32 {
        let v = UInt32(bytes[position]) << 24 | UInt32(bytes[position + 1]) << 16
            | UInt32(bytes[position + 2]) << 8 | UInt32(bytes[position + 3])
        position += 4
        return v
    }

    public func putU32(_ v: UInt32) {
        bytes[position] = UInt8(v >> 24 & 0xFF); bytes[position + 1] = UInt8(v >> 16 & 0xFF)
        bytes[position + 2] = UInt8(v >> 8 & 0xFF); bytes[position + 3] = UInt8(v & 0xFF)
        position += 4
    }

    public func probeU32(_ diff: Int) -> UInt32 {
        UInt32(bytes[position + diff]) << 24 | UInt32(bytes[position + diff + 1]) << 16
            | UInt32(bytes[position + diff + 2]) << 8 | UInt32(bytes[position + diff + 3])
    }

    // MARK: u64 big-endian

    @discardableResult public func getU64() -> UInt64 {
        var v: UInt64 = 0
        for i in 0 ..< 8 { v = v << 8 | UInt64(bytes[position + i]) }
        position += 8
        return v
    }

    public func putU64(_ v: UInt64) {
        for i in stride(from: 7, through: 0, by: -1) {
            bytes[position + (7 - i)] = UInt8(v >> UInt64(i * 8) & 0xFF)
        }
        position += 8
    }

    // MARK: position helpers

    public func move(_ diff: Int) { position += diff }

    public func padZero(_ size: Int) {
        for _ in 0 ..< size { putU8(0) }
    }

    public func flip() { limit = position; position = 0 }

    public func clear() { position = 0; limit = capacity }

    /// Slide unconsumed payload to the start of the backing array.
    public func compact() {
        let payload = Array(bytes[position ..< limit])
        bytes.replaceSubrange(0 ..< payload.count, with: payload)
        position = 0
        limit = payload.count
    }

    /// Index of the first occurrence of `target` within [position, limit - target.count], or nil.
    /// The reference searches only complete occurrences inside the remaining window.
    public func indexOf(_ target: [UInt8]) -> Int? {
        guard target.count <= remaining else { return nil }
        let upperBound = limit - target.count
        guard upperBound >= position else { return nil }
        for start in position ... upperBound {
            var matched = true
            for i in 0 ..< target.count where bytes[start + i] != target[i] {
                matched = false
                break
            }
            if matched { return start }
        }
        return nil
    }

    public var array: [UInt8] { bytes }

    public func toStringOrNull(_ encoding: String.Encoding) -> String? {
        String(bytes: bytes[position ..< limit], encoding: encoding)
    }
}

// MARK: - byte-array helpers (extension/ByteArray.kt of mvc)

extension Array where Element == UInt8 {
    public func isSame(as other: [UInt8]) -> Bool {
        self == other
    }

    public func match(_ pattern: [UInt8], at offset: Int = 0) -> Bool {
        guard pattern.count <= count - offset else { return false }
        for i in 0 ..< pattern.count where self[offset + i] != pattern[i] { return false }
        return true
    }

    public func search(_ pattern: [UInt8]) -> Int {
        let diff = count - pattern.count
        guard diff >= 0 else { return -1 }
        outer: for i in 0 ... diff {
            for j in 0 ..< pattern.count where self[i + j] != pattern[j] { continue outer }
            return i
        }
        return -1
    }

    public mutating func read(from other: [UInt8]) {
        precondition(count <= other.count)
        replaceSubrange(0 ..< count, with: other[0 ..< count])
    }

    public var ipv4String: String {
        count == 4 ? "\(self[0]).\(self[1]).\(self[2]).\(self[3])" : ""
    }

    public static func fromIPv4String(_ text: String) -> [UInt8]? {
        let parts = text.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var out = [UInt8]()
        for p in parts { guard let v = UInt8(p) else { return nil }; out.append(v) }
        return out
    }

    public func toHexString(grouped: Bool = false) -> String {
        var s = ""
        for (index, b) in enumerated() {
            s += String(format: "%02X", b)
            if grouped { s += index % 16 == 15 ? "\n" : " " }
        }
        return s
    }
}

extension FixedWidthInteger {
    /// Byte-order swap as in Int.reversed() of mvc (endianness inversion).
    public func reversedEndian() -> Self {
        byteSwapped
    }
}
