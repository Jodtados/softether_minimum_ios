// Management wire format, TOTP and the hardware-id hash — byte-compatible
// with the Android client (admin/Heartbeat.kt, admin/AdminApi.kt,
// control/Totp.kt, control/AppLockManager.kt) so the server cannot tell the
// platforms apart. Pure Foundation + CryptoKit: host-testable without iOS.

import Foundation
import CryptoKit

// MARK: - heartbeat body

/// The /api/hb POST payload. Optional fields (hwid, vc, suite, abi, traffic)
/// are omitted when empty, exactly as the Android writer does.
public struct MgmtHeartbeatBody {
    public var user: String
    public var device: String
    public var version: String
    public var vc: Int
    public var suite: String
    public var abi: String
    public var role: String
    public var model: String
    public var hwid: String
    public var locked: Bool
    public var servers: Int
    public var server: String
    public var login: String
    public var traffic: [String: Int64]

    public init(user: String = "", device: String = "", version: String = "",
                vc: Int = 0, suite: String = "se", abi: String = "universal",
                role: String = "user", model: String = "", hwid: String = "",
                locked: Bool = false, servers: Int = 0, server: String = "",
                login: String = "", traffic: [String: Int64] = [:]) {
        self.user = user
        self.device = device
        self.version = version
        self.vc = vc
        self.suite = suite
        self.abi = abi
        self.role = role
        self.model = model
        self.hwid = hwid
        self.locked = locked
        self.servers = servers
        self.server = server
        self.login = login
        self.traffic = traffic
    }

    public func encoded() -> String {
        var body: [String: Any] = [
            "user": user,
            "device": device,
            "version": version,
            "server": server,
            "model": model,
            "login": login,
            "servers": servers,
            "role": role,
            "locked": locked,
        ]
        if !hwid.isEmpty { body["hwid"] = hwid }
        if vc > 0 { body["vc"] = vc }
        if !suite.isEmpty { body["suite"] = suite }
        if !abi.isEmpty { body["abi"] = abi }
        if !traffic.isEmpty { body["traffic"] = traffic }
        guard let data = try? JSONSerialization.data(withJSONObject: body),
              let text = String(data: data, encoding: .utf8)
        else { return "{}" }
        return text
    }
}

// MARK: - heartbeat reply

public struct MgmtCommand: Equatable {
    public var type: String
    public var payload: String

    public init(type: String, payload: String) {
        self.type = type
        self.payload = payload
    }
}

public struct MgmtHeartbeatReply: Equatable {
    public var commands: [MgmtCommand]
    /// personal token minted at enrollment / rotation; nil when the server did
    /// not hand one out (also for pre-0.6.0 servers with no such field)
    public var deviceToken: String?

    public init(commands: [MgmtCommand] = [], deviceToken: String? = nil) {
        self.commands = commands
        self.deviceToken = deviceToken
    }
}

/// Pure parser; malformed input yields nil instead of throwing. Mirrors the
/// Android parseHeartbeatReply: missing/broken `commands` fails the reply, an
/// explicitly empty `deviceToken` is NOT an enrollment.
public func parseHeartbeatReply(_ text: String) -> MgmtHeartbeatReply? {
    guard let data = text.data(using: .utf8),
          let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let rawCommands = root["commands"] as? [[String: Any]]
    else { return nil }

    let commands = rawCommands.map { item in
        MgmtCommand(type: item["type"] as? String ?? "",
                    payload: item["payload"] as? String ?? "")
    }
    let token = (root["deviceToken"] as? String) ?? ""
    return MgmtHeartbeatReply(commands: commands, deviceToken: token.isEmpty ? nil : token)
}

// MARK: - device identity

/// Stable per-installation device id, the Android format: "d-" + lowercase uuid.
public func newDeviceId() -> String {
    "d-" + UUID().uuidString.lowercased()
}

/// Stable install fingerprint — byte-compatible with the Android dedup scheme:
/// SHA-256("mvc-hwid:" + raw) as lowercase hex, first 32 chars. A raw id of
/// "" disables dedup (same as Android ROMs without ANDROID_ID).
public func mgmtHardwareId(rawInstallId: String) -> String {
    guard !rawInstallId.isEmpty else { return "" }
    let digest = SHA256.hash(data: Data("mvc-hwid:\(rawInstallId)".utf8))
    return digest.map { String(format: "%02x", $0) }.joined().prefix(32).description
}

// MARK: - activation cooldown (control/AppLockManager.kt)

public let mgmtCooldownBaseSeconds = 30
public let mgmtMaxAttemptsPerCooldown = 5

/// 30s per full batch of 5 failed attempts (30, 60, 90 …); the batch that just
/// started (attempts 0…4) carries no cooldown yet.
public func mgmtCooldownSeconds(forFailedAttempts attempts: Int) -> Int {
    mgmtCooldownBaseSeconds * (attempts / mgmtMaxAttemptsPerCooldown)
}

// MARK: - TOTP (control/Totp.kt)

/// RFC 6238 TOTP, SHA-1, 6 digits, 30s period, one-step window both ways —
/// the same numbers the Android gate and any authenticator app produce.
public enum Totp {
    static let period: UInt64 = 30
    static let digits = 6
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    public static func verify(secretBase32: String, code: String, nowMillis: Int64) -> Bool {
        // ASCII digits only: localized digit glyphs must not slip through
        guard code.count == digits,
              code.unicodeScalars.allSatisfy({ $0.value >= 48 && $0.value <= 57 })
        else { return false }
        guard let key = base32Decode(secretBase32) else { return false }

        let counter = UInt64(max(0, nowMillis)) / 1000 / period
        for skew in -1 ... 1 {
            let shifted = Int64(counter) + Int64(skew)
            let candidate = shifted < 0 ? UInt64(0) : UInt64(shifted)
            let expected = Array(hotp(key: key, counter: candidate).utf8)
            if constantTimeEquals(expected, Array(code.utf8)) { return true }
        }
        return false
    }

    public static func hotp(key: [UInt8], counter: UInt64) -> String {
        var counterBytes = [UInt8](repeating: 0, count: 8)
        for i in 0 ..< 8 {
            counterBytes[7 - i] = UInt8(truncatingIfNeeded: counter >> (8 * UInt64(i)))
        }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(counterBytes), using: SymmetricKey(data: Data(key)))
        let d = Array(mac)
        let off = Int(d[d.count - 1] & 0xF)
        let bin = (Int(d[off]) & 0x7F) << 24
            | Int(d[off + 1]) << 16
            | Int(d[off + 2]) << 8
            | Int(d[off + 3])
        return String(format: "%06d", bin % 1_000_000)
    }

    /// Base32 (RFC 4648, padding/whitespace ignored); nil on any foreign char.
    static func base32Decode(_ text: String) -> [UInt8]? {
        var out = [UInt8]()
        var bits = 0
        var value = 0
        for char in text.uppercased() {
            if char.isWhitespace || char == "=" { continue }
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            value = (value << 5) | alphabet.distance(from: alphabet.startIndex, to: index)
            bits += 5
            if bits >= 8 {
                out.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        return out
    }

    private static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0 ..< a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
