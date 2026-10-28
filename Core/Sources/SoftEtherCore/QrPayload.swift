// MVC1 QR transfer format, byte-compatible with softether_minimum Android
// (control/QrPayload.kt): "MVC1:" + Base64url( IV(12) || AES-256-GCM(ct||tag) )
// over compact JSON. Key = SHA-256(Base32Decode(secret)).

import Foundation
import CryptoKit
import CommonCrypto

public enum QrPayload {
    static let prefix = "MVC1:"
    static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    public struct Entry: Equatable {
        public var label: String
        public var hostname: String
        public var hub: String
        public var username: String
        public var password: String
        public var port: Int
        public var certBody: String?

        public init(label: String, hostname: String, hub: String, username: String,
                    password: String, port: Int, certBody: String?) {
            self.label = label
            self.hostname = hostname
            self.hub = hub
            self.username = username
            self.password = password
            self.port = port
            self.certBody = certBody
        }
    }

    public static func deriveKey(_ secret: String) -> [UInt8] {
        sha256(base32Decode(secret))
    }

    public static func encode(_ profile: ServerProfile, key: [UInt8], includeCert: Bool = true) -> String {
        seal(profileJson(profile, includeCert), key: key)
    }

    /// All profiles packed into one QR; decode accepts both v1 and v2 tokens.
    public static func encodeAll(_ profiles: [ServerProfile], key: [UInt8], includeCert: Bool = true) -> String {
        var json = "{\"v\":2,\"servers\":["
        json += profiles.map { profileJson($0, includeCert) }.joined(separator: ",")
        json += "]}"
        return seal(json, key: key)
    }

    private static func profileJson(_ profile: ServerProfile, _ includeCert: Bool) -> String {
        var json = "{\"label\":\(jsonEscape(profile.label))"
            + ",\"hostname\":\(jsonEscape(profile.hostname))"
            + ",\"hub\":\(jsonEscape(profile.hub))"
            + ",\"username\":\(jsonEscape(profile.username))"
            + ",\"password\":\(jsonEscape(profile.password))"
            + ",\"port\":\(String(profile.port))"

        if includeCert, let body = pemBody(profile.trustedCertPem) {
            json += ",\"cert\":\(jsonEscape(body))"
        }

        return json + "}"
    }

    public static func seal(_ json: String, key: [UInt8]) -> String {
        var iv = [UInt8](repeating: 0, count: 12)
        _ = SecRandomCopyBytes(kSecRandomDefault, 12, &iv)

        let sealedBox = try! AES.GCM.seal(
            Array(json.utf8),
            using: SymmetricKey(data: Data(key)),
            nonce: AES.GCM.Nonce(data: Data(iv))
        )

        var combined = iv
        combined.append(contentsOf: sealedBox.ciphertext)
        combined.append(contentsOf: sealedBox.tag)

        return prefix + base64UrlEncode(combined)
    }

    public static func decode(_ token: String, key: [UInt8]) -> [Entry]? {
        guard token.hasPrefix(prefix) else { return nil }

        return decodeRaw(token, key: key)
    }

    private static func decodeRaw(_ token: String, key: [UInt8]) -> [Entry]? {
        guard let raw = base64UrlDecode(String(token.dropFirst(prefix.count))) else { return nil }
        guard raw.count >= 12 + 16 else { return nil }

        let iv = Array(raw[0 ..< 12])
        let ciphertext = Array(raw[12...])

        guard let sealedBox = try? AES.GCM.SealedBox(
                  nonce: AES.GCM.Nonce(data: Data(iv)), ciphertext: Data(ciphertext.dropLast(16)),
                  tag: Data(ciphertext.suffix(16))
              ),
              let plain = try? AES.GCM.open(sealedBox, using: SymmetricKey(data: Data(key))),
              let json = try? JSONSerialization.jsonObject(with: Data(plain)) as? [String: Any]
        else { return nil }

        if let entries = json["servers"] as? [[String: Any]] {
            if entries.isEmpty { return nil }

            // all-or-nothing: one broken profile poisons the whole batch
            var out: [Entry] = []
            for entry in entries {
                guard let parsed = parseEntry(entry) else { return nil }
                out.append(parsed)
            }
            return out
        }

        guard let parsed = parseEntry(json) else { return nil }
        return [parsed]
    }

    private static func parseEntry(_ json: [String: Any]) -> Entry? {
        let hostname = json["hostname"] as? String ?? ""
        let hub = json["hub"] as? String ?? ""
        let username = json["username"] as? String ?? ""
        let password = json["password"] as? String ?? ""
        let port: Int
        if let p = json["port"] as? Int {
            port = p
        } else if let p = json["port"] as? String, let v = Int(p) {
            port = v
        } else {
            port = 443
        }

        if hostname.trimmingCharacters(in: .whitespaces).isEmpty
            || hub.trimmingCharacters(in: .whitespaces).isEmpty
            || username.trimmingCharacters(in: .whitespaces).isEmpty
            || password.trimmingCharacters(in: .whitespaces).isEmpty
        {
            return nil
        }
        if !(1 ... 65535).contains(port) { return nil }

        return Entry(
            label: json["label"] as? String ?? "",
            hostname: hostname, hub: hub, username: username, password: password,
            port: port,
            certBody: json["cert"] as? String
        )
    }

    /// PEM headers and line breaks stripped, to keep the QR payload small.
    public static func pemBody(_ pem: String?) -> String? {
        guard let pem else { return nil }
        let body = pem.components(separatedBy: .newlines)
            .filter { !$0.contains("-----") }
            .joined()
            .trimmingCharacters(in: .whitespaces)
        return body.isEmpty ? nil : body
    }

    public static func pemFromBody(_ body: String) -> String {
        var pem = "-----BEGIN CERTIFICATE-----\n"
        var index = body.startIndex
        while index < body.endIndex {
            let end = body.index(index, offsetBy: 64, limitedBy: body.endIndex) ?? body.endIndex
            pem += body[index ..< end] + "\n"
            index = end
        }
        return pem + "-----END CERTIFICATE-----\n"
    }

    // MARK: crypto / encoding helpers

    static func sha256(_ input: [UInt8]) -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        input.withUnsafeBufferPointer { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(input.count), &hash)
        }
        return hash
    }

    static func base32Decode(_ input: String) -> [UInt8] {
        var bits = 0
        var value = 0
        var out: [UInt8] = []

        for char in input.uppercased() {
            if char == "=" { break }
            guard let index = base32Alphabet.firstIndex(of: char) else {
                continue // Android throws; tolerant here as decode() guards the result
            }

            value = (value << 5) | base32Alphabet.distance(from: base32Alphabet.startIndex, to: index)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xFF))
            }
        }

        return out
    }

    static func base64UrlEncode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64UrlDecode(_ text: String) -> [UInt8]? {
        var normalized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while normalized.count % 4 != 0 { normalized += "=" }
        guard let data = Data(base64Encoded: normalized) else { return nil }
        return Array(data)
    }

    static func jsonEscape(_ text: String) -> String {
        let data = try! JSONSerialization.data(withJSONObject: [text])
        // [<quoted string>]
        let inner = String(data: data.dropFirst().dropLast(), encoding: .utf8) ?? "\"\""
        return inner
    }
}
