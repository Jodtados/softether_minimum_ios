// Build-time baked management secrets — the same XOR scheme as Android
// control/Secrets.kt / build.gradle SECRET_SEED: a value only ever exists as
// hex(plaintext XOR SHA-256(seed)), so the plain forms appear neither in the
// repo nor in the binary. The endpoint/token/gate values are injected into
// Info.plist at build time (ios-unsigned.yml "Bake management secrets" step);
// absent keys decode to "" and leave the feature dormant. Neutral key names
// hide their purpose.
//
// Raises the bar against casual extraction — NOT a guarantee against a
// determined reverse engineer (the seed ships in the app).

import Foundation
import CryptoKit

enum MgmtSecrets {
    // must match SECRET_SEED in the Android build.gradle and Secrets.kt
    private static let seed = "mvc-6f2c-9d41-b7e8"

    private static let keystream: [UInt8] = Array(SHA256.hash(data: Data(seed.utf8)))

    /// hex(plain XOR keystream) → plain; undecodable input yields "".
    static func decode(_ hex: String) -> String {
        guard !hex.isEmpty, hex.count % 2 == 0 else { return "" }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(after: index)
            guard let value = UInt8(hex[index ... next], radix: 16) else { return "" }
            bytes.append(value ^ keystream[bytes.count % keystream.count])
            index = hex.index(after: next)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func baked(_ key: String) -> String {
        decode(Bundle.main.object(forInfoDictionaryKey: key) as? String ?? "")
    }

    /// management endpoint URL (b0); empty = the client stays offline
    static let url = baked("MGMT_B0")
    /// shared provisioning device token (b1)
    static let deviceToken = baked("MGMT_B1")
    /// TOTP secret of the one-time activation gate (b2); empty = no gate
    static let totpSecret = baked("MGMT_B2")
    /// baked QR secret for MVC1 tokens (b3); empty = Settings pin required
    static let qrSecret = baked("QR_B3")

    /// SPKI of the management server's self-signed certificate, base64 — the
    /// same encoded constant as Android AdminApi.PINNED_PUBLIC_KEY_ENC (public
    /// data; the encoding is uniformity, not secrecy). https connections trust
    /// exactly this key and nothing else.
    /// regenerate: openssl x509 -pubkey -noout < server/certs/mgmt-cert.pem
    static let spkiPin = decode(
        "2ae4b9a3a8b7e122f03bb84cb6f99746dcea2b74e884bdcf14bf197eace52edc36c59391c2f8cb12ca3bb530a7c7ce31f294140bf28a81e319e6647da9ed28ce0dc19ee1c6acfa2ddd23ab72a1e4de46cc8e165cd28dc8cc16904f0da5c527f15689b0bed8a78813fc388576add29071d98c0a4af1aea5b416b21407")
}
