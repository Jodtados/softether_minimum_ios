// Cross-platform MVC1 vectors, ported 1:1 from softether_minimum QrPayloadTest.kt.

import XCTest
import CryptoKit
@testable import SoftEtherCore

final class QrPayloadTests: XCTestCase {
    // test-only key material, not the build secret
    private let key = QrPayload.deriveKey("TESTKEYTESTKEYTESTKEYTESTKEY32")

    private let pem = "-----BEGIN CERTIFICATE-----\n"
        + "MIIBkTCB+wIJAKoXJ5mZ7k7UMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs\n"
        + "aG9zdDAeFw0yNjEwMjUwMDAwMDBaFw0yNzEwMjUwMDAwMDBaMBQxEjAQBgNVBAMM\n"
        + "CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDE\n"
        + "-----END CERTIFICATE-----\n"

    private lazy var profile = ServerProfile(
        id: "source-id",
        label: "Работа",
        hostname: "vpn.example.com",
        hub: "VPN",
        username: "user",
        password: "pass",
        port: 5555,
        trustedCertPem: pem
    )

    private lazy var profile2 = ServerProfile(
        id: "source-id-2",
        label: "Дом",
        hostname: "home.example.org",
        hub: "VPN2",
        username: "u2",
        password: "p2",
        port: 443,
        trustedCertPem: nil
    )

    private var expectedCertBody: String {
        pem.components(separatedBy: .newlines).filter { !$0.contains("-----") }.joined()
    }

    private func base64Body(_ token: String) -> [UInt8] {
        QrPayload.base64UrlDecode(String(token.dropFirst("MVC1:".count)))!
    }

    private func tokenFrom(_ bytes: [UInt8]) -> String {
        "MVC1:" + QrPayload.base64UrlEncode(bytes)
    }

    private func decodeSingle(_ token: String) -> QrPayload.Entry? {
        QrPayload.decode(token, key: key)?.first
    }

    func testRoundtripWithCert() {
        let decoded = decodeSingle(QrPayload.encode(profile, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertEqual("Работа", decoded?.label)
        XCTAssertEqual("vpn.example.com", decoded?.hostname)
        XCTAssertEqual("VPN", decoded?.hub)
        XCTAssertEqual("user", decoded?.username)
        XCTAssertEqual("pass", decoded?.password)
        XCTAssertEqual(5555, decoded?.port)
        // cert body comes back compacted: no headers, no line breaks
        XCTAssertEqual(expectedCertBody, decoded?.certBody)
        // and reconstructs a full PEM
        XCTAssertTrue(QrPayload.pemFromBody(decoded!.certBody!).contains("BEGIN CERTIFICATE"))
    }

    func testRoundtripWithoutCert() {
        var noCert = profile
        noCert.trustedCertPem = nil
        let decoded = decodeSingle(QrPayload.encode(noCert, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertNil(decoded?.certBody)
    }

    func testV1TokenDecodesAsSingleItemList() {
        let list = QrPayload.decode(QrPayload.encode(profile, key: key), key: key)

        XCTAssertEqual(1, list?.count)
    }

    func testProfileIdIsNeverEncoded() {
        let token = QrPayload.encode(profile, key: key)

        XCTAssertFalse(token.contains("source-id"))
        XCTAssertFalse(token.contains(QrPayload.base64UrlEncode(Array("source-id".utf8))))
    }

    func testTamperedCiphertextIsRejected() {
        var bytes = base64Body(QrPayload.encode(profile, key: key))
        bytes[bytes.count / 2] ^= 0x01

        XCTAssertNil(QrPayload.decode(tokenFrom(bytes), key: key))
    }

    func testForeignTokensAreRejected() {
        XCTAssertNil(QrPayload.decode("vless://uuid@example.com:443?type=tcp", key: key))
        XCTAssertNil(QrPayload.decode("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP", key: key))

        let mvc2 = "MVC2:" + String(QrPayload.encode(profile, key: key).dropFirst("MVC1:".count))
        XCTAssertNil(QrPayload.decode(mvc2, key: key))
        XCTAssertNil(QrPayload.decode("MVC1:not-base64!!!", key: key))
        XCTAssertNil(QrPayload.decode("MVC1:AAAA", key: key)) // shorter than IV+tag
    }

    func testMissingRequiredFieldIsRejected() {
        let json = #"{"label":"x","hub":"VPN","username":"u","password":"p","port":443}"# // no hostname

        XCTAssertNil(QrPayload.decode(QrPayload.seal(json, key: key), key: key))
    }

    func testInvalidPortsAreRejected() {
        for port in [0, 70000, -1] {
            let json = #"{"hostname":"h","hub":"VPN","username":"u","password":"p","port":\#(port)}"#

            XCTAssertNil(QrPayload.decode(QrPayload.seal(json, key: key), key: key), "port \(port) must be rejected")
        }
    }

    func testAbsentPortDefaultsTo443() {
        let json = #"{"hostname":"h","hub":"VPN","username":"u","password":"p"}"#
        let decoded = decodeSingle(QrPayload.seal(json, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertEqual(443, decoded?.port)
    }

    func testWrongKeyIsRejected() {
        let otherKey = QrPayload.deriveKey("OTHERKEYOTHERKEYOTHERKEYOTHER7")

        XCTAssertNil(QrPayload.decode(QrPayload.encode(profile, key: key), key: otherKey))
    }

    func testBatchRoundtrip() {
        let decoded = QrPayload.decode(QrPayload.encodeAll([profile, profile2], key: key), key: key)

        XCTAssertEqual(2, decoded?.count)
        XCTAssertEqual("Работа", decoded?[0].label)
        XCTAssertEqual("vpn.example.com", decoded?[0].hostname)
        XCTAssertEqual(5555, decoded?[0].port)
        XCTAssertEqual(expectedCertBody, decoded?[0].certBody)
        XCTAssertEqual("Дом", decoded?[1].label)
        XCTAssertEqual("home.example.org", decoded?[1].hostname)
        XCTAssertEqual(443, decoded?[1].port)
        XCTAssertNil(decoded?[1].certBody)
    }

    func testBatchRoundtripWithoutCert() {
        let decoded = QrPayload.decode(QrPayload.encodeAll([profile, profile2], key: key, includeCert: false), key: key)

        XCTAssertEqual(2, decoded?.count)
        XCTAssertNil(decoded?[0].certBody)
        XCTAssertNil(decoded?[1].certBody)
    }

    func testBatchIdsAreNeverEncoded() {
        let token = QrPayload.encodeAll([profile, profile2], key: key)

        XCTAssertFalse(token.contains("source-id"))
        XCTAssertFalse(token.contains("source-id-2"))
    }

    func testBatchTamperingIsRejected() {
        var bytes = base64Body(QrPayload.encodeAll([profile, profile2], key: key))
        bytes[bytes.count / 2] ^= 0x01

        XCTAssertNil(QrPayload.decode(tokenFrom(bytes), key: key))
    }

    func testEmptyBatchIsRejected() {
        let json = #"{"v":2,"servers":[]}"#

        XCTAssertNil(QrPayload.decode(QrPayload.seal(json, key: key), key: key))
    }

    func testBatchWithOneInvalidEntryIsRejected() {
        let json = """
        {"v":2,"servers":[
        {"label":"ok","hostname":"h","hub":"VPN","username":"u","password":"p","port":443},
        {"label":"bad","hostname":"h","hub":"VPN","username":"u","password":"p","port":70000}
        ]}
        """

        XCTAssertNil(QrPayload.decode(QrPayload.seal(json, key: key), key: key))
    }

    // -- 0.9.3: credentials-free imports -------------------------------------

    func testEmptyCredentialsAreAccepted() {
        let json = #"{"hostname":"h","hub":"VPN","port":443}"#

        let decoded = decodeSingle(QrPayload.seal(json, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertEqual("", decoded?.username)
        XCTAssertEqual("", decoded?.password)
    }

    func testEmptyCredentialsRoundtrip() {
        var noCreds = profile
        noCreds.username = ""
        noCreds.password = ""
        let decoded = decodeSingle(QrPayload.encode(noCreds, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertEqual("", decoded?.username)
        XCTAssertEqual("", decoded?.password)
        XCTAssertEqual("vpn.example.com", decoded?.hostname)
    }

    // -- 0.9.4: messenger seams + compact tokens ------------------------------

    func testLineWrappedTokenStillDecodes() {
        // a token shared as text (messenger, clipboard) arrives line-wrapped:
        // every whitespace seam must be stripped before base64url decoding
        let token = QrPayload.encode(profile, key: key)
        var wrapped = ""
        for (index, char) in token.enumerated() {
            if index > 0 && index % 13 == 0 { wrapped += "\r\n" }
            wrapped.append(char)
        }

        let decoded = decodeSingle(wrapped)

        XCTAssertNotNil(decoded)
        XCTAssertEqual(profile.hostname, decoded?.hostname)
    }

    func testNbspAndZeroWidthAreStrippedToo() {
        let token = QrPayload.encode(profile, key: key)
        // NBSP (U+00A0), zero-width space (U+200B), BOM (U+FEFF) mid-token
        let seams = String(String.UnicodeScalarView([
            Unicode.Scalar(0x00A0)!, Unicode.Scalar(0x200B)!, Unicode.Scalar(0xFEFF)!,
        ]))
        let index = token.index(token.startIndex, offsetBy: 5)
        let dirty = String(token[..<index]) + seams + String(token[index...])

        XCTAssertNotNil(QrPayload.decode(dirty, key: key))
    }

    func testDefaultsAreOmittedAndStillDecode() {
        // empty label/credentials and port 443 are not written; the decoder
        // fills them back in (older installs read the short form the same way)
        var minimal = profile
        minimal.label = ""
        minimal.username = ""
        minimal.password = ""
        minimal.port = 443
        minimal.trustedCertPem = nil

        let decoded = QrPayload.decode(QrPayload.encodeAll([minimal], key: key), key: key)?.first

        XCTAssertNotNil(decoded)
        XCTAssertEqual("", decoded?.label)
        XCTAssertEqual("", decoded?.username)
        XCTAssertEqual("", decoded?.password)
        XCTAssertEqual(443, decoded?.port)
    }

    func testCompactPlaintextOmitsDefaultKeys() {
        // byte-level parity with Android 0.9.4: the sealed JSON carries
        // hostname/hub only — no label/username/password/port for defaults
        var minimal = profile
        minimal.label = ""
        minimal.username = ""
        minimal.password = ""
        minimal.port = 443
        minimal.trustedCertPem = nil

        let raw = QrPayload.base64UrlDecode(String(QrPayload.encode(minimal, key: key).dropFirst("MVC1:".count)))!
        let sealed = try! AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(raw[..<12])),
            ciphertext: Data(raw[12..<(raw.count - 16)]),
            tag: Data(raw[(raw.count - 16)...])
        )
        let plain = try! AES.GCM.open(sealed, using: SymmetricKey(data: Data(key)))
        let json = String(data: plain, encoding: .utf8)!

        XCTAssertEqual(#"{"hostname":"vpn.example.com","hub":"VPN"}"#, json)
    }

    func testHostnameLabelIsNotDuplicated() {
        // label == hostname is dropped on encode; import names it by hostname
        var named = profile
        named.label = profile.hostname
        let decoded = decodeSingle(QrPayload.encode(named, key: key))

        XCTAssertNotNil(decoded)
        XCTAssertEqual("", decoded?.label)
        XCTAssertEqual(profile.hostname, decoded?.hostname)
    }

    func testIsMvcTokenDetectsWrappedAndForeignText() {
        let token = QrPayload.encode(profile, key: key)
        var wrapped = ""
        for (index, char) in token.enumerated() {
            if index > 0 && index % 11 == 0 { wrapped += "\n " }
            wrapped.append(char)
        }

        XCTAssertTrue(QrPayload.isMvcToken(wrapped))
        XCTAssertFalse(QrPayload.isMvcToken("https://vpn.example.com:443?hub=VPN"))
        XCTAssertFalse(QrPayload.isMvcToken("MVC2:" + String(token.dropFirst("MVC1:".count))))
    }
}
