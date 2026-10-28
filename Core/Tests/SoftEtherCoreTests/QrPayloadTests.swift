// Cross-platform MVC1 vectors, ported 1:1 from softether_minimum QrPayloadTest.kt.

import XCTest
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

        XCTAssertNil(QrPayload.decode(QrPayload.encode(profile, key: key), otherKey))
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
}
