// MgmtWire vectors: the TOTP numbers must match RFC 4226 (and therefore the
// Android gate and any authenticator app), the reply parser must mirror the
// Android parseHeartbeatReply contract, the hardware id must follow the
// "mvc-hwid:" dedup scheme.

import XCTest
import CryptoKit
@testable import SoftEtherCore

final class MgmtWireTests: XCTestCase {
    // RFC 4226 test key "12345678901234567890" in Base32 and its SHA-1 HOTP
    // vectors — independent proof the HMAC/truncation bytes match Android.
    private let rfcKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    private let rfcVectors: [(UInt64, String)] = [
        (0, "755224"), (1, "287082"), (2, "359152"),
    ]

    private func millis(counter: UInt64) -> Int64 {
        Int64(counter) * 30_000
    }

    // MARK: TOTP

    func testHotpRfcVectors() {
        let key = Totp.base32Decode(rfcKey)!
        XCTAssertEqual(key, Array("12345678901234567890".utf8))
        for (counter, expected) in rfcVectors {
            XCTAssertEqual(Totp.hotp(key: key, counter: counter), expected)
        }
    }

    func testVerifyAcceptsCurrentAndWindowSteps() {
        let code = Totp.hotp(key: Totp.base32Decode(rfcKey)!, counter: 5)
        // now = step 5: window 4..6 → accepted
        XCTAssertTrue(Totp.verify(secretBase32: rfcKey, code: code, nowMillis: millis(counter: 5)))
        // one step later: window 5..7 still covers the code
        XCTAssertTrue(Totp.verify(secretBase32: rfcKey, code: code, nowMillis: millis(counter: 6)))
    }

    func testVerifyRejectsOutsideWindowAndGarbage() {
        let code = Totp.hotp(key: Totp.base32Decode(rfcKey)!, counter: 5)
        // now = step 3: window 2..4 → outside
        XCTAssertFalse(Totp.verify(secretBase32: rfcKey, code: code, nowMillis: millis(counter: 3)))
        XCTAssertFalse(Totp.verify(secretBase32: rfcKey, code: "75522x", nowMillis: millis(counter: 0)))
        XCTAssertFalse(Totp.verify(secretBase32: rfcKey, code: "75522", nowMillis: millis(counter: 0)))
        XCTAssertFalse(Totp.verify(secretBase32: rfcKey, code: "7552244", nowMillis: millis(counter: 0)))
        // empty secret decodes to an empty key: nothing verifies
        XCTAssertFalse(Totp.verify(secretBase32: "", code: "755224", nowMillis: millis(counter: 0)))
        // foreign base32 character
        XCTAssertFalse(Totp.verify(secretBase32: "ABC1", code: "755224", nowMillis: millis(counter: 0)))
    }

    // MARK: hardware id

    func testHardwareIdFormatAndStability() {
        let id = mgmtHardwareId(rawInstallId: "1234ABCD-1234-1234-1234-1234ABCD1234")
        XCTAssertEqual(id.count, 32)
        XCTAssertTrue(id.allSatisfy { $0.isLowercase || $0.isNumber })
        XCTAssertEqual(id, mgmtHardwareId(rawInstallId: "1234ABCD-1234-1234-1234-1234ABCD1234"))
        XCTAssertNotEqual(id, mgmtHardwareId(rawInstallId: "other"))
        XCTAssertEqual(mgmtHardwareId(rawInstallId: ""), "")
    }

    func testHardwareIdMatchesAndroidScheme() {
        // the prefix must enter the hash exactly as on Android
        let viaHelper = mgmtHardwareId(rawInstallId: "X")
        let direct = SHA256.hash(data: Data("mvc-hwid:X".utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(32).description
        XCTAssertEqual(viaHelper, direct)
    }

    // MARK: heartbeat body

    func testHeartbeatBodyCarriesAllFields() throws {
        let body = MgmtHeartbeatBody(
            user: "u1", device: "d-1", version: "0.1.0", vc: 11, suite: "se",
            abi: "universal", role: "user", model: "Apple iPhone14,2",
            hwid: "abc", locked: true, servers: 3, server: "vpn-1",
            login: "u1", traffic: ["vpn-1": 4096])
        let data = try XCTUnwrap(body.encoded().data(using: .utf8))
        let root = try XCTUnwrap(
            (try? JSONSerialization.jsonObject(with: data)) as? [String: Any])

        XCTAssertEqual(root["user"] as? String, "u1")
        XCTAssertEqual(root["device"] as? String, "d-1")
        XCTAssertEqual(root["version"] as? String, "0.1.0")
        XCTAssertEqual(root["vc"] as? Int, 11)
        XCTAssertEqual(root["suite"] as? String, "se")
        XCTAssertEqual(root["abi"] as? String, "universal")
        XCTAssertEqual(root["role"] as? String, "user")
        XCTAssertEqual(root["model"] as? String, "Apple iPhone14,2")
        XCTAssertEqual(root["hwid"] as? String, "abc")
        XCTAssertEqual(root["locked"] as? Bool, true)
        XCTAssertEqual(root["servers"] as? Int, 3)
        XCTAssertEqual(root["server"] as? String, "vpn-1")
        XCTAssertEqual(root["login"] as? String, "u1")
        XCTAssertEqual((root["traffic"] as? [String: Int])?["vpn-1"], 4096)
    }

    func testHeartbeatBodyOmitsOptionalFieldsWhenEmpty() throws {
        let body = MgmtHeartbeatBody(user: "u", device: "d")
        let data = try XCTUnwrap(body.encoded().data(using: .utf8))
        let root = try XCTUnwrap(
            (try? JSONSerialization.jsonObject(with: data)) as? [String: Any])

        XCTAssertNil(root["hwid"])   // empty id → dedup disabled, key absent
        XCTAssertNil(root["vc"])     // 0 → never announced, key absent
        XCTAssertNil(root["traffic"]) // no counters yet, key absent
        // suite/abi defaults are announced even for a bare body
        XCTAssertEqual(root["suite"] as? String, "se")
        XCTAssertEqual(root["abi"] as? String, "universal")
    }

    // MARK: reply parsing

    func testParseReplyCommandsAndEnrollment() throws {
        let reply = try XCTUnwrap(parseHeartbeatReply(
            #"{"commands":[{"type":"servers","payload":"MVC1-abc"},{"type":"disconnect","payload":""}],"deviceToken":"abc123def456"}"#))
        XCTAssertEqual(reply.commands.count, 2)
        XCTAssertEqual(reply.commands[0], MgmtCommand(type: "servers", payload: "MVC1-abc"))
        XCTAssertEqual(reply.commands[1].type, "disconnect")
        XCTAssertEqual(reply.deviceToken, "abc123def456")
    }

    func testParseReplyUpdateCommandSurvives() throws {
        // iOS ignores update commands, but they must parse like any other
        let reply = try XCTUnwrap(parseHeartbeatReply(
            #"{"commands":[{"type":"update","payload":"{\"file\":\"se user 0.8.0-11.apk\"}"}]}"#))
        XCTAssertEqual(reply.commands[0].type, "update")
        XCTAssertTrue(reply.commands[0].payload.contains("0.8.0"))
        XCTAssertNil(reply.deviceToken)
    }

    func testParseReplyEmptyTokenIsNoEnrollment() throws {
        let reply = try XCTUnwrap(parseHeartbeatReply(#"{"commands":[],"deviceToken":""}"#))
        XCTAssertEqual(reply.commands, [])
        XCTAssertNil(reply.deviceToken)
    }

    func testParseReplyRejectsBrokenInput() {
        XCTAssertNil(parseHeartbeatReply("not json"))
        XCTAssertNil(parseHeartbeatReply(#"{"deviceToken":"abc"}"#)) // no commands array
    }

    // MARK: cooldown ladder

    func testCooldownLadder() {
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 0), 0)
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 4), 0)
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 5), 30)
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 9), 30)
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 10), 60)
        XCTAssertEqual(mgmtCooldownSeconds(forFailedAttempts: 15), 90)
    }

    // MARK: device id

    func testNewDeviceIdMatchesAndroidFormat() {
        let id = newDeviceId()
        XCTAssertTrue(id.hasPrefix("d-"))
        XCTAssertEqual(id.count, 38) // "d-" + 36-char lowercase uuid
        XCTAssertEqual(id, id.lowercased()) // uuid lowercase, like Android
        XCTAssertNotEqual(id, newDeviceId())
    }
}
