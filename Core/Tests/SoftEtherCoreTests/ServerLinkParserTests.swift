// Server link parsing vectors, ported from ServerLinkParserTest.kt,
// plus ServerStore traffic/rotation logic checks.

import XCTest
@testable import SoftEtherCore

final class ServerLinkParserTests: XCTestCase {
    func testVpnGateLinkParsesHostAndPort() {
        let csv = "vpn123456789.opengw.net,1555,TCP,1652645648,2,11.28,1652645648,116,2237,JP"
        let link = "vpn://" + Data(csv.utf8).base64EncodedString()

        let parsed = ServerLinkParser.parse(link)!

        XCTAssertEqual("vpn123456789.opengw.net", parsed.hostname)
        XCTAssertEqual(1555, parsed.port)
    }

    func testVpnGateLinkWithoutPortFallsBackToNullPort() {
        let csv = "vpn123456789.opengw.net"
        let link = "vpn://" + Data(csv.utf8).base64EncodedString()

        let parsed = ServerLinkParser.parse(link)!

        XCTAssertEqual("vpn123456789.opengw.net", parsed.hostname)
        XCTAssertNil(parsed.port)
    }

    func testVpnGateGarbagePayloadYieldsNull() {
        XCTAssertNil(ServerLinkParser.parse("vpn://!!!not-base64!!!"))
    }

    func testHttpLinkParsesHostPortHubCredentials() {
        let parsed = ServerLinkParser.parse(
            "https://vpn.example.org:8443/MYHUB?user=alice&pass=secret%20pass"
        )!

        XCTAssertEqual("vpn.example.org", parsed.hostname)
        XCTAssertEqual(8443, parsed.port)
        XCTAssertEqual("MYHUB", parsed.hub)
        XCTAssertEqual("alice", parsed.username)
        XCTAssertEqual("secret pass", parsed.password)
    }

    func testHttpLinkPortFromQueryWinsOverDefault() {
        let parsed = ServerLinkParser.parse(
            "https://vpn.example.org/hubname?port=443&username=bob&password=x"
        )!

        XCTAssertEqual("vpn.example.org", parsed.hostname)
        XCTAssertEqual(443, parsed.port)
        XCTAssertEqual("hubname", parsed.hub)
        XCTAssertEqual("bob", parsed.username)
        XCTAssertEqual("x", parsed.password)
    }

    func testPlainHttpLinkHasNullOptionals() {
        let parsed = ServerLinkParser.parse("http://10.0.0.1")!

        XCTAssertEqual("10.0.0.1", parsed.hostname)
        XCTAssertNil(parsed.port)
        XCTAssertNil(parsed.hub)
    }

    func testBareHostWithPortParses() {
        let parsed = ServerLinkParser.parse("soft.example.com:443")!

        XCTAssertEqual("soft.example.com", parsed.hostname)
        XCTAssertEqual(443, parsed.port)
    }

    func testBareIpv4Parses() {
        let parsed = ServerLinkParser.parse("192.168.1.10")!

        XCTAssertEqual("192.168.1.10", parsed.hostname)
        XCTAssertNil(parsed.port)
    }

    func testGarbageYieldsNull() {
        XCTAssertNil(ServerLinkParser.parse(""))
        XCTAssertNil(ServerLinkParser.parse("   "))
        XCTAssertNil(ServerLinkParser.parse("hello world"))
        XCTAssertNil(ServerLinkParser.parse("MVC1:AAAA"))
    }
}

final class ServerStoreTests: XCTestCase {
    private var defaults: UserDefaults!
    private var store: ServerStore!

    override func setUp() {
        super.setUp()
        let suiteName = "softether-tests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
        defaults.removePersistentDomain(forName: suiteName)
        store = ServerStore(defaults: defaults)
    }

    private func makeProfile(_ name: String, id: String) -> ServerProfile {
        ServerProfile(id: id, label: name, hostname: "\(name).example.com", hub: "VPN",
                      username: "u", password: "p", port: 443)
    }

    func testTrafficCounterAccumulates() {
        let p = makeProfile("a", id: "a")
        store.addUsedBytes(id: p.id, bytes: 100)
        store.addUsedBytes(id: p.id, bytes: 23)

        XCTAssertEqual(123, store.getUsedBytes(id: p.id))
    }

    func testLimitSwitchSkipsExhaustedServers() {
        store.saveServer(makeProfile("a", id: "a"))
        store.saveServer(makeProfile("b", id: "b"))
        store.trafficLimitMB = 1 // 1 MB
        store.trafficLimitEnabled = true

        store.addUsedBytes(id: "b", bytes: 2 * 1024 * 1024) // b exhausted

        store.setActiveServer("b", isUserInitiated: false)
        XCTAssertEqual("a", store.selectSwitchCandidate(currentId: "b")?.id)

        // anchor untouched by auto-switch
        store.setActiveServer("a", isUserInitiated: true)
        store.setActiveServer("b", isUserInitiated: false)
        XCTAssertEqual("a", store.anchorServerId())
        XCTAssertEqual("b", store.activeServerId())
    }

    func testDisabledLimitMeansUnlimited() {
        store.trafficLimitEnabled = false
        XCTAssertEqual(Int64.max, store.effectiveLimitBytes())
    }

    func testMacAddressPersists() {
        let first = store.loadMacAddress()
        XCTAssertEqual(6, first.count)
        XCTAssertEqual(0x5E, first[0])
        XCTAssertEqual(first, store.loadMacAddress())
    }

    func testTunnelConfigMtuDerivation() {
        var config = TunnelConfig()
        config.ethernetMTU = 1500
        config.udpAccelerationEnabled = true
        // 1500 - 20 - 8 - 23 - 12 - 16 - 14 = 1407
        XCTAssertEqual(1407, config.internalEthernetMTU)

        config.udpAccelerationEnabled = false
        XCTAssertEqual(1500, config.internalEthernetMTU)
    }
}
