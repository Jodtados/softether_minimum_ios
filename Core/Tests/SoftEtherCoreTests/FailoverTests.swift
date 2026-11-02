// planFailover vectors, ported from softether_minimum FailoverPlanner logic
// (Android 0.9.0): round-robin target, backoff row 3/6/12/24/48 s, Stop rules.

import XCTest
@testable import SoftEtherCore

final class FailoverTests: XCTestCase {
    private let list = ["a", "b", "c"].map { id in
        ServerProfile(id: id, label: id, hostname: "\(id).example.com", hub: "VPN",
                      username: "u", password: "p", port: 443)
    }

    func testEmptyListStops() {
        XCTAssertEqual(.stop, planFailover(servers: [], currentId: "a", consecutiveFailures: 0, loopForever: true))
    }

    func testNextServerRoundRobinWithBackoff() {
        // first failure: b after 3 s, second: c after 6 s, then back to a after 12 s
        let first = planFailover(servers: list, currentId: "a", consecutiveFailures: 0, loopForever: true)
        XCTAssertEqual(.switchTo(targetId: "b", delayMs: 3000, attempt: 1, fullCircle: false), first)

        let second = planFailover(servers: list, currentId: "b", consecutiveFailures: 1, loopForever: true)
        XCTAssertEqual(.switchTo(targetId: "c", delayMs: 6000, attempt: 2, fullCircle: false), second)

        let third = planFailover(servers: list, currentId: "c", consecutiveFailures: 2, loopForever: true)
        XCTAssertEqual(.switchTo(targetId: "a", delayMs: 12000, attempt: 3, fullCircle: true), third)
    }

    func testBackoffCapsAt48Seconds() {
        let plan = planFailover(servers: list, currentId: "a", consecutiveFailures: 7, loopForever: true)

        XCTAssertEqual(.switchTo(targetId: "b", delayMs: 48000, attempt: 8, fullCircle: false), plan)
    }

    func testWithoutLoopEveryServerGetsOneAttempt() {
        // 3 servers, 2 failures already: the third attempt is the last one
        let last = planFailover(servers: list, currentId: "c", consecutiveFailures: 2, loopForever: false)
        XCTAssertEqual(.stop, last)

        let notLast = planFailover(servers: list, currentId: "b", consecutiveFailures: 1, loopForever: false)
        XCTAssertEqual(.switchTo(targetId: "c", delayMs: 6000, attempt: 2, fullCircle: false), notLast)
    }

    func testSingleServerLoopsOnItself() {
        let single = [list[0]]

        let plan = planFailover(servers: single, currentId: "only", consecutiveFailures: 0, loopForever: true)
        XCTAssertEqual(.switchTo(targetId: "only", delayMs: 3000, attempt: 1, fullCircle: true), plan)

        XCTAssertEqual(.stop, planFailover(servers: single, currentId: "only", consecutiveFailures: 0, loopForever: false))
    }

    func testUnknownCurrentIdFallsBackToFirstIndex() {
        // indexOfFirst misses → coerceAtLeast(0): target = servers[1]
        let plan = planFailover(servers: list, currentId: "missing", consecutiveFailures: 0, loopForever: true)
        XCTAssertEqual(.switchTo(targetId: "b", delayMs: 3000, attempt: 1, fullCircle: false), plan)
    }
}
