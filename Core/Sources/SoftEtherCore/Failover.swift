// Failover planning, ported from softether_minimum Android 0.9.0
// (control/FailoverPlanner.kt): given the server list and the number of
// consecutive failures, decide what happens next — in the spirit of
// ServerRotationManager.nextRotationState.

public enum FailoverDecision: Equatable {
    case switchTo(targetId: String, delayMs: Int, attempt: Int, fullCircle: Bool)
    case stop
}

/// Given the server list and the number of consecutive failures so far,
/// plan the next move after a failed dial or a dropped session.
/// - loopForever: keep rotating forever (FAILOVER_LOOP); otherwise every
///   server gets exactly one attempt before giving up.
public func planFailover(servers: [ServerProfile], currentId: String,
                         consecutiveFailures: Int, loopForever: Bool) -> FailoverDecision {
    if servers.isEmpty { return .stop }

    let attempt = consecutiveFailures + 1

    // without looping, every server gets exactly one attempt before giving up
    if !loopForever && attempt >= servers.count { return .stop }

    let index = max(servers.firstIndex { $0.id == currentId } ?? 0, 0)
    let target = servers[(index + 1) % servers.count]

    return .switchTo(
        targetId: target.id,
        delayMs: Failover.backoffBaseMs << min(attempt - 1, 4), // 3, 6, 12, 24, 48, 48... s
        attempt: attempt,
        fullCircle: attempt % servers.count == 0
    )
}

public enum Failover {
    public static let backoffBaseMs = 3000
}
