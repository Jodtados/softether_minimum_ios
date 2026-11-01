// One-time activation gate — a port of Android control/AppLockManager.kt:
// a fresh install asks for a TOTP code generated from the build-time secret;
// after one correct entry the install is activated forever. A remote
// "panic lock" (force-majeur console) additionally hard-blocks the gate: no
// code is accepted until the admin lifts it. State lives in plain UserDefaults
// (not the app group: the tunnel provider never reads it).

import Foundation
import SoftEtherCore

enum AppLock {
    private static let activatedKey = "app_activated"
    private static let failedAttemptsKey = "app_failed_attempts"
    private static let lockedUntilKey = "app_locked_until"
    private static let panicKey = "app_panic"

    private static var defaults: UserDefaults { .standard }

    static func isPanicLocked() -> Bool {
        defaults.bool(forKey: panicKey)
    }

    /// true while this install still has to pass the activation gate
    static func isActivationRequired() -> Bool {
        if isPanicLocked() { return true }
        // no baked secret → nothing to gate on (builds without MGMT_B2)
        return !MgmtSecrets.totpSecret.isEmpty && !isActivated()
    }

    static func isActivated() -> Bool {
        defaults.bool(forKey: activatedKey)
    }

    @discardableResult
    static func verify(code: String, nowMillis: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        // the panic flag wins over every code, even a correct one
        if isPanicLocked() { return false }
        if code.isEmpty || cooldownRemainingSeconds(nowMillis: nowMillis) > 0 { return false }

        guard Totp.verify(secretBase32: MgmtSecrets.totpSecret, code: code, nowMillis: nowMillis) else {
            registerFailedAttempt(nowMillis: nowMillis)
            return false
        }

        defaults.set(true, forKey: activatedKey)
        defaults.removeObject(forKey: failedAttemptsKey)
        defaults.removeObject(forKey: lockedUntilKey)
        return true
    }

    /// remote admin "lock": the next app start asks for the activation code again
    static func deactivate() {
        defaults.set(false, forKey: activatedKey)
    }

    /// force-majeur: no code is accepted anymore (lifted only by panic_clear)
    static func panicLock() {
        defaults.set(true, forKey: panicKey)
        defaults.set(false, forKey: activatedKey)
    }

    static func panicClear() {
        // stays unactivated: the legit holder passes the normal gate once
        defaults.set(false, forKey: panicKey)
    }

    static func cooldownRemainingSeconds(
        nowMillis: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) -> Int {
        let lockedUntil = defaults.double(forKey: lockedUntilKey)
        return Int(max(0, (lockedUntil - Double(nowMillis)) / 1000))
    }

    private static func registerFailedAttempt(nowMillis: Int64) {
        let attempts = defaults.integer(forKey: failedAttemptsKey) + 1
        defaults.set(attempts, forKey: failedAttemptsKey)
        if attempts % mgmtMaxAttemptsPerCooldown == 0 {
            let seconds = Double(mgmtCooldownSeconds(forFailedAttempts: attempts))
            defaults.set(Double(nowMillis) + seconds * 1000, forKey: lockedUntilKey)
        }
    }
}

/// Root-level gate state: the app shows either the activation screen or the
/// real UI. Refreshed on scene activation and after every command batch so a
/// remote lock/panic_clear takes effect while the app runs.
@MainActor
final class AppLockModel: ObservableObject {
    @Published private(set) var gateRequired = AppLock.isActivationRequired()
    @Published private(set) var panicLocked = AppLock.isPanicLocked()

    func refresh() {
        gateRequired = AppLock.isActivationRequired()
        panicLocked = AppLock.isPanicLocked()
    }
}
