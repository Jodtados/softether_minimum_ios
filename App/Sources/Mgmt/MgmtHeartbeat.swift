// Device side of remote management — a thin port of the Android admin/
// Heartbeat.kt: announces this device to the management server and silently
// applies the queued commands. iOS keeps it FOREGROUND-ONLY: the timer runs
// while the scene is active, so between launches the device reads "offline"
// in the consoles (documented limitation — iOS grants no cheap long-running
// background loop without extra entitlements; the lock state still reports
// correctly at every launch).

import Foundation
import UIKit
import SoftEtherCore

final class MgmtHeartbeat {
    static let shared = MgmtHeartbeat()
    private static let period: TimeInterval = 5 * 60
    private static let bootstrapMinInterval: TimeInterval = 15 * 60

    /// posted on the main queue after commands were applied, so the gate and
    /// the UI can refresh themselves (a remote lock must bite immediately)
    static let commandsApplied = Notification.Name("mgmt_commands_applied")

    private enum Keys {
        static let url = "mgmt_server_url"
        static let token = "mgmt_device_token"
        static let deviceId = "mgmt_device_id"
        static let userName = "mgmt_user_name"
    }

    private var timer: Timer?
    private var lastBootstrapAttempt = Date.distantPast
    /// dedicated serial queue: pulses serialize and never block the main thread
    private let queue = DispatchQueue(label: "mgmt-heartbeat")
    private var defaults: UserDefaults { .standard }

    private init() {}

    // MARK: effective config (manual pins win over the baked defaults)

    private var pinnedUrl: String { defaults.string(forKey: Keys.url) ?? "" }
    private var pinnedToken: String { defaults.string(forKey: Keys.token) ?? "" }

    var effectiveUrl: String { pinnedUrl.isEmpty ? MgmtSecrets.url : pinnedUrl }
    var effectiveDeviceToken: String { pinnedToken.isEmpty ? MgmtSecrets.deviceToken : pinnedToken }
    var isConfigured: Bool { !effectiveUrl.isEmpty && !effectiveDeviceToken.isEmpty }

    /// stable per-installation device id, generated on first use
    func deviceId() -> String {
        let existing = defaults.string(forKey: Keys.deviceId) ?? ""
        if !existing.isEmpty { return existing }
        let fresh = newDeviceId()
        defaults.set(fresh, forKey: Keys.deviceId)
        return fresh
    }

    // MARK: foreground pulse loop

    /// an immediate beat, then one every 5 minutes while the scene stays active
    func start() {
        stop()
        pulse()
        let timer = Timer(timeInterval: Self.period, target: self,
                          selector: #selector(pulseFromTimer),
                          userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    @objc private func pulseFromTimer() { pulse() }

    /// fire-and-forget pulse: announces the device and applies queued commands
    func pulse() {
        guard isConfigured else { return }
        queue.async { [weak self] in
            self?.pulseSync()
        }
    }

    private func pulseSync() {
        var reply = heartbeatOnce()
        if reply == nil {
            // dead URL or a rotated token: re-resolve via /api/bootstrap, retry once
            guard bootstrapQuietly() else { return }
            reply = heartbeatOnce()
        }
        guard let reply else { return }

        // enrollment: the server minted a personal token for this device (first
        // heartbeat with the shared token); pin it BEFORE applying commands so
        // a token riding in the same reply cannot clobber it
        if let token = reply.deviceToken, token != effectiveDeviceToken {
            defaults.set(token, forKey: Keys.token)
        }

        applyCommands(reply.commands)
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Self.commandsApplied, object: nil)
        }
    }

    @discardableResult
    private func heartbeatOnce() -> MgmtHeartbeatReply? {
        guard let response = requestSync(
            MgmtApi.shared.endpoint(effectiveUrl, "/api/hb"),
            method: "POST",
            deviceToken: effectiveDeviceToken,
            body: buildBody().encoded()
        ) else { return nil }
        return parseHeartbeatReply(response.body)
    }

    /// blocking wrapper over the callback transport for the pulse queue; the
    /// queue is dedicated, so waiting here is safe (completion always fires)
    private func requestSync(
        _ url: String, method: String, deviceToken: String = "", body: String? = nil
    ) -> MgmtResponse? {
        let semaphore = DispatchSemaphore(value: 0)
        var stored: MgmtResponse?
        MgmtApi.shared.request(url, method: method, deviceToken: deviceToken, body: body) { result in
            if case .success(let response) = result { stored = response }
            semaphore.signal()
        }
        semaphore.wait()
        return stored
    }

    // MARK: body assembly

    private func buildBody() -> MgmtHeartbeatBody {
        let store = AppModel.store
        let active = store.activeServer()

        return MgmtHeartbeatBody(
            // the console names devices after the VPN login
            user: firstNonEmpty(active?.username, defaults.string(forKey: Keys.userName)),
            device: deviceId(),
            version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
            // build number — informational only: iOS never self-updates
            vc: Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "") ?? 0,
            suite: "se",
            abi: "universal",
            role: "user",
            model: Self.deviceModel(),
            // identifierForVendor is the iOS stand-in for ANDROID_ID: stable for
            // this vendor on this device; hashed with the shared scheme
            hwid: mgmtHardwareId(rawInstallId: UIDevice.current.identifierForVendor?.uuidString ?? ""),
            locked: AppLock.isActivationRequired(),
            servers: store.loadServers().count,
            server: active.map { $0.label.isEmpty ? $0.hostname : $0.label } ?? "",
            login: active?.username ?? "",
            traffic: Self.trafficToday(store)
        )
    }

    private func firstNonEmpty(_ candidates: String?...) -> String {
        candidates.first { !($0 ?? "").isEmpty } ?? ""
    }

    /// e.g. "Apple iPhone14,2" — utsname machine is the precise hardware id
    static func deviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let mirror = Mirror(reflecting: systemInfo.machine)
        var machine = ""
        for element in mirror.children {
            guard let value = element.value as? Int8, value != 0 else { break }
            machine.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
        }
        return machine.isEmpty ? "Apple iOS" : "Apple \(machine)"
    }

    /// today's burned bytes per server, for the console traffic column;
    /// blank labels fall back to the hostname (the same rule as the row naming)
    private static func trafficToday(_ store: ServerStore) -> [String: Int64] {
        var traffic: [String: Int64] = [:]
        for server in store.loadServers().prefix(20) {
            let used = store.getUsedBytes(id: server.id)
            if used > 0 {
                let name = server.label.isEmpty ? server.hostname : server.label
                traffic[String(name.prefix(64))] = used
            }
        }
        return traffic
    }

    // MARK: bootstrap (token/server rotation channel)

    /// the baked URL/token are only a starting point: when the server moves or
    /// the token rotates, /api/bootstrap hands out the current values and they
    /// get pinned. Throttled so a dead server is not hammered.
    private func bootstrapQuietly() -> Bool {
        guard Date().timeIntervalSince(lastBootstrapAttempt) >= Self.bootstrapMinInterval else {
            return false
        }
        lastBootstrapAttempt = Date()

        guard let response = requestSync(
            MgmtApi.shared.endpoint(effectiveUrl, "/api/bootstrap"),
            method: "GET",
            deviceToken: effectiveDeviceToken
        ), let root = response.json() else { return false }

        if let server = root["server"] as? String, !server.isEmpty {
            defaults.set(server, forKey: Keys.url)
        }
        if let token = root["deviceToken"] as? String, !token.isEmpty {
            defaults.set(token, forKey: Keys.token)
        }
        return true
    }

    // MARK: commands (all applied silently, as on Android)

    private func applyCommands(_ commands: [MgmtCommand]) {
        guard !commands.isEmpty else { return }
        let store = AppModel.store

        for command in commands {
            switch command.type {
            case "servers":
                importServers(command.payload, into: store)

            case "clear_servers":
                disconnectVpn()
                store.deleteAllServers()

            case "lock":
                disconnectVpn()
                AppLock.deactivate()

            case "disconnect":
                disconnectVpn()

            case "mgmt_url":
                // the console pushes the current management address when the
                // server moves: pin it so the next pulse already goes there
                var url = command.payload.trimmingCharacters(in: .whitespacesAndNewlines)
                while url.hasSuffix("/") { url.removeLast() }
                if url.hasPrefix("https://") || url.hasPrefix("http://") {
                    defaults.set(url, forKey: Keys.url)
                }

            case "panic_lock":
                disconnectVpn()
                AppLock.panicLock()

            case "panic_clear":
                AppLock.panicClear()

            case "reconnect":
                // redial the active server in place — only if a tunnel runs
                DispatchQueue.main.async {
                    if VpnManager.shared.session?.status == .connected {
                        VpnManager.shared.connect()
                    }
                }

            case "limits":
                applyLimits(command.payload, to: store)

            case "update":
                // parsed upstream, deliberately ignored: iOS has no silent
                // self-update — builds arrive via TestFlight/Sideloadly
                break

            default:
                break
            }
        }
    }

    /// MVC1 token → server profiles with fresh ids, the same path as a manual
    /// QR import but silent. (iOS QrPayload has no v3 mgmt block: a token that
    /// carries one simply fails to decode here.)
    private func importServers(_ token: String, into store: ServerStore) {
        let secret = AppModel.qrSecret
        guard !secret.isEmpty,
              let entries = QrPayload.decode(token, key: QrPayload.deriveKey(secret)),
              !entries.isEmpty
        else { return }

        let isFirstServer = store.loadServers().isEmpty
        var firstId: String?
        for entry in entries {
            let profile = ServerProfile(
                label: entry.label.isEmpty ? entry.hostname : entry.label,
                hostname: entry.hostname,
                hub: entry.hub,
                username: entry.username,
                password: entry.password,
                port: entry.port,
                trustedCertPem: entry.certBody.map(QrPayload.pemFromBody)
            )
            firstId = firstId ?? profile.id
            store.saveServer(profile)
        }
        if isFirstServer, let firstId {
            store.setActiveServer(firstId, isUserInitiated: true)
        }
    }

    /// partial update: only the keys present in the payload are applied; the
    /// exhaustion-action/loop knobs do not exist on iOS and are skipped
    /// payload: {"limitMb":500,"enabled":true,"action":"CYCLE","loop":true}
    private func applyLimits(_ payload: String, to store: ServerStore) {
        guard let data = payload.data(using: .utf8),
              let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return }

        if let limitMb = body["limitMb"] as? Int, limitMb > 0 {
            store.trafficLimitMB = limitMb
        }
        if let enabled = body["enabled"] as? Bool {
            store.trafficLimitEnabled = enabled
        }
    }

    private func disconnectVpn() {
        DispatchQueue.main.async {
            VpnManager.shared.disconnect()
        }
    }
}
