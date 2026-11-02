// PacketTunnelProvider for SoftEther (iOS port of kittoku/mvc service layer).

import Foundation
import NetworkExtension
import SoftEtherCore

let appGroupId = "group.com.jodtados.softether"

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var controller: Controller?
    private var flowTerminal: FlowTerminal?
    private var defaults: UserDefaults?
    private var store: ServerStore?
    private var rotationStartedAt: Date?

    // failover cycle state (service/SoftEtherVpnService.kt, Android 0.9.0/0.9.1);
    // reset on establish and on a fresh user intent
    private var consecutiveFailures = 0
    // some servers (SoftEther 5.x) drop the dial when UDP acceleration is
    // requested: the flag gives the next dial a TCP-only path
    private var udpDisabledForNextDial = false
    private var dialedWithUdp = false
    private var failoverTask: Task<Void, Never>?

    enum StartKind { case freshUser, plannedSwitch, failoverSwitch }
    private var nextStartKind: StartKind = .freshUser

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let sharedDefaults = UserDefaults(suiteName: appGroupId)
        defaults = sharedDefaults
        store = sharedDefaults.map(ServerStore.init(defaults:))

        guard let store,
              let profile = store.activeServer(),
              !profile.hostname.isEmpty
        else {
            completionHandler(TunnelError.noServerConfigured)
            return
        }

        var config = store.tunnelConfig(for: profile)

        // failover bookkeeping: a fresh user intent retries UDP acceleration,
        // a planned move (rotation/limit) dials fresh too; a failover switch
        // keeps the current flags (the circle stays TCP-only once tripped)
        let startKind = nextStartKind
        nextStartKind = .freshUser
        if startKind == .freshUser { consecutiveFailures = 0 }
        if startKind != .failoverSwitch { udpDisabledForNextDial = false }
        if udpDisabledForNextDial { config.udpAccelerationEnabled = false }
        dialedWithUdp = config.udpAccelerationEnabled

        // app-supplied overrides (rotation restarts reuse the same mechanism)
        if let hostname = options?["hostname"] as? String { config.serverHostname = hostname }
        if let hub = options?["hub"] as? String { config.serverHubName = hub }
        if let username = options?["username"] as? String { config.clientUsername = username }
        if let password = options?["password"] as? String { config.clientPassword = password }
        if let port = options?["port"] as? Int { config.serverPort = port }

        let bridge = SharedBridge(config: config)
        bridge.clientOsVer = ProcessInfo.processInfo.operatingSystemVersionString

        // pin-on-first-use: the captured leaf PEM goes back into the profile
        let profileId = profile.id
        let certDefaults = sharedDefaults
        bridge.onCertCaptured = { pem in
            guard let store = self.store else { return }
            if store.findServer(id: profileId)?.trustedCertPem == nil {
                store.saveTrustedCert(id: profileId, pem: pem)
                _ = certDefaults // profile table is shared through the same defaults
            }
        }

        bridge.log = { text in
            NSLog("[SoftEther] %@", text)
        }

        let terminal = FlowTerminal(flow: packetFlow, bridge: bridge)
        flowTerminal = terminal
        bridge.ipTerminal = terminal

        let callbacks = TunnelCallbacks(
            onEstablish: { [weak self] assignedIp, subnetMask, dns, mtu in
                try await self?.applyNetworkSettings(assignedIp: assignedIp, subnetMask: subnetMask, dns: dns, mtu: mtu)
            },
            onFinish: { [weak self] established, errorHeader in
                self?.handleFinish(established: established, errorHeader: errorHeader)
            },
            onRotate: { [weak self] in
                await self?.tickRotationAndLimit() ?? false
            }
        )

        let controller = Controller(bridge: bridge, callbacks: callbacks)
        self.controller = controller
        rotationStartedAt = Date()

        // the handshake result decides the start outcome; the tunnel keeps
        // running after establishment and reports disconnects via displayStatus
        finishLock.lock()
        pendingStartCompletion = completionHandler
        startCompleted = false
        pendingRotationRestart = false
        finishLock.unlock()

        publishStatus(text: "Подключение…")
        controller.run()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        isStopping = true
        failoverTask?.cancel()
        controller?.kill(nil)
        controller = nil
        setTunnelNetworkSettings(nil) { _ in }
        publishStatus(text: "Отключено")
        completionHandler()
    }

    // MARK: network settings

    private func applyNetworkSettings(assignedIp: [UInt8], subnetMask: [UInt8], dns: [UInt8]?, mtu: Int) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv4Settings = NEIPv4Settings(addresses: [assignedIp.ipv4String], subnetMasks: [subnetMask.ipv4String])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings

        if let dns {
            settings.dnsSettings = NEDNSSettings(servers: [dns.ipv4String])
        }

        settings.mtu = NSNumber(value: mtu)

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    // MARK: start completion bridging

    private let finishLock = NSLock()
    private var pendingStartCompletion: ((Error?) -> Void)?
    private var startCompleted = false
    private var isStopping = false
    private var pendingRotationRestart = false

    private func handleFinish(established: Bool, errorHeader: String?) {
        finishLock.lock()
        let firstCompletion = !startCompleted
        startCompleted = true
        let completion = pendingStartCompletion
        pendingStartCompletion = nil
        let shouldRestart = pendingRotationRestart
        pendingRotationRestart = false
        finishLock.unlock()

        if established { consecutiveFailures = 0 } // reset on establish

        if let completion {
            if established {
                // established once — the start call already succeeded
                completion(nil)
                publishStatus(text: "Подключено")
            } else {
                // dial failed: report success so the tunnel stays alive and the
                // failover cycle runs inside it (status text stays truthful)
                completion(nil)
                scheduleFailover(dialFailure: true, errorHeader: errorHeader)
            }
            return
        }

        if shouldRestart, !isStopping {
            // limit / rotation switch: reconnect with the new active profile
            nextStartKind = .plannedSwitch
            restart()
            return
        }

        if isStopping {
            publishStatus(text: errorHeader == nil ? "Отключено" : "Ошибка: \(errorHeader!)")
            return
        }

        // a dial that never came up, or a live session that died on its own:
        // plan the move to the next server (0.9.0), don't just drop the tunnel
        scheduleFailover(dialFailure: !established, errorHeader: errorHeader)
    }

    // MARK: failover (scheduleFailover/failoverNow, Android 0.9.0 + 0.9.1)

    private func scheduleFailover(dialFailure: Bool, errorHeader: String?) {
        guard !isStopping, let store else { return }

        // a dial that died with UDP acceleration requested gets one TCP-only retry of the
        // SAME server before the circle moves on: SoftEther 5.x drops such sessions at once
        if dialFailure && dialedWithUdp && !udpDisabledForNextDial {
            udpDisabledForNextDial = true
            publishStatus(text: "Подключение…")
            failoverTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                self?.failoverNow(targetId: nil) // nil = same server, now TCP-only
            }
            return
        }

        let plan = planFailover(
            servers: store.loadServers(),
            currentId: store.activeServerId(),
            consecutiveFailures: consecutiveFailures,
            loopForever: store.failoverLoop
        )

        switch plan {
        case .stop:
            publishStatus(text: "Не удалось подключиться: серверы недоступны")
            cancelTunnelWithError(nil)

        case let .switchTo(targetId, delayMs, attempt, fullCircle):
            consecutiveFailures = attempt

            let label = store.findServer(id: targetId)?.label.trimmingCharacters(in: .whitespaces)
            let server = (label?.isEmpty == false) ? label! : "сервер"
            // no popup notification (0.9.2): only the persistent status updates
            publishStatus(text: fullCircle
                ? "Все серверы недоступны — продолжаю по кругу"
                : "Переподключение к \(server) через \(delayMs / 1000) с…")

            failoverTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
                self?.failoverNow(targetId: targetId)
            }
        }
    }

    private func failoverNow(targetId: String?) {
        guard !isStopping, let store else { return }

        // the list may have changed while the backoff was running
        let servers = store.loadServers()
        guard !servers.isEmpty else {
            publishStatus(text: "Не удалось подключиться: серверы недоступны")
            cancelTunnelWithError(nil)
            return
        }

        // nil target = the TCP-only retry of the same (still active) server
        let target = targetId.flatMap { id in servers.first { $0.id == id } }
            ?? store.activeServer()
            ?? servers[0]

        store.setActiveServer(target.id, isUserInitiated: false)
        nextStartKind = .failoverSwitch
        restart()
    }

    private func restart() {
        controller = nil
        flowTerminal = nil
        startTunnel(options: [:]) { [weak self] error in
            if let error {
                NSLog("[SoftEther] restart failed: %@", String(describing: error))
                self?.publishStatus(text: "Ошибка: \(error.localizedDescription)")
                self?.cancelTunnelWithError(nil)
            }
        }
    }

    private func publishStatus(text: String) {
        defaults?.set(text, forKey: prefStatusText)
    }

    // MARK: traffic limit + rotation (1s tick from the Controller)

    private func tickRotationAndLimit() async -> Bool {
        guard let store, let defaults else { return false }
        guard let bridge = controllerBridge else { return false }

        bridge.trafficLock.lock()
        let rx = Int64(bridge.rxBytes)
        let tx = Int64(bridge.txBytes)
        bridge.rxBytes = 0
        bridge.txBytes = 0
        bridge.trafficLock.unlock()

        let profileId = store.activeServerId()
        if !profileId.isEmpty {
            store.addUsedBytes(id: profileId, bytes: rx &+ tx)
            defaults.set(Double(store.getUsedBytes(id: profileId)), forKey: prefUsedBytesSnapshot)
        }

        // daily limit: switch to the next server with quota left
        let limit = store.effectiveLimitBytes()
        if !profileId.isEmpty, store.getUsedBytes(id: profileId) >= limit {
            if let candidate = store.selectSwitchCandidate(currentId: profileId) {
                store.setActiveServer(candidate.id, isUserInitiated: false)
                publishStatus(text: "Лимит: переключение на «\(candidate.label)»")
                finishLock.lock()
                pendingRotationRestart = true
                finishLock.unlock()
                return true // controller kills itself; we restart below
            }

            publishStatus(text: "Лимит исчерпан")
            return false
        }

        // timed rotation between servers with quota
        if let startedAt = rotationStartedAt,
           Date().timeIntervalSince(startedAt) > Double(store.rotationIntervalMinutes * 60),
           let candidate = store.selectSwitchCandidate(currentId: profileId)
        {
            store.setActiveServer(candidate.id, isUserInitiated: false)
            publishStatus(text: "Ротация: «\(candidate.label)»")
            finishLock.lock()
            pendingRotationRestart = true
            finishLock.unlock()
            return true
        }

        return false
    }

    private var controllerBridge: SharedBridge? {
        // the bridge reference travels through FlowTerminal
        flowTerminal?.bridge
    }

    enum TunnelError: LocalizedError {
        case noServerConfigured
        case handshake(String)

        var errorDescription: String? {
            switch self {
            case .noServerConfigured: return "Активный сервер не настроен"
            case .handshake(let header): return "Не удалось подключиться: \(header)"
            }
        }
    }
}

// MARK: - packetFlow adapter (IPTerminal.kt)

final class FlowTerminal: IpTerminal {
    let flow: NEPacketTunnelFlow
    let bridge: SharedBridge

    init(flow: NEPacketTunnelFlow, bridge: SharedBridge) {
        self.flow = flow
        self.bridge = bridge
    }

    func retrievePacket(_ buffer: ByteBuffer) async {
        let mtu = bridge.config.internalEthernetMTU

        while true {
            let (packets, _) = await flow.readPackets()

            for packet in packets {
                guard packet.count <= mtu, let first = packet.first, first >> 4 == 4 else {
                    continue // IPv4 only, like mvc
                }

                buffer.clear()
                buffer.put(bridge.defaultGatewayMacAddress)
                buffer.put(bridge.config.clientMacAddress)
                buffer.putU16(etherTypeIPv4)
                packet.withUnsafeBytes { raw in
                    buffer.put(Array(raw.bindMemory(to: UInt8.self)))
                }
                buffer.flip()
                return
            }
        }
    }

    func writePacket(start: Int, size: Int, src: [UInt8]) {
        guard size > ethernetHeaderSize, start + size <= src.count else { return }

        let ipPacket = Array(src[(start + ethernetHeaderSize) ..< (start + size)])
        flow.writePackets([Data(ipPacket)], withProtocols: [NSNumber(value: AF_INET)])
    }
}
