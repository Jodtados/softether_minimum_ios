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

        if let completion {
            if established {
                // established once — the start call already succeeded
                completion(nil)
                publishStatus(text: "Подключено")
            } else {
                completion(TunnelError.handshake(errorHeader ?? "ERR"))
                publishStatus(text: "Ошибка: \(errorHeader ?? "ERR")")
                return
            }
        }

        if shouldRestart, !isStopping {
            // limit / rotation switch: reconnect with the new active profile
            restart()
            return
        }

        publishStatus(text: errorHeader == nil ? "Отключено" : "Ошибка: \(errorHeader!)")

        // a live session that died on its own: stop the configuration
        if established, !isStopping {
            cancelTunnelWithError(nil)
        }
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
