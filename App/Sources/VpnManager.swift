// NETunnelProviderManager wrapper (parity with mvc's MainActivity + VpnListener).

import Foundation
import NetworkExtension

final class VpnManager {
    static let shared = VpnManager()

    private var manager: NETunnelProviderManager?

    var session: NETunnelProviderSession? {
        manager?.connection as? NETunnelProviderSession
    }

    var status: NEVPNStatus {
        session?.status ?? .invalid
    }

    /// Loads (or creates) the tunnel configuration. Must run before connect.
    func prepare() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()

        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleId
        }) {
            manager = existing
            existing.isEnabled = true
            try await existing.saveToPreferences()
            return
        }

        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleId
        proto.serverAddress = "Калькулятор"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Калькулятор"
        manager.isEnabled = true
        // the user approves the profile once; re-save keeps it active
        try await manager.saveToPreferences()
        self.manager = manager
    }

    func connect() {
        Task {
            do {
                if manager == nil {
                    try await prepare()
                }
                // saveToPreferences can invalidate the session object — reload first
                try await manager?.loadFromPreferences()
                manager?.isEnabled = true
                try await manager?.saveToPreferences()

                guard let session else { return }
                if session.status == .disconnected || session.status == .invalid {
                    try session.startTunnel(options: [:])
                } else if session.status == .connected || session.status == .connecting
                    || session.status == .reasserting
                {
                    try session.startTunnel(options: [:]) // no-op if already active
                }
            } catch {
                NSLog("[SoftEther] connect failed: %@", String(describing: error))
                // surface the failure in the app status instead of dying silently:
                // code 5 (permission denied) = the signing profile has no
                // packet-tunnel entitlement — free Apple ID / Sideloadly installs
                let text = (error as NSError).domain == "NEVPNErrorDomain" && (error as NSError).code == 5
                    ? "Ошибка: VPN-профиль запрещён подписью (нужен платный Apple Developer или установку делать через Xcode с правами на NetworkExtension)"
                    : "Ошибка: \(error.localizedDescription)"
                AppModel.sharedDefaults.set(text, forKey: prefStatusText)
            }
        }
    }

    func disconnect() {
        session?.stopTunnel()
    }
}
