// Server profiles, settings and traffic counters, ported from
// kittoku/mvc control/ServerStore.kt. Persisted in UserDefaults of the
// App Group, shared between the app and the tunnel provider.

import Foundation

public let defaultLimitMB = 500
public let mb: Int64 = 1024 * 1024

public let prefServerProfiles = "SERVER_PROFILES"
public let prefActiveServerId = "ACTIVE_SERVER_ID"
public let prefAnchorServerId = "ANCHOR_SERVER_ID"
public let prefTrafficPrefix = "traffic_"
public let prefTrustedCert = "HOME_TRUSTED_CERT"

public let prefSslVersion = "SSL_VERSION"
public let prefSslDoSelectSuites = "SSL_DO_SELECT_SUITES"
public let prefSslSuites = "SSL_SUITES"
public let prefUdpEnableAcceleration = "UDP_ENABLE_ACCELERATION"
public let prefEthernetMTU = "ETHERNET_MTU"
public let prefTrafficLimitEnabled = "TRAFFIC_LIMIT_ENABLED"
public let prefTrafficLimitMB = "TRAFFIC_LIMIT_MB"
public let prefRotationIntervalMinutes = "ROTATION_INTERVAL_MINUTES"
public let prefMacAddress = "ETHERNET_MAC_ADDRESS"
public let prefStatusText = "STATUS_TEXT"
public let prefUsedBytesSnapshot = "USED_BYTES_SNAPSHOT"
public let prefServerSecret = "MVC_QR_SECRET"

public struct ServerProfile: Equatable, Codable, Identifiable {
    public var id: String
    public var label: String
    public var hostname: String
    public var hub: String
    public var username: String
    public var password: String
    public var port: Int
    public var trustedCertPem: String?

    public init(id: String = UUID().uuidString, label: String, hostname: String, hub: String,
                username: String, password: String, port: Int = 443, trustedCertPem: String? = nil) {
        self.id = id
        self.label = label
        self.hostname = hostname
        self.hub = hub
        self.username = username
        self.password = password
        self.port = port
        self.trustedCertPem = trustedCertPem
    }
}

func todayKey() -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyyMMdd"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    return formatter.string(from: Date()) // date in the key: automatic midnight reset
}

public final class ServerStore {
    public let defaults: UserDefaults

    public init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    // MARK: profiles

    public func loadServers() -> [ServerProfile] {
        guard let json = defaults.string(forKey: prefServerProfiles),
              let data = json.data(using: .utf8),
              let servers = try? JSONDecoder().decode([ServerProfile].self, from: data)
        else { return [] }
        return servers
    }

    private func saveServers(_ servers: [ServerProfile]) {
        guard let data = try? JSONEncoder().encode(servers),
              let json = String(data: data, encoding: .utf8)
        else { return }
        defaults.set(json, forKey: prefServerProfiles)
    }

    public func saveServer(_ profile: ServerProfile) {
        var servers = loadServers()
        if let index = servers.firstIndex(where: { $0.id == profile.id }) {
            servers[index] = profile
        } else {
            servers.append(profile)
        }
        saveServers(servers)
    }

    public func deleteServer(id: String) {
        saveServers(loadServers().filter { $0.id != id })
    }

    public func findServer(id: String) -> ServerProfile? {
        loadServers().first { $0.id == id }
    }

    public func activeServerId() -> String {
        defaults.string(forKey: prefActiveServerId) ?? ""
    }

    public func activeServer() -> ServerProfile? {
        findServer(id: activeServerId())
    }

    public func anchorServerId() -> String {
        defaults.string(forKey: prefAnchorServerId) ?? ""
    }

    /// Anchor = last user-initiated connect/selection; NEVER set by auto-switch/rotation.
    public func setActiveServer(_ id: String, isUserInitiated: Bool) {
        defaults.set(id, forKey: prefActiveServerId)
        if isUserInitiated {
            defaults.set(id, forKey: prefAnchorServerId)
        }
    }

    /// Trust pinned per server, stored after the user accepts the certificate.
    public func saveTrustedCert(id: String, pem: String) {
        var servers = loadServers()
        if let index = servers.firstIndex(where: { $0.id == id }) {
            servers[index].trustedCertPem = pem
            saveServers(servers)
        }
    }

    // MARK: traffic counters (daily, key contains the date)

    private func trafficKey(_ id: String) -> String {
        prefTrafficPrefix + id + "_" + todayKey()
    }

    public func getUsedBytes(id: String) -> Int64 {
        Int64(defaults.double(forKey: trafficKey(id)))
    }

    public func addUsedBytes(id: String, bytes: Int64) {
        defaults.set(Double(getUsedBytes(id: id) + bytes), forKey: trafficKey(id))
    }

    // MARK: settings

    public var sslVersion: String {
        get { defaults.string(forKey: prefSslVersion) ?? "TLSv1.3" }
        set { defaults.set(newValue, forKey: prefSslVersion) }
    }

    public var sslDoSelectSuites: Bool {
        get { defaults.object(forKey: prefSslDoSelectSuites) as? Bool ?? true }
        set { defaults.set(newValue, forKey: prefSslDoSelectSuites) }
    }

    public var sslSuites: [String] {
        get { defaults.stringArray(forKey: prefSslSuites) ?? ["TLS_AES_256_GCM_SHA384"] }
        set { defaults.set(newValue, forKey: prefSslSuites) }
    }

    public var udpAcceleration: Bool {
        get { defaults.object(forKey: prefUdpEnableAcceleration) as? Bool ?? true }
        set { defaults.set(newValue, forKey: prefUdpEnableAcceleration) }
    }

    public var ethernetMTU: Int {
        get { defaults.object(forKey: prefEthernetMTU) as? Int ?? 1500 }
        set { defaults.set(newValue, forKey: prefEthernetMTU) }
    }

    public var trafficLimitEnabled: Bool {
        get { defaults.object(forKey: prefTrafficLimitEnabled) as? Bool ?? true }
        set { defaults.set(newValue, forKey: prefTrafficLimitEnabled) }
    }

    public var trafficLimitMB: Int {
        get { defaults.object(forKey: prefTrafficLimitMB) as? Int ?? defaultLimitMB }
        set { defaults.set(newValue, forKey: prefTrafficLimitMB) }
    }

    public var rotationIntervalMinutes: Int {
        get { defaults.object(forKey: prefRotationIntervalMinutes) as? Int ?? 30 }
        set { defaults.set(newValue, forKey: prefRotationIntervalMinutes) }
    }

    public func loadMacAddress() -> [UInt8] {
        if let stored = defaults.string(forKey: prefMacAddress), stored.count == 12,
           let bytes = [UInt8].fromHexString(stored) {
            return bytes
        }

        var address: [UInt8] = [0x5E]
        address.append(contentsOf: (0 ..< 5).map { _ in UInt8.random(in: 0 ... 255) })
        defaults.set(address.toHexString(), forKey: prefMacAddress)
        return address
    }

    // MARK: limits & rotation

    /// The single daily limit is global; toggle off means no enforcement.
    public func effectiveLimitBytes() -> Int64 {
        if !trafficLimitEnabled { return Int64.max }
        return Int64(trafficLimitMB) * mb
    }

    /// Every OTHER server that still has quota today, in list order.
    public func selectSwitchCandidate(currentId: String) -> ServerProfile? {
        let limit = effectiveLimitBytes()
        return loadServers().first { $0.id != currentId && getUsedBytes(id: $0.id) < limit }
    }

    // MARK: config assembly

    public func tunnelConfig(for profile: ServerProfile) -> TunnelConfig {
        var config = TunnelConfig()
        config.serverHostname = profile.hostname
        config.serverPort = profile.port
        config.serverHubName = profile.hub
        config.clientUsername = profile.username
        config.clientPassword = profile.password
        config.serverTrustedCertPem = profile.trustedCertPem
        config.clientMacAddress = loadMacAddress()
        config.sslVersion = sslVersion
        config.doSelectCipherSuites = sslDoSelectSuites
        config.selectedCipherSuites = sslSuites
        config.udpAccelerationEnabled = udpAcceleration
        config.ethernetMTU = ethernetMTU
        return config
    }
}

extension Array where Element == UInt8 {
    public static func fromHexString(_ text: String) -> [UInt8]? {
        guard text.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(after: index)
            guard let value = UInt8(text[index ... next], radix: 16) else { return nil }
            out.append(value)
            index = text.index(after: next)
        }
        return out
    }
}

// MARK: - ServerLinkParser (control/ServerLinkParser.kt)

public enum ServerLinkParser {
    public struct ParsedServer: Equatable {
        public var hostname: String?
        public var port: Int?
        public var hub: String?
        public var username: String?
        public var password: String?

        public init(hostname: String?, port: Int?, hub: String?, username: String?, password: String?) {
            self.hostname = hostname
            self.port = port
            self.hub = hub
            self.username = username
            self.password = password
        }
    }

    public static func parse(_ raw: String) -> ParsedServer? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }

        if text.lowercased().hasPrefix("vpn://") {
            return parseVpnGate(String(text.dropFirst(6)))
        }
        if text.lowercased().hasPrefix("http://") || text.lowercased().hasPrefix("https://") {
            return parseHttp(text)
        }
        return parseBareHost(text)
    }

    private static func parseVpnGate(_ payload: String) -> ParsedServer? {
        // VPN Gate links: vpn:// + base64 of "hostname,port,..."
        let standard = payload
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        var padded = standard
        while padded.count % 4 != 0 { padded += "=" }

        guard let data = Data(base64Encoded: padded),
              let csv = String(data: data, encoding: .utf8)
        else { return parseBareHost(payload) }

        let fields = csv.split(whereSeparator: { $0 == "," || $0 == ";" }).map(String.init)
        guard let hostname = fields.first?.trimmingCharacters(in: .whitespaces), !hostname.isEmpty else {
            return nil
        }

        return ParsedServer(
            hostname: hostname,
            port: fields.count > 1 ? Int(fields[1].trimmingCharacters(in: .whitespaces)) : nil,
            hub: nil, username: nil, password: nil
        )
    }

    private static func parseHttp(_ text: String) -> ParsedServer? {
        guard let url = URL(string: text), let host = url.host else { return nil }

        func query(_ name: String) -> String? {
            guard let components = URLComponents(string: text) else { return nil }
            return components.queryItems?
                .first { $0.name.lowercased() == name }?
                .value
                .flatMap { $0.isEmpty ? nil : $0 }
        }

        var hub = query("hub") ?? query("hubname")
        if hub == nil {
            let path = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            hub = path.split(separator: "/").first.map(String.init).flatMap { $0.isEmpty ? nil : $0 }
        }

        let port: Int?
        if let p = query("port"), let v = Int(p) {
            port = v
        } else if url.port != nil, url.port! > 0 {
            port = url.port
        } else {
            port = nil
        }

        return ParsedServer(
            hostname: host, port: port, hub: hub,
            username: query("user") ?? query("username"),
            password: query("pass") ?? query("password")
        )
    }

    private static func parseBareHost(_ text: String) -> ParsedServer? {
        // host:port — a plain name or an IPv4 literal
        let hostPortPattern = #"^\[?([0-9a-zA-Z.\-_]+(?::[0-9a-fA-F]+)*?)\]?:(\d{1,5})$"#
        if let match = text.range(of: hostPortPattern, options: .regularExpression) {
            let captured = String(text[match])
            let parts = captured.split(separator: ":")
            if parts.count == 2, let port = Int(parts[1]) {
                return ParsedServer(hostname: String(parts[0]).trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
                                    port: port, hub: nil, username: nil, password: nil)
            }
        }

        let domainPattern = #"^[0-9a-zA-Z.\-_]+(\.[0-9a-zA-Z\-_]+)+$"#
        let ipv4Pattern = #"^\d{1,3}(\.\d{1,3}){3}$"#
        let isDomain = text.range(of: domainPattern, options: .regularExpression) != nil
        let isIPv4 = text.range(of: ipv4Pattern, options: .regularExpression) != nil

        guard isDomain || isIPv4 else { return nil }

        return ParsedServer(hostname: text, port: nil, hub: nil, username: nil, password: nil)
    }
}
