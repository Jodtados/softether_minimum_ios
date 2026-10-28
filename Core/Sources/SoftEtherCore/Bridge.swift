// Shared state of one tunnel connection, ported from kittoku/mvc SharedBridge.kt.
// Coroutine channels become the Mailbox below; the Android service hooks
// (protect(), foreground, notifications) are injected closures.

import Foundation

// MARK: - mailbox (kotlinx.coroutines.channels.Channel analogue)

public final class Mailbox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var buffered: [T] = []
    private var waiters: [CheckedContinuation<T, Never>] = []
    private var closed = false

    public init() {}

    public func send(_ value: T) {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        if !waiters.isEmpty {
            let continuation = waiters.removeFirst()
            lock.unlock()
            continuation.resume(returning: value)
        } else {
            buffered.append(value)
            lock.unlock()
        }
    }

    public func receive() async -> T {
        lock.lock()
        if !buffered.isEmpty {
            let value = buffered.removeFirst()
            lock.unlock()
            return value
        }
        if closed {
            lock.unlock()
            await Task.yield()
            return await receiveAgainAfterClose()
        }
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
            lock.unlock()
        }
    }

    private func receiveAgainAfterClose() async -> T {
        // Channel(1)-style mailbox used in the port never closes mid-flight in practice;
        // park forever instead of crashing the provider on teardown.
        while true { await Task.yield() }
    }

    @discardableResult
    public func tryReceive() -> T? {
        lock.lock()
        defer { lock.unlock() }
        return buffered.isEmpty ? nil : buffered.removeFirst()
    }

    public func close() {
        lock.lock()
        closed = true
        let pending = waiters
        waiters = []
        lock.unlock()
        // parked readers keep waiting (see receiveAgainAfterClose)
        _ = pending
    }

    public func clear() {
        lock.lock()
        buffered.removeAll()
        lock.unlock()
    }
}

// MARK: - control plane

public enum Where: String, Codable {
    case softEther = "SOFTETHER"
    case dhcp = "DHCP"
    case arp = "ARP"
    case control = "CONTROL"
}

public enum MvcResult: String, Codable {
    case proceeded = "PROCEEDED"
    case errTimeout = "ERR_TIMEOUT"
    case invalidConfiguration = "INVALID_CONFIGURATION"
}

public struct ControlMessage {
    public let from: Where
    public let result: MvcResult
    public let supplement: String?

    public init(from: Where, result: MvcResult, supplement: String? = nil) {
        self.from = from
        self.result = result
        self.supplement = supplement
    }
}

// MARK: - UDP acceleration state

public enum UDPStatus: String {
    case closed = "CLOSED"
    case open = "OPEN"
}

public final class UdpAccelerationConfig: @unchecked Sendable {
    public var status = UDPStatus.closed

    public var clientReportedAddress: [UInt8] = []
    public var clientNATTAddress: [UInt8]?
    public var clientReportedPort: Int = 0
    public var clientNATTPort: Int = 0
    public var clientCookie: UInt32 = 0
    public var clientKey = [UInt8](repeating: 0, count: 32)

    public var serverCurrentAddress: [UInt8]?
    public var serverReportedAddress: [UInt8] = []
    public var serverNATTAddress: [UInt8]?
    public var serverCurrentPort: Int = 0
    public var serverReportedPort: Int = 0
    public var serverNATTPort: Int = 0
    public var serverCookie: UInt32 = 0
    public var serverKey = [UInt8](repeating: 0, count: 32)

    let nattHostname: String

    public private(set) var nattAddress: [UInt8]?

    public init(random: inout some RandomNumberGenerator) {
        let hex = (0 ..< 1).map { _ in UInt8.random(in: 0 ... 255, using: &random) }
        let text = hex.map { String(format: "%02x", $0) }.joined()
        let chars = Array(text)
        nattHostname = "x\(chars[0]).x\(chars[1]).dev.servers.nat-traversal.softether-network.net"
    }

    public func initializeNATTAddress() {
        nattAddress = Resolve.ipv4(nattHostname)
    }

    public var validServerPorts: [Int] {
        var ports: [Int] = []
        if serverCurrentPort != 0 { ports.append(serverCurrentPort) }
        if serverReportedPort != 0 && serverReportedPort != serverCurrentPort { ports.append(serverReportedPort) }
        if serverNATTPort != 0 && serverNATTPort != serverCurrentPort && serverNATTPort != serverReportedPort {
            ports.append(serverNATTPort)
        }
        return ports
    }

    public var validServerAddresses: [[UInt8]] {
        var list: [[UInt8]] = []
        if let a = serverCurrentAddress { list.append(a) }
        if !serverReportedAddress.isEmpty && serverReportedAddress != serverCurrentAddress {
            list.append(serverReportedAddress)
        }
        if let a = serverNATTAddress, a != serverCurrentAddress, a != serverReportedAddress {
            list.append(a)
        }
        return list
    }
}

// MARK: - tunnel configuration (what prepareParameters() used to read from prefs)

public struct TunnelConfig: Sendable {
    public var serverPort = 443
    public var serverHostname = ""
    public var serverHubName = ""
    public var clientUsername = ""
    public var clientPassword = ""
    public var serverTrustedCertPem: String?
    public var clientMacAddress = [UInt8](repeating: 0, count: 6)

    public var sslVersion = "DEFAULT" // "DEFAULT" | "TLSv1.2" | "TLSv1.3" (others ignored)
    public var doSelectCipherSuites = false // cosmetic on Apple TLS; kept for profile parity
    public var selectedCipherSuites: [String] = []

    public var udpAccelerationEnabled = true
    public var ethernetMTU = 1500

    // derived
    public var internalEthernetMTU: Int {
        if udpAccelerationEnabled {
            return ethernetMTU - ipv4HeaderSize - udpHeaderSize - udpSoftetherHeaderSize
                - chacha20Poly1305NonceSize - chacha20Poly1305TagSize - ethernetHeaderSize
        }
        return ethernetMaxMTU
    }

    public var maxInternalFrameSize: Int { internalEthernetMTU + ethernetHeaderSize }

    public init() {}
}

// MARK: - shared bridge

public final class SharedBridge: @unchecked Sendable {
    public let config: TunnelConfig
    public let randomLock = NSLock()
    public var random = SystemRandomNumberGenerator()

    public var tcpTerminal: TcpTerminal?
    public var udpTerminal: UdpTerminal?
    public var ipTerminal: IpTerminal?

    public var clientAppName = "SoftEther"
    public var clientOsName = "iOS"
    public var clientOsVer = "17.0"

    public var rxBytes = 0 // downloaded through the tunnel
    public var txBytes = 0 // uploaded through the tunnel
    public let trafficLock = NSLock()
    public let controlMailbox = Mailbox<ControlMessage>()
    public let httpRequestChannel = Mailbox<Bool>()

    public var udpAccelerationConfig: UdpAccelerationConfig?

    // filled in during negotiation
    public var assignedIpAddress = [UInt8](repeating: 0, count: ipv4AddressSize)
    public var subnetMask = [UInt8](repeating: 0, count: ipv4AddressSize)
    public var defaultGatewayIpAddress = [UInt8](repeating: 0, count: ipv4AddressSize)
    public var defaultGatewayMacAddress = [UInt8](repeating: 0, count: ethernetMacAddressSize)
    public var dhcpServerIpAddress = [UInt8](repeating: 0, count: ipv4AddressSize)
    public var dnsServerIpAddress: [UInt8]?
    public var leaseTime: Int?

    // platform hooks
    public var onCertCaptured: ((String) -> Void)? // leaf PEM, called on TLS handshake
    public var log: ((String) -> Void)?

    public init(config: TunnelConfig) {
        self.config = config

        if config.udpAccelerationEnabled {
            var r = random
            let udpConfig = UdpAccelerationConfig(random: &r)
            random = r
            udpAccelerationConfig = udpConfig
        }
    }

    public func nextBytes(_ size: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: size)
        randomLock.lock()
        for i in 0 ..< size { out[i] = random.next() }
        randomLock.unlock()
        return out
    }

    public func nextInt() -> Int {
        randomLock.lock()
        defer { randomLock.unlock() }
        return Int(Int32(bitPattern: UInt32(truncatingIfNeeded: random.next())))
    }

    public func logReport(_ text: String) {
        log?(text)
    }
}

// MARK: - small DNS helper (getaddrinfo, IPv4)

public enum Resolve {
    public static func ipv4(_ hostname: String) -> [UInt8]? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(hostname, nil, &hints, &info) == 0, let first = info else { return nil }
        defer { freeaddrinfo(info) }

        var out: [UInt8]?
        let current = info
        if let sa = current?.pointee.ai_addr, current!.pointee.ai_family == AF_INET {
            sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                let addr = $0.pointee.sin_addr
                out = withUnsafeBytes(of: addr) { Array($0) }
            }
        }
        // first result is enough (natt hostnames resolve to a single A)
        return out
    }
}
