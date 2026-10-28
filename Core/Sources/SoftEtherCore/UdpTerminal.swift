// UDP acceleration terminal, ported from kittoku/mvc teminal/UDPTerminal.kt.
// Uses a raw BSD datagram socket (sendto to multiple candidate endpoints,
// recvfrom with a receive timeout) and CryptoKit ChaCha20-Poly1305 — the JCE
// "ChaCha20-Poly1305" with a 12-byte IV and appended 16-byte tag maps exactly
// onto CryptoKit's combined representation.

import Foundation
import CryptoKit

public let udpCipherAlgorithm = "ChaCha20-Poly1305"
public let chacha20Poly1305KeySize = 32
public let chacha20Poly1305NonceSize = 12
public let chacha20Poly1305TagSize = 16

let udpPacketBufferSize = 1600
public let udpSoftetherHeaderSize = 23 // cookie + 2 ticks + size + flag
let udpMaxPaddingSize = 32
let udpKeepAliveTimeout = 2_100
public let udpKeepAliveMinInterval: Int = 500
public let udpKeepAliveIntervalDiff: Int = 500
let udpPacketAvailableTime: Int = 30_000

public let udpNattPort: UInt16 = 5004
public let udpNattIntervalInitial: Int = 3_000
public let udpNattIntervalMin: Int = 300_000
public let udpNattIntervalDiff: Int = 300_000

public let udpNattIpRegex = #"^IP=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"#
public let udpNattPortRegex = #"PORT=[0-9]+$"#

public enum UdpTerminalError: Error {
    case noAvailableAddress
    case socketFailed
    case sendFailed
    case decryptFailed
}

public final class UdpTerminal: @unchecked Sendable {
    private let bridge: SharedBridge
    private let config: UdpAccelerationConfig
    private let fd: Int32

    private var lastReceivedTick: Int = 0
    private var lastReceivedClientTick: Int = 0
    private var lastReceivedServerTick: Int = 0

    private let packetMutex = NSLock()

    public private(set) var localAddress: [UInt8] = []

    public init(bridge: SharedBridge) throws {
        self.bridge = bridge
        self.config = bridge.udpAccelerationConfig!

        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw UdpTerminalError.socketFailed }
        fd = descriptor

        // bind to the primary IPv4 interface address (as mvc does), else to any
        let bindAddress = Self.primaryIPv4Address()
        var sockaddr = sockaddr_in()
        sockaddr.sin_family = sa_family_t(AF_INET)
        sockaddr.sin_port = 0
        if let address = bindAddress {
            sockaddr.sin_addr = address.withUnsafeBytes { $0.load(as: in_addr.self) }
            localAddress = address
        }

        let bindResult = withUnsafePointer(to: &sockaddr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(descriptor)
            throw UdpTerminalError.socketFailed
        }

        // large receive buffer, as in mvc
        var receiveBufferSize: Int32 = 2_097_152
        setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &receiveBufferSize, socklen_t(MemoryLayout<Int32>.size))

        // 500 ms receive timeout drives the polling loops
        var timeout = timeval(tv_sec: 0, tv_usec: __darwin_suseconds_t(udpKeepAliveMinInterval * 1000))
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        if localAddress.isEmpty {
            localAddress = Self.primaryIPv4Address() ?? []
        }

        // report the socket's actual bound port
        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &boundLength)
            }
        }
        config.clientReportedAddress = localAddress
        config.clientReportedPort = Int(UInt16(bigEndian: boundAddress.sin_port))
    }

    static func primaryIPv4Address() -> [UInt8]? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        defer { freeifaddrs(ifaddr) }

        var loopback: [UInt8]?
        var candidate: [UInt8]?
        var pointer = ifaddr
        while let current = pointer {
            let interface = current.pointee
            if interface.ifa_addr!.pointee.sa_family == sa_family_t(AF_INET) {
                let name = String(cString: interface.ifa_name)
                if name.hasPrefix("lo") {
                    loopback = withUnsafeBytes(of: interface.ifa_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }) { Array($0) }
                } else if name.hasPrefix("en") || name.hasPrefix("pdp_ip") {
                    if candidate == nil {
                        candidate = withUnsafeBytes(of: interface.ifa_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }) { Array($0) }
                    }
                }
            }
            pointer = interface.ifa_next
        }
        return candidate ?? loopback
    }

    private func sockaddrFor(_ address: [UInt8], _ port: Int) -> sockaddr_in {
        var sockaddr = sockaddr_in()
        sockaddr.sin_family = sa_family_t(AF_INET)
        sockaddr.sin_port = UInt16(port).bigEndian
        sockaddr.sin_addr = address.withUnsafeBytes { $0.load(as: in_addr.self) }
        return sockaddr
    }

    public func sendPacket(_ data: [UInt8], to address: [UInt8], port: Int) throws {
        var sockaddr = sockaddrFor(address, port)
        let sent = data.withUnsafeBytes { rawBuffer -> Int in
            withUnsafePointer(to: &sockaddr) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, rawBuffer.baseAddress, data.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == data.count else { throw UdpTerminalError.sendFailed }
    }

    private func expectPacket() -> (payload: [UInt8], senderAddress: [UInt8], senderPort: Int)? {
        var buffer = [UInt8](repeating: 0, count: udpPacketBufferSize)
        var sender = sockaddr_in()
        var senderLength = socklen_t(MemoryLayout<sockaddr_in>.size)

        let received = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
            withUnsafeMutablePointer(to: &sender) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, rawBuffer.baseAddress, udpPacketBufferSize, 0, $0, &senderLength)
                }
            }
        }

        guard received >= 0 else { return nil } // EWOULDBLOCK / timeout

        var senderAddress = [UInt8]()
        withUnsafeBytes(of: sender.sin_addr) { senderAddress.append(contentsOf: $0) }
        let senderPort = Int(UInt16(bigEndian: sender.sin_port))
        return (Array(buffer[0 ..< received]), senderAddress, senderPort)
    }

    public func sendData(_ buffer: ByteBuffer) async throws {
        packetMutex.lock()
        defer { packetMutex.unlock() }

        let dataSize = buffer.remaining

        let encryptBuffer = ByteBuffer(capacity: udpPacketBufferSize)
        encryptBuffer.putU32(config.serverCookie)
        encryptBuffer.putU64(UInt64(Date().milliseconds()))
        encryptBuffer.putU64(UInt64(lastReceivedServerTick))
        encryptBuffer.putU16(UInt16(dataSize))
        encryptBuffer.putU8(0) // flag
        encryptBuffer.put(buffer.bytes, from: buffer.position, length: dataSize)
        buffer.position = buffer.limit

        let diff = bridge.config.maxInternalFrameSize - dataSize
        if diff >= 0 {
            let randomSize = abs(bridge.nextInt()) % (min(diff, udpMaxPaddingSize) + 1)
            encryptBuffer.padZero(randomSize)
        } else {
            throw UdpTerminalError.sendFailed
        }

        let nonce = bridge.nextBytes(chacha20Poly1305NonceSize)
        let key = SymmetricKey(data: config.clientKey)
        let sealed = try ChaChaPoly.seal(
            Data(encryptBuffer.bytes[0 ..< encryptBuffer.position]),
            using: key,
            nonce: ChaChaPoly.Nonce(data: Data(nonce))
        )
        // combined == nonce || ciphertext || tag; the wire format wants nonce || (ciphertext || tag)
        var packet = nonce
        packet.append(contentsOf: sealed.ciphertext)
        packet.append(contentsOf: sealed.tag)

        if config.status == .open, let address = config.serverCurrentAddress {
            try sendPacket(packet, to: address, port: config.serverCurrentPort)
        } else {
            for address in config.validServerAddresses {
                for port in config.validServerPorts {
                    try? sendPacket(packet, to: address, port: port)
                }
            }
        }
    }

    private func processNATTInformation(_ text: String) {
        guard let ipRange = text.range(of: udpNattIpRegex, options: .regularExpression),
              let portRange = text.range(of: udpNattPortRegex, options: .regularExpression)
        else { return }

        let ip = String(text[ipRange].dropFirst(3))
        let port = Int(text[portRange].dropFirst(5)) ?? 0
        config.clientNATTAddress = [UInt8].fromIPv4String(ip)
        config.clientNATTPort = port
    }

    /// Returns a positioned ByteBuffer with one decrypted data frame, or nil.
    public func tryReceivePacket() throws -> ByteBuffer? {
        let currentTime = Date().milliseconds()
        if currentTime - lastReceivedTick > udpKeepAliveTimeout {
            config.status = .closed
        }

        guard let received = expectPacket() else { return nil }
        let (payload, senderAddress, senderPort) = received

        if senderAddress == config.nattAddress {
            if let text = String(bytes: payload, encoding: .ascii) {
                processNATTInformation(text)
            }
            return nil
        }

        guard payload.count >= udpSoftetherHeaderSize else { return nil }

        let nonce = Array(payload[0 ..< chacha20Poly1305NonceSize])
        let ciphertext = Array(payload[chacha20Poly1305NonceSize...])

        guard let sealed = try? ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: Data(nonce)), ciphertext: Data(ciphertext)),
              let decrypted = try? ChaChaPoly.open(sealed, using: SymmetricKey(data: config.serverKey))
        else {
            // not for us (older key, stray packet); silently drop as mvc's AEADBadTagException path
            return nil
        }

        let decryptBuffer = ByteBuffer.wrap(Array(decrypted))
        if decryptBuffer.getU32() != config.clientCookie {
            return nil
        }

        let serverTick = Int(decryptBuffer.getU64())
        if serverTick >= lastReceivedServerTick {
            lastReceivedServerTick = serverTick
            config.serverCurrentAddress = senderAddress
            config.serverCurrentPort = senderPort
        } else if lastReceivedServerTick - serverTick >= udpPacketAvailableTime {
            return nil
        }

        let clientTick = Int(decryptBuffer.getU64())
        lastReceivedClientTick = max(clientTick, lastReceivedClientTick)
        if lastReceivedClientTick + udpPacketAvailableTime >= currentTime {
            lastReceivedTick = currentTime
        }

        config.status = currentTime - lastReceivedTick > udpKeepAliveTimeout ? .closed : .open

        let realDataSize = Int(decryptBuffer.getU16())
        decryptBuffer.move(1) // ignore flag

        if realDataSize <= 0 {
            return nil
        }

        decryptBuffer.limit = decryptBuffer.position + realDataSize
        return decryptBuffer
    }

    public func close() {
        Darwin.close(fd)
    }
}

extension Date {
    func milliseconds() -> Int {
        Int(timeIntervalSince1970 * 1000)
    }
}
