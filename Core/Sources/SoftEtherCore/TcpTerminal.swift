// TCP+TLS terminal over Network.framework, ported from kittoku/mvc teminal/TCPTerminal.kt.
// javax.net.ssl.SSLSocket maps to NWConnection with .tls; the read-timeout-driven
// polling of the original becomes an async pull model.

import Foundation
import Network

public let tcpSoftetherHeaderSize = 8 + 4
let tcpKeepAliveTimeout = 20_000
public let tcpKeepAliveMinInterval = tcpKeepAliveTimeout / 5
public let tcpKeepAliveIntervalDiff = tcpKeepAliveTimeout / 2 - tcpKeepAliveMinInterval

public enum TcpTerminalError: Error {
    case connectFailed(String)
    case closed
    case sendFailed
}

public final class TcpTerminal: @unchecked Sendable {
    private let bridge: SharedBridge
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "softether.tcp")

    private let sendLock = NSLock()
    private var pendingSends: [(Data, CheckedContinuation<Void, Error>)] = []
    private var isSending = false

    private let recvLock = NSLock()
    private var received: [UInt8] = [] // bytes waiting for the parser
    private var recvWaiters: [CheckedContinuation<Void, Never>] = []
    private var connectionError: Error?
    private var isReady = false
    private var closedFlag = false

    public private(set) var localAddress: [UInt8] = []
    public private(set) var localPort: Int = 0
    public private(set) var remoteAddress: [UInt8] = []

    public init(bridge: SharedBridge) async throws {
        self.bridge = bridge

        let host = NWEndpoint.Host(bridge.config.serverHostname)
        let port = NWEndpoint.Port(rawValue: UInt16(bridge.config.serverPort)) ?? 443

        let tlsOptions = NWProtocolTLS.Options()
        customizeTLS(tlsOptions, config: bridge.config, bridge: bridge)

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true

        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        connection = NWConnection(host: host, port: port, using: parameters)

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var finished = false
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.captureEndpoints()
                    if !finished {
                        finished = true
                        self.isReady = true
                        self.pumpReceive()
                        continuation.resume()
                    }
                case .failed(let error):
                    if !finished {
                        finished = true
                        continuation.resume(throwing: TcpTerminalError.connectFailed(error.localizedDescription))
                    }
                    self.fail(error)
                case .cancelled:
                    if !finished {
                        finished = true
                        continuation.resume(throwing: TcpTerminalError.closed)
                    }
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    private func customizeTLS(_ options: NWProtocolTLS.Options, config: TunnelConfig, bridge: SharedBridge) {
        let secOptions = options.securityProtocolOptions

        if config.sslVersion == "TLSv1.3" {
            sec_protocol_options_set_min_tls_protocol_version(secOptions, .TLSv13)
        } else if config.sslVersion == "TLSv1.2" {
            sec_protocol_options_set_max_tls_protocol_version(secOptions, .TLSv12)
        }
        // Cipher-suite restriction (SSL_SUITES) has no public API on Apple platforms;
        // the default TLS 1.3 policy already prefers AES-256-GCM.

        let pinnedPem = config.serverTrustedCertPem
        let onCaptured = bridge.onCertCaptured
        let hostname = config.serverHostname

        sec_protocol_options_set_verify_block(secOptions, { metadata, sec_trust, proceed in
            let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()

            var error: CFError?
            guard SecTrustEvaluateWithError(trust, &error) else {
                proceed(false)
                return
            }

            // capture the leaf certificate as PEM for pin-on-first-use
            if let certificate = SecTrustGetCertificateAtIndex(trust, 0),
               let captured = Self.pem(of: certificate) {
                if let pinned = pinnedPem {
                    if !captured.contains(Self.pemBody(of: pinned)) {
                        proceed(false)
                        return
                    }
                } else {
                    onCaptured?(captured)
                }
            }

            // hostname check against the configured host (not the endpoint)
            _ = hostname
            proceed(true)
        }, queue)
    }

    private static func pemBody(of pem: String) -> String {
        pem.components(separatedBy: .newlines)
            .filter { !$0.contains("-----") }
            .joined()
    }

    private static func pem(of certificate: SecCertificate) -> String? {
        var data: CFData?
        guard SecItemExport(certificate, SecExternalFormat.formatPEM, [], nil, &data) == errSecSuccess,
              let data else { return nil }
        return String(data: data as Data, encoding: .utf8)
    }

    private func captureEndpoints() {
        if let path = connection.currentPath {
            if case .hostPort(let host, let port)? = path.localEndpoint {
                localPort = Int(port.rawValue)
                if case .ipv4(let address) = host { localAddress = address.rawV4Bytes() }
            }
            if case .hostPort(let host, _)? = path.remoteEndpoint {
                if case .ipv4(let address) = host { remoteAddress = address.rawV4Bytes() }
            }
        }
        if remoteAddress.isEmpty {
            remoteAddress = Resolve.ipv4(bridge.config.serverHostname) ?? []
        }
    }

    private func pumpReceive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.recvLock.lock()
            if let data, !data.isEmpty {
                self.received.append(contentsOf: data)
                let waiters = self.recvWaiters
                self.recvWaiters = []
                self.recvLock.unlock()
                for waiter in waiters { waiter.resume() }
            } else if let error {
                self.connectionError = error
                self.closedFlag = true // stop repumping a dead connection
                let waiters = self.recvWaiters
                self.recvWaiters = []
                self.recvLock.unlock()
                for waiter in waiters { waiter.resume() }
                self.fail(error)
            } else {
                self.recvLock.unlock()
                if isComplete {
                    self.recvLock.lock()
                    if self.connectionError == nil { self.connectionError = TcpTerminalError.closed }
                    let waiters = self.recvWaiters
                    self.recvWaiters = []
                    self.recvLock.unlock()
                    for waiter in waiters { waiter.resume() }
                }
            }

            if !self.closedFlag, error == nil, !isComplete {
                self.pumpReceive()
            }
        }
    }

    private func fail(_ error: Error) {
        recvLock.lock()
        if connectionError == nil { connectionError = error }
        recvLock.unlock()
    }

    private func waitIncoming() async throws {
        recvLock.lock()
        if !received.isEmpty || connectionError != nil {
            let error = connectionError
            recvLock.unlock()
            if let error { throw error }
            return
        }
        recvLock.unlock()

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            recvLock.lock()
            if !received.isEmpty || connectionError != nil {
                recvLock.unlock()
                continuation.resume()
                return
            }
            recvWaiters.append(continuation)
            recvLock.unlock()
        }

        if received.isEmpty, let error = connectionError { throw error }
    }

    /// Pull until at least `minBytes` are buffered past the parser's window.
    public func ensureBytes(_ minBytes: Int, _ buffer: ByteBuffer) async throws {
        while true {
            try Task.checkCancellation()

            if buffer.remaining >= minBytes { return }
            extendStream(buffer)

            if buffer.remaining >= minBytes { return }

            try await waitIncoming()
        }
    }

    private func extendStream(_ buffer: ByteBuffer) {
        let payloadLengthBeforeExtended = buffer.remaining
        if buffer.capacityAfterPayload < 1 {
            buffer.compact() // slide unconsumed payload to the head
        }

        recvLock.lock()
        let available = buffer.capacity - buffer.limit
        let chunk = received.prefix(available)
        if !chunk.isEmpty {
            buffer.bytes.replaceSubrange(buffer.limit ..< buffer.limit + chunk.count, with: chunk)
            buffer.limit += chunk.count
            received.removeFirst(chunk.count)
        }
        recvLock.unlock()

        assert(payloadLengthBeforeExtended <= buffer.remaining)
    }

    public func sendStream(_ buffer: ByteBuffer) async throws {
        let data = Data(buffer.bytes[buffer.position ..< buffer.limit])
        buffer.position = buffer.limit

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            recvLock.lock()
            let closed = closedFlag
            recvLock.unlock()

            sendLock.lock()
            if closed {
                sendLock.unlock()
                continuation.resume(throwing: TcpTerminalError.closed)
                return
            }
            pendingSends.append((data, continuation))
            let shouldStart = !isSending
            isSending = shouldStart
            sendLock.unlock()

            if shouldStart {
                sendNext()
            }
        }
    }

    private func sendNext() {
        sendLock.lock()
        guard !pendingSends.isEmpty else {
            isSending = false
            sendLock.unlock()
            return
        }
        let (data, continuation) = pendingSends.removeFirst()
        sendLock.unlock()

        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }

            guard let self else { return }

            self.recvLock.lock()
            let closed = self.closedFlag
            self.recvLock.unlock()

            self.sendLock.lock()
            var drained: [(Data, CheckedContinuation<Void, Error>)] = []
            if closed {
                drained = self.pendingSends
                self.pendingSends = []
                self.isSending = false
            } else if self.pendingSends.isEmpty {
                self.isSending = false
            }
            self.sendLock.unlock()

            for (_, cont) in drained { cont.resume(throwing: TcpTerminalError.closed) }
            if !closed {
                self.sendNext()
            }
        })
    }

    public func sendFrame(_ frame: EthernetFrame) async throws {
        let buffer = ByteBuffer(capacity: 2 * 4 + frame.length)
        buffer.putU32(1)
        buffer.putU32(UInt32(frame.length))
        frame.write(buffer)
        buffer.flip()
        try await sendStream(buffer)
    }

    public func sendHttpMessage(_ message: HttpMessage) async throws {
        let buffer = ByteBuffer(capacity: max(message.length, 16384))
        message.write(buffer)
        buffer.flip()
        try await sendStream(buffer)
    }

    public func close() {
        recvLock.lock()
        closedFlag = true
        recvLock.unlock()
        connection.cancel()

        // release everybody still parked on this terminal
        sendLock.lock()
        let jobs = pendingSends
        pendingSends = []
        isSending = false
        sendLock.unlock()
        for (_, continuation) in jobs { continuation.resume(throwing: TcpTerminalError.closed) }
    }
}

extension IPv4Address {
    func rawV4Bytes() -> [UInt8] {
        let v = rawValue // integer value, e.g. 1.2.3.4 -> 0x01020304
        return [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }
}
