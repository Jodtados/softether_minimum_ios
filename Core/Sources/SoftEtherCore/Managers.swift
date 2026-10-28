// Incoming/Outgoing managers, ported from kittoku/mvc io/.
// The coroutine jobs of the original become structured Tasks owned by the
// manager; keepalive timers run as their own task instead of being wedged
// into the blocking receive loop.

import Foundation

public final class IncomingManager: @unchecked Sendable {
    private let bridge: SharedBridge
    private let bufferSize: Int

    private var taskTCP: Task<Void, Never>?
    private var taskUDP: Task<Void, Never>?
    private var taskKeepAlive: Task<Void, Never>?

    var nextTCPKeepAlive = 0
    var nextUDPKeepAlive = 0
    var nextUDPInquireNATT = 0

    var softEtherMailbox: Mailbox<HttpMessage>?
    var dhcpMailbox: Mailbox<EthernetFrame>?
    var arpMailbox: Mailbox<EthernetFrame>?

    public init(bridge: SharedBridge) {
        self.bridge = bridge
        self.bufferSize = max(16384, tcpSoftetherHeaderSize + ethernetMaxMTU)
    }

    public func registerMailbox(client: SoftEtherClient) { softEtherMailbox = client.mailbox }
    public func unregisterMailbox(client: SoftEtherClient) { softEtherMailbox = nil }
    public func registerMailbox(client: DhcpClient) { dhcpMailbox = client.mailbox }
    public func unregisterMailbox(client: DhcpClient) { dhcpMailbox = nil }
    public func registerMailbox(client: ArpClient) { arpMailbox = client.mailbox }
    public func unregisterMailbox(client: ArpClient) { arpMailbox = nil }

    public func launchJobTCP() {
        taskTCP = Task { [weak self] in
            await self?.runTCP()
        }
    }

    public func launchJobUDP() {
        taskUDP = Task { [weak self] in
            await self?.runUDP()
        }
        taskKeepAlive = Task { [weak self] in
            await self?.runKeepAliveTimers()
        }
    }

    public func cancel() {
        taskTCP?.cancel()
        taskUDP?.cancel()
        taskKeepAlive?.cancel()
    }

    // MARK: TCP stream loop

    private func runTCP() async {
        let buffer = ByteBuffer(capacity: bufferSize)
        buffer.limit = 0

        while !Task.isCancelled {
            do {
                if bridge.httpRequestChannel.tryReceive() == true {
                    try await relayHttpMessage(buffer)
                    continue
                }

                try await bridge.tcpTerminal!.ensureBytes(4, buffer)
                let numFrame = Int(Int32(bitPattern: buffer.getU32()))

                if Int32(numFrame) == keepAliveFrameNum {
                    buffer.move(-4)
                    try await processKeepAlivePacket(buffer)
                    continue
                }

                for _ in 0 ..< numFrame {
                    try await bridge.tcpTerminal!.ensureBytes(4, buffer)
                    let frameSize = Int(buffer.getU32())
                    try await bridge.tcpTerminal!.ensureBytes(frameSize, buffer)

                    guard frameSize > ethernetHeaderSize else {
                        buffer.move(frameSize)
                        continue
                    }

                    if !isToMeFrame(buffer, bridge.config.clientMacAddress) {
                        buffer.move(frameSize) // discard frame
                        continue
                    }

                    if isToMePacket(buffer, bridge.assignedIpAddress) && !isDhcpPacket(buffer) {
                        processDataPacket(frameSize, buffer)
                        continue
                    }

                    let frame = EthernetFrame()
                    frame.readWithGivenSize(frameSize, buffer)

                    if frame.etherType == etherTypeARP {
                        arpMailbox?.send(frame)
                        continue
                    }

                    if frame.payloadIPv4Packet?.payloadUDPDatagram?.payloadDhcpMessage != nil {
                        dhcpMailbox?.send(frame)
                        continue
                    }
                }
            } catch is CancellationError {
                break
            } catch {
                bridge.logReport("incoming tcp loop: \(error)")
                bridge.controlMailbox.send(ControlMessage(from: .control, result: .errTimeout, supplement: "TCP: \(error)"))
                break
            }
        }
    }

    // MARK: UDP stream loop

    private func runUDP() async {
        while !Task.isCancelled {
            guard let terminal = bridge.udpTerminal else { break }

            let received: ByteBuffer?
            do {
                received = try terminal.tryReceivePacket()
            } catch {
                continue
            }

            guard let buffer = received else {
                await Task.yield()
                continue
            }

            let frameSize = buffer.remaining
            guard frameSize > ethernetHeaderSize else { continue }

            if !isToMeFrame(buffer, bridge.config.clientMacAddress) {
                continue
            }

            if isToMePacket(buffer, bridge.assignedIpAddress) && !isDhcpPacket(buffer) {
                processDataPacket(frameSize, buffer)
                continue
            }

            let frame = EthernetFrame()
            frame.readWithGivenSize(frameSize, buffer)

            if frame.etherType == etherTypeARP {
                arpMailbox?.send(frame)
                continue
            }

            if frame.payloadIPv4Packet?.payloadUDPDatagram?.payloadDhcpMessage != nil {
                dhcpMailbox?.send(frame)
                continue
            }
        }
    }

    // MARK: keepalive / NATT timers

    private func runKeepAliveTimers() async {
        while !Task.isCancelled {
            do {
                try await sendTCPKeepAliveIfNeeded(force: false)
                try await sendUDPKeepAliveIfNeeded()
                try await sendUDPInquireNATTIfNeeded()
                try await Task.sleep(nanoseconds: 200_000_000)
            } catch {
                break
            }
        }
    }

    private func sendTCPKeepAliveIfNeeded(force: Bool = false) async throws {
        let now = Date().milliseconds()
        guard now > nextTCPKeepAlive else { return }

        let packet = KeepAlivePacket()
        packet.nattAddress = bridge.udpAccelerationConfig?.clientNATTAddress
        packet.nattPort = bridge.udpAccelerationConfig?.clientNATTPort ?? 0
        var random = SystemRandomNumberGenerator()
        packet.preparePacket(&random)

        let buffer = ByteBuffer(capacity: packet.length)
        packet.write(buffer)
        buffer.flip()
        try await bridge.tcpTerminal!.sendStream(buffer)

        nextTCPKeepAlive = now + tcpKeepAliveMinInterval
            + abs(bridge.nextInt()) % tcpKeepAliveIntervalDiff
    }

    private func sendUDPKeepAliveIfNeeded() async throws {
        guard let terminal = bridge.udpTerminal else { return }

        let now = Date().milliseconds()
        guard now > nextUDPKeepAlive else { return }

        try await terminal.sendData(ByteBuffer(capacity: 0))

        nextUDPKeepAlive = now + udpKeepAliveMinInterval
            + abs(bridge.nextInt()) % udpKeepAliveIntervalDiff
    }

    private func sendUDPInquireNATTIfNeeded() async throws {
        guard let terminal = bridge.udpTerminal,
              let config = bridge.udpAccelerationConfig,
              let nattAddress = config.nattAddress
        else { return }

        let now = Date().milliseconds()
        guard now > nextUDPInquireNATT else { return }

        try terminal.sendPacket(Array("B".utf8), to: nattAddress, port: Int(udpNattPort))

        let interval: Int
        if config.status == .open {
            interval = udpNattIntervalMin + abs(bridge.nextInt()) % udpNattIntervalDiff
        } else {
            interval = udpNattIntervalInitial
        }

        nextUDPInquireNATT = now + interval
    }

    // MARK: helpers

    private func processDataPacket(_ frameSize: Int, _ buffer: ByteBuffer) {
        let packetSize = frameSize - ethernetHeaderSize

        if let ipTerminal = bridge.ipTerminal {
            bridge.trafficLock.lock()
            bridge.rxBytes += packetSize
            bridge.trafficLock.unlock()
            // writePacket receives the frame start and strips the ethernet header itself
            ipTerminal.writePacket(start: buffer.position, size: frameSize, src: buffer.bytes)
        }

        buffer.move(frameSize)
    }

    private func processKeepAlivePacket(_ buffer: ByteBuffer) async throws {
        try await bridge.tcpTerminal!.ensureBytes(8, buffer)
        let frameSize = Int(buffer.probeU32(4))
        try await bridge.tcpTerminal!.ensureBytes(frameSize + 8, buffer)

        let packet = KeepAlivePacket()
        packet.read(buffer)

        if let config = bridge.udpAccelerationConfig {
            packet.extractNATTInfo()

            if packet.nattPort != 0 {
                config.serverNATTPort = packet.nattPort
            }

            if let address = packet.nattAddress {
                config.serverNATTAddress = address
            }
        }
    }

    private let httpSuffix: [UInt8] = Array("\r\n\r\n".utf8)

    private func relayHttpMessage(_ buffer: ByteBuffer) async throws {
        var header = ""

        while true {
            try Task.checkCancellation()
            try await bridge.tcpTerminal!.ensureBytes(httpSuffix.count, buffer)

            if let startSuffix = buffer.indexOf(httpSuffix) {
                header += String(bytes: buffer.bytes[buffer.position ..< startSuffix], encoding: .utf8) ?? ""
                buffer.position = startSuffix + httpSuffix.count
                break
            }

            // keep the last 3 bytes: the suffix may be fragmented
            header += String(bytes: buffer.bytes[buffer.position ..< buffer.limit - 3], encoding: .utf8) ?? ""
            buffer.position = buffer.limit - 3
            try await bridge.tcpTerminal!.ensureBytes(buffer.limit + 1, buffer)
        }

        let message = HttpMessage()
        let lines = header.components(separatedBy: "\r\n")
        for (i, line) in lines.enumerated() {
            if i == 0 {
                message.startLine = line
            } else if let delimiterIndex = line.range(of: ": ") {
                message.setField(String(line[..<delimiterIndex.lowerBound]),
                                 String(line[delimiterIndex.upperBound...]))
            }
        }

        if let contentLengthText = message.fields["Content-Length"], let contentLength = Int(contentLengthText) {
            var body = [UInt8](repeating: 0, count: contentLength)
            var writeStart = 0

            while writeStart < contentLength {
                try await bridge.tcpTerminal!.ensureBytes(1, buffer)
                let writeSize = min(contentLength - writeStart, buffer.remaining)
                body.replaceSubrange(writeStart ..< writeStart + writeSize, with: buffer.get(writeSize))
                writeStart += writeSize
            }

            message.body = body
        }

        softEtherMailbox?.send(message)
    }
}
