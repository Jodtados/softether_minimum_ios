// Connection orchestrator, ported from kittoku/mvc control/Controller.kt.
// The Android VpnService.Builder step becomes the `onEstablish` hook, supplied
// by the PacketTunnelProvider (NEPacketTunnelNetworkSettings).

import Foundation

/// Abstraction over Android's ParcelFileDescriptor (IPTerminal.kt) / NEPacketTunnelFlow.
public protocol IpTerminal: AnyObject {
    /// Reads one IPv4 packet from the OS, wrapped into an ethernet frame
    /// (dst = default gateway, src = client MAC, type = IPv4), into `buffer`.
    func retrievePacket(_ buffer: ByteBuffer) async
    /// Injects an IP packet (stripped of the ethernet header) into the OS stack.
    func writePacket(start: Int, size: Int, src: [UInt8])
}

public struct TunnelCallbacks {
    public var onEstablish: (_ assignedIp: [UInt8], _ subnetMask: [UInt8], _ dns: [UInt8]?, _ mtu: Int) async throws -> Void
    public var onFinish: (_ established: Bool, _ errorHeader: String?) -> Void
    public var onRotate: () async -> Bool // returns true when the profile was switched

    public init(
        onEstablish: @escaping ([UInt8], [UInt8], [UInt8]?, Int) async throws -> Void,
        onFinish: @escaping (Bool, String?) -> Void,
        onRotate: @escaping () async -> Bool
    ) {
        self.onEstablish = onEstablish
        self.onFinish = onFinish
        self.onRotate = onRotate
    }
}

public final class Controller: @unchecked Sendable {
    private let bridge: SharedBridge
    private let callbacks: TunnelCallbacks

    private var incomingManager: IncomingManager?
    private var outgoingManager: OutgoingManager?

    private var softEtherClient: SoftEtherClient?
    private var dhcpClient: DhcpClient?
    private var arpClient: ArpClient?

    private var jobMain: Task<Void, Never>?
    private var jobTick: Task<Void, Never>?
    private let closeMutex = NSLock()
    private var isClosing = false
    private var wasEstablished = false

    public init(bridge: SharedBridge, callbacks: TunnelCallbacks) {
        self.bridge = bridge
        self.callbacks = callbacks
    }

    public func run() {
        jobMain = Task { [weak self] in
            await self?.runMain()
        }
    }

    private func runMain() async {
        bridge.logReport("Connecting has been attempted")

        do {
            bridge.tcpTerminal = try await TcpTerminal(bridge: bridge)

            if let udpConfig = bridge.udpAccelerationConfig {
                udpConfig.initializeNATTAddress()
                bridge.udpTerminal = try UdpTerminal(bridge: bridge)
            }

            let incoming = IncomingManager(bridge: bridge)
            incomingManager = incoming
            incoming.launchJobTCP()

            // SoftEther negotiation
            let softEther = SoftEtherClient(bridge: bridge)
            softEtherClient = softEther
            incoming.registerMailbox(client: softEther)
            try await softEther.negotiate()
            guard await expectProceeded(.softEther, softEtherNegotiationTimeout) else { return }
            incoming.unregisterMailbox(client: softEther)

            // DHCP negotiation
            let dhcp = DhcpClient(bridge: bridge)
            dhcpClient = dhcp
            incoming.registerMailbox(client: dhcp)
            await dhcp.negotiate()
            guard await expectProceeded(.dhcp, dhcpNegotiationTimeout) else { return }
            incoming.unregisterMailbox(client: dhcp)

            // ARP negotiation
            let arp = ArpClient(bridge: bridge)
            arpClient = arp
            incoming.registerMailbox(client: arp)
            await arp.negotiate()
            guard await expectProceeded(.arp, arpNegotiationTimeout) else { return }
            arp.launchJobControl()

            // Establish VPN
            let config = bridge.config
            try await callbacks.onEstablish(
                bridge.assignedIpAddress, bridge.subnetMask, bridge.dnsServerIpAddress,
                config.internalEthernetMTU
            )

            outgoingManager = OutgoingManager(bridge: bridge)
            outgoingManager!.launchJobRetrieve()
            outgoingManager!.launchJobMain()

            if bridge.udpAccelerationConfig != nil {
                incoming.launchJobUDP()
            }

            bridge.logReport("VPN connection has been established")
            wasEstablished = true

            launchTickLoop()

            // wait until disconnection
            _ = await expectProceeded(.control, nil)
        } catch is CancellationError {
            kill(nil)
        } catch {
            kill(error)
        }
    }

    private func launchTickLoop() {
        jobTick = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self else { return }

                if await self.callbacks.onRotate() {
                    // profile switched; the provider restarts the tunnel
                    self.kill(nil, finishHeader: nil)
                    return
                }
            }
        }
    }

    private func expectProceeded(_ where_: Where, _ timeout: UInt64?) async -> Bool {
        let received: ControlMessage
        if let timeout {
            guard let message = await withTimeout(timeout, { [bridge] in await bridge.controlMailbox.receive() }) else {
                await finish(.errTimeout, where_, nil)
                return false
            }
            received = message
        } else {
            received = await bridge.controlMailbox.receive()
        }

        if received.result == .proceeded {
            precondition(received.from == where_)
            return true
        }

        await finish(received.result, received.from, received.supplement)
        return false
    }

    private func finish(_ result: MvcResult, _ from: Where, _ supplement: String?) async {
        let header = "\(from.rawValue): \(result.rawValue)"
        bridge.logReport(supplement == nil ? header : header + "\n" + supplement!)
        kill(nil, finishHeader: header)
    }

    private var finishReported = false

    /// Tears the connection down; reports onFinish exactly once.
    /// `finishHeader` carries the user-facing error (nil on rotation/user stop).
    public func kill(_ throwable: Error?, finishHeader: String? = nil) {
        closeMutex.lock()
        let alreadyClosing = isClosing
        isClosing = true
        let firstReport = !finishReported
        finishReported = true
        closeMutex.unlock()

        if let throwable {
            bridge.logReport("connection error: \(throwable)")
        }

        jobMain?.cancel()
        jobTick?.cancel()
        incomingManager?.cancel()
        outgoingManager?.cancel()

        bridge.tcpTerminal?.close()
        bridge.udpTerminal?.close()

        guard firstReport else { return }

        if let throwable, finishHeader == nil {
            callbacks.onFinish(wasEstablished, "MVC: ERR_UNEXPECTED")
        } else {
            callbacks.onFinish(wasEstablished, finishHeader)
        }
    }
}

// MARK: - OutgoingManager (io/outgoing of mvc)

public final class OutgoingManager: @unchecked Sendable {
    private let bridge: SharedBridge
    private let retrieveChannel = Mailbox<ByteBuffer>()
    private var jobMain: Task<Void, Never>?
    private var jobRetrieve: Task<Void, Never>?

    public init(bridge: SharedBridge) {
        self.bridge = bridge
    }

    public func launchJobMain() {
        jobMain = Task { [weak self] in
            await self?.runMain()
        }
    }

    public func launchJobRetrieve() {
        jobRetrieve = Task { [weak self] in
            await self?.runRetrieve()
        }
    }

    public func cancel() {
        jobMain?.cancel()
        jobRetrieve?.cancel()
    }

    private func runRetrieve() async {
        let bufferSize = bridge.config.internalEthernetMTU + ethernetHeaderSize
        while !Task.isCancelled {
            let buffer = ByteBuffer(capacity: bufferSize)
            await bridge.ipTerminal!.retrievePacket(buffer)

            bridge.trafficLock.lock()
            let size = buffer.remaining
            bridge.txBytes += size - ethernetHeaderSize
            bridge.trafficLock.unlock()

            retrieveChannel.send(buffer)
        }
    }

    private func runMain() async {
        let minCapacity = tcpSoftetherHeaderSize + ethernetMaxMTU
        let mainBuffer = ByteBuffer(capacity: max(16384, minCapacity * 4))

        while !Task.isCancelled {
            let firstPacket = await retrieveChannel.receive()

            // send through the UDP hole if possible
            if let udpTerminal = bridge.udpTerminal,
               let config = bridge.udpAccelerationConfig,
               config.status == .open
            {
                try? await udpTerminal.sendData(firstPacket)
                continue
            }

            mainBuffer.clear()
            mainBuffer.move(4)
            addOutgoingPacket(firstPacket, to: mainBuffer)
            var frameNum = 1

            while mainBuffer.remaining >= minCapacity {
                guard let polled = retrieveChannel.tryReceive() else { break }
                addOutgoingPacket(polled, to: mainBuffer)
                frameNum += 1
            }

            do {
                try await sendOutgoingPacket(frameNum, mainBuffer)
            } catch {
                bridge.controlMailbox.send(ControlMessage(from: .control, result: .errTimeout, supplement: "TCP send: \(error)"))
                break
            }
        }
    }

    private func addOutgoingPacket(_ buffer: ByteBuffer, to mainBuffer: ByteBuffer) {
        mainBuffer.putU32(UInt32(buffer.remaining))
        mainBuffer.put(buffer.bytes, from: buffer.position, length: buffer.remaining)
    }

    private func sendOutgoingPacket(_ frameNum: Int, _ mainBuffer: ByteBuffer) async throws {
        mainBuffer.bytes.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: frameNum.bigEndian, as: UInt32.self, at: 0)
        }
        mainBuffer.flip()
        try await bridge.tcpTerminal!.sendStream(mainBuffer)
    }
}
