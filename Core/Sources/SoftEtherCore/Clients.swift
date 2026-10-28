// SoftEther / DHCP / ARP negotiation clients, ported from kittoku/mvc client/.

import Foundation

public let softEtherNegotiationTimeout: UInt64 = 30_000_000_000
public let dhcpResendMessageTimeout: UInt64 = 3_000_000_000
public let dhcpNegotiationTimeout: UInt64 = 30_000_000_000
public let arpNegotiationTimeout: UInt64 = 30_000_000_000

let defaultUserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
let httpKeepAlive = "timeout=15; max=19"
let http200Header = "HTTP/1.1 200 OK"
let udpAccelerationV2KeySize = 128

// MARK: - SoftEtherClient

public final class SoftEtherClient {
    public let mailbox = Mailbox<HttpMessage>()
    private let bridge: SharedBridge
    private var receivedPack: PropertyPack?

    public init(bridge: SharedBridge) {
        self.bridge = bridge
    }

    public func negotiate() async throws {
        try await uploadWatermark()
        try await uploadProperties()

        bridge.httpRequestChannel.send(false) // switch the TCP loop to binary frames
        bridge.controlMailbox.send(ControlMessage(from: .softEther, result: .proceeded))
    }

    private func uploadWatermark() async throws {
        let randomSize = abs(bridge.nextInt()) % 2000
        let bodySize = WATERMARK.count + randomSize

        var body = WATERMARK
        body.append(contentsOf: bridge.nextBytes(randomSize))

        let request = HttpMessage()
        request.startLine = "POST /vpnsvc/connect.cgi HTTP/1.1"
        request.setField("Host", bridge.config.serverHostname)
        request.setField("Content-Type", "image/jpeg")
        request.setField("Content-Length", String(bodySize))
        request.setField("Connection", "Keep-Alive")
        request.body = body

        try await bridge.tcpTerminal!.sendHttpMessage(request)
        bridge.httpRequestChannel.send(true)

        let response = await mailbox.receive()

        let pack = PropertyPack()
        pack.read(ByteBuffer.wrap(response.body ?? []))
        receivedPack = pack

        guard response.startLine == http200Header,
              pack.intProperties[sepError] == nil,
              pack.bytesProperties[sepRandom] != nil
        else {
            throw MvcError.assertion("watermark rejected: \(response.startLine)")
        }
    }

    private func calcSecurePassword() -> [UInt8] {
        let password = Array(bridge.config.clientPassword.utf8)
        let uppercaseUsername = Array(bridge.config.clientUsername.uppercased().utf8)

        let hashedPassword = hashSha0(password + uppercaseUsername)

        return hashSha0(hashedPassword + (receivedPack!.bytesProperties[sepRandom] ?? []))
    }

    private func preparePropertyPack() -> [UInt8] {
        let pack = PropertyPack()
        let appName = bridge.clientAppName

        pack.intProperties[sepBuild] = compatibleBuild
        pack.intProperties[sepVersion] = compatibleVersion
        pack.bytesProperties[sepUniqueIdCamel] = bridge.nextBytes(16)
        pack.bytesProperties[sepUniqueIdSnake] = bridge.nextBytes(20) // pseudo implementation
        pack.intProperties[sepClientBuild] = compatibleBuild
        pack.intProperties[sepClientId] = 0
        pack.asciiProperties[sepClientStr] = appName
        pack.intProperties[sepClientVer] = compatibleVersion
        pack.asciiProperties[sepClientHostname] = "ios-\(String(bridge.nextInt() & 0xFFFFFF, radix: 16))"
        pack.addressProperties[sepClientIpAddress] = bridge.tcpTerminal?.localAddress ?? [UInt8](repeating: 0, count: 4)
        pack.asciiProperties[sepClientOsName] = bridge.clientOsName
        pack.asciiProperties[sepClientOsVer] = bridge.clientOsVer
        pack.intProperties[sepClientPort] = bridge.tcpTerminal?.localPort ?? 0
        pack.intProperties[sepClientProductBuild] = compatibleBuild
        pack.asciiProperties[sepClientProductName] = appName
        pack.intProperties[sepClientProductVer] = compatibleVersion
        pack.asciiProperties[sepHello] = appName

        pack.intProperties[sepProxyPort] = 0
        pack.addressProperties[sepProxyIpAddress] = [UInt8](repeating: 0, count: ipv4AddressSize)

        pack.asciiProperties[sepServerHostname] = bridge.config.serverHostname
        pack.addressProperties[sepServerIpAddress] = bridge.tcpTerminal?.remoteAddress ?? [UInt8](repeating: 0, count: 4)
        pack.intProperties[sepServerPort2] = bridge.config.serverPort
        pack.intProperties[sepServerProductBuild] = receivedPack?.intProperties[sepBuild] ?? 0
        pack.asciiProperties[sepServerProductName] = receivedPack?.asciiProperties[sepHello] ?? ""
        pack.intProperties[sepServerProductVer] = receivedPack?.intProperties[sepVersion] ?? 0

        pack.asciiProperties[sepMethod] = "login"
        pack.intProperties[sepAuthType] = 1
        pack.asciiProperties[sepUsername] = bridge.config.clientUsername
        pack.intProperties[sepProtocol] = 0
        pack.asciiProperties[sepHubName] = bridge.config.serverHubName
        pack.booleanProperties[sepUseEncrypt] = true
        pack.booleanProperties[sepUseCompress] = false
        pack.intProperties[sepMaxConnection] = 1
        pack.intProperties[sepHalfConnection] = 0
        pack.bytesProperties[sepSecurePassword] = calcSecurePassword()
        pack.bytesProperties[sepPenCore] = bridge.nextBytes(abs(bridge.nextInt()) % 1000)

        if let config = bridge.udpAccelerationConfig {
            pack.booleanProperties[sepUseUdpAcceleration] = true
            pack.intProperties[sepUdpVersion] = 2
            pack.intProperties[sepUdpMaxVersion] = 2
            pack.addressProperties[sepUdpClientIp] = config.clientReportedAddress
            pack.intProperties[sepUdpClientPort] = config.clientReportedPort
            pack.booleanProperties[sepUdpSupportFastDisconnectDetect] = true

            let keyBytes = bridge.nextBytes(udpAccelerationV2KeySize)
            config.clientKey = Array(keyBytes.prefix(chacha20Poly1305KeySize))
            pack.bytesProperties[sepUdpClientKeyV2] = keyBytes
        }

        let buffer = ByteBuffer(capacity: pack.length)
        pack.write(buffer)
        return buffer.bytes
    }

    private func uploadProperties() async throws {
        let body = preparePropertyPack()

        let request = HttpMessage()
        request.startLine = "POST /vpnsvc/vpn.cgi HTTP/1.1"
        request.body = body
        request.setField("Host", bridge.config.serverHostname)
        request.setField("Content-Type", "application/octet-stream")
        request.setField("Content-Length", String(body.count))
        request.setField("Connection", "Keep-Alive")
        request.setField("Keep-Alive", httpKeepAlive)

        try await bridge.tcpTerminal!.sendHttpMessage(request)
        bridge.httpRequestChannel.send(true)

        let response = await mailbox.receive()

        let pack = PropertyPack()
        pack.read(ByteBuffer.wrap(response.body ?? []))

        guard response.startLine == http200Header, pack.intProperties[sepError] == nil else {
            throw MvcError.assertion("login rejected: \(response.startLine)")
        }

        if let config = bridge.udpAccelerationConfig {
            guard pack.intProperties[sepUdpVersion] == 2,
                  pack.booleanProperties[sepUdpUseEncryption] == true,
                  pack.booleanProperties[sepUdpEnableFastDisconnectDetect] == true
            else {
                throw MvcError.assertion("udp acceleration denied")
            }

            guard let clientCookie = pack.intProperties[sepUdpClientCookie],
                  let serverAddress = pack.addressProperties[sepUdpServerIp],
                  let serverPort = pack.intProperties[sepUdpServerPort],
                  let serverCookie = pack.intProperties[sepUdpServerCookie],
                  let serverKey = pack.bytesProperties[sepUdpServerKeyV2]
            else {
                throw MvcError.assertion("udp acceleration fields missing")
            }

            config.clientCookie = UInt32(bitPattern: Int32(clientCookie))
            config.serverReportedAddress = serverAddress
            config.serverReportedPort = serverPort
            config.serverCookie = UInt32(bitPattern: Int32(serverCookie))
            config.serverKey = Array(serverKey.prefix(chacha20Poly1305KeySize))
        }
    }
}

// MARK: - DhcpClient

public final class DhcpClient {
    public let mailbox = Mailbox<EthernetFrame>()
    private let bridge: SharedBridge

    public init(bridge: SharedBridge) {
        self.bridge = bridge
    }

    /// Result of one DHCP sub-sequence: `retry` (timeout — resend), `failed`
    /// (the tunnel is dead — abort, the error already went to controlMailbox)
    /// or the reply message.
    private enum SequenceOutcome {
        case retry
        case failed
        case done(DhcpMessage)
    }

    public func negotiate() async {
        while !Task.isCancelled {
            let offer: DhcpMessage
            switch await startDiscoverOfferSequence() {
            case .retry: continue
            case .failed:
                bridge.controlMailbox.send(ControlMessage(from: .dhcp, result: .errTimeout))
                return
            case .done(let message): offer = message
            }

            let ack: DhcpMessage
            switch await startRequestAckSequence(offer) {
            case .retry: continue
            case .failed:
                bridge.controlMailbox.send(ControlMessage(from: .dhcp, result: .errTimeout))
                return
            case .done(let message): ack = message
            }

            if !registerDhcpInformation(ack) {
                bridge.controlMailbox.send(ControlMessage(from: .dhcp, result: .invalidConfiguration))
            }

            break
        }

        bridge.controlMailbox.send(ControlMessage(from: .dhcp, result: .proceeded))
    }

    private func generateBasicOptionsParameters() -> [UInt8] {
        [dhcpOptionSubnetMask, dhcpOptionRouterAddress, dhcpOptionDnsServerAddress]
    }

    private func extractMessageToMe(_ frame: EthernetFrame) -> DhcpMessage? {
        let isBroadcastFrame = frame.dstMac.isSame(as: ethernetBroadcastAddress)
        let isToMeFrame = frame.dstMac.isSame(as: bridge.config.clientMacAddress)
        if !(isBroadcastFrame || isToMeFrame) { return nil }

        guard let datagram = frame.payloadIPv4Packet?.payloadUDPDatagram else { return nil }
        if datagram.dstPort != udpPortDhcpClient || datagram.srcPort != udpPortDhcpServer { return nil }

        guard let message = datagram.payloadDhcpMessage else { return nil }
        if !message.clientMacAddress.isSame(as: bridge.config.clientMacAddress) { return nil }

        return message
    }

    private func sendAsBroadcast(_ message: DhcpMessage) async throws {
        let datagram = UDPDatagram()
        datagram.dstPort = udpPortDhcpServer
        datagram.srcPort = udpPortDhcpClient
        datagram.payloadDhcpMessage = message

        let packet = IPv4Packet()
        packet.protocolv = ipProtocolUDP
        packet.identification = UInt16(bitPattern: Int16(truncatingIfNeeded: bridge.nextInt()))
        packet.dstAddress.read(from: ipv4BroadcastAddress)
        packet.srcAddress.read(from: ipv4UnknownAddress)
        packet.payloadUDPDatagram = datagram
        datagram.importIPv4Header(packet)

        let frame = EthernetFrame()
        frame.etherType = etherTypeIPv4
        frame.dstMac.read(from: ethernetBroadcastAddress)
        frame.srcMac.read(from: bridge.config.clientMacAddress)
        frame.payloadIPv4Packet = packet

        try await bridge.tcpTerminal!.sendFrame(frame)
    }

    private func startDiscoverOfferSequence() async -> SequenceOutcome {
        await withTimeout(dhcpResendMessageTimeout) { [self] in
            let transactionId = bridge.nextInt()

            let options = OptionPack()
            options.byteOptions[dhcpOptionMessageType] = dhcpMessageTypeDiscover
            options.variableOptions[dhcpOptionParameterList] = generateBasicOptionsParameters()

            let message = DhcpMessage()
            message.opcode = dhcpOpcodeBootRequest
            message.transactionId = transactionId
            message.clientMacAddress.read(from: bridge.config.clientMacAddress)
            message.options = options

            do {
                try await sendAsBroadcast(message)
            } catch {
                return .failed
            }

            while !Task.isCancelled {
                guard let reply = extractMessageToMe(await mailbox.receive()), reply.transactionId == transactionId else {
                    continue
                }
                return reply.options.byteOptions[dhcpOptionMessageType] == dhcpMessageTypeOffer
                    ? .done(reply) : .retry
            }
            return .retry
        } ?? .retry
    }

    private func startRequestAckSequence(_ offer: DhcpMessage) async -> SequenceOutcome {
        await withTimeout(dhcpResendMessageTimeout) { [self] in
            let options = OptionPack()
            options.byteOptions[dhcpOptionMessageType] = dhcpMessageTypeRequest
            options.addressOptions[dhcpOptionRequestedAddress] = offer.yourIpAddress
            options.addressOptions[dhcpOptionDhcpServerAddress] =
                offer.options.addressOptions[dhcpOptionDhcpServerAddress] ?? [0, 0, 0, 0]
            options.variableOptions[dhcpOptionParameterList] = generateBasicOptionsParameters()

            let message = DhcpMessage()
            message.opcode = dhcpOpcodeBootRequest
            message.transactionId = offer.transactionId
            message.clientMacAddress.read(from: bridge.config.clientMacAddress)
            message.options = options

            do {
                try await sendAsBroadcast(message)
            } catch {
                return .failed
            }

            while !Task.isCancelled {
                guard let reply = extractMessageToMe(await mailbox.receive()), reply.transactionId == offer.transactionId else {
                    continue
                }
                return reply.options.byteOptions[dhcpOptionMessageType] == dhcpMessageTypeAck
                    ? .done(reply) : .retry
            }
            return .retry
        } ?? .retry
    }

    private func registerDhcpInformation(_ ack: DhcpMessage) -> Bool {
        if ack.yourIpAddress.isSame(as: ipv4UnknownAddress) { return false }
        bridge.assignedIpAddress.read(from: ack.yourIpAddress)

        guard let subnetMask = ack.options.addressOptions[dhcpOptionSubnetMask],
              !subnetMask.isSame(as: ipv4UnknownAddress)
        else { return false }
        bridge.subnetMask.read(from: subnetMask)

        guard let givenDefaultGatewayAddresses = ack.options.variableOptions[dhcpOptionRouterAddress],
              givenDefaultGatewayAddresses.count >= ipv4AddressSize
        else { return false }
        let defaultGatewayAddress = Array(givenDefaultGatewayAddresses.prefix(ipv4AddressSize))
        if defaultGatewayAddress.isSame(as: ipv4UnknownAddress) { return false }
        bridge.defaultGatewayIpAddress.read(from: defaultGatewayAddress)

        guard let dhcpServerAddress = ack.options.addressOptions[dhcpOptionDhcpServerAddress],
              !dhcpServerAddress.isSame(as: ipv4UnknownAddress)
        else { return false }
        bridge.dhcpServerIpAddress.read(from: dhcpServerAddress)

        if let dnsServers = ack.options.variableOptions[dhcpOptionDnsServerAddress] {
            if dnsServers.isSame(as: ipv4UnknownAddress) { return false }
            bridge.dnsServerIpAddress = Array(dnsServers.prefix(ipv4AddressSize))
        }

        if let leaseTime = ack.options.intOptions[dhcpOptionLeaseTime], leaseTime < 0 { return false }
        if let leaseTime = ack.options.intOptions[dhcpOptionLeaseTime] {
            bridge.leaseTime = leaseTime * 1000
        }

        return true
    }
}

// MARK: - ArpClient

public final class ArpClient {
    public let mailbox = Mailbox<EthernetFrame>()
    private let bridge: SharedBridge
    private var controlTask: Task<Void, Never>?

    public init(bridge: SharedBridge) {
        self.bridge = bridge
    }

    public func negotiate() async {
        while !Task.isCancelled {
            switch await startResolveDefaultGatewaySequence() {
            case .retry:
                continue
            case .failed:
                bridge.controlMailbox.send(ControlMessage(from: .arp, result: .errTimeout))
                return
            case .done(let reply):
                if !registerArpInformation(reply) {
                    bridge.controlMailbox.send(ControlMessage(from: .arp, result: .invalidConfiguration))
                }
            }

            break
        }

        bridge.controlMailbox.send(ControlMessage(from: .arp, result: .proceeded))
    }

    public func launchJobControl() {
        controlTask = Task { [weak self] in
            await self?.runControl()
        }
    }

    private func runControl() async {
        while !Task.isCancelled {
            let received = await mailbox.receive()

            if isARPRequest(received) {
                try? await processARPRequest(received)
            }
        }
    }

    private func isARPRequest(_ frame: EthernetFrame) -> Bool {
        guard let packet = frame.payloadARPPacket else { return false }
        return packet.targetIp.isSame(as: bridge.assignedIpAddress) && packet.opcode == arpOpcodeRequest
    }

    private func processARPRequest(_ requestFrame: EthernetFrame) async throws {
        let requestPacket = requestFrame.payloadARPPacket!

        let replyPacket = ARPPacket()
        replyPacket.opcode = arpOpcodeReply
        replyPacket.senderIp.read(from: bridge.assignedIpAddress)
        replyPacket.senderMac.read(from: bridge.config.clientMacAddress)
        replyPacket.targetIp.read(from: requestPacket.senderIp)
        replyPacket.targetMac.read(from: requestPacket.senderMac)

        let frame = EthernetFrame()
        frame.etherType = etherTypeARP
        frame.dstMac.read(from: requestFrame.srcMac)
        frame.srcMac.read(from: bridge.config.clientMacAddress)
        frame.payloadARPPacket = replyPacket

        try await bridge.tcpTerminal!.sendFrame(frame)
    }

    private enum SequenceOutcome {
        case retry
        case failed
        case done(ARPPacket)
    }

    private func startResolveDefaultGatewaySequence() async -> SequenceOutcome {
        await withTimeout(dhcpResendMessageTimeout) { [self] in
            let packet = ARPPacket()
            packet.opcode = arpOpcodeRequest
            packet.senderIp.read(from: bridge.assignedIpAddress)
            packet.senderMac.read(from: bridge.config.clientMacAddress)
            packet.targetIp.read(from: bridge.defaultGatewayIpAddress)

            let frame = EthernetFrame()
            frame.etherType = etherTypeARP
            frame.dstMac.read(from: ethernetBroadcastAddress)
            frame.srcMac.read(from: bridge.config.clientMacAddress)
            frame.payloadARPPacket = packet

            do {
                try await bridge.tcpTerminal!.sendFrame(frame)
            } catch {
                return .failed
            }

            while !Task.isCancelled {
                let received = await mailbox.receive()
                let isBroadcastFrame = received.dstMac.isSame(as: ethernetBroadcastAddress)
                let isToMeFrame = received.dstMac.isSame(as: bridge.config.clientMacAddress)
                if !(isBroadcastFrame || isToMeFrame) { continue }

                guard let reply = received.payloadARPPacket else { continue }
                return reply.opcode == arpOpcodeReply ? .done(reply) : .retry
            }
            return .retry
        } ?? .retry
    }

    private func registerArpInformation(_ reply: ARPPacket) -> Bool {
        if !reply.targetIp.isSame(as: bridge.assignedIpAddress) { return false }
        if !reply.targetMac.isSame(as: bridge.config.clientMacAddress) { return false }
        if !reply.senderIp.isSame(as: bridge.defaultGatewayIpAddress) { return false }
        if reply.senderMac.isSame(as: ethernetUnknownAddress) { return false }
        if reply.senderMac.isSame(as: ethernetBroadcastAddress) { return false }

        bridge.defaultGatewayMacAddress.read(from: reply.senderMac)
        return true
    }
}

// MARK: - support

public enum MvcError: Error {
    case assertion(String)
}

@discardableResult
func withTimeout<T>(_ nanoseconds: UInt64, _ operation: @escaping () async -> T) async -> T? {
    await withTaskGroup(of: T?.self) { group in
        group.addTask { await operation() }
        group.addTask {
            try? await Task.sleep(nanoseconds: nanoseconds)
            return nil
        }
        guard let first = await group.next() else {
            group.cancelAll()
            return nil
        }
        group.cancelAll()
        return first
    }
}
