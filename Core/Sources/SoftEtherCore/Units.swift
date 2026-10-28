// Ethernet/IPv4/ARP/UDP/KeepAlive/HTTP units, ported from kittoku/mvc unit/.

import Foundation

// MARK: - constants

public let etherTypeIPv4: UInt16 = 0x0800
public let etherTypeARP: UInt16 = 0x0806
public let ethernetMacAddressSize = 6
public let ethernetUnknownAddress = [UInt8](repeating: 0, count: ethernetMacAddressSize)
public let ethernetBroadcastAddress = [UInt8](repeating: 0xFF, count: ethernetMacAddressSize)
public let ethernetHeaderSize = 2 * ethernetMacAddressSize + 2
public let ethernetMaxMTU = 1500

public let ipv4HeaderSize = 20
public let ipv4VersionAndHeaderLength: UInt8 = 0x45
public let ipv4DefaultTTL: UInt8 = 0x7F
public let ipv4CorrectChecksum: UInt16 = 0xFFFF
public let ipProtocolUDP: UInt8 = 0x11
public let ipv4AddressSize = 4
public let ipv4UnknownAddress = [UInt8](repeating: 0, count: ipv4AddressSize)
public let ipv4BroadcastAddress = [UInt8](repeating: 0xFF, count: ipv4AddressSize)

public let arpHardwareTypeEthernet: UInt16 = 1
public let arpMacAddressSize: UInt8 = 6
public let arpIpAddressSize: UInt8 = 4
public let arpOpcodeRequest: UInt16 = 1
public let arpOpcodeReply: UInt16 = 2

public let udpHeaderSize = 8
public let udpCorrectChecksum: UInt16 = 0xFFFF
public let udpPortEcho: UInt16 = 7
public let udpPortDhcpServer: UInt16 = 67
public let udpPortDhcpClient: UInt16 = 68

public let keepAliveMaxSize = 512
public let keepAliveFrameNum: Int32 = -1
public let keepAliveNattPortTag = Array("NATT_MY_PORT".utf8)
public let keepAliveNattIpTag = Array("NATT_MY_IP".utf8)
public let keepAliveNattInfoSize = keepAliveNattPortTag.count + 2 + keepAliveNattIpTag.count + 16

// MARK: - ones-complement checksum (extension/Int.kt of mvc)

func addOnesComplement(_ lhs: Int, _ addend: Int) -> Int {
    var sum = lhs + addend
    if sum & 0x0001_0000 != 0 { sum += 1 }
    return sum & 0x0000_FFFF
}

// MARK: - EthernetFrame

public final class EthernetFrame {
    public var dstMac = [UInt8](repeating: 0, count: ethernetMacAddressSize)
    public var srcMac = [UInt8](repeating: 0, count: ethernetMacAddressSize)
    public var etherType: UInt16 = 0

    public var payloadARPPacket: ARPPacket?
    public var payloadIPv4Packet: IPv4Packet?
    public var payloadUnknown: [UInt8]?

    public init() {}

    var validPayloadLength: Int {
        if let p = payloadARPPacket { return p.length }
        if let p = payloadIPv4Packet { return p.length }
        if let p = payloadUnknown { return p.count }
        return 0
    }

    public var length: Int { ethernetHeaderSize + validPayloadLength }

    public func write(_ buffer: ByteBuffer) {
        buffer.put(dstMac)
        buffer.put(srcMac)
        buffer.putU16(etherType)

        if let p = payloadARPPacket { p.write(buffer) }
        else if let p = payloadIPv4Packet { p.write(buffer) }
        else if let p = payloadUnknown { buffer.put(p) }
    }

    public func read(_ buffer: ByteBuffer) {
        readWithGivenSize(Int(buffer.getU32()), buffer)
    }

    public func readWithGivenSize(_ frameSize: Int, _ buffer: ByteBuffer) {
        let frameStop = buffer.position + frameSize
        let payloadLength = frameSize - ethernetHeaderSize
        precondition(payloadLength > 0)

        buffer.get(&dstMac, ethernetMacAddressSize)
        buffer.get(&srcMac, ethernetMacAddressSize)
        etherType = buffer.getU16()

        if payloadLength > 0 {
            switch etherType {
            case etherTypeARP:
                let startArp = buffer.position
                let isEthernet = buffer.getU16() == arpHardwareTypeEthernet
                let isIPv4 = buffer.getU16() == etherTypeIPv4
                buffer.position = startArp
                if isEthernet && isIPv4 {
                    let packet = ARPPacket()
                    packet.read(buffer)
                    payloadARPPacket = packet
                } else {
                    payloadUnknown = buffer.get(payloadLength)
                }
            case etherTypeIPv4:
                let packet = IPv4Packet()
                packet.read(buffer)
                payloadIPv4Packet = packet
            default:
                payloadUnknown = buffer.get(payloadLength)
            }
        }

        buffer.position = frameStop // discard padding
    }
}

// MARK: - ARPPacket

public final class ARPPacket {
    public var opcode: UInt16 = 0
    public var senderMac = [UInt8](repeating: 0, count: 6)
    public var senderIp = [UInt8](repeating: 0, count: 4)
    public var targetMac = [UInt8](repeating: 0, count: 6)
    public var targetIp = [UInt8](repeating: 0, count: 4)

    public init() {}

    public var length: Int { 28 }

    public func write(_ buffer: ByteBuffer) {
        buffer.putU16(arpHardwareTypeEthernet)
        buffer.putU16(etherTypeIPv4)
        buffer.putU8(arpMacAddressSize)
        buffer.putU8(arpIpAddressSize)
        buffer.putU16(opcode)
        buffer.put(senderMac)
        buffer.put(senderIp)
        buffer.put(targetMac)
        buffer.put(targetIp)
    }

    public func read(_ buffer: ByteBuffer) {
        precondition(buffer.getU16() == arpHardwareTypeEthernet)
        precondition(buffer.getU16() == etherTypeIPv4)
        precondition(buffer.getU8() == arpMacAddressSize)
        precondition(buffer.getU8() == arpIpAddressSize)
        opcode = buffer.getU16()
        buffer.get(&senderMac, 6)
        buffer.get(&senderIp, 4)
        buffer.get(&targetMac, 6)
        buffer.get(&targetIp, 4)
    }
}

// MARK: - IPv4Packet (not to be fragmented)

public final class IPv4Packet {
    public var identification: UInt16 = 0
    public var protocolv: UInt8 = 0
    public var srcAddress = [UInt8](repeating: 0, count: 4)
    public var dstAddress = [UInt8](repeating: 0, count: 4)
    public var payloadUDPDatagram: UDPDatagram?
    public var payloadUnknown: [UInt8]?

    public init() {}

    var validPayloadLength: Int {
        if let p = payloadUDPDatagram { return p.length }
        if let p = payloadUnknown { return p.count }
        return 0
    }

    public var length: Int { ipv4HeaderSize + validPayloadLength }

    public func write(_ buffer: ByteBuffer) {
        let startIp = buffer.position

        buffer.putU8(ipv4VersionAndHeaderLength)
        buffer.putU8(0) // tos
        buffer.putU16(UInt16(length))
        buffer.putU16(identification)
        buffer.putU16(0) // frags and fragment offset
        buffer.putU8(ipv4DefaultTTL)
        buffer.putU8(protocolv)

        let startChecksum = buffer.position
        buffer.putU16(0)
        buffer.put(srcAddress)
        buffer.put(dstAddress)
        let stopIp = buffer.position

        buffer.position = startChecksum
        buffer.putU16(calcChecksum(startIp, buffer))
        buffer.position = stopIp

        if let p = payloadUDPDatagram { p.write(buffer) }
        else if let p = payloadUnknown { buffer.put(p) }
    }

    public func read(_ buffer: ByteBuffer) {
        let startIp = buffer.position

        precondition(buffer.getU8() == ipv4VersionAndHeaderLength)
        buffer.move(1) // ignore tos

        let payloadLength = Int(buffer.getU16()) - ipv4HeaderSize
        precondition(payloadLength >= 0)

        identification = buffer.getU16()
        precondition(Int(buffer.getU16()) & 0b101_111111111 == 0) // no fragments

        buffer.move(1) // ignore ttl
        protocolv = buffer.getU8()
        buffer.move(2) // skip given checksum
        buffer.get(&srcAddress, 4)
        buffer.get(&dstAddress, 4)

        precondition(calcChecksum(startIp, buffer) == ipv4CorrectChecksum)

        if payloadLength > 0 {
            if protocolv == ipProtocolUDP {
                let datagram = UDPDatagram()
                datagram.read(buffer)
                payloadUDPDatagram = datagram
            } else {
                payloadUnknown = buffer.get(payloadLength)
            }
        }
    }

    private func calcChecksum(_ start: Int, _ buffer: ByteBuffer) -> UInt16 {
        var sum = 0
        var offset = start
        while offset < start + ipv4HeaderSize {
            sum = addOnesComplement(sum, Int(buffer.probeU16(offset - buffer.position)))
            offset += 2
        }

        let invSum = ~sum
        return invSum & 0x0000_FFFF == 0 ? 0xFFFF : UInt16(invSum & 0x0000_FFFF)
    }
}

// MARK: - UDPDatagram (TCP connection only, not UDP acceleration)

public final class UDPDatagram {
    public var srcPort: UInt16 = 0
    public var dstPort: UInt16 = 0
    public var payloadDhcpMessage: DhcpMessage?
    public var payloadUnknown: [UInt8]?

    var pseudoIPHeader: [UInt8]? // don't validate checksum if nil

    public init() {}

    var validPayloadLength: Int {
        if let p = payloadDhcpMessage { return p.length }
        if let p = payloadUnknown { return p.count }
        return 0
    }

    public var length: Int { udpHeaderSize + validPayloadLength }

    public func write(_ buffer: ByteBuffer) {
        let startUdp = buffer.position

        buffer.putU16(srcPort)
        buffer.putU16(dstPort)
        buffer.putU16(UInt16(length))

        let startChecksum = buffer.position
        buffer.putU16(0)

        if let p = payloadDhcpMessage { p.write(buffer) }
        else if let p = payloadUnknown { buffer.put(p) }

        let stopUdp = buffer.position

        let checksum = pseudoIPHeader.map { calcChecksum($0, startUdp, buffer) } ?? 0

        buffer.position = startChecksum
        buffer.putU16(checksum)
        buffer.position = stopUdp
    }

    public func read(_ buffer: ByteBuffer) {
        let startUdp = buffer.position
        srcPort = buffer.getU16()
        dstPort = buffer.getU16()

        let payloadLength = Int(buffer.getU16()) - udpHeaderSize
        precondition(payloadLength >= 0)

        let givenChecksum = buffer.getU16()

        if payloadLength > 0 {
            if srcPort == udpPortDhcpServer && dstPort == udpPortDhcpClient {
                let message = DhcpMessage()
                message.read(buffer)
                payloadDhcpMessage = message
            } else {
                payloadUnknown = buffer.get(payloadLength)
            }
        }

        if let header = pseudoIPHeader, givenChecksum != 0 {
            precondition(calcChecksum(header, startUdp, buffer) == udpCorrectChecksum)
        }
    }

    private func calcChecksum(_ ipHeader: [UInt8], _ startUdp: Int, _ buffer: ByteBuffer) -> UInt16 {
        var sum = 0
        var i = 0
        while i + 1 < ipHeader.count {
            sum = addOnesComplement(sum, Int(UInt16(ipHeader[i]) << 8 | UInt16(ipHeader[i + 1])))
            i += 2
        }
        if i < ipHeader.count { // odd header would need zero padding; our header is always even
            sum = addOnesComplement(sum, Int(ipHeader[i]) << 8)
        }

        let datagramLength = length
        if datagramLength % 2 == 0 {
            var offset = startUdp
            while offset < startUdp + datagramLength {
                sum = addOnesComplement(sum, Int(buffer.probeU16(offset - buffer.position)))
                offset += 2
            }
        } else {
            let lastByteIndex = startUdp + datagramLength - 1
            var offset = startUdp
            while offset < lastByteIndex {
                sum = addOnesComplement(sum, Int(buffer.probeU16(offset - buffer.position)))
                offset += 2
            }
            sum = addOnesComplement(sum, Int(buffer.bytes[lastByteIndex]) << 8) // as if 00 were padded
        }

        let invSum = ~sum
        return invSum & 0x0000_FFFF == 0 ? 0xFFFF : UInt16(invSum & 0x0000_FFFF)
    }

    /// Invoke just before write.
    public func importIPv4Header(_ packet: IPv4Packet) {
        let header = ByteBuffer(capacity: 12)
        header.put(packet.srcAddress)
        header.put(packet.dstAddress)
        header.putU8(0)
        header.putU8(ipProtocolUDP)
        header.putU16(UInt16(length))
        pseudoIPHeader = header.bytes
    }
}

// MARK: - KeepAlivePacket

public final class KeepAlivePacket {
    public var value: [UInt8]?
    public var nattAddress: [UInt8]? // IPv4 address bytes
    public var nattPort: Int = 0

    public init() {}

    var valueLength: Int { value?.count ?? 0 }
    public var length: Int { 8 + valueLength }

    public func preparePacket(_ random: inout some RandomNumberGenerator) {
        let minSize = nattAddress != nil ? keepAliveNattInfoSize : 0
        let randomSize = max(Int.random(in: 0 ... keepAliveMaxSize, using: &random), minSize)

        var array = [UInt8](repeating: 0, count: randomSize)
        for i in 0 ..< randomSize { array[i] = UInt8.random(in: 0 ... 255, using: &random) }

        if let address = nattAddress {
            let buffer = ByteBuffer.wrap(array)
            buffer.put(keepAliveNattPortTag)
            buffer.putU16(UInt16(nattPort))
            buffer.put(keepAliveNattIpTag)
            buffer.padZero(10)
            buffer.putU16(0xFFFF)
            buffer.put(address)
            array = buffer.bytes
        }

        value = array
    }

    public func extractNATTInfo() {
        nattPort = 0
        nattAddress = nil

        guard let array = value else { return }
        let buffer = ByteBuffer.wrap(array)

        let startPortTag = array.search(keepAliveNattPortTag)
        if startPortTag >= 0 {
            nattPort = Int(buffer.probeU16(startPortTag + keepAliveNattPortTag.count))
        }

        let startIPTag = array.search(keepAliveNattIpTag)
        if startIPTag >= 0 {
            let startIP = startIPTag + keepAliveNattPortTag.count + 12
            buffer.position = startIP
            nattAddress = buffer.get(ipv4AddressSize)
        }
    }

    public func read(_ buffer: ByteBuffer) {
        precondition(Int32(bitPattern: buffer.getU32()) == keepAliveFrameNum)
        value = buffer.get(Int(buffer.getU32()))
    }

    public func write(_ buffer: ByteBuffer) {
        buffer.putU32(UInt32(bitPattern: keepAliveFrameNum))
        buffer.putU32(UInt32(valueLength))
        if let v = value { buffer.put(v) }
    }
}

// MARK: - HttpMessage (write-only; parsing lives in IncomingManager)

public final class HttpMessage {
    public var startLine = ""
    public var fields: [String: String] = [:] // insertion order preserved by ordered keys list
    public private(set) var fieldOrder: [String] = []
    public var body: [UInt8]?

    public init() {}

    public func setField(_ key: String, _ value: String) {
        if fields[key] == nil { fieldOrder.append(key) }
        fields[key] = value
    }

    public var length: Int {
        var sum = 2 // last CRLF
        sum += startLine.utf8.count + 2
        for key in fieldOrder { sum += key.utf8.count + (fields[key]?.utf8.count ?? 0) + 4 }
        sum += body?.count ?? 0
        return sum
    }

    public func write(_ buffer: ByteBuffer) {
        var text = startLine + "\r\n"
        for key in fieldOrder { text += "\(key): \(fields[key] ?? "")\r\n" }
        text += "\r\n"
        buffer.put(Array(text.utf8))
        if let b = body { buffer.put(b) }
    }
}

// MARK: - frame classification (teminal/common.kt of mvc)

let startIpDst = ethernetHeaderSize + 16

public func isToMeFrame(_ buffer: ByteBuffer, _ myMacAddress: [UInt8]) -> Bool {
    if buffer.bytes.match(myMacAddress, at: buffer.position) { return true }
    if buffer.bytes.match(ethernetBroadcastAddress, at: buffer.position) { return true }
    return false
}

public func isToMePacket(_ buffer: ByteBuffer, _ myIPAddress: [UInt8]) -> Bool {
    if buffer.bytes.match(myIPAddress, at: buffer.position + startIpDst) { return true }
    if buffer.bytes.match(ipv4BroadcastAddress, at: buffer.position + startIpDst) { return true }
    return false
}

public func isDhcpPacket(_ buffer: ByteBuffer) -> Bool {
    if buffer.probeU8(ethernetHeaderSize + 9) != ipProtocolUDP { return false }
    return buffer.probeU16(ethernetHeaderSize + ipv4HeaderSize + 2) == udpPortDhcpClient
}
