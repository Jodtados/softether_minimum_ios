// DHCP message and option pack, ported from kittoku/mvc unit/dhcp/.

import Foundation

public let dhcpHardwareTypeEthernet: UInt8 = 1
public let dhcpMagicCookie: UInt32 = 0x63825363

public let dhcpOpcodeBootRequest: UInt8 = 1
public let dhcpOpcodeBootReply: UInt8 = 2

public let dhcpOptionSubnetMask: UInt8 = 1
public let dhcpOptionRouterAddress: UInt8 = 3
public let dhcpOptionDnsServerAddress: UInt8 = 6
public let dhcpOptionRequestedAddress: UInt8 = 50
public let dhcpOptionLeaseTime: UInt8 = 51
public let dhcpOptionMessageType: UInt8 = 53
public let dhcpOptionDhcpServerAddress: UInt8 = 54
public let dhcpOptionParameterList: UInt8 = 55
public let dhcpOptionEnd: UInt8 = 0xFF

let dhcpByteOptions: Set<UInt8> = [dhcpOptionMessageType]
let dhcpIntOptions: Set<UInt8> = [dhcpOptionLeaseTime]
let dhcpAddressOptions: Set<UInt8> = [
    dhcpOptionSubnetMask, dhcpOptionRequestedAddress, dhcpOptionDhcpServerAddress,
]
let dhcpVariableOptions: Set<UInt8> = [
    dhcpOptionRouterAddress, dhcpOptionDnsServerAddress, dhcpOptionParameterList,
]

public let dhcpMessageTypeDiscover: UInt8 = 1
public let dhcpMessageTypeOffer: UInt8 = 2
public let dhcpMessageTypeRequest: UInt8 = 3
public let dhcpMessageTypeDecline: UInt8 = 4
public let dhcpMessageTypeAck: UInt8 = 5
public let dhcpMessageTypeNak: UInt8 = 6
public let dhcpMessageTypeRelease: UInt8 = 7

public final class OptionPack {
    public var byteOptions: [UInt8: UInt8] = [:]
    public var intOptions: [UInt8: Int] = [:]
    public var addressOptions: [UInt8: [UInt8]] = [:]
    public var variableOptions: [UInt8: [UInt8]] = [:]

    public init() {}

    public var length: Int {
        var sum = 1 // END
        for _ in byteOptions { sum += 2 + 1 }
        for _ in intOptions { sum += 2 + 4 }
        for _ in addressOptions { sum += 2 + 4 }
        for value in variableOptions.values { sum += 2 + value.count }
        return sum
    }

    public func write(_ buffer: ByteBuffer) {
        for (key, value) in byteOptions {
            buffer.putU8(key)
            buffer.putU8(1)
            buffer.putU8(value)
        }

        for (key, value) in intOptions {
            buffer.putU8(key)
            buffer.putU8(4)
            buffer.putU32(UInt32(bitPattern: Int32(value)))
        }

        for (key, value) in addressOptions {
            precondition(value.count == ipv4AddressSize)
            buffer.putU8(key)
            buffer.putU8(UInt8(ipv4AddressSize))
            buffer.put(value)
        }

        for (key, value) in variableOptions {
            buffer.putU8(key)
            buffer.putU8(UInt8(value.count))
            buffer.put(value)
        }

        buffer.putU8(dhcpOptionEnd)
    }

    public func read(_ buffer: ByteBuffer) {
        while true {
            let tag = buffer.getU8()

            if dhcpByteOptions.contains(tag) {
                precondition(buffer.getU8() == 1)
                byteOptions[tag] = buffer.getU8()
            } else if dhcpIntOptions.contains(tag) {
                precondition(buffer.getU8() == 4)
                intOptions[tag] = Int(Int32(bitPattern: buffer.getU32()))
            } else if dhcpAddressOptions.contains(tag) {
                precondition(buffer.getU8() == UInt8(ipv4AddressSize))
                addressOptions[tag] = buffer.get(ipv4AddressSize)
            } else if dhcpVariableOptions.contains(tag) {
                let valueLength = Int(buffer.getU8())
                variableOptions[tag] = buffer.get(valueLength)
            } else if tag == dhcpOptionEnd {
                break
            } else {
                discardOption(buffer)
            }
        }
    }

    private func discardOption(_ buffer: ByteBuffer) {
        let size = Int(buffer.getU8())
        buffer.move(size)
    }
}

public final class DhcpMessage {
    public var opcode: UInt8 = 0
    public var transactionId: Int = 0
    public var clientIpAddress = [UInt8](repeating: 0, count: 4)
    public var yourIpAddress = [UInt8](repeating: 0, count: 4)
    public var serverIpAddress = [UInt8](repeating: 0, count: 4)
    public var clientMacAddress = [UInt8](repeating: 0, count: 6)
    public var options = OptionPack()

    public init() {}

    var lengthBeforePadded: Int { 240 + options.length }
    let minimumLength = 300

    public var length: Int { max(lengthBeforePadded, minimumLength) }

    public func write(_ buffer: ByteBuffer) {
        buffer.putU8(opcode)
        buffer.putU8(dhcpHardwareTypeEthernet)
        buffer.putU8(arpMacAddressSize)
        buffer.putU8(0) // hops

        buffer.putU32(UInt32(bitPattern: Int32(transactionId)))
        buffer.putU16(0) // secs
        buffer.putU16(0) // flags

        buffer.put(clientIpAddress)
        buffer.put(yourIpAddress)
        buffer.put(serverIpAddress)
        buffer.putU32(0) // relay IP address

        buffer.put(clientMacAddress)
        buffer.padZero(10)

        buffer.padZero(64) // server host name
        buffer.padZero(128) // boot file name

        buffer.putU32(dhcpMagicCookie)

        options.write(buffer)

        if minimumLength > lengthBeforePadded {
            buffer.padZero(minimumLength - lengthBeforePadded)
        }
    }

    public func read(_ buffer: ByteBuffer) {
        let startDhcp = buffer.position

        opcode = buffer.getU8()
        precondition(buffer.getU8() == dhcpHardwareTypeEthernet)
        precondition(buffer.getU8() == arpMacAddressSize)
        buffer.move(1) // hops

        transactionId = Int(Int32(bitPattern: buffer.getU32()))
        buffer.move(2) // secs
        buffer.move(2) // flags

        buffer.get(&clientIpAddress, 4)
        buffer.get(&yourIpAddress, 4)
        buffer.get(&serverIpAddress, 4)
        buffer.move(4) // relay IP address

        buffer.get(&clientMacAddress, 6)
        buffer.move(10)

        buffer.move(64) // server host name
        buffer.move(128) // boot file name

        precondition(buffer.getU32() == dhcpMagicCookie)

        options.read(buffer)

        let readLength = buffer.position - startDhcp
        if readLength < minimumLength {
            buffer.move(minimumLength - readLength)
        }
    }
}
