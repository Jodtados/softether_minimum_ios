// Unit-layer vectors, ported from mvc MvcTest.kt (SHA-0, UDP/IPv4 round-trips,
// NATT regex, byte search) plus a ServerStore logic check.

import XCTest
@testable import SoftEtherCore

final class UnitsTests: XCTestCase {
    // MARK: SHA-0

    func testHashSha0() {
        let actual0 = hashSha0(Array("abc".utf8))
        let expected0 = [UInt8].fromHexString("0164B8A914CD2A5E74C4F7FF082C4D97F1EDF880")!

        let actual1 = hashSha0(Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))
        let expected1 = [UInt8].fromHexString("D2516EE1ACFA5BAF33DFC1C471E438449EF134C8")!

        XCTAssertTrue(actual0.isSame(as: expected0))
        XCTAssertTrue(actual1.isSame(as: expected1))
    }

    // MARK: UDP datagram write/read round-trips

    private func writeReadUDPDatagram(_ datagram: UDPDatagram) {
        let buffer = ByteBuffer(capacity: datagram.length)
        datagram.write(buffer)
        buffer.flip()

        let read = UDPDatagram()
        read.pseudoIPHeader = datagram.pseudoIPHeader
        read.read(buffer)

        XCTAssertEqual(datagram.srcPort, read.srcPort)
        XCTAssertEqual(datagram.dstPort, read.dstPort)
        XCTAssertEqual(datagram.payloadUnknown ?? [], read.payloadUnknown ?? [])
    }

    func testUDPDatagram() {
        let zero = also(UDPDatagram()) {
            $0.srcPort = UInt16(bitPattern: Int16(truncatingIfNeeded: -8))
            $0.dstPort = 0
            $0.payloadUnknown = []
            $0.pseudoIPHeader = []
        }
        writeReadUDPDatagram(zero)

        let oneByte = also(UDPDatagram()) {
            $0.srcPort = UInt16(bitPattern: Int16(truncatingIfNeeded: -549_654_713))
            $0.dstPort = UInt16(bitPattern: Int16(truncatingIfNeeded: -1_991_713_114))
            $0.payloadUnknown = [0x9C]
            $0.pseudoIPHeader = []
        }
        writeReadUDPDatagram(oneByte)

        let big = also(UDPDatagram()) {
            $0.srcPort = 65214
            $0.dstPort = 33409
            $0.payloadUnknown = [UInt8].fromHexString(
                "35BBF96E035649A57EB582554A292B9A1932553E70930421BF5D207A6DB421717"
                    + "CE65F0A76CDD62C926CA9950EAD9FA9925B84066D7E7724CF39F922BA2593855B"
                    + "7FDFD2B434"
            )
            $0.pseudoIPHeader = [UInt8].fromHexString("29DB7C1FB0CF03F513C4B712")
        }
        writeReadUDPDatagram(big)
    }

    // MARK: IPv4 packet round-trip

    func testIPPacket() {
        let packet = also(IPv4Packet()) {
            $0.srcAddress[3] = 0xEC // -20 in Java terms
            $0.payloadUnknown = []
        }

        let buffer = ByteBuffer(capacity: packet.length)
        packet.write(buffer)
        buffer.flip()

        let read = IPv4Packet()
        read.read(buffer)

        XCTAssertEqual(packet.srcAddress, read.srcAddress)
        XCTAssertEqual(packet.protocolv, read.protocolv)
    }

    // MARK: NATT regex

    func testNATTRegex() {
        let text = "IP=192.168.0.1,PORT=11235"

        XCTAssertEqual("IP=192.168.0.1", firstMatch(udpNattIpRegex, in: text))
        XCTAssertEqual("PORT=11235", firstMatch(udpNattPortRegex, in: text))
    }

    private func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex ..< text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              match.range.location != NSNotFound
        else { return nil }
        return (text as NSString).substring(with: match.range)
    }

    // MARK: byte-array search

    func testByteArraySearch() {
        let array = Array("ABCDEFG".utf8)

        XCTAssertEqual(-1, array.search(Array("ABCDEFGH".utf8)))
        XCTAssertEqual(3, array.search(Array("DEF".utf8)))
        XCTAssertEqual(-1, array.search(Array("XYZ".utf8)))
        XCTAssertEqual(-1, array.search(Array("GH".utf8)))
    }

    // MARK: ethernet frame with IPv4 payload round-trips through isToMe checks

    func testFrameClassification() {
        let myMac: [UInt8] = [0x5E, 11, 23, 58, 13, 21]
        let myIp: [UInt8] = [10, 0, 0, 5]

        let frame = also(EthernetFrame()) {
            $0.dstMac = myMac
            $0.srcMac = [0xAA, 1, 2, 3, 4, 5]
            $0.etherType = etherTypeIPv4
            let packet = also(IPv4Packet()) {
                $0.srcAddress = [10, 0, 0, 1]
                $0.dstAddress = myIp
                $0.payloadUnknown = [1, 2, 3] // non-UDP: parsed as opaque payload
            }
            $0.payloadIPv4Packet = packet
        }

        let buffer = ByteBuffer(capacity: frame.length)
        frame.write(buffer)
        buffer.flip()

        XCTAssertTrue(isToMeFrame(buffer, myMac))
        XCTAssertTrue(isToMePacket(buffer, myIp))
    }
}

func also<T>(_ value: T, _ block: (T) -> Void) -> T {
    block(value)
    return value
}

// MARK: - PropertyPack round-trip (wire format symmetry)

final class PropertyPackTests: XCTestCase {
    func testRoundTrip() {
        let pack = PropertyPack()
        pack.booleanProperties[sepUseEncrypt] = true
        pack.intProperties[sepVersion] = 444 // BE group
        pack.intProperties[sepClientPort] = 443 // LE (byte-swapped) group
        pack.asciiProperties[sepUsername] = "user"
        pack.asciiProperties[sepHubName] = "VPN"
        pack.bytesProperties[sepUdpClientKeyV2] = (0 ..< 32).map { UInt8($0) }
        pack.addressProperties[sepClientIpAddress] = [10, 0, 0, 5]

        let buffer = ByteBuffer(capacity: pack.length)
        pack.write(buffer)
        buffer.flip()

        XCTAssertEqual(pack.length, buffer.remaining)

        let read = PropertyPack()
        read.read(buffer)

        XCTAssertEqual(true, read.booleanProperties[sepUseEncrypt])
        XCTAssertEqual(444, read.intProperties[sepVersion])
        XCTAssertEqual(443, read.intProperties[sepClientPort])
        XCTAssertEqual("user", read.asciiProperties[sepUsername])
        XCTAssertEqual("VPN", read.asciiProperties[sepHubName])
        XCTAssertEqual((0 ..< 32).map { UInt8($0) }, read.bytesProperties[sepUdpClientKeyV2])
        XCTAssertEqual([10, 0, 0, 5], read.addressProperties[sepClientIpAddress])
    }

    func testUnknownPropertyIsDiscarded() {
        // two known props + one unknown key in between; read must skip it over
        var wire = [UInt8]()
        wire.append(contentsOf: [0, 0, 0, 2]) // numProperties

        func header(_ key: String, _ type: UInt32) -> [UInt8] {
            var out = [UInt8]()
            let k = Array(key.utf8)
            out += withUnsafeBytes(of: UInt32(k.count + 1).bigEndian) { Array($0) }
            out += k
            out += withUnsafeBytes(of: type.bigEndian) { Array($0) }
            out += [0, 0, 0, 1]
            return out
        }

        wire += header("unknown_key", UInt32(sepIntType))
        wire += [0, 0, 0, 7] // unknown int value

        wire += header(sepMethod, UInt32(sepAsciiType))
        wire += [0, 0, 0, 5]
        wire += Array("login".utf8)

        let read = PropertyPack()
        read.read(ByteBuffer.wrap(wire))

        XCTAssertEqual("login", read.asciiProperties[sepMethod])
        XCTAssertEqual(0, read.intProperties.count)
    }
}
