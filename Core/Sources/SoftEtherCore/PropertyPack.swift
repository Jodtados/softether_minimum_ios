// SoftEther "Pack" property serialization, ported from kittoku/mvc unit/property/.
// Int properties are big-endian, except the "LE" group which the protocol
// stores byte-swapped; IPv4 addresses go out reversed.

import Foundation

public let compatibleVersion = 444
public let compatibleBuild = 9807

public let sepIntType = 0
public let sepBytesType = 1
public let sepAsciiType = 2
public let sepUtf8Type = 3
public let sepLongType = 4

public let sepBuild = "build"
public let sepVersion = "version"
public let sepUniqueIdCamel = "UniqueId"
public let sepUniqueIdSnake = "unique_id"
public let sepClientBuild = "client_build"
public let sepClientId = "client_id"
public let sepClientStr = "client_str"
public let sepClientVer = "client_ver"
public let sepClientHostname = "ClientHostname"
public let sepClientIpAddress = "ClientIpAddress"
public let sepClientOsName = "ClientOsName"
public let sepClientOsVer = "ClientOsVer"
public let sepClientPort = "ClientPort"
public let sepClientProductBuild = "ClientProductBuild"
public let sepClientProductName = "ClientProductName"
public let sepClientProductVer = "ClientProductVer"
public let sepHello = "hello"

public let sepProxyPort = "ProxyPort"
public let sepProxyIpAddress = "ProxyIpAddress"

public let sepServerHostname = "ServerHostname"
public let sepServerIpAddress = "ServerIpAddress"
public let sepServerPort2 = "ServerPort2"
public let sepServerProductBuild = "ServerProductBuild"
public let sepServerProductName = "ServerProductName"
public let sepServerProductVer = "ServerProductVer"

public let sepMethod = "method"
public let sepAuthType = "authtype"
public let sepUsername = "username"
public let sepSecurePassword = "secure_password"
public let sepProtocol = "protocol"
public let sepHubName = "hubname"
public let sepUseEncrypt = "use_encrypt"
public let sepUseCompress = "use_compress"
public let sepMaxConnection = "max_connection"
public let sepHalfConnection = "half_connection"

public let sepRandom = "random"
public let sepPenCore = "pencore"
public let sepError = "error"

// UDP acceleration properties
public let sepUseUdpAcceleration = "use_udp_acceleration"
public let sepUdpUseEncryption = "udp_acceleration_use_encryption"
public let sepUdpVersion = "udp_acceleration_version"
public let sepUdpMaxVersion = "udp_acceleration_max_version"
public let sepUdpClientIp = "udp_acceleration_client_ip"
public let sepUdpClientPort = "udp_acceleration_client_port"
public let sepUdpClientKeyV2 = "udp_acceleration_client_key_v2"
public let sepUdpClientCookie = "udp_acceleration_client_cookie"
public let sepUdpServerIp = "udp_acceleration_server_ip"
public let sepUdpServerPort = "udp_acceleration_server_port"
public let sepUdpServerKeyV2 = "udp_acceleration_server_key_v2"
public let sepUdpServerCookie = "udp_acceleration_server_cookie"
public let sepUdpEnableFastDisconnectDetect = "udp_accel_fast_disconnect_detect"
public let sepUdpSupportFastDisconnectDetect = "support_udp_accel_fast_disconnect_detect"

let softetherBooleanProperties: Set<String> = [
    sepUseEncrypt, sepUseCompress, sepUseUdpAcceleration, sepUdpUseEncryption,
    sepUdpSupportFastDisconnectDetect, sepUdpEnableFastDisconnectDetect,
]

let softetherBEIntProperties: Set<String> = [
    sepClientId, sepVersion, sepBuild, sepClientVer, sepClientBuild, sepAuthType,
    sepProtocol, sepMaxConnection, sepHalfConnection, sepError, sepUdpVersion,
    sepUdpMaxVersion, sepUdpClientPort, sepUdpServerPort, sepUdpClientCookie,
    sepUdpServerCookie,
]

let softetherLEIntProperties: Set<String> = [
    sepClientPort, sepClientProductBuild, sepClientProductVer, sepProxyPort,
    sepServerPort2, sepServerProductBuild, sepServerProductVer,
]

let softetherLongProperties: Set<String> = []

let softetherAddressProperties: Set<String> = [
    sepClientIpAddress, sepProxyIpAddress, sepServerIpAddress, sepUdpClientIp,
    sepUdpServerIp,
]

let softetherBytesProperties: Set<String> = [
    sepUniqueIdCamel, sepUniqueIdSnake, sepPenCore, sepUdpClientKeyV2,
    sepUdpServerKeyV2,
]

let softether160BitsProperties: Set<String> = [sepSecurePassword, sepRandom]

let softetherAsciiProperties: Set<String> = [
    sepClientStr, sepClientHostname, sepClientOsName, sepClientOsVer,
    sepClientProductName, sepHello, sepServerHostname, sepServerProductName,
    sepMethod, sepUsername, sepHubName,
]

let softetherUtf8Properties: Set<String> = []

let propertyFixedHeaderSize = 12 // keySize + valueType + valueNum

public final class PropertyPack {
    public var booleanProperties: [String: Bool] = [:]
    public var intProperties: [String: Int] = [:]
    public var longProperties: [String: Int] = [:]
    public var addressProperties: [String: [UInt8]] = [:]
    public var bytesProperties: [String: [UInt8]] = [:]
    public var asciiProperties: [String: String] = [:]
    public var utf8Properties: [String: String] = [:]

    public init() {}

    public var length: Int {
        var sum = 4
        for key in booleanProperties.keys { sum += propertyFixedHeaderSize + key.utf8.count + 4 }
        for key in intProperties.keys { sum += propertyFixedHeaderSize + key.utf8.count + 4 }
        for key in longProperties.keys { sum += propertyFixedHeaderSize + key.utf8.count + 8 }
        for key in addressProperties.keys { sum += propertyFixedHeaderSize + key.utf8.count + ipv4AddressSize }
        for (key, value) in bytesProperties { sum += propertyFixedHeaderSize + key.utf8.count + 4 + value.count }
        for (key, value) in asciiProperties { sum += propertyFixedHeaderSize + key.utf8.count + 4 + value.utf8.count }
        for (key, value) in utf8Properties {
            sum += propertyFixedHeaderSize + key.utf8.count + 4 + value.utf8.count
        }
        return sum
    }

    private func writeHeader(_ key: String, _ valueType: Int, _ valueNum: Int, _ buffer: ByteBuffer) {
        buffer.putU32(UInt32(key.utf8.count + 1))
        buffer.put(Array(key.utf8))
        buffer.putU32(UInt32(valueType))
        buffer.putU32(UInt32(valueNum))
    }

    public func write(_ buffer: ByteBuffer) {
        buffer.putU32(UInt32(
            booleanProperties.count + intProperties.count + longProperties.count
                + addressProperties.count + bytesProperties.count + asciiProperties.count
                + utf8Properties.count
        ))

        for (key, value) in booleanProperties {
            precondition(softetherBooleanProperties.contains(key))
            writeHeader(key, sepIntType, 1, buffer)
            buffer.putU32(value ? 1 : 0)
        }

        for (key, value) in intProperties {
            if softetherBEIntProperties.contains(key) {
                writeHeader(key, sepIntType, 1, buffer)
                buffer.putU32(UInt32(bitPattern: Int32(value)))
            } else {
                precondition(softetherLEIntProperties.contains(key))
                writeHeader(key, sepIntType, 1, buffer)
                buffer.putU32(UInt32(bitPattern: Int32(value)).reversedEndian())
            }
        }

        for (key, value) in longProperties {
            precondition(softetherLongProperties.contains(key))
            writeHeader(key, sepLongType, 1, buffer)
            buffer.putU64(UInt64(bitPattern: Int64(value)))
        }

        for (key, value) in addressProperties {
            precondition(softetherAddressProperties.contains(key))
            precondition(value.count == ipv4AddressSize)
            writeHeader(key, sepIntType, 1, buffer)
            buffer.put(value.reversed())
        }

        for (key, value) in bytesProperties {
            if !softether160BitsProperties.contains(key) {
                precondition(softetherBytesProperties.contains(key))
            } else {
                precondition(value.count == 20)
            }
            writeHeader(key, sepBytesType, 1, buffer)
            buffer.putU32(UInt32(value.count))
            buffer.put(value)
        }

        for (key, value) in asciiProperties {
            precondition(softetherAsciiProperties.contains(key))
            writeHeader(key, sepAsciiType, 1, buffer)
            let encoded = Array(value.utf8)
            buffer.putU32(UInt32(encoded.count))
            buffer.put(encoded)
        }

        for (key, value) in utf8Properties {
            precondition(softetherUtf8Properties.contains(key))
            writeHeader(key, sepUtf8Type, 1, buffer)
            let encoded = Array(value.utf8)
            buffer.putU32(UInt32(encoded.count))
            buffer.put(encoded)
        }
    }

    public func read(_ buffer: ByteBuffer) {
        let propertyNum = Int(buffer.getU32())
        precondition(propertyNum >= 0)

        for _ in 0 ..< propertyNum {
            let keySize = Int(buffer.getU32()) - 1
            precondition(keySize >= 0)

            let key = String(bytes: buffer.get(keySize), encoding: .ascii) ?? ""

            if softetherBooleanProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepIntType))
                precondition(buffer.getU32() == 1)
                booleanProperties[key] = buffer.getU32() != 0
            } else if softetherBEIntProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepIntType))
                precondition(buffer.getU32() == 1)
                intProperties[key] = Int(Int32(bitPattern: buffer.getU32()))
            } else if softetherLEIntProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepIntType))
                precondition(buffer.getU32() == 1)
                intProperties[key] = Int(Int32(bitPattern: buffer.getU32().reversedEndian()))
            } else if softetherLongProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepLongType))
                precondition(buffer.getU32() == 1)
                longProperties[key] = Int(Int64(bitPattern: buffer.getU64()))
            } else if softetherAddressProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepIntType))
                precondition(buffer.getU32() == 1)
                addressProperties[key] = buffer.get(ipv4AddressSize).reversed()
            } else if softether160BitsProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepBytesType))
                precondition(buffer.getU32() == 1)
                let size = Int(buffer.getU32())
                precondition(size == 20)
                bytesProperties[key] = buffer.get(size)
            } else if softetherBytesProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepBytesType))
                precondition(buffer.getU32() == 1)
                let size = Int(buffer.getU32())
                precondition(size >= 0)
                bytesProperties[key] = buffer.get(size)
            } else if softetherAsciiProperties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepAsciiType))
                precondition(buffer.getU32() == 1)
                let size = Int(buffer.getU32())
                precondition(size >= 0)
                asciiProperties[key] = String(bytes: buffer.get(size), encoding: .ascii) ?? ""
            } else if softetherUtf8Properties.contains(key) {
                precondition(buffer.getU32() == UInt32(sepUtf8Type))
                precondition(buffer.getU32() == 1)
                let size = Int(buffer.getU32())
                precondition(size >= 0)
                utf8Properties[key] = String(bytes: buffer.get(size), encoding: .utf8) ?? ""
            } else {
                discardProperty(buffer)
            }
        }
    }

    private func discardProperty(_ buffer: ByteBuffer) {
        switch Int(buffer.getU32()) {
        case sepIntType: buffer.move(4 + 4)
        case sepLongType: buffer.move(4 + 8)
        case sepBytesType, sepAsciiType, sepUtf8Type:
            buffer.move(4)
            let size = Int(buffer.getU32())
            precondition(size >= 0)
            buffer.move(size)
        default: preconditionFailure("unknown property type")
        }
    }
}
