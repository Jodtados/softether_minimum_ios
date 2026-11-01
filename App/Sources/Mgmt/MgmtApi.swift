// Pinned HTTPS transport for the management server — a port of the Android
// AdminApi trust model (and the v2rayNG_ios ModMgmt.swift native side): the
// leaf certificate's SubjectPublicKeyInfo DER must equal the baked SPKI pin
// and nothing else is trusted, so an active man-in-the-middle — provider
// included — cannot read or forge heartbeats and console commands. The server
// has no domain, so no hostname verification applies; an absent or mismatched
// pin fails closed for https requests.

import Foundation
import Security

struct MgmtResponse {
    let status: Int
    let body: String

    func json() -> [String: Any]? {
        guard let data = body.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

enum MgmtError: Error {
    case network(String)
    /// non-2xx reply: status plus the server's "error" detail when present
    case http(Int, String)

    var message: String {
        switch self {
        case .network(let text): return text
        case .http(let code, let detail):
            return detail.isEmpty ? "HTTP \(code)" : "HTTP \(code): \(detail)"
        }
    }
}

final class MgmtApi {
    static let shared = MgmtApi()
    private init() {}

    /// URL normalization identical to the Android client: trim space and
    /// trailing slashes; a scheme-less value gets http:// (the full baked URL
    /// always carries its own scheme).
    static func normalize(_ raw: String) -> String {
        var trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        if trimmed.isEmpty { return "" }
        return trimmed.hasPrefix("http") ? trimmed : "http://\(trimmed)"
    }

    func endpoint(_ url: String, _ path: String) -> String {
        Self.normalize(url) + path
    }

    func request(
        _ urlText: String,
        method: String = "GET",
        deviceToken: String = "",
        body: String? = nil,
        completion: @escaping (Result<MgmtResponse, MgmtError>) -> Void
    ) {
        guard let url = URL(string: Self.normalize(urlText)) else {
            completion(.failure(.network("bad url")))
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if !deviceToken.isEmpty {
            request.setValue(deviceToken, forHTTPHeaderField: "X-Device-Token")
        }
        if let body {
            request.httpBody = Data(body.utf8)
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        }

        PinnedRequest(pinB64: MgmtSecrets.spkiPin).run(request) { result in
            DispatchQueue.main.async { completion(result) }
        }
    }
}

/// One request with its own ephemeral session so the pin rides along as
/// delegate state; mgmt traffic is a few requests per minute, so per-request
/// session setup is irrelevant next to the handshake itself.
private final class PinnedRequest: NSObject, URLSessionDataDelegate {
    private let pin: Data?
    private var completion: ((Result<MgmtResponse, MgmtError>) -> Void)?
    private var session: URLSession?

    init(pinB64: String) {
        self.pin = Data(base64Encoded: pinB64)
        super.init()
    }

    func run(_ request: URLRequest, completion: @escaping (Result<MgmtResponse, MgmtError>) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 20
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        self.session = session
        self.completion = completion
        session.dataTask(with: request) { data, response, error in
            self.finish {
                if let error {
                    return .failure(.network(error.localizedDescription))
                }
                guard let http = response as? HTTPURLResponse else {
                    return .failure(.network("no response"))
                }
                let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                let response = MgmtResponse(status: http.statusCode, body: text)
                if (200 ... 299).contains(http.statusCode) {
                    return .success(response)
                }
                let detail = response.json()?["error"] as? String ?? ""
                return .failure(.http(http.statusCode, detail))
            }
        }.resume()
    }

    private func finish(_ build: () -> Result<MgmtResponse, MgmtError>) {
        session?.invalidateAndCancel()
        session = nil
        let built = build()
        completion?(built)
        completion = nil
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // An absent or undecodable pin fails closed for https requests.
        guard let pin, !pin.isEmpty,
            let spki = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?
                .first
                .flatMap(SecCertificateCopyKey)
                .flatMap({ SpkiDer.fromKey($0) }),
            spki == pin
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.performDefaultHandling, URLCredential(trust: trust))
    }
}

/// Rebuilds the SubjectPublicKeyInfo DER that Android pins
/// (`certificate.publicKey.encoded`) from Apple's raw key export
/// (`SecKeyCopyExternalRepresentation`: X9.63 point for EC, PKCS#1 for RSA).
enum SpkiDer {
    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        var bytes = [UInt8]()
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    private static func wrap(tag: UInt8, contents: [UInt8]) -> [UInt8] {
        [tag] + derLength(contents.count) + contents
    }

    /// `parameters` holds a curve OID for EC or the empty DER NULL for RSA
    /// (`05 00`, encoded explicitly by the caller).
    private static func algorithmIdentifier(oid: [UInt8], parameters: [UInt8]) -> [UInt8] {
        wrap(tag: 0x30, contents: wrap(tag: 0x06, contents: oid) + parameters)
    }

    private static func bitString(_ raw: [UInt8]) -> [UInt8] {
        wrap(tag: 0x03, contents: [0x00] + raw)
    }

    // Curve OIDs per RFC 5480: prime256v1, secp384r1, secp521r1.
    private static let curveOids: [Int: [UInt8]] = [
        256: [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        384: [0x2B, 0x81, 0x04, 0x00, 0x22],
        521: [0x2B, 0x81, 0x04, 0x00, 0x23],
    ]

    static func fromKey(_ key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return nil }
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any]
        let keyType = attributes?[kSecAttrKeyType] as? String
        let keySize = attributes?[kSecAttrKeySizeInBits] as? Int ?? 0
        let rawBytes = [UInt8](raw)

        let algorithm: [UInt8]
        let publicKey: [UInt8]
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            guard let curve = curveOids[keySize] else { return nil }
            // EC keys export as the raw uncompressed point || X || Y.
            algorithm = algorithmIdentifier(
                oid: [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01],
                parameters: wrap(tag: 0x06, contents: curve),
            )
            publicKey = bitString(rawBytes)
        } else if keyType == (kSecAttrKeyTypeRSA as String) {
            // RSA keys export as PKCS#1; SPKI wraps it in the rsaEncryption
            // AlgorithmIdentifier with the NULL parameter (05 00).
            algorithm = algorithmIdentifier(
                oid: [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
                parameters: [0x05, 0x00],
            )
            publicKey = bitString(rawBytes)
        } else {
            return nil
        }
        return Data(wrap(tag: 0x30, contents: algorithm + publicKey))
    }
}
