// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import os
import Security

private let pairLog = SPLLogging.logger(for: .pair)

public struct PairClient: Sendable {
    private let session: URLSession
    private let lanTransport: any LANPairTransport
    private let clientInfo: SPLClientInfo

    public init(clientInfo: SPLClientInfo) {
        self.init(session: .shared, lanTransport: CertlessPairExchange(), clientInfo: clientInfo)
    }

    init(session: URLSession, lanTransport: any LANPairTransport = CertlessPairExchange(), clientInfo: SPLClientInfo) {
        self.session = session
        self.lanTransport = lanTransport
        self.clientInfo = clientInfo
    }

    public func pair(
        pairURL: PairURL,
        deviceLabel: String,
        relayEndpoint: URL,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate] = { $0 }
    ) async throws -> StoredPairing {
        let generated = try Self.generatePairingMaterial(deviceLabel: deviceLabel)
        switch pairURL.kind {
        case .direct:
            return try await pairDirect(
                pairURL: pairURL,
                generated: generated,
                deviceLabel: deviceLabel,
                relayEndpoint: relayEndpoint,
                orderCandidates: orderCandidates
            )
        case .relay:
            return try await pairViaRelay(
                pairURL: pairURL,
                generated: generated,
                deviceLabel: deviceLabel,
                defaultRelayEndpoint: relayEndpoint
            )
        }
    }

    private func pairDirect(
        pairURL: PairURL,
        generated: PairingMaterial,
        deviceLabel: String,
        relayEndpoint: URL,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate]
    ) async throws -> StoredPairing {
        guard pairURL.candidates.allSatisfy({ TunnelAddressClassifier.isLocalNetworkAddressLiteral($0.address) }) else {
            pairLog.notice("direct pair candidates rejected reason=\("non_local_candidate", privacy: .public) count=\(pairURL.candidates.count, privacy: .public)")
            throw PairError.directAddressNotLocal
        }
        let ordered = orderCandidates(pairURL.candidates)
        var sawCAFingerprintMismatch = false
        var lastError: PairError?

        for (index, candidate) in ordered.enumerated() {
            let candidatePort = Int(candidate.port)
            pairLog.notice("dialing pair candidate index=\(index + 1, privacy: .public) count=\(ordered.count, privacy: .public) host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
            do {
                let lanResponse = try await postDirectPair(
                    pairURL: pairURL,
                    host: candidate.address,
                    port: candidatePort,
                    csrPEM: generated.csrPEM,
                    deviceLabel: deviceLabel
                )
                pairLog.notice("paired direct host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
                let relayEnrollment = await optionalRelayEnrollment(relayEndpoint: relayEndpoint, lanResponse: lanResponse)
                return try Self.makeStoredPairing(
                    lanResponse: lanResponse,
                    generated: generated,
                    relayEndpoint: relayEndpoint,
                    relayEnrollment: relayEnrollment,
                    dialedEndpoint: LocalEndpoint(host: candidate.address, port: candidatePort, scope: "")
                )
            } catch let error as PairError {
                switch error {
                case .nonceExpired, .pairingWindowClosed:
                    throw error
                case .lanCAFingerprintMismatch:
                    sawCAFingerprintMismatch = true
                    lastError = error
                    pairLog.notice("pair candidate ca_mismatch host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
                default:
                    lastError = error
                }
            }
        }

        pairLog.notice("pair candidates exhausted count=\(ordered.count, privacy: .public)")
        if ordered.count == 1, let lastError {
            throw lastError
        }
        throw PairError.lanCandidatesExhausted(sawCAFingerprintMismatch: sawCAFingerprintMismatch)
    }

    private func pairViaRelay(
        pairURL: PairURL,
        generated: PairingMaterial,
        deviceLabel: String,
        defaultRelayEndpoint: URL
    ) async throws -> StoredPairing {
        let pairKey: PairWindowRelayKey
        do {
            pairKey = try PairWindowRelayKey(sBytes: pairURL.sBytes)
        } catch {
            throw PairError.relayResponseInvalid(status: nil)
        }

        let relayEndpoint = pairURL.relayOrigin?.resolved(default: defaultRelayEndpoint) ?? defaultRelayEndpoint
        let lanResponse: LANPairResponse
        do {
            let transport = try await DialClient.dialPairRelay(
                endpoint: relayEndpoint,
                pairKey: pairKey,
                clientInfo: clientInfo
            )
            lanResponse = try await Self.postPairThroughTunnel(
                transport: transport,
                caPin: pairURL.caPin,
                path: Self.pairWindowInnerPath(sBytes: pairURL.sBytes),
                csrPEM: generated.csrPEM,
                deviceLabel: deviceLabel,
                clientInfo: clientInfo
            )
        } catch let error as DialError {
            switch error {
            case .pairingWindowClosed, .relayUnauthorized:
                throw PairError.pairingWindowClosed
            default:
                throw PairError.relayRequestFailed(underlying: error)
            }
        }
        let relayEnrollment = await optionalRelayEnrollment(relayEndpoint: relayEndpoint, lanResponse: lanResponse)
        return try Self.makeStoredPairing(
            lanResponse: lanResponse,
            generated: generated,
            relayEndpoint: relayEndpoint,
            relayEnrollment: relayEnrollment
        )
    }

    private func postDirectPair(
        pairURL: PairURL,
        host: String,
        port: Int,
        csrPEM: String,
        deviceLabel: String
    ) async throws -> LANPairResponse {
        let jsonBody = try Self.encodePairRequestBody(csrPEM: csrPEM, deviceLabel: deviceLabel)
        let response: (status: Int, body: Data)
        do {
            response = try await lanTransport.send(
                host: host,
                port: port,
                caFingerprintBytes: pairURL.caFingerprintBytes,
                requestBytes: CertlessPairExchange.encodeRequest(
                    host: host,
                    path: "/app/network/pair?token=\(CertChain.hex(pairURL.nonceBytes))",
                    jsonBody: jsonBody
                )
            )
        } catch InnerTLSError.caFingerprintMismatch {
            throw PairError.lanCAFingerprintMismatch
        } catch InnerTLSError.peerNotPinned {
            throw PairError.lanCAFingerprintMismatch
        } catch CertlessPairError.closedBeforeStatus {
            throw PairError.pairingWindowClosed
        } catch CertlessPairError.malformedResponse {
            throw PairError.lanResponseInvalid(status: nil)
        } catch {
            throw PairError.lanRequestFailed(underlying: error)
        }

        return try Self.decodePairResponse(status: response.status, body: response.body)
    }

    private func postRelay(relayEndpoint: URL, lanResponse: LANPairResponse) async throws -> RelayEnrollResponse {
        let request = try Self.makeRelayRequest(
            relayEndpoint: relayEndpoint,
            response: lanResponse,
            userAgent: clientInfo.userAgent
        )

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw PairError.relayRequestFailed(underlying: error)
        }

        guard let http = response as? HTTPURLResponse else {
            throw PairError.relayResponseInvalid(status: nil)
        }

        switch http.statusCode {
        case 200:
            do {
                return try Self.decodeRelayResponse(data: data)
            } catch {
                throw PairError.relayResponseInvalid(status: http.statusCode)
            }
        case 401, 403, 409:
            throw PairError.attestationRejected(status: http.statusCode)
        case 400, 404:
            throw PairError.relayResponseInvalid(status: http.statusCode)
        case 503:
            throw PairError.relayRequestFailed(underlying: nil)
        case 500...599:
            throw PairError.relayRequestFailed(underlying: nil)
        default:
            throw PairError.relayResponseInvalid(status: http.statusCode)
        }
    }

    private func optionalRelayEnrollment(relayEndpoint: URL, lanResponse: LANPairResponse) async -> RelayEnrollment {
        do {
            let relayResponse = try await postRelay(relayEndpoint: relayEndpoint, lanResponse: lanResponse)
            return .enrolled(deviceToken: relayResponse.deviceToken, expiresAt: relayResponse.expiresAt)
        } catch let error as PairError {
            if let status = error.statusCode {
                pairLog.notice("relay enrollment failed status=\(status, privacy: .public)")
            } else {
                pairLog.notice("relay enrollment failed")
            }
            return .unavailable
        } catch {
            pairLog.notice("relay enrollment failed")
            return .unavailable
        }
    }

    static func postPairThroughTunnel(
        transport: any ByteTransport,
        caPin: PairingCAPin,
        path: String,
        csrPEM: String,
        deviceLabel: String,
        clientInfo: SPLClientInfo
    ) async throws -> LANPairResponse {
        let tls: InnerTLS
        let caSPKIDER: [UInt8]
        do {
            let pairingTLS = try await InnerTLS.connectPairingViaTransport(transport: transport, caPin: caPin)
            tls = pairingTLS.tls
            caSPKIDER = pairingTLS.caSPKIDER
        } catch InnerTLSError.peerNotPinned {
            throw PairError.lanCAFingerprintMismatch
        } catch InnerTLSError.caFingerprintMismatch {
            throw PairError.lanCAFingerprintMismatch
        }
        let mux = Multiplexer(sink: { data in
            try await tls.send(data)
        }, role: .dialer)
        let pump = Task {
            do {
                for try await chunk in tls.inbound {
                    try await mux.feedInbound(chunk)
                }
                await mux.tearDown(reason: .transportFailure)
            } catch {
                await mux.tearDown(reason: .transportFailure)
            }
        }

        do {
            let requestBody = try Self.encodePairRequestBody(csrPEM: csrPEM, deviceLabel: deviceLabel)
            let stream = try await mux.openStream()
            try await stream.write(Self.buildHTTPRequest(
                method: "POST",
                path: path,
                body: requestBody,
                clientInfo: clientInfo
            ))
            try await stream.close()

            var responseData = Data()
            for try await chunk in stream.inbound {
                responseData.append(chunk)
            }
            let response = try Self.parseHTTPResponse(responseData)
            let lanResponse = try Self.decodePairResponse(status: response.status, body: response.body)
            try Self.verifyRelayPairResponse(lanResponse, caSPKIDER: caSPKIDER)
            await cleanupPairingTunnel(tls: tls, mux: mux, pump: pump)
            return lanResponse
        } catch {
            await cleanupPairingTunnel(tls: tls, mux: mux, pump: pump)
            throw error
        }
    }

    static func encodePairRequestBody(csrPEM: String, deviceLabel: String) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(LANPairRequest(csr: csrPEM, deviceLabel: deviceLabel))
    }

    static func pairWindowInnerPath(sBytes: [UInt8]) -> String {
        "/app/network/pair?token=\(CertChain.hex(sBytes))"
    }

    static func verifyRelayPairResponse(_ response: LANPairResponse, caSPKIDER: [UInt8]) throws {
        let responseCAP256SPKI = try responseCAP256SPKI(response.caChain)
        guard responseCAP256SPKI == caSPKIDER else {
            throw PairError.relayInstanceMismatch
        }
        let expected = CertChain.jidFromSPKI(caSPKIDER)
        guard response.instanceID == expected else {
            throw PairError.relayInstanceMismatch
        }
    }

    private static func responseCAP256SPKI(_ caChain: [String]) throws -> [UInt8] {
        do {
            let certificates = try CertChain.certificates(fromPEM: joinPEMChain(caChain))
            guard let caCertificate = certificates.first else {
                throw PairError.relayInstanceMismatch
            }
            return try CertChain.canonicalP256SubjectPublicKeyInfoDER(certificate: caCertificate)
        } catch let error as PairError {
            throw error
        } catch {
            throw PairError.relayInstanceMismatch
        }
    }

    static func makeRelayRequest(relayEndpoint: URL, response: LANPairResponse, userAgent: String) throws -> URLRequest {
        var request = URLRequest(url: try controlURL(relayEndpoint, path: "enroll/device"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONEncoder().encode(RelayEnrollRequest(
            instanceID: response.instanceID,
            homeAttestation: response.homeAttestation
        ))
        return request
    }

    static func buildHTTPRequest(method: String, path: String, body: Data, clientInfo: SPLClientInfo) -> Data {
        var request = Data()
        let head = [
            "\(method) \(path) HTTP/1.1",
            "Host: spl.local",
            "User-Agent: \(clientInfo.userAgent)",
            "Content-Type: application/json",
            "Content-Length: \(body.count)",
            "Connection: close",
            "",
            "",
        ].joined(separator: "\r\n")
        request.append(Data(head.utf8))
        request.append(body)
        return request
    }

    static func decodeLANResponse(data: Data) throws -> LANPairResponse {
        try JSONDecoder().decode(LANPairResponse.self, from: data)
    }

    static func decodeRelayResponse(data: Data) throws -> RelayEnrollResponse {
        try JSONDecoder().decode(RelayEnrollResponse.self, from: data)
    }

    static func controlURL(_ base: URL, path: String, queryItems: [URLQueryItem] = []) throws -> URL {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              components.host != nil else {
            throw PairError.relayResponseInvalid(status: nil)
        }

        switch scheme {
        case "https", "http":
            components.scheme = scheme
        case "wss":
            components.scheme = "https"
        case "ws":
            components.scheme = "http"
        default:
            throw PairError.relayResponseInvalid(status: nil)
        }

        let basePath = components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let suffix = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.percentEncodedPath = "/" + [basePath, suffix].filter { !$0.isEmpty }.joined(separator: "/")
        var mergedItems = components.queryItems ?? []
        mergedItems.append(contentsOf: queryItems)
        components.queryItems = mergedItems.isEmpty ? nil : mergedItems

        guard let url = components.url else {
            throw PairError.relayResponseInvalid(status: nil)
        }
        return url
    }

    static func parseHTTPResponse(_ data: Data) throws -> PairHTTPResponse {
        let marker = Data("\r\n\r\n".utf8)
        guard let range = data.range(of: marker),
              let headerText = String(data: data[data.startIndex..<range.lowerBound], encoding: .utf8) else {
            throw PairError.lanResponseInvalid(status: nil)
        }

        let lines = headerText.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else {
            throw PairError.lanResponseInvalid(status: nil)
        }
        let statusParts = statusLine.split(separator: " ")
        guard statusParts.count >= 2,
              let status = Int(statusParts[1]) else {
            throw PairError.lanResponseInvalid(status: nil)
        }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        var body = Data(data[range.upperBound...])
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = try decodeChunkedBody(body)
        } else if let rawLength = headers["content-length"],
                  let length = Int(rawLength),
                  body.count > length {
            body = Data(body.prefix(length))
        }
        return PairHTTPResponse(status: status, headers: headers, body: body)
    }

    private static func generatePairingMaterial(deviceLabel: String) throws -> PairingMaterial {
        do {
            let generated = try CryptoCSR.generate(deviceLabel: deviceLabel)
            return PairingMaterial(csrPEM: generated.csrPEM, privateKeyPEM: generated.privateKeyPEM)
        } catch {
            throw PairError.csrBuildFailed
        }
    }

    private static func decodePairResponse(status: Int, body: Data) throws -> LANPairResponse {
        switch status {
        case 200:
            do {
                return try decodeLANResponse(data: body)
            } catch {
                throw PairError.lanResponseInvalid(status: status)
            }
        case 400, 401, 404:
            throw PairError.lanResponseInvalid(status: status)
        case 410:
            throw PairError.nonceExpired
        case 500...599:
            throw PairError.lanRequestFailed(underlying: nil)
        default:
            throw PairError.lanResponseInvalid(status: status)
        }
    }

    private static func makeStoredPairing(
        lanResponse: LANPairResponse,
        generated: PairingMaterial,
        relayEndpoint: URL,
        relayEnrollment: RelayEnrollment,
        dialedEndpoint: LocalEndpoint? = nil
    ) throws -> StoredPairing {
        let certificates = try? CertChain.certificates(fromPEM: lanResponse.clientCert)
        guard let clientCertificate = certificates?.first else {
            throw PairError.lanResponseInvalid(status: nil)
        }

        var localEndpoints = lanResponse.localEndpoints
        if let dialedEndpoint {
            let existingScope = localEndpoints.first {
                $0.host == dialedEndpoint.host && $0.port == dialedEndpoint.port
            }?.scope
            localEndpoints.removeAll {
                $0.host == dialedEndpoint.host && $0.port == dialedEndpoint.port
            }
            localEndpoints.insert(
                LocalEndpoint(
                    host: dialedEndpoint.host,
                    port: dialedEndpoint.port,
                    scope: existingScope ?? dialedEndpoint.scope
                ),
                at: 0
            )
        }

        return StoredPairing(
            instanceID: lanResponse.instanceID,
            homeLabel: lanResponse.homeLabel,
            relayEndpoint: relayEndpoint.absoluteString,
            fingerprint: "sha256:\(CertChain.sha256Fingerprint(of: clientCertificate))",
            clientCertPEM: lanResponse.clientCert,
            clientKeyPEM: generated.privateKeyPEM,
            caChainPEM: joinPEMChain(lanResponse.caChain),
            relayEnrollment: relayEnrollment,
            localEndpoints: localEndpoints,
            pairedAt: Date()
        )
    }

    private static func cleanupPairingTunnel(tls: InnerTLS, mux: Multiplexer, pump: Task<Void, Never>) async {
        pump.cancel()
        await mux.tearDown(reason: .normalShutdown)
        await tls.close()
    }

    private static func decodeChunkedBody(_ body: Data) throws -> Data {
        let crlf = Data("\r\n".utf8)
        var cursor = body.startIndex
        var decoded = Data()

        while cursor < body.endIndex {
            guard let lineRange = body[cursor...].range(of: crlf),
                  let line = String(data: body[cursor..<lineRange.lowerBound], encoding: .utf8) else {
                throw PairError.lanResponseInvalid(status: nil)
            }
            let sizeToken = line.split(separator: ";", maxSplits: 1).first.map(String.init) ?? line
            guard let size = Int(sizeToken.trimmingCharacters(in: .whitespaces), radix: 16) else {
                throw PairError.lanResponseInvalid(status: nil)
            }
            cursor = lineRange.upperBound
            if size == 0 {
                return decoded
            }
            guard cursor + size <= body.endIndex else {
                throw PairError.lanResponseInvalid(status: nil)
            }
            decoded.append(body[cursor..<(cursor + size)])
            cursor += size
            guard cursor + crlf.count <= body.endIndex,
                  Data(body[cursor..<(cursor + crlf.count)]) == crlf else {
                throw PairError.lanResponseInvalid(status: nil)
            }
            cursor += crlf.count
        }

        throw PairError.lanResponseInvalid(status: nil)
    }

    private static func joinPEMChain(_ chain: [String]) -> String {
        chain.map { pem in
            pem.hasSuffix("\n") ? pem : "\(pem)\n"
        }.joined()
    }
}

struct PairingMaterial: Sendable {
    let csrPEM: String
    let privateKeyPEM: String
}

struct PairHTTPResponse: Equatable, Sendable {
    let status: Int
    let headers: [String: String]
    let body: Data
}

struct LANPairRequest: Encodable {
    let csr: String
    let deviceLabel: String

    enum CodingKeys: String, CodingKey {
        case csr
        case deviceLabel = "device_label"
    }
}

struct LANPairResponse: Decodable {
    let instanceID: String
    let homeLabel: String
    let clientCert: String
    let caChain: [String]
    let homeAttestation: String
    let localEndpoints: [LocalEndpoint]

    enum CodingKeys: String, CodingKey {
        case instanceID = "instance_id"
        case homeLabel = "home_label"
        case clientCert = "client_cert"
        case caChain = "ca_chain"
        case homeAttestation = "home_attestation"
        case localEndpoints = "local_endpoints"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        instanceID = try container.decode(String.self, forKey: .instanceID)
        homeLabel = try container.decode(String.self, forKey: .homeLabel)
        clientCert = try container.decode(String.self, forKey: .clientCert)
        caChain = try container.decode([String].self, forKey: .caChain)
        homeAttestation = try container.decode(String.self, forKey: .homeAttestation)
        localEndpoints = try container.decodeIfPresent([LocalEndpoint].self, forKey: .localEndpoints) ?? []
    }
}

struct RelayEnrollRequest: Encodable {
    let instanceID: String
    let homeAttestation: String

    enum CodingKeys: String, CodingKey {
        case instanceID = "instance_id"
        case homeAttestation = "home_attestation"
    }
}

struct RelayEnrollResponse: Decodable {
    let deviceToken: String
    let expiresAt: String?

    enum CodingKeys: String, CodingKey {
        case deviceToken = "device_token"
        case expiresAt = "expires_at"
    }
}

public enum PairError: Error, Equatable, Sendable {
    case csrBuildFailed
    case lanRequestFailed(underlying: (any Error & Sendable)?)
    case lanCAFingerprintMismatch
    case lanResponseInvalid(status: Int?)
    case nonceExpired
    case pairingWindowClosed
    case lanCandidatesExhausted(sawCAFingerprintMismatch: Bool)
    case relayRequestFailed(underlying: (any Error & Sendable)?)
    case relayResponseInvalid(status: Int?)
    case relayInstanceMismatch
    case attestationRejected(status: Int)
    case directAddressNotLocal

    var statusCode: Int? {
        switch self {
        case .lanResponseInvalid(let status),
             .relayResponseInvalid(let status):
            return status
        case .attestationRejected(let status):
            return status
        default:
            return nil
        }
    }

    public static func == (lhs: PairError, rhs: PairError) -> Bool {
        switch (lhs, rhs) {
        case (.csrBuildFailed, .csrBuildFailed),
             (.lanRequestFailed, .lanRequestFailed),
             (.lanCAFingerprintMismatch, .lanCAFingerprintMismatch),
             (.nonceExpired, .nonceExpired),
             (.pairingWindowClosed, .pairingWindowClosed),
             (.relayRequestFailed, .relayRequestFailed),
             (.relayInstanceMismatch, .relayInstanceMismatch),
             (.directAddressNotLocal, .directAddressNotLocal):
            return true
        case (.lanCandidatesExhausted(let lhsSawCA), .lanCandidatesExhausted(let rhsSawCA)):
            return lhsSawCA == rhsSawCA
        case (.lanResponseInvalid(let lhsStatus), .lanResponseInvalid(let rhsStatus)):
            return lhsStatus == rhsStatus
        case (.relayResponseInvalid(let lhsStatus), .relayResponseInvalid(let rhsStatus)):
            return lhsStatus == rhsStatus
        case (.attestationRejected(let lhsStatus), .attestationRejected(let rhsStatus)):
            return lhsStatus == rhsStatus
        default:
            return false
        }
    }
}
