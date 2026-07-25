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
    private let materialGenerator: @Sendable (String) throws -> PairingMaterial

    public init(clientInfo: SPLClientInfo) {
        self.init(session: .shared, lanTransport: CertlessPairExchange(), clientInfo: clientInfo)
    }

    init(
        session: URLSession,
        lanTransport: any LANPairTransport = CertlessPairExchange(),
        clientInfo: SPLClientInfo,
        materialGenerator: @escaping @Sendable (String) throws -> PairingMaterial = Self.generatePairingMaterial
    ) {
        self.session = session
        self.lanTransport = lanTransport
        self.clientInfo = clientInfo
        self.materialGenerator = materialGenerator
    }

    public func pair(
        pairURL: PairURL,
        deviceLabel: String,
        relayEndpoint: URL,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate] = { $0 }
    ) async throws -> StoredPairing {
        switch pairURL.kind {
        case .direct:
            return try await pairDirect(
                pairURL: pairURL,
                deviceLabel: deviceLabel,
                relayEndpoint: relayEndpoint,
                orderCandidates: orderCandidates
            )
        case .relay:
            let generated = try materialGenerator(deviceLabel)
            let validatedRelayEndpoint = try Self.validatedRelayEndpoint(relayEndpoint)
            return try await pairViaRelay(
                pairURL: pairURL,
                generated: generated,
                deviceLabel: deviceLabel,
                defaultRelayEndpoint: validatedRelayEndpoint
            )
        }
    }

    func pair(
        pairURL: PairURL,
        deviceLabel: String,
        relayEndpoint: RelayEndpoint,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate] = { $0 }
    ) async throws -> StoredPairing {
        switch pairURL.kind {
        case .direct:
            return try await pairDirect(
                pairURL: pairURL,
                deviceLabel: deviceLabel,
                relayEndpoint: relayEndpoint.url,
                enrollmentEndpoint: relayEndpoint,
                orderCandidates: orderCandidates
            )
        case .relay:
            let generated = try materialGenerator(deviceLabel)
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
        deviceLabel: String,
        relayEndpoint: URL,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate]
    ) async throws -> StoredPairing {
        let enrollmentEndpoint = try? RelayEndpoint(relayEndpoint)
        return try await pairDirect(
            pairURL: pairURL,
            deviceLabel: deviceLabel,
            relayEndpoint: relayEndpoint,
            enrollmentEndpoint: enrollmentEndpoint,
            orderCandidates: orderCandidates
        )
    }

    private func pairDirect(
        pairURL: PairURL,
        deviceLabel: String,
        relayEndpoint: URL,
        enrollmentEndpoint: RelayEndpoint?,
        orderCandidates: @Sendable ([PairCandidate]) -> [PairCandidate]
    ) async throws -> StoredPairing {
        guard pairURL.candidates.allSatisfy({ TunnelAddressClassifier.isLocalNetworkAddressLiteral($0.address) }) else {
            pairLog.notice("direct pair candidates rejected reason=\("non_local_candidate", privacy: .public) count=\(pairURL.candidates.count, privacy: .public)")
            throw PairError.directAddressNotLocal
        }
        let canonical = Self.coalesceCandidates(pairURL.candidates)
        let ordered = Self.validatedOrderedCandidates(
            requested: orderCandidates(canonical),
            canonical: canonical
        )
        let generated = try materialGenerator(deviceLabel)
        let jsonBody = try Self.encodePairRequestBody(csrPEM: generated.csrPEM, deviceLabel: deviceLabel)
        var sawCAFingerprintMismatch = false
        var lastError: PairError?

        for (index, candidate) in ordered.enumerated() {
            let candidatePort = Int(candidate.port)
            pairLog.notice("dialing pair candidate index=\(index + 1, privacy: .public) count=\(ordered.count, privacy: .public) host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
            var attempt: (any LANPairAttempt)?
            var requestCommitted = false
            do {
                let prepared = try await lanTransport.prepare(
                    host: candidate.address,
                    port: candidatePort,
                    caFingerprintBytes: pairURL.caFingerprintBytes
                )
                attempt = prepared
                let requestBytes = CertlessPairExchange.encodeRequest(
                    host: candidate.address,
                    path: "/app/network/pair?token=\(CertChain.hex(pairURL.nonceBytes))",
                    jsonBody: jsonBody
                )
                requestCommitted = true
                let response = try await prepared.send(requestBytes: requestBytes)
                let lanResponse = try Self.decodePairResponse(status: response.status, body: response.body)
                await attempt?.close()
                attempt = nil
                pairLog.notice("paired direct host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
                let relayEnrollment = await optionalRelayEnrollment(relayEndpoint: enrollmentEndpoint, lanResponse: lanResponse)
                return try Self.makeStoredPairing(
                    lanResponse: lanResponse,
                    generated: generated,
                    relayEndpoint: relayEndpoint,
                    relayEnrollment: relayEnrollment,
                    dialedEndpoint: LocalEndpoint(host: candidate.address, port: candidatePort, scope: "")
                )
            } catch {
                await attempt?.close()
                let pairError = Self.mapDirectPairError(error)
                if requestCommitted {
                    throw pairError
                }
                try Task.checkCancellation()
                switch pairError {
                case .lanCAFingerprintMismatch:
                    sawCAFingerprintMismatch = true
                    lastError = pairError
                    pairLog.notice("pair candidate ca_mismatch host=\(candidate.address, privacy: .public) port=\(candidatePort, privacy: .public)")
                default:
                    lastError = pairError
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
        defaultRelayEndpoint: RelayEndpoint
    ) async throws -> StoredPairing {
        let pairKey: PairWindowRelayKey
        do {
            pairKey = try PairWindowRelayKey(sBytes: pairURL.sBytes)
        } catch {
            throw PairError.relayResponseInvalid(status: nil)
        }

        let relayEndpoint = try Self.relayEndpoint(pairURL.relayOrigin, default: defaultRelayEndpoint)
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
            relayEndpoint: relayEndpoint.url,
            relayEnrollment: relayEnrollment
        )
    }

    private static func coalesceCandidates(_ candidates: [PairCandidate]) -> [PairCandidate] {
        var seen: Set<PairCandidate> = []
        var result: [PairCandidate] = []
        result.reserveCapacity(candidates.count)
        for candidate in candidates where !seen.contains(candidate) {
            seen.insert(candidate)
            result.append(candidate)
        }
        return result
    }

    private static func validatedOrderedCandidates(requested: [PairCandidate], canonical: [PairCandidate]) -> [PairCandidate] {
        let canonicalCounts = candidateCounts(canonical)
        let requestedCounts = candidateCounts(requested)
        guard requestedCounts == canonicalCounts else {
            let missingCount = canonicalCounts.reduce(0) { total, entry in
                total + max(0, entry.value - (requestedCounts[entry.key] ?? 0))
            }
            let unknownCount = requestedCounts.reduce(0) { total, entry in
                total + (canonicalCounts[entry.key] == nil ? entry.value : 0)
            }
            let duplicateCount = requestedCounts.reduce(0) { total, entry in
                total + max(0, entry.value - 1)
            }
            pairLog.notice(
                "direct pair candidate order rejected reason=\("invalid_permutation", privacy: .public) input_count=\(canonical.count, privacy: .public) output_count=\(requested.count, privacy: .public) missing_count=\(missingCount, privacy: .public) unknown_count=\(unknownCount, privacy: .public) duplicate_count=\(duplicateCount, privacy: .public) using=\("candidate_link_order", privacy: .public)"
            )
            return canonical
        }
        return requested
    }

    private static func candidateCounts(_ candidates: [PairCandidate]) -> [PairCandidate: Int] {
        var counts: [PairCandidate: Int] = [:]
        for candidate in candidates {
            counts[candidate, default: 0] += 1
        }
        return counts
    }

    private static func mapDirectPairError(_ error: any Error) -> PairError {
        if let pairError = error as? PairError {
            return pairError
        }
        if let tlsError = error as? InnerTLSError {
            switch tlsError {
            case .caFingerprintMismatch, .peerNotPinned:
                return .lanCAFingerprintMismatch
            default:
                return .lanRequestFailed(underlying: tlsError)
            }
        }
        if let certlessError = error as? CertlessPairError {
            switch certlessError {
            case .closedBeforeStatus:
                return .lanClosedBeforeResponse
            case .malformedResponse:
                return .lanResponseInvalid(status: nil)
            }
        }
        return .lanRequestFailed(underlying: error)
    }

    private func postRelay(relayEndpoint: RelayEndpoint, lanResponse: LANPairResponse) async throws -> RelayEnrollResponse {
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

    private func optionalRelayEnrollment(relayEndpoint: RelayEndpoint?, lanResponse: LANPairResponse) async -> RelayEnrollment {
        guard let relayEndpoint else {
            pairLog.notice("relay enrollment failed")
            return .unavailable
        }
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

    static func makeRelayRequest(relayEndpoint: RelayEndpoint, response: LANPairResponse, userAgent: String) throws -> URLRequest {
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
        try controlURL(validatedRelayEndpoint(base), path: path, queryItems: queryItems)
    }

    static func controlURL(_ base: RelayEndpoint, path: String, queryItems: [URLQueryItem] = []) throws -> URL {
        guard var components = URLComponents(url: base.url, resolvingAgainstBaseURL: false),
              let scheme = base.controlScheme else {
            throw PairError.relayResponseInvalid(status: nil)
        }

        components.scheme = scheme

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

    private static func validatedRelayEndpoint(_ url: URL) throws -> RelayEndpoint {
        do {
            return try RelayEndpoint(url)
        } catch {
            throw PairError.relayResponseInvalid(status: nil)
        }
    }

    private static func relayEndpoint(_ origin: RelayOrigin?, default defaultEndpoint: RelayEndpoint) throws -> RelayEndpoint {
        guard let origin else {
            return defaultEndpoint
        }
        switch origin {
        case .wellKnown:
            return defaultEndpoint
        case .custom(let url):
            return try validatedRelayEndpoint(url)
        }
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
        case 403:
            // The cert-less gate also emits "pairing tunnel may only use /app/network/pair";
            // only "pairing window closed" is a window-closed signal.
            let message = String(data: body, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            if message == "pairing window closed" {
                throw PairError.pairingWindowClosed
            }
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
    case lanClosedBeforeResponse
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
             (.lanClosedBeforeResponse, .lanClosedBeforeResponse),
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
