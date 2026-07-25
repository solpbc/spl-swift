// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Security
@testable import SPLTunnel

private let pairingServerQueue = DispatchQueue(label: "SPLTunnel.tests.pairing-server")

struct PairingHTTPServerRequest: Sendable, Equatable {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data
}

struct PairingHTTPServerResponse: Sendable, Equatable {
    let status: Int
    let body: Data
    let headers: [String: String]

    init(status: Int, body: Data, headers: [String: String] = ["Content-Type": "application/json"]) {
        self.status = status
        self.body = body
        self.headers = headers
    }
}

actor PairingMuxServer {
    private let bundle: TestCA.Bundle
    private let responseProvider: @Sendable (PairingHTTPServerRequest) async -> PairingHTTPServerResponse
    private let onRequest: @Sendable (PairingHTTPServerRequest) async -> Void
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var tasks: [Task<Void, Never>] = []
    private var boundPort: NWEndpoint.Port?
    private var closedConnectionCount = 0
    private var closeWaiters: [(count: Int, continuation: CheckedContinuation<Void, Never>)] = []
    private(set) var lastRequest: PairingHTTPServerRequest?
    private(set) var requestCount = 0

    init(
        bundle: TestCA.Bundle,
        response: PairingHTTPServerResponse,
        onRequest: @escaping @Sendable (PairingHTTPServerRequest) async -> Void = { _ in }
    ) {
        self.init(bundle: bundle, onRequest: onRequest) { _ in
            response
        }
    }

    init(
        bundle: TestCA.Bundle,
        directPair configuration: PairingDirectPairConfiguration,
        onRequest: @escaping @Sendable (PairingHTTPServerRequest) async -> Void = { _ in }
    ) {
        let responder = PairingDirectPairResponder(bundle: bundle, configuration: configuration)
        self.init(bundle: bundle, onRequest: onRequest) { request in
            await responder.response(for: request)
        }
    }

    init(
        bundle: TestCA.Bundle,
        onRequest: @escaping @Sendable (PairingHTTPServerRequest) async -> Void = { _ in },
        responseProvider: @escaping @Sendable (PairingHTTPServerRequest) async -> PairingHTTPServerResponse
    ) {
        self.bundle = bundle
        self.responseProvider = responseProvider
        self.onRequest = onRequest
    }

    var port: Int {
        Int(boundPort?.rawValue ?? 0)
    }

    func waitForClosedConnectionCount(_ count: Int) async {
        guard closedConnectionCount < count else {
            return
        }
        await withCheckedContinuation { continuation in
            closeWaiters.append((count: count, continuation: continuation))
        }
    }

    func start() async throws {
        let parameters = NWParameters(tls: try makeServerTLSOptions(), tcp: NWProtocolTCP.Options())
        let listener = try NWListener(using: parameters, on: .any)
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            Task {
                await self.accept(connection)
            }
        }
        self.listener = listener
        try await startAndWaitForPairingListenerReady(listener)
        boundPort = listener.port
    }

    func stop() async {
        for task in tasks {
            task.cancel()
        }
        tasks.removeAll()
        for connection in connections {
            connection.cancel()
        }
        connections.removeAll()
        listener?.cancel()
        listener = nil
        boundPort = nil
    }

    private func accept(_ connection: NWConnection) {
        connections.append(connection)
        connection.start(queue: pairingServerQueue)
        let mux = Multiplexer(sink: { data in
            try await Self.send(data, on: connection)
        }, role: .listener)

        tasks.append(Task {
            await Self.pump(connection: connection, into: mux)
            self.recordConnectionClosed()
        })
        tasks.append(Task {
            for await stream in mux.incomingStreams {
                await self.handle(stream)
            }
        })
    }

    private func handle(_ stream: MuxStream) async {
        do {
            let request = try await Self.readRequest(from: stream)
            lastRequest = request
            requestCount += 1
            await onRequest(request)
            let response = await responseProvider(request)
            try await stream.write(Self.encode(response))
            try await stream.close()
        } catch {
            let failure = PairingHTTPServerResponse(status: 500, body: Data())
            try? await stream.write(Self.encode(failure))
            try? await stream.close()
        }
    }

    private func recordConnectionClosed() {
        closedConnectionCount += 1
        let ready = closeWaiters.filter { closedConnectionCount >= $0.count }
        closeWaiters.removeAll { closedConnectionCount >= $0.count }
        for waiter in ready {
            waiter.continuation.resume()
        }
    }

    private func makeServerTLSOptions() throws -> NWProtocolTLS.Options {
        let identity = try TestCA.secIdentity(
            certificatePEM: "\(bundle.serverCertificatePEM)\n\(bundle.caCertificatePEM)",
            privateKeyPEM: bundle.serverPrivateKeyPEM
        )
        let options = NWProtocolTLS.Options()
        let secOptions = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(secOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(secOptions, .TLSv13)
        sec_protocol_options_set_local_identity(secOptions, identity)
        return options
    }

    private static func pump(connection: NWConnection, into mux: Multiplexer) async {
        do {
            while !Task.isCancelled {
                guard let data = try await receive(from: connection) else {
                    await mux.tearDown(reason: .transportFailure)
                    return
                }
                try await mux.feedInbound(data)
            }
        } catch {
            await mux.tearDown(reason: .transportFailure)
        }
    }

    private static func receive(from connection: NWConnection) async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                    return
                }
                if isComplete {
                    continuation.resume(returning: nil)
                    return
                }
                continuation.resume(returning: nil)
            }
        }
    }

    private static func send(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private static func readRequest(from stream: MuxStream) async throws -> PairingHTTPServerRequest {
        var buffer = Data()
        for try await chunk in stream.inbound {
            buffer.append(chunk)
            if let request = try parseRequest(buffer) {
                return request
            }
        }
        throw CertlessPairError.malformedResponse
    }

    private static func parseRequest(_ data: Data) throws -> PairingHTTPServerRequest? {
        let marker = Data("\r\n\r\n".utf8)
        guard let range = data.range(of: marker),
              let headerText = String(data: data[..<range.lowerBound], encoding: .utf8) else {
            return nil
        }

        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            throw CertlessPairError.malformedResponse
        }
        let requestParts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard requestParts.count >= 2 else {
            throw CertlessPairError.malformedResponse
        }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else {
                throw CertlessPairError.malformedResponse
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }

        guard let rawLength = headers["content-length"],
              let contentLength = Int(rawLength),
              contentLength >= 0 else {
            throw CertlessPairError.malformedResponse
        }
        let bodyStart = range.upperBound
        let bodyEnd = bodyStart + contentLength
        guard data.endIndex >= bodyEnd else {
            return nil
        }

        return PairingHTTPServerRequest(
            method: String(requestParts[0]),
            path: String(requestParts[1]),
            headers: headers,
            body: Data(data[bodyStart..<bodyEnd])
        )
    }

    private static func encode(_ response: PairingHTTPServerResponse) -> Data {
        let reason = HTTPURLResponse.localizedString(forStatusCode: response.status)
        var lines = ["HTTP/1.1 \(response.status) \(reason)"]
        for (name, value) in response.headers.sorted(by: { $0.key < $1.key }) {
            lines.append("\(name): \(value)")
        }
        lines.append("Content-Length: \(response.body.count)")
        lines.append("")
        lines.append("")

        var data = Data(lines.joined(separator: "\r\n").utf8)
        data.append(response.body)
        return data
    }
}

struct PairingDirectPairConfiguration: Sendable {
    let outstandingTokens: Set<String>
    let instanceID: String
    let homeLabel: String
    let homeAttestation: String
    let localEndpoints: [LocalEndpoint]
    let authorizedClients: MockAuthorizedClients

    init(
        token: String,
        instanceID: String,
        homeLabel: String,
        homeAttestation: String,
        localEndpoints: [LocalEndpoint],
        authorizedClients: MockAuthorizedClients
    ) {
        self.outstandingTokens = [token]
        self.instanceID = instanceID
        self.homeLabel = homeLabel
        self.homeAttestation = homeAttestation
        self.localEndpoints = localEndpoints
        self.authorizedClients = authorizedClients
    }

    init(
        outstandingTokens: Set<String>,
        instanceID: String,
        homeLabel: String,
        homeAttestation: String,
        localEndpoints: [LocalEndpoint],
        authorizedClients: MockAuthorizedClients
    ) {
        self.outstandingTokens = outstandingTokens
        self.instanceID = instanceID
        self.homeLabel = homeLabel
        self.homeAttestation = homeAttestation
        self.localEndpoints = localEndpoints
        self.authorizedClients = authorizedClients
    }
}

private actor PairingDirectPairResponder {
    private var outstandingTokens: Set<String>
    private let bundle: TestCA.Bundle
    private let instanceID: String
    private let homeLabel: String
    private let homeAttestation: String
    private let localEndpoints: [LocalEndpoint]
    private let authorizedClients: MockAuthorizedClients

    init(bundle: TestCA.Bundle, configuration: PairingDirectPairConfiguration) {
        self.bundle = bundle
        self.outstandingTokens = configuration.outstandingTokens
        self.instanceID = configuration.instanceID
        self.homeLabel = configuration.homeLabel
        self.homeAttestation = configuration.homeAttestation
        self.localEndpoints = configuration.localEndpoints
        self.authorizedClients = configuration.authorizedClients
    }

    func addToken(_ token: String) {
        outstandingTokens.insert(token)
    }

    func response(for request: PairingHTTPServerRequest) -> PairingHTTPServerResponse {
        guard request.method == "POST" else {
            return Self.json(status: 404, ["error": "not_found"])
        }
        guard let components = URLComponents(string: "http://mock-home\(request.path)"),
              components.path == "/app/network/pair" else {
            return Self.json(status: 404, ["error": "not_found"])
        }
        guard let token = components.queryItems?.first(where: { $0.name == "token" })?.value,
              outstandingTokens.remove(token) != nil else {
            return Self.json(status: 410, ["error": "nonce_expired"])
        }
        guard let pairRequest = try? JSONDecoder().decode(DirectPairRequest.self, from: request.body),
              !pairRequest.csr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !pairRequest.deviceLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return Self.json(status: 400, ["error": "bad_request"])
        }

        do {
            let caKey = try CryptoCSR.pkcs8PEMToPrivateKey(bundle.caPrivateKeyPEM)
            let clientCert = try MockHomeCA.signCSR(
                csrPEM: pairRequest.csr,
                caKey: caKey,
                caCertPEM: bundle.caCertificatePEM
            )
            guard let leaf = try CertChain.certificates(fromPEM: clientCert).first else {
                return Self.json(status: 500, ["error": "cert_sign_failed"])
            }
            authorizedClients.insert(CertChain.sha256Fingerprint(of: leaf))
            let response = DirectPairResponse(
                instanceID: instanceID,
                homeLabel: homeLabel,
                clientCert: clientCert,
                caChain: [bundle.caCertificatePEM],
                homeAttestation: homeAttestation,
                localEndpoints: localEndpoints
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return PairingHTTPServerResponse(status: 200, body: try encoder.encode(response))
        } catch {
            return Self.json(status: 400, ["error": "bad_request"])
        }
    }

    private static func json(status: Int, _ object: [String: String]) -> PairingHTTPServerResponse {
        let body = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        return PairingHTTPServerResponse(status: status, body: body)
    }
}

private struct DirectPairRequest: Decodable {
    let csr: String
    let deviceLabel: String

    enum CodingKeys: String, CodingKey {
        case csr
        case deviceLabel = "device_label"
    }
}

private struct DirectPairResponse: Encodable {
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
}

private final class PairingServerListenerReadyWaiter: @unchecked Sendable {
    // why: NWListener state callbacks race test tasks; NSLock gives one-shot resume.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var result: Result<Void, Error>?

    func wait() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let result: Result<Void, Error>? = lock.withLock {
                if let result = self.result {
                    return result
                }
                self.continuation = continuation
                return nil
            }

            if let result {
                continuation.resume(with: result)
            }
        }
    }

    func complete(_ result: Result<Void, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<Void, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}

private func startAndWaitForPairingListenerReady(_ listener: NWListener) async throws {
    let waiter = PairingServerListenerReadyWaiter()
    listener.stateUpdateHandler = { state in
        switch state {
        case .ready:
            waiter.complete(.success(()))
        case .failed(let error):
            waiter.complete(.failure(error))
        case .cancelled:
            waiter.complete(.failure(DialError.connectionFailed("pairing listener cancelled")))
        case .setup, .waiting:
            break
        @unknown default:
            break
        }
    }
    listener.start(queue: pairingServerQueue)
    try await waiter.wait()
}
