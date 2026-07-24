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
    private let response: PairingHTTPServerResponse
    private let onRequest: @Sendable (PairingHTTPServerRequest) async -> Void
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var tasks: [Task<Void, Never>] = []
    private var boundPort: NWEndpoint.Port?
    private(set) var lastRequest: PairingHTTPServerRequest?
    private(set) var requestCount = 0

    init(
        bundle: TestCA.Bundle,
        response: PairingHTTPServerResponse,
        onRequest: @escaping @Sendable (PairingHTTPServerRequest) async -> Void = { _ in }
    ) {
        self.bundle = bundle
        self.response = response
        self.onRequest = onRequest
    }

    var port: Int {
        Int(boundPort?.rawValue ?? 0)
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
            try await stream.write(Self.encode(response))
            try await stream.close()
        } catch {
            let failure = PairingHTTPServerResponse(status: 500, body: Data())
            try? await stream.write(Self.encode(failure))
            try? await stream.close()
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
