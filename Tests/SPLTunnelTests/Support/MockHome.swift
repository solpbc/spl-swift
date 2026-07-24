// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Crypto
import Foundation
import Network
import Security
@testable import SPLTunnel

private let mockHomeQueue = DispatchQueue(label: "SPLTunnel.tests.mock-home")

actor MockHome {
    let bundle: TestCA.Bundle
    let authorizedClients: MockAuthorizedClients

    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var tasks: [Task<Void, Never>] = []
    private var boundPort: NWEndpoint.Port?
    private var maxAppBufferedRequestBytes = 0
    private var maxReceiveQueueBytes = 0

    init(bundle: TestCA.Bundle, authorizedClients: MockAuthorizedClients) {
        self.bundle = bundle
        self.authorizedClients = authorizedClients
    }

    var port: UInt16? {
        boundPort?.rawValue
    }

    func appRequestBufferHighWaterMark() -> Int {
        maxAppBufferedRequestBytes
    }

    func resetAppRequestBufferHighWaterMark() {
        maxAppBufferedRequestBytes = 0
    }

    func receiveQueueHighWaterMark() -> Int {
        maxReceiveQueueBytes
    }

    func resetReceiveQueueHighWaterMark() {
        maxReceiveQueueBytes = 0
    }

    func start(port requestedPort: Int? = nil) async throws -> (host: String, port: UInt16) {
        if let boundPort {
            return (host: "127.0.0.1", port: boundPort.rawValue)
        }

        let parameters = NWParameters(tls: try makeServerTLSOptions(), tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(
            host: "127.0.0.1",
            port: try Self.requestedListenerPort(requestedPort)
        )
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in
            Task {
                await self?.accept(connection)
            }
        }
        self.listener = listener
        let port = try await startAndWaitForMockHomeListenerReady(listener)
        boundPort = NWEndpoint.Port(rawValue: port)
        return (host: "127.0.0.1", port: port)
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
        connection.start(queue: mockHomeQueue)
        let mux = Multiplexer(sink: { data in
            try await Self.send(data, on: connection)
        }, role: .listener)

        tasks.append(Task {
            await Self.pump(connection: connection, into: mux)
        })
        tasks.append(Task {
            for await stream in mux.incomingStreams {
                await self.handleHTTPRoute(on: stream, mux: mux)
            }
        })
    }

    private func handleHTTPRoute(on stream: MuxStream, mux: Multiplexer) async {
        do {
            let request = try await readRequest(from: stream, mux: mux)
            let response: (Int, [String: Any])
            if request.headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
                response = (411, ["error": "chunked_unsupported"])
            } else if request.body.count > MockHTTPConnection.maxBodySize {
                response = (413, ["error": "body_too_large"])
            } else if request.method == "GET", request.path == "/app/network/api/status" {
                response = (200, ["status": "ok", "echo": "mock-home"])
            } else if request.method == "GET", request.path.hasPrefix("/echo") {
                let message = URLComponents(string: request.path)?
                    .queryItems?
                    .first(where: { $0.name == "msg" })?
                    .value ?? ""
                response = (200, ["msg": message])
            } else if request.method == "POST", request.path == "/app/observer/ingest" {
                response = (200, try Self.ingestResponse(for: request))
            } else {
                response = (404, ["error": "not_found"])
            }
            try await Self.writeJSON(response.1, status: response.0, to: stream)
            try? await stream.close()
        } catch MockHTTPError.bodyTooLarge {
            try? await Self.writeJSON(["error": "body_too_large"], status: 413, to: stream)
            try? await stream.close()
        } catch {
            await stream.reset(reason: .internalError)
        }
    }

    private func readRequest(from stream: MuxStream, mux: Multiplexer) async throws -> MockHTTPRequest {
        var iterator = stream.inbound.makeAsyncIterator()
        var buffer = Data()
        while !buffer.homeHeaderTerminatorRangeFound {
            await recordReceiveQueue(mux)
            guard let chunk = try await iterator.next() else {
                throw MockHTTPError.closed
            }
            buffer.append(chunk)
            recordRequestBuffer(buffer.count)
            if buffer.count > MockHTTPConnection.maxBodySize {
                throw MockHTTPError.bodyTooLarge
            }
        }
        let terminator = buffer.homeHeaderTerminatorRange!
        let headerEnd = terminator.lowerBound
        let bodyStart = terminator.upperBound
        let headerText = String(data: buffer[..<headerEnd], encoding: .utf8) ?? ""
        let lines = headerText.components(separatedBy: "\r\n")
        let parts = (lines.first ?? "").split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count >= 2 else {
            throw MockHTTPError.invalidRequest
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let index = line.firstIndex(of: ":") else {
                continue
            }
            let name = String(line[..<index]).lowercased()
            let value = line[line.index(after: index)...].trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }
        let contentLength = Int(headers["content-length"] ?? "0") ?? 0
        guard contentLength <= MockHTTPConnection.maxBodySize else {
            throw MockHTTPError.bodyTooLarge
        }

        var body = Data(buffer[bodyStart...])
        recordRequestBuffer(body.count)
        while body.count < contentLength {
            await recordReceiveQueue(mux)
            guard let chunk = try await iterator.next() else {
                throw MockHTTPError.closed
            }
            body.append(chunk)
            recordRequestBuffer(body.count)
            if body.count > MockHTTPConnection.maxBodySize {
                throw MockHTTPError.bodyTooLarge
            }
        }
        return MockHTTPRequest(method: parts[0], path: parts[1], headers: headers, body: Data(body.prefix(contentLength)))
    }

    private func recordRequestBuffer(_ byteCount: Int) {
        maxAppBufferedRequestBytes = max(maxAppBufferedRequestBytes, byteCount)
    }

    private func recordReceiveQueue(_ mux: Multiplexer) async {
        maxReceiveQueueBytes = max(maxReceiveQueueBytes, await mux.queuedInboundByteCount())
    }

    private func makeServerTLSOptions() throws -> NWProtocolTLS.Options {
        let anchors = try CertChain.certificates(fromPEM: bundle.caCertificatePEM)
        let identity = try TestCA.secIdentity(
            certificatePEM: "\(bundle.serverCertificatePEM)\n\(bundle.caCertificatePEM)",
            privateKeyPEM: bundle.serverPrivateKeyPEM
        )
        let options = NWProtocolTLS.Options()
        let secOptions = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(secOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(secOptions, .TLSv13)
        sec_protocol_options_set_local_identity(secOptions, identity)
        sec_protocol_options_set_peer_authentication_required(secOptions, true)
        sec_protocol_options_set_verify_block(secOptions, { [authorizedClients] _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            SecTrustSetPolicies(secTrust, SecPolicyCreateBasicX509())
            SecTrustSetAnchorCertificates(secTrust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(secTrust, true)
            var error: CFError?
            guard SecTrustEvaluateWithError(secTrust, &error),
                  let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                  let leaf = chain.first else {
                complete(false)
                return
            }
            complete(authorizedClients.contains(CertChain.sha256Fingerprint(of: leaf)))
        }, mockHomeQueue)
        return options
    }

    private static func ingestResponse(for request: MockHTTPRequest) throws -> [String: Any] {
        let boundary = request.headers["content-type"]?
            .components(separatedBy: "boundary=")
            .last?
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        let files = try parseMultipart(body: request.body, boundary: boundary ?? "")
        let total = files.reduce(0) { $0 + ($1["bytes"] as? Int ?? 0) }
        return ["received_bytes": total, "files": files]
    }

    private static func parseMultipart(body: Data, boundary: String) throws -> [[String: Any]] {
        guard !boundary.isEmpty else {
            let digest = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
            return [["name": "body", "bytes": body.count, "sha256": digest]]
        }
        let marker = Data("--\(boundary)".utf8)
        var cursor = body.startIndex
        var files: [[String: Any]] = []
        while let markerRange = body[cursor...].range(of: marker) {
            cursor = markerRange.upperBound
            if body[cursor...].starts(with: Data("--".utf8)) {
                break
            }
            if body[cursor...].starts(with: Data("\r\n".utf8)) {
                cursor += 2
            }
            guard let headerRange = body[cursor...].range(of: Data("\r\n\r\n".utf8)) else {
                break
            }
            let headerText = String(data: body[cursor..<headerRange.lowerBound], encoding: .utf8) ?? ""
            cursor = headerRange.upperBound
            guard let nextMarker = body[cursor...].range(of: Data("\r\n--\(boundary)".utf8)) else {
                break
            }
            let part = Data(body[cursor..<nextMarker.lowerBound])
            cursor = nextMarker.lowerBound + 2
            let name = headerText.components(separatedBy: "name=\"").dropFirst().first?
                .components(separatedBy: "\"")
                .first ?? "file"
            let digest = SHA256.hash(data: part).map { String(format: "%02x", $0) }.joined()
            files.append(["name": name, "bytes": part.count, "sha256": digest])
        }
        return files
    }

    private static func writeJSON(_ object: [String: Any], status: Int, to stream: MuxStream) async throws {
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let reason = HTTPURLResponse.localizedString(forStatusCode: status)
        var response = Data("HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        response.append(body)
        try await stream.write(response)
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
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                    return
                }
                continuation.resume(returning: isComplete ? nil : Data())
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

    private static func requestedListenerPort(_ port: Int?) throws -> NWEndpoint.Port {
        guard let port else {
            return .any
        }
        guard let requested = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw MockHomeError.invalidListenerPort
        }
        return requested
    }
}

enum MockHomeError: Error {
    case invalidListenerPort
    case listenerMissingPort
}

final class MockAuthorizedClients: @unchecked Sendable {
    // why: TLS verify blocks are synchronous dispatch callbacks; NSLock guards the authorized fingerprint set.
    private let lock = NSLock()
    private var fingerprints = Set<String>()

    func insert(_ fingerprint: String) {
        _ = lock.withLock {
            fingerprints.insert(fingerprint)
        }
    }

    func contains(_ fingerprint: String) -> Bool {
        lock.withLock {
            fingerprints.contains(fingerprint)
        }
    }
}

private final class MockHomeListenerReadyWaiter: @unchecked Sendable {
    // why: NWListener state callbacks run on a dispatch queue while actor start methods await; NSLock serializes one-shot completion.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<UInt16, Error>?
    private var result: Result<UInt16, Error>?

    func wait() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            let result: Result<UInt16, Error>? = lock.withLock {
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

    func complete(_ result: Result<UInt16, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<UInt16, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}

private func startAndWaitForMockHomeListenerReady(_ listener: NWListener) async throws -> UInt16 {
    let waiter = MockHomeListenerReadyWaiter()
    listener.stateUpdateHandler = { state in
        switch state {
        case .ready:
            if let port = listener.port?.rawValue {
                waiter.complete(.success(port))
            } else {
                waiter.complete(.failure(MockHomeError.listenerMissingPort))
            }
        case .failed(let error):
            waiter.complete(.failure(error))
        case .cancelled:
            waiter.complete(.failure(DialError.connectionFailed("mock home listener cancelled")))
        case .setup, .waiting:
            break
        @unknown default:
            break
        }
    }
    listener.start(queue: mockHomeQueue)
    return try await waiter.wait()
}

private extension Data {
    var homeHeaderTerminatorRange: Range<Data.Index>? {
        range(of: Data("\r\n\r\n".utf8))
    }

    var homeHeaderTerminatorRangeFound: Bool {
        homeHeaderTerminatorRange != nil
    }
}
