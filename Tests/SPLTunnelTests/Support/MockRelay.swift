// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Crypto
import Network
import Security

actor MockRelay {
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var pairDialTargetPort: UInt16?
    private(set) var pairKeyHeader: String?

    init() throws {}

    func routePairDial(toTLSPort port: Int) throws {
        guard let target = UInt16(exactly: port), 1...65535 ~= port else {
            throw MockRelayError.invalidPairDialTarget
        }
        pairDialTargetPort = target
    }

    func start() async throws -> URL {
        if let port = listener?.port?.rawValue {
            return URL(string: "http://127.0.0.1:\(port)")!
        }

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let waiter = MockRelayListenerReadyWaiter()
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port?.rawValue {
                    waiter.complete(.success(port))
                } else {
                    waiter.complete(.failure(MockRelayError.listenerMissingPort))
                }
            case .failed(let error):
                waiter.complete(.failure(error))
            case .cancelled, .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            Task {
                await self?.accept(connection)
            }
        }
        self.listener = listener
        listener.start(queue: .global(qos: .utility))
        let port = try await waiter.wait()
        return URL(string: "http://127.0.0.1:\(port)")!
    }

    func stop() {
        for connection in connections {
            connection.cancel()
        }
        connections.removeAll()
        listener?.cancel()
        listener = nil
    }

    private func accept(_ connection: NWConnection) {
        connections.append(connection)
        connection.start(queue: .global(qos: .utility))
        Task {
            await handle(connection)
        }
    }

    private func handle(_ connection: NWConnection) async {
        do {
            let request = try await MockHTTPConnection.readRequest(from: connection)
            if request.method == "GET",
               Self.requestPath(request.path) == "/session/pair-dial" {
                try await handlePairDial(request: request, connection: connection)
                return
            }

            guard request.method == "POST", request.path == "/enroll/device" else {
                try await MockHTTPConnection.send(status: 404, body: #"{"error":"not_found"}"#, to: connection)
                connection.cancel()
                return
            }
            guard let json = try JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  json["instance_id"] as? String != nil,
                  json["home_attestation"] as? String != nil else {
                try await MockHTTPConnection.send(status: 400, body: #"{"error":"bad_request"}"#, to: connection)
                connection.cancel()
                return
            }
            let response = [
                "device_token": Self.randomHex(byteCount: 32),
                "expires_at": ISO8601DateFormatter().string(from: Date().addingTimeInterval(24 * 60 * 60)),
            ]
            let data = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            try await MockHTTPConnection.send(status: 200, body: String(data: data, encoding: .utf8)!, to: connection)
            connection.cancel()
        } catch {
            connection.cancel()
        }
    }

    private func handlePairDial(request: MockHTTPRequest, connection: NWConnection) async throws {
        guard let targetPort = pairDialTargetPort,
              let pairKey = request.headers["sec-pair-key"],
              request.headers["upgrade"]?.lowercased() == "websocket",
              request.headers["sec-websocket-key"] != nil else {
            try await MockHTTPConnection.send(status: 401, body: #"{"error":"pair_window_closed"}"#, to: connection)
            connection.cancel()
            return
        }

        pairKeyHeader = pairKey
        let tcp = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: targetPort)!,
            using: .tcp
        )
        connections.append(tcp)
        tcp.start(queue: .global(qos: .utility))

        let response = "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: \(Self.webSocketAcceptValue(for: request.headers["sec-websocket-key"]!))\r\n" +
            "\r\n"
        try await MockHTTPConnection.send(Data(response.utf8), to: connection)
        pumpWebSocket(connection, to: tcp)
        pumpTCP(tcp, to: connection)
    }

    private func pumpWebSocket(_ webSocket: NWConnection, to tcp: NWConnection, buffered: Data = Data()) {
        webSocket.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard error == nil, let data, !data.isEmpty else {
                if isComplete || error != nil {
                    webSocket.cancel()
                    tcp.cancel()
                }
                return
            }

            var buffer = buffered
            buffer.append(data)
            do {
                while let frame = try MockWebSocketFrame.decode(from: &buffer) {
                    switch frame.opcode {
                    case .binary, .continuation:
                        tcp.send(content: frame.payload, completion: .contentProcessed { _ in })
                    case .close:
                        webSocket.cancel()
                        tcp.cancel()
                        return
                    case .ping:
                        webSocket.send(content: MockWebSocketFrame.encodePong(frame.payload), completion: .contentProcessed { _ in })
                    case .pong:
                        break
                    }
                }
            } catch {
                webSocket.cancel()
                tcp.cancel()
                return
            }

            guard let relay = self else {
                return
            }
            Task {
                await relay.pumpWebSocket(webSocket, to: tcp, buffered: buffer)
            }
        }
    }

    private func pumpTCP(_ tcp: NWConnection, to webSocket: NWConnection) {
        tcp.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard error == nil, let data, !data.isEmpty else {
                if isComplete || error != nil {
                    webSocket.cancel()
                    tcp.cancel()
                }
                return
            }
            guard let relay = self else {
                return
            }

            webSocket.send(
                content: MockWebSocketFrame.encodeBinary(data),
                completion: .contentProcessed { _ in
                    Task {
                        await relay.pumpTCP(tcp, to: webSocket)
                    }
                }
            )
        }
    }

    private static func requestPath(_ raw: String) -> String {
        URLComponents(string: "http://mock-relay\(raw)")?.path ?? raw
    }

    private static func webSocketAcceptValue(for key: String) -> String {
        let data = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
        let digest = Insecure.SHA1.hash(data: data)
        return Data(digest).base64EncodedString()
    }

    private nonisolated static func randomHex(byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

enum MockRelayError: Error {
    case invalidPairDialTarget
    case listenerMissingPort
}

private struct MockWebSocketFrame {
    enum Opcode: UInt8 {
        case continuation = 0x0
        case binary = 0x2
        case close = 0x8
        case ping = 0x9
        case pong = 0xa
    }

    let opcode: Opcode
    let payload: Data

    static func decode(from buffer: inout Data) throws -> MockWebSocketFrame? {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 2 else {
            return nil
        }

        let opcode = Opcode(rawValue: bytes[0] & 0x0f)
        let masked = bytes[1] & 0x80 != 0
        var length = UInt64(bytes[1] & 0x7f)
        var offset = 2
        if length == 126 {
            guard bytes.count >= offset + 2 else {
                return nil
            }
            length = UInt64(UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]))
            offset += 2
        } else if length == 127 {
            guard bytes.count >= offset + 8 else {
                return nil
            }
            length = 0
            for byte in bytes[offset..<(offset + 8)] {
                length = (length << 8) | UInt64(byte)
            }
            offset += 8
        }
        guard length <= UInt64(Int.max) else {
            throw MockHTTPError.invalidRequest
        }

        var mask: ArraySlice<UInt8> = []
        if masked {
            guard bytes.count >= offset + 4 else {
                return nil
            }
            mask = bytes[offset..<(offset + 4)]
            offset += 4
        }

        let payloadLength = Int(length)
        guard bytes.count >= offset + payloadLength else {
            return nil
        }
        var payload = Array(bytes[offset..<(offset + payloadLength)])
        if masked {
            let maskBytes = Array(mask)
            for index in payload.indices {
                payload[index] ^= maskBytes[index % 4]
            }
        }

        let end = buffer.index(buffer.startIndex, offsetBy: offset + payloadLength)
        buffer.removeSubrange(buffer.startIndex..<end)
        guard let opcode else {
            throw MockHTTPError.invalidRequest
        }
        return MockWebSocketFrame(opcode: opcode, payload: Data(payload))
    }

    static func encodeBinary(_ payload: Data) -> Data {
        encode(opcode: .binary, payload: payload)
    }

    static func encodePong(_ payload: Data) -> Data {
        encode(opcode: .pong, payload: payload)
    }

    private static func encode(opcode: Opcode, payload: Data) -> Data {
        var frame = Data([0x80 | opcode.rawValue])
        let count = payload.count
        if count <= 125 {
            frame.append(UInt8(count))
        } else if count <= UInt16.max {
            frame.append(126)
            frame.append(UInt8((count >> 8) & 0xff))
            frame.append(UInt8(count & 0xff))
        } else {
            frame.append(127)
            let length = UInt64(count)
            for shift in stride(from: 56, through: 0, by: -8) {
                frame.append(UInt8((length >> UInt64(shift)) & 0xff))
            }
        }
        frame.append(payload)
        return frame
    }
}

struct MockHTTPRequest: Sendable {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data
}

enum MockHTTPConnection {
    static let maxBodySize = 16 * 1024 * 1024

    static func readRequest(from connection: NWConnection) async throws -> MockHTTPRequest {
        var buffer = Data()
        while !buffer.containsHeaderTerminator {
            guard let chunk = try await receive(from: connection), !chunk.isEmpty else {
                throw MockHTTPError.closed
            }
            buffer.append(chunk)
            if buffer.count > maxBodySize {
                throw MockHTTPError.bodyTooLarge
            }
        }

        let headerEnd = buffer.headerTerminatorRange!.lowerBound
        let bodyStart = buffer.headerTerminatorRange!.upperBound
        let headerData = buffer[..<headerEnd]
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            throw MockHTTPError.invalidRequest
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            throw MockHTTPError.invalidRequest
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count >= 2 else {
            throw MockHTTPError.invalidRequest
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let index = line.firstIndex(of: ":") else {
                continue
            }
            let name = line[..<index].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: index)...].trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            throw MockHTTPError.chunkedUnsupported
        }
        let contentLength = Int(headers["content-length"] ?? "0") ?? 0
        guard contentLength <= maxBodySize else {
            throw MockHTTPError.bodyTooLarge
        }

        var body = Data(buffer[bodyStart...])
        while body.count < contentLength {
            guard let chunk = try await receive(from: connection), !chunk.isEmpty else {
                throw MockHTTPError.closed
            }
            body.append(chunk)
        }
        if body.count > contentLength {
            body = Data(body.prefix(contentLength))
        }
        return MockHTTPRequest(method: parts[0], path: parts[1], headers: headers, body: body)
    }

    static func send(status: Int, body: String, to connection: NWConnection) async throws {
        let reason = HTTPURLResponse.localizedString(forStatusCode: status)
        let response = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        try await send(Data(response.utf8), to: connection)
    }

    static func send(_ data: Data, to connection: NWConnection) async throws {
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
}

enum MockHTTPError: Error {
    case bodyTooLarge
    case chunkedUnsupported
    case closed
    case invalidRequest
}

private extension Data {
    var headerTerminatorRange: Range<Data.Index>? {
        range(of: Data("\r\n\r\n".utf8))
    }

    var containsHeaderTerminator: Bool {
        headerTerminatorRange != nil
    }
}

private final class MockRelayListenerReadyWaiter: @unchecked Sendable {
    // why: NWListener state callbacks run on a dispatch queue while start() awaits; NSLock serializes one-shot completion.
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
