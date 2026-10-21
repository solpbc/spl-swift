// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
@testable import SPLTunnel

private let tamperQueue = DispatchQueue(label: "SPLTunnel.tests.tamper-proxy")

/// A TCP relay in front of a TLS server that flips one byte of the first record the server
/// sends after the client's encrypted handshake flight, as an attacker on the path could.
actor RecordTamperProxy {
    private let upstreamPort: Int
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var boundPort: NWEndpoint.Port?

    init(upstreamPort: Int) {
        self.upstreamPort = upstreamPort
    }

    var port: Int {
        Int(boundPort?.rawValue ?? 0)
    }

    func start() async throws {
        let listener = try NWListener(using: .tcp, on: .any)
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            Task {
                await self.accept(connection)
            }
        }
        self.listener = listener
        let ready = AsyncStream<Result<Void, Error>>.makeStream()
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                ready.continuation.yield(.success(()))
            case .failed(let error):
                ready.continuation.yield(.failure(error))
            default:
                break
            }
        }
        listener.start(queue: tamperQueue)
        var iterator = ready.stream.makeAsyncIterator()
        try await iterator.next()?.get()
        boundPort = listener.port
    }

    func stop() {
        for connection in connections {
            connection.cancel()
        }
        connections.removeAll()
        listener?.cancel()
        listener = nil
    }

    private func accept(_ client: NWConnection) {
        guard let port = NWEndpoint.Port(rawValue: UInt16(clamping: upstreamPort)) else {
            client.cancel()
            return
        }
        let upstream = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        connections.append(client)
        connections.append(upstream)
        let state = TamperState()
        client.start(queue: tamperQueue)
        upstream.start(queue: tamperQueue)
        Self.pump(from: client, to: upstream, records: TLSRecordReader()) { record in
            if record.first == 0x17 {
                state.clientFlightSeen()
            }
            return record
        }
        Self.pump(from: upstream, to: client, records: TLSRecordReader()) { record in
            guard state.takeTamperTurn() else {
                return record
            }
            var tampered = record
            tampered[tampered.count - 1] ^= 0x01
            return tampered
        }
    }

    /// Forwards whole TLS records, letting `transform` see each one before it is sent.
    private nonisolated static func pump(
        from source: NWConnection,
        to sink: NWConnection,
        records: TLSRecordReader,
        transform: @escaping @Sendable (Data) -> Data
    ) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
            guard error == nil else {
                sink.cancel()
                return
            }
            if let data, !data.isEmpty {
                let outgoing = records.feed(data).map(transform).reduce(Data(), +)
                sink.send(content: outgoing.isEmpty ? nil : outgoing, completion: .contentProcessed { _ in
                    pump(from: source, to: sink, records: records, transform: transform)
                })
                return
            }
            if isComplete {
                sink.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                return
            }
            pump(from: source, to: sink, records: records, transform: transform)
        }
    }
}

private final class TamperState: @unchecked Sendable {
    // why: the two pump directions run callbacks on the proxy queue and share these flags; NSLock guards them.
    private let lock = NSLock()
    private var flightSeen = false
    private var tampered = false

    func clientFlightSeen() {
        lock.withLock { flightSeen = true }
    }

    func takeTamperTurn() -> Bool {
        lock.withLock {
            guard flightSeen, !tampered else {
                return false
            }
            tampered = true
            return true
        }
    }
}

/// Splits a byte stream into TLS records (5-byte header plus payload).
private final class TLSRecordReader: @unchecked Sendable {
    // why: one pump direction feeds it at a time, but callbacks hop threads; NSLock guards the buffer.
    private let lock = NSLock()
    private var buffer = Data()

    func feed(_ data: Data) -> [Data] {
        lock.withLock {
            buffer.append(data)
            var records: [Data] = []
            while buffer.count >= 5 {
                let start = buffer.startIndex
                let length = Int(buffer[start + 3]) << 8 | Int(buffer[start + 4])
                guard buffer.count >= 5 + length else {
                    break
                }
                records.append(Data(buffer[start..<(start + 5 + length)]))
                buffer = Data(buffer[(start + 5 + length)...])
            }
            return records
        }
    }
}
