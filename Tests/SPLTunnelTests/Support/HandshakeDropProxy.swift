// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
@testable import SPLTunnel

private let proxyQueue = DispatchQueue(label: "SPLTunnel.tests.drop-proxy")

/// A TCP relay in front of a TLS server that ends the client's connection below TLS as soon
/// as the server side completes the handshake: a FIN with no close_notify, or a reset.
actor HandshakeDropProxy {
    enum Drop: Sendable {
        case finWithoutCloseNotify
        case reset
    }

    private let upstreamPort: Int
    private let handshakes: AsyncStream<Void>
    private let drop: Drop
    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var boundPort: NWEndpoint.Port?

    init(upstreamPort: Int, handshakes: AsyncStream<Void>, drop: Drop) {
        self.upstreamPort = upstreamPort
        self.handshakes = handshakes
        self.drop = drop
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
        listener.start(queue: proxyQueue)
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
        let gate = DropGate()
        client.start(queue: proxyQueue)
        upstream.start(queue: proxyQueue)
        Self.pump(from: client, to: upstream, gate: gate)
        Self.pump(from: upstream, to: client, gate: gate)
        let handshakes = handshakes
        let drop = drop
        Task {
            var iterator = handshakes.makeAsyncIterator()
            _ = await iterator.next()
            gate.close()
            switch drop {
            case .finWithoutCloseNotify:
                client.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
            case .reset:
                client.forceCancel()
            }
        }
    }

    private nonisolated static func pump(from source: NWConnection, to sink: NWConnection, gate: DropGate) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
            guard error == nil, !gate.isClosed else {
                return
            }
            if let data, !data.isEmpty {
                sink.send(content: data, completion: .contentProcessed { _ in
                    pump(from: source, to: sink, gate: gate)
                })
                return
            }
            if isComplete {
                return
            }
            pump(from: source, to: sink, gate: gate)
        }
    }
}

private final class DropGate: @unchecked Sendable {
    // why: Network callbacks on the proxy queue read the flag the dropping task sets; NSLock guards it.
    private let lock = NSLock()
    private var closed = false

    var isClosed: Bool {
        lock.withLock { closed }
    }

    func close() {
        lock.withLock { closed = true }
    }
}
