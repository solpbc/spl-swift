// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation

public protocol MuxStreamOpening: Sendable {
    func openStream() async throws -> MuxStream
}

extension Multiplexer: MuxStreamOpening {}

public enum ConnectedVia: Sendable, Equatable {
    case lanDirect(host: String, port: Int)
    case relay(endpoint: URL)
}

public enum ConnectionMode: Sendable, Equatable {
    case plDirect
    case plViaSpl
}

public enum TunnelState: Sendable, Equatable {
    case disconnected
    case connecting(candidates: [ConnectedVia])
    case tlsHandshaking(via: ConnectedVia)
    case awaitingBroker(via: ConnectedVia)
    case connected(via: ConnectedVia)
    case failed(SessionError)
}

public protocol TunnelSessioning: Sendable {
    nonisolated var stateUpdates: AsyncStream<TunnelState> { get }
    nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> { get }
    var connectionMode: ConnectionMode? { get async }

    @discardableResult
    func connect(endpoints: [TransportEndpoint]) async throws -> ConnectedVia
    func disconnect() async
    func openStream() async throws -> MuxStream
    func inboundActivitySnapshot() async -> UInt64
}
