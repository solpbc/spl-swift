// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import os

private let sessionLog = SPLLogging.logger(for: .session)

protocol TunnelTLSIO: Sendable {
    nonisolated var inbound: AsyncThrowingStream<Data, Error> { get }

    func send(_ data: Data) async throws
    func close() async
}

extension InnerTLS: TunnelTLSIO {}

typealias TunnelTLSConnector = @Sendable (
    TransportEndpoint,
    StoredPairing,
    @Sendable (ConnectedVia) async -> Void
) async throws -> any TunnelTLSIO

public actor TunnelSession: TunnelSessioning, MuxStreamOpening {
    public nonisolated var stateUpdates: AsyncStream<TunnelState> {
        stateStream
    }

    public nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> {
        connectionModeStream
    }

    public private(set) var connectionMode: ConnectionMode?

    private let pairing: StoredPairing
    private let policy: SessionPolicy
    private let tlsConnector: TunnelTLSConnector
    private let stateStream: AsyncStream<TunnelState>
    private let stateContinuation: AsyncStream<TunnelState>.Continuation
    private let connectionModeStream: AsyncStream<ConnectionMode?>
    private let connectionModeContinuation: AsyncStream<ConnectionMode?>.Continuation
    private var state: TunnelState = .disconnected
    private var inboundPumpTask: Task<Void, Never>?
    private var inboundPumpID: UUID?
    private var keepaliveWatchTask: Task<Void, Never>?
    private var innerTLS: (any TunnelTLSIO)?
    private var multiplexer: Multiplexer?

    public init(
        pairing: StoredPairing,
        clientInfo: SPLClientInfo,
        policy: SessionPolicy = SessionPolicy()
    ) {
        self.init(
            pairing: pairing,
            policy: policy,
            tlsConnector: Self.defaultTLSConnector(policy: policy, clientInfo: clientInfo)
        )
    }

    init(
        pairing: StoredPairing,
        policy: SessionPolicy = SessionPolicy(),
        tlsConnector: @escaping TunnelTLSConnector
    ) {
        self.pairing = pairing
        self.policy = policy
        self.tlsConnector = tlsConnector

        let state = AsyncStream<TunnelState>.makeStream()
        self.stateStream = state.stream
        self.stateContinuation = state.continuation

        let mode = AsyncStream<ConnectionMode?>.makeStream()
        self.connectionModeStream = mode.stream
        self.connectionModeContinuation = mode.continuation

        state.continuation.yield(.disconnected)
        mode.continuation.yield(nil)
    }

    @discardableResult
    public func connect(endpoints: [TransportEndpoint]) async throws -> ConnectedVia {
        guard !endpoints.isEmpty else {
            throw SessionError.unreachable
        }
        guard case .disconnected = state else {
            // Single-shot: the owner creates a fresh session for every generation.
            if case .connected(let via) = state {
                return via
            }
            throw SessionError.unreachable
        }

        let connected = try await connectOnce(endpoints: endpoints)
        await installConnected(connected)
        publishConnected(connected)
        return connected.via
    }

    public func disconnect() async {
        await tearDownCurrent(reason: .normalShutdown)
        setConnectionMode(nil)
        publish(.disconnected)
        stateContinuation.finish()
        connectionModeContinuation.finish()
    }

    public func openStream() async throws -> MuxStream {
        guard case .connected = state, let multiplexer else {
            throw SessionError.notConnected
        }

        do {
            return try await multiplexer.openStream()
        } catch MuxError.transportClosed {
            sessionLog.warning("open stream failed reason=\("mux closed", privacy: .public)")
            await failConnectedSession(.transportFailed("mux closed"), tearDownReason: .transportFailure)
            throw SessionError.notConnected
        }
    }

    public func inboundActivitySnapshot() async -> UInt64 {
        guard let multiplexer else {
            return 0
        }
        return await multiplexer.inboundActivitySnapshot()
    }

    private func connectOnce(endpoints: [TransportEndpoint]) async throws -> ConnectedAttempt {
        publish(.connecting(candidates: endpoints))

        do {
            let coordinator = RaceCoordinator<ConnectedAttempt>(
                stagger: policy.race.stagger,
                loserGrace: policy.race.loserGrace,
                budget: policy.race.budget,
                close: { await $0.tls.close() }
            ) { endpoint, progress in
                try await self.connectEndpoint(endpoint, progress: progress)
            }
            let result = try await coordinator.connect(endpoints: endpoints)
            return result.value
        } catch let error as SessionError {
            sessionLog.warning("connect failed error=\(Self.describe(error), privacy: .public)")
            publish(.failed(error))
            throw error
        } catch {
            let sessionError = SessionError.unreachable
            sessionLog.warning("connect failed error=\(Self.describe(sessionError), privacy: .public)")
            publish(.failed(sessionError))
            throw sessionError
        }
    }

    private func connectEndpoint(
        _ endpoint: TransportEndpoint,
        progress: RaceAttemptProgress
    ) async throws -> ConnectedAttempt {
        let via = endpoint.connectedVia
        publish(.tlsHandshaking(via: via))
        let startedAt = ContinuousClock.now

        let connect: @Sendable () async throws -> any TunnelTLSIO = {
            try await self.tlsConnector(endpoint, self.pairing) { waitingVia in
                await progress.reportWaiting()
                await self.publishAwaitingBroker(via: waitingVia)
            }
        }
        let tls: any TunnelTLSIO
        if endpoint.isDirect {
            tls = try await connect()
        } else {
            tls = try await withSessionTimeout(policy.race.heldRelayTimeout, operation: connect)
        }
        let transport = endpoint.isDirect ? "lan" : "relay"
        sessionLog.notice("connected transport=\(transport, privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
        return ConnectedAttempt(endpoint: endpoint, via: via, tls: tls)
    }

    private func publishConnected(_ connected: ConnectedAttempt) {
        if connected.endpoint.isDirect {
            setConnectionMode(.plDirect)
        } else {
            setConnectionMode(.plViaSpl)
        }
        publish(.connected(via: connected.via))
    }

    private func installConnected(_ connected: ConnectedAttempt) async {
        let tls = connected.tls
        innerTLS = tls
        let pumpID = UUID()
        inboundPumpID = pumpID
        let mux = Multiplexer { data in
            try await tls.send(data)
        }
        multiplexer = mux

        inboundPumpTask = Task {
            do {
                for try await chunk in tls.inbound {
                    try await mux.feedInbound(chunk)
                }
                await self.handlePumpEnded(id: pumpID, error: nil)
            } catch {
                await self.handlePumpEnded(id: pumpID, error: error)
            }
        }

        if shouldRunKeepalive(via: connected.via) {
            await mux.startKeepalive(
                interval: policy.keepalive.interval,
                idleThreshold: policy.keepalive.idleThreshold,
                missedLimit: policy.keepalive.missedLimit
            )
            keepaliveWatchTask = Task { [mux] in
                for await _ in mux.keepaliveLost {
                    await self.handleKeepaliveLost()
                    break
                }
            }
        }
    }

    private func handlePumpEnded(id: UUID, error: (any Error)?) async {
        guard inboundPumpID == id, case .connected = state else {
            return
        }
        let fault = error.map { String(describing: $0) }
        if let fault {
            sessionLog.error("inbound pump failed fault=\(fault, privacy: .public)")
        } else {
            sessionLog.warning("inbound pump closed")
        }
        await failConnectedSession(.inboundClosed(fault: fault), tearDownReason: .transportFailure)
    }

    private func handleKeepaliveLost() async {
        guard case .connected = state else {
            return
        }
        switch connectionMode {
        case .plDirect:
            sessionLog.warning("keepalive lost route=\("direct", privacy: .public)")
            await failConnectedSession(.directKeepaliveMissed, tearDownReason: .transportFailure)
        case .plViaSpl:
            sessionLog.warning("keepalive lost route=\("relay", privacy: .public)")
            await failConnectedSession(.relayKeepaliveMissed, tearDownReason: .transportFailure)
        case nil:
            return
        }
    }

    private func failConnectedSession(_ error: SessionError, tearDownReason: TearDownReason) async {
        guard case .connected = state else {
            return
        }
        publish(.failed(error))
        await tearDownCurrent(reason: tearDownReason)
    }

    private func tearDownCurrent(reason: TearDownReason) async {
        inboundPumpID = nil
        keepaliveWatchTask?.cancel()
        keepaliveWatchTask = nil
        inboundPumpTask?.cancel()
        inboundPumpTask = nil
        await multiplexer?.tearDown(reason: reason)
        multiplexer = nil
        await innerTLS?.close()
        innerTLS = nil
        setConnectionMode(nil)
    }

    private func shouldRunKeepalive(via: ConnectedVia) -> Bool {
        switch via {
        case .lanDirect:
            return true
        case .relay:
            return policy.keepalive.runsOnRelayPath
        }
    }

    private func publish(_ newState: TunnelState) {
        state = newState
        stateContinuation.yield(newState)
        sessionLog.notice("state=\(Self.describe(newState), privacy: .public)")
    }

    private func publishAwaitingBroker(via: ConnectedVia) {
        publish(.awaitingBroker(via: via))
    }

    private func setConnectionMode(_ newMode: ConnectionMode?) {
        connectionMode = newMode
        connectionModeContinuation.yield(newMode)
    }

    private static func defaultTLSConnector(
        policy: SessionPolicy,
        clientInfo: SPLClientInfo
    ) -> TunnelTLSConnector {
        { endpoint, pairing, onAwaitingBroker in
            switch endpoint {
            case .lan(let host, let port, _, let unpinnedInterface):
                return try await withSessionTimeout(policy.race.directConnectTimeout) {
                    try await InnerTLS.connectLAN(
                        host: host,
                        port: port,
                        pairing: pairing,
                        unpinnedInterface: unpinnedInterface
                    )
                }
            case .relay:
                return try await connectRelay(
                    endpoint: endpoint,
                    pairing: pairing,
                    clientInfo: clientInfo,
                    relayOpenTimeout: policy.race.relayOpenTimeout,
                    onAwaitingBroker: onAwaitingBroker
                )
            }
        }
    }

    private static func connectRelay(
        endpoint: TransportEndpoint,
        pairing: StoredPairing,
        clientInfo: SPLClientInfo,
        relayOpenTimeout: Duration,
        onAwaitingBroker: @Sendable (ConnectedVia) async -> Void
    ) async throws -> any TunnelTLSIO {
        let lease = RelayTransportLease()
        return try await withTaskCancellationHandler {
            let transport = try await DialClient.dial(
                endpoint,
                clientInfo: clientInfo,
                timeout: relayOpenTimeout
            )
            await lease.set(transport)
            await onAwaitingBroker(endpoint.connectedVia)
            do {
                let tls = try await InnerTLS.connectViaTransport(transport: transport, pairing: pairing)
                await lease.release()
                return tls
            } catch {
                await lease.close()
                throw error
            }
        } onCancel: {
            Task {
                await lease.close()
            }
        }
    }

    private static func describe(_ state: TunnelState) -> String {
        switch state {
        case .disconnected:
            return "disconnected"
        case .connecting(let candidates):
            return "connecting candidates=\(describe(candidates))"
        case .tlsHandshaking(let via):
            return "tls_handshaking via=\(describe(via))"
        case .awaitingBroker(let via):
            return "awaiting_broker via=\(describe(via))"
        case .connected(let via):
            return "connected via=\(describe(via))"
        case .failed(let error):
            return "failed error=\(describe(error))"
        }
    }

    private static func describe(_ endpoints: [TransportEndpoint]) -> String {
        endpoints.map(\.logDescription).joined(separator: ", ")
    }

    private static func describe(_ via: ConnectedVia) -> String {
        switch via {
        case .lanDirect(let host, let port):
            return "lan \(host):\(port)"
        case .relay(let endpoint):
            let scheme = endpoint.scheme ?? "unknown"
            let host = endpoint.host ?? "unknown"
            let port = endpoint.port.map(String.init) ?? "default"
            return "relay \(scheme)://\(host):\(port)"
        }
    }

    private static func describe(_ error: SessionError) -> String {
        switch error {
        case .unreachable:
            return "unreachable"
        case .tlsFailed:
            return "tlsFailed"
        case .revoked:
            return "revoked"
        case .authRefreshRequired:
            return "authRefreshRequired"
        case .notEntitled:
            return "notEntitled"
        case .notConnected:
            return "notConnected"
        case .directKeepaliveMissed:
            return "directKeepaliveMissed"
        case .relayKeepaliveMissed:
            return "relayKeepaliveMissed"
        case .transportFailed(let reason):
            return "transportFailed(\(reason))"
        case .inboundClosed(let fault):
            return "inboundClosed(fault=\(fault ?? "nil"))"
        }
    }
}

private struct ConnectedAttempt: Sendable {
    let endpoint: TransportEndpoint
    let via: ConnectedVia
    let tls: any TunnelTLSIO
}

private actor RelayTransportLease {
    private var transport: (any ByteTransport)?

    func set(_ transport: any ByteTransport) {
        self.transport = transport
    }

    func release() {
        transport = nil
    }

    func close() async {
        guard let transport else {
            return
        }
        self.transport = nil
        await transport.close()
    }
}

private func withSessionTimeout<T: Sendable>(
    _ timeout: Duration,
    onTimeout: @escaping @Sendable () async -> Void = {},
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withTaskCancellationHandler {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                await onTimeout()
                throw SessionError.unreachable
            }

            let value = try await group.next()!
            group.cancelAll()
            return value
        }
    } onCancel: {
        Task {
            await onTimeout()
        }
    }
}

private extension Duration {
    var milliseconds: Int {
        let components = components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
