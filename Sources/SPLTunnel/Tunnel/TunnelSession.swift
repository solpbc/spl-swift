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

private struct RevocationReportingTunnelTLS: TunnelTLSIO {
    let base: any TunnelTLSIO
    let report: @Sendable () async -> Void

    var inbound: AsyncThrowingStream<Data, Error> {
        base.inbound
    }

    func send(_ data: Data) async throws {
        do {
            try await base.send(data)
        } catch {
            if isPeerAccessDenied(error) {
                await report()
                throw SessionError.revoked
            }
            throw error
        }
    }

    func close() async {
        await base.close()
    }
}

typealias TunnelTLSConnector = @Sendable (
    TransportEndpoint,
    StoredPairing,
    @Sendable (ConnectedVia) async -> Void
) async throws -> any TunnelTLSIO

typealias TunnelMuxFactory = @Sendable (any TunnelTLSIO) -> Multiplexer

private struct PendingInstallFailure: Sendable {
    let pumpID: UUID
    let error: SessionError
    let tearDownReason: TearDownReason
}

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
    private let makeMultiplexer: TunnelMuxFactory
    private let installWindowTestGate: @Sendable () async -> Void
    private let pendingInstallFailureTestObserver: @Sendable () async -> Void
    private let postReadyFailureTestGate: @Sendable (SessionError) async -> Void
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
    private var activeEndpoint: TransportEndpoint?
    private var pendingInstallFailure: PendingInstallFailure?
    // why: A generic post-ready failure may publish before a concurrent terminal TLS callback;
    // retain its epoch through teardown so .revoked can win, then close on terminal, disconnect, or successor install.
    private var terminalEligiblePumpID: UUID?
    private var isTerminated = false

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
        tlsConnector: @escaping TunnelTLSConnector,
        makeMultiplexer: @escaping TunnelMuxFactory = { tls in
            Multiplexer { data in
                try await tls.send(data)
            }
        },
        // Internal test seam for holding the pre-publish install window open.
        // Default no-op; production draining is the unconditional Task.yield() below.
        installWindowTestGate: @escaping @Sendable () async -> Void = {},
        // Internal test observation point for the pending install-failure latch.
        // The default has no production effect.
        pendingInstallFailureTestObserver: @escaping @Sendable () async -> Void = {},
        // Internal test seam for holding a post-ready failure before teardown clears its epoch.
        // The default has no production effect.
        postReadyFailureTestGate: @escaping @Sendable (SessionError) async -> Void = { _ in }
    ) {
        self.pairing = pairing
        self.policy = policy
        self.tlsConnector = tlsConnector
        self.makeMultiplexer = makeMultiplexer
        self.installWindowTestGate = installWindowTestGate
        self.pendingInstallFailureTestObserver = pendingInstallFailureTestObserver
        self.postReadyFailureTestGate = postReadyFailureTestGate

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
        try await connect(endpoints: endpoints, preferredEndpoint: nil)
    }

    @discardableResult
    func connect(
        endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint?
    ) async throws -> ConnectedVia {
        guard !endpoints.isEmpty else {
            throw SessionError.unreachable
        }
        guard !isTerminated else {
            throw SessionError.notConnected
        }
        guard case .disconnected = state else {
            // Single-shot: the owner creates a fresh session for every generation.
            if case .connected(let via) = state {
                return via
            }
            throw SessionError.notConnected
        }

        let connected = try await connectOnce(endpoints: endpoints, preferredEndpoint: preferredEndpoint)
        await installConnected(connected)
        try await publishConnected(connected)
        return connected.via
    }

    public func disconnect() async {
        isTerminated = true
        // A user disconnect closes the terminal eligibility window.
        terminalEligiblePumpID = nil
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

    func connectedEndpoint() -> TransportEndpoint? {
        activeEndpoint
    }

    private func connectOnce(
        endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint?
    ) async throws -> ConnectedAttempt {
        publish(.connecting(candidates: endpoints.map(\.connectedVia)))

        do {
            let coordinator = RaceCoordinator<ConnectedAttempt>(
                stagger: policy.race.stagger,
                loserGrace: policy.race.loserGrace,
                budget: policy.race.budget,
                close: { await $0.tls.close() }
            ) { endpoint, progress in
                try await self.connectEndpoint(endpoint, progress: progress)
            }
            let result = try await coordinator.connect(endpoints: endpoints, preferredEndpoint: preferredEndpoint)
            return result.value
        } catch let error as SessionError {
            sessionLog.warning("connect failed error=\(TunnelStateLogDescription.describe(error), privacy: .public)")
            publish(.failed(error))
            throw error
        } catch {
            let sessionError = SessionError.unreachable
            sessionLog.warning("connect failed error=\(TunnelStateLogDescription.describe(sessionError), privacy: .public)")
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

    private func publishConnected(_ connected: ConnectedAttempt) async throws {
        if let pending = pendingInstallFailure, pending.pumpID == inboundPumpID {
            pendingInstallFailure = nil
            publish(.failed(pending.error))
            await tearDownCurrent(reason: pending.tearDownReason)
            throw pending.error
        }
        pendingInstallFailure = nil
        activeEndpoint = connected.endpoint
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
        // Replacing the value closes the previous terminal eligibility window.
        terminalEligiblePumpID = pumpID
        pendingInstallFailure = nil
        let reportingTLS = RevocationReportingTunnelTLS(base: tls) { [weak self, pumpID] in
            await self?.handlePeerAccessDenied(id: pumpID)
        }
        let mux = makeMultiplexer(reportingTLS)
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
            let keepaliveError = Self.keepaliveError(for: connected.via)
            keepaliveWatchTask = Task { [mux, pumpID, keepaliveError] in
                for await _ in mux.keepaliveLost {
                    await self.handleKeepaliveLost(id: pumpID, error: keepaliveError)
                }
            }
            await mux.startKeepalive(
                interval: policy.keepalive.interval,
                missedLimit: policy.keepalive.missedLimit
            )
        }
        // Let already-ended pump/loss tasks run and latch against this install epoch
        // before publishConnected can publish a durable connected state.
        await Task.yield()
        await installWindowTestGate()
    }

    private func handlePumpEnded(id: UUID, error: (any Error)?) async {
        let isTerminalError = error.map(isTerminalPeerAccessDenied) ?? false
        guard inboundPumpID == id || (isTerminalError && terminalEligiblePumpID == id) else {
            return
        }
        if isTerminalError {
            await handlePeerAccessDenied(id: id)
            return
        }
        let fault = error.map { String(describing: $0) }
        let sessionError = SessionError.inboundClosed(fault: fault)
        guard case .connected = state else {
            await recordPendingInstallFailure(
                id: id,
                error: sessionError,
                tearDownReason: .transportFailure
            )
            return
        }
        if let fault {
            sessionLog.error("inbound pump failed fault=\(fault, privacy: .public)")
        } else {
            sessionLog.warning("inbound pump closed")
        }
        await failConnectedSession(sessionError, tearDownReason: .transportFailure)
    }

    private func handleKeepaliveLost(id: UUID, error: SessionError) async {
        guard inboundPumpID == id else {
            return
        }
        guard case .connected = state else {
            await recordPendingInstallFailure(
                id: id,
                error: error,
                tearDownReason: .transportFailure
            )
            return
        }
        switch error {
        case .directKeepaliveMissed:
            sessionLog.warning("keepalive lost route=\("direct", privacy: .public)")
        case .relayKeepaliveMissed:
            sessionLog.warning("keepalive lost route=\("relay", privacy: .public)")
        default:
            break
        }
        await failConnectedSession(error, tearDownReason: .transportFailure)
    }

    private func failConnectedSession(_ error: SessionError, tearDownReason: TearDownReason) async {
        guard case .connected = state else {
            return
        }
        publish(.failed(error))
        await postReadyFailureTestGate(error)
        await tearDownCurrent(reason: tearDownReason)
    }

    private func handlePeerAccessDenied(id: UUID) async {
        guard terminalEligiblePumpID == id else {
            return
        }
        if case .disconnected = state {
            // A disconnected session cannot be revived by a stale terminal callback.
            terminalEligiblePumpID = nil
            return
        }
        // Consuming the epoch makes a second terminal callback for it a no-op.
        terminalEligiblePumpID = nil
        let isConnected: Bool
        if case .connected = state {
            isConnected = true
        } else {
            isConnected = false
        }
        sessionLog.notice("terminal peer access denied")
        if isConnected {
            await failConnectedSession(.revoked, tearDownReason: .transportFailure)
            return
        }
        if case .failed = state {
            publish(.failed(.revoked))
            await tearDownCurrent(reason: .transportFailure)
            return
        }
        await recordPendingInstallFailure(
            id: id,
            error: .revoked,
            tearDownReason: .transportFailure
        )
    }

    private func tearDownCurrent(reason: TearDownReason) async {
        inboundPumpID = nil
        pendingInstallFailure = nil
        keepaliveWatchTask?.cancel()
        keepaliveWatchTask = nil
        inboundPumpTask?.cancel()
        inboundPumpTask = nil
        let activeMultiplexer = multiplexer
        let activeTLS = innerTLS
        multiplexer = nil
        innerTLS = nil
        activeEndpoint = nil
        await activeMultiplexer?.tearDown(reason: reason)
        await activeTLS?.close()
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

    private func recordPendingInstallFailure(
        id: UUID,
        error: SessionError,
        tearDownReason: TearDownReason
    ) async {
        guard pendingInstallFailure == nil || (
            pendingInstallFailure?.error != .revoked && error == .revoked
        ) else {
            return
        }
        pendingInstallFailure = PendingInstallFailure(
            pumpID: id,
            error: error,
            tearDownReason: tearDownReason
        )
        await pendingInstallFailureTestObserver()
    }

    private static func keepaliveError(for via: ConnectedVia) -> SessionError {
        switch via {
        case .lanDirect:
            return .directKeepaliveMissed
        case .relay:
            return .relayKeepaliveMissed
        }
    }

    private func isTerminalPeerAccessDenied(_ error: any Error) -> Bool {
        if let sessionError = error as? SessionError, sessionError == .revoked {
            return true
        }
        return isPeerAccessDenied(error)
    }

    private func publish(_ newState: TunnelState) {
        if case .failed = newState {
            isTerminated = true
        }
        state = newState
        stateContinuation.yield(newState)
        sessionLog.notice("state=\(TunnelStateLogDescription.describe(newState), privacy: .public)")
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
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw SessionError.unreachable
        }

        let value = try await group.next()!
        group.cancelAll()
        return value
    }
}

private extension Duration {
    var milliseconds: Int {
        let components = components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
