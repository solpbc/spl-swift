// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import os

private let supervisorLog = SPLLogging.logger(for: .session)

public struct ReconnectStatus: Sendable, Equatable {
    public let reason: SessionError?
    public let attempt: Int
    public let retryAfter: Duration?
    public let terminalPause: Bool

    public init(
        reason: SessionError?,
        attempt: Int,
        retryAfter: Duration?,
        terminalPause: Bool
    ) {
        self.reason = reason
        self.attempt = attempt
        self.retryAfter = retryAfter
        self.terminalPause = terminalPause
    }
}

protocol TunnelGeneration: TunnelSessioning {
    @discardableResult
    func connect(endpoints: [TransportEndpoint], preferredEndpoint: TransportEndpoint?) async throws -> ConnectedVia
    func connectedEndpoint() async -> TransportEndpoint?
}

extension TunnelSession: TunnelGeneration {}

typealias TunnelGenerationFactory = @Sendable (
    StoredPairing,
    SPLClientInfo,
    SessionPolicy
) async -> any TunnelGeneration

public actor TunnelSupervisor: TunnelSessioning, MuxStreamOpening {
    public nonisolated var stateUpdates: AsyncStream<TunnelState> {
        stateStream
    }

    public nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> {
        connectionModeStream
    }

    public nonisolated var reconnectUpdates: AsyncStream<ReconnectStatus> {
        reconnectStream
    }

    public private(set) var connectionMode: ConnectionMode?
    public private(set) var reconnectStatus: ReconnectStatus?

    private enum Lifecycle: Sendable, Equatable {
        case idle
        case running
        case paused(SessionError)
    }

    private struct Generation: Sendable {
        let token: UInt64
        let session: any TunnelGeneration
    }

    private let pairing: StoredPairing
    private let clientInfo: SPLClientInfo
    private let policy: SessionPolicy
    private let makeSession: TunnelGenerationFactory
    private let sleeper: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> ContinuousClock.Instant

    private let stateStream: AsyncStream<TunnelState>
    private let stateContinuation: AsyncStream<TunnelState>.Continuation
    private let connectionModeStream: AsyncStream<ConnectionMode?>
    private let connectionModeContinuation: AsyncStream<ConnectionMode?>.Continuation
    private let reconnectStream: AsyncStream<ReconnectStatus>
    private let reconnectContinuation: AsyncStream<ReconnectStatus>.Continuation

    private var lifecycle: Lifecycle = .idle
    private var state: TunnelState = .disconnected
    private var generation: Generation?
    private var nextGenerationToken: UInt64 = 0
    private var connectingToken: UInt64?
    private var stateTask: Task<Void, Never>?
    private var modeTask: Task<Void, Never>?
    private var redriveTask: Task<Void, Never>?
    private var pendingRedrive = false
    private var plannedEndpoints: [TransportEndpoint] = []
    private var currentVia: ConnectedVia?
    private var planner = DialPlanner()
    private var backoff = ReconnectBackoff()

    public init(
        pairing: StoredPairing,
        clientInfo: SPLClientInfo,
        policy: SessionPolicy = SessionPolicy()
    ) {
        self.init(
            pairing: pairing,
            clientInfo: clientInfo,
            policy: policy,
            makeSession: { pairing, clientInfo, policy in
                TunnelSession(pairing: pairing, clientInfo: clientInfo, policy: policy)
            }
        )
    }

    init(
        pairing: StoredPairing,
        clientInfo: SPLClientInfo,
        policy: SessionPolicy = SessionPolicy(),
        reconnectBackoff: ReconnectBackoff = ReconnectBackoff(),
        sleeper: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        makeSession: @escaping TunnelGenerationFactory = { pairing, clientInfo, policy in
            TunnelSession(pairing: pairing, clientInfo: clientInfo, policy: policy)
        }
    ) {
        self.pairing = pairing
        self.clientInfo = clientInfo
        self.policy = policy
        self.backoff = reconnectBackoff
        self.sleeper = sleeper
        self.now = now
        self.makeSession = makeSession

        let state = AsyncStream<TunnelState>.makeStream()
        self.stateStream = state.stream
        self.stateContinuation = state.continuation

        let mode = AsyncStream<ConnectionMode?>.makeStream()
        self.connectionModeStream = mode.stream
        self.connectionModeContinuation = mode.continuation

        let reconnect = AsyncStream<ReconnectStatus>.makeStream(bufferingPolicy: .bufferingNewest(1))
        self.reconnectStream = reconnect.stream
        self.reconnectContinuation = reconnect.continuation

        state.continuation.yield(.disconnected)
        mode.continuation.yield(nil)
    }

    @discardableResult
    public func connect(endpoints: [TransportEndpoint]) async throws -> ConnectedVia {
        guard !endpoints.isEmpty else {
            throw SessionError.unreachable
        }

        plannedEndpoints = endpoints
        switch lifecycle {
        case .running:
            if let currentVia {
                return currentVia
            }
        case .idle, .paused:
            lifecycle = .running
            pendingRedrive = false
            redriveTask?.cancel()
            redriveTask = nil
            backoff.reset()
            setReconnectStatus(nil)
        }

        return try await connectUntilEstablished(reason: nil, immediate: true)
    }

    public func disconnect() async {
        lifecycle = .idle
        pendingRedrive = false
        redriveTask?.cancel()
        redriveTask = nil
        connectingToken = nil
        backoff.reset()
        setReconnectStatus(nil)
        await clearGeneration(disconnect: true)
        currentVia = nil
        setConnectionMode(nil)
        publish(.disconnected)
    }

    public func requestReconnect() async {
        guard lifecycle == .running else {
            return
        }
        backoff.reset()
        requestRedrive(reason: nil, immediate: true)
    }

    public func openStream() async throws -> MuxStream {
        guard let session = generation?.session else {
            throw SessionError.notConnected
        }
        do {
            return try await session.openStream()
        } catch {
            requestRedrive(reason: .transportFailed("mux closed"), immediate: true)
            throw error
        }
    }

    public func inboundActivitySnapshot() async -> UInt64 {
        guard let session = generation?.session else {
            return 0
        }
        return await session.inboundActivitySnapshot()
    }

    private func connectUntilEstablished(reason: SessionError?, immediate: Bool) async throws -> ConnectedVia {
        var nextReason = reason
        var nextImmediate = immediate
        while lifecycle == .running {
            if !nextImmediate {
                let step = backoff.nextDelay()
                setReconnectStatus(ReconnectStatus(
                    reason: nextReason,
                    attempt: step.attempt,
                    retryAfter: step.delay,
                    terminalPause: false
                ))
                try await sleeper(step.delay)
            } else {
                setReconnectStatus(ReconnectStatus(
                    reason: nextReason,
                    attempt: 1,
                    retryAfter: nil,
                    terminalPause: false
                ))
            }

            do {
                let via = try await startGeneration()
                backoff.reset()
                setReconnectStatus(nil)
                return via
            } catch let error as SessionError {
                if Self.isTerminalPause(error) {
                    await pause(error)
                    throw error
                }
                nextReason = error
                nextImmediate = false
            }
        }
        throw SessionError.notConnected
    }

    private func startGeneration() async throws -> ConnectedVia {
        guard !plannedEndpoints.isEmpty else {
            throw SessionError.unreachable
        }

        nextGenerationToken += 1
        let token = nextGenerationToken
        let session = await makeSession(pairing, clientInfo, policy)
        await installGeneration(session, token: token)

        let plan = planner.plan(candidates: plannedEndpoints, now: now())
        connectingToken = token
        do {
            let via = try await session.connect(
                endpoints: plan.candidates,
                preferredEndpoint: plan.preferredEndpoint
            )
            connectingToken = nil
            guard generation?.token == token else {
                throw SessionError.notConnected
            }
            currentVia = via
            planner.noteConnected(endpoint: await session.connectedEndpoint(), now: now())
            supervisorLog.notice("supervisor connected generation=\(token, privacy: .public)")
            return via
        } catch let error as SessionError {
            connectingToken = nil
            planner.noteFailure(error, attemptedTrustedEndpoint: plan.preferredEndpoint)
            throw error
        } catch {
            connectingToken = nil
            planner.noteFailure(.unreachable, attemptedTrustedEndpoint: plan.preferredEndpoint)
            throw SessionError.unreachable
        }
    }

    private func installGeneration(_ session: any TunnelGeneration, token: UInt64) async {
        await clearGeneration(disconnect: true)
        generation = Generation(token: token, session: session)
        currentVia = nil
        stateTask = Task { [session] in
            for await state in session.stateUpdates {
                await self.handleChildState(state, token: token)
            }
        }
        modeTask = Task { [session] in
            for await mode in session.connectionModeUpdates {
                await self.handleChildMode(mode, token: token)
            }
        }
    }

    private func clearGeneration(disconnect: Bool) async {
        stateTask?.cancel()
        stateTask = nil
        modeTask?.cancel()
        modeTask = nil
        let session = generation?.session
        generation = nil
        if disconnect {
            await session?.disconnect()
        }
    }

    private func handleChildState(_ childState: TunnelState, token: UInt64) async {
        guard generation?.token == token else {
            return
        }

        switch childState {
        case .disconnected:
            break
        case .connecting, .tlsHandshaking, .awaitingBroker, .connected:
            publish(childState)
        case .failed(let error):
            currentVia = nil
            planner.noteFailure(error, attemptedTrustedEndpoint: nil)
            if Self.isTerminalPause(error) {
                await pause(error)
                return
            }
            guard connectingToken != token else {
                return
            }
            requestRedrive(reason: error, immediate: false)
        }
    }

    private func handleChildMode(_ mode: ConnectionMode?, token: UInt64) async {
        guard generation?.token == token else {
            return
        }
        setConnectionMode(mode)
    }

    private func requestRedrive(reason: SessionError?, immediate: Bool) {
        guard lifecycle == .running else {
            return
        }
        pendingRedrive = true
        guard redriveTask == nil else {
            return
        }
        redriveTask = Task {
            await self.runRedrive(reason: reason, immediate: immediate)
        }
    }

    private func runRedrive(reason: SessionError?, immediate: Bool) async {
        pendingRedrive = false
        do {
            _ = try await connectUntilEstablished(reason: reason, immediate: immediate)
        } catch {
            if !Self.isTerminalPause(error) {
                supervisorLog.notice("supervisor redrive stopped")
            }
        }
        pendingRedrive = false
        redriveTask = nil
    }

    private func pause(_ error: SessionError) async {
        lifecycle = .paused(error)
        pendingRedrive = false
        redriveTask?.cancel()
        redriveTask = nil
        connectingToken = nil
        backoff.reset()
        planner.noteTerminalPause()
        currentVia = nil
        await clearGeneration(disconnect: true)
        setConnectionMode(nil)
        setReconnectStatus(ReconnectStatus(
            reason: error,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        ))
        publish(.failed(error))
    }

    private func publish(_ newState: TunnelState) {
        state = newState
        stateContinuation.yield(newState)
        supervisorLog.notice("supervisor state=\(String(describing: newState), privacy: .public)")
    }

    private func setConnectionMode(_ newMode: ConnectionMode?) {
        connectionMode = newMode
        connectionModeContinuation.yield(newMode)
    }

    private func setReconnectStatus(_ status: ReconnectStatus?) {
        reconnectStatus = status
        if let status {
            reconnectContinuation.yield(status)
        }
    }

    private static func isTerminalPause(_ error: any Error) -> Bool {
        guard let error = error as? SessionError else {
            return false
        }
        return isTerminalPause(error)
    }

    private static func isTerminalPause(_ error: SessionError) -> Bool {
        switch error {
        case .authRefreshRequired, .notEntitled, .revoked:
            return true
        case .unreachable, .tlsFailed, .notConnected, .directKeepaliveMissed,
             .relayKeepaliveMissed, .transportFailed, .inboundClosed:
            return false
        }
    }
}
