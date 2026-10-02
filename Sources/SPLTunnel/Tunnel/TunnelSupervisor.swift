// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import os

private let supervisorLog = SPLLogging.logger(for: .session)

public struct ReconnectStatus: Sendable, Equatable {
    public let reason: SessionError?
    public let attempt: Int
    public let retryAfter: Duration?
    public let terminalPause: Bool

    init(
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
    func isTransferring(quiet: Duration, pendingLimit: Duration) async -> Bool
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
    /// Actor-isolated current high-level attempt state. Starts in `.idle`.
    public private(set) var attemptState: TunnelSupervisorAttemptState = .idle

    // why: observation-only test instrumentation and must never gate behavior.
    var attemptStateSubscriberCount: Int {
        attemptStateSubscribers.count
    }

    private enum Lifecycle: Sendable, Equatable {
        case idle
        case running
        case paused
    }

    enum RetirementCommitCaller: Sendable, Equatable {
        case publicOpenStream
        case establishment
        case activeChildConnected
    }

    private struct Generation: Sendable {
        let token: UInt64
        let session: any TunnelGeneration
    }

    private struct RetiringGeneration: Sendable {
        let generation: Generation
        let stateTask: Task<Void, Never>?
    }

    private struct Establishment: Sendable {
        let token: UInt64
        let task: Task<ConnectedVia, Error>
    }

    private struct RedriveRequest: Sendable, Equatable {
        var sourceToken: UInt64?
        var reason: SessionError?
        var userInitiated: Bool

        mutating func merge(reason: SessionError?, userInitiated: Bool, sourceToken: UInt64?) {
            if self.reason == nil {
                self.reason = reason
            }
            self.userInitiated = self.userInitiated || userInitiated
            if let sourceToken {
                self.sourceToken = sourceToken
            }
        }
    }

    // why: LoopbackProxy sets no proxied request deadline, so the active request
    // path inherits Foundation's 60 s default; field evidence saw doomed
    // generations live ~32 s, proving a 10 s dial-cycle floor was too low.
    private static let stableGenerationInterval: Duration = .seconds(60)

    // A carrier on a worse path than the pairing offers tries the better paths
    // again after these delays (the last repeats). An interface change tries at
    // once. A better carrier takes new streams; the old one drains.
    private static let upgradeDelays: [Duration] = [.seconds(30), .seconds(120), .seconds(600)]
    private static let drainQuiet: Duration = .seconds(5)
    private static let drainPendingLimit: Duration = .seconds(30)
    private static let drainCap: Duration = .seconds(120)
    private static let drainPoll: Duration = .seconds(1)

    private let pairing: StoredPairing
    private let clientInfo: SPLClientInfo
    private let policy: SessionPolicy
    private let makeSession: TunnelGenerationFactory
    private let sleeper: @Sendable (Duration) async throws -> Void
    private let upgradeSleeper: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> ContinuousClock.Instant
    private let retirementCommitTestGate: (@Sendable (UInt64, RetirementCommitCaller) async -> Void)?
    private let stateEmissionTestObserver: @Sendable (TunnelState) -> Void
    // why: This is observation-only test instrumentation and must never gate behavior.
    private let redriveRequestTestObserver: @Sendable () -> Void

    private let stateStream: AsyncStream<TunnelState>
    private let stateContinuation: AsyncStream<TunnelState>.Continuation
    private let connectionModeStream: AsyncStream<ConnectionMode?>
    private let connectionModeContinuation: AsyncStream<ConnectionMode?>.Continuation
    private let reconnectStream: AsyncStream<ReconnectStatus>
    private let reconnectContinuation: AsyncStream<ReconnectStatus>.Continuation

    private var lifecycle: Lifecycle = .idle
    private var generation: Generation?
    private var retiringGeneration: RetiringGeneration?
    private var nextGenerationToken: UInt64 = 0
    private var connectingToken: UInt64?
    private var establishment: Establishment?
    private var nextEstablishmentToken: UInt64 = 0
    private var stateTask: Task<Void, Never>?
    private var modeTask: Task<Void, Never>?
    private var redriveTask: Task<Void, Never>?
    private var stabilityTask: Task<Void, Never>?
    private var pendingRedrive: RedriveRequest?
    private var redriveSourceToken: UInt64?
    private var nextStabilityToken: UInt64 = 0
    private var activeStabilityToken: UInt64?
    private var generationFailure: (token: UInt64, error: SessionError)?
    private var plannedEndpoints: [TransportEndpoint] = []
    private var currentVia: ConnectedVia?
    private var currentEndpoint: TransportEndpoint?
    private var upgradeTask: Task<Void, Never>?
    private var upgradeAttempts = 0
    private var upgradeDialing = false
    private var draining: [UInt64: (session: any TunnelGeneration, task: Task<Void, Never>)] = [:]
    private var planner = DialPlanner()
    private var backoff = ReconnectBackoff()
    private var pendingRetryStep: ReconnectBackoff.Step?
    private var attemptStateSubscribers: [UInt64: AsyncStream<TunnelSupervisorAttemptState>.Continuation] = [:]
    private var nextAttemptStateSubscriberID: UInt64 = 0

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
        upgradeSleeper: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        makeSession: @escaping TunnelGenerationFactory = { pairing, clientInfo, policy in
            TunnelSession(pairing: pairing, clientInfo: clientInfo, policy: policy)
        },
        // Internal test seams; defaults have no production effect.
        retirementCommitTestGate: (@Sendable (UInt64, RetirementCommitCaller) async -> Void)? = nil,
        stateEmissionTestObserver: @escaping @Sendable (TunnelState) -> Void = { _ in },
        redriveRequestTestObserver: @escaping @Sendable () -> Void = {}
    ) {
        self.pairing = pairing
        self.clientInfo = clientInfo
        self.policy = policy
        self.backoff = reconnectBackoff
        self.sleeper = sleeper
        self.upgradeSleeper = upgradeSleeper
        self.now = now
        self.makeSession = makeSession
        self.retirementCommitTestGate = retirementCommitTestGate
        self.stateEmissionTestObserver = stateEmissionTestObserver
        self.redriveRequestTestObserver = redriveRequestTestObserver

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

    /// Returns a new `.bufferingNewest(1)` stream yielding attempt-state transitions.
    ///
    /// Yields the current `attemptState` immediately upon creation. Cancelling an iterator removes
    /// only that individual subscription. The stream does not finish on pause or disconnect.
    public func attemptStateUpdates() -> AsyncStream<TunnelSupervisorAttemptState> {
        let (stream, continuation) = AsyncStream<TunnelSupervisorAttemptState>.makeStream(bufferingPolicy: .bufferingNewest(1))
        nextAttemptStateSubscriberID += 1
        let subscriberID = nextAttemptStateSubscriberID
        attemptStateSubscribers[subscriberID] = continuation
        continuation.yield(attemptState)
        continuation.onTermination = { [weak self] _ in
            Task {
                await self?.removeAttemptStateSubscriber(subscriberID)
            }
        }
        return stream
    }

    private func removeAttemptStateSubscriber(_ id: UInt64) {
        attemptStateSubscribers.removeValue(forKey: id)
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
            return try await establish(reason: nil, userInitiated: true)
        case .idle, .paused:
            lifecycle = .running
            pendingRedrive = nil
            redriveSourceToken = nil
            redriveTask?.cancel()
            redriveTask = nil
            cancelEstablishment()
            backoff.reset()
            pendingRetryStep = nil
            setReconnectStatus(nil)
        }

        return try await establish(reason: nil, userInitiated: true)
    }

    public func disconnect() async {
        lifecycle = .idle
        cancelUpgrade()
        await disconnectDraining()
        pendingRedrive = nil
        redriveSourceToken = nil
        redriveTask?.cancel()
        redriveTask = nil
        cancelStabilityTimer()
        cancelEstablishment()
        connectingToken = nil
        backoff.reset()
        pendingRetryStep = nil
        setReconnectStatus(nil)
        currentVia = nil
        currentEndpoint = nil
        publishAttemptState(.idle)
        await clearGeneration(disconnect: true)
        setConnectionMode(nil)
        publish(.disconnected)
    }

    public func requestReconnect() async {
        guard lifecycle == .running else {
            return
        }
        requestRedrive(reason: nil, userInitiated: false, sourceToken: redriveSourceToken ?? currentGenerationToken())
    }

    /// Try the pairing's better paths now. Does nothing unless a carrier is up on
    /// a path some other candidate outranks. The current carrier keeps working
    /// unless a better one connects.
    public func requestUpgrade() async {
        guard lifecycle == .running, let current = generation, currentVia != nil, !upgradeDialing else {
            return
        }
        upgradeAttempts = 0
        scheduleUpgrade(from: current.token, connectedTo: currentEndpoint, immediately: true)
    }

    public func openStream() async throws -> MuxStream {
        guard let current = generation else {
            throw SessionError.notConnected
        }

        let stream: MuxStream
        do {
            stream = try await current.session.openStream()
        } catch {
            if let sessionError = error as? SessionError, sessionError == .revoked {
                throw sessionError
            }
            if generation?.token == current.token, connectingToken != current.token {
                publishRetryingUnavailable(.transportFailed("mux closed"))
                requestRedrive(
                    reason: .transportFailed("mux closed"),
                    userInitiated: false,
                    sourceToken: current.token
                )
            }
            throw error
        }

        guard await commitRetiringGeneration(
            for: current.token,
            caller: .publicOpenStream
        ) else {
            throw SessionError.notConnected
        }
        return stream
    }

    public func inboundActivitySnapshot() async -> UInt64 {
        guard let session = generation?.session else {
            return 0
        }
        return await session.inboundActivitySnapshot()
    }

    private func establish(reason: SessionError?, userInitiated: Bool) async throws -> ConnectedVia {
        let current = ensureEstablishment(reason: reason, userInitiated: userInitiated)
        do {
            let via = try await current.task.value
            clearEstablishment(token: current.token)
            return via
        } catch {
            clearEstablishment(token: current.token)
            throw error
        }
    }

    private func ensureEstablishment(reason: SessionError?, userInitiated: Bool) -> Establishment {
        if let establishment {
            return establishment
        }

        nextEstablishmentToken += 1
        let token = nextEstablishmentToken
        let task = Task {
            try await self.connectUntilEstablished(reason: reason, userInitiated: userInitiated)
        }
        let establishment = Establishment(token: token, task: task)
        self.establishment = establishment
        return establishment
    }

    private func clearEstablishment(token: UInt64) {
        guard establishment?.token == token else {
            return
        }
        establishment = nil
    }

    private func cancelEstablishment() {
        establishment?.task.cancel()
        establishment = nil
    }

    private func connectUntilEstablished(reason: SessionError?, userInitiated: Bool) async throws -> ConnectedVia {
        var nextReason = reason
        var nextUserInitiated = userInitiated
        while lifecycle == .running {
            if !nextUserInitiated {
                let step = consumeRetryStep()
                setReconnectStatus(ReconnectStatus(
                    reason: nextReason,
                    attempt: step.attempt,
                    retryAfter: step.delay,
                    terminalPause: false
                ))
                try await sleeper(step.delay)
                guard lifecycle == .running else {
                    throw SessionError.notConnected
                }
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
                setReconnectStatus(nil)
                return via
            } catch let error as SessionError {
                if Self.isTerminalPause(error) {
                    await pause(error)
                    throw error
                }
                publishRetryingUnavailable(error)
                nextReason = error
                nextUserInitiated = false
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
        guard lifecycle == .running, nextGenerationToken == token else {
            throw SessionError.notConnected
        }
        await installGeneration(session, token: token)

        let plan = planner.plan(candidates: plannedEndpoints, now: now())
        connectingToken = token
        guard lifecycle == .running, nextGenerationToken == token else {
            connectingToken = nil
            throw SessionError.notConnected
        }
        publishAttemptState(.attempting)
        let connected: (via: ConnectedVia, endpoint: TransportEndpoint?)
        do {
            let via = try await session.connect(
                endpoints: plan.candidates,
                preferredEndpoint: plan.preferredEndpoint
            )
            let endpoint = await session.connectedEndpoint()
            guard generation?.token == token else {
                throw SessionError.notConnected
            }
            guard lifecycle == .running else {
                throw SessionError.notConnected
            }
            if let failure = generationFailure, failure.token == token {
                throw failure.error
            }
            connectingToken = nil
            currentVia = via
            connected = (via, endpoint)
        } catch let error as SessionError {
            // why: leave connectingToken set so a racing child .failed cannot look like
            // post-connect route-loss and increment the retry attempt a second time.
            if generationFailure?.token != token {
                generationFailure = (token: token, error: error)
            }
            planner.noteFailure(error, attemptedTrustedEndpoint: plan.preferredEndpoint)
            throw error
        } catch {
            if generationFailure?.token != token {
                generationFailure = (token: token, error: .unreachable)
            }
            planner.noteFailure(.unreachable, attemptedTrustedEndpoint: plan.preferredEndpoint)
            throw SessionError.unreachable
        }

        guard await commitRetiringGeneration(for: token, caller: .establishment) else {
            // why: handleActiveChildState already recorded this failure with the planner;
            // re-noting it here would demote direct trust for a post-ready failure.
            if let failure = generationFailure, failure.token == token {
                throw failure.error
            }
            throw SessionError.notConnected
        }
        publishAttemptState(.connected)
        currentEndpoint = connected.endpoint
        planner.noteConnected(endpoint: connected.endpoint, now: now())
        armStabilityTimer(for: token)
        scheduleUpgrade(from: token, connectedTo: connected.endpoint, immediately: false)
        supervisorLog.notice("supervisor connected generation=\(token, privacy: .public)")
        return connected.via
    }

    private func installGeneration(_ session: any TunnelGeneration, token: UInt64) async {
        cancelStabilityTimer()
        cancelUpgrade()
        let outgoing = generation
        let shouldRetireOutgoing = outgoing.map { generationFailure?.token == $0.token } ?? false
        if shouldRetireOutgoing, retiringGeneration == nil, let outgoing {
            retireActiveGeneration(outgoing)
        } else {
            await clearActiveGeneration(disconnect: true)
        }
        generation = Generation(token: token, session: session)
        currentVia = nil
        currentEndpoint = nil
        generationFailure = nil
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
        cancelStabilityTimer()
        await clearActiveGeneration(disconnect: disconnect)
        await clearRetiringGeneration(disconnect: disconnect)
    }

    private func retireActiveGeneration(_ outgoing: Generation) {
        let outgoingStateTask = stateTask
        stateTask = nil
        modeTask?.cancel()
        modeTask = nil
        generation = nil
        generationFailure = nil
        retiringGeneration = RetiringGeneration(generation: outgoing, stateTask: outgoingStateTask)
    }

    private func clearActiveGeneration(disconnect: Bool) async {
        stateTask?.cancel()
        stateTask = nil
        modeTask?.cancel()
        modeTask = nil
        let session = generation?.session
        let wasConnected = (attemptState == .connected)
        generation = nil
        generationFailure = nil
        if lifecycle == .running, wasConnected, session != nil {
            publishAttemptState(.unavailable(.replacing))
        }
        if disconnect {
            await session?.disconnect()
        }
    }

    private func isValidInstalledGeneration(_ token: UInt64) -> Bool {
        generation?.token == token &&
            lifecycle == .running &&
            generationFailure?.token != token
    }

    private func commitRetiringGeneration(
        for token: UInt64,
        caller: RetirementCommitCaller
    ) async -> Bool {
        guard isValidInstalledGeneration(token) else {
            return false
        }
        guard retiringGeneration != nil else {
            return true
        }
        if let retirementCommitTestGate {
            await retirementCommitTestGate(token, caller)
        }
        // The test gate can suspend while identity, lifecycle, or failure eligibility changes.
        guard isValidInstalledGeneration(token) else {
            return false
        }
        guard let retiringGeneration else {
            return true
        }
        self.retiringGeneration = nil
        retiringGeneration.stateTask?.cancel()
        await retiringGeneration.generation.session.disconnect()
        return isValidInstalledGeneration(token)
    }

    private func clearRetiringGeneration(disconnect: Bool) async {
        guard let retiringGeneration else {
            return
        }
        self.retiringGeneration = nil
        retiringGeneration.stateTask?.cancel()
        if disconnect {
            await retiringGeneration.generation.session.disconnect()
        }
    }

    private func armStabilityTimer(for generationToken: UInt64) {
        cancelStabilityTimer()
        nextStabilityToken &+= 1
        let stabilityToken = nextStabilityToken
        activeStabilityToken = stabilityToken
        stabilityTask = Task {
            do {
                try await sleeper(Self.stableGenerationInterval)
            } catch {
                return
            }
            self.completeStabilityTimer(
                generationToken: generationToken,
                stabilityToken: stabilityToken
            )
        }
    }

    private func cancelStabilityTimer() {
        stabilityTask?.cancel()
        stabilityTask = nil
        activeStabilityToken = nil
    }

    private func completeStabilityTimer(generationToken: UInt64, stabilityToken: UInt64) {
        guard activeStabilityToken == stabilityToken,
              generation?.token == generationToken,
              lifecycle == .running,
              currentVia != nil else {
            return
        }
        if let failure = generationFailure, failure.token == generationToken {
            return
        }
        backoff.reset()
        pendingRetryStep = nil
        stabilityTask = nil
        activeStabilityToken = nil
        if let currentEndpoint, betterCandidates(than: currentEndpoint).isEmpty {
            upgradeAttempts = 0
        }
    }

    private func handleChildState(_ childState: TunnelState, token: UInt64) async {
        if generation?.token == token {
            await handleActiveChildState(childState, token: token)
            return
        }

        guard retiringGeneration?.generation.token == token,
              case .failed(.revoked) = childState else {
            return
        }
        await pause(.revoked)
    }

    private func handleActiveChildState(_ childState: TunnelState, token: UInt64) async {
        switch childState {
        case .disconnected:
            break
        case .connecting, .tlsHandshaking, .awaitingBroker:
            publish(childState)
        case .connected:
            // why: Connected is the first public capability; dial-progress states must retain
            // terminal eligibility until the successor is externally observable or usable.
            guard await commitRetiringGeneration(
                for: token,
                caller: .activeChildConnected
            ) else {
                return
            }
            publish(childState)
        case .failed(let error):
            currentVia = nil
            currentEndpoint = nil
            cancelUpgrade()
            let alreadyRecorded = generationFailure?.token == token
            generationFailure = (token: token, error: error)
            cancelStabilityTimer()
            if Self.isTerminalPause(error) {
                await pause(error)
                return
            }
            guard connectingToken != token else {
                return
            }
            // why: connect() catch already recorded this generation; a late .failed must
            // not publish a second retrying step.
            guard !alreadyRecorded else {
                return
            }
            publishRetryingUnavailable(error)
            planner.noteFailure(error, attemptedTrustedEndpoint: nil)
            publish(.connecting(candidates: plannedEndpoints.map(\.connectedVia)))
            requestRedrive(reason: error, userInitiated: false, sourceToken: token)
        }
    }

    private func handleChildMode(_ mode: ConnectionMode?, token: UInt64) async {
        guard generation?.token == token else {
            return
        }
        setConnectionMode(mode)
    }

    private func requestRedrive(reason: SessionError?, userInitiated: Bool, sourceToken: UInt64?) {
        guard lifecycle == .running else {
            return
        }
        if let redriveSourceToken, redriveSourceToken == sourceToken {
            return
        }
        if var request = pendingRedrive {
            request.merge(reason: reason, userInitiated: userInitiated, sourceToken: sourceToken)
            pendingRedrive = request
        } else {
            pendingRedrive = RedriveRequest(sourceToken: sourceToken, reason: reason, userInitiated: userInitiated)
        }
        redriveRequestTestObserver()
        guard redriveTask == nil else {
            return
        }
        redriveTask = Task {
            await self.runRedrive()
        }
    }

    private func runRedrive() async {
        while lifecycle == .running {
            guard let request = pendingRedrive else {
                break
            }
            pendingRedrive = nil
            redriveSourceToken = request.sourceToken
            do {
                _ = try await establish(reason: request.reason, userInitiated: request.userInitiated)
            } catch {
                if !Self.isTerminalPause(error) {
                    supervisorLog.notice("supervisor redrive stopped")
                }
            }
            redriveSourceToken = nil
        }
        redriveTask = nil
    }

    private func pause(_ error: SessionError) async {
        guard lifecycle == .running else {
            return
        }
        lifecycle = .paused
        cancelUpgrade()
        await disconnectDraining()
        pendingRedrive = nil
        redriveSourceToken = nil
        redriveTask?.cancel()
        redriveTask = nil
        cancelStabilityTimer()
        cancelEstablishment()
        connectingToken = nil
        backoff.reset()
        pendingRetryStep = nil
        planner.noteTerminalPause()
        currentVia = nil
        currentEndpoint = nil
        publishAttemptState(.terminal(error.attemptFailureClass))
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

    private func betterCandidates(than endpoint: TransportEndpoint) -> [TransportEndpoint] {
        let currentRank = CandidateOrdering.rank(endpoint)
        return plannedEndpoints.filter { CandidateOrdering.rank($0) < currentRank }
    }

    private func cancelUpgrade() {
        upgradeTask?.cancel()
        upgradeTask = nil
    }

    private func scheduleUpgrade(from token: UInt64, connectedTo endpoint: TransportEndpoint?, immediately: Bool) {
        cancelUpgrade()
        guard policy.returnsToBetterPath, let endpoint, !betterCandidates(than: endpoint).isEmpty else {
            return
        }
        let delay = immediately
            ? Duration.zero
            : Self.upgradeDelays[min(upgradeAttempts, Self.upgradeDelays.count - 1)]
        let upgradeSleeper = upgradeSleeper
        upgradeTask = Task {
            if delay > .zero {
                do {
                    try await upgradeSleeper(delay)
                } catch {
                    return
                }
            }
            await self.attemptUpgrade(from: token)
        }
    }

    private func isCurrentHealthyGeneration(_ token: UInt64) -> Bool {
        !Task.isCancelled && lifecycle == .running && generation?.token == token && currentVia != nil
    }

    private func attemptUpgrade(from token: UInt64) async {
        guard isCurrentHealthyGeneration(token), let current = generation, let endpoint = currentEndpoint else {
            return
        }
        let better = betterCandidates(than: endpoint)
        guard !better.isEmpty else {
            return
        }
        upgradeAttempts += 1
        upgradeDialing = true
        defer { upgradeDialing = false }
        supervisorLog.notice("supervisor upgrade attempt generation=\(token, privacy: .public) from=\(endpoint.logDescription, privacy: .public) candidates=\(better.count, privacy: .public)")
        let candidate = await makeSession(pairing, clientInfo, policy)
        guard isCurrentHealthyGeneration(token) else {
            await candidate.disconnect()
            return
        }
        let via: ConnectedVia
        do {
            via = try await candidate.connect(endpoints: better, preferredEndpoint: nil)
        } catch {
            await candidate.disconnect()
            supervisorLog.notice("supervisor upgrade found no better path; keeping generation=\(token, privacy: .public)")
            if isCurrentHealthyGeneration(token) {
                scheduleUpgrade(from: token, connectedTo: endpoint, immediately: false)
            }
            return
        }
        let upgradedEndpoint = await candidate.connectedEndpoint()
        guard isCurrentHealthyGeneration(token) else {
            await candidate.disconnect()
            return
        }
        promote(candidate, via: via, endpoint: upgradedEndpoint, replacing: current)
    }

    /// Makes an already-connected carrier the generation new streams use, and
    /// lets the one it replaces finish what it is carrying.
    private func promote(
        _ session: any TunnelGeneration,
        via: ConnectedVia,
        endpoint: TransportEndpoint?,
        replacing old: Generation
    ) {
        cancelStabilityTimer()
        stateTask?.cancel()
        stateTask = nil
        modeTask?.cancel()
        modeTask = nil
        nextGenerationToken += 1
        let token = nextGenerationToken
        generation = Generation(token: token, session: session)
        generationFailure = nil
        currentVia = via
        currentEndpoint = endpoint
        // The new carrier's dial progress is already buffered in its streams;
        // replaying it would announce a reconnect that never happened.
        stateTask = Task { [session] in
            var connected = false
            for await state in session.stateUpdates {
                if !connected {
                    if case .connected = state {
                        connected = true
                    }
                    continue
                }
                await self.handleChildState(state, token: token)
            }
        }
        modeTask = Task { [session] in
            for await mode in session.connectionModeUpdates where mode != nil {
                await self.handleChildMode(mode, token: token)
            }
        }
        drain(old)
        setConnectionMode(endpoint?.isDirect == false ? .plViaSpl : .plDirect)
        planner.noteConnected(endpoint: endpoint, now: now())
        armStabilityTimer(for: token)
        publish(.connected(via: via))
        supervisorLog.notice("supervisor upgraded generation=\(token, privacy: .public) endpoint=\(endpoint?.logDescription ?? "unknown", privacy: .public) draining=\(old.token, privacy: .public)")
        scheduleUpgrade(from: token, connectedTo: endpoint, immediately: false)
    }

    private func drain(_ old: Generation) {
        let token = old.token
        let session = old.session
        let start = now()
        let now = now
        let poll = upgradeSleeper
        let task = Task {
            while true {
                let busy = await session.isTransferring(quiet: Self.drainQuiet, pendingLimit: Self.drainPendingLimit)
                if !busy || start.duration(to: now()) >= Self.drainCap {
                    break
                }
                do {
                    try await poll(Self.drainPoll)
                } catch {
                    break
                }
            }
            await self.finishDrain(token)
        }
        draining[token] = (session, task)
    }

    private func finishDrain(_ token: UInt64) async {
        guard let entry = draining.removeValue(forKey: token) else {
            return
        }
        supervisorLog.notice("supervisor drained generation=\(token, privacy: .public)")
        await entry.session.disconnect()
    }

    private func disconnectDraining() async {
        let entries = draining
        draining.removeAll()
        for (_, entry) in entries {
            entry.task.cancel()
            await entry.session.disconnect()
        }
    }

    private func publishAttemptState(_ new: TunnelSupervisorAttemptState) {
        guard new != attemptState else {
            return
        }
        attemptState = new
        for continuation in attemptStateSubscribers.values {
            continuation.yield(new)
        }
        supervisorLog.notice("supervisor attempt_state=\(String(describing: new), privacy: .public)")
    }

    private func publishRetryingUnavailable(_ error: SessionError) {
        let step = backoff.nextDelay()
        pendingRetryStep = step
        publishAttemptState(.unavailable(.retrying(
            failureClass: error.attemptFailureClass,
            attempt: step.attempt,
            retryAfter: step.delay
        )))
    }

    private func consumeRetryStep() -> ReconnectBackoff.Step {
        if let pending = pendingRetryStep {
            pendingRetryStep = nil
            return pending
        }
        return backoff.nextDelay()
    }

    private func publish(_ newState: TunnelState) {
        stateEmissionTestObserver(newState)
        stateContinuation.yield(newState)
        supervisorLog.notice("supervisor state=\(TunnelStateLogDescription.describe(newState), privacy: .public)")
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

    private func currentGenerationToken() -> UInt64? {
        generation?.token ?? connectingToken
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
