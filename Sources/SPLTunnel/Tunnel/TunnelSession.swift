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

/// Routes a failed write through the session's verdict window, so a write that fails before
/// the journal's first byte reports the journal's refusal rather than the write's symptom.
private struct VerdictReportingTunnelTLS: TunnelTLSIO {
    let base: any TunnelTLSIO
    let resolveWriteFailure: @Sendable (any Error) async -> SessionError?

    var inbound: AsyncThrowingStream<Data, Error> {
        base.inbound
    }

    func send(_ data: Data) async throws {
        do {
            try await base.send(data)
        } catch {
            if let verdict = await resolveWriteFailure(error) {
                throw verdict
            }
            throw error
        }
    }

    func close() async {
        await base.close()
    }
}

/// Where one connection stands in its verdict window (`proto/session.md` § 7): it opens
/// when the client's handshake completes and closes at the journal's first application byte.
private enum VerdictWindow: Sendable, Equatable {
    /// Neither an application byte nor the journal's refusal has arrived.
    case open
    /// The journal sent its first application byte: it accepted this device. Any alert
    /// after this is an ordinary session error.
    case accepted
    /// The journal refused this device.
    case refused(SessionError)
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

    /// A stop outranks the journal's other verdicts, which outrank any other failure.
    static func rank(_ error: SessionError) -> Int {
        switch error {
        case .revoked, .refusalsExhausted:
            2
        case .refused, .certificateUnknown:
            1
        default:
            0
        }
    }
}

/// How long a write that failed inside the verdict window waits for the journal's verdict.
let verdictReadGrace: Duration = .seconds(1)

public actor TunnelSession: TunnelSessioning, MuxStreamOpening, TunnelAttemptObserving {
    public nonisolated var stateUpdates: AsyncStream<TunnelState> {
        stateStream
    }

    public nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> {
        connectionModeStream
    }

    public nonisolated var attemptUpdates: AsyncStream<TunnelAttemptEvent> {
        attemptUpdatesStream
    }

    /// Peers that answered where the paired journal was expected but are not it, in the
    /// order they were seen. A sighting is delivered even when another path then connects.
    /// The newest 32 are kept until read.
    public nonisolated var unknownJournalSightings: AsyncStream<UnknownJournalSighting> {
        sightingsStream
    }

    public private(set) var connectionMode: ConnectionMode?

    private let pairing: StoredPairing
    private let policy: SessionPolicy
    private let tlsConnector: TunnelTLSConnector
    private let makeMultiplexer: TunnelMuxFactory
    private let installWindowTestGate: @Sendable () async -> Void
    private let pendingInstallFailureTestObserver: @Sendable () async -> Void
    private let stateStream: AsyncStream<TunnelState>
    private let stateContinuation: AsyncStream<TunnelState>.Continuation
    private let connectionModeStream: AsyncStream<ConnectionMode?>
    private let connectionModeContinuation: AsyncStream<ConnectionMode?>.Continuation
    private let attemptUpdatesStream: AsyncStream<TunnelAttemptEvent>
    private let attemptUpdatesContinuation: AsyncStream<TunnelAttemptEvent>.Continuation
    private let sightingsStream: AsyncStream<UnknownJournalSighting>
    private let sightingsContinuation: AsyncStream<UnknownJournalSighting>.Continuation
    private let unknownJournalObserver: @Sendable (UnknownJournalSighting) -> Void
    private let refusals: HandshakeRefusalLedger
    private let now: @Sendable () -> ContinuousClock.Instant
    private var state: TunnelState = .disconnected
    private var inboundPumpTask: Task<Void, Never>?
    private var inboundPumpID: UUID?
    private var keepaliveWatchTask: Task<Void, Never>?
    private var innerTLS: (any TunnelTLSIO)?
    private var multiplexer: Multiplexer?
    private var activeEndpoint: TransportEndpoint?
    private var pendingInstallFailure: PendingInstallFailure?
    // why: A generically failed session stays eligible for the journal's verdict until its
    // supervisor retires or disconnects it; this ID scopes that verdict to one connection.
    private var terminalEligiblePumpID: UUID?
    // The connection whose verdict window this session is tracking; cleared by a user disconnect.
    private var verdictPumpID: UUID?
    private var verdictWindow: VerdictWindow = .open
    private var pumpEnded = false
    private var verdictWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var connectAttemptID: UUID?
    private var isTerminated = false
    private var attemptUpdatesFinished = false

    /// Creates a single-connection session.
    ///
    /// `refusalStore` keeps the credential's refusal count and stop across processes; pass
    /// the ``SPLKeychainStore/refusalStore`` of the store that holds the pairing.
    public init(
        pairing: StoredPairing,
        clientInfo: SPLClientInfo,
        policy: SessionPolicy = SessionPolicy(),
        refusalStore: any HandshakeRefusalStore
    ) {
        self.init(
            pairing: pairing,
            policy: policy,
            tlsConnector: Self.defaultTLSConnector(policy: policy, clientInfo: clientInfo),
            refusalLedger: HandshakeRefusalLedger(credential: pairing.refusalCredential, store: refusalStore)
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
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        refusalLedger: HandshakeRefusalLedger? = nil,
        unknownJournalObserver: @escaping @Sendable (UnknownJournalSighting) -> Void = { _ in }
    ) {
        self.pairing = pairing
        self.refusals = refusalLedger ?? HandshakeRefusalLedger(
            credential: pairing.refusalCredential,
            store: EphemeralRefusalStore()
        )
        self.unknownJournalObserver = unknownJournalObserver
        self.policy = policy
        self.tlsConnector = tlsConnector
        self.makeMultiplexer = makeMultiplexer
        self.installWindowTestGate = installWindowTestGate
        self.pendingInstallFailureTestObserver = pendingInstallFailureTestObserver
        self.now = now

        let state = AsyncStream<TunnelState>.makeStream()
        self.stateStream = state.stream
        self.stateContinuation = state.continuation

        let mode = AsyncStream<ConnectionMode?>.makeStream()
        self.connectionModeStream = mode.stream
        self.connectionModeContinuation = mode.continuation

        let attempts = AsyncStream<TunnelAttemptEvent>.makeStream(bufferingPolicy: .unbounded)
        self.attemptUpdatesStream = attempts.stream
        self.attemptUpdatesContinuation = attempts.continuation

        let sightings = AsyncStream<UnknownJournalSighting>.makeStream(bufferingPolicy: .bufferingNewest(32))
        self.sightingsStream = sightings.stream
        self.sightingsContinuation = sightings.continuation

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
        defer { finishAttemptUpdates() }
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

        let attemptID = UUID()
        connectAttemptID = attemptID
        // A stopped credential is never dialled again; only a new pairing ends a stop.
        if let stop = await refusals.stop() {
            guard isCurrentConnectAttempt(attemptID) else {
                throw SessionError.notConnected
            }
            let error = stop.sessionError
            sessionLog.notice("connect skipped: credential stopped stop=\(stop.rawValue, privacy: .public)")
            publish(.failed(error))
            throw error
        }
        guard isCurrentConnectAttempt(attemptID) else {
            throw SessionError.notConnected
        }
        let connected = try await connectOnce(endpoints: endpoints, preferredEndpoint: preferredEndpoint)
        guard isCurrentConnectAttempt(attemptID) else {
            await connected.tls.close()
            throw SessionError.notConnected
        }
        await installConnected(connected)
        try await publishConnected(connected, attemptID: attemptID)
        return connected.via
    }

    public func disconnect() async {
        isTerminated = true
        connectAttemptID = nil
        // A user disconnect closes the terminal eligibility window.
        terminalEligiblePumpID = nil
        verdictPumpID = nil
        await tearDownCurrent(reason: .normalShutdown)
        setConnectionMode(nil)
        publish(.disconnected)
        stateContinuation.finish()
        connectionModeContinuation.finish()
        sightingsContinuation.finish()
        finishAttemptUpdates()
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

    // why: observation-only test instrumentation and must never gate behavior.
    var pendingVerdictWaiterCount: Int {
        verdictWaiters.count
    }

    func isTransferring(quiet: Duration, pendingLimit: Duration) async -> Bool {
        guard let multiplexer else {
            return false
        }
        return await multiplexer.isTransferring(quiet: quiet, pendingLimit: pendingLimit)
    }

    private func connectOnce(
        endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint?
    ) async throws -> ConnectedAttempt {
        publish(.connecting(candidates: endpoints.map(\.connectedVia)))

        do {
            let attemptUpdatesContinuation = attemptUpdatesContinuation
            let coordinator = RaceCoordinator<ConnectedAttempt>(
                stagger: policy.race.stagger,
                loserGrace: policy.race.loserGrace,
                budget: policy.race.budget,
                close: { await $0.tls.close() },
                now: now,
                attemptEventSink: { event in
                    attemptUpdatesContinuation.yield(event)
                }
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
        do {
            if endpoint.isDirect {
                tls = try await connect()
            } else {
                tls = try await withSessionTimeout(policy.race.heldRelayTimeout, operation: connect)
            }
        } catch InnerTLSError.unknownJournal(let claimedJournalID) {
            noteUnknownJournal(UnknownJournalSighting(dialled: via, claimedJournalID: claimedJournalID))
            throw InnerTLSError.unknownJournal(claimedJournalID: claimedJournalID)
        }
        let transport = endpoint.isDirect ? "lan" : "relay"
        sessionLog.notice("connected transport=\(transport, privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
        return ConnectedAttempt(endpoint: endpoint, via: via, tls: tls)
    }

    private func publishConnected(_ connected: ConnectedAttempt, attemptID: UUID) async throws {
        guard isCurrentConnectAttempt(attemptID) else {
            await tearDownCurrent(reason: .normalShutdown)
            throw SessionError.notConnected
        }
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
        // This pump ID owns the session's one terminal peer-denial callback.
        terminalEligiblePumpID = pumpID
        pendingInstallFailure = nil
        verdictPumpID = pumpID
        verdictWindow = .open
        pumpEnded = false
        let reportingTLS = VerdictReportingTunnelTLS(base: tls) { [weak self, pumpID] error in
            guard let self else {
                // A released session tracks no verdict window: tell the writer what the peer said.
                return HandshakeFailure.verdict(from: error)?.sessionError
            }
            return await self.resolveWriteFailure(error, id: pumpID)
        }
        let mux = makeMultiplexer(reportingTLS)
        multiplexer = mux

        inboundPumpTask = Task {
            var accepted = false
            do {
                for try await chunk in tls.inbound {
                    if !accepted {
                        accepted = true
                        await self.handleFirstInbound(id: pumpID)
                    }
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
                missedLimit: policy.keepalive.missedLimit,
                deferralLimit: policy.keepalive.deferralLimit
            )
        }
        // Let already-ended pump/loss tasks run and latch against this install epoch
        // before publishConnected can publish a durable connected state.
        await Task.yield()
        await installWindowTestGate()
    }

    private func handlePumpEnded(id: UUID, error: (any Error)?) async {
        if let error, let verdict = HandshakeFailure.verdict(from: error) {
            if await handleVerdict(verdict, id: id) != nil {
                return
            }
        }
        if verdictPumpID == id {
            // The reader ended without a verdict; a write waiting for one has nothing to wait for.
            pumpEnded = true
            resumeVerdictWaiters()
        }
        guard inboundPumpID == id else {
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

    /// The journal sent its first application byte: it accepted this device, and the
    /// verdict window is closed.
    private func handleFirstInbound(id: UUID) async {
        guard verdictPumpID == id, verdictWindow == .open else {
            return
        }
        verdictWindow = .accepted
        resumeVerdictWaiters()
        await refusals.accepted()
    }

    /// A write failed. Inside the verdict window the journal's refusal may be what ended
    /// the connection, so a received alert is classified at once and any other failure
    /// waits up to ``verdictReadGrace`` for the reader to see one. Returns the verdict to
    /// report instead of the write's own error, or `nil`.
    private func resolveWriteFailure(_ error: any Error, id: UUID) async -> SessionError? {
        guard verdictPumpID == id else {
            // A connection this session no longer tracks: tell its writer what the peer said,
            // and record nothing.
            return HandshakeFailure.verdict(from: error)?.sessionError
        }
        if let verdict = HandshakeFailure.verdict(from: error) {
            if let decided = await handleVerdict(verdict, id: id) {
                return decided
            }
        } else if verdictWindow == .open, !pumpEnded {
            await waitForVerdict(timeout: verdictReadGrace)
        }
        // A session carries one connection, so its window is that connection's verdict.
        if case .refused(let decided) = verdictWindow {
            return decided
        }
        return nil
    }

    /// Records the journal's verdict on this connection once, inside its window. Returns
    /// the error the connection ends with, or `nil` when the verdict was not taken.
    private func handleVerdict(_ verdict: HandshakeFailure, id: UUID) async -> SessionError? {
        guard verdictPumpID == id, verdictWindow == .open else {
            return nil
        }
        // why: the window closes before the suspension below, so a second reader or writer
        // that sees the same refusal cannot record it twice.
        verdictWindow = .refused(verdict.sessionError)
        let stop = await refusals.record(verdict)
        let error = stop?.sessionError ?? verdict.sessionError
        verdictWindow = .refused(error)
        resumeVerdictWaiters()
        sessionLog.notice("journal refused handshake verdict=\(TunnelStateLogDescription.describe(error), privacy: .public)")
        await applyVerdict(error, id: id)
        return error
    }

    private func waitForVerdict(timeout: Duration) async {
        let waiterID = UUID()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            verdictWaiters[waiterID] = continuation
            Task { [weak self] in
                try? await Task.sleep(for: timeout)
                await self?.resumeVerdictWaiter(waiterID)
            }
        }
    }

    private func resumeVerdictWaiter(_ waiterID: UUID) {
        verdictWaiters.removeValue(forKey: waiterID)?.resume()
    }

    private func resumeVerdictWaiters() {
        let waiters = verdictWaiters
        verdictWaiters.removeAll()
        for waiter in waiters.values {
            waiter.resume()
        }
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
        await tearDownCurrent(reason: tearDownReason)
    }

    /// Ends the connection with the journal's verdict. A stop is terminal and replaces any
    /// failure already reported; another verdict replaces only a failure that is not one.
    private func applyVerdict(_ error: SessionError, id: UUID) async {
        guard terminalEligiblePumpID == id else {
            return
        }
        if case .disconnected = state {
            // A disconnected session cannot be revived by a stale verdict.
            terminalEligiblePumpID = nil
            return
        }
        let isStop = PendingInstallFailure.rank(error) == 2
        if isStop {
            // Consuming the epoch makes a second terminal callback for it a no-op.
            terminalEligiblePumpID = nil
        }
        switch state {
        case .connected:
            await failConnectedSession(error, tearDownReason: .transportFailure)
        case .failed(let previous):
            guard isStop, previous != error else {
                return
            }
            publish(.failed(error))
            await tearDownCurrent(reason: .transportFailure)
        default:
            await recordPendingInstallFailure(
                id: id,
                error: error,
                tearDownReason: .transportFailure
            )
        }
    }

    private func tearDownCurrent(reason: TearDownReason) async {
        inboundPumpID = nil
        pendingInstallFailure = nil
        resumeVerdictWaiters()
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
        if let pending = pendingInstallFailure,
           PendingInstallFailure.rank(error) <= PendingInstallFailure.rank(pending.error) {
            return
        }
        pendingInstallFailure = PendingInstallFailure(
            pumpID: id,
            error: error,
            tearDownReason: tearDownReason
        )
        await pendingInstallFailureTestObserver()
    }

    private func isCurrentConnectAttempt(_ attemptID: UUID) -> Bool {
        !isTerminated && connectAttemptID == attemptID
    }

    private static func keepaliveError(for via: ConnectedVia) -> SessionError {
        switch via {
        case .lanDirect:
            return .directKeepaliveMissed
        case .relay:
            return .relayKeepaliveMissed
        }
    }

    private func noteUnknownJournal(_ sighting: UnknownJournalSighting) {
        sessionLog.notice("unknown journal answered via=\(TunnelStateLogDescription.describe(sighting.dialled), privacy: .public) claimed_jid=\(sighting.claimedJournalID ?? "none", privacy: .public)")
        sightingsContinuation.yield(sighting)
        unknownJournalObserver(sighting)
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

    private func finishAttemptUpdates() {
        guard !attemptUpdatesFinished else {
            return
        }
        attemptUpdatesFinished = true
        attemptUpdatesContinuation.finish()
    }

    static func defaultTLSConnector(
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
