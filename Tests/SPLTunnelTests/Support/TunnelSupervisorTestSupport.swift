// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let supervisorTestClientInfo = SPLClientInfo(userAgent: "spl-swift-supervisor-support/1")

struct FakeConnectCall: Sendable, Equatable {
    let endpoints: [TransportEndpoint]
    let preferredEndpoint: TransportEndpoint?
}

struct FakeGenerationScript: Sendable {
    let result: Result<TransportEndpoint, SessionError>
    let gate: TestSignal?
    let connectedSignal: TestSignal?
    let returnGate: TestSignal?
    let connectedEndpointSignal: TestSignal?
    let connectedEndpointGate: TestSignal?
    let openStreamFailure: SessionError?
    let makeSessionSignal: TestSignal?
    let makeSessionGate: TestSignal?
    let disconnectSignal: TestSignal?
    let disconnectGate: TestSignal?
    let muxClosedAfterSuccessCount: Int?
    let muxClosedError: SessionError?

    static func success(
        _ endpoint: TransportEndpoint,
        gate: TestSignal? = nil,
        connectedSignal: TestSignal? = nil,
        returnGate: TestSignal? = nil,
        connectedEndpointSignal: TestSignal? = nil,
        connectedEndpointGate: TestSignal? = nil,
        openStreamFailure: SessionError? = nil,
        makeSessionSignal: TestSignal? = nil,
        makeSessionGate: TestSignal? = nil,
        disconnectSignal: TestSignal? = nil,
        disconnectGate: TestSignal? = nil,
        muxClosedAfterSuccessCount: Int? = nil,
        muxClosedError: SessionError? = nil
    ) -> FakeGenerationScript {
        FakeGenerationScript(
            result: .success(endpoint),
            gate: gate,
            connectedSignal: connectedSignal,
            returnGate: returnGate,
            connectedEndpointSignal: connectedEndpointSignal,
            connectedEndpointGate: connectedEndpointGate,
            openStreamFailure: openStreamFailure,
            makeSessionSignal: makeSessionSignal,
            makeSessionGate: makeSessionGate,
            disconnectSignal: disconnectSignal,
            disconnectGate: disconnectGate,
            muxClosedAfterSuccessCount: muxClosedAfterSuccessCount,
            muxClosedError: muxClosedError
        )
    }

    static func failure(
        _ error: SessionError,
        gate: TestSignal? = nil,
        makeSessionSignal: TestSignal? = nil,
        makeSessionGate: TestSignal? = nil,
        disconnectSignal: TestSignal? = nil,
        disconnectGate: TestSignal? = nil
    ) -> FakeGenerationScript {
        FakeGenerationScript(
            result: .failure(error),
            gate: gate,
            connectedSignal: nil,
            returnGate: nil,
            connectedEndpointSignal: nil,
            connectedEndpointGate: nil,
            openStreamFailure: nil,
            makeSessionSignal: makeSessionSignal,
            makeSessionGate: makeSessionGate,
            disconnectSignal: disconnectSignal,
            disconnectGate: disconnectGate,
            muxClosedAfterSuccessCount: nil,
            muxClosedError: nil
        )
    }
}

actor FakeGenerationFactory {
    private var scripts: [FakeGenerationScript]
    private var generations: [FakeGeneration] = []

    init(scripts: [FakeGenerationScript]) {
        self.scripts = scripts
    }

    func makeSession() async -> any TunnelGeneration {
        let script = scripts.removeFirst()
        await script.makeSessionSignal?.signal()
        if let gate = script.makeSessionGate {
            await gate.wait()
        }
        let generation = FakeGeneration(script: script)
        generations.append(generation)
        return generation
    }

    func count() -> Int {
        generations.count
    }

    func generation(at index: Int) throws -> FakeGeneration {
        try #require(generations.indices.contains(index))
        return generations[index]
    }
}

actor FakeGeneration: TunnelGeneration {
    nonisolated var stateUpdates: AsyncStream<TunnelState> {
        stateStream
    }

    nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> {
        connectionModeStream
    }

    private let script: FakeGenerationScript
    private let stateStream: AsyncStream<TunnelState>
    private let stateContinuation: AsyncStream<TunnelState>.Continuation
    private let connectionModeStream: AsyncStream<ConnectionMode?>
    private let connectionModeContinuation: AsyncStream<ConnectionMode?>.Continuation
    private var calls: [FakeConnectCall] = []
    private var endpoint: TransportEndpoint?
    private(set) var connectionMode: ConnectionMode?
    private var successfulOpenStreamCount = 0

    init(script: FakeGenerationScript) {
        self.script = script
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
    func connect(endpoints: [TransportEndpoint]) async throws -> ConnectedVia {
        try await connect(endpoints: endpoints, preferredEndpoint: nil)
    }

    @discardableResult
    func connect(endpoints: [TransportEndpoint], preferredEndpoint: TransportEndpoint?) async throws -> ConnectedVia {
        calls.append(FakeConnectCall(endpoints: endpoints, preferredEndpoint: preferredEndpoint))
        publish(.connecting(candidates: endpoints.map(\.connectedVia)))
        await script.gate?.wait()
        switch script.result {
        case .success(let endpoint):
            self.endpoint = endpoint
            setConnectionMode(endpoint.isDirect ? .plDirect : .plViaSpl)
            publish(.connected(via: endpoint.connectedVia))
            await script.connectedSignal?.signal()
            await script.returnGate?.wait()
            return endpoint.connectedVia
        case .failure(let error):
            publish(.failed(error))
            throw error
        }
    }

    func disconnect() async {
        await script.disconnectSignal?.signal()
        if let gate = script.disconnectGate {
            await gate.wait()
        }
        endpoint = nil
        setConnectionMode(nil)
        publish(.disconnected)
        stateContinuation.finish()
        connectionModeContinuation.finish()
    }

    func openStream() async throws -> MuxStream {
        if let error = script.openStreamFailure {
            publish(.failed(error))
            throw SessionError.notConnected
        }
        if let threshold = script.muxClosedAfterSuccessCount, let error = script.muxClosedError {
            if successfulOpenStreamCount >= threshold {
                throw error
            }
            successfulOpenStreamCount += 1
            return MuxStream(id: UInt32(successfulOpenStreamCount), sink: { _ in }, onTerminal: { _ in })
        }
        return MuxStream(id: 1, sink: { _ in }, onTerminal: { _ in })
    }

    func inboundActivitySnapshot() async -> UInt64 {
        0
    }

    func connectedEndpoint() async -> TransportEndpoint? {
        await script.connectedEndpointSignal?.signal()
        await script.connectedEndpointGate?.wait()
        return endpoint
    }

    func fail(_ error: SessionError) {
        endpoint = nil
        setConnectionMode(nil)
        publish(.failed(error))
    }

    func connectCalls() -> [FakeConnectCall] {
        calls
    }

    private func publish(_ state: TunnelState) {
        stateContinuation.yield(state)
    }

    private func setConnectionMode(_ mode: ConnectionMode?) {
        connectionMode = mode
        connectionModeContinuation.yield(mode)
    }
}

actor SleepProbe {
    private var count = 0
    private var durations: [Duration] = []
    private var countWaiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []
    private var sleepContinuations: [(duration: Duration, continuation: CheckedContinuation<Void, Never>)] = []

    func sleep(_ duration: Duration) async throws {
        count += 1
        durations.append(duration)
        resumeSatisfiedWaiters()
        await withCheckedContinuation { continuation in
            sleepContinuations.append((duration: duration, continuation: continuation))
        }
    }

    func waitForSleepCount(_ target: Int) async throws {
        if count >= target {
            return
        }
        await withCheckedContinuation { continuation in
            countWaiters.append((target, continuation))
        }
    }

    func observedDurations() -> [Duration] {
        durations
    }

    func observedDurations(excluding excluded: Duration) -> [Duration] {
        durations.filter { $0 != excluded }
    }

    func waitForSleepCount(excluding excluded: Duration, target: Int) async {
        await waitUntil("sleep count excluding \(excluded)") {
            await self.observedDurations(excluding: excluded).count >= target
        }
    }

    func releaseFirstSleep(duration: Duration) async {
        await waitUntil("release sleep with duration \(duration)") {
            await self.hasSleep(duration: duration)
        }
        guard let index = sleepContinuations.firstIndex(where: { $0.duration == duration }) else {
            return
        }
        let continuation = sleepContinuations.remove(at: index).continuation
        continuation.resume()
    }

    func releaseAllSleeps(duration: Duration) async {
        await waitUntil("release all sleeps with duration \(duration)") {
            await self.hasSleep(duration: duration)
        }
        let matches = sleepContinuations.filter { $0.duration == duration }
        sleepContinuations.removeAll { $0.duration == duration }
        for match in matches {
            match.continuation.resume()
        }
    }

    private func hasSleep(duration: Duration) -> Bool {
        sleepContinuations.contains(where: { $0.duration == duration })
    }

    func releaseSleeps() async {
        let continuations = sleepContinuations
        sleepContinuations.removeAll()
        for continuation in continuations {
            continuation.continuation.resume()
        }
    }

    private func resumeSatisfiedWaiters() {
        var remaining: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []
        for waiter in countWaiters {
            if count >= waiter.target {
                waiter.continuation.resume()
            } else {
                remaining.append(waiter)
            }
        }
        countWaiters = remaining
    }
}

actor ReconnectProbe {
    private var statuses: [ReconnectStatus] = []
    private var task: Task<Void, Never>?

    func start(stream: AsyncStream<ReconnectStatus>) {
        guard task == nil else {
            return
        }
        task = Task { [weak self] in
            for await status in stream {
                await self?.record(status)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    func count(_ expected: ReconnectStatus) -> Int {
        statuses.filter { $0 == expected }.count
    }

    func containsNonterminal() -> Bool {
        statuses.contains { $0.terminalPause == false }
    }

    private func record(_ status: ReconnectStatus) {
        statuses.append(status)
    }
}

func reconnectProbe(for supervisor: TunnelSupervisor) async -> ReconnectProbe {
    let probe = ReconnectProbe()
    await probe.start(stream: supervisor.reconnectUpdates)
    return probe
}

actor RetirementCommitGate {
    struct Entry: Sendable, Equatable {
        let id: UUID
        let token: UInt64
        let caller: TunnelSupervisor.RetirementCommitCaller
    }

    private enum EntryCondition {
        case count(Int)
        case caller(TunnelSupervisor.RetirementCommitCaller)
        case exact(token: UInt64, caller: TunnelSupervisor.RetirementCommitCaller)
    }

    private struct EntryWaiter {
        let condition: EntryCondition
        let continuation: CheckedContinuation<Entry?, Never>
    }

    private let holdFrom: Int
    private var entries: [Entry] = []
    private var entryWaiters: [UUID: EntryWaiter] = [:]
    private var blockedEntries: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var releasedAll = false

    init(holdFrom: Int) {
        self.holdFrom = holdFrom
    }

    func waitAtCommit(token: UInt64, caller: TunnelSupervisor.RetirementCommitCaller) async {
        let entry = Entry(id: UUID(), token: token, caller: caller)
        entries.append(entry)
        resumeEntryWaiters()
        guard entries.count >= holdFrom, !releasedAll else {
            return
        }
        await withCheckedContinuation { continuation in
            blockedEntries[entry.id] = continuation
        }
    }

    func waitForEntry(_ target: Int) async -> Bool {
        await waitForEntry(condition: .count(target)) != nil
    }

    func waitForEntry(
        token: UInt64,
        caller: TunnelSupervisor.RetirementCommitCaller
    ) async -> Entry? {
        await waitForEntry(condition: .exact(token: token, caller: caller))
    }

    func waitForEntry(caller: TunnelSupervisor.RetirementCommitCaller) async -> Entry? {
        await waitForEntry(condition: .caller(caller))
    }

    func recordedEntries() -> [Entry] {
        entries
    }

    func release(_ entry: Entry) {
        blockedEntries.removeValue(forKey: entry.id)?.resume()
    }

    func release() {
        releasedAll = true
        let blockedEntries = blockedEntries
        self.blockedEntries.removeAll()
        for (_, continuation) in blockedEntries {
            continuation.resume()
        }
    }

    private func waitForEntry(condition: EntryCondition) async -> Entry? {
        if let entry = matchingEntry(for: condition) {
            return entry
        }

        let waiterID = UUID()
        do {
            return try await withThrowingTaskGroup(of: Entry.self) { group in
                group.addTask {
                    guard let entry = await self.waitForEntrySignal(condition, waiterID: waiterID) else {
                        throw CancellationError()
                    }
                    return entry
                }
                group.addTask {
                    try await Task<Never, Never>.sleep(for: .seconds(1))
                    throw TestTimeout()
                }
                let entry = try await group.next()!
                group.cancelAll()
                return entry
            }
        } catch {
            return nil
        }
    }

    private func waitForEntrySignal(
        _ condition: EntryCondition,
        waiterID: UUID
    ) async -> Entry? {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if let entry = matchingEntry(for: condition) {
                    continuation.resume(returning: entry)
                    return
                }
                if Task.isCancelled {
                    continuation.resume(returning: nil)
                    return
                }
                entryWaiters[waiterID] = EntryWaiter(condition: condition, continuation: continuation)
            }
        } onCancel: {
            Task {
                await self.cancelEntryWaiter(waiterID)
            }
        }
    }

    private func resumeEntryWaiters() {
        let satisfiedWaiters = entryWaiters.compactMap { waiterID, waiter in
            matchingEntry(for: waiter.condition).map { (waiterID, $0) }
        }
        for (waiterID, entry) in satisfiedWaiters {
            entryWaiters.removeValue(forKey: waiterID)?.continuation.resume(returning: entry)
        }
    }

    private func cancelEntryWaiter(_ waiterID: UUID) {
        entryWaiters.removeValue(forKey: waiterID)?.continuation.resume(returning: nil)
    }

    private func matchingEntry(for condition: EntryCondition) -> Entry? {
        switch condition {
        case let .count(target):
            guard entries.count >= target else { return nil }
            return entries[target - 1]
        case let .caller(caller):
            return entries.first { $0.caller == caller }
        case let .exact(token, caller):
            return entries.first { $0.token == token && $0.caller == caller }
        }
    }
}

func fakeSupervisor(
    factory: FakeGenerationFactory,
    reconnectBackoff: ReconnectBackoff = ReconnectBackoff(schedule: .table([.milliseconds(1)]), random: { _ in 1.0 }),
    sleeper: @escaping @Sendable (Duration) async throws -> Void = { _ in },
    retirementCommitTestGate: (@Sendable (UInt64, TunnelSupervisor.RetirementCommitCaller) async -> Void)? = nil
) -> TunnelSupervisor {
    TunnelSupervisor(
        pairing: fakePairing(),
        clientInfo: supervisorTestClientInfo,
        reconnectBackoff: reconnectBackoff,
        sleeper: sleeper,
        makeSession: { _, _, _ in
            await factory.makeSession()
        },
        retirementCommitTestGate: retirementCommitTestGate
    )
}
