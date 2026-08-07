// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import os

private let raceLog = SPLLogging.logger(for: .race)

struct RaceResult<Value: Sendable>: Sendable {
    let endpoint: TransportEndpoint
    let value: Value
}

struct RaceAttemptProgress: Sendable {
    private let onWaiting: @Sendable () async -> Void

    init(onWaiting: @escaping @Sendable () async -> Void) {
        self.onWaiting = onWaiting
    }

    func reportWaiting() async {
        await onWaiting()
    }
}

private actor RaceAttemptEmitter {
    private let routes: [Int: TunnelAttemptRoute]
    private let now: @Sendable () -> ContinuousClock.Instant
    private let sink: @Sendable (TunnelAttemptEvent) -> Void
    private var starts: [Int: ContinuousClock.Instant] = [:]
    private var waitingEmitted = Set<Int>()
    private var terminalEmitted = Set<Int>()
    private var cancellationObserved = Set<Int>()

    init(
        routes: [TunnelAttemptRoute],
        now: @escaping @Sendable () -> ContinuousClock.Instant,
        sink: @escaping @Sendable (TunnelAttemptEvent) -> Void
    ) {
        self.routes = Dictionary(uniqueKeysWithValues: routes.enumerated().map { ($0.offset, $0.element) })
        self.now = now
        self.sink = sink
    }

    func started(order: Int) {
        guard starts[order] == nil, !cancellationObserved.contains(order), let route = routes[order] else {
            return
        }
        starts[order] = now()
        sink(TunnelAttemptEvent(route: route, ordinal: order, phase: .started))
    }

    func waiting(order: Int) {
        guard starts[order] != nil, !terminalEmitted.contains(order), waitingEmitted.insert(order).inserted else {
            return
        }
        emit(order: order, phase: .waitingForBroker(elapsedMilliseconds: elapsedMilliseconds(order: order)))
    }

    func transportReady(order: Int) {
        guard !terminalEmitted.contains(order), !cancellationObserved.contains(order) else {
            return
        }
        emit(order: order, phase: .transportReady(elapsedMilliseconds: elapsedMilliseconds(order: order)))
    }

    func failed(order: Int, failureClass: TunnelAttemptFailureClass) {
        emitTerminal(order: order, phase: .failed(failureClass, elapsedMilliseconds: elapsedMilliseconds(order: order)))
    }

    func selected(order: Int) {
        emitTerminal(order: order, phase: .selected(elapsedMilliseconds: elapsedMilliseconds(order: order)))
    }

    func cancelled(order: Int) {
        emitTerminal(order: order, phase: .cancelled(elapsedMilliseconds: elapsedMilliseconds(order: order)))
    }

    func observeCancellation(excluding winnerOrder: Int? = nil) {
        for order in routes.keys where order != winnerOrder && !terminalEmitted.contains(order) {
            cancellationObserved.insert(order)
        }
    }

    func observeCancellation(order: Int) {
        guard !terminalEmitted.contains(order) else {
            return
        }
        cancellationObserved.insert(order)
    }

    func isCancellationObserved(order: Int) -> Bool {
        cancellationObserved.contains(order)
    }

    private func emitTerminal(order: Int, phase: TunnelAttemptPhase) {
        guard terminalEmitted.insert(order).inserted else {
            return
        }
        emit(order: order, phase: phase)
    }

    private func emit(order: Int, phase: TunnelAttemptPhase) {
        guard starts[order] != nil, let route = routes[order] else {
            return
        }
        sink(TunnelAttemptEvent(route: route, ordinal: order, phase: phase))
    }

    private func elapsedMilliseconds(order: Int) -> Int {
        guard let startedAt = starts[order] else {
            return 0
        }
        return startedAt.duration(to: now()).milliseconds
    }
}

private actor RaceWaitingTracker {
    private var waitingOrders = Set<Int>()

    var hasWaiting: Bool {
        !waitingOrders.isEmpty
    }

    func markWaiting(order: Int) {
        waitingOrders.insert(order)
    }

    func clearWaiting(order: Int) {
        waitingOrders.remove(order)
    }
}

struct RaceCoordinator<Value: Sendable>: Sendable {
    private enum Event: Sendable {
        case success(order: Int, endpoint: TransportEndpoint, value: Value)
        case failure(order: Int, error: SessionError)
        case budgetExpired
        case graceExpired
    }

    private let stagger: Duration
    private let loserGrace: Duration
    private let budget: Duration
    private let close: @Sendable (Value) async -> Void
    private let dial: @Sendable (TransportEndpoint, RaceAttemptProgress) async throws -> Value
    private let now: @Sendable () -> ContinuousClock.Instant
    private let attemptEventSink: @Sendable (TunnelAttemptEvent) -> Void

    init(
        stagger: Duration,
        loserGrace: Duration,
        budget: Duration,
        close: @escaping @Sendable (Value) async -> Void,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        attemptEventSink: @escaping @Sendable (TunnelAttemptEvent) -> Void = { _ in },
        dial: @escaping @Sendable (TransportEndpoint, RaceAttemptProgress) async throws -> Value
    ) {
        self.stagger = stagger
        self.loserGrace = loserGrace
        self.budget = budget
        self.close = close
        self.dial = dial
        self.now = now
        self.attemptEventSink = attemptEventSink
    }

    func connect(
        endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint? = nil
    ) async throws -> RaceResult<Value> {
        guard !endpoints.isEmpty else {
            throw SessionError.unreachable
        }

        let sorted = Self.sorted(endpoints, preferredEndpoint: preferredEndpoint)
        raceLog.notice("dial candidates=\(Self.describe(sorted), privacy: .public)")
        let attempts = RaceAttemptEmitter(
            routes: sorted.map(Self.attemptRoute),
            now: now,
            sink: attemptEventSink
        )
        guard sorted.count > 1 else {
            let endpoint = sorted[0]
            let startedAt = now()
            await attempts.started(order: 0)
            do {
                let progress = RaceAttemptProgress {
                    await attempts.waiting(order: 0)
                }
                let value = try await dial(endpoint, progress)
                await attempts.transportReady(order: 0)
                await attempts.selected(order: 0)
                raceLog.notice("candidate ok endpoint=\(endpoint.logDescription, privacy: .public) duration_ms=\(startedAt.duration(to: now()).milliseconds, privacy: .public)")
                raceLog.notice("race winner endpoint=\(endpoint.logDescription, privacy: .public)")
                return RaceResult(endpoint: endpoint, value: value)
            } catch {
                let sessionError = Self.sessionError(from: error)
                if Task.isCancelled {
                    await attempts.observeCancellation(order: 0)
                    await attempts.cancelled(order: 0)
                } else {
                    await attempts.failed(order: 0, failureClass: Self.attemptFailureClass(for: sessionError))
                }
                raceLog.notice("candidate failed endpoint=\(endpoint.logDescription, privacy: .public) error=\(String(describing: sessionError), privacy: .public) duration_ms=\(startedAt.duration(to: now()).milliseconds, privacy: .public)")
                throw sessionError
            }
        }

        let waitingTracker = RaceWaitingTracker()
        return try await withThrowingTaskGroup(of: Event.self, returning: RaceResult<Value>.self) { group in
            for (order, endpoint) in sorted.enumerated() {
                group.addTask {
                    if order > 0 {
                        do {
                            try await Task.sleep(for: stagger * order)
                        } catch {
                            return .failure(order: order, error: .unreachable)
                        }
                    }

                    await attempts.started(order: order)
                    let startedAt = now()
                    do {
                        let progress = RaceAttemptProgress {
                            await waitingTracker.markWaiting(order: order)
                            await attempts.waiting(order: order)
                        }
                        let value = try await dial(endpoint, progress)
                        await attempts.transportReady(order: order)
                        raceLog.notice("candidate ok endpoint=\(endpoint.logDescription, privacy: .public) duration_ms=\(startedAt.duration(to: now()).milliseconds, privacy: .public)")
                        return .success(order: order, endpoint: endpoint, value: value)
                    } catch {
                        let sessionError = Self.sessionError(from: error)
                        if await attempts.isCancellationObserved(order: order) || Task.isCancelled {
                            await attempts.observeCancellation(order: order)
                            await attempts.cancelled(order: order)
                        } else {
                            await attempts.failed(order: order, failureClass: Self.attemptFailureClass(for: sessionError))
                        }
                        raceLog.notice("candidate failed endpoint=\(endpoint.logDescription, privacy: .public) error=\(String(describing: sessionError), privacy: .public) duration_ms=\(startedAt.duration(to: now()).milliseconds, privacy: .public)")
                        return .failure(order: order, error: sessionError)
                    }
                }
            }

            group.addTask {
                do {
                    try await Task.sleep(for: budget)
                } catch {
                    return .budgetExpired
                }
                return .budgetExpired
            }

            var failures = 0
            var successes: [(order: Int, endpoint: TransportEndpoint, value: Value)] = []
            var closedOrders = Set<Int>()
            var graceStarted = false
            var sawNotEntitled = false
            var sawAuthRefreshRequired = false

            func closeIfNeeded(order: Int, value: Value, winnerOrder: Int?) async {
                guard order != winnerOrder, closedOrders.insert(order).inserted else {
                    return
                }
                await close(value)
                if await attempts.isCancellationObserved(order: order) {
                    await attempts.cancelled(order: order)
                }
            }

            func cancelAndDrain(winnerOrder: Int?) async {
                await attempts.observeCancellation(excluding: winnerOrder)
                group.cancelAll()
                for success in successes {
                    await closeIfNeeded(order: success.order, value: success.value, winnerOrder: winnerOrder)
                }
                while let event = try? await group.next() {
                    if case .success(let order, _, let value) = event {
                        await closeIfNeeded(order: order, value: value, winnerOrder: winnerOrder)
                    }
                }
            }

            do {
                while let event = try await group.next() {
                    if Task.isCancelled {
                        await attempts.observeCancellation()
                        if case .success(let order, _, let value) = event {
                            await closeIfNeeded(order: order, value: value, winnerOrder: nil)
                        }
                        await cancelAndDrain(winnerOrder: nil)
                        throw CancellationError()
                    }

                    switch event {
                    case .success(let order, let endpoint, let value):
                        await waitingTracker.clearWaiting(order: order)
                        successes.append((order, endpoint, value))
                        if !graceStarted {
                            graceStarted = true
                            group.addTask {
                                do {
                                    try await Task.sleep(for: loserGrace)
                                } catch {
                                    return .graceExpired
                                }
                                return .graceExpired
                            }
                        }

                    case .failure(let order, let error):
                        await waitingTracker.clearWaiting(order: order)
                        failures += 1
                        if error == .revoked {
                            await cancelAndDrain(winnerOrder: nil)
                            throw SessionError.revoked
                        }
                        if error == .notEntitled {
                            sawNotEntitled = true
                        }
                        if error == .authRefreshRequired {
                            sawAuthRefreshRequired = true
                        }
                        if failures == sorted.count, successes.isEmpty {
                            let aggregate = Self.aggregateFailure(
                                sawNotEntitled: sawNotEntitled,
                                sawAuthRefreshRequired: sawAuthRefreshRequired
                            )
                            group.cancelAll()
                            throw aggregate
                        }

                    case .budgetExpired:
                        if await waitingTracker.hasWaiting {
                            continue
                        }
                        if let winner = successes.min(by: { $0.order < $1.order }) {
                            await cancelAndDrain(winnerOrder: winner.order)
                            await attempts.selected(order: winner.order)
                            raceLog.notice("race winner endpoint=\(winner.endpoint.logDescription, privacy: .public)")
                            return RaceResult(endpoint: winner.endpoint, value: winner.value)
                        }
                        let aggregate = Self.aggregateFailure(
                            sawNotEntitled: sawNotEntitled,
                            sawAuthRefreshRequired: sawAuthRefreshRequired
                        )
                        await cancelAndDrain(winnerOrder: nil)
                        throw aggregate

                    case .graceExpired:
                        guard let winner = successes.min(by: { $0.order < $1.order }) else {
                            let aggregate = Self.aggregateFailure(
                                sawNotEntitled: sawNotEntitled,
                                sawAuthRefreshRequired: sawAuthRefreshRequired
                            )
                            await cancelAndDrain(winnerOrder: nil)
                            throw aggregate
                        }
                        await cancelAndDrain(winnerOrder: winner.order)
                        await attempts.selected(order: winner.order)
                        raceLog.notice("race winner endpoint=\(winner.endpoint.logDescription, privacy: .public)")
                        return RaceResult(endpoint: winner.endpoint, value: winner.value)
                    }
                }
            } catch is CancellationError {
                await cancelAndDrain(winnerOrder: nil)
                throw CancellationError()
            }

            guard let winner = successes.min(by: { $0.order < $1.order }) else {
                throw Self.aggregateFailure(
                    sawNotEntitled: sawNotEntitled,
                    sawAuthRefreshRequired: sawAuthRefreshRequired
                )
            }
            if Task.isCancelled {
                await cancelAndDrain(winnerOrder: nil)
                throw CancellationError()
            }
            await cancelAndDrain(winnerOrder: winner.order)
            await attempts.selected(order: winner.order)
            raceLog.notice("race winner endpoint=\(winner.endpoint.logDescription, privacy: .public)")
            return RaceResult(endpoint: winner.endpoint, value: winner.value)
        }
    }

    static func sorted(
        _ endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint? = nil
    ) -> [TransportEndpoint] {
        endpoints.enumerated()
            .sorted { lhs, rhs in
                let leftPreferred = lhs.element == preferredEndpoint ? 0 : 1
                let rightPreferred = rhs.element == preferredEndpoint ? 0 : 1
                if leftPreferred != rightPreferred {
                    return leftPreferred < rightPreferred
                }
                let leftRank = rank(lhs.element)
                let rightRank = rank(rhs.element)
                if leftRank == rightRank {
                    return lhs.offset < rhs.offset
                }
                return leftRank < rightRank
            }
            .map(\.element)
    }

    private static func rank(_ endpoint: TransportEndpoint) -> Int {
        switch endpoint {
        case .lan(let host, _, _, _):
            if TunnelAddressClassifier.isRFC1918IPv4Literal(host), !endpoint.unpinnedInterface {
                return 0
            }
            if TunnelAddressClassifier.isIPv6ULA(host) {
                return 1
            }
            if TunnelAddressClassifier.isRFC1918IPv4Literal(host), endpoint.unpinnedInterface {
                return 3
            }
            return 2
        case .relay:
            return 4
        }
    }

    private static func describe(_ endpoints: [TransportEndpoint]) -> String {
        endpoints.map(\.logDescription).joined(separator: ", ")
    }

    private static func attemptRoute(_ endpoint: TransportEndpoint) -> TunnelAttemptRoute {
        switch endpoint {
        case .lan(_, _, _, let unpinnedInterface):
            return unpinnedInterface ? .directUnpinned : .directPinned
        case .relay:
            return .relay
        }
    }

    private static func attemptFailureClass(for error: SessionError) -> TunnelAttemptFailureClass {
        switch error {
        case .unreachable:
            .unreachable
        case .tlsFailed:
            .tls
        case .authRefreshRequired:
            .authRefreshRequired
        case .notEntitled:
            .notEntitled
        case .revoked:
            .revoked
        case .transportFailed, .inboundClosed, .directKeepaliveMissed, .relayKeepaliveMissed:
            .transport
        case .notConnected:
            .other
        }
    }

    static func sessionError(from error: any Error) -> SessionError {
        if let sessionError = error as? SessionError {
            return sessionError
        }
        if let dialError = error as? DialError,
           dialError == .relayUnauthorized || dialError == .relayCloseUnauthorized {
            return .authRefreshRequired
        }
        if let dialError = error as? DialError,
           dialError == .relayNotEntitled {
            return .notEntitled
        }
        if isPeerAccessDenied(error) {
            return .revoked
        }
        if let tlsError = error as? InnerTLSError {
            return .tlsFailed(String(describing: tlsError))
        }
        return .unreachable
    }

    static func aggregateFailure(
        sawNotEntitled: Bool,
        sawAuthRefreshRequired: Bool
    ) -> SessionError {
        if sawNotEntitled {
            return .notEntitled
        }
        if sawAuthRefreshRequired {
            return .authRefreshRequired
        }
        return .unreachable
    }
}

private func * (duration: Duration, multiplier: Int) -> Duration {
    let components = duration.components
    let milliseconds = Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    return .milliseconds(milliseconds * multiplier)
}

private extension Duration {
    var milliseconds: Int {
        let components = self.components
        return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
    }
}
