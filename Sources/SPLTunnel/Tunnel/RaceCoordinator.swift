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
    static let none = RaceAttemptProgress(onWaiting: {})

    private let onWaiting: @Sendable () async -> Void

    init(onWaiting: @escaping @Sendable () async -> Void) {
        self.onWaiting = onWaiting
    }

    func reportWaiting() async {
        await onWaiting()
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

    init(
        stagger: Duration,
        loserGrace: Duration,
        budget: Duration,
        close: @escaping @Sendable (Value) async -> Void,
        dial: @escaping @Sendable (TransportEndpoint, RaceAttemptProgress) async throws -> Value
    ) {
        self.stagger = stagger
        self.loserGrace = loserGrace
        self.budget = budget
        self.close = close
        self.dial = dial
    }

    func connect(endpoints: [TransportEndpoint]) async throws -> RaceResult<Value> {
        guard !endpoints.isEmpty else {
            throw SessionError.unreachable
        }

        let sorted = Self.sorted(endpoints)
        raceLog.notice("dial candidates=\(Self.describe(sorted), privacy: .public)")
        guard sorted.count > 1 else {
            let endpoint = sorted[0]
            let startedAt = ContinuousClock.now
            do {
                let value = try await dial(endpoint, .none)
                raceLog.notice("candidate ok endpoint=\(endpoint.logDescription, privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
                raceLog.notice("race winner endpoint=\(endpoint.logDescription, privacy: .public)")
                return RaceResult(endpoint: endpoint, value: value)
            } catch {
                let sessionError = Self.sessionError(from: error)
                raceLog.notice("candidate failed endpoint=\(endpoint.logDescription, privacy: .public) error=\(String(describing: sessionError), privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
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

                    let startedAt = ContinuousClock.now
                    do {
                        let progress = RaceAttemptProgress {
                            await waitingTracker.markWaiting(order: order)
                        }
                        let value = try await dial(endpoint, progress)
                        raceLog.notice("candidate ok endpoint=\(endpoint.logDescription, privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
                        return .success(order: order, endpoint: endpoint, value: value)
                    } catch {
                        let sessionError = Self.sessionError(from: error)
                        raceLog.notice("candidate failed endpoint=\(endpoint.logDescription, privacy: .public) error=\(String(describing: sessionError), privacy: .public) duration_ms=\(startedAt.duration(to: .now).milliseconds, privacy: .public)")
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
            var sawRevocation = false
            var sawNotEntitled = false
            var sawAuthRefreshRequired = false

            func closeIfNeeded(order: Int, value: Value, winnerOrder: Int?) async {
                guard order != winnerOrder, closedOrders.insert(order).inserted else {
                    return
                }
                await close(value)
            }

            func cancelAndDrain(winnerOrder: Int?) async {
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
                            sawRevocation = true
                        }
                        if error == .notEntitled {
                            sawNotEntitled = true
                        }
                        if error == .authRefreshRequired {
                            sawAuthRefreshRequired = true
                        }
                        if failures == sorted.count, successes.isEmpty {
                            let aggregate = Self.aggregateFailure(
                                sawRevocation: sawRevocation,
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
                            raceLog.notice("race winner endpoint=\(winner.endpoint.logDescription, privacy: .public)")
                            return RaceResult(endpoint: winner.endpoint, value: winner.value)
                        }
                        let aggregate = Self.aggregateFailure(
                            sawRevocation: sawRevocation,
                            sawNotEntitled: sawNotEntitled,
                            sawAuthRefreshRequired: sawAuthRefreshRequired
                        )
                        await cancelAndDrain(winnerOrder: nil)
                        throw aggregate

                    case .graceExpired:
                        guard let winner = successes.min(by: { $0.order < $1.order }) else {
                            let aggregate = Self.aggregateFailure(
                                sawRevocation: sawRevocation,
                                sawNotEntitled: sawNotEntitled,
                                sawAuthRefreshRequired: sawAuthRefreshRequired
                            )
                            await cancelAndDrain(winnerOrder: nil)
                            throw aggregate
                        }
                        await cancelAndDrain(winnerOrder: winner.order)
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
                    sawRevocation: sawRevocation,
                    sawNotEntitled: sawNotEntitled,
                    sawAuthRefreshRequired: sawAuthRefreshRequired
                )
            }
            if Task.isCancelled {
                await cancelAndDrain(winnerOrder: nil)
                throw CancellationError()
            }
            await cancelAndDrain(winnerOrder: winner.order)
            raceLog.notice("race winner endpoint=\(winner.endpoint.logDescription, privacy: .public)")
            return RaceResult(endpoint: winner.endpoint, value: winner.value)
        }
    }

    static func sorted(_ endpoints: [TransportEndpoint]) -> [TransportEndpoint] {
        endpoints.enumerated()
            .sorted { lhs, rhs in
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
        if let tlsError = error as? InnerTLSError {
            return .tlsFailed(String(describing: tlsError))
        }
        return .unreachable
    }

    static func aggregateFailure(
        sawRevocation: Bool,
        sawNotEntitled: Bool,
        sawAuthRefreshRequired: Bool
    ) -> SessionError {
        if sawRevocation {
            return .revoked
        }
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
