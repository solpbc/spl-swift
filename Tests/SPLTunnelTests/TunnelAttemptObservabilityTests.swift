// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

@Suite("Tunnel Attempt Observability", .serialized)
struct TunnelAttemptObservabilityTests {
    @Test func singleRelayReportsWaitingForBroker() async throws {
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, onAwaitingBroker in
            await onAwaitingBroker(endpoint.connectedVia)
            return tls
        }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)

        _ = try await session.connect(endpoints: [endpoint])
        let events = await collect(session.attemptUpdates)

        #expect(events.map(\.route) == [.relay, .relay, .relay, .relay])
        #expect(events.map(\.ordinal) == [0, 0, 0, 0])
        #expect(events.map(\.phase).map(phaseName) == ["started", "waiting", "ready", "selected"])
    }

    @Test func mixedRaceEmitsSanitizedCausalPerAttemptPhases() async throws {
        let direct = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "private")
        let relay = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { endpoint, _, onAwaitingBroker in
            switch endpoint {
            case .lan:
                throw SessionError.transportFailed("upstream transport fault")
            case .relay:
                await onAwaitingBroker(endpoint.connectedVia)
                return tls
            }
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: SessionPolicy(race: RacePolicy(stagger: .milliseconds(1))),
            tlsConnector: connector.connector
        )

        _ = try await session.connect(endpoints: [relay, direct])
        let events = await collect(session.attemptUpdates)
        let directEvents = events.filter { $0.ordinal == 0 }
        let relayEvents = events.filter { $0.ordinal == 1 }
        let startedOrders = events.compactMap { event -> Int? in
            if case .started = event.phase {
                return event.ordinal
            }
            return nil
        }

        #expect(startedOrders == [0, 1])
        #expect(directEvents.map(\.route) == [.directPinned, .directPinned])
        #expect(directEvents.map(\.phase).map(phaseName) == ["started", "failed.transport"])
        #expect(relayEvents.map(\.route) == [.relay, .relay, .relay, .relay])
        #expect(relayEvents.map(\.phase).map(phaseName) == ["started", "waiting", "ready", "selected"])
        #expect(events.allSatisfy { event in
            switch event.phase {
            case .failed(let failureClass, _):
                return failureClass == .transport
            default:
                return true
            }
        })
    }

    @Test func repeatedWaitingCoalescesAndAttemptStreamFinishes() async throws {
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, onAwaitingBroker in
            await onAwaitingBroker(endpoint.connectedVia)
            await onAwaitingBroker(endpoint.connectedVia)
            return tls
        }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)

        _ = try await withAttemptTimeout {
            try await session.connect(endpoints: [endpoint])
        }
        let events = await collect(session.attemptUpdates)

        #expect(events.filter {
            if case .waitingForBroker = $0.phase {
                return true
            }
            return false
        }.count == 1)
        #expect(events.count <= 4)
    }

    @Test func allFailuresPreserveAggregateAndEmitSafeTerminalFailures() async {
        let direct = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "private")
        let relay = relayEndpoint()
        let connector = ConnectorProbe { endpoint, _, _ in
            if case .relay = endpoint {
                throw DialError.relayNotEntitled
            }
            throw SessionError.unreachable
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: SessionPolicy(race: RacePolicy(stagger: .milliseconds(0))),
            tlsConnector: connector.connector
        )

        await expectSessionError(.notEntitled) {
            _ = try await session.connect(endpoints: [direct, relay])
        }
        let events = await collect(session.attemptUpdates)

        #expect(events.map(\.ordinal).sorted() == [0, 0, 1, 1])
        #expect(events.compactMap { event -> TunnelAttemptFailureClass? in
            if case .failed(let failureClass, _) = event.phase {
                return failureClass
            }
            return nil
        }.sorted { String(describing: $0) < String(describing: $1) } == [.notEntitled, .unreachable].sorted {
            String(describing: $0) < String(describing: $1)
        })
    }

    @Test func attemptEventsAreRedactedForDrivenRace() async {
        let direct = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "private")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance-secret",
            deviceToken: "token-secret"
        )
        let fault = "PEM CERTIFICATE upstream-fault"
        let connector = ConnectorProbe { endpoint, _, _ in
            if case .lan = endpoint {
                throw InnerTLSError.handshakeFailed(fault)
            }
            throw SessionError.transportFailed(fault)
        }
        let session = TunnelSession(
            pairing: StoredPairing(
                instanceID: "instance-secret",
                homeLabel: "home",
                relayEndpoint: "wss://relay.example/session",
                fingerprint: "fingerprint",
                clientCertPEM: "-----BEGIN CERTIFICATE-----",
                clientKeyPEM: "key",
                caChainPEM: "ca",
                relayEnrollment: .enrolled(deviceToken: "token-secret", expiresAt: nil),
                pairedAt: Date(timeIntervalSince1970: 0)
            ),
            policy: SessionPolicy(race: RacePolicy(stagger: .milliseconds(0))),
            tlsConnector: connector.connector
        )

        await expectSessionError(.unreachable) {
            _ = try await session.connect(endpoints: [direct, relay])
        }
        let secrets = [
            "192.168.1.10", "443", "wss://relay.example/session", "instance-secret", "token-secret",
            "-----BEGIN CERTIFICATE-----", fault,
        ]
        for event in await collect(session.attemptUpdates) {
            let storedStrings = strings(in: event)
            for secret in secrets {
                #expect(!storedStrings.contains { $0.contains(secret) })
                #expect(!String(describing: event).contains(secret))
            }
        }
    }

    @Test func transportReadyLoserClosesBeforeCancellationEvent() async throws {
        let winner = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let loser = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let loserReady = TestSignal()
        let releaseWinner = TestSignal()
        let closeLog = AttemptCloseLog()
        let stream = AsyncStream<TunnelAttemptEvent>.makeStream()
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(0),
            loserGrace: .milliseconds(20),
            budget: .seconds(1),
            close: { value in await closeLog.record(value) },
            attemptEventSink: { stream.continuation.yield($0) }
        ) { endpoint, _ in
            if endpoint == winner {
                await releaseWinner.wait()
                return 1
            }
            await loserReady.signal()
            return 2
        }

        let task = Task { try await coordinator.connect(endpoints: [winner, loser]) }
        await loserReady.wait()
        await releaseWinner.signal()
        let result = try await task.value
        stream.continuation.finish()
        let events = await collect(stream.stream)
        let loserPhases = events.filter { $0.ordinal == 1 }.map(\.phase).map(phaseName)

        #expect(result.value == 1)
        #expect(await closeLog.count(2) == 1)
        #expect(loserPhases == ["started", "ready", "cancelled"])
        #expect(!loserPhases.contains("selected"))
    }

    @Test func injectedClockControlsElapsedAndDuplicateOrdinals() async throws {
        let base = ContinuousClock.now
        let duplicate = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let stream = AsyncStream<TunnelAttemptEvent>.makeStream()
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(0),
            loserGrace: .milliseconds(1),
            budget: .seconds(1),
            close: { _ in },
            now: { base },
            attemptEventSink: { stream.continuation.yield($0) }
        ) { _, progress in
            await progress.reportWaiting()
            return 1
        }

        _ = try await coordinator.connect(endpoints: [duplicate, duplicate], preferredEndpoint: duplicate)
        stream.continuation.finish()
        let events = await collect(stream.stream)

        #expect(Set(events.map(\.ordinal)) == [0, 1])
        for phase in events.map(\.phase) {
            switch phase {
            case .started:
                break
            case .waitingForBroker(let elapsedMilliseconds), .transportReady(let elapsedMilliseconds),
                 .selected(let elapsedMilliseconds), .cancelled(let elapsedMilliseconds):
                #expect(elapsedMilliseconds == 0)
            case .failed(_, let elapsedMilliseconds):
                #expect(elapsedMilliseconds == 0)
            }
        }
    }

    @Test func cancellationDuringDialEmitsOneCancelledTerminal() async throws {
        let endpoint = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let dialStarted = TestSignal()
        let stream = AsyncStream<TunnelAttemptEvent>.makeStream()
        let coordinator = RaceCoordinator<Int>(
            stagger: .seconds(1),
            loserGrace: .seconds(1),
            budget: .seconds(5),
            close: { _ in },
            attemptEventSink: { stream.continuation.yield($0) }
        ) { _, _ in
            await dialStarted.signal()
            do {
                try await Task.sleep(for: .seconds(5))
            } catch {
                throw TunnelAttemptTestError.afterCancellation
            }
            return 1
        }

        let task = Task { try await coordinator.connect(endpoints: [endpoint]) }
        await dialStarted.wait()
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch {
        }
        stream.continuation.finish()
        let events = await collect(stream.stream)

        #expect(events.map(\.phase).map(phaseName) == ["started", "cancelled"])
    }

    @Test func cancellationDuringStaggerEmitsNoEventForUndialedCandidate() async throws {
        let first = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let staggered = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let firstStarted = TestSignal()
        let stream = AsyncStream<TunnelAttemptEvent>.makeStream()
        let coordinator = RaceCoordinator<Int>(
            stagger: .seconds(5),
            loserGrace: .seconds(1),
            budget: .seconds(10),
            close: { _ in },
            attemptEventSink: { stream.continuation.yield($0) }
        ) { endpoint, _ in
            if endpoint == first {
                await firstStarted.signal()
                try await Task.sleep(for: .seconds(5))
            }
            return 1
        }

        let task = Task { try await coordinator.connect(endpoints: [first, staggered]) }
        await firstStarted.wait()
        task.cancel()
        _ = try? await task.value
        stream.continuation.finish()
        let events = await collect(stream.stream)

        #expect(events.map(\.ordinal) == [0, 0])
        #expect(events.map(\.phase).map(phaseName) == ["started", "cancelled"])
    }

    private func collect(_ stream: AsyncStream<TunnelAttemptEvent>) async -> [TunnelAttemptEvent] {
        do {
            return try await withAttemptTimeout {
                var events: [TunnelAttemptEvent] = []
                for await event in stream {
                    events.append(event)
                }
                return events
            }
        } catch {
            Issue.record("Attempt updates stream did not finish before timeout")
            return []
        }
    }

    private func strings(in value: Any) -> [String] {
        if let string = value as? String {
            return [string]
        }
        return Mirror(reflecting: value).children.flatMap { strings(in: $0.value) }
    }

    private func phaseName(_ phase: TunnelAttemptPhase) -> String {
        switch phase {
        case .started:
            "started"
        case .waitingForBroker:
            "waiting"
        case .transportReady:
            "ready"
        case .selected:
            "selected"
        case .failed(let failureClass, _):
            "failed.\(failureClass)"
        case .cancelled:
            "cancelled"
        }
    }

    private func withAttemptTimeout<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: .seconds(1))
                throw TunnelAttemptTestError.timedOut
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    private func expectSessionError(
        _ expected: SessionError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected \(expected)")
        } catch let error as SessionError {
            #expect(error == expected)
        } catch {
            Issue.record("Expected \(expected), got \(error)")
        }
    }
}

private enum TunnelAttemptTestError: Error, Sendable {
    case timedOut
    case afterCancellation
}

private actor AttemptCloseLog {
    private var counts: [Int: Int] = [:]

    func record(_ value: Int) {
        counts[value, default: 0] += 1
    }

    func count(_ value: Int) -> Int {
        counts[value, default: 0]
    }
}
