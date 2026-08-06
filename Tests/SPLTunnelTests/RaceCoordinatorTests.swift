// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Testing
@testable import SPLTunnel

private struct RaceTestError: Error, Sendable {}
private struct RaceTestTimeout: Error, Sendable {}

@Suite("RaceCoordinator", .serialized)
struct RaceCoordinatorTests {
    @Test func sortsRFC1918ThenULAThenOtherDirectThenRelay() {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let endpoints: [TransportEndpoint] = [
            relay,
            .lan(host: "203.0.113.10", port: 443, scope: "public"),
            .lan(host: "192.168.1.10", port: 443, scope: "local"),
            .lan(host: "fd12:3456::1", port: 443, scope: "ula"),
        ]

        #expect(RaceCoordinator<Int>.sorted(endpoints) == [
            .lan(host: "192.168.1.10", port: 443, scope: "local"),
            .lan(host: "fd12:3456::1", port: 443, scope: "ula"),
            .lan(host: "203.0.113.10", port: 443, scope: "public"),
            relay,
        ])
    }

    @Test func preferredEndpointSortsBeforeRankAndPreservesRankForOthers() {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let rankedFirst = TransportEndpoint.lan(host: "10.0.0.8", port: 443, scope: "ranked")
        let ula = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let publicDirect = TransportEndpoint.lan(host: "203.0.113.10", port: 443, scope: "public")
        let preferred = TransportEndpoint.lan(
            host: "192.168.1.20",
            port: 443,
            scope: "trusted",
            unpinnedInterface: true
        )
        let endpoints = [relay, publicDirect, preferred, rankedFirst, ula]

        #expect(RaceCoordinator<Int>.sorted(endpoints, preferredEndpoint: preferred) == [
            preferred,
            rankedFirst,
            ula,
            publicDirect,
            relay,
        ])
        #expect(RaceCoordinator<Int>.sorted(endpoints, preferredEndpoint: nil) == [
            rankedFirst,
            ula,
            publicDirect,
            preferred,
            relay,
        ])
    }

    @Test func rfc1918WinsOverULAWithStaggerAndSimilarHandshakeTime() async throws {
        let ula = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let rfc1918 = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let coordinator = RaceCoordinator<TransportEndpoint>(
            stagger: .milliseconds(20),
            loserGrace: .milliseconds(10),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            try await Task.sleep(for: .milliseconds(15))
            return endpoint
        }

        let result = try await coordinator.connect(endpoints: [rfc1918, ula])

        #expect(result.endpoint == rfc1918)
        #expect(result.value == rfc1918)
    }

    @Test func rfc1918ClassifierCoversIPv4LiteralEdgeCasesOnly() {
        let cases: [(host: String, expected: Bool)] = [
            ("172.15.255.255", false),
            ("172.32.0.1", false),
            ("172.16.0.1", true),
            ("10.2.3.4", true),
            ("192.168.4.20", true),
            ("127.0.0.1", false),
            ("100.64.0.1", false),
            ("fd12:3456::1", false),
            ("home.local", false),
        ]

        for testCase in cases {
            #expect(TunnelAddressClassifier.isRFC1918IPv4Literal(testCase.host) == testCase.expected)
        }
    }

    @Test func candidatesAddUnpinnedRFC1918DuplicateAsLastResortBeforeRelay() {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let pinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let ula = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let unpinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true)
        let pairing = racePairing(
            relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
            localEndpoints: [
                LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
                LocalEndpoint(host: "fd12:3456::1", port: 443, scope: "ula"),
            ]
        )

        let candidates = TransportEndpoint.candidates(for: pairing)

        #expect(candidates.contains(pinned))
        #expect(candidates.contains(unpinned))
        #expect(!candidates.contains(.lan(host: "fd12:3456::1", port: 443, scope: "ula", unpinnedInterface: true)))
        #expect(RaceCoordinator<Int>.sorted(candidates) == [pinned, ula, unpinned, relay])
    }

    @Test func directOnlyRFC1918CandidateKeepsUnpinnedFallbackPath() {
        let pinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let unpinned = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true)
        let pairing = racePairing(
            relayEnrollment: .unavailable,
            localEndpoints: [
                LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
            ]
        )

        #expect(RaceCoordinator<Int>.sorted(TransportEndpoint.candidates(for: pairing)) == [pinned, unpinned])
    }

    @Test func candidatesKeepDirectWhenRelayMetadataIsAbsentBlankOrMalformed() {
        // candidates(for:) remains non-throwing and direct-preserving when relay metadata is absent or invalid.
        let localEndpoints = [
            LocalEndpoint(host: "192.168.1.10", port: 443, scope: "local"),
            LocalEndpoint(host: "fd12:3456::1", port: 443, scope: "ula"),
        ]
        let expectedDirect = [
            TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local"),
            TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local", unpinnedInterface: true),
            TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula"),
        ]
        let variants: [StoredPairing] = [
            racePairing(relayEnrollment: .unavailable, localEndpoints: localEndpoints),
            racePairing(
                relayEnrollment: .enrolled(deviceToken: "   ", expiresAt: nil),
                localEndpoints: localEndpoints
            ),
            racePairing(
                relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
                localEndpoints: localEndpoints,
                relayEndpoint: "://not-a-url"
            ),
            racePairing(
                relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
                localEndpoints: localEndpoints,
                relayEndpoint: ""
            ),
        ]

        for pairing in variants {
            #expect(TransportEndpoint.candidates(for: pairing) == expectedDirect)
        }
    }

    @Test func loserGraceLetsSlowerBetterCandidateWin() async throws {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<TransportEndpoint>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(50),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            switch endpoint {
            case .lan:
                try await Task.sleep(for: .milliseconds(30))
            case .relay:
                try await Task.sleep(for: .milliseconds(1))
            }
            return endpoint
        }

        let result = try await coordinator.connect(endpoints: [relay, direct])

        #expect(result.endpoint == direct)
    }

    @Test func loserDiscardedExactlyOnce() async throws {
        let winner = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let loser = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(50),
            budget: .seconds(2),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == winner {
                return DiscardValue(id: 1)
            }
            return DiscardValue(id: 2)
        }

        let result = try await coordinator.connect(endpoints: [loser, winner])

        #expect(result.endpoint == winner)
        #expect(result.value.id == 1)
        #expect(await log.count(1) == 0)
        #expect(await log.count(2) == 1)
    }

    @Test func lateSuccessDiscardedExactlyOnce() async throws {
        let winner = TransportEndpoint.lan(host: "fd12:3456::1", port: 443, scope: "ula")
        let loser = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(20),
            budget: .seconds(2),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == winner {
                return DiscardValue(id: 1)
            }
            do {
                try await Task.sleep(for: .seconds(1))
            } catch {
            }
            return DiscardValue(id: 2)
        }

        let result = try await coordinator.connect(endpoints: [loser, winner])

        #expect(result.endpoint == winner)
        #expect(result.value.id == 1)
        try await waitForCloseCount(1, id: 2, log: log)
        #expect(await log.count(1) == 0)
        #expect(await log.count(2) == 1)
    }

    @Test func budgetAbortThrowsUnreachable() async {
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(20),
            close: { _ in }
        ) { _, _ in
            try await Task.sleep(for: .seconds(1))
            return 1
        }

        await expectSessionError(.unreachable) {
            _ = try await coordinator.connect(endpoints: [
                .lan(host: "10.0.0.5", port: 443, scope: "local"),
                .lan(host: "192.168.1.10", port: 443, scope: "local"),
            ])
        }
    }

    @Test func singleElementBypassesRaceStagger() async throws {
        let endpoint = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let startedAt = ContinuousClock.now
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(500),
            loserGrace: .milliseconds(500),
            budget: .seconds(1),
            close: { _ in }
        ) { _, _ in 42 }

        let result = try await coordinator.connect(endpoints: [endpoint])
        let elapsed = startedAt.duration(to: .now)

        #expect(result.endpoint == endpoint)
        #expect(result.value == 42)
        #expect(elapsed < .milliseconds(100))
    }

    @Test func allFailuresThrowUnreachable() async {
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { _, _ in
            throw RaceTestError()
        }

        await expectSessionError(.unreachable) {
            _ = try await coordinator.connect(endpoints: [
                .lan(host: "10.0.0.5", port: 443, scope: "local"),
                .lan(host: "192.168.1.10", port: 443, scope: "local"),
            ])
        }
    }

    @Test func singleRelayUnauthorizedThrowsAuthRefreshRequired() async {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { _, _ in
            throw DialError.relayUnauthorized
        }

        await expectSessionError(.authRefreshRequired) {
            _ = try await coordinator.connect(endpoints: [relay])
        }
    }

    @Test func relayNotEntitledMapsToNotEntitled() async {
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { _, _ in
            throw DialError.relayNotEntitled
        }

        await expectSessionError(.notEntitled) {
            _ = try await coordinator.connect(endpoints: [relay])
        }
    }

    @Test func relayUnauthorizedWinsAllFailSurfaceAsAuthRefreshRequired() async {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            if case .relay = endpoint {
                throw DialError.relayUnauthorized
            }
            throw RaceTestError()
        }

        await expectSessionError(.authRefreshRequired) {
            _ = try await coordinator.connect(endpoints: [direct, relay])
        }
    }

    @Test func notEntitledWinsOverUnreachableInAggregate() async {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            if case .relay = endpoint {
                throw DialError.relayNotEntitled
            }
            throw RaceTestError()
        }

        await expectSessionError(.notEntitled) {
            _ = try await coordinator.connect(endpoints: [direct, relay])
        }
    }

    @Test func revokedWinsOverNotEntitled() async {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            if case .relay = endpoint {
                throw DialError.relayNotEntitled
            }
            throw SessionError.revoked
        }

        await expectSessionError(.revoked) {
            _ = try await coordinator.connect(endpoints: [direct, relay])
        }
    }

    @Test(arguments: [false, true])
    func peerAccessDeniedShortCircuitDrainsCollectedSuccesses(terminalIsRelay: Bool) async {
        // Security/SecBase.h: access denied terminates the race and closes an already-ready competitor.
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let terminal = terminalIsRelay ? relay : direct
        let successful = terminalIsRelay ? direct : relay
        let successReady = TestSignal()
        let releaseTerminal = TestSignal()
        let closeLog = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(0),
            loserGrace: .seconds(1),
            budget: .seconds(1),
            close: { value in await closeLog.record(value.id) }
        ) { endpoint, _ in
            if endpoint == terminal {
                await releaseTerminal.wait()
                throw NWError.tls(-9832)
            }
            await successReady.signal()
            return DiscardValue(id: endpoint == direct ? 1 : 2)
        }

        let task = Task {
            try await coordinator.connect(endpoints: [direct, relay])
        }
        await successReady.wait()
        await releaseTerminal.signal()
        await expectSessionError(.revoked) {
            _ = try await task.value
        }
        #expect(await closeLog.count(successful == direct ? 1 : 2) == 1)
    }

    @Test func relayCloseUnauthorizedWinsAllFailSurfaceAsAuthRefreshRequired() async {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example/session")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { endpoint, _ in
            if case .relay = endpoint {
                throw DialError.relayCloseUnauthorized
            }
            throw RaceTestError()
        }

        await expectSessionError(.authRefreshRequired) {
            _ = try await coordinator.connect(endpoints: [direct, relay])
        }
    }

    @Test func tlsPinningMismatchStaysTLSFailureForSingleCandidate() async {
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(200),
            close: { _ in }
        ) { _, _ in
            throw InnerTLSError.peerNotPinned
        }

        do {
            _ = try await coordinator.connect(endpoints: [direct])
            Issue.record("Expected tls failure")
        } catch let error as SessionError {
            if case .tlsFailed(let reason) = error {
                #expect(reason.contains("peerNotPinned"))
            } else {
                Issue.record("Expected tlsFailed, got \(error)")
            }
        } catch {
            Issue.record("Expected SessionError.tlsFailed, got \(error)")
        }
    }

    @Test func graceExpiredClosesCollectedAndPendingLosersExactlyOnce() async throws {
        let closeLog = CloseLog()
        let relay = URL(string: "wss://relay.example.com")!
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(30),
            budget: .seconds(1),
            close: { value in await closeLog.record(value.id) }
        ) { endpoint, _ in
            switch endpoint {
            case .lan(let host, _, _, _):
                if host == "10.0.0.2" {
                    return DiscardValue(id: 0)
                }
                try await Task.sleep(for: .milliseconds(5))
                return DiscardValue(id: 1)
            case .relay:
                do {
                    try await Task.sleep(for: .milliseconds(200))
                } catch {
                }
                return DiscardValue(id: 2)
            }
        }

        let result = try await coordinator.connect(endpoints: [
            .lan(host: "fd00::1", port: 1234, scope: ""),
            .lan(host: "10.0.0.2", port: 1234, scope: ""),
            .relay(endpoint: relay, instanceID: "instance", deviceToken: "token"),
        ])

        #expect(result.value.id == 0)
        let counts = await closeLog.counts()
        #expect(counts[0] == nil)
        #expect(counts[1] == 1)
        #expect(counts[2] == 1)
    }

    @Test func relayCloseUnauthorizedSurvivesFailedRaceAggregation() async {
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(50),
            close: { _ in }
        ) { endpoint, _ in
            if case .relay = endpoint {
                throw DialError.relayCloseUnauthorized
            }
            throw SessionError.unreachable
        }

        await expectSessionError(.authRefreshRequired) {
            _ = try await coordinator.connect(endpoints: [
                .lan(host: "127.0.0.1", port: 1234, scope: ""),
                .relay(endpoint: URL(string: "wss://relay.example.com")!, instanceID: "instance", deviceToken: "token"),
            ])
        }
    }

    @Test func budgetDoesNotAbortAfterRelayReportsWaiting() async throws {
        let relay = URL(string: "wss://relay.example.com")!
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(30),
            close: { _ in }
        ) { endpoint, progress in
            switch endpoint {
            case .lan:
                throw SessionError.unreachable
            case .relay:
                await progress.reportWaiting()
                try await Task.sleep(for: .milliseconds(80))
                return 42
            }
        }

        let result = try await coordinator.connect(endpoints: [
            .lan(host: "127.0.0.1", port: 1234, scope: ""),
            .relay(endpoint: relay, instanceID: "instance", deviceToken: "token"),
        ])

        #expect(result.value == 42)
        #expect(result.endpoint == .relay(endpoint: relay, instanceID: "instance", deviceToken: "token"))
    }

    @Test func waitingCandidateFailureStillAggregatesWhenAllCandidatesFail() async {
        let coordinator = RaceCoordinator<Int>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .seconds(1),
            close: { _ in }
        ) { endpoint, progress in
            switch endpoint {
            case .lan:
                throw SessionError.unreachable
            case .relay:
                await progress.reportWaiting()
                throw RaceTestError()
            }
        }

        await expectSessionError(.unreachable) {
            _ = try await coordinator.connect(endpoints: [
                .lan(host: "127.0.0.1", port: 1234, scope: ""),
                .relay(endpoint: URL(string: "wss://relay.example.com")!, instanceID: "instance", deviceToken: "token"),
            ])
        }
    }

    @Test func budgetExpiryClosesCollectedAndLateSuccessesExactlyOnce() async throws {
        // Race budget expiry must close and drain collected values exactly once.
        let winner = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let loser = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .seconds(5),
            budget: .milliseconds(30),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == winner {
                return DiscardValue(id: 1)
            }
            do {
                try await Task.sleep(for: .seconds(5))
            } catch {
            }
            return DiscardValue(id: 2)
        }

        let result = try await withTestTimeout(.milliseconds(500)) {
            try await coordinator.connect(endpoints: [winner, loser])
        }

        #expect(result.value.id == 1)
        try await waitForCloseCount(1, id: 2, log: log)
        #expect(await log.count(1) == 0)
    }

    @Test func budgetWithoutWinnerDrainsLateSuccessExactlyOnce() async throws {
        // Budget exhaustion must drain a late success exactly once.
        let pending = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let failing = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .milliseconds(30),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == pending {
                do {
                    try await Task.sleep(for: .seconds(5))
                } catch {
                }
                return DiscardValue(id: 1)
            }
            throw RaceTestError()
        }

        await expectSessionError(.unreachable) {
            _ = try await coordinator.connect(endpoints: [pending, failing])
        }
        try await waitForCloseCount(1, id: 1, log: log)
    }

    @Test func allFailAggregatesNotEntitledAndClosesNothing() async {
        // All-fail aggregation must not close values that were never collected.
        let direct = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let relay = TransportEndpoint.relay(
            endpoint: URL(string: "wss://relay.example.com")!,
            instanceID: "instance",
            deviceToken: "token"
        )
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .milliseconds(1),
            budget: .seconds(1),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == relay {
                throw DialError.relayNotEntitled
            }
            throw RaceTestError()
        }

        await expectSessionError(.notEntitled) {
            _ = try await coordinator.connect(endpoints: [direct, relay])
        }
        #expect(await log.counts().isEmpty)
    }

    @Test func taskCancellationDrainsLateSuccessesExactlyOnce() async throws {
        // Task cancellation must drain late successes exactly once.
        let firstSuccess = Signal()
        let loserStarted = Signal()
        let winner = TransportEndpoint.lan(host: "10.0.0.5", port: 443, scope: "local")
        let loser = TransportEndpoint.lan(host: "192.168.1.10", port: 443, scope: "local")
        let log = CloseLog()
        let coordinator = RaceCoordinator<DiscardValue>(
            stagger: .milliseconds(1),
            loserGrace: .seconds(5),
            budget: .seconds(5),
            close: { value in await log.record(value.id) }
        ) { endpoint, _ in
            if endpoint == winner {
                await firstSuccess.signal()
                return DiscardValue(id: 1)
            }
            await loserStarted.signal()
            do {
                try await Task.sleep(for: .seconds(5))
            } catch {
            }
            return DiscardValue(id: 2)
        }

        let task = Task {
            try await coordinator.connect(endpoints: [winner, loser])
        }
        await firstSuccess.wait()
        await loserStarted.wait()
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch is CancellationError {
        } catch {
            Issue.record("Expected cancellation, got \(error)")
        }

        try await waitForCloseCount(1, id: 1, log: log)
        try await waitForCloseCount(1, id: 2, log: log)
    }

    private func expectSessionError(
        _ expected: SessionError,
        _ operation: () async throws -> Void
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

    private func racePairing(
        relayEnrollment: RelayEnrollment,
        localEndpoints: [LocalEndpoint],
        relayEndpoint: String = "wss://relay.example/session"
    ) -> StoredPairing {
        StoredPairing(
            instanceID: "instance",
            homeLabel: "home",
            relayEndpoint: relayEndpoint,
            fingerprint: "fingerprint",
            clientCertPEM: "cert",
            clientKeyPEM: "key",
            caChainPEM: "ca",
            relayEnrollment: relayEnrollment,
            localEndpoints: localEndpoints,
            pairedAt: Date()
        )
    }
}

private struct DiscardValue: Sendable, Equatable {
    let id: Int
}

private actor CloseLog {
    private var closeCounts: [Int: Int] = [:]

    func record(_ id: Int) {
        closeCounts[id, default: 0] += 1
    }

    func count(_ id: Int) -> Int {
        closeCounts[id, default: 0]
    }

    func counts() -> [Int: Int] {
        closeCounts
    }
}

private actor Signal {
    private var isSignaled = false
    private var continuations: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isSignaled {
            return
        }
        await withCheckedContinuation { continuation in
            if isSignaled {
                continuation.resume()
            } else {
                continuations.append(continuation)
            }
        }
    }

    func signal() {
        guard !isSignaled else {
            return
        }
        isSignaled = true
        let pending = continuations
        continuations.removeAll()
        for continuation in pending {
            continuation.resume()
        }
    }
}

private func waitForCloseCount(_ expected: Int, id: Int, log: CloseLog) async throws {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
        if await log.count(id) == expected {
            return
        }
        try await Task.sleep(for: .milliseconds(10))
    }
    throw RaceTestTimeout()
}

private func withTestTimeout<T: Sendable>(
    _ timeout: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw RaceTestTimeout()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}
