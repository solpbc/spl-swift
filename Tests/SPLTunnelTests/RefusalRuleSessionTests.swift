// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Testing
@testable import SPLTunnel

private let refusalClientInfo = SPLClientInfo(userAgent: "spl-swift-refusal-tests/1")

/// proto/session.md § 7 applied by a session and a supervisor: the verdict window, what
/// counts, the outcome across legs, and the stop that latches.
@Suite("RefusalRuleSession", .serialized)
struct RefusalRuleSessionTests {
    private static let lan = TransportEndpoint.lan(host: "192.0.2.10", port: 7657, scope: "lan")

    // Falsified by clearing the count when the client's own handshake completes (each
    // connection would start again from zero and never stop), or by a per-code counter (each
    // connection here is refused with a different code).
    @Test func readyThenARefusalBeforeAnyInboundByteSevenTimesAtSpacingStops() async throws {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        let pairing = fakePairing()
        let ledger = refusalLedger(for: pairing, store: store, clock: clock)
        let codes: [Int32] = [
            PeerAlert.internalError,
            PeerAlert.badCertificate,
            PeerAlert.unexpectedMessage,
            PeerAlert.badRecordMac,
            PeerAlert.recordOverflow,
            PeerAlert.genericFatal,
            -9831,
        ]
        #expect(codes.count == HandshakeRefusalPolicy.refusalLimit)

        for (index, code) in codes.enumerated() {
            let tls = FakeTunnelTLS()
            let session = TunnelSession(
                pairing: pairing,
                tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
                refusalLedger: ledger
            )
            let states = await stateProbe(for: session)
            _ = try await session.connect(endpoints: [relayEndpoint()])
            await tls.finishInbound(throwing: NWError.tls(code))
            let last = index == codes.count - 1
            #expect(await waitForFailure(last ? .refusalsExhausted : .refused, in: states))
            #expect(await ledger.view().refusals == index + 1)
            await session.disconnect()
            await states.stop()
            clock.advance(.seconds(300))
        }
        #expect(store.record(credential: pairing.refusalCredential)?.stop == .refusalsExhausted)

        let connector = ConnectorProbe { _, _, _ in FakeTunnelTLS() }
        let next = TunnelSession(pairing: pairing, tlsConnector: connector.connector, refusalLedger: ledger)
        await expectSessionError(.refusalsExhausted) {
            try await next.connect(endpoints: [relayEndpoint()])
        }
        #expect(await connector.invocationCount == 0)
    }

    // Falsified by counting a close, a reset or a local TLS failure as a refusal: the seventh
    // of these would stop a credential the journal never refused.
    @Test func failuresThatAreNotReceivedAlertsNeverCount() async throws {
        let clock = ManualRefusalClock()
        let pairing = fakePairing()
        let ledger = refusalLedger(for: pairing, store: TestRefusalStore(), clock: clock)
        let endings: [(any Error)?] = [
            NWError.tls(PeerAlert.closedGraceful),
            NWError.tls(PeerAlert.closedAbort),
            NWError.posix(.ECONNRESET),
            nil,
            NWError.tls(PeerAlert.closedNoNotify),
            NWError.tls(PeerAlert.localDecryptionFailure),
            InnerTLSError.receiveFailed("connection reset"),
        ]
        #expect(endings.count == HandshakeRefusalPolicy.refusalLimit)

        for ending in endings {
            let tls = FakeTunnelTLS()
            let session = TunnelSession(
                pairing: pairing,
                tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
                refusalLedger: ledger
            )
            let states = await stateProbe(for: session)
            _ = try await session.connect(endpoints: [relayEndpoint()])
            await tls.finishInbound(throwing: ending)
            #expect(await waitForFailure(in: states) { error in
                if case .inboundClosed = error {
                    return true
                }
                return false
            })
            await session.disconnect()
            await states.stop()
            clock.advance(.seconds(300))
        }
        #expect(await ledger.view() == HandshakeRefusalRecord())

        let connector = ConnectorProbe { _, _, _ in FakeTunnelTLS() }
        let next = TunnelSession(pairing: pairing, tlsConnector: connector.connector, refusalLedger: ledger)
        _ = try await next.connect(endpoints: [relayEndpoint()])
        #expect(await connector.invocationCount == 1)
        await next.disconnect()
    }

    // Falsified by reading an alert as the journal's verdict after its first application byte
    // closed the window: the access denied here would stop the credential.
    @Test func anAlertAfterTheJournalsFirstByteIsNeitherCountedNorAStop() async throws {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        let pairing = fakePairing()
        store.seed(HandshakeRefusalRecord(refusals: 3, lastCountedAt: clock.now), credential: pairing.refusalCredential)
        let ledger = refusalLedger(for: pairing, store: store, clock: clock)
        let tls = FakeTunnelTLS()
        let session = TunnelSession(
            pairing: pairing,
            tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
            refusalLedger: ledger
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [relayEndpoint()])
        await tls.yieldInbound(try encodeFrame(buildPing(nonce: Data(repeating: 7, count: 8))))
        await tls.finishInbound(throwing: NWError.tls(PeerAlert.accessDenied))

        #expect(await waitForFailure(in: states) { error in
            if case .inboundClosed = error {
                return true
            }
            return false
        })
        #expect(await states.containsFailure { $0 == .revoked } == false)
        #expect(await ledger.stop() == nil)
        #expect(store.record(credential: pairing.refusalCredential) == HandshakeRefusalRecord(refusals: 0))
        await session.disconnect()
        await states.stop()
    }

    // Falsified by deciding a write that failed inside the window without reading once more:
    // the writer would see the reset, and nothing would be counted.
    @Test func aResetWriteFollowedByAPendingAlertIsClassifiedByTheAlert() async throws {
        let pairing = fakePairing()
        let ledger = refusalLedger(for: pairing, store: TestRefusalStore())
        let tls = FakeTunnelTLS()
        let session = TunnelSession(
            pairing: pairing,
            tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
            refusalLedger: ledger
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [relayEndpoint()])
        let stream = try await session.openStream()
        await tls.setSendError(NWError.posix(.ECONNRESET))
        let write = Task { try await stream.write(Data([0x01])) }
        #expect(await waitUntil("the failed write waits for the verdict", timeout: .seconds(2)) {
            await session.pendingVerdictWaiterCount == 1
        })
        await tls.finishInbound(throwing: NWError.tls(PeerAlert.internalError))

        await expectSessionError(.refused) {
            try await write.value
        }
        #expect(await waitForFailure(.refused, in: states))
        #expect(await ledger.view().refusals == 1)
        await session.disconnect()
        await states.stop()
    }

    // Falsified by an attempt that keeps dialling or ranks the relay leg once the selected LAN
    // leg has the journal's verdict: the relay's own outcome would replace the refusal.
    @Test func aSelectedLANLegRefusedWhileTheRelayIsStillDiallingDecidesTheAttempt() async throws {
        let pairing = fakePairing()
        let ledger = refusalLedger(for: pairing, store: TestRefusalStore())
        let lanTLS = FakeTunnelTLS()
        await lanTLS.finishInbound(throwing: NWError.tls(PeerAlert.internalError))
        let relayStarted = TestSignal()
        let relayCancelled = TestSignal()
        let connector = ConnectorProbe { endpoint, _, _ in
            if case .lan = endpoint {
                return lanTLS
            }
            await relayStarted.signal()
            await withTaskCancellationHandler {
                try? await Task.sleep(for: .seconds(30))
            } onCancel: {
                Task { await relayCancelled.signal() }
            }
            throw InnerTLSError.unknownJournal(claimedJournalID: "relay-leg-must-not-rank")
        }
        let session = TunnelSession(
            pairing: pairing,
            policy: SessionPolicy(race: RacePolicy(stagger: .milliseconds(1), loserGrace: .milliseconds(50))),
            tlsConnector: connector.connector,
            refusalLedger: ledger
        )
        let states = await stateProbe(for: session)
        let attempts = session.attemptUpdates

        do {
            _ = try await session.connect(endpoints: [Self.lan, relayEndpoint()])
        } catch let error as SessionError {
            #expect(error == .refused)
        }
        try await relayStarted.waitWithTimeout()
        try await relayCancelled.waitWithTimeout()
        #expect(await waitForFailure(.refused, in: states))
        #expect(await states.containsFailure { $0 == .unknownJournal || $0 == .unreachable } == false)
        #expect(await ledger.view().refusals == 1)

        var phases: [TunnelAttemptRoute: TunnelAttemptPhase] = [:]
        for await event in attempts {
            phases[event.route] = event.phase
        }
        guard case .selected = phases[.directPinned] else {
            Issue.record("LAN leg was not selected: \(String(describing: phases[.directPinned]))")
            return
        }
        guard case .cancelled = phases[.relay] else {
            Issue.record("relay leg was not cancelled: \(String(describing: phases[.relay]))")
            return
        }
        await session.disconnect()
        await states.stop()
    }

    // Falsified by collapsing every no-verdict outcome to unreachable, or by ranking by leg
    // order alone (the unknown journal is the earlier leg in one case and the later in the
    // other). The sighting is delivered either way, and nothing is counted.
    @Test(arguments: [true, false])
    func legsThatEndWithoutAVerdictRankAnUnknownJournalAboveUnreachable(unknownOnLAN: Bool) async throws {
        let pairing = fakePairing()
        let ledger = refusalLedger(for: pairing, store: TestRefusalStore())
        let connector = ConnectorProbe { endpoint, _, _ in
            let isLAN: Bool
            if case .lan = endpoint {
                isLAN = true
            } else {
                isLAN = false
            }
            if isLAN == unknownOnLAN {
                throw InnerTLSError.unknownJournal(claimedJournalID: "claimed-jid")
            }
            throw SessionError.unreachable
        }
        let session = TunnelSession(pairing: pairing, tlsConnector: connector.connector, refusalLedger: ledger)
        let sightings = session.unknownJournalSightings

        await expectSessionError(.unknownJournal) {
            try await session.connect(endpoints: [Self.lan, relayEndpoint()])
        }
        await session.disconnect()
        var seen: [UnknownJournalSighting] = []
        for await sighting in sightings {
            seen.append(sighting)
        }
        let dialled = unknownOnLAN ? Self.lan.connectedVia : relayEndpoint().connectedVia
        #expect(seen == [UnknownJournalSighting(dialled: dialled, claimedJournalID: "claimed-jid")])
        #expect(await ledger.view() == HandshakeRefusalRecord())
    }

    // Falsified by a supervisor that drops its connections' sightings, or that lets an
    // unknown journal on one leg keep it from connecting through another.
    @Test func aSupervisorDeliversItsConnectionsSightingsEvenWhenAnotherLegConnects() async throws {
        let pairing = fakePairing()
        let connector = ConnectorProbe { endpoint, _, _ in
            if case .lan = endpoint {
                throw InnerTLSError.unknownJournal(claimedJournalID: "claimed-by-lan-peer")
            }
            return FakeTunnelTLS()
        }
        let supervisor = TunnelSupervisor(
            pairing: pairing,
            clientInfo: refusalClientInfo,
            policy: SessionPolicy(race: RacePolicy(stagger: .milliseconds(1), loserGrace: .milliseconds(20))),
            makeSession: { pairing, _, policy, context in
                TunnelSession(
                    pairing: pairing,
                    policy: policy,
                    tlsConnector: connector.connector,
                    refusalLedger: context.refusals,
                    unknownJournalObserver: context.unknownJournalObserver
                )
            },
            refusalLedger: refusalLedger(for: pairing, store: TestRefusalStore())
        )
        var sightings = supervisor.unknownJournalSightings.makeAsyncIterator()

        #expect(try await supervisor.connect(endpoints: [Self.lan, relayEndpoint()]) == relayEndpoint().connectedVia)
        #expect(await sightings.next() == UnknownJournalSighting(
            dialled: Self.lan.connectedVia,
            claimedJournalID: "claimed-by-lan-peer"
        ))
        await supervisor.disconnect()
    }

    // Falsified by an in-memory-only count: a new process would start from zero.
    @Test func aFreshSessionOverARecordOfSixStopsOnItsNextRefusal() async throws {
        let clock = ManualRefusalClock()
        let store = TestRefusalStore()
        let pairing = fakePairing()
        store.seed(
            HandshakeRefusalRecord(refusals: 6, lastCountedAt: clock.now.addingTimeInterval(-300)),
            credential: pairing.refusalCredential
        )
        let tls = FakeTunnelTLS()
        let session = TunnelSession(
            pairing: pairing,
            tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
            refusalLedger: refusalLedger(for: pairing, store: store, clock: clock)
        )
        let states = await stateProbe(for: session)
        _ = try await session.connect(endpoints: [relayEndpoint()])
        await tls.finishInbound(throwing: NWError.tls(PeerAlert.internalError))
        #expect(await waitForFailure(.refusalsExhausted, in: states))
        #expect(store.record(credential: pairing.refusalCredential)?.stop == .refusalsExhausted)
        await session.disconnect()
        await states.stop()
    }

    // Falsified by a stop that does not persist: a new process would dial the stopped
    // credential again.
    @Test func aPersistedStopMeansAFreshClientDoesNotDial() async throws {
        let pairing = fakePairing()
        let store = TestRefusalStore()
        store.seed(HandshakeRefusalRecord(stop: .accessDenied), credential: pairing.refusalCredential)

        let connector = ConnectorProbe { _, _, _ in FakeTunnelTLS() }
        let session = TunnelSession(
            pairing: pairing,
            tlsConnector: connector.connector,
            refusalLedger: refusalLedger(for: pairing, store: store)
        )
        await expectSessionError(.revoked) {
            try await session.connect(endpoints: [relayEndpoint()])
        }
        #expect(await connector.invocationCount == 0)

        let supervisor = TunnelSupervisor(pairing: pairing, clientInfo: refusalClientInfo, refusalStore: store)
        let states = await stateProbe(for: supervisor)
        await expectSessionError(.revoked) {
            try await supervisor.connect(endpoints: [relayEndpoint()])
        }
        #expect(await supervisor.attemptState == .terminal(.revoked))
        await supervisor.requestReconnect()
        await supervisor.requestUpgrade()
        #expect(await waitForFailure(.revoked, in: states))
        #expect(await supervisor.attemptState == .terminal(.revoked))
        await supervisor.disconnect()
        await states.stop()
    }

    // Falsified by re-arming a stopped supervisor on connect (the earlier behaviour), by a
    // reconnect or upgrade request dialling a stopped credential, or by clearing a stop when
    // the journal later accepts a connection.
    @Test func afterAStopConnectAndReconnectRequestsDoNotDialAndAcceptanceDoesNotClearIt() async throws {
        let pairing = fakePairing()
        let store = TestRefusalStore()
        let ledger = refusalLedger(for: pairing, store: store)
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let supervisor = TunnelSupervisor(
            pairing: pairing,
            clientInfo: refusalClientInfo,
            reconnectBackoff: ReconnectBackoff(schedule: .table([.milliseconds(1)]), random: { _ in 1.0 }),
            sleeper: { _ in },
            makeSession: { pairing, _, policy, context in
                TunnelSession(
                    pairing: pairing,
                    policy: policy,
                    tlsConnector: connector.connector,
                    refusalLedger: context.refusals
                )
            },
            refusalLedger: ledger
        )
        let states = await stateProbe(for: supervisor)

        _ = try await supervisor.connect(endpoints: [relayEndpoint()])
        await tls.finishInbound(throwing: NWError.tls(PeerAlert.accessDenied))
        #expect(await waitForFailure(.revoked, in: states))
        #expect(await waitUntil("supervisor stops") {
            await supervisor.attemptState == .terminal(.revoked)
        })
        #expect(store.record(credential: pairing.refusalCredential)?.stop == .accessDenied)

        await ledger.accepted()
        await expectSessionError(.revoked) {
            try await supervisor.connect(endpoints: [relayEndpoint()])
        }
        await supervisor.requestReconnect()
        await supervisor.requestUpgrade()
        await supervisor.disconnect()
        await expectSessionError(.revoked) {
            try await supervisor.connect(endpoints: [relayEndpoint()])
        }
        #expect(await connector.invocationCount == 1)
        #expect(store.record(credential: pairing.refusalCredential)?.stop == .accessDenied)

        // A relaunch over the same store does not dial either.
        let relaunched = TunnelSupervisor(pairing: pairing, clientInfo: refusalClientInfo, refusalStore: store)
        await expectSessionError(.revoked) {
            try await relaunched.connect(endpoints: [relayEndpoint()])
        }
        await supervisor.disconnect()
        await states.stop()
    }

    // Falsified by letting an unreadable store hide an access denied: the session must still
    // stop the credential in this process.
    @Test func aFailedReadAtLaunchStillLetsAccessDeniedStop() async throws {
        let pairing = fakePairing()
        let store = TestRefusalStore()
        store.setFailingReads(true)
        let ledger = refusalLedger(for: pairing, store: store)
        let tls = FakeTunnelTLS()
        let session = TunnelSession(
            pairing: pairing,
            tlsConnector: ConnectorProbe { _, _, _ in tls }.connector,
            refusalLedger: ledger
        )
        let states = await stateProbe(for: session)
        _ = try await session.connect(endpoints: [relayEndpoint()])
        await tls.finishInbound(throwing: NWError.tls(PeerAlert.accessDenied))
        #expect(await waitForFailure(.revoked, in: states))
        #expect(await ledger.stop() == .accessDenied)
        #expect(store.record(credential: pairing.refusalCredential) == nil)

        let connector = ConnectorProbe { _, _, _ in FakeTunnelTLS() }
        let next = TunnelSession(pairing: pairing, tlsConnector: connector.connector, refusalLedger: ledger)
        await expectSessionError(.revoked) {
            try await next.connect(endpoints: [relayEndpoint()])
        }
        #expect(await connector.invocationCount == 0)
        await session.disconnect()
        await states.stop()
    }
}
