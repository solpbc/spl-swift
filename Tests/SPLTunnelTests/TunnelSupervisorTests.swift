// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Synchronization
import Testing
@testable import SPLTunnel

private let supervisorClientInfo = SPLClientInfo(userAgent: "spl-swift-supervisor-tests/1")
private struct PostReadyRaceTestError: Error, Sendable {}
private let supervisorRaceEndpoints = [directEndpoint("10.0.0.5"), relayEndpoint()]
private let terminalRevocationStatus = ReconnectStatus(
    reason: .revoked,
    attempt: 1,
    retryAfter: nil,
    terminalPause: true
)

@Suite(
    "TunnelSupervisor",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct TunnelSupervisorTests {
    @Test func reconnectSurvivesThreeFixedPortServerKillRestartCycles() async throws {
        let fixture = try TestCA.make()
        let port = FixedPortReclaimTestPorts.tunnelSupervisorRebindPort
        var server = TLSEchoServer(bundle: fixture, mode: .mux)
        try await server.start(port: port)
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: port, scope: "local")
        let supervisor = TunnelSupervisor(
            pairing: pairing(from: fixture, localEndpoints: [
                LocalEndpoint(host: "127.0.0.1", port: port, scope: "local"),
            ]),
            clientInfo: supervisorClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            sleeper: { _ in }
        )
        let states = await stateProbe(for: supervisor)

        _ = try await supervisor.connect(endpoints: [endpoint])
        var connectedCount = await states.count(.connected(via: endpoint.connectedVia))

        for _ in 0..<3 {
            await server.stop()
            server = TLSEchoServer(bundle: fixture, mode: .mux)
            try await server.start(port: port)
            connectedCount += 1
            let expectedConnectedCount = connectedCount
            #expect(await waitUntil("supervisor reconnected fixed-port server", timeout: .seconds(3)) {
                await states.count(.connected(via: endpoint.connectedVia)) >= expectedConnectedCount
            })
        }

        await supervisor.disconnect()
        await states.stop()
        await server.stop()
    }

    @Test func trustDirectUsesNormalRaceWithoutExtraCandidates() async throws {
        let trusted = TransportEndpoint.lan(host: "192.168.1.20", port: 443, scope: "trusted", unpinnedInterface: true)
        let rankedFirst = TransportEndpoint.lan(host: "10.0.0.8", port: 443, scope: "ranked")
        let relay = relayEndpoint()
        let planned = [rankedFirst, trusted, relay]
        let connector = ConnectorProbe { _, _, _ in
            FakeTunnelTLS()
        }
        let supervisor = supervisorWithConnector(connector, racePolicy: allCandidatesRacePolicy())

        _ = try await supervisor.connect(endpoints: [trusted])
        _ = try await supervisor.connect(endpoints: planned)
        await supervisor.requestReconnect()

        await connector.waitForInvocationCount(1 + planned.count)
        let attempts = await connector.attemptedEndpoints()
        let redriveAttempts = Array(attempts.dropFirst())
        #expect(redriveAttempts.count == planned.count)
        expectSameEndpoints(redriveAttempts, planned)

        await supervisor.disconnect()
    }

    @Test func trustDirectDoesNotDialCachedEndpointOutsideCurrentPlannedSet() async throws {
        let trusted = TransportEndpoint.lan(host: "192.168.1.20", port: 443, scope: "trusted", unpinnedInterface: true)
        let rankedFirst = TransportEndpoint.lan(host: "10.0.0.8", port: 443, scope: "ranked")
        let relay = relayEndpoint()
        let planned = [rankedFirst, relay]
        let connector = ConnectorProbe { _, _, _ in
            FakeTunnelTLS()
        }
        let supervisor = supervisorWithConnector(connector, racePolicy: allCandidatesRacePolicy())

        _ = try await supervisor.connect(endpoints: [trusted])
        _ = try await supervisor.connect(endpoints: planned)
        await supervisor.requestReconnect()

        await connector.waitForInvocationCount(1 + planned.count)
        let attempts = await connector.attemptedEndpoints()
        let redriveAttempts = Array(attempts.dropFirst())
        #expect(redriveAttempts.count == planned.count)
        expectSameEndpoints(redriveAttempts, planned)
        #expect(attempts.contains(trusted) == true)
        #expect(redriveAttempts.contains(trusted) == false)
        #expect(attempts.count == 1 + planned.count)

        await supervisor.disconnect()
    }

    @Test func directKeepaliveMissUsesRelayOnlyForNextGeneration() async throws {
        let direct = directEndpoint("10.0.0.5")
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(relay),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct, relay])
        let first = try await factory.generation(at: 0)
        await first.fail(.directKeepaliveMissed)

        #expect(await waitUntil("relay-only reconnect") {
            await factory.count() == 2
        })
        let second = try await factory.generation(at: 1)
        let calls = await second.connectCalls()
        #expect(calls.first?.endpoints == [relay])
        #expect(calls.first?.preferredEndpoint == nil)

        await supervisor.disconnect()
    }

    @Test func keepaliveSendFailureRedrivesConnectedGeneration() async throws {
        let direct = directEndpoint("10.0.0.5")
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        let first = try await factory.generation(at: 0)
        await first.fail(.directKeepaliveMissed)

        #expect(await waitUntil("keepalive failure redrive") {
            await factory.count() == 2
        })

        await supervisor.disconnect()
    }

    @Test func healableFailurePublishesConnectingBeforeRetryDelayElapses() async throws {
        let direct = directEndpoint("10.0.0.5")
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: sleeper.sleep)
        let states = await stateProbe(for: supervisor)

        _ = try await supervisor.connect(endpoints: [direct])
        let connectingCount = await states.count(.connecting(candidates: [direct.connectedVia]))
        let first = try await factory.generation(at: 0)
        await first.fail(.inboundClosed(fault: nil))

        #expect(await waitUntil("healable failure connecting state") {
            await states.count(.connecting(candidates: [direct.connectedVia])) > connectingCount
        })
        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await factory.count() == 1)
        #expect(await supervisor.reconnectStatus == ReconnectStatus(
            reason: .inboundClosed(fault: nil),
            attempt: 1,
            retryAfter: .milliseconds(1),
            terminalPause: false
        ))

        await sleeper.releaseFirstSleep(duration: .milliseconds(1))
        #expect(await waitUntil("healable failure retry connects") {
            await factory.count() == 2
        })
        await supervisor.disconnect()
        await sleeper.releaseSleeps()
        await states.stop()
    }

    @Test func deadMuxOpenStreamCoalescesWithGenerationFailureAndThrowsNotConnected() async throws {
        let direct = directEndpoint("10.0.0.5")
        let factory = FakeGenerationFactory(scripts: [
            .success(direct, openStreamFailure: .transportFailed("mux closed")),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        await expectSessionError(.notConnected) {
            _ = try await supervisor.openStream()
        }

        #expect(await waitUntil("dead mux open redrive") {
            await factory.count() == 2
        })

        await supervisor.disconnect()
    }

    @Test func terminalAuthPauseRearmsOnConnectSameSupervisor() async throws {
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [
            .failure(.authRefreshRequired),
            .success(relay),
        ])
        let supervisor = fakeSupervisor(factory: factory)
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let terminalStatus = ReconnectStatus(
            reason: .authRefreshRequired,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        )

        await expectSessionError(.authRefreshRequired) {
            try await supervisor.connect(endpoints: [relay])
        }
        #expect(await waitForFailure(.authRefreshRequired, in: states))
        #expect(await states.count(.failed(.authRefreshRequired)) == 1)
        #expect(await reconnects.count(terminalStatus) == 1)
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let failureCount = await states.count(.failed(.authRefreshRequired))
            let statusCount = await reconnects.count(terminalStatus)
            return failureCount > 1 || statusCount > 1
        } == false)
        #expect(await supervisor.reconnectStatus == terminalStatus)

        _ = try await supervisor.connect(endpoints: [relay])
        #expect(await factory.count() == 2)

        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test func terminalPeerAccessDeniedPauseRearmsOnConnectSameSupervisor() async throws {
        // Security/SecBase.h: peer access denied pauses once and an explicit connect re-arms the supervisor.
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [
            .failure(.revoked),
            .success(relay),
        ])
        let supervisor = fakeSupervisor(factory: factory)
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let terminalStatus = ReconnectStatus(
            reason: .revoked,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        )

        await expectSessionError(.revoked) {
            try await supervisor.connect(endpoints: [relay])
        }
        #expect(await waitForFailure(.revoked, in: states))
        #expect(await states.count(.failed(.revoked)) == 1)
        #expect(await reconnects.count(terminalStatus) == 1)
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 1
        } == false)

        _ = try await supervisor.connect(endpoints: [relay])
        #expect(await factory.count() == 2)
        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func denialDuringRecoveryBackoffPausesBeforeReplacementDial(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            reconnectBackoff: longFirstBackoff()
        )
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let stream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await stream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())

        #expect(await waitUntil("nonterminal reconnect status") {
            guard let status = await supervisor.reconnectStatus else { return false }
            return status.terminalPause == false
        })
        #expect(await reconnects.containsNonterminal())
        #expect(await connector.invocationCount == 1)

        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        _ = await assertSingleTerminalRevocation(states: states, reconnects: reconnects)
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await connector.invocationCount > 1
        } == false)

        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func denialAfterSuccessorInstallPausesAndDiscardsHeldCandidate(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let candidate = FakeTunnelTLS()
        let candidateGate = ConnectorReturnGate()
        let tlsSequence = TunnelTLSSequence([tls, candidate], gates: [nil, candidateGate])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let supervisor = supervisorWithConnector(connector, racePolicy: controlledRacePolicy())
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let stream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await stream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        await candidateGate.waitForEntry()
        #expect(await connector.invocationCount == 2)

        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        _ = await assertSingleTerminalRevocation(states: states, reconnects: reconnects)

        await candidateGate.release()
        await expectSessionError(.notConnected) { _ = try await supervisor.openStream() }
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let connectedCount = await states.count(.connected(via: endpoint.connectedVia))
            let invocationCount = await connector.invocationCount
            return connectedCount > 1 || invocationCount > 2
        } == false)

        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func retiringGenerationSurvivesMultiplePrecommitCandidates(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let candidate = FakeTunnelTLS()
        let candidateGate = ConnectorReturnGate()
        let attempts = ConnectorAttemptSequence([
            .tls(tls),
            .failure,
            .failure,
            .tls(candidate),
        ], gates: [nil, nil, nil, candidateGate])
        let connector = ConnectorProbe { _, _, _ in try await attempts.next() }
        let supervisor = supervisorWithConnector(connector, racePolicy: controlledRacePolicy())
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let stream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await stream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        await candidateGate.waitForEntry()
        #expect(await connector.invocationCount == 4)

        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        guard await assertSingleTerminalRevocation(states: states, reconnects: reconnects) else {
            await candidateGate.release()
            await supervisor.disconnect()
            await states.stop()
            await reconnects.stop()
            return
        }
        await candidateGate.release()
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await connector.invocationCount > 4
        } == false)

        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func peerAccessDeniedThenLaterGenericCallbackPausesOnceAndRearms(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let supervisor = supervisorWithConnector(connector, racePolicy: controlledRacePolicy())
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let deniedGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let stream = try await supervisor.openStream()
        await tls.enqueueSendGate(deniedGate)
        let deniedWrite = Task { try await stream.write(Data([0x01])) }
        await deniedGate.waitForEntry()
        // openStream's OPEN is a control frame, but it cannot preempt the in-flight
        // DATA sink call; it stays queued in the mux until this write completes.
        let genericOpen = Task { try await supervisor.openStream() }

        await tls.setSendError(NWError.tls(-9832))
        await deniedGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        _ = await assertSingleTerminalRevocation(states: states, reconnects: reconnects)

        await expectSessionError(.notConnected) { _ = try await genericOpen.value }
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let terminalCount = await reconnects.count(terminalRevocationStatus)
            let invocationCount = await connector.invocationCount
            return terminalCount > 1 || invocationCount > 1
        } == false)

        _ = try await supervisor.connect(endpoints: [endpoint])
        #expect(await connector.invocationCount == 2)
        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func genericRecoveryConnectsUsableSuccessor(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let emissions = StateEmissionProbe()
        let successorConnected = TestSignal()
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            stateEmissionTestObserver: { state in
                emissions.record(state)
                if state == .connected(via: endpoint.connectedVia),
                   emissions.count(.connected(via: endpoint.connectedVia)) == 2 {
                    Task {
                        await successorConnected.signal()
                    }
                }
            }
        )
        let reconnects = await reconnectProbe(for: supervisor)

        _ = try await supervisor.connect(endpoints: [endpoint])
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        try await successorConnected.waitWithTimeout()
        let stream = try await supervisor.openStream()
        try await stream.write(Data([0x01]))
        #expect(await reconnects.count(terminalRevocationStatus) == 0)

        await supervisor.disconnect()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func userDisconnectClosesDelayedPeerDenialWindow(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let supervisor = supervisorWithConnector(connector, racePolicy: controlledRacePolicy())
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let stream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await stream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await supervisor.disconnect()
        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        _ = await deniedWrite.result
        #expect(await reconnects.count(terminalRevocationStatus) == 0)
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let invocationCount = await connector.invocationCount
            let sawRevocation = await states.containsFailure { $0 == .revoked }
            return invocationCount > 1 || sawRevocation
        } == false)

        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func currentOpenRejectsWhenFailureRegistersDuringLowerLevelOpen(
        _ endpoint: TransportEndpoint
    ) async throws {
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let failureRegistered = TestSignal()
        let observeFailure = Mutex(false)
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            reconnectBackoff: longFirstBackoff(),
            stateEmissionTestObserver: { state in
                guard observeFailure.withLock({ $0 }), case .connecting = state else {
                    return
                }
                Task {
                    await failureRegistered.signal()
                }
            }
        )
        let openGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        await tls.enqueueSendGate(openGate)
        let opening = Task { try await supervisor.openStream() }
        await openGate.waitForEntry()
        observeFailure.withLock { $0 = true }
        await tls.finishInbound(throwing: PostReadyRaceTestError())

        let didRegisterFailure: Bool
        do {
            try await failureRegistered.waitWithTimeout()
            didRegisterFailure = true
        } catch {
            didRegisterFailure = false
        }
        guard didRegisterFailure else {
            #expect(Bool(false))
            await openGate.release()
            _ = await opening.result
            await supervisor.disconnect()
            return
        }

        await openGate.release()
        await expectSessionError(.notConnected) { _ = try await opening.value }
        await supervisor.disconnect()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func stalePublicOpenPreservesRetiringPeerDenialEligibility(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let commitGate = RetirementCommitGate(holdFrom: 1)
        let emissions = StateEmissionProbe()
        let redrives = RedriveRequestProbe()
        let openReturnGate = OpenReturnGate()
        let generations = SessionGenerationCounter()
        let supervisor = TunnelSupervisor(
            pairing: fakePairing(),
            clientInfo: supervisorClientInfo,
            policy: SessionPolicy(race: controlledRacePolicy()),
            reconnectBackoff: ReconnectBackoff(
                schedule: .table([.milliseconds(1)]),
                random: { _ in 1.0 }
            ),
            makeSession: { pairing, _, policy in
                let session = TunnelSession(pairing: pairing, policy: policy, tlsConnector: connector.connector)
                if await generations.isSuccessor() {
                    return session
                }
                return GatedOpenGeneration(base: session, gate: openReturnGate)
            },
            retirementCommitTestGate: { token, caller in
                await commitGate.waitAtCommit(token: token, caller: caller)
            },
            stateEmissionTestObserver: { emissions.record($0) },
            redriveRequestTestObserver: { redrives.record() }
        )
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let deniedGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let oldStream = try await supervisor.openStream()
        await tls.enqueueSendGate(deniedGate)
        let deniedWrite = Task { try await oldStream.write(Data([0x01])) }
        await deniedGate.waitForEntry()
        await openReturnGate.arm()
        let staleOpen = Task { try await supervisor.openStream() }
        try await openReturnGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())

        guard await commitGate.waitForEntry(caller: .establishment) != nil else {
            #expect(Bool(false))
            await commitGate.release()
            await openReturnGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await deniedGate.release()
            _ = await staleOpen.result
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await states.stop()
            await reconnects.stop()
            return
        }
        let emissionBaseline = emissions.totalCount()
        let reconnectBaseline = await supervisor.reconnectStatus
        let redriveBaseline = redrives.count()
        let connectorBaseline = await connector.invocationCount

        await openReturnGate.release()
        await expectSessionError(.notConnected) { _ = try await staleOpen.value }
        #expect(emissions.totalCount() == emissionBaseline)
        #expect(await supervisor.reconnectStatus == reconnectBaseline)
        #expect(redrives.count() == redriveBaseline)
        #expect(await connector.invocationCount == connectorBaseline)

        await tls.setSendError(NWError.tls(-9832))
        await deniedGate.release()
        _ = await expectSessionError(.revoked) { try await deniedWrite.value }
        _ = await assertSingleTerminalRevocation(states: states, reconnects: reconnects)

        await commitGate.release()
        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func disconnectMakesHeldOldOpenAndLaterPeerDenialStale(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let openReturnGate = OpenReturnGate()
        let generations = SessionGenerationCounter()
        let emissions = StateEmissionProbe()
        let redrives = RedriveRequestProbe()
        let supervisor = TunnelSupervisor(
            pairing: fakePairing(),
            clientInfo: supervisorClientInfo,
            policy: SessionPolicy(race: controlledRacePolicy()),
            makeSession: { pairing, _, policy in
                let session = TunnelSession(pairing: pairing, policy: policy, tlsConnector: connector.connector)
                if await generations.isSuccessor() { return session }
                return GatedOpenGeneration(base: session, gate: openReturnGate)
            },
            stateEmissionTestObserver: { emissions.record($0) },
            redriveRequestTestObserver: { redrives.record() }
        )
        let reconnects = await reconnectProbe(for: supervisor)
        let deniedGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        let oldStream = try await supervisor.openStream()
        await tls.enqueueSendGate(deniedGate)
        let deniedWrite = Task { try await oldStream.write(Data([0x01])) }
        await deniedGate.waitForEntry()
        await openReturnGate.arm()
        let heldOpen = Task { try await supervisor.openStream() }
        try await openReturnGate.waitForEntry()

        await supervisor.disconnect()
        let emissionBaseline = emissions.totalCount()
        let reconnectBaseline = await supervisor.reconnectStatus
        let redriveBaseline = redrives.count()
        let connectorBaseline = await connector.invocationCount

        await openReturnGate.release()
        await expectSessionError(.notConnected) { _ = try await heldOpen.value }
        await tls.setSendError(NWError.tls(-9832))
        await deniedGate.release()
        _ = await expectSessionError(.revoked) { try await deniedWrite.value }
        #expect(emissions.totalCount() == emissionBaseline)
        #expect(await supervisor.reconnectStatus == reconnectBaseline)
        #expect(redrives.count() == redriveBaseline)
        #expect(await connector.invocationCount == connectorBaseline)
        #expect(await reconnects.count(terminalRevocationStatus) == 0)
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func publicSuccessorOpenCommitsRetirementAndMakesLaterPeerDenialStale(
        _ endpoint: TransportEndpoint
    ) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let successorInstallGate = SuccessorInstallGate()
        let commitGate = RetirementCommitGate(holdFrom: 1)
        let emissions = StateEmissionProbe()
        let redrives = RedriveRequestProbe()
        let initialConnected = TestSignal()
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            successorInstallGate: successorInstallGate,
            retirementCommitTestGate: { token, caller in
                await commitGate.waitAtCommit(token: token, caller: caller)
            },
            stateEmissionTestObserver: { state in
                emissions.record(state)
                if state == .connected(via: endpoint.connectedVia),
                   emissions.count(.connected(via: endpoint.connectedVia)) == 1 {
                    Task {
                        await initialConnected.signal()
                    }
                }
            },
            redriveRequestTestObserver: { redrives.record() }
        )
        let reconnects = await reconnectProbe(for: supervisor)
        let deniedGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        try await initialConnected.waitWithTimeout()
        let oldStream = try await supervisor.openStream()
        await tls.enqueueSendGate(deniedGate)
        let deniedWrite = Task { try await oldStream.write(Data([0x01])) }
        await deniedGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        try await successorInstallGate.waitForEntry()
        await successorInstallGate.release()

        guard await commitGate.waitForEntry(1) else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await deniedGate.release()
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await reconnects.stop()
            return
        }

        guard let firstCommit = await commitGate.recordedEntries().first else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await deniedGate.release()
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await reconnects.stop()
            return
        }
        let successorToken = firstCommit.token
        let successorOpen = Task { try await supervisor.openStream() }
        guard let publicOpenEntry = await commitGate.waitForEntry(
            token: successorToken,
            caller: .publicOpenStream
        ) else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await deniedGate.release()
            _ = await successorOpen.result
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await reconnects.stop()
            return
        }

        await commitGate.release(publicOpenEntry)
        let successorStream = try await successorOpen.value
        try await successorStream.write(Data([0x02]))
        let laterStream = try await supervisor.openStream()
        try await laterStream.write(Data([0x03]))

        let emissionBaseline = emissions.totalCount()
        let reconnectBaseline = await supervisor.reconnectStatus
        let redriveBaseline = redrives.count()
        let connectorBaseline = await connector.invocationCount
        await tls.setSendError(NWError.tls(-9832))
        await deniedGate.release()
        _ = await expectSessionError(.revoked) { try await deniedWrite.value }
        #expect(emissions.totalCount() == emissionBaseline)
        #expect(await supervisor.reconnectStatus == reconnectBaseline)
        #expect(redrives.count() == redriveBaseline)
        #expect(await connector.invocationCount == connectorBaseline)
        #expect(await reconnects.count(terminalRevocationStatus) == 0)

        await commitGate.release()
        await supervisor.disconnect()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func oldPeerDenialAfterSharedCommitStaysStaleAndSuccessorRemainsUsable(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let successorInstallGate = SuccessorInstallGate()
        let commitGate = RetirementCommitGate(holdFrom: 1)
        let emissions = StateEmissionProbe()
        let initialConnected = TestSignal()
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            successorInstallGate: successorInstallGate,
            retirementCommitTestGate: { token, caller in
                await commitGate.waitAtCommit(token: token, caller: caller)
            },
            stateEmissionTestObserver: { state in
                emissions.record(state)
                if state == .connected(via: endpoint.connectedVia),
                   emissions.count(.connected(via: endpoint.connectedVia)) == 1 {
                    Task {
                        await initialConnected.signal()
                    }
                }
            }
        )
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        try await initialConnected.waitWithTimeout()
        let connectedCount = emissions.count(.connected(via: endpoint.connectedVia))
        let oldStream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await oldStream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        try await successorInstallGate.waitForEntry()
        await successorInstallGate.release()
        guard await commitGate.waitForEntry(1) else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await writeGate.release()
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await reconnects.stop()
            return
        }
        #expect(emissions.count(.connected(via: endpoint.connectedVia)) == connectedCount)

        let successorOpen = Task {
            try await supervisor.openStream()
        }
        guard await commitGate.waitForEntry(3) else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await writeGate.release()
            _ = await deniedWrite.result
            _ = await successorOpen.result
            await supervisor.disconnect()
            await reconnects.stop()
            return
        }
        #expect(emissions.count(.connected(via: endpoint.connectedVia)) == connectedCount)

        await commitGate.release()
        let successorStream = try await successorOpen.value
        try await successorStream.write(Data([0x01]))

        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        #expect(await reconnects.count(terminalRevocationStatus) == 0)
        let finalStream = try await supervisor.openStream()
        try await finalStream.write(Data([0x01]))
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let connected = emissions.count(.connected(via: endpoint.connectedVia))
            let revoked = emissions.contains(.failed(.revoked))
            let invocations = await connector.invocationCount
            return connected > connectedCount + 1 || revoked || invocations > 2
        } == false)

        await supervisor.disconnect()
        await reconnects.stop()
    }

    @Test(arguments: supervisorRaceEndpoints)
    func oldPeerDenialBeforeRetirementCommitPausesInstalledSuccessor(_ endpoint: TransportEndpoint) async throws {
        let tls = FakeTunnelTLS()
        let replacementTLS = FakeTunnelTLS()
        let tlsSequence = TunnelTLSSequence([tls, replacementTLS])
        let connector = ConnectorProbe { _, _, _ in await tlsSequence.next() }
        let successorInstallGate = SuccessorInstallGate()
        let commitGate = RetirementCommitGate(holdFrom: 1)
        let emissions = StateEmissionProbe()
        let initialConnected = TestSignal()
        let supervisor = supervisorWithConnector(
            connector,
            racePolicy: controlledRacePolicy(),
            successorInstallGate: successorInstallGate,
            retirementCommitTestGate: { token, caller in
                await commitGate.waitAtCommit(token: token, caller: caller)
            },
            stateEmissionTestObserver: { state in
                emissions.record(state)
                if state == .connected(via: endpoint.connectedVia),
                   emissions.count(.connected(via: endpoint.connectedVia)) == 1 {
                    Task {
                        await initialConnected.signal()
                    }
                }
            }
        )
        let states = await stateProbe(for: supervisor)
        let reconnects = await reconnectProbe(for: supervisor)
        let writeGate = FakeTunnelTLSSendGate()

        _ = try await supervisor.connect(endpoints: [endpoint])
        try await initialConnected.waitWithTimeout()
        let connectedCount = emissions.count(.connected(via: endpoint.connectedVia))
        let oldStream = try await supervisor.openStream()
        await tls.enqueueSendGate(writeGate)
        let deniedWrite = Task { try await oldStream.write(Data([0x01])) }
        await writeGate.waitForEntry()
        await tls.finishInbound(throwing: PostReadyRaceTestError())
        try await successorInstallGate.waitForEntry()
        await successorInstallGate.release()
        guard await commitGate.waitForEntry(1) else {
            #expect(Bool(false))
            await commitGate.release()
            await tls.setSendError(NWError.tls(-9832))
            await writeGate.release()
            _ = await deniedWrite.result
            await supervisor.disconnect()
            await states.stop()
            await reconnects.stop()
            return
        }
        #expect(emissions.count(.connected(via: endpoint.connectedVia)) == connectedCount)

        await tls.setSendError(NWError.tls(-9832))
        await writeGate.release()
        await expectSessionError(.revoked) { try await deniedWrite.value }
        guard await assertSingleTerminalRevocation(states: states, reconnects: reconnects) else {
            await commitGate.release()
            await supervisor.disconnect()
            await states.stop()
            await reconnects.stop()
            return
        }
        await commitGate.release()
        await expectSessionError(.notConnected) { _ = try await supervisor.openStream() }
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            let connected = emissions.count(.connected(via: endpoint.connectedVia))
            let invocations = await connector.invocationCount
            return connected > connectedCount || invocations > 2
        } == false)

        await supervisor.disconnect()
        await states.stop()
        await reconnects.stop()
    }

    @Test func preReadyPeerAccessDeniedPausesDirectAndRelayForFailedAndWaiting() async throws {
        // Security/SecBase.h: access denied before ready pauses without fallback or autonomous redrive.
        let direct = directEndpoint("10.0.0.5")
        let relay = relayEndpoint()
        let terminalStatus = ReconnectStatus(
            reason: .revoked,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        )

        for state in [
            NWConnection.State.failed(.tls(-9832)),
            NWConnection.State.waiting(.tls(-9832)),
        ] {
            for endpoint in [direct, relay] {
                let error = innerTLSError(for: try #require(preReadyNetworkError(from: state)))
                let connector = ConnectorProbe { _, _, _ in
                    throw error
                }
                let supervisor = supervisorWithConnector(connector, racePolicy: allCandidatesRacePolicy())
                let states = await stateProbe(for: supervisor)
                let reconnects = await reconnectProbe(for: supervisor)

                await expectSessionError(.revoked) {
                    try await supervisor.connect(endpoints: [endpoint])
                }
                #expect(await waitForFailure(.revoked, in: states))
                #expect(await waitUntil("terminal reconnect status") {
                    await reconnects.count(terminalStatus) >= 1
                })
                #expect(await reconnects.count(terminalStatus) == 1)
                #expect(await connector.invocationCount == 1)
                #expect(await conditionObserved(timeout: .milliseconds(100)) {
                    await connector.invocationCount > 1
                } == false)
                await supervisor.disconnect()
                await states.stop()
                await reconnects.stop()
            }
        }
    }

    @Test func preReadyPeerInternalErrorKeepsReadyCompetitorAndDoesNotPause() async throws {
        // Security/SecBase.h: peer internal error remains nonterminal and does not suppress a ready competitor.
        let direct = directEndpoint("10.0.0.5")
        let relay = relayEndpoint()
        let terminalStatus = ReconnectStatus(
            reason: .revoked,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        )

        for state in [
            NWConnection.State.failed(.tls(-9838)),
            NWConnection.State.waiting(.tls(-9838)),
        ] {
            let generic = innerTLSError(for: try #require(preReadyNetworkError(from: state)))
            let connector = ConnectorProbe { endpoint, _, _ in
                if endpoint == direct {
                    throw generic
                }
                return FakeTunnelTLS()
            }
            let supervisor = supervisorWithConnector(connector, racePolicy: allCandidatesRacePolicy())
            let states = await stateProbe(for: supervisor)
            let reconnects = await reconnectProbe(for: supervisor)

            #expect(try await supervisor.connect(endpoints: [direct, relay]) == relay.connectedVia)
            #expect(await connector.invocationCount == 2)
            #expect(await waitForState(.connected(via: relay.connectedVia), in: states))
            #expect(await states.containsFailure { $0 == .revoked } == false)
            #expect(await reconnects.count(terminalStatus) == 0)
            await supervisor.disconnect()
            await states.stop()
            await reconnects.stop()
        }
    }

    @Test func requestReconnectWhilePausedDoesNotUnpause() async throws {
        let relay = relayEndpoint()
        let factory = FakeGenerationFactory(scripts: [
            .failure(.notEntitled),
            .success(relay),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        await expectSessionError(.notEntitled) {
            try await supervisor.connect(endpoints: [relay])
        }

        await supervisor.requestReconnect()
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 1
        } == false)

        _ = try await supervisor.connect(endpoints: [relay])
        #expect(await factory.count() == 2)

        await supervisor.disconnect()
    }

    @Test func requestReconnectCoalescesConnectedRequestsThroughExistingLoop() async throws {
        let direct = directEndpoint("10.0.0.5")
        let sleeper = SleepProbe()
        let release = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(direct, gate: release),
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: sleeper.sleep)

        _ = try await supervisor.connect(endpoints: [direct])
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<5 {
                group.addTask {
                    await supervisor.requestReconnect()
                }
            }
        }

        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await factory.count() == 1)
        #expect(await supervisor.reconnectStatus == ReconnectStatus(
            reason: nil,
            attempt: 1,
            retryAfter: .milliseconds(1),
            terminalPause: false
        ))
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await sleeper.observedDurations(excluding: .seconds(60)).count > 1
        } == false)

        await sleeper.releaseFirstSleep(duration: .milliseconds(1))
        #expect(await waitUntil("coalesced manual reconnect") {
            await factory.count() == 2
        })
        await release.signal()
        #expect(await waitUntil("manual reconnect completed") {
            await supervisor.connectionMode == .plDirect
        })
        #expect(await factory.count() == 2)

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func explicitConnectBypassesBackoffFloor() async throws {
        let direct = directEndpoint("10.0.0.5")
        let release = TestSignal()
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct, gate: release),
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: sleeper.sleep)
        let task = Task {
            try await supervisor.connect(endpoints: [direct])
        }

        #expect(await waitUntil("user initiated generation starts immediately") {
            await factory.count() == 1
        })
        #expect(await sleeper.observedDurations(excluding: .seconds(60)).isEmpty)
        await release.signal()
        #expect(try await task.value == direct.connectedVia)

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func generationFailureDuringConnectedEndpointWindowDoesNotReturnSuccess() async throws {
        let direct = directEndpoint("10.0.0.5")
        let endpointLookupEntered = TestSignal()
        let releaseEndpointLookup = TestSignal()
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: [
            .success(
                direct,
                connectedEndpointSignal: endpointLookupEntered,
                connectedEndpointGate: releaseEndpointLookup
            ),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory, sleeper: sleeper.sleep)
        let task = Task {
            try await supervisor.connect(endpoints: [direct])
        }

        try await endpointLookupEntered.waitWithTimeout()
        let first = try await factory.generation(at: 0)
        await first.fail(.inboundClosed(fault: nil))
        await releaseEndpointLookup.signal()

        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 1)
        #expect(await factory.count() == 1)
        await sleeper.releaseFirstSleep(duration: .milliseconds(1))
        #expect(await waitUntil("replacement after post-await failure") {
            await factory.count() == 2
        })
        #expect(try await task.value == direct.connectedVia)

        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func shortLivedGenerationsGrowReconnectDelayMonotonically() async throws {
        let direct = directEndpoint("10.0.0.5")
        let sleeper = SleepProbe()
        let delays = (1...10).map { Duration.milliseconds($0) }
        let factory = FakeGenerationFactory(scripts: Array(
            repeating: .success(direct),
            count: 11
        ))
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: ReconnectBackoff(schedule: .table(delays), random: { _ in 1.0 }),
            sleeper: sleeper.sleep
        )

        _ = try await supervisor.connect(endpoints: [direct])
        for index in 0..<10 {
            let generation = try await factory.generation(at: index)
            await generation.fail(.inboundClosed(fault: nil))
            await sleeper.waitForSleepCount(excluding: .seconds(60), target: index + 1)
            await sleeper.releaseFirstSleep(duration: delays[index])
            #expect(await waitUntil("short-lived replacement \(index)") {
                await factory.count() == index + 2
            })
        }

        #expect(await sleeper.observedDurations(excluding: .seconds(60)) == delays)
        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func generationSurvivingStabilityIntervalResetsReconnectDelay() async throws {
        let direct = directEndpoint("10.0.0.5")
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: Array(
            repeating: .success(direct),
            count: 3
        ))
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: ReconnectBackoff(schedule: .table([.milliseconds(1), .milliseconds(2)]), random: { _ in 1.0 }),
            sleeper: sleeper.sleep
        )

        _ = try await supervisor.connect(endpoints: [direct])
        let first = try await factory.generation(at: 0)
        await first.fail(.inboundClosed(fault: nil))
        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleeper.releaseFirstSleep(duration: .milliseconds(1))
        #expect(await waitUntil("second generation connected") {
            await factory.count() == 2
        })
        #expect(await waitUntil("stability timers armed") {
            await sleeper.observedDurations().filter { $0 == .seconds(60) }.count >= 2
        })
        await sleeper.releaseAllSleeps(duration: .seconds(60))
        for _ in 0..<3 {
            await Task.yield()
        }

        let second = try await factory.generation(at: 1)
        await second.fail(.inboundClosed(fault: nil))
        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 2)

        #expect(await sleeper.observedDurations(excluding: .seconds(60)) == [
            .milliseconds(1),
            .milliseconds(1),
        ])
        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func staleStabilityTokenCannotResetReplacementGeneration() async throws {
        let direct = directEndpoint("10.0.0.5")
        let sleeper = SleepProbe()
        let factory = FakeGenerationFactory(scripts: Array(
            repeating: .success(direct),
            count: 3
        ))
        let supervisor = fakeSupervisor(
            factory: factory,
            reconnectBackoff: ReconnectBackoff(schedule: .table([.milliseconds(1), .milliseconds(2)]), random: { _ in 1.0 }),
            sleeper: sleeper.sleep
        )

        _ = try await supervisor.connect(endpoints: [direct])
        let first = try await factory.generation(at: 0)
        await first.fail(.inboundClosed(fault: nil))
        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 1)
        await sleeper.releaseFirstSleep(duration: .milliseconds(1))
        #expect(await waitUntil("replacement generation connected") {
            await factory.count() == 2
        })
        #expect(await waitUntil("replacement stability timer armed") {
            await sleeper.observedDurations().filter { $0 == .seconds(60) }.count >= 2
        })
        await sleeper.releaseFirstSleep(duration: .seconds(60))

        let second = try await factory.generation(at: 1)
        await second.fail(.inboundClosed(fault: nil))
        await sleeper.waitForSleepCount(excluding: .seconds(60), target: 2)

        #expect(await sleeper.observedDurations(excluding: .seconds(60)) == [
            .milliseconds(1),
            .milliseconds(2),
        ])
        await supervisor.disconnect()
        await sleeper.releaseSleeps()
    }

    @Test func replacementGenerationFailureDuringRedriveQueuesOneMoreGeneration() async throws {
        let direct = directEndpoint("10.0.0.5")
        let connected = TestSignal()
        let releaseReturn = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(
                direct,
                connectedSignal: connected,
                returnGate: releaseReturn,
                openStreamFailure: .transportFailed("mux closed")
            ),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        await supervisor.requestReconnect()
        #expect(await waitUntil("replacement generation installed") {
            await factory.count() == 2
        })
        try await connected.waitWithTimeout()

        await expectSessionError(.notConnected) {
            _ = try await supervisor.openStream()
        }
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 2
        } == false)

        await releaseReturn.signal()
        #expect(await waitUntil("queued replacement redrive") {
            await factory.count() == 3
        })

        await supervisor.disconnect()
    }

    @Test func concurrentConnectsShareInFlightEstablishment() async throws {
        let direct = directEndpoint("10.0.0.5")
        let release = TestSignal()
        let factory = FakeGenerationFactory(scripts: Array(
            repeating: .success(direct, gate: release),
            count: 5
        ))
        let supervisor = fakeSupervisor(factory: factory)
        let tasks = (0..<5).map { _ in
            Task {
                try await supervisor.connect(endpoints: [direct])
            }
        }

        #expect(await waitUntil("one shared connect generation") {
            await factory.count() == 1
        })
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 1
        } == false)

        await release.signal()
        for task in tasks {
            #expect(try await task.value == direct.connectedVia)
        }
        #expect(await factory.count() == 1)

        await supervisor.disconnect()
    }

    @Test func convergingDeathSignalsProduceOneReconnect() async throws {
        let direct = directEndpoint("10.0.0.5")
        let release = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct, openStreamFailure: .transportFailed("mux closed")),
            .success(direct, gate: release),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        let first = try await factory.generation(at: 0)

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await first.fail(.inboundClosed(fault: nil))
            }
            group.addTask {
                await supervisor.requestReconnect()
            }
            group.addTask {
                _ = try? await supervisor.openStream()
            }
        }

        #expect(await waitUntil("converged reconnect") {
            await factory.count() == 2
        })
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 2
        } == false)

        await release.signal()
        await supervisor.disconnect()
    }

    @Test func disconnectIgnoresLaterChildFailureWithoutRedrive() async throws {
        // Stale child teardown after parent disconnect must not redrive the supervisor.
        // Mux keepalive cancellation is covered separately.
        let direct = directEndpoint("10.0.0.5")
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(direct),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        let first = try await factory.generation(at: 0)
        await supervisor.disconnect()
        await first.fail(.directKeepaliveMissed)

        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 1
        } == false)
    }
}

private func supervisorWithConnector(
    _ connector: ConnectorProbe,
    racePolicy: RacePolicy,
    reconnectBackoff: ReconnectBackoff = ReconnectBackoff(
        schedule: .table([.milliseconds(1)]),
        random: { _ in 1.0 }
    ),
    successorInstallGate: SuccessorInstallGate? = nil,
    retirementCommitTestGate: (@Sendable (UInt64, TunnelSupervisor.RetirementCommitCaller) async -> Void)? = nil,
    stateEmissionTestObserver: @escaping @Sendable (TunnelState) -> Void = { _ in },
    redriveRequestTestObserver: @escaping @Sendable () -> Void = {}
) -> TunnelSupervisor {
    let generations = SessionGenerationCounter()
    return TunnelSupervisor(
        pairing: fakePairing(),
        clientInfo: supervisorClientInfo,
        policy: SessionPolicy(race: racePolicy),
        reconnectBackoff: reconnectBackoff,
        makeSession: { pairing, _, policy in
            if await generations.isSuccessor(), let successorInstallGate {
                return TunnelSession(
                    pairing: pairing,
                    policy: policy,
                    tlsConnector: connector.connector,
                    installWindowTestGate: {
                        await successorInstallGate.waitForRelease()
                    }
                )
            }
            return TunnelSession(
                pairing: pairing,
                policy: policy,
                tlsConnector: connector.connector
            )
        },
        retirementCommitTestGate: retirementCommitTestGate,
        stateEmissionTestObserver: stateEmissionTestObserver,
        redriveRequestTestObserver: redriveRequestTestObserver
    )
}

private actor SessionGenerationCounter {
    private var count = 0

    func isSuccessor() -> Bool {
        count += 1
        return count == 2
    }
}

private actor SuccessorInstallGate {
    private let entered = TestSignal()
    private let released = TestSignal()

    func waitForEntry() async throws {
        try await entered.waitWithTimeout()
    }

    func release() async {
        await released.signal()
    }

    func waitForRelease() async {
        await entered.signal()
        await released.wait()
    }
}

private actor OpenReturnGate {
    private let entered = TestSignal()
    private let released = TestSignal()
    private var armed = false

    func arm() {
        armed = true
    }

    func waitForEntry() async throws {
        try await entered.waitWithTimeout()
    }

    func release() async {
        await released.signal()
    }

    func waitForRelease() async {
        guard armed else {
            return
        }
        await entered.signal()
        await released.wait()
    }
}

private actor GatedOpenGeneration: TunnelGeneration {
    nonisolated var stateUpdates: AsyncStream<TunnelState> { base.stateUpdates }
    nonisolated var connectionModeUpdates: AsyncStream<ConnectionMode?> { base.connectionModeUpdates }

    private let base: TunnelSession
    private let gate: OpenReturnGate

    init(base: TunnelSession, gate: OpenReturnGate) {
        self.base = base
        self.gate = gate
    }

    var connectionMode: ConnectionMode? {
        get async { await base.connectionMode }
    }

    func connect(endpoints: [TransportEndpoint]) async throws -> ConnectedVia {
        try await base.connect(endpoints: endpoints)
    }

    func connect(
        endpoints: [TransportEndpoint],
        preferredEndpoint: TransportEndpoint?
    ) async throws -> ConnectedVia {
        try await base.connect(endpoints: endpoints, preferredEndpoint: preferredEndpoint)
    }

    func connectedEndpoint() async -> TransportEndpoint? {
        await base.connectedEndpoint()
    }

    func disconnect() async {
        await base.disconnect()
    }

    func openStream() async throws -> MuxStream {
        // Hold before the mux OPEN so a paused DATA sink cannot deadlock a
        // serialized outbound scheduler (control frames cannot preempt in-flight DATA).
        await gate.waitForRelease()
        return try await base.openStream()
    }

    func inboundActivitySnapshot() async -> UInt64 {
        await base.inboundActivitySnapshot()
    }
}

private final class StateEmissionProbe: Sendable {
    private let states = Mutex<[TunnelState]>([])

    func record(_ state: TunnelState) {
        states.withLock { states in
            states.append(state)
        }
    }

    func count(_ expected: TunnelState) -> Int {
        states.withLock { states in
            states.filter { $0 == expected }.count
        }
    }

    func contains(_ expected: TunnelState) -> Bool {
        states.withLock { states in
            states.contains(expected)
        }
    }

    func totalCount() -> Int {
        states.withLock { $0.count }
    }
}

private final class RedriveRequestProbe: Sendable {
    private let requests = Mutex(0)

    func record() {
        requests.withLock { $0 += 1 }
    }

    func count() -> Int {
        requests.withLock { $0 }
    }
}

private actor TunnelTLSSequence {
    private var values: [any TunnelTLSIO]
    private var gates: [ConnectorReturnGate?]

    init(_ values: [any TunnelTLSIO], gates: [ConnectorReturnGate?] = []) {
        self.values = values
        self.gates = gates + Array(repeating: nil, count: max(0, values.count - gates.count))
    }

    func next() async -> any TunnelTLSIO {
        let value = values.removeFirst()
        let gate = gates.removeFirst()
        await gate?.waitForRelease()
        return value
    }
}

private actor ConnectorReturnGate {
    private let entered = TestSignal()
    private let released = TestSignal()

    func waitForEntry() async {
        await entered.wait()
    }

    func release() async {
        await released.signal()
    }

    func waitForRelease() async {
        await entered.signal()
        await released.wait()
    }
}

private enum ConnectorAttempt: Sendable {
    case tls(any TunnelTLSIO)
    case failure
}

private actor ConnectorAttemptSequence {
    private var attempts: [ConnectorAttempt]
    private var gates: [ConnectorReturnGate?]

    init(_ attempts: [ConnectorAttempt], gates: [ConnectorReturnGate?] = []) {
        self.attempts = attempts
        self.gates = gates + Array(repeating: nil, count: max(0, attempts.count - gates.count))
    }

    func next() async throws -> any TunnelTLSIO {
        let attempt = attempts.removeFirst()
        let gate = gates.removeFirst()
        await gate?.waitForRelease()
        switch attempt {
        case .tls(let tls):
            return tls
        case .failure:
            throw DialError.connectTimeout
        }
    }
}

private func allCandidatesRacePolicy() -> RacePolicy {
    RacePolicy(
        stagger: .milliseconds(0),
        loserGrace: .milliseconds(5),
        budget: .milliseconds(100),
        directConnectTimeout: .milliseconds(100),
        relayOpenTimeout: .milliseconds(100),
        heldRelayTimeout: .milliseconds(100)
    )
}

private func controlledRacePolicy() -> RacePolicy {
    RacePolicy(
        stagger: .milliseconds(0),
        loserGrace: .milliseconds(5),
        budget: .seconds(30),
        directConnectTimeout: .seconds(30),
        relayOpenTimeout: .seconds(30),
        heldRelayTimeout: .seconds(30)
    )
}

private func longFirstBackoff() -> ReconnectBackoff {
    ReconnectBackoff(schedule: .table([.seconds(30)]), random: { _ in 1.0 })
}

private func assertSingleTerminalRevocation(
    states: StateProbe,
    reconnects: ReconnectProbe
) async -> Bool {
    guard await waitForFailure(.revoked, in: states) else {
        #expect(Bool(false))
        return false
    }
    guard await waitUntil("terminal reconnect status", condition: {
        await reconnects.count(terminalRevocationStatus) >= 1
    }) else {
        #expect(Bool(false))
        return false
    }
    let singleFailure = await states.count(.failed(.revoked)) == 1
    let singlePause = await reconnects.count(terminalRevocationStatus) == 1
    #expect(singleFailure)
    #expect(singlePause)
    return singleFailure && singlePause
}

private func directEndpoint(_ host: String) -> TransportEndpoint {
    .lan(host: host, port: 443, scope: "test")
}

private func pairing(
    from fixture: TestCA.Bundle,
    relayEndpoint: String? = nil,
    localEndpoints: [LocalEndpoint] = []
) -> StoredPairing {
    StoredPairing(
        instanceID: fixture.pairing.instanceID,
        homeLabel: fixture.pairing.homeLabel,
        relayEndpoint: relayEndpoint ?? fixture.pairing.relayEndpoint,
        fingerprint: fixture.pairing.fingerprint,
        clientCertPEM: fixture.pairing.clientCertPEM,
        clientKeyPEM: fixture.pairing.clientKeyPEM,
        caChainPEM: fixture.pairing.caChainPEM,
        relayEnrollment: fixture.pairing.relayEnrollment,
        localEndpoints: localEndpoints,
        pairedAt: fixture.pairing.pairedAt
    )
}


private func expectSameEndpoints(_ actual: [TransportEndpoint], _ expected: [TransportEndpoint]) {
    #expect(actual.count == expected.count)
    for endpoint in expected {
        #expect(actual.contains(endpoint))
    }
}
