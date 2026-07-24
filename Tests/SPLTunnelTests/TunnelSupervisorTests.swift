// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private let supervisorClientInfo = SPLClientInfo(userAgent: "spl-swift-supervisor-tests/1")

@Suite(
    "TunnelSupervisor",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct TunnelSupervisorTests {
    @Test func reconnectSurvivesThreeFixedPortServerKillRestartCycles() async throws {
        let fixture = try TestCA.make()
        var server = TLSEchoServer(bundle: fixture, mode: .mux)
        try await server.start()
        let port = await server.port
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

    @Test func trustDirectReordersCachedEndpointFirstWithinCurrentPlannedSet() async throws {
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
        #expect(Array(attempts.dropFirst()) == [trusted, rankedFirst, relay])
        #expect(attempts.count == 1 + planned.count)

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
        #expect(Array(attempts.dropFirst()) == planned)
        #expect(attempts.contains(trusted) == true)
        #expect(Array(attempts.dropFirst()).contains(trusted) == false)
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

        await expectSessionError(.authRefreshRequired) {
            try await supervisor.connect(endpoints: [relay])
        }
        #expect(await waitForFailure(.authRefreshRequired, in: states))
        #expect(await supervisor.reconnectStatus == ReconnectStatus(
            reason: .authRefreshRequired,
            attempt: 1,
            retryAfter: nil,
            terminalPause: true
        ))

        _ = try await supervisor.connect(endpoints: [relay])
        #expect(await factory.count() == 2)

        await supervisor.disconnect()
        await states.stop()
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
        let release = TestSignal()
        let factory = FakeGenerationFactory(scripts: [
            .success(direct),
            .success(direct, gate: release),
        ])
        let supervisor = fakeSupervisor(factory: factory)

        _ = try await supervisor.connect(endpoints: [direct])
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<5 {
                group.addTask {
                    await supervisor.requestReconnect()
                }
            }
        }

        #expect(await waitUntil("coalesced manual reconnect") {
            await factory.count() == 2
        })
        #expect(await supervisor.reconnectStatus == ReconnectStatus(
            reason: nil,
            attempt: 1,
            retryAfter: nil,
            terminalPause: false
        ))
        #expect(await conditionObserved(timeout: .milliseconds(100)) {
            await factory.count() > 2
        } == false)

        await release.signal()
        #expect(await waitUntil("manual reconnect completed") {
            await supervisor.connectionMode == .plDirect
        })
        #expect(await factory.count() == 2)

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

    @Test func cleanDisconnectDoesNotRedriveAfterKeepaliveCancellation() async throws {
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

private func fakeSupervisor(factory: FakeGenerationFactory) -> TunnelSupervisor {
    TunnelSupervisor(
        pairing: fakePairing(),
        clientInfo: supervisorClientInfo,
        reconnectBackoff: ReconnectBackoff(schedule: .table([.milliseconds(1)]), random: { _ in 1.0 }),
        sleeper: { _ in },
        makeSession: { _, _, _ in
            await factory.makeSession()
        }
    )
}

private func supervisorWithConnector(
    _ connector: ConnectorProbe,
    racePolicy: RacePolicy
) -> TunnelSupervisor {
    TunnelSupervisor(
        pairing: fakePairing(),
        clientInfo: supervisorClientInfo,
        policy: SessionPolicy(race: racePolicy),
        reconnectBackoff: ReconnectBackoff(schedule: .table([.milliseconds(1)]), random: { _ in 1.0 }),
        sleeper: { _ in },
        makeSession: { pairing, _, policy in
            TunnelSession(pairing: pairing, policy: policy, tlsConnector: connector.connector)
        }
    )
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

private struct FakeConnectCall: Sendable, Equatable {
    let endpoints: [TransportEndpoint]
    let preferredEndpoint: TransportEndpoint?
}

private struct FakeGenerationScript: Sendable {
    let result: Result<TransportEndpoint, SessionError>
    let gate: TestSignal?
    let openStreamFailure: SessionError?

    static func success(
        _ endpoint: TransportEndpoint,
        gate: TestSignal? = nil,
        openStreamFailure: SessionError? = nil
    ) -> FakeGenerationScript {
        FakeGenerationScript(result: .success(endpoint), gate: gate, openStreamFailure: openStreamFailure)
    }

    static func failure(_ error: SessionError) -> FakeGenerationScript {
        FakeGenerationScript(result: .failure(error), gate: nil, openStreamFailure: nil)
    }
}

private actor FakeGenerationFactory {
    private var scripts: [FakeGenerationScript]
    private var generations: [FakeGeneration] = []

    init(scripts: [FakeGenerationScript]) {
        self.scripts = scripts
    }

    func makeSession() -> any TunnelGeneration {
        let script = scripts.removeFirst()
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

private actor FakeGeneration: TunnelGeneration {
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
            return endpoint.connectedVia
        case .failure(let error):
            publish(.failed(error))
            throw error
        }
    }

    func disconnect() async {
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
        return MuxStream(id: 1, sink: { _ in }, onTerminal: { _ in })
    }

    func inboundActivitySnapshot() async -> UInt64 {
        0
    }

    func connectedEndpoint() -> TransportEndpoint? {
        endpoint
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
