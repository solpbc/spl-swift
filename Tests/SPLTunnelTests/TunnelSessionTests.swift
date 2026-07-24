// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

private enum TunnelSessionTestError: Error, Sendable, Equatable {
    case timedOut(String)
    case fakePumpFault
}

private let tunnelClientInfo = SPLClientInfo(userAgent: "spl-swift-tests/1")

@Suite(
    "TunnelSession",
    .serialized,
    .enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)")
)
struct TunnelSessionTests {
    @Test func lanHappyPathOpensMuxStreamAndEchoesPayload() async throws {
        // LAN sessions must round-trip through real InnerTLS and NWListener traffic.
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture, mode: .mux)
        try await server.start()
        let port = await server.port
        let pairing = pairing(from: fixture, localEndpoints: [
            LocalEndpoint(host: "127.0.0.1", port: port, scope: "local"),
        ])
        let session = TunnelSession(pairing: pairing, clientInfo: tunnelClientInfo)

        let via = try await session.connect(endpoints: [
            .lan(host: "127.0.0.1", port: port, scope: "local"),
        ])
        try await assertEchoRoundTrip(session: session, payload: Data([0x01, 0x02, 0x03]))
        await session.disconnect()
        await server.stop()

        #expect(via == .lanDirect(host: "127.0.0.1", port: port))
    }

    @Test func relayHappyPathOpensMuxStreamAndEchoesPayload() async throws {
        // Relay sessions must round-trip and enter the presence-hold lifecycle when brokered.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .mux)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = tunnelSessionAllowingPlaintextRelay(pairing: pairing, clientInfo: tunnelClientInfo)

        let via = try await session.connect(endpoints: [
            .relay(endpoint: endpoint, instanceID: pairing.instanceID, deviceToken: deviceToken(from: pairing)),
        ])
        try await assertEchoRoundTrip(session: session, payload: Data([0x04, 0x05, 0x06]))
        await session.disconnect()
        await relay.stop()
        await tlsServer.stop()

        #expect(via == .relay(endpoint: endpoint))
    }

    @Test func disconnectTearsDownAndOpenStreamThrowsNotConnected() async throws {
        // Disconnect must publish terminal state and reject later stream opens.
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture, mode: .mux)
        try await server.start()
        let port = await server.port
        let pairing = pairing(from: fixture, localEndpoints: [
            LocalEndpoint(host: "127.0.0.1", port: port, scope: "local"),
        ])
        let session = TunnelSession(pairing: pairing, clientInfo: tunnelClientInfo)

        _ = try await session.connect(endpoints: [
            .lan(host: "127.0.0.1", port: port, scope: "local"),
        ])
        await session.disconnect()
        await expectSessionError(.notConnected) {
            _ = try await session.openStream()
        }
        await server.stop()
    }

    @Test func connectAfterDisconnectThrowsNotConnected() async throws {
        // Single-shot invariant: disconnect terminates the session and forbids a second generation.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)

        _ = try await session.connect(endpoints: [endpoint])
        await session.disconnect()
        await expectSessionError(.notConnected) {
            try await session.connect(endpoints: [endpoint])
        }
        #expect(await connector.invocationCount == 1)
    }

    @Test func directKeepaliveDropControlPublishesDirectKeepaliveMissed() async throws {
        // Direct-mode keepalive loss must surface as a direct keepalive miss.
        let fixture = try TestCA.make()
        let server = TLSEchoServer(bundle: fixture, mode: .muxDropControl)
        try await server.start()
        let port = await server.port
        let pairing = pairing(from: fixture, localEndpoints: [
            LocalEndpoint(host: "127.0.0.1", port: port, scope: "local"),
        ])
        let session = TunnelSession(
            pairing: pairing,
            clientInfo: tunnelClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: false)
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [
            .lan(host: "127.0.0.1", port: port, scope: "local"),
        ])
        #expect(await waitForFailure(.directKeepaliveMissed, in: states, timeout: .seconds(2)))
        await session.disconnect()
        await states.stop()
        await server.stop()
    }

    @Test func relayKeepaliveDropControlStaysConnectedWhenRunsOnRelayPathFalse() async throws {
        // Relay keepalive remains off by default unless policy opts in.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .muxDropControl)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = tunnelSessionAllowingPlaintextRelay(
            pairing: pairing,
            clientInfo: tunnelClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: false)
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [
            .relay(endpoint: endpoint, instanceID: pairing.instanceID, deviceToken: deviceToken(from: pairing)),
        ])
        let failed = await conditionObserved(timeout: .milliseconds(200)) {
            await states.containsFailure { _ in true }
        }
        #expect(failed == false)
        try await assertEchoRoundTrip(session: session, payload: Data([0x07, 0x08, 0x09]))
        await session.disconnect()
        await states.stop()
        await relay.stop()
        await tlsServer.stop()
    }

    @Test func relayKeepaliveDropControlPublishesRelayKeepaliveMissedWhenOptedIn() async throws {
        // Relay keepalive policy opt-in must surface relay keepalive misses.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .muxDropControl)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = tunnelSessionAllowingPlaintextRelay(
            pairing: pairing,
            clientInfo: tunnelClientInfo,
            policy: fastKeepalivePolicy(runsOnRelayPath: true)
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [
            .relay(endpoint: endpoint, instanceID: pairing.instanceID, deviceToken: deviceToken(from: pairing)),
        ])
        #expect(await waitForFailure(.relayKeepaliveMissed, in: states, timeout: .seconds(2)))
        await session.disconnect()
        await states.stop()
        await relay.stop()
        await tlsServer.stop()
    }

    @Test func relayAwaitingBrokerCanHoldThenConnectAtSessionLayer() async throws {
        // Presence-hold is client-owned and may wait for the broker before connecting.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let release = TestSignal()
        let awaiting = TestSignal()
        let connector = ConnectorProbe { candidate, _, onAwaitingBroker in
            await onAwaitingBroker(candidate.connectedVia)
            await awaiting.signal()
            await release.wait()
            return tls
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            tlsConnector: connector.connector
        )
        let states = await stateProbe(for: session)
        let task = Task {
            try await session.connect(endpoints: [endpoint])
        }

        try await awaiting.waitWithTimeout()
        #expect(await waitForState(.awaitingBroker(via: endpoint.connectedVia), in: states))
        await release.signal()
        #expect(try await task.value == endpoint.connectedVia)
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }

    @Test func connectingStateCarriesNoRelaySecrets() async throws {
        // Secret-free state invariant: public TunnelState payloads must not carry relay token or instanceID.
        let endpointURL = try #require(URL(string: "wss://relay.example/session"))
        let endpoint = TransportEndpoint.relay(
            endpoint: endpointURL,
            instanceID: "secret-instance",
            deviceToken: "secret-token"
        )
        let release = TestSignal()
        let connector = ConnectorProbe { _, _, _ in
            await release.wait()
            return FakeTunnelTLS()
        }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)
        let states = await stateProbe(for: session)
        let task = Task {
            try await session.connect(endpoints: [endpoint])
        }

        #expect(await waitUntil("secret-free connecting state") {
            await states.connectingCandidates() == [.relay(endpoint: endpointURL)]
        })
        let candidates = await states.connectingCandidates()
        #expect(candidates == [.relay(endpoint: endpointURL)])
        #expect(String(describing: candidates).contains("secret-token") == false)
        #expect(String(describing: candidates).contains("secret-instance") == false)
        await release.signal()
        #expect(try await task.value == .relay(endpoint: endpointURL))
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }

    @Test func heldRelayTimeoutFailsWaitingRelayAndClearsRaceWait() async throws {
        // Held relay timeout must clear the RaceCoordinator waiting exemption.
        let direct = TransportEndpoint.lan(host: "127.0.0.1", port: 1, scope: "local")
        let relay = relayEndpoint()
        let awaiting = TestSignal()
        let connector = ConnectorProbe { candidate, _, onAwaitingBroker in
            if candidate.isDirect {
                throw SessionError.unreachable
            }
            await onAwaitingBroker(candidate.connectedVia)
            await awaiting.signal()
            try await Task.sleep(for: .seconds(5))
            return FakeTunnelTLS()
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: SessionPolicy(
                race: RacePolicy(
                    stagger: .milliseconds(1),
                    loserGrace: .milliseconds(1),
                    budget: .milliseconds(20),
                    directConnectTimeout: .milliseconds(20),
                    relayOpenTimeout: .milliseconds(20),
                    heldRelayTimeout: .milliseconds(80)
                )
            ),
            tlsConnector: connector.connector
        )

        try await awaitingConnectFails(.unreachable, session: session, endpoints: [direct, relay], awaiting: awaiting)
        #expect(await connector.invocationCount == 2)
    }

    @Test func pumpEndPublishesInboundClosedNilAndDoesNotReconnect() async throws {
        // Clean EOF must publish terminal closure without reconnecting.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [endpoint])
        await tls.finishInbound()
        #expect(await waitForFailure(.inboundClosed(fault: nil), in: states))
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }

    @Test func pumpFaultPublishesInboundClosedFaultAndDoesNotReconnect() async throws {
        // Decoder and TLS pump faults must surface as distinguishable non-nil faults.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [endpoint])
        await tls.finishInbound(throwing: TunnelSessionTestError.fakePumpFault)
        #expect(await waitForFailure(in: states) { error in
            if case .inboundClosed(let fault) = error {
                return fault == "fakePumpFault"
            }
            return false
        })
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }

    @Test func disconnectBeforePumpEndIgnoresStalePumpEpoch() async throws {
        // Stale pump completion after disconnect must not publish failure.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [endpoint])
        await session.disconnect()
        await tls.finishInbound(throwing: TunnelSessionTestError.fakePumpFault)
        let failed = await conditionObserved(timeout: .milliseconds(100)) {
            await states.containsFailure { _ in true }
        }
        #expect(failed == false)
        #expect(await connector.invocationCount == 1)
        await states.stop()
    }

    @Test func openStreamTransportClosedPublishesMuxClosedTearsDownOnceAndServesNoOpen() async throws {
        // Dead mux handling must coalesce caller failure, terminal state, teardown, and open rejection.
        let endpoint = relayEndpoint()
        let tls = FakeTunnelTLS(sendError: .transportClosed)
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(pairing: fakePairing(), tlsConnector: connector.connector)
        let states = await stateProbe(for: session)
        var servedOpen = false

        _ = try await session.connect(endpoints: [endpoint])
        await expectSessionError(.notConnected) {
            _ = try await session.openStream()
            servedOpen = true
        }

        #expect(servedOpen == false)
        #expect(await waitForFailure(.transportFailed("mux closed"), in: states))
        #expect(await tls.closeCount == 1)
        #expect(await tls.sendCount == 1)
        await expectSessionError(.notConnected) {
            _ = try await session.openStream()
        }
        #expect(await tls.closeCount == 1)
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }
}

private func assertEchoRoundTrip(session: TunnelSession, payload: Data) async throws {
    let stream = try await session.openStream()
    try await stream.write(payload)
    #expect(try await readInboundPayload(from: stream, timeout: .seconds(2)) == payload)
}

private func awaitingConnectFails(
    _ expected: SessionError,
    session: TunnelSession,
    endpoints: [TransportEndpoint],
    awaiting: TestSignal
) async throws {
    let task = Task {
        try await session.connect(endpoints: endpoints)
    }
    try await awaiting.waitWithTimeout()
    do {
        _ = try await withTunnelTestTimeout(.seconds(1)) {
            try await task.value
        }
        Issue.record("Expected \(expected)")
    } catch let error as SessionError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), got \(error)")
    }
}

private func withTunnelTestTimeout<T: Sendable>(
    _ timeout: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw TunnelSessionTestError.timedOut("operation")
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
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

private func deviceToken(from pairing: StoredPairing) -> String {
    if case .enrolled(let deviceToken, _) = pairing.relayEnrollment {
        return deviceToken
    }
    return ""
}
