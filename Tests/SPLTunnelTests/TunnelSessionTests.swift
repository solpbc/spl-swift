// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
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
        #expect(await states.count(.failed(.directKeepaliveMissed)) == 1)
        await expectSessionError(.notConnected) {
            _ = try await session.openStream()
        }
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

    @Test func continuousValidPongsKeepTransportConnectedWithoutApplicationRequests() async throws {
        // Keepalive proves transport liveness, not application success.
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: 443, scope: "local")
        let tls = PongingTunnelTLS()
        let gate = KeepaliveTickGate()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: SessionPolicy(keepalive: KeepalivePolicy(
                interval: .milliseconds(500),
                missedLimit: 3,
                runsOnRelayPath: false
            )),
            tlsConnector: connector.connector,
            makeMultiplexer: { tls in
                Multiplexer(
                    sink: { data in try await tls.send(data) },
                    sleeper: { duration in try await gate.sleep(duration) }
                )
            }
        )
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [endpoint])
        for tick in 1...6 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
        }

        #expect(await states.contains(.connected(via: endpoint.connectedVia)))
        #expect(await states.containsFailure { _ in true } == false)
        #expect(await tls.applicationFrameCount == 0)
        await session.disconnect()
        await states.stop()
        await gate.cancelAll()
    }

    @Test func keepaliveLossDuringInstallThrowsAndTearsDownWithoutDurableConnected() async throws {
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: 443, scope: "local")
        let tls = FakeTunnelTLS()
        let gate = KeepaliveTickGate()
        let latched = TestSignal()
        let connector = ConnectorProbe { _, _, _ in tls }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: SessionPolicy(keepalive: KeepalivePolicy(
                interval: .milliseconds(500),
                missedLimit: 1,
                runsOnRelayPath: false
            )),
            tlsConnector: connector.connector,
            makeMultiplexer: { _ in
                Multiplexer(
                    sink: { _ in },
                    sleeper: { duration in try await gate.sleep(duration) }
                )
            },
            installWindowTestGate: {
                await gate.waitForObservedTick(count: 1)
                await gate.releaseOne()
                await gate.waitForObservedTick(count: 2)
                await gate.releaseOne()
                do {
                    try await latched.waitWithTimeout()
                } catch {
                    Issue.record("keepalive loss did not latch before publishConnected")
                }
            },
            pendingInstallFailureTestObserver: {
                await latched.signal()
            }
        )
        let states = await stateProbe(for: session)

        await expectSessionError(.directKeepaliveMissed) {
            try await session.connect(endpoints: [endpoint])
        }

        #expect(await states.count(.connected(via: endpoint.connectedVia)) == 0)
        #expect(await states.count(.failed(.directKeepaliveMissed)) == 1)
        #expect(await tls.closeCount == 1)
        await session.disconnect()
        await states.stop()
        await gate.cancelAll()
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

    @Test func inboundEndDuringDirectInstallThrowsInboundClosedWithoutDurableConnected() async throws {
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: 443, scope: "local")
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in
            await tls.finishInbound()
            return tls
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            tlsConnector: connector.connector
        )
        let states = await stateProbe(for: session)

        await expectSessionError(.inboundClosed(fault: nil)) {
            try await session.connect(endpoints: [endpoint])
        }

        #expect(await states.count(.connected(via: endpoint.connectedVia)) == 0)
        #expect(await waitForFailure(.inboundClosed(fault: nil), in: states))
        #expect(await connector.invocationCount == 1)
        await session.disconnect()
        await states.stop()
    }

    @Test func inboundFaultDuringDirectInstallThrowsInboundClosedFaultWithoutDurableConnected() async throws {
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: 443, scope: "local")
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in
            await tls.finishInbound(throwing: TunnelSessionTestError.fakePumpFault)
            return tls
        }
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            tlsConnector: connector.connector
        )
        let states = await stateProbe(for: session)

        await expectSessionError(.inboundClosed(fault: "fakePumpFault")) {
            try await session.connect(endpoints: [endpoint])
        }

        #expect(await states.count(.connected(via: endpoint.connectedVia)) == 0)
        #expect(await waitForFailure(.inboundClosed(fault: "fakePumpFault"), in: states))
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
        let tls = FakeTunnelTLS(sendError: MuxError.transportClosed)
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

    @Test(arguments: PostReadyTerminalCase.allCases)
    func peerAccessDeniedPostReadyIngressesFailOnce(_ testCase: PostReadyTerminalCase) async throws {
        // Security/SecBase.h: errSSLPeerAccessDenied reaches terminal session handling from every mux write ingress.
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let gate = KeepaliveTickGate()
        let session: TunnelSession
        let policy = fastKeepalivePolicy(runsOnRelayPath: true)
        if testCase.ingress == .keepalive {
            session = TunnelSession(
                pairing: fakePairing(),
                policy: policy,
                tlsConnector: connector.connector,
                makeMultiplexer: { tls in
                    Multiplexer(
                        sink: { data in try await tls.send(data) },
                        sleeper: { duration in try await gate.sleep(duration) }
                    )
                }
            )
        } else {
            session = TunnelSession(pairing: fakePairing(), policy: policy, tlsConnector: connector.connector)
        }
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [testCase.endpoint])
        await tls.setSendError(NWError.tls(-9832))
        try await trigger(
            testCase.ingress,
            tlsStatus: -9832,
            expectation: .sessionError(.revoked),
            session: session,
            tls: tls,
            keepaliveGate: gate
        )

        #expect(await waitForFailure(.revoked, in: states))
        #expect(await states.count(.failed(.revoked)) == 1)
        #expect(await states.containsFailure { $0 != .revoked } == false)
        #expect(await tls.closeCount == 1)
        await session.disconnect()
        await states.stop()
        await gate.cancelAll()
    }

    @Test(arguments: PostReadyTerminalCase.allCases)
    func peerInternalErrorPostReadyIngressesRetainCurrentBehavior(_ testCase: PostReadyTerminalCase) async throws {
        // Security/SecBase.h: errSSLPeerInternalError is nonterminal at every post-ready ingress.
        let tls = FakeTunnelTLS()
        let connector = ConnectorProbe { _, _, _ in tls }
        let gate = KeepaliveTickGate()
        let policy = fastKeepalivePolicy(runsOnRelayPath: true)
        let session: TunnelSession
        if testCase.ingress == .keepalive {
            session = TunnelSession(
                pairing: fakePairing(),
                policy: policy,
                tlsConnector: connector.connector,
                makeMultiplexer: { tls in
                    Multiplexer(
                        sink: { data in try await tls.send(data) },
                        sleeper: { duration in try await gate.sleep(duration) }
                    )
                }
            )
        } else {
            session = TunnelSession(pairing: fakePairing(), policy: policy, tlsConnector: connector.connector)
        }
        let states = await stateProbe(for: session)

        _ = try await session.connect(endpoints: [testCase.endpoint])
        await tls.setSendError(NWError.tls(-9838))
        try await trigger(
            testCase.ingress,
            tlsStatus: -9838,
            expectation: .rawTLS(-9838),
            session: session,
            tls: tls,
            keepaliveGate: gate
        )

        switch testCase.ingress {
        case .receive, .pong, .unknownStreamReset, .isolateReset:
            // The inbound pump still classifies ordinary mux and receive failures as inbound closure.
            #expect(await waitForFailure(in: states) { error in
                if case .inboundClosed = error {
                    return true
                }
                return false
            })
        case .open, .write, .close, .window:
            // trigger observes the original raw Network.framework error at the propagating boundary.
            break
        case .reset:
            // reset suppresses its send error; a second stream write proves the session remains usable.
            await tls.setSendError(nil)
            let stream = try await session.openStream()
            try await stream.write(Data([0x01]))
        case .keepalive:
            let expected: SessionError
            switch testCase.endpoint {
            case .lan:
                expected = .directKeepaliveMissed
            case .relay:
                expected = .relayKeepaliveMissed
            }
            #expect(await waitForFailure(expected, in: states))
        }

        #expect(await states.count(.failed(.revoked)) == 0)
        await session.disconnect()
        await states.stop()
        await gate.cancelAll()
    }

    @Test func terminalInstallFailureOverridesGenericAndGenericCannotReplaceTerminal() async throws {
        // A terminal peer denial must win the pre-publish failure latch in either arrival order.
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: 443, scope: "local")
        let tls = FakeTunnelTLS(sendError: NWError.tls(-9832))
        let gate = KeepaliveTickGate()
        let latches = InstallFailureLatchProbe()
        let session = TunnelSession(
            pairing: fakePairing(),
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            tlsConnector: ConnectorProbe { _, _, _ in
                await tls.finishInbound(throwing: TunnelSessionTestError.fakePumpFault)
                return tls
            }.connector,
            makeMultiplexer: { tls in
                Multiplexer(
                    sink: { data in try await tls.send(data) },
                    sleeper: { duration in try await gate.sleep(duration) }
                )
            },
            installWindowTestGate: {
                await latches.waitForCount(1)
                await gate.waitForObservedTick()
                await gate.releaseOne()
                await latches.waitForCount(2)
            },
            pendingInstallFailureTestObserver: {
                await latches.record()
            }
        )
        let states = await stateProbe(for: session)

        await expectSessionError(.revoked) {
            try await session.connect(endpoints: [endpoint])
        }
        #expect(await states.count(.failed(.revoked)) == 1)
        #expect(await states.containsFailure { $0 == .inboundClosed(fault: "fakePumpFault") } == false)
        await session.disconnect()
        await states.stop()
        await gate.cancelAll()
    }
}

enum PostReadyTerminalIngress: CaseIterable, Sendable {
    case receive
    case open
    case write
    case close
    case reset
    case pong
    case unknownStreamReset
    case isolateReset
    case window
    case keepalive
}

struct PostReadyTerminalCase: Sendable {
    let ingress: PostReadyTerminalIngress
    let endpoint: TransportEndpoint

    static let allCases = PostReadyTerminalIngress.allCases.flatMap { ingress in
        [
            PostReadyTerminalCase(
                ingress: ingress,
                endpoint: .lan(host: "127.0.0.1", port: 443, scope: "local")
            ),
            PostReadyTerminalCase(ingress: ingress, endpoint: relayEndpoint()),
        ]
    }
}

private func trigger(
    _ ingress: PostReadyTerminalIngress,
    tlsStatus: Int32,
    expectation: PostReadyThrowExpectation,
    session: TunnelSession,
    tls: FakeTunnelTLS,
    keepaliveGate: KeepaliveTickGate
) async throws {
    switch ingress {
    case .receive:
        await tls.finishInbound(throwing: NWError.tls(tlsStatus))
    case .open:
        await expectPostReadyThrow(expectation) {
            _ = try await session.openStream()
        }
    case .write:
        await tls.setSendError(nil)
        let stream = try await session.openStream()
        await tls.setSendError(NWError.tls(tlsStatus))
        await expectPostReadyThrow(expectation) {
            try await stream.write(Data([0x01]))
        }
    case .close:
        await tls.setSendError(nil)
        let stream = try await session.openStream()
        await tls.setSendError(NWError.tls(tlsStatus))
        await expectPostReadyThrow(expectation) {
            try await stream.close()
        }
    case .reset:
        await tls.setSendError(nil)
        let stream = try await session.openStream()
        await tls.setSendError(NWError.tls(tlsStatus))
        await stream.reset(reason: .internalError)
    case .pong:
        await tls.yieldInbound(try encodeFrame(buildPing(nonce: Data(repeating: 0, count: 8))))
    case .unknownStreamReset:
        await tls.yieldInbound(rawMuxFrame(streamID: 99, flags: FrameFlags.data.rawValue, payload: Data([0x01])))
    case .isolateReset:
        await tls.setSendError(nil)
        let stream = try await session.openStream()
        await tls.setSendError(NWError.tls(tlsStatus))
        await tls.yieldInbound(rawMuxFrame(
            streamID: stream.id,
            flags: FrameFlags.data.rawValue | FrameFlags.window.rawValue
        ))
    case .window:
        await tls.setSendError(nil)
        let stream = try await session.openStream()
        try await tls.yieldInbound(encodeFrame(buildData(
            streamID: stream.id,
            payload: Data(repeating: 0, count: MuxConstants.windowGrantThreshold)
        )))
        await tls.setSendError(NWError.tls(tlsStatus))
        var iterator = stream.inbound.makeAsyncIterator()
        await expectPostReadyThrow(expectation) {
            _ = try await iterator.next()
        }
    case .keepalive:
        await keepaliveGate.waitForObservedTick()
        await keepaliveGate.releaseOne()
    }
}

private enum PostReadyThrowExpectation: Sendable {
    case rawTLS(Int32)
    case sessionError(SessionError)
}

private func expectPostReadyThrow<T: Sendable>(
    _ expectation: PostReadyThrowExpectation,
    operation: () async throws -> T
) async {
    switch expectation {
    case .rawTLS(let status):
        await expectRawTLSError(status, operation: operation)
    case .sessionError(let error):
        await expectSessionError(error, operation: operation)
    }
}

private func expectRawTLSError<T: Sendable>(
    _ expectedStatus: Int32,
    operation: () async throws -> T
) async {
    do {
        _ = try await operation()
        Issue.record("Expected NWError.tls(\(expectedStatus))")
    } catch let error as NWError {
        #expect(error == .tls(expectedStatus))
    } catch {
        Issue.record("Expected NWError.tls(\(expectedStatus)), got \(error)")
    }
}

private actor InstallFailureLatchProbe {
    private var count = 0
    private var waiters: [(count: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func record() {
        count += 1
        let ready = waiters.filter { count >= $0.count }
        waiters.removeAll { count >= $0.count }
        for waiter in ready {
            waiter.continuation.resume()
        }
    }

    func waitForCount(_ expected: Int) async {
        guard count < expected else {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append((count: expected, continuation: continuation))
        }
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
