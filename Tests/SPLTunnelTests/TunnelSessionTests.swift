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
        // §9.4 pins LAN single-shot session round trip through real InnerTLS/NWListener traffic.
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
        // §9.4/S2 pins relay single-shot session round trip and presence-hold lifecycle entrypoint.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .mux)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = TunnelSession(pairing: pairing, clientInfo: tunnelClientInfo)

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
        // §9.4 pins disconnect terminal behavior for the single-shot session.
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
        // S8 pins framing.md:163-169 direct-mode keepalive failure classification.
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
        // X10 pins framing.md:163-169 direct-mode default: relay keepalive is off unless opted in.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .muxDropControl)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = TunnelSession(
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
        // X10 pins the macOS opt-in relay keepalive policy.
        let fixture = try TestCA.make()
        let tlsServer = TLSEchoServer(bundle: fixture, mode: .muxDropControl)
        try await tlsServer.start()
        let relay = RelayBridgeServer(tlsPort: await tlsServer.port)
        try await relay.start()
        let endpoint = try #require(URL(string: "ws://127.0.0.1:\(await relay.port)"))
        let pairing = pairing(from: fixture, relayEndpoint: endpoint.absoluteString)
        let session = TunnelSession(
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
        // S2 pins session.md:340,344 presence-hold and client-owned waiting lifecycle.
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
        // S2+S12 pins session.md:344 and the RaceCoordinator waiting exemption clearing path.
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
        // S3 pins clean EOF terminal publish and no reconnect path.
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
        // S3 pins decoder/TLS pump fault surfacing as distinguishable non-nil fault.
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
        // S3 pins pump epoch handling: stale pump completion after disconnect must not publish failure.
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
        // S7 pins dead mux: caller .notConnected, terminal .transportFailed("mux closed"), one teardown, zero opens.
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

private actor ConnectorProbe {
    private let behavior: @Sendable (
        TransportEndpoint,
        StoredPairing,
        @Sendable (ConnectedVia) async -> Void
    ) async throws -> any TunnelTLSIO
    private var count = 0

    init(
        behavior: @escaping @Sendable (
            TransportEndpoint,
            StoredPairing,
            @Sendable (ConnectedVia) async -> Void
        ) async throws -> any TunnelTLSIO
    ) {
        self.behavior = behavior
    }

    var invocationCount: Int {
        count
    }

    nonisolated var connector: TunnelTLSConnector {
        { endpoint, pairing, onAwaitingBroker in
            try await self.connect(endpoint: endpoint, pairing: pairing, onAwaitingBroker: onAwaitingBroker)
        }
    }

    private func connect(
        endpoint: TransportEndpoint,
        pairing: StoredPairing,
        onAwaitingBroker: @Sendable (ConnectedVia) async -> Void
    ) async throws -> any TunnelTLSIO {
        count += 1
        return try await behavior(endpoint, pairing, onAwaitingBroker)
    }
}

private actor FakeTunnelTLS: TunnelTLSIO {
    nonisolated var inbound: AsyncThrowingStream<Data, Error> {
        inboundStream
    }

    private let inboundStream: AsyncThrowingStream<Data, Error>
    private let inboundContinuation: AsyncThrowingStream<Data, Error>.Continuation
    private let sendError: MuxError?
    private(set) var sendCount = 0
    private(set) var closeCount = 0

    init(sendError: MuxError? = nil) {
        self.sendError = sendError
        var continuation: AsyncThrowingStream<Data, Error>.Continuation!
        self.inboundStream = AsyncThrowingStream<Data, Error> { continuation = $0 }
        self.inboundContinuation = continuation
    }

    func send(_ data: Data) async throws {
        sendCount += 1
        if let sendError {
            throw sendError
        }
    }

    func close() async {
        closeCount += 1
        inboundContinuation.finish()
    }

    func finishInbound(throwing error: (any Error)? = nil) {
        if let error {
            inboundContinuation.finish(throwing: error)
        } else {
            inboundContinuation.finish()
        }
    }
}

private actor StateProbe {
    private var states: [TunnelState] = []
    private var task: Task<Void, Never>?

    func start(stream: AsyncStream<TunnelState>) {
        guard task == nil else {
            return
        }
        task = Task { [weak self] in
            for await state in stream {
                await self?.record(state)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    func contains(_ expected: TunnelState) -> Bool {
        states.contains(expected)
    }

    func connectingCandidates() -> [ConnectedVia]? {
        states.compactMap { state in
            if case .connecting(let candidates) = state {
                return candidates
            }
            return nil
        }.first
    }

    func containsFailure(_ matches: @Sendable (SessionError) -> Bool) -> Bool {
        states.contains { state in
            if case .failed(let error) = state {
                return matches(error)
            }
            return false
        }
    }

    private func record(_ state: TunnelState) {
        states.append(state)
    }
}

private func stateProbe(for session: TunnelSession) async -> StateProbe {
    let probe = StateProbe()
    await probe.start(stream: session.stateUpdates)
    return probe
}

private func assertEchoRoundTrip(session: TunnelSession, payload: Data) async throws {
    let stream = try await session.openStream()
    try await stream.write(payload)
    #expect(try await readInboundPayload(from: stream, timeout: .seconds(2)) == payload)
}

private func waitForState(
    _ expected: TunnelState,
    in states: StateProbe,
    timeout: Duration = .seconds(1)
) async -> Bool {
    await waitUntil("state \(expected)", timeout: timeout) {
        await states.contains(expected)
    }
}

private func waitForFailure(
    _ expected: SessionError,
    in states: StateProbe,
    timeout: Duration = .seconds(1)
) async -> Bool {
    await waitForFailure(in: states, timeout: timeout) { $0 == expected }
}

private func waitForFailure(
    in states: StateProbe,
    timeout: Duration = .seconds(1),
    matching: @escaping @Sendable (SessionError) -> Bool
) async -> Bool {
    await waitUntil("failure state", timeout: timeout) {
        await states.containsFailure(matching)
    }
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

private func expectSessionError<T: Sendable>(
    _ expected: SessionError,
    operation: () async throws -> T
) async {
    do {
        _ = try await operation()
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

private func fastKeepalivePolicy(runsOnRelayPath: Bool) -> SessionPolicy {
    SessionPolicy(
        keepalive: KeepalivePolicy(
            interval: .milliseconds(20),
            idleThreshold: .milliseconds(20),
            missedLimit: 1,
            runsOnRelayPath: runsOnRelayPath
        )
    )
}

private func relayEndpoint() -> TransportEndpoint {
    .relay(
        endpoint: URL(string: "wss://relay.example/session")!,
        instanceID: "instance",
        deviceToken: "token"
    )
}

private func fakePairing() -> StoredPairing {
    StoredPairing(
        instanceID: "instance",
        homeLabel: "home",
        relayEndpoint: "wss://relay.example/session",
        fingerprint: "fingerprint",
        clientCertPEM: "cert",
        clientKeyPEM: "key",
        caChainPEM: "ca",
        relayEnrollment: .enrolled(deviceToken: "token", expiresAt: nil),
        pairedAt: Date(timeIntervalSince1970: 0)
    )
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
