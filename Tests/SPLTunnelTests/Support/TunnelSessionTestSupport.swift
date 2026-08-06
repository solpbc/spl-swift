// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Testing
@testable import SPLTunnel

actor ConnectorProbe {
    private let behavior: @Sendable (
        TransportEndpoint,
        StoredPairing,
        @Sendable (ConnectedVia) async -> Void
    ) async throws -> any TunnelTLSIO
    private var count = 0
    private var endpoints: [TransportEndpoint] = []
    private var countWaiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

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

    func attemptedEndpoints() -> [TransportEndpoint] {
        endpoints
    }

    func waitForInvocationCount(_ target: Int) async {
        if count >= target {
            return
        }
        await withCheckedContinuation { continuation in
            countWaiters.append((target, continuation))
        }
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
        endpoints.append(endpoint)
        resumeSatisfiedWaiters()
        return try await behavior(endpoint, pairing, onAwaitingBroker)
    }

    private func resumeSatisfiedWaiters() {
        var remaining: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []
        for waiter in countWaiters {
            if count >= waiter.target {
                waiter.continuation.resume()
            } else {
                remaining.append(waiter)
            }
        }
        countWaiters = remaining
    }
}

actor FakeTunnelTLS: TunnelTLSIO {
    nonisolated var inbound: AsyncThrowingStream<Data, Error> {
        inboundStream
    }

    private let inboundStream: AsyncThrowingStream<Data, Error>
    private let inboundContinuation: AsyncThrowingStream<Data, Error>.Continuation
    private var sendError: (any Error)?
    private var sendGates: [FakeTunnelTLSSendGate] = []
    private(set) var sendCount = 0
    private(set) var closeCount = 0

    init(sendError: (any Error)? = nil) {
        self.sendError = sendError
        var continuation: AsyncThrowingStream<Data, Error>.Continuation!
        self.inboundStream = AsyncThrowingStream<Data, Error> { continuation = $0 }
        self.inboundContinuation = continuation
    }

    func send(_ data: Data) async throws {
        sendCount += 1
        let gate = sendGates.isEmpty ? nil : sendGates.removeFirst()
        await gate?.waitForRelease()
        if let sendError {
            throw sendError
        }
    }

    func setSendError(_ error: (any Error)?) {
        sendError = error
    }

    func enqueueSendGate(_ gate: FakeTunnelTLSSendGate) {
        sendGates.append(gate)
    }

    func yieldInbound(_ data: Data) {
        inboundContinuation.yield(data)
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

actor FakeTunnelTLSSendGate {
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

actor PongingTunnelTLS: TunnelTLSIO {
    nonisolated var inbound: AsyncThrowingStream<Data, Error> {
        inboundStream
    }

    private let inboundStream: AsyncThrowingStream<Data, Error>
    private let inboundContinuation: AsyncThrowingStream<Data, Error>.Continuation
    private var decoder = FrameDecoder()
    private(set) var applicationFrameCount = 0
    private(set) var closeCount = 0

    init() {
        var continuation: AsyncThrowingStream<Data, Error>.Continuation!
        self.inboundStream = AsyncThrowingStream<Data, Error> { continuation = $0 }
        self.inboundContinuation = continuation
    }

    func send(_ data: Data) async throws {
        decoder.feed(data)
        while let frame = try decoder.next() {
            if frame.streamID == 0, frame.flags == FrameFlags.ping.rawValue {
                inboundContinuation.yield(try encodeFrame(buildPong(nonce: try parseControlNonce(from: frame.payload))))
            } else {
                applicationFrameCount += 1
            }
        }
    }

    func close() async {
        closeCount += 1
        inboundContinuation.finish()
    }
}

func tunnelSessionAllowingPlaintextRelay(
    pairing: StoredPairing,
    clientInfo: SPLClientInfo,
    policy: SessionPolicy = SessionPolicy()
) -> TunnelSession {
    TunnelSession(
        pairing: pairing,
        policy: policy,
        tlsConnector: plaintextRelayTLSConnector(clientInfo: clientInfo, policy: policy)
    )
}

private func plaintextRelayTLSConnector(
    clientInfo: SPLClientInfo,
    policy: SessionPolicy
) -> TunnelTLSConnector {
    { endpoint, pairing, onAwaitingBroker in
        switch endpoint {
        case .lan(let host, let port, _, let unpinnedInterface):
            return try await InnerTLS.connectLAN(
                host: host,
                port: port,
                pairing: pairing,
                unpinnedInterface: unpinnedInterface
            )
        case .relay(let endpointURL, let instanceID, let deviceToken):
            let transport = try await DialClient.dialRelay(
                endpoint: RelayEndpoint.unchecked(endpointURL),
                instanceID: instanceID,
                authToken: deviceToken,
                path: "session/dial",
                clientInfo: clientInfo,
                timeout: policy.race.relayOpenTimeout
            )
            await onAwaitingBroker(.relay(endpoint: endpointURL))
            return try await InnerTLS.connectViaTransport(transport: transport, pairing: pairing)
        }
    }
}

actor StateProbe {
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

    func count(_ expected: TunnelState) -> Int {
        states.filter { $0 == expected }.count
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

func stateProbe(for session: any TunnelSessioning) async -> StateProbe {
    let probe = StateProbe()
    await probe.start(stream: session.stateUpdates)
    return probe
}

func waitForState(
    _ expected: TunnelState,
    in states: StateProbe,
    timeout: Duration = .seconds(1)
) async -> Bool {
    await waitUntil("state \(expected)", timeout: timeout) {
        await states.contains(expected)
    }
}

func waitForFailure(
    _ expected: SessionError,
    in states: StateProbe,
    timeout: Duration = .seconds(1)
) async -> Bool {
    await waitForFailure(in: states, timeout: timeout) { $0 == expected }
}

func waitForFailure(
    in states: StateProbe,
    timeout: Duration = .seconds(1),
    matching: @escaping @Sendable (SessionError) -> Bool
) async -> Bool {
    await waitUntil("failure state", timeout: timeout) {
        await states.containsFailure(matching)
    }
}

func expectSessionError<T: Sendable>(
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

func fastKeepalivePolicy(runsOnRelayPath: Bool) -> SessionPolicy {
    SessionPolicy(
        keepalive: KeepalivePolicy(
            interval: .milliseconds(20),
            missedLimit: 1,
            runsOnRelayPath: runsOnRelayPath
        )
    )
}

func relayEndpoint() -> TransportEndpoint {
    .relay(
        endpoint: URL(string: "wss://relay.example/session")!,
        instanceID: "instance",
        deviceToken: "token"
    )
}

func fakePairing() -> StoredPairing {
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
