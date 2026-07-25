// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import os
import Testing
@testable import SPLTunnel

@Suite("LoopbackProxy", .serialized)
struct LoopbackProxyTests {
    @Test func listenerReadyWaiterResolvesWhenListenerIsCancelled() async throws {
        // Listener cancellation must resolve a suspended start waiter.
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let waiter = LoopbackListenerReadyWaiter()
        let cancelled = AsyncResultBox<Bool>()
        let cancelRequested = OSAllocatedUnfairLock(initialState: false)

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard !cancelRequested.withLock({ $0 }) else {
                    return
                }
                if let port = listener.port?.rawValue {
                    waiter.complete(.success(port))
                } else {
                    waiter.complete(.failure(LoopbackProxyError.listenerMissingPort))
                }
            case .failed(let error):
                waiter.complete(.failure(LoopbackProxyError.listenerFailed(error.localizedDescription)))
            case .cancelled:
                Task {
                    await cancelled.store(true)
                }
                waiter.complete(.failure(LoopbackProxyError.listenerCancelled))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
        listener.newConnectionHandler = { connection in
            connection.cancel()
        }

        let listenerQueue = DispatchQueue(label: "test.spl.loopback.listener-cancel")
        listenerQueue.suspend()
        var listenerQueueIsSuspended = true
        defer {
            listener.cancel()
            if listenerQueueIsSuspended {
                listenerQueue.resume()
            }
        }

        listener.start(queue: listenerQueue)

        let outcome = AsyncResultBox<WaitOutcome>()
        let started = AsyncResultBox<Bool>()
        let task = Task {
            await started.store(true)
            do {
                _ = try await withTaskCancellationHandler {
                    try await waiter.wait()
                } onCancel: {
                    cancelRequested.withLock { $0 = true }
                    listener.cancel()
                }
                await outcome.store(.returned)
            } catch LoopbackProxyError.listenerCancelled {
                await outcome.store(.listenerCancelled)
            } catch {
                await outcome.store(.other)
            }
        }

        #expect(await waitUntil("loopback listener waiter started") {
            await started.snapshot() == true
        })
        task.cancel()
        listenerQueue.resume()
        listenerQueueIsSuspended = false

        #expect(await waitUntil("loopback listener cancelled") {
            await cancelled.snapshot() == true
        })
        let didFinish = await waitUntil("loopback listener waiter finished") {
            await outcome.snapshot() != nil
        }
        #expect(didFinish)
        #expect(await outcome.snapshot() == .listenerCancelled)
        if didFinish {
            await task.value
        }

        let doubleCompleteWaiter = LoopbackListenerReadyWaiter()
        doubleCompleteWaiter.complete(.success(1_234))
        doubleCompleteWaiter.complete(.failure(LoopbackProxyError.listenerCancelled))
        #expect(try await doubleCompleteWaiter.wait() == 1_234)

        let completeBeforeWaiter = LoopbackListenerReadyWaiter()
        completeBeforeWaiter.complete(.success(5_678))
        #expect(try await completeBeforeWaiter.wait() == 5_678)
    }

    @Test func receiveCancelCancelsConnectionAndResolves() async throws {
        // Receive cancellation must close the NWConnection.
        let pair = try await makeConnectionPair()
        defer {
            pair.client.cancel()
            pair.server.cancel()
            pair.listener.cancel()
        }

        let cancelled = AsyncResultBox<Bool>()
        pair.server.stateUpdateHandler = { state in
            if case .cancelled = state {
                Task {
                    await cancelled.store(true)
                }
            }
        }
        let outcome = AsyncResultBox<WaitOutcome>()
        let started = AsyncResultBox<Bool>()
        let task = Task {
            await started.store(true)
            do {
                _ = try await LoopbackProxy.receive(from: pair.server)
                await outcome.store(.returned)
            } catch {
                await outcome.store(.other)
            }
        }

        #expect(await waitUntil("loopback receive task started") {
            await started.snapshot() == true
        })
        task.cancel()

        let didFinish = await waitUntil("loopback receive task finished") {
            await outcome.snapshot() != nil
        }
        #expect(didFinish)
        #expect(await waitUntil("loopback receive connection cancelled") {
            await cancelled.snapshot() == true
        })
        if didFinish {
            await task.value
        }
    }

    @Test func sendCancelResolvesPendingSend() async throws {
        // Send cancellation must close the NWConnection.
        let pair = try await makeConnectionPair()
        defer {
            pair.client.cancel()
            pair.server.cancel()
            pair.listener.cancel()
        }

        let cancelled = AsyncResultBox<Bool>()
        pair.client.stateUpdateHandler = { state in
            if case .cancelled = state {
                Task {
                    await cancelled.store(true)
                }
            }
        }
        let outcome = AsyncResultBox<Bool>()
        let started = AsyncResultBox<Bool>()
        let payload = Data(repeating: 0x41, count: 64 * 1024 * 1024)
        let task = Task {
            await started.store(true)
            do {
                try await LoopbackProxy.send(payload, to: pair.client)
                await outcome.store(false)
            } catch {
                await outcome.store(true)
            }
        }

        #expect(await waitUntil("loopback send task started") {
            await started.snapshot() == true
        })
        task.cancel()

        let didFinish = await waitUntil("loopback send task finished") {
            await outcome.snapshot() != nil
        }
        #expect(didFinish)
        #expect(await outcome.snapshot() == true)
        #expect(await waitUntil("loopback send connection cancelled") {
            await cancelled.snapshot() == true
        })
        if didFinish {
            await task.value
        }
    }

    @Test func bidirectionalRoundTripThroughInMemoryOpener() async throws {
        // Loopback proxy must pump bidirectionally between TCP and MuxStream.
        let request = Data("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8)
        let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".utf8)
        let opener = InMemoryLoopbackOpener(response: response)

        try await Self.withLoopbackProxy(opener: opener) { _, port in
            let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
            let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
            defer {
                client.cancel()
            }

            let ready = startAndReturnReadyWaiter(client)
            try await ready.wait()
            let responseBox = AsyncResultBox<Data>()
            let receiver = Task {
                do {
                    let data = try await Self.collectResponse(from: client)
                    await responseBox.store(data)
                } catch {
                    await responseBox.store(Data())
                }
            }

            try await Self.sendFinal(request, to: client)
            let didCaptureRequest = await waitUntil("loopback opener captured request") {
                await opener.capturedRequest() == request
            }
            #expect(didCaptureRequest)
            let didReceiveResponse = await waitUntil("loopback client received response") {
                await responseBox.snapshot() != nil
            }
            #expect(didReceiveResponse)
            #expect(await responseBox.snapshot() == response)
            if didReceiveResponse {
                await receiver.value
            } else {
                receiver.cancel()
            }
        }
    }

    @Test func shortLivedConnectionChurnDoesNotRetainCompletedTasks() async throws {
        // Actor-owned task bookkeeping must stay bounded under short-lived connection churn.
        let churnCount = 200
        let opener = FailingLoopbackOpener()

        try await Self.withLoopbackProxy(opener: opener) { proxy, port in
            let endpointPort = try #require(NWEndpoint.Port(rawValue: port))
            var clients: [NWConnection] = []
            clients.reserveCapacity(churnCount)
            defer {
                for client in clients {
                    client.cancel()
                }
            }

            for _ in 0..<churnCount {
                let client = NWConnection(host: "127.0.0.1", port: endpointPort, using: .tcp)
                clients.append(client)
                client.start(queue: .global(qos: .utility))
            }

            // 200 real loopback connections need more than the 500 ms default: the
            // bound is a safety net on a completion signal, not a timing assertion.
            #expect(await waitUntil("loopback churn accepted", timeout: .seconds(10)) {
                await opener.attemptCount() >= churnCount
            })
            for _ in 0..<100 {
                await Task.yield()
            }

            let retainedCount = await proxy.connectionTaskCount()
            #expect(retainedCount == 0)
        }
    }

    @Test(.enabled(if: IdentityAssemblyCapability.isAvailable, "\(IdentityAssemblyCapability.reason)"))
    func supervisorLoopbackPortStaysStableAcrossReconnectGenerations() async throws {
        let fixture = try TestCA.make()
        let tunnelPort = FixedPortReclaimTestPorts.loopbackProxyRebindPort
        var server = TLSEchoServer(bundle: fixture, mode: .mux)
        try await server.start(port: tunnelPort)
        let endpoint = TransportEndpoint.lan(host: "127.0.0.1", port: tunnelPort, scope: "local")
        let supervisor = TunnelSupervisor(
            pairing: loopbackPairing(from: fixture, localEndpoints: [
                LocalEndpoint(host: "127.0.0.1", port: tunnelPort, scope: "local"),
            ]),
            clientInfo: SPLClientInfo(userAgent: "spl-swift-loopback-tests/1"),
            policy: fastKeepalivePolicy(runsOnRelayPath: false),
            sleeper: { _ in }
        )
        let proxy = LoopbackProxy(opener: supervisor)
        let states = await stateProbe(for: supervisor)

        do {
            let loopbackPort = try await proxy.start()
            _ = try await supervisor.connect(endpoints: [endpoint])
            var connectedCount = await states.count(.connected(via: endpoint.connectedVia))

            for _ in 0..<3 {
                await server.stop()
                server = TLSEchoServer(bundle: fixture, mode: .mux)
                try await server.start(port: tunnelPort)
                connectedCount += 1
                let expectedConnectedCount = connectedCount
                #expect(await waitUntil("stable loopback supervisor reconnect", timeout: .seconds(3)) {
                    await states.count(.connected(via: endpoint.connectedVia)) >= expectedConnectedCount
                })
                #expect(try await proxy.start() == loopbackPort)
            }

            await proxy.stop()
            await supervisor.disconnect()
            await states.stop()
            await server.stop()
        } catch {
            await proxy.stop()
            await supervisor.disconnect()
            await states.stop()
            await server.stop()
            throw error
        }
    }

    private static func withLoopbackProxy<T: Sendable>(
        opener: any MuxStreamOpening,
        operation: (LoopbackProxy, UInt16) async throws -> T
    ) async throws -> T {
        let proxy = LoopbackProxy(opener: opener)
        do {
            let port = try await proxy.start()
            let result = try await operation(proxy, port)
            await proxy.stop()
            return result
        } catch {
            await proxy.stop()
            throw error
        }
    }

    private static func sendFinal(_ data: Data, to connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: data,
                    contentContext: .finalMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume()
                        }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func collectResponse(from connection: NWConnection) async throws -> Data {
        var response = Data()
        while true {
            let (chunk, isComplete) = try await LoopbackProxy.receive(from: connection)
            if let chunk {
                response.append(chunk)
            }
            if isComplete || chunk == nil {
                return response
            }
        }
    }
}

private struct LoopbackTestError: Error, Sendable {}

private func loopbackPairing(
    from fixture: TestCA.Bundle,
    localEndpoints: [LocalEndpoint] = []
) -> StoredPairing {
    StoredPairing(
        instanceID: fixture.pairing.instanceID,
        homeLabel: fixture.pairing.homeLabel,
        relayEndpoint: fixture.pairing.relayEndpoint,
        fingerprint: fixture.pairing.fingerprint,
        clientCertPEM: fixture.pairing.clientCertPEM,
        clientKeyPEM: fixture.pairing.clientKeyPEM,
        caChainPEM: fixture.pairing.caChainPEM,
        relayEnrollment: fixture.pairing.relayEnrollment,
        localEndpoints: localEndpoints,
        pairedAt: fixture.pairing.pairedAt
    )
}

private actor FailingLoopbackOpener: MuxStreamOpening {
    private var attempts = 0

    func openStream() async throws -> MuxStream {
        attempts += 1
        throw LoopbackTestError()
    }

    func attemptCount() -> Int {
        attempts
    }
}

private actor InMemoryLoopbackOpener: MuxStreamOpening {
    private let response: Data
    private var request = Data()
    private var decoder = FrameDecoder()
    private var stream: MuxStream?
    private var nextStreamID: UInt32 = 1

    init(response: Data) {
        self.response = response
    }

    func openStream() async throws -> MuxStream {
        let streamID = nextStreamID
        nextStreamID &+= 2
        let stream = MuxStream(
            id: streamID,
            sink: { bytes in
                try await self.acceptOutbound(bytes)
            },
            onTerminal: { _ in }
        )
        self.stream = stream
        return stream
    }

    func capturedRequest() -> Data {
        request
    }

    private func acceptOutbound(_ bytes: Data) async throws {
        decoder.feed(bytes)
        while let frame = try decoder.next() {
            switch frame.flags {
            case FrameFlags.open.rawValue:
                break
            case FrameFlags.data.rawValue:
                request.append(frame.payload)
            case FrameFlags.close.rawValue:
                guard let stream else {
                    return
                }
                _ = await stream.deliverInboundData(response)
                await stream.deliverInboundClose()
            default:
                break
            }
        }
    }
}
