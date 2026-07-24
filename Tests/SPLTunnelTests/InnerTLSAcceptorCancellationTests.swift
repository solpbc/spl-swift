// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import Testing
@testable import SPLTunnel

private struct AcceptorCancellationTimeout: Error, Sendable {}

@Suite("InnerTLS acceptor cancellation", .serialized)
struct InnerTLSAcceptorCancellationTests {
    @Test func acceptorCancelResolvesSuspendedWaiter() async throws {
        // L4 §6.3 T3 pins acceptor cancellation resolving a suspended waiter.
        let acceptor = OneShotConnectionAcceptor()
        let started = TestSignal()
        let task = Task {
            await started.signal()
            do {
                _ = try await withTaskCancellationHandler {
                    try await acceptor.wait()
                } onCancel: {
                    acceptor.cancel()
                }
                return WaitOutcome.returned
            } catch InnerTLSError.closed {
                return WaitOutcome.closed
            } catch {
                return WaitOutcome.other
            }
        }

        try await started.waitWithTimeout()
        task.cancel()
        let outcome = try await task.valueWithTimeout()
        #expect(outcome == .closed)
    }

    @Test func acceptorCompleteAfterCancelCancelsLateConnection() async throws {
        // L4 §6.3 T3 pins late accepted connections being cancelled after acceptor cancellation.
        let pair = try await Self.makeConnectionPair()
        defer {
            pair.client.cancel()
            pair.server.cancel()
            pair.listener.cancel()
        }

        let acceptor = OneShotConnectionAcceptor()
        let cancelled = TestSignal()
        pair.server.stateUpdateHandler = { state in
            if case .cancelled = state {
                Task {
                    await cancelled.signal()
                }
            }
        }

        acceptor.cancel()
        acceptor.complete(pair.server)

        try await cancelled.waitWithTimeout()
    }

    @Test func acceptorCancelAfterCompleteCancelsStoredConnection() async throws {
        // L4 §6.3 T3 pins cancellation of a stored accepted connection.
        let pair = try await Self.makeConnectionPair()
        defer {
            pair.client.cancel()
            pair.server.cancel()
            pair.listener.cancel()
        }

        let acceptor = OneShotConnectionAcceptor()
        let cancelled = TestSignal()
        pair.server.stateUpdateHandler = { state in
            if case .cancelled = state {
                Task {
                    await cancelled.signal()
                }
            }
        }

        acceptor.complete(pair.server)
        acceptor.cancel()

        try await cancelled.waitWithTimeout()
    }

    @Test func connectionReadyWaiterResolvesWhenConnectionIsCancelled() async throws {
        // L4 §6.3 T3 pins connection-ready waiter cancellation resolving with InnerTLSError.closed.
        let port = NWEndpoint.Port(rawValue: 65_000)!
        let connection = NWConnection(host: "198.51.100.1", port: port, using: .tcp)
        let waiter = startAndReturnReadyWaiter(connection)
        let started = TestSignal()
        let task = Task {
            await started.signal()
            do {
                try await withTaskCancellationHandler {
                    try await waiter.wait()
                } onCancel: {
                    connection.cancel()
                }
                return WaitOutcome.returned
            } catch InnerTLSError.closed {
                return WaitOutcome.closed
            } catch {
                return WaitOutcome.other
            }
        }

        try await started.waitWithTimeout()
        task.cancel()
        let outcome = try await task.valueWithTimeout()
        #expect(outcome == .closed)
    }

    private static func makeConnectionPair() async throws -> ConnectionPair {
        let listener = try NWListener(using: .tcp, on: .any)
        let ready = ListenerPortWaiter()
        let acceptor = OneShotConnectionAcceptor()
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port {
                    ready.complete(.success(port))
                }
            case .failed(let error):
                ready.complete(.failure(error))
            case .cancelled, .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
        listener.newConnectionHandler = { connection in
            acceptor.complete(connection)
        }
        listener.start(queue: .global(qos: .utility))

        let port = try await ready.wait()
        let client = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        let clientWaiter = startAndReturnReadyWaiter(client)
        let server = try await acceptor.wait()
        let serverWaiter = startAndReturnReadyWaiter(server)
        try await clientWaiter.wait()
        try await serverWaiter.wait()
        return ConnectionPair(listener: listener, client: client, server: server)
    }
}

private enum WaitOutcome: Sendable, Equatable {
    case returned
    case closed
    case other
}

private struct ConnectionPair {
    let listener: NWListener
    let client: NWConnection
    let server: NWConnection
}

private actor TestSignal {
    private var isSignaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        guard !isSignaled else {
            return
        }
        isSignaled = true
        let waiters = waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    func wait() async {
        if isSignaled {
            return
        }
        await withCheckedContinuation { continuation in
            if isSignaled {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }
}

private final class ListenerPortWaiter: @unchecked Sendable {
    // why: NWListener state callbacks race test tasks; NSLock gives one-shot resume.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<NWEndpoint.Port, Error>?
    private var result: Result<NWEndpoint.Port, Error>?

    func wait() async throws -> NWEndpoint.Port {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<NWEndpoint.Port, Error>) in
            let result: Result<NWEndpoint.Port, Error>? = lock.withLock {
                if let result = self.result {
                    return result
                }
                self.continuation = continuation
                return nil
            }

            if let result {
                continuation.resume(with: result)
            }
        }
    }

    func complete(_ result: Result<NWEndpoint.Port, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<NWEndpoint.Port, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}

private extension TestSignal {
    func waitWithTimeout() async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                await self.wait()
            }
            group.addTask {
                try await Task<Never, Never>.sleep(for: .seconds(1))
                throw AcceptorCancellationTimeout()
            }
            try await group.next()!
            group.cancelAll()
        }
    }
}

private extension Task where Success: Sendable, Failure == Never {
    func valueWithTimeout() async throws -> Success {
        try await withThrowingTaskGroup(of: Success.self) { group in
            group.addTask {
                await value
            }
            group.addTask {
                try await Task<Never, Never>.sleep(for: .seconds(1))
                throw AcceptorCancellationTimeout()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}
