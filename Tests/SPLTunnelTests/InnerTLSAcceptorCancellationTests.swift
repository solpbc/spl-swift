// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Network
import Testing
@testable import SPLTunnel

@Suite("InnerTLS acceptor cancellation", .serialized)
struct InnerTLSAcceptorCancellationTests {
    @Test func acceptorCancelResolvesSuspendedWaiter() async throws {
        // Acceptor cancellation must resolve a suspended waiter.
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
        // Late accepted connections must be cancelled after acceptor cancellation.
        let pair = try await makeConnectionPair()
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
        // Cancelling after accept completion must cancel the stored connection.
        let pair = try await makeConnectionPair()
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
        // Cancelling a connection-ready waiter must resolve with InnerTLSError.closed.
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
}
