// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
@testable import SPLTunnel

struct TestTimeout: Error, Sendable {}

enum WaitOutcome: Sendable, Equatable {
    case returned
    case closed
    case listenerCancelled
    case other
}

struct ConnectionPair {
    let listener: NWListener
    let client: NWConnection
    let server: NWConnection
}

func makeConnectionPair() async throws -> ConnectionPair {
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

func preReadyNetworkError(from state: NWConnection.State) -> NWError? {
    switch state {
    case .failed(let error), .waiting(let error):
        return error
    case .setup, .preparing, .ready, .cancelled:
        return nil
    @unknown default:
        return nil
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

extension TestSignal {
    func waitWithTimeout() async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                await self.wait()
            }
            group.addTask {
                try await Task<Never, Never>.sleep(for: .seconds(1))
                throw TestTimeout()
            }
            try await group.next()!
            group.cancelAll()
        }
    }
}

extension Task where Success: Sendable, Failure == Never {
    func valueWithTimeout() async throws -> Success {
        try await withThrowingTaskGroup(of: Success.self) { group in
            group.addTask {
                await value
            }
            group.addTask {
                try await Task<Never, Never>.sleep(for: .seconds(1))
                throw TestTimeout()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

actor TestSignal {
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
