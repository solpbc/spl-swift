// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import Network
import os

private let logger = SPLLogging.logger(for: .loopback)

public enum LoopbackProxyError: Error, Sendable, Equatable {
    case listenerMissingPort
    case listenerFailed(String)
    case listenerCancelled
}

/// Counts the tunnel-side failures a proxied loopback connection can hit.
///
/// These were invisible before 2026-09-12: a refused stream closed the TCP
/// connection with no response, which a URLSession client reports only as
/// `NSURLErrorNetworkConnectionLost` (-1005) — indistinguishable from a real
/// network loss. A consumer surfaces these in its own diagnostics.
public struct LoopbackProxyStats: Sendable, Equatable {
    /// Local stream opens the multiplexer refused outright (its own cap).
    public var streamOpenFailures: Int
    /// Idle keep-alive connections whose remote stream this proxy reclaimed.
    public var idleReclaims: Int
    /// Streams the peer reset, including its stream-limit refusal.
    public var streamResets: Int

    public init(streamOpenFailures: Int = 0, idleReclaims: Int = 0, streamResets: Int = 0) {
        self.streamOpenFailures = streamOpenFailures
        self.idleReclaims = idleReclaims
        self.streamResets = streamResets
    }
}

final class LoopbackProxyCounters: @unchecked Sendable {
    // why: incremented from detached per-connection tasks, read from the actor.
    private let state = OSAllocatedUnfairLock(initialState: LoopbackProxyStats())

    func noteStreamOpenFailure() { state.withLock { $0.streamOpenFailures += 1 } }
    func noteIdleReclaim() { state.withLock { $0.idleReclaims += 1 } }
    func noteStreamReset() { state.withLock { $0.streamResets += 1 } }
    func snapshot() -> LoopbackProxyStats { state.withLock { $0 } }
}

/// Tracks whether a proxied connection is waiting on a response, and how long
/// it has been silent while it is not.
///
/// A remote stream is held for the whole life of its TCP connection, and the
/// door frees a stream slot only when both halves close. An HTTP keep-alive
/// connection that has finished its response therefore pins a scarce slot
/// while doing nothing. `awaitingResponse` is what keeps a slow request — a
/// large ingest the journal is still processing — from being mistaken for one.
final class LoopbackIdleGuard: @unchecked Sendable {
    private struct State {
        var lastActivity: ContinuousClock.Instant
        var awaitingResponse: Bool
    }

    private let state: OSAllocatedUnfairLock<State>

    init(now: ContinuousClock.Instant = .now) {
        state = OSAllocatedUnfairLock(initialState: State(lastActivity: now, awaitingResponse: false))
    }

    func noteRequestBytes(now: ContinuousClock.Instant = .now) {
        state.withLock {
            $0.lastActivity = now
            $0.awaitingResponse = true
        }
    }

    func noteResponseBytes(now: ContinuousClock.Instant = .now) {
        state.withLock {
            $0.lastActivity = now
            $0.awaitingResponse = false
        }
    }

    /// How long this connection has been silent, or `nil` while a request is
    /// still awaiting its response.
    func idleDuration(now: ContinuousClock.Instant = .now) -> Duration? {
        state.withLock { state in
            state.awaitingResponse ? nil : state.lastActivity.duration(to: now)
        }
    }
}

public actor LoopbackProxy {
    /// Reclaim a remote stream after this long with no bytes in either
    /// direction and no request awaiting a response.
    ///
    /// Above the journal's 15 s SSE heartbeat by a wide margin, so a live
    /// event stream is never mistaken for an idle keep-alive connection.
    public static let defaultIdleReclaim: Duration = .seconds(120)

    private let opener: any MuxStreamOpening
    private let idleReclaimAfter: Duration
    private let counters = LoopbackProxyCounters()
    private var listener: NWListener?
    private var connectionTasks: [UUID: Task<Void, Never>] = [:]

    public init(opener: any MuxStreamOpening, idleReclaimAfter: Duration = LoopbackProxy.defaultIdleReclaim) {
        self.opener = opener
        self.idleReclaimAfter = idleReclaimAfter
    }

    /// Tunnel-side failures seen since this proxy was created.
    public func stats() -> LoopbackProxyStats {
        counters.snapshot()
    }

    public func start() async throws -> UInt16 {
        if let port = listener?.port?.rawValue {
            return port
        }

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let waiter = LoopbackListenerReadyWaiter()

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port?.rawValue {
                    waiter.complete(.success(port))
                } else {
                    waiter.complete(.failure(LoopbackProxyError.listenerMissingPort))
                }
            case .failed(let error):
                waiter.complete(.failure(LoopbackProxyError.listenerFailed(error.localizedDescription)))
            case .cancelled:
                waiter.complete(.failure(LoopbackProxyError.listenerCancelled))
            case .setup, .waiting:
                break
            @unknown default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let proxy = self else {
                connection.cancel()
                return
            }
            Task {
                await proxy.accept(connection: connection)
            }
        }

        self.listener = listener
        listener.start(queue: .global(qos: .utility))
        return try await withTaskCancellationHandler {
            try await waiter.wait()
        } onCancel: {
            listener.cancel()
        }
    }

    public func stop() async {
        listener?.cancel()
        listener = nil

        let tasks = connectionTasks.values
        connectionTasks.removeAll()
        for task in tasks {
            task.cancel()
        }
    }

    // Diverges from the iOS origin: create and store in one actor turn so a
    // short-lived handler cannot remove before the task is recorded.
    private func accept(connection: NWConnection) {
        let opener = self.opener
        let counters = self.counters
        let idleReclaimAfter = self.idleReclaimAfter
        let id = UUID()
        let task = Task {
            await Self.handle(
                connection: connection,
                opener: opener,
                counters: counters,
                idleReclaimAfter: idleReclaimAfter
            )
            self.removeConnectionTask(id)
        }
        connectionTasks[id] = task
    }

    private func removeConnectionTask(_ id: UUID) {
        connectionTasks[id] = nil
    }

    func connectionTaskCount() -> Int {
        connectionTasks.count
    }

    private nonisolated static func handle(
        connection: NWConnection,
        opener: any MuxStreamOpening,
        counters: LoopbackProxyCounters,
        idleReclaimAfter: Duration
    ) async {
        var bytesIn = 0
        var bytesOut = 0
        defer {
            logger.debug("closed connection bytes_in=\(bytesIn, privacy: .public) bytes_out=\(bytesOut, privacy: .public)")
            connection.cancel()
        }

        connection.start(queue: .global(qos: .utility))
        let stream: MuxStream
        let firstRead: (Data, Bool)
        do {
            // Browser preconnections can remain idle. Allocate a remote stream only
            // when this TCP connection has bytes to forward, preserving its first read.
            while true {
                let (chunk, isComplete) = try await receive(from: connection)
                try Task.checkCancellation()
                if let chunk, !chunk.isEmpty {
                    firstRead = (chunk, isComplete)
                    break
                }
                if isComplete || chunk == nil { return }
            }
            stream = try await opener.openStream()
        } catch is CancellationError {
            return
        } catch {
            // error, not debug: this is the only account of a request that
            // reaches the local client as a bare connection close.
            counters.noteStreamOpenFailure()
            logger.error("loopback stream open refused: \(String(describing: error), privacy: .public)")
            return
        }

        let idleGuard = LoopbackIdleGuard()
        idleGuard.noteRequestBytes()
        let watchdog = Task {
            await reclaimWhenIdle(
                connection,
                stream: stream,
                idleGuard: idleGuard,
                after: idleReclaimAfter,
                counters: counters
            )
        }
        defer { watchdog.cancel() }

        await withTaskGroup(of: LoopbackPumpStats.self) { group in
            group.addTask {
                let bytes = await pumpTCP(connection, to: stream, firstRead: firstRead, idleGuard: idleGuard)
                return LoopbackPumpStats(bytesIn: bytes, bytesOut: 0)
            }
            group.addTask {
                let bytes = await pumpStream(stream, to: connection, idleGuard: idleGuard, counters: counters)
                return LoopbackPumpStats(bytesIn: 0, bytesOut: bytes)
            }

            for await stats in group {
                bytesIn += stats.bytesIn
                bytesOut += stats.bytesOut
            }
        }
    }

    /// Closes a connection that has been silent past `deadline` with no request
    /// in flight, returning its stream slot to the carrier.
    ///
    /// The door frees a slot only when both halves of a stream close, and
    /// nothing in the path times a stream out, so without this an idle
    /// keep-alive connection holds one of eight slots until the process exits.
    /// HTTP/1.1 expects a persistent connection to be closable while idle;
    /// clients re-open transparently.
    private nonisolated static func reclaimWhenIdle(
        _ connection: NWConnection,
        stream: MuxStream,
        idleGuard: LoopbackIdleGuard,
        after deadline: Duration,
        counters: LoopbackProxyCounters
    ) async {
        let tick = min(deadline, .seconds(1))
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: tick)
            } catch {
                return
            }
            guard let idle = idleGuard.idleDuration(), idle >= deadline else { continue }
            counters.noteIdleReclaim()
            logger.notice(
                "reclaiming idle loopback stream stream_id=\(stream.id, privacy: .public) idle_seconds=\(idle.components.seconds, privacy: .public)"
            )
            await stream.reset(reason: .cancel)
            connection.cancel()
            return
        }
    }

    private nonisolated static func pumpTCP(
        _ connection: NWConnection,
        to stream: MuxStream,
        firstRead: (Data, Bool),
        idleGuard: LoopbackIdleGuard
    ) async -> Int {
        var bytes = 0
        var pendingRead: (Data?, Bool)? = firstRead
        while !Task.isCancelled {
            do {
                let (chunk, isComplete): (Data?, Bool)
                if let first = pendingRead {
                    (chunk, isComplete) = first
                    pendingRead = nil
                } else {
                    (chunk, isComplete) = try await receive(from: connection)
                }
                if let chunk, !chunk.isEmpty {
                    bytes += chunk.count
                    idleGuard.noteRequestBytes()
                    try await stream.write(chunk)
                }
                if isComplete || chunk == nil {
                    try? await stream.close()
                    return bytes
                }
            } catch {
                await stream.reset(reason: .internalError)
                return bytes
            }
        }
        await stream.reset(reason: .cancel)
        return bytes
    }

    private nonisolated static func pumpStream(
        _ stream: MuxStream,
        to connection: NWConnection,
        idleGuard: LoopbackIdleGuard,
        counters: LoopbackProxyCounters
    ) async -> Int {
        var bytes = 0
        do {
            for try await chunk in stream.inbound {
                bytes += chunk.count
                idleGuard.noteResponseBytes()
                try await send(chunk, to: connection)
            }
            try? await sendEOF(to: connection)
        } catch {
            // The peer's reset reason is the only explanation the local client
            // will never see: it reaches URLSession as a bare connection close.
            if let muxError = error as? MuxError, case .streamReset(let streamID, let reason, _) = muxError {
                counters.noteStreamReset()
                logger.error(
                    "loopback stream reset by peer stream_id=\(streamID, privacy: .public) reason=\(String(describing: reason), privacy: .public)"
                )
            } else {
                logger.error("loopback stream failed: \(String(describing: error), privacy: .public)")
            }
            connection.cancel()
        }
        return bytes
    }

    nonisolated static func receive(from connection: NWConnection) async throws -> (Data?, Bool) {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }
                    continuation.resume(returning: (data, isComplete))
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    nonisolated static func send(_ data: Data, to connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private nonisolated static func sendEOF(to connection: NWConnection) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: nil,
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
}

private struct LoopbackPumpStats: Sendable {
    var bytesIn: Int
    var bytesOut: Int
}

final class LoopbackListenerReadyWaiter: @unchecked Sendable {
    // why: NWListener invokes state callbacks on a dispatch queue while start() awaits; NSLock guards one-shot result delivery.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<UInt16, Error>?
    private var result: Result<UInt16, Error>?

    func wait() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            let result: Result<UInt16, Error>? = lock.withLock {
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

    func complete(_ result: Result<UInt16, Error>) {
        let continuation = lock.withLock {
            guard self.result == nil else {
                return nil as CheckedContinuation<UInt16, Error>?
            }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(with: result)
    }
}
