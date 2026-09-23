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
    ///
    /// Deliberately still counts every reason, so a consumer reading it keeps
    /// the meaning it had before `streamLimitRefusals` existed. Use that field,
    /// not this one, to tell a stream-limit refusal from a transport death.
    public var streamResets: Int
    /// The subset of `streamResets` the peer attributed to its concurrent-stream
    /// cap (`ResetReason.streamLimitExceeded`).
    ///
    /// This is the one refusal a well-behaved client provokes simply by holding
    /// more concurrent streams than the peer admits. It is the case that must be
    /// distinguishable from a genuine transport death, because both reach a
    /// URLSession client as `NSURLErrorNetworkConnectionLost` (-1005).
    public var streamLimitRefusals: Int
    /// Local connections this proxy refused because their first request did
    /// not carry the process's `LoopbackCapability`.
    ///
    /// Either another process on the machine knocked, or one of our own call
    /// sites forgot the capability. Neither reached the tunnel.
    public var capabilityRefusals: Int

    public init(
        streamOpenFailures: Int = 0,
        idleReclaims: Int = 0,
        streamResets: Int = 0,
        streamLimitRefusals: Int = 0,
        capabilityRefusals: Int = 0
    ) {
        self.streamOpenFailures = streamOpenFailures
        self.idleReclaims = idleReclaims
        self.streamResets = streamResets
        self.streamLimitRefusals = streamLimitRefusals
        self.capabilityRefusals = capabilityRefusals
    }
}

/// Notified when the peer resets one of this proxy's streams, with the wire
/// reason it gave.
///
/// A counter alone cannot carry *when* — the proxy is rebuilt on every tunnel
/// reconnect, so its tally starts over while the owner-visible problem does
/// not. A consumer that needs a durable record observes here and writes one at
/// the moment the refusal arrives.
///
/// Called synchronously from the connection's own stream pump as it tears down,
/// so it must not block: hand the reason to a `Task` and return.
public typealias PeerStreamResetObserver = @Sendable (ResetReason) -> Void

final class LoopbackProxyCounters: @unchecked Sendable {
    // why: incremented from detached per-connection tasks, read from the actor.
    private let state = OSAllocatedUnfairLock(initialState: LoopbackProxyStats())

    func noteStreamOpenFailure() { state.withLock { $0.streamOpenFailures += 1 } }
    func noteIdleReclaim() { state.withLock { $0.idleReclaims += 1 } }
    func noteCapabilityRefusal() { state.withLock { $0.capabilityRefusals += 1 } }

    /// A peer reset carries its reason on the wire; record which one it was.
    ///
    /// `MuxError.streamLimitExceeded` is a *different* condition — this
    /// multiplexer refusing its own local open — and is counted by
    /// `noteStreamOpenFailure()`. Only a reset the peer sent lands here.
    func noteStreamReset(reason: ResetReason) {
        state.withLock {
            $0.streamResets += 1
            if reason == .streamLimitExceeded {
                $0.streamLimitRefusals += 1
            }
        }
    }

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
    private let onPeerStreamReset: PeerStreamResetObserver?
    private let capability: LoopbackCapability
    private var listener: NWListener?
    private var connectionTasks: [UUID: Task<Void, Never>] = [:]

    public init(
        opener: any MuxStreamOpening,
        idleReclaimAfter: Duration = LoopbackProxy.defaultIdleReclaim,
        onPeerStreamReset: PeerStreamResetObserver? = nil,
        capability: LoopbackCapability = .process
    ) {
        self.opener = opener
        self.idleReclaimAfter = idleReclaimAfter
        self.onPeerStreamReset = onPeerStreamReset
        self.capability = capability
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
        let onPeerStreamReset = self.onPeerStreamReset
        let capability = self.capability
        let id = UUID()
        let task = Task {
            await Self.handle(
                connection: connection,
                opener: opener,
                counters: counters,
                idleReclaimAfter: idleReclaimAfter,
                onPeerStreamReset: onPeerStreamReset,
                capability: capability
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
        idleReclaimAfter: Duration,
        onPeerStreamReset: PeerStreamResetObserver?,
        capability: LoopbackCapability
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
            // once this TCP connection has sent a request head carrying the
            // capability, preserving every byte read so far.
            var buffered = Data()
            admission: while true {
                let (chunk, isComplete) = try await receive(from: connection)
                try Task.checkCancellation()
                if let chunk {
                    buffered.append(chunk)
                }
                switch capability.admission(of: buffered) {
                case .admitted:
                    firstRead = (buffered, isComplete)
                    break admission
                case .refused(let refusal):
                    // notice, not debug: a refusal is either a missed call site in
                    // our own app or another process knocking, and both must
                    // survive to a post-hoc log read. Never the header values.
                    counters.noteCapabilityRefusal()
                    logger.notice("loopback connection refused: capability \(refusal.rawValue, privacy: .public)")
                    try? await send(forbiddenResponse(refusal), to: connection)
                    try? await sendEOF(to: connection)
                    if !isComplete {
                        await drainRefused(connection)
                    }
                    return
                case .incomplete:
                    if isComplete || chunk == nil { return }
                }
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
                let bytes = await pumpStream(
                    stream,
                    to: connection,
                    idleGuard: idleGuard,
                    counters: counters,
                    onPeerStreamReset: onPeerStreamReset
                )
                return LoopbackPumpStats(bytesIn: 0, bytesOut: bytes)
            }

            for await stats in group {
                bytesIn += stats.bytesIn
                bytesOut += stats.bytesOut
            }
        }
    }

    /// Reads and discards what a refused client is still sending, until it
    /// closes or a short bound passes.
    ///
    /// Closing a socket with unread bytes resets it, and a client that is still
    /// writing a request body would then see a lost connection instead of the
    /// 403 already sent: a refusal that reads as a transient network failure.
    private nonisolated static func drainRefused(_ connection: NWConnection) async {
        let bound = Task {
            try? await Task.sleep(for: .seconds(2))
            connection.cancel()
        }
        defer { bound.cancel() }
        var drained = 0
        while drained < 64 * 1024 * 1024 {
            guard let (chunk, isComplete) = try? await receive(from: connection) else { return }
            drained += chunk?.count ?? 0
            if isComplete || chunk == nil { return }
        }
    }

    /// Closes a connection that has been silent past `deadline` with no request
    /// in flight, returning its stream slot to the carrier.
    ///
    /// The door frees a slot only when both halves of a stream close, and
    /// nothing in the path times a stream out, so without this an idle
    /// keep-alive connection holds one finite peer slot until the process exits.
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
        counters: LoopbackProxyCounters,
        onPeerStreamReset: PeerStreamResetObserver?
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
            // Keep it — both the counter and the observer are how it survives
            // past this log line, which no consumer reads.
            if let muxError = error as? MuxError, case .streamReset(let streamID, let reason, _) = muxError {
                counters.noteStreamReset(reason: reason)
                onPeerStreamReset?(reason)
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

/// What a connection without the capability gets back. It never reaches the
/// tunnel: no stream is opened for it.
///
/// A plain-text body, not an empty one: an empty 403 renders as a blank page in
/// a web view, or is cancelled as an unshowable MIME type, and either way the
/// refusal is invisible. The marker header lets a client tell this refusal from
/// a journal 403.
private func forbiddenResponse(_ refusal: LoopbackRefusal) -> Data {
    let body = "refused: this connection is missing the solstone app's local secret\n"
    return Data((
        "HTTP/1.1 403 Forbidden\r\n"
            + "Content-Type: text/plain; charset=utf-8\r\n"
            + "X-SPL-Loopback-Refused: \(refusal.rawValue)\r\n"
            + "Content-Length: \(body.utf8.count)\r\n"
            + "Connection: close\r\n\r\n"
            + body
    ).utf8)
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
