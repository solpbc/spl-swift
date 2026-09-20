// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import Foundation
import os
import Security

private let logger = SPLLogging.logger(for: .mux)

public enum MuxError: Error, Equatable, Sendable {
    case flowControlError
    case streamLimitExceeded
    case parityViolation
    case unknownStream
    case transportClosed
    case writeAfterClose
    case payloadTooLarge
    case protocolError
    case streamReset(streamID: UInt32, reason: ResetReason, rawByte: UInt8)
}

public enum TearDownReason: Sendable, Equatable {
    case normalShutdown
    case transportFailure
    case protocolError
}

public enum Role: Sendable {
    case dialer
    case listener
}

private enum PingNonceError: Error, Sendable {
    case generationFailed(OSStatus)
}

private struct OutstandingPing: Sendable {
    let nonce: Data
    let issuedTick: UInt64
}

public struct KeepaliveLossEvent: Sendable, Equatable {
    public enum Reason: Sendable, Equatable {
        case sendFailure
        case missedPingLimit
    }

    public let reason: Reason
    public let missedPingCount: Int
    public let elapsedSinceLastPong: Duration
    public let outboundInFlight: Bool
}

public actor Multiplexer {
    public nonisolated var keepaliveLost: AsyncStream<KeepaliveLossEvent> {
        keepaliveLostStream
    }

    public nonisolated let incomingStreams: AsyncStream<MuxStream>

    private let scheduler: MuxOutboundScheduler
    private let dataSink: @Sendable (Data) async throws -> Void
    private let sleeper: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> ContinuousClock.Instant
    private let role: Role
    private let incomingContinuation: AsyncStream<MuxStream>.Continuation
    private let keepaliveLostStream: AsyncStream<KeepaliveLossEvent>
    private let keepaliveLostContinuation: AsyncStream<KeepaliveLossEvent>.Continuation
    private var nextOutboundID: UInt32
    private var streams: [UInt32: MuxStream] = [:]
    private var tornDown = false
    private var decoder = FrameDecoder()
    private var keepaliveTask: Task<Void, Never>?
    private var outstandingPings: [OutstandingPing] = []
    private var keepaliveTickIndex: UInt64 = 0
    private var inboundActivityCounter: UInt64 = 0
    /// Keepalive tick index current when the newest application-stream frame
    /// arrived. `nil` until the first one after `startKeepalive`.
    private var streamInboundTick: UInt64?
    private var lastMatchedPongAt: ContinuousClock.Instant?
    private var keepaliveStartedAt: ContinuousClock.Instant?

    public init(sink: @escaping @Sendable (Data) async throws -> Void, role: Role = .dialer) {
        self.init(
            sink: sink,
            role: role,
            sleeper: { interval in try await Task.sleep(for: interval) }
        )
    }

    internal init(
        sink: @escaping @Sendable (Data) async throws -> Void,
        role: Role = .dialer,
        sleeper: @escaping @Sendable (Duration) async throws -> Void,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }
    ) {
        let incoming = AsyncStream<MuxStream>.makeStream()
        let keepalive = AsyncStream<KeepaliveLossEvent>.makeStream()
        let scheduler = MuxOutboundScheduler(sink: sink)
        self.scheduler = scheduler
        self.dataSink = { data in
            try await scheduler.send(data, priority: .data)
        }
        self.role = role
        self.sleeper = sleeper
        self.now = now
        self.incomingStreams = incoming.stream
        self.incomingContinuation = incoming.continuation
        self.keepaliveLostStream = keepalive.stream
        self.keepaliveLostContinuation = keepalive.continuation
        self.nextOutboundID = (role == .dialer) ? 1 : 2
    }

    public func openStream() async throws -> MuxStream {
        guard !tornDown else {
            throw MuxError.transportClosed
        }
        guard activeStreamCount() < MuxConstants.maxConcurrentStreams else {
            throw MuxError.streamLimitExceeded
        }

        let id = nextOutboundID
        nextOutboundID &+= 2
        let stream = MuxStream(
            id: id,
            sink: dataSink,
            onTerminal: { [weak self] streamID in
                await self?.evictTerminalStream(id: streamID)
            },
            now: now
        )
        let frame = try encodeFrame(buildOpen(streamID: id))
        streams[id] = stream
        do {
            try await sendControl(frame)
        } catch {
            streams.removeValue(forKey: id)
            throw error
        }
        return stream
    }

    public func feedInbound(_ bytes: Data) async throws {
        guard !tornDown else {
            throw MuxError.transportClosed
        }

        decoder.feed(bytes)
        while let frame = try decoder.next() {
            try await dispatch(frame)
        }
    }

    public func startKeepalive(
        interval: Duration = .milliseconds(500),
        missedLimit: Int = 3,
        deferralLimit: Duration = .seconds(30)
    ) {
        guard keepaliveTask == nil else {
            return
        }

        outstandingPings.removeAll(keepingCapacity: true)
        keepaliveTickIndex = 0
        streamInboundTick = nil
        lastMatchedPongAt = nil
        keepaliveStartedAt = now()
        keepaliveTask = Task {
            await runKeepalive(interval: interval, missedLimit: missedLimit, deferralLimit: deferralLimit)
        }
    }

    public func tearDown(reason: TearDownReason) async {
        guard !tornDown else {
            return
        }

        tornDown = true
        keepaliveTask?.cancel()
        keepaliveTask = nil
        await scheduler.tearDown()
        keepaliveLostContinuation.finish()
        outstandingPings.removeAll(keepingCapacity: true)
        incomingContinuation.finish()
        let openStreams = streams.values
        streams.removeAll()
        for stream in openStreams {
            await stream.tearDown(reason: reason)
        }
    }

    public func inboundActivitySnapshot() -> UInt64 {
        inboundActivityCounter
    }

    func queuedInboundByteCount() async -> Int {
        var total = 0
        for stream in streams.values {
            total += await stream.queuedInboundByteCount()
        }
        return total
    }

    private func dispatch(_ frame: Frame) async throws {
        inboundActivityCounter &+= 1

        let isOpen = frame.flags & FrameFlags.open.rawValue != 0
        let isData = frame.flags & FrameFlags.data.rawValue != 0
        let isClose = frame.flags & FrameFlags.close.rawValue != 0
        let isReset = frame.flags & FrameFlags.reset.rawValue != 0
        let isWindow = frame.flags & FrameFlags.window.rawValue != 0
        let isPing = frame.flags & FrameFlags.ping.rawValue != 0
        let isPong = frame.flags & FrameFlags.pong.rawValue != 0

        if frame.streamID == 0 {
            try await handleControlFrame(frame, isPing: isPing, isPong: isPong)
            return
        }

        // A frame on an application stream is the peer reading or writing our
        // streams right now. The keepalive uses it to tell a PONG that is late
        // behind a full send buffer from a path that has gone dark: a dark path
        // sends nothing at all, control frames included.
        streamInboundTick = keepaliveTickIndex

        let stream = streams[frame.streamID]
        // The peer has spoken on this stream, so it owes us nothing right now.
        // Keyed on this frame's stream: one stream's WINDOW grant must not
        // vouch for another stream that is still waiting on a reply.
        if let stream {
            await stream.noteInboundActivity()
        }

        if !FrameFlags.validCombinations.contains(frame.flags) {
            if let stream {
                try await isolateStream(stream, frame: frame, reason: .protocolError)
            } else {
                try await emitUnknownStreamReset(
                    streamID: frame.streamID,
                    flags: frame.flags,
                    length: frame.payload.count,
                    reason: .protocolError
                )
            }
            return
        }

        if isPing || isPong {
            if let stream {
                try await isolateStream(stream, frame: frame, reason: .protocolError)
            } else {
                try await emitUnknownStreamReset(
                    streamID: frame.streamID,
                    flags: frame.flags,
                    length: frame.payload.count,
                    reason: .protocolError
                )
            }
            return
        }

        if isOpen {
            try await handleInboundOpen(frame)
            return
        }

        guard let stream else {
            if isData || isWindow {
                try await emitUnknownStreamReset(
                    streamID: frame.streamID,
                    flags: frame.flags,
                    length: frame.payload.count,
                    reason: .protocolError
                )
            } else {
                logger.debug(
                    "ignoring frame for unknown stream id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public)"
                )
            }
            return
        }

        if isWindow {
            let credit: UInt32
            do {
                credit = try parseWindowCredit(from: frame.payload)
            } catch {
                try await isolateStream(stream, frame: frame, reason: .protocolError)
                return
            }

            let outcome = await stream.grantSendCredit(credit)
            if outcome == .flowControlExceeded {
                try await isolateStream(stream, frame: frame, reason: .flowControlError)
                return
            }
        }

        if isData {
            let outcome = await stream.deliverInboundData(frame.payload)
            if outcome == .receiveWindowExceeded {
                try await isolateStream(stream, frame: frame, reason: .flowControlError)
                return
            }
        }

        if isClose {
            await stream.deliverInboundClose()
        }

        if isReset {
            let reset = parseResetReason(from: frame.payload)
            await stream.deliverInboundReset(reason: reset.reason, rawByte: reset.rawByte)
        }
    }

    private func handleInboundOpen(_ frame: Frame) async throws {
        let isOdd = frame.streamID % 2 == 1
        let parityRejected = (role == .dialer && isOdd) || (role == .listener && !isOdd)
        if parityRejected {
            logger.warning(
                "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.protocolError.rawValue, privacy: .public)"
            )
            try await sendControl(try encodeFrame(buildReset(streamID: frame.streamID, reason: .protocolError)))
            return
        }

        if streams[frame.streamID] != nil {
            logger.warning(
                "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.protocolError.rawValue, privacy: .public)"
            )
            try await sendControl(try encodeFrame(buildReset(streamID: frame.streamID, reason: .protocolError)))
            return
        }

        guard activeStreamCount() < MuxConstants.maxConcurrentStreams else {
            logger.warning(
                "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.streamLimitExceeded.rawValue, privacy: .public)"
            )
            try await sendControl(try encodeFrame(buildReset(streamID: frame.streamID, reason: .streamLimitExceeded)))
            return
        }

        let stream = MuxStream(
            id: frame.streamID,
            sink: dataSink,
            onTerminal: { [weak self] streamID in
                await self?.evictTerminalStream(id: streamID)
            },
            now: now
        )

        if !frame.payload.isEmpty {
            let outcome = await stream.admitInitialPayload(frame.payload)
            if outcome == .receiveWindowExceeded {
                logger.warning(
                    "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.flowControlError.rawValue, privacy: .public)"
                )
                try await sendControl(try encodeFrame(buildReset(streamID: frame.streamID, reason: .flowControlError)))
                return
            }
        }

        if frame.flags & FrameFlags.close.rawValue != 0 {
            await stream.deliverInboundClose()
        }

        streams[frame.streamID] = stream
        incomingContinuation.yield(stream)
    }

    private func handleControlFrame(_ frame: Frame, isPing: Bool, isPong: Bool) async throws {
        guard frame.flags == FrameFlags.ping.rawValue || frame.flags == FrameFlags.pong.rawValue else {
            throw FramingError.unknownControlFrame
        }

        switch (isPing, isPong) {
        case (true, false):
            let nonce = try parseControlNonce(from: frame.payload)
            try await sendControl(try encodeFrame(buildPong(nonce: nonce)))
        case (false, true):
            let nonce = try parseControlNonce(from: frame.payload)
            if let matched = outstandingPings.first(where: { $0.nonce == nonce }) {
                outstandingPings.removeAll { $0.issuedTick <= matched.issuedTick }
                lastMatchedPongAt = now()
            }
        default:
            throw FramingError.unknownControlFrame
        }
    }

    private func isolateStream(_ stream: MuxStream, frame: Frame, reason: ResetReason) async throws {
        guard await stream.markResetLocal() else {
            return
        }

        logger.warning(
            "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(reason.rawValue, privacy: .public)"
        )
        try await sendControl(try encodeFrame(buildReset(streamID: frame.streamID, reason: reason)))
    }

    private func emitUnknownStreamReset(
        streamID: UInt32,
        flags: UInt8,
        length: Int,
        reason: ResetReason
    ) async throws {
        logger.warning(
            "framing_protocol_violation stream_id=\(streamID, privacy: .public) flags=\(flags, privacy: .public) length=\(length, privacy: .public) reason=\(reason.rawValue, privacy: .public)"
        )
        try await sendControl(try encodeFrame(buildReset(streamID: streamID, reason: reason)))
    }

    private func evictTerminalStream(id: UInt32) {
        streams.removeValue(forKey: id)
    }

    private func runKeepalive(interval: Duration, missedLimit: Int, deferralLimit: Duration) async {
        while !Task.isCancelled {
            do {
                try await sleeper(interval)
                let tick = keepaliveTickIndex
                try await performKeepaliveTick(
                    currentTick: tick,
                    missedLimit: missedLimit,
                    deferralLimit: deferralLimit
                )
                keepaliveTickIndex = tick &+ 1
            } catch {
                guard !Task.isCancelled, !(error is CancellationError) else {
                    return
                }
                // Sink failure means the transport write path is dead; tear down immediately.
                logger.notice("mux keepalive lost reason=\("sendFailure", privacy: .public)")
                await emitKeepaliveLost(reason: .sendFailure, missedPingCount: outstandingPings.count)
                await tearDown(reason: .transportFailure)
                return
            }
        }
    }

    private func performKeepaliveTick(
        currentTick: UInt64,
        missedLimit: Int,
        deferralLimit: Duration
    ) async throws {
        guard !tornDown else {
            throw MuxError.transportClosed
        }

        let effectiveMissedLimit = max(missedLimit, 1)
        let missedLimitTicks = UInt64(effectiveMissedLimit)
        if currentTick >= missedLimitTicks,
           let oldest = outstandingPings.first,
           oldest.issuedTick <= currentTick - missedLimitTicks {
            // The scheduler puts a PING ahead of queued DATA, but not ahead of
            // DATA the transport has already buffered below it, so during a bulk
            // upload the PING reaches the peer only after those bytes do and its
            // PONG is late by the buffer's drain time. If the peer has touched an
            // application stream within the same window (a WINDOW grant, a
            // response) the path is demonstrably alive; keep pinging and let the
            // wall-clock cap decide when late becomes lost.
            //
            // Inbound activity alone is not enough, because the peer is allowed
            // to be legitimately silent: between a bulk POST's last body byte
            // and the first byte of the reply it sends nothing on that stream at
            // all, which is exactly where a large upload dies. A stream we have
            // written to and heard nothing back on is that case, and it carries
            // its own age bound, so a stream stranded awaiting a reply that
            // never comes cannot defer every later loss on this carrier.
            //
            // A dark path with nothing outstanding sends nothing at all and
            // still fails at the missed limit.
            let sinceLastPong = pongOrigin().duration(to: now())
            let streamRecentlyActive = streamInboundTick.map { $0 + missedLimitTicks > currentTick } ?? false
            let awaitingPeer = await anyStreamAwaitingPeer(within: deferralLimit)
            if (streamRecentlyActive || awaitingPeer) && sinceLastPong < deferralLimit {
                logger.notice(
                    "mux keepalive deferred missed_pings=\(effectiveMissedLimit, privacy: .public) since_pong_ms=\(Self.milliseconds(sinceLastPong), privacy: .public)"
                )
            } else {
                // Missed PONGs are session policy: signal and let the session decide whether to tear down.
                logger.notice("mux keepalive lost missed_pings=\(effectiveMissedLimit, privacy: .public)")
                await emitKeepaliveLost(reason: .missedPingLimit, missedPingCount: effectiveMissedLimit)
                keepaliveTask?.cancel()
                keepaliveTask = nil
                return
            }
        }

        let nonce = try randomNonce()
        outstandingPings.append(OutstandingPing(nonce: nonce, issuedTick: currentTick))
        try await sendControl(try encodeFrame(buildPing(nonce: nonce)))
    }

    /// `true` when any open stream handed the peer DATA within `limit` and has
    /// had nothing back on that stream since.
    private func anyStreamAwaitingPeer(within limit: Duration) async -> Bool {
        let instant = now()
        for stream in streams.values {
            if await stream.isAwaitingPeer(within: limit, asOf: instant) {
                return true
            }
        }
        return false
    }

    private func sendControl(_ frame: Data) async throws {
        try await scheduler.send(frame, priority: .control)
    }

    private func pongOrigin() -> ContinuousClock.Instant {
        lastMatchedPongAt ?? keepaliveStartedAt ?? now()
    }

    private static func milliseconds(_ duration: Duration) -> Int64 {
        let components = duration.components
        return components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000
    }

    private func emitKeepaliveLost(reason: KeepaliveLossEvent.Reason, missedPingCount: Int) async {
        let event = KeepaliveLossEvent(
            reason: reason,
            missedPingCount: missedPingCount,
            elapsedSinceLastPong: pongOrigin().duration(to: now()),
            outboundInFlight: await scheduler.dataInFlightOrQueued()
        )
        keepaliveLostContinuation.yield(event)
    }

    private func activeStreamCount() -> Int {
        // framing.md:114-118 caps concurrent non-terminal streams to bound memory
        // under a misbehaving peer; .halfClosedLocal and .halfClosedRemote streams
        // still hold flow-control buffers, and terminal streams are evicted through
        // onTerminal. The async eviction callback may briefly over-count a
        // just-terminal stream, which is conservative and safe for a memory cap.
        streams.count
    }

    private func randomNonce() throws -> Data {
        var nonce = Data(count: 8)
        let status = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 8, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw PingNonceError.generationFailed(status)
        }
        return nonce
    }
}
