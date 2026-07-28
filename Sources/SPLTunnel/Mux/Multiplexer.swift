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

public actor Multiplexer {
    public nonisolated var keepaliveLost: AsyncStream<Void> {
        keepaliveLostStream
    }

    public nonisolated let incomingStreams: AsyncStream<MuxStream>

    private let sink: @Sendable (Data) async throws -> Void
    private let sleeper: @Sendable (Duration) async throws -> Void
    private let role: Role
    private let incomingContinuation: AsyncStream<MuxStream>.Continuation
    private let keepaliveLostStream: AsyncStream<Void>
    private let keepaliveLostContinuation: AsyncStream<Void>.Continuation
    private var nextOutboundID: UInt32
    private var streams: [UInt32: MuxStream] = [:]
    private var tornDown = false
    private var decoder = FrameDecoder()
    private var keepaliveTask: Task<Void, Never>?
    private var outstandingPings: [OutstandingPing] = []
    private var keepaliveTickIndex: UInt64 = 0
    private var inboundActivityCounter: UInt64 = 0

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
        sleeper: @escaping @Sendable (Duration) async throws -> Void
    ) {
        let incoming = AsyncStream<MuxStream>.makeStream()
        let keepalive = AsyncStream<Void>.makeStream()
        self.sink = sink
        self.role = role
        self.sleeper = sleeper
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
            sink: sink,
            onTerminal: { [weak self] streamID in
                await self?.evictTerminalStream(id: streamID)
            }
        )
        let frame = try encodeFrame(buildOpen(streamID: id))
        streams[id] = stream
        do {
            try await sink(frame)
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
        missedLimit: Int = 3
    ) {
        guard keepaliveTask == nil else {
            return
        }

        outstandingPings.removeAll(keepingCapacity: true)
        keepaliveTickIndex = 0
        keepaliveTask = Task {
            await runKeepalive(interval: interval, missedLimit: missedLimit)
        }
    }

    public func tearDown(reason: TearDownReason) async {
        guard !tornDown else {
            return
        }

        tornDown = true
        keepaliveTask?.cancel()
        keepaliveTask = nil
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

        let stream = streams[frame.streamID]

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
            try await sink(try encodeFrame(buildReset(streamID: frame.streamID, reason: .protocolError)))
            return
        }

        if streams[frame.streamID] != nil {
            logger.warning(
                "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.protocolError.rawValue, privacy: .public)"
            )
            try await sink(try encodeFrame(buildReset(streamID: frame.streamID, reason: .protocolError)))
            return
        }

        guard activeStreamCount() < MuxConstants.maxConcurrentStreams else {
            logger.warning(
                "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.streamLimitExceeded.rawValue, privacy: .public)"
            )
            try await sink(try encodeFrame(buildReset(streamID: frame.streamID, reason: .streamLimitExceeded)))
            return
        }

        let stream = MuxStream(
            id: frame.streamID,
            sink: sink,
            onTerminal: { [weak self] streamID in
                await self?.evictTerminalStream(id: streamID)
            }
        )

        if !frame.payload.isEmpty {
            let outcome = await stream.admitInitialPayload(frame.payload)
            if outcome == .receiveWindowExceeded {
                logger.warning(
                    "framing_protocol_violation stream_id=\(frame.streamID, privacy: .public) flags=\(frame.flags, privacy: .public) length=\(frame.payload.count, privacy: .public) reason=\(ResetReason.flowControlError.rawValue, privacy: .public)"
                )
                try await sink(try encodeFrame(buildReset(streamID: frame.streamID, reason: .flowControlError)))
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
            try await sink(try encodeFrame(buildPong(nonce: nonce)))
        case (false, true):
            let nonce = try parseControlNonce(from: frame.payload)
            if let matched = outstandingPings.first(where: { $0.nonce == nonce }) {
                outstandingPings.removeAll { $0.issuedTick <= matched.issuedTick }
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
        try await sink(try encodeFrame(buildReset(streamID: frame.streamID, reason: reason)))
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
        try await sink(try encodeFrame(buildReset(streamID: streamID, reason: reason)))
    }

    private func evictTerminalStream(id: UInt32) {
        streams.removeValue(forKey: id)
    }

    private func runKeepalive(interval: Duration, missedLimit: Int) async {
        while !Task.isCancelled {
            do {
                try await sleeper(interval)
                let tick = keepaliveTickIndex
                try await performKeepaliveTick(
                    currentTick: tick,
                    missedLimit: missedLimit
                )
                keepaliveTickIndex = tick &+ 1
            } catch {
                guard !Task.isCancelled, !(error is CancellationError) else {
                    return
                }
                // Sink failure means the transport write path is dead; tear down immediately.
                logger.notice("mux keepalive lost reason=\("sendFailure", privacy: .public)")
                keepaliveLostContinuation.yield(())
                await tearDown(reason: .transportFailure)
                return
            }
        }
    }

    private func performKeepaliveTick(
        currentTick: UInt64,
        missedLimit: Int
    ) async throws {
        guard !tornDown else {
            throw MuxError.transportClosed
        }

        let effectiveMissedLimit = max(missedLimit, 1)
        let missedLimitTicks = UInt64(effectiveMissedLimit)
        if currentTick >= missedLimitTicks,
           let oldest = outstandingPings.first,
           oldest.issuedTick <= currentTick - missedLimitTicks {
            // Missed PONGs are session policy: signal and let the session decide whether to tear down.
            logger.notice("mux keepalive lost missed_pings=\(effectiveMissedLimit, privacy: .public)")
            keepaliveLostContinuation.yield(())
            keepaliveTask?.cancel()
            keepaliveTask = nil
            return
        }

        let nonce = try randomNonce()
        outstandingPings.append(OutstandingPing(nonce: nonce, issuedTick: currentTick))
        try await sink(try encodeFrame(buildPing(nonce: nonce)))
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
