// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("MuxKeepalive", .serialized)
struct MuxKeepaliveTests {
    @Test func inboundDataDoesNotSuppressFixedCadencePings() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let stream = try await mux.openStream()
        await recorder.reset()

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        for tick in 1...4 {
            await gate.waitForObservedTick(count: tick)
            // proto/framing.md@613a82d:165 fixed 500 ms cadence is not suppressed by inbound frames.
            let payload = tick.isMultiple(of: 2) ? Data() : Data([UInt8(tick)])
            try await mux.feedInbound(try encodeFrame(buildData(streamID: stream.id, payload: payload)))
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
            let ping = try #require(try await pingFrames(in: recorder).last)
            try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: ping.payload))))
        }

        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func streamActivityDefersLossWhilePongsAreLateThenDarkPathStillFails() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let stream = try await mux.openStream()
        await recorder.reset()
        // One consumer for the whole test: probing the stream early and cancelling
        // the probe finishes the AsyncStream before the real loss is yielded.
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost, timeout: .seconds(5)) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        // A bulk upload: the peer keeps granting WINDOW, our PING sits behind the
        // buffered DATA, and no PONG arrives for six ticks. Twice the missed limit
        // passes; a loss here would stop the pings at three.
        for tick in 1...6 {
            await gate.waitForObservedTick(count: tick)
            try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
            await gate.releaseOne()
            try await expectTick(gate, count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }

        // The late PONG for the newest ping clears the whole backlog.
        let ping = try #require(try await pingFrames(in: recorder).last)
        try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: ping.payload))))

        // Then the path goes dark: no stream frames, no PONGs. The stale grants
        // from the upload must not carry the deferral, so the loss lands at the
        // ordinary point, three unanswered pings after the last PONG. Nine pings
        // at the loss is the proof of both halves: a loss during the upload would
        // have stopped them at three, a backlog that did not clear at six.
        for tick in 7...9 {
            await gate.releaseOne()
            try await expectTick(gate, count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(try await pingFrames(in: recorder).count == 9)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func staleStreamActivityDoesNotDeferLoss() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let stream = try await mux.openStream()
        await recorder.reset()
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        // One WINDOW grant before the first ping, then silence.
        await gate.waitForObservedTick(count: 1)
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
        for tick in 1...3 {
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(try await pingFrames(in: recorder).count == 3)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func streamActivityCannotDeferLossPastTheDeferralLimit() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let clock = MuxInstantBox()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.get() }
        )
        let stream = try await mux.openStream()
        await recorder.reset()
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3, deferralLimit: .seconds(3))
        // WINDOW every tick and never a PONG: ticks 4 and 5 defer (2.0 s, 2.5 s
        // since the keepalive started), tick 6 reaches the cap.
        for tick in 1...5 {
            await gate.waitForObservedTick(count: tick)
            try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
            clock.advance(.milliseconds(500))
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }
        try await mux.feedInbound(try encodeFrame(buildWindow(streamID: stream.id, credit: 1)))
        clock.advance(.milliseconds(500))
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(event.elapsedSinceLastPong == .seconds(3))
        #expect(try await pingFrames(in: recorder).count == 5)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func deadPathEmitsExactlyOneLossAfterThreeUnansweredPings() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        for tick in 1...3 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }

        // proto/framing.md@613a82d:167 3 consecutive unanswered pings mark the path lost.
        await gate.releaseOne()
        try await loss.value
        #expect(try await pingFrames(in: recorder).count == 3)
        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func missedLimitOneTripsBeforeSecondPing() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        #expect(try await pingFrames(in: recorder).count == 1)
        await gate.releaseOne()
        try await loss.value
        #expect(try await pingFrames(in: recorder).count == 1)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func pongClearsPendingButDoesNotSuppressNextPing() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        for tick in 1...4 {
            await gate.waitForObservedTick(count: tick)
            // proto/framing.md@613a82d:166 matching PONG clears pending state.
            if let previous = try await pingFrames(in: recorder).last {
                try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: previous.payload))))
            }
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            // proto/framing.md@613a82d:165 PONG is not an idle gate; the next tick still PINGs.
            #expect(try await pingFrames(in: recorder).count == tick)
        }

        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func latePongForOutstandingNonceKeepsHighRTTPathAlive() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        for tick in 1...3 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
        }

        let first = try #require(try await pingFrames(in: recorder).first)
        // proto/framing.md@613a82d:166 late matching PONG still clears its outstanding nonce.
        try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: first.payload))))
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 5)

        #expect(try await pingFrames(in: recorder).count == 4)
        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func strayPongWhileNonceOutstandingClearsNothingAndDoesNotMoveLossSchedule() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)

        // proto/framing.md@613a82d:159 stray PONGs are tolerated and silently dropped.
        try await mux.feedInbound(try encodeFrame(buildPong(nonce: Data([9, 9, 9, 9, 9, 9, 9, 9]))))
        for tick in 2...3 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
        }

        // proto/framing.md@613a82d:166 unmatched PONG clears no outstanding nonce.
        await gate.releaseOne()
        try await loss.value
        #expect(try await pingFrames(in: recorder).count == 3)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func keepaliveCanRestartAfterLossAndEmitSecondLoss() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )

        let firstLoss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }
        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        await gate.releaseOne()
        try await firstLoss.value

        let secondLoss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }
        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 3)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 4)
        await gate.releaseOne()
        try await secondLoss.value

        #expect(try await pingFrames(in: recorder).count == 2)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func keepaliveSendFailureEmitsLostBeforeTeardown() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.ping.rawValue))
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await sink.recordOrThrow(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()

        try await loss.value
        await expectMuxError(.transportClosed) {
            try await mux.openStream()
        }
        await gate.cancelAll()
    }

    @Test func normalKeepaliveCancellationEmitsNoLost() async throws {
        do {
            let recorder = MuxFrameRecorder()
            let gate = KeepaliveTickGate()
            let mux = Multiplexer(
                sink: { bytes in try await recorder.record(bytes) },
                sleeper: { duration in try await gate.sleep(duration) }
            )

            await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
            await gate.waitForObservedTick(count: 1)
            await mux.tearDown(reason: .normalShutdown)
            await gate.cancelAll()

            #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        }

        do {
            let recorder = MuxFrameRecorder()
            let mux = Multiplexer(
                sink: { bytes in try await recorder.record(bytes) },
                sleeper: { _ in throw CancellationError() }
            )

            await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
            #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
            await mux.tearDown(reason: .normalShutdown)
        }
    }

    @Test func tearDownIsIdempotentAfterKeepaliveLoss() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        await gate.releaseOne()
        try await loss.value

        await mux.tearDown(reason: .transportFailure)
        await mux.tearDown(reason: .transportFailure)
        await expectMuxError(.transportClosed) {
            try await mux.openStream()
        }
        await gate.cancelAll()
    }

    @Test func pongReplyJumpsQueuedDataWithinBudget() async throws {
        let sink = SlowFIFOMuxSink(perFrameDelay: .milliseconds(50))
        let mux = Multiplexer(sink: { bytes in try await sink.record(bytes) })
        // A single MuxStream.write awaits each sink call, so one 16-chunk payload
        // cannot occupy the FIFO with 16 frames at once. 16 concurrent 64KB writes
        // produce the same total (1 MiB) and genuinely queue DATA ahead of PONG.
        var streams: [MuxStream] = []
        for _ in 0..<16 {
            streams.append(try await mux.openStream())
        }
        let chunk = Data(count: MuxConstants.recommendedChunk)
        let writes = streams.map { stream in
            Task {
                try await stream.write(chunk)
            }
        }
        await sink.waitUntilAcceptedDataCount(1)
        try await Task.sleep(for: .milliseconds(20))

        let pingStartedAt = ContinuousClock.now
        try await mux.feedInbound(try encodeFrame(buildPing(nonce: Data(repeating: 7, count: 8))))
        try await sink.waitUntilCompletedPong(timeout: .milliseconds(200))
        #expect(pingStartedAt.duration(to: .now) < .milliseconds(200))

        await mux.tearDown(reason: .normalShutdown)
        for write in writes {
            write.cancel()
            _ = await write.result
        }
    }

    @Test func missedLimitTwoEmitsExactMissedPingCount() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 2)
        for tick in 1...2 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
        }
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(event.missedPingCount == 2)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func elapsedSinceLastPongUsesInjectedClock() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let clock = MuxInstantBox()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.get() }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        let ping = try #require(try await pingFrames(in: recorder).last)
        try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: ping.payload))))
        clock.advance(.milliseconds(1500))
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 3)
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(event.elapsedSinceLastPong == .milliseconds(1500))
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func sendFailureEmitsSendFailureReason() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.ping.rawValue))
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await sink.recordOrThrow(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 3)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()

        let event = try await loss.value
        #expect(event.reason == .sendFailure)
        await gate.cancelAll()
    }

    @Test func outboundInFlightIsFalseWhenNoDataIsQueuedAtMissedPingLoss() async throws {
        let recorder = MuxFrameRecorder()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(event.outboundInFlight == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func outboundInFlightIsTrueWhenDataIsQueuedAtMissedPingLoss() async throws {
        let sink = SlowFIFOMuxSink(perFrameDelay: .milliseconds(80))
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await sink.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) }
        )
        var streams: [MuxStream] = []
        for _ in 0..<16 {
            streams.append(try await mux.openStream())
        }
        let chunk = Data(count: MuxConstants.recommendedChunk)
        let writes = streams.map { stream in
            Task {
                try await stream.write(chunk)
            }
        }
        await sink.waitUntilAcceptedDataCount(1)

        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }
        await mux.startKeepalive(interval: .milliseconds(500), missedLimit: 1)
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)
        await gate.releaseOne()
        let event = try await loss.value
        #expect(event.reason == .missedPingLimit)
        #expect(event.outboundInFlight == true)

        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
        for write in writes {
            write.cancel()
            _ = await write.result
        }
    }

    /// Wait for the keepalive to reach `count` observed ticks, failing instead of hanging if
    /// the keepalive stopped early: a loss cancels the task, and a test that expects no loss
    /// would otherwise wait forever for a tick that never comes.
    private func expectTick(_ gate: KeepaliveTickGate, count: Int, within timeout: Duration = .seconds(2)) async throws {
        guard await gate.waitForObservedTick(count: count, within: timeout) else {
            throw MuxTestError.timedOut("keepalive tick \(count) never observed; the keepalive stopped early")
        }
    }

    private func pingFrames(in recorder: MuxFrameRecorder) async throws -> [Frame] {
        await recorder.frames().filter { $0.streamID == 0 && $0.flags == FrameFlags.ping.rawValue }
    }
}
