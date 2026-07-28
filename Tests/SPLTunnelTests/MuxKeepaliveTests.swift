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

    private func pingFrames(in recorder: MuxFrameRecorder) async throws -> [Frame] {
        await recorder.frames().filter { $0.streamID == 0 && $0.flags == FrameFlags.ping.rawValue }
    }
}
