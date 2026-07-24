// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

@testable import SPLTunnel
import Foundation
import Testing

@Suite("MuxKeepalive", .serialized)
struct MuxKeepaliveTests {
    @Test func busyTicksStaySilentAndDoNotEmitKeepaliveLost() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 3)
        for tick in 1...6 {
            await gate.waitForObservedTick(count: tick)
            clock.advance(by: .milliseconds(250))
            await gate.releaseOne()
        }
        await gate.waitForObservedTick(count: 7)

        #expect(try await pingFrames(in: recorder).isEmpty)
        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func idleTicksEscalateAfterBudget() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 3)
        clock.advance(by: .seconds(2))
        for tick in 1...3 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
            #expect(try await pingFrames(in: recorder).count == tick)
        }

        await gate.releaseOne()
        try await loss.value
        #expect(try await pingFrames(in: recorder).count == 3)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func escalationCountsConsecutiveUnansweredIdleTicks() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .milliseconds(1), missedLimit: 3)
        clock.advance(by: .milliseconds(1))
        for tick in 1...3 {
            await gate.waitForObservedTick(count: tick)
            await gate.releaseOne()
            await gate.waitForObservedTick(count: tick + 1)
        }
        #expect(try await pingFrames(in: recorder).count == 3)

        await gate.releaseOne()
        try await loss.value
        #expect(try await pingFrames(in: recorder).count == 3)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func pongResetsPendingPingAndMakesNextTickBusy() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 3)
        clock.advance(by: .seconds(2))
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 2)

        let ping = try #require(try await pingFrames(in: recorder).first)
        try await mux.feedInbound(try encodeFrame(buildPong(nonce: try parseControlNonce(from: ping.payload))))
        let pingCountAfterPong = try await pingFrames(in: recorder).count
        clock.advance(by: .milliseconds(500))
        await gate.releaseOne()
        await gate.waitForObservedTick(count: 3)

        #expect(try await pingFrames(in: recorder).count == pingCountAfterPong)
        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()
    }

    @Test func keepaliveSendFailureEmitsLostBeforeTeardown() async throws {
        let sink = SelectiveMuxSink(failureMode: .flags(FrameFlags.ping.rawValue))
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await sink.recordOrThrow(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 3)
        clock.advance(by: .seconds(2))
        await gate.waitForObservedTick(count: 1)
        await gate.releaseOne()

        try await loss.value
        await expectMuxError(.transportClosed) {
            try await mux.openStream()
        }
        await gate.cancelAll()
    }

    @Test func normalKeepaliveCancellationEmitsNoLost() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 3)
        await gate.waitForObservedTick(count: 1)
        await mux.tearDown(reason: .normalShutdown)
        await gate.cancelAll()

        #expect(await keepaliveLossObserved(from: mux.keepaliveLost) == false)
    }

    @Test func tearDownIsIdempotentAfterKeepaliveLoss() async throws {
        let recorder = MuxFrameRecorder()
        let clock = ManualMuxClock()
        let gate = KeepaliveTickGate()
        let mux = Multiplexer(
            sink: { bytes in try await recorder.record(bytes) },
            sleeper: { duration in try await gate.sleep(duration) },
            now: { clock.now() }
        )
        let loss = Task { try await firstKeepaliveLoss(from: mux.keepaliveLost) }

        await mux.startKeepalive(interval: .milliseconds(500), idleThreshold: .seconds(2), missedLimit: 1)
        clock.advance(by: .seconds(2))
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
